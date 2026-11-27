//! ADR-259：用户完成通知账本。只存定长 Copy 记录，不碰 VMO、Proc 或 DMA 租约。

use crate::filesystem::vfs::BlockError;
use crate::sync::{IrqSpinLock, RANK_NOTIFY};

pub const NOTIFY_SLOTS: usize = 32;
pub const NOTIFY_HEADER_BYTES: usize = 32;
pub const NOTIFY_RECORD_BYTES: usize = 64;
pub const NOTIFY_MAGIC: u32 = 0x4e4f_5446;
pub const NOTIFY_VERSION: u32 = 1;
pub const OFF_PRODUCER: usize = 16;
pub const OFF_CONSUMED: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyError {
    Full,
    BadEndpoint,
    StaleEndpoint,
    BadAck,
    WrongContext,
    Locked,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotifyEndpoint {
    pub proc: u16,
    pub proc_gen: u32,
    pub vmo: u8,
    pub vmo_gen: u64,
    pub ring_va: u64,
    pub capacity: u16,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotifyRecord {
    pub seq: u64,
    pub token: u64,
    pub target: u64,
    pub result: i32,
    pub sectors_done: u32,
    pub diagnostic: [u8; 16],
}

impl NotifyRecord {
    pub const EMPTY: Self = Self {
        seq: 0,
        token: 0,
        target: 0,
        result: 0,
        sectors_done: 0,
        diagnostic: [0; 16],
    };

    pub fn to_bytes(self) -> [u8; NOTIFY_RECORD_BYTES] {
        let mut out = [0u8; NOTIFY_RECORD_BYTES];
        out[0..8].copy_from_slice(&self.seq.to_le_bytes());
        out[8..16].copy_from_slice(&self.token.to_le_bytes());
        out[16..24].copy_from_slice(&self.target.to_le_bytes());
        out[24..28].copy_from_slice(&self.result.to_le_bytes());
        out[28..32].copy_from_slice(&self.sectors_done.to_le_bytes());
        out[32..48].copy_from_slice(&self.diagnostic);
        out
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NotifyStats {
    pub next_seq: u64,
    pub acked_seq: u64,
    pub published_seq: u64,
    pub retained: usize,
    pub replacements: u32,
    pub full: u32,
    pub stale: u32,
}

struct State {
    endpoint: Option<NotifyEndpoint>,
    next_generation: u64,
    next_seq: u64,
    acked_seq: u64,
    published_seq: u64,
    slots: [Option<NotifyRecord>; NOTIFY_SLOTS],
    replacements: u32,
    full: u32,
    stale: u32,
}

const EMPTY_STATE: State = State {
    endpoint: None,
    next_generation: 0,
    next_seq: 1,
    acked_seq: 0,
    published_seq: 0,
    slots: [None; NOTIFY_SLOTS],
    replacements: 0,
    full: 0,
    stale: 0,
};

struct Cell(core::cell::UnsafeCell<State>);
// SAFETY: 所有访问都在 NOTIFY_LOCK 内；载荷为 Copy 数值，闭包不借出状态引用。
unsafe impl Sync for Cell {}

static STATE: Cell = Cell(core::cell::UnsafeCell::new(EMPTY_STATE));
static NOTIFY_LOCK: IrqSpinLock<()> = IrqSpinLock::new(RANK_NOTIFY, ());

fn with_state<R>(body: impl FnOnce(&mut State) -> R) -> Result<R, NotifyError> {
    if crate::arch::x86_64::apic::in_isr() {
        return Err(NotifyError::WrongContext);
    }
    #[cfg(not(feature = "fault-notify-lock-rank"))]
    let _guard = NOTIFY_LOCK.lock_checked().ok_or(NotifyError::Locked)?;
    #[cfg(feature = "fault-notify-lock-rank")]
    let _guard = NOTIFY_LOCK.lock();
    // SAFETY: 锁内独占，载荷全为 Copy，返回后不借出引用。
    let state = unsafe { &mut *STATE.0.get() };
    Ok(body(state))
}

fn same_endpoint(a: NotifyEndpoint, b: NotifyEndpoint) -> bool {
    #[cfg(not(feature = "fault-notify-skip-gen"))]
    {
        a == b
    }
    #[cfg(feature = "fault-notify-skip-gen")]
    {
        a.proc == b.proc
            && a.proc_gen == b.proc_gen
            && a.vmo == b.vmo
            && a.vmo_gen == b.vmo_gen
            && a.ring_va == b.ring_va
            && a.capacity == b.capacity
    }
}

fn result_code(error: Option<BlockError>) -> i32 {
    match error {
        None => 0,
        Some(BlockError::NoDevice) => 1,
        Some(BlockError::NotIssued) => 2,
        Some(BlockError::NotSettled) => 3,
        Some(BlockError::DeviceError) => 4,
        Some(BlockError::Quarantined) => 5,
        Some(BlockError::Refused) => 6,
        Some(BlockError::BeyondPartition) => 7,
    }
}

/// 安装端点。旧端点只失效，未确认记录与 seq 一律保留。
pub fn install(mut endpoint: NotifyEndpoint) -> Result<NotifyEndpoint, NotifyError> {
    with_state(|state| {
        if endpoint.capacity as usize != NOTIFY_SLOTS
            || endpoint.ring_va == 0
            || endpoint.proc_gen == 0
            || endpoint.vmo_gen == 0
        {
            return Err(NotifyError::BadEndpoint);
        }
        state.next_generation = state.next_generation.checked_add(1).ok_or(NotifyError::Exhausted)?;
        endpoint.generation = state.next_generation;
        if state.endpoint.is_some() {
            state.replacements = state.replacements.saturating_add(1);
        }
        state.endpoint = Some(endpoint);
        #[cfg(not(feature = "fault-notify-drop-replay"))]
        {
            state.published_seq = state.acked_seq;
        }
        #[cfg(feature = "fault-notify-drop-replay")]
        {
            state.published_seq = state.next_seq - 1;
        }
        Ok(endpoint)
    })?
}

pub fn endpoint() -> Option<NotifyEndpoint> {
    with_state(|state| state.endpoint).ok().flatten()
}

/// 核内完成入账。队列满时明确拒绝，不覆盖最早未确认记录。
pub fn publish(
    token: u64,
    target: u64,
    sectors_done: u32,
    error: Option<BlockError>,
    diagnostic: [u8; 16],
) -> Result<u64, NotifyError> {
    with_state(|state| {
        #[cfg(not(feature = "fault-notify-overwrite"))]
        if state.slots.iter().all(Option::is_some) {
            state.full = state.full.saturating_add(1);
            return Err(NotifyError::Full);
        }
        let seq = state.next_seq;
        state.next_seq = seq.checked_add(1).ok_or(NotifyError::Exhausted)?;
        let result = result_code(error);
        #[cfg(not(feature = "fault-notify-drop-sectors"))]
        let sectors_done = sectors_done;
        #[cfg(feature = "fault-notify-drop-sectors")]
        let sectors_done = if error.is_some() { 0 } else { sectors_done };
        let record = NotifyRecord { seq, token, target, result, sectors_done, diagnostic };
        let slot = if cfg!(feature = "fault-notify-overwrite") && state.slots.iter().all(Option::is_some) {
            state.full = state.full.saturating_add(1);
            0
        } else {
            state.slots.iter().position(Option::is_none).ok_or(NotifyError::Full)?
        };
        state.slots[slot] = Some(record);
        Ok(seq)
    })?
}

/// 给页面镜像器的下一条待发布记录；世代不符必须拒绝。
pub fn next_to_write(endpoint: NotifyEndpoint) -> Result<Option<NotifyRecord>, NotifyError> {
    with_state(|state| {
        if !state.endpoint.is_some_and(|current| same_endpoint(current, endpoint)) {
            state.stale = state.stale.saturating_add(1);
            return Err(NotifyError::StaleEndpoint);
        }
        if state.published_seq >= state.next_seq - 1 {
            return Ok(None);
        }
        let seq = state.published_seq + 1;
        state.slots.iter().flatten().find(|record| record.seq == seq).copied().map(Some).ok_or(NotifyError::BadAck)
    })?
}

/// 页面已写入且 producer 已 Release 发布后才推进账本。
pub fn mark_published(endpoint: NotifyEndpoint, seq: u64) -> Result<(), NotifyError> {
    with_state(|state| {
        if !state.endpoint.is_some_and(|current| same_endpoint(current, endpoint)) {
            state.stale = state.stale.saturating_add(1);
            return Err(NotifyError::StaleEndpoint);
        }
        if seq != state.published_seq + 1 || seq >= state.next_seq {
            return Err(NotifyError::BadAck);
        }
        state.published_seq = seq;
        Ok(())
    })?
}

/// 消费端确认到连续 seq；已确认记录永久删除，端点替换也不会重投。
pub fn confirm_acked(endpoint: NotifyEndpoint, consumed: u64) -> Result<(), NotifyError> {
    with_state(|state| {
        if !state.endpoint.is_some_and(|current| same_endpoint(current, endpoint)) {
            state.stale = state.stale.saturating_add(1);
            return Err(NotifyError::StaleEndpoint);
        }
        if consumed < state.acked_seq || consumed > state.published_seq {
            return Err(NotifyError::BadAck);
        }
        for seq in state.acked_seq + 1..=consumed {
            if !state.slots.iter().flatten().any(|record| record.seq == seq) {
                return Err(NotifyError::BadAck);
            }
        }
        for seq in state.acked_seq + 1..=consumed {
            let slot = state.slots.iter().position(|record| record.is_some_and(|r| r.seq == seq));
            if let Some(slot) = slot {
                state.slots[slot] = None;
            }
        }
        state.acked_seq = consumed;
        Ok(())
    })?
}

pub fn invalidate(endpoint: NotifyEndpoint) -> Result<(), NotifyError> {
    with_state(|state| {
        if !state.endpoint.is_some_and(|current| same_endpoint(current, endpoint)) {
            state.stale = state.stale.saturating_add(1);
            return Err(NotifyError::StaleEndpoint);
        }
        state.endpoint = None;
        state.published_seq = state.acked_seq;
        Ok(())
    })?
}

pub fn stats() -> NotifyStats {
    with_state(|state| NotifyStats {
        next_seq: state.next_seq,
        acked_seq: state.acked_seq,
        published_seq: state.published_seq,
        retained: (state.next_seq - 1 - state.acked_seq) as usize,
        replacements: state.replacements,
        full: state.full,
        stale: state.stale,
    })
    .unwrap_or_default()
}

#[doc(hidden)]
pub fn reset_for_test() {
    let _ = with_state(|state| *state = EMPTY_STATE);
}
