//! §9.4 启动循环保护与安全模式。
//!
//! 三条形状上的硬要求，每条都有能变红的判据：
//!
//! 1. **先计数，再进可能崩溃的路径**。`decide()` 里读到的那个数立刻 +1 写回盘，
//!    然后才继续启动 —— 否则一个在写回之前就崩掉的路径永远不会被计数，而这一格
//!    正是"连续失败"的定义所在。
//! 2. **读不到就是最坏情况**，不是"当 0 看"（`state_store::read` 只有 `Ok`/`Err` 两个出口，
//!    默认值在这里没有藏身处）。
//! 3. **模式必须对外可见**（手册反复要的那条：不提供某件事不许静默）。可见的地方有两处：
//!    串口一行，`sys_abi_info()` 的 `F_SAFE_MODE` 位 —— 后者由 `user::abi_word()` 直接
//!    读这里的真实状态，不是读"我打算开"。
//!
//! 处置只做到"不起非必要设备"这一件今天真的存在的事：安全模式下 AHCI 只起到
//! 第一块有盘的口为止，其余口一个寄存器都不写。**没有**做隔离名单（§9.4 后半句），
//! 因为本内核还没有驱动加载器可以挂它 —— 那条与 §8.2 的 registry 一起做（BACKLOG）。

use crate::state_store::{self, BootState};
use core::sync::atomic::{AtomicU32, Ordering};

/// 连续失败多少次进安全模式。取 3：一次装机抖动 + 一次内核升级失败 + 一次掉电，
/// 刚好都在阈值之下；这个数是**策略**不是事实，改了不需要判据配合，但改了要说。
pub const MAX_FAILED_BOOTS: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootMode {
    Normal,
    Safe,
}

/// 0 = 还没决定（此时任何设备初始化都按 Normal 走，见 `optional_devices_allowed`），
/// 1 = Normal，2 = Safe
static MODE: AtomicU32 = AtomicU32::new(0);
/// 本次启动**读到的**那个数（写回的是它 +1），日志与判据都用它
static FAILED_SEEN: AtomicU32 = AtomicU32::new(0);
/// 读状态区的结果：0 = 成功，1 = 读不到（最坏情况）
static READ_FAILED: AtomicU32 = AtomicU32::new(0);

pub fn mode() -> BootMode {
    match MODE.load(Ordering::Relaxed) {
        2 => BootMode::Safe,
        _ => BootMode::Normal,
    }
}

pub fn decided() -> bool {
    MODE.load(Ordering::Relaxed) != 0
}

pub fn failed_seen() -> u32 {
    FAILED_SEEN.load(Ordering::Relaxed)
}

pub fn read_failed() -> bool {
    READ_FAILED.load(Ordering::Relaxed) != 0
}

/// 非必要设备（第二块盘、virtio 这类）还允许起吗。
/// **没决定之前返回 true**：本模块只在存储起来之后才跑，在那之前问到它的都是必要路径。
pub fn optional_devices_allowed() -> bool {
    mode() == BootMode::Normal
}

/// 从"连续失败几次"定模式。**纯函数**：判据可以不打盘就把阈值那条线钉住
/// （"读不到"走的就是这里 —— 调用方把最坏情况的数传进来）
pub fn mode_for(failed: u32) -> BootMode {
    if failed >= MAX_FAILED_BOOTS { BootMode::Safe } else { BootMode::Normal }
}

/// 读计数 → 定模式 → **立刻把 +1 写回盘**（先计数再进可能崩溃的路径）。
pub fn decide() {
    let (failed, st) = match state_store::read(state_store::KIND_BOOT) {
        Ok((_, _, st)) => (st.failed_boots, st),
        Err(e) => {
            READ_FAILED.store(1, Ordering::Relaxed);
            crate::log_warn!("boot: 状态区读不到 {:?}", e);
            // 最坏情况：当成"已经到了阈值"，进安全模式
            (MAX_FAILED_BOOTS, BootState::default())
        }
    };
    FAILED_SEEN.store(failed, Ordering::Relaxed);
    let m = mode_for(failed);
    MODE.store(if m == BootMode::Safe { 2 } else { 1 }, Ordering::Relaxed);
    let next = BootState { failed_boots: failed.saturating_add(1), ..st };
    let back = state_store::write(state_store::KIND_BOOT, &next);
    crate::log_info!(
        "boot: 模式={:?} 读到的连续失败={} 阈值={} 读不到={}",
        m,
        failed,
        MAX_FAILED_BOOTS,
        read_failed()
    );
    match back {
        Ok((slot, seq)) => crate::log_info!(
            "boot: 落盘 区LBA={} 槽={} 槽字节={} seq={} failed={} 种类={}",
            state_store::STATE_START_LBA,
            slot,
            state_store::SLOT_BYTES,
            seq,
            failed.saturating_add(1),
            state_store::KIND_BOOT
        ),
        Err(e) => crate::log_warn!("boot: 计数写不回盘（状态区坏了），这次只剩内存里的模式 {:?}", e),
    }
}

/// 健康条件达成：把计数清零（其余字段原样留着，槽位状态是 §9.5 的事）
pub fn mark_healthy() {
    let st = match state_store::read(state_store::KIND_BOOT) {
        Ok((_, _, st)) => st,
        Err(_) => BootState::default(),
    };
    match state_store::write(state_store::KIND_BOOT, &BootState { failed_boots: 0, ..st }) {
        Ok((slot, seq)) => crate::log_info!(
            "boot: 健康清零 落盘 区LBA={} 槽={} 槽字节={} seq={} failed={} 种类={}",
            state_store::STATE_START_LBA,
            slot,
            state_store::SLOT_BYTES,
            seq,
            0,
            state_store::KIND_BOOT
        ),
        Err(e) => crate::log_warn!("boot: 健康清零写不回盘 {:?}", e),
    }
}

/// 只给用例用的后门：临时把模式设成某个值，返回旧值好还原。
/// 真实启动路径上没人调它 —— 模式只能由 `decide()` 从盘上的数定出来。
pub fn force_for_test(m: BootMode) -> BootMode {
    let old = mode();
    MODE.store(if m == BootMode::Safe { 2 } else { 1 }, Ordering::Relaxed);
    old
}
