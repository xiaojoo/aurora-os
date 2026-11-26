//! ADR-259：通知账本到共享 VMO 的页面镜像。只有 integration 能碰 Proc/句柄/VMO。

use crate::capability::handle::{self, Handle, HErr, RIGHT_READ, RIGHT_WRITE};
use crate::filesystem::block_notify::{self, NotifyEndpoint, NotifyError, NotifyRecord};
use crate::proc;
use crate::vmo;
use crate::vmo::{VmoError, VmoId};
use core::sync::atomic::Ordering;

pub const BROKER_RING_VA: u64 = 0x2_7000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerError {
    Notify(NotifyError),
    Vmo(VmoError),
    Handle(HErr),
    Dead,
    Spawn(&'static str),
    Wait(&'static str),
}

impl From<NotifyError> for BrokerError {
    fn from(error: NotifyError) -> Self {
        Self::Notify(error)
    }
}

impl From<VmoError> for BrokerError {
    fn from(error: VmoError) -> Self {
        Self::Vmo(error)
    }
}

impl From<HErr> for BrokerError {
    fn from(error: HErr) -> Self {
        Self::Handle(error)
    }
}

pub fn init_ring(vmo: VmoId, base_seq: u64) -> Result<(), BrokerError> {
    let mut header = [0u8; block_notify::NOTIFY_HEADER_BYTES];
    header[0..4].copy_from_slice(&block_notify::NOTIFY_MAGIC.to_le_bytes());
    header[4..8].copy_from_slice(&block_notify::NOTIFY_VERSION.to_le_bytes());
    header[8..12].copy_from_slice(&(block_notify::NOTIFY_SLOTS as u32).to_le_bytes());
    header[12..16].copy_from_slice(&(block_notify::NOTIFY_RECORD_BYTES as u32).to_le_bytes());
    header[block_notify::OFF_PRODUCER..block_notify::OFF_PRODUCER + 8]
        .copy_from_slice(&base_seq.to_le_bytes());
    header[block_notify::OFF_CONSUMED..block_notify::OFF_CONSUMED + 8]
        .copy_from_slice(&base_seq.to_le_bytes());
    vmo::vmo_write(vmo, 0, &header)?;
    Ok(())
}

pub fn mirror_record(vmo: VmoId, endpoint: NotifyEndpoint, record: NotifyRecord) -> Result<(), BrokerError> {
    let index = (record.seq - 1) % endpoint.capacity as u64;
    let offset = block_notify::NOTIFY_HEADER_BYTES + index as usize * block_notify::NOTIFY_RECORD_BYTES;
    vmo::vmo_write(vmo, offset, &record.to_bytes())?;
    vmo::vmo_atomic_store(vmo, block_notify::OFF_PRODUCER, record.seq, Ordering::Release)?;
    block_notify::mark_published(endpoint, record.seq)?;
    Ok(())
}

pub(crate) const BROKER_SID: u8 = 3;
const BROKER_SI_VA: u64 = 0x2_5000_0000 + BROKER_SID as u64 * 4096;
const CONFIG_OFF: usize = 280;
const CONFIG_BYTES: usize = 48;
const CONFIG_MAGIC: u32 = 0x424e_4f54;

fn dispatch(rax: u64, rdi: u64, rsi: u64, rdx: u64, r10: u64) -> u64 {
    let mut frame = crate::arch::x86_64::trap::TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10, r9: 0, r8: 0,
        rbp: 0, rdi, rsi, rdx, rcx: 0, rbx: 0, rax, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    };
    crate::user::syscall_dispatch(&mut frame);
    frame.rax
}

pub struct RunningBroker {
    pub endpoint: NotifyEndpoint,
    pub vmo: VmoId,
    pub ring_handle: Handle,
    pub owner: (usize, u32),
    pub pid: u16,
    pub proc_gen: u32,
    pub gidx: usize,
    pub tid: u32,
    pub job: u16,
    pub job_handle: Handle,
    pub si: VmoId,
    pub si_handle: Handle,
}

fn wait_task_resources(gidx: usize) -> bool {
    if crate::sched::owned_of(gidx) == 0 {
        return true;
    }
    let mut clean = false;
    crate::arch::x86_64::apic::with_interrupts(|| {
        let start = crate::tsc::now();
        while crate::tsc::now().wrapping_sub(start) < 1_000_000_000 {
            if crate::sched::owned_of(gidx) == 0 {
                clean = true;
                break;
            }
            crate::tsc::spin(20_000);
        }
    });
    clean
}

impl RunningBroker {
    pub fn pump(&self) -> Result<usize, BrokerError> {
        pump(self.vmo, self.ring_handle, self.owner, self.endpoint)
    }

    pub fn wait(self) -> Result<u32, BrokerError> {
        self.finish(false)
    }

    pub fn stop(self) -> Result<u32, BrokerError> {
        self.finish(true)
    }

    fn finish(self, kill_first: bool) -> Result<u32, BrokerError> {
        let mut cleanup = Cleanup {
            active: true,
            owner: self.owner,
            sid: BROKER_SID,
            job: Some(self.job),
            job_handle: Some(self.job_handle),
            proc: Some(self.pid),
            thread: Some(self.gidx),
            thread_id: Some(self.tid),
            proc_handle: None,
            thread_handle: None,
            si: Some(self.si),
            si_handle: Some(self.si_handle),
            ring: Some(self.vmo),
            ring_handle: Some(self.ring_handle),
            endpoint: Some(self.endpoint),
        };
        let first = if kill_first {
            None
        } else {
            crate::arch::x86_64::apic::with_interrupts(|| {
                crate::sched::wait_for_proc(self.pid, crate::clock::window_cycles(64))
            })
        };
        if first.is_none() {
            let _ = crate::sched::terminate_task(self.gidx);
            let second = crate::arch::x86_64::apic::with_interrupts(|| {
                crate::sched::wait_for_proc(self.pid, crate::clock::window_cycles(16))
            });
            if second.is_none() {
                return Err(BrokerError::Wait("broker 终止后仍未收工"));
            }
        }
        if !wait_task_resources(self.gidx) {
            return Err(BrokerError::Wait("broker 任务资源未交回"));
        }
        let _ = handle::revoke_task(self.gidx, self.tid);
        let consumed = vmo::vmo_atomic_load(self.vmo, block_notify::OFF_CONSUMED, Ordering::Acquire)?;
        if let Err(error) = block_notify::confirm_acked(self.endpoint, consumed) {
            if error != block_notify::NotifyError::StaleEndpoint {
                return Err(error.into());
            }
        }
        let info = proc::proc_info(self.pid as usize).ok_or(BrokerError::Dead)?;
        if info.gen != self.proc_gen || !info.terminated {
            return Err(BrokerError::Wait("broker Proc 世代或终止态不符"));
        }
        let code = proc::proc_reap(self.pid).map_err(|_| BrokerError::Wait("broker reap 失败"))?;
        #[cfg(feature = "fault-notify-panic-fatal")]
        {
            if code == 3 {
                crate::log_info!("notify-panic-fatal: 用户退出码 3 被变异档当成内核 fatal");
                crate::exit::finish(crate::exit::Code::ExceptionFatal);
            }
        }
        cleanup.proc = None;
        cleanup.thread = None;
        Ok(code)
    }
}

struct Cleanup {
    active: bool,
    owner: (usize, u32),
    sid: u8,
    job: Option<u16>,
    job_handle: Option<Handle>,
    proc: Option<u16>,
    thread: Option<usize>,
    thread_id: Option<u32>,
    proc_handle: Option<Handle>,
    thread_handle: Option<Handle>,
    si: Option<VmoId>,
    si_handle: Option<Handle>,
    ring: Option<VmoId>,
    ring_handle: Option<Handle>,
    endpoint: Option<NotifyEndpoint>,
}

impl Cleanup {
    fn fail(mut self, site: &'static str) -> BrokerError {
        self.active = true;
        drop(self);
        BrokerError::Spawn(site)
    }

    fn disarm(mut self) {
        self.active = false;
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(endpoint) = self.endpoint.take() {
            let _ = block_notify::invalidate(endpoint);
        }
        if let Some(thread) = self.thread.take() {
            let _ = crate::sched::terminate_task(thread);
            let _ = wait_task_resources(thread);
            if let Some(tid) = self.thread_id.take() {
                let _ = handle::revoke_task(thread, tid);
            }
        }
        if let Some(proc) = self.proc.take() {
            if self.thread_handle.is_some() || proc::proc_info(proc as usize).is_some_and(|info| info.threads > 0) {
                let _ = proc::proc_reap(proc);
            } else {
                let _ = proc::proc_discard(proc);
            }
        }
        for handle in [self.proc_handle.take(), self.thread_handle.take(), self.si_handle.take(), self.ring_handle.take(), self.job_handle.take()].into_iter().flatten() {
            let _ = handle::close(handle, self.owner);
        }
        if let Some(si) = self.si.take() {
            vmo::vmo_unref(si);
        }
        if let Some(ring) = self.ring.take() {
            vmo::vmo_unref(ring);
        }
        if let Some(job) = self.job.take() {
            let _ = proc::job_destroy(job);
        }
        crate::user::session_release_va(self.sid);
    }
}

/// 创建独立 ring3 broker；不新增 syscall，仍走 11/14/15/16 的既有产品序列。
pub fn spawn(mode: u32) -> Result<RunningBroker, BrokerError> {
    let Some(owner) = crate::sched::current_identity() else { return Err(BrokerError::Spawn("无身份")) };
    let mut cleanup = Cleanup {
        active: true, owner, sid: BROKER_SID,
        job: None, job_handle: None, proc: None, thread: None, thread_id: None,
        proc_handle: None, thread_handle: None, si: None, si_handle: None,
        ring: None, ring_handle: None, endpoint: None,
    };
    macro_rules! bail {
        ($site:literal) => {{ return Err(cleanup.fail($site)); }};
    }

    let job = match proc::job_create(None, 2, 64) {
        Ok(job) => job,
        Err(_) => bail!("job_create"),
    };
    cleanup.job = Some(job);
    let Some(job_gen) = proc::job_gen(job) else { bail!("job_gen") };
    let job_handle = match handle::grant_job(
        owner, job, job_gen, handle::RIGHT_READ | handle::RIGHT_CREATE | handle::RIGHT_TRANSFER,
    ) {
        Ok(handle) => handle,
        Err(_) => bail!("grant_job"),
    };
    cleanup.job_handle = Some(job_handle);
    let proc_ret = dispatch(crate::user::SYS_PROCESS_CREATE, job_handle.0, 0, 0, 0);
    let proc_handle = Handle(proc_ret);
    let (pid, proc_gen) = match handle::resolve(proc_handle, owner, 0) {
        Ok((handle::ObjRef::Proc { slot, gen }, _)) => (slot, gen),
        _ => bail!("resolve_proc"),
    };
    cleanup.proc = Some(pid);
    cleanup.proc_handle = Some(proc_handle);
    let Some((aslot, _)) = proc::proc_aspace(pid, proc_gen) else { bail!("proc_aspace") };

    crate::user::begin_session_load(BROKER_SID);
    let loaded = match crate::user::load_into(aslot, crate::ktests::common::NOTIFY_ELF) {
        Ok(loaded) => loaded,
        Err(_) => {
            crate::user::end_session_load();
            bail!("load_into");
        }
    };
    if loaded.owned.into_current().is_err() {
        crate::user::end_session_load();
        bail!("owned_into_current");
    }
    let si = match vmo::vmo_create(1) { Ok(vmo) => vmo, Err(_) => bail!("si_vmo") };
    cleanup.si = Some(si);
    let si_handle = match handle::grant_vmo(owner, si, handle::RIGHT_READ | handle::RIGHT_WRITE | handle::RIGHT_MAP) {
        Ok(handle) => handle,
        Err(_) => bail!("grant_si"),
    };
    cleanup.si_handle = Some(si_handle);
    let ring = match vmo::vmo_create(1) { Ok(vmo) => vmo, Err(_) => bail!("ring_vmo") };
    cleanup.ring = Some(ring);
    let ring_handle = match handle::grant_vmo(owner, ring, handle::RIGHT_READ | handle::RIGHT_WRITE | handle::RIGHT_MAP) {
        Ok(handle) => handle,
        Err(_) => bail!("grant_ring"),
    };
    cleanup.ring_handle = Some(ring_handle);

    let base_seq = block_notify::stats().acked_seq;
    if init_ring(ring, base_seq).is_err() { bail!("init_ring") }
    let mut header = [0u8; 24];
    header[0..4].copy_from_slice(&crate::user::SI_MAGIC.to_le_bytes());
    header[4..6].copy_from_slice(&(crate::user::ABI_MAJOR as u16).to_le_bytes());
    header[6..8].copy_from_slice(&(crate::user::ABI_MINOR as u16).to_le_bytes());
    header[12..16].copy_from_slice(&(CONFIG_OFF as u32).to_le_bytes());
    header[16..20].copy_from_slice(&(CONFIG_BYTES as u32).to_le_bytes());
    let mut config = [0u8; CONFIG_BYTES];
    config[0..4].copy_from_slice(&CONFIG_MAGIC.to_le_bytes());
    config[4..8].copy_from_slice(&1u32.to_le_bytes());
    config[8..16].copy_from_slice(&BROKER_RING_VA.to_le_bytes());
    config[16..20].copy_from_slice(&(block_notify::NOTIFY_SLOTS as u32).to_le_bytes());
    config[20..24].copy_from_slice(&(block_notify::NOTIFY_RECORD_BYTES as u32).to_le_bytes());
    config[24..28].copy_from_slice(&mode.to_le_bytes());
    config[28..32].copy_from_slice(&proc_gen.to_le_bytes());
    config[32..40].copy_from_slice(&ring_handle.gen().to_le_bytes());
    if vmo::vmo_write(si, 0, &header).is_err() || vmo::vmo_write(si, CONFIG_OFF, &config).is_err() {
        bail!("si_write")
    }
    let si_map = dispatch(crate::user::SYS_ASPACE_MAP, si_handle.0, 0, proc_handle.0, BROKER_SI_VA);
    let ring_map = dispatch(crate::user::SYS_ASPACE_MAP, ring_handle.0, 1, proc_handle.0, BROKER_RING_VA);
    crate::user::end_session_load();
    if si_map != BROKER_SI_VA || ring_map != BROKER_RING_VA { bail!("aspace_map") }

    let endpoint = match block_notify::install(NotifyEndpoint {
        proc: pid, proc_gen, vmo: ring.slot(), vmo_gen: ring_handle.gen(),
        ring_va: BROKER_RING_VA, capacity: block_notify::NOTIFY_SLOTS as u16, generation: 0,
    }) {
        Ok(endpoint) => endpoint,
        Err(_) => bail!("install_endpoint"),
    };
    cleanup.endpoint = Some(endpoint);
    let thread_ret = dispatch(
        crate::user::SYS_THREAD_CREATE, proc_handle.0, loaded.entry, loaded.stack_top, 0,
    );
    let thread_handle = Handle(thread_ret);
    let (gidx, tid) = match handle::resolve(thread_handle, owner, 0) {
        Ok((handle::ObjRef::Thread { gidx, id }, _)) => (gidx, id),
        _ => bail!("resolve_thread"),
    };
    cleanup.thread = Some(gidx);
    cleanup.thread_id = Some(tid);
    cleanup.thread_handle = Some(thread_handle);
    let started = dispatch(
        crate::user::SYS_PROCESS_START, proc_handle.0, thread_handle.0, si_handle.0, BROKER_SI_VA,
    );
    if started != 0 { bail!("process_start") }
    let _ = handle::close(proc_handle, owner);
    let _ = handle::close(thread_handle, owner);
    cleanup.proc_handle = None;
    cleanup.thread_handle = None;
    let _ = crate::arch::x86_64::apic::timer_start();
    let running = RunningBroker {
        endpoint, vmo: ring, ring_handle, owner, pid, proc_gen, gidx, tid,
        job, job_handle, si, si_handle,
    };
    cleanup.disarm();
    Ok(running)
}

fn validate(vmo: VmoId, handle: Handle, owner: (usize, u32), endpoint: NotifyEndpoint) -> Result<(), BrokerError> {
    let info = proc::proc_info(endpoint.proc as usize).ok_or(BrokerError::Dead)?;
    if info.gen != endpoint.proc_gen || info.terminated || info.threads == 0 {
        return Err(BrokerError::Dead);
    }
    if handle.gen() != endpoint.vmo_gen {
        return Err(BrokerError::Handle(HErr::Stale));
    }
    let current = handle::vmo_of(handle, owner, RIGHT_READ | RIGHT_WRITE)?;
    if current != vmo || vmo::vmo_pages(vmo) != Some(1) {
        return Err(BrokerError::Handle(HErr::Denied));
    }
    Ok(())
}

/// 先确认 consumed，再把未发布记录逐条写页并 Release producer；满环时等待，不覆盖。
pub fn pump(
    vmo: VmoId,
    handle: Handle,
    owner: (usize, u32),
    endpoint: NotifyEndpoint,
) -> Result<usize, BrokerError> {
    if let Err(error) = validate(vmo, handle, owner, endpoint) {
        let _ = block_notify::invalidate(endpoint);
        return Err(error);
    }
    let consumed = vmo::vmo_atomic_load(vmo, block_notify::OFF_CONSUMED, Ordering::Acquire)?;
    block_notify::confirm_acked(endpoint, consumed)?;
    let mut written = 0usize;
    for _ in 0..block_notify::NOTIFY_SLOTS {
        let Some(record) = block_notify::next_to_write(endpoint)? else { break };
        mirror_record(vmo, endpoint, record)?;
        written += 1;
    }
    Ok(written)
}
