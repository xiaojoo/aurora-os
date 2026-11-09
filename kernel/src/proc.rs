//! W3 P3（ADR-073）：进程与 Job 对象。
//!
//! 今天**没有 syscall**——这些对象只由内核/ktest 直接创建。用户态看不见它们（P4+ 才接）。
//! 形状：定长表 + 显式名单（与 ADR-069 的 resident 同律）；额度只收窄（Q7 裁决）。
//!
//! Q7 裁的是"进程数 + 页数"两项额度。**本轮只落进程数那一项的用量计量**：页数要有
//! "进程名下有哪些页"才有得可加，而进程到 AS/VMO 的归属是 P4 的东西。所以 `max_pages`
//! 现在只参与**子 Job 收窄**这条检查，用量与超页拒绝留到 P4（写在 ADR-073 的"本轮没做"里）。
//!
//! 锁的三条分界（硬约束 6：故障路径不等锁）：
//! - **表结构**（占槽/还槽/额度）只在 VMM(20) 内改：`job_create`、`proc_create`、
//!   `proc_attach_thread`、`proc_reap`、`proc_discard`、`job_destroy`、`reset_for_test`；
//! - **收工出口**（`proc_thread_exited`）可能被故障路径调到，那里 VMM 可能已被本 CPU 持有，
//!   所以它一个锁都不取，只动原子量（`used`/`threads`/`signal`）。
//!   代价是额度要等到 `proc_reap` 才归还——这正是主流的"僵尸仍占额度"口径：
//!   记录必须在等待者读到结局之后才消失，否则退出码无处可读。
//! - **计数读数**（`proc_count`/`job_count`）也不取锁：用例收尾的扫描（`main.rs::finish_sweep`）
//!   按 ADR-069 是"只读快照、不拿锁"的，为此两张表的 `used` 都是 `AtomicBool`。

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use crate::mm;

pub const MAX_PROCESSES: usize = 4;
pub const MAX_JOBS: usize = 4;
/// Task.proc_id 的"无进程"哨兵。
pub const NO_PROC: u16 = 0xFFFF;
/// `ProcEntry::aspace` 的"这个进程还没有地址空间"哨兵（与 `sched::NO_ASPACE` 同值不同模块）。
pub const NO_ASPACE: u8 = 0xFF;
/// signal：bit31 = 0 表示还在跑。
const SIG_RUNNING: u32 = 0;
/// signal：bit31 = 1 表示已终止，低 31 位是退出码。
const SIG_TERMINATED: u32 = 1 << 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcError {
    TableFull,
    NoSuchJob,
    /// 状态不允许：子 Job 放大额度、收还在跑的进程、销毁名下还有进程的 Job。
    Denied,
    QuotaProcs,
    NoSuchProc,
    /// 想往一个已进入终止态的进程上挂线程。
    AlreadyTerminated,
    InvalidArgument,
}

// ---------------------------------------------------------------- 两张表

struct JobEntry {
    used: AtomicBool,
    /// **对象世代号**（P5c-1，ADR-075 决策 4 的补充）。`job_create` 在旧值上 +1，
    /// `job_destroy` **不清零也不复位** ⇒ 槽位被复用时旧值仍然对不上。
    /// 句柄表里存的是 `(slot, gen)` 两格：只有槽号对、世代不对 ⇒ `NoSuch`（保守拒绝），
    /// 这一位是"句柄不能指着别人新造的 Job"的唯一凭据，`used` 单独不够。
    gen: u32,
    max_procs: u32,
    /// 只参与收窄检查，用量计量在 P4（见模块头）。
    max_pages: u64,
    used_procs: u32,
}

struct ProcEntry {
    used: AtomicBool,
    /// 同 `JobEntry::gen`（P5c-1）：`proc_create` +1，销毁不复位。
    gen: u32,
    /// 只在 `used` 为真期间有效；由 `proc_create` 在 VMM 内写，`proc_reap`/`proc_discard` 在 VMM 内读。
    job: u16,
    threads: AtomicU16,
    signal: AtomicU32,
    /// 这个进程名下那张 AS 的 `(槽号, 世代)`（P5c-3a，ADR-075 决策 8）。
    /// **主人是这张表**，不是 RAII 柄：`AspaceHandle` 是 non-Copy 且 Drop 里要取 VMM，
    /// 放进表里既不能 const 初始化也不能在锁内丢（P1 撞过）。销毁走 `mm::aspace_destroy`，
    /// 而且**必须在放掉 VMM 之后**调（它自己要取 VMM，锁内调就是重入 ⇒ L4）。
    aspace: u8,
    as_gen: u32,
}

const JOB_EMPTY: JobEntry = JobEntry {
    used: AtomicBool::new(false),
    gen: 0,
    max_procs: 0,
    max_pages: 0,
    used_procs: 0,
};

const PROC_EMPTY: ProcEntry = ProcEntry {
    used: AtomicBool::new(false),
    gen: 0,
    aspace: NO_ASPACE,
    as_gen: 0,
    job: 0,
    threads: AtomicU16::new(0),
    signal: AtomicU32::new(SIG_RUNNING),
};

struct ProcState {
    procs: [ProcEntry; MAX_PROCESSES],
    jobs: [JobEntry; MAX_JOBS],
}

struct StateCell(core::cell::UnsafeCell<ProcState>);
// SAFETY: 非原子字段（`job`、`max_*`、`used_procs`）只在 VMM(20) 内读写；
// `used`/`threads`/`signal` 是原子量，收工出口与等待方、收尾扫描在锁外碰它们（见模块头的三条分界）。
// 互斥由 VMM 提供，可见性由 Ordering 提供。
unsafe impl Sync for StateCell {}

static S: StateCell = StateCell(core::cell::UnsafeCell::new(ProcState {
    procs: [PROC_EMPTY, PROC_EMPTY, PROC_EMPTY, PROC_EMPTY],
    jobs: [JOB_EMPTY, JOB_EMPTY, JOB_EMPTY, JOB_EMPTY],
}));

/// 持 VMM 时的表引用。
fn st() -> &'static mut ProcState {
    // SAFETY: 调用方持 VMM（本模块所有表操作都在 with_vmm_lock 闭包里）
    unsafe { &mut *S.0.get() }
}

/// 锁外的表引用：**只允许碰原子字段**。
fn st_atomic() -> &'static ProcState {
    // SAFETY: 见上面 Sync 的论证。调用方（proc_thread_exited / proc_signal / 两个 count）
    // 只读 used、只读写 threads/signal，不读非原子的 job，也不碰 jobs 表的其余字段。
    unsafe { &*S.0.get() }
}

fn alive_flag(f: &AtomicBool) -> bool {
    f.load(Ordering::Acquire)
}

// ---------------------------------------------------------------- 创建 / 销毁

/// 创建一个 Job（根 Job 传 `None`）。子 Job 的额度只能收窄（Q7）。
pub fn job_create(parent: Option<u16>, max_procs: u32, max_pages: u64) -> Result<u16, ProcError> {
    if max_procs == 0 {
        return Err(ProcError::InvalidArgument);
    }
    mm::with_vmm_lock(|| {
        let s = st();
        if let Some(p) = parent {
            let pe = s.jobs.get(p as usize).ok_or(ProcError::NoSuchJob)?;
            if !alive_flag(&pe.used) {
                return Err(ProcError::NoSuchJob);
            }
            if max_procs > pe.max_procs || max_pages > pe.max_pages {
                return Err(ProcError::Denied);
            }
        }
        let slot = s.jobs.iter().position(|j| !alive_flag(&j.used)).ok_or(ProcError::TableFull)?;
        s.jobs[slot] = JobEntry {
            used: AtomicBool::new(true),
            gen: s.jobs[slot].gen.wrapping_add(1),
            max_procs,
            max_pages,
            used_procs: 0,
        };
        Ok(slot as u16)
    })
}

/// 创建一个进程，占住 Job 的一个进程额度。返回进程表槽号。
pub fn proc_create(job: u16) -> Result<u16, ProcError> {
    mm::with_vmm_lock(|| {
        let s = st();
        let j = s.jobs.get_mut(job as usize).ok_or(ProcError::NoSuchJob)?;
        if !alive_flag(&j.used) {
            return Err(ProcError::NoSuchJob);
        }
        if j.used_procs >= j.max_procs {
            return Err(ProcError::QuotaProcs);
        }
        let slot = s
            .procs
            .iter()
            .position(|p| !alive_flag(&p.used))
            .ok_or(ProcError::TableFull)?;
        s.procs[slot].gen = s.procs[slot].gen.wrapping_add(1);
        s.procs[slot].job = job;
        s.procs[slot].threads.store(0, Ordering::Relaxed);
        s.procs[slot].signal.store(SIG_RUNNING, Ordering::Relaxed);
        s.procs[slot].used.store(true, Ordering::Release);
        j.used_procs += 1;
        Ok(slot as u16)
    })
}

/// 撤掉一次登记（**只给创建失败的回滚路径用**，P5c-3）。
/// 与 `proc_thread_exited` 的差别：那条是"线程真的跑完并收工"，会写结局信号；
/// 这条是"线程根本没建起来"，只把计数减回去，**不碰 signal**——
/// 否则一次失败的 thread_create 会把整个进程标成已终止。
pub fn proc_detach_thread(proc_id: u16) -> Result<(), ProcError> {
    mm::with_vmm_lock(|| {
        let s = st();
        let p = s.procs.get_mut(proc_id as usize).ok_or(ProcError::NoSuchProc)?;
        if !alive_flag(&p.used) {
            return Err(ProcError::NoSuchProc);
        }
        let n = p.threads.load(Ordering::Acquire);
        if n == 0 {
            return Err(ProcError::Denied);
        }
        p.threads.store(n - 1, Ordering::Release);
        Ok(())
    })
}

/// 给进程登记一条线程（**在 `spawn` 之前**调：反序的话任务可能两步之间就跑完了，
/// 那条边看到的是 `NO_PROC`，计数永远减不到）。
pub fn proc_attach_thread(proc_id: u16) -> Result<(), ProcError> {
    mm::with_vmm_lock(|| {
        let s = st();
        let p = s.procs.get_mut(proc_id as usize).ok_or(ProcError::NoSuchProc)?;
        if !alive_flag(&p.used) {
            return Err(ProcError::NoSuchProc);
        }
        if p.signal.load(Ordering::Relaxed) & SIG_TERMINATED != 0 {
            return Err(ProcError::AlreadyTerminated);
        }
        p.threads.fetch_add(1, Ordering::AcqRel);
        Ok(())
    })
}

/// 收工出口调：**不取锁**。减线程计数；最后一条线程退出时把进程置成终止态（僵尸）。
/// 额度与槽位留到 `proc_reap` 才还。
pub fn proc_thread_exited(proc_id: u16, exit_code: u32) {
    if proc_id == NO_PROC {
        return;
    }
    let s = st_atomic();
    if let Some(p) = s.procs.get(proc_id as usize) {
        if !alive_flag(&p.used) {
            return;
        }
        // 每条线程都要减，只有最后一条置 signal；置过之后再减不覆盖结局。
        if p.threads.fetch_sub(1, Ordering::AcqRel) <= 1 {
            p.signal.store(SIG_TERMINATED | (exit_code & !SIG_TERMINATED), Ordering::Release);
        }
    }
}

/// 收走一个**已终止**的进程（僵尸）：还额度、清槽，返回退出码。
/// 只在进程上下文里调（取 VMM），**不在故障路径上**。
pub fn proc_reap(proc_id: u16) -> Result<u32, ProcError> {
    let (code, aspace) = mm::with_vmm_lock(|| {
        let s = st();
        let p = s.procs.get_mut(proc_id as usize).ok_or(ProcError::NoSuchProc)?;
        if !alive_flag(&p.used) {
            return Err(ProcError::NoSuchProc);
        }
        let sig = p.signal.load(Ordering::Acquire);
        if sig & SIG_TERMINATED == 0 {
            return Err(ProcError::Denied);
        }
        let code = sig & !SIG_TERMINATED;
        let job = p.job;
        let aspace = p.aspace;
        // **gen 必须活过销毁**（P5c-3a 修的那条 ABA）：整项写回 EMPTY 会把 gen 复位成 0，
        // 下一次 create 又变 1 ⇒ 旧句柄的 `(slot, gen)` 重新匹配上。
        let gen = p.gen;
        *p = PROC_EMPTY;
        p.gen = gen;
        if let Some(j) = s.jobs.get_mut(job as usize) {
            j.used_procs = j.used_procs.saturating_sub(1);
        }
        Ok((code, aspace))
    })?;
    // 锁外销毁：`aspace_destroy` 自己取 VMM，留在上面那个闭包里就是重入
    if aspace != NO_ASPACE {
        mm::aspace_destroy(aspace);
    }
    Ok(code)
}

/// 回滚一条**还没起过线程**的进程记录（占额度的动作已经发生，线程创建失败要能退回去）。
/// 有线程或已终止的一律拒绝——那种结局只能走 `proc_reap`。
pub fn proc_discard(proc_id: u16) -> Result<(), ProcError> {
    let aspace = mm::with_vmm_lock(|| {
        let s = st();
        let p = s.procs.get_mut(proc_id as usize).ok_or(ProcError::NoSuchProc)?;
        if !alive_flag(&p.used) {
            return Err(ProcError::NoSuchProc);
        }
        if p.threads.load(Ordering::Acquire) != 0
            || p.signal.load(Ordering::Acquire) != SIG_RUNNING
        {
            return Err(ProcError::Denied);
        }
        let job = p.job;
        let aspace = p.aspace;
        // **gen 必须活过销毁**（P5c-3a 修的那条 ABA）：整项写回 EMPTY 会把 gen 复位成 0，
        // 下一次 create 又变 1 ⇒ 旧句柄的 `(slot, gen)` 重新匹配上。
        let gen = p.gen;
        *p = PROC_EMPTY;
        p.gen = gen;
        if let Some(j) = s.jobs.get_mut(job as usize) {
            j.used_procs = j.used_procs.saturating_sub(1);
        }
        Ok(aspace)
    })?;
    if aspace != NO_ASPACE {
        mm::aspace_destroy(aspace);
    }
    Ok(())
}

// ---------------------------------------------------------------- 读数

/// 记下这个进程名下那张 AS（`process_create` 用）。槽号与世代一起存，
/// 理由同句柄：槽号复用，只有 `(slot, gen)` 才能证明"还是当初那张表"。
pub fn proc_set_aspace(proc_id: u16, slot: u8, gen: u32) -> Result<(), ProcError> {
    mm::with_vmm_lock(|| {
        let s = st();
        let p = s.procs.get_mut(proc_id as usize).ok_or(ProcError::NoSuchProc)?;
        if !alive_flag(&p.used) {
            return Err(ProcError::NoSuchProc);
        }
        if p.aspace != NO_ASPACE {
            // 一个进程只有一张 AS；重复登记是调用方的错，不静默覆盖（覆盖就漏一张表）
            return Err(ProcError::Denied);
        }
        p.aspace = slot;
        p.as_gen = gen;
        Ok(())
    })
}

/// 这个进程名下那张 AS 的 `(槽号, 世代)`；没有或进程已不在返回 None。
/// `gen` 必须与 `proc_gen` 读到的那一次一致（调用方拿 Proc 句柄里的世代来核）。
pub fn proc_aspace(proc_id: u16, gen: u32) -> Option<(u8, u32)> {
    mm::with_vmm_lock(|| {
        let s = st();
        let p = s.procs.get(proc_id as usize)?;
        if !alive_flag(&p.used) || p.gen != gen || p.aspace == NO_ASPACE {
            return None;
        }
        Some((p.aspace, p.as_gen))
    })
}

/// 读进程的 signal。0=还在跑，bit31=已终止（低 31 位=退出码）。
/// `NO_PROC` 与空槽一律读成"已终止、码 0"：调用方是等待方，读到"永不终止"会空转到超时。
pub fn proc_signal(proc_id: u16) -> u32 {
    if proc_id == NO_PROC {
        return SIG_TERMINATED;
    }
    let s = st_atomic();
    match s.procs.get(proc_id as usize) {
        Some(p) if alive_flag(&p.used) => p.signal.load(Ordering::Acquire),
        _ => SIG_TERMINATED,
    }
}

/// 进程是否已终止（僵尸态也算——记录还在，退出码还读得到）。
pub fn proc_is_terminated(proc_id: u16) -> bool {
    proc_signal(proc_id) & SIG_TERMINATED != 0
}

/// 退出码（低 31 位）。
pub fn proc_exit_code(proc_id: u16) -> u32 {
    proc_signal(proc_id) & !SIG_TERMINATED
}

/// 收尾扫描与额度读数用：占着的进程槽数 + 首个槽号（`u16::MAX` = 一个都没有）。
/// 含僵尸——僵尸的记录还没交出去，本来就该被点名。不取锁：见模块头的第三条分界。
/// 这个 Job 槽**当前这次使用**的世代号（不存在返回 None）。
/// 与 `job_create` 的返回值配对用：句柄要存 `(slot, gen)`。
/// 取 VMM 只读一个数；跨 CPU 的"读到的 gen 已经过期"只会让发出去的句柄一落地就 `NoSuch`
/// （fail-closed），不会把别人的 Job 错认成自己的。
pub fn job_gen(job: u16) -> Option<u32> {
    mm::with_vmm_lock(|| {
        let s = st();
        let e = s.jobs.get(job as usize)?;
        if alive_flag(&e.used) { Some(e.gen) } else { None }
    })
}

/// 进程版的 `job_gen`。
pub fn proc_gen(proc_id: u16) -> Option<u32> {
    mm::with_vmm_lock(|| {
        let s = st();
        let e = s.procs.get(proc_id as usize)?;
        if alive_flag(&e.used) { Some(e.gen) } else { None }
    })
}

/// `(槽号, 世代)` 两者都对才算活着（句柄使用前的活性判据）。
pub fn job_live(job: u16, gen: u32) -> bool {
    job_gen(job) == Some(gen)
}

/// 进程版的 `job_live`。
pub fn proc_live(proc_id: u16, gen: u32) -> bool {
    proc_gen(proc_id) == Some(gen)
}

pub fn proc_residual() -> (usize, u16) {
    let mut n = 0usize;
    let mut first = u16::MAX;
    for (i, p) in st_atomic().procs.iter().enumerate() {
        if alive_flag(&p.used) {
            n += 1;
            if first == u16::MAX {
                first = i as u16;
            }
        }
    }
    (n, first)
}

/// 同上，Job 表。
pub fn job_residual() -> (usize, u16) {
    let mut n = 0usize;
    let mut first = u16::MAX;
    for (i, j) in st_atomic().jobs.iter().enumerate() {
        if alive_flag(&j.used) {
            n += 1;
            if first == u16::MAX {
                first = i as u16;
            }
        }
    }
    (n, first)
}

/// 一个 Job 名下还占着的进程数（额度可见性；额度格与收尾格都读它）。
pub fn job_used_procs(job: u16) -> Option<u32> {
    mm::with_vmm_lock(|| {
        let j = st().jobs.get(job as usize)?;
        if !alive_flag(&j.used) {
            return None;
        }
        Some(j.used_procs)
    })
}

/// 销毁一个 Job（名下进程额度必须已清零）。
pub fn job_destroy(job: u16) -> Result<(), ProcError> {
    mm::with_vmm_lock(|| {
        let s = st();
        let j = s.jobs.get_mut(job as usize).ok_or(ProcError::NoSuchJob)?;
        if !alive_flag(&j.used) {
            return Err(ProcError::NoSuchJob);
        }
        if j.used_procs != 0 {
            return Err(ProcError::Denied);
        }
        // 同 `proc_reap`/`proc_discard`：gen 活过销毁
        let gen = j.gen;
        *j = JOB_EMPTY;
        j.gen = gen;
        Ok(())
    })
}
