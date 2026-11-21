//! 信号（ADR-177 决策 1 的信号族 67/68/69）。
//!
//! ## 这一层只做三件事
//!
//! 1. **注册**：`sigaction(signo, handler, flags)` 把 handler 记进表；
//! 2. **投递**：在 ring3 返回路径上（`iretq` 之前）查「这个任务有没有待处理信号」，
//!    有就在用户栈上压一份 `TrapFrame` + 信号号，把 `rip` 改成 handler、`rsp` 改成压完之后的栈顶；
//! 3. **返回**：`sigreturn()` 从用户栈上把那份 `TrapFrame` 读回来，**整份覆盖**当前 frame，
//!    于是 `iretq` 自然回到被中断的那条指令。
//!
//! ## 为什么状态不放 `Task` 里
//!
//! `Task` 有 6 处字面量（`EMPTY_TASK` + 5 处 spawn 路径），加字段要全改，
//! 而信号是**一个任务一个位图 + 一张 handler 表**这种按任务索引的形状——
//! 与 `EXIT_CODES: [AtomicU32; MAX_TASKS_TOTAL]` 同一手法。
//! 独立成表还带来一个好处：`terminate_task` 只需要清一格，不用碰 `Task` 的构造。
//!
//! ## 今天**不做**的（如实写）
//!
//! - **信号帧压用户栈失败时的回滚**：压栈用 `copy_to_user`，失败就把信号丢掉并计数，
//!   任务继续跑。不杀任务——「投递失败」不等于「这个任务该杀」。
//! - **信号屏蔽字**：`sigmask` 只存不用（见 `sig_mask` 的注释）。
//! - **`SIGKILL`/`SIGSTOP` 不可捕获**：今天 kill 走的是 18/29 号的直接杀路径，**不经过信号**。
//!   把 kill 改成发信号是另一刀（它要改 18/29 的语义，属于已采纳 ADR 的范围）。
//! - **`EINTR`**：阻塞调用被信号打断的语义没有，因为今天的阻塞等待（17/19 号）不看信号。

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// 信号号上限（含）。Linux 是 64，这里取 32：一个 `u32` 位图装得下，
/// 而今天**没有任何**调用方需要第 33 号以后的信号。
pub const NSIG: u32 = 32;

/// 一次 `sigaction` 注册的 handler。`0` = 未注册（默认动作）。
///
/// 存成 `u64` 而不是函数指针：用户态地址，内核**不校验也不解引用**它——
/// 它只是被写进 `rip`。真正的校验发生在那一刻：跳到野地址 ⇒ 取指故障 ⇒ 该任务被 kill。
/// 这是刻意的：内核替用户态验地址，就要复制一份用户态的映射知识，而那份知识会漂。
type Handler = u64;

/// 每个任务一份信号状态。
#[derive(Clone, Copy)]
struct SigState {
    /// 待处理位图：bit i = 信号 i+1 待处理（bit 0 不用，因为信号从 1 开始）。
    pending: u32,
    /// 已注册 handler：`handlers[i]` 对应信号 i+1。0 = 默认动作。
    handlers: [Handler; NSIG as usize],
    /// 屏蔽字（今天只存不用，见模块头「今天不做的」）。
    mask: u32,
    /// 正在处理的信号（0 = 不在 handler 里）。用于「handler 里再收到同一信号」的判据。
    active: u32,
}

const SIG_EMPTY: SigState = SigState {
    pending: 0,
    handlers: [0; NSIG as usize],
    mask: 0,
    active: 0,
};

/// 表本身。用 `AtomicU64` 存位图与计数，`handlers` 用 `AtomicU64` 数组——
/// 因为它在 IRQ 上下文里被读（返回路径），不能是普通 `static mut`。
struct SigTable {
    pending: [AtomicU32; MAX_SIG_TASKS],
    active: [AtomicU32; MAX_SIG_TASKS],
    mask: [AtomicU32; MAX_SIG_TASKS],
    handlers: [[AtomicU64; NSIG as usize]; MAX_SIG_TASKS],
}

/// 与 `sched::MAX_TASKS_TOTAL` 同一个数。这里**另写一份**而不是引用：
/// `signal` 是 `sched` 的下游，引用它会把依赖方向倒过来（`check-module-interfaces` 会红）。
/// 两份数字由 `t_signal_arity` 对账。
const MAX_SIG_TASKS: usize = 96;

const Z32: AtomicU32 = AtomicU32::new(0);
const Z64: AtomicU64 = AtomicU64::new(0);

static SIG: SigTable = SigTable {
    pending: [Z32; MAX_SIG_TASKS],
    active: [Z32; MAX_SIG_TASKS],
    mask: [Z32; MAX_SIG_TASKS],
    // 嵌套数组的 const 初始化：内层用 `const {}` 块（`[Z64; N]` 要求 Copy，AtomicU64 不是 Copy）
    handlers: [const { [Z64; NSIG as usize] }; MAX_SIG_TASKS],
};

/// 投递计数：判据要能分辨「投递了」与「根本没走到」。
static DELIVERED: AtomicU64 = AtomicU64::new(0);
/// 投递失败（压栈失败）的次数。**与投递成功分开数**：
/// 合成一个数会让「信号丢了」这件事没有证据。
static DROPPED: AtomicU64 = AtomicU64::new(0);
static RETURNED: AtomicU64 = AtomicU64::new(0);

pub fn delivered() -> u64 {
    DELIVERED.load(Ordering::Relaxed)
}
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}
pub fn returned() -> u64 {
    RETURNED.load(Ordering::Relaxed)
}

/// 注册 handler。`handler == 0` 表示「恢复默认动作」。
///
/// 返回旧 handler（0 = 之前没注册）。`signo` 越界返回 `None`。
pub fn sigaction(task: usize, signo: u32, handler: Handler) -> Option<Handler> {
    if task >= MAX_SIG_TASKS || signo == 0 || signo > NSIG {
        return None;
    }
    let idx = (signo - 1) as usize;
    let old = SIG.handlers[task][idx].swap(handler, Ordering::AcqRel);
    Some(old)
}

/// 读一个任务已注册的 handler（0 = 没注册）。
pub fn handler_of(task: usize, signo: u32) -> Handler {
    if task >= MAX_SIG_TASKS || signo == 0 || signo > NSIG {
        return 0;
    }
    SIG.handlers[task][(signo - 1) as usize].load(Ordering::Acquire)
}

/// 把信号标记成待处理。返回 `true` = 这一位之前没置过（去重）。
///
/// **没有 handler 的信号直接丢弃并计数**：今天的默认动作不是「杀」（那要改 kill 语义），
/// 而是「忽略 + 留一条读数」。这比假装投递成功诚实。
pub fn raise(task: usize, signo: u32) -> bool {
    if task >= MAX_SIG_TASKS || signo == 0 || signo > NSIG {
        return false;
    }
    if handler_of(task, signo) == 0 {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let bit = 1u32 << (signo - 1);
    let prev = SIG.pending[task].fetch_or(bit, Ordering::AcqRel);
    prev & bit == 0
}

/// 取走一个待处理信号（最低位优先）。返回 0 = 没有。
pub fn take_pending(task: usize) -> u32 {
    if task >= MAX_SIG_TASKS {
        return 0;
    }
    loop {
        let cur = SIG.pending[task].load(Ordering::Acquire);
        if cur == 0 {
            return 0;
        }
        let bit = cur & cur.wrapping_neg(); // 最低置位
        if SIG.pending[task]
            .compare_exchange(cur, cur & !bit, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // 位号 -> 信号号（bit 0 => 信号 1）
            return bit.trailing_zeros() + 1;
        }
    }
}

pub fn set_active(task: usize, signo: u32) {
    if task < MAX_SIG_TASKS {
        SIG.active[task].store(signo, Ordering::Release);
    }
}
pub fn clear_active(task: usize) {
    if task < MAX_SIG_TASKS {
        SIG.active[task].store(0, Ordering::Release);
    }
}
pub fn active_of(task: usize) -> u32 {
    if task >= MAX_SIG_TASKS {
        return 0;
    }
    SIG.active[task].load(Ordering::Acquire)
}
pub fn set_mask(task: usize, mask: u32) -> u32 {
    if task >= MAX_SIG_TASKS {
        return 0;
    }
    SIG.mask[task].swap(mask, Ordering::AcqRel)
}
pub fn mask_of(task: usize) -> u32 {
    if task >= MAX_SIG_TASKS {
        return 0;
    }
    SIG.mask[task].load(Ordering::Acquire)
}

/// 清一个任务的全部信号状态（`terminate_task` 调）。
///
/// **必须清**：槽号是复用的，不清的话下一个复用这条槽的任务会继承死者的
/// handler 与待处理位——那是 ADR-061 未决 1 那条 ABA 的同一家族。
pub fn clear_task(task: usize) {
    if task >= MAX_SIG_TASKS {
        return;
    }
    SIG.pending[task].store(0, Ordering::Release);
    SIG.active[task].store(0, Ordering::Release);
    SIG.mask[task].store(0, Ordering::Release);
    for h in SIG.handlers[task].iter() {
        h.store(0, Ordering::Release);
    }
}

pub fn note_delivered() {
    DELIVERED.fetch_add(1, Ordering::Relaxed);
}
pub fn note_dropped() {
    DROPPED.fetch_add(1, Ordering::Relaxed);
}
pub fn note_returned() {
    RETURNED.fetch_add(1, Ordering::Relaxed);
}

/// 判据用：把三格计数归零（与 `user::clear_counters` 同一手法）。
pub fn reset_counters() {
    DELIVERED.store(0, Ordering::Relaxed);
    DROPPED.store(0, Ordering::Relaxed);
    RETURNED.store(0, Ordering::Relaxed);
}