//! `IrqSpinLock`（手册 §7.1，V1.2 R16 的五条修改全部落在这里）。
//!
//! M3a 时这里只能测**重入检测与锁序**，因为系统里只有一个运行中的核（AP 停在 bootloader
//! 的停车点上，ADR-014/019）。M3b 放 AP 之后，本文件有三条**因为多核才暴露出来**的错，
//! 都已经在下面这些代码里改掉，每条都对应一次真实的红：
//! * 预读说空闲、CAS 却失败 ⇒ 旧实现当"状态被写坏"当场 L4。多核下这是一次正常竞争。
//! * 等级栈 `INNERMOST` 是一份全局值 ⇒ 两个 CPU 交错取锁会互相伪造"外层等级"，
//!   报出根本不存在的嵌套。现在按 CPU 槽位各存一份。
//! * 等锁上界是"自旋 2^32 次" ⇒ 那不是看门狗。现在按时间界判，并把等待本身记成数字。
//!
//! 还有两条今天**仍然**测不到，不要写成已验证：
//! * `Mapping::drop` 依赖的 TLB shootdown（§6.6）还没实现，所以"持锁期间另一个 CPU
//!   还在用旧 TLB 条目"这条路没被测过；
//! * 中断上下文里取锁的禁令只有堆这一把有守卫（`heap::refuse_if_isr`），其它锁没有。
//!
//! 四个设计点：
//! 1. **持有者令牌是本 CPU 的 LAPIC id**（理由写在 `cpu_token` 上：用栈帧地址判不出
//!    "同一 CPU 的第二个栈帧重入同一把锁"，那种自死锁只会退化成关中断自旋）。
//!    多核下它顺带解决了另一个问题：两个 CPU 不可能撞出同一个令牌，前提是
//!    `cpu::reserve_ap_slot` 拒绝重复 id——那条检查不是洁癖，是这条判据的地基。
//! 2. **`lockdep` 只在 CAS 成功之后记录**。§7.1 R16 的原文理由：在抢占成功之前记录，
//!    失败的那次获取也会污染依赖图 ⇒ 假阳性 ⇒  eventually 有人把 lockdep 关掉。
//! 3. **守卫 `#[must_use]`**：丢弃它等于立刻释放，锁就白拿了。
//! 4. **不做 Relaxed 预读**：多核下预读的结果在 CAS 时一律可能已经失效，留着只会诱导
//!    "预读说空闲就可以直接写"这种错误分支——旧实现就是这么写出那条假的 L4 的。

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockRank(pub u8);

/// 等级就是"从外到内的获取顺序"，数值小的先拿、嵌套时必须严格递增。
/// 今天真实的嵌套链只有一条，所以这张表的次序不是排版而是调用关系：
/// `堆(10) -> VMM(20) -> PMM(30) -> 台账(40)`；ACPI(50) 目前只在启动期单独用。
/// 新增一把锁必须先改 `docs/architecture/lock-order.md`（§7.1 的原文要求）。
pub const RANK_HEAP: LockRank = LockRank(10);
/// 每 CPU 运行队列的所有权（ADR-047 决策 2，`sched::RQ`）。
///
/// 为什么是 8 而不是 9 或 12：`INNERMOST` 用 0 表示"没持锁"（`prev_rank != 0` 那道判据），
/// 所以比堆更外层的锁只有 1..9 这九格可取；`spawn` 在队列锁内要任务栈 ⇒ 必须能向下嵌套
/// `HEAP(10)`，因此 8 < 10；留 9 是给"将来仍在堆之下、但在队列之外"的锁。
/// 允许的内部嵌套见 `docs/architecture/lock-order.md`：**不许**跨 `context_load` 持有，
/// 也不许在锁内 drop `Mapping`（那会等 shootdown 回执 = 等别的 CPU 开中断）。
pub const RANK_RUNQ: LockRank = LockRank(8);
pub const RANK_VMM: LockRank = LockRank(20);
pub const RANK_PMM: LockRank = LockRank(30);
/// 用户句柄表（P7）。只读文件对象**不持有页框** ⇒ 表锁内只许调台账(40)、不许调 mm(20)；
/// 盘 I/O 也不在锁内（AHCI 在关中断下只能走轮询宽限窗）。见 `docs/architecture/lock-order.md`。
pub const RANK_HANDLE: LockRank = LockRank(35);
pub const RANK_LEDGER: LockRank = LockRank(40);
pub const RANK_ACPI: LockRank = LockRank(50);
/// 跨核竞争用例专用（`smp::CONTENTION_LOCK`）。排在最内层是因为它**不嵌套任何东西**：
/// 临界区里只有一次原子读改写，不调分配器、不碰页表、不打日志。
/// 给它一个独立的等级而不是复用 40/50，是为了让"测试锁混进了真实嵌套链"这种错误
/// 当场报成锁序违规，而不是安静地共用一个数字。
pub const RANK_TEST: LockRank = LockRank(60);

/// 等待的世代号（ADR-053 决策 3，P4a）。
///
/// 为什么放 `sync` 而不是 `sched`：`sched -> sync` 这条边已经存在，类型放这边不新增依赖；
/// 反过来放会让 `sync` 依赖 `sched`，把 `sched` 拉进环 A（SCC 闸与站点棘轮会同时红）。
/// `seq` 用来分辨"叫醒的是这次等待"，而不是上一次遗留的那次——陈旧 wake 必须无效。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitToken {
    /// 等待队列编号（P4b 的 `WaitQueue` 用它定位；P4a 的同核用例填 0）
    pub queue: u8,
    /// 本次等待的世代号，由等待方单调递增地取
    pub seq: u64,
}

/// 等待队列锁（ADR-047 决策 3 / ADR-053，P4b 落地）。
/// 等级 5：必须**低于**运行队列锁 `RANK_RUNQ(8)`，因为持等待队列锁时要叫醒别人（取 RUNQ）；
/// 又必须低于 `HEAP(10)`，方向才与"从外到内递增"一致。0 是"没持锁"的哨兵，不能当等级用。
/// 嵌套方向唯一：`WAITQ -> RUNQ`；反向在同 CPU 上由 `lock()` 的等级判据当场升 L4。
pub const RANK_WAITQ: LockRank = LockRank(5);
/// 定时器轮（P6/ADR-058）。等级 6：夹在 `WAITQ(5)` 与 `RUNQ(8)` 之间，因为两个方向都要嵌套它——
/// `wait_while` 持 WAITQ 注册到期项（5→6），tick 扫描持 TIMER 叫醒任务要取 RUNQ（6→8）。
/// 0 是"没持锁"哨兵、5/8 已占，1..9 里只剩 6/7/9 可用，取 6 给两侧都留了余地。
pub const RANK_TIMER: LockRank = LockRank(6);

/// 队列数与每队列 waiter 槽数（ADR-047 决策 3）。**定长、不进堆**：
/// 理由不是 ISR 禁令（ISR 内分配是 L3 拒绝、可观察），而是 `LARGE_MAX = 2048`
/// 与"故障路径不分配"。这两个数目前是**上限**，不是由 workload 钉出来的（ADR-053 未决 1）：
/// 槽满回 `NoCapacity`，调用方必须处理，不许在等待路径上顺手分配。
pub const MAX_WAIT_QUEUES: usize = 16;
pub const MAX_WAITERS: usize = 16;

/// 等待的失败分类（B 类资源 / C 类契约）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitError {
    /// 槽满：调用方**不得**阻塞，应改用轮询或退避
    NoCapacity,
    /// 回调表还没装（启动早期）或当前上下文不是任务：调用方不得阻塞
    NotInstalled,
}

/// 依赖反转表（ADR-053 决策 1）：`sync` 不引用 `sched`，否则会把 `sched` 拉进环 A。
/// 由 `sched::install_wait_ops()` 在启动期装一次，之后只读；默认桩让装表前的调用安全失败。
pub struct WaitOps {
    /// 当前任务的全局下标；`usize::MAX` = 当前上下文不是任务
    pub current: fn() -> usize,
    /// 把该任务标成 `Blocked(token)`（内部自己取 RUNQ 锁）
    pub block: fn(usize, WaitToken) -> bool,
    /// 世代号匹配时把 `Blocked` 转回 `Runnable` 并立目标 CPU 的 need 牌
    pub wake: fn(usize, WaitToken) -> bool,
    /// 让出（自陷 resched，ADR-049）。**必须在放掉 WAITQ 锁之后调用**
    pub yield_now: fn(),
}

struct OpsCell(core::cell::UnsafeCell<WaitOps>);
// SAFETY: 表在启动期单核、关中断安装一次，之后只读；默认桩保证安装前调用也安全。
// 与 `hooks::HooksCell` 同一论证形状（ADR-040）。
unsafe impl Sync for OpsCell {}
fn no_current() -> usize { usize::MAX }
fn no_block(_: usize, _: WaitToken) -> bool { false }
fn no_wake(_: usize, _: WaitToken) -> bool { false }
fn no_yield() {}
static WAIT_OPS: OpsCell = OpsCell(core::cell::UnsafeCell::new(WaitOps {
    current: no_current, block: no_block, wake: no_wake, yield_now: no_yield,
}));

/// 启动期安装一次（由 sched 调）。
pub fn install_wait_ops(o: WaitOps) {
    // SAFETY: 见 OpsCell；调用点固定在 after_switch 开头，早于 AP 与定时器。
    unsafe { *WAIT_OPS.0.get() = o; }
}

fn wait_ops() -> &'static WaitOps {
    // SAFETY: 见 OpsCell；装表后只读。
    unsafe { &*WAIT_OPS.0.get() }
}

const NO_NEXT: u16 = u16::MAX;

#[derive(Clone, Copy)]
struct Waiter {
    used: bool,
    task: usize,
    token: WaitToken,
    next: u16,
}

struct WaitInner {
    slots: [Waiter; MAX_WAITERS],
    head: u16,
    seq: u64,
    blocks: u64,
    wakes: u64,
    /// 队列空时还来叫的次数：它是"生产者跑在消费者阻塞之前"的合法情形，
    /// 也是丢唤醒变异要盯的数之一（配合 blocks/wakes 一起看才有意义）。
    empty_wakes: u64,
}

/// 一把等待队列。锁与数据同体，`RANK_WAITQ`。
pub struct WaitQueue(IrqSpinLock<WaitInner>);

impl WaitQueue {
    pub const fn new() -> Self {
        WaitQueue(IrqSpinLock::new(RANK_WAITQ, WaitInner {
            slots: [Waiter { used: false, task: 0, token: WaitToken { queue: 0, seq: 0 }, next: NO_NEXT }; MAX_WAITERS],
            head: NO_NEXT,
            seq: 0,
            blocks: 0,
            wakes: 0,
            empty_wakes: 0,
        }))
    }

    /// 条件等待（ADR-053 决策 2）：**查条件与入队在同一把锁内**，放锁后才切走。
    ///
    /// 为什么这样就不丢唤醒：致命窗口是"查完条件到入队之间插进一次 wake"，
    /// 而这两步同锁，插不进来。放锁之后即使立刻被 wake，本任务已是 `Runnable`，
    /// 让出后仍会被选回来。反过来，**持锁切走**会让守卫在阻塞期间一直不释放
    /// （`IrqGuard` 的 Drop 在函数返回时执行，而阻塞者不返回），唤醒方全死。
    ///
    /// `cond` 必须是**廉价谓词**：它在锁内被调用，不得睡眠、不得取比 WAITQ 更外层的锁。
    /// 返回 `Ok(true)` = 条件成立（可能没阻塞，也可能被唤醒后成立）。
    pub fn wait_while(&self, qid: u8, cond: impl Fn() -> bool) -> Result<bool, WaitError> {
        let o = wait_ops();
        let me = (o.current)();
        if me == usize::MAX {
            return Err(WaitError::NotInstalled);
        }
        let enqueued = {
            let mut g = self.0.lock();
            let inner = g.get();
            if cond() {
                return Ok(true); // 条件已成立：不入队，也不阻塞
            }
            let Some(slot) = inner.slots.iter().position(|w| !w.used) else {
                return Err(WaitError::NoCapacity);
            };
            inner.seq = inner.seq.wrapping_add(1);
            let tok = WaitToken { queue: qid, seq: inner.seq };
            if !(o.block)(me, tok) {
                return Err(WaitError::NotInstalled);
            }
            inner.slots[slot] = Waiter { used: true, task: me, token: tok, next: inner.head };
            inner.head = slot as u16;
            inner.blocks += 1;
            true
        }; // ← 锁在这里放掉，**然后**才切走
        if enqueued {
            (o.yield_now)();
            // 回来就摘链：正常路径下 wake 已经摘过，这里兜住"被直接 wake_task 叫醒"的情形
            let _ = self.remove_task(me);
        }
        Ok(cond())
    }

    /// 叫醒队首一个。返回实际转移的状态数（0 或 1）。
    pub fn wake_one(&self) -> usize {
        let o = wait_ops();
        let mut g = self.0.lock();
        let inner = g.get();
        if inner.head == NO_NEXT {
            inner.empty_wakes += 1;
            return 0;
        }
        let h = inner.head as usize;
        let w = inner.slots[h];
        inner.head = w.next;
        inner.slots[h].used = false;
        inner.slots[h].next = NO_NEXT;
        inner.wakes += 1;
        // 持 WAITQ 取 RUNQ：方向合法（5 -> 8），见 lock-order.md
        if (o.wake)(w.task, w.token) { 1 } else { 0 }
    }

    /// 叫醒全部，返回实际转移数。
    pub fn wake_all(&self) -> usize {
        let o = wait_ops();
        let mut n = 0usize;
        let mut g = self.0.lock();
        let inner = g.get();
        let mut cur = inner.head;
        inner.head = NO_NEXT;
        while cur != NO_NEXT {
            let i = cur as usize;
            let w = inner.slots[i];
            cur = w.next;
            inner.slots[i].used = false;
            inner.slots[i].next = NO_NEXT;
            inner.wakes += 1;
            if (o.wake)(w.task, w.token) {
                n += 1;
            }
        }
        n
    }

    /// 把某个任务从链上摘掉（杀死阻塞任务时用，ADR-053 决策 4）。
    pub fn remove_task(&self, task: usize) -> bool {
        let mut g = self.0.lock();
        let inner = g.get();
        let mut cur = inner.head;
        let mut prev = NO_NEXT;
        while cur != NO_NEXT {
            let i = cur as usize;
            if inner.slots[i].task == task {
                let nxt = inner.slots[i].next;
                if prev == NO_NEXT { inner.head = nxt; } else { inner.slots[prev as usize].next = nxt; }
                inner.slots[i].used = false;
                inner.slots[i].next = NO_NEXT;
                return true;
            }
            prev = cur;
            cur = inner.slots[i].next;
        }
        false
    }

    /// `(blocks, wakes, empty_wakes, 仍在链上的槽数)`。判据用它对账，不靠串口猜。
    pub fn stats(&self) -> (u64, u64, u64, usize) {
        let mut g = self.0.lock();
        let inner = g.get();
        (inner.blocks, inner.wakes, inner.empty_wakes, inner.slots.iter().filter(|w| w.used).count())
    }
}

static WAIT_QUEUES: [WaitQueue; MAX_WAIT_QUEUES] = [const { WaitQueue::new() }; MAX_WAIT_QUEUES];

/// 按编号取队列；越界返回 None（调用方必须处理，不许 unwrap）。
pub fn wait_queue(id: u8) -> Option<&'static WaitQueue> {
    WAIT_QUEUES.get(id as usize)
}

const UNHELD: u64 = u64::MAX;

pub struct IrqSpinLock<T> {
    locked: AtomicUsize,
    held_by: AtomicU64,
    rank: LockRank,
    data: UnsafeCell<T>,
}

// SAFETY: `data` 只能在持有 `locked` 时访问，因此 T: Send 即可跨线程共享。
// 注意这只覆盖"互斥"，不覆盖 M3b 的多核 TLB/内存序问题（那需要 §6.6 的 shootdown）。
unsafe impl<T: Send> Sync for IrqSpinLock<T> {}

#[must_use = "丢弃守卫会立即释放锁，等于什么都没锁（§7.1 R16）"]
pub struct IrqGuard<'a, T: Send> {
    lock: &'a IrqSpinLock<T>,
    /// 获取前的 RFLAGS。释放时**整份恢复**而不是无脑 `cli`：
    /// 在 IF 本来就为 0 的路径里嵌套获取，恢复成 0 才对。
    flags: u64,
    /// 获取前的"当前最深锁等级"。**必须在 Drop 里还原**：
    /// 不还原的话，锁依次获取两次就会被当成嵌套（10 <= 10）而误报 L4——
    /// 这个错今天真的把正常构建打成了 39，就是这么来的。
    prev_rank: u8,
    /// 守卫属于哪个 CPU。等级栈是 per-CPU 的（见 `INNERMOST`），
    /// 所以还原时必须回到**获取时那个 CPU** 的那一份上——守卫不可能跨 CPU 移交，
    /// 持锁期间本 CPU 的 IF=0，不会有第二次调度把它带走。
    slot: usize,
}

impl<'a, T: Send> IrqGuard<'a, T> {
    pub fn get(&mut self) -> &mut T {
        // SAFETY: 持有本守卫期间只有本 CPU 能进入（IF=0 且 locked 已置），
        // 且本类型不实现 Clone/Copy，生命周期由借用检查器限制在作用域内。
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: Send> Drop for IrqGuard<'_, T> {
    fn drop(&mut self) {
        // 顺序很重要：先清 held_by，再放锁，最后恢复标志。
        // 先还原本 CPU 的锁序栈，再放锁：顺序反了不会出错，但会让人怀疑"释放后还有窗口"
        INNERMOST[self.slot].store(self.prev_rank, Ordering::Relaxed);
        self.lock.held_by.store(UNHELD, Ordering::Relaxed);
        // SAFETY: 写 0 是解锁的唯一约定入口（本模块不对外暴露 locked）
        unsafe { self.lock.locked.store(0, Ordering::Release) };
        restore_flags(self.flags);
    }
}

#[inline]
fn save_and_cli() -> u64 {
    let f: u64;
    // 没有 `options(may_unwind)`：本内核 panic=abort（ADR-005），不存在穿过 asm 的展开，
    // 而且这个选项在本工具链上是 unstable。
    // SAFETY: pushfq 把 EFLAGS 压栈再 pop 进寄存器，只读写 [rsp] 这 8 字节，不改栈指针
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {r}",
            "cli",
            r = out(reg) f
        );
    }
    f
}

#[inline]
fn restore_flags(f: u64) {
    // SAFETY: popfq 把获取前保存的整份 EFLAGS 恢复回去；不访存、不动栈指针
    unsafe { core::arch::asm!("push {r}", "popfq", r = in(reg) f) };
}

/// 持有者令牌 = **本 CPU 的 LAPIC id**。
///
/// 为什么不能用栈帧地址：同一次自死锁（同一任务在两个不同栈帧里拿同一把锁）
/// 会产生两个不同地址，于是"重入"判不出来，只剩关中断自旋——表现是卡到
/// 自旋计数溢出才叫，归因极难。用 CPU 号则不同：持锁期间 IF=0，本 CPU 上
/// 不可能有第二个上下文进来，所以"同一 CPU 再次获取"必然就是自死锁。
/// APIC 还没初始化时退到 0（启动早期所有锁都在 BSP 上，这是正确的）。
#[inline]
fn cpu_token() -> u64 {
    crate::arch::x86_64::apic::self_id()
}

// ----------------------------------------------------------------- lockdep

/// 每个 CPU 各自的"当前最深锁等级"。
///
/// **必须 per-CPU**：这是一张嵌套栈，而嵌套只发生在同一个 CPU 上。用全局一份时，
/// A 核拿堆锁(10) → 释放 → B 核拿 VMM(20) → B 核再拿堆锁之外的任何一把，
/// 读到的"外层等级"可能是 A 核留下的残值，于是 `10 <= 20` 这种根本不存在嵌套的
/// 组合会被报成锁序违规（M3b 放 AP 之后就是随机红）。
/// 释放守卫时还原的是**本 CPU** 的那一份，见 `IrqGuard::drop`。
static INNERMOST: [AtomicU8; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicU8::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];
static ORDER_VIOLATIONS: AtomicUsize = AtomicUsize::new(0);
static REENTRANT_HITS: AtomicUsize = AtomicUsize::new(0);
static ACQUIRES: AtomicUsize = AtomicUsize::new(0);
// 跨 CPU 竞争的账：真正等过锁的次数、自旋总数、最长一次的等待周期、看门狗到期的次数。
// 这五个数就是"锁在多核下被验证过"的证据；没有它们，"acquires=431 violations=0"
// 只证明了一件事：一台机器上没人跟自己抢。
static WAIT_EVENTS: AtomicUsize = AtomicUsize::new(0);
static WAIT_SPINS_TOTAL: AtomicUsize = AtomicUsize::new(0);
static WAIT_MAX_CYCLES: AtomicU64 = AtomicU64::new(0);
static WAIT_TIMEOUTS: AtomicUsize = AtomicUsize::new(0);

/// 等锁看门狗（§7.1 R16 的"有界自旋"、§9.6 的看门狗配对）。
///
/// 定在周期数而不是毫秒上：持有者此刻可能正在吐一行串口日志，而"多久算卡死"必须
/// 明显大于**最慢的一次合法持锁**。200M 周期在本机（tsc≈3.33 GHz）约 60 ms，
/// 在 1 GHz 的机器上是 200 ms；用例打印换算值，但不拿它当判据。
pub const LOCK_WATCHDOG_CYCLES: u64 = 200_000_000;

#[derive(Clone, Copy)]
pub struct Stats {
    pub acquires: usize,
    pub order_violations: usize,
    pub reentrant_hits: usize,
    pub wait_events: usize,
    pub wait_spins_total: usize,
    pub wait_max_cycles: u64,
    pub wait_timeouts: usize,
}

pub fn stats() -> Stats {
    Stats {
        acquires: ACQUIRES.load(Ordering::Relaxed),
        order_violations: ORDER_VIOLATIONS.load(Ordering::Relaxed),
        reentrant_hits: REENTRANT_HITS.load(Ordering::Relaxed),
        wait_events: WAIT_EVENTS.load(Ordering::Relaxed),
        wait_spins_total: WAIT_SPINS_TOTAL.load(Ordering::Relaxed),
        wait_max_cycles: WAIT_MAX_CYCLES.load(Ordering::Relaxed),
        wait_timeouts: WAIT_TIMEOUTS.load(Ordering::Relaxed),
    }
}


pub fn order_violations() -> usize {
    ORDER_VIOLATIONS.load(Ordering::Relaxed)
}

pub fn reentrant_hits() -> usize {
    REENTRANT_HITS.load(Ordering::Relaxed)
}

impl<T: Send> IrqSpinLock<T> {
    pub const fn new(rank: LockRank, v: T) -> Self {
        Self { locked: AtomicUsize::new(0), held_by: AtomicU64::new(UNHELD), rank, data: UnsafeCell::new(v) }
    }

    pub fn rank(&self) -> LockRank {
        self.rank
    }

    /// 关中断获取。重入、看门狗到期、违反锁序**当场升 L4**（§9.2：继续跑就是不可恢复的状态）。
    ///
    /// M3b 放 AP 之后，"被别人持有"从**故障**变成了**合法路径**，所以这段整个重写：
    /// * 旧实现里 CAS 失败（预读说空闲却被抢走）直接 L4。单机成立，多核不成立——
    ///   另一个 CPU 完全可能在我们预读和 CAS 之间拿走锁，那是一次正常竞争，不是状态被写坏。
    /// * 旧实现的自旋上限是"计数溢出 2^32 次"，那不是看门狗，是最后一次兜底；
    ///   现在按时间界判，并把"等过锁"这件事本身记成数字（`wait_events` 等），
    ///   否则"锁验证过了"这句话没有证据可指。
    pub fn lock(&self) -> IrqGuard<'_, T> {
        ACQUIRES.fetch_add(1, Ordering::Relaxed);
        let flags = save_and_cli();
        let token = cpu_token();
        let slot = crate::arch::x86_64::cpu::self_slot();
        let mut spins = 0u64;
        let t0 = crate::tsc::now();
        loop {
            if self.locked.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                break;
            }
            // CAS 失败有两种原因，必须分开：
            // (a) 本 CPU 已经持有 => 重入。IF 已经是 0，持有者永远不会让出，这是自死锁，当场叫。
            // (b) 别的 CPU 持有 => 合法竞争，自旋等它释放。
            let held = self.held_by.load(Ordering::Relaxed);
            if held == token {
                REENTRANT_HITS.fetch_add(1, Ordering::Relaxed);
                crate::log_fatal!("L4 sync: 重入获取 rank={} token={:#x}", self.rank.0, token);
                crate::exit::finish(crate::exit::Code::ExceptionFatal);
            }
            core::hint::spin_loop();
            spins += 1;
            // 每 256 次自旋才取一次 TSC：看门狗自己不能成为被测量的开销。
            // 代价是最坏情况下超出界限 256 次自旋才被看见，而界是 2e8 量级，可以忽略。
            if spins & 0xff == 0 && crate::tsc::now().wrapping_sub(t0) > LOCK_WATCHDOG_CYCLES {
                WAIT_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
                crate::log_fatal!(
                    "L4 sync: 等锁超过看门狗 rank={} 等待者 token={:#x} 持有者 token={:#x} 自旋={}",
                    self.rank.0, token, held, spins
                );
                crate::exit::finish(crate::exit::Code::ExceptionFatal);
            }
        }
        if spins > 0 {
            // 真的为别人等过一次锁：把这件事记进数字，供用例判断"跨核竞争确实发生过"
            let waited = crate::tsc::now().wrapping_sub(t0);
            WAIT_EVENTS.fetch_add(1, Ordering::Relaxed);
            WAIT_SPINS_TOTAL.fetch_add(spins as usize, Ordering::Relaxed);
            WAIT_MAX_CYCLES.fetch_max(waited, Ordering::Relaxed);
        }
        // 以下两件事**必须在抢占成功之后**做（§7.1 R16）
        let prev_rank = INNERMOST[slot].swap(self.rank.0, Ordering::Relaxed);
        if self.rank.0 <= prev_rank && prev_rank != 0 {
            ORDER_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
            crate::log_fatal!("L4 sync: 锁序违规，外层 rank={} 本次 rank={}", prev_rank, self.rank.0);
            crate::exit::finish(crate::exit::Code::ExceptionFatal);
        }
        self.held_by.store(token, Ordering::Relaxed);
        IrqGuard { lock: self, flags, prev_rank, slot }
    }

    /// 只在"确定没被持有"时用一次；不改变标志位。返回 None 表示已有人持有。
    ///
    /// 多核下这条路径的语义就是它的名字：**试一次**。竞争失败不记账、不自旋。
    pub fn try_lock(&self) -> Option<IrqGuard<'_, T>> {
        let flags = save_and_cli();
        if self.locked.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            restore_flags(flags);
            return None;
        }
        let slot = crate::arch::x86_64::cpu::self_slot();
        let prev_rank = INNERMOST[slot].swap(self.rank.0, Ordering::Relaxed);
        if self.rank.0 <= prev_rank && prev_rank != 0 {
            ORDER_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
        }
        self.held_by.store(cpu_token(), Ordering::Relaxed);
        Some(IrqGuard { lock: self, flags, prev_rank, slot })
    }
}

