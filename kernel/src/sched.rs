//! 最小内核线程 + 时钟抢占（§5.2 每 CPU 栈、§6.4 guard page、§7.2 的切换成本 P1）。
//!
//! 三条决定本文件形状的事实：
//! 1. **切换单位是 `trap::TrapFrame`**，不是"六个 callee-saved + ret"：被抢占任务的续跑点
//!    就是它压在自己栈上的那个异常帧。所以只有一个恢复原语 `context_load(frame)`（永不返回），
//!    而新任务的第一次运行**合成同一种帧**走同一条路径——少一种特例就少一处只有真机才暴露的偏差。
//! 2. **运行队列每 CPU 一份、无锁**：每条队列只由自己的 CPU 读写（`Task::on_cpu` 就是这条归属），
//!    所以不需要论证锁序。临界区一律 `save_and_cli`，IF=0 时本 CPU 的 tick 进不来，
//!    "同一个 CPU 的 ISR 抢同一把锁"构造不出来；真正的危险是跨 CPU（靠有界自旋 + 看门狗，见 `sync`）。
//!    **任务迁移还没有**：那必须引入同步，不能靠改一个字段就搬走。
//! 3. **栈底 guard page 是真的**（保留 5 页 VA，第一页永不映射）。启动上下文跑在 `mm::State`
//!    的静态数组上，它没有 guard page ⇒ 如实登记 `guarded=false`，不把别人的例外说成已满足。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::{mm};
use crate::arch::x86_64::{trap};
use crate::mm::{ModuleId, PageFlags, VirtAddr};

pub const MOD_STACK_TASK: ModuleId = ModuleId(12);
/// 用户任务的**内核栈**单独一个模块号：台账要能分开回答
/// 任务栈占了多少帧和为用户态陷入准备的栈占了多少帧（§6.7）。
pub const MOD_STACK_KUSER: ModuleId = ModuleId(15);
/// **每 CPU** 的队列容量。名字保留 `MAX_TASKS` 是因为用例都按它写；
/// 全局下标 = `cpu * MAX_TASKS + slot`，所以 BSP 的任务下标仍是 0..MAX_TASKS。
/// 6 → 8 是 M4-1 撞出来的（Done 的任务以前从不回收槽位）。加两格只是容量，
/// 不是把回收问题解掉：过程与现在的状态见 BACKLOG 的 M4 一节。
/// 8 → 9 是 W3 P3 的 Q2 裁决（2026-11-09，使用者选定）：参考 workload
/// （init + 3 子进程 × 2 线程 = 7 条线程）加 boot 上下文与兜底 idle **正好 9 格、零余量**。
/// 实测读数与三本账的代价见 ADR-071 决策 3 的补记；再要余量得重开那一题。
pub const MAX_TASKS: usize = 9;
/// `Task::as_slot` 的"内核 AS"哨兵（W3 P5b，ADR-075 决策 2）。
/// **内核任务恒为它**，所以既有路径一次 CR3 都不多写（矩阵 45 行不该变的论证基础）。
pub const NO_ASPACE: u8 = 0xFF;
// ADR-041：VA 保留表的容量归 memory 拥有；扩槽要把 memory 的容量一起抬。
const _: () = assert!(MAX_TASKS <= crate::mm::MAX_TASKS_SUPPORTED);
/// 全系统可登记的任务数（跨所有 CPU）。用例读 `WORK[i]` / `state_of(i)` 时用的是这个空间里的全局下标。
pub const MAX_TASKS_TOTAL: usize = MAX_TASKS * crate::arch::x86_64::cpu::MAX_CPUS;
const STACK_PAGES: usize = 4;
/// +1 = 栈底 guard 页（永不映射）
const STACK_VA_PAGES: usize = STACK_PAGES + 1;

/// (CPU 槽位, 队列内下标) -> 全局任务下标。
#[inline]
pub const fn gidx(cpu: usize, slot: usize) -> usize {
    cpu * MAX_TASKS + slot
}
/// 全局任务下标属于哪个 CPU。
#[inline]
pub const fn cpu_of(i: usize) -> usize {
    i / MAX_TASKS
}
/// 全局任务下标在本 CPU 队列里的位置。
#[inline]
pub const fn slot_of(i: usize) -> usize {
    i % MAX_TASKS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Free,
    Runnable,
    Running,
    Done,
    /// 阻塞在某个等待队列上（ADR-053，P4a）。**不是**"可运行"：
    /// `pick_next` 与 `tasks_active` 的 `Runnable | Running` 过滤天然把它排除，
    /// `reap` 也跳过它（它还活着、还持有资源）。唤醒由 `wake_task` 按世代号转移。
    Blocked(crate::sync::WaitToken),
}

pub struct Task {
    pub id: u32,
    /// 续跑点：一个 `TrapFrame` 的**低地址端**（cr2 那一格）。0 = 还没被保存过。
    pub frame: u64,
    /// **异常帧所在的那条栈**的区间。内核任务里它等于任务栈；
    /// 用户任务里它是这个任务自己的**内核栈**（ring3→ring0 硬件按 `TSS.rsp0` 切过去，
    /// 帧落在那边，不在用户栈上）。`preempt_point` 的"帧在不在这条栈上"检查读的就是这两格。
    pub kstack_lo: u64,
    pub kstack_hi: u64,
    /// 换入本任务时要装进 `TSS.rsp0` 的值（用户任务才有意义；内核任务用不到但可以同值）。
    pub kstack_top: u64,
    /// 任务**自己**的栈（用户任务 = ring3 的 rsp；内核任务 = 同 kstack）。
    pub stack_lo: u64,
    pub stack_hi: u64,
    pub guarded: bool,
    pub state: TaskState,
    /// 是不是用户态任务（决定换入时要不要装 rsp0，也决定故障该杀还是该停机）。
    pub user: bool,
    /// **设计上就不退出的常驻工人**：每 CPU 的启动/空闲上下文（slot 0）、BSP 的兜底 idle、
    /// AP 队列里的工人。收尾判据只豁免这一份名单里的内核任务，其余还 `Runnable` 的
    /// 内核工人一律点名（关掉 ADR-050 未决 1 的另一半、ADR-061 未决 3）。
    ///
    /// 取值只有五个来源，就是下面五个 `Task` 字面量；`terminate_task` 释放槽位时清掉，
    /// 所以"槽位被复用"不会把常驻身份带给下一个任务（ADR-061 未决 1 的 ABA 同一条线）。
    pub resident: bool,
    /// 所属进程槽号（`proc::NO_PROC` = 无进程/内核任务）。W3 P3（ADR-073）。
    /// 收工出口据此置 signal + 减线程计数；收尾判据据此判"用例造的进程线程必须清零"。
    pub proc_id: u16,
    /// 这个任务跑在哪个地址空间里（`NO_ASPACE` = 内核那份）。W3 P5b（ADR-075 决策 2）。
    pub as_slot: u8,
    /// 登记时缓存下来的根表物理地址（0 = 内核 AS）。**换人时只比较它，不查表**：
    /// 查表要取 VMM，而换人点 IF=0，持 VMM 等别的 CPU 回执会把两边绑死（ADR-047 决策 2）。
    pub as_pml4: u64,
    /// **属于哪个 CPU 的队列**（`cpu` 模块的槽位号）。
    ///
    /// 为什么要把"在哪个 CPU 上"从 `state` 里分出来：M3a 那次挂死就是两者共用一个字段造成的——
    /// 任务自己标了 `Done`（=可被调度掉），但抢占判据去问 `state == Running`，
    /// 于是它永远不被换下、等 CPU 的任务永远回不来。`state` 说"能不能被调度"，
    /// `on_cpu` 说"归哪个 CPU 调度"，两件事各自一个字段，`pick_next` 只在本队列里选。
    pub on_cpu: u8,
    pub runs: u64,
    /// 最后一次被换下 CPU 的时刻，用来算"它被晾了多久"
    pub left_tsc: u64,
    /// **这个任务名下的映射**（它的内核栈，以及从容器装进来的用户页与用户栈）。
    ///
    /// 为什么要让任务自己拿着，而不是"分配了就当内核的"：§6.3 R13 说解映射与归还
    /// 物理页由映射的主人负责。此前 `spawn` / `user::load` 一律
    /// `core::mem::forget(m)` —— 那是**故意不还**，代价就是任务结束之后
    /// 槽位、页框和 VA 保留全部有去无回（M4-1/M4-2 的实测：Done 的任务永久占着
    /// run queue 的一格，`MAX_TASKS` 从 6 提到 8 只是让用例的绿不再靠"谁先跑"）。
    /// 现在主人是任务本身：结束（自己 `SYS_EXIT` 或被旁观者 `terminate_task`）之后
    /// 由**下一个不是它**的上下文在抢占点释放。
    pub owned: OwnedSet,
}

/// 一个任务能持有的映射数上限。**定长而不是 `Vec`**：任务结构住在 per-CPU 静态数组里，
/// 而 `heap::LARGE_MAX = 2048` 会把"按段开缓冲"的写法当场打死（ADR-026）。
/// 超了就明确失败，不静默丢——丢一次就是一批页框永久漏掉，而台账不会告诉你。
/// 现在数的是**块**而不是页（`user::load` 按段贪心切 2 的幂）。实测 6/8 与"余量 ≥ 2"那条判据：
/// 见 §10.7 的 `MAX_OWNED` 那一行、BACKLOG 的 R33 那节。
pub const MAX_OWNED: usize = 8;

/// 一组"任务名下的拥有项"（ADR-067 决策 2）。计数的仍是**条**——ADR-027 的计数规则、
/// `owned_of` 与"回基线"判据全部不变，只是元素从单一 `Mapping` 变成两臂枚举。
pub enum OwnedItem {
    Map(mm::Mapping),
    /// 惰性区间只挂**柄**：区间本体住 mm 的 LAZY 表（VMM 纪律），
    /// 这样 #PF 修复路径不必为了碰 owned 去取 RUNQ(8)（§136 教训）。
    Lazy(mm::LazyHandle),
    /// 往 AS 铺的共享映射（ADR-074）：Drop 清叶子 + shootdown + 还帧参考 + 放手 VA 保留。
    /// 与 `Map` 的差别是它**不拥有帧**（帧的主人是 VMO），所以还的是参考而不是所有权。
    AsMap(mm::AspaceMapping),
}

pub struct OwnedSet {
    items: [Option<OwnedItem>; MAX_OWNED],
    n: usize,
}

impl OwnedSet {
    /// `const fn` 是硬要求：它要进 `EMPTY_TASK` 这个静态初值。
    pub const fn new() -> Self {
        Self {
            items: [None, None, None, None, None, None, None, None],
            n: 0,
        }
    }

    pub fn push(&mut self, m: mm::Mapping) -> Result<(), mm::MmError> {
        self.push_item(OwnedItem::Map(m))
    }

    /// 惰性区间柄入列（ADR-067）：`LazyHandle::drop` 解映射已填充页、归还帧并放手 VA 保留，
    /// 所以"任务结束账回基线"对这一臂同样由 `release_owned` 兑现，不加新路径。
    pub fn push_lazy(&mut self, h: mm::LazyHandle) -> Result<(), mm::MmError> {
        self.push_item(OwnedItem::Lazy(h))
    }

    /// 共享映射入列（ADR-074）：退出时由 `release_owned` 在**锁外** drop，
    /// 所以它的 shootdown 等待不会发生在持 RUNQ 的时候。
    pub fn push_asmap(&mut self, m: mm::AspaceMapping) -> Result<(), mm::MmError> {
        self.push_item(OwnedItem::AsMap(m))
    }

    fn push_item(&mut self, it: OwnedItem) -> Result<(), mm::MmError> {
        if self.n >= MAX_OWNED {
            // 满了就把刚交来的项就地丢弃：`Map` 走 `Mapping::drop` 解映射并归还页框、
            // `Lazy` 走 `LazyHandle::drop` 归还整段区间、`AsMap` 走 `AspaceMapping::drop`
            // 清叶子并还帧参考——所以这里没有泄漏——调用方拿到 `Err` 会停下这条装载路径。
            // **注意**：这条就地丢弃只发生在装载路径（不持 RUNQ）；syscall 路径走
            // `own_current`，它满了会先放锁再丢，因为 AsMap 的 Drop 要等跨 CPU 回执。
            drop(it);
            return Err(mm::MmError::Unsupported);
        }
        self.items[self.n] = Some(it);
        self.n += 1;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.n
    }
}

/// 每个 CPU 一格：**还有几个槽的资源在等"CPU 挪开它"**。为 0 就等于没有待回收，
/// 所以 `preempt_point` 可以先读这一格再决定要不要扫队列（见 `reap` 的计数语义）。
/// 为什么需要它：`preempt_point` 在**每次**出中断时都会路过回收检查，
/// 而绝大多数时候没有任何东西要收。先读这一格（自己的缓存行里，几十周期以内），
/// 为 0 就直接走——把 8 格的扫描放进 P3/P5 的被测区间是不诚实的代价。
static REAP_PENDING: [core::sync::atomic::AtomicUsize; crate::arch::x86_64::cpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];

/// 本次运行里"任务结束后释放掉的映射数"（判据要看见回收真的发生过，而不是只看见状态变 Free）。
static REAP_RELEASED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn reap_released() -> u64 {
    REAP_RELEASED.load(Ordering::Relaxed)
}

/// `SYS_EXIT` 的内核侧：任务自己要求结束。
///
/// 只做三件事，顺序有意义：① 标 Free（不再被 `pick_next` 选中，也不会再被换进来）；
/// ② 资源**留在槽里**；③ 立重调度牌，让同一次中断出口就把 CPU 换给别人。
/// 释放由下一个不是它的上下文在抢占点做（见 `reap`）。
///
/// 为什么这里不直接 unmap：此刻 rsp 就在这个任务的内核栈里。当场解映射等于
/// 让下一次访存踩到一条已经不存在映射的地址 —— 那是 ring0 的 #PF，按 §9.2 直接 L4，
/// 而现场看起来会像"退出路径自己写坏了"。**这个错误我确实撞到过一次**（见 BACKLOG）。
pub fn exit_current(cpu: usize) {
    let me = current_of(cpu);
    terminate_task(me);
    mark_need(cpu);
}

/// 结束一个任务：标 Free，**但不动它的映射**。
///
/// 为什么不在这里直接释放：调用发生在任务自己的上下文里（`SYS_EXIT` 的处理路径就是它），
/// 它正站在要交出去的那条内核栈上。当场 unmap 就是下一次访存/取指故障，
/// 而且那是 ring0 的故障 ⇒ 按 §9.2 直接 L4。所以释放必须推迟到
/// "本 CPU 上跑的已经不是它"的那一刻，也就是 `reap`。
///
/// `terminate_task` 是同一个内部动作的旁观者版本（用例结束一个仍在跑的任务时用），
/// **不是**给用户态的接口：用户态只有一条 `SYS_EXIT`。
pub fn terminate_task(task: usize) -> bool {
    if task >= MAX_TASKS_TOTAL {
        return false;
    }
    let cpu = cpu_of(task);
    let (slot, on_cpu_now, has_bag, was_blocked, dead_id, dead_proc) = {
        let mut s = rq(cpu);
        let slot = slot_of(task);
        if s.tasks[slot].state == TaskState::Free {
            return false;
        }
        let was_blocked = match s.tasks[slot].state {
            TaskState::Blocked(tok) => Some(tok),
            _ => None,
        };
        s.tasks[slot].state = TaskState::Free;
        s.tasks[slot].frame = 0;
        // 常驻身份跟着槽位走，所以释放时必须清掉：否则下一个复用这条槽的任务
        // 会白白拿到豁免（ADR-061 未决 1 那条 ABA 的同一家族）。
        s.tasks[slot].resident = false;
        // 进程归属同理（W3 P3，ADR-073）：留着的话，复用这条槽的任务收工时会把
        // **别人的**进程线程计数减一次——那个进程就永远等不到结局。
        let dead_proc = s.tasks[slot].proc_id;
        s.tasks[slot].proc_id = crate::proc::NO_PROC;
        // AS 归属同样跟着槽位走（W3 P5b）：留着的话复用这条槽的任务会被换进一个
        // 已经销毁的表。契约是"任务先死、AS 后销毁"，这里把槽位那一侧清干净。
        s.tasks[slot].as_slot = NO_ASPACE;
        s.tasks[slot].as_pml4 = 0;
        s.entries[slot] = None;
        (slot, s.current == task, s.tasks[slot].owned.n > 0, was_blocked, s.tasks[slot].id, dead_proc)
    };
    // **被杀的线程也要给它的进程记一笔收工**（P5c-3 修的一条 P3 遗留洞）：
    // 这条路径不走 `finish_current`/`kill_current`，只清 `proc_id` 的话进程的 `threads`
    // 永远减不到 0 ⇒ 那个进程永远 reap/discard 不掉（名额与它名下的 AS 一起漏）。
    // 退出码 1 = 非正常，与 `kill_current` 同一口径。放在放掉 RUNQ 之后：
    // `proc_thread_exited` 今天只动原子量，但这条边不该依赖"它恰好不取锁"。
    if dead_proc != crate::proc::NO_PROC {
        crate::proc::proc_thread_exited(dead_proc, 1);
    }
    // P6a：旁观者终止也算收工（这条路径把槽直接标 Free），等待者同样要收到发布
    task_wait_signal(TW_TASK, task as u32, 1);
    if dead_proc != crate::proc::NO_PROC {
        task_wait_signal(TW_PROC, u32::from(dead_proc), 1);
    }
    // P7b（欠账⑥）：阻塞着的任务还占着**两份注册**——等待链上的 waiter 与定时器轮里的项。
    // 只改任务槽的话这两份永久留着：槽会被 spawn 复用，而注册认的是槽下标，
    // 于是等待队列 16 格 / 轮 64 格杀够次数就再也等不了（实测 6 次杀 ⇒ 各漏 6 格）。
    // **必须在放掉 RUNQ 之后做**：WAITQ(5)/TIMER(6) 都在 RUNQ(8) 之内，持着 RUNQ 去取是反向嵌套。
    // 摘链与取消都用 token 里带的队列号；`timer_del_for_wait` 自己按 (task, token) 匹配，
    // 所以陈旧调用是无效操作，不会误删别人那一格。
    if let Some(tok) = was_blocked {
        if let Some(q) = crate::sync::wait_queue(tok.queue) {
            let _ = q.remove_task(task);
        }
        let _ = timer_del_for_wait(task, tok);
    }
    // 放掉队列锁之后再回收：`release_owned` 自己分段取锁，而它中间要 drop `Mapping`
    // （拿 VMM 锁、可能等 shootdown 回执）。拿着队列锁去等一把跨 CPU 的锁，等于把两条
    // 不变量绑成一条——这正是 ADR-047 决策 2 禁止的形状。
    if on_cpu_now {
        // 正在 CPU 上：等下一次抢占点换下去（`mark_need` 由调用方负责，
        // SYS_EXIT 的路径会立刻立牌；旁观者路径靠本 CPU 的下一次 tick）。
        // 句柄撤销留给 `reap`：它此刻还在跑，撤销会让它手上的句柄当场失效。
        REAP_PENDING[cpu].fetch_add(1, Ordering::AcqRel);
    } else {
        // 已经不在 CPU 上了，就地回收安全。**句柄也要在这里撤销**（W3 P5a 实测撞出来的漏洞）：
        // 撤销原来只在 `reap` 里做，而这条路径就地 release_owned 之后袋子空了 ⇒
        // `reap` 的 `has_bag` 闸把这一格跳过 ⇒ 句柄与它背后的 VMO/帧永远回不来。
        // 现场：probe 用例收场格 `live0->1 vmo0->1 free 少 2 帧`。
        // 放在放掉 RUNQ 之后：revoke_task 取 HANDLE(35)、其 VMO 归还在锁外取 VMM(20)。
        #[cfg(feature = "handles")]
        crate::handle::revoke_task(task, dead_id);
        if has_bag {
            release_owned(cpu, slot);
        }
    }
    true
}

/// 释放某个槽位名下的映射。**调用前必须确认这个槽位不在本 CPU 上运行**。
/// 退一份共享映射的页额度账（P6b 余下）。**只在放锁之后调**：它要取 VMM（proc 表在那里），
/// 而调用点分别是 `release_owned`（已放 RUNQ）与 `own_current` 的满而丢弃分支（已 drop 守卫）。
/// 退账故意放在 sched 而不是 mm：`AspaceMapping::drop` 在 memory 模块里，让它调 proc
/// 就是 `memory → sched` 的新边，会把 sched 拖进冻结的核心环（P5c-1 实测过同形状）。
fn refund_asmap(it: &OwnedItem) {
    if let OwnedItem::AsMap(m) = it {
        if let Some(slot) = m.as_slot() {
            if let Some(job) = crate::proc::job_of_aspace(slot) {
                crate::proc::job_refund_pages(job, m.pages() as u64);
            }
        }
    }
}

fn release_owned(cpu: usize, slot: usize) {
    // 一次持锁把"取走计数 + 把映射搬出槽位"做完（原来分两次，每次都要重取队列锁）。
    // `drop(bag)` 仍旧留在锁外——那才是真正可能阻塞的一步，合并取锁不能把它带进来。
    let mut bag = OwnedSet::new();
    let mut released = 0usize;
    {
        let mut s = rq(cpu);
        let n = core::mem::take(&mut s.tasks[slot].owned.n);
        for i in 0..n.min(MAX_OWNED) {
            if let Some(m) = s.tasks[slot].owned.items[i].take() {
                bag.items[i] = Some(m);
                released += 1;
            }
        }
        // `bag.n` 也要填：它不是"装饰字段"，`OwnedSet::push` 用它当下标，
        // 而且第一版这里就是靠 `bag.n` 来数释放了几条 —— 而我从没往 bag.n 里加过，
        // 于是 `reap_released()` 恒为 0（现场：页确实被解映射了，计数却说什么都没发生）。
        bag.n = released;
    }
    // 把映射从槽位里搬出来再 drop：不能在持有队列句柄的时候逐个 drop，
    // 因为 `Mapping::drop` 要拿 VMM 锁、可能等 shootdown 回执——
    // 拿着队列去等一把跨 CPU 的锁，等于把两条不变量绑在一起（ADR-048 决策 3）。
    // 退页额度账也在这里（已放 RUNQ）：drop 之后 AS 可能已被销毁，就找不到 Job 了。
    for it in bag.items.iter().take(bag.n) {
        if let Some(it) = it {
            refund_asmap(it);
        }
    }
    drop(bag);
    if released > 0 {
        REAP_RELEASED.fetch_add(released as u64, Ordering::Relaxed);
    }
    let mut s = rq(cpu);
    s.tasks[slot].kstack_lo = 0;
    s.tasks[slot].kstack_hi = 0;
    s.tasks[slot].kstack_top = 0;
    s.tasks[slot].stack_lo = 0;
    s.tasks[slot].stack_hi = 0;
    s.tasks[slot].guarded = false;
}

/// 抢占点上的回收：把本 CPU 队列里"已 Free、还牵着映射、且不是当前任务"的槽位放手。
///
/// `skip = current` 这一条是全部的要点：当前任务正站在自己的内核栈上，
/// 它的映射（如果有）在这一刻**不能**解映射。所以退出时先标 Free、把资源留在槽里，
/// 等这个 CPU 换别人上来之后再收。
pub fn reap(cpu: usize) -> usize {
    if cpu >= crate::arch::x86_64::cpu::MAX_CPUS || REAP_PENDING[cpu].load(Ordering::Acquire) == 0 {
        return 0;
    }
    let cur = current_of(cpu);
    let mut retired = 0usize;
    // 这一轮"该收但收不了"的槽数：只有"它就是当前任务"这一种阻塞原因。
    let mut waiting = 0usize;
    for slot in 0..MAX_TASKS {
        let gi = gidx(cpu, slot);
        // 一轮里这一格只取放一次队列锁（原来是 3~4 次：state、has_bag、id 各一次）。
        // 这不是微优化——A/B 之后必须把抢占点上的锁流量降下来（ADR-048 未决 1）。
        // `continue` 从这个块里离开时句柄先析构，不会带着锁跳出循环体。
        let (st, has_bag, _id) = {
            let s = rq(cpu);
            let st = s.tasks[slot].state;
            // Done 的判定带 `|| st == Done` 是因为"被杀但映射为空"也要归化成 Free，
            // 否则槽位永远停在 Done —— 那正是 M4-1 撞过的"队列被占满"的形状。
            (st, s.tasks[slot].owned.n > 0 || st == TaskState::Done, s.tasks[slot].id)
        };
        if st != TaskState::Free && st != TaskState::Done {
            continue;
        }
        if !has_bag {
            continue;
        }
        if gi == cur {
            // **不能收**：它的内核栈就是现在这条栈（或者它正站在里面的用户页上）。
            // 留着这一格计数，下一轮抢占点再来试；不能因为"这一轮放了别人"就把账抹平。
            waiting += 1;
            continue;
        }
        // 任务退出撤销：句柄表里 owner 两格都对的表项在这里清掉。**这是唯一安全的时刻**——
        // 它的内核栈与用户页都已经不会再被踩（设计 §7）。只读文件对象不持有页框，账只记在手柄表里。
        #[cfg(feature = "handles")]
        crate::handle::revoke_task(gi, _id);
        release_owned(cpu, slot);
        let mut s = rq(cpu);
        s.tasks[slot].state = TaskState::Free;
        s.tasks[slot].frame = 0;
        s.tasks[slot].runs = 0;
        s.entries[slot] = None;
        retired += 1;
    }
    // 计数 = "还在等 CPU 挪开的槽数"，**不是**"发生过几次退出"。
    // 上一版按后者记账并用 `done` 去减，于是被 `current` 挡住的那个槽会被
    // 别的槽的释放冲掉账（现场：`released` 涨了 7、槽位是 Free、而 `owned_of` 仍是 5）。
    // 语义变了就顺手把名字改对：它现在是一个"等待数"。
    REAP_PENDING[cpu].store(waiting, Ordering::Release);
    retired
}

const EMPTY_TASK: Task = Task {
    id: 0,
    frame: 0,
    kstack_lo: 0,
    kstack_hi: 0,
    kstack_top: 0,
    stack_lo: 0,
    stack_hi: 0,
    guarded: false,
    state: TaskState::Free,
    user: false,
    resident: false,
    proc_id: crate::proc::NO_PROC,
    as_slot: NO_ASPACE,
    as_pml4: 0,
    on_cpu: 0,
    runs: 0,
    left_tsc: 0,
    owned: OwnedSet::new(),
};

/// 一条 CPU 的运行队列。`current` 与 `tasks` 必须放在一起：
/// 把 `current` 做成全局的话，"谁在跑"这件事就又是两个核共用的一个格子。
struct RunQueue {
    tasks: [Task; MAX_TASKS],
    /// 本 CPU 正在跑的任务（全局下标）。每条队列只由自己的 CPU 读写，见模块头第 2 条。
    current: usize,
    entries: [Option<fn() -> !>; MAX_TASKS],
}

const EMPTY_QUEUE: RunQueue = RunQueue {
    tasks: [EMPTY_TASK; MAX_TASKS],
    current: 0,
    entries: [None; MAX_TASKS],
};

#[repr(C, align(64))]
struct QueueCell {
    lock: crate::sync::IrqSpinLock<()>,
    data: core::cell::UnsafeCell<RunQueue>,
}
// SAFETY: 队列的**写**只发生在持有 `lock`（`RANK_RUNQ`，取锁即关 IF）的时候，
// 由 `RqLock` 这个句柄保证——拿不到句柄就改不了 `data`。
// 剩下的一类访问是**跨核只读快照**（`state_of`/`current_of`/`runs_of` 等），
// 它们刻意不取锁：那是观测用的弱读，判据只用它做"归属对不对"这类断言，
// 不参与任何调度决定（要按它决定就得先有迁移协议，ADR-047 的 P9）。
// ADR-047 之前这段论证是"每条队列只由它自己的 CPU 读写"，那是靠人守的事实；
// 现在写权归锁，所以这条 unsafe 的凭据换成了锁本身。
unsafe impl Sync for QueueCell {}
static RQ: [QueueCell; crate::arch::x86_64::cpu::MAX_CPUS] = [const {
    QueueCell { lock: crate::sync::IrqSpinLock::new_isr_taken(crate::sync::RANK_RUNQ, ()), data: core::cell::UnsafeCell::new(EMPTY_QUEUE) }
}; crate::arch::x86_64::cpu::MAX_CPUS];

/// 一条队列的所有权句柄：持有它 = 本 CPU 关着中断独占这条队列。
///
/// 两条规矩（ADR-047）：
/// * **不许跨过 `context_load`**——换栈时本句柄的 `Drop` 不会在预期位置执行，
///   per-CPU 的等级栈与 IF 归属会一起错位（`lock-order.md` 的 M3b-1 那一节）；
/// * **不许在句柄活着的时候 `drop Mapping` / 等 shootdown 回执**——那是拿队列锁去等一把
///   跨 CPU 的锁，两条不变量会绑成一条（`release_owned` 因此自己分段取锁）。
struct RqLock {
    cell: &'static QueueCell,
    _g: crate::sync::IrqGuard<'static, ()>,
}

impl core::ops::Deref for RqLock {
    type Target = RunQueue;
    fn deref(&self) -> &RunQueue {
        // SAFETY: 见 QueueCell——`_g` 证明本 CPU 持有这条队列的 RANK_RUNQ 锁。
        unsafe { &*self.cell.data.get() }
    }
}

impl core::ops::DerefMut for RqLock {
    fn deref_mut(&mut self) -> &mut RunQueue {
        // SAFETY: 同上；`&mut self` 保证同一时刻只有一个可变句柄。
        unsafe { &mut *self.cell.data.get() }
    }
}

/// 每条 CPU 的调度标志，**一行一条缓存行**：三个原子数组按 CPU 铺开时，
/// 八个原子量正好挤在同一条 64 字节行里，而它就在被测路径正中间（读 `NEED_RESCHED`、写 `TICKS`）
/// ⇒ AP 每次 tick 都在动 BSP 那条行，这是伪共享。拆行之类的量化过程见 ADR-024。
#[repr(C, align(64))]
struct FlagRow {
    /// 本 CPU 是否需要重调度。tick 置位，`preempt_point` 复位。
    need: AtomicBool,
    /// 本 CPU 观察到的 tick 数（BSP 经 I/O APIC、AP 经本地 APIC 定时器）。
    ticks: AtomicUsize,
    /// 本 CPU 的切换次数（也是 P1 的样本数）。
    switches: AtomicUsize,
    /// 填充：让上面三个字段所在的那条缓存行不与邻居共享
    _pad: [usize; 6],
}

static FLAGS: [FlagRow; crate::arch::x86_64::cpu::MAX_CPUS] = [const {
    FlagRow {
        need: AtomicBool::new(false),
        ticks: AtomicUsize::new(0),
        switches: AtomicUsize::new(0),
        _pad: [0; 6],
    }
}; crate::arch::x86_64::cpu::MAX_CPUS];

/// 抢占标志**按 CPU 放**。
///
/// 全局一份的故障形状是这样的：AP 的本地 tick 把标志置起来，BSP 下一次出中断时
/// 就白做一遍"帧在不在这条栈上"的检查并可能换人——一次与 BSP 无关的事件改变了 BSP 的调度。
/// 反过来（BSP 置位、AP 清位）会把 BSP 真正需要的重调度悄悄吃掉。两个方向都不能留。

/// P1：`save + pick + 发出 context_load` 这段的周期数。
/// **不含** `iretq` 本身与之后新任务第一条指令的取指/TLB 成本，边界写死在这里。
/// M3b-2b 起按 CPU 分行，并且切换路径一次都不读 LAPIC id（槽位由异常入口传进来）。
/// 读数变化的归因是四轮排除法做下来的（结论：被测区间里多读了三次 UC- 寄存器，
/// 拆掉之后 2536 → 735；顺带量到一次 `self_slot()` ≈600 周期），过程与数据在 ADR-024。
static P1_LAST: [AtomicU64; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];
static P1_SUM: [AtomicU64; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];
static P1_MIN: [AtomicU64; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicU64::new(u64::MAX) }; crate::arch::x86_64::cpu::MAX_CPUS];
static P1_MAX: [AtomicU64; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];
/// 每个任务往自己的格子里加的计数：测试据此判断"确实轮转过"，而不是只切了一次。
/// 下标是**全局任务下标**（`gidx(cpu, slot)`），所以 BSP 的任务仍然落在 0..MAX_TASKS。
pub static WORK: [AtomicUsize; MAX_TASKS_TOTAL] = [const { AtomicUsize::new(0) }; MAX_TASKS_TOTAL];
static NEXT_ID: AtomicU32 = AtomicU32::new(1);
/// 换入用户任务时装 rsp0 的次数（= P1 区间里这一次额外写发生的次数）。
static RSP0_WRITES: AtomicU64 = AtomicU64::new(0);

pub fn rsp0_writes() -> u64 {
    RSP0_WRITES.load(Ordering::Relaxed)
}

#[inline]
fn rq(cpu: usize) -> RqLock {
    // SAFETY: `RQ` 是定长静态数组，调用方保证 cpu < MAX_CPUS（各入口都有检查）。
    let cell = &RQ[cpu];
    RqLock { cell, _g: cell.lock.lock() }
}

/// 本 CPU 的队列。
#[inline]
fn my_rq() -> RqLock {
    rq(crate::arch::x86_64::cpu::self_slot())
}

core::arch::global_asm!(
    r#"
    .text
    .code64
    // context_load(rdi = TrapFrame 低地址端, rsi = 本 CPU 的中断窗口是否开着)
    // —— 与 isr_common 的出口同构，差别只有一条：它永不返回。
    // 顺序必须是 trap.rs 里 TrapFrame 的字段顺序（cr2 最底，往上 r15..rax，再 vec/error_code，
    // 再 iretq 要的 rip/cs/rflags/rsp/ss）。两处对齐补丁不能省：
    //   add rsp,8   跳过 cr2（第 16 个压栈项，既不属于 iretq 也不属于 pop 序列）
    //   add rsp,16  跳过 vec + error_code
    // **第一件事是改写 rflags 的 IF 位**（ADR-021：IF 属于 CPU 不属于任务）：`iretq` 会把栈上
    // 那份 rflags 整个装回 CPU，连 IF 一起装。必须在**弹栈之前**改 [frame+160]，
    // 因为 rsi 会在 pop 序列里被覆盖掉。
    .global context_load
context_load:
    call if_patch
    mov rsp, rdi
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    iretq

    // IF 位的改写单独成为一个可调用的例程，有两个理由：
    // 1) `context_load` 永不返回，那段位操作本来就没有任何测试能走到"关着窗口"那一支；
    //    拆出来之后用例可以直接调它，走的是**同一条指令序列**，不是复制一份逻辑。
    // 2) 偏移 160（= `TrapFrame::rflags`）是 asm 与 Rust 之间少数几处没有类型系统保护的接缝，
    //    写错的现场是"某个别的寄存器变成了别的值"，比 IF 位错更难查。
    // 只用 rdi/rsi 与标志位，不碰任何 GPR：`context_load` 紧接着要从帧里 pop 它们。
    .global if_patch
if_patch:
    test rsi, rsi
    jz .Lip_clear
    bts qword ptr [rdi + 160], 9
    ret
.Lip_clear:
    btr qword ptr [rdi + 160], 9
    ret

    // 量具自检用的额外 invlpg（bench-switch-load 注入）：见 sched::preempt_point
    .global p1_extra_flush
p1_extra_flush:
    invlpg [rdi]
    ret
"#
);

extern "C" {
    fn context_load(frame: u64, if_open: u64) -> !;
    /// 只改写 `[frame+160]` 的 bit9，其余 22 个字一个都不碰。用例直接调它，
    /// 因此"关着窗口换入"那条分支不再是写好了却没人走过的代码。
    pub fn if_patch(frame: u64, if_open: u64);
    fn p1_extra_flush(addr: u64);
}

/// `TrapFrame::rflags` 相对帧底的偏移。写死一个常量比让 Rust 去 `offset_of!` 更危险，
/// 所以这里由 `TrapFrame` 的字段序算出来，并在 `t_if_belongs_to_cpu` 里断言它仍是 20 项。
const RFLAGS_OFF: usize = 20 * 8;
const RFLAGS_IF: u64 = 1 << 9;

pub fn current_id() -> usize {
    my_rq().current
}

/// 当前任务的 `(全局下标, Task::id)` 两格（P7 句柄的 owner）。
/// 只认槽号会让新任务继承死者的句柄：`spawn` 找 `Free` 槽而退出当场就标 Free（设计 §2.2）。
#[cfg(feature = "handles")]
pub fn current_identity() -> Option<(usize, u32)> {
    let cpu = crate::arch::x86_64::cpu::self_slot();
    let gi = current_of(cpu);
    let slot = slot_of(gi);
    let mut s = rq(cpu);
    let t = &s.tasks[slot];
    if t.state == TaskState::Free {
        None
    } else {
        Some((gi, t.id))
    }
}

/// 按**全局下标**查 `(gidx, Task::id)`。装载器用它把句柄授给"这个容器"，
/// 而不是授给正在跑验收的启动上下文——两者是不同任务，混了就等于没有归属。
#[cfg(feature = "handles")]
pub fn identity_of(gidx: usize) -> Option<(usize, u32)> {
    if gidx >= MAX_TASKS_TOTAL {
        return None;
    }
    let cpu = cpu_of(gidx);
    let slot = slot_of(gidx);
    let mut s = rq(cpu);
    let t = &s.tasks[slot];
    if t.state == TaskState::Free {
        None
    } else {
        Some((gidx, t.id))
    }
}

/// 某个 CPU 当前跑的任务（全局下标）。跨核用例用它证明"两个核各自跑各自队列里的任务"。
pub fn current_of(cpu: usize) -> usize {
    if cpu >= crate::arch::x86_64::cpu::MAX_CPUS {
        return 0;
    }
    // SAFETY: 只读，且读的是**别的 CPU 独占**的那条队列——这是一个无同步的快照读，
    // 用途仅限观测（判据只用它做"不等于"这种弱断言），不参与任何决策。
    // 这条不是可重用的接口：真要按它做调度决定，必须先有迁移锁。
    unsafe { (*RQ[cpu].data.get()).current }
}

/// (本 CPU 的切换次数, 本 CPU 的 tick 数, 可调度任务数)。
/// 前两个数**按 CPU 取**：把它们混成一个全局数，"BSP 换过 27 次人"和
/// "两个 CPU 各换过 13 次"就再也分不出来了。
pub fn stats() -> (usize, usize, usize) {
    let slot = crate::arch::x86_64::cpu::self_slot();
    (FLAGS[slot].switches.load(Ordering::Relaxed), FLAGS[slot].ticks.load(Ordering::Relaxed), tasks_active())
}

pub fn stats_of(slot: usize) -> (usize, usize) {
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS {
        return (0, 0);
    }
    (FLAGS[slot].switches.load(Ordering::Relaxed), FLAGS[slot].ticks.load(Ordering::Relaxed))
}

static SWITCHES_FOR: [AtomicUsize; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicUsize::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];

/// 所有 CPU 上"还能被调度"的任务数之和（跨核快照，只用于日志与判据）。
pub fn tasks_active() -> usize {
    // `Blocked` 不在集合里（它既不是 Runnable 也不是 Running）——这不是"任务消失了"，
    // 是它正在等；idle 也被排除（它不是工作）。两条都由 ADR-051/053 明确要求写明。
    (0..MAX_TASKS_TOTAL)
        .filter(|&i| {
            // idle 不是"工作"：把它算进去会让 active_left 一类读数凭空 +1（ADR-051 决策 4）
            i != idle_of(cpu_of(i))
                && matches!(state_of(i), TaskState::Runnable | TaskState::Running)
        })
        .count()
}

/// P1 的 **BSP** 读数：`(样本数, mean, min, max)`。样本数取本 CPU 的切换计数，
/// 与那张 per-CPU 表同源，不会出现"分母来自四个核、分子来自一个核"。
/// 手册 §12.4.1 与 `tools/aurora.py bench` 的解析格式从这个形状来，所以不改成跨 CPU 汇总；
/// 各核分别走 `p1_stats_all()`，日志里单独打一行。
pub fn p1_stats() -> (u64, u64, u64, u64) {
    p1_stats_of(crate::arch::x86_64::cpu::BSP_SLOT)
}

pub fn p1_stats_of(slot: usize) -> (u64, u64, u64, u64) {
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS {
        return (0, 0, 0, 0);
    }
    let n = FLAGS[slot].switches.load(Ordering::Relaxed) as u64;
    (
        n,
        if n == 0 { 0 } else { P1_SUM[slot].load(Ordering::Relaxed) / n },
        if n == 0 { 0 } else { P1_MIN[slot].load(Ordering::Relaxed) },
        P1_MAX[slot].load(Ordering::Relaxed),
    )
}

/// 每个 CPU 的 P1 读数（只列真有样本的那些）。
pub fn p1_with_samples() -> alloc::vec::Vec<(usize, u64, u64, u64, u64)> {
    let mut out = alloc::vec::Vec::new();
    for s in 0..crate::arch::x86_64::cpu::MAX_CPUS {
        let (n, mean, min, max) = p1_stats_of(s);
        if n > 0 {
            out.push((s, n, mean, min, max));
        }
    }
    out
}


/// 定时器中断里只做两件事：计数 + 给自己那个 CPU 置标志。真正的换栈在异常出口做。
pub fn mark_tick() {
    let slot = crate::arch::x86_64::cpu::self_slot();
    FLAGS[slot].ticks.fetch_add(1, Ordering::Relaxed);
    FLAGS[slot].need.store(true, Ordering::Release);
}

/// 每个 CPU 收到 resched IPI 并立牌的次数（P4c 的见证读数）。
static RESCHED_MARKS: [core::sync::atomic::AtomicU64; crate::arch::x86_64::cpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];
static RESCHED_IPI_FAIL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// 收到 resched IPI 时立本 CPU 的 need 牌，并记一次见证读数。
fn mark_need_self() {
    let cpu = crate::arch::x86_64::cpu::self_slot();
    if cpu < crate::arch::x86_64::cpu::MAX_CPUS {
        RESCHED_MARKS[cpu].fetch_add(1, Ordering::Relaxed);
    }
    mark_need(cpu);
}

/// 该 CPU 收到并立牌的次数（跨核用例用它证明 IPI 真的到了）。
pub fn resched_marks(cpu: usize) -> u64 {
    if cpu >= crate::arch::x86_64::cpu::MAX_CPUS { return 0; }
    RESCHED_MARKS[cpu].load(Ordering::Relaxed)
}

/// resched IPI 发送失败次数。失败**不丢唤醒**：目标任务的状态已经是 Runnable，
/// 只是要等它自己的下一次 tick 才被选上，所以这里只计数不升 L4（与 shootdown 不同——
/// 那边收不齐回执就需要升 L4，因为正确性依赖回执）。
pub fn resched_ipi_fail() -> u64 { RESCHED_IPI_FAIL.load(Ordering::Relaxed) }

/// 向某个 CPU 发 resched IPI，让它尽快重新调度（ADR-055，P4c）。
pub fn request_resched(cpu: usize) -> bool {
    if cpu >= crate::arch::x86_64::cpu::MAX_CPUS || !crate::arch::x86_64::cpu::is_online(cpu) {
        return false;
    }
    let Some(id) = crate::arch::x86_64::cpu::lapic_id_of(cpu) else { return false };
    // 注入（欠账⑦ / ADR-062）：健康 QEMU 上 IPI 从不失败，resched_ipi_fail() 恒 0、没人能
    // 证明它会咬。这条构建在**记账点**强制走 Err 分支（与真失败同一条处置：计数 + 返回 false），
    // 验证计数真的涨、且失败不丢唤醒。注入放这里而不是 send_ipi_to：那里是 apic.rs，
    // check-vector-table 会把任何 `vector == VEC_*` 的提前 return 误读成"不发 EOI 的分支"。
    #[cfg(feature = "fault-resched-ipi")]
    let sent: Result<(), crate::arch::x86_64::apic::ApicError> = Err(crate::arch::x86_64::apic::ApicError::MapFailed);
    #[cfg(not(feature = "fault-resched-ipi"))]
    let sent = crate::arch::x86_64::apic::send_ipi_to(id, trap::VEC_RESCHED_IPI as u32);
    match sent {
        Ok(()) => true,
        Err(_) => { RESCHED_IPI_FAIL.fetch_add(1, Ordering::Relaxed); false }
    }
}

/// `current_id` 的**不取锁**版本（P7a）：只读快照，供故障/崩溃路径用。
/// 它不参与调度决定，所以弱读是合法的（与 `current_of` 同一条论证）。
fn current_id_no_lock() -> usize {
    current_of(crate::arch::x86_64::cpu::self_slot())
}

/// 把调度器实现装进 `sync` 的等待回调表（ADR-053 决策 1 的反转）。
/// `sync` 因此不引用 `sched`，依赖方向不变、环 A 不动。启动期装一次，之后只读。
pub fn install_wait_ops() {
    // 阻塞者总是当前任务，所以 ops 传来的下标只作校验用，实际改的是 current
    fn block_for_wait(_task: usize, token: crate::sync::WaitToken) -> bool {
        block_current(token)
    }
    crate::sync::install_wait_ops(crate::sync::WaitOps {
        current: current_id,
        block: block_for_wait,
        wake: wake_task,
        yield_now: yield_now,
        timer_add: timer_add_for_wait,
        timer_del: timer_del_for_wait,
    });
}

/// 给等待者注册到期项（P6b）。**由 `sync` 在持 WAITQ(5) 时调用**，这里取 TIMER(6)：
/// 方向 5→6 合法（lock-order.md）。token 与等待槽共用，所以两种唤醒谁先都认。
fn timer_add_for_wait(task: usize, token: crate::sync::WaitToken, deadline: u64) -> bool {
    let cpu = cpu_of(task);
    if cpu >= crate::arch::x86_64::cpu::MAX_CPUS {
        return false;
    }
    let mut g = WHEELS[cpu].lock();
    let w = g.get();
    let Some(slot) = w.slots.iter().position(|e| !e.used) else {
        return false;
    };
    w.slots[slot] = TimerEntry { used: true, deadline, task, token };
    w.registered += 1;
    true
}

/// 取消到期项；返回 true 表示它当时还挂着（即不是定时器叫醒的）。
fn timer_del_for_wait(task: usize, token: crate::sync::WaitToken) -> bool {
    let cpu = cpu_of(task);
    if cpu >= crate::arch::x86_64::cpu::MAX_CPUS {
        return false;
    }
    let mut g = WHEELS[cpu].lock();
    let w = g.get();
    for e in w.slots.iter_mut() {
        if e.used && e.task == task && e.token == token {
            e.used = false;
            return true;
        }
    }
    false
}

/// 把**当前任务**标成阻塞（ADR-053 P4a）。只改状态、**不让出**——
/// 调用方要在放掉队列锁之后自己 `yield_now()`，因为持锁切走会让 guard 在阻塞期间
/// 一直不释放（ADR-053 决策 2 修正了 ADR-047 的措辞）。
/// 返回 false 表示当前上下文不是可运行任务（没登记/已 Done），调用方不该再让出。
pub fn block_current(token: crate::sync::WaitToken) -> bool {
    let cpu = crate::arch::x86_64::cpu::self_slot();
    let mut s = rq(cpu);
    let me = s.current;
    let sl = slot_of(me);
    if !matches!(s.tasks[sl].state, TaskState::Running | TaskState::Runnable) {
        return false;
    }
    s.tasks[sl].state = TaskState::Blocked(token);
    true
}

/// 把**别的**任务标成阻塞（P5c-3a，使用者裁决的方案 B）。
///
/// 为什么要有这一条：`thread_create`（15 号）把新线程建出来就必须**停住它**，
/// 直到 `process_start`（16 号）把 `StartupInfo` 回填完（D2 要求子线程看到的是填好的表）。
/// 已有的 `block_current` 只能停"自己"，而刚 spawn 的任务不是当前任务。
///
/// 复用 `Blocked(token)` 而不是给 `Task` 加一个 `parked` 标志：状态机、picker 的跳过、
/// `wake_task` 的世代核对、以及 ADR-061 那条"杀阻塞任务要摘两份注册"全都已经实测过；
/// 加标志位要同时动 pick/terminate/收尾扫描三处判据。
/// **这里不给 token 注册任何等待队列项**（它不等事件，只等 16 号），
/// 所以 terminate 路径上那两句摘链天然是无效操作，也不会漏出"格数"来。
pub fn block_task(gidx: usize, token: crate::sync::WaitToken) -> bool {
    if gidx >= MAX_TASKS_TOTAL {
        return false;
    }
    let cpu = cpu_of(gidx);
    let mut s = rq(cpu);
    let sl = slot_of(gidx);
    // 只停 Runnable：正在 CPU 上的该用 `block_current`（它还要负责让出），
    // Done/Free/Blocked 都不该被这条路径改写。
    if s.tasks[sl].state != TaskState::Runnable || current_of(cpu) == gidx {
        return false;
    }
    s.tasks[sl].state = TaskState::Blocked(token);
    true
}

/// 唤醒一个阻塞任务（P4a：立目标 CPU 的 need 牌；跨核 IPI 在 P4c）。
/// **只有**目标槽确实是 `Blocked` 且世代号匹配时才转移，否则返回 false：
/// 陈旧 wake、唤醒一个已 Free/Done 的槽、或 token 对不上，都必须是无效操作，
/// 否则会把一个新任务误当成旧等待者放出去（ADR-053 决策 4）。
pub fn wake_task(gidx: usize, token: crate::sync::WaitToken) -> bool {
    if gidx >= MAX_TASKS_TOTAL {
        return false;
    }
    let cpu = cpu_of(gidx);
    let moved = {
        let mut s = rq(cpu);
        let sl = slot_of(gidx);
        match s.tasks[sl].state {
            TaskState::Blocked(t) if t == token => {
                s.tasks[sl].state = TaskState::Runnable;
                true
            }
            _ => false,
        }
    };
    if moved {
        mark_need(cpu);
        // 跨核：牌已经立了，但目标 CPU 可能正在自旋/hlt，要一发 IPI 让它立刻看牌
        if cpu != crate::arch::x86_64::cpu::self_slot() {
            let _ = request_resched(cpu);
        }
    }
    moved
}

/// 主动让出：立牌 + 自陷 resched 向量（ADR-049，P3a）。
///
/// 为什么用自陷而不是直接调 `preempt_point`：那个函数的契约要求**异常帧就在当前任务
/// 栈上**，而普通内核上下文没有帧。`int 0xF0` 让硬件压帧，于是既有的
/// `isr_common → preempt_point` 原样可用，不需要第二套切换机制。
/// `int` 不受 IF 影响 ⇒ **关着窗口也能让出**，这正是 `loads_closed` 缺的触发源。
/// 门是中断门（不是陷阱门），所以硬件进来时清 IF、`iretq` 时按保存的 rflags 还原，
/// 窗口状态不会被这次让出改掉（ADR-021：IF 属于 CPU）。
pub fn yield_now() {
    mark_need(crate::arch::x86_64::cpu::self_slot());
    // SAFETY: `int` 会压栈并进入本 CPU 的同步入口，所以**不能**声明 nostack/nomem；
    // 向量 0xF0 的门是 DPL0、已装建帧桩（`STUB_NOERR 240`），处理侧只计数不发 EOI，
    // `iretq` 回到这里继续执行。前提：调用者是一个已登记的任务（帧要落在它的内核栈上），
    // 由 `preempt_point` 的"帧在不在这条栈上"那道检查兜住——不满足时它只是不换人。
    unsafe { core::arch::asm!("int {}", const crate::arch::x86_64::trap::VEC_RESCHED) };
}

/// 让本 CPU 在**下一次出中断时**换人。`mark_tick` 也立这块牌，但它同时把 tick 数加一——
/// 那是"发生过一次时钟"的记录，不该被别的理由借用（借用的后果是 P5/`ticks` 的数
/// 与真实 tick 数对不上，而那条"两台仪器数到同一个数"的判据就废了）。
/// 现在唯一的另一个用户是 `user::park_current`：任务被判死刑，必须当场换下去。
pub fn mark_need(slot: usize) {
    if slot < crate::arch::x86_64::cpu::MAX_CPUS {
        FLAGS[slot].need.store(true, Ordering::Release);
    }
}

/// 本 CPU 的 tick 数（AP 也数得出来，供跨核用例读）。
pub fn ticks_of(slot: usize) -> usize {
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS {
        return 0;
    }
    FLAGS[slot].ticks.load(Ordering::Relaxed)
}

/// ADR-021 的读数：换入时按窗口状态改写 IF 的各发生了多少次。
/// 两条都必须非 0 才算这条规则真的在跑——只有 open 没有 closed，说明窗口从来没关过，
/// 也就等于没测到"关掉之后换入的人不能带 IF"。
static IF_LOADS: [AtomicUsize; 2] = [const { AtomicUsize::new(0) }; 2];

pub fn if_loads() -> (usize, usize) {
    (IF_LOADS[0].load(Ordering::Relaxed), IF_LOADS[1].load(Ordering::Relaxed))
}

/// 某个任务当前存的异常帧里 IF 位的状态。None = 这个任务还没有异常帧。
/// 用例用它把 ADR-021 变成一次读数，而不是我的一句话。
/// §220：换入点探针（定义见 `preempt_point` 里的写入处）。`#[used]` 防链接器回收
/// （§216 踩过：无调用者的静态量会被当死代码删掉，宿主机就"符号找不到 ⇒ 整段不读"）。
#[used]
static SWITCH_PROBE: [core::sync::atomic::AtomicU64; 5] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 5];

pub fn frame_if_bit(slot_task: usize) -> Option<bool> {
    frame_rflags_of(slot_task).map(|f| f & RFLAGS_IF != 0)
}

/// 读某个任务当前存的异常帧里的 rflags（0 = 还没保存过帧）。
/// 用例靠它验证"帧里的 IF 位 == 该 CPU 的窗口状态"，而不是听我说。
pub fn frame_rflags_of(task: usize) -> Option<u64> {
    let f = task_frame(task)?;
    if f == 0 {
        return None;
    }
    // SAFETY: frame 落在该任务自己的栈上（preempt_point 已按栈边界校验过），
    // rflags 是第 20 项；本函数只在读侧，不改变任何状态。
    Some(unsafe { core::ptr::read_volatile((f as usize + RFLAGS_OFF) as *const u64) })
}

/// 第 i 个任务名下**还牵着几条映射**。排查回收用的独立证人：
/// "槽位是 Free"不等于"资源回去了"——上一版的现场就是这两件事同时成立、却还漏着 3 条保留。
pub fn owned_of(i: usize) -> usize {
    if i >= MAX_TASKS_TOTAL {
        return 0;
    }
    // SAFETY: 只读快照，理由同 `current_of`
    unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].owned.count() }
}

/// 某个任务当前的续跑点（全局下标）。None = 这个槽位没登记过任务。
/// `pub` 的唯一额外理由是 M4-1 的用例：`iretq` 那五个字段没有类型系统保护，
/// 用例要在**换入之前**把内存里的真值读回来对着看（见 main.rs 的 `user: ... frame=`）。
pub fn task_frame(task: usize) -> Option<u64> {
    if task >= MAX_TASKS_TOTAL {
        return None;
    }
    // SAFETY: 只读快照，理由同 `current_of`
    Some(unsafe { (*RQ[cpu_of(task)].data.get()).tasks[slot_of(task)].frame })
}

/// 把当前上下文登记为任务 0（启动上下文）。
pub fn init_boot_task() {
    let (lo, hi) = mm::boot_stack_range();
    let cpu = crate::arch::x86_64::cpu::self_slot();
    let mut s = rq(cpu);
    s.tasks[0] = Task {
        id: 0,
        frame: 0,
        kstack_lo: lo,
        kstack_hi: hi,
        kstack_top: hi - 16,
        stack_lo: lo,
        // 启动栈是 .bss 里的数组：它的"上一格"属于同一个静态量，不是 guard page
        stack_hi: hi,
        guarded: false,
        state: TaskState::Running,
        user: false,
        resident: true, // 每 CPU 的启动/空闲上下文：设计上不退出（名单见 Task::resident）
        proc_id: crate::proc::NO_PROC,
        as_slot: NO_ASPACE,
        as_pml4: 0,
        on_cpu: cpu as u8,
        runs: 1,
        left_tsc: 0,
        // 启动上下文跑在 `.bss` 的静态数组上，没有 `Mapping` 要它持有
        owned: OwnedSet::new(),
    };
    s.current = gidx(cpu, 0);
}

/// 把一个 CPU 的当前上下文登记为它自己队列里的任务 0（AP 的空闲上下文）。
///
/// 为什么不能沿用 `init_boot_task`：那个函数用 `mm::boot_stack_range()` 拿栈边界，
/// 那是 **BSP 的 `.bss` 启动栈**。AP 跑在自己那条由 VMM 建的带 guard 的栈上，
/// 边界不同。栈边界搞错的后果不是崩溃而是**永远不换人**：
/// `preempt_point` 的"帧在不在这条栈上"那道检查会一直判否，然后白倒一次标志。
pub fn init_idle_task(stack_lo: u64, stack_hi: u64, guarded: bool) {
    let cpu = crate::arch::x86_64::cpu::self_slot();
    let mut s = rq(cpu);
    s.tasks[0] = Task {
        id: 0,
        frame: 0,
        kstack_lo: stack_lo,
        kstack_hi: stack_hi,
        kstack_top: stack_hi - 16,
        stack_lo,
        stack_hi,
        guarded,
        state: TaskState::Running,
        user: false,
        resident: true, // 每 CPU 的启动/空闲上下文：设计上不退出（名单见 Task::resident）
        proc_id: crate::proc::NO_PROC,
        as_slot: NO_ASPACE,
        as_pml4: 0,
        on_cpu: cpu as u8,
        runs: 1,
        left_tsc: 0,
        // AP 空闲上下文的栈由 `smp` 为**这个 CPU** 建，终身持有：不能挂到任务上，
        // 否则任务被换下时会被 `reap` 解映射，把一个还在用的 CPU 栈抽掉。
        owned: OwnedSet::new(),
    };
    s.current = gidx(cpu, 0);
}

/// P3b-2：每 CPU 的兜底 idle 栈。**静态**持有，不挂到任务名下（`owned` 为空）——
/// 否则它被换下时 `reap` 会把一条还在用的 CPU 栈解映射（`init_idle_task` 的注释已写明这条）。
/// 放 .bss 而不是走分配器：idle 必须在堆/VA 保留表耗尽时仍然存在，它是最后的兜底。
const IDLE_STACK_BYTES: usize = 8192;
#[repr(C, align(16))]
struct IdleStack([u8; IDLE_STACK_BYTES]);
// 必须用 `UnsafeCell` 包起来：裸的 `[const { IdleStack([0; N]) }; N]` 被 LLVM 当成
// 编译期常量放进了 **.rodata**（实测 `llvm-objdump -t` 显示段名 .rodata），
// 于是往里写帧当场 #PF(err=0x3，写只读页)。UnsafeCell 表达内部可变性，落到可写段。
#[repr(C, align(16))]
struct IdleStackCell(core::cell::UnsafeCell<IdleStack>);
// SAFETY: 每个 CPU 只碰 `IDLE_STACKS[自己那格]`（索引取自 `cpu::self_slot()`），
// 而写帧只发生在 `init_idle` 持本 CPU 队列锁、IF=0 的那一次；此后这块内存只由
// 该 CPU 上的 idle 任务自己当栈用。与 `QueueCell` 同一条论证形状。
unsafe impl Sync for IdleStackCell {}
static IDLE_STACKS: [IdleStackCell; crate::arch::x86_64::cpu::MAX_CPUS] =
    [const { IdleStackCell(core::cell::UnsafeCell::new(IdleStack([0; IDLE_STACK_BYTES]))) };
        crate::arch::x86_64::cpu::MAX_CPUS];
/// 每个 CPU 的 idle 全局下标；`usize::MAX` = 还没登记。
static IDLE_GIDX: [core::sync::atomic::AtomicUsize; crate::arch::x86_64::cpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicUsize::new(usize::MAX) }; crate::arch::x86_64::cpu::MAX_CPUS];

/// 本 CPU 的兜底 idle 下标；`usize::MAX` 表示没有（那时 `pick_next` 仍退回旧行为）。
pub fn idle_of(cpu: usize) -> usize {
    if cpu >= crate::arch::x86_64::cpu::MAX_CPUS {
        return usize::MAX;
    }
    IDLE_GIDX[cpu].load(Ordering::Relaxed)
}

/// idle 的入口：开窗口后 `hlt` 等中断（P5/ADR-057）。
/// 它只在"没有别的可运行任务"时才会被选中（见 `pick_next` 的两遍扫描）。
fn idle_entry() -> ! {
    let cpu = crate::arch::x86_64::cpu::self_slot();
    // 自己开窗口、**永不关**：本任务不退出，与 AP 空闲上下文（smp 步骤 8/9）同一形状。
    // 不用 `with_interrupts`：它是"这次调用期间开着"的语义，最外层返回时照样倒牌
    // （ADR-068 只把**嵌套**改成计数，没改非嵌套的收场），而本任务的窗口是常驻的，
    // 属 ADR-068 决策 3 的裸接口一侧。牌开着，换入的下个任务按 ADR-021
    // 由 `context_load` 供 IF，语义不变。
    loop {
        // **每次 hlt 前都要重新开窗口**，不能只在入口开一次：牌是 per-CPU 的，
        // 别的代码（`with_interrupts` 最外层返回时一律把牌置 false，ADR-068 没改这一侧）
        // 会在 idle 不在 CPU 上时关掉它，而换回来时 `context_load` 按牌供 IF ⇒ IF=0 的
        // hlt 永远醒不来。
        // 实测：P6b 的用例调了 `apic::wait_ticks`（内部 with_interrupts）之后，
        // BSP 就停在 idle_entry 里 HLT=1 而 RFL=0x7（IF=0），整机静默。
        crate::arch::x86_64::apic::open_cpu_window(cpu);
        // P6a：有等待者 armed 时**不能 hlt**——用例常常停表跑，没有中断会来叫醒 idle，
        // 而等待时限只在 task_wake_tick 里检查 ⇒ hlt 睡死就是整机挂死（本轮实测 HANG）。
        // 这里改成转一圈再查，上限就是那个等待时限；没有等待者时行为与原来逐字相同。
        if task_wake_tick() {
            continue;
        }
        if cpu < crate::arch::x86_64::cpu::MAX_CPUS {
            IDLE_HLT[cpu].fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: hlt 只停到下一个中断；上面已开窗口（IF=1），所以本地 tick 或
        // resched IPI 都能叫醒它。不访问内存、不动栈。
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
}

// ---- P6：每 CPU 定时器轮（ADR-058）----
//
// 为什么放 `sched` 而不是 `time`：轮到点要叫醒任务，放 `time` 就新增 `time -> sched` 边，
// 而 `time` 在环 A 内、`sched` 是环外单点 ⇒ 会把 sched 拉进强连通分量，SCC 闸与棘轮同时红。
// 放这里则只用到已有的 `sched -> sync`（锁）与 `sched -> time`（TSC）边，依赖图不变。

/// 定时器轮的保留队列号：不与任何 `WaitQueue`（0..MAX_WAIT_QUEUES）冲突，
/// 所以它的世代号不会被误当成某个等待队列的唤醒。
const TIMER_QID: u8 = u8::MAX;
/// 每 CPU 的到期项槽数。**上限**，不是 workload 钉出来的（与 ADR-054 的 16×16 同一口径）。
const WHEEL_SLOTS: usize = 64;

#[derive(Clone, Copy)]
struct TimerEntry {
    used: bool,
    deadline: u64,
    task: usize,
    token: crate::sync::WaitToken,
}

struct Wheel {
    slots: [TimerEntry; WHEEL_SLOTS],
    seq: u64,
    registered: u64,
    fired: u64,
}

/// 每 CPU 一个轮，锁与数据同体（`RANK_TIMER`）。`Wheel` 全是普通数据 ⇒ Send ⇒ 锁自动 Sync，
/// 不需要再包一层 UnsafeCell（比 `RoleCell`/`OpsCell` 少三处 unsafe）。
static WHEELS: [crate::sync::IrqSpinLock<Wheel>; crate::arch::x86_64::cpu::MAX_CPUS] =
    [const { crate::sync::IrqSpinLock::new_isr_taken(crate::sync::RANK_TIMER, Wheel {
        slots: [TimerEntry { used: false, deadline: 0, task: 0,
                 token: crate::sync::WaitToken { queue: TIMER_QID, seq: 0 } }; WHEEL_SLOTS],
        seq: 0, registered: 0, fired: 0,
    }) }; crate::arch::x86_64::cpu::MAX_CPUS];

/// 睡到 `deadline`（TSC 绝对值）。返回 true = 由定时器叫醒（到期），
/// false = 没睡成（槽满/不是任务/已过期）或被别人提前叫醒。
/// **必须放锁后再切走**（ADR-053 决策 2）：持轮锁睡眠会让锁在整段睡眠里不释放。
pub fn sleep_until(deadline: u64) -> bool {
    let cpu = crate::arch::x86_64::cpu::self_slot();
    if cpu >= crate::arch::x86_64::cpu::MAX_CPUS {
        return false;
    }
    if deadline <= crate::tsc::now() {
        return false; // 已过期：不睡，调用方自己决定怎么处理
    }
    let me = current_id();
    let token = {
        let mut g = WHEELS[cpu].lock();
        let w = g.get();
        let Some(slot) = w.slots.iter().position(|e| !e.used) else {
            return false; // 槽满：不阻塞，调用方必须处理
        };
        w.seq = w.seq.wrapping_add(1);
        let tok = crate::sync::WaitToken { queue: TIMER_QID, seq: w.seq };
        w.slots[slot] = TimerEntry { used: true, deadline, task: me, token: tok };
        w.registered += 1;
        tok
    };
    if !block_current(token) {
        let mut g = WHEELS[cpu].lock();
        let w = g.get();
        for e in w.slots.iter_mut() {
            if e.used && e.token == token {
                e.used = false;
            }
        }
        return false;
    }
    yield_now(); // 锁已放掉，这时才切走
    // 回来：条目已被 wheel_tick 摘掉 ⇒ 是到期叫醒；还在 ⇒ 被别人提前叫醒，自己摘掉
    let mut g = WHEELS[cpu].lock();
    let w = g.get();
    for e in w.slots.iter_mut() {
        if e.used && e.task == me && e.token == token {
            e.used = false;
            return false;
        }
    }
    true
}

/// tick 路径上扫轮：把到期的项叫醒。**在 ISR 顶半之外**调用（`preempt_point` 开头），
/// 所以可以取锁；顶半只立牌，不碰轮（ADR-047 决策 7）。
fn wheel_tick(cpu: usize) {
    if cpu >= crate::arch::x86_64::cpu::MAX_CPUS {
        return;
    }
    let now = crate::tsc::now();
    let mut g = WHEELS[cpu].lock();
    let w = g.get();
    for e in w.slots.iter_mut() {
        if e.used && e.deadline <= now {
            e.used = false;
            w.fired += 1;
            // 持 TIMER(6) 取 RUNQ(8)：方向合法，见 lock-order.md
            let _ = wake_task(e.task, e.token);
        }
    }
}

/// `(registered, fired, 仍挂着的项数)`。判据用它对账，不靠串口猜。
pub fn timer_stats(cpu: usize) -> (u64, u64, usize) {
    if cpu >= crate::arch::x86_64::cpu::MAX_CPUS {
        return (0, 0, 0);
    }
    let mut g = WHEELS[cpu].lock();
    let w = g.get();
    (w.registered, w.fired, w.slots.iter().filter(|e| e.used).count())
}

/// 每个 CPU 的 idle 任务进入 `hlt` 的次数（P5 的见证读数）。
static IDLE_HLT: [core::sync::atomic::AtomicU64; crate::arch::x86_64::cpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];

/// idle 的 hlt 次数。**这是内核自报**，宿主机只能解析这一行，不是独立见证（ADR-057 写明）。
pub fn idle_hlt_count(cpu: usize) -> u64 {
    if cpu >= crate::arch::x86_64::cpu::MAX_CPUS { return 0; }
    IDLE_HLT[cpu].load(Ordering::Relaxed)
}

/// 给**本 CPU**登记一个专属 idle 任务（ADR-051 决策 3，P3b-2）。
/// 幂等：已登记就直接返回 true。栈是静态的，`owned` 为空，所以 `reap` 永远不会碰它。
pub fn init_idle() -> bool {
    let cpu = crate::arch::x86_64::cpu::self_slot();
    if cpu >= crate::arch::x86_64::cpu::MAX_CPUS {
        return false;
    }
    if idle_of(cpu) != usize::MAX {
        return true;
    }
    let base = IDLE_STACKS[cpu].0.get() as u64;
    let (lo, hi) = (base, base + IDLE_STACK_BYTES as u64);
    let mut s = rq(cpu);
    // 不用 slot 0：那是启动/空闲上下文的位置，`init_boot_task`/`init_idle_task` 会重写它。
    let Some(slot) = (1..MAX_TASKS).find(|&i| s.tasks[i].state == TaskState::Free) else {
        return false;
    };
    let f = (hi - trap::TRAP_FRAME_BYTES as u64) as usize;
    let mut frame = [0u64; 23];
    frame[16] = 0;
    frame[17] = 0;
    frame[18] = idle_entry as *const () as u64;
    frame[19] = trap::kcode_sel();
    frame[20] = 0x2; // IF 由 CPU 供（ADR-021），与 spawn 同一条规矩
    frame[21] = hi - 16;
    frame[22] = trap::kdata_sel();
    for (i, v) in frame.iter().enumerate() {
        // SAFETY: f..f+23*8 落在 IDLE_STACKS[cpu] 这个静态数组内（hi 是它的上界），
        // 16 字节对齐满足 u64 写入；此刻本 CPU 持队列锁且 IF=0，没有并发读者。
        unsafe { core::ptr::write_volatile((f + i * 8) as *mut u64, *v) };
    }
    let gi = gidx(cpu, slot);
    s.tasks[slot] = Task {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        frame: f as u64,
        kstack_lo: lo,
        kstack_hi: hi,
        kstack_top: hi - 16,
        stack_lo: lo,
        stack_hi: hi,
        guarded: false, // .bss 数组，与启动栈同理：上一格属于同一个静态量
        state: TaskState::Runnable,
        user: false,
        resident: true, // 兜底 idle 永不退出（ADR-051）：它是"没人可换"时的最后一格
        proc_id: crate::proc::NO_PROC,
        as_slot: NO_ASPACE,
        as_pml4: 0,
        on_cpu: cpu as u8,
        runs: 0,
        left_tsc: 0,
        owned: OwnedSet::new(),
    };
    IDLE_GIDX[cpu].store(gi, Ordering::Release);
    true
}

/// 建一个任务：保留 `STACK_VA_PAGES` 页，最低那一页永不映射当 guard。
/// 新任务挂在**调用者所在 CPU** 的队列上（`Task::on_cpu`），返回值是全局任务下标。
/// 建一个任务。**默认不是常驻工人**：收尾判据会在用例跑完之后把它点名。
/// 只有"设计上不退出"的启动路径工人要走 `spawn_resident`（名单见 `Task::resident`）。
pub fn spawn(entry: fn() -> !) -> Result<usize, mm::MmError> {
    spawn_inner(entry, false)
}

/// 与 `spawn` 同一件事，但把这个任务登记进**常驻名单**（ADR-050 未决 1 的另一半）。
/// 今天唯一的调用点是 AP 的工人循环（`smp.rs`）：它按设计不退出，`stop_aps()` 之后
/// 才随那条 CPU 一起停机。装进 hooks 表而不是让 arch 直调 sched，与 `spawn` 同一条理由。
pub fn spawn_resident(entry: fn() -> !) -> Result<usize, mm::MmError> {
    spawn_inner(entry, true)
}

fn spawn_inner(entry: fn() -> !, resident: bool) -> Result<usize, mm::MmError> {
    let cpu = crate::arch::x86_64::cpu::self_slot();
    // 分配走 mm 的锁，**不能**在已经拿着自己队列的时候做：
    // 队列的 SAFETY 前提是"只由本 CPU 碰"，而 mm 的等待时间完全可能跨过别的 CPU 的观察点。
    let win = mm::alloc_va_range(STACK_VA_PAGES).ok_or(mm::MmError::OutOfMemory)?;
    let map_lo = win.0 + mm::PAGE as u64; // 第一页留 guard
    let frames = mm::phys_alloc(STACK_PAGES.trailing_zeros() as u8, MOD_STACK_TASK)?;
    let m = mm::map(VirtAddr(map_lo), frames, PageFlags::RW)?;
    // 这一句以前是 `core::mem::forget(m)`，注释写"任务栈与内核同寿命：M3a 不做回收"。
    // M4-2 把它作废了：**任务会结束，所以它的栈必须有一个能在结束时还回去的主人**。
    // 忘记句柄的代价已经在台账上出现过两次（Done 的任务永久占格；页框与 VA 保留有去无回）。
    let mut owned = OwnedSet::new();
    owned.push(m)?;
    let stack_hi = win.0 + (STACK_VA_PAGES as u64) * mm::PAGE as u64;

    let mut s = rq(cpu);
    let slot = (0..MAX_TASKS).find(|&i| s.tasks[i].state == TaskState::Free).ok_or(mm::MmError::Unsupported)?;
    // 合成首次运行的异常帧：放在栈顶往下，字段顺序必须与 trap::TrapFrame 逐格一致。
    let f = (stack_hi - trap::TRAP_FRAME_BYTES as u64) as usize;
    let mut frame = [0u64; 23];
    // cr2..rax 全 0；vector/error_code 用 0（context_load 会跳过它们）
    frame[16] = 0; // vector
    frame[17] = 0; // error_code
    frame[18] = trampoline as *const () as u64; // rip
    frame[19] = trap::kcode_sel(); // cs
    // rflags 写成 **IF=0**（只剩保留位 0x2）。这不是"忘了开中断"：
    // ADR-021 规定 IF 属于 CPU，`context_load` 在换入的那一刻按本 CPU 的窗口状态改写这一位。
    // M3a 的旧写法是在这里手工置 IF（0x202），因为那时任务自带 rflags 是硬件默认行为，
    // 写 0x2 会让首次运行的任务永久聋掉、整个用例挂死。现在这条依赖已经从"约定"
    // 变成"由 CPU 供 IF"的机制，挂死的那条路不存在了——`t_if_belongs_to_cpu` 数的就是这件事。
    frame[20] = 0x2;
    frame[21] = stack_hi - 16; // 任务自己的 rsp
    frame[22] = trap::kdata_sel(); // ss
    for (i, v) in frame.iter().enumerate() {
        // SAFETY: f 落在刚映射的栈内，长度 23*8 字节已按上面算过不越界
        unsafe { core::ptr::write_volatile((f + i * 8) as *mut u64, *v) };
    }
    s.entries[slot] = Some(entry);
    s.tasks[slot] = Task {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        frame: f as u64,
        kstack_lo: map_lo,
        kstack_hi: stack_hi,
        kstack_top: stack_hi - 16,
        stack_lo: map_lo,
        stack_hi,
        guarded: true,
        state: TaskState::Runnable,
        user: false,
        resident,
        proc_id: crate::proc::NO_PROC,
        as_slot: NO_ASPACE,
        as_pml4: 0,
        on_cpu: cpu as u8,
        runs: 0,
        left_tsc: 0,
        owned,
    };
    Ok(gidx(cpu, slot))
}

/// 建一个**用户态**任务：一条自己的内核栈 + ring3 的入口与用户栈。
/// `res` 是它名下的其余资源（容器装进来的代码/数据/用户栈，见 `user::load`）；
/// 本函数只再加一条**内核栈**：ring3 陷入时硬件按 `TSS.rsp0` 切到那里，异常帧落在里面，
/// 所以它与任务同生同死——既不算 CPU 的，也不算镜像的。
/// 三条规则：①帧必须落在内核栈上，那道"帧在不在这条栈上"的检查才继续成立；
/// ②首次运行的帧同样是 `TrapFrame`（`cs/ss` 是 RPL3、`rsp` 指向用户栈），
/// 与内核任务共用 `context_load`；③`rflags` 里不写 IF——IF 由 CPU 供（ADR-021）。
/// 建一条用户线程。`arg` 写进首帧的 `rdi`（`TrapFrame` 的第 10 格），
/// 也就是子线程第一条用户指令看到的第一个参数（ADR-075 决策 5）。
/// **既有调用点全部传 0** ⇒ 行为逐字不变（`t_elf_load_run` 那一族本来就不看 rdi）。
pub fn spawn_user(entry_rip: u64, user_stack_top: u64, arg: u64, mut res: OwnedSet) -> Result<usize, mm::MmError> {
    let cpu = crate::arch::x86_64::cpu::self_slot();
    let win = mm::alloc_va_range(STACK_VA_PAGES).ok_or(mm::MmError::OutOfMemory)?;
    let map_lo = win.0 + mm::PAGE as u64;
    let frames = mm::phys_alloc(STACK_PAGES.trailing_zeros() as u8, MOD_STACK_KUSER)?;
    let m = mm::map(VirtAddr(map_lo), frames, PageFlags::RW)?;
    res.push(m)?;
    let kstack_hi = win.0 + (STACK_VA_PAGES as u64) * mm::PAGE as u64;

    let mut s = rq(cpu);
    let slot = (0..MAX_TASKS).find(|&i| s.tasks[i].state == TaskState::Free).ok_or(mm::MmError::Unsupported)?;
    let f = (kstack_hi - trap::TRAP_FRAME_BYTES as u64) as usize;
    let mut frame = [0u64; 23];
    frame[16] = 0; // vector
    frame[17] = 0; // error_code
    frame[10] = arg; // 用户入口的第一个参数（16 号传的是 StartupInfo 的 VA）
    frame[18] = entry_rip; // 用户代码入口
    frame[19] = trap::ucode_sel(); // cs = 0x23（RPL3）
    // 与内核任务同理：IF 由 CPU 供（ADR-021），这里只留保留位 0x2。
    // 差别在于这个值会随 iretq 装进 ring3 的 rflags——用户态能收中断，是因为
    // 换入它的那一刻本 CPU 的窗口是开的，不是因为这里写了 0x202。
    frame[20] = 0x2;
    frame[21] = user_stack_top; // 用户 rsp
    frame[22] = trap::udata_sel(); // ss = 0x1b（RPL3）
    for (i, v) in frame.iter().enumerate() {
        // SAFETY: f 落在刚映射的内核栈内，长度 23*8 字节已按上面算过不越界
        unsafe { core::ptr::write_volatile((f + i * 8) as *mut u64, *v) };
    }
    s.entries[slot] = None; // 用户任务没有内核入口函数
    s.tasks[slot] = Task {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        frame: f as u64,
        kstack_lo: map_lo,
        kstack_hi,
        kstack_top: kstack_hi - 16,
        stack_lo: 0,
        stack_hi: 0,
        guarded: true,
        state: TaskState::Runnable,
        user: true,
        resident: false, // 用户任务永远不进常驻名单：收尾判据对它本来就点名（ADR-050）
        proc_id: crate::proc::NO_PROC,
        as_slot: NO_ASPACE,
        as_pml4: 0,
        on_cpu: cpu as u8,
        runs: 0,
        left_tsc: 0,
        owned: res,
    };
    Ok(gidx(cpu, slot))
}

/// 所有任务入口的统一跳板。
extern "C" fn trampoline() -> ! {
    let me = current_id();
    // 入口指针要在**放掉队列锁之后**再调：工人函数体里会 spawn、会结束任务，那都要取队列锁，
    // 拿着锁调它 = 同 CPU 重入 = 当场 L4（ADR-047 决策 2：持锁不许跨未知回调）。
    let entry = {
        let s = my_rq();
        s.entries[slot_of(me)]
    };
    if let Some(f) = entry {
        f();
    }
    // W3 P3：工人函数返回 = 正常退出（exit_code=0）。顺序是"先置结局、再摘牌"：
    // 等待方以 Done 当"结局可读"的凭据，反序给它一个看到 Done 却读不到退出码的空窗。
    // proc_id 是一次性边令牌（取走即置回 NO_PROC），所以自己调过 finish_current、
    // 又从工人函数 return 出来的任务不会被减两次线程计数。
    let pid = my_rq().tasks[slot_of(me)].proc_id;
    if pid != crate::proc::NO_PROC {
        my_rq().tasks[slot_of(me)].proc_id = crate::proc::NO_PROC;
        crate::proc::proc_thread_exited(pid, 0);
    }
    {
        let mut s = my_rq();
        s.tasks[slot_of(me)].state = TaskState::Done;
    }
    loop {
        crate::tsc::spin(1000);
    }
}

static RUN: AtomicBool = AtomicBool::new(true);

/// 工作任务的主循环靠它判断"该收工了"。收工 = 把自己标成 Done，
/// 然后等下一次 tick 把自己换下去（本里程碑**没有**主动让出，见模块头第 1 条：
/// 只有异常帧这一种续跑格式，所以"任务自己放弃 CPU"也必须由时钟来推进）。
pub fn should_run() -> bool {
    RUN.load(Ordering::Relaxed)
}

pub fn stop_workers() {
    RUN.store(false, Ordering::Relaxed);
}

/// 打开工作循环的闸门。每个要用工人的用例**自己**调一次：
/// `RUN` 是全局的收工标志，而 `.ktests` 的枚举顺序由链接顺序决定，
/// 不能假设"上一个用例没把它关掉"——那样同一个构建会因为顺序不同给出两种样本数。
pub fn start_workers() {
    RUN.store(true, Ordering::Relaxed);
}

/// 等到任务 0（开窗口的那个上下文）重新拿到 CPU。
///
/// 关闭中断的动必须由**开启它的**上下文执行，否则别的任务会带着 IF=1 一直占着 CPU，
/// 而窗口的另一半代码永远不会跑（实测就是这么挂死的）。本函数在窗口内调用。
pub fn wait_for_boot_task(budget_cycles: u64) -> bool {
    let t0 = crate::tsc::now();
    while current_id() != 0 {
        if crate::tsc::now() - t0 > budget_cycles {
            return false;
        }
        crate::tsc::spin(20_000);
    }
    true
}

// ---- P6a（ADR-071 决策 1）：任务/进程收工的等待与唤醒 ----
//
// 形状照定时器轮那一套（保留队列号 + 自己的表 + block_current），**不占 `WaitQueue` 的 16×16 槽**：
// 那些槽是给"用户任务条件变量"用的，把内核等待塞进去会让"队列满"这种业务错误码去承载内核契约违例。
//
// **收工出口只发布、不在那里唤醒**：`kill_current` 可能在持着 VMM(20) 的故障路径上被调到，
// 而 `wake_task` 要取目标 CPU 的 RUNQ(8) ⇒ 20→8 的反向嵌套（per-CPU 等级栈看得见，当场 L4）。
// 所以出口只做原子写（置 signal + 把等待槽标成"已置信号"），真唤醒放在 `preempt_point` 里
// **need 闸之后**那一处——与 `wheel_tick` 同一个位置、同一条安全论证：need 只由 tick/resched IPI 立，
// 而那些只在 IF=1 时被取走 ⇒ 被中断的上下文不可能持着锁。代价是唤醒最多晚一个 tick，如实记。

/// 任务/进程等待的保留队列号（与 `TIMER_QID = u8::MAX` 同一手法：只出现在 token 里）。
const TASK_QID: u8 = u8::MAX - 1;
/// 等待者槽数。**上限**，不是 workload 钉出来的（与 `WHEEL_SLOTS` 同一口径）：
/// 今天 `MAX_PROCESSES = 4`、用例里同时等待的不超过 2 个，取 8 留一倍余量。
const TASK_WAIT_SLOTS: usize = 8;
/// 等的是任务槽还是进程。
const TW_TASK: u8 = 1;
const TW_PROC: u8 = 2;
/// 槽状态：0 空 → 1 已占未武装 → 2 已武装 → 3 已置信号待唤醒 → 4 已唤醒（等调用方读走 observed）。
/// **先写字段、最后用 Release 写 state=2**；唤醒方用 Acquire 读 state ⇒ 看到 2 就一定看得到字段。
/// 这条顺序是"不丢唤醒"的全部要点：武装在前、查条件在后，
/// 若信号在武装之前就置好了，调用方那次查条件会看见并直接返回。
const TW_FREE: u8 = 0;
const TW_CLAIMED: u8 = 1;
const TW_ARMED: u8 = 2;
const TW_SIGNALLED: u8 = 3;
const TW_WOKEN: u8 = 4;

struct TaskWaiter {
    state: core::sync::atomic::AtomicU8,
    kind: core::sync::atomic::AtomicU8,
    target: core::sync::atomic::AtomicU32,
    waiter: core::sync::atomic::AtomicU32,
    seq: core::sync::atomic::AtomicU64,
    deadline: core::sync::atomic::AtomicU64,
    observed: core::sync::atomic::AtomicU32,
}

static TASK_WAITERS: [TaskWaiter; TASK_WAIT_SLOTS] = [const {
    TaskWaiter {
        state: core::sync::atomic::AtomicU8::new(TW_FREE),
        kind: core::sync::atomic::AtomicU8::new(0),
        target: core::sync::atomic::AtomicU32::new(0),
        waiter: core::sync::atomic::AtomicU32::new(0),
        seq: core::sync::atomic::AtomicU64::new(0),
        deadline: core::sync::atomic::AtomicU64::new(0),
        observed: core::sync::atomic::AtomicU32::new(0),
    }
}; TASK_WAIT_SLOTS];

static TASK_WAKE_PENDING: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// 当前**已武装**的等待者数（P6c）。有了它，`task_wake_tick` 在"没人等待"时只做一次 Acquire 读，
/// 不再每圈扫 8 个槽——那是 P6a 记在 `p4-tolerance.md` 上的成本账（抢占点与 idle 每圈都扫）。
/// 只数 ARMED 状态的进出：登记时 +1，被信号/超时唤醒时 -1；调用方自己读走结果那一支不减
/// （它离开 ARMED 是在登记之后立刻查条件成立那条路，那里也要减，见 task_wait_take）。
static TASK_ARMED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static TASK_WAIT_SEQ: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
/// 观测计数：登记过几次、被信号唤醒几次、超时几次、槽满拒过几次。
/// 没有这四个数，"等待真的阻塞过"只能指着一句"返回了 true"空谈。
static TW_REGISTERED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static TW_SIGNALED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static TW_TIMEOUTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static TW_FULL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// §195 的三个**违例可见性**计数（不是业务量）：
/// `TW_WAKE_MISS` = drain 消费了槽但 `wake_task` 失败（等待者那时还没 Blocked）。
/// 旧代码把这个 false 用 `let _ =` 吞掉，于是唤醒被提前投递然后丢弃 ⇒ 永久停住（§194 测到的 B1）。
/// `TW_ARMED_FLOOR`/`TW_PENDING_FLOOR` = 饱和减撞到 0 的次数。**正常跑必须恒为 0**；
/// 非 0 就说明"谁转出 {ARMED,SIGNALLED} 谁减一次"这条不变量被破了，比下溢成 u64::MAX 好查得多。
static TW_WAKE_MISS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static TW_ARMED_FLOOR: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static TW_PENDING_FLOOR: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// 饱和减：到 0 就不减并记一次违例。`fetch_sub` 在 usize 上双减会回绕成 u64::MAX（§194 实测），
/// 那会让判别表把"计数坏了"读成"有等待者"。这里让下溢**不可能**，同时把违例留成可读的数。
fn sat_dec(c: &core::sync::atomic::AtomicUsize, floor: &core::sync::atomic::AtomicU64) {
    use core::sync::atomic::Ordering as O;
    if c.fetch_update(O::AcqRel, O::Relaxed, |v| if v == 0 { None } else { Some(v - 1) }).is_err() {
        floor.fetch_add(1, O::Relaxed);
    }
}

/// 槽状态快照（§195 的 post-block 再查要用）。
fn task_wait_state(slot: usize) -> u8 {
    TASK_WAITERS[slot].state.load(Ordering::Acquire)
}

/// §195：`block_current` 之后**再查一次槽**。返回 true = 槽已被 drain 消费成 WOKEN。
/// 为什么必须再查：登记与 block_current 之间等待者还是 Running，drain 若在这段窗口里消费了槽，
/// `wake_task` 会失败（目标不是 Blocked），槽却已经 WOKEN、ARMED/PENDING 已减 ⇒
/// 之后 block_current 把等待者永久停住。这一支负责**自己把牌翻回来**（ADR-073 补记）。
fn wait_slot_already_drained(slot: usize, me: usize, token: crate::sync::WaitToken) -> bool {
    if task_wait_state(slot) != TW_WOKEN {
        return false;
    }
    // 把 block_current 置的 Blocked(token) 翻回 Runnable；若 drain 那次 wake 已成功，
    // 这里看到的是 Runnable ⇒ 返回 false，是无效操作，不改语义（ADR-053 决策 4）。
    let _ = wake_task(me, token);
    true
}

/// 三个违例计数给用例与宿主机仪器用（与 `task_wait_stats` 同一姿态，不动它的四元组签名）。
pub fn task_wait_health() -> (u64, u64, u64) {
    (
        TW_WAKE_MISS.load(Ordering::Relaxed),
        TW_ARMED_FLOOR.load(Ordering::Relaxed),
        TW_PENDING_FLOOR.load(Ordering::Relaxed),
    )
}

/// 这四个数给用例与 `object_wait` 的判据用（与 `sync::stats()` 同一姿态）。
pub fn task_wait_stats() -> (u64, u64, u64, u64) {
    (
        TW_REGISTERED.load(Ordering::Relaxed),
        TW_SIGNALED.load(Ordering::Relaxed),
        TW_TIMEOUTS.load(Ordering::Relaxed),
        TW_FULL.load(Ordering::Relaxed),
    )
}

/// 收工出口调它：**只原子写，不取任何锁、不唤醒**（理由见上面那段）。
/// `observed` 对任务等待是 1，对进程等待是进程的 signal（`TERMINATED | 退出码`）。
pub fn task_wait_signal(kind: u8, target: u32, observed: u32) {
    use core::sync::atomic::Ordering as O;
    for w in TASK_WAITERS.iter() {
        if w.state.load(O::Acquire) == TW_ARMED
            && w.kind.load(O::Relaxed) == kind
            && w.target.load(O::Relaxed) == target
        {
            w.observed.store(observed, O::Relaxed);
            w.state.store(TW_SIGNALLED, O::Release);
            TASK_WAKE_PENDING.fetch_add(1, O::AcqRel);
            TW_SIGNALED.fetch_add(1, O::Relaxed);
        }
    }
}

/// 在 `preempt_point` 的 need 闸之后调：把"已置信号"与"已到期"的等待者真唤醒。
/// 这里可以取 RUNQ（`wake_task` 内部取），因为被中断的上下文不可能持锁（同 `wheel_tick` 的论证）。
fn task_wake_tick() -> bool {
    use core::sync::atomic::Ordering as O;
    // 没人武装也没有待唤醒 ⇒ 一次读就返回（这是 idle 与每个抢占点都要走的热路径）
    if TASK_ARMED.load(O::Acquire) == 0 && TASK_WAKE_PENDING.load(O::Acquire) == 0 {
        return false;
    }
    if TASK_WAKE_PENDING.load(O::Acquire) == 0 {
        // 没有信号也要看超时：超时是时间到了，不是谁发布的
        let now = crate::tsc::now();
        let mut any = false;
        for w in TASK_WAITERS.iter() {
            if w.state.load(O::Acquire) == TW_ARMED && w.deadline.load(O::Relaxed) <= now {
                any = true;
                break;
            }
        }
        if !any {
            return false;
        }
    }
    let now = crate::tsc::now();
    for w in TASK_WAITERS.iter() {
        let st = w.state.load(O::Acquire);
        let expired = st == TW_ARMED && w.deadline.load(O::Relaxed) <= now;
        if st != TW_SIGNALLED && !expired {
            continue;
        }
        // §195：**CAS 消费**。旧写法是 load-then-store，两个 drain 并发会各自减一次计数
        // （BSP 的 tick 抢占点与 idle 都调这里）⇒ ARMED 下溢成 u64::MAX（§194 run-099 实测）。
        // 只有把 st 改成 WOKEN 的那一个才减；CAS 失败说明别人（另一个 drain 或 take）已转出。
        if w.state.compare_exchange(st, TW_WOKEN, O::AcqRel, O::Relaxed).is_err() {
            continue;
        }
        if expired {
            // 超时那条路 observed 必须是 0。写在 CAS 之后：只有真消费了才动这个槽的字段，
            // 免得把 0 写进一个已被 take 释放、甚至已被别人重新登记的槽。
            w.observed.store(0, O::Relaxed);
            TW_TIMEOUTS.fetch_add(1, O::Relaxed);
        }
        sat_dec(&TASK_ARMED, &TW_ARMED_FLOOR);
        let gidx = w.waiter.load(O::Relaxed) as usize;
        let tok = crate::sync::WaitToken { queue: TASK_QID, seq: w.seq.load(O::Relaxed) };
        // wake 失败**不再吞掉**：记一次违例。等待者可能还没 Blocked（登记与 block_current 之间
        // 那段窗口），此时槽已 WOKEN 而没人会再叫醒它 ⇒ 由 wait_slot_already_drained 那一支自救。
        if !wake_task(gidx, tok) {
            TW_WAKE_MISS.fetch_add(1, O::Relaxed);
        }
        if st == TW_SIGNALLED {
            sat_dec(&TASK_WAKE_PENDING, &TW_PENDING_FLOOR);
        }
    }
    // 还有 armed 的等待者 ⇒ 调用方（idle）不能 hlt 睡死：停表时没有中断会来叫它，
    // 而时限要靠这里检查。返回 true 让 idle 改成有界自旋（上限就是那个时限）。
    TASK_WAITERS.iter().any(|w| w.state.load(O::Acquire) == TW_ARMED)
}

/// 登记一个等待槽。返回 (槽号, token)；槽满返回 None（调用方必须处理，不静默降级）。
fn task_wait_register(kind: u8, target: u32, me: usize, deadline: u64) -> Option<(usize, crate::sync::WaitToken)> {
    use core::sync::atomic::Ordering as O;
    for (i, w) in TASK_WAITERS.iter().enumerate() {
        if w.state
            .compare_exchange(TW_FREE, TW_CLAIMED, O::AcqRel, O::Relaxed)
            .is_ok()
        {
            let seq = TASK_WAIT_SEQ.fetch_add(1, O::Relaxed);
            w.kind.store(kind, O::Relaxed);
            w.target.store(target, O::Relaxed);
            w.waiter.store(me as u32, O::Relaxed);
            w.seq.store(seq, O::Relaxed);
            w.deadline.store(deadline, O::Relaxed);
            w.observed.store(0, O::Relaxed);
            w.state.store(TW_ARMED, O::Release);
            TASK_ARMED.fetch_add(1, O::AcqRel);
            TW_REGISTERED.fetch_add(1, O::Relaxed);
            return Some((i, crate::sync::WaitToken { queue: TASK_QID, seq }));
        }
    }
    TW_FULL.fetch_add(1, O::Relaxed);
    None
}

/// 读走结果并交回槽位。`None` = 这一槽不是"已唤醒"状态（不该发生，调用方按超时处理）。
fn task_wait_take(slot: usize) -> Option<u32> {
    use core::sync::atomic::Ordering as O;
    let w = &TASK_WAITERS[slot];
    let v = w.observed.load(O::Acquire);
    // §195 的不变量：**谁把槽转出 {ARMED,SIGNALLED} 谁减一次**。
    // ARMED：登记时 +1，这里减。SIGNALLED：信号时 ARMED 没减（它仍算武装）而 PENDING +1，
    // 所以这一支要减两个——旧写法只判 ARMED，于是"信号已置、调用方查条件成立自己收走"会漏减。
    // WOKEN：drain 已经减过，这里再减就违例（饱和减把它记成 floor 而不是回绕）。
    match w.state.swap(TW_FREE, O::AcqRel) {
        TW_ARMED => sat_dec(&TASK_ARMED, &TW_ARMED_FLOOR),
        TW_SIGNALLED => {
            sat_dec(&TASK_ARMED, &TW_ARMED_FLOOR);
            sat_dec(&TASK_WAKE_PENDING, &TW_PENDING_FLOOR);
        }
        _ => {}
    }
    Some(v)
}

/// 等一个进程收工（P6a）。返回 `Some(退出码)` 或 `None`（超时/槽满/不是可运行任务）。
/// **武装在前、查条件在后**，才不会丢唤醒（见 TW_ARMED 那段）：若信号在武装之前就置好了，
/// 下面那次查条件会看见并直接返回；若之后才置，发布方一定看得到已武装的槽。
/// 调用者必须是已登记的任务且不持任何锁；时限有界，超时返回 None **不升 L4**
/// （"目标永远不收工"是业务事实而不是契约违例，ADR-071 决策 1）。
pub fn wait_for_proc(proc_id: u16, deadline_cycles: u64) -> Option<u32> {
    let deadline = crate::tsc::now().wrapping_add(deadline_cycles);
    let me = current_id();
    let Some((slot, token)) = task_wait_register(TW_PROC, u32::from(proc_id), me, deadline) else {
        return None;
    };
    if crate::proc::proc_is_terminated(proc_id) {
        let _ = task_wait_take(slot);
        return Some(crate::proc::proc_exit_code(proc_id));
    }
    if !block_current(token) {
        let _ = task_wait_take(slot);
        return None;
    }
    // §195：同 wait_for_task 那一支（两个等待入口必须同律，否则修了一半）
    if wait_slot_already_drained(slot, me, token) {
        return match task_wait_take(slot) {
            Some(0) | None => None,
            Some(_) => Some(crate::proc::proc_exit_code(proc_id)),
        };
    }
    // 这里没持任何锁（block_current 的守卫已析构），所以可以直接切走（ADR-053 决策 2）
    yield_now();
    // 醒来了：observed=0 是超时那条路写的，非 0 才是真收工
    match task_wait_take(slot) {
        Some(0) | None => None,
        Some(_) => Some(crate::proc::proc_exit_code(proc_id)),
    }
}

/// 把创建者袋里"目标 AS = `as_slot`"的共享映射搬进子线程的袋（**P6b：进程级归属**）。
///
/// 为什么这样就够，不用新造一张进程级的表：`spawn_user` 就在**调用者那颗 CPU** 上建子线程，
/// 所以两个任务的 `owned` 在同一个 `RQ` 里 ⇒ **一次 RUNQ 就够**，不必嵌套两把同级锁
/// （8→8 是锁序违规）。搬完之后主人就是子线程：父先退不再带走子进程的代码/栈，
/// 而子线程死时由既有 `release_owned` 在锁外 drop（清叶子 + 还帧参考 + 放手 VA），
/// **一条新的释放路径都不用加**（ADR-027 的不变量原样保留）。
///
/// **先数清、确认装得下，再动手**：`push_item` 满了会就地 `drop`，而 `AsMap` 的 Drop 要取 VMM
/// 并等跨 CPU 回执 ⇒ 持 RUNQ 时做正是 ADR-047 决策 2 禁止的形状。所以这里预检容量，
/// 搬的过程**没有失败路径**，也不用那个会 drop 的入口。
pub fn adopt_asmaps(parent: usize, child: usize, as_slot: u8) -> Result<usize, mm::MmError> {
    if parent >= MAX_TASKS_TOTAL || child >= MAX_TASKS_TOTAL || parent == child {
        return Err(mm::MmError::Unsupported);
    }
    let cpu = cpu_of(parent);
    if cpu_of(child) != cpu {
        // 跨 CPU 就要两把同级 RUNQ ⇒ 违规。今天的调用点（16 号）保证同 CPU，
        // 这条闸是把那个前提变成显式拒绝，而不是靠"它恰好同 CPU"。
        return Err(mm::MmError::Unsupported);
    }
    let mut s = rq(cpu);
    let (psl, csl) = (slot_of(parent), slot_of(child));
    let mut n = 0usize;
    for it in s.tasks[psl].owned.items.iter() {
        if matches!(it, Some(OwnedItem::AsMap(m)) if m.as_slot() == Some(as_slot)) {
            n += 1;
        }
    }
    if s.tasks[csl].owned.count() + n > MAX_OWNED {
        return Err(mm::MmError::Unsupported);
    }
    let mut moved = 0usize;
    let mut w = 0usize;
    for i in 0..MAX_OWNED {
        let take = matches!(&s.tasks[psl].owned.items[i],
            Some(OwnedItem::AsMap(m)) if m.as_slot() == Some(as_slot));
        if take {
            let it = s.tasks[psl].owned.items[i].take();
            let cn = s.tasks[csl].owned.count();
            s.tasks[csl].owned.items[cn] = it;
            s.tasks[csl].owned.n = cn + 1;
            moved += 1;
        } else if s.tasks[psl].owned.items[i].is_some() {
            // 压缩创建者那一侧的空洞，保持 items[0..n] 紧排（`count()` 与它的不变量）
            s.tasks[psl].owned.items[w] = s.tasks[psl].owned.items[i].take();
            w += 1;
        }
    }
    s.tasks[psl].owned.n = w;
    Ok(moved)
}

/// 收掉一个进程的全部线程（**P6b：18 `process_kill`**，使用者裁决"全表扫 72 格按 proc_id 认"）。
/// 不新加每进程线程名单：那张表要维护"槽位复用/收工漏摘"一组新不变量，而今天只有 4 个进程、
/// 72 格扫一遍的成本可忽略。**逐个在锁外 terminate**（`terminate_task` 自己取放 RUNQ），
/// 跨 CPU 收线程走的就是 ADR-047/061 那条已验证的线。返回真收掉了几条。
pub fn kill_process_threads(proc_id: u16) -> usize {
    if proc_id == crate::proc::NO_PROC {
        return 0;
    }
    // 先快照出名单再动手：一边扫一边 terminate 会让同一个槽被复用后又被认成同一个进程
    let mut list = [0usize; MAX_TASKS_TOTAL];
    let mut n = 0usize;
    for gi in 0..MAX_TASKS_TOTAL {
        if state_of(gi) != TaskState::Free && proc_id_of(gi) == proc_id {
            list[n] = gi;
            n += 1;
        }
    }
    let mut killed = 0usize;
    for gi in list.iter().take(n) {
        if terminate_task(*gi) {
            killed += 1;
        }
    }
    killed
}

/// 等一条任务收工（P6a 把 P3 的轮询版换成真阻塞）。语义与原来一致：
/// 目标变成 `Done`/`Free` 返回 true，超时返回 false。**没有任务上下文时退回有界轮询**
/// （启动早期还没 `init_boot_task` 的调用方今天的形状），不静默假装等过。
pub fn wait_for_task(target: usize, deadline_cycles: u64) -> bool {
    let t0 = crate::tsc::now();
    let deadline = t0.wrapping_add(deadline_cycles);
    let me = current_id();
    let installed = me < MAX_TASKS_TOTAL
        && !matches!(state_of(me), TaskState::Free);
    if !installed {
        loop {
            if matches!(state_of(target), TaskState::Done | TaskState::Free) {
                return true;
            }
            if crate::tsc::now().wrapping_sub(t0) > deadline_cycles {
                return false;
            }
            yield_now();
        }
    }
    let Some((slot, token)) = task_wait_register(TW_TASK, target as u32, me, deadline) else {
        return false;
    };
    if matches!(state_of(target), TaskState::Done | TaskState::Free) {
        let _ = task_wait_take(slot);
        return true;
    }
    // 负样本（§194）：**只撑大窗口，不改任何语义**。这段自旋不持锁、不分配、不动中断牌，
    // 有界（约 6ms @3.2GHz），正常构建里整段不存在（`#[cfg]` 不是 `cfg!`，产物逐字节不变）。
    // 预期：目标在窗口里收工 ⇒ 唤醒被提前投递并丢弃 ⇒ 下面 block_current 之后永久停住。
    #[cfg(feature = "fault-wait-race")]
    {
        // 窗口入口计数：没有这个数，"注入没挂"可能只是**注入变空转了**（§193 的教训）。
        crate::log_info!("wait-race: 进入窗口 target={} 槽={}", target, slot);
        let t = crate::tsc::now();
        while crate::tsc::now().wrapping_sub(t) < 20_000_000 {
            core::hint::spin_loop();
        }
    }
    if !block_current(token) {
        let _ = task_wait_take(slot);
        return false;
    }
    // §195：槽若已被 drain 消费（唤醒提前投递给了还没 Blocked 的我们），**不能 yield**。
    if wait_slot_already_drained(slot, me, token) {
        // 只在注入构建里打：这一支被走到就是"窗口真被碰上且自救成功"的直接证据。
        // 正常构建里整段不存在 ⇒ 串口量与日志契约一字不动（P4 那把尺子不受影响）。
        #[cfg(feature = "fault-wait-race")]
        {
            let (miss, af, pf) = task_wait_health();
            crate::log_info!("wait-race: 提前投递的唤醒已自救 miss={} armed_floor={} pending_floor={}", miss, af, pf);
        }
        return !matches!(task_wait_take(slot), Some(0) | None);
    }
    yield_now();
    !matches!(task_wait_take(slot), Some(0) | None)
}

/// 把当前任务标成 Done：之后 `pick_next` 不会再选它。
///
/// 这里直接写非原子的 `state` 字段是有意的简化，但前提已经换成一条更窄的论证：
/// **本 CPU 的队列只由本 CPU 碰**（见 `QueueCell` 的 SAFETY），写它的任务上下文与
/// 读它的 ISR 在同一 CPU 上，而 ISR 只能在 IF=1 时到达——两件事不会同时发生。
/// 跨 CPU 读（`state_of`）只是观测快照，不参与决策。
pub fn finish_current() {
    let me = current_id();
    // W3 P3：先置结局再摘牌（同 trampoline 那条理由）；proc_id 取走即置回哨兵，边只走一次。
    let pid = my_rq().tasks[slot_of(me)].proc_id;
    if pid != crate::proc::NO_PROC {
        my_rq().tasks[slot_of(me)].proc_id = crate::proc::NO_PROC;
        crate::proc::proc_thread_exited(pid, 0);
    }
    my_rq().tasks[slot_of(me)].state = TaskState::Done;
    // P6c（ADR-071 决策 2 的"确定回收时刻"）：**正常收工也要登记待收**。
    // 原来只有 `kill_current` 登记，而 `reap` 在 REAP_PENDING 为 0 时直接返回 ⇒
    // 正常收工的槽要等别人去 kill/exit 才被顺手收掉，这就是"有效容量 5/9"那笔欠账的成因
    // （改前实测 `本CPU先占=4(其中Done待收=2)`）。登记之后回收时刻是确定的：
    // 下一次"本 CPU 跑的不是它"的抢占点。此刻它还是 current，所以 reap 会把它记成 waiting
    // 而保持计数非零，换人之后那一轮才真收 —— 不是立刻收，也不靠运气。
    REAP_PENDING[cpu_of(me)].fetch_add(1, Ordering::AcqRel);
    // P6a：**先置 signal 再发布等待者**。这里只原子写，真唤醒在抢占点的 need 闸之后做
    // （收工出口可能在持锁的故障路径上）。M38 实测：把这两句的顺序调换**仍然全绿**——
    // 因为唤醒是延迟到抢占点的，drain 跑起来时两句都已执行完 ⇒ 顺序在本设计里不可观测。
    // 所以"先置 signal 再唤醒"是**延迟唤醒设计的结构性后果**，不是一条被测出来的判据（ADR-054 口径）。
    task_wait_signal(TW_TASK, me as u32, 1);
    if pid != crate::proc::NO_PROC {
        task_wait_signal(TW_PROC, u32::from(pid), 1);
    }
}

/// **被杀**那条路径的"标结束"：`finish_current` 做的事 + 登记一次待回收。
/// 为什么不合并成一个：登记之后下一次抢占点会把这槽归化成 Free 并放手它名下的映射——
/// 对牵资源的用户任务正是我们要的（不登记就是静默的漏）；而跑完的**内核**任务也带着一条
/// 内核栈，合并会让 `KT_PREEMPT` 那几条"事后读这格发生过什么"的判据在观测之前就被清掉。
/// 内核任务的槽位回收本身是欠账（要连同"谁来读走这份记录"一起改）：见 BACKLOG ⑫ 与 M4 那节。
pub fn kill_current() {
    let me = current_id();
    let cpu = cpu_of(me);
    // W3 P3：被杀也置结局（退出码 1 = 非正常）。本函数在故障路径上也会被调，
    // 所以这条边一个锁都不取（proc_thread_exited 只动原子量）。
    let pid = my_rq().tasks[slot_of(me)].proc_id;
    if pid != crate::proc::NO_PROC {
        my_rq().tasks[slot_of(me)].proc_id = crate::proc::NO_PROC;
        crate::proc::proc_thread_exited(pid, 1);
    }
    my_rq().tasks[slot_of(me)].state = TaskState::Done;
    REAP_PENDING[cpu].fetch_add(1, Ordering::AcqRel);
    // P6a：被杀也算收工，等待者不该只能等超时（同 finish_current 的顺序）
    task_wait_signal(TW_TASK, me as u32, 1);
    if pid != crate::proc::NO_PROC {
        task_wait_signal(TW_PROC, u32::from(pid), 1);
    }
}

/// 第 i 个任务登记归属哪个 CPU。用例用它核对 `gidx/cpu_of/slot_of` 这组算术：
/// 队列拆成 per-CPU 之后，"全局下标"与"队列内下标"这对关系是新的接缝，
/// 写错的现场是某个任务永远不被调度或两个核抢同一个任务。
pub fn on_cpu_of(i: usize) -> Option<usize> {
    if i >= MAX_TASKS_TOTAL {
        return None;
    }
    // SAFETY: 只读快照，理由同 `current_of`
    Some(unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].on_cpu as usize })
}

/// 第 i 个任务的栈区间与"有没有 guard page"。用例要靠它验证 §6.4 那条不变量。
pub fn stack_bounds(i: usize) -> Option<(u64, u64, bool)> {
    if i >= MAX_TASKS_TOTAL {
        return None;
    }
    // SAFETY: 只读快照，理由同 `current_of`
    let t = unsafe { &(*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)] };
    if t.stack_lo == 0 {
        return None;
    }
    Some((t.stack_lo, t.stack_hi, t.guarded))
}

/// 第 i 个任务的**内核栈栈顶**（= 换入它时该装进 `TSS.rsp0` 的那个值）。
///
/// 与 `stack_bounds` 分开是因为两件事不是一回事：用户任务的 `stack_*` 描述的是
/// 它的**用户栈**（在用户半区），而 rsp0 用的是内核栈；把两者混成一个区间，
/// "ring3 栈溢出打在 guard 页上"与"陷入内核落在哪"就没法分别验证了。
pub fn kstack_top_of(i: usize) -> Option<u64> {
    if i >= MAX_TASKS_TOTAL {
        return None;
    }
    // SAFETY: 只读快照，理由同 `current_of`
    let t = unsafe { &(*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)] };
    if t.kstack_hi == 0 {
        return None;
    }
    Some(t.kstack_top)
}

pub fn state_of(i: usize) -> TaskState {
    if i >= MAX_TASKS_TOTAL {
        return TaskState::Free;
    }
    // SAFETY: 只读快照，理由同 `current_of`
    unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].state }
}

/// 改一条**已停住**的用户线程的首参（首帧 `rdi` = 第 10 格）。`process_start` 第④步用：
/// 回填完 `StartupInfo` 之后才把它的 VA 交给子线程，然后 `wake_task` 放它跑。
/// 只许对 `Blocked` 的槽做：Runnable/Running 的帧可能正被出口路径读，改它就是数据竞争。
pub fn set_thread_arg(gidx: usize, arg: u64) -> bool {
    if gidx >= MAX_TASKS_TOTAL {
        return false;
    }
    let cpu = cpu_of(gidx);
    let mut s = rq(cpu);
    let sl = slot_of(gidx);
    if !matches!(s.tasks[sl].state, TaskState::Blocked(_)) || !s.tasks[sl].user {
        return false;
    }
    let f = s.tasks[sl].frame;
    if f == 0 {
        return false;
    }
    // SAFETY: f 是这条任务内核栈上的真实异常帧（spawn_user 建帧时算过 kstack_hi - TRAP_FRAME_BYTES），
    // 23 个 u64 已映射；第 10 格是 rdi（TrapFrame 字段序），持 RUNQ 且任务是 Blocked ⇒ 无人同时在读它
    unsafe { core::ptr::write_volatile((f as usize + 10 * 8) as *mut u64, arg) };
    true
}

/// 这个槽位是不是用户态任务（P3a-2 的收尾不变量要用它区分"内核工人"与"容器任务"）。
/// 与 `state_of` 同样是只读快照，不参与调度决定。
pub fn is_user(i: usize) -> bool {
    if i >= MAX_TASKS_TOTAL {
        return false;
    }
    // SAFETY: 只读快照，理由同 `current_of`
    unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].user }
}

/// 这个槽位是不是**显式登记的常驻工人**（启动/空闲上下文、兜底 idle、AP 工人）。
/// 收尾判据用它把豁免范围从"所有内核任务"收到"名单里这几个"（ADR-050 未决 1 的另一半）。
/// 与 `is_user` 同样是只读快照，不参与调度决定，也不取队列锁（取锁会引入
/// "BSP 等 AP 的 RUNQ"这种跨核等待，ADR-047 决策 2 禁止的就是这个形状）。
pub fn is_resident(i: usize) -> bool {
    if i >= MAX_TASKS_TOTAL {
        return false;
    }
    // SAFETY: 只读快照，理由同 `current_of`
    unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].resident }
}

/// W3 P3：把一个已 spawn 的任务挂到进程上（用例用；将来 P5 的 `thread_create` 走同一条登记）。
///
/// 返回 `false` = 没挂上，调用方必须当成失败处理。两种拒绝：
/// - 目标不在**本 CPU** 的队列上：`QueueCell` 的论证是"每 CPU 的队列只由本 CPU 写"（ADR-047 决策 2），
///   跨 CPU 写要等远程登记那套一起重做；
/// - 目标已经不是 Ready：它在我们登记之前就跑完了 ⇒ 收工边走的是 `NO_PROC`，线程计数减不到，
///   这时候静默返回会让等待方一直空转到超时。
pub fn set_proc_id(i: usize, pid: u16) -> bool {
    if i >= MAX_TASKS_TOTAL || cpu_of(i) != crate::arch::x86_64::cpu::self_slot() {
        return false;
    }
    let mut s = my_rq();
    if !matches!(s.tasks[slot_of(i)].state, TaskState::Runnable | TaskState::Running) {
        return false;
    }
    s.tasks[slot_of(i)].proc_id = pid;
    true
}

/// 把一件资源挂到**当前任务**名下（syscall 路径用；退出时由 `reap`/`release_owned` 放手）。
/// 满了**先放 RUNQ 再丢**：`AsMap` 的 Drop 要取 VMM 并等别的 CPU 的 shootdown 回执，
/// 持着队列锁做那件事正是 ADR-047 决策 2 禁止的形状（`push_item` 的就地丢弃只在装载路径用）。
pub fn own_current(item: OwnedItem) -> Result<(), mm::MmError> {
    let me = current_id();
    let mut s = my_rq();
    if s.tasks[slot_of(me)].owned.count() >= MAX_OWNED {
        drop(s);
        refund_asmap(&item); // 已放 RUNQ 才退账（它要取 VMM）
        drop(item);
        return Err(mm::MmError::Unsupported);
    }
    s.tasks[slot_of(me)].owned.push_item(item)
}

/// 把一个任务登记到某个 AS 上（W3 P5b；用例用，P5c 的 `thread_create` 走同一条）。
/// **在这里查一次根表并缓存**，换人时就不再取 VMM。只允许本 CPU 的活任务（同 `set_proc_id`）。
pub fn set_aspace(i: usize, slot: u8) -> bool {
    if i >= MAX_TASKS_TOTAL || cpu_of(i) != crate::arch::x86_64::cpu::self_slot() {
        return false;
    }
    let pml4 = if slot == NO_ASPACE { 0 } else { mm::aspace_pml4_of(slot).unwrap_or(0) };
    if slot != NO_ASPACE && pml4 == 0 {
        return false;
    }
    let mut s = my_rq();
    if !matches!(s.tasks[slot_of(i)].state, TaskState::Runnable | TaskState::Running) {
        return false;
    }
    s.tasks[slot_of(i)].as_slot = slot;
    s.tasks[slot_of(i)].as_pml4 = pml4;
    true
}

/// 读一个任务的 AS 归属（只读快照，判据用）。
pub fn aspace_of(i: usize) -> u8 {
    if i >= MAX_TASKS_TOTAL {
        return NO_ASPACE;
    }
    // SAFETY: 只读快照，理由同 `current_of`
    unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].as_slot }
}

/// 读一个任务的 proc_id（只读快照）。
/// 这个任务槽**当前住户**的 `Task::id`（快照读，理由同 `state_of`）。
/// `id` 由全局 `NEXT_ID` 单调发号，所以"旧 id 撞上新一任住户"在回绕前不可能发生。
pub fn id_of(i: usize) -> u32 {
    if i >= MAX_TASKS_TOTAL {
        return 0;
    }
    // SAFETY: 只读快照，理由同 `state_of`
    unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].id }
}

/// 线程句柄的活性判据（P5c-1）：`Free` 槽或 id 对不上都算"没有这条线程"。
/// 语义是**保守拒绝**，不是"活着"的完备证明：判为真之后它仍可能立刻退出，
/// 那由 `state_of` 的调用方各自处理（本函数不改任何状态）。
pub fn thread_live(gidx: usize, id: u32) -> bool {
    id != 0 && id_of(gidx) == id && state_of(gidx) != TaskState::Free
}

pub fn proc_id_of(i: usize) -> u16 {
    if i >= MAX_TASKS_TOTAL { return crate::proc::NO_PROC; }
    // SAFETY: 只读快照，理由同 `current_of`
    unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].proc_id }
}

pub fn runs_of(i: usize) -> u64 {
    if i >= MAX_TASKS_TOTAL {
        return 0;
    }
    // SAFETY: 只读快照，理由同 `current_of`
    unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].runs }
}

/// 在本 CPU 的队列里选下一个。参数与返回值都是**全局任务下标**。
/// 队列已经是 per-CPU 的，所以这里只可能在自己那 `MAX_TASKS` 格里转；
/// `on_cpu` 那道过滤因此是**双重保险**而不是唯一防线——它同时把"迁移还没做"
/// 变成一条可检查的不变量（`t_percpu_queues` 就是数这个）。
fn pick_next(prev: usize, cpu: usize) -> usize {
    let s = rq(cpu);
    let idle = idle_of(cpu);
    let start = (slot_of(prev) + 1) % MAX_TASKS;
    // 第一遍：**排除 idle** 的轮转。这样只要还有真任务可跑，行为与 P3b-2 之前逐字相同，
    // 既有轮转判据与 P1 的样本形状都不受扰动（ADR-051 影响一节要求的"最小扰动"）。
    for k in 0..MAX_TASKS {
        let slot = (start + k) % MAX_TASKS;
        let gi = gidx(cpu, slot);
        if gi != idle && s.tasks[slot].state == TaskState::Runnable && s.tasks[slot].on_cpu as usize == cpu {
            return gi;
        }
    }
    // 第二遍：**只有 prev 自己已经不再可运行时**才回落 idle。
    // 要治的形状是"已标 Done/Free 却仍占着 CPU"：返回 prev 会让它永远不被换下，
    // 于是 `reap` 的 `skip = current` 永远跳过它、资源永不回账（BACKLOG 144）。
    // 反过来，prev 还活着（Runnable/Running）时返回 prev 是**正确且安全**的：
    // 它继续跑，不依赖 tick 才能回来。若无条件回落 idle，一个活任务在关窗口/停表时
    // 让出就会被切到 idle 而再也回不来——那正是 §111 那一类挂死，等于自己造一个新的。
    let prev_live = matches!(s.tasks[slot_of(prev)].state, TaskState::Runnable | TaskState::Running);
    if !prev_live && idle != usize::MAX && idle != prev && slot_of(idle) < MAX_TASKS {
        let sl = slot_of(idle);
        if s.tasks[sl].state == TaskState::Runnable && s.tasks[sl].frame != 0 {
            return idle;
        }
    }
    prev
}

/// 抢占点。由 `aurora_trap_entry` 在出口之前调用；`frame` 就是本次中断压在
/// 当前任务栈上的 `TrapFrame` 地址。若发生切换，本函数**不返回**
/// （它变成 `context_load`， iretq 进另一个任务）。
pub unsafe fn preempt_point(frame: u64, cpu: usize) {
    // 不跑调度器的 CPU 直接把标志倒掉再返回。今天 AP 的中断根本不经过这里
    // （`isr_stub_cpu_timer` 是独立快路径），这条判断是给"把 AP 接进调度"留的
    // 显式闸门，而不是靠"它恰好没被调用"这种隐式事实。
    // **回收点在这里，不在退出函数里**。任务自己结束的那一刻，它正站在要交出去的
    // 那条内核栈上（`SYS_EXIT` 走的就是它的上下文），当场解映射 = 下一次访存就故障
    // = ring0 故障 = 按 §9.2 升 L4。能安全放手的时刻只有一个：本 CPU 上跑的已经不是它。
    // 抢占点每轮都路过这里，所以先读一格计数（为 0 时一个字节都不多读）。
    if REAP_PENDING[cpu].load(Ordering::Acquire) != 0 {
        reap(cpu);
    }
    if !crate::arch::x86_64::cpu::runs_sched(cpu) {
        FLAGS[cpu].need.store(false, Ordering::Relaxed);
        return;
    }
    if !FLAGS[cpu].need.load(Ordering::Acquire) {
        return;
    }
    // P6：扫定时器轮。**必须在 need 闸之后**：need 只由 tick/resched IPI 立，而那些只在
    // IF=1 时被取走 ⇒ 被中断的上下文不可能持着锁。放在闸之前会让**每次异常出口**都扫轮，
    // 包括持 VMM(20) 时发生的同步 #PF ⇒ `锁序违规 外层 rank=20 本次 rank=6`（实测 3/3 39）。
    // 仍在取 RUNQ 之前，所以嵌套方向是 TIMER(6) -> RUNQ(8)，与锁序表一致。
    wheel_tick(cpu);
    // P6a：任务/进程等待的唤醒与超时也在这里做，同一条安全论证（need 闸之后 ⇒ 被中断的上下文不持锁）
    task_wake_tick();
    let t0 = crate::tsc::now();
    let me = current_of(cpu);
    let mslot = slot_of(me);
    // 这里只问"异常帧是不是就在当前任务的栈上"，**不问它的 state**：
    // 一个已经自己标成 Done 的任务仍然正占着 CPU，必须照样能被换下去，
    // 否则它就永久霸占处理器（实测：boot 任务再也不被调度，整机挂死）。
    // "在 CPU 上"和"可被调度"是两件事，之前把它们混成了同一个字段。
    let on_my_stack = {
        let s = rq(cpu);
        let t = &s.tasks[mslot];
        t.kstack_lo != 0 && frame >= t.kstack_lo && frame < t.kstack_hi
    };
    if !on_my_stack {
        FLAGS[cpu].need.store(false, Ordering::Relaxed);
        return;
    }
    // 判据是"有没有别的可调度任务"（下面靠 pick_next 返回自身来体现），
    // 不是"active 数量 >= 2"。用后者会死锁在这个位置：
    // 一个已经 Done 的任务还占着 CPU，而 active 只数 Runnable/Running，
    // 于是 done 任务永远不被换下、等待中的任务永远回不来（实测就是这样挂死的）。
    let next = pick_next(me, cpu);
    if next == me {
        FLAGS[cpu].need.store(false, Ordering::Relaxed);
        return;
    }
    let nslot = slot_of(next);
    // 锁内只取下一个任务的归属值（Copy），写 CR3 在放锁之后做
    let (next_as, next_slot) = {
        let s = rq(cpu);
        (s.tasks[nslot].as_pml4, s.tasks[nslot].as_slot)
    };
    {
        let mut s = rq(cpu);
        // 只有 Running 才降级成 Runnable。**不能**把 Done 又改回 Runnable：
        // 收工后的任务还在自己最后那段 spin 循环里，而它是带 IF=1 跑上来的，
        // 于是"标记完成 → 被时钟抢占 → 又被复活"会永远循环，
        // 且最后一个持有 CPU 的任务会永久霸占 CPU（实测：整个测试挂死）。
        if s.tasks[mslot].state == TaskState::Running {
            s.tasks[mslot].state = TaskState::Runnable;
        }
        s.tasks[mslot].frame = frame; // 换回来时从这个异常帧继续出口路径
        s.tasks[mslot].left_tsc = t0;
        s.current = next;
        s.tasks[nslot].state = TaskState::Running;
        s.tasks[nslot].runs += 1;
        // 换入用户任务要同时装 TSS.rsp0：ring3→ring0 硬件靠它找内核栈，
        // 装错或没装的下场是 #DF（rsp 从 0 开始压帧）。
        // 这条写在 P1 的被测区间之内——§7.2 说"CR3 写与 TSS RSP0 更新在 Rust 侧"，
        // 那这条代价就该被 P1 数到，而不是藏到区间外面去美化数字。
        if s.tasks[nslot].user {
            let top = s.tasks[nslot].kstack_top;
            trap::set_rsp0(cpu, top);
            RSP0_WRITES.fetch_add(1, Ordering::Relaxed);
        }
    }
    // W3 P5b（ADR-075 决策 2）：换入谁的表就与**实际 CR3** 比，相同不写（A2 的"不同才写"）。
    // **不拿 prev 任务的记录来比**：登记（`set_aspace`）只改记录、不改 CR3，所以"当前任务的记录"
    // 与实际 CR3 可以不一致；按记录比会漏写，实测后果是工人跑在内核表上读它自己 AS 的 VA
    // ⇒ ring0 `#PF cr2=0x200000000 err=0x0` 升 L4。`aspace_switch` 内部读 CR3 再决定写不写，
    // 那是唯一可靠的不变量（代价是每次换人多一条特权读，它在 P1 区间里，如实计入）。
    // 位置三条约束：①放掉 RUNQ 之后；②在 P1 的 `t0..d` 区间之内（§7.2：CR3 写是被测成本）；
    // ③在 `context_load` 之前，此后到换人只碰内核半区（所有 AS 共享，ADR-070 A1）⇒ 不会踩空。
    let target = if next_as == 0 { mm::our_cr3() } else { next_as };
    // SAFETY: target 来自登记时核对过的 AS 表项或内核根；内核半区等价由 aspace_new 保证；
    // 槽号与根表来自同一格的同一次读，所以位图写的是"这个表所属的 AS"
    let next_as_slot = if next_slot == NO_ASPACE { None } else { Some(next_slot) };
    unsafe { mm::aspace_switch(target, cpu, next_as_slot) };
    // 换出去的那次中断不会经过异常桩出口，所以在这里替它记账（见 trap::p3_record_irq）
    trap::p3_record_irq(cpu, crate::tsc::now().wrapping_sub(trap::entry_tsc_of(cpu)));
    FLAGS[cpu].switches.fetch_add(1, Ordering::Relaxed);
    #[cfg(feature = "trace-switch")]
    {
        let mut s = rq(cpu);
        crate::log_info!(
            "sw#{} cpu{} {}->{} me_frame={:#x} next_frame={:#x} st=[{:?},{:?},{:?}] need_rs={} ticks={}",
            cpu, me, next, frame, s.tasks[nslot].frame,
            s.tasks[0].state, s.tasks[1].state, s.tasks[2].state,
            FLAGS[cpu].need.load(Ordering::Relaxed), FLAGS[cpu].ticks.load(Ordering::Relaxed)
        );
    }
    // 量具自检（§12.4.1 规则 3）：带这个 feature 时，在**被测量的那段之内**加一件
    // 已知耗时的事，P1 必须变大，否则"切换成本"这条基线是修辞。
    // 位置是要害：第一次这段写在下面的记账之后，bench 当场报"切换 min 625 -> 810 不符合"
    // —— 那条"不符合"报得对，因为注入根本没落进 `t0..d` 这个区间里。
    // 负载量级也是实测定下来的：单加一条 invlpg（几百周期）会被同构建两次 min 之差吞掉。
    #[cfg(feature = "bench-switch-load")]
    {
        unsafe { p1_extra_flush(frame) };
        crate::tsc::spin(20_000);
    }
    let d = crate::tsc::now() - t0;
    P1_LAST[cpu].store(d, Ordering::Relaxed);
    P1_SUM[cpu].fetch_add(d, Ordering::Relaxed);
    P1_MIN[cpu].fetch_min(d, Ordering::Relaxed);
    P1_MAX[cpu].fetch_max(d, Ordering::Relaxed);
    FLAGS[cpu].need.store(false, Ordering::Relaxed);
    // ADR-021：换入的人带的 IF 由**本 CPU 的窗口状态**决定，不由它自己的异常帧决定。
    // 两个计数都要报：只有 open 没有 closed 就等于从没测过"窗口关着时换入不能带 IF"。
    //
    // `fault-if-carriage` 是这条决定的负样本：它改回"任务自己带 IF"（硬件的默认行为），
    // 用来证明这条规则不是修辞——去掉它，M3a 记录过的故障形状必须回来。
    #[cfg(not(feature = "fault-if-carriage"))]
    let if_open = crate::arch::x86_64::apic::interrupts_enabled(cpu);
    #[cfg(feature = "fault-if-carriage")]
    let if_open = frame_if_bit(next).unwrap_or(false);
    IF_LOADS[usize::from(if_open)].fetch_add(1, Ordering::Relaxed);
    // §220 **零串口换入探针**：run-701 实测 BSP 在 ring3 关中断自旋（IF=0 HLT=0 RIP 用户半区、
    // LAPIC IRR=32 已锁存）⇒ 要回答"换入它时牌是几"。只写静态量、串口零加行。
    // 槽0=最后一次 if_open 1=最后一次换入的 gidx 2=最后一次 cpu 3=牌=0 的换入次数 4=换入总次数
    SWITCH_PROBE[0].store(u64::from(if_open), Ordering::Relaxed);
    SWITCH_PROBE[1].store(next as u64, Ordering::Relaxed);
    SWITCH_PROBE[2].store(cpu as u64, Ordering::Relaxed);
    if !if_open {
        SWITCH_PROBE[3].fetch_add(1, Ordering::Relaxed);
    }
    SWITCH_PROBE[4].fetch_add(1, Ordering::Relaxed);
    // P1 的 SUM/MIN/MAX 三张表**今天仍是全局一份**。这在本段是成立的，因为
    // `runs_sched` 只有 BSP 为真——AP 跑调度之后，"两个核的切换成本"会被合成一个 min，
    // 那把尺子的含义就变了（与 P3/P5 同一件事，一起 per-CPU 化，见任务 #11 的第 2 步）。
    let resume = rq(cpu).tasks[nslot].frame;
    // SAFETY: resume 由 spawn 合成或上一次抢占时保存，落在该任务自己的栈上
    unsafe { context_load(resume, if_open as u64) }
}


/// ADR-040：把调度器实现装进 arch 的回调表。只在 after_switch 开头调用一次。
pub fn install_arch_hooks() {
    crate::hooks::install(crate::hooks::SchedHooks {
        mark_tick,
        mark_need: mark_need_self,
        current_id_snapshot: current_id_no_lock,
        init_idle_task,
        spawn,
        spawn_resident,
        bump_current_work,
        syscall_dispatch: crate::user::syscall_dispatch,
        park_current: crate::user::park_current,
        current_id,
        exit_current,
        preempt_point: preempt_hook,
        // ADR-067/P5：#PF 修复接缝装的是 mm 的实现（sched 只是安装方，不加自己的逻辑）。
        demand_zero: mm::demand_zero_try,
    });
}

/// AP 工人经 hook 调用：只数自己的圈，不再直接碰 WORK。
pub fn bump_current_work() {
    WORK[current_id()].fetch_add(1, Ordering::Relaxed);
}

/// hook 的安全垫片：把“必须持有当前异常帧”的契约收在这里，表里只放安全 fn。
fn preempt_hook(frame: u64, cpu: usize) {
    // SAFETY: 调用点是异常出口，frame 指向本 CPU 刚保存的 TrapFrame；
    // 契约与 sched::preempt_point 的 SAFETY 注释相同。
    unsafe { preempt_point(frame, cpu) }
}
