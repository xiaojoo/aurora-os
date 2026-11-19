//! arch 与 sched 之间的回调表（ADR-040）。
//!
//! 方向：arch 只认这张表，sched 在启动期把实现装进来。安装发生在单核、关中断的
//! 启动早期，之后只读；默认桩保证“安装前被调用”也是安全的。
use core::cell::UnsafeCell;

use crate::arch::x86_64::trap::TrapFrame;
use crate::mm::MmError;

pub struct SchedHooks {
    pub mark_tick: fn(),
    /// 收到 resched IPI 时立**本 CPU** 的 need 牌（ADR-055，P4c）。与 mark_tick 分开：
    /// 借 mark_tick 会把 tick 数灌进去，破坏"两台仪器数到同一个数"（ADR-049 决策 3）。
    pub mark_need: fn(),
    pub init_idle_task: fn(u64, u64, bool),
    pub spawn: fn(fn() -> !) -> Result<usize, MmError>,
    /// 同 `spawn`，但把新建的任务登记进**常驻工人名单**（`Task::resident`）。
    /// 唯一的调用点是 AP 的工人循环：它设计上不退出，所以用例收尾判据要豁免它，
    /// 而豁免必须显式，不能靠"它是内核任务"这种 blanket 理由（ADR-050 未决 1 的另一半）。
    /// 在 `spawn` 里一次性写定，不做"先建再标记"——那会让收尾有机会在标记之前看到一个
    /// 还没进名单的 Runnable 工人。
    pub spawn_resident: fn(fn() -> !) -> Result<usize, MmError>,
    pub bump_current_work: fn(),
    pub syscall_dispatch: fn(&mut TrapFrame) -> bool,
    pub park_current: fn(&mut TrapFrame),
    pub current_id: fn() -> usize,
    /// 同 `current_id` 但**不取锁**（只读快照），供故障/崩溃路径用（P7a/ADR-060）。
    /// 致命故障可能发生在持 VMM/HEAP 锁时，那条路上再取 RUNQ 会级联出第二条锁序违规。
    pub current_id_snapshot: fn() -> usize,
    /// #PF 修复接缝（ADR-067/P5）：只由 trap 在"ring3 ∧ 页不存在 ∧ 非取指"三条合取后调用，
    /// 返回 true = 页此刻已映射、重执行将成功；false = 不修，走既有 Kill/Fatal 判据。
    /// 走表而不是直调 `mm::`：环内 `arch->memory` 棘轮只许降不许升（ADR-040 的先例通道）。
    pub demand_zero: fn(u64) -> bool,
    pub exit_current: fn(usize),
    /// 安全契片由 sched 安装；调用点必须在异常出口。
    pub preempt_point: fn(u64, usize),
}

struct HooksCell(UnsafeCell<SchedHooks>);
// SAFETY: install 只在 BSP 启动早期单次调用（AP 未释放、中断未开）；此后只读。
// 读侧是 `&'static SchedHooks`，字段全是 fn 指针，不存在可变别名。
unsafe impl Sync for HooksCell {}

fn no_mark_tick() {}
fn no_mark_need() {}
fn no_init_idle(_: u64, _: u64, _: bool) {}
fn no_spawn(_: fn() -> !) -> Result<usize, MmError> {
    Err(MmError::Unsupported)
}
fn no_bump() {}
fn no_syscall(_: &mut TrapFrame) -> bool {
    false
}
fn no_park(_: &mut TrapFrame) {}
fn no_id() -> usize {
    0
}
fn no_demand_zero(_: u64) -> bool {
    false
}
fn no_exit(_: usize) {}
fn no_preempt(_: u64, _: usize) {}

static HOOKS: HooksCell = HooksCell(UnsafeCell::new(SchedHooks {
    mark_tick: no_mark_tick,
    mark_need: no_mark_need,
    init_idle_task: no_init_idle,
    spawn: no_spawn,
    spawn_resident: no_spawn,
    bump_current_work: no_bump,
    syscall_dispatch: no_syscall,
    park_current: no_park,
    current_id: no_id,
    current_id_snapshot: no_id,
    demand_zero: no_demand_zero,
    exit_current: no_exit,
    preempt_point: no_preempt,
}));

/// 启动期安装一次。重复调用是同一组实现，不做断言。
pub fn install(h: SchedHooks) {
    // SAFETY: 见 HooksCell；调用点固定在 after_switch 开头，早于 AP 与定时器。
    unsafe { *HOOKS.0.get() = h; }
}

pub fn sched() -> &'static SchedHooks {
    // SAFETY: 表在启动期安装、之后只读；默认桩让安装前的调用也可安全返回。
    unsafe { &*HOOKS.0.get() }
}
