//! arch 与 sched 之间的回调表（ADR-040）。
//!
//! 方向：arch 只认这张表，sched 在启动期把实现装进来。安装发生在单核、关中断的
//! 启动早期，之后只读；默认桩保证“安装前被调用”也是安全的。
use core::cell::UnsafeCell;

use crate::arch::x86_64::trap::TrapFrame;
use crate::mm::MmError;

pub struct SchedHooks {
    pub mark_tick: fn(),
    pub init_idle_task: fn(u64, u64, bool),
    pub spawn: fn(fn() -> !) -> Result<usize, MmError>,
    pub bump_current_work: fn(),
    pub syscall_dispatch: fn(&mut TrapFrame) -> bool,
    pub park_current: fn(&mut TrapFrame),
    pub exit_current: fn(usize),
    /// 安全契片由 sched 安装；调用点必须在异常出口。
    pub preempt_point: fn(u64, usize),
}

struct HooksCell(UnsafeCell<SchedHooks>);
// SAFETY: install 只在 BSP 启动早期单次调用（AP 未释放、中断未开）；此后只读。
// 读侧是 `&'static SchedHooks`，字段全是 fn 指针，不存在可变别名。
unsafe impl Sync for HooksCell {}

fn no_mark_tick() {}
fn no_init_idle(_: u64, _: u64, _: bool) {}
fn no_spawn(_: fn() -> !) -> Result<usize, MmError> {
    Err(MmError::Unsupported)
}
fn no_bump() {}
fn no_syscall(_: &mut TrapFrame) -> bool {
    false
}
fn no_park(_: &mut TrapFrame) {}
fn no_exit(_: usize) {}
fn no_preempt(_: u64, _: usize) {}

static HOOKS: HooksCell = HooksCell(UnsafeCell::new(SchedHooks {
    mark_tick: no_mark_tick,
    init_idle_task: no_init_idle,
    spawn: no_spawn,
    bump_current_work: no_bump,
    syscall_dispatch: no_syscall,
    park_current: no_park,
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
