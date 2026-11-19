//! §9.6 的软锁死一格：心跳 = 这个核的**定时器 tick**，"没前进"就是它已经不再响应自己的定时器。
//!
//! 心跳的来源两台不一样，必须按各自的接线读，不能拿一个数当两台仪器：
//! * BSP 走 `PIT(100 Hz) → I/O APIC → ISA IRQ`，计数在 `apic::ticks()`；
//! * AP 走本地 LAPIC 定时器（向量 `VEC_CPU_TIMER`），计数在 `apic::cpu_ticks(slot)`。
//!   BSP 那一格的 `cpu_ticks` 永远是 0（它的定时器不从这个向量来），照读就会每个窗口都报警。
//!
//! 今天只交付**检测与可见**，不交付处置：把停跳的核摘线要的是 §8.2 那套隔离，而它按驱动组织、
//! 没有 CPU 这一维（`actions_taken` 因此恒为 0，并且有判据钉住它不许偷偷变成非 0）。
//! 另外两格不做也不写"已交付"：硬锁死要平台真给 NMI，硬件看门狗要平台真有那个器件，
//! 这台 QEMU 量不出来（§9.6 自己写了"平台提供时才启用"）。

use crate::arch::x86_64::apic;
use crate::arch::x86_64::cpu;
use crate::tsc;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

/// 一个核连续这么多窗口不前进才算锁死。乘上 `WINDOW_MS` 就是"多久没心跳算卡住"：
/// 3 × 50 ms，比 10 ms 的定时周期宽得多 —— 正常抖动不误报，真卡住的核在开机阶段边界上就够数。
pub const STALL_LIMIT: u32 = 3;
/// 两次采样的最小间隔（毫秒）。阶段边界可能挨得很近，不拦的话"窗口"就退化成"每次调用"。
pub const WINDOW_MS: u64 = 50;

static LAST_EVAL: AtomicUsize = AtomicUsize::new(0);
static SAMPLES: AtomicU32 = AtomicU32::new(0);
static ALARM_WINDOWS: AtomicU32 = AtomicU32::new(0);
static ALARM_EVENTS: AtomicU32 = AtomicU32::new(0);
static ACTIONS: AtomicU32 = AtomicU32::new(0);
static LAST_MASK: AtomicU32 = AtomicU32::new(0);
static PREV_HB: [AtomicUsize; cpu::MAX_CPUS] = [const { AtomicUsize::new(0) }; cpu::MAX_CPUS];
static STREAK: [AtomicU32; cpu::MAX_CPUS] = [const { AtomicU32::new(0) }; cpu::MAX_CPUS];

/// 这个核的心跳。按各自的定时器来源读（文件头那条）：`cpu::BSP_SLOT` 的心跳来自 PIT 那条线，
/// 而它的 `cpu_ticks` 永远是 0 —— 照读就变成"每个窗口 BSP 都卡死"。
pub fn heartbeat(slot: usize) -> usize {
    if slot >= cpu::MAX_CPUS {
        return 0;
    }
    if slot == cpu::BSP_SLOT {
        apic::ticks()
    } else {
        apic::cpu_ticks(slot)
    }
}

/// 阶段边界上的轮询：窗口没到就什么都不做（返回上一次的位图）。
pub fn poll() -> u32 {
    let now = tsc::now();
    let prev = LAST_EVAL.load(Ordering::Relaxed) as u64;
    let budget = crate::clock::hz().map_or(200_000_000, |hz| hz * WINDOW_MS / 1000);
    if prev != 0 && now.wrapping_sub(prev) < budget {
        return LAST_MASK.load(Ordering::Relaxed);
    }
    LAST_EVAL.store(now as usize, Ordering::Relaxed);
    sample()
}

/// 立刻采一次样（用例要连着采 `STALL_LIMIT` 次，所以留这个口子；产品路径只走 `poll`）。
pub fn sample() -> u32 {
    SAMPLES.fetch_add(1, Ordering::Relaxed);
    let mut mask = 0u32;
    for slot in 0..cpu::MAX_CPUS {
        let hb = heartbeat(slot);
        let prev = PREV_HB[slot].swap(hb, Ordering::Relaxed);
        if !cpu::is_online(slot) {
            // 不在线的核不参与判断：它本来就不该有心跳，报出来是把"关机"读成"卡死"
            STREAK[slot].store(0, Ordering::Relaxed);
            continue;
        }
        if hb == prev {
            let streak = STREAK[slot].fetch_add(1, Ordering::Relaxed) + 1;
            if streak >= STALL_LIMIT {
                mask |= 1 << slot;
            }
        } else {
            STREAK[slot].store(0, Ordering::Relaxed);
        }
    }
    if mask != 0 {
        ALARM_WINDOWS.fetch_add(1, Ordering::Relaxed);
        ALARM_EVENTS.fetch_add(mask.count_ones(), Ordering::Relaxed);
        if mask & !LAST_MASK.load(Ordering::Relaxed) != 0 {
            // 只在新出现的核上报警时打一行：同一个核连续 N 个窗口卡住不该刷 N 行
            crate::log_warn!(
                "watchdog: 心跳停 位图={:#x} 连续窗口限={} 已采样={} 处置={}",
                mask,
                STALL_LIMIT,
                SAMPLES.load(Ordering::Relaxed),
                ACTIONS.load(Ordering::Relaxed)
            );
        }
    }
    LAST_MASK.store(mask, Ordering::Relaxed);
    mask
}

/// (采样次数, 报警窗口数, 报警核次, 位图, 处置次数)
pub fn stats() -> (u32, u32, u32, u32, u32) {
    (
        SAMPLES.load(Ordering::Relaxed),
        ALARM_WINDOWS.load(Ordering::Relaxed),
        ALARM_EVENTS.load(Ordering::Relaxed),
        LAST_MASK.load(Ordering::Relaxed),
        ACTIONS.load(Ordering::Relaxed),
    )
}

/// 用例收尾：把五个计数放回它进来时的值。`.ktests` 的顺序由链接器决定，
/// 留给下一格的必须是"和本用例无关"的现场。
pub fn restore(saved: (u32, u32, u32, u32, u32)) {
    let (samples, windows, events, mask, actions) = saved;
    SAMPLES.store(samples, Ordering::Relaxed);
    ALARM_WINDOWS.store(windows, Ordering::Relaxed);
    ALARM_EVENTS.store(events, Ordering::Relaxed);
    LAST_MASK.store(mask, Ordering::Relaxed);
    ACTIONS.store(actions, Ordering::Relaxed);
    reset_for_test(true);
}

/// 用例收尾要能把现场放回启动时的样子（`.ktests` 顺序由链接器决定，不能留给下一格）。
pub fn reset_for_test(keep_stats: bool) {
    for slot in 0..cpu::MAX_CPUS {
        STREAK[slot].store(0, Ordering::Relaxed);
        PREV_HB[slot].store(heartbeat(slot), Ordering::Relaxed);
    }
    LAST_MASK.store(0, Ordering::Relaxed);
    LAST_EVAL.store(0, Ordering::Relaxed);
    if !keep_stats {
        SAMPLES.store(0, Ordering::Relaxed);
        ALARM_WINDOWS.store(0, Ordering::Relaxed);
        ALARM_EVENTS.store(0, Ordering::Relaxed);
    }
}
