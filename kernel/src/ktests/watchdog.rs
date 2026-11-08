//! 看门狗采样用例（T0.1 纯搬移）。

use crate::arch::x86_64::{apic, cpu};
use crate::{acpi, clock, tsc, watchdog};
use crate::ktest;

/// M6-c①：§9.6 的软锁死。七格，每格只挡一类错法：
/// 1 健康窗口里所有在线核的心跳都在前进 ⇒ 位图为 0（这条先证明"不报"不是常量）
/// 2 头两个窗口必须静默：阈值 3 个窗口不是装饰（去掉阈值这条当场红）
/// 3 报警落在第 3 或第 4 个窗口 —— 不是"恰好第 3 个"：`timer_stop()` 之后还会有一个**在途
///    tick** 落进计数（实测两种都出现过），写成等式就变成一条自己会飘红的判据
/// 4 报的必须是停掉那一个核，别的核不许连坐（AP 用本地 LAPIC、BSP 用 PIT，两条来源）
/// 5 报警计数按窗口/按核各计（两个数不能混成一个），且处置次数恒为 0
/// 6 恢复心跳后**能消警**：下一窗口位图回 0（把 BSP 接到错的来源上，这条永远消不掉）
/// 7 用例自己停表，所以进来时先量"心跳原本在不在前进"，收尾按进来时的状态放回
/// 用例每格之间用 TSC 等 30 ms 真实时间（比 10 ms 的定时周期宽三倍）。
fn t_watchdog() -> bool {
    use watchdog as wd;
    // 用例自足（T0.1 顺序暴露）：`timer_start`/`timer_stop` 都要 APIC 已初始化；
    // 否则它们返回 Err 被 `.ok()` 吞掉，下面"停表"那几窗其实没停，报警永远不会来。
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("watchdog: APIC 起不来");
        return false;
    }
    let saved = wd::stats();
    let bsp = cpu::BSP_SLOT;
    // 每格之间的真实时间：30 ms 比 10 ms 的定时周期宽三倍，健康核一定前进，停掉的核一定不前进
    let settle = || {
        let budget = clock::hz().map_or(120_000_000, |hz| hz * 30 / 1000);
        let t0 = tsc::now();
        apic::with_interrupts(|| {
            while tsc::now().wrapping_sub(t0) < budget {
                tsc::spin(20_000);
            }
        });
    };
    // 进来时 BSP 的心跳未必在前进：`.ktests` 顺序由链接器决定，而有用例（`t_copy_user`）
    // 收尾会把表停掉。先量这个事实，再决定要不要为用例建立"健康窗口"这个前提，
    // 最后按进来时的状态放回 —— 不然本用例会把下一格的时钟弄活或弄死。
    let t_in = apic::ticks();
    settle();
    let running_on_entry = apic::ticks() != t_in;
    if !running_on_entry {
        apic::timer_start().ok();
    }

    settle();
    let healthy = wd::sample();
    // 停表之前把 streak 与基线清零：报警要出现在"从我这次注入起的第 STALL_LIMIT 个窗口"，
    // 而不是前面那些无关窗口的尾巴上（第一版就是这么红的：`限内不报=false(0x0/0x1)`）。
    wd::reset_for_test(false);
    apic::timer_stop().ok();
    // 整个停表分段关着 IF 跑（修复 ①）。`close_cpu_window` 同时倒牌，所以
    // `interrupts_enabled` 读到的就是硬件状态，判据可以真的测它，不是读一句注释。
    let was_open = apic::interrupts_enabled(bsp);
    apic::close_cpu_window(bsp);
    let mut closed_ok = true;
    let mut seq = [0u32; 4];
    for item in seq.iter_mut().take(4) {
        // 停表分段的等待：不开中断窗口，并且**在窗口内部**逐轮采样 IF。
        // 为什么必须在内部采：`with_interrupts` 退出时会把牌倒回去，在两次窗口之间读
        // 永远是 false —— 第一版判据就是这么空转的（MUTATION-A 当时没咬）。
        let budget = clock::hz().map_or(120_000_000, |hz| hz * 30 / 1000);
        let t0 = tsc::now();
        while tsc::now().wrapping_sub(t0) < budget {
            closed_ok &= !apic::interrupts_enabled(bsp);
            tsc::spin(20_000);
        }
        *item = wd::sample();
    }
    apic::timer_start().ok();
    if was_open {
        apic::open_cpu_window(bsp);
    }
    crate::log_info!("watchdog: 停表窗口 全程关中断={} 分段前IF={}", closed_ok, was_open);
    // 阈值那条线断的是"第几个窗口才报"，不是"第几次采样必须报"：`timer_stop()` 之后还有
    // 一个**在途 tick** 会落进计数（实测两种都有 —— 有时报在第 3 个窗口、有时第 4 个），
    // 把等式写成"恰好第 3 个"就变成一条会自己飘红的判据。
    let first_alarm = seq.iter().position(|m| *m != 0).map_or(0, |i| i + 1);
    let below_limit = seq[0] == 0 && seq[1] == 0;
    let alarmed = first_alarm == wd::STALL_LIMIT as usize || first_alarm == wd::STALL_LIMIT as usize + 1;
    let alarm = seq.iter().find(|m| **m != 0).copied().unwrap_or(0);
    let right_cpu = alarm == (1u32 << bsp);
    let no_collateral = seq.iter().all(|m| *m == 0 || *m == (1u32 << bsp));
    settle();
    let cleared = wd::sample() == 0;
    if !running_on_entry {
        apic::timer_stop().ok();
    }
    let (samples, windows, events, last_mask, actions) = wd::stats();
    let counters = windows >= 1 && events >= 1 && last_mask == 0 && actions == 0;
    crate::log_info!(
        "watchdog: 判据 进表时心跳前进={} 健康窗口不报={} 前两窗静默={} 第几窗报={}(限={}) 报的是本核={} 没连坐={} 计数(窗口={} 核次={} 采样={}) 消警={} 处置={} AP槽心跳={}",
        running_on_entry,
        healthy == 0,
        below_limit,
        first_alarm,
        wd::STALL_LIMIT,
        right_cpu,
        no_collateral,
        windows,
        events,
        samples,
        cleared,
        actions,
        apic::cpu_ticks(bsp + 1) > 0
    );
    wd::restore(saved);
    let ok = healthy == 0 && below_limit && alarmed && right_cpu && no_collateral && cleared && counters && actions == 0 && closed_ok;
    if !ok {
        crate::log_fatal!(
            "watchdog: 判据不成立 健康={} 前两窗静默={} 第几窗报={}/限={} 报的是本核={} 没连坐={} 消警={} 计数={}",
            healthy == 0,
            below_limit,
            first_alarm,
            wd::STALL_LIMIT,
            right_cpu,
            no_collateral,
            cleared,
            counters
        );
    }
    ok
}
ktest!(KT_WATCHDOG, t_watchdog);

