//! ADR-137：32 号 `SYS_CLOCK_UPTIME` 的判据——用户态读 uptime。
//!
//! 只测**约定面**（不测标定本身，`ktests/time.rs` 的 `t_clock_calibrated_by_pit`
//! 已把频率与宿主机对过表）：
//! 1. **单调不减**：连读两次，第二次 ≥ 第一次（TSC 只前进；相等也算过，
//!    两次 syscall 间隔可能小于 1 µs）；
//! 2. **与既有量具对账**：读数必须 ≥ 本用例自证消耗的 ticks 换算出的微秒数
//!    ——`apic::wait_ticks` 等 2 个 tick 再读，uptime 必须 ≥ 2×tick_period
//!    换算的微秒（两条独立路径：32 号走 `BOOT_TSC` 锚 + `micros`，
//!    ticks 走 APIC 计数器；共同源只有标定参数）；
//! 3. **理性区间**：读数必须 ≤ 整个用例运行期的物理上限——用 TSC 直接量
//!    本用例从起跑到读数的 cycles，换算后 uptime 不可能超过它
//!    （锚点在 kmain 早期 ⇒ uptime ≤ 任意一点到锚的时长 ≤ "任意两点的时长上界"）；
//! 4. **重锚计数为 0**：有人重锚就把 uptime 拉回 0，那是骗人。
//!
//! 不测的：微秒级精度（TSC 频率本身有 ±几个 % 的标定误差，判据用的是
//! 数量级区间而不是精确值——与 `t_clock_calibrated_by_pit` 的 9..11 ms 同一口径）。

use crate::arch::x86_64::trap::TrapFrame;
use crate::ktest;
use crate::user::{self, syscall_dispatch};
use crate::{clock, sched};

fn frame0() -> TrapFrame {
    TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    }
}

fn read_uptime() -> i64 {
    let mut f = frame0();
    f.rax = user::SYS_CLOCK_UPTIME;
    syscall_dispatch(&mut f);
    f.rax as i64
}

fn t_clock_uptime() -> bool {
    crate::log_info!("uptime: 起（32 号的判据）");
    if sched::current_identity().is_none() {
        sched::init_boot_task();
    }

    // ---- ⓪ **先分档**：PIT 标定没跑的档（如 a2-exec-bad，实测 a=-1）里，
    //     32 号回 `-1` 是**正确行为**（clock.rs 的纪律：没标定不编数字）——
    //     这时只验"-1 的形状 + 重锚为 0"，换算格全部跳过（没有标定就没有换算）。
    //     有标定的档走完整四格。
    if clock::hz().is_none() {
        let a = read_uptime();
        let b = read_uptime();
        let ok = a == -1 && b == -1 && clock::reanchors() == 0;
        crate::log_info!(
            "uptime: 判据={} 无标定档 a={} b=-1 形状={} 无重锚={}",
            ok, a, a == -1 && b == -1, clock::reanchors() == 0
        );
        return ok;
    }

    // ---- ① 单调不减：连读两次。
    let a = read_uptime();
    let b = read_uptime();
    let monotonic_ok = a >= 0 && b >= a;

    // ---- ② 与 ticks 对账：等 2 个 tick，uptime 增量必须 ≥ 2×tick_period 的微秒。
    //     等待需要定时器在跑；`.ktests` 次序由链接器决定，本用例自足于时钟状态
    //     （与 `t_wait_timeout` 同一条纪律：先探，停了才开，用完还原）。
    let tick_in = crate::arch::x86_64::apic::ticks();
    let probe = crate::arch::x86_64::apic::wait_ticks(tick_in, 2, clock::window_cycles(2));
    let was_running = probe.ticks >= 2;
    if !was_running {
        crate::arch::x86_64::apic::timer_start().ok();
    }
    let t0 = read_uptime();
    let w = crate::arch::x86_64::apic::wait_ticks(
        crate::arch::x86_64::apic::ticks(),
        2,
        clock::window_cycles(2),
    );
    let t1 = read_uptime();
    if !was_running {
        crate::arch::x86_64::apic::timer_stop().ok();
    }
    // **对账口径（ADR-137 修订）**：`wait_ticks(t, 2, ..)` 等的是"计数 ≥ 2"，
    // 它可能在 tick 边界**中途**开始 ⇒ 实际等待在 [1, 2] 个 tick 周期之间。
    // 初版把下界写成 2 个整周期（20 ms），在 a3-shell 档实测增量 19023 µs < 20000
    // ⇒ 红——那是判据的数学错误，不是内核错（§399 的 prockill 同族：跨档才暴露）。
    // 正确的下界：跨越 2 个 tick 边界**至少跨过 1 个完整周期**；
    // 上界：≤ 窗口 cycles 换算的微秒（wait_ticks 自带的上界）。
    // 上界再加 1 个 tick 周期余量：`t1` 在 `wait_ticks` 返回**之后**才读，
    // 中间的指令可能跨过又一个 tick 边界（实测差 44 µs，正好半个周期以内）。
    let (lo_us, hi_us) = clock::current().map_or((None, None), |c| {
        (
            clock::micros(c.tick_period_cycles),
            clock::micros(w.cycles.saturating_add(c.tick_period_cycles)),
        )
    });
    let ticks_ok = match (lo_us, hi_us) {
        (Some(lo), Some(hi)) => {
            t1 >= t0 && t1 - t0 >= lo as i64 && t1 - t0 <= hi as i64 + 1
        }
        _ => false,
    };
    crate::log_info!(
        "uptime: 2tick 等待={} 增量={}us 区间=[{}..{}]us (窗口={} cycles 轮数={})",
        was_running, t1.saturating_sub(t0),
        lo_us.unwrap_or(0), hi_us.unwrap_or(0), w.cycles, w.rounds
    );

    // ---- ③ 理性上界：本用例起跑时刻用 TSC 直接量，uptime(现在) − uptime(那时)
    //     不可能超过"两次 TSC 读数的差"换算出的微秒（同一把尺子的两种走法，
    //     走 syscall 的那条绕了 trap+分派，只会更慢不会更快）。
    // **§482 修：TSC 的取样区间必须覆盖两次 uptime 读数的全程。**
    //
    // 原来的写法是 `c0 → u0 → c1 → u1`，`span = c1 - c0` 只量了两次 uptime 调用
    // **之间**的空隙，而 `u1 - u0` 包含的是**两次调用本身的耗时**（每次约 22 µs 的
    // syscall 路径）。于是判据 `u1 - u0 <= span` 在结构上就不可能成立——
    // 除非 `read_uptime` 是零开销的。
    //
    // 实测（§482 整链，`A2越界argv被校验拒` 那一行）：`a=3824170 b=3824238` ⇒ 68 cycles
    // ≈ 0.02 µs，而 `u0=3861321 u1=3861366` ⇒ 45 µs。**45 >> 0.02**，必红。
    // 它偶尔绿，是因为两次调用落在同一个 tick 内、`u1 - u0 == 0`。
    //
    // 正确的区间：`c_lo` 在**第一次读之前**、`c_hi` 在**第二次读之后**，
    // 于是 `u1 - u0` 必然落在 `[c_lo, c_hi]` 之内——那才是这条判据想证的
    // 「uptime 不会比 TSC 走得快」。
    let c_lo = crate::tsc::now();
    let u0 = read_uptime();
    let c1 = crate::tsc::now();
    let u1 = read_uptime();
    let c_hi = crate::tsc::now();
    let span_us = clock::micros(c_hi.wrapping_sub(c_lo)).unwrap_or(0);
    // `+1` 是微秒换算的取整余量（两次 `micros` 各可能丢不到 1 µs）。
    let bound_ok = u1 >= u0 && (u1 - u0) <= span_us as i64 + 1;
    let _ = c1; // 中间那次读数留着：它是「两次调用之间确实有空隙」的证人，不参与判据

    // ---- ④ 重锚计数为 0。
    let reanchor_ok = clock::reanchors() == 0;

    let ok = monotonic_ok && ticks_ok && bound_ok && reanchor_ok;
    crate::log_info!(
        "uptime: 判据={} 单调={} 对ticks={} 上界={} 无重锚={} (a={} b={} u0={} u1={})",
        ok, monotonic_ok, ticks_ok, bound_ok, reanchor_ok, a, b, u0, u1
    );
    ok
}

ktest!(KT_CLOCK_UPTIME, t_clock_uptime);
