//! APIC 定时器、PIC 屏蔽与时钟标定用例（T0.1 纯搬移）。

use crate::arch::x86_64::{apic, cpu, trap};
use crate::{acpi, arch, clock};
use crate::{calibrate_clock_once};
use crate::ktest;

/// 真实定时器中断：开 IF 的窗口里必须**周期性**收到，且 spurious / 意外向量为 0。
/// 分两段采样，是因为"来过一次"和"在走"是两回事——EOI 漏写就是前者：第一条之后
/// ISR 位一直挂着，中断再也不来，而单次采样看不出任何毛病。
fn t_timer_ticks_recur() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    let st = match apic::get_or_init(&m) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("timer test: apic::init failed: {:?}", e);
            return false;
        }
    };
    if apic::timer_start().is_err() {
        crate::log_fatal!("timer test: 打不开定时器中断");
        return false;
    }
    let before = apic::counts();
    let c0 = apic::ticks();
    // 用例自足（T0.1 顺序暴露）：P5 的逐桶账是**全局累计**的，前面的用例可能留下一个
    // "走 context_load 出口、没有向量桶"的样本（`p3_record_irq` 对 v<32 也 +1）。
    // 绝对数相等因此依赖顺序；这里只比**本用例窗口内的增量**（与下面 tick 基线同一条规矩）。
    let p5_0 = trap::p5_irq_stats();
    let hist0 = trap::p5_hist_of(crate::arch::x86_64::cpu::BSP_SLOT);
    let non_irq0 = trap::p5_non_irq();
    let rust0: usize = before.irq.iter().sum::<usize>() + before.unexpected + before.spurious;
    // 基线必须是**相对的**：`apic::ticks()` 是全局累计值，前面跑过的抢占用例
    // 已经把它推到 9，用绝对数 2 判断"等到两次 tick"就永远立刻成立（实测踩过：
    // 窗口一次都没等，t1==c0，用例红）。表的枚举顺序不由源码顺序决定，
    // 所以每条用例都只能看自己开始之后的增量。
    //
    // 三段窗口的长度一律按 cycles 给，不再按轮数：轮数值多少时间是宿主机的函数，
    // 同一颗 QEMU 10.2.1 只换 `-accel`，kvm 档 400 轮连两个 tick 都攒不齐（第一轮
    // 实测只走了 1 个），tcg 档 318 轮就攒齐了——于是这条判据测的是宿主机，不是中断。
    // 游标：窗口前后各写一格 RTC 用户 RAM 并读回。宿主机拿这两个游标把 trace 里的
    // `vector 32` 投递切进这一段——simple trace 不带时间戳，没有游标就只知道全跑投了几发。
    let mk0 = apic::pit_mark();
    let w1 = apic::wait_ticks(c0, 2, clock::window_cycles(2));
    let mk1 = apic::pit_mark();
    let t1 = apic::ticks();
    // 窗口已关（with_interrupts 退出时 cli）：此刻起计数必须冻住。
    // 这一段用 wait_tick_count 而不是固定轮数——它的长度必须够一个 tick 周期，
    // 否则"IF 真开着也测不出来"（原先 20 轮只值 tick 周期的八分之一）。
    let w_idle = apic::wait_tick_count(clock::window_cycles(1));
    let t_after_cli = apic::ticks();
    // 关 IF 那一段里 PIT 的边沿没有消失，只是被挡在 IRR 上。重新开中断必须把它们交出来——
    // 这一格证的是"挡住"而不是"丢掉"。三段判据原本没有这一条，"计数冻住"和"再开还能收到"
    // 就混成了同一件事。
    let w_drain = apic::wait_ticks(t_after_cli, 1, clock::window_cycles(1));
    let t_drained = apic::ticks();
    // 第三段从**排空之后**起算，数的必须是新到的两个 tick。不排空就会被攒下的 backlog
    // 当场填满（实测：那一段 2 个 tick 只花 10,363,532 cycles，而第一段同样 2 个花
    // 68,040,996——同一个量两次读数差 6.6 倍，说明其中一次没在测它声称的东西）。
    let mk2 = apic::pit_mark();
    let w2 = apic::wait_ticks(t_drained, 2, clock::window_cycles(2));
    let mk3 = apic::pit_mark();
    let t2 = apic::ticks();
    // 四格游标单独打一行：宿主机按游标的**先后**把 trace 切成段（simple trace 不带时间戳），
    // 所以这四个数是段边界本身，读数出格（None）就等于证人不在场。
    crate::log_info!("timer 游标: 段1={:?}..{:?} 段2={:?}..{:?}（PIT latch 计数，None=出格）",
        mk0, mk1, mk2, mk3);
    let _ = st;
    apic::timer_stop().ok();
    let after = apic::counts();
    crate::log_info!(
        "timer: ticks {} -> {} (第一段 {} ticks cycles={} 轮数={} 游标={:?}..{:?}) ; after_cli={} (关IF 空转 {} ticks cycles={} 轮数={}) ; 排空={} (+{} cycles={}) ; second_window={} (第二段 {} ticks cycles={} 轮数={})",
        c0, t1, w1.ticks, w1.cycles, w1.rounds, mk0, mk1, t_after_cli, w_idle.ticks, w_idle.cycles, w_idle.rounds,
        t_drained, w_drain.ticks, w_drain.cycles, t2, w2.ticks, w2.cycles, w2.rounds
    );
    crate::log_info!(
        "timer counters: eois={} spurious={} unexpected={:?} irq[0]={}",
        after.eois - before.eois, after.spurious - before.spurious, after.unexpected - before.unexpected, after.irq[0]
    );
    // 四段判据：开着 IF 的窗口里确实在走；关 IF 后**不再增长**（IF 真的管住了这条线）；
    // 挡下的那批重新开中断要交出来（挡住≠丢掉）；排空之后还要能再收到新鲜的两个。
    // 加上没有意外向量、没有 spurious，且每个进来的中断都写过一次 EOI。
    let recurring = w1.ticks >= 2;
    let if_gates = t_after_cli == t1 && w_idle.ticks == 0;
    let drained = w_drain.ticks >= 1;
    let again = w2.ticks >= 2;
    let clean = after.spurious == before.spurious && after.unexpected == before.unexpected;
    let eoi_per_irq = after.eois - before.eois >= (t2 - c0);
    // 两台仪器必须数到同一个数：asm 出口记账的样本数 == Rust 侧各类中断计数之和。
    // 不相等就是有一类向量绕过了记账（或者被记了两次），那 P5 的每个数字都不可信。
    let p5 = trap::p5_irq_stats();
    let cc = apic::counts();
    let rust_total: usize = cc.irq.iter().sum::<usize>() + cc.unexpected + cc.spurious;
    // 对齐式子现在写全了：P5 的样本 == 驱动数到的外部中断 + 那些**驱动刻意不数**的
    // 非 ISA 向量（本地 APIC 定时器 0xF1 是第一条）。只写"两边相等"的话，多出一个
    // 非 IRQ 样本只会让它变红且不告诉你差哪一类；写全之后它红得明白，
    // 并且逼迫"新增一类会进 P5 的向量"必须在这里显式表态。
    let non_irq = trap::p5_non_irq();
    // **逐向量比对**，不是只比总数：总数相等可以藏住"IRQ0 多一个、IRQ1 少一个"，
    // 而这一轮要查的正是一个样本的来路（`asm=47 / rust=46`、非 ISA 桶 = 0 ⇒
    // 差的那一个落在 32..47 里面，总数判据到此已经给不出更多信息了）。
    // 比的是**增量**：读数与基线同一形状，顺序不再影响绝对数。
    let hist = trap::p5_hist_of(crate::arch::x86_64::cpu::BSP_SLOT);
    let p5_delta = p5.faults - p5_0.faults;
    let rust_delta = rust_total - rust0;
    let non_irq_delta = non_irq - non_irq0;
    let mut hist_delta = hist;
    let mut irq_delta = cc.irq;
    for i in 0..hist_delta.len() {
        hist_delta[i] -= hist0[i];
        irq_delta[i] -= before.irq[i];
    }
    let mut hist_bad = 0usize;
    let mut first_diff = "";
    for i in 0..hist_delta.len() {
        if hist_delta[i] != irq_delta[i] as u64 {
            hist_bad += 1;
            if first_diff.is_empty() {
                first_diff = "见下行";
                crate::log_fatal!(
                    "p5 逐向量不一致 vec={}：P5增量={} 驱动增量={}",
                    trap::VEC_IRQ_BASE + i, hist_delta[i], irq_delta[i]
                );
            }
        }
    }
    // 逐桶相等 + "P5 总数 == 各桶之和 + 非 ISA 桶"（后者是**自洽检查**：
    // 它抓的是"有一次进桩没进任何桶"，那种漏法逐桶比对看不出来）。
    let bucketed: u64 = hist_delta.iter().sum::<u64>() + non_irq_delta;
    let instruments_agree =
        hist_bad == 0 && p5_delta as usize == rust_delta && bucketed == p5_delta;
    crate::log_info!(
        "timer 判据逐项: recurring={} drained={} again={} if_gates={} clean={} eoi_per_irq={} (eoi_delta={} ticks_delta={}) instruments_agree={}",
        recurring, drained, again, if_gates, clean, eoi_per_irq, after.eois - before.eois, t2 - c0, instruments_agree
    );
    crate::log_info!(
        "p5 cross-check: asm_samples={} rust_samples={} 非ISA样本={} 入桶合计={} 不一致桶={}({}) agree={}",
        p5_delta, rust_delta, non_irq_delta, bucketed, hist_bad, first_diff, instruments_agree
    );
    crate::log_info!(
        "p5 hist: P5={:?} 驱动={:?}",
        hist_delta,
        &irq_delta[..hist_delta.len()]
    );
    // 这个数只能叫**窗口均值**，不能叫周期：窗口里第一个间隔可能不完整，均值必然是周期的
    // 下界（实测 2 ticks / 47,831,965 cycles ⇒ 均值 23.9M，而标定给的真周期是 33.3M）。
    // 原先这里更糟——拿第二段的 cycles 除**四段合计**的 tick 数，印出来 14.9M cycles/tick
    // 而同一跑标定是 34.7M，差 2.3 倍正好是多算进去的那一半 tick 数；那个数不是"偏保守的
    // 估计"，是除错了（BACKLOG 56 那一行按它反推过 1.44 GHz，已就地作废）。
    let dt = t2 - c0;
    let mean = if w2.ticks > 0 { w2.cycles / w2.ticks } else { 0 };
    crate::log_info!(
        "timer: 四段合计 {} ticks / {} cycles ⇒ 第二段窗口均值 {} cycles/tick（均值的第一个间隔可能不完整，它是周期的**下界**不是周期）；ISR 自己量的相邻间隔 last={} max={}（第二段窗口：{} ticks / {} cycles）",
        dt, w1.cycles + w_idle.cycles + w_drain.cycles + w2.cycles, mean,
        apic::tick_delta_cycles(), apic::tick_delta_max_cycles(), w2.ticks, w2.cycles
    );
    recurring && drained && again && if_gates && clean && eoi_per_irq && instruments_agree
}
ktest!(KT_TIMER_TICKS, t_timer_ticks_recur);

/// §6.5/§7.1 的中断上下文分配禁令**有没有机制**。
/// 本用例自己再开一次窗口，不依赖表里谁先跑（枚举顺序由链接顺序决定，不由源码决定）。
/// 正常构建必须 `tries == 0`；`fault-alloc-in-irq` 构建必须让它变成非 0——
/// 那条注入构建就是这把尺子的"已知能坏"样本。
fn t_no_alloc_in_isr() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    let st = match apic::get_or_init(&m) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("isr-alloc test: apic::init failed: {:?}", e);
            return false;
        }
    };
    let t0 = apic::ticks();
    let tries0 = apic::irq_alloc_tries();
    if apic::timer_start().is_err() {
        crate::log_fatal!("isr-alloc test: 打不开定时器中断");
        return false;
    }
    // 窗口长度按 cycles 给（同一个理由：轮数是宿主机的函数）。这里只要 1 个 tick，
    // 因为判据看的是"ISR 里发生过一次分配尝试没有"，多等只是让变异样本更难对齐。
    let w = apic::wait_ticks(t0, 1, clock::window_cycles(1));
    let _ = st;
    apic::timer_stop().ok();
    let tries = apic::irq_alloc_tries() - tries0;
    crate::log_info!(
        "isr-alloc guard: ticks_in_window={} alloc_attempts_in_isr={} (窗口={} cycles 轮数={})",
        w.ticks, tries, w.cycles, w.rounds
    );
    w.ticks >= 1 && tries == 0
}
ktest!(KT_ISR_ALLOC_GUARD, t_no_alloc_in_isr);

/// 时钟标定：用 PIT 的已知 tick 周期反推 TSC 频率，并把"换算必须自洽"当成判据。
/// 本用例自己开窗口取样本，不依赖表里谁先跑。
fn t_clock_calibrated_by_pit() -> bool {
    let Some(cal) = calibrate_clock_once() else { return false };
    let tick_us = clock::micros(cal.tick_period_cycles);
    let linear = clock::micros_of_two_ticks_is_double(cal.tick_period_cycles);
    // 第一格要说清楚它挡什么：`micros(period)` 与 `tsc_hz` 是同一个 period 换两次单位，
    // 所以 10 ms 这个读数**按构造**就落在区间里——它挡的是定点乘除把数量级写反
    // （写反就读成 10 µs 或 10^7 µs），不是"频率量出来正好 10 ms"。真正的频率对不对
    // 由下面那条跨仪器等式与宿主机的 `tsc: Detected ...` 对表来管。
    let unit_ok = tick_us.is_some_and(|v| (9_000..=11_000).contains(&v)) && linear;
    // 两把尺子数的是同一条事件流：窗口里数到 s 个 tick，ISR 就该记到 s-1 段相邻间隔。
    // 差一段就是"有一次 tick 被数了两次"或"有一间隔没记"，那 tsc_hz 直接不可信。
    let cross = cal.samples >= 2 && cal.interval_n + 1 == cal.samples;
    crate::log_info!(
        "clock 判据: 单位自洽={} 跨仪器等式={}（samples={} interval_n={} interval_mean={} tsc_hz={}）",
        unit_ok, cross, cal.samples, cal.interval_n, cal.interval_mean, cal.tsc_hz
    );
    unit_ok && cross
}
ktest!(KT_CLOCK, t_clock_calibrated_by_pit);

/// 继承状态自证：传统 PIC 必须仍是全屏蔽（协议这么保证，但读回来才算实测）。
/// 不成立就意味着同一条 IRQ 可能同时从 8259 与 I/O APIC 各来一次，
/// 典型现象是 spurious IRQ7 —— 那种故障最难归因。
fn t_pic_still_masked() -> bool {
    let (m, s) = apic::pic_imr();
    crate::log_info!("pic imr readback: master={:#02x} slave={:#02x} (want 0xff/0xff)", m, s);
    m == 0xff && s == 0xff
}
ktest!(KT_PIC_MASKED, t_pic_still_masked);

