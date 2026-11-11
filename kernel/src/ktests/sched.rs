//! 调度、AP 上线、IF 归属与 shootdown 用例（T0.1 纯搬移）。

use crate::arch::x86_64::{apic, cpu, smp, trap};
use crate::{acpi, clock, limine, mm, sched, sync, tsc};
use crate::{mp_snapshot};
use crate::ktest;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 工作任务：数自己的圈数，收工时把自己标 Done。
fn sched_worker() -> ! {
    let me = sched::current_id();
    while sched::should_run() {
        sched::WORK[me].fetch_add(1, Ordering::Relaxed);
        tsc::spin(3_000);
    }
    sched::finish_current();
    loop {
        tsc::spin(3_000);
    }
}

/// **不收工**的工作任务。给"需要在别人收工之后再被调度两次"的用例用。
///
/// 为什么要有第二条：`RUN` 是全局的收工标志，`t_preempt_round_robin` 跑过之后它就是 false 了，
/// 而 `.ktests` 的枚举顺序由链接顺序决定——于是同一份 `sched_worker` 在有的顺序下
/// 一进门就 Done、runs 永远停在 1。用例不能靠"我恰好排在谁后面"来拿到样本，
/// 所以这里要一个不看 `RUN` 的入口。代价：这一槽会一直占着队列，
/// 后面的轮转用例因此多一个可调度任务（无害，它只数自己的圈）。
fn sched_worker_forever() -> ! {
    let me = sched::current_id();
    loop {
        sched::WORK[me].fetch_add(1, Ordering::Relaxed);
        tsc::spin(3_000);
    }
}

/// P3a 的搭档：让出一次就把 CPU 还给启动上下文，然后收工。
///
/// 为什么必须"让回来"：关着窗口又没有 tick，让出去之后**没有任何抢占来源**能把 CPU
/// 拿回来（§111 那条挂死机制）。所以这个搭档自己再让一次——它是那条机制的反面用法。
fn yield_partner() -> ! {
    sched::yield_now();
    sched::finish_current();
    loop {
        tsc::spin(3_000);
    }
}

/// 时钟抢占的轮转：两个任务 + 启动上下文必须**都**推进过，且切换次数、
/// 每个任务的 runs 都要非零。只证明"能进中断"不够——必须证明
/// "被换下去的任务后来又被换回来并继续跑"，否则轮转是假的。
fn t_preempt_round_robin() -> bool {
    // §199：收尾按原样放回。**入口**记一次状态，只守卫**最后一个** stop；
    // 中间那些 stop 是被测语义本身（故意停表的窗口），一个都不动。
    let timer_was_running =
        apic::wait_ticks(apic::ticks(), 2, crate::clock::window_cycles(2)).ticks >= 2;
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("sched: APIC 起不来，抢占测不了");
        return false;
    }
    sched::init_boot_task();
    sched::start_workers();
    // 用例自足（T0.1 顺序暴露）：任务下标不是常量。前面的用例可能已经占掉 1、2 两格，
    // 这里必须用 spawn 交回的下标读数，不能写死——否则两条工人跑在别的槽里，
    // `WORK[1]/WORK[2]` 读到的是别人留下的数。判据本身的语义不变：两条工人都推进过。
    let w1 = match sched::spawn(sched_worker) {
        Ok(v) => v,
        Err(_) => {
            crate::log_fatal!("sched: spawn 失败");
            return false;
        }
    };
    let w2 = match sched::spawn(sched_worker) {
        Ok(v) => v,
        Err(_) => {
            crate::log_fatal!("sched: spawn 失败");
            return false;
        }
    };
    let (sw0, tk0, _) = sched::stats();
    let boot0 = sched::WORK[0].load(Ordering::Relaxed);
    apic::timer_start().ok();
    // 第一段窗口。原先整个测试只有一段，因为分成两段时**第二段一条 tick 都收不到**，
    // 现场是 `sw=6 ticks=6 irr0=0 isr0=0 svr=0x1ff rte2 未屏蔽` —— LAPIC 使能、EOI 干净、
    // 表项没关，说明请求根本没送到 CPU：第一段出口那句 `cli` 是在"当时持有 CPU 的那个上下文"
    // 里执行的，而被抢占过的任务恢复时又带回自己保存的 rflags(IF=1)。也就是说 IF 的归属没定。
    // ADR-021 把这条定成"**IF 属于 CPU**"，所以下面必须再开第二段：
    // 那不是补充测试，是那条决定的唯一故障复现证据——机制没生效时这里就是 0 个 tick。
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        // 目标切换次数从 6 提到 24：P1 的 min 在样本只有 9~11 个时本身抖得厉害，
        // 多采样才让"注入几千周期"这件事判得出来（§12.4.1 规则 3 要求先证明尺子能分辨）。
        while sched::stats().0 < sw0 + 24 && tsc::now() - t0 < 900_000_000 {
            sched::WORK[0].fetch_add(1, Ordering::Relaxed);
            tsc::spin(20_000);
            #[cfg(feature = "trace-switch")]
            if sched::WORK[0].load(Ordering::Relaxed) % 30 == 0 {
                let (sw, tk, act) = sched::stats();
                crate::log_info!("loop1 poll: sw={} ticks={} active={} cur={} lapic_irr0={:#x}", sw, tk, act, sched::current_id(), apic::lapic_debug().0);
            }
        }
        sched::stop_workers();
        // 收工标志要真的落到 Done 状态上：工人得再被调度到一次才会去检查它
        let t1 = tsc::now();
        // P6c：收工之后槽可能已经被回收成 Free（回收时刻从此是确定的），所以判"收工了"
        // 要接受 Done **或** Free；只认 Done 会在回收变快之后永远等不到 ⇒ 挂死。
        let done_or_free = |g: usize| {
            matches!(sched::state_of(g), sched::TaskState::Done | sched::TaskState::Free)
        };
        while (!done_or_free(w1) || !done_or_free(w2))
            && tsc::now() - t1 < 400_000_000
        {
            sched::WORK[0].fetch_add(1, Ordering::Relaxed);
            tsc::spin(20_000);
        }
        // 关中断必须由开窗口的上下文来做
        let back = sched::wait_for_boot_task(400_000_000);
        sched::WORK[0].fetch_add(if back { 100 } else { 1 }, Ordering::Relaxed);
    });
    apic::timer_stop().ok();
    // ---- 第二段窗口（ADR-021 的故障复现位置）
    // 此刻所有任务都已经 Done、没有新的抢占发生，被测的只有一件事：**这个 CPU 还能不能收到 tick**。
    // IF 的归属没定时，这里观测到的增量是 0；归属定成"属于 CPU"之后，
    // 换入的上下文带的 IF 由窗口状态供，第二段窗口就必然收得到。
    apic::timer_start().ok();
    let tick_a = apic::ticks();
    // 这一段本来就是按 cycles 封的界（400_000_000），换成同一个推导式上界，
    // 免得"这一格该给多少"在文件里有两本账。
    let w_pre = apic::wait_ticks(tick_a, 2, clock::window_cycles(2));
    let tick_b = apic::ticks();
    if !timer_was_running {
        apic::timer_stop().ok();
    }
    let boot1 = sched::WORK[0].load(Ordering::Relaxed);
    let (sw1, tk1, active) = sched::stats();
    let (n, mean, min, max) = sched::p1_stats();
    crate::log_info!(
        "preempt: switches {} -> {} (ticks {} -> {}), work boot={} w1={} w2={}, active_left={}, runs1={} runs2={}, state1={:?} state2={:?}",
        sw0, sw1, tk0, tk1, boot1 - boot0,
        sched::WORK[w1].load(Ordering::Relaxed), sched::WORK[w2].load(Ordering::Relaxed),
        active, sched::runs_of(w1), sched::runs_of(w2),
        sched::state_of(w1), sched::state_of(w2)
    );
    crate::log_info!("p1 switch: samples={} mean={} min={} max={} cycles (excludes iretq and the new task's first instruction)", n, mean, min, max);
    let rotated = sw1 >= sw0 + 24;
    let all_worked = boot1 > boot0
        && sched::WORK[w1].load(Ordering::Relaxed) > 0
        && sched::WORK[w2].load(Ordering::Relaxed) > 0;
    // P6c：回收时刻确定之后，槽可能已经被归化成 Free，而 `reap` 会清 `runs`
    // （"身份随槽走"的既有设计）⇒ 回收之后读 `runs_of` 读到的是**下一任住户**的数或 0，
    // 这条断言就不再有意义。"两个工人都真被换上去跑过"的**幸存证据**是它们自己加的 WORK 计数
    // （工人跑起来才加），所以改读它；判据的意图没变，只是换成回收后仍然可读的那一份。
    let resumed = sched::WORK[w1].load(Ordering::Relaxed) > 0
        && sched::WORK[w2].load(Ordering::Relaxed) > 0;
    let p1_sane = n > 0 && min <= mean && mean <= max && mean > 0;
    let second_window = tick_b >= tick_a + 2;
    crate::log_info!(
        "preempt: 第二段窗口 ticks {} -> {} (收到 {} cycles={} 轮数={}) ; if_loads closed/open={}/{}",
        tick_a, tick_b, w_pre.ticks, w_pre.cycles, w_pre.rounds, sched::if_loads().0, sched::if_loads().1
    );
    rotated && all_worked && resumed && p1_sane && second_window
}
ktest!(KT_PREEMPT, t_preempt_round_robin);

/// 任务栈的 guard page（§6.4 从 V1.0 就承诺、M2 之后才具备实现条件的那条）。
/// 栈底那一页必须**未映射**且访问它就故障，栈内第一页必须已映射且不故障——
/// 两条一起测，否则"访问 guard 故障"可能只是因为整段都没映射。
fn t_task_stack_guard() -> bool {
    let slot = match sched::spawn(sched_worker) {
        Ok(i) => i,
        Err(e) => {
            crate::log_fatal!("guard: spawn 失败 {:?}", e);
            return false;
        }
    };
    let Some((lo, _hi, guarded)) = sched::stack_bounds(slot) else {
        crate::log_fatal!("guard: 拿不到任务栈边界");
        return false;
    };
    let guard_va = lo - mm::PAGE as u64;
    let guard_unmapped = !mm::is_mapped(guard_va);
    let first_mapped = mm::is_mapped(lo);
    let guard_faults = trap::probe_page_fault(guard_va).is_some();
    let first_faults = trap::probe_page_fault(lo).is_some();
    // 收尾自己收干净（W1 收尾 B2 查出来的第二个泄漏）：这个工人只是借它的栈量边界，
    // 用例不需要它活着。以前"内核任务一律豁免"藏住了它——它要等别的用例调
    // `stop_workers()` 才收工，而那条用例可能排在本用例之前也可能排在之后。
    let swept = sched::terminate_task(slot);
    crate::log_info!(
        "task stack guard: lo={:#x} guarded={} guard_unmapped={} guard_faults={} first_mapped={} first_faults={} 工人收掉={}",
        lo, guarded, guard_unmapped, guard_faults, first_mapped, first_faults, swept
    );
    guarded && guard_unmapped && guard_faults && first_mapped && !first_faults && swept
}
ktest!(KT_TASK_STACK_GUARD, t_task_stack_guard);

/// AP 有没有真的被释放，并且各自把**本地**定时器跑起来了。
///
/// 三条判据都要成立，缺一不可：
/// 1. 释放数 == MP 报的非 BSP 核数（少了就是 ADR-022 说的降级，必须可见而不是被平均掉）；
/// 2. 每个登记槽位都 online + 自报到 + 自己读到过硬件 id；
/// 3. **复发性**：隔一段已知时间再数一次 tick，必须变大。第一次就非 0 不等于在走
///    （ADR-020 里 EOI 漏写就是这个形状：来过一次，之后再没有）。
fn t_ap_released_and_ticking() -> bool {
    let Some(mp) = mp_snapshot() else {
        crate::log_fatal!("smp: 没有 MP 响应，AP 起不来（这不是硬件故障，是启动信息缺失）");
        return false;
    };
    if let Err(e) = smp::bringup() {
        crate::log_fatal!("smp: bringup 失败 {:?}", e);
        return false;
    }
    let bsp = match apic::state() {
        Some(s) => s.id,
        None => return false,
    };
    // MP 里除 BSP 之外应当有几个 AP（含"超出容量没登记"的那部分，所以按 id 数不按槽位数）
    let expected = (0..mp.n).filter(|&i| mp.lapic_ids[i] != bsp).count();
    let released = smp::released_count();
    let refused = smp::refused_count();
    let hz = clock::hz().unwrap_or(0);
    let mut per_cpu = [0usize; cpu::MAX_CPUS];
    let mut all_ticked_before = true;
    for s in 0..cpu::MAX_CPUS {
        per_cpu[s] = apic::cpu_ticks(s);
        if cpu::is_registered(s) && s != cpu::BSP_SLOT && per_cpu[s] == 0 {
            all_ticked_before = false;
        }
    }
    // 等约 50 ms（BSP 不需要开自己的窗口：AP 的 IF 由它自己打开）
    if hz > 0 {
        let t0 = tsc::now();
        while tsc::now().wrapping_sub(t0) < hz / 20 {
            core::hint::spin_loop();
        }
    } else {
        tsc::spin(2_000_000);
    }
    let mut recurred = true;
    let mut online_aps = 0usize;
    for s in 1..cpu::MAX_CPUS {
        if !cpu::is_registered(s) {
            continue;
        }
        let now_ticks = apic::cpu_ticks(s);
        if now_ticks <= per_cpu[s] {
            recurred = false;
        }
        if cpu::is_online(s) && cpu::is_ready(s) && smp::ap_stage(s) >= 2 {
            online_aps += 1;
        }
    }
    let (exstack_failed, lapic_failed) = smp::ap_failures();
    // ISR 深度必须每个 CPU 都回到 0。残留的深度会让那个 CPU 上**每一次**堆分配
    // 都被 `refuse_if_isr` 拒掉（L3），现场是"只有那个核的用例红"，极难归因。
    let depth_stuck: usize =
        (0..cpu::MAX_CPUS).filter(|&s| cpu::is_registered(s) && apic::isr_depth(s) != 0).count();
    crate::log_info!(
        "smp: mp_cpus={} expected_ap={} released={} refused={} online_ap={} timer_failed={} id_mismatch={} ready_timeout={} isr_depth_stuck={}",
        mp.cpu_count, expected, released, refused, online_aps, smp::ap_timer_failures(),
        smp::ap_id_mismatches(), smp::ready_timeouts(), depth_stuck
    );
    crate::log_info!(
        "smp: bsp_lapic={} cpu_ticks={:?} ap_exstack_failed={} ap_lapic_failed={} ap_stages={:?} ap_timer_init={:?}",
        bsp, apic::cpu_ticks_all(), exstack_failed, lapic_failed,
        [smp::ap_stage(1), smp::ap_stage(2), smp::ap_stage(3), smp::ap_stage(4)],
        [smp::ap_timer_init(1), smp::ap_timer_init(2), smp::ap_timer_init(3), smp::ap_timer_init(4)]
    );
    // AP 定时器标定的现场（最后一次写者赢）：tmcct, spent, dt_cycles, counts_per_sec, initial
    crate::log_info!(
        "smp: ap timer_err={} cal_dbg[tmcct={:#x} spent={} dt_cycles={} counts_per_sec={} initial={:#x}]",
        smp::ap_timer_err_kind(),
        apic::cal_dbg()[0], apic::cal_dbg()[1], apic::cal_dbg()[2], apic::cal_dbg()[3], apic::cal_dbg()[4]
    );
    // 容量不足也要报红：把 8 核机器当 4 核机验证，等于没验证
    let capacity_ok = refused == 0 && released == expected;
    capacity_ok && all_ticked_before && recurred && online_aps == released && lapic_failed == 0
        && depth_stuck == 0
}
ktest!(KT_AP_TICKING, t_ap_released_and_ticking);

/// 三个来源的 CPU id 必须互相吻合：MP 响应、MADT 表、以及**每个 CPU 自己读回的 LAPIC 寄存器**。
/// 前两个都是"别人告诉我们的"，只有第三个是硬件当场说的；少一个来源，
/// "槽位分对了"这句话就只是自证（`t_mp_agrees_with_madt` 已经对过前两个）。
fn t_cpu_ids_agree() -> bool {
    // 每一个提前返回都要留一句话。这一条用例第一次跑就是这么静悄悄 false 掉的
    // （bringup 的前置没满足，见 `smp::bringup` 里补 apic::get_or_init 那段），
    // 日志里什么线索都没有——"量具不出数不等于出数为 0"，用例不解释为什么不算数更糟。
    let Some(mp) = mp_snapshot() else {
        crate::log_fatal!("cpu ids: 没有 MP 响应");
        return false;
    };
    let Some(s) = acpi::summary() else {
        crate::log_fatal!("cpu ids: ACPI 没解析出摘要");
        return false;
    };
    let Some(m) = s.madt else {
        crate::log_fatal!("cpu ids: 没有 MADT");
        return false;
    };
    if let Err(e) = smp::bringup() {
        crate::log_fatal!("cpu ids: bringup 失败 {:?}", e);
        return false;
    }
    let unmatched0 = cpu::unmatched_self_lookups();
    let mut mismatches = 0usize;
    let mut checked = 0usize;
    for slot in 0..cpu::MAX_CPUS {
        let Some(registered) = cpu::lapic_id_of(slot) else { continue };
        let Some(seen) = cpu::hw_id_seen(slot) else {
            crate::log_warn!("cpu ids: slot={} 还没上报过硬件 id", slot);
            mismatches += 1;
            continue;
        };
        // MADT 里必须也有这一条：否则我们释放的是一个表里不存在的核
        let in_madt = m.lapic_ids[..m.n_ids].contains(&registered);
        let in_mp = mp.lapic_ids[..mp.n].contains(&registered);
        if seen != registered || !in_madt || !in_mp {
            mismatches += 1;
            crate::log_fatal!(
                "cpu ids: slot={} 登记={:#x} 硬件读回={:#x} 在MADT={} 在MP={}",
                slot, registered, seen, in_madt, in_mp
            );
        }
        checked += 1;
    }
    let unmatched = cpu::unmatched_self_lookups() - unmatched0;
    crate::log_info!(
        "cpu ids: checked={} mismatches={} unmatched_self_lookups_delta={} (madt_ids={:?} mp_ids={:?})",
        checked, mismatches, unmatched, &m.lapic_ids[..m.n_ids], &mp.lapic_ids[..mp.n]
    );
    // 两个数都要 0：id 不一致 = 槽位表不可信；自查找落空 = 有人在没登记的情况下跑了别的 id
    mismatches == 0 && unmatched == 0 && checked >= 1
}
ktest!(KT_CPU_IDS, t_cpu_ids_agree);

/// ADR-021 的读数：IF 由 CPU 供，不由任务帧携带。
///
/// 这条用例的形状是**故意**的：先看一个新任务的合成帧里 IF 位是 0（`spawn` 写 0x2），
/// 再让它在开窗口的窗口里第一次被换入并至少被换下一次，然后读它**此刻存的帧**——
/// 那是硬件在它被抢占时压下来的现场，IF=1 就证明它当时真的带着开着的 IF 在跑。
/// 如果换入时没人改写这一位（旧行为），它会一直是 0，窗口里再也没有第二个 tick，
/// 整条用例直接挂不住——那正是 M3a 记录过的"合成帧写 0x2 就整机卡死"的故障形状。
fn t_if_belongs_to_cpu() -> bool {
    // §199：收尾按原样放回。**入口**记一次状态，只守卫**最后一个** stop；
    // 中间那些 stop 是被测语义本身（故意停表的窗口），一个都不动。
    let timer_was_running =
        apic::wait_ticks(apic::ticks(), 2, crate::clock::window_cycles(2)).ticks >= 2;
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        return false;
    }
    let slot = match sched::spawn(sched_worker_forever) {
        Ok(i) => i,
        Err(e) => {
            crate::log_fatal!("if-rule: spawn 失败 {:?}", e);
            return false;
        }
    };
    let before = sched::frame_rflags_of(slot);
    let if_before = sched::frame_if_bit(slot).unwrap_or(true);
    sched::init_boot_task();
    apic::timer_start().ok();
    let (sw0, _) = sched::stats_of(cpu::BSP_SLOT);
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        // 要求这一槽被**换入过并且换下过**：runs>=2 之后它存的必然是自己的抢占现场
        while (sched::runs_of(slot) < 2 || sched::stats_of(cpu::BSP_SLOT).0 < sw0 + 4)
            && tsc::now() - t0 < 600_000_000
        {
            tsc::spin(20_000);
        }
        sched::stop_workers();
        let back = sched::wait_for_boot_task(400_000_000);
        if !back {
            crate::log_fatal!("if-rule: 启动上下文没能回到 CPU（窗口收场不了）");
        }
    });
    if !timer_was_running {
        apic::timer_stop().ok();
    }
    let after = sched::frame_rflags_of(slot);
    let if_after = sched::frame_if_bit(slot).unwrap_or(false);
    let runs = sched::runs_of(slot);
    // ---- P3a：关着窗口主动让出，给 `loads_closed` 一个真正的触发源（ADR-049）----
    // 先把那个"不收工"的工人请出队列：它不会让回来，而关窗口 + 停表之后没有任何
    // 抢占来源，让出去就再也回不来（§111 的机制，这里刻意避开它）。
    let _ = sched::terminate_task(slot);
    // 用例自足：关窗口 + 停表之后**没有任何抢占来源**，所以此刻本 CPU 上除启动上下文
    // 以外不许留下任何可选中的任务——否则 `pick_next` 会把它选上来，而它若是个只会
    // 自旋的 ring3 任务，整机就再也回不来（实测 RIP=0x100102040 CPL=3，与 §111 同一地址）。
    // 残留是谁不由本用例决定（`.ktests` 顺序由链接器定），所以逐个清掉并留一行证据。
    let boot = sched::current_id();
    let mut swept = 0usize;
    for i in 0..sched::MAX_TASKS_TOTAL {
        if i == boot || sched::cpu_of(i) != cpu::BSP_SLOT || i == sched::idle_of(cpu::BSP_SLOT) {
            continue; // idle 是兜底，不能扫掉（ADR-051）：扫掉它就回到"没人可换"的老形状
        }
        if sched::state_of(i) != sched::TaskState::Free && sched::terminate_task(i) {
            swept += 1;
            crate::log_info!("yield: 清掉残留任务 #{}", i);
        }
    }
    let closed_before = sched::if_loads().0;
    let partner = match sched::spawn(yield_partner) {
        Ok(i) => i,
        Err(e) => {
            crate::log_fatal!("yield: 搭档 spawn 失败 {:?}", e);
            return false;
        }
    };
    apic::close_cpu_window(cpu::BSP_SLOT);
    sched::yield_now(); // 关着窗口让出：硬件建帧 → preempt_point 换入搭档
    // 搭档会让回来。能回到这一行，就说明"关窗口换入"这条路真的走通了。
    apic::open_cpu_window(cpu::BSP_SLOT);
    apic::open_cpu_window(cpu::BSP_SLOT);
    let closed_after = sched::if_loads().0;
    let partner_runs = sched::runs_of(partner);
    let (loads_closed, loads_open) = sched::if_loads();
    // 读数取完之后把搭档收掉（W1 收尾 B2 查出来的第三个泄漏）：它要**第二次**被换上
    // 才走得到自己的 `finish_current()`，而这一段表已经停了、没有任何抢占来源，
    // 于是它永远停在 `Runnable`。以前"内核任务一律豁免"看不见这一格。
    let partner_swept = sched::terminate_task(partner);
    crate::log_info!(
        "if-rule(ADR-021): slot={} runs={} frame_before={:?}(IF={}) frame_after={:?}(IF={}) loads_open={} loads_closed={}",
        slot, runs, before, if_before, after, if_after, loads_open, loads_closed
    );
    crate::log_info!(
        "yield(ADR-049): 关窗口让出 closed {} -> {} 搭档runs={} 自陷计数={} 清残留={} 窗口还原={} 搭档收掉={}",
        closed_before, closed_after, partner_runs, apic::counts().resched, swept,
        apic::interrupts_enabled(cpu::BSP_SLOT), partner_swept);
    // 判据：换入前 IF=0（帧里带的）→ 换入后跑过 ≥2 次且它的现场里 IF=1（CPU 给的）。
    // `loads_closed` 这一格从 P3a 起**有触发源了**：`yield_now` 自陷 0xF0，软件中断不受
    // IF 影响，所以关着窗口也能换人（ADR-049）。原来那句"必然 0、等主动让出时补"
    // 就是在这里补上的：现在要求它真的前进过，且搭档确实被换入过。
    !if_before && runs >= 2 && if_after && loads_open > 0
        && closed_after > closed_before && partner_runs >= 1 && partner_swept
}
ktest!(KT_IF_BELONGS_TO_CPU, t_if_belongs_to_cpu);

/// ADR-068：嵌套的 `with_interrupts` 不许关掉外层还开着的窗口。三格各管一件事：
/// 1. **牌**：内层返回后，外层的牌必须还写着开 ⇒ 直接对着 BACKLOG 82 记的那句话
///    （"返回时把牌一律置 false，不恢复原值"）。
/// 2. **硬件**：同一段外层窗口里必须真收到 ≥1 发 tick ⇒ 牌只是软件影子，这一格量 EFLAGS.IF。
///    这里用 `wait_tick_count` 而不是 `wait_ticks`：前者**不碰**中断状态，所以它没再嵌套一层，
///    量到的就是外层窗口的真实 IF。
/// 3. **没改坏非嵌套**：最外层返回后牌回关，且整段窗口长度里 0 发 tick ⇒ 用例不是
///    "改了什么东西就红"：修复前这一格照样绿。
/// 修复前的期望是 1、2 红、3 绿；`window_cycles(N)` 是按 TSC 区间最坏端点推的上界，
/// 所以第 2 格不需要碰运气（与 `time.rs` 三段窗口同一口径）。
fn t_if_window_nested() -> bool {
    let slot = cpu::self_slot();
    // 前提归一：从"窗口关着"起步，判据不取决于上一条用例留下什么牌；收尾按进来时放回。
    let prior = apic::interrupts_enabled(slot);
    apic::close_cpu_window(slot);
    // 用例自足：tick 靠表驱动，而 `.ktests` 顺序由链接器定，前面的用例可能把表停了
    // （与 `t_sleep_until` 同一形状）。这个 probe 自己开窗关窗，落在前提之后，不影响判据。
    let probe = apic::wait_ticks(apic::ticks(), 2, clock::window_cycles(2));
    let running_on_entry = probe.ticks >= 2;
    if !running_on_entry {
        apic::timer_start().ok();
    }

    let mut inner_saw_open = false;
    let mut sign_after_inner = false;
    let mut outer_ticks = 0u64;
    let mut outer_cycles = 0u64;
    apic::with_interrupts(|| {
        // 内层：进来时外层已经开着，出去时不许把外层关掉
        apic::with_interrupts(|| {
            inner_saw_open = apic::interrupts_enabled(slot);
        });
        sign_after_inner = apic::interrupts_enabled(slot);
        let w = apic::wait_tick_count(clock::window_cycles(2));
        outer_ticks = w.ticks;
        outer_cycles = w.cycles;
    });
    let sign_after_outer = apic::interrupts_enabled(slot);
    let after = apic::wait_tick_count(clock::window_cycles(1));
    if !running_on_entry {
        apic::timer_stop().ok();
    }
    if prior {
        apic::open_cpu_window(slot);
    }
    crate::log_info!(
        "nested(ADR-068): 内层见开={} 内层返回后牌={} 外层窗口内tick={}跨{}cycles 外层返回后牌={} 之后tick={}跨{}cycles 进表时心跳={}",
        inner_saw_open,
        sign_after_inner,
        outer_ticks,
        outer_cycles,
        sign_after_outer,
        after.ticks,
        after.cycles,
        running_on_entry
    );
    let ok = inner_saw_open
        && sign_after_inner
        && outer_ticks >= 1
        && !sign_after_outer
        && after.ticks == 0
        && after.cycles >= clock::window_cycles(1);
    if !ok {
        crate::log_fatal!(
            "nested: 判据不成立 内层见开={} 内层后牌={} 外层内tick={} 外层后牌={} 之后tick={}(应0) 之后跨={}(应>=窗口)",
            inner_saw_open,
            sign_after_inner,
            outer_ticks,
            sign_after_outer,
            after.ticks,
            after.cycles
        );
    }
    ok
}
ktest!(KT_IF_WINDOW_NESTED, t_if_window_nested);

// ---- W1 收尾 B2：收尾判据的豁免改成**显式名单**，扫描范围扩到所有在线 CPU ----
//
// 这条用例就是那份"同轮的负样本"（ADR-050 未决 2 要求扩范围必须同轮换判据与负样本）。
// 它注入的是**不登记**的常驻形状工人（自己不退出不收工），分两格：
// BSP 一格、AP 一格。AP 那一格只有在扫描范围真的扩到全 CPU 时才看得见——
// 把 `finish_sweep` 改回"只扫 BSP"，第 2 格当场红（MUTATION-F1）。
// 把豁免改回"所有内核任务都豁免"（blanket），第 1、2 格同时红（MUTATION-F2）。

/// 被注入的工人：只数自己的圈，**永不退出**。它走 `spawn`，所以 `Task::resident=false`。
static FSN_WORK: [core::sync::atomic::AtomicU64; cpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; cpu::MAX_CPUS];
/// 每颗 CPU 上那个注入工人的全局槽号（`usize::MAX` = 没建成/已收掉）。
static FSN_GIDX: [core::sync::atomic::AtomicUsize; cpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicUsize::new(usize::MAX) }; cpu::MAX_CPUS];

fn fsn_stray_worker() -> ! {
    let c = cpu::self_slot();
    loop {
        FSN_WORK[c].fetch_add(1, Ordering::Relaxed);
        tsc::spin(3_000);
    }
}

/// AP 侧的角色：在**自己这条 CPU** 的队列里建一个不登记的工人。
/// `spawn` 挂在 `cpu::self_slot()` 上，所以这个任务生来就归那颗 AP——这正是
/// "只扫 BSP 的判据看不见 AP 残留"的那个形状，拿它当证人而不是靠推断。
fn fsn_ap_spawn_role() {
    let c = cpu::self_slot();
    FSN_WORK[c].store(0, Ordering::Relaxed);
    if let Ok(g) = sched::spawn(fsn_stray_worker) {
        FSN_GIDX[c].store(g, Ordering::Release);
    }
}

fn fsn_noop() {}

fn fsn_clear() {
    for c in 0..cpu::MAX_CPUS {
        let g = FSN_GIDX[c].swap(usize::MAX, Ordering::AcqRel);
        if g != usize::MAX {
            let _ = sched::terminate_task(g);
        }
    }
}

/// 收尾判据自己的判据：注入必须被点名、点名范围必须覆盖 AP、收干净必须回 0。
fn t_finish_sweep_names_worker() -> bool {
    // 前提：进来时账是干净的。不干净就别测——残留是谁留的由链接顺序决定，
    // 那种红离本用例的成因太远（§86e 的教训）。
    let sw0 = crate::finish_sweep();
    if sw0.stray != 0 || sw0.blocked != 0 {
        crate::log_fatal!("finish-sweep: 前提失效，进用例时已有 未登记={} 阻塞={}", sw0.stray, sw0.blocked);
        return false;
    }
    // 名单非空是"豁免是显式的"这句话的反空转格：BSP 至少占两格（启动上下文 + 兜底 idle）。
    if sw0.residents < 2 {
        crate::log_fatal!("finish-sweep: 常驻名单是空的（residents={}）⇒ 豁免这一侧没被测过", sw0.residents);
        return false;
    }

    // ① BSP 注入
    let g_bsp = match sched::spawn(fsn_stray_worker) {
        Ok(g) => g,
        Err(e) => {
            crate::log_fatal!("finish-sweep: BSP 侧 spawn 失败 {:?}", e);
            return false;
        }
    };
    FSN_GIDX[cpu::BSP_SLOT].store(g_bsp, Ordering::Release);
    let sw1 = crate::finish_sweep();

    // ② 收掉 BSP 那一格，只剩 AP 上的注入——此刻点名范围必须落在非 BSP 的 CPU 上
    let _ = sched::terminate_task(g_bsp);
    FSN_GIDX[cpu::BSP_SLOT].store(usize::MAX, Ordering::Release);
    if smp::run_ap_role(fsn_ap_spawn_role, fsn_noop).is_err() {
        crate::log_fatal!("finish-sweep: AP 角色没跑起来 ⇒ 第 2 格的证人不存在，不静默跳过");
        fsn_clear();
        return false;
    }
    let sw2 = crate::finish_sweep();
    let ap_strays = (1..cpu::MAX_CPUS).filter(|&c| FSN_GIDX[c].load(Ordering::Acquire) != usize::MAX).count();

    // ③ 全部收干净
    fsn_clear();
    let sw3 = crate::finish_sweep();

    crate::log_info!(
        "收尾名单(ADR-050/061): 在线CPU={} 进用例豁免={} BSP注入后点名={}/{}(cpu{} 首个#{}) 只剩AP注入时={}/{}(cpu{} 首个#{}) 收干净后={}/{} AP侧建成={}",
        sw0.cpus,
        sw0.residents,
        sw1.stray,
        sw1.blocked,
        sw1.stray_cpu,
        sw1.first_stray,
        sw2.stray,
        sw2.blocked,
        sw2.stray_cpu,
        sw2.first_stray,
        sw3.stray,
        sw3.blocked,
        ap_strays
    );
    let ok = sw1.stray == 1
        && sw1.first_stray == g_bsp
        && sw1.stray_cpu == cpu::BSP_SLOT
        && ap_strays >= 1
        && sw2.stray == ap_strays
        && sw2.stray_cpu != cpu::BSP_SLOT
        && sw3.stray == 0
        && sw3.blocked == 0
        && sw3.residents == sw0.residents;
    if !ok {
        crate::log_fatal!(
            "finish-sweep: 判据不成立 注入后={}/{}(cpu{} 首个#{}, 期望 1/#{}#{}) AP-only={}/{}(cpu{}, 期望 AP 且={}) 收干净={}/{} 豁免{}->{}",
            sw1.stray,
            sw1.blocked,
            sw1.stray_cpu,
            sw1.first_stray,
            g_bsp,
            cpu::BSP_SLOT,
            sw2.stray,
            sw2.blocked,
            sw2.stray_cpu,
            ap_strays,
            sw3.stray,
            sw3.blocked,
            sw0.residents,
            sw3.residents
        );
    }
    ok
}
ktest!(KT_FINISH_SWEEP, t_finish_sweep_names_worker);

/// P3b 的工人：**自己**终止自己，然后让出。
/// `terminate_task` 对"正在 CPU 上"的任务只登记待回收、不就地释放（它正站在那条栈上），
/// 所以必须让出去一次，别人才收得到它。
fn self_terminating_worker() -> ! {
    let me = sched::current_id();
    let _ = sched::terminate_task(me);
    sched::yield_now();
    loop {
        tsc::spin(3_000);
    }
}

/// P3b：把 BACKLOG 144 那条**没写下来的前提**变成被测的不变量。
///
/// 前提原文：资源释放推迟到"本 CPU 上跑的已经不是它"的那一刻（`reap` 的 `skip = current`）。
/// 它今天成立，是因为总有别人可换（启动上下文）——但那是**假设**，不是保证：
/// 一旦没有别人，标了 Done/Free 的任务就永远占着 CPU，`reap` 永远跳过它，资源永不回账。
/// 这条用例用 `yield_now`（ADR-049）把"换别人"做成确定性动作，然后验证前提的结论：
/// 自己终止的任务在 CPU 换过别人之后，槽位归 Free、名下资源回账。
///
/// 它同时是 P3b 后半（兜底 idle）的**判据基线**：idle 落地之后这条必须仍然绿，
/// 而且那时"总有别人可换"才第一次由构造保证，而不是靠启动上下文恰好在册。
fn t_reap_premise() -> bool {
    // 只在 0 号槽确实空着时登记启动上下文：`init_boot_task` 会无条件重写 slot 0
    // （frame=0、runs=1），在已有 boot 任务时调它会把别的用例的读数打掉。
    if sched::state_of(0) == sched::TaskState::Free {
        sched::init_boot_task();
    }
    let released0 = sched::reap_released();
    let w = match sched::spawn(self_terminating_worker) {
        Ok(i) => i,
        Err(e) => {
            crate::log_fatal!("reap 前提: 工人 spawn 失败 {:?}", e);
            return false;
        }
    };
    sched::yield_now(); // 换工人上来：它自己 terminate + 让出
    sched::yield_now(); // 再让一次：给 reap 一个"它已不是 current"的机会
    let st = sched::state_of(w);
    let owned = sched::owned_of(w);
    let released = sched::reap_released();
    crate::log_info!(
        "reap 前提(BACKLOG144): worker=#{} 状态={:?} 名下={} released {} -> {}",
        w, st, owned, released0, released);
    st == sched::TaskState::Free && owned == 0 && released > released0
}
ktest!(KT_REAP_PREMISE, t_reap_premise);

/// P3b-2 的搭档：让出一次就收工，用来证明"有真任务时 idle 不许被选中"。
fn idle_probe_partner() -> ! {
    sched::yield_now();
    sched::finish_current();
    loop {
        tsc::spin(3_000);
    }
}

/// P3b-2：兜底 idle 的三条可观测保证（ADR-051 决策 3/4）。
///
/// ①它登记在册、可运行、**名下无资源**（`owned` 为空 ⇒ `reap` 永远不会解映射它的栈）；
/// ②`tasks_active()` 把它排除——用**独立重算**对账，不是读一遍同一个函数自证；
/// ③有真任务可跑时**不许**选它：让出一次，看 idle 的 `runs` 有没有动。
///
/// 覆盖缺口要说清：**回落分支本身**（prev 已 Done/Free 且没有别的真任务）无法由用例直接
/// 触发——那要求跑用例的上下文自己不再可运行，等于把测试 runner 结束掉。所以这里验的是
/// 使那条分支安全的三个前提，分支本身留待 P4 的阻塞用例间接覆盖（见 BACKLOG）。
fn t_idle_fallback() -> bool {
    let idle = sched::idle_of(cpu::BSP_SLOT);
    if idle == usize::MAX {
        crate::log_fatal!("idle: BSP 没有登记兜底 idle");
        return false;
    }
    let st = sched::state_of(idle);
    let owned = sched::owned_of(idle);
    // ② 独立重算：自己数一遍"非 idle 且可运行"，与 tasks_active() 对账
    let mut recount = 0usize;
    for i in 0..sched::MAX_TASKS_TOTAL {
        if i == sched::idle_of(sched::cpu_of(i)) {
            continue;
        }
        if matches!(sched::state_of(i), sched::TaskState::Runnable | sched::TaskState::Running) {
            recount += 1;
        }
    }
    let active = sched::tasks_active();
    // ③ 有真任务时不许选 idle
    let runs0 = sched::runs_of(idle);
    let partner = match sched::spawn(idle_probe_partner) {
        Ok(i) => i,
        Err(e) => {
            crate::log_fatal!("idle: 搭档 spawn 失败 {:?}", e);
            return false;
        }
    };
    sched::yield_now();
    let runs1 = sched::runs_of(idle);
    let partner_runs = sched::runs_of(partner);
    // 收尾自己收干净（W1 收尾 B2 查出来的）：这个搭档让出一次就回到 `Runnable`，
    // 永远走不到它自己的 `finish_current()`。以前"内核任务一律豁免"把它藏住了，
    // 改成显式名单之后收尾判据当场点名——它不是 idle，不在名单里，就该被收掉。
    // 读数已经在上面取完，所以收掉它不影响本用例的判据。
    let swept = sched::terminate_task(partner);
    crate::log_info!(
        "idle(ADR-051): 下标={} 状态={:?} 名下={} active={} 独立重算={} idle_runs {} -> {} 搭档runs={} 搭档收掉={}",
        idle, st, owned, active, recount, runs0, runs1, partner_runs, swept);
    st == sched::TaskState::Runnable && owned == 0 && active == recount
        && runs1 == runs0 && partner_runs >= 1 && swept
}
ktest!(KT_IDLE_FALLBACK, t_idle_fallback);

/// P4a 的工人：标阻塞 → 告诉启动上下文 → 让出 → 被唤醒后置位 → **再让一次**还 CPU → 收工。
/// 最后那次让出是必须的：否则它标 Done 之后就在原地自旋，启动上下文读不到 WOKE
/// （停表时没有 tick 能把它换下去，§111 那一类）。
static BW_MARKED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static BW_WOKE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
const BW_TOKEN: sync::WaitToken = sync::WaitToken { queue: 0, seq: 1 };

fn block_wake_worker() -> ! {
    if sched::block_current(BW_TOKEN) {
        BW_MARKED.store(1, Ordering::Relaxed); // 此刻它确实是 Blocked 了
        sched::yield_now();
    }
    BW_WOKE.store(1, Ordering::Relaxed);
    sched::yield_now();
    sched::finish_current();
    loop {
        tsc::spin(3_000);
    }
}

/// P4a（ADR-053）：同核阻塞/唤醒的状态转移与**世代号**。
///
/// 判据四格：①工人真的进了 `Blocked(token)`；②**错世代号的 wake 必须无效**
/// （返回 false 且状态仍是 Blocked）——这一格就是决策 4 的负样本，内置在判据里，
/// 去掉世代号比较它会当场红；③对的 token 能唤醒；④工人真的被放出去跑过。
/// 全部用 `yield_now` 驱动，不依赖 tick，所以停表状态下也确定性成立。
fn t_block_wake() -> bool {
    if sched::state_of(0) == sched::TaskState::Free {
        sched::init_boot_task();
    }
    BW_MARKED.store(0, Ordering::Relaxed);
    BW_WOKE.store(0, Ordering::Relaxed);
    let w = match sched::spawn(block_wake_worker) {
        Ok(i) => i,
        Err(e) => {
            crate::log_fatal!("block/wake: 工人 spawn 失败 {:?}", e);
            return false;
        }
    };
    sched::yield_now(); // 换工人上来
    let mut n = 0usize;
    while BW_MARKED.load(Ordering::Relaxed) == 0 && n < 1000 {
        sched::yield_now();
        n += 1;
    }
    let marked = BW_MARKED.load(Ordering::Relaxed) == 1;
    let st_blocked = sched::state_of(w);
    let stale = sched::wake_task(w, sync::WaitToken { queue: 0, seq: 2 });
    let st_after_stale = sched::state_of(w);
    let woke = sched::wake_task(w, BW_TOKEN);
    let mut m = 0usize;
    while BW_WOKE.load(Ordering::Relaxed) == 0 && m < 1000 {
        sched::yield_now();
        m += 1;
    }
    let woken = BW_WOKE.load(Ordering::Relaxed) == 1;
    crate::log_info!(
        "block/wake(ADR-053): worker=#{} marked={} 阻塞态={:?} 错token={} 之后={:?} 对token={} 被唤醒={} 让出={}/{}",
        w, marked, st_blocked, stale, st_after_stale, woke, woken, n, m);
    // 收干净（ADR-050 的同一纪律，这里是内核工人）：留一个仍 Runnable 的工人在队列里，
    // 后续用例让出时就会把它选上来，而它标 Done 之后原地自旋——停表窗口里 idle 也要靠
    // tick 才能还回 CPU，于是整机静默。实测这么挂过一次，所以用例自己 terminate 掉。
    let _ = sched::terminate_task(w);
    marked
        && matches!(st_blocked, sched::TaskState::Blocked(t) if t == BW_TOKEN)
        && !stale
        && matches!(st_after_stale, sched::TaskState::Blocked(_))
        && woke
        && woken
}
ktest!(KT_BLOCK_WAKE, t_block_wake);

/// P4b 的生产者/消费者：消费者在条件不成立时阻塞，生产者置位后 wake_one。
static WQ_FLAG: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static WQ_DONE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
const WQ_ROUNDS: u64 = 24;

fn wq_consumer() -> ! {
    let q = sync::wait_queue(0);
    for _ in 0..WQ_ROUNDS {
        if let Some(q) = q {
            // 条件谓词在 WAITQ 锁内被调用，所以它必须是廉价读，不能睡、不能取更外层的锁
            let _ = q.wait_while(0, || WQ_FLAG.load(Ordering::Relaxed) != 0);
        }
        WQ_FLAG.store(0, Ordering::Relaxed);
        WQ_DONE.fetch_add(1, Ordering::Relaxed);
        sched::yield_now(); // 把 CPU 还给生产者，让它推进下一轮
    }
    sched::finish_current();
    loop {
        tsc::spin(3_000);
    }
}

/// P4b（ADR-053）：条件等待协议的可观测保证。
///
/// 四格：①每一轮都推进到 `WQ_ROUNDS`（没有丢唤醒——丢一次就会卡在某轮，有界让出后判红）；
/// ②链上无残留槽；③`blocks == wakes`（每次阻塞都被一次有效唤醒配对）；
/// ④`empty_wakes` 与 `blocks` 一起读才有意义：生产者跑在消费者阻塞之前是**合法**的，
/// 那一次 wake 落在空队列上，消费者随后查条件直接成立、不阻塞。
/// 全部用 `yield_now` 驱动，停表状态下也确定性成立。
fn t_waitqueue() -> bool {
    if sched::state_of(0) == sched::TaskState::Free {
        sched::init_boot_task();
    }
    let Some(q) = sync::wait_queue(0) else {
        crate::log_fatal!("waitqueue: 0 号队列取不到");
        return false;
    };
    WQ_FLAG.store(0, Ordering::Relaxed);
    WQ_DONE.store(0, Ordering::Relaxed);
    let c = match sched::spawn(wq_consumer) {
        Ok(i) => i,
        Err(e) => {
            crate::log_fatal!("waitqueue: 消费者 spawn 失败 {:?}", e);
            return false;
        }
    };
    let mut stalled = 0usize;
    for round in 0..WQ_ROUNDS {
        // **先让消费者去阻塞**：不先让一次，生产者总是跑在前面，消费者查条件时 flag 已置位，
        // 于是一次都不阻塞（实测第一版 blocks=0 wakes=0 empty_wakes=24，判据全绿却什么都没测）。
        sched::yield_now();
        WQ_FLAG.store(1, Ordering::Relaxed);
        let _ = q.wake_one();
        let target = round + 1;
        let mut n = 0usize;
        while WQ_DONE.load(Ordering::Relaxed) < target && n < 200 {
            sched::yield_now();
            n += 1;
        }
        if WQ_DONE.load(Ordering::Relaxed) < target {
            stalled += 1;
            crate::log_fatal!("waitqueue: 第 {} 轮没推进（done={}）", round, WQ_DONE.load(Ordering::Relaxed));
            break;
        }
    }
    let done = WQ_DONE.load(Ordering::Relaxed);
    let (blocks, wakes, empty, used) = q.stats();
    // 收干净（ADR-050 的纪律）：消费者若还阻塞着，先摘链再终止，避免留一个陈旧 waiter
    let _ = q.remove_task(c);
    let _ = sched::terminate_task(c);
    crate::log_info!(
        "waitqueue(ADR-053): rounds={} done={} blocks={} wakes={} empty_wakes={} 仍在链上={} 卡住={}",
        WQ_ROUNDS, done, blocks, wakes, empty, used, stalled);
    // `blocks > 0` 是**防空转**的一格：没有它，"生产者永远跑在前面"也能让其余各格全绿
    done == WQ_ROUNDS && stalled == 0 && used == 0 && blocks == wakes && blocks > 0
}
ktest!(KT_WAITQUEUE, t_waitqueue);

/// P4c-1（ADR-055）：跨核 resched 的**直接见证**——发一发 IPI，目标 CPU 真的立了牌。
///
/// 为什么先做这一格再上四核压力：跨核唤醒链条有三环（发送方标 Runnable → IPI 送达 →
/// 目标立牌后 preempt 换人）。压力用例把三环混在一个读数里，红了分不清哪一环；
/// 这一格只验后两环，且是确定性的（每个在线 AP 都必须送达）。
/// 第一环由 `t_block_wake`/`t_waitqueue` 的状态转移判据覆盖。
#[cfg(not(feature = "fault-resched-ipi"))]
fn t_cross_cpu_resched() -> bool {
    if smp::bringup().is_err() {
        crate::log_fatal!("resched: AP 起不来");
        return false;
    }
    let mut checked = 0usize;
    let mut delivered = 0usize;
    let mut refused = 0usize;
    for ap in 1..cpu::MAX_CPUS {
        if !cpu::is_online(ap) {
            continue;
        }
        checked += 1;
        let m0 = sched::resched_marks(ap);
        if !sched::request_resched(ap) {
            refused += 1;
            continue;
        }
        let t0 = tsc::now();
        while sched::resched_marks(ap) <= m0 && tsc::now().wrapping_sub(t0) < 200_000_000 {
            tsc::spin(2_000);
        }
        if sched::resched_marks(ap) > m0 {
            delivered += 1;
        }
    }
    let fails = sched::resched_ipi_fail();
    crate::log_info!(
        "resched 跨核(ADR-055): 在线AP={} 送达={} 发送被拒={} IPI失败累计={}",
        checked, delivered, refused, fails);
    // 健康跑里每一发都送达（delivered==checked），失败计数就必须是 0——这是"计数不误报"
    // 的那一半；"计数会咬"的另一半由 fault-resched-ipi 构建的 t_resched_ipi_fail_fallback 证。
    checked > 0 && delivered == checked && refused == 0 && fails == 0
}
#[cfg(not(feature = "fault-resched-ipi"))]
ktest!(KT_CROSS_CPU_RESCHED, t_cross_cpu_resched);

// ---- P4c-2：跨核阻塞/唤醒压力。逻辑全部在**测试层** ----
// arch 只提供"把 AP 编组进相位跑给定角色"的原语（`smp::run_ap_role`）。
// 为什么这样分层：压力逻辑要引用 `sync::WaitQueue` 与 `clock`，写进 arch 会让环内边
// `arch->sync`、`arch->time` 变胖，ADR-044 的棘轮当场红（实测红过一次）。
// 放 ktests 既合层次，又按 ADR-043 不计产品依赖边。

const WWC_QID: u8 = 1;
const WWC_ROUNDS: u64 = 200;
static WWC_COUNT: [core::sync::atomic::AtomicU64; cpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; cpu::MAX_CPUS];
static WWC_DONE: [core::sync::atomic::AtomicU64; cpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; cpu::MAX_CPUS];
static WWC_ERR: [core::sync::atomic::AtomicU64; cpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; cpu::MAX_CPUS];
/// 生产者侧的观测结果（BSP 单点写，读它在收齐回执之后）
static WWC_MAXLAT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static WWC_SLOW: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static WWC_STALLED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static WWC_PARTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static WWC_BOUND: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// AP 侧的**消费者**：条件不成立时真的阻塞，被跨核 IPI 唤醒后继续。
fn wwc_consumer() {
    let slot = cpu::self_slot();
    let Some(q) = sync::wait_queue(WWC_QID) else {
        WWC_ERR[slot].fetch_add(1, Ordering::Relaxed);
        return;
    };
    let mut c = 0u64;
    while c < WWC_ROUNDS {
        let target = c + 1;
        match q.wait_while(WWC_QID, || WWC_COUNT[slot].load(Ordering::Acquire) >= target) {
            Ok(_) => {}
            Err(_) => {
                WWC_ERR[slot].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        c = target;
        WWC_DONE[slot].store(c, Ordering::Release);
    }
}

/// BSP 侧的**生产者兼观察者**：永不阻塞，所以丢唤醒时它能报红而不是整机静默。
fn wwc_producer() {
    let (n, aps) = smp::participant_slots();
    WWC_PARTS.store(n as u64 + 1, Ordering::Relaxed);
    let Some(q) = sync::wait_queue(WWC_QID) else { return };
    let bound = clock::window_cycles(1) / 2;
    WWC_BOUND.store(bound, Ordering::Relaxed);
    let mut max_lat = 0u64;
    let mut slow = 0u64;
    for i in 1..=WWC_ROUNDS {
        for &s in &aps[..n] {
            WWC_COUNT[s].store(i, Ordering::Release);
        }
        let t0 = tsc::now();
        let _ = q.wake_all();
        let mut spins = 0u64;
        while !aps[..n].iter().all(|&s| WWC_DONE[s].load(Ordering::Acquire) >= i) && spins < 2_000_000 {
            core::hint::spin_loop();
            spins += 1;
        }
        let lat = tsc::now().wrapping_sub(t0);
        if lat > max_lat {
            max_lat = lat;
        }
        if lat > bound {
            slow += 1;
        }
        if spins >= 2_000_000 {
            WWC_STALLED.store(1, Ordering::Relaxed);
            break;
        }
    }
    WWC_MAXLAT.store(max_lat, Ordering::Relaxed);
    WWC_SLOW.store(slow, Ordering::Relaxed);
}

/// P4c-2（ADR-056）：跨核阻塞/唤醒的**并发**证明。
///
/// 八格：不卡住、全消费到轮数、无等待错误、链上无残留、`blocks == wakes`、
/// **`blocks > 0`（防空转）**、**慢轮 ≤ 10%**、**收到的跨核 IPI > 0**。
/// 延迟用**慢轮比例**而不是最大值：实测有 IPI 时慢轮 1.5~2.5%、最大值约 1.3 个 tick，
/// 那部分是 TCG 把四个 vCPU 串在一个宿主线程上轮转的抖动，量的是模拟器不是内核；
/// 去掉 IPI 则每轮都要等目标自己的 tick ⇒ 慢轮 52~77%（实测）。所以 10% 是两个 regime
/// 的分界，不是性能 SLA；最大延迟只作观察量报出来。
#[cfg(not(feature = "fault-resched-ipi"))]
fn t_cross_cpu_wait() -> bool {
    let (n, aps) = smp::participant_slots();
    for &s in &aps[..n] {
        WWC_COUNT[s].store(0, Ordering::Relaxed);
        WWC_DONE[s].store(0, Ordering::Relaxed);
        WWC_ERR[s].store(0, Ordering::Relaxed);
    }
    WWC_MAXLAT.store(0, Ordering::Relaxed);
    WWC_SLOW.store(0, Ordering::Relaxed);
    WWC_STALLED.store(0, Ordering::Relaxed);
    let ipi0 = apic::resched_ipi_received() as u64;
    let ack = match smp::run_ap_role(wwc_consumer, wwc_producer) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("跨核等待: 测不成 {:?}", e);
            return false;
        }
    };
    let ipi = apic::resched_ipi_received() as u64 - ipi0;
    let Some(q) = sync::wait_queue(WWC_QID) else { return false };
    let (blocks, wakes, empty, left) = q.stats();
    let mut errors = 0u64;
    let mut all_consumed = true;
    for &s in &aps[..n] {
        errors += WWC_ERR[s].load(Ordering::Relaxed);
        if WWC_DONE[s].load(Ordering::Acquire) < WWC_ROUNDS {
            all_consumed = false;
        }
    }
    let stalled = WWC_STALLED.load(Ordering::Relaxed) != 0;
    let slow = WWC_SLOW.load(Ordering::Relaxed);
    crate::log_info!(
        "跨核等待(ADR-056): 参与={} 轮={} 全消费={} 卡住={} 错误={} blocks={} wakes={} empty={} 链上={} 最大延迟={} 上界={} 慢轮={} 收到IPI={} ack超时={}",
        WWC_PARTS.load(Ordering::Relaxed), WWC_ROUNDS, all_consumed, stalled, errors,
        blocks, wakes, empty, left, WWC_MAXLAT.load(Ordering::Relaxed),
        WWC_BOUND.load(Ordering::Relaxed), slow, ipi, ack);
    !stalled && all_consumed && errors == 0 && left == 0
        && blocks == wakes && blocks > 0
        && slow * 10 <= WWC_ROUNDS && ipi > 0 && ack == 0
}
#[cfg(not(feature = "fault-resched-ipi"))]
ktest!(KT_CROSS_CPU_WAIT, t_cross_cpu_wait);

// ---- 欠账⑦（ADR-062）：resched IPI 失败不丢唤醒。只在 fault-resched-ipi 构建里注册 ----
// 健康 QEMU 上 IPI 从不失败，resched_ipi_fail() 恒 0；这条构建强制它失败，证明计数会咬，
// 且失败之后目标任务靠自己的 tick 仍被选上（"失败不丢唤醒"那条安全不变量）。
#[cfg(feature = "fault-resched-ipi")]
const RIF_QID: u8 = 5;
#[cfg(feature = "fault-resched-ipi")]
static RIF_FLAG: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "fault-resched-ipi")]
static RIF_DONE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "fault-resched-ipi")]
static RIF_TASK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// AP 侧消费者：真的阻塞一次，被唤醒后置 DONE。角色跑在 AP 的空闲上下文里，
/// 所以**不能** `finish_current`（与 wwc_consumer 同一理由：空闲上下文不退出）。
#[cfg(feature = "fault-resched-ipi")]
fn rif_consumer() {
    let Some(q) = sync::wait_queue(RIF_QID) else { return };
    RIF_TASK.store(sched::current_id() as u64, Ordering::Release);
    match q.wait_while(RIF_QID, || RIF_FLAG.load(Ordering::Acquire) != 0) {
        Ok(_) => { RIF_DONE.store(1, Ordering::Release); }
        Err(_) => { RIF_DONE.store(u64::MAX, Ordering::Release); }
    }
}

/// BSP 侧观察者：等消费者**真的阻塞了**再置位并 wake_all。注入下这次 wake 的 IPI 必失败，
/// 但消费者已是 Runnable，靠它自己的下一次 tick 仍会跑完。永不阻塞，所以丢唤醒时它能报红。
#[cfg(feature = "fault-resched-ipi")]
fn rif_observer() {
    let t0 = tsc::now();
    while tsc::now().wrapping_sub(t0) < 100_000_000 {
        let task = RIF_TASK.load(Ordering::Acquire);
        if task != u64::MAX && matches!(sched::state_of(task as usize), sched::TaskState::Blocked(_)) {
            break;
        }
        tsc::spin(2_000);
    }
    RIF_FLAG.store(1, Ordering::Release);
    if let Some(q) = sync::wait_queue(RIF_QID) {
        let _ = q.wake_all();
    }
}

/// 四格：ack 不超时、消费者真的跑完（DONE==1，不是错误标记）、失败计数涨了、收到的 IPI 为 0。
/// `fail > fail0` 是"计数会咬"的直接见证；`received == 0` 证明注入确实把 IPI 打掉了；
/// `done` 证明**没丢唤醒**。三者缺一，这条判据就退化成"看起来绿"。
#[cfg(feature = "fault-resched-ipi")]
fn t_resched_ipi_fail_fallback() -> bool {
    RIF_FLAG.store(0, Ordering::Relaxed);
    RIF_DONE.store(0, Ordering::Relaxed);
    RIF_TASK.store(u64::MAX, Ordering::Relaxed);
    let fail0 = sched::resched_ipi_fail();
    let ipi0 = apic::resched_ipi_received() as u64;
    let ack = match smp::run_ap_role(rif_consumer, rif_observer) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("resched IPI 失败注入: 测不成 {:?}", e);
            return false;
        }
    };
    let fail = sched::resched_ipi_fail();
    let received = apic::resched_ipi_received() as u64 - ipi0;
    let done = RIF_DONE.load(Ordering::Acquire);
    crate::log_info!(
        "resched IPI失败注入(ADR-062): ack超时={} 完成={} 失败计数 {}->{} 收到IPI={}",
        ack, done, fail0, fail, received);
    ack == 0 && done == 1 && fail > fail0 && received == 0
}
#[cfg(feature = "fault-resched-ipi")]
ktest!(KT_RESCHED_IPI_FAIL, t_resched_ipi_fail_fallback);

// ---- P5：把 BSP 的 idle 真的逼出来跑一次 hlt，并证明 IPI 能叫醒它 ----
const P5_QID: u8 = 2;
static P5_FLAG: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static P5_BLOCKER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
static P5_AP_SAW: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static P5_H0: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// AP 侧：等 BSP 那个任务**真的阻塞了**再置位并唤醒。
/// 不等就唤醒的话，BSP 查条件时已成立、根本不阻塞，idle 也就不会被逼出来（那就白测了）。
fn p5_ap_waker() {
    // `run_ap_role` 先收齐 ENTERED 才跑 BSP 那一份，所以这里必须**有界等**它公布下标；
    // 第一版直接 return，结果 AP 全收工了 BSP 才阻塞 ⇒ 没人唤醒 ⇒ idle hlt 到死（实测 3/3 HANG）。
    let mut b = P5_BLOCKER.load(Ordering::Acquire);
    let tw = tsc::now();
    while b == u64::MAX && tsc::now().wrapping_sub(tw) < 400_000_000 {
        tsc::spin(2_000);
        b = P5_BLOCKER.load(Ordering::Acquire);
    }
    if b == u64::MAX {
        return;
    }
    let bg = b as usize;
    let t0 = tsc::now();
    // 必须等 BSP **真的换了人**（current 不再是阻塞者），而不是只等它标 Blocked。
    // 只等 Blocked 的话，唤醒会赶在 `yield_now` 之前把它改回 Runnable，
    // `pick_next` 看到 prev 还活着就返回 prev ⇒ 根本不切走 ⇒ idle 永远跑不到
    // （实测：回落分支 0 次命中、bsp_hlt 0->0）。那是 ADR-053"放锁后切走"窗口的
    // **正确行为**（不丢唤醒），所以要用例去适配它，不是改内核。
    // 等 idle **真的执行到 hlt**（计数在 hlt 前一步自增），不是只等"current 换了人"。
    // `s.current = next` 写在 `context_load` 之前，所以"换了人"那一刻 idle 可能还没跑；
    // 此时发 IPI，它会在 idle 刚 `sti` 时立刻被取走，idle 连第一条 hlt 都执行不到
    // （实测：idle_runs=1 而 bsp_hlt=0）。等计数前进才是"它已经停在 hlt 上"的证人。
    let _ = bg;
    while sched::idle_hlt_count(cpu::BSP_SLOT) <= P5_H0.load(Ordering::Acquire)
        && tsc::now().wrapping_sub(t0) < 400_000_000
    {
        tsc::spin(2_000);
    }
    if sched::idle_hlt_count(cpu::BSP_SLOT) > P5_H0.load(Ordering::Acquire) {
        P5_AP_SAW.fetch_add(1, Ordering::Relaxed);
    }
    P5_FLAG.store(1, Ordering::Release);
    if let Some(q) = sync::wait_queue(P5_QID) {
        let _ = q.wake_all();
    }
}

/// BSP 侧：阻塞。此刻本 CPU 上除了 idle 没有别的可运行任务（下面清过场），
/// 所以 `pick_next` 只能回落到 idle ⇒ idle 进 hlt ⇒ AP 的跨核唤醒发 IPI 把它叫醒。
fn p5_bsp_blocker() {
    P5_BLOCKER.store(sched::current_id() as u64, Ordering::Release);
    if let Some(q) = sync::wait_queue(P5_QID) {
        let _ = q.wait_while(P5_QID, || P5_FLAG.load(Ordering::Acquire) != 0);
    }
}

/// P5：BSP idle 的 hlt 路径**必须被执行到**，否则那段转换等于没验。
/// 判据：清场后 BSP 只剩 idle 可跑 ⇒ `idle_hlt_count(BSP)` 必须前进；
/// AP 确实看到了阻塞态（`P5_AP_SAW>0`）；启动上下文被跨核唤醒后回来了（flag 生效）。
#[cfg(not(feature = "fault-resched-ipi"))]
fn t_idle_hlt_wakes() -> bool {
    if sched::state_of(0) == sched::TaskState::Free {
        sched::init_boot_task();
    }
    let boot = sched::current_id();
    // 清场：本 CPU 上除启动上下文与 idle 以外全部收掉，否则 pick_next 选不到 idle
    for i in 0..sched::MAX_TASKS_TOTAL {
        if i == boot || sched::cpu_of(i) != cpu::BSP_SLOT || i == sched::idle_of(cpu::BSP_SLOT) {
            continue;
        }
        if sched::state_of(i) != sched::TaskState::Free {
            if let Some(q) = sync::wait_queue(P5_QID) {
                let _ = q.remove_task(i);
            }
            let _ = sched::terminate_task(i);
        }
    }
    P5_FLAG.store(0, Ordering::Relaxed);
    P5_AP_SAW.store(0, Ordering::Relaxed);
    P5_BLOCKER.store(u64::MAX, Ordering::Relaxed);
    let h0 = sched::idle_hlt_count(cpu::BSP_SLOT);
    P5_H0.store(h0, Ordering::Release);
    let ack = match smp::run_ap_role(p5_ap_waker, p5_bsp_blocker) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("idle hlt: 测不成 {:?}", e);
            return false;
        }
    };
    let h1 = sched::idle_hlt_count(cpu::BSP_SLOT);
    let saw = P5_AP_SAW.load(Ordering::Relaxed);
    let woke = P5_FLAG.load(Ordering::Acquire) != 0;
    crate::log_info!(
        "idle hlt(P5): bsp_hlt {} -> {} idle_runs={} idle_state={:?} AP见到换人={} 被唤醒={} ack超时={}",
        h0, h1, sched::runs_of(sched::idle_of(cpu::BSP_SLOT)),
        sched::state_of(sched::idle_of(cpu::BSP_SLOT)), saw, woke, ack);
    // 同样要上界：真 hlt 时增量是 1（停一次、被 IPI 叫醒一次），退回自旋版实测是 133。
    // 只判 `h1 > h0` 量的是"idle 跑过"，不是"idle 真的停住了"。
    h1 > h0 && h1 - h0 <= 4 && saw > 0 && woke && ack == 0
}
#[cfg(not(feature = "fault-resched-ipi"))]
ktest!(KT_IDLE_HLT_WAKES, t_idle_hlt_wakes);

// ---- P6：sleep_until 的精度判据，BSP 与 AP 各一档 ----
static P6_AP_ELAPSED: [core::sync::atomic::AtomicU64; cpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; cpu::MAX_CPUS];
static P6_AP_OK: [core::sync::atomic::AtomicU64; cpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; cpu::MAX_CPUS];
static P6_D: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// §201 **零串口探针**：`t_sleep_until` 的探测读数写在这里，挂死时由宿主机 QMP 读回。
/// 为什么不用 `log_info!`：§200 实测带串口诊断 80 跑 0 挂、无诊断 50 跑 2 挂（4%），
/// 往串口加行本身疑似把现象压掉了（Fisher p≈0.146，嫌疑未证）。改成静态量后**两臂代码相同**，
/// 扰动只剩几条 store，也不必备条件化符号表。槽位含义（宿主机仪器按同一份注释解）：
/// 0=tick_in 1=got 2=cycles 3=rounds 4=was_running 5=进来时 rte2 低 DWORD
/// 6=有没有调 timer_start 7=调了是否 Ok 8=调完 rte2 低 DWORD 9=本用例被进入过几次
/// rte2 读不到时存 u64::MAX（与" masked 位"区分开，不拿 0 冒充读数）。
static SLEEP_PROBE: [core::sync::atomic::AtomicU64; 10] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 10];

fn rte_lo() -> u64 {
    apic::rte_raw(2).map_or(u64::MAX, |(lo, _)| u64::from(lo))
}


/// AP 档：在自己的 CPU 上睡同样长，量自己的 elapsed（tick 源是本地 LAPIC，不是 BSP 的 PIT）
fn p6_ap_sleeper() {
    let slot = cpu::self_slot();
    let d = P6_D.load(Ordering::Acquire);
    let t0 = tsc::now();
    let ok = sched::sleep_until(t0.wrapping_add(d));
    P6_AP_ELAPSED[slot].store(tsc::now().wrapping_sub(t0), Ordering::Release);
    P6_AP_OK[slot].store(if ok { 1 } else { 0 }, Ordering::Release);
}

fn p6_bsp_noop() {}

/// P6（ADR-058）：`sleep_until` 必须落在 `[d, d+2 tick]`，**tick 按被睡 CPU 自己的源计**。
/// BSP 的 tick 来自 PIT→IOAPIC 向量 32，AP 来自本地 LAPIC 0xF1，两本账不许混
/// （`watchdog.rs` 的既有口径）。所以这里 BSP 与 AP **各测一档**，不是一个数糊过去。
/// 另外三格：确实由定时器叫醒（返回 true）、`fired` 前进、轮上无残留项。
fn t_sleep_until() -> bool {
    SLEEP_PROBE[5].store(rte_lo(), Ordering::Relaxed);
    if sched::state_of(0) == sched::TaskState::Free {
        sched::init_boot_task();
    }
    // tick 周期用标定值；没标定就用保守上界（与 clock 的既有口径一致）
    let tick = clock::current().map_or_else(clock::max_tick_period_cycles, |c| c.tick_period_cycles);
    let d = tick * 2;
    P6_D.store(d, Ordering::Release);
    // 用例自足：轮靠 tick 扫，而 .ktests 顺序由链接器定，前面的用例可能把表停了
    // （实测不保证就直接 HANG 3/3）。先量进来时心跳有没有在走，不在走就开表，收尾按原样放回。
    let tick_in = apic::ticks();
    let probe = apic::wait_ticks(tick_in, 2, clock::window_cycles(2));
    let was_running = probe.ticks >= 2;
    // §201：读数进静态量，**不往串口加行**（理由见 SLEEP_PROBE 头注释）。
    SLEEP_PROBE[0].store(tick_in as u64, Ordering::Relaxed);
    SLEEP_PROBE[1].store(probe.ticks, Ordering::Relaxed);
    SLEEP_PROBE[2].store(probe.cycles, Ordering::Relaxed);
    SLEEP_PROBE[3].store(probe.rounds, Ordering::Relaxed);
    SLEEP_PROBE[4].store(u64::from(was_running), Ordering::Relaxed);
    SLEEP_PROBE[9].fetch_add(1, Ordering::Relaxed);
    if !was_running {
        let r = apic::timer_start();
        SLEEP_PROBE[6].store(1, Ordering::Relaxed);
        SLEEP_PROBE[7].store(u64::from(r.is_ok()), Ordering::Relaxed);
        SLEEP_PROBE[8].store(rte_lo(), Ordering::Relaxed);
    }
    let (reg0, fired0, _) = sched::timer_stats(cpu::BSP_SLOT);
    let t0 = tsc::now();
    let bsp_ok = sched::sleep_until(t0.wrapping_add(d));
    let bsp_el = tsc::now().wrapping_sub(t0);
    let (reg1, fired1, pend) = sched::timer_stats(cpu::BSP_SLOT);
    // AP 档
    let (n, aps) = smp::participant_slots();
    for &s in &aps[..n] {
        P6_AP_ELAPSED[s].store(0, Ordering::Relaxed);
        P6_AP_OK[s].store(0, Ordering::Relaxed);
    }
    let ack = smp::run_ap_role(p6_ap_sleeper, p6_bsp_noop);
    let mut ap_ok = n > 0;
    let mut ap_min = u64::MAX;
    let mut ap_max = 0u64;
    for &s in &aps[..n] {
        let e = P6_AP_ELAPSED[s].load(Ordering::Acquire);
        if e < ap_min { ap_min = e; }
        if e > ap_max { ap_max = e; }
        if P6_AP_OK[s].load(Ordering::Acquire) != 1 || e < d || e > d + 2 * tick {
            ap_ok = false;
        }
    }
    if !was_running {
        apic::timer_stop().ok();
    }
    crate::log_info!(
        "sleep(P6): tick={} d={} BSP elapsed={} ok={} registered {}->{} fired {}->{} 残留={} AP档={} min={} max={} ack={:?}",
        tick, d, bsp_el, bsp_ok, reg0, reg1, fired0, fired1, pend, ap_ok, ap_min, ap_max, ack);
    bsp_ok && bsp_el >= d && bsp_el <= d + 2 * tick
        && fired1 > fired0 && reg1 > reg0 && pend == 0
        && ap_ok && ack.is_ok()
}
ktest!(KT_SLEEP_UNTIL, t_sleep_until);

// ---- P6b：带时限的条件等待 ----
const P6B_QID: u8 = 3;
static P6B_FLAG: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static P6B_BOOT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// 场景2 的唤醒者：等启动上下文**真的阻塞了**再置位并 wake_all（赶在它让出之前唤醒的话，
/// 它查条件就成立、根本不阻塞，那测不到"条件唤醒后取消轮项"这条）。
fn p6b_waker() -> ! {
    let b = P6B_BOOT.load(Ordering::Acquire);
    if b != u64::MAX {
        let bg = b as usize;
        let t0 = tsc::now();
        while !matches!(sched::state_of(bg), sched::TaskState::Blocked(_))
            && tsc::now().wrapping_sub(t0) < 100_000_000
        {
            tsc::spin(2_000);
        }
        P6B_FLAG.store(1, Ordering::Release);
        if let Some(q) = sync::wait_queue(P6B_QID) {
            let _ = q.wake_all();
        }
    }
    sched::finish_current();
    loop {
        tsc::spin(3_000);
    }
}

/// P6b（ADR-058 决策 5/6）：带时限等待的两种结局都必须对。
///
/// 场景1：条件永不成立 ⇒ 必须 `TimedOut`，且 elapsed 落在 `[d, d+2 tick]`（与 sleep 同一口径）。
/// 场景2：条件先成立 ⇒ 必须 `Condition`，且**轮项被取消**（残留=0）——不取消的话它会占着槽
/// 一直到 deadline，槽满时后来者就睡不了。另判 `fired` 前进（场景1 真的由定时器叫醒）。
fn t_wait_timeout() -> bool {
    if sched::state_of(0) == sched::TaskState::Free {
        sched::init_boot_task();
    }
    let tick = clock::current().map_or_else(clock::max_tick_period_cycles, |c| c.tick_period_cycles);
    let d = tick * 2;
    // 用例自足于时钟状态（与 t_sleep_until 同一理由：链接顺序可能让前面的用例停过表）
    let tick_in = apic::ticks();
    let probe = apic::wait_ticks(tick_in, 2, clock::window_cycles(2));
    let was_running = probe.ticks >= 2;
    if !was_running {
        apic::timer_start().ok();
    }
    let Some(q) = sync::wait_queue(P6B_QID) else {
        crate::log_fatal!("wait 时限: 队列取不到");
        return false;
    };
    let (_, f0, _) = sched::timer_stats(cpu::BSP_SLOT);
    // 场景1：条件永不成立
    P6B_FLAG.store(0, Ordering::Relaxed);
    P6B_BOOT.store(u64::MAX, Ordering::Relaxed);
    let t0 = tsc::now();
    let r1 = q.wait_while_until(P6B_QID, || P6B_FLAG.load(Ordering::Acquire) != 0, t0.wrapping_add(d));
    let e1 = tsc::now().wrapping_sub(t0);
    // 场景2：条件先成立
    P6B_FLAG.store(0, Ordering::Relaxed);
    P6B_BOOT.store(sched::current_id() as u64, Ordering::Release);
    let w = match sched::spawn(p6b_waker) {
        Ok(i) => i,
        Err(e) => {
            crate::log_fatal!("wait 时限: 唤醒者 spawn 失败 {:?}", e);
            return false;
        }
    };
    let t1 = tsc::now();
    let r2 = q.wait_while_until(P6B_QID, || P6B_FLAG.load(Ordering::Acquire) != 0, t1.wrapping_add(d * 4));
    let e2 = tsc::now().wrapping_sub(t1);
    let (_, f1, pend) = sched::timer_stats(cpu::BSP_SLOT);
    let _ = q.remove_task(w);
    let _ = sched::terminate_task(w);
    if !was_running {
        apic::timer_stop().ok();
    }
    crate::log_info!(
        "wait 时限(P6b): d={} 场景1={:?} elapsed={} 场景2={:?} elapsed={} fired {}->{} 残留={}",
        d, r1, e1, r2, e2, f0, f1, pend);
    matches!(r1, Ok(sync::WaitOutcome::TimedOut)) && e1 >= d && e1 <= d + 2 * tick
        && matches!(r2, Ok(sync::WaitOutcome::Condition)) && e2 < d * 4
        && f1 > f0 && pend == 0
}
ktest!(KT_WAIT_TIMEOUT, t_wait_timeout);

const P7B_QID: u8 = 4;
const P7B_ROUNDS: usize = 6;
static P7B_FLAG: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// 一直阻塞到被人杀掉的工人：条件永不成立，deadline 取 20 个 tick 之后。
/// 这样它同时占着**一个等待槽**和**一个轮项**——两份注册都要有人收。
/// deadline 不用"远在未来"：被杀之后那两份注册就是**孤儿**（槽已 Free，`wake_task` 拒绝唤醒），
/// 修复前没有任何公开接口能取消它们。取有界的 deadline，让轮自己到期把槽放开，
/// 红的那一跑才能把残留收干净、不连坐后面的用例。20 tick 远大于本用例一轮的耗时。
fn p7b_blocked_worker() -> ! {
    if let Some(q) = sync::wait_queue(P7B_QID) {
        let tick = clock::current().map_or_else(clock::max_tick_period_cycles, |c| c.tick_period_cycles);
        let _ = q.wait_while_until(P7B_QID, || P7B_FLAG.load(Ordering::Acquire) != 0, tsc::now().wrapping_add(tick * 20));
    }
    sched::finish_current();
    loop {
        tsc::spin(3_000);
    }
}

/// P7b（欠账⑥）：杀掉一个**正阻塞着**的内核工人，它占的两份注册必须一起消失。
///
/// 为什么这条值得单独一格：`terminate_task` 原来只改任务槽（标 Free），
/// 等待链上的 waiter 与定时器轮里的项都不动。任务槽会被 `spawn` 复用，而那两份注册
/// 认的是**槽下标**，于是它们永久占着槽：等待队列 16 格、轮 64 格，杀够次数就再也等不了。
/// 三条判据分开数，红的时候能指出漏的是哪一份：
/// ①`blocked_ok` 是**防空转**格——工人必须真的到过 `Blocked` 且两份注册都涨了一格，
///   否则"杀完残留=0"可能只是因为它压根没注册；
/// ②每轮杀完等待链回到基线；③每轮杀完轮项回到基线。
/// 收尾把还阻塞着的工人叫醒再终止：红的那一跑（修复前）也不许把残留留给后面的用例。
fn t_kill_blocked_cleans_registrations() -> bool {
    if sched::state_of(0) == sched::TaskState::Free {
        sched::init_boot_task();
    }
    let Some(q) = sync::wait_queue(P7B_QID) else {
        crate::log_fatal!("杀阻塞工人: 队列取不到");
        return false;
    };
    let bsp = cpu::BSP_SLOT;
    // 用例自足于时钟状态（与 t_wait_timeout 同一理由：链接顺序可能让前面的用例停过表）。
    // 收尾要靠在跑的用例被 tick 换回来，表停了那一步就永远等不到。
    let tick_in = apic::ticks();
    let probe = apic::wait_ticks(tick_in, 2, clock::window_cycles(2));
    let was_running = probe.ticks >= 2;
    if !was_running {
        apic::timer_start().ok();
    }
    P7B_FLAG.store(0, Ordering::Relaxed);
    let (_, _, _, q0) = q.stats();
    let (_, _, t0) = sched::timer_stats(bsp);
    let mut blocked_ok = 0usize;
    let mut q_leaks = 0usize;
    let mut t_leaks = 0usize;
    let mut spawned: [usize; P7B_ROUNDS] = [usize::MAX; P7B_ROUNDS];
    for round in 0..P7B_ROUNDS {
        let w = match sched::spawn(p7b_blocked_worker) {
            Ok(i) => i,
            Err(e) => {
                crate::log_fatal!("杀阻塞工人: 第 {} 轮 spawn 失败 {:?}", round, e);
                break;
            }
        };
        spawned[round] = w;
        // 先让工人上去阻塞：不让这一次，它还没注册就被杀，判据会变成空转
        let mut n = 0usize;
        loop {
            sched::yield_now();
            let (_, _, _, qd) = q.stats();
            let (_, _, td) = sched::timer_stats(bsp);
            if matches!(sched::state_of(w), sched::TaskState::Blocked(_)) && qd == q0 + 1 && td == t0 + 1 {
                blocked_ok += 1;
                break;
            }
            n += 1;
            if n >= 200 { break; }
        }
        let _ = sched::terminate_task(w);
        let (_, _, _, qd) = q.stats();
        let (_, _, td) = sched::timer_stats(bsp);
        if qd != q0 { q_leaks += 1; }
        if td != t0 { t_leaks += 1; }
    }
    let (_, _, _, q_left) = q.stats();
    let (_, _, t_left) = sched::timer_stats(bsp);
    // 收尾：被杀之后那两份注册是孤儿——槽已 Free，`wake_task` 拒绝唤醒，所以既叫不醒、
    // 也没法让工人自己跑回来取消。等待链用 `remove_task` 逐个摘（它只认槽下标）；
    // 轮项没有公开取消接口，靠 20 tick 的 deadline 自己到期放开（`wheel_tick` 无条件清 used）。
    // 前面三版都在这里绕：wake 完就 terminate（工人没机会跑）、按 state_of 等（槽已 Free，
    // 条件当场成立）、按轮项数配 yield 等（孤儿项不会因 wake 消失，等到最后整机挂死）。
    // 现在不做任何 yield：红的那一跑留给后面用例的轮项会在 200 ms 内自己到期。
    for w in spawned {
        if w != usize::MAX {
            let _ = q.remove_task(w);
        }
    }
    let (_, _, _, q_end) = q.stats();
    let (_, _, t_end) = sched::timer_stats(bsp);
    // 进来时表是停的就停回去——**但只在没有残留的时候**。修复前那一跑留着 6 个孤儿轮项，
    // 停表等于让它们永远占着槽（后面 t_wait_timeout 的"残留=0"会被连坐）。
    // 留着表跑，它们 20 tick 之后自己到期；这是用例自足与不污染之间唯一能两头都顾的写法。
    if !was_running && t_end == t0 {
        apic::timer_stop().ok();
    }
    crate::log_info!(
        "杀阻塞工人(P7b): rounds={} 真阻塞过={} 等待链残留 {}->{} 轮项残留 {}->{} 漏链轮数={} 漏轮项轮数={} 收尾后 链={} 轮={}",
        P7B_ROUNDS, blocked_ok, q0, q_left, t0, t_left, q_leaks, t_leaks, q_end, t_end);
    blocked_ok == P7B_ROUNDS && q_leaks == 0 && t_leaks == 0
}
ktest!(KT_KILL_BLOCKED, t_kill_blocked_cleans_registrations);

/// `if_patch` 两条分支的直接覆盖，以及 asm 偏移与 Rust 结构体的对账。
///
/// 为什么这条用例存在：ADR-021 的"关着窗口换入"分支今天**没有触发源**
/// （所有换入都发生在开窗口的窗口之内，见上一条用例里 `loads_closed=0` 那段说明）。
/// 写好了却没走过的代码不能算验证过，但也不该为了凑覆盖去伪造一次调度。
/// 解法是把那段位操作从 `context_load` 里拆成一个可调用的例程，用例走**同一条指令序列**：
/// 1. `TrapFrame::rflags` 的偏移必须等于 asm 里写死的 160 —— 这条接缝没有类型系统保护；
/// 2. 置位/清位只能动 bit9，其余 22 个字与 rflags 里其它位（这里是 bit63）都不许变。
///    第 2 条就是当年 `and qword ptr [rsp+160], 0xfffffdff` 那一类掩码/符号扩展错误会被抓住的形状。
fn t_if_patch_both_branches() -> bool {
    let off = {
        let f = core::mem::MaybeUninit::<trap::TrapFrame>::zeroed();
        let base = f.as_ptr() as u64;
        // SAFETY: 只取字段地址，不读未初始化的值（zeroed 的 MaybeUninit 每个字节都是 0）
        unsafe { core::ptr::addr_of!((*f.as_ptr()).rflags) as u64 - base }
    };
    let size_ok = core::mem::size_of::<trap::TrapFrame>() == 23 * 8;
    let mut words = [0u64; 23];
    for (i, w) in words.iter_mut().enumerate() {
        *w = 0x1000 + i as u64;
    }
    // bit63 置起来：清位那条分支如果写成 imm32 符号扩展错，这一位最容易先被抹掉
    words[20] = 0x8000_0000_0000_0002;
    // SAFETY: words 是本用例自己的 23 个 u64，if_patch 只写 [ptr+160] 这一格
    unsafe { sched::if_patch(words.as_mut_ptr() as u64, 1) };
    let opened = words[20];
    // SAFETY: 同上
    unsafe { sched::if_patch(words.as_mut_ptr() as u64, 0) };
    let closed = words[20];
    // 另外还要确认"置位"这条分支幂等，且不会顺手清掉别的位
    words[20] = 0x8000_0000_0000_0202;
    // SAFETY: 同上
    unsafe { sched::if_patch(words.as_mut_ptr() as u64, 1) };
    let idempotent = words[20];
    let untouched = words
        .iter()
        .enumerate()
        .all(|(i, &v)| i == 20 || v == 0x1000 + i as u64);
    crate::log_info!(
        "if_patch: rflags_off={} (asm 写死 160) size_ok={} opened={:#x} closed={:#x} idempotent={:#x} others_untouched={}",
        off, size_ok, opened, closed, idempotent, untouched
    );
    off == 160
        && size_ok
        && opened == 0x8000_0000_0000_0202
        && closed == 0x8000_0000_0000_0002
        && idempotent == 0x8000_0000_0000_0202
        && untouched
}
ktest!(KT_IF_PATCH, t_if_patch_both_branches);

/// 跨 CPU 抢同一把锁。这条用例的**全部价值**在于它自带对照组：
/// 同一个共享数据、同样的"读—磨—写"，无锁那一轮必须**丢数**，加锁那一轮必须**不丢**。
/// 如果无锁那轮也丢 0，说明两个 CPU 根本没撞上，那"锁挡住了竞争"这句话就没有证据——
/// 所以 `wait_events > 0` 和 `unlocked_lost > 0` 两条都是判据，不是装饰。
fn t_cross_cpu_lock_contention() -> bool {
    let o = match smp::contention_round() {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("contention: 测不成 {:?}", e);
            return false;
        }
    };
    let st = sync::stats();
    crate::log_info!(
        "contention: participants={} rounds_per_cpu={} unlocked_lost={} locked_lost={} wait_events={} wait_max={}",
        o.participants, o.rounds_per_cpu, o.unlocked_lost, o.locked_lost, o.wait_events, o.wait_max_cycles
    );
    crate::log_info!(
        "contention lockdep: acquires={} order_violations={} reentrant_hits={} ack_timeouts={}",
        st.acquires, st.order_violations, st.reentrant_hits, o.ack_timeouts
    );
    // 每 CPU 4000 次自增，丢数比例报出来才有可比性（全丢和丢 1 个是两件事）
    let total = o.participants as u64 * o.rounds_per_cpu;
    let loss_bps = if total > 0 { o.unlocked_lost * 10_000 / total } else { 0 };
    crate::log_info!(
        "contention: 无锁丢数 {} / {} = {} bp（这条数字是尺子能分辨的证据）",
        o.unlocked_lost, total, loss_bps
    );
    // 这里**不**停 AP：停机放在所有用例跑完之后（见 after_switch）。
    // 停在这里的话，链接顺序在后面的那条 AP 用例就会看到"tick 不再增长"，
    // 于是同一条用例在两种顺序下给出两种结论——那属于"只有跑的时候才知道顺序错了"的那类故障。
    o.unlocked_lost > 0 && o.locked_lost == 0 && o.wait_events > 0 && o.ack_timeouts == 0
        && st.order_violations == 0 && st.reentrant_hits == 0 && st.wait_timeouts == 0
}
ktest!(KT_CONTENTION, t_cross_cpu_lock_contention);

/// AP 入口 ABI：asm 按 `ApBoot` 的 +0/+8/+16 读三个 u64，而 `size_of` 的编译期断言
/// 只钉住总大小。这里再钉住**内容**：槽位号与登记一致、期望 id 与登记表一致、
/// 栈顶落在一条已映射的页上（它下面那一页是 guard，永远不该映射）。
/// 这条用例存在的理由：AP 的入口例程一旦拿错栈或拿错槽位，表现是三重故障或
/// 跑进别人的栈，两者都没有可读的错误信息。
fn t_ap_boot_abi() -> bool {
    if let Err(e) = smp::bringup() {
        crate::log_fatal!("smp: bringup 失败（本用例无法验证多核）{:?}", e);
        return false;
    }
    let mut checked = 0usize;
    let mut bad = 0usize;
    for slot in 1..cpu::MAX_CPUS {
        if !cpu::is_registered(slot) {
            continue;
        }
        let (top, got_slot, expect_id) = smp::ap_boot_layout(slot);
        let Some(registered) = cpu::lapic_id_of(slot) else { continue };
        let stack_page = top & !(mm::PAGE as u64 - 1);
        // guard 页在**这条栈的最低那一格**，不是"栈顶下面那一页"——后者仍然是映射着的栈
        let lo = smp::ap_stack_lo(slot);
        let guard_unmapped = lo != 0 && !mm::is_mapped(lo - mm::PAGE as u64);
        let first_mapped = lo != 0 && mm::is_mapped(lo);
        let top_mapped = top != 0 && mm::is_mapped(stack_page);
        if got_slot != slot as u64 || expect_id != registered as u64 || !top_mapped || !first_mapped || !guard_unmapped {
            bad += 1;
            crate::log_fatal!(
                "ap abi: slot={} 写入槽位={} 期望id={:#x} 登记id={:#x} top={:#x} lo={:#x} 栈顶页已映射={} 首映射页={} guard未映射={}",
                slot, got_slot, expect_id, registered, top, lo, top_mapped, first_mapped, guard_unmapped
            );
        }
        checked += 1;
    }
    crate::log_info!("ap abi: checked={} bad={} (size_of::<ApBoot>()={} size_of::<MpInfo>()={})",
        checked, bad, core::mem::size_of::<smp::ApBoot>(), core::mem::size_of::<limine::MpInfo>());
    checked >= 1 && bad == 0
}
ktest!(KT_AP_ABI, t_ap_boot_abi);

/// §6.4 里那句"所有内核栈头尾都有 guard page"的**异常栈**那一半。
/// 每个 CPU 都要过一遍：guard 未映射、访问它故障、栈内第一页已映射且不故障——
/// 四条一起测，否则"访问 guard 故障"可能只是因为整段都没映射（与任务栈那条同一把尺子）。
fn t_exception_stack_guard() -> bool {
    if let Err(e) = smp::bringup() {
        crate::log_fatal!("smp: bringup 失败（本用例无法验证多核）{:?}", e);
        return false;
    }
    let mut checked = 0usize;
    let mut bad = 0usize;
    for slot in 0..cpu::MAX_CPUS {
        let Some(si) = trap::ex_stack_info(slot) else {
            if slot != cpu::BSP_SLOT && cpu::is_registered(slot) {
                crate::log_fatal!("exstack: slot={} 登记了但没有换上带 guard 的异常栈", slot);
                bad += 1;
            }
            continue;
        };
        let guard_unmapped = !mm::is_mapped(si.guard_va);
        let first_mapped = mm::is_mapped(si.stack_lo);
        let guard_faults = trap::probe_page_fault(si.guard_va).is_some();
        let first_faults = trap::probe_page_fault(si.stack_lo).is_some();
        // ist1 必须落在这一段的最后一格，并且 16 字节对齐（IST 的硬件要求）
        let top_ok = si.top > si.stack_lo && si.top <= si.stack_hi && si.top & 0xf == 0;
        if !(guard_unmapped && first_mapped && guard_faults && !first_faults && top_ok) {
            bad += 1;
            crate::log_fatal!(
                "exstack: slot={} guard={:#x} lo={:#x} hi={:#x} ist1={:#x} guard_unmapped={} guard_faults={} first_mapped={} first_faults={} top_ok={}",
                slot, si.guard_va, si.stack_lo, si.stack_hi, si.top,
                guard_unmapped, guard_faults, first_mapped, first_faults, top_ok
            );
        }
        checked += 1;
    }
    crate::log_info!("exstack guard: checked={} bad={}", checked, bad);
    checked >= 1 && bad == 0
}
ktest!(KT_EXSTACK_GUARD, t_exception_stack_guard);

/// §6.6 的 TLB shootdown：解映射之前必须让**每个其它在线 CPU**清掉那一条 VA 并回执。
///
/// 这条用例测的是**协议**，不测"硬件里真的没有旧条目"：QEMU 的 TCG 会因为页表被写
/// 而自行失效相关条目，所以"没通知也能读对"在这台机器上永远成立。
/// 因此判据全部落在可数的东西上：请求次数 == 解掉的页数、每个在线 CPU 的 invlpg 与回执
/// 各自都增长、超时次数为 0、以及帧确实回到 PMM。
/// "没通知也能读对"这件事由 `fault-shootdown-noack` 反过来验：只把回执拿掉，
/// 请求方必须升 L4（判定矩阵第 9 行）。
fn t_tlb_shootdown() -> bool {
    if let Err(e) = smp::bringup() {
        crate::log_fatal!("shootdown: bringup 失败 {:?}", e);
        return false;
    }
    let online = cpu::online_count();
    if online < 2 {
        crate::log_fatal!("shootdown: 只有 {} 个在线 CPU，多核那半没法测", online);
        return false;
    }
    let before = mm::shootdown_stats();
    let free0 = mm::free_frames();
    // 映射 2 页、写一遍（确认这块页真的在用），然后 drop —— 归还 Mapping 会走
    // unmap_pages -> clear_leaf -> shootdown_others，每页一次 IPI 往返
    let win = match mm::alloc_va_range(2) {
        Some(v) => v,
        None => {
            crate::log_fatal!("shootdown: 拿不到 VA");
            return false;
        }
    };
    let frames = match mm::phys_alloc(1, mm::MOD_TEST) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("shootdown: 拿不到 2 连续帧 {:?}", e);
            return false;
        }
    };
    let m = match mm::map(win, frames, mm::PageFlags::RW) {
        Ok(m) => m,
        Err(e) => {
            crate::log_fatal!("shootdown: map 失败 {:?}", e);
            return false;
        }
    };
    // SAFETY: win 是刚映射的 2 页 RW，长度与 phys_alloc(1) 的 2 页一致
    unsafe { core::ptr::write_volatile(win.0 as *mut u64, 0x5a5a_5a5a_5a5a_5a5a) };
    let written = unsafe { core::ptr::read_volatile(win.0 as *const u64) };
    drop(m);
    let after = mm::shootdown_stats();
    let requests = after.requests - before.requests;
    let mut acked_all = true;
    for s in 0..cpu::MAX_CPUS {
        if s == cpu::BSP_SLOT || !cpu::is_online(s) {
            continue;
        }
        // 每个别的在线 CPU 都应当：invlpg 至少 2 次、回执至少比 BSP 自己那一份多
        if after.invlpg[s] - before.invlpg[s] < 2 || after.acks[s] - before.acks[s] < 2 {
            acked_all = false;
        }
    }
    let frames_back = mm::free_frames() >= free0; // 归还了 2 帧（别的用例也可能同时在动，只判不回退）
    crate::log_info!(
        "shootdown: online={} requests={} timeouts={} written={:#x} frames_back={} acks={:?} invlpg={:?}",
        online, requests, after.timeouts - before.timeouts, written, frames_back,
        after.acks, after.invlpg
    );
    requests == 2 && after.timeouts == before.timeouts && acked_all && written == 0x5a5a_5a5a_5a5a_5a5a && frames_back
}
ktest!(KT_SHOOTDOWN, t_tlb_shootdown);

/// 每 CPU 运行队列 + AP 真的在跑自己的调度器。三条判据各挡一种错法：
/// ①AP 自己换过人且它的工人跑过 ⇒ 挡"AP 只是活着但从没被调度"（那 per-CPU 队列就是摆设）；
/// ②每个跑调度的 CPU，其 `current` 必须归属它自己 ⇒ 挡"两个核选中同一个任务"（同一个帧被 iretq 两次）；
/// ③非空任务的 `on_cpu` 必须等于它所在的队列 ⇒ 挡 `gidx/cpu_of/slot_of` 这对新算术写错。
/// 顺带记 `ticks_of(ap)`：AP 的 tick 从这一段起走异常帧路径，所以 tick 数与 P5 样本数一起涨。
fn t_percpu_queues() -> bool {
    if let Err(e) = smp::bringup() {
        crate::log_fatal!("percpu sched: bringup 失败 {:?}", e);
        return false;
    }
    let deadline = 400_000_000;
    let mut checked_aps = 0usize;
    let mut switched_aps = 0usize;
    let mut worked_aps = 0usize;
    let mut halted_aps = 0usize;
    let mut bad_owner = 0usize;
    for ap in 1..cpu::MAX_CPUS {
        if !cpu::runs_sched(ap) {
            continue;
        }
        checked_aps += 1;
        let Some(task) = smp::ap_task_of(ap) else {
            bad_owner += 1; // 队列开闸了却没有工人任务：这条 CPU 只有一个上下文，换不了人
            continue;
        };
        // 等这条 CPU 至少换过两次人（AP 的 tick 目标周期 10 ms，两次换人约 20~30 ms）
        let t0 = tsc::now();
        while sched::stats_of(ap).0 < 2 && tsc::now().wrapping_sub(t0) < deadline {
            core::hint::spin_loop();
        }
        if sched::stats_of(ap).0 >= 2 {
            switched_aps += 1;
        }
        if sched::runs_of(task) >= 1 && sched::WORK[task].load(Ordering::Relaxed) > 0 {
            worked_aps += 1;
        }
        // P5：工人不再常驻自旋，而是 hlt 等中断。这一格证明转换真的发生了——
        // 退回自旋版它会是 0（变异证红）。与 worked_aps 分开：那格证"跑过活"，
        // 这格证"不烧 CPU"，两件事不能混成一个数。
        // 判据必须是**能分辨 regime 的上界**，不是">0"：计数在 hlt 前一步自增，
        // 所以退回自旋版它照样涨（实测第一版两条变异都没咬）。实测分界极干净：
        // hlt 版 ap≈140、ticks≈40（约 3.5 倍）；自旋版 ap≈120000（约 3000 倍）。
        // 32 倍 + 64 是两 regime 的分界，不是性能 SLA。
        let loops = smp::ap_worker_hlt(ap);
        if loops > 0 && loops <= sched::ticks_of(ap) as u64 * 32 + 64 {
            halted_aps += 1;
        }
        // 归属不变量：本 CPU 的 current 必须落在自己的队列里。
        // **不要求它是 Running** —— 这是一次跨核快照读，实测就会读到换人做到一半的样子
        // （`cpu1 的 current=6 归属=1 状态=Runnable`：那条 CPU 上 `preempt_point` 已经把
        // 空闲上下文降级成 Runnable，还没写 `current`）。所以跨核只能断言"归属对不对"，
        // "状态对不对"这条只在**自己读自己**的时候成立，见下面 BSP 那一条。
        let cur = sched::current_of(ap);
        if sched::cpu_of(cur) != ap || sched::state_of(cur) == sched::TaskState::Free {
            bad_owner += 1;
            crate::log_fatal!(
                "percpu sched: cpu{} 的 current={} 归属={} 状态={:?}",
                ap, cur, sched::cpu_of(cur), sched::state_of(cur)
            );
        }
    }
    // BSP 读自己的队列：这里可以要求 Running，因为没有别的可能并发改它
    {
        let cur = sched::current_of(cpu::BSP_SLOT);
        if sched::state_of(cur) != sched::TaskState::Running || sched::cpu_of(cur) != cpu::BSP_SLOT {
            bad_owner += 1;
            crate::log_fatal!(
                "percpu sched: bsp 的 current={} 状态={:?}（自读，应当是 Running 且归属 0）",
                cur, sched::state_of(cur)
            );
        }
    }
    // 所有 CPU 的队列都查一遍归属（含 BSP）
    let mut misfiled = 0usize;
    let mut nonempty = 0usize;
    for i in 0..sched::MAX_TASKS_TOTAL {
        if sched::state_of(i) == sched::TaskState::Free {
            continue;
        }
        nonempty += 1;
        if sched::on_cpu_of(i) != Some(sched::cpu_of(i)) {
            misfiled += 1;
            crate::log_fatal!("percpu sched: 任务 {} 的 on_cpu={:?} 与所在队列 {} 不一致", i, sched::on_cpu_of(i), sched::cpu_of(i));
        }
    }
    crate::log_info!(
        "percpu sched: aps_with_sched={} switched={} worked={} halted={} checked={} bad_owner={} misfiled={} nonempty={}",
        checked_aps, switched_aps, worked_aps, halted_aps, checked_aps, bad_owner, misfiled, nonempty
    );
    crate::log_info!(
        "percpu sched: ticks 每个 CPU ={:?} ; switches 每个 CPU ={:?}",
        [sched::ticks_of(0), sched::ticks_of(1), sched::ticks_of(2), sched::ticks_of(3)],
        [sched::stats_of(0).0, sched::stats_of(1).0, sched::stats_of(2).0, sched::stats_of(3).0]
    );
    checked_aps >= 1 && switched_aps == checked_aps && worked_aps == checked_aps
        && halted_aps == checked_aps && bad_owner == 0 && misfiled == 0 && nonempty >= 1
}
ktest!(KT_PERCPU_QUEUES, t_percpu_queues);


// ---- ADR-073 决策 5（裁决 Q2）：上限不拍数，先按参考 workload 实测 ----
//
// 参考形状 = init + 3 子进程 × 2 线程 ⇒ 4 个进程 / 7 条线程。
// 今天**没有 CPU 迁移**，`spawn_inner` 只往调用者那颗 CPU 的队列里放
// （`sched.rs` 头注释第 2 条），所以量出来的是"单颗 CPU 同时装得下几条活线程"——
// 这正是 `MAX_TASKS` 要回答的那个数。读数来路必须带上这条限制：
// 将来有迁移之后，同一份负载会摊到多颗核上，需求数变小而不是变大。
//
// 五格：①容量真的在管（成功 + 拒绝 = 请求，不是静默丢弃）；②峰值 = 成功数
// （每条成功的线程**同时**活着，不是排队轮到的）；③结局齐全（等待、收尸、回滚三者对得上）；
// ④spawn 失败路径回滚（页框与 VA 保留都回基线——被拒的那几次各发过一段窗口）；
// ⑤收尾（进程/Job 清零、reap 真的发生、活跃任务数回基线）。
// 变异：M5 把满槽的 `ok_or(Unsupported)` 换成静默复用槽 0 ⇒ ①的 refused 变 0 且槽 0 被踩；
// M6 收工处不减线程计数 ⇒ ③的收尸数红；M7 让 proc_discard 也放行已终止的进程 ⇒
// ③"哪些走 reap、哪些走 discard"这条分界红。
static Q2_RELEASE: AtomicUsize = AtomicUsize::new(0);
static Q2_LIVE: AtomicUsize = AtomicUsize::new(0);
static Q2_PEAK_LIVE: AtomicUsize = AtomicUsize::new(0);
static Q2_PEAK_ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// 参考形状里的一条线程：就位、**让出**等发令、有界超时兜底，然后正常收工。
fn q2_worker() -> ! {
    Q2_LIVE.fetch_add(1, Ordering::AcqRel);
    let t0 = tsc::now();
    // 有界：发令丢了也不能永远占着槽（这个上限比用例的采样轮数大一个量级）。
    // 等的时候**自旋**而不是让出：七条线程一起 `int 0xF0` 在挂 `-d int` 的矩阵行里是中断风暴
    // （每条中断都要写宿主机日志，实测烧穿 120 s 预算）。换人交给 tick，时钟由用例自己保证在跑。
    while Q2_RELEASE.load(Ordering::Acquire) == 0
        && tsc::now().wrapping_sub(t0) < 20_000_000_000
    {
        core::hint::spin_loop();
    }
    sched::finish_current();
    // 让出**一次**把 CPU 立刻还给等待方（一条中断，不是风暴）；换不动就靠自旋等 tick。
    sched::yield_now();
    loop {
        tsc::spin(1000);
    }
}

/// 采样：在开着的窗口里**按 tick 逐轮**取样，把"同时活着的工人数"与"可调度任务数"的最大值取回来。
/// 一轮一个 tick：轮转是按 tick 换人的，所以 `线程数+3` 轮足够每条线程被选中一次。
/// 不用 `yield_now` 逐轮换人——工人等发令时是自旋的，让出过去要等满一个 tick 才回得来，
/// 那样每轮都花一个 tick 却只走一格，白等（本轮实测 P4 总量因此涨了 50 %）。
fn q2_sample(rounds: usize) {
    apic::with_interrupts(|| {
        for _ in 0..rounds {
            let b = apic::ticks();
            apic::wait_ticks(b, 1, clock::window_cycles(2));
            let live = Q2_LIVE.load(Ordering::Acquire);
            let active = sched::tasks_active();
            if live > Q2_PEAK_LIVE.load(Ordering::Acquire) {
                Q2_PEAK_LIVE.store(live, Ordering::Release);
            }
            if active > Q2_PEAK_ACTIVE.load(Ordering::Acquire) {
                Q2_PEAK_ACTIVE.store(active, Ordering::Release);
            }
        }
    });
}

fn t_q2_workload_slots() -> bool {
    use crate::ktests::common::drain_reap;
    use crate::proc;
    // 用例自足（与 `t_demand_zero` 同一套）：登记启动上下文与 `RUN` 位必须在**任何 spawn/yield 之前**，
    // 理由与症状见 `t_proc_job_wait` 开头那条同型注释（ahci-scratch 与 fault-resched-ipi 两档实测）。
    sched::init_boot_task();
    sched::start_workers();
    Q2_RELEASE.store(0, Ordering::Relaxed);
    Q2_LIVE.store(0, Ordering::Relaxed);
    Q2_PEAK_LIVE.store(0, Ordering::Relaxed);
    Q2_PEAK_ACTIVE.store(0, Ordering::Relaxed);

    // 前提：表是空的（本用例不假设别的用例收过尾）
    let (pc0, _) = proc::proc_residual();
    let (jc0, _) = proc::job_residual();
    let f0 = mm::free_frames();
    let va0 = mm::reservation_count();
    let rel0 = sched::reap_released();
    // active 的基线里含跑用例的 boot 上下文自己（它也是 Running），所以拿读数对读数
    let act0 = sched::tasks_active();
    // 本 CPU 此刻占着几格：这一格解释"成功数为什么小于请求数"——链接顺序会把别的用例
    // 留下的任务算进来，而 `spawn` 只往调用者这颗 CPU 放（今天没有迁移）。
    let me_cpu = cpu::self_slot();
    let slots_used0 = (0..sched::MAX_TASKS)
        .filter(|&sl| sched::state_of(sched::gidx(me_cpu, sl)) != sched::TaskState::Free)
        .count();
    // 其中"已 Done 但还没被回收"的格数：这一格是 BACKLOG ⑫ 那笔欠账的容量代价——
    // 有效容量 = MAX_TASKS - 先占，而先占里有一部分是收工了却还占着槽的任务。
    let slots_done0 = (0..sched::MAX_TASKS)
        .filter(|&sl| sched::state_of(sched::gidx(me_cpu, sl)) == sched::TaskState::Done)
        .count();
    if pc0 != 0 || jc0 != 0 {
        crate::log_fatal!("q2: 前提失效 残留进程={} Job={}", pc0, jc0);
        return false;
    }

    let job = match proc::job_create(None, 4, 64) {
        Ok(j) => j,
        Err(e) => { crate::log_fatal!("q2: job_create {:?}", e); return false; }
    };
    // init 1 条线程，三个子进程各 2 条
    let shapes = [1usize, 2, 2, 2];
    let total_req: usize = shapes.iter().sum();
    let mut pids = [u16::MAX; 4];
    for (i, slot) in pids.iter_mut().enumerate() {
        *slot = match proc::proc_create(job) {
            Ok(p) => p,
            Err(e) => { crate::log_fatal!("q2: proc_create({}) {:?}", i, e); return false; }
        };
    }

    // 先 spawn、后登记：工人要等发令才收工，不存在"登记之前就跑完"那个窗口
    //（t_proc_job_wait 那边先 attach 的规则针对的是立刻收工的工人，两种顺序各有前提）。
    let mut gids = [usize::MAX; 8];
    let mut proc_with_thread = [false; 4];
    let mut ok_n = 0usize;
    let mut refused = 0usize;
    for (pi, &nthr) in shapes.iter().enumerate() {
        for _ in 0..nthr {
            match sched::spawn(q2_worker) {
                Ok(g) => {
                    let reg = proc::proc_attach_thread(pids[pi]).is_ok() && sched::set_proc_id(g, pids[pi]);
                    if reg {
                        gids[ok_n] = g;
                        ok_n += 1;
                        proc_with_thread[pi] = true;
                    } else {
                        // 登记没成 ⇒ 这条线程不算进任何进程，槽位当场交回去
                        let _ = sched::terminate_task(g);
                        refused += 1;
                    }
                }
                Err(_) => refused += 1,
            }
        }
    }
    let cap_ok = ok_n + refused == total_req;
    // P6c：Done 槽的回收时刻确定之后（`finish_current` 也登记待收），**参考 workload 应当全装得下**。
    // 改前实测 `请求=7 成功=5 拒绝=2 本CPU先占=4(其中Done待收=2)`——那 2 格就是欠账的容量代价。
    // 所以判据从"守恒"（成功+拒绝==请求，欠账时也绿）收紧成"7 条全成功"，
    // 并把 `Done待收` 留在读数里当证人。负样本：把 finish_current 那句登记去掉 ⇒ 本格红。
    let full_ok = ok_n == total_req;

    // 时钟：本条的推进**不靠** tick（工人与采样环都靠让出换人，见 `q2_worker`/`q2_sample`）；
    // 探测一次并自己开关，是为了让后面 `drain_reap` 那一步有 tick 可等——
    // 停表时它退化成"没看到增量"的一句 warn，判据靠 `reap_released` 的增量成立。
    // 有些用例会停掉 LAPIC 定时器再不带回来（`t_demand_zero` 的同一套理由），所以这里探测。
    // 同上第四条：排在标定之前时 `switches` 恒 0，等待必须由 tick 驱动，所以补一次幂等标定。
    if clock::current().is_none() {
        crate::calibrate_clock_once();
    }
    let tick_in = apic::ticks();
    let probe = apic::wait_ticks(tick_in, 2, clock::window_cycles(2));
    let was_running = probe.ticks >= 2;
    if !was_running {
        apic::timer_start().ok();
    }

    // 采样轮数必须容纳"每条活线程至少被选中一次"再加 boot 自己与 idle 的份；
    // 给少了峰值必然偏低，那是量具不成立而不是被测代码。
    q2_sample(ok_n + 3);
    let peak_live = Q2_PEAK_LIVE.load(Ordering::Acquire);
    let peak_active = Q2_PEAK_ACTIVE.load(Ordering::Acquire);
    // active 里含跑用例的 boot 上下文自己（它也是 Running），所以基线用 act0 而不是 1
    let peak_ok = peak_live == ok_n && peak_active == act0 + ok_n && ok_n >= 2;

    // 发令 → 逐条等收工。工人收工后自己让出，所以一次有界等待就够（不等 tick）。
    Q2_RELEASE.store(1, Ordering::Release);
    let mut ended = 0usize;
    for g in gids.iter().take(ok_n) {
        let w = apic::with_interrupts(|| sched::wait_for_task(*g, clock::window_cycles(8)));
        if w {
            ended += 1;
        }
    }
    for g in gids.iter().take(ok_n) {
        let _ = sched::terminate_task(*g);
    }
    // 收尸：起过线程的进程已经是僵尸 ⇒ reap；一条线程都没建成的（槽位不够）⇒ 走回滚那条路。
    // 这两种结局分开数是故意的：**"进程建了但线程起不来"正是 P6 要防的中途失败形状**，
    // 在这里把它撞实，比等到 P6 再发现"额度回不来"便宜。
    let mut reaped = 0usize;
    let mut rolled_back = 0usize;
    for (i, pid) in pids.iter().enumerate() {
        if proc_with_thread[i] {
            if proc::proc_reap(*pid) == Ok(0) {
                reaped += 1;
            }
        } else if proc::proc_discard(*pid).is_ok() {
            rolled_back += 1;
        }
    }
    let done_ok = ended == ok_n && reaped + rolled_back == shapes.len();

    // 先看增量再决定要不要烧窗口，理由同 `t_proc_job_wait` 那条（`-d int` 行的墙钟预算）。
    // P6c：回收变确定之后释放可能早于窗口，所以"全部槽已 Free"也是等价证据
    // （`reap` 先释放资源再标 Free）。逐个看比只看计数稳：计数可能已被别的用例的回收涨过。
    let all_free = (0..ok_n).all(|i| sched::state_of(gids[i]) == sched::TaskState::Free);
    let drained = sched::reap_released() > rel0 || all_free || drain_reap();
    let jd = proc::job_destroy(job);
    let (pc1, _) = proc::proc_residual();
    let (jc1, _) = proc::job_residual();
    let f1 = mm::free_frames();
    let va1 = mm::reservation_count();
    let active1 = sched::tasks_active();
    // drain_reap 要的正是 tick，所以停表放在它之后
    if !was_running {
        apic::timer_stop().ok();
    }
    // ④ 被拒的那几次 spawn 各已经发过一段 VA 窗口和 4 个页框：它们必须原样回来。
    //    这一格本来只是读数，实测 `va23->23 / free 不变` ⇒ 升成判据（去回滚它就红）。
    let rollback_ok = f1 == f0 && va1 == va0;
    // ⑤ 收尾：进程/Job 清零、回收发生、活跃任务数回基线（含别的用例留下的底噪，所以对读数）
    let baseline_ok = drained && jd.is_ok() && pc1 == 0 && jc1 == 0 && active1 == act0;

    crate::log_info!(
        "q2(P3): 请求={} 成功={} 拒绝={} 峰值同活={} active基线={} active峰值={} 收工={} 收尸={} 回滚={} 全装得下={} 每CPU槽上限={} 本CPU先占={}(其中Done待收={}) 参考需线程+boot+idle={} 回基线=(drained{} free{}->{} va{}->{} active{})",
        total_req, ok_n, refused, peak_live, act0, peak_active, ended, reaped, rolled_back,
        full_ok, sched::MAX_TASKS, slots_used0, slots_done0, total_req + 2, drained, f0, f1, va0, va1, active1);
    let ok = cap_ok && full_ok && peak_ok && done_ok && rollback_ok && baseline_ok;
    if !ok {
        crate::log_fatal!(
            "q2: 判据不成立 cap={} full={} peak={} done={} rollback={} baseline={}",
            cap_ok, full_ok, peak_ok, done_ok, rollback_ok, baseline_ok);
    }
    ok
}
ktest!(KT_Q2_WORKLOAD, t_q2_workload_slots);
