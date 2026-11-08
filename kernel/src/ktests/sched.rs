//! 调度、AP 上线、IF 归属与 shootdown 用例（T0.1 纯搬移）。

use crate::arch::x86_64::{apic, cpu, smp, trap};
use crate::{acpi, clock, limine, mm, sched, sync, tsc};
use crate::{mp_snapshot};
use crate::ktest;
use core::sync::atomic::{Ordering};

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
        while (sched::state_of(w1) != sched::TaskState::Done || sched::state_of(w2) != sched::TaskState::Done)
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
    apic::timer_stop().ok();
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
    let resumed = sched::runs_of(w1) >= 1 && sched::runs_of(w2) >= 1;
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
    crate::log_info!(
        "task stack guard: lo={:#x} guarded={} guard_unmapped={} guard_faults={} first_mapped={} first_faults={}",
        lo, guarded, guard_unmapped, guard_faults, first_mapped, first_faults
    );
    guarded && guard_unmapped && guard_faults && first_mapped && !first_faults
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
    apic::timer_stop().ok();
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
    crate::log_info!(
        "if-rule(ADR-021): slot={} runs={} frame_before={:?}(IF={}) frame_after={:?}(IF={}) loads_open={} loads_closed={}",
        slot, runs, before, if_before, after, if_after, loads_open, loads_closed
    );
    crate::log_info!(
        "yield(ADR-049): 关窗口让出 closed {} -> {} 搭档runs={} 自陷计数={} 清残留={} 窗口还原={}",
        closed_before, closed_after, partner_runs, apic::counts().resched, swept,
        apic::interrupts_enabled(cpu::BSP_SLOT));
    // 判据：换入前 IF=0（帧里带的）→ 换入后跑过 ≥2 次且它的现场里 IF=1（CPU 给的）。
    // `loads_closed` 这一格从 P3a 起**有触发源了**：`yield_now` 自陷 0xF0，软件中断不受
    // IF 影响，所以关着窗口也能换人（ADR-049）。原来那句"必然 0、等主动让出时补"
    // 就是在这里补上的：现在要求它真的前进过，且搭档确实被换入过。
    !if_before && runs >= 2 && if_after && loads_open > 0
        && closed_after > closed_before && partner_runs >= 1
}
ktest!(KT_IF_BELONGS_TO_CPU, t_if_belongs_to_cpu);

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
    crate::log_info!(
        "idle(ADR-051): 下标={} 状态={:?} 名下={} active={} 独立重算={} idle_runs {} -> {} 搭档runs={}",
        idle, st, owned, active, recount, runs0, runs1, partner_runs);
    st == sched::TaskState::Runnable && owned == 0 && active == recount
        && runs1 == runs0 && partner_runs >= 1
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
        "percpu sched: aps_with_sched={} switched={} worked={} checked={} bad_owner={} misfiled={} nonempty={}",
        checked_aps, switched_aps, worked_aps, checked_aps, bad_owner, misfiled, nonempty
    );
    crate::log_info!(
        "percpu sched: ticks 每个 CPU ={:?} ; switches 每个 CPU ={:?}",
        [sched::ticks_of(0), sched::ticks_of(1), sched::ticks_of(2), sched::ticks_of(3)],
        [sched::stats_of(0).0, sched::stats_of(1).0, sched::stats_of(2).0, sched::stats_of(3).0]
    );
    checked_aps >= 1 && switched_aps == checked_aps && worked_aps == checked_aps
        && bad_owner == 0 && misfiled == 0 && nonempty >= 1
}
ktest!(KT_PERCPU_QUEUES, t_percpu_queues);

