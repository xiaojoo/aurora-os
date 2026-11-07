//! 用户态往返与任务退出回收用例（T0.1 纯搬移）。

use crate::arch::x86_64::{apic, cpu, trap};
use crate::{acpi, arch, mm, resource, sched, sync, tsc, user};
use crate::ktests::common::{HELLO_ELF, P7_CALLS, drain_reap};
use crate::ktest;
use core::sync::atomic::{Ordering};

/// M4-1 的用户态闭环：进得去、回得来、参数与返回穿得过去、越界只杀这个任务。
/// 它从红到绿拆出的五个缺陷（①–⑤）现场在 BACKLOG 的 M4-1 表里。
/// **本条用例的判据清单（0 / 0b / 0c / 1…6，以及每条各挡一类什么错法）已搬进手册 §12.3.2**；
/// 下面的编号与函数体顺序一致，改判据要同时改那张表。
fn t_user_roundtrip() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("user: APIC 起不来，跑不了时间片");
        return false;
    }
    if user::init().is_err() {
        crate::log_fatal!("user: 建用户镜像失败");
        return false;
    }
    // prog 要在**任何一次 iretq 之前**就读回来：判据 0/0b 靠它拿页号去量生效位。
    let Some(prog) = user::prog() else {
        crate::log_fatal!("user: init 返回了 Ok 但 prog() 读不回来");
        return false;
    };
    sched::init_boot_task();
    // **判据 0：段描述符自检（每台 CPU 都查），跑在任何一次 iretq 之前。**
    // 这条是 M4-1 那次 #GP 直接教出来的：选择子的值(0x1b/0x23)全对，而 GDT 里
    // 用户数据段漏了 S 位(bit4) ⇒ 那条目变成"系统描述符，类型 2 = LDT"，
    // 装 SS 就是非法段 ⇒ #GP；而 QEMU 把错误码的 RPL 两位抹掉，报成 0x18，
    // 现场读起来像"选择子写错了"，指不到真正错的那一位。选择子与描述符是两处独立事实，
    // 只验其一都会漏，所以这里两边都验，并且按**选择子推出来的下标**去查描述符
    //（下标写错与段属性写错都会被同一条判据抓到；而 0x23/0x1b 这两个值是 ADR-025
    // 里 STAR 隐式加 0x20/0x10 的前提，也必须钉住）。
    let (ui, ci) = (trap::udata_sel() >> 3, trap::ucode_sel() >> 3);
    let mut segs_ok = ui == 3 && ci == 4 && trap::udata_sel() & 3 == 3 && trap::ucode_sel() & 3 == 3;
    for slot in 0..crate::arch::x86_64::cpu::registered() {
        let (Some(d), Some(c)) = (trap::gdt_entry(slot, ui as usize), trap::gdt_entry(slot, ci as usize)) else {
            crate::log_fatal!("user: cpu{slot} 读不到 GDT 条目");
            segs_ok = false;
            break;
        };
        let (da, ca) = ((d >> 40) & 0xff, (c >> 40) & 0xff);
        let ok = (da >> 4) & 1 == 1          // S=1：是代码/数据段，不是系统描述符
            && (ca >> 4) & 1 == 1
            && (da >> 7) & 1 == 1            // P=1
            && (ca >> 7) & 1 == 1
            && (da >> 5) & 3 == 3            // DPL=3
            && (ca >> 5) & 3 == 3
            && (da & 0x8) == 0               // 数据段：type 的 E 位为 0
            && (da & 0x2) != 0               //        且可写
            && (ca & 0x8) != 0               // 代码段：可执行
            && (c >> 53) & 1 == 1            // L=1（64 位代码段）
            && (c >> 52) & 1 == 0;           // 而 long mode 下 D/B 必须为 0
        if !ok {
            crate::log_fatal!("user: cpu{slot} 段描述符不对 data={d:#x} code={c:#x}");
            segs_ok = false;
        }
    }
    crate::log_info!(
        "user: segs udata={:#x} ucode={:#x} idx=[{},{}] segs_ok={}",
        trap::udata_sel(), trap::ucode_sel(), ui, ci, segs_ok
    );
    if !segs_ok {
        return false;
    }
    // **判据 0b：页的"生效位"（W^X + SMEP/SMAP 的地基）**。
    // 这里量的是 `mm::effective_flags`（整条页表链逐级相与之后的结果），不是 `PageFlags`
    // 这个意图：M4-1 那次"映射成功但 ring3 一取指就 #PF"就是因为只验意图，
    // 而上级表项的 U/S=0 在叶子里根本看不见。
    // 三条都要成立，缺一不可：
    //   代码页 = 用户可达 + 可执行 + **不可写**；数据/栈页 = 用户可达 + 可写 + **不可执行**；
    //   内核页 = **不可**用户可达（这一条是上一条的对照组：
    //   映射用户页时会把 U/S=1 传到共享的上级表项，没有这条对照就分不清
    //   "放宽了一格"与"放宽了整条内核映射"）。
    let (Some(code), Some(data), Some(kern)) = (
        mm::effective_flags(prog.code_va),
        mm::effective_flags(prog.data_va),
        sched::stack_bounds(0).and_then(|(lo, _, _)| mm::effective_flags(lo)),
    ) else {
        crate::log_fatal!("user: 页表链读不回来（code/data/内核栈）");
        return false;
    };
    let wx_ok = code.user && code.executable && !code.writable
        && data.user && data.writable && !data.executable
        && !kern.user
        && code.levels >= 2 && data.levels >= 2;
    crate::log_info!(
        "user: eff code={:?} data={:?} kernel_stack={:?}",
        code, data, kern
    );
    if !wx_ok {
        crate::log_fatal!("user: 生效位不对（W^X 或 内核页用户可达）");
        return false;
    }
    sched::start_workers();
    user::clear_counters();
    let entry = prog.entry;
    let stop = prog.stack_top;
    // `OwnedSet::new()` 不是占位：手写镜像那三页是**测试脚手架**，两个任务共用同一套页，
    // 所以它们不属于任何一个任务（属于谁就该在谁结束时释放）。容器那条路径
    // （`t_elf_load_run`）才是"一次装载一份资源"，那份资源交给任务持有。
    let utask = match sched::spawn_user(entry, stop, sched::OwnedSet::new()) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("user: spawn_user 失败 {:?}", e);
            return false;
        }
    };
    // 两条用户任务的**内核栈顶**要在换入之前就记下来：TSS 那条判据比它晚，
    // 而被杀的那一条此刻可能已经被回收（`release_owned` 会把 `kstack_top` 清零），
    // 到时候读出来是 None —— 那不是"rsp0 装错了"，是量具在自己被测的那一瞬间之后才按下快门。
    let good_top = sched::kstack_top_of(utask);
    // "越界的那条"故意从**数据页**取指：这一页对 ring3 可达、可写、但不可执行，
    // 所以取指必然 #PF(err=0x15) —— 判据不依赖"我猜这条指令的第二个字节会解码成什么"。
    // （之前写成 `entry + 1`，实测那条字节串 `C7 C0 01 00 00 00` = `mov eax,1` 是**合法**
    // 指令，任务照常跑完三次调用，`kills` 读出 0：判据抓不到任何东西。）
    let bad = match sched::spawn_user(prog.data_va, stop, sched::OwnedSet::new()) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("user: 第二条（从数据页取指）任务建不起来 {:?}", e);
            return false;
        }
    };
    let bad_top = sched::kstack_top_of(bad);
    apic::timer_start().ok();
    // **换入之前**把两条用户任务的异常帧逐格读回来。这条打印不是装饰：
    // iretq 的字段没有类型系统保护，"写进去的值"与"CPU 读到的值"之间唯一的证人就是它。
    //（M4-1 第一次红的现场是 #GP(0x18)——那是"SS 选择子的 RPL 不是 3"的号码，
    // 而 `udata_sel()` 明明写的是 0x1b，所以必须看真内存里那一格是什么。）
    for (name, gi) in [("good", utask), ("bad", bad)] {
        let Some(f) = sched::task_frame(gi) else {
            crate::log_fatal!("user: {name} 任务没有帧地址");
            return false;
        };
        // SAFETY: f 是 spawn_user 刚写好的 23 格帧，落在它自己那条已映射的内核栈区间内
        //（`t_percpu_queues` 那条判据已经验过栈边界），这里只读不改。
        let w = unsafe {
            [
                core::ptr::read_volatile(f as *const u64),
                core::ptr::read_volatile((f + 144) as *const u64),
                core::ptr::read_volatile((f + 152) as *const u64),
                core::ptr::read_volatile((f + 160) as *const u64),
                core::ptr::read_volatile((f + 168) as *const u64),
                core::ptr::read_volatile((f + 176) as *const u64),
            ]
        };
        crate::log_info!(
            "user: {name} frame={f:#x} cr2={:#x} [rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} ss={:#x}]",
            w[0], w[1], w[2], w[3], w[4], w[5]
        );
    }
    // 两段窗口：先让好的那个跑完三次调用，再让坏的那个故障。
    // 分开是因为 kill 会把任务标 Done，同一个窗口里两个都要不到时间片就会互相干扰读数。
    for (i, focus) in [utask, bad].iter().enumerate() {
        let _ = focus;
        apic::with_interrupts(|| {
            let t0 = tsc::now();
            while tsc::now() - t0 < 120_000_000 && user::served() < 3 + (i as u64 * 0) {
                if i == 1 && user::kills() >= 1 {
                    break;
                }
                tsc::spin(20_000);
            }
            let back = sched::wait_for_boot_task(300_000_000);
            if !back {
                crate::log_fatal!("user: 窗口收不了场（启动上下文没回到 CPU）");
            }
        });
    }
    apic::timer_stop().ok();
    let slot0 = user::read_slot(user::SLOT_PING);
    let slot1 = user::read_slot(user::SLOT_ADD);
    let slot2 = user::read_slot(user::SLOT_UNKNOWN);
    // SMAP：不开窗口直接读用户页必须故障（probe_page_fault 返回 Some 表示"确实故障并恢复了"）
    let smap_blocks = user::probe_slot_without_window(user::SLOT_PING).is_some();
    // 探针登记表必须回到"没有待恢复"的状态：留着非 0 就是下一次无关故障的劫持目标
    //（M4-1 第一次红就是这么坏的：`user::init` 的 SMAP 写故障被上一次没故障的探针
    // 留下的 PF_RESUME 劫持，跳进探针尾巴上的 `ret`，内核带着 0x3a000 去取指）。
    let probes_clean = trap::probe_registers_clear();
    let stale_hits = trap::PF_STALE_HITS.load(core::sync::atomic::Ordering::Relaxed);
    crate::log_info!(
        "user: served={} unknown={} kills={} slots=[{:?},{:?},{:?}] smap_blocks_kernel_read={} utask_state={:?} bad_state={:?}",
        user::served(), user::unknown_nr(), user::kills(), slot0, slot1, slot2, smap_blocks,
        sched::state_of(utask), sched::state_of(bad)
    );
    crate::log_info!(
        "user: code={:#x} mapped={} data={:#x} stack={:#x} entry={:#x} tramp={:#x} pf_stale_hits={} probes_clean={}",
        prog.code_va, mm::is_mapped(prog.code_va), prog.data_va, prog.stack_va, prog.entry,
        user::trampoline(), stale_hits, probes_clean
    );
    // **判据 0c：TSS 的架构偏移**。这里读的是"按 Intel 那张表的位置"上的字节，
    // 不是按 Rust 声明的字段名——`#[repr(C, align(16))]` 会把 `rsp0` 挪到偏移 8，
    // 而 CPU 从偏移 4 取 8 个字节，于是换栈换到一个被截断的地址（M4-1 的三重故障）。
    // ist1 与 iomap_base 此刻就装好了；rsp0 只有在换入过用户任务之后才非 0，
    // 所以三种合法读数都接受：还没装(0)、两条用户任务各自的内核栈顶。
    let ex_top = trap::ex_stack_info(crate::arch::x86_64::cpu::BSP_SLOT).map_or(0, |i| i.top);
    let (rsp0_now, ist1_now, iomap_now) = trap::tss_offsets(crate::arch::x86_64::cpu::BSP_SLOT).unwrap_or((0, 0, 0));
    let tops = [good_top, bad_top];
    let tss_ok = ist1_now == ex_top
        && iomap_now == 104
        && (rsp0_now == 0 || tops.iter().any(|t| *t == Some(rsp0_now)));
    // `rsp0` 可能指向**已经被回收**的那条内核栈（被杀的任务换下去之后资源就还了）。
    // 这不构成"ring3 一陷入就踩已释放的页"：`rsp0` 只在 ring3→ring0 转换时被 CPU 取用，
    // 而那一刻本 CPU 上跑的必然是用户任务，换入它的那一步（`preempt_point` 里
    // `if tasks[nslot].user { set_rsp0(..) }`）先把它自己的栈顶装了进去。
    // 也就是说这条不变量是"rsp0 与当前任务同源"，不是"rsp0 永远指向活着的栈"。
    // 上面那句 `tops` 用**换入前记下的**两个栈顶，正是为了让这条判据在回收之后照样读得出。
    crate::log_info!(
        "user: tss rsp0={:#x} ist1={:#x}(期望 {:#x}) iomap={} tss_ok={}",
        rsp0_now, ist1_now, ex_top, iomap_now, tss_ok
    );
    let ping_ok = slot0.is_some_and(|v| v >= 1);
    let add_ok = slot1 == Some(0x2a);
    let unk_ok = slot2 == Some(user::E_INVALID);
    // 判 `kills == 1`（精确）而不是 `>= 1`：唯一能分辨"真杀掉"与"同一个故障每秒重演几十次"
    // 的就是这个数（M4-2 的现场是三十多行重复 `#GP`，`>= 1` 对它照样绿）。
    // 状态判"不再可运行"而不是"等于 Done"：被杀的任务现在会走完 标 Done → 登记待回收 →
    // 抢占点归化成 Free 并放手资源，停在哪个状态取决于窗口里过了几次 tick。
    // "被杀之后资源真的回账"不在这里判——手写镜像的 owned 只有它自己的内核栈；
    // 那条判据在 `KT_USER_POINTER` 第四档（有容器资源可还）。见 ADR-028、BACKLOG ⑫。
    let not_runnable = !matches!(sched::state_of(bad), sched::TaskState::Runnable | sched::TaskState::Running);
    let killed = user::kills() == 1
        && not_runnable
        && sched::runs_of(bad) <= 1
        // 落脚页存在且是"内核拥有、对用户开放、不可写"的一页：kill 的出口要跳的就是它
        && user::trampoline() == user::TRAMPOLINE_VA
        && mm::effective_flags(user::TRAMPOLINE_VA)
            .is_some_and(|e| e.user && e.executable && !e.writable);
    crate::log_info!(
        "user: killed={} kills={} bad_state={:?} runs={} 落脚页用户可达={}",
        killed,
        user::kills(),
        sched::state_of(bad),
        sched::runs_of(bad),
        mm::effective_flags(user::TRAMPOLINE_VA).is_some_and(|e| e.user)
    );
    ping_ok && add_ok && unk_ok && smap_blocks && killed && user::unknown_nr() >= 1
        && stale_hits == 0 && probes_clean && tss_ok
}
ktest!(KT_USER_ROUNDTRIP, t_user_roundtrip);

/// M4-2 第三段：任务的结束与资源回账。两条收场路径都要走，各判一件事：
/// **旁观者结束**（用例调 `terminate_task`，对应"被杀/被回收"）与
/// **自己退出**（程序打 `SYS_EXIT`，对应"进程正常走完"）。
///
/// 最硬的一条判据是**同一个固定 VA 连续装载三次都成功**：
/// `ET_EXEC` 的地址是容器定死的，只要上一次的映射或 VA 保留没还回来，
/// `load` 就会撞 `VaTaken`；所以"第三次装得上"本身就是回收发生了的证据，
/// 不依赖我去读自己写的计数器。计数（reservation / live frames / exits / reap_released）
/// 只是把"为什么成功"说清楚的第二台仪器。
fn t_task_exit() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("exit: APIC 起不来");
        return false;
    }
    // 用例自足（T0.1 顺序暴露）：落脚页是**全局设施**，第一次 `user::load` 才建。
    // 它名下的 1 条 VA 保留 + 1 个 MOD_USER 页框会记进第一轮的账里，于是"第一轮是否回账"
    // 取决于本用例是不是第一个装载者。先把它建好，基线才真的是"本用例开始时的账"。
    if user::ensure_trampoline().is_none() {
        crate::log_fatal!("exit: 落脚页建立失败");
        return false;
    }
    let base_res = mm::reservation_count();
    let base_live = resource::live_of(user::MOD_USER);
    let base_released = sched::reap_released();
    sched::init_boot_task();
    sched::start_workers();
    apic::timer_start().ok();

    // ---- 一轮 = 装载 → 跑 → 结束（mode 决定谁发起结束）→ 回收 → 检查账目
    let mut one_ok = true;
    let mut two_ok = true;
    let mut three_ok = true;

    // === 第一轮：旁观者结束（terminate_task，此时该任务已不在 CPU 上 ⇒ 就地回收） ===
    let l1 = match user::load(HELLO_ELF) {
        Ok(l) => l,
        Err(e) => {
            crate::log_fatal!("exit: 第一次装载失败 —— {}", user::describe_load(e));
            return false;
        }
    };
    let entry_page = l1.entry;
    let t1 = match sched::spawn_user(l1.entry, l1.stack_top, l1.owned) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("exit: 第一个任务建不起来 {:?}", e);
            return false;
        }
    };
    user::clear_counters();
    let run1 = sched::state_of(t1);
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        while user::served() < 8 && tsc::now().wrapping_sub(t0) < 200_000_000 {
            tsc::spin(20_000);
        }
        if !sched::wait_for_boot_task(300_000_000) {
            crate::log_fatal!("exit: 第一轮窗口收不了场");
        }
    });
    // 此刻 current 是启动上下文，所以 terminate 走的是"就地回收"那条分支
    let term1 = sched::terminate_task(t1);
    // 旁观者路径（任务已不在 CPU 上）是**就地回收**，不需要等 tick，
    // 所以这里不能要求 drain_reap 命中——它可能本来就已经是零待收了。
    let _ = drain_reap();
    let reload1 = user::load(HELLO_ELF).is_ok();
    crate::log_info!(
        "exit: 一轮(旁观者) 结束前状态={:?} terminate返回={} 装载的映射数回账={} 再装载成功={} reservations={}→{} live={}→{}",
        run1,
        term1,
        sched::state_of(t1) == sched::TaskState::Free,
        reload1,
        base_res,
        mm::reservation_count(),
        base_live,
        resource::live_of(user::MOD_USER)
    );
    one_ok = term1
        && reload1
        && sched::state_of(t1) == sched::TaskState::Free
        && !mm::is_reserved(entry_page)
        && mm::reservation_count() <= base_res
        && resource::live_of(user::MOD_USER) <= base_live;
    // `reload1` 那次装载没有泄漏：返回值被丢掉 ⇒ 它的 `OwnedSet` 立刻 drop ⇒
    // 解映射 + 归还页框 + 放手保留。这正是 `Mapping` 的 RAII 在收尾——
    // "没接住所有权"不等于"资源还在"，第三轮装得上就是这件事的证据。
    // （`l1` 的 `owned` 字段已经在 `spawn_user` 那一步移走了，这里不能整体借用它。）

    // === 第二轮：自己退出（程序读 flag 打 SYS_EXIT ⇒ 释放必须延迟到下一个上下文） ===
    let l2 = match user::load(HELLO_ELF) {
        Ok(l) => l,
        Err(e) => {
            // 第一次已经回收过了还装不上，就是回账没发生：直接判红，不必再跑后面两轮
            crate::log_fatal!("exit: 第二次装载失败（说明第一轮的回收没真正放手）—— {}", user::describe_load(e));
            return false;
        }
    };
    let mut two_ran = false;
    if l2.segs >= 1 {
        let r2_base = sched::reap_released();
        user::clear_counters();
        // 通过 SMAP 窗口往它的 flag 格写非 0：程序跑完调用序列之后就自己结束。
        // 这一步同时是 §10.3 的最小预览（内核开窗口**写**用户页），不是测试专用的后门。
        user::write_at(l2.data_va + 48, 1);
        match sched::spawn_user(l2.entry, l2.stack_top, l2.owned) {
            Ok(t2) => {
                apic::with_interrupts(|| {
                    let t0 = tsc::now();
                    while user::served() < P7_CALLS && tsc::now().wrapping_sub(t0) < 200_000_000 {
                        tsc::spin(20_000);
                    }
                    if !sched::wait_for_boot_task(300_000_000) {
                        crate::log_fatal!("exit: 第二轮窗口收不了场");
                    }
                });
                // SYS_EXIT 的释放是**延迟**的（那一刻它还站在自己的内核栈上），
                // 必须等到本 CPU 出现下一次抢占，所以这一处 `drain` 是真判据。
                // 但延迟可能在本窗口结束前就完成了：`drain_reap` 只认"它自己的窗口里有增量"，
                // 于是"释放已经发生"会被读成"没等到"。以**本轮开始前**为基线，两者取或。
                let drained = drain_reap() || sched::reap_released() > r2_base;
                let exits = user::exits();
                // 回收前后的两个独立读数：槽里还牵着几条映射、代码页还在不在。
                // 只看"能不能再装载一次"会漏掉"装得上是因为它换了地址"这类假绿。
                let owned_after = sched::owned_of(t2);
                let code_after = mm::is_mapped(l2.entry);
                let reload2 = user::load(HELLO_ELF).is_ok();
                crate::log_info!(
                    "exit: 二轮(自己退出) exits={} 等到回收={} 槽位Free={} 槽内还剩映射={} 代码页还在={} 再装载成功={} released={}→{} reservations={} live={}",
                    exits,
                    drained,
                    sched::state_of(t2) == sched::TaskState::Free,
                    owned_after,
                    code_after,
                    reload2,
                    base_released,
                    sched::reap_released(),
                    mm::reservation_count(),
                    resource::live_of(user::MOD_USER)
                );
                two_ran = true;
                two_ok = exits >= 1
                    && drained
                    && reload2
                    && sched::state_of(t2) == sched::TaskState::Free
                    && !mm::is_mapped(l2.data_va)
                    && sched::reap_released() > base_released
                    && mm::reservation_count() <= base_res
                    && resource::live_of(user::MOD_USER) <= base_live;
            }
            Err(e) => {
                crate::log_fatal!("exit: 第二个任务建不起来 {:?}", e);
                one_ok = false;
            }
        }
    }

    // === 第三轮：什么都不做，只证明"上两轮的账目是平的" ===
    if two_ran {
        let l3 = user::load(HELLO_ELF);
        match l3 {
            Ok(l) => {
                three_ok = true;
                let _ = l.segs;
                // l 在这里被 drop ⇒ 它的映射与保留立刻归还；三次都能装 ⇒ 回收是真的在发生
            }
            Err(e) => {
                crate::log_fatal!("exit: 第三次装载失败 —— {}", user::describe_load(e));
                three_ok = false;
            }
        }
    }
    apic::timer_stop().ok();
    crate::log_info!(
        "exit: 判定 一轮={} 二轮={} 三轮={} 最终 reservations={} live={}",
        one_ok,
        two_ok,
        three_ok,
        mm::reservation_count(),
        resource::live_of(user::MOD_USER)
    );
    one_ok && two_ok && three_ok
}
ktest!(KT_TASK_EXIT, t_task_exit);

