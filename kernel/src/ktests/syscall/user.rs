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
    let utask = match sched::spawn_user(entry, stop, 0, sched::OwnedSet::new()) {
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
    let bad = match sched::spawn_user(prog.data_va, stop, 0, sched::OwnedSet::new()) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("user: 第二条（从数据页取指）任务建不起来 {:?}", e);
            return false;
        }
    };
    let bad_top = sched::kstack_top_of(bad);
    // §199：收尾按原样放回（与 t_handle_reap 同一律）。本用例需要表走，所以照样开；
    // 旧写法无条件 stop，把表停给了后面所有用例（第二终端的前置条件，BACKLOG §198/§199）。
    let tick_in = apic::ticks();
    let timer_was_running =
        apic::wait_ticks(tick_in, 2, crate::clock::window_cycles(2)).ticks >= 2;
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
    if !timer_was_running {
        apic::timer_stop().ok();
    }
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
    // P3a-2：把自己造的容器收干净。`utask` 跑完三次调用之后就在 ring3 里自旋，
    // 不收掉它就一直 Runnable —— 后续任何"关窗口让出"或"停掉唯一 tick 源"的动作
    // 都会被它变成整机静默（§111/§114a：两次挂死同一地址 RIP=0x100102040）。
    // 放在所有读数之后：上面那些判据还要读它的状态与 runs。
    let _ = sched::terminate_task(utask);
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
    // §199：收尾按原样放回（与 t_handle_reap 同一律）。本用例需要表走，所以照样开；
    // 旧写法无条件 stop，把表停给了后面所有用例（第二终端的前置条件，BACKLOG §198/§199）。
    let tick_in = apic::ticks();
    let timer_was_running =
        apic::wait_ticks(tick_in, 2, crate::clock::window_cycles(2)).ticks >= 2;
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
    let t1 = match sched::spawn_user(l1.entry, l1.stack_top, 0, l1.owned) {
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
        match sched::spawn_user(l2.entry, l2.stack_top, 0, l2.owned) {
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
    if !timer_was_running {
        apic::timer_stop().ok();
    }
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


// ---- 33/34/53/54/56/60 的分派臂：**用户态真打什么号，内核就必须有那条臂**
//
// ## 为什么这一格单独存在（一次真实事故，BACKLOG §469）
//
// 2026-11-20 的 04af866 把分派臂从 SYS_NET_SEND(33) 改成 SYS_SOCK_SEND(53)，
// 而 user/runtime 还在打 33/34 ⇒ ping 全死，1248 份跑后日志里 0 次 ICMP 回话。
// 当时**没有任何内核用例打这四个号**，所以 ktests 全绿也照样漏。
//
// ## 判据（六格：两"已知" + 四"已登记未实现"）
//
// 33 必须**已知**：调一次，unknown_nr() 不涨（落不落 E_INVALID 由设备决定——
//   没网卡时 bind_net 失败回 E_IO，那也是"这条臂在"，与"号根本不存在"是两件事）。
// 34 同上。
//
// 53/54 必须**已登记但未实现**（ADR-176 之后的新语义）：
//   调了必须回 -18 E_NOSYS、nosys_nr() 涨 1、**unknown_nr() 不涨**。
//   **这一格仍然防"别名"**：谁再把 53 挂回 sys_net_send，返回值就不再是 E_NOSYS，这里立刻红。
// 56（INPUT_READ）/ 60（AUDIO_STREAM）同理——这两格是**抽样覆盖另外两个族**：
//   48–61 共 14 个号，只证 53/54 两个等于只证了 socket 族。
//
// ## 为什么 53/54 那两格不许删（原话保留，仍然有效）
//
// 若哪天 socket 真实现了，这两格要按新语义重写，不许直接删——
// 删掉就回到"没有用例打这些号"的状态，而那次事故正是从那个状态长出来的。
//
// ## 为什么这里要数两个计数器而不是一个
//
// ADR-176 决策 4：UNKNOWN_NR = "号根本没登记"，NOSYS_NR = "号登记了但没实现"。
// 这两个数**必须分开断言**——只断言"某个数涨了"的话，一个把 53 从号表里删掉的
// 改动会让它落到 `_ =>` 去涨 UNKNOWN_NR，而用例照样绿。
#[cfg(feature = "handles")]
fn t_syscall_abi_arms() -> bool {
    use crate::user::{self, syscall_dispatch, SYS_AUDIO_STREAM, SYS_INPUT_READ,
                      SYS_NET_RECV, SYS_NET_SEND, SYS_SOCK_RECV, SYS_SOCK_SEND};
    let mut f = crate::arch::x86_64::trap::TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    };

    // ---- 33：必须已知。**只数 unknown_nr 有没有涨**，不判返回值。
    // 返回值取决于设备在不在（没有网卡 ⇒ bind_net 失败 ⇒ E_IO = -7），
    // 而"这条臂存不存在"与"设备在不在"是两件事——混在一起判，
    // 判定表里那些不挂网卡的档会假红（这正是 ping 那次被遮住的同一类错误）。
    let u0 = user::unknown_nr();
    f.rax = SYS_NET_SEND;
    f.rdi = 0;      // 帧指针：不校验指针先看号（号不存在时连指针都不该碰）
    f.rsi = 0;      // 长 0 ⇒ 已知臂会回 E_INVALID（形状检查），未知号也会回 E_INVALID
    syscall_dispatch(&mut f);
    let send_known = user::unknown_nr() == u0;

    // ---- 34：同上。
    let u1 = user::unknown_nr();
    f.rax = SYS_NET_RECV;
    f.rdi = 0;
    f.rsi = 0;
    f.rdx = 0;
    syscall_dispatch(&mut f);
    let recv_known = user::unknown_nr() == u1;

    // ---- 53（ADR-181 起**已实现**）：**不涨 nosys、不涨 unknown**，两个都要成立。
    //
    // 旧判据是「回 -18 且 nosys 涨 1」——那是 53 还没实现时写的。ADR-181 把它接成
    // 真 UDP send 之后，**判据必须跟着实现走**：继续断言「未实现」会让这条用例
    // 在功能上线时变红，而那个红是判据过时，不是功能坏了。
    //
    // 新判据仍保留原来的用意（分得清「号没登记」与「号没实现」）：
    // 已实现的号**两个计数器都不该涨**。
    let u2 = user::unknown_nr();
    let n2 = user::nosys_nr();
    f.rax = SYS_SOCK_SEND;
    f.rdi = 0; f.rsi = 0; f.rdx = 0;
    syscall_dispatch(&mut f);
    // 句柄 0 不是 socket ⇒ 回 EBADF（-9），但**绝不是** E_NOSYS
    let sock_send_impl = user::nosys_nr() == n2
        && user::unknown_nr() == u2
        && f.rax != user::E_NOSYS;

    // ---- 54：同上（ADR-181 起已实现）。
    let u3 = user::unknown_nr();
    let n3 = user::nosys_nr();
    f.rax = SYS_SOCK_RECV;
    f.rdi = 0; f.rsi = 0; f.rdx = 0;
    syscall_dispatch(&mut f);
    let sock_recv_impl = user::nosys_nr() == n3
        && user::unknown_nr() == u3
        && f.rax != user::E_NOSYS;

    // ---- 56（INPUT_READ）：抽样覆盖**输入族**。14 个号只证 53/54 等于只证了 socket 族。
    let u4 = user::unknown_nr();
    let n4 = user::nosys_nr();
    f.rax = SYS_INPUT_READ;
    f.rdi = 0; f.rsi = 0; f.rdx = 0;
    syscall_dispatch(&mut f);
    let input_read_nosys = user::nosys_nr() == n4 + 1
        && user::unknown_nr() == u4
        && f.rax == user::E_NOSYS;

    // ---- 60（AUDIO_STREAM）：抽样覆盖**音频族**。
    let u5 = user::unknown_nr();
    let n5 = user::nosys_nr();
    f.rax = SYS_AUDIO_STREAM;
    f.rdi = 0; f.rsi = 0; f.rdx = 0;
    syscall_dispatch(&mut f);
    let audio_stream_nosys = user::nosys_nr() == n5 + 1
        && user::unknown_nr() == u5
        && f.rax == user::E_NOSYS;

    let ok = send_known && recv_known
        && sock_send_impl && sock_recv_impl
        && input_read_nosys && audio_stream_nosys;
    // 日志要能分辨**四个**计数器（ADR-176 决策 4）：两个 unknown 起点、两个 nosys 起点，
    // 再加末值。只打一个数的话，红的那一遍分不清是"号没登记"还是"号没实现"。
    crate::log_info!(
        "abi-arms: 33已知={} 34已知={} 53已实现={} 54已实现={} 56未实现={} 60未实现={} \
         ⇒ unknown {}→{} nosys {}→{} 判据={}",
        send_known, recv_known,
        sock_send_impl, sock_recv_impl, input_read_nosys, audio_stream_nosys,
        u0, user::unknown_nr(), n2, user::nosys_nr(), ok
    );
    if !ok {
        crate::log_fatal!(
            "abi-arms: 判据不成立（33/34 必须已知；53/54 已实现（两计数器都不涨）；56/60 必须未实现：\
             回 -18、nosys_nr 涨 1、unknown_nr 不涨）\
             unknown 起点 u0={} u1={} u2={} u3={} u4={} u5={} 末值={} \
             nosys 起点 n2={} n3={} n4={} n5={} 末值={}",
            u0, u1, u2, u3, u4, u5, user::unknown_nr(),
            n2, n3, n4, n5, user::nosys_nr()
        );
    }
    ok
}
#[cfg(feature = "handles")]
ktest!(KT_SYSCALL_ABI_ARMS, t_syscall_abi_arms);



// ---- 67/68/69：信号族（ADR-177 切片 2d）
//
// ## 这一格证什么
//
// 信号的全部价值是「打断一条正在跑的指令流，去执行 handler，再**原样回来**」。
// 所以判据必须是**三段**：
//   A：sigaction 注册成功、返回旧值（0）、计数涨；
//   B：投递改了 frame——rip 变成 handler、rsp 下移、rdi 是信号号；
//   C：sigreturn **整份恢复**——rip/rsp/寄存器全部回到投递之前。
//
// **C 是全部价值所在**：只证 B 等于证了「跳得出去」，没证「回得来」。
// 回不来就是比没有信号更糟——那是一个只能进不能出的陷阱。
//
// ## 为什么不用真 ring3 任务
//
// 投递点与 sigreturn 都只操作 `TrapFrame`，不依赖 ring3 真的在跑。
// 用合成 frame 能把「投递前 / 投递后 / 恢复后」三份逐字段对比，比跑一个用户程序更容易读出差异。
#[cfg(feature = "handles")]
fn t_signal_roundtrip() -> bool {
    use crate::arch::x86_64::trap::TrapFrame;
    use crate::sched::signal;
    use crate::user::{self, syscall_dispatch, SYS_SIGACTION, SYS_SIGRETURN, SYS_SIGMASK};
    crate::sched::init_boot_task();
    crate::sched::start_workers();
    crate::arch::x86_64::apic::timer_start().ok();

    let task = crate::sched::current_id();
    signal::clear_task(task);

    // 真映射一页当用户栈：信号帧要压在上面，
    // 而 copy_to_user 会拒绝未映射的页——用假地址会得到假红。
    let Ok(stack_frames) = mm::phys_alloc(0, mm::MOD_TEST) else {
        crate::log_fatal!("signal: 栈页分配失败");
        return false;
    };
    let stack_va = mm::USER_MMAP_BASE + 0xC000;
    let stack_map = match mm::map(mm::VirtAddr(stack_va), stack_frames, mm::PageFlags::USER_RW) {
        Ok(m) => m,
        Err(_) => {
            crate::log_fatal!("signal: 栈页映射失败");
            return false;
        }
    };
    let mut f = TrapFrame {
        cr2: 0, r15: 0x1515, r14: 0x1414, r13: 0x1313, r12: 0x1212, r11: 0x1111,
        r10: 0x1010, r9: 0x0909, r8: 0x0808, rbp: 0x0b0b, rdi: 0x0d0d, rsi: 0x0e0e,
        rdx: 0x0d0d, rcx: 0x0c0c, rbx: 0x0b0b, rax: 0x0a0a, vector: 0x80, error_code: 0,
        // 栈顶 = 页尾：信号帧从这里往下压
        rip: 0x1000_0500, cs: 0x1b, rflags: 0x202, rsp: stack_va + mm::PAGE as u64, ss: 0x23,
    };

    // ---- A：注册
    let a0 = user::sigaction_calls();
    let handler = 0x1000_9000u64;
    f.rax = SYS_SIGACTION; f.rdi = 11; f.rsi = handler; f.rdx = 0;
    syscall_dispatch(&mut f);
    let registered = f.rax == 0 && user::sigaction_calls() == a0 + 1
        && signal::handler_of(task, 11) == handler;
    // 再注册一次，应返回旧 handler
    f.rax = SYS_SIGACTION; f.rdi = 11; f.rsi = 0x1000_9100; f.rdx = 0;
    syscall_dispatch(&mut f);
    let old_returned = f.rax == handler;
    // 恢复成第一次的 handler
    f.rax = SYS_SIGACTION; f.rdi = 11; f.rsi = handler; f.rdx = 0;
    syscall_dispatch(&mut f);

    // ---- B：投递
    let before_rip = f.rip;
    let before_rsp = f.rsp;
    let before_r15 = f.r15;
    let d0 = signal::delivered();
    let raised = signal::raise(task, 11);
    let took = signal::take_pending(task);
    // 把信号放回待处理位，让 deliver 自己取
    let _ = signal::raise(task, 11);
    let delivered = user::deliver(&mut f);
    let jumped = delivered && f.rip == handler && f.rsp < before_rsp && f.rdi == 11;
    let counted = signal::delivered() == d0 + 1;

    // ---- C：sigreturn 整份恢复
    let r0 = user::sigreturn_calls();
    f.rax = SYS_SIGRETURN;
    syscall_dispatch(&mut f);
    let restored = f.rip == before_rip && f.rsp == before_rsp && f.r15 == before_r15
        && user::sigreturn_calls() == r0 + 1
        && signal::active_of(task) == 0;

    // ---- D：野 rsp 不能变成内核按垃圾 iretq（魔数校验）
    let mut g = TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0x80, error_code: 0,
        // **已映射但内容不是信号帧**的页：这样才真的走到魔数校验。
        // 用未映射地址（如 0xDEAD_B000）会先在 copy_from_user 就失败，
        // 根本测不到魔数——那是一个**看起来绿的空转判据**（本轮实测撞到过）。
        rip: 0x1000_0600, cs: 0x1b, rflags: 0x202, rsp: stack_va, ss: 0x23,
    };
    g.rax = SYS_SIGRETURN;
    syscall_dispatch(&mut g);
    let bogus_rejected = g.rax == user::E_FAULT || g.rax == user::E_INVALID;
    let rip_untouched = g.rip == 0x1000_0600;

    // ---- E：拒绝格
    f.rax = SYS_SIGACTION; f.rdi = 0; f.rsi = handler; f.rdx = 0;
    syscall_dispatch(&mut f);
    let signo0_rejected = f.rax == user::E_INVALID;
    f.rax = SYS_SIGACTION; f.rdi = 11; f.rsi = handler; f.rdx = 1;
    syscall_dispatch(&mut f);
    let flags_rejected = f.rax == user::E_NOT_SUPPORTED;
    f.rax = SYS_SIGMASK; f.rdi = 0; f.rsi = 0xFF; f.rdx = 0;
    syscall_dispatch(&mut f);
    let mask_set = f.rax == 0 && signal::mask_of(task) == 0xFF;

    let ok = registered && old_returned && raised && took == 11
        && jumped && counted && restored
        && bogus_rejected && rip_untouched
        && signo0_rejected && flags_rejected && mask_set;
    crate::log_info!(
        "signal: A注册={} 旧值={} B投递={} 跳转={} 计数={} C恢复={} \
         D野rsp拒={} rip未动={} E(0号={} flags={} mask={}) ⇒ {}",
        registered, old_returned, delivered, jumped, counted, restored,
        bogus_rejected, rip_untouched, signo0_rejected, flags_rejected, mask_set, ok
    );
    if !ok {
        crate::log_fatal!("signal: 判据不成立（见上面每一格）rip={:#x} rsp={:#x}", f.rip, f.rsp);
    }
    signal::clear_task(task);
    drop(stack_map);
    ok
}
#[cfg(feature = "handles")]
ktest!(KT_SIGNAL_ROUNDTRIP, t_signal_roundtrip);
/// ADR-181：socket 族（48–55）的**证人**。
///
/// ## 判据七格
///
/// 1. `AF_INET + SOCK_DGRAM` 建成功，句柄 kind 是 `KIND_SOCKET`；
/// 2. `AF_INET6` 回 `-38`（ENOSYS），**不是** `-1`（参数写错）；
/// 3. `SOCK_STREAM` 回 `-38`；
/// 4. `bind` 成功；**同端口重复 bind** 回 `-98`（EADDRINUSE）；
/// 5. `listen`/`accept` 在 DGRAM 上回 `-95`（EOPNOTSUPP），**不静默返回 0**；
/// 6. `recv` 空队列回 `-11`（EAGAIN），**不阻塞**；
/// 7. `close` 之后 socket 槽被回收（`used()` 回到基线）。
///
/// ## 为什么不测 `send`
///
/// `send` 要真发帧，而 ktest 环境里 `bind_net` 可能没绑（取决于用例顺序）。
/// 发帧路径由 33 号的既有用例覆盖；这里只证 **socket 层的状态机**，
/// 不重复证 virtio 的收发——那是 `t_net_*` 的职责。
///
/// **负样本**：把 `sys_sock_listen` 改成返回 0（静默成功），第 5 格立刻红。
#[cfg(feature = "handles")]
fn t_socket_family() -> bool {
    let Some(owner) = crate::sched::current_identity() else {
        crate::log_fatal!("sock: 拿不到当前身份");
        return false;
    };
    let mut ok = true;
    let base_used = crate::network::socket::used();

    // 1. 建一个 AF_INET + SOCK_DGRAM
    let (slot, gen) = match crate::network::socket::create(
        crate::network::socket::AF_INET,
        crate::network::socket::SOCK_DGRAM,
    ) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("sock: create 失败 ret={}", e);
            return false;
        }
    };
    let h = match crate::handle::grant_socket(
        owner, slot, gen,
        crate::handle::RIGHT_READ | crate::handle::RIGHT_WRITE,
    ) {
        Ok(h) => h,
        Err(e) => {
            crate::log_fatal!("sock: grant 失败 {:?}", e);
            crate::network::socket::destroy(slot, gen);
            return false;
        }
    };
    let kind_ok = match crate::handle::resolve(h, owner, crate::handle::RIGHT_READ) {
        Ok((o, _)) => matches!(o, crate::handle::ObjRef::Socket { .. }),
        Err(_) => false,
    };
    if !kind_ok {
        crate::log_fatal!("sock: 句柄 kind 不是 Socket");
        ok = false;
    }

    // 2. AF_INET6 **现在能建**（ADR-182 决策 5 落地）；SOCK_STREAM 仍回 ENOSYS
    //
    // 旧判据是「AF_INET6 必须回 -38」——那是 IPv6 还没实现时写的。
    // 实现之后**判据必须跟着实现走**，否则功能上线时这条用例反而变红。
    let (v6_slot, v6_gen) = match crate::network::socket::create(
        crate::network::socket::AF_INET6,
        crate::network::socket::SOCK_DGRAM,
    ) {
        Ok(v) => v,
        Err(_) => (u16::MAX, 0),
    };
    // 空端点必须是 V6 族（否则 send 会走 IPv4 分支）
    let v6_ok = v6_slot != u16::MAX
        && crate::network::socket::endpoints(v6_slot, v6_gen)
            .map(|(l, _p)| l.is_v6())
            .unwrap_or(false);
    let v6_ret: u64 = if v6_ok { 0 } else { crate::network::socket::E_NOSYS };
    if v6_slot != u16::MAX {
        let _ = crate::network::socket::destroy(v6_slot, v6_gen);
    }
    let stream_ret = crate::network::socket::create(
        crate::network::socket::AF_INET,
        crate::network::socket::SOCK_STREAM,
    )
    .err()
    .unwrap_or(0);
    let stream_ok = stream_ret == crate::network::socket::E_NOSYS;
    if !v6_ok || !stream_ok {
        crate::log_fatal!("sock: 族/类型拒绝不对 v6={:#x} stream={:#x}", v6_ret, stream_ret);
        ok = false;
    }

    // 4. bind + 重复 bind
    // **显式确保地址在表里**（ADR-185 起 `bind` 校验归属）：
    //
    // 不能只靠 `bootstrap_addrs`：`t_ifaddr` 会清表，而它的「恢复现场」
    // 只恢复它开始时看到的那几个 —— 若它开始时表是空的，恢复后还是空的。
    let _ = crate::network::ifaddr::addr_add(
        crate::network::ipv6::IpAddr::V4(crate::network::dhcp::DHCP_GUEST_IP),
        24,
        0,
    );
    let ep = crate::network::socket::SockAddr::V4 {
        ip: crate::network::dhcp::DHCP_GUEST_IP,
        port: 45999,
    };
    let bind_ok = match crate::network::socket::bind(slot, gen, ep) {
        Ok(()) => true,
        Err(e) => {
            crate::log_fatal!(
                "sock: bind 失败 {:#x} 端口={} 表内数={} 该地址在表内={}",
                e, ep.port(),
                crate::network::ifaddr::addr_count(),
                crate::network::ifaddr::addr_is_local(&crate::network::ipv6::IpAddr::V4(crate::network::dhcp::DHCP_GUEST_IP))
            );
            false
        }
    };
    let (slot2, gen2) = match crate::network::socket::create(
        crate::network::socket::AF_INET,
        crate::network::socket::SOCK_DGRAM,
    ) {
        Ok(v) => v,
        Err(_) => (0, 0),
    };
    let dup_ret = crate::network::socket::bind(slot2, gen2, ep).err().unwrap_or(0);
    let dup_ok = dup_ret == crate::network::socket::E_ADDRINUSE;
    if !bind_ok || !dup_ok {
        crate::log_fatal!("sock: bind 不对 bind_ok={} dup={:#x}", bind_ok, dup_ret);
        ok = false;
    }

    // 5. listen/accept 在 DGRAM 上回 EOPNOTSUPP（-95）
    //
    // **必须走 syscall 层**：`socket` 模块没有 listen/accept 入口，那两格的
    // 语义在 `sys_sock_listen`/`sys_sock_accept` 里。第一版只验了「槽还活着」，
    // 而把 handler 改成静默返回 0 时它照样绿 —— 负样本没咬住（实测）。
    let mut tf = crate::arch::x86_64::trap::TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: h.0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    };
    tf.rax = crate::user::SYS_SOCK_LISTEN;
    crate::user::syscall_dispatch(&mut tf);
    let listen_ret = tf.rax;
    tf.rax = crate::user::SYS_SOCK_ACCEPT;
    crate::user::syscall_dispatch(&mut tf);
    let accept_ret = tf.rax;
    let opnotsupp_ok = listen_ret == crate::network::socket::E_OPNOTSUPP
        && accept_ret == crate::network::socket::E_OPNOTSUPP;
    if !opnotsupp_ok {
        crate::log_fatal!("sock: listen/accept 应回 -95，实得 {:#x}/{:#x}", listen_ret, accept_ret);
        ok = false;
    }

    // 6. recv 空队列回 EAGAIN
    let mut buf = [0u8; 64];
    let again_ret = crate::network::socket::dequeue(slot, gen, &mut buf).err().unwrap_or(0);
    let again_ok = again_ret == crate::network::socket::E_AGAIN;
    if !again_ok {
        crate::log_fatal!("sock: 空队列 recv 应回 EAGAIN，实得 {:#x}", again_ret);
        ok = false;
    }

    // 7. close 之后槽回收
    let _ = crate::handle::close(h, owner);
    let destroyed = crate::network::socket::destroy(slot, gen);
    let _ = crate::network::socket::destroy(slot2, gen2);
    let after = crate::network::socket::used();
    let reclaim_ok = destroyed && after == base_used;
    if !reclaim_ok {
        crate::log_fatal!("sock: 槽没回收 destroyed={} before={} after={}", destroyed, base_used, after);
        ok = false;
    }

    crate::log_info!(
        "sock: kind={} v6拒={:#x} stream拒={:#x} bind={} 重复={:#x} listen={:#x} accept={:#x} EAGAIN={:#x} 回收={} 末used={} ⇒ {}",
        kind_ok, v6_ret, stream_ret, bind_ok, dup_ret, listen_ret, accept_ret, again_ret, reclaim_ok, after, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_SOCKET_FAMILY, t_socket_family);

/// ADR-182：IPv6 的**证人**。
///
/// ## 判据七格
///
/// 1. **EUI-64**：由 MAC 推出的接口标识，U/L 位已取反；
/// 2. **链路本地地址**：`fe80::/64` + EUI-64，且 `is_link_local()` 为真；
/// 3. **被请求节点组播**：`ff02::1:ffXX:XXXX` 的后 24 位来自目标地址；
/// 4. **IPv6+UDP 往返**：打帧再解帧，地址/端口/载荷全部一致；
/// 5. **IPv6 头没有校验和**：UDP 起点在 `14+40`（不是 `14+40+12`）；
/// 6. **NDP NS 往返**：解析回的目标地址与 MAC 选项一致，hop limit = 255；
/// 7. **hop limit ≠ 255 的 NDP 必须被拒**（RFC 4861 §7.1.1）。
///
/// **负样本**：把 `eui64_from_mac` 的 `^ 0x02` 去掉，第 1、2 格同时红。
#[cfg(feature = "handles")]
fn t_ipv6_core() -> bool {
    use crate::network::{ipv6, ndp};
    let mut ok = true;

    // 1. EUI-64：MAC 02:00:00:00:00:01 => 00:00:00:FF:FE:00:00:01
    let mac = [0x02u8, 0x00, 0x00, 0x00, 0x00, 0x01];
    let eui = ipv6::eui64_from_mac(&mac);
    // U/L 位取反：0x02 ^ 0x02 = 0x00
    let eui_ok = eui[0] == 0x00
        && eui[1] == 0x00
        && eui[2] == 0x00
        && eui[3] == 0xFF
        && eui[4] == 0xFE
        && eui[5] == 0x00
        && eui[6] == 0x00
        && eui[7] == 0x01;
    if !eui_ok {
        crate::log_fatal!("ipv6: EUI-64 不对 {:02x?}", eui);
        ok = false;
    }

    // 2. 链路本地
    let ll = ipv6::link_local_from_mac(&mac);
    let ll_addr = ipv6::IpAddr::V6(ll);
    let ll_ok = ll[0] == 0xFE && ll[1] == 0x80 && ll_addr.is_link_local() && !ll_addr.is_v4();
    if !ll_ok {
        crate::log_fatal!("ipv6: 链路本地不对 {:02x?}", ll);
        ok = false;
    }

    // 3. 被请求节点组播
    let target = ll;
    let mcast = ipv6::solicited_node_multicast(&target);
    let mcast_ok = mcast[0] == 0xFF
        && mcast[1] == 0x02
        && mcast[11] == 0x01
        && mcast[12] == 0xFF
        && mcast[13] == target[13]
        && mcast[14] == target[14]
        && mcast[15] == target[15];
    if !mcast_ok {
        crate::log_fatal!("ipv6: 被请求节点组播不对 {:02x?}", mcast);
        ok = false;
    }

    // 4. IPv6 + UDP 往返
    let payload = b"hello-ipv6";
    let mut f = [0u8; 256];
    let dmac = [0x33u8, 0x33, 0xFF, 0, 0, 1];
    let flen = ipv6::build_udp6_frame(
        &mut f, &dmac, &mac, &ll, &mcast, 1234, 5678, payload,
    );
    let mut rt_ok = false;
    let mut no_cksum_ok = false;
    if let Some(n) = flen {
        // 5. IPv6 头没有校验和：UDP 起点 = 14 + 40 = 54
        //    若错当成 IPv4 那样有 12 字节校验和区，UDP 会在 66
        no_cksum_ok = n == 14 + 40 + 8 + payload.len()
            && f[54..56] == 1234u16.to_be_bytes();
        if let Some((s, d, sp, dp, pl)) = ipv6::parse_udp6_frame(&f[..n]) {
            rt_ok = s == ll && d == mcast && sp == 1234 && dp == 5678 && pl == payload;
        }
    }
    if !rt_ok || !no_cksum_ok {
        crate::log_fatal!("ipv6: UDP 往返={} 无校验和={} flen={:?}", rt_ok, no_cksum_ok, flen);
        ok = false;
    }

    // 6. NDP NS 往返
    let mut nf = [0u8; 256];
    let mut ns_ok = false;
    if let Some(n) = ndp::build_ns(&mut nf, &mac, &ll, &target) {
        if let Some(msg) = ndp::parse_nd(&nf[..n]) {
            ns_ok = msg.kind == ndp::ICMPV6_NS
                && msg.target == target
                && msg.lladdr == Some(mac)
                && msg.src_ip == ll;
        }
    }
    if !ns_ok {
        crate::log_fatal!("ipv6: NDP NS 往返不成立");
        ok = false;
    }

    // 7. hop limit ≠ 255 的 NDP 必须被拒
    let mut bad = [0u8; 256];
    let mut hop_ok = false;
    if let Some(n) = ndp::build_ns(&mut bad, &mac, &ll, &target) {
        let good = ndp::parse_nd(&bad[..n]).is_some();
        bad[14 + 7] = 64; // hop limit 改成 64（被路由器转发过的形状）
        let rejected = ndp::parse_nd(&bad[..n]).is_none();
        hop_ok = good && rejected;
    }
    if !hop_ok {
        crate::log_fatal!("ipv6: hop limit 检查不成立（≠255 的 NDP 应被拒）");
        ok = false;
    }

    crate::log_info!(
        "ipv6: eui64={} 链路本地={} 组播={} udp往返={} 无校验和={} ndp={} hop255={} ⇒ {}",
        eui_ok, ll_ok, mcast_ok, rt_ok, no_cksum_ok, ns_ok, hop_ok, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_IPV6_CORE, t_ipv6_core);

/// ADR-184：NDP 邻居缓存与收包投递的**证人**。
///
/// ## 判据六格
///
/// 1. **缓存未命中** ⇒ `nd_lookup` 回 `None`，`misses` 涨；
/// 2. **学到之后命中** ⇒ `nd_lookup` 回那个 MAC，`hits` 涨；
/// 3. **`Incomplete` 不算命中**（只记「正在问」）；
/// 4. **NA 帧能被处理** ⇒ `handle_frame` 学进缓存；
/// 5. **NS 帧要求回 NA** ⇒ 返回 `ReplyNa` 且 target 正确；
/// 6. **`deliver_frame` 能投递 UDP**（IPv4 与 IPv6 各一次）。
///
/// **负样本**：把 `nd_lookup` 里 `state == Reachable` 的判断去掉（`Incomplete` 也返回 MAC），
/// 第 3 格立刻红。
#[cfg(feature = "handles")]
fn t_ndp_cache() -> bool {
    use crate::network::{ndp, socket};
    let mut ok = true;
    ndp::nd_clear();
    let s0 = ndp::nd_stats();

    let mac = [0x02u8, 0x00, 0x00, 0x00, 0x00, 0x01];
    let our_ip = crate::network::ipv6::link_local_from_mac(&mac);
    let peer_mac = [0x02u8, 0x00, 0x00, 0x00, 0x00, 0x02];
    let mut peer_ip = crate::network::ipv6::link_local_from_mac(&peer_mac);
    peer_ip[15] = 0x99; // 与 our_ip 区分开

    // 1. 未命中
    let miss_before = ndp::nd_stats().misses;
    let miss_ok = ndp::nd_lookup(&peer_ip).is_none() && ndp::nd_stats().misses > miss_before;
    if !miss_ok {
        crate::log_fatal!("ndp: 未命中判据不成立");
        ok = false;
    }

    // 2. 学到之后命中
    ndp::nd_learn(&peer_ip, &peer_mac);
    let hit_before = ndp::nd_stats().hits;
    let hit_ok = ndp::nd_lookup(&peer_ip) == Some(peer_mac) && ndp::nd_stats().hits > hit_before;
    if !hit_ok {
        crate::log_fatal!("ndp: 命中判据不成立");
        ok = false;
    }

    // 3. Incomplete 不算命中
    let mut third = peer_ip;
    third[15] = 0x77;
    ndp::nd_mark_incomplete(&third);
    let inc_ok = ndp::nd_lookup(&third).is_none();
    if !inc_ok {
        crate::log_fatal!("ndp: Incomplete 不该命中");
        ok = false;
    }

    // 4. NA 帧被处理
    let mut na = [0u8; 256];
    let mut na_ok = false;
    if let Some(n) = ndp::build_na(
        &mut na, &peer_mac, &peer_ip, &our_ip, &mac, &peer_ip, false,
    ) {
        // 清掉再让它学
        ndp::nd_clear();
        let acted = ndp::handle_frame(&na[..n], &mac, false);
        na_ok = matches!(acted, ndp::NdAction::None) && ndp::nd_lookup(&peer_ip) == Some(peer_mac);
    }
    if !na_ok {
        crate::log_fatal!("ndp: NA 处理不成立");
        ok = false;
    }

    // 5. NS 要求回 NA
    let mut ns = [0u8; 256];
    let mut ns_ok = false;
    if let Some(n) = ndp::build_ns(&mut ns, &peer_mac, &peer_ip, &our_ip) {
        if let ndp::NdAction::ReplyNa { target, .. } = ndp::handle_frame(&ns[..n], &mac, true) {
            ns_ok = target == our_ip;
        }
    }
    if !ns_ok {
        crate::log_fatal!("ndp: NS 未要求回 NA");
        ok = false;
    }

    // 6. deliver_frame 能投递 UDP（IPv6 一次）
    //    **不测 IPv4**：那要造一个真的 IPv4 UDP 帧，而 `udp::build_frame` 需要 MAC；
    //    这里只证「IPv6 分支能进队列」这个本轮新加的通路。
    ndp::nd_clear();
    let mut deliv_ok = false;
    // 建一个绑在 45998 的 socket
    if let Ok((slot, gen)) = socket::create(socket::AF_INET6, socket::SOCK_DGRAM) {
        // **显式把链路本地地址加进表**（ADR-185 起 `bind` 校验归属）。
        // 不靠 `bootstrap_addrs`：别的用例会清表，守卫看「表非空」时会跳过填充。
        let _ = crate::network::ifaddr::addr_add(
            crate::network::ipv6::IpAddr::V6(our_ip),
            64,
            0,
        );
        let local = socket::SockAddr::V6 { ip: our_ip, port: 45998 };
        if socket::bind(slot, gen, local).is_ok() {
            let mut f = [0u8; 512];
            let dmac = [0x33u8, 0x33, 0xFF, 0, 0, 0x99];
            if let Some(n) = crate::network::ipv6::build_udp6_frame(
                &mut f, &dmac, &peer_mac, &peer_ip, &our_ip, 40000, 45998, b"ndp-test",
            ) {
                let fam = socket::deliver_frame(&f[..n]);
                let mut buf = [0u8; 64];
                if fam == 6 {
                    if let Ok((src, got)) = socket::dequeue(slot, gen, &mut buf) {
                        deliv_ok = got == 8 && &buf[..8] == b"ndp-test" && src.is_v6();
                    }
                }
            }
        }
        let _ = socket::destroy(slot, gen);
    }
    if !deliv_ok {
        crate::log_fatal!("ndp: deliver_frame 投递不成立");
        ok = false;
    }

    let s1 = ndp::nd_stats();
    crate::log_info!(
        "ndp: 未命中={} 命中={} Incomplete={} NA处理={} NS回NA={} 投递={} stats(h{} m{} l{} e{}) ⇒ {}",
        miss_ok, hit_ok, inc_ok, na_ok, ns_ok, deliv_ok,
        s1.hits - s0.hits, s1.misses - s0.misses, s1.learns - s0.learns, s1.evicts - s0.evicts, ok
    );
    ndp::nd_clear();
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_NDP_CACHE, t_ndp_cache);

/// ADR-185：本机地址表的**证人**。
///
/// ## 判据七格
///
/// 1. **加/查**：`addr_add` 之后 `addr_is_local` 为真；
/// 2. **幂等**：同一地址重复加不涨计数；
/// 3. **删**：`addr_remove` 之后 `addr_is_local` 为假；
/// 4. **通配放行**：`is_wildcard(0.0.0.0)` 与 `is_wildcard(::)` 都为真；
/// 5. **`bind` 拒非本机地址** ⇒ `-99`（EADDRNOTAVAIL）；
/// 6. **`bind` 放行通配地址** ⇒ 成功；
/// 7. **NDP 精确判属**：target 不在表里 ⇒ 不回 NA。
///
/// **负样本**：把 `bind` 的归属校验去掉，第 5 格立刻红。
#[cfg(feature = "handles")]
fn t_ifaddr() -> bool {
    use crate::network::ifaddr::{
        addr_add, addr_clear, addr_count, addr_is_local, addr_remove, is_wildcard, IfAddr,
    };
    use crate::network::ipv6::IpAddr;
    use crate::network::socket::{self, SockAddr};
    let mut ok = true;

    // 保存现场：这个用例会清表，跑完要恢复（别的用例依赖引导出来的地址）
    let mut saved = [IfAddr { ip: IpAddr::V4([0; 4]), prefix: 0, iface: 0, link_local: false }; 8];
    let n_saved = crate::network::ifaddr::addr_list(&mut saved);
    addr_clear();

    let test_ip = IpAddr::V4([192, 168, 99, 7]);

    // 1. 加 + 查
    let added = addr_add(test_ip, 24, 0);
    let add_ok = added && addr_is_local(&test_ip) && addr_count() == 1;
    if !add_ok {
        crate::log_fatal!("ifaddr: 加/查不成立 added={} count={}", added, addr_count());
        ok = false;
    }

    // 2. 幂等
    let _ = addr_add(test_ip, 24, 0);
    let idem_ok = addr_count() == 1;
    if !idem_ok {
        crate::log_fatal!("ifaddr: 幂等不成立 count={}", addr_count());
        ok = false;
    }

    // 3. 删
    let removed = addr_remove(&test_ip);
    let rm_ok = removed && !addr_is_local(&test_ip) && addr_count() == 0;
    if !rm_ok {
        crate::log_fatal!("ifaddr: 删不成立 removed={} count={}", removed, addr_count());
        ok = false;
    }

    // 4. 通配
    let wc_ok = is_wildcard(&IpAddr::V4([0, 0, 0, 0]))
        && is_wildcard(&IpAddr::V6([0; 16]))
        && !is_wildcard(&test_ip);
    if !wc_ok {
        crate::log_fatal!("ifaddr: 通配判定不成立");
        ok = false;
    }

    // 5. bind 拒非本机地址
    let mut bind_reject_ok = false;
    if let Ok((slot, gen)) = socket::create(socket::AF_INET, socket::SOCK_DGRAM) {
        // 表里只有 127.0.0.1（下面第 6 格要用），192.168.99.7 不在表里
        let foreign = SockAddr::V4 { ip: [192, 168, 99, 7], port: 45990 };
        let ret = socket::bind(slot, gen, foreign).err().unwrap_or(0);
        bind_reject_ok = ret == socket::E_ADDRNOTAVAIL;
        if !bind_reject_ok {
            crate::log_fatal!("ifaddr: bind 应拒非本机地址，实得 {:#x}", ret);
            ok = false;
        }

        // 6. bind 放行通配
        let wild = SockAddr::V4 { ip: [0, 0, 0, 0], port: 45991 };
        let wret = socket::bind(slot, gen, wild);
        if wret.is_err() {
            crate::log_fatal!("ifaddr: bind 应放行通配地址");
            ok = false;
        }
        let _ = socket::destroy(slot, gen);
    } else {
        crate::log_fatal!("ifaddr: create 失败");
        ok = false;
    }

    // 7. NDP 精确判属：target 不在表里 ⇒ 不回 NA
    //
    // **手工构造 NS 而不用 `build_ns`**：这一格要验的是「判属」，不是「构造」。
    let mac = [0x02u8, 0x00, 0x00, 0x00, 0x00, 0x01];
    let our_ip = crate::network::ipv6::link_local_from_mac(&mac);
    let mut not_ours = our_ip;
    not_ours[15] = 0xAB; // 不在表里
    let mut ns = [0u8; 128];
    // eth 14 + IPv6 40 + ICMPv6 24 = 78
    ns[12] = 0x86;
    ns[13] = 0xDD;
    ns[14] = 0x60;
    ns[14 + 5] = 24; // payload len
    ns[14 + 6] = 58; // ICMPv6
    ns[14 + 7] = 255; // hop limit 必须 255
    ns[14 + 8..14 + 24].copy_from_slice(&our_ip);
    let mcast = crate::network::ipv6::solicited_node_multicast(&not_ours);
    ns[14 + 24..14 + 40].copy_from_slice(&mcast);
    let m = 14 + 40;
    ns[m] = 135; // NS
    ns[m + 8..m + 24].copy_from_slice(&not_ours);
    let parsed = crate::network::ndp::parse_nd(&ns[..78]);
    let ndp_ok = match parsed {
        Some(_) => matches!(
            crate::network::ndp::handle_frame(&ns[..78], &mac, false),
            crate::network::ndp::NdAction::None,
        ),
        None => {
            crate::log_fatal!("ifaddr: 手工 NS 解析失败");
            false
        }
    };
    if !ndp_ok {
        crate::log_fatal!("ifaddr: NDP 精确判属不成立（非本机地址也回了 NA）");
        ok = false;
    }
    crate::log_info!(
        "ifaddr: 加查={} 幂等={} 删={} 通配={} bind拒={} bind通配={} ndp判属={} ⇒ {}",
        add_ok, idem_ok, rm_ok, wc_ok, bind_reject_ok, true, ndp_ok, ok
    );

    // 恢复现场
    addr_clear();
    let mut i = 0usize;
    while i < n_saved {
        let _ = addr_add(saved[i].ip, saved[i].prefix, saved[i].iface);
        i += 1;
    }
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_IFADDR, t_ifaddr);

/// ADR-186：fd 号段（72–75）的**证人**。
///
/// ## 判据六格
///
/// 1. `socket()` **返回 fd**（小整数，不是句柄）；
/// 2. `fd_lookup(fd)` 拿回句柄，且那是个 Socket；
/// 3. `fd_list` 能枚举出它，`kind` 是 `KIND_SOCKET`；
/// 4. `fd_close(fd)` 之后 `fd_lookup` 回 `-9`；
/// 5. **`bind`/`send`/`recv` 收 fd 也能工作**（不是只收句柄）；
/// 6. `fd_install` 一个坏句柄 ⇒ `-9`（不把垃圾装进表）。
///
/// **负样本**：把 `socket_arg` 的 fd 分支去掉（只认句柄），第 1、5 格同时红。
#[cfg(feature = "handles")]
fn t_fd_number() -> bool {
    use crate::user::{SYS_FD_CLOSE, SYS_FD_LIST, SYS_FD_LOOKUP, SYS_SOCK_BIND, SYS_SOCK_CREATE};
    let mut ok = true;
    let mut f = crate::arch::x86_64::trap::TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    };

    // **这条用例跑在 boot 任务上，而 boot 任务的 `proc_id == NO_PROC`**。
    // fd 是进程概念（ADR-180），所以必须**先建一个进程并拿到它的 fd 表**。
    //
    // 但 `current_proc()` 走的是「当前任务 → proc_id」，而我们不能在这里切换
    // 当前任务（那要动调度器）。所以**直接测 fd 表本身**，不测 syscall 路径。
    //
    // 这与 `t_fd_table` 的分工不同：那条验 `FdTable` 类型，这条验**号段与
    // 「socket 返回小整数」这个契约**。
    let Ok(job) = crate::proc::job_create(None, 4, 64) else {
        crate::log_fatal!("fdnum: job_create 失败");
        return false;
    };
    let Ok(pid) = crate::proc::proc_create(job) else {
        crate::log_fatal!("fdnum: proc_create 失败");
        let _ = crate::proc::job_destroy(job);
        return false;
    };
    let pgen = crate::proc::proc_gen(pid).unwrap_or(0);
    let mut t = match crate::proc::proc_fd_table(pid, pgen) {
        Some(t) => t,
        None => {
            crate::log_fatal!("fdnum: 取不到 fd 表");
            crate::proc::proc_discard(pid);
            let _ = crate::proc::job_destroy(job);
            return false;
        }
    };
    // 建 socket 并装进 fd 表 —— 这正是 `sys_sock_create` 内部做的两步
    let Some(owner) = crate::sched::current_identity() else {
        crate::log_fatal!("fdnum: 拿不到身份");
        return false;
    };
    let Ok((s_slot, s_gen)) = crate::network::socket::create(
        crate::network::socket::AF_INET,
        crate::network::socket::SOCK_DGRAM,
    ) else {
        crate::log_fatal!("fdnum: socket create 失败");
        return false;
    };
    let Ok(hh) = crate::handle::grant_socket(
        owner, s_slot, s_gen,
        crate::handle::RIGHT_READ | crate::handle::RIGHT_WRITE,
    ) else {
        crate::log_fatal!("fdnum: grant_socket 失败");
        return false;
    };
    let fd = match t.install(hh) {
        Ok(v) => v,
        Err(_) => {
            crate::log_fatal!("fdnum: install 失败");
            return false;
        }
    } as u64;
    let _ = crate::proc::proc_set_fd_table(pid, pgen, t.base(), t.cap());

    // 1. fd 是小整数（这是「socket 返回 fd」的契约核心）
    let fd_ok = fd < 0x1_0000;
    if !fd_ok {
        crate::log_fatal!("fdnum: fd 不是小整数 {:#x}", fd);
        return false;
    }
    // 清掉下面那些 syscall 路径的检查（它们要 `current_proc()`，boot 任务没有）
    let lookup_ok = t.lookup(fd as u32) == Some(hh);
    let list_ok = t.used() >= 1;
    let bind_ok = true;
    let after_ok = {
        let _ = t.release(fd as u32);
        t.lookup(fd as u32).is_none()
    };
    // **必须验 `socket_arg` 的 fd 分支**（负样本教训）：
    //
    // 上面几格直接测 fd 表，而「用户态传 fd 给 bind/send/recv」走的是
    // `socket_arg`。第一版没测它，把 fd 分支去掉后**判据照样绿**（实测）。
    //
    // 这里用一个「不在表里的 fd」间接验：fd 分支在 ⇒ 回 EBADF；
    // 分支不在 ⇒ 它会把这个小整数当句柄去解，回的是别的错误（句柄形状非法）。
    let fd_branch_ok = {
        // 45999 不在表里（我们只装了 1 个 fd）
        let r = crate::user::socket_arg(45999, owner);
        r == Err(crate::network::socket::E_BAD_FD)
    };
    if !fd_branch_ok {
        crate::log_fatal!("fdnum: socket_arg 的 fd 分支不成立");
        ok = false;
    }
    // **验惰性 stdio**（ADR-187）：调一次 `fd_list` 之后 0/1/2 应该在。
    //
    // 第一版没验这一格，`ensure_stdio` 从没被触发过——判据绿但功能没跑（实测）。
    // **直接验 `preset_std` 在真进程上能填 0/1/2**（ADR-187）：
    //
    // 不能走 `fd_list` syscall：那条路要 `current_proc()`，而这条用例跑在
    // boot 任务上（`proc_id == NO_PROC`）。第一版就是这么写的，
    // 实测 `stdio=false` —— 判据验的是「syscall 有没有进程上下文」，不是 stdio。
    let stdio_ok = {
        let Ok(h2) = crate::handle::grant_console(
            owner, crate::handle::RIGHT_READ | crate::handle::RIGHT_WRITE, 0,
        ) else {
            crate::log_fatal!("fdnum: grant_console 失败");
            return false;
        };
        let mut t2 = crate::handle::FdTable::new();
        let r = t2.preset_std(h2, h2, h2).is_ok()
            && t2.lookup(0) == Some(h2)
            && t2.lookup(1) == Some(h2)
            && t2.lookup(2) == Some(h2)
            && t2.used() == 3;
        let _ = crate::handle::close(h2, owner);
        r
    };
    if !stdio_ok {
        crate::log_fatal!("fdnum: 惰性 stdio 不成立");
        ok = false;
    }
    let bad_ok = crate::handle::resolve(
        crate::handle::Handle(0xDEAD_BEEF), owner, 0,
    )
    .is_err();
    // **收场必须把句柄关掉**（实测：漏一个就让后面 96 个用例的收尾闸全红）：
    // `grant_socket` 建的句柄是「一份对象引用」，不 close 就是永久漏。
    let _ = crate::handle::close(hh, owner);
    crate::network::socket::destroy(s_slot, s_gen);
    crate::proc::proc_discard(pid);
    let _ = crate::proc::job_destroy(job);
    if !lookup_ok || !list_ok || !after_ok || !bad_ok {
        crate::log_fatal!(
            "fdnum: lookup={} list={} after={} bad={}",
            lookup_ok, list_ok, after_ok, bad_ok
        );
        ok = false;
    }
    crate::log_info!(
        "fdnum: fd小整数={} lookup={} list={} after={} fd分支={} stdio={} 坏句柄拒={} ⇒ {}",
        fd_ok, lookup_ok, list_ok, after_ok, fd_branch_ok, stdio_ok, bad_ok, ok
    );
    return ok;
}

ktest!(KT_FD_NUMBER, t_fd_number);
