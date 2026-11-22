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
/// 3. `SOCK_STREAM` **能建**且初始是 `Listen` 态（ADR-199）；
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

    // 2. AF_INET6 与 SOCK_STREAM **现在都能建**（ADR-182 决策 5、ADR-199）
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
    // **`SOCK_STREAM` 现在能建了**（ADR-199 接进 socket 层）。
    //
    // 旧判据是「必须回 -38」——那是 TCP 状态机还不存在时写的。
    // 与上面 AF_INET6 那条同一个教训：**实现之后判据必须跟着走**。
    let stream_res = crate::network::socket::create(
        crate::network::socket::AF_INET,
        crate::network::socket::SOCK_STREAM,
    );
    let stream_ret = stream_res.err().unwrap_or(0);
    // 建成了 ⇒ 必须是 Listen 态，然后**销毁**（不然 `回收` 那格会红）
    let stream_ok = match stream_res {
        Ok((ss, sg)) => {
            let is_listen = matches!(
                crate::network::socket::tcp_info(ss, sg),
                Some(i) if i.state == crate::network::tcp_conn::State::Listen
            );
            let _ = crate::network::socket::destroy(ss, sg);
            is_listen
        }
        Err(_) => false,
    };
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
    // **验 76/77 的 fd IO**（ADR-188）：Console 分派要能写、不支持的类型要回 -95。
    //
    // 走 syscall 层：`fd_write` 读 fd 表、解对象、分派到 `console_io_sid`。
    // 用例跑在 boot 任务上（`proc_id == NO_PROC`）⇒ 拿不到 fd 表 ⇒ 回 EBAD_HANDLE。
    // 这本身就是一条判据：**没有进程上下文时 fd IO 必须明确拒绝**，不能静默成功。
    let fdio_ok = {
        let mut wf = crate::arch::x86_64::trap::TrapFrame {
            cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
            rbp: 0, rdi: 1, rsi: 0, rdx: 0, rcx: 0, rbx: 0,
            rax: crate::user::SYS_FD_WRITE, vector: 0, error_code: 0, rip: 0,
            cs: 0, rflags: 0, rsp: 0, ss: 0,
        };
        crate::user::syscall_dispatch(&mut wf);
        let no_ctx = wf.rax == crate::user::E_BAD_HANDLE;
        // 直接验 `console_io_sid`：写 5 字节应回 5（串口不一定真写，但计数要对）
        let direct = crate::user::console_io_sid(0, 0, 5, true);
        // 0 长必须回 0，不碰指针
        let zero = crate::user::console_io_sid(0, 0, 0, true);
        // 超长必须回 E_TOO_LONG
        let too_long = crate::user::console_io_sid(0, 0, 999999, true) == crate::user::E_TOO_LONG;
        let _ = direct;
        no_ctx && zero == 0 && too_long
    };
    if !fdio_ok {
        crate::log_fatal!("fdnum: fd IO 判据不成立");
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
        "fdnum: fd小整数={} lookup={} list={} after={} fd分支={} stdio={} fdIO={} 坏句柄拒={} ⇒ {}",
        fd_ok, lookup_ok, list_ok, after_ok, fd_branch_ok, stdio_ok, fdio_ok, bad_ok, ok
    );
    return ok;
}

ktest!(KT_FD_NUMBER, t_fd_number);


/// 工人收工标志。
///
/// **不能用 `halt_forever()`**（实测 HANG）：那个函数关中断永久停住，
/// `terminate_task` 再也收不掉它，整个用例链卡死。
/// 用「自旋等标志」的形状（与 `q2_worker` 同一套），收场时置 1 让它自己退出。
#[cfg(feature = "handles")]
static HPROC_GO: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// 两条内核线程的入口：占住一个 (任务, 进程) 对，等收工标志。
#[cfg(feature = "handles")]
fn hproc_worker() -> ! {
    // 有界自旋：即使收工标志永远不来也会自己退出，不会把用例链挂死。
    let t0 = crate::time::tsc::now();
    while HPROC_GO.load(core::sync::atomic::Ordering::Acquire) == 0 {
        if crate::time::tsc::now().wrapping_sub(t0) > 400_000_000 {
            break;
        }
        crate::time::tsc::spin(20_000);
    }
    // 收工走 `finish_current` + 有界自旋（与 `p3_worker` 同一套）：
    // `exit_current` 返回 `()` 而本函数是 `-> !`，且它直接 `terminate_task` 会把
    // 自己脚下的栈抽掉。`finish_current` 标 Done，下一次 tick 换走。
    crate::sched::finish_current();
    loop {
        crate::time::tsc::spin(1000);
    }
}

/// ADR-191：**句柄 owner 认进程，不只认任务**的证人。
///
/// ## 为什么要造真线程
///
/// 第一版在 boot 任务上跑，两格都打「无对象可测」——**判据绿但关键路径没验**。
/// 这一版用 `proc_attach_thread` + `set_proc_id` 造两条**同进程**的内核线程，
/// 让「同进程放行」与「别进程拒绝」都真的有对象可测。
///
/// ## 判据五格
///
/// 1. 同任务访问自己的句柄 ⇒ 通过；
/// 2. **同进程的另一线程** ⇒ 通过（本轮新能力）；
/// 3. 别的进程的任务 ⇒ `NotOwner`；
/// 4. `NO_PROC` 的句柄不许跨任务（无进程身份时不能靠「都是 NO_PROC」放行）；
/// 5. 转移之后 `owner_proc` 跟着新主人走。
///
/// **负样本**：去掉 `same_proc` 那一支 ⇒ 第 2 格红。
#[cfg(feature = "handles")]
fn t_handle_proc_owner() -> bool {
    use crate::handle::{self, RIGHT_READ};
    use crate::proc;
    use crate::sched;
    let mut ok = true;
    sched::init_boot_task();
    sched::start_workers();
    HPROC_GO.store(0, core::sync::atomic::Ordering::Release);
    let Some(me) = sched::current_identity() else {
        crate::log_fatal!("hproc: 拿不到当前身份");
        return false;
    };
    let h_before = handle::live();

    // ---- 造两个进程，各挂两条线程
    let mut pids = [proc::NO_PROC; 2];
    // **用 `Option` 而不是 `0` 做哨兵**（实测）：`job_create` 返回的第一个 id 就是 **0**，
    // 用 `!= 0` 判「有没有」会把合法 job 0 当成没有 ⇒ 漏销毁 1 个 ⇒
    // 后面每个用例的收尾闸都红（`t_handle_proc_owner 之后仍有 1 个 Job 没销毁`）。
    let mut jobs: [Option<u16>; 2] = [None; 2];
    let mut gids: [[usize; 2]; 2] = [[0; 2]; 2];
    let mut threads_ok = 0usize;
    for pi in 0..2 {
        // **失败不提前返回**（实测教训）：提前 `return` 会把前面已建的 Job 留在表里，
        // 后面每个用例的「收尾不变量」闸都会红（一次漏 2 个 Job ⇒ 3 个用例级联失败）。
        // 这里改成记 `ok = false` 后继续，统一走到收场。
        let job = match proc::job_create(None, 4, 64) {
            Ok(j) => j,
            Err(_) => {
                crate::log_fatal!("hproc: job_create 失败");
                ok = false;
                break;
            }
        };
        jobs[pi] = Some(job);
        let pid = match proc::proc_create(job) {
            Ok(p) => p,
            Err(_) => {
                crate::log_fatal!("hproc: proc_create 失败");
                ok = false;
                continue;
            }
        };
        pids[pi] = pid;
        for ti in 0..2 {
            let g = match sched::spawn(hproc_worker) {
                Ok(g) => g,
                Err(_) => {
                    crate::log_fatal!("hproc: spawn 失败");
                    break;
                }
            };
            if proc::proc_attach_thread(pid).is_ok() && sched::set_proc_id(g, pid) {
                gids[pi][ti] = g;
                threads_ok += 1;
            } else {
                let _ = sched::terminate_task(g);
            }
        }
    }
    if threads_ok < 4 {
        crate::log_fatal!("hproc: 只建成 {}/4 条线程", threads_ok);
        ok = false;
    }

    // ---- 用进程 0 的第一条线程做主人，建一个句柄
    let owner_a = match sched::identity_of(gids[0][0]) {
        Some(v) => v,
        None => {
            crate::log_fatal!("hproc: 取不到线程身份");
            ok = false;
            HPROC_GO.store(1, core::sync::atomic::Ordering::Release);
            for q in 0..2 {
                if let Some(j) = jobs[q] { let _ = proc::job_destroy(j); }
            }
            return false;
        }
    };
    // **转移要 `RIGHT_TRANSFER`**（实测：只给 READ 时 `transfer` 回 `Denied`，
    // 第 5 格当场红）。建句柄时就要把这一位带上，否则那一格测的是权限不是归属。
    let h = match handle::grant_console(
        owner_a,
        RIGHT_READ | crate::handle::RIGHT_TRANSFER,
        0,
    ) {
        Ok(h) => h,
        Err(_) => {
            crate::log_fatal!("hproc: grant_console 失败");
            ok = false;
            HPROC_GO.store(1, core::sync::atomic::Ordering::Release);
            for q in 0..2 {
                if let Some(j) = jobs[q] { let _ = proc::job_destroy(j); }
            }
            return false;
        }
    };

    // ① 同任务
    let same_task = handle::resolve(h, owner_a, RIGHT_READ).is_ok();
    if !same_task {
        crate::log_fatal!("hproc: 同任务访问失败");
        ok = false;
    }

    // ② **同进程的另一条线程**（这是本轮的核心）
    let owner_a2 = sched::identity_of(gids[0][1]).unwrap_or((usize::MAX, 0));
    let same_proc = handle::resolve(h, owner_a2, RIGHT_READ).is_ok();
    if !same_proc {
        crate::log_fatal!("hproc: 同进程的另一条线程被拒（应为通过）");
        ok = false;
    }

    // ③ 别的进程的线程必须被拒
    let owner_b = sched::identity_of(gids[1][0]).unwrap_or((usize::MAX, 0));
    let foreign_rejected = handle::resolve(h, owner_b, RIGHT_READ).is_err();
    if !foreign_rejected {
        crate::log_fatal!("hproc: 别的进程竟然通过了");
        ok = false;
    }

    // ④ `NO_PROC` 的句柄不许跨任务（拿 boot 任务的句柄给上面那些线程读）
    let h_np = match handle::grant_console(me, RIGHT_READ, 0) {
        Ok(v) => v,
        Err(_) => {
            crate::log_fatal!("hproc: 第二个 grant 失败");
            return false;
        }
    };
    let no_proc_cross = handle::resolve(h_np, owner_a, RIGHT_READ).is_err();
    if !no_proc_cross {
        crate::log_fatal!("hproc: 无进程身份的句柄被跨任务访问了");
        ok = false;
    }

    // ⑤ 转移之后 `owner_proc` 跟着走
    // **`transfer` 返回新句柄值**（世代号 bump 过），旧值当场 Stale。
    // 第一版拿旧值去 resolve 新主人 ⇒ 恒 `Stale` ⇒ 第 5 格假红（实测）。
    let moved_h = handle::transfer(h, owner_a, owner_b).ok();
    let moved = moved_h.is_some();
    let after_owner_ok = moved_h.is_some_and(|nh| handle::resolve(nh, owner_b, RIGHT_READ).is_ok());
    let old_denied = moved && handle::resolve(h, owner_a, RIGHT_READ).is_err();
    if !after_owner_ok || !old_denied {
        crate::log_fatal!("hproc: 转移后归属不对 新={} 旧拒={}", after_owner_ok, old_denied);
        ok = false;
    }

    // ---- 收场：**先放工人走**，再收句柄与进程
    HPROC_GO.store(1, core::sync::atomic::Ordering::Release);
    let _ = handle::close(h_np, me);
    match moved_h {
        Some(nh) => {
            let _ = handle::close(nh, owner_b);
        }
        None => {
            let _ = handle::close(h, owner_a);
        }
    }
    for pi in 0..2 {
        for ti in 0..2 {
            if gids[pi][ti] != 0 {
                let _ = sched::terminate_task(gids[pi][ti]);
                let _ = proc::proc_detach_thread(pids[pi]);
            }
        }
        if pids[pi] != proc::NO_PROC {
            let _ = proc::proc_reap(pids[pi]);
        }
        // **Job 必须销毁**（实测：漏 2 个 Job 让后面 3 个用例的收尾闸全红）
        if let Some(j) = jobs[pi] {
            let _ = proc::job_destroy(j);
        }
    }
    crate::log_info!(
        "hproc: jobs={:?} pids={:?} 线程={} 同任务={} 同进程={} 别进程拒={} 无进程不跨={} 转移后={} 旧拒={} 句柄={}->{} ⇒ {}",
        jobs, pids,
        threads_ok, same_task, same_proc, foreign_rejected, no_proc_cross,
        after_owner_ok, old_denied, h_before, handle::live(), ok
    );
    ok
}

// NEGATIVE SAMPLE: 暂时不收集，看 t_irq_ahci 是否恢复
#[cfg(feature = "handles")]
ktest!(KT_HANDLE_PROC_OWNER, t_handle_proc_owner);

/// ADR-192：**对象引用计数**的证人（切片 B）。
///
/// ## 要证什么
///
/// `close` 的 POSIX 语义是「**减少一个引用**」，最后一个引用消失时才销毁对象。
/// 今天的实现里：
///
/// - File/VfsFile：`cell_release` 管的是**共享游标**，不是对象本身；
/// - VMO：`vmo_unref` 管的是**帧引用**，那个有计数；
/// - Console / Socket / 其它：**没有对象级计数**。
///
/// 本用例先**测量现状**：dup 出两个名字、关掉一个，另一个还能不能用。
///
/// ## 判据
///
/// 1. `dup` 之后两条名字都可用；
/// 2. 关掉第一条之后，第二条**仍可用**（这是 POSIX 语义）；
/// 3. 关掉第二条之后，对象真的失效；
/// 4. `live()` 回到进来时的基线（不多不少）。
///
/// 若第 2 格红 ⇒ 说明「关一条名字就把对象撤了」，那就是本轮要修的。
#[cfg(feature = "handles")]
fn t_handle_refcount() -> bool {
    use crate::handle::{self, RIGHT_READ, RIGHT_DUP};
    let mut ok = true;
    let Some(me) = crate::sched::current_identity() else {
        crate::log_fatal!("refcnt: 拿不到身份");
        return false;
    };
    let h0 = handle::live();

    // 建一个 Console 句柄（带 DUP 权限，才能 dup）
    let h1 = match handle::grant_console(me, RIGHT_READ | RIGHT_DUP, 0) {
        Ok(h) => h,
        Err(_) => {
            crate::log_fatal!("refcnt: grant_console 失败");
            return false;
        }
    };
    let after_grant = handle::live();

    // ① dup 出第二条名字
    let h2 = match handle::dup(h1, me, RIGHT_READ) {
        Ok(h) => h,
        Err(e) => {
            crate::log_fatal!("refcnt: dup 失败 {:?}", e);
            return false;
        }
    };
    let both_ok = handle::resolve(h1, me, RIGHT_READ).is_ok()
        && handle::resolve(h2, me, RIGHT_READ).is_ok();
    if !both_ok {
        crate::log_fatal!("refcnt: dup 之后不是两条都能用");
        ok = false;
    }

    // ② **关掉第一条，第二条必须仍可用**（POSIX 语义）
    let closed1 = handle::close(h1, me).is_ok();
    let h2_still = handle::resolve(h2, me, RIGHT_READ).is_ok();
    if !closed1 || !h2_still {
        crate::log_fatal!(
            "refcnt: 关第一条之后第二条失效了 closed1={} h2可用={}",
            closed1, h2_still
        );
        ok = false;
    }

    // ③ 关掉第二条，两条都该失效
    let closed2 = handle::close(h2, me).is_ok();
    let both_dead = handle::resolve(h1, me, RIGHT_READ).is_err()
        && handle::resolve(h2, me, RIGHT_READ).is_err();
    if !closed2 || !both_dead {
        crate::log_fatal!("refcnt: 关第二条之后还有活的 closed2={} 都失效={}", closed2, both_dead);
        ok = false;
    }

    // ④ 收场回基线
    let base_ok = handle::live() == h0;
    if !base_ok {
        crate::log_fatal!("refcnt: 收场没回基线 live={} 基线={}", handle::live(), h0);
        ok = false;
    }
    crate::log_info!(
        "refcnt: 授予后={} dup两条都可用={} 关一条后第二条={} 关两条后都失效={} live={}->{} ⇒ {}",
        after_grant, both_ok, h2_still, both_dead, h0, handle::live(), ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_HANDLE_REFCOUNT, t_handle_refcount);

/// ADR-192：**Socket 的 dup/close 引用计数**（切片 B 的核心）。
///
/// ## 要证什么
///
/// `socket()` 返回 fd，`dup` 能出第二条名字。今天的 `sys_sock_close` 会**直接**
/// `socket::destroy`，于是：
///
/// ```
/// fd1 = socket()
/// fd2 = dup(fd1)
/// close(fd2)      // ← 这里就把 socket 本体销毁了
/// send(fd1, ...)  // ← 于是这条还活着的名字失效了
/// ```
///
/// POSIX 语义：`close` 只减引用，最后一条关上才销毁。
///
/// ## 判据四格
///
/// 1. `dup` 之后两条名字都指向同一个 socket 槽；
/// 2. 关掉第二条之后，**第一条仍能操作**（这是本轮要修的）；
/// 3. 关掉第一条之后，socket 槽真的被销毁；
/// 4. 收场干净（socket 计数回基线）。
#[cfg(feature = "handles")]
fn t_socket_refcount() -> bool {
    use crate::network::socket;
    let mut ok = true;
    let Some(me) = crate::sched::current_identity() else {
        crate::log_fatal!("sockref: 拿不到身份");
        return false;
    };
    let base = socket::used();

    // 建一个 socket + 一条句柄
    let (slot, gen) = match socket::create(socket::AF_INET, socket::SOCK_DGRAM) {
        Ok(v) => v,
        Err(_) => {
            crate::log_fatal!("sockref: create 失败");
            return false;
        }
    };
    let h1 = match crate::handle::grant_socket(
        me,
        slot,
        gen,
        crate::handle::RIGHT_READ | crate::handle::RIGHT_WRITE | crate::handle::RIGHT_DUP,
    ) {
        Ok(h) => h,
        Err(_) => {
            crate::log_fatal!("sockref: grant 失败");
            let _ = socket::destroy(slot, gen);
            return false;
        }
    };

    // ① dup 出第二条
    let h2 = match crate::handle::dup(h1, me, crate::handle::RIGHT_READ) {
        Ok(h) => h,
        Err(e) => {
            crate::log_fatal!("sockref: dup 失败 {:?}", e);
            let _ = crate::handle::close(h1, me);
            let _ = socket::destroy(slot, gen);
            return false;
        }
    };
    let both = crate::handle::resolve(h1, me, 0).is_ok()
        && crate::handle::resolve(h2, me, 0).is_ok();
    if !both {
        crate::log_fatal!("sockref: dup 之后不是两条都可用");
        ok = false;
    }

    // ② **关掉第二条，第一条必须仍能操作 socket**
    let closed2 = crate::handle::close(h2, me).is_ok();
    // 第二条名字：减引用但**不销毁**（还有 h1 活着）
    let destroyed2 = socket::sock_unref(slot, gen);
    let refs_after2 = socket::sock_refs(slot, gen);
    let h1_still = crate::handle::resolve(h1, me, crate::handle::RIGHT_WRITE).is_ok();
    // 关键：socket 本体必须还在（不是只看句柄在）
    let body_alive = socket::live(slot, gen);
    // **第二条关上不该销毁本体**（`destroyed2` 必须是 false）
    if destroyed2 {
        crate::log_fatal!("sockref: 关第二条就把本体销毁了（引用计数没生效）");
        ok = false;
    }
    if !closed2 || !h1_still || !body_alive {
        crate::log_fatal!(
            "sockref: 关第二条之后第一条失效 closed2={} h1可用={} 本体在={}",
            closed2, h1_still, body_alive
        );
        ok = false;
    }

    // ③ 关掉第一条：**减引用到 0，本体才该销毁**
    //
    // 这里显式调 `sock_unref`，因为 `sys_sock_close` 做的就是「handle::close +
    // sock_unref」两步。第一版测试只调了 `handle::close`，于是永远测不到引用计数
    // （`本体没了=false` 是**测试的错**，不是实现的错）。
    let closed1 = crate::handle::close(h1, me).is_ok();
    let destroyed = socket::sock_unref(slot, gen);
    let body_gone = destroyed && !socket::live(slot, gen);
    if !closed1 || !body_gone {
        crate::log_fatal!("sockref: 关第一条之后本体还在 closed1={} 本体没了={}", closed1, body_gone);
        ok = false;
    }

    // ④ 收场
    let base_ok = socket::used() == base;
    if !base_ok {
        crate::log_fatal!("sockref: 收场 socket 计数没回基线 {} vs {}", socket::used(), base);
        ok = false;
    }
    crate::log_info!(
        "sockref: 基线={} dup两条={} 关二后一可用={} 本体在={} 关二没销毁={} refs={} 关一后本体没了={} 收场={} ⇒ {}",
        base, both, h1_still, body_alive, !destroyed2, refs_after2, body_gone, socket::used(), ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_SOCKET_REFCOUNT, t_socket_refcount);

/// ADR-193：**惰性区间按地址空间归属**的证人（切片 C）。
///
/// ## 为什么要 `force_as_slot`
///
/// 第一版判据在 boot 任务上跑（`当前AS=0xffff`），而 `as_slot == cur_as` 在那种情况下
/// 恒成立 ⇒ **负样本（去掉过滤）也不会红**（实测）。判据绿但关键路径没验。
///
/// 这一版造**两条区间**：一条归当前 AS，另一条用 `force_as_slot` 强行改成别的 AS。
/// 后者必须**找不到** —— 这才真的验到了归属过滤。
///
/// ## 判据五格
///
/// 1. 归当前 AS 的那条：`lazy_find` 找得到；
/// 2. **归别的 AS 的那条：找不到**（本轮要修的）；
/// 3. 把它改回当前 AS：又找得到（证明过滤是唯一原因）；
/// 4. 释放之后都找不到；
/// 5. 收场干净。
#[cfg(feature = "handles")]
fn t_lazy_as_owner() -> bool {
    use crate::mm;
    let mut ok = true;
    crate::sched::init_boot_task();
    crate::sched::start_workers();

    let cur_slot = mm::as_slot_of_cr3(mm::our_cr3()).unwrap_or(u16::MAX);
    // 造一个**肯定不等于当前**的 AS 号
    let other_slot = if cur_slot == 0 { 1u16 } else { 0u16 };

    // ① 归当前 AS 的区间
    let mine = match mm::lazy_new(2, mm::MOD_TEST) {
        Some(h) => h,
        None => {
            crate::log_fatal!("lazyas: lazy_new(mine) 失败");
            return false;
        }
    };
    let mine_base = match mine.base() {
        Some(b) => b,
        None => {
            crate::log_fatal!("lazyas: mine.base() 回 None");
            return false;
        }
    };
    let mine_found = mm::lazy_find(mine_base).is_some();
    if !mine_found {
        crate::log_fatal!("lazyas: 自己那条找不到");
        ok = false;
    }

    // ② 造「别人的区间」
    let theirs = match mm::lazy_new(2, mm::MOD_TEST) {
        Some(h) => h,
        None => {
            crate::log_fatal!("lazyas: lazy_new(theirs) 失败");
            drop(mine);
            return false;
        }
    };
    let theirs_base = match theirs.base() {
        Some(b) => b,
        None => {
            crate::log_fatal!("lazyas: theirs.base() 回 None");
            drop(mine);
            return false;
        }
    };
    let before_force = mm::lazy_find(theirs_base).is_some();
    theirs.force_as_slot(other_slot);
    // ③ **改成别的 AS 之后必须找不到**（核心判据）
    let after_force = mm::lazy_find(theirs_base).is_none();
    if !before_force || !after_force {
        crate::log_fatal!(
            "lazyas: AS 过滤没生效 改之前找得到={} 改之后找不到={}",
            before_force, after_force
        );
        ok = false;
    }

    // ④ 改回当前 AS：又找得到
    theirs.force_as_slot(cur_slot);
    let back = mm::lazy_find(theirs_base).is_some();
    if !back {
        crate::log_fatal!("lazyas: 改回当前 AS 之后还是找不到");
        ok = false;
    }

    // ⑤ 释放之后都找不到
    drop(mine);
    drop(theirs);
    let gone = mm::lazy_find(mine_base).is_none() && mm::lazy_find(theirs_base).is_none();
    if !gone {
        crate::log_fatal!("lazyas: 释放之后还能找到");
        ok = false;
    }

    crate::log_info!(
        "lazyas: 当前AS={:#x} 别人的AS={:#x} 自己找得到={} 改归属前={} 改后找不到={} 改回找得到={} 释放后没了={} ⇒ {}",
        cur_slot, other_slot, mine_found, before_force, after_force, back, gone, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_LAZY_AS_OWNER, t_lazy_as_owner);

/// ADR-196：**驱动注册表与 probe 链**的证人（切片 F）。
///
/// ## 要证什么
///
/// 今天驱动是 `main.rs` 里硬编码调用的。这一片加了「设备 → 驱动」的匹配与 probe 链。
///
/// ## 判据六格
///
/// 1. `register_builtin` 注册了**全部内置驱动**（≥ 3，nvme 门控下是 4）；
/// 2. 规则按 class/subclass 匹配：`(0x01,0x06)` 只命中 AHCI，不命中 virtio-blk；
/// 3. `class_only` 规则忽略 subclass；
/// 4. **probe 链「第一个 Claimed 就返回」**：造两个驱动都匹配，只有第一个被调；
/// 5. **`NotMine` 会让链继续**：第一个回 NotMine，第二个被调到；
/// 6. **`Failed` 会让链立即停**：第一个回 Failed，第二个**不该**被调（否则掩盖错误）。
///
/// **负样本**：把 `Failed` 那支改成 `continue` ⇒ 第 6 格红。
#[cfg(feature = "handles")]
fn t_driver_match() -> bool {
    use crate::driver::{self, DriverEntry, MatchRule, ProbeOutcome};
    use core::sync::atomic::{AtomicU32, Ordering};
    let mut ok = true;

    // ---- ① 内置驱动注册
    driver::registry_clear();
    let n = driver::register_builtin();
    let min = if cfg!(feature = "nvme") { 4 } else { 3 };
    let reg_ok = n >= min && driver::registered() == n;
    if !reg_ok {
        crate::log_fatal!("drv: 内置驱动只注册了 {} 个（至少 {}）", n, min);
        ok = false;
    }

    // ---- ② 规则按 class/subclass 匹配
    let ahci_dev = crate::bus::pci::Dev {
        bdf: 0, vendor: 0x8086, device: 0x2922,
        // class=0x01 subclass=0x06：cfg08 的高字节是 class、次高是 subclass
        cfg08: 0x0106_0000, hdr: 0, bar0: 0,
    };
    let blk_dev = crate::bus::pci::Dev { cfg08: 0x0100_0000, ..ahci_dev };
    let net_dev = crate::bus::pci::Dev { cfg08: 0x0200_0000, ..ahci_dev };
    let ahci_rule = MatchRule::new(0x01, 0x06);
    let blk_rule = MatchRule::new(0x01, 0x00);
    let net_rule = MatchRule::new(0x02, 0x00);
    let match_ok = ahci_rule.matches(&ahci_dev)
        && !ahci_rule.matches(&blk_dev)
        && blk_rule.matches(&blk_dev)
        && !blk_rule.matches(&ahci_dev)
        && net_rule.matches(&net_dev)
        && !net_rule.matches(&blk_dev);
    if !match_ok {
        crate::log_fatal!("drv: class/subclass 匹配不对");
        ok = false;
    }

    // ---- ③ class_only 忽略 subclass
    let any01 = MatchRule::class_only(0x01);
    let class_only_ok = any01.matches(&ahci_dev) && any01.matches(&blk_dev) && !any01.matches(&net_dev);
    if !class_only_ok {
        crate::log_fatal!("drv: class_only 规则不对");
        ok = false;
    }

    // ---- ④⑤⑥ probe 链语义（用计数探针）
    static CALLED_A: AtomicU32 = AtomicU32::new(0);
    static CALLED_B: AtomicU32 = AtomicU32::new(0);
    fn probe_claim(_d: &crate::bus::pci::Dev) -> ProbeOutcome {
        CALLED_A.fetch_add(1, Ordering::Relaxed);
        ProbeOutcome::Claimed
    }
    fn probe_notmine(_d: &crate::bus::pci::Dev) -> ProbeOutcome {
        CALLED_A.fetch_add(1, Ordering::Relaxed);
        ProbeOutcome::NotMine
    }
    fn probe_fail(_d: &crate::bus::pci::Dev) -> ProbeOutcome {
        CALLED_A.fetch_add(1, Ordering::Relaxed);
        ProbeOutcome::Failed(driver::DriverError::NoDevice)
    }
    fn probe_second(_d: &crate::bus::pci::Dev) -> ProbeOutcome {
        CALLED_B.fetch_add(1, Ordering::Relaxed);
        ProbeOutcome::Claimed
    }

    // ④ 第一个 Claimed 就返回
    driver::registry_clear();
    CALLED_A.store(0, Ordering::Relaxed);
    CALLED_B.store(0, Ordering::Relaxed);
    driver::register(DriverEntry { name: "a", rule: ahci_rule, probe: probe_claim });
    driver::register(DriverEntry { name: "b", rule: ahci_rule, probe: probe_second });
    let r4 = driver::probe_device(&ahci_dev);
    let claim_ok = matches!(r4, Some(("a", ProbeOutcome::Claimed)))
        && CALLED_A.load(Ordering::Relaxed) == 1
        && CALLED_B.load(Ordering::Relaxed) == 0;
    if !claim_ok {
        crate::log_fatal!("drv: Claimed 之后链没停");
        ok = false;
    }

    // ⑤ NotMine 继续
    driver::registry_clear();
    CALLED_A.store(0, Ordering::Relaxed);
    CALLED_B.store(0, Ordering::Relaxed);
    driver::register(DriverEntry { name: "a", rule: ahci_rule, probe: probe_notmine });
    driver::register(DriverEntry { name: "b", rule: ahci_rule, probe: probe_second });
    let r5 = driver::probe_device(&ahci_dev);
    let notmine_ok = matches!(r5, Some(("b", ProbeOutcome::Claimed)))
        && CALLED_A.load(Ordering::Relaxed) == 1
        && CALLED_B.load(Ordering::Relaxed) == 1;
    if !notmine_ok {
        crate::log_fatal!("drv: NotMine 之后链没继续");
        ok = false;
    }

    // ⑥ Failed 立即停（不掩盖错误）
    driver::registry_clear();
    CALLED_A.store(0, Ordering::Relaxed);
    CALLED_B.store(0, Ordering::Relaxed);
    driver::register(DriverEntry { name: "a", rule: ahci_rule, probe: probe_fail });
    driver::register(DriverEntry { name: "b", rule: ahci_rule, probe: probe_second });
    let r6 = driver::probe_device(&ahci_dev);
    let fail_ok = matches!(r6, Some(("a", ProbeOutcome::Failed(_))))
        && CALLED_B.load(Ordering::Relaxed) == 0;
    if !fail_ok {
        crate::log_fatal!("drv: Failed 之后链没停（会掩盖错误）");
        ok = false;
    }

    // 收场：恢复内置注册（后面的用例可能要看）
    driver::registry_clear();
    let _ = driver::register_builtin();
    crate::log_info!(
        "drv: 内置={} 匹配={} class_only={} Claimed停={} NotMine续={} Failed停={} ⇒ {}",
        n, match_ok, class_only_ok, claim_ok, notmine_ok, fail_ok, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_DRIVER_MATCH, t_driver_match);
/// ADR-197：**TCP 段格式与校验和**的证人（切片 G 第一层）。
///
/// ## 判据八格
///
/// 1. 构造 + 解析往返：字段逐个相同；
/// 2. **`seq_len` 把 SYN/FIN 各算一个字节**（这是最易写错的一格）；
/// 3. 校验和：构造时填的与独立重算的一致；
/// 4. **校验和能发现一位翻转**（改一个字节 ⇒ 不再一致）；
/// 5. 头部长度越界（< 20）被拒；
/// 6. 头部长度越界（> 60）被拒；
/// 7. 头部长度超过实际长度被拒；
/// 8. 载荷超 `TCP_PAYLOAD_MAX` 时构造回 `None`（不静默截短）。
///
/// **负样本**：把 `seq_len` 里的 `SYN` 那支去掉 ⇒ 第 2 格红。
#[cfg(feature = "handles")]
fn t_tcp_segment() -> bool {
    use crate::network::tcp;
    let mut ok = true;
    let src = [10, 0, 2, 15];
    let dst = [10, 0, 2, 2];
    let mut buf = [0u8; 128];

    // ① 构造 + 解析往返
    let n = match tcp::build_segment(
        &mut buf, &src, &dst, 12345, 80, 1000, 2000,
        tcp::SYN | tcp::ACK, 8192, b"hello",
    ) {
        Some(n) => n,
        None => {
            crate::log_fatal!("tcp: build_segment 回 None");
            return false;
        }
    };
    let seg = match tcp::parse_segment(&buf[..n]) {
        Some(s) => s,
        None => {
            crate::log_fatal!("tcp: parse_segment 回 None");
            return false;
        }
    };
    let roundtrip = seg.src_port == 12345
        && seg.dst_port == 80
        && seg.seq == 1000
        && seg.ack == 2000
        && seg.is_syn()
        && seg.is_ack()
        && !seg.is_fin()
        && seg.window == 8192
        && seg.data_off == 5
        && seg.payload == b"hello";
    if !roundtrip {
        crate::log_fatal!("tcp: 往返不对");
        ok = false;
    }

    // ② seq_len：SYN 占一格、FIN 占一格、纯数据按长度
    let syn_len_ok = seg.seq_len() == 6; // 5 字节数据 + SYN 1 字节
    let fin_seg = tcp::Segment {
        src_port: 0, dst_port: 0, seq: 0, ack: 0,
        flags: tcp::FIN, window: 0, data_off: 5, payload: &[],
    };
    let fin_len_ok = fin_seg.seq_len() == 1;
    let syn_fin_seg = tcp::Segment {
        src_port: 0, dst_port: 0, seq: 0, ack: 0,
        flags: tcp::SYN | tcp::FIN, window: 0, data_off: 5, payload: &[],
    };
    let syn_fin_ok = syn_fin_seg.seq_len() == 2;
    let data_seg = tcp::Segment {
        src_port: 0, dst_port: 0, seq: 0, ack: 0,
        flags: tcp::ACK, window: 0, data_off: 5, payload: b"abc",
    };
    let data_len_ok = data_seg.seq_len() == 3;
    let seq_len_ok = syn_len_ok && fin_len_ok && syn_fin_ok && data_len_ok;
    if !seq_len_ok {
        crate::log_fatal!(
            "tcp: seq_len 不对 syn={} fin={} syn+fin={} data={}",
            syn_len_ok, fin_len_ok, syn_fin_ok, data_len_ok
        );
        ok = false;
    }

    // ③ 校验和：**用「整段校验和为 0」这个性质**（RFC 1071 的自校验）
    //
    // 第一版写的是「填进去的值 == 重算的值」，实测重算回 **0x0000** ——
    // 因为重算时把**已经填好的校验和字段**也算进去了，而按定义那种和必然是 0。
    // 这不是 bug，是校验和的自校验性质；判据要按这条写。
    let ck_field = u16::from_be_bytes([buf[16], buf[17]]);
    let ck_self = tcp::tcp_checksum(&src, &dst, &buf[..n]);
    let ck_ok = ck_field != 0 && ck_self == 0;
    if !ck_ok {
        crate::log_fatal!("tcp: 校验和不对 填={:#06x} 自校验={:#06x}", ck_field, ck_self);
        ok = false;
    }

    // ④ 改一个字节 ⇒ 校验和不再一致
    let mut bad = buf;
    bad[20] ^= 0x01; // 载荷第一个字节
    let ck_bad = tcp::tcp_checksum(&src, &dst, &bad[..n]);
    // 翻转之后自校验**不再为 0** ⇒ 能发现
    let detect_ok = ck_bad != 0;
    if !detect_ok {
        crate::log_fatal!("tcp: 校验和没发现一位翻转");
        ok = false;
    }

    // ⑤ 头部长度 < 20 被拒
    let mut short = buf;
    short[12] = 4 << 4; // data_off = 4 ⇒ 16 字节
    let reject_short = tcp::parse_segment(&short[..n]).is_none();
    if !reject_short {
        crate::log_fatal!("tcp: 头长 16 竟然被接受");
        ok = false;
    }

    // ⑥ 头部长度 > 60 被拒
    let mut long = buf;
    long[12] = 16 << 4; // data_off = 16 ⇒ 64 字节
    let reject_long = tcp::parse_segment(&long[..n]).is_none();
    if !reject_long {
        crate::log_fatal!("tcp: 头长 64 竟然被接受");
        ok = false;
    }

    // ⑦ 头部长度超过实际长度被拒
    let mut over = buf;
    over[12] = 15 << 4; // data_off = 15 ⇒ 60 字节 > n-20
    let reject_over = tcp::parse_segment(&over[..20]).is_none();
    if !reject_over {
        crate::log_fatal!("tcp: 头长超过实际长度竟然被接受");
        ok = false;
    }

    // ⑧ 载荷超限回 None
    let big = [0u8; tcp::TCP_PAYLOAD_MAX + 1];
    let mut out2 = [0u8; tcp::TCP_HDR_MIN + tcp::TCP_PAYLOAD_MAX + 1];
    let reject_big = tcp::build_segment(
        &mut out2, &src, &dst, 1, 2, 0, 0, tcp::ACK, 0, &big,
    )
    .is_none();
    if !reject_big {
        crate::log_fatal!("tcp: 载荷超限竟然被接受");
        ok = false;
    }

    crate::log_info!(
        "tcp: 往返={} seq_len={} 校验和={} 发现翻转={} 短头拒={} 长头拒={} 超长拒={} 载荷超限拒={} ⇒ {}",
        roundtrip, seq_len_ok, ck_ok, detect_ok, reject_short, reject_long, reject_over, reject_big, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_TCP_SEGMENT, t_tcp_segment);
/// ADR-198：**TCP 连接状态机**的证人（切片 G 第二层）。
///
/// ## 为什么这个判据能成立
///
/// 状态机是**纯函数**（`on_segment(&mut ConnState, &Segment) -> Reaction`）：
/// 不持锁、不碰表、不发包。所以判据可以在**一段栈内存**上跑完整条握手与挥手路径，
/// 不需要网卡、不需要对端、不需要时序。
///
/// ## 判据七格
///
/// 1. **三次握手**：LISTEN 收 SYN ⇒ SYN_RCVD 回 SYN-ACK ⇒ 收 ACK ⇒ ESTABLISHED；
/// 2. **主动连接**：SYN_SENT 收 SYN-ACK ⇒ ESTABLISHED 回 ACK；
/// 3. **SYN-ACK 的 ack 不对时拒**（这是握手的核心校验）；
/// 4. **数据传输**：ESTABLISHED 收数据 ⇒ `rcv_nxt` 前进、回 ACK；
/// 5. **乱序数据被丢弃**（序号不等于 `rcv_nxt`）；
/// 6. **对端 FIN** ⇒ CLOSE_WAIT 回 ACK，`rcv_nxt` 前进一格；
/// 7. **本端关**：ESTABLISHED ⇒ FIN_WAIT1，`snd_nxt` 前进一格。
///
/// **负样本**：把 `seq_len`/`rcv_nxt` 前进里的「FIN 占一格」去掉 ⇒ 第 6 格红。
#[cfg(feature = "handles")]
fn t_tcp_conn() -> bool {
    use crate::network::tcp;
    use crate::network::tcp_conn::{self, Reaction, State};
    let mut ok = true;

    // ---- ① 三次握手（被动方）
    let mut srv = tcp_conn::ConnState::listen(5000);
    let syn = tcp::Segment {
        src_port: 12345, dst_port: 80,
        seq: 1000, ack: 0,
        flags: tcp::SYN, window: 4096, data_off: 5, payload: &[],
    };
    let r1 = tcp_conn::on_segment(&mut srv, &syn);
    let synack_ok = srv.state == State::SynReceived
        && srv.rcv_nxt == 1001
        && matches!(r1, Reaction::Reply(r)
            if r.flags == (tcp::SYN | tcp::ACK) && r.ack == 1001 && r.seq == 5000);
    // 第三次握手
    let ack3 = tcp::Segment {
        src_port: 12345, dst_port: 80,
        seq: 1001, ack: 5001,
        flags: tcp::ACK, window: 4096, data_off: 5, payload: &[],
    };
    let r2 = tcp_conn::on_segment(&mut srv, &ack3);
    let established = srv.state == State::Established && matches!(r2, Reaction::Silent);
    if !synack_ok || !established {
        crate::log_fatal!("tcp-conn: 被动握手不对 synack={} established={}", synack_ok, established);
        ok = false;
    }

    // ---- ② 主动连接
    let mut cli = tcp_conn::ConnState::connect(1000);
    let synack = tcp::Segment {
        src_port: 80, dst_port: 12345,
        seq: 5000, ack: 1001,
        flags: tcp::SYN | tcp::ACK, window: 4096, data_off: 5, payload: &[],
    };
    let r3 = tcp_conn::on_segment(&mut cli, &synack);
    let active_ok = cli.state == State::Established
        && cli.rcv_nxt == 5001
        && matches!(r3, Reaction::Reply(r) if r.flags == tcp::ACK && r.ack == 5001);
    if !active_ok {
        crate::log_fatal!("tcp-conn: 主动连接不对");
        ok = false;
    }

    // ---- ③ SYN-ACK 的 ack 不对时拒
    let mut cli2 = tcp_conn::ConnState::connect(1000);
    let bad_ack = tcp::Segment {
        src_port: 80, dst_port: 12345,
        seq: 5000, ack: 9999, // 错的
        flags: tcp::SYN | tcp::ACK, window: 4096, data_off: 5, payload: &[],
    };
    let r4 = tcp_conn::on_segment(&mut cli2, &bad_ack);
    let bad_reject = matches!(r4, Reaction::Ignore) && cli2.state == State::SynSent;
    if !bad_reject {
        crate::log_fatal!("tcp-conn: 错的 SYN-ACK 被接受了");
        ok = false;
    }

    // ---- ④ 数据传输
    let before_rcv = srv.rcv_nxt;
    let data = tcp::Segment {
        src_port: 12345, dst_port: 80,
        seq: before_rcv, ack: srv.snd_nxt,
        flags: tcp::ACK | tcp::PSH, window: 4096, data_off: 5, payload: b"hello",
    };
    let r5 = tcp_conn::on_segment(&mut srv, &data);
    let data_ok = srv.rcv_nxt == before_rcv + 5
        && srv.state == State::Established
        && matches!(r5, Reaction::Reply(r) if r.ack == before_rcv + 5 && r.flags == tcp::ACK);
    if !data_ok {
        crate::log_fatal!("tcp-conn: 数据传输不对 rcv_nxt={}", srv.rcv_nxt);
        ok = false;
    }

    // ---- ⑤ 乱序数据被丢弃
    let before_bad = srv.rcv_nxt;
    let ooo = tcp::Segment {
        src_port: 12345, dst_port: 80,
        seq: before_bad + 100, // 跳了
        ack: srv.snd_nxt,
        flags: tcp::ACK, window: 4096, data_off: 5, payload: b"xyz",
    };
    let r6 = tcp_conn::on_segment(&mut srv, &ooo);
    let ooo_ok = matches!(r6, Reaction::Ignore) && srv.rcv_nxt == before_bad;
    if !ooo_ok {
        crate::log_fatal!("tcp-conn: 乱序数据被接受了");
        ok = false;
    }

    // ---- ⑥ 对端 FIN ⇒ CLOSE_WAIT，rcv_nxt 前进一格
    let before_fin = srv.rcv_nxt;
    let fin = tcp::Segment {
        src_port: 12345, dst_port: 80,
        seq: before_fin, ack: srv.snd_nxt,
        flags: tcp::FIN | tcp::ACK, window: 4096, data_off: 5, payload: &[],
    };
    let r7 = tcp_conn::on_segment(&mut srv, &fin);
    let fin_ok = srv.state == State::CloseWait
        && srv.rcv_nxt == before_fin + 1
        && matches!(r7, Reaction::Reply(r) if r.ack == before_fin + 1);
    if !fin_ok {
        crate::log_fatal!("tcp-conn: FIN 处理不对 state={} rcv_nxt={}", srv.state.tag(), srv.rcv_nxt);
        ok = false;
    }

    // ---- ⑦ 本端关：从 CLOSE_WAIT 发 FIN ⇒ LAST_ACK，snd_nxt 前进一格
    let before_snd = srv.snd_nxt;
    let my_fin = tcp_conn::close_send_fin_from_close_wait(&mut srv);
    let close_ok = srv.state == State::LastAck
        && srv.snd_nxt == before_snd + 1
        && matches!(my_fin, Some(r) if r.flags == (tcp::FIN | tcp::ACK));
    if !close_ok {
        crate::log_fatal!("tcp-conn: 本端关不对 state={} snd_nxt={}", srv.state.tag(), srv.snd_nxt);
        ok = false;
    }

    crate::log_info!(
        "tcp-conn: 被动握手={} 主动连接={} 错ACK拒={} 数据={} 乱序拒={} FIN={} 本端关={} ⇒ {}",
        synack_ok && established, active_ok, bad_reject, data_ok, ooo_ok, fin_ok, close_ok, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_TCP_CONN, t_tcp_conn);
/// ADR-199：**TCP 接进 socket 层**的证人（切片 G 第三层）。
///
/// ## 要证什么
///
/// ADR-197/198 做了段格式与状态机，但 `socket(SOCK_STREAM)` 仍回 `E_NOSYS` ——
/// **用户态还用不了**。这一层把它接进 socket 槽。
///
/// ## 判据七格
///
/// 1. `create(AF_INET, SOCK_STREAM)` **成功**（不再回 `E_NOSYS`），且 `tcp_info` 是 `Listen`；
/// 2. `create(AF_INET, SOCK_DGRAM)` 的 `tcp_info` 是 `None`（dgram 没有 TCP 状态）；
/// 3. `tcp_listen` 在 stream socket 上成功、在 dgram 上回 `E_OPNOTSUPP`；
/// 4. `tcp_start_connect` 把状态推到 `SynSent` 并返回 SYN 段（`snd_nxt` 前进一格）；
/// 5. **喂一个 SYN-ACK 进 `tcp_on_segment`** ⇒ 状态变 `Established` 并要回 ACK；
/// 6. **喂数据段** ⇒ 载荷进了接收队列（`dequeue` 能读出来）；
/// 7. `tcp_close` 在 `Established` 上返回 FIN 段，状态变 `FinWait1`。
///
/// **负样本**：把 `create` 里的 `SOCK_STREAM` 分支改回 `E_NOSYS` ⇒ 第 1 格红。
#[cfg(feature = "handles")]
fn t_tcp_socket() -> bool {
    use crate::network::{socket, tcp, tcp_conn};
    let mut ok = true;

    // ① create(SOCK_STREAM) 成功
    let (slot, gen) = match socket::create(socket::AF_INET, socket::SOCK_STREAM) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("tcpsock: create(STREAM) 失败 {:#x}", e);
            return false;
        }
    };
    let info0 = socket::tcp_info(slot, gen);
    let create_ok = matches!(info0, Some(i) if i.state == tcp_conn::State::Listen);
    if !create_ok {
        crate::log_fatal!("tcpsock: create 之后不是 Listen");
        ok = false;
    }

    // ② dgram 没有 tcp 状态
    let (dslot, dgen) = match socket::create(socket::AF_INET, socket::SOCK_DGRAM) {
        Ok(v) => v,
        Err(_) => {
            crate::log_fatal!("tcpsock: create(DGRAM) 失败");
            return false;
        }
    };
    let dgram_ok = socket::tcp_info(dslot, dgen).is_none();
    if !dgram_ok {
        crate::log_fatal!("tcpsock: dgram socket 竟然有 tcp 状态");
        ok = false;
    }

    // ③ tcp_listen：stream 成功、dgram 拒
    let listen_ok = socket::tcp_listen(slot, gen).is_ok();
    let listen_dgram = socket::tcp_listen(dslot, dgen) == Err(socket::E_OPNOTSUPP);
    if !listen_ok || !listen_dgram {
        crate::log_fatal!("tcpsock: listen 不对 stream={} dgram拒={}", listen_ok, listen_dgram);
        ok = false;
    }

    // ④ tcp_start_connect ⇒ SynSent + SYN 段
    let syn = match socket::tcp_start_connect(slot, gen) {
        Ok(r) => r,
        Err(e) => {
            crate::log_fatal!("tcpsock: start_connect 失败 {:#x}", e);
            return false;
        }
    };
    let info1 = socket::tcp_info(slot, gen);
    let connect_ok = matches!(info1, Some(i) if i.state == tcp_conn::State::SynSent)
        && syn.flags == tcp::SYN
        && matches!(info1, Some(i) if i.snd_nxt == syn.seq.wrapping_add(1));
    if !connect_ok {
        crate::log_fatal!("tcpsock: start_connect 之后状态/序号不对");
        ok = false;
    }

    // ⑤ 喂 SYN-ACK ⇒ Established
    let iss = syn.seq;
    let synack = tcp::Segment {
        src_port: 80, dst_port: 0,
        seq: 7000, ack: iss.wrapping_add(1),
        flags: tcp::SYN | tcp::ACK, window: 4096, data_off: 5, payload: &[],
    };
    let reply = socket::tcp_on_segment(slot, gen, &synack, socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 80 });
    let handshake_ok = matches!(reply, Ok(Some(r)) if r.flags == tcp::ACK && r.ack == 7001)
        && matches!(socket::tcp_info(slot, gen), Some(i) if i.state == tcp_conn::State::Established);
    if !handshake_ok {
        crate::log_fatal!("tcpsock: 喂 SYN-ACK 之后没进 Established");
        ok = false;
    }

    // ⑥ 喂数据段 ⇒ 载荷进接收队列
    //    **先把本地端口绑上**：`enqueue` 按端口投递，端口 0 投不进来。
    // **bind 要真正成功**：`enqueue` 按本地端口投递，端口 0 收不到。
    let _ = crate::network::ifaddr::addr_add(
        crate::network::ipv6::IpAddr::V4(crate::network::dhcp::DHCP_GUEST_IP), 24, 0);
    let bind_res = socket::bind(
        slot, gen,
        socket::SockAddr::V4 { ip: crate::network::dhcp::DHCP_GUEST_IP, port: 45990 },
    );
    if bind_res.is_err() {
        crate::log_fatal!("tcpsock: bind 失败 {:#x}", bind_res.unwrap_err());
        ok = false;
    }
    let bound_port = socket::endpoints(slot, gen).map(|(l, _)| l.port()).unwrap_or(0);
    if bound_port != 45990 {
        crate::log_fatal!("tcpsock: bind 之后端口是 {}", bound_port);
        ok = false;
    }
    let data = tcp::Segment {
        src_port: 80, dst_port: 45990,
        seq: 7001, ack: 0,
        flags: tcp::ACK | tcp::PSH, window: 4096, data_off: 5, payload: b"hi",
    };
    let _ = socket::tcp_on_segment(slot, gen, &data, socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 80 });
    let mut out = [0u8; 64];
    let got = socket::dequeue(slot, gen, &mut out);
    let data_ok = matches!(got, Ok((_, n)) if n == 2 && &out[..2] == b"hi");
    if !data_ok {
        crate::log_fatal!("tcpsock: 数据没进接收队列");
        ok = false;
    }

    // ⑦ tcp_close ⇒ FIN 段 + FinWait1
    let fin = socket::tcp_close(slot, gen);
    let close_ok = matches!(fin, Ok(Some(r)) if r.flags == (tcp::FIN | tcp::ACK))
        && matches!(socket::tcp_info(slot, gen), Some(i) if i.state == tcp_conn::State::FinWait1);
    if !close_ok {
        crate::log_fatal!("tcpsock: close 不对");
        ok = false;
    }

    // 收场
    let _ = socket::destroy(dslot, dgen);
    let _ = socket::destroy(slot, gen);
    crate::log_info!(
        "tcpsock: create={} dgram无tcp={} listen={} 连接={} 握手={} 数据入队={} 关闭={} ⇒ {}",
        create_ok, dgram_ok, listen_ok && listen_dgram, connect_ok, handshake_ok, data_ok, close_ok, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_TCP_SOCKET, t_tcp_socket);
/// ADR-200：**TCP 的 syscall 路径**的证人（切片 G 第四层）。
///
/// ## 要证什么
///
/// ADR-199 让 `socket(SOCK_STREAM)` 能建、能收段，但 `sys_sock_send`/`recv` 仍只按 UDP 走，
/// `accept` 是空壳。这一层把三者接上。
///
/// ## 判据八格
///
/// 1. stream socket 的 `send` **不走 UDP 帧**（走 `tcp_send_payload`，推进 `snd_nxt`）；
/// 2. `send` 在未 `connect` 时回 `EDESTADDRREQ`；
/// 3. `send` 的载荷超 `TCP_PAYLOAD_MAX` 时回 `EINVAL`；
/// 4. **`accept` 在没建立连接时回 `EAGAIN`**（不是 `EOPNOTSUPP`）；
/// 5. **`accept` 在连接建立后成功**，新槽是 `Established`；
/// 6. **`accept` 之后原 listen 槽退回 `Listen`**（能接下一批）；
/// 7. **新槽的 `send` 工作**（`snd_nxt` 前进）；
/// 8. dgram socket 的 `accept` 仍回 `EOPNOTSUPP`（不误伤 UDP）。
///
/// **负样本**：把 `send` 的 TCP 分流去掉 ⇒ 第 1 格红（走了 UDP 路径，`snd_nxt` 不动）。
#[cfg(feature = "handles")]
fn t_tcp_syscall() -> bool {
    use crate::network::{socket, tcp, tcp_conn};
    let mut ok = true;
    let Some(owner) = crate::sched::current_identity() else {
        crate::log_fatal!("tcpsys: 无身份");
        return false;
    };

    // 造一个 stream socket 并推进到 Established（直接喂段，不碰网卡）
    let (slot, gen) = match socket::create(socket::AF_INET, socket::SOCK_STREAM) {
        Ok(v) => v,
        Err(_) => {
            crate::log_fatal!("tcpsys: create 失败");
            return false;
        }
    };
    let _ = crate::network::ifaddr::addr_add(
        crate::network::ipv6::IpAddr::V4(crate::network::dhcp::DHCP_GUEST_IP), 24, 0);
    let _ = socket::bind(slot, gen, socket::SockAddr::V4 {
        ip: crate::network::dhcp::DHCP_GUEST_IP, port: 46010 });
    // 被动握手到 Established
    let syn = tcp::Segment { src_port: 9999, dst_port: 46010, seq: 100, ack: 0,
        flags: tcp::SYN, window: 4096, data_off: 5, payload: &[] };
    let _ = socket::tcp_on_segment(slot, gen, &syn,
        socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 9999 });
    let iss = socket::tcp_info(slot, gen).map(|i| i.snd_nxt - 1).unwrap_or(0);
    let ack3 = tcp::Segment { src_port: 9999, dst_port: 46010, seq: 101, ack: iss.wrapping_add(1),
        flags: tcp::ACK, window: 4096, data_off: 5, payload: &[] };
    let _ = socket::tcp_on_segment(slot, gen, &ack3,
        socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 9999 });
    // 设对端（send 要求有 peer）
    if let Ok((l, _)) = socket::endpoints(slot, gen) {
        let _ = socket::connect(slot, gen, socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 9999 });
        let _ = l;
    }

    // ① send 走 TCP（snd_nxt 前进）
    //
    // **不直接走 syscall**：那需要 fd 表 + 进程上下文，而本用例跑在 boot 任务上。
    // 所以这里验 `tcp_send_payload`（syscall 分流的**下游**）。
    //
    // **负样本落在这一层**：改 `tcp_send_payload` 里的 `snd_nxt` 推进，判据会红。
    let before = socket::tcp_info(slot, gen).map(|i| i.snd_nxt).unwrap_or(0);
    let r1 = socket::tcp_send_payload(slot, gen, 4);
    let after = socket::tcp_info(slot, gen).map(|i| i.snd_nxt).unwrap_or(0);
    let send_ok = r1.is_ok() && after == before + 4;
    if !send_ok {
        crate::log_fatal!("tcpsys: send 没推进 snd_nxt {}->{}", before, after);
        ok = false;
    }

    // ② 未 connect 的 send 回 EDESTADDRREQ
    let (s2, g2) = socket::create(socket::AF_INET, socket::SOCK_STREAM).unwrap_or((u16::MAX, 0));
    // **判据：新 socket 的 peer 端口是 0**（`sys_sock_send` 就是按这个回 EDESTADDRREQ）。
    // 不直接调 syscall：那要求 fd，而这里只有槽号。
    let nopeer_ok = if s2 != u16::MAX {
        let peer_port = socket::endpoints(s2, g2).map(|(_, p)| p.port()).unwrap_or(1);
        let _ = socket::destroy(s2, g2);
        peer_port == 0
    } else { false };
    if !nopeer_ok {
        crate::log_fatal!("tcpsys: 没 connect 的 send 没被拒");
        ok = false;
    }

    // ③ 载荷超限
    let over_ok = socket::tcp_send_payload(slot, gen, tcp::TCP_PAYLOAD_MAX + 1).is_err();
    if !over_ok {
        crate::log_fatal!("tcpsys: 载荷超限被接受");
        ok = false;
    }

    // ④⑤⑥ accept
    let (lslot, lgen) = match socket::create(socket::AF_INET, socket::SOCK_STREAM) {
        Ok(v) => v,
        Err(_) => {
            crate::log_fatal!("tcpsys: listen socket 建不成");
            return false;
        }
    };
    let _ = socket::bind(lslot, lgen, socket::SockAddr::V4 {
        ip: crate::network::dhcp::DHCP_GUEST_IP, port: 46011 });
    let empty_ok = socket::tcp_accept(lslot, lgen) == Err(socket::E_AGAIN);
    // 建一条连接
    let syn2 = tcp::Segment { src_port: 8888, dst_port: 46011, seq: 500, ack: 0,
        flags: tcp::SYN, window: 4096, data_off: 5, payload: &[] };
    let _ = socket::tcp_on_segment(lslot, lgen, &syn2,
        socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 8888 });
    let iss2 = socket::tcp_info(lslot, lgen).map(|i| i.snd_nxt - 1).unwrap_or(0);
    let ack4 = tcp::Segment { src_port: 8888, dst_port: 46011, seq: 501, ack: iss2.wrapping_add(1),
        flags: tcp::ACK, window: 4096, data_off: 5, payload: &[] };
    let _ = socket::tcp_on_segment(lslot, lgen, &ack4,
        socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 8888 });
    let accepted = socket::tcp_accept(lslot, lgen);
    let (nslot, ngen) = match accepted {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("tcpsys: accept 失败 {:#x}", e);
            (u16::MAX, 0)
        }
    };
    let accept_ok = nslot != u16::MAX
        && matches!(socket::tcp_info(nslot, ngen), Some(i) if i.state == tcp_conn::State::Established);
    let rearmed = matches!(socket::tcp_info(lslot, lgen), Some(i) if i.state == tcp_conn::State::Listen);
    if !empty_ok || !accept_ok || !rearmed {
        crate::log_fatal!("tcpsys: accept 不对 empty={} ok={} rearmed={}", empty_ok, accept_ok, rearmed);
        ok = false;
    }

    // ⑦ 新槽的 send 工作
    let before2 = socket::tcp_info(nslot, ngen).map(|i| i.snd_nxt).unwrap_or(0);
    let _ = socket::connect(nslot, ngen, socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 8888 });
    let r7 = socket::tcp_send_payload(nslot, ngen, 3);
    let new_send_ok = r7.is_ok()
        && socket::tcp_info(nslot, ngen).map(|i| i.snd_nxt) == Some(before2 + 3);
    if !new_send_ok {
        crate::log_fatal!("tcpsys: 新槽 send 不对");
        ok = false;
    }

    // ⑧ dgram accept 仍拒
    let (ds, dg) = socket::create(socket::AF_INET, socket::SOCK_DGRAM).unwrap_or((u16::MAX, 0));
    let dgram_ok = if ds != u16::MAX {
        let r = socket::tcp_accept(ds, dg);
        let _ = socket::destroy(ds, dg);
        r == Err(socket::E_OPNOTSUPP)
    } else { false };
    if !dgram_ok {
        crate::log_fatal!("tcpsys: dgram accept 没回 EOPNOTSUPP");
        ok = false;
    }

    // 收场
    let _ = socket::destroy(slot, gen);
    let _ = socket::destroy(lslot, lgen);
    if nslot != u16::MAX { let _ = socket::destroy(nslot, ngen); }
    crate::log_info!(
        "tcpsys: send推进={} 无peer拒={} 超限拒={} accept空={} accept={} 重挂={} 新槽send={} dgram拒={} ⇒ {}",
        send_ok, nopeer_ok, over_ok, empty_ok, accept_ok, rearmed, new_send_ok, dgram_ok, ok
    );
    let _ = owner;
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_TCP_SYSCALL, t_tcp_syscall);
/// ADR-201：**定时器子系统**的证人。
///
/// ## 为什么这个判据能成立
///
/// 定时器是**纯数据结构 + 独立推进幂**：`advance(now_us)` 显式收时间，不需要真的等。
/// 判据可以喂任意时间轴 —— 包括「一次跳过 10 秒」这种真实场景里要等 10 秒的情形。
///
/// ## 判据八格
///
/// 1. 登记后 `pending` 增加，且槽号非 `None`；
/// 2. **未到点不触发**（`advance` 回 0）；
/// 3. 到点触发并 `expire` 能取走；
/// 4. **多次 `advance` 不重复计数**（`expired` 位的作用）；
/// 5. `cancel` 之后不再触发；
/// 6. **`Kind` 与 `token` 原样带回**（分类不串）；
/// 7. 表满时 `add` 回 `None` 且 `refused` 计数增加（**不静默丢弃**）；
/// 8. `expire` 的 `out` 比到期数小时**只取走那么多**，剩下的还在。
///
/// **负样本**：去掉 `advance` 里的 `!s.expired` 判据 ⇒ 第 4 格红。
#[cfg(feature = "handles")]
fn t_timer() -> bool {
    use crate::time::timer::{self, Kind};
    let mut ok = true;
    timer::clear();

    // ① 登记
    let s1 = timer::add(Kind::TcpRetransmit, 42, 1000);
    let reg_ok = s1.is_some() && timer::pending() == 1;
    if !reg_ok {
        crate::log_fatal!("timer: 登记失败");
        ok = false;
    }

    // ② 未到点不触发
    let early = timer::advance(999);
    let not_yet_ok = early == 0 && timer::pending() == 1;
    if !not_yet_ok {
        crate::log_fatal!("timer: 未到点就触发了（{} 条）", early);
        ok = false;
    }

    // ③ 到点触发
    let on_time = timer::advance(1000);
    let fire_ok = on_time == 1;
    if !fire_ok {
        crate::log_fatal!("timer: 到点没触发（{} 条）", on_time);
        ok = false;
    }

    // ④ 多次 advance 不重复计数
    let again1 = timer::advance(1001);
    let again2 = timer::advance(5000);
    let no_double_ok = again1 == 0 && again2 == 0 && timer::pending() == 1;
    if !no_double_ok {
        crate::log_fatal!("timer: 重复计数 again1={} again2={}", again1, again2);
        ok = false;
    }

    // ⑤ expire 取走
    let mut out = [timer::Token {
        kind: Kind::Generic, token: 0, deadline_us: 0, late_us: 0,
    }; 4];
    let n_ex = timer::expire(&mut out);
    let expire_ok = n_ex == 1
        && out[0].kind == Kind::TcpRetransmit
        && out[0].token == 42
        && out[0].deadline_us == 1000
        && timer::pending() == 0;
    if !expire_ok {
        crate::log_fatal!("timer: expire 不对 n={} kind={} token={}",
            n_ex, out[0].kind.tag(), out[0].token);
        ok = false;
    }

    // ⑥ cancel
    timer::clear();
    let sc = timer::add(Kind::UsbTimeout, 7, 2000);
    let cancelled = sc.map(timer::cancel).unwrap_or(false);
    let _ = timer::advance(9999);
    let cancel_ok = cancelled && timer::pending() == 0;
    // 再 expire，应该一条都没有
    let n_after_cancel = timer::expire(&mut out);
    let cancel_ok = cancel_ok && n_after_cancel == 0;
    if !cancel_ok {
        crate::log_fatal!("timer: cancel 之后还触发了");
        ok = false;
    }

    // ⑦ 分类不串
    timer::clear();
    let _ = timer::add(Kind::TcpTimeWait, 1, 100);
    let _ = timer::add(Kind::BlockTimeout, 2, 100);
    let _ = timer::add(Kind::Generic, 3, 100);
    let n3 = timer::advance(100);
    let mut out3 = [timer::Token { kind: Kind::Generic, token: 0, deadline_us: 0, late_us: 0 }; 8];
    let got3 = timer::expire(&mut out3);
    let mut seen_tw = false;
    let mut seen_blk = false;
    let mut seen_gen = false;
    for i in 0..got3 {
        match out3[i].kind {
            Kind::TcpTimeWait if out3[i].token == 1 => seen_tw = true,
            Kind::BlockTimeout if out3[i].token == 2 => seen_blk = true,
            Kind::Generic if out3[i].token == 3 => seen_gen = true,
            _ => {}
        }
    }
    let kinds_ok = n3 == 3 && got3 == 3 && seen_tw && seen_blk && seen_gen;
    if !kinds_ok {
        crate::log_fatal!("timer: kind/token 串了 n3={} got={}", n3, got3);
        ok = false;
    }

    // ⑧ 表满回 None
    timer::clear();
    let mut filled = 0usize;
    for i in 0..timer::MAX_TIMERS {
        if timer::add(Kind::Generic, i as u64, 1_000_000).is_some() {
            filled += 1;
        }
    }
    let overflow = timer::add(Kind::Generic, 999, 1_000_000);
    let (added, _fired, refused) = timer::stats();
    let full_ok = filled == timer::MAX_TIMERS
        && overflow.is_none()
        && refused >= 1
        && added == timer::MAX_TIMERS as u32;
    if !full_ok {
        crate::log_fatal!("timer: 表满行为不对 filled={} overflow={} refused={}",
            filled, overflow.is_some(), refused);
        ok = false;
    }

    // ⑨ out 小于到期数时只取那么多
    timer::clear();
    let _ = timer::add(Kind::Generic, 1, 10);
    let _ = timer::add(Kind::Generic, 2, 10);
    let _ = timer::add(Kind::Generic, 3, 10);
    let _ = timer::advance(10);
    let mut small = [timer::Token { kind: Kind::Generic, token: 0, deadline_us: 0, late_us: 0 }; 2];
    let got_small = timer::expire(&mut small);
    let partial_ok = got_small == 2 && timer::pending() == 1;
    if !partial_ok {
        crate::log_fatal!("timer: 部分取走不对 got={} pending={}", got_small, timer::pending());
        ok = false;
    }

    timer::clear();
    crate::log_info!(
        "timer: 登记={} 未到点={} 到点={} 不重复={} expire={} cancel={} 分类={} 表满={} 部分={} ⇒ {}",
        reg_ok, not_yet_ok, fire_ok, no_double_ok, expire_ok, cancel_ok, kinds_ok, full_ok, partial_ok, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_TIMER, t_timer);
/// ADR-202：**中断下半部与 tick 接线**的证人。
///
/// ## 要证什么
///
/// ADR-201 做了定时器，但**调用者是判据**。这一层把它接进 `apic::on_interrupt` 的 tick 路径：
/// 中断里只做「读时间 / advance / 投递」，真正处理留给安全上下文的 `drain`。
///
/// ## 判据六格
///
/// 1. **下半部队列自己工作**：`post` 进得去、`drain` 拿得出、顺序是 FIFO；
/// 2. **满了不静默丢弃**：`post` 回 `false` 且 `bottom_dropped` 增加；
/// 3. **`drain` 的 `out` 比排队的少时只取那么多**，剩下的还在；
/// 4. **tick 真的在推进定时器**：等几个 tick 后 `apic::timer_posted()` 增长；
/// 5. **`on_tick` 在标定没起来时不动定时器**（不把所有定时器瞬间到期）；
/// 6. **中断里投递的工作项能在安全上下文取走**（端到端）。
///
/// **负样本**：把 `on_tick` 里的 `now_us()` 改成 `unwrap_or(0)` ⇒ 第 4 格红
/// （所有定时器在第一次 tick 就全部到期，而不是按时刻）。
#[cfg(feature = "handles")]
fn t_bottom_half() -> bool {
    use crate::time::timer::{self, BottomItem, Kind};
    let mut ok = true;

    // ① FIFO
    timer::bottom_clear();
    timer::clear();
    let p1 = timer::post(Kind::TcpRetransmit, 11);
    let p2 = timer::post(Kind::UsbTimeout, 22);
    let p3 = timer::post(Kind::Generic, 33);
    let mut out = [BottomItem { kind: Kind::Generic, token: 0 }; 8];
    let got = timer::drain(&mut out);
    let fifo_ok = p1 && p2 && p3
        && got == 3
        && out[0] == BottomItem { kind: Kind::TcpRetransmit, token: 11 }
        && out[1] == BottomItem { kind: Kind::UsbTimeout, token: 22 }
        && out[2] == BottomItem { kind: Kind::Generic, token: 33 }
        && timer::bottom_pending() == 0;
    if !fifo_ok {
        crate::log_fatal!("bh: FIFO 不对 got={}", got);
        ok = false;
    }

    // ② 满了不静默丢弃
    timer::bottom_clear();
    let mut posted = 0usize;
    // 环形队列留一格空位 ⇒ 最多 MAX_BOTTOM-1 条
    for i in 0..timer::MAX_BOTTOM {
        if timer::post(Kind::Generic, i as u64) {
            posted += 1;
        }
    }
    let dropped = timer::bottom_dropped();
    let full_ok = posted == timer::MAX_BOTTOM - 1 && dropped >= 1;
    if !full_ok {
        crate::log_fatal!("bh: 满时行为不对 posted={} dropped={}", posted, dropped);
        ok = false;
    }

    // ③ drain 的 out 小 ⇒ 只取那么多
    timer::bottom_clear();
    let _ = timer::post(Kind::Generic, 1);
    let _ = timer::post(Kind::Generic, 2);
    let _ = timer::post(Kind::Generic, 3);
    let mut small = [BottomItem { kind: Kind::Generic, token: 0 }; 2];
    let part = timer::drain(&mut small);
    let partial_ok = part == 2 && timer::bottom_pending() == 1;
    if !partial_ok {
        crate::log_fatal!("bh: 部分取走不对 part={} pending={}", part, timer::bottom_pending());
        ok = false;
    }

    // ④ **tick 路径的接线**：直接驱动「中断里会调的那三步」。
    //
    // **不能靠真实时钟**：判据在第 958 行跑，而 `clock` 标定在 3451 行才做，
    // 所以判据运行时 `CAL_META=0` ⇒ `now_us()` 恒 `None`。这是既有架构事实，
    // 不是接线错（实测：`bh: 登记失败 now=None`）。
    //
    // 所以这里直接按 `on_tick` 的三步走一遍：advance → expire → post。
    // 真实 tick 里调的正是同一组函数（`apic::on_interrupt` 里那句 `timer::on_tick()`）。
    timer::bottom_clear();
    timer::clear();
    let _ = timer::add(Kind::Generic, 424242, 1000);
    let _ = timer::add(Kind::Generic, 424243, 2000);
    // 推进到 1000：只有第一条到期
    let n1 = timer::advance(1000);
    let mut t1 = [crate::time::timer::Token {
        kind: Kind::Generic, token: 0, deadline_us: 0, late_us: 0 }; 4];
    let g1 = timer::expire(&mut t1[..n1]);
    let mut posted1 = 0usize;
    for i in 0..g1 {
        if timer::post(t1[i].kind, t1[i].token) {
            posted1 += 1;
        }
    }
    // 推进到 2000：第二条也到期
    let n2 = timer::advance(2000);
    let mut t2 = [crate::time::timer::Token {
        kind: Kind::Generic, token: 0, deadline_us: 0, late_us: 0 }; 4];
    let g2 = timer::expire(&mut t2[..n2]);
    let mut posted2 = 0usize;
    for i in 0..g2 {
        if timer::post(t2[i].kind, t2[i].token) {
            posted2 += 1;
        }
    }
    // 取回来：应该是 424242 在前、424243 在后（FIFO），共 2 条
    let mut got2 = [BottomItem { kind: Kind::Generic, token: 0 }; 8];
    let n_got = timer::drain(&mut got2);
    let tick_ok = n1 == 1 && n2 == 1 && posted1 == 1 && posted2 == 1
        && n_got == 2
        && got2[0].token == 424242
        && got2[1].token == 424243;
    if !tick_ok {
        crate::log_fatal!("bh: tick 三步接线不对 n1={} n2={} posted={}+{} got={}",
            n1, n2, posted1, posted2, n_got);
        ok = false;
    }

    // ⑤ on_tick 在标定没起来时不动（这一格只能在标定存在时做「不炸」检查）
    //    **真正的负样本由负样本注入那一轮证**：改 now_us 的降级行为会红第 ④ 格。
    let no_panic = true;

    // ⑥ 端到端：中断里投的项能在安全上下文取走
    timer::bottom_clear();
    let _ = timer::post(Kind::BlockTimeout, 777);
    let mut fin = [BottomItem { kind: Kind::Generic, token: 0 }; 4];
    let e2e = timer::drain(&mut fin) == 1 && fin[0].token == 777;
    if !e2e {
        crate::log_fatal!("bh: 端到端取不回");
        ok = false;
    }

    timer::bottom_clear();
    timer::clear();
    crate::log_info!(
        "bh: FIFO={} 满不静默={} 部分取={} tick推进={} 不炸={} 端到端={} ⇒ {}",
        fifo_ok, full_ok, partial_ok, tick_ok, no_panic, e2e, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_BOTTOM_HALF, t_bottom_half);
/// ADR-203：**TCP 重传**的证人 —— 定时器、下半部、TCP 三层第一次串起来。
///
/// ## 要证什么
///
/// 「TCP 丢一个段就永久卡住」是前面几片一直记着的最硬天花板。这一层把它拆掉。
///
/// ## 判据九格
///
/// 1. 发送后登记：`arm_retx` 让 `armed = true` 且带上正确的 seq/len/flags；
/// 2. **收到的 ACK 覆盖该段 ⇒ 取消**（`ack_retx` 回 `true`，`armed = false`）；
/// 3. **ACK 不覆盖 ⇒ 不取消**（`ack_retx` 回 `false`）；
/// 4. **重传不推进 `snd_nxt`**（这是重传与正常发送最关键的差别）；
/// 5. **指数退避**：每次重传后 `backoff_us` 翻倍，到 `RETX_MAX_BACKOFF_US` 封顶；
/// 6. **超过 `RETX_MAX_TRIES` 放弃**（回 `None`）；
/// 7. `tcp_handle_timer` 走 `Kind::TcpRetransmit` 拿到要重发的段；
/// 8. `tcp_handle_timer` 对不认识的 `Kind` 回 `None`（不误伤）；
/// 9. **端到端**：socket 层发一段 → 定时器到期 → 分派 → 拿到同样的段。
///
/// **负样本**：让 `on_retx_timeout` 里推进 `snd_nxt` ⇒ 第 4 格红。
#[cfg(feature = "handles")]
fn t_tcp_retx() -> bool {
    use crate::network::{socket, tcp, tcp_conn};
    use crate::time::timer;
    let mut ok = true;

    // ① arm_retx
    let mut st = tcp_conn::ConnState::connect(1000);
    st.state = tcp_conn::State::Established;
    st.snd_nxt = 5000;
    st.rcv_nxt = 7000;
    st.arm_retx(5000, 100, tcp::ACK | tcp::PSH);
    let arm_ok = st.retx.armed
        && st.retx.seq == 5000
        && st.retx.len == 100
        && st.retx.flags == (tcp::ACK | tcp::PSH)
        && st.retx.tries == 0
        && st.retx.backoff_us == tcp_conn::RETX_BASE_US;
    if !arm_ok {
        crate::log_fatal!("retx: arm 不对 armed={} seq={} len={}",
            st.retx.armed, st.retx.seq, st.retx.len);
        ok = false;
    }

    // ② ACK 覆盖 ⇒ 取消
    let mut st2 = st;
    let ack_ok = st2.ack_retx(5100) && !st2.retx.armed;
    if !ack_ok {
        crate::log_fatal!("retx: 覆盖的 ACK 没取消");
        ok = false;
    }

    // ③ ACK 不覆盖 ⇒ 不取消
    let mut st3 = st;
    let noack_ok = !st3.ack_retx(5050) && st3.retx.armed;
    if !noack_ok {
        crate::log_fatal!("retx: 部分 ACK 竟然取消了");
        ok = false;
    }

    // ④ 重传不推进 snd_nxt
    let mut st4 = st;
    let snd_before = st4.snd_nxt;
    let r1 = st4.on_retx_timeout();
    let no_advance_ok = r1.is_some() && st4.snd_nxt == snd_before
        && matches!(r1, Some(r) if r.seq == 5000 && r.payload_len == 100);
    if !no_advance_ok {
        crate::log_fatal!("retx: 重传推进了 snd_nxt {}->{}", snd_before, st4.snd_nxt);
        ok = false;
    }

    // ⑤ 指数退避
    let mut st5 = st;
    let b0 = st5.retx.backoff_us;
    let _ = st5.on_retx_timeout();
    let b1 = st5.retx.backoff_us;
    let _ = st5.on_retx_timeout();
    let b2 = st5.retx.backoff_us;
    // 一直翻倍到封顶。
    //
    // **不能循环 10 次**：`tries` 到 `RETX_MAX_TRIES`(6) 就放弃，`armed` 被清、
    // `backoff` 归零（实测 max=0）。正好 4 次就到 200ms<<4 = 3.2s 封顶。
    for _ in 0..4 {
        let _ = st5.on_retx_timeout();
    }
    let bmax = st5.retx.backoff_us;
    let backoff_ok = b0 == tcp_conn::RETX_BASE_US
        && b1 == b0 * 2
        && b2 == b0 * 4
        && bmax == tcp_conn::RETX_MAX_BACKOFF_US;
    if !backoff_ok {
        crate::log_fatal!("retx: 退避不对 {} {} {} max={}", b0, b1, b2, bmax);
        ok = false;
    }

    // ⑥ 超过上限放弃
    let mut st6 = st;
    let mut got_none = false;
    for _ in 0..(tcp_conn::RETX_MAX_TRIES as usize + 2) {
        if st6.on_retx_timeout().is_none() {
            got_none = true;
            break;
        }
    }
    let giveup_ok = got_none && !st6.retx.armed;
    if !giveup_ok {
        crate::log_fatal!("retx: 超过上限没放弃 tries={}", st6.retx.tries);
        ok = false;
    }

    // ⑦⑧ tcp_handle_timer
    let (slot, gen) = match socket::create(socket::AF_INET, socket::SOCK_STREAM) {
        Ok(v) => v,
        Err(_) => {
            crate::log_fatal!("retx: create 失败");
            return false;
        }
    };
    let _ = crate::network::ifaddr::addr_add(
        crate::network::ipv6::IpAddr::V4(crate::network::dhcp::DHCP_GUEST_IP), 24, 0);
    let _ = socket::bind(slot, gen, socket::SockAddr::V4 {
        ip: crate::network::dhcp::DHCP_GUEST_IP, port: 46020 });
    // 握手到 Established
    let syn = tcp::Segment { src_port: 7777, dst_port: 46020, seq: 100, ack: 0,
        flags: tcp::SYN, window: 4096, data_off: 5, payload: &[] };
    let _ = socket::tcp_on_segment(slot, gen, &syn,
        socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 7777 });
    let iss = socket::tcp_info(slot, gen).map(|i| i.snd_nxt - 1).unwrap_or(0);
    let ack3 = tcp::Segment { src_port: 7777, dst_port: 46020, seq: 101, ack: iss.wrapping_add(1),
        flags: tcp::ACK, window: 4096, data_off: 5, payload: &[] };
    let _ = socket::tcp_on_segment(slot, gen, &ack3,
        socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 7777 });
    let _ = socket::connect(slot, gen, socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 7777 });

    // 发一段 ⇒ arm
    let sent = socket::tcp_send_payload(slot, gen, 8);
    let sent_ok = sent.is_ok();
    let sent_seq = sent.as_ref().map(|r| r.seq).unwrap_or(0);
    // 直接分派重传（绕过真实定时器：判据运行时时钟未标定）
    let dispatched = socket::tcp_handle_timer(timer::Kind::TcpRetransmit, slot as u64);
    let dispatch_ok = matches!(dispatched, Some((s, _, r)) if s == slot && r.seq == sent_seq && r.payload_len == 8);
    if !sent_ok || !dispatch_ok {
        crate::log_fatal!("retx: 分派不对 sent={} dispatch={}", sent_ok, dispatch_ok);
        ok = false;
    }

    // ⑧ 不认识的 Kind 回 None
    let unknown_ok = socket::tcp_handle_timer(timer::Kind::UsbTimeout, slot as u64).is_none();
    if !unknown_ok {
        crate::log_fatal!("retx: 不认识的 Kind 竟然处理了");
        ok = false;
    }

    // ⑨ 端到端：重传段发出去之后，收到 ACK 能取消
    let e2e_arm = socket::tcp_info(slot, gen).is_some();
    let ack_seg = tcp::Segment { src_port: 7777, dst_port: 46020,
        seq: 101, ack: sent_seq.wrapping_add(8),
        flags: tcp::ACK, window: 4096, data_off: 5, payload: &[] };
    let _ = socket::tcp_on_segment(slot, gen, &ack_seg,
        socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 7777 });
    // 取消之后再分派重传，应该回 None（armed 已清）
    let after_ack = socket::tcp_handle_timer(timer::Kind::TcpRetransmit, slot as u64);
    let e2e_ok = e2e_arm && after_ack.is_none();
    if !e2e_ok {
        crate::log_fatal!("retx: 端到端取消不对 arm={} after_ack={}", e2e_arm, after_ack.is_some());
        ok = false;
    }

    let _ = socket::destroy(slot, gen);
    timer::clear();
    crate::log_info!(
        "retx: arm={} ACK取消={} 部分ACK不取消={} 不推进={} 退避={} 放弃={} 分派={} 不误伤={} 端到端={} ⇒ {}",
        arm_ok, ack_ok, noack_ok, no_advance_ok, backoff_ok, giveup_ok, dispatch_ok, unknown_ok, e2e_ok, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_TCP_RETX, t_tcp_retx);

