//! syscall 指针校验、copy_user 与快路径用例（T0.1 纯搬移）。

use crate::arch::x86_64::{apic, cpu, trap};
use crate::{acpi, arch, mm, sched, sync, tsc, user};
use crate::ktests::common::{HELLO_ELF, P7_CALLS, drain_reap};
use crate::ktest;
use core::sync::atomic::{Ordering};

/// 一轮实验的读数。`base` = 可写段的页基址（`.slots` 就在那一页的开头），
/// `stack_top` 用来算**这个任务自己的** guard 页，`state` 是窗口结束、回收等完之后槽位的状态。
struct Round {
    base: u64,
    stack_top: u64,
    t: usize,
    served: u64,
    state: sched::TaskState,
    /// `None` = 这一档根本没有东西要回收（任务还活着），所以"等回收"这个动作不成立。
    /// 把"没等"与"等了没等到"分开放进类型里，判据才不会把前者读成后者。
    drained: Option<bool>,
    image_lo: u64,
    image_hi: u64,
}

/// 装载一份镜像、按 `flag` 写进输入格、跑一轮、把 CPU 还给启动上下文，然后交回全部读数。
/// 三档实验共用这一个动作，差别只在 `flag` 的位与"这一档会不会把任务结束掉"。
///
/// `expect_end` 必须显式给：`drain_reap` 等的是"`reap_released()` 真的涨"，而任务还活着时
/// 没有任何槽登记待回收 —— 那时它只会白等一个 120M 周期的窗口再返回 false，
/// 读数就成了"回收没发生"，而真实原因是"等待条件不成立"。这一课在 `KT_TASK_EXIT` 上付过学费。
fn run_one(flag: u64, calls: u64, tag: &str, expect_end: bool) -> Option<Round> {
    let l = match user::load(HELLO_ELF) {
        Ok(l) => l,
        Err(e) => {
            crate::log_fatal!("abi {tag}: 装载失败 —— {}", user::describe_load(e));
            return None;
        }
    };
    let (base, stack_top, entry, owned) = (l.data_va, l.stack_top, l.entry, l.owned);
    let (image_lo, image_hi) = (l.image_lo, l.image_hi);
    user::write_at(base + user::ABI_SLOT_FLAG, flag);
    let t = match sched::spawn_user(entry, stack_top, owned) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("abi {tag}: 任务建不起来 {:?}", e);
            return None;
        }
    };
    user::clear_counters();
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        while user::served() < calls && tsc::now().wrapping_sub(t0) < 200_000_000 {
            tsc::spin(20_000);
        }
        // 被杀那一档不打 `SYS_EXIT`：任务停在内核给的落脚页里等换出，
        // 所以这里只能靠 tick，再由 `wait_for_boot_task` 把 CPU 还给启动上下文。
        if !sched::wait_for_boot_task(300_000_000) {
            crate::log_fatal!("abi {tag}: 窗口收不了场");
        }
    });
    // 先等回收、再读状态：反过来就会读到"Done 但还没归化成 Free"的中间态，
    // 而那个中间态不代表任何事，只代表快门按早了。
    let drained = if expect_end { Some(drain_reap()) } else { None };
    let state = sched::state_of(t);
    Some(Round { base, stack_top, t, served: user::served(), state, drained, image_lo, image_hi })
}

/// M4-3 第一段：用户指针校验，以及"坏指针既不杀用户、也不许内核替它读内核页"。
/// 四档各挡一类错法（内容已写进 §10.3.1 的表，这里只留名字）：
/// 1 合法指针读出真值（挡"校验永远失败"那种永远 -EFAULT 的装饰）；
/// 2 内核地址与未映射地址都回 -EFAULT 且任务活着、`kills == 0`、`bad_ptrs >= 2`
///   （提权与拒绝服务这两个方向相反的错误都不会让机器挂，所以必须各自数）；
/// 3 `ac_active() == false` 独立读回 rflags.AC（挡"CLAC 被某条 `?` 提前 return 跳过"）；
/// 4 ring3 自己写 guard 页 ⇒ 只杀这个任务并且资源回账（这条不经过指针校验，把关人只能是页表+故障归属）。
/// 顺带守住两条结构性规则：地址分区（`partition_ok`）与落脚页（`tramp_ok`）。
fn t_user_pointer_checks() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("abi: APIC 起不来");
        return false;
    }
    // 这里**不**调 `user::init()`。以前那一句的含义是"容器任务的 kill 要靠手写镜像那一页
    // 当地脚页"，而这条依赖在代码里看不见，还要靠 `.ktests` 段里的先后顺序才成立
    //（段顺序由链接器决定，不由源码决定）。现在 `user::load()` 自己会建内核的落脚页。
    sched::init_boot_task();
    sched::start_workers();
    apic::timer_start().ok();

    // ---- (1)(2)(3)：三档指针实验。这一档不把任务结束掉，收尾由下面的旁观者路径做
    let peek_calls = P7_CALLS + 3;
    let r1 = match run_one(user::FLAG_PEEK, peek_calls, "peek", false) {
        Some(v) => v,
        None => {
            apic::timer_stop().ok();
            return false;
        }
    };
    // **地址分区**的读数：镜像整段在 `[USER_VA_BASE, USER_MMAP_BASE)`，
    // 内核发的用户栈在 `USER_MMAP_BASE` 之上。两条分别量——"装上了"不是证据，
    // 装上也可能是"脚手架那次没先跑"，而这条规则要的是与顺序无关。
    let page_mask = (mm::PAGE as u64) - 1;
    let stack_page = r1.stack_top & !page_mask;
    let partition_ok = r1.image_lo >= mm::USER_VA_BASE
        && r1.image_hi <= mm::USER_MMAP_BASE
        && stack_page >= mm::USER_MMAP_BASE;
    let tramp_ok = user::trampoline() == user::TRAMPOLINE_VA
        && mm::effective_flags(user::TRAMPOLINE_VA)
            .is_some_and(|e| e.user && e.executable && !e.writable);
    let peek_ok = user::read_at(r1.base + user::ABI_SLOT_PEEK_OK);
    let peek_kernel = user::read_at(r1.base + user::ABI_SLOT_PEEK_KERNEL);
    let peek_unmapped = user::read_at(r1.base + user::ABI_SLOT_PEEK_UNMAPPED);
    let ac_after = user::ac_active();
    let kills_after_peek = user::kills();
    let bad = user::bad_ptrs();
    crate::log_info!(
        "abi: peek ok={:?} kernel={:?} unmapped={:?} bad_ptrs={} kills={} ac_active={} served={} 分区={} 落脚页={} 槽位={:?}",
        peek_ok,
        peek_kernel,
        peek_unmapped,
        bad,
        kills_after_peek,
        ac_after,
        r1.served,
        partition_ok,
        tramp_ok,
        r1.state
    );
    crate::log_info!(
        "abi: 地址 image=[{:#x}..{:#x}) 栈页={:#x} 分界={:#x}",
        r1.image_lo,
        r1.image_hi,
        stack_page,
        mm::USER_MMAP_BASE
    );
    let peek_ok_good = peek_ok == Some(0xa7);
    let rejects = peek_kernel == Some(user::E_FAULT) && peek_unmapped == Some(user::E_FAULT);
    let survived = kills_after_peek == 0 && bad >= 2 && r1.served >= peek_calls;
    let window_closed = !ac_after;
    // 收尾：旁观者路径（任务已不在 CPU 上 ⇒ `terminate_task` 就地回收）。
    // 资源是否真的还回来读**两台**仪器：计数涨了 + 那两页不再映射。
    // 只看"能不能再装载一次"会漏掉"装得上是因为它换了地址"这类假绿。
    let rel_before = sched::reap_released();
    let peek_cleanup = sched::terminate_task(r1.t);
    let peek_pages_back = !mm::is_mapped(r1.base) && !mm::is_mapped(r1.stack_top);
    let peek_released = sched::reap_released() > rel_before;

    // ---- (4) 从 ring3 越界写自己的 guard 页：会被杀，所以要等回收
    let r2 = match run_one(user::FLAG_GUARD_STORE, P7_CALLS, "guard", true) {
        Some(v) => v,
        None => {
            apic::timer_stop().ok();
            return false;
        }
    };
    let kills = user::kills();
    // 程序写的是"自己栈页下面那一页"的最后一个 8 字节。**判据不去读那一格**：
    // 它从未映射，内核去读就是一次 ring0 的 #PF ⇒ 按 §9.2 直接 L4，而现场看起来
    // 像"用例把内核写坏了"。量具自己先把整机打死是最坏的一种红。
    // "有没有落地"换一台能分辨的仪器：那一页现在是不是**仍然**没映射。
    let guard_va = (r2.stack_top & !page_mask) - mm::PAGE as u64;
    let guard_still_unmapped = !mm::is_mapped(guard_va);
    let pages_back = !mm::is_mapped(r2.base) && !mm::is_mapped(r2.stack_top);
    crate::log_info!(
        "abi: guard kills={} kills精确={} 那一页仍没映射={} 槽位={:?} 页已回收={} 等到回收={:?}",
        kills,
        kills == 1,
        guard_still_unmapped,
        r2.state,
        pages_back,
        r2.drained
    );

    apic::timer_stop().ok();
    let ok = peek_ok_good
        && rejects
        && survived
        && window_closed
        && partition_ok
        && tramp_ok
        && peek_cleanup
        && peek_pages_back
        && peek_released
        && kills == 1
        && guard_still_unmapped
        && r2.state == sched::TaskState::Free
        && pages_back
        && r2.drained == Some(true);
    if !ok {
        crate::log_fatal!("abi: 判定不成立（上面四行是全部读数）");
    }
    ok
}
ktest!(KT_USER_POINTER, t_user_pointer_checks);
/// M4-3 第二段：跨页拷贝、窗口内的可恢复故障，以及"长度也是用户给的数"。
/// 七格判据与各自挡的错法在 §10.3.1 的表里，这里是清单：
/// ①② 内核→用户跨页写 512 字节由**程序逐字节**核对（`buf_ok == 1`、`buf_n == 0x200`；
///     "写满第一页、第二页没动"在内核侧看返回值看不出来，所以核对的一方必须是被写的那一边）；
/// ③ 用户→内核跨页读：内核算 FNV-1a，用例独立算同一个期望和，两数必须相等；
/// ④ 超 `COPY_MAX` 回 `TooLong`（拒绝而不是取小）；⑤ 往代码页写回 `NotWritable`；
/// ⑥ 第 2 页没映射要在校验阶段就回 `NotMapped` 且 `COPY_RECOVERED` 不动；
/// ⑦ 恢复路径本身用 `probe_copy_from` 走一次真故障：恰好搬成 8、计数 +1、AC 关、登记干净。
fn t_copy_user() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("copy: APIC 起不来");
        return false;
    }
    sched::init_boot_task();
    sched::start_workers();
    apic::timer_start().ok();
    let page_mask = (mm::PAGE as u64) - 1;
    let l = match user::load(HELLO_ELF) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("copy: 装载失败 —— {}", user::describe_load(e));
            apic::timer_stop().ok();
            return false;
        }
    };
    // 两个输入格都由内核经 SMAP 窗口写进去：`self_va` 给程序算跨页缓冲区的地址，
    // `flag` 选这一档实验。这就是 §10.3 "内核写用户内存"那一半，不是测试专用的后门。
    user::write_at(l.data_va + user::ABI_SLOT_SELF_VA, l.data_va);
    user::write_at(l.data_va + user::ABI_SLOT_FLAG, user::FLAG_BUF);
    let (base, entry, stack_top, owned) = (l.data_va, l.entry, l.stack_top, l.owned);
    let t = match sched::spawn_user(entry, stack_top, owned) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("copy: 任务建不起来 {:?}", e);
            apic::timer_stop().ok();
            return false;
        }
    };
    user::clear_counters();
    let calls = P7_CALLS + 3; // 主序列 + poke_buf + peek_buf + 那一次故意超限
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        while user::served() < calls && tsc::now().wrapping_sub(t0) < 200_000_000 {
            tsc::spin(20_000);
        }
        if !sched::wait_for_boot_task(300_000_000) {
            crate::log_fatal!("copy: 窗口收不了场");
        }
    });
    // `served()` 只证明那条超限请求**进过内核**，不证明程序已经回到用户态把返回值
    // 写进它自己的格子（实测：偶发一次读到 `buf_err=Some(0)`，而其余三格与全部计数器
    // 逐位相同 ⇒ 红了也说不出是谁的错）。这一格是程序最后写的那格，所以等它本身就等于
    // 等前面几格都落定；等不到就照原样失败，并把等了几轮打出来。
    let e_toolong_wait: u64 = (-(3i64)) as u64;
    let mut settle_reads = 0u32;
    let t_settle = tsc::now();
    while user::read_at(base + user::ABI_SLOT_BUF_ERR) != Some(e_toolong_wait) && settle_reads < 200_000 {
        settle_reads += 1;
        if tsc::now().wrapping_sub(t_settle) > 200_000_000 {
            break;
        }
        tsc::spin(20_000);
    }
    // 四格读数（页此刻还映射着、任务还活着，所以这里读得到；回收之后就读不到了）
    let self_back = user::read_at(base + user::ABI_SLOT_SELF_VA);
    let buf_ok = user::read_at(base + user::ABI_SLOT_BUF_OK);
    let buf_sum = user::read_at(base + user::ABI_SLOT_BUF_SUM);
    let buf_n = user::read_at(base + user::ABI_SLOT_BUF_N);
    let buf_err = user::read_at(base + user::ABI_SLOT_BUF_ERR);
    let kills_now = user::kills();
    let served_now = user::served();
    let expect_sum = user::fnv1a_over_pattern(user::BUF_LEN, |j| 0x5A ^ (j as u8));
    // **数值本身**，不是常量自己：`E_*` 也是会被人改的代码，而错误码是公开的 ABI，
    // 改错了的表现是旧程序把失败读成成功（§10.2"只增不改"那条的实际代价）。
    let e_inval: u64 = (-(1i64)) as u64;
    let e_fault: u64 = (-(2i64)) as u64;
    let e_toolong: u64 = (-(3i64)) as u64;
    crate::log_info!(
        "copy: buf_ok={:?} buf_n={:?} buf_sum={:?} expect_sum={:?} buf_err={:?} self_back={:?} 回填正确={} kills={} served={}/{} 等回填={} 周期={}",
        buf_ok,
        buf_n,
        buf_sum,
        expect_sum,
        buf_err,
        self_back,
        self_back == Some(base),
        kills_now,
        served_now,
        calls,
        settle_reads,
        tsc::now().wrapping_sub(t_settle)
    );
    crate::log_info!(
        "copy: 错误码数值 E_INVALID={:#x} E_FAULT={:#x} E_TOO_LONG={:#x} 三个都不同={}",
        user::E_INVALID,
        user::E_FAULT,
        user::E_TOO_LONG,
        user::E_INVALID != user::E_FAULT && user::E_FAULT != user::E_TOO_LONG
    );

    // ---- ④⑤⑥：三条必须在**拷贝之前**就失败的调用（不经 ABI，直接调函数）
    let too_long = user::copy_into_scratch(base, user::COPY_MAX + 1);
    let mut sink = [0u8; 16];
    let stack_page = stack_top & !page_mask;
    // 这一段的前 8 字节在栈页里、后 8 字节在**没映射**的那一页上：校验应当逐页看到第二页
    let straddle_unmapped = user::copy_from_user(stack_page + mm::PAGE as u64 - 8, &mut sink);
    let next_mapped = mm::is_mapped(stack_page + mm::PAGE as u64);
    let write_rx = user::copy_to_user(&[0u8; 16], entry);
    let rec_after_three = trap::COPY_RECOVERED.load(core::sync::atomic::Ordering::Relaxed);
    crate::log_info!(
        "copy: 超长={} 写代码页={} 跨未映射页={} 上面那页映射着={} 三条里恢复计数={}",
        matches!(too_long, Err(user::PtrError::TooLong)),
        matches!(write_rx, Err(user::PtrError::NotWritable)),
        matches!(straddle_unmapped, Err(user::PtrError::NotMapped)),
        next_mapped,
        rec_after_three
    );

    // ---- ⑦：恢复路径。`probe_copy_from` 跳过校验，所以这次访**真的**会故障。
    let got = user::probe_copy_from(stack_page + mm::PAGE as u64 - 8, 0x10);
    let recovered = trap::COPY_RECOVERED.load(core::sync::atomic::Ordering::Relaxed) - rec_after_three;
    let ac = user::ac_active();
    let probes_clean = trap::probe_registers_clear();
    let stale = trap::PF_STALE_HITS.load(core::sync::atomic::Ordering::Relaxed);
    crate::log_info!(
        "copy: 恢复路径 搬成={} 期望=8 接住次数={} ac={} 登记干净={} pf_stale_hits={} 槽位={:?}",
        got,
        recovered,
        ac,
        probes_clean,
        stale,
        sched::state_of(t)
    );
    let cleanup = sched::terminate_task(t);
    apic::timer_stop().ok();
    let pages_back = !mm::is_mapped(base) && !mm::is_mapped(stack_top);
    crate::log_info!(
        "copy: 判定 收尾={} 页已回收={} 恢复不重复={}",
        cleanup,
        pages_back,
        recovered == 1
    );
    buf_ok == Some(1)
        && buf_n == Some(user::BUF_LEN as u64)
        && buf_sum == Some(expect_sum)
        // `-3` 这一格是"每个号都得有人走过"那条规则的证人：程序故意超限，内核分开回
        && buf_err == Some(e_toolong)
        && user::E_INVALID == e_inval
        && user::E_FAULT == e_fault
        && user::E_TOO_LONG == e_toolong
        && self_back == Some(base)
        && kills_now == 0
        && served_now >= calls
        && matches!(too_long, Err(user::PtrError::TooLong))
        && matches!(write_rx, Err(user::PtrError::NotWritable))
        && matches!(straddle_unmapped, Err(user::PtrError::NotMapped))
        && !next_mapped
        && rec_after_three == 0
        && got == 8
        && recovered == 1
        && !ac
        && probes_clean
        && stale == 0
        && cleanup
        && pages_back
}
ktest!(KT_COPY_USER, t_copy_user);
/// M4-4：`syscall`/`sysret` 快路径。判据的原则是**读用户这一侧回来的事实**，
/// 不读内核里的常数（ADR-025 的"装机参数"表就是靠这一格兑现的）。
fn t_syscall_fastpath() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("fast: APIC 起不来");
        return false;
    }
    sched::init_boot_task();
    sched::start_workers();
    apic::timer_start().ok();
    let l = match user::load(HELLO_ELF) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("fast: 装载失败 —— {}", user::describe_load(e));
            apic::timer_stop().ok();
            return false;
        }
    };
    user::write_at(l.data_va + user::ABI_SLOT_FLAG, user::FLAG_FASTPATH);
    let (base, entry, stack_top, owned) = (l.data_va, l.entry, l.stack_top, l.owned);
    let t = match sched::spawn_user(entry, stack_top, owned) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("fast: 任务建不起来 {:?}", e);
            apic::timer_stop().ok();
            return false;
        }
    };
    user::clear_counters();
    // 主序列 32 次（`int 0x80`）+ `sys_abi_info` 1 次 + 快路径 8 次
    const FAST_CALLS: u64 = 8;
    let calls = P7_CALLS + 1 + FAST_CALLS;
    let back = apic::with_interrupts(|| {
        let t0 = tsc::now();
        while user::served() < calls && tsc::now().wrapping_sub(t0) < 200_000_000 {
            tsc::spin(20_000);
        }
        // 这条等待能收场**本身就是 IF 的判据**：快路径出口若把 IF 写成 0，
        // 这个任务就在自己的 `jmp .` 里关着中断死转，boot 上下文永远回不来（M4-1 实测过）。
        sched::wait_for_boot_task(300_000_000)
    });
    let abi = user::read_at(base + user::ABI_SLOT_ABI_WORD);
    let fast_ping = user::read_at(base + user::ABI_SLOT_FAST_PING);
    let fast_cs = user::read_at(base + user::ABI_SLOT_FAST_CS);
    let fast_ss = user::read_at(base + user::ABI_SLOT_FAST_SS);
    let kills = user::kills();
    let served = user::served();
    let (efer, star, lstar) = trap::fast_readback();
    let (fc, fmin, fcold, flead) = trap::p7_fast_of(crate::arch::x86_64::cpu::BSP_SLOT);
    let ints = trap::stats_syscall_of(crate::arch::x86_64::cpu::BSP_SLOT);
    let (area_kstack, area_slot) = trap::fast_area_of(crate::arch::x86_64::cpu::BSP_SLOT).unwrap_or((0, 0));
    let rsp0 = trap::rsp0_of(crate::arch::x86_64::cpu::BSP_SLOT);
    let (smep, smap) = crate::arch::x86_64::cpu::user_protections_active();
    let bits = abi.unwrap_or(0) & 0xFFFF;
    crate::log_info!(
        "fast: abi={:#x} major={} minor={} 位=[fast={} smap={} smep={}] ping={:?} cs={:?} ss={:?}",
        abi.unwrap_or(0),
        (abi.unwrap_or(0) >> 32) as u32,
        ((abi.unwrap_or(0) >> 16) & 0xFFFF) as u64,
        bits & user::F_FASTPATH != 0,
        bits & user::F_SMAP != 0,
        bits & user::F_SMEP != 0,
        fast_ping,
        fast_cs,
        fast_ss
    );
    crate::log_info!(
        "fast: 装机读回 efer={:#x} star={:#x} lstar={:#x} on={} 槽位={} rsp0={:#x} 区={:#x} 同源={}",
        efer,
        star,
        lstar,
        trap::fastpath_on(),
        area_slot,
        rsp0,
        area_kstack,
        rsp0 == area_kstack
    );
    crate::log_info!(
        "fast: P7 对比 int0x80[样本={} min={} mean={} max={} cold={}] vs syscall[样本={} min={:?} cold={} lead={:?}]",
        ints.faults,
        ints.min_cycles,
        ints.mean_cycles,
        ints.max_cycles,
        ints.cold_samples,
        fc,
        fmin,
        fcold,
        flead
    );
    let cleanup = sched::terminate_task(t);
    apic::timer_stop().ok();
    let ok = trap::fastpath_on()
        && efer & 1 != 0
        // 特性位：程序读到的那一位与内核自己读回的 CR4 两位必须讲同一件事（两台仪器）
        && (bits & user::F_FASTPATH != 0)
        && (bits & user::F_SMAP != 0) == smap
        && (bits & user::F_SMEP != 0) == smep
        && (abi.unwrap_or(0) >> 32) as u32 == user::ABI_MAJOR as u32
        && ((abi.unwrap_or(0) >> 16) & 0xFFFF) as u64 == user::ABI_MINOR
        // 返回值穿过边界 + 硬件从 STAR 算出的选择子被用户读回来
        && fast_ping.is_some_and(|v| v >= 1)
        && fast_cs == Some(0x23)
        && fast_ss == Some(0x1b)
        && fc >= FAST_CALLS
        && fmin > 0
        && served >= calls
        && back
        && kills == 0
        && trap::PF_STALE_HITS.load(core::sync::atomic::Ordering::Relaxed) == 0
        && rsp0 == area_kstack
        && cleanup
        && !mm::is_mapped(base);
    if !ok {
        crate::log_fatal!("fast: 判定不成立（上面四行是全部读数）");
    }
    ok
}
ktest!(KT_SYSCALL_FAST, t_syscall_fastpath);

