//! ELF 容器解析、装载与运行用例（T0.1 纯搬移）。

use crate::arch::x86_64::{apic, cpu, trap};
use crate::{acpi, arch, elf, heap, mm, sched, tsc, user};
use crate::ktests::common::{HELLO_ELF, P7_CALLS};
use crate::ktest;
use alloc::vec::Vec;
use core::cell::UnsafeCell;

/// 用例的可变副本缓冲。**这里不能用 `Vec`**：本内核的分配器上限是
/// `heap::LARGE_MAX = 2048` 字节（`t_heap_rejects_oversize` 验的就是这条），
/// 而真产物有 18 KB —— 本用例第一版写的是 `HELLO_ELF.to_vec()`，
/// 第一次分配就走 `handle_alloc_error`，整机构成 39：
/// `kernel panic at /rustc/.../library/alloc/src/alloc.rs`。
/// 这条不是测试的小修补，它是 M4-2 的一条硬约束：**加载器不许按段大小分配内存**，
/// 只能从文件缓冲区流式取字节（已记 BACKLOG）。
const ELF_SCRATCH: usize = 32 * 1024;
struct ElfScratch(UnsafeCell<[u8; ELF_SCRATCH]>);
// SAFETY: 只在 ktest 自己的上下文里用，调用点在关中断窗口内，且每次借用都被
// `with_elf_copy` 限制在一次调用的函数体内——不同时存在两份可变引用。
unsafe impl Sync for ElfScratch {}
static ELF_BUF: ElfScratch = ElfScratch(UnsafeCell::new([0u8; ELF_SCRATCH]));

/// 把夹具拷进静态缓冲，交出一个**只在这次调用内活着**的可变切片。
/// 返回 `None` = 缓冲不够大。那是一种"用例自己失效"的状态，必须逐条算失败，
/// 绝不能让"跳过这条负样本"读成"这条负样本通过了"。
fn with_elf_copy<R>(f: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
    let n = HELLO_ELF.len();
    if n > ELF_SCRATCH {
        return None;
    }
    // SAFETY: 见 ElfScratch——单一持有者、关中断窗口内的用例上下文，
    // 且返回的切片在本次调用内就失效（不外泄 `&'static mut`）
    let buf = unsafe { &mut *ELF_BUF.0.get() };
    buf[..n].copy_from_slice(HELLO_ELF);
    Some(f(&mut buf[..n]))
}

fn put16(v: &mut [u8], at: usize, x: u16) {
    v[at..at + 2].copy_from_slice(&x.to_le_bytes());
}
fn put32(v: &mut [u8], at: usize, x: u32) {
    v[at..at + 4].copy_from_slice(&x.to_le_bytes());
}
fn put64(v: &mut [u8], at: usize, x: u64) {
    v[at..at + 8].copy_from_slice(&x.to_le_bytes());
}
fn get16(v: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([v[at], v[at + 1]])
}
fn get64(v: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&v[at..at + 8]);
    u64::from_le_bytes(a)
}

/// 一条负样本必须命中**它自己那一格**错误码。
///
/// 只要求"解析失败"的话，任何一条提前生效的检查都能让其余的门看起来像在工作——
/// 这正是 §12.4.1 规则 3 要防的那种绿。所以这里比对具体变体，
/// 并把没命中的那条单独打一行（`want`/`got` 两边都给名字，不给数字）。
fn rejects(name: &str, want: elf::ElfError, mutate: impl FnOnce(&mut [u8]), ok: &mut usize, bad: &mut usize) {
    let Some(r) = with_elf_copy(|v| {
        mutate(v);
        elf::parse(v)
    }) else {
        *bad += 1;
        crate::log_fatal!(
            "elf 负样本 {name}: 夹具 {}B 超出用例缓冲 {ELF_SCRATCH}B（本条没跑成，不算通过）",
            HELLO_ELF.len()
        );
        return;
    };
    match r {
        Err(got) if got == want => *ok += 1,
        Err(got) => {
            *bad += 1;
            crate::log_fatal!(
                "elf 负样本 {name}: 期望 {} 实际 {}",
                elf::describe(want),
                elf::describe(got)
            );
        }
        Ok(_) => {
            *bad += 1;
            crate::log_fatal!("elf 负样本 {name}: 期望被拒绝（{}）但通过了", elf::describe(want));
        }
    }
}

/// M4-2 第一段：ELF64 程序头解析。判据两层——正样本收下真产物，
/// 二十来条负样本每条各命中一格拒绝理由。
fn t_elf_container() -> bool {
    // 头部字段**直接从夹具读**：`elf::parse` 不改动输入，只有负样本需要副本
    // （而副本走静态缓冲，理由见 `ELF_SCRATCH` 那段——一次 `to_vec()` 就是把整机打到 39）。
    let h: &[u8] = HELLO_ELF;
    if h.len() > ELF_SCRATCH {
        crate::log_fatal!("elf: 夹具 {}B 超出用例缓冲 {ELF_SCRATCH}B", h.len());
        return false;
    }
    let phoff = get64(h, 32) as usize;
    let phent = get16(h, 54) as usize;
    let phnum = get16(h, 56) as usize;
    if phent < 56 || phnum < 2 {
        crate::log_fatal!("elf: 夹具本身不像预期（phent={} phnum={}）", phent, phnum);
        return false;
    }
    // ELF64 的程序头是定长 56 字节，字段偏移写在一处，下面十几条负样本共用
    let (i_type, i_flags, i_off, i_vaddr, i_filesz, i_memsz, i_align) = (0usize, 4, 8, 16, 32, 40, 48);

    let p = match elf::parse(h) {
        Ok(p) => p,
        Err(e) => {
            crate::log_fatal!("elf: 真产物被拒绝 —— {}", elf::describe(e));
            return false;
        }
    };
    // **正样本的不变量**。不写死地址与长度：那些随 `user/hello` 的改动而变，
    // 写死会让"改了用户程序"与"解析器坏了"读起来是同一件事。
    let segs = p.segments();
    let entry_in_text = segs.iter().any(|s| s.contains_va(p.entry) && s.executable && s.readable);
    let congruent = segs
        .iter()
        .all(|s| s.vaddr % mm::PAGE as u64 == s.offset % mm::PAGE as u64);
    let wx = segs.iter().all(|s| !(s.writable && s.executable));
    let user_half = segs.iter().all(|s| s.vaddr < elf::USER_VA_TOP);
    let no_overlap = segs.windows(2).all(|w| w[0].va_end() <= w[1].vaddr);
    crate::log_info!(
        "elf: fixture={}B entry={:#x} phnum={} load={} segs={}",
        h.len(),
        p.entry,
        p.phnum,
        p.n,
        segs.len()
    );
    for s in segs {
        crate::log_info!(
            "elf:   seg off={:#x} va={:#x} fsz={:#x} msz={:#x} {}{}{} pages={}",
            s.offset,
            s.vaddr,
            s.filesz,
            s.memsz,
            if s.readable { 'r' } else { '-' },
            if s.writable { 'w' } else { '-' },
            if s.executable { 'x' } else { '-' },
            s.pages().unwrap_or(0)
        );
    }
    if !(entry_in_text && congruent && wx && user_half && no_overlap && p.n >= 1) {
        crate::log_fatal!(
            "elf: 正样本不变量不成立 entry_in_text={} congruent={} wx={} user_half={} no_overlap={}",
            entry_in_text,
            congruent,
            wx,
            user_half,
            no_overlap
        );
        return false;
    }

    let mut ok = 0usize;
    let mut bad = 0usize;
    // ---- 头部字段：每改一处，必须命中对应那一格
    // "太短"这条不用副本：`parse` 不改输入，直接把夹具的前 63 个字节给它就行
    match elf::parse(&h[..63]) {
        Err(elf::ElfError::TooShort) => ok += 1,
        Err(other) => {
            bad += 1;
            crate::log_fatal!(
                "elf 负样本 太短: 期望 {} 实际 {}",
                elf::describe(elf::ElfError::TooShort),
                elf::describe(other)
            );
        }
        Ok(_) => {
            bad += 1;
            crate::log_fatal!("elf 负样本 太短: 期望被拒绝（截断成 63 字节）但它通过了");
        }
    }
    rejects("魔数", elf::ElfError::BadMagic, |v| v[1] = b'X', &mut ok, &mut bad);
    rejects("非 64 位", elf::ElfError::Not64Bit, |v| v[4] = 1, &mut ok, &mut bad);
    rejects("大端", elf::ElfError::NotLittleEndian, |v| v[5] = 2, &mut ok, &mut bad);
    rejects("ident 版本", elf::ElfError::BadVersion, |v| v[6] = 0, &mut ok, &mut bad);
    rejects("e_version", elf::ElfError::BadVersion, |v| put32(v, 20, 2), &mut ok, &mut bad);
    rejects(
        "不是 x86-64",
        elf::ElfError::WrongMachine,
        |v| put16(v, 18, 0x28),
        &mut ok,
        &mut bad,
    );
    rejects(
        "ET_DYN",
        elf::ElfError::RelocationUnsupported,
        |v| put16(v, 16, 3),
        &mut ok,
        &mut bad,
    );
    rejects(
        "ET_REL",
        elf::ElfError::NotExecutableImage,
        |v| put16(v, 16, 1),
        &mut ok,
        &mut bad,
    );
    rejects(
        "每项过小",
        elf::ElfError::BadPhEntSize,
        |v| put16(v, 54, 48),
        &mut ok,
        &mut bad,
    );
    rejects(
        "表越界",
        elf::ElfError::PhdrsOutOfBounds,
        |v| put16(v, 56, 0xffff),
        &mut ok,
        &mut bad,
    );

    // ---- 段级：拿夹具里真实存在的前两段来改
    let s0 = phoff;
    let s1 = phoff + phent;
    let va0 = get64(h, s0 + i_vaddr);
    let va1 = get64(h, s1 + i_vaddr);
    let fsz0 = get64(h, s0 + i_filesz);
    let off1 = get64(h, s1 + i_off);
    rejects(
        "align 不是 2 的幂",
        elf::ElfError::BadAlignment,
        |v| put64(v, s0 + i_align, 0x3000),
        &mut ok,
        &mut bad,
    );
    rejects(
        "W+X",
        elf::ElfError::WxViolation,
        |v| put32(v, s0 + i_flags, 4 | 2 | 1),
        &mut ok,
        &mut bad,
    );
    rejects(
        "装进内核地址",
        elf::ElfError::NotUserRange,
        |v| put64(v, s0 + i_vaddr, 0xffff_ffff_8000_0000),
        &mut ok,
        &mut bad,
    );
    rejects(
        "文件区间越界",
        elf::ElfError::SegmentOutOfBounds,
        |v| put64(v, s0 + i_filesz, fsz0 + 0x400_0000),
        &mut ok,
        &mut bad,
    );
    rejects(
        "memsz<filesz",
        elf::ElfError::SegmentOutOfBounds,
        |v| put64(v, s1 + i_memsz, 4),
        &mut ok,
        &mut bad,
    );
    rejects(
        "vaddr/offset 不同余",
        elf::ElfError::MisalignedSegment,
        |v| put64(v, s1 + i_off, off1 + 1),
        &mut ok,
        &mut bad,
    );
    rejects(
        "两段重叠",
        elf::ElfError::OverlappingSegments,
        |v| put64(v, s1 + i_vaddr, va0),
        &mut ok,
        &mut bad,
    );
    rejects(
        "没有可加载段",
        elf::ElfError::NoLoadSegment,
        |v| {
            for i in 0..phnum {
                put32(v, phoff + i * phent + i_type, 2); // 全改成 PT_DYNAMIC
            }
        },
        &mut ok,
        &mut bad,
    );
    rejects(
        "入口不可执行",
        elf::ElfError::EntryNotExecutable,
        |v| put64(v, 24, va1),
        &mut ok,
        &mut bad,
    );
    // 0x401000 落在两个段之间的**空洞**里：段的范围是 [0x400000,+0x53) 与 [0x402000,+0x1000)。
    // （第一次写的是 0x400000，那正好是段首、也就是合法入口——负样本自己写错时
    //  报的是"解析器放过了坏容器"，那条红是它的证据，不是解析器的。）
    rejects(
        "入口不在任何段里",
        elf::ElfError::EntryNotLoaded,
        |v| put64(v, 24, 0x40_1000),
        &mut ok,
        &mut bad,
    );

    // ---- 段数上限：把 phnum 扩到 9，多出来的项写成"零长度、互不重叠、只读"，
    // 让它们都通过前面每一道门，最后必须撞在 TooManySegments 上。
    // 这是唯一能证明"上限真在起作用"而不是装饰的负样本。
    let base_off = get64(h, s0 + i_off);
    rejects(
        "段数超上限",
        elf::ElfError::TooManySegments,
        |v| {
            put16(v, 56, 9);
            for i in phnum..9 {
                let at = phoff + i * phent;
                put32(v, at + i_type, 1);
                put32(v, at + i_flags, 4);
                put64(v, at + i_off, base_off);
                put64(v, at + i_vaddr, 0x800_0000 + (i as u64) * mm::PAGE as u64 * 64);
                put64(v, at + i_filesz, 0);
                put64(v, at + i_memsz, 0);
                put64(v, at + i_align, mm::PAGE as u64);
            }
        },
        &mut ok,
        &mut bad,
    );

    crate::log_info!("elf: 负样本 命中={} 未命中={}（未命中的每条已单独报）", ok, bad);
    bad == 0 && ok >= 21
}
ktest!(KT_ELF, t_elf_container);

fn t_elf_load_run() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("elfload: APIC 起不来，跑不了时间片");
        return false;
    }
    let h = HELLO_ELF;
    let loaded = match user::load(h) {
        Ok(l) => l,
        Err(e) => {
            crate::log_fatal!("elfload: 加载失败 —— {}", user::describe_load(e));
            return false;
        }
    };
    crate::log_info!(
        "elfload: segs={} pages={} entry={:#x} data={:#x} stack_top={:#x}",
        loaded.segs,
        loaded.pages,
        loaded.entry,
        loaded.data_va,
        loaded.stack_top
    );
    // **生效位**（ADR-026 的判据落点）：入口那一页必须 user+可执行+不可写，
    // 可写段必须 user+可写+不可执行。这里读的是整条页表链相与/相或之后的结果，
    // 不是加载器"打算给什么"。
    let code_eff = mm::effective_flags(loaded.entry);
    let data_eff = mm::effective_flags(loaded.data_va);
    let eff_ok = code_eff.is_some_and(|f| f.user && f.executable && !f.writable)
        && data_eff.is_some_and(|f| f.user && f.writable && !f.executable);
    // 加载器给的三个权限分支里，`USER_R`（`r--` 那条）**不在上面两条里**。
    // 它由程序自己的第四个槽证明（见 user/hello 的 OFF_RODATA 注释）：
    // 分支没有证据 = 写好了却没人走过的代码。
    crate::log_info!(
        "elfload: eff code={:?} data={:?}",
        code_eff,
        data_eff
    );
    if !eff_ok {
        crate::log_fatal!("elfload: 生效位不对（见上一行）");
        return false;
    }

    sched::init_boot_task();
    sched::start_workers();
    user::clear_counters();
    // 装载产物（代码/数据/用户栈）连同 `spawn_user` 自己加的内核栈一起归这个任务
    let t = match sched::spawn_user(loaded.entry, loaded.stack_top, loaded.owned) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("elfload: spawn_user 失败 {:?}", e);
            return false;
        }
    };
    apic::timer_start().ok();
    // **容量的证人**（M4 欠账第一条的落点）：一个任务名下的映射条数。
    // 按段切块之前它是"页数 + 2"（这份夹具 5 页 ⇒ 7 条）；现在每段按"剩余页数的二进制位数"
    // 切块 ⇒ 同一份夹具 6 条（串口上那行 `收尾回收 released=6` 是第二台仪器）。
    // 判的是**余量**而不是"等于 6"：等于 6 只是这一版夹具的快照，改夹具就会红，
    // 而那种红不代表容量坏了。真正要挡的是"再加一段就撞 `MAX_OWNED`，
    // 而失败长得像 `MmError::Unsupported` 而不是像容量到了头"。
    let owned_now = sched::owned_of(t);
    let headroom = sched::MAX_OWNED.saturating_sub(owned_now);
    crate::log_info!(
        "elfload: 容量 owned={} 上限={} 镜像页数={} 余量={}",
        owned_now,
        sched::MAX_OWNED,
        loaded.pages,
        headroom
    );
    if headroom < 2 {
        crate::log_fatal!("elfload: 容量余量不足 2 条映射（要么改 `MAX_OWNED`，要么把夹具收小）");
    }
    // 程序第一件事就是把魔数写进它自己的数据页，所以"魔数到位"就是"跑到第 X 行"的证人。
    // 超时用周期数上限而不是"等多久"：这台机器上 TSC 非 invariant（§12.4.1 规则 2），
    // 只保证有界，不承诺毫秒。
    let mut rounds = 0u64;
    // `P7_CALLS` = 夹具这一版会打的调用总数（1 次 ping + 29 次归因 ping + add + unknown）。
    // 等的是"打完"而不是"开始打了"：窗口收得太早，第五个槽（loops）还没被写，
    // 读回来不是 29 就是判据红——那条红是真的，但原因在用例的等待条件，不在被测代码。

    // **读用户页必须发生在窗口之外**。SMAP 窗口的约束是"开着 AC 的那几行里不许有中断"
    // （`user.rs::read_slot` 的注释），而 `with_interrupts` 内 IF=1 —— 所以在窗口里轮询
    // 魔数是错的（第一版就是这么写的，那条 SAFETY 注释本身也不成立）。
    // 正确的形状：窗口内只做"让任务跑起来 + 看内核自己的计数器"，关掉之后才碰用户页。
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        // `served` 是内核 .data 里的原子量，读它不需要 SMAP 窗口
        while user::served() < P7_CALLS && tsc::now().wrapping_sub(t0) < 200_000_000 {
            rounds += 1;
            tsc::spin(20_000);
        }
        // 程序在第三次调用之后还要读一次 .rodata 再写第四个槽，给一小段落地时间；
        // 它写完就停在 `hlt`，所以下面 `wait_for_boot_task` 一定会把 CPU 还回来。
        tsc::spin(2_000_000);
        if !sched::wait_for_boot_task(300_000_000) {
            crate::log_fatal!("elfload: 窗口收不了场（启动上下文没回到 CPU）");
        }
    });
    apic::timer_stop().ok();
    let magic = user::read_at(loaded.data_va);
    // 偏移 8/16/24/32 是夹具的约定（`user/hello` 的 `OFF_*`）。它们不是内核读出来的，
    // 但**魔数在偏移 0 到位**证明了这一页就是那个结构、且程序的写入落在这里；
    // 值本身对不对则由下面四条各判一格（往返、参数、错误码、只读段可读）。
    let ping = user::read_at(loaded.data_va + 8);
    let add = user::read_at(loaded.data_va + 16);
    let unk = user::read_at(loaded.data_va + 24);
    let rod = user::read_at(loaded.data_va + 32);
    let served = user::served();
    let state = sched::state_of(t);
    // 第二台仪器：这个任务被换上来过几次（`runs`）。如果冷样本数 == 换入次数，
    // 说明"冷"发生在**每次重新进入之后的第一次调用**，而不是发生在入口指令本身；
    // 如果冷样本只有 1 次而 runs 远大于 1，那才是"一次性预热"。
    // 这两个数是独立计数的（一个来自 P7 的门槛分类，一个来自 run queue 的换入计数）。
    let runs = sched::runs_of(t);
    // **P7 的样本数必须等于内核服务过的调用数**：一张表按"进了出口记账"计数，
    // 另一张按"分发器被调到"计数，两者不等就说明有一类向量绕过了记账（或记了两次）。
    // 这条同时是 P5 干净的反证：把系统调用错并进 P5 的那版实现里，
    // `timer 判据` 的两台仪器差 3（= 这 3 次调用），现在它们各自对得上。
    let sc = trap::stats_syscall_of(crate::arch::x86_64::cpu::BSP_SLOT);
    crate::log_info!(
        "elfload: magic={:?} ping={:?} add={:?} unk={:?} rodata={:?} served={} unknown_nr={} rounds={} runs={} state={:?} guard_unmapped={}",
        magic,
        ping,
        add,
        unk,
        rod,
        served,
        user::unknown_nr(),
        rounds,
        runs,
        state,
        !mm::is_mapped(loaded.stack_top - mm::PAGE as u64 - 8)
    );
    let loops = user::read_at(loaded.data_va + 40);
    // **P7 归因**：`first` = 这个 CPU 第一次被记账的代价，`min` = 同一条路径
    // 连续 30 多次调用里最小的那一次。两者之比就是"冷启动"与"结构成本"的分界读数。
    // 这里刻意只报比值不报结论：判据要能分辨，但"为什么"要另做一次实验才能写。
    let ratio = if sc.min_cycles > 0 {
        sc.first_cycles / sc.min_cycles
    } else {
        0
    };
    crate::log_info!(
        "elfload: p7 samples={} lead={:?} min={} mean={} max={} first/min={} cold(>={}周期)={} runs={} loops={:?} (served={}) p5_last_vec={:#x}",
        sc.faults,
        trap::p7_lead(),
        sc.min_cycles,
        sc.mean_cycles,
        sc.max_cycles,
        ratio,
        trap::P7_COLD_CYCLES,
        sc.cold_samples,
        runs,
        loops,
        served,
        trap::p5_last_vec()
    );
    // 栈的 guard：栈页下面那一页必须没映射（这条与 `init()` 的形状同源）。
    // `stack_top` 在栈页内，`- PAGE` 落到 guard 页；`- 8` 是因为栈顶留了 16 字节。
    let guard_ok = !mm::is_mapped(loaded.stack_top - mm::PAGE as u64 - 8);
    // **尺子必须能分辨**（§12.4.1 规则 3）：`ImageInDynamicRegion` 没人走就是装饰。
    // 做法：把夹具第一条可执行 PT_LOAD 连同 `e_entry` 一起向上平移 1 MiB，让它跨过
    // `USER_MMAP_BASE` 那条线。两个坑都踩过才写在这儿：①只动段不动 `e_entry` 会先在
    // `EntryNotLoaded` 上失败，那条证人不是这一格；②程序头偏移要照 `elf.rs` 那张表
    // （`p_vaddr` 在 +16，不是 +0x20——那是 `p_filesz`，凭记忆写会命中 `SegmentOutOfBounds`）。
    // 教训本身是 ADR-026"按架构偏移声明字段"在防的事。详见 BACKLOG ⑪。
    let mut partition_reject = false;
    if let Some(r) = with_elf_copy(|v| {
        let phoff = get64(v, 0x20) as usize;
        let phentsize = get16(v, 0x36) as usize;
        let phnum = get16(v, 0x38) as usize;
        let mut vaddr_at = 0usize;
        for i in 0..phnum {
            let base = phoff + i * phentsize;
            let ty = u32::from_le_bytes([v[base], v[base + 1], v[base + 2], v[base + 3]]);
            let flags = u32::from_le_bytes([
                v[base + 4],
                v[base + 5],
                v[base + 6],
                v[base + 7],
            ]);
            if ty == 1 && flags & 4 != 0 {
                vaddr_at = base + 16;
                break;
            }
        }
        if vaddr_at == 0 {
            crate::log_fatal!("elfload: 分区负样本找不到可执行的 PT_LOAD（本条没跑成，不算通过）");
            return false;
        }
        let shift = 0x0010_0000u64;
        put64(v, 0x18, get64(v, 0x18) + shift);
        put64(v, vaddr_at, get64(v, vaddr_at) + shift);
        match user::load(v) {
            Err(user::LoadError::ImageInDynamicRegion { va, end }) => {
                crate::log_info!(
                    "elfload: 分区负样本按预期被拒 va={va:#x} end={end:#x}（分界={:#x}）",
                    mm::USER_MMAP_BASE
                );
                true
            }
            Err(e) => {
                crate::log_fatal!("elfload: 分区负样本命中了别的拒绝码 —— {}", user::describe_load(e));
                false
            }
            Ok(_) => {
                crate::log_fatal!("elfload: 分区负样本**装上了**（分区规则没生效）");
                false
            }
        }
    }) {
        partition_reject = r;
    }
    let roundtrip_ok = loops == Some(28)
        && magic == Some(0xa5a5_5a5a_1234_5678)
        && ping.is_some_and(|v| v >= 1)
        && add == Some(0x2a + 0x12)
        && unk == Some(user::E_INVALID)
        && rod == Some(0xa7)
        && served >= P7_CALLS
        && user::unknown_nr() >= 1
        && guard_ok
        && headroom >= 2
        && partition_reject
        && sc.faults >= served;
    if !roundtrip_ok {
        crate::log_fatal!("elfload: 判据不成立（上面一行是全部读数）");
    }
    // 收尾：本用例只验"装得上、跑得通"，资源要还回去——夹具的 VA 是容器定死的
    // （`ET_EXEC` 搬不动），留着就会让后面任何一次 `user::load` 撞 `VaTaken`。
    // 这一句同时也是 `terminate_task` 的第二个使用点：它必须能在"任务不在 CPU 上"时
    // 就地回收，而不需要等一次 tick。
    if sched::terminate_task(t) {
        crate::log_info!("elfload: 收尾回收 slots={} released={}", mm::reservation_count(), sched::reap_released());
    }
    roundtrip_ok
}
ktest!(KT_ELF_LOAD, t_elf_load_run);
// ---- ADR-075（W3 P5a）第二个用户产物：真在 ring3 打 12/13/14 ----
//
// 与 `t_elf_load_run` 的分工：那条证"容器 → 页表 → ring3"这段路（用 hello），
// 这条证**用户态自己调 VMO 三个号并读回映射**（用 probe）。两份容器基址错开
// （hello 0x100000000 / probe 0x100080000，都在加载器窗口里），所以可以共存。
// 八格：①魔数到位 ②ABI 的 F_VMO 位 ③12 的句柄形状 ④13 的字节数 ⑤14 的 VA 落在动态区
// ⑥探针自己读回一致 ⑦生效位是第二台仪器 ⑧收场之后句柄/VMO/帧/VA 全回基线。
// 变异：M10 探针不打 14 ⇒ ⑤⑥⑦红；M11 内核不回填/不映射 ⇒ ⑥红；
// M12 新包的 unsafe 不登记 ⇒ check-unsafe 红（这条同时补 P5-0 留下的那一半证人）。

/// 与 `user/probe/src/main.rs` 独立声明的同一组常量（两侧各写一遍，靠读回对账）。
#[cfg(feature = "handles")]
const PROBE_MAGIC: u64 = 0xa5a5_5a5a_8765_4321;
#[cfg(feature = "handles")]
const PROBE_OFF_ABI: u64 = 8;
#[cfg(feature = "handles")]
const PROBE_OFF_HANDLE: u64 = 16;
#[cfg(feature = "handles")]
const PROBE_OFF_WRITTEN: u64 = 24;
#[cfg(feature = "handles")]
const PROBE_OFF_MAP_VA: u64 = 32;
#[cfg(feature = "handles")]
const PROBE_OFF_READBACK: u64 = 40;
#[cfg(feature = "handles")]
const PROBE_OFF_DONE: u64 = 48;
#[cfg(feature = "handles")]
const PROBE_OFF_X_REQ: u64 = 56;
#[cfg(feature = "handles")]
const PROBE_OFF_X_RET: u64 = 64;
#[cfg(feature = "handles")]
const PROBE_OFF_X_READ: u64 = 72;
#[cfg(feature = "handles")]
const PROBE_OFF_WX_RET: u64 = 80;
#[cfg(feature = "handles")]
const PROBE_OFF_UN_RET: u64 = 88;
#[cfg(feature = "handles")]
const PROBE_PATTERN: [u8; 8] = [0x5A, 0xA5, 1, 2, 3, 4, 5, 6];
/// 探针这一版**至少**打几个调用：abi_info + create + write + map + 1 次扩展形 + 2 次被拒 = 7。
/// 等的是"打完"而不是"开始打了"（与 `P7_CALLS` 同一条纪律）。候选最多试四组 ⇒
/// 窗口尾部那段落地等待从 2M 提到 8M 周期。
#[cfg(feature = "handles")]
const PROBE_CALLS: u64 = 7;

#[cfg(feature = "handles")]
fn t_probe_ring3() -> bool {
    use crate::ktests::common::PROBE_ELF;
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("probe: APIC 起不来，跑不了时间片");
        return false;
    }
    let f0 = mm::free_frames();
    let va0 = mm::reservation_count();
    let lv0 = crate::handle::live();
    let v0 = crate::vmo::vmo_count();
    let loaded = match user::load(PROBE_ELF) {
        Ok(l) => l,
        Err(e) => {
            crate::log_fatal!("probe: 加载失败 —— {}", user::describe_load(e));
            return false;
        }
    };
    crate::log_info!(
        "probe: segs={} pages={} entry={:#x} data={:#x} stack_top={:#x} 夹具={}B",
        loaded.segs, loaded.pages, loaded.entry, loaded.data_va, loaded.stack_top, PROBE_ELF.len());
    sched::init_boot_task();
    sched::start_workers();
    user::clear_counters();
    let t = match sched::spawn_user(loaded.entry, loaded.stack_top, loaded.owned) {
        Ok(t) => t,
        Err(e) => { crate::log_fatal!("probe: spawn_user 失败 {:?}", e); return false; }
    };
    apic::timer_start().ok();
    // 窗口内只让任务跑 + 读内核自己的计数器；**读用户页必须在窗口之外**（SMAP，
    // 与 t_elf_load_run 同一条纪律：开着 AC 的那几行里不许有中断）。
    let mut served = 0u64;
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        while user::served() < PROBE_CALLS && tsc::now().wrapping_sub(t0) < 300_000_000 {
            tsc::spin(20_000);
        }
        served = user::served();
        // 写完最后一个槽之前还要打扩展形与两次被拒，给一段落地时间（8M 周期 ≈ 2.4 ms）
        tsc::spin(8_000_000);
        if !sched::wait_for_boot_task(300_000_000) {
            crate::log_fatal!("probe: 窗口收不了场（启动上下文没回到 CPU）");
        }
    });
    apic::timer_stop().ok();
    let slot = |off: u64| user::read_at(loaded.data_va + off).unwrap_or(u64::MAX);
    let magic = slot(0);
    let abi = slot(PROBE_OFF_ABI);
    let h = slot(PROBE_OFF_HANDLE);
    let n = slot(PROBE_OFF_WRITTEN);
    let mva = slot(PROBE_OFF_MAP_VA);
    let readback = slot(PROBE_OFF_READBACK);
    let done = slot(PROBE_OFF_DONE);
    let magic_ok = magic == PROBE_MAGIC;
    let abi_ok = abi & crate::user::F_VMO != 0;
    // 句柄形状由宿主机/内核各自拆：slot < 16、gen != 0（负数是错误码， unpack 会拒）
    let handle_ok = crate::handle::Handle(h).unpack().is_some();
    let write_ok = n == 8;
    let va_ok = (mva as i64) > 0
        && mva >= mm::USER_MMAP_BASE && mva < mm::USER_VA_TOP
        && (mva & (mm::PAGE as u64 - 1)) == 0;
    // 第二台仪器：生效位（整条链相与之后的结果），不是加载器/映射入口"打算给什么"
    let eff = mm::effective_flags(mva);
    let eff_ok = eff.is_some_and(|f| f.user && f.writable && !f.executable);
    // 内核侧再独立读一遍映射内容：与探针自己读回的那一格互为两台仪器
    let mut back = [0u8; 8];
    let kernel_read = user::copy_from_user(mva, &mut back) == Ok(8) && back == PROBE_PATTERN;
    // ---- 14 号扩展形（ADR-075 决策 6）三格
    let x_req = slot(PROBE_OFF_X_REQ);
    let x_ret = slot(PROBE_OFF_X_RET);
    let x_read = slot(PROBE_OFF_X_READ);
    let wx_ret = slot(PROBE_OFF_WX_RET);
    let un_ret = slot(PROBE_OFF_UN_RET);
    // 这一格**不许空转**：`x_ret == x_req` 本身就要求"有一次按请求值拿到了地址"
    // （一次都没成功时探针留下的是一对不相等的值），再加生效位与读回三件。
    let xform_ok = x_ret == x_req
        && x_req >= mm::USER_MMAP_BASE && x_req < mm::USER_VA_TOP
        && mm::effective_flags(x_req).is_some_and(|f| f.user && f.executable && !f.writable)
        && x_read == 1;
    let wx_ok = wx_ret == user::E_INVALID;
    let un_ok = un_ret == user::E_INVALID;
    let run_ok = magic_ok && abi_ok && handle_ok && write_ok && va_ok && readback == 1
        && done == 1 && xform_ok && wx_ok && un_ok;
    // 收场：终止任务 → 回收（reap 里 revoke_task 关句柄、句柄两段式还 VMO、资源袋还映射）
    let rel0 = sched::reap_released();
    let _ = sched::terminate_task(t);
    let drained = sched::reap_released() > rel0 || crate::ktests::common::drain_reap();
    let f1 = mm::free_frames();
    let va1 = mm::reservation_count();
    let base_ok = drained && f1 == f0 && va1 == va0
        && crate::handle::live() == lv0 && crate::vmo::vmo_count() == v0;
    crate::log_info!(
        "probe(P5c-2): 魔数={} ABI位={} 句柄={} 写={} VA={} 自读回={} 生效位={:?} 内核读回={} 扩展形=(请求{:#x} 返回{:#x} 判据{} 读回{}) W+X拒={} 非对齐拒={} 收场=(drained{} free{}->{} va{}->{} live{}->{} vmo{}->{}) served={}",
        magic_ok, abi_ok, handle_ok, write_ok, va_ok, readback == 1, eff, kernel_read,
        x_req, x_ret, xform_ok, x_read, wx_ok, un_ok,
        drained, f0, f1, va0, va1, lv0, crate::handle::live(), v0, crate::vmo::vmo_count(), served);
    let ok = run_ok && eff_ok && kernel_read && base_ok;
    if !ok {
        crate::log_fatal!(
            "probe: 判据不成立 跑={} 生效位={} 内核读回={} 收场={} 原始=[magic={:#x} abi={:#x} h={:#x} n={} va={:#x} rb={} done={}]",
            run_ok, eff_ok, kernel_read, base_ok, magic, abi, h, n, mva, readback, done);
    }
    ok
}
#[cfg(feature = "handles")]
crate::ktest!(KT_PROBE_RING3, t_probe_ring3);
