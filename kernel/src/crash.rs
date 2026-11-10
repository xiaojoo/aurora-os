//! §9.7 的落点：崩溃现场在停机前**尽力落盘**，下次启动读回来报出去。
//!
//! 手册要的是两段式（先进跨重启保留的内存，存储就绪后再持久化）。第一段今天做不了：
//! 预留内存是否真的跨重启保留，QEMU 上量不出来（§9.7 自己就写了这句），所以这里落的是
//! "落盘 + 下次启动读回"这一半，内存那一半排在 M7 的硬件矩阵里。载体是 ADR-031 的状态区，
//! `kind = KIND_CRASH`、`version = 2`（变长载荷：固定 64 字节 + 每帧 8 字节）。
//!
//! 三条硬约束：
//! 1. 这条路径跑在 L4 出口上，**只能降级、不能再故障**：全程 `Result`，写不进去就只留
//!    串口那一行，并把"没写进去"这件事本身打出来。
//! 2. 调用栈是**有界**走的，且两种地址各按各自的形状判，断在任何一关就停在那里、已经走到的照存：
//!    **帧指针**要 8 字节对齐 + 内核半区 + 已映射（`push rbp` 保证对齐）；**返回地址**要
//!    内核半区 + **生效权限说它可执行**（指令是变长的，对齐判据会把真的链判死，见 `is_code`）。
//!    这一段的意义不是"总能走满 32 层"，而是"走歪了也不会变成第二次故障"（判据在
//!    `KT_CRASH` 里：给一条 `rbp` 就不可用的现场，帧数必须停在 1 而且不落 panic）。
//! 3. 填不出的字段一律留 0 并写明为什么：`process_id`（进程模型还没长出来）、
//!    `module_id`（异常现场不知道是哪个模块，只有驱动路径能给）、最近日志（要环形日志缓冲）。

use crate::arch::x86_64::cpu::{self_slot, MAX_CPUS};
use crate::mm;
use crate::state_store::{self, CrashRecord, KIND_CRASH, MAX_FRAMES};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// `vector = 0` 的约定：**没有异常现场**（`panic` 或内部一致性检查升 L4）。
/// 真异常那条路会给到真的向量号，所以"0"和"14"分得开，不必再引一个可选类型。
pub const NO_VECTOR: u8 = 0;
/// 内核半区的下界（HHDM 之后的高地址）。栈走只在这里头走。
const KERNEL_HALF: u64 = 0xffff_8000_0000_0000;
/// §9.2 的级别：能落到这条路径上的都是 L4
const LEVEL_L4: u32 = 4;

/// 本次启动是否已经落过崩溃摘要。出口在 `exit::finish` 那一颗**唯一的收口**上：
/// L4 的调用点会随模块增加（`mm::free_violation`、`heap` 的两处、以后更多），逐点手工挂
/// `dump` 早晚漏一处，而漏掉那处的表现是"盘上安静地没有记录"——那种故障不会有别的尺子报出来。
static DUMPED: AtomicBool = AtomicBool::new(false);

/// 异常现场里能直接拿到的那几格（由 `trap::TrapFrame` 填，字段名一一对得上）
/// 转换写在 `main.rs::exit_fatal_from_exception` **一处**：那里已经有 `frame` 的全部字段，
/// 而把 `Site::of(frame)` 放进本文件要多引一次 `arch/x86_64/trap`——ADR-044 的棘轮按站点数计，
/// 一个纯搬运的构造函数不值得让 diagnostics->arch 变胖（现场那五格的读法由用例与宿主机对账盯）。
#[derive(Clone, Copy, Debug, Default)]
pub struct Site {
    pub vector: u32,
    pub error_code: u32,
    pub cr2: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
}

// ---- 无锁现场记录表（§181，猎间歇挂的取证刀）------------------------------------
//
// 为什么已有 `dump_site` 还要另开一张表：抓到的那次挂死，CPU#0 的 RIP 就落在
// `dump_site` 里面，而串口上既没有 `[fatal]` 也没有 `crash:` 那一行、更没有收尾与退出行。
// 那条路径上的两个可疑卡点——串口行锁与块设备写——恰好都在"把现场说出来"之前，
// 所以现场必须落在**碰它们之前**、且只由原子写构成的地方。否则量具自己是嫌疑人。
//
// 表在 `.bss`，全 `AtomicU64`：不取锁、不分配、零 `unsafe`（AGENTS 硬约束 6）。
// 宿主机按启动那一行 `fatalrec: 物理=…` 给出的物理地址 `pmemsave` 读回整张表，
// 因此**字段顺序是接口**：`tools/aurora.py` 的 `FATAL_FIELD_NAMES` 必须与下面这八个
// `FR_*` 下标逐字对得上，由 `check-fat32-ports` 门禁核（改成重排 ⇒ 门禁红，不靠人记）。
pub const FATAL_FIELDS: usize = 8;
pub const FR_SEQ: usize = 0;
pub const FR_STAGE: usize = 1;
pub const FR_VECTOR: usize = 2;
pub const FR_ERR: usize = 3;
pub const FR_RIP: usize = 4;
pub const FR_RSP: usize = 5;
pub const FR_CR2: usize = 6;
pub const FR_AUX: usize = 7;

/// 进度点。同一颗 CPU 上按**程序顺序**往前走（写入本身不设单调闸：致命路径不许多出
/// 一条"可能被拒"的分支，那正是第二次故障的来源）。宿主机读到哪一格，就说明走到了
/// 那一格的**下一步**之前。
/// `0` = 这一跑从没进过致命/崩溃出口（大多数正常跑的常态，不是异常）。
pub const STAGE_NONE: u64 = 0;
/// 判定为致命、还没打任何日志之前（`exit_fatal_from_exception` 的第一件事）
pub const STAGE_FATAL_ENTER: u64 = 1;
/// 进了 `dump_site`，在走栈、取日志环、写盘之前
pub const STAGE_DUMPSITE_ENTER: u64 = 2;
/// `write_crash` 返回之后（`aux`：0 = 没写进去，否则 = 成功槽号 + 1）
pub const STAGE_DUMPSITE_EXIT: u64 = 3;
/// `exit::finish` 里写 `qemu-exit` 之前（`aux` = 那个 `Code` 的原值）。
/// 看到这一格却串口上没有退出行 ⇒ 卡在出口的串口写，不在崩溃落盘。
pub const STAGE_EXIT_FINISH: u64 = 4;

/// 每 CPU 八个字段的一张表。下标 = `cpu * FATAL_FIELDS + FR_*`。
/// `MAX_CPUS`/`self_slot` 从**一行 use** 来（文件顶部）而不是四处全限定名：ADR-044 的棘轮按
/// 站点数算，`crate::arch::x86_64::cpu::` 一行就占三个站点（arch、x86_64、cpu 各一次），
/// 写四遍会把 diagnostics->arch 撑胖，而那条环内边"只许减不许增"。
pub static FATAL_RECORD: [AtomicU64; MAX_CPUS * FATAL_FIELDS] =
    [const { AtomicU64::new(0) }; MAX_CPUS * FATAL_FIELDS];

/// 本 CPU 那一槽的基址。越界取模折回表内：致命路径不该再添一条"槽号不对怎么办"的分支，
/// 那条分支本身就是第二次故障的来源，而槽号越界只可能是 `self_slot` 已经坏了。
fn slot_base(cpu: usize) -> usize {
    (cpu % MAX_CPUS) * FATAL_FIELDS
}

/// 记一次现场。`site` 为 `None` 时只推进 `stage`/`aux`，**不动向量那五格**——
/// 那五格因此留着本次致命最早的那份现场，后面几步再路过也不会把它擦成 0。
pub fn mark_fatal(stage: u64, aux: u64, site: Option<Site>) {
    let b = slot_base(self_slot());
    FATAL_RECORD[b + FR_SEQ].fetch_add(1, Ordering::Relaxed);
    if let Some(s) = site {
        FATAL_RECORD[b + FR_VECTOR].store(u64::from(s.vector), Ordering::Relaxed);
        FATAL_RECORD[b + FR_ERR].store(u64::from(s.error_code), Ordering::Relaxed);
        FATAL_RECORD[b + FR_RIP].store(s.rip, Ordering::Relaxed);
        FATAL_RECORD[b + FR_RSP].store(s.rsp, Ordering::Relaxed);
        FATAL_RECORD[b + FR_CR2].store(s.cr2, Ordering::Relaxed);
    }
    FATAL_RECORD[b + FR_AUX].store(aux, Ordering::Relaxed);
    // stage 放最后、用 Release：宿主机读到新 stage 时，前面几格在那之前就已经可见。
    FATAL_RECORD[b + FR_STAGE].store(stage, Ordering::Release);
}

/// 读回某一槽。用例与宿主机对账走同一个入口，避免出现第二份布局。
pub fn fatal_snapshot(cpu: usize) -> [u64; FATAL_FIELDS] {
    let b = slot_base(cpu);
    let mut out = [0u64; FATAL_FIELDS];
    for i in 0..FATAL_FIELDS {
        out[i] = FATAL_RECORD[b + i].load(Ordering::Acquire);
    }
    out
}

/// 这张表在**物理内存**里的地址（宿主机 `pmemsave` 要用它）。
/// `phys_of` 给的是页基址，所以补上页内偏移；译不出来就返回 `None`，
/// 由调用方把"没有物理地址"这件事打出来——静默当 0 会比报红更贵。
pub fn record_phys() -> Option<u64> {
    let va = core::ptr::addr_of!(FATAL_RECORD) as *const u8 as u64;
    crate::mm::phys_of(va).map(|page| page + (va & 0xfff))
}

/// 落一条崩溃摘要。返回写到的槽与 `seq`，判据要用它们。
/// `cpu` 收 `usize`（槽位的原生形状）而落盘是 u32：槽位数远小于 2^32，收窄放在这一处。
pub fn dump_site(site: Site, cpu: usize) -> Result<(u8, u64), state_store::StoreError> {
    // 这一格带 `site`：`dump_site` 的入参就是现场本身，无论调用方是致命出口、
    // `panic`（向量为约定的 0）还是用例，表里都留下同一份可读回的数。
    mark_fatal(STAGE_DUMPSITE_ENTER, 0, Some(site));
    DUMPED.store(true, Ordering::Relaxed);
    let mut rec = CrashRecord {
        vector: site.vector,
        error_code: site.error_code,
        cpu: cpu as u32,
        fault_level: LEVEL_L4,
        thread_id: (crate::hooks::sched().current_id_snapshot)() as u32,
        rip: site.rip,
        rsp: site.rsp,
        rbp: site.rbp,
        cr2: site.cr2,
        ..CrashRecord::default()
    };
    walk_frames(site.rbp, site.rip, &mut rec);
    // 环里那段"临终前的话"要在这里取：崩溃路径自己后面还要打日志，取晚了会把"落盘"这件事
    // 本身也塞进最近日志里，而那一行的内容记录里已经有了。
    let mut text = [0u8; state_store::LOG_TEXT_MAX];
    let tail = crate::serial::recent_tail(&mut text);
    let out = state_store::write_crash(&rec);
    // 落盘回来第一件事记这一格（在打日志之前）：挂死那一次要分辨的正是"卡在写盘里"
    // 与"写完了却没能说话"。`aux` 用槽号 +1，0 留给"没写进去"。
    mark_fatal(
        STAGE_DUMPSITE_EXIT,
        match &out {
            Ok((slot, _)) => u64::from(*slot) + 1,
            Err(_) => 0,
        },
        None,
    );
    match &out {
        Ok((slot, seq)) => {
            crate::log_info!(
                "crash: 落盘 区LBA={} 槽={} 槽字节={} seq={} 向量={} 错误码={} cpu={} rip={:#x} rsp={:#x} rbp={:#x} cr2={:#x} 帧数={} 种类={} 版本=2",
                state_store::STATE_START_LBA,
                slot,
                state_store::SLOT_BYTES,
                seq,
                rec.vector,
                rec.error_code,
                rec.cpu,
                rec.rip,
                rec.rsp,
                rec.rbp,
                rec.cr2,
                rec.frame_count,
                KIND_CRASH
            );
            // 日志尾只在摘要写成功之后才写：那块盘已经不可信的时候，第二笔写只是第二次故障。
            // 顺序也定在这里：串口上"落盘"在前、"日志尾"在后，宿主机才分得清哪一段是崩溃前的话。
            if tail.lines == 0 {
                crate::log_warn!(
                    "crash: 环里取不出整行（累计 {} 字节），这条崩溃没有最近日志",
                    crate::serial::ring_total()
                );
            } else {
                match state_store::write_log(*seq, tail.lines, &text[..tail.bytes as usize]) {
                    Ok((lslot, lseq)) => crate::log_info!(
                        "crash: 日志尾 槽={} seq={} 配崩溃 seq={} 行数={} 文本字节={}（上限 {}）",
                        lslot, lseq, seq, tail.lines, tail.bytes, state_store::LOG_TEXT_MAX
                    ),
                    Err(e) => crate::log_warn!(
                        "crash: 日志尾没写进去 {:?}，这条崩溃只有摘要没有最近日志", e
                    ),
                }
            }
        }
        Err(e) => crate::log_warn!("crash: 摘要写不进盘 {:?}，这条崩溃只剩串口上那一行", e),
    }
    out
}

/// 没有异常现场的那条路（`panic`、`mm`/`heap` 的一致性检查）：向量按约定留 0。
pub fn dump(vector: u8, cpu: usize, rip: u64) -> Result<(u8, u64), state_store::StoreError> {
    dump_site(Site { vector: u32::from(vector), rip, ..Site::default() }, cpu)
}

/// 一关三判：**8 字节对齐 + 内核半区 + 已映射**。`fp` 与 `next` 判的是同一件事，
/// 原来两处各写一遍（两遍都带一次 `mm::is_mapped`）。合成一个函数不是省字：
/// ADR-044 的棘轮按站点数算 diagnostics->memory，这条边只许减不许增，
/// 而"同一个判据写两处"正是早晚会在其中一处漏掉第三关的形状。
fn frame_usable(va: u64) -> bool {
    va & 7 == 0 && va >= KERNEL_HALF && mm::is_mapped(va)
}

/// 有界地走 `rbp` 链。第 0 帧是出事那条指令自己（`rip`），所以链断了也至少有一帧。
/// 断链的条件按"能用就行、不能用就停"来写，不去猜编译器的帧布局：帧指针那一侧要
/// 对齐 + 内核半区 + 已映射三关全过才读（`frame_usable`）；读回来的返回地址换一关判（`is_code`）。
fn walk_frames(rbp: u64, rip: u64, rec: &mut CrashRecord) {
    rec.frames[0] = rip;
    let mut n = 1usize;
    let mut fp = rbp;
    while n < MAX_FRAMES {
        if !frame_usable(fp) {
            break;
        }
        // SAFETY: 上面那关已经确认这个地址在已映射的内核半区且 8 字节对齐；
        //        这是 L4 出口上的一次有界读，读到的值只进记录、不解引用、不控制流。
        let next = unsafe { (fp as *const u64).read_volatile() };
        // SAFETY: 同上，偏移在同一个已映射的帧内（rbp 指向帧头，+8 不会越出这一页的
        //        可能性由下面的 `next` 自检兜住：拿回来的"链"必须是内核半区的对齐地址）
        let ret = unsafe { ((fp + 8) as *const u64).read_volatile() };
        // 先记这一帧，再决定要不要往上走：这一层帧的返回地址是有效的，即使它的上一帧
        // 的链断了。反过来（先验 `next` 再记）会把最后那一帧丢掉 —— 第一版就是这么少的一个帧
        if !is_code(ret) {
            break;
        }
        rec.frames[n] = ret;
        n += 1;
        if !frame_usable(next) || next <= fp {
            break;
        }
        fp = next;
    }
    rec.frame_count = n as u32;
}

/// 返回地址的合法性：**内核半区 + 已映射 + 生效权限说它可执行**。
/// 这里刻意不要求 8 字节对齐：x86-64 指令是变长的，`call` 的下一条指令可以落在任何字节边界，
/// 真实现场的第一层返回地址实测就是 `0xffffffff80010517`（`& 7 == 7`）——按对齐判会把
/// 一条真的链当成断链（BACKLOG 56c 那条"帧数=1"的真因，不是帧指针没开）。
/// 换成"可执行"这一关不是放松：栈、堆、`.data` 全是 NX，拿数据冒充返回地址照样拒。
fn is_code(va: u64) -> bool {
    va >= KERNEL_HALF && mm::effective_flags(va).is_some_and(|f| f.executable)
}

/// L4 出口的收口：还没有任何现场落过的话，补一条"没有异常现场"的摘要。
/// 已有现场（真异常那条路给了向量号与真 RIP）就不覆盖 —— 一次崩溃只该有一条记录。
pub fn ensure_dumped() {
    if !DUMPED.swap(true, Ordering::Relaxed) {
        dump(NO_VECTOR, self_slot(), 0).ok();
    }
}

/// 只给用例用的后门：把"本次已经落过"这个旗子放回启动时的值（假记录不许吞掉后面真崩溃的那条）。
/// 真实启动路径上没人调它 —— 到得了这里就说明还没停机。
pub fn reset_for_test() {
    DUMPED.store(false, Ordering::Relaxed);
}

/// 下一次启动（存储起来之后）把上一条崩溃读回来。没有也是正常情况，两种都只打一行、都不判失败。
pub fn report_previous() {
    let crash_seq = match state_store::read_crash() {
        Ok((slot, seq, rec)) => {
            crate::log_info!(
                "crash: 上一条 槽={} seq={} 向量={} 错误码={} cpu={} rip={:#x} rsp={:#x} cr2={:#x} 帧数={} 第一帧={:#x}",
                slot,
                seq,
                rec.vector,
                rec.error_code,
                rec.cpu,
                rec.rip,
                rec.rsp,
                rec.cr2,
                rec.frame_count,
                rec.frames[0]
            );
            Some(seq)
        }
        Err(e) => {
            crate::log_info!("crash: 没有上一条记录（{:?}）", e);
            None
        }
    };
    // 最近日志：读回来逐行原样打一遍。这一格的价值在真机上（M7：没有串口抓取这台仪器），
    // 在本机它是宿主机对账的对照物——判定不在这里做，见矩阵第 27 行。
    match state_store::read_log() {
        Ok((slot, seq, rec)) => {
            let paired = crash_seq == Some(rec.crash_seq);
            crate::log_info!(
                "crash: 上一条日志 槽={} seq={} 配崩溃 seq={} 配对={} 行数={} 文本字节={}",
                slot, seq, rec.crash_seq, paired, rec.lines, rec.bytes
            );
            let text = &rec.text[..rec.bytes as usize];
            let mut n = 0u32;
            for line in text.split_inclusive(|b| *b == b'\n') {
                n += 1;
                // 日志原文是 ASCII；万一不是（上一遍写了二进制进去），这一行打"打不出"而不是吞掉
                match core::str::from_utf8(line) {
                    Ok(s) => crate::log_info!("  日志尾 #{}: {}", n, s.trim_end_matches('\n')),
                    Err(_) => crate::log_warn!("  日志尾 #{}: 不是 UTF-8，{} 字节", n, line.len()),
                }
            }
            crate::log_info!("crash: 上一条日志 打完行数={}（记录声称 {}）", n, rec.lines);
        }
        Err(e) => crate::log_info!("crash: 没有上一条日志尾（{:?}）", e),
    }
}
