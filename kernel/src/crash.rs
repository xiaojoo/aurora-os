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

use crate::mm;
use crate::state_store::{self, CrashRecord, KIND_CRASH, MAX_FRAMES};
use core::sync::atomic::{AtomicBool, Ordering};

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
#[derive(Clone, Copy, Debug, Default)]
pub struct Site {
    pub vector: u32,
    pub error_code: u32,
    pub cr2: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
}

/// 落一条崩溃摘要。返回写到的槽与 `seq`，判据要用它们。
/// `cpu` 收 `usize`（槽位的原生形状）而落盘是 u32：槽位数远小于 2^32，收窄放在这一处。
pub fn dump_site(site: Site, cpu: usize) -> Result<(u8, u64), state_store::StoreError> {
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

/// 有界地走 `rbp` 链。第 0 帧是出事那条指令自己（`rip`），所以链断了也至少有一帧。
/// 断链的条件按"能用就行、不能用就停"来写，不去猜编译器的帧布局：帧指针那一侧要
/// 对齐 + 内核半区 + 已映射三关全过才读；读回来的返回地址换一关判（`is_code`）。
fn walk_frames(rbp: u64, rip: u64, rec: &mut CrashRecord) {
    rec.frames[0] = rip;
    let mut n = 1usize;
    let mut fp = rbp;
    while n < MAX_FRAMES {
        if fp & 7 != 0 || fp < KERNEL_HALF {
            break;
        }
        if !mm::is_mapped(fp) {
            break;
        }
        // SAFETY: 上面两关已经确认这个地址在已映射的内核半区且 8 字节对齐；
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
        if next & 7 != 0 || next < KERNEL_HALF || next <= fp || !mm::is_mapped(next) {
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
        dump(NO_VECTOR, crate::arch::x86_64::cpu::self_slot(), 0).ok();
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
