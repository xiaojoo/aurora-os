//! 崩溃记录与现场栈用例（T0.1 纯搬移）。

use crate::{ahci, crash, serial, state_store};
use crate::ktest;

/// M6-d/M6-f：§9.7 的崩溃记录走 V2（变长载荷 + 有界栈走 + 最近日志）。判据十五格，逐条只挡一类错法：
/// 1 全字段往返：向量/错误码/CPU/RIP/RSP/RBP/CR2/帧数 写下去按同一种类读回来
/// 2 `rbp` 用不了（这里是 0）⇒ 帧数停在 1，而且不许 panic：走不下去就停，不是编一条链
/// 3 合成一条三层帧链 ⇒ 帧数 = 4、第一帧就是出事那条指令、后面三帧是我给的返回地址
/// 4 第二条记录 `seq` 比第一条大 2（**一条崩溃落盘 = 摘要 + 日志尾两条记录**）且换槽；
///    `read_crash` 取的是**该种类**最新那条
/// 5 配对：日志尾的 `crash_seq` 必须指回它配的那条摘要，自己的 `seq` 比它大 1
/// 6 区里只有崩溃记录时启动记录必须"读不到"；反过来 V1 的启动记录在新解码器下**照读**
///    （§10.2 只增不改在这一格的字面含义：认 version 1 也认 version 2）
/// 7 翻掉**最后一帧**的一个字节（不重算校验和）⇒ 该槽作废、退回上一条完整记录：
///    这一格证明校验和真的覆盖到尾部，而不是只管头部那几十字节
/// 8 声明帧数与长度不自洽（**校验和是对的**）⇒ 必须拒，并且同样退回上一条：
///    只看头部就选最新的话，一条自相矛盾的记录会把整个种类锁死
/// 9 `size` 指到区外（> 480）⇒ 必须在界检查上被拒，不许拿它去切片
/// 10 设备拒执行这条命令（注入非法命令码 ⇒ 以 `ERR` 干净完成）⇒ `dump` 只许返回 `Err`，
///    停机路径上不许二次故障。不选"端口死了"那格注入：它只拦 `start_port`，而这里端口
///    早就起好了、命令照样跑，那样注入会变成假通过
/// 11 第 10 格之后驱动还能用（撤掉注入之后读得回记录）
/// 12 环形取尾：刚打的三行按顺序在段尾、段末必须是换行、行数要等于换行符的真实个数；
///    再给一个比"最新一行"还短的小缓冲 ⇒ 一行都不许给（不许从半行中间开始）
/// 13 声明行数与换行符数不符（**校验和是对的**）⇒ 必须拒，且拒因要点名"行数与换行符数不符"
/// 14 文本超过一槽上界 ⇒ 编码侧截断出来的那半行必须被"末行不完整"拒，不许安静存下缺尾的一行
/// 15 收尾把盘放回用例开始时的样子（三种记录都放回去）：假记录不许留在盘上冒充真崩溃
fn t_crash() -> bool {
    use state_store as ss;
    if ahci::init().is_err() {
        crate::log_fatal!("crash: AHCI 没认领上，落盘判据没法做");
        return false;
    }
    let port = match ahci::boot_port() {
        Ok(p) => p,
        Err(e) => {
            crate::log_fatal!("crash: 找不到引导盘 {:?}", e);
            return false;
        }
    };
    let saved_boot = ss::read(ss::KIND_BOOT).ok();
    let saved_crash = ss::read_crash().ok();
    let saved_log = ss::read_log().ok();
    ss::wipe().ok();
    crash::reset_for_test();

    // ①② 现场给一个用不了的 rbp：帧链必须停在"只有出事那条指令"，不许猜、不许故障
    let s1 = crash::Site { vector: 13, error_code: 0x08, cr2: 0xdead_0000, rip: 0xffff_8000_1234_0000, rsp: 0xffff_8000_5678_0000, rbp: 0 };
    let d1 = crash::dump_site(s1, 1);
    let (slot1, seq1) = match d1 {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("crash: 第一条记录没写进去 {:?}", e);
            return false;
        }
    };
    let r1 = ss::read_crash();
    let fields_back = matches!(r1, Ok((s, q, ref rec)) if s == slot1 && q == seq1
        && rec.vector == 13 && rec.error_code == 0x08 && rec.cpu == 1
        && rec.rip == 0xffff_8000_1234_0000 && rec.rsp == 0xffff_8000_5678_0000
        && rec.cr2 == 0xdead_0000 && rec.fault_level == 4);
    let single_frame = matches!(r1, Ok((_, _, ref rec)) if rec.frame_count == 1 && rec.frames[0] == 0xffff_8000_1234_0000);
    crash::report_previous();

    // ③ 合成三层帧链（帧指针在低地址一侧，"返回地址"指到**真的代码**里）
    //   这一格原来是把返回地址指到本函数的一个局部变量上的，旧的"8 字节对齐"门禁照收 ——
    //   换成"可执行"之后它当场变红：数据不能冒充返回地址。改指 `t_crash` 自己的代码地址。
    let entry: fn() -> bool = t_crash;
    let code_va = entry as *const () as u64;
    let mut chain = [[0u64; 2]; 3];
    let chain_base = &chain as *const [u64; 2] as u64;
    for i in 0..3 {
        chain[i][1] = code_va;
        chain[i][0] = if i + 1 < 3 { chain_base + 16 * (i as u64 + 1) } else { 0 };
    }
    let s2 = crash::Site { vector: 14, error_code: 0, cr2: 0x1000, rip: 0xffff_8000_2222_0000, rsp: 0xffff_8000_4444_0000, rbp: chain_base };
    let d2 = crash::dump_site(s2, 2);
    let (slot2, seq2) = match d2 {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("crash: 第二条记录没写进去 {:?}", e);
            return false;
        }
    };
    let r2 = ss::read_crash();
    let walked = matches!(r2, Ok((_, _, ref rec)) if rec.frame_count == 4
        && rec.frames[0] == 0xffff_8000_2222_0000
        && rec.frames[1] == code_va && rec.frames[2] == code_va && rec.frames[3] == code_va);
    // ④ 轮转与"取该种类最新"。`seq` 一步不是 +1 而是 +2：**一条崩溃落盘是两条记录**
    //   （摘要 + 日志尾），而日志尾共用同一块区、同一个游标（M6-b① 立的规矩）。
    //   所以这一格同时钉两件事：日志尾确实占了 seq，以及两个种类的"谁最新"仍然有定义。
    let stepped = seq2 == seq1 + 2 && slot2 != slot1;
    // ⑤ 配对：日志尾必须指回它配的那条崩溃摘要（`crash_seq`），并且自己的 seq 比它大 1
    let tail_pair = matches!(ss::read_log(), Ok((_, lseq, lrec))
        if lseq == seq2 + 1 && lrec.crash_seq == seq2 && lrec.lines > 0 && lrec.bytes > 0);
    let newest_wins = matches!(r2, Ok((s, q, ref rec)) if s == slot2 && q == seq2 && rec.vector == 14);
    // ⑥ 只有崩溃记录时启动记录读不到；而 V1 的启动记录写下去在新解码器里照读
    let boot_absent = matches!(ss::read(ss::KIND_BOOT), Err(ss::StoreError::NoValidSlot));
    let st_v1 = ss::BootState { failed_boots: 7, good_slot: 1, bad_slot: 2, last_vector: 13, last_cpu: 1, last_rip: 9 };
    let w_v1 = ss::write(ss::KIND_BOOT, &st_v1);
    let v1_still_readable = matches!(&w_v1, Ok((s, q)) if ss::read(ss::KIND_BOOT).map(|(s2, q2, st)| s2 == *s && q2 == *q && st == st_v1).unwrap_or(false));

    // ⑦ 尾帧撕裂（不重算校验和）⇒ 这一槽作废，退回上一条完整记录（⑥ 写的那条 V1 启动记录不算）
    let rec2 = match &r2 { Ok((_, _, rec)) => *rec, Err(_) => ss::CrashRecord::default() };
    let mut torn = ss::encode_crash(seq2, &rec2);
    let last = ss::HDR_OFF + ss::CRASH_FIXED_OFF + 8 * (rec2.frame_count as usize - 1);
    torn[last] ^= 0xFF;
    let wrote_torn = ahci::write_bytes(port, ss::slot_lba(slot2), &torn).is_ok();
    let fell_back = matches!(ss::read_crash(), Ok((s, q, ref rec)) if s == slot1 && q == seq1 && rec.vector == 13);

    // ⑧ 声明帧数与长度不自洽，但**校验和是对的** ⇒ 仍然必须拒，并且退回上一条
    let mut bogus = ss::encode_crash(seq2 + 1, &rec2);
    bogus[ss::HDR_OFF + 28] = 32;
    ss::reseal(&mut bogus);
    let wrote_bogus = ahci::write_bytes(port, ss::slot_lba(slot2), &bogus).is_ok();
    let bogus_rejected = matches!(ss::read_crash(), Ok((s, _, _)) if s == slot1);

    // ⑨ `size` 指到区外 ⇒ 界检查先挡住（不许拿它去切片）
    let mut huge = ss::encode_crash(seq2 + 2, &rec2);
    huge[0..4].copy_from_slice(&4000u32.to_le_bytes());
    ss::reseal(&mut huge);
    let wrote_huge = ahci::write_bytes(port, ss::slot_lba(slot2), &huge).is_ok();
    let huge_rejected = matches!(ss::read_crash(), Ok((s, _, _)) if s == slot1);

    // ⑩⑪ 停机路径上的失败形状：只降级、不二次故障；撤掉注入后驱动照常
    ahci::set_op_override(0xFF);
    let degraded = crash::dump(15, 0, 0);
    ahci::set_op_override(0);
    let degrade_ok = degraded.is_err();
    let alive_after = ss::read_crash().is_ok();

    // ⑫ 环形取尾的整行规则（§9.7 的"最近日志"）：刚打的三行要按顺序出现在段尾，段末字节必须是
    //   换行；再给一个比"最新一行"还短的小缓冲 ⇒ 必须**一行都不给**，而不是从半行中间开始。
    //   "小缓冲 = 0 行"是机制结论而不是实测巧合：本用例自己打的每一行都超过 24 字节。
    crate::log_info!("m6f 尾行 A 0123456789abcdef0123456789abcdef");
    crate::log_info!("m6f 尾行 B 0123456789abcdef0123456789abcdef");
    crate::log_info!("m6f 尾行 C 0123456789abcdef0123456789abcdef");
    let mut big = [0u8; ss::LOG_TEXT_MAX];
    let t_big = serial::recent_tail(&mut big);
    let big_text = &big[..t_big.bytes as usize];
    let marks = ["m6f 尾行 A", "m6f 尾行 B", "m6f 尾行 C"]
        .iter()
        .try_fold(0usize, |pos, m| {
            core::str::from_utf8(big_text).ok().and_then(|s| s[pos..].find(*m).map(|p| pos + p))
        });
    let tail_whole = !big_text.is_empty()
        && big_text[big_text.len() - 1] == b'\n'
        && marks.is_some()
        && t_big.lines as usize == big_text.iter().filter(|b| **b == b'\n').count();
    let mut small = [0u8; 24];
    let t_small = serial::recent_tail(&mut small);
    let no_room_no_line = t_small.lines == 0 && t_small.bytes == 0;
    // ⑬ 声明行数与换行符数不符（**校验和是对的**）⇒ 必须拒，而且拒因必须是那一格
    let mut wrong_lines = ss::encode_log(seq2 + 3, seq2, 9, b"x\ny\n");
    ss::reseal(&mut wrong_lines);
    let lines_rejected = matches!(
        ss::decode_log(0, &wrong_lines),
        Err(ss::StoreError::Torn { why: "行数与换行符数不符", .. })
    );
    // ⑭ 文本给得超过一槽装得下的上界 ⇒ 编码侧截断，而截断造出的半行必须在解码侧被"末行不完整"拒掉，
    //    不许安静存下"缺了尾巴的那一行"（那等于伪造一段没说过的话）
    let mut long = [b'a'; ss::LOG_TEXT_MAX + 6];
    long[long.len() - 1] = b'\n';
    let truncated = ss::encode_log(seq2 + 4, seq2, 1, &long);
    let tail_rejected = matches!(
        ss::decode_log(0, &truncated),
        Err(ss::StoreError::Torn { why: "末行不完整", .. })
    );

    // ⑮ 收尾：抹掉假记录，把启动时那三条原样放回（崩溃后放 ⇒ 它的 seq 更大，链保持原样）
    ss::wipe().ok();
    crash::reset_for_test();
    let mut restored = v1_still_readable && wrote_torn && wrote_bogus && wrote_huge;
    if let Some((_, _, st)) = saved_boot {
        restored &= ss::write(ss::KIND_BOOT, &st).is_ok();
    }
    if let Some((_, _, rec)) = saved_crash {
        restored &= ss::write_crash(&rec).is_ok();
    }
    if let Some((_, _, rec)) = saved_log {
        restored &= ss::write_log(rec.crash_seq, rec.lines, &rec.text[..rec.bytes as usize]).is_ok();
    }

    crate::log_info!(
        "crash: 判据 引导口={} 全字段往返={} 断链只一帧={} 走三层={} 轮转(seq{}→{} 槽{}→{})={} 配对={} 取最新={} 种类隔离={}/{} 尾帧撕裂退回={} 帧数不自洽退回={} 长度越界退回={} 只降级={} 之后还能读={} 尾行整段={} 装不下就不给={} 行数不符拒={} 截断拒={} 现场还原={}",
        port,
        fields_back,
        single_frame,
        walked,
        seq1,
        seq2,
        slot1,
        slot2,
        stepped,
        tail_pair,
        newest_wins,
        boot_absent,
        v1_still_readable,
        fell_back,
        bogus_rejected,
        huge_rejected,
        degrade_ok,
        alive_after,
        tail_whole,
        no_room_no_line,
        lines_rejected,
        tail_rejected,
        restored
    );
    let ok = fields_back && single_frame && walked && stepped && tail_pair && newest_wins && boot_absent
        && v1_still_readable && fell_back && bogus_rejected && huge_rejected && degrade_ok
        && alive_after && tail_whole && no_room_no_line && lines_rejected && tail_rejected
        && restored;
    if !ok {
        crate::log_fatal!("crash: 崩溃记录判据不成立（上面一行是全部读数）");
    }
    ok
}
ktest!(KT_CRASH, t_crash);

/// M6-d：§9.7 的现场必须由 **CPU 给的数** 填出来。这条只在 `fault-crash-oops` 构建里存在：
/// 核心态读一个未映射地址 ⇒ #PF(14) 没有恢复项 ⇒ `Action::Fatal` ⇒ 停机前落一条 V2 记录。
/// 判据形状不是"崩了就算过"（那 39 已经是判定级的事了），而是：**没故障就是失败**——
/// 读得回来就说明这条构建根本没走到异常里，那它的记录里那些字段全是编的。
#[cfg(feature = "fault-crash-oops")]
fn t_crash_oops() -> bool {
    const BAD: u64 = 0xffff_c000_0000_0008;   // 规范化内核地址、8 字节对齐、保证没映射
    crate::log_info!("oops: 故意读 {:#x}，期待 #PF(14) 升 L4（cr2 应该等于这个数）", BAD);
    // SAFETY: 这是**故意**的一次非法核心态访问，用来制造真异常现场；它之前的日志已经打完，
    //        之后再没有需要保全的状态。判据是"这一行不许返回"，读回来的值只用于打印。
    let v = unsafe { (BAD as *const u64).read_volatile() };
    crate::log_fatal!("oops: 没有发生故障，读到 {:#x} ⇒ 这条构建没在量它声称的东西", v);
    false
}
#[cfg(feature = "fault-crash-oops")]
ktest!(KT_CRASH_OOPS, t_crash_oops);

