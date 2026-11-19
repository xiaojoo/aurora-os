//! 崩溃记录与现场栈用例（T0.1 纯搬移）。

use crate::{ahci, crash, serial, state_store};
use crate::ktest;

/// M6-d/M6-f：§9.7 的崩溃记录走 V2（变长载荷 + 有界栈走 + 最近日志）。判据十六格，逐条只挡一类错法：
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

    // ⑯ 无锁现场表里**不许留着本用例的合成 site**。`dump_site` 既是崩溃的收口也是本用例的入口，
    //   它要把手上的 `Site` 当现场写进表，下一次挂宿主机就读到一个"从没发生过的 #PF(14)"——
    //   本用例给过 13/14/15 三个向量与两个夹具 rip（`s1`/`s2`/⑩ 的 `dump(15,0,0)`）。
    //   扫描放在**这里**（自己那几笔调用之后）而不是别的用例里：`.ktests` 的顺序由链接器决定，
    //   隔着用例查等于赌顺序。配对的负样本（实测）：把 `crash.rs` 里那句
    //   `mark_fatal(STAGE_DUMPSITE_ENTER, 0, None)` 改回 `Some(site)` ⇒ 这一格当场红。
    let site_absent = |vector: u64, rip: u64, cr2: u64| {
        !(0..crate::arch::x86_64::cpu::MAX_CPUS).any(|c| {
            let row = crash::fatal_snapshot(c);
            row[crash::FR_VECTOR] == vector && row[crash::FR_RIP] == rip && row[crash::FR_CR2] == cr2
        })
    };
    let site_not_recorded = site_absent(13, 0xffff_8000_1234_0000, 0xdead_0000)
        && site_absent(14, 0xffff_8000_2222_0000, 0x1000)
        && site_absent(15, 0, 0);

    crate::log_info!(
        "crash: 判据 引导口={} 全字段往返={} 断链只一帧={} 走三层={} 轮转(seq{}→{} 槽{}→{})={} 配对={} 取最新={} 种类隔离={}/{} 尾帧撕裂退回={} 帧数不自洽退回={} 长度越界退回={} 只降级={} 之后还能读={} 尾行整段={} 装不下就不给={} 行数不符拒={} 截断拒={} 现场还原={} 现场表无夹具site={}",
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
        restored,
        site_not_recorded
    );
    let ok = fields_back && single_frame && walked && stepped && tail_pair && newest_wins && boot_absent
        && v1_still_readable && fell_back && bogus_rejected && huge_rejected && degrade_ok
        && alive_after && tail_whole && no_room_no_line && lines_rejected && tail_rejected
        && restored && site_not_recorded;
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

/// 无锁现场记录表（§181，猎间歇挂那一刀的取证量具）自己的判据十一格。
/// 这张表存在的唯一理由是"下一次挂死时它是唯一的证人"，所以它必须**先被证会咬**：
/// 只跑一整遍绿的默认构建抓不到它的错——那种跑法里它一次都没被读过。
/// 1 布局：八个 `FR_*` 下标互不相同、都在界内、数量等于 `FATAL_FIELDS`（重排/漏一格 ⇒ 宿主机解出的是别人的字段）
/// 2 逐格往返：五个**各不相同**的 magic 按 `FR_*` 写、按 `FR_*` 读，一一对上
/// 3 `seq` 每写一次恰好 +1（"看着像涨了"不算）
/// 4 `site=None` 的进度点**不动现场那五格**：后面几步不许把最早那份现场抹成 0
/// 5 物理地址推导：`record_phys` 保留页内偏移，且 HHDM 别名可译（宿主机 `pmemsave` 用的就是这个数）
/// 6 分槽不串：动邻居那一槽，本槽一个字段都不变（`other == mine` 时直接红 ⇒ CPU 数退化也是判据）
/// 6b/6c **步长自洽**：用例按宿主机那个式子（`cpu * FATAL_FIELDS + FR_*`）写，`fatal_snapshot`
///    按内核自己的 `slot_base` 读——两个式子必须落在同一格，写进去看得见、还原后也一样。
///    第一版的这一格是**空转的**：只断言"本槽没被邻居的写打扰"，而 `slot_base` 步长改错一格
///    时它照样绿（实测：注入 `FATAL_FIELDS - 1` 之后整跑 PASS/33）。补上双向对照才咬得住。
/// 7 每一槽的 `stage` 都必须是已知值（值域守卫：挡住"现场地址被当成 stage"那类脏值；
///    步长错**不是**它量的，见 6b）
/// 8 现场还原：本槽放回进来之前的样子。这一格不是礼貌——用例自己填的 vector=0x2a 若留在表里，
///    下一次真挂死会读出"一个从没发生过的异常"，那是量具自己伪造的现场。
fn t_fatal_record() -> bool {
    use crate::arch::x86_64::cpu;
    use core::sync::atomic::Ordering;
    // 五个各不相同的 magic：任何一格与另一格写串了都会被读出来（相同值抓不到换位）
    const M_RIP: u64 = 0x1111_2222_3333_4444;
    const M_RSP: u64 = 0x5555_6666_7777_8888;
    const M_CR2: u64 = 0x9999_aaaa_bbbb_cccc;
    const M_VEC: u64 = 0x2a;
    const M_ERR: u64 = 0xbe;

    let idx = [
        crash::FR_SEQ, crash::FR_STAGE, crash::FR_VECTOR, crash::FR_ERR, crash::FR_RIP,
        crash::FR_RSP, crash::FR_CR2, crash::FR_AUX,
    ];
    let (mut distinct, mut in_range) = (true, true);
    for a in 0..idx.len() {
        if idx[a] >= crash::FATAL_FIELDS {
            in_range = false;
        }
        for b in a + 1..idx.len() {
            if idx[a] == idx[b] {
                distinct = false;
            }
        }
    }
    let layout_ok = distinct && in_range && idx.len() == crash::FATAL_FIELDS;

    let mine = cpu::self_slot();
    let before = crash::fatal_snapshot(mine);
    let site = crash::Site {
        vector: M_VEC as u32,
        error_code: M_ERR as u32,
        cr2: M_CR2,
        rip: M_RIP,
        rsp: M_RSP,
        rbp: 0,
    };
    crash::mark_fatal(crash::STAGE_FATAL_ENTER, 0, Some(site));
    let after = crash::fatal_snapshot(mine);
    let fields_back = after[crash::FR_VECTOR] == M_VEC
        && after[crash::FR_ERR] == M_ERR
        && after[crash::FR_RIP] == M_RIP
        && after[crash::FR_RSP] == M_RSP
        && after[crash::FR_CR2] == M_CR2;
    let stage_written = after[crash::FR_STAGE] == crash::STAGE_FATAL_ENTER;
    let seq_stepped = after[crash::FR_SEQ] == before[crash::FR_SEQ] + 1;

    // ④ 只推进度点，不许抹现场
    crash::mark_fatal(crash::STAGE_DUMPSITE_EXIT, 7, None);
    let step2 = crash::fatal_snapshot(mine);
    let progress_keeps_site = step2[crash::FR_RIP] == M_RIP
        && step2[crash::FR_CR2] == M_CR2
        && step2[crash::FR_AUX] == 7
        && step2[crash::FR_STAGE] == crash::STAGE_DUMPSITE_EXIT
        && step2[crash::FR_SEQ] == after[crash::FR_SEQ] + 1;

    // ⑤ 宿主机按这个数去读内存，所以它的错法是"少了页内偏移"与"根本译不出来"
    let va = core::ptr::addr_of!(crash::FATAL_RECORD) as *const u8 as u64;
    let phys_ok = crash::record_phys().is_some_and(|p| {
        p & 0xfff == va & 0xfff && crate::mm::is_mapped(crate::mm::hhdm() + p)
    });

    // ⑥ 分槽：直接写邻居那一槽（`mark_fatal` 只会写自己那槽，这里要的是"两槽互不影响"）
    //    下标按**宿主机的方式**算（`cpu * FATAL_FIELDS + FR_*`），读却走内核自己的
    //    `slot_base`（经 `fatal_snapshot`）。两个式子必须落在同一格，这一格才不是空转：
    //    实测把 `slot_base` 的步长改成 `FATAL_FIELDS - 1`，下面两行立刻对不上（⑥ 与 ⑥b 同红）。
    let other = (mine + 1) % cpu::MAX_CPUS;
    let neighbor = other * crash::FATAL_FIELDS + crash::FR_AUX;
    let other_old = crash::FATAL_RECORD[neighbor].load(Ordering::Acquire);
    crash::FATAL_RECORD[neighbor].store(0xfeed, Ordering::Relaxed);
    let mine_now = crash::fatal_snapshot(mine);
    let other_now = crash::fatal_snapshot(other);
    let slots_isolated = other != mine
        && mine_now[crash::FR_AUX] == 7
        && mine_now[crash::FR_RIP] == M_RIP
        && mine_now[crash::FR_SEQ] == step2[crash::FR_SEQ];
    let stride_agrees = other_now[crash::FR_AUX] == 0xfeed;
    crash::FATAL_RECORD[neighbor].store(other_old, Ordering::Relaxed);
    let stride_restored = crash::fatal_snapshot(other)[crash::FR_AUX] == other_old;

    // ⑦ 值域守卫：每一槽的 stage 必须是五个已知值之一。这一格挡的是"脏值"（比如现场地址
    //    串到了 stage 那一格），**不挡步长**——步长由 ⑥b/⑥c 的双向对照挡（那里有实测记录）。
    let stages_known = (0..cpu::MAX_CPUS).all(|c| {
        matches!(
            crash::fatal_snapshot(c)[crash::FR_STAGE],
            crash::STAGE_NONE
                | crash::STAGE_FATAL_ENTER
                | crash::STAGE_DUMPSITE_ENTER
                | crash::STAGE_DUMPSITE_EXIT
                | crash::STAGE_EXIT_FINISH
        )
    });

    // ⑧ 本槽还原（与 `fatal_snapshot` 配成一对，"怎么写回"只有一处算术；再读一遍确认）
    crash::fatal_restore(mine, &before);
    let restored = crash::fatal_snapshot(mine) == before;

    crate::log_info!(
        "fatalrec: 判据 布局={} 五格往返={} stage={} seq涨1={} 进度不抹现场={} 物理={:#x}可译={} 分槽不串={} 步长自洽={} 还原后邻居一致={} 各槽stage已知={} 现场还原={}（本槽 cpu={}，邻居 cpu={}）",
        layout_ok,
        fields_back,
        stage_written,
        seq_stepped,
        progress_keeps_site,
        crash::record_phys().unwrap_or(0),
        phys_ok,
        slots_isolated,
        stride_agrees,
        stride_restored,
        stages_known,
        restored,
        mine,
        other
    );
    let ok = layout_ok
        && fields_back
        && stage_written
        && seq_stepped
        && progress_keeps_site
        && phys_ok
        && slots_isolated
        && stride_agrees
        && stride_restored
        && stages_known
        && restored;
    if !ok {
        crate::log_fatal!("fatalrec: 无锁现场记录表的判据不成立（上面一行是全部读数）");
    }
    ok
}
ktest!(KT_FATAL_RECORD, t_fatal_record);

/// 这张表的**端到端取证自查**：只在 `fatal-record-stall` 构建里存在。
/// 形状是"写一个每格都不同的现场，然后 `cli+hlt` 停住"——宿主机在那一跑超时之后用
/// `pmemsave` 把整张表读回来，与下面这行串口上的数对账。只有**物理地址推导、字段顺序、
/// 表本身**三件全对，宿主机才解得出这五个 magic；错任何一件它对不上，而它对不上就是红。
/// 这一行自己期望 **HANG**：正常收尾等于这条构建根本没停住，那它什么都没测
/// （与 `t_crash_oops` 的"没故障就是失败"同一形状）。
#[cfg(feature = "fatal-record-stall")]
fn t_fatal_record_stall() -> bool {
    const M_RIP: u64 = 0xfa01_fa02_fa03_fa04;
    const M_RSP: u64 = 0xfb01_fb02_fb03_fb04;
    const M_CR2: u64 = 0xfc01_fc02_fc03_fc04;
    crate::log_info!(
        "fatalrec: 自查 故意停住 期待宿主机读回 向量=53 错误码=122 rip={:#x} rsp={:#x} cr2={:#x} stage=1",
        M_RIP,
        M_RSP,
        M_CR2
    );
    crash::mark_fatal(
        crash::STAGE_FATAL_ENTER,
        0,
        Some(crash::Site {
            vector: 53,
            error_code: 122,
            cr2: M_CR2,
            rip: M_RIP,
            rsp: M_RSP,
            rbp: 0,
        }),
    );
    crate::arch::x86_64::trap::halt_forever()
}
#[cfg(feature = "fatal-record-stall")]
ktest!(KT_FATAL_RECORD_STALL, t_fatal_record_stall);

