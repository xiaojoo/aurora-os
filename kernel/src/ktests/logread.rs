//! ADR-135：30 号 `SYS_LOG_READ` 的判据——用户态读内核日志环。
//!
//! 只测**约定面**（不测 Logger 的格式化与串口硬件）：
//! 1. 环里有什么就读到什么：返回的行数/字节数与 `recent_tail` 自己的判定一致；
//! 2. **只给整行**：拿回来的字节里，第一条从行首开始、最后一条以换行结束
//!    （半行日志会伪装成"没打完的记录"，这条规则是 `recent_tail` 的，30 号不许改它）；
//! 3. 返回形状 `(lines<<32)|bytes` 自洽，且 `bytes` 与用户缓冲里实际内容吻合；
//! 4. 负样本：`len == 0` ⇒ `-1`、`len > COPY_MAX` ⇒ `-3`、目标页不可写 ⇒ `-2`。
//!
//! **为什么不清环**：`ring_reset_for_test()` 会把启动以来的日志抹掉，而
//! `日志尾与串口逐行对账`（判定表里的既有行）依赖那一段。本用例只读、不看数量。

use crate::arch::x86_64::trap::TrapFrame;
use crate::ktest;
use crate::user::{self, syscall_dispatch};
use crate::{mm, sched, serial};

fn frame0() -> TrapFrame {
    TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    }
}

/// 从用户 VA 读一段（`copy_from_user` 走用户窗口）。
fn get_user(va: u64, dst: &mut [u8]) -> bool {
    matches!(user::copy_from_user(va, dst), Ok(n) if n == dst.len())
}

fn t_log_read() -> bool {
    use crate::user::{E_FAULT, E_TOO_LONG};
    crate::log_info!("logread: 起（30 号的判据）");
    // 与 procinfo/prockill 同一条纪律：`.ktests` 次序由链接器决定，先探后建。
    if sched::current_identity().is_none() {
        sched::init_boot_task();
    }

    // 用户缓冲：真占一段用户 VA 并建叶子（只分配不映射 ⇒ copy_to_user 回 -2）。
    let Some(va) = mm::alloc_user_va_range(1) else {
        crate::log_fatal!("logread: 拿不到用户 VA");
        return false;
    };
    let Ok(frames) = mm::phys_alloc(0, mm::MOD_TEST) else {
        crate::log_fatal!("logread: 用户页帧分配失败");
        mm::release_va(va.0);
        return false;
    };
    let Ok(flags) = mm::PageFlags::new(true, false, true) else {
        crate::log_fatal!("logread: 页标志构造失败");
        mm::release_va(va.0);
        return false;
    };
    let Ok(page) = mm::map(va, frames, flags) else {
        crate::log_fatal!("logread: 用户页映射失败");
        mm::release_va(va.0);
        return false;
    };

    // ---- ① 正向：读一段（长度取整页的一小段，环里必然有启动以来的日志）。
    const WANT: usize = 1024;
    let mut f = frame0();
    f.rax = user::SYS_LOG_READ;
    f.rdi = va.0;
    f.rsi = WANT as u64;
    syscall_dispatch(&mut f);
    let r = f.rax;
    let lines = (r >> 32) as u32;
    let bytes = (r & 0xffff_ffff) as usize;
    // 启动以来环里一定有过不止一行日志 ⇒ 这条构建下 lines/bytes 必须非零。
    let nonempty_ok = r > 0 && lines >= 1 && bytes >= 1 && bytes <= WANT;

    // ---- ② 只给整行：拿回来的内容必须以换行结尾（结尾半行被 `recent_tail` 丢掉），
    //     且不含"开头是半行"的痕迹（首字节之前的那个字节若在环里是换行才算行首，
    //     这一条由内核保证，用户侧只能验末尾）。
    let mut buf = [0u8; WANT];
    let got = bytes > 0 && get_user(va.0, &mut buf[..bytes.min(WANT)]);
    let tail_nl = got && buf[bytes - 1] == b'\n';
    // 行数必须等于内容里换行的个数（同一份规则的两种算法交叉验证）。
    let nl_count = if got {
        buf[..bytes].iter().filter(|b| **b == b'\n').count() as u32
    } else {
        0
    };
    let lines_match = got && nl_count == lines;

    // ---- ③ **第二台仪器**：直接从环的原始字节算"最后一行是否完整"。
    //     **不用 `recent_tail` 对账 30 号**——那是同一台仪器量两遍，变异咬不动
    //     （本轮实测：把 `recent_tail` 的整行规则改坏时，两边同时坏、反而自洽为绿）。
    //     这里取环的最后若干字节（用 `ring_byte_for_test` 按绝对序号读），
    //     独立地找最后一个换行，要求它之后**没有残余字节**（即环尾恰好收在行尾）。
    //     注意：环里此刻正在写的那一行可能还没换行（内核日志是异步的），
    //     所以这一格只在"环尾是换行"或"30 号给的尾巴确实以换行结束"两种情形下成立，
    //     判据取**后者**：30 号返回的那一段，其最后一个字节必须是换行（已由 ② 验），
    //     并且它必须是环里**真实存在**的连续字节（逐字节与环比）。
    let total = serial::ring_total();
    let mut ring_bytes_ok = bytes > 0;
    if bytes > 0 {
        // 30 号拷回来的是"环里最近 bytes 字节的整行段"，它在环里的绝对起点 =
        // 环尾往前 bytes 字节（这一段一定是环的严格后缀）。
        let base = total.saturating_sub(bytes as u64);
        let mut i = 0usize;
        while i < bytes {
            match (serial::ring_byte_for_test(base + i as u64), buf.get(i)) {
                (Some(rb), Some(&ub)) if rb == ub => {}
                _ => {
                    ring_bytes_ok = false;
                    break;
                }
            }
            i += 1;
        }
    }
    // 环里最后写进去的那一格必是换行或正在写的半行；若 30 号返回的段不空，
    // 就要求它的末字节是换行（② 已验），且它是环的真后缀（上面逐字节比过）。
    let same_as_kernel = ring_bytes_ok;

    // ---- ④ 负样本：len == 0 ⇒ -1
    let mut f2 = frame0();
    f2.rax = user::SYS_LOG_READ;
    f2.rdi = va.0;
    f2.rsi = 0;
    syscall_dispatch(&mut f2);
    let zero_len_ok = f2.rax == user::E_INVALID;

    // ---- ⑤ 负样本：len > COPY_MAX ⇒ -3（容量边界，不是"悄悄截短"）
    let mut f3 = frame0();
    f3.rax = user::SYS_LOG_READ;
    f3.rdi = va.0;
    f3.rsi = (user::COPY_MAX + 1) as u64;
    syscall_dispatch(&mut f3);
    let too_long_ok = f3.rax == E_TOO_LONG;

    // ---- ⑥ 负样本：目标页**只读**（不能写）⇒ -2。
    //     **为什么不用"没映射的 VA"**：`alloc_user_va_range` 会复用刚释放的 VA，
    //     而页表叶子可能还在 ⇒ 那一格实测拿到 rc=0（本轮 run-1919），前提不成立。
    //     造一个**明确只读**的映射（`PageFlags::USER_R`），`copy_to_user` 的
    //     `validate_range(.., writable=true)` 必然拒。
    let unwritable_ok = match (mm::alloc_user_va_range(1), mm::phys_alloc(0, mm::MOD_TEST)) {
        (Some(va2), Ok(f2)) => {
            match mm::map(va2, f2, mm::PageFlags::USER_R) {
                Ok(ro_page) => {
                    let mut f4 = frame0();
                    f4.rax = user::SYS_LOG_READ;
                    f4.rdi = va2.0;
                    f4.rsi = 64;
                    syscall_dispatch(&mut f4);
                    let ok = f4.rax == E_FAULT;
                    drop(ro_page);
                    mm::release_va(va2.0);
                    ok
                }
                Err(_) => {
                    mm::release_va(va2.0);
                    false
                }
            }
        }
        (Some(va2), Err(_)) => {
            mm::release_va(va2.0);
            false
        }
        (None, _) => false,
    };

    // ---- ③' **半行必须被丢掉**（这一格是本用例真正的负样本，也是唯一能咬住
    //     `recent_tail` 整行规则的变异点）：先往环尾写一段**不含换行**的字节，
    //     让环尾恰好停在半行上；再读一次，要求拿回来的段**不以那半行结尾**。
    //     **为什么需要它**：正常时序下内核日志写完就换行，环尾本来就是 `\n`，
    //     "丢掉结尾半行"那条规则根本不被触发——所以不加这一格时，把
    //     `recent_tail` 的整行规则改坏也照样绿（本轮实测）。
    serial::write_bytes(b"logread-half-line-no-newline");
    let mut f2b = frame0();
    f2b.rax = user::SYS_LOG_READ;
    f2b.rdi = va.0;
    f2b.rsi = WANT as u64;
    syscall_dispatch(&mut f2b);
    let r2 = f2b.rax;
    let b2 = (r2 & 0xffff_ffff) as usize;
    let mut buf2 = [0u8; WANT];
    let got2 = b2 > 0 && get_user(va.0, &mut buf2[..b2.min(WANT)]);
    // 拿到的那一段必须仍以换行结尾（半行被丢掉），且**不含**刚写进去的那串半行。
    let half_dropped = got2
        && buf2[b2 - 1] == b'\n'
        && !buf2[..b2].windows(28).any(|w| w == b"logread-half-line-no-newline");

    drop(page);

    let ok = nonempty_ok && tail_nl && lines_match && same_as_kernel && half_dropped
        && zero_len_ok && too_long_ok && unwritable_ok;
    crate::log_info!(
        "logread: 判据={} 有内容={} 整行={} 行数自洽={} 与环同字节={} 半行丢掉={} 零长拒={} 超长拒={} 不可写拒={}",
        ok, nonempty_ok, tail_nl, lines_match, same_as_kernel, half_dropped,
        zero_len_ok, too_long_ok, unwritable_ok
    );
    ok
}

ktest!(KT_LOG_READ, t_log_read);
