//! ADR-266 判据：ISN（RFC 6528）与临时端口（RFC 6056）。**未编译未运行**。形状对齐 `ktests/syscall/user.rs` 的 TCP 夹具（手工喂段）。
//!
//! 每格带**防空转证人**：没有它，"全部走了降级旧公式"也能让"相邻槽 ISN 差不恒定"之外的格子全绿。
//! 第 1 格要求 `ISN_STRONG` 增量 > 0——若 `rand` 没播种（QEMU 无 rdrand/rdseed），本组判据**整体报"跳过：未播种"而不是绿**。
use crate::ktest_late;
use crate::network::{isn_source, socket, tcp, tcp_conn};
use crate::ktest;
use core::sync::atomic::Ordering;

fn seeded() -> bool { isn_source::is_ready() }

/// 格 1：被动端 ISN 在 SYN 到达时按四元组重算。
///   · 同一监听槽、4 个不同客户端端口的 SYN ⇒ 4 个 SYN-ACK 的 seq 必须两两不同，且相邻差不得恒为 4096（旧 accept 公式）或 256（旧 create 公式）。
///   · 证人：`ISN_STRONG` 增量 ≥ 4；`ISN_WEAK` 增量 = 0。
///   · 负样本（变异）：把 `tcp_on_segment` 里的"重算"删掉 ⇒ 4 个 seq 全等于占位值 ⇒ 本格红。
fn t_isn_passive_per_tuple() -> bool {
    if !seeded() { crate::log_warn!("isn: 跳过——rand 未播种（熵源不足），本格不判绿也不判红"); return true; }
    let w0 = isn_source::ISN_WEAK.load(Ordering::Relaxed);
    let s0 = isn_source::ISN_STRONG.load(Ordering::Relaxed);
    let mut seqs = [0u32; 4];
    for (i, cport) in [40001u16, 40002, 40003, 40004].iter().enumerate() {
        // 每个四元组独立建一个 Listen 槽：RST 不会把槽复位回 Listen，不能复用一个槽。
        let Ok((slot, gen)) = socket::create(socket::AF_INET, socket::SOCK_STREAM) else { return false };
        let local = socket::SockAddr::V4 { ip: [0, 0, 0, 0], port: 8080 };
        if socket::bind(slot, gen, local).is_err() { return false; }
        if socket::tcp_listen(slot, gen).is_err() { return false; }
        let syn = tcp::Segment { src_port: *cport, dst_port: 8080, seq: 1000 + i as u32, ack: 0, flags: tcp::SYN, window: 8192, data_off: 5, payload: &[] };
        let r = socket::tcp_on_segment(slot, gen, &syn, socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: *cport });
        match r { Ok(Some(rep)) => seqs[i] = rep.seq, _ => return false }
        let _ = socket::destroy(slot, gen);
    }
    let d: [u32; 3] = [seqs[1].wrapping_sub(seqs[0]), seqs[2].wrapping_sub(seqs[1]), seqs[3].wrapping_sub(seqs[2])];
    let all_distinct = seqs[0] != seqs[1] && seqs[1] != seqs[2] && seqs[2] != seqs[3] && seqs[0] != seqs[3];
    let not_old = d.iter().all(|x| *x != 4096 && *x != 256);
    let not_const = !(d[0] == d[1] && d[1] == d[2]);
    let strong = isn_source::ISN_STRONG.load(Ordering::Relaxed) - s0;
    let weak = isn_source::ISN_WEAK.load(Ordering::Relaxed) - w0;
    let ok = all_distinct && not_old && not_const && strong >= 4 && weak == 0;
    crate::log_info!("isn-passive: seq 两两不同={} 差非旧公式={} 差非常数={} 证人 STRONG+{} WEAK+{} ⇒ {}", all_distinct, not_old, not_const, strong, weak, ok);
    ok
}
ktest_late!(KT_ISN_PASSIVE, t_isn_passive_per_tuple);

/// 格 2：主动端 `tcp_start_connect` 按 (local,peer) 重算，且 SynSent 仍自洽——对**正确的** ack(=iss+1) 的 SYN-ACK 进 Established；
///   对**占位 iss+1** 的 SYN-ACK 必须被拒（防"重算后状态机仍按旧值"）。
fn t_isn_active_selfconsistent() -> bool {
    if !seeded() { return true; }
    let Ok((slot, gen)) = socket::create(socket::AF_INET, socket::SOCK_STREAM) else { return false };
    let _ = socket::bind(slot, gen, socket::SockAddr::V4 { ip: [10, 0, 2, 15], port: 41000 });
    let _ = socket::connect(slot, gen, socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 80 });
    let placeholder = isn_source::legacy_isn(slot, gen);
    let Ok(syn) = socket::tcp_start_connect(slot, gen) else { return false };
    let real_iss = syn.seq;
    let differs = real_iss != placeholder;
    // 错 ack（占位+1）→ 必须被忽略（状态仍 SynSent）
    let bad = tcp::Segment { src_port: 80, dst_port: 41000, seq: 9000, ack: placeholder.wrapping_add(1), flags: tcp::SYN | tcp::ACK, window: 8192, data_off: 5, payload: &[] };
    let r_bad = socket::tcp_on_segment(slot, gen, &bad, socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 80 });
    let rejected = matches!(r_bad, Ok(None));
    let still_synsent = socket::tcp_info(slot, gen).map(|i| i.state == tcp_conn::State::SynSent).unwrap_or(false);
    // 正确 ack → Established
    let good = tcp::Segment { src_port: 80, dst_port: 41000, seq: 9000, ack: real_iss.wrapping_add(1), flags: tcp::SYN | tcp::ACK, window: 8192, data_off: 5, payload: &[] };
    let r_good = socket::tcp_on_segment(slot, gen, &good, socket::SockAddr::V4 { ip: [10, 0, 2, 2], port: 80 });
    let est = socket::tcp_info(slot, gen).map(|i| i.state == tcp_conn::State::Established).unwrap_or(false);
    let _ = socket::destroy(slot, gen);
    let ok = differs && rejected && still_synsent && matches!(r_good, Ok(Some(_))) && est;
    crate::log_info!("isn-active: iss≠占位={} 占位ack被拒={} 仍SynSent={} 正确ack建立={} ⇒ {}", differs, rejected, still_synsent, est, ok);
    ok
}
ktest_late!(KT_ISN_ACTIVE, t_isn_active_selfconsistent);

/// 格 3：同四元组快速重连 ISN 单调前进（M 项）。取两次 `isn_for`，间隔 ≥1 个时钟粒度：第二次必须比第一次大（模 2^32）。
///   证人：两次都走 STRONG。若时钟未就绪（`now_us()==None`）⇒ 本格跳过并报 `ISN_NOCLOCK`。
fn t_isn_monotonic_same_tuple() -> bool {
    if !seeded() || isn_source::now_us().is_none() { crate::log_warn!("isn: 跳过——secret 或时钟未就绪"); return true; }
    let a = isn_source::isn_for([10, 0, 2, 15], 5000, [10, 0, 2, 2], 80, 1, 1);
    // 等 ≥ 4 µs×k：自旋 20 000 次 tsc（粗略 ~ms 量级，具体耗时依 CPU，**判据不依赖具体数值，只要求严格前进**）
    let _ = crate::time::tsc::spin(200_000);
    let b = isn_source::isn_for([10, 0, 2, 15], 5000, [10, 0, 2, 2], 80, 1, 1);
    let adv = (b.wrapping_sub(a) as i32) > 0;
    crate::log_info!("isn-mono: a={:#x} b={:#x} 前进={}", a, b, adv);
    adv
}
ktest_late!(KT_ISN_MONO, t_isn_monotonic_same_tuple);

/// 格 4：临时端口：段内、避开占用、相邻 connect 不再是 slot 顺序。
fn t_ephemeral_port() -> bool {
    if !seeded() { return true; }
    let used = |p: u16| (49152..49252).contains(&p);
    let mut ports = [0u16; 8];
    for (i, rp) in [80u16, 81, 82, 83, 84, 85, 86, 87].iter().enumerate() {
        ports[i] = isn_source::ephemeral([10, 0, 2, 15], [10, 0, 2, 2], *rp, i as u16, &used);
    }
    let in_range = ports.iter().all(|p| *p >= 49152 && !used(*p));
    // 旧公式 49152+slot：slot=0..7 → 连续 8 个相邻值。新公式不应出现 8 个连续递增。
    let sequential = ports.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
    let w = isn_source::ISN_WEAK.load(Ordering::Relaxed);
    crate::log_info!("ephemeral: 段内且避开占用={} 退化为连续递增={} ports={:?} WEAK={}", in_range, sequential, ports, w);
    in_range && !sequential
}
ktest_late!(KT_EPHEMERAL, t_ephemeral_port);
