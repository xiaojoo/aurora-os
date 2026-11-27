//! 宿主机测试。这些性质已先用 Python 等价移植跑过（RTO 例值=RFC 6298 §2 手算；retx 3000 轮×60 步随机含回绕；
//! reasm 6000 轮差分：无丢弃时与位图模型一致，有丢弃时重传可收敛）。Rust 版是同一逻辑的固化，**仍须你本机跑**。
use crate::{reasm::*, retx::*, rto::*, window::*, seq_lt};

// ------------------------------------------------------------ RTO
#[test]
fn rto_first_sample_matches_rfc6298() {
    let mut r = Rto::new(1_000_000, 0, 60_000_000, 10_000);
    r.on_sample(100_000);
    assert_eq!((r.srtt_us(), r.rttvar_us(), r.rto_us()), (Some(100_000), Some(50_000), 300_000));
}
#[test]
fn rto_second_sample_updates_rttvar_before_srtt() {
    let mut r = Rto::new(1_000_000, 0, 60_000_000, 10_000);
    r.on_sample(100_000);
    r.on_sample(140_000);
    // RTTVAR=(3*50000+40000)/4=47500；SRTT=(7*100000+140000)/8=105000；RTO=105000+4*47500
    assert_eq!((r.rttvar_us(), r.srtt_us(), r.rto_us()), (Some(47_500), Some(105_000), 295_000));
}
#[test]
fn rto_backoff_matches_adr203_supplement_ladder_and_caps() {
    // 1 s 基数、60 s 封顶：2,4,8,16,32,60（第 6 次封顶）。与 t_tcp_retx ⑤ 的 b1==2*b0、b2==4*b0、bmax==MAX 同形。
    let mut r = Rto::adr203();
    let mut v = [0u32; 6];
    for x in v.iter_mut() { r.on_timeout(); *x = r.rto_us(); }
    assert_eq!(v, [2_000_000, 4_000_000, 8_000_000, 16_000_000, 32_000_000, 60_000_000]);
}
#[test]
fn rto_legacy_200ms_ladder_still_reproducible() {
    let mut r = Rto::legacy_200ms();
    let mut v = [0u32; 6];
    for x in v.iter_mut() { r.on_timeout(); *x = r.rto_us(); }
    assert_eq!(v, [400_000, 800_000, 1_600_000, 3_200_000, 3_200_000, 3_200_000]);
}
#[test]
fn rto_respects_floor_1s() {
    let mut r = Rto::adr203();
    r.on_sample(1_000);                       // 极小 RTT 样本
    assert_eq!(r.rto_us(), 1_000_000);        // 下限 1 s 生效
}
/// 回归钉：3.2 s 封顶 + 1 s 基数会让第 2 次翻倍就撞顶，破坏 t_tcp_retx ⑤ 的 b2==4*b0。
/// 本测试把“选 60 s 而不是 3.2 s”的理由固化成可执行判据。
#[test]
fn rto_cap_must_allow_four_x_base() {
    let base = 1_000_000u32;
    let bad = Rto::new(base, base, 3_200_000, 10_000);
    let mut b = bad; b.on_timeout(); b.on_timeout();
    assert_ne!(b.rto_us(), 4 * base, "3.2 s 封顶下第二次翻倍应撞顶(这就是不能只改基数的原因)");
    let good = Rto::adr203();
    let mut g = good; g.on_timeout(); g.on_timeout();
    assert_eq!(g.rto_us(), 4 * base);
}
#[test]
fn rto_converges_on_constant_rtt() {
    let mut r = Rto::rfc6298();
    for _ in 0..200 { r.on_sample(50_000); }
    assert_eq!(r.srtt_us(), Some(50_000));
    assert!(r.rto_us() >= 50_000 + 10_000);
}

// ------------------------------------------------------------ retx
#[test]
fn retx_full_queue_is_refused_not_dropped() {
    let mut q = RetxQueue::<4>::new();
    for i in 0..4 { q.push(1000 + i * 100, 100, 0x10, 0).unwrap(); }
    assert_eq!(q.push(0, 1, 0, 0), Err(PushError::Full));
    assert_eq!(q.len(), 4);
}
#[test]
fn retx_cumulative_ack_and_partial_ack() {
    let mut q = RetxQueue::<4>::new();
    for i in 0..4u32 { q.push(1000 + i * 100, 100, 0x10, (i * 10) as u64).unwrap(); }
    let r = q.on_ack(1100, 1400, 50);
    assert_eq!((r.advanced, r.rtt_sample_us, r.acked_segs), (true, Some(50), 1));
    let r = q.on_ack(1250, 1400, 60);
    assert!(r.advanced);
    let s = q.oldest().unwrap();
    assert_eq!((s.seq, s.len, s.tries), (1250, 50, 1)); // 部分确认：裁前缀、标记不再产 RTT 样本
}
#[test]
fn retx_wraparound() {
    let mut q = RetxQueue::<4>::new();
    q.push(0xFFFF_FFF0, 0x20, 0, 0).unwrap();
    let r = q.on_ack(0x10, 0x10, 5);
    assert_eq!((r.advanced, r.rtt_sample_us, r.acked_segs), (true, Some(5), 1));
    let mut q = RetxQueue::<4>::new();
    q.push(0xFFFF_FFF0, 0x20, 0, 0).unwrap();
    let r = q.on_ack(0xFFFF_FFF8, 0x10, 5);
    assert!(r.advanced && r.rtt_sample_us.is_none());
    let s = q.oldest().unwrap();
    assert_eq!((s.seq, s.len), (0xFFFF_FFF8, 0x18));
}
#[test]
fn retx_gives_up_after_max_tries_and_karn_filters() {
    let mut q = RetxQueue::<2>::new();
    q.push(1, 10, 0, 0).unwrap();
    for _ in 0..MAX_TRIES { assert!(matches!(q.on_timeout(), Timeout::Resend(_))); }
    assert_eq!(q.on_timeout(), Timeout::GiveUp);
    let mut q = RetxQueue::<2>::new();
    q.push(1, 10, 0, 0).unwrap();
    let _ = q.on_timeout();
    let r = q.on_ack(11, 11, 99);
    assert_eq!((r.rtt_sample_us, r.acked_segs), (None, 1)); // Karn：重传过的段不产样本
}
#[test]
fn retx_rejects_ack_above_snd_nxt() {
    let mut q = RetxQueue::<2>::new();
    q.push(1000, 100, 0x10, 0).unwrap();
    let r = q.on_ack(2000, 1100, 50);
    assert!(!r.advanced && r.acked_segs == 0 && q.len() == 1);
    let r = q.on_ack(1100, 1100, 50);
    assert!(r.advanced && r.acked_segs == 1 && q.is_empty());
}
#[test]
fn retx_empty_timeout_is_nothing() {
    let mut q = RetxQueue::<2>::new();
    assert_eq!(q.on_timeout(), Timeout::Nothing);
}

// ------------------------------------------------------------ window
#[test]
fn window_limits_sending_to_peer_window() {
    let mut w = SendWindow::new(1000, 5000);
    assert_eq!(w.usable(u32::MAX), 5000);
    w.on_send(3000); assert_eq!(w.usable(u32::MAX), 2000);
    w.on_send(2000); assert_eq!(w.usable(u32::MAX), 0); // 对端窗口满：不得再发
    assert!(w.on_ack_segment(1, 4000, 2000));
    assert_eq!(w.usable(u32::MAX), 0);                   // inflight=2000, wnd=2000
    assert!(w.on_ack_segment(2, 6000, 8000));
    assert_eq!(w.usable(u32::MAX), 8000);
}
#[test]
fn window_rejects_bad_acks_and_stale_window_updates() {
    let mut w = SendWindow::new(1000, 5000);
    w.on_send(5000);
    assert!(w.on_ack_segment(2, 6000, 8000));
    assert!(!w.on_ack_segment(3, 6001, 1));   // 超过 snd_nxt
    assert!(!w.on_ack_segment(3, 5000, 1));   // 旧 ACK（< snd_una）
    assert!(w.on_ack_segment(1, 6000, 1));    // 旧 seq 的段：ACK 可接受，但不得回退窗口
    assert_eq!(w.snd_wnd, 8000);
}
#[test]
fn window_zero_needs_probe() {
    let w = SendWindow::new(1, 0);
    assert!(w.needs_probe());
}
#[test]
fn window_cwnd_also_limits() {
    let w = SendWindow::new(0, 10_000);
    assert_eq!(w.usable(3_000), 3_000);
}

// ------------------------------------------------------------ reasm
#[test]
fn reasm_basic_gap_fill() {
    let mut r = Reasm::<4>::new(1000);
    assert_eq!(r.insert(0, 10, 10), Insert::Buffered);
    assert_eq!(r.insert(0, 0, 5), Insert::Advanced(5));
    assert_eq!(r.insert(5, 3, 9), Insert::Advanced(20)); // 部分旧 + 衔接缓冲区间
    assert!(r.ranges().is_empty());
}
#[test]
fn reasm_duplicate_and_cap() {
    assert_eq!(Reasm::<2>::new(100).insert(50, 10, 10), Insert::Duplicate);
    assert_eq!(Reasm::<2>::new(100).insert(0, 500, 10), Insert::Dropped);
}
#[test]
fn reasm_is_bounded_and_keeps_nearest() {
    let mut r = Reasm::<2>::new(1000);
    for s in [100u32, 200, 300, 400, 500] { let _ = r.insert(0, s, 10); }
    assert_eq!(r.ranges().len(), 2);
    assert!(r.dropped > 0);
    assert_eq!(r.ranges()[0].start, 100); // 保留靠近 rcv_nxt 的区间（补洞收益最大）
}
#[test]
fn reasm_wraparound() {
    let mut r = Reasm::<4>::new(1000);
    let rcv = 0xFFFF_FFF0u32;
    assert_eq!(r.insert(rcv, rcv.wrapping_add(0x20), 8), Insert::Buffered);
    assert_eq!(r.insert(rcv, rcv, 0x20), Insert::Advanced(rcv.wrapping_add(0x28)));
}

mod props {
    use super::*;
    use proptest::prelude::*;
    proptest! {
        /// 随机包序列：不变量恒成立；无丢弃则必须收齐；有丢弃则“发送方按序重传一遍”后必须收齐。
        #[test]
        fn reasm_differential(base in any::<u32>(), total in 20u32..200, cuts in proptest::collection::vec(1u32..25, 1..40),
                              segs_pick in 0usize..3, seed in any::<u64>()) {
            // 按 cuts 切出包（总长不超 total）
            let mut pkts = std::vec::Vec::new(); let mut pos = 0u32;
            for c in cuts { if pos >= total { break; } let l = c.min(total - pos); pkts.push((pos, l)); pos += l; }
            let total = pos; if total == 0 { return Ok(()); }
            let all = pkts.clone();
            // 伪随机洗牌（xorshift），避免引入 rand 依赖
            let mut s = seed | 1;
            let mut next = || { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s };
            for i in (1..pkts.len()).rev() { let j = (next() % (i as u64 + 1)) as usize; pkts.swap(i, j); }
            let mut rcv = base;
            macro_rules! run { ($r:expr, $v:expr) => {{
                let mut prev_end: Option<u32> = None;
                for (p, l) in $v {
                    if let Insert::Advanced(n) = $r.insert(rcv, base.wrapping_add(p), l) { rcv = n; }
                    for g in $r.ranges() {
                        prop_assert!(seq_lt(g.start, g.end));
                        prop_assert!(seq_lt(rcv, g.start));
                        if let Some(pe) = prev_end { prop_assert!(seq_lt(pe, g.start)); }
                        prev_end = Some(g.end);
                    }
                    prev_end = None;
                    prop_assert!(!seq_lt(base.wrapping_add(total), rcv));
                }
            }}; }
            match segs_pick {
                0 => { let mut r = Reasm::<2>::new(400); run!(r, pkts.clone()); if r.dropped == 0 { prop_assert_eq!(rcv, base.wrapping_add(total)); } else { let mut a = all.clone(); a.sort(); run!(r, a); prop_assert_eq!(rcv, base.wrapping_add(total)); } }
                1 => { let mut r = Reasm::<8>::new(400); run!(r, pkts.clone()); if r.dropped == 0 { prop_assert_eq!(rcv, base.wrapping_add(total)); } else { let mut a = all.clone(); a.sort(); run!(r, a); prop_assert_eq!(rcv, base.wrapping_add(total)); } }
                _ => { let mut r = Reasm::<64>::new(400); run!(r, pkts.clone()); prop_assert_eq!(r.dropped, 0); prop_assert_eq!(rcv, base.wrapping_add(total)); }
            }
        }
        /// RTO 永远落在 [min,max]。
        #[test]
        fn rto_always_clamped(samples in proptest::collection::vec(1u32..5_000_000, 1..50)) {
            let mut r = Rto::adr203();
            for s in samples { r.on_sample(s); prop_assert!(r.rto_us() >= 1_000_000 && r.rto_us() <= 60_000_000); r.on_timeout(); prop_assert!(r.rto_us() <= 60_000_000); }
        }
    }
}
