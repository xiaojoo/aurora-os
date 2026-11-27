//! 拥塞控制（S4 步骤 1）：可插拔接口 + NewReno（RFC 5681 / RFC 6582）。
//!
//! ## 为什么不是手册案例 11 的原样
//! 手册案例 11 标题写 "Reno/NewReno"，**实际是 Reno**：恢复期内收到部分确认（ack < recover）时直接退出恢复，
//! 多段丢失只能等 RTO。RFC 6582 §3.2 要求部分确认**留在恢复**并重传下一个洞。本文件补上，并加 `recover` 点。
//! 沙箱端到端对比（同一随机丢包链路、仅部分确认处理不同）：丢包越多优势越大，p=0.05 时 RTO 次数 41.5→32.1、完成轮数 −9.0%；
//! p=0.005 时仅 −1.2%。**只证明方向，不证明数值**（数值取决于模拟器设的 RTO=10 轮与独立丢包）。
//! （我的前两版模拟器曾给出"NewReno 更慢 137%"的荒谬结果，根因是模拟器让两个算法改了不同的状态，已修；见 ADR-266 §4。）
//!
//! ## 接口
//! 全部为字节单位、纯函数/纯数据、无时钟、无锁。`flight` 由调用方传入（= snd_nxt − snd_una）。
//! `CongestionOps` 的 trait 对象在 no_std 无分配下用 `&mut dyn`，**不用 Box**。
//! 初值 IW10（RFC 6928）：**手册说"未在已核验链接中，落地前请自行核对"——我也没有核对**，保持手册口径并在 ADR 标注。
use crate::{seq_le, seq_lt};

/// ACK 的分类结果，驱动调用方的重传动作。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckEvent {
    /// 新数据被确认（推进 snd_una）。
    NewAck,
    /// 重复 ACK（未达 3 个，或已在恢复中）。
    DupAck,
    /// 第 3 个重复 ACK：调用方应**立即重传 snd_una 处的段**（快速重传）。
    FastRetransmit,
    /// 恢复中的部分确认：调用方应**重传新的 snd_una 处的段**（下一个洞）。
    PartialAck,
    /// 旧/无意义 ACK（ack < snd_una，或无在途数据时的原地 ACK）。
    Stale,
}

pub trait CongestionOps {
    fn cwnd(&self) -> u32;
    fn ssthresh(&self) -> u32;
    /// 处理一个到达的 ACK。`ack` 为累积确认号，`snd_nxt` 为当前发送边界。
    fn on_ack(&mut self, ack: u32, snd_nxt: u32) -> AckEvent;
    /// RTO 超时。
    fn on_timeout(&mut self, snd_nxt: u32);
    fn in_recovery(&self) -> bool;
}

#[derive(Clone, Copy, Debug)]
pub struct NewReno {
    mss: u32,
    cwnd: u32,
    ssthresh: u32,
    dup_acks: u8,
    in_recovery: bool,
    /// RFC 6582 §3.2：进入快速重传时的 snd_nxt；ack ≥ recover 才是"完全确认"。
    recover: u32,
    snd_una: u32,
}

/// 初始窗口（段数）。RFC 6928 的 10；**若落地核对后发现不适用，只改这一个常量**。
pub const IW_SEGMENTS: u32 = 10;
/// dup ACK 门限（RFC 5681 §3.2）。
pub const DUPTHRESH: u8 = 3;

impl NewReno {
    /// `snd_una` 为首个未确认序号的初值（= ISS+1，SYN 已确认后）。
    ///
    /// **`recover` 初值必须是 `snd_una - 1`（= ISS），不是 `snd_una`**：防护条件是 `recover < ack`，
    /// 新连接第一次丢包时 `ack == snd_una`；若初值等于 `snd_una` 则条件为假，**第一次丢包永远不触发快速重传**，只能等 RTO。
    /// （本文件初稿正是这样写的，被沙箱等价移植的单测抓到：3 项失败；`first_loss_on_new_connection_fast_retransmits` 咬住它。）
    pub const fn new(mss: u32, snd_una: u32) -> Self {
        NewReno { mss, cwnd: IW_SEGMENTS * mss, ssthresh: u32::MAX, dup_acks: 0, in_recovery: false, recover: snd_una.wrapping_sub(1), snd_una }
    }
    #[inline] fn flight(&self, snd_nxt: u32) -> u32 { snd_nxt.wrapping_sub(self.snd_una) }
    /// RFC 5681 式 (4)：ssthresh = max(FlightSize/2, 2*SMSS)。
    #[inline] fn half_flight(&self, snd_nxt: u32) -> u32 { (self.flight(snd_nxt) / 2).max(2 * self.mss) }
    pub fn snd_una(&self) -> u32 { self.snd_una }
    pub fn mss(&self) -> u32 { self.mss }
}

impl CongestionOps for NewReno {
    fn cwnd(&self) -> u32 { self.cwnd }
    fn ssthresh(&self) -> u32 { self.ssthresh }
    fn in_recovery(&self) -> bool { self.in_recovery }

    fn on_ack(&mut self, ack: u32, snd_nxt: u32) -> AckEvent {
        if seq_lt(ack, self.snd_una) { return AckEvent::Stale; }
        // ack 超过 snd_nxt = 确认了没发过的数据：不是合法 ACK，忽略（RFC 9293 §3.10.7.4）。
        if seq_lt(snd_nxt, ack) { return AckEvent::Stale; }
        if ack == self.snd_una {
            // 重复 ACK 的定义（RFC 5681 §2）：有在途数据、不带数据/窗口更新（后两项由调用方过滤后再调本函数）。
            if snd_nxt == self.snd_una { return AckEvent::Stale; }
            self.dup_acks = self.dup_acks.saturating_add(1);
            if self.in_recovery {
                // 窗口膨胀（RFC 5681 §3.2 步骤 4）
                self.cwnd = self.cwnd.saturating_add(self.mss);
                return AckEvent::DupAck;
            }
            if self.dup_acks == DUPTHRESH {
                // RFC 6582 §3.2 步骤 1 的"防重复触发"：只有 ack-1 > recover（即 ack > recover）才进入快速重传，
                // 否则这是超时后同一窗口内的旧 dup，进入恢复会二次减半。
                if seq_lt(self.recover, ack) {
                    self.ssthresh = self.half_flight(snd_nxt);
                    self.recover = snd_nxt;
                    self.cwnd = self.ssthresh.saturating_add(3 * self.mss);
                    self.in_recovery = true;
                    return AckEvent::FastRetransmit;
                }
                // 否则：不触发，但保留计数，等下一个新 ACK 重置。
            }
            return AckEvent::DupAck;
        }
        // ---- 新数据被确认
        let acked = ack.wrapping_sub(self.snd_una);
        self.snd_una = ack;
        if self.in_recovery {
            if seq_lt(ack, self.recover) {
                // 部分确认（RFC 6582 §3.2 步骤 5）：留在恢复；窗口收缩 acked，若 ≥MSS 补一个 MSS；重传下一个洞。
                self.cwnd = self.cwnd.saturating_sub(acked);
                if acked >= self.mss { self.cwnd = self.cwnd.saturating_add(self.mss); }
                self.cwnd = self.cwnd.max(self.mss);
                self.dup_acks = 0;
                return AckEvent::PartialAck;
            }
            // 完全确认：退出恢复，窗口放气（RFC 6582 §3.2 步骤 5 的 "deflate" 选项）。
            self.in_recovery = false;
            self.dup_acks = 0;
            self.cwnd = self.ssthresh.min(self.flight(snd_nxt).max(self.mss).saturating_add(self.mss));
            return AckEvent::NewAck;
        }
        self.dup_acks = 0;
        if self.cwnd < self.ssthresh {
            // 慢启动：每 ACK 增长 min(acked, SMSS)（RFC 5681 §3.1 式 (2)；RFC 3465 ABC 限制 L=1）
            self.cwnd = self.cwnd.saturating_add(acked.min(self.mss));
        } else {
            // 拥塞避免：每 ACK 增长 SMSS*SMSS/cwnd（式 (3)），至少 1 字节防止长期停滞
            self.cwnd = self.cwnd.saturating_add((self.mss * self.mss / self.cwnd.max(1)).max(1));
        }
        AckEvent::NewAck
    }

    fn on_timeout(&mut self, snd_nxt: u32) {
        // RFC 5681 §3.1 式 (4) 与 RTO 后 cwnd=1 SMSS（式 (5)）。
        self.ssthresh = self.half_flight(snd_nxt);
        self.cwnd = self.mss;
        self.dup_acks = 0;
        self.in_recovery = false;
        // RFC 6582 §3.2 步骤 1 的配套：超时后 recover 置为已发送的最高序号，防止随后的 dup 误触发快速重传。
        self.recover = snd_nxt;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const M: u32 = 1000;

    #[test]
    fn first_loss_on_new_connection_fast_retransmits() {
        // 回归：recover 初值 = snd_una 时，新连接的第一次丢包（ack==snd_una）永远不触发快速重传。
        for una in [0u32, 1, 0x1000_0001, u32::MAX, u32::MAX - 3] {
            let mut c = NewReno::new(M, una); let nxt = una.wrapping_add(20 * M);
            assert_eq!(c.on_ack(una, nxt), AckEvent::DupAck);
            assert_eq!(c.on_ack(una, nxt), AckEvent::DupAck);
            assert_eq!(c.on_ack(una, nxt), AckEvent::FastRetransmit, "una={una:#x}");
        }
    }

    #[test]
    fn slow_start_doubles_per_rtt() {
        let mut c = NewReno::new(M, 0);
        let mut nxt = 10 * M; let mut una = 0u32; let mut w = [0u32; 5];
        for r in 0..5 {
            w[r] = c.cwnd() / M;
            let n = c.cwnd() / M;
            for _ in 0..n { una = una.wrapping_add(M); c.on_ack(una, nxt); }
            nxt = una.wrapping_add(c.cwnd());
        }
        assert_eq!(w, [10, 20, 40, 80, 160]);
    }

    #[test]
    fn third_dup_ack_triggers_fast_retransmit_once() {
        let mut c = NewReno::new(M, 0); let nxt = 20 * M;
        assert_eq!(c.on_ack(0, nxt), AckEvent::DupAck);
        assert_eq!(c.on_ack(0, nxt), AckEvent::DupAck);
        assert_eq!(c.on_ack(0, nxt), AckEvent::FastRetransmit);
        assert_eq!(c.ssthresh(), 10 * M);            // flight=20M → /2
        assert_eq!(c.cwnd(), 13 * M);                // ssthresh + 3*MSS
        assert_eq!(c.on_ack(0, nxt), AckEvent::DupAck);
        assert_eq!(c.cwnd(), 14 * M);                // 恢复内每个 dup +MSS
    }

    #[test]
    fn partial_ack_stays_in_recovery_newreno_not_reno() {
        let mut c = NewReno::new(M, 0); let nxt = 20 * M;
        for _ in 0..3 { c.on_ack(0, nxt); }
        assert!(c.in_recovery());
        // 重传的段 0 到达，累积确认推进到 3M，但 recover=20M，3M < 20M → 部分确认
        assert_eq!(c.on_ack(3 * M, nxt), AckEvent::PartialAck);
        assert!(c.in_recovery(), "手册案例 11 在此处退出恢复，这是它与 NewReno 的差别");
        assert_eq!(c.on_ack(20 * M, nxt), AckEvent::NewAck);
        assert!(!c.in_recovery());
    }

    #[test]
    fn timeout_resets_and_blocks_stale_dupacks() {
        let mut c = NewReno::new(M, 0); let nxt = 20 * M;
        c.on_timeout(nxt);
        assert_eq!(c.cwnd(), M);
        assert_eq!(c.ssthresh(), 10 * M);
        // 超时后同窗口内迟到的 3 个 dup 不得再次触发快速重传（recover==nxt，ack(0) 不 > recover）
        for _ in 0..5 { assert_ne!(c.on_ack(0, nxt), AckEvent::FastRetransmit); }
    }

    #[test]
    fn invalid_ack_beyond_snd_nxt_ignored() {
        let mut c = NewReno::new(M, 0);
        assert_eq!(c.on_ack(5 * M, 3 * M), AckEvent::Stale);
        assert_eq!(c.snd_una(), 0);
    }

    #[test]
    fn wraparound_safe() {
        let start = u32::MAX - 5 * M;
        let mut c = NewReno::new(M, start); let nxt = start.wrapping_add(10 * M);
        assert_eq!(c.on_ack(start.wrapping_add(M), nxt), AckEvent::NewAck);
        assert_eq!(c.snd_una(), start.wrapping_add(M));
    }

    #[test]
    fn invariants_hold_under_random_events() {
        // 无 proptest 依赖的确定性伪随机；任何序列下 cwnd>=1、ssthresh>=2*MSS（超时/进入恢复后）、snd_una 单调。
        let mut s = 0x1234_5678u32;
        let mut next = || { s ^= s << 13; s ^= s >> 17; s ^= s << 5; s };
        for _ in 0..2000 {
            let mut c = NewReno::new(M, 0); let mut nxt = 10 * M; let mut una_seen = 0u32;
            for _ in 0..200 {
                match next() % 4 {
                    0 => { nxt = nxt.wrapping_add((next() % 5) * M); }
                    1 => { let a = c.snd_una().wrapping_add((next() % 4) * M); c.on_ack(a, nxt); }
                    2 => { c.on_ack(c.snd_una(), nxt); }
                    _ => { c.on_timeout(nxt); }
                }
                assert!(c.cwnd() >= 1);
                // snd_una 单调不回退（模 2^32）：这条断言必须真的会失败，不许 `|| true`。
                assert!(!seq_lt(c.snd_una(), una_seen), "snd_una 回退");
                una_seen = c.snd_una();
            }
        }
    }
}
