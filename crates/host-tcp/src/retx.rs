//! 多段重传队列（取代“单格 `RetxState`”的能力缺口；ADR-203 未决 1）。
//!
//! 定长 `N` 段环；每段记 seq/len/flags/首次发送时刻/重传次数。
//! * `push`：发出数据段后登记；队列满返回 `Err(Full)`，调用方必须停发（不许丢记录）。
//! * `on_ack`：累积确认（回绕安全）。完全被确认的段出队；**部分确认**的段保留并裁掉已确认前缀
//!   （RFC 9293 §3.10.7.4：只确认部分数据时，段需按 ACK 截断）。
//! * Karn：`tries==0` 的段被确认才产出 RTT 样本；重传过的段不产样本。
//! * `on_timeout`：只重传**最老**的一段（RFC 6298 (5.4)）；`tries` 超限返回 `GiveUp`。
use crate::{seq_gt, seq_le, seq_lt};

pub const MAX_TRIES: u8 = 6; // 与 ADR-203 的 RETX_MAX_TRIES 同值，接入时须保持一致

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushError { Full }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seg { pub seq: u32, pub len: u32, pub flags: u8, pub sent_us: u64, pub tries: u8 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timeout {
    /// 没有未确认段。
    Nothing,
    /// 重传这一段（seq/len/flags 原样）。
    Resend(Seg),
    /// 次数超限：连接应判死。
    GiveUp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AckResult {
    /// 本次 ACK 推进了 `snd_una` 吗。
    pub advanced: bool,
    /// 干净（未重传）段产生的 RTT 样本（µs）；取最新被完全确认的那一段。
    pub rtt_sample_us: Option<u32>,
    /// 完全出队的段数。
    pub acked_segs: u8,
}

pub struct RetxQueue<const N: usize> {
    q: [Seg; N],
    head: usize,
    len: usize,
}

const EMPTY: Seg = Seg { seq: 0, len: 0, flags: 0, sent_us: 0, tries: 0 };

impl<const N: usize> RetxQueue<N> {
    pub const fn new() -> Self { RetxQueue { q: [EMPTY; N], head: 0, len: 0 } }
    pub fn len(&self) -> usize { self.len }
    pub fn is_empty(&self) -> bool { self.len == 0 }
    fn at(&self, i: usize) -> &Seg { &self.q[(self.head + i) % N] }
    fn at_mut(&mut self, i: usize) -> &mut Seg { let k = (self.head + i) % N; &mut self.q[k] }

    /// 最老未确认段的 seq（= snd_una 的上界提示）；空队列 None。
    pub fn oldest(&self) -> Option<Seg> { if self.len == 0 { None } else { Some(*self.at(0)) } }

    pub fn push(&mut self, seq: u32, len: u32, flags: u8, now_us: u64) -> Result<(), PushError> {
        if self.len == N { return Err(PushError::Full); }
        let k = (self.head + self.len) % N;
        self.q[k] = Seg { seq, len, flags, sent_us: now_us, tries: 0 };
        self.len += 1;
        Ok(())
    }

    /// 累积 ACK。`ack` 为对端期望的下一个序号，`snd_nxt` 是本端已发送的最后序号。
    /// ACK 超过 `snd_nxt` 是非法确认，直接忽略，不能把未发送的序号当成已确认。
    pub fn on_ack(&mut self, ack: u32, snd_nxt: u32, now_us: u64) -> AckResult {
        let mut r = AckResult::default();
        if self.len == 0 || seq_gt(ack, snd_nxt) { return r; }
        while self.len > 0 {
            let s = *self.at(0);
            let end = s.seq.wrapping_add(s.len);
            if seq_le(end, ack) {
                // 完全确认
                if s.tries == 0 {
                    r.rtt_sample_us = Some(now_us.saturating_sub(s.sent_us).min(u32::MAX as u64) as u32);
                }
                self.head = (self.head + 1) % N; self.len -= 1;
                r.advanced = true; r.acked_segs = r.acked_segs.saturating_add(1);
            } else if seq_lt(s.seq, ack) {
                // 部分确认：裁掉已确认前缀，保留余下；该段此后视为“重传过”（不再产样本），符合 Karn 的保守取向
                let cut = ack.wrapping_sub(s.seq);
                let m = self.at_mut(0);
                m.seq = ack; m.len -= cut; m.tries = m.tries.max(1);
                r.advanced = true;
                break;
            } else {
                break;
            }
        }
        r
    }

    /// 重传定时器到期。只动最老段。
    pub fn on_timeout(&mut self) -> Timeout {
        if self.len == 0 { return Timeout::Nothing; }
        let s = *self.at(0);
        if s.tries >= MAX_TRIES { return Timeout::GiveUp; }
        let m = self.at_mut(0);
        m.tries += 1;
        Timeout::Resend(*m)
    }

    /// 清空（连接复位/关闭）。
    pub fn clear(&mut self) { self.head = 0; self.len = 0; }
}
