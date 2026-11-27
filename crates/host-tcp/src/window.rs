//! 发送窗口（对端通告窗口限速）。
//!
//! 可发字节数 = min(cwnd, snd_wnd) - 在途字节，其中在途 = snd_nxt - snd_una。
//! 现状（tcp_conn.rs 头注释）：“窗口字段照填，但不按对端窗口限制发送”——本模块补上这一判据。
//! 零窗口：`snd_wnd==0` 时不发新数据，改由持续定时器（persist）探测 1 字节（RFC 9293 §3.8.6.1）。
use crate::{seq_gt, seq_le, seq_lt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendWindow {
    pub snd_una: u32,
    pub snd_nxt: u32,
    /// 对端通告窗口（字节，已按窗口缩放换算；当前无缩放则等于头部 window 字段）。
    pub snd_wnd: u32,
    /// 上次更新窗口所用段的 (seq, ack)，用于 RFC 9293 §3.10.7.4 的“防旧段更新窗口”判据。
    wl1: u32,
    wl2: u32,
}

impl SendWindow {
    pub const fn new(iss: u32, wnd: u32) -> Self { SendWindow { snd_una: iss, snd_nxt: iss, snd_wnd: wnd, wl1: 0, wl2: 0 } }
    pub fn in_flight(&self) -> u32 { self.snd_nxt.wrapping_sub(self.snd_una) }

    /// 现在最多还能发多少字节。`cwnd` 由拥塞控制给（尚无则传 `u32::MAX`）。
    pub fn usable(&self, cwnd: u32) -> u32 {
        let lim = self.snd_wnd.min(cwnd);
        lim.saturating_sub(self.in_flight())
    }

    /// 发出 `n` 字节（调用方已确保 n <= usable）。
    pub fn on_send(&mut self, n: u32) { self.snd_nxt = self.snd_nxt.wrapping_add(n); }

    /// 收到 ACK 段时更新 snd_una 与窗口。返回 ACK 是否可接受（落在 (snd_una, snd_nxt]）。
    /// 窗口更新条件（RFC 9293 §3.10.7.4）：SND.WL1 < SEG.SEQ，或 (SND.WL1 == SEG.SEQ 且 SND.WL2 <= SEG.ACK)。
    pub fn on_ack_segment(&mut self, seg_seq: u32, seg_ack: u32, seg_wnd: u32) -> bool {
        // 旧 ACK / 未发送数据的 ACK：不可接受
        if seq_lt(self.snd_nxt, seg_ack) { return false; }
        if seq_lt(seg_ack, self.snd_una) { return false; }
        if seq_gt(seg_ack, self.snd_una) { self.snd_una = seg_ack; }
        if seq_lt(self.wl1, seg_seq) || (self.wl1 == seg_seq && seq_le(self.wl2, seg_ack)) {
            self.snd_wnd = seg_wnd; self.wl1 = seg_seq; self.wl2 = seg_ack;
        }
        true
    }
    /// 是否应由持续定时器发 1 字节探测：对端窗口为 0 且无在途数据。
    pub fn needs_probe(&self) -> bool { self.snd_wnd == 0 && self.in_flight() == 0 }
}
