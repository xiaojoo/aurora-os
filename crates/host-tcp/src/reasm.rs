//! 有界乱序重组。
//!
//! 现状（tcp_conn.rs）：“收到的段必须正好是期望序号，否则丢弃”。这里补一个**有界**缓冲：
//! 最多 `SEGS` 个乱序区间，总缓存字节上限 `CAP`；溢出时丢最远端的区间并计数（**不 panic、不无限增长**）。
//! 这是对 Linux 历史上“乱序/SACK 缓冲被滥用为内存 DoS”的直接防御（S2 手册 S2.5）。
//!
//! 只做**区间簿记**（不存载荷字节）：调用方把载荷放进自己的环形接收缓冲，本结构只回答
//! “现在 rcv_nxt 能推进到哪”。这样无拷贝、无分配，也便于宿主机穷举测试。
use crate::{seq_le, seq_lt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range { pub start: u32, pub end: u32 } // [start, end)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Insert {
    /// 正好是期望序号（含合并后推进）：新的 rcv_nxt。
    Advanced(u32),
    /// 乱序，已入簿（等待补洞）。
    Buffered,
    /// 完全是旧数据/重复。
    Duplicate,
    /// 超出容量被丢弃（区间数或字节数）。
    Dropped,
}

pub struct Reasm<const SEGS: usize> {
    r: [Range; SEGS],
    n: usize,
    cap: u32,
    pub dropped: u32,
}

impl<const SEGS: usize> Reasm<SEGS> {
    /// `cap`：允许缓存的**窗口外**字节上限（即 rcv_nxt 之后最远能容纳多少）。
    pub const fn new(cap: u32) -> Self { Reasm { r: [Range { start: 0, end: 0 }; SEGS], n: 0, cap, dropped: 0 } }
    pub fn ranges(&self) -> &[Range] { &self.r[..self.n] }

    fn remove(&mut self, i: usize) { for k in i..self.n - 1 { self.r[k] = self.r[k + 1]; } self.n -= 1; }

    /// 收到 [seq, seq+len)。`rcv_nxt` 为当前期望序号。
    pub fn insert(&mut self, rcv_nxt: u32, seq: u32, len: u32) -> Insert {
        if len == 0 { return Insert::Duplicate; }
        let end = seq.wrapping_add(len);
        if seq_le(end, rcv_nxt) { return Insert::Duplicate; }                       // 全旧
        let mut start = seq;
        if seq_lt(start, rcv_nxt) { start = rcv_nxt; }                                // 裁掉已收前缀
        // 容量：离 rcv_nxt 太远
        if end.wrapping_sub(rcv_nxt) > self.cap { self.dropped += 1; return Insert::Dropped; }
        if start == rcv_nxt {
            // 可立即推进；再吃掉与之相接/重叠的已缓存区间
            let mut nxt = end;
            loop {
                let mut merged = false;
                let mut i = 0;
                while i < self.n {
                    let rg = self.r[i];
                    if seq_le(rg.start, nxt) {
                        if seq_lt(nxt, rg.end) { nxt = rg.end; }
                        self.remove(i); merged = true; break;
                    }
                    i += 1;
                }
                if !merged { break; }
            }
            return Insert::Advanced(nxt);
        }
        // 乱序：并入已有区间或新建
        let (mut s, mut e) = (start, end);
        let mut i = 0;
        while i < self.n {
            let rg = self.r[i];
            // 相交或相接
            if seq_le(rg.start, e) && seq_le(s, rg.end) {
                if seq_lt(rg.start, s) { s = rg.start; }
                if seq_lt(e, rg.end) { e = rg.end; }
                self.remove(i);
                continue;
            }
            i += 1;
        }
        if self.n == SEGS {
            // 满：丢最远端（start 最大）的一个，保留靠近 rcv_nxt 的——补洞收益最大
            let mut far = 0;
            for k in 1..self.n { if seq_lt(self.r[far].start, self.r[k].start) { far = k; } }
            if seq_lt(self.r[far].start, s) { self.dropped += 1; return Insert::Dropped; }
            self.remove(far); self.dropped += 1;
        }
        // 按 start 升序插入
        let mut pos = self.n;
        for k in 0..self.n { if seq_lt(s, self.r[k].start) { pos = k; break; } }
        let mut k = self.n; while k > pos { self.r[k] = self.r[k - 1]; k -= 1; }
        self.r[pos] = Range { start: s, end: e }; self.n += 1;
        Insert::Buffered
    }
}
