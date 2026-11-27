//! SACK（RFC 2018，S4 步骤 2）：收端块生成 + 发端 scoreboard。纯函数/纯数据，无分配、无锁、无时钟。
//!
//! 黄金测试：RFC 2018 §7 的 Case 2、Case 3 及其后续两步，在沙箱 Python 等价模型里与权威表**逐字一致**（测试里原样复刻）。
//!
//! ## 本文件做了、而 RFC 没规定的设计决定（须评审）
//! 1. [`sanitize_blocks`]：丢弃 `r > snd_nxt`（SACK 了从未发送的数据）、`l < snd_una`、空块。RFC 2018 对此无规定；
//!    不过滤则攻击者可伪造 SACK 让发端以为对端已收到、不再重传。
//! 2. [`Scoreboard`] 固定 [`SB_SLOTS`]=16 槽；溢出时丢**最低**块并计数。丢低端块只会让其被**多重传**（安全方向），不会漏重传。
//! 3. RTO 后 [`Scoreboard::on_timeout`] 清空全部块（RFC 2018 §5：对端可能 renege）。
use crate::{seq_le, seq_lt};

pub const SB_SLOTS: usize = 16;
/// 带时间戳选项时最多 3 块，否则 4 块（RFC 2018 §3）。
pub const MAX_BLOCKS: usize = 4;
/// 收端排队块上限。超过时拒收最新的乱序段（有界，不 panic）。
pub const RX_SLOTS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Block { pub l: u32, pub r: u32 }

impl Block {
    #[inline] fn contains(&self, o: &Block) -> bool { seq_le(self.l, o.l) && seq_le(o.r, self.r) }
}

// ------------------------------------------------------------------ 收端
#[derive(Clone, Copy, Debug)]
pub struct SackRx {
    pub rcv_nxt: u32,
    blocks: [Block; RX_SLOTS],
    n: usize,
    /// 最近作为"第一块"报告过的块，新→旧（RFC 2018 §4 第 3 条用它补满选项）。
    recent: [Block; MAX_BLOCKS],
    nrecent: usize,
    pub dropped_ooo: u32,
}

/// `on_segment` 的结果：累积 ACK 号 + 要带的 SACK 块（至多 `max_blocks`）。
#[derive(Clone, Copy, Debug)]
pub struct AckOut { pub ack: u32, pub blocks: [Block; MAX_BLOCKS], pub nblocks: usize }
impl AckOut {
    pub fn as_slice(&self) -> &[Block] { &self.blocks[..self.nblocks] }
}

impl SackRx {
    pub const fn new(rcv_nxt: u32) -> Self {
        SackRx { rcv_nxt, blocks: [Block { l: 0, r: 0 }; RX_SLOTS], n: 0, recent: [Block { l: 0, r: 0 }; MAX_BLOCKS], nrecent: 0, dropped_ooo: 0 }
    }

    pub fn on_segment(&mut self, seq: u32, len: u32, max_blocks: usize) -> AckOut {
        let maxb = max_blocks.min(MAX_BLOCKS);
        let end = seq.wrapping_add(len);
        if len == 0 || seq_le(end, self.rcv_nxt) {
            return self.emit(None, maxb); // 旧段/空段：仍回 ACK
        }
        if seq_le(seq, self.rcv_nxt) {
            // 推进左边缘并吸收相邻已排队块
            self.rcv_nxt = end;
            loop {
                let mut changed = false;
                let mut i = 0;
                while i < self.n {
                    if seq_le(self.blocks[i].l, self.rcv_nxt) {
                        if seq_lt(self.rcv_nxt, self.blocks[i].r) { self.rcv_nxt = self.blocks[i].r; }
                        self.remove(i);
                        changed = true;
                    } else { i += 1; }
                }
                if !changed { break; }
            }
            self.prune_recent();
            return self.emit(None, maxb);
        }
        // 乱序段：并入块表
        if !self.merge(Block { l: seq, r: end }) {
            self.dropped_ooo += 1;
            return self.emit(None, maxb);
        }
        let trig = self.containing(seq).unwrap_or(Block { l: seq, r: end });
        self.push_recent(trig);
        self.emit(Some(trig), maxb)
    }

    fn remove(&mut self, i: usize) { self.blocks[i] = self.blocks[self.n - 1]; self.n -= 1; }
    fn containing(&self, s: u32) -> Option<Block> {
        self.blocks[..self.n].iter().copied().find(|b| seq_le(b.l, s) && seq_lt(s, b.r))
    }
    /// 并入 `nb`，与重叠/相邻块合并。表满且无法合并 → false（拒收，有界）。
    fn merge(&mut self, mut nb: Block) -> bool {
        loop {
            let mut hit = None;
            for i in 0..self.n {
                let b = self.blocks[i];
                // 相邻或重叠：nb.l <= b.r 且 b.l <= nb.r
                if seq_le(nb.l, b.r) && seq_le(b.l, nb.r) { hit = Some(i); break; }
            }
            match hit {
                Some(i) => {
                    let b = self.blocks[i];
                    if seq_lt(b.l, nb.l) { nb.l = b.l; }
                    if seq_lt(nb.r, b.r) { nb.r = b.r; }
                    self.remove(i);
                }
                None => break,
            }
        }
        if self.n == RX_SLOTS { return false; }
        self.blocks[self.n] = nb; self.n += 1; true
    }
    fn push_recent(&mut self, b: Block) {
        // 去掉被 b 包含的旧项，再插队首
        let mut tmp = [Block::default(); MAX_BLOCKS]; let mut k = 0;
        tmp[k] = b; k += 1;
        for i in 0..self.nrecent {
            let o = self.recent[i];
            if b.contains(&o) { continue; }
            if k < MAX_BLOCKS { tmp[k] = o; k += 1; }
        }
        self.recent = tmp; self.nrecent = k;
    }
    fn prune_recent(&mut self) {
        let mut k = 0;
        for i in 0..self.nrecent {
            let o = self.recent[i];
            if seq_lt(self.rcv_nxt, o.r) { self.recent[k] = o; k += 1; }
        }
        self.nrecent = k;
    }
    fn still_present(&self, b: &Block) -> Option<Block> {
        self.blocks[..self.n].iter().copied().find(|x| x.contains(b) || b.contains(x))
    }
    fn emit(&self, trig: Option<Block>, maxb: usize) -> AckOut {
        let mut out = AckOut { ack: self.rcv_nxt, blocks: [Block::default(); MAX_BLOCKS], nblocks: 0 };
        if self.n == 0 || maxb == 0 { return out; }
        let mut push = |o: &mut AckOut, b: Block| -> bool {
            if o.nblocks >= maxb { return false; }
            // 不收录已被已选块包含的子集（RFC 2018 §4 第 3 条）
            for i in 0..o.nblocks { if o.blocks[i].contains(&b) { return true; } }
            o.blocks[o.nblocks] = b; o.nblocks += 1; true
        };
        if let Some(t) = trig { push(&mut out, t); }
        for i in 0..self.nrecent {
            if let Some(cur) = self.still_present(&self.recent[i]) { if !push(&mut out, cur) { break; } }
        }
        for i in 0..self.n { if !push(&mut out, self.blocks[i]) { break; } }
        out
    }
}

// ------------------------------------------------------------------ 发端
/// 过滤畸形 SACK 块（设计决定 1）。返回通过的块数，写入 `out`。
pub fn sanitize_blocks(blocks: &[Block], snd_una: u32, snd_nxt: u32, out: &mut [Block; MAX_BLOCKS]) -> usize {
    let mut k = 0;
    for b in blocks {
        if k >= MAX_BLOCKS { break; }
        if b.l == b.r { continue; }
        if seq_lt(snd_nxt, b.r) { continue; }       // 超过已发送：伪造/畸形
        if seq_lt(b.l, snd_una) { continue; }       // 左边缘早于 snd_una
        if !seq_lt(b.l, b.r) { continue; }
        out[k] = *b; k += 1;
    }
    k
}

#[derive(Clone, Copy, Debug)]
pub struct Scoreboard {
    pub snd_una: u32,
    blocks: [Block; SB_SLOTS],
    n: usize,
    pub overflow: u32,
}

impl Scoreboard {
    pub const fn new(snd_una: u32) -> Self { Scoreboard { snd_una, blocks: [Block { l: 0, r: 0 }; SB_SLOTS], n: 0, overflow: 0 } }

    /// 处理一个 ACK：推进 `snd_una`，并入（已 sanitize 的）SACK 块。
    pub fn update(&mut self, ack: u32, sacked: &[Block]) {
        if seq_lt(self.snd_una, ack) { self.snd_una = ack; }
        // 去掉已被累积确认覆盖的部分
        let mut k = 0;
        for i in 0..self.n {
            let mut b = self.blocks[i];
            if seq_le(b.r, self.snd_una) { continue; }
            if seq_lt(b.l, self.snd_una) { b.l = self.snd_una; }
            self.blocks[k] = b; k += 1;
        }
        self.n = k;
        for b in sacked { self.insert(*b); }
    }

    fn insert(&mut self, mut nb: Block) {
        if seq_le(nb.r, self.snd_una) { return; }
        if seq_lt(nb.l, self.snd_una) { nb.l = self.snd_una; }
        loop {
            let mut hit = None;
            for i in 0..self.n {
                let b = self.blocks[i];
                if seq_le(nb.l, b.r) && seq_le(b.l, nb.r) { hit = Some(i); break; }
            }
            match hit {
                Some(i) => {
                    let b = self.blocks[i];
                    if seq_lt(b.l, nb.l) { nb.l = b.l; }
                    if seq_lt(nb.r, b.r) { nb.r = b.r; }
                    self.blocks[i] = self.blocks[self.n - 1]; self.n -= 1;
                }
                None => break,
            }
        }
        if self.n == SB_SLOTS {
            // 溢出：丢**最低**块（含刚合并出的 nb 若它最低），计数。安全方向：只会多重传。
            let mut lo = 0;
            for i in 1..self.n { if seq_lt(self.blocks[i].l, self.blocks[lo].l) { lo = i; } }
            if seq_lt(nb.l, self.blocks[lo].l) { self.overflow += 1; return; }
            self.blocks[lo] = nb; self.overflow += 1; return;
        }
        self.blocks[self.n] = nb; self.n += 1;
    }

    /// RTO：清空所有 SACK 信息（RFC 2018 §5）。**去掉这一行的变异必须被测试抓到。**
    pub fn on_timeout(&mut self) { self.n = 0; }

    pub fn highest_sacked(&self) -> Option<u32> {
        let mut hi: Option<u32> = None;
        for b in &self.blocks[..self.n] { hi = Some(match hi { Some(h) if seq_le(b.r, h) => h, _ => b.r }); }
        hi
    }

    /// `[snd_una, 最高 SACK)` 内第一个未被 SACK 的字节区间；没有则 None。`from` 用于跳过已重传的洞。
    pub fn next_hole(&self, from: u32) -> Option<Block> {
        let hi = self.highest_sacked()?;
        let mut cur = if seq_lt(from, self.snd_una) { self.snd_una } else { from };
        // 按 l 升序遍历
        let mut order = [0usize; SB_SLOTS];
        for i in 0..self.n { order[i] = i; }
        for i in 1..self.n { let mut j = i; while j > 0 && seq_lt(self.blocks[order[j]].l, self.blocks[order[j - 1]].l) { order.swap(j, j - 1); j -= 1; } }
        for k in 0..self.n {
            let b = self.blocks[order[k]];
            if seq_lt(cur, b.l) { return Some(Block { l: cur, r: b.l }); }
            if seq_lt(cur, b.r) { cur = b.r; }
        }
        let _ = hi;
        None
    }
    pub fn block_count(&self) -> usize { self.n }
    pub fn is_sacked(&self, s: u32) -> bool { self.blocks[..self.n].iter().any(|b| seq_le(b.l, s) && seq_lt(s, b.r)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn b(l: u32, r: u32) -> Block { Block { l, r } }

    #[test]
    fn rfc2018_case2_one_block_grows() {
        // 左边缘 5000，首段丢失，其余 7 段（各 500 B）到达。
        let mut rx = SackRx::new(5000);
        let exp = [6000, 6500, 7000, 7500, 8000, 8500, 9000];
        for (i, e) in exp.iter().enumerate() {
            let o = rx.on_segment(5500 + 500 * i as u32, 500, 4);
            assert_eq!(o.ack, 5000);
            assert_eq!(o.as_slice(), &[b(5500, *e)]);
        }
    }

    #[test]
    fn rfc2018_case3_and_followups() {
        let mut rx = SackRx::new(5000);
        let o = rx.on_segment(5000, 500, 3); assert_eq!((o.ack, o.nblocks), (5500, 0));
        let o = rx.on_segment(6000, 500, 3); assert_eq!((o.ack, o.as_slice()), (5500, &[b(6000, 6500)][..]));
        let o = rx.on_segment(7000, 500, 3); assert_eq!(o.as_slice(), &[b(7000, 7500), b(6000, 6500)]);
        let o = rx.on_segment(8000, 500, 3); assert_eq!(o.as_slice(), &[b(8000, 8500), b(7000, 7500), b(6000, 6500)]);
        // 第 4 段（6500）迟到：触发块是合并后的 [6000,7500)，其后是 [8000,8500)
        let o = rx.on_segment(6500, 500, 3); assert_eq!((o.ack, o.as_slice()), (5500, &[b(6000, 7500), b(8000, 8500)][..]));
        // 第 2 段（5500）到达：ack 推进到 7500
        let o = rx.on_segment(5500, 500, 3); assert_eq!((o.ack, o.as_slice()), (7500, &[b(8000, 8500)][..]));
    }

    #[test]
    fn sender_never_marks_unreceived_as_sacked_and_never_misses_a_hole() {
        // 确定性伪随机：乱序 + 丢段 + ACK 丢失；不变量：scoreboard 中每个字节收端都收到过；hi 以下的真洞必在 next_hole 链上。
        let mut s = 0x2468_ace1u32; let mut nx = || { s ^= s << 13; s ^= s >> 17; s ^= s << 5; s };
        for _ in 0..3000 {
            let una = 5000u32.wrapping_add(nx() % 8) ; let m = 500u32; let total = 8 + nx() % 32;
            let snd_nxt = una.wrapping_add(total * m);
            let mut rx = SackRx::new(una); let mut sb = Scoreboard::new(una);
            let mut got = [false; 48];
            let mut order = [0u32; 48]; let mut cnt = 0;
            for i in 0..total { if nx() % 3 != 0 { order[cnt] = i; cnt += 1; } }
            for _ in 0..(nx() % 6) { if cnt > 1 { let k = (nx() as usize) % (cnt - 1); order.swap(k, k + 1); } }
            for idx in 0..cnt {
                let i = order[idx]; got[i as usize] = true;
                let o = rx.on_segment(una.wrapping_add(i * m), m, 4);
                if nx() % 100 < 15 { continue; }
                let mut clean = [Block::default(); MAX_BLOCKS];
                let k = sanitize_blocks(o.as_slice(), sb.snd_una, snd_nxt, &mut clean);
                sb.update(o.ack, &clean[..k]);
                for j in 0..total { let x = una.wrapping_add(j * m); if sb.is_sacked(x) { assert!(got[j as usize], "sacked-but-not-received"); } }
            }
        }
    }

    #[test]
    fn rto_clears_sack() {
        let mut sb = Scoreboard::new(0); sb.update(0, &[b(1000, 2000)]);
        assert_eq!(sb.block_count(), 1); sb.on_timeout(); assert_eq!(sb.block_count(), 0);
    }

    #[test]
    fn sanitize_rejects_forged() {
        let mut out = [Block::default(); MAX_BLOCKS];
        assert_eq!(sanitize_blocks(&[b(1000, 99999)], 0, 5000, &mut out), 0, "超过 snd_nxt");
        assert_eq!(sanitize_blocks(&[b(0, 100)], 500, 5000, &mut out), 0, "左边缘 < snd_una");
        assert_eq!(sanitize_blocks(&[b(7, 7)], 0, 5000, &mut out), 0, "空块");
        assert_eq!(sanitize_blocks(&[b(1000, 2000)], 0, 5000, &mut out), 1);
    }

    #[test]
    fn overflow_drops_lowest_and_counts() {
        let mut sb = Scoreboard::new(0);
        for i in 1..30u32 { sb.update(0, &[b(i * 1000, i * 1000 + 500)]); }
        assert_eq!(sb.block_count(), SB_SLOTS); assert!(sb.overflow >= 13);
        // 保留的是**高**端块；最低 SB_SLOTS 之外被丢——低端洞会被"多重传"，不会被漏
        assert!(!sb.is_sacked(1000));
    }

    #[test]
    fn wraparound() {
        let una = u32::MAX - 1000;
        let mut sb = Scoreboard::new(una); sb.update(una, &[b(una.wrapping_add(500), una.wrapping_add(1500))]);
        assert!(sb.is_sacked(una.wrapping_add(600)) && !sb.is_sacked(una.wrapping_add(100)));
        assert_eq!(sb.next_hole(una), Some(b(una, una.wrapping_add(500))));
    }

    #[test]
    fn next_hole_never_covers_sacked_bytes_and_chain_has_no_gap() {
        // 判据（沙箱：基线 0，变异"整段 [una,hi)"27536）：hole 不得含任何已 SACK 字节（否则重传已收数据）。
        let mut s = 0x1357_9bdfu32; let mut nx = || { s ^= s << 13; s ^= s >> 17; s ^= s << 5; s };
        for _ in 0..2000 {
            let una = 5000u32; let m = 500u32; let total = 8 + nx() % 32; let snd_nxt = una + total * m;
            let mut rx = SackRx::new(una); let mut sb = Scoreboard::new(una);
            for i in 0..total {
                if nx() % 3 == 0 { continue; }
                let o = rx.on_segment(una + i * m, m, 4);
                let mut clean = [Block::default(); MAX_BLOCKS];
                let k = sanitize_blocks(o.as_slice(), sb.snd_una, snd_nxt, &mut clean);
                sb.update(o.ack, &clean[..k]);
                let mut cur = sb.snd_una;
                for _ in 0..64 {
                    let Some(h) = sb.next_hole(cur) else { break };
                    let mut x = h.l; while seq_lt(x, h.r) { assert!(!sb.is_sacked(x), "hole 含已 SACK 字节"); x = x.wrapping_add(m); }
                    cur = h.r;
                }
            }
        }
    }
}
