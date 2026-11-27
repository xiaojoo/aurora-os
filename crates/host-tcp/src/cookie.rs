//! SYN cookie（S4 步骤 3）：纯函数。**接线被阻塞**：`Listen` 槽今天没有 backlog（socket.rs:866），"队列满"这个触发条件不存在。
//!
//! ## 与手册案例 12 的差异（均已在沙箱验证）
//! 1. **布局**：手册 5 位时间 + 3 位 MSS + 24 位 MAC = 32 位，**没有 SACK/WS 标志位**，与手册自己 S4.3 选型表
//!    （"cookie 里保留 MSS 档位与 SACK/WS 标志"）矛盾。本文件：`[31:28]` 时间片(4) `[27:26]` MSS 档(2) `[25]` SACK `[24]` WS `[23:0]` MAC(24)。
//!    代价：MSS 只有 4 档（手册 8 档）、时间片周期 16×64 s=1024 s（手册 2048 s）；**MAC 仍是 24 位**。
//! 2. **PRF 是调用方注入的闭包**，本 crate 不实现哈希。手册案例用 `siphash24`，**没有标准向量测试前不得内核落地**（手册自己也这么说）。
//!    内核侧可先接 S1 已有的 `crate::sign::digest`（SHA-256，已被宿主机 hashlib 第二仪器对账），慢但正确。
//! 3. 单个盲猜只能匹配**一个**时间片（高 4 位不同），所以单包伪造概率是 **2⁻²⁴**，不是我先前写的 2⁻²³。
//!    沙箱对**真实 `check`** 做黑盒盲猜：MAC=8/10/12/14 位下经验命中率与 2⁻ᵇⁱᵗˢ 比值 0.86~1.10；24 位是**同一代码路径外推**，非直接测得。
//!
//! ## 无状态协议的固有代价（不是缺陷，是取舍）
//! cookie 在 2 个时间片内可重放；丢失 SYN 中的其它选项（时间戳、ECN 等）；`check` 通过后仍须按 RFC 校验 `ack`/`seq` 范围。
//! 单包伪造成功率 2⁻²⁴≈6×10⁻⁸；洪泛 1e5 pps 时攻击者每秒期望成功≈0.006 个（≈168 s 一个）——**这是算术，不是实测，且我没有 Linux 的对照数据，不声称"与 Linux 同量级"**。
pub const MSS_TABLE: [u16; 4] = [536, 1220, 1440, 1460]; // 档位是设计选择，未经实测

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoded { pub mss: u16, pub sack: bool, pub ws: bool }

#[derive(Clone, Copy, Debug)]
pub struct Tuple { pub src: [u8; 4], pub dst: [u8; 4], pub sport: u16, pub dport: u16 }

/// 选 ≤ `peer_mss` 的最大档；比最小档还小则取最小档（RFC 要求不低于 536 的对端才用此档，调用方可另拒）。
pub fn mss_index(peer_mss: u16) -> u8 {
    let mut idx = 0u8;
    for (i, m) in MSS_TABLE.iter().enumerate() { if *m <= peer_mss { idx = i as u8; } }
    idx
}

/// 生成 cookie（= SYN-ACK 的 seq）。`peer_isn` 是客户端 SYN 的 seq；`t` 是完整的 64 秒时间片计数（进 PRF 的是完整值）。
/// `prf(tuple, peer_isn, t, flags) -> u32` 只取低 24 位。
pub fn make(tp: &Tuple, peer_isn: u32, mss_idx: u8, sack: bool, ws: bool, t: u32, prf: &dyn Fn(&Tuple, u32, u32, u8) -> u32) -> u32 {
    let flags = ((mss_idx & 3) << 2) | ((sack as u8) << 1) | (ws as u8);
    ((t & 0xF) << 28) | ((flags as u32) << 24) | (prf(tp, peer_isn, t, flags) & 0x00FF_FFFF)
}

/// 校验最终 ACK。`seg_ack` = cookie+1，`seg_seq` = 客户端 ISN+1。当前片与前一片可接受。
pub fn check(tp: &Tuple, seg_ack: u32, seg_seq: u32, now: u32, prf: &dyn Fn(&Tuple, u32, u32, u8) -> u32) -> Option<Decoded> {
    let cookie = seg_ack.wrapping_sub(1);
    let isn_c = seg_seq.wrapping_sub(1);
    let flags = ((cookie >> 24) & 0xF) as u8;
    for dt in 0..2u32 {
        let t = now.wrapping_sub(dt);
        if (cookie >> 28) & 0xF != t & 0xF { continue; }       // 先比 4 位，省一次 PRF
        if prf(tp, isn_c, t, flags) & 0x00FF_FFFF == cookie & 0x00FF_FFFF {
            return Some(Decoded { mss: MSS_TABLE[((flags >> 2) & 3) as usize], sack: flags & 2 != 0, ws: flags & 1 != 0 });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    // 测试用 PRF：不是密码学安全，只验证 make/check 的结构性质。
    fn prf(tp: &Tuple, isn: u32, t: u32, f: u8) -> u32 {
        let mut h = 0x811c9dc5u32 ^ 0xdead_beef;
        for b in tp.src.iter().chain(tp.dst.iter()) { h = (h ^ *b as u32).wrapping_mul(16777619); }
        for x in [tp.sport as u32, tp.dport as u32, isn, t, f as u32] { h = (h ^ x).wrapping_mul(16777619); h ^= h >> 15; }
        h
    }
    const TP: Tuple = Tuple { src: [10, 0, 0, 1], dst: [10, 0, 0, 2], sport: 40000, dport: 80 };

    #[test]
    fn roundtrip_all_16_flag_combos() {
        for mi in 0..4u8 { for sk in [false, true] { for ws in [false, true] {
            let c = make(&TP, 0xAABB_CCDD, mi, sk, ws, 1234, &prf);
            let d = check(&TP, c.wrapping_add(1), 0xAABB_CCDDu32.wrapping_add(1), 1234, &prf).unwrap();
            assert_eq!(d, Decoded { mss: MSS_TABLE[mi as usize], sack: sk, ws });
        }}}
    }
    #[test]
    fn time_window_current_and_previous_only() {
        let isn = 0x1234_5678; let c = make(&TP, isn, 1, true, false, 1234, &prf);
        let f = |now| check(&TP, c.wrapping_add(1), isn.wrapping_add(1), now, &prf).is_some();
        assert!(f(1234)); assert!(f(1235)); assert!(!f(1236));
        assert!(!f(1234 + 16), "16 片后低 4 位相同，但完整 t 进 PRF，必须拒绝");
    }
    #[test]
    fn any_tuple_change_rejects() {
        let isn = 7; let c = make(&TP, isn, 2, false, true, 99, &prf);
        let mut t = TP; t.src[3] = 9; assert!(check(&t, c + 1, isn + 1, 99, &prf).is_none());
        let mut t = TP; t.dst[3] = 9; assert!(check(&t, c + 1, isn + 1, 99, &prf).is_none());
        let mut t = TP; t.sport += 1; assert!(check(&t, c + 1, isn + 1, 99, &prf).is_none());
        let mut t = TP; t.dport += 1; assert!(check(&t, c + 1, isn + 1, 99, &prf).is_none());
        assert!(check(&TP, c + 1, isn + 2, 99, &prf).is_none(), "客户端 ISN 变化");
    }
    #[test]
    fn mss_index_picks_largest_not_exceeding() {
        assert_eq!(mss_index(1460), 3); assert_eq!(mss_index(1300), 1); assert_eq!(mss_index(536), 0); assert_eq!(mss_index(100), 0);
    }
}
