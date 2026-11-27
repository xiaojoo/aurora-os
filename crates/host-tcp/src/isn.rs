//! 初始序号与临时端口（S4 步骤 4）：RFC 6528 + RFC 6056 算法 3。纯函数；PRF 与时钟由调用方注入。
//!
//! ## 现状（读源码得到，不是推测）
//! * ISN：`socket.rs:267` `0x1000_0000 + (slot<<8) + gen`；`accept` 后 `+0x1000`（socket.rs:919）。相邻槽 ISN 差**恒为 256**，完全可预测。
//! * 端口：UDP `user.rs:3197` `49152 + slot`，顺序可预测。TCP 的 `tcp_start_connect` **没有端口分配**（见 ADR-266 §0：它在产品代码里零调用点）。
//!
//! ## RFC 6528 §3
//! `ISN = M + F(localip, localport, remoteip, remoteport, secret)`，M 为 4 µs 计时器，F 为 PRF，secret ≥128 位。
//! **M 必须保留**：纯随机 ISN 会破坏 4.4BSD 的 TIME-WAIT 重用启发式（RFC 6528 §2）。secret 仅在启动时取一次、**不做运行期轮换**
//! （轮换会改变重现连接的 ISN 空间，需静默 2×MSL，RFC 6528 §3）。
//!
//! ## 沙箱验证
//! 同四元组 +4 s ⇒ ISN 差恰为 1_000_000；相邻端口 ISN 差高 8 位卡方 260.4（自由度 255，95% 上界≈293）；旧公式差恒为 256；
//! 固定 secret 变异（两次"启动"同四元组 ISN 相同）被判红。
use crate::seq_lt;

pub const EPHEM_LO: u16 = 49152;
pub const EPHEM_HI: u16 = 65535;
pub const EPHEM_N: u32 = (EPHEM_HI - EPHEM_LO) as u32 + 1; // 16384

#[derive(Clone, Copy, Debug)]
pub struct Conn { pub lip: [u8; 4], pub lport: u16, pub rip: [u8; 4], pub rport: u16 }

/// RFC 6528 §3。`now_us` 为单调微秒；`prf(conn)` 为以启动期 secret 为密钥的 PRF 低 32 位。
#[inline]
pub fn isn(c: &Conn, now_us: u64, prf: &dyn Fn(&Conn) -> u32) -> u32 {
    ((now_us / 4) as u32).wrapping_add(prf(c))
}

/// RFC 6056 算法 3：`port = LO + (F(lip, rip, rport, key) + counter + k) % N`，被占则 k+1 探测。
/// `in_use(p)` 查本地端口占用表。最多探测 `max_probe` 次；全占/超限返回 None。
/// 内核里 `MAX_SOCKETS=256`，故真实最坏探测 ≤256（沙箱 3000 次随机占用实测最坏 255）。
pub fn ephemeral_port(lip: [u8; 4], rip: [u8; 4], rport: u16, counter: u32, max_probe: u32,
                      prf: &dyn Fn([u8; 4], [u8; 4], u16) -> u32, in_use: &dyn Fn(u16) -> bool) -> Option<u16> {
    let off = prf(lip, rip, rport);
    let mut k = 0u32;
    while k < max_probe.min(EPHEM_N) {
        let p = EPHEM_LO as u32 + (off.wrapping_add(counter).wrapping_add(k)) % EPHEM_N;
        if !in_use(p as u16) { return Some(p as u16); }
        k += 1;
    }
    None
}

/// 已用于判据：ISN 单调性（同四元组，时间前进 ⇒ 序号前进，回绕安全）。
pub fn isn_advances(a: u32, b: u32, max_span: u32) -> bool { seq_lt(a, b) && b.wrapping_sub(a) <= max_span }

#[cfg(test)]
mod tests {
    use super::*;
    fn prf_c(c: &Conn) -> u32 {
        let mut h = 0x9e37_79b9u32;
        for b in c.lip.iter().chain(c.rip.iter()) { h = (h ^ *b as u32).wrapping_mul(0x0100_0193); h ^= h >> 13; }
        for x in [c.lport as u32, c.rport as u32] { h = (h ^ x).wrapping_mul(0x0100_0193); h ^= h >> 13; }
        h
    }
    fn prf_p(l: [u8; 4], r: [u8; 4], p: u16) -> u32 { prf_c(&Conn { lip: l, lport: 0, rip: r, rport: p }) }

    #[test]
    fn same_connection_advances_one_per_4us() {
        let c = Conn { lip: [10, 0, 0, 1], lport: 5000, rip: [10, 0, 0, 2], rport: 80 };
        let a = isn(&c, 1_000_000_000, &prf_c); let b = isn(&c, 1_004_000_000, &prf_c);
        assert_eq!(b.wrapping_sub(a), 1_000_000);
        assert!(isn_advances(a, b, 2_000_000));
    }
    #[test]
    fn adjacent_ports_have_unrelated_isn() {
        // 旧公式相邻槽差恒为 256；新公式差不应是常数。
        let mut diffs = [0u32; 64];
        for i in 0..64u16 {
            let a = Conn { lip: [10, 0, 0, 1], lport: 5000 + i, rip: [10, 0, 0, 2], rport: 80 };
            let b = Conn { lport: 5001 + i, ..a };
            diffs[i as usize] = isn(&b, 0, &prf_c).wrapping_sub(isn(&a, 0, &prf_c));
        }
        let first = diffs[0]; assert!(diffs.iter().any(|d| *d != first), "ISN 差为常数 = 可预测");
        assert!(diffs.iter().all(|d| *d != 256), "不得退化为旧公式的 256");
    }
    #[test]
    fn ephemeral_in_range_and_avoids_used() {
        let used = |p: u16| (EPHEM_LO..EPHEM_LO + 100).contains(&p);
        for rp in [80u16, 443, 8080] {
            let p = ephemeral_port([10, 0, 0, 1], [10, 0, 2, 2], rp, 0, 256, &prf_p, &used).unwrap();
            assert!((EPHEM_LO..=EPHEM_HI).contains(&p) && !used(p));
        }
    }
    #[test]
    fn ephemeral_exhausted_returns_none() {
        assert_eq!(ephemeral_port([1; 4], [2; 4], 80, 0, 256, &prf_p, &|_| true), None);
        assert_eq!(ephemeral_port([1; 4], [2; 4], 80, 0, 0, &prf_p, &|_| false), None, "max_probe=0 不探测");
    }
    #[test]
    fn counter_makes_consecutive_connects_sequential_but_dest_dependent_start() {
        let none = |_p: u16| false;
        let a0 = ephemeral_port([10, 0, 0, 1], [10, 0, 2, 2], 80, 0, 256, &prf_p, &none).unwrap();
        let a1 = ephemeral_port([10, 0, 0, 1], [10, 0, 2, 2], 80, 1, 256, &prf_p, &none).unwrap();
        let b0 = ephemeral_port([10, 0, 0, 1], [10, 0, 2, 3], 80, 0, 256, &prf_p, &none).unwrap();
        assert_eq!(a1 as u32 - EPHEM_LO as u32, (a0 as u32 - EPHEM_LO as u32 + 1) % EPHEM_N);
        assert_ne!(a0, b0, "不同目的起点应不同（RFC 6056 算法 3 的性质）");
    }
    #[test]
    fn probe_count_is_bounded_by_max_probe() {
        // 真的数探测次数：每次 in_use 被调用计一次；全占时必须恰好探测 max_probe 次后返回 None。
        use core::cell::Cell;
        for max_probe in [1u32, 7, 256] {
            let calls = Cell::new(0u32);
            let r = ephemeral_port([1; 4], [2; 4], 80, 0, max_probe, &prf_p, &|_| { calls.set(calls.get() + 1); true });
            assert_eq!(r, None);
            assert_eq!(calls.get(), max_probe, "探测次数必须恰等于上限（无无界循环）");
        }
    }
}
