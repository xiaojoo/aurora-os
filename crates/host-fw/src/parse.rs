//! 从以太网帧取五元组。**任意输入不 panic、不越界**：全函数没有一处下标或切片下标，
//! 每次读取都是 `get()`，越界即 [`Parsed::Malformed`]。
//!
//! ## 与内核解析器的关系（务必读）
//!
//! UDP 两条路的**接受条件逐条照抄**内核：
//! * IPv4：`kernel/src/network/udp.rs:163-204` `parse_frame`（含 IHL、分片、总长、UDP 长度四道）；
//! * IPv6：`kernel/src/network/ipv6.rs:246-279` `parse_udp6_frame`（无扩展头、plen、UDP 长度）。
//!
//! 宿主机差分（Python 移植，README T6）：47 016 条帧上"内核接受 ⇔ 本函数给出 UDP 包且五元组相等"，0 处不一致。
//! **但内核挂载点的 UDP 分支不用本函数**——它直接拿内核解析器已经解出的端点构造 [`Packet`]
//! （"过滤的就是将要被消费的"，从结构上消灭解析差分绕过）。本函数在内核里只用于 NDP 分支，
//! 并为第二期出站过滤备用。
//!
//! ICMPv6：要求完整 40 字节 IPv6 头、`next header = 58`、`plen ≥ 4` 且 `14+40+plen ≤ len`。
//! 它**严格宽于** `ndp.rs:200` `parse_nd` 的接受集（后者还要 `plen ≥ 24`、`hop = 255`、类型 135/136），
//! 差分检验：parse_nd 接受的帧本函数全部接受（0 例外）。所以"过滤器启用时，NDP 分支取不出头就丢"
//! 不会误丢任何内核本来会处理的 NS/NA。

use crate::packet::{Dir, Packet};

/// 解析结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parsed {
    /// 取出了五元组。
    Packet(Packet),
    /// 不是 IPv4/IPv6（ARP 等）。
    NotIp,
    /// 长度/版本/长度字段不自洽。
    Malformed,
    /// IP 合法但不是第一期覆盖的协议（TCP、分片、IPv6 扩展头……）。
    Unsupported,
}

const ETH: usize = 14;
const IP4: usize = 20;
const IP6: usize = 40;
const UDP: usize = 8;

fn g(f: &[u8], i: usize) -> Option<u8> {
    f.get(i).copied()
}

fn be16(f: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([g(f, i)?, g(f, i.checked_add(1)?)?]))
}

fn arr<const N: usize>(f: &[u8], at: usize) -> Option<[u8; N]> {
    f.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// 解析一帧。`dir` 原样写进 [`Packet::dir`]。
pub fn parse_eth(f: &[u8], dir: Dir) -> Parsed {
    match be16(f, 12) {
        None => Parsed::Malformed,
        Some(0x0800) => parse_v4(f, dir).unwrap_or(Parsed::Malformed),
        Some(0x86DD) => parse_v6(f, dir).unwrap_or(Parsed::Malformed),
        Some(_) => Parsed::NotIp,
    }
}

fn parse_v4(f: &[u8], dir: Dir) -> Option<Parsed> {
    let ip = ETH;
    if f.len() < ETH + IP4 + UDP {
        return Some(Parsed::Malformed);
    }
    let vh = g(f, ip)?;
    if vh >> 4 != 4 {
        return Some(Parsed::Malformed);
    }
    let ihl = usize::from(vh & 0x0F) * 4;
    if ihl < IP4 || f.len() < ip + ihl + UDP {
        return Some(Parsed::Malformed);
    }
    if g(f, ip + 9)? != 17 {
        return Some(Parsed::Unsupported);
    }
    if be16(f, ip + 6)? & 0x3FFF != 0 {
        return Some(Parsed::Unsupported); // 分片：内核也不收（不重组）
    }
    let tot = usize::from(be16(f, ip + 2)?);
    if tot < ihl + UDP || ip + tot > f.len() {
        return Some(Parsed::Malformed);
    }
    let u = ip + ihl;
    let ulen = usize::from(be16(f, u + 4)?);
    if ulen < UDP || u + ulen > ip + tot {
        return Some(Parsed::Malformed);
    }
    let src: [u8; 4] = arr(f, ip + 12)?;
    let dst: [u8; 4] = arr(f, ip + 16)?;
    Some(Parsed::Packet(Packet::udp4(src, dst, be16(f, u)?, be16(f, u + 2)?, dir)))
}

fn parse_v6(f: &[u8], dir: Dir) -> Option<Parsed> {
    let ip = ETH;
    if f.len() < ETH + IP6 {
        return Some(Parsed::Malformed);
    }
    if g(f, ip)? >> 4 != 6 {
        return Some(Parsed::Malformed);
    }
    let nh = g(f, ip + 6)?;
    let plen = usize::from(be16(f, ip + 4)?);
    let src: [u8; 16] = arr(f, ip + 8)?;
    let dst: [u8; 16] = arr(f, ip + 24)?;
    match nh {
        17 => {
            if f.len() < ETH + IP6 + UDP {
                return Some(Parsed::Malformed);
            }
            if plen < UDP || ip + IP6 + plen > f.len() {
                return Some(Parsed::Malformed);
            }
            let u = ip + IP6;
            let ulen = usize::from(be16(f, u + 4)?);
            if ulen < UDP || ulen > plen {
                return Some(Parsed::Malformed);
            }
            Some(Parsed::Packet(Packet::udp6(src, dst, be16(f, u)?, be16(f, u + 2)?, dir)))
        }
        58 => {
            if f.len() < ETH + IP6 + 4 {
                return Some(Parsed::Malformed);
            }
            if plen < 4 || ip + IP6 + plen > f.len() {
                return Some(Parsed::Malformed);
            }
            Some(Parsed::Packet(Packet::icmp6(src, dst, g(f, ip + IP6)?, dir)))
        }
        _ => Some(Parsed::Unsupported),
    }
}
