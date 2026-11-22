//! IPv6 地址与报文（ADR-182）。
//!
//! ## 与 IPv4 的关系
//!
//! **两条路并存，不合并**（ADR-182 决策 1）。IPv4 的函数签名保持 `[u8; 4]`——
//! 那是今天唯一能跑的路径，改签名是纯风险。
//!
//! 新代码（本模块、NDP、UDP over IPv6、DNS AAAA）用 [`IpAddr`]。

use crate::network::dhcp::NET_TYPE_IPV4;

/// IPv6 的以太网类型（RFC 2464）。
pub const NET_TYPE_IPV6: [u8; 2] = [0x86, 0xDD];

/// IPv6 固定头长（RFC 8200 §3）：**40 字节，没有选项字段**。
///
/// 与 IPv4 的 20 字节不同，这一条写错会让后面所有偏移全错。
pub const IP6_HDR: usize = 40;

/// IPv6 地址长度。
pub const IP6_ADDR_LEN: usize = 16;

/// IPv6 最小 MTU（RFC 8200 §5：1280 字节，低于它不得分片）。
pub const IP6_MIN_MTU: usize = 1280;

/// 一个 IP 地址，两个族并列（ADR-182 决策 1）。
///
/// **为什么是枚举而不是 `[u8; 16]`**：把 IPv4 也塞进 16 字节会让既有路径全部改签名，
/// 而那些路径**实测在跑**。枚举让「只有新代码认识两个族」成为类型事实。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpAddr {
    /// 字节长度（4 或 16）。
    pub const fn len(&self) -> usize {
        match self {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        }
    }

    pub const fn is_v4(&self) -> bool {
        matches!(self, IpAddr::V4(_))
    }

    /// IPv4 视图。`None` = 这是 IPv6 地址。
    pub const fn as_v4(&self) -> Option<[u8; 4]> {
        match self {
            IpAddr::V4(a) => Some(*a),
            IpAddr::V6(_) => None,
        }
    }

    /// IPv6 视图。`None` = 这是 IPv4 地址。
    pub const fn as_v6(&self) -> Option<[u8; 16]> {
        match self {
            IpAddr::V4(_) => None,
            IpAddr::V6(a) => Some(*a),
        }
    }

    /// 是不是链路本地（`fe80::/10`）。
    ///
    /// 判据：头 10 位是 `1111111010`。所以 `a[0] == 0xFE` 且 `a[1] & 0xC0 == 0x80`。
    pub fn is_link_local(&self) -> bool {
        match self {
            IpAddr::V4(_) => false,
            IpAddr::V6(a) => a[0] == 0xFE && (a[1] & 0xC0) == 0x80,
        }
    }

    /// 是不是组播（`ff00::/8`）。
    pub fn is_multicast(&self) -> bool {
        match self {
            IpAddr::V4(a) => a[0] >= 224 && a[0] <= 239,
            IpAddr::V6(a) => a[0] == 0xFF,
        }
    }
}

/// 全零 IPv6 地址（未指定）。
pub const IP6_UNSPECIFIED: [u8; 16] = [0; 16];

/// 所有节点链路本地组播 `ff02::1`（RFC 4291 §2.7.1）。
pub const IP6_ALL_NODES_LL: [u8; 16] = [
    0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
];

/// 被请求节点组播 `ff02::1:ffXX:XXXX`（RFC 4291 §2.7.1）。
///
/// **NDP 用它而不是广播**：IPv6 没有广播，邻居请求发给「目标地址后 24 位」对应的组播组。
/// 这比 IPv4 的 ARP 广播精确得多——只有真正关心那个地址的节点会收。
pub fn solicited_node_multicast(target: &[u8; 16]) -> [u8; 16] {
    let mut m = [0u8; 16];
    m[0] = 0xFF;
    m[1] = 0x02;
    m[11] = 0x01;
    m[12] = 0xFF;
    m[13] = target[13];
    m[14] = target[14];
    m[15] = target[15];
    m
}

/// 由 48 位 MAC 推出 EUI-64 接口标识（RFC 4291 附录 A）。
///
/// 步骤：
///
///     1. MAC 拆成前后两半（各 3 字节）
///     2. 中间插 FFFE
///     3. 第一个字节的 bit1（U/L 位）取反
///
/// **第 3 步最容易漏**，漏了之后算出来的地址在别的设备看来是「全局管理」的，
/// 而链路本地地址必须是本地管理的。
pub fn eui64_from_mac(mac: &[u8; 6]) -> [u8; 8] {
    let mut e = [0u8; 8];
    e[0] = mac[0] ^ 0x02; // U/L 位取反
    e[1] = mac[1];
    e[2] = mac[2];
    e[3] = 0xFF;
    e[4] = 0xFE;
    e[5] = mac[3];
    e[6] = mac[4];
    e[7] = mac[5];
    e
}

/// 由 MAC 推出链路本地地址（`fe80::/64` + EUI-64）。
pub fn link_local_from_mac(mac: &[u8; 6]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0xFE;
    a[1] = 0x80;
    let e = eui64_from_mac(mac);
    a[8..16].copy_from_slice(&e);
    a
}

/// IPv6 伪首部校验和用的「上层长度 + 下一头部」。
///
/// ## IPv6 与 IPv4 的关键差异
///
/// **IPv6 头没有校验和**（RFC 8200 §3）。校验完全交给上层，而 UDP 在 IPv6 上
/// **必须**算校验和（IPv4 上算 0 表示「不算」是允许的）。
///
/// 所以这个函数算的是 UDP 的校验和，只是伪首部换成了 IPv6 的形状：
///
///     +--------+--------+--------+--------+
///     |          源地址（16 字节）          |
///     +--------+--------+--------+--------+
///     |        目标地址（16 字节）          |
///     +--------+--------+--------+--------+
///     |        UDP 长度（4 字节）           |
///     +--------+--------+--------+--------+
///     |  zero  |  zero  |  zero  | next=17 |
///     +--------+--------+--------+--------+
pub fn udp6_checksum(src: &[u8; 16], dst: &[u8; 16], udp_seg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < 16 {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
        i += 2;
    }
    let len = udp_seg.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    sum += 17; // next header = UDP
    let mut k = 0;
    while k + 1 < udp_seg.len() {
        sum += u16::from_be_bytes([udp_seg[k], udp_seg[k + 1]]) as u32;
        k += 2;
    }
    if k < udp_seg.len() {
        sum += u16::from_be_bytes([udp_seg[k], 0]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let ck = !(sum as u16);
    if ck == 0 { 0xffff } else { ck }
}

/// 打一个 IPv6 + UDP 帧（eth 14 + IPv6 40 + UDP 8 + 载荷）。
///
/// 返回帧长度；`None` = 载荷超限或缓冲装不下。
///
/// **不做分片、不处理扩展头**（ADR-182 未决 2）：载荷超 MTU 直接拒，不静默截断。
pub fn build_udp6_frame(
    out: &mut [u8],
    dst_mac: &[u8; 6],
    src_mac: &[u8; 6],
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<usize> {
    let udp_len = 8 + payload.len();
    let total = 14 + IP6_HDR + udp_len;
    if out.len() < total || udp_len > IP6_MIN_MTU {
        return None;
    }
    out[0..6].copy_from_slice(dst_mac);
    out[6..12].copy_from_slice(src_mac);
    out[12..14].copy_from_slice(&NET_TYPE_IPV6);
    let ip = 14;
    // 版本(4) + 流量类(8) + 流标签(20) = 4 字节；版本 6 在最高 4 位
    out[ip] = 0x60;
    out[ip + 1] = 0;
    out[ip + 2] = 0;
    out[ip + 3] = 0;
    // 载荷长度（不含 IPv6 头本身）
    out[ip + 4] = (udp_len >> 8) as u8;
    out[ip + 5] = udp_len as u8;
    out[ip + 6] = 17; // next header = UDP
    out[ip + 7] = 64; // hop limit
    out[ip + 8..ip + 24].copy_from_slice(src_ip);
    out[ip + 24..ip + 40].copy_from_slice(dst_ip);
    // **IPv6 头没有校验和**：ip+40 就是 UDP 起点，中间没有 12 字节的校验和字段。
    let u = ip + IP6_HDR;
    out[u] = (src_port >> 8) as u8;
    out[u + 1] = src_port as u8;
    out[u + 2] = (dst_port >> 8) as u8;
    out[u + 3] = dst_port as u8;
    out[u + 4] = (udp_len >> 8) as u8;
    out[u + 5] = udp_len as u8;
    out[u + 6] = 0;
    out[u + 7] = 0;
    out[u + 8..u + udp_len].copy_from_slice(payload);
    let ck = udp6_checksum(src_ip, dst_ip, &out[u..u + udp_len]);
    out[u + 6] = (ck >> 8) as u8;
    out[u + 7] = ck as u8;
    Some(total)
}

/// 从以太网帧里解出一段 UDP over IPv6。
///
/// 返回 `(源地址, 目标地址, 源端口, 目标端口, 载荷)`。
/// `None` = 不是 IPv6/UDP、有扩展头、或长度不自洽。
///
/// **有扩展头就拒**（ADR-182 未决 2）：扩展头链可以任意长，跳过它的代码
/// 是分片重组的前置，而本轮不做。拒掉比读错安全。
pub fn parse_udp6_frame(
    frame: &[u8],
) -> Option<([u8; 16], [u8; 16], u16, u16, &[u8])> {
    if frame.len() < 14 + IP6_HDR + 8 {
        return None;
    }
    if frame[12..14] != NET_TYPE_IPV6 {
        return None;
    }
    let ip = 14;
    if frame[ip] >> 4 != 6 {
        return None;
    }
    // 只认无扩展头的 UDP（next header = 17）
    if frame[ip + 6] != 17 {
        return None;
    }
    let plen = u16::from_be_bytes([frame[ip + 4], frame[ip + 5]]) as usize;
    if plen < 8 || ip + IP6_HDR + plen > frame.len() {
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&frame[ip + 8..ip + 24]);
    dst.copy_from_slice(&frame[ip + 24..ip + 40]);
    let u = ip + IP6_HDR;
    let udp_len = u16::from_be_bytes([frame[u + 4], frame[u + 5]]) as usize;
    if udp_len < 8 || udp_len > plen {
        return None;
    }
    let sp = u16::from_be_bytes([frame[u], frame[u + 1]]);
    let dp = u16::from_be_bytes([frame[u + 2], frame[u + 3]]);
    Some((src, dst, sp, dp, &frame[u + 8..u + udp_len]))
}

/// 这个帧是不是 IPv4（给双栈收包路径分流用）。
pub fn is_ipv4_frame(frame: &[u8]) -> bool {
    frame.len() >= 14 && frame[12..14] == NET_TYPE_IPV4
}

/// 这个帧是不是 IPv6。
pub fn is_ipv6_frame(frame: &[u8]) -> bool {
    frame.len() >= 14 && frame[12..14] == NET_TYPE_IPV6
}