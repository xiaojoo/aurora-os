//! UDP 打包与解包（ADR-181 决策 1）。
//!
//! ## 为什么单独一个模块
//!
//! `dns.rs` 里那段构造是**硬编码给 DNS 的**（固定 10.0.2.3:53、固定 QNAME 布局）。
//! socket 要发任意对端、任意端口的 UDP，不能复用那份。
//!
//! 但**校验和规则必须与它一致**——两边算得不一样，slirp 会静默丢包，
//! 而"发出去没回音"是最难查的故障形状。所以这里的 `udp_checksum` 与
//! `dns.rs` 用的是同一套算法，且有交叉用例（`t_udp_dns_agree`）。

use crate::network::dhcp::NET_TYPE_IPV4;
use crate::network::ipv4::ip_cksum;

/// IPv4 头长（无选项）。
pub const IP_HDR: usize = 20;
/// UDP 头长。
pub const UDP_HDR: usize = 8;
/// 以太网头长。
pub const ETH_HDR: usize = 14;

/// UDP 数据报的最大载荷（保守取 1472 = 1500 MTU - 20 IP - 8 UDP）。
pub const UDP_PAYLOAD_MAX: usize = 1472;

/// 一个 UDP 端点（地址 + 端口，均为**网络序**的字节形式）。
///
/// 为什么用字节数组而不是 `u32`/`u16`：
/// 收发两个方向都要原样拷进/拷出帧，用字节数组省掉两次 `to_be_bytes`，
/// 也避免"这个 u32 到底是主机序还是网络序"这类错误。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UdpEndpoint {
    pub ip: [u8; 4],
    pub port: u16,
}

impl UdpEndpoint {
    pub const fn new(ip: [u8; 4], port: u16) -> UdpEndpoint {
        UdpEndpoint { ip, port }
    }

    /// 全零 = 未绑定/未连接。
    pub const fn is_zero(&self) -> bool {
        if self.port != 0 {
            return false;
        }
        let mut i = 0;
        while i < 4 {
            if self.ip[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

/// UDP 校验和（含 IPv4 伪首部）。返回 `0xFFFF` 表示"算出来是 0，按 RFC 768 发全 1"。
///
/// ## 伪首部
///
///     +--------+--------+--------+--------+
///     |          源地址（4 字节）          |
///     +--------+--------+--------+--------+
///     |        目标地址（4 字节）          |
///     +--------+--------+--------+--------+
///     |  zero  | proto  |    UDP 长度     |
///     +--------+--------+--------+--------+
///
/// 少算伪首部是 UDP 校验和最常见的错，且症状是"对端静默丢包"。
pub fn udp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], udp_seg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // 伪首部：源 IP + 目标 IP
    for c in src_ip.chunks(2).chain(dst_ip.chunks(2)) {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    // zero + proto(17) + UDP 长度
    sum += 17u32;
    sum += udp_seg.len() as u32;
    // UDP 段本身（校验和字段按 0 参与计算，调用方保证传进来时它是 0）
    let mut i = 0;
    while i + 1 < udp_seg.len() {
        sum += u16::from_be_bytes([udp_seg[i], udp_seg[i + 1]]) as u32;
        i += 2;
    }
    if i < udp_seg.len() {
        sum += u16::from_be_bytes([udp_seg[i], 0]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let ck = !(sum as u16);
    if ck == 0 { 0xffff } else { ck }
}

/// 把一段载荷打成完整的以太网帧（eth + IPv4 + UDP）。
///
/// 返回帧长度；`None` = 载荷超 `UDP_PAYLOAD_MAX` 或缓冲装不下。
///
/// **不做分片**（ADR-181 决策 1 的边界）：超 MTU 的载荷直接拒，不静默截断。
pub fn build_frame(
    out: &mut [u8],
    dst_mac: &[u8; 6],
    src_mac: &[u8; 6],
    src: UdpEndpoint,
    dst: UdpEndpoint,
    payload: &[u8],
) -> Option<usize> {
    if payload.len() > UDP_PAYLOAD_MAX {
        return None;
    }
    let udp_len = UDP_HDR + payload.len();
    let ip_len = IP_HDR + udp_len;
    let total = ETH_HDR + ip_len;
    if out.len() < total {
        return None;
    }
    out[0..6].copy_from_slice(dst_mac);
    out[6..12].copy_from_slice(src_mac);
    out[12..14].copy_from_slice(&NET_TYPE_IPV4);
    // IPv4 头
    let ip = ETH_HDR;
    out[ip] = 0x45;
    out[ip + 1] = 0;
    out[ip + 2] = (ip_len >> 8) as u8;
    out[ip + 3] = ip_len as u8;
    out[ip + 4] = 0;
    out[ip + 5] = 0;
    out[ip + 6] = 0x40; // DF
    out[ip + 7] = 0;
    out[ip + 8] = 64; // TTL
    out[ip + 9] = 17; // UDP
    out[ip + 10] = 0;
    out[ip + 11] = 0;
    out[ip + 12..ip + 16].copy_from_slice(&src.ip);
    out[ip + 16..ip + 20].copy_from_slice(&dst.ip);
    let ck = ip_cksum(&out[ip..ip + IP_HDR]);
    out[ip + 10] = (ck >> 8) as u8;
    out[ip + 11] = ck as u8;
    // UDP 头
    let u = ip + IP_HDR;
    out[u] = (src.port >> 8) as u8;
    out[u + 1] = src.port as u8;
    out[u + 2] = (dst.port >> 8) as u8;
    out[u + 3] = dst.port as u8;
    out[u + 4] = (udp_len >> 8) as u8;
    out[u + 5] = udp_len as u8;
    out[u + 6] = 0;
    out[u + 7] = 0;
    out[u + UDP_HDR..u + udp_len].copy_from_slice(payload);
    // 校验和（此时字段是 0）
    let ck = udp_checksum(&src.ip, &dst.ip, &out[u..u + udp_len]);
    out[u + 6] = (ck >> 8) as u8;
    out[u + 7] = ck as u8;
    Some(total)
}

/// 从以太网帧里解出一段 UDP。
///
/// 返回 `(源, 目标, 载荷切片)`；`None` = 不是 IPv4/UDP、被分片、或长度字段不自洽。
///
/// **不校验 UDP 校验和**：QEMU slirp 发出的包校验和字段可能是 0（表示"未计算"，
/// RFC 768 允许），严格校验会把正常包判成坏的。IP 头校验和照校验——那是强制的。
pub fn parse_frame(frame: &[u8]) -> Option<(UdpEndpoint, UdpEndpoint, &[u8])> {
    if frame.len() < ETH_HDR + IP_HDR + UDP_HDR {
        return None;
    }
    if frame[12..14] != NET_TYPE_IPV4 {
        return None;
    }
    let ip = ETH_HDR;
    if frame[ip] >> 4 != 4 {
        return None;
    }
    let ihl = ((frame[ip] & 0x0f) as usize) * 4;
    if ihl < IP_HDR || frame.len() < ip + ihl + UDP_HDR {
        return None;
    }
    if frame[ip + 9] != 17 {
        return None;
    }
    // 分片：MF 置位或片偏移非 0 都跳过（本轮不做重组）
    let frag = u16::from_be_bytes([frame[ip + 6], frame[ip + 7]]);
    if frag & 0x3fff != 0 {
        return None;
    }
    let ip_total = u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]) as usize;
    if ip_total < ihl + UDP_HDR || ip + ip_total > frame.len() {
        return None;
    }
    let u = ip + ihl;
    let udp_len = u16::from_be_bytes([frame[u + 4], frame[u + 5]]) as usize;
    if udp_len < UDP_HDR || u + udp_len > ip + ip_total {
        return None;
    }
    let src = UdpEndpoint {
        ip: [frame[ip + 12], frame[ip + 13], frame[ip + 14], frame[ip + 15]],
        port: u16::from_be_bytes([frame[u], frame[u + 1]]),
    };
    let dst = UdpEndpoint {
        ip: [frame[ip + 16], frame[ip + 17], frame[ip + 18], frame[ip + 19]],
        port: u16::from_be_bytes([frame[u + 2], frame[u + 3]]),
    };
    Some((src, dst, &frame[u + UDP_HDR..u + udp_len]))
}