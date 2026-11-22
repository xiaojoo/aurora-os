//! 邻居发现（NDP，RFC 4861）—— IPv6 的「ARP 替代品」（ADR-182 决策 3）。
//!
//! ## 与 ARP 的三个关键差异
//!
//! | 项 | ARP | NDP |
//! |---|---|---|
//! | 承载 | 独立的以太网类型 `0x0806` | **ICMPv6**（`0x86DD` + next=58）|
//! | 目标 | 广播 `FF:FF:FF:FF:FF:FF` | **被请求节点组播**（精确得多）|
//! | 地址 | 32 位 | 128 位（选项里带，长度可变）|
//!
//! 第二条是 NDP 比 ARP 好的地方：只有真正关心那个地址的节点会收到，
//! 而不是整个广播域。

use crate::network::ipv6::{
    solicited_node_multicast, IP6_ADDR_LEN, IP6_HDR, NET_TYPE_IPV6,
};

/// ICMPv6 的下一头部值（RFC 4443）。
pub const NEXT_HEADER_ICMPV6: u8 = 58;

/// 邻居请求（RFC 4861 §4.3）。
pub const ICMPV6_NS: u8 = 135;
/// 邻居通告（§4.4）。
pub const ICMPV6_NA: u8 = 136;

/// 选项类型：源链路层地址（§4.6.1）。
pub const OPT_SRC_LLADDR: u8 = 1;
/// 选项类型：目标链路层地址（§4.6.1）。
pub const OPT_TGT_LLADDR: u8 = 2;

/// 一个 NS/NA 帧的固定长度：
///
///     eth 14 + IPv6 40 + ICMPv6 24（type/code/cksum + reserved + target）+ 选项 8
///
/// 选项 8 = 类型 1 + 长度 1 + MAC 6。
pub const NDP_FRAME_BYTES: usize = 14 + IP6_HDR + 24 + 8;

/// 算 ICMPv6 校验和（含 IPv6 伪首部，RFC 8200 §8.1）。
///
/// **IPv6 上 ICMPv6 的校验和是强制的**（IPv4 的 ICMP 也是，但 IPv6 没有头校验和，
/// 所以这个值更关键：算错 = 对端静默丢弃）。
fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], msg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < 16 {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
        i += 2;
    }
    let len = msg.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    sum += NEXT_HEADER_ICMPV6 as u32;
    let mut k = 0;
    while k + 1 < msg.len() {
        sum += u16::from_be_bytes([msg[k], msg[k + 1]]) as u32;
        k += 2;
    }
    if k < msg.len() {
        sum += u16::from_be_bytes([msg[k], 0]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 打一个邻居请求（NS）。
///
/// 目标 IP 是**被请求节点组播**（`ff02::1:ffXX:XXXX`），不是广播——
/// 目标 MAC 则是这个组播地址对应的 `33:33:ff:XX:XX:XX`（RFC 2464 §7）。
pub fn build_ns(
    out: &mut [u8],
    our_mac: &[u8; 6],
    our_ip: &[u8; 16],
    target_ip: &[u8; 16],
) -> Option<usize> {
    if out.len() < NDP_FRAME_BYTES {
        return None;
    }
    let dst_ip = solicited_node_multicast(target_ip);
    // 组播 MAC：33:33 + 地址后 32 位
    let mut dst_mac = [0x33u8, 0x33, 0, 0, 0, 0];
    dst_mac[2] = dst_ip[12];
    dst_mac[3] = dst_ip[13];
    dst_mac[4] = dst_ip[14];
    dst_mac[5] = dst_ip[15];
    out[0..6].copy_from_slice(&dst_mac);
    out[6..12].copy_from_slice(our_mac);
    out[12..14].copy_from_slice(&NET_TYPE_IPV6);
    let ip = 14;
    // 载荷 = ICMPv6 24 + 选项 8 = 32
    let payload_len = 24 + 8;
    out[ip] = 0x60;
    out[ip + 1] = 0;
    out[ip + 2] = 0;
    out[ip + 3] = 0;
    out[ip + 4] = (payload_len >> 8) as u8;
    out[ip + 5] = payload_len as u8;
    out[ip + 6] = NEXT_HEADER_ICMPV6;
    out[ip + 7] = 255; // hop limit 必须是 255（RFC 4861 §7.1.1 强制）
    out[ip + 8..ip + 24].copy_from_slice(our_ip);
    out[ip + 24..ip + 40].copy_from_slice(&dst_ip);
    let m = ip + IP6_HDR;
    out[m] = ICMPV6_NS;
    out[m + 1] = 0;
    out[m + 2] = 0;
    out[m + 3] = 0;
    out[m + 4..m + 8].copy_from_slice(&[0, 0, 0, 0]); // reserved
    out[m + 8..m + 24].copy_from_slice(target_ip);
    // 源链路层地址选项
    let o = m + 24;
    out[o] = OPT_SRC_LLADDR;
    out[o + 1] = 1; // 长度单位是 8 字节
    out[o + 2..o + 8].copy_from_slice(our_mac);
    let ck = icmpv6_checksum(our_ip, &dst_ip, &out[m..m + payload_len]);
    out[m + 2] = (ck >> 8) as u8;
    out[m + 3] = ck as u8;
    Some(NDP_FRAME_BYTES)
}

/// 打一个邻居通告（NA）。
///
/// `solicited` = 这是对某个 NS 的直接应答（此时目标 IP 是请求方的单播地址）；
/// `override` = 允许对方覆盖已有的缓存项。
pub fn build_na(
    out: &mut [u8],
    our_mac: &[u8; 6],
    our_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    dst_mac: &[u8; 6],
    target_ip: &[u8; 16],
    solicited: bool,
) -> Option<usize> {
    if out.len() < NDP_FRAME_BYTES {
        return None;
    }
    out[0..6].copy_from_slice(dst_mac);
    out[6..12].copy_from_slice(our_mac);
    out[12..14].copy_from_slice(&NET_TYPE_IPV6);
    let ip = 14;
    let payload_len = 24 + 8;
    out[ip] = 0x60;
    out[ip + 1] = 0;
    out[ip + 2] = 0;
    out[ip + 3] = 0;
    out[ip + 4] = (payload_len >> 8) as u8;
    out[ip + 5] = payload_len as u8;
    out[ip + 6] = NEXT_HEADER_ICMPV6;
    out[ip + 7] = 255;
    out[ip + 8..ip + 24].copy_from_slice(our_ip);
    out[ip + 24..ip + 40].copy_from_slice(dst_ip);
    let m = ip + IP6_HDR;
    out[m] = ICMPV6_NA;
    out[m + 1] = 0;
    out[m + 2] = 0;
    out[m + 3] = 0;
    // flags：R(0x80) S(0x40) O(0x20)
    let mut flags = 0x20u8; // override
    if solicited {
        flags |= 0x40;
    }
    out[m + 4] = flags;
    out[m + 5] = 0;
    out[m + 6] = 0;
    out[m + 7] = 0;
    out[m + 8..m + 24].copy_from_slice(target_ip);
    let o = m + 24;
    out[o] = OPT_TGT_LLADDR;
    out[o + 1] = 1;
    out[o + 2..o + 8].copy_from_slice(our_mac);
    let ck = icmpv6_checksum(our_ip, dst_ip, &out[m..m + payload_len]);
    out[m + 2] = (ck >> 8) as u8;
    out[m + 3] = ck as u8;
    Some(NDP_FRAME_BYTES)
}

/// 一个解析出来的 NS/NA。
pub struct NdMessage {
    /// 135 = NS，136 = NA。
    pub kind: u8,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    /// 报文里的 target 地址。
    pub target: [u8; 16],
    /// 报文里的链路层地址选项（没有则 `None`）。
    pub lladdr: Option<[u8; 6]>,
    /// NA 的 flags（NS 恒 0）。
    pub flags: u8,
}

/// 解析一个 NS/NA。
///
/// `None` = 不是 ICMPv6 NS/NA、有扩展头、或长度不自洽。
///
/// **hop limit 必须等于 255**（RFC 4861 §7.1.1）：小于 255 说明包被路由器转发过，
/// 而 NDP 是链路本地的协议——转发过的 NDP 一定是伪造或误配。
pub fn parse_nd(frame: &[u8]) -> Option<NdMessage> {
    if frame.len() < 14 + IP6_HDR + 24 {
        return None;
    }
    if frame[12..14] != NET_TYPE_IPV6 {
        return None;
    }
    let ip = 14;
    if frame[ip] >> 4 != 6 || frame[ip + 6] != NEXT_HEADER_ICMPV6 {
        return None;
    }
    if frame[ip + 7] != 255 {
        return None;
    }
    let plen = u16::from_be_bytes([frame[ip + 4], frame[ip + 5]]) as usize;
    if plen < 24 || ip + IP6_HDR + plen > frame.len() {
        return None;
    }
    let m = ip + IP6_HDR;
    let kind = frame[m];
    if kind != ICMPV6_NS && kind != ICMPV6_NA {
        return None;
    }
    let mut src_ip = [0u8; 16];
    let mut dst_ip = [0u8; 16];
    let mut target = [0u8; 16];
    src_ip.copy_from_slice(&frame[ip + 8..ip + 24]);
    dst_ip.copy_from_slice(&frame[ip + 24..ip + 40]);
    target.copy_from_slice(&frame[m + 8..m + 24]);
    let flags = if kind == ICMPV6_NA { frame[m + 4] } else { 0 };
    // 扫选项（每条：类型 1 + 长度 1 + 内容）
    let mut lladdr = None;
    let mut p = m + 24;
    let end = m + plen;
    while p + 2 <= end {
        let otype = frame[p];
        let olen = usize::from(frame[p + 1]) * 8;
        if olen == 0 || p + olen > end {
            break;
        }
        if (otype == OPT_SRC_LLADDR || otype == OPT_TGT_LLADDR) && olen >= 8 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&frame[p + 2..p + 8]);
            lladdr = Some(mac);
        }
        p += olen;
    }
    Some(NdMessage { kind, src_ip, dst_ip, target, lladdr, flags })
}

/// 这个地址是不是「所有节点」组播（`ff02::1`）。
///
/// 是的话不能拿它当单播目标发 NA——那会变成一个通告打给所有人。
pub fn is_all_nodes(addr: &[u8; 16]) -> bool {
    let mut i = 0;
    while i < IP6_ADDR_LEN {
        let expect = if i == 0 { 0xFF } else if i == 1 { 0x02 } else if i == 15 { 0x01 } else { 0 };
        if addr[i] != expect {
            return false;
        }
        i += 1;
    }
    true
}