//! ICMP（RFC 792）：echo request 构造与 reply 解析。



use crate::network::arp::{NET_GATEWAY_IP};
use crate::network::dhcp::{NET_TYPE_IPV4};
use crate::network::eth::{NET_FRAME_BYTES, NET_TX_MAX, frame_hash};
use crate::network::ipv4::{ip_cksum};
use crate::network::NetError;

// ---------------------------------------------------------------- B2 第二刀（ADR-140）：ICMP echo
/// ICMP 的几个号（RFC 792）。ping 的对象 = slirp 网关（10.0.2.2，与 ARP 同一个对端）。
pub const NET_TYPE_ICMP: [u8; 2] = [0x08, 0x00];
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_ECHO_ID: u16 = 0xA5A5;
pub const ICMP_PAYLOAD: [u8; 16] = [0xA5; 16];
/// ICMP 帧总长 = eth 14 + IPv4 20 + ICMP 头 4 + payload 16，垫到最小帧 60。
pub const ICMP_FRAME_BYTES: usize = NET_FRAME_BYTES;
const _: () = assert!(ICMP_FRAME_BYTES <= NET_TX_MAX);

/// ICMP 段的校验和：与 `ip_cksum` 同一条 16 位反码和（ICMP 校验和覆盖整个 ICMP 段）。
fn icmp_cksum(seg: &[u8]) -> u16 {
    ip_cksum(seg)
}

/// 构造一个 ICMP echo request：单播给 `gw_mac`（上一刀 ARP 拿到的网关 MAC，
/// **从线上读的而不是硬编码**），问网关。返回帧与自算哈希。
pub fn build_icmp_echo_request(
    gw_mac: &[u8; 6],
    our_mac: &[u8; 6],
    our_ip: &[u8; 4],
    seq: u16,
) -> ([u8; ICMP_FRAME_BYTES], u64) {
    let mut f = [0u8; ICMP_FRAME_BYTES];
    f[0..6].copy_from_slice(gw_mac);            // 单播：ARP 已把网关的 MAC 解出来了
    f[6..12].copy_from_slice(our_mac);
    f[12..14].copy_from_slice(&NET_TYPE_IPV4);
    let ip_len = 20 + 4 + ICMP_PAYLOAD.len();   // IPv4 头 + ICMP 段
    f[14] = 0x45;
    f[16] = (ip_len >> 8) as u8;
    f[17] = ip_len as u8;
    f[18] = 0; f[19] = 1;                       // 标识/seq：单发就 0/1
    f[20] = 0x40;                               // DF
    f[22] = 64;                                 // TTL
    f[23] = 1;                                  // protocol = ICMP
    f[26..30].copy_from_slice(our_ip);           // 源地址（IPv4 头的 26..30）
    f[30..34].copy_from_slice(&NET_GATEWAY_IP); // 目的地址（IPv4 头的 30..34） // 单播目标 = 网关
    let ck = ip_cksum(&f[14..34]);
    f[24] = (ck >> 8) as u8;
    f[25] = ck as u8;
    let ic = 14 + 20;                           // ICMP 段起点
    f[ic] = ICMP_ECHO_REQUEST;
    f[ic + 1] = 0;                              // code
    // 校验和先置零再算整段
    f[ic + 2] = 0; f[ic + 3] = 0;
    f[ic + 4..ic + 6].copy_from_slice(&ICMP_ECHO_ID.to_be_bytes());
    f[ic + 6..ic + 8].copy_from_slice(&seq.to_be_bytes());
    f[ic + 8..ic + 8 + ICMP_PAYLOAD.len()].copy_from_slice(&ICMP_PAYLOAD);
    let seg_len = 4 + ICMP_PAYLOAD.len();
    let cks = icmp_cksum(&f[ic..ic + seg_len]);
    f[ic + 2] = (cks >> 8) as u8;
    f[ic + 3] = cks as u8;
    let h = crate::network::eth::frame_hash(&f);
    (f, h)
}

/// 收到的 ICMP echo reply 里能拿出来的事实。字段全从**收到的字节**里读。
#[derive(Clone, Copy, Debug)]
pub struct IcmpReply {
    pub len: usize,
    pub hash: u64,
    pub icmp_type: u8,
    pub icmp_id: u16,
    pub icmp_seq: u16,
    pub src_ip: [u8; 4],
    pub used_idx: u16,
    pub used_len: u32,
    pub used_id: u32,
}

/// 解一包 ICMP echo reply：ethertype=0x0800、protocol=1、type=0。
/// 每处切片先验长度（`parse_reply` 同条：线上的数不能直接当界用）。
pub fn parse_icmp_reply(buf: &[u8], used_idx: u16, used_len: u32, used_id: u32) -> Result<IcmpReply, NetError> {
    if buf.len() < 14 + 20 + 4 || buf[12] != NET_TYPE_IPV4[0] || buf[13] != NET_TYPE_IPV4[1] {
        return Err(NetError::NotV4 { at: buf.len(), guard: 1 });
    }
    let ihl = usize::from(buf[14] & 0x0F) * 4;
    if ihl < 20 || buf[14 + 9] != 1 || buf.len() < 14 + ihl + 4 {
        return Err(NetError::NotV4 { at: buf.len(), guard: 2 });
    }
    let ic = 14 + ihl;
    if buf[ic] != ICMP_ECHO_REPLY {
        return Err(NetError::NotV4 { at: buf.len(), guard: 3 });
    }
    let mut src_ip = [0u8; 4];
    src_ip.copy_from_slice(&buf[14 + 12..14 + 16]);
    Ok(IcmpReply {
        len: used_len as usize,
        hash: crate::network::eth::frame_hash(&buf[..(used_len as usize).min(buf.len())]),
        icmp_type: buf[ic],
        icmp_id: u16::from_be_bytes([buf[ic + 4], buf[ic + 5]]),
        icmp_seq: u16::from_be_bytes([buf[ic + 6], buf[ic + 7]]),
        src_ip,
        used_idx,
        used_len,
        used_id,
    })
}
