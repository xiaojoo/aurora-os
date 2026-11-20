//! ARP（RFC 826）：帧构造与解析。


use crate::network::dhcp::{DHCP_GUEST_IP};
use crate::network::eth::{NET_DST, NET_FRAME_BYTES, NET_TX_MAX, frame_hash};
use crate::network::NetError;

// ---------------------------------------------------------------- B2 第一刀（ADR-139）：ARP
/// ARP 的几个号（RFC 826）。网关 IP 是 QEMU 用户网络（slirp）的默认网关 10.0.2.2，
/// 我们自己的地址是 DHCP 夹具里那个 10.0.2.15（`DHCP_GUEST_IP`，同源对账）。
pub const NET_TYPE_ARP: [u8; 2] = [0x08, 0x06];
pub const ARP_HTYPE_ETH: u16 = 1;
pub const ARP_PTYPE_IPV4: u16 = 0x0800;
pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;
pub const ARP_LEN: usize = 28;
/// slirp 的默认网关：ARP request 问它，reply 的 sender_ip 必须等于它。
pub const NET_GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
/// ARP 帧总长 = eth 头 14 + ARP 主体 28，再垫到最小帧 60（`NET_FRAME_BYTES` 同一条：
/// 以太网最小帧 64 减 FCS，短了硬件补零——我们发满 60，省得依赖设备的补零形状）。
pub const ARP_FRAME_BYTES: usize = NET_FRAME_BYTES;
const _: () = assert!(ARP_FRAME_BYTES <= NET_TX_MAX);

/// 构造一个 ARP request：广播"谁是 10.0.2.2？告诉 10.0.2.15"。
/// 判据读数自证：`sender_mac` 填我们自己的 MAC（回话那一头会拿它把 reply 寄回来），
/// 其余字段按 RFC 826 的形状。返回帧与自算哈希（与 `build_dhcp_discover` 同一形状）。
pub fn build_arp_request(mac: &[u8; 6]) -> ([u8; ARP_FRAME_BYTES], u64) {
    let mut f = [0u8; ARP_FRAME_BYTES];
    f[0..6].copy_from_slice(&NET_DST);          // 广播：还不知道网关的 MAC，这正是 ARP 要问的
    f[6..12].copy_from_slice(mac);
    f[12..14].copy_from_slice(&NET_TYPE_ARP);
    f[14..16].copy_from_slice(&ARP_HTYPE_ETH.to_be_bytes());
    f[16..18].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
    f[18] = 6;  // hlen：以太网 MAC 6 字节
    f[19] = 4;  // plen：IPv4 4 字节
    f[20..22].copy_from_slice(&ARP_REQUEST.to_be_bytes());
    f[22..28].copy_from_slice(mac);              // sender hardware address
    f[28..32].copy_from_slice(&DHCP_GUEST_IP);   // sender protocol address：我们自己
    // target hardware address 全 0（还不知道，问的就是它）
    f[38..42].copy_from_slice(&NET_GATEWAY_IP);  // target protocol address：网关
    let h = crate::network::eth::frame_hash(&f);
    (f, h)
}

/// 收到的 ARP reply 里能拿出来的事实。字段全从**收到的字节**里读。
#[derive(Clone, Copy, Debug)]
pub struct ArpReply {
    pub len: usize,
    pub hash: u64,
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_ip: [u8; 4],
    pub used_idx: u16,
    pub used_len: u32,
    pub used_id: u32,
}

/// 解一包 ARP reply：ethertype=0x0806、opcode=2，字段按 RFC 826 的布局。
/// 每一处切片先验长度（`parse_reply` 同一条：线上的数不能直接当界用）。
pub fn parse_arp_reply(buf: &[u8], used_idx: u16, used_len: u32, used_id: u32) -> Result<ArpReply, NetError> {
    if buf.len() < 14 + ARP_LEN || buf[12] != NET_TYPE_ARP[0] || buf[13] != NET_TYPE_ARP[1] {
        return Err(NetError::NotV4 { at: buf.len(), guard: 1 });
    }
    let opcode = u16::from_be_bytes([buf[20], buf[21]]);
    if opcode != ARP_REPLY {
        return Err(NetError::NotV4 { at: buf.len(), guard: 2 });
    }
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&buf[22..28]);
    let mut sender_ip = [0u8; 4];
    sender_ip.copy_from_slice(&buf[28..32]);
    let mut target_ip = [0u8; 4];
    target_ip.copy_from_slice(&buf[38..42]);
    Ok(ArpReply {
        len: used_len as usize,
        // used_len 是设备写的数，线上的数不能直接当界用（.3：它可以超出我们挂的缓冲）⇒ 夹到 buf.len()。
        hash: crate::network::eth::frame_hash(&buf[..(used_len as usize).min(buf.len())]),
        opcode,
        sender_mac,
        sender_ip,
        target_ip,
        used_idx,
        used_len,
        used_id,
    })
}
