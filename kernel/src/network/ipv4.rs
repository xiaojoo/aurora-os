//! IPv4 路由：子网判断、下一跳、从帧里学 ARP。


use crate::network::arp::{NET_GATEWAY_IP};
use crate::network::arp_table::{arp_learn};
use crate::network::dhcp::{DHCP_GUEST_IP};

/// `10.0.2.0/24` 的默认子网掩码——没有 DHCP option 1 时的回退值。
/// 这不是猜的：它是 QEMU `-netdev user,net=10.0.2.0/24` 的参数，与 `DHCP_GUEST_IP`
/// 同一来源；内核不在运行期发明事实，所以在这里给出明确形状。
pub const NET_SUBNET_MASK: [u8; 4] = [255, 255, 255, 0];

/// 路由判据（ADR-147）：`dst` 在不在本子网里？
///
/// 本子网 -> 直接 ARP 目标；外部 -> ARP 网关。掩码两端都可以是 0（没分子网），
/// 那时只有 [同一个 IP] 才算本子网——这是退化而不是"正确"：
/// 掩码 0 的语义有两种读法，这里取「无子网 = 只能自己」这一支。
pub fn is_local_subnet(our_ip: &[u8; 4], mask: &[u8; 4], dst: &[u8; 4]) -> bool {
    let mut i = 0usize;
    while i < 4 {
        let m = match mask.get(i) { Some(v) => *v, None => return false };
        let a = match our_ip.get(i) { Some(v) => *v, None => return false };
        let d = match dst.get(i) { Some(v) => *v, None => return false };
        if (a & m) != (d & m) { return false; }
        i += 1;
    }
    // 全 0 掩码下只有同一个 IP 才算本子网
    if *mask == [0u8; 4] { return *our_ip == *dst; }
    true
}

/// 下一跳（ADR-147）：一个目标地址该去解谁的 MAC。
/// 本子网 -> 目标自己；外部 -> 网关。这就是今天"路由"的全部内容：
/// 一条默认路由，没有路由表、没有最长前缀匹配。
pub fn next_hop(our_ip: &[u8; 4], mask: &[u8; 4], dst: &[u8; 4]) -> [u8; 4] {
    if is_local_subnet(our_ip, mask, dst) { *dst } else { NET_GATEWAY_IP }
}

/// RFC 826 的被动学习（ADR-146）：收到一帧就看它是不是 ARP，
/// 是就把 sender 那一对 (ip, mac) 按 merge 规则归进表。
///
/// **为什么在收帧路径上学**：用户态 `ping` 自己发广播 ARP，
/// 它不会上报——在收帧处被动学，两条 ARP 实现就不再是"各自管自己"。
/// 行为形状与读的是**原帧**（从 eth 头起）：`ethertype==0x0806` 且长度>=42。
/// 不管是 request 还是 reply：两者的 sender 字段在同一个偏移上。
/// 返回 `true` = 这一帧认真被学了（判据读数）。
pub fn arp_learn_from_frame(f: &[u8]) -> bool {
    if f.len() < 42 { return false; }
    // ethertype 在 12..14；ARP 是 0x0806
    if f[12] != 0x08 || f[13] != 0x06 { return false; }
    // 验证前提：htype=1(Ethernet)、ptype=0x0800(IPv4)、hlen=6、plen=4
    if f[14] != 0 || f[15] != 1 { return false; }
    if f[16] != 0x08 || f[17] != 0x00 { return false; }
    if f[18] != 6 || f[19] != 4 { return false; }
    let mut ip = [0u8; 4];
    ip.copy_from_slice(&f[28..32]);
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&f[22..28]);
    // 全零 sender 不学（那是探针/未初始化的形状）
    if mac == [0u8; 6] || ip == [0u8; 4] { return false; }
    // 不学自己（自己的 IP/MAC 不是"邻居"）
    if ip == DHCP_GUEST_IP { return false; }
    arp_learn(&ip, &mac);
    true
}

/// **放在这里而不是 `dhcp.rs`**：`dhcp`/`dns`/`icmp` 三个协议都要构造 IP 头、
/// 都要用它。拆分时按行号切把它切进了 `dhcp`，分类不对——它属 IPv4 层。
/// 下沉之后 `ipv4` 不依赖任何人（纯算术），三个协议各自 `use` 它。
/// IPv4 首部校验和：16 位一步的反码和，进位回卷后取反
pub fn ip_cksum(b: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0usize;
    while i + 1 < b.len() {
        sum += u32::from(u16::from_be_bytes([b[i], b[i + 1]]));
        i += 2;
    }
    if i < b.len() {
        sum += u32::from(b[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
