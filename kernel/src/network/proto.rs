//! 网络协议层实现（ADR-166 决策 1 的第一刀）。
//!
//! **全部是纯函数**：吃 `&[u8]` 与几个读数，吐解析结果或 `NetError`。不碰设备、
//! 不取锁、不分配。收发由 `driver` 域的网卡驱动负责（依赖方向 `network → driver`）。
//!
//! 这一版**整块搬**而不是一次拆成 7 个文件：这些函数互相引用
//! （`build_dns_query` 用 MAC 布局、`parse_reply` 用 `ip_cksum`、
//! `arp_learn_from_frame` 用 `NET_TYPE_ARP`），一次拆 7 个要同时改几十处 `use`，
//! 出错面比收益大。**先证明「搬出去能编、判据不变」，再按文件细分**——两步分开，
//! 各自可验证。下一步的机械工作见 ADR-166 的表。

use crate::network::NetError;

// ---- 帧布局常量（ADR-166：从 `driver/virtio.rs` 下沉到这一层）----
//
// 这 8 个是**协议概念**（帧怎么排、载荷怎么算），不属驱动层。下沉之后
// 依赖方向才是 `driver → network` 单向；之前 `network` 反过来 `use driver`
// 拿这两个常量，与 `driver` 的重导出凑成双向边 ⇒ `network` 进了环 A。
// **环消失是分类变对的结果，不是目的。**
pub const NET_TYPE: [u8; 2] = [0x88, 0xB5]; // IEEE 802 Local Experimental：不冒认任何协议
pub const NET_DST: [u8; 6] = [0xFF; 6]; // 广播：还没有邻居，也不需要邻居就能上线
pub const NET_HEAD_BYTES: usize = 6 + 6 + 2;
pub const NET_FRAME_BYTES: usize = 60; // ethernet 最小帧（64 减掉 FCS，硬件补 FCS）
pub const NET_PAYLOAD_BYTES: usize = NET_FRAME_BYTES - NET_HEAD_BYTES;
pub const NET_MUL: u32 = 11;
pub const NET_ADD: u32 = 0xA5;
pub const NET_XOR: u32 = 0x5C;

/// 一次能发的最大帧长（驱动侧也 `pub use` 它，供既有调用点保持路径不变）。
pub const NET_TX_MAX: usize = 1514;


/// 一次能发的最大帧长：一个标准 ethernet 帧（不带 FCS）的上限。
/// 帧体与三段环共用一块连续 DMA，所以这条还受"帧体之后剩下多少"限制——那条不变量写在下面
/// 的编译期断言里，不靠我每次手工量。

/// IPv4/UDP/BOOTP 的那几个号，与夹具里 `dhcpstart=` 那一个 IP：内核与 `tools/aurora.py`
/// 各写一份，由 `check-net-pattern` 逐字对账（对端答不答这两个数，两边说的必须是同一件事）
pub const NET_TYPE_IPV4: [u8; 2] = [0x08, 0x00];
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_XID: u32 = 0xA5A5_1234;
/// 夹具里 `dhcpstart=10.0.2.15` 那一个数：内核从线上读回来的 `yiaddr` 必须等于它
pub const DHCP_GUEST_IP: [u8; 4] = [10, 0, 2, 15];
/// magic cookie：`0x63825363` = 99,130,83,99（RFC 2131 定下来的那四个字节）。
/// 我第一版把它凭记忆写成 99,130,131,15 —— 对端照样答了（slirp 不校验入站的 cookie），
/// 所以这条只能靠**对端自己写下来的那四个字节**来纠正：真机上的服务器会直接丢掉这一份请求。
pub const DHCP_MAGIC: [u8; 4] = [99, 130, 83, 99];
pub const OPT_MSG_TYPE: u8 = 53;
/// DHCP option 1：子网掩码（ADR-147 的路由判据）。
pub const OPT_SUBNET_MASK: u8 = 1;
/// DHCP option 3：路由器列表（取第一个 = 默认网关）。
pub const OPT_ROUTER: u8 = 3;
pub const OPT_END: u8 = 255;
pub const OPT_PAD: u8 = 0;
pub const BOOTREQUEST: u8 = 1;
pub const BOOTREPLY: u8 = 2;
pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_ACK: u8 = 5;

/// BOOTP：固定段到 236，`magic` 在 236，options 从 240 起
const BOOTP_OFF: usize = 14 + 20 + 8;
const BOOTP_OPT: usize = 240;

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
    let h = crate::ahci::fnv1a64(&f);
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
        hash: crate::ahci::fnv1a64(&buf[..(used_len as usize).min(buf.len())]),
        opcode,
        sender_mac,
        sender_ip,
        target_ip,
        used_idx,
        used_len,
        used_id,
    })
}
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
    let h = crate::ahci::fnv1a64(&f);
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
        hash: crate::ahci::fnv1a64(&buf[..(used_len as usize).min(buf.len())]),
        icmp_type: buf[ic],
        icmp_id: u16::from_be_bytes([buf[ic + 4], buf[ic + 5]]),
        icmp_seq: u16::from_be_bytes([buf[ic + 6], buf[ic + 7]]),
        src_ip,
        used_idx,
        used_len,
        used_id,
    })
}
// ---------------------------------------------------------------- B2 第三刀（ADR-141）：UDP 往返（DNS 查询）
/// DNS 的几个号（RFC 1035）。slirp 的 DNS 服务器是固定的 10.0.2.3（QEMU 用户网络约定），
/// 它把查询转发给宿主机的 DNS——回的是真 DNS 服务器的话。
pub const NET_DNS_IP: [u8; 4] = [10, 0, 2, 3];
pub const DNS_CLIENT_PORT: u16 = 53;
/// 查询的源端口：非特权（实测 源端端口 0 时 slirp 回 ICMP Port Unreachable）
pub const DNS_QUERY_PORT: u16 = 1053;

// ---------------------------------------------------------------- B2 第四刀（ADR-142）：ARP 缓存
/// ARP 缓存（RFC 826 的"merge" 规则）：每次单播前先查表，miss 才广播。
/// **无堆、固定 8 项、线性查找**（不引堆、不引哈希）。`hits`/`misses` 是判据读数。
pub const ARP_TABLE_MAX: usize = 8;
pub struct ArpStats {
    pub hits: u32,
    pub misses: u32,
    pub learns: u32,
    pub evicts: u32,
}
static ARP_TABLE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0); // 0=未初始化 1=已初始化
struct ArpTable {
    // 线性数组，`ips[i]==0` 表示空槽（IP 0.0.0.0 不会是合法邻居）
    ips: [[u8; 4]; ARP_TABLE_MAX],
    macs: [[u8; 6]; ARP_TABLE_MAX],
    n: usize,
    hits: u32,
    misses: u32,
    learns: u32,
    evicts: u32,
}
struct ArpCell(core::cell::UnsafeCell<ArpTable>);
unsafe impl Sync for ArpCell {}
static ARP: ArpCell = ArpCell(core::cell::UnsafeCell::new(ArpTable {
    ips: [[0; 4]; ARP_TABLE_MAX],
    macs: [[0; 6]; ARP_TABLE_MAX],
    n: 0, hits: 0, misses: 0, learns: 0, evicts: 0,
}));

/// 查缓存。hit ⇒ MAC，miss ⇒ None（调用方广播）。
pub fn arp_lookup(ip: &[u8; 4]) -> Option<[u8; 6]> {
    // SAFETY: 见 `bn` 同款-- 单核初期内核、调用点都在内核串行上下文，无并发写。
    let t = unsafe { &mut *ARP.0.get() };
    let mut i = 0usize;
    while i < t.n {
        if t.ips[i] == *ip {
            t.hits += 1;
            return Some(t.macs[i]);
        }
        i += 1;
    }
    t.misses += 1;
    None
}

/// 学一条（ARP reply 的 sender）。已有则覆盖（RFC 826 merge），满则挤第一条（FIFO，最简而且测得出）。
pub fn arp_learn(ip: &[u8; 4], mac: &[u8; 6]) {
    // SAFETY: 同 `arp_lookup`。
    let t = unsafe { &mut *ARP.0.get() };
    t.learns += 1;
    let mut i = 0usize;
    while i < t.n {
        if t.ips[i] == *ip {
            t.macs[i] = *mac;
            return;
        }
        i += 1;
    }
    if t.n < ARP_TABLE_MAX {
        t.ips[t.n] = *ip;
        t.macs[t.n] = *mac;
        t.n += 1;
        return;
    }
    t.evicts += 1;
    // 满表：挤第 0 条，其余前移（FIFO）。
    let mut k = 0usize;
    while k + 1 < ARP_TABLE_MAX {
        t.ips[k] = t.ips[k + 1];
        t.macs[k] = t.macs[k + 1];
        k += 1;
    }
    t.ips[ARP_TABLE_MAX - 1] = *ip;
    t.macs[ARP_TABLE_MAX - 1] = *mac;
}

/// 缓存读数（判据用）。
pub fn arp_stats() -> ArpStats {
    // SAFETY: 同 `arp_lookup`。
    let t = unsafe { &*ARP.0.get() };
    ArpStats { hits: t.hits, misses: t.misses, learns: t.learns, evicts: t.evicts }
}

/// `arp_stats` 的同族入口：按游标把**表项**读出来（ADR-145：`ip neigh` 的读数通道）。
/// 每条**定长 10 字节**：IP4 + MAC6，紧排写到 `out`。
/// 返回写入的条数；`cursor` 超过表长时返 0（分页的终点）。
pub fn arp_read_from(cursor: u32, out: &mut [u8]) -> usize {
    // SAFETY: 同 `arp_lookup`。
    let t = unsafe { &*ARP.0.get() };
    let mut n = 0usize;
    let mut i = cursor as usize;
    while i < t.n && (n + 1) * 10 <= out.len() {
        let at = n * 10;
        out[at..at + 4].copy_from_slice(&t.ips[i]);
        out[at + 4..at + 10].copy_from_slice(&t.macs[i]);
        n += 1;
        i += 1;
    }
    n
}

/// 表里当前有多少项（`ip neigh` 分页的上界）。
pub fn arp_len() -> u32 {
    // SAFETY: 同 `arp_lookup`。
    let t = unsafe { &*ARP.0.get() };
    t.n as u32
}


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
pub const DNS_QTYPE_A: u16 = 1;
pub const DNS_QCLASS_IN: u16 = 1;
/// DNS 帧总长 = eth 14 + IPv4 20 + UDP 8 + DNS 查询（问 localhost），垫到 60。
/// 问 localhost：slirp 的 DNS 对它有本地答案（127.0.0.1），**不依赖外网**。
/// **DNS 查询超最小帧**（ARP/ICMP 的 60 字节装不下）：
/// eth 14 + IPv4 20 + UDP 8 + DNS 头 12 + QNAME 11 + QT/QC 4 = 69，垫到 72。
/// 帧长按内容算，不再套“60 字节”的模板——那条只对最小帧成立。
pub const DNS_FRAME_BYTES: usize = 72;
const _: () = assert!(DNS_FRAME_BYTES <= NET_TX_MAX);

/// 构造一个 DNS A 查询（问 localhost）：单播给 DNS 服务器 10.0.2.3，
/// MAC 用 ARP 解出来的网关（发到别的子网一样先解网关）。
pub fn build_dns_query(gw_mac: &[u8; 6], our_mac: &[u8; 6], our_ip: &[u8; 4], txid: u16)
    -> ([u8; DNS_FRAME_BYTES], u64) {
    build_dns_query_name(gw_mac, our_mac, our_ip, txid, b"localhost")
}

/// ADR-158：**名字参数化**的 DNS 查询构造（`nslookup <name>` 的前置）。
///
/// `name` 是点分域名（`example.com`），长度上限 [`DNS_NAME_MAX`]。
/// **编码成 DNS 的「长度前置」格式**（`\x07example\x03com\x00`）——
/// 第一版硬编码 `\x09localhost\x00`，只认一个名字，不能做 `nslookup`。
pub fn build_dns_query_name(
    gw_mac: &[u8; 6],
    our_mac: &[u8; 6],
    our_ip: &[u8; 4],
    txid: u16,
    name: &[u8],
) -> ([u8; DNS_FRAME_BYTES], u64) {
    let mut f = [0u8; DNS_FRAME_BYTES];
    f[0..6].copy_from_slice(gw_mac);
    f[6..12].copy_from_slice(our_mac);
    f[12..14].copy_from_slice(&NET_TYPE_IPV4);
    // 把 `name` 编成 DNS 的「长度前置」格式（RFC 1035 §3.1）。
    // **原地编进一个定长缓冲**：`DNS_NAME_MAX` 字节够 `a.b.c.d` 四级。
    // 编码失败（空名 / 有连续点 / 某段超 63）⇒ 退回 `localhost`，
    // 由调用方从应答里看不出"名字被换过"——所以**返回值里的 hash 会不同**，
    // 那是调用方能察觉的唯一信号（ADR-158 未决 1）。
    let mut namebuf = [0u8; DNS_NAME_MAX];
    let nlen = encode_dns_name(name, &mut namebuf);
    let dns_name: &[u8] = if nlen == 0 {
        b"\x09localhost\x00"
    } else {
        namebuf.get(..nlen).unwrap_or(b"\x09localhost\x00")
    };
    let ip_len = 20 + 8 + 12 + dns_name.len() + 4;
    f[14] = 0x45;
    f[16] = (ip_len >> 8) as u8;
    f[17] = ip_len as u8;
    f[19] = 1;
    f[20] = 0x40;
    f[22] = 64;
    f[23] = 17;                                   // protocol = UDP
    f[26..30].copy_from_slice(our_ip);
    f[30..34].copy_from_slice(&NET_DNS_IP);
    let ck = ip_cksum(&f[14..34]);
    f[24] = (ck >> 8) as u8;
    f[25] = ck as u8;
    let u = 14 + 20;                              // UDP 段起点
    f[u] = (DNS_QUERY_PORT >> 8) as u8; f[u+1] = DNS_QUERY_PORT as u8; // 源端口：**非特权**（实测 源端 0 时 slirp 回 ICMP Port Unreachable）
    f[u+2] = (DNS_CLIENT_PORT >> 8) as u8;
    f[u+3] = DNS_CLIENT_PORT as u8;               // 目标 = 53
    let udp_len = 8 + 12 + dns_name.len() + 4;
    f[u+4] = (udp_len >> 8) as u8;
    f[u+5] = udp_len as u8;
    let d = u + 8;                                // DNS 段起点
    f[d] = (txid >> 8) as u8;
    f[d+1] = txid as u8;
    f[d+2] = 0x01; f[d+3] = 0x00;                 // flags: 标准查询 RD=1
    f[d+4] = 0; f[d+5] = 1;                       // QDCOUNT=1
    // QNAME 从 d+12 起（头四格 与 QDCOUNT 后的 ANCOUNT/NSCOUNT/ARCOUNT 全零）
    f[d+12..d+12+dns_name.len()].copy_from_slice(dns_name);
    let q = d + 12 + dns_name.len();
    f[q..q+2].copy_from_slice(&DNS_QTYPE_A.to_be_bytes());
    f[q+2..q+4].copy_from_slice(&DNS_QCLASS_IN.to_be_bytes());
    let h = crate::ahci::fnv1a64(&f);
    (f, h)
}

/// 从 DNS 应答里取**第一条 A 记录**的地址。返回 `[0,0,0,0]` = 没有。
///
/// 走法：跳过 12 字节头 + QDCOUNT 条问题（每条 = QNAME + 4 字节 type/class），
/// 然后逐条看 answer（NAME + 10 字节 + RDLENGTH 字节 RDATA），
/// 遇到 `TYPE == 1`（A）且 `RDLENGTH == 4` 就把那 4 字节拿回来。
///
/// **QNAME 要处理压缩指针**（`0xC0` 高两位）：指针是"跳到别处继续读"，
/// 一个恶意/损坏的包可以让它指回自己 ⇒ 无限循环。这里的对策是**只认"指针指向
/// 更靠前的地址"**（`ptr < 当前位置`），且最多跳 [`DNS_MAX_PTR_JUMPS`] 次。
/// 这不是完整的 DNS 解析器，只是"取第一条 A"这一件事的最小正确实现。
///
/// 每一处切片都先验长度（ARP/ICMP 同条：线上的数不能直接当界用）。
fn dns_first_a(buf: &[u8], d: usize, ancount: u16) -> [u8; 4] {
    let mut p = d + 12;
    // 跳过 QDCOUNT 条问题（构造时恒 1 条，但应答里的数不能当已知用）
    let qd = if buf.len() > d + 4 {
        u16::from_be_bytes([buf[d+4], buf[d+5]])
    } else {
        0
    };
    let mut qi = 0u16;
    while qi < qd {
        let Some(np) = dns_skip_name(buf, p) else { return [0; 4] };
        p = np + 4; // type(2) + class(2)
        if p > buf.len() {
            return [0; 4];
        }
        qi += 1;
    }
    // 逐条 answer
    let mut ai = 0u16;
    while ai < ancount {
        let Some(np) = dns_skip_name(buf, p) else { return [0; 4] };
        p = np;
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 10 字节
        if p + 10 > buf.len() {
            return [0; 4];
        }
        let rtype = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let rdlen = usize::from(u16::from_be_bytes([buf[p + 8], buf[p + 9]]));
        let rd = p + 10;
        if rd + rdlen > buf.len() {
            return [0; 4];
        }
        if rtype == DNS_QTYPE_A && rdlen == 4 {
            return [buf[rd], buf[rd + 1], buf[rd + 2], buf[rd + 3]];
        }
        p = rd + rdlen;
        ai += 1;
    }
    [0; 4]
}

/// 跳过一段 DNS 名字，返回**它之后**的偏移。压缩指针最多跳 [`DNS_MAX_PTR_JUMPS`] 次，
/// 且只认"指向更靠前"的指针（防自指循环）。失败返回 `None`。
fn dns_skip_name(buf: &[u8], start: usize) -> Option<usize> {
    let mut p = start;
    let mut jumps = 0usize;
    // `end` 是"名字结束后该从哪继续"——遇到指针后它固定为指针的下一个字节
    let mut end: Option<usize> = None;
    loop {
        let b = *buf.get(p)?;
        if b == 0 {
            return Some(end.unwrap_or(p + 1));
        }
        if b & 0xC0 == 0xC0 {
            // 压缩指针：2 字节，目标必须更靠前
            let lo = *buf.get(p + 1)?;
            let target = (usize::from(b & 0x3F) << 8) | usize::from(lo);
            if target >= p {
                return None; // 自指或前向指 ⇒ 拒绝（防循环）
            }
            if end.is_none() {
                end = Some(p + 2);
            }
            jumps += 1;
            if jumps > DNS_MAX_PTR_JUMPS {
                return None;
            }
            p = target;
            continue;
        }
        // 普通标签：长度 + 内容
        p += 1 + usize::from(b);
        if p > buf.len() {
            return None;
        }
    }
}

/// 压缩指针最多跳几次。
const DNS_MAX_PTR_JUMPS: usize = 8;

/// DNS 名字编码后的最大字节数（长度前置格式含结尾 0）。
pub const DNS_NAME_MAX: usize = 128;

/// 把点分域名编成 DNS 的「长度前置」格式。返回编码长度；0 = 编码失败。
///
/// 规则（RFC 1035 §3.1）：
/// - 每段前一个字节是**该段长度**（1..=63）；
/// - 段之间不额外分隔（点只出现在输入里）；
/// - 结尾一个 0 字节。
///
/// 失败条件：空名、某段为空（连续点 / 开头点 / 结尾点）、某段超 63 字节、
/// 编码后超 `DNS_NAME_MAX`。**失败返回 0，不 panic、不截断**。
fn encode_dns_name(name: &[u8], out: &mut [u8]) -> usize {
    if name.is_empty() || out.is_empty() {
        return 0;
    }
    let mut w = 0usize;
    let mut seg_start = 0usize;
    let mut i = 0usize;
    loop {
        let at_end = i == name.len();
        let is_dot = !at_end && name.get(i).copied() == Some(b'.');
        if at_end || is_dot {
            let seg_len = i - seg_start;
            // 空段（连续点 / 首尾点）或超 63 ⇒ 失败
            if seg_len == 0 || seg_len > 63 {
                return 0;
            }
            if w + 1 + seg_len > out.len() {
                return 0;
            }
            if let Some(s) = out.get_mut(w) {
                *s = seg_len as u8;
            }
            w += 1;
            let mut k = 0usize;
            while k < seg_len {
                if let (Some(d), Some(src)) = (out.get_mut(w + k), name.get(seg_start + k)) {
                    *d = *src;
                }
                k += 1;
            }
            w += seg_len;
            seg_start = i + 1;
            if at_end {
                break;
            }
        }
        i += 1;
    }
    // 结尾 0
    if w >= out.len() {
        return 0;
    }
    if let Some(s) = out.get_mut(w) {
        *s = 0;
    }
    w + 1
}

/// 收到的 DNS reply 里能拿出来的事实。
#[derive(Clone, Copy, Debug)]
pub struct DnsReply {
    pub len: usize,
    pub hash: u64,
    pub txid: u16,
    pub rcode: u8,       // flags 的低 4 位
    pub ancount: u16,    // 回答条数
    /// ADR-158：第一条 A 记录的地址（`ancount == 0` 或没有 A 记录时全 0）。
    /// **`[0,0,0,0]` 不是合法地址**，所以"全 0"能当"没有"的哨兵。
    pub a_record: [u8; 4],
    pub used_idx: u16,
    pub used_len: u32,
    pub used_id: u32,
}

/// 解一包 UDP/DNS reply：ethertype=0x0800、protocol=17、源端 53。
/// 每处切片先验长度（ARP/ICMP 同条：线上的数不能直接当界用）。
pub fn parse_dns_reply(buf: &[u8], used_idx: u16, used_len: u32, used_id: u32) -> Result<DnsReply, NetError> {
    if buf.len() < 14 + 20 + 8 || buf[12] != NET_TYPE_IPV4[0] || buf[13] != NET_TYPE_IPV4[1] {
        return Err(NetError::NotV4 { at: buf.len(), guard: 1 });
    }
    let ihl = usize::from(buf[14] & 0x0F) * 4;
    if ihl < 20 || buf[14 + 9] != 17 || buf.len() < 14 + ihl + 8 {
        return Err(NetError::NotV4 { at: buf.len(), guard: 2 });
    }
    let u = 14 + ihl;
    if buf[u] != (DNS_CLIENT_PORT >> 8) as u8 || buf[u+1] != DNS_CLIENT_PORT as u8 {
        return Err(NetError::NotV4 { at: buf.len(), guard: 3 });
    }
    let d = u + 8;
    if buf.len() < d + 12 {
        return Err(NetError::NotV4 { at: buf.len(), guard: 4 });
    }
    let ancount = u16::from_be_bytes([buf[d+6], buf[d+7]]);
    Ok(DnsReply {
        len: used_len as usize,
        hash: crate::ahci::fnv1a64(&buf[..(used_len as usize).min(buf.len())]),
        txid: u16::from_be_bytes([buf[d], buf[d+1]]),
        rcode: buf[d+3] & 0x0F,
        ancount,
        a_record: dns_first_a(buf, d, ancount),
        used_idx,
        used_len,
        used_id,
    })
}


const BOOTP_OPT_LEN: usize = 8;
const BOOTP_BYTES: usize = BOOTP_OPT + BOOTP_OPT_LEN;
pub const DHCP_FRAME_BYTES: usize = BOOTP_OFF + BOOTP_BYTES;
const _: () = assert!(DHCP_FRAME_BYTES <= NET_TX_MAX);

/// IPv4 首部校验和：16 位一步的反码和，进位回卷后取反
fn ip_cksum(b: &[u8]) -> u16 {
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

/// 凑一个 DHCP DISCOVER：以太网 + IPv4 + UDP + BOOTP。源 IP 是 `0.0.0.0`、目的
/// `255.255.255.255`（还没有地址可填），`chaddr` 用设备配置空间读回来的那个 MAC。
/// UDP 校验和按 IPv4 里的合法写法留 0；IPv4 首部校验和是真算的（`ip_cksum`）。
pub fn build_dhcp_discover(mac: &[u8; 6]) -> ([u8; DHCP_FRAME_BYTES], u64) {
    let mut f = [0u8; DHCP_FRAME_BYTES];
    f[0..6].copy_from_slice(&NET_DST);
    f[6..12].copy_from_slice(mac);
    f[12..14].copy_from_slice(&NET_TYPE_IPV4);
    let ip_len = 20 + 8 + BOOTP_BYTES;
    f[14] = 0x45;
    f[16] = (ip_len >> 8) as u8;
    f[17] = ip_len as u8;
    f[18] = 0x00;
    f[19] = 0x01;
    f[20] = 0x40; // Don't Fragment
    f[22] = 64;
    f[23] = 17;
    f[30..34].copy_from_slice(&[255, 255, 255, 255]);
    let ck = ip_cksum(&f[14..34]);
    f[24] = (ck >> 8) as u8;
    f[25] = ck as u8;
    f[34] = (DHCP_CLIENT_PORT >> 8) as u8;
    f[35] = DHCP_CLIENT_PORT as u8;
    f[36] = (DHCP_SERVER_PORT >> 8) as u8;
    f[37] = DHCP_SERVER_PORT as u8;
    let ul = 8 + BOOTP_BYTES;
    f[38] = (ul >> 8) as u8;
    f[39] = ul as u8;
    let b = BOOTP_OFF;
    f[b] = BOOTREQUEST;
    f[b + 1] = 1;
    f[b + 2] = 6;
    f[b + 4..b + 8].copy_from_slice(&DHCP_XID.to_be_bytes());
    f[b + 28..b + 34].copy_from_slice(mac);
    f[b + 236..b + 240].copy_from_slice(&DHCP_MAGIC);
    f[b + BOOTP_OPT] = OPT_MSG_TYPE;
    f[b + BOOTP_OPT + 1] = 1;
    f[b + BOOTP_OPT + 2] = DHCP_DISCOVER;
    f[b + BOOTP_OPT + 3] = 55;
    f[b + BOOTP_OPT + 4] = 2;
    f[b + BOOTP_OPT + 5] = 1;
    f[b + BOOTP_OPT + 6] = 3;
    f[b + BOOTP_OPT + 7] = OPT_END;
    let h = crate::ahci::fnv1a64(&f);
    (f, h)
}

/// 收到的那一包（BOOTREPLY）里能拿出来的事实。字段全从**收到的字节**里读，不是我以为的
#[derive(Clone, Copy, Debug)]
pub struct Reply {
    pub len: usize,
    pub hash: u64,
    pub ethertype: [u8; 2],
    pub op: u8,
    pub msg_type: u8,
    pub xid: u32,
    pub yiaddr: [u8; 4],
    /// option 1（ADR-147）：子网掩码；服务器没给就是 0.0.0.0
    pub subnet_mask: [u8; 4],
    /// option 3 的第一个地址（默认网关）；没给就是 0.0.0.0
    pub router: [u8; 4],
    pub used_idx: u16,
    pub used_len: u32,
    /// `used.id`：设备说它写的是我们挂的那一条链（今天只挂得下一条，所以合法值只有 0）
    pub used_id: u32,
}

/// 解一包：只解到"是不是 IPv4/UDP/BOOTP 与 `yiaddr` 是哪一个数"，不做任何协议决定。
/// 每一处切片都先验长度（§10.3 同一条：盘上/线上的数不能直接当界用）
pub fn parse_reply(buf: &[u8], used_idx: u16, used_len: u32, used_id: u32) -> Result<Reply, NetError> {
    if buf.len() < BOOTP_OFF || buf[12] != NET_TYPE_IPV4[0] || buf[13] != NET_TYPE_IPV4[1] {
        return Err(NetError::NotV4 { at: buf.len(), guard: 1 });
    }
    let ihl = usize::from(buf[14] & 0x0F) * 4;
    // 每一处都要先看长度：`ihl` 从线上来，它可以是 0..15 里的任何数，也可能大到越出这一包
    if ihl < 20 || buf[14 + 9] != 17 || buf.len() < 14 + ihl + 8 + BOOTP_OPT {
        return Err(NetError::NotV4 { at: buf.len(), guard: 2 });
    }
    // UDP 的头就在 IPv4 之后：源 67（服务器）→ 目的 68（客户机）。
    // 端口在 UDP 头的 **0..2 与 2..4**，6..8 是校验和（第一版按 +6 取目的端口，
    // 于是把校验和当成了端口，任何真回话都会被判成"不是给我这台机器的"）
    if buf[14 + ihl + 2] != (DHCP_CLIENT_PORT >> 8) as u8
        || buf[14 + ihl + 3] != DHCP_CLIENT_PORT as u8
    {
        return Err(NetError::NotV4 { at: buf.len(), guard: 3 });
    }
    let b = 14 + ihl + 8; // BOOTP 从以太网 14 + IP 头 + UDP 头之后开始
    // options 从固定段的 240 起，magic 在它前面（236..240），不要再跳 4 个字节
    let opts = b + BOOTP_OPT;
    let mut msg_type = 0u8;
    let mut subnet_mask = [0u8; 4];
    let mut router = [0u8; 4];
    let mut i = opts;
    // 有界走查：`PAD` 是单字节，其余是 `code + len + len 个字节`。
    // 长度说出去就越过这一包末尾时**停下来**，不猜——猜下去就是把畸形输入当合法，
    // 而畸形输入正是 M8 那句验收（协议 fuzz）要喂的东西
    while i < buf.len() {
        let code = buf[i];
        if code == OPT_END {
            break;
        }
        if code == OPT_PAD {
            i += 1;
            continue;
        }
        if i + 1 >= buf.len() {
            break;
        }
        let ln = usize::from(buf[i + 1]);
        if ln == 0 || i + 2 + ln > buf.len() {
            break;
        }
        if code == OPT_MSG_TYPE {
            msg_type = buf[i + 2];
        }
        // ADR-147：子网掩码 / 路由器。**长度先验**：
        // option 的 ln 是 4 才取，不合形状就当没给（不猜默认值）。
        if code == OPT_SUBNET_MASK && ln == 4 {
            subnet_mask = [buf[i + 2], buf[i + 3], buf[i + 4], buf[i + 5]];
        }
        if code == OPT_ROUTER && ln >= 4 {
            router = [buf[i + 2], buf[i + 3], buf[i + 4], buf[i + 5]];
        }
        i += 2 + ln;
    }
    Ok(Reply {
        len: buf.len(),
        hash: crate::ahci::fnv1a64(buf),
        ethertype: [buf[12], buf[13]],
        op: buf[b],
        msg_type,
        xid: u32::from_be_bytes([buf[b + 4], buf[b + 5], buf[b + 6], buf[b + 7]]),
        yiaddr: [buf[b + 16], buf[b + 17], buf[b + 18], buf[b + 19]],
        subnet_mask,
        router,
        used_idx,
        used_len,
        used_id,
    })
}
