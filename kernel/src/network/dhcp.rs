//! DHCP/BOOTP：DISCOVER 构造与 OFFER/ACK 解析。



use crate::network::eth::{NET_DST, NET_TX_MAX, frame_hash};
use crate::network::ipv4::{ip_cksum};
use crate::network::NetError;

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



const BOOTP_OPT_LEN: usize = 8;
const BOOTP_BYTES: usize = BOOTP_OPT + BOOTP_OPT_LEN;
pub const DHCP_FRAME_BYTES: usize = BOOTP_OFF + BOOTP_BYTES;
const _: () = assert!(DHCP_FRAME_BYTES <= NET_TX_MAX);


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
    let h = crate::network::eth::frame_hash(&f);
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
        hash: crate::network::eth::frame_hash(buf),
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

/// 把 DHCP 应答写进地址表（ADR-185 决策 3）。
///
/// ## 三件事
///
/// 1. `yiaddr` + `subnet_mask` 推前缀，加进地址表；
/// 2. `router` 记成默认网关（**不进地址表**——它不是本机地址）；
/// 3. 幂等：同一地址重复 apply 不重复加。
///
/// ## 为什么前缀从掩码推
///
/// DHCP 给的是 `subnet_mask`（如 `255.255.255.0`），而地址表存的是 `prefix`（如 24）。
/// 数掩码里前导 1 的个数即可。
///
/// **掩码全零或全 1 时退回 24**：`0.0.0.0` 与 `255.255.255.255` 都不是合法的单播掩码，
/// 服务器给这种值说明配置有问题，用默认值比算出一个荒谬的前缀安全。
#[cfg(feature = "virtio-net")]
pub fn dhcp_apply(reply: &Reply) -> bool {
    use crate::network::ifaddr::{addr_add, set_gateway};
    use crate::network::ipv6::IpAddr;
    let ip = reply.yiaddr;
    if ip == [0, 0, 0, 0] {
        return false;
    }
    // 数前导 1 的个数（合法掩码是连续的 1 后跟连续的 0）
    let mut prefix = 0u8;
    let mut done = false;
    for b in reply.subnet_mask {
        let mut bit = 0x80u8;
        while bit != 0 {
            if done || (b & bit) == 0 {
                done = true;
            } else {
                prefix += 1;
            }
            bit >>= 1;
        }
    }
    if prefix == 0 || prefix == 32 {
        prefix = 24;
    }
    let added = addr_add(IpAddr::V4(ip), prefix, 0);
    if reply.router != [0, 0, 0, 0] {
        set_gateway(IpAddr::V4(reply.router));
    }
    added
}
