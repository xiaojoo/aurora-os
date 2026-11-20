//! DNS（RFC 1035）：查询构造与 A 记录解析。



use crate::network::dhcp::{NET_TYPE_IPV4};
use crate::network::eth::{NET_TX_MAX, frame_hash};
use crate::network::ipv4::{ip_cksum};
use crate::network::NetError;

// ---------------------------------------------------------------- B2 第三刀（ADR-141）：UDP 往返（DNS 查询）
/// DNS 的几个号（RFC 1035）。slirp 的 DNS 服务器是固定的 10.0.2.3（QEMU 用户网络约定），
/// 它把查询转发给宿主机的 DNS——回的是真 DNS 服务器的话。
pub const NET_DNS_IP: [u8; 4] = [10, 0, 2, 3];
pub const DNS_CLIENT_PORT: u16 = 53;
/// 查询的源端口：非特权（实测 源端端口 0 时 slirp 回 ICMP Port Unreachable）
pub const DNS_QUERY_PORT: u16 = 1053;


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
    let h = crate::network::eth::frame_hash(&f);
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
        hash: crate::network::eth::frame_hash(&buf[..(used_len as usize).min(buf.len())]),
        txid: u16::from_be_bytes([buf[d], buf[d+1]]),
        rcode: buf[d+3] & 0x0F,
        ancount,
        a_record: dns_first_a(buf, d, ancount),
        used_idx,
        used_len,
        used_id,
    })
}

