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

use crate::sync::{IrqSpinLock, RANK_NET};

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

// ---------------------------------------------------------------- ADR-184：NDP 邻居缓存

/// NDP 邻居缓存的槽数。
///
/// 与 ARP 表的 8 项同量级：链路本地的邻居个数是个位数。
/// 256 位地址 + 48 位 MAC + 状态 = 约 32 B/项 ⇒ 8 项 256 B，放 `.bss` 无压力。
pub const NDP_TABLE_MAX: usize = 8;

/// 邻居缓存状态（RFC 4861 §7.3.2 的简化版）。
///
/// **本轮只做 REACHABLE 与 INCOMPLETE 两态**：
/// STALE/DELAY/PROBE 是为了「邻居悄悄换了 MAC」的检测，
/// 那需要定时器与再确认逻辑——本轮没有，所以学到的就当真。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NdState {
    /// 还没学到 MAC（发过 NS，没等到 NA）。
    Incomplete,
    /// 学到了，可以直接用。
    Reachable,
}

#[derive(Clone, Copy)]
struct NdEntry {
    ip: [u8; 16],
    mac: [u8; 6],
    state: NdState,
    /// 空槽标记（`ip` 全零且 state=Incomplete 时也算空——见 `is_empty`）。
    used: bool,
}

const ND_EMPTY: NdEntry = NdEntry {
    ip: [0u8; 16],
    mac: [0u8; 6],
    state: NdState::Incomplete,
    used: false,
};

struct NdTable {
    entries: [NdEntry; NDP_TABLE_MAX],
    hits: u32,
    misses: u32,
    learns: u32,
    evicts: u32,
}

/// 缓存表的锁等级：与 socket 表同用 `RANK_NET(36)`。
///
/// **为什么可以共用一把锁**：两者都是「网络层的小表」，且从不互相嵌套获取。
/// 共用的好处是「查表 → 发包」这一串只有一个锁等级要维护。
static NDP_TABLE: IrqSpinLock<NdTable> = IrqSpinLock::new(
    RANK_NET,
    NdTable {
        entries: [ND_EMPTY; NDP_TABLE_MAX],
        hits: 0,
        misses: 0,
        learns: 0,
        evicts: 0,
    },
);

/// 邻居缓存的读数（判据用）。
pub struct NdStats {
    pub hits: u32,
    pub misses: u32,
    pub learns: u32,
    pub evicts: u32,
}

/// 查邻居缓存。`Reachable` 才返回 MAC；`Incomplete` 与 miss 都回 `None`。
///
/// **`Incomplete` 也回 `None`**：那个槽只是「我们正在问」，还没有答案。
pub fn nd_lookup(ip: &[u8; 16]) -> Option<[u8; 6]> {
    let mut g = NDP_TABLE.lock();
    let t = g.get();
    let mut i = 0usize;
    while i < NDP_TABLE_MAX {
        if t.entries[i].used && t.entries[i].ip == *ip {
            if t.entries[i].state == NdState::Reachable {
                t.hits += 1;
                return Some(t.entries[i].mac);
            }
            // 找到槽但还没学到 ⇒ 也算 miss（调用方要发 NS）
            t.misses += 1;
            return None;
        }
        i += 1;
    }
    t.misses += 1;
    None
}

/// 学一条邻居（NA 里的 target + 目标链路层地址选项）。
///
/// 已有则覆盖（与 ARP 的 RFC 826 merge 同律）；满则挤第一条（FIFO，最简且测得出）。
pub fn nd_learn(ip: &[u8; 16], mac: &[u8; 6]) {
    let mut g = NDP_TABLE.lock();
    let t = g.get();
    t.learns += 1;
    // 先找已有槽
    let mut i = 0usize;
    while i < NDP_TABLE_MAX {
        if t.entries[i].used && t.entries[i].ip == *ip {
            t.entries[i].mac = *mac;
            t.entries[i].state = NdState::Reachable;
            return;
        }
        i += 1;
    }
    // 找空槽
    let mut i = 0usize;
    while i < NDP_TABLE_MAX {
        if !t.entries[i].used {
            t.entries[i].ip = *ip;
            t.entries[i].mac = *mac;
            t.entries[i].state = NdState::Reachable;
            t.entries[i].used = true;
            return;
        }
        i += 1;
    }
    // 满了：挤第 0 条
    t.evicts += 1;
    t.entries[0].ip = *ip;
    t.entries[0].mac = *mac;
    t.entries[0].state = NdState::Reachable;
    t.entries[0].used = true;
}

/// 记一条「正在问」的邻居（发 NS 之前调）。已 `Reachable` 的不降级。
pub fn nd_mark_incomplete(ip: &[u8; 16]) {
    let mut g = NDP_TABLE.lock();
    let t = g.get();
    let mut i = 0usize;
    while i < NDP_TABLE_MAX {
        if t.entries[i].used && t.entries[i].ip == *ip {
            return; // 已有槽，状态不动
        }
        i += 1;
    }
    let mut i = 0usize;
    while i < NDP_TABLE_MAX {
        if !t.entries[i].used {
            t.entries[i].ip = *ip;
            t.entries[i].state = NdState::Incomplete;
            t.entries[i].used = true;
            return;
        }
        i += 1;
    }
}

/// 读数。
pub fn nd_stats() -> NdStats {
    let mut g = NDP_TABLE.lock();
    let t = g.get();
    NdStats { hits: t.hits, misses: t.misses, learns: t.learns, evicts: t.evicts }
}

/// 清表（用例收尾用）。
pub fn nd_clear() {
    let mut g = NDP_TABLE.lock();
    let t = g.get();
    let mut i = 0usize;
    while i < NDP_TABLE_MAX {
        t.entries[i] = ND_EMPTY;
        i += 1;
    }
}

/// 处理一帧 NDP（NS 或 NA），返回是否被消费。
///
/// ## NS 的处理
///
/// 收到 NS 时**我们必须回 NA**，否则对端学不到我们的 MAC。
/// 但回 NA 要发包，而本函数在 `RANK_NET` 锁内——**不能在这里发**。
/// 所以返回一个「待发 NA」的指示，由调用方在锁外发。
///
/// ## NA 的处理
///
/// 直接把 `target + lladdr` 学进缓存。
pub enum NdAction {
    /// 消费了，不需要回包。
    None,
    /// 需要回一个 NA 给 `dst_ip`（目标 MAC 用 `dst_mac`）。
    ReplyNa { dst_ip: [u8; 16], dst_mac: [u8; 6], target: [u8; 16] },
}
/// 只看这一帧的 NS target，**不持任何锁**（ADR-185）。
///
/// 给调用方「先查地址表判属，再把结果传进 `handle_frame`」用。
pub fn peek_ns_target(f: &[u8]) -> Option<[u8; 16]> {
    let msg = parse_nd(f)?;
    if msg.kind == ICMPV6_NS { Some(msg.target) } else { None }
}



/// 解析并处理一帧。**不持锁调用发包**：返回动作由调用方执行。
/// `is_ours` = 这个 NS 的 target 是不是本机地址（**由调用方查地址表后传入**）。
///
/// **为什么不在这里查**：见 `ICMPV6_NS` 分支里的注释——同等级重入会 L4。
pub fn handle_frame(f: &[u8], our_mac: &[u8; 6], is_ours: bool) -> NdAction {
    let Some(msg) = parse_nd(f) else {
        return NdAction::None;
    };
    match msg.kind {
        ICMPV6_NA => {
            // 只学「有目标链路层地址选项」的 NA——没有选项的 NA 是「不在此处」
            if let Some(mac) = msg.lladdr {
                nd_learn(&msg.target, &mac);
            }
            NdAction::None
        }
        ICMPV6_NS => {
            // **精确判属**（ADR-185 决策 4）：target 在地址表里才回 NA。
            //
            // ADR-184 那一版是「总是回」，代价是链路上每台机器都回 NA，
            // 真正的目标只是回得更快。地址表落地后这条可以精确了。
            let _ = our_mac;
            // **地址表查询不能在这里做**（ADR-185 实测）：
            //
            // `handle_frame` 的调用方（`deliver_frame`）可能已持 `RANK_NET`，
            // 而 `addr_is_local` 也要 `RANK_NET` ⇒ 同等级重入 ⇒ L4（实测
            // `锁序违规，外层 rank=36 本次 rank=36`）。
            //
            // 所以把判属**提到调用方**：`handle_frame` 只解析，判属由 `deliver_frame`
            // 在拿锁之前做完，通过 `is_ours` 传进来。
            if !is_ours {
                return NdAction::None;
            }
            NdAction::ReplyNa {
                dst_ip: msg.src_ip,
                dst_mac: msg.lladdr.unwrap_or([0xFF; 6]),
                target: msg.target,
            }
        }
        _ => NdAction::None,
    }
}
