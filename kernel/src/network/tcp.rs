//! TCP 段格式与校验和（ADR-197）。
//!
//! ## 这一层只做「字节」
//!
//! 与 `udp.rs` 同一条纪律：**只处理字节，不碰设备、不碰状态机**。
//! 连接状态机、重传队列、滑动窗口在 `tcp_conn.rs` 里。
//!
//! ## 为什么 TCP 不能像 UDP 那样一个函数搞定
//!
//! UDP 的「帧」是一个完整的语义单位（一问一答）。TCP 的段不是：
//! 它有**序号空间**（seq/ack 各自单调）、**标志位组合**（SYN/FIN/ACK/RST/PSH 各有含义）、
//! 还有**伪首部校验和**。所以这里只解析/构造段，语义交给上层。

pub const TCP_HDR_MIN: usize = 20;

/// TCP 数据偏移字段的最大值（4 位 × 4 字节 = 60）。
pub const TCP_HDR_MAX: usize = 60;

/// 一个 TCP 段的载荷上限：IPv4 MTU 1500 − 20(IP) − 20(TCP) = 1460。
///
/// **这不是「越大越好」**：超了要分段，而分段要 IP 层重组，那是另一个子系统。
pub const TCP_PAYLOAD_MAX: usize = 1460;

// ---- 标志位（RFC 793 的 6 位 + ECN 的 2 位）
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;

/// 解析出来的一个 TCP 段。
///
/// 载荷是 `&[u8]` 借用：调用方拿到的是**网卡收包缓冲里的那一段**，不是副本。
/// 要留住必须自己复制（`Datagram` 就是这么做的）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    /// **只有 `ACK` 置位时这个值才有意义**（RFC 793 §3.1）。
    pub ack: u32,
    /// 标志位打包（`FIN`/`SYN`/`RST`/`PSH`/`ACK`/`URG`）。
    pub flags: u8,
    /// 窗口大小：**本端还能收多少字节**。
    pub window: u16,
    /// 数据偏移（头部长度，单位 32 位字）。
    pub data_off: u8,
    /// 载荷。空段（纯 SYN/ACK/FIN）这里是空的。
    pub payload: &'a [u8],
}

impl<'a> Segment<'a> {
    pub fn is_syn(&self) -> bool {
        self.flags & SYN != 0
    }
    pub fn is_ack(&self) -> bool {
        self.flags & ACK != 0
    }
    pub fn is_fin(&self) -> bool {
        self.flags & FIN != 0
    }
    pub fn is_rst(&self) -> bool {
        self.flags & RST != 0
    }
    /// 这个段在序号空间里占几个字节（SYN/FIN 各占一个）。
    ///
    /// **这是 TCP 最容易写错的地方之一**：`SYN` 和 `FIN` 不携带数据，但它们**消耗序号**。
    /// 漏了它们，握手与挥手的序号会差一格，而那种错在「传数据」时看不出来。
    pub fn seq_len(&self) -> u32 {
        let mut n = self.payload.len() as u32;
        if self.is_syn() {
            n += 1;
        }
        if self.is_fin() {
            n += 1;
        }
        n
    }
}

/// 伪首部 + TCP 段的校验和（RFC 793）。
///
/// 与 `udp::udp_checksum` 同一形状：伪首部是 `src(4) + dst(4) + zero + proto + len`。
/// `proto = 6`（TCP）。
pub fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_seg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // 伪首部
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 6u32; // 协议号 TCP
    sum += tcp_seg.len() as u32;
    // 段本体（奇数长度补 0）
    let mut i = 0usize;
    while i + 1 < tcp_seg.len() {
        sum += u16::from_be_bytes([tcp_seg[i], tcp_seg[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_seg.len() {
        sum += u16::from_be_bytes([tcp_seg[i], 0]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// 构造一个 TCP 段（不含 IP 头）到 `out`，返回写入的字节数。
///
/// ## 参数顺序照 RFC 793 的字段顺序
///
/// 故意**不做「自动填窗口」那种便利**：窗口是连接状态，调用方必须显式给。
#[allow(clippy::too_many_arguments)]
pub fn build_segment(
    out: &mut [u8],
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Option<usize> {
    if payload.len() > TCP_PAYLOAD_MAX {
        return None;
    }
    let total = TCP_HDR_MIN + payload.len();
    if out.len() < total {
        return None;
    }
    out[0..2].copy_from_slice(&src_port.to_be_bytes());
    out[2..4].copy_from_slice(&dst_port.to_be_bytes());
    out[4..8].copy_from_slice(&seq.to_be_bytes());
    out[8..12].copy_from_slice(&ack.to_be_bytes());
    // 数据偏移（5 个 32 位字 = 20 字节）在**高 4 位**
    out[12] = ((TCP_HDR_MIN / 4) as u8) << 4;
    out[13] = flags;
    out[14..16].copy_from_slice(&window.to_be_bytes());
    // 校验和字段先清零，算完再填
    out[16] = 0;
    out[17] = 0;
    out[18..20].copy_from_slice(&0u16.to_be_bytes()); // 紧急指针
    out[TCP_HDR_MIN..total].copy_from_slice(payload);
    let ck = tcp_checksum(src_ip, dst_ip, &out[..total]);
    out[16..18].copy_from_slice(&ck.to_be_bytes());
    Some(total)
}

/// 解析一个 TCP 段。**任何形状不对都回 `None`**（不猜、不截短）。
pub fn parse_segment(seg: &[u8]) -> Option<Segment<'_>> {
    if seg.len() < TCP_HDR_MIN {
        return None;
    }
    let src_port = u16::from_be_bytes([seg[0], seg[1]]);
    let dst_port = u16::from_be_bytes([seg[2], seg[3]]);
    let seq = u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]);
    let ack = u32::from_be_bytes([seg[8], seg[9], seg[10], seg[11]]);
    let data_off = seg[12] >> 4;
    let flags = seg[13];
    let window = u16::from_be_bytes([seg[14], seg[15]]);
    // 头部长度必须 >= 20 且 <= 60，且不能超过实际长度
    let hdr = data_off as usize * 4;
    if hdr < TCP_HDR_MIN || hdr > TCP_HDR_MAX || hdr > seg.len() {
        return None;
    }
    Some(Segment {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        data_off,
        payload: &seg[hdr..],
    })
}