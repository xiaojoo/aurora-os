//! 过滤器看见的"包"：五元组 + 方向 + ICMPv6 类型（纯数据）。
//!
//! 地址统一放进 16 字节：IPv4 占前 4 字节、其余 12 字节为 0。**规则若写了地址前缀就必须写族**
//! （[`crate::rules::CompileError::PrefixWithoutFamily`]），所以不会出现"v4 前缀误配 v6 包"。

/// 方向。
///
/// 第一期只有入站挂载点（`socket.rs` 的 `deliver_frame`），内核恒以 [`Dir::In`] 调用。
/// `Out` 保留在规则模型里但**没有挂载点**（出站过滤列为第二期，ADR-267 §6）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// 入站。
    In,
    /// 出站（第一期无挂载点）。
    Out,
}

impl Dir {
    /// 字段 [`field::DIR`] 的取值：In=0、Out=1。
    pub const fn code(self) -> u32 {
        match self {
            Dir::In => 0,
            Dir::Out => 1,
        }
    }
}

/// 地址族取值（与 IP 版本号一致）。
pub const FAMILY_V4: u8 = 4;
/// 地址族取值（与 IP 版本号一致）。
pub const FAMILY_V6: u8 = 6;
/// IP 协议号：UDP。
pub const PROTO_UDP: u8 = 17;
/// IP 协议号：ICMPv6（IPv6 next header）。
pub const PROTO_ICMPV6: u8 = 58;

/// `LDF` 指令可读的字段号（`imm`）。共 [`field::COUNT`] 个，验证器拒绝越界字段。
pub mod field {
    /// 地址族（4/6）。
    pub const FAMILY: u32 = 0;
    /// 协议号。
    pub const PROTO: u32 = 1;
    /// 方向（[`super::Dir::code`]）。
    pub const DIR: u32 = 2;
    /// 源端口（ICMPv6 为 0）。
    pub const SPORT: u32 = 3;
    /// 目的端口（ICMPv6 为 0）。
    pub const DPORT: u32 = 4;
    /// 源地址第 0 个 32 位字（大端；IPv4 地址就在这一字）。
    pub const SRC0: u32 = 5;
    /// 源地址第 3 个 32 位字。
    pub const SRC3: u32 = 8;
    /// 目的地址第 0 个 32 位字。
    pub const DST0: u32 = 9;
    /// 目的地址第 3 个 32 位字。
    pub const DST3: u32 = 12;
    /// ICMPv6 类型（非 ICMPv6 为 0）。
    pub const ICMP_TYPE: u32 = 13;
    /// 字段总数。
    pub const COUNT: u32 = 14;
}

/// 一个待判决的包。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet {
    /// [`FAMILY_V4`] / [`FAMILY_V6`]。
    pub family: u8,
    /// IP 协议号。
    pub proto: u8,
    /// 方向。
    pub dir: Dir,
    /// 源地址（IPv4 占前 4 字节）。
    pub src: [u8; 16],
    /// 目的地址（IPv4 占前 4 字节）。
    pub dst: [u8; 16],
    /// 源端口。
    pub sport: u16,
    /// 目的端口。
    pub dport: u16,
    /// ICMPv6 类型。
    pub icmp_type: u8,
}

fn widen(a: [u8; 4]) -> [u8; 16] {
    [a[0], a[1], a[2], a[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

impl Packet {
    /// UDP over IPv4。
    pub fn udp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, dir: Dir) -> Packet {
        Packet { family: FAMILY_V4, proto: PROTO_UDP, dir, src: widen(src), dst: widen(dst), sport, dport, icmp_type: 0 }
    }

    /// UDP over IPv6。
    pub fn udp6(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16, dir: Dir) -> Packet {
        Packet { family: FAMILY_V6, proto: PROTO_UDP, dir, src, dst, sport, dport, icmp_type: 0 }
    }

    /// ICMPv6（含 NDP）。端口恒为 0。
    pub fn icmp6(src: [u8; 16], dst: [u8; 16], icmp_type: u8, dir: Dir) -> Packet {
        Packet { family: FAMILY_V6, proto: PROTO_ICMPV6, dir, src, dst, sport: 0, dport: 0, icmp_type }
    }

    /// 取字段值；`None` = 字段号越界（已验证程序不会走到）。
    pub fn field(&self, f: u32) -> Option<u32> {
        match f {
            field::FAMILY => Some(u32::from(self.family)),
            field::PROTO => Some(u32::from(self.proto)),
            field::DIR => Some(self.dir.code()),
            field::SPORT => Some(u32::from(self.sport)),
            field::DPORT => Some(u32::from(self.dport)),
            field::SRC0..=field::SRC3 => word(&self.src, f - field::SRC0),
            field::DST0..=field::DST3 => word(&self.dst, f - field::DST0),
            field::ICMP_TYPE => Some(u32::from(self.icmp_type)),
            _ => None,
        }
    }
}

/// 地址的第 `i` 个大端 32 位字（`i` 越界 ⇒ `None`）。
pub fn word(a: &[u8; 16], i: u32) -> Option<u32> {
    let i = usize::try_from(i).ok()?;
    let s = a.get(i.checked_mul(4)?..i.checked_mul(4)?.checked_add(4)?)?;
    let b: [u8; 4] = s.try_into().ok()?;
    Some(u32::from_be_bytes(b))
}
