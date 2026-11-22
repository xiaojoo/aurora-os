//! 本机地址表（ADR-185）。
//!
//! ## 为什么需要它
//!
//! 三个具体后果逼出来的：
//!
//! 1. **NDP 应答泛滥**：`handle_frame` 收到 NS 时无法判断 target 是不是自己的，只能总是回 NA。
//! 2. **`bind` 语义错**：`bind(192.168.1.1)` 在 Linux 上是 `EADDRNOTAVAIL`，我们之前接受。
//! 3. **DHCP 白做**：解析出 `yiaddr` 却不生效，等于没有 DHCP。
//!
//! ## 形状
//!
//! 「接口 × 地址」的**扁平列表**，不是每接口一个。今天只有一张网卡，
//! 嵌套结构要多一层索引却没有收益。`iface` 字段已经留着，等真有第二张卡时按它过滤即可。

use crate::network::ipv6::IpAddr;
use crate::sync::{IrqSpinLock, RANK_NET};

/// 地址表容量。
///
/// 8 是「一块网卡可能有的地址数」的实用上界：
/// IPv4 单播 + IPv4 链路本地（169.254）+ IPv6 链路本地 + 几个 IPv6 全局 + 临时地址。
pub const IF_ADDR_MAX: usize = 8;

/// 一个本机地址（ADR-185 决策 1）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IfAddr {
    pub ip: IpAddr,
    /// 前缀长度（IPv4 的 24、IPv6 的 64）。
    pub prefix: u8,
    /// 这个地址的接口号（今天恒 0，单网卡）。
    pub iface: u8,
    /// 是不是链路本地（`fe80::/10` 或 `169.254.0.0/16`）。
    pub link_local: bool,
}

const IF_EMPTY: IfAddr = IfAddr {
    ip: IpAddr::V4([0, 0, 0, 0]),
    prefix: 0,
    iface: 0,
    link_local: false,
};

struct AddrTable {
    addrs: [IfAddr; IF_ADDR_MAX],
    n: usize,
    /// 默认网关（不是本机地址，所以单独存）。
    gateway: Option<IpAddr>,
}

static ADDRS: IrqSpinLock<AddrTable> = IrqSpinLock::new(
    RANK_NET,
    AddrTable { addrs: [IF_EMPTY; IF_ADDR_MAX], n: 0, gateway: None },
);

/// 这个 `IpAddr` 是不是链路本地。
pub fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a[0] == 169 && a[1] == 254,
        IpAddr::V6(_) => ip.is_link_local(),
    }
}

/// 这个 `IpAddr` 是不是通配地址（`0.0.0.0` / `::`）。
///
/// **通配地址在 `bind` 上必须放行**（ADR-185 决策 5）：
/// `bind(0.0.0.0:80)` 是「监听所有接口」的标准写法，
/// 校验它等于让所有服务端程序失败。
pub fn is_wildcard(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0,
        IpAddr::V6(a) => {
            let mut i = 0;
            while i < 16 {
                if a[i] != 0 {
                    return false;
                }
                i += 1;
            }
            true
        }
    }
}

/// 加一个地址。返回 `false` = 表满或已存在（幂等）。
pub fn addr_add(ip: IpAddr, prefix: u8, iface: u8) -> bool {
    let mut g = ADDRS.lock();
    let t = g.get();
    // 已存在 ⇒ 幂等成功（DHCP 重复 apply 会走这条）
    let mut i = 0usize;
    while i < t.n {
        if t.addrs[i].ip == ip {
            return true;
        }
        i += 1;
    }
    if t.n >= IF_ADDR_MAX {
        return false;
    }
    t.addrs[t.n] = IfAddr { ip, prefix, iface, link_local: is_link_local(&ip) };
    t.n += 1;
    true
}

/// 删一个地址。返回 `false` = 本来就不在表里。
pub fn addr_remove(ip: &IpAddr) -> bool {
    let mut g = ADDRS.lock();
    let t = g.get();
    let mut i = 0usize;
    while i < t.n {
        if t.addrs[i].ip == *ip {
            // 后面的往前挪（顺序不重要，但保持紧凑让 `n` 有意义）
            let mut k = i;
            while k + 1 < t.n {
                t.addrs[k] = t.addrs[k + 1];
                k += 1;
            }
            t.n -= 1;
            return true;
        }
        i += 1;
    }
    false
}

/// 查一个地址是不是本机的。
pub fn addr_is_local(ip: &IpAddr) -> bool {
    let mut g = ADDRS.lock();
    let t = g.get();
    let mut i = 0usize;
    while i < t.n {
        if t.addrs[i].ip == *ip {
            return true;
        }
        i += 1;
    }
    false
}

/// 取表里第一个 IPv4 地址（「主地址」，发 DHCP/DNS 时用）。
pub fn primary_v4() -> Option<[u8; 4]> {
    let mut g = ADDRS.lock();
    let t = g.get();
    let mut i = 0usize;
    while i < t.n {
        if let IpAddr::V4(a) = t.addrs[i].ip {
            if !t.addrs[i].link_local {
                return Some(a);
            }
        }
        i += 1;
    }
    None
}

/// 取表里第一个 IPv6 链路本地地址。
pub fn primary_v6_link_local() -> Option<[u8; 16]> {
    let mut g = ADDRS.lock();
    let t = g.get();
    let mut i = 0usize;
    while i < t.n {
        if let IpAddr::V6(a) = t.addrs[i].ip {
            if t.addrs[i].link_local {
                return Some(a);
            }
        }
        i += 1;
    }
    None
}

/// 设默认网关。
pub fn set_gateway(gw: IpAddr) {
    let mut g = ADDRS.lock();
    g.get().gateway = Some(gw);
}

/// 读默认网关。
pub fn gateway() -> Option<IpAddr> {
    let mut g = ADDRS.lock();
    g.get().gateway
}

/// 表里有多少个地址。
pub fn addr_count() -> usize {
    let mut g = ADDRS.lock();
    g.get().n
}

/// 把表拷进调用方的缓冲，返回条数。**判据与用户态出口用**。
pub fn addr_list(out: &mut [IfAddr]) -> usize {
    let mut g = ADDRS.lock();
    let t = g.get();
    let n = t.n.min(out.len());
    let mut i = 0usize;
    while i < n {
        out[i] = t.addrs[i];
        i += 1;
    }
    n
}

/// 清表（用例收尾用）。
pub fn addr_clear() {
    let mut g = ADDRS.lock();
    let t = g.get();
    t.n = 0;
    t.gateway = None;
}