//! socket 表与 UDP socket 本体（ADR-181）。
//!
//! ## 形状
//!
//!     用户 fd ──→ 句柄（capability 表）──→ ObjRef::Socket { slot, gen } ──→ 本模块的槽表
//!
//! 中间那层句柄不是多余的：`close` 语义、权限位、跨进程传递（`dup`）都已经在句柄层做好了。
//! socket 直接放 fd 表里等于把这三件事重做一遍（ADR-181 决策 5）。
//!
//! ## 为什么槽表是定长 `.bss` 而 fd 表是运行时分配
//!
//! 两者的量级差三个数量级：fd 表是**每进程** 64–1024 格（× 32768 进程），
//! socket 表是**全系统** 256 格。后者 256 × ~48 B = 12 KiB，放 `.bss` 不推高布局
//! （ADR-179 那条纪律的阈值是「容量 × 元素 > 几十 KiB」）。

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::network::udp::{self, UdpEndpoint, UDP_PAYLOAD_MAX};
use crate::sync::{IrqSpinLock, RANK_NET};

/// 全系统 socket 槽数。Linux 的 `somaxconn` 是 listen 队列长度、不是 socket 总数；
/// socket 总数受 `RLIMIT_NOFILE` 与内存约束，没有对应常量。取 256 是本轮接缝。
pub const MAX_SOCKETS: usize = 256;

/// 每个 socket 的接收队列深度（数据报个数）。
///
/// **满了丢新包**（不是丢老包）：UDP 本来就允许丢，丢老的会让"最近的数据"消失，
/// 而调用方最常要的是最近的。
pub const SOCK_RX_QUEUE: usize = 8;

/// 地址族（与 Linux `include/linux/socket.h` 一致）。
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// socket 类型（与 Linux 一致）。
pub const SOCK_STREAM: u16 = 1;
pub const SOCK_DGRAM: u16 = 2;

/// 错误码（与内核既有 `E_*` 对齐）。
pub const E_BAD_FD: u64 = u64::MAX - 8;      // -9  EBADF
pub const E_AGAIN: u64 = u64::MAX - 10;      // -11 EAGAIN
pub const E_INVAL: u64 = u64::MAX;           // -1  EINVAL
pub const E_NOSYS: u64 = u64::MAX - 37;      // -38 ENOSYS
pub const E_OPNOTSUPP: u64 = u64::MAX - 94;  // -95 EOPNOTSUPP
pub const E_ADDRINUSE: u64 = u64::MAX - 97;  // -98 EADDRINUSE
pub const E_ADDRNOTAVAIL: u64 = u64::MAX - 98; // -99 EADDRNOTAVAIL（地址不属于本机）
pub const E_EXHAUSTED: u64 = u64::MAX - 5;   // -6  ENOMEM

/// 一个 socket 端点：两个族并列（ADR-182 决策 5 / ADR-183）。
///
/// ## 为什么不用 `udp::UdpEndpoint`
///
/// 那个类型是 `{ ip: [u8; 4], port: u16 }` —— **装不下 IPv6**。
/// 但它是 IPv4 路径上**实测在跑**的类型，改它等于改 `udp.rs` 的全部调用点。
///
/// 所以 socket 层自己用一个能装两族的枚举，IPv4 值从 `UdpEndpoint` 转换过来。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SockAddr {
    V4 { ip: [u8; 4], port: u16 },
    V6 { ip: [u8; 16], port: u16 },
}

impl SockAddr {
    pub const fn port(&self) -> u16 {
        match self {
            SockAddr::V4 { port, .. } => *port,
            SockAddr::V6 { port, .. } => *port,
        }
    }

    pub const fn is_v6(&self) -> bool {
        matches!(self, SockAddr::V6 { .. })
    }

    /// 未绑定/未连接的哨兵（端口 0 且地址全零）。
    ///
    /// **族也要判**：`V4{0.0.0.0:0}` 与 `V6{:::0}` 都是「空」，
    /// 但它们的族不同——一个 `AF_INET6` socket 的空端点必须是 `V6`，
    /// 否则 `send` 会走进 IPv4 分支。
    pub fn is_empty(&self) -> bool {
        match self {
            SockAddr::V4 { ip, port } => *port == 0 && ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0,
            SockAddr::V6 { ip, port } => {
                if *port != 0 {
                    return false;
                }
                let mut i = 0;
                while i < 16 {
                    if ip[i] != 0 {
                        return false;
                    }
                    i += 1;
                }
                true
            }
        }
    }

    /// IPv4 视图（`send` 走 `udp::build_frame` 时用）。
    pub const fn as_v4(&self) -> Option<udp::UdpEndpoint> {
        match self {
            SockAddr::V4 { ip, port } => Some(udp::UdpEndpoint { ip: *ip, port: *port }),
            SockAddr::V6 { .. } => None,
        }
    }

    /// IPv6 视图（`send` 走 `ipv6::build_udp6_frame` 时用）。
    pub const fn as_v6(&self) -> Option<([u8; 16], u16)> {
        match self {
            SockAddr::V4 { .. } => None,
            SockAddr::V6 { ip, port } => Some((*ip, *port)),
        }
    }

    /// 由 IPv4 端点构造（既有路径的转换入口）。
    pub const fn from_v4(e: udp::UdpEndpoint) -> SockAddr {
        SockAddr::V4 { ip: e.ip, port: e.port }
    }
}

/// 一个数据报在队列里的一份拷贝。
#[derive(Clone, Copy)]
pub struct Datagram {
    pub src: SockAddr,
    pub len: u16,
    pub data: [u8; UDP_PAYLOAD_MAX],
}

const DG_EMPTY: Datagram = Datagram {
    src: SockAddr::V4 { ip: [0; 4], port: 0 },
    len: 0,
    data: [0; UDP_PAYLOAD_MAX],
};

/// 一个 socket 槽。
pub struct Socket {
    used: AtomicU32,
    /// 世代号：槽复用后旧句柄必须失配（与 `Proc`/`Job` 同律）。
    gen: AtomicU32,
    /// **名字引用数**（ADR-192）：`dup` 加一、`close` 减一，**减到 0 才销毁本体**。
    ///
    /// ## 为什么必须有
    ///
    /// 第一版 `sys_sock_close` 无条件 `destroy`，于是：
    ///
    /// ```
    /// fd1 = socket(); fd2 = dup(fd1);
    /// close(fd2);       // ← 本体被销毁
    /// send(fd1, ...);   // ← 这条还活着的名字悬空
    /// ```
    ///
    /// POSIX 语义是「`close` 减引用，最后一条关上才销毁」。
    refs: AtomicU32,
    domain: u16,
    ty: u16,
    /// 本地端点（`bind` 之后有效）。
    local: SockAddr,
    /// 默认对端（`connect` 之后有效）。UDP 的 connect 只是记住对端。
    peer: SockAddr,
    /// 接收队列头/尾与计数（环形）。
    rx_head: AtomicU32,
    rx_tail: AtomicU32,
    rx_count: AtomicU32,
    rx: [Datagram; SOCK_RX_QUEUE],
}

const SOCK_EMPTY: Socket = Socket {
    used: AtomicU32::new(0),
    gen: AtomicU32::new(0),
    refs: AtomicU32::new(0),
    domain: 0,
    ty: 0,
    local: SockAddr::V4 { ip: [0; 4], port: 0 },
    peer: SockAddr::V4 { ip: [0; 4], port: 0 },
    rx_head: AtomicU32::new(0),
    rx_tail: AtomicU32::new(0),
    rx_count: AtomicU32::new(0),
    rx: [DG_EMPTY; SOCK_RX_QUEUE],
};

struct SocketTable {
    slots: [Socket; MAX_SOCKETS],
}

static TABLE: IrqSpinLock<SocketTable> = IrqSpinLock::new(RANK_NET, SocketTable { slots: [SOCK_EMPTY; MAX_SOCKETS] });

/// 建一个 socket，返回 `(槽号, 世代)`。
///
/// `domain` 收 `AF_INET` 与 `AF_INET6`（ADR-182 决策 5 落地：IPv6 已能建 socket）。
/// 调用方要能分辨「参数写错」与「这个族还没实现」，ADR-181 决策 2）。
/// `ty` 只收 `SOCK_DGRAM`；`SOCK_STREAM` 回 `E_NOSYS`（ADR-181 决策 1）。
pub fn create(domain: u16, ty: u16) -> Result<(u16, u32), u64> {
    if domain != AF_INET && domain != AF_INET6 {
        return Err(E_INVAL);
    }
    if ty == SOCK_STREAM {
        return Err(E_NOSYS);
    }
    if ty != SOCK_DGRAM {
        return Err(E_INVAL);
    }
    let mut g = TABLE.lock();
    let t = g.get();
    let slot = t
        .slots
        .iter()
        .position(|s| s.used.load(Ordering::Acquire) == 0)
        .ok_or(E_EXHAUSTED)?;
    let s = &mut t.slots[slot];
    s.gen.store(s.gen.load(Ordering::Acquire).wrapping_add(1), Ordering::Release);
    s.domain = domain;
    s.ty = ty;
    // **空端点的族必须与 domain 一致**（ADR-182）：
    // 一个 AF_INET6 socket 的空端点若是 V4，`send` 会走进 IPv4 分支。
    if domain == AF_INET6 {
        s.local = SockAddr::V6 { ip: [0; 16], port: 0 };
        s.peer = SockAddr::V6 { ip: [0; 16], port: 0 };
    } else {
        s.local = SockAddr::V4 { ip: [0; 4], port: 0 };
        s.peer = SockAddr::V4 { ip: [0; 4], port: 0 };
    }
    s.rx_head.store(0, Ordering::Relaxed);
    s.rx_tail.store(0, Ordering::Relaxed);
    s.rx_count.store(0, Ordering::Relaxed);
    // **出生时一条名字**（ADR-192）：`dup` 加、`close` 减，减到 0 才销毁。
    s.refs.store(1, Ordering::Release);
    s.used.store(1, Ordering::Release);
    Ok((slot as u16, s.gen.load(Ordering::Acquire)))
}

/// 给 socket **加一条名字引用**（`dup` 时调，ADR-192）。
///
/// `gen` 不符（槽已复用）⇒ `false`，调用方必须把它当成「对象不在了」。
pub fn sock_ref(slot: u16, gen: u32) -> bool {
    let mut g = TABLE.lock();
    let t = g.get();
    let Some(s) = t.slots.get_mut(slot as usize) else { return false };
    if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != gen {
        return false;
    }
    s.refs.fetch_add(1, Ordering::AcqRel);
    true
}

/// 给 socket **减一条名字引用**；**减到 0 才真的销毁本体**（ADR-192）。
///
/// 返回 `true` = 本体已销毁；`false` = 还有别的名字活着，或 `gen` 不符。
///
/// **这就是 POSIX 的 `close` 语义**：第一版无条件 `destroy`，`dup` 之后关一条就把
/// 本体撤了，另一条名字悬空（实测 `sockref` 用例抓到）。
pub fn sock_unref(slot: u16, gen: u32) -> bool {
    let mut g = TABLE.lock();
    let t = g.get();
    let Some(s) = t.slots.get_mut(slot as usize) else { return false };
    if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != gen {
        return false;
    }
    let prev = s.refs.fetch_sub(1, Ordering::AcqRel);
    if prev > 1 {
        return false; // 还有别的名字活着
    }
    // 最后一条：真的销毁
    s.refs.store(0, Ordering::Release);
    s.used.store(0, Ordering::Release);
    s.rx_head.store(0, Ordering::Relaxed);
    s.rx_tail.store(0, Ordering::Relaxed);
    s.rx_count.store(0, Ordering::Relaxed);
    true
}

/// 当前名字引用数（判据用）。
pub fn sock_refs(slot: u16, gen: u32) -> u32 {
    let mut g = TABLE.lock();
    let t = g.get();
    match t.slots.get(slot as usize) {
        Some(s) if s.used.load(Ordering::Acquire) != 0 && s.gen.load(Ordering::Acquire) == gen => {
            s.refs.load(Ordering::Acquire)
        }
        _ => 0,
    }
}

/// 销毁一个 socket。`gen` 不符 ⇒ `false`（槽已被复用，不是当初那个）。
pub fn destroy(slot: u16, gen: u32) -> bool {
    let mut g = TABLE.lock();
    let t = g.get();
    let Some(s) = t.slots.get_mut(usize::from(slot)) else {
        return false;
    };
    if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != gen {
        return false;
    }
    s.used.store(0, Ordering::Release);
    true
}

/// 活性判定（与 `ObjRef` 的其它 kind 同律：close 撤名字、销毁走显式路径）。
pub fn live(slot: u16, gen: u32) -> bool {
    let mut g = TABLE.lock();
    let t = g.get();
    t.slots
        .get(usize::from(slot))
        .map(|s| s.used.load(Ordering::Acquire) != 0 && s.gen.load(Ordering::Acquire) == gen)
        .unwrap_or(false)
}

/// `bind`：记住本地端点。
pub fn bind(slot: u16, gen: u32, local: SockAddr) -> Result<(), u64> {
    // **地址归属校验必须在拿锁之前做**（ADR-185 实测）：
    //
    // `bootstrap_addrs` 与 `addr_is_local` 都要 `RANK_NET(36)`，而本函数下面
    // 也要 `RANK_NET`（socket 表与地址表共用一把）。在锁内查就是同等级重入 ⇒ L4
    // （实测 `锁序违规，外层 rank=36 本次 rank=36`）。
    //
    // `bind(192.168.1.1)` 在 Linux 上是 `EADDRNOTAVAIL`，我们之前接受。
    // **通配地址必须放行**：`bind(0.0.0.0:80)` 是「监听所有接口」的标准写法。
    bootstrap_addrs();
    let check_ip = match local {
        SockAddr::V4 { ip, .. } => crate::network::ipv6::IpAddr::V4(ip),
        SockAddr::V6 { ip, .. } => crate::network::ipv6::IpAddr::V6(ip),
    };
    if !crate::network::ifaddr::is_wildcard(&check_ip)
        && !crate::network::ifaddr::addr_is_local(&check_ip)
    {
        return Err(E_ADDRNOTAVAIL);
    }
    let mut g = TABLE.lock();
    let t = g.get();
    let Some(s) = t.slots.get_mut(usize::from(slot)) else {
        return Err(E_BAD_FD);
    };
    if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != gen {
        return Err(E_BAD_FD);
    }
    // 同端口重复绑定：本表没有"地址族共享"的概念，只查精确相同
    if local.port() != 0 {
        for (i, o) in t.slots.iter().enumerate() {
            if i == usize::from(slot) || o.used.load(Ordering::Acquire) == 0 {
                continue;
            }
            if o.local == local {
                return Err(E_ADDRINUSE);
            }
        }
    }
    t.slots[usize::from(slot)].local = local;
    Ok(())
}

/// `connect`：UDP 的 connect 只是记住默认对端。
pub fn connect(slot: u16, gen: u32, peer: SockAddr) -> Result<(), u64> {
    let mut g = TABLE.lock();
    let t = g.get();
    let Some(s) = t.slots.get_mut(usize::from(slot)) else {
        return Err(E_BAD_FD);
    };
    if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != gen {
        return Err(E_BAD_FD);
    }
    s.peer = peer;
    Ok(())
}

/// 取本地/对端端点（`send`/`recv` 用）。
pub fn endpoints(slot: u16, gen: u32) -> Result<(SockAddr, SockAddr), u64> {
    let mut g = TABLE.lock();
    let t = g.get();
    let Some(s) = t.slots.get(usize::from(slot)) else {
        return Err(E_BAD_FD);
    };
    if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != gen {
        return Err(E_BAD_FD);
    }
    Ok((s.local, s.peer))
}

/// 往接收队列里放一个数据报。队列满 ⇒ 丢新包，返回 `false`。
pub fn enqueue(dst_port: u16, src: SockAddr, payload: &[u8]) -> bool {
    let mut g = TABLE.lock();
    let t = g.get();
    // 找绑定在这个端口的 socket（端口 0 的 socket 收不到包）
    let Some(idx) = t.slots.iter().position(|s| {
        s.used.load(Ordering::Acquire) != 0 && s.local.port() == dst_port && dst_port != 0
    }) else {
        return false;
    };
    let s = &mut t.slots[idx];
    if s.rx_count.load(Ordering::Acquire) as usize >= SOCK_RX_QUEUE {
        return false;
    }
    let tail = s.rx_tail.load(Ordering::Acquire) as usize % SOCK_RX_QUEUE;
    let n = payload.len().min(UDP_PAYLOAD_MAX);
    s.rx[tail].src = src;
    s.rx[tail].len = n as u16;
    s.rx[tail].data[..n].copy_from_slice(&payload[..n]);
    s.rx_tail.store(((tail + 1) % SOCK_RX_QUEUE) as u32, Ordering::Release);
    s.rx_count.fetch_add(1, Ordering::Release);
    true
}

/// 从接收队列取一个数据报。空 ⇒ `None`（调用方回 `E_AGAIN`）。
pub fn dequeue(slot: u16, gen: u32, out: &mut [u8]) -> Result<(SockAddr, usize), u64> {
    let mut g = TABLE.lock();
    let t = g.get();
    let Some(s) = t.slots.get_mut(usize::from(slot)) else {
        return Err(E_BAD_FD);
    };
    if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != gen {
        return Err(E_BAD_FD);
    }
    if s.rx_count.load(Ordering::Acquire) == 0 {
        return Err(E_AGAIN);
    }
    let head = s.rx_head.load(Ordering::Acquire) as usize % SOCK_RX_QUEUE;
    let dg = s.rx[head];
    let n = (dg.len as usize).min(out.len());
    out[..n].copy_from_slice(&dg.data[..n]);
    s.rx_head.store(((head + 1) % SOCK_RX_QUEUE) as u32, Ordering::Release);
    s.rx_count.fetch_sub(1, Ordering::Release);
    Ok((dg.src, n))
}

/// 已用槽数（判据用）。
pub fn used() -> usize {
    let mut g = TABLE.lock();
    let t = g.get();
    t.slots.iter().filter(|s| s.used.load(Ordering::Acquire) != 0).count()
}

// ---------------------------------------------------------------- ADR-184：收包投递到 socket 队列

/// 把一帧收到的以太网帧**按协议分发**：UDP 进 socket 队列，其余忽略。
///
/// ## 为什么需要这个函数
///
/// ADR-181 建了 socket 队列（`socket::enqueue`），但**没有任何调用者** ——
/// 收了包不会进队列，`recv` 永远回 EAGAIN。这是那一轮留下的真实缺口。
///
/// ## 为什么不在中断里做
///
/// `socket::enqueue` 要取 `RANK_NET(36)` 锁。中断上下文里取它会与
/// `sys_sock_send`（持 36 的路径）形成跨上下文互等。
/// 所以本函数**只在 syscall 上下文**（`sys_sock_recv` 轮询时）调。
///
/// ## 返回值
///
/// 投递成功的**协议族**（4 或 6），`0` = 这帧不是我们能处理的 UDP。
#[cfg(feature = "handles")]
pub fn deliver_frame(f: &[u8]) -> u8 {
    use crate::network::socket::{enqueue, SockAddr};
    // IPv6 优先判：`0x86DD` 与 `0x0800` 首字节不同，不会误判
    if crate::network::ipv6::is_ipv6_frame(f) {
        // **先看是不是 NDP**（ICMPv6 58），是就处理并返回——NDP 不是 UDP，
        // 不能走下面的 UDP 解析。
        if f.len() > 14 + 6 && f[14 + 6] == crate::network::ndp::NEXT_HEADER_ICMPV6 {
            let our_mac = crate::virtio::net_info().map(|i| i.mac).unwrap_or([0u8; 6]);
            // 判属在**拿锁之前**做（`handle_frame` 内部不能查地址表，会同等级重入）
            let is_ours = crate::network::ndp::peek_ns_target(f)
                .map(|t| {
                    crate::network::ifaddr::addr_is_local(
                        &crate::network::ipv6::IpAddr::V6(t),
                    )
                })
                .unwrap_or(false);
            match crate::network::ndp::handle_frame(f, &our_mac, is_ours) {
                crate::network::ndp::NdAction::ReplyNa { dst_ip, dst_mac, target } => {
                    // **回 NA 必须在锁外**（`handle_frame` 已放锁）
                    let our_ip = crate::network::ipv6::link_local_from_mac(&our_mac);
                    let mut nf = [0u8; 256];
                    if let Some(n) = crate::network::ndp::build_na(
                        &mut nf, &our_mac, &our_ip, &dst_ip, &dst_mac, &target, true,
                    ) {
                        let _ = crate::virtio::send_raw(&nf[..n]);
                    }
                }
                crate::network::ndp::NdAction::None => {}
            }
            return 6;
        }
        if let Some((src, _dst, sp, dp, payload)) = crate::network::ipv6::parse_udp6_frame(f) {
            let ep = SockAddr::V6 { ip: src, port: sp };
            if enqueue(dp, ep, payload) {
                return 6;
            }
        }
        return 0;
    }
    if crate::network::ipv6::is_ipv4_frame(f) {
        if let Some((src, _dst, payload)) = crate::network::udp::parse_frame(f) {
            let ep = SockAddr::from_v4(src);
            if enqueue(_dst.port, ep, payload) {
                return 4;
            }
        }
        return 0;
    }
    0
}

/// 轮询一次网卡，把收到的 UDP 投递到 socket 队列。
///
/// 返回投递成功的帧数。`wait_ms = 0` 表示**不等待**（非阻塞轮询）。
///
/// ## 为什么用轮询而不是中断
///
/// virtio 的接收路径今天就是轮询式的（`receive(wait_ms)`）。
/// 改成中断要动 `RANK_NET` 的「是否在 ISR 取」那一格（`lock-order.md` 写明是「否」），
/// 那是另一件事——本轮先把「收了能进队列」打通。
#[cfg(feature = "handles")]
pub fn poll_once(wait_ms: u64) -> usize {
    bootstrap_addrs();
    if crate::virtio::bind_net().is_err() {
        return 0;
    }
    let mut delivered = 0usize;
    // 一次轮询最多处理 8 帧：队列深度是 8，超过没意义，而且拖长 syscall
    for _ in 0..8 {
        match crate::virtio::receive(wait_ms) {
            Ok((data, n, _uidx, _ulen, _uid)) => {
                if n == 0 {
                    break;
                }
                // 被动学 ARP（与 34 号同一条：原帧是 ARP 就按 sender 学）
                let _ = crate::virtio::arp_learn_from_frame(&data[..n]);
                if deliver_frame(&data[..n]) != 0 {
                    delivered += 1;
                }
            }
            Err(_) => break,
        }
        if wait_ms == 0 {
            // 非阻塞模式下不循环等：一次 receive 已经取了当前可取的帧
            break;
        }
    }
    delivered
}

// ---------------------------------------------------------------- ADR-185：地址表的惰性引导

/// 地址表是否已经引导过（避免每次 `bind` 都重复加）。
static ADDR_BOOTSTRAPPED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// 惰性引导地址表：把网卡 MAC 对应的链路本地 IPv6 地址与 DHCP 夹具的 IPv4 地址加进去。
///
/// ## 为什么在 socket 层而不在 `bind_net`
///
/// `bind_net` 在 `driver/virtio.rs`，而 `driver` 不该依赖 `network`（ADR-166 的方向是
/// `network → driver` 单向）。所以引导放在**用到地址的第一处**（`bind` 与 `poll_once`）。
///
/// ## 为什么 IPv4 用 `DHCP_GUEST_IP`
///
/// 那是 QEMU slirp 的固定地址（`dhcpstart=10.0.2.15`），也是 DHCP 夹具的期望值。
/// 真正的 DHCP 回填走 `dhcp_apply`——但那个要真的发一次 DHCP 请求，
/// 而今天没有任何路径自动做（ADR-185 未决 1）。
///
/// **所以这里是「静态引导 + DHCP 可覆盖」的混合**：先加夹具地址让 socket 能用，
/// 真跑到 DHCP 时 `dhcp_apply` 会再加一条（`addr_add` 幂等）。
pub fn bootstrap_addrs() {
    use crate::network::ifaddr::{addr_add, addr_count};
    use crate::network::ipv6::{link_local_from_mac, IpAddr};
    // **守卫看「表是否非空」，不看「跑过没有」**（ADR-185 实测）：
    //
    // 第一版用一个 `AtomicBool` 记住「跑过」，但 `t_ifaddr` 会 `addr_clear()`，
    // 之后 `bootstrap_addrs` 被守卫挡住不再填 ⇒ 后续 `bind` 全部 EADDRNOTAVAIL。
    // 表非空才是「已经有地址」的正确判据。
    if crate::network::ifaddr::addr_count() != 0 {
        return;
    }
    let mac = crate::virtio::net_info().map(|i| i.mac).unwrap_or([0u8; 6]);
    if mac == [0u8; 6] {
        // 网卡还没绑：不加（下次再试）
        return;
    }
    if addr_count() == 0 {
        // IPv4：QEMU slirp 的固定地址（`dhcpstart`）
        let _ = addr_add(IpAddr::V4(crate::network::dhcp::DHCP_GUEST_IP), 24, 0);
        // IPv6：链路本地（由 MAC 按 EUI-64 推出）
        let _ = addr_add(IpAddr::V6(link_local_from_mac(&mac)), 64, 0);
    }

}
