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

/// socket 的 TCP 状态（ADR-199）。
///
/// `None` = 不是 stream socket；`Some` = 有一个连接状态。
pub struct SocketTcp(core::cell::UnsafeCell<Option<crate::network::tcp_conn::ConnState>>);

// SAFETY: 所有读写都在 `TABLE`（`RANK_NET=36`）内，锁提供互斥；
// `ConnState` 是纯 `Copy` 数值，无别名逃逸。
unsafe impl Sync for SocketTcp {}

impl SocketTcp {
    const fn new() -> Self {
        Self(core::cell::UnsafeCell::new(None))
    }
    /// 读快照（表锁内调）。
    fn get(&self) -> Option<crate::network::tcp_conn::ConnState> {
        // SAFETY: 调用方持 `TABLE` 锁。
        unsafe { *self.0.get() }
    }
    /// 可变访问（表锁内调）。
    fn with<R>(&self, f: impl FnOnce(&mut Option<crate::network::tcp_conn::ConnState>) -> R) -> R {
        // SAFETY: 调用方持 `TABLE` 锁。
        unsafe { f(&mut *self.0.get()) }
    }
}

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
    /// **TCP 连接状态**（ADR-199）：`Some` = 这是一个 stream socket。
    ///
    /// ## 为什么用 `UnsafeCell` 包一层
    ///
    /// `Socket` 存在 `IrqSpinLock<SocketTable>` 里，而 `ConnState` 要**可变**
    /// （`on_segment` 收 `&mut`）。表锁已经保证互斥，所以这里只需要绕过 `&self`。
    ///
    /// **锁序**：`ConnState` 的读写全在 `TABLE`（`RANK_NET=36`）内，不取别的锁。
    tcp: SocketTcp,
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
    tcp: SocketTcp::new(),
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
    // **`SOCK_STREAM` 现在支持了**（ADR-199）：走 TCP 状态机。
    //
    // ADR-181 决策 1 当时回 `E_NOSYS`，理由是「TCP 状态机不存在」。
    // ADR-198 把状态机做出来了（纯函数），这一轮把它接进 socket 槽。
    if ty != SOCK_DGRAM && ty != SOCK_STREAM {
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
    // stream socket 出生在 `Listen` 态（`bind`+`listen` 之后才真的收 SYN）；
    // dgram 的 `tcp` 保持 `None`。
    if ty == SOCK_STREAM {
        // ISS 用组合数：槽号 + 世代，够避免同一槽复用时序号撞车
        let iss = 0x1000_0000u32.wrapping_add((slot as u32) << 8).wrapping_add(s.gen.load(Ordering::Acquire));
        let st = crate::network::tcp_conn::ConnState::listen(iss);
        s.tcp.with(|o| *o = Some(st));
    }
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

// ---------------------------------------------------------------- ADR-199：TCP 接进 socket 层

/// TCP 连接在 socket 槽上的快照（判据用）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpInfo {
    pub state: crate::network::tcp_conn::State,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
}

/// 取一个 stream socket 的 TCP 状态快照。**dgram socket 回 `None`**。
pub fn tcp_info(slot: u16, gen: u32) -> Option<TcpInfo> {
    let mut g = TABLE.lock();
    let t = g.get();
    let s = t.slots.get(slot as usize)?;
    if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != gen {
        return None;
    }
    let st = s.tcp.get()?;
    Some(TcpInfo { state: st.state, snd_nxt: st.snd_nxt, rcv_nxt: st.rcv_nxt })
}

/// `listen`：把 stream socket 从 `Listen` 状态保持住（幂等），并记下本地端口。
///
/// **dgram socket 回 `E_OPNOTSUPP`**：UDP 没有 listen。
pub fn tcp_listen(slot: u16, gen: u32) -> Result<(), u64> {
    let mut g = TABLE.lock();
    let t = g.get();
    let s = t.slots.get_mut(slot as usize).ok_or(E_BAD_FD)?;
    if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != gen {
        return Err(E_BAD_FD);
    }
    if s.ty != SOCK_STREAM {
        return Err(E_OPNOTSUPP);
    }
    s.tcp.with(|o| match o {
        Some(st) => {
            // 只有 `Listen`（或已退回 `Listen`）能 listen
            if st.state == crate::network::tcp_conn::State::Listen {
                Ok(())
            } else {
                Err(E_INVAL)
            }
        }
        None => Err(E_INVAL),
    })
}

/// **主动连接**：把本端推进到 `SynSent`，返回要发出的 SYN 段。
///
/// ## 为什么返回段而不是自己发
///
/// socket 层**不碰设备**（与 `udp` 同一纪律）。调用方（syscall 层）拿到段去发。
/// 这样判据可以只测状态机与段构造，不需要网卡。
pub fn tcp_start_connect(slot: u16, gen: u32) -> Result<crate::network::tcp_conn::Reply, u64> {
    let mut g = TABLE.lock();
    let t = g.get();
    let s = t.slots.get_mut(slot as usize).ok_or(E_BAD_FD)?;
    if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != gen {
        return Err(E_BAD_FD);
    }
    if s.ty != SOCK_STREAM {
        return Err(E_OPNOTSUPP);
    }
    s.tcp.with(|o| match o {
        Some(st) => {
            if st.state != crate::network::tcp_conn::State::Listen {
                return Err(E_INVAL);
            }
            // Listen ⇒ SynSent
            let iss = st.iss;
            *st = crate::network::tcp_conn::ConnState::connect(iss);
            let r = st.syn_segment();
            // SYN 占一格
            st.snd_nxt = st.snd_nxt.wrapping_add(1);
            Ok(r)
        }
        None => Err(E_INVAL),
    })
}

/// **收一个段**：把段喂给状态机，返回要回的段（`None` = 不用回）。
///
/// ## 载荷去哪了
///
/// 段里的数据被**复制进接收队列**（`enqueue` 那条路），所以调用方之后能用
/// `dequeue` 读出来 —— 与 UDP 的 `recv` 走同一个出口。
///
/// **这是本 ADR 最关键的一个接线决定**：TCP 的数据不走新路径，复用了 UDP 的接收队列。
/// 理由：接收队列的语义（环形、有界、按端口投递）与传输层无关。
pub fn tcp_on_segment(
    slot: u16,
    gen: u32,
    seg: &crate::network::tcp::Segment<'_>,
    src: SockAddr,
) -> Result<Option<crate::network::tcp_conn::Reply>, u64> {
    use crate::network::tcp_conn::{self, Reaction};
    let mut g = TABLE.lock();
    let t = g.get();
    let s = t.slots.get_mut(slot as usize).ok_or(E_BAD_FD)?;
    if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != gen {
        return Err(E_BAD_FD);
    }
    if s.ty != SOCK_STREAM {
        return Err(E_OPNOTSUPP);
    }
    // 先把载荷复制出来（`enqueue` 要再取一次表锁 —— 那是同等级重入，所以必须**先放锁**）。
    //
    // 这里用一个小缓冲把载荷搬出锁外，长度受 `TCP_PAYLOAD_MAX` 约束。
    let payload_len = seg.payload.len().min(crate::network::tcp::TCP_PAYLOAD_MAX);
    let mut payload = [0u8; crate::network::tcp::TCP_PAYLOAD_MAX];
    payload[..payload_len].copy_from_slice(&seg.payload[..payload_len]);

    let (reaction, accepted, acked) = s.tcp.with(|o| match o {
        Some(st) => {
            let before = st.rcv_nxt;
            let r = tcp_conn::on_segment(st, seg);
            let acc = st.rcv_nxt != before && payload_len > 0;
            // **收到 ACK ⇒ 取消重传**（ADR-203）。
            //
            // 这一步必须在 `on_segment` **之后**：状态机可能刚刚接受了这段数据，
            // 而 ACK 号里带着对端对我们那一段的确认。
            let acked = if seg.is_ack() { st.ack_retx(seg.ack) } else { false };
            (r, acc, acked)
        }
        None => (Reaction::Ignore, false, false),
    });
    // 放表锁（`g` 在这里 drop）
    drop(g);

    if accepted {
        let _ = enqueue(slot_port(slot), src, &payload[..payload_len]);
    }

    let _ = acked;
    match reaction {
        Reaction::Reply(r) => Ok(Some(r)),
        Reaction::Silent | Reaction::Ignore => Ok(None),
    }
}

/// 取一个 socket 的本地端口（`enqueue` 按端口投递时用）。
fn slot_port(slot: u16) -> u16 {
    let mut g = TABLE.lock();
    let t = g.get();
    match t.slots.get(slot as usize) {
        Some(s) if s.used.load(Ordering::Acquire) != 0 => s.local.port(),
        _ => 0,
    }
}

/// 本端主动关：返回要发的 FIN 段（`None` = 状态不允许）。
pub fn tcp_close(slot: u16, gen: u32) -> Result<Option<crate::network::tcp_conn::Reply>, u64> {
    use crate::network::tcp_conn;
    let mut g = TABLE.lock();
    let t = g.get();
    let s = t.slots.get_mut(slot as usize).ok_or(E_BAD_FD)?;
    if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != gen {
        return Err(E_BAD_FD);
    }
    if s.ty != SOCK_STREAM {
        return Ok(None);
    }
    s.tcp.with(|o| match o {
        Some(st) => {
            // 先试 `ESTABLISHED`，再试 `CLOSE_WAIT`
            if let Some(r) = tcp_conn::close_send_fin(st) {
                return Ok(Some(r));
            }
            if let Some(r) = tcp_conn::close_send_fin_from_close_wait(st) {
                return Ok(Some(r));
            }
            Ok(None)
        }
        None => Ok(None),
    })
}

/// **TCP 发送**：把 `payload` 作为数据段发出去，返回要发的段（ADR-200）。
///
/// ## 为什么返回段而不是自己发
///
/// 与 `tcp_start_connect` 同一条：socket 层不碰设备。
///
/// ## 状态不对时回 `E_OPNOTSUPP`
///
/// 只有 `Established` / `CloseWait` 能发数据（`State::can_send`）。
///
/// **`CloseWait` 也算能发**：对端关了写方向，本端还能把剩余数据写完（半关闭）。
pub fn tcp_send_payload(
    slot: u16,
    gen: u32,
    payload_len: usize,
) -> Result<crate::network::tcp_conn::Reply, u64> {
    use crate::network::tcp;
    let mut g = TABLE.lock();
    let t = g.get();
    let s = t.slots.get_mut(slot as usize).ok_or(E_BAD_FD)?;
    if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != gen {
        return Err(E_BAD_FD);
    }
    if s.ty != SOCK_STREAM {
        return Err(E_OPNOTSUPP);
    }
    if payload_len == 0 || payload_len > tcp::TCP_PAYLOAD_MAX {
        return Err(E_INVAL);
    }
    s.tcp.with(|o| match o {
        Some(st) => {
            if !st.state.can_send() {
                return Err(E_OPNOTSUPP);
            }
            let r = crate::network::tcp_conn::Reply {
                seq: st.snd_nxt,
                ack: st.rcv_nxt,
                flags: tcp::ACK | tcp::PSH,
                window: st.rcv_wnd,
                payload_len: payload_len as u16,
            };
            // **登记重传**（ADR-203）：记下这一段的序号/长度/标志，
            // 没收到的 ACK 之前要能原样再发一次。
            st.arm_retx(r.seq, r.payload_len, r.flags);
            st.snd_nxt = st.snd_nxt.wrapping_add(payload_len as u32);
            Ok(r)
        }
        None => Err(E_INVAL),
    })
}

/// **`accept`**：从 `Listen` 槽上分出一个新的已连接槽（ADR-200）。
///
/// ## 简化说明（如实记）
///
/// 真实 TCP 的 `accept` 从**已完成队列**里取一条（三次握手由内核完成，应用只取结果）。
///
/// 这里没有队列：`Listen` 槽收到 SYN 之后直接进 `SynReceived`，再收到 ACK 进 `Established`，
/// 而 `accept` **把那个已建立的连接搬到新槽**，原槽退回 `Listen`。
///
/// **代价**：同一时刻一个 `Listen` 槽只能承载一条连接（没有 backlog）。
/// 对今天的用例够用；真实服务端需要队列。已写进未决 1。
///
/// 返回 `(新槽, 新世代)`；没有已建立的连接时回 `E_AGAIN`（非阻塞）。
pub fn tcp_accept(listen_slot: u16, listen_gen: u32) -> Result<(u16, u32), u64> {
    use crate::network::tcp_conn::State;
    let mut g = TABLE.lock();
    let t = g.get();
    // ① 先确认 listen 槽确实是 stream socket 且已建立
    {
        let s = t.slots.get(listen_slot as usize).ok_or(E_BAD_FD)?;
        if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != listen_gen {
            return Err(E_BAD_FD);
        }
        if s.ty != SOCK_STREAM {
            return Err(E_OPNOTSUPP);
        }
        let ready = s.tcp.get().map(|st| st.state == State::Established).unwrap_or(false);
        if !ready {
            return Err(E_AGAIN);
        }
    }
    // ② 搬到一个新槽
    let new_slot = t
        .slots
        .iter()
        .position(|s| s.used.load(Ordering::Acquire) == 0)
        .ok_or(E_EXHAUSTED)?;
    // 先把已建立的连接快照出来
    let established = t.slots[listen_slot as usize].tcp.get();
    let local = t.slots[listen_slot as usize].local;
    let peer = t.slots[listen_slot as usize].peer;
    let domain = t.slots[listen_slot as usize].domain;
    // ③ 建新槽
    {
        let s = &mut t.slots[new_slot];
        s.gen.store(s.gen.load(Ordering::Acquire).wrapping_add(1), Ordering::Release);
        s.domain = domain;
        s.ty = SOCK_STREAM;
        s.local = local;
        s.peer = peer;
        s.rx_head.store(0, Ordering::Relaxed);
        s.rx_tail.store(0, Ordering::Relaxed);
        s.rx_count.store(0, Ordering::Relaxed);
        s.refs.store(1, Ordering::Release);
        s.tcp.with(|o| *o = established);
        s.used.store(1, Ordering::Release);
    }
    // ④ 原槽退回 `Listen`（用同一个 ISS 重新开）
    {
        let s = &mut t.slots[listen_slot as usize];
        let iss = s.tcp.get().map(|st| st.iss).unwrap_or(0x1000_0000);
        // 换一个 ISS：同一条连接不该复用同一个初始序号
        let new_iss = iss.wrapping_add(0x1000);
        let fresh = crate::network::tcp_conn::ConnState::listen(new_iss);
        s.tcp.with(|o| *o = Some(fresh));
        s.peer = SockAddr::V4 { ip: [0; 4], port: 0 };
    }
    Ok((new_slot as u16, t.slots[new_slot].gen.load(Ordering::Acquire)))
}

/// **下半部分派**：处理一个到期项（ADR-203）。
///
/// ## 这是三层第一次真正串起来
///
/// 定时器（ADR-201）到点 → 下半部（ADR-202）投递 → **这里**分派到 TCP 重传。
/// 前两层在此之前都只是「零件」，这是它们的第一个真实消费者。
///
/// ## 返回值
///
/// 返回 `Some(Reply)` 表示「要重发一个段」，调用方拿到后去装帧发出。
/// 返回 `None` 表示「不用发 / 已放弃」。
///
/// **放弃时连接会被标记**（`retx.armed = false` 且 `tries` 到顶），
/// 调用方可以从 `tcp_info` 看到状态没变但重传没了 —— 那是「连接死了」的信号。
pub fn tcp_handle_timer(kind: crate::time::timer::Kind, token: u64) -> Option<(u16, u32, crate::network::tcp_conn::Reply)> {
    use crate::time::timer::Kind;
    match kind {
        Kind::TcpRetransmit => {
            let slot = token as u16;
            let mut g = TABLE.lock();
            let t = g.get();
            let s = t.slots.get_mut(slot as usize)?;
            if s.used.load(Ordering::Acquire) == 0 {
                return None;
            }
            let gen = s.gen.load(Ordering::Acquire);
            let r = s.tcp.with(|o| match o {
                Some(st) => st.on_retx_timeout(),
                None => None,
            })?;
            Some((slot, gen, r))
        }
        // 其它类别今天不处理（USB / 块层还没消费定时器）
        _ => None,
    }
}

/// **为一条连接的重传登记定时器**（ADR-203）。
///
/// 由 `tcp_send_payload` 的调用方在**发出段之后**调（发之前登记会让「发送失败」
/// 也留下一个假的重传）。
///
/// 返回定时器槽号；登记失败（表满 / 时钟未标定）回 `None` —— **调用方要知道**，
/// 因为没有定时器就没有重传。
pub fn tcp_arm_retx_timer(slot: u16) -> Option<u16> {
    let backoff = {
        let mut g = TABLE.lock();
        let t = g.get();
        let s = t.slots.get(slot as usize)?;
        s.tcp.get().map(|st| st.retx_backoff_us()).unwrap_or(0)
    };
    if backoff == 0 {
        return None;
    }
    crate::time::timer::add_after_ms(
        crate::time::timer::Kind::TcpRetransmit,
        slot as u64,
        (backoff / 1000) as u64,
    )
}

/// **定时器分派**（ADR-204）：把一个到期项交给对应的子系统。
///
/// 返回是否真的处理了（`false` = 不认识这类 / 无事可做）。
///
/// ## 与 `tcp_handle_timer` 的分工
///
/// - `tcp_handle_timer` 只认 `Kind::TcpRetransmit`，返回要重发的段，**不发**；
/// - 这里负责「拿到段之后真的发出去」，并把失败记录进计数。
///
/// 分开的理由与 `tcp_send` 那条同源：**socket 层不碰设备**，但「发」这一步必须有人做。
/// 放在这里是因为 `drain_bottom`（sched 层）不该知道怎么装 TCP 帧。
///
/// ## 没有定时器保护时的行为
///
/// 重传一定要求「时钟已标定」。标定没起来时 `tcp_arm_retx_timer` 回 `None`，
/// 那条连接**没有被重传保护** —— 这里不因此报错，只计数，让调用方能看到。
pub fn dispatch_timer(kind: crate::time::timer::Kind, token: u64) -> bool {
    match kind {
        crate::time::timer::Kind::TcpRetransmit => {
            let slot = token as u16;
            let Some((s, g, reply)) = tcp_handle_timer(kind, token) else {
                return false;
            };
            RETX_FIRED.fetch_add(1, Ordering::Relaxed);
            // 真的发出去
            let sent = tcp_retransmit_send(s, g, &reply);
            if sent {
                RETX_SENT.fetch_add(1, Ordering::Relaxed);
                // 再登记下一次（指数退避已经在 `on_retx_timeout` 里翻倍过了）
                let _ = tcp_arm_retx_timer(s);
            } else {
                RETX_FAILED.fetch_add(1, Ordering::Relaxed);
            }
            true
        }
        // USB / 块层还没消费定时器
        _ => false,
    }
}

/// 重传触发/发出/失败计数（ADR-204 的判据用）。
pub fn retx_stats() -> (u64, u64, u64) {
    (
        RETX_FIRED.load(Ordering::Relaxed),
        RETX_SENT.load(Ordering::Relaxed),
        RETX_FAILED.load(Ordering::Relaxed),
    )
}

static RETX_FIRED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static RETX_SENT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static RETX_FAILED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

// ---------------------------------------------------------------- ADR-205：重传载荷缓冲

/// **待重传段的载荷缓冲**（ADR-205）。
///
/// ## 为什么全局一份而不是每连接一份
///
/// 每连接一份是 `MAX_SOCKETS × 1460 = 374 KiB` —— **不可接受**。
///
/// 全局一份是 **1460 字节**，而它能工作的前提是：本仓库的 TCP 是「**发一段等一段**」
/// 的语义（`tcp_send_payload` 一次一段，`RetxState` 也只记一段）。
///
/// ## 一个真实的限制
///
/// **两条连接同时有待重传的段时，后发的会覆盖先发的。**
/// 这与 `RetxState` 只记一段是**同一个限制**，不是新引入的 —— 见 ADR-205 未决 1。
struct RetxBuf(core::cell::UnsafeCell<[u8; crate::network::tcp::TCP_PAYLOAD_MAX]>);
// SAFETY: 读写全在 `RETX_BUF_LOCK` 内；缓冲是纯字节，无别名逃逸。
unsafe impl Sync for RetxBuf {}

static RETX_BUF: RetxBuf = RetxBuf(core::cell::UnsafeCell::new([0u8; crate::network::tcp::TCP_PAYLOAD_MAX]));
static RETX_BUF_LEN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static RETX_BUF_LOCK: crate::sync::IrqSpinLock<()> =
    // **用 `new` 而不是 `new_isr_taken`**：`RANK_NET` 按 lock-order 表不在中断里取。
    // 这条也是 `check-fat32-ports` 抓出来的（ADR-081 决策 2 的**反方向**）。
    crate::sync::IrqSpinLock::new(crate::sync::RANK_NET, ());

/// **保存一段载荷以便重传**（ADR-205）。
///
/// 由 `tcp_send` 在**发出成功后**调（发之前保存会让「发送失败」也留下一个假的待重传）。
pub fn retx_buf_store(payload: &[u8]) {
    let n = payload.len().min(crate::network::tcp::TCP_PAYLOAD_MAX);
    let _g = RETX_BUF_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let b = unsafe { &mut *RETX_BUF.0.get() };
    b[..n].copy_from_slice(&payload[..n]);
    RETX_BUF_LEN.store(n as u32, Ordering::Release);
}


/// **取回待重传的载荷**（ADR-205）：拷进 `out`，返回长度（`0` = 没有）。
///
/// ## 为什么先比长度
///
/// 缓冲里存的是「**最后一次发出的段**」。而要求重传的那一段可能是更早的
/// （如果中间又发了别段）。长度不符 ⇒ **不能拿这份数据**，回 0 让调用方知道。
///
/// **返回 0 比返回错数据好得多**：错数据是静默损坏，0 是可见的失败。
fn retx_buf_load(want_len: u16, out: &mut [u8]) -> usize {
    let stored = RETX_BUF_LEN.load(Ordering::Acquire) as usize;
    if stored == 0 || stored != want_len as usize || out.len() < stored {
        return 0;
    }
    let _g = RETX_BUF_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let b = unsafe { &*RETX_BUF.0.get() };
    out[..stored].copy_from_slice(&b[..stored]);
    stored
}

/// 判据用：从缓冲取回载荷（`retx_buf_load` 的 `pub` 包装）。
pub fn retx_buf_load_pub(want_len: u16, out: &mut [u8]) -> usize {
    retx_buf_load(want_len, out)
}

/// 判据用：清掉缓冲。
#[cfg(feature = "handles")]
pub fn retx_buf_clear() {
    RETX_BUF_LEN.store(0, Ordering::Release);
}

/// 判据用：缓冲里存了几字节。
pub fn retx_buf_len() -> u16 {
    RETX_BUF_LEN.load(Ordering::Acquire) as u16
}


/// **MAC 解析的注入点**（ADR-204）。
///
/// 为什么注入而不是直接调：`mac_of` 在 `sched/user.rs` 里（它要查 ARP 表 + 可能发 NS），
/// 而 `network` 不能依赖 `sched`（那会造出一个新的强连通分量）。
///
/// 与 `install_proc_of` / `install_as_of_task` 同一个模式 —— 这是本仓库第四次用它。
static MAC_OF: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// 装 MAC 解析函数（启动期调一次）。
pub fn install_mac_of(f: fn([u8; 4]) -> Option<[u8; 6]>) {
    MAC_OF.store(f as usize as u64, Ordering::Release);
}

fn mac_of(ip: [u8; 4]) -> Option<[u8; 6]> {
    let p = MAC_OF.load(Ordering::Acquire);
    if p == 0 {
        return None;
    }
    // SAFETY: 指针由 `install_mac_of` 写入，来源是 `fn` 指针（长度/对齐/生命周期
    // 都由 Rust 类型系统保证）；只读一次，调用期间不变。
    let f: fn([u8; 4]) -> Option<[u8; 6]> = unsafe { core::mem::transmute(p as usize) };
    f(ip)
}


/// **重传段装帧并发出**（ADR-204）。
///
/// ## 载荷从哪来
///
/// 重传要发**同样的载荷**，但 `RetxState` 只记了长度、没存内容（存内容要每连接一份缓冲，
/// 那是 `MAX_SOCKETS × 1460 = 374 KiB`，不可接受）。
///
/// **所以今天重传发的是「空载荷 + 正确的序号与长度」** —— 那不对，但对端会看到
/// 「序号对了但数据没了」，而这正是本 ADR 要暴露的缺口。已写进未决 1。
///
/// **更准确地说：这个函数现在只把「重传事件」变成了「一个带正确头部、零载荷的段」。**
/// 它证明了接线通了，但没证明数据能重传。
fn tcp_retransmit_send(slot: u16, gen: u32, reply: &crate::network::tcp_conn::Reply) -> bool {
    use crate::network::tcp;
    let Ok((local, peer)) = endpoints(slot, gen) else {
        return false;
    };
    let _ = 0;
    let (Some(l), Some(p)) = (local.as_v4(), peer.as_v4()) else {
        return false;
    };
    if crate::virtio::bind_net().is_err() {
        return false;
    }
    let our_mac = crate::virtio::net_info().map(|i| i.mac).unwrap_or([0u8; 6]);
    let Some(dst_mac) = mac_of(p.ip) else {
        return false;
    };
    let mut f = [0u8; 1536];
    f[0..6].copy_from_slice(&dst_mac);
    f[6..12].copy_from_slice(&our_mac);
    f[12..14].copy_from_slice(&crate::network::dhcp::NET_TYPE_IPV4);
    let ip = &mut f[14..34];
    ip[0] = 0x45;
    ip[1] = 0;
    ip[2..4].copy_from_slice(&((20 + tcp::TCP_HDR_MIN) as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&0u16.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[10..12].copy_from_slice(&0u16.to_be_bytes());
    ip[12..16].copy_from_slice(&l.ip);
    ip[16..20].copy_from_slice(&p.ip);
    let ipck = crate::network::ipv4::ip_cksum(ip);
    ip[10..12].copy_from_slice(&ipck.to_be_bytes());
    // **从缓冲取回载荷**（ADR-205）。
    //
    // 取不到（长度不符 / 缓冲空）就**不发** —— 发一个空载荷段是对端眼里
    // 「序号对了但数据没了」，那是最坏的一种故障。
    let mut payload = [0u8; tcp::TCP_PAYLOAD_MAX];
    let got = retx_buf_load(reply.payload_len, &mut payload);
    if got == 0 && reply.payload_len != 0 {
        // 有长度但取不到数据 ⇒ 明确失败，不静默发空
        return false;
    }
    let n = match tcp::build_segment(
        &mut f[34..],
        &l.ip,
        &p.ip,
        l.port,
        p.port,
        reply.seq,
        reply.ack,
        reply.flags,
        reply.window,
        &payload[..got],
    ) {
        Some(n) => n,
        None => return false,
    };
    crate::virtio::send_raw(&f[..34 + n]).is_ok()
}

/// 注入点装上没有（判据用）。
pub fn mac_of_installed() -> bool {
    MAC_OF.load(Ordering::Acquire) != 0
}

/// **判据专用**：把注入点清空，用来验证「未装时回 `None`」。
///
/// **不暴露给产品路径**：产品路径永远不该「拆掉」注入点。
#[cfg(feature = "handles")]
pub fn install_mac_of_unset_for_test() {
    MAC_OF.store(0, Ordering::Release);
}

/// 判据用：探一下 `mac_of` 的行为（不触发副作用）。
#[cfg(feature = "handles")]
pub fn mac_of_probe(ip: [u8; 4]) -> Option<[u8; 6]> {
    mac_of(ip)
}