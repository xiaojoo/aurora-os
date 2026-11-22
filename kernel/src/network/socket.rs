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
pub const E_EXHAUSTED: u64 = u64::MAX - 5;   // -6  ENOMEM

/// 一个数据报在队列里的一份拷贝。
#[derive(Clone, Copy)]
pub struct Datagram {
    pub src: UdpEndpoint,
    pub len: u16,
    pub data: [u8; UDP_PAYLOAD_MAX],
}

const DG_EMPTY: Datagram = Datagram {
    src: UdpEndpoint { ip: [0; 4], port: 0 },
    len: 0,
    data: [0; UDP_PAYLOAD_MAX],
};

/// 一个 socket 槽。
pub struct Socket {
    used: AtomicU32,
    /// 世代号：槽复用后旧句柄必须失配（与 `Proc`/`Job` 同律）。
    gen: AtomicU32,
    domain: u16,
    ty: u16,
    /// 本地端点（`bind` 之后有效）。
    local: UdpEndpoint,
    /// 默认对端（`connect` 之后有效）。UDP 的 connect 只是记住对端。
    peer: UdpEndpoint,
    /// 接收队列头/尾与计数（环形）。
    rx_head: AtomicU32,
    rx_tail: AtomicU32,
    rx_count: AtomicU32,
    rx: [Datagram; SOCK_RX_QUEUE],
}

const SOCK_EMPTY: Socket = Socket {
    used: AtomicU32::new(0),
    gen: AtomicU32::new(0),
    domain: 0,
    ty: 0,
    local: UdpEndpoint { ip: [0; 4], port: 0 },
    peer: UdpEndpoint { ip: [0; 4], port: 0 },
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
/// `domain` 只收 `AF_INET`；`AF_INET6` 回 `E_NOSYS`（**不是** `E_INVAL`——
/// 调用方要能分辨「参数写错」与「这个族还没实现」，ADR-181 决策 2）。
/// `ty` 只收 `SOCK_DGRAM`；`SOCK_STREAM` 回 `E_NOSYS`（ADR-181 决策 1）。
pub fn create(domain: u16, ty: u16) -> Result<(u16, u32), u64> {
    if domain == AF_INET6 {
        return Err(E_NOSYS);
    }
    if domain != AF_INET {
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
    s.local = UdpEndpoint { ip: [0; 4], port: 0 };
    s.peer = UdpEndpoint { ip: [0; 4], port: 0 };
    s.rx_head.store(0, Ordering::Relaxed);
    s.rx_tail.store(0, Ordering::Relaxed);
    s.rx_count.store(0, Ordering::Relaxed);
    s.used.store(1, Ordering::Release);
    Ok((slot as u16, s.gen.load(Ordering::Acquire)))
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
pub fn bind(slot: u16, gen: u32, local: UdpEndpoint) -> Result<(), u64> {
    let mut g = TABLE.lock();
    let t = g.get();
    let Some(s) = t.slots.get_mut(usize::from(slot)) else {
        return Err(E_BAD_FD);
    };
    if s.used.load(Ordering::Acquire) == 0 || s.gen.load(Ordering::Acquire) != gen {
        return Err(E_BAD_FD);
    }
    // 同端口重复绑定：本表没有"地址族共享"的概念，只查精确相同
    if local.port != 0 {
        for (i, o) in t.slots.iter().enumerate() {
            if i == usize::from(slot) || o.used.load(Ordering::Acquire) == 0 {
                continue;
            }
            if o.local.port == local.port && o.local.ip == local.ip {
                return Err(E_ADDRINUSE);
            }
        }
    }
    t.slots[usize::from(slot)].local = local;
    Ok(())
}

/// `connect`：UDP 的 connect 只是记住默认对端。
pub fn connect(slot: u16, gen: u32, peer: UdpEndpoint) -> Result<(), u64> {
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
pub fn endpoints(slot: u16, gen: u32) -> Result<(UdpEndpoint, UdpEndpoint), u64> {
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
pub fn enqueue(dst_port: u16, src: UdpEndpoint, payload: &[u8]) -> bool {
    let mut g = TABLE.lock();
    let t = g.get();
    // 找绑定在这个端口的 socket（端口 0 的 socket 收不到包）
    let Some(idx) = t.slots.iter().position(|s| {
        s.used.load(Ordering::Acquire) != 0 && s.local.port == dst_port && dst_port != 0
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
pub fn dequeue(slot: u16, gen: u32, out: &mut [u8]) -> Result<(UdpEndpoint, usize), u64> {
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