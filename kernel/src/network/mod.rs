//! 网络协议层（ADR-166）。
//!
//! 这一层的边界：**只处理字节，不碰设备**。以太网/ARP/IPv4/ICMP/UDP/DNS/DHCP
//! 全部是纯函数——吃一个 `&[u8]` 与几个读数，吐一个解析结果或一个错误。
//! 收发由 `driver` 域的网卡驱动负责。
//!
//! 为什么单独成域而不是继续住在 `driver/virtio.rs` 里（ADR-166 决策 1）：
//!
//! 1. **一个文件两套职责**：`virtio.rs` 同时是 virtio 硬件驱动与协议栈，96 KiB；
//! 2. **物理网卡进来后必然重复**：e1000e/igb/rtl8139 都要引用同一份协议代码，
//!    而它们不属于 `driver/virtio.rs`；
//! 3. **TCP/Socket 还要加几百行**（syscall 48–55 已预留），塞不进去。
//!
//! 依赖方向是 **`network → driver`**（单向）：协议通过驱动的收发原语工作。
//! 所以这一层不反向引用驱动，而是让驱动把字节交上来。

pub mod proto;







/// 协议层的错误。**不复用 `VirtioError`**（那是硬件侧的）。
///
/// 为什么必须分开（ADR-166 未决 4 的落法）：协议函数原本返回 `VirtioError`，
/// 直接搬走会造出反向依赖（协议层反向引用驱动），而依赖方向应该是
/// `driver → network`（驱动把收到的字节交给协议层解）。
///
/// 每个变体都带**读数**：这条路径的全部意义是"为什么这一包没解出来"，
/// 不给读数就等于没诊断（与 `VirtioError::NotV4` 的 `guard` 同一口径）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    /// 缓冲短于这一层要求的最小长度。`at` 是长度门槛、`got` 是实际给的
    Short { at: usize, got: usize },
    /// 以太类型号不是我们认的那几种
    NotEtherType([u8; 2]),
    /// IPv4 头长/协议号不认。`guard` 点名是哪一格拒的
    /// （1 版本或头长、2 协议号、3 目的端口），否则红了只能说"不知道哪一格"
    NotV4 { at: usize, guard: u8 },
    /// 校验和不符（IPv4 头校验和、ICMP 校验和）
    BadChecksum { want: u16, got: u16 },
    /// 名字编码/解码超出缓冲
    NameTooLong { need: usize, have: usize },
    /// 设备侧没在时限内交上数据（由驱动翻译后交给协议层）
    Timeout,
}

impl NetError {
    /// 人话描述。**只给成因，不给建议**——建议由调用方按上下文决定。
    pub fn describe(e: NetError) -> &'static str {
        match e {
            NetError::Short { .. } => "缓冲比这一层要求的最小长度还短",
            NetError::NotEtherType(_) => "以太类型号不是我们认的那几种",
            NetError::NotV4 { .. } => "不是 IPv4/UDP/BOOTP（guard 点名是哪一格）",
            NetError::BadChecksum { .. } => "校验和不符",
            NetError::NameTooLong { .. } => "名字编码超出缓冲",
            NetError::Timeout => "设备侧没在时限内交上数据",
        }
    }
}
