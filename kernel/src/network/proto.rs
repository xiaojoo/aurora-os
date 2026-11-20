//! 协议层的**重导出层**（ADR-171）。
//!
//! 实现已按协议拆成 7 个文件：`eth` / `arp` / `ipv4` / `icmp` / `dns` / `dhcp` /
//! `arp_table`。这里把它们重新导出成原来那一层名字，**既有调用点一字不改**
//! （`driver/virtio.rs` 的 `pub use`、`main.rs`、`ktests/net/`）。
//!
//! **为什么不直接改调用点**：判定表第 32/33 行的帧对账按 `net: 帧 seq=…`
//! 这类中文锚点匹配，改调用点时容易连带改日志文本 ⇒ 判据静默读成零条。
//! 这一层就是那道缓冲：**路径不变、实现分开**。

pub use crate::network::arp::*;
pub use crate::network::arp_table::*;
pub use crate::network::dhcp::*;
pub use crate::network::dns::*;
pub use crate::network::eth::*;
pub use crate::network::icmp::*;
pub use crate::network::ipv4::*;
