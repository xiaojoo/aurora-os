//! 内存层。`mm` / `heap` / `vmo` / `sysinfo` 在这一层。
//!
//! 四者的共同点：它们都只回答"这块内存归谁"，不回答"哪个设备在用"。
//! `sysinfo` 放这里而不是 `diagnostics`：它读的是 `mm` 的页账，属于本层的出口。

pub(crate) mod heap;
pub(crate) mod mm;
pub(crate) mod sysinfo;
pub(crate) mod vmo;
