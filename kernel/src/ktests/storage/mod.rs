//! 块层与文件系统（`.ktests` 段的一格）。
//!
//! 门控条件逐条照搬自重构前的 `ktests/mod.rs`——它决定这一档编译哪些用例，
//! 改它等于改判定表覆盖的用例集。

#[cfg(feature = "fat32-probe")]
pub(crate) mod fs;
#[cfg(feature = "fat16-probe")]
mod fat16;
#[cfg(feature = "fs-open")]
mod fs_open;
#[cfg(feature = "fs-rw")]
mod fs_rw;
/// NVMe 上挂真卷（ADR-172）。与 `driver/nvme` 的三格是**不同层**的证据：
/// 设备能读扇区 != 那块盘上有能被解析的卷 != 文件内容对。
#[cfg(feature = "nvme")]
mod nvme_fat;
#[cfg(feature = "gpt-probe")]
mod gpt;
#[cfg(feature = "esp-probe")]
mod esp;
#[cfg(feature = "fs-ro")]
mod vfs_ro;
#[cfg(feature = "block-notify")]
mod block_notify;
