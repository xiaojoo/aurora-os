//! 文件系统层（手册 §8.4「文件系统」那一节，任务 L3-C 的第一格）。
//!
//! 这一层只有一条依赖方向：**往下**通过 `vfs::Block` 要扇区，**不碰**任何具体驱动。
//! 建目录而不是平铺，是因为这一族的边界今天真的存在：`fat32` 不知道 AHCI 与 virtio 的区别，
//! 驱动不知道什么是目录项。

pub mod block_io;
pub mod fat32;
#[cfg(any(feature = "gpt-probe", feature = "fs-ro"))]
pub mod gpt;
pub mod vfs;
#[cfg(feature = "fs-open")]
pub mod part;
#[cfg(feature = "fs-ro")]
pub mod vfs_ro;
#[cfg(feature = "fs-open")]
pub mod fs_open;
#[cfg(feature = "fs-rw")]
pub mod fs_rw;
