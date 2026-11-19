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
#[cfg(feature = "gpt-probe")]
mod gpt;
#[cfg(feature = "esp-probe")]
mod esp;
#[cfg(feature = "fs-ro")]
mod vfs_ro;
