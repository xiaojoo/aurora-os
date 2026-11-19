//! 驱动框架、virtio、资源台账、看门狗（`.ktests` 段的一格）。
//!
//! 门控条件逐条照搬自重构前的 `ktests/mod.rs`——它决定这一档编译哪些用例，
//! 改它等于改判定表覆盖的用例集。

mod driver;
#[cfg(feature = "virtio-blk")]
mod virtio;
mod resource;
mod watchdog;
