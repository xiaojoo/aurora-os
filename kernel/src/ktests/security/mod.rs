//! 签名、凭据与 SDK 样例（`.ktests` 段的一格）。
//!
//! 门控条件逐条照搬自重构前的 `ktests/mod.rs`——它决定这一档编译哪些用例，
//! 改它等于改判定表覆盖的用例集。

#[cfg(feature = "sig-check")]
mod sign;
#[cfg(feature = "handles")]
mod sdkdemo;
