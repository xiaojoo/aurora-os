//! capability 域：对象句柄表。
//!
//! 单独一个域而不是挂在 `security/` 下：`check-module-interfaces` 要求
//! `main.rs` 的每个顶层 `mod` **恰好被一个**逻辑模块覆盖。句柄表在登记表里
//! 是独立的 `capability` 逻辑模块（它的依赖边、锁等级 RANK_HANDLE=35、
//! 重入负样本都是单独维护的），所以物理上也单独一层。

#[cfg(feature = "handles")]
pub(crate) mod handle;
