//! 测试基础设施：`.ktests` 段的注册原语。
//!
//! 只有 `ktest!` 宏与 `KTest` 结构——它必须住在 `testing` 逻辑模块里，
//! 因为 `check-module-interfaces` 按"产品路径"统计依赖边时会把 `ktests/*` 排除，
//! 而注册原语本身是产品代码（`main.rs` 会遍历那张表）。

pub(crate) mod ktest;
