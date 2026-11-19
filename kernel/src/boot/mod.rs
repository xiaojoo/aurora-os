//! 引导层。`source_modules` 登记名仍是 `limine` / `boot_guard`（逻辑名不变，只改物理路径）。
//!
//! 收进来的理由：两者都在启动早期、都只依赖 `diagnostics` 与 `boot` 自身，
//! 与运行期的任何一次设备访问无关。

/// Limine 交接信息的规范化副本（启动期一次写入，之后只读）。
pub(crate) mod limine;
/// 启动循环保护与安全模式判定。
pub(crate) mod boot_guard;
