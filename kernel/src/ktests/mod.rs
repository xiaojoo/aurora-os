//! 内核用例（`.ktests` 段）按域分文件夹。
//!
//! **顺序由链接器决定**，不是这里 `mod` 声明的顺序——用例必须自足，
//! 不能假设别的用例已经认领过设备（AGENTS.md 取证纪律）。
//! 这一层的 `mod` 声明只决定"哪些用例被编进这一档"，不决定它们跑的先后。

mod boot;
mod diag;
mod driver;
/// 显示与输入的端到端判据（ADR-170）。两个域以前只有解码/自报，没有端到端。
mod display;
mod memory;
mod net;
mod sched;
mod security;
pub(crate) mod storage;
mod syscall;

pub(crate) mod common;
