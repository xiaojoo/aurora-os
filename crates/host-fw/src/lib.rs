//! 最小防火墙的纯函数层（ADR-267，第一期 = UDP/NDP 入站无状态过滤）。
//!
//! ## 定位
//!
//! * 手册 S4.5 对策表那一句："规则引擎出现逃逸类漏洞 → 最小防火墙用**有界字节码 + 加载期验证**，
//!   先模糊测试再放开"。本 crate 就是那句话的落地：
//!   [`insn`] 定义极小指令集，[`verify`] 是加载期验证器（攻击面），[`exec`] 是有界执行器，
//!   [`rules`] 把五元组规则编译成字节码，[`parse`] 从以太网帧取五元组。
//! * **全部纯函数/纯数据**：不持锁、不分配、不碰设备、不读时钟、无 `unsafe`。
//!   帧与字节码的每一次读取都经 `get()`，没有下标访问 —— "任意输入不 panic"是构造性的。
//!
//! ## 有界性（核心不变量）
//!
//! 验证器接受的程序满足：①所有跳转目标**严格在后**（`target > pc`）且 `< len`；②最后一条是 `RET`。
//! 于是执行时 `pc` 每步严格递增、且不会越过最后一条 ⇒ **步数 ≤ len ≤ [`MAX_INSNS`] = 128**。
//! 执行器另有独立的步数预算 [`MAX_STEPS`]（= 128），对未经验证的输入也保证终止（纵深防御）。
//!
//! 证据（Python 等价移植，**不是 Rust 本身**）见 `verify/run_all.py` 与 README 验证表。
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod exec;
pub mod insn;
pub mod packet;
pub mod parse;
pub mod rules;
pub mod verify;

pub use exec::{run, run_raw, ExecFault, ExecOutcome, Verdict, MAX_STEPS};
pub use insn::{Insn, INSN_BYTES, MAX_INSNS, MAX_PROG_BYTES, NREGS};
pub use packet::{Dir, Packet};
pub use verify::{verify, verify_into, Program, VerifyError};

#[cfg(test)]
mod tests;
