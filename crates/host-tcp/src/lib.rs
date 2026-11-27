//! TCP 可靠性纯函数层（S2 步骤 7）。
//!
//! ## 定位（务必读）
//! * **并行新增，不替换** `kernel/src/network/tcp_conn.rs` 里的 `RetxState`：
//!   `socket.rs`（11 处）与 `ktests/syscall/user.rs`（32 处）直接用 `retx`/`arm_retx`/`ack_retx`/`on_retx_timeout`，
//!   `t_tcp_retx` 钉着 200 ms 初值/指数退避/6 次放弃。本 crate 先在宿主机把算法证明对，**接入内核是另一步**，
//!   且接入必须同步改 ADR-203 的判据口径（见 README 的“接入前置”）。
//! * 全部为**纯函数/纯数据**：不持锁、不碰表、不发包、不读时钟（时间由调用方以 µs 传入）。
//!
//! ## 序号比较
//! 一律用回绕安全的 `seq_lt/seq_le`（RFC 9293 §3.4：序号空间模 2^32）。
#![cfg_attr(not(test), no_std)]

pub mod rto;
pub mod retx;
pub mod window;
pub mod reasm;
pub mod cc;      // S4-1 NewReno（纯函数，未接线）
pub mod sack;    // S4-2 SACK（纯函数，未接线）
pub mod cookie;  // S4-3 SYN cookie（纯函数，未接线）
pub mod isn;     // S4-4 ISN/临时端口（已接线 kernel/network/isn_source.rs）

/// a < b（模 2^32）。
#[inline] pub fn seq_lt(a: u32, b: u32) -> bool { (a.wrapping_sub(b) as i32) < 0 }
/// a <= b（模 2^32）。
#[inline] pub fn seq_le(a: u32, b: u32) -> bool { (a.wrapping_sub(b) as i32) <= 0 }
/// a > b。
#[inline] pub fn seq_gt(a: u32, b: u32) -> bool { seq_lt(b, a) }
/// a >= b。
#[inline] pub fn seq_ge(a: u32, b: u32) -> bool { seq_le(b, a) }

#[cfg(test)]
mod tests;
