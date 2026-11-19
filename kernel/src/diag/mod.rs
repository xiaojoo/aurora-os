//! 诊断层：串口、崩溃记录、退出码、持久状态区、看门狗。
//!
//! 这一层的共同点是**它们必须在别处坏了的时候还能工作**：
//! 串口是唯一权威判据通道，崩溃记录要在锁和调度器都不可信时写入，
//! 退出码是判定契约的端点，看门狗要在别人卡死时叫。

pub(crate) mod crash;
pub(crate) mod exit;
pub(crate) mod serial;
pub(crate) mod state_store;
pub(crate) mod watchdog;
