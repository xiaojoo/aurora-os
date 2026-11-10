//! 内核用例（T0.1 从 main.rs 纯搬移：只挪位置，不改判据）。

mod acpi;
mod boot;
pub(crate) mod common;
mod crash;
mod driver;
mod elf;
#[cfg(feature = "fat16-probe")]
mod fat16;
#[cfg(feature = "esp-probe")]
mod esp;
#[cfg(feature = "fat32-probe")]
pub(crate) mod fs;
#[cfg(feature = "gpt-probe")]
mod gpt;
mod heap;
mod mm;
#[cfg(feature = "virtio-net")]
mod net;
mod resource;
mod sched;
#[cfg(feature = "sig-check")]
mod sign;
mod state;
mod syscall;
mod time;
mod user;
#[cfg(feature = "virtio-blk")]
mod virtio;
mod watchdog;
