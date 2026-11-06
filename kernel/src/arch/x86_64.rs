//! x86_64 的机器层。成员与文件的对应关系：
//! * `boot` 在 `crate::limine` + `crate::main` 的启动判定里（Limine 交接后的那段不属于架构层）
//! * `gdt/idt/interrupts/context` 全在 `trap`（异常桩、描述符表、上下文切换同一个文件，
//!   因为它们的字节布局是互相咬合的，拆开只会让"谁改了哪一格"跨三个文件对不上）
//! * `paging` 在 `crate::mm`（页表与 VMM/heap 的分配是同一本账）
//! * `apic` / `smp` / `cpu` / `cpuid` 各自一层
pub mod apic;
pub mod cpu;
pub mod cpuid;
pub mod smp;
pub mod trap;
