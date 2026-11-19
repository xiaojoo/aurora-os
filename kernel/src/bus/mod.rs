//! 总线与固件表层：PCI 配置空间、ACPI 表形状、带边界检查的 MMIO 访问器。
//!
//! 三者同层是因为它们描述的是**同一件事的不同深度**：ACPI 说设备在哪条总线上、
//! PCI 说那台设备的 BAR 是什么形状、`hw` 说怎么安全地碰那几个寄存器。
//! 这一层不认识任何具体驱动。

pub(crate) mod acpi;
pub(crate) mod hw;
pub(crate) mod pci;
