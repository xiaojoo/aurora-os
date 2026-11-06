//! CPUID 特性检测（手册 §5.1）。
//!
//! 位号按 Intel SDM Vol.2A 的 CPUID 叶/位定义填写，**评审时逐项核对**；
//! 通用代码只依赖本结构，不依赖 CPU 型号。

#[derive(Debug, Clone, Copy, Default)]
pub struct CpuFeatures {
    pub nx: bool,
    pub smep: bool,
    pub smap: bool,
    pub pcid: bool,
    pub x2apic: bool,
    pub xsave: bool,
    pub rdrand: bool,
    pub tsc_inv: bool,
    /// SYSCALL/SYSRET（0x8000_0001 EDX bit11）。快路径是**可选特性**：缺失就不装 LSTAR，
    /// 由 `sys_abi_info()` 报 false，程序退回 `int 0x80`（不进 §5.1 的必需项清单）。
    pub syscall: bool,
}

pub fn detect() -> CpuFeatures {
    // CPUID 在本工具链版本里是安全函数；无内存副作用，且不依赖任何未初始化状态。
    let l1 = core::arch::x86_64::__cpuid(1);
    let l7 = core::arch::x86_64::__cpuid_count(7, 0);
    let ext = core::arch::x86_64::__cpuid(0x8000_0001);
    // 0x8000_0007 的 EDX bit8 = invariant TSC
    let ext7 = core::arch::x86_64::__cpuid(0x8000_0007);

    let bit = |v: u32, i: u32| -> bool { v & (1 << i) != 0 };
    CpuFeatures {
        nx: bit(ext.edx, 20),
        smep: bit(l7.ebx, 7),
        smap: bit(l7.ebx, 20),
        pcid: bit(l1.ecx, 17),
        x2apic: bit(l1.ecx, 21),
        xsave: bit(l1.ecx, 26),
        rdrand: bit(l1.ecx, 30),
        tsc_inv: bit(ext7.edx, 8),
        syscall: bit(ext.edx, 11),
    }
}

impl CpuFeatures {
    /// §5.1 的“必需（M4 起）”里 long mode/NX 这两条在本切片就要判：
    /// NX 缺失意味着页表执行位不可用，W^X 无从谈起。
    pub fn missing_required(&self) -> Option<&'static str> {
        if !self.nx {
            return Some("NX");
        }
        None
    }
}
