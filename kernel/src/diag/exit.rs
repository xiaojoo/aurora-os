//! 判定通道：把测试结果变成宿主进程退出码，不靠人看屏幕（手册 §12.2）。
//!
//! 依据 QEMU `hw/misc/debugexit.c`：写入端口后 QEMU 以 `(val << 1) | 1` 退出。
//! 该设备的**默认** iobase 是 0x501，本项目统一用 0xf4，且必须与运行脚本里
//! `-device isa-debug-exit,iobase=0xf4,iosize=0x04` 一致；改一处忘改另一处，
//! 内核会往不存在的端口写，测试既不失败也不通过，只能等到超时。

use crate::serial;
#[cfg(feature = "kdump")]
use core::sync::atomic::{AtomicUsize, Ordering};

const DEBUGEXIT_PORT: u16 = 0xf4;
#[cfg(feature = "kdump")]
static CAPTURE_ENTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Code {
    /// 全部通过 -> QEMU 退出码 33
    Success = 0x10,
    /// 有失败 -> 35
    Failed = 0x11,
    /// 启动信息不可信/无法继续 -> 37（与“测试失败”区分开，避免三种故障压成同一个红）
    BootInvalid = 0x12,
    /// 异常致命 -> 39
    ExceptionFatal = 0x13,
}

impl Code {
    /// QEMU 侧实际观察到的进程退出码，判定脚本按这张表比对
    pub const fn qemu_exit(self) -> i64 {
        ((self as u64) << 1 | 1) as i64
    }
}

#[cfg(feature = "kdump")]
pub fn install_capture_enter(entry: usize) {
    CAPTURE_ENTER.store(entry, Ordering::Release);
}

/// 写判定码并停住。若 QEMU 没带 debugexit 设备，这里会挂住，由外层超时判“挂死”，
/// 而不是误判成“通过”。
pub fn finish(code: Code) -> ! {
    if code == Code::ExceptionFatal {
        serial::unlock_for_halt();
        #[cfg(feature = "kdump")]
        {
            let entry = CAPTURE_ENTER.load(Ordering::Acquire);
            if entry == 0 {
                // 捕获上下文尚未初始化：不能跳入口，落到统一 39 出口并保留原因。
                serial::line("fatal", format_args!("kdump: capture 入口未安装"));
            } else {
                // SAFETY: 入口由 stage_memory 在 capture 初始化成功后安装；两个指针参数的 C ABI 表示相同。
                let enter: unsafe extern "C" fn(*const (), *const ()) -> ! =
                    unsafe { core::mem::transmute(entry) };
                // SAFETY: 软件 L4 出口处于 ring0，capture 栈与快照已由启动期初始化。
                unsafe { enter(core::ptr::null(), core::ptr::null()) };
            }
        }
        #[cfg(not(feature = "kdump"))]
        crate::crash::ensure_dumped();
    }
    // 停机的最后一格也记一笔（同样在串口写之前）：看到这一格却没有 `qemu-exit=` 行，
    // 卡点就在出口的串口写上，而不在崩溃落盘——那两个候选原来只有寄存器能分。
    crate::crash::mark_fatal(crate::crash::STAGE_EXIT_FINISH, code as u64, None);
    serial::line("exit", format_args!("qemu-exit={}", code.qemu_exit()));
    serial::out8(DEBUGEXIT_PORT, code as u8);
    crate::arch::x86_64::trap::halt_forever()
}

/// 启动阶段就无法继续：先尽量把原因打到串口，再给独立退出码
pub fn boot_invalid(reason: &str) -> ! {
    serial::line("fatal", format_args!("boot-invalid: {}", reason));
    finish(Code::BootInvalid)
}
