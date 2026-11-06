//! 判定通道：把测试结果变成宿主进程退出码，不靠人看屏幕（手册 §12.2）。
//!
//! 依据 QEMU `hw/misc/debugexit.c`：写入端口后 QEMU 以 `(val << 1) | 1` 退出。
//! 该设备的**默认** iobase 是 0x501，本项目统一用 0xf4，且必须与运行脚本里
//! `-device isa-debug-exit,iobase=0xf4,iosize=0x04` 一致；改一处忘改另一处，
//! 内核会往不存在的端口写，测试既不失败也不通过，只能等到超时。

use crate::serial;

const DEBUGEXIT_PORT: u16 = 0xf4;

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

/// 写判定码并停住。若 QEMU 没带 debugexit 设备，这里会挂住，由外层超时判“挂死”，
/// 而不是误判成“通过”。
pub fn finish(code: Code) -> ! {
    if code == Code::ExceptionFatal {
        // 行锁在这里放开并转入"不再排队"：崩溃那几行是这段话里最不能丢的，而此刻也没有
        // 别人该来抢这通道（别的 CPU 要么已经停机，要么正一起停机）。
        serial::unlock_for_halt();
        // §9.7：L4 是终点，所以崩溃摘要必须在停机之前尽力落盘。收口放在这里而不是每个
        // 调用点，是因为调用点会长（`mm::free_violation`、`heap` 的两处……）——漏掉一处的
        // 表现是"盘上安静地没有记录"，那种故障不会有别的尺子报出来。
        crate::crash::ensure_dumped();
    }
    serial::line("exit", format_args!("qemu-exit={}", code.qemu_exit()));
    serial::out8(DEBUGEXIT_PORT, code as u8);
    crate::trap::halt_forever()
}

/// 启动阶段就无法继续：先尽量把原因打到串口，再给独立退出码
pub fn boot_invalid(reason: &str) -> ! {
    serial::line("fatal", format_args!("boot-invalid: {}", reason));
    finish(Code::BootInvalid)
}
