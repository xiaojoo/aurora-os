//! A2 切片（ADR-130）：**第一个经 A2 语义启动的外部 ELF**。
//!
//! 与 fileprobe/shell 的差别在"输入从哪来"：
//! - 旧路径：`find_console` 按 ROLE_LOG 找控制台，参数不存在；
//! - **本片（A2 语义）**：stdin/stdout/stderr 由创建方经 16 号 transfer 以
//!   `ROLE_STDIN/STDOUT/STDERR` 转移进来（不再认 ROLE_LOG），argv 从 SI 页的
//!   args 区（`SI_OFF_ARGS_OFF/LEN`，ADR-130 赋义）读出。
//!
//! 行为：读 argv → 把 `execprobe: argv[0]=<首串>` 写到**继承的 stdout** →
//! `exit(7)`。退出码 7 是判定行的特征值：内核 init 侧收尸读退出码，串口与
//! 退出码双锚点互相独立，一条缺席另一条仍能指认。
//!
//! 全部 syscall 走 `aurora-user-runtime`（A2 接线后的底座），本文件 unsafe 只剩
//! 对 runtime 两个 unsafe fn（`handle_of_role` / `args_at`）的调用。

#![no_std]
#![no_main]

use aurora_user_runtime as rt;

// 提示串是 **static blob + RIP 相对 lea 取基址**，不用字符串字面量——镜像基址在
// 4 GiB 之上，字面量地址会退化成 R_X86_64_32S 绝对重定位，链接期 out of range
// （shell 的 MSGS 同一条纪律，本轮实测又撞一次）。
static MSGS: [u8; 20] = *b"execprobe: argv[0]=\n";

#[inline(never)]
fn msgs_base() -> u64 {
    let base: u64;
    // SAFETY: lea 只取地址不访存；`sym` 操作数把符号名交给汇编器，RIP 相对寻址与基址无关。
    unsafe {
        core::arch::asm!(
            "lea {}, [rip + {sym}]",
            out(reg) base,
            sym = sym MSGS,
            options(nomem, nostack, preserves_flags)
        );
    }
    base
}

fn msg(off: usize, len: usize) -> &'static [u8] {
    // SAFETY: 偏移/长度来自本文件两条常量，恒在 MSGS 界内。
    unsafe { core::slice::from_raw_parts((msgs_base() + off as u64) as *const u8, len) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // 用户态 panic 就停在这一核上自旋（与 fileprobe/shell 同一形状）。
    // SAFETY: 用户态自旋；内核的看门狗/时间片会记下这台核不动。
    loop {
        unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) };
    }
}

/// ADR-130 argv 区约定：首串是 argv[0]（NUL 结尾），从 args_off 起到 args_len。
fn first_arg(args: &[u8]) -> &[u8] {
    match args.iter().position(|&b| b == 0) {
        Some(i) => &args[..i],
        None => args,
    }
}

#[no_mangle]
pub extern "C" fn _start(si_va: u64) -> ! {
    // A2 的核心验证点：stdout 来自**继承**（ROLE_STDOUT），不是 ROLE_LOG。
    // SAFETY: si_va 由内核校验并映射（user+只读），契约同 rt::find_console；
    // 本进程存活期间那一页不会被解映射。
    let stdout = match unsafe { rt::handle_of_role(si_va, rt::ROLE_STDOUT) } {
        Some(h) => h,
        None => rt::exit(11),
    };
    // SAFETY: 同上；args 区已被内核校验在页内且不与句柄表重叠（ADR-130 决策 2）。
    let args = match unsafe { rt::args_at(si_va) } {
        Some(a) if !a.is_empty() => a,
        _ => rt::exit(22),
    };
    let _ = rt::console_write(stdout, msg(0, 19));
    let _ = rt::console_write(stdout, first_arg(args));
    let _ = rt::console_write(stdout, msg(19, 1));
    // 特征退出码 7：内核 init 侧收尸后与判定行对账。
    rt::exit(7);
}
