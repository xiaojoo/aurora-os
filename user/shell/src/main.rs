//! S5c：第一个**交互式**用户程序——串口 shell。
//!
//! 与 hello/probe 的三条约定相同（ADR-025 / §10.2 / elf.rs）：
//! 1. 入口走 `int 0x80`，所以**不**声明 `rcx`/`r11` 被破坏（那是 SYSCALL 的硬件行为）。
//! 2. 号在 `rax`，参数 `rdi/rsi/rdx`，返回 `rax`，负数是 `-ErrorCode`。
//! 3. 段地址与对齐由 `link.ld` 保证，不靠"我记得链接脚本怎么排的"。
//!
//! **控制台句柄从哪来**：`process_start` 的第④步 `set_thread_arg(gidx, si_va)`
//! 把 StartupInfo 那一页在**子 AS 里的 VA** 作为首参交进来（`user.rs` 的注释明写
//! "首参 = 那一页在子 AS 里的 VA"）。所以 `_start` 的第一个参数就是它。
//! 内核按 `role == ROLE_LOG(5)` 把控制台句柄转移给我们（`main.rs` 的 S5b 段），
//! 我们**只认角色号**，不认"第几条"——顺序不是契约，角色才是。
//!
//! **命令只用真实存在的 syscall**：help/echo/ping/abi/exit。
//! `ps`/`mem`/`reboot` 需要新号，本片**不做**，也不假装做了。

#![no_std]
#![no_main]

// ---- 调用号（与 kernel/src/user.rs 同一组数，用户侧独立声明）----
const SYS_PING: u64 = 1;
const SYS_EXIT: u64 = 3;
const SYS_ABI_INFO: u64 = 7;
const SYS_CONSOLE_WRITE: u64 = 20;
const SYS_CONSOLE_READ: u64 = 21;

// ---- StartupInfo 布局（ADR-075 决策 3；与内核同一组偏移）----
const SI_MAGIC: u32 = 0x4155_524f;
const SI_OFF_MAGIC: usize = 0;
const SI_OFF_NHANDLES: usize = 8;
const SI_OFF_HANDLES: usize = 24;
const SI_DESC_BYTES: usize = 16;
const SI_DESC_ROLE: usize = 0;
const SI_DESC_HANDLE: usize = 8;
const ROLE_LOG: u32 = 5;
const MAX_STARTUP_HANDLES: usize = 16;

/// 所有提示串拼成一个静态 blob。**为什么不用字符串字面量**：镜像基址在 4 GiB 之上，
/// `relocation-model=static` 下字面量地址会退化成 `R_X86_64_32S` 绝对重定位，链接期 out of range
/// （hello/probe 的模块头都记过这个坑，本轮实测又撞一次）。改成 RIP 相对 lea 取基址 + 常量偏移。
static MSGS: [u8; 173] = *b"commands: help | echo <text> | ping | abi | exit\x0a\x0aAurora shell (S5c). type 'help'.\x0aAURORA:/ > \x0aline too long, discarded\x0aunknown command:  (try help)\x0aping=abi_info=bye\x0a\x08 \x08^C\x0a";

const M_HELP: (usize, usize) = (0, 49);
const M_BANNER: (usize, usize) = (49, 34);
const M_PROMPT: (usize, usize) = (83, 11);
const M_NL: (usize, usize) = (94, 1);
const M_TOOLONG: (usize, usize) = (95, 25);
const M_UNKNOWN: (usize, usize) = (120, 17);
const M_TRYHELP: (usize, usize) = (137, 12);
const M_PING: (usize, usize) = (149, 5);
const M_ABI: (usize, usize) = (154, 9);
const M_BYE: (usize, usize) = (163, 4);
const M_BS: (usize, usize) = (167, 3);
/// Ctrl+C 的回显串（S6q）。**追加在 blob 末尾**：这样前面那 11 条偏移一个都不用动。
const M_INT: (usize, usize) = (170, 3);

/// blob 的真实基址（RIP 相对 lea，不产生 32 位绝对重定位）。
fn msgs_base() -> u64 {
    let b: u64;
    // SAFETY: lea 只算地址不访存、不动栈；RIP 相对 => 无绝对重定位。
    unsafe {
        core::arch::asm!("lea {}, [rip + {sym}]", out(reg) b, sym = sym MSGS,
                         options(nomem, nostack, preserves_flags));
    }
    b
}

/// 按 (偏移,长度) 取一条消息。
fn msg(m: (usize, usize)) -> &'static [u8] {
    // SAFETY: 基址来自 msgs_base()（本程序 .rodata 里的 MSGS），m 是上面那组常量，
    // 偏移+长度都落在 blob 内；只读、生命周期是整个程序。
    unsafe { core::slice::from_raw_parts((msgs_base() + m.0 as u64) as *const u8, m.1) }
}

/// 一行命令的上限。超了就丢弃整行并提示——不静默截断成另一条命令。
const LINE_MAX: usize = 128;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // 用户态没有停机权，也不能用 hlt/cli（ring3 下都是 #GP，hello 的注释里记过实测）。
    loop {
        unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) };
    }
}

/// 三参 syscall。`int 0x80` 不动 rcx/r11，所以不声明它们为 clobber。
#[inline]
unsafe fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    // SAFETY: 只有内核能处理这条中断；号走 rax、参数 rdi/rsi/rdx、返回 rax。
    // preserves_flags 是对的：中断门清的是内核的 IF，iretq 把用户帧那份 rflags 原样装回。
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            options(preserves_flags)
        );
    }
    ret
}

/// 往控制台写一段字节。返回内核实际写出的字节数（负数 = 错误码取反）。
fn con_write(h: u64, s: &[u8]) -> u64 {
    unsafe { syscall3(SYS_CONSOLE_WRITE, h, s.as_ptr() as u64, s.len() as u64) }
}

/// 从控制台读**一个**字节。返回 None 表示当前没有输入（21 号不阻塞）。
fn con_read_byte(h: u64, slot: &mut u8) -> Option<u8> {
    let n = unsafe { syscall3(SYS_CONSOLE_READ, h, slot as *mut u8 as u64, 1) };
    if n == 1 {
        Some(*slot)
    } else {
        None
    }
}

/// Ctrl+C = **行内中断**（S6q）：丢弃已键入的内容、回显 `^C`、重新给提示符。
///
/// 口径写清楚：本内核还没有信号与前台进程组，命令也都是瞬间完成的，所以这里"中断"的是
/// **正在编辑的这一行**，不是某个进程（BACKLOG §261 记着）。
///
/// **为什么单独一个 `#[inline(never)]` 的函数**：把这个字节比较塞进 `_start` 里那串
/// 已有的字节比较（换行/退格/DEL），LLVM 会把整串降成 `switch` + 跳转表，而那张表落在
/// 4 GiB 之上的 `.rodata`——静态链接下取址是绝对重定位，链接器直接报
/// `R_X86_64_32S out of range`（本轮实测两次：加比较、加 xor 都一样）。把它关进一个
/// 只做一次比较的函数里，`_start` 里就只剩一次调用。
#[inline(never)]
fn ctrl_c(console: u64, b: u8) -> bool {
    if b != 0x03 {
        return false;
    }
    con_write(console, msg(M_INT));
    con_write(console, msg(M_PROMPT));
    true
}

/// 把一个小整数按十进制写出去（no_std 里没有格式化器可用，也不引依赖）。
fn put_u64(h: u64, mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    if v == 0 {
        // 局部数组而不是 `&[b'0']`：后者是 const 提升，会在 .rodata 里落一个字节，
        // 取它的地址就是 32 位绝对重定位（本轮实测：链接器报的那个 .Lanon 段内容正是 b'0'）。
        let zero = [b'0'];
        con_write(h, &zero);
        return;
    }
    while v > 0 {
        i -= 1;
        // 用 get_mut 而不是索引：索引的边界检查在带调试断言的档里会生成 panic Location。
        if let Some(slot) = buf.get_mut(i) {
            *slot = b'0' + (v % 10) as u8;
        }
        v /= 10;
    }
    if let Some(tail) = buf.get(i..) {
        con_write(h, tail);
    }
}

/// 从 StartupInfo 里按**角色号**取控制台句柄。找不到就返回 None。
///
/// # Safety
/// `si_va` 必须是内核映射好的那一页（`process_start` 校验过 user+只读），
/// 且在本函数读取期间不被解映射。
unsafe fn find_console(si_va: u64) -> Option<u64> {
    let base = si_va as *const u8;
    // SAFETY: 见上；只读前 24 字节头 + 最多 16 条描述，都在那一页内。
    let magic = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_MAGIC) as *const u32) };
    if magic != SI_MAGIC {
        return None;
    }
    let n = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_NHANDLES) as *const u32) } as usize;
    let n = if n > MAX_STARTUP_HANDLES { MAX_STARTUP_HANDLES } else { n };
    for i in 0..n {
        let d = unsafe { base.add(SI_OFF_HANDLES + i * SI_DESC_BYTES) };
        let role = unsafe { core::ptr::read_unaligned(d.add(SI_DESC_ROLE) as *const u32) };
        if role == ROLE_LOG {
            return Some(unsafe { core::ptr::read_unaligned(d.add(SI_DESC_HANDLE) as *const u64) });
        }
    }
    None
}

const CMD_HELP: [u8; 4] = [b'h', b'e', b'l', b'p'];
const CMD_ECHO: [u8; 4] = [b'e', b'c', b'h', b'o'];
const CMD_PING: [u8; 4] = [b'p', b'i', b'n', b'g'];
const CMD_ABI: [u8; 3] = [b'a', b'b', b'i'];
const CMD_EXIT: [u8; 4] = [b'e', b'x', b'i', b't'];

/// 命令词用 const 字节数组而不是字符串字面量：const 数组会被折成 immediates，
/// 不产生 .rodata 的 32 位绝对重定位（字面量会，本轮实测撞到）。
fn streq(a: &[u8], b: &[u8]) -> bool {
    a == b
}

/// 分派一条命令。返回 false 表示要退出 shell。
fn dispatch(h: u64, line: &[u8]) -> bool {
    // 去掉首尾空白
    let mut s = line;
    while let Some((c, rest)) = s.split_first() {
        if *c == b' ' || *c == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((c, rest)) = s.split_last() {
        if *c == b' ' || *c == b'\t' || *c == b'\r' {
            s = rest;
        } else {
            break;
        }
    }
    if s.is_empty() {
        return true;
    }
    // 命令词与参数
    let (cmd, arg) = match s.iter().position(|c| *c == b' ') {
        Some(i) => match s.split_at_checked(i) {
            Some((a, b)) => (a, b.get(1..).unwrap_or(&[])),
            None => (s, &[][..]),
        },
        None => (s, &[][..]),
    };
    if streq(cmd, &CMD_HELP) {
        con_write(h, msg(M_HELP));
    } else if streq(cmd, &CMD_ECHO) {
        con_write(h, arg);
        con_write(h, msg(M_NL));
    } else if streq(cmd, &CMD_PING) {
        let n = unsafe { syscall3(SYS_PING, 0, 0, 0) };
        con_write(h, msg(M_PING));
        put_u64(h, n);
        con_write(h, msg(M_NL));
    } else if streq(cmd, &CMD_ABI) {
        let v = unsafe { syscall3(SYS_ABI_INFO, 0, 0, 0) };
        con_write(h, msg(M_ABI));
        put_u64(h, v);
        con_write(h, msg(M_NL));
    } else if streq(cmd, &CMD_EXIT) {
        con_write(h, msg(M_BYE));
        return false;
    } else {
        con_write(h, msg(M_UNKNOWN));
        con_write(h, cmd);
        con_write(h, msg(M_TRYHELP));
    }
    true
}

/// 入口。`rdi` = StartupInfo 那一页在子 AS 里的 VA（`process_start` 的 set_thread_arg）。
#[no_mangle]
pub extern "C" fn _start(si_va: u64) -> ! {
    // SAFETY: si_va 由内核校验并映射（user+只读），见 find_console 的契约。
    let console = match unsafe { find_console(si_va) } {
        Some(h) => h,
        None => {
            // 没有控制台就什么都做不了。**不**静默自旋假装在跑：
            // 直接 exit(1)，让内核侧的收工读数能看出"shell 没拿到控制台"。
            unsafe { syscall3(SYS_EXIT, 1, 0, 0) };
            loop {
                unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) };
            }
        }
    };
    con_write(console, msg(M_BANNER));
    let mut line = [0u8; LINE_MAX];
    let mut len = 0usize;
    let mut overflow = false;
    con_write(console, msg(M_PROMPT));
    loop {
        let mut b = 0u8;
        match con_read_byte(console, &mut b) {
            None => {
                // 没有输入就再问一次。**这是忙等，不是让出**：21 号不阻塞，而 syscall 表里
                // 没有 yield 号（新增号要裁决，本片不做）。占住的核靠时间片抢占轮转，
                // 所以别的任务仍跑得到；阻塞读/唤醒是 BACKLOG §235 记着的欠账。
                continue;
            }
            Some(c) => c,
        };
        if b == b'\n' || b == b'\r' {
            con_write(console, msg(M_NL));
            if overflow {
                con_write(console, msg(M_TOOLONG));
            } else if !dispatch(console, line.get(..len).unwrap_or(&[])) {
                unsafe { syscall3(SYS_EXIT, 0, 0, 0) };
            }
            len = 0;
            overflow = false;
            con_write(console, msg(M_PROMPT));
            continue;
        }
        if ctrl_c(console, b) {
            len = 0;
            overflow = false;
            continue;
        }
        if b == 0x08 || b == 0x7f {
            if len > 0 {
                len -= 1;
                con_write(console, msg(M_BS));
            }
            continue;
        }
        if len < LINE_MAX {
            if let Some(slot) = line.get_mut(len) {
                *slot = b;
            }
            len += 1;
            // 回显
            let echo = [b];
            con_write(console, &echo);
        } else {
            overflow = true;
        }
    }
}
