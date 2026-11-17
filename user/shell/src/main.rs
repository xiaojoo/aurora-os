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
//!
//! A3：命令分发重构为"解析器 + 注册表"——`parser.rs` 负责切词，
//! `registry.rs` 持有全部命令与 unknown 输出；本文件只剩读行循环。
//! A2 接线：串口底座（int 0x80 入口 / con_read/con_write / SI 页解析）迁到
//! `aurora-user-runtime`，本 crate 不再持有任何 syscall 底座 unsafe。
//! 五个命令与 unknown 提示的串口输出保持**逐字节不变**（回归安全线）。

#![no_std]
#![no_main]

use aurora_user_runtime as rt;

mod parser;
mod registry;

// A2 接线：调用号（SYS_*）与 StartupInfo 布局（SI_*）随 syscall 底座一起迁到
// `aurora-user-runtime`——本文件不再直接打 int 0x80，也不再解析 SI 页。
// shell 侧保留的 unsafe 只剩：panic/收尾的自跳转与对 `rt::find_console`（unsafe fn）
// 的那一处调用，见 unsafe-census.md 的 user/shell 节。

/// 所有提示串拼成一个静态 blob。**为什么不用字符串字面量**：镜像基址在 4 GiB 之上，
/// `relocation-model=static` 下字面量地址会退化成 `R_X86_64_32S` 绝对重定位，链接期 out of range
/// （hello/probe 的模块头都记过这个坑，本轮实测又撞一次）。改成 RIP 相对 lea 取基址 + 常量偏移。
/// S6u：横幅的前导 `\x0a` 去掉了——那是当年为了跟上面的内核日志隔开留的，
/// ADR-096 之后画面正文只有会话输出，前面什么都没有，那一格就成了纯粹的空行。
static MSGS: [u8; 341] = *b"commands: help | echo <text> | ping | abi | ps | free | top | exit\x0aAurora OS 6.1.0-aurora (tty1)\x0aaurora@os:~$ \x0aline too long, discarded\x0aunknown command:  (try help)\x0aping=abi_info=bye\x0a\x08 \x08^C\x0arun:  exit= (timeout) error=usage: run <path>\x0a-PID GEN THR ST PAGES\x0aps: no job handle\x0alivedead ps: error=free: procs= threads= pages=#\x0atop: usage\x0aframe ";

const M_HELP: (usize, usize) = (0, 67);
const M_BANNER: (usize, usize) = (67, 30);
const M_PROMPT: (usize, usize) = (97, 13);
const M_NL: (usize, usize) = (110, 1);
const M_TOOLONG: (usize, usize) = (111, 25);
const M_UNKNOWN: (usize, usize) = (136, 17);
const M_TRYHELP: (usize, usize) = (153, 12);
const M_PING: (usize, usize) = (165, 5);
const M_ABI: (usize, usize) = (170, 9);
const M_BYE: (usize, usize) = (179, 4);
const M_BS: (usize, usize) = (183, 3);
const M_INT: (usize, usize) = (186, 3);
const M_RUN_PREFIX: (usize, usize) = (189, 5);
const M_RUN_EXIT: (usize, usize) = (194, 6);
const M_RUN_TIMEOUT: (usize, usize) = (200, 10);
const M_RUN_ERR: (usize, usize) = (210, 7);
const M_RUN_USAGE: (usize, usize) = (217, 18);
const M_MINUS: (usize, usize) = (235, 1);
const M_PS_HDR: (usize, usize) = (236, 21);
const M_PS_NOJOB: (usize, usize) = (257, 18);
const M_LIVE: (usize, usize) = (275, 4);
const M_DEAD: (usize, usize) = (279, 4);
const M_SP: (usize, usize) = (283, 1);
const M_PS_ERR: (usize, usize) = (284, 10);
const M_FREE_PFX: (usize, usize) = (294, 12);
const M_FREE_THR: (usize, usize) = (306, 9);
const M_FREE_PAGES: (usize, usize) = (315, 7);
// `top`（ADR-133）：表头与 ps 同列名，另加"快照序号"前缀行与 usage。
const M_TOP_USAGE: (usize, usize) = (324, 11);
const M_TOP_FRAME: (usize, usize) = (335, 6);
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

/// 去掉首尾的空格/Tab（脚本模式下 `;` 两侧常带空格）。
fn trim_ascii(mut b: &[u8]) -> &[u8] {
    while let Some((&c, rest)) = b.split_first() {
        if c == b' ' || c == b'\t' {
            b = rest;
        } else {
            break;
        }
    }
    while let Some((&c, rest)) = b.split_last() {
        if c == b' ' || c == b'\t' {
            b = rest;
        } else {
            break;
        }
    }
    b
}

/// 往控制台写一段字节。
/// A2 接线：本体迁到 `rt::console_write`。旧版返回 syscall rax，但**全仓没有调用方
/// 读它**（逐处核对过）——签名顺势改 `()`，错误也和旧版一样不上抛（旧版忽略 rax，
/// 交互程序对写失败没有可恢复动作；`let _` 是显式声明"与旧版同口径地忽略"，不是吞错）。
fn con_write(h: u64, s: &[u8]) {
    let _ = rt::console_write(h, s);
}

/// 从控制台读**一个**字节。返回 None 表示当前没有输入（21 号不阻塞）。
/// A2 接线：本体迁到 `rt::console_read`；判据与旧版逐字同义（成功且恰好 1 字节）。
fn con_read_byte(h: u64, slot: &mut u8) -> Option<u8> {
    match rt::console_read(h, core::slice::from_mut(slot)) {
        Ok(1) => Some(*slot),
        _ => None,
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

// A2 接线：find_console（SI 页解析）整段迁到 `rt::find_console`——两边逐字同源
// （runtime 版注明了出处 main.rs 原实现），Si 页偏移常量也随之迁走。

/// 入口。`rdi` = StartupInfo 那一页在子 AS 里的 VA（`process_start` 的 set_thread_arg）。
#[no_mangle]
pub extern "C" fn _start(si_va: u64) -> ! {
    // SAFETY: si_va 由内核校验并映射（user+只读）；`rt::find_console` 的 Safety 契约
    // 与旧 shell 版逐字相同（那一页在读取期间不被解映射）。
    let console = match unsafe { rt::find_console(si_va) } {
        Some(h) => h,
        None => {
            // 没有控制台就什么都做不了。**不**静默自旋假装在跑：
            // 直接 exit(1)，让内核侧的收工读数能看出"shell 没拿到控制台"。
            // `rt::exit` 是 `-> !`：失败时 runtime 侧已带自旋兜底，不再手写第二份 asm。
            rt::exit(1);
        }
    };
    con_write(console, msg(M_BANNER));
    // A3（ADR-131）：SI 页的 **argv 区**若带了一条命令，就执行它一次然后退出
    // （`sh -c` 语义）。默认构建的内核不写 argv（0/0），所以交互行为**一字未变**；
    // 有 argv 时不打印提示符——脚本模式不该等输入。
    // SAFETY: si_va 契约同 `find_console`（内核 process_start 校验并映射、user+只读）。
    if let Some(argv) = unsafe { rt::args_at(si_va) } {
        let line = argv.split(|&b| b == 0).next().unwrap_or(&[]);
        // **`;` 分隔多条**：脚本模式（argv）与交互模式的差别只在这里——交互一次一行，
        // 脚本一行可以带几条。空段（`;;`、末尾 `;`）跳过，不产生输出。
        let mut any = false;
        for part in line.split(|&b| b == b';') {
            let cmd = trim_ascii(part);
            if cmd.is_empty() {
                continue;
            }
            any = true;
            con_write(console, cmd);
            con_write(console, msg(M_NL));
            let parsed = parser::parse(cmd);
            let _ = registry::dispatch(console, si_va, &parsed);
        }
        if any {
            rt::exit(0);
        }
    }
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
            } else {
                // A3：解析 → 注册表分派。msg 常量与打印顺序一行未动，
                // 五命令与 unknown 的输出路径逐字节不变（见两模块头注释）。
                let parsed = parser::parse(line.get(..len).unwrap_or(&[]));
                // A3：`run` 要按角色取 Job 句柄，所以把 SI 页地址一并传进分派层
                // （只有 `run` 用它，其余命令一个字都没变）。
                if !registry::dispatch(console, si_va, &parsed) {
                    // A2 接线：与旧版同义（3 号、code=0）。`rt::exit` 是 `-> !`，
                    // 失败时 runtime 侧自旋兜底（旧版这里无兜底，exit 失败会掉回循环——
                    // 那是内核异常态，自旋比静默继续更诚实）。
                    rt::exit(0);
                }
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
