//! A3：内置命令注册表——名字 → 处理器的唯一映射点。
//!
//! **为什么不是"函数指针静态表"**：镜像基址在 4 GiB 之上，`relocation-model=static`
//! 加小代码模型之下，凡是"把一个地址当作值"的形状——函数指针存进表、运行期变址
//! 读表、枚举 `match` 降成的跳转表——都会退化成 `R_X86_64_32S` 绝对重定位，
//! 链接期就炸。`main.rs` 的 MSGS 注释、`ctrl_c` 的 `#[inline(never)]` 注释、
//! hello 的 `OFF_SELF_VA` 注释记的都是同一类事故，都不是理论推演。
//! 链接期被证明安全的形状只有三种：const 字节数组折成的 immediate 比较、
//! `call rel32` 的直接调用、RIP 相对 lea。
//!
//! 所以这张"表"落成：**const 名字字节数组 + 编译期展开的匹配链 + 直接调用处理器**。
//! 名字到处理器的映射仍然只有 `dispatch` 这一处；加命令的配方见 `dispatch` 尾注。
//!
//! 处理器统一签名 `fn(ConsoleHandle, &Parsed) -> bool`：返回是否继续主循环，
//! `exit` 回 `false`。签名带整个 [`Parsed`] 而不是只有 `args`：echo 需要
//! `rest`（原始剩余）才能保住逐字节回归线，见 `cmd_echo`。

use crate::parser::Parsed;
use aurora_user_runtime as rt;

use crate::{con_write, msg, put_u64};
use crate::{
    M_ABI, M_BYE, M_BYTES, M_CAT, M_CAT_USAGE, M_D, M_DEAD, M_ENTRIES, M_F, M_FNV, M_FREE_PAGES,
    M_FREE_PFX, M_FREE_THR, M_HELP, M_LIVE, M_LS, M_MINUS, M_NL, M_PING, M_PS_ERR, M_PS_HDR,
    M_PS_NOJOB, M_HELP2, M_RUN_ERR, M_RUN_EXIT, M_RUN_PREFIX, M_RUN_TIMEOUT, M_RUN_USAGE, M_SP, M_TRYHELP,
    M_UNKNOWN,
};

/// 控制台句柄（内核按角色 `ROLE_LOG` 转移给 shell 的那个 u64）。
pub type ConsoleHandle = u64;

/// 一次分派的上下文。`si_va` 是 StartupInfo 那一页在**本进程 AS** 里的地址：
/// `run` 要按角色号从描述表里取 Job 句柄（`ROLE_JOB`），与 console 同一个来源。
pub struct Ctx<'a> {
    /// 控制台句柄。
    pub h: ConsoleHandle,
    /// StartupInfo 页 VA（内核 `process_start` 的首参）。
    pub si_va: u64,
    /// 已解析的一行。
    pub p: &'a Parsed<'a>,
}

// ---- 命令词：const 字节数组折成 immediates，不取地址（沿用旧 dispatch 的纪律）----
const CMD_HELP: [u8; 4] = [b'h', b'e', b'l', b'p'];
const CMD_ECHO: [u8; 4] = [b'e', b'c', b'h', b'o'];
const CMD_PING: [u8; 4] = [b'p', b'i', b'n', b'g'];
const CMD_ABI: [u8; 3] = [b'a', b'b', b'i'];
const CMD_EXIT: [u8; 4] = [b'e', b'x', b'i', b't'];
const CMD_RUN: [u8; 3] = [b'r', b'u', b'n'];
const CMD_PS: [u8; 2] = [b'p', b's'];
const CMD_FREE: [u8; 4] = [b'f', b'r', b'e', b'e'];
const CMD_LS: [u8; 2] = [b'l', b's'];
const CMD_CAT: [u8; 3] = [b'c', b'a', b't'];

/// 命令词比较。走 `&[u8] == &[u8]`，LLVM 折成 immediate 比较（旧 dispatch 同款）。
fn streq(a: &[u8], b: &[u8]) -> bool {
    a == b
}

// ---- 五个处理器：统一签名，返回 false = 退出 shell ----

fn cmd_help(c: &Ctx) -> bool {
    con_write(c.h, msg(M_HELP));
    con_write(c.h, msg(M_HELP2));
    true
}

/// **为什么用 `p.rest` 而不是 `p.args`**：旧实现 echo 打印的是"第一个空格之后的
/// 原始剩余"——多空格、Tab、引号都原样回显。`args` 是切分去引号后的词，
/// 用它会在 `echo a  b`、`echo "x"` 这类输入上改字节，撞逐字节回归线。
/// 引号切分的收益留给将来真正带参的命令（先查 `p.err` 再用 `args`）。
fn cmd_echo(c: &Ctx) -> bool {
    con_write(c.h, c.p.rest);
    con_write(c.h, msg(M_NL));
    true
}

fn cmd_ping(c: &Ctx) -> bool {
    // A2 接线：1 号调用迁到 `rt::ping()`（返回值同义：内核服务计数）。
    let n = rt::ping();
    con_write(c.h, msg(M_PING));
    put_u64(c.h, n);
    con_write(c.h, msg(M_NL));
    true
}

fn cmd_abi(c: &Ctx) -> bool {
    // A2 接线：7 号调用迁到 `rt::abi_info()`。
    let v = rt::abi_info();
    con_write(c.h, msg(M_ABI));
    put_u64(c.h, v);
    con_write(c.h, msg(M_NL));
    true
}

fn cmd_exit(c: &Ctx) -> bool {
    con_write(c.h, msg(M_BYE));
    false
}

/// A3：跑一个外部 ELF——`run <path>`。
///
/// 装载/启动/等待全在 `rt::exec`（22/25 → 12/13/14 → 11/15/16/17 的编排）；
/// 本函数只做三件 shell 自己的事：取参数、补绝对路径、把结果打成人能读的一行。
///
/// **路径补 `/` 而不是要求用户打绝对路径**：`vfs_ro::lookup` 只收绝对路径
/// （实测 `NotAbsolute`），而在 shell 里打 `run HELLO.ELF` 是自然写法。
/// 补前缀是显示层的事，内核不需要知道。
///
/// 超时（`Ok(None)`）**不杀**目标：18 号是杀进程的独立决定，这里只如实说"还在跑"。
fn cmd_run(c: &Ctx) -> bool {
    // 词法超限（参数太多/太长/引号没闭合）先拒：`args` 此时只含出错前的完整词。
    let arg = match (c.p.err.is_none(), c.p.args.get(0)) {
        (true, Some(a)) => a,
        _ => {
            con_write(c.h, msg(M_RUN_USAGE));
            return true;
        }
    };
    // 拼绝对路径（静态缓冲，超长就拒而不是截断）。
    let mut buf = [0u8; 80];
    let mut n = 0usize;
    // 用模式匹配而不是 `!= Some(&b'/')`：后者会把 `b'/'` 取址成一个匿名 `.rodata` 常量，
    // 4 GiB+ 链接基址下就是 `R_X86_64_32S`（2026-11-17 实测：cmd_run 里那一处炸链接）。
    // **不用 `buf[0] = ...`**：索引赋值带越界检查，编译器会为它生成一条 panic location
    // （文件名+行号的匿名 `.rodata`），4 GiB+ 基址下就是 `R_X86_64_32S`——这是本仓库
    // 第三/四族 32S 的统一解法：所有索引改 `get`/`get_mut`。`buf` 长度是常量，
    // 这里的 `None` 分支不可能走到，仍然写成不 panic 的形状。
    if !matches!(arg.first(), Some(b'/')) {
        if let Some(slot) = buf.get_mut(0) {
            *slot = b'/';
            n = 1;
        }
    }
    let end = match n.checked_add(arg.len()) {
        Some(e) if e <= buf.len() => e,
        _ => {
            con_write(c.h, msg(M_RUN_USAGE));
            return true;
        }
    };
    // **不用 `copy_from_slice`**：它的长度不等断言会带一条 panic 消息（格式化串落在
    // 匿名 `.rodata`），4 GiB+ 基址下同样是 `R_X86_64_32S`。逐字节 `get_mut` + 有界循环。
    let mut i = 0usize;
    while i < arg.len() {
        match (buf.get_mut(n + i), arg.get(i)) {
            (Some(dst), Some(src)) => *dst = *src,
            _ => {
                con_write(c.h, msg(M_RUN_USAGE));
                return true;
            }
        }
        i += 1;
    }
    let path = match buf.get(..end) {
        Some(p) => p,
        None => {
            con_write(c.h, msg(M_RUN_USAGE));
            return true;
        }
    };
    // Job 句柄按角色号取（init-user 给 shell 的那份带 CREATE|TRANSFER）。
    // SAFETY: si_va 契约同 find_console（内核校验过、只读、存活期不解映射）。
    let job = match unsafe { rt::handle_of_role(c.si_va, rt::ROLE_JOB) } {
        Some(h) => h,
        None => {
            // 没有 Job 句柄就开不了进程：如实说，不假装"命令不存在"。
            con_write(c.h, msg(M_RUN_ERR));
            put_i64(c.h, -4);
            con_write(c.h, msg(M_NL));
            return true;
        }
    };
    con_write(c.h, msg(M_RUN_PREFIX));
    con_write(c.h, path);
    match rt::exec::run(path, c.h, job, 5_000) {
        Ok(Some(code)) => {
            con_write(c.h, msg(M_RUN_EXIT));
            put_u64(c.h, code as u64);
        }
        Ok(None) => con_write(c.h, msg(M_RUN_TIMEOUT)),
        Err(e) => {
            con_write(c.h, msg(M_RUN_ERR));
            put_i64(c.h, e.0);
        }
    }
    con_write(c.h, msg(M_NL));
    true
}

/// 按角色取 Job 句柄（`ps`/`free` 共用）。没有就打印一句并返回 None。
fn job_of(c: &Ctx) -> Option<rt::Handle> {
    // SAFETY: si_va 契约同 `find_console`（内核校验并映射、user+只读、存活期不解映射）。
    match unsafe { rt::handle_of_role(c.si_va, rt::ROLE_JOB) } {
        Some(h) => Some(h),
        None => {
            con_write(c.h, msg(M_PS_NOJOB));
            None
        }
    }
}

/// ADR-132：`ps` —— 枚举自己 Job 名下的进程（27 号）。
///
/// **看得见的范围就是自己 Job**：内核按句柄里的 Job 过滤，所以这里不需要（也不该）
/// 扫全表。列宽不做对齐（无堆、无格式化库）：`PID GEN THR ST PAGES` 五列以单空格分隔。
fn cmd_ps(c: &Ctx) -> bool {
    con_write(c.h, msg(M_PS_HDR));
    let Some(job) = job_of(c) else { return true };
    let mut buf = [0u8; rt::PROC_RECORD_LEN * 4];
    let mut cursor = 0u32;
    loop {
        match rt::proc_enum(job, cursor, &mut buf) {
            Ok((next, n)) => {
                let mut i = 0usize;
                while i < n as usize {
                    if let Some(e) = rt::proc_enum_at(&buf, i) {
                        put_u64(c.h, u64::from(e.pid));
                        con_write(c.h, msg(M_SP));
                        put_u64(c.h, u64::from(e.gen));
                        con_write(c.h, msg(M_SP));
                        put_u64(c.h, u64::from(e.threads));
                        con_write(c.h, msg(M_SP));
                        con_write(c.h, if e.terminated { msg(M_DEAD) } else { msg(M_LIVE) });
                        con_write(c.h, msg(M_SP));
                        put_u64(c.h, u64::from(e.pages));
                        con_write(c.h, msg(M_NL));
                    }
                    i += 1;
                }
                if next == 0 {
                    break;
                }
                cursor = next;
            }
            Err(e) => {
                con_write(c.h, msg(M_PS_ERR));
                put_i64(c.h, e.0);
                con_write(c.h, msg(M_NL));
                break;
            }
        }
    }
    true
}

/// ADR-132：`free` —— 自己 Job 的**用量读数**（27 号的聚合）。
///
/// **口径**：`pages` 是"名下 AS 当前映射着的页数"，不是物理常驻页（后者没有量具）；
/// 全机空闲帧数在内核里，用户态今天读不到——`free` 不假装知道它。
fn cmd_free(c: &Ctx) -> bool {
    let Some(job) = job_of(c) else { return true };
    let mut buf = [0u8; rt::PROC_RECORD_LEN * 4];
    let mut cursor = 0u32;
    let (mut procs, mut threads, mut pages) = (0u64, 0u64, 0u64);
    loop {
        match rt::proc_enum(job, cursor, &mut buf) {
            Ok((next, n)) => {
                let mut i = 0usize;
                while i < n as usize {
                    if let Some(e) = rt::proc_enum_at(&buf, i) {
                        procs += 1;
                        threads += u64::from(e.threads);
                        pages += u64::from(e.pages);
                    }
                    i += 1;
                }
                if next == 0 {
                    break;
                }
                cursor = next;
            }
            Err(e) => {
                con_write(c.h, msg(M_PS_ERR));
                put_i64(c.h, e.0);
                con_write(c.h, msg(M_NL));
                return true;
            }
        }
    }
    con_write(c.h, msg(M_FREE_PFX));
    put_u64(c.h, procs);
    con_write(c.h, msg(M_FREE_THR));
    put_u64(c.h, threads);
    con_write(c.h, msg(M_FREE_PAGES));
    put_u64(c.h, pages);
    con_write(c.h, msg(M_NL));
    true
}

/// 有符号十进制（负数先打 `-`，再打绝对值）。`put_u64` 只处理非负。
fn put_i64(h: ConsoleHandle, v: i64) {
    if v < 0 {
        con_write(h, msg(M_MINUS));
        put_u64(h, v.unsigned_abs());
    } else {
        put_u64(h, v as u64);
    }
}

/// `ls [path]`：默认列根。每条一行：`d <短名>` 或 `f <短名> <字节数>`，末尾 `ls: <条数> entries`。
fn cmd_ls(c: &Ctx) -> bool {
    // 局部数组而不是 `b"/"`：后者会被提升成 .rodata 常量，取址即 32 位绝对重定位
    // （put_u64 的注释记过同一个坑；本题第一版就撞在 dispatch+0xce9）。
    let slash = [b'/'];
    let path: &[u8] = match c.p.args.get(0) {
        Some(a) if c.p.err.is_none() && !a.is_empty() => a,
        _ => &slash[..],
    };
    con_write(c.h, msg(M_LS));
    con_write(c.h, path);
    con_write(c.h, msg(M_NL));
    let mut n = 0u64;
    let r = rt::dir_list(path, |e| {
        con_write(c.h, if e.kind == 2 { msg(M_D) } else { msg(M_F) });
        // 有长名就显示长名（`DirEnt.long` 空串 = 没有），否则短名。
        con_write(c.h, if e.long.is_empty() { e.name } else { e.long });
        if e.kind != 2 {
            con_write(c.h, msg(M_SP));
            put_u64(c.h, u64::from(e.size));
        }
        con_write(c.h, msg(M_NL));
        n += 1;
    });
    match r {
        Ok(_) => {
            con_write(c.h, msg(M_LS));
            put_u64(c.h, n);
            con_write(c.h, msg(M_ENTRIES));
            con_write(c.h, msg(M_NL));
        }
        Err(e) => {
            con_write(c.h, msg(M_RUN_ERR));
            put_i64(c.h, e.0);
            con_write(c.h, msg(M_NL));
        }
    }
    true
}

/// `cat <path>`：原样打印文件字节，随后一行 `cat: <字节数> bytes= fnv=<FNV-1a 64>`。
/// 那条尾巴是**第二台仪器**：宿主机用自己解析 FAT 的同一份字节算同一个数（行里对得上）。
fn cmd_cat(c: &Ctx) -> bool {
    let path = match (c.p.err.is_none(), c.p.args.get(0)) {
        (true, Some(a)) if !a.is_empty() => a,
        _ => {
            con_write(c.h, msg(M_CAT_USAGE));
            con_write(c.h, msg(M_NL));
            return true;
        }
    };
    con_write(c.h, msg(M_CAT));
    con_write(c.h, path);
    con_write(c.h, msg(M_NL));
    let mut n = 0u64;
    let mut hsh = 0xcbf2_9ce4_8422_2325u64;
    let r = rt::cat_each(path, |b| {
        con_write(c.h, b);
        let mut i = 0usize;
        while i < b.len() {
            hsh ^= u64::from(b[i]);
            hsh = hsh.wrapping_mul(0x100_0000_01b3);
            i += 1;
        }
        n += b.len() as u64;
    });
    match r {
        Ok(_) => {
            con_write(c.h, msg(M_NL));
            con_write(c.h, msg(M_CAT));
            put_u64(c.h, n);
            con_write(c.h, msg(M_BYTES));
            con_write(c.h, msg(M_FNV));
            put_u64(c.h, hsh);
            con_write(c.h, msg(M_NL));
        }
        Err(e) => {
            con_write(c.h, msg(M_RUN_ERR));
            put_i64(c.h, e.0);
            con_write(c.h, msg(M_NL));
        }
    }
    true
}

/// 分派一条已解析的命令。返回 false = 退出 shell。
///
/// 每个分支都是"名字 immediate 比较 → 直接调用处理器"，不写 `match lookup()`：
/// 多分支枚举 match 有被 LLVM 降成跳转表的前科（`ctrl_c` 注释记过）。
///
/// **加命令的配方**：一个 const 名字数组 + 一个处理器 + 链上加一节；
/// 带参命令在处理器里先查 `p.err` 再用 `p.args`。
pub fn dispatch(h: ConsoleHandle, si_va: u64, p: &Parsed) -> bool {
    let c = Ctx { h, si_va, p };
    if p.cmd.is_empty() {
        // 空行：旧实现静默回到提示符，不产出任何输出。
        return true;
    }
    if streq(p.cmd, &CMD_HELP) {
        return cmd_help(&c);
    }
    if streq(p.cmd, &CMD_ECHO) {
        return cmd_echo(&c);
    }
    if streq(p.cmd, &CMD_PING) {
        return cmd_ping(&c);
    }
    if streq(p.cmd, &CMD_ABI) {
        return cmd_abi(&c);
    }
    if streq(p.cmd, &CMD_EXIT) {
        return cmd_exit(&c);
    }
    if streq(p.cmd, &CMD_RUN) {
        return cmd_run(&c);
    }
    if streq(p.cmd, &CMD_PS) {
        return cmd_ps(&c);
    }
    if streq(p.cmd, &CMD_FREE) {
        return cmd_free(&c);
    }
    if streq(p.cmd, &CMD_LS) {
        return cmd_ls(&c);
    }
    if streq(p.cmd, &CMD_CAT) {
        return cmd_cat(&c);
    }
    // unknown：三段输出与旧实现逐字节一致——词原样回显（借用不拷贝，全长不截断）。
    con_write(c.h, msg(M_UNKNOWN));
    con_write(c.h, c.p.cmd);
    con_write(c.h, msg(M_TRYHELP));
    true
}
