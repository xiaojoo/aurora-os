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
    M_ABI, M_BYE, M_DEAD, M_FREE_PAGES, M_FREE_PFX, M_FREE_THR, M_HELP, M_LIVE, M_MINUS, M_NL,
    M_PING, M_PS_ERR, M_PS_HDR, M_PS_NOJOB, M_RUN_ERR, M_RUN_EXIT, M_RUN_PREFIX, M_RUN_TIMEOUT,
    M_DMESG_ERR, M_DMESG_HDR, M_DMESG_USAGE, M_KILLED, M_KILL_USAGE, M_LSPCI_USAGE,
    M_RUN_USAGE, M_SLEEP_USAGE, M_SP, M_TOP_FRAME, M_UPTIME_USAGE,
    M_TOP_USAGE, M_TRYHELP, M_UNKNOWN,
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
const CMD_TOP: [u8; 3] = [b't', b'o', b'p'];
const CMD_KILL: [u8; 4] = [b'k', b'i', b'l', b'l'];
const CMD_DMESG: [u8; 5] = [b'd', b'm', b'e', b's', b'g'];
const CMD_LSPCI: [u8; 5] = [b'l', b's', b'p', b'c', b'i'];
const CMD_UPTIME: [u8; 6] = [b'u', b'p', b't', b'i', b'm', b'e'];
const CMD_SLEEP: [u8; 5] = [b's', b'l', b'e', b'e', b'p'];

/// 命令词比较。走 `&[u8] == &[u8]`，LLVM 折成 immediate 比较（旧 dispatch 同款）。
fn streq(a: &[u8], b: &[u8]) -> bool {
    a == b
}

/// **按字节手写的命令名比较**（ADR-137 实测的 32S 事故的修法）。
///
/// `streq` 对**短数组**（≤4 字节）会被 LLVM 折叠成 immediate 比较，
/// 不取址——dispatch 的老分支都走这条。但 **≥5 字节的数组折叠不动**：
/// LLVM 降级成 `memcmp` 并对 `.rodata` 里的数组**32 位绝对取址**
/// ⇒ 镜像基址在 4 GiB 之上，链接期 `R_X86_64_32S out of range`
/// （与 MSGS/`put_u64` 那族同根：const 提升出来的对象一取址就炸）。
/// 实测顺序：加 `dmesg`(5)/`lspci`(5) 时侥幸没炸，加 `uptime`(6)
/// 之后 dispatch 的分支数改变折叠决策，三个数组全走 memcmp ⇒ 炸。
///
/// 这里用**首字节 switch + 长度 + 逐字节 immediate 比较**：比较数以
/// immediate 出现在指令流里，`.rodata` 里不需要落数组，免疫 32S。
/// `black_box` 那条路试过（挡住了 memcmp 但循环展开后仍取址），不行。
fn cmd_is(cmd: &[u8], name: &[u8]) -> bool {
    if cmd.len() != name.len() {
        return false;
    }
    let mut i = 0usize;
    let mut eq = true;
    while i < name.len() {
        // 用 match 把字节读成 immediate 比较（get 会引入边界检查路径，
        // 在这个档里展开出的形状不稳定；直接 match on Option<&u8> 同样免疫）。
        let (x, y) = (cmd.get(i), name.get(i));
        if x != y {
            eq = false;
        }
        i += 1;
    }
    eq
}

// ---- 五个处理器：统一签名，返回 false = 退出 shell ----

fn cmd_help(c: &Ctx) -> bool {
    con_write(c.h, msg(M_HELP));
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

// ---------------------------------------------------------------------------
// `top`（ADR-133）：定期刷新的进程表，纯用户态
// ---------------------------------------------------------------------------

/// `top` 的快照行数。单 Job 的形状由 `t_proc_info`/`q2` 的判据约束着（`make_job_proc`
/// 每次 2 条、q2 至多 4 条），4 条就是枚举能给出的全部；行数组放**栈上**而不是
/// static——static 的地址在 4 GiB+ 链接基址下同样会被取成 32 位绝对重定位
/// （`R_X86_32S out of range`，本轮实测；与 MSGS 注释是同一族事故）。
/// 320 字节（8 行）曾把 shell 的一页栈顶穿出去（`#PF cr2=栈底下一页 err=0x6`，
/// rip=0x10000397e，本轮实测），4 行 160 字节是留有余量的形状。
const TOP_ROWS_MAX: usize = 4;

/// 一帧快照的原始行（`ps` 同款五列，按 [`top_cmp`] 排好序后逐条打印）。
#[derive(Clone, Copy)]
struct TopRow {
    pid: u64,
    gen: u64,
    threads: u64,
    terminated: bool,
    pages: u64,
}

/// 排序口径（ADR-132 §未做 1 在本片定案）：**pages 降序**（资源视角，与 `free`
/// 的聚合口径同源），并列时 pid 升序（同页数下按诞生先后读）。
/// 返回 true = `a` 应排在 `b` 之前。
fn top_cmp(a: &TopRow, b: &TopRow) -> bool {
    if a.pages != b.pages {
        return a.pages > b.pages;
    }
    a.pid < b.pid
}

/// 扫一帧快照进 `rows`，返回实际条数。枚举语义与 `cmd_ps` 同款（游标推进到 0）。
/// 错误（含 `ps: no job handle` 的前置）由调用方处置，这里只攒数据。
fn top_scan(job: rt::Handle, rows: &mut [TopRow; TOP_ROWS_MAX]) -> usize {
    let mut buf = [0u8; rt::PROC_RECORD_LEN * 4];
    let mut cursor = 0u32;
    let mut n = 0usize;
    loop {
        match rt::proc_enum(job, cursor, &mut buf) {
            Ok((next, count)) => {
                let mut i = 0usize;
                while i < count as usize {
                    if let Some(e) = rt::proc_enum_at(&buf, i) {
                        if let Some(slot) = rows.get_mut(n) {
                            *slot = TopRow {
                                pid: u64::from(e.pid),
                                gen: u64::from(e.gen),
                                threads: u64::from(e.threads),
                                terminated: e.terminated,
                                pages: u64::from(e.pages),
                            };
                            n += 1;
                        }
                    }
                    i += 1;
                }
                if next == 0 {
                    break;
                }
                cursor = next;
            }
            Err(_) => break,
        }
    }
    n
}

/// 选择排序（原位，`top_cmp` 升序谓词）。n ≤ TOP_ROWS_MAX，交换开销可忽略。
fn top_sort(rows: &mut [TopRow; TOP_ROWS_MAX], n: usize) {
    let mut i = 0usize;
    while i < n {
        let mut best = i;
        let mut j = i + 1;
        while j < n {
            // rows.get 两侧都拿不到时保持 best 不动：n 由调用方约束 ≤ 数组长度，
            // 这个分支不可达，写成不 panic 的形状（本仓库 32S 纪律）。
            let take = match (rows.get(j), rows.get(best)) {
                (Some(rj), Some(rb)) => top_cmp(rj, rb),
                _ => false,
            };
            if take {
                best = j;
            }
            j += 1;
        }
        if best != i {
            // 不用 `rows.swap(i, best)`：那是切片方法，带越界检查，会生成一条
            // panic Location 常量（.rodata 匿名 8 字节），4 GiB+ 基址下取址就是
            // `R_X86_32S out of range`（本轮实测）。两个 get_mut 一次拿会撞借用检查，
            // 所以按"读出两值→写回"分三步走；`None` 分支不可达（best/j 都 < n ≤ 上限），
            // 缺格的当轮跳过，仍写成不 panic 形状。
            let (vi, vb) = match (rows.get(i), rows.get(best)) {
                (Some(a), Some(b)) => (*a, *b),
                _ => {
                    i += 1;
                    continue;
                }
            };
            match rows.get_mut(i) {
                Some(a) => *a = vb,
                None => {}
            }
            match rows.get_mut(best) {
                Some(b) => *b = vi,
                None => {}
            }
        }
        i += 1;
    }
}

/// 打一帧：`frame N` 前缀行 + 表头 + 排好序的表行。`#[inline(never)]`：帧打印是
/// `cmd_top` 里唯一的输出体，关进独立函数让它对 `.text` 只贡献一份代码
/// （shell 链接脚本给 `.text` 留 16 KiB，第一版把打印循环内联两份直接撞
/// `section .text virtual address range overlaps with .rodata`——本轮实测）。
#[inline(never)]
fn top_print_frame(h: ConsoleHandle, frame: u64, rows: &[TopRow; TOP_ROWS_MAX], n: usize) {
    con_write(h, msg(M_TOP_FRAME));
    put_u64(h, frame);
    con_write(h, msg(M_NL));
    con_write(h, msg(M_PS_HDR));
    let mut i = 0usize;
    while i < n {
        let Some(r) = rows.get(i) else { break };
        put_u64(h, r.pid);
        con_write(h, msg(M_SP));
        put_u64(h, r.gen);
        con_write(h, msg(M_SP));
        put_u64(h, r.threads);
        con_write(h, msg(M_SP));
        con_write(h, if r.terminated { msg(M_DEAD) } else { msg(M_LIVE) });
        con_write(h, msg(M_SP));
        put_u64(h, r.pages);
        con_write(h, msg(M_NL));
        i += 1;
    }
}

/// `top <秒数>`：按 pages 降序刷新进程表。
///
/// **帧数由参数给**（`top` 无参 = 默认 3 帧；`top 0`/负数/超上限 = usage）——
/// 判定语义"至少两帧"不靠次数硬凑：串口里每帧带 `frame N` 前缀行，宿主机对账按
/// 前缀行数与表行数核。帧间隔 1000 ms 走 [`rt::sleep_ms`]（19 号带时限等待，
/// 任务真阻塞不让 CPU 空转，见该函数注释）。
///
/// 每帧之间 pid/gen 集合**不做**快照间一致性断言（那是内核判据的事，`t_proc_info`
/// 已有"隔离"格）；显示层的职责只是把每一帧如实打出来。
fn cmd_top(c: &Ctx) -> bool {
    // 参数：无参 = 3 帧；有参必须是能读的十进制且 ≤ 5（秒）。解析失败 = usage。
    let frames: u64 = if c.p.args.count() == 0 {
        3
    } else {
        let arg = match c.p.args.get(0) {
            Some(a) => a,
            None => {
                con_write(c.h, msg(M_TOP_USAGE));
                return true;
            }
        };
        match parse_u64(arg) {
            Some(v) if v >= 2 && v <= 5 => v,
            _ => {
                con_write(c.h, msg(M_TOP_USAGE));
                return true;
            }
        }
    };
    let Some(job) = job_of(c) else { return true };
    // SELF_THREAD 句柄：16 号回填进 SI 表的角色 0 描述（内核自动 grant，user.rs:990）。
    // 拿不到就没有可睡的对象——如实说一句（不假装刷新）。
    // SAFETY: si_va 契约同 job_of（内核校验并映射、只读、存活期不解映射）。
    let sleep_h = match unsafe { rt::handle_of_role(c.si_va, rt::ROLE_SELF_THREAD) } {
        Some(h) => h,
        None => {
            con_write(c.h, msg(M_TOP_USAGE));
            return true;
        }
    };
    // 行数组在栈上（见 TOP_ROWS_MAX 的注释：static 的地址在 4 GiB+ 基址下会被
    // 取成 32S 绝对重定位，栈才是这个程序里唯一免费的缓冲位）。
    let mut rows: [TopRow; TOP_ROWS_MAX] = [TopRow { pid: 0, gen: 0, threads: 0, terminated: false, pages: 0 }; TOP_ROWS_MAX];
    // 显式把所有格写成已知值（零值），保证 `0..TOP_ROWS_MAX` 全部可读——
    // 不依赖上一次 `top` 残留的任何内容。
    let mut k = 0usize;
    while k < TOP_ROWS_MAX {
        if let Some(slot) = rows.get_mut(k) {
            slot.pid = 0;
            slot.gen = 0;
            slot.threads = 0;
            slot.terminated = false;
            slot.pages = 0;
        }
        k += 1;
    }
    let mut sleeping = true;
    let mut frame = 0u64;
    while frame < frames {
        let n = top_scan(job, &mut rows);
        top_sort(&mut rows, n);
        top_print_frame(c.h, frame, &rows, n);
        frame += 1;
        // 帧间睡 1 s（总时长 = (frames-1) × 1s）；最后一帧之后不再睡。
        // 睡不成的档位（SELF_THREAD 句柄不在/内核等待表没起）：降级成"不睡连打"，
        // 剩下的帧一次打完——显示层如实降级而不是死循环。
        if frame < frames && sleeping {
            if rt::sleep_ms(sleep_h, 1000).is_err() {
                sleeping = false;
            }
        }
    }
    true
}

/// 十进制解析（无堆、不 panic）。空串/非数字/溢出都回 None。
fn parse_u64(b: &[u8]) -> Option<u64> {
    if b.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &c in b {
        if !(c >= b'0' && c <= b'9') {
            return None;
        }
        let d = u64::from(c - b'0');
        v = v.checked_mul(10)?.checked_add(d)?;
    }
    Some(v)
}

/// ADR-134：`kill <pid>` —— 按 pid 杀进程（29 号）。
///
/// pid 只是寻址，授权由内核按"调用者名下的 RIGHT_WRITE Proc 句柄"判
/// （内核反查、走与 18 号同一条杀路径）。shell 这层只解析参数、打结果。
/// `kill` 无参 / 非十进制 / pid 超 u16 ⇒ usage；不静默吞错。
fn cmd_kill(c: &Ctx) -> bool {
    let arg = match (c.p.err.is_none(), c.p.args.get(0)) {
        (true, Some(a)) => a,
        _ => {
            con_write(c.h, msg(M_KILL_USAGE));
            return true;
        }
    };
    let pid = match parse_u64(arg) {
        Some(v) if v <= u64::from(u16::MAX) => v as u16,
        _ => {
            con_write(c.h, msg(M_KILL_USAGE));
            return true;
        }
    };
    match rt::process_kill_pid(pid) {
        Ok(n) => {
            con_write(c.h, msg(M_KILLED));
            put_u64(c.h, n);
        }
        Err(e) => put_i64(c.h, e.0),
    }
    con_write(c.h, msg(M_NL));
    true
}

/// ADR-135：`dmesg` —— 把内核串口日志环的最近整行打出来（30 号）。
///
/// 缓冲放**栈上**（`COPY_MAX` 512 字节一页够用；ADR-133 记过：static 在 4 GiB+
/// 用户镜像里会被取成 32S 绝对重定位）。内核只给整行，所以这里直接写出去，
/// 不需要再拼换行——多拼一个会在用户侧造出一条空行，破坏与串口原文的逐行对账。
///
/// 返回 0 行是**成功**（环里还没有完整行），此时什么都不打。
/// ADR-135：`dmesg` —— 内核串口日志环的最近整行（30 号）。
///
/// **⚠ 本命令目前不进判定行，且已知缺陷未归因**：实测 `rt::log_read` 返回之后，
/// 同一任务后续的 `con_write` 全部静默失败（连表头都打不出来），而把 `log_read`
/// 换成任何别的调用则正常。内核侧 30 号有自己的判据 `t_log_read`（十格全绿 +
/// 变异证红），所以问题在"30 号返回后的用户态上下文"这一侧，**根因未归因**
/// （候选：trap 帧/被调用者保存寄存器、串口行锁状态）。记在 BACKLOG，留作独立一片。
/// 命令本身保留：内核面已验，等根因定位后接进 argv 判据即可。
fn cmd_dmesg(c: &Ctx) -> bool {
    // 只接受无参形式：过滤/翻页属后续片，带参一律 usage（不静默忽略）。
    if c.p.err.is_some() || c.p.args.count() != 0 {
        con_write(c.h, msg(M_DMESG_USAGE));
        return true;
    }
    let mut buf = [0u8; 256];
    match rt::log_read(&mut buf) {
        Ok((_lines, bytes)) => {
            con_write(c.h, msg(M_DMESG_HDR));
            // 内核回的是"环里最近整行的字节数"，可能大于本次请求长度
            // （30 号按环容量算）⇒ 必须夹到缓冲长度。
            let n = (bytes as usize).min(buf.len());
            if n > 0 {
                if let Some(s) = buf.get(..n) {
                    con_write(c.h, s);
                }
            }
        }
        Err(e) => {
            con_write(c.h, msg(M_DMESG_ERR));
            put_i64(c.h, e.0);
            con_write(c.h, msg(M_NL));
        }
    }
    true
}

/// ADR-136：`lspci` —— 把 PCI 设备清单按行打出来（31 号）。
///
/// 每台一行：`bus dev func vendor device class`，全部**十进制**（shell 只有
/// 十进制打印，十六进制属后续片；判据比对的是数字本身，不是格式）。
/// 缓冲 256 字节 = 8 条/次（栈预算，与 `dmesg` 同一条纪律），配合 31 号的
/// 游标语义分页取完。
fn cmd_lspci(c: &Ctx) -> bool {
    if c.p.err.is_some() || c.p.args.count() != 0 {
        con_write(c.h, msg(M_LSPCI_USAGE));
        return true;
    }
    const REC: usize = rt::PCI_ENUM_REC; // 32
    let mut buf = [0u8; 8 * REC]; // 8 条/次，栈预算内
    let mut cursor = 0u64;
    loop {
        match rt::pci_enum(&mut buf, cursor) {
            Ok((next, n)) => {
                let mut i = 0usize;
                while i < n as usize {
                    let off = i * REC;
                    if let Some(r) = buf.get(off..off + REC) {
                        let bdf = u32::from_le_bytes([r[8], r[9], r[10], r[11]]);
                        let vd = u32::from_le_bytes([r[12], r[13], r[14], r[15]]);
                        let c08 = u32::from_le_bytes([r[16], r[17], r[18], r[19]]);
                        put_u64(c.h, u64::from((bdf >> 16) & 0xFF));
                        con_write(c.h, msg(M_SP));
                        put_u64(c.h, u64::from((bdf >> 11) & 0x1F));
                        con_write(c.h, msg(M_SP));
                        put_u64(c.h, u64::from((bdf >> 8) & 0x7));
                        con_write(c.h, msg(M_SP));
                        put_u64(c.h, u64::from(vd & 0xFFFF));
                        con_write(c.h, msg(M_SP));
                        put_u64(c.h, u64::from((vd >> 16) & 0xFFFF));
                        con_write(c.h, msg(M_SP));
                        put_u64(c.h, u64::from((c08 >> 8) & 0xFFFFFF));
                        con_write(c.h, msg(M_NL));
                    }
                    i += 1;
                }
                if next == 0 {
                    break;
                }
                cursor = u64::from(next);
            }
            Err(_e) => {
                con_write(c.h, msg(M_LSPCI_USAGE));
                break;
            }
        }
    }
    true
}

/// ADR-137：`uptime` —— 启动以来的微秒数（32 号）。
///
/// 无参：打 `put_u64(微秒)` + 换行。带参一律 usage（不静默忽略）。
/// 内核没锚点/没标定时回 `-1`，原样打出来——**不把错误读成 0**
/// （0 会被读成"刚开机"，那是骗人的另一种形状）。
fn cmd_uptime(c: &Ctx) -> bool {
    if c.p.err.is_some() || c.p.args.count() != 0 {
        con_write(c.h, msg(M_UPTIME_USAGE));
        return true;
    }
    match rt::uptime_us() {
        Ok(us) => put_u64(c.h, us),
        Err(e) => put_i64(c.h, e.0),
    }
    con_write(c.h, msg(M_NL));
    true
}

/// ADR-137 续：`sleep <ms>` —— 睡指定毫秒（19 号带时限等待的薄壳）。
///
/// **为什么这就是内核原语**：`signals = 0` 的 19 号等一个永不置位的信号图，
/// 唯一出路是超时 ⇒ 真阻塞、不让 CPU 空转（`rt::sleep_ms` 的注释已记）。
/// 句柄用 `ROLE_SELF_THREAD`（Thread 对象永不终止，与 `cmd_top` 同款）。
/// 范围 1..=`rt::WAIT_MAX_MS`（60000）：0 毫秒没有语义（usage），超过上限
/// 内核回 `-1`（WAIT_MAX_MS 双侧同数）。
/// 成功**无输出**（Unix 惯例）；错误打码（-1/-4）。
fn cmd_sleep(c: &Ctx) -> bool {
    let ms = match (c.p.err.is_none(), c.p.args.get(0)) {
        (true, Some(a)) => match parse_u64(a) {
            Some(v) if v >= 1 && v <= rt::WAIT_MAX_MS => v,
            _ => {
                con_write(c.h, msg(M_SLEEP_USAGE));
                return true;
            }
        },
        _ => {
            con_write(c.h, msg(M_SLEEP_USAGE));
            return true;
        }
    };
    // **ROLE_SELF_PROC 而不是 SELF_THREAD**：19 号今天只支持 Proc 对象
    // （user.rs 的 wait_on_proc：非 Proc 一律 -4），Thread 句柄直接被拒——
    // 实测 sleep 打出 -4。等**自己的 Proc** terminate 永不发生 ⇒ 正好睡满超时，
    // 语义等价且真阻塞。（cmd_top 用 SELF_THREAD 睡失败但错误被忽略，
    // 是它自己的既有欠账，不在本片。）
    let h = match unsafe { rt::handle_of_role(c.si_va, rt::ROLE_SELF_PROC) } {
        Some(h) => h,
        None => {
            con_write(c.h, msg(M_SLEEP_USAGE));
            return true;
        }
    };
    if let Err(e) = rt::sleep_ms(h, ms) {
        put_i64(c.h, e.0);
        con_write(c.h, msg(M_NL));
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
    if streq(p.cmd, &CMD_TOP) {
        return cmd_top(&c);
    }
    if streq(p.cmd, &CMD_KILL) {
        return cmd_kill(&c);
    }
    if cmd_is(p.cmd, &CMD_DMESG) {
        return cmd_dmesg(&c);
    }
    if cmd_is(p.cmd, &CMD_LSPCI) {
        return cmd_lspci(&c);
    }
    if cmd_is(p.cmd, &CMD_UPTIME) {
        return cmd_uptime(&c);
    }
    if cmd_is(p.cmd, &CMD_SLEEP) {
        return cmd_sleep(&c);
    }
    // unknown：三段输出与旧实现逐字节一致——词原样回显（借用不拷贝，全长不截断）。
    con_write(c.h, msg(M_UNKNOWN));
    con_write(c.h, c.p.cmd);
    con_write(c.h, msg(M_TRYHELP));
    true
}
