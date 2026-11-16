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
use crate::{M_ABI, M_BYE, M_HELP, M_NL, M_PING, M_TRYHELP, M_UNKNOWN};

/// 控制台句柄（内核按角色 `ROLE_LOG` 转移给 shell 的那个 u64）。
pub type ConsoleHandle = u64;

// ---- 命令词：const 字节数组折成 immediates，不取地址（沿用旧 dispatch 的纪律）----
const CMD_HELP: [u8; 4] = [b'h', b'e', b'l', b'p'];
const CMD_ECHO: [u8; 4] = [b'e', b'c', b'h', b'o'];
const CMD_PING: [u8; 4] = [b'p', b'i', b'n', b'g'];
const CMD_ABI: [u8; 3] = [b'a', b'b', b'i'];
const CMD_EXIT: [u8; 4] = [b'e', b'x', b'i', b't'];

/// 命令词比较。走 `&[u8] == &[u8]`，LLVM 折成 immediate 比较（旧 dispatch 同款）。
fn streq(a: &[u8], b: &[u8]) -> bool {
    a == b
}

// ---- 五个处理器：统一签名，返回 false = 退出 shell ----

fn cmd_help(h: ConsoleHandle, _p: &Parsed) -> bool {
    con_write(h, msg(M_HELP));
    true
}

/// **为什么用 `p.rest` 而不是 `p.args`**：旧实现 echo 打印的是"第一个空格之后的
/// 原始剩余"——多空格、Tab、引号都原样回显。`args` 是切分去引号后的词，
/// 用它会在 `echo a  b`、`echo "x"` 这类输入上改字节，撞逐字节回归线。
/// 引号切分的收益留给将来真正带参的命令（先查 `p.err` 再用 `args`）。
fn cmd_echo(h: ConsoleHandle, p: &Parsed) -> bool {
    con_write(h, p.rest);
    con_write(h, msg(M_NL));
    true
}

fn cmd_ping(h: ConsoleHandle, _p: &Parsed) -> bool {
    // A2 接线：1 号调用迁到 `rt::ping()`（返回值同义：内核服务计数）。
    let n = rt::ping();
    con_write(h, msg(M_PING));
    put_u64(h, n);
    con_write(h, msg(M_NL));
    true
}

fn cmd_abi(h: ConsoleHandle, _p: &Parsed) -> bool {
    // A2 接线：7 号调用迁到 `rt::abi_info()`。
    let v = rt::abi_info();
    con_write(h, msg(M_ABI));
    put_u64(h, v);
    con_write(h, msg(M_NL));
    true
}

fn cmd_exit(h: ConsoleHandle, _p: &Parsed) -> bool {
    con_write(h, msg(M_BYE));
    false
}

/// 分派一条已解析的命令。返回 false = 退出 shell。
///
/// 每个分支都是"名字 immediate 比较 → 直接调用处理器"，不写 `match lookup()`：
/// 多分支枚举 match 有被 LLVM 降成跳转表的前科（`ctrl_c` 注释记过）。
///
/// **加命令的配方**：一个 const 名字数组 + 一个处理器 + 链上加一节；
/// 带参命令在处理器里先查 `p.err` 再用 `p.args`。
pub fn dispatch(h: ConsoleHandle, p: &Parsed) -> bool {
    if p.cmd.is_empty() {
        // 空行：旧实现静默回到提示符，不产出任何输出。
        return true;
    }
    if streq(p.cmd, &CMD_HELP) {
        return cmd_help(h, p);
    }
    if streq(p.cmd, &CMD_ECHO) {
        return cmd_echo(h, p);
    }
    if streq(p.cmd, &CMD_PING) {
        return cmd_ping(h, p);
    }
    if streq(p.cmd, &CMD_ABI) {
        return cmd_abi(h, p);
    }
    if streq(p.cmd, &CMD_EXIT) {
        return cmd_exit(h, p);
    }
    // unknown：三段输出与旧实现逐字节一致——词原样回显（借用不拷贝，全长不截断）。
    con_write(h, msg(M_UNKNOWN));
    con_write(h, p.cmd);
    con_write(h, msg(M_TRYHELP));
    true
}
