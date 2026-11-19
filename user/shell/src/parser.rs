//! A3：行解析器——一行字节 → 命令词 + 参数表。
//!
//! 约定与边界（每一条都有出处）：
//! - **切分只认空格（b' '）**。命令词在第一个空格处切，Tab 不是分隔符——
//!   这不是随手的选择：旧 `dispatch` 就是这么切的，逐字节回归线要求
//!   新解析器在同形输入上产出同一个命令词，所以规则原样搬过来。
//! - **成对双引号**：词首的 `"` 开启，到下一个 `"` 关闭，期间的空格并进同一个词。
//!   词中的引号按普通字节；空串引号 `""` 不产出词（与旧实现的"连续空格不产词"同口径）。
//!   管道 `|` 由 [`split_pipe`] 单独切（ADR-155）：`parse` 不认它，
//!   调用方先切管道再逐段 `parse`——这样"一个词的解析"与"多段的组合"
//!   是两件事，各自的边界都能单独测。
//! - 静态缓冲、无堆；所有容量编译期定死。**任何输入都不 panic**：
//!   空行、超长、引号不闭合、非 ASCII 字节，走到的都是普通分支。
//! - **超限记错误而不是截断假装成功**：个数超 `ARG_MAX`、单词超 `ARG_LEN`、
//!   引号不闭合，都记进 `Parsed::err`，此时 `args` 只含出错前收下的完整词。
//!   本片五个内置命令都不消费 `args`（echo 用 `rest` 保持逐字节兼容），
//!   所以 `err` 不改变任何输出路径；将来带参的命令必须先看它。
//! - `cmd`/`rest` **借用输入行，不拷贝**：unknown 回显要原样全长，
//!   拷进定长缓冲就会把长命令词截断——旧实现是整词回显的。

/// 单个参数的容量上限（字节）。
pub const ARG_LEN: usize = 32;
/// 参数个数上限。
pub const ARG_MAX: usize = 8;

/// 词法超限的种类。只记录、不打印：显示策略归调用方。
pub enum ParseError {
    /// 参数个数超过 [`ARG_MAX`]。
    TooManyArgs,
    /// 单个参数超过 [`ARG_LEN`] 字节。
    ArgTooLong,
    /// 双引号不闭合。
    UnterminatedQuote,
}

/// 去引号后的参数表（固定容量，无堆）。
pub struct Args {
    buf: [[u8; ARG_LEN]; ARG_MAX],
    lens: [usize; ARG_MAX],
    count: usize,
}

impl Args {
    fn new() -> Self {
        Args { buf: [[0; ARG_LEN]; ARG_MAX], lens: [0; ARG_MAX], count: 0 }
    }

    /// 已收下的参数个数。
    #[allow(dead_code)] // A3 的接口面：当前五命令都不消费 args（echo 用 rest 保逐字节兼容），
    pub fn count(&self) -> usize { // 留给后续带参命令切片用；提前声明免得接口悄悄漂移。
        self.count
    }

    /// 第 `i` 个参数。越界回 `None`，不 panic。
    #[allow(dead_code)] // 同上：args 消费方尚未进来。
    pub fn get(&self, i: usize) -> Option<&[u8]> {
        let len = *self.lens.get(i)?;
        // len 在写入时已保证 <= ARG_LEN；这里再用 get(..len) 兜一层，
        // 即使不变量将来被改坏，也只是回 None，不会 panic。
        self.buf.get(i)?.get(..len)
    }
}

/// 解析产物。
pub struct Parsed<'a> {
    /// 命令词（借用输入行）。原样全长，见模块头的"不拷贝"理由。
    pub cmd: &'a [u8],
    /// 命令词之后的原始剩余（不重切）。echo 用它保持逐字节兼容，见 `registry::cmd_echo`。
    pub rest: &'a [u8],
    /// 去引号切分后的参数表。
    // A3 接口面：带参命令（后续切片）先查 err 再用 args；本片五命令都不消费，
    // 所以这两个字段暂无读者——这是"解析器 API 先到位、消费方后到"的既定顺序，
    // 不是死代码。不许为了让 lint 安静而假消费。
    #[allow(dead_code)]
    pub args: Args,
    /// 词法超限（个数/宽度/引号不闭合）。`Some` 时 `args` 只含出错前的完整词。
    #[allow(dead_code)] // 同 args。
    pub err: Option<ParseError>,
}

/// 解析一行。首尾修剪与命令词切分逐条照搬旧 `dispatch`：
/// 头部去空格/Tab，尾部去空格/Tab/CR，第一个 b' ' 之前是命令词。
pub fn parse(line: &[u8]) -> Parsed<'_> {
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
        // 全空白行：旧实现静默返回，不产出任何输出。
        return Parsed { cmd: &[], rest: &[], args: Args::new(), err: None };
    }
    // 只在第一个 b' ' 处分出命令词（Tab 属于词内字节，旧实现同）。
    let (cmd, rest) = match s.iter().position(|c| *c == b' ') {
        Some(i) => match s.split_at_checked(i) {
            Some((a, b)) => (a, b.get(1..).unwrap_or(&[])),
            None => (s, &[][..]),
        },
        None => (s, &[][..]),
    };
    let mut args = Args::new();
    let mut err = None;
    tokenize(rest, &mut args, &mut err);
    Parsed { cmd, rest, args, err }
}

/// 把 [`Parsed::rest`] 切成词。只认空格；词首引号开启"空格并入"模式。
/// 第一个超限发生即记 [`ParseError`] 并停止（首个错误优先，`args` 保留此前收下的完整词）。
fn tokenize(rest: &[u8], args: &mut Args, err: &mut Option<ParseError>) {
    // 当前词的暂存区：词落地前先在栈上攒，超宽当场记错，绝不截断。
    let mut tok = [0u8; ARG_LEN];
    let mut tlen = 0usize;
    let mut started = false; // 本词是否开始（引号开启也算开始）
    let mut in_quotes = false;
    let mut i = 0usize;
    while let Some(&c) = rest.get(i) {
        if !in_quotes && c == b' ' {
            // 词边界：落词、清暂存。落词失败（超限）直接结束。
            if !commit(&tok, tlen, started, args, err) {
                return;
            }
            tlen = 0;
            started = false;
            i += 1;
            continue;
        }
        if !started && c == b'"' {
            // 词首引号：开启并入模式，引号本身不进词。
            started = true;
            in_quotes = true;
            i += 1;
            continue;
        }
        if in_quotes && c == b'"' {
            // 闭引号：退出并入模式，继续收同一词的后续字节。
            in_quotes = false;
            i += 1;
            continue;
        }
        // 普通字节进词（含词中的引号与非 ASCII 字节——都是普通数据，不会 panic）。
        if tlen == ARG_LEN {
            *err = Some(ParseError::ArgTooLong);
            return;
        }
        if let Some(slot) = tok.get_mut(tlen) {
            *slot = c;
        }
        tlen += 1;
        started = true;
        i += 1;
    }
    if in_quotes {
        // 收到行尾引号还没闭合：记错。此时最后那个词不该落——它是不完整的。
        *err = Some(ParseError::UnterminatedQuote);
        return;
    }
    commit(&tok, tlen, started, args, err);
}

/// 把暂存区里的词落进参数表。返回 false = 已记超限错误，调用方应停止。
/// 空词（长度 0，含空串引号 `""`）不落——与旧实现"连续空格不产词"同口径。
fn commit(
    tok: &[u8; ARG_LEN],
    tlen: usize,
    started: bool,
    args: &mut Args,
    err: &mut Option<ParseError>,
) -> bool {
    if !started || tlen == 0 {
        return true;
    }
    if args.count >= ARG_MAX {
        *err = Some(ParseError::TooManyArgs);
        return false;
    }
    // 索引全部走 get/get_mut：即使计数被改坏，也只是少收一个词，不会 panic。
    let n = args.count;
    if let (Some(dst), Some(l)) = (args.buf.get_mut(n), args.lens.get_mut(n)) {
        for j in 0..tlen {
            if let (Some(src), Some(dst_slot)) = (tok.get(j), dst.get_mut(j)) {
                *dst_slot = *src;
            }
        }
        *l = tlen;
    }
    args.count += 1;
    true
}

/// 管道切分（ADR-155）：把一行按 `|` 切成最多 [`PIPE_MAX`] 段。
///
/// **为什么不在 `tokenize` 里做**：管道是**段间**结构，而 tokenize 处理的是
/// **段内**词法。混在一起会让"引号里的 `|` 算不算分隔符"变成一个必须回答的问题
/// ——今天不回答它（引号内的 `|` 一律当普通字节，因为切分发生在 parse 之前，
/// 此时还不知道引号状态）。这是**明确的限制**，写进 ADR-155 未决 1。
///
/// 返回切出的段数；每段是**原样的字节切片**（不去空格，交给 `parse` 修剪）。
/// 空段（`a || b` 或行首 `|`）**保留**——由调用方判"空段 = 语法错误"，
/// 因为"要不要报错"是执行策略，不是词法事实。
pub const PIPE_MAX: usize = 4;

pub fn split_pipe(line: &[u8]) -> ([&[u8]; PIPE_MAX], usize) {
    let mut segs: [&[u8]; PIPE_MAX] = [&[]; PIPE_MAX];
    let mut n = 0usize;
    let mut start = 0usize;
    let mut i = 0usize;
    while let Some(&c) = line.get(i) {
        if c == b'|' {
            if n == PIPE_MAX {
                // 超过上限：把剩余全部并入最后一段（不丢字节，也不静默截断）
                break;
            }
            if let Some(s) = line.get(start..i) {
                if let Some(slot) = segs.get_mut(n) {
                    *slot = s;
                }
                n += 1;
            }
            start = i + 1;
        }
        i += 1;
    }
    if n < PIPE_MAX {
        if let Some(s) = line.get(start..) {
            if let Some(slot) = segs.get_mut(n) {
                *slot = s;
            }
            n += 1;
        }
    }
    (segs, n)
}
