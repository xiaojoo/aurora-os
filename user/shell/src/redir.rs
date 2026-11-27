//! S2 步骤 4：shell 重定向（词法层）`>` `>>` `<`。
//!
//! ## 在哪一层剥
//! 与 `parser::split_pipe` 同层、**在 `parser::parse` 之前**：`echo` 用 `Parsed::rest`（原样字节）保逐字节兼容，
//! 所以不能改 `parse`/`tokenize`；这里把重定向从行里剥掉，剩下的“命令部分”原样交给 `parse`。
//!
//! ## 规则（与 parser.rs 同口径）
//! * 只认**空格**为分隔；`"` 在**词首**开启并入模式，期间的 `> <` 是普通字节（`echo "a > b"` 不触发重定向）。
//! * 重定向符：`>`、`>>`、`<`；目标可连写（`>f`）或分写（`> f`）。目标到下一个空格/`> < "` 为止。
//! * 目标为空（行尾 `>`）→ `EmptyTarget`；引号未闭合 → `UnterminatedQuote`（与 `ParseError` 同属“记错误不假装成功”）。
//! * 静态缓冲、无堆、**任何输入不 panic**：全部下标走 `get`。
//! * 已知限制（沿用 ADR-155 对 `|` 的取舍）：本函数在 `split_pipe` 之后、逐段调用；引号状态以**段内**计。
//!
//! S3 补完：已由 `main.rs::run_one_redirected` 调用。`#[cfg(test)]` 用例需本机 `cargo test`
//! （user/shell 是 no_std 二进制，纯逻辑建议另抽 crate 做宿主机测试）。

/// 一行里最多接受的重定向条数（超出记 `TooMany`）。目标只存借用，不拷贝。
pub const REDIR_MAX: usize = 3;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind { In, Out, Append }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RedirError { EmptyTarget, UnterminatedQuote, TooMany }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Redir<'a> { pub kind: Kind, pub target: &'a [u8] }

pub struct Split<'a> {
    /// 剥掉重定向后的命令部分（借用输入行的前缀/子串；因为重定向可在中间，这里返回**写入调用方缓冲**后的长度，见 `strip`）。
    pub cmd_len: usize,
    pub redirs: [Redir<'a>; REDIR_MAX],
    pub n: usize,
    pub err: Option<RedirError>,
}

const EMPTY: Redir<'static> = Redir { kind: Kind::Out, target: &[] };

/// 把 `line` 里的重定向剥掉：命令部分写入 `cmd_out[..cmd_len]`，目标借用 `line`。
/// `cmd_out` 至少与 `line` 等长（调用方用与行缓冲同容量的数组）。
pub fn strip<'a>(line: &'a [u8], cmd_out: &mut [u8]) -> Split<'a> {
    let mut sp = Split { cmd_len: 0, redirs: [EMPTY; REDIR_MAX], n: 0, err: None };
    let n = line.len();
    let (mut i, mut o) = (0usize, 0usize);
    let mut inq = false;
    while i < n {
        let c = match line.get(i) { Some(&c) => c, None => break };
        if c == b'"' {
            let at_word_start = i == 0 || line.get(i - 1) == Some(&b' ');
            if !inq && at_word_start { inq = true } else if inq { inq = false }
            if !put(cmd_out, &mut o, c) { break; }
            i += 1;
            continue;
        }
        if !inq && (c == b'>' || c == b'<') {
            let mut kind = if c == b'<' { Kind::In } else { Kind::Out };
            i += 1;
            if kind == Kind::Out && line.get(i) == Some(&b'>') { kind = Kind::Append; i += 1; }
            while line.get(i) == Some(&b' ') { i += 1; }
            let start = i;
            while let Some(&d) = line.get(i) {
                if d == b' ' || d == b'>' || d == b'<' || d == b'"' { break; }
                i += 1;
            }
            let target = line.get(start..i).unwrap_or(&[]);
            if target.is_empty() { sp.err = Some(RedirError::EmptyTarget); break; }
            match sp.redirs.get_mut(sp.n) {
                Some(slot) => { *slot = Redir { kind, target }; sp.n += 1; }
                None => { sp.err = Some(RedirError::TooMany); break; }
            }
            continue;
        }
        if !put(cmd_out, &mut o, c) { break; }
        i += 1;
    }
    if sp.err.is_none() && inq { sp.err = Some(RedirError::UnterminatedQuote); }
    // 去尾部空格（与 parse 的尾修剪同口径，错误分支也统一）
    while o > 0 && cmd_out.get(o - 1) == Some(&b' ') { o -= 1; }
    sp.cmd_len = o;
    sp
}

#[inline]
fn put(buf: &mut [u8], o: &mut usize, c: u8) -> bool {
    match buf.get_mut(*o) { Some(s) => { *s = c; *o += 1; true } None => false }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(line: &[u8]) -> (std::vec::Vec<u8>, std::vec::Vec<(Kind, std::vec::Vec<u8>)>, Option<RedirError>) {
        let mut buf = [0u8; 256];
        let s = strip(line, &mut buf);
        (buf[..s.cmd_len].to_vec(), s.redirs[..s.n].iter().map(|r| (r.kind, r.target.to_vec())).collect(), s.err)
    }
    #[test] fn out() { assert_eq!(run(b"echo hi > f"), (b"echo hi".to_vec(), vec![(Kind::Out, b"f".to_vec())], None)); }
    #[test] fn append() { assert_eq!(run(b"echo hi >> f").1, vec![(Kind::Append, b"f".to_vec())]); }
    #[test] fn input() { assert_eq!(run(b"cat < in").1, vec![(Kind::In, b"in".to_vec())]); }
    #[test] fn glued_target() { assert_eq!(run(b"echo hi >f").1, vec![(Kind::Out, b"f".to_vec())]); }
    #[test] fn both() { assert_eq!(run(b"cat < in > out").1, vec![(Kind::In, b"in".to_vec()), (Kind::Out, b"out".to_vec())]); }
    #[test] fn quoted_gt_is_data() { assert_eq!(run(b"echo \"a > b\""), (b"echo \"a > b\"".to_vec(), vec![], None)); }
    #[test] fn quoted_then_redir() { assert_eq!(run(b"echo \"a > b\" > f").1, vec![(Kind::Out, b"f".to_vec())]); }
    #[test] fn empty_target() { assert_eq!(run(b"echo hi >").2, Some(RedirError::EmptyTarget)); assert_eq!(run(b"echo hi >   ").0, b"echo hi".to_vec()); }
    #[test] fn unterminated() { assert_eq!(run(b"echo \"x").2, Some(RedirError::UnterminatedQuote)); }
    #[test] fn too_many() { assert_eq!(run(b"a > 1 > 2 > 3 > 4").2, Some(RedirError::TooMany)); }
    #[test] fn plain_and_empty() { assert_eq!(run(b"ls"), (b"ls".to_vec(), vec![], None)); assert_eq!(run(b""), (vec![], vec![], None)); }
    #[test] fn never_panics_on_garbage() {
        let mut x = 0x1234_5678u32;
        for _ in 0..20_000 {
            let len = (x % 30) as usize; let mut v = std::vec::Vec::new();
            for _ in 0..len { x ^= x << 13; x ^= x >> 17; x ^= x << 5; v.push(b" ><\"|abc\0\xff"[(x % 10) as usize]); }
            let mut buf = [0u8; 64]; let _ = strip(&v, &mut buf);
        }
    }
}
