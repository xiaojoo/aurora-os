//! 规则模型（五元组 + 方向 + 动作）、参考语义、编译到字节码。
//!
//! * [`rule_matches`] / [`eval_rules`] 是**参考语义**：逐位比较前缀、闭区间比端口，不经过字节码。
//! * [`compile`] 把规则表编成字节码；产物必须能过 [`crate::verify`]，且对任意包与参考语义判决一致
//!   （宿主机差分检验，见 README T4）。
//!
//! 语义：**首条命中**（first match），都不命中取 `default`。没有 Reject：第一期挂载点
//! 只能"不投递"，要回 ICMP 不可达需要在 `deliver_frame` 里发包（NDP 分支今天就在那里发 NA，
//! 机制上可行），但那会让过滤器成为放大器——列为第二期（ADR-267 §6）。

use crate::exec::Verdict;
use crate::insn::{op, Insn, INSN_BYTES, MAX_INSNS, V_ACCEPT, V_DROP};
use crate::packet::{field, word, Dir, Packet, FAMILY_V4, FAMILY_V6};

/// 动作。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// 放行。
    Accept,
    /// 丢弃。
    Drop,
}

impl Action {
    /// `RET` 的判决码。
    pub const fn code(self) -> u32 {
        match self {
            Action::Accept => V_ACCEPT,
            Action::Drop => V_DROP,
        }
    }
    /// 对应的判决。
    pub const fn verdict(self) -> Verdict {
        match self {
            Action::Accept => Verdict::Accept,
            Action::Drop => Verdict::Drop,
        }
    }
}

/// 地址前缀。`addr` 为 16 字节（IPv4 占前 4 字节），`len` 为位数。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    /// 地址。
    pub addr: [u8; 16],
    /// 前缀位数（IPv4 ≤ 32，IPv6 ≤ 128）。
    pub len: u8,
}

impl Prefix {
    /// IPv4 前缀。
    pub fn v4(a: [u8; 4], len: u8) -> Prefix {
        Prefix { addr: [a[0], a[1], a[2], a[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len }
    }
    /// IPv6 前缀。
    pub fn v6(a: [u8; 16], len: u8) -> Prefix {
        Prefix { addr: a, len }
    }
}

/// 端口闭区间 `[lo, hi]`。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRange {
    /// 下界（含）。
    pub lo: u16,
    /// 上界（含）。
    pub hi: u16,
}

/// 一条规则。`None` = 该维度不限。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    /// 方向（第一期内核只以 `In` 调用；`Out` 规则编得出来但永不命中）。
    pub dir: Dir,
    /// 地址族。写了前缀就必须写族。
    pub family: Option<u8>,
    /// 协议号。
    pub proto: Option<u8>,
    /// 源地址前缀。
    pub src: Option<Prefix>,
    /// 目的地址前缀。
    pub dst: Option<Prefix>,
    /// 源端口区间。
    pub sport: Option<PortRange>,
    /// 目的端口区间。
    pub dport: Option<PortRange>,
    /// 动作。
    pub action: Action,
}

impl Rule {
    /// 只限方向的规则（其余维度不限）。
    pub const fn any(dir: Dir, action: Action) -> Rule {
        Rule { dir, family: None, proto: None, src: None, dst: None, sport: None, dport: None, action }
    }
}

/// 编译失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompileError {
    /// 产物超过 [`MAX_INSNS`] 条（规则表太大）。
    TooManyInsns,
    /// 输出缓冲装不下。
    OutTooSmall,
    /// `family` 不是 4/6。
    BadFamily {
        /// 规则下标。
        rule: usize,
    },
    /// 写了前缀却没写族。
    PrefixWithoutFamily {
        /// 规则下标。
        rule: usize,
    },
    /// 前缀位数超过族的地址长度。
    PrefixTooLong {
        /// 规则下标。
        rule: usize,
    },
    /// 端口区间 `lo > hi`。
    EmptyPortRange {
        /// 规则下标。
        rule: usize,
    },
    /// 内部长度核算不一致（不应发生；返回错误而不是 panic）。
    Internal,
}

// ---------------------------------------------------------------- 参考语义

fn prefix_match(px: &Prefix, a: &[u8; 16]) -> bool {
    let mut bit = 0usize;
    while bit < usize::from(px.len) && bit < 128 {
        let byte = bit / 8;
        let m = 0x80u8 >> (bit % 8);
        let (x, y) = match (px.addr.get(byte), a.get(byte)) {
            (Some(x), Some(y)) => (*x, *y),
            _ => return false,
        };
        if x & m != y & m {
            return false;
        }
        bit += 1;
    }
    true
}

/// 一条规则是否命中（参考语义）。
pub fn rule_matches(r: &Rule, p: &Packet) -> bool {
    if r.dir != p.dir {
        return false;
    }
    if let Some(f) = r.family {
        if p.family != f {
            return false;
        }
    }
    if let Some(pr) = r.proto {
        if p.proto != pr {
            return false;
        }
    }
    if let Some(px) = &r.src {
        if !prefix_match(px, &p.src) {
            return false;
        }
    }
    if let Some(px) = &r.dst {
        if !prefix_match(px, &p.dst) {
            return false;
        }
    }
    if let Some(pr) = r.sport {
        if p.sport < pr.lo || p.sport > pr.hi {
            return false;
        }
    }
    if let Some(pr) = r.dport {
        if p.dport < pr.lo || p.dport > pr.hi {
            return false;
        }
    }
    true
}

/// 规则表判决（参考语义，首条命中）。
pub fn eval_rules(rules: &[Rule], default: Action, p: &Packet) -> Verdict {
    for r in rules {
        if rule_matches(r, p) {
            return r.action.verdict();
        }
    }
    default.verdict()
}

// ---------------------------------------------------------------- 编译

/// 前缀第 `i` 个 32 位字的 (掩码, 掩码后的值)；`None` = 这一字不参与比较。
fn prefix_word(px: &Prefix, i: u32) -> Option<(u32, u32)> {
    let used = u32::from(px.len).saturating_sub(32 * i).min(32);
    if used == 0 {
        return None;
    }
    let mask = if used == 32 { u32::MAX } else { !(u32::MAX >> used) };
    let w = word(&px.addr, i)?;
    Some((mask, w & mask))
}

fn prefix_insns(px: Option<&Prefix>) -> usize {
    let Some(px) = px else { return 0 };
    let mut n = 0usize;
    let mut i = 0u32;
    while i < 4 {
        match prefix_word(px, i) {
            Some((m, _)) => n += if m == u32::MAX { 2 } else { 3 },
            None => break,
        }
        i += 1;
    }
    n
}

fn range_insns(pr: Option<PortRange>) -> usize {
    let Some(pr) = pr else { return 0 };
    if pr.lo == 0 && pr.hi == u16::MAX {
        return 0;
    }
    if pr.lo == pr.hi {
        return 2;
    }
    1 + usize::from(pr.lo > 0) + usize::from(pr.hi < u16::MAX)
}

fn rule_insns(r: &Rule) -> usize {
    let fam = 2 * usize::from(r.family.is_some());
    let proto = 2 * usize::from(r.proto.is_some());
    2 + fam + proto
        + prefix_insns(r.src.as_ref())
        + prefix_insns(r.dst.as_ref())
        + range_insns(r.sport)
        + range_insns(r.dport)
        + 1
}

fn validate(r: &Rule, idx: usize) -> Result<(), CompileError> {
    if let Some(f) = r.family {
        if f != FAMILY_V4 && f != FAMILY_V6 {
            return Err(CompileError::BadFamily { rule: idx });
        }
    }
    for px in [r.src, r.dst].iter().flatten() {
        let max = match r.family {
            None => return Err(CompileError::PrefixWithoutFamily { rule: idx }),
            Some(FAMILY_V4) => 32,
            Some(_) => 128,
        };
        if px.len > max {
            return Err(CompileError::PrefixTooLong { rule: idx });
        }
    }
    for pr in [r.sport, r.dport].iter().flatten() {
        if pr.lo > pr.hi {
            return Err(CompileError::EmptyPortRange { rule: idx });
        }
    }
    Ok(())
}

struct Writer<'a> {
    out: &'a mut [u8],
    n: usize,
}

impl Writer<'_> {
    fn push(&mut self, i: Insn) -> Result<(), CompileError> {
        if self.n >= MAX_INSNS {
            return Err(CompileError::TooManyInsns);
        }
        let lo = self.n * INSN_BYTES;
        let dst = self.out.get_mut(lo..lo + INSN_BYTES).ok_or(CompileError::OutTooSmall)?;
        dst.copy_from_slice(&i.encode());
        self.n += 1;
        Ok(())
    }

    /// 发一条"条件成立 ⇒ 跳到本规则末尾之后（下一条规则）"的跳转。
    fn skip_if(&mut self, opc: u8, imm: u32, end: usize) -> Result<(), CompileError> {
        let off = end.checked_sub(self.n + 1).ok_or(CompileError::Internal)?;
        let off = i16::try_from(off).map_err(|_| CompileError::TooManyInsns)?;
        self.push(Insn { op: opc, a: 0, off, imm })
    }
}

/// 把规则表编成字节码写进 `out`，返回字节数。`out` 至少 [`crate::MAX_PROG_BYTES`] 字节最稳妥。
///
/// 形状（每条规则）：`LDF r0,DIR; JNE r0,dir,→next; [族][协议][源前缀][目的前缀][源端口][目的端口]; RET 动作`，
/// 末尾 `RET default`。只用 r0，每次比较前都重新装载 ⇒ 不存在未初始化读；每条规则至少有方向检查这条
/// 前跳 ⇒ 下一条规则可达 ⇒ 不存在不可达代码。
pub fn compile(rules: &[Rule], default: Action, out: &mut [u8]) -> Result<usize, CompileError> {
    let mut w = Writer { out, n: 0 };
    for (idx, r) in rules.iter().enumerate() {
        validate(r, idx)?;
        let end = w.n + rule_insns(r);
        w.push(Insn::ldf(0, field::DIR))?;
        w.skip_if(op::JNE, r.dir.code(), end)?;
        if let Some(f) = r.family {
            w.push(Insn::ldf(0, field::FAMILY))?;
            w.skip_if(op::JNE, u32::from(f), end)?;
        }
        if let Some(p) = r.proto {
            w.push(Insn::ldf(0, field::PROTO))?;
            w.skip_if(op::JNE, u32::from(p), end)?;
        }
        for (base, px) in [(field::SRC0, r.src), (field::DST0, r.dst)] {
            let Some(px) = px else { continue };
            let mut i = 0u32;
            while i < 4 {
                let Some((mask, val)) = prefix_word(&px, i) else { break };
                w.push(Insn::ldf(0, base + i))?;
                if mask != u32::MAX {
                    w.push(Insn::and(0, mask))?;
                }
                w.skip_if(op::JNE, val, end)?;
                i += 1;
            }
        }
        for (fld, pr) in [(field::SPORT, r.sport), (field::DPORT, r.dport)] {
            let Some(pr) = pr else { continue };
            if pr.lo == 0 && pr.hi == u16::MAX {
                continue;
            }
            w.push(Insn::ldf(0, fld))?;
            if pr.lo == pr.hi {
                w.skip_if(op::JNE, u32::from(pr.lo), end)?;
            } else {
                if pr.lo > 0 {
                    w.skip_if(op::JLT, u32::from(pr.lo), end)?;
                }
                if pr.hi < u16::MAX {
                    w.skip_if(op::JGT, u32::from(pr.hi), end)?;
                }
            }
        }
        w.push(Insn::ret(r.action.code()))?;
        if w.n != end {
            return Err(CompileError::Internal);
        }
    }
    w.push(Insn::ret(default.code()))?;
    Ok(w.n * INSN_BYTES)
}
