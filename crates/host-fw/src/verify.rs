//! 加载期验证器（攻击面）。
//!
//! 只有通过本验证器的字节码才能变成 [`Program`]（字段私有，**唯一构造路径**是 [`verify`] / [`verify_into`]），
//! 内核也只存 `Program`。拒绝规则（按检查顺序；错误码 `code()` 进 82 号的统计记录）：
//!
//! | 码 | 变体 | 拒绝什么 |
//! |---|---|---|
//! | 1 | `Empty` | 空程序 |
//! | 2 | `Misaligned` | 字节数不是 8 的倍数（截断/拼接） |
//! | 3 | `TooLong` | 超过 [`MAX_INSNS`] 条 |
//! | 4 | `BadOpcode` | 非法操作码（含"调用""存储"等一切未定义编码） |
//! | 5 | `BadReg` | 寄存器号 ≥ 4（寄存器"溢出"） |
//! | 6 | `Reserved` | 保留字段非 0（拒绝非规范编码，避免同义不同码） |
//! | 7 | `BadField` | `LDF` 字段号越界 |
//! | 8 | `BadVerdict` | `RET` 判决码不是 0/1 |
//! | 9 | `BackwardJump` | `off<0` 或目标 `≤ pc`（后向跳转/自环 ⇒ 环） |
//! | 10 | `JumpOutOfRange` | 目标 `≥ len` |
//! | 11 | `FallsOffEnd` | 最后一条不是 `RET`（无终止） |
//! | 12 | `Unreachable` | 有不可达指令 |
//! | 13 | `UninitRead` | 某条路径上读了未写过的寄存器（前向数据流，汇合取**交集**） |
//!
//! 寄存器机没有栈，所以"栈溢出/下溢"在本设计里不存在；对应的检查是 `BadReg`（越界寄存器）与
//! `UninitRead`（读未定义值）。执行器把寄存器初始化为 0，所以 `UninitRead` 不是内存安全问题，
//! 而是**语义卫生**：它让"程序结果只取决于包字段与立即数"成为验证期可判定的事实。

use crate::insn::{falls_through, is_jump, op, reads_reg, writes_reg, Insn, INSN_BYTES, MAX_INSNS, NREGS, V_ACCEPT, V_DROP};
use crate::packet::field;

/// 验证失败的原因。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// 空程序。
    Empty,
    /// 字节数不是 8 的倍数。
    Misaligned {
        /// 实际字节数。
        len: usize,
    },
    /// 指令数超过 [`MAX_INSNS`]。
    TooLong {
        /// 实际指令数。
        insns: usize,
    },
    /// 非法操作码。
    BadOpcode {
        /// 指令下标。
        pc: usize,
    },
    /// 寄存器号越界。
    BadReg {
        /// 指令下标。
        pc: usize,
    },
    /// 保留字段非 0。
    Reserved {
        /// 指令下标。
        pc: usize,
    },
    /// 字段号越界。
    BadField {
        /// 指令下标。
        pc: usize,
    },
    /// 判决码非法。
    BadVerdict {
        /// 指令下标。
        pc: usize,
    },
    /// 后向跳转 / 自环。
    BackwardJump {
        /// 指令下标。
        pc: usize,
    },
    /// 跳转目标越界。
    JumpOutOfRange {
        /// 指令下标。
        pc: usize,
    },
    /// 最后一条不是 `RET`。
    FallsOffEnd,
    /// 不可达指令。
    Unreachable {
        /// 指令下标。
        pc: usize,
    },
    /// 读未初始化寄存器。
    UninitRead {
        /// 指令下标。
        pc: usize,
        /// 寄存器号。
        reg: u8,
    },
}

impl VerifyError {
    /// 稳定的数字码（82 号统计记录的 `last_reject` 字段；0 = 从未拒绝）。
    pub const fn code(self) -> u32 {
        match self {
            VerifyError::Empty => 1,
            VerifyError::Misaligned { .. } => 2,
            VerifyError::TooLong { .. } => 3,
            VerifyError::BadOpcode { .. } => 4,
            VerifyError::BadReg { .. } => 5,
            VerifyError::Reserved { .. } => 6,
            VerifyError::BadField { .. } => 7,
            VerifyError::BadVerdict { .. } => 8,
            VerifyError::BackwardJump { .. } => 9,
            VerifyError::JumpOutOfRange { .. } => 10,
            VerifyError::FallsOffEnd => 11,
            VerifyError::Unreachable { .. } => 12,
            VerifyError::UninitRead { .. } => 13,
        }
    }
}

/// 一个**已验证**的程序。只能经 [`verify`] / [`verify_into`] 得到。
#[derive(Clone, Copy)]
pub struct Program {
    insns: [Insn; MAX_INSNS],
    len: usize,
}

impl Program {
    /// 空壳（`len=0`，执行器对它返回 `PcOutOfRange`）：只给 [`verify_into`] 当输出缓冲用，
    /// 不是一个"可运行的程序"。内核不存它（内核存 `Option<Program>`，只放验证成功的值）。
    pub const fn blank() -> Program {
        Program { insns: [Insn::ZERO; MAX_INSNS], len: 0 }
    }
    /// 指令数。
    pub fn len(&self) -> usize {
        self.len
    }
    /// 是否为空（验证成功的程序恒非空）。
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// 指令切片。
    pub fn insns(&self) -> &[Insn] {
        self.insns.get(..self.len).unwrap_or(&[])
    }
}

/// 跳转目标 `pc + 1 + off`；为负 ⇒ `None`。执行器与验证器**共用**这一个公式。
pub(crate) fn target(pc: usize, off: i16) -> Option<usize> {
    let p = i64::try_from(pc).ok()?;
    let t = p.checked_add(1)?.checked_add(i64::from(off))?;
    usize::try_from(t).ok()
}

/// 验证并返回程序。
pub fn verify(bytes: &[u8]) -> Result<Program, VerifyError> {
    let mut p = Program::blank();
    verify_into(bytes, &mut p)?;
    Ok(p)
}

/// 验证并写入 `out`（避免在内核栈上多复制一份 1 KiB）。失败时 `out.len()==0`，调用方不得使用它。
pub fn verify_into(bytes: &[u8], out: &mut Program) -> Result<(), VerifyError> {
    out.len = 0;
    if bytes.is_empty() {
        return Err(VerifyError::Empty);
    }
    if bytes.len() % INSN_BYTES != 0 {
        return Err(VerifyError::Misaligned { len: bytes.len() });
    }
    let n = bytes.len() / INSN_BYTES;
    if n > MAX_INSNS {
        return Err(VerifyError::TooLong { insns: n });
    }
    // ---- 第一遍：逐条解码 + 单条形状检查
    let mut pc = 0usize;
    while pc < n {
        let lo = pc * INSN_BYTES;
        let raw: [u8; INSN_BYTES] = bytes
            .get(lo..lo + INSN_BYTES)
            .and_then(|s| s.try_into().ok())
            .ok_or(VerifyError::Misaligned { len: bytes.len() })?;
        let i = Insn::decode(raw);
        check_one(i, pc, n)?;
        match out.insns.get_mut(pc) {
            Some(slot) => *slot = i,
            None => return Err(VerifyError::TooLong { insns: n }),
        }
        pc += 1;
    }
    match out.insns.get(n - 1) {
        Some(last) if last.op == op::RET => {}
        _ => return Err(VerifyError::FallsOffEnd),
    }
    // ---- 第二遍：可达性 + 寄存器定义（前向数据流）。
    // 所有边都指向更大的 pc（第一遍已保证），所以按 pc 递增一遍扫完时，每条指令的全部前驱都已处理。
    let mut reach = [false; MAX_INSNS];
    let mut defs = [0u8; MAX_INSNS];
    if let Some(r) = reach.get_mut(0) {
        *r = true;
    }
    let mut pc = 0usize;
    while pc < n {
        let i = match out.insns.get(pc) {
            Some(i) => *i,
            None => return Err(VerifyError::FallsOffEnd),
        };
        if !reach.get(pc).copied().unwrap_or(false) {
            return Err(VerifyError::Unreachable { pc });
        }
        let d = defs.get(pc).copied().unwrap_or(0);
        let bit = reg_bit(i.a);
        if reads_reg(i.op) && d & bit == 0 {
            return Err(VerifyError::UninitRead { pc, reg: i.a });
        }
        let after = if writes_reg(i.op) { d | bit } else { d };
        if falls_through(i.op) {
            merge(&mut reach, &mut defs, pc + 1, after, n)?;
        }
        if is_jump(i.op) {
            let t = target(pc, i.off).ok_or(VerifyError::JumpOutOfRange { pc })?;
            merge(&mut reach, &mut defs, t, after, n)?;
        }
        pc += 1;
    }
    out.len = n;
    Ok(())
}

fn reg_bit(a: u8) -> u8 {
    if usize::from(a) < NREGS {
        1u8 << a
    } else {
        0
    }
}

/// 汇合：第一次到达直接取，之后取**交集**（must-defined）。取并集就是 merge_union 那颗变异。
fn merge(reach: &mut [bool; MAX_INSNS], defs: &mut [u8; MAX_INSNS], t: usize, d: u8, n: usize) -> Result<(), VerifyError> {
    if t >= n {
        // 第一遍已排除；留着是纵深防御，不是可达分支。
        return Err(VerifyError::FallsOffEnd);
    }
    match (reach.get_mut(t), defs.get_mut(t)) {
        (Some(r), Some(x)) => {
            if *r {
                *x &= d;
            } else {
                *r = true;
                *x = d;
            }
            Ok(())
        }
        _ => Err(VerifyError::FallsOffEnd),
    }
}

fn check_one(i: Insn, pc: usize, n: usize) -> Result<(), VerifyError> {
    let reg_ok = usize::from(i.a) < NREGS;
    match i.op {
        op::LDF => {
            if !reg_ok {
                return Err(VerifyError::BadReg { pc });
            }
            if i.off != 0 {
                return Err(VerifyError::Reserved { pc });
            }
            if i.imm >= field::COUNT {
                return Err(VerifyError::BadField { pc });
            }
            Ok(())
        }
        op::LDI | op::AND => {
            if !reg_ok {
                return Err(VerifyError::BadReg { pc });
            }
            if i.off != 0 {
                return Err(VerifyError::Reserved { pc });
            }
            Ok(())
        }
        op::JEQ | op::JNE | op::JLT | op::JGT => {
            if !reg_ok {
                return Err(VerifyError::BadReg { pc });
            }
            jump_ok(pc, i.off, n)
        }
        op::JA => {
            if i.a != 0 || i.imm != 0 {
                return Err(VerifyError::Reserved { pc });
            }
            jump_ok(pc, i.off, n)
        }
        op::RET => {
            if i.a != 0 || i.off != 0 {
                return Err(VerifyError::Reserved { pc });
            }
            if i.imm != V_DROP && i.imm != V_ACCEPT {
                return Err(VerifyError::BadVerdict { pc });
            }
            Ok(())
        }
        _ => Err(VerifyError::BadOpcode { pc }),
    }
}

fn jump_ok(pc: usize, off: i16, n: usize) -> Result<(), VerifyError> {
    if off < 0 {
        return Err(VerifyError::BackwardJump { pc });
    }
    match target(pc, off) {
        // 纵深防御：不只看 off 的符号，也直接要求"目标严格在后"。
        // 这样 `target()` 公式哪天被改错（变异 exec_target_off_by_one），环也进不来。
        Some(t) if t <= pc => Err(VerifyError::BackwardJump { pc }),
        Some(t) if t < n => Ok(()),
        _ => Err(VerifyError::JumpOutOfRange { pc }),
    }
}
