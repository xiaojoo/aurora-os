//! 有界执行器。
//!
//! **最坏步数上界**：已验证程序 ⇒ 每步 `pc` 严格递增、且最后一条是 `RET` ⇒ 步数 ≤ `len` ≤ 128。
//! 执行器另带独立预算 [`MAX_STEPS`]：对**未验证**的指令序列（[`run_raw`]）也保证 ≤128 步后返回
//! `Err(StepBudget)`。两道界互相独立：验证器错了，预算兜底；预算错了，验证器保证不会触到它。
//!
//! 执行器不 panic：取指、读写寄存器、读字段全部经 `get()`，任何异常形状都变成 [`ExecFault`]。

use crate::insn::{op, Insn, MAX_INSNS, NREGS, V_ACCEPT, V_DROP};
use crate::packet::Packet;
use crate::verify::{target, Program};

/// 步数预算（= 指令数上限）。
pub const MAX_STEPS: u32 = MAX_INSNS as u32;

/// 判决。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// 丢弃。
    Drop,
    /// 放行。
    Accept,
}

/// 一次成功执行的结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecOutcome {
    /// 判决。
    pub verdict: Verdict,
    /// 实际执行步数（含最后的 `RET`）。
    pub steps: u32,
}

/// 执行异常。**已验证程序不会产生**（宿主机证据见 README）；内核遇到它按 ADR-267 §2 D9（R21 待裁决）放行并计数。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecFault {
    /// 步数预算用尽（环）。
    StepBudget,
    /// `pc` 越界（跑出末尾或负目标）。
    PcOutOfRange,
    /// 非法操作码。
    BadOpcode,
    /// 寄存器号越界。
    BadReg,
    /// 字段号越界。
    BadField,
    /// 判决码非法。
    BadVerdict,
}

/// 执行一个已验证程序。
pub fn run(p: &Program, pkt: &Packet) -> Result<ExecOutcome, ExecFault> {
    run_raw(p.insns(), pkt)
}

/// 执行任意指令序列（未验证也安全：有界、不 panic）。
pub fn run_raw(insns: &[Insn], pkt: &Packet) -> Result<ExecOutcome, ExecFault> {
    let mut r = [0u32; NREGS];
    let mut pc = 0usize;
    let mut steps = 0u32;
    loop {
        if steps >= MAX_STEPS {
            return Err(ExecFault::StepBudget);
        }
        let i = *insns.get(pc).ok_or(ExecFault::PcOutOfRange)?;
        steps += 1;
        let ra = usize::from(i.a);
        match i.op {
            op::LDF => {
                let v = pkt.field(i.imm).ok_or(ExecFault::BadField)?;
                *r.get_mut(ra).ok_or(ExecFault::BadReg)? = v;
                pc += 1;
            }
            op::LDI => {
                *r.get_mut(ra).ok_or(ExecFault::BadReg)? = i.imm;
                pc += 1;
            }
            op::AND => {
                let x = r.get_mut(ra).ok_or(ExecFault::BadReg)?;
                *x &= i.imm;
                pc += 1;
            }
            op::JEQ | op::JNE | op::JLT | op::JGT => {
                let x = *r.get(ra).ok_or(ExecFault::BadReg)?;
                let take = match i.op {
                    op::JEQ => x == i.imm,
                    op::JNE => x != i.imm,
                    op::JLT => x < i.imm,
                    _ => x > i.imm,
                };
                pc = if take { target(pc, i.off).ok_or(ExecFault::PcOutOfRange)? } else { pc + 1 };
            }
            op::JA => {
                pc = target(pc, i.off).ok_or(ExecFault::PcOutOfRange)?;
            }
            op::RET => {
                let verdict = match i.imm {
                    V_DROP => Verdict::Drop,
                    V_ACCEPT => Verdict::Accept,
                    _ => return Err(ExecFault::BadVerdict),
                };
                return Ok(ExecOutcome { verdict, steps });
            }
            _ => return Err(ExecFault::BadOpcode),
        }
    }
}
