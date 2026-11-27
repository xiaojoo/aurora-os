//! 指令集：4 个 32 位寄存器、9 条指令、定长 8 字节编码。
//!
//! ```text
//!  字节  0     1     2..4          4..8
//!       op    a     off(i16 LE)   imm(u32 LE)
//! ```
//!
//! | op | 助记 | 语义 | 合法形状（其余字段必须为 0） |
//! |---|---|---|---|
//! | 0x01 | `LDF a, imm` | `r[a] = packet.field(imm)` | `a<4`、`off=0`、`imm<14` |
//! | 0x02 | `LDI a, imm` | `r[a] = imm` | `a<4`、`off=0` |
//! | 0x03 | `AND a, imm` | `r[a] &= imm`（读 `r[a]`） | `a<4`、`off=0` |
//! | 0x10..0x13 | `JEQ/JNE/JLT/JGT a, imm, off` | 条件成立 ⇒ `pc = pc+1+off`，否则 `pc+1`（无符号比较） | `a<4`、`0 ≤ off`、目标 `< len` |
//! | 0x14 | `JA off` | `pc = pc+1+off` | `a=0`、`imm=0`、`0 ≤ off`、目标 `< len` |
//! | 0x20 | `RET imm` | 结束：0=Drop、1=Accept | `a=0`、`off=0`、`imm∈{0,1}` |
//!
//! **没有**：内存读写、栈、调用、后向跳转、间接跳转、算术溢出语义、可变长编码。
//! 这些都是 eBPF 验证器历史上出逃逸漏洞的地方（指针算术、边界跟踪、环检测），第一期一律不给。

/// 每条指令的字节数。
pub const INSN_BYTES: usize = 8;
/// 单个程序的指令数上限（也是执行步数上界）。登记在 capacity-baseline（`MAX_FW_INSNS`）。
pub const MAX_INSNS: usize = 128;
/// 单个程序的字节数上限（= 81 号 syscall 的单次拷贝上限）。
pub const MAX_PROG_BYTES: usize = MAX_INSNS * INSN_BYTES;
/// 寄存器个数。
pub const NREGS: usize = 4;

/// 操作码。
pub mod op {
    /// 读包字段。
    pub const LDF: u8 = 0x01;
    /// 读立即数。
    pub const LDI: u8 = 0x02;
    /// 按位与立即数。
    pub const AND: u8 = 0x03;
    /// 相等则跳。
    pub const JEQ: u8 = 0x10;
    /// 不等则跳。
    pub const JNE: u8 = 0x11;
    /// 小于（无符号）则跳。
    pub const JLT: u8 = 0x12;
    /// 大于（无符号）则跳。
    pub const JGT: u8 = 0x13;
    /// 无条件前跳。
    pub const JA: u8 = 0x14;
    /// 返回判决。
    pub const RET: u8 = 0x20;
}

/// `RET` 的判决码：丢弃。
pub const V_DROP: u32 = 0;
/// `RET` 的判决码：放行。
pub const V_ACCEPT: u32 = 1;

/// 一条已解码的指令。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    /// 操作码。
    pub op: u8,
    /// 寄存器号（JA/RET 必须为 0）。
    pub a: u8,
    /// 跳转偏移（目标 = pc+1+off）；非跳转指令必须为 0。
    pub off: i16,
    /// 立即数 / 字段号 / 判决码。
    pub imm: u32,
}

impl Insn {
    /// 全零（`op=0` 是非法操作码）：仅作数组初值。
    pub const ZERO: Insn = Insn { op: 0, a: 0, off: 0, imm: 0 };

    /// 从 8 字节解码（任何字节组合都能解码；合法性由验证器判）。
    pub fn decode(b: [u8; INSN_BYTES]) -> Insn {
        Insn {
            op: b[0],
            a: b[1],
            off: i16::from_le_bytes([b[2], b[3]]),
            imm: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    /// 编码成 8 字节。
    pub fn encode(self) -> [u8; INSN_BYTES] {
        let o = self.off.to_le_bytes();
        let i = self.imm.to_le_bytes();
        [self.op, self.a, o[0], o[1], i[0], i[1], i[2], i[3]]
    }

    /// `LDF r, field`。
    pub const fn ldf(r: u8, f: u32) -> Insn {
        Insn { op: op::LDF, a: r, off: 0, imm: f }
    }
    /// `LDI r, imm`。
    pub const fn ldi(r: u8, v: u32) -> Insn {
        Insn { op: op::LDI, a: r, off: 0, imm: v }
    }
    /// `AND r, mask`。
    pub const fn and(r: u8, m: u32) -> Insn {
        Insn { op: op::AND, a: r, off: 0, imm: m }
    }
    /// `JEQ r, imm, off`。
    pub const fn jeq(r: u8, v: u32, off: i16) -> Insn {
        Insn { op: op::JEQ, a: r, off, imm: v }
    }
    /// `JNE r, imm, off`。
    pub const fn jne(r: u8, v: u32, off: i16) -> Insn {
        Insn { op: op::JNE, a: r, off, imm: v }
    }
    /// `JLT r, imm, off`。
    pub const fn jlt(r: u8, v: u32, off: i16) -> Insn {
        Insn { op: op::JLT, a: r, off, imm: v }
    }
    /// `JGT r, imm, off`。
    pub const fn jgt(r: u8, v: u32, off: i16) -> Insn {
        Insn { op: op::JGT, a: r, off, imm: v }
    }
    /// `JA off`。
    pub const fn ja(off: i16) -> Insn {
        Insn { op: op::JA, a: 0, off, imm: 0 }
    }
    /// `RET v`。
    pub const fn ret(v: u32) -> Insn {
        Insn { op: op::RET, a: 0, off: 0, imm: v }
    }
}

/// 读寄存器 `a` 的指令（AND 与四条条件跳转）。
pub(crate) const fn reads_reg(o: u8) -> bool {
    matches!(o, op::AND | op::JEQ | op::JNE | op::JLT | op::JGT)
}
/// 写寄存器 `a` 的指令（LDF/LDI；AND 读改写，定义状态不变）。
pub(crate) const fn writes_reg(o: u8) -> bool {
    matches!(o, op::LDF | op::LDI)
}
/// 会顺序落到 `pc+1` 的指令（除 JA/RET）。
pub(crate) const fn falls_through(o: u8) -> bool {
    !matches!(o, op::JA | op::RET)
}
/// 有跳转边的指令。
pub(crate) const fn is_jump(o: u8) -> bool {
    matches!(o, op::JEQ | op::JNE | op::JLT | op::JGT | op::JA)
}
