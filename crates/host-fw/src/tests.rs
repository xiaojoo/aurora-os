//! 宿主机测试（`cargo test -p host-fw`）。**未在本沙箱运行**（无 Rust 工具链）；
//! 每一格都在 Python 等价移植里有同形检验且基线/变异数字见 README。
//!
//! 不用 proptest：自带 xorshift64*，种子固定，失败可复现；零外部依赖。

use crate::exec::{run, run_raw, ExecFault, MAX_STEPS};
use crate::insn::{op, Insn, INSN_BYTES, MAX_INSNS, MAX_PROG_BYTES, V_ACCEPT, V_DROP};
use crate::packet::{field, Dir, Packet};
use crate::parse::{parse_eth, Parsed};
use crate::rules::{compile, eval_rules, Action, PortRange, Prefix, Rule};
use crate::verify::{verify, VerifyError};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn asm(v: &[Insn]) -> std::vec::Vec<u8> {
    v.iter().flat_map(|i| i.encode()).collect()
}

fn reject(v: &[Insn]) -> VerifyError {
    match verify(&asm(v)) {
        Err(e) => e,
        Ok(_) => VerifyError::Empty, // 让调用方的 assert_eq 失败：坏程序居然被接受
    }
}

fn accepts(v: &[Insn]) -> bool {
    verify(&asm(v)).is_ok()
}

// ---------------------------------------------------------------- T1：最小对（每个坏程序都有一个只差一处、必须被接受的兄弟）
#[test]
fn verifier_minimal_pairs() {
    let r = Insn::ret(V_ACCEPT);
    assert_eq!(verify(&[]).err(), Some(VerifyError::Empty));
    let good = asm(&[Insn::ldf(0, field::DPORT), Insn::jne(0, 53, 1), Insn::ret(V_DROP), r]);
    let mut odd = good.clone();
    odd.push(0);
    assert!(matches!(verify(&odd), Err(VerifyError::Misaligned { .. })));
    assert!(verify(&good).is_ok());

    let mut long = std::vec![Insn::ldi(0, 0); MAX_INSNS];
    long.push(r);
    assert!(matches!(verify(&asm(&long)), Err(VerifyError::TooLong { .. })));
    long.truncate(MAX_INSNS - 1);
    long.push(r);
    assert!(accepts(&long));

    let cases: &[(&[Insn], VerifyError, &[Insn])] = &[
        (&[Insn { op: 0x7F, a: 0, off: 0, imm: 0 }, r], VerifyError::BadOpcode { pc: 0 }, &[Insn::ldi(0, 0), r]),
        (&[Insn::ldi(4, 0), r], VerifyError::BadReg { pc: 0 }, &[Insn::ldi(3, 0), r]),
        (&[Insn::ldf(0, 14), r], VerifyError::BadField { pc: 0 }, &[Insn::ldf(0, 13), r]),
        (&[Insn { op: op::LDF, a: 0, off: 1, imm: field::DPORT }, r], VerifyError::Reserved { pc: 0 }, &[Insn::ldf(0, field::DPORT), r]),
        (&[Insn { op: op::JA, a: 1, off: 0, imm: 0 }, r], VerifyError::Reserved { pc: 0 }, &[Insn::ja(0), r]),
        (&[Insn { op: op::RET, a: 1, off: 0, imm: 1 }], VerifyError::Reserved { pc: 0 }, &[r]),
        (&[Insn::ret(2)], VerifyError::BadVerdict { pc: 0 }, &[r]),
        (&[Insn::ldi(0, 0), Insn::jeq(0, 0, -2), r], VerifyError::BackwardJump { pc: 1 }, &[Insn::ldi(0, 0), Insn::jeq(0, 0, 0), r]),
        (&[Insn::ldi(0, 0), Insn::ja(-1), r], VerifyError::BackwardJump { pc: 1 }, &[Insn::ldi(0, 0), Insn::ja(0), r]),
        (&[Insn::ldi(0, 0), Insn::jeq(0, 0, 1), r], VerifyError::JumpOutOfRange { pc: 1 }, &[Insn::ldi(0, 0), Insn::jeq(0, 0, 0), r]),
        (&[Insn::ja(1), r], VerifyError::JumpOutOfRange { pc: 0 }, &[Insn::ja(0), r]),
        (&[Insn::ldi(0, 0)], VerifyError::FallsOffEnd, &[Insn::ldi(0, 0), r]),
        (&[Insn::ldi(0, 0), Insn::jeq(0, 0, 0)], VerifyError::JumpOutOfRange { pc: 1 }, &[Insn::ldi(0, 0), Insn::jeq(0, 0, 0), Insn::ret(0)]),
        (&[r, Insn::ret(0)], VerifyError::Unreachable { pc: 1 }, &[Insn::ldi(0, 0), Insn::jeq(0, 1, 1), r, Insn::ret(0)]),
        (&[Insn::ja(1), Insn::ldi(0, 0), r], VerifyError::Unreachable { pc: 1 }, &[Insn::ja(0), Insn::ldi(0, 0), r]),
        (&[Insn::jeq(0, 0, 0), r], VerifyError::UninitRead { pc: 0, reg: 0 }, &[Insn::ldi(0, 0), Insn::jeq(0, 0, 0), r]),
        (&[Insn::and(1, 1), r], VerifyError::UninitRead { pc: 0, reg: 1 }, &[Insn::ldi(1, 0), Insn::and(1, 1), r]),
        (
            &[Insn::ldf(0, field::DPORT), Insn::jeq(0, 53, 1), Insn::ldi(1, 7), Insn::jeq(1, 7, 0), r],
            VerifyError::UninitRead { pc: 3, reg: 1 },
            &[Insn::ldi(1, 0), Insn::ldf(0, field::DPORT), Insn::jeq(0, 53, 1), Insn::ldi(1, 7), Insn::jeq(1, 7, 0), r],
        ),
    ];
    for (bad, want, good) in cases {
        assert_eq!(reject(bad), *want, "坏程序 {:?}", bad);
        assert!(accepts(good), "最小对的好程序被拒 {:?}", good);
    }
}

// ---------------------------------------------------------------- T5：步数上界的两条边
#[test]
fn step_bound_edges() {
    let p = Packet::udp4([10, 0, 2, 15], [10, 0, 2, 2], 1, 2, Dir::In);
    let mut longest = std::vec![Insn::ldi(0, 0); MAX_INSNS - 1];
    longest.push(Insn::ret(V_ACCEPT));
    let prog = match verify(&asm(&longest)) {
        Ok(p) => p,
        Err(e) => panic!("最长合法程序被拒 {e:?}"),
    };
    assert_eq!(run(&prog, &p).map(|o| o.steps), Ok(MAX_STEPS));
    let mut over = std::vec![Insn::ldi(0, 0); MAX_INSNS];
    over.push(Insn::ret(V_ACCEPT));
    assert_eq!(run_raw(&over, &p).err(), Some(ExecFault::StepBudget));
    assert_eq!(run_raw(&[Insn::ja(-1)], &p).err(), Some(ExecFault::StepBudget));
    assert_eq!(run_raw(&[], &p).err(), Some(ExecFault::PcOutOfRange));
}

// ---------------------------------------------------------------- T2（缩小版）：已验证 ⇒ 不出错、步数 ≤ len
#[test]
fn verified_programs_never_fault() {
    let mut rng = Rng(0x2671);
    let pkts = [
        Packet::udp4([10, 0, 2, 15], [10, 0, 2, 2], 53, 53, Dir::In),
        Packet::icmp6([0xfe; 16], [0x80; 16], 135, Dir::In),
        Packet::udp6([1; 16], [2; 16], 0, 65535, Dir::Out),
    ];
    let mut accepted = 0u32;
    for _ in 0..20_000 {
        let n = 1 + rng.below(40) as usize;
        let mut v = std::vec::Vec::new();
        for k in 0..4u8 {
            v.push(Insn::ldi(k, 0));
        }
        for pc in 0..n {
            let room = (n - pc).saturating_sub(1) as u64;
            let reg = rng.below(4) as u8;
            let i = match rng.below(6) {
                0 => Insn::ldf(reg, rng.below(14) as u32),
                1 => Insn::ldi(reg, rng.next() as u32),
                2 => Insn::and(reg, rng.next() as u32),
                3 | 4 => Insn { op: op::JEQ + rng.below(4) as u8, a: reg, off: rng.below(room + 1) as i16, imm: rng.below(70) as u32 },
                _ => Insn::ja(rng.below(room.min(2) + 1) as i16),
            };
            v.push(i);
        }
        v.push(Insn::ret(rng.below(2) as u32));
        if rng.below(3) == 0 {
            let k = rng.below(v.len() as u64) as usize;
            v[k] = Insn::decode((rng.next()).to_le_bytes());
        }
        let Ok(prog) = verify(&asm(&v)) else { continue };
        accepted += 1;
        for p in &pkts {
            match run(&prog, p) {
                Ok(o) => assert!(o.steps as usize <= prog.len()),
                Err(e) => panic!("已验证程序执行出错 {e:?}: {v:?}"),
            }
        }
    }
    assert!(accepted > 1000, "接受数 {accepted} 太少 ⇒ 这格没有检验功率");
}

// ---------------------------------------------------------------- T4（缩小版）：编译 ≡ 参考语义
#[test]
fn compile_matches_reference() {
    let mut rng = Rng(0x2672);
    let mut evals = 0u32;
    for _ in 0..1500 {
        let nr = rng.below(8) as usize;
        let mut rules = std::vec::Vec::new();
        for _ in 0..nr {
            let fam = match rng.below(3) { 0 => None, 1 => Some(4u8), _ => Some(6u8) };
            let mut a = [0u8; 16];
            for b in a.iter_mut().take(if fam == Some(4) { 4 } else { 16 }) {
                *b = rng.below(256) as u8;
            }
            let px = match fam {
                Some(4) if rng.below(2) == 0 => Some(Prefix { addr: a, len: rng.below(33) as u8 }),
                Some(6) if rng.below(2) == 0 => Some(Prefix { addr: a, len: rng.below(129) as u8 }),
                _ => None,
            };
            let lo = rng.below(65536) as u16;
            let hi = lo.saturating_add(rng.below(3000) as u16);
            rules.push(Rule {
                dir: if rng.below(8) == 0 { Dir::Out } else { Dir::In },
                family: fam,
                proto: [None, Some(17u8), Some(58u8)][rng.below(3) as usize],
                src: px,
                dst: None,
                sport: None,
                dport: if rng.below(2) == 0 { Some(PortRange { lo, hi }) } else { None },
                action: if rng.below(2) == 0 { Action::Drop } else { Action::Accept },
            });
        }
        let default = if rng.below(2) == 0 { Action::Drop } else { Action::Accept };
        let mut buf = [0u8; MAX_PROG_BYTES];
        let Ok(n) = compile(&rules, default, &mut buf) else { continue };
        assert_eq!(n % INSN_BYTES, 0);
        let prog = match verify(&buf[..n]) {
            Ok(p) => p,
            Err(e) => panic!("编译产物未过验证 {e:?}"),
        };
        for _ in 0..30 {
            let r0 = rules.first().copied();
            let mut src = [0u8; 16];
            let fam = if rng.below(2) == 0 { 4 } else { 6 };
            if let Some(Rule { src: Some(px), .. }) = r0 {
                src = px.addr;
                let k = rng.below(129) as usize;
                if k < 128 && rng.below(2) == 0 {
                    src[k / 8] ^= 0x80 >> (k % 8);
                }
            }
            if fam == 4 {
                for b in src.iter_mut().skip(4) {
                    *b = 0;
                }
            }
            let dport = match r0 {
                Some(Rule { dport: Some(pr), .. }) => [pr.lo.wrapping_sub(1), pr.lo, pr.hi, pr.hi.wrapping_add(1)][rng.below(4) as usize],
                _ => rng.below(65536) as u16,
            };
            let p = Packet {
                family: fam,
                proto: [17u8, 58, 6][rng.below(3) as usize],
                dir: if rng.below(8) == 0 { Dir::Out } else { Dir::In },
                src,
                dst: [0; 16],
                sport: 0,
                dport,
                icmp_type: 0,
            };
            assert_eq!(run(&prog, &p).map(|o| o.verdict), Ok(eval_rules(&rules, default, &p)), "rules={rules:?} p={p:?}");
            evals += 1;
        }
    }
    assert!(evals > 10_000, "差分次数 {evals} 太少");
}

// ---------------------------------------------------------------- T6（缩小版）：解析器对任意字节不 panic；已知帧取值正确
fn udp4_frame(dport: u16, ihl: u8) -> std::vec::Vec<u8> {
    let opts = usize::from(ihl - 5) * 4;
    let tot = (usize::from(ihl) * 4 + 8 + 3) as u16;
    let mut f = std::vec![2u8; 6];
    f.extend_from_slice(&[4; 6]);
    f.extend_from_slice(&[0x08, 0x00, 0x40 | ihl, 0]);
    f.extend_from_slice(&tot.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 2, 2, 10, 0, 2, 15]);
    f.extend(std::iter::repeat(0).take(opts));
    f.extend_from_slice(&1234u16.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&11u16.to_be_bytes());
    f.extend_from_slice(&[0, 0, b'a', b'b', b'c']);
    f
}

#[test]
fn parse_known_and_fuzz() {
    for ihl in [5u8, 6, 15] {
        let f = udp4_frame(5353, ihl);
        assert_eq!(
            parse_eth(&f, Dir::In),
            Parsed::Packet(Packet::udp4([10, 0, 2, 2], [10, 0, 2, 15], 1234, 5353, Dir::In)),
            "ihl={ihl}"
        );
        for k in 0..f.len() {
            assert!(!matches!(parse_eth(&f[..k], Dir::In), Parsed::Packet(_)), "截断到 {k} 仍被接受");
        }
    }
    let mut rng = Rng(0x2673);
    let mut buf = [0u8; 128];
    for _ in 0..50_000 {
        let n = rng.below(128) as usize;
        for b in buf.iter_mut().take(n) {
            *b = rng.below(256) as u8;
        }
        if n > 14 && rng.below(2) == 0 {
            buf[12] = if rng.below(2) == 0 { 0x08 } else { 0x86 };
            buf[13] = if buf[12] == 0x08 { 0x00 } else { 0xDD };
        }
        let _ = parse_eth(&buf[..n], Dir::In); // 判据：不 panic（cargo test 下 panic = 失败）
    }
}

#[test]
fn reject_codes_are_distinct() {
    let all = [
        VerifyError::Empty,
        VerifyError::Misaligned { len: 0 },
        VerifyError::TooLong { insns: 0 },
        VerifyError::BadOpcode { pc: 0 },
        VerifyError::BadReg { pc: 0 },
        VerifyError::Reserved { pc: 0 },
        VerifyError::BadField { pc: 0 },
        VerifyError::BadVerdict { pc: 0 },
        VerifyError::BackwardJump { pc: 0 },
        VerifyError::JumpOutOfRange { pc: 0 },
        VerifyError::FallsOffEnd,
        VerifyError::Unreachable { pc: 0 },
        VerifyError::UninitRead { pc: 0, reg: 0 },
    ];
    for (k, a) in all.iter().enumerate() {
        assert_eq!(a.code() as usize, k + 1);
    }
}
