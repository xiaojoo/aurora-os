//! ADR-267：最小防火墙的 ktest（`fw` 特性）。**未编译、未在 QEMU 运行。**
//!
//! 形状对齐 `ktests/syscall/user.rs` 的 `t_ndp_cache`：不靠网卡，手工造帧直接喂 `socket::deliver_frame`，
//! 再用 `socket::dequeue` / `ndp::nd_lookup` 看帧到底有没有被消费。
//!
//! **每格都带"防空转证人"**——没有它，挂载点根本没被走到时这些格子也会全绿：
//! * "被丢"的格子同时要求 `evaluated`/`dropped` 计数**精确**增长，并且**同一帧**在停用/清空后能被投递
//!   （证明夹具本身是活的、丢弃确实来自过滤器）；
//! * "放行"的格子要求 `evaluated`/`accepted` 增长（区分"判过放行"与"压根没判"）；
//! * 畸形帧格要求 `malformed_dropped` 增量等于**事先算好的**帧数；
//! * 验证器格要求最小对里的好程序被接受、世代号恰好前进好程序的个数。
//!
//! 每个用例开头与结尾都 `fw::clear()`：别的用例（`t_ndp_cache` 等）也喂 deliver_frame，不能被本组的规则影响。
//! 端口 47001–47009 是本组独占（全仓 ripgrep `4700[0-9]` 零命中）。

use crate::ktest;
use crate::ktests::common::{frame0, get_user, put_user};
use crate::network::{fw, ndp, socket, udp};
use crate::{mm, user};
use host_fw::insn::{Insn, V_ACCEPT, V_DROP};
use host_fw::packet::field;
use host_fw::rules::{compile, Action, CompileError, PortRange, Rule};
use host_fw::{Dir, VerifyError};

const OUR_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
const OUR_V4: [u8; 4] = [10, 0, 2, 15];
const PEER_V4: [u8; 4] = [10, 0, 2, 2];
const PAY: &[u8] = b"fw-267";

fn v4_frame(buf: &mut [u8], dport: u16) -> usize {
    udp::build_frame(buf, &OUR_MAC, &PEER_MAC, udp::UdpEndpoint::new(PEER_V4, 40000), udp::UdpEndpoint::new(OUR_V4, dport), PAY)
        .unwrap_or(0)
}

fn v6_frame(buf: &mut [u8], dport: u16) -> usize {
    let ours = crate::network::ipv6::link_local_from_mac(&OUR_MAC);
    let mut peer = crate::network::ipv6::link_local_from_mac(&PEER_MAC);
    peer[15] = 0x99;
    crate::network::ipv6::build_udp6_frame(buf, &OUR_MAC, &PEER_MAC, &peer, &ours, 40000, dport, PAY).unwrap_or(0)
}

/// 绑在 `port` 的 IPv4 dgram socket（通配地址 ⇒ 不依赖地址表）。
fn bound(port: u16) -> Option<(u16, u32)> {
    let (s, g) = socket::create(socket::AF_INET, socket::SOCK_DGRAM).ok()?;
    if socket::bind(s, g, socket::SockAddr::V4 { ip: [0; 4], port }).is_err() {
        let _ = socket::destroy(s, g);
        return None;
    }
    Some((s, g))
}

fn got_payload(s: u16, g: u32) -> bool {
    let mut b = [0u8; 64];
    matches!(socket::dequeue(s, g, &mut b), Ok((_, n)) if n == PAY.len() && b.get(..n) == Some(PAY))
}

fn queue_empty(s: u16, g: u32) -> bool {
    let mut b = [0u8; 64];
    matches!(socket::dequeue(s, g, &mut b), Err(e) if e == socket::E_AGAIN)
}

fn drop_udp4_dport(p: u16) -> Rule {
    Rule {
        dir: Dir::In,
        family: Some(4),
        proto: Some(17),
        src: None,
        dst: None,
        sport: None,
        dport: Some(PortRange { lo: p, hi: p }),
        action: Action::Drop,
    }
}

fn load_rules(rules: &[Rule], default: Action, enable: bool) -> bool {
    let mut b = [0u8; fw::FW_PROG_BYTES_MAX];
    match compile(rules, default, &mut b) {
        Ok(n) => b.get(..n).map(|p| fw::load(p, enable).is_ok()).unwrap_or(false),
        Err(_) => false,
    }
}

fn asm(v: &[Insn], out: &mut [u8]) -> usize {
    let mut n = 0usize;
    for i in v {
        if let Some(d) = out.get_mut(n..n + 8) {
            d.copy_from_slice(&i.encode());
            n += 8;
        }
    }
    n
}

// ---------------------------------------------------------------- ① 规则命中丢弃 / 放行 / 族区分
fn t_fw_rules() -> bool {
    fw::clear();
    let (sa, ga, sb, gb) = match (bound(47001), bound(47002)) {
        (Some((sa, ga)), Some((sb, gb))) => (sa, ga, sb, gb),
        (a, b) => {
            // 只建成一个也要还掉，不留给后面的用例
            for (s, g) in [a, b].into_iter().flatten() {
                let _ = socket::destroy(s, g);
            }
            crate::log_fatal!("fw-rules: 建 socket 失败（端口被占？）");
            fw::clear();
            return false;
        }
    };
    let mut f = [0u8; 256];
    let loaded = load_rules(&[drop_udp4_dport(47001)], Action::Accept, true);

    // 1 命中 ⇒ 丢：返回 0、队列空、evaluated 与 dropped 各 +1
    let s0 = fw::stats();
    let n = v4_frame(&mut f, 47001);
    let fam1 = socket::deliver_frame(&f[..n]);
    let s1 = fw::stats();
    let hit_dropped = loaded && n > 0 && fam1 == 0 && queue_empty(sa, ga)
        && s1.evaluated == s0.evaluated + 1 && s1.dropped == s0.dropped + 1;

    // 2 不命中 ⇒ 放：投递到 47002，accepted +1
    let n = v4_frame(&mut f, 47002);
    let fam2 = socket::deliver_frame(&f[..n]);
    let s2 = fw::stats();
    let miss_accepted = fam2 == 4 && got_payload(sb, gb) && s2.accepted == s1.accepted + 1 && s2.evaluated == s1.evaluated + 1;

    // 3 族区分：同端口的 IPv6 帧不命中 family=4 的规则 ⇒ 放（enqueue 按端口找槽，所以进 sa）
    let n6 = v6_frame(&mut f, 47001);
    let fam3 = socket::deliver_frame(&f[..n6]);
    let s3 = fw::stats();
    let v6_not_matched = n6 > 0 && fam3 == 6 && got_payload(sa, ga) && s3.accepted == s2.accepted + 1;

    // 防空转证人：停用后**同一帧**必须投递成功、且 evaluated 不再增长
    fw::disable();
    let n = v4_frame(&mut f, 47001);
    let fam4 = socket::deliver_frame(&f[..n]);
    let s4 = fw::stats();
    let witness = fam4 == 4 && got_payload(sa, ga) && s4.evaluated == s3.evaluated;

    let _ = socket::destroy(sa, ga);
    let _ = socket::destroy(sb, gb);
    fw::clear();
    let ok = hit_dropped && miss_accepted && v6_not_matched && witness;
    crate::log_info!(
        "fw-rules: 装载={} 命中丢={} 未命中放={} 族区分={} 证人(停用后同帧投递)={} ⇒ {}",
        loaded, hit_dropped, miss_accepted, v6_not_matched, witness, ok
    );
    if !ok {
        crate::log_fatal!("fw-rules: 判据不成立（见上一行每一格）");
    }
    ok
}
ktest!(KT_FW_RULES, t_fw_rules);

// ---------------------------------------------------------------- ② 默认策略：无程序/装了未启用 ⇒ 放行且不判；启用 ⇒ 程序的默认生效
fn t_fw_default_policy() -> bool {
    fw::clear();
    let Some((s, g)) = bound(47003) else {
        crate::log_fatal!("fw-default: 建 socket 失败");
        return false;
    };
    let mut f = [0u8; 256];
    let n = v4_frame(&mut f, 47003);

    let e0 = fw::stats().evaluated;
    let a_none = socket::deliver_frame(&f[..n]) == 4 && got_payload(s, g) && fw::stats().evaluated == e0;

    let loaded = load_rules(&[], Action::Drop, false); // 空规则表 + 默认 Drop，但不启用
    let b_disabled = loaded && socket::deliver_frame(&f[..n]) == 4 && got_payload(s, g) && fw::stats().evaluated == e0;

    let en = fw::enable();
    let d0 = fw::stats().dropped;
    let c_enabled = en && socket::deliver_frame(&f[..n]) == 0 && queue_empty(s, g)
        && fw::stats().evaluated == e0 + 1 && fw::stats().dropped == d0 + 1;

    fw::clear();
    let d_cleared = socket::deliver_frame(&f[..n]) == 4 && got_payload(s, g) && !fw::enable() && !fw::stats().enabled;

    let _ = socket::destroy(s, g);
    fw::clear();
    // 证人：A/B/D 与 C 是**同一帧**，只有 C 被丢、只有 C 让 evaluated 前进。
    let ok = a_none && b_disabled && c_enabled && d_cleared;
    crate::log_info!("fw-default: 无程序放={} 未启用放={} 启用后默认丢={} 清空后放且不可再启用={} ⇒ {}", a_none, b_disabled, c_enabled, d_cleared, ok);
    if !ok {
        crate::log_fatal!("fw-default: 判据不成立");
    }
    ok
}
ktest!(KT_FW_DEFAULT_POLICY, t_fw_default_policy);

// ---------------------------------------------------------------- ③ 畸形帧不崩 + NDP 分支取不出头即丢（计数精确）
fn t_fw_malformed() -> bool {
    fw::clear();
    ndp::nd_clear();
    let mut acc = [0u8; 8];
    let n_acc = asm(&[Insn::ret(V_ACCEPT)], &mut acc);
    let loaded = fw::load(&acc[..n_acc], true).is_ok();

    // (a) 有效 IPv4 UDP 帧的每一个截断：内核解析器全拒 ⇒ 挂载点不被走到 ⇒ evaluated 只为完整帧 +1
    let Some((s, g)) = bound(47004) else {
        fw::clear();
        return false;
    };
    let mut f = [0u8; 256];
    let n = v4_frame(&mut f, 47004);
    let e0 = fw::stats().evaluated;
    let mut trunc_zero = true;
    for k in 0..n {
        trunc_zero &= socket::deliver_frame(&f[..k]) == 0;
    }
    let e1 = fw::stats().evaluated;
    let full_ok = socket::deliver_frame(&f[..n]) == 4 && got_payload(s, g) && fw::stats().evaluated == e1 + 1;
    let trunc_ok = trunc_zero && e1 == e0;

    // (b) NA 帧（86 字节）截断到 21..86：都满足 `len>20 && f[20]==58` ⇒ 进 NDP 分支；
    //     plen=32 ⇒ 需要 86 字节才取得出头 ⇒ 65 帧全部"取不出头即丢"，malformed_dropped 精确 +65。
    let ours = crate::network::ipv6::link_local_from_mac(&OUR_MAC);
    let mut peer = crate::network::ipv6::link_local_from_mac(&PEER_MAC);
    peer[15] = 0x99;
    let mut na = [0u8; 256];
    let nn = ndp::build_na(&mut na, &PEER_MAC, &peer, &ours, &OUR_MAC, &peer, false).unwrap_or(0);
    let m0 = fw::stats().malformed_dropped;
    let mut nd_zero = true;
    let mut fed = 0u64;
    for k in 21..nn {
        nd_zero &= socket::deliver_frame(&na[..k]) == 0;
        fed += 1;
    }
    let m1 = fw::stats().malformed_dropped;
    let nd_trunc_ok = nn == 86 && nd_zero && m1 == m0 + fed && fed == 65 && ndp::nd_lookup(&peer).is_none();
    // 证人：完整 NA 判放行后**真被 handle_frame 学进邻居缓存**（NDP 路径是活的）
    let nd_full_ok = socket::deliver_frame(&na[..nn]) == 6 && ndp::nd_lookup(&peer) == Some(PEER_MAC);

    // (c) 头部变异：对有效帧逐字节异或 4096 次（确定性 xorshift），只要求"返回了"（不 panic、不挂），
    //     并要求 evaluated 与 malformed_dropped 都前进（证明变异帧确实走到了两条判决路径）。
    let e2 = fw::stats().evaluated;
    let m2 = fw::stats().malformed_dropped;
    let mut x: u64 = 0x2675;
    let mut rounds = 0u32;
    for i in 0..4096u32 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let src = if i % 2 == 0 { &f[..n] } else { &na[..nn] };
        let mut b = [0u8; 256];
        let len = src.len();
        b[..len].copy_from_slice(src);
        let at = 12 + ((x as usize) % (len - 12).max(1));
        if let Some(byte) = b.get_mut(at) {
            *byte ^= (x >> 32) as u8 | 1;
        }
        let cut = if x & 0x30 == 0 { ((x as usize) >> 8) % (len + 1) } else { len };
        let _ = socket::deliver_frame(&b[..cut]);
        let _ = socket::dequeue(s, g, &mut [0u8; 64]);
        rounds += 1;
    }
    let s3 = fw::stats();
    let fuzz_ok = rounds == 4096 && s3.evaluated > e2 && s3.malformed_dropped > m2 && s3.faults == 0;

    let _ = socket::destroy(s, g);
    ndp::nd_clear();
    fw::clear();
    let ok = loaded && trunc_ok && full_ok && nd_trunc_ok && nd_full_ok && fuzz_ok;
    crate::log_info!(
        "fw-malformed: 截断v4不判={} 完整v4放={} NDP截断丢(+{}，期望65)={} 完整NA学到={} 变异{}轮(eval+{} malf+{} faults={})={} ⇒ {}",
        trunc_ok, full_ok, m1 - m0, nd_trunc_ok, nd_full_ok, rounds, s3.evaluated - e2, s3.malformed_dropped - m2, s3.faults, fuzz_ok, ok
    );
    if !ok {
        crate::log_fatal!("fw-malformed: 判据不成立");
    }
    ok
}
ktest!(KT_FW_MALFORMED, t_fw_malformed);

// ---------------------------------------------------------------- ④ 容量：128 条收、129 条拒且旧程序不动；规则编译边界 14/15
fn t_fw_capacity() -> bool {
    fw::clear();
    let Some((s, g)) = bound(47006) else {
        return false;
    };
    let mut f = [0u8; 256];
    let n = v4_frame(&mut f, 47006);
    let mut buf = [0u8; fw::FW_PROG_BYTES_MAX + 8];

    // 128 条：127×LDI + RET DROP。证人：帧被丢 ⇒ 执行器真的跑完了 128 步（RET 在最后一格）。
    let mut v = [Insn::ldi(0, 0); 128];
    v[127] = Insn::ret(V_DROP);
    let n128 = asm(&v, &mut buf);
    let g128 = fw::load(&buf[..n128], true);
    let st = fw::stats();
    let full_ok = g128.is_ok() && st.insns == fw::MAX_FW_INSNS as u16 && socket::deliver_frame(&f[..n]) == 0 && queue_empty(s, g);

    // 129 条：拒（TooLong），世代号/指令数/行为都不变
    let mut v2 = [Insn::ldi(0, 0); 129];
    v2[128] = Insn::ret(V_ACCEPT);
    let n129 = asm(&v2, &mut buf);
    let r0 = st.loads_rejected;
    let over = fw::load(&buf[..n129], true);
    let st2 = fw::stats();
    let over_ok = matches!(over, Err(VerifyError::TooLong { insns: 129 }))
        && st2.generation == st.generation && st2.insns == 128 && st2.loads_rejected == r0 + 1 && st2.last_reject == 3
        && socket::deliver_frame(&f[..n]) == 0;

    // 规则编译边界：典型规则 9 条指令 ⇒ 14 条装得下（126+1=127），15 条 TooManyInsns
    let rule = Rule { dport: Some(PortRange { lo: 53, hi: 53 }), ..drop_udp4_dport(53) };
    let fourteen = [rule; 14];
    let fifteen = [rule; 15];
    let c14 = compile(&fourteen, Action::Accept, &mut buf[..fw::FW_PROG_BYTES_MAX]);
    let c15 = compile(&fifteen, Action::Accept, &mut buf[..fw::FW_PROG_BYTES_MAX]);
    let compile_ok = c14 == Ok(127 * 8) && c15 == Err(CompileError::TooManyInsns);

    let _ = socket::destroy(s, g);
    fw::clear();
    let ok = full_ok && over_ok && compile_ok;
    crate::log_info!("fw-capacity: 128条装且执行={} 129条拒且旧程序不动={} 编译14/15边界={} ⇒ {}", full_ok, over_ok, compile_ok, ok);
    if !ok {
        crate::log_fatal!("fw-capacity: 判据不成立");
    }
    ok
}
ktest!(KT_FW_CAPACITY, t_fw_capacity);

// ---------------------------------------------------------------- ⑤ 验证器拒坏字节码（最小对；拒绝时世代号不动）
fn t_fw_verifier_rejects() -> bool {
    fw::clear();
    let r = Insn::ret(V_ACCEPT);
    let cases: [(&[Insn], VerifyError, &[Insn]); 12] = [
        (&[Insn { op: 0x7F, a: 0, off: 0, imm: 0 }, r], VerifyError::BadOpcode { pc: 0 }, &[Insn::ldi(0, 0), r]),
        (&[Insn::ldi(4, 0), r], VerifyError::BadReg { pc: 0 }, &[Insn::ldi(3, 0), r]),
        (&[Insn::ldf(0, 14), r], VerifyError::BadField { pc: 0 }, &[Insn::ldf(0, field::ICMP_TYPE), r]),
        (&[Insn::ret(2)], VerifyError::BadVerdict { pc: 0 }, &[r]),
        (&[Insn::ldi(0, 0), Insn::jeq(0, 0, -2), r], VerifyError::BackwardJump { pc: 1 }, &[Insn::ldi(0, 0), Insn::jeq(0, 0, 0), r]),
        (&[Insn::ldi(0, 0), Insn::ja(-1), r], VerifyError::BackwardJump { pc: 1 }, &[Insn::ldi(0, 0), Insn::ja(0), r]),
        (&[Insn::ldi(0, 0), Insn::jeq(0, 0, 1), r], VerifyError::JumpOutOfRange { pc: 1 }, &[Insn::ldi(0, 0), Insn::jeq(0, 0, 0), r]),
        (&[Insn::ldi(0, 0)], VerifyError::FallsOffEnd, &[Insn::ldi(0, 0), r]),
        (&[r, Insn::ret(V_DROP)], VerifyError::Unreachable { pc: 1 }, &[Insn::ldi(0, 0), Insn::jeq(0, 1, 1), r, Insn::ret(V_DROP)]),
        (&[Insn::jeq(0, 0, 0), r], VerifyError::UninitRead { pc: 0, reg: 0 }, &[Insn::ldi(0, 0), Insn::jeq(0, 0, 0), r]),
        (
            &[Insn::ldf(0, field::DPORT), Insn::jeq(0, 53, 1), Insn::ldi(1, 7), Insn::jeq(1, 7, 0), r],
            VerifyError::UninitRead { pc: 3, reg: 1 },
            &[Insn::ldi(1, 0), Insn::ldf(0, field::DPORT), Insn::jeq(0, 53, 1), Insn::ldi(1, 7), Insn::jeq(1, 7, 0), r],
        ),
        (&[Insn { op: 0x20, a: 1, off: 0, imm: 1 }], VerifyError::Reserved { pc: 0 }, &[r]),
    ];
    let mut buf = [0u8; 64];
    let mut bad_ok = 0u32;
    let mut good_ok = 0u32;
    let gen0 = fw::stats().generation;
    let mut first_fail = 0usize;
    for (k, (bad, want, good)) in cases.iter().enumerate() {
        let before = fw::stats().generation;
        let nb = asm(bad, &mut buf);
        if fw::load(&buf[..nb], false) == Err(*want) && fw::stats().generation == before {
            bad_ok += 1;
        } else if first_fail == 0 {
            first_fail = k + 1;
        }
        let ng = asm(good, &mut buf);
        if fw::load(&buf[..ng], false).is_ok() {
            good_ok += 1;
        }
    }
    // 另两条只能用原始字节表达的：空、不对齐
    let empty_ok = fw::load(&[], false) == Err(VerifyError::Empty);
    let mis_ok = matches!(fw::load(&[0x20, 0, 0, 0, 1, 0, 0], false), Err(VerifyError::Misaligned { len: 7 }));
    let gen1 = fw::stats().generation;
    fw::clear();
    // 证人：12 个好兄弟全部被接受、世代号**恰好**前进 12（坏程序一次都没让它动）
    let ok = bad_ok == 12 && good_ok == 12 && gen1 == gen0.wrapping_add(12) && empty_ok && mis_ok;
    crate::log_info!(
        "fw-verifier: 坏程序按预期拒 {}/12 好兄弟收 {}/12 世代 {}→{} 空={} 不对齐={} 首个失配格={} ⇒ {}",
        bad_ok, good_ok, gen0, gen1, empty_ok, mis_ok, first_fail, ok
    );
    if !ok {
        crate::log_fatal!("fw-verifier: 判据不成立");
    }
    ok
}
ktest!(KT_FW_VERIFIER_REJECTS, t_fw_verifier_rejects);

// ---------------------------------------------------------------- ⑥ 81/82 号经 syscall_dispatch：权限、先拷后验、失败不改规则、统计读回
fn t_fw_syscalls() -> bool {
    // 用例自足三条（与 ktests/storage/fs_rw.rs:478-480 同形）
    crate::sched::init_boot_task();
    crate::sched::start_workers();
    crate::arch::x86_64::apic::timer_start().ok();
    fw::clear();
    let Some((gidx, _)) = crate::sched::current_identity() else {
        crate::log_fatal!("fw-sys: 当前任务没有身份");
        return false;
    };
    let Some((s, g)) = bound(47007) else {
        return false;
    };
    // 字节码要能被 copy_from_user 读到：现建一页真用户页（与 fs_rw.rs:485-496 同法）
    let Ok(pf) = mm::phys_alloc(0, mm::MOD_TEST) else {
        let _ = socket::destroy(s, g);
        return false;
    };
    let va = mm::USER_MMAP_BASE + 0xC000;
    let Ok(map) = mm::map(mm::VirtAddr(va), pf, mm::PageFlags::USER_RW) else {
        let _ = socket::destroy(s, g);
        return false;
    };
    let mut prog = [0u8; fw::FW_PROG_BYTES_MAX];
    let np = compile(&[drop_udp4_dport(47007)], Action::Accept, &mut prog).unwrap_or(0);
    let mut back = [0u8; 24];
    let nb = asm(&[Insn::ldi(0, 0), Insn::jeq(0, 0, -2), Insn::ret(V_ACCEPT)], &mut back);
    let staged = np > 0 && put_user(va, 0, &prog[..np]) && put_user(va, 2048, &back[..nb]);

    let mut fr = frame0();
    let mut call = |nr: u64, a1: u64, a2: u64, a3: u64| -> u64 {
        fr.rax = nr;
        fr.rdi = a1;
        fr.rsi = a2;
        fr.rdx = a3;
        user::syscall_dispatch(&mut fr);
        fr.rax
    };
    let mut f = [0u8; 256];
    let n = v4_frame(&mut f, 47007);
    let u0 = user::unknown_nr();
    let ns0 = user::nosys_nr();
    let old_cred = crate::sched::set_cred(gidx, None);

    // (1) 无凭据 ⇒ E_BAD_HANDLE，世代号不动
    let gen0 = fw::stats().generation;
    let c1 = call(user::SYS_FW_LOAD, va, np as u64, 1) == user::E_BAD_HANDLE && fw::stats().generation == gen0;

    // (2) guest（只有 CAP_READ）⇒ 81 与 82-CLEAR 都 E_DENIED；82-STATS 允许
    let guest = crate::cred::cred_create(1000, 1000, crate::cred::CAP_READ, b"fwguest");
    let root = crate::cred::cred_create(0, 0, crate::cred::CAP_ALL, b"fwroot");
    let _ = crate::sched::set_cred(gidx, guest);
    let c2 = guest.is_some()
        && call(user::SYS_FW_LOAD, va, np as u64, 1) == user::E_DENIED
        && call(user::SYS_FW_CTL, fw::FW_CTL_CLEAR, 0, 0) == user::E_DENIED
        && call(user::SYS_FW_CTL, fw::FW_CTL_STATS, va + 3072, fw::FW_STATS_LEN as u64) == fw::FW_STATS_LEN as u64
        && fw::stats().generation == gen0;

    // (3) root ⇒ 装载并启用；证人：同一帧被丢（syscall 路径真的把程序装进去了）
    let _ = crate::sched::set_cred(gidx, root);
    let r3 = call(user::SYS_FW_LOAD, va, np as u64, 1);
    let c3 = root.is_some() && r3 == u64::from(gen0.wrapping_add(1)) && socket::deliver_frame(&f[..n]) == 0 && queue_empty(s, g);

    // (4) root + 坏字节码（后向跳转）⇒ E_INVALID；世代号不动、旧程序仍生效
    let gen3 = fw::stats().generation;
    let c4 = call(user::SYS_FW_LOAD, va + 2048, nb as u64, 1) == user::E_INVALID
        && fw::stats().generation == gen3 && fw::stats().last_reject == 9
        && socket::deliver_frame(&f[..n]) == 0;

    // (5) 形状：超长 / 零长 / 非法标志 / 未知子命令
    let c5 = call(user::SYS_FW_LOAD, va, (fw::FW_PROG_BYTES_MAX + 8) as u64, 0) == user::E_TOO_LONG
        && call(user::SYS_FW_LOAD, va, 0, 0) == user::E_INVALID
        && call(user::SYS_FW_LOAD, va, np as u64, 2) == user::E_INVALID
        && call(user::SYS_FW_CTL, 9, 0, 0) == user::E_INVALID
        && call(user::SYS_FW_CTL, fw::FW_CTL_STATS, va + 3072, 63) == user::E_INVALID
        && fw::stats().generation == gen3;

    // (6) 统计读回：魔数、世代号、指令数与内核快照一致
    let mut rec = [0u8; 64];
    let c6 = call(user::SYS_FW_CTL, fw::FW_CTL_STATS, va + 3072, 64) == 64 && get_user(va, 3072, &mut rec) && {
        let st = fw::stats();
        rec[0..4] == fw::FW_STATS_MAGIC.to_le_bytes() && rec[4..8] == st.generation.to_le_bytes()
            && rec[8..10] == st.insns.to_le_bytes() && rec[10] == 1
    };

    // (7) 停用 / 启用 / 清空 都经 82；清空后同帧投递（防空转证人：丢弃确实来自过滤器）
    let c7 = call(user::SYS_FW_CTL, fw::FW_CTL_DISABLE, 0, 0) == 0 && socket::deliver_frame(&f[..n]) == 4 && got_payload(s, g)
        && call(user::SYS_FW_CTL, fw::FW_CTL_ENABLE, 0, 0) == 0 && socket::deliver_frame(&f[..n]) == 0
        && call(user::SYS_FW_CTL, fw::FW_CTL_CLEAR, 0, 0) == 0 && socket::deliver_frame(&f[..n]) == 4 && got_payload(s, g)
        && call(user::SYS_FW_CTL, fw::FW_CTL_ENABLE, 0, 0) == user::E_NOT_FOUND;

    // 臂存在性：本档里 81/82 不该落到 `_ =>`（unknown）也不该回 nosys
    let arms = user::unknown_nr() == u0 && user::nosys_nr() == ns0;

    let _ = crate::sched::set_cred(gidx, old_cred);
    let _ = socket::destroy(s, g);
    drop(map);
    fw::clear();
    let ok = staged && c1 && c2 && c3 && c4 && c5 && c6 && c7 && arms;
    crate::log_info!(
        "fw-sys: 夹具={} 无凭据拒={} guest拒={} root装且生效={} 坏码拒且旧规则在={} 形状={} 统计读回={} 控制={} 臂在={} ⇒ {}",
        staged, c1, c2, c3, c4, c5, c6, c7, arms, ok
    );
    if !ok {
        crate::log_fatal!("fw-sys: 判据不成立");
    }
    ok
}
ktest!(KT_FW_SYSCALLS, t_fw_syscalls);
