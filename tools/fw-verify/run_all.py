"""host-fw Python 等价移植的验证电池 + 变异检验。

运行：python run_all.py            （基线 + 全部变异，写 results.json）
**再强调一次：这里"抓到/通过"的对象是 fw_model.py（Python 移植），不是 Rust 源码。**
"""
import json
import random
import sys
import time

try:
    import fw_model as M
except ImportError:  # 沙箱禁 sys.path/importlib：由调用方把已 exec 的模型对象注入为 _INJECTED_M
    M = _INJECTED_M  # noqa: F821

# ---------------------------------------------------------------- 公用
def P(*a):
    print(*a, flush=True)


V4A = bytes([10, 0, 2, 15])
V4B = bytes([10, 0, 2, 2])
V6A = bytes.fromhex("fe800000000000000000000000000001")
V6B = bytes.fromhex("fe800000000000000000000000000099")


def rand_packet(rng, hint_rules=()):
    fam = rng.choice([4, 6])
    proto = rng.choice([17, 17, 58, rng.randrange(256)])
    d = M.DIR_IN if rng.random() < 0.85 else M.DIR_OUT

    def addr():
        if hint_rules and rng.random() < 0.7:
            r = rng.choice(hint_rules)
            px = rng.choice([r.src, r.dst])
            if px is not None:
                a = bytearray(px[0])
                ln = px[1]
                # 在前缀边界附近翻位：边界内（应匹配）与边界上（应不匹配）都要覆盖
                k = rng.choice([ln - 1, ln, ln + 1, rng.randrange(129)])
                if 0 <= k < 128 and rng.random() < 0.6:
                    a[k // 8] ^= 0x80 >> (k % 8)
                if fam == 4:
                    a[4:] = bytes(12)
                return bytes(a)
        if fam == 4:
            return bytes(rng.randrange(256) for _ in range(4)) + bytes(12)
        return bytes(rng.randrange(256) for _ in range(16))

    def port():
        if hint_rules and rng.random() < 0.7:
            r = rng.choice(hint_rules)
            pr = rng.choice([r.sport, r.dport])
            if pr is not None:
                c = rng.choice([pr[0] - 1, pr[0], pr[1], pr[1] + 1, (pr[0] + pr[1]) // 2])
                return max(0, min(0xFFFF, c))
        return rng.choice([0, 53, 67, 68, 5353, 65535, rng.randrange(65536)])

    return M.Packet(fam, proto, d, addr(), addr(), port(), port(), rng.randrange(256))


def rand_rule(rng):
    fam = rng.choice([None, 4, 6])
    r = M.Rule(dir_=M.DIR_IN if rng.random() < 0.85 else M.DIR_OUT,
               family=fam,
               proto=rng.choice([None, 17, 58]),
               action=rng.choice(["Drop", "Accept"]))

    def px():
        if fam is None or rng.random() < 0.5:
            return None
        mx = 32 if fam == 4 else 128
        ln = rng.choice([0, 1, 7, 8, 9, 16, 24, 31, 32, rng.randrange(mx + 1)] + ([33, 63, 64, 65, 96, 127, 128] if fam == 6 else []))
        ln = min(ln, mx)
        a = bytes(rng.randrange(256) for _ in range(4 if fam == 4 else 16))
        return (a + bytes(16 - len(a)), ln)

    def pr():
        c = rng.random()
        if c < 0.4:
            return None
        if c < 0.6:
            p = rng.choice([0, 53, 65535, rng.randrange(65536)])
            return (p, p)
        lo = rng.choice([0, 1, 1024, rng.randrange(65536)])
        hi = rng.choice([65535, 65534, lo, min(65535, lo + rng.randrange(2000))])
        if hi < lo:
            lo, hi = hi, lo
        return (lo, hi)

    r.src, r.dst, r.sport, r.dport = px(), px(), pr(), pr()
    return r


# ---------------------------------------------------------------- T1 验证器单元表（最小对）
def t1_verifier_table():
    I = M
    G = [I.ldf(0, I.F_DPORT), I.jne(0, 53, 1), I.ret(I.V_DROP), I.ret(I.V_ACCEPT)]
    cases = [
        ("空程序", b"", ("Empty", None), None),
        ("不对齐", I.assemble(G) + b"\x00", ("Misaligned", None), I.assemble(G)),
        ("超长129", I.assemble([I.ldi(0, 0)] * 128 + [I.ret(1)]), ("TooLong", None),
         I.assemble([I.ldi(0, 0)] * 127 + [I.ret(1)])),
        ("非法操作码", [I.Insn(0x7F), I.ret(1)], ("BadOpcode", 0), [I.ldi(0, 0), I.ret(1)]),
        ("寄存器越界", [I.ldi(4, 0), I.ret(1)], ("BadReg", 0), [I.ldi(3, 0), I.ret(1)]),
        ("字段越界", [I.ldf(0, 14), I.ret(1)], ("BadField", 0), [I.ldf(0, 13), I.ret(1)]),
        ("保留位LDF.off", [I.Insn(I.LDF, 0, 1, I.F_DPORT), I.ret(1)], ("Reserved", 0), [I.ldf(0, I.F_DPORT), I.ret(1)]),
        ("保留位JA.a", [I.Insn(I.JA, 1, 0, 0), I.ret(1)], ("Reserved", 0), [I.ja(0), I.ret(1)]),
        ("保留位RET.a", [I.Insn(I.RET, 1, 0, 1)], ("Reserved", 0), [I.ret(1)]),
        ("非法判决", [I.ret(2)], ("BadVerdict", 0), [I.ret(1)]),
        ("后向跳转", [I.ldi(0, 0), I.jeq(0, 0, -2), I.ret(1)], ("BackwardJump", 1), [I.ldi(0, 0), I.jeq(0, 0, 0), I.ret(1)]),
        ("自环", [I.ldi(0, 0), I.ja(-1), I.ret(1)], ("BackwardJump", 1), [I.ldi(0, 0), I.ja(0), I.ret(1)]),
        ("跳出末尾", [I.ldi(0, 0), I.jeq(0, 0, 1), I.ret(1)], ("JumpOutOfRange", 1), [I.ldi(0, 0), I.jeq(0, 0, 0), I.ret(1)]),
        ("JA跳出末尾", [I.ja(1), I.ret(1)], ("JumpOutOfRange", 0), [I.ja(0), I.ret(1)]),
        ("无终止", [I.ldi(0, 0)], ("FallsOffEnd", None), [I.ldi(0, 0), I.ret(1)]),
        ("以条件跳转结尾", [I.ldi(0, 0), I.jeq(0, 0, 0)], ("JumpOutOfRange", 1), [I.ldi(0, 0), I.jeq(0, 0, 0), I.ret(0)]),
        ("不可达尾", [I.ret(1), I.ret(0)], ("Unreachable", 1), [I.ldi(0, 0), I.jeq(0, 1, 1), I.ret(1), I.ret(0)]),
        ("不可达中段", [I.ja(1), I.ldi(0, 0), I.ret(1)], ("Unreachable", 1), [I.ja(0), I.ldi(0, 0), I.ret(1)]),
        ("未初始化读(跳转)", [I.jeq(0, 0, 0), I.ret(1)], ("UninitRead", 0), [I.ldi(0, 0), I.jeq(0, 0, 0), I.ret(1)]),
        ("未初始化读(AND)", [I.and_(1, 1), I.ret(1)], ("UninitRead", 0), [I.ldi(1, 0), I.and_(1, 1), I.ret(1)]),
        ("单路径未初始化(需交集)", [I.ldf(0, I.F_DPORT), I.jeq(0, 53, 1), I.ldi(1, 7), I.jeq(1, 7, 0), I.ret(1)], ("UninitRead", 3),
         [I.ldi(1, 0), I.ldf(0, I.F_DPORT), I.jeq(0, 53, 1), I.ldi(1, 7), I.jeq(1, 7, 0), I.ret(1)]),
    ]
    fails = []
    for name, bad, (kind, pc), good in cases:
        b = bad if isinstance(bad, (bytes, bytearray)) else I.assemble(bad)
        try:
            I.verify(b)
            fails.append(f"{name}: 坏程序被接受")
        except I.VErr as e:
            if e.kind != kind or (pc is not None and e.pc != pc):
                fails.append(f"{name}: 期望 {kind}@{pc}，实得 {e.kind}@{e.pc}")
        if good is not None:
            gb = good if isinstance(good, (bytes, bytearray)) else I.assemble(good)
            try:
                I.verify(gb)
            except I.VErr as e:
                fails.append(f"{name}: 最小对的好程序被拒 {e!r}")
    return {"cases": len(cases), "fail": len(fails), "detail": fails[:10]}


# ---------------------------------------------------------------- T2 随机程序：已验证 ⇒ 执行安全
def gen_program(rng):
    """先生成"干净"的程序（前向跳转、合法字段），再以 35% 概率注入恰好一处缺陷。
    这样被接受的比例足够高（检验有功率），被拒的也覆盖每一类缺陷。"""
    L = rng.choice([rng.randint(1, 8), rng.randint(1, 40), rng.randint(60, 128)])
    out = []
    for pc in range(L):
        room = L - pc - 2            # 跳转目标必须 ≤ L-1
        c = rng.random()
        reg = rng.choice([0, 0, 1, 2, 3])
        if pc == L - 1 or (c < 0.015 and pc > 0):
            out.append(M.ret(rng.choice([0, 1])))
        elif c < 0.33:
            out.append(M.ldf(reg, rng.randrange(14)))
        elif c < 0.45:
            out.append(M.ldi(reg, rng.choice([0, 1, 53, rng.randrange(1 << 32)])))
        elif c < 0.55:
            out.append(M.and_(reg, rng.choice([0xFF, 0xFFFF0000, rng.randrange(1 << 32)])))
        elif c < 0.97 and room >= 0:
            op = rng.choice(M.COND)
            off = rng.choice([0, min(1, room), rng.randint(0, room)])
            out.append(M.Insn(op, reg, off, rng.choice([0, 1, 53, 17, 58, rng.randrange(1 << 32)])))
        elif room >= 0:
            out.append(M.ja(rng.choice([0, 0, rng.randint(0, room)])))
        else:
            out.append(M.ldi(reg, 0))
    if rng.random() < 0.7:
        out = [M.ldi(0, 0), M.ldi(1, 0), M.ldi(2, 0), M.ldi(3, 0)] + out
        out = out[:M.MAX_INSNS - 1] + [out[-1]] if len(out) > M.MAX_INSNS else out
    if rng.random() < 0.35:
        k = rng.randrange(len(out))
        i = out[k]
        d = rng.choice(["back", "oor", "reg", "field", "op", "verdict", "resv", "noret", "long", "self"])
        if d == "back": out[k] = M.Insn(rng.choice(M.COND + (M.JA,)), 0, -rng.randint(1, k + 2), 0)
        elif d == "self": out[k] = M.ja(-1)
        elif d == "oor": out[k] = M.Insn(rng.choice(M.COND + (M.JA,)), 0, len(out) - k - 1 + rng.randint(0, 3), 0)
        elif d == "reg": out[k] = M.Insn(i.op if i.op != M.RET else M.LDI, rng.randint(4, 255), 0 if i.op in (M.LDF, M.LDI, M.AND, M.RET) else i.off, i.imm)
        elif d == "field": out[k] = M.ldf(0, rng.choice([14, 15, 255, 1 << 31]))
        elif d == "op": out[k] = M.Insn(rng.choice([0, 4, 0x15, 0x21, 0x7F, 0xFF]), 0, 0, 0)
        elif d == "verdict": out[k] = M.ret(rng.choice([2, 3, 0xFFFFFFFF]))
        elif d == "resv": out[k] = M.Insn(M.RET, 1, 0, 1) if rng.random() < 0.5 else M.Insn(M.LDI, 0, 1, 0)
        elif d == "noret": out = out[:-1] + [M.ldi(0, 0)]
        elif d == "long": out = [M.ldi(0, 0)] * (M.MAX_INSNS + 1 - len(out) + rng.randint(0, 2)) + out
    return out


def check_program_safety(insns, pkts):
    """返回违例描述列表（空 = 安全）。"""
    bad = []
    for p in pkts:
        tr = M.Trace()
        try:
            v, steps = M.run_raw(insns, p, tr)
        except M.Fault as e:
            bad.append(f"Fault:{e}")
            continue
        if steps > len(insns):
            bad.append(f"steps {steps} > len {len(insns)}")
        if tr.uninit_reads:
            bad.append("uninit_read")
        if tr.non_increasing_pc:
            bad.append("pc 不递增")
    return bad


def t2_random_programs(N=30000, seed=2671):
    rng = random.Random(seed)
    pkts = [rand_packet(rng) for _ in range(6)] + [M.udp4(V4A, V4B, 53, 53), M.icmp6(V6A, V6B, 135)]
    acc = viol = 0
    maxsteps = 0
    reasons = {}
    first = []
    for _ in range(N):
        prog = gen_program(rng)
        b = M.assemble(prog)
        try:
            insns = M.verify(b)
        except M.VErr as e:
            reasons[e.kind] = reasons.get(e.kind, 0) + 1
            continue
        acc += 1
        bad = check_program_safety(insns, pkts)
        for p in pkts:
            try:
                _, s = M.run_raw(insns, p)
                maxsteps = max(maxsteps, s)
            except M.Fault:
                pass
        if bad:
            viol += 1
            if len(first) < 3:
                first.append((bad[:2], [repr(i) for i in insns[:8]]))
    return {"programs": N, "accepted": acc, "violations": viol, "max_steps": maxsteps,
            "reject_reasons": reasons, "fail": viol, "first": first}


# ---------------------------------------------------------------- T3 穷举：长度 ≤4、18 条指令字母表
ALPHABET = [
    M.ldf(0, M.F_DPORT), M.ldf(1, M.F_PROTO), M.ldf(0, 14), M.ldi(0, 53), M.ldi(4, 0),
    M.and_(0, 0xFF), M.and_(1, 1), M.jeq(0, 53, 0), M.jeq(0, 53, 1), M.jne(1, 17, 1),
    M.jlt(0, 60, 2), M.jgt(0, 3, -1), M.ja(0), M.ja(1), M.ja(-1),
    M.ret(0), M.ret(1), M.ret(2),
]


def t3_exhaustive(maxlen=4):
    pkts = [M.udp4(V4A, V4B, 53, 53), M.udp4(V4A, V4B, 1, 70), M.udp6(V6A, V6B, 9, 2),
            M.icmp6(V6A, V6B, 135), M.Packet(4, 6, 1, bytes(16), bytes(16), 0, 0, 0), M.udp4(V4A, V4B, 0, 59)]
    total = acc = viol = safe_rej = 0
    maxsteps = 0
    import itertools
    for L in range(1, maxlen + 1):
        for combo in itertools.product(ALPHABET, repeat=L):
            total += 1
            b = M.assemble(combo)
            try:
                insns = M.verify(b)
                ok = True
            except M.VErr:
                ok = False
            if ok:
                acc += 1
                if check_program_safety(insns, pkts):
                    viol += 1
                for p in pkts:
                    try:
                        maxsteps = max(maxsteps, M.run_raw(insns, p)[1])
                    except M.Fault:
                        pass
            else:
                # 保守度：被拒但在这 6 个包上其实安全的个数（如实报告，不是失败）
                lst = [M.Insn.decode(b[k * 8:k * 8 + 8]) for k in range(L)]
                if not check_program_safety(lst, pkts):
                    safe_rej += 1
    return {"programs": total, "accepted": acc, "violations": viol, "max_steps": maxsteps,
            "rejected_but_safe_on_6pkts": safe_rej, "fail": viol}


# ---------------------------------------------------------------- T4 编译器 vs 参考语义
def t4_compile_diff(N=2500, seed=2672):
    rng = random.Random(seed)
    sets = evals = mism = toolong = unverified = 0
    first = []
    maxsteps = 0
    for _ in range(N):
        rules = [rand_rule(rng) for _ in range(rng.choice([0, 1, 2, 3, 5, 8, 12]))]
        default = rng.choice(["Accept", "Drop"])
        try:
            b = M.compile_rules(rules, default)
        except M.CErr as e:
            if str(e) == "TooManyInsns":
                toolong += 1
                continue
            raise
        try:
            insns = M.verify(b)
        except M.VErr as e:
            unverified += 1
            if len(first) < 3:
                first.append(f"编译产物未过验证 {e!r} rules={rules}")
            continue
        sets += 1
        for _ in range(40):
            p = rand_packet(rng, rules)
            want = M.eval_rules(rules, default, p)
            try:
                got, s = M.run_raw(insns, p)
                maxsteps = max(maxsteps, s)
            except M.Fault as e:
                got = f"Fault:{e}"
            evals += 1
            if got != want:
                mism += 1
                if len(first) < 3:
                    first.append(f"want={want} got={got} pkt={p} rules={rules}")
    return {"rulesets": sets, "evals": evals, "mismatch": mism, "too_many_insns": toolong,
            "compiled_but_unverified": unverified, "max_steps": maxsteps, "fail": mism + unverified, "first": first}


# ---------------------------------------------------------------- T5 步数上界的边界
def t5_step_bound():
    fails = []
    p = M.udp4(V4A, V4B, 1, 2)
    longest = [M.ldi(0, 0)] * (M.MAX_INSNS - 1) + [M.ret(1)]
    try:
        insns = M.verify(M.assemble(longest))
        v, s = M.run_raw(insns, p)
        if s != M.MAX_INSNS:
            fails.append(f"最长程序步数 {s} != {M.MAX_INSNS}")
    except (M.VErr, M.Fault) as e:
        fails.append(f"最长合法程序没跑完：{e!r}")
    over = [M.ldi(0, 0)] * M.MAX_INSNS + [M.ret(1)]
    # 未验证直接执行：执行器自己的步数预算必须咬（证明预算不是摆设）
    try:
        M.run_raw(over, p)
        fails.append("129 条直线程序未触发 StepBudget")
    except M.Fault as e:
        if str(e) != "StepBudget":
            fails.append(f"期望 StepBudget 实得 {e}")
    # 验证器必须拒它（否则"已验证 ⇒ 不触预算"不成立）
    try:
        M.verify(M.assemble(over))
        fails.append("129 条程序被验证器接受")
    except M.VErr:
        pass
    # 未验证的自环：执行器靠预算终止
    try:
        M.run_raw([M.ja(-1)], p)
        fails.append("自环未被预算终止")
    except M.Fault as e:
        if str(e) != "StepBudget":
            fails.append(f"自环期望 StepBudget 实得 {e}")
    return {"fail": len(fails), "detail": fails}


# ---------------------------------------------------------------- T6 解析：fuzz + 与内核解析器差分
def gen_frames(seed=2673):
    rng = random.Random(seed)
    frames = []
    bases = []
    for _ in range(60):
        ihl = rng.choice([5, 5, 5, 6, 8, 15])
        pl = bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 7, 40])))
        bases.append(M.build_udp4(bytes(rng.randrange(256) for _ in range(4)), bytes(rng.randrange(256) for _ in range(4)),
                                  rng.randrange(65536), rng.randrange(65536), pl, ihl))
        bases.append(M.build_udp6(bytes(rng.randrange(256) for _ in range(16)), bytes(rng.randrange(256) for _ in range(16)),
                                  rng.randrange(65536), rng.randrange(65536), pl))
        bases.append(M.build_nd(V6B, V6A, rng.choice([135, 136]), V6A))
        bases.append(M.build_nd(V6B, V6A, 135, V6A, with_opt=False))
        # 让 T7 的"丢 UDP dport 5353"真有被测帧（第一版语料里 0 条，见 README 自错清单）
        dp = rng.choice([5353, 5353, 53])
        bases.append(M.build_udp4(V4B, V4A, rng.randrange(65536), dp, pl, ihl))
        bases.append(M.build_udp6(V6B, V6A, rng.randrange(65536), dp, pl))
    frames += bases
    for b in bases[:24]:                       # 每个长度截断
        frames += [b[:k] for k in range(len(b))]
    for _ in range(30000):                     # 头部变异
        b = bytearray(rng.choice(bases))
        for _ in range(rng.randint(1, 3)):
            k = rng.randrange(12, min(len(b), 70)) if rng.random() < 0.8 else rng.randrange(len(b))
            b[k] = rng.randrange(256) if rng.random() < 0.5 else b[k] ^ (1 << rng.randrange(8))
        if rng.random() < 0.2:
            b = b[:rng.randrange(len(b) + 1)]
        frames.append(bytes(b))
    for _ in range(15000):                     # 纯随机
        n = rng.randrange(0, 120)
        b = bytearray(rng.randrange(256) for _ in range(n))
        if n >= 14 and rng.random() < 0.6:
            b[12:14] = rng.choice([b"\x08\x00", b"\x86\xdd"])
            if n > 14 and rng.random() < 0.6:
                b[14] = rng.choice([0x45, 0x46, 0x60, 0x4F])
            if n > 20 and b[12:14] == b"\x86\xdd" and rng.random() < 0.5:
                b[20] = rng.choice([17, 58])
        frames.append(bytes(b))
    return frames


def t6_parse(frames):
    crash = koob = 0
    d1 = d2 = d3 = 0
    some4 = some6 = somend = 0
    first = []
    for f in frames:
        try:
            r = M.parse_eth(f)
        except Exception as e:  # noqa: BLE001
            crash += 1
            if len(first) < 3: first.append(f"parse_eth 异常 {e!r} len={len(f)}")
            continue
        try:
            k4, k6, kn = M.k_parse_frame(f), M.k_parse_udp6_frame(f), M.k_parse_nd(f)
        except M.StrictOOB as e:
            koob += 1          # 内核解析器移植若越界 ⇒ 内核本身可能 panic
            if len(first) < 3: first.append(f"内核解析器移植越界 {e!r}")
            continue
        is_pkt = r[0] == "Packet"
        p = r[1] if is_pkt else None
        if k4 is not None:
            some4 += 1
            (sip, sp), (dip, dp), _ = k4
            if not (is_pkt and p == M.udp4(sip, dip, sp, dp)):
                d1 += 1
                if len(first) < 3: first.append(f"D1 内核v4有/fw无或不等 {r}")
        elif is_pkt and p.family == 4:
            d1 += 1
            if len(first) < 3: first.append("D1 fw v4 有、内核无")
        if k6 is not None:
            some6 += 1
            src, dst, sp, dp, _ = k6
            if not (is_pkt and p == M.udp6(src, dst, sp, dp)):
                d2 += 1
                if len(first) < 3: first.append(f"D2 内核v6有/fw不等 {r}")
        elif is_pkt and p.family == 6 and p.proto == 17:
            d2 += 1
            if len(first) < 3: first.append("D2 fw v6udp 有、内核无")
        if kn is not None:
            somend += 1
            kind, src, dst, _, _ = kn
            if not (is_pkt and p == M.icmp6(src, dst, kind)):
                d3 += 1
                if len(first) < 3: first.append(f"D3 parse_nd 有/fw 不含 {r}")
    return {"frames": len(frames), "crash": crash, "kernel_port_oob": koob,
            "kernel_v4_some": some4, "kernel_v6udp_some": some6, "kernel_nd_some": somend,
            "D1_v4": d1, "D2_v6udp": d2, "D3_nd_containment": d3,
            "fail": crash + koob + d1 + d2 + d3, "first": first}


# ---------------------------------------------------------------- T7 挂载点模型
def t7_hook(frames):
    socks = set()
    for f in frames:            # 让一部分帧真有人收
        r = M.k_parse_frame(f) if len(f) >= 14 and f[12:14] == b"\x08\x00" else None
        if r and len(socks) < 40: socks.add(r[1][1])
    socks |= {5353, 53}
    fails = []
    nfail = 0
    # 7a 不干扰：未装程序 / 装了但停用 ⇒ 与原函数逐帧一致，且 evaluated==0
    for mode in ("none", "loaded_disabled"):
        fw = M.FwState()
        if mode == "loaded_disabled":
            try:
                fw.load(M.compile_rules([M.Rule(proto=17, action="Drop")], "Drop"), enable=False)
            except (M.VErr, M.CErr) as e:
                return {"fail": 1, "detail": [f"7a 装载失败 {e!r}"]}
        diff = 0
        for f in frames:
            if M.deliver_frame_model(f, None, socks) != M.deliver_frame_model(f, fw, socks):
                diff += 1
        if diff or fw.evaluated:
            fails.append(f"7a[{mode}] 不一致帧={diff} evaluated={fw.evaluated}")
            nfail += diff + fw.evaluated
    # 7b 判决一致：规则 = 丢 UDP dport 5353、丢 ICMPv6（proto 58）、默认放行
    rules = [M.Rule(proto=17, dport=(5353, 5353), action="Drop"), M.Rule(family=6, proto=58, action="Drop")]
    fw = M.FwState()
    try:
        fw.load(M.compile_rules(rules, "Accept"), enable=True)
    except (M.VErr, M.CErr) as e:
        return {"fail": 1, "detail": fails + [f"7b 装载失败 {e!r}"]}
    wrong = dropped_expected = ndp_seen = udp_drop_expected = 0
    for f in frames:
        base = M.deliver_frame_model(f, None, socks)
        got = M.deliver_frame_model(f, fw, socks)
        k4 = M.k_parse_frame(f) if len(f) >= 14 and f[12:14] == b"\x08\x00" else None
        is6 = len(f) >= 14 and f[12:14] == b"\x86\xdd"
        ndp_branch = is6 and len(f) > 20 and f[20] == 58
        k6 = M.k_parse_udp6_frame(f) if is6 and not ndp_branch else None
        if ndp_branch:
            ndp_seen += 1
            r = M.parse_eth(f)
            if r[0] == "Packet":
                expect_drop = M.eval_rules(rules, "Accept", r[1]) == "Drop"
            else:
                expect_drop = True          # 过滤启用时 NDP 分支取不出头 ⇒ 丢
        elif k4 is not None:
            (sip, sp), (dip, dp), _ = k4
            expect_drop = M.eval_rules(rules, "Accept", M.udp4(sip, dip, sp, dp)) == "Drop"
        elif k6 is not None:
            src, dst, sp, dp, _ = k6
            expect_drop = M.eval_rules(rules, "Accept", M.udp6(src, dst, sp, dp)) == "Drop"
        else:
            expect_drop = False
        if expect_drop:
            dropped_expected += 1
            if not ndp_branch:
                udp_drop_expected += 1
            if got != (0, []):
                wrong += 1
        elif got != base:
            wrong += 1
    if wrong:
        fails.append(f"7b 判决与参考不一致 {wrong} 帧")
        nfail += wrong
    if udp_drop_expected == 0 or ndp_seen == 0:
        fails.append("7b 空转：没有任何 UDP 帧应被丢 / 没有 NDP 分支帧")
        nfail += 1
    return {"fail": nfail, "detail": fails, "expected_drops": dropped_expected, "expected_udp_drops": udp_drop_expected, "ndp_branch_frames": ndp_seen,
            "fw_counters": {"evaluated": fw.evaluated, "dropped": fw.dropped, "malformed": fw.malformed}}


# ---------------------------------------------------------------- 驱动
def battery(frames, quick=False):
    out = {}
    t = time.time()
    out["T1"] = t1_verifier_table()
    out["T2"] = t2_random_programs(N=8000 if quick else 30000)
    out["T3"] = t3_exhaustive(maxlen=3 if quick else 4)
    out["T4"] = t4_compile_diff(N=800 if quick else 2500)
    out["T5"] = t5_step_bound()
    out["T6"] = t6_parse(frames)
    out["T7"] = t7_hook(frames)
    out["_secs"] = round(time.time() - t, 1)
    return out


MUTANTS = [
    "no_backward_check", "range_off_by_one", "no_fallsoff_check", "no_uninit_check", "no_reg_check",
    "no_field_check", "no_opcode_check", "no_verdict_check", "merge_union", "no_toolong_check",
    "no_unreachable_check", "no_reserved_check",
    "exec_swap_lt_gt", "exec_target_off_by_one",
    "compile_hi_exclusive", "compile_mask_off_by_one", "compile_no_family",
    "parse_v4_fixed_ihl", "parse_v6_no_ulen_check", "parse_icmp6_too_strict",
    "hook_after_enqueue", "hook_skip_ndp",
]


def summarize(res):
    return {k: v["fail"] for k, v in res.items() if isinstance(v, dict)}


def main(which=None, out_path="results.json"):
    frames = gen_frames()
    P(f"帧语料 {len(frames)} 条")
    M.MUT.clear()
    base = battery(frames)
    P("基线:", json.dumps(summarize(base), ensure_ascii=False), f"{base['_secs']}s")
    results = {"baseline": base, "mutants": {}}
    for m in (which or MUTANTS):
        M.MUT.clear()
        M.MUT.add(m)
        try:
            r = battery(frames, quick=True)
            s = summarize(r)
        except Exception as e:  # noqa: BLE001 —— 变异让模型自身崩溃也算"被抓到"，但要如实标注
            r, s = {"crash": repr(e)}, {"CRASH": repr(e)}
        caught = any(v for v in s.values()) if "CRASH" not in s else True
        results["mutants"][m] = {"summary": s, "caught": caught, "full": r}
        P(f"变异 {m}: {'抓到' if caught else '**未抓到**'} {json.dumps(s, ensure_ascii=False)}")
    M.MUT.clear()
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, ensure_ascii=False, indent=1, default=str)
    return results


if __name__ == "__main__":
    main(sys.argv[1:] or None)
