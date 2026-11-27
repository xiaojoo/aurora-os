"""host-fw 的 Python 等价移植（逐函数对照 crates/host-fw/src/*.rs）。

**这是移植，不是 Rust 本身**：这里抓到的任何问题、通过的任何性质，都只对这份移植成立；
Rust 与移植之间可能存在我没发现的偏差（见 README「需本机核对」）。

约定：
* 所有对帧字节的访问都走 `g(f, i)` / `be16(f, i)` / `sub(f, a, b)`，越界返回 None
  —— 对应 Rust 的 `f.get(i)` / `f.get(a..b)`。**Rust 侧解析器不用下标**，所以"不 panic"是构造性的；
  这里额外用 `STRICT` 计数器记录"如果写成下标会不会越界"，供 fuzz 报告。
* `MUT` 是变异开关集合：每个名字对应 README 验证表里的一行变异。基线运行时 `MUT` 为空。
"""

MUT: set = set()

# ---------------------------------------------------------------- packet.rs
FAMILY_V4, FAMILY_V6 = 4, 6
PROTO_UDP, PROTO_ICMPV6 = 17, 58
DIR_IN, DIR_OUT = 0, 1

F_FAMILY, F_PROTO, F_DIR, F_SPORT, F_DPORT = 0, 1, 2, 3, 4
F_SRC0, F_SRC3, F_DST0, F_DST3, F_ICMP_TYPE = 5, 8, 9, 12, 13
F_COUNT = 14


class Packet:
    __slots__ = ("family", "proto", "dir", "src", "dst", "sport", "dport", "icmp_type")

    def __init__(self, family, proto, dir_, src, dst, sport, dport, icmp_type):
        assert len(src) == 16 and len(dst) == 16
        self.family, self.proto, self.dir = family, proto, dir_
        self.src, self.dst = bytes(src), bytes(dst)
        self.sport, self.dport, self.icmp_type = sport, dport, icmp_type

    def key(self):
        return (self.family, self.proto, self.dir, self.src, self.dst, self.sport, self.dport, self.icmp_type)

    def __eq__(self, o):
        return isinstance(o, Packet) and self.key() == o.key()

    def __repr__(self):
        return f"Packet{self.key()!r}"

    def field(self, f):
        if f == F_FAMILY: return self.family
        if f == F_PROTO: return self.proto
        if f == F_DIR: return self.dir
        if f == F_SPORT: return self.sport
        if f == F_DPORT: return self.dport
        if F_SRC0 <= f <= F_SRC3: return word(self.src, f - F_SRC0)
        if F_DST0 <= f <= F_DST3: return word(self.dst, f - F_DST0)
        if f == F_ICMP_TYPE: return self.icmp_type
        return None


def word(a, i):
    s = a[i * 4:i * 4 + 4]
    if len(s) != 4:
        return None
    return int.from_bytes(s, "big")


def widen(a4):
    return bytes(a4) + bytes(12)


def udp4(src, dst, sport, dport, d=DIR_IN):
    return Packet(FAMILY_V4, PROTO_UDP, d, widen(src), widen(dst), sport, dport, 0)


def udp6(src, dst, sport, dport, d=DIR_IN):
    return Packet(FAMILY_V6, PROTO_UDP, d, src, dst, sport, dport, 0)


def icmp6(src, dst, t, d=DIR_IN):
    return Packet(FAMILY_V6, PROTO_ICMPV6, d, src, dst, 0, 0, t)


# ---------------------------------------------------------------- insn.rs
INSN_BYTES = 8
MAX_INSNS = 128
MAX_PROG_BYTES = MAX_INSNS * INSN_BYTES
NREGS = 4
LDF, LDI, AND, JEQ, JNE, JLT, JGT, JA, RET = 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x14, 0x20
V_DROP, V_ACCEPT = 0, 1
COND = (JEQ, JNE, JLT, JGT)


class Insn:
    __slots__ = ("op", "a", "off", "imm")

    def __init__(self, op, a=0, off=0, imm=0):
        self.op, self.a, self.off, self.imm = op & 0xFF, a & 0xFF, off, imm & 0xFFFFFFFF

    def encode(self):
        return bytes([self.op, self.a]) + (self.off & 0xFFFF).to_bytes(2, "little") + self.imm.to_bytes(4, "little")

    @staticmethod
    def decode(b8):
        off = int.from_bytes(b8[2:4], "little")
        if off >= 0x8000:
            off -= 0x10000
        return Insn(b8[0], b8[1], off, int.from_bytes(b8[4:8], "little"))

    def __repr__(self):
        return f"Insn({self.op:#x},{self.a},{self.off},{self.imm})"


def ldf(r, f): return Insn(LDF, r, 0, f)
def ldi(r, v): return Insn(LDI, r, 0, v)
def and_(r, m): return Insn(AND, r, 0, m)
def jeq(r, v, o): return Insn(JEQ, r, o, v)
def jne(r, v, o): return Insn(JNE, r, o, v)
def jlt(r, v, o): return Insn(JLT, r, o, v)
def jgt(r, v, o): return Insn(JGT, r, o, v)
def ja(o): return Insn(JA, 0, o, 0)
def ret(v): return Insn(RET, 0, 0, v)


def assemble(insns):
    return b"".join(i.encode() for i in insns)


# ---------------------------------------------------------------- verify.rs
class VErr(Exception):
    def __init__(self, kind, pc=None, reg=None):
        super().__init__(kind)
        self.kind, self.pc, self.reg = kind, pc, reg

    def __repr__(self):
        return f"VErr({self.kind},{self.pc},{self.reg})"


def target(pc, off):
    t = pc + 1 + off
    if "exec_target_off_by_one" in MUT:      # 变异：执行器与验证器共用的目标公式少加 1
        t = pc + off
    return None if t < 0 else t


def jump_ok(pc, off, n):
    if off < 0 and "no_backward_check" not in MUT:
        raise VErr("BackwardJump", pc)
    t = target(pc, off)
    # 纵深防御：不只看 off 的符号，还直接看"目标是否严格在后"——
    # 这样即便 target() 的公式写错（变异 exec_target_off_by_one），环也进不来。
    if t is not None and t <= pc and "no_backward_check" not in MUT:
        raise VErr("BackwardJump", pc)
    limit = n + 1 if "range_off_by_one" in MUT else n
    if t is None or t >= limit:
        raise VErr("JumpOutOfRange", pc)


def check_one(i, pc, n):
    reg_ok = i.a < NREGS or "no_reg_check" in MUT
    if i.op == LDF:
        if not reg_ok: raise VErr("BadReg", pc)
        if i.off != 0 and "no_reserved_check" not in MUT: raise VErr("Reserved", pc)
        if i.imm >= F_COUNT and "no_field_check" not in MUT: raise VErr("BadField", pc)
    elif i.op in (LDI, AND):
        if not reg_ok: raise VErr("BadReg", pc)
        if i.off != 0 and "no_reserved_check" not in MUT: raise VErr("Reserved", pc)
    elif i.op in COND:
        if not reg_ok: raise VErr("BadReg", pc)
        jump_ok(pc, i.off, n)
    elif i.op == JA:
        if (i.a != 0 or i.imm != 0) and "no_reserved_check" not in MUT: raise VErr("Reserved", pc)
        jump_ok(pc, i.off, n)
    elif i.op == RET:
        if (i.a != 0 or i.off != 0) and "no_reserved_check" not in MUT: raise VErr("Reserved", pc)
        if i.imm not in (V_DROP, V_ACCEPT) and "no_verdict_check" not in MUT: raise VErr("BadVerdict", pc)
    else:
        if "no_opcode_check" not in MUT:
            raise VErr("BadOpcode", pc)


def reads_reg(op): return op in (AND,) + COND
def writes_reg(op): return op in (LDF, LDI)
def falls_through(op): return op not in (JA, RET)
def is_jump(op): return op in COND + (JA,)


def verify(b):
    """返回 insns 列表；失败抛 VErr。与 verify_into 同序。"""
    if len(b) == 0:
        raise VErr("Empty")
    if len(b) % INSN_BYTES != 0:
        raise VErr("Misaligned")
    n = len(b) // INSN_BYTES
    if n > MAX_INSNS and "no_toolong_check" not in MUT:
        raise VErr("TooLong")
    insns = []
    for pc in range(n):
        i = Insn.decode(b[pc * 8:pc * 8 + 8])
        check_one(i, pc, n)
        insns.append(i)
    if insns[n - 1].op != RET and "no_fallsoff_check" not in MUT:
        raise VErr("FallsOffEnd")
    reach = [False] * max(n, 1)
    defs = [0] * max(n, 1)
    reach[0] = True

    def merge(t, d):
        if t >= n:
            if "no_fallsoff_check" in MUT or "range_off_by_one" in MUT:
                return            # 变异下：让坏程序通过，看执行器是否被抓
            raise VErr("FallsOffEnd")
        if reach[t]:
            if "merge_union" in MUT:
                defs[t] |= d
            else:
                defs[t] &= d
        else:
            reach[t] = True
            defs[t] = d

    for pc in range(n):
        i = insns[pc]
        if not reach[pc] and "no_unreachable_check" not in MUT:
            raise VErr("Unreachable", pc)
        d = defs[pc]
        bit = (1 << i.a) if i.a < NREGS else 0
        if reads_reg(i.op) and (d & bit) == 0 and "no_uninit_check" not in MUT:
            raise VErr("UninitRead", pc, i.a)
        out = (d | bit) if writes_reg(i.op) else d
        if falls_through(i.op):
            merge(pc + 1, out)
        if is_jump(i.op):
            t = target(pc, i.off)
            if t is None:
                if "no_backward_check" in MUT:
                    continue
                raise VErr("JumpOutOfRange", pc)
            if t <= pc and "no_backward_check" in MUT:
                continue      # 变异：后向边不进数据流（等价于验证器根本没想到环）
            merge(t, out)
    return insns


# ---------------------------------------------------------------- exec.rs
MAX_STEPS = MAX_INSNS


class Fault(Exception):
    pass


class Trace:
    """执行插桩（Rust 执行器没有这些；只用于证明"已验证程序不会读未初始化寄存器、pc 严格递增"）。"""
    def __init__(self):
        self.uninit_reads = 0
        self.non_increasing_pc = 0
        self.steps = 0


def run_raw(insns, pkt, tr=None):
    r = [0] * NREGS
    init = [False] * NREGS
    pc = 0
    steps = 0
    while True:
        if steps >= MAX_STEPS:
            raise Fault("StepBudget")
        if not (0 <= pc < len(insns)):
            raise Fault("PcOutOfRange")
        i = insns[pc]
        steps += 1
        if tr is not None:
            tr.steps = steps
        prev = pc
        if i.op == LDF:
            v = pkt.field(i.imm)
            if v is None: raise Fault("BadField")
            if i.a >= NREGS: raise Fault("BadReg")
            r[i.a] = v; init[i.a] = True; pc += 1
        elif i.op == LDI:
            if i.a >= NREGS: raise Fault("BadReg")
            r[i.a] = i.imm; init[i.a] = True; pc += 1
        elif i.op == AND:
            if i.a >= NREGS: raise Fault("BadReg")
            if tr is not None and not init[i.a]: tr.uninit_reads += 1
            r[i.a] &= i.imm; pc += 1
        elif i.op in COND:
            if i.a >= NREGS: raise Fault("BadReg")
            if tr is not None and not init[i.a]: tr.uninit_reads += 1
            x = r[i.a]
            if i.op == JEQ: take = x == i.imm
            elif i.op == JNE: take = x != i.imm
            elif i.op == JLT: take = (x > i.imm) if "exec_swap_lt_gt" in MUT else (x < i.imm)
            else: take = (x < i.imm) if "exec_swap_lt_gt" in MUT else (x > i.imm)
            if take:
                t = target(pc, i.off)
                if t is None: raise Fault("PcOutOfRange")
                pc = t
            else:
                pc += 1
        elif i.op == JA:
            t = target(pc, i.off)
            if t is None: raise Fault("PcOutOfRange")
            pc = t
        elif i.op == RET:
            if i.imm == V_DROP: return ("Drop", steps)
            if i.imm == V_ACCEPT: return ("Accept", steps)
            raise Fault("BadVerdict")
        else:
            raise Fault("BadOpcode")
        if tr is not None and pc <= prev:
            tr.non_increasing_pc += 1


# ---------------------------------------------------------------- rules.rs
class Rule:
    __slots__ = ("dir", "family", "proto", "src", "dst", "sport", "dport", "action")

    def __init__(self, dir_=DIR_IN, family=None, proto=None, src=None, dst=None, sport=None, dport=None, action="Drop"):
        self.dir, self.family, self.proto = dir_, family, proto
        self.src, self.dst = src, dst            # (addr16, len) 或 None
        self.sport, self.dport = sport, dport    # (lo, hi) 或 None
        self.action = action

    def __repr__(self):
        return f"Rule(dir={self.dir},fam={self.family},proto={self.proto},src={self.src},dst={self.dst},sp={self.sport},dp={self.dport},{self.action})"


class CErr(Exception):
    pass


def prefix_match(px, a16):
    addr, ln = px
    for bit in range(ln):
        byte, sh = divmod(bit, 8)
        m = 0x80 >> sh
        if (addr[byte] & m) != (a16[byte] & m):
            return False
    return True


def rule_matches(r, p):
    if r.dir != p.dir: return False
    if r.family is not None and p.family != r.family: return False
    if r.proto is not None and p.proto != r.proto: return False
    if r.src is not None and not prefix_match(r.src, p.src): return False
    if r.dst is not None and not prefix_match(r.dst, p.dst): return False
    if r.sport is not None and not (r.sport[0] <= p.sport <= r.sport[1]): return False
    if r.dport is not None and not (r.dport[0] <= p.dport <= r.dport[1]): return False
    return True


def eval_rules(rules, default, p):
    for r in rules:
        if rule_matches(r, p):
            return r.action
    return default


def vcode(a): return V_ACCEPT if a == "Accept" else V_DROP


def prefix_words(px):
    addr, ln = px
    out = []
    for i in range(4):
        bits = max(0, min(32, ln - 32 * i))
        if "compile_mask_off_by_one" in MUT and 0 < bits < 32:
            bits += 1
        if bits == 0:
            break
        mask = 0xFFFFFFFF if bits == 32 else (~(0xFFFFFFFF >> bits)) & 0xFFFFFFFF
        out.append((i, mask, word(addr, i) & mask))
    return out


def prefix_len_insns(px):
    if px is None: return 0
    return sum(2 if m == 0xFFFFFFFF else 3 for (_, m, _) in prefix_words(px))


def range_len(pr):
    if pr is None: return 0
    lo, hi = pr
    if lo == 0 and hi == 0xFFFF: return 0
    if lo == hi: return 2
    return 1 + (1 if lo > 0 else 0) + (1 if hi < 0xFFFF else 0)


def rule_len(r):
    n = 2
    if r.family is not None and "compile_no_family" not in MUT: n += 2
    if r.proto is not None: n += 2
    n += prefix_len_insns(r.src) + prefix_len_insns(r.dst)
    n += range_len(r.sport) + range_len(r.dport)
    return n + 1


def validate(r):
    if r.family is not None and r.family not in (FAMILY_V4, FAMILY_V6): raise CErr("BadFamily")
    for px in (r.src, r.dst):
        if px is None: continue
        if r.family is None: raise CErr("PrefixWithoutFamily")
        if px[1] > (32 if r.family == FAMILY_V4 else 128): raise CErr("PrefixTooLong")
    for pr in (r.sport, r.dport):
        if pr is not None and pr[0] > pr[1]: raise CErr("EmptyPortRange")


def compile_rules(rules, default):
    out = []

    def push(i):
        if len(out) >= MAX_INSNS: raise CErr("TooManyInsns")
        out.append(i)

    def j(kind, val, end):
        p = len(out)
        push(Insn(kind, 0, end - (p + 1), val))

    for r in rules:
        validate(r)
        end = len(out) + rule_len(r)
        push(ldf(0, F_DIR)); j(JNE, r.dir, end)
        if r.family is not None and "compile_no_family" not in MUT:
            push(ldf(0, F_FAMILY)); j(JNE, r.family, end)
        if r.proto is not None:
            push(ldf(0, F_PROTO)); j(JNE, r.proto, end)
        for base, px in ((F_SRC0, r.src), (F_DST0, r.dst)):
            if px is None: continue
            for (wi, mask, val) in prefix_words(px):
                push(ldf(0, base + wi))
                if mask != 0xFFFFFFFF: push(and_(0, mask))
                j(JNE, val, end)
        for fld, pr in ((F_SPORT, r.sport), (F_DPORT, r.dport)):
            if pr is None: continue
            lo, hi = pr
            if lo == 0 and hi == 0xFFFF: continue
            push(ldf(0, fld))
            if lo == hi:
                j(JNE, lo, end)
            else:
                if lo > 0: j(JLT, lo, end)
                if hi < 0xFFFF:
                    if "compile_hi_exclusive" in MUT:
                        j(JGT, hi - 1, end)
                    else:
                        j(JGT, hi, end)
        push(ret(vcode(r.action)))
        if len(out) != end: raise CErr("Internal")
    push(ret(vcode(default)))
    return assemble(out)


# ---------------------------------------------------------------- parse.rs
def g(f, i):
    return f[i] if 0 <= i < len(f) else None


def be16(f, i):
    a, b = g(f, i), g(f, i + 1)
    if a is None or b is None: return None
    return (a << 8) | b


def sub(f, a, b):
    if a < 0 or b > len(f) or a > b: return None
    return bytes(f[a:b])


def parse_eth(f, d=DIR_IN):
    """返回 ('Packet', pkt) / ('NotIp',) / ('Malformed',) / ('Unsupported',)。"""
    et = be16(f, 12)
    if et is None:
        return ("Malformed",)
    if et == 0x0800:
        return parse_v4(f, d)
    if et == 0x86DD:
        return parse_v6(f, d)
    return ("NotIp",)


def parse_v4(f, d):
    ip = 14
    if len(f) < 14 + 20 + 8: return ("Malformed",)
    vh = g(f, ip)
    if vh is None or (vh >> 4) != 4: return ("Malformed",)
    ihl = (vh & 0x0F) * 4
    if "parse_v4_fixed_ihl" in MUT: ihl = 20
    if ihl < 20 or len(f) < ip + ihl + 8: return ("Malformed",)
    if g(f, ip + 9) != 17: return ("Unsupported",)
    frag = be16(f, ip + 6)
    if frag is None: return ("Malformed",)
    if frag & 0x3FFF != 0: return ("Unsupported",)
    tot = be16(f, ip + 2)
    if tot is None: return ("Malformed",)
    if tot < ihl + 8 or ip + tot > len(f): return ("Malformed",)
    u = ip + ihl
    ulen = be16(f, u + 4)
    if ulen is None: return ("Malformed",)
    if ulen < 8 or u + ulen > ip + tot: return ("Malformed",)
    src, dst = sub(f, ip + 12, ip + 16), sub(f, ip + 16, ip + 20)
    sp, dp = be16(f, u), be16(f, u + 2)
    if None in (src, dst, sp, dp): return ("Malformed",)
    return ("Packet", udp4(src, dst, sp, dp, d))


def parse_v6(f, d):
    ip = 14
    if len(f) < 14 + 40: return ("Malformed",)
    v = g(f, ip)
    if v is None or (v >> 4) != 6: return ("Malformed",)
    nh = g(f, ip + 6)
    plen = be16(f, ip + 4)
    src, dst = sub(f, ip + 8, ip + 24), sub(f, ip + 24, ip + 40)
    if None in (nh, plen, src, dst): return ("Malformed",)
    if nh == 17:
        if len(f) < 14 + 40 + 8: return ("Malformed",)
        if plen < 8 or ip + 40 + plen > len(f): return ("Malformed",)
        u = ip + 40
        ulen = be16(f, u + 4)
        if ulen is None: return ("Malformed",)
        if "parse_v6_no_ulen_check" not in MUT:
            if ulen < 8 or ulen > plen: return ("Malformed",)
        sp, dp = be16(f, u), be16(f, u + 2)
        if None in (sp, dp): return ("Malformed",)
        return ("Packet", udp6(src, dst, sp, dp, d))
    if nh == 58:
        need = 14 + 40 + 32 if "parse_icmp6_too_strict" in MUT else 14 + 40 + 4
        if len(f) < need: return ("Malformed",)
        if plen < 4 or ip + 40 + plen > len(f): return ("Malformed",)
        t = g(f, ip + 40)
        if t is None: return ("Malformed",)
        return ("Packet", icmp6(src, dst, t, d))
    return ("Unsupported",)


# ---------------------------------------------------------------- 内核解析器的移植（差分对照用）
#   udp.rs:163-204 parse_frame / ipv6.rs:246-279 parse_udp6_frame / ndp.rs:200-248 parse_nd
#   这三段按源码逐行移植；下标访问换成"先判长度再取"，与源码里的长度检查顺序一致。
class StrictOOB(Exception):
    pass


def S(f, i):
    if not (0 <= i < len(f)):
        raise StrictOOB(i)
    return f[i]


def Sslice(f, a, b):
    if a < 0 or b > len(f) or a > b:
        raise StrictOOB((a, b))
    return bytes(f[a:b])


def k_parse_frame(frame):
    if len(frame) < 14 + 20 + 8: return None
    if Sslice(frame, 12, 14) != b"\x08\x00": return None
    ip = 14
    if S(frame, ip) >> 4 != 4: return None
    ihl = (S(frame, ip) & 0x0F) * 4
    if ihl < 20 or len(frame) < ip + ihl + 8: return None
    if S(frame, ip + 9) != 17: return None
    frag = (S(frame, ip + 6) << 8) | S(frame, ip + 7)
    if frag & 0x3FFF != 0: return None
    tot = (S(frame, ip + 2) << 8) | S(frame, ip + 3)
    if tot < ihl + 8 or ip + tot > len(frame): return None
    u = ip + ihl
    ulen = (S(frame, u + 4) << 8) | S(frame, u + 5)
    if ulen < 8 or u + ulen > ip + tot: return None
    src = (Sslice(frame, ip + 12, ip + 16), (S(frame, u) << 8) | S(frame, u + 1))
    dst = (Sslice(frame, ip + 16, ip + 20), (S(frame, u + 2) << 8) | S(frame, u + 3))
    payload = Sslice(frame, u + 8, u + ulen)
    return (src, dst, payload)


def k_parse_udp6_frame(frame):
    if len(frame) < 14 + 40 + 8: return None
    if Sslice(frame, 12, 14) != b"\x86\xdd": return None
    ip = 14
    if S(frame, ip) >> 4 != 6: return None
    if S(frame, ip + 6) != 17: return None
    plen = (S(frame, ip + 4) << 8) | S(frame, ip + 5)
    if plen < 8 or ip + 40 + plen > len(frame): return None
    src = Sslice(frame, ip + 8, ip + 24)
    dst = Sslice(frame, ip + 24, ip + 40)
    u = ip + 40
    ulen = (S(frame, u + 4) << 8) | S(frame, u + 5)
    if ulen < 8 or ulen > plen: return None
    sp = (S(frame, u) << 8) | S(frame, u + 1)
    dp = (S(frame, u + 2) << 8) | S(frame, u + 3)
    return (src, dst, sp, dp, Sslice(frame, u + 8, u + ulen))


def k_parse_nd(frame):
    if len(frame) < 14 + 40 + 24: return None
    if Sslice(frame, 12, 14) != b"\x86\xdd": return None
    ip = 14
    if S(frame, ip) >> 4 != 6 or S(frame, ip + 6) != 58: return None
    if S(frame, ip + 7) != 255: return None
    plen = (S(frame, ip + 4) << 8) | S(frame, ip + 5)
    if plen < 24 or ip + 40 + plen > len(frame): return None
    m = ip + 40
    kind = S(frame, m)
    if kind not in (135, 136): return None
    src = Sslice(frame, ip + 8, ip + 24)
    dst = Sslice(frame, ip + 24, ip + 40)
    target_ = Sslice(frame, m + 8, m + 24)
    p, end = m + 24, m + plen
    lladdr = None
    while p + 2 <= end:
        ot, ol = S(frame, p), S(frame, p + 1) * 8
        if ol == 0 or p + ol > end: break
        if ot in (1, 2) and ol >= 8: lladdr = Sslice(frame, p + 2, p + 8)
        p += ol
    return (kind, src, dst, target_, lladdr)


# ---------------------------------------------------------------- 内核挂载点模型（socket.rs deliver_frame + fw.rs）
class FwState:
    def __init__(self):
        self.prog = None        # insns 列表（已验证）
        self.enabled = False
        self.gen = 0
        self.evaluated = self.accepted = self.dropped = self.faults = self.malformed = 0
        self.rejected = 0

    def load(self, b, enable):
        try:
            p = verify(b)
        except VErr:
            self.rejected += 1
            raise
        self.prog = p
        self.gen = (self.gen + 1) & 0xFFFFFFFF or 1
        if enable:
            self.enabled = True
        return self.gen

    def filter(self, pkt):
        if not self.enabled or self.prog is None:
            return True
        self.evaluated += 1
        try:
            v, _ = run_raw(self.prog, pkt)
        except Fault:
            self.faults += 1
            return True
        if v == "Accept":
            self.accepted += 1
            return True
        self.dropped += 1
        return False

    def active(self):
        return self.enabled and self.prog is not None

    def filter_icmp6_frame(self, f):
        r = parse_eth(f, DIR_IN)
        if r[0] == "Packet":
            return self.filter(r[1])
        if self.active():
            self.malformed += 1
            return False
        return True


def deliver_frame_model(f, fw, sockets):
    """返回 (族, 副作用列表)。`sockets` = 绑定的端口集合；副作用记录 enqueue / ndp。
    与 socket.rs:493-541 的分支结构一一对应；`fw=None` 表示不带 fw 特性的原函数。"""
    eff = []
    if len(f) >= 14 and f[12:14] == b"\x86\xdd":
        if len(f) > 20 and f[20] == 58:
            if fw is not None and "hook_skip_ndp" not in MUT:
                if not fw.filter_icmp6_frame(f):
                    return 0, eff
            nd = k_parse_nd(f)
            eff.append(("ndp", nd is not None))
            return 6, eff
        r = k_parse_udp6_frame(f)
        if r is not None:
            src, dst, sp, dp, payload = r
            if "hook_after_enqueue" in MUT:
                ok = dp in sockets and dp != 0
                if ok: eff.append(("enq", dp, payload))
                if fw is not None: fw.filter(udp6(src, dst, sp, dp))
                return (6 if ok else 0), eff
            if fw is not None and not fw.filter(udp6(src, dst, sp, dp)):
                return 0, eff
            if dp in sockets and dp != 0:
                eff.append(("enq", dp, payload))
                return 6, eff
        return 0, eff
    if len(f) >= 14 and f[12:14] == b"\x08\x00":
        r = k_parse_frame(f)
        if r is not None:
            (sip, sp), (dip, dp), payload = r
            if "hook_after_enqueue" in MUT:
                ok = dp in sockets and dp != 0
                if ok: eff.append(("enq", dp, payload))
                if fw is not None: fw.filter(udp4(sip, dip, sp, dp))
                return (4 if ok else 0), eff
            if fw is not None and not fw.filter(udp4(sip, dip, sp, dp)):
                return 0, eff
            if dp in sockets and dp != 0:
                eff.append(("enq", dp, payload))
                return 4, eff
        return 0, eff
    return 0, eff


# ---------------------------------------------------------------- 帧构造（移植 udp.rs build_frame / ipv6.rs build_udp6_frame / ndp.rs build_ns 的布局）
def build_udp4(src_ip, dst_ip, sp, dp, payload, ihl_words=5):
    opts = bytes((ihl_words - 5) * 4)
    ulen = 8 + len(payload)
    tot = ihl_words * 4 + ulen
    ip = bytes([0x40 | ihl_words, 0]) + tot.to_bytes(2, "big") + b"\x00\x00\x40\x00" + bytes([64, 17, 0, 0]) + bytes(src_ip) + bytes(dst_ip) + opts
    udp = sp.to_bytes(2, "big") + dp.to_bytes(2, "big") + ulen.to_bytes(2, "big") + b"\x00\x00" + payload
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + udp


def build_udp6(src, dst, sp, dp, payload):
    ulen = 8 + len(payload)
    ip = b"\x60\x00\x00\x00" + ulen.to_bytes(2, "big") + bytes([17, 64]) + bytes(src) + bytes(dst)
    udp = sp.to_bytes(2, "big") + dp.to_bytes(2, "big") + ulen.to_bytes(2, "big") + b"\x00\x00" + payload
    return b"\x33" * 6 + b"\x04" * 6 + b"\x86\xdd" + ip + udp


def build_nd(src, dst, kind, target_, mac=b"\x02\x00\x00\x00\x00\x02", with_opt=True):
    body = bytes([kind, 0, 0, 0, 0, 0, 0, 0]) + bytes(target_)
    if with_opt:      # DAD 的 NS 不带源链路层地址选项（RFC 4862 §5.4.2）⇒ plen=24、帧长 78
        body += bytes([1 if kind == 135 else 2, 1]) + mac
    ip = b"\x60\x00\x00\x00" + len(body).to_bytes(2, "big") + bytes([58, 255]) + bytes(src) + bytes(dst)
    return b"\x33" * 6 + mac + b"\x86\xdd" + ip + body
