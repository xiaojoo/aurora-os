#!/usr/bin/env python3
"""host-svc 的 Python 等价移植 + 变异驱动。

**这证明的是移植，不是 Rust。** Rust 与移植之间可能有我没发现的偏差；以本机 `cargo test -p host-svc` 为准。
用法：python tools/svc-verify/svc_model.py     （纯 Python，无依赖；写 results.json）
"""
import json, random, sys, os

NAME_MAX, EXEC_MAX, BACKOFF_MAX, RING_MAX, WINDOW_MS = 16, 64, 8, 16, 60_000
FLAGS = {"breaker_never_trips": False, "backoff_no_clamp": False, "parse_accept_dup": False}

class ParseErr(Exception):
    def __init__(self, k): self.k = k
RESTART = ("never", "on-failure", "always")

def trim(b):
    s, e = 0, len(b)
    while s < e and b[s] in b" \t\r": s += 1
    while e > s and b[e-1] in b" \t\r": e -= 1
    return b[s:e]

def parse_u32(v):
    if not v: raise ParseErr("BadNumber")
    acc = 0
    for c in v:
        if not (48 <= c <= 57): raise ParseErr("BadNumber")
        acc = acc*10 + (c-48)
        if acc > 0xFFFFFFFF: raise ParseErr("BadNumber")
    return acc

def parse_unit(data):
    if 0 in data: raise ParseErr("BadBytes")
    try: data.decode("utf-8")
    except UnicodeDecodeError: raise ParseErr("BadBytes")
    u = dict(name=b"", exec=b"", restart="on-failure", backoff=[], max=5)
    seen = dict(name=False, exec=False, restart=False, backoff=False, max=False)
    def dup(k):
        if seen[k] and not FLAGS["parse_accept_dup"]: raise ParseErr("DupKey")
        seen[k] = True
    def put(v, lim):
        if not v or len(v) > lim: raise ParseErr("BadValue")
        return v
    for raw in data.split(b"\n"):
        line = trim(raw)
        if not line or line[:1] == b"#": continue
        eq = line.find(b"=")
        if eq < 0: raise ParseErr("NoEquals")
        key, val = trim(line[:eq]), trim(line[eq+1:])
        if key == b"name": dup("name"); u["name"] = put(val, NAME_MAX)
        elif key == b"exec": dup("exec"); u["exec"] = put(val, EXEC_MAX)
        elif key == b"restart":
            dup("restart")
            s = val.decode()
            if s not in RESTART: raise ParseErr("BadValue")
            u["restart"] = s
        elif key == b"backoff_ms":
            dup("backoff"); n = 0; lst = []
            for part in val.split(b","):
                v = parse_u32(trim(part))
                if n >= BACKOFF_MAX: raise ParseErr("BadBackoff")
                lst.append(v); n += 1
            if n == 0: raise ParseErr("BadBackoff")
            u["backoff"] = lst
        elif key == b"max_per_minute":
            dup("max"); v = parse_u32(val)
            if v > RING_MAX: raise ParseErr("TooManyPerMinute")
            u["max"] = v
        else: raise ParseErr("UnknownKey")
    if not u["name"] or not u["exec"]: raise ParseErr("Missing")
    if not u["backoff"]: u["backoff"] = [200, 1000, 5000]
    return u

def exit_from_code(code):
    """Rust: Exit::from_code —— 0 ⇒ Clean(False 失败)，其余 ⇒ Failed。返回 failed 布尔。"""
    return code != 0

def next_delay(tries, table):
    if FLAGS["backoff_no_clamp"]:
        return table[tries] if tries < len(table) else None
    if tries < len(table): return table[tries]
    return table[-1] if table else None

class Breaker:
    def __init__(self): self.ts = []
    def record(self, now):
        keep = [t for t in self.ts if max(now - t, 0) < WINDOW_MS]   # saturating_sub
        if len(keep) > RING_MAX: keep = keep[1:]
        keep.append(now); self.ts = keep
        return len(keep)

def on_exit(u, br, tries, failed, now):
    n = br.record(now)
    tripped = False if FLAGS["breaker_never_trips"] else n > u["max"]
    if tripped: return ("MarkFailed",)
    want = u["restart"] == "always" or (u["restart"] == "on-failure" and failed)
    if not want: return ("None",)
    d = next_delay(tries, u["backoff"])
    return ("RestartAfter", d) if d is not None else ("None",)

def mk(max_, restart, table):
    return dict(name=b"a", exec=b"/A", restart=restart, backoff=list(table), max=max_)

# ----------------------------------------------------------- 测试（与 tests.rs 同名同形）
def t_parse_ok_roundtrip():
    u = parse_unit(b"name=httpd\nexec=/HTTPD.ELF\nrestart=on-failure\nbackoff_ms=200,1000,5000\nmax_per_minute=5\n")
    assert u["name"] == b"httpd" and u["exec"] == b"/HTTPD.ELF" and u["backoff"] == [200,1000,5000] and u["max"] == 5
def t_parse_defaults():
    u = parse_unit(b"name=a\nexec=/A.ELF\n"); assert u["restart"] == "on-failure" and u["backoff"] == [200,1000,5000] and u["max"] == 5
def t_parse_comments_crlf():
    u = parse_unit(b"# c\r\n\r\nname=a\r\n  exec = /A.ELF  "); assert u["name"] == b"a" and u["exec"] == b"/A.ELF"
def rej(data, kind):
    try: parse_unit(data)
    except ParseErr as e: assert e.k == kind, (data, e.k, kind); return
    raise AssertionError(("被接受了", data))
def t_parse_rejects():
    rej(b"name=a\nexec=/A\nname=b\n","DupKey"); rej(b"name=a\nexec=/A\nbogus=1\n","UnknownKey")
    rej(b"name=a\nexec=/A\nnoequals\n","NoEquals"); rej(b"name=a\n","Missing"); rej(b"exec=/A\n","Missing"); rej(b"","Missing")
    rej(b"name=\nexec=/A\n","BadValue"); rej(b"name=a\nexec=/A\nrestart=sometimes\n","BadValue")
    rej(b"name=a\nexec=/A\nmax_per_minute=x\n","BadNumber"); rej(b"name=a\nexec=/A\nmax_per_minute=99999999999\n","BadNumber")
    rej(b"name=a\nexec=/A\nmax_per_minute=17\n","TooManyPerMinute"); rej(b"name=a\0b\nexec=/A\n","BadBytes"); rej(bytes([0xff,0xfe]),"BadBytes")
def t_parse_boundaries():
    parse_unit(b"name="+b"x"*NAME_MAX+b"\nexec=/A\n"); rej(b"name="+b"x"*(NAME_MAX+1)+b"\nexec=/A\n","BadValue")
    parse_unit(b"name=a\nexec=/A\nbackoff_ms=1,2,3,4,5,6,7,8\n"); rej(b"name=a\nexec=/A\nbackoff_ms=1,2,3,4,5,6,7,8,9\n","BadBackoff")
    rej(b"name=a\nexec=/A\nbackoff_ms=\n","BadNumber"); parse_unit(b"name=a\nexec=/A\nmax_per_minute=16\n"); parse_unit(b"name=a\nexec=/A\nmax_per_minute=0\n")
def t_parse_never_panics():
    rnd = random.Random(0x12345678); alpha = b"name=exec/\n#, 0123456789.ELFabcdefgrstuvw\r\t\0\xff"
    for _ in range(30000):
        v = bytes(alpha[rnd.randrange(len(alpha))] for _ in range(rnd.randrange(80)))
        try: parse_unit(v)
        except ParseErr: pass
def t_backoff():
    t=[200,1000,5000]; assert [next_delay(i,t) for i in (0,1,2,3,2**32-1)]==[200,1000,5000,5000,5000]
    assert next_delay(0,[]) is None and next_delay(7,[42])==42
def t_breaker_strict():
    u=mk(3,"always",[10]); b=Breaker()
    for i in range(3): assert on_exit(u,b,i,True,1000+i)==("RestartAfter",10)
    assert on_exit(u,b,3,True,1003)==("MarkFailed",)
def t_breaker_window_edges():
    u=mk(1,"always",[10]); b=Breaker()
    assert on_exit(u,b,0,True,0)==("RestartAfter",10); assert on_exit(u,b,1,True,WINDOW_MS)==("RestartAfter",10)
    b2=Breaker(); on_exit(u,b2,0,True,0); assert on_exit(u,b2,1,True,WINDOW_MS-1)==("MarkFailed",)
def t_breaker_zero(): assert on_exit(mk(0,"always",[10]),Breaker(),0,True,5)==("MarkFailed",)
def t_breaker_backwards():
    u=mk(5,"always",[10]); b=Breaker(); on_exit(u,b,0,True,1_000_000); on_exit(u,b,1,True,5); assert len(b.ts)>=1
def t_breaker_ring_bounded():
    u=mk(RING_MAX,"always",[1]); b=Breaker()
    for i in range(1000): on_exit(u,b,0,True,i); assert len(b.ts)<=RING_MAX+1
def t_breaker_max_16_trips():
    u=mk(16,"always",[1]); b=Breaker()
    for i in range(16): assert on_exit(u,b,i,True,i)==("RestartAfter",1)
    assert on_exit(u,b,16,True,16)==("MarkFailed",)
def t_policy():
    for rst,failed,want in [("never",True,False),("never",False,False),("on-failure",True,True),("on-failure",False,False),("always",True,True),("always",False,True)]:
        assert (on_exit(mk(5,rst,[10]),Breaker(),0,failed,1)[0]=="RestartAfter")==want
def t_exit_from_code():
    assert exit_from_code(0) is False and exit_from_code(1) is True and exit_from_code(2**32-1) is True
def t_empty_table(): assert on_exit(mk(5,"always",[]),Breaker(),0,True,1)==("None",)
def t_storm():
    u=mk(5,"always",[1]); b=Breaker(); first=None
    for i in range(50):
        if on_exit(u,b,0,True,i)==("MarkFailed",) and first is None: first=i
    assert first==5 and on_exit(u,b,0,True,60)==("MarkFailed",)

TESTS=[v for k,v in sorted(globals().items()) if k.startswith("t_")]
def run_all():
    bad=[]
    for t in TESTS:
        try: t()
        except Exception as e: bad.append((t.__name__, repr(e)[:90]))
    return bad

if __name__=="__main__":
    out={"tests":len(TESTS)}
    out["baseline_failures"]=run_all()
    for flag in FLAGS:
        for k in FLAGS: FLAGS[k]=False
        FLAGS[flag]=True
        out["mutant_"+flag]=[n for n,_ in run_all()]
    for k in FLAGS: FLAGS[k]=False
    here=os.path.dirname(os.path.abspath(__file__))
    json.dump(out,open(os.path.join(here,"results.json"),"w",encoding="utf-8"),ensure_ascii=False,indent=1)
    print(json.dumps(out,ensure_ascii=False,indent=1))
    ok = not out["baseline_failures"] and all(out["mutant_"+f] for f in FLAGS)
    print("结论:", "基线全绿且每个变异都被至少一个测试抓到" if ok else "有问题：基线红或变异存活")
    sys.exit(0 if ok else 1)
