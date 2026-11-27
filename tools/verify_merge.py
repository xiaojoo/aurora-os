#!/usr/bin/env python3
"""Aurora OS 合入后验证脚本（S3 补丁 + S4 合入）。

用法（在仓库根目录，Windows 控制台务必带 UTF-8，见 AGENTS.md）：
    set PYTHONIOENCODING=utf-8
    set PYTHONUTF8=1
    python tools/verify_merge.py            # 全部步骤
    python tools/verify_merge.py --static   # 只跑不需要工具链的静态检查
    python tools/verify_merge.py --stop     # 遇到第一个失败就停

分三层，**每层通过才有资格进下一层**：
  L0 静态自检（纯 Python，无需 Rust）：文件在不在、锚点对不对、行尾、括号配平、偏移表自洽。
  L1 宿主机：cargo test -p host-tcp / host-initramfs；cargo build 用户态 shell。
  L2 仓库门禁：aurora.py build / check(21 道) / ktests / test。

本脚本只是把你本来要手敲的命令串起来并给出结论，**它不替代阅读报错**。
输出末尾打印 PASS/FAIL 汇总，并把完整日志写入 build/verify-merge.log。
"""
import os, re, subprocess, sys, time, hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
STATIC_ONLY = "--static" in sys.argv
STOP = "--stop" in sys.argv
LOG = os.path.join(ROOT, "build", "verify-merge.log")
os.makedirs(os.path.dirname(LOG), exist_ok=True)
results = []

def log(s):
    print(s)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(s + "\n")

def rd(p):
    with open(p, encoding="utf-8", newline="") as f:
        return f.read()

def record(name, ok, detail=""):
    results.append((name, ok, detail))
    log(("[PASS] " if ok else "[FAIL] ") + name + (("  -- " + detail) if detail else ""))
    if not ok and STOP:
        summary(); sys.exit(1)

def run(name, cmd, timeout=3600):
    log("\n$ " + " ".join(cmd))
    t0 = time.time()
    try:
        p = subprocess.run(cmd, env=ENV, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
    except FileNotFoundError:
        record(name, False, "命令不存在：" + cmd[0]); return None
    except subprocess.TimeoutExpired:
        record(name, False, "超时"); return None
    out = (p.stdout or "") + (p.stderr or "")
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(out + "\n")
    tail = "\n".join(out.strip().splitlines()[-25:])
    record(name, p.returncode == 0, "%.0fs rc=%d" % (time.time() - t0, p.returncode))
    if p.returncode != 0:
        log("--- 末 25 行 ---\n" + tail + "\n----------------")
    return out

# ----------------------------------------------------------------- L0 静态
def l0():
    log("\n===== L0 静态自检 =====")
    need = [
        "crates/host-tcp/src/cc.rs", "crates/host-tcp/src/sack.rs", "crates/host-tcp/src/cookie.rs",
        "crates/host-tcp/src/isn.rs", "kernel/src/network/isn_source.rs", "kernel/src/ktests/net/isn.rs",
        "docs/adr/ADR-266-网络安全一-拥塞控制SACK-cookie-ISN.md",
        "user/shell/src/redir.rs", "user/runtime/src/sync.rs",
    ]
    miss = [p for p in need if not os.path.exists(p)]
    record("L0.1 新增文件齐全", not miss, ",".join(miss))

    # 括号配平（粗检；字符串/注释里的括号会有噪声，只当提示）
    for p in ["user/shell/src/main.rs", "user/runtime/src/lib.rs", "user/shell/src/registry.rs",
              "kernel/src/network/socket.rs", "kernel/src/network/isn_source.rs", "kernel/src/ktests/net/isn.rs"]:
        t = rd(p)
        t2 = re.sub(r'//[^\n]*', '', t)
        t2 = re.sub(r'"(?:\\.|[^"\\])*"', '""', t2)
        b = (t2.count("{") - t2.count("}"), t2.count("(") - t2.count(")"), t2.count("[") - t2.count("]"))
        record("L0.2 括号配平 " + p, b == (0, 0, 0), str(b))

    # 行尾约定（AGENTS.md）：aurora.py / make_fat32_mem.py 必须 CRLF
    for p in ["tools/aurora.py", "tools/make_fat32_mem.py"]:
        if os.path.exists(p):
            t = rd(p); lf = t.count("\n") - t.count("\r\n")
            record("L0.3 CRLF 保持 " + p, lf == 0, "裸 LF 行数=%d" % lf)
    t = rd("kernel/src/sched/user.rs")
    record("L0.3b user.rs 行尾未被打乱", (t.count("\n") - t.count("\r\n")) in (0, t.count("\n")),
           "CRLF=%d" % t.count("\r\n"))

    # shell 重定向错误消息 blob 与偏移表自洽（手写偏移最易错）
    m = rd("user/shell/src/main.rs")
    mb = re.search(r'static RMSGS: \[u8; (\d+)\] = \*b"(.*?)";', m, re.S)
    ok = False; det = "未找到 RMSGS"
    if mb:
        n = int(mb.group(1)); body = mb.group(2).encode().decode("unicode_escape").encode("latin1")
        rm = re.findall(r'const RM_[A-Z]+: \(usize, usize\) = \((\d+),\s*(\d+)\);', m)
        pairs = [tuple(map(int, x)) for x in rm]
        lines = body.split(b"\n")[:-1]
        exp = []; off = 0
        for l in lines:
            exp.append((off, len(l) + 1)); off += len(l) + 1
        ok = (n == len(body)) and pairs == exp
        det = "blob=%d 声明=%d 偏移表%s" % (len(body), n, "一致" if pairs == exp else "不一致 期望%s 实际%s" % (exp, pairs))
    record("L0.4 RMSGS 偏移表自洽", ok, det)

    # MSGS 主 blob：声明长度必须等于实际字节数（我没动它，但这是最容易炸的东西）
    mm = re.search(r'static MSGS: \[u8; (\d+)\] = \*b"(.*?)";', m, re.S)
    if mm:
        body = mm.group(2).encode().decode("unicode_escape").encode("latin1", "ignore")
        record("L0.5 MSGS 声明长度", int(mm.group(1)) == len(mm.group(2).encode().decode("unicode_escape").encode("utf-8")),
               "声明=%s" % mm.group(1))

    # S4 接线点都在
    s = rd("kernel/src/network/socket.rs")
    checks = {
        "socket: create 用 legacy_isn 占位": "isn_source::legacy_isn(slot as u16" in s,
        "socket: 主动端 isn_for": "isn_source::isn_for(lip, lp, rip, rp, slot, gen)" in s,
        "socket: 被动端 isn_for_syn": "isn_for_syn" in s,
        "socket: accept 不再 +0x1000": "wrapping_add(0x1000)" not in s,
        "network/mod.rs 导出 isn_source": "pub mod isn_source;" in rd("kernel/src/network/mod.rs"),
        "main.rs 播种 init_secret": "isn_source::init_secret()" in rd("kernel/src/main.rs"),
        "kernel/Cargo.toml 依赖 host-tcp": "host-tcp" in rd("kernel/Cargo.toml"),
        "user.rs UDP 端口随机化": "isn_source::ephemeral(" in rd("kernel/src/sched/user.rs"),
        "ktests/net 注册 isn": "mod isn;" in rd("kernel/src/ktests/net/mod.rs"),
        "host-tcp lib 导出 4 模块": all(("pub mod %s;" % k) in rd("crates/host-tcp/src/lib.rs") for k in ("cc", "sack", "cookie", "isn")),
        "isn_source 复用 host_tcp::isn::isn": "host_tcp::isn::isn(" in rd("kernel/src/network/isn_source.rs"),
        "shell 已调用 redir::strip": "redir::strip(" in m,
        "shell 已调用 overwrite_file/append_file": "rt::overwrite_file(" in m and "rt::append_file(" in m,
    }
    for k, v in checks.items():
        record("L0.6 " + k, v)

    # 变异存活检查：这些字符串若出现，说明旧的坏写法还在
    def code_only(t):  # 去掉 // 注释（含 /// //!），避免文档里“曾经写错过”的说明被误报
        return "\n".join(l.split("//")[0] for l in t.split("\n"))
    bad = {"socket.rs 残留旧 iss 公式": "0x1000_0000u32.wrapping_add((slot as u32) << 8)" in code_only(s),
           "ktest 残留不存在的 arch::x86_64::tsc": "arch::x86_64::tsc" in code_only(rd("kernel/src/ktests/net/isn.rs")),
           "isn_source 残留不存在的 time::now_us": "crate::time::now_us" in code_only(rd("kernel/src/network/isn_source.rs"))}
    for k, v in bad.items():
        record("L0.7 " + k, not v)


    # ---- 防火墙（ADR-267）接线 ----
    fwc = {
        "host-fw crate 文件齐全": all(os.path.exists("crates/host-fw/src/%s.rs" % k) for k in ("lib","insn","verify","exec","packet","rules","parse","tests")),
        "fw.rs / ktest 存在": os.path.exists("kernel/src/network/fw.rs") and os.path.exists("kernel/src/ktests/net/fw.rs"),
        "sync: RANK_FW=42 且名字表有 FW": "RANK_FW: LockRank = LockRank(42)" in rd("kernel/src/sync/mod.rs") and '42 => "FW"' in rd("kernel/src/sync/mod.rs"),
        "sync: 无两把锁同为 41": len(re.findall(r"LockRank\(41\)", rd("kernel/src/sync/mod.rs"))) == 1,
        "lock-order.md 有 RANK_FW 42": re.search(r"`RANK_FW`\s*\|\s*42\s*\|", rd("docs/architecture/lock-order.md")) is not None,
        "user.rs: 81/82 常量+实现+臂": all(k in rd("kernel/src/sched/user.rs") for k in ("SYS_FW_LOAD: u64 = 81", "SYS_FW_CTL: u64 = 82", "fn sys_fw_load", "fn sys_fw_ctl", "SYS_FW_LOAD => nosys()", "SYS_FW_CTL => nosys()")),
        "socket.rs: 3 个挂载点": rd("kernel/src/network/socket.rs").count("network::fw::filter") == 3,
        "kernel/Cargo.toml: fw 特性 + optional host-fw": 'fw = ["handles", "dep:host-fw"]' in rd("kernel/Cargo.toml") and "host-fw" in rd("kernel/Cargo.toml") and "optional = true" in rd("kernel/Cargo.toml"),
        "根 Cargo members 含 host-fw": "crates/host-fw" in rd("Cargo.toml"),
        "crates.toml 登记 host-fw(含 license.pending)": "crate.host-fw" in rd("docs/architecture/crates.toml") and "license.pending.host-fw" in rd("docs/architecture/crates.toml"),
        "capacity-baseline 有 MAX_FW_INSNS": "MAX_FW_INSNS" in rd("docs/architecture/capacity-baseline.toml"),
        "module-interfaces 有 fw:: 与 isn_source::": "fw::filter" in rd("docs/architecture/module-interfaces.toml") and "isn_source::isn_for" in rd("docs/architecture/module-interfaces.toml"),
        "runtime 有 fw_call/fw_load/fw_ctl/fw_stats": all(k in rd("user/runtime/src/lib.rs") for k in ("fn fw_call", "pub fn fw_load", "pub fn fw_ctl", "pub fn fw_stats")),
        "host-svc crate 与模型齐全": all(os.path.exists(os.path.join(ROOT, x)) for x in ("crates/host-svc/Cargo.toml","crates/host-svc/src/lib.rs","crates/host-svc/src/tests.rs","tools/svc-verify/svc_model.py")),
        "host-svc 已登记(members+crates.toml+license)": "crates/host-svc" in rd("Cargo.toml") and "crate.host-svc" in rd("docs/architecture/crates.toml") and "license.pending.host-svc" in rd("docs/architecture/crates.toml"),
        "host-svc Rust 与 Python 模型测试数一致": len(re.findall(r"#\[test\]", rd("crates/host-svc/src/tests.rs"))) == len(re.findall(r"^def (t_\w+)", rd("tools/svc-verify/svc_model.py"), re.M)),
        "83 号 proc_reap：常量/实现/臂/封装/ktest/ADR": all([
            "SYS_PROC_REAP: u64 = 83" in rd("kernel/src/sched/user.rs"), "fn sys_proc_reap" in rd("kernel/src/sched/user.rs"),
            "SYS_PROC_REAP => sys_proc_reap(frame)" in rd("kernel/src/sched/user.rs"), "SYS_PROC_REAP => nosys()" in rd("kernel/src/sched/user.rs"),
            "syscall_abi(SYS_PROC_REAP" in rd("user/runtime/src/lib.rs"), "SYS_PROC_REAP: u64 = 83" in rd("user/runtime/src/lib.rs"),
            os.path.exists(os.path.join(ROOT, "kernel/src/ktests/sched/proc_reap.rs")), "mod proc_reap;" in rd("kernel/src/ktests/sched/mod.rs"),
            os.path.exists(os.path.join(ROOT, "docs/adr/ADR-270-proc_reap-用户态回收终止进程.md"))]),
        "proc_reap 已归还 fd 表（ADR-180 漏改的缺陷已修）": (
            "pub fn proc_reap_gen" in rd("kernel/src/sched/proc.rs") and
            "release_fd_table(fd_base, fd_bytes)" in rd("kernel/src/sched/proc.rs").split("fn proc_reap_inner")[1].split("pub fn proc_discard")[0] and
            "fd_cap.load" in rd("kernel/src/sched/proc.rs").split("fn proc_reap_inner")[1].split("pub fn proc_discard")[0]),
        "fault-reap-leak-fdtable 特性已声明": "fault-reap-leak-fdtable" in rd("kernel/Cargo.toml"),
        "ADR-267 存在且为 42": "RANK_FW = 42" in rd("docs/adr/ADR-267-最小防火墙第一期-UDP与NDP入站无状态过滤.md"),
        "ktests/net 注册 fw": 'feature = "fw"' in rd("kernel/src/ktests/net/mod.rs"),
    }
    for k, v in fwc.items():
        record("L0.9 " + k, v)
    # 两处 syscall 常量在内核与 runtime 必须同数（check-syscall-abi-arms 规则 1 对 fw_call 间接传参看不见，这里补一道）
    ku = rd("kernel/src/sched/user.rs"); rl = rd("user/runtime/src/lib.rs")
    same = all(re.search(r"pub const %s: u64 = (\d+);" % n, ku).group(1) == re.search(r"pub const %s: u64 = (\d+);" % n, rl).group(1) for n in ("SYS_FW_LOAD", "SYS_FW_CTL", "SYS_FILE_APPEND", "SYS_PROC_REAP"))
    record("L0.10 内核与 runtime 的 syscall 号一致(80/81/82/83)", same)
    # unsafe 登记自洽：total = U1+U2+U3+U4+U5+U6
    w = rd("docs/security/unsafe-whitelist.toml")
    sec = w[w.find("[unsafe-census]"):]
    sec = sec[:sec.find("\n[modules") if "\n[modules" in sec else len(sec)]
    nums = {k: int(v) for k, v in re.findall(r"^(total|U[1-6])\s*=\s*(\d+)", sec, re.M)}
    record("L0.11 unsafe 普查 total=ΣU1..U6", nums.get("total") == sum(nums.get("U%d" % i, 0) for i in range(1, 7)), str(nums))

    # 登记文件（check-crates / check-sbom 会读）
    ct = rd("docs/architecture/crates.toml")
    root = rd("Cargo.toml")
    for c in ("host-tcp", "host-initramfs"):
        record("L0.8 登记 " + c, ('crate.' + c) in ct and ('license.pending.' + c) in ct and ('crates/' + c) in root)

# ----------------------------------------------------------------- L1 宿主机
def l1():
    log("\n===== L1 宿主机测试 =====")
    run("L1.1 cargo test -p host-tcp", ["cargo", "test", "-p", "host-tcp"])
    run("L1.2 cargo test -p host-initramfs", ["cargo", "test", "-p", "host-initramfs"])
    run("L1.2b cargo test -p host-svc（ADR-269，应 17 个）", ["cargo", "test", "-p", "host-svc"])
    # 变异证红：每个特性打开后测试必须变红（rc != 0）。注意：这里"失败"才是期望结果。
    for feat in ("fault-svc-breaker-never-trips", "fault-svc-backoff-no-clamp", "fault-svc-parse-accept-dup"):
        run("L1.2c 变异 " + feat + "（期望测试红）", ["cargo", "test", "-p", "host-svc", "--features", feat])
        name, ok, det = results[-1]
        results[-1] = (name, not ok, "变异被抓到" if not ok else "**变异存活：测试没咬住**")
    run("L1.2d host-svc Python 等价模型", [sys.executable, "tools/svc-verify/svc_model.py"])
    log("提示：S4 README 声称 host-tcp 新增 26 个 #[test]（cc 8 / sack 8 / cookie 4 / isn 6）；S3 前基线 23 个。")
    log("      合计应 ≥49。若少于此数，说明 lib.rs 里 `mod tests;` 没覆盖新模块或测试没编进来。")
    log("      L1.3 shell 的 redir 单测（user/shell 是 no_std 二进制，不能直接 cargo test）：")
    log("      建议把 user/shell/src/redir.rs 临时拷到 /tmp 下建一个 std crate 跑 `cargo test`，")
    log("      其 #[cfg(test)] 用例使用 std::vec::Vec，需 `extern crate std;` 才能在 no_std 下编。")

# ----------------------------------------------------------------- L2 仓库门禁
def l2():
    log("\n===== L2 仓库门禁（需 Rust 1.99.1 + QEMU + OVMF）=====")
    run("L2.1 aurora build（默认）", [sys.executable, "tools/aurora.py", "build"])
    run("L2.2 aurora build --features fs-rw", [sys.executable, "tools/aurora.py", "build", "--features", "fs-rw"])
    run("L2.3 aurora build --features fs-rw,fs-dirloc", [sys.executable, "tools/aurora.py", "build", "--features", "fs-rw,fs-dirloc"])
    o = run("L2.4 aurora check（应 21/21）", [sys.executable, "tools/aurora.py", "check"])
    if o is not None:
        n = len(re.findall(r"(?m)^\[ ok \]", o))
        record("L2.4b check 21/21", n == 21, "实际 %d/21" % n)
    run("L2.5 aurora ktests（只核注册表，不执行 QEMU）", [sys.executable, "tools/aurora.py", "ktests"])
    run("L2.5b QEMU 防火墙档", [sys.executable, "tools/aurora.py", "run", "--features", "fw", "--timeout", "180"])
    run("L2.5c QEMU 防火墙+可写卷档", [sys.executable, "tools/aurora.py", "run", "--features", "fw,fs-rw", "--timeout", "180"])
    run("L2.5d proc_reap 漏还 fd 表变异（期望红）", [sys.executable, "tools/aurora.py", "run", "--features", "fault-reap-leak-fdtable", "--timeout", "180"])
    name, ok, det = results[-1]
    results[-1] = (name, not ok, "变异被抓到" if not ok else "**变异存活：测试没咬住**")
    o = run("L2.6 aurora test（判定表，预期 106/106 符合）", [sys.executable, "tools/aurora.py", "test"], timeout=7200)
    if o is not None:
        rows = re.findall(r"(?m)^.*: .* -> (符合|不符合)\s*$", o)
        record("L2.6b 判定表", bool(rows) and "不符合" not in rows,
               "符合=%d 不符合=%d" % (rows.count("符合"), rows.count("不符合")))
    log("提示：判定表基线仍是 §593 的 106 行；S4 的 isn/proc_reap 在既有档内，fw 档由 L2.5b/L2.5c 单独执行。")
    log("      AGENTS.md 取证纪律：残余偶发（t_irq_ahci / t_user_roundtrip 等）用同 ELF 重跑区分，不要为一次红就改代码。")

# ----------------------------------------------------------------- 手测清单
MANUAL = """
===== 手测清单（QEMU 串口 shell 里逐条敲）=====
S3 重定向（期望见括号）：
  echo hi > a.txt         （无输出）
  cat a.txt               （hi，尾行 bytes=3）
  echo x >> a.txt         （无输出）
  cat a.txt               （hi\nx）
  cat < a.txt             （cat 无参数时读 stdin；若 cat 不支持 stdin 请改用 grep/wc：grep h < a.txt）
  wc < a.txt              （lines=2 …）
  echo hi > a.txt         （再次覆盖：cat 应只有 hi）
  echo a > b*c            （redirect: write failed，且 a.txt 内容不受影响）
  ls | grep a > r.txt     （末段重定向 OK）
  ls > r.txt | wc         （redirect: not allowed before pipe）
  echo hi >               （redirect: empty target）
  cat < nosuch            （redirect: read failed）
S4 ISN：
  串口日志应出现 'rand: 熵源 N 路成功'，且**没有** 'isn: secret 未取得'；
  ktests 里 isn-passive/isn-active/isn-mono/ephemeral 四行 ⇒ true；若出现 '跳过——rand 未播种' 则本组不算通过。
VMware（见 docs 说明）：
  firmware = "efi"；磁盘 NVMe 或 SATA；无 virtio——virtio-blk/net 在 VMware 下不可用。
"""

def summary():
    log("\n===== 汇总 =====")
    p = sum(1 for _, ok, _ in results if ok); f = len(results) - p
    for n, ok, d in results:
        if not ok: log("  FAIL " + n + ("  -- " + d if d else ""))
    log("PASS=%d FAIL=%d  日志：%s" % (p, f, LOG))
    log(MANUAL)

if __name__ == "__main__":
    open(LOG, "w", encoding="utf-8").close()
    l0()
    if not STATIC_ONLY:
        l1(); l2()
    summary()
    sys.exit(1 if any(not ok for _, ok, _ in results) else 0)
