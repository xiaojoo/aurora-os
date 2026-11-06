"""可续传、分块、带校验的下载器（开发工具，不进内核 TCB）。

为什么要有它：weilnetz 的 QEMU Windows 包 206 MB，本机单连接约 130 KB/s，
且每块下载到 ~16 MB 左右就被服务器掐断。上一版脚本不检查完整性就 cat 合并，
结果拿 155 MB 的残包当安装包——sha512 不匹配才暴露出来。

规则：
  * 每个分块记录期望区间，缺多少补多少（用 HTTP Range 续传）
  * **所有**分块都到齐才合并；合并后必须比对 sha512，不比对就报错退出
  * 任何一块补 20 轮仍不完整就失败退出，不无限重试

用法：
    python tools/fetch.py --url URL --out .tools/qemu-setup.exe \
        --sha512 HASH --size 206615928 [--chunks 10]
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import subprocess
import sys
import time

# Windows 控制台是 GBK，✓ 这类字符会抛 UnicodeEncodeError：
# 实测就是它让一次**成功的**下载以退出码 1 收场，把好消息报成了坏消息。
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        _s.reconfigure(encoding="utf-8", errors="replace")

MAX_ROUNDS = 20


def part_bounds(total: int, chunks: int) -> list[tuple[int, int]]:
    out = []
    for i in range(chunks):
        s = i * total // chunks
        e = (i + 1) * total // chunks - 1 if i < chunks - 1 else total - 1
        out.append((s, e))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sha512", required=True)
    ap.add_argument("--size", type=int, required=True)
    ap.add_argument("--chunks", type=int, default=10)
    a = ap.parse_args()

    out = pathlib.Path(a.out)
    work = out.with_suffix(out.suffix + ".parts")
    work.mkdir(parents=True, exist_ok=True)
    bounds = part_bounds(a.size, a.chunks)

    for rnd in range(1, MAX_ROUNDS + 1):
        # 回收残留 tmp：它是某个区间从起点开始的连续前缀，扔了就等于白下几 MB
        for p in sorted(work.glob("part.*.tmp")):
            target = work / p.name[: -len(".tmp")]
            tsize, psize = (target.stat().st_size if target.exists() else 0), p.stat().st_size
            i = int(target.name.split(".")[1])
            s, e = bounds[i]
            expect = e - s + 1
            if psize == 0:
                p.unlink()
                continue
            # 只有“目标已有长度 + tmp 长度 <= 该块应有长度”才是合法续接；
            # 否则说明来源不可追溯，宁可丢弃（损坏的镜像比慢 20 分钟更糟）
            if tsize + psize > expect:
                print(f"  丢弃 {p.name}：{tsize}+{psize} 超过该块应有 {expect}")
                p.unlink()
                continue
            with open(target, "ab") as f:
                f.write(p.read_bytes())
            print(f"  回收 {p.name} -> {target.name}（现有 {target.stat().st_size}/{expect}）")
            p.unlink()

        pending = []
        for i, (s, e) in enumerate(bounds):
            p = work / f"part.{i:02d}"
            want = e - s + 1
            have = p.stat().st_size if p.exists() else 0
            if have >= want:
                continue
            pending.append((i, s, e, have, want, p))
        if not pending:
            break
        print(f"[轮 {rnd}] 待补 {len(pending)} 块，合计 {sum(w - h for _, _, _, h, w, _ in pending)/1024/1024:.1f} MiB")
        # 并发补块：串行时单连接会被服务器拖到 12 KB/s，而限速是按 IP 算的，
        # 多连接才能把可用带宽吃满。--speed-limit/--speed-time 让 stall 的连接尽早断开重试。
        def one(job):
            i, s, e, have, want, p = job
            from_ = s + have
            # 注意：不能用 p.with_suffix(".tmp") —— "part.00" 的后缀是 ".00"，
            # 那会得到 part.tmp，十个分块共用同一个临时文件，并发时互相覆盖
            tmp = p.with_name(p.name + ".tmp")
            # 不用 --speed-limit/--speed-time：本机到该站每条连接本来就只有十几 KB/s，
            # 那条判据会把“慢但真实在前进”的连接掐掉，而掐掉就丢弃整个 tmp（最多 240 秒的量），
            # 净效果是倒退。只保留总时长上限。
            cmd = ["curl", "-sS", "--fail", "--max-time", "900",
                   "-r", f"{from_}-{e}", "-o", str(tmp), a.url]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                tmp.unlink(missing_ok=True)
                return i, 0, f"请求失败 rc={r.returncode} {r.stderr.strip()[:80]}"
            got = tmp.stat().st_size
            expect = e - from_ + 1
            if got != expect:
                tmp.unlink(missing_ok=True)
                return i, got, f"长度 {got} != 期望 {expect}"
            with open(p, "ab") as f:
                f.write(tmp.read_bytes())
            tmp.unlink()
            return i, p.stat().st_size, ""

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=min(8, len(pending))) as ex:
            for i, n, note in ex.map(one, pending):
                print(f"   part.{i:02d}: {note if note else f'累计 {n} 字节'}")
        time.sleep(1)
    else:
        print(f"{MAX_ROUNDS} 轮后仍未完整，放弃")
        return 1

    # 合并
    with open(out, "wb") as f:
        for i in range(a.chunks):
            p = work / f"part.{i:02d}"
            if not p.exists():
                print(f"缺 part.{i:02d}")
                return 1
            f.write(p.read_bytes())
    size = out.stat().st_size
    h = hashlib.sha512(out.read_bytes()).hexdigest()
    print(f"合并完成 {size} 字节（期望 {a.size}）")
    if size != a.size:
        print("大小不对，判失败")
        return 1
    if h != a.sha512:
        print("sha512 不匹配")
        print("  got =", h)
        print("  want=", a.sha512)
        return 1
    print("sha512 匹配 ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
