#!/usr/bin/env python3
"""S1 步骤 4：virtio 多扇区异步“未归因”的 **取证** 脚本。只读；不修改驱动、不应用任何补丁。

校正版手册 S1.2 步骤 4：先审阅本地 build/virtio-long-aborted.patch 与 QEMU trace，再决定是否重开实现。
本脚本做两件事：
  1) 用与 aurora.py 相同的 QEMU 参数跑一次，附加 -trace，把 1 扇区正常路径与失败路径的 trace 落盘；
  2) 对 trace 做对比摘要：是否出现 virtqueue_pop / virtio_blk_handle_* / virtio_blk_req_complete。
不得据此宣称“已归因”——只有 trace 证据与控制实验都齐备时，才在 BACKLOG 写结论。

用法：
  PYTHONIOENCODING=utf-8 PYTHONUTF8=1 python tools/virtio_trace.py --qemu "<与 aurora.py 一致的完整命令>" --out build/virtio-trace
"""
import argparse, os, re, shlex, subprocess, sys, pathlib

EVENTS = ["virtqueue_pop", "virtio_blk_handle_read", "virtio_blk_handle_write",
          "virtio_blk_req_complete", "virtqueue_fill", "virtqueue_flush", "virtio_notify"]

def run(qemu_cmd: str, out: pathlib.Path, tag: str, timeout: int) -> pathlib.Path:
    out.mkdir(parents=True, exist_ok=True)
    trace = out / f"{tag}.trace"
    events = out / "events.txt"
    events.write_text("\n".join(EVENTS) + "\n", encoding="utf-8")
    cmd = shlex.split(qemu_cmd) + ["-trace", f"events={events},file={trace}"]
    print("[run]", " ".join(cmd))
    try:
        subprocess.run(cmd, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        print("[warn] 超时终止（判定为 HANG 是正常取证结果，不要重跑整链凑绿）")
    return trace

def summarize(trace: pathlib.Path) -> dict:
    if not trace.exists():
        return {"missing": True}
    txt = trace.read_text(encoding="utf-8", errors="ignore")
    return {e: len(re.findall(rf"\b{e}\b", txt)) for e in EVENTS}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", required=True, help="完整 QEMU 命令行（与 aurora.py run 打印的一致）")
    ap.add_argument("--out", default="build/virtio-trace")
    ap.add_argument("--tag", default="run")
    ap.add_argument("--timeout", type=int, default=120)
    a = ap.parse_args()
    out = pathlib.Path(a.out)
    t = run(a.qemu, out, a.tag, a.timeout)
    s = summarize(t)
    print("[summary]", s)
    # 判读提示（不做结论）：
    if s.get("missing"):
        print("[hint] 没有 trace 文件：QEMU 可能不支持 -trace events=（检查构建选项 --enable-trace-backends=log）")
    elif s["virtqueue_pop"] == 0:
        print("[hint] 设备侧从未 pop：avail ring 对设备不可见 / 描述符链在 pop 前被拒 → 看 -d guest_errors 与 monitor `info mtree`")
    elif s["virtio_blk_handle_read"] + s["virtio_blk_handle_write"] == 0:
        print("[hint] 有 pop 但未进 handle_*：请求头/描述符布局可能被覆盖 → 对比 1 扇区与 2 扇区的 req 字节")
    else:
        print("[hint] 设备已处理：问题可能在 guest 侧完成判据（used_len/状态字）")
    print("[note] 这只是取证摘要，不是归因结论。")

if __name__ == "__main__":
    sys.exit(main())
