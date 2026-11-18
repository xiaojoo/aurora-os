#!/usr/bin/env python3
# tools/pkg_manifest.py — C2 第一刀（ADR-138）：签名包的**包清单**。
#
# 双向对账（第二台仪器纪律）：
#   verify    读整盘镜像的包区，解析头（魔数/版本/覆盖名/载荷长），
#             载荷 SHA-256 与 kernel/fixtures/hello.elf 对账（包的载荷就是它的内容），
#             覆盖名/锚点与 esp_image.py 的常量对账（esp_image 是包的产地），
#             Lamport 签名复算必须过；全部通过后与 docs/pkg/manifest.json 逐字段比。
#   --expect  不读镜像，按 esp_image.py 的常量生成期望清单（build 之前 check 也能跑）。
#   --write   生成/更新 docs/pkg/manifest.json。
#   --tamper  把镜像包区的覆盖名一字节翻转（负样本注入工具，宿主机侧改盘；
#             verify 必须红，还原绿——与 S3 的"改盘一字节"同一形状）。
#
# 纪律：CRLF（与 tools/aurora.py、tools/make_fat32_mem.py 同一条）。
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import esp_image  # noqa: E402  — 包的产地（常量与 Lamport 实现的唯一来源）

SECTOR = esp_image.SECTOR
PKG_START_LBA = esp_image.PKG_START_LBA
PKG_SECTORS = esp_image.PKG_SECTORS
PKG_HDR_BYTES = esp_image.PKG_HDR_BYTES
PKG_BYTES = esp_image.PKG_BYTES
PATH_OFF = esp_image.PATH_OFF
PATH_BYTES = esp_image.PATH_BYTES
PKG_MAGIC = esp_image.PKG_MAGIC
PKG_VERSION = esp_image.PKG_VERSION
MANIFEST = ROOT / "docs" / "pkg" / "manifest.json"
HELLO = ROOT / "kernel" / "fixtures" / "hello.elf"


def read_pkg(img_path: Path) -> dict:
    data = img_path.read_bytes()
    off = PKG_START_LBA * SECTOR
    pkg = data[off : off + PKG_BYTES]
    if len(pkg) != PKG_BYTES:
        raise SystemExit(f"镜像太短：包区需要 {PKG_BYTES} 字节，只有 {len(pkg)}")
    magic = pkg[0:4]
    if magic != PKG_MAGIC:
        raise SystemExit(f"包区魔数不符：got={magic!r} want={PKG_MAGIC!r}")
    version = struct.unpack_from("<I", pkg, 4)[0]
    pk_len = struct.unpack_from("<I", pkg, 8)[0]
    sig_len = struct.unpack_from("<I", pkg, 12)[0]
    payload_len = struct.unpack_from("<I", pkg, 16)[0]
    path_field = pkg[PATH_OFF : PATH_OFF + PATH_BYTES]
    name = path_field.split(b"\x00")[0].decode("ascii")
    payload = pkg[esp_image.PAY_OFF : esp_image.PAY_OFF + payload_len]
    pk = pkg[esp_image.PK_OFF : esp_image.PK_OFF + pk_len]
    sig = pkg[esp_image.SIG_OFF : esp_image.SIG_OFF + sig_len]
    ok, reason = esp_image.pkg_verify(pkg)
    return {
        "magic": magic.decode("ascii"),
        "version": version,
        "covers": name,
        "payload_len": payload_len,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "anchor_sha256": hashlib.sha256(pk).hexdigest(),
        "pk_bytes": pk_len,
        "sig_bytes": sig_len,
        "signature_ok": ok,
        "signature_reason": reason,
    }


def expected() -> dict:
    """按 esp_image.py 的常量算期望（不读镜像）：包的产地自己说的那份。"""
    payload = HELLO.read_bytes() if HELLO.exists() else esp_image.package_payload()
    path_field = bytes(esp_image.PKG_PATH).ljust(esp_image.PATH_BYTES, b"\x00")
    pkg = esp_image.pkg_build(payload)
    return {
        "magic": esp_image.PKG_MAGIC.decode("ascii"),
        "version": esp_image.PKG_VERSION,
        "covers": esp_image.PKG_PATH.decode("ascii"),
        "payload_len": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "anchor_sha256": hashlib.sha256(esp_image.lamport_pk()).hexdigest(),
        "pk_bytes": esp_image.PK_BYTES,
        "sig_bytes": esp_image.SIG_BYTES,
        "signature_ok": True,
        "signature_reason": "ok",
    }


def compare(got: dict, want: dict) -> list[str]:
    bad = []
    for k, v in want.items():
        g = got.get(k)
        if k == "signature_reason" and g is None:
            g = ""
        if g != v:
            bad.append(f"{k}: 清单={g!r} 期望={v!r}")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description="C2 包清单：签名包与 manifest.json 的双向对账")
    ap.add_argument("cmd", nargs="?", default="verify", choices=["verify", "expect"])
    ap.add_argument("--img", type=Path, default=ROOT / "build" / "aurora.img")
    ap.add_argument("--out", type=Path, default=MANIFEST)
    ap.add_argument("--write", action="store_true", help="把 verify/expect 的结果写进 manifest.json")
    ap.add_argument("--tamper", action="store_true", help="把包区覆盖名一字节翻转（负样本注入）")
    args = ap.parse_args()

    if args.cmd == "expect":
        want = expected()
        if args.write:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(want, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"期望清单已写 {args.out}")
            return 0
        print(json.dumps(want, indent=2, sort_keys=True))
        return 0

    # verify
    if args.tamper:
        data = bytearray(args.img.read_bytes())
        off = PKG_START_LBA * SECTOR + PATH_OFF
        data[off] ^= 0x20  # 翻覆盖名第一个字节的第 5 位（'/' 与其它可打印字符互变）
        args.img.write_bytes(data)
        print(f"--tamper：已翻转包区覆盖名一字节（{args.img} offset {off}）")
        return 0

    got = read_pkg(args.img)
    want = expected()
    bad = compare(got, want)
    if bad:
        print("包区读数与产地期望不符：")
        for x in bad:
            print("   ", x)
        return 1

    if args.write or not MANIFEST.exists():
        MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST.write_text(json.dumps(got, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"清单已写 {MANIFEST}")
        return 0

    listed = json.loads(MANIFEST.read_text(encoding="utf-8"))
    bad = compare(listed, want)
    if bad:
        print("manifest.json 与产地期望不符：")
        for x in bad:
            print("   ", x)
        return 1
    print("pkg manifest ok：包区读数 = 产地期望 = 清单")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
