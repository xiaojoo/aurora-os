"""ESP 镜像的独立校验器：不 import esp_image，直接从字节按 FAT 规范重算。

存在的意义：生成器和它的 read_back 出自同一份假设，错会一起错。这里只信规范：
  * LFN 条目的 checksum 必须等于其 8.3 名按 FAT 规则算出的值——不对则 UEFI 驱动不认长名
  * LFN 序号必须从 1 连续递增，且**最大序号那一条带 0x40 位并出现在物理最前**
  * 簇链必须终止于 0xFFFF，且不能成环
  * 文件读出的字节数必须 >= 目录项里的大小

用法：python tools/validate_esp.py build/aurora.img
"""

from __future__ import annotations

import binascii
import struct
import sys

SECTOR = 512
ATTR_LFN, ATTR_DIR, ATTR_VOL = 0x0F, 0x10, 0x08
EOC = 0xFFFF


def checksum(sb: bytes) -> int:
    s = 0
    for b in sb:
        s = ((s >> 1) + (s << 8) + b) & 0xFF
    return s


def main(path: str) -> int:
    d = open(path, "rb").read()
    problems_all: list[str] = []

    # ---- GPT 头按 UEFI 布局逐字段核（字段顺序取自 limine.c 的 struct gpt_table_header）。
    # 之所以要逐字段断言：上一版校验器只验了签名和“我自己算的”头部 CRC，
    # 结果字段整体错位也照样“通过”——自己出题自己答，等于没有第二台仪器。
    g = d[512:512 + 92]
    if g[0:8] != b"EFI PART":
        print("不是 GPT 磁盘"); return 1
    fields = {
        "revision(=0x00010000)": (struct.unpack_from("<I", g, 8)[0], 0x00010000),
        "header_size(=92)": (struct.unpack_from("<I", g, 12)[0], 92),
        "my_lba(=1)": (struct.unpack_from("<Q", g, 24)[0], 1),
        "alternate_lba": (struct.unpack_from("<Q", g, 32)[0], len(d) // SECTOR - 1),
        "first_usable_lba(=34)": (struct.unpack_from("<Q", g, 40)[0], 34),
        "last_usable_lba": (struct.unpack_from("<Q", g, 48)[0], len(d) // SECTOR - 34),
        "partition_entry_lba(=2)": (struct.unpack_from("<Q", g, 72)[0], 2),
        "entry_count(=128)": (struct.unpack_from("<I", g, 80)[0], 128),
        "entry_size(=128)": (struct.unpack_from("<I", g, 84)[0], 128),
    }
    for name, (got, want) in fields.items():
        if got != want:
            problems_all.append(f"GPT 头 {name}: got={got} want={want}")
    if g[56:72] == b"\x00" * 16:
        problems_all.append("GPT 头 DiskGUID 全 0（偏移 56 处）")
    z = bytearray(g); z[16:20] = b"\x00\x00\x00\x00"
    if binascii.crc32(bytes(z)) & 0xFFFFFFFF != struct.unpack_from("<I", g, 16)[0]:
        problems_all.append("GPT 头 CRC32 自洽性不成立")
    arr = d[2 * SECTOR: 2 * SECTOR + 128 * 128]
    if binascii.crc32(arr) & 0xFFFFFFFF != struct.unpack_from("<I", g, 88)[0]:
        problems_all.append("分区条目数组 CRC32 不匹配")
    first_lba = struct.unpack_from("<Q", d, 1024 + 32)[0]
    print(f"GPT 头字段核对：{'通过' if not problems_all else '有问题'}")
    for p in problems_all:
        print("   ", p)
    esp = d[first_lba * SECTOR:]

    bpb = esp[:SECTOR]
    assert bpb[510:512] == b"\x55\xaa", "ESP 引导扇区签名不对"
    spc, reserved, nfats = bpb[13], struct.unpack_from("<H", bpb, 14)[0], bpb[16]
    root_entries, spf = struct.unpack_from("<H", bpb, 17)[0], struct.unpack_from("<H", bpb, 22)[0]
    tot = struct.unpack_from("<H", bpb, 19)[0] or struct.unpack_from("<I", bpb, 32)[0]
    fat = esp[reserved * SECTOR: (reserved + spf) * SECTOR]
    root_off = (reserved + nfats * spf) * SECTOR
    data_off = root_off + root_entries * 32
    problems: list[str] = []

    def fat_get(i: int) -> int:
        return struct.unpack_from("<H", fat, i * 2)[0]

    def chain_of(first: int) -> bytes:
        out, c, seen = bytearray(), first, set()
        while c not in (EOC, 0):
            if c in seen:
                problems.append(f"簇链成环 @ {first}")
                break
            if c < 2 or c * spc * SECTOR // SECTOR <= 1:
                problems.append(f"非法簇号 {c}")
                break
            seen.add(c)
            off = data_off + (c - 2) * spc * SECTOR
            out += esp[off: off + spc * SECTOR]
            c = fat_get(c)
        return bytes(out)

    def walk(off: int, prefix: str, depth: int) -> None:
        raw = esp[off:]
        i, pending = 0, []
        while i + 32 <= len(raw):
            e = raw[i: i + 32]
            if e[0] == 0x00:
                break
            i += 32
            if e[0] == 0xE5 or e[11] == ATTR_VOL:
                continue
            if e[11] == ATTR_LFN:
                pending.append(e)
                continue
            if pending:
                sb = e[0:11]
                want = checksum(sb)
                for k, le in enumerate(pending):
                    got = le[13]          # FAT 规范：checksum 是偏移 13 的单字节
                    if got != want:
                        problems.append(f"{prefix}{e[0:8].decode().strip()} 的 LFN 校验和不符：条目{k} got={got:#04x} want={want:#04x}")
                    seq = le[0] & 0x3F
                    if seq != k + 1:
                        problems.append(f"{prefix} LFN 序号不连续：第 {k} 条 seq={seq}")
                if not (pending[0][0] & 0x40):
                    problems.append(f"{prefix} 物理首条 LFN 未带 0x40 终止位")
                pending = []
            name = e[0:8].decode(errors="replace").strip() + "." + e[8:11].decode(errors="replace").strip()
            first = struct.unpack_from("<H", e, 26)[0]
            size = struct.unpack_from("<I", e, 28)[0]
            if e[11] & ATTR_DIR:
                if name.split(".")[0] in (".", ".."):
                    continue
                sub_off = data_off + (first - 2) * spc * SECTOR
                walk(sub_off, f"{prefix}{name.split('.')[0]}/", depth + 1)
            else:
                body = chain_of(first)
                if len(body) < size:
                    problems.append(f"{prefix}{name}: 簇链只有 {len(body)} 字节 < 目录项声明 {size}")
                else:
                    print(f"  {prefix}{name:16s} {size:>9} 字节  首簇={first}  校验通过")

    print(f"ESP: 起始 LBA {first_lba}, 每簇 {spc} 扇区, 保留 {reserved}, FAT {nfats}×{spf}, 根项 {root_entries}, 总扇区 {tot}")
    walk(root_off, "/", 0)
    all_problems = problems_all + problems
    if all_problems:
        print("\n发现问题：")
        for p in all_problems:
            print("   ", p)
        return 1
    print("\n独立校验通过（GPT 头逐字段 / LFN 校验和 / 序号 / 簇链 / 长度）")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "build/aurora.img"))
