"""ESP 镜像的独立校验器：不 import esp_image，直接从字节按 FAT 规范重算。

存在的意义：生成器和它的 read_back 出自同一份假设，错会一起错。这里只信规范：
  * LFN 条目的 checksum 必须等于其 8.3 名按 FAT 规则算出的值——不对则 UEFI 驱动不认长名
  * LFN 序号必须从 1 连续递增，且**最大序号那一条带 0x40 位并出现在物理最前**
  * 簇链必须终止于 0xFFFF，且不能成环
  * 文件读出的字节数必须 >= 目录项里的大小

用法：python tools/validate_esp.py build/aurora.img
      python tools/validate_esp.py build/aurora.img --report   # key=value，给判定矩阵对账用
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


# UEFI 规范的 EFI System Partition type GUID（C12A7328-F81F-11D2-BA4B-00A0C93EC93B）。
# **混合端序**：前三段小端、后两段大端。这是规范常数，故意不从 esp_image import——
# 生成器与校验器共用一张常量表就退化成一台仪器（本文件首行那条纪律）。
ESP_TYPE_GUID = bytes([0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
                       0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B])


def gpt_facts(d: bytes) -> dict[str, str]:
    """从整盘字节独立重算 GPT 的事实，供 `--report` 打成 key=value 给判定矩阵对账。

    与内核 `filesystem/gpt.rs` 是两台实现：偏移表各写一份、CRC 各算一遍。
    这里**只报读到的数与自己算的数**，不替内核下结论；对不对由调用方逐格比。
    备份头也读（内核要交叉核它，宿主机不读就没有第二份证词）。
    """
    f: dict[str, str] = {}
    problems: list[str] = []
    mbr = d[0:SECTOR]
    f["mbr_sig"] = str(mbr[510:512] == b"\x55\xaa").lower()
    f["mbr_type"] = f"0x{mbr[446 + 4]:02x}"
    g = d[SECTOR:SECTOR + 92]
    sig = g[0:8].decode(errors="replace")
    f["signature"] = sig
    if g[0:8] != b"EFI PART":
        f["problems"] = "1"
        f["problem0"] = "LBA1 不是 EFI PART"
        return f
    u32 = lambda off: struct.unpack_from("<I", g, off)[0]
    u64 = lambda off: struct.unpack_from("<Q", g, off)[0]
    f["revision"] = str(u32(8))
    f["header_size"] = str(u32(12))
    f["header_crc"] = f"0x{u32(16):08x}"
    f["my_lba"] = str(u64(24))
    f["alternate_lba"] = str(u64(32))
    f["first_usable"] = str(u64(40))
    f["last_usable"] = str(u64(48))
    f["disk_guid"] = g[56:72].hex()
    f["entry_lba"] = str(u64(72))
    f["entry_count"] = str(u32(80))
    f["entry_size"] = str(u32(84))
    f["array_crc"] = f"0x{u32(88):08x}"
    z = bytearray(g)
    z[16:20] = b"\x00" * 4
    hc = binascii.crc32(bytes(z)) & 0xFFFFFFFF
    f["header_crc_calc"] = f"0x{hc:08x}"
    if hc != u32(16):
        problems.append("头 CRC32 自洽性不成立")
    if g[56:72] == b"\x00" * 16:
        problems.append("DiskGUID 全 0")

    n, sz, elba = u32(80), u32(84), u64(72)
    arr = d[elba * SECTOR: elba * SECTOR + n * sz]
    f["array_bytes"] = str(len(arr))
    ac = binascii.crc32(arr) & 0xFFFFFFFF
    f["array_crc_calc"] = f"0x{ac:08x}"
    if ac != u32(88):
        problems.append("条目数组 CRC32 不匹配")
    if len(arr) != n * sz:
        problems.append(f"条目数组读不满：要 {n * sz} 字节只读到 {len(arr)}")
    f["seen"] = str(n)
    used = 0
    esp_done = False
    for i in range(n):
        e = arr[i * sz: (i + 1) * sz]
        if len(e) < sz or e[0:16] == bytes(16):
            continue
        tg = e[0:16]
        first = struct.unpack_from("<Q", e, 32)[0]
        last = struct.unpack_from("<Q", e, 40)[0]
        f[f"part{used}_index"] = str(i)
        f[f"part{used}_type"] = tg.hex()
        f[f"part{used}_first"] = str(first)
        f[f"part{used}_last"] = str(last)
        if tg == ESP_TYPE_GUID and not esp_done:
            f["esp_index"] = str(i)
            f["esp_type"] = tg.hex()
            f["esp_unique"] = e[16:32].hex()
            f["esp_first"] = str(first)
            f["esp_last"] = str(last)
            f["esp_attrs"] = f"0x{struct.unpack_from('<Q', e, 48)[0]:x}"
            esp_done = True
        used += 1
    f["used"] = str(used)
    if not esp_done:
        problems.append("找不到 ESP（type GUID 不匹配）")

    # 备份头：内核交叉核五格，宿主机这里把同样的数读出来供逐格比。
    alt = u64(32)
    b = d[alt * SECTOR: alt * SECTOR + 92]
    if len(b) < 92 or b[0:8] != b"EFI PART":
        problems.append("备份头不在位或签名不对")
        f["backup_present"] = "false"
    else:
        f["backup_present"] = "true"
        f["backup_my_lba"] = str(struct.unpack_from("<Q", b, 24)[0])
        f["backup_alternate_lba"] = str(struct.unpack_from("<Q", b, 32)[0])
        f["backup_first_usable"] = str(struct.unpack_from("<Q", b, 40)[0])
        f["backup_last_usable"] = str(struct.unpack_from("<Q", b, 48)[0])
        f["backup_array_crc"] = f"0x{struct.unpack_from('<I', b, 88)[0]:08x}"
        f["backup_header_crc"] = f"0x{struct.unpack_from('<I', b, 16)[0]:08x}"
        zb = bytearray(b)
        zb[16:20] = b"\x00" * 4
        bh = binascii.crc32(bytes(zb)) & 0xFFFFFFFF
        f["backup_header_crc_calc"] = f"0x{bh:08x}"
        if bh != struct.unpack_from("<I", b, 16)[0]:
            problems.append("备份头 CRC32 不成立")
        for name, a, bb in (
            ("my_lba", u64(32), struct.unpack_from("<Q", b, 24)[0]),
            ("alternate_lba", u64(24), struct.unpack_from("<Q", b, 32)[0]),
            ("first_usable", u64(40), struct.unpack_from("<Q", b, 40)[0]),
            ("last_usable", u64(48), struct.unpack_from("<Q", b, 48)[0]),
            ("array_crc", u32(88), struct.unpack_from("<I", b, 88)[0]),
        ):
            if a != bb:
                problems.append(f"备份交叉核 {name} 不符：主={a} 备={bb}")
    f["problems"] = str(len(problems))
    for i, p in enumerate(problems):
        f[f"problem{i}"] = p
    return f


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
    argv = sys.argv[1:]
    report = "--report" in argv
    rest = [a for a in argv if a != "--report"]
    target = rest[0] if rest else "build/aurora.img"
    if report:
        # 机器可读模式：只打 key=value，给 tools/aurora.py 的判定行逐格对内核串口读数。
        # 不走 main() 的人读输出，也不因为它发现问题就退出非零——**问题数本身是一个字段**，
        # 由调用方决定怎么判（否则"宿主机发现盘坏了"与"宿主机自己挂了"会长成同一个退出码）。
        for k, v in gpt_facts(open(target, "rb").read()).items():
            print(f"{k}={v}")
        sys.exit(0)
    sys.exit(main(target))
