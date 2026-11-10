"""现算一块**合成 FAT16 整卷**夹具（W4 S2a，ADR-078 / ADR-038 决策 3 同族手法）。

为什么需要它：本机没有 mtools，而真 FAT16 卷在引导盘的 ESP 里、要等 S2b 的分区偏移才读得到。
这块卷由宿主机现算、内核 `include_bytes!` **同一份字节**，于是"两台仪器读的是同一块卷"
而不是"各自实现同一个配方"——后者错会一起错（ADR-038 决策 2 的理由）。

它不在仓库里（`.gitignore` 的 `*.img`），指纹登记在 `tools/aurora.py`，
配方与用例里那批写死的数分家时红在**编译之前**。

几何故意选小：23 个扇区、簇数 16（**落在 FAT12 档**）而结构是 FAT16
⇒ 它本身就是"判型只看结构、阈值只报数"的反例。

用法：python tools/make_fat16_mem.py [输出路径]
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

SECTOR = 512
SPC = 1
RESERVED = 1
FAT_COUNT = 2
SPF16 = 1
ROOT_ENTRIES = 64
ROOT_SECTORS = ROOT_ENTRIES * 32 // SECTOR        # 4
DATA_START = RESERVED + FAT_COUNT * SPF16 + ROOT_SECTORS   # 7
DATA_CLUSTERS = 16
TOTAL_SECTORS = DATA_START + DATA_CLUSTERS * SPC   # 23
VOL_BYTES = TOTAL_SECTORS * SECTOR                 # 11776
FILE_SIZE = 1000


def content_at(i: int) -> int:
    """内容**显式依赖扇区序号**：只写成 i*m mod 256 的话，因为 512 ≡ 0 (mod 256)，
    每个扇区会逐字节相同 ⇒ 读错扇区也对得上（本仓在 FAT32 合成卷上踩过这个坑）。"""
    return ((i // SECTOR) * 7 + (i % SECTOR) * 13) & 0xFF


def build() -> bytes:
    b = bytearray(VOL_BYTES)
    b[0:3] = b"\xeb\xfe\x90"
    b[3:11] = b"AURORA16"
    struct.pack_into("<H", b, 11, SECTOR)
    b[13] = SPC
    struct.pack_into("<H", b, 14, RESERVED)
    b[16] = FAT_COUNT
    struct.pack_into("<H", b, 17, ROOT_ENTRIES)
    struct.pack_into("<H", b, 19, 0)              # total16 = 0 ⇒ 用 total32
    b[21] = 0xF8
    struct.pack_into("<H", b, 22, SPF16)
    struct.pack_into("<I", b, 32, TOTAL_SECTORS)
    struct.pack_into("<I", b, 36, 0)              # 36..40 在 FAT16 里不是 spf32，是扩展引导记录
    b[38] = 0x29                                  # BS_BootSig：**故意写它**，它让 36..40 非零，
                                                  # 第一版那条 `spf32==0` 的结构闸就是这么被抓到的
    b[54:62] = b"FAT16   "
    b[510:512] = b"\x55\xaa"
    for k in range(FAT_COUNT):
        f = (RESERVED + k * SPF16) * SECTOR
        struct.pack_into("<H", b, f, 0xFFF8)
        struct.pack_into("<H", b, f + 2, 0xFFFF)
        struct.pack_into("<H", b, f + 4, 3)       # 簇 2 → 簇 3
        struct.pack_into("<H", b, f + 6, 0xFFFF)  # 簇 3 = FAT16 的 EOC
    root = (RESERVED + FAT_COUNT * SPF16) * SECTOR

    def entry(off: int, name: bytes, attr: int, cluster: int, size: int) -> None:
        assert len(name) == 11
        b[off:off + 11] = name
        b[off + 11] = attr
        struct.pack_into("<H", b, off + 26, cluster)
        struct.pack_into("<I", b, off + 28, size)

    entry(root, b"AURORA16   ", 0x08, 0, 0)       # 卷标：必须被跳过
    entry(root + 32, b"TEST    BIN", 0x20, 2, FILE_SIZE)
    for i in range(FILE_SIZE):
        b[DATA_START * SECTOR + i] = content_at(i)
    return bytes(b)


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "kernel" / "fixtures" / "fat16-mem.img"
    data = build()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    print(f"FAT16 合成整卷: {out} {len(data)} 字节 sha256={hashlib.sha256(data).hexdigest()}")
    print(f"  几何: {TOTAL_SECTORS} 扇区 数据起点={DATA_START} 根目录区={ROOT_SECTORS} 扇区 "
          f"根项={ROOT_ENTRIES} 每份FAT={SPF16} 扇区 簇数={DATA_CLUSTERS}（阈值档=FAT12，结构=FAT16）")
    return 0


if __name__ == "__main__":
    sys.exit(main())