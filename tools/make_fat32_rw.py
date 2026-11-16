"""ADR-111：可写 FAT32 夹具（`build/fat32-rw.img`）——现算、跑完即丢。

与 `make_fat32_deep.py` 的分工：那块卷是**只读**判据的基准（指纹进提交），这块卷的存在意义是
被写坏——所以它不进仓库、不进 `.img.zz`，由 `ensure_fat_rw()` 每次跑之前现算一遍。

形状（故意小：写方向的判据要的是"字节真的变了、且只变该变的那段"，不是容量）：

    /DATA.BIN   1024 字节，2 簇（簇 3-4）——跨簇写、整扇区写都用它
    /LOG.TXT      64 字节，1 簇（簇 5）  ——只覆盖前 64 字节，用来证"没写到的字节一个没动"
    卷簇数 2,048（1 MiB）——与卷A 同形：按簇数阈值会算成 Fat16，按结构特征是 Fat32。
    核内 `parse_boot_sector` 走的是**结构**判型（卷A 就是那个反例），所以这形状能挂上。

读回复算（写在落盘之后）：BPB 十字段、备份引导扇区逐字节、FSInfo 三签名与副本位置、
两份 FAT 逐字节相同、根目录三项、两个文件的内容与簇链——任何一格不成立就退出非零。
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

SEC = 512
SPC = 1
RESERVED = 32
FATS = 2
ROOT_CLUSTER = 2
FSINFO = 1
BACKUP = 6
FSINFO_BACKUP = BACKUP + 6
CLUSTERS = 2_048
SPF = (CLUSTERS + 2 + 127) // 128
TOTAL = RESERVED + FATS * SPF + CLUSTERS
DATA_START = RESERVED + FATS * SPF
EOC = 0x0FFF_FFFF

DATA_CL = 3
LOG_CL = 5

OUT = Path("build/fat32-rw.img")
if len(sys.argv) > 1:
    OUT = Path(sys.argv[1])


def u16(v):
    return struct.pack("<H", v & 0xFFFF)


def u32(v):
    return struct.pack("<I", v & 0xFFFF_FFFF)


def sector_of(cluster):
    return DATA_START + (cluster - 2) * SPC


def body(seed, n):
    return bytes([((i * 37 + seed * 11) & 0xFF) ^ (seed & 0xFF) for i in range(n)])


def dentry(name8, ext3, attr, cluster, size):
    b = bytearray(32)
    b[0:8] = name8.ljust(8)[:8].encode("latin1")
    b[8:11] = ext3.ljust(3)[:3].encode("latin1")
    b[11] = attr
    b[13:15] = u16(0x4800)
    b[16:18] = u16(0x2B01)
    b[20:22] = u16((cluster >> 16) & 0xFFFF)
    b[26:28] = u16(cluster & 0xFFFF)
    b[28:32] = u32(size)
    return b


img = bytearray(TOTAL * SEC)

# ---------------------------------------------------------------- 引导扇区
bs = bytearray(SEC)
bs[0:3] = bytes([0xEB, 0x58, 0x90])
bs[3:11] = b"MSDOS5.1"
bs[11:13] = u16(SEC)
bs[13] = SPC
bs[14:16] = u16(RESERVED)
bs[16] = FATS
bs[17:19] = u16(0)
bs[19:21] = u16(0)
bs[21] = 0xF8
bs[22:24] = u16(0)
bs[24:26] = u16(0)
bs[26:28] = u16(0)
bs[28:32] = u32(0)
bs[32:36] = u32(TOTAL)
bs[36:40] = u32(SPF)
bs[40:42] = u16(0)
bs[42:44] = u16(0)
bs[44:48] = u32(ROOT_CLUSTER)
bs[48:50] = u16(FSINFO)
bs[50:52] = u16(BACKUP)
bs[64] = 0x80
bs[66] = 0x29
bs[67:71] = u32(0x0DEE_0004)
bs[71:82] = b"FAT32   AUR"
bs[82:90] = b"FAT32   "
bs[510:512] = bytes([0x55, 0xAA])
if len(bs) != SEC or bs[510:512] != bytes([0x55, 0xAA]):
    raise SystemExit("引导扇区长度/签名错（窄值写进宽切片会把整个扇区缩短）")
img[0:SEC] = bs

# ---------------------------------------------------------------- FSInfo 与副本
used = 1 + 1 + 2 + 1          # 根 + DATA(2) + LOG(1)
fi = bytearray(SEC)
fi[0:4] = u32(0x4161_5252)
fi[484:488] = u32(0x6141_7272)
fi[488:492] = u32(CLUSTERS - used)
fi[492:496] = u32(6)          # 下一个空闲簇（提示值）
fi[508:512] = u32(0xAA55_0000)
if len(fi) != SEC:
    raise SystemExit("FSInfo 长度不是 512")
img[FSINFO * SEC:(FSINFO + 1) * SEC] = fi
img[FSINFO_BACKUP * SEC:(FSINFO_BACKUP + 1) * SEC] = fi
img[BACKUP * SEC:(BACKUP + 1) * SEC] = bs

# ---------------------------------------------------------------- FAT（两份逐字节相同）
fat = bytearray(SPF * SEC)
fat[0:4] = u32(0x0FF8)
fat[4:8] = u32(EOC)


def set_chain(first, n=1):
    for k in range(n):
        nxt = EOC if k == n - 1 else first + k + 1
        fat[(first + k) * 4:(first + k) * 4 + 4] = u32(nxt)


set_chain(ROOT_CLUSTER, 1)
set_chain(DATA_CL, 2)
set_chain(LOG_CL, 1)
for k in range(FATS):
    img[(RESERVED + k * SPF) * SEC:(RESERVED + (k + 1) * SPF) * SEC] = fat

# ---------------------------------------------------------------- 根目录（簇 2）
root = bytearray(SEC)
root[0:32] = dentry("DATA", "BIN", 0x20, DATA_CL, 1024)
root[32:64] = dentry("LOG", "TXT", 0x20, LOG_CL, 64)
root[64:68] = bytes(4)                        # 结束标记：解析器在这里停
img[sector_of(ROOT_CLUSTER) * SEC:(sector_of(ROOT_CLUSTER) + 1) * SEC] = root

# ---------------------------------------------------------------- 文件内容
img[sector_of(DATA_CL) * SEC:sector_of(DATA_CL) * SEC + SEC] = body(1, SEC)
img[sector_of(DATA_CL + 1) * SEC:sector_of(DATA_CL + 1) * SEC + SEC] = body(2, SEC)
img[sector_of(LOG_CL) * SEC:sector_of(LOG_CL) * SEC + 64] = body(3, 64)

OUT.parent.mkdir(exist_ok=True)
OUT.write_bytes(bytes(img))

# ---------------------------------------------------------------- 读回复算（信盘上的字节，不信上面的意图）
data = OUT.read_bytes()
if len(data) != TOTAL * SEC:
    raise SystemExit(f"落盘 {len(data)} 字节 != {TOTAL * SEC}")


def g16(off):
    return struct.unpack_from("<H", data, off)[0]


def g32(off):
    return struct.unpack_from("<I", data, off)[0]


pbp = {"每簇扇区": (data[13], SPC), "保留扇区": (g16(14), RESERVED), "FAT份数": (data[16], FATS),
       "根目录项": (g16(17), 0), "每份FAT16": (g16(22), 0), "总扇区32": (g32(32), TOTAL),
       "每份FAT32": (g32(36), SPF), "根簇": (g32(44), ROOT_CLUSTER), "FSInfo": (g16(48), FSINFO),
       "备份引导": (g16(50), BACKUP)}
for tag, (got, want) in pbp.items():
    if got != want:
        raise SystemExit(f"盘上 BPB `{tag}` = {got}，配方写的是 {want}")
if data[510:512] != bytes([0x55, 0xAA]):
    raise SystemExit("盘上 510:512 不是 0x55AA")
if data[BACKUP * SEC:BACKUP * SEC + SEC] != data[0:SEC]:
    raise SystemExit("备份引导扇区与主引导扇区不逐字节相同")
for tag, base in (("FSInfo", g16(48)), ("FSInfo备份", g16(50) + 6)):
    o = base * SEC
    got = (g32(o), g32(o + 484), data[o + 510:o + 512])
    if got != (0x4161_5252, 0x6141_7272, bytes([0x55, 0xAA])):
        raise SystemExit(f"盘上 {tag} 签名不对：{got}")

fat1 = data[g16(14) * SEC:(g16(14) + g32(36)) * SEC]
fat2 = data[(g16(14) + g32(36)) * SEC:(g16(14) + 2 * g32(36)) * SEC]
if fat1 != fat2:
    raise SystemExit("两份 FAT 不是逐字节相同（写方向第一刀要求它们同步，读方向也靠这点对账）")


def fat_at(c):
    return struct.unpack_from("<I", data, (g16(14) * SEC) + c * 4)[0]


def sector(cl):
    return (g16(14) + data[16] * g32(36) + (cl - 2) * data[13]) * SEC


if fat_at(DATA_CL) != DATA_CL + 1 or fat_at(DATA_CL + 1) != EOC:
    raise SystemExit(f"DATA.BIN 的簇链不对：{fat_at(DATA_CL):#x}, {fat_at(DATA_CL + 1):#x}")
if fat_at(LOG_CL) != EOC:
    raise SystemExit("LOG.TXT 的簇链没有终止于 EOC")
# 读到终止项（首字节 0）就停：目录项之后是结束标记，不是第三个条目。
ro = []
for i in range(0, 96, 32):
    e = data[sector(g32(44)) + i:sector(g32(44)) + i + 32]
    if e[0] == 0:
        break
    ro.append(e)
names = [(e[0:8].rstrip(b" ").decode(), e[8:11].rstrip(b" ").decode(),
          struct.unpack_from("<I", e, 28)[0]) for e in ro]
if names != [("DATA", "BIN", 1024), ("LOG", "TXT", 64)]:
    raise SystemExit(f"根目录读回来不对：{names}")

data_bytes = data[sector(DATA_CL):sector(DATA_CL) + SEC] + data[sector(DATA_CL + 1):sector(DATA_CL + 1) + SEC]
log_bytes = data[sector(LOG_CL):sector(LOG_CL) + 64]
if data_bytes != body(1, SEC) + body(2, SEC):
    raise SystemExit("DATA.BIN 的内容与配方不同")
if log_bytes != body(3, 64):
    raise SystemExit("LOG.TXT 的内容与配方不同")

print(f"total_sectors={TOTAL} bytes={TOTAL * SEC} clusters={CLUSTERS} sectors_per_fat={SPF} "
      f"data_start={DATA_START} root_cluster={ROOT_CLUSTER} files=/DATA.BIN(1024,/LOG.TXT(64)")
print(f"DATA.BIN head8=0x{int.from_bytes(data_bytes[:8], 'little'):x} bytesum={sum(data_bytes)} "
      f"first={DATA_CL} tail8=0x{int.from_bytes(data_bytes[512:520], 'little'):x}")
print(f"LOG.TXT  head8=0x{int.from_bytes(log_bytes[:8], 'little'):x} bytesum={sum(log_bytes)} first={LOG_CL}")
print(f"sha256={hashlib.sha256(data).hexdigest()}")
