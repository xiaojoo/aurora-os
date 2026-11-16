#!/usr/bin/env python3
"""FS-03 多级真卷夹具（ADR-109）：现算一块**盘上** FAT32 深目录卷。

与 `make_fat32_mem.py` / `esp_image.py` 同一条卫生规矩：
* 产物 `build/fat32-deep.img` **不进仓库**（`.gitignore` 的 `*.img` 挡着），每次由本配方现算；
* 字节数与 sha256 登记在 `tools/aurora.py` 的 `FAT_DEEP_EXPECT`——先核指纹再核解析，
  把"配方与镜像分家"与"被测物坏了"分在两道闸上；
* 本文件不 import 内核常量、也不复用 `esp_image` 的写表逻辑：几何与目录项按 FAT 规范自己写，
  所以它可以当第二台仪器（§333 那条"两份同错算法不是两台仪器"就是这么进来的）。

为什么簇数推过 65,525（使用者 2026-11-16 裁决，ADR-109 补记一）：
`filesystem/fat32.rs` 的判型有两半——**阈值判型**看簇数（<65,525 落 Fat16 档），
**结构判型**看"固定根项为 0 且每份 FAT32 扇区数不为 0"。小卷上两半不一致（卷A 就是那格反例）。
这块卷的角色是"多级目录 + 子目录 LFN 走真块层"，不该再兼一份判型反例 ⇒ 簇数落 Fat32 档，
两半说同一句话。代价是镜像 32.7 MiB；只有 `fs-open` 档挂它，判定表其它行与四把尺子不吃这块盘。

内容清单（每项都为了在判定链上拉住在某一格，不是装饰）：

| 路径 | 角色 |
|---|---|
| `/SMALL.BIN` | 根文件 100 字节，沿用 FS-03 的形状 |
| `/PROJECT` | 一级目录（1 簇） |
| `/PROJECT/DOCS` | 二级目录，**跨两簇**：填充项把 LFN 那三条推到第二扇区 |
| `/PROJECT/DOCS/NESTED.TXT` | 三级命中：open/read/stat 走 ring3 |
| `/PROJECT/DOCS/AURORA~1.TXT` + 长名 `AuroraLongDocument.txt` | 子目录 LFN：校验和绑定短名、序号物理倒序 |
| `/GONE.BIN`（首字节 `0xE5`） | 已删除项：跳过但仍计入扫过项，与根目录同一数法 |
| `/D1/D2/…/D16/F.TXT` | 16 层真深链（17 个组件）⇒ `MAX_COMPONENTS = 16` 的边界 |
"""

import hashlib
import struct
import sys
from pathlib import Path

SEC = 512
SPC = 1                       # 每簇 1 扇区：这一格里"簇"与"扇区"等价，读数不必换算
RESERVED = 32
FATS = 2
ROOT_CLUSTER = 2
FSINFO = 1
BACKUP = 6
FSINFO_BACKUP = BACKUP + 6      # 规范：FSInfo 的副本在**备份引导扇区 + 6**，不是 +1
CLUSTERS = 66_000             # 数据簇数 >= 65,536 ⇒ 阈值判型落 Fat32 档
SPF = (CLUSTERS + 2 + 127) // 128      # 每份 FAT 扇区数（128 个 4 字节项 / 扇区）
TOTAL = RESERVED + FATS * SPF + CLUSTERS
DATA_START = RESERVED + FATS * SPF
EOC = 0x0FFF_FFFF
FILLER = 15                   # DOCS 里的填充文件数：把目录项推过第一扇区边界
FILLER_FIRST = 11
# 三级文件故意放在 65,536 号簇**之上**：这样它的目录项高半是 1，两半必须拼起来才读得到。
# 卷B 已经在根目录那一层证过"只取低半会读到别处"，这一格证的是**多级 lookup 之后**
# 那一次拼接还在不在——两条路径在核内不是同一个调用点（`find_child` 返回的 `Entry` 再走簇链）。
NESTED_CL = 65_600
# `MAX_COMPONENTS = 16` 那条上限要**真深链**才喂得动（ADR-109 最后一条负样本）：16 层目录
# 各占一簇、第 16 层里放一个文件；17 个组件的路径必须在第 17 次查找**之前**就被拒。
CHAIN_FIRST = 65_700
CHAIN = 16
CHAIN_FILE_CL = CHAIN_FIRST + CHAIN

OUT = Path("build/fat32-deep.img")
if len(sys.argv) > 1:                    # tools/aurora.py 用绝对路径调用，不着 CWD——与 make_fat16_mem 同一规矩
    OUT = Path(sys.argv[1])


def u16(v):
    return struct.pack("<H", v & 0xFFFF)


def u32(v):
    return struct.pack("<I", v & 0xFFFF_FFFF)


def sector_of(cluster):
    return DATA_START + (cluster - 2) * SPC


def body(seed, n):
    """确定性假数据：只依赖下标与种子 ⇒ 重跑逐字节相同（指纹闸的前提）。"""
    return bytes([((i * 31 + seed * 7) & 0xFF) ^ ((seed >> 3) & 0xFF) for i in range(n)])


def checksum(sb):
    """VFAT 对 11 字节短名（空格补齐、无点）的校验和：带**循环右移**那一步。
    §333 里 `esp_image.py` 与 `validate_esp.py` 同时丢了最高位，两份同错还互相"核过"。
    """
    s = 0
    for b in sb:
        s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    return s


class Dir:
    """目录簇链的条目写入器：按簇提交，所以能自己断言"到底跨了几簇"。"""

    def __init__(self, first_cluster, clusters):
        self.first = first_cluster
        self.clusters = clusters
        self.buf = bytearray(clusters * SPC * SEC)
        self.p = 0

    def put(self, ent):
        self.buf[self.p:self.p + 32] = ent
        self.p += 32

    def finish(self, img):
        self.buf[self.p:self.p + 4] = bytes(4)        # 末尾空项：解析器在这里停下
        for k in range(self.clusters):
            sec = sector_of(self.first + k)
            img[sec * SEC:(sec + 1) * SEC] = self.buf[k * SPC * SEC:(k + 1) * SPC * SEC]
        return self.p


def dentry(name8, ext3, attr, cluster, size, first=None):
    """32 字节 8.3 目录项。名字一律空格补齐——`name_matches` 是靠那个空格停下的。"""
    b = bytearray(32)
    b[0:8] = name8.ljust(8)[:8].encode("latin1")
    b[8:11] = ext3.ljust(3)[:3].encode("latin1")
    b[11] = attr
    b[13:15] = u16(0x4800)                    # 创建时间 09:00
    b[16:18] = u16(0x2B01)                    # 创建日期 2001-01-01
    b[20:22] = u16((cluster >> 16) & 0xFFFF)  # 首簇高半：FAT32 两半拼起来才是首簇
    b[26:28] = u16(cluster & 0xFFFF)         # 首簇低半
    b[28:32] = u32(size)
    if first is not None:
        b[0] = first
    return b


def lfn_entries(chars, short8, shortext):
    """UCS-2 名字拆成 LFN 片段（每条 13 个单元），**物理顺序尾块在前**：
    盘上第一条的序号 = 总条数 | 0x40。校验和按短名 11 字节算，存在条目偏移 13。
    """
    units = [ord(c) for c in chars] + [0x0000]
    units += [0xFFFF] * ((13 - len(units) % 13) % 13)
    n = len(units) // 13
    sb = (short8.ljust(8)[:8] + shortext.ljust(3)[:3]).encode("latin1")
    csum = checksum(sb)
    out = []
    for k in range(n):
        b = bytearray(32)
        seq = n - k                          # 物理第一条的序号最大，且带 0x40
        b[0] = seq | (0x40 if k == 0 else 0)
        b[11] = 0x0F
        # 内容按**序号**取第 seq 块，不是按物理位置取第 k 块。早先这里写的是 `units[k*13:]`，
        # 于是"头块装在尾号的条目里"——按规范读回来得到的是"ument.txt"（9 个字符），
        # 而**照抄同一个错假设的两份宿主机脚本都看不出问题**。抓到它的是核内那份按序号落位的解码。
        chunk = units[(seq - 1) * 13: seq * 13]
        for i, off in enumerate([1, 3, 5, 7, 9] + [14, 16, 18, 20, 22, 24] + [28, 30]):
            ch = chunk[i] if i < len(chunk) else 0x0000
            b[off] = ch & 0xFF
            b[off + 1] = (ch >> 8) & 0xFF
        b[12] = 0x00
        b[13] = csum
        b[26:28] = u16(0)
        out.append(b)
    return out


def fnv1a64(data):
    h = 0xCBf2_9CE4_8422_2325
    for b in data:
        h = ((h ^ b) * 0x0100_0000_01B3) & 0xFFFF_FFFF_FFFF_FFFF
    return h


img = bytearray(TOTAL * SEC)

# ---------------------------------------------------------------- 引导扇区
bs = bytearray(SEC)
bs[0:3] = bytes([0xEB, 0x58, 0x90])
bs[3:11] = b"MSDOS5.1"
bs[11:13] = u16(SEC)
bs[13] = SPC
bs[14:16] = u16(RESERVED)
bs[16] = FATS
bs[17:19] = u16(0)              # 固定根项 = 0 ⇒ 结构上是 FAT32
bs[19:21] = u16(0)              # 小扇区数留空（这块卷 > 65,535 扇区）
bs[21] = 0xF8
bs[22:24] = u16(0)              # 每份 FAT16 扇区 = 0 ⇒ FAT32
bs[24:26] = u16(0)              # 每磁道扇区
bs[26:28] = u16(0)              # 磁头数
bs[28:32] = u32(0)
bs[32:36] = u32(TOTAL)
bs[36:40] = u32(SPF)
bs[40:42] = u16(0)              # 扩展标志
bs[42:44] = u16(0)              # 文件系统版本
bs[44:48] = u32(ROOT_CLUSTER)
bs[48:50] = u16(FSINFO)
bs[50:52] = u16(BACKUP)
bs[64] = 0x80
bs[66] = 0x29
bs[67:71] = u32(0x0DEE_0003)
bs[71:82] = b"FAT32   AUR"
bs[82:90] = b"FAT32   "
bs[510:512] = bytes([0x55, 0xAA])
if len(bs) != SEC:
    raise SystemExit(f"引导扇区长度不再是 {SEC}（{len(bs)}）"
                     f"⇒ 某处把窄值写进了宽切片，字段会整体错位")
if bs[510:512] != bytes([0x55, 0xAA]):
    raise SystemExit("0x55AA 不在引导扇区的 510:512：前面有写把整个 bs 缩短了")
img[0:SEC] = bs

# ---------------------------------------------------------------- FSInfo 与其备份
used = 1 + 1 + 1 + 2 + 1 + 1 + 1 + FILLER + CHAIN + 1   # 根+SMALL+PROJECT+DOCS(2)+NESTED+长名+GONE+填充+深链(16+文件)
fi = bytearray(SEC)
fi[0:4] = u32(0x4161_5252)
fi[484:488] = u32(0x6141_7272)
fi[488:492] = u32(CLUSTERS - used)
fi[492:496] = u32(FILLER_FIRST + FILLER)
# 尾签名：核内 `fat32.rs` 读的是偏移 510 处那个 u16 = 0xAA55（等价于 508 处的 u32 0xAA550000）。
# 早先漏了这两格，挂载被当场拒成 `FSInfo签名不符` —— 夹具自己不合格，红却长得像解析器坏了。
fi[508:512] = u32(0xAA55_0000)
img[FSINFO * SEC:(FSINFO + 1) * SEC] = fi
img[FSINFO_BACKUP * SEC:(FSINFO_BACKUP + 1) * SEC] = fi

# ---------------------------------------------------------------- 备份引导扇区：逐字节相同
# `t_fat32` 有一格判据就叫"备份逐字节同"。故意让它差一个签名会把那格读成"夹具坏了"
# 而不是"被测物坏了"——所以连签名一起照抄。
img[BACKUP * SEC:(BACKUP + 1) * SEC] = bs

# ---------------------------------------------------------------- FAT
fat = bytearray(SPF * SEC)
fat[0:4] = u32(0x0FF8)
fat[4:8] = u32(EOC)


def set_chain(first, n=1):
    for k in range(n):
        nxt = EOC if k == n - 1 else first + k + 1
        fat[(first + k) * 4:(first + k) * 4 + 4] = u32(nxt)


for c, n in ((ROOT_CLUSTER, 1), (3, 1), (4, 1), (5, 2), (NESTED_CL, 1), (8, 1), (9, 1),
           (CHAIN_FILE_CL, 1)):
    set_chain(c, n)
for i in range(CHAIN):
    set_chain(CHAIN_FIRST + i, 1)          # 深链的每一层各一簇
for f in range(FILLER_FIRST, FILLER_FIRST + FILLER):
    set_chain(f, 1)
for k in range(FATS):
    img[(RESERVED + k * SPF) * SEC:(RESERVED + (k + 1) * SPF) * SEC] = fat

# ---------------------------------------------------------------- 根目录（簇 2）
root = Dir(ROOT_CLUSTER, 1)
root.put(dentry("SMALL", "BIN", 0x20, 3, 100))
root.put(dentry("PROJECT", "", 0x10, 4, 0))
gone = dentry("GONE", "BIN", 0x20, 9, 33)
gone[0] = 0xE5                    # 已删除项：内核要跳过它**并且**把它计入扫过的项数
root.put(gone)
root.put(dentry("D1", "", 0x10, CHAIN_FIRST, 0))
root_p = root.finish(img)

# ---------------------------------------------------------------- /PROJECT（簇 4）
proj = Dir(4, 1)
proj.put(dentry("DOCS", "", 0x10, 5, 0))
proj.finish(img)

# ---------------------------------------------------------------- /PROJECT/DOCS（簇 5-6）
# 先放 FILLER 条填充，让 NESTED 正好写完第一扇区，LFN 那三条整体落进**第二扇区**：
# 跨簇目录里"名字条目与短名条目分家"是最容易数错的形状，短目录永远碰不到它。
docs = Dir(5, 2)
for idx in range(FILLER):
    docs.put(dentry(f"DOC{idx:04d}", "TXT", 0x20, FILLER_FIRST + idx, 8))
docs.put(dentry("NESTED", "TXT", 0x20, NESTED_CL, 64))
LONG = "AuroraLongDocument.txt"
for e in lfn_entries(LONG, "AURORA~1", "TXT"):
    docs.put(e)
docs.put(dentry("AURORA~1", "TXT", 0x20, 8, 48))
docs_p = docs.finish(img)

# ---------------------------------------------------------------- 深链 /D1/…/D16
# 每层只有一条子目录项；第 16 层放一个 8 字节文件。这一串是 `MAX_COMPONENTS` 唯一的真对象。
for i in range(CHAIN):
    d = Dir(CHAIN_FIRST + i, 1)
    if i + 1 < CHAIN:
        d.put(dentry(f"D{i + 2}", "", 0x10, CHAIN_FIRST + i + 1, 0))
    else:
        d.put(dentry("F", "TXT", 0x20, CHAIN_FILE_CL, 8))
    d.finish(img)

# ---------------------------------------------------------------- 文件内容
img[sector_of(3) * SEC:sector_of(3) * SEC + 100] = body(1, 100)
img[sector_of(NESTED_CL) * SEC:sector_of(NESTED_CL) * SEC + 64] = body(2, 64)
img[sector_of(8) * SEC:sector_of(8) * SEC + 48] = body(3, 48)
img[sector_of(9) * SEC:sector_of(9) * SEC + 33] = body(4, 33)
img[sector_of(CHAIN_FILE_CL) * SEC:sector_of(CHAIN_FILE_CL) * SEC + 8] = body(9, 8)
for idx in range(FILLER):
    sec = sector_of(FILLER_FIRST + idx)
    img[sec * SEC:sec * SEC + 8] = body(5 + idx, 8)

OUT.parent.mkdir(exist_ok=True)
OUT.write_bytes(bytes(img))

# ---------------------------------------------------------------- 自证：跨簇那一格不是空转
if NESTED_CL >= CLUSTERS:
    raise SystemExit(f"三级文件的簇号 {NESTED_CL} 落在数据区之外（共 {CLUSTERS} 簇）")
if not SEC < docs_p <= 2 * SEC:
    raise SystemExit(f"DOCS 目录没有跨到第二簇（写了 {docs_p} 字节）⇒ 这一格白造")

print(f"total_sectors={TOTAL} bytes={TOTAL * SEC} clusters={CLUSTERS} sectors_per_fat={SPF} "
      f"data_start={DATA_START} root_cluster={ROOT_CLUSTER} fsinfo={FSINFO} backup={BACKUP}")
print(f"band_by_clusters={'Fat32' if CLUSTERS >= 65525 else 'Fat16'} struct_is_fat32=true")
print(f"sha256={hashlib.sha256(bytes(img)).hexdigest()}")
print(f"root_entries_bytes={root_p} docs_entries_bytes={docs_p}")
for tag, seed, n in (("SMALL.BIN", 1, 100), ("NESTED.TXT", 2, 64),
                     ("LONG.TXT", 3, 48), ("GONE.BIN", 4, 33)):
    print(f"file {tag} size={n} fnv={fnv1a64(body(seed, n)):#x}")
print(f"NESTED.TXT first={NESTED_CL} hi={(NESTED_CL >> 16) & 0xFFFF} lo={NESTED_CL & 0xFFFF}")
print(f"lfn_checksum(AURORA~1TXT)={checksum(b'AURORA~1TXT'):#04x}")
# ---------------------------------------------------------------- 读回来复算（量具自检）
#
# 上面那些断言看的是"我打算写成什么"，这一节看的是"盘上现在是什么"。这两件事在本仓库里
# 分开过一次：BS 那一格把两个 u16 写进了 4 字节切片，bytearray 于是把整个引导扇区缩短了
# 4 字节，偏移 24 之后的每个字段整体错位、0x55AA 落到 508——而**所有写入前的断言全部通过**。
# 只信落盘字节，不信常量：下面每个数都从 `data` 里按规范偏移读回来。
data = OUT.read_bytes()
if len(data) != TOTAL * SEC:
    raise SystemExit(f"落盘 {len(data)} 字节 != {TOTAL * SEC}")


def g16(off):
    return struct.unpack_from("<H", data, off)[0]


def g32(off):
    return struct.unpack_from("<I", data, off)[0]


def g32_at(off):
    return struct.unpack_from("<I", data, off)[0]

if data[510:512] != bytes([0x55, 0xAA]):
    raise SystemExit("盘上 510:512 不是 0x55AA")
pbp = {"每簇扇区": (data[13], SPC), "保留扇区": (g16(14), RESERVED), "FAT份数": (data[16], FATS),
       "根目录项数": (g16(17), 0), "每份FAT16": (g16(22), 0), "总扇区32": (g32(32), TOTAL),
       "每份FAT32": (g32(36), SPF), "根簇": (g32(44), ROOT_CLUSTER), "FSInfo": (g16(48), FSINFO),
       "备份引导扇区": (g16(50), BACKUP)}
for tag, (got, want) in pbp.items():
    if got != want:
        raise SystemExit(f"盘上 BPB `{tag}` = {got}，配方写的是 {want} ⇒ 字段错位或宽度写错")
# FSInfo 与它的备份：三处签名逐个从盘上读回来（这块扇区是挂载的前置条件，漏一格全盘挂不上）。
for tag, base in (("FSInfo", g16(48)), ("FSInfo备份", g16(50) + 6)):  # 规范：备份引导扇区 + 6
    o = base * SEC
    got = (g32_at(o), g32_at(o + 484), data[o + 510:o + 512])
    if got != (0x4161_5252, 0x6141_7272, bytes([0x55, 0xAA])):
        raise SystemExit(f"盘上 {tag} 签名不对：{got}")
if data[BACKUP * SEC:BACKUP * SEC + SEC] != data[0:SEC]:
    raise SystemExit("备份引导扇区与主引导扇区不逐字节相同")

# 判型两把尺子必须同口径（ADR-109 拍板那一格要的正是这个）：按簇数落 Fat32 档，
# 且按结构（根项=0 / FAT16 每份=0 / FAT32 每份≠0）也算 FAT32。
data_sectors = g32(32) - (g16(14) + data[16] * g32(36))
cluster_count = data_sectors // data[13]
band = "Fat32" if cluster_count >= 65525 else ("Fat16" if cluster_count >= 4085 else "Fat12")
struct_fat32 = g16(17) == 0 and g16(22) == 0 and g32(36) != 0
if band != "Fat32" or not struct_fat32:
    raise SystemExit(f"这块卷没有同时满足两种 FAT32 判法：按簇数={band}({cluster_count}) 按结构={struct_fat32}")
if cluster_count != CLUSTERS:
    raise SystemExit(f"按盘上 BPB 算出的簇数 {cluster_count} != 配方里的 {CLUSTERS}")


def fat_at(c):
    return struct.unpack_from("<I", data, (g16(14) + (c % 128) // 128) * SEC + c * 4)[0]


def fat(c):
    base = (g16(14) + data[16] * g32(36)) * SEC
    return struct.unpack_from("<I", data, base + (c - 2) * SEC)[0]


def dentries(cluster, count=1):
    """沿簇链把目录项读回来：`count` 个扇区，每项 32 字节。"""
    out, c = [], cluster
    for _ in range(count):
        off = (g16(14) + data[16] * g32(36)) * SEC + (c - 2) * SEC
        for i in range(0, SEC, 32):
            e = data[off + i:off + i + 32]
            if e[0] == 0x00:
                return out
            out.append(e)
        c = fat_at(c)
    return out


def short(e):
    return (e[0:8].rstrip(b" ").decode("latin1"), e[8:11].rstrip(b" ").decode("latin1"))


root = dentries(g32(44))
names = [short(e) for e in root if e[11] != 0x0F and e[0] != 0xE5]
if ("SMALL", "BIN") not in names or ("PROJECT", "") not in names:
    raise SystemExit(f"根目录读回来少了项：{names}")
if any(short(e) == ("GONE", "BIN") for e in root if e[0] != 0xE5):
    raise SystemExit("GONE.BIN 的删除标记没生效")
proj = [e for e in root if short(e) == ("PROJECT", "")][0]
proj_cl = struct.unpack_from("<H", proj, 20)[0] << 16 | struct.unpack_from("<H", proj, 26)[0]
docs = [e for e in dentries(proj_cl) if short(e) == ("DOCS", "")][0]
docs_cl = struct.unpack_from("<H", docs, 20)[0] << 16 | struct.unpack_from("<H", docs, 26)[0]
if fat_at(docs_cl) != docs_cl + 1 or fat_at(docs_cl + 1) != EOC:
    raise SystemExit("DOCS 没有真的跨两簇（这一格的整件事就是跨簇）")
listed = dentries(docs_cl, 2)
nested = [i for i, e in enumerate(listed) if e[11] != 0x0F and short(e) == ("NESTED", "TXT")][0]
e = listed[nested]
first = struct.unpack_from("<H", e, 20)[0] << 16 | struct.unpack_from("<H", e, 26)[0]
if first != NESTED_CL or fat_at(first) != EOC:
    raise SystemExit(f"三级文件首簇两半拼出 {first}，期望 {NESTED_CL}（FAT 项 {fat_at(first):#x}）")
if struct.unpack_from("<H", e, 20)[0] == 0:
    raise SystemExit("三级文件的簇号高半是 0 ⇒ 这一格没有覆盖两半拼接")
# 子目录 LFN：LFN 那两条物理上紧邻**它们自己的**短名（这块卷上是 AURORA~1.TXT，
# 排在 NESTED 之后），校验和绑定的是那条短名的 8.3 字段。
alias = [i for i, x in enumerate(listed) if x[11] != 0x0F and short(x) == ("AURORA~1", "TXT")][0]
ae = listed[alias]
run = []
k = alias
while listed[k - 1][11] == 0x0F:
    run.append(listed[k - 1])
    k -= 1
run.reverse()                      # run[0] 是物理最前那条（序号最大、带 0x40）
if not run:
    raise SystemExit("短名前面没有 LFN 条目")
if [x[0] & 0x1F for x in run] != list(range(len(run), 0, -1)):
    raise SystemExit(f"LFN 序号物理顺序不对：{[x[0] & 0x1F for x in run]}")
if not run[0][0] & 0x40:
    raise SystemExit("LFN 物理首条没带 0x40")
want_sum = checksum(ae[0:11])
if {x[13] for x in run} != {want_sum}:
    raise SystemExit(f"LFN 校验和与短名不符：盘上 {run[0][13]:#x} 该是 {want_sum:#x}")
def units_of(x):
    # 规范里的 13 个单元分三段：偏移 1(5)、14(6)、28(2)。32:36 不是名字，是保留与 Next。
    return list(struct.unpack_from("<5H", x, 1)) + list(struct.unpack_from("<6H", x, 14)) \
        + list(struct.unpack_from("<2H", x, 28))


pieces = [None] * len(run)
for x in run:
    pieces[(x[0] & 0x1F) - 1] = units_of(x)   # 按**序号**落位，与物理顺序无关
if any(p is None for p in pieces):
    raise SystemExit(f"LFN 序号有缺：{[x[0] & 0x1F for x in run]}")
flat = [u for p in pieces for u in p]
name_units = []
for u in flat:
    if u == 0 or u == 0xFFFF:
        break
    name_units.append(chr(u))
long_read = "".join(name_units)
if long_read != LONG:
    raise SystemExit(f"长名读回 {long_read!r}，配方写的是 {LONG!r}")
# 深链读回来：从根目录的 D1 开始一层层 find，层数必须正好 CHAIN，底层那项必须是 F.TXT/8 字节。
depth, cur, last = 0, None, None
for e in dentries(g32(44)):
    if e[11] != 0x0F and short(e) == ("D1", ""):
        last = e
while last is not None and (last[11] & 0x10):
    depth += 1
    cl = struct.unpack_from("<H", last, 20)[0] << 16 | struct.unpack_from("<H", last, 26)[0]
    nxt = dentries(cl)
    if not nxt:
        raise SystemExit(f"深链第 {depth} 层没有条目")
    last = nxt[0]
if depth != CHAIN:
    raise SystemExit(f"深链读回只有 {depth} 层，配方写的是 {CHAIN}")
if short(last) != ("F", "TXT") or struct.unpack_from("<I", last, 28)[0] != 8:
    raise SystemExit(f"深链底层不是 F.TXT/8 字节：{short(last)}")
print(f"readback: clusters={cluster_count} band={band} struct_fat32={struct_fat32} "
      f"NESTED first={first} hi={struct.unpack_from('<H', e, 20)[0]} 长名={long_read!r} lfn={len(run)}条 校验和={want_sum:#04x}")
