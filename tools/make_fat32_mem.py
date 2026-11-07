"""造 L3-C② 的内存夹具卷 kernel/fixtures/fat32-mem.img。

为什么这块卷不能用 mtools 造：mformat 拒绝做簇数少于 65,525 的 FAT32 卷（它按微软那条
经验阈值判型）。这一块的用途不是"另一台设备"，而是**便宜的分支覆盖**：真卷上一次走链要发
几百条块命令，而这里的读是一次内存拷贝，所以 65,536 簇上界、环链、簇号越界这些
"真卷上要么贵要么造不出来"的分支才有地方跑。偏移表的可信度由另一处担保：同一套
`parse_boot_sector` 必须也把 mtools 造的两块真卷读成同样的形状（`KT_FAT32` 的卷A/卷B）。

布局（全部 512 字节扇区，簇 = 1 扇区）：

| 扇区 | 内容 |
|---|---|
| 0 | 引导扇区（BPB）|
| 1 | FSInfo |
| 6 | 备份引导扇区（必须与 0 逐字节相同）|
| 8, 9 | FAT 两份（相同）|
| 10 + (n-2) | 簇 n 的数据 |

| 簇 | 用来判哪一格 |
|---|---|
| 2 | 根目录（下面那张表）|
| 3-6 | LONG~1.TXT：4 簇、2000 字节 ⇒ 尾格 464，`tail_bytes` 有非平凡值 |
| 7 | NOSHORT：没有扩展名的名字（`name_matches` 不补那个点）|
| 8,9,10 | CYCLIC.BIN：8→9→10→**9** 成环，size=0xFFFF_FFFF ⇒ 走链必须撞到 `ChainTooLong` |
| 12 | SHORTCHAIN.BIN：size=4096 而链只有 1 簇 ⇒ `ChainEndsEarly` |
| 13 | 环链的第三步落点（10→9 之后继续走）|

根目录 32 字节条目（顺序就是 `entries_seen` 的顺序）：

| # | 名字 | attr | 簇 | 大小 | 这一格存在的理由 |
|---|---|---|---|---|---|
| 0 | MYVOLUME | 0x08 卷标 | 0 | 0 | 卷标条目必须被跳过 |
| 1-2 | （两条 LFN）| 0x0F | 0 | 0 | LFN **计数**那格有人走过，虽然长名本身没实现 |
| 3 | LONG~1.TXT | 0x20 | 3 | 2000 | 8.3 名字命中，而 lfn_entries==2 |
| 4 | 0xE5 GONE.BIN | 0x20 | 12 | 512 | 已删除条目必须被跳过（但仍计入扫过的项数）|
| 5 | 0x05 OLD.TXT | 0x20 | 7 | 10 | 首字节 0x05 ⇒ 名字按 '?' 起头（盘上第一位的 `O` 已被那个标记**吃掉**，所以能查到的名字是 `?LD.TXT`，不是 `?OLD.TXT`）|
| 6 | MYDIR | 0x10 目录 | 12 | 0 | 子目录今天不交付，必须被跳过而不是当成文件 |
| 7 | NOSHORT | 0x20 | 7 | 10 | 无扩展名 |
| 8 | CYCLIC.BIN | 0x20 | 8 | 0xFFFF_FFFF | 环链必须有界 |
| 9 | SHORTCHAIN.BIN | 0x20 | 12 | 4096 | 链比元数据短 |
| 10 | BADCLU.BIN | 0x20 | 0x0FFF_FFF8 | 512 | 目录项的簇号落在 EOC/坏簇区 ⇒ 拒 |
| 11 | 首字节 0x00 | — | — | — | 目录结束 |
"""
import hashlib
import pathlib

# 相对仓库根，而不是本机绝对路径：`kernel/fixtures/*.img` 被 .gitignore 挡着（那条规则挡的是
# 构建产物，顺带把这块夹具卷也挡了），所以**这块卷只在这台机器上存在**——能被重新算出来的东西
# 才允许不进仓库。`tools/aurora.py` 在带 `fat32-probe` 构建之前会调本脚本并把结果与登记指纹比，
# 于是"克隆下来编不出这个变体"和"配方与镜像悄悄分家"两件事都红在构建那一步，而不是红在解析器。
OUT = pathlib.Path(__file__).resolve().parents[1] / "kernel" / "fixtures" / "fat32-mem.img"
SEC = 512
RESERVED = 8
FAT_C = 2
SPF = 1
DATA_START = RESERVED + FAT_C * SPF          # 10
CLUSTERS = 12                                # 簇 2..13
TOTAL = DATA_START + CLUSTERS                # 22

ent = lambda c: DATA_START + c - 2


def u16(v):
    return (v & 0xFF, (v >> 8) & 0xFF)


def u32(v):
    return (v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF)


def dentry(name8, ext3, attr, cluster, size, first=None):
    """一条 32 字节的 8.3 目录项。`first` 直接覆盖首字节（造 0xE5/0x05 那两种特殊值）。"""
    b = bytearray(32)
    # 名字与扩展名**一律用空格补齐**：真卷就是这么写的，而 `name_matches` 是靠那个空格停下的。
    # 用 NUL 补齐会让无扩展名的项拼出"NOSHORT"后面跟三个 NUL，用例永远匹配不上——那是夹具在骗人。
    b[0:8] = name8.ljust(8)[:8].encode("latin1")
    b[8:11] = ext3.ljust(3)[:3].encode("latin1")
    b[11] = attr
    b[20:22] = u16((cluster >> 16) & 0xFFFF)  # 簇号高半
    b[26:28] = u16(cluster & 0xFFFF)          # 簇号低半
    b[28:32] = u32(size)
    if first is not None:
        b[0] = first
    return bytes(b)


def lfn(seq, chars):
    """一条 LFN 条目：attr=0x0F、序号在首字节、UCS-2 名字散在 1..10/14..25/28..31。"""
    b = bytearray(32)
    b[0] = seq                  # 调用方把 0x40（"这是最后一条"）并进序号里；解析器只看 attr
    b[11] = 0x0F
    # UCS-2 的名字散在三段里：字节 1..10（5 个字符）、14..25（6 个）、28..31（2 个）= 13 个字符
    slots = [1, 3, 5, 7, 9] + [14, 16, 18, 20, 22, 24] + [28, 30]
    for i, off in enumerate(slots):
        ch = ord(chars[i]) if i < len(chars) else 0
        b[off] = ch & 0xFF
        b[off + 1] = (ch >> 8) & 0xFF
    b[13] = 0x00      # 保留字节；解析器不读它，写出来只为形状像真卷
    return bytes(b)


img = bytearray(TOTAL * SEC)

# ---------------------------------------------------------------- 引导扇区（BPB）
bs = bytearray(SEC)
bs[0:3] = b"\xEB\x58\x90"          # 跳转nop：mformat 也写这三字节，内容没人判
bs[3:11] = b"MSDOS5.0"             # OEM 名：只打印不判
bs[11:13] = u16(SEC)               # bytes/sector
bs[13] = 1                         # sectors/cluster
bs[14:16] = u16(RESERVED)
bs[16] = FAT_C
bs[17:19] = u16(0)                 # root_entries = 0 ⇒ FAT32 的结构证据之一
bs[19:21] = u16(0)                 # total sectors 16：留 0，让 32 那格生效
bs[21] = 0xF8                      # media
bs[22:24] = u16(0)                 # sectors/FAT 16 = 0 ⇒ 结构证据之二
bs[32:36] = u32(TOTAL)
bs[36:40] = u32(SPF)               # sectors/FAT 32 非 0 ⇒ 结构证据之三
bs[44:48] = u32(2)                 # root cluster
bs[48:50] = u16(1)                 # FSInfo
bs[50:52] = u16(6)                 # 备份引导扇区
bs[64] = 0x80                      # drive number
bs[66] = 0x29                      # BS_BootSig：扩展字段在位
bs[82:89] = b"FAT32  "
bs[510] = 0x55
bs[511] = 0xAA
img[0:SEC] = bs
img[6 * SEC:7 * SEC] = bs          # 备份 = 逐字节相同

# ---------------------------------------------------------------- FSInfo
fi = bytearray(SEC)
fi[0:4] = u32(0x4161_5252)
fi[484:488] = u32(0x6141_7272)
fi[488:492] = u32(CLUSTERS - 9)    # 自由簇数（自报，只打印不判）
fi[492:496] = u32(14)
fi[510] = 0x55
fi[511] = 0xAA
img[1 * SEC:2 * SEC] = fi

# ---------------------------------------------------------------- FAT
fat = bytearray(SEC)
for i in range(CLUSTERS):
    fat[i * 4:i * 4 + 4] = u32(0x0FFF_FFF7)  # 未用到的簇填"坏簇"，不留 0（0 会被当簇号）
fat[0:4] = u32(0x0FFF_FFF8)        # 保留 0：介质描述符
fat[4:8] = u32(0x0FFF_FFFF)        # 保留 1
root = 2 * 4
fat[root:root + 4] = u32(0x0FFF_FFF8)   # 簇 2 = 根目录，链尾
hello = 3 * 4
for c in (3, 4, 5):                       # FILE.BIN 3->4->5->6->EOC
    fat[c * 4:c * 4 + 4] = u32(c + 1)
fat[6 * 4:6 * 4 + 4] = u32(0x0FFF_FFF8)
fat[7 * 4:7 * 4 + 4] = u32(0x0FFF_FFF8)   # NOSHORT / OLD.TXT 单簇
fat[8 * 4:8 * 4 + 4] = u32(9)             # 环：8 -> 9
fat[9 * 4:9 * 4 + 4] = u32(10)            #     9 -> 10
fat[10 * 4:10 * 4 + 4] = u32(9)           #    10 -> 9  ⇒ 回到 9，永远走不完
fat[12 * 4:12 * 4 + 4] = u32(0x0FFF_FFF8)  # SHORTCHAIN 只有一簇
fat[13 * 4:13 * 4 + 4] = u32(0x0FFF_FFF8)
img[RESERVED * SEC:RESERVED * SEC + SEC] = fat
img[(RESERVED + 1) * SEC:(RESERVED + 2) * SEC] = fat   # 第二份 FAT 同样内容

# ---------------------------------------------------------------- 根目录
names = [
    dentry("MYVOLUME", "", 0x08, 0, 0),
    lfn(0x42, "LongNameFile"),  # 集合里最后一条（0x40 那一位在位）
    lfn(0x01, "LongNameFile"),
    dentry("LONG~1", "TXT", 0x20, 3, 2000),
    dentry("GONE", "BIN", 0x20, 12, 512, first=0xE5),
    dentry("OLD", "TXT", 0x20, 7, 10, first=0x05),
    dentry("MYDIR", "", 0x10, 12, 0),
    dentry("NOSHORT", "", 0x20, 7, 10),
    dentry("CYCLIC", "BIN", 0x20, 8, 0xFFFF_FFFF),
    dentry("SHORTCHN", "BIN", 0x20, 12, 4096),
    dentry("BADCLU", "BIN", 0x20, 0x0FFF_FFF8, 512),
    b"\x00" * 32,
]
root_bytes = b"".join(names)
assert len(root_bytes) == 12 * 32, len(root_bytes)
img[ent(2) * SEC:ent(2) * SEC + len(root_bytes)] = root_bytes

# ---------------------------------------------------------------- 文件内容
# LONG~1.TXT 的 2000 字节：值 = (扇区序号*29 + 扇区内偏移*3 + 0x11) & 0xFF，宿主机与内核各自重算。
# 逐扇区项 扇区序号*29 不可省：只按文件偏移算的话，512*3 ≡ 0 (mod 256)，相邻扇区内容逐字节
# 相同——多扇区簇读错扇区也判绿（P7 审查抓到的夹具盲点）。29 是奇数，保证每扇区第 0 字节就不同。
for off in range(2000):
    img[ent(3) * SEC + off] = ((off // SEC) * 29 + (off % SEC) * 3 + 0x11) & 0xFF
for off in range(10):
    img[ent(7) * SEC + off] = (off * 5 + 0x77) & 0xFF

data = bytes(img)
# 只在字节真变了时才写：`include_bytes!` 的依赖挂在 mtime 上，每次无条件重写会让内核每次
# 全量重编（`do_build_user` 对 hello.elf 那条是同一个理由）。
changed = not OUT.exists() or OUT.read_bytes() != data
if changed:
    OUT.write_bytes(data)
print(f"写出 {OUT.relative_to(OUT.parents[2])}  {len(data)} 字节  扇区={TOTAL} 数据起点={DATA_START} "
      f"簇数={CLUSTERS}  sha256={hashlib.sha256(data).hexdigest()[:12]} "
      f"{'（已更新）' if changed else '（与现有夹具一致）'}")
print(f"根目录条目 {len(names)} 条（含两条 LFN、一条已删除、一条目录、一条 EOC）")
print("LONG~1.TXT 尾格字节数 =", 2000 - 3 * 512, " 走簇数 =", 4)
