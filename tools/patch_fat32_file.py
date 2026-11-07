"""把一块 FAT32 镜像里某个 8.3 文件的内容换成新字节（无 mtools 的替代路径）。

为什么需要这个脚本：两块真卷是**源**（`tools/fixtures/*.img.zz`），本机没有 mtools
（BACKLOG 78h-6 / 80f-1），而用户程序 `hello.elf` 一改，卷上那份 `HELLO.ELF` 就与内嵌夹具
分家——判定表第 36/38/39 行与宿主机对账都会红。这个脚本只做一件事：就地替换一个文件。

纪律（与仓库其它量具同一条）：
* **写前先算、写后重读**：结果由 `tools/aurora.py` 的独立解析器（`fat32_host_volume`）重算
  一遍，文件字节、大小、簇链、FNV 全对上才算成功；对不上就退出非零。
* 只做**增长**（必要时追加新簇）；缩短时把多余簇从链上摘掉并标 0，不回收目录项。
* 两份 FAT 与 FSInfo 一起改：只改第一份会让"两份 FAT 相同"这条隐含前提在下次重造时爆掉。

用法：
    python tools/patch_fat32_file.py <img> <NAME.EXT> <new-bytes-file>
"""
import pathlib
import sys


def u16(b, o):
    return int.from_bytes(b[o:o + 2], "little")


def u32(b, o):
    return int.from_bytes(b[o:o + 4], "little")


def put32(b, o, v):
    b[o:o + 4] = (v & 0xFFFF_FFFF).to_bytes(4, "little")


EOC = 0x0FFF_FFFF
MASK = 0x0FFF_FFFF


def patch(path: pathlib.Path, name: str, content: bytes) -> None:
    img = bytearray(path.read_bytes())
    bps = u16(img, 11)
    if bps != 512:
        sys.exit(f"{path.name}: 每扇区 {bps} 字节，本脚本只处理 512")
    spc = img[13]
    res = u16(img, 14)
    fats = img[16]
    spf = u32(img, 36)
    root = u32(img, 44)
    total = u16(img, 19) or u32(img, 32)
    data_start = res + fats * spf
    clusters = (total - data_start) // spc
    cbytes = spc * bps
    fat_off = res * bps
    fat_bytes = spf * bps

    def fat_get(c):
        return u32(img, fat_off + c * 4) & MASK

    def coff(c):
        return (data_start + (c - 2) * spc) * bps

    def chain_of(first):
        out, c, seen = [], first, 0
        while 2 <= c < 0x0FFF_FFF8:
            out.append(c)
            seen += 1
            if seen > clusters:
                sys.exit("簇链成环或损坏：拒绝改一块我看不懂的卷")
            c = fat_get(c)
        return out

    want8 = name.split(".")[0].ljust(8)[:8].encode("latin1")
    want3 = (name.split(".") + [""])[1].ljust(3)[:3].encode("latin1")
    entry = None
    for c in chain_of(root):
        blk = img[coff(c):coff(c) + cbytes]
        for o in range(0, len(blk), 32):
            e = blk[o:o + 32]
            if e[0] == 0x00:
                break
            if e[11] == 0x0F or e[0] == 0xE5 or e[11] & 0x08 or e[11] & 0x10:
                continue
            if e[0:8].rstrip() == want8.rstrip() and e[8:11].rstrip() == want3.rstrip():
                entry = (coff(c) + o, e)
                break
        if entry:
            break
    if not entry:
        sys.exit(f"{path.name}: 根目录里没有 {name}")
    ent_off, e = entry
    first = (u16(e, 20) << 16) | u16(e, 26)
    old_size = u32(e, 28)
    chain = chain_of(first)
    need = (len(content) + cbytes - 1) // cbytes
    have = len(chain)
    print(f"{path.name}: {name} 首簇={first} 旧大小={old_size} 链={have} 新需要={need} 簇字节={cbytes}")
    if need == 0:
        put32(img, fat_off + first * 4, EOC)
        for c in chain[1:]:
            put32(img, fat_off + c * 4, 0)
        chain = [first]
        have = 1
    elif need < have:
        for c in chain[need:]:
            put32(img, fat_off + c * 4, 0)
        put32(img, fat_off + chain[need - 1] * 4, EOC)
        chain = chain[:need]
        have = need
    elif need > have:
        free = [c for c in range(2, clusters + 2) if fat_get(c) == 0]
        add = need - have
        if len(free) < add:
            sys.exit(f"{path.name}: 需要 {add} 个新簇，只有 {len(free)} 个空闲")
        take = free[:add]
        put32(img, fat_off + chain[-1] * 4, take[0])
        for i, c in enumerate(take):
            put32(img, fat_off + c * 4, take[i + 1] if i + 1 < len(take) else EOC)
        chain += take
        fsinfo = u16(img, 48)
        free_before = u32(img, fsinfo * bps + 488)
        put32(img, fsinfo * bps + 488, max(0, free_before - add))
        put32(img, fsinfo * bps + 492, take[-1] + 1)
        print(f"{path.name}: 追加 {add} 簇 {take[0]}..{take[-1]}")

    off = 0
    for c in chain:
        room = min(cbytes, len(content) - off) if off < len(content) else 0
        img[coff(c):coff(c) + room] = content[off:off + room]
        if room < cbytes:
            img[coff(c) + room:coff(c) + cbytes] = b"\x00" * (cbytes - room)
        off += room
    if off != len(content):
        sys.exit(f"{path.name}: 写完 {off} 字节，应为 {len(content)}")

    put32(img, ent_off + 28, len(content))
    for i in range(1, fats):
        img[(res + i * spf) * bps:(res + i * spf) * bps + fat_bytes] = \
            img[fat_off:fat_off + fat_bytes]

    path.write_bytes(bytes(img))
    print(f"{path.name}: 已写入 {len(content)} 字节，链={len(chain)} 簇；请用解析器复验")


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 2
    patch(pathlib.Path(sys.argv[1]), sys.argv[2], pathlib.Path(sys.argv[3]).read_bytes())
    return 0


if __name__ == "__main__":
    sys.exit(main())
