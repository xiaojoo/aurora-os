"""造一块**只给 GPT 解析用例读**的小夹具盘（W4 S1，ADR-078 决策 7 的载体）。

为什么需要它（实测出来的，不是设计偏好）：引导盘上的 GPT 改不动——
OVMF/EDK2 启动时会**用备份表把主表修回原值**（数组首字节 0x29 改下去、跑完读回 0x28），
所以"数组 CRC/头 CRC/entry_count/备份不一致"四条注入根本到不了内核；
而"保护性 MBR 类型"与"ESP first_lba"两条固件治不好 ⇒ NOBOOT，连内核都起不来。
六条负样本因此必须落在一块**固件永远不会碰**的盘上。

这块盘挂 AHCI 口 1（`if=ide,index=1`，口号映射沿用 scratch/FAT 那两格**实测过**的关系），
只在 `gpt-probe` 档挂。它里面**没有文件系统**——GPT 解析不挂载，分区区里填确定性图案，
所以不需要 FAT，也不需要 mtools（本机没有）。

与 `tools/esp_image.py` 的关系：**故意各写一份偏移表**。那边是引导盘的写表器、这边是夹具的写表器，
而读表对账那一台是 `tools/validate_esp.py`（它谁都不 import）。三台分开才证得动"两边错得一样"。

用法：python tools/make_gpt_disk.py build/gpt-fixture.img
"""

from __future__ import annotations

import binascii
import hashlib
import struct
import sys
from pathlib import Path

SECTOR = 512
DISK_SECTORS = 8192                     # 4 MiB：装得下两份 16 KiB 条目数组与两个分区
ENTRY_COUNT = 128
ENTRY_SIZE = 128
FIRST_USABLE = 34
LAST_USABLE = DISK_SECTORS - 34         # 8158
BACKUP_ARRAY_LBA = DISK_SECTORS - 33    # 8159
BACKUP_HEADER_LBA = DISK_SECTORS - 1    # 8191

# 两个**不同类型**的分区：ESP 那条用来证 find_esp，另一条用来证"按 GUID 找到的不是第一条就算"。
# 只放一条的话，"找对了"与"返回了第一条"长得一样（空转）。
ESP_TYPE_GUID = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
DATA_TYPE_GUID = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
DISK_GUID = "a1b2c3d4-e5f6-4788-9abc-def012345678"
ESP_UNIQUE = "11111111-2222-4333-8444-555555555555"
DATA_UNIQUE = "66666666-7777-4888-9999-aaaaaaaaaaaa"
ESP_FIRST, ESP_LAST = 34, 4127          # 2 MiB
DATA_FIRST, DATA_LAST = 4128, 8158      # 余下全部


def guid_bytes(text: str) -> bytes:
    a, b, c, d, e = text.split("-")
    return (struct.pack("<I", int(a, 16)) + struct.pack("<H", int(b, 16))
            + struct.pack("<H", int(c, 16)) + bytes.fromhex(d + e))


def entry(type_guid: str, unique: str, first: int, last: int, name: str) -> bytes:
    e = bytearray(ENTRY_SIZE)
    e[0:16] = guid_bytes(type_guid)
    e[16:32] = guid_bytes(unique)
    struct.pack_into("<Q", e, 32, first)
    struct.pack_into("<Q", e, 40, last)
    struct.pack_into("<Q", e, 48, 0)
    n = name.encode("utf-16-le")
    assert len(n) <= 72, f"分区名过长: {len(n)}"
    e[56:56 + len(n)] = n
    # 断言尺寸而不是依赖切片语义：esp_image 那边被切片赋值撑大过一次（128→132），
    # 于是 CRC 覆盖的字节数与盘上的不同，EDK2 判整张表无效。
    assert len(e) == ENTRY_SIZE, f"条目被意外改成 {len(e)} 字节"
    return bytes(e)


def header(my_lba: int, alternate: int, entry_lba: int, array_crc: int) -> bytes:
    h = bytearray(92)
    h[0:8] = b"EFI PART"
    struct.pack_into("<I", h, 8, 0x00010000)
    struct.pack_into("<I", h, 12, 92)
    struct.pack_into("<I", h, 16, 0)                 # 先清零，算完再回填
    struct.pack_into("<Q", h, 24, my_lba)
    struct.pack_into("<Q", h, 32, alternate)
    struct.pack_into("<Q", h, 40, FIRST_USABLE)
    struct.pack_into("<Q", h, 48, LAST_USABLE)
    h[56:72] = guid_bytes(DISK_GUID)
    struct.pack_into("<Q", h, 72, entry_lba)
    struct.pack_into("<I", h, 80, ENTRY_COUNT)
    struct.pack_into("<I", h, 84, ENTRY_SIZE)
    struct.pack_into("<I", h, 88, array_crc)
    struct.pack_into("<I", h, 16, binascii.crc32(bytes(h)) & 0xFFFFFFFF)
    return bytes(h)


def build() -> bytes:
    img = bytearray(DISK_SECTORS * SECTOR)
    mbr = bytearray(SECTOR)
    mbr[446 + 4] = 0xEE
    struct.pack_into("<I", mbr, 446 + 8, 1)
    struct.pack_into("<I", mbr, 446 + 12, min(DISK_SECTORS - 1, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"
    img[0:SECTOR] = mbr

    array = (entry(ESP_TYPE_GUID, ESP_UNIQUE, ESP_FIRST, ESP_LAST, "FIX ESP")
             + entry(DATA_TYPE_GUID, DATA_UNIQUE, DATA_FIRST, DATA_LAST, "FIX DATA")
             + bytes(ENTRY_SIZE * (ENTRY_COUNT - 2)))
    assert len(array) == ENTRY_COUNT * ENTRY_SIZE
    crc = binascii.crc32(array) & 0xFFFFFFFF
    img[2 * SECTOR:2 * SECTOR + len(array)] = array
    img[BACKUP_ARRAY_LBA * SECTOR:BACKUP_ARRAY_LBA * SECTOR + len(array)] = array
    img[1 * SECTOR:1 * SECTOR + 92] = header(1, BACKUP_HEADER_LBA, 2, crc)
    img[BACKUP_HEADER_LBA * SECTOR:BACKUP_HEADER_LBA * SECTOR + 92] = header(
        BACKUP_HEADER_LBA, 1, BACKUP_ARRAY_LBA, crc)

    # 分区区里填确定性图案：全零的话"读到了分区内容"与"什么都没读"长得一样。
    # 这里只为了夹具可复现与非零，GPT 解析本身无调用者读它。
    for first, last in ((ESP_FIRST, ESP_LAST), (DATA_FIRST, DATA_LAST)):
        for lba in range(first, last + 1):
            off = lba * SECTOR
            img[off:off + SECTOR] = bytes(((lba * 7 + i * 13) & 0xFF) for i in range(SECTOR))
    return bytes(img)


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "build/gpt-fixture.img")
    data = build()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    print(f"GPT 夹具盘: {out} {len(data)} 字节 sha256={hashlib.sha256(data).hexdigest()}")
    print(f"  几何: {DISK_SECTORS} 扇区 first_usable={FIRST_USABLE} last_usable={LAST_USABLE} "
          f"条目 {ENTRY_COUNT}×{ENTRY_SIZE} 备份阵列 LBA={BACKUP_ARRAY_LBA} 备份头 LBA={BACKUP_HEADER_LBA}")
    print(f"  分区: ESP {ESP_FIRST}..{ESP_LAST} / DATA {DATA_FIRST}..{DATA_LAST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())