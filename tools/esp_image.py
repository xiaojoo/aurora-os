"""GPT + FAT16 ESP 镜像生成器（纯 Python，无第三方依赖）。

为什么需要它：本机走“纯 Windows 便携链”，没有 mtools / mkfs.vfat / xorriso；
而 GitHub 的 release 资产主机不可达，拿不到现成镜像工具。

三条硬依据（不是偏好）：
  1. Limine 11.4.1 只认 FAT12/16/32 与 ISO9660，所以做 FAT16。
  2. 配置文件名 `limine.conf` 的扩展名有 4 个字符，**塞不进 8.3**（FAT 扩展名字段只有
     3 字节）。因此必须写 VFAT 长名条目；短名同时写 `LIMINE CON`，让只认 8.3 的驱动
     也有机会命中。Limine 的 FAT 驱动是否实现 LFN **未核实**，所以两条路都留着。
  3. 写出去的东西一律由 read_back() 独立读回来比对，不“算完就当写对了”。

对外只有两个函数：build_disk() 与 read_back()。
"""

from __future__ import annotations

import binascii
import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path

SECTOR = 512
CLUSTER_SECTORS = 8                 # 4 KiB 簇
RESERVED_SECTORS = 32
ROOT_ENTRIES = 512
ROOT_DIR_SECTORS = (ROOT_ENTRIES * 32 + SECTOR - 1) // SECTOR
ATTR_RO, ATTR_HIDDEN, ATTR_SYS, ATTR_VOL, ATTR_DIR, ATTR_ARCHIVE = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
ATTR_LFN = 0x0F
FAT16_EOC = 0xFFFF
FAT16_BAD = 0xFFF7
ESP_START_LBA = 2048
# 内核持久状态区。**必须与 kernel/src/state_store.rs 的两个同名常量同数**
# （`tools/aurora.py check` 的 `check-state-window` 逐字对账两边，理由同 DEBUGEXIT_PORT）
STATE_START_LBA = 67_648           # ESP 卷（2048+65536）之后，留一点余量
STATE_SECTORS = 8                  # 8 个 512 字节的槽 = 4 KiB
GPT_HEADER_LBA = 1
GPT_ENTRY_COUNT = 128
GPT_ENTRY_SIZE = 128
ESP_TYPE_GUID = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
DISK_GUID = "01234567-89ab-cdef-0123-456789abcdef"
ESP_GUID = "0badf00d-dead-beef-0123-456789abcdef"


# ------------------------------------------------------------------- 持久状态区
#
# 这份记录格式与 `kernel/src/state_store.rs` 是**两台仪器**：宿主机在这里把它写进镜像、
# 事后又按同一套偏移解一遍，内核在另一边解。哪一侧的偏移或宽度错了，对账当场就红。
# 校验和用的是内核那侧的 FNV-1a 64（`tools/aurora.py` 里已有同一个实现）。

STATE_MAGIC = 0x4253_5541
STATE_VERSION = 1
STATE_VERSION2 = 2
STATE_KIND_BOOT = 1
STATE_KIND_CRASH = 2
STATE_KIND_LOG = 3
STATE_HDR = 24
STATE_PAYLOAD = 28
# V2 崩溃记录：固定 64 字节 + 每帧 8 字节，最多 32 帧（内核侧同名常量在 state_store.rs）
CRASH_FIXED = 64
MAX_FRAMES = 32
# V2 最近日志（kind=3）：固定 16 字节（crash_seq/lines/bytes）+ 文本，文本上限 464
# 内核侧那个上限是推导的（`MAX_PAYLOAD - LOG_FIXED`），对账由 check-state-window 现算一遍
LOG_FIXED = 16
LOG_TEXT_MAX = 464
_FNV_OFFSET = 0xCBF2_9CE4_8422_2325
_FNV_PRIME = 0x0000_0100_0000_01B3
_MASK64 = (1 << 64) - 1


def fnv1a64(data: bytes) -> int:
    h = _FNV_OFFSET
    for b in data:
        h = ((h ^ b) * _FNV_PRIME) & _MASK64
    return h


def state_encode(kind: int, seq: int, failed: int, good: int, bad: int, vector: int, cpu: int, rip: int) -> bytes:
    body = struct.pack("<IIIII", failed, good, bad, vector, cpu) + struct.pack("<Q", rip)
    assert len(body) == STATE_PAYLOAD, f"payload 长度 {len(body)} != {STATE_PAYLOAD}"
    buf = bytearray(512)
    struct.pack_into("<IIII", buf, 0, STATE_PAYLOAD, STATE_MAGIC, STATE_VERSION, kind)
    struct.pack_into("<Q", buf, 16, seq)
    buf[STATE_HDR:STATE_HDR + STATE_PAYLOAD] = body
    used = STATE_HDR + STATE_PAYLOAD
    struct.pack_into("<Q", buf, used, fnv1a64(bytes(buf[:used])))
    return bytes(buf)


def crash_encode_crash(seq: int, rec: dict) -> bytes:
    """按内核 `encode_crash` 同一套偏移编一条 V2 崩溃记录（宿主机这边只用来自检/对账）。"""
    frames = rec.get("frames", [])
    n = len(frames)
    assert n <= MAX_FRAMES, f"帧数 {n} 超过 {MAX_FRAMES}"
    size = CRASH_FIXED + 8 * n
    buf = bytearray(512)
    struct.pack_into("<IIII", buf, 0, size, STATE_MAGIC, STATE_VERSION2, STATE_KIND_CRASH)
    struct.pack_into("<Q", buf, 16, seq)
    struct.pack_into("<IIII", buf, STATE_HDR, rec["vector"], rec["error_code"], rec["cpu"], rec.get("module_id", 0))
    struct.pack_into("<IIII", buf, STATE_HDR + 16, rec.get("fault_level", 4), rec.get("thread_id", 0),
                     rec.get("process_id", 0), n)
    struct.pack_into("<QQQQ", buf, STATE_HDR + 32, rec["rip"], rec["rsp"], rec.get("rbp", 0), rec.get("cr2", 0))
    for i, f in enumerate(frames):
        struct.pack_into("<Q", buf, STATE_HDR + CRASH_FIXED + 8 * i, f)
    used = STATE_HDR + size
    struct.pack_into("<Q", buf, used, fnv1a64(bytes(buf[:used])))
    return bytes(buf)


def log_encode_log(seq: int, crash_seq: int, lines: int, text: bytes) -> bytes:
    """按内核 `encode_log` 同一套偏移编一条 V2 最近日志记录。
    宿主机拿它做两种事：正常记录（自写自解必须过）与**故意自相矛盾**的记录
    （编完之后自己改字段再重算校验和，让红的原因落在自洽检查而不是校验和上）。"""
    n = len(text)
    assert n <= LOG_TEXT_MAX, f"日志文本 {n} 超过 {LOG_TEXT_MAX}"
    size = LOG_FIXED + n
    buf = bytearray(512)
    struct.pack_into("<IIII", buf, 0, size, STATE_MAGIC, STATE_VERSION2, STATE_KIND_LOG)
    struct.pack_into("<Q", buf, 16, seq)
    struct.pack_into("<QII", buf, STATE_HDR, crash_seq, lines, n)
    buf[STATE_HDR + LOG_FIXED:STATE_HDR + LOG_FIXED + n] = text
    used = STATE_HDR + size
    struct.pack_into("<Q", buf, used, fnv1a64(bytes(buf[:used])))
    assert state_decode(buf).get("seq") == seq, "自写自解都要过，否则两边镜像实现早就分叉了"
    return bytes(buf)


def state_decode(buf: bytes) -> dict:
    """解一条记录；不可解就返回 {'why': ...}。上界检查照内核侧同一条规矩做。

    两个版本都认：V1 是那 28 字节的启动状态，V2 是变长的崩溃记录。
    **两边的拒与放必须逐条同判** —— 内核侧多了一条"声明帧数要与长度自洽"的检查，
    这里也必须有；否则同一块盘上两台仪器会给出两种结论，而那正是对账要防的事。
    """
    size, magic, version, kind = struct.unpack_from("<IIII", buf, 0)
    if magic != STATE_MAGIC:
        return {"why": f"magic={magic:#x}"}
    if version not in (STATE_VERSION, STATE_VERSION2):
        return {"why": f"version={version}"}
    if size == 0 or STATE_HDR + size + 8 > len(buf):
        return {"why": f"size={size} 出界"}
    used = STATE_HDR + size
    want = fnv1a64(buf[:used])
    if struct.unpack_from("<Q", buf, used)[0] != want:
        return {"why": "校验和不符"}
    seq = struct.unpack_from("<Q", buf, 16)[0]
    if version == STATE_VERSION:
        failed, good, bad, vector, cpu = struct.unpack_from("<IIIII", buf, STATE_HDR)
        return {"kind": kind, "seq": seq, "version": 1, "failed": failed,
                "good": good, "bad": bad, "vector": vector, "cpu": cpu,
                "rip": struct.unpack_from("<Q", buf, STATE_HDR + 20)[0]}
    # V2 的两种载荷形状靠 kind 分家；内核侧同样是"扫描按 kind 过滤，再各自类型化解码"
    if kind == STATE_KIND_LOG:
        if size < LOG_FIXED:
            return {"why": "载荷比固定段还短"}
        nbytes = size - LOG_FIXED
        if nbytes > LOG_TEXT_MAX:
            return {"why": f"日志文本 {nbytes} 越界"}
        if struct.unpack_from("<I", buf, STATE_HDR + 12)[0] != nbytes:
            return {"why": "声明长度与长度不自洽"}
        text = bytes(buf[STATE_HDR + LOG_FIXED:STATE_HDR + LOG_FIXED + nbytes])
        if nbytes and text[-1] != 0x0A:
            return {"why": "末行不完整"}
        lines = struct.unpack_from("<I", buf, STATE_HDR + 8)[0]
        if text.count(b"\n") != lines:
            return {"why": f"行数 {lines} 与换行符数不符"}
        return {"kind": kind, "seq": seq, "version": 2,
                "crash_seq": struct.unpack_from("<Q", buf, STATE_HDR)[0],
                "lines": lines, "bytes": nbytes, "text": text, "failed": None}
    # V2：先验长度自洽，再按帧数取栈
    if size < CRASH_FIXED:
        return {"why": "载荷比固定段还短"}
    if (size - CRASH_FIXED) % 8 != 0:
        return {"why": "帧数与长度不整除"}
    frames_n = (size - CRASH_FIXED) // 8
    if frames_n > MAX_FRAMES:
        return {"why": f"帧数 {frames_n} 越界"}
    declared = struct.unpack_from("<I", buf, STATE_HDR + 28)[0]
    if declared != frames_n:
        return {"why": f"声明帧数 {declared} 与长度不自洽"}
    vector, error_code, cpu, module_id = struct.unpack_from("<IIII", buf, STATE_HDR)
    fault_level, thread_id, process_id, _n = struct.unpack_from("<IIII", buf, STATE_HDR + 16)
    rip, rsp, rbp, cr2 = struct.unpack_from("<QQQQ", buf, STATE_HDR + 32)
    frames = [struct.unpack_from("<Q", buf, STATE_HDR + CRASH_FIXED + 8 * i)[0] for i in range(frames_n)]
    return {"kind": kind, "seq": seq, "version": 2, "vector": vector, "error_code": error_code,
            "cpu": cpu, "module_id": module_id, "fault_level": fault_level, "thread_id": thread_id,
            "process_id": process_id, "frame_count": frames_n, "frames": frames,
            "rip": rip, "rsp": rsp, "rbp": rbp, "cr2": cr2,
            # 启动状态那六个字段在 V2 里没有位置；留一个 None 让调用方区分"没这个字段"
            # 与"这个字段是 0"（对账时把 0 当成缺字段是假通过）
            "failed": None}


def seed_state_region(img: bytearray) -> None:
    """镜像生成时把槽 0 写成一条**有效**的初始记录（failed=0，seq=1）。

    为什么不能留全 0：§9.4 的第一条硬规矩是"读不到就按最坏情况处理"，而最坏情况 = 直接进
    安全模式。留全 0 等于让每一块新盘的第一次启动都进安全模式 —— 那是把"未知"当成"坏"，
    而不是当成"新"。装机时写一条初始记录，才是这份存储的正常起点；而"读不到"仍然保留给
    真的坏掉的情形（用例里就打了那种）。
    """
    rec = state_encode(STATE_KIND_BOOT, 1, 0, 0, 0, 0, 0, 0)
    assert state_decode(rec).get("seq") == 1, "自写自解都要过，否则两边镜像实现早就分叉了"
    off = STATE_START_LBA * SECTOR
    img[off:off + SECTOR] = rec


# --------------------------------------------------------------- M9-a②：签名包
#
# 常量必须与 kernel/src/sign.rs 的同名项逐字同数（`check-state-window` 那道门禁一起对账）。
# 钥匙不是随机数：`priv[i] = SHA-256(seed || "aurora-lamport" || u32be(i))`，内核与这里
# 各自重算得到同一张 —— 于是"验签"这件事不需要把私钥交给内核。

KEY_LABEL = b"aurora-lamport"
# 测试锚点的种子。生产要换成离线保管的真钥匙（那一半没做，写在 BACKLOG 61）
PKG_SEED = hashlib.sha256(b"aurora-os M9-a test anchor 2026-11-06").digest()
PKG_MAGIC = b"PKGA"
PKG_VERSION = 1
PKG_HDR_BYTES = 512
PK_ITEMS = 512                    # 256 个比特 ⇒ 256 对
PK_BYTES = PK_ITEMS * 32          # 16 KiB
SIG_ITEMS = 256
SIG_BYTES = SIG_ITEMS * 32        # 8 KiB
PKG_PAYLOAD_BYTES = 32768         # 载荷上限（hello.elf 是 31,320 字节）
PKG_BYTES = PKG_HDR_BYTES + PK_BYTES + SIG_BYTES + PKG_PAYLOAD_BYTES
PKG_SECTORS = PKG_BYTES // SECTOR
PK_OFF = PKG_HDR_BYTES
SIG_OFF = PK_OFF + PK_BYTES
PAY_OFF = SIG_OFF + SIG_BYTES
# 放在持久状态区之后，中间留 8 个扇区（状态区以后要轮转、要加种类，别把它盖住）
PKG_START_LBA = STATE_START_LBA + STATE_SECTORS + 8


def lamport_priv(i: int) -> bytes:
    return hashlib.sha256(PKG_SEED + KEY_LABEL + i.to_bytes(4, "big")).digest()


def lamport_pk() -> bytes:
    return b"".join(hashlib.sha256(lamport_priv(i)).digest() for i in range(PK_ITEMS))


def lamport_bits(d: bytes) -> list[int]:
    """摘要的 256 个比特，最高位在前（与内核 `sign::bits` 同一顺序）。"""
    return [(d[i] >> (7 - j)) & 1 for i in range(32) for j in range(8)]


def lamport_sign(msg: bytes) -> bytes:
    d = hashlib.sha256(msg).digest()
    return b"".join(lamport_priv(i * 2 + b) for i, b in enumerate(lamport_bits(d)))


def pkg_anchor() -> bytes:
    """内核要内置的那 32 个字节：整张公钥的摘要。"""
    return hashlib.sha256(lamport_pk()).digest()


def pkg_build(payload: bytes) -> bytes:
    """头 + 公钥 + 签名 + 载荷。签名承诺的是**载荷那 `payload_len` 个字节**。"""
    assert len(payload) <= PKG_PAYLOAD_BYTES, f"载荷超出包上限 {len(payload)} > {PKG_PAYLOAD_BYTES}"
    hdr = bytearray(PKG_HDR_BYTES)
    hdr[0:4] = PKG_MAGIC
    hdr[4:8] = PKG_VERSION.to_bytes(4, "little")
    hdr[8:12] = PK_BYTES.to_bytes(4, "little")
    hdr[12:16] = SIG_BYTES.to_bytes(4, "little")
    hdr[16:20] = len(payload).to_bytes(4, "little")
    body = payload + bytes(PKG_PAYLOAD_BYTES - len(payload))
    pkg = bytes(hdr) + lamport_pk() + lamport_sign(payload) + body
    assert len(pkg) == PKG_BYTES, (len(pkg), PKG_BYTES)
    return pkg


def pkg_verify(pkg: bytes) -> tuple[bool, str]:
    """宿主机自己的那一条实现：内核说通过/内核说哪一格拒绝，这里必须给同一个答案。"""
    if len(pkg) != PKG_BYTES:
        return False, f"BadLen({len(pkg)})"
    if pkg[0:4] != PKG_MAGIC or int.from_bytes(pkg[4:8], "little") != PKG_VERSION:
        return False, "BadHeader"
    n = int.from_bytes(pkg[16:20], "little")
    if n > PKG_PAYLOAD_BYTES:
        return False, f"PayloadTooLong({n})"
    pk, sig = pkg[PK_OFF:PK_OFF + PK_BYTES], pkg[SIG_OFF:SIG_OFF + SIG_BYTES]
    payload = pkg[PAY_OFF:PAY_OFF + n]
    if hashlib.sha256(pk).digest() != pkg_anchor():
        return False, "AnchorMismatch"
    d = hashlib.sha256(payload).digest()
    for i, b in enumerate(lamport_bits(d)):
        given = sig[i * 32:(i + 1) * 32]
        want = pk[(i * 2 + b) * 32:(i * 2 + b + 1) * 32]
        if hashlib.sha256(given).digest() != want:
            return False, f"BitMismatch({i})"
    return True, "ok"


def package_payload() -> bytes:
    """被签的那段字节 = 真夹具 `hello.elf` 的内容，不是编出来的假数据。

    选它是因为内核里就有一份一模一样的（`include_bytes!`），于是"包里的载荷"与
    "内核手上那份文件"可以各自算一遍摘要再对上——那是两条独立来源的事实。
    """
    elf = Path(__file__).resolve().parents[1] / "kernel" / "fixtures" / "hello.elf"
    return elf.read_bytes()


def pkg_reason(pkg: bytes) -> tuple[str, int]:
    """宿主机这一侧给"哪一个分支拒绝了、附带哪个数"，与内核 `sign::check_package` 同序同名。

    两条实现必须对同一批畸形输入给同一个答案 —— 这就是判据本身，
    而不是"内核说拒了就行"（拒错了东西也叫拒）。
    """
    if len(pkg) != PKG_BYTES:
        return "BadLen", len(pkg)
    if pkg[0:4] != PKG_MAGIC or int.from_bytes(pkg[4:8], "little") != PKG_VERSION:
        return "BadHeader", -1
    pk_len = int.from_bytes(pkg[8:12], "little")
    sig_len = int.from_bytes(pkg[12:16], "little")
    pay_len = int.from_bytes(pkg[16:20], "little")
    if pk_len != PK_BYTES or sig_len != SIG_BYTES:
        return "BadLen", max(pk_len, sig_len)
    if pay_len > PKG_PAYLOAD_BYTES or PAY_OFF + pay_len > len(pkg):
        return "PayloadTooLong", pay_len
    pk, sig = pkg[PK_OFF:PK_OFF + PK_BYTES], pkg[SIG_OFF:SIG_OFF + SIG_BYTES]
    if hashlib.sha256(pk).digest() != pkg_anchor():
        return "AnchorMismatch", -1
    d = hashlib.sha256(pkg[PAY_OFF:PAY_OFF + pay_len]).digest()
    for i, b in enumerate(lamport_bits(d)):
        given = sig[i * 32:(i + 1) * 32]
        want = pk[(i * 2 + b) * 32:(i * 2 + b + 1) * 32]
        if hashlib.sha256(given).digest() != want:
            return "BitMismatch", i
    return "ok", -1


def pkg_verify(pkg: bytes) -> tuple[bool, str]:
    """生成器自写自解都要过的那条：只有"通过/不通过"两个值。"""
    reason, arg = pkg_reason(pkg)
    return reason == "ok", reason if arg < 0 else f"{reason}({arg})"


# 篡改表：与内核 `sign::TAMPERS` 逐条同数（`check-sig-anchor` 对账）。每一条都要**走到一个
# 不同的拒绝分支**，否则这张表只是在重复测同一件事
TAMPERS = [
    (PK_OFF, 0x01),
    (PK_OFF + PK_BYTES - 1, 0x80),
    (SIG_OFF, 0x01),
    (SIG_OFF + SIG_BYTES // 2, 0x10),
    (SIG_OFF + SIG_BYTES - 1, 0x01),
    (PAY_OFF, 0x01),
    (19, 0xFF),
    (8, 0xFF),
    (0, 0xFF),
]


def pkg_tampered(pkg: bytes, at: int, mask: int) -> bytes:
    b = bytearray(pkg)
    b[at] ^= mask
    return bytes(b)


def seed_package(img: bytearray, payload: bytes) -> None:
    pkg = pkg_build(payload)
    off = PKG_START_LBA * SECTOR
    end = (PKG_START_LBA + PKG_SECTORS) * SECTOR
    assert PKG_START_LBA >= STATE_START_LBA + STATE_SECTORS, "签名包压在状态区上"
    assert end <= len(img), f"签名包超出镜像末尾：{end} > {len(img)}"
    img[off:end] = pkg


# ------------------------------------------------------------------ 目录树模型

@dataclass
class Node:
    """文件或目录。目录的 data 为空，children 是 {显示名: Node}。"""

    name: str
    data: bytes = b""
    children: "dict[str, Node]" = field(default_factory=dict)
    first_cluster: int = 0
    n_clusters: int = 0

    @property
    def is_dir(self) -> bool:
        return bool(self.children)

    def dir_bytes(self) -> int:
        if not self.is_dir:
            return len(self.data)
        total = 0
        for child in self.children.values():
            total += entry_bytes(child.name, short_of(child.name))
        # 至少占一个簇，目录项不能跨到未分配的簇上
        return max(total, 32)


def short_of(name: str) -> str:
    """按 FAT 规则算 8.3 短名（扩展名截到 3 字节）。"""
    base, _, ext = name.upper().partition(".")
    return f"{base[:8]}.{ext[:3]}"


def entry_bytes(long: str, short: str) -> int:
    """一个条目的总字节数 = LFN 条目数 + 1 个短名条目。"""
    chars = len(long) + 1                       # 结尾要一个 NUL
    n_lfn = (chars + 12) // 13
    return (n_lfn + 1) * 32


def _pad_short(short: str) -> bytes:
    base, _, ext = short.partition(".")
    return base.encode("ascii").ljust(8) + ext.encode("ascii").ljust(3)


def _checksum(sb: bytes) -> int:
    s = 0
    for b in sb:
        s = ((s >> 1) + (s << 8) + b) & 0xFF
    return s


def encode_entries(dir_node: Node) -> bytes:
    """把一个目录的条目全部编出来（含 LFN）。"""
    out = bytearray()
    for name, child in dir_node.children.items():
        sb = _pad_short(short_of(name))
        chk = _checksum(sb)
        padded = name + "\0"
        chunks = [padded[i : i + 13] for i in range(0, len(padded), 13)]
        n = len(chunks)
        for i in range(n):
            seq = n - i                                    # 物理顺序：尾块在前
            ch = chunks[seq - 1]
            e = bytearray(32)
            e[0] = seq | (0x40 if seq == n else 0)
            for j, u in enumerate(ch[:5]):
                struct.pack_into("<H", e, 1 + j * 2, ord(u))
            e[11] = ATTR_LFN
            e[12] = 0                                      # 类型 0
            e[13] = chk                                    # checksum 是 1 字节字段（偏移 13），不是 2 字节
            for j, u in enumerate(ch[5:11]):
                struct.pack_into("<H", e, 14 + j * 2, ord(u))
            for j, u in enumerate(ch[11:13]):
                struct.pack_into("<H", e, 28 + j * 2, ord(u))
            out += bytes(e)
        e = bytearray(32)
        e[0:11] = sb
        e[11] = ATTR_DIR if child.is_dir else ATTR_ARCHIVE
        struct.pack_into("<H", e, 26, child.first_cluster & 0xFFFF)
        struct.pack_into("<I", e, 28, len(child.data) if not child.is_dir else child.dir_bytes())
        out += bytes(e)
    return bytes(out)


# ------------------------------------------------------------------- FAT16 生成

class Fat16:
    """在内存里生成一个 FAT16 卷映象。"""

    def __init__(self, total_sectors: int):
        self.total_sectors = total_sectors
        self.sec_per_fat, self.data_start, self.clusters = self._geometry()

    def _sec_per_fat(self, clusters: int) -> int:
        return max(1, (clusters * 2 + SECTOR - 1) // SECTOR)

    def _geometry(self):
        spf = self._sec_per_fat((self.total_sectors - RESERVED_SECTORS - ROOT_DIR_SECTORS - 2 * 32) // CLUSTER_SECTORS)
        for _ in range(16):
            data_start = RESERVED_SECTORS + 2 * spf + ROOT_DIR_SECTORS
            clusters = (self.total_sectors - data_start) // CLUSTER_SECTORS
            want = self._sec_per_fat(clusters)
            if want == spf:
                return spf, data_start, clusters
            spf = want
        raise RuntimeError("FAT 几何未收敛")

    def build(self, root: Node) -> bytes:
        need = lambda nbytes: 0 if nbytes == 0 else (nbytes + CLUSTER_SECTORS * SECTOR - 1) // (CLUSTER_SECTORS * SECTOR)

        # 1) 先分配所有簇（广度按名字序，保证可复现）
        cursor = [2]
        used = 0

        def assign(node: Node, nbytes: int) -> None:
            nonlocal used
            n = need(nbytes)
            used = max(used, cursor[0] + n - 1)
            node.first_cluster = cursor[0] if n else 0
            node.n_clusters = n
            cursor[0] += n
            if node.is_dir:
                for c in node.children.values():
                    assign(c, len(c.data) if not c.is_dir else c.dir_bytes())

        root.first_cluster = 0            # 根目录固定在保留区，不占簇
        for c in root.children.values():
            assign(c, len(c.data) if not c.is_dir else c.dir_bytes())

        fat = bytearray(self.sec_per_fat * SECTOR * 2)

        def set_fat(i: int, v: int) -> None:
            struct.pack_into("<H", fat, i * 2, v & 0xFFFF)

        set_fat(0, 0xFFF8)
        set_fat(1, FAT16_EOC)

        def chain(first: int, n: int) -> None:
            for k in range(n):
                set_fat(first + k, FAT16_EOC if k == n - 1 else first + k + 1)

        # 2) 铺卷
        img = bytearray(self.total_sectors * SECTOR)

        def write_clusters(first: int, nbytes: int, data: bytes) -> None:
            if first == 0:
                return
            off = (self.data_start + (first - 2) * CLUSTER_SECTORS) * SECTOR
            img[off : off + len(data)] = data[: nbytes]

        # BPB
        bpb = bytearray(SECTOR)
        bpb[0:3] = b"\xeb\xfe\x90"
        bpb[3:11] = b"AURORA51"
        struct.pack_into("<H", bpb, 11, SECTOR)
        struct.pack_into("<B", bpb, 13, CLUSTER_SECTORS)
        struct.pack_into("<H", bpb, 14, RESERVED_SECTORS)
        struct.pack_into("<B", bpb, 16, 2)
        struct.pack_into("<H", bpb, 17, ROOT_ENTRIES)
        # 总扇区数 >= 65536 时 16 位字段必须为 0，改用偏移 32 的 32 位字段（FAT 规范）
        struct.pack_into("<H", bpb, 19, 0 if self.total_sectors > 0xFFFF else self.total_sectors)
        struct.pack_into("<I", bpb, 32, self.total_sectors)
        struct.pack_into("<B", bpb, 21, 0xF8)
        struct.pack_into("<H", bpb, 22, self.sec_per_fat)
        struct.pack_into("<I", bpb, 28, 0)
        struct.pack_into("<B", bpb, 38, 0x29)
        struct.pack_into("<I", bpb, 39, 0xA0A0A0A0)
        bpb[43:54] = b"AURORA_ESP".ljust(11, b" ")
        bpb[54:62] = b"FAT16   "
        bpb[510:512] = b"\x55\xaa"
        img[0:SECTOR] = bpb

        # 根目录（固定在保留区之后）
        root_bytes = encode_entries(root)
        goff = (RESERVED_SECTORS + 2 * self.sec_per_fat) * SECTOR
        img[goff : goff + len(root_bytes)] = root_bytes

        # 子目录与文件
        def emit(node: Node) -> None:
            if node.is_dir and node.first_cluster:
                body = encode_entries(node)
                chain(node.first_cluster, node.n_clusters)
                write_clusters(node.first_cluster, node.n_clusters * CLUSTER_SECTORS * SECTOR, body)
                for c in node.children.values():
                    emit(c)
            elif node.first_cluster:
                chain(node.first_cluster, node.n_clusters)
                write_clusters(node.first_cluster, node.n_clusters * CLUSTER_SECTORS * SECTOR, node.data)

        for c in root.children.values():
            emit(c)

        img[RESERVED_SECTORS * SECTOR : (RESERVED_SECTORS + self.sec_per_fat) * SECTOR] = fat[: self.sec_per_fat * SECTOR]
        p2 = (RESERVED_SECTORS + self.sec_per_fat) * SECTOR
        img[p2 : p2 + self.sec_per_fat * SECTOR] = fat[: self.sec_per_fat * SECTOR]
        return bytes(img)


# ------------------------------------------------------------------------ 读回

def read_back(esp: bytes) -> dict[str, bytes]:
    """独立地走一遍 FAT：返回 {"/路径": 内容}。用来验证 build 的结果，不复用写入代码。"""
    bpb = esp[0:SECTOR]
    assert bpb[510:512] == b"\x55\xaa", "引导扇区签名不对"
    spc = bpb[13]
    reserved = struct.unpack_from("<H", bpb, 14)[0]
    nfats = bpb[16]
    root_entries = struct.unpack_from("<H", bpb, 17)[0]
    spf = struct.unpack_from("<H", bpb, 22)[0]
    fat1 = esp[reserved * SECTOR : (reserved + spf) * SECTOR]
    root_off = (reserved + nfats * spf) * SECTOR
    root_dir = esp[root_off : root_off + root_entries * 32]

    def fat_get(i: int) -> int:
        return struct.unpack_from("<H", fat1, i * 2)[0]

    def clusters_of(first: int) -> bytes:
        out = bytearray()
        c, guard = first, 0
        data_base = root_off + root_entries * 32
        while c not in (FAT16_EOC, 0) and guard < 100000:
            off = data_base + (c - 2) * spc * SECTOR
            out += esp[off : off + spc * SECTOR]
            c = fat_get(c)
            guard += 1
        return bytes(out)

    def parse_dir(raw: bytes) -> list[tuple[str, int, int, int]]:
        """目录项解析：LFN 条目的物理顺序是“尾块在前”，所以短名到达时把已收集的分片
        逆序拼接即为长名。"""
        items: list[tuple[str, int, int, int]] = []
        pending: list[str] = []
        for i in range(0, len(raw) - 31, 32):
            e = raw[i : i + 32]
            if e[0] == 0x00:
                break
            if e[0] == 0xE5:
                continue
            if e[11] == ATTR_VOL:
                continue
            if e[11] == ATTR_LFN:
                chars = [struct.unpack_from("<H", e, o + 2 * j)[0] for o, n in ((1, 5), (14, 6), (28, 2)) for j in range(n)]
                pending.append("".join(chr(c) for c in chars if c not in (0, 0xFFFF)))
                continue
            base = e[0:8].decode(errors="replace").strip()
            ext = e[8:11].decode(errors="replace").strip()
            sname = f"{base}.{ext}".strip(".")
            name = "".join(reversed(pending)) if pending else sname
            pending = []
            items.append((name, e[11], struct.unpack_from("<H", e, 26)[0], struct.unpack_from("<I", e, 28)[0]))
        return items

    result: dict[str, bytes] = {}

    def walk(prefix: str, raw: bytes) -> None:
        for name, attr, first, size in parse_dir(raw):
            if name in (".", ".."):
                continue
            path = f"{prefix}{name}"
            body = clusters_of(first)
            if attr & ATTR_DIR:
                result[path + "/"] = b""
                walk(path + "/", body)
            else:
                result[path] = body[:size]

    walk("/", root_dir)
    return result


# ------------------------------------------------------------------------- GPT

def guid_bytes(text: str) -> bytes:
    a, b, c, d, e = text.split("-")
    return struct.pack("<I", int(a, 16)) + struct.pack("<H", int(b, 16)) + struct.pack("<H", int(c, 16)) + bytes.fromhex(d + e)


def build_disk(root: Node, esp_sectors: int, disk_sectors: int) -> tuple[bytes, dict[str, bytes]]:
    """生成整盘镜像，并**同时**读回一次做自检；返回 (镜像字节, 读回的文件表)。"""
    if disk_sectors < ESP_START_LBA + esp_sectors + 34:
        raise ValueError("磁盘放不下 ESP 与备份 GPT")
    esp = Fat16(esp_sectors).build(root)
    entry = bytearray(GPT_ENTRY_SIZE)
    entry[0:16] = guid_bytes(ESP_TYPE_GUID)
    entry[16:32] = guid_bytes(ESP_GUID)
    struct.pack_into("<Q", entry, 32, ESP_START_LBA)
    struct.pack_into("<Q", entry, 40, ESP_START_LBA + esp_sectors - 1)
    # 名字字段是 partition_name[36] = 72 字节（limine.c 的 struct gpt_entry 确认）。
    # 之前写 entry[56:72] = <20 字节> 被 bytearray 切片赋值**撑大了数组**（128->132），
    # 于是 CRC 覆盖的字节数与文件里的 16384 不同，EDK2 判整张分区表无效。
    name = "Aurora ESP".encode("utf-16-le")
    assert len(name) <= 72, f"分区名过长: {len(name)}"
    entry[56 : 56 + len(name)] = name
    # 断言尺寸而不是依赖切片语义：撑大过一次都不会被发现
    assert len(entry) == GPT_ENTRY_SIZE, f"条目被意外改成 {len(entry)} 字节"
    array = bytes(entry) + bytes(GPT_ENTRY_SIZE * (GPT_ENTRY_COUNT - 1))
    assert len(array) == GPT_ENTRY_SIZE * GPT_ENTRY_COUNT, f"数组长度 {len(array)} 不对"
    entries_crc = binascii.crc32(array) & 0xFFFFFFFF

    # GPT 头字段偏移：逐条对照本机可读的真实实现 limine-bin/limine.c 的
    # struct gpt_table_header（signature[8], revision, header_size, crc32, reserved0,
    # my_lba, alternate_lba, first_usable_lba, last_usable_lba, disk_guid[2],
    # partition_entry_lba, number_of_partition_entries, size_of_partition_entry,
    # partition_entry_array_crc32）
    OFF_REV, OFF_HSIZE, OFF_CRC, OFF_MY_LBA = 8, 12, 16, 24
    OFF_ALT_LBA, OFF_FIRST_USABLE, OFF_LAST_USABLE = 32, 40, 48
    OFF_DISK_GUID, OFF_ENTRY_LBA, OFF_ENTRY_COUNT = 56, 72, 80
    OFF_ENTRY_SIZE, OFF_ARRAY_CRC = 84, 88

    def header(my_lba: int, alternate_lba: int, entry_lba: int,
               first_usable: int, last_usable: int) -> bytes:
        h = bytearray(92)
        h[0:8] = b"EFI PART"
        struct.pack_into("<I", h, OFF_REV, 0x00010000)
        struct.pack_into("<I", h, OFF_HSIZE, 92)
        struct.pack_into("<I", h, OFF_CRC, 0)              # 先清零，算完再回填
        struct.pack_into("<Q", h, OFF_MY_LBA, my_lba)
        struct.pack_into("<Q", h, OFF_ALT_LBA, alternate_lba)
        struct.pack_into("<Q", h, OFF_FIRST_USABLE, first_usable)
        struct.pack_into("<Q", h, OFF_LAST_USABLE, last_usable)
        h[OFF_DISK_GUID:OFF_DISK_GUID + 16] = guid_bytes(DISK_GUID)
        struct.pack_into("<Q", h, OFF_ENTRY_LBA, entry_lba)
        struct.pack_into("<I", h, OFF_ENTRY_COUNT, GPT_ENTRY_COUNT)
        struct.pack_into("<I", h, OFF_ENTRY_SIZE, GPT_ENTRY_SIZE)
        struct.pack_into("<I", h, OFF_ARRAY_CRC, entries_crc)
        # 头部 CRC32 覆盖 header_size 字节，且计算时自身字段为 0
        struct.pack_into("<I", h, OFF_CRC, binascii.crc32(bytes(h)) & 0xFFFFFFFF)
        return bytes(h)

    first_usable, last_usable = 34, disk_sectors - 34      # 主/备各占 33 块
    backup_array_lba = disk_sectors - 33

    img = bytearray(disk_sectors * SECTOR)
    mbr = bytearray(SECTOR)
    mbr[446 + 4] = 0xEE
    struct.pack_into("<I", mbr, 446 + 8, 1)
    struct.pack_into("<I", mbr, 446 + 12, min(disk_sectors - 1, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"
    img[0:SECTOR] = mbr

    img[GPT_HEADER_LBA * SECTOR : GPT_HEADER_LBA * SECTOR + 92] = header(
        GPT_HEADER_LBA, disk_sectors - 1, 2, first_usable, last_usable)
    img[2 * SECTOR : 2 * SECTOR + len(array)] = array

    img[backup_array_lba * SECTOR : backup_array_lba * SECTOR + len(array)] = array
    img[(disk_sectors - 1) * SECTOR : (disk_sectors - 1) * SECTOR + 92] = header(
        disk_sectors - 1, GPT_HEADER_LBA, backup_array_lba, first_usable, last_usable)

    img[ESP_START_LBA * SECTOR : ESP_START_LBA * SECTOR + len(esp)] = esp

    # 内核的持久状态区（§9.4 启动循环计数、§9.7 崩溃记录摘要）。它在 ESP 卷之外、
    # 备份 GPT 之前那段"未分配"的空隙里 —— 卷的簇分配器碰不到它，所以不需要改 FAT 几何。
    # 两条断言各挡一种静默灾难：①与卷/备份表重叠（那会是"某天写坏文件系统或写坏 GPT"）；
    # ②生成出来的镜像里这块不是全 0（那说明还有一条路径在往这里写，两边就都在猜）。
    state_end = STATE_START_LBA + STATE_SECTORS
    esp_end = ESP_START_LBA + esp_sectors
    assert STATE_START_LBA >= esp_end, f"状态区撞进 ESP 卷：{STATE_START_LBA} < {esp_end}"
    assert state_end <= disk_sectors - 34, f"状态区撞进备份 GPT：{state_end} > {disk_sectors - 34}"
    region = bytes(img[STATE_START_LBA * SECTOR : state_end * SECTOR])
    assert region == bytes(len(region)), "状态区在生成的镜像里不是全 0（有别的写入方）"
    # 装机时的那条初始记录：没有它，第一次启动会按"读不到 = 最坏情况"直接进安全模式
    seed_state_region(img)
    assert state_decode(bytes(img[STATE_START_LBA * SECTOR:][:SECTOR])).get("failed") == 0
    # 签名包：同一段 GPT 未分配空隙里，状态区之后。先确认这里也没有别的写入方，
    # 再写下去（与状态区一条规矩：两段"约定出来的分区"要能证明彼此不重叠）
    pkg_region = bytes(img[PKG_START_LBA * SECTOR:(PKG_START_LBA + PKG_SECTORS) * SECTOR])
    assert pkg_region == bytes(len(pkg_region)), "签名包区域在生成的镜像里不是全 0（有别的写入方）"
    assert PKG_START_LBA >= state_end, f"签名包压在状态区上：{PKG_START_LBA} < {state_end}"
    assert PKG_START_LBA + PKG_SECTORS <= disk_sectors - 34, "签名包撞进备份 GPT"
    seed_package(img, package_payload())
    ok, why = pkg_verify(bytes(img[PKG_START_LBA * SECTOR:(PKG_START_LBA + PKG_SECTORS) * SECTOR]))
    assert ok, f"生成器自己签的包自己验不过：{why}"
    return bytes(img), read_back(esp)
