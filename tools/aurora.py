"""Aurora OS 统一入口（替代手册 §3.5 的 justfile：本机没有 just，也不引外部依赖）。

用法：
    python tools/aurora.py build                # 编内核
    python tools/aurora.py image                # 造 ESP 镜像
    python tools/aurora.py run                  # 启动一次并按退出码分级判定
    python tools/aurora.py test                 # 正向 + 负样本 + 两条 L4 注入，证明尺子能分辨
    python tools/aurora.py bench                # P3/P4 基线，并用"已知更慢"的样本验证量具能分辨
    python tools/aurora.py check                # 门禁：lints 接线 / unsafe 登记表 / 镜像内浮点 / crate 清单

判定分级（手册 §12.2 与 §12.3 R19 要求把“挂死”“没起来”“失败”分开）：
    33 通过 / 35 用例失败 / 37 启动信息不可信 / 39 异常致命
    33 但块内容与宿主机镜像对不上 -> CONTENT-MISMATCH（判据在核外，所以不并成 35）
    超时且串口有 boot-ok            -> HANG（判失败，但原因不同）
    超时且串口无 boot-ok            -> NOBOOT
    QEMU 自己起不来（无退出码且日志空）-> NOEMU
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import hashlib
import subprocess
import sys
import time
from pathlib import Path

# Windows 控制台默认 GBK：中文能编码，但 ✓/✗/→ 这类字符会抛 UnicodeEncodeError 直接崩掉
# 整个工具（实测踩过）。统一按 UTF-8 输出，编码不了的字符替换而不是报错；
# 同时给子进程传 PYTHONUTF8，避免被调用的 python 脚本再撞一次同样的坑。
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / ".tools"
CARGO = TOOLS / "cargo" / "bin" / "cargo.exe"
TARGET = "x86_64-unknown-none"
IMAGE = ROOT / "build" / "aurora.img"
SERIAL_LOG = ROOT / "build" / "serial.log"
BUILD = ROOT / "build"
QEMU = TOOLS / "qemu" / "qemu-system-x86_64.exe"

# 与 kernel/linker.ld 的 ENTRY 和 §6.1 的 high 半区一致
KERNEL_BASE = 0xFFFFFFFF80000000
# §3.5 固定的测试拓扑；比较基线时必须同一套参数。
# -cpu max 是**必需**而非偏好：默认 qemu64 实测 smep/smap/xsave/x2apic 全为 false，
# 而 §5.1（V1.2 R17）已把 SMEP/SMAP 定为必需项，用默认 CPU 等于在“硬件不支持”的拓扑上做验收。
QEMU_SMP = "4"
QEMU_MEM = "512M"
# 第 30 行的窗口按"每秒几万条 raise"的量级定，不是按一次观测值定（BACKLOG 71）
STORM_TIMEOUT = 6
STORM_FLOOR = 10_000
QEMU_CPU = "max"
DEBUGEXIT_IOBASE = "0xf4"


def env() -> dict[str, str]:
    e = dict(os.environ)
    e["RUSTUP_HOME"] = str(TOOLS / "rustup").replace("\\", "/")
    e["CARGO_HOME"] = str(TOOLS / "cargo").replace("\\", "/")
    e["PYTHONUTF8"] = "1"      # 子进程里的 python 也不撞 GBK
    return e


def sh(cmd: list[str], cwd: Path | None = None) -> int:
    print("+", " ".join(cmd))
    return subprocess.call(cmd, cwd=str(cwd or ROOT), env=env())


# ------------------------------------------------------------------------ 构建

def kernel_path(features: list[str]) -> Path:
    """构建**之后**产物在哪。单列出来是给 `image_is_current` 用：判断新旧不该触发编译。"""
    kind = "release" if features == ["release"] else "debug"
    return ROOT / "target" / TARGET / kind / "aurora-kernel"


def kernel_binary(features: list[str]) -> Path:
    profile = ["--release"] if features == ["release"] else []
    args = [str(CARGO), "build", "--target", TARGET, "-p", "aurora-kernel"]
    if profile:
        args += profile
    if features and features != ["release"]:
        args += ["--features", ",".join(features)]
    if sh(args) != 0:
        sys.exit("构建失败")
    return kernel_path(features)


def limine_conf() -> bytes:
    """配置文件。路径写的是镜像里的实际位置（8.3 安全名，见 esp_image.py 顶部说明）。"""
    p = ROOT / "boot" / "limine.conf"
    return p.read_bytes()


# 第一个用户程序（M4-2）：它的 ELF 产物**当测试夹具**嵌进内核镜像。
# 为什么不直接从文件系统读：内核还没有驱动与文件系统（M5），而 `elf.rs` 要面对的必须是
# `rustc` 真产出的容器（带 `.debug_*`、多段、`filesz==memsz`），不是我手编的字节。
USER_PKG = "aurora-user-hello"
USER_ELF = ROOT / "target" / TARGET / "debug" / "hello"
FIXTURE = ROOT / "kernel" / "fixtures" / "hello.elf"
# 与 .cargo/config.toml 里给内核那组 rustflags **平行**的一份：链接脚本不同，
# 而 cargo 的 `[target.*]` 段是按 target 生效的，两个包共用同一个 target 时只能靠
# RUSTFLAGS 覆盖（这是 cargo 的既定优先级，不是本机 hack）。
USER_RUSTFLAGS = "-C link-arg=-Tuser/hello/link.ld -C relocation-model=static -C panic=abort -C opt-level=1"


def do_build_user() -> Path:
    r = subprocess.run(
        [str(CARGO), "build", "--target", TARGET, "-p", USER_PKG],
        capture_output=True, text=True, cwd=str(ROOT),
        env={**env(), "RUSTFLAGS": USER_RUSTFLAGS},
    )
    if r.returncode != 0:
        sys.exit("用户程序构建失败：" + (r.stdout + r.stderr)[-2000:])
    data = USER_ELF.read_bytes()
    FIXTURE.parent.mkdir(exist_ok=True)
    # 只在**字节真的变了**时才覆写：`include_bytes!` 的依赖关系挂在 mtime 上，
    # 每次无条件重写会让内核每次全量重编，于是"增量构建"这件事静默失效。
    changed = not FIXTURE.exists() or FIXTURE.read_bytes() != data
    if changed:
        FIXTURE.write_bytes(data)
    import hashlib
    print(f"用户程序: {FIXTURE.relative_to(ROOT)}  {len(data)} 字节  "
          f"sha256={hashlib.sha256(data).hexdigest()[:12]} {'（夹具已更新）' if changed else '（与夹具一致）'}")
    return FIXTURE


def do_build(features: list[str]) -> Path:
    do_build_user()
    elf = kernel_binary(features)
    print(f"内核: {elf}  ({elf.stat().st_size} 字节)")
    return elf


def do_image(features: list[str]) -> Path:
    sys.path.insert(0, str(ROOT / "tools"))
    import esp_image  # noqa: E402

    elf = do_build(features)
    esp_sectors = 65536          # 32 MiB
    disk_sectors = 131072        # 64 MiB
    bootx = TOOLS / "limine-bin" / "BOOTX64.EFI"
    if not bootx.exists():
        sys.exit(f"缺少 {bootx}；Limine 预编译产物未就位")


    # 诊断模式：往 ESP 根放一个 startup.nsh，让 EDK2 自己的 FAT 驱动把目录列到串口上。
    # 目的是用**第二台仪器**判断“我的写入器和我的解析器是不是错在一起”。
    # 用 raw 三引号：脚本里有 \EFI\BOOT 这类反斜杠，普通字符串会把它们当转义序列吃掉。
    extra_children: dict[str, esp_image.Node] = {}
    if os.environ.get("AURORA_ESP_DIAG") == "1":
        script = r"""echo --> MAP
map -b
echo --> ROOT OF fs0
ls fs0:
echo --> fs0:\EFI\BOOT
ls fs0:\EFI\BOOT
echo --> fs0:\BOOT
ls fs0:\BOOT
echo --> DIAG DONE
"""
        extra_children["startup.nsh"] = esp_image.Node("startup.nsh", data=script.encode())
    root = esp_image.Node("/", children={
        "EFI": esp_image.Node("EFI", children={
            "BOOT": esp_image.Node("BOOT", children={
                "BOOTX64.EFI": esp_image.Node("BOOTX64.EFI", data=bootx.read_bytes()),
            }),
        }),
        "boot": esp_image.Node("boot", children={
            # aurora-kernel 有 13 个字符，超出 8.3；镜像里用 aurora.bin
            "aurora.bin": esp_image.Node("aurora.bin", data=elf.read_bytes()),
        }),
        "limine.conf": esp_image.Node("limine.conf", data=limine_conf()),
        **extra_children,
    })
    img, back = esp_image.build_disk(root, esp_sectors, disk_sectors)

    # 读回自检：每个文件的**内容摘要**必须和源文件一致，不是“算完就当写对了”
    import hashlib

    expect = {
        "/EFI/BOOT/BOOTX64.EFI": bootx.read_bytes(),
        "/boot/aurora.bin": elf.read_bytes(),
        "/limine.conf": limine_conf(),
    }
    if os.environ.get("AURORA_ESP_DIAG") == "1":
        expect["/startup.nsh"] = extra_children["startup.nsh"].data
    bad = []
    for path, data in expect.items():
        got = back.get(path)
        if got is None:
            bad.append(f"{path}: 读回缺失")
        elif hashlib.sha256(got).hexdigest() != hashlib.sha256(data).hexdigest():
            bad.append(f"{path}: 摘要不一致 got={len(got)}B want={len(data)}B")
    if bad:
        print("镜像自检失败：")
        for b in bad:
            print("   ", b)
        sys.exit(1)
    IMAGE.parent.mkdir(exist_ok=True)
    IMAGE.write_bytes(img)
    # 产物指纹：判定必须和“我到底启动了哪个镜像”绑在一起。
    # 否则一次失败会被读成代码的问题，实际启动的是上一次遗留的镜像。
    import hashlib as _hl
    info = [
        f"variant={','.join(features) if features else 'normal'}",
        f"elf_sha256={_hl.sha256(elf.read_bytes()).hexdigest()}",
        f"elf_bytes={elf.stat().st_size}",
        f"image_bytes={len(img)}",
        f"esp_entries={sorted(k for k in back if not k.endswith('/'))}",
    ]
    (BUILD / "image-info.txt").write_text("\n".join(info) + "\n", encoding="utf-8")
    for line in info[:3]:
        print("   ", line)
    print(f"镜像 OK: {IMAGE}  {len(img)} 字节，读回 {len(back)} 条目，摘要全部一致")
    return IMAGE


# ------------------------------------------------------------------------ 运行

SCRATCH = BUILD / "scratch.qcow2"
SCRATCH_LBA = 1 << 28          # 只有 LBA 的字节 8（位 31:24）参与才读得到这一格
SCRATCH_PATTERN = 0xA5
SCRATCH_FEATURES = {
    "ahci-scratch", "fault-ahci-highlba", "fault-ahci-write-dir", "fault-ahci-write-partial",
}
# §8.5：这些文件是"驱动"，只能通过 `driver.rs` 的句柄表碰硬件。新增驱动就加进这张表，
# 于是它从第一天起就受 `check-driver-ctx` 约束（不加进来 = 没人管它，这条网关就会慢慢变假）。
DRIVER_MODULES = ["ahci.rs", "virtio.rs"]

# M5-f：第三块盘，走 virtio-blk 而不是 AHCI。容量写成整数 MiB，因为宿主机要拿
# `virtual size / 512` 与内核读到的 `容量扇区=` 对账（两台仪器）。
VBLK = BUILD / "virtio-disk.qcow2"
VBLK_MIB = 64
VBLK_PATTERN = 0x5C
VBLK_FEATURES = {"virtio-blk", "virtio-msix-probe"}

# M8-a：第一张网卡走 virtio-net（手册 §8.6 里它与 virtio-blk 同列 P1，而且 M5-f② 之后
# split queue 这条路已经跑通，第二张网卡不该再引入一套新的环布局）。
# "发出去的字节真的上了线"这句话交给 QEMU 自己的抓包器（`filter-dump` 写 pcap）当第二台仪器：
# 内核说它发了 60 字节，宿主机就得在 pcap 里读到同样的 60 字节，否则是 CONTENT-MISMATCH。
NET_FEATURES = {"virtio-net"}
PCAP = BUILD / "guest.pcap"
# M5-g③：QEMU `-d int` 的投递日志。这台仪器读的是 QEMU 自己打的那几行，不是内核转述的数
# —— 这一格存在的理由就是「内核数的投递」与「机器真投递的」必须各算一遍
TRACE_LOG = BUILD / "irq-trace.log"
# M5-g④：设备事件的第二条日志通道（`-trace events=`）。清单由工具自己写，不留手工文件
EVENTS_TXT = BUILD / "ahci-events.txt"
EDGE_LOG = BUILD / "ahci-edge.log"
STORM_LOG = BUILD / "ahci-storm.log"
# 投递分层的第三台仪器：`-trace apic_deliver_irq`。它数的是"消息带着哪个目的地进了中断控制器"，
# 与 `-d int` 那台"CPU 真收了第几号向量"不是同层，与 `ahci_irq_raise`"设备决定拉高"也不同层。
# 换掉 `-d int` 买到两件事：目的地是**直读**（dest 字段）而不是从 SP 高位推断，且这一跑
# 不再受 `-d int` 的自扰动（第 28 行那条 3/30 的假红来源）。
# 但它**同样只在 tcg 档有产出**：`-accel kvm` 下 LAPIC 在 KVM 内核侧，实测 0 条，
# 而 `-machine kernel_irqchip=off` 被 KVM 直接拒绝（`KVM does not support userspace APIC`）
# ⇒ "投给了谁/CPU 收到了几发"这两维在 KVM 档结构上读不到，只有设备事件读得到（BACKLOG 76a/76b）。
DELIVER_LOG = BUILD / "apic-deliver.log"
DELIVER_EVENTS = ["apic_deliver_irq", "apic_local_deliver", "ahci_irq_raise", "ahci_check_irq",
                  "mc146818rzy_write"]
NET_MAC = "52:54:00:12:34:56"      # 只用于 `mac=`：内核读的是设备配置空间里那份，不拿它当判据

# 这一帧的形状与内核 `virtio.rs` 里那几行是同一张表，由 `check-net-pattern` 逐字对账
NET_MUL, NET_ADD, NET_XOR = 11, 0xA5, 0x5C
NET_TYPE = bytes([0x88, 0xB5])     # IEEE 802 Local Experimental：不冒认任何协议
NET_DST = b"\xff\xff\xff\xff\xff\xff"
NET_HEAD_BYTES = 6 + 6 + 2
NET_FRAME_BYTES = 60
NET_PAYLOAD_BYTES = NET_FRAME_BYTES - NET_HEAD_BYTES


def net_payload_byte(j: int, seq: int) -> int:
    """与内核 `net_payload_byte` 同一条式子：图案随序号走，所以第二帧必须逐字节不同。"""
    return (((j * NET_MUL + NET_ADD + seq) & 0xFF) ^ NET_XOR) & 0xFF


def build_net_frame(seq: int, mac: bytes) -> bytes:
    return NET_DST + mac + NET_TYPE + bytes(net_payload_byte(j, seq) for j in range(NET_PAYLOAD_BYTES))


def read_pcap(path: Path) -> tuple[int, list[bytes]]:
    """读 QEMU `filter-dump` 写出来的 libpcap：返回 (linktype, 每一包的原始字节)。

    只认标准头（24 字节全局 + 每包 16 字节），两种字节序都吃；解析不出来的文件**报错**
    而不是返回空表——"抓不到包"与"抓到了但我读不懂"必须是两件不同的事。
    """
    import struct

    d = path.read_bytes()
    if len(d) < 24:
        raise ValueError(f"pcap 只有 {len(d)} 字节，连全局头都不完整")
    magic = d[:4]
    if magic == bytes([0xD4, 0xC3, 0xB2, 0xA1]):
        end = "<"
    elif magic == bytes([0xA1, 0xB2, 0xC3, 0xD4]):
        end = ">"
    elif magic == bytes([0x4D, 0x3C, 0xB2, 0xA1]) or magic == bytes([0xA1, 0xB2, 0x3C, 0x4D]):
        raise ValueError("这是 pcapng，`filter-dump` 写的不是这个格式")
    else:
        raise ValueError(f"pcap 魔数不对：{magic.hex()}")
    _vmaj, _vmin, _zone, _sig, snaplen, linktype = struct.unpack(end + "HHiIII", d[4:24])
    out, off = [], 24
    while off + 16 <= len(d):
        _ts_s, _ts_u, incl, orig = struct.unpack(end + "IIII", d[off:off + 16])
        off += 16
        if off + incl > len(d):
            raise ValueError(f"最后一个包截断在 {incl} 字节处（文件被谁半路拿走了？）")
        out.append(d[off:off + incl])
        off += incl
        if orig != incl:
            raise ValueError(f"包被截短：抓到 {orig} 字节只留下 {incl}（snaplen={snaplen}）")
    return linktype, out


def make_vblk() -> list[str]:
    """64 MiB 的 qcow2 + 第 0 扇区打一个图案。

    大小必须是**整数 MiB**：容量对账比的是 `virtual_size / 512` 这个整数，
    留一个不整的尾部就会两边各算出不同的扇区数，而那看起来像驱动读错了偏移。
    """
    VBLK.unlink(missing_ok=True)
    if sh([str(TOOLS / "qemu" / "qemu-img.exe"), "create", "-f", "qcow2", str(VBLK), f"{VBLK_MIB}M"]) != 0:
        return ["qemu-img 造不出 virtio 盘"]
    cmd = f"write -P 0x{VBLK_PATTERN:02x} 0 512"
    if sh([str(TOOLS / "qemu" / "qemu-io.exe"), "-f", "qcow2", "-c", cmd, str(VBLK)]) != 0:
        return ["qemu-io 写不进 virtio 盘的图案"]
    return []


def vblk_virtual_sectors() -> int | None:
    """宿主机这一侧的容量仪器：`qemu-img info --output=json` 的 virtual-size。"""
    import json
    r = subprocess.run(
        [str(TOOLS / "qemu" / "qemu-img.exe"), "info", "--output=json", str(VBLK)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if r.returncode != 0:
        return None
    try:
        return int(json.loads(r.stdout)["virtual-size"]) // 512
    except Exception:  # noqa: BLE001 - 读不出来本身就是要报的一条
        return None


def make_scratch() -> list[str]:
    """第二块盘：130 GiB 的 qcow2（文件只占几百 KB —— qcow2 自己就是稀疏格式）。

    为什么必须有它：这条 64 MiB 的引导盘最大 LBA 是 `0x1FFFF`，H2D FIS 里代表
    LBA 31:24 的字节 8 永远写 0 ⇒ 我第一版把它按 `>>32` 写也照样全绿（BACKLOG ㉛）。
    为什么不用裸盘：这台 NTFS 上 `truncate(130 GiB)` 实测**真的占 130 GiB**（㉝）。
    图案由这个函数写下去，内核那边按同一个常量对账 ⇒ 两台仪器（宿主机走 QEMU 块层，
    内核走 AHCI DMA）各自算一遍同一格内容。
    """
    SCRATCH.unlink(missing_ok=True)
    if sh([str(TOOLS / "qemu" / "qemu-img.exe"), "create", "-f", "qcow2", str(SCRATCH), "130G"]) != 0:
        return ["qemu-img 造不出第二块盘"]
    cmd = f"write -P 0x{SCRATCH_PATTERN:02x} {hex(SCRATCH_LBA * 512)} 512"
    if sh([str(TOOLS / "qemu" / "qemu-io.exe"), "-f", "qcow2", "-c", cmd, str(SCRATCH)]) != 0:
        return ["qemu-io 写不进图案"]
    return []


def ovmf_files() -> tuple[Path, Path]:
    """返回 (code 镜像, vars 模板)。

    实测（QEMU 11.1.0 Windows 包）：x86_64 **只有 code 镜像**（3653632 字节 = 892 页），
    没有 combined 整块 ROM，也没有 edk2-x86_64-vars.fd（vars 模板与架构无关，包里只有
    edk2-i386-vars.fd 一份）。因此 `-bios FILE` 会报 "could not load PC BIOS"——
    必须用两块 pflash：unit0 = code(只读) + unit1 = vars(可写副本)。
    share 目录布局随版本变过，所以先查已知位置再递归搜，找不到就点名搜过哪里。
    """
    root = TOOLS / "qemu"
    shares = [d for d in (root / "share" / "qemu", root / "share") if d.exists()]
    if not shares:
        sys.exit(f"找不到 {root} 下的 share 目录，QEMU 未就位？")

    def find(pats: tuple[str, ...]) -> Path | None:
        for d in shares:
            for pat in pats:
                if (d / pat).exists():
                    return d / pat
        for pat in pats:  # 递归兜底
            hits = sorted(root.rglob(pat))
            if hits:
                return hits[0]
        return None

    code = find(("edk2-x86_64-code.fd", "OVMF_CODE.fd", "OVMF.fd"))
    if code is None:
        sys.exit(f"在 {shares} 下找不到 x86_64 UEFI 固件（edk2-x86_64-code.fd / OVMF_CODE.fd）")
    tpl = find(("edk2-x86_64-vars.fd", "edk2-i386-vars.fd", "OVMF_VARS.fd"))
    if tpl is None:
        sys.exit(f"在 {shares} 下找不到 vars 模板（edk2-*-vars.fd / OVMF_VARS.fd）")
    return code, tpl


def ensure_image(features: list[str]) -> None:
    """镜像里装的到底是哪个产物，必须由指纹说，不能靠"我记得刚才造过"。

    实测踩过：`test` 跑完留下的是最后一个负样本变体，随后的 `run` 因为 IMAGE 还在
    就没重造，读到的是 `fault-shootdown-noack` 的 39 —— 一次代码改动被读成了一次故障。

    先按当前源码构建（所以"改了没 build"不会变成"启动旧产物"），再比两件事：
    镜像记录的变体名与请求一致、记录的 ELF sha256 与刚构建出来的 ELF 一致。
    任一条不成立就重造镜像。
    """
    import hashlib as _hl
    elf = kernel_binary(features)
    info = BUILD / "image-info.txt"
    want_variant = ",".join(features) if features else "normal"
    fresh = IMAGE.exists() and info.exists()
    if fresh:
        rec = dict(
            line.split("=", 1)
            for line in info.read_text(encoding="utf-8").splitlines()
            if "=" in line
        )
        fresh = rec.get("variant") == want_variant and rec.get("elf_sha256") == _hl.sha256(elf.read_bytes()).hexdigest()
    if not fresh:
        do_image(features)


def force_boot_state(failed: int, seq: int = 200) -> None:
    """把"已经连续失败 N 次"这个现场**做到盘上**，而不是等一次偶发故障把它撞出来。

    为什么需要它：一次偶发的"状态区读不到"曾经把机器锁死在安全模式（BACKLOG ㊿），
    而那种偶发不可复现 ⇒ 判据不能写在"多跑几遍也许能撞上"上。这里用生成器那份
    编码器（同一套偏移、同一个校验和）覆盖槽 0，`seq` 给一个大数 ⇒ 内核按"取最大 seq"
    的规则读到的就是这条，槽 1 里那条旧的自动变成"上一槽"，撕裂路径照旧可判。
    """
    sys.path.insert(0, str(ROOT / "tools"))
    import esp_image  # noqa: E402
    if not IMAGE.exists():
        sys.exit("force_boot_state 要求镜像已经在盘上（先跑一次启动，让它自己写出记录）")
    img = bytearray(IMAGE.read_bytes())
    off = esp_image.STATE_START_LBA * 512
    img[off:off + 512] = esp_image.state_encode(
        esp_image.STATE_KIND_BOOT, seq, failed, 0, 0, 0, 0, 0)
    IMAGE.write_bytes(bytes(img))


def do_run(features: list[str], timeout: int, extra: str = "") -> tuple[str, int, str]:
    if not QEMU.exists():
        sys.exit(f"QEMU 未就位：{QEMU}")
    ensure_image(features)
    if SCRATCH_FEATURES & set(features):
        # 第二块盘每次重造：写方向那条判据（写完前后的哈希必须不同）要求目标区
        # 开局是已知的空状态。之前这一步只在 do_test 里做，单跑 `run --features ahci-scratch`
        # 就复用了上一次留下的图案 —— 同一条用例经两条路径跑出两个读数（实测：第二次改成
        # "改了=false"）。夹具该跟着"要挂这块盘"这件事走，而不是跟着哪个子命令走。
        bad = make_scratch()
        if bad:
            sys.exit("scratch 盘造不出来：" + " / ".join(bad))
    if VBLK_FEATURES & set(features):
        # 同一条规矩：夹具跟着"要挂这块盘"走。virtio 盘的内容不重要（f① 只取证），
        # 但**容量**重要 —— 宿主机知道这块文件多大，内核读到的 `容量扇区=` 必须等于它。
        bad = make_vblk()
        if bad:
            sys.exit("virtio 盘造不出来：" + " / ".join(bad))
    SERIAL_LOG.unlink(missing_ok=True)
    code, tpl = ovmf_files()
    # vars 每次从模板重拷：上一次运行写入的 NVRAM 启动项不该影响本次判定（可复现）
    vars_run = BUILD / "ovmf-vars.fd"
    vars_run.write_bytes(tpl.read_bytes())

    cmd = [
        str(QEMU), "-M", "q35", "-m", QEMU_MEM, "-smp", QEMU_SMP, "-cpu", QEMU_CPU,
        "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
        "-drive", f"if=pflash,format=raw,file={vars_run}",
        "-drive", f"format=raw,file={IMAGE}",
        "-serial", f"file:{SERIAL_LOG}",
        # 端口必须与 kernel/src/exit.rs 的 DEBUGEXIT_PORT 一致（check-verdict 机器对账）
        "-device", f"isa-debug-exit,iobase={DEBUGEXIT_IOBASE},iosize=0x04",
        "-display", "none", "-no-reboot", "-monitor", "none",
    ]
    if SCRATCH_FEATURES & set(features):
        # `if=ide,index=2` 实测落在 AHCI 的**口 2**（q35 的内置 ich9-ahci 把 IDE 兼容总线
        # 映射到它的端口上），驱动侧就能在端口表里看到第二块 `sig=0x101 ssts=0x113` 的盘
        cmd += ["-drive", f"if=ide,index=2,format=qcow2,file={SCRATCH}"]
    if VBLK_FEATURES & set(features):
        # `if=none` + 显式 `virtio-blk-pci`：这台设备的寄存器布局由 PCI 能力链说，
        # 不像 ide 那样被 q35 的 AHCI 吃掉槽位。地址不写死，让 QEMU 自己挑空槽——
        # 驱动侧本来就该按 vendor 0x1AF4 找，而不是记一个 BDF。
        cmd += [
            "-drive", f"if=none,id=vblk0,format=qcow2,file={VBLK}",
            "-device", "virtio-blk-pci,drive=vblk0",
        ]
    # 一次性实验用的附加参数（例如 `-device intel-iommu,intremap=on` 去真正解析 DMAR）。
    # 走环境变量而不是加一堆子命令开关：这类实验今天要做、明天可能就废，不该进判定链的默认路径。
    if NET_FEATURES & set(features):
        # 抓包文件每次重开：上一跑的包会被读成这一跑发出去的（实测那类"旧证据冒充新事实"
        # 在 scratch 夹具上已经栽过一次，这里不重复）
        PCAP.unlink(missing_ok=True)
        cmd += [
            "-object", f"filter-dump,id=dump0,netdev=n0,file={PCAP}",
            "-netdev", f"user,id=n0,net=10.0.2.0/24,dhcpstart=10.0.2.15",
            "-device", f"virtio-net-pci,netdev=n0,mac={NET_MAC}",
        ]
    # 形参 `extra` 只给判定表里那一格用（M5-g③ 挂 `-d int`）；环境变量那条逃生口保留给手工实验。
    # 两者都按空白切分 ⇒ 路径里有空格会被切开。本机 build/ 下没有空格；哪天有，这里要改成传列表。
    extra_all = " ".join(x for x in (extra, os.environ.get("AURORA_QEMU_EXTRA", "").strip()) if x).strip()
    if extra_all:
        cmd += extra_all.split()
        print("   + QEMU 附加参数:", extra_all)
    t0 = time.time()
    r = None
    try:
        r = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=timeout, env=env())
        rc = r.returncode
    except subprocess.TimeoutExpired:
        rc = -1
    # 必须显式按 UTF-8 读：内核写的是 UTF-8，而 `read_text()` 不带 encoding 时用本机默认
    # 编码（这台机是 GBK），中文日志全部变乱码——于是任何按中文锚点的判据都会读成"零条记录"。
    # 实测踩过：内容对账第一次跑报"串口里只有 0 条块读记录"，而记录明明在。
    log = SERIAL_LOG.read_text(encoding="utf-8", errors="replace") if SERIAL_LOG.exists() else ""
    if rc == 33:
        verdict = "PASS"
    elif rc in (35, 37, 39):
        verdict = {35: "FAIL", 37: "BOOT-INVALID", 39: "EXCEPTION"}[rc]
    elif rc == -1:
        verdict = "HANG" if "boot-ok" in log else "NOBOOT"
    elif not log:
        verdict = "NOEMU"
    else:
        verdict = f"QEMU-EXIT-{rc}"
    if verdict == "PASS":
        # 内核自报 PASS 之后还有一关：块内容必须与宿主机上的镜像对得上
        bad = check_disk_content(log)
        if bad:
            # 独立一级，不并成 FAIL：FAIL 的成因在串口里（ktest 报的是哪一格），
            # 而这一级的成因在核外——混起来就没法回答"到底是内核说的还是我们说的"
            verdict = "CONTENT-MISMATCH"
            for b in bad:
                print("    内容对账:", b)
    # 「固件用法不对 / 参数不对」只会显示成一个抽象的 NOEMU，这里把 stderr 抖出来
    if verdict in ("NOEMU", "NOBOOT") and r is not None and r.stderr.strip():
        print("--- qemu stderr（截断 600 字）---")
        print(r.stderr.strip()[:600])
    fp = BUILD / "image-info.txt"
    tag = ""
    if fp.exists():
        kv = dict(ln.split("=", 1) for ln in fp.read_text(encoding="utf-8").splitlines() if "=" in ln)
        tag = f" 启动产物={kv.get('variant', '?')}/elf {kv.get('elf_sha256', '?')[:12]}"
    else:
        tag = " 警告：无 image-info.txt，无法确认启动的是哪个产物"
    print(f"判定={verdict} qemu_rc={rc} 用时={time.time() - t0:.1f}s{tag}")
    return verdict, rc, log



def fnv1a64(data: bytes) -> int:
    """与 `kernel/src/ahci.rs` 的 `fnv1a64` 逐字一样的实现（64 位 FNV-1a）。
    两份实现分属两个进程，这就是"两台独立仪器"的意思——改一份必须同步改另一份，
    所以这里把参数写死在注释里：offset basis = 0xcbf29ce484222325，prime = 0x100000001b3。"""
    h = 0xcbf29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def check_disk_content(log: str) -> list[str]:
    """内核 DMA 读回来的块必须与宿主机镜像的对应偏移逐字节相同。

    内核一侧只负责**报数**（`ahci: 读 lba=… 哈希=…`），它自判的那些内容见证（MBR 签名、
    `EFI PART`、两次不同）都还在同一个进程里；这一条把它们之外的那一半——"内容到底是不是
    那块盘上的内容"——交给另一台仪器。驱动里任何一格寄存器错位都只能读不到数据，
    读到了但错一位也会在这里露出来。
    """
    bad: list[str] = []
    rows = re.findall(r"读 lba=(\d+) 计数=(\d+) (?:\S+ )+哈希=(0x[0-9a-f]+)", log)
    if len(rows) < 2:
        return [f"串口里只有 {len(rows)} 条块读记录，对账至少需要 2 条"]
    img = IMAGE.read_bytes()
    # 键必须是 **(lba, 计数)**。这里踩过一次自己写的死判据：原来查的是 `lba in by_lba`
    # （字符串 vs int 键的字典），恒为假 ⇒ "同一个 LBA 报出两个不同哈希" 那条从来没生效过，
    # 而它看起来像一条判据。M5-c 之后同一个 LBA 会被读两次（1 个扇区与 257 个扇区），
    # 那是两次不同的读，只有同一对键报出两个哈希才是问题。
    seen: dict[tuple[int, int], str] = {}
    for lba, count, got in rows:
        key = (int(lba), int(count))
        n, off = key[1], key[0] * 512
        if off + n * 512 > len(img):
            bad.append(f"lba={lba} 的 {n} 个扇区越过镜像末尾（{len(img)} 字节）")
            continue
        want = f"0x{fnv1a64(img[off:off + n * 512]):016x}"
        if want != got:
            bad.append(f"lba={lba} 计数={n} 内核报 {got}，宿主机同一偏移算出 {want}")
        if key in seen and seen[key] != got:
            bad.append(f"lba={lba} 计数={n} 被报了两次且哈希不同（{seen[key]} vs {got}）")
        seen[key] = got
    # 同长度、不同 LBA ⇒ 内容必须不同：这是"偏移字段真的参与寻址"的对账版本
    by_count: dict[int, dict[int, str]] = {}
    for (lba, n), h in seen.items():
        by_count.setdefault(n, {})[lba] = h
    for n, per_lba in by_count.items():
        if len(per_lba) > 1 and len(set(per_lba.values())) != len(per_lba):
            bad.append(f"计数={n} 时不同 LBA 读出同一份内容：{per_lba}")
    # 写方向的宿主机对账。**这条曾经是个死门禁**：函数与注释都在，唯独没有调用点，
    # 于是 M5-c③ 说的"两台仪器"实际上只有一台在跑（BACKLOG ㊵）。
    bad += check_scratch_write(log)
    bad += check_virtio_capacity(log)
    bad += check_state_record(log)
    return bad


def check_vblk_write(log: str) -> list[str]:
    """客户机经 virtio 写进第二台控制器的图案，宿主机必须按同一偏移读到同一串字节。

    三个数一起看才成立：内核写之前算的哈希、内核读回来的哈希、宿主机读到的哈希。
    前两个同数只证明"驱动自己一致"，加上第三个才证明"盘上真是那样"。
    没有 `vq: 判据` 那一行说明这一跑没跑 virtio 用例（正常构建就是如此），返回空。
    """
    m = re.search(r"vq: 取证 扇区0哈希=(0x[0-9a-f]+) 扇区1哈希=(0x[0-9a-f]+) 扇区8写后哈希=(0x[0-9a-f]+) 期望写值哈希=(0x[0-9a-f]+)", log)
    if not m:
        return []
    back, want = int(m.group(3), 16), int(m.group(4), 16)
    if back != want:
        return [f"内核自己就不一致：写完回读 {back:#018x} != 期望 {want:#018x}"]
    try:
        got = qemu_io_read(8 * 512, 512, VBLK)
    except Exception as e:  # noqa: BLE001 - 读不到本身就是要报的一条
        return [f"宿主机读不到 virtio 盘扇区 8：{e}"]
    host = fnv1a64(got)
    if host != want:
        diff = sum(1 for i, ch in enumerate(got) if ch != pattern_byte(8, i))
        return [f"virtio 盘扇区 8：宿主机读到 {host:#018x}，内核说 {want:#018x}（{diff} 个字节与图案不符）"]
    return []


NET_FRAME_RE = re.compile(
    r"net: 帧 序号=(?P<seq>\d+) 长=(?P<len>\d+) 哈希=(?P<hash>0x[0-9a-f]+) "
    r"源MAC=(?P<mac>[0-9a-f:]{17}) 回执长=(?P<ulen>\d+) 发后哈希=(?P<after>0x[0-9a-f]+)")


def ip_cksum(b: bytes) -> int:
    """IPv4 首部校验和：16 位一步的反码和，进位回卷后取反（与内核 `ip_cksum` 同一条式子）。"""
    ssum = 0
    i = 0
    while i + 1 < len(b):
        ssum += int.from_bytes(b[i:i + 2], "big")
        i += 2
    if i < len(b):
        ssum += b[i] << 8
    while ssum >> 16:
        ssum = (ssum & 0xFFFF) + (ssum >> 16)
    return (~ssum) & 0xFFFF


# DHCP 那几个数与内核 `virtio.rs` 里那份是同一张表，由 `check-net-pattern` 对账
DHCP_CLIENT_PORT, DHCP_SERVER_PORT = 68, 67
DHCP_XID = 0xA5A51234
DHCP_GUEST_IP = (10, 0, 2, 15)
DHCP_MAGIC = bytes([99, 130, 83, 99])   # 0x63825363
DHCP_FRAME_BYTES = 290


def build_dhcp_discover(mac: bytes) -> bytes:
    """宿主机这一侧重算一遍 DISCOVER：内核发出去的那 290 个字节必须与它逐字节相同。

    这一格判的不是"对端答了什么"，而是**我构造的 IPv4/UDP/BOOTP 是不是合法的那一份**——
    对端肯答它是一次行为证据，逐字节相同才是把首部校验和、长度字段、端口方向全部钉住。
    """
    bootp = bytearray(248)
    bootp[0] = 1                      # BOOTREQUEST
    bootp[1], bootp[2], bootp[3] = 1, 6, 0
    bootp[4:8] = DHCP_XID.to_bytes(4, "big")
    bootp[28:34] = mac
    bootp[236:240] = DHCP_MAGIC
    bootp[240:248] = bytes([53, 1, 1, 55, 2, 1, 3, 255])
    udp = bytes([DHCP_CLIENT_PORT >> 8, DHCP_CLIENT_PORT & 0xFF,
                 DHCP_SERVER_PORT >> 8, DHCP_SERVER_PORT & 0xFF]) + \
        (8 + len(bootp)).to_bytes(2, "big") + b"\x00\x00"
    ip = bytearray(20)                 # 只有首部：载荷是 udp + bootp，别把它们的字节再摆一遍
    ip[0] = 0x45
    ip[2:4] = (20 + len(udp) + len(bootp)).to_bytes(2, "big")   # 总长 = 首部 + 载荷
    ip[4:6] = b"\x00\x01"
    ip[6:8] = b"\x40\x00"             # Don't Fragment
    ip[8], ip[9] = 64, 17
    ip[16:20] = bytes([255, 255, 255, 255])
    ck = ip_cksum(bytes(ip))
    ip[10:12] = bytes([ck >> 8, ck & 0xFF])
    return NET_DST + mac + bytes([0x08, 0x00]) + bytes(ip) + udp + bytes(bootp)


def bootp_of(frame: bytes) -> dict | None:
    """宿主机自己解一遍 BOOTP（与内核那份 `parse_reply` 是两条独立实现）。"""
    if len(frame) < 42 or frame[12:14] != bytes([0x08, 0x00]) or frame[23] != 17:
        return None
    ihl = (frame[14] & 0x0F) * 4
    if ihl < 20 or len(frame) < 14 + ihl + 8 + 248 \
            or frame[14 + ihl + 2:14 + ihl + 4] != bytes([DHCP_CLIENT_PORT >> 8, DHCP_CLIENT_PORT & 0xFF]):
        return None
    b = frame[14 + ihl + 8:]
    if b[236:240] != DHCP_MAGIC:
        return None
    msg = 0
    i = 240
    # 有界走查，与内核那份同语义但独立写：PAD 占一字节；长度不自洽（要越过这一包末尾）就停
    while i < len(b):
        code = b[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(b):
            break
        ln = b[i + 1]
        if ln == 0 or i + 2 + ln > len(b):
            break
        if code == 53:
            msg = b[i + 2]
        i += 2 + ln
    return {"op": b[0], "xid": int.from_bytes(b[4:8], "big"),
            "yiaddr": tuple(b[16:20]), "msg": msg, "chaddr": bytes(b[28:34])}


NET_RX_RE = re.compile(
    r"rx: 收到 长=(?P<len>\d+) 哈希=(?P<hash>0x[0-9a-f]+) 类型=(?P<et>0x[0-9a-f]+) "
    r"op=(?P<op>\d+) 消息=(?P<msg>\d+) xid=(?P<xid>0x[0-9a-f]+) yiaddr=(?P<ip>\d+\.\d+\.\d+\.\d+)")
NET_TX_DISCOVER_RE = re.compile(r"rx: 发 DISCOVER 长=(?P<len>\d+) 哈希=(?P<hash>0x[0-9a-f]+) 自算=(?P<self>0x[0-9a-f]+)")


def check_net_rx(log: str) -> list[str]:
    """第一条真协议往返：内核读回来的那一包，必须与 pcap 里那一条**同数且同解**。

    三处独立：①内核自报的哈希 == 宿主机对 pcap 那条包的哈希；②内核解出的
    `op/消息/xid/yiaddr` == 宿主机用自己的那份 `bootp_of` 解出来的（两条实现，不是一个数抄两遍）；
    ③`yiaddr` == 夹具里 `dhcpstart=` 的那一个 IP——这个数是**宿主机自己定的**，内核不可能猜到，
    所以它是这一行里唯一"答案在核外"的判据。另外内核发出去的 DISCOVER 也逐字节重算一遍。
    """
    got = NET_RX_RE.search(log)
    sent = NET_TX_DISCOVER_RE.search(log)
    if not got and not sent:
        if "rx: 判据" in log:
            return ["有 `rx: 判据` 却没有 `rx: 收到`/`rx: 发 DISCOVER` 记录"]
        return []          # 这一跑没挂网卡，正常构建就是这样
    bad: list[str] = []
    if not PCAP.exists():
        return [f"内核报了往返，但 pcap 不存在：{PCAP}"]
    try:
        linktype, pkts = read_pcap(PCAP)
    except ValueError as e:
        return [f"pcap 读不出来：{e}"]
    if linktype != 1:
        return [f"pcap 的 linktype={linktype} 不是 1（以太网）"]
    if not got:
        return ["内核没报收到那一包（`rx: 收到` 缺失）"]
    if not sent:
        return ["内核没报发出去那一次（`rx: 发 DISCOVER` 缺失）"]
    mac = bytes(int(x, 16) for x in NET_MAC.split(":"))
    want_disc = build_dhcp_discover(mac)
    hits = [p for p in pkts if p == want_disc]
    if not hits:
        d = min((sum(1 for a, b in zip(p, want_disc) if a != b)
                 for p in pkts if len(p) == len(want_disc)), default=-1)
        bad.append(f"pcap 里没有那份 DISCOVER（同长度的包最少差 {d} 个字节 / 共 {len(want_disc)}）")
    elif fnv1a64(hits[0]) != int(sent.group("hash"), 16):
        bad.append(f"DISCOVER：pcap 那条哈希 {fnv1a64(hits[0]):#018x} != 内核自报 {sent.group('hash')}")
    if int(sent.group("hash"), 16) != int(sent.group("self"), 16):
        bad.append(f"DISCOVER：内核自己两次不同（发出前 {sent.group('hash')} / 自算 {sent.group('self')}）")
    want_len = int(got.group("len"))
    rx_hits = [p for p in pkts if len(p) == want_len and fnv1a64(p) == int(got.group("hash"), 16)]
    if not rx_hits:
        same = [p for p in pkts if len(p) == want_len]
        bad.append(f"pcap 里没有内核读到的那一条（长 {want_len} 的包有 {len(same)} 个，"
                   f"哈希 {[hex(fnv1a64(p)) for p in same]} != {got.group('hash')}）")
        return bad
    p = rx_hits[0]
    host = bootp_of(p)
    if host is None:
        bad.append("宿主机自己解不开 pcap 里那一条（内核却解开了 ⇒ 两份实现至少一份错）")
        return bad
    kernel = {"op": int(got.group("op")), "xid": int(got.group("xid"), 16),
              "yiaddr": tuple(int(x) for x in got.group("ip").split(".")),
              "msg": int(got.group("msg"))}
    for k in ("op", "xid", "msg", "yiaddr"):
        if host[k] != kernel[k]:
            bad.append(f"收到的那包 {k} 两份实现不同：内核 {kernel[k]}，宿主机 {host[k]}")
    if host["yiaddr"] != DHCP_GUEST_IP:
        bad.append(f"对端给的地址不是夹具定的 {DHCP_GUEST_IP}，而是 {host['yiaddr']}")
    if host["chaddr"] != mac:
        bad.append(f"回话里的 chaddr {host['chaddr'].hex()} 不是这块网卡的 MAC {NET_MAC}")
    return bad



def check_net_tx(log: str) -> list[str]:
    """内核说它发出去的每一帧，宿主机必须在 pcap 里读到**逐字节相同**的那一个。

    内核那八格判据全在"驱动自己知道"的范围里：队列起来了、回执来了、缓冲没被动过。
    **帧的内容对不对**只有核外的仪器能答，这里就是 QEMU 的 `filter-dump`。
    三处对账，各挡一类错法：
    - pcap 的字节 == 宿主机按同一张表重算的字节（挡"图案表两边不同"）
    - pcap 那个包的哈希 == 内核自报的哈希（挡"重算的表对了但发出去的不是它"）
    - pcap 里的源 MAC == 命令行 `mac=` 给的那一个（内核那一份是从**设备配置空间**读的，
      所以这一格同时证了"配置空间那个偏移我读对了"，两台仪器各持一份）
    """
    frames = list(NET_FRAME_RE.finditer(log))
    if not frames:
        if "net: 判据" in log:
            return ["有 `net: 判据` 却没有 `net: 帧` 记录（发帧那两格没跑到，或被跳过）"]
        return []          # 这一跑没挂网卡，正常构建就是这样
    if not PCAP.exists():
        return [f"内核报了 {len(frames)} 帧，但 pcap 不存在：{PCAP}"]
    try:
        linktype, pkts = read_pcap(PCAP)
    except ValueError as e:
        return [f"pcap 读不出来：{e}"]
    bad: list[str] = []
    if linktype != 1:
        return [f"pcap 的 linktype={linktype} 不是 1（以太网）⇒ 那些字节不能按帧头解，下面的对账没意义"]
    # `filter-dump` 是**双向**的：实测抓包文件里除了我们那两帧，开机更早的时候还有一条
    # IPv6 组播离开报文（`33:33:ff:… 52:54:00:12:34:56 86dd …`），源 MAC 就是这块网卡的，
    # 但它不是这台内核发的（用例不构造 IPv6）。所以"包数 == 帧数"是错的假设（第一版就是这么红的）。
    # 认自己的帧要按**只属于我们的那格**：ethertype `0x88B5` 是我们自己挑的本地实验号，
    # slirp 与任何协议栈都不会用它 ⇒ 带着它的包必须恰好等于内核报的帧数，多一个少一个都判红
    mine = [p for p in pkts if len(p) >= 14 and p[12:14] == NET_TYPE]
    foreign = [p for p in pkts if p not in mine]
    if len(mine) != len(frames):
        bad.append(f"带着 0x88B5 的包有 {len(mine)} 个，内核报了 {len(frames)} 帧 ⇒ 有一边在说谎")
    for p in foreign:
        src = ":".join(f"{x:02x}" for x in p[6:12]) if len(p) >= 12 else "?"
        dst = ":".join(f"{x:02x}" for x in p[0:6]) if len(p) >= 6 else "?"
        et = p[12:14].hex() if len(p) >= 14 else "?"
        print(f"    抓包里另有一包（不带 0x88B5：可能是外来的，也可能是我们的 DISCOVER）："
              f"{dst} <- {src} 类型 0x{et} 长 {len(p)}")
    host_mac = bytes(int(x, 16) for x in NET_MAC.split(":"))
    for m in frames:
        seq = int(m.group("seq"))
        kmac = bytes(int(x, 16) for x in m.group("mac").split(":"))
        if kmac != host_mac:
            bad.append(f"序号 {seq}：内核从设备配置空间读的 MAC {m.group('mac')} != 宿主机 `mac=` 给的 {NET_MAC}")
        want = build_net_frame(seq, kmac)
        hits = [p for p in mine if p == want]
        if not hits:
            # 报"差在哪"而不是只报"没有"：先分长度，再数不同字节的个数 ——
            # 少了两个字节是头长错了，差满整帧是图案表错了，只差几格是搬运错了
            same_len = [p for p in mine if len(p) == len(want)]
            if same_len:
                d = min(sum(1 for a, b in zip(p, want) if a != b) for p in same_len)
                bad.append(f"序号 {seq}：pcap 里没有这一帧（同长度的包最少差 {d} 个字节 / 共 {len(want)}）")
            else:
                bad.append(f"序号 {seq}：pcap 里没有一个 0x88B5 的包是 {len(want)} 字节"
                           f"（长度分布 {sorted(len(p) for p in mine)}）")
            continue
        p = hits[0]
        if int(m.group("len")) != len(p):
            bad.append(f"序号 {seq}：内核说发了 {m.group('len')} 字节，pcap 里那个包是 {len(p)}")
        if fnv1a64(p) != int(m.group("hash"), 16):
            bad.append(f"序号 {seq}：pcap 里那个包哈希 {fnv1a64(p):#018x} != 内核自报 {m.group('hash')}")
        if int(m.group("hash"), 16) != int(m.group("after"), 16):
            bad.append(f"序号 {seq}：内核自己两次不同（发前 {m.group('hash')} / 发后 {m.group('after')}）")
    return bad


def check_virtio_capacity(log: str) -> list[str]:
    """设备自报的容量必须等于宿主机那块 qcow2 的 `virtual-size / 512`。

    为什么单独一条：virtio 的容量在**设备配置结构**里（能力链指给它的那块窗口），
    而不是像 AHCI 那样由 Identify Device 的扇区数报出来。内核读到 0 或读到一个
    离谱的数，最可能的原因就是我对 `DEVICE_CFG` 那条能力的 `offset/length` 理解错了——
    而这恰是取证版要钉住的东西，所以对账必须在核外做，不能只信内核自己打印的判据。
    """
    if "virtio: 能力 cfg_type=" not in log:
        return []  # 这一跑没挂 virtio 设备，正常构建就是这样
    m = re.search(r"容量扇区=(\d+)", log)
    if not m:
        return ["有 virtio 取证记录但没有 `容量扇区=` 那一行"]
    want = vblk_virtual_sectors()
    if want is None:
        return ["宿主机读不到 virtio 盘的 virtual-size（qemu-img info 失败）"]
    got = int(m.group(1))
    if got != want:
        return [f"设备自报容量 {got} 个扇区，宿主机这块文件是 {want} 个（差 {got - want}）"]
    return []


def pattern_byte(lba: int, i: int) -> int:
    """与 `kernel/src/ahci.rs` 的 `pattern_byte` 逐字一样的实现。

    写成一行就是为了让"两份实现"这件事本身不可能出错：
    `((i * 7) + lba) & 0xff` 再异或 `0x3C`。改任何一头都必须同时改另一头，
    否则这条门禁会红——那是有意的耦合，不是巧合。
    """
    return (((i * 7) + lba) & 0xFF) ^ 0x3C


def qemu_io_read(off: int, length: int, path: Path = SCRATCH) -> bytes:
    """用 QEMU 自己的工具读 qcow2 的一段字节（宿主机这一侧的仪器）。

    QEMU 已经退出，所以不存在"客户机还开着文件"的竞态；读到的就是落到盘上的内容。
    输出是 `偏移: 16 个十六进制字节  ASCII` 的 hexdump，只取十六进制那一段。
    """
    r = subprocess.run(
        [str(TOOLS / "qemu" / "qemu-io.exe"), "-f", "qcow2", "-c", f"read -v {hex(off)} {length}", str(path)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env(),
    )
    out = bytearray()
    for ln in (r.stdout or "").splitlines():
        m = re.match(r"^[0-9a-f]{6,}:\s+((?:[0-9a-f]{2}\s+){1,16})", ln)
        if m:
            out += bytes.fromhex(m.group(1).replace(" ", ""))
    if len(out) < length:
        raise ValueError(f"qemu-io 只读出 {len(out)} 字节（要 {length}）：{r.stdout[:120]}{r.stderr[:120]}")
    return bytes(out[:length])


def check_scratch_write(log: str) -> list[str]:
    """客户机写进第二块盘的图案，必须能在**宿主机**上按同样的偏移量读到。

    内核那三条判据（前后哈希不同、回读逐字节相同、第二段没盖住第一段）全都在同一个进程里；
    这一条把"确实落到盘上了"交给另一台仪器。图案按 LBA 取，所以"写错了偏移"也会在这里露出来。
    """
    bad: list[str] = []
    rows = re.findall(r"写 lba=(\d+) 计数=(\d+) ", log)
    if not rows:
        # 正常构建没有第二次盘，写用例根本不注册 ⇒ 没有写记录是**正确的**。
        # 但带 `ahci-scratch` 的那一跑一定有（它的取证行 `高LBA 第二块盘口=` 是设备给的标记），
        # 于是"该有而没有"仍然能被抓到，不用把变体名传进来。
        if "高LBA 第二块盘口=" in log:
            return ["串口里有第二块盘的取证记录却没有写记录（写用例没跑或被跳过）"]
        return []
    for lba, count in rows:
        n, off = int(count), int(lba) * 512
        try:
            got = qemu_io_read(off, n * 512)
        except Exception as e:  # noqa: BLE001 - 门禁要把读不到本身报成一条问题
            bad.append(f"宿主机读不到 scratch 盘 lba={lba}：{e}")
            continue
        want = bytes(pattern_byte(int(lba), i) for i in range(n * 512))
        diff = sum(1 for a, b in zip(got, want) if a != b)
        if diff:
            bad.append(f"scratch 盘 lba={lba} 计数={n}：宿主机读到 {diff} 个字节与图案不符（客户机说一致）")
    return bad


def _elf_sections(elf: Path) -> tuple[bytes, dict]:
    """ELF64 段表：{段名: 段头元组}。两个消费者（`.ktests` 表与崩溃帧符号化）必须用同一份解析，
    复制两份的话其中一份会跟着产物格式漂移而另一份照样绿。"""
    import struct

    d = elf.read_bytes()
    hdr = struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
    e_shoff, e_shentsize, e_shnum, e_shstrndx = hdr[5], hdr[10], hdr[11], hdr[12]
    raw = [struct.unpack_from("<IIQQQQIIQQ", d, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    str_off = raw[e_shstrndx][4]
    return d, {d[str_off + v[0]:].split(bytes([0]))[0].decode(): v for v in raw}


def func_syms(elf: Path) -> list[tuple[int, int, str]]:
    """符号表里的 FUNC：(起, 止, 名)。`st_size == 0` 的那些给不出边界，直接不收 ——
    收进来会变成"任何地址都落在它里面"，那台仪器就永远说对。"""
    import struct

    d, secs = _elf_sections(elf)
    symtab, strtab = secs[".symtab"], secs[".strtab"]
    out = []
    for i in range(symtab[5] // symtab[9]):
        st_name, info, _o, _x, st_value, st_size = struct.unpack_from("<IBBHQQ", d, symtab[4] + i * symtab[9])
        if (info & 0xF) != 2 or st_value == 0 or st_size == 0:
            continue
        name = d[strtab[4] + st_name:].split(bytes([0]))[0].decode(errors="replace")
        out.append((st_value, st_value + st_size, name))
    return sorted(out)


def _mangle_tail(*segs: str) -> str:
    """Rust v0 符号名的**尾部**：每一段前缀自己的字节数，如 `13aurora_kernel12t_crash_oops`。
    只比尾部是因为中段的 crate 哈希（`CsgltG6jfyOBx`）随构建变，而路径这段不变。
    长度由代码算，不手写 —— 手写过的每一次数错的都是它。"""
    return "".join(f"{len(s)}{s}" for s in segs)


def symbolize(fs: list[tuple[int, int, str]], addr: int) -> tuple[str, int] | None:
    """地址落在哪个函数里（`addr` 已经由调用方决定要不要 -1）。"""
    hit = None
    for s, e, n in fs:
        if s <= addr < e and (hit is None or s > hit[0]):
            hit = (s, e, n)
    return (hit[2], addr - hit[0]) if hit else None


def pretty_sym(name: str) -> str:
    """把 v0 mangled 名里那串"长度前缀 + 标识符"读出来，只给台账**看**。
    判定不走它（走 `_mangle_tail` 的 endswith），所以它读歪了也不会造成假绿。"""
    i, segs = 0, []
    while i < len(name):
        if name[i].isdigit():
            j = i
            while j < len(name) and name[j].isdigit():
                j += 1
            n = int(name[i:j])
            # 只有"长度对得上、下一段又是长度前缀"才算一段，否则那是哈希里的数字
            if 0 < n and j + n <= len(name) and (j + n == len(name) or name[j + n].isdigit()):
                segs.append(name[j:j + n])
                i = j + n
                continue
        i += 1
    return "::".join(segs) if segs else name


def ktests_in_elf(elf: Path) -> list[str]:
    """从 ELF 里把 `.ktests` 表读出来：段符号地址 -> rodata 偏移 -> 逐条取 name。
    用途是查“到底注册了几条用例”——表空与全通过在内核退出码里长得一样。"""
    import struct

    d, secs = _elf_sections(elf)
    symtab, strtab = secs[".symtab"], secs[".strtab"]

    def sym(name: str) -> int:
        for i in range(symtab[5] // symtab[9]):
            st_name, _i, _o, _x, st_value, _sz = struct.unpack_from("<IBBHQQ", d, symtab[4] + i * symtab[9])
            if d[strtab[4] + st_name:].split(bytes([0]))[0].decode() == name:
                return st_value
        raise KeyError(name)

    ro_addr, ro_off = secs[".rodata"][3], secs[".rodata"][4]
    start, end = sym("__ktests_start"), sym("__ktests_end")
    out = []
    for a in range(start, end, 24):
        ptr, ln, _run = struct.unpack_from("<QQQ", d, ro_off + (a - ro_addr))
        out.append(d[ro_off + (ptr - ro_addr):][:ln].decode(errors="replace"))
    return sorted(out)


# ------------------------------------------------------------------------ 门禁

def check_lints_wired() -> list[str]:
    """[workspace.lints] 不会自动作用于成员 crate；没接线就是“门禁空转”。"""
    bad = []
    manifests = [ROOT / "kernel" / "Cargo.toml", *(ROOT / "crates").glob("*/Cargo.toml")] if (ROOT / "crates").exists() else [ROOT / "kernel" / "Cargo.toml"]
    for m in manifests:
        s = m.read_text(encoding="utf-8")
        if "[lints]" not in s or "workspace = true" not in s:
            bad.append(f"{m.relative_to(ROOT)} 缺 [lints] workspace = true")
    return bad


def check_unsafe_registry() -> list[str]:
    """登记表 <-> 实际 unsafe 双向对账（手册 §1.3 第 6 条）。

    按**包名**统计（登记表用包名，目录名可能不同，例如 kernel/ 目录对应 aurora-kernel 包）。
    """
    reg = ROOT / "docs" / "security" / "unsafe-whitelist.toml"
    if not reg.exists():
        return ["缺 docs/security/unsafe-whitelist.toml"]
    listed = {
        ln.strip().strip("[]").removeprefix("crate.")
        for ln in reg.read_text(encoding="utf-8").splitlines()
        if ln.strip().startswith("[crate.")
    }
    out = subprocess.run([str(CARGO), "metadata", "--format-version", "1", "--no-deps"], capture_output=True, text=True, env=env())
    if out.returncode != 0:
        return ["cargo metadata 失败，无法确定包与源文件归属"]
    import json

    bad = []
    for pkg in json.loads(out.stdout)["packages"]:
        name = pkg["name"]
        root_dir = Path(pkg["manifest_path"]).parent
        n = 0
        for f in root_dir.rglob("*.rs"):
            text = f.read_text(encoding="utf-8")
            n += sum(1 for ln in text.splitlines() if "unsafe" in ln and not ln.strip().startswith("//"))
        if name in listed and n == 0:
            bad.append(f"{name}: 登记了 unsafe 但实际统计为 0（白名单虚报）")
        if name not in listed and n > 0:
            bad.append(f"{name}: 有 {n} 处含 unsafe 的行但未登记（越权 unsafe）")
    return bad


def check_nofloat(elf: Path) -> list[str]:
    """镜像里不允许出现 SSE/x87 指令：本目标默认不发浮点，但这个保证可被单个
    #[target_feature] 或 C 侧选项悄悄拆掉，而 §5.3 的入口桩不保存浮点状态。"""
    objdump = None
    for c in (TOOLS / "rustup" / "toolchains").glob("*/lib/rustlib/*/bin/llvm-objdump.exe"):
        objdump = c
        break
    if objdump is None:
        return ["找不到 llvm-objdump（rustup 组件 llvm-tools 未装？）"]
    r = subprocess.run([str(objdump), "-d", str(elf)], capture_output=True, text=True, env=env())
    out = r.stdout
    # 先自证量具能看见东西：反汇编行数为 0 时，"没找到浮点指令"是假的通过
    body = [ln for ln in out.splitlines() if ln.strip() and not ln.lstrip().startswith(("-", ".", "H:", "In"))]
    if len(body) < 50:
        return [f"反汇编只有 {len(body)} 行，尺子看不见代码 -> 判失败（objdump rc={r.returncode}）"]
    pats = ("xmm", "ymm", "fld", "fst", "fist", "fild", "paddd", "cvtsi", "movaps", "movups")
    hits = [ln.strip() for ln in body if any(p in ln.lower() for p in pats)]
    if hits:
        return [f"镜像里出现 {len(hits)} 条浮点/向量指令"] + hits[:10]
    print(f"       （反汇编 {len(body)} 行，浮点/向量命中 0）")
    return []


def check_crates_listed() -> list[str]:
    """正文/代码引用的 crate 必须都登记在 docs/architecture/crates.toml（§2.5 R10）。"""
    reg = ROOT / "docs" / "architecture" / "crates.toml"
    if not reg.exists():
        return ["缺 docs/architecture/crates.toml"]
    listed = {ln.split("=")[1].strip().strip('"') for ln in reg.read_text(encoding="utf-8").splitlines() if ln.strip().startswith("crate.")}
    out = subprocess.run([str(CARGO), "metadata", "--format-version", "1", "--no-deps"], capture_output=True, text=True, env=env())
    if out.returncode != 0:
        return ["cargo metadata 失败"]
    import json

    pkgs = {p["name"] for p in json.loads(out.stdout)["packages"]}
    missing = pkgs - listed
    extra = listed - pkgs
    bad = []
    if missing:
        bad.append(f"已存在但未登记: {sorted(missing)}")
    if extra:
        bad.append(f"登记了但不存在: {sorted(extra)}")
    return bad


def check_driver_no_raw() -> list[str]:
    """§8.5 的"驱动只能通过 `DriverCtx`"要有机器保证：驱动模块里不许出现裸访问。

    这是一条文本网关（不是编译器能替我们挡的那一层）：`ahci.rs` 改完之后仍然可以有人
    图省事再写一次 `read_volatile` 直接摸映射，而那条路**读起来完全正常**——句柄表、
    世代号、边界检查全部被绕过，而系统里没有任何东西会因此变红。

    允许清单只有一条：静态 `RING` 那一格的 `UnsafeCell` 读写（拿句柄，不拿指针）。
    """
    bad: list[str] = []
    # 模式要紧：曾经把 `write_bytes` 也列进来，于是 `pub fn write_bytes(...)`（一个合法的
    # 块层接口名）被当成裸访问 —— 文本网关误报一次，下次就有人去放宽整条网关
    forbidden = ("read_volatile", "write_volatile", "from_raw_parts", "ptr::")
    for name in DRIVER_MODULES:
        f = ROOT / "kernel" / "src" / name
        if not f.exists():
            bad.append(f"驱动清单里有 {name}，但文件不在（清单过期）")
            continue
        for i, ln in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if ln.lstrip().startswith("//"):
                continue
            hit = [p for p in forbidden if p in ln]
            if hit:
                bad.append(f"{name}:{i} 出现裸访问 {hit}，绕过了 DriverCtx 的句柄表：{ln.strip()[:78]}")
    return bad


def check_state_window() -> list[str]:
    """状态区在哪、多大：内核与镜像生成器各写了一份数字，所以必须机器对账（手册 V8）。

    不对账的后果很实在：改了一边、另一边还在原地写，写进去的字节落在文件系统簇里
    或者落在备份 GPT 上 —— 而两边都"以为自己对"，测试仍然是绿的。
    """
    bad: list[str] = []
    rs = (ROOT / "kernel" / "src" / "state_store.rs").read_text(encoding="utf-8")
    gen = (ROOT / "tools" / "esp_image.py").read_text(encoding="utf-8")
    r_lba = re.search(r"pub const STATE_START_LBA: u64 = ([0-9_]+);", rs)
    r_slot = re.search(r"pub const SLOT_BYTES: usize = (\d+);", rs)
    r_n = re.search(r"pub const N_SLOTS: u8 = (\d+);", rs)
    g_lba = re.search(r"^STATE_START_LBA = ([0-9_]+)", gen, re.M)
    g_sec = re.search(r"^STATE_SECTORS = (\d+)", gen, re.M)
    if not all((r_lba, r_slot, r_n, g_lba, g_sec)):
        return ["状态区常量没在两边都找到（改名了？内核侧 STATE_START_LBA/SLOT_BYTES/N_SLOTS，生成器侧 STATE_START_LBA/STATE_SECTORS）"]
    rlba = int(r_lba.group(1).replace("_", ""))
    glba = int(g_lba.group(1).replace("_", ""))
    rsec = int(r_slot.group(1)) * int(r_n.group(1)) // 512
    gsec = int(g_sec.group(1))
    if rlba != glba:
        bad.append(f"起始 LBA 不一致：内核 {rlba}，生成器 {glba}")
    if rsec != gsec:
        bad.append(f"区大小不一致：内核 {rsec} 个扇区，生成器 {gsec} 个")
    # V2 崩溃记录的形状也是**两边各写一份**：偏移/帧数上限错一位，宿主机就会把同一条记录
    # 解成另一种样子（或对不上），而内核自己那侧照样"读得通"——正是这一族门禁要挡的形状。
    pairs = (
        ("HDR 偏移", r"const HDR: usize = (\d+);", r"^STATE_HDR = (\d+)"),
        ("版本 2", r"pub const VERSION2: u32 = (\d+);", r"^STATE_VERSION2 = (\d+)"),
        ("崩溃记录固定段", r"const CRASH_FIXED: usize = (\d+);", r"^CRASH_FIXED = (\d+)"),
        ("最多帧数", r"pub const MAX_FRAMES: usize = (\d+);", r"^MAX_FRAMES = (\d+)"),
        ("崩溃记录种类", r"pub const KIND_CRASH: u32 = (\d+);", r"^STATE_KIND_CRASH = (\d+)"),
        ("日志记录种类", r"pub const KIND_LOG: u32 = (\d+);", r"^STATE_KIND_LOG = (\d+)"),
        ("日志固定段", r"const LOG_FIXED: usize = (\d+);", r"^LOG_FIXED = (\d+)"),
    )
    for label, rs_pat, gen_pat in pairs:
        rv = re.search(rs_pat, rs)
        gv = re.search(gen_pat, gen, re.M)
        if not (rv and gv):
            bad.append(f"{label}: 两边没都找到（内核侧 `{rs_pat}` / 生成器侧 `{gen_pat}`）")
            continue
        if rv.group(1) != gv.group(1):
            bad.append(f"{label} 不一致：内核 {rv.group(1)}，生成器 {gv.group(1)}")
    # `LOG_TEXT_MAX` 在内核侧是**推导**的（`MAX_PAYLOAD - LOG_FIXED`），生成器侧是字面量 464。
    # 字面量对不了字符串，所以把推导在这里重算一遍：三个来源常量各从文件里读，读不到就红。
    # 不重算的后果很具体：改小 `SLOT_BYTES` 或改大 `LOG_FIXED`，内核的文本上限跟着变，
    # 而生成器还按 464 解 —— 记录会被一侧写成"合法"、另一侧读成"越界"。
    r_trail = re.search(r"const MAX_PAYLOAD: usize = SLOT_BYTES - HDR - (\d+);", rs)
    r_hdr = re.search(r"const HDR: usize = (\d+);", rs)
    r_lf = re.search(r"const LOG_FIXED: usize = (\d+);", rs)
    g_lt = re.search(r"^LOG_TEXT_MAX = (\d+)", gen, re.M)
    if not all((r_trail, r_hdr, r_lf, g_lt)):
        bad.append("日志文本上限的推导链条读不出来（内核侧 MAX_PAYLOAD/HDR/LOG_FIXED、生成器侧 LOG_TEXT_MAX）")
    else:
        derived = int(r_slot.group(1)) - int(r_hdr.group(1)) - int(r_trail.group(1)) - int(r_lf.group(1))
        if derived != int(g_lt.group(1)):
            bad.append(f"日志文本上限不一致：内核推导 {derived}，生成器 {g_lt.group(1)}")
    return bad
    return bad


def check_state_record(log: str) -> list[str]:
    """宿主机这一侧把内核留在盘上的那条记录**重新解一遍**，与它自报的数对账。

    解码是 `state_store.rs::decode` 的镜像实现（同一套偏移、同一个 FNV-1a）。
    两边不一致意味着：偏移/宽度/校验和三者之一在一侧是错的 —— 那正是"看起来存下来了"
    而下次启动读不出来的形状，不能只信内核自己打印的那条 `落盘` 行。
    """
    m = re.search(r"state: 落盘 区LBA=(\d+) 槽=(\d+) 槽字节=(\d+) seq=(\d+) failed=(\d+) 种类=(\d+)", log)
    if not m:
        return []  # 这一跑没跑状态区用例（正常构建一定有；这里不报错，交给矩阵行去红）
    lba, slot, slot_bytes, seq, failed, kind = (int(x) for x in m.groups())
    sys.path.insert(0, str(ROOT / "tools"))
    import esp_image  # noqa: E402  —— 解记录的那份实现只有一份：装机写它，对账也解它
    img = IMAGE.read_bytes()
    off = lba * 512 + slot * slot_bytes
    if off + slot_bytes > len(img):
        return [f"状态区越界：LBA {lba} 槽 {slot} 已经出了镜像末尾（{len(img)} 字节）"]
    rec = esp_image.state_decode(img[off : off + slot_bytes])
    if "why" in rec:
        return [f"槽{slot} 宿主机解不开（{rec['why']}），而内核说它写成功了"]
    if rec["kind"] != kind or rec["seq"] != seq or rec["failed"] != failed:
        return [
            f"槽{slot} 对不上：宿主机解出 种类={rec['kind']} seq={rec['seq']} failed={rec['failed']}，"
            f"内核报 种类={kind} seq={seq} failed={failed}"
        ]
    return []


ROW_RE = re.compile(r'^\s*\("([^"]+)",\s*(.+?),\s*([A-Za-z_]\w*),\s*"([A-Z-]+)",\s*(-?\d+)\),', re.M)
LOG_ENTRY_RE = re.compile(r'"([^"]+)"\s*:\s*([A-Za-z_]\w*)')


def check_matrix_wiring() -> list[str]:
    """判定表里每一行只能吃**自己那一跑**的证据：变量名撞车会让一行静默变成另一行的副本。

    抓到的形状（BACKLOG ㊾）：启动循环那四遍复用了 `lv/lrc/llog`，于是"泄漏注入被检出"
    读的是负样本构建的第四次启动。两行恰好都期望 `FAIL(35)` ⇒ 矩阵 18/18 全符合，
    而那条判据已经不再测它点名的东西。这类故障没有症状，只能靠表的结构自己说话：
    行名不重、每行都有证据、两行不许共用同一份串口日志或同一个退出码变量。
    """
    src = (ROOT / "tools" / "aurora.py").read_text(encoding="utf-8")
    bad: list[str] = []
    rows_block = re.search(r"^    rows = \[\n(.*?)\n    \]\n", src, re.M | re.S)
    logs_block = re.search(r"^    logs = \{\n(.*?)\n    \}\n", src, re.M | re.S)
    if not rows_block or not logs_block:
        return ["判定表的 rows/logs 两块没按 `rows = [` / `logs = {` 的形状写了（改了缩进或结构？本门禁靠这两块对账行与证据）"]

    rows = [m.groups() for m in ROW_RE.finditer(rows_block.group(1))]
    if not rows:
        return ["判定表里一行都没解析出来（行的写法变了？）"]
    # 本门禁自己的量具也要能被发现失灵：行里出现没见过的形状（第三个位置不是标识符、
    # 期望码不是整数……）时，静默少解析一行就等于静默少测一行，所以按行数对账
    tuple_lines = len(re.findall(r'^\s{8}\("', rows_block.group(1), re.M))
    if tuple_lines != len(rows):
        bad.append(
            f"判定表有 {tuple_lines} 行元组，本门禁只解析出 {len(rows)} 行 ⇒ 写法变了，"
            "检查 ROW_RE 是否还吃得住（少解析一行 = 少测一行而且不会报红）"
        )
    logs = dict(LOG_ENTRY_RE.findall(logs_block.group(1)))

    seen: dict[str, str] = {}
    for name, _verdict, rc_var, _want, _want_rc in rows:
        if name in seen:
            bad.append(f"行名重复：{name}")
        seen[name] = rc_var
        if name not in logs:
            bad.append(f"{name}: 这一行在 logs 表里没有自己的串口日志 ⇒ 它红的时候打不出成因")

    for name, var in logs.items():
        if name not in seen:
            bad.append(f"logs 里的 {name} 在 rows 里没有对应的行（改了行名？）")

    by_log: dict[str, list[str]] = {}
    for name, var in logs.items():
        by_log.setdefault(var, []).append(name)
    for var, names in by_log.items():
        if len(names) > 1:
            bad.append(f"共用同一份串口日志变量 {var} 的行有 {names} —— 每行必须各拿自己那一跑的日志")

    by_rc: dict[str, list[str]] = {}
    for name, _verdict, rc_var, _want, _want_rc in rows:
        by_rc.setdefault(rc_var, []).append(name)
    for var, names in by_rc.items():
        if len(names) > 1:
            bad.append(f"共用同一份退出码变量 {var} 的行有 {names} —— 其中至少一行的实际值不是自己那一跑的")
    return bad


def check_virtio_pattern() -> list[str]:
    """夹具图案字节：宿主机写进 qcow2 的那个数，与内核用例里期望的那个数，必须机器对账。

    这不是洁癖 —— 写这条门禁的时候我先把内核侧填成了 `0x5A`，而夹具是 `0x5C`：
    没有这道对账，那条判据会**当场红一次**（红是对的方向），但更常见的情节是有人为了让它绿
    去改其中一边，从此这条判据只在"两边一起改"时才红，而那是它唯一不需要证明的事。
    """
    rs = (ROOT / "kernel" / "src" / "main.rs").read_text(encoding="utf-8")
    m = re.search(r"const EXPECT_PATTERN: u8 = 0x([0-9A-Fa-f]{2})", rs)
    if m is None:
        return ["内核侧没找到 EXPECT_PATTERN（改名了？用例在 virtio-blk 变体里，常量必须留在 main.rs）"]
    if int(m.group(1), 16) != VBLK_PATTERN:
        return [f"夹具图案字节不一致：内核 0x{int(m.group(1), 16):02X}，aurora.py 0x{VBLK_PATTERN:02X}"]
    return []


def check_net_pattern() -> list[str]:
    """帧的形状：内核 `virtio.rs` 里那几行与宿主机重算用的那一份，必须机器对账。

    与 `check-virtio-pattern` 同一条理由：宿主机是**另一台仪器**，它按同一张表重算一遍，
    才知道 pcap 里那个包是不是我们声称发出去的那一帧。两边各写一份而不对账，改一边就把判据
    变成"只在两边一起错时才红"——而那是它唯一不需要证明的事。
    """
    src = (ROOT / "kernel" / "src" / "virtio.rs").read_text(encoding="utf-8")
    # 内核侧这几个数三种写法都有：十进制（步长 `11`）、十六进制（图案那两个字节）、
    # 加法（`6 + 6 + 2`：谁跟谁加起来）。三种都吃，比较一律按**数值** ——
    # 按渲染比会把 `11` 与 `0x0B` 报成不一致（这条门禁第一次跑就是这么红的，红的是量具）
    want = {
        "NET_MUL": (NET_MUL, "u32"),
        "NET_ADD": (NET_ADD, "u32"),
        "NET_XOR": (NET_XOR, "u32"),
        "NET_FRAME_BYTES": (NET_FRAME_BYTES, "usize"),
        "NET_HEAD_BYTES": (NET_HEAD_BYTES, "usize"),
        # DHCP 那三个号：宿主机既要按同一份**重算** DISCOVER，也要按同一份**解**那一包回话。
        # 少对一份的话，"内核解开了"与"宿主机解开了"就成了两份互不约束的解释
        "DHCP_CLIENT_PORT": (DHCP_CLIENT_PORT, "u16"),
        "DHCP_SERVER_PORT": (DHCP_SERVER_PORT, "u16"),
        "DHCP_XID": (DHCP_XID, "u32"),
    }
    bad: list[str] = []
    for name, (exp, ty) in want.items():
        m = re.search(
            rf"const {name}: {ty} = (0x[0-9A-Fa-f_]{{1,10}}|[0-9]+(?:\s*\+\s*[0-9]+)*);", src)
        if not m:
            bad.append(f"内核侧找不到 {name}（改名了，或者写法不在『数值 / 加法 / 0x』这三种里？）")
            continue
        text = m.group(1)
        got = sum(int(x) for x in re.findall(r"\d+", text)) if "+" in text else int(text, 0)
        if got != exp:
            bad.append(f"{name} 不一致：内核 {text} = {got}，aurora.py {exp}")
    for name, exp in (("DHCP_GUEST_IP", bytes(DHCP_GUEST_IP)),
                      ("DHCP_MAGIC", DHCP_MAGIC),
                      ("NET_TYPE_IPV4", bytes([0x08, 0x00]))):
        m = re.search(rf"const {name}: \[u8; \d\] = \[([^\]]+)\];", src)
        if not m:
            bad.append(f"内核侧找不到 {name}（宿主机重算/解码要按同一串字节）")
            continue
        got = bytes(int(x.strip(), 0) for x in m.group(1).split(","))
        if got != exp:
            bad.append(f"{name} 不一致：内核 {list(got)}，aurora.py {list(exp)}")
    m = re.search(r"pub const NET_TYPE: \[u8; 2\] = \[0x([0-9A-Fa-f]{2}), 0x([0-9A-Fa-f]{2})\];", src)
    if not m:
        bad.append("内核侧找不到 NET_TYPE（两个字节分开写的形式，宿主机按同一形式重算）")
    elif bytes.fromhex(m.group(1) + m.group(2)) != NET_TYPE:
        bad.append(f"NET_TYPE 不一致：内核 {m.group(1)}{m.group(2)}，aurora.py {NET_TYPE.hex()}")
    if not re.search(r"pub const NET_DST: \[u8; 6\] = \[0xFF; 6\];", src):
        bad.append("内核侧 NET_DST 不再是『六个 0xFF』（目的地址换了？宿主机重算与 pcap 里的字节都要跟着改）")
    return bad



def sha_primitives() -> tuple[list[int], list[int]]:
    """按 FIPS 180-4 的**定义**重算 SHA-256 的 IV 与 K：素数平方根/立方根的小数前 32 位。

    不用我脑子里那张表，也不用任何现成实现的表 —— 那张表本身就是从这条定义来的。
    定点算术（Decimal 90 位）足够拿到 32 位无误：小数部分离有理边界的距离远大于 2^-80。
    """
    from decimal import Decimal, getcontext

    getcontext().prec = 90
    primes, c = [], 2
    while len(primes) < 64:
        if all(c % q for q in primes if q * q <= c):
            primes.append(c)
        c += 1

    def frac_bits(x: int, root: int) -> int:
        v = Decimal(x) ** (Decimal(1) / Decimal(root))
        return int((v - int(v)) * (1 << 32))

    return [frac_bits(q, 2) for q in primes[:8]], [frac_bits(q, 3) for q in primes]


def check_sha_primitives() -> list[str]:
    """SHA-256 的两张常数表：内核里那份必须与定义重算出来的逐字相同。

    为什么单独一道门禁：这两个表是我**最容易凭记忆写错**的东西（64 个三十二位数），
    而错一个词的表现不是崩溃，是"摘要对一切输入都自洽地错"——除了拿另一台仪器重算，
    没有任何判据会红。第二轮（`check-sha256` 的 hashlib 对账）管轮函数，这一道管表。
    """
    src = (ROOT / "kernel" / "src" / "sign.rs").read_text(encoding="utf-8")

    def grab(name: str) -> list[int] | None:
        m = re.search(rf"{name}: [^=]+?= \[(.*?)\];", src, re.S)
        if not m:
            return None
        return [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]{8}", m.group(1))]

    iv_want, k_want = sha_primitives()
    bad: list[str] = []
    iv_got, k_got = grab("IV"), grab("K")
    if iv_got is None or len(iv_got) != 8:
        bad.append(f"内核侧 IV 解析不到或不是 8 个字（解析到 {0 if not iv_got else len(iv_got)} 个）")
    elif iv_got != iv_want:
        d = [i for i, (a, b) in enumerate(zip(iv_got, iv_want)) if a != b]
        bad.append(f"IV 与定义不符：第 {d} 个字（内核 {[hex(x) for x in iv_got]}，定义 {[hex(x) for x in iv_want]}）")
    if k_got is None or len(k_got) != 64:
        bad.append(f"内核侧 K 解析不到或不是 64 个字（解析到 {0 if not k_got else len(k_got)} 个）")
    elif k_got != k_want:
        d = [i for i, (a, b) in enumerate(zip(k_got, k_want)) if a != b]
        bad.append(f"K 表与定义不符：{len(d)} 个字不同，前五个下标 {d[:5]}（内核 {k_got[d[0]]:#010x}，定义 {k_want[d[0]]:#010x}）")
    return bad


def check_sha256(log: str) -> list[str]:
    """十三条长度向量的摘要，宿主机用 `hashlib` 独立算一遍逐字对账。

    两台仪器：内核的轮函数 vs CPython 的实现。表错了、补位错了、端序错了、块边界错了，
    在这里都只能红 —— 而这四类在"内核自己算自己比"的判据里全是绿的。
    """
    if "sha: 判据" not in log:
        return []           # 这一跑没带 sig-check，正常构建就是这样
    import hashlib

    lines = [ln for ln in log.splitlines() if "sha: 向量 长度=" in ln]
    if len(lines) != 13:
        return [f"串口里 SHA 向量是 {len(lines)} 条，用例说 13 条（对账少测 = 少证明）"]
    bad: list[str] = []
    for ln in lines:
        m = re.search(r"长度=(\d+) 摘要=(.*)", ln)
        n = int(m.group(1))
        got = [int(x, 16) for x in re.findall(r"0x([0-9a-f]{8})", m.group(2))]
        if len(got) != 8:
            bad.append(f"长度 {n}：摘要只解析出 {len(got)} 个字（要 8 个）")
            continue
        msg = bytes(((i * 7 + 0x5A) & 0xFF) for i in range(n))
        want = [int.from_bytes(d, "big") for d in
                (hashlib.sha256(msg).digest()[j:j + 4] for j in range(0, 32, 4))]
        if got != want:
            j = next(i for i in range(8) if got[i] != want[i])
            bad.append(f"长度 {n}：第 {j} 个字不符 内核 {got[j]:#010x} hashlib {want[j]:#010x}"
                       f"（前 4 字节 内核 {bytes.fromhex(''.join(f'{x:08x}' for x in got))[:4].hex()}"
                       f" hashlib {bytes.fromhex(''.join(f'{x:08x}' for x in want))[:4].hex()}）")
    return bad


def rust_int(expr: str, env: dict[str, int]) -> int:
    """把 Rust 常量表达式（只有名字、十六进制/十进制和 `+ - * /`）算成整数。

    不用 `eval`：这是一道**读源码文本**的门禁，把源码丢进 `eval` 等于给门禁加了一条
    任意代码执行的通道。这里只需要四则运算，就自己写一个 20 行的递归下降。
    """
    import re as _re

    # 下划线只可能出现在数字里（Rust 的字面量分隔符），所以逐个 token 处理而不是整串替换
    # ——整串替换会把 `PK_ITEMS` 变成 `PKITEMS`，然后所有派生常量一起算不出来
    toks = _re.findall(r"0x[0-9A-Fa-f_]+|\d[\d_]*|[A-Za-z_][\w]*|[-+*/()]", expr)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def atom():
        t = take()
        if t == "(":
            v = add()
            assert take() == ")", f"括号不配平：{expr}"
            return v
        if t.startswith("0x"):
            return int(t.replace("_", ""), 16)
        if t[0].isdigit():
            return int(t.replace("_", ""))
        if t in env:
            return env[t]
        raise ValueError(f"不认识的名字 {t}（表达式 {expr}）")

    def mul():
        v = atom()
        while peek() in ("*", "/"):
            op = take()
            r = atom()
            v = v * r if op == "*" else v // r
        return v

    def add():
        v = mul()
        while peek() in ("+", "-"):
            op = take()
            r = mul()
            v = v + r if op == "+" else v - r
        return v

    return add()


def kernel_sig_constants() -> tuple[dict[str, int], list[tuple[int, int]], bytes, list[str]]:
    """从 `kernel/src/sign.rs` 读出签名那套形状、锚点字节与篡改表。"""
    src = (ROOT / "kernel" / "src" / "sign.rs").read_text(encoding="utf-8")
    bad: list[str] = []
    names = ["DIGEST_BYTES", "PK_ITEMS", "PK_BYTES", "SIG_ITEMS", "SIG_BYTES",
             "PKG_VERSION", "PKG_HDR_BYTES", "PK_OFF", "SIG_OFF", "PAY_OFF", "PKG_PAYLOAD_BYTES",
             "PKG_BYTES", "PKG_START_LBA", "SECTOR_BYTES", "PKG_SECTORS"]
    vals: dict[str, int] = {}
    for n in names:
        m = re.search(rf"pub const {n}: [^=]+= (.*);", src)
        if not m:
            bad.append(f"内核侧找不到 {n}")
            continue
        text = m.group(1).strip()
        if n == "PKG_MAGIC_V":
            continue
        try:
            vals[n] = rust_int(text, vals) if not text.replace("_", "").isdigit() else int(text.replace("_", ""))
        except Exception as e:  # noqa: BLE001 - 读不出来本身就是要报的一条
            bad.append(f"内核侧 {n} = {text} 算不出来：{e}")
    m = re.search(r"pub const PKG_MAGIC: \[u8; 4\] = \*b\"([^\"]+)\";", src)
    if not m:
        bad.append('内核侧 PKG_MAGIC 不是 `*b"...."` 那种写法（改了魔数？生成器那侧要跟着改）')
    else:
        vals["MAGIC"] = int.from_bytes(m.group(1).encode(), "big")
    m = re.search(r"pub const PK_ANCHOR: \[u8; DIGEST_BYTES\] = \[(.*?)\];", src, re.S)
    if not m:
        bad.append("内核侧找不到 PK_ANCHOR")
        anchor = b""
    else:
        anchor = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", m.group(1)))
    tampers: list[tuple[int, int]] = []
    for at, mask in re.findall(r"Tamper \{ at: ([^,]+), mask: (0x[0-9a-fA-F]{2})", src):
        try:
            tampers.append((rust_int(at, vals), int(mask, 16)))
        except Exception as e:  # noqa: BLE001
            bad.append(f"篡改表里 at={at} 算不出来：{e}")
    return vals, tampers, anchor, bad


def check_sig_anchor() -> list[str]:
    """签名那一套的**形状、锚点与篡改表**：内核与镜像生成器各写一份，逐条机器对账。

    三条各自挡一类错法：形状错了 = 内核读到的偏移与生成器写的偏移分家（表现是一枚永远
    验不过的签名）；锚点错了 = 内核认的钥匙与包里的公钥不是同一把（`AnchorMismatch`）；
    篡改表错了 = 两边对同一批畸形输入给不同答案，那正是"两份独立实现"最容易被悄悄改成
    一份的形态。
    """
    sys.path.insert(0, str(ROOT / "tools"))
    import esp_image

    vals, tampers, anchor, bad = kernel_sig_constants()
    want = {
        "DIGEST_BYTES": 32, "PK_ITEMS": esp_image.PK_ITEMS, "PK_BYTES": esp_image.PK_BYTES,
        "SIG_ITEMS": esp_image.SIG_ITEMS, "SIG_BYTES": esp_image.SIG_BYTES,
        "PKG_VERSION": esp_image.PKG_VERSION, "PKG_HDR_BYTES": esp_image.PKG_HDR_BYTES,
        "PK_OFF": esp_image.PK_OFF, "SIG_OFF": esp_image.SIG_OFF, "PAY_OFF": esp_image.PAY_OFF,
        "PKG_PAYLOAD_BYTES": esp_image.PKG_PAYLOAD_BYTES, "PKG_BYTES": esp_image.PKG_BYTES,
        "PKG_START_LBA": esp_image.PKG_START_LBA, "SECTOR_BYTES": esp_image.SECTOR,
        "PKG_SECTORS": esp_image.PKG_SECTORS,
    }
    for n, exp in want.items():
        if vals.get(n) != exp:
            bad.append(f"{n} 不一致：内核 {vals.get(n)}，生成器 {exp}")
    if "MAGIC" in vals and vals["MAGIC"] != int.from_bytes(esp_image.PKG_MAGIC, "big"):
        bad.append(f"PKG_MAGIC 不一致：内核 {vals['MAGIC']:#010x}，生成器 {esp_image.PKG_MAGIC!r}")
    if anchor and anchor != esp_image.pkg_anchor():
        bad.append(f"PK_ANCHOR 与生成器算出的公钥摘要不同：内核 {anchor.hex()[:16]}… "
                   f"生成器 {esp_image.pkg_anchor().hex()[:16]}…")
    if len(anchor) not in (0, 32):
        bad.append(f"PK_ANCHOR 解析出 {len(anchor)} 个字节（要 32）")
    if len(tampers) != len(esp_image.TAMPERS):
        bad.append(f"篡改表条数不一致：内核 {len(tampers)}，生成器 {len(esp_image.TAMPERS)}")
    for i, (a, m) in enumerate(tampers):
        if i < len(esp_image.TAMPERS) and (a, m) != esp_image.TAMPERS[i]:
            bad.append(f"篡改第 {i} 条不一致：内核 {a:#x}/{m:#04x}，生成器 {esp_image.TAMPERS[i][0]:#x}/{esp_image.TAMPERS[i][1]:#04x}")
    # 顺手钉住一件更基础的事：内核里的 SHA-256 与生成器用的 hashlib 必须给同一个锚点。
    # 这一格红过 ⇒ 意味着两边实现的哈希已经分叉，签名这件事整体不可信
    if anchor and hashlib.sha256(b"".join(
            hashlib.sha256(esp_image.lamport_priv(i)).digest() for i in range(esp_image.PK_ITEMS))
    ).digest() != anchor:
        bad.append("锚点不等于生成器自己按定义重算的 sha256(pk)（钥匙导出式子两边不一样）")
    return bad


PKG_TAMPER_RE = re.compile(
    r"pkg: 篡改 (?P<i>\d+) 位置=(?P<at>\d+) 掩码=(?P<mask>0x[0-9a-f]{2}) 目的=(?P<why>.+?) "
    r"理由=(?P<why2>[A-Za-z]+) 附带=(?P<arg>\d+)")
PKG_FORENSIC_RE = re.compile(
    r"pkg: 取证 读满=(\d+) 次 字节=(\d+) 头自洽=(\w+) 验签=(\w+) 载荷长=(\d+)/(\d+) 载荷同=(\w+)")


def check_sig_package(log: str) -> list[str]:
    """盘上那份签名包：宿主机用自己的实现把它读一遍、验一遍、再按同一批篡改各验一遍。

    与内核的判据是"逐条同答案"，不是"内核拒了就行"：拒错东西也叫拒。
    """
    if "pkg: 判据" not in log:
        return []
    bad: list[str] = []
    sys.path.insert(0, str(ROOT / "tools"))
    import esp_image

    img = IMAGE.read_bytes()
    seg = esp_image.PKG_START_LBA * esp_image.SECTOR
    pkg = img[seg:seg + esp_image.PKG_BYTES]
    host_reason, host_arg = esp_image.pkg_reason(pkg)
    m = PKG_FORENSIC_RE.search(log)
    if not m:
        return ["有 `pkg: 判据` 却没有 `pkg: 取证` 那一行（用例没跑到读包那一步）"]
    reads, bytes_got, hdr_ok, verify_ok, pay_len, elf_len, payload_same = m.groups()
    if host_reason != "ok":
        bad.append(f"生成器自己写的包，宿主机读回来验不过：{host_reason}({host_arg})")
    if verify_ok != "true" or hdr_ok != "true":
        bad.append(f"内核说没验过：头自洽={hdr_ok} 验签={verify_ok}")
    if bytes_got != str(esp_image.PKG_BYTES):
        bad.append(f"内核读到 {bytes_got} 字节，包应是 {esp_image.PKG_BYTES}")
    if pay_len != elf_len:
        bad.append(f"包内载荷长度 {pay_len} 与夹具长度 {elf_len} 不同")
    want_len = len((ROOT / "kernel" / "fixtures" / "hello.elf").read_bytes())
    if int(pay_len) != want_len:
        bad.append(f"包承诺的载荷长度 {pay_len} 不等于宿主机那份 hello.elf 的 {want_len}")
    if payload_same != "true":
        bad.append("内核说包里的载荷与它手上那份夹具不同数（两条来源必须同数）")
    if hashlib.sha256((ROOT / "kernel" / "fixtures" / "hello.elf").read_bytes()).hexdigest() \
            != hashlib.sha256(pkg[esp_image.PAY_OFF:esp_image.PAY_OFF + want_len]).hexdigest():
        bad.append("宿主机自己也比出不同：盘上的载荷不是那份 ELF")
    rows = list(PKG_TAMPER_RE.finditer(log))
    if len(rows) != len(esp_image.TAMPERS):
        bad.append(f"内核打了 {len(rows)} 条篡改，生成器这张表有 {len(esp_image.TAMPERS)} 条")
    for r in rows:
        i = int(r.group("i"))
        if i >= len(esp_image.TAMPERS):
            bad.append(f"第 {i} 条篡改在这张表里不存在")
            continue
        at, mask = esp_image.TAMPERS[i]
        if int(r.group("at")) != at or int(r.group("mask"), 16) != mask:
            bad.append(f"第 {i} 条篡改的位置/掩码两边不同：内核 {r.group('at')}/{r.group('mask')}，"
                       f"生成器 {at:#x}/{mask:#04x}")
            continue
        h_reason, h_arg = esp_image.pkg_reason(esp_image.pkg_tampered(pkg, at, mask))
        k_arg = int(r.group("arg"))
        if h_arg < 0:
            h_arg = 0xFFFF_FFFF          # 内核用 0xFFFFFFFF 表示"这一格没有附带数字"
        if r.group("why2") != h_reason or k_arg != h_arg:
            bad.append(f"第 {i} 条（{r.group('why')}）两份实现答案不同："
                       f"内核 {r.group('why2')}/{k_arg}，宿主机 {h_reason}/{h_arg}")
        if h_reason == "ok":
            bad.append(f"第 {i} 条篡改宿主机也验过了 ⇒ 这一格根本没在测拒绝（篡改表要重挑）")
    return bad


SBOM_PATH = ROOT / "docs" / "release" / "sbom.json"
NL = chr(10)   # 文件末尾那个换行写成常量：在脚本里生成源码时它比转义可靠


def license_policy() -> tuple[set[str], dict[str, str]]:
    """许可证白名单与『暂时留空并写明理由』那份表，唯一来源是 docs/architecture/crates.toml。

    ADR-009b（发布许可证）还没定，所以今天**不许**给成员随便填一个 MIT：
    留空必须是**登记过的留空**（带一条理由与到期条件），不是没人注意的空白。
    """
    txt = (ROOT / "docs" / "architecture" / "crates.toml").read_text(encoding="utf-8")
    # 只数没被注释掉的那几行：注释掉一条 `license.pending` 就是**撤掉那条豁免**，
    # 而按整篇文本搜的话它照样在 ⇒ 豁免撤了门禁还绿（我这条门禁自己的量具就是这么漏的）
    live = chr(10).join(ln for ln in txt.splitlines() if not ln.lstrip().startswith("#"))
    allow = set(re.findall(r"license\.allow\[\] = \"([^\"]+)\"", live))
    pending = dict(re.findall(r"license\.pending\.(\S+) = \"([^\"]*)\"", live))
    return allow, pending


def sbom_current() -> dict:
    """从 `cargo metadata` 的全依赖图生成 SBOM 应有的内容（不是手工维护的第二张表）。"""
    import json

    r = subprocess.run([str(CARGO), "metadata", "--format-version", "1"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", env=env())
    if r.returncode != 0:
        raise RuntimeError("cargo metadata 失败，SBOM 无从生成")
    d = json.loads(r.stdout)
    members = {p["name"] for p in d["packages"] if str(ROOT) in str(p["manifest_path"])}
    comps = []
    for pkg in sorted(d["packages"], key=lambda x: (x["name"], x["version"])):
        comps.append({
            "name": pkg["name"],
            "version": pkg["version"],
            "license": pkg.get("license") or "",
            "source": "workspace" if pkg["name"] in members else (pkg.get("source") or "unknown"),
            "description": (pkg.get("description") or "").strip(),
        })
    return {
        "format": "aurora-sbom-v1",
        "generator": "tools/aurora.py release",
        "note": "外部 crate 数为 0 是实测而不是省略；依赖出现的第一天 check-sbom 就要管到它",
        "workspace_packages": len(members),
        "external_packages": len(comps) - len(members),
        "packages": comps,
    }


def check_sbom() -> list[str]:
    """SBOM 与依赖图必须一致，且每一个许可证都要么在白名单里、要么是登记过的留空。

    这一道今天就有内容可判：内核与用户夹具两个成员都**没有声明许可证**（ADR-009b 未定），
    所以它们在 `license.pending` 里各占一条带理由的留空。门禁查的是
    『留空有没有登记』，不是『留空对不对』——后者要等他定许可证。
    """
    import json

    bad: list[str] = []
    if not SBOM_PATH.exists():
        return [f"缺 {SBOM_PATH.relative_to(ROOT)}（先跑 python tools/aurora.py release）"]
    allow, pending = license_policy()
    got = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
    want = sbom_current()
    if {c["name"] for c in got.get("packages", [])} != {c["name"] for c in want["packages"]}:
        bad.append(f"SBOM 的成员集合与 cargo metadata 不同：SBOM {sorted(c['name'] for c in got.get('packages', []))} "
                   f"实际 {sorted(c['name'] for c in want['packages'])}")
    by_name = {c["name"]: c for c in got.get("packages", [])}
    for w in want["packages"]:
        g = by_name.get(w["name"])
        if not g:
            continue
        if g.get("version") != w["version"]:
            bad.append(f"{w['name']} 版本不同：SBOM {g.get('version')} 实际 {w['version']}")
        if g.get("license") != w["license"]:
            bad.append(f"{w['name']} 许可证不同：SBOM {g.get('license')!r} 实际 {w['license']!r}")
        lic = (g.get("license") or "").strip()
        if not lic:
            if w["name"] not in pending:
                bad.append(f"{w['name']} 没有许可证，也不在 license.pending 里（留空必须是登记过的留空）")
            elif not pending[w["name"]].strip():
                bad.append(f"{w['name']} 在 license.pending 里没有写理由")
        elif allow and lic not in allow and not any(lic.startswith(a) for a in allow):
            bad.append(f"{w['name']} 的许可证 {lic!r} 不在白名单里（白名单见 crates.toml，ADR-009b 未定）")
    if want["external_packages"] and not allow:
        bad.append("有外部依赖但白名单是空的 ⇒ 谁都进得来")
    return bad


def sha256_file(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def do_release(timeout: int) -> int:
    """发布流程的三条判据：SBOM 与依赖图一致、同样源码两次构建出同一个产物、产物内容可复核。

    这里**不**做签名（钥匙还没定，ADR-033 的没做到的那一节），也不做发布渠道：
    今天能判的就是这两件事加上镜像内容的逐文件摘要。
    """
    import json

    print("=== 1) 第一次构建 ===")
    elf1 = do_build([])
    h1 = sha256_file(elf1)
    img1 = do_image([])
    sys.path.insert(0, str(ROOT / "tools"))
    import esp_image  # noqa: E402

    print("    内核 ELF sha256 =", h1)

    print("=== 2) 清掉内核产物再建一次（同一台机、同一份源码、同一个 target 目录）===")
    r = subprocess.run([str(CARGO), "clean", "-p", "aurora-kernel"], capture_output=True, text=True,
                       cwd=str(ROOT), env=env())
    if r.returncode != 0:
        print("[FAIL] cargo clean 失败：", (r.stdout + r.stderr)[-400:])
        return 1
    elf2 = do_build([])
    h2 = sha256_file(elf2)
    repro_ok = h1 == h2
    print(f"    第二次 sha256 = {h2}")
    print(f"    可复现构建（两次全新编译必须同摘要）：{'符合' if repro_ok else '不符合'}")

    print("=== 3) 镜像里每一份文件的内容摘要 ===")
    data = img1.read_bytes()
    entries = esp_image.read_back(data[esp_image.ESP_START_LBA * esp_image.SECTOR:])
    dig = {k: hashlib.sha256(v).hexdigest()[:16] for k, v in sorted(entries.items())}
    for k, v in dig.items():
        print(f"    {k:28s} {v}")

    print("=== 4) 生成 SBOM ===")
    SBOM_PATH.parent.mkdir(parents=True, exist_ok=True)
    sbom = sbom_current()
    sbom["kernel_elf_sha256"] = h1
    sbom["image_sha256"] = hashlib.sha256(data).hexdigest()
    sbom["image_file_digests"] = dig
    SBOM_PATH.write_text(json.dumps(sbom, indent=2, ensure_ascii=False) + NL, encoding="utf-8")
    print(f"    {SBOM_PATH.relative_to(ROOT)}：成员 {sbom['workspace_packages']} 个、"
          f"外部 crate {sbom['external_packages']} 个")
    bad = check_sbom()
    for x in bad:
        print("    [SBOM]", x)
    ok = repro_ok and not bad
    print("release 判定：", "符合" if ok else "不符合")
    return 0 if ok else 1


def check_verdict_contract() -> list[str]:
    """判定契约的两端必须一致：kernel/src/exit.rs 的端口与退出码，和这里的常量。

    这正是手册 B.3/V8 说的“改一处忘改另一处”——后果不是报错，而是内核往不存在的端口写，
    测试既不通过也不失败，只能等到超时。两个文件里各写一份数字，就必须有机器对账。
    """
    src = (ROOT / "kernel" / "src" / "exit.rs").read_text(encoding="utf-8")
    bad: list[str] = []

    import re

    m = re.search(r"DEBUGEXIT_PORT:\s*u16\s*=\s*(0x[0-9a-fA-F]+)", src)
    if m is None:
        bad.append("exit.rs 里找不到 DEBUGEXIT_PORT 定义")
    elif int(m.group(1), 16) != int(DEBUGEXIT_IOBASE, 16):
        bad.append(f"端口不一致：exit.rs={m.group(1)} 本脚本={DEBUGEXIT_IOBASE}")

    # Rust: Success=0x10 -> (v<<1)|1 = 33；Python 侧硬编码了 33/35/37/39 的语义
    codes = dict(re.findall(r"^\s{4}(Success|Failed|BootInvalid|ExceptionFatal)\s*=\s*(0x[0-9a-f]+),", src, re.M))
    want = {"Success": 33, "Failed": 35, "BootInvalid": 37, "ExceptionFatal": 39}
    for name, expect in want.items():
        if name not in codes:
            bad.append(f"exit.rs 缺 Code::{name}")
            continue
        got = (int(codes[name], 16) << 1) | 1
        if got != expect:
            bad.append(f"Code::{name} 算出 qemu_exit={got}，本脚本判定表期望 {expect}")
    return bad


CRASH_DUMP_RE = re.compile(
    r"crash: 落盘 区LBA=(?P<lba>\d+) 槽=(?P<slot>\d+) 槽字节=(?P<sb>\d+) seq=(?P<seq>\d+) "
    r"向量=(?P<vec>\d+) 错误码=(?P<err>\d+) cpu=(?P<cpu>\d+) "
    r"rip=(?P<rip>0x[0-9a-f]+) rsp=(?P<rsp>0x[0-9a-f]+) rbp=(?P<rbp>0x[0-9a-f]+) cr2=(?P<cr2>0x[0-9a-f]+) "
    r"帧数=(?P<nfr>\d+) 种类=(?P<kind>\d+) 版本=(?P<ver>\d+)")
CRASH_BACK_RE = re.compile(
    r"crash: 上一条 槽=(?P<slot>\d+) seq=(?P<seq>\d+) 向量=(?P<vec>\d+) 错误码=(?P<err>\d+) "
    r"cpu=(?P<cpu>\d+) rip=(?P<rip>0x[0-9a-f]+) rsp=(?P<rsp>0x[0-9a-f]+) cr2=(?P<cr2>0x[0-9a-f]+) "
    r"帧数=(?P<nfr>\d+) 第一帧=(?P<f0>0x[0-9a-f]+)")
# 串口打的那条异常现场（`trap::dump_frame`）——`fault-crash-oops` 那行拿它当同一时刻的第二格。
# `[cpu] 0x<序号> vec=…` 里那个序号是串口自己加的，正则漏了它就会一律"现场行=无"，
# 而那表现为 site_ok=False —— 看着像被测物错了，其实是我的正则没匹配上（实测踩过一次）。
CPU_SITE_RE = re.compile(
    r"\[cpu\] 0x[0-9a-f]+ vec=(?P<vec>\d+) err=(?P<err>0x[0-9a-f]+) rip=(?P<rip>0x[0-9a-f]+) "
    r"cs=(?P<cs>0x[0-9a-f]+) rflags=(?P<fl>0x[0-9a-f]+) rsp=(?P<rsp>0x[0-9a-f]+)")


def crash_cross(log1: str, log2: str) -> tuple[bool, bool, bool]:
    """崩溃记录的跨重启对账，两遍必须来自**同一个变体**（否则镜像会被重建、记录被抹掉）。

    返回三格：
    * `report_ok`：第二遍读回的与第一遍落盘的逐字段相同（命名组逐个比 —— 加了 rsp/rbp/cr2
      之后位置下标错过一次，而"错过"的表现是判据在比不同的两格却照样绿）；
      并且第一帧必须就是 `rip` 那一格（帧数组与出事地址绑在一起对）。
    * `host_ok`：宿主机按 ADR-031 那套偏移把盘上那条重解一遍，逐字段相同（第二台仪器）。
    * `site_ok`：落盘那条与**同一次启动串口打的异常现场**同一条（`fault-crash-oops` 才有；
      没有真实现场的构建这一格不参与判定，由调用方决定怎么用它）。
    """
    m_dump = CRASH_DUMP_RE.search(log1)
    m_back = CRASH_BACK_RE.search(log2)
    report_ok = bool(
        m_dump and m_back
        and all(m_dump.group(k) == m_back.group(k) for k in
                ("slot", "seq", "vec", "err", "cpu", "rip", "rsp", "cr2", "nfr"))
        and m_dump.group("rip") == m_back.group("f0"))
    host_ok = False
    if m_dump:
        sys.path.insert(0, str(ROOT / "tools"))
        import esp_image  # noqa: E402
        lba, slot, sb, seq = (int(m_dump.group(i)) for i in ("lba", "slot", "sb", "seq"))
        off = lba * 512 + slot * sb
        img = IMAGE.read_bytes()
        if off + sb <= len(img):
            rec = esp_image.state_decode(img[off:off + sb])
            nfr = int(m_dump.group("nfr"))
            host_ok = (rec.get("kind") == int(m_dump.group("kind"))
                       and rec.get("seq") == seq and rec.get("version") == int(m_dump.group("ver"))
                       and rec.get("vector") == int(m_dump.group("vec"))
                       and rec.get("error_code") == int(m_dump.group("err"))
                       and rec.get("cpu") == int(m_dump.group("cpu"))
                       and rec.get("rip") == int(m_dump.group("rip"), 16)
                       and rec.get("rsp") == int(m_dump.group("rsp"), 16)
                       and rec.get("rbp") == int(m_dump.group("rbp"), 16)
                       and rec.get("cr2") == int(m_dump.group("cr2"), 16)
                       and rec.get("frame_count") == nfr
                       and len(rec.get("frames", [])) == nfr
                       and (nfr == 0 or rec["frames"][0] == rec["rip"]))
    site = CPU_SITE_RE.search(log1)
    # 现场那一行与记录里的字段**不能按字符串比**：`crash: 落盘` 把错误码打成十进制，
    # `dump_frame` 打成 `0x…`（实测这两边一位不同，红的是我的比较法而不是被测物）。
    # 一律走 int(x, 0)：十进制与 0x 前缀都能解，格式差异就不可能伪装成"字段不同"。
    def num(g: re.Match, key: str) -> int:
        return int(g.group(key), 0)

    site_ok = bool(m_dump and site
                   and num(m_dump, "vec") == num(site, "vec")
                   and num(m_dump, "err") == num(site, "err")
                   and num(m_dump, "rip") == num(site, "rip")
                   and num(m_dump, "rsp") == num(site, "rsp"))
    return report_ok, host_ok, site_ok


# 第 21 行的第二台仪器：内核只交出**地址**，"这个地址属于哪个函数"由 ELF 符号表说。
# 两个期望写成模块路径，尾部由 _mangle_tail 现算 —— 手写 mangled 长度是本机错过的那一类数。
OOPS_FRAMES_FNS = (
    ("aurora_kernel", "t_crash_oops"),   # 出事那一帧：必须落在故意越界的那个函数里
    ("aurora_kernel", "ktest", "run_all"),  # 它的调用者：用例就是被运行器调进去的
)


def crash_frames_symbolized(log: str) -> tuple[bool, str]:
    """把盘上那条崩溃记录的帧数组逐条解成"函数名 + 偏移"，并验前两层是不是**机制要求的**那两个函数。

    为什么不是"帧数够多就算过"：帧数是内核自己数出来的，而"这一帧属于哪个函数"它给不出——
    `.symtab` 不在运行时镜像里（Limine 只加载段），符号表只有核外读得到。前两层钉死是有依据的：
    `KT_CRASH_OOPS` 是一条被 `run_all` 调进去的用例，所以出事函数与它的调用者是**结构**决定的；
    第三层往上取决于内联与调度器栈的形状，不钉（钉了会变成"编译器今天碰巧这样"的假判据）。
    返回地址查函数用 `addr - 1`：那指向 `call` 的**下一条**指令，不减一可能把边界上的
    一次调用算进相邻函数里。`rip` 那一帧不减：它就是出事那条指令自己。
    """
    m = CRASH_DUMP_RE.search(log)
    if not m:
        return False, "日志里没有落盘行"
    elf = kernel_binary(["fault-crash-oops"])
    if not elf.exists():
        return False, f"符号表找不到产物 {elf.name}"
    info = BUILD / "image-info.txt"
    rec_info = dict(
        line.split("=", 1) for line in info.read_text(encoding="utf-8").splitlines() if "=" in line
    ) if info.exists() else {}
    import hashlib as _hl
    if rec_info.get("elf_sha256") != _hl.sha256(elf.read_bytes()).hexdigest():
        # 帧地址只有配上**同一个**产物才有意义：摘要不同就说明符号表来自另一个构建，
        # 那种情况下"解得出函数名"恰恰是最危险的假绿（偏移会落到别的函数里）。
        return False, "符号表来自另一个产物（image-info 的 elf_sha256 与当前 ELF 不符）"
    sys.path.insert(0, str(ROOT / "tools"))
    import esp_image  # noqa: E402
    lba, slot, sb = (int(m.group(i)) for i in ("lba", "slot", "sb"))
    off = lba * 512 + slot * sb
    img = IMAGE.read_bytes()
    if off + sb > len(img):
        return False, "落盘行指的槽超出镜像"
    rec = esp_image.state_decode(img[off:off + sb])
    n = int(rec.get("frame_count", 0))
    frames = list(rec.get("frames", []))[:n]
    fs = func_syms(elf)
    hits = [symbolize(fs, a if i == 0 else a - 1) for i, a in enumerate(frames)]
    ok = all(h is not None for h in hits) and n >= len(OOPS_FRAMES_FNS)
    out = [f"#{i} {pretty_sym(h[0])}+{h[1]:#x}" if h else f"#{i} {a:#x}→不在任何函数内"
           for i, (a, h) in enumerate(zip(frames, hits))]
    for i, segs in enumerate(OOPS_FRAMES_FNS):
        h = hits[i] if i < len(hits) else None
        ok = bool(ok and h and h[0].endswith(_mangle_tail(*segs)))
    return ok, f"FUNC={len(fs)} 帧={n} " + " ".join(out)


CRASH_TAIL_RE = re.compile(
    r"crash: 日志尾 槽=(?P<slot>\d+) seq=(?P<seq>\d+) 配崩溃 seq=(?P<cseq>\d+) "
    r"行数=(?P<lines>\d+) 文本字节=(?P<bytes>\d+)（上限 (?P<max>\d+)）")


def log_tail_cross(log: str) -> tuple[bool, str]:
    """盘上那条 kind=3 与**同一遍启动的串口原文**逐行对账（§9.7"最近日志"的第二台仪器）。

    按行集合比是这里的老形状，它抓到的是内容错、取错时刻、环里是旧货那三类。
    L3-A 之前**只敢**按行比：`serial::line` 不加锁，"这一段在串口里连续出现"这句在 SMP 现场
    本来就可能是假的。行锁进去之后，那条更紧的 claim 也补上了（下面第 ⑤ 条），两边现在都判。
    再加一条更紧的：记录的**最后一行**必须正好是落盘行之前那最后一条 `[cpu]` 现场行，
    于是"取早了"（少掉现场行）与"取晚了"（把写盘动作自己打的行收进来）两种错法都跑不掉。
    """
    m_t = CRASH_TAIL_RE.search(log)
    m_c = CRASH_DUMP_RE.search(log)
    if not (m_t and m_c):
        return False, "串口里没有日志尾或落盘行"
    sys.path.insert(0, str(ROOT / "tools"))
    import esp_image  # noqa: E402
    slot = int(m_t.group("slot"))
    sb = int(m_c.group("sb"))  # 槽字节由落盘行自己报（同一遍启动里的数字，不是我猜的 512）
    lba = int(m_c.group("lba"))
    off = lba * 512 + slot * sb
    img = IMAGE.read_bytes()
    if off + sb > len(img):
        return False, "日志尾指的槽超出镜像"
    rec = esp_image.state_decode(img[off:off + sb])
    if "text" not in rec:
        return False, f"槽{slot} 解不开：{rec.get('why')}"
    text = rec["text"]
    ser = [ln for ln in log.splitlines()]
    lines_txt = [ln.decode(errors="replace") for ln in text.split(b"\n") if ln]
    bad: list[str] = []
    # ① 内核自报的数与宿主机解出的数逐格同数（同一遍启动里的两台仪器）
    for label, want_g, got in (("seq", "seq", rec.get("seq")), ("配崩溃 seq", "cseq", rec.get("crash_seq")),
                               ("行数", "lines", rec.get("lines")), ("文本字节", "bytes", rec.get("bytes"))):
        if int(m_t.group(want_g)) != got:
            bad.append(f"{label} 自报 {m_t.group(want_g)} 宿主机 {got}")
    if rec.get("kind") != esp_image.STATE_KIND_LOG:
        bad.append(f"种类 {rec.get('kind')} 不是 3")
    if int(m_c.group("seq")) != rec.get("crash_seq"):
        bad.append(f"配的崩溃 seq {rec.get('crash_seq')} != 落盘那条 {m_c.group('seq')}")
    # ② 文本自己：长度、末字节、行数（换行符真实个数，不信内核数的那遍）
    if len(text) != int(m_t.group("bytes")):
        bad.append(f"文本长度 {len(text)} != 字节数 {m_t.group('bytes')}")
    if not text.endswith(b"\n"):
        bad.append("末字节不是换行 ⇒ 存进去的是半行")
    nl = text.count(b"\n")
    if nl != rec.get("lines"):
        bad.append(f"换行符 {nl} 个 != 声明行数 {rec.get('lines')}")
    if int(m_t.group("max")) != esp_image.LOG_TEXT_MAX:
        bad.append(f"内核报的上限 {m_t.group('max')} != 生成器的 {esp_image.LOG_TEXT_MAX}")
    # ③ 逐行必须在同一遍的串口原文里逐字出现
    miss = [ln for ln in lines_txt if ln not in ser]
    if miss:
        bad.append(f"{len(miss)}/{len(lines_txt)} 行在串口里找不到：{miss[0][:60]}")
    # ⑤ 连续子串：这一段必须能在串口原文里整段找到（行锁之后才敢写的一条）
    blob = ("\n".join(ser) + "\n").encode("utf-8", errors="replace")
    if text and text not in blob:
        bad.append("盘上这一段在串口原文里不连续 ⇒ 行锁没管住，或两侧的顺序不是同一套")
    # ④ 取的时刻：最后一行 == 落盘行之前那最后一条 `[cpu]` 现场行（`trap::dump_frame` 打的）。
    #    不锚在"落盘行的前一行"：写这条记录本身会在中间插进块层的 `ahci: 取证` 行，
    #    那一行是**写盘动作**说的，不是崩溃现场说的（实测：锚错时盘上末行是 [cpu] 而串口前一行是取证行）。
    #    落盘/日志尾这两行自己不许出现在文本里 ⇒ "取晚了"同样跑不掉。
    dump_i = next((i for i, ln in enumerate(ser) if "crash: 落盘" in ln), None)
    if dump_i is None or dump_i == 0:
        bad.append("找不到落盘行，没法判断取的是哪一刻")
    else:
        site_i = next((i for i in range(dump_i - 1, -1, -1) if ser[i].startswith("[cpu]")), None)
        if site_i is None:
            bad.append("落盘行之前没有 [cpu] 现场行")
        elif not lines_txt or lines_txt[-1] != ser[site_i]:
            bad.append(f"最后一行不是现场最后一行：盘上 {lines_txt[-1][:40]!r} 串口 {ser[site_i][:40]!r}")
        if b"crash: " in text:
            bad.append("文本里混进了崩溃路径自己打的行 ⇒ 取晚了")
    return not bad, (f"行数={rec.get('lines')} 字节={len(text)} 逐行={len(lines_txt) - len(miss)}/{len(lines_txt)} "
        f"连续={'是' if (not text or text in blob) else '否'} ") + \
        ("对账不符：" + "；".join(bad) if bad else "全部相符")


TRACE_INT_RE = re.compile(r": v=(?P<vec>[0-9a-f]{2}) e=[0-9a-f]+ i=\S+ cpl=(?P<cpl>\d) IP=[0-9a-f]+:(?P<ip>\w+) pc=(?P<pc>\w+)")
P5_CPU_RE = re.compile(r"irq1\.\.15=(?P<total>\d+) 按CPU=\[(?P<cpu>[0-9, ]+)\]")
# 挂上 `-d int` 之后，这一跑的内核用例红不许由对账函数沉默吞掉：读数里必须自己点名
KT_TOTAL_RE = re.compile(r"ktests: total=(?P<total>\d+) passed=(?P<passed>\d+) failed=(?P<failed>\d+)")
KT_FAIL_RE = re.compile(r"^\[FAIL\] \S+ (?P<case>t_\w+) -> failed", re.M)
CAL_REFUSED_RE = re.compile(r"clock: calibration refused: (?P<why>\w+)")
# 放行窗口的两条边：1.5 是内核自己的门槛（kernel/src/clock.rs），2.0 是"真漏一个 tick"的形状
MISSED_TICKS_RE = re.compile(r"MissedTicks \{ mean: (?P<mean>\d+), max_tick_gap: (?P<gap>\d+) \}")
IT_EXCUSE_CASE = "t_cpu_ids_agree"


def instrument_caused_red(log: str) -> tuple[bool, str]:
    """挂了 `-d int` 的跑里，唯一由仪器自己造成的红（BACKLOG 69 实测）。

    三条**同时**成立才放行，缺一条就照内核的判定报红：
    * 红的用例只有 `t_cpu_ids_agree` 一条，且 `failed` 恰好是 1；
    * 同一跑里有 `clock: calibration refused: MissedTicks`；
    * 越线的比值落在 [1.5, 2.0)。到 2.0 就是真漏 tick 的形状，往内核身上查，不许算仪器的账。
    """
    m_kt = KT_TOTAL_RE.search(log)
    reds = KT_FAIL_RE.findall(log)
    m_cal = MISSED_TICKS_RE.search(log)
    if not m_kt or not m_cal or not CAL_REFUSED_RE.search(log):
        return False, "没有 `clock: calibration refused: MissedTicks` 那一行 ⇒ 这一跑的红与仪器无关"
    if reds != [IT_EXCUSE_CASE] or m_kt.group("failed") != "1":
        return False, f"红用例={reds} failed={m_kt.group('failed')}（要正好 1 条且是 {IT_EXCUSE_CASE}）"
    mean = int(m_cal.group("mean"))
    gap = int(m_cal.group("gap"))
    if mean == 0:
        return False, "mean=0，比值没有定义"
    ratio = gap / mean
    if 1.5 <= ratio < 2.0:
        return True, f"比值 {ratio:.2f} 落在 [1.50, 2.00) ⇒ tick 间隔被宿主机的 trace 写拉长，不是漏 tick"
    return False, f"比值 {ratio:.2f} 不在 [1.50, 2.00) ⇒ 不像仪器拉长，按内核自己的红来查"



def check_irq_trace(log: str, src: Path | None = None) -> tuple[list[str], str]:
    """M5-g③：把 QEMU `-d int` 数到的投递与内核自己报的两本账对起来。

    这台仪器买到的，是内核侧那三处计数自己给不了的三件事：
    * 投递**是不是机器发起的**：`apic` 那 16 格只证明「我接到并处理过」，
      handler 被自己的代码调一遍也能涨，所以「QEMU 真投过」必须有第二个来源；
    * **投给了谁**：那 16 格是全局的，目的地写错（投到别的核上）时它照样涨
      ⇒ `irq::by_cpu()` 那本账只能拿核外的数来对；这一维日志里没有 CPU 编号，
      但 `SP` 高位分辨得出 BSP（`ffffffff80…`）与非 BSP（`ffff8000…`，HHDM 下的 AP 栈）——
      见 BACKLOG 68e，所以「核外完全读不出目的地」这句旧话不要用；
    * **投递发生在哪一层**：`cpl` 与 `pc` 是出事瞬间的真相。区间内的每一发都该在
      内核窗口里、cpl=0；pc 不在内核窗口的那些单独数出来并报红 —— 那是一发落在
      「我们的 IDT 还没装好」的时刻，两边都不该把它算进相等式里假装对上了。

    返回 `(问题列表, 一行读数)`：读数无论红绿都打，红了要能说清是哪一维红的。
    """
    src = src or TRACE_LOG
    if not src.exists():
        return [f"trace 文件不存在：{src.name}（`-d int -D` 没挂上？）"], "trace 缺失"
    m = P5_CPU_RE.search(log)
    if not m:
        return ["内核没报出 `irq1..15=… 按CPU=[…]` 这一行 ⇒ 判定退化成只剩核外那一侧的数"], "内核侧读数缺失"
    txt = src.read_text(encoding="utf-8", errors="replace")
    hits = [(int(x.group("vec"), 16), x.group("cpl"), x.group("pc")) for x in TRACE_INT_RE.finditer(txt)]
    rng = [h for h in hits if 0x21 <= h[0] <= 0x2F]
    kern_rng = [h for h in rng if h[2].startswith("ffffffff80")]
    out_rng = [h for h in rng if not h[2].startswith("ffffffff80")]
    cpl_bad = [h for h in kern_rng if h[1] != "0"]
    total = int(m.group("total"))
    per = [int(x) for x in m.group("cpu").split(",")]
    others = sum(per[1:])
    bad: list[str] = []
    if not kern_rng:
        bad.append("trace 里区间内一发都没有 ⇒ 这一格在量它没有的东西（投递没发生，别当成相等成立）")
    if len(kern_rng) != total:
        bad.append(f"投递数对不上：宿主机数到 {len(kern_rng)} 发（内核窗口内），内核自报 irq1..15={total}")
    if per and per[0] != len(kern_rng):
        bad.append(f"内核里 BSP 那格 {per[0]} != 宿主机数到的 {len(kern_rng)}")
    if others:
        bad.append(f"有 {others} 发投到了非 BSP（目的地不该是它们；中断亲和性还没做）")
    if out_rng:
        bad.append(f"有 {len(out_rng)} 发区间内投递的 pc 不在内核窗口（IDT 没装好的时刻？不许混进相等式）")
    if cpl_bad:
        bad.append(f"有 {len(cpl_bad)} 发投递发生在 cpl!=0")
    by_vec: dict[str, int] = {}
    for v, _c, _pc in kern_rng:
        k = f"0x{v:02x}"
        by_vec[k] = by_vec.get(k, 0) + 1
    m_kt = KT_TOTAL_RE.search(log)
    reds = KT_FAIL_RE.findall(log)
    m_cal = CAL_REFUSED_RE.search(log)
    kern = (f" 内核用例={m_kt.group('passed')}/{m_kt.group('total')}" if m_kt else " 内核用例=?")
    if reds:
        kern += f" 红用例={reds}"
    if m_cal:
        kern += f" 标定被拒={m_cal.group('why')}"
    return bad, (f"宿主机={len(kern_rng)} 内核={total} 按CPU={per} 区间内={len(rng)} "
                 f"窗口外={len(out_rng)} cpl!=0={len(cpl_bad)} 按向量={by_vec}" + kern)




EDGE_EVENTS = ["ahci_check_irq", "ahci_irq_raise", "ahci_irq_lower", "ahci_trigger_irq",
               "ahci_cmd_done", "ahci_port_write"]
STORM_EVENTS = ["ahci_check_irq", "ahci_irq_raise"]
_EVENT_RE = re.compile(r"^(ahci_\w+) ahci\([0-9a-f]+\)(?:\[(\d)\])?: (.*)$")
_TRANS_RE = re.compile(r"(0x[0-9a-f]+)\s*-->\s*(0x[0-9a-f]+)")
_INT21_RE = re.compile(r": v=21 e=")
# 事件行里 PxIS 的 W1C 是"清源"这件事在设备侧的唯一可见形状
_W1C_RE = re.compile(r"ahci_port_write .*\[reg:PxIS\]")


def write_events(path: Path, names: list[str]) -> None:
    # 必须显式 LF：Windows 上 `write_text` 默认把 "\n" 换成 os.linesep，而 QEMU 解析事件清单
    # 时**不剥行尾的 \r**——实测 WSL 那颗 10.2.1 会报 `trace event 'apic_deliver_irq\r' does not
    # exist` 然后**带着零个事件照常启动**（BACKLOG 76c：仪器清单写坏的表现是"静默全盲"，不是报错退出）。
    path.write_text("\n".join(names) + "\n", encoding="utf-8", newline="\n")


def parse_ahci_trace(path: Path, cap: int = 6_000_000) -> dict[str, int]:
    """数设备事件与投递行。两者在**同一份文件**里（`-d int -D A` 与 `-trace file=B` 同给时
    只落 B），所以边沿与投递的先后不必靠时间戳对齐。

    `cap` 是硬上限而不是优化：不清源那一跑的 raise 以每秒几万条的速度长（实测 180 秒
    = 474 万条 raise、日志 7.4 GiB），不设上限的仪器会先把这台机吃死。
    """
    out = {"raise": 0, "边沿": 0, "被吸收": 0, "lower": 0, "trigger": 0,
           "cmd_done": 0, "pxis_w1c": 0, "投递": 0, "行数": 0}
    prev: tuple[str, str] | None = None
    if not path.exists():
        out["缺失"] = 1
        return out
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            out["行数"] += 1
            if out["行数"] > cap:
                out["截断"] = 1
                break
            m = _EVENT_RE.match(line.rstrip("\n"))
            if m:
                name, rest = m.group(1), m.group(3)
                if name == "ahci_check_irq":
                    t = _TRANS_RE.search(rest)
                    prev = (t.group(1), t.group(2)) if t else None
                elif name == "ahci_irq_raise":
                    out["raise"] += 1
                    if prev == ("0x00000000", "0x00000001"):
                        out["边沿"] += 1
                    elif prev == ("0x00000001", "0x00000001"):
                        out["被吸收"] += 1
                elif name == "ahci_irq_lower":
                    out["lower"] += 1
                elif name == "ahci_trigger_irq":
                    out["trigger"] += 1
                elif name == "ahci_cmd_done":
                    out["cmd_done"] += 1
                if _W1C_RE.match(line.rstrip("\n")):
                    out["pxis_w1c"] += 1
            elif _INT21_RE.search(line):
                out["投递"] += 1
    return out


def check_edge_absorption(ser: str, trc: Path, src: Path) -> tuple[list[str], str]:
    """M5-g④ 第 29 行：把「MSI 消息只由低到高的边沿产生」从对应关系升成判据。

    三条同时成立才算过：解析自洽、消息数等于边沿数、而**被吸收的那批真的存在**。
    最后一条是非空转条款——没有吸收的跑证不了吸收，与第 28 行「相等而两边都是 0 不算过」同一形状。
    """
    bad, why = check_irq_trace(ser, src=src)
    t = parse_ahci_trace(trc)
    if t.get("缺失"):
        bad.append(f"设备事件文件不存在：{trc.name}（`-trace events=` 没挂上？）")
    elif t.get("截断"):
        bad.append("事件文件被上限截断 ⇒ 边沿与投递的对应关系不再完整，别拿截断后的数当判据")
    else:
        if t["raise"] != t["边沿"] + t["被吸收"]:
            bad.append(f"解析不自洽：raise={t['raise']} 而 边沿+被吸收={t['边沿'] + t['被吸收']}"
                       " ⇒ 有 raise 前面没有 check_irq（这台 QEMU 的事件顺序变了，判据要重读）")
        # 方向式而不是等式：消息只可能由边沿产生，所以**投递绝不许多于边沿**。
        # 反方向的差额是有来历的：边沿落在 MSI 使能关着的窗口里就不成消息（`KT_IRQ_AHCI`
        # 故意关再开），所以那一侧只能给上界不能给等号。上一版写的是 `abs(边沿-投递) <= 1`，
        # 那是照一个样本拟的数——换个跑边沿从 5 变 6、投递仍是 4，当场假红。
        if t["投递"] > t["边沿"]:
            bad.append(f"投递比边沿多：投递={t['投递']} 边沿={t['边沿']} ⇒ 有消息不是边沿发出来的，"
                       "这台机的 MSI 不再是「只有低到高才发消息」")
        gap = t["边沿"] - t["投递"]
        if gap > t["pxis_w1c"] + 2:
            bad.append(f"有 {gap} 条边沿没成消息，而这一跑清源只做了 {t['pxis_w1c']} 次 ⇒ 差额没法用"
                       "「使能关着的窗口」解释，两个来源对不上")
        if t["被吸收"] < 20:
            bad.append(f"被吸收的 raise 只有 {t['被吸收']} 次 ⇒ 这一格在量它没有的东西")
    return bad, (f"raise={t['raise']} 边沿={t['边沿']} 被吸收={t['被吸收']} 清源={t['pxis_w1c']} "
                 f"投递={t['投递']}（边沿−投递={t['边沿'] - t['投递']}"
                 f"{'，差额落在使能关着的窗口' if t['边沿'] >= t['投递'] else '，投递反超：已红'}）｜ {why}")


def check_storm(trc: Path, floor: int) -> tuple[list[str], str]:
    """M5-g④ 第 30 行：故意不清 `PxIS` 之后，每一次清全局 `IS` 都成了新边沿 ⇒ 风暴。

    这一行证的不是"会挂死"，而是**边沿模型在两个方向上同时成立**：这里 raise 全部是边沿、
    而且每一条都兑现成投递；第 29 行那边 raise 大头是被吸收的 1→1、只有边沿兑现。
    """
    t = parse_ahci_trace(trc)
    bad: list[str] = []
    if t.get("缺失"):
        return [f"事件文件不存在：{trc.name}"], "事件缺失"
    if t["raise"] < floor:
        bad.append(f"raise 只有 {t['raise']} 次，低于下限 {floor} ⇒ 注入没造出风暴，"
                   "别把「没发生」读成「机制成立」")
    if t["raise"] and t["边沿"] != t["raise"]:
        bad.append(f"raise 里有 {t['raise'] - t['边沿']} 次不是 0→1 边沿 ⇒ 变体并没有把源留住，"
                   "这一跑的现场不是注入出来的那个")
    if abs(t["raise"] - t["投递"]) > 2:
        bad.append(f"raise 与投递不等：raise={t['raise']} 投递={t['投递']} ⇒ "
                   "「每个边沿一条消息」在这台机上不成立")
    return bad, (f"raise={t['raise']} 边沿={t['边沿']} lower={t['lower']} 投递={t['投递']} "
                 f"事件行数={t['行数']}")





ATOMIC_HEAD_RE = re.compile(
    r"^\[\w+\] 0x(?P<seq>[0-9a-f]{8}) atomic: cpu=(?P<cpu>\d+) n=(?P<n>\d+) tag=(?P<tag>\w+)")
ATOMIC_STAT_RE = re.compile(
    r"atomic: 判据 参与核=(?P<cpus>\d+) 每核行=(?P<lines>\d+) .*总行=(?P<total>\d+) "
    r"取锁=(?P<holds>\d+) 竞争=(?P<contended>\d+) 重入=(?P<nested>\d+) 超时=(?P<timeouts>\d+)")
HEAD_SEQ_RE = re.compile(r"^\[\w+\] 0x(?P<seq>[0-9a-f]{8}) ")


def check_line_atomicity(log: str) -> tuple[list[str], str]:
    """L3-A 的第二台仪器：数**行的形状**。内核那一台数账（`t_serial_atomic`），两边都过才算。

    四件事，各管一种错法：
    * 行数齐：参与核 × 每核行 == 宿主机数到的整行数，也 == 内核自报的总行（半行会被这里抓到）；
    * 序号列递增：序号在行锁**里面**取，所以输出顺序与序号顺序必须同套（取号在锁外会在这里红）；
    * tag 单一：一行里出现两个字母就是两行互相插进了正文；
    * tag 与 cpu 号一致：抓"张冠李戴"——行内容来自别的 CPU 而表头是这一颗。
    """
    m = ATOMIC_STAT_RE.search(log)
    if not m:
        return ["串口里没有 `atomic: 判据` 那一行 ⇒ 这一格在量它没有的东西（变体没跑起来？）"], "缺判据行"
    heads = [x.groupdict() for x in (ATOMIC_HEAD_RE.match(l) for l in log.splitlines()) if x]
    cpus = int(m.group("cpus"))
    per = int(m.group("lines"))
    want = cpus * per
    bad: list[str] = []
    if len(heads) != want:
        bad.append(f"整行数 {len(heads)} != 参与核×每核行 {want}（{cpus}×{per}）⇒ 有行被吞或只剩半行")
    if int(m.group("total")) != want:
        bad.append(f"内核自报总行 {m.group('total')} != 这个乘积 {want}")
    seq = [int(h["seq"], 16) for h in heads]
    inv = sum(1 for a, b in zip(seq, seq[1:]) if b <= a)
    if inv:
        bad.append(f"atomic 段的序号列有 {inv} 处不递增 ⇒ 序号不在行锁里取，或有行互相插了半边")
    all_seq = [int(x.group("seq"), 16) for x in (HEAD_SEQ_RE.match(l) for l in log.splitlines()) if x]
    all_inv = sum(1 for a, b in zip(all_seq, all_seq[1:]) if b <= a)
    if all_inv:
        bad.append(f"整份日志的序号列有 {all_inv} 处不递增（不止 atomic 那一段）")
    mixed = [h for h in heads if len(set(h["tag"])) != 1]
    if mixed:
        bad.append(f"{len(mixed)} 行的 tag 有两种以上字母（首例 cpu={mixed[0]['cpu']}）⇒ 两行互相插进了正文")
    wrong = [h for h in heads if ord(h["tag"][0]) - 97 != int(h["cpu"])]
    if wrong:
        bad.append(f"{len(wrong)} 行的 tag 与自己报的 CPU 号不一致")
    return bad, (f"整行数={len(heads)}/{want} 序号逆序=atomic段{inv}/全日志{all_inv} "
                 f"tag混行={len(mixed)} tag错主={len(wrong)} "
                 f"内核账[取锁={m.group('holds')} 竞争={m.group('contended')} 重入={m.group('nested')} "
                 f"超时={m.group('timeouts')}]")




SP_RE = re.compile(r"SP=[0-9a-f]{4}:(?P<sp>[0-9a-f]{8})")
AFF_STEP_RE = re.compile(r"irq-aff: 移到AP后 .*?按CPU=\[(?P<cpu>[0-9, ]+)\]")


def check_affinity(log: str) -> tuple[list[str], str]:
    """L3-B：目的地这一维由两台仪器各数一遍。

    内核那一台数它自己登记的槽（`irq::by_cpu()`）；这一台数 `-d int` 每一发的 `SP` 高位——
    BSP 的栈在 `ffffffff80…`，AP 的栈在 HHDM `ffff8000…`（BACKLOG 68e 实测，不是推断）。
    两边不是同一个来源：一个要改内核计数才动，一个要改栈布局才动，所以它们对上才算数。
    """
    if not TRACE_LOG.exists():
        return [f"trace 文件不存在：{TRACE_LOG.name}（`-d int -D` 没挂上？）"], "trace 缺失"
    m = P5_CPU_RE.search(log)
    if not m:
        return ["内核没报出 `irq1..15=… 按CPU=[…]` 这一行"], "内核侧读数缺失"
    total = int(m.group("total"))
    per = [int(x) for x in m.group("cpu").split(",")]
    bsp = ap = other = 0
    for line in TRACE_LOG.read_text(encoding="utf-8", errors="replace").splitlines():
        if ": v=21 " not in line:
            continue
        sp = SP_RE.search(line)
        head = sp.group("sp")[:8] if sp else ""
        if head == "ffffffff":
            bsp += 1
        elif head == "ffff8000":
            ap += 1
        else:
            other += 1
    bad: list[str] = []
    if bsp + ap + other == 0:
        bad.append("trace 里一发 0x21 都没有 ⇒ 这一格在量它没有的东西")
    if total != bsp + ap + other:
        bad.append(f"投递总数对不上：内核 {total}，宿主机 {bsp + ap + other}")
    if per and per[0] != bsp:
        bad.append(f"BSP 那格对不上：内核 {per[0]}，宿主机按 SP 数到 {bsp}")
    if sum(per[1:]) != ap:
        bad.append(f"非 BSP 那几格对不上：内核 {sum(per[1:])}，宿主机按 SP 数到 {ap}")
    if other:
        bad.append(f"有 {other} 发的 SP 既不是 BSP 栈也不是 HHDM 栈 ⇒ 归属这台仪器今天读不懂")
    if sum(per[1:]) < 1:
        bad.append("移动过目的地却没有任何一发落在非 BSP 上 ⇒ 这一格在量它没有的东西")
    ms = AFF_STEP_RE.search(log)
    step = [int(x) for x in ms.group("cpu").split(",")] if ms else []
    if not ms:
        bad.append("串口里没有 `irq-aff: 移到AP后 … 按CPU=[…]` 那行 ⇒ 用例没跑到移动那一步")
    else:
        step = [int(x) for x in ms.group("cpu").split(",")]
        if sum(step[1:]) < sum(per[1:]) or sum(step[1:]) < 1:
            bad.append(f"移动窗口里非 BSP 那几格没涨：窗口内 {step[1:]}，收尾 {per[1:]}")
    return bad, (f"内核={total} 宿主机={bsp + ap + other}（BSP栈={bsp} AP栈={ap} 其它={other}）"
                 f" 按CPU={per} 移动窗口非BSP={sum(step[1:]) if ms else '?'}")


APIC_DELIVER_RE = re.compile(
    r"apic_deliver_irq dest (?P<dest>\d+) dest_mode \d+ delivery_mode (?P<mode>\d+) "
    r"vector (?P<vec>\d+) trigger_mode (?P<trig>\d+)")
AFF_IDS_RE = re.compile(r"irq-aff: 判据 BSP id=(?P<bsp>0x[0-9a-f]+) AP id=(?P<ap>0x[0-9a-f]+) "
                        r"槽=(?P<slot>\d+)")
AHCI_VEC_RE = re.compile(r"irq-ahci: 判据 .*?向量=(?P<vec>0x[0-9a-f]{2})")


def parse_apic_deliver(src: Path, vec: int, cap: int = 6_000_000) -> tuple[dict[int, int], int, int]:
    """数控制器收到的消息：返回 `(按 dest 的计数, 该向量总条数, 读到的行数)`。

    `cap` 是硬上限（第 30 行那种一跑几百万条的教训）：读够就停，宁可少读也不要把宿主机的盘写爆。
    """
    by_dest: dict[int, int] = {}
    total = lines = 0
    with src.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            lines += 1
            if lines > cap:
                break
            m = APIC_DELIVER_RE.match(line.strip())
            if not m or int(m.group("vec")) != vec:
                continue
            d = int(m.group("dest"))
            by_dest[d] = by_dest.get(d, 0) + 1
            total += 1
    return by_dest, total, lines


def check_deliver_layer(log: str, src: Path | None = None) -> tuple[list[str], str]:
    """投递的三层各由一台仪器数，层与层之间只有**方向式**关系，没有相等式。

    三层是：设备决定拉高（`ahci_irq_raise`）→ 控制器收到消息（`apic_deliver_irq`，带 dest）
    → CPU 真收了那一发（内核 ISR 条目，`irq1..15=`）。每一发 ISR 必须先有一条消息、每条消息
    都来自一次拉高决定；**合并只会让上层更多，不会让下层更多**，所以写 `≤` 而不是 `==`
    （写 `==` 就是照某一次观测拟数，与 71a 那个错法同源）。

    目的地那一维在这里是直读：`dest` 就是中断控制器解码 MSI 地址之后看到的值。
    上一格（第 32 行）是从 `-d int` 的 SP 高位**推断**发生在哪个核上——两件事不一样：
    推断证明"处理发生在 AP 栈上"，直读证明"目的地字段真的被控制器按我们写的那个值解出来了"。

    仪器瞎了必须红，不许读成"没有消息"：`apic_deliver_irq` 一条都没有 ⇒ 这一档的 LAPIC
    不在 QEMU 用户态（KVM 的 split/on irqchip 就是这样，实测 0 条），这一格在这一档不可判。
    """
    src = src or DELIVER_LOG
    bad: list[str] = []
    if not src.exists():
        return [f"控制器事件文件不存在：{src.name}（`-trace events=apic_deliver_irq` 没挂上？）"], "trace 缺失"
    mv = AHCI_VEC_RE.search(log)
    mid = AFF_IDS_RE.search(log)
    m = P5_CPU_RE.search(log)
    if not mv:
        return ["内核没报出 `irq-ahci: 判据 … 向量=0xNN` ⇒ 宿主机不知道要数哪个向量（不猜常数）"], "内核侧读数缺失"
    if not mid:
        return ["串口里没有 `irq-aff: 判据 BSP id=… AP id=…` ⇒ 目的地没有可比的身份"], "内核侧读数缺失"
    if not m:
        return ["内核没报出 `irq1..15=… 按CPU=[…]`"], "内核侧读数缺失"
    vec = int(mv.group("vec"), 16)
    bsp_id = int(mid.group("bsp"), 16)
    ap_id = int(mid.group("ap"), 16)
    total = int(m.group("total"))
    per = [int(x) for x in m.group("cpu").split(",")]
    raises = 0
    events = 0
    with src.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.strip()
            if s.startswith("ahci_irq_raise"):
                raises += 1
            elif s.startswith("apic_deliver_irq"):
                events += 1
    by_dest, msgs, _ = parse_apic_deliver(src, vec)
    if events == 0:
        bad.append(f"控制器一条投递事件都没有（本跑 raise={raises}）⇒ 这一档的 LAPIC 不在 QEMU 用户态，"
                   f"这一格不可判；不许读成「没有投递」")
    if not bad:
        if msgs == 0:
            bad.append(f"向量 {vec:#04x} 一条消息都没有 ⇒ 这一格在量它没有的东西")
        if total > msgs:
            bad.append(f"层间方向破了：内核 ISR 条目 {total} > 控制器消息 {msgs}（每一发处理都必须先有一条消息）")
        if per and per[0] > by_dest.get(bsp_id, 0):
            bad.append(f"BSP 那格 {per[0]} > 目的地 {bsp_id:#x} 的消息数 {by_dest.get(bsp_id, 0)}")
        if sum(per[1:]) > by_dest.get(ap_id, 0):
            bad.append(f"非 BSP 那几格 {sum(per[1:])} > 目的地 {ap_id:#x} 的消息数 {by_dest.get(ap_id, 0)}")
        if by_dest.get(ap_id, 0) == 0:
            bad.append(f"移动过目的地却没有任何一条消息的 dest 是 {ap_id:#x} ⇒ 设备侧没被重新编程，"
                       f"或者亲和性只是核内表里改了个数（第 32 行的 SP 那一维看不出这种错）")
        if msgs > raises:
            bad.append(f"消息 {msgs} > 设备拉高决定 {raises} ⇒ 计数来源不对（消息只能来自拉高）")
        unknown = {d: c for d, c in by_dest.items() if d not in (bsp_id, ap_id)}
        if unknown:
            bad.append(f"有 {sum(unknown.values())} 发去了没登记过的目的地 {unknown}")
    return bad, (f"拉高={raises} 消息={msgs}（按目的地="
                 + ",".join(f"{d:#x}:{c}" for d, c in sorted(by_dest.items())) +
                 f"） ISR={total}（BSP={per[0] if per else '?'} 非BSP={sum(per[1:]) if per else '?'}）"
                 f" 向量={vec:#04x} BSPid={bsp_id:#x} APid={ap_id:#x}")


def do_check(elf: Path | None) -> int:
    gates = {
        "check-lints-wired": lambda: check_lints_wired(),
        "check-unsafe": lambda: check_unsafe_registry(),
        "check-crates": lambda: check_crates_listed(),
        "check-driver-ctx": lambda: check_driver_no_raw(),
        "check-state-window": lambda: check_state_window(),
        "check-virtio-pattern": lambda: check_virtio_pattern(),
        "check-net-pattern": lambda: check_net_pattern(),
        "check-sha-primitives": lambda: check_sha_primitives(),
        "check-sig-anchor": lambda: check_sig_anchor(),
        "check-sbom": lambda: check_sbom(),
        "check-matrix-wiring": lambda: check_matrix_wiring(),
        "check-verdict": lambda: check_verdict_contract(),
        "check-nofloat": (lambda: check_nofloat(elf)) if elf else (lambda: ["未提供内核镜像路径"]),
    }
    rc = 0
    for name, fn in gates.items():
        bad = fn()
        if bad:
            rc = 1
            print(f"[FAIL] {name}")
            for b in bad:
                print("       ", b)
        else:
            print(f"[ ok ] {name}")
    return rc


# -------------------------------------------------------------------- 负样本

def do_test(timeout: int) -> int:
    """正向必须 33、负样本必须 35。只跑正向的话，永远分不清“代码没问题”
    和“判定链根本没生效”。"""
    print("=== 正向 ===")
    v, rc, log = do_run([], timeout)
    good = v == "PASS"
    print("=== 负样本（--features negative-probe，按设计应失败）===")
    IMAGE.unlink(missing_ok=True)
    nv, nrc, nlog = do_run(["negative-probe"], timeout)
    neg_ok = nv == "FAIL"
    print()
    print("=== L4 注入（--features fault-double-free，重复释放必须停机）===")
    IMAGE.unlink(missing_ok=True)
    dv, drc, dlog = do_run(["fault-double-free"], timeout)
    l4_ok = dv == "EXCEPTION"
    print("=== L4 注入（--features fault-heap-oom，堆分配失败必须升到 39）===")
    IMAGE.unlink(missing_ok=True)
    ov, orc, olog = do_run(["fault-heap-oom"], timeout)

    print("=== 泄漏注入（--features fault-resource-leak，台账必须抓到）===")
    IMAGE.unlink(missing_ok=True)
    lv, lrc, llog = do_run(["fault-resource-leak"], timeout)
    print("=== 中断内分配注入（--features fault-alloc-in-irq，守卫必须挡下）===")
    IMAGE.unlink(missing_ok=True)
    av, arc, alog = do_run(["fault-alloc-in-irq"], timeout)
    print("=== 锁重入注入（--features fault-lock-reentrant，held_by 必须当场叫）===")
    IMAGE.unlink(missing_ok=True)
    rv, rrc, rlog = do_run(["fault-lock-reentrant"], timeout)

    # ADR-021 的负样本：把"IF 属于 CPU"改回"任务自己带 IF"。
    # 期望是**挂死**而不是报红——被抢占过的任务换回来时带着 IF=0，就再没有 tick 能抢占任何人。
    # 这与 M3a 记录的症状同一条（那次是"第二段窗口一条 tick 都收不到"，最后是整机停摆）。
    # 这一行单独用较短的超时：它注定要等到超时，用全矩阵的 120s 只是白等。
    # §5.1 R17 的负样本：SMEP/SMAP 是必需项，清掉 SMAP 位必须让启动停在 BOOT-INVALID(37)。
    print("=== 必需项注入（--features fault-no-smap，SMAP 没开成必须不启动）===")
    IMAGE.unlink(missing_ok=True)
    sv2, src2, slog2 = do_run(["fault-no-smap"], timeout)

    print("=== IF 归属注入（--features fault-if-carriage，按 ADR-021 必须挂死）===")
    IMAGE.unlink(missing_ok=True)
    fv, frc, flog = do_run(["fault-if-carriage"], min(timeout, 60))

    # §6.6 的负样本：收到 shootdown 的 CPU 照常 invlpg，但**不回执**。
    # 请求方必须在有界等待到期时升 L4：收不齐回执就归还物理页 = 允许两个主人同一块页。
    print("=== 高 LBA 判据（--features ahci-scratch，多挂一块 130 GiB 的 qcow2）===")
    hv, hrc, hlog = do_run(["ahci-scratch"], timeout)
    print("=== 高位写错注入（--features fault-ahci-highlba，字节 8 按 >>32 写）===")
    ghv, ghrc, ghlog = do_run(["fault-ahci-highlba"], timeout)
    print("=== 写方向少编程扇区数（--features fault-ahci-write-partial，回读必须不一致）===")
    pwv, pwrc, pwlog = do_run(["fault-ahci-write-partial"], timeout)
    print("=== 写方向丢 W 位注入（--features fault-ahci-write-dir，本机测不出来）===")
    wdv, wdrc, wdlog = do_run(["fault-ahci-write-dir"], timeout)
    print("=== 计数位置注入（--features fault-ahci-count-hi，257 扇区那次必须红）===")
    IMAGE.unlink(missing_ok=True)
    chv, chrc, chlog = do_run(["fault-ahci-count-hi"], timeout)
    print("=== 块内容对账注入（--features fault-ahci-lba，内核全绿但标签错了）===")
    IMAGE.unlink(missing_ok=True)
    cv, crc, clog = do_run(["fault-ahci-lba"], timeout)
    print("=== shootdown 不回执注入（--features fault-shootdown-noack，必须升 L4）===")
    IMAGE.unlink(missing_ok=True)
    sv, src, slog = do_run(["fault-shootdown-noack"], timeout)
    print("=== virtio-blk 取证（--features virtio-blk，第三块盘走 virtio）===")
    vv, vrc, vlog = do_run(["virtio-blk"], timeout)
    print("=== 启动循环保护：同一份镜像连跑四遍（--features negative-probe），第四次必须进安全模式 ===")
    # §9.4 的验收句在这一行：注入故障后系统会不会*自己*走向安全模式，只有跨重启才看得出来。
    # 所以这四遍**不许重建镜像**（`ensure_image` 比的是"变体 + ELF 摘要"，同变体同 ELF 就复用），
    # 而开头先 unlink 一次，把状态区放回装机时的初始记录。
    IMAGE.unlink(missing_ok=True)
    loop: list[tuple[str, int, str]] = []
    for _ in range(4):
        lpv, lprc, lplog = do_run(["negative-probe"], timeout)
        m = re.search(r"boot: 模式=(\w+) 读到的连续失败=(\d+) 阈值=(\d+) 读不到=(\w+)", lplog)
        loop.append((lpv, int(m.group(2)) if m else -1, m.group(1) if m else "?"))
    counts = [n for _, n, _ in loop]
    modes = [mm for _, _, mm in loop]
    verdicts = [v for v, _, _ in loop]
    loop_ok = counts == [0, 1, 2, 3] and modes == ["Normal", "Normal", "Normal", "Safe"] and all(v == "FAIL" for v in verdicts)
    print(f"    四遍读数 连续失败={counts} 模式={modes} 判定={verdicts}")
    IMAGE.unlink(missing_ok=True)   # 别让后面那几行继承一个"已经失败三次"的镜像

    print("=== 安全模式退回正常：把计数做到盘上，再连着起两遍健康构建 ===")
    # §9.4 的另一半：进了安全模式之后必须**出得去**。这个现场以前只能靠偶发撞（一次"状态区读不到"
    # 把机器锁在 Safe 里 9 遍，见 BACKLOG ㊿），现在由宿主机直接改盘做出来 ⇒ 判据是确定的。
    do_run([], timeout)             # 先让正常构建在新镜像上写出自己的那条记录
    force_boot_state(99)            # 槽 0：seq=200、连续失败=99 ⇒ 下一遍必须以 Safe 起来
    sbv, sbrc, sblog = do_run([], timeout)
    snv, snrc, snlog = do_run([], timeout)
    went_safe = re.search(r"boot: 模式=Safe 读到的连续失败=99", sblog) is not None
    cleared = "boot: 健康清零" in sblog
    back_normal = re.search(r"boot: 模式=Normal 读到的连续失败=0", snlog) is not None
    loop_back_ok = went_safe and cleared and back_normal and sbv == "PASS" and snv == "PASS"
    print(f"    强制 Safe 遍：模式读到 Safe={went_safe} 健康清零={cleared} 判定={sbv}；"
          f"下一遍：回到 Normal={back_normal} 判定={snv}")
    IMAGE.unlink(missing_ok=True)

    print("=== virtio 第一条 I/O 落到盘上：再跑一遍 virtio-blk，宿主机读扇区 8 ===")
    # 内核那三条判据（图案、位置敏感、写完回读）都在同一个进程里；这一遍把
    # "确实落到那块 qcow2 上"交给第二台仪器（qemu-io）。同一变体再跑一次也是幂等性检查。
    vvi, vvic, vvilog = do_run(["virtio-blk"], timeout)
    vblk_bad = check_vblk_write(vvilog)
    vblk_verdict = "PASS" if not vblk_bad else "CONTENT-MISMATCH"
    for x in vblk_bad:
        print("    对账:", x)
    IMAGE.unlink(missing_ok=True)

    print("=== 崩溃记录跨重启读回：同一份镜像连跑两遍 fault-double-free ===")
    # §9.7 的另一半只能跨重启量：崩溃时写下的摘要，要被**下一次启动**读回来。
    # 两遍用同一个变体 ⇒ `ensure_image` 复用镜像（它比的是"变体 + ELF 摘要"），
    # 第二遍读到的才是第一遍留在盘上的那条；换成另一个变体就会重建镜像、把记录一起抹掉。
    IMAGE.unlink(missing_ok=True)
    cbv1, cbrc1, cblog1 = do_run(["fault-double-free"], timeout)
    cbv2, cbrc, cblog2 = do_run(["fault-double-free"], timeout)
    crash_report_ok, crash_host_ok, _ = crash_cross(cblog1, cblog2)
    crash_back_ok = crash_report_ok and crash_host_ok and cbv1 == "EXCEPTION" and cbv2 == "EXCEPTION"
    print(f"    两遍判定={cbv1}/{cbv2} 内核自报对上={crash_report_ok} 宿主机解出同一条={crash_host_ok}")
    IMAGE.unlink(missing_ok=True)

    print("=== 崩溃现场是真异常给的：同一份镜像连跑两遍 fault-crash-oops ===")
    # 第 20 行验的是"字段搬得对不对"，这一行验的是"字段是不是 CPU 给的那个数"：
    # 核心态故意读一个未映射地址 ⇒ #PF(14) 没有恢复项 ⇒ 停机前落盘。
    # 于是同一遍启动里有两处现场：串口打的 `cpu] vec=14 …` 与记录里那一条，必须同数；
    # 向量必须是 14、CR2 必须等于用例注入的那个地址（这两个数是"真到过异常里"的证人）。
    # M6-e 起再加一维：帧数组逐条由 ELF 符号表解成函数名，前两层必须是
    # 「故意越界那个函数」与「ktest 运行器」——函数边界内核给不出（`.symtab` 不在运行时镜像里）。
    oov1, _orc1, oolog1 = do_run(["fault-crash-oops"], timeout)
    oov2, oorrc, oolog2 = do_run(["fault-crash-oops"], timeout)
    oo_report_ok, oo_host_ok, oo_site_ok = crash_cross(oolog1, oolog2)
    oo_sym_ok, oo_sym_why = crash_frames_symbolized(oolog1)
    m_oo = CRASH_DUMP_RE.search(oolog1)
    oops_ok = bool(oo_report_ok and oo_host_ok and oo_site_ok and oo_sym_ok
                   and m_oo and int(m_oo.group("vec")) == 14
                   and m_oo.group("cr2") == "0xffffc00000000008"
                   and int(m_oo.group("nfr")) >= len(OOPS_FRAMES_FNS)
                   and oov1 == "EXCEPTION" and oov2 == "EXCEPTION")
    print(f"    两遍判定={oov1}/{oov2} 自报={oo_report_ok} 宿主机={oo_host_ok} 与串口现场同一条={oo_site_ok} "
          f"向量={m_oo.group('vec') if m_oo else '无'} 帧数={m_oo.group('nfr') if m_oo else '无'} "
          f"符号化={oo_sym_ok}（{oo_sym_why}）")
    print("=== 崩溃前的最近日志：跑一遍 fault-crash-oops，宿主机拿盘上那段与这一遍串口原文逐行比 ===")
    # §9.7 的"最近日志"：内核在停机前把环形缓冲里最后那几行**整行**写进 kind=3 记录。
    # 这一行是新开的第二台仪器：文本内容、行数、以及"取的是哪一刻"都由核外判，
    # 因为内核自己数出来的行数与它写进记录的行数是同一个来源（`KT_LOG_TAIL` 只能证搬运工）。
    IMAGE.unlink(missing_ok=True)
    ltv, ltrc, ltlog = do_run(["fault-crash-oops"], timeout)
    lt_ok, lt_why = log_tail_cross(ltlog)
    lt_verdict = ltv if ltv != "EXCEPTION" else ("EXCEPTION" if lt_ok else "CONTENT-MISMATCH")
    print(f"    判定={ltv} 日志尾对账={lt_ok}（{lt_why}）")
    IMAGE.unlink(missing_ok=True)

    print("=== 网卡第一帧上了线：跑 virtio-net，宿主机读 filter-dump 写下的 pcap ===")
    # 内核那八格只到"驱动自己一致"这一层：队列起来了、回执来了、缓冲没被动过。
    # **帧的每一个字节是不是我们声称的那一帧**只有核外的仪器能答，这一行就是那台仪器。
    # 抓包文件由 `do_run` 在挂网卡那一路里先删后写，所以这里读到的一定是这一遍发的
    ntv, ntrc, ntlog = do_run(["virtio-net"], timeout)
    net_bad = check_net_tx(ntlog)
    # 内核自己没绿就照报它的判定级：把"驱动红了"与"驱动绿了但发出去的不是那一帧"混成
    # 同一个 CONTENT-MISMATCH，等于把两类成因合成一个数（§12.3 的分法）
    net_verdict = ntv if ntv != "PASS" else ("PASS" if not net_bad else "CONTENT-MISMATCH")
    for x in net_bad:
        print("    对账:", x)
    PCAP.unlink(missing_ok=True)
    IMAGE.unlink(missing_ok=True)

    print("=== SHA-256 的十三条长度向量：跑 sig-check，宿主机用 hashlib 各算一遍 ===")
    # 表错了 / 补位错了 / 端序错了 / 块边界错了——这四类在"内核自己算自己比"里全是绿的，
    # 只有第二台实现能看见。长度向量专门踩补位的四个边界（55|56、63|64、111|112、119|120）
    shv, shrc, shlog = do_run(["sig-check"], timeout)
    # 同一个变体再跑一遍给签名包那一行用：判定表要求每一行拿自己那一跑的日志
    spv, sprc, splog = do_run(["sig-check"], timeout)
    sig_bad = check_sig_package(splog)
    sig_verdict = spv if spv != "PASS" else ("PASS" if not sig_bad else "CONTENT-MISMATCH")
    for x in sig_bad:
        print("    对账:", x)
    sha_bad = check_sha256(shlog)
    sha_verdict = shv if shv != "PASS" else ("PASS" if not sha_bad else "CONTENT-MISMATCH")
    for x in sha_bad:
        print("    对账:", x)
    IMAGE.unlink(missing_ok=True)

    print("=== 第一条真协议往返：再跑一遍 virtio-net，宿主机自己解 pcap 里那条回话 ===")
    # 内核那份 `parse_reply` 与宿主机这份 `bootp_of` 是**两条独立实现**，同一个数对上才叫
    # "读回来的就是那一包"；而 `yiaddr` 是宿主机自己定的（`dhcpstart=`），内核猜不到 ⇒
    # 这一行里唯一答案在核外的判据。同一变体再跑一遍也是幂等性检查（与第 22 行同一形状）
    rtv, rtrc, rtlog = do_run(["virtio-net"], timeout)
    rx_bad = check_net_rx(rtlog)
    rx_verdict = rtv if rtv != "PASS" else ("PASS" if not rx_bad else "CONTENT-MISMATCH")
    for x in rx_bad:
        print("    对账:", x)
    PCAP.unlink(missing_ok=True)
    IMAGE.unlink(missing_ok=True)

    print("=== 中断投递由宿主机数到：跑正常构建挂 `-d int`，把 QEMU 的投递日志与内核两本账对起来 ===")
    # 这一格是 M5-g② 那三处内核侧计数的第二台仪器：`apic` 的 16 格证明「我处理过」，
    # 证明不了「机器真投过」，更证明不了「投给了 BSP」（那本账是全局的）。三个数各来一遍。
    TRACE_LOG.unlink(missing_ok=True)
    IMAGE.unlink(missing_ok=True)
    itv, itrc, itlog = do_run([], timeout, extra=f"-d int -D {TRACE_LOG}")
    it_bad, it_why = check_irq_trace(itlog)
    # 与第 22/24/27 行同一形状：内核自己没绿就照报它的判定级，红了才分得清是内核的事还是对账的事。
    # 唯一的例外是仪器自己造成的那一条链（`instrument_caused_red`），放行时必须在读数里点名，
    # 而六个维度一旦对不上就绝不放行——那条判据与 trace 写盘无关。
    excused, it_excuse = instrument_caused_red(itlog)
    if itv == "PASS":
        it_verdict = "PASS" if not it_bad else "CONTENT-MISMATCH"
    else:
        it_verdict = "PASS" if (excused and not it_bad) else itv
    print(f"    判定={itv} 投递对账={not it_bad}（{it_why}）")
    if itv != "PASS":
        print(f"    仪器链：{'放行' if it_verdict == 'PASS' else '不放行'}｜{it_excuse}")
    for x in it_bad:
        print("    对账:", x)
    TRACE_LOG.unlink(missing_ok=True)
    print("=== 边沿与消息由设备事件数到：正常构建再挂 `-trace events`，把 68 那条对应关系变成判据 ===")
    # 两个仪器同给时 `-D` 那份不生成，所以第 28 行的六维这一跑要从合并文件里读（src=EDGE_LOG）
    EVENTS_TXT.unlink(missing_ok=True)
    EDGE_LOG.unlink(missing_ok=True)
    TRACE_LOG.unlink(missing_ok=True)
    IMAGE.unlink(missing_ok=True)
    write_events(EVENTS_TXT, EDGE_EVENTS)
    eav, earc, erglog = do_run([], timeout, extra=(f"-d int -D {TRACE_LOG} "
                                                   f"-trace events={EVENTS_TXT} -trace file={EDGE_LOG}"))
    ea_bad, ea_why = check_edge_absorption(erglog, EDGE_LOG, EDGE_LOG)
    ea_excused, _ = instrument_caused_red(erglog)
    if eav == "PASS":
        ea_verdict = "PASS" if not ea_bad else "CONTENT-MISMATCH"
    else:
        ea_verdict = "PASS" if (ea_excused and not ea_bad) else eav
    print(f"    判定={eav} 边沿对账={not ea_bad}（{ea_why}）")
    for x in ea_bad:
        print("    对账:", x)
    EDGE_LOG.unlink(missing_ok=True)

    print("=== 不清源就风暴：变体 irq-sticky-pxis，6 秒有界窗口（实测 180 秒会写出 7.4 GiB 日志）===")
    EVENTS_TXT.unlink(missing_ok=True)
    STORM_LOG.unlink(missing_ok=True)
    TRACE_LOG.unlink(missing_ok=True)
    IMAGE.unlink(missing_ok=True)
    write_events(EVENTS_TXT, STORM_EVENTS)
    strc = -1
    stv, stlog = "HANG", ""
    st_verdict, st_bad, st_why = "HANG", [], "跳过"
    if STORM_TIMEOUT > 0:
        stv, strc, stlog = do_run(["irq-sticky-pxis"], STORM_TIMEOUT,
                                  extra=(f"-d int -D {TRACE_LOG} -trace events={EVENTS_TXT} "
                                         f"-trace file={STORM_LOG}"))
        st_bad, st_why = check_storm(STORM_LOG, STORM_FLOOR)
        if stv == "HANG":
            st_verdict = "HANG" if not st_bad else "CONTENT-MISMATCH"
        else:
            st_verdict = stv
        print(f"    判定={stv} 风暴对账={not st_bad}（{st_why}）")
        for x in st_bad:
            print("    对账:", x)
    STORM_LOG.unlink(missing_ok=True)
    TRACE_LOG.unlink(missing_ok=True)

    print("=== 整行原子性由宿主机数形状：变体 serial-atomic-probe，四个 CPU 同时各打一批行 ===")
    # 内核那一台仪器数账（行锁四本账与每 CPU 行数），这台数行的形状——两边都过才算，单侧绿不算
    IMAGE.unlink(missing_ok=True)
    lav, larc, lalog = do_run(["serial-atomic-probe"], timeout)
    la_bad, la_why = check_line_atomicity(lalog)
    la_verdict = lav if lav != "PASS" else ("PASS" if not la_bad else "CONTENT-MISMATCH")
    print(f"    判定={lav} 形状对账={not la_bad}（{la_why}）")
    for x in la_bad:
        print("    对账:", x)
    IMAGE.unlink(missing_ok=True)

    print("=== 目的地由宿主机按 SP 形状数到：变体 irq-affinity-probe 挂 `-d int`，两台仪器各数一遍归属")
    TRACE_LOG.unlink(missing_ok=True)
    IMAGE.unlink(missing_ok=True)
    afv, afrc, aflog = do_run(["irq-affinity-probe"], timeout, extra=f"-d int -D {TRACE_LOG}")
    af_bad, af_why = check_affinity(aflog)
    af_excused, _ = instrument_caused_red(aflog)
    if afv == "PASS":
        af_verdict = "PASS" if not af_bad else "CONTENT-MISMATCH"
    else:
        af_verdict = "PASS" if (af_excused and not af_bad) else afv
    print(f"    判定={afv} 归属对账={not af_bad}（{af_why}）")
    for x in af_bad:
        print("    对账:", x)
    TRACE_LOG.unlink(missing_ok=True)
    IMAGE.unlink(missing_ok=True)

    print("=== 投递三层由控制器事件数到：同一变体改挂 `-trace events`（不带 `-d int`，"
          "所以这一跑的耗时数字可用，目的地也是直读）===")
    EVENTS_TXT.unlink(missing_ok=True)
    DELIVER_LOG.unlink(missing_ok=True)
    IMAGE.unlink(missing_ok=True)
    write_events(EVENTS_TXT, DELIVER_EVENTS)
    dlv, dlrc, dllog = do_run(["irq-affinity-probe"], timeout,
                              extra=f"-trace events={EVENTS_TXT} -trace file={DELIVER_LOG}")
    dl_bad, dl_why = check_deliver_layer(dllog)
    if dlv == "PASS":
        dl_verdict = "PASS" if not dl_bad else "CONTENT-MISMATCH"
    else:
        dl_verdict = dlv
    print(f"    判定={dlv} 分层对账={not dl_bad}（{dl_why}）")
    for x in dl_bad:
        print("    对账:", x)
    DELIVER_LOG.unlink(missing_ok=True)
    IMAGE.unlink(missing_ok=True)

    rows = [
        ("正向", v, rc, "PASS", 33),
        ("负样本", nv, nrc, "FAIL", 35),
        ("L4 重复释放", dv, drc, "EXCEPTION", 39),
        ("L4 堆分配失败", ov, orc, "EXCEPTION", 39),
        ("泄漏注入被检出", lv, lrc, "FAIL", 35),
        # 守卫拒绝之后容器路径必然走 handle_alloc_error（ADR-018 的稳定版唯一去向），
        # 所以这条构建的正确期望是 39 而不是 35：违规被**当场停机**，比继续跑完用例更好。
        ("中断内分配被挡下", av, arc, "EXCEPTION", 39),
        ("锁重入被抓住", rv, rrc, "EXCEPTION", 39),
        # 必需项没开成 = 前提不满足，处置是**不启动**（37），不是运行中停机（39）：
        # §9.2 把这两类分成不同级正是因为处置不同，判据也必须能分辨它们。
        ("SMAP 没开成不启动", sv2, src2, "BOOT-INVALID", 37),
        # 挂死不是一种"错误码"，而是判定契约里的独立一级（§12.3）：这里它就是期望结果
        ("IF 归任务就挂死", fv, frc, "HANG", -1),
        ("shootdown 收不齐回执升 L4", sv, src, "EXCEPTION", 39),
        # 期望的是**新的一级**而不是 FAIL：这一条的故障在内核之外，rc 仍是 33
        ("块内容对账抓得出错标签", cv, crc, "CONTENT-MISMATCH", 33),
        # 这条红在**内核里**，不是对账层。原先我推测的成因是"QEMU 把命令丢掉 ⇒ 有界等待到期"，
        # 实测不是：它搬完 count 个扇区就正常完成，所以红的是**长读尾巴与单独那一扇区对不上**
        # （见 BACKLOG ㉜）。它证明"跨 255 扇区那次读"确实是扇区数高字节的判据
        ("计数放错位置读不出长块", chv, chrc, "FAIL", 35),
        # 这两行是一对：第一行证明"字节 8 写对了读得到 128 GiB 外那一格"，
        # 第二行把它改回我第一版的写法（`>>32`），必须红 ⇒ 这条判据不是空转
        ("高LBA 与写方向判据成立", hv, hrc, "PASS", 33),
        ("高位写错就读不到图案", ghv, ghrc, "FAIL", 35),
        # 写方向两条负样本，结论不一样：少编程扇区数**能咬**（回读逐字节当场不一致）；
        # 丢 DW0 的 W 位在本机**不可见**（方向由命令字节 0x35 决定，QEMU 不看 W 位）。
        # 后一条的期望按实测写成 PASS —— 它是记录，不是判据；真机上必须重测这一格。
        ("写方向少编程扇区数必须红", pwv, pwrc, "FAIL", 35),
        ("丢 W 位本机不可见", wdv, wdrc, "PASS", 33),
        # virtio 那台设备的取证：能力链、选页对、状态字节、队列选择器都要成立。
        # 期望 PASS 的含义是"十格证人全过"，不是"我读到了想要的数"——任何一格读不懂
        # 都会让内核自己红（`virtio: 取证判据 …` 那一行带着全部读数）
        ("virtio 取证十格证人全过", vv, vrc, "PASS", 33),
        # 这一行的"实际值"是四遍启动的**序列**，不是某一遍的退出码：序列不对就报
        # `SEQ-BROKEN`，那与"内核自己红了"（FAIL）是两种不同的成因，必须分得开
        ("启动循环三次后进安全模式", "FAIL" if loop_ok else "SEQ-BROKEN", lprc, "FAIL", 35),
        # 第 19 行与第 18 行是一对：18 行证"进得去"，这一行证"出得来"。两遍都是健康构建，
        # 所以期望判定是 PASS(33)；实际值同样是**两遍的序列**（强制 Safe → 健康清零 → 回 Normal）
        ("安全模式健康后退回正常", "PASS" if loop_back_ok else "SEQ-BROKEN", snrc, "PASS", 33),
        # §9.7 那一半同样是跨重启的事实：第一遍崩下来写进盘上的摘要，第二遍必须读回来，
        # 而且宿主机按同一套偏移解出的那条要与内核自报的逐字段相同
        ("崩溃记录跨重启读回", "EXCEPTION" if crash_back_ok else "SEQ-BROKEN", cbrc, "EXCEPTION", 39),
        # 第 20 行证"字段搬得对"，这一行证"字段是 CPU 给的"：向量必须 14、CR2 必须等于注入地址、
        # 记录必须与同一遍串口打的那条异常现场同数
        ("崩溃现场来自真异常", "EXCEPTION" if oops_ok else "SEQ-BROKEN", oorrc, "EXCEPTION", 39),
        # M6-f：崩溃前那几行整行日志落盘之后，由核外把它与**同一遍**串口原文逐行对账。
        # 内核自己崩了是期望（39），而"落下去的那段不是这一遍的话"报 CONTENT-MISMATCH——两种成因分得开
        ("日志尾与串口逐行对账", lt_verdict, ltrc, "EXCEPTION", 39),
        # M5-g③：投递是否真由机器发起、是否投给 BSP，由 QEMU 的 `-d int` 日志与内核两本账对出来
        ("中断投递由宿主机数到", it_verdict, itrc, "PASS", 33),
        # M5-g④：消息与边沿一对一、而 1→1 那批 raise 一条消息都不发——两件事在同一跑里数出来
        ("边沿与消息由设备事件数到", ea_verdict, earc, "PASS", 33),
        # 故意不清源的那一跑：期望就是挂死（风暴把机器淹了），而"淹"这件事由 raise 与投递的 1:1 说话
        ("不清源就风暴（有界窗口）", st_verdict, strc, "HANG", -1),
        # L3-A：行锁在内核数账，宿主机数行的形状（序号递增、tag 单一、行数齐）——两台都要过
        ("整行原子性由宿主机数到", la_verdict, larc, "PASS", 33),
        # L3-B：投递归属——内核数登记的槽，宿主机数 SP 的形状，两个来源必须数到同一件事
        ("目的地由宿主机按SP数到", af_verdict, afrc, "PASS", 33),
        ("投递三层由控制器事件数到", dl_verdict, dlrc, "PASS", 33),
        # M5-f②：第一条 virtio I/O 落到盘上的字节由第二台仪器读回来核
        ("virtio 写落盘与宿主机对账", vblk_verdict, vvic, "PASS", 33),
        # M8-a①：驱动说发出去的那一帧，宿主机必须在 QEMU 的抓包文件里读到逐字节相同的那一个
        ("网卡第一帧与 pcap 对账", net_verdict, ntrc, "PASS", 33),
        # M8-a②：对端答了，内核读回来的那一包由宿主机第二次独立解一遍，且地址必须是宿主机定的那一个
        ("第一条协议往返与 pcap 对账", rx_verdict, rtrc, "PASS", 33),
        # M9-a①：摘要由第二台实现（CPython 的 hashlib）逐字核对；不对报 CONTENT-MISMATCH
        ("SHA-256 十三向量与 hashlib 对账", sha_verdict, shrc, "PASS", 33),
        # M9-a②：盘上那份签名包，宿主机用自己的实现读一遍、验一遍、再按同一批篡改各验一遍，
        #          两边必须逐条给同一个答案（不是"内核拒了就行"）
        ("签名包两份实现同答案", sig_verdict, sprc, "PASS", 33),
    ]
    # 每一行对应那一跑的串口：不符时把红的那几格打出来。
    # 单独一张表而不是把日志塞进 `rows` 的元组里：元组要保持成"名字/期望/实际"这种
    # 一眼能核对的形状，串口文本只是它的证据附件
    logs = {
        "正向": log, "负样本": nlog, "L4 重复释放": dlog, "L4 堆分配失败": olog,
        "泄漏注入被检出": llog, "中断内分配被挡下": alog, "锁重入被抓住": rlog,
        "SMAP 没开成不启动": slog2, "IF 归任务就挂死": flog,
        "shootdown 收不齐回执升 L4": slog, "块内容对账抓得出错标签": clog,
        "计数放错位置读不出长块": chlog, "高LBA 与写方向判据成立": hlog,
        "高位写错就读不到图案": ghlog, "写方向少编程扇区数必须红": pwlog,
        "丢 W 位本机不可见": wdlog,
        "virtio 取证十格证人全过": vlog,
        "启动循环三次后进安全模式": lplog,
        "安全模式健康后退回正常": snlog,
        "崩溃记录跨重启读回": cblog2,
        "崩溃现场来自真异常": oolog2,
        "日志尾与串口逐行对账": ltlog,
        "中断投递由宿主机数到": itlog,
        "边沿与消息由设备事件数到": erglog,
        "不清源就风暴（有界窗口）": stlog,
        "整行原子性由宿主机数到": lalog,
        "目的地由宿主机按SP数到": aflog,
        "投递三层由控制器事件数到": dllog,
        "virtio 写落盘与宿主机对账": vvilog,
        "网卡第一帧与 pcap 对账": ntlog,
        "第一条协议往返与 pcap 对账": rtlog,
        "SHA-256 十三向量与 hashlib 对账": shlog,
        "签名包两份实现同答案": splog,
    }
    all_ok = True
    print()
    for name, got, got_rc, want, want_rc in rows:
        ok = got == want and got_rc == want_rc
        all_ok = all_ok and ok
        print(f"{name:14s}: {got}(rc={got_rc}) 期望 {want}(rc={want_rc}) -> {'符合' if ok else '不符合'}")
        if not ok:
            # 不符的那一行必须自己说清"是哪几格红的"：串口日志会被下一次启动覆盖，
            # 否则一次偶然的红只能靠重跑撞见（实测：正向行红过一次，当时没人拿得到成因）。
            # 只挑 fail/fatal 那一行还不够——**判据的读数在红行上面两行**（用例都是先打读数
            # 再下结论），所以带上那两行上下文：否则下次飘红还是只看得见"不成立"三个字。
            lines = logs.get(name, "").splitlines()
            hits = []
            for idx, ln in enumerate(lines):
                if "-> fail" in ln or "[fatal]" in ln:
                    hits.extend(x.strip()[:170] for x in lines[max(0, idx - 2):idx + 1] if x.strip())
                    hits.append("——")
            for h in hits[:12]:
                print("        成因:", h.strip()[:170])
            if not hits:
                print("        成因: 这一跑的串口里没有 fail/fatal 行（红在判定级，不是用例级）")
    if log:
        print("--- 正向串口日志 ---")
        print(log.strip())
    return 0 if all_ok else 1


def do_bench(timeout: int) -> int:
    """§12.4.1 规则 3：基线在用来判回归之前，必须先证明这把尺子能分辨“已知更慢”的样本。

    跑三次：同一份 no-load 构建跑两遍（量 P4 自己的重复性离散度），再跑一遍
    `bench-pf-load`（在 #PF 恢复路径上加一段确定性空循环）。

    断言只下在 **P3 的 min** 上，理由是一次踩坑踩出来的：第一版这里断言
    "p4 total 必须变大"，结果带负载那次反而**变小**了。注入的负载是
    2 次故障 x ~225k 周期 ≈ 45 万周期，只占 P4 总量（约 6.9 千万）的 0.65%，
    而 P4 同机同构建的两次实测差就有 ~5% —— 也就是说 P4 的噪声地板比被测的
    效应高一个数量级。**能分辨的尺子才是尺子**，所以 P4 在这里只做对照不做判据，
    并把它的离散度打出来，作为以后定容忍度的依据。
    """
    import re
    import platform

    p3_re = re.compile(r"p3 resume: faults=(\d+) mean=(\d+) min=(\d+) max=(\d+) cycles")
    p4_re = re.compile(r"p4: stages=(\d+) total=(\d+) cycles(?: = ~\d+ us \([^)]*\))? serial_bytes=(\d+)")
    p1_re = re.compile(r"p1 switch: samples=(\d+) mean=(\d+) min=(\d+) max=(\d+) cycles")
    # P2（§12.4）：一次 MMIO 读、一次 DMA 往返，外加内核自己那一条"1 次 vs 4 次"的自证
    p2_rd_re = re.compile(r"p2 mmio-rd: samples=(\d+) mean=(\d+) min=(\d+) max=(\d+) cycles")
    p2_wr_re = re.compile(r"p2 mmio-wr: samples=(\d+) mean=(\d+) min=(\d+) max=(\d+) cycles")
    p2_dma_re = re.compile(r"p2 dma: samples=(\d+) mean=(\d+) min=(\d+) max=(\d+) cycles")
    p2_ruler_re = re.compile(r"p2 ruler: 1次min=(\d+) 4次min=(\d+)")

    rows = []
    # 四个构建：同一份 no-load 跑两遍（量重复性地板），再分别跑两种"已知更慢"的注入：
    # bench-pf-load 只加在 #PF 恢复路径上（验 P3），bench-switch-load 只加在切换上（验 P1）。
    # 一条注入只能验一把尺子，混在一起就说不清是谁动了。
    plan = (
        ("no-load#1", []),
        ("no-load#2", []),
        ("bench-pf-load", ["bench-pf-load"]),
        ("bench-switch-load", ["bench-switch-load"]),
    )
    for label, feats in plan:
        IMAGE.unlink(missing_ok=True)
        v, rc, log = do_run(feats, timeout)
        if v != "PASS":
            print(f"[FAIL] {label}：判定={v}(rc={rc})。带负载的构建只允许更慢，不允许改变正确性")
            return 1
        m3, m4, m1 = p3_re.search(log), p4_re.search(log), p1_re.search(log)
        m2r, m2w, m2d, m2u = p2_rd_re.search(log), p2_wr_re.search(log), p2_dma_re.search(log), p2_ruler_re.search(log)
        missing = [n for n, m in (("p3", m3), ("p4", m4), ("p1", m1), ("p2 mmio-rd", m2r), ("p2 mmio-wr", m2w), ("p2 dma", m2d), ("p2 ruler", m2u)) if not m]
        if missing:
            # 报错要点名缺哪一条：上次这里笼统写"p1/p3/p4"，害得我去查三条，
            # 实际只是 p4 的格式变了（标定上线后多了一段 "= ~N us (...)"）。
            print(f"[FAIL] {label}：日志里解析不到 {'/'.join(missing)} 行。量具没出数不等于出数为 0")
            return 1
        rows.append((
            label, v, rc, tuple(map(int, m3.groups())), tuple(map(int, m4.groups())), tuple(map(int, m1.groups())),
            tuple(map(int, m2r.groups())), tuple(map(int, m2w.groups())), tuple(map(int, m2d.groups())),
            tuple(map(int, m2u.groups())),
        ))
        print(
            f"{label:16s}: p3={rows[-1][3]}  p1={rows[-1][5]}  p4(stages,total,bytes)={rows[-1][4]} "
            f"p2 rmin={rows[-1][6][2]} wmin={rows[-1][7][2]} dma_rmin={rows[-1][8][2]} ruler={rows[-1][9]}"
        )

    (t1, t2) = (rows[0][4][1], rows[1][4][1])
    # 用千分比再折算成小数：整数百分比会把 0.9% 打成 0%，
    # 而"地板是 0%"会被误读成"这条尺子毫无噪声"。
    spread_bps = abs(t1 - t2) * 10_000 // max(t1, t2)
    spread = spread_bps / 100.0
    min0, min1 = rows[0][3][2], rows[2][3][2]
    min0b = rows[1][3][2]
    # P1：切换成本的判别下在 min 上（406 周期量级的那次），mean 被日志与冷 TLB 污染
    p1_a, p1_b = rows[0][5][2], rows[1][5][2]
    p1_0 = min(p1_a, p1_b)
    p1_1 = rows[3][5][2]
    # 地板 = 同一构建两次 min 的实测差（不是拍一个百分比阈值）：
    # 判"注入有没有被看见"，门坎必须用这台机器自己的噪声来定，否则就是在比噪声。
    p1_noise = abs(p1_a - p1_b) + 1
    p1_ok = p1_1 > p1_0 + p1_noise
    # P2：判别下在"1 次 vs 4 次"的 min 比值上（内核自己按同一次采样算的），
    # 再加一条数量级自检：一次 DMA 映射+撤销必须比一次寄存器读贵——它包含页框分配、
    # 建叶表项、TLB 无关的 unmap 与台账两笔账。反过来就是有一侧没在量它说的那件事。
    p2_rd, p2_wr, p2_dma = rows[0][6], rows[0][7], rows[0][8]
    one_min, four_min = rows[0][9]
    p2_ok = four_min > one_min * 2 and p2_dma[2] > p2_rd[2]
    ok = min1 > max(min0, min0b) * 2 and p1_ok and p2_ok
    print(f"P4 重复性离散度（同一构建两次）= {spread:.2f}%（{spread_bps} bp）  <- 以后 P4 容忍度必须大于这个地板")
    print(f"尺子 P3 能分辨：min {min0}/{min0b} -> {min1}（要求 >2x）-> {'符合' if min1 > max(min0, min0b) * 2 else '不符合'}")
    print(f"尺子 P1 能分辨：切换 min {p1_a}/{p1_b} -> 注入后 {p1_1} cycles（地板=同构建两次 min 之差 {p1_noise}）-> {'符合' if p1_ok else '不符合'}")
    print(
        f"尺子 P2 能分辨：一次 MMIO 读 min={one_min} -> 四次 min={four_min}（要求 >2x）；"
        f"一次 DMA 往返 min={p2_dma[2]} vs 一次 MMIO 读 min={p2_rd[2]}（要求 DMA 更贵）-> {'符合' if p2_ok else '不符合'}"
    )
    print(f"P2 数量级（cycles）：MMIO 读 mean={p2_rd[1]} min={p2_rd[2]}；MMIO 写 mean={p2_wr[1]} min={p2_wr[2]}；DMA 映射+撤销 mean={p2_dma[1]} min={p2_dma[2]}")
    injected = (min1 - max(min0, min0b)) * 2
    inj_bps = injected * 10_000 // max(t1, t2)
    print(f"注入的增量换算到 P4 只有 {inj_bps / 100:.2f}%（{inj_bps} bp），低于上面 {spread:.2f}% 的地板 -> P4 只作对照，不作判据")

    out_dir = ROOT / "docs" / "testing" / "baselines"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y-%m-%dT%H-%M-%SZ", time.gmtime())
    out = out_dir / f"{stamp}-p3p4.txt"
    body = [f"# P3/P4 原始输出（{stamp}）。可比性依据 §12.4.1 规则 2，跨机只看比值。",
            f"host_cpu={platform.processor() or 'unknown'} qemu_cpu={QEMU_CPU} smp={QEMU_SMP} mem={QEMU_MEM} rust=见 tools/versions.toml",
            f"discriminate={'yes' if ok else 'NO'} p4_repeat_spread_bps={spread_bps}"]
    body += [
        f"{l} verdict={v} rc={rc} p3_faults,mean,min,max={p} p4_stages,total,bytes={q} p1_samples,mean,min,max={s1} "
        f"p2_mmio_rd={r} p2_mmio_wr={w} p2_dma={d} p2_ruler_1v4={u}"
        for l, v, rc, p, q, s1, r, w, d, u in rows
    ]
    out.write_text("\n".join(body) + "\n", encoding="utf-8")
    print("原始输出入库：", out)
    return 0 if (ok and spread < 20) else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("build", "image", "run", "test", "bench", "check", "ktests", "release"):
        p = sub.add_parser(name)
        p.add_argument("--features", default="")
        p.add_argument("--timeout", type=int, default=120)
    a = ap.parse_args()
    feats = [f for f in a.features.split(",") if f]
    if a.cmd == "build":
        do_build(feats)
        return 0
    if a.cmd == "image":
        do_image(feats)
        return 0
    if a.cmd == "run":
        v, rc, _ = do_run(feats, a.timeout)
        return 0 if v == "PASS" else 1
    if a.cmd == "release":
        return do_release(a.timeout)
    if a.cmd == "test":
        return do_test(a.timeout)
    if a.cmd == "bench":
        return do_bench(a.timeout)
    if a.cmd == "ktests":
        elf = next((ROOT / "target" / TARGET / k / "aurora-kernel" for k in ("debug", "release") if (ROOT / "target" / TARGET / k / "aurora-kernel").exists()), None)
        if elf is None:
            sys.exit("还没构建")
        names = ktests_in_elf(elf)
        print(f"{elf.name}: 注册用例 {len(names)} 条")
        for n in names:
            print("   ", n)
        return 0 if names else 1
    if a.cmd == "check":
        elf = next((ROOT / "target" / TARGET / k / "aurora-kernel" for k in ("debug", "release") if (ROOT / "target" / TARGET / k / "aurora-kernel").exists()), None)
        return do_check(elf)
    return 2


if __name__ == "__main__":
    sys.exit(main())
