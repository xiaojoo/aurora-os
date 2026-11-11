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
import struct
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
    if FAT_FEATURES & set(features):
        # 必须在 cargo 之前：`include_bytes!("../fixtures/fat32-mem.img")` 是编译期读的，
        # 那块文件不在仓库里（配方现算），晚一步就是"构建失败"而不是"夹具不对"。
        bad = ensure_fat32_mem()
        if bad:
            sys.exit("内存夹具卷不成立：" + " / ".join(bad))
    if FAT16_FEATURES & set(features):
        # 同一条规矩：`include_bytes!("../fixtures/fat16-mem.img")` 是编译期读的，
        # 必须在 cargo 之前现算并核指纹，晚一步就是"构建失败"而不是"夹具不对"。
        bad = ensure_fat16_mem()
        if bad:
            sys.exit("FAT16 合成夹具卷不成立：" + " / ".join(bad))
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


# 第二个用户程序（W3 P5a，ADR-075 决策 1）：与 hello 平行的第二套常量。
# 刻意**不**把 do_build_user 改成表驱动：那条函数的打印与夹具路径被既有判据与日志来路吃着，
# 两份显式常量比一个"通用产物构建器"更容易核对（AGENTS.md 硬约束 2 的同一条口径）。
# 它**不进签名链**（2026-11-09 裁决）：签名包单载荷、余量 96 字节，这个产物走第二个内嵌夹具。
PROBE_PKG = "aurora-user-probe"
PROBE_ELF = ROOT / "target" / TARGET / "debug" / "probe"
PROBE_FIXTURE = ROOT / "kernel" / "fixtures" / "probe.elf"
PROBE_RUSTFLAGS = "-C link-arg=-Tuser/probe/link.ld -C relocation-model=static -C panic=abort -C opt-level=1"


def do_build_probe() -> Path:
    r = subprocess.run(
        [str(CARGO), "build", "--target", TARGET, "-p", PROBE_PKG],
        capture_output=True, text=True, cwd=str(ROOT),
        env={**env(), "RUSTFLAGS": PROBE_RUSTFLAGS},
    )
    if r.returncode != 0:
        sys.exit("探针程序构建失败：" + (r.stdout + r.stderr)[-2000:])
    data = PROBE_ELF.read_bytes()
    PROBE_FIXTURE.parent.mkdir(exist_ok=True)
    # 与 hello 同一条纪律：只在字节真变了时才覆写，否则 include_bytes! 的 mtime 依赖
    # 会让内核每次全量重编，"增量构建"静默失效。
    changed = not PROBE_FIXTURE.exists() or PROBE_FIXTURE.read_bytes() != data
    if changed:
        PROBE_FIXTURE.write_bytes(data)
    import hashlib
    print(f"探针程序: {PROBE_FIXTURE.relative_to(ROOT)}  {len(data)} 字节  "
          f"sha256={hashlib.sha256(data).hexdigest()[:12]} {'（夹具已更新）' if changed else '（与夹具一致）'}")
    return PROBE_FIXTURE


def do_build(features: list[str]) -> Path:
    do_build_user()
    do_build_probe()
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
# W4 S1（ADR-078 决策 7）：GPT 解析用例的夹具盘。**为什么负样本不改引导盘**（实测出来的）：
# OVMF/EDK2 启动时会**用备份 GPT 把主表修回原值**（数组首字节 0x29 改下去、跑完读回 0x28），
# 所以"数组 CRC/头 CRC/entry_count/备份不一致"四条注入根本到不了内核（实测都 PASS(33)）；
# 另两条（保护性 MBR 类型 0xEE→0x0C、ESP first_lba+重算 CRC）固件治不好 ⇒ **NOBOOT**，连内核都起不来。
# 六条因此必须落在一块**固件永远不会碰**的盘上：口 1，只在 gpt-probe 档挂。
GPT_FIX = BUILD / "gpt-fixture.img"
GPT_FIX_PORT = 1
# 名单是**文本交集**，不跟 cargo 的依赖闭包走：`esp-probe` 依赖 `gpt-probe`（因此会注册
# `t_gpt`、要读口 1 那块盘），但这里若只写 gpt-probe，盘就不挂 ⇒ 那条用例以
# `Io(NotSettled)` 红，而红的成因看起来像驱动坏了（S2b 开工第一跑实测就是这个形状）。
GPT_FEATURES = {"gpt-probe", "esp-probe"}
# S2b：从口 0 的 ESP 分区里真读的那个文件。**8.3 短名**（`name_matches` 拼 `NAME.EXT`），
# 与 `ktests/esp.rs` 的 `WANT` 由 check-fat32-ports 逐字对账。为什么不是 `/boot/aurora.bin`：
# `open()` 只扫根、不走子目录，LFN 也没实现 ⇒ 根级常驻可开的只有 limine.conf 的短名。
ESP_FILE_NAME = "LIMINE.CON"
ESP_FEATURES = {"esp-probe"}
# 配方指纹：由 tools/make_gpt_disk.py 现算（盘里没有文件系统，所以不需要 mtools）。
# 与 FAT 那两块同一规矩：夹具跟着"要挂这块盘"走，每跑重造并核指纹，注入的寿命就是一跑。
GPT_FIX_BYTES = 4194304
GPT_FIX_SHA256 = "bbf0e999a6de7eb1dc03195daa875cfd73ffb7a9d2d02ed7e24d9e059d8feceb"
# 六条宿主机侧改盘注入（ADR-078 决策 7）。**不是 cargo 特性**：负样本用的就是正向那一跑的
# 同一个 ELF，只有盘不同（理由与 FAT_HOST_FAULTS 那段逐字相同）。值 = 串口里必须点名的拒因；
# 空串那条特殊：内核必须**绿**，红在宿主机对账上（证"对账能分辨"而不是"解析能拒"）。
GPT_HOST_FAULTS = {
    "fault-gpt-array-crc": "ArrayCrc",
    "fault-gpt-header-crc": "HeaderCrc",
    "fault-gpt-mbr-type": "NoProtectiveMbr",
    "fault-gpt-entry-count": "TooManyEntries",
    "fault-gpt-esp-first": "",
}
# 第六条（备份头与主表不一致）**做不成改盘负样本，这是实测结论不是偷懒**：
# 只要有一份表是好的，EDK2 就拿它修另一份（跑完盘回到 pristine）；两份都好但字段不一致时
# 它挑主表、重写备份 ⇒ 内核读到的永远是一致的两份。该闸由**同一份 ELF 里的合成盘**证到
# （ktests/gpt.rs 那 16 格之一，点名 BackupMismatch）。名字留在这里当账，免得下次有人再试一遍。
GPT_FAULT_UNDELIVERABLE = {
    "fault-gpt-backup-mismatch": "固件必然治愈（实测跑完回到 pristine）⇒ 由合成盘证，不做改盘行",
}
GPT_RECIPE = BUILD / "gpt-fixture-recipe.img"

# L3-C①：两块只读 FAT32 卷，挂在 AHCI 的口 3 与口 4。这两个数不是一串参数而是一张**对账表**：
# 内核 `ktests/fs.rs` 里写死 `FAT_PORT_A`/`FAT_PORT_B`，宿主机写死在下面的 `FAT_PORTS`，两边由门禁
# `check-fat32-ports` 比着（同 `check-driver-ctx` 与 DEBUGEXIT_PORT 那条的形状）。
# 为什么宿主机也要自己解析一遍这两块卷：内核读回来的每一个数（簇数、首簇的高/低半、走字节、
# FNV）目前只有解析器自己一张嘴。夹具、内核解析、宿主机解析是三方，任何两方一致才叫数。
# 两个集合分开是有原因的：**带哪条特性都要挂盘**（`FAT_DISK_FEATURES`）与
# **注入点长在被测代码里**（`FAT_FAULT_FEATURES`）不是同一件事——把两者用一把尺子判，
# 会把一个正确的设计读成断线（本轮实测踩过一次，见 BACKLOG 78e 最后一条）。
FAT_DISK_FEATURES = {"fat32-probe", "fat32-exec"}
FAT_FAULT_FEATURES = {"fault-fat32-tail"}
# L3-C④（BACKLOG 80）：**宿主机侧**注入。它们不是 cargo 特性，走 `do_run(..., host_fault=…)`。
# 为什么不做成特性（第一版做成了，实测之后改回来）：特性名会进 cargo 的 `-C metadata`，
# crate disambiguator 跟着变 ⇒ 符号哈希变 ⇒ 链接器排序与绝对地址变。实测同一份源码
# `fat32-exec` 与 `fat32-exec,fault-fat32-exec-byte` 的 ELF 是 4,540,048 / 4,536,960 字节、
# sha256 54af93493ef9e44c / a112bc67b329c373，`.text` 有 312,950 格不同；归一化掉地址与符号名
# 之后指令多重集逐条相同（77,768 条，两边独有 0）——差异是布局不是代码，但那要靠在宿主机上
# 反汇编两遍才论证得动。不做成特性就没有这个论证负担：负样本用的**就是正向那一跑的同一个 ELF**，
# "只有盘不同"由构造保证。门禁反过来要求这两个名字既不在 Cargo.toml 里、也不在内核源码里。
FAT_HOST_FAULTS = {
    "fault-fat32-exec-byte": "fat32-small",
    "fault-fat32-cluster-hi": "fat32-wide",
}
FAT_FEATURES = FAT_DISK_FEATURES | FAT_FAULT_FEATURES
# 卷A 是**阈值判型的反例**（64,496 簇按微软那条经验阈值算 FAT16、按结构算 FAT32）；
# 卷B 用一个 34,603,008 字节的 FILLER.BIN 把后面三个文件推到 65,536 簇之上，于是目录项的
# 簇号必须两半拼（只取低半的错法在这里会读到别处，而字节数照样对得上）。角色不能互换。
FAT_PORTS = {3: "fat32-small", 4: "fat32-wide"}
# 内核声明"要读哪几个文件"。这张表有两个用处，缺一不可：
# 1 宿主机这台仪器只走这几个名字的链——卷B 上那个 34,603,008 字节的 FILLER.BIN 没有任何
#   一条判据读它，跟着算哈希会让对账先挂死（本轮实测：一次 3,400 万次的逐字节循环）。
# 2 门禁 `check-fat32-ports` 拿它与 ktests/fs.rs 里那两个 `want` 表逐名对账 ⇒ 用例读的名字与
#   仪器核的名字不可能各走各的（"对账核的是另一个文件"这种绿是没有意义的绿）。
FAT_READ_NAMES = {
    "A": ("HELLO.ELF", "NOTES", "SMALL.BIN"),
    "B": ("HELLO.ELF", "NOTES", "SMALL.BIN"),
    # L3-C②：合成卷上内核查的三个名字（LFN 命中项、删除标记项、无扩展名项）
    "MEM": ("LONG~1.TXT", "?LD.TXT", "NOSHORT"),
}
# 与内核 `MAX_CLUSTERS_WALKED` 同一个数：两台实现各自有界，界还必须看得见是同一个界
FAT_MAX_WALKED = 65_535
FAT_ZZ = {name: ROOT / "tools" / "fixtures" / f"{name}.img.zz" for name in FAT_PORTS.values()}
FAT_IMG = {name: BUILD / f"{name}.img" for name in FAT_PORTS.values()}
# 夹具自己的指纹（字节数 + 解压后的 sha256）。内核那一批写死的期望数全是照着这一对卷量的，
# 所以哪天卷换了而期望数没跟着换，红会落在解析器身上——可错的是夹具。指纹先于解析判，
# 就是把"量具换了"和"被测物坏了"分在两道闸上。
# 存成 `.img.zz` 的理由很实际：`.gitignore` 里 `*.img` 挡的是构建产物，裸卷 32/64 MiB 不该进仓库，
# 而它们**是**源（配方与 mtools 数值记在 BACKLOG 78）。压缩后 40 KB 与 262 KB，几乎全是零与重复图案。
FAT_EXPECT = {
    "fat32-small": (33_554_432, "3eb1d518923ae4e3692aafec7d545c1bfa92ef75366ea3ab82fbc5256f97c976"),
    "fat32-wide": (67_108_864, "da3aa3a2e2e7d600d45fa47ad142b635c072269a9bba25d7df2f51e08c8d34e9"),
}
# L3-C② 的内存夹具卷：11,264 字节，由 `tools/make_fat32_mem.py` 现算（这块卷**不在仓库里**——
# `.gitignore` 的 `*.img` 把它挡了，而能被配方重新算出来的东西本来就该不进仓库）。
# 指纹登记在这里，构建前先跑配方脚本：对不上就是"配方与镜像分家"，红在编译之前，
# 而不是红在解析器身上（新克隆没有这块卷时同一条路径负责把它造出来）。
FAT_MEM_OUT = ROOT / "kernel" / "fixtures" / "fat32-mem.img"
FAT_MEM_SCRIPT = ROOT / "tools" / "make_fat32_mem.py"
FAT_MEM_EXPECT = (11_264, "28f6f1d9cf135d4ab44de4e015a5b9a271cd087f2165139987088cd0eeff89ae")
# W4 S2a：FAT16 合成整卷（23 扇区）。与 fat32-mem 同一规矩——不在仓库里、现算、指纹登记，
# 内核 `include_bytes!` **同一份字节**，宿主机 `validate_esp.py --fat16-report` 独立重算
# ⇒ 两台仪器读的是同一块卷，而不是各自实现同一个配方（后者错会一起错）。
FAT16_MEM_OUT = ROOT / "kernel" / "fixtures" / "fat16-mem.img"
FAT16_MEM_SCRIPT = ROOT / "tools" / "make_fat16_mem.py"
FAT16_MEM_EXPECT = (11_776, "72cbe26b0cb080a586f82a8b8a21edfa584a807d7aa212bd7bd1fafdfbc9bb25")
FAT16_FEATURES = {"fat16-probe"}

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
# 事件清单里为什么带 `pit_ioport_write`：它是 `apic::pit_mark()` 留下的窗口游标
# （`[0x3] <- 0x0`，实测 QEMU 打 `0x0` 不补零）。为什么不带 RTC：`0x70/0x71` 在这台
# OVMF/QEMU 上写进去读不回来，且 `mc146818rzy_*` 一条都不产出（已实测，别再挂回去）。
DELIVER_EVENTS = ["apic_deliver_irq", "apic_local_deliver", "ahci_irq_raise", "ahci_check_irq",
                  "pit_ioport_write"]
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


def make_gpt_fixture() -> list[str]:
    """现算那块 GPT 夹具盘并核指纹（与 make_fat_volumes 同一规矩：先核 pristine 再谈注入）。

    每跑重造，所以注入的寿命就是一跑；指纹不符就红在跑之前，而不是跑完之后对着一行 FAIL 猜。
    """
    import hashlib
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "make_gpt_disk.py"), str(GPT_FIX)],
                       capture_output=True, text=True, encoding="utf-8", env=env())
    if r.returncode != 0:
        return [f"make_gpt_disk.py 退出 {r.returncode}：{r.stderr.strip()[:200]}"]
    if not GPT_FIX.exists():
        return ["GPT 夹具盘没造出来"]
    data = GPT_FIX.read_bytes()
    if len(data) != GPT_FIX_BYTES:
        return [f"GPT 夹具盘 {len(data)} 字节，配方说 {GPT_FIX_BYTES}"]
    got = hashlib.sha256(data).hexdigest()
    if got != GPT_FIX_SHA256:
        return [f"GPT 夹具指纹不符：{got} != {GPT_FIX_SHA256}"
                "（配方改了？那要连用例与对账的期望一起重量，不是把指纹改过去就算）"]
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


def make_fat_volumes() -> list[str]:
    """把两块夹具卷从仓库里的 zlib 副本解压到 `build/`，并先核自己的指纹。

    与 scratch 那一块的区别：scratch 每次必须重造（写方向的判据要求开局是已知空状态），
    这两块卷**只读**，所以只需要"字节对得上"。落盘时也只在内容真变了时才写：
    QEMU 打开的就是这些文件，mtime 每次变动会让"同一份夹具"这件事在取证上打折扣。

    指纹不符时返回的是红而不是警告：带着可疑的夹具跑，内核那一读的每一个数都不可解释，
    而那时红会落在解析器身上——错其实在量具。
    """
    import hashlib
    import zlib
    bad: list[str] = []
    for name, (size, sha) in FAT_EXPECT.items():
        zz, out = FAT_ZZ[name], FAT_IMG[name]
        if not zz.exists():
            bad.append(f"夹具源不在位：{zz.relative_to(ROOT)}（配方见 BACKLOG 78 的 mtools 那一节）")
            continue
        raw = zlib.decompress(zz.read_bytes())
        got = hashlib.sha256(raw).hexdigest()
        if len(raw) != size or got != sha:
            bad.append(f"夹具 {name} 指纹不符：{len(raw)} 字节 sha256={got[:16]}，期望 {size} 字节 {sha[:16]}")
            continue
        if not out.exists() or out.read_bytes() != raw:
            out.write_bytes(raw)
    return bad


def ensure_fat32_mem() -> list[str]:
    """把 L3-C② 的配方脚本跑一遍并核指纹——`include_bytes!` 是**编译时**要的。

    这块 11,264 字节的卷不在仓库里（`.gitignore` 的 `*.img` 挡的），所以两件事必须在这里判：
    1 新克隆能不能编出这个变体（跑一遍脚本就够了，不需要 mtools 或任何外部工具）；
    2 配方与用例里那些写死的数是不是还对得上（簇数 12、尾格 464、`entries_seen` 4/6/8、
      头四字节 0x11 0x14 0x17 0x1a——全是照着这块卷量的，指纹一变就得重算一遍）。
    红在编译之前，而不是等内核把这块卷读成别的形状之后再回头查解析器。
    """
    import hashlib
    if not FAT_MEM_SCRIPT.exists():
        return [f"配方脚本缺失：{FAT_MEM_SCRIPT.relative_to(ROOT)}（这块夹具卷不在仓库里，只能现算）"]
    if sh([sys.executable, str(FAT_MEM_SCRIPT)]) != 0:
        return ["make_fat32_mem.py 退出非零"]
    if not FAT_MEM_OUT.exists():
        return [f"脚本没写出 {FAT_MEM_OUT.relative_to(ROOT)}"]
    data = FAT_MEM_OUT.read_bytes()
    size, sha = FAT_MEM_EXPECT
    got = hashlib.sha256(data).hexdigest()
    if len(data) != size or got != sha:
        return [f"内存夹具指纹不符：{len(data)} 字节 sha256={got[:12]}，期望 {size} 字节 {sha[:12]}"
                "（配方改了，用例里那批写死的数必须跟着重算）"]
    return []


def ensure_fat16_mem() -> list[str]:
    """现算 FAT16 合成整卷并核指纹（与 `ensure_fat32_mem` 同一规矩：红在编译之前）。"""
    import hashlib
    if not FAT16_MEM_SCRIPT.exists():
        return [f"配方脚本缺失：{FAT16_MEM_SCRIPT.relative_to(ROOT)}（这块夹具卷不在仓库里，只能现算）"]
    if sh([sys.executable, str(FAT16_MEM_SCRIPT), str(FAT16_MEM_OUT)]) != 0:
        return ["make_fat16_mem.py 退出非零"]
    if not FAT16_MEM_OUT.exists():
        return [f"脚本没写出 {FAT16_MEM_OUT.relative_to(ROOT)}"]
    data = FAT16_MEM_OUT.read_bytes()
    size, sha = FAT16_MEM_EXPECT
    got = hashlib.sha256(data).hexdigest()
    if len(data) != size or got != sha:
        return [f"FAT16 合成卷指纹不符：{len(data)} 字节 sha256={got[:12]}，期望 {size} 字节 {sha[:12]}"
                "（配方改了，用例与对账那批写死的数必须跟着重算）"]
    return []


# ------------------------------------------------------------------ L3-C① 宿主机那一侧的 FAT32 仪器
#
# 这一族函数是**第二台实现**：只按微软 FAT 规范 1.03 的偏移从镜像字节里读，不读内核打印的
# 任何一个数，也不参与造夹具。它存在的理由与 `hashlib` 对 SHA-256、`bootp_of` 对 DHCP 那一包
# 完全相同——"解析器自己说它对"不是一格判据。
#
# 偏移表与内核 `filesystem/fat32.rs` 那一份是同一次由 mtools 的 `minfo` 对出来的（两处都记着
# 那个 49→50 的错），而这里**故意重写一遍**而不是 import 过去：两份独立实现撞上同一个数才有
# 意义，共用一张表就退化成一台仪器。

FAT_SEC = 512
FAT_EOC = 0x0FFF_FFF8


def _fat_u16(b: bytes, o: int) -> int:
    return b[o] | (b[o + 1] << 8)


def _fat_u32(b: bytes, o: int) -> int:
    return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)


def fat32_host_volume(img: bytes, read_names: tuple[str, ...] = ()) -> dict:
    """独立解析一块 FAT32 卷：几何 + FSInfo 自述 + 根目录每一项的账。

    `read_names` 之外的项只读目录项元数据、不走链也不算哈希（卷B 的 FILLER.BIN 有 34 MB，
    而没有任何一条判据读它）。哈希只对声明要读的那几项算，因为对账比的就是那几项的内容。
    """
    bs = img[:FAT_SEC]
    spc, res, fats = bs[13], _fat_u16(bs, 14), bs[16]
    root_ent, spf16 = _fat_u16(bs, 17), _fat_u16(bs, 22)
    spf32 = _fat_u32(bs, 36)
    total = _fat_u16(bs, 19) or _fat_u32(bs, 32)
    # 判型只看结构：固定根目录为 0 且 FAT32 的每份扇区不为 0（卷A 的簇数按阈值算落 FAT16 档）
    struct32 = root_ent == 0 and spf16 == 0 and spf32 != 0
    spf = spf32 if struct32 else (spf16 or spf32)
    data_start = res + fats * spf
    clusters = (total - data_start) // spc
    band = "Fat12" if clusters < 4085 else ("Fat16" if clusters < 65525 else "Fat32")
    fsinfo, backup = _fat_u16(bs, 48), _fat_u16(bs, 50)
    fsi = img[fsinfo * FAT_SEC:fsinfo * FAT_SEC + FAT_SEC]

    def fat_next(c: int) -> int:
        return _fat_u32(img, res * FAT_SEC + c * 4) & 0x0FFF_FFFF

    def cluster_off(c: int) -> int:
        return (data_start + (c - 2) * spc) * FAT_SEC

    # 根目录：跟着簇链走。条目序号与内核 `entries_seen` 用同一个数法（被跳过的卷标/目录/LFN
    # 也算在内，到命中那一项为止）——两边数法不同时，对账会红在"扫过项"那一格，
    # 而不是各数各的还都绿。
    files: dict[str, dict] = {}
    labels = dirs = 0
    c, seen, lfn = _fat_u32(bs, 44), 0, 0
    stop = False
    root_walked = 0
    while c < FAT_EOC and not stop:
        if root_walked > FAT_MAX_WALKED:
            raise ValueError(f"根目录簇链超过 {FAT_MAX_WALKED} 簇：环链或损坏，这台仪器不跟着转")
        root_walked += 1
        blk = img[cluster_off(c):cluster_off(c) + spc * FAT_SEC]
        for o in range(0, len(blk), 32):
            e = blk[o:o + 32]
            if e[0] == 0x00:
                stop = True
                break
            seen += 1
            if e[11] == 0x0F:
                lfn += 1
                continue
            if e[11] & 0x08:
                labels += 1
                continue
            if e[11] & 0x10:
                dirs += 1
                continue
            if e[0] == 0xE5:
                # 已删除条目：内核跳过但仍计入扫过的项数，这台仪器必须同数法。
                # 不跳的话内存夹具里那条 0xE5 GONE.BIN 会被宿主机数成"内核漏读了一项"。
                continue
            name = e[0:8].decode("latin1").rstrip()
            if e[0] == 0x05:
                # 删除标记占掉第一位，原名字的第一字符在盘上已经不存在了 ⇒ 规范读成 '?'。
                # 内核 `name_matches` 同一件事，两边同一读法才谈得上对账。
                name = "?" + name[1:]
            ext = e[8:11].decode("latin1").rstrip()
            if ext:
                name += "." + ext
            size = _fat_u32(e, 28)
            hi, lo = _fat_u16(e, 20), _fat_u16(e, 26)
            first = (hi << 16) | lo
            cc, n, walked, got = first, size, 0, bytearray()
            last = after = 0
            off_image = False
            cyclic = False
            # 簇号落在保留/坏簇区，或链指到镜像之外：这台仪器**不跟着造链**。
            # 内核那一侧对应 `EntryOutsideData`（目录项的闸）与 `BadCluster`（走链的闸）；
            # 这里跟着走会拿一个不存在的簇号去切片，读出空字节后 `take=0` 就是死循环——
            # 量具自己先挂，比被测物挂了更难查（内存夹具里 BADCLU.BIN 那一条就是这个形状）。
            bad_cluster = cc < 2 or cc >= FAT_EOC
            # 只走"内核声明要读的那几个名字"的链：卷B 的 FILLER.BIN 有 34,603,008 字节，
            # 而 `t_fat32` 从不读它——跟着读的话这台仪器要先算 3,400 万次逐字节哈希，
            # 实测会把对账拖成一次挂死（本轮踩过）。范围由 `FAT_READ_NAMES` 定，
            # 与内核那两个 `want` 表由 `check-fat32-ports` 静态对账。
            want_walk = first in range(2, FAT_EOC) and name in read_names
            if want_walk:
                while n > 0:
                    if walked > FAT_MAX_WALKED:
                        # 环链：内核撞 `ChainTooLong`，这台仪器撞自己的界。
                        # 没有这一格，`CYCLIC.BIN`（size=0xFFFF_FFFF、链 8→9→10→9）会让宿主机先死。
                        cyclic = True
                        break
                    chunk = img[cluster_off(cc):cluster_off(cc) + spc * FAT_SEC]
                    if len(chunk) < spc * FAT_SEC:
                        off_image = True
                        break
                    take = min(len(chunk), n)
                    got += chunk[:take]
                    n -= take
                    walked += 1
                    last = cc
                    after = fat_next(cc)
                    cc = after
                    if after >= FAT_EOC and n > 0:
                        break
            files[name] = dict(
                size=size, first=first, hi=hi, lo=lo, seen=seen, lfn=lfn,
                # 这一条目录项自己在镜像里的字节偏移。宿主机侧注入（L3-C④）要靠它改盘，
                # 而"改哪一格"必须由解析算出来，不能写死一个偏移：夹具重建之后写死的那个数
                # 会静默改到别处，负样本照样红，红的却不是要证的那一格。
                ent_off=cluster_off(c) + o,
                bytes=len(got), clusters=walked, last=last, after=after,
                tail=len(got) - (walked - 1) * spc * FAT_SEC if walked else 0,
                head=bytes(got[:4]), fnv=fnv1a64(bytes(got)) if want_walk else 0,
                # 走过的项才留字节（其余项只留元数据）：③ 那行要把盘上那份与内嵌那份
                # 直接比 sha256，而那只有 31,320 字节
                blob=bytes(got) if want_walk else b"",
                bad_cluster=bad_cluster, off_image=off_image,
                walked_it=want_walk, cyclic=cyclic)
        if not stop:
            c = fat_next(c)
    return dict(
        bytes_per_sector=_fat_u16(bs, 11), sectors_per_cluster=spc, reserved=res, fat_count=fats,
        root_entries=root_ent, sectors_per_fat=spf, total_sectors=total, data_start=data_start,
        clusters=clusters, band=band, struct="Fat32" if struct32 else "非Fat32",
        cluster_bytes=spc * FAT_SEC, root_cluster=_fat_u32(bs, 44),
        fsinfo_sector=fsinfo, backup_sector=backup, boot_sig=bs[66], drv_num=bs[64],
        fs_name_str=bs[82:87].decode("latin1"),
        fsinfo_lead=_fat_u32(fsi, 0), fsinfo_struct=_fat_u32(fsi, 484),
        fsinfo_free=_fat_u32(fsi, 488), fsinfo_next=_fat_u32(fsi, 492),
        backup_same=img[backup * FAT_SEC:backup * FAT_SEC + FAT_SEC] == bs,
        entries_seen=seen, lfn=lfn, volume_label=labels, subdirs=dirs, files=files,
    )


# 内核 `t_fat32` 打的三类行：几何一行、每个文件一行、引导盘被拒一行。锚点写全，少任何一条
# 都当成"这一跑没读到"报红——静默少一条就是静默少测一条（与 check-matrix-wiring 同规矩）。
FAT_GEO_RE = re.compile(
    r"fat32: 几何 卷(?P<vol>[AB]) 簇数=(?P<clusters>\d+) 数据起点=(?P<data>\d+) "
    r"每簇字节=(?P<clu>\d+) FAT份=(?P<fats>\d+) 每份扇区=(?P<spf>\d+) 根簇=(?P<root>\d+) "
    r"FSInfo扇区=(?P<fsinfo>\d+) 备份扇区=(?P<backup>\d+) 阈值判型=(?P<band>\w+) "
    r"结构判型=(?P<struct>\w+) 名字串=(?P<name>true|false) 备份逐字节同=(?P<bsame>true|false) "
    r"自由簇=(?P<free>\d+)")
FAT_FILE_RE = re.compile(
    r"fat32: 卷(?P<vol>\d) (?P<name>\S+)\s+大小=(?P<size>\d+) 簇=(?P<cluster>\d+) "
    r"高半=(?P<hi>\d+) 低半=(?P<lo>\d+) 扫过项=(?P<seen>\d+) LFN=(?P<lfn>\d+) "
    r"走字节=(?P<wbytes>\d+) 走簇=(?P<wclusters>\d+) 尾字节=(?P<tail>\d+) "
    r"末簇后继=(?P<after>0x[0-9a-f]+) 头四字节=\[(?P<head>[0-9a-f, ]+)\] 哈希=(?P<hash>0x[0-9a-f]+)")
FAT_MBR_RE = re.compile(r"fat32: 引导盘 口(?P<port>\d+) 拒因=Some\((?P<err>\w+)")
# L3-C② 那两行：几何与目录。`Ok(FileStat { … })` 是 Rust 的 Debug 原文，锚点把它整条写完——
# 字段名改了这里就红，因为那意味着串口里的数不再可核对（与 check-matrix-wiring 同一规矩）。
FAT_MEM_GEO_RE = re.compile(
    r"fat32-mem: 几何 簇数=(?P<clusters>\d+) 数据起点=(?P<data>\d+) 每簇字节=(?P<clu>\d+) "
    r"FAT份=(?P<fats>\d+) 每份扇区=(?P<spf>\d+) 根簇=(?P<root>\d+) 阈值判型=(?P<band>\w+) "
    r"结构判型=(?P<struct>\w+) 名字串=(?P<name>true|false) 备份逐字节同=(?P<bsame>true|false) "
    r"自由簇=(?P<free>\d+)")
FAT_MEM_DIR_RE = re.compile(r"fat32-mem: 目录 (?P<body>.*)")
# P7 ⑤：装载器授予容器的那一行，与 ring3 自己写的结论行。
HANDLE_GRANT_RE = re.compile(
    r"elfdisk: 授予容器 句柄=(?P<h>0x[0-9a-f]+) 主人=\((?P<g>\d+),(?P<id>\d+)\)")
HANDLE_RING3_RE = re.compile(
    r"elfdisk: ring3 句柄 魔数=Some\((?P<magic>\d+)\) done=Some\((?P<done>\d+)\) "
    r"句柄值=(?P<h>0x[0-9a-f]+) 表清空=(?P<clean>true|false) ⇒ (?P<ok>true|false)")
FAT_MEM_CURSOR_RE = re.compile(
    r"fat32-cursor: memory checks=\[(?P<checks>[a-z, ]+)\] sum=(?P<sum>0x[0-9a-f]+) "
    r"bound_reads=(?P<bound>\d+) position=(?P<pos>\d+)")
FAT_MEM_STAT_RE = re.compile(
    r"(?P<name>[A-Za-z0-9~_.?]+)=Ok\(FileStat \{ size: (?P<size>\d+), first_cluster: (?P<cluster>\d+), "
    r"entries_seen: (?P<seen>\d+), lfn_entries: (?P<lfn>\d+) \}\)")


def check_fat32_mem(log: str) -> list[str]:
    """内存夹具那一本账：配方脚本写的字节，与内核读回来的数，由这台仪器各算一遍。

    为什么这块卷也要对账（它明明是"合成"的）：它的每一个期望数（簇数 12、`entries_seen`
    4/6/8、尾格 464、头四字节 0x11 0x14 0x17 0x1a）都是照着配方脚本写的字节手工推的。
    脚本一改（加一条目录项、挪一个簇）而那些数没跟着改，红会出现在**内核的用例**里，
    看起来像解析器坏了。这里从脚本刚写出的那份字节重算，把"配方与用例分家"这一类
    在跑完之后立刻点名。
    """
    bad: list[str] = []
    geo = FAT_MEM_GEO_RE.search(log)
    if not geo:
        return ["这一跑挂了 fat32 变体，但串口没有 `fat32-mem: 几何 …` 那一行（② 那本账没跑）"]
    if not FAT_MEM_OUT.exists():
        return [f"宿主机没有 {FAT_MEM_OUT.relative_to(ROOT)}：配方脚本没写出它，内核却把它编进了 .rodata"]
    h = fat32_host_volume(FAT_MEM_OUT.read_bytes(), FAT_READ_NAMES["MEM"])
    for tag, got, want in [
        ("簇数", geo.group("clusters"), h["clusters"]),
        ("数据起点", geo.group("data"), h["data_start"]),
        ("每簇字节", geo.group("clu"), h["cluster_bytes"]),
        ("FAT份", geo.group("fats"), h["fat_count"]),
        ("每份扇区", geo.group("spf"), h["sectors_per_fat"]),
        ("根簇", geo.group("root"), h["root_cluster"]),
        ("自由簇", geo.group("free"), h["fsinfo_free"]),
    ]:
        if int(got) != int(want):
            bad.append(f"内存卷 几何 {tag}: 内核={got} 宿主机按配方的字节读={want}")
    for tag, got, want in [("阈值判型", geo.group("band"), h["band"]),
                           ("结构判型", geo.group("struct"), h["struct"])]:
        if got != want:
            bad.append(f"内存卷 {tag}: 内核={got} 宿主机={want}")
    if geo.group("name") != ("true" if h["fs_name_str"] == "FAT32" else "false"):
        bad.append(f"内存卷 名字串: 内核={geo.group('name')} 宿主机读偏移 82 = {h['fs_name_str']!r}")
    if geo.group("bsame") != ("true" if h["backup_same"] else "false"):
        bad.append(f"内存卷 备份扇区: 内核={geo.group('bsame')} 宿主机={h['backup_same']}")

    dirm = FAT_MEM_DIR_RE.search(log)
    if not dirm:
        return bad + ["串口没有 `fat32-mem: 目录 …` 那一行"]
    got_stats = {m.group("name"): m for m in FAT_MEM_STAT_RE.finditer(dirm.group("body"))}
    # 用例查的三个名字（`FAT_READ_NAMES["MEM"]`，与 ktests/fs.rs 的 `vol.open(...)` 由门禁对账）。
    # `?LD.TXT` 里那个问号不是笔误：配方把首字节写成 0x05（删除标记），于是盘上第一位的那个
    # `O` 已经不在了，两台实现都只能按规范把它读成 '?'——上一轮这里查 `?OLD.TXT`，红在 NoEntry。
    for want_name in FAT_READ_NAMES["MEM"]:
        hf = h["files"].get(want_name)
        if hf is None:
            bad.append(f"内存卷：配方写出的根目录里没有 {want_name}（脚本改了？用例查的就是它）")
            continue
        m = got_stats.get(want_name)
        if m is None:
            bad.append(f"内存卷 {want_name}: 内核那一行不是 Ok(FileStat …)（读不成或被改名，"
                       "用例红在目录那一格）")
            continue
        for tag, got, want in [("大小", int(m.group("size")), hf["size"]),
                               ("首簇", int(m.group("cluster")), hf["first"]),
                               ("扫过项", int(m.group("seen")), hf["seen"]),
                               ("LFN", int(m.group("lfn")), hf["lfn"])]:
            if got != want:
                bad.append(f"内存卷 {want_name} {tag}: 内核={got} 宿主机={want}")
    # 续读游标的内容账：内核逐块读出来的 FNV，与这台仪器自己走链算的 FNV 必须是同一个数。
    # 内核那 19 项判据是它自己判自己；这一格让"读出来的字节"有第二台仪器作证。
    cm = FAT_MEM_CURSOR_RE.search(log)
    if not cm:
        bad.append("串口没有 `fat32-cursor: memory checks=… sum=…` 那一行（续读内存账没跑或契约变了）")
    else:
        if cm.group("checks") != ", ".join(["true"] * 19):
            bad.append(f"内存卷 续读判据有不成立的格: [{cm.group('checks')}]")
        hf = h["files"].get("LONG~1.TXT")
        if hf is None:
            bad.append("内存卷：宿主机没走出 LONG~1.TXT 的链，续读内容账没有对账对象")
        elif int(cm.group("sum"), 16) != hf["fnv"]:
            bad.append(f"内存卷 LONG~1.TXT 内容FNV: 内核续读={cm.group('sum')} 宿主机走链={hf['fnv']:#018x}")
        if int(cm.group("bound")) != FAT_MAX_WALKED or int(cm.group("pos")) != FAT_MAX_WALKED * 512:
            bad.append(f"内存卷 环链撞界: 内核={cm.group('bound')}/{cm.group('pos')} "
                       f"宿主机期望={FAT_MAX_WALKED}/{FAT_MAX_WALKED * 512}")
    return bad


def check_fat32(log: str) -> list[str]:
    """内核从两块卷读回来的每一个数，与宿主机解析同一批字节的结果逐字段对账。

    为什么值得单独一行（而不是只信内核 `判据` 那行里的十三个 bool）：那十三条全是**内核自己
    与写死的期望数**比。期望数与夹具不同步时（换卷、换 mtools），两边会"错得一样"，而任何一台
    仪器都发现不了那种一致。这台从镜像字节自己算，逐字段与串口那个数比；口位接反也一样露馅——
    两块卷簇数不同（64,496 与 129,022），口 3 与口 4 挂反了 `卷1` 那一行就对不上小卷。
    """
    bad: list[str] = []
    geo = {m.group("vol"): m for m in FAT_GEO_RE.finditer(log)}
    if not geo:
        return ["这一跑挂了 fat32 变体，但串口里没有 `fat32: 几何 卷A|B …` 那两行（用例没跑到，或被改名）"]
    missing = [name for name in FAT_PORTS.values() if not FAT_IMG[name].exists()]
    if missing:
        return [f"宿主机这边没有解压好的夹具：{missing}（`make_fat_volumes` 没跑或失败）"]
    vols = {"A": fat32_host_volume(FAT_IMG[FAT_PORTS[3]].read_bytes(), FAT_READ_NAMES["A"]),
            "B": fat32_host_volume(FAT_IMG[FAT_PORTS[4]].read_bytes(), FAT_READ_NAMES["B"])}
    for letter in ("A", "B"):
        if letter not in geo:
            bad.append(f"串口没有 `几何 卷{letter}` 那一行（两卷各一行，缺的那卷没被读到）")

    # 几何：卷A = 口 3 = 小卷，卷B = 口 4 = 宽卷。字段集两边对称是内核那两行的形状决定的，
    # 接错口位在这里就会红：两块卷的簇数与数据起点不同，串口那行却按口号打卷名。
    for letter in ("A", "B"):
        m = geo.get(letter)
        if m is None:
            continue
        h = vols[letter]
        for tag, got, want in [
            ("簇数", m.group("clusters"), h["clusters"]),
            ("数据起点", m.group("data"), h["data_start"]),
            ("每簇字节", m.group("clu"), h["cluster_bytes"]),
            ("FAT份", m.group("fats"), h["fat_count"]),
            ("每份扇区", m.group("spf"), h["sectors_per_fat"]),
            ("根簇", m.group("root"), h["root_cluster"]),
            ("FSInfo扇区", m.group("fsinfo"), h["fsinfo_sector"]),
            ("备份扇区", m.group("backup"), h["backup_sector"]),
            ("自由簇", m.group("free"), h["fsinfo_free"]),
        ]:
            if int(got) != int(want):
                bad.append(f"卷{letter} 几何 {tag}: 内核={got} 宿主机={want}")
        for tag, got, want in [("阈值判型", m.group("band"), h["band"]),
                               ("结构判型", m.group("struct"), h["struct"])]:
            if got != want:
                bad.append(f"卷{letter} {tag}: 内核={got} 宿主机={want}")
        # 名字串与备份扇区：内核那两格各是一条"读错偏移就会 false"的检查（模块头记着
        # 49→50 与 484/488 那两次对表），所以它们在**两块卷上**都要被第二台仪器读过一遍
        if m.group("name") != ("true" if h["fs_name_str"] == "FAT32" else "false"):
            bad.append(f"卷{letter} 名字串: 内核={m.group('name')} 宿主机读偏移 82 = {h['fs_name_str']!r}")
        if m.group("bsame") != ("true" if h["backup_same"] else "false"):
            bad.append(f"卷{letter} 备份扇区逐字节同: 内核={m.group('bsame')} 宿主机={h['backup_same']}")
    # `自由簇` 那一格内核只打印不判，所以只有这台仪器在判它。484 与 488 那 4 个字节的偏移之争
    # 最后由这个数结案：读错偏移会得到 0x61417272（结构签名）这样一个"非零且看着合理"的数，
    # 任何"非 0 即通过"的检查都拦不住。
    for letter in ("A", "B"):
        h = vols[letter]
        if h["fsinfo_lead"] != 0x4161_5252 or h["fsinfo_struct"] != 0x6141_7272:
            bad.append(f"卷{letter} 宿主机自己读的 FSInfo 签名就不是规范值："
                       f"前导={h['fsinfo_lead']:#010x} 结构={h['fsinfo_struct']:#010x}（夹具坏了，先修夹具）")

    # 逐文件：目录项的四格（大小、首簇两半、扫过项、LFN）、走链的四格（字节/簇/尾格/末簇后继）、
    # 内容的两格（头四字节、FNV）。卷名 A/B 与记录行的"卷1/卷2"按 FAT_PORTS 的口序对应。
    vol_letter = {1: "A", 2: "B"}
    lines = {(int(m.group("vol")), m.group("name")): m for m in FAT_FILE_RE.finditer(log)}
    for vi, letter in vol_letter.items():
        h = vols[letter]
        declared = FAT_READ_NAMES[letter]
        got_rows = sorted(n for (v, n) in lines if v == vi)
        if got_rows != sorted(declared):
            bad.append(f"卷{letter}: 串口读的名字是 {got_rows}，这张表声明的是 {sorted(declared)}"
                       "——两边读的不是同一组文件，逐字段对账就失去了对象")
        for name in declared:
            hf = h["files"].get(name)
            if hf is None:
                bad.append(f"卷{letter} {name}: 内核说读了它，宿主机在这块卷的根目录里找不到这一项")
                continue
            if hf["bad_cluster"] or hf["off_image"] or hf["cyclic"]:
                bad.append(f"卷{letter} {name}: 宿主机算下来它的链不可读"
                           f"（坏簇={hf['bad_cluster']} 越出镜像={hf['off_image']} 环链={hf['cyclic']}），"
                           "而内核给了它一条记录行")
                continue
            m = lines.get((vi, name))
            if m is None:
                bad.append(f"卷{letter} {name}: 宿主机读到这一项，串口没有对应记录行")
                continue
            head = bytes.fromhex(m.group("head").replace(", ", "").replace(" ", ""))
            for tag, got, want in [
                ("大小", int(m.group("size")), hf["size"]),
                ("首簇", int(m.group("cluster")), hf["first"]),
                ("高半", int(m.group("hi")), hf["hi"]),
                ("低半", int(m.group("lo")), hf["lo"]),
                ("扫过项", int(m.group("seen")), hf["seen"]),
                ("LFN", int(m.group("lfn")), hf["lfn"]),
                ("走字节", int(m.group("wbytes")), hf["bytes"]),
                ("走簇", int(m.group("wclusters")), hf["clusters"]),
                ("尾字节", int(m.group("tail")), hf["tail"]),
                ("末簇后继", int(m.group("after"), 16), hf["after"]),
                ("头四字节", head.hex(), hf["head"].hex()),
                ("内容FNV", int(m.group("hash"), 16), hf["fnv"]),
            ]:
                if got != want:
                    bad.append(f"卷{letter} {name} {tag}: 内核={got} 宿主机={want}")
    mbr = FAT_MBR_RE.search(log)
    if not mbr:
        bad.append("串口没有 `fat32: 引导盘 口N 拒因=…` 那一行（引导盘那格没跑）")
    elif mbr.group("err") != "BadBytesPerSector":
        bad.append(f"引导盘拒因={mbr.group('err')}，宿主机算下来应该崩在每扇区字节数那道闸"
                   f"（保护性 MBR 的 0x55AA 也在位，签名闸拦不住它）")
    # ② 那本账（合成卷）在同一跑里，一并核：两块真卷证明偏移表，合成卷证明分支覆盖，
    # 两边都从宿主机自己的字节算一遍才算这一行覆盖了这个变体里的两条用例
    bad += check_fat32_mem(log)
    cursor_rows = re.findall(
        r"fat32-cursor: port=(\d+) size=(\d+) bytes=(\d+) first_cluster=(\d+) "
        r"hash=(0x[0-9a-f]+) agree=(true|false)", log)
    if sorted(int(row[0]) for row in cursor_rows) != sorted(FAT_PORTS):
        bad.append("fat32-cursor: 两块卷的续读记录缺失、重复或口号不符")
    if log.count("fat32-cursor: port=") != len(cursor_rows):
        bad.append("fat32-cursor: 有无法解析的续读记录")
    for port, size, count, first, digest, agree in cursor_rows:
        letter = {3: "A", 4: "B"}.get(int(port))
        if letter is None:
            continue
        hf = vols[letter]["files"].get("HELLO.ELF")
        if hf is None:
            bad.append(f"fat32-cursor: 卷{letter} 没有 HELLO.ELF")
            continue
        for field, got, want in [("size", int(size), hf["size"]), ("bytes", int(count), hf["bytes"]),
                                 ("first_cluster", int(first), hf["first"]), ("hash", int(digest, 16), hf["fnv"])]:
            if got != want:
                bad.append(f"fat32-cursor: 卷{letter} {field} 内核={got} 宿主机={want}")
        if agree != "true":
            bad.append(f"fat32-cursor: 卷{letter} 续读与旧 walk 不一致")
    return bad


FAT_EXE_DIR_RE = re.compile(
    r"elfdisk: 目录 大小=(?P<size>\d+) 首簇=(?P<cluster>\d+) 扫过项=(?P<seen>\d+) "
    r"缓冲上限=(?P<cap>\d+) 与内嵌夹具同长=(?P<same>true|false)")
FAT_EXE_SEG_RE = re.compile(
    r"elfdisk: 段(?P<i>\d+) off=(?P<off>\d+) va=(?P<va>0x[0-9a-f]+) filesz=(?P<filesz>\d+) "
    r"memsz=(?P<memsz>\d+) r=(?P<r>true|false) w=(?P<w>true|false) x=(?P<x>true|false)")
FAT_EXE_RUN_RE = re.compile(
    r"elfdisk: 跑后 entry=(?P<entry>0x[0-9a-f]+) data=(?P<data>0x[0-9a-f]+) "
    r"stack_top=(?P<stack>0x[0-9a-f]+) segs=(?P<segs>\d+) pages=(?P<pages>\d+) "
    r"magic=(?P<magic>Some\([^)]*\)|None) ping=(?P<ping>Some\([^)]*\)|None) "
    r"add=(?P<add>Some\([^)]*\)|None) unk=(?P<unk>Some\([^)]*\)|None) "
    r"rodata=(?P<rod>Some\([^)]*\)|None) loops=(?P<loops>Some\([^)]*\)|None) "
    r"served=(?P<served>\d+) rounds=(?P<rounds>\d+) guard_unmapped=(?P<guard>true|false)")
FAT_EXE_NEG_RE = re.compile(
    r"elfdisk: 负格 元数据说大=Some\(ChainEndsEarly[^)]*\) 截短=Some\(Elf\(SegmentOutOfBounds\)\)")
FAT_EXE_CLEAN_RE = re.compile(
    # ⑦ 与⑤⑥ 打在**同一行**里（`负格 … | 收尾 …`）：锚点要连着那个竖线，
    # 否则读成"没有那一行"——报的是缺行，看着像用例没跑，其实是正则找错了开头。
    r"\| 收尾 终止=(?P<term>true|false) 回收=(?P<released>\d+) 保留(?P<before>\d+)→(?P<after>\d+)")
# `elfload:` 是同一跑里"内嵌那份"的读数行（M4-2 那条用例打的）。③ 的对照物就是它。
ELFLOAD_RUN_RE = re.compile(
    r"elfload: magic=(?P<magic>Some\([^)]*\)|None) ping=(?P<ping>Some\([^)]*\)|None) "
    r"add=(?P<add>Some\([^)]*\)|None) unk=(?P<unk>Some\([^)]*\)|None) "
    r"rodata=(?P<rodata>Some\([^)]*\)|None) served=(?P<served>\d+) "
    r"unknown_nr=(?P<unknr>\d+) rounds=(?P<rounds>\d+) runs=(?P<runs>\d+) "
    r"state=(?P<state>\S+) guard_unmapped=(?P<guard>true|false)")
# L3-C④ 那两行负样本的锚点：判据整行与那条拒因的四个数。锚点写全（与上面同一条规矩）——
# 少一格就报"缺行"而不是"不符"，那看着像用例没跑，其实是正则找错了地方。
FAT_VERDICT_RE = re.compile(
    r"fat32: 判据 引导盘被拒=(?P<mbr>true|false) 卷A阈值反例=(?P<ac>true|false) "
    r"卷B结构=(?P<bs>true|false) 几何=(?P<geo>true|false) 目录=(?P<dir>true|false) "
    r"链=(?P<walk>true|false) ELF头=(?P<magic>true|false) 无长名=(?P<lfn>true|false) "
    r"两卷同哈希=(?P<cross>true|false) 大小写=(?P<case>true|false) "
    r"缺项被拒=(?P<absent>true|false) 低半单独被拒=(?P<lo>true|false)")
FAT_LATE_RE = re.compile(
    r"fat32: 卷2 HELLO\.ELF 读不成 ChainEndsLate \{ bytes: (?P<bytes>\d+), size: (?P<size>\d+), "
    r"cluster: (?P<cluster>\d+), next: (?P<next>\d+) \}")
FAT_EXE_VERDICT_RE = re.compile(
    r"elfdisk: 判据 同长=(?P<bound>true|false) 走链=(?P<walk>true|false) 字节同=(?P<bytes>true|false) "
    r"段表同=(?P<segs>true|false) 跑通=(?P<run>true|false) 元数据说大被拒=(?P<early>true|false) "
    r"截短被拒=(?P<short>true|false) 收尾干净=(?P<clean>true|false)")


def elf64_host_parse(b: bytes) -> dict:
    """宿主机这一侧的 ELF64 解析（第三份实现）：头 + PT_LOAD 表。

    偏移按 ELF64 规范：`e_entry` 在 24、`e_phoff` 在 32、`e_phentsize` 在 54、`e_phnum` 在 56；
    每条程序头里 `p_type` 0、`p_flags` 4、`p_offset` 8、`p_vaddr` 16、`p_filesz` 32、
    `p_memsz` 40。这套偏移在 `t_elf_load_run` 的分区负样本那段也踩过一次坑
    （`p_vaddr` 不是 +0x20，那是 `p_filesz`），所以这里把每个数写在行尾而不是靠记忆。
    """
    assert len(b) >= 64 and b[:4] == b"\x7fELF", "宿主机这份容器连头都不是 ELF64"
    phoff = int.from_bytes(b[32:40], "little")          # e_phoff 在 ELF64 里是 8 字节
    phentsize, phnum = _fat_u16(b, 54), _fat_u16(b, 56)
    entry = int.from_bytes(b[24:32], "little")          # e_entry
    loads = []
    for i in range(phnum):
        at = phoff + i * phentsize
        if int.from_bytes(b[at:at + 4], "little") != 1:   # PT_LOAD = 1，其余（GNU_STACK 等）不收
            continue
        flags = int.from_bytes(b[at + 4:at + 8], "little")
        loads.append(dict(
            offset=int.from_bytes(b[at + 8:at + 16], "little"),     # p_offset
            vaddr=int.from_bytes(b[at + 16:at + 24], "little"),     # p_vaddr
            filesz=int.from_bytes(b[at + 32:at + 40], "little"),    # p_filesz
            memsz=int.from_bytes(b[at + 40:at + 48], "little"),     # p_memsz
            r=bool(flags & 4), w=bool(flags & 2), x=bool(flags & 1),  # PF_R/X/W
        ))
    return dict(entry=entry, phnum=phnum, n=len(loads), loads=loads)


# ------------------------------------------------- L3-C④ 宿主机侧注入（改盘，不改内核）
#
# 这两条负样本证的是两件不同的事，但共用一条纪律：**要改的那一格由解析算出来，不写死偏移**。
# 写死一个镜像偏移的注入在夹具重建之后会静默改到别处，而负样本照样"以红收场"——
# 红的却不是要证的那一格，这种绿（对着红看的绿）比红更贵。
#
# 为什么第一条盯的是代码段里那条 immediate 而不是 `.rodata` 的第一个字节：
# 实测（llvm-objdump -d kernel/fixtures/hello.elf）`BANNER[0]` 被编译器折成了
# `movq $0xa7, 0x1fb9(%rip)`，而整份容器里**没有一条指令引用 0x100001xxx**（rodata 页）。
# 所以改 .rodata 那一字节只会让"字节同/sha"红，④ 的槽读数一动不动——半空转。
# 这件事本身也是一条缺陷（user/hello 声称第四个槽证明 r-- 段 ring3 读得到），记在 BACKLOG 80。
FAT_EXEC_BYTE_NEW = 0x5A
FAT_EXEC_INSN = re.compile(rb"\x48\xc7\x05....\xa7\x00\x00\x00", re.S)
FAT_EXEC_IMM_AT = 7          # REX.W + C7 + ModRM(05) + disp32 之后才是 imm32
FAT_DIR_HI_AT = 20           # 目录项里簇号高半的偏移，与内核 `OFF_CLUSTER_HI` 同一个数


def _fat_image_off(img: bytes, first: int, blob_off: int) -> int:
    """文件内偏移 → 镜像字节偏移：跟着簇链走到第 `blob_off // cluster_bytes` 个簇。"""
    bs = img[:FAT_SEC]
    spc, res, fats = bs[13], _fat_u16(bs, 14), bs[16]
    data_start = res + fats * _fat_u32(bs, 36)
    cb = spc * FAT_SEC
    c, skip = first, blob_off // cb
    if skip > FAT_MAX_WALKED:
        raise ValueError(f"要跳过 {skip} 个簇，超过本机走链上界 {FAT_MAX_WALKED}")
    for _ in range(skip):
        c = _fat_u32(img, res * FAT_SEC + c * 4) & 0x0FFF_FFFF
        if c < 2 or c >= FAT_EOC:
            raise ValueError(f"链在第 {_ + 1} 步就断了（簇号 {c:#x}）")
    return (data_start + (c - 2) * spc) * FAT_SEC + blob_off % cb


def fat_host_fault_plan(kind: str) -> tuple[str, int, bytes, bytes]:
    """定位一条宿主机侧注入：返回 (卷名, 镜像偏移, 现值, 新值)。

    读的是仓库里那份 `.img.zz`（配方），不是 `build/` 里那份可能已经被改过的镜像——
    所以这个函数既能用来改盘，也能用来核"盘真被改成了这个样子"，两次算的是同一个数。
    定位不到、命中不唯一、或改了等于没改，一律抛 ValueError：红在跑之前，而不是跑完之后
    对着一行 FAIL 猜"它红在哪"。
    """
    import zlib
    name = FAT_HOST_FAULTS[kind]
    raw = zlib.decompress(FAT_ZZ[name].read_bytes())
    f = fat32_host_volume(raw, ("HELLO.ELF",))["files"].get("HELLO.ELF")
    if f is None or not f["walked_it"]:
        raise ValueError(f"{name} 上读不到 HELLO.ELF 的字节（注入没有对象）")
    if kind == "fault-fat32-cluster-hi":
        at = f["ent_off"] + FAT_DIR_HI_AT
        old = raw[at:at + 2]
        if old == b"\x00\x00":
            raise ValueError(f"{name} 的簇号高半本来就是 0 ⇒ 抹零是空转"
                             "（这块卷的角色是「高半非零」，夹具换了？）")
        return name, at, old, b"\x00\x00"
    prog = elf64_host_parse(f["blob"])
    exe = [s for s in prog["loads"] if s["x"]]
    if len(exe) != 1:
        raise ValueError(f"容器里有 {len(exe)} 条可执行段，要恰好 1 条才谈得上「改那一条里的字节」")
    seg = exe[0]
    body = f["blob"][seg["offset"]:seg["offset"] + seg["filesz"]]
    hits = [m.start() for m in FAT_EXEC_INSN.finditer(body)]
    if len(hits) != 1:
        raise ValueError(f"代码段里 `movq $0xa7, disp32(%rip)` 命中 {len(hits)} 处，要恰好 1 处"
                         "（容器重建了？那就要重新量这条指令，而不是随便挑一处改）")
    at = seg["offset"] + hits[0] + FAT_EXEC_IMM_AT
    old, new = f["blob"][at], FAT_EXEC_BYTE_NEW
    if old == new:
        raise ValueError(f"现值与新值都是 {new:#x} ⇒ 这条注入是空转")
    return name, _fat_image_off(raw, f["first"], at), bytes([old]), bytes([new])


def apply_fat_host_fault(kind: str) -> list[str]:
    """把一条宿主机侧注入写到 `build/` 那块卷上（在 `make_fat_volumes` 之后调）。

    改的是解压出来的那份，仓库里的 `.img.zz` 一个字节不动；而 `make_fat_volumes` 每次
    都比「build 里的字节 == 配方解压出来的字节」，所以下一跑自动回到 pristine——
    注入的寿命就是一跑。跑完由 `fat_host_witness` 还原（它是两条路上最后一个读改过的盘的人），
    不让一块被改过的盘留在 build/ 里冒充下一跑的证据。
    """
    try:
        name, off, old, new = fat_host_fault_plan(kind)
    except ValueError as e:
        return [f"{kind} 定位不成：{e}"]
    img = FAT_IMG[name]
    data = bytearray(img.read_bytes())
    if bytes(data[off:off + len(old)]) != old:
        return [f"{kind}: {name} 偏移 {off} 现值 {bytes(data[off:off + len(old)]).hex()} "
                f"不是配方里的 {old.hex()}"]
    data[off:off + len(old)] = new
    img.write_bytes(data)
    print(f"    宿主机侧注入 {kind}: {name} 镜像偏移 {off} {old.hex()} → {new.hex()}"
          "（内核用的是正向那一跑的同一个 ELF，只有盘不同）")
    return []


def check_fat32_exec_byte(log: str) -> list[str]:
    """第 38 行的证人：盘上真被改了一格，而 ④ 的槽读数跟着变、"字节同"那格红。

    只要求"这一跑以红收场"是不够的（第 37 行同一条纪律）：别的用例红了这一行也照样符合。
    所以这里要三件互相独立的事同时成立——
    1 build/ 里那块卷与配方只差**计划中的那一字节**（宿主机自己比，不信串口）；
    2 串口那格判据说 `字节同=false 跑通=false`，而 `同长/走链/段表同` 还是 true
    ⇒ 改的是段内字节，不是元数据，红不是"读不出来"而是"读出来的不一样"；
    3 同一跑里两条来源的 rodata 槽**不再同数**，且盘上那条正好等于注入的新值、
    内嵌那条还是 0xa7 ⇒ ④ 的配对判据真的被这一字节推翻了。
    """
    bad: list[str] = []
    import zlib
    try:
        name, off, old, new = fat_host_fault_plan("fault-fat32-exec-byte")
    except ValueError as e:
        return [f"注入点定位不成，这一行的证人无从算起：{e}"]
    pristine = zlib.decompress(FAT_ZZ[name].read_bytes())
    got = FAT_IMG[name].read_bytes()
    if len(got) != len(pristine):
        return [f"{name} 镜像长度变了：{len(got)} 对配方 {len(pristine)}"]
    diff = [i for i in range(len(got)) if got[i] != pristine[i]]
    if diff != [off] or bytes(got[off:off + 1]) != new:
        return [f"盘上不是「只差计划中那一格」：差异偏移 {diff[:8]}（共 {len(diff)} 处），"
                f"计划是 {off} 改成 {new.hex()}"]
    v = FAT_EXE_VERDICT_RE.search(log)
    if not v:
        return bad + ["串口没有 `elfdisk: 判据 …` 那一行（③ 没跑到结论）"]
    for tag, want in (("bound", "true"), ("walk", "true"), ("segs", "true"),
                      ("bytes", "false"), ("run", "false")):
        if v.group(tag) != want:
            bad.append(f"③ 判据 {tag}={v.group(tag)}，期望 {want}"
                       "（改的是段内字节：长度/走链/段表都该还对，只有内容与跑后读数该红）")
    runm, emb = FAT_EXE_RUN_RE.search(log), ELFLOAD_RUN_RE.search(log)
    if not runm or not emb:
        return bad + ["串口缺 `elfdisk: 跑后 …` 或 `elfload: magic=…`（④ 的配对没有对象）"]
    want_new, want_old = f"Some({new[0]})", f"Some({old[0]})"
    if runm.group("rod") != want_new:
        bad.append(f"盘上那条的 rodata 槽={runm.group('rod')}，期望 {want_new}"
                   "（改的那一格就是这条槽的来源，它没变说明注入没走到用户态）")
    if emb.group("rodata") != want_old:
        bad.append(f"内嵌那条的 rodata 槽={emb.group('rodata')}，期望 {want_old}（对照物自己被改了？）")
    return bad


def check_fat32_cluster_hi(log: str) -> list[str]:
    """第 39 行的证人：高半抹零之后内核读到的是**另一个文件的字节**，而不是"读不出来"。

    宿主机先自己把改过的那块卷解析一遍：首簇掉到低半、走满 64 簇喂够 32,672 字节、
    末簇后继还不是 EOC、头四字节不再是 ELF 魔数。然后要求串口那条拒因里的四个数
    与宿主机算的逐格相同——这才叫"少一半就读到别的东西"，而不是"期望对上了"。
    """
    bad: list[str] = []
    import zlib
    try:
        name, off, old, new = fat_host_fault_plan("fault-fat32-cluster-hi")
    except ValueError as e:
        return [f"注入点定位不成，这一行的证人无从算起：{e}"]
    pristine = zlib.decompress(FAT_ZZ[name].read_bytes())
    got = FAT_IMG[name].read_bytes()
    if len(got) != len(pristine):
        return [f"{name} 镜像长度变了：{len(got)} 对配方 {len(pristine)}"]
    diff = [i for i in range(len(got)) if got[i] != pristine[i]]
    # 高半是 1 ⇒ 盘上是 `01 00`，抹成 `00 00` **只真变一格**。第一版这里写死 `[off, off+1]`，
    # 于是注入完全成立的那一跑被自己的证人报成红（实测：差异偏移 [1049652]，共 1 处）。
    # 该期望的是"计划里 old 与 new 不同的那些格"，不是"计划覆盖的那些格"。
    want_diff = [off + i for i in range(len(old)) if old[i] != new[i]]
    if diff != want_diff or bytes(got[off:off + len(new)]) != new:
        return [f"盘上不是「只抹了高半那两格」：差异偏移 {diff[:8]}（共 {len(diff)} 处），"
                f"计划是 {want_diff} 处改成 {new.hex()}"]
    f = fat32_host_volume(got, ("HELLO.ELF",))["files"]["HELLO.ELF"]
    if f["hi"] != 0 or f["first"] != f["lo"]:
        bad.append(f"宿主机读改过的盘：高半={f['hi']} 首簇={f['first']}，期望 0 与 {f['lo']}")
    if f["bytes"] != f["size"] or f["after"] >= FAT_EOC:
        bad.append(f"宿主机走链：字节={f['bytes']} 大小={f['size']} 末簇后继={f['after']:#x}"
                   " ⇒ 这不是 ChainEndsLate 的形状（注入没落到长链中间）")
    if f["head"] == bytes([0x7F, 0x45, 0x4C, 0x46]):
        bad.append("抹零之后读出来的还是 ELF 魔数 ⇒ 没读到别的文件，这一格证不了「两半拼」")
    m = FAT_LATE_RE.search(log)
    if not m:
        return bad + ["串口没有 `fat32: 卷2 HELLO.ELF 读不成 ChainEndsLate { … }` 那一行"]
    for tag, want in (("bytes", f["bytes"]), ("size", f["size"]),
                      ("cluster", f["last"]), ("next", f["after"])):
        if int(m.group(tag)) != want:
            bad.append(f"拒因里的 {tag}={m.group(tag)}，宿主机按改过的盘算得 {want}")
    v = FAT_VERDICT_RE.search(log)
    if not v:
        return bad + ["串口没有 `fat32: 判据 …` 那一行"]
    for tag in ("dir", "walk", "cross"):
        if v.group(tag) != "false":
            bad.append(f"判据 {tag}={v.group(tag)}，期望 false（高半抹零该把目录/链/两卷同哈希三格都推翻）")
    return bad


def check_handle_ring3(log: str) -> list[str]:
    """第 40 行的证人：ring3 读到的 4 字节、收到的句柄值、以及"表清空"都由宿主机独立对。

    魔数的期望**不来自内核**：它由宿主机读 `kernel/fixtures/hello.elf` 的前 4 字节算出来；
    句柄值的槽/世代也由宿主机按 ABI 拆开检查。内核那行 `⇒ true` 是它自己判自己，这里补第二台。
    """
    bad: list[str] = []
    m = HANDLE_RING3_RE.search(log)
    if not m:
        return ["串口没有 `elfdisk: ring3 句柄 …` 那一行（P7 ⑤ 没跑到结论）"]
    want_magic = int.from_bytes((ROOT / "kernel" / "fixtures" / "hello.elf").read_bytes()[:4], "little")
    if int(m.group("magic")) != want_magic:
        bad.append(f"ring3 读到的魔数={m.group('magic')}，宿主机读 hello.elf 前四字节={want_magic}")
    if int(m.group("done")) != 0x4844_4F4E_45:
        bad.append(f"ring3 的 done 哨兵={m.group('done')}，期望 0x48444f4e45")
    if m.group("clean") != "true":
        bad.append("ring3 跑完句柄表没清空（close 没走到或授错了对象）")
    if m.group("ok") != "true":
        bad.append("ring3 那一行自己的判据是 false（上面几格应有具体成因）")
    g = HANDLE_GRANT_RE.search(log)
    if not g:
        bad.append("串口没有 `elfdisk: 授予容器 句柄=… 主人=(…)` 那一行")
    else:
        hv = int(g.group("h"), 16)
        slot, gen = hv & 0xFFFF, hv >> 16
        if slot >= 16 or gen == 0:
            bad.append(f"授予的句柄值形状不对：slot={slot} gen={gen}")
        if hv != int(m.group("h"), 16):
            bad.append(f"ring3 拿到的句柄={m.group('h')} 不是授予的那个 {g.group('h')}")
        if int(g.group("g")) == 0:
            bad.append("主人是 gidx=0（启动上下文）——句柄授给了错的任务")
    kt = KT_TOTAL_RE.search(log)
    if not kt or kt.group("passed") != kt.group("total"):
        bad.append("这一跑的 ktests 不是全过（ring3 的结论靠它一起成立）")
    return bad


FAT_HOST_WITNESS = {
    "fault-fat32-exec-byte": check_fat32_exec_byte,
    "fault-fat32-cluster-hi": check_fat32_cluster_hi,
}


def fat_host_witness(kind: str, log: str) -> list[str]:
    """跑完之后叫证人。判定链里那两行与手工 `run --host-fault` 走的是同一个入口——
    两处各写一遍调用，就会出现"链里核了、单跑没核"那种只在一条路上成立的绿。

    还原放在这里而不是调用方：两个证人都要**读改过的那块盘**（自己比差异偏移），
    所以这里是两条路上最后一个读它的人，再往后就必须回到 pristine。
    """
    bad = FAT_HOST_WITNESS[kind](log)
    for x in bad:
        print("    对账:", x)
    bad += make_fat_volumes()
    return bad


def check_fat32_exec(log: str) -> list[str]:
    """L3-C③ 那一本账：盘上那份容器、内嵌那份容器、与宿主机自己算的第三份，三者必须同数。

    这一行比 34 行多了两台仪器，因为③ 换掉的是**输入的来源**而不是算法：
    * 宿主机用自己的 FAT 解析从卷A 里取出 `HELLO.ELF` 的字节，与 `kernel/fixtures/hello.elf`
      （rustc 的产物，构建时嵌进镜像的那份）比 sha256 ⇒ 证明"两条路喂给加载器的确实是同一个容器"
      这件事不由内核自己说。
    * 宿主机再自己解析一遍 ELF64 的头与 PT_LOAD 表（第三份实现），与串口那几行段读数逐格比。
      截短那一格期望的 `SegmentOutOfBounds` 也由这里作证：宿主机算出的 `max(offset+filesz)`
      必须真的落在文件内部——否则内核报的红是量具的红。
    * 最后把 ③ 的读数与同一跑里 `elfload:`（内嵌那份）的读数配对：同一个容器经两条来源跑出
      同一组数，才叫"换来源不换行为"。两行都在同一份串口里，与用例先后无关。
    """
    bad: list[str] = []
    dirm = FAT_EXE_DIR_RE.search(log)
    if not dirm:
        return ["这一跑挂了 fat32-exec，但串口没有 `elfdisk: 目录 …` 那一行（③ 没跑到）"]
    if not FAT_IMG[FAT_PORTS[3]].exists():
        return [f"宿主机没有解压好的 {FAT_PORTS[3]} 卷，无法独立取那份容器"]

    # 第一台：从卷里按 FAT 结构取出 HELLO.ELF 的字节
    host_vol = fat32_host_volume(FAT_IMG[FAT_PORTS[3]].read_bytes(), ("HELLO.ELF",))
    hf = host_vol["files"].get("HELLO.ELF")
    if hf is None:
        return ["宿主机从卷A 的根目录里读不到 HELLO.ELF（那 ③ 读的是什么？）"]
    import hashlib
    fixture = (ROOT / "kernel" / "fixtures" / "hello.elf").read_bytes()
    body = hf["blob"]
    if not fixture:
        return ["kernel/fixtures/hello.elf 是空的（内嵌那份的来源没了，两处对照都失去对象）"]
    for tag, got, want in [("大小", hf["size"], len(fixture)),
                           ("走字节", hf["bytes"], len(fixture)),
                           ("内容FNV", hf["fnv"], fnv1a64(fixture))]:
        if int(got) != int(want):
            bad.append(f"③ 的容器 {tag}: 宿主机从卷里读={got} 内嵌那份文件={want}")
    # 整份字节直接比。哈希那一格 34 行已经判过；这里要的是"加载器拿到的就是同一份容器"
    # 这句话本身，而摘要相同、字节不同在原则上不是不可能
    if body != fixture:
        bad.append(f"盘上那份与内嵌那份不是同一个容器：{len(body)} 字节 sha256={hashlib.sha256(body).hexdigest()[:16]} "
                   f"对 {len(fixture)} 字节 sha256={hashlib.sha256(fixture).hexdigest()[:16]}")

    # 第二台：宿主机自己解析 ELF64 的头与 PT_LOAD 表
    prog = elf64_host_parse(body)
    if int(dirm.group("size")) != len(fixture):
        bad.append(f"内核读到的大小={dirm.group('size')}，内嵌那份文件是 {len(fixture)} 字节")
    if dirm.group("same") != "true":
        bad.append("内核自己报了 `与内嵌夹具同长=false`")
    segs = list(FAT_EXE_SEG_RE.finditer(log))
    if len(segs) != prog["n"]:
        bad.append(f"串口打了 {len(segs)} 条段记录，宿主机的 ELF 表里有 {prog['n']} 条 PT_LOAD")
    for m, seg in zip(segs, prog["loads"]):
        for tag, got, want in [("off", int(m.group("off")), seg["offset"]),
                               ("va", int(m.group("va"), 16), seg["vaddr"]),
                               ("filesz", int(m.group("filesz")), seg["filesz"]),
                               ("memsz", int(m.group("memsz")), seg["memsz"]),
                               ("r", m.group("r"), "true" if seg["r"] else "false"),
                               ("w", m.group("w"), "true" if seg["w"] else "false"),
                               ("x", m.group("x"), "true" if seg["x"] else "false")]:
            if got != want:
                bad.append(f"③ 段{m.group('i')} {tag}: 内核={got} 宿主机解析 ELF 得={want}")
    runm = FAT_EXE_RUN_RE.search(log)
    if not runm:
        return bad + ["串口没有 `elfdisk: 跑后 …` 那一行（④ 那格没跑成）"]
    if int(runm.group("entry"), 16) != prog["entry"]:
        bad.append(f"入口: 内核={runm.group('entry')} 宿主机 e_entry={prog['entry']:#x}")
    if int(runm.group("segs")) != prog["n"]:
        bad.append(f"段数: 内核={runm.group('segs')} 宿主机={prog['n']}")

    # 截短那一格的证人：宿主机算的 `max(offset+filesz)` 必须在文件内，且减 1 之后
    # 确实少掉了某段的一部分（否则内核的红是量具的红）
    last_end = max(w["offset"] + w["filesz"] for w in prog["loads"])
    neg = FAT_EXE_NEG_RE.search(log)
    if not neg:
        bad.append("串口没有 `负格 元数据说大=Some(ChainEndsEarly…) … 截短=Some(Elf(SegmentOutOfBounds))` 那一行")
    if not (0 < last_end <= len(fixture)):
        bad.append(f"宿主机算的段表文件末尾 last_end={last_end} 不在文件长度 {len(fixture)} 之内 ⇒ ⑥ 那格该判没跑成")

    # 第三台：同一跑里内嵌那条路径的读数，两行必须给同一组数
    emb = ELFLOAD_RUN_RE.search(log)
    if not emb:
        bad.append("同一跑里没有 `elfload: magic=…` 那行（内嵌那份的对照物不在，配对判据失去对象）")
    else:
        for tag, a, b in [("magic", runm.group("magic"), emb.group("magic")),
                          ("ping", runm.group("ping"), emb.group("ping")),
                          ("add", runm.group("add"), emb.group("add")),
                          ("unk", runm.group("unk"), emb.group("unk")),
                          ("rodata", runm.group("rod"), emb.group("rodata")),
                          ("guard", runm.group("guard"), emb.group("guard"))]:
            if a != b:
                bad.append(f"两条来源跑出的数不同（{tag}）: 盘上={a} 内嵌={b}")
        # 盘上那一跑还带 `FLAG_HANDLE`：ring3 句柄段多打两次调用（file_read + close）。
        # 只有**同一跑里真有 `授予容器` 那一行**才允许这个 +2；没有授予行就仍要逐字相等。
        want_served = int(emb.group("served")) + (2 if HANDLE_GRANT_RE.search(log) else 0)
        if int(runm.group("served")) != want_served:
            bad.append(f"两条来源跑出的数不同（served）: 盘上={runm.group('served')} "
                       f"内嵌={emb.group('served')} 期望={want_served}（有授予行时 +2）")

    clean = FAT_EXE_CLEAN_RE.search(log)
    if not clean:
        bad.append("串口没有 `elfdisk: 收尾 …` 那一行（⑦ 那格没跑）")
    elif clean.group("before") != clean.group("after") or clean.group("term") != "true":
        bad.append(f"收尾不干净：终止={clean.group('term')} 保留{clean.group('before')}→{clean.group('after')}"
                   "（留给后面的用例就是 `VaTaken`）")
    return bad


def check_gpt_bounds() -> list[str]:
    """ADR-078 决策 4 末条：GPT 的上界常量与宿主机侧逐字对账。

    **核的不是硬相等**：内核 `MAX_ENTRY_BYTES=512` 是"装配缓冲准备接多少"，夹具 `ENTRY_SIZE=128`
    是"盘上实际多大"，两者本来就不该相等。要核的是三件事：
      1 夹具几何落在内核的界**之内**（否则正向那一行会红，而红在跑之后不如红在跑之前）；
      2 内核那条 `MAX_ARRAY_BYTES = MAX_ENTRIES × MAX_ENTRY_BYTES` 的**内部自洽**——
        正是它让第三道"数组太大"的闸不可达而被删掉（§173），改了它那个论证就不成立；
      3 **读表那一台与写表那一台对同一个夹具的期望一致**（validate_esp.py vs make_gpt_disk.py），
        否则对账核的是另一个对象，那种绿比红更贵。
    符号常量只认已知的那两种写法，写法变了就报红而不是静默算成 0（静默少核一条 = 静默少测一条）。
    """
    bad: list[str] = []
    gpt = (ROOT / "kernel" / "src" / "filesystem" / "gpt.rs").read_text(encoding="utf-8")
    vfs = (ROOT / "kernel" / "src" / "filesystem" / "vfs.rs").read_text(encoding="utf-8")
    writer = (ROOT / "tools" / "make_gpt_disk.py").read_text(encoding="utf-8")
    reader = (ROOT / "tools" / "validate_esp.py").read_text(encoding="utf-8")

    def num(text: str, pat: str, tag: str) -> int | None:
        m = re.search(pat, text, re.M)
        if m is None:
            bad.append(f"{tag}：找不到常量（改名/挪进函数体了？这条对账就不核它了）")
            return None
        return int(m.group(1).replace("_", ""), 0)

    sector = num(vfs, r"^pub const SECTOR_BYTES: usize = (\d+);", "内核 SECTOR_BYTES")
    k_min_hdr = num(gpt, r"^pub const MIN_HEADER_BYTES: u32 = (\d+);", "内核 MIN_HEADER_BYTES")
    k_min_ent = num(gpt, r"^pub const MIN_ENTRY_BYTES: u32 = (\d+);", "内核 MIN_ENTRY_BYTES")
    k_max_ent = num(gpt, r"^pub const MAX_ENTRIES: u32 = (\d+);", "内核 MAX_ENTRIES")
    k_rev = num(gpt, r"^pub const GPT_REVISION: u32 = (0x[0-9a-fA-F_]+);", "内核 GPT_REVISION")
    w_sector = num(writer, r"^SECTOR = (\d+)", "写表器 SECTOR")
    w_disk = num(writer, r"^DISK_SECTORS = (\d+)", "写表器 DISK_SECTORS")
    w_count = num(writer, r"^ENTRY_COUNT = (\d+)", "写表器 ENTRY_COUNT")
    w_size = num(writer, r"^ENTRY_SIZE = (\d+)", "写表器 ENTRY_SIZE")
    w_first = num(writer, r"^FIRST_USABLE = (\d+)", "写表器 FIRST_USABLE")
    r_sector = num(reader, r"^SECTOR = (\d+)", "读表器 SECTOR")
    r_hdr = num(reader, r'"header_size\(=(\d+)\)"', "读表器 header_size 期望")
    r_count = num(reader, r'"entry_count\(=(\d+)\)"', "读表器 entry_count 期望")
    r_size = num(reader, r'"entry_size\(=(\d+)\)"', "读表器 entry_size 期望")
    r_rev = num(reader, r'"revision\(=(0x[0-9a-fA-F]+)\)"', "读表器 revision 期望")
    r_first = num(reader, r'"first_usable_lba\(=(\d+)\)"', "读表器 first_usable 期望")

    # 两个符号常量：只认已知写法，写法变了必须报红（否则下面整段静默空转）。
    k_max_bytes = k_max_array = None
    m = re.search(r"^pub const MAX_ENTRY_BYTES: usize = ([^;]+);", gpt, re.M)
    if m is None:
        bad.append("内核 MAX_ENTRY_BYTES 找不到")
    elif m.group(1).strip() == "SECTOR_BYTES":
        k_max_bytes = sector
    else:
        bad.append(f"内核 MAX_ENTRY_BYTES 的写法变成了 {m.group(1).strip()!r}（本门禁只认 SECTOR_BYTES）"
                   "⇒ 装配缓冲与扇区的关系不再被核，改写法要连这里一起改")
    m = re.search(r"^pub const MAX_ARRAY_BYTES: u32 = ([^;]+);", gpt, re.M)
    if m is None:
        bad.append("内核 MAX_ARRAY_BYTES 找不到")
    elif m.group(1).strip() == "MAX_ENTRIES * MAX_ENTRY_BYTES as u32":
        if k_max_ent is not None and k_max_bytes is not None:
            k_max_array = k_max_ent * k_max_bytes
    else:
        bad.append(f"内核 MAX_ARRAY_BYTES 的写法变成了 {m.group(1).strip()!r}"
                   "（本门禁只认 MAX_ENTRIES * MAX_ENTRY_BYTES as u32）⇒ 『第三道闸不可达』那个论证不再被核")
    if None in (sector, k_min_hdr, k_min_ent, k_max_ent, k_rev, k_max_bytes, k_max_array,
                w_sector, w_disk, w_count, w_size, w_first, r_sector, r_hdr, r_count, r_size, r_first):
        return bad + ["有常量没解析出来 ⇒ 上面的界与一致性对账整体不成立（不许当成核过了）"]

    for tag, a, b in (("扇区字节 内核 vs 写表器", sector, w_sector),
                      ("扇区字节 内核 vs 读表器", sector, r_sector),
                      ("头最小字节 内核 vs 读表器期望", k_min_hdr, r_hdr),
                      ("revision 内核 vs 读表器期望", k_rev, r_rev),
                      ("first_usable 写表器 vs 读表器期望", w_first, r_first),
                      ("条目数 写表器 vs 读表器期望", w_count, r_count),
                      ("条目大小 写表器 vs 读表器期望", w_size, r_size),
                      ("夹具盘字节数 本脚本 vs 写表器", GPT_FIX_BYTES, w_disk * w_sector)):
        if a != b:
            bad.append(f"{tag}：{a} != {b}")
    if not k_min_ent <= w_size <= k_max_bytes:
        bad.append(f"夹具 ENTRY_SIZE={w_size} 不在内核的界 [{k_min_ent}, {k_max_bytes}] 之内"
                   "⇒ 正向那一跑会被 EntryTooSmall/EntryTooBig 拒，红在跑之后不如红在这里")
    if w_count > k_max_ent:
        bad.append(f"夹具 ENTRY_COUNT={w_count} 超过内核 MAX_ENTRIES={k_max_ent}"
                   "⇒ 正向那一跑会被 TooManyEntries 拒")
    if w_count * w_size > k_max_array:
        bad.append(f"夹具数组 {w_count}×{w_size}={w_count * w_size} 超过内核预算 MAX_ARRAY_BYTES={k_max_array}")
    if w_first != 34 or w_disk - 34 < w_first:
        bad.append(f"写表器几何不自洽：FIRST_USABLE={w_first}（规范是 34）、DISK_SECTORS={w_disk}")
    return bad


def check_fatal_record() -> list[str]:
    """无锁现场记录表的**接线对账**：那张表是挂死那一跑唯一的证人，证人不能靠印象。

    核四件事：
    ① 布局：`crash.rs` 的 `FATAL_FIELDS` 与八个 `FR_*` 下标，必须与本脚本 `FATAL_FIELD_NAMES`
       的**名字与次序**逐格对上。错了不报"少了字段"，而是整体错位——那比缺一格更贵，
       所以这一条只能在跑之前用文本核，不能在跑之后用读数核。
    ② stage 值：内核那五个 `STAGE_*` 与本脚本 `FATAL_STAGE_NAMES` 的键一一对应，不许内核
       多出一个"宿主机念不出名字"的进度点（念不出来就等于没证据）。
    ③ 口号：内核打的 `fatalrec: 物理=…` 与 `fatalrec: 自查 …` 两行，必须与本脚本的正则**逐字**
       对得上。正则与格式串分家时的表现是"读回整段静默跳过"，那是最坏的一种绿。
    ④ 四个进度点都还在位（致命入口 / 进 dump_site / 落盘返回 / 出口写码前）。少一处不会报错，
       只会让下一次挂死的证据少一级——那种缺失只有静态对账抓得到。
    """
    bad: list[str] = []
    src = (ROOT / "kernel" / "src" / "crash.rs").read_text(encoding="utf-8")
    m = re.search(r"pub const FATAL_FIELDS: usize = (\d+);", src)
    if m is None:
        return ["crash.rs 里找不到 `pub const FATAL_FIELDS`（改名了？整张对账不成立，不许当成核过了）"]
    if int(m.group(1)) != len(FATAL_FIELD_NAMES):
        bad.append(f"crash.rs 说每槽 {m.group(1)} 格，本脚本 FATAL_FIELD_NAMES 有 {len(FATAL_FIELD_NAMES)} 个名字")
    found: dict[str, int] = {}
    for name in FATAL_FIELD_NAMES:
        cm = re.search(rf"pub const FR_{name.upper()}: usize = (\d+);", src)
        if cm is None:
            bad.append(f"crash.rs 里没有 `pub const FR_{name.upper()}`（改名或删掉了一格 ⇒ 本脚本那个名字解出来的是别人的字段）")
            continue
        found[name] = int(cm.group(1))
    if len(found) == len(FATAL_FIELD_NAMES):
        for name, idx in found.items():
            if idx != FATAL_FIELD_NAMES.index(name):
                bad.append(f"字段 {name}：内核下标 {idx}，本脚本名字表里它在 {FATAL_FIELD_NAMES.index(name)} ⇒ 顺序分家")
    # ② stage：内核侧逐个取值，与宿主机念名表比
    kstages: dict[str, int] = {}
    for mm2 in re.finditer(r"pub const (STAGE_[A-Z_]+): u64 = (\d+);", src):
        kstages[mm2.group(1)] = int(mm2.group(2))
    if not kstages:
        bad.append("crash.rs 里一个 `STAGE_*` 都没有 ⇒ 宿主机念不出任何进度点")
    if len(set(kstages.values())) != len(kstages):
        bad.append(f"内核的 STAGE_* 有重号：{kstages}")
    for kname, val in sorted(kstages.items(), key=lambda kv: kv[1]):
        if val not in FATAL_STAGE_NAMES:
            bad.append(f"内核新增进度点 {kname}={val}，本脚本 FATAL_STAGE_NAMES 没有它 ⇒ 挂死时那一格念不出来")
    for val in FATAL_STAGE_NAMES:
        if val not in kstages.values():
            bad.append(f"本脚本念的 stage={val} 在 crash.rs 里没有对应的 STAGE_* 常量（宿主机在念一个不存在的进度点）")
    # ③ 口号逐字对账：内核打的格式串 vs 本脚本的正则（各取头部那一段固定文本）
    boot_fmt = re.search(r'"fatalrec: 物理=\{:#x\} cpu数=\{\} 每cpu字段=\{\} 字节=\{\}"',
                         (ROOT / "kernel" / "src" / "main.rs").read_text(encoding="utf-8"))
    if boot_fmt is None:
        bad.append("main.rs 里没有 `fatalrec: 物理={:#x} cpu数={} 每cpu字段={} 字节={}` 那行（改了格式串没改本脚本的正则 ⇒ 读回静默跳过）")
    ks = (ROOT / "kernel" / "src" / "ktests" / "crash.rs").read_text(encoding="utf-8")
    if 'fatalrec: 自查 故意停住 期待宿主机读回 向量=' not in ks:
        bad.append("ktests/crash.rs 里没有 `fatalrec: 自查 故意停住 期待宿主机读回 向量=` 那行 ⇒ 端到端自查无从对账")
    # ④ 四个进度点都在各自的调用文件里被真的写出去（删掉一处 = 证据少一级，且不会报错）
    for stage, file in (
        ("STAGE_FATAL_ENTER", "main.rs"),
        ("STAGE_DUMPSITE_ENTER", "crash.rs"),
        ("STAGE_DUMPSITE_EXIT", "crash.rs"),
        ("STAGE_EXIT_FINISH", "exit.rs"),
    ):
        txt = (ROOT / "kernel" / "src" / file).read_text(encoding="utf-8")
        if re.search(rf"mark_fatal\(\s*(?:crate::)?(?:crash::)?{stage}\b", txt) is None:
            bad.append(f"{file} 里没有把 {stage} 真写出去的那次 mark_fatal 调用（进度点被删 ⇒ 下一次挂死的证据少一级）")
    # 自查那一档必须在 Cargo 里存在，且 ktests 真的按它门控（否则"端到端证过"这句话没载体）
    feats = (ROOT / "kernel" / "Cargo.toml").read_text(encoding="utf-8")
    if not re.search(r"^fatal-record-stall = \[\]", feats, re.M):
        bad.append("Cargo.toml 的 [features] 里没有 fatal-record-stall ⇒ 端到端自查跑不起来")
    gate = '#[cfg(feature = "fatal-record-stall")]'
    if ks.count(gate) != 2:
        bad.append(f'ktests/crash.rs 里 `{gate}` 不是两处（用例与注册各一处），实测 {ks.count(gate)}'
                   " ⇒ 要么那一档编不出被测物，要么注册没跟着门控（默认构建里多一条会停住的用例）")
    if "ktest!(KT_FATAL_RECORD," not in ks:
        bad.append("ktests/crash.rs 里没有注册 KT_FATAL_RECORD ⇒ 默认构建里这张表没有任何用例读过它")
    # 模式二（`fatal-record-dump-stall`）：把 §180 那个"卡在崩溃路径"做成确定发生的一次。
    # 这一档的判据形状很脆，四条都要机器盯：口号、注入位置（必须在写盘**之前**）、
    # 两处 cfg（调用 + 定义）、以及**依赖 fault-crash-oops**——少了依赖就没有真 #PF，
    # 那一跑会安静地 PASS，于是"表能在真挂死里被读一次"这句话变成绿着的空话。
    if not re.search(r'^fatal-record-dump-stall = \["fault-crash-oops"\]', feats, re.M):
        bad.append('Cargo.toml 里没有 `fatal-record-dump-stall = ["fault-crash-oops"]`'
                   " ⇒ 那一档编不出真 #PF，会安静地 PASS（绿着的空话，比红更贵）")
    gate2 = '#[cfg(feature = "fatal-record-dump-stall")]'
    if src.count(gate2) != 2:
        bad.append(f'crash.rs 里 `{gate2}` 不是两处（调用与定义各一处），实测 {src.count(gate2)}'
                   " ⇒ 要么注入进不去 dump_site，要么默认构建里多了一条永远转的循环")
    if DUMP_STALL_MARK not in src:
        bad.append(f"crash.rs 里没有 `{DUMP_STALL_MARK}` 这个口号 ⇒ 宿主机认不出这一档的模式，自查整段静默跳过")
    wedge_at = src.find("wedge_before_disk_write();")
    write_at = src.find("let out = state_store::write_crash(&rec);")
    if wedge_at < 0 or write_at < 0:
        bad.append("crash.rs 里找不到 `wedge_before_disk_write();` 或 `let out = state_store::write_crash(&rec);`"
                   " ⇒ 注入位置无从对账（不许当成核过了）")
    elif wedge_at > write_at:
        bad.append("注入点跑到了 `write_crash` **之后** ⇒ 那一跑会等到 stage=3，量不到 §180 那个形状（写盘没回来）")
    return bad


def check_wedge_probe() -> list[str]:
    """挂死判别仪器的接线对账：读的每一个符号都必须真的是那个模块里的那个静态量。

    为什么必须机器核：这台仪器按 mangle 尾部找符号，**找错了不会报错**——它会读到另一块
    内存然后给出一个看着合理的数。所以逐个回源文件核 `static NAME:` 的存在与类型，
    并由类型推出元素宽度（AtomicBool=1，AtomicUsize/AtomicU64=8），与仪器里写的那份比。
    """
    bad: list[str] = []
    seen: dict[tuple[str, ...], str] = {}
    for segs, label, width in WEDGE_SYMBOLS:
        # 两个条目指向同一个符号是**复制粘贴错**的形状：逐个核都会过（那个符号确实存在），
        # 但表里会少读一个量、多读一遍另一个，而判别表按标签取数 ⇒ 静默读错。
        if segs in seen:
            bad.append(f"wedge 符号 {label} 与 {seen[segs]} 指向同一个静态量（{'::'.join(segs)}）⇒ 少读一个量")
            continue
        seen[segs] = label
        name = segs[-1]
        path = ROOT / "kernel" / "src" / ("/".join(segs[:-1]) + ".rs")
        if not path.exists():
            bad.append(f"wedge 符号 {label}：源文件 {path.name} 不在（模块挪了？）")
            continue
        src = path.read_text(encoding="utf-8")
        # 类型可能写成全限定（`core::sync::atomic::AtomicU64`），取**最后一段**；
        # 只取第一段会拿到 `core` 然后"宽度推不出来"（本门禁第一版就是这么红的）。
        m = re.search(rf"static {name}\s*:\s*\[?\s*([A-Za-z0-9_:]+)", src)
        if m is None:
            bad.append(f"wedge 符号 {label}：{path.name} 里没有 `static {name}` ⇒ 仪器会读到别的内存")
            continue
        ty = m.group(1).split("::")[-1]
        want = 1 if ty == "AtomicBool" else 8
        if ty not in ("AtomicBool", "AtomicUsize", "AtomicU64"):
            bad.append(f"wedge 符号 {label}：类型是 {ty}，宽度推不出来 ⇒ 不许猜")
        elif want != width:
            bad.append(f"wedge 符号 {label}：类型 {ty} 该按 {want} 字节解，仪器写的是 {width}")
    # 判别轴的语义前提必须机器核。这几条都是 §193 踩出来的：
    # ①`IDLE_HLT` 只有在 `task_wake_tick()` 返回 false 之后才自增，判别表才敢拿它当
    #   "每圈都没有可唤醒的等待者"。顺序反了这条判据就整个翻面。
    # ②`WORK` 只被 AP 工人循环与 ktests/sched.rs 那几条工人自增 ⇒ 它不是"任务在跑"，
    #   判别表里不许出现它（第一版就是拿它当第三支，把真挂死判成了"有任务在跑"）。
    sched_src = (ROOT / "kernel" / "src" / "sched.rs").read_text(encoding="utf-8")
    idle = sched_src[sched_src.find("fn idle_entry()"):]
    idle = idle[:idle.find("\n}")]
    guard = idle.find("if task_wake_tick()")
    bump = idle.find("IDLE_HLT[cpu].fetch_add")
    if guard < 0 or bump < 0 or guard > bump:
        bad.append("idle_entry 里 task_wake_tick 的闸不在 IDLE_HLT 自增之前 ⇒ wedge 拿 idle_hlt 当判据的前提不成立")
    vs = (ROOT / "tools" / "aurora.py").read_text(encoding="utf-8")
    # 必须按**行首**找定义：本函数自己那行就写着这两个字面量，用 find 会命中门禁自身
    # ⇒ 切出 30 个字符的空片，判据永远不咬（§193 实测：变异插进去 check 照样绿）。
    mv = re.search(r"^def wedge_verdict\(", vs, re.M)
    mp = re.search(r"^def wedge_probe\(", vs, re.M)
    vbody = vs[mv.start():mp.start()] if mv and mp and mp.start() > mv.start() else ""
    # 反空转：切片里必须真有函数体，否则这一格是"看着在核其实没核"。
    if "irq_moved" not in vbody or "return" not in vbody:
        bad.append("切不出 wedge_verdict 的函数体 ⇒ WORK 那条判据是空转的（切片命中了门禁自身的字面量？）")
    elif "工人圈数WORK" in vbody:
        bad.append("wedge_verdict 又拿 WORK 当判别轴 ⇒ 它只数 AP 工人与几条 ktest 工人，接近空转（§193）")
    paths = sorted(str(f.relative_to(ROOT)).replace("\\", "/")
                   for f in (ROOT / "kernel" / "src").rglob("*.rs")
                   if re.search(r"WORK\[[^\]]*\]\.fetch_add", f.read_text(encoding="utf-8", errors="replace")))
    want = ["kernel/src/ktests/sched.rs", "kernel/src/sched.rs"]
    if paths != want:
        bad.append(f"WORK 的直接自增点不再是那两处（现在={paths}）⇒ 它的语义变了，wedge 的只报不判要重核")
    # AP 工人走 hook 不直接写 WORK ⇒ 那一支要单独核，否则这个普查是假的
    smp = (ROOT / "kernel" / "src" / "arch" / "x86_64" / "smp.rs").read_text(encoding="utf-8")
    if "bump_current_work)()" not in smp:
        bad.append("smp.rs 里找不到 bump_current_work 的 hook 调用 ⇒ WORK 的语义普查漏了 AP 工人那一支")
    # 留档序号必须跨进程接着数：撞号会**覆盖**上一跑的串口与现场（§193 实测丢过一次）。
    src_all = (ROOT / "tools" / "aurora.py").read_text(encoding="utf-8")
    if not re.search(r"RUN_SEQ = _run_seq_start\(\)", src_all):
        bad.append("RUN_SEQ 不再从已有留档接着数 ⇒ 单独跑一次 run 就会覆盖矩阵同号那一跑的现场")
    # D 支（§196）必须在"idle 计数没涨"那一支**之前**：IDLE_HLT 冻结在 >0 是"进了第一次 hlt
    # 就再没醒过"，冻结在 0 才是"从没进过 idle"。顺序反了就把睡死读成关中断自旋（run-118 实测错判）。
    di = vbody.find("idle_abs > 0")
    ii = vbody.find("if not idle_moved:")
    # 前提只核**条件那一行**：D 支的返回文案里也写着"按向量中断全冻结"，
    # 拿整段切片去找那个词会被自己的文案喂饱 ⇒ 格子空转（§196 第一版就是这么错的）。
    dline = next((ln for ln in vbody.splitlines() if "idle_abs > 0" in ln), "")
    if di < 0 or ii < 0 or di > ii:
        bad.append("wedge_verdict 的 D 支（IDLE_HLT 冻结但 >0 ⇒ BSP 睡死）不在 idle 那一支之前 ⇒ 会把睡死读成关中断自旋（§196）")
    elif "按向量中断" not in dline:
        bad.append("D 支的条件没核『按向量中断全冻结』⇒ 会把中断风暴（run-068）误判成 BSP 中断源停了")
    # §202 的棘轮：探测判据的**两半必须一致**——`wait_ticks(base, N, …)` 与随后用作判据的
    # `.ticks >= M` 必须 N == M。§202 实测踩过：只把 want 改成 2、比较仍留 >=1，
    # 等于只拉长窗口没改判据，run-348 照样挂（got=1 rounds=2028 却 was_running=1）。
    # ADR-081 决策 2：lock-order.md 的"是否在中断上下文取"那一列是 never_taken_in_isr 的
    # **唯一依据来源**，表与代码必须逐把一致。填错就是新死锁（§205：对 TIMER/RUNQ 开窗会自死锁）。
    lo = (ROOT / "docs" / "architecture" / "lock-order.md").read_text(encoding="utf-8")
    tab = {}
    for ln in lo.splitlines():
        m = re.match(r"\| `(RANK_\w+)` \| (\d+) \|", ln)
        if m:
            tab[m.group(1)] = "**是**" in ln.rsplit("|", 2)[-2]
    ctor = {}
    for f in sorted((ROOT / "kernel" / "src").rglob("*.rs")):
        for ln in f.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.search(r"IrqSpinLock::(new_isr_taken|new)\(\s*(?:crate::sync::|sync::)?(RANK_\w+)", ln)
            if m:
                ctor[m.group(2)] = (m.group(1) == "new_isr_taken", f.name)
    if not tab or not ctor:
        bad.append("锁序表或构造点一个都没解析出来 ⇒ ADR-081 决策 2 那条对账是空转的")
    for rk, (isr, fname) in ctor.items():
        if rk not in tab:
            bad.append(f"{fname} 用了 {rk} 但锁序表里没有这一行 ⇒ 新锁必须先改表（硬约束 4）")
        elif tab[rk] != isr:
            want = "new_isr_taken" if tab[rk] else "new"
            bad.append(f"{rk} 表里说{'在中断上下文取' if tab[rk] else '不在中断上下文取'}，"
                       f"代码却用了 {'new_isr_taken' if isr else 'new'} ⇒ 应当用 {want}（ADR-081 决策 2，填错就是新死锁）")
    pairs = 0
    for f in sorted((ROOT / "kernel" / "src").rglob("*.rs")):
        ls = f.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, ln in enumerate(ls):
            mw = re.search(r"wait_ticks\([^,]+,\s*(\d+)\s*,", ln)
            if not mw:
                continue
            for j in range(i, min(i + 7, len(ls))):
                mg = re.search(r"\.ticks\s*>=\s*(\d+)\b", ls[j])
                if mg:
                    pairs += 1
                    if mw.group(1) != mg.group(1):
                        bad.append(
                            f"{f.name}:{j+1} 探测判据两半不一致：wait_ticks want={mw.group(1)} "
                            f"而 .ticks >= {mg.group(1)} ⇒ 改一半等于没改（§202 run-348 实测）")
                    break
    # 反空转：一个判据对都没扫到就说明这条闸没在核东西（正则写错/调用点搬家都会这样）
    if pairs == 0:
        bad.append("扫不到任何 wait_ticks 与 .ticks >= N 的判据对 ⇒ §202 那条棘轮是空转的")
    # §195 的等待/唤醒不变量（ADR-073 补记）。这几条都是实测买来的：
    # 旧 drain 是 load-then-store ⇒ 两个 drain 各自减一次 ⇒ ARMED 下溢成 u64::MAX（run-099 原始字节）；
    # 旧 take 只判 ARMED ⇒ SIGNALLED 那一支漏减；旧 drain 把 wake_task 的 false 用 let _ = 吞掉
    # ⇒ 唤醒提前投递给还没 Blocked 的等待者然后丢弃（run-096/100 的 B1）。
    sc = (ROOT / "kernel" / "src" / "sched.rs").read_text(encoding="utf-8")
    if "compare_exchange(st, TW_WOKEN" not in sc:
        bad.append("drain 不再用 CAS 消费等待槽 ⇒ 两个 drain 会各自减一次计数（§194 实测下溢成 u64::MAX）")
    if "let _ = wake_task(gidx, tok);" in sc:
        bad.append("drain 又把 wake_task 的失败吞掉了 ⇒ 提前投递的唤醒会被丢弃（§194 的 B1 成因）")
    if "TW_WAKE_MISS.fetch_add" not in sc:
        bad.append("wake 失败不再计数 ⇒ 那条路被走到也看不见（§195 靠它证自救支真的 firing）")
    if "fn sat_dec(" not in sc or "fetch_update" not in sc:
        bad.append("饱和减不见了 ⇒ ARMED/PENDING 双减会回绕成 u64::MAX，判别表会把计数坏了读成有等待者")
    if "TW_SIGNALLED => {" not in sc:
        bad.append("take 不再处理 SIGNALLED ⇒ 信号已置而调用方自己收走那一支漏减 ARMED/PENDING")
    # 两个等待入口必须同律：只修 wait_for_task 就是修了一半
    for fn in ("wait_for_task", "wait_for_proc"):
        m = re.search(rf"pub fn {fn}\(", sc)
        if m is None:
            bad.append(f"sched.rs 里找不到 {fn} ⇒ 这条对账不成立")
            continue
        nxt = re.search(r"^pub fn ", sc[m.end():], re.M)
        body = sc[m.end():m.end() + nxt.start()] if nxt else sc[m.end():]
        if "wait_slot_already_drained(slot, me, token)" not in body:
            bad.append(f"{fn} 少了 block_current 之后的再查 ⇒ 两个等待入口不同律（§195 修了一半）")
    labels = {label for _s, label, _w in WEDGE_SYMBOLS}
    for need in ("armed等待者", "待唤醒发布", "等待登记过", "等待被信号", "等待超时过", "等待槽满拒"):
        if need not in labels:
            bad.append(f"wedge 符号表里没有 {need} ⇒ 取证末尾那行会 KeyError，正好在挂死那一刻崩")
    return bad


def check_esp_partition() -> list[str]:
    """S2b 的接线对账：分区偏移视图 + 句柄身份 + 第二台仪器，三处的口号与依赖必须机器核。

    核五件：①内核读的文件名与本脚本 `ESP_FILE_NAME` 逐字；②`esp-probe` 的三条依赖都在
    （少了 `handles` 就编不出句柄表、少了 gpt/fat16 就没有被测物）；③`esp-probe` 在挂盘名单里
    ——**这一条是实测买来的**：名单是文本交集不跟 cargo 依赖闭包走，漏了它口 1 的盘不挂，
    `t_gpt` 以 `Io(NotSettled)` 红，而成因看起来像驱动坏了；④偏移真的进了句柄身份
    （`FileObj` 有 `part`、`read` 真的按它重建视图）；⑤越界有**自己的**错误码与 tag。
    """
    bad: list[str] = []
    k = ROOT / "kernel" / "src" / "ktests" / "esp.rs"
    if not k.exists():
        return ["缺 kernel/src/ktests/esp.rs：S2b 的被测物不在位，整段对账不成立"]
    ks = k.read_text(encoding="utf-8")
    m = re.search(r'const WANT: &str = "([^"]+)";', ks)
    if m is None:
        bad.append("ktests/esp.rs 里找不到 `const WANT`（挪进函数体了？两处各写一份就会分家）")
    elif m.group(1) != ESP_FILE_NAME:
        bad.append(f"读的文件名：内核={m.group(1)} 本脚本 ESP_FILE_NAME={ESP_FILE_NAME}")
    feats = (ROOT / "kernel" / "Cargo.toml").read_text(encoding="utf-8")
    fm = re.search(r"^esp-probe = \[(.*?)\]", feats, re.M)
    if fm is None:
        bad.append("Cargo.toml 的 [features] 里没有 esp-probe")
    else:
        deps = re.findall(r'"([^"]+)"', fm.group(1))
        for need in ("gpt-probe", "fat16-probe", "handles"):
            if need not in deps:
                bad.append(f"esp-probe 必须依赖 {need}（否则那一档编不出被测物），实际={deps}")
    if not ESP_FEATURES <= GPT_FEATURES:
        bad.append(f"esp-probe 不在 GPT_FEATURES 里 ⇒ 口 1 的夹具盘不挂，t_gpt 会以 Io(NotSettled) 红"
                   f"（名单是文本交集，不跟 cargo 依赖闭包走）：{sorted(GPT_FEATURES)}")
    mods = (ROOT / "kernel" / "src" / "ktests" / "mod.rs").read_text(encoding="utf-8")
    if '#[cfg(feature = "esp-probe")]\nmod esp;' not in mods.replace("\r\n", "\n"):
        bad.append("ktests/mod.rs 没有按 esp-probe 门控注册 mod esp ⇒ 用例进不了 .ktests 表")
    h = (ROOT / "kernel" / "src" / "handle.rs").read_text(encoding="utf-8")
    if "pub part: Option<Partition>" not in h:
        bad.append("handle.rs 的 FileObj 没有 `pub part: Option<Partition>` ⇒ 偏移没进句柄身份，"
                   "read 重建整盘之后偏移就丢了（S2b 的裁决是『偏移进身份』）")
    if "PartitionView { inner: &disk, part }" not in h:
        bad.append("handle::read 没有按票里的分区重建 PartitionView ⇒ 身份带了偏移也没人用")
    v = (ROOT / "kernel" / "src" / "filesystem" / "vfs.rs").read_text(encoding="utf-8")
    if "BeyondPartition" not in v or "越出分区" not in v:
        bad.append("vfs.rs 缺 BeyondPartition 变体或它的 tag ⇒ 越界与形状错合成一个码，负样本分不开")
    if "pub struct PartitionView" not in v:
        bad.append("vfs.rs 缺 PartitionView ⇒ 偏移视图不在位")
    return bad


def check_fat32_ports() -> list[str]:
    """两处各写死一份口号，就必须有机器对账：内核的 `FAT_PORT_A`/`FAT_PORT_B` 与本脚本的 `FAT_PORTS`。

    这一格防的是一件很具体的事：内核注释写着"由 tools/aurora.py 的 FAT_PORTS 定"，而脚本里
    根本没有那个名字的时候，注释就成了悬空引用，两侧可以各挂各的盘而没人报错——串口只会说
    "挂载失败"，看起来像驱动坏了，其实是接线断了（本轮开工时仓库里就是这个状态）。
    顺带把"夹具在位""特性名在 Cargo 里存在""注入变体依赖探针"三件一起判掉：
    任何一处断了，红都发生在跑之前，而不是跑完之后没人知道少了什么。
    """
    bad: list[str] = []
    src = (ROOT / "kernel" / "src" / "ktests" / "fs.rs").read_text(encoding="utf-8")
    for tag, const in (("卷A", "FAT_PORT_A"), ("卷B", "FAT_PORT_B")):
        m = re.search(rf"const {const}: u8 = (\d+);", src)
        if m is None:
            bad.append(f"ktests/fs.rs 里找不到模块层的 `const {const}`（挪回函数体里了？③ 也要读同一块盘，两处各写一份就会分家）")
            continue
        port = int(m.group(1))
        if port not in FAT_PORTS:
            bad.append(f"{tag}: 内核用口 {port}，本脚本 FAT_PORTS 只有 {sorted(FAT_PORTS)}")
        elif FAT_PORTS[port] not in FAT_EXPECT:
            bad.append(f"{tag}: 口 {port} 挂的 `{FAT_PORTS[port]}` 没有指纹登记")
    if len(set(FAT_PORTS.values())) != len(FAT_PORTS):
        bad.append("FAT_PORTS 里两块卷重名：同一份夹具不可能同时充当两个判型角色")
    for name in set(FAT_PORTS.values()):
        if not FAT_ZZ[name].exists():
            bad.append(f"夹具源缺失：{FAT_ZZ[name].relative_to(ROOT)}")
    # 口位不能与已有的盘撞：口 0 是引导 ESP（也是 MBR 那一格的证人），口 2 是 scratch
    # （`if=ide,index=2` 实测落在 AHCI 口 2）。撞了就是"看着挂上了，其实换了块盘"那种红。
    taken = {0: "引导 ESP/MBR", 2: "scratch 130 GiB"}
    for port, name in sorted(FAT_PORTS.items()):
        if port in taken:
            bad.append(f"口 {port} 已被 {taken[port]} 占用，却又要挂 {name}")
    # W4 S1（ADR-078 决策 7）：GPT 夹具盘的口号同样两处各写一份，必须机器对账。
    # 它**不能**撞引导盘（口 0）——负样本的全部意义就在于"改的是一块固件不碰的盘"，
    # 撞上去就回到实测过的那个死路：EDK2 用备份表把主表修回去，注入到不了内核。
    gsrc = (ROOT / "kernel" / "src" / "ktests" / "gpt.rs").read_text(encoding="utf-8")
    gm = re.search(r"const GPT_FIX_PORT: u8 = (\d+);", gsrc)
    if gm is None:
        bad.append("ktests/gpt.rs 里找不到模块层的 `const GPT_FIX_PORT`（挪进函数体了？两处各写一份就会分家）")
    elif int(gm.group(1)) != GPT_FIX_PORT:
        bad.append(f"GPT 夹具盘口号：内核用 {gm.group(1)}，本脚本 GPT_FIX_PORT={GPT_FIX_PORT}")
    if GPT_FIX_PORT in taken or GPT_FIX_PORT in FAT_PORTS:
        bad.append(f"GPT 夹具盘口 {GPT_FIX_PORT} 与引导盘/scratch/FAT 卷撞了 ⇒ 改它会动到别人")
    gfeats = (ROOT / "kernel" / "Cargo.toml").read_text(encoding="utf-8")
    for f in sorted(GPT_FEATURES):
        if not re.search(rf"^{f} = ", gfeats, re.M):
            bad.append(f"Cargo.toml 的 [features] 里没有 {f}，本脚本却按它挂 GPT 夹具盘")
    if not (ROOT / "tools" / "make_gpt_disk.py").exists():
        bad.append("缺 tools/make_gpt_disk.py：GPT 夹具盘的配方不在位")
    # 上界常量与宿主机逐字对账（ADR-078 决策 4 末条）。放在这道门禁里而不是新开第 18 道：
    # 它已经是"存储夹具与口号"那一格，GPT 夹具盘的口号/特性/注入反面检查都在上面。
    bad += check_gpt_bounds()
    # 无锁现场记录表（§181）的接线对账：同一格"存储夹具与口号"，不新开第 18 道门禁。
    bad += check_fatal_record()
    # S2b：分区偏移视图 + 句柄身份 + 第二台仪器的接线对账（同一格，不新开第 18 道门禁）。
    bad += check_esp_partition()
    # 挂死判别仪器读的符号逐个回源文件核（同一格，不新开第 18 道门禁）。
    bad += check_wedge_probe()

    feats = (ROOT / "kernel" / "Cargo.toml").read_text(encoding="utf-8")
    for f in sorted(FAT_FEATURES):
        if not re.search(rf"^{f} = ", feats, re.M):
            bad.append(f"Cargo.toml 的 [features] 里没有 {f}，本脚本却按它挂盘")
    # 注入变体必须依赖探针：否则 `--features fault-fat32-tail` 会编出一个不带 t_fat32 的内核，
    # 那条负样本永远"没有红"——不是判据不成立，而是被测的东西根本没进镜像。
    # ③（`fat32-exec`）同理：它复用 ① 的挂载与解析，依赖断了就是一条独立实现的孤儿用例；
    # P7 之后它还依赖 `handles`（句柄表）——**判据是"列表里必须含 fat32-probe"**，不是"只有它"。
    for f in sorted(FAT_FEATURES - {"fat32-probe"}):
        m = re.search(rf'^{f} = \[(.*?)\]', feats, re.M)
        deps = re.findall(r'"([^"]+)"', m.group(1)) if m else []
        if "fat32-probe" not in deps:
            bad.append(f"{f} 必须依赖 fat32-probe（否则它是没有探针的孤儿用例），实际={deps}")
    # 探针与 ③ 的代码在 `ktests/fs.rs`（用例本体），注入的落点在 `fat32.rs`（被测代码里那一行）。
    # 两条查法不能互换：注入特性不新写用例，只把解析器里那个 `cfg!` 翻开。
    for f in sorted(FAT_DISK_FEATURES):
        if f'feature = "{f}"' not in src:
            bad.append(f'ktests/fs.rs 里没有 `feature = "{f}"`：这条特性编不出被调用的用例')
    fat_src = (ROOT / "kernel" / "src" / "filesystem" / "fat32.rs").read_text(encoding="utf-8")
    for f in sorted(FAT_FAULT_FEATURES):
        if f'feature = "{f}"' not in fat_src:
            bad.append(f"fat32.rs 里没有 `feature = \"{f}\"`：注入点被删了，那条负样本是空转")
    # 宿主机侧注入查的是**反面**：这两个名字既不许是 cargo 特性，也不许在内核源码里有落点。
    # 它们的全部意义在于"负样本用的就是正向那一跑的同一个 ELF，只有盘不同"；做成特性会让
    # crate disambiguator 跟着变（实测 .text 有 31 万格不同，虽然归一化后指令多重集相同），
    # 而在内核里加 cfg 开关更是直接把负样本换成了另一类东西——两种退化的判定表都照样绿。
    for f in sorted(FAT_HOST_FAULTS):
        if re.search(rf"^{f} = ", feats, re.M):
            bad.append(f"Cargo.toml 里有 {f}：宿主机侧注入不该是构建变量（改了它 ELF 就变了，"
                       "「只有盘不同」这句话就不再成立）")
        for rel, text in (("kernel/src/ktests/fs.rs", src), ("kernel/src/filesystem/fat32.rs", fat_src)):
            if f'feature = "{f}"' in text:
                bad.append(f"{rel} 里出现了 `feature = \"{f}\"`：这是宿主机侧注入，内核不该有落点")
        if FAT_HOST_FAULTS[f] not in set(FAT_PORTS.values()):
            bad.append(f"{f} 要改的卷 {FAT_HOST_FAULTS[f]} 没挂在任何口上 ⇒ 改了也没人读")
            continue        # 卷名不在 FAT_ZZ 里，再往下走是 KeyError 而不是红
        # 注入点必须**现在**就定位得出来：门禁里跑一遍 planner，与跑那一跑用的是同一个函数。
        # 夹具重建之后图案没了、或高半本来就是 0，红要落在这里，而不是落在一行看不出成因的 FAIL 上。
        try:
            name, off, old, new = fat_host_fault_plan(f)
        except ValueError as e:
            bad.append(f"{f} 注入点定位不成：{e}")
            continue
        if old == new:
            bad.append(f"{f}: 现值与新值都是 {old.hex()} ⇒ 这条注入是空转")
        if not 0 <= off < FAT_EXPECT[name][0]:
            bad.append(f"{f}: 算出的镜像偏移 {off} 不在 {name} 的 {FAT_EXPECT[name][0]} 字节之内")

    # GPT 那六条宿主机侧注入查同样的**反面**，外加"现在就定位得出来"（与 FAT 那六行同一纪律）。
    gpt_ktest = (ROOT / "kernel" / "src" / "ktests" / "gpt.rs").read_text(encoding="utf-8")
    gpt_mod = (ROOT / "kernel" / "src" / "filesystem" / "gpt.rs").read_text(encoding="utf-8")
    for f in sorted(GPT_HOST_FAULTS):
        if re.search(rf"^{f} = ", feats, re.M):
            bad.append(f"Cargo.toml 里有 {f}：宿主机侧注入不该是构建变量（改了它 ELF 就变了，"
                       "「只有盘不同」这句话就不再成立）")
        for rel, text in (("kernel/src/ktests/gpt.rs", gpt_ktest), ("kernel/src/filesystem/gpt.rs", gpt_mod)):
            if f'feature = "{f}"' in text:
                bad.append(f"{rel} 里出现了 `feature = \"{f}\"`：这是宿主机侧注入，内核不该有落点")
        try:
            want = gpt_fault_image(f)
            edits, _seal = gpt_host_fault_plan(f)
        except ValueError as e:
            bad.append(f"{f} 注入点定位不成：{e}")
            continue
        for at, old, new in edits:
            if old == new:
                bad.append(f"{f}: 现值与新值都是 {old.hex()} ⇒ 这条注入是空转")
            if not 0 <= at < GPT_FIX_BYTES:
                bad.append(f"{f}: 算出的偏移 {at} 不在夹具盘的 {GPT_FIX_BYTES} 字节之内")
        if want == gpt_recipe_bytes():
            bad.append(f"{f}: 计划改完之后与配方一字节不差 ⇒ 这条注入是空转")
    # 做不成改盘的那一条也要有机器看着：不许有人把它悄悄加回可注入表（那会多一行永远绿的判定），
    # 也不许把它做成 cargo 特性绕过"只有盘不同"这条纪律。
    for f, why in sorted(GPT_FAULT_UNDELIVERABLE.items()):
        if f in GPT_HOST_FAULTS:
            bad.append(f"{f} 实测做不成改盘注入（{why}），却又出现在 GPT_HOST_FAULTS 里")
        if re.search(rf"^{f} = ", feats, re.M):
            bad.append(f"Cargo.toml 里有 {f}：做不成改盘就不许改成构建变量绕过纪律")
        try:
            gpt_host_fault_plan(f)
            bad.append(f"{f} 的 planner 竟然定位成功了 ⇒ 与『做不成』的账不符，要重新量")
        except ValueError:
            pass

    # W4 S2a：FAT16 合成整卷的配方常数与内核用例里的同名常数逐字对账。
    # 两处各写一份而不核对正是手册 V8 点名的形状：改了配方没改用例，红会落在"判据不成立"上，
    # 而不是落在"夹具与期望分家"上——后者一眼看得出是谁的错。
    f16_ktest = (ROOT / "kernel" / "src" / "ktests" / "fat16.rs").read_text(encoding="utf-8")
    f16_recipe = (ROOT / "tools" / "make_fat16_mem.py").read_text(encoding="utf-8")
    for name in ("RESERVED", "FAT_COUNT", "SPF16", "ROOT_ENTRIES", "ROOT_SECTORS",
                 "DATA_START", "DATA_CLUSTERS", "TOTAL_SECTORS", "VOL_BYTES", "FILE_SIZE"):
        kr = re.search(rf"^const {name}: usize = ([^;]+);", f16_ktest, re.M)
        pr = re.search(rf"^{name} = ([^\n#]+)", f16_recipe, re.M)
        if kr is None or pr is None:
            bad.append(f"FAT16 常数 {name} 没在两边都找到（改名/挪走了？这条对账就不核它了）")
            continue
        kv = kr.group(1).replace("_", "")
        pv = pr.group(1).strip().replace("_", "")
        # 内核那边允许写成算式（如 ROOT_ENTRIES * 32 / SECTOR_BYTES），只在两边都是纯数字时逐字比；
        # 算式那几格由"跑起来对不对"担保（判据里它们的值都进了串口，宿主机逐格对账）。
        if kv.isdigit() and pv.isdigit() and int(kv) != int(pv):
            bad.append(f"FAT16 常数 {name}：内核={kv} 配方={pv}")
    for f in sorted(FAT16_FEATURES):
        if not re.search(rf"^{f} = ", feats, re.M):
            bad.append(f"Cargo.toml 的 [features] 里没有 {f}，本脚本却按它现算 FAT16 夹具")
    if not FAT16_MEM_SCRIPT.exists():
        bad.append("缺 tools/make_fat16_mem.py：FAT16 合成卷的配方不在位")

    # 内核读哪几个文件 = 这台仪器核哪几个文件。两处各写一遍就会分家，而分家的表现是
    # "对账核的是另一个对象"——那种绿比红更贵。名字表按 want_a 再 want_b 的顺序比。
    want_names = re.findall(r'Want \{ name: "([^"]+)"', src)
    declared = list(FAT_READ_NAMES["A"] + FAT_READ_NAMES["B"])
    if want_names != declared:
        bad.append(f"ktests/fs.rs 的 want 表读的名字是 {want_names}，本脚本 FAT_READ_NAMES 核的是 {declared}")
    for n in FAT_READ_NAMES["MEM"]:
        if f'vol.open("{n}")' not in src:
            bad.append(f'内存卷那一本账里没有 `vol.open("{n}")`：这张表核的名字用例不查它')
    # ③ 读的就是 34 行那张表里的同一个对象；而它打的每一行都是宿主机正则的锚点——
    # 锚点写坏了的表现是"这一行没读到"而不是"对账不符"，所以要静态确认锚点还在源码里。
    if 'vol.open("HELLO.ELF")' not in src:
        bad.append('③ 没有 `vol.open("HELLO.ELF")`：它读的名字与 FAT_READ_NAMES 不是同一个对象')
    # T0.1：`elfload: magic=` 这句在 `t_elf_load_run`（ktests/elf.rs），其余在 ktests/fs.rs。
    # 锚点必须去它实际所在的那个文件找；只改读的文件、不改判据强度。
    elf_src = (ROOT / "kernel" / "src" / "ktests" / "elf.rs").read_text(encoding="utf-8")
    for anchor in ("elfdisk: 目录 大小=", "elfdisk: 段", "elfdisk: 跑后 entry=",
                   "elfdisk: 负格 元数据说大=", "| 收尾 终止=", "elfload: magic=",
                   "elfdisk: 尾格溢出 已喂=", "elfdisk: 判据 同长=",
                   "fat32: 判据 引导盘被拒=", "读不成 {:?}"):
        if anchor not in src and anchor not in elf_src:
            bad.append(f"串口锚点 `{anchor}` 不在 ktests/fs.rs 或 ktests/elf.rs 里了：`check_fat32_exec` 的那条正则读成空，"
                       "第 36 行会报缺行而不是报不符（改日志格式要两处一起改）")
    # 第 39 行的证人读的是 `ChainEndsLate` 的 **Debug 字段序**（bytes/size/cluster/next）。
    # 那个序在 fat32.rs 的枚举声明里，改它等于改串口原文 ⇒ 正则读成空、报"缺行"而不是"不符"。
    if "ChainEndsLate { bytes: usize, size: u32, cluster: u32, next: u32 }" not in fat_src:
        bad.append("fat32.rs 里 ChainEndsLate 的字段序变了：`FAT_LATE_RE` 按 bytes/size/cluster/next "
                   "读那四个数，改序要两处一起改（否则第 39 行报缺行，看着像用例没跑）")
    # 走链的上界：内核有界、仪器也必须同样有界，否则"两边都有界"这句话里只有一半成立。
    m = re.search(r"pub const MAX_CLUSTERS_WALKED: u32 = ([\d_]+);", fat_src)
    if m is None:
        bad.append("fat32.rs 里找不到 MAX_CLUSTERS_WALKED（本仪器的界与它靠这一行对账）")
    elif int(m.group(1).replace("_", "")) != FAT_MAX_WALKED:
        bad.append(f"走链上界不一致：内核={m.group(1)} 本脚本={FAT_MAX_WALKED}")
    if not FAT_MEM_SCRIPT.exists():
        bad.append(f"内存卷配方缺失：{FAT_MEM_SCRIPT.relative_to(ROOT)}（那块卷不在仓库里，编不出就等于这个变体不存在）")
    if len(FAT_MEM_EXPECT[1]) != 64 or len(FAT_EXPECT) != len(FAT_PORTS):
        bad.append("夹具指纹登记得不完整：每块卷都要有字节数与 64 位十六进制的 sha256")
    return bad


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
    global PKG_DIRTY
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
    # 改包注入的寿命必须是一跑：包在引导镜像里，而镜像**不像 GPT 夹具那样每跑重造**。
    # 不强制重造的话下一跑会复用改过的盘 ⇒ 第二条注入读到的是第一条留下的坏魔数，
    # 两条都报 BadHeader，而第二条明明改的是载荷（**实测撞过这个形状**）。
    if PKG_DIRTY:
        fresh = False
    if not fresh:
        do_image(features)
        PKG_DIRTY = False


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


# 每一跑的留档序号（见 do_run 里的 run-NNN.log）。
# **跨进程必须接着数**：原来是进程内从 0 起，于是每次单独 `run` 都写 run-001.log，
# 把上一张矩阵同号那一跑的留档覆盖掉（§193 实测丢了一次）。取证文件名跟着这个号走，
# 号一撞现场也跟着撞——而"引数必须连时间/变体一起引"那条纪律只能事后补救，不能防覆盖。
def _run_seq_start() -> int:
    n = 0
    for f in BUILD.glob("run-*.log"):
        m = re.fullmatch(r"run-(\d+)\.log", f.name)
        if m:
            n = max(n, int(m.group(1)))
    return n


RUN_SEQ = _run_seq_start()


def qmp_snapshot(port: int, cmds: list[str]) -> str:
    """P2.5 取证通道：向 QMP 发 `human-monitor-command`，把 HMP 原文取回来。

    为什么要有它：挂死那一跑唯一的缺陷是"杀进程之前什么都没看到"——CPU 停在哪个函数
    只有当场问机器才知道。静态排查已排除无界忙等与锁等待（§107/§108），剩下的候选
    （故障路径再故障走到 cli+hlt、或机器级停顿）用串口原文分不开。
    只在 `AURORA_QEMU_QMP=<port>` 时启用：默认跑的命令行一个字符都不变。
    """
    import json
    import socket

    out = []
    nl = chr(10)
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
    except OSError as e:
        return "QMP 连不上（port=" + str(port) + "）：" + repr(e)
    f = s.makefile("rw", encoding="utf-8")
    try:
        out.append("# greeting: " + f.readline().strip())
        f.write(json.dumps({"execute": "qmp_capabilities"}) + chr(13) + chr(10)); f.flush()
        out.append("# caps: " + f.readline().strip())
        for c in cmds:
            req = {"execute": "human-monitor-command", "arguments": {"command-line": c}}
            f.write(json.dumps(req) + chr(13) + chr(10)); f.flush()
            line = f.readline()
            try:
                body = json.loads(line).get("return", line)
                txt = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)[:4000]
                out.append("### " + c + nl + txt)
            except json.JSONDecodeError:
                out.append("### " + c + nl + line)
    except OSError as e:
        out.append("# QMP 读取中断：" + repr(e))
    finally:
        f.close()
        s.close()
    return nl.join(out)

def stall_report(log: str, elapsed: float, budget: int) -> str:
    """判定级停住（HANG/NOBOOT）的现场：停在哪条用例之后、有没有跑完、用时是否恰好等于预算。

    为什么要有它：两次间歇挂的**停住点不同**（一次在 `t_q2_workload_slots` 之前、一次在
    `t_vmo_syscalls` 之前），而归档里只有串口原文——每次都要手工 grep 才知道停在哪，
    于是"下一跑绿了"就被当成修好了。稀有故障要买确定性而不是买跑数：这条把停住点变成
    每次自动留痕的读数，并与归档同号存成 `run-NNN.stall.txt`。
    """
    # 两种 tag 都要收：成功是 `[test] … -> ok`，失败是 `[FAIL] … -> failed`。
    # 只收 `[test]` 的话"红过的用例"永远是空——那一格就成了空转（本轮自查抓到）。
    tests = re.findall(r"\[(?:test|FAIL)\] (0x[0-9a-f]+) (\w+) -> (\w+)", log)
    total = re.search(r"ktests: total=(\d+) passed=(\d+) failed=(\d+)", log)
    out = [f"判定级停住现场：用时 {elapsed:.1f}s / 预算 {budget}s"
           + ("（**恰好等于预算** ⇒ 先怀疑预算与宿主负载，再怀疑 guest 死锁）"
              if elapsed >= budget * 0.99 else "")]
    out.append(f"跑过用例 {len(tests)} 条；最后一条 = "
               + (f"{tests[-1][1]} -> {tests[-1][2]}（序号 {tests[-1][0]}）" if tests
                  else "无（连一条用例都没跑到）"))
    out.append(f"ktests 收尾行 = {'有: ' + total.group(0) if total else '**无**（没跑完）'}；"
               f"退出行 = {'有' if 'qemu-exit' in log else '**无**'}")
    tail = [l.strip() for l in log.splitlines() if l.strip()]
    out.append("串口最后一行 = " + (tail[-1][:160] if tail else "（空）"))
    reds = [f"{n}->{r}" for _s, n, r in tests if r != "ok"]
    out.append("红过的用例 = " + (", ".join(reds) if reds else "无"))
    return "\n".join(out)


# ---- 无锁现场记录表的宿主机读回（W4 猎间歇挂，BACKLOG §181）--------------------------
# 内核 `crash::FATAL_RECORD` 是"每 CPU 八个 u64"的一张表，致命/崩溃出口在碰**串口与块设备
# 之前**往里写。它存在的理由很具体：抓到的那次挂死，RIP 就落在 `crash::dump_site` 里，
# 而串口上既没有 `[fatal]` 也没有 `crash:` 那一行——那条路径上两个可疑卡点（行锁、写盘）
# 恰好都在"把现场说出来"之前，所以现场只能靠内存读回来，不能靠日志。
# 字段顺序因此是**接口**：下面这份名字表与 `crash.rs` 的 `FR_*` 下标由 `check-fat32-ports`
# 逐字对账；表自己会不会咬由 `fatal-record-stall` 那一跑端到端证（见 fatal_selfcheck）。
FATAL_FIELD_NAMES = ["seq", "stage", "vector", "err", "rip", "rsp", "cr2", "aux"]
FATAL_STAGE_NAMES = {
    0: "从没进过致命/崩溃出口",
    1: "致命入口（任何串口写之前）",
    2: "进 dump_site（走栈/取日志环/写盘之前）",
    3: "write_crash 返回之后（aux=成功槽号+1，0=没写进去）",
    4: "exit::finish 写 qemu-exit 之前（aux=Code 原值）",
}


def fatalrec_boot_facts(log: str) -> tuple[int, int, int, int] | None:
    """从启动那一行 `fatalrec: 物理=… cpu数=… 每cpu字段=… 字节=…` 取出读回所需的四个数。

    这四个数**全部来自内核**，宿主机不写死任何一格：内核改了布局而脚本没跟上时，
    这里读到的字节数与解码用的字段数会当场不一致（fatalrec_readback 会报出来）。
    """
    m = re.search(r"fatalrec: 物理=0x([0-9a-f]+) cpu数=(\d+) 每cpu字段=(\d+) 字节=(\d+)", log)
    if m is None:
        return None
    return int(m.group(1), 16), int(m.group(2)), int(m.group(3)), int(m.group(4))


def qmp_pmemsave(port: int, addr: int, size: int, path: Path) -> str:
    """QMP `pmemsave`：把 guest **物理**内存的一段写进宿主机文件。空串 = 成功，否则是成因。

    用物理地址不是偷懒：`xp`/`pmemsave` 都只认物理地址，而内核那张表住在高半区的虚拟地址里。
    桥是内核自己搭的——`crash::record_phys()` 走 `mm::phys_of` 推出物理地址并由启动那行说出来。
    """
    import json
    import socket

    req = {"execute": "pmemsave",
           "arguments": {"val": addr, "size": size, "filename": str(path).replace("\\", "/")}}
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
    except OSError as e:
        return "QMP 连不上（port=" + str(port) + "）：" + repr(e)
    f = s.makefile("rw", encoding="utf-8")
    try:
        f.readline()  # greeting
        f.write(json.dumps({"execute": "qmp_capabilities"}) + "\r\n"); f.flush()
        f.readline()
        f.write(json.dumps(req) + "\r\n"); f.flush()
        while True:
            line = f.readline()
            if not line:
                return "QMP 没有回话（连接断开）"
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "error" in msg:
                return "pmemsave 被拒：" + json.dumps(msg["error"], ensure_ascii=False)
            if msg.get("return") is not None:
                return ""
    except OSError as e:
        return "QMP 读取中断：" + repr(e)
    finally:
        f.close()
        s.close()


def fatalrec_readback(port: int, log: str, build_dir: Path, seq: int) -> tuple[str, list[list[int]]]:
    """挂死那一跑的现场读回。返回（给人看的文本，逐槽解码）；解码为空 ⇒ 一步都没成。

    防空转是这段的主判据：**任何一步失败都要说出失败在哪一步**，不许返回空表让调用方
    以为"读回来是全零"。全零与"根本没读到"是两件事——前者是证据，后者是量具坏了。
    """
    facts = fatalrec_boot_facts(log)
    if facts is None:
        return ("fatalrec: 串口里没有 `fatalrec: 物理=…` 那一行 ⇒ 这一跑的 ELF 里没有这张表"
                "（旧内核？页表接管之前就挂了？），读回整段跳过", [])
    phys, cpus, fields, nbytes = facts
    if fields != len(FATAL_FIELD_NAMES):
        return (f"fatalrec: 内核说每槽 {fields} 格，本脚本 FATAL_FIELD_NAMES 有 {len(FATAL_FIELD_NAMES)} 个名字"
                " ⇒ 布局分家，解出来的字段名会整体错位，不读", [])
    if nbytes != cpus * fields * 8:
        return (f"fatalrec: 内核说 {nbytes} 字节，按 cpu数{cpus}×字段{fields}×8 应是 {cpus * fields * 8}"
                " ⇒ 它自己就不自洽，不读", [])
    # 文件名带跑号：一张矩阵里可能红不止一行，而固定名会让后一次挂死覆盖前一次的证据
    # （`run-NNN.log` 撞过一次同族的坑，见 BACKLOG 关于 run-001 那条）。
    blob = build_dir / f"fatalrec-run-{seq:03d}.bin"
    out = [f"fatalrec: 读回 物理={hex(phys)} cpu数={cpus} 每cpu字段={fields} 字节={nbytes}"]
    if blob.exists():
        blob.unlink()
    err = qmp_pmemsave(port, phys, nbytes, blob)
    if err:
        return "\n".join(out) + "\nfatalrec: 读回失败 " + err, []
    data = blob.read_bytes()
    if len(data) != nbytes:
        return "\n".join(out) + f"\nfatalrec: pmemsave 只给出 {len(data)} 字节（要 {nbytes}）", []
    vals = list(struct.unpack("<" + "Q" * (cpus * fields), data))
    table = [vals[c * fields:(c + 1) * fields] for c in range(cpus)]
    out.append("fatalrec: 逐槽（只打非全零的槽；全零 = 那颗 CPU 从没进过致命/崩溃出口）")
    for c, row in enumerate(table):
        if not any(row):
            continue
        stage = row[FATAL_FIELD_NAMES.index("stage")]
        cells = " ".join(f"{FATAL_FIELD_NAMES[i]}={row[i]:#x}" for i in range(fields))
        out.append(f"  cpu{c}: {cells}  => {FATAL_STAGE_NAMES.get(stage, '**未知的 stage**（内核与本脚本分家了）')}")
    return "\n".join(out), table


DUMP_STALL_MARK = "dumpsite: 注入 停在写盘之前"


def fatal_selfcheck(log: str, table: list[list[int]]) -> tuple[list[str], str]:
    """两种取证自查的判据（都不在矩阵里常挂：两档各自期望 HANG）。返回（红行，绿的那句话）。

    模式一 `fatal-record-stall`：合成五个 magic。证明**内核算出的物理地址对、字段顺序对、
    原子写真的落了内存**三件事同时成立。找法用"哪一槽五个 magic 全对上"，不写死 cpu0：
    用例在哪颗 CPU 上跑由调度决定。
    模式二 `fatal-record-dump-stall`：**真 `#PF(14)`** 的现场（CPU 给的 rip/cr2/err）+
    "停在写盘之前"这个进度点。证明的是这张表能在**§180 那个形状**里被读一次：
    串口 `[fatal]` 那条与内存里那一槽逐格一致，且那一槽停在 `stage=2`（等不到 `stage=3`）。
    这一模式还多一格**串口自洽**：`oops: 故意读 <addr>` 声称的地址必须等于 CPU 报的 `cr2`，
    不等就说明这次故障不是那次 deliberate 读造成的 ⇒ 实验本身不成立（不许当绿）。
    两种都不在（普通挂死）⇒ 返回空，只留证据不判对错。
    """
    if not table:
        return [], ""
    if DUMP_STALL_MARK in log:
        mo = re.search(r"oops: 故意读 (0x[0-9a-f]+)", log)
        mf = re.search(r"\[fatal\] (?:0x[0-9a-f]+ )?unexpected #PF rip=(0x[0-9a-f]+) "
                       r"cr2=(0x[0-9a-f]+) err=(0x[0-9a-f]+) cpu_cpl=0", log)
        if mo is None or mf is None:
            return ([f"dump-stall 自查：串口里有 `{DUMP_STALL_MARK}` 但 "
                     f"{'`oops: 故意读` 那一行' if mo is None else '`[fatal] unexpected #PF` 那一行'}"
                     " 解析不出来 ⇒ 这一跑的证据不可用（不许静默当绿）"], "")
        want_cr2 = int(mo.group(1), 16)
        if want_cr2 != int(mf.group(2), 16):
            return ([f"dump-stall 自查：用例声称读 {hex(want_cr2)}，而 CPU 报的 cr2 是 "
                     f"{hex(int(mf.group(2), 16))} ⇒ 这次 #PF 不是那次 deliberate 读，实验不成立"], "")
        want = {"vector": 14, "stage": 2, "rip": int(mf.group(1), 16),
                "cr2": want_cr2, "err": int(mf.group(3), 16)}
        hits = [c for c, row in enumerate(table)
                if all(v == row[FATAL_FIELD_NAMES.index(k)] for k, v in want.items())
                and row[FATAL_FIELD_NAMES.index("seq")] >= 2]
        if len(hits) == 1:
            return ([], f"dump-stall 自查: 绿（真 #PF(14) 的现场由内存读回，与串口 [fatal] 那条"
                    f"逐格一致：cpu{hits[0]} rip={hex(want['rip'])} cr2={hex(want_cr2)} "
                    f"err={hex(want['err'])}，且停在 stage=2=进 dump_site、写盘没回来）")
        detail = "; ".join(f"cpu{c}:{' '.join(FATAL_FIELD_NAMES[i] + '=' + hex(row[i]) for i in range(len(row)))}"
                           for c, row in enumerate(table) if any(row)) or "全表零"
        return ([f"dump-stall 自查：内存里对不上串口那条真 #PF 现场（要 vector=14 stage=2 "
                 f"rip={hex(want['rip'])} cr2={hex(want_cr2)} err={hex(want['err'])}），"
                 f"命中 {len(hits)} 槽；内存实况={detail}"], "")
    if "fatalrec: 自查" not in log:
        return [], ""
    m = re.search(r"fatalrec: 自查 故意停住 期待宿主机读回 向量=(\d+) 错误码=(\d+) "
                  r"rip=0x([0-9a-f]+) rsp=0x([0-9a-f]+) cr2=0x([0-9a-f]+) stage=(\d+)", log)
    if m is None:
        return ["fatalrec 自查：串口里有 `fatalrec: 自查` 但那一行解析不出来 ⇒ 口号分家，自查不成立"], ""
    want = {"vector": int(m.group(1)), "err": int(m.group(2)), "rip": int(m.group(3), 16),
            "rsp": int(m.group(4), 16), "cr2": int(m.group(5), 16), "stage": int(m.group(6))}
    hits = []
    for c, row in enumerate(table):
        got = dict(zip(FATAL_FIELD_NAMES, row))
        if all(int(want[k]) == got[k] for k in want):
            hits.append(c)
    if not hits:
        return ["fatalrec 自查：内存里**没有**任何一槽带着串口上那五个 magic ⇒ 表没写进去，"
                "或物理地址/字段顺序错了（这一跑的证据不可用）"], ""
    if len(hits) > 1:
        return [f"fatalrec 自查：{len(hits)} 槽（cpu{hits}）同时带着同一份 magic ⇒ 分槽算错了"], ""
    return [], "fatalrec 自查: 绿（内存里那一槽与串口上那五个 magic 逐格对上）"


def data_sym(elf: Path, segs: tuple[str, ...]) -> tuple[int, int, str] | None:
    """按 mangle 尾部找**数据**符号（STT_OBJECT），返回 (va, size, 原名)。

    与 `func_syms` 同一份 ELF 解析（`_elf_sections`），只是类型过滤换成 OBJECT。
    `st_size` 直接给出字节数 ⇒ **元素个数不用手写**（手写过的每一次数错的都会静默错位）。
    私有 static 被 LLVM 内部化之后带 `.llvm.<hash>` 后缀，所以允许尾部跟一段 `.llvm.`；
    除此之外必须**正好结束**，否则 `CPU_TICKS_EXTRA` 这种会被当成 `CPU_TICKS`。
    命中不唯一就不给（宁可报"找不到"，也不许挑一个看着像的）。
    """
    import struct

    d, secs = _elf_sections(elf)
    if ".symtab" not in secs or ".strtab" not in secs:
        return None
    symtab, strtab = secs[".symtab"], secs[".strtab"]
    tail = _mangle_tail(*segs).encode()
    hits = []
    for i in range(symtab[5] // symtab[9]):
        st_name, info, _o, _x, st_value, st_size = struct.unpack_from("<IBBHQQ", d, symtab[4] + i * symtab[9])
        if (info & 0xF) != 1 or st_value == 0 or st_size == 0:
            continue
        name = d[strtab[4] + st_name:].split(bytes([0]))[0]
        j = name.find(tail)
        if j < 0:
            continue
        rest = name[j + len(tail):]
        if rest == b"" or rest.startswith(b".llvm."):
            hits.append((st_value, st_size, name.decode(errors="replace")))
    return hits[0] if len(hits) == 1 else None


def _elf_first_load(elf: Path) -> tuple[int, int, int, bytes] | None:
    """第一个 PT_LOAD 的 (文件偏移, vaddr, filesz, 整个 ELF 字节)。VA 基址与镜像头字节都从这里来。"""
    import struct

    d = elf.read_bytes()
    e_phoff = struct.unpack_from("<Q", d, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", d, 54)[0], struct.unpack_from("<H", d, 56)[0]
    for i in range(e_phnum):
        p_type, _fl, p_offset, p_vaddr, _pa, p_filesz, _ms, _al = struct.unpack_from(
            "<IIQQQQQQ", d, e_phoff + i * e_phentsize)
        if p_type == 1:
            return p_offset, p_vaddr, p_filesz, d
    return None


# 判别表**预注册**在这里（跑之前写死，免得看到数再编解释）：
#   两次采样全冻结                     ⇒ 中断根本没来（假设 A：中断源停了）
#   中断计数/本地 tick/idle_hlt 涨而 WORK 冻结 ⇒ 中断来了但没任务跑（假设 B：丢唤醒 / 任务 blocked）
#   WORK 涨                           ⇒ 有任务在跑，不是整机停住（要看串口停在哪条用例）
# **两条语义先核清楚再写判据**（否则会写出永远成立或永远不成立的空转判据）：
#   * `CPU_TICKS` 只数**本地 APIC 定时器**（apic.rs:577-586），BSP 的 tick 走 PIT/I-O APIC，
#     数在 `IRQ_COUNTS[TIMER_ISA_IRQ=0]` ⇒ "中断来了"必须**两本都看**。
#   * `RESCHED` 在**自陷 0xF0 那一支也加**（apic.rs:524），所以 `RESCHED > RESCHED_IPI_RECV`
#     在正常跑里就成立，**不能**当成"IPI 没被取走"。第一版写了这条，核语义时抓出来删掉：
#     marks/recv/fail 三个数只**报出来**供人判，不写成自动结论。
# 读的全是**内核里已有的**计数器 ⇒ 这一刀零内核改动、不改串口量、不动中断语义。
WEDGE_SYMBOLS = [
    (("arch", "x86_64", "apic", "CPU_TICKS"), "每CPU本地tick", 8),
    (("arch", "x86_64", "apic", "IRQ_COUNTS"), "按向量中断", 8),
    (("arch", "x86_64", "apic", "RESCHED"), "resched合计", 8),
    (("arch", "x86_64", "apic", "RESCHED_IPI_RECV"), "resched_IPI取走", 8),
    (("sched", "RESCHED_MARKS"), "每CPU重排标记", 8),
    (("sched", "RESCHED_IPI_FAIL"), "resched_IPI发失败", 8),
    (("arch", "x86_64", "apic", "EOIS"), "EOI", 8),
    (("arch", "x86_64", "apic", "TICK_TSC_LAST"), "最后一拍TSC", 8),
    (("arch", "x86_64", "apic", "CPU_IF"), "每CPU_IF牌", 1),
    (("sched", "IDLE_HLT"), "idle_hlt", 8),
    # **WORK 不是"任务在跑"的计数**（§193 核出来的）：全仓只有 smp.rs 的 AP 工人循环
    # 与 ktests/sched.rs 那几条特定工人自增它。别的用例跑着时它照样冻结 ⇒
    # 拿它当判别轴接近空转。所以只报不判，标签也写明它的真实语义。
    (("sched", "WORK"), "工人圈数WORK", 8),
    # 这两个是"有没有 armed 的等待期限"的**直接读数**。第一版靠 idle_hlt 在涨去**推断**
    # task_wake_tick() 返回 false，那是间接证据；抓到真挂死之后改成直接读（§193）。
    (("sched", "TASK_ARMED"), "armed等待者", 8),
    (("sched", "TASK_WAKE_PENDING"), "待唤醒发布", 8),
    # 等待队列那本账（四个都是单写点的 AtomicU64，语义逐个核过）：
    # 登记 sched.rs:1685 / 信号 :1614 / 超时 :1650 / 槽满拒 :1689。
    # 它们直接回答"阻塞的任务到底有没有挂在等待槽上"，比 WORK 硬得多。
    (("sched", "TW_REGISTERED"), "等待登记过", 8),
    (("sched", "TW_SIGNALED"), "等待被信号", 8),
    (("sched", "TW_TIMEOUTS"), "等待超时过", 8),
    (("sched", "TW_FULL"), "等待槽满拒", 8),
    # §201 零串口探针：t_sleep_until 的探测读数（10 槽，含义见 ktests/sched.rs 的 SLEEP_PROBE 头注释）。
    # 为什么是静态量而不是串口日志：§200 实测带串口诊断 80 跑 0 挂、无诊断 50 跑 2 挂 ⇒
    # 往串口加行疑似把现象压掉了。静态量让两臂代码相同，扰动只剩几条 store。
    (("ktests", "sched", "SLEEP_PROBE"), "睡眠探测", 8),
    # §215 零串口步骤探针（elfload / two_containers 的停点定位）
    (("ktests", "elf", "ELF_PROBE"), "ELF步骤", 8),
    (("ktests", "elf", "FAT32_PROBE"), "FAT32步骤", 8),
    (("sched", "SWITCH_PROBE"), "换入探针", 8),
]


class QmpSession:
    """一条 QMP 连接上发多条命令。

    为什么必须复用：QEMU 的 `-qmp …,server=on` 一次只服务一个客户端，而 `makefile` 出来的
    文件对象不关就会拖住 FIN ⇒ 下一笔连接被接受却没人服务。**实测**：每读一个符号新开一条连接，
    取证跑到第 5 笔就卡住不返回（>400 s，最后只能杀进程）。所以这里一条连接读到底，
    并且 `close()` 先关文件对象再关 socket。
    """

    def __init__(self, port: int):
        import json
        import socket

        self._json = json
        self.s = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.f = self.s.makefile("rw", encoding="utf-8")
        self.f.readline()  # greeting
        self._send({"execute": "qmp_capabilities"})
        self.f.readline()

    def _send(self, obj: dict) -> None:
        self.f.write(self._json.dumps(obj) + "\r\n")
        self.f.flush()

    def pmemsave(self, addr: int, size: int, path: Path) -> str:
        """空串 = 成功；否则是成因。异步事件（没有 return/error 的那些）跳过继续等。"""
        self._send({"execute": "pmemsave",
                    "arguments": {"val": addr, "size": size, "filename": str(path).replace("\\", "/")}})
        while True:
            line = self.f.readline()
            if not line:
                return "QMP 没有回话（连接断开）"
            try:
                msg = self._json.loads(line)
            except ValueError:
                continue
            if "error" in msg:
                return "pmemsave 被拒：" + self._json.dumps(msg["error"], ensure_ascii=False)
            if "return" in msg:
                return ""

    def close(self) -> None:
        try:
            self.f.close()
        finally:
            self.s.close()


def wedge_verdict(deltas: dict, second: dict, moved: list, dump: str = "") -> str:
    """预注册判别表：两次采样的增量 + 第二次绝对值 ⇒ 一句话结论。

    抽成纯函数是为了能**拿留档的真挂死样本回放**（§193）：间歇挂约 1% 每行，
    靠再撞一次来证新分支会咬太贵。回放实测的边界要写清：build/hunt-caught/wedge-064-*.bin
    是**旧 11 符号**表抓的，回放到 B 支入口就停（armed/待唤醒/等待账那六个符号那一跑没读）
    ⇒ 它只能证前三轴把真挂死判进 B 支，**B1/B2/B3 对那一次仍是未测**。

    **判别轴的选择是核过语义的**（§193 的教训）：
    * `IRQ_COUNTS[0]` 数 BSP 的 PIT（经 I/O APIC），`CPU_TICKS[slot]` 数 AP 的本地定时器
      ⇒ "中断来了"必须两本都看，只看一本会把正常跑读成中断停了。
    * `IDLE_HLT[cpu]` 只在 `idle_entry` 里 `task_wake_tick()` 返回 false 之后、hlt 之前自增
      （sched.rs:1134-1142）⇒ 它在涨就等于"每圈都没有可唤醒的等待者"。
    * `WORK` **不是**"任务在跑"：全仓只有 AP 工人循环与 ktests/sched.rs 那几条工人自增它
      ⇒ 只报不判。第一版拿它当第三支的判据，把真挂死判成了"有任务在跑"。
    """
    # 计数下溢必须**最先**判：armed/待唤醒是 usize，双减一次就回绕成 u64::MAX。
    # §194 实测（run-099 原始字节 = 18446744073709551615）：旧表把 MAX 当成"有 armed"
    # 判成 B2，而下溢根本不是"有等待者"⇒ 计数器坏了的时候别的支一律不成立。
    if second["armed等待者"][0] == 2**64 - 1 or second["待唤醒发布"][0] == 2**64 - 1:
        return ("armed/待唤醒计数**下溢**（读到 u64::MAX）⇒ 唤醒计数被双减，"
                "先修计数再谈唤醒（假设 C：task_wake_tick 的 load-then-store 与 task_wait_take 的 swap 不互斥，§194）")
    irq_moved = any(deltas["按向量中断"]) or any(deltas["每CPU本地tick"])
    idle_moved = any(deltas["idle_hlt"])
    armed = second["armed等待者"][0]
    pending = second["待唤醒发布"][0]
    to_moved = any(deltas["等待超时过"])
    if not moved:
        return "两次采样**全冻结** ⇒ 中断根本没来（假设 A：中断源停了）"
    if not irq_moved:
        return ("有量在涨但**两本中断账都没动** ⇒ 不是 tick 驱动的推进"
                "（形状不在预注册表里，只留证据不下结论）")
    # §219：**寄存器分支优先于一切基于计数的推断**。§218 实测教训：IDLE_HLT 冻结只说明
    # "不在 idle 里循环"，**不说明"在 idle 里睡着"**——run-701 的 BSP 其实在 ring3 关中断自旋。
    # 寄存器 dump 本来就取回来了，用它分支才是直接证据。
    if dump:
        m0 = re.search(r"^CPU#0$", dump, re.M)
        if m0:
            blk = dump[m0.start():m0.start() + 900]
            mr = re.search(r"RFL=(\w+)", blk)
            mh = re.search(r"HLT=(\d)", blk)
            mp = re.search(r"RIP=(\w+)", blk)
            if mr and mh and mp:
                rfl = int(mr.group(1), 16)
                iflag = 1 if rfl & 0x200 else 0
                hlt = mh.group(1)
                rip = int(mp.group(1), 16)
                user = rip >= 0x100000000
                irr = re.search(r"^IRR\s+(.*)$", dump, re.M)
                irrs = irr.group(1).strip() if irr else "?"
                if iflag == 0 and hlt == "0" and user:
                    return (f"BSP **在 ring3 关着中断自旋**（IF=0 HLT=0 RIP={hex(rip)} 用户半区，LAPIC IRR={irrs}）"
                            "⇒ 不是睡死是**取不到中断**：用户态无法自己开 IF，牌=0 被换入就永远不被抢占"
                            "（假设 E：IF 牌为什么是 0，去查 context_load 的 if_open 实参，§218/§219）")
                if iflag == 0 and hlt == "1":
                    return (f"BSP **关着中断睡死**（IF=0 HLT=1 RIP={hex(rip)}，LAPIC IRR={irrs}）"
                            "⇒ hlt 永远醒不来（假设 F：谁在关窗口时进了 hlt，§219）")
                if iflag == 1 and hlt == "1" and irrs not in ("(none)", "?", ""):
                    return (f"BSP **IF=1 且 HLT=1 而 LAPIC IRR 非空（{irrs}）⇒ 该取却没取**"
                            "（假设 G：比 IF 更深的一层，RIP=" + hex(rip) + "，§219）")
    # D 支（§196）：IDLE_HLT **冻结但绝对值 > 0** 与"冻结且为 0"是两件事，旧表把它们混成一支。
    # idle_entry 每圈 hlt 前都自增 IDLE_HLT ⇒ 冻结在 1 意味着"进了第一次 hlt 就再没醒过"，
    # 而不是"没有 CPU 在 idle"。run-118/124 实测：IRQ 全冻结 + AP 本地 tick 照涨 + IDLE_HLT[0]=1，
    # 且 ioapic **pin2 masked**（B1 那两次是 unmasked）⇒ BSP 的 PIT 路由被屏蔽，没有任何中断源叫它。
    # 对照 run-069（fault-if-carriage）：IDLE_HLT[0]=**0** ⇒ BSP 从没进过 idle，那才是关中断自旋。
    idle_abs = second["idle_hlt"][0]
    ap_moved = any(deltas["每CPU本地tick"])
    if not idle_moved and idle_abs > 0 and not any(deltas["按向量中断"]) and ap_moved:
        head = ("BSP 在 idle 的**第一次 hlt 就睡死**（IDLE_HLT 冻结在 " + str(idle_abs) + "）而 AP 的本地 tick 照涨、"
                "按向量中断全冻结 ⇒ **BSP 的中断源停了**（假设 D，§196）")
        sp = second.get("睡眠探测")
        if not sp:
            return head + "；这一跑没读到睡眠探针 ⇒ 自愈有没有被触发**未测**"
        # 槽位：4=was_running 6=有没有调 timer_start 7=是否 Ok 8=调完 rte2 低 DWORD 9=进入次数
        if sp[6] == 0:
            return (head + f"；探针：进入{sp[9]}次 was_running={sp[4]} **没调 timer_start** "
                    "⇒ 探测以为表在走（D1：自愈没被触发，去核 wait_ticks 的 got 与 RTE 的 masked 位）")
        if sp[7] == 0:
            return head + f"；探针：调了 timer_start 但**返回 Err**（D2：开表失败，rte2={sp[8]:#x}）"
        return (head + f"；探针：调了 timer_start 且 Ok、调完 rte2={sp[8]:#x}"
                "（D3：开表成功却仍 masked ⇒ 之后又被屏蔽，或 unmask 没落到 pin2）")
    if not idle_moved:
        return ("idle 计数没涨（BSP 的 IDLE_HLT 绝对值=" + str(idle_abs) + "，0 = 从没进过 idle）"
                "⇒ 有任务占着 CPU（在跑或在关中断自旋），要看串口停在哪条用例")
    if armed == 0 and pending == 0:
        return ("中断在涨、CPU 在 idle、**没有 armed 等待者也没有待唤醒** ⇒ 停住的任务不在等待槽上"
                "（假设 B1：没有期限也没有信号目标会叫醒它——Blocked 而没登记，或根本不 Blocked）")
    if not to_moved:
        return (f"有 armed/待唤醒（{armed}/{pending}）而采样窗内**零超时** ⇒ 期限还没到，或超时路径没在跑"
                "（假设 B2：本仪器不读期限值，这两者今天分不开）")
    return ("超时在发生而用例仍不推进 ⇒ 期限到了却没换成进展"
            "（假设 B3：唤醒/换人那一侧，要看 wake_task 与 pick_next）")


def wedge_probe(port: int, log: str, elf: Path, build_dir: Path, seq: int, dump: str = "") -> str:
    """挂死时把已有计数器**读两次**（隔 3 秒），判"中断源停了"还是"丢唤醒"。

    VA→PA 靠现成锚点：`fatalrec: 物理=` 那行给 FATAL_RECORD 的 PA，符号表给它的 VA，
    两者相减得内核镜像的物理基址（ELF 里 paddr==vaddr 是链接器占位，**不能用**）。
    **非循环自检**：拿推出来的基址去读镜像头 256 字节，必须与 ELF 第一个 PT_LOAD 的
    文件字节逐字相同——用锚点推基址再反算锚点永远相等，那种自检是空转。
    符号表还需要与这一跑的产物同源（image-info 的 sha），否则地址会落到另一个构建里。
    """
    import hashlib as _hl
    import struct

    facts = fatalrec_boot_facts(log)
    if facts is None:
        return "wedge: 串口没有 fatalrec 锚点行 ⇒ 推不出物理基址，整段跳过（不猜）"
    info = build_dir / "image-info.txt"
    rec = dict(l.split("=", 1) for l in info.read_text(encoding="utf-8").splitlines() if "=" in l) if info.exists() else {}
    if not elf.exists():
        return f"wedge: 产物不在 {elf}"
    if rec.get("elf_sha256") != _hl.sha256(elf.read_bytes()).hexdigest():
        return "wedge: 符号表与这一跑的产物不同源（image-info 的 elf_sha256 不符）⇒ 不读"
    fr = data_sym(elf, ("crash", "FATAL_RECORD"))
    load = _elf_first_load(elf)
    if fr is None or load is None:
        return "wedge: 符号表里找不到 FATAL_RECORD 或第一个 PT_LOAD ⇒ 不猜基址"
    p_offset, va_base, _filesz, d = load
    base = facts[0] - (fr[0] - va_base)
    try:
        q = QmpSession(port)
    except OSError as e:
        return "wedge: QMP 连不上（port=" + str(port) + "）：" + repr(e)
    try:
        head = build_dir / f"wedge-head-{seq:03d}.bin"
        err = q.pmemsave(base, 256, head)
        if err:
            return "wedge: 镜像头读不回来（" + err + "）⇒ 基址推导无从验证，整段不读"
        if head.read_bytes() != d[p_offset:p_offset + 256]:
            return (f"wedge: **基址自检红** 推导基址={hex(base)}，按它读回的镜像头 256 字节与 ELF 段字节不同"
                    " ⇒ 线性映射假设不成立，后面所有符号都不读")
        syms = []
        for segs, label, width in WEDGE_SYMBOLS:
            s = data_sym(elf, segs)
            if s is None:
                return f"wedge: 符号 {label}（{'::'.join(segs)}）在符号表里找不到或不唯一 ⇒ 整段不读"
            syms.append((label, width, s))
        samples = []
        for k in (1, 2):
            if k == 2:
                time.sleep(3)
            row = {}
            for i, (label, width, (va, size, _n)) in enumerate(syms):
                # 文件名只用跑号/样本号/序号：中文标签进文件名在本机控制台上读起来是乱码，
                # 而证据文件是要被人翻的。
                f = build_dir / f"wedge-{seq:03d}-{k}-{i:02d}.bin"
                err = q.pmemsave(base + (va - va_base), size, f)
                if err:
                    return f"wedge: 第 {k} 次采样读 {label} 失败（{err}）⇒ 不给半截结论"
                b = f.read_bytes()
                row[label] = list(struct.unpack("<" + ("Q" if width == 8 else "B") * (size // width), b))
            samples.append(row)
    finally:
        q.close()
    a, b = samples
    out = [f"wedge: 基址={hex(base)}（锚点自检绿：镜像头 256 字节与 ELF 逐字相同）；两次采样间隔 3s"]
    moved = []
    deltas = {}
    for label, width, (_va, size, _n) in syms:
        n = size // width
        va_, vb_ = a[label][:n], b[label][:n]
        delta = [y - x for x, y in zip(va_, vb_)]
        deltas[label] = delta
        tag = "涨" if any(delta) else "冻结"
        if any(delta):
            moved.append(label)
        out.append(f"  {label:16s} {tag}  一次={va_ if n <= 16 else str(va_[:8]) + '…'}"
                   f"  增量={delta if n <= 16 else str(delta[:8]) + '…'}")
    verdict = wedge_verdict(deltas, b, moved, dump)
    out.append(f"  参考数（只报不判：marks 含自陷，不能拿它与 recv 的差当丢唤醒）"
               f" resched合计={b['resched合计'][0]} IPI取走={b['resched_IPI取走'][0]}"
               f" IPI发失败={b['resched_IPI发失败'][0]} 每CPU标记={b['每CPU重排标记']}")
    out.append(f"  armed等待者={b['armed等待者'][0]} 待唤醒发布={b['待唤醒发布'][0]}"
               "（两个都 0 ⇒ 没有 armed 期限，blocked 的任务不会被超时唤醒）")
    out.append(f"  等待队列账（登记/信号/超时/槽满拒）="
               f"{b['等待登记过'][0]}/{b['等待被信号'][0]}/{b['等待超时过'][0]}/{b['等待槽满拒'][0]}"
               f"  增量={deltas['等待登记过'][0]}/{deltas['等待被信号'][0]}"
               f"/{deltas['等待超时过'][0]}/{deltas['等待槽满拒'][0]}")
    sp = b.get("睡眠探测")
    if sp:
        out.append(f"  睡眠探针（t_sleep_until）进入次数={sp[9]} tick_in={sp[0]} got={sp[1]} cycles={sp[2]}"
                   f" rounds={sp[3]} was_running={sp[4]} 进来rte2={sp[5]:#x}"
                   f" 调开表={sp[6]} 开表Ok={sp[7]} 调完rte2={sp[8]:#x}")
    ep = b.get("ELF步骤")
    if ep:
        out.append(f"  ELF步骤探针 最后步骤={ep[0]} elf_load进入={ep[1]} two_containers进入={ep[2]} elf_load离开={ep[3]}")
    fp = b.get("FAT32步骤")
    if fp:
        out.append(f"  FAT32步骤探针 最后步骤={fp[0]} t_fat32_exec进入={fp[1]}")
    sw = b.get("换入探针")
    if sw:
        out.append(f"  换入探针 最后if_open={sw[0]} 最后换入gidx={sw[1]} cpu={sw[2]}"
                   f" 牌0换入次数={sw[3]} 换入总次数={sw[4]}"
                   f" **最后一次牌0换入: gidx={sw[5]} cpu={sw[6]} 第{sw[7]}次**")
    out.append("wedge 判定: " + verdict)
    return "\n".join(out)


def qmp_hang_evidence(port: int, log: str, build_dir: Path, seq: int) -> str:
    """超时那一次的完整取证：寄存器/LAPIC/PIC + 无锁现场表读回 + 两种自查判据 + 中断源/丢唤醒判别。"""
    # §218：投递侧取证。pin2 未屏蔽却 IRQ 冻结 ⇒ 要问"PIT 还在不在走、BSP 的 LAPIC 挡没挡"。
    # `info pit` 不是所有 QEMU 都有；取不到就明说取不到，**不拿空值冒充读数**。
    dump = qmp_snapshot(port, ["info registers -a", "info lapic", "info pic", "info pit"])
    text_extra = []
    m = re.search(r"APR\s+(0x[0-9a-f]+)\s+TPR\s+(0x[0-9a-f]+).*?PPR\s+(0x[0-9a-f]+)", dump)
    if m:
        text_extra.append(f"投递侧 BSP LAPIC: APR={m.group(1)} TPR={m.group(2)} PPR={m.group(3)}"
                          "（TPR/PPR 的 bit7:4 >= vec32 的 0x2 就会挡住 PIT）")
    else:
        text_extra.append("投递侧 BSP LAPIC: **没解析到 APR/TPR/PPR**（info lapic 格式变了？）")
    isr = re.search(r"^ISR\s+(.*)$", dump, re.M)
    irr = re.search(r"^IRR\s+(.*)$", dump, re.M)
    rirr = re.search(r"Remote IRR\s+(.*)", dump)
    text_extra.append(f"投递侧 ISR={isr.group(1).strip() if isr else '?'} IRR={irr.group(1).strip() if irr else '?'}"
                      f" ioapic RemoteIRR={rirr.group(1).strip() if rirr else '?'}")
    pit = dump.split("### info pit")[-1] if "### info pit" in dump else ""
    if pit and "unknown" not in pit.lower() and "not supported" not in pit.lower() and pit.strip():
        text_extra.append("投递侧 PIT 原文已取回（见下方 info pit 段）")
    else:
        text_extra.append("投递侧 PIT: **这个 QEMU 的 info pit 取不到** ⇒ PIT 计数器状态仍是盲区，"
                          "要另找路（例如让 AP 的 tick ISR 采样 PIT 端口写进静态量）")
    text, table = fatalrec_readback(port, log, build_dir, seq)
    text = chr(10).join(text_extra) + chr(10) + text
    bad, green = fatal_selfcheck(log, table)
    if bad:
        text += "\n" + "；".join(bad)
    elif green:
        text += "\n" + green
    # 判别仪器与崩溃表是两件事：表答"有没有进崩溃路径"，这一台答"为什么没人再跑"。
    # 产物路径直接取（**不调 kernel_binary**：那会触发构建，而取证必须在 kill 之前做完）。
    elf = ROOT / "target" / TARGET / "debug" / "aurora-kernel"
    text += "\n" + wedge_probe(port, log, elf, build_dir, seq, dump)
    return dump + "\n" + text + "\n"


def do_run(features: list[str], timeout: int, extra: str = "", host_fault: str = "") -> tuple[str, int, str]:
    # 声明放在函数头：挂死取证要**这一跑的跑号**（读 RUN_SEQ），
    # 而 Python 要求 `global` 早于同一作用域里对这个名字的任何使用。
    global RUN_SEQ
    if not QEMU.exists():
        sys.exit(f"QEMU 未就位：{QEMU}")
    # 宿主机侧注入不是特性（见 FAT_HOST_FAULTS 那一段）：它改盘，不改构建。
    # 两道前置闸都在这里，因为"改了盘却没人读它"与"注入名写错了"都表现为一跑看不出成因的红。
    if host_fault and host_fault not in FAT_HOST_FAULTS and host_fault not in GPT_HOST_FAULTS and host_fault not in PKG_HOST_FAULTS:
        sys.exit(f"不认识的宿主机侧注入：{host_fault}"
                 f"（有的那些：{sorted([*FAT_HOST_FAULTS, *GPT_HOST_FAULTS, *PKG_HOST_FAULTS])}）")
    if host_fault in FAT_HOST_FAULTS and not (FAT_DISK_FEATURES & set(features)):
        sys.exit(f"{host_fault} 改的是 FAT32 卷，这一跑却没带任何挂盘的特性 ⇒ 改了也没人读")
    if host_fault in GPT_HOST_FAULTS and not (GPT_FEATURES & set(features)):
        sys.exit(f"{host_fault} 改的是 GPT 夹具盘，这一跑却没带 gpt-probe ⇒ 改了也没人读")
    # 改包注入必须从**pristine**镜像出发：先立脏旗让 ensure_image 重造，再改。
    # 否则上一跑留下的翻转会变成这一跑的"old"，两条注入互相顶掉（实测撞过）。
    if host_fault in PKG_HOST_FAULTS:
        global PKG_DIRTY
        PKG_DIRTY = True
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
    if FAT_FEATURES & set(features):
        # L3-C①：两块只读 FAT32 卷。夹具跟着"要挂这两块盘"走（与前两块的规矩同一条），
        # 而且这里**必须**在解压之前先核指纹：内核那一批写死的期望数全是照着这两个字节串量的。
        bad = make_fat_volumes()
        if bad:
            sys.exit("FAT32 夹具不成立：" + " / ".join(bad))
        # L3-C④：宿主机侧注入必须在**核完指纹之后**改盘——顺序反了就是拿改过的字节去核
        # pristine 的指纹，那条闸会把注入本身当成"夹具坏了"，而真正的注入点永远走不到。
        if host_fault:
            bad = apply_fat_host_fault(host_fault)
            if bad:
                sys.exit("FAT32 宿主机侧注入不成立：" + " / ".join(bad))
    if GPT_FEATURES & set(features):
        # 与 scratch/virtio/FAT 同一条规矩：夹具跟着"要挂这块盘"走，每跑重造并核指纹。
        bad = make_gpt_fixture()
        if bad:
            sys.exit("GPT 夹具盘不成立：" + " / ".join(bad))
        # 注入必须在**核完指纹之后**改盘（与 FAT 那条顺序同一理由）。
        if host_fault in GPT_HOST_FAULTS:
            bad = apply_gpt_host_fault(host_fault)
            if bad:
                sys.exit("GPT 宿主机侧注入不成立：" + " / ".join(bad))
    # 改包注入（W4 S3）：包在引导镜像的裸 LBA 上，所以它跟着 ensure_image 走、与挂盘特性无关。
    # 必须在镜像造好之后改，且**不重算任何校验**——拒因要来自签名/形状检查本身。
    if host_fault in PKG_HOST_FAULTS:
        bad = apply_pkg_host_fault(host_fault)
        if bad:
            sys.exit("改包宿主机侧注入不成立：" + " / ".join(bad))
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
    if FAT_FEATURES & set(features):
        # 口号映射沿用 scratch 那一格**实测过**的关系：`if=ide,index=N` 落在 ich9-ahci 的口 N。
        # 这里不另写一套 `-device ide-hd,bus=ahci0.x`：那条路径没在本机量过，而端口表是内核
        # 自己扫出来的——接线方式一变，"口 3 挂的是卷A"这件事就得重新找证人。
        # 证人换成两头的对账：`check-fat32-ports` 比口号，`check_fat32` 比内容（两块卷簇数
        # 不同，接反了内容对账当场红）。
        for port, name in sorted(FAT_PORTS.items()):
            cmd += ["-drive", f"if=ide,index={port},format=raw,file={FAT_IMG[name]}"]
    if GPT_FEATURES & set(features):
        # 口号映射沿用上面那条**实测过**的关系（`if=ide,index=N` 落在 ich9-ahci 的口 N）。
        # 这块盘固件不会去读它（不是引导盘、也没有 ESP 里的 BOOTX64.EFI），所以改它不会
        # 触发 EDK2 那套"用备份表修主表"的治愈行为——六条负样本正是靠这一点才到得了内核。
        cmd += ["-drive", f"if=ide,index={GPT_FIX_PORT},format=raw,file={GPT_FIX}"]
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
    # P2.5：只有设了开关才挂 QMP，且挂上之后超时**先取证再杀**
    qmp_port = int(os.environ.get("AURORA_QEMU_QMP") or 0)
    if qmp_port:
        cmd += ["-qmp", "tcp:127.0.0.1:" + str(qmp_port) + ",server=on,wait=off"]
        print("   + QMP 取证通道: 127.0.0.1:" + str(qmp_port))
    t0 = time.time()
    r = None
    # 接线方式必须留痕：挂死/枚举不到设备的现场，第一件要问的就是"盘真的交给 QEMU 了吗"。
    # 原来这里只回显附加参数，`-drive` 那几项进不了日志——一次"第二块盘没到 HBA"的
    # 红因此无法归因（实测：同一条用例经矩阵与 `run` 两条路给出不同读数，日志里看不出差别）。
    print("   + QEMU 接线:", " ".join(x for x in cmd if x.startswith("-drive") or "qcow2" in x or x == "-M" or "q35" in x))
    if qmp_port:
        with subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, env=env()) as proc:
            try:
                proc.communicate(timeout=timeout)
                rc = proc.returncode
            except subprocess.TimeoutExpired:
                # 取证要在 kill **之前**：进程一死，内存就没了，那张表再也读不回来。
                early = SERIAL_LOG.read_text(encoding="utf-8", errors="replace") if SERIAL_LOG.exists() else ""
                # 跑号 = 这一跑稍后要留档的那个号（RUN_SEQ 在下面才自增）：证据与串口同号，
                # 一张矩阵里挂两行才不会互相覆盖（固定文件名 qmp-hang.txt 就是这个覆盖的形状）。
                seq = RUN_SEQ + 1
                dump = qmp_hang_evidence(qmp_port, early, BUILD, seq)
                name = f"qmp-hang-run-{seq:03d}.txt"
                (BUILD / name).write_text(dump, encoding="utf-8")
                print("   + 挂死现场已存 build/" + name + "（" + str(len(dump)) + " 字节）")
                print("   + " + "\n   + ".join(dump.splitlines()[-6:]))
                proc.kill()
                proc.communicate()
                rc = -1
    else:
        try:
            r = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=timeout, env=env())
            rc = r.returncode
        except subprocess.TimeoutExpired:
            rc = -1
    # 必须显式按 UTF-8 读：内核写的是 UTF-8，而 `read_text()` 不带 encoding 时用本机默认
    # 编码（这台机是 GBK），中文日志全部变乱码——于是任何按中文锚点的判据都会读成"零条记录"。
    # 实测踩过：内容对账第一次跑报"串口里只有 0 条块读记录"，而记录明明在。
    log = SERIAL_LOG.read_text(encoding="utf-8", errors="replace") if SERIAL_LOG.exists() else ""
    # 每一跑都留档（P3a 之后补的量具缺口）：矩阵原来只在内存里留着各行的串口原文，
    # 于是"某一行红了"事后无法归因——只能重跑，而重跑往往就绿了（实测两次）。
    # 留档之后，红那一跑的用例名与 fatal 原文都在，不需要靠复现率去猜。
    RUN_SEQ += 1
    keep = BUILD / f"run-{RUN_SEQ:03d}.log"
    keep.write_text(log, encoding="utf-8")
    print(f"   串口留档: {keep.name}")
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
    if rc == -1:
        # 停住点自动留痕（与归档同号）：下一次撞到就有现场，不用靠重跑撞见。
        sr = stall_report(log, time.time() - t0, timeout)
        print("   " + sr.replace("\n", "\n   "))
        (BUILD / f"run-{RUN_SEQ:03d}.stall.txt").write_text(sr, encoding="utf-8")
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

_MEMBERS_CACHE: list[Path] | None = None


def workspace_members() -> list[Path] | None:
    """workspace 成员包的根目录（按名字排序）。**唯一来源是 cargo metadata**，不是写死的路径表。

    W3 P5 之前这里有两处写死：`check_lints_wired` 只扫 kernel 与 crates/*，
    `_unsafe_roots()` 只扫 kernel/src 与 user/hello/src ⇒ 新增一个用户态产物时，
    它的 `[lints]` 不会被查、它的 unsafe 一处都不会被普查（BACKLOG §154 的两个盲区）。
    取不到成员集时返回 None，**调用方必须报红**：静默退回写死表就是把盲区又装回去。
    """
    global _MEMBERS_CACHE
    if _MEMBERS_CACHE is not None:
        return _MEMBERS_CACHE
    out = subprocess.run([str(CARGO), "metadata", "--format-version", "1", "--no-deps"],
                         capture_output=True, text=True, env=env())
    if out.returncode != 0:
        return None
    import json
    try:
        pkgs = json.loads(out.stdout)["packages"]
    except (ValueError, KeyError):
        return None
    dirs = sorted({Path(pkg["manifest_path"]).parent for pkg in pkgs}, key=lambda d: d.as_posix())
    _MEMBERS_CACHE = dirs
    return dirs


def check_lints_wired() -> list[str]:
    """[workspace.lints] 不会自动作用于成员 crate；没接线就是“门禁空转”。

    范围 = **全部 workspace 成员**（P5 起；此前只扫 kernel 与 crates/*，user/ 下的产物漏在外面）。
    """
    members = workspace_members()
    if members is None:
        return ["cargo metadata 失败：查不到成员集 ⇒ 这道门不能装作只扫 kernel 就算绿"]
    bad = []
    for d in members:
        m = d / "Cargo.toml"
        if not m.exists():
            bad.append(f"{d.relative_to(ROOT)} 没有 Cargo.toml")
            continue
        s = m.read_text(encoding="utf-8")
        if "[lints]" not in s or "workspace = true" not in s:
            bad.append(f"{m.relative_to(ROOT)} 缺 [lints] workspace = true")
    return bad


# ------------------------------------------------- P3：unsafe 现场分类（U1..U6）
#
# 类别由**规则算**，不是人断言。登记表存的是「模块 × 类别 → 处数」这份普查快照，
# 门禁每次从源码重算一遍再逐格比 ⇒「新增一个未登记的 unsafe 块」与「登记了一条源码里
# 没有的记录」都表现为计数不符，而不是靠人记得去改散文（旧登记表的 scope 就是这么写漏的：
# 它自己承认「门禁按包计数，所以这行写漏不会让检查失败」）。
#
# 规则有优先序，先命中先归类。逐处判定由 `unsafe_sites()` 一并返回，审计表落进
# docs/security/unsafe-census.md。**类别判错了改规则，不改登记数去凑**——后者会让
# 这份普查变成一份跟着代码走的橡皮图章。
UNSAFE_CLASSES = ("U1", "U2", "U3", "U4", "U5", "U6")
UNSAFE_CLASS_NAME = {
    "U1": "架构入口与特殊寄存器",
    "U2": "页表、物理内存与 MMIO",
    "U3": "DMA 与设备共享内存",
    "U4": "并发共享状态与 UnsafeCell",
    "U5": "用户指针与地址空间访问",
    "U6": "诊断路径的有限现场读取",
}
# 与旧门禁同口径：非注释行里含 unsafe，且是块/impl/fn/extern 四种之一。
# 实测 273 处全部落在这四种里（235 块 + 27 impl + 10 fn + 1 extern），没有第五种形状。
UNSITE = re.compile(r"\bunsafe\s*(\{|impl|fn|extern)")
# 顶层 fn（列 0）。只认列 0 是有意的：extern "C" {} 里那些缩进的 fn 是**声明**不是定义，
# 认了它会把后面整个文件的"所属函数"都记成 context_load。
UNFN = re.compile(r'^(?:pub )?(?:unsafe )?(?:extern "C" )?fn\s+(\w+)')
UNSAFE_ARCH_TABLE = ("tss.", "gdt", "idt", "gdtr", "write_unaligned")


def _unsafe_roots() -> list[Path]:
    """普查范围 = **全部 workspace 成员**的 src。与 check_unsafe_registry 的按包对账同一份来源。

    P5 之前这里写死两个根（kernel/src 与 user/hello/src），新产物一处都不会被普查；
    现在跟着 cargo metadata 走。取不到成员集时退回空表 ⇒ 普查算出 0 处，
    与登记表的非零总数对不上 ⇒ check-unsafe 报红（不会静默绿）。
    """
    members = workspace_members()
    if members is None:
        return []
    return [d / "src" for d in members if (d / "src").is_dir()]


def unsafe_extern_syms() -> dict[str, str]:
    """extern "C" {} 里的符号 → 'fn' 或 'static'。这些是全局 asm 定义的入口与链接器符号。

    分开记是有用的：调用一个 extern **fn**（context_load / if_patch）或索引一个 extern
    **static**（isr_table[v]）是架构入口 ⇒ U1；而对链接器符号取地址（`&raw const __text_start`）
    只是在量镜像边界，没有入口语义 ⇒ 落到 U2。
    """
    syms: dict[str, str] = {}
    for root in _unsafe_roots():
        for f in sorted(root.rglob("*.rs")):
            t = f.read_text(encoding="utf-8")
            for m in re.finditer(r'extern\s+"C"\s*\{', t):
                i, depth = m.end(), 1
                while i < len(t) and depth:
                    depth += (t[i] == "{") - (t[i] == "}")
                    i += 1
                body = t[m.end():i - 1]
                for kind, pat in (("fn", r"\bfn\s+(\w+)"), ("static", r"\bstatic\s+(\w+)")):
                    for n in re.findall(pat, body):
                        syms[n] = kind
    return syms


def _classify_unsafe(kind: str, text: str, module: str, fn: str,
                     syms: dict[str, str]) -> str:
    """一处 unsafe 现场 → U1..U6。text 是现场行与其后两行拼起来的窗口
    （`unsafe {` 常常单独一行，操作在下一行；只看当行会把它们全归到兜底类）。

    **按这处操作做什么归类，不按它坐在哪个函数里。** 第一版有一条"所属函数是
    `extern "C" fn` 就归 U1"，实测把 `user/hello` 的 `_start` 与 `mm::take_over`
    整个函数体都染成了 U1（29 处与 5 处），而它们真正做的是 syscall 跨界与镜像边界测量。
    入口**声明本身**由 `kind == "extern"` 那条归 U1，够了。
    """
    if kind == "impl":
        return "U2" if "GlobalAlloc" in text else "U4"
    # 用户指针拷贝先判：ucopy_from/to 也是 extern fn，但它的语义比"架构入口"更具体。
    if "ucopy_from" in text or "ucopy_to" in text:
        return "U5"
    if "asm!" in text or kind == "extern":
        return "U1"
    for n, k in syms.items():
        if (f"{n}(" in text) if k == "fn" else (f"{n}[" in text):
            return "U1"
    if any(k in text for k in UNSAFE_ARCH_TABLE):
        return "U1"
    if any(k in text for k in (".0.get()", "UnsafeCell", ".data.get()", "locked.store")):
        return "U4"
    if module in ("crash", "ktest"):
        return "U6"
    # 用户态成员包一律按"入口声明 = U1、其余 = 用户指针 U5"归类。
    # **不写死 user/hello**（P5a 实测：新包 user/probe 掉进 U2 兜底，而它做的是 syscall 跨界
    # 与读自己映射的用户页，语义就是 U1/U5）。这是改规则，不是改登记数去凑。
    if module.startswith("user/"):
        return "U1" if kind == "fn" else "U5"
    if module == "driver" and any(k in text for k in ("read_volatile", "write_volatile", "write_bytes")):
        return "U3"
    if module == "limine" and any(k in text for k in ("extra_argument", "goto_address", "release_mp_cpu")):
        return "U3"
    if fn.startswith("t_"):
        return "U6"
    return "U2"


def unsafe_sites() -> list[dict]:
    """普查每一处 unsafe 现场：模块、行号、形状、所属顶层函数、判定类别与判定依据原文。"""
    syms = unsafe_extern_syms()
    out: list[dict] = []
    for root in _unsafe_roots():
        for f in sorted(root.rglob("*.rs")):
            rel = f.relative_to(ROOT)
            # 模块名：内核包 = 包内相对路径去掉 .rs（既有键一格不动）；
            # 别的成员包 = 包目录相对仓库根（`user/hello`、`user/<probe>`…），
            # 入口文件（main.rs/lib.rs）就用包目录本身，免得以 "main" 与内核的 main 撞名；
            # 包里再有别的文件就接在后面。**不再写死 user/hello 前缀**（P5 之前的盲区）。
            pkg = next((d for d in _unsafe_roots() if root == d), None)
            if pkg is not None and pkg.parent != ROOT / "kernel":
                base = pkg.parent.relative_to(ROOT).as_posix()
                sub = f.relative_to(pkg).with_suffix("").as_posix()
                module = base if sub in ("main", "lib") else f"{base}/{sub}"
            else:
                module = f.relative_to(ROOT / "kernel" / "src").with_suffix("").as_posix()
            lines = f.read_text(encoding="utf-8").splitlines()
            fn = ""
            for i, ln in enumerate(lines):
                m = UNFN.match(ln)
                if m:
                    fn = m.group(1)
                if ln.strip().startswith("//") or not UNSITE.search(ln):
                    continue
                kind = UNSITE.search(ln).group(1)
                text = " ".join(x.strip() for x in lines[i:i + 3])
                out.append(dict(module=module, path=rel.as_posix(), line=i + 1, kind=kind,
                                fn=fn, text=text, cls=_classify_unsafe(kind, text, module, fn, syms)))
    return out


def unsafe_census() -> dict[tuple[str, str], int]:
    """模块 × 类别 → 处数。登记表存的就是这份快照。"""
    c: dict[tuple[str, str], int] = {}
    for s in unsafe_sites():
        k = (s["module"], s["cls"])
        c[k] = c.get(k, 0) + 1
    return c


def check_unsafe_registry() -> list[str]:
    """登记表 <-> 实际 unsafe 双向对账（手册 §1.3 第 6 条），两层粒度。

    第一层按**包名**（哪个包允许含 unsafe）：登记表用包名，目录名可能不同，
    例如 kernel/ 目录对应 aurora-kernel 包。这一层是原来就有的准入闸。
    第二层按**模块 × 类别**（P3 细分）：从源码逐处重算普查，与 `[modules.*]` 逐格比。
    只有第一层时，登记表自己承认的那句「门禁按包计数，所以这行写漏不会让检查失败」
    就是真的——scope 散文写漏了照样绿。第二层把"漏登记一处"变成计数不符。
    """
    reg = ROOT / "docs" / "security" / "unsafe-whitelist.toml"
    if not reg.exists():
        return ["缺 docs/security/unsafe-whitelist.toml"]
    raw = reg.read_text(encoding="utf-8")
    listed = {
        ln.strip().strip("[]").removeprefix("crate.")
        for ln in raw.splitlines()
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

    # 第二层。先真解析一遍 TOML：本轮开工时这份文件**根本不是合法 TOML**
    # （scope_actual 里有嵌套裸双引号），而旧门禁只按行首扫 `[crate.`，所以那个错一直没人发现。
    # 解析失败必须是红，否则下面整层对账会静默空转。
    import tomllib
    try:
        doc = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as e:
        return bad + [f"unsafe-whitelist.toml 不是合法 TOML：{e}（按包对账看不出这个，"
                      "而模块×类别那一层整层会空转）"]
    census = doc.get("unsafe-census")
    modules = doc.get("modules")
    if not isinstance(census, dict) or not isinstance(modules, dict):
        return bad + ["缺 [unsafe-census] 或 [modules] 段：P3 细分登记不在位，第二层对账空转"]
    got = unsafe_census()
    want = {(m, c): n for m, v in modules.items() for c, n in v.items()}
    for m, v in modules.items():
        for c in v:
            if c not in UNSAFE_CLASSES:
                bad.append(f"模块 {m} 登记了不存在的类别 {c}（只有 {'/'.join(UNSAFE_CLASSES)}）")
    for k in sorted(set(want) - set(got)):
        bad.append(f"登记了 {k[0]} 的 {k[1]} {want[k]} 处，源码里一处都算不出来（白名单虚报）")
    for k in sorted(set(got) - set(want)):
        bad.append(f"{k[0]} 有 {got[k]} 处 {k[1]}（{UNSAFE_CLASS_NAME[k[1]]}）但没登记（越权 unsafe）")
    for k in sorted(set(got) & set(want)):
        if got[k] != want[k]:
            bad.append(f"{k[0]} {k[1]}: 登记 {want[k]} 处，源码算出 {got[k]} 处"
                       "（新增/删除了 unsafe，或分类规则变了——改规则要连登记一起改，并重新核对审计表）")
    total = sum(got.values())
    if census.get("total") != total:
        bad.append(f"[unsafe-census] total={census.get('total')}，源码算出 {total}")
    for c in UNSAFE_CLASSES:
        n = sum(v for (m, k), v in got.items() if k == c)
        if census.get(c) != n:
            bad.append(f"[unsafe-census] {c}={census.get(c)}，源码算出 {n}")
    # 审计表与登记表同源，但它是给人读的那一份：只核它的汇总锚点行，
    # 不逐处比（逐处的权威来源是上面那次重算，两处各写一份就会分家）。
    audit = ROOT / "docs" / "security" / "unsafe-census.md"
    if not audit.exists():
        bad.append("缺 docs/security/unsafe-census.md（逐处审计表：类别判错了要能翻到具体哪一处）")
    else:
        line = "总计 %d 处。%s" % (total, " · ".join(
            f"{c} {sum(v for (m, k), v in got.items() if k == c)}" for c in UNSAFE_CLASSES))
        if line not in audit.read_text(encoding="utf-8"):
            bad.append(f"unsafe-census.md 的汇总行与重算不符，应当是：{line}")
        # 逐处章节标题也要对账。Task A 生成 census 时丢过 `###`，而上面只核汇总行，
        # 所以那处结构损坏一直没人发现；这里补一条“每个登记模块恰好一个 ### 段”。
        audit_text = audit.read_text(encoding="utf-8")
        heads = set(re.findall(r"(?m)^### (.+)$", audit_text))
        want_heads = set(modules.keys())
        missing = sorted(want_heads - heads)
        extra = sorted(heads - want_heads)
        if missing or extra:
            bad.append(f"unsafe-census.md 的逐处章节与 [modules] 不符：缺 {missing}，多 {extra}")
    return bad


def check_module_interfaces() -> list[str]:
    """Task A：`docs/architecture/module-interfaces.toml` 与源码事实双向对账。

    核四件事（任何一条断了，登记表就会慢慢变成一篇好看的散文）：
    1. main.rs 的每个 `mod` 都被**恰好一个**逻辑模块的 source_modules 覆盖；
    2. public_api 里的每个符号在它声称的源模块里真的是 pub/pub(crate)；
    3. dependencies / allowed_callers 与源码实际引用边（剥注释、排除 ktests/*）**相等**；
       实际命中 forbidden_dependencies 的边必须列在 known_violations（冻结当前基线，
       新增违规当场红）；
    4. unsafe_scope 里的模块×类别在 `unsafe_sites()` 重算里确实存在。
    """
    import tomllib

    reg = ROOT / "docs" / "architecture" / "module-interfaces.toml"
    if not reg.exists():
        return ["缺 docs/architecture/module-interfaces.toml（Task A 的登记表）"]
    try:
        doc = tomllib.loads(reg.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        return [f"module-interfaces.toml 不是合法 TOML：{e}"]
    mods = doc.get("modules")
    if not isinstance(mods, dict) or not mods:
        return ["module-interfaces.toml 缺 [modules.*] 段或为空：整层对账会空转"]
    for key in ("status_values", "context_values", "error_classes"):
        if not isinstance(doc.get(key), list) or not doc[key]:
            return [f"module-interfaces.toml 缺 {key}（没有取值域，下面的枚举校验会空转）"]

    src = ROOT / "kernel" / "src"
    files = sorted(src.rglob("*.rs"))
    texts = {f.relative_to(src).with_suffix("").as_posix(): f.read_text(encoding="utf-8") for f in files}
    pub_re = re.compile(
        r'^(pub(?:\(crate\))?)\s+(?:unsafe\s+)?(?:extern\s+"C"\s+)?'
        r'(fn|struct|enum|const|static|type|trait|mod)\s+([A-Za-z_][A-Za-z0-9_]*)'
    )
    pubs = {path: {m.group(3) for ln in text.splitlines() if (m := pub_re.match(ln))}
            for path, text in texts.items()}

    def resolve(s: str) -> str | None:
        if s in pubs:
            return s
        if s + "/mod" in pubs:
            return s + "/mod"
        return None

    bad: list[str] = []
    req = ["module_id", "owner", "layer", "source_modules", "public_api", "allowed_callers",
           "dependencies", "forbidden_dependencies", "known_violations", "context",
           "error_classes", "resource_ownership", "error_policy", "unsafe_scope",
           "test_targets", "status"]
    for mid, m in mods.items():
        for f in req:
            if f not in m:
                bad.append(f"{mid}: 缺字段 {f}")
        if m.get("module_id") != mid:
            bad.append(f"{mid}: module_id={m.get('module_id')!r} 与键不符")
        if m.get("status") not in doc["status_values"]:
            bad.append(f"{mid}: status={m.get('status')!r} 不在 {doc['status_values']}")
        for c in m.get("context", []):
            if c not in doc["context_values"]:
                bad.append(f"{mid}: context {c!r} 不在 {doc['context_values']}")
        for c in m.get("error_classes", []):
            if c not in doc["error_classes"]:
                bad.append(f"{mid}: error_class {c!r} 不在 {doc['error_classes']}")
        for s in m.get("source_modules", []):
            if resolve(s) is None:
                bad.append(f"{mid}: source_module {s!r} 没有对应源文件")

    # 覆盖：main.rs 的每个顶层 mod 恰好属于一个逻辑模块；main.rs 本体也必须登记。
    main_src = (src / "main.rs").read_text(encoding="utf-8")
    top = sorted(set(re.findall(r'^(?:pub(?:\(crate\))?\s+)?mod ([a-z_][a-z0-9_]*);', main_src, re.M)))
    for t in top:
        hits = [k for k, v in mods.items()
                if any(s == t or s.startswith(t + "/") for s in v.get("source_modules", []))]
        if len(hits) != 1:
            bad.append(f"main.rs 的 mod {t} 被 {len(hits)} 个逻辑模块覆盖（{hits}）")
    hits = [k for k, v in mods.items() if "main" in v.get("source_modules", [])]
    if len(hits) != 1:
        bad.append(f"main.rs 本体被 {len(hits)} 个逻辑模块登记（{hits}）")

    # 短名 -> 源路径；同一个短名只能指向一个文件。
    short2path: dict[str, str] = {}
    path2log: dict[str, str] = {}
    for mid, m in mods.items():
        for s in m.get("source_modules", []):
            rp = resolve(s)
            if rp is None:
                continue
            short = s.split("/")[-1]
            if short in short2path and short2path[short] != rp:
                bad.append(f"短名冲突 {short}: {short2path[short]} vs {rp}")
            short2path[short] = rp
            path2log[rp] = mid
            path2log[s] = mid

    valid = set(mods) | {"alloc", "core"}
    for mid, m in mods.items():
        for field in ("allowed_callers", "dependencies", "forbidden_dependencies"):
            for n in m.get(field, []):
                if n not in valid:
                    bad.append(f"{mid}.{field}: 未知模块 {n!r}")
                if n == mid:
                    bad.append(f"{mid}.{field}: 自依赖")
        for kv in m.get("known_violations", []):
            if "->" not in kv:
                bad.append(f"{mid}.known_violations: {kv!r} 不是 a->b")
                continue
            a, b = kv.split("->", 1)
            if a != mid or b not in mods:
                bad.append(f"{mid}.known_violations: {kv!r} 端点不合法")

    for mid, m in mods.items():
        for entry in m.get("public_api", []):
            if "::" not in entry:
                bad.append(f"{mid}.public_api: {entry!r} 缺 ::")
                continue
            spec, sym = entry.rsplit("::", 1)
            path = resolve(spec) if resolve(spec) is not None else short2path.get(spec)
            if path is None:
                bad.append(f"{mid}.public_api: {entry!r} 的模块无法解析")
                continue
            if path2log.get(path) != mid:
                bad.append(f"{mid}.public_api: {entry!r} 指向别的逻辑模块 {path}")
                continue
            if sym not in pubs.get(path, set()):
                bad.append(f"{mid}.public_api: {path} 没有 pub 符号 {sym}")

    # 实际依赖边：只统计**产品路径**。剥 // 注释、排除 ktests/*，并跳过产品文件里的
    # `mod tests { ... }` 块——测试代码不是模块接口；把它算进来会造出假的环
    # （ADR-043：capability↔sched 就是 handle.rs 的 mod tests 造成的）。
    def strip_product(text: str) -> str:
        out = []
        depth = 0
        skip_at = None
        for ln in text.splitlines():
            code = ln.split("//", 1)[0]
            s = code.strip()
            if skip_at is None:
                is_mod = (s.startswith("mod ") or s.startswith("pub mod ")) and "tests" in s.split("{")[0] and "{" in s
                is_fn = (s.startswith("fn t_") or s.startswith("pub fn t_") or s.startswith("pub(crate) fn t_")) and "{" in s
                if is_mod or is_fn:
                    skip_at = depth
                if "ktest!(" in code:
                    out.append("")
                    continue
            depth += code.count("{") - code.count("}")
            if skip_at is not None:
                if depth <= skip_at:
                    skip_at = None
                out.append("")
            else:
                out.append(code)
        return "\n".join(out)

    actual: dict[str, set[str]] = {}
    callers: dict[str, set[str]] = {}
    # site_n：每条实际边的**引用站点数**（按行计）。它是 ADR-044 棘轮的输入——
    # 环内边只许变瘦不许变胖，否则"消环进度"只能写在文档里靠人自觉。
    site_n: dict[tuple[str, str], int] = {}
    for path, text in texts.items():
        if path.startswith("ktests/"):
            continue
        a = path2log.get(path) or path2log.get(path.split("/")[0])
        if a is None:
            continue
        code = strip_product(text)
        for short, p in short2path.items():
            b = path2log.get(p)
            if b is None or a == b:
                continue
            n = sum(1 for ln in code.splitlines()
                    if re.search(r"\b" + re.escape(short) + r"::|\bcrate::" + re.escape(short) + r"\b", ln))
            if n:
                actual.setdefault(a, set()).add(b)
                callers.setdefault(b, set()).add(a)
                site_n[(a, b)] = site_n.get((a, b), 0) + n
    for a in set(actual) | set(mods):
        got = actual.get(a, set())
        want = set(mods[a].get("dependencies", []))
        if got != want:
            only_src = sorted(got - want)
            only_reg = sorted(want - got)
            bad.append(f"{a}.dependencies 不符：源码多 {only_src}，登记多 {only_reg}")
    for b in set(callers) | set(mods):
        got = callers.get(b, set())
        want = set(mods[b].get("allowed_callers", []))
        if got != want:
            bad.append(f"{b}.allowed_callers 不符：源码多 {sorted(got - want)}，登记多 {sorted(want - got)}")
    for a, bs in actual.items():
        for b in bs:
            if b in mods[a].get("forbidden_dependencies", []) \
                    and f"{a}->{b}" not in mods[a].get("known_violations", []):
                bad.append(f"{a}->{b} 命中 forbidden_dependencies 但没有登记 known_violations")
    for a in mods:
        for kv in mods[a].get("known_violations", []):
            b = kv.split("->", 1)[1] if "->" in kv else ""
            if b not in actual.get(a, set()) or b not in mods[a].get("forbidden_dependencies", []):
                bad.append(f"{a}.known_violations 的 {kv} 已不是实际的 forbidden 边（基线过期）")

    base = doc.get("baseline")
    if not isinstance(base, dict) or not isinstance(base.get("known_scc"), list):
        bad.append("缺 [baseline].known_scc（循环依赖的冻结基线；没有它，新增环无人发现）")
    else:
        expected = []
        for comp in base["known_scc"]:
            if not isinstance(comp, list) or len(comp) < 2:
                bad.append(f"baseline.known_scc 的 {comp!r} 不是至少两项的列表")
                continue
            for n in comp:
                if n not in mods:
                    bad.append(f"baseline.known_scc 含未知模块 {n!r}")
            expected.append(sorted(comp))

        def sccs_of(g: dict[str, set[str]]) -> list[list[str]]:
            index: dict[str, int] = {}
            low: dict[str, int] = {}
            on: set[str] = set()
            stack: list[str] = []
            out: list[list[str]] = []
            counter = [0]

            def strong(v: str) -> None:
                index[v] = low[v] = counter[0]
                counter[0] += 1
                stack.append(v)
                on.add(v)
                for w in g.get(v, ()):
                    if w not in index:
                        strong(w)
                        low[v] = min(low[v], low[w])
                    elif w in on:
                        low[v] = min(low[v], index[w])
                if low[v] == index[v]:
                    comp: list[str] = []
                    while True:
                        w = stack.pop()
                        on.discard(w)
                        comp.append(w)
                        if w == v:
                            break
                    out.append(sorted(comp))

            for v in g:
                if v not in index:
                    strong(v)
            return out

        got = sorted([sorted(c) for c in sccs_of(actual) if len(c) > 1])
        if got != sorted(expected):
            bad.append(f"强连通分量与 baseline.known_scc 不符：源码 {got}，基线 {sorted(expected)}"
                       "（新增/消除环都要同步 baseline；拆环是好事，但必须显式更新）")

        # ADR-044 的棘轮：**环内**边的引用站点数只许减不许增。环外的一条向边
        # （sched->boot 这类）不套棘轮——功能开发本来就会让上层模块的出边变多，
        # 把它们一起钉住只会逼人放宽判据，那就不是门禁了。
        ring_nodes = {n for c in got for n in c}
        measured = {f"{a}->{b}": n for (a, b), n in site_n.items() if a in ring_nodes and b in ring_nodes}
        ratchet = base.get("ring_edge_sites")
        if not isinstance(ratchet, dict) or not ratchet:
            bad.append("缺 [baseline].ring_edge_sites（环内边的站点数棘轮；没有它，消环的进度只体现在散文里）。"
                       f"当前实测：{dict(sorted(measured.items()))}")
        else:
            for k, v in ratchet.items():
                if "->" not in k or not isinstance(v, int):
                    bad.append(f"ring_edge_sites 的 {k!r}={v!r} 不是 'a->b'=整数")
            for k in sorted(set(measured) | set(ratchet)):
                if k not in ratchet:
                    bad.append(f"环内新边 {k}（站点 {measured[k]}）未登记棘轮")
                elif k not in measured:
                    bad.append(f"ring_edge_sites 的 {k} 已不是环内实际边（基线过期：消掉一条环边要显式删登记）")
                elif measured[k] > ratchet[k]:
                    bad.append(f"环内边 {k} 站点数 {measured[k]} > 登记 {ratchet[k]}（ADR-044 棘轮：环内引用只许减不许增）")
                elif measured[k] < ratchet[k]:
                    bad.append(f"环内边 {k} 站点数已降到 {measured[k]}（登记 {ratchet[k]}）："
                               "请把登记一起收紧，否则余量会被下一个人悄悄用掉")

    # P0-1（ADR-045）：**反向**登记规则——产品路径里被别的源文件引用到的 pub 符号，
    # 必须出现在它所属模块的 public_api 里。此前的规则只验"登记的符号真存在"，
    # 于是 `use crate::sync::{IrqSpinLock, RANK_HANDLE}` 导入后裸用的符号一直逃逸
    # （handle.rs:25 导入、:165 用的 RANK_HANDLE 至今不在登记表——实测）。
    # 只做单向：反向相等会把 `ktest::KTest`（由 ktest! 宏展开引用）与 `main::kmain`
    # （由 asm/extern 引用）这类"只被测试/汇编用到的入口"误判成死条目，实测 9 条。
    def imported_names(body: str) -> list[str]:
        names: list[str] = []
        br = re.search(r"\{([^{}]*)\}", body)
        if br:
            for part in br.group(1).split(","):
                p = part.strip()
                if " as " in p:
                    p = p.split(" as ")[0].strip()
                if p and p != "self":
                    names.append(p)
        else:
            tail = body.rstrip().split("::")[-1].strip()
            if tail and tail != "self":
                names.append(tail)
        return names

    registered_api: dict[str, set[str]] = {}
    for mid, m in mods.items():
        for e in m.get("public_api", []):
            if "::" not in e:
                continue
            spec, sym = e.rsplit("::", 1)
            pp = resolve(spec) or short2path.get(spec)
            if pp:
                registered_api.setdefault(pp, set()).add(sym)

    referenced: dict[tuple[str, str], str] = {}
    for path, text in texts.items():
        if path.startswith("ktests/"):
            continue
        code = strip_product(text)
        for p2, tsyms in pubs.items():
            if p2 == path or p2.startswith("ktests/") or not tsyms:
                continue
            short = p2.split("/")[-1]
            for sym in tsyms:
                if re.search(r"\b(?:crate::)?(?:\w+::)*" + re.escape(short) + r"::" + re.escape(sym) + r"\b", code):
                    referenced.setdefault((p2, sym), path)
            for ln in code.splitlines():
                mu = re.match(r"^(?:pub\s+)?use\s+(.+)$", ln.strip())
                if mu is None or f"{short}::" not in mu.group(1):
                    continue
                for nm in imported_names(mu.group(1)):
                    if nm in tsyms:
                        referenced.setdefault((p2, nm), path)
    missing_api = sorted(k for k in referenced if k[1] not in registered_api.get(k[0], set()))
    for (p2, sym) in missing_api[:20]:
        bad.append(f"public_api 漏登记：{p2.split('/')[-1]}::{sym}"
                   f"（被 {referenced[(p2, sym)]} 在产品路径上引用）")
    if len(missing_api) > 20:
        bad.append(f"public_api 漏登记共 {len(missing_api)} 条，上面只列前 20")

    census = unsafe_census()
    for mid, m in mods.items():
        for entry in m.get("unsafe_scope", []):
            if ":" not in entry:
                bad.append(f"{mid}.unsafe_scope: {entry!r} 缺 :")
                continue
            path, cls = entry.split(":", 1)
            if path2log.get(resolve(path) or "") != mid:
                bad.append(f"{mid}.unsafe_scope: {path} 不在本逻辑模块")
            for c in cls.split(","):
                if c not in UNSAFE_CLASSES:
                    bad.append(f"{mid}.unsafe_scope: 类别 {c!r} 不合法")
                elif census.get((path, c), 0) <= 0:
                    bad.append(f"{mid}.unsafe_scope: {path} 的重算里没有 {c}（登记虚报）")

    all_text = "\n".join(texts.values())
    fns = set(re.findall(r"\bfn (t_[a-z0-9_]+)\s*\(", all_text))
    for mid, m in mods.items():
        for t in m.get("test_targets", []):
            if t not in fns:
                bad.append(f"{mid}.test_targets: 找不到 fn {t}")
    return bad


def check_vector_table() -> list[str]:
    """P0-2（ADR-046）：具名中断向量与 `docs/architecture/vectors.toml` 双向对账。

    ADR-020 §一只登记了四段区间（0..31/32..47/48..254/255），具名向量 0x80/0xF1/0xF2
    从来没进那张表——所以 W1 任务卡里"新向量登记进 ADR-020 向量表"这句话一直没有可循的
    先例格式。本闸把具名向量变成机器可对账的登记表，并把**三处特例**钉在源码的判据上：
    DPL3 门（`idt_gate(..., v == X)`）、不建帧的快路径（`if v == X {`）、不发 EOI 的判定
    （apic.rs `vector == X`）。W1 要加的 resched IPI 恰好落在这三处的射程里：
    它若走不建帧路径，就必须同时改源码判据与登记，两边不一致当场红。
    """
    import tomllib

    trap = ROOT / "kernel" / "src" / "arch" / "x86_64" / "trap.rs"
    apic = ROOT / "kernel" / "src" / "arch" / "x86_64" / "apic.rs"
    text, atext = trap.read_text(encoding="utf-8"), apic.read_text(encoding="utf-8")
    consts = {m.group(1): int(m.group(2), 0) for m in re.finditer(
        r"pub const (VEC_[A-Z0-9_]+)\s*:\s*(?:usize|u64)\s*=\s*(0x[0-9a-fA-F]+|\d+)", text)}
    if not consts:
        return ["trap.rs 里没解析到任何 `pub const VEC_*`——常量写法变了，本闸会静默空转"]

    reg = ROOT / "docs" / "architecture" / "vectors.toml"
    if not reg.exists():
        return ["缺 docs/architecture/vectors.toml；trap.rs 实测具名向量："
                + str({k: hex(v) for k, v in sorted(consts.items(), key=lambda kv: kv[1])})]
    doc = tomllib.loads(reg.read_text(encoding="utf-8"))
    rows, ranges, meta = doc.get("vector") or [], doc.get("range") or [], doc.get("meta") or {}
    if not rows or not ranges:
        return ["vectors.toml 的 [[vector]] 或 [[range]] 为空：本闸会空转（空表不等于全对）"]
    bad: list[str] = []

    names = [r.get("name") for r in rows]
    if len(set(names)) != len(names):
        bad.append("vectors.toml 有重名条目")
    for n in sorted(set(consts) - set(names)):
        bad.append(f"具名向量 {n}={consts[n]:#x} 在 trap.rs 定义了却没登记")
    for n in sorted(set(names) - set(consts)):
        bad.append(f"登记的 {n} 在 trap.rs 里已不存在（基线过期）")
    for r in rows:
        n, v = r.get("name"), r.get("value")
        if n in consts and v != consts[n]:
            bad.append(f"{n} 登记值 {v} ≠ trap.rs 实测 {consts[n]}（{consts[n]:#x}）")
        if not isinstance(v, int):
            bad.append(f"{n} 的 value 不是整数")
            continue
        idt = r.get("idt")
        if not isinstance(idt, bool):
            bad.append(f"{n} 缺 idt 布尔位（它占的是 IDT 门还是 MSR 入口？）")
        elif idt != (0 <= v < 256):
            bad.append(f"{n}={v:#x} 的 idt={idt} 与取值区间矛盾（只有 0..255 是 IDT 门）")
        stub = r.get("stub", "")
        if not stub:
            bad.append(f"{n} 缺 stub")
        elif stub not in text:
            bad.append(f"{n} 的 stub `{stub}` 在 trap.rs 里找不到（桩改名了？）")
    vals = [r["value"] for r in rows if isinstance(r.get("value"), int)]
    for v in sorted(set(vals)):
        if vals.count(v) > 1:
            bad.append(f"向量号 {v:#x} 被两条登记占用：={[r['name'] for r in rows if r.get('value') == v]}")

    pos = 0
    for lo, hi in sorted((r.get("lo", -1), r.get("hi", -1)) for r in ranges):
        if lo != pos:
            bad.append(f"[[range]] 在 {lo:#x} 处{'与上一段重叠' if lo < pos else '有缺口'}"
                       f"（上一段结束于 {pos:#x}）")
        pos = hi
    if pos != 256:
        bad.append(f"[[range]] 只铺到 {pos:#x}，而 IDT 有 256 个门——新段必须把旧段改掉，不许留洞")

    anchors = {
        "dpl3_gate": (r"v == (VEC_[A-Z0-9_]+)\s*,\s*\n\s*\)", text, "唯一的 DPL3 门", False),
        "frame_bypass": (r"if v == (VEC_[A-Z0-9_]+) \{", text, "不建帧的快路径门", False),
        # 「不发 EOI」不看"提没提到"，只看**分支形状**：on_interrupt 里提前 `return` 的那条
        # 分支才是不发 EOI 的那条。第一版只按名字匹配，结果把 CPU 定时器分支也算了进来
        # （它提到 VEC_CPU_TIMER 但不 return），等于给特例登记面上凭空多一条——已收紧。
        "no_eoi": (r"vector == crate::arch::x86_64::trap::(VEC_[A-Z0-9_]+)", atext,
                   "不发 EOI 的判定（提前 return 的分支）", True),
    }
    for key, (pat, src_text, label, need_return) in anchors.items():
        got = {m.group(1) for m in re.finditer(pat, src_text) if m.group(1) in consts}
        if need_return:
            # 用**花括号配对**取分支体再判 return。旧版是"匹配后 400 字符内找 return"，
            # 两头都会错：分支里加几行注释就把 return 挤出窗口（漏判 0xF0），
            # else-if 链上没有同缩进收尾花括号时又一路吞到后面的 return（误判 0xF3）。
            # 两种都实测发生过（ADR-055），所以换成结构判据。
            early: set[str] = set()
            for m in re.finditer(pat, src_text):
                brace = src_text.find("{", m.end())
                if brace < 0:
                    continue
                depth = 0
                end = brace
                for j in range(brace, min(len(src_text), brace + 4000)):
                    ch = src_text[j]
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            end = j
                            break
                # 剥掉 // 注释再判：分支注释里写"不 return"也会被正则命中（实测误判 0xF3）
                body = chr(10).join(x.split("//", 1)[0] for x in src_text[brace:end].split(chr(10)))
                if re.search(r"\breturn\b", body):
                    early.add(m.group(1))
                    early.add(m.group(1))
            got = early
        base = meta.get(key)
        base = {base} if isinstance(base, str) else set(base or [])
        if not got:
            bad.append(f"源码里没解析到「{label}」的点名（正则失效 = 量具坏了）：{key}")
        elif got != base:
            bad.append(f"「{label}」源码点名 {sorted(got)} ≠ vectors.toml 的 {key}={sorted(base)}"
                       "（加/减一处特例都要两边一起改）")
    return bad


def check_interface_change() -> list[str]:
    """Task E：ADR 最小格式 + 模块接口变更必须有 ADR。

    1) `docs/adr/ADR-<3位>-*.md`：标题编号与文件名一致、编号唯一、有 `状态：` 行且取值合法；
    2) 工作树里 `module-interfaces.toml` / `module-dependencies.md` 有改动时，
       必须同时有 `docs/adr/ADR-*.md` 的改动。

    第 2 条是**提交前**的工作树门禁：干净树不推断历史（见 ADR-039「未决」）。
    """
    adr_dir = ROOT / "docs" / "adr"
    files = sorted(adr_dir.glob("ADR-[0-9][0-9][0-9]-*.md"))
    if not files:
        return ["docs/adr/ 下一份 ADR-<3位>-*.md 都没有：接口变更检查会空转"]
    tokens = ("已采纳", "采纳", "已核实", "部分采纳", "已取代", "提议", "拒绝", "已起草")
    bad: list[str] = []
    seen: dict[str, str] = {}
    for f in files:
        text = f.read_text(encoding="utf-8")
        lines = text.splitlines()
        first = lines[0] if lines else ""
        fm = re.match(r"ADR-(\d{3})-", f.name)
        tm = re.match(r"#\s*ADR-(\d{3})\s*[:：]", first)
        if fm is None:
            bad.append(f"{f.name}: 文件名不是 ADR-<3位>-<标题>.md")
            continue
        num = fm.group(1)
        if tm is None:
            bad.append(f"{f.name}: 首行不是 `# ADR-{num}: <决定>`")
        elif tm.group(1) != num:
            bad.append(f"{f.name}: 标题编号 ADR-{tm.group(1)} 与文件名 ADR-{num} 不一致")
        if num in seen:
            bad.append(f"ADR-{num} 重复：{seen[num]} 与 {f.name}")
        seen[num] = f.name
        m = re.search(r"(?m)^状态\s*[:：]\s*(.+)$", text)
        if m is None:
            bad.append(f"{f.name}: 缺 `状态：` 行（模板见 ADR-template.md）")
        elif not any(tok in m.group(1) for tok in tokens):
            bad.append(f"{f.name}: 状态取值 {m.group(1)[:40]!r} 不在 {tokens}")

    # 接口变更必须带 ADR（工作树门禁）。
    out = subprocess.run(["git", "status", "--porcelain", "-z"], cwd=ROOT,
                         capture_output=True, text=True, env=env())
    if out.returncode != 0:
        bad.append("git status 失败：接口变更检查无法执行")
        return bad
    paths = []
    for entry in out.stdout.split("\0"):
        if len(entry) >= 4 and entry[2] == " ":
            paths.append(entry[3:])
    iface = {"docs/architecture/module-interfaces.toml", "docs/architecture/module-dependencies.md",
             "docs/architecture/vectors.toml"}
    iface_changed = sorted(p for p in paths if p in iface)
    adr_changed = [p for p in paths if re.fullmatch(r"docs/adr/ADR-\d{3}-.*\.md", p)]
    if iface_changed and not adr_changed:
        bad.append(f"{iface_changed} 有未提交改动，但工作树里没有 ADR 改动；"
                   "先按 docs/adr/ADR-template.md 写一份 ADR（接口变更先有决策、后有实现）")
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

    # 撞车的第三种形状，上面两条都盖不住（本轮实测踩过）：判定值那个名字被**别的语句**重新赋过。
    # 现场是 `ov = EVF_OV_RE.search(evlog)` 撞上了 `ov, orc, olog = do_run(["fault-heap-oom"])`
    # ⇒ "L4 堆分配失败"那一行的实际值变成一个 Match 对象，而它的 rc 与日志还是自己那一跑的，
    # 所以那一行报"不符合"、别的行全绿——看起来像被测物坏了，其实是量具在互相覆盖。
    # 判定值这一路静态上不好归一（很多行写的是 `"FAIL" if loop_ok else "SEQ-BROKEN"` 这种算式），
    # 所以只查可判的那一半：被 `do_run` 三元组接过的名字不许再被别的语句赋，反过来也一样。
    dt = re.search(r"^def do_test\(.*?\n(?=^def [A-Za-z_])", src, re.M | re.S)
    if not dt:
        bad.append("没找到 `def do_test` 的函数体（本门禁的变量对账靠它，找不着就是空转）")
    else:
        body = dt.group(0)
        # 判的是**次序**：先接住 `do_run` 的证据、后被别的赋值覆盖，才是那一类事故。
        # 反过来的那种（先写占位 `strc = -1` 与 `stv, stlog = "HANG", ""`，要带负载时再由
        # `do_run` 覆盖）是有界窗口被 `STORM_TIMEOUT=0` 跳过时留给那一行打数的，有意设计；
        # 把它一起报红就是误伤，而误伤的门禁活不过下一次改动。
        evidence: set[str] = set()
        seen_any = False
        clash: set[str] = set()
        # `^\s*` 不是可有可无的：赋值行全在函数体里带缩进，从行首直接匹配的话两边都会是空的，
        # 而这条对账就变成**静默绿**——正是它要抓的那种错（本轮第一版写完就是这样，`check` 照样 ok）。
        # 所以下面还要单独自查"到底解析出东西没有"。
        for m in re.finditer(r"^\s*(\w+(?:\s*,\s*\w+)*)\s*=\s*(.*)$", body, re.M):
            targets = {x.strip() for x in m.group(1).split(",") if x.strip()}
            seen_any = True
            if "do_run(" in m.group(2):
                evidence |= targets
                continue
            clash |= targets & evidence
            evidence -= targets      # 覆盖之后它就不再是证据了；再被 `do_run` 赋一次算新的
        if not seen_any:
            bad.append("do_test 函数体里一条赋值都没解析出来 ⇒ 下面这两条对账整体空转"
                       "（缩进或写法变了？改了它就同时改这里）")
        if not evidence:
            bad.append("do_test 里一条 `x, y, z = do_run(...)` 都没解析出来 ⇒ 本条对账空转")
        if clash:
            bad.append(f"do_test 里这些名字接住 `do_run` 之后又被别的语句覆盖：{sorted(clash)}"
                       " —— 某一行的实际值因此不再是自己那一跑的（本轮的 `ov` 变成 Match 对象，"
                       "那一行报不符合而它的退出码与日志都是对的）")
    return bad


def check_virtio_pattern() -> list[str]:
    """夹具图案字节：宿主机写进 qcow2 的那个数，与内核用例里期望的那个数，必须机器对账。

    这不是洁癖 —— 写这条门禁的时候我先把内核侧填成了 `0x5A`，而夹具是 `0x5C`：
    没有这道对账，那条判据会**当场红一次**（红是对的方向），但更常见的情节是有人为了让它绿
    去改其中一边，从此这条判据只在"两边一起改"时才红，而那是它唯一不需要证明的事。
    """
    rs = (ROOT / "kernel" / "src" / "ktests" / "virtio.rs").read_text(encoding="utf-8")
    m = re.search(r"const EXPECT_PATTERN: u8 = 0x([0-9A-Fa-f]{2})", rs)
    if m is None:
        return ["内核侧没找到 EXPECT_PATTERN（改名了？用例在 virtio-blk 变体里，常量必须留在 ktests/virtio.rs）"]
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
    ("aurora_kernel", "ktests", "crash", "t_crash_oops"),   # T0.1 搬进 ktests/crash 出事那一帧：必须落在故意越界的那个函数里
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



def l4_exit_cascade(log: str, first_anchor: str) -> tuple[bool, str]:
    """P7a / ADR-060：致命故障停在**持锁现场**时，退出路径不许再级联出第二条 L4。

    现场（改前实测）：`fault-lock-reentrant` 与 `fault-shootdown-noack` 两档各打两条 L4 ——
    第一条是被注入的那个故障，第二条是退出路径上的 `锁序违规，外层 rank=10/20 本次 rank=8`
    （致命路径还在持锁，`preempt_point` 去取 RUNQ(8)）。第二条污染崩溃记录：
    `crash.thread_id` 走的是会取锁的那条路，于是记录里那一格也不是出事任务的。

    判据只查"级联"这一件事，不查故障本身（那是那一行的退出码在管）：
    * 必须有锚点行，否则注入根本没走到 —— 那是量具没咬，不许算绿；
    * 锚点之后**到日志末尾**不许再出现 `L4 sync: 锁序违规`。锚点之前也不查：
      将来若有别的用例故意造锁序违规，那不是这条判据要管的事。
    """
    i = log.find(first_anchor)
    if i < 0:
        return False, f"这一跑没有锚点 `{first_anchor}` ⇒ 注入没走到，判据不算数"
    tail = log[i:]
    n = tail.count("L4 sync: 锁序违规")
    if n:
        return False, f"锚点之后还有 {n} 条 `L4 sync: 锁序违规` ⇒ 退出路径级联又回来了"
    return True, "锚点在，锚点之后无级联"


# 欠账⑦ / ADR-062：resched IPI 失败注入那一跑的见证行。四个数都要由宿主机独立解出来，
# 不是读内核那个 bool：失败计数涨（f1>f0）、收到的 IPI 为 0、消费者跑完（done=1）、ack 不超时。
RIF_RE = re.compile(
    r"resched IPI失败注入\(ADR-062\): ack超时=(?P<ack>\d+) 完成=(?P<done>\d+) "
    r"失败计数 (?P<f0>\d+)->(?P<f1>\d+) 收到IPI=(?P<ipi>\d+)")


def check_resched_ipi_fail(log: str) -> tuple[bool, str]:
    m = RIF_RE.search(log)
    if m is None:
        return False, "没找到见证行 ⇒ 注入用例没跑到（判据不算数，不许算绿）"
    ack, done = int(m.group("ack")), int(m.group("done"))
    f0, f1, ipi = int(m.group("f0")), int(m.group("f1")), int(m.group("ipi"))
    if ack != 0:
        return False, f"ack超时={ack} ⇒ 相位没跑完"
    if done != 1:
        return False, f"完成={done} ⇒ 消费者没跑完，丢唤醒了"
    if f1 <= f0:
        return False, f"失败计数 {f0}->{f1} 没涨 ⇒ 计数没咬（注入没走到 Err 分支）"
    if ipi != 0:
        return False, f"收到IPI={ipi} ⇒ 注入没把 IPI 打掉，这条构建没在量它声称的东西"
    return True, f"失败计数 {f0}->{f1} 收到IPI=0 完成=1 ack=0"


# ADR-066 / W2 P4：split/map_hole 的见证行。宿主机逐字段独立解，不是读内核的 bool；
# leaf 属性位由宿主机按 SDM/PAT 规则重算（第二台仪器），内核绿而对不上 ⇒ CONTENT-MISMATCH。
SPLIT_P4_RE = re.compile(
    r"split\(P4\): 等价=(?P<eq>true|false) 金丝雀=(?P<can>true|false) 跨别名=(?P<cross>true|false) "
    r"幂等=(?P<idem>true|false) map成功=(?P<map>true|false) 永久PT=(?P<pt>\d+) requests增量=(?P<req>\d+)")
MAP_HOLE_P4_RE = re.compile(
    r"map_hole\(P4\): 单属性=(?P<single>true|false) 拒覆盖=(?P<cov>true|false) 拒usable=(?P<us>true|false) "
    r"往返=(?P<rt>true|false) leaf=(?P<leaf>0x[0-9a-f]+)")
SPLIT_OOM_P4_RE = re.compile(
    r"split OOM\(P4\): err=(?P<err>\w+) 原样=(?P<intact>true|false) 回基线=(?P<back>true|false)")


def check_split_p4(log: str) -> list[str]:
    m = SPLIT_P4_RE.search(log)
    if m is None:
        return ["没找到 split(P4) 见证行 ⇒ 用例没跑到（判据不算数，不许算绿）"]
    bad = []
    for g in ("eq", "can", "cross", "idem", "map"):
        if m.group(g) != "true":
            bad.append(f"split(P4) {g}={m.group(g)}")
    # 用例拆两个块（被测块 + HHDM 尾块，尾页做 unmap/map 验收，见 ADR-066 落地记录）
    if int(m.group("pt")) != 2:
        bad.append(f"永久PT={m.group('pt')} ≠ 2（页表页台账）")
    if int(m.group("req")) != 2:
        bad.append(f"requests增量={m.group('req')} ≠ 2（shootdown 协议计数）")
    return bad


def check_map_hole_p4(log: str) -> list[str]:
    m = MAP_HOLE_P4_RE.search(log)
    if m is None:
        return ["没找到 map_hole(P4) 见证行 ⇒ 用例没跑到"]
    bad = []
    for g in ("single", "cov", "us", "rt"):
        if m.group(g) != "true":
            bad.append(f"map_hole(P4) {g}={m.group(g)}")
    # 宿主机独立重算：IOAPIC pa | P | W | PCD(UC-) | NX，与内核读回的叶子原始值对账
    want = 0xFEC00000 | 0x1 | 0x2 | 0x10 | (1 << 63)
    if int(m.group("leaf"), 16) != want:
        bad.append(f"leaf={m.group('leaf')} 宿主机重算={want:#x}（UC- 属性位）")
    return bad


def check_split_oom_p4(log: str) -> tuple[bool, str]:
    m = SPLIT_OOM_P4_RE.search(log)
    if m is None:
        return False, "没找到 split OOM(P4) 见证行 ⇒ 注入没跑到"
    if m.group("err") != "OutOfMemory":
        return False, f"err={m.group('err')} ≠ OutOfMemory"
    if m.group("intact") != "true" or m.group("back") != "true":
        return False, f"原样={m.group('intact')} 回基线={m.group('back')}"
    return True, "OOM 被传播、原页原样、台账回基线"


# ADR-067 / W2 P5：demand-zero 见证行。修复计数=+2 的账目：ring3 首触 1 页 + 竞争格 1 页；
# 竞争者按"真的就位"数（participant_slots 的 ticks>0 前提在本用例调用时刻可能未成立，实测）。
DZ_P5_RE = re.compile(
    r"demand-zero\(P5\): 修复计数=(?P<cnt>\+\d+) 首读全0=(?P<zero>true|false) 区间外仍杀=(?P<kill>true|false) "
    r"copy不修=(?P<copy>true|false) 取指仍杀=(?P<fetch>true|false) 竞争填充=(?P<fill>\d+) "
    r"输家还帧=(?P<lost>\d+) 独占账回0=(?P<ledger>true|false) 退出回基线=(?P<back>true|false) "
    r"就位=(?P<ready>\d+) 发令=(?P<start>true|false) 回执=(?P<rets>\d+) 持页=(?P<holds>true|false) ack=(?P<ack>true|false)")


def check_demand_zero_p5(log: str, require_losers: bool = False) -> list[str]:
    m = DZ_P5_RE.search(log)
    if m is None:
        return ["没找到 demand-zero(P5) 见证行 ⇒ 用例没跑到（判据不算数，不许算绿）"]
    bad = []
    if m.group("cnt") != "+2":
        bad.append(f"修复计数={m.group('cnt')} ≠ +2（ring3 1 页 + 竞争 1 页）")
    for g in ("zero", "kill", "copy", "fetch", "ledger", "back", "start", "holds", "ack"):
        if m.group(g) != "true":
            bad.append(f"demand-zero(P5) {g}={m.group(g)}")
    if m.group("fill") != "1":
        bad.append(f"竞争填充={m.group('fill')} ≠ 1（四路只能填进一页）")
    ready, rets = int(m.group("ready")), int(m.group("rets"))
    if ready < 1:
        bad.append(f"就位={ready} ⇒ 竞争格没有 AP 参与，判据空转")
    if rets != ready + 1:
        bad.append(f"回执={rets} ≠ 就位+1={ready + 1}（BSP 自己那一路）")
    if require_losers and int(m.group("lost")) < 1:
        bad.append(f"输家还帧={m.group('lost')} ⇒ race-demand-zero 下没有真输家，重叠没构造出来")
    return bad


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


PIT_MARK_LINE = "pit_ioport_write [0x3] <- 0x0"   # QEMU 打 `0x0` 不补零（实测）
V32_LINE = re.compile(r"^apic_deliver_irq dest \d+ dest_mode \d+ delivery_mode \d+ vector 32 ")
TIMER_W1 = re.compile(r"timer: ticks \d+ -> \d+ \(第一段 (?P<t>\d+) ticks cycles=(?P<c>\d+) "
                      r"轮数=\d+ 游标=\S+\.\.\S+\)")
TIMER_REC = re.compile(r"recurring=(\w+)")
TIMER_MARKS = re.compile(r"timer 游标: 段1=(?P<a>\S+)\.\.(?P<b>\S+) 段2=(?P<c>\S+)\.\.(?P<d>\S+)")
TIMER_W2 = re.compile(r"second_window=\d+ \(第二段 (?P<t>\d+) ticks cycles=(?P<c>\d+) 轮数=\d+\)")
INTERVAL_MEAN = re.compile(r"clock 判据: .*interval_mean=(?P<v>\d+)")


def window_deliveries(src: Path, cap: int = 12_000_000) -> tuple[int, int, int]:
    """拿 PIT latch 游标把 trace 切成窗口段，数里面投了几发 vector 32。

    返回 `(第一段窗口内投递, 第二段窗口内投递, 全跑投递)`。游标不够就返回 `-1`：
    调用方**必须**把"证人不在场"与"窗口内一发都没投"分开——后者是事实，前者是盲区。
    （`-trace` 清单写坏时 QEMU 只 warning 就带零事件启动，这条就是那一族的兜底。）

    段与段之间靠**游标的先后**分，不靠时间戳：simple trace 后端不打时间戳（实测），
    而Latch 命令在 trace 里的形状唯一（`[0x3] <- 0x0`，QEMU 打 `0x0` 不补零），
    所以第 1、2 个游标之间就是第一段，第 3、4 个之间就是第二段。
    """
    marks: list[int] = []
    hits: list[int] = []
    n = 0
    with src.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            n += 1
            if n > cap:
                break
            s = line.strip()
            if s == PIT_MARK_LINE:
                marks.append(n)
            elif V32_LINE.match(s):
                hits.append(n)
    d1 = sum(1 for h in hits if marks[0] < h < marks[1]) if len(marks) >= 2 else -1
    d2 = sum(1 for h in hits if marks[2] < h < marks[3]) if len(marks) >= 4 else -1
    return d1, d2, len(hits)


def aurora_pit_divisor() -> int:
    """PIT 分频只有一份来源：内核 `clock.rs` 的 `PIT_DIVISOR`。
    宿主机不自己写死 11932——写死就是凭记忆改硬件常数，那一族错的源头。"""
    m = re.search(r"pub const PIT_DIVISOR: u64 = ([0-9_]+);",
                  (ROOT / "kernel" / "src" / "clock.rs").read_text(encoding="utf-8"))
    if not m:
        raise SystemExit("clock.rs 里找不到 PIT_DIVISOR ⇒ 设备侧超速的上界没有依据，拒绝判定")
    return int(m.group(1).replace("_", ""))


def check_timer_window(log: str, src: Path) -> tuple[list[str], str]:
    """两段窗口各记两本账：窗口内**取到**几发（内核）与窗口内**投出**几发（控制器）。

    这四格是 ADR-036 那条"窗口长度必须是时间单位"的续集。`recurring` 原来要求
    "两个 tick 周期的墙上时间里取到 2 发"，而这台 QEMU 的 PIT 是**短脉冲 + 电平线**：
    vCPU 被宿主按住时投递照样发生，但 IRR 只有一个位，攒下的会被合并。
    ⇒ "取到 ≥ 2"在可抢占的宿主上不是"紧"，是**形状错了**。换成两条能判的：

    * `T ≤ D`：每一发处理都必须先有一次投递；合并只让 D 多，不会让 T 多。
    * `D ≤ ⌈窗口 cycles ÷ 周期⌉ + 1`：设备不可能比 PIT 自己的 100 Hz 还快。
      周期取标定读出的相邻间隔均值（`clock 判据` 那行的 `interval_mean=`），
      分频常数从内核 `clock.rs` 读回来（不写死）。

    再加两条管仪器自己在不在场：游标读不到 ⇒ **不许豁免也不许读成"没投"**；
    latch 回来的计数出格 ⇒ 通道 0 不是那个 100 Hz 速率发生器，相位与上界都失去依据。
    """
    bad: list[str] = []
    mw1 = TIMER_W1.search(log)
    if not mw1:
        return ["串口里没有带游标的 `timer: ticks … (第一段 … 游标=… 收尾=…)` ⇒ "
                "内核侧的窗口取数或游标读数没打出来"], "内核侧读数缺失"
    mi = INTERVAL_MEAN.search(log)
    if not mi:
        return ["没有 `clock 判据: … interval_mean=` ⇒ 窗口时长没有可比的时间单位"], "标定侧读数缺失"
    mrec = TIMER_REC.search(log)
    m_w2 = TIMER_W2.search(log)
    taken, wcycles = int(mw1.group("t")), int(mw1.group("c"))
    taken2, cyc2 = (int(m_w2.group("t")), int(m_w2.group("c"))) if m_w2 else (-1, -1)
    period = int(mi.group("v"))
    d1, d2, d_all = window_deliveries(src)
    if not m_w2:
        bad.append("串口里没有第二段窗口那半行（`second_window=… (第二段 … 轮数=…)`）⇒ 少一段可比的两本账")
    for name, tk, cyc, d in (("第一段", taken, wcycles, d1), ("第二段", taken2, cyc2, d2)):
        if tk < 0:
            continue
        if d < 0:
            bad.append(f"{name}窗口的游标读不到（全跑投递 {d_all} 条在）⇒ 证人不在场，"
                       f"这一格不许豁免，也不许读成「窗口里没投」")
            continue
        if d == 0:
            bad.append(f"{name}窗口里控制器一发都没投（取到 {tk}）⇒ 这一格在量它没有的东西")
        if tk > d:
            bad.append(f"{name}窗口层间方向破了：取到 {tk} > 投出 {d}（每一发处理都必须先有一次投递）")
        ceiling = -(-cyc // max(period, 1)) + 1
        if d > ceiling:
            bad.append(f"{name}窗口设备侧超速：{cyc} cycles 内投了 {d} 发，"
                       f"按周期 {period} cycles/发推出来的上界是 {ceiling}")
    mmarks = TIMER_MARKS.search(log)
    if not mmarks:
        bad.append("串口里没有 `timer 游标: 段1=… 段2=…` 那行 ⇒ 段边界没有依据，两本账切不出来")
    else:
        for grp in ("a", "b", "c", "d"):
            if mmarks.group(grp) == "None":
                bad.append(f"游标 {grp} 读数出格（latch 回来的计数不在 [1, {aurora_pit_divisor()}]）"
                           f"⇒ 通道 0 不是那个 100 Hz 速率发生器，段边界与上界都失去依据")
                break
    if mrec and mrec.group(1) == "false" and (d1 < 0 or d2 < 0):
        bad.append("recurring=false 而证人读不到 ⇒ 这条红既不能定罪也不能豁免，先修仪器")
    return bad, (f"第一段 取到={taken} 投出={d1} ／ 第二段 取到={taken2} 投出={d2} "
                 f"(窗口 cycles={wcycles}/{cyc2}，周期={period}，上限="
                 f"{-(-wcycles // max(period, 1)) + 1}/{-(-cyc2 // max(period, 1)) + 1}) "
                 f"游标={mmarks.group('a')}..{mmarks.group('b')}|{mmarks.group('c')}..{mmarks.group('d')} "
                 f"全跑投出={d_all} recurring={mrec.group(1) if mrec else '?'}")


def do_check(elf: Path | None) -> int:
    gates = {
        "check-lints-wired": lambda: check_lints_wired(),
        "check-unsafe": lambda: check_unsafe_registry(),
        "check-crates": lambda: check_crates_listed(),
        "check-module-interfaces": lambda: check_module_interfaces(),
        "check-vector-table": lambda: check_vector_table(),
        "check-interface-change": lambda: check_interface_change(),
        "check-driver-ctx": lambda: check_driver_no_raw(),
        "check-state-window": lambda: check_state_window(),
        "check-virtio-pattern": lambda: check_virtio_pattern(),
        "check-fat32-ports": lambda: check_fat32_ports(),
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

def check_probe_elf(log: str) -> list[str]:
    """探针夹具的**宿主机侧独立对账**（第二台仪器，§156/§160 欠的那条）。

    内核那侧的装载器自己报 `segs/pages/entry/data/夹具字节数`，它的判据比的是"自己算的和自己写的"。
    这里用 Python 独立解析 `kernel/fixtures/probe.elf` 的 ELF64 程序头再算一遍同样的四个数：
      segs  = PT_LOAD 且 memsz>0 的段数
      pages = Σ ceil(p_memsz / 4096)
      entry = e_entry
      data  = **第一个可写** PT_LOAD 段的 p_vaddr（内核 `user::load` 就是这个口径）
    两边不一致就是 CONTENT-MISMATCH：可能是装载器数错了，也可能是夹具被换过而日志没跟上。
    """
    bad: list[str] = []
    m = re.search(
        r"probe: segs=(\d+) pages=(\d+) entry=(0x[0-9a-f]+) data=(0x[0-9a-f]+) "
        r"stack_top=(0x[0-9a-f]+) 夹具=(\d+)B",
        log,
    )
    if not m:
        return ["内核没报探针的装载几何（segs/pages/entry/data/夹具），宿主机对账没有对象"]
    k_segs, k_pages = int(m.group(1)), int(m.group(2))
    k_entry, k_data, k_size = int(m.group(3), 16), int(m.group(4), 16), int(m.group(6))
    if not PROBE_FIXTURE.exists():
        return [f"夹具不在：{PROBE_FIXTURE}"]
    b = PROBE_FIXTURE.read_bytes()
    if len(b) != k_size:
        bad.append(f"夹具字节数：内核说 {k_size}，宿主机读到的文件是 {len(b)}")
    if b[:4] != b"\x7fELF" or b[4] != 2:
        return bad + ["夹具不是 ELF64，宿主机没法独立解析"]
    e_entry = struct.unpack_from("<Q", b, 0x18)[0]
    e_phoff = struct.unpack_from("<Q", b, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", b, 0x36)[0]
    e_phnum = struct.unpack_from("<H", b, 0x38)[0]
    segs = 0
    pages = 0
    first_w = None
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", b, o)[0]
        if p_type != 1:  # PT_LOAD
            continue
        p_flags = struct.unpack_from("<I", b, o + 4)[0]
        p_vaddr = struct.unpack_from("<Q", b, o + 0x10)[0]
        p_memsz = struct.unpack_from("<Q", b, o + 0x28)[0]
        if p_memsz == 0:
            continue
        segs += 1
        pages += (p_memsz + 4095) // 4096
        if first_w is None and (p_flags & 2):  # PF_W
            first_w = p_vaddr
    if segs != k_segs:
        bad.append(f"段数：宿主机数出 {segs} 个 PT_LOAD，内核报 {k_segs}")
    if pages != k_pages:
        bad.append(f"页数：宿主机按 Σceil(memsz/4096) 算出 {pages}，内核报 {k_pages}")
    if e_entry != k_entry:
        bad.append(f"入口：ELF 头里是 {e_entry:#x}，内核报 {k_entry:#x}")
    if first_w is None:
        bad.append("宿主机没找到任何可写 PT_LOAD 段，data_va 无从对账")
    elif first_w != k_data:
        bad.append(f"第一个可写段：宿主机算出 {first_w:#x}，内核报 {k_data:#x}")
    return bad


def gpt_host_report(path: Path) -> tuple[dict[str, str], list[str]]:
    """调**独立那一台**（validate_esp.py --report）从指定盘重算 GPT 事实。

    它不 import 内核、也不 import esp_image 的写表常量；这里只负责把它的 key=value 收回来，
    并守住"这台仪器自己空转/崩了"两种情况——都不许当成"对上了"。
    """
    if not path.exists():
        return {}, [f"盘不在：{path}（对账必须吃同一跑的那块盘）"]
    out = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "validate_esp.py"), str(path), "--report"],
        capture_output=True, text=True, encoding="utf-8", env=env())
    if out.returncode != 0:
        return {}, [f"validate_esp.py --report 退出 {out.returncode}：{out.stderr.strip()[:200]}"]
    host = dict(ln.split("=", 1) for ln in out.stdout.splitlines() if "=" in ln)
    if len(host) < 20:
        return {}, [f"宿主机只解析出 {len(host)} 个字段（应当 >= 20）⇒ 这台仪器自己空转了"]
    return host, []


def check_gpt_fixture(log: str) -> list[str]:
    """夹具盘（口 1）那一半的对账：六条改盘负样本的载体，正向跑必须与宿主机逐格相同。

    与引导盘那一半分开比，因为两块盘的几何与分区数不同（夹具盘故意放**两条不同类型**的分区，
    只放一条的话"按 GUID 找对了"与"返回了第一条"长得一样）。
    """
    bad: list[str] = []
    mh = re.search(
        r"gptfix: 头 口(\d+) revision=(0x[0-9a-f]+) header_size=(\d+) my_lba=(\d+) "
        r"alternate_lba=(\d+) first_usable=(\d+) last_usable=(\d+) entry_lba=(\d+) "
        r"entry_count=(\d+) entry_size=(\d+) header_crc=(0x[0-9a-f]+) array_crc=(0x[0-9a-f]+)", log)
    mt = re.search(
        r"gptfix: 表 扫过=(\d+) 非空=(\d+) 回调=(\d+) 数组字节=(\d+) 自算CRC=(0x[0-9a-f]+) "
        r"备份my_lba=(\d+) 备份alternate_lba=(\d+) disk_guid=\[([0-9a-f, ]+)\]", log)
    me = re.search(
        r"gptfix: ESP 序号=(\d+) first=(\d+) last=(\d+) attrs=(0x[0-9a-f]+) "
        r"type=\[([0-9a-f, ]+)\] unique=\[([0-9a-f, ]+)\]", log)
    md = re.search(
        r"gptfix: 另一条 序号=(\d+) first=(\d+) last=(\d+) attrs=(0x[0-9a-f]+) "
        r"type=\[([0-9a-f, ]+)\] unique=\[([0-9a-f, ]+)\]", log)
    if not (mh and mt and me and md):
        miss = [n for n, m in (("头", mh), ("表", mt), ("ESP", me), ("另一条", md)) if not m]
        return [f"内核没报齐夹具盘的 GPT 读数（缺 {'/'.join(miss)} 行）⇒ 对账没有对象"]
    # 期望来自**配方**而不是当前盘：注入是在跑之前改盘的，期望跟着当前盘走就两边同数、永远绿。
    host, errs = gpt_host_report(gpt_recipe_file())
    if errs:
        return errs
    required = ["signature", "mbr_type", "revision", "header_size", "header_crc", "header_crc_calc",
                "my_lba", "alternate_lba", "first_usable", "last_usable", "disk_guid", "entry_lba",
                "entry_count", "entry_size", "array_crc", "array_crc_calc", "array_bytes", "seen",
                "used", "esp_index", "esp_type", "esp_unique", "esp_first", "esp_last", "esp_attrs",
                "part1_index", "part1_type", "part1_unique", "part1_first", "part1_last",
                "backup_present", "backup_my_lba", "backup_alternate_lba", "problems"]
    missing = [k for k in required if k not in host]
    if missing:
        probs = "; ".join(v for k, v in host.items() if k.startswith("problem") and k != "problems")
        return [f"宿主机报告缺字段 {missing}（它自己发现的问题：{probs or '无'}）"]

    def hexbytes(s: str) -> str:
        return "".join(re.findall(r"[0-9a-f]{2}", s))

    def eq(tag: str, k, h) -> None:
        if k != h:
            bad.append(f"夹具盘 {tag}：内核={k} 宿主机={h}")

    eq("口号", GPT_FIX_PORT, int(mh.group(1)))
    eq("revision", int(mh.group(2), 16), int(host["revision"]))
    for tag, ki, hk in (
        ("header_size", 3, "header_size"), ("my_lba", 4, "my_lba"),
        ("alternate_lba", 5, "alternate_lba"), ("first_usable", 6, "first_usable"),
        ("last_usable", 7, "last_usable"), ("entry_lba", 8, "entry_lba"),
        ("entry_count", 9, "entry_count"), ("entry_size", 10, "entry_size"),
    ):
        eq(tag, int(mh.group(ki)), int(host[hk]))
    eq("头CRC(盘上写的)", int(mh.group(11), 16), int(host["header_crc"], 16))
    eq("头CRC(自己算的)", int(mh.group(11), 16), int(host["header_crc_calc"], 16))
    eq("数组CRC(盘上写的)", int(mh.group(12), 16), int(host["array_crc"], 16))
    eq("数组CRC(内核流式算的)", int(mt.group(5), 16), int(host["array_crc_calc"], 16))
    eq("数组字节数", int(mt.group(4)), int(host["array_bytes"]))
    eq("扫过条目数", int(mt.group(1)), int(host["seen"]))
    eq("非空条目数", int(mt.group(2)), int(host["used"]))
    eq("回调次数(独立recount)", int(mt.group(3)), int(host["used"]))
    eq("disk_guid", hexbytes(mt.group(8)), host["disk_guid"])
    eq("备份my_lba", int(mt.group(6)), int(host["backup_my_lba"]))
    eq("备份alternate_lba", int(mt.group(7)), int(host["backup_alternate_lba"]))
    eq("ESP序号", int(me.group(1)), int(host["esp_index"]))
    eq("ESP first_lba", int(me.group(2)), int(host["esp_first"]))
    eq("ESP last_lba", int(me.group(3)), int(host["esp_last"]))
    eq("ESP attrs", int(me.group(4), 16), int(host["esp_attrs"], 16))
    eq("ESP type GUID", hexbytes(me.group(5)), host["esp_type"])
    eq("ESP unique GUID", hexbytes(me.group(6)), host["esp_unique"])
    eq("另一条序号", int(md.group(1)), int(host["part1_index"]))
    eq("另一条 first_lba", int(md.group(2)), int(host["part1_first"]))
    eq("另一条 last_lba", int(md.group(3)), int(host["part1_last"]))
    eq("另一条 type GUID", hexbytes(md.group(5)), host["part1_type"])
    eq("另一条 unique GUID", hexbytes(md.group(6)), host["part1_unique"])
    eq("宿主机自己发现的问题数", 0, int(host["problems"]))
    mj = re.search(r"gptfix: 判据 [^\n]*", log)
    if not mj:
        bad.append("内核没报夹具盘的判据那一行")
    elif "false" in mj.group(0):
        bad.append(f"夹具盘判据里有 false：{mj.group(0).strip()[:170]}")
    return bad


def gpt_recipe_bytes() -> bytes:
    """夹具盘的**配方字节**（现算，不读 build/ 里那份可能已经被改过的镜像）。

    与 `fat_host_fault_plan` 读 `.img.zz` 是同一条纪律：定位注入点与核"盘真被改成了这个样子"
    两次算的必须是同一个数，而那个数不能来自已经被改过的那份。
    """
    import hashlib
    sys.path.insert(0, str(ROOT / "tools"))
    import make_gpt_disk  # noqa: E402
    data = make_gpt_disk.build()
    got = hashlib.sha256(data).hexdigest()
    if got != GPT_FIX_SHA256:
        raise ValueError(f"配方指纹变了：{got} != {GPT_FIX_SHA256}（要连用例与对账的期望一起重量）")
    return data


def gpt_recipe_file() -> Path:
    """把配方写成一份文件，供**独立那一台**（validate_esp.py）去读。

    对账的期望必须来自配方而不是当前盘：注入是在跑之前改盘的，若期望也跟着当前盘走，
    内核与宿主机读的是同一块改过的盘 ⇒ 两边同数 ⇒ 那条负样本永远绿。
    """
    GPT_RECIPE.write_bytes(gpt_recipe_bytes())
    return GPT_RECIPE


def gpt_host_fault_plan(kind: str) -> tuple[list[tuple[int, bytes, bytes]], str]:
    """定位一条 GPT 改盘注入：返回 ([(偏移, 现值, 新值)], 封 CRC 的方式)。

    改哪一格**由解析算出来**，不写死镜像偏移（ADR-038 决策 9 的纪律：夹具重建后
    写死的偏移会静默改到别处，而负样本照样红）。命中不唯一 / 改了等于没改 ⇒ 抛 ValueError，
    红在跑之前而不是跑完之后对着一行 FAIL 猜。
    """
    import binascii
    b = gpt_recipe_bytes()
    g = b[512:512 + 92]
    entry_lba = struct.unpack_from("<Q", g, 72)[0]
    count = struct.unpack_from("<I", g, 80)[0]
    esize = struct.unpack_from("<I", g, 84)[0]
    alt = struct.unpack_from("<Q", g, 32)[0]
    arr = entry_lba * 512
    boff = alt * 512
    # 备份阵列的 LBA 从**备份头自己说的** entry_lba 取，不靠"主头 alternate 减 32"推算。
    barr = struct.unpack_from("<Q", b, boff + 72)[0] * 512
    if kind == "fault-gpt-array-crc":
        # **主备两份一起翻**：只改主份的话 EDK2 会拿备份把它修回去（实测跑完盘回到 pristine，
        # 注入根本到不了内核）。两份都坏 ⇒ 固件无从修起 ⇒ 盘活着进内核，红在数组 CRC 那道闸。
        if b[arr] != b[barr]:
            raise ValueError("主备阵列的第一个字节不同 ⇒ 这条注入要重新量")
        return [(arr, bytes([b[arr]]), bytes([b[arr] ^ 0x01])),
                (barr, bytes([b[barr]]), bytes([b[barr] ^ 0x01]))], "none"
    if kind == "fault-gpt-header-crc":
        at, bat = 512 + 40, boff + 40      # first_usable 的低字节，主备各一处
        if b[at] != b[bat]:
            raise ValueError("主备头的 first_usable 低字节不同 ⇒ 这条注入要重新量")
        return [(at, bytes([b[at]]), bytes([b[at] ^ 0x01])),
                (bat, bytes([b[bat]]), bytes([b[bat] ^ 0x01]))], "none"
    if kind == "fault-gpt-mbr-type":
        at = 446 + 4
        if b[at] != 0xEE:
            raise ValueError(f"保护性 MBR 的类型字节是 {b[at]:#x} 不是 0xEE ⇒ 这条注入是空转")
        return [(at, b"\xee", b"\x0c")], "none"
    if kind == "fault-gpt-backup-mismatch":
        # **这一条做不成改盘负样本（实测）**：只要主表是好的，EDK2 就会拿它把备份修回去
        # （跑完盘回到 pristine）；反过来改主表则它拿备份修主表。两份都好但字段不一致时
        # 它挑主表、重写备份 ⇒ 无论怎么改，内核读到的都是一致的两份。
        # 该闸由**同一份 ELF 里的合成盘**证到（ktests/gpt.rs 的 16 格之一，BackupMismatch 点名）。
        raise ValueError("备份不一致必然被固件治愈（实测：跑完盘回到 pristine）⇒ 改盘证不到这一格，"
                         "它由同一份 ELF 里的合成盘证；不要为了凑六条而把这条做成空转")
    if kind == "fault-gpt-entry-count":
        at, bat = 512 + 80, boff + 80
        old = struct.unpack_from("<I", b, at)[0]
        if old != 128 or struct.unpack_from("<I", b, bat)[0] != old:
            raise ValueError(f"entry_count 主={old} 备={struct.unpack_from('<I', b, bat)[0]}，要两份都是 128")
        # 主备一起改 + 两份都重封头 CRC ⇒ 固件两份都算不过数组 CRC，无从修起。
        return [(at, struct.pack("<I", old), struct.pack("<I", 129)),
                (bat, struct.pack("<I", old), struct.pack("<I", 129))], "headers"
    if kind == "fault-gpt-esp-first":
        at = arr + 32                      # 第 0 条（ESP）的 first_lba
        old = struct.unpack_from("<Q", b, at)[0]
        if old != 34:
            raise ValueError(f"夹具 ESP first_lba 是 {old} 不是 34 ⇒ 夹具变了")
        # 改完**把两个 CRC 都重算** ⇒ 解析必须成功、内核 bool 全绿，红只能红在宿主机对账上。
        return [(at, struct.pack("<Q", old), struct.pack("<Q", old + 1))], "recrc"
    raise ValueError(f"不认识的 GPT 注入：{kind}")


def _gpt_seal(b: bytearray, off: int) -> None:
    import binascii
    b[off + 16:off + 20] = b"\x00" * 4
    struct.pack_into("<I", b, off + 16, binascii.crc32(bytes(b[off:off + 92])) & 0xFFFFFFFF)


def check_sign_boot(log: str, want_ok: bool, want_reason: str = "") -> list[str]:
    """启动路径验签那一行的判据（W4 S3，ADR-080）。

    三件事都要在：①那一行存在且前缀对；②通过/被拒与期望一致，被拒时**理由与附带都要点名**；
    ③`拒启=false` 显式在行里。**第③条是"只检测不拒启"这个决定的证人**：
    若实现偷偷拒启，判定值会从 PASS 变成 BOOT-INVALID，那一行矩阵自己就红了；
    而"日志里没写拒启"不算证据（日志缺失会被读成"没拒启"），所以要求它显式打出来。
    """
    bad: list[str] = []
    if want_ok:
        m = re.search(r"sign-boot: 验签通过 载荷字节=(\d+) 读盘次数=(\d+) 包字节=(\d+) "
                      r"起始LBA=(\d+) 拒启=(true|false)", log)
        if m is None:
            return ["启动日志里没有 `sign-boot: 验签通过 … 拒启=…` 那一行 ⇒ 验签没进启动路径"]
        if m.group(5) != "false":
            bad.append(f"sign-boot 拒启={m.group(5)}（ADR-080 决定只检测不拒启）")
        if int(m.group(2)) < 1:
            bad.append(f"sign-boot 读盘次数={m.group(2)} ⇒ 没真读盘")
        return bad
    m = re.search(r"sign-boot: 验签被拒 理由=(\w+) 附带=(\d+) 读盘次数=(\d+) 包字节=(\d+) "
                  r"起始LBA=(\d+) 拒启=(true|false)", log)
    if m is None:
        return ["改盘之后启动日志里没有 `sign-boot: 验签被拒 理由=… 附带=…` 那一行 ⇒ 注入没咬到或没点名"]
    if m.group(1) != want_reason:
        bad.append(f"sign-boot 理由={m.group(1)}，期望 {want_reason}")
    if m.group(6) != "false":
        bad.append(f"sign-boot 拒启={m.group(6)}（ADR-080：被拒也必须继续启动）")
    # 附带数**按拒因分**：BadHeader 本来就没有附带数（`reason_arg` 回 0xFFFFFFFF），
    # 而 BitMismatch/BadLen/PayloadTooLong 必须带一个。一律要求"有数"会把 BadHeader 判红，
    # 一律不要求又会让 BitMismatch 丢掉它唯一能定位到第几位的证据（第一版就写错成前者）。
    carries_arg = want_reason in ("BitMismatch", "BadLen", "PayloadTooLong", "SigBadLen")
    if carries_arg and m.group(2) == "4294967295":
        bad.append(f"sign-boot 理由={m.group(1)} 本该带一个附带数，却是 0xFFFFFFFF")
    if not carries_arg and m.group(2) != "4294967295":
        bad.append(f"sign-boot 理由={m.group(1)} 不该有附带数，却打了 {m.group(2)}")
    return bad


# 宿主机侧改包注入（W4 S3）。包在**裸 LBA 状态区**、不是 GPT ⇒ 固件不会像 S1 那次把它自愈回去。
# 期望拒因**预注册**在这里：改魔数 ⇒ BadHeader；改载荷一个字节 ⇒ 摘要变 ⇒ BitMismatch。
PKG_HOST_FAULTS = {"fault-pkg-header": "BadHeader", "fault-pkg-payload": "BitMismatch"}
# 注入前的那个字节（给证人核"盘真被改了"）。寿命是一跑，与 GPT 那套同规矩。
PKG_PRISTINE: dict[str, tuple[int, int]] = {}
# 上一跑改过包 ⇒ 下一跑 ensure_image 必须重造镜像（否则注入会跨跑污染，见那里的注释）。
PKG_DIRTY = False


def pkg_host_fault_plan(kind: str) -> tuple[int, str]:
    """返回（整盘镜像里的字节偏移, 期望拒因）。偏移由 esp_image 的常量算，不手写魔数。"""
    if kind not in PKG_HOST_FAULTS:
        raise ValueError(f"不认识的改包注入：kind={kind}")
    sys.path.insert(0, str(ROOT / "tools"))
    import esp_image  # noqa: E402
    base = esp_image.PKG_START_LBA * esp_image.SECTOR
    off = base if kind == "fault-pkg-header" else base + esp_image.PAY_OFF + 16
    return off, PKG_HOST_FAULTS[kind]


def apply_pkg_host_fault(kind: str) -> list[str]:
    """把注入写到 build/aurora.img 上（在 ensure_image 之后调）。翻转一个字节，不重算任何校验。

    包没有自校验字段可封（签名本身就是校验），所以翻一个字节就足以让它验不过——
    这正是我们要的：**拒因来自签名/形状检查，而不是来自某个 CRC 闸**。
    """
    try:
        off, _reason = pkg_host_fault_plan(kind)
    except ValueError as e:
        return [str(e)]
    if not IMAGE.exists():
        return [f"{kind}: 引导镜像不在 {IMAGE}"]
    b = bytearray(IMAGE.read_bytes())
    if off >= len(b):
        return [f"{kind}: 偏移 {off} 超出镜像 {len(b)}"]
    old = b[off]
    # **old 必须与配方对得上**，不能信当前盘：盘可能还带着上一跑的注入。
    # 这一条就是抓"注入跨跑污染"的闸——实测它抓到过（两条注入都报 BadHeader）。
    sys.path.insert(0, str(ROOT / "tools"))
    import esp_image  # noqa: E402
    want_old = (esp_image.PKG_MAGIC[0] if kind == "fault-pkg-header"
                else esp_image.package_payload()[16])
    if old != want_old:
        return [f"{kind}: 偏移 {off} 现值 {old:02x} 与配方 {want_old:02x} 不符 ⇒ 盘不是 pristine"]
    new = old ^ 0xFF
    if new == old:
        return [f"{kind}: 翻了等于没翻 ⇒ 空转"]
    b[off] = new
    IMAGE.write_bytes(bytes(b))
    PKG_PRISTINE[kind] = (off, old)
    global PKG_DIRTY
    PKG_DIRTY = True
    print(f"    宿主机侧注入 {kind}: 引导镜像 偏移{off} {old:02x}→{new:02x}"
          f"（期望拒因={PKG_HOST_FAULTS[kind]}，启动应当**仍然成功**）")
    return []


def pkg_host_witness(kind: str, log: str) -> list[str]:
    """证人三件：①盘上那个字节真的改了（不信串口）②日志点名了预注册的拒因
    ③**引导盘那一半仍绿**（读包不许把别的读者弄坏）。还原放在这里，寿命一跑。"""
    bad: list[str] = []
    if kind not in PKG_PRISTINE:
        return [f"{kind}: 没有注入前的记录 ⇒ 这一跑根本没注入，证人不成立"]
    off, old = PKG_PRISTINE.pop(kind)
    cur = IMAGE.read_bytes()
    if cur[off] == old:
        bad.append(f"{kind}: 盘上偏移 {off} 又回到原值 {old:02x} ⇒ 注入被谁还原了（固件？重造？）")
    want = PKG_HOST_FAULTS[kind]
    bad += check_sign_boot(log, want_ok=False, want_reason=want)
    head = cur[512:520]
    if head != b"EFI PART":
        bad.append(f"{kind}: 引导盘的 GPT 头签名坏了（{head!r}）⇒ 改包波及了别的结构")
    # 还原：下一跑 ensure_image 本来会重造，但同进程里紧接着的行不该吃到改过的盘
    b = bytearray(cur)
    b[off] = old
    IMAGE.write_bytes(bytes(b))
    return bad


def gpt_fault_image(kind: str) -> bytes:
    """按计划造出"改过之后应当长什么样"的整块盘字节（证人与注入共用这一份计算）。"""
    import binascii
    edits, seal = gpt_host_fault_plan(kind)
    b = bytearray(gpt_recipe_bytes())
    for at, old, new in edits:
        if bytes(b[at:at + len(old)]) != old:
            raise ValueError(f"{kind}: 偏移 {at} 现值与配方不符")
        if old == new:
            raise ValueError(f"{kind}: 改了等于没改 ⇒ 空转")
        b[at:at + len(old)] = new
    g = b[512:512 + 92]
    alt = struct.unpack_from("<Q", g, 32)[0]
    if seal == "recrc":
        elba = struct.unpack_from("<Q", g, 72)[0]
        n = struct.unpack_from("<I", g, 80)[0]
        sz = struct.unpack_from("<I", g, 84)[0]
        arr = elba * 512
        ac = binascii.crc32(bytes(b[arr:arr + n * sz])) & 0xFFFFFFFF
        struct.pack_into("<I", b, 512 + 88, ac)
        struct.pack_into("<I", b, alt * 512 + 88, ac)
        _gpt_seal(b, 512)
        _gpt_seal(b, alt * 512)
    elif seal == "headers":
        _gpt_seal(b, 512)
        _gpt_seal(b, alt * 512)
    return bytes(b)


def apply_gpt_host_fault(kind: str) -> list[str]:
    """把注入写到 build/ 那块夹具盘上（在 make_gpt_fixture 核完指纹之后调）。

    顺序反了就是拿改过的字节去核 pristine 的指纹，那条闸会把注入本身当成"夹具坏了"。
    注入的寿命是一跑：下一跑 make_gpt_fixture 重造，跑完由 gpt_host_witness 还原。
    """
    try:
        want = gpt_fault_image(kind)
    except ValueError as e:
        return [f"{kind} 定位不成：{e}"]
    cur = GPT_FIX.read_bytes()
    diffs = [i for i in range(min(len(cur), len(want))) if cur[i] != want[i]]
    if not diffs:
        return [f"{kind}: 计划改完之后与现盘一字节不差 ⇒ 这条注入是空转"]
    GPT_FIX.write_bytes(want)
    edits, seal = gpt_host_fault_plan(kind)
    desc = " / ".join(f"偏移{at} {old.hex()}→{new.hex()}" for at, old, new in edits)
    print(f"    宿主机侧注入 {kind}: GPT 夹具盘 {desc}（封CRC={seal}，差异 {len(diffs)} 字节；"
          "内核用的是正向那一跑的同一个 ELF，只有这块固件不碰的盘不同）")
    return []


def check_gpt_fault(kind: str, log: str) -> list[str]:
    """六条注入的证人。三件互相独立的事必须同时成立（只要求"这一跑以红收场"是不够的）：
    1 build/ 里那块盘与配方只差**计划中的那些字节**（宿主机自己比，不信串口）；
    2 串口点名了该点名的拒因；`esp-first` 那条反过来——内核必须绿、红在宿主机对账上；
    3 **引导盘那一半仍绿** ⇒ 注入没波及别的盘（改的是口 1，不是口 0）。
    """
    bad: list[str] = []
    try:
        want = gpt_fault_image(kind)
    except ValueError as e:
        return [f"{kind} 定位不成：{e}"]
    if not GPT_FIX.exists():
        return [f"夹具盘不在：{GPT_FIX}"]
    cur = GPT_FIX.read_bytes()
    edits, _seal = gpt_host_fault_plan(kind)
    missing = [at for at, _old, new in edits if cur[at:at + len(new)] != new]
    if missing:
        bad.append(f"{kind}: 计划要改的那几处没改到位（偏移 {missing}）⇒ 注入没活到内核读它")
    if cur == gpt_recipe_bytes():
        bad.append(f"{kind}: 盘跑完回到了 pristine ⇒ 注入被固件治愈了，这一格证不到内核")
    # 与计划**额外**的差异只报数不判红：固件启动时会往盘上写（实测 esp-first 那一跑
    # 备份阵列被动了 1 字节）。判据由两头担保：计划那几处在位 + 内核点名/宿主机对账红。
    extra = sum(1 for i in range(min(len(cur), len(want))) if cur[i] != want[i])
    print(f"    注入核对: 计划在位={not missing} 与计划额外差异={extra} 字节（固件可能写盘，只报数）")
    want_cause = GPT_HOST_FAULTS[kind]
    if want_cause:
        m = re.search(r"gptfix: 扫描被拒 口(\d+) 拒因=([^\n]+)", log)
        if not m:
            bad.append(f"{kind}: 串口没有『gptfix: 扫描被拒 … 拒因=』那一行（红在别处就不算证到）")
        else:
            if int(m.group(1)) != GPT_FIX_PORT:
                bad.append(f"{kind}: 拒的是口 {m.group(1)}，不是夹具盘口 {GPT_FIX_PORT}")
            if want_cause not in m.group(2):
                bad.append(f"{kind}: 拒因没点名 {want_cause}，实际={m.group(2).strip()[:120]}")
    else:
        if "gptfix: 扫描被拒" in log:
            bad.append(f"{kind}: 内核竟然拒了——这一格证的是『对账能分辨』，不是『解析能拒』")
        host_bad = check_gpt_fixture(log)
        if not any("ESP first_lba" in x for x in host_bad):
            bad.append(f"{kind}: 宿主机对账没红在 ESP first_lba（实际 {host_bad[:3]}）")
    mj = re.search(r"gpt: 判据 [^\n]*", log)
    if not mj:
        bad.append(f"{kind}: 引导盘那一半没报判据（注入波及了别的盘？）")
    elif "false" in mj.group(0):
        bad.append(f"{kind}: 引导盘那一半也红了 ⇒ 注入不只改了夹具盘：{mj.group(0).strip()[:150]}")
    return bad


def gpt_host_witness(kind: str, log: str) -> list[str]:
    """跑完之后叫证人。判定链那六行与手工 `run --host-fault` 走**同一个入口**。

    还原放在这里而不是调用方：证人要读改过的那块盘，所以这里是两条路上最后一个读它的人，
    再往后就必须回到 pristine，不让一块被改过的盘冒充下一跑的证据。
    """
    bad = check_gpt_fault(kind, log)
    for x in bad:
        print("    对账:", x)
    bad += make_gpt_fixture()
    return bad


def check_esp_file(log: str) -> list[str]:
    """ESP 分区里真读一个文件的**宿主机侧独立对账**（W4 S2b，第二台仪器）。

    内核走 `gpt::find_esp` → `PartitionView` → `Volume::mount` → 游标读；这里让
    `validate_esp.py --esp-file` 从**同一份 `build/aurora.img`** 自己解 GPT、自己按 first_lba
    切分区、自己走 FAT16 簇链，各算一遍 FNV 再逐格比。内核绿而对不上 ⇒ 调用方改判
    CONTENT-MISMATCH（与"内核自己红"分开）。
    防空转三条：内核那两行缺任何一行 ⇒ 点名红；宿主机吐不到 12 个字段 ⇒ 报"仪器自己空转"；
    必需字段缺失 ⇒ 先点名再往下比（不静默当成核过了）。
    """
    bad: list[str] = []
    m1 = re.search(
        r"esp: 口=(\d+) ESP\[first=(\d+) last=(\d+) 扇区=(\d+)\] 类型FAT16=(true|false) "
        r"文件=(\S+) 大小=(\d+) 读到=(\d+) 装得下=(true|false) FNV=(0x[0-9a-f]+) "
        r"扫过项=(\d+) 长名项=(\d+)", log)
    m2 = re.search(
        r"esp: 判据 真读=(true|false) 句柄带偏移同数=(true|false) 不带偏移不同=(true|false)"
        r"（那一路读到=(\S+?)） 越界拒=(true|false) 形状错另码=(true|false) 空区间拒=(true|false) "
        r"base0拒=(true|false) 合成偏移照读=(true|false) 偏移改一格内容变=(true|false)", log)
    if not (m1 and m2):
        miss = [n for n, m in (("读数", m1), ("判据", m2)) if not m]
        return [f"内核没报齐 ESP 读数（缺 {'/'.join(miss)} 行）⇒ 宿主机对账没有对象"]
    cells = ["真读", "句柄带偏移同数", "不带偏移不同", "越界拒", "形状错另码", "空区间拒",
             "base0拒", "合成偏移照读", "偏移改一格内容变"]
    vals = [m2.group(i) for i in (1, 2, 3, 5, 6, 7, 8, 9, 10)]
    for name, v in zip(cells, vals):
        if v != "true":
            bad.append(f"ESP 判据 {name}={v}")
    if not IMAGE.exists():
        return [f"引导镜像不在：{IMAGE}（对账必须吃**这一跑**的那块盘）"]
    out = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "validate_esp.py"), str(IMAGE), "--esp-file", ESP_FILE_NAME],
        capture_output=True, text=True, encoding="utf-8", env=env())
    if out.returncode != 0:
        return [f"validate_esp.py --esp-file 退出 {out.returncode}：{out.stderr.strip()[:200]}"]
    host = dict(ln.split("=", 1) for ln in out.stdout.splitlines() if "=" in ln)
    if len(host) < 12:
        return [f"宿主机只解析出 {len(host)} 个字段（应当 >= 12）⇒ 这台仪器自己空转了"]
    required = ["esp_first", "esp_last", "esp_sectors", "found", "size", "fnv", "seen", "lfn",
                "want", "vol_band", "vol_root_entries", "vol_data_start"]
    missing = [k for k in required if k not in host]
    if missing:
        return [f"宿主机报告缺字段 {missing}（它自己给的成因：{host.get('why', '无')}）"]
    if host["found"] != "true":
        return [f"宿主机在 ESP 里开不出 {ESP_FILE_NAME}（{host.get('why', '无')}）⇒ 对账没有对象"]

    def eq(tag: str, k, h) -> None:
        if str(k) != str(h):
            bad.append(f"ESP {tag}：内核={k} 宿主机={h}")

    eq("分区 first_lba", m1.group(2), host["esp_first"])
    eq("分区 last_lba", m1.group(3), host["esp_last"])
    eq("分区扇区数", m1.group(4), host["esp_sectors"])
    eq("判型（ESP 必须是 FAT16）", "Fat16" if m1.group(5) == "true" else "非Fat16", host["vol_band"])
    eq("文件名", m1.group(6), host["want"])
    eq("目录项大小", m1.group(7), host["size"])
    eq("真读到的字节数", m1.group(8), host["size"])
    eq("内容 FNV", m1.group(10), host["fnv"])
    eq("扫过项", m1.group(11), host["seen"])
    eq("长名项", m1.group(12), host["lfn"])
    if m1.group(6) != ESP_FILE_NAME:
        bad.append(f"内核读的文件名 {m1.group(6)} 与本脚本 ESP_FILE_NAME={ESP_FILE_NAME} 分家")
    return bad


def check_fat16(log: str) -> list[str]:
    """FAT16 合成整卷的**宿主机侧独立对账**（W4 S2a，第二台仪器）。

    内核 `t_fat16` 自己报几何/目录/走链；这里让 `validate_esp.py --fat16-report` 从**同一份夹具字节**
    独立重算同样的数（它不 import 内核、也不 import esp_image），逐格比。内核绿而对不上 ⇒
    调用方改判 CONTENT-MISMATCH，与"内核自己红"分得开。
    防空转：内核那三行缺任何一行、或宿主机吐不到 15 个字段，都直接报红并点名。
    """
    bad: list[str] = []
    mg = re.search(
        r"fat16: 几何 判型=(\w+) 簇数=(\d+) 数据起点=(\d+) 根目录区扇区=(\d+) 根项数=(\d+) "
        r"每份扇区=(\d+) 项宽=(\d+) EOC=(0x[0-9a-f]+) 掩码=(0x[0-9a-f]+) 名字串=(true|false) "
        r"无备份引导=(true|false) 阈值判型=(\w+)", log)
    md = re.search(r"fat16: 目录 大小=(\d+) 首簇=(\d+) 扫过项=(\d+) 长名=(\d+)", log)
    mw = re.search(
        r"fat16: 走链 字节=(\d+) 簇=(\d+) 尾字节=(\d+) 末簇后继=(0x[0-9a-f]+) "
        r"内容FNV=(0x[0-9a-f]+) 内容逐字节同=(true|false) 游标一致=(true|false)", log)
    if not (mg and md and mw):
        miss = [n for n, m in (("几何", mg), ("目录", md), ("走链", mw)) if not m]
        return [f"内核没报齐 FAT16 读数（缺 {'/'.join(miss)} 行）⇒ 宿主机对账没有对象"]
    if not FAT16_MEM_OUT.exists():
        return [f"FAT16 夹具卷不在：{FAT16_MEM_OUT}（这一跑之后被谁删了？对账必须吃同一份字节）"]
    out = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "validate_esp.py"), str(FAT16_MEM_OUT), "--fat16-report"],
        capture_output=True, text=True, encoding="utf-8", env=env())
    if out.returncode != 0:
        return [f"validate_esp.py --fat16-report 退出 {out.returncode}：{out.stderr.strip()[:200]}"]
    host = dict(ln.split("=", 1) for ln in out.stdout.splitlines() if "=" in ln)
    if len(host) < 15:
        return [f"宿主机只解析出 {len(host)} 个字段（应当 >= 15）⇒ 这台仪器自己空转了"]
    required = ["clusters", "band", "data_start", "root_dir_sectors", "root_entries", "spf16",
                "fat_entry_bytes", "eoc", "mask", "found", "first_cluster", "size", "seen", "lfn",
                "walk_bytes", "walk_clusters", "tail_bytes", "after_last", "fnv"]
    missing = [k for k in required if k not in host]
    if missing:
        return [f"宿主机报告缺字段 {missing}（它自己发现的问题：{host.get('chain_error', '无')}）"]

    def eq(tag: str, k, h) -> None:
        if k != h:
            bad.append(f"FAT16 {tag}：内核={k} 宿主机={h}")

    eq("判型（必须按结构收为 Fat16）", "Fat16", mg.group(1))
    eq("簇数", int(mg.group(2)), int(host["clusters"]))
    eq("阈值判型（只报数）", mg.group(12), host["band"])
    eq("数据起点", int(mg.group(3)), int(host["data_start"]))
    eq("根目录区扇区", int(mg.group(4)), int(host["root_dir_sectors"]))
    eq("根项数", int(mg.group(5)), int(host["root_entries"]))
    eq("每份FAT扇区", int(mg.group(6)), int(host["spf16"]))
    eq("项宽", int(mg.group(7)), int(host["fat_entry_bytes"]))
    eq("EOC", int(mg.group(8), 16), int(host["eoc"], 16))
    eq("掩码", int(mg.group(9), 16), int(host["mask"], 16))
    eq("名字串", mg.group(10), "true")
    eq("无备份引导", mg.group(11), "true")
    eq("目录大小", int(md.group(1)), int(host["size"]))
    eq("首簇", int(md.group(2)), int(host["first_cluster"]))
    eq("扫过项", int(md.group(3)), int(host["seen"]))
    eq("长名计数", int(md.group(4)), int(host["lfn"]))
    eq("走字节", int(mw.group(1)), int(host["walk_bytes"]))
    eq("走簇", int(mw.group(2)), int(host["walk_clusters"]))
    eq("尾字节", int(mw.group(3)), int(host["tail_bytes"]))
    eq("末簇后继", int(mw.group(4), 16), int(host["after_last"], 16))
    eq("内容FNV（两台实现各走一遍链）", int(mw.group(5), 16), int(host["fnv"], 16))
    eq("内容逐字节同", mw.group(6), "true")
    eq("游标一致", mw.group(7), "true")
    mj = re.search(r"fat16: 判据 [^\n]*", log)
    if not mj:
        bad.append("内核没报 FAT16 判据那一行")
    elif "false" in mj.group(0):
        bad.append(f"FAT16 判据里有 false：{mj.group(0).strip()[:170]}")
    return bad


def check_gpt(log: str) -> list[str]:
    """GPT 分区表的**宿主机侧独立对账**（ADR-078 决策 5，第二台仪器）。

    内核 `filesystem/gpt.rs` 自己报头字段、两个 CRC、覆盖面与 ESP 几何，它的判据比的是
    "自己算的和自己读的"。这里换一台：`tools/validate_esp.py --report` 从**同一跑的那块整盘镜像**
    独立重算同样的数（它不 import 内核，也不 import `esp_image` 的写表常量），逐格比。
    内核绿而对不上 ⇒ 调用方把实际值改判 CONTENT-MISMATCH，与"内核自己红"分得开。

    这台仪器自己也要防空转：解析不出内核那四行、或宿主机只吐出不到 20 个字段，
    都**直接报红**而不是返回空列表（返回空等于"对上了"，那是最坏的一种假绿）。
    """
    bad: list[str] = []
    mh = re.search(
        r"gpt: 头 口(\d+) revision=(0x[0-9a-f]+) header_size=(\d+) my_lba=(\d+) "
        r"alternate_lba=(\d+) first_usable=(\d+) last_usable=(\d+) entry_lba=(\d+) "
        r"entry_count=(\d+) entry_size=(\d+) header_crc=(0x[0-9a-f]+) array_crc=(0x[0-9a-f]+)", log)
    mt = re.search(
        r"gpt: 表 扫过=(\d+) 非空=(\d+) 回调=(\d+) 数组字节=(\d+) 自算CRC=(0x[0-9a-f]+) "
        r"备份my_lba=(\d+) 备份alternate_lba=(\d+) disk_guid=\[([0-9a-f, ]+)\]", log)
    me = re.search(
        r"gpt: ESP 序号=(\d+) first=(\d+) last=(\d+) attrs=(0x[0-9a-f]+) "
        r"type=\[([0-9a-f, ]+)\] unique=\[([0-9a-f, ]+)\]", log)
    mg = re.search(
        r"gpt: 未分派 状态区LBA=(\d+) 签名包LBA=(\d+) 被条目覆盖=\((true|false),(true|false)\) "
        r"都在可用区间=(true|false) 空隙成立=(true|false)", log)
    if not (mh and mt and me and mg):
        miss = [n for n, m in (("头", mh), ("表", mt), ("ESP", me), ("未分派", mg)) if not m]
        return [f"内核没报齐 GPT 读数（缺 {'/'.join(miss)} 行）⇒ 宿主机对账没有对象，这一行不许当成对上了"]
    if not IMAGE.exists():
        return [f"镜像不在：{IMAGE}（这一跑之后被谁 unlink 了？对账必须吃同一跑的盘）"]
    host, errs = gpt_host_report(IMAGE)
    if errs:
        return errs
    # 盘坏掉时宿主机可能根本找不到 ESP（type GUID 被改了一格就没有 esp_* 那几行）。
    # 这里**必须先点名缺字段再往下比**：直接下标会崩成 KeyError，而崩溃的表现是
    # 整张判定表挂掉、看起来像被测物坏了（本轮自查就是这么抓到自己的）。
    required = [
        "signature", "mbr_sig", "mbr_type", "revision", "header_size", "header_crc",
        "header_crc_calc", "my_lba", "alternate_lba", "first_usable", "last_usable",
        "disk_guid", "entry_lba", "entry_count", "entry_size", "array_crc", "array_crc_calc",
        "array_bytes", "seen", "used", "esp_index", "esp_type", "esp_unique", "esp_first",
        "esp_last", "esp_attrs", "backup_present", "backup_my_lba", "backup_alternate_lba",
        "problems",
    ]
    missing = [k for k in required if k not in host]
    if missing:
        probs = "; ".join(v for k, v in host.items() if k.startswith("problem") and k != "problems")
        return [f"宿主机报告缺字段 {missing}（它自己发现的问题：{probs or '无'}）"
                "⇒ 盘坏了或这台仪器坏了，两种都要点名，不许崩成 KeyError"]

    def hexbytes(s: str) -> str:
        return "".join(re.findall(r"[0-9a-f]{2}", s))

    def eq(tag: str, k, h) -> None:
        if k != h:
            bad.append(f"{tag}：内核={k} 宿主机={h}")

    eq("头签名", "EFI PART", host.get("signature"))
    eq("保护性MBR签名", "true", host.get("mbr_sig"))
    eq("保护性MBR类型", "0xee", host.get("mbr_type"))
    eq("revision", int(mh.group(2), 16), int(host["revision"]))
    for tag, ki, hk in (
        ("header_size", 3, "header_size"), ("my_lba", 4, "my_lba"),
        ("alternate_lba", 5, "alternate_lba"), ("first_usable", 6, "first_usable"),
        ("last_usable", 7, "last_usable"), ("entry_lba", 8, "entry_lba"),
        ("entry_count", 9, "entry_count"), ("entry_size", 10, "entry_size"),
    ):
        eq(tag, int(mh.group(ki)), int(host[hk]))
    eq("头CRC(盘上写的)", int(mh.group(11), 16), int(host["header_crc"], 16))
    eq("头CRC(自己算的)", int(mh.group(11), 16), int(host["header_crc_calc"], 16))
    eq("数组CRC(盘上写的)", int(mh.group(12), 16), int(host["array_crc"], 16))
    eq("数组CRC(内核流式算的)", int(mt.group(5), 16), int(host["array_crc_calc"], 16))
    eq("数组字节数", int(mt.group(4)), int(host["array_bytes"]))
    eq("扫过条目数", int(mt.group(1)), int(host["seen"]))
    eq("非空条目数", int(mt.group(2)), int(host["used"]))
    eq("回调次数(独立recount)", int(mt.group(3)), int(host["used"]))
    eq("disk_guid", hexbytes(mt.group(8)), host["disk_guid"])
    eq("备份my_lba", int(mt.group(6)), int(host["backup_my_lba"]))
    eq("备份alternate_lba", int(mt.group(7)), int(host["backup_alternate_lba"]))
    eq("备份头在位", "true", host.get("backup_present"))
    eq("ESP序号", int(me.group(1)), int(host["esp_index"]))
    eq("ESP first_lba", int(me.group(2)), int(host["esp_first"]))
    eq("ESP last_lba", int(me.group(3)), int(host["esp_last"]))
    eq("ESP attrs", int(me.group(4), 16), int(host["esp_attrs"], 16))
    eq("ESP type GUID", hexbytes(me.group(5)), host["esp_type"])
    eq("ESP unique GUID", hexbytes(me.group(6)), host["esp_unique"])
    eq("宿主机自己发现的问题数", 0, int(host["problems"]))

    # 未分派那一段：宿主机用**自己的**分区区间与自己的两个 LBA 常数重算覆盖面，
    # 不信内核报的那两个 LBA（它可能把常数写错，而写错的表现是"空隙成立"照样绿）。
    sys.path.insert(0, str(ROOT / "tools"))
    import esp_image  # noqa: E402
    state_lba, pkg_lba = esp_image.STATE_START_LBA, esp_image.PKG_START_LBA
    eq("状态区LBA常数", int(mg.group(1)), state_lba)
    eq("签名包LBA常数", int(mg.group(2)), pkg_lba)
    ranges = [(int(host[f"part{i}_first"]), int(host[f"part{i}_last"]))
              for i in range(int(host["used"]))]
    cov_s = any(a <= state_lba <= b for a, b in ranges)
    cov_p = any(a <= pkg_lba <= b for a, b in ranges)
    eq("状态区被条目覆盖", mg.group(3), str(cov_s).lower())
    eq("签名包被条目覆盖", mg.group(4), str(cov_p).lower())
    fu, lu = int(host["first_usable"]), int(host["last_usable"])
    in_ok = fu <= state_lba <= lu and fu <= pkg_lba <= lu
    eq("两个裸LBA区都在可用区间", mg.group(5), str(in_ok).lower())
    eq("空隙成立", mg.group(6), str(not cov_s and not cov_p and in_ok).lower())

    # 内核那几行自述判据：宿主机不因为它们绿就放过上面的对账，但它们红了对账也没有意义。
    for tag, pat in (
        ("真盘判据", r"gpt: 判据 [^\n]*"),
        ("CRC向量", r"gpt: CRC向量 [^\n]*"),
        ("合成盘正向", r"gpt: 合成盘 [^\n]*"),
        ("查找", r"gpt: 查找 [^\n]*"),
    ):
        m = re.search(pat, log)
        if not m:
            bad.append(f"内核没报 {tag} 那一行")
        elif "false" in m.group(0):
            bad.append(f"{tag} 里有 false：{m.group(0).strip()[:150]}")
    mn = re.search(r"gpt: 合成判据 [^\n]*点名负样本=(\d+)/(\d+)", log)
    if not mn:
        bad.append("内核没报点名负样本的计数")
    elif mn.group(1) != mn.group(2) or int(mn.group(2)) == 0:
        bad.append(f"点名负样本={mn.group(1)}/{mn.group(2)}（必须全中且分母非零，否则那批闸是空转）")
    return bad


def do_test(timeout: int) -> int:
    """正向必须 33、负样本必须 35。只跑正向的话，永远分不清“代码没问题”
    和“判定链根本没生效”。"""
    print("=== 正向 ===")
    v, rc, log = do_run([], timeout)
    good = v == "PASS"
    # ADR-066 / W2 P4：split/map_hole 两条见证由宿主机独立对账（leaf 位宿主机重算）
    # ADR-067 / W2 P5：demand-zero 见证同样由宿主机独立解（默认档不苛求输家，见变体行）
    p4_bad = check_split_p4(log) + check_map_hole_p4(log) + check_demand_zero_p5(log)
    for x in p4_bad:
        print("    对账:", x)
    print("=== 负样本（--features negative-probe，按设计应失败）===")
    IMAGE.unlink(missing_ok=True)
    nv, nrc, nlog = do_run(["negative-probe"], timeout)
    neg_ok = nv == "FAIL"
    print()
    print("=== L4 注入（--features fault-double-free，重复释放必须停机）===")
    IMAGE.unlink(missing_ok=True)
    dv, drc, dlog = do_run(["fault-double-free"], timeout)
    l4_ok = dv == "EXCEPTION"
    # P1c / ADR-063：共享帧 frame_put 到 0 后再 put 一次，走 frame_put 的 DoubleFree 判定升 L4。
    # 与 fault-double-free（走 phys_free）成对：两条释放路径的 DoubleFree 都要能咬。
    print("=== L4 注入（--features fault-put-double-free，共享帧多 put 必须停机）===")
    IMAGE.unlink(missing_ok=True)
    pdv, pdrc, pdlog = do_run(["fault-put-double-free"], timeout)
    pd_ok = pdv == "EXCEPTION" and "L4 integrity: DoubleFree" in pdlog
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
    # P7a / ADR-060：这一跑停机时正持着 HEAP(10)，退出路径不许再级联出第二条 L4。
    rcasc_ok, rcasc_msg = l4_exit_cascade(rlog, "L4 sync: 重入获取")
    print("    无级联:", rcasc_msg)

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
    # 同一条判据的第二个样本：这一跑停机时持的是 VMM(20)，级联那条的外层 rank 因此不同。
    # 两档各查一次而不只查一档：只看其中一档，另一档的退出路径改坏了也照样绿。
    scasc_ok, scasc_msg = l4_exit_cascade(slog, "L4 mm: shootdown 超时")
    print("    无级联:", scasc_msg)
    # 欠账⑦ / ADR-062：resched IPI 发送一律失败的注入。期望整体仍 PASS（失败不丢唤醒，
    # 目标靠自己的 tick 仍被选上），但宿主机要独立核三件事：失败计数真的涨了、收到的 IPI 为 0、
    # 消费者真的跑完。内核自判之外再加这台仪器，"计数会咬"才不是内核自说自话。
    print("=== resched IPI 失败注入（--features fault-resched-ipi，计数必须涨且不丢唤醒）===")
    IMAGE.unlink(missing_ok=True)
    riv, rirc, rilog = do_run(["fault-resched-ipi"], timeout)
    rif_ok, rif_msg = check_resched_ipi_fail(rilog)
    print("    IPI失败注入:", rif_msg)
    # ADR-066 / W2 P4：split 取 PT 页失败必须传播 Err、原大页原样。整体期望 PASS，
    # 宿主机独立核 err/原样/回基线 三格；内核绿而对不上 ⇒ CONTENT-MISMATCH。
    print("=== split OOM 注入（--features fault-split-oom，失败必须原页原样）===")
    IMAGE.unlink(missing_ok=True)
    soomv, soomrc, soomlog = do_run(["fault-split-oom"], timeout)
    spo_ok, spo_msg = check_split_oom_p4(soomlog)
    print("    split OOM:", spo_msg)
    # ADR-067 / W2 P5：竞争放大变体。自旋把 alloc→map 窗口拉宽，输家路径必须被走到；
    # 期望整体 PASS，宿主机额外苛求 输家还帧>=1 —— 内核绿而没输家 ⇒ CONTENT-MISMATCH。
    print("=== demand-zero 四路竞争（--features race-demand-zero，必须有真输家）===")
    IMAGE.unlink(missing_ok=True)
    dzv, dzrc, dzlog = do_run(["race-demand-zero"], timeout)
    dz_bad = check_demand_zero_p5(dzlog, require_losers=True)
    for x in dz_bad:
        print("    对账:", x)
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
    # 同一跑、同一份 trace 再切两段窗口，把"窗口内取到 ≤ 窗口内投出"与设备侧超速一起判掉
    tw_bad, tw_why = check_timer_window(dllog, DELIVER_LOG)
    dl_bad = dl_bad + tw_bad
    if dlv == "PASS":
        dl_verdict = "PASS" if not dl_bad else "CONTENT-MISMATCH"
    else:
        dl_verdict = dlv
    print(f"    判定={dlv} 分层对账={not dl_bad}（{dl_why}）")
    print(f"    窗口两本账={not tw_bad}（{tw_why}）")
    for x in dl_bad:
        print("    对账:", x)
    DELIVER_LOG.unlink(missing_ok=True)
    IMAGE.unlink(missing_ok=True)

    print("=== 探针夹具：宿主机独立解析 probe.elf，与内核装载器报的几何对账（第二台仪器）===")
    # 内核那侧比的是"自己算的和自己写的"；这一行换成"和另一台实现"（Python 解析 ELF64 程序头）。
    # 用 handles 档跑：探针用例与它的装载器几何只在这一档里出现。
    IMAGE.unlink(missing_ok=True)
    pbv, pbrc, pblog = do_run(["handles"], timeout)
    pb_bad = check_probe_elf(pblog)
    pb_verdict = pbv if pbv != "PASS" else ("PASS" if not pb_bad else "CONTENT-MISMATCH")
    for x in pb_bad:
        print("    对账:", x)

    print("=== GPT 分区表：内核读回的每个数由 validate_esp.py 独立重算（ADR-078 决策 5，第二台仪器）===")
    # 内核那侧的 t_gpt 比的是"自己算的和自己读的"，外加一张合成盘把 16 道闸各证红一次。
    # 这一行换成"和另一台实现"：validate_esp.py 不 import 内核、也不 import esp_image 的写表常量，
    # 从**同一跑的那块盘**重算头字段、两个 CRC、覆盖面、ESP 几何与备份头，逐格比。
    # 用 gpt-probe 档跑：解析器与它的用例只在这一档里编译（默认档 ELF 一个字节不动）。
    IMAGE.unlink(missing_ok=True)
    gptv, gptrc, gptlog = do_run(["gpt-probe"], timeout)
    gpt_bad = check_gpt(gptlog) + check_gpt_fixture(gptlog)
    gpt_verdict = gptv if gptv != "PASS" else ("PASS" if not gpt_bad else "CONTENT-MISMATCH")
    for x in gpt_bad:
        print("    对账:", x)

    # ADR-078 决策 7：**五条**改盘负样本（原计划六条，"备份头不一致"那条实测被固件必然治愈，
    # 账记在 GPT_FAULT_UNDELIVERABLE，由合成盘证）。载体是口 1 那块夹具盘，不是引导盘——
    # 实测引导盘改不动：EDK2 用备份表把主表修回原值，四条注入根本到不了内核。
    # 五行都用**正向那一跑的同一个 ELF**（gpt-probe），只有盘不同；注入名不是 cargo 特性。
    # 前四条期望 FAIL(35) 且**红必须点名**：红了但拒因不是该点名的那道闸 ⇒ 改判 CONTENT-MISMATCH。
    print("=== GPT 负样本①：夹具盘条目数组翻一字节（主备一起改，不重算 CRC）⇒ 必须红在数组 CRC 那道闸 ===")
    gacv, gacrc, gaclog = do_run(["gpt-probe"], timeout, host_fault="fault-gpt-array-crc")
    gac_bad = gpt_host_witness("fault-gpt-array-crc", gaclog)
    gac_verdict = gacv if gacv != "FAIL" else ("FAIL" if not gac_bad else "CONTENT-MISMATCH")

    print("=== GPT 负样本②：夹具盘头字段翻一字节（不重算头 CRC）⇒ 必须红在头 CRC 那道闸 ===")
    ghcv, ghcrc, ghclog = do_run(["gpt-probe"], timeout, host_fault="fault-gpt-header-crc")
    ghc_bad = gpt_host_witness("fault-gpt-header-crc", ghclog)
    ghc_verdict = ghcv if ghcv != "FAIL" else ("FAIL" if not ghc_bad else "CONTENT-MISMATCH")

    print("=== GPT 负样本③：夹具盘保护性 MBR 的 0xEE 改 0x0C ⇒ 第一道判型闸必须拒 ===")
    gmtv, gmtrc, gmtlog = do_run(["gpt-probe"], timeout, host_fault="fault-gpt-mbr-type")
    gmt_bad = gpt_host_witness("fault-gpt-mbr-type", gmtlog)
    gmt_verdict = gmtv if gmtv != "FAIL" else ("FAIL" if not gmt_bad else "CONTENT-MISMATCH")

    print("=== GPT 负样本④：夹具盘 entry_count 改 129（主备一起改 + 两份重封头 CRC）⇒ 先验上界那道闸必须拒 ===")
    gecv, gecrc, geclog = do_run(["gpt-probe"], timeout, host_fault="fault-gpt-entry-count")
    gec_bad = gpt_host_witness("fault-gpt-entry-count", geclog)
    gec_verdict = gecv if gecv != "FAIL" else ("FAIL" if not gec_bad else "CONTENT-MISMATCH")

    print("=== GPT 负样本⑤：夹具盘 ESP first_lba 改一格**并重算两个 CRC** ⇒ 内核必须绿、红在对账 ===")
    # 这一格证的是"**对账能分辨**"而不是"解析能拒"：一切自洽、只有 first_lba 与配方对不上。
    # 期望因此是 CONTENT-MISMATCH(rc=33)，与"块内容对账抓得出错标签"那一行同一形状。
    gefv, gefrc, geflog = do_run(["gpt-probe"], timeout, host_fault="fault-gpt-esp-first")
    gef_bad = gpt_host_witness("fault-gpt-esp-first", geflog)
    gef_verdict = gefv if gefv != "PASS" else ("CONTENT-MISMATCH" if not gef_bad else "PASS")

    print("=== FAT16 合成整卷：内核读回的每个数由 validate_esp.py 独立重算（W4 S2a，第二台仪器）===")
    # 夹具由 make_fat16_mem.py 现算、内核 include_bytes! **同一份字节**，所以两台仪器读的是同一块卷。
    # 内核那八格判据比的是"自己和写死的期望数"；这一行换成"和另一台实现"，逐格比。
    IMAGE.unlink(missing_ok=True)
    f16v, f16rc, f16log = do_run(["fat16-probe"], timeout)
    f16_bad = check_fat16(f16log)
    f16_verdict = f16v if f16v != "PASS" else ("PASS" if not f16_bad else "CONTENT-MISMATCH")
    for x in f16_bad:
        print("    对账:", x)

    print("=== ESP 分区里真读一个已存在的文件：偏移视图 + 句柄身份（W4 S2b，第二台仪器）===")
    # 内核走 GPT→PartitionView→mount→游标；宿主机自己解 GPT、自己切分区、自己走 FAT16 簇链。
    # 读的是**引导盘上本来就有的** limine.conf（短名 LIMINE.CON），不往 ESP 里加新文件。
    IMAGE.unlink(missing_ok=True)
    espv, espc, esplog = do_run(["esp-probe"], timeout)
    esp_bad = check_esp_file(esplog)
    esp_verdict = espv if espv != "PASS" else ("PASS" if not esp_bad else "CONTENT-MISMATCH")
    for x in esp_bad:
        print("    对账:", x)

    print("=== 启动路径验签：只检测不拒启（W4 S3，ADR-080），正向 + 两条改包负样本 ===")
    # 三行都期望 PASS(33)：**被拒也必须继续启动**就是这一刀的判定形状。
    # 若实现偷偷拒启，这两行的判定值会变成 BOOT-INVALID(37) ⇒ 矩阵自己红。
    IMAGE.unlink(missing_ok=True)
    sbv, sbrc, sblog = do_run([], timeout)
    sb_bad = check_sign_boot(sblog, want_ok=True)
    sb_verdict = sbv if sbv != "PASS" else ("PASS" if not sb_bad else "CONTENT-MISMATCH")
    for x in sb_bad:
        print("    对账:", x)

    phv, phrc, phlog = do_run([], timeout, host_fault="fault-pkg-header")
    ph_bad = pkg_host_witness("fault-pkg-header", phlog)
    ph_verdict = phv if phv != "PASS" else ("PASS" if not ph_bad else "CONTENT-MISMATCH")
    for x in ph_bad:
        print("    对账:", x)

    ppv, pprc, pplog = do_run([], timeout, host_fault="fault-pkg-payload")
    pp_bad = pkg_host_witness("fault-pkg-payload", pplog)
    pp_verdict = ppv if ppv != "PASS" else ("PASS" if not pp_bad else "CONTENT-MISMATCH")
    for x in pp_bad:
        print("    对账:", x)

    print("=== FAT32 只读解析：两块卷挂 AHCI 口 3/4，内核读回的每个数由宿主机再解析一遍 ===")
    # 内核那十三条判据比的是"自己和写死的期望数"，这一行把它们换成"和另一台实现"：
    # 几何 14 格、每个文件 12 格、以及引导盘该崩在哪一道闸。两块卷的角色不重叠——
    # 卷A 是阈值判型的反例，卷B 的簇号高半非零（只取低半会读到 FILLER.BIN 中间去）。
    IMAGE.unlink(missing_ok=True)
    fatv, fatrc, fatlog = do_run(["fat32-probe"], timeout)
    fat_bad = check_fat32(fatlog)
    fat_verdict = fatv if fatv != "PASS" else ("PASS" if not fat_bad else "CONTENT-MISMATCH")
    for x in fat_bad:
        print("    对账:", x)

    print("=== 尾格多喂一个字节（--features fault-fat32-tail）：簇数/EOC/大小全好看，只有哈希对不上 ===")
    # 这条注入专门盯"尾格只喂真的属于文件的那几个字节"那一句：多喂的那个字节是**文件之后的
    # 盘上内容**，走字节、走簇、末簇后继每一格都还自洽，红只能红在内容账上。
    IMAGE.unlink(missing_ok=True)
    ftv, ftrc, ftlog = do_run(["fault-fat32-tail"], timeout)
    IMAGE.unlink(missing_ok=True)

    print("=== 用户镜像的来源换成盘：走链喂进缓冲、装进窗口、真跑一遍（--features fat32-exec）===")
    # 这一行判的不是"读得出来"（34 行判过），而是**换了输入来源之后行为是否不变**：
    # 段表逐项相同、跑后五格与同一跑里 `elfload:`（内嵌那份）逐字段相同；
    # 加上"目录项撒谎时不许往下装"那两格（说大 4096 ⇒ 走链先红；截到段末减一 ⇒ 加载器先红）。
    # 那两格是换成盘之后才存在的一类：内嵌夹具的 size 是我编的，改不动它。
    IMAGE.unlink(missing_ok=True)
    exv, exc, exlog = do_run(["fat32-exec"], timeout)
    ex_bad = check_fat32_exec(exlog)
    ex_verdict = exv if exv != "PASS" else ("PASS" if not ex_bad else "CONTENT-MISMATCH")
    for x in ex_bad:
        print("    对账:", x)
    IMAGE.unlink(missing_ok=True)

    print("=== 第 36 行的证红：同时带上尾格注入，③ 必须红在「多喂一字节」那一格 ===")
    # 只要求"这一构建以红收场"的话，任何一条别的用例红了这一行也照样符合 —— 那不是证红，
    # 那是巧合。所以这一行拿串口那格读数当证人：已喂 + 这一段 = 界 + 1，
    # 而 `walk` 自报的字节数也是 界 + 1（多喂的那个字节来自文件之后的盘上内容）。
    # 这一跑还顺带验一件事：③ 的拷贝在被注入推翻"walk 不超过 size"那句承诺时，
    # 必须**拒绝往下写**而不是越界 —— 后者表现为 panic(39)，量具自己把用例红升级成内核挂。
    EVF_OV_RE = re.compile(
        r"elfdisk: 尾格溢出 已喂=(?P<at>\d+) 这段还要喂=(?P<n>\d+) 目录项说=(?P<size>\d+) "
        r"走链自报字节=(?P<wb>\d+)")
    evv, evc, evlog = do_run(["fat32-exec", "fault-fat32-tail"], timeout)
    ovf = EVF_OV_RE.search(evlog)
    ev_verdict = evv
    if evv == "FAIL":
        if ovf is None:
            ev_verdict = "CONTENT-MISMATCH"
            print("    对账: 这一跑是 FAIL，但串口没有 `elfdisk: 尾格溢出 …` ⇒ 红不是 ③ 带来的（别的用例红了）")
        else:
            at, n, esize, wb = (int(ovf.group(i)) for i in ("at", "n", "size", "wb"))
            if wb != esize + 1 or at + n != esize + 1:
                ev_verdict = "CONTENT-MISMATCH"
                print(f"    对账: 溢出的读数不像「多喂一个字节」：已喂={at} 这段={n} 界={esize} 自报={wb}")
            else:
                print(f"    溢出现场 已喂={at} 这段={n} 界={esize} 走链自报={wb} ⇒ 正好多出 1 字节")
    IMAGE.unlink(missing_ok=True)

    print("=== 第 38 行：给第 36 行 ④ 那格证红——宿主机改卷A 上容器的一个段内字节（内核二进制不变）===")
    # ④ 今天是"两条来源跑出同一组数"，那是配对，不是证红。这一跑把盘上那份的
    # `movq $0xa7,…(%rip)` 的 immediate 改成 0x5a：rodata 槽必须变成 90、"字节同"必须红，
    # 而长度/走链/段表三格还得是 true（改的是段内字节，不是元数据）。
    # 为什么改代码段而不是 .rodata：实测 BANNER[0] 被折成 immediate，改 .rodata 槽读数不动（BACKLOG 80）。
    IMAGE.unlink(missing_ok=True)
    ebv, ebc, eblog = do_run(["fat32-exec"], timeout, host_fault="fault-fat32-exec-byte")
    eb_bad = fat_host_witness("fault-fat32-exec-byte", eblog)
    eb_verdict = ebv if not eb_bad else "CONTENT-MISMATCH"
    IMAGE.unlink(missing_ok=True)

    print("=== 第 39 行：给第 34 行 ⑦ 那格证红——宿主机把卷B 目录项的簇号高半抹成 0 ===")
    # ⑦ 今天是内核自己构造一个"只取低半"的 FileStat 再走链——那证明的是 walk 的拒因，
    # 不是 open 真的把两半拼起来了。这一跑改的是**盘上的目录项**：首簇从 67,587 掉到 2,051，
    # 落在 FILLER.BIN 中间，走满 64 簇喂够字节而链还没到 EOC ⇒ ChainEndsLate，
    # 且读出来的头四字节不再是 ELF 魔数。拒因里那四个数由宿主机按改过的盘独立算一遍。
    IMAGE.unlink(missing_ok=True)
    hiv, hirc, hilog = do_run(["fat32-probe"], timeout, host_fault="fault-fat32-cluster-hi")
    hi_bad = fat_host_witness("fault-fat32-cluster-hi", hilog)
    hi_verdict = hiv if not hi_bad else "CONTENT-MISMATCH"
    IMAGE.unlink(missing_ok=True)

    print("=== 第 40 行：P7 ⑤ ring3 句柄——容器读自己的镜像，宿主机按下发的句柄值复核 ===")
    # 设计 §9 F：正向行复用 `fat32-exec` 档**再跑一遍**，不新增构建档。
    # 这一行的期望值（魔数）来自宿主机自己读 hello.elf，不是内核打印的 true。
    IMAGE.unlink(missing_ok=True)
    h3v, h3rc, h3log = do_run(["fat32-exec"], timeout)
    h3_bad = check_handle_ring3(h3log)
    h3_verdict = h3v if h3v != "PASS" else ("PASS" if not h3_bad else "CONTENT-MISMATCH")
    for x in h3_bad:
        print("    对账:", x)
    IMAGE.unlink(missing_ok=True)

    print("=== 第 41 行：授错主人必须红（--features fault-handle-owner）===")
    # 内核侧注入（§80a 允许做成特性）：授予时把 Task::id 改错一格。容器拿自己的句柄读
    # 必须 `-4`，ring3 的魔数变成错误标记、表也清不空 ⇒ 这一跑必须 FAIL。
    ihv, ihrc, ihlog = do_run(["fat32-exec", "fault-handle-owner"], timeout)
    im = HANDLE_RING3_RE.search(ihlog)
    want_magic = int.from_bytes((ROOT / "kernel" / "fixtures" / "hello.elf").read_bytes()[:4], "little")
    inj_ok = ihv == "FAIL" and im is not None and im.group("ok") == "false"         and int(im.group("magic")) != want_magic
    ih_verdict = "FAIL" if inj_ok else "CONTENT-MISMATCH"
    if not inj_ok:
        print("    对账: 授错主人这一跑没有红在 ring3 那格（判定/魔数/布尔至少一项不符）")
    IMAGE.unlink(missing_ok=True)

    rows = [
        ("正向", v if v != "PASS" or not p4_bad else "CONTENT-MISMATCH", rc, "PASS", 33),
        ("负样本", nv, nrc, "FAIL", 35),
        ("L4 重复释放", dv, drc, "EXCEPTION", 39),
        # P1c / ADR-063：共享帧多 put 的 DoubleFree 升 L4（走 frame_put，与上一行的 phys_free 成对）
        ("共享帧多put升L4", pdv if pd_ok else "CONTENT-MISMATCH", pdrc, "EXCEPTION", 39),
        ("L4 堆分配失败", ov, orc, "EXCEPTION", 39),
        ("泄漏注入被检出", lv, lrc, "FAIL", 35),
        # 守卫拒绝之后容器路径必然走 handle_alloc_error（ADR-018 的稳定版唯一去向），
        # 所以这条构建的正确期望是 39 而不是 35：违规被**当场停机**，比继续跑完用例更好。
        ("中断内分配被挡下", av, arc, "EXCEPTION", 39),
        # P7a / ADR-060：期望仍是 39（注入的故障就该当场停机），但"级联出第二条 L4"
        # 是另一种成因 ⇒ 报 CONTENT-MISMATCH，与"内核没抓到重入"分得开
        ("锁重入被抓住", rv if rcasc_ok else "CONTENT-MISMATCH", rrc, "EXCEPTION", 39),
        # 必需项没开成 = 前提不满足，处置是**不启动**（37），不是运行中停机（39）：
        # §9.2 把这两类分成不同级正是因为处置不同，判据也必须能分辨它们。
        ("SMAP 没开成不启动", sv2, src2, "BOOT-INVALID", 37),
        # 挂死不是一种"错误码"，而是判定契约里的独立一级（§12.3）：这里它就是期望结果
        ("IF 归任务就挂死", fv, frc, "HANG", -1),
        ("shootdown 收不齐回执升 L4", sv if scasc_ok else "CONTENT-MISMATCH", src, "EXCEPTION", 39),
        # 欠账⑦ / ADR-062：IPI 发送失败但**不丢唤醒**，所以整体期望 PASS(33)。
        # 内核绿而宿主机那三件事（计数涨/收到0/跑完）对不上 ⇒ CONTENT-MISMATCH，两种成因分得开
        ("resched IPI失败计数会咬", riv if rif_ok else "CONTENT-MISMATCH", rirc, "PASS", 33),
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
        # L3-C①：内核从两块卷读回的每一个数（几何 14 格 + 每文件 12 格）由宿主机第二台实现
        # 逐字段核对；内核绿而对不上 ⇒ CONTENT-MISMATCH，两种成因分得开
        ("FAT32两卷与宿主机对账", fat_verdict, fatrc, "PASS", 33),
        # 这一行期望 FAIL：注入让尾格多喂一个字节，走字节/走簇/末簇后继每格还自洽，
        # 只有内容账不认——没有这条注入，"尾格只喂属于文件的那几个字节"是修辞
        ("FAT32尾格多喂必须红", ftv, ftrc, "FAIL", 35),
        # L3-C③：容器来自卷而不是 `.rodata`，段表与跑后的五格都要与内嵌那份同数；
        # 两台仪器（宿主机的 FAT+ELF 解析、同一跑里的 `elfload:` 读数）都对上才算 PASS
        ("FAT32读出的镜像装上并跑通", ex_verdict, exc, "PASS", 33),
        # 第 36 行的证红：把尾格注入叠加到 ③ 上，红必须点名"多喂出来的那一个字节"。
        # 红了但红在别处 ⇒ 上面已经把实际值改成 CONTENT-MISMATCH，这一行就不会假装符合
        ("FAT32③多喂一字节红在溢出", ev_verdict, evc, "FAIL", 35),
        # 第 36 行 ④ 那格的证红：盘上那份容器的一个**段内字节**被宿主机改掉（内核二进制不变），
        # rodata 槽必须跟着变成注入值、"字节同"必须红。红了但槽读数没变 ⇒ 注入没走到用户态，
        # 上面已把实际值改成 CONTENT-MISMATCH，这一行不会假装符合
        ("FAT32④段内字节改了必须红", eb_verdict, ebc, "FAIL", 35),
        # 第 34 行 ⑦ 那格的证红：目录项高半抹零 ⇒ open 拼出的首簇掉进 FILLER.BIN 中间，
        # 读到的是别的文件的字节。拒因里四个数由宿主机按改过的盘独立重算
        ("FAT32簇号高半抹零必须红", hi_verdict, hirc, "FAIL", 35),
        # P7 ⑤：装载器把 READ|DUP 句柄授给**容器**（owner 两格），ring3 读自己的镜像。
        # 期望值与句柄形状由宿主机独立算；内核那行 true 只是它的自述。
        ("P7 句柄ring3读自己镜像", h3_verdict, h3rc, "PASS", 33),
        # P5c-3b：探针夹具的宿主机侧独立对账（§156/§160 欠的那条），判据是"另一台实现算出同样的数"
        ("探针几何与宿主机对账", pb_verdict, pbrc, "PASS", 33),
        # ADR-078 决策 5 / W4 S1：GPT 的头字段、两个 CRC、覆盖面、ESP 几何与备份头由
        # validate_esp.py 从同一跑的盘独立重算；内核绿而对不上 ⇒ CONTENT-MISMATCH
        ("GPT分区表与宿主机对账", gpt_verdict, gptrc, "PASS", 33),
        # ADR-078 决策 7 的六条改盘负样本：同一个 ELF、只改口 1 那块固件不碰的夹具盘。
        # 前五条红必须**点名**那道闸（红了但点错名 ⇒ 上面已改判 CONTENT-MISMATCH，不会假装符合）
        ("GPT数组CRC改坏必须红", gac_verdict, gacrc, "FAIL", 35),
        ("GPT头CRC改坏必须红", ghc_verdict, ghcrc, "FAIL", 35),
        ("GPT保护性MBR改坏必须红", gmt_verdict, gmtrc, "FAIL", 35),
        ("GPT条目数超上界必须红", gec_verdict, gecrc, "FAIL", 35),
        # 第五条证的是"对账能分辨"：内核绿、两个 CRC 都自洽，只有 first_lba 与配方对不上。
        # 原计划的第六条（备份头不一致）**做不成改盘行**：固件必然治愈，实测跑完回到 pristine
        # ⇒ 那道闸由同一份 ELF 里的合成盘证（16 格之一），账记在 GPT_FAULT_UNDELIVERABLE。
        ("GPT改first并重算CRC对账红", gef_verdict, gefrc, "CONTENT-MISMATCH", 33),
        # W4 S2a：FAT16 合成整卷（23 扇区、簇数落 FAT12 档而结构是 FAT16）。内核八格判据
        # 比的是"自己和写死的期望数"，这一行换成"和 validate_esp.py 的独立读表"，逐格比
        ("FAT16合成卷与宿主机对账", f16_verdict, f16rc, "PASS", 33),
        ("ESP分区偏移真读文件", esp_verdict, espc, "PASS", 33),
        ("启动验签通过不拒启", sb_verdict, sbrc, "PASS", 33),
        ("改包头被拒仍启动", ph_verdict, phrc, "PASS", 33),
        ("改载荷被拒仍启动", pp_verdict, pprc, "PASS", 33),
        # P7 第 40 行的证红：owner 改错一格 ⇒ 容器读不到 ⇒ 必须红在 ring3 那格
        ("P7 句柄授错主人必须红", ih_verdict, ihrc, "FAIL", 35),
        # ADR-066 / W2 P4：OOM 被传播（Err）且原页原样 ⇒ 期望 PASS(33)；
        # 内核绿而宿主机三格对不上 ⇒ CONTENT-MISMATCH，两种成因分得开
        ("split OOM原页原样", soomv if spo_ok else "CONTENT-MISMATCH", soomrc, "PASS", 33),
        # ADR-067 / W2 P5：竞争放大档。PASS + 宿主机苛求真输家；没重叠就没证据 ⇒ CONTENT-MISMATCH
        ("demand-zero四路有真输家", dzv if not dz_bad else "CONTENT-MISMATCH", dzrc, "PASS", 33),
    ]
    # 每一行对应那一跑的串口：不符时把红的那几格打出来。
    # 单独一张表而不是把日志塞进 `rows` 的元组里：元组要保持成"名字/期望/实际"这种
    # 一眼能核对的形状，串口文本只是它的证据附件
    logs = {
        "正向": log, "负样本": nlog, "L4 重复释放": dlog, "共享帧多put升L4": pdlog, "L4 堆分配失败": olog,
        "泄漏注入被检出": llog, "中断内分配被挡下": alog, "锁重入被抓住": rlog,
        "SMAP 没开成不启动": slog2, "IF 归任务就挂死": flog,
        "shootdown 收不齐回执升 L4": slog, "resched IPI失败计数会咬": rilog, "块内容对账抓得出错标签": clog,
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
        "FAT32两卷与宿主机对账": fatlog,
        "FAT32尾格多喂必须红": ftlog,
        "FAT32读出的镜像装上并跑通": exlog,
        "FAT32③多喂一字节红在溢出": evlog,
        "FAT32④段内字节改了必须红": eblog,
        "FAT32簇号高半抹零必须红": hilog,
        "P7 句柄ring3读自己镜像": h3log,
        "探针几何与宿主机对账": pblog,
        "GPT分区表与宿主机对账": gptlog,
        "GPT数组CRC改坏必须红": gaclog,
        "GPT头CRC改坏必须红": ghclog,
        "GPT保护性MBR改坏必须红": gmtlog,
        "GPT条目数超上界必须红": geclog,
        "GPT改first并重算CRC对账红": geflog,
        "FAT16合成卷与宿主机对账": f16log,
        "ESP分区偏移真读文件": esplog,
        "启动验签通过不拒启": sblog,
        "改包头被拒仍启动": phlog,
        "改载荷被拒仍启动": pplog,
        "P7 句柄授错主人必须红": ihlog,
        "split OOM原页原样": soomlog,
        "demand-zero四路有真输家": dzlog,
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
        if name == "run":
            # 第 38/39 行那两条宿主机侧注入要能脱离判定链单独复现：`run --features fat32-exec
            # --host-fault fault-fat32-exec-byte` 必须与链里那一跑是同一个证人。只给 `run`——
            # 别的子命令收下这个参数却不读它，就是"看着开了其实没开"那种绿。
            p.add_argument("--host-fault", default="",
                           choices=["", *sorted(FAT_HOST_FAULTS), *sorted(GPT_HOST_FAULTS), *sorted(PKG_HOST_FAULTS)])
    a = ap.parse_args()
    feats = [f for f in a.features.split(",") if f]
    if a.cmd == "build":
        do_build(feats)
        return 0
    if a.cmd == "image":
        do_image(feats)
        return 0
    if a.cmd == "run":
        v, rc, log = do_run(feats, a.timeout, host_fault=a.host_fault)
        if a.host_fault in GPT_HOST_FAULTS:
            if gpt_host_witness(a.host_fault, log):
                v = "CONTENT-MISMATCH"
        elif a.host_fault and fat_host_witness(a.host_fault, log):
            v = "CONTENT-MISMATCH"
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
