# Aurora OS 在 VMware Workstation Pro 上的安装测试指南

> **状态：全部未验证。** Aurora 目前只在 QEMU（q35 / ich9-ahci / OVMF，TCG）上取得过读数；
> 本文是依据源码静态阅读写出的**可行性分析与操作步骤**，没有在 VMware 上跑过。按 AGENTS.md 口径，
> "未验证"的一律不得写成"已支持"。第一次启动大概率需要你把串口/屏幕上的报错贴回来迭代。

## 0. 你截图里那一步怎么选

`Hardware compatibility` 选 **Workstation 25H2 or later**（默认项）即可，本机就是 Workstation Pro 25H2，不需要向下兼容。
这个选项只影响虚拟硬件版本号，与 Aurora 能否启动无关。

## 1. Aurora 对虚拟机的硬性要求（读源码得到）

| 项 | Aurora 的要求 | 依据 |
|---|---|---|
| 固件 | **UEFI**（Limine EFI 引导，`BOOTX64.EFI`）。BIOS/Legacy 不行 | `tools/aurora.py::do_image`：造的是 GPT + ESP，里面是 `\EFI\BOOT\BOOTX64.EFI` |
| 磁盘 | GPT，ESP 128 MiB + 状态区 + 签名包，总 256 MiB（`disk_sectors = 524288`） | 同上 |
| 存储控制器 | **SATA(AHCI)** 或 **NVMe**。**VMware 没有 virtio**，所以 `virtio-blk` / `virtio-net` 在 VMware 下**不可用** | `kernel/src/driver/{ahci,nvme,virtio}.rs`；AHCI 按 PCI class 0x01/0x06/progif 0x01 认领，NVMe 按 0x01/0x08/0x02 |
| 网卡 | 目前只有 **virtio-net** 驱动。VMware 的 e1000/e1000e/vmxnet3 **没有驱动** ⇒ VMware 里**没有网络**（`ping`/`nslookup`/防火墙/ISN 在 VMware 下只能看到"没有网卡"） | `driver/` 目录里没有 e1000 |
| 显示 | Limine 的 framebuffer（`framebuffer`/`fbcon-*` 特性），VMware 的 UEFI GOP 一般可用 | `kernel/Cargo.toml` |
| 键盘 | **PS/2（i8042）**，特性 `ps2-kbd`/`fbcon-live`。VMware 虚拟机默认提供 PS/2 键盘，一般可用；USB 键盘（xHCI）只有"真设备探针与命令环切片"，**不能当输入** | AGENTS.md 已交付清单 |
| 串口 | `serial: yes`、COM1。VMware 需要**手动加串口**才有串口输出 | `boot/limine.conf` |
| CPU | x86-64；`MAX_CPUS = 8`（超过会判红），建议 **1–4 个核** | `docs/hardware/bringup.md` H-06 |
| 内存 | 建议 ≥ 1 GiB（`handles` 档内核 ELF 约 44 MiB） | `do_image` 注释 |

**结论（诚实版）**：
- **能不能启动**：理论路径通（UEFI + AHCI/NVMe + Limine），**但没人在 VMware 上试过**，bringup.md 里 51 条真机/非 QEMU 项全是"待测"。
- **有没有 CLI**：shell 是**串口 + 键盘 + 帧缓冲**三路，取决于你构建时开的特性（见 §3）。**默认构建不带键盘和帧缓冲**，只有串口。
- **有没有网络**：**没有**（无 e1000/vmxnet3 驱动）。要在 VMware 里测网络，得先写网卡驱动，这是另一个大工程。

## 2. 把镜像变成 VMware 能用的磁盘

`python tools/aurora.py image --features <特性>` 会产出一个**裸磁盘镜像**（路径见脚本里的 `IMAGE`，通常在 `build/`）。
VMware 不吃裸 `.img`，需转成 VMDK（任选其一）：

```bat
:: 方法 A：用 qemu-img（仓库 .tools 里有 QEMU 的话已自带）
qemu-img convert -f raw -O vmdk -o subformat=monolithicSparse build\aurora.img aurora.vmdk

:: 方法 B：VMware 自带的 vmware-vdiskmanager 不能直接转 raw，建议用 A
```

## 3. 构建特性（决定 VMware 里看得见什么）

先在 QEMU 里确认下面这组能跑，再放进 VMware：

```bat
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
python tools/aurora.py image --features "resident-init,fs-rw,fbcon-live"
```

- `resident-init`：init 常驻，shell 才能一直接受输入。
- `fs-rw`：可写卷（`>` `>>` 重定向要它）。
- `fbcon-live` = `framebuffer + ps2-kbd`：屏幕出字 + PS/2 键盘输入。**没有它 VMware 窗口里什么都看不到。**
- **不要**带 `virtio-blk` / `virtio-net`（VMware 没有）。

> 以上特性组合我**没有**在 QEMU 里跑过；`aurora.py` 的判定矩阵里有没有这一档请看 `docs/testing`。若组合不被支持，会在 build 阶段报错，请把原文贴回来。

## 4. 新建虚拟机（逐步）

1. **New Virtual Machine → Custom (advanced)** → Hardware compatibility：**Workstation 25H2 or later** → Next。
2. **I will install the operating system later** → Guest OS：**Other → Other 64-bit**。
3. 处理器：**1 个处理器 × 2 核**（先别开多，`MAX_CPUS=8` 与 SMP 路径在真机/VMware 均未测）。
4. 内存：**2048 MB**。
5. 网络：**Do not use a network connection**（反正没有驱动）。
6. I/O 控制器类型：默认即可。
7. 磁盘类型：先选 **SATA**（对应 AHCI，QEMU 里已验证）；**NVMe 是第二选择**（`nvme` 特性路径在 QEMU 里验证过，VMware 里未测）。
8. 磁盘：**Use an existing virtual disk** → 选上面转出的 `aurora.vmdk` → **Keep existing format**。
9. 完成后**先不要开机**，关掉向导。

### 4.1 改 `.vmx`（必须，关机状态下用记事本编辑）

在虚拟机目录里找到 `*.vmx`，追加/确认这几行：

```
firmware = "efi"
efi.legacyBoot.enabled = "FALSE"
uefi.secureBoot.enabled = "FALSE"

serial0.present = "TRUE"
serial0.fileType = "file"
serial0.fileName = "aurora-serial.log"
serial0.tryNoRxLoss = "TRUE"
```

- `firmware = "efi"`：**最重要**，否则 Limine 不会被加载。
- **关闭 Secure Boot**：Limine 的 `BOOTX64.EFI` 没签名。
- 串口输出到文件 `aurora-serial.log`：开机后用记事本/`tail` 看内核日志。**这是你判断"到底卡在哪"的主要仪器**。
  想要交互式串口，把 `fileType` 改 `"pipe"`，`fileName = "\\.\pipe\aurora"`，需另配 `serial0.pipe.endPoint = "server"`，再用能连 Windows 命名管道的串口工具接入（具体工具我未验证）。

## 5. 第一次启动与排错

| 现象 | 可能原因 | 做什么 |
|---|---|---|
| 进 UEFI Shell / 提示无启动项 | 没有 `firmware="efi"`，或磁盘不是 GPT+ESP | 检查 `.vmx`；确认转换的是 `aurora.img` 本体 |
| 黑屏、`aurora-serial.log` 为空 | Limine 没起来 | 在 VMware 的 EFI 菜单（开机按 Esc）看有没有启动项；检查 Secure Boot 已关 |
| 串口日志有内核输出但窗口黑屏 | 没带 `fbcon-live`，或 GOP 分辨率不被 `framebuffer` 接受 | 先用串口确认内核活着；把日志里 `framebuffer`/`fb` 相关行贴回 |
| 日志停在 PCI/AHCI 阶段 | VMware 的 AHCI 与 QEMU 的 ich9-ahci 寄存器行为有差 | 把最后 30 行日志贴回，这是预期会遇到的迭代点 |
| 能看到提示符但键盘没反应 | PS/2 特性没开，或 VMware 没把键盘路由到 i8042 | 确认 `fbcon-live`；在窗口里点一下获取输入焦点 |
| 有 `rand: 熵源 N 路成功` 且 N<2 | VMware 可能不向客户机暴露 rdrand/rdseed，TSC 抖动也可能判为不足 | 不要改 CPUID 屏蔽位。把这行日志贴回；此时 ISN/临时端口会降级为旧可预测公式并让 `ISN_WEAK` 计数（`isn_source`），ktest 的 isn 四格会**跳过而不判绿** |

## 6. 先在 QEMU 里把这些跑绿，再进 VMware

按顺序：`python tools/verify_merge.py --static` → `python tools/verify_merge.py`（含 cargo/aurora.py 全套）→ 手测清单。
**QEMU 绿了，VMware 才有意义**；VMware 上的任何问题都应先问"QEMU 里同一特性组合是否绿"。
