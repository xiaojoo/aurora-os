# Aurora OS 硬件驱动与虚拟机/真机测试体系设计（V1.0，按仓库实测校正版）

状态：**设计文档（校正版）**。本文不是从零规划，而是把"原设计草案"逐条拿到本仓库的
代码、门禁、判定表与 ADR 上对账后，**改写成能落地的那一版**。

- 取证日期：2026-11-19
- 取证基线：HEAD `b85d185`，工作树仅 `AGENTS.md` / `COORD.md` 未跟踪
- 本轮实测读数：`python tools/aurora.py check` = **18/18 全绿**；
  判定表 `rows` = **74 行**；`ktest!` 注册 = **151 条**；`docs/adr/` = **136 份**（ADR-007…160，有缺号）；
  bench 基线 = **91 份**；`kernel/src` 下 `.rs` = **84 个**，全仓（排除 `target/`、`.tools/`）= **165 个**
- 写作纪律（沿用 `AGENTS.md` 硬约束 7）：
  **「检测到」不等于「已恢复」**；**「能编译」不等于「能跑」**；
  **「QEMU 通过」不等于「真机兼容」**。本文每条结论标 **实测** 或 **未验证**，
  未跑过的一律写「未验证」，不抄 QEMU 的数充真机读数。

---

## 0. 一句话结论

**这套硬件驱动工程可以做，但不能按原草案的形状做。**

原草案的技术方向（先 QEMU 真设备模型、再真机；驱动复用现有实现；宿主机第二台仪器对账）
与本仓库既有纪律**一致**，可以照做。但草案有 **11 处**需要改，按性质分三类：

| 性质 | 条目 | 后果（若照抄） |
|---|---|---|
| **推翻已采纳的 ADR 或已生效的裁决**（3 处） | §3.1 `trait Driver`（撞 ADR-030）<br>§3.3 `PixelFormat` 枚举（撞 ADR-083/086 的掩码设计）<br>§3.4 USB/xHCI 与硬件矩阵（撞裁决 ④A/⑥A） | 门禁红，但红因会指向"框架没建好"，不是"你改了已定的语义"；裁决被无声取代 |
| **状态判断错**（2 处） | §3.2 鼠标三键/滚轮（未做，不是待完善）<br>§3.5 DNS/DHCP（已交付，不是欠账） | 前者验收永不通过；后者白干一遍 |
| **环境事实与前置漏项**（6 处） | §3.6 `-display none`（环境事实错）<br>§3.7 显示/输入第二台仪器不在链里<br>§3.8 中断向量 16 格<br>§3.9 DMA 缺"先停再还"判据<br>§3.10 三处登记<br>§3.11 容量硬约束 | 里程碑顺序错位；"看起来绿、实际没测" |

本文 §2 是逐条对账表（**24 项现状 + 7 项路线 + 13 项 QEMU + 10 项测试 + 15 项约束 = 69 项**），
§3 是这 11 处的改法，§4 起是校正后的完整设计。

---

## 1. 为什么"原草案不能照做"值得单独说明

这个仓库的验收制度是**判定表 + 负样本 + 第二台仪器**三件套，不是"功能清单打勾"。
一个设计文档如果带着错的现状描述进来，最坏的结果不是"多做一点"，而是：

- 把**已经交付**的能力当欠账重做 ⇒ 白干，并且**新增一条与既有判据抢设备的用例**；
- 把**已裁决跳过**的能力当里程碑 ⇒ 推翻裁决而没人记录 ⇒ 下一个接手的人以为裁决还在；
- 把**已采纳 ADR 定死的语义**（例如 ADR-030 的"驱动唯一接口是能力句柄表"）
  改成一个 `trait Driver` ⇒ 门禁 `check-driver-ctx` 与 `check-module-interfaces` 当场红，
  而红因会指向"驱动框架没建好"，不是"你改了已定的语义"。

所以本文先做对账，再谈路线。**对账表本身就是这份文档最重要的交付物。**

---

## 2. 逐条对账：原草案断言 vs 仓库实测

判定列：**✅ 相符** / **⚠️ 部分相符（需改写）** / **❌ 不符（必须改）**

### 2.1 现状描述

| # | 原草案断言 | 仓库实测 | 判定 |
|---|---|---|---|
| 1 | 「鼠标：PS/2 Mouse、IRQ12、移动、点击」 | `mouse.rs`（308 行）：i8042 第二口、IRQ12、3 字节包、`decode()` 纯函数、坐标钳位、按下沿记一次点击。**只有左键（bit0）产生点击事件**；bit1/bit2 只进 `BTNS` 原子量，没有右键/中键事件。**无滚轮**（未发 `0xF3` 采样率、未解 4 字节包） | ✅ 相符（但"点击"只指左键，见 §3.2） |
| 2 | 「键盘：PS/2 Keyboard、IRQ1、字符环」 | `kbd.rs`（392 行）：i8042 第一口、IRQ1、64 格字符环、`step()` 纯函数、八格分账计数。**只解 make 码**；文件头自述「本片只解 make 码，且不处理 shift/caps」；Ctrl 已做（S6q，`apply_ctrl`）；`E0 48/50` 走 UI 键槽；break 码**只计数、不产生释放事件** | ✅ 相符 |
| 3 | 「显示屏：Limine Framebuffer、像素写入、文本绘制」 | `frame.rs`（295 行）：按 memmap 物理区间自映射 UC、**只接受 32bpp + RGB 内存模型**（其余直接 `UnsupportedMode`）、按 Limine 掩码打包、**双缓冲 + 行级脏标记已存在**。`fbcon.rs` **4968 行**：位图字形资产、双宽格、浮窗、标签条、下拉、设置页 | ⚠️ 实际比描述强得多；草案的 `PixelFormat` 枚举方向是**错的**（§3.3） |
| 4 | 「显卡：帧缓冲输出」 | 全仓搜 `virtio_gpu` / `nvme` / `xhci` / `usb_hid`：**零命中**（唯一一条是 `mm.rs:1688` 的注释提到 NVMe BAR）。**没有 VirtIO GPU、没有 NVMe、没有 xHCI/USB** | ✅ 相符（真未做） |
| 5 | 「网卡：VirtIO-Net PCI Modern」 | `virtio.rs`（96 KiB）：能力链找寄存器、RX/TX 双队列、DMA 环、DHCP/ARP/ICMP/UDP/DNS 报文构造与解析、ARP 表、路由。**网卡没有认领中断**（全仓 `request_irq` 只有 `ahci.rs:686` 一处）⇒ 收方向是**轮询**（`receive()` 用 `wait_u16` 等 `used.idx`） | ⚠️ 相符，但草案说的"MSI-X 中断"是**未做** |
| 6 | 「磁盘控制器：AHCI SATA DMA 读写、VirtIO Block」 | `ahci.rs`（82 KiB）含 IRQ 认领；`virtio.rs` 两台 virtio-blk 并存（ADR-112）。块请求层**已交付**（`filesystem/block_io.rs`，ADR-110：死线、取消、`sectors_done`、错误归因不合并） | ⚠️ 相符，但草案说"需要请求队列"**已过期** |
| 7 | 「PCI/PCIe：枚举、ECAM/CAM、BAR、能力链」 | `pci.rs`（514 行）：ECAM 优先、CAM 回退、BAR 尺寸探测（写全 1 + 还原 + 读回对账）、MSI/MSI-X/INTx 能力链读取（带跳数上限与坏链归因）、`MAX_DEVICES=64`、`MAX_ECAM_BUSES=256`、**多段 ECAM 只登记第一段**（静默忽略） | ✅ 相符 |
| 8 | 「中断：LAPIC、IOAPIC、MSI/MSI-X」 | `irq.rs` + `apic.rs`（47 KiB）：认领表、向量 `32..=47`（**16 格硬上限**）、亲和性、两本账（到过 ISR 的发数 / 认领的发数） | ⚠️ 相符，但**16 格是硬容量**，草案完全没提（§3.8） |
| 9 | 「DMA：DriverCtx、DMA 资源管理」 | `driver.rs`（521 行）：`MmioHandle`/`DmaHandle`/`IrqHandle` 都是 `槽号+世代号`，资源本体只在表里；`MMIO_SLOTS=8`、`DMA_SLOTS=8`；撤销后旧句柄必被拒（`StaleHandle`）；句柄认主人（`NotOwner`）；**中断上下文建资源被拒**（`WrongContext`）；DMA 缓冲**不交出 `&[u8]`** | ✅ 相符，且比草案描述更严格 |
| 10 | 「还没有完整的 `Device/Driver` 对象模型」 | 属实：没有 `trait Driver`、没有 `DeviceInfo`、没有设备树、没有匹配器。**但** `lspci`/`lsdev`/`devctl status` 已交付（ADR-149），31 号 `SYS_PCI_ENUM` 有用户态出口 | ✅ 相符（"缺什么"描述对，"该怎么办"不对，§3.1） |
| 11 | 「`driver.rs` 包括 DriverCtx / MmioHandle / DmaHandle / IrqHandle / 资源认领与句柄管理」 | 逐项对上，另加 `irq_message`/`irq_counts`/`irq_set_affinity`/`irq_dest`/`occupancy()` | ✅ 相符 |
| 12 | 「VirtIO-Net 能工作不代表 Intel/Realtek 能工作」 | 完全成立。物理网卡驱动**零行代码** | ✅ 相符 |
| 13 | 「`kernel/src/input/kbd.rs`、`mouse.rs`、`irq.rs` 已有」 | 三个文件都在 | ✅ 相符 |
| 14 | 「`kernel/src/display/frame.rs`、`fbcon.rs` 已有」 | 都在（`fbcon.rs` 4968 行，远超草案想象） | ✅ 相符 |
| 15 | 「`kernel/src/driver/virtio.rs` 已含 VirtIO 网络设备实现」 | 属实（含 blk + net + MSI-X 探测） | ✅ 相符 |
| 16 | 「`kernel/src/ktests/net/net.rs` 有网络测试：帧发送/接收/ARP/Ping/UDP/路由」 | 实测 6 条：`KT_NET_TX` `KT_NET_RX` `KT_NET_ARP` `KT_NET_PING` `KT_NET_UDP` `KT_NET_ROUTE` | ✅ 相符 |
| 17 | 「已有 84 个 Rust 源文件」 | `kernel/src` 下 `.rs` = 84 ✅；但**全仓**（排除 `target/`、`.tools/`）= 165 | ⚠️ 口径要说清 |
| 18 | 「`check` 18 道门禁」 | 本轮实测 **18/18**：lints-wired / unsafe / crates / module-interfaces / vector-table / interface-change / driver-ctx / state-window / virtio-pattern / fat32-ports / net-pattern / sha-primitives / sig-anchor / pkg-manifest / sbom / matrix-wiring / verdict / nofloat | ✅ 相符（注：`AGENTS.md` 写的"17 道"**已过期**） |
| 19 | 「判定表 41 行」 | 实测 **74 行** | ❌ 不符（`AGENTS.md` 的 41 也过期） |
| 20 | 「ADR 目前 014–045，共 31 份」 | 实测 **136 份**，编号 ADR-007…ADR-160（有缺号），最新 `ADR-160` | ❌ 不符（`AGENTS.md` 严重过期） |
| 21 | 「新决定从 046 起编」 | 已用到 **160**，下一个是 **161** | ❌ 不符 |
| 22 | 「`docs/hardware/` 目录都还不存在」（草案引审计语） | `docs/hardware/bringup.md` **已存在**（109 行，M7 待测清单，**31 条** H-01…H-31，**零条已测**），且**已被 git 跟踪** | ❌ 不符 |
| 22b | `AGENTS.md` 说「ADR-007 已起草并采纳（**文件仍未跟踪**）」 | `git ls-files docs/adr/ADR-007-用户权限只从句柄来而两张句柄表分家.md*` **有输出** ⇒ 该文件**已被跟踪**。`AGENTS.md` 这一句也过期 | ❌ 不符（补记） |
| 22c | `AGENTS.md` 说「`docs/Aurora_OS_内核详细架构设计与模块接口规范_V1.0.md` 在仓库里是**未跟踪**文件」 | `git ls-files` 该路径**有输出** ⇒ **已被跟踪**。同一段落里两条「未跟踪」描述都已过期 | ❌ 不符（补记） |

### 2.2 路线与里程碑

| # | 原草案断言 | 仓库实测 | 判定 |
|---|---|---|---|
| 23 | 「AHE-01 统一驱动框架：Device、Driver、驱动注册、设备匹配、资源管理和生命周期」是**最优先** | 资源管理与生命周期**已存在且已采纳 ADR-030**；真正缺的是"设备对象 + 匹配器 + 生命周期编排"。若按草案写 `trait Driver { probe/initialize/shutdown }`，与 ADR-030「驱动的唯一接口是能力句柄表」冲突，且违反硬约束 2「不创建没有真实调用者的空 trait」 | ❌ 排序与形状都要改（§3.1） |
| 24 | 「AHE-06 USB Host：xHCI、USB 枚举、HID」 | **裁决 ④A 已明确跳过 D1（USB Host/HID）**，记录在 `docs/Aurora-OS-未完成步骤审计-2026-11-19.md` §三与 §四；总设计 §9 D1 段也只写"后期" | ❌ 推翻已采纳裁决（§3.4） |
| 25 | 「AHE-04 VirtIO GPU」排在显示之后 | 仓库无任何 virtio-gpu 代码，QEMU 11.1.0 **支持** `virtio-gpu-pci`；但当前 QEMU 命令行是 `-display none`，**没有 `-vga`、没有 GPU 设备** | ⚠️ 可做，但要先改 QEMU 接线（§5.2） |
| 26 | 「AHE-05 网络：完善 VirtIO-Net，打通 DHCP、DNS、TCP、Socket」 | DHCP 报文构造/解析**已有**；DNS 解析器**已有**（47 号 `SYS_DNS_RESOLVE`，ADR-158，含名字编码与 A 记录提取）；**TCP 与 Socket API 真没有** | ⚠️ 一半已交付（§3.5） |
| 27 | 「AHE-07 物理硬件驱动：Intel/Realtek 网卡、NVMe、物理显示设备及 USB 外设」 | 全部未做，且 QEMU 侧 `e1000`/`e1000e`/`igb`/`rtl8139`/`nvme` **都有设备模型**可先做驱动 | ✅ 相符（可做，顺序要改） |
| 28 | 「AHE-08 真实 PC 验收：硬件兼容性矩阵」 | `docs/hardware/bringup.md` 已有清单但**无目标机型**（§1 全"待填"）；裁决 ⑥A 已跳过 D5（硬件矩阵与发行） | ❌ 与裁决 ⑥A 冲突（§3.4） |
| 29 | 「继续使用 `check` / `test` / `bench`」 | 对，但 `aurora.py` 实际有 **8 个子命令**：`build`/`image`/`run`/`test`/`bench`/`check`/`ktests`/`release`。且本机控制台是 **GBK**，跑任何入口都要 `PYTHONIOENCODING=utf-8 PYTHONUTF8=1`，否则中文锚点判据会静默读成"零条记录" | ⚠️ 需补全（§7.1） |

### 2.3 QEMU 环境

| # | 原草案断言 | 仓库实测（`tools/aurora.py:3823-3831` 的 `cmd` 块） | 判定 |
|---|---|---|---|
| 30 | 机器类型 Q35 | `-M q35`（`:3823`） | ✅ |
| 31 | CPU x86-64 `-cpu max` | `-cpu max`（注释：**必需**而非偏好——默认 `qemu64` 的 smep/smap/x2apic 全 false） | ✅ |
| 32 | CPU 核数 4 | `-smp 4` | ✅ |
| 33 | 内存 2 GB | **`-m 512M`** | ❌ 不符 |
| 34 | 固件 OVMF UEFI | 两块 pflash（code 只读 + vars 可写副本，每次从模板重拷） | ✅ |
| 35 | Bootloader Limine | `boot/limine.conf`，Limine 11.4.1，`kernel_path: boot():/boot/aurora.bin` | ✅ |
| 36 | 显示输出「QEMU 标准 VGA / VirtIO 显示设备分阶段测试」 | **`-display none`**，命令行**无 `-vga`**。今天所有画面验证走 QMP `screendump`（headless） | ❌ 不符（§3.6） |
| 37 | 键盘「PS/2 + USB 键盘」 | PS/2 有（`ps2-kbd` 特性）；USB **无**（裁决 ④A） | ⚠️ 一半 |
| 38 | 鼠标「PS/2 + USB 鼠标」 | PS/2 有（`ps2-mouse` 特性）；USB 无 | ⚠️ 一半 |
| 39 | 网络 VirtIO-Net | `-device virtio-net-pci,netdev=n0,mac=…` + `filter-dump` 写 pcap（第二台仪器） | ✅ |
| 40 | 存储「AHCI + VirtIO Block」 | `if=ide,index=N` 落 ich9-ahci 端口 N；`virtio-blk-pci` 最多两台 | ✅ |
| 41 | 「`aurora-dev` / `aurora-hwtest` 两套配置」 | 今天只有一套配方；`AURORA_QEMU_EXTRA` 环境变量是逃生口 | ⚠️ 需新建（§5.3） |
| 42 | QEMU 版本 | **11.1.0**（`v11.1.0-12130-ge470268ff4`），已核实支持 `virtio-gpu-pci`、`nvme`、`qemu-xhci`、`usb-kbd`、`usb-mouse`、`intel-iommu`、`e1000`/`e1000e`/`igb`/`rtl8139`、`pcie-root-port`、`ich9-intel-hda` | ✅（设备模型齐全） |

### 2.4 测试体系

| # | 原草案断言 | 仓库实测 | 判定 |
|---|---|---|---|
| 43 | 「每个驱动至少要通过四类测试：单元 / 硬件集成 / 端到端 / 故障注入」 | 本仓库实际做到 **三类**：内核 ktest + 判定表行 + 变异证红。审计 §四.4 自己承认「单元测试与故障注入覆盖不均」 | ⚠️ 目标可写，但要标注"现状三类" |
| 44 | 「不能只看内核启动成功，也不能只看驱动打印 `initialized`」 | 完全成立，且本仓库更严：**每条硬件结论都要第二台仪器** | ✅ |
| 45 | 「Aurora OS 现有 `tools/aurora.py` 已采用宿主机辅助验证，推广到所有硬件驱动」 | 成立且规模很大：pcap 对账、`qemu-img info` 容量对账、`-d int` 投递对账、`pmemsave` 读回致命现场、`validate_esp.py` 独立重算 GPT/FAT16 | ✅ |
| 46 | 「显示屏：QMP `screendump`、PPM 像素采样」 | **这是最大的缺口**：`tools/aurora.py` 里 `screendump` **零命中**。screendump 脚本全在 `.scratch/`（`s57-drag-check.py`、`s6q_flicker.py` 等），而 `.scratch/` 被 `.gitignore` 挡着、**零个文件被跟踪** ⇒ **显示/输入的第二台仪器不在判定链里** | ❌ 不符（§3.7） |
| 46b | 「QMP `screendump` 已经能用」 | 半对：`qmp_snapshot`（`aurora.py:2993`）与 `qmp_pmemsave`（`:3088`）已在链里，但**只用于挂死取证与致命现场**，没有 `screendump`。`screendump` 的 socket 形状可以照抄这两个 | ⚠️ 需新建 |
| 47 | 「键盘：QMP 输入注入、串口日志」 | `tools/aurora.py` 无 `input-send-event` / `send-key`；`serial-rx-probe` 走的是**串口**喂字节（`chardev:serialrx`），不是 QMP 键盘注入 | ❌ 不符 |
| 48 | 「鼠标：QMP 鼠标移动、点击注入」 | 同上，无 QMP 注入；拖动验证靠 `.scratch/s57-drag-check.py`（未跟踪） | ❌ 不符 |
| 49 | 「磁盘：镜像文件哈希、扇区内容对账」 | 成立（`check_disk_content`、`check_vblk_write`、`check_scratch_write`、`check_fs_rw_image`） | ✅ |
| 50 | 「网卡：tcpdump、pcap 文件」 | 成立（QEMU `filter-dump` + `check_net_tx`/`check_net_rx` 逐字节重算） | ✅ |
| 51 | 「单元测试：验证协议和数据解析」 | 有纯函数级用例（`t_ps2_kbd_decode`、`t_madt_offsets_synthetic`、`t_pci_config` 等），但**不是每个域都有** | ⚠️ 部分 |

### 2.5 约束与硬规则

| # | 原草案断言 | 仓库实测 | 判定 |
|---|---|---|---|
| 52 | 「不重写 `pci.rs` / `driver.rs` / `ahci.rs` / `virtio.rs` / `kbd.rs` / `mouse.rs` / `frame.rs` / `fbcon.rs`」 | 与 `AGENTS.md` 硬约束 1/2 同向，可照做 | ✅ |
| 53 | 「不允许无限等待，所有硬件轮询都必须设置超时」 | 已是既成事实：`xfer` 带 spins、`wait_u16` 带 `wait_ms`、`block_io` 带 `deadline`、`CAP_HOPS_MAX=16` | ✅（已成立，非新要求） |
| 54 | 「ISR 不打印、不阻塞、不受控分配、正确 EOI」 | 已是既成事实且有判据：`KT_ISR_ALLOC_GUARD`（`t_no_alloc_in_isr`）+ `fault-alloc-in-irq` 期望 39 | ✅（已成立） |
| 55 | 「DMA 安全：缓冲区明确所有权、设备停 DMA 后才回收」 | `DmaHandle` 不交切片；但**「先停 DMA 再还页」这一步没有机器判据**，只有 `Mapping::drop` 的解映射顺序 | ⚠️ 方向对，缺判据（§3.9） |
| 56 | 「逐步引入 IOMMU 映射与隔离」 | `acpi.rs` 只解析 DMAR 的 `host_address_width` 与 `flags`（`:171-172`、`:442-444`），**不建任何映射表**；本机 DMAR 缺席 | ⚠️ 相符（"逐步"是对的） |
| 57 | 「每次修改必须回归」 | 成立，但必须跑 `check` **18** 道 + 判定表 **74** 行 + `ktests` **151** 条 | ⚠️ 数字要更新 |
| 58 | 「不要把现有 84 个 Rust 源文件整体重构」 | 成立（`kernel/src` = 84） | ✅ |
| 59 | 「新增硬件变体必须有独立测试入口，不能污染默认测试基线」 | 成立，且已制度化：47 个特性被判定表使用；`check-matrix-wiring` 抓"行名重复/共用日志变量/共用退出码变量/判定值被覆盖" | ✅ |
| 60 | 草案未提：**新增驱动必须登记 `module-interfaces.toml`** | `check-module-interfaces` 要求 `main.rs` 每个顶层 `mod` 恰好被一个逻辑模块覆盖，且 `[baseline].known_scc` 与实际强连通分量**相等**。当前有**一个 11 模块的环 A**（arch·boot·diagnostics·driver·irq·memory·pci·resource·storage·sync·time） | ❌ 漏项（§3.10） |
| 61 | 草案未提：**新增驱动必须进 `DRIVER_MODULES`** | `check-driver-ctx` 只扫 `["ahci.rs", "virtio.rs"]` 两个文件。新驱动不加进清单 ⇒ 这条门禁**对它是假的** | ❌ 漏项（§3.10） |
| 62 | 草案未提：**中断向量只有 16 格** | `trap::VEC_IRQ_BASE=32`、`VEC_IRQ_LAST=47` ⇒ `irq::SLOTS=16`。AHCI、kbd、mouse、串口等已在用 | ❌ 漏项（§3.8） |
| 63 | 草案未提：**堆单次上限 2048 字节** | `heap::LARGE_MAX = 2048`（ADR-018 / ADR-026）。任何"按段开缓冲"的写法会被当场打死 | ❌ 漏项（§3.11） |
| 64 | 草案未提：**`MAX_TASKS = 9` 每 CPU 且零余量** | `sched.rs:31`；`docs/design/完整化路线-M0至M9-依赖重排与四裁决.md` 记「7 线程 + boot + idle **零余量**」 | ❌ 漏项 |
| 65 | 草案未提：**`.text` 窗口反复溢出** | 审计 §四.2：已第六次扩容 20→24→32→40→48 KiB；ADR-155 记第七次 48→128 KiB。根因是 shell 单二进制承载全部命令 | ❌ 漏项 |
| 66 | 草案未提：**`.ktests` 顺序由链接器决定** | `AGENTS.md` 取证纪律：用例必须自足，不能假设别的用例已经认领过设备；搬迁模块会改串口行序 | ❌ 漏项（§7.3） |

---

## 3. 必须改的 11 处（按影响排序）

### 3.1 【最重要】不要引入 `trait Driver` 对象；用「设备表 + 匹配器 + 既有 DriverCtx」

**原草案**：

```rust
pub trait Driver {
    fn name(&self) -> &'static str;
    fn probe(&self, device: &DeviceInfo) -> Result<ProbeResult, DriverError>;
    fn initialize(&mut self, ctx: &DriverCtx) -> Result<(), DriverError>;
    fn shutdown(&mut self) -> Result<(), DriverError>;
}
```

**为什么不能照做**（三条独立理由，任何一条都足以否掉）：

1. **与已采纳的 ADR-030 冲突**。ADR-030 标题就是「驱动的唯一接口是能力句柄表；MMIO 与 DMA 由内核持有」，
   决定 1 写死"句柄 = 槽号 + 世代号，资源本体只活在表里"，决定 5 写死"**首期只做被用到的方法**……
   先把没人调的方法摆进 trait，就是把目录当成实现"。`trait Driver` 的四个方法里，
   `name`/`shutdown` 今天**零调用者**。
2. **违反 `AGENTS.md` 硬约束 2**：「不创建没有真实调用者的空 trait、空服务、空模块」。
3. **`&mut self` 在这个内核里没有落脚点**。驱动状态今天住在静态 `UnsafeCell` 里
   （`driver.rs:127` 的 `TABLE`、`pci.rs:52` 的 `TABLE`、`virtio.rs` 的 `NetCell`），
   因为 `mm`/`sched`/`trap` 都不许重写，没有"驱动实例"这个内存位置可放 `&mut self`。
   硬造一个就得先造分配器 + 生命周期 + 析构顺序，那是把 AHE-01 变成一次内核对象模型重构。

**改成**（与本仓库形状一致，且每一条都能被机器判）：

```text
设备表（定长，静态）
  pci::Dev 已存在：bdf / vendor / device / cfg08 / hdr / bar0
  ↓ 只加"不重不漏"的三格，不新建设备树对象
DeviceInfo { dev: Dev, class: u8, subclass: u8, progif: u8, revision: u8 }

匹配器（纯函数，可单测，无分配）
  fn match_id(vendor: u16, device: u16) -> Option<DriverId>
  fn match_class(cls: u8, sub: u8, progif: u8) -> Option<DriverId>
  ↑ 两张静态表 + 一个纯函数 ⇒ 能写 t_ 用例，能被变异证红，不需要实例

驱动入口（保持现有形状：自由函数 + DriverCtx）
  ahci::claim(ctx) -> Result<(), AhciError>          ← 已存在
  virtio::bind_at(i) -> Result<(), VirtioError>      ← 已存在
  nvme::claim(ctx) -> Result<(), NvmeError>          ← 新增，同一形状

生命周期（表驱动，不是 trait 对象）
  DeviceState { Unclaimed, Probing, Active, Failed(&'static str), Released }
  状态迁移只经 driver::set_state(dev_id, new) —— 非法迁移返回 Denied，计数可见
```

**这条改动的验收**：`t_match_id` / `t_match_class` 纯函数用例 + 一条变异
（把 `match_id` 恒返 `None` ⇒ 判据必须红）。不需要新 ADR，因为它**没有改** ADR-030 的语义，
只是把 ADR-030 决定 5 说的"没调用者就别写"落成实际形状。

> 如果使用者**确实**要 `trait Driver`（例如为了将来把驱动移到用户态），那是一次
> **改 ADR-030 已定语义**的动作，按 `AGENTS.md` 工作协议必须**先停下来问**，
> 并起草新 ADR（编号从 **161** 起），不能在本设计里悄悄落。

### 3.2 鼠标：右键/中键与滚轮是"未做"，不是"已有待完善"

**实测**（`mouse.rs`）：

- `decode()` 返回 `(dx, dy, buttons)`，`buttons` 取 `p0 & 0x07` ⇒ 三键位**都读到了**；
- 但 `isr()` 里只有 `btns & 0x01 != 0 && prev & 0x01 == 0` 才产生 `CLICK_PENDING` ⇒
  **只有左键有事件**；右键/中键只在 `BTNS` 里存在，`main.rs:2971` 只读 `& 0x01`；
- **完全没有滚轮**：没发 `0xF3`（设置采样率）切到 4 字节包，没有解 `p2` 的低 4 位作为 Z 位移。

所以原草案 §5.1 的验收要求 3「左键、右键、中键正确」与 4「支持滚轮」，
**当前一条都不满足**，不是"更多协议"这种边角。

**改成**（分三步，每步可独立判定）：

| 步 | 内容 | 判据 | 负样本 |
|---|---|---|---|
| M-1 | 右键/中键事件：把"按下沿"从只判 bit0 改成三键各记一次，事件带 `button: u8` | `t_mouse_edges`：喂 `p0` 序列，断言三键各产生恰好一次按下沿、按住不重复 | 把 bit1 判成 bit0 ⇒ 红 |
| M-2 | 滚轮：先发 `0xF3 200` 再 `0xF3 100` 再 `0xF3 80`，读 `0xF2` 回包确认采样率接受；解 4 字节包，`p3` 低 4 位符号扩展为 Z | `t_mouse_wheel`：喂 4 字节包，断言方向与步数；`EnableInfo` 增加 `sample_rate_ack` 三格读数 | 不切 4 字节包 ⇒ 第 4 字节被当下一包首 ⇒ `BAD_SYNC` 计数涨 ⇒ 红 |
| M-3 | 用户态出口：新增事件队列 + 一个读接口（**需要新 syscall 号 ⇒ 先裁决**） | 判定表新增一行，ring3 探针读到事件 | 队列不推进 ⇒ 红 |

> **M-3 触到 `AGENTS.md` 的"新增 syscall 号要停下来问"**。今天 1..47 已占满连续段
> （**2 号是 `rdi + rsi` 的算术探针，不是空洞**；99 号是 `SYS_NOT_A_NUMBER` 负样本），
> 下一个是 **48**。本文不替你决定，只标出前置条件。

### 3.3 显示：不要建 `PixelFormat` 枚举；沿用"按 Limine 掩码打包"

**原草案**给了一个 `PixelFormat { Rgb888, Bgr888, Xrgb8888, Xbgr8888 }` 枚举并要求
"像素格式识别、RGB/BGR 格式处理"。

**为什么这是错的**：`frame.rs:164` 的 `pack()` 已经用**启动信息给的掩码**算，
注释写明了理由——"字段宽度不足 8 位时高位要丢掉，而移位量是 bootloader/固件给的——
不同机器上 BGRA 与 RGBX 都出现过。硬编码的结果是'画出来了但颜色不对'，那种错不会让任何判据变红"。
用一个四值枚举替换掩码运算，等于**把"设备说了算"改回"我们猜"**，方向正好相反。

**真正的缺口**是：`frame.rs:76` 直接拒掉非 32bpp / 非 RGB 内存模型

```rust
if info.bpp != SUPPORTED_BPP || info.memory_model != MEMORY_MODEL_RGB {
    return Err(FrameError::UnsupportedMode { bpp: info.bpp, memory_model: info.memory_model });
}
```

**改成**：

- 保留掩码打包（不动）；
- 把"只支持 32bpp"从**硬拒绝**改成**分级支持**：24bpp/16bpp 各加一个按掩码拆字节的写入器，
  每个宽度一条用例 + 一条变异（把 5/6/5 的字段宽度写错一位 ⇒ 串色 ⇒ 红）；
- `UnsupportedMode` 保留给**真正不支持**的形状（例如 `memory_model != RGB` 且不是已知索引色），
  并且**必须打印实际值**（现在已经在打印）。

**热插拔与分辨率切换要删掉**：`docs/hardware/bringup.md` 已经说明真机侧
"Limine 交接的 framebuffer"是启动期一次性事实；UEFI GOP 没有热插拔语义。
把它写进第一阶段里程碑会让"通过"永远无法达成。改为**长期目标**并注明依赖 UEFI Runtime Services。

### 3.4 USB/xHCI 与硬件矩阵：已被裁决跳过，要重开必须显式重新裁决

**实测**：

- `docs/Aurora-OS-未完成步骤审计-2026-11-19.md:28`：「**D1** USB Host/HID | **未开始** | 无 xHCI、无 USB 栈（**按裁决④A 跳过**）」
- 同文件 `:32`：「**D5** 硬件矩阵与发行 | **未开始** | …（**按裁决⑥A 跳过**）」
- 同文件 `:153`：「按使用者裁决 **④A / ⑤A / ⑥A 跳过**……这三项**不是遗漏，是显式决定**。」
- 总设计 §9 D1 段（`:1085`）本身只写标题，正文归在"后期能力"（`:664-668`：「先完成 PCI/中断/DMA/IOMMU/驱动模型，再进入 USB Host Controller」）

**原草案把 xHCI 列为 AHE-06、把硬件矩阵列为 AHE-08**，等于无声推翻两条裁决。

**改成**：

1. 本文**不**把 USB 与硬件矩阵排进 AHE-01..N 的必做序列，改为**候选里程碑（需重新裁决）**；
2. 给出**重开条件**（写清什么条件下才值得重开，避免"因为想做所以做"）：
   - USB：物理机验收要求"USB 键盘可用"是**硬需求**时（因为现代 PC 普遍无 PS/2）；
   - 硬件矩阵：有第二台及以上目标机型，且 `bringup.md` §1 的七个字段能填满。
3. 若重开，走 `AGENTS.md` 的"先裁决、后实现、再登记"：新 ADR（**161** 起）+ BACKLOG 记一条
   "裁决 ④A/⑥A 被取代，理由与替代裁决"。

> 本文的立场：**先做能被现有判定表接住的驱动（NVMe、virtio-gpu、物理网卡），
> 再谈需要新裁决的外设栈。** 这不是保守，是因为前者的"通过"今天就能定义，后者不能。

### 3.5 网络：DNS 与 DHCP 已交付，只剩 TCP 与 Socket

**实测**：

- DNS：`virtio.rs:1559 build_dns_query_name`、`:1721 encode_dns_name`（RFC1035 长度前置编码）、
  `:1628 dns_first_a`（跳过 QDCOUNT 再逐条看 answer，压缩指针只认向前、最多跳 8 次）、
  `:1787 parse_dns_reply`；用户态出口 `SYS_DNS_RESOLVE=47`（ADR-158）。
- DHCP：`build_dhcp_discover` / `parse_reply` / `OPT_SUBNET_MASK` / `OPT_ROUTER` 都在。
- **TCP：零行**。**Socket API：零行**（`SYS_` 表里没有 socket 一族）。
- 已知欠账：DHCP 解析出的掩码/网关**没进全局配置槽**（ADR-147 未决 1）；
  slirp 的 DNS 在本机离线 ⇒ `nslookup localhost` 返回 `ancount=0`（ADR-141/ADR-158 已诚实记录）。

**改成**：AHE 网络段拆成两片，顺序倒过来：

1. **先补 DHCP 掩码/网关进配置槽**（小，可判定，不需要新号）——它是 `ip route` 正确性的前置；
2. **再 TCP**（大）。TCP 必须**先有 Socket API 的形状**才能定验收句，否则"TCP 通了"只能靠内核自报，
   而本仓库纪律不接受自报。所以 TCP 与 Socket 是**一片**，不是两片。
3. **物理网卡**（Intel/Realtek）排在 TCP **之前**——理由：QEMU 有 `e1000`/`e1000e`/`igb`/`rtl8139`
   设备模型，可以用**同一套判定表**验证物理驱动（同一份 pcap 对账），而 TCP 需要新判据。
   先用物理网卡把"驱动"这件事做完，再上协议栈。

### 3.6 QEMU 环境：`-display none` 是当前事实，显示里程碑必须先改接线

**实测**（`tools/aurora.py:3823-3831`）：

```python
cmd = [
    str(QEMU), "-M", "q35", "-m", QEMU_MEM, "-smp", QEMU_SMP, "-cpu", QEMU_CPU,
    "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
    "-drive", f"if=pflash,format=raw,file={vars_run}",
    "-drive", f"format=raw,file={IMAGE}",
    "-serial", "chardev:serialrx" if serial_rx else f"file:{SERIAL_LOG}",
    # 端口必须与 kernel/src/exit.rs 的 DEBUGEXIT_PORT 一致（check-verdict 机器对账）
    "-device", f"isa-debug-exit,iobase={DEBUGEXIT_IOBASE},iosize=0x04",
    "-display", "none", "-no-reboot", "-monitor", "none",
]
```

没有 `-vga`、没有 `-device virtio-gpu-pci`、没有 `-device VGA`。
**今天能出画面，是因为 Limine 拿到了 OVMF 提供的 framebuffer**（`-display none` 下
QEMU 仍提供默认 VGA 设备的 linear framebuffer，只是不显示窗口）。

**改成**（这是显示/GPU 里程碑的**第一步**，不是可选项）：

| 阶段 | QEMU 接线 | 目的 |
|---|---|---|
| D-0（今天） | `-display none` + 默认 VGA framebuffer | 已有，`frame.rs` 能映射 |
| D-1 | `-display none -device VGA,vgamem_mb=16`（显式声明） | 把"默认 VGA"变成**接线上的事实**，而不是隐式行为 |
| D-2 | `-display none -device virtio-vga` | virtio-gpu 的**兼容模式**：framebuffer 仍由 PCI BAR 给，但设备已是 virtio |
| D-3 | `-display none -device virtio-gpu-pci` | 纯 virtio-gpu：**没有 framebuffer**，必须走资源创建 + scanout |

**关键判断**：D-2 与 D-3 是**两条不同的设备路径**。原草案说"不能把标准 VGA 帧缓冲输出成功当成
VirtIO GPU 驱动完成"——这句是对的，本文保留，并把它落成一条判据：
**`devctl status` 必须能分辨这两种设备，判定表必须各有一行。**

### 3.7 显示/输入的第二台仪器不在判定链里（最大缺口）

**实测**：

- `tools/aurora.py` 搜 `screendump`：**零命中**；
- 搜 `input-send-event` / `send-key`：**零命中**；
- `screendump` 只出现在 `.scratch/s57-drag-check.py`、`.scratch/s6q_flicker.py`、`.scratch/_s6g_look.py` 等；
- `.scratch/` 在 `.gitignore` 里（`/.scratch/`），`git ls-files .scratch` = **0 个文件**；
- 被跟踪文件里提到 `screendump` 的只有三个：`BACKLOG.md`、`kernel/Cargo.toml`（注释）、`kernel/src/main.rs`（注释）。

⇒ **原草案说"这套方法应该推广到所有硬件驱动"是对的，但显示与输入恰好是唯一没推广到的两个域。**
`main.rs:244` 的注释甚至写清了流程（"取证跑用 `framebuffer,handles,resident-init`，宿主机轮询到标记再发 QMP `screendump`"），
但**宿主机那一半从未进 `aurora.py`**。

**改成**：把"第二台仪器"从 `.scratch/` 提升为 `tools/` 的正式入口，并进判定表。

| 新增 | 形状 | 判据 |
|---|---|---|
| `tools/aurora.py` 内 `qmp_screendump(port, path)` | 复用已有 `qmp_snapshot` 的 socket 形状（`:2993`） | `screendump` 返回后**必须等落盘**（`.scratch/s6h_docs.py:57` 记过：不等会读到上一版 PPM） |
| `check_frame_ppm(ppm, log)` | 按 `frame.rs:samples()` 的**同一份算法独立复算**四个采样点 | 四个点全对才 PASS；错一个报 CONTENT-MISMATCH |
| 判定表新增行 | `("帧缓冲图案与宿主机PPM对账", ..., "PASS", 33)` | 内核绿而 PPM 不对 ⇒ CONTENT-MISMATCH |
| 负样本 | 改 `draw_test_pattern` 的色条顺序 | 必须红在"下左红"那一点 |

**这条是本设计里性价比最高的一处**：它把已经写好但**没进链**的取证接进判定表，
让显示域从"零行判据"变成"一行判据 + 一条负样本"。

### 3.8 中断向量只有 16 格，是硬容量

**实测**：`trap.rs:158-159`：

```rust
pub const VEC_IRQ_BASE: usize = 32;
pub const VEC_IRQ_LAST: usize = 47;
```

⇒ `irq.rs:32` 的 `SLOTS = 16`。`irq.rs` 的公开面只有 11 个函数
（`request`/`release`/`message`/`set_affinity`/`dest`/`counts`/`moves`/`by_cpu`/`in_range`/`dispatch`/`stats`），
**没有 `occupancy()`** ⇒ 今天**读不到"还剩几格"**。这是本文要补的第一件事。

今天已知占用：AHCI（MSI）、PS/2 键盘（IRQ1）、PS/2 鼠标（IRQ12）、串口（IRQ4）、
LAPIC timer、resched IPI、跨核 shootdown 等——**注意 `irq::request` 全仓只有一个产品调用者**
（`ahci.rs:686`）；`kbd.rs:312` 与 `mouse.rs:238` 也调它，但两者都在 `ps2-*` 特性档里。

**原草案完全没提这件事**，但它直接决定"AHE 能同时接几个设备"。

**改成**：

1. 在设备接入清单里加一列**"要几颗向量"**；
2. 定一条**容量闸**：`irq::occupancy()` 超过 12/16 时 `devctl status` 必须打警告行
   （不是错误，是可见的余量读数）；
3. 真要超，**唯一干净的路是把 `VEC_IRQ_LAST` 抬到 63**（IDT 已有 32 条独立向量，
   `t_all_32_vectors_distinct` 是既有判据），但那要同步改 `trap.rs` 的 `p5_hist` 数组、
   `vectors.toml` 登记表、`check-vector-table` 门禁——**是一次要写 ADR 的改动**，
   不放进第一片。

### 3.9 DMA：缺"先停设备再还页"的机器判据

**原草案**说得很对：「设备停止 DMA 后才能回收缓冲区，不能在设备仍可能访问 DMA 缓冲区时释放物理页」。
**但仓库里没有这条的判据。**

**实测**：`driver.rs:416` 的 `release_dma` 只是 `take()` 掉表项，`DmaEntry` 里的 `Mapping`
被 drop 时解映射 + 还帧（`driver.rs:415` 注释）。**没有任何一步检查设备是否还在用这块内存。**
今天之所以不出事，是因为所有调用点都是"先 quiesce 队列再 release"的手写顺序，靠人记。

**改成**（两片，第一片很小）：

1. **第一片（不需要新 ADR）**：给 `DmaEntry` 加一格 `inflight: AtomicUsize`，
   由驱动在"把描述符交给设备"时 +1、"收到完成"时 -1；
   `release_dma` 时若 `inflight != 0` ⇒ 返回新错误 `DriverError::Busy`，**拒绝释放**。
   判据：`t_dma_busy_release`（提交一个描述符不完成 ⇒ release 必拒）+ 变异（去掉检查 ⇒ 红）。
2. **第二片（要 ADR）**：真正的 IOMMU 隔离。`acpi.rs` 已经有 DMAR 的 `host_address_width`/`flags`，
   但没有建表。这一片要新 ADR（**161** 起），且本机 DMAR 缺席 ⇒ **QEMU 侧只能用
   `-device intel-iommu,intremap=on` 做**，真机重测。

### 3.10 新增驱动必须同时改三处登记，否则门禁对它是假的

这是原草案**完全漏掉**的一类工作，而它是"看起来绿、实际没测"的典型来源。

| 登记点 | 文件 | 不改的后果 |
|---|---|---|
| `DRIVER_MODULES` | `tools/aurora.py`（`check_driver_no_raw` 上方） | `check-driver-ctx` **不扫**新驱动 ⇒ 新驱动可以随便 `read_volatile` 摸映射，门禁全绿 |
| `[modules."…"]` | `docs/architecture/module-interfaces.toml` | `check-module-interfaces` 红：「`main.rs` 的顶层 `mod` 没被任何逻辑模块覆盖」 |
| `[baseline].known_scc` | `docs/architecture/module-dependencies.md` + toml | 新驱动若落在环 A 里 ⇒ SCC 变化 ⇒ 红；若在环外 ⇒ 也要登记，否则"环缩小了"没人知道 |
| `[baseline].ring_edge_sites` | 同上（ADR-044 棘轮） | 环内边站点数**必须相等**：+1 红、−1 也红 |

**这条要写进设计的"完成定义"**：一个驱动的里程碑**不算完成**，直到三处登记都改过、且 `check` 18/18。

### 3.11 容量与硬约束清单（草案完全没有，但会直接打死设计）

| 约束 | 实测值 | 对驱动设计的影响 |
|---|---|---|
| 堆单次分配上限 | `LARGE_MAX = 2048` 字节（ADR-018/026） | **不能** `Vec` 化描述符环、不能按段开缓冲。所有大缓冲走 `phys_alloc(order)` + `MmioRegion`（`DriverCtx::alloc_dma` 已是这条路） |
| `MAX_TASKS` | **9 / 每 CPU**，零余量 | 新增"设备服务线程"必须先重算容量；今天已 7 线程 + boot + idle |
| 中断向量 | **16**（32..47） | 见 §3.8 |
| MMIO / DMA 句柄 | 各 **8** 格（`driver.rs:30-32`） | 一个驱动占 1 格 MMIO + 1..2 格 DMA。**但要注意 `probe()` 也占格**：`virtio::probe`（`virtio.rs:246`）为了取证映射一次 MMIO，`bind_one`（`:600`）再映射一次 ⇒ **同一台设备会短暂占 2 格**。今天在线的是 AHCI(1+1) + virtio-blk×2(2+2) + virtio-net(1+2) + probe 的临时格 ⇒ 已接近上限。NVMe + virtio-gpu + 物理网卡同时上 **必然超** |
| PCI 设备表 | `MAX_DEVICES = 64` | 够用，但 `truncated` 必须可见（已有读数） |
| ECAM 总线 | `MAX_ECAM_BUSES = 256`，**只登记第一段** | 多段 ECAM 真机会静默忽略（`bringup.md` H-05） |
| `.text` 窗口 | 已扩到 **128 KiB**（ADR-155） | 新驱动代码会再撞墙。要么继续扩，要么把 shell 外部命令化（审计 §四.2 指出的结构性解法） |
| 内核镜像 | `image=` 行有读数 | 新驱动会让 ELF 变大，`check-nofloat` 的反汇编行数（175842）会涨 |

> **`MMIO_SLOTS`/`DMA_SLOTS` = 8 是本文发现的最硬的一堵墙**：原草案的里程碑要同时挂
> AHCI + 2×virtio-blk + virtio-net + virtio-gpu + NVMe + 物理网卡，**7 台设备，8 格不够**。
> 这不是"以后再说"，是 AHE-02 之前必须解决的前置。

---

## 4. 校正后的技术路线

### 4.1 原则（保留原草案正确的部分）

1. **先在 QEMU 接真设备模型，再上真机**——正确，保留。
2. **QEMU 虚拟设备是真驱动，不是伪造事件**——正确，保留。
3. **两者共用驱动架构，但 QEMU 通过 ≠ 物理兼容**——正确，保留，并升级为硬规则：
   每份驱动文档必须有两个独立结论栏：`QEMU 判定` 与 `真机判定`，后者未跑就写"未验证"。
4. **复用现有实现，不重造**——正确，保留，并落成"§3.1 不改 ADR-030 形状"。
5. **上层不直接操作硬件寄存器**——已经是事实（`check-driver-ctx` 在管），保留。

### 4.2 里程碑重排（AHE-01 … AHE-09）

排序依据不是"哪个功能更想要"，而是**"哪个能解锁最多后续项"** + **"哪个的前置今天已经具备"**。

| 序 | 里程碑 | 为什么排这里 | 前置 | 判定表影响 |
|---|---|---|---|---|
| **AHE-01** | **容量与登记前置** | 8 格句柄 + 16 格向量 + `ModuleId(19)` 撞车 + 三处登记，不先解决，后面每个驱动都在借债 | 无（`ModuleId` 那条要 ADR） | 0 行（只改容量常数 + 门禁清单） |
| **AHE-02** | **设备对象 + 匹配器（无 trait）** | §3.1 的形状；纯函数，能单测 | AHE-01 | +2 行（匹配器正/负） |
| **AHE-03** | **DMA 生命周期判据** | §3.9 第一片；它是所有后续驱动的安全前提 | AHE-02 | +1 行 + 1 负样本 |
| **AHE-04** | **显示第二台仪器接入** | §3.7；把已写好的取证接进链，性价比最高 | 无（可与 01-03 并行） | +1 行 + 1 负样本 |
| **AHE-05** | **NVMe** | 真设备、真 DMA、真 MSI-X，**且不依赖 USB 裁决**；QEMU 有 `nvme` 模型 | AHE-01..03 | +2 行（读/写对账 + 负样本） |
| **AHE-06** | **VirtIO GPU（D-2 → D-3）** | 图形里程碑的**真**入口；先 `virtio-vga` 兼容模式再 `virtio-gpu-pci` | AHE-04 + §3.6 接线 | +2 行（资源创建 / scanout 对账） |
| **AHE-07** | **物理网卡（Intel 优先）** | QEMU 有 `e1000e`/`igb` 模型 ⇒ 可用**同一份 pcap 判据**；比 TCP 便宜 | AHE-01..03 | +2 行（第一帧 / 往返，复用现有 pcap 判据） |
| **AHE-08** | **输入事件统一（鼠标三键 + 滚轮）** | §3.2；PS/2 已通，扩展是增量的 | AHE-04（要 QMP 注入才判得动） | +2 行 |
| **AHE-09** | **TCP + Socket** | 最后，因为它需要新 syscall 号段 ⇒ 要裁决 | AHE-07 | +2 行 |
| 候选 | USB/xHCI、硬件矩阵 | **已被裁决 ④A/⑥A 跳过**，重开需新 ADR（§3.4） | 重新裁决 | — |

**与原草案的顺序差异（要说明理由）**：

- 原草案把 **USB 排在第 6**、**物理驱动排第 7**；本文把 **NVMe 提前到第 5**、**USB 移出必做序列**。
  理由：USB 要新裁决，NVMe 不要；而 NVMe 与 AHCI 共用 `Block` trait，能立刻接进既有块层判据。
- 原草案把 **VirtIO GPU 排第 4**、**显示完善排第 3**；本文把**显示的第二台仪器**提到第 4，
  GPU 放到第 6。理由：GPU 判据必须靠截图，截图不进链 ⇒ GPU 做完了也判不出来。
- 原草案把 **TCP/Socket 放在网络段内**（第 5）；本文拆到第 9。理由：TCP 要新号段，
  而物理网卡不要；先做不要裁决的那一半。

### 4.3 每个里程碑的"完成定义"（比原草案多两条）

原草案列了 8 项交付（源码、接口文档、ADR、正向、负向、QEMU 记录、宿主机对账、回归）。
**本文加两条，因为不加就会重演这个仓库踩过的坑**：

9. **三处登记已改**（§3.10），`check` 18/18；
10. **负样本证明过会咬**：把实现改坏一次看它红、还原看它绿（`AGENTS.md` 取证纪律：
    「量具自己也会错，而且错了看起来像被测物坏了」）。

---

## 5. QEMU 硬件环境（校正版）

### 5.1 实际参数（今天的事实，不是计划）

| 项 | 实际值 | 来源 |
|---|---|---|
| 机器 | `-M q35` | `aurora.py:3823` |
| CPU | `-cpu max` | 同上（必需项，非偏好） |
| 核数 | `-smp 4` | `aurora.py:57` |
| 内存 | **`-m 512M`** | `aurora.py:58` |
| 固件 | 两块 pflash：`edk2-x86_64-code.fd`（只读）+ `edk2-x86_64-vars.fd`（每跑从模板重拷） | `aurora.py:3824-3825`、`:2885-2915` |
| 显示 | **`-display none`**，无 `-vga` | `aurora.py:3830` |
| 串口 | `-serial file:build/serial.log`（或 `chardev:serialrx` 探针） | `aurora.py:3827` |
| 退出 | `isa-debug-exit,iobase=0xf4,iosize=0x04` | `aurora.py:3829` |
| 网络 | `-netdev user,id=n0,net=10.0.2.0/24,dhcpstart=10.0.2.15` + `virtio-net-pci,mac=…` + `filter-dump` 写 pcap | `aurora.py:3888-3893` |
| 存储 | `if=ide,index=N`（落 ich9-ahci 端口 N）+ `virtio-blk-pci` ×2 | `aurora.py:3832-3881` |
| QEMU | **11.1.0** | 实测 `--version` |

### 5.2 需要新增的接线（按里程碑）

| 里程碑 | 新增 QEMU 参数 | 已核实设备存在 |
|---|---|---|
| AHE-05 NVMe | `-drive if=none,id=nvme0,format=qcow2,file=… -device nvme,serial=deadbeef,drive=nvme0` | ✅ `nvme`、`nvme-ns`、`nvme-subsys` |
| AHE-06 GPU D-2 | `-device virtio-vga` | ✅ `virtio-vga`、`virtio-vga-gl` |
| AHE-06 GPU D-3 | `-device virtio-gpu-pci` | ✅ `virtio-gpu-pci`、`virtio-gpu-device` |
| AHE-07 网卡 | `-device e1000e,netdev=n1` / `-device igb,netdev=n1` / `-device rtl8139,netdev=n1` | ✅ `e1000e` `igb` `rtl8139` `e1000` `e1000-82544gc` `e1000-82545em` |
| （候选）USB | `-device qemu-xhci -device usb-kbd -device usb-mouse` | ✅ 全部存在（另有 `ich9-usb-ehci1/2`、`ich9-usb-uhci1..6`） |
| （候选）IOMMU | `-device intel-iommu,intremap=on` | ✅ `intel-iommu`（DMAR 解析已有一半，见 §3.9） |
| （候选）音频 | `-device ich9-intel-hda` | ✅ 存在（裁决 ⑤A 已跳过 D2） |
| PCIe 热插拔实验 | `-device pcie-root-port` | ✅ 存在（GPU/网卡若需真 PCIe 拓扑） |

### 5.3 `aurora-dev` 与 `aurora-hwtest` 两套配置（原草案这一条是对的，补上落法）

原草案要求两套配置。本文补**落法**，因为今天只有一套：

- **不加新子命令**（`aurora.py` 的八子命令是既定契约，加第九个要走裁决）。
- 用**特性名 + 环境变量**表达：
  - `aurora-dev` = 默认配方 + `AURORA_QEMU_QMP=<port>`（已有逃生口，`aurora.py:3901`）
    + `AURORA_QEMU_EXTRA`（已有）；
  - `aurora-hwtest` = **去掉** `isa-debug-exit` 与 QMP，用**真串口判据**或屏幕判据收工
    ⇒ 这一档**不进判定表**（它没有退出码），单独入口跑，与 `fatal-record-stall`
    「这一档自己期望 HANG，所以不进判定矩阵」同一条先例。

> **这条先例很重要**：本仓库已经有"某档不进判定矩阵"的合法形状（`fatal-record-stall`、
> `fatal-record-dump-stall`）。`aurora-hwtest` 照它做，不需要新机制。

---

## 6. 统一驱动框架（校正版，替代原草案 §4）

### 6.1 不新增 `driver/` 子目录

原草案建议：

```text
kernel/src/driver/
├── mod.rs  device.rs  driver.rs  manager.rs  bus.rs
├── resource.rs  power.rs  error.rs  lifecycle.rs
```

**不改的理由**：

1. `kernel/src/driver/mod.rs` **已经存在**（521 行，ADR-030 的落地物）。把它改成目录会
   **移动文件**，而 `check-module-interfaces` 按 `main.rs` 顶层 `mod` 与源模块路径对账
   ⇒ 会红，且红因是"模块接口登记过期"，不是"设计不对"。
2. `AGENTS.md` 硬约束 2：不创建没有真实调用者的空模块。`bus.rs`/`power.rs` 今天**零调用者**
   （没有电源状态机、没有多总线）。
3. 拆目录会改 `unsafe_whitelist.toml` 的模块路径口径（`check-unsafe` 两层口径：crate 名 vs 模块路径）。

**改成**：在 `driver.rs` 里**加**三样（都在现有文件内，不移动任何东西）：

```rust
// driver.rs 追加（不新建文件）
pub struct DeviceInfo { pub dev: Dev, pub class: u8, pub subclass: u8, pub progif: u8, pub revision: u8 }
pub enum DeviceState { Unclaimed, Probing, Active, Failed(&'static str), Released }
pub fn set_state(dev: u32, next: DeviceState) -> Result<(), DriverError>  // 非法迁移 → Denied
pub fn state_of(dev: u32) -> Option<DeviceState>
pub fn occupancy_by_state() -> (usize, usize, usize, usize, usize)  // 五格计数，可见余量
```

**为什么放在 `driver.rs` 而不是新模块**：`driver.rs` 已经在环 A（11 模块强连通）里，
加东西不改 SCC；新开模块会改 `known_scc` ⇒ 门禁红 ⇒ 要先写 ADR 说明为什么拆。
**第一片不拆，是正确的成本选择**，不是保守。

### 6.2 匹配器（纯函数，可单测）

```rust
// driver.rs 追加
pub struct IdMatch { pub vendor: u16, pub device: u16, pub driver: DriverId }
pub struct ClassMatch { pub class: u8, pub subclass: u8, pub progif: u8, pub driver: DriverId }
pub enum DriverId { Ahci, VirtioBlk, VirtioNet, VirtioGpu, Nvme, E1000e, Ig b, Rtl8139 }

static ID_TABLE: [IdMatch; N] = [...];
static CLASS_TABLE: [ClassMatch; M] = [...];

pub fn match_device(d: &Dev) -> Option<DriverId>   // 先按 ID，再按 class 三件套
```

**为什么必须有 `match_class` 而不能只按 vendor/device**：`pci.rs:366` 的注释记了实测——
多挂一块 virtio-blk 之后 class 0x01 有两台设备，而 virtio-blk 的槽位（06.0）排在
ich9-ahci（1f.2）**前面**，扫描顺序决定结果 ⇒ "只按 class 找"会挑错设备。
`first_of_triple(cls, sub, progif)` 就是为此存在的。

### 6.3 生命周期（表驱动，不是状态机框架）

```text
PCI 枚举（已有，pci::init）
  ↓ 每台设备建 DeviceInfo（已有 Dev + 三件套解码）
match_device()
  ├─ Some(id) → set_state(Probing)
  │              ↓ 驱动 claim(ctx)（已有形状：ahci::claim / virtio::bind_at）
  │            Ok  → set_state(Active)      + devctl status 计数 +1
  │            Err → set_state(Failed(名))  + 释放已取资源（DriverCtx 的 Drop 负责）
  └─ None     → set_state(Unclaimed)       + 可见计数（不是错误，是读数）
```

**"释放已取资源"今天已经成立**：`kbd.rs:346-353` 与 `mouse.rs:300-307` 都是
"路由失败先把刚认领的槽还回去"的形状。新驱动照抄这个形状，不新建机制。

### 6.4 原草案那 6 条硬要求，逐条给"今天的状态"

原草案 §4.2 末尾列了 6 条。本文逐条标注，**因为其中 3 条已经是既成事实**（不需要再做），
2 条需要新判据，1 条要新 ADR：

| 原草案要求 | 今天的状态 | 本文处置 |
|---|---|---|
| 不能绕过 `DriverCtx` 直接随意映射 MMIO | **已有机器判据**（`check-driver-ctx`，但只扫 2 个文件） | §3.10：新驱动必须进清单 |
| 不能让驱动自行管理不受约束的 DMA 物理地址 | **已有**：`bus_addr()` 返回整数，DMA 不交切片 | 保持 |
| 设备资源必须有明确所有权 | **已有**：`owner: ModuleId` + `NotOwner` 拒绝 | 保持 |
| 驱动初始化失败必须能清理已取得的资源 | **已有形状**（kbd/mouse 的撤销顺序），**无统一判据** | AHE-03 加一条：注入 `claim` 中途失败 ⇒ `occupancy()` 回基线 |
| 驱动异常不能直接导致整个内核崩溃 | **部分**：`BootMode::Safe` 会跳过可选设备（`boot_guard::optional_devices_allowed`） | 需要一条判定行：`fault-nvme-claim` ⇒ 期望 PASS（不是 39） |
| ISR 不阻塞/不分配/正确 EOI | **已有判据**：`KT_ISR_ALLOC_GUARD` + `fault-alloc-in-irq` ⇒ 39 | 保持 |

---

## 7. 测试体系（校正版，替代原草案 §6）

### 7.1 唯一入口是八个子命令，且必须带 UTF-8 环境

```powershell
$env:PYTHONIOENCODING='utf-8'; $env:PYTHONUTF8='1'
python tools/aurora.py build     # 构建
python tools/aurora.py image     # 造引导镜像
python tools/aurora.py run       # 单跑一档（--features / --host-fault / --timeout）
python tools/aurora.py test      # 判定表（74 行）
python tools/aurora.py bench     # 四把尺子（P1/P2/P3/P4），原始输出自动入库
python tools/aurora.py check     # 18 道静态门禁
python tools/aurora.py ktests    # 只跑内核用例
python tools/aurora.py release   # 发布检查
```

**GBK 那条不是小事**：本机控制台是 GBK，不带环境变量时中文日志读成乱码，
而判定表里大量判据按**中文锚点**匹配 ⇒ 会静默读成"零条记录"⇒ 判据变成空转。

### 7.2 四类测试在本仓库的落法（不是另起一套）

| 原草案的类别 | 本仓库的对应物 | 今天的状态 |
|---|---|---|
| 单元测试 | `ktest!` 里的纯函数用例（`t_ps2_kbd_decode`、`t_madt_offsets_synthetic`、`t_pci_config`…），共 **151** 条 | 部分覆盖 |
| 硬件集成测试 | 判定表行 + `--features` 挂设备 | 覆盖存储/网络/中断/内存 |
| 端到端测试 | ring3 探针（`KT_PROBE_RING3`、`KT_FS_OPEN_RING3`、`KT_SDKDEMO`）+ 判定行 | 覆盖文件/进程/凭据 |
| 故障注入 | `fault-*` 特性（`kernel/Cargo.toml` 里 **25 个**） | 覆盖锁/堆/中断/TLB/AHCI/GPT/FAT/句柄 |
| **第二台仪器** | pcap / `qemu-img` / `-d int` / `pmemsave` / `validate_esp.py` | 覆盖存储/网络/中断/崩溃；**缺显示与输入**（§3.7） |

**结论**：不需要新框架。**需要补的是显示/输入的第二台仪器**，以及把新驱动接进已有的四类。

### 7.3 新增驱动用例的三条纪律（来自本仓库踩过的坑）

1. **用例必须自足**：`.ktests` 的顺序由链接器决定，不能假设别的用例已经认领过设备
   （`AGENTS.md` 取证纪律）。
2. **每行只吃自己那一跑的日志**：`check-matrix-wiring` 会抓"行名重复 / 共用日志变量 /
   共用退出码变量 / 判定值被别的语句覆盖"四种撞车。
3. **搬迁模块会改串口行序**：判据不能写"逐行 diff 一致"，要先归一行序。

### 7.4 各设备的判定表增量（校正后）

| 里程碑 | 新增行 | 负样本 | 第二台仪器 |
|---|---|---|---|
| AHE-02 匹配器 | 1（正）+ 1（负） | `match_device` 恒返 None | 无（纯函数） |
| AHE-03 DMA 生命周期 | 1（`Busy` 拒绝释放） | 去掉 inflight 检查 | `occupancy()` 回基线 |
| AHE-04 显示 | 1（PPM 四采样点） | 色条顺序改错 | **QMP screendump**（新） |
| AHE-05 NVMe | 1（读对账）+ 1（写对账） | LBA 高位写错（照抄 `fault-ahci-highlba` 形状） | `qemu-img` 容量 + 扇区内容 |
| AHE-06 GPU | 1（资源创建）+ 1（scanout） | 资源 ID 复用不拒 | QMP screendump |
| AHE-07 网卡 | 1（第一帧）+ 1（往返） | 帧图案字节错（照抄 `fault-ahci-lba` 形状） | `filter-dump` pcap |
| AHE-08 输入 | 1（三键）+ 1（滚轮） | bit1 判成 bit0 | **QMP 注入**（新） |
| AHE-09 TCP | 1（握手）+ 1（重传） | 序号回绕错 | pcap 逐包 |

---

## 8. 真机阶段（基于已存在的 `bringup.md`，不是新建）

**原草案说"`docs/hardware/` 目录都还不存在"——错。`docs/hardware/bringup.md` 已存在、已跟踪、
109 行、**31 条**待测项（H-01…H-31）。**

本文不重写它，只补两件事：

### 8.1 分级（原草案 H0–H7 是对的，与 `bringup.md` 对齐）

| 级 | 内容 | 对应 `bringup.md` 段 |
|---|---|---|
| H0 | UEFI 能加载 Aurora OS | §2.1 H-01..H-04（x2APIC/PIC/ICR） |
| H1 | CPU/内存/ACPI/PCI 识别 | §2.1 H-05..H-09、§2.2 H-10..H-14 |
| H2 | 显示正常输出 | **缺**（`bringup.md` 没有显示段）⇒ 本文补 |
| H3 | 键盘鼠标正常输入 | **缺** ⇒ 本文补 |
| H4 | SATA/NVMe 读写 | §2.3 H-15..H-19 |
| H5 | 物理网卡收发 | **缺** ⇒ 本文补 |
| H6 | USB 外设 | 候选（裁决 ④A） |
| H7 | 长跑/重置/异常恢复 | §2.4 H-24..H-28 |

### 8.2 必须补进 `bringup.md` 的四段

本文建议（**不擅自改那个文件**，因为它有"状态列只允许写待测/已测"的纪律）：

1. **§2.6 显示**：EDID 是否存在、Limine 给的 bpp/memory_model/掩码、分辨率、双缓冲撕裂、
   真机无串口时的 framebuffer 日志（`bringup.md` H-28 已经点到这一条）。
2. **§2.7 输入**：PS/2 是否存在（现代 PC 普遍无）、USB 键盘是否为唯一输入、
   i8042 命令字节真机值、IRQ1/IRQ12 是否被固件占用。
3. **§2.8 物理网卡**：PCI ID、MAC 来源（EEPROM vs 固件）、MSI-X 表大小、
   DMA 地址宽度（32/64 位 BAR）、链路状态寄存器语义。
4. **§2.9 GPU/显示设备**：是 iGPU 还是 dGPU、固件是否已初始化、GOP framebuffer 是否可用、
   GPU 是否需要固件（AMD/NVIDIA 需要，Intel i915 也需要 GuC/HuC）。

### 8.3 真机纪律（沿用 `bringup.md` §3，本文不改）

- 状态列只允许「待测」/「已测」；
- 读数列**未跑就写「未验证」**，不许抄 QEMU 的数；
- 真机与 QEMU 不一致：先在 `BACKLOG.md` 记差异、写"不归因"还是"口径变更"，再决定改代码；
- 改判据要起草 ADR，不在 `bringup.md` 里改。

**加一条本文认为必须的**：

> 真机没有第二台仪器的项（例如"输入延迟"），读数栏必须写「无第二仪器」，
> 并且该结论**不得**作为里程碑通过的依据。

---

## 9. 与既有架构的接口影响（原草案完全没有的一节）

### 9.1 新增逻辑模块还是复用

> **下表带「新文件」字样的路径今天都不存在**，是本文的建议落点，不是既有事实。
> 复核时用 `Test-Path` 会得到 `False`——那是预期的。

| 需要的东西 | 落点 | 是否改 `known_scc` |
|---|---|---|
| 设备对象、匹配器、状态 | `driver.rs`（已在环 A） | 否 |
| NVMe | 新文件 `kernel/src/nvme.rs`，登记为 `storage` 模块的 `source_modules` | 否（storage 已在环 A） |
| VirtIO GPU | `virtio.rs` 内扩展（与 blk/net 同文件） | 否 |
| 物理网卡 | 新文件 `kernel/src/net_eth.rs`？ | **是**（新模块）⇒ 需 ADR |
| 输入事件统一 | `kbd.rs`/`mouse.rs` 内扩展 + 一个 `input.rs` | **是**（`input` 是已登记逻辑模块，`source_modules` 可加） |

**判断**：`input` 与 `display` **已经是** `module-interfaces.toml` 里的逻辑模块
（`[modules."input"]`、`[modules."display"]`），所以在这两个域加文件**不需要**新模块登记，
只要改 `source_modules` 数组。而**新开一个 `net_eth` 顶层模块**会改 SCC ⇒ 要 ADR。

**因此本文的建议**：物理网卡**放进 `virtio.rs` 之外的一个新文件但归 `storage`… 不对，
归 `pci` 也不行**。最省的做法是**放进现有的 `virtio.rs` 旁边的 `netdev.rs`，登记为
`storage`/`driver` 之外的**已有**逻辑模块成员。具体归哪个模块，要看 `module-interfaces.toml`
里 `network` 是否存在——**实测：不存在**（只有 boot/arch/memory/sched/sync/display/driver/pci/irq/storage/diagnostics/input/security/time/capability/resource/testing/integration 共 18 个）。

⇒ **结论：网络驱动目前没有归属逻辑模块**。`virtio.rs` 被归在 `storage` 里（因为它先做 blk）。
物理网卡要么并入 `storage`（语义不对），要么**新开 `network` 逻辑模块**（改 SCC，要 ADR）。

**这是本文发现的第二个硬前置**：`network` 逻辑模块的建立要写 ADR（**161** 起），
且要同时决定 `virtio.rs` 是否按 blk/net 拆分（拆 = 改 SCC + 改 `unsafe_scope` 路径口径）。

**补一条实测出来的隐患（与上一条同源）**：`virtio.rs:21` 定义 `MOD_VIRTIO = ModuleId(19)`，
而 `vmo.rs:20` 也定义 `MOD_VMO = ModuleId(19)` ⇒ **两个模块共用同一个台账号**。
今天不出事，是因为 `MOD_VMO` 只用于帧记账、`MOD_VIRTIO` 只用于 MMIO/DMA 句柄记账，
两条账从不放在一起比。但 `resource::Ledger` 是**按 ModuleId 聚合**的
（`AGENTS.md` 已知脆性：「资源台账按模块聚合而非逐句柄」）⇒ 一旦有人拿 19 号去查
"virtio 占了多少帧"，会读到 VMO 的数。**新增驱动前必须先把这两个号分开**，
否则新驱动的资源账从一开始就是错的。这条属于 AHE-01，不是 AHE-07。

### 9.2 门禁影响清单（新驱动 PR 必须逐条过）

| 门禁 | 会不会红 | 怎么过 |
|---|---|---|
| `check-driver-ctx` | 若新驱动进 `DRIVER_MODULES` 而有裸访问 | 全部走 `DriverCtx` |
| `check-module-interfaces` | 若新开顶层 `mod` 或改 SCC | 改 `source_modules` + 必要时写 ADR |
| `check-unsafe` | 若新增 `unsafe` | 登记 `unsafe-whitelist.toml`（指针来源/范围/对齐/生命周期/并发/上下文/谁保证不变量，七项） |
| `check-vector-table` | 若新增中断向量名 | 改 `docs/architecture/vectors.toml`（ADR-046） |
| `check-state-window` | 若新增持久状态字段 | 改状态区记录格式（ADR-031） |
| `check-matrix-wiring` | 若新增判定行 | 行名唯一、各拿自己那一跑的日志与退出码 |
| `check-nofloat` | 若驱动用了浮点/向量 | 内核禁用浮点（实测反汇编 175842 行，命中 0） |
| `check-sbom` | 若新增 crate | 改 `docs/architecture/crates.toml` + `docs/release/sbom.json` |

---

## 10. 风险与未验证项（诚实清单）

| # | 风险 | 性质 | 处置 |
|---|---|---|---|
| R-01 | `MMIO_SLOTS`/`DMA_SLOTS` = 8 撑不住 7 台设备 | **实测**（`driver.rs:30-32`） | AHE-01 必须重算，写 ADR |
| R-02 | 中断向量 16 格 | **实测**（`trap.rs:158-159`） | AHE-01 加余量读数；扩容要 ADR |
| R-03 | `.text` 128 KiB 会再撞墙 | **实测**（ADR-155 第七次扩容） | 结构性解法是 shell 外部命令化，不在本设计范围 |
| R-04 | 显示/输入的第二台仪器不在判定链 | **实测**（`aurora.py` 零 `screendump`） | AHE-04 补齐 |
| R-05 | `network` 逻辑模块不存在 | **实测**（18 个逻辑模块，无 network） | 物理网卡前必须写 ADR |
| R-06 | IOMMU 只有 DMAR 头解析，无表 | **实测**（`acpi.rs:171-172`） | 第二片，需 ADR + `intel-iommu` 设备 |
| R-07 | 真机零条已测 | **实测**（`bringup.md` 31 条全"待测"） | 无目标机型 ⇒ M7 无通过 |
| R-08 | `AGENTS.md` 的读数过期（17 门禁/41 行/ADR 014-045） | **实测**（18/74/136） | 本文记录正确读数；建议单独一轮更新 `AGENTS.md`，**不在本设计里改** |
| R-09 | 审计文档说 `docs/hardware/` 不存在 | **实测**（已存在且已跟踪） | 本文以 `bringup.md` 为准 |
| R-10 | TCP 需要新 syscall 号段（48 起） | **推断**（1..47 已连续占满） | 需裁决，本文不替使用者决定 |
| R-11 | virtio-gpu 的 2D 资源格式与 `frame.rs` 的"按掩码打包"如何对齐 | **未验证** | AHE-06 的第一件事是读 `virtio_gpu` 的资源格式能力位，不猜 |
| R-12 | 物理网卡的 DMA 地址宽度（32 位 BAR 限制） | **未验证** | 真机必测（`bringup.md` 无此条 ⇒ 本文补 §8.2） |
| R-13 | NVMe 的 MSI-X 表大小与队列深度 | **未验证** | QEMU `nvme` 模型先量，真机重测 |
| R-14 | `virtio.rs` 与 `vmo.rs` 共用 `ModuleId(19)` | **实测**（`virtio.rs:21`、`vmo.rs:20`） | AHE-01 分开，写 ADR |
| R-15 | 原草案的「11 处不符」中有 2 处（QEMU 内存 512M、`-display none`）**可能随使用者本机配方不同** | **推断** | 本文以 `tools/aurora.py` 为唯一来源；若使用者另有配方，以配方为准 |

---

## 11. 立即可做的第一步（不超过一个会话的量）

**AHE-01：容量与登记前置。零新驱动、零新设备、不改任何 ADR 语义。**

具体八件事：

1. `driver.rs`：把 `MMIO_SLOTS`/`DMA_SLOTS` 从 8 重算（按"最多同时在线几台设备"，
   **含 `probe()` 的临时格**——见 §3.11），并把 `occupancy()` 的读数扩成"已用/总量"两格。
2. `driver.rs`：加 `DeviceInfo` / `DeviceState` / `set_state` / `state_of` / `occupancy_by_state`。
3. `driver.rs`：加 `match_device`（`IdMatch` + `ClassMatch` 两张静态表 + 纯函数）。
4. `irq.rs`：加 `occupancy() -> (usize, usize)`（已用/总量）。**这一格今天是零**，
   而它是"AHE 能接几台设备"的另一个硬上限（§3.8）。
5. `virtio.rs` / `vmo.rs`：把撞车的 `ModuleId(19)` 分开（§9.1 补记）。**这条要写 ADR**，
   因为它改了资源台账的归属语义。
6. `ktests`：`t_match_device` + `t_state_machine`（非法迁移必须 `Denied`）+ 两条变异证红。
7. `devctl status`：末行从 `count=<n>` 扩成
   `count=<n> active=<a> failed=<f> irq=<i>/<I> mmio=<m>/<M> dma=<d>/<D>`
   ——**这是让余量可见的那一行**，比任何文档都管用。
8. `tools/aurora.py`：把新驱动文件加进 `DRIVER_MODULES`（此时还没有新驱动，但清单要跟着长）；
   判定表加 2 行（匹配器正/负）。跑 `check`（应 18/18）、`ktests`、`test`，把前后读数贴进 `BACKLOG.md`。

**这一片完成后的判定**：`devctl status` 那一行能同时报出"几台设备在跑、几台失败、
中断/MMIO/DMA 各用了多少格"。**在这之前，任何"AHE 能接几台设备"的说法都是猜的。**

---

## 12. 与原草案的差异总表（一页看完）

| 原草案 | 本文 | 原因 |
|---|---|---|
| `trait Driver { probe/init/shutdown }` | 表驱动匹配器 + 既有 `DriverCtx` | 与 ADR-030 冲突；违反硬约束 2；无 `&mut self` 落脚点 |
| 新建 `driver/` 子目录 9 个文件 | 在 `driver.rs` 内追加 | 改 `main.rs` 顶层 `mod` ⇒ 门禁红；空模块违反硬约束 2 |
| `PixelFormat` 四值枚举 | 沿用 Limine 掩码打包 | 枚举把"设备说了算"改回"我们猜"，方向相反 |
| 显示要"热插拔、模式切换" | 移出第一阶段 | UEFI GOP 无热插拔语义；写进里程碑则永不通过 |
| USB/xHCI 列为 AHE-06 | 候选里程碑，需重新裁决 | 裁决 ④A 已跳过 |
| 硬件矩阵列为 AHE-08 | 候选，需重新裁决 | 裁决 ⑥A 已跳过 |
| DNS 是欠账 | 已交付（ADR-158，47 号） | 过期 |
| 块设备"无请求队列" | 已交付（ADR-110 `block_io`） | 过期 |
| 内存 2 GB | 512 MB | 实测 |
| 「QEMU 标准 VGA 分阶段测试」 | 今天 `-display none` 无 `-vga` | 实测 |
| 「`docs/hardware/` 不存在」 | 已存在 `bringup.md`（31 条待测） | 实测 |
| 「判定表 41 行」 | 74 行 | 实测 |
| 「17 道门禁」 | 18 道 | 实测 |
| 「ADR 014–045，新决定从 046」 | 136 份，007–160，下一个 **161** | 实测 |
| 「screendump/pcap 已是现有工具」 | screendump 在未跟踪的 `.scratch/`；pcap 在链里 | 实测（半对） |
| 未提容量约束 | §3.11 完整清单（堆 2048 / 任务 9 / 向量 16 / 句柄 8+8） | 漏项 |
| 未提三处登记 | §3.10 | 漏项 |
| 未提 `network` 逻辑模块缺失 | §9.1 | 漏项 |
| 未提 GBK 控制台 | §7.1 | 漏项 |

---

## 13. 参考（全部为仓库内可复核来源）

- `AGENTS.md`（硬约束 1–7、取证纪律；**注意其中读数已过期**，见 R-08）
- `BACKLOG.md`（13115 行，逐轮实测；最新 §436 = ADR-160）
- `docs/adr/ADR-030-驱动的唯一接口是能力句柄表.md`（驱动的唯一接口是能力句柄表）← 本文 §3.1 的依据
- `docs/adr/ADR-018-内核堆OOM出口.md`、`ADR-026`（堆上限 2048）← §3.11
- `docs/adr/ADR-110-块设备请求层与virtio-blk第一刀.md`（块设备请求层）← §3.5
- `docs/adr/ADR-112-virtio设备表化与第二台virtio-blk.md`（virtio 设备表化、第二台 blk）
- `docs/adr/ADR-149-B1验收句lsdev与devctl.md`（`lsdev`/`devctl`）← §11 第 5 件
- `docs/adr/ADR-155-A3第一片管道与grep.md`（`.text` 48→128 KiB）← R-03
- `docs/adr/ADR-158-§10.4第三条nslookup与DNS解析出口.md`（DNS 解析出口）← §3.5
- `docs/adr/ADR-083-显示子系统第一刀按物理区间自映射并以宿主机PPM为画面判据.md`/`ADR-086`（显示第一刀与字形资产）← §3.3
- `docs/adr/ADR-091-PS2鼠标与屏幕指针及点击命中.md`（PS/2 鼠标与屏幕指针）← §3.2
- `docs/adr/ADR-099-浮窗拖动-按住态轮询与旧矩形并集还原.md`（浮窗拖动）← 输入/显示的既有交互基线
- `docs/architecture/module-interfaces.toml`、`module-dependencies.md`（SCC 环 A、棘轮）← §9
- `docs/architecture/lock-order.md`（锁等级；新增锁必须同步改）← §9.2
- `docs/security/unsafe-whitelist.toml`（七项登记要求）← §9.2
- `docs/hardware/bringup.md`（M7 待测清单，31 条，零条已测）← §8
- `docs/Aurora-OS-未完成步骤审计-2026-11-19.md`（裁决 ④A/⑤A/⑥A 的出处）← §3.4
- `docs/Aurora-OS-完整操作系统架构与Shell命令体系建设总设计-V1.0.md` §9 D1/D5（后期能力定位）
- `tools/aurora.py`（八子命令、18 门禁、74 行判定表、QEMU 接线）
- `kernel/src/driver/mod.rs`、`pci.rs`、`irq.rs`、`ahci.rs`、`virtio.rs`、`frame.rs`、`fbcon.rs`、`kbd.rs`、`mouse.rs`
- `kernel/src/filesystem/block_io.rs`（ADR-110 的落地物）
- QEMU 11.1.0 `-device help` 实测输出（virtio-gpu/nvme/xhci/e1000e/igb/rtl8139/intel-iommu 均存在）

---

## 附：本文的取证方式（可复现）

```powershell
$env:PYTHONIOENCODING='utf-8'; $env:PYTHONUTF8='1'

# 门禁 18/18
python tools/aurora.py check

# 判定表行数 = 74
python -c "import io,re;s=io.open('tools/aurora.py',encoding='utf-8').read();i=s.index('    rows = [\n        (\"正向\"');j=s.index('\n    ]',i);print(len(re.findall(r'^\s{8}\(\"([^\"]+)\",',s[i:j],re.M)))"

# ktest 注册 = 151
Get-ChildItem kernel\src -Recurse -Filter *.rs | Select-String -Pattern 'ktest!\(KT_' | Measure-Object

# ADR = 136
(Get-ChildItem docs\adr -Filter 'ADR-*.md' | Where-Object { $_.Name -ne 'ADR-template.md' }).Count

# 裸设备搜索（virtio-gpu/nvme/xhci/usb_hid）应零命中
Get-ChildItem kernel\src -Recurse -Filter *.rs | Select-String -Pattern 'virtio_gpu|nvme|xhci|usb_hid' -CaseSensitive:$false

# screendump 在 tools/aurora.py 应零命中；在 .scratch 有，但 .scratch 未跟踪
Select-String -Path tools\aurora.py -Pattern 'screendump'
git ls-files .scratch | Measure-Object -Line

# QEMU 设备模型存在性
.\.tools\qemu\qemu-system-x86_64.exe -device help | Select-String 'virtio-gpu|nvme|qemu-xhci|e1000e|igb|rtl8139|intel-iommu'
```

**本轮实测读数**：`check` **18/18 全绿**；`rows` = **74**；`ktest!` = **151**；ADR = **136**；
bench 基线 = **91**；`kernel/src` `.rs` = **84**（全仓排除 `target`/`.tools` = 165）；
判定表使用的特性 = **47** 个。
