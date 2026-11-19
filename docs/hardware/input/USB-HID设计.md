# USB HID 设计（**候选里程碑，需重新裁决**）

状态：**未实施 · 被裁决 ④A 跳过 · 本文只作设计储备，不含实施计划**

- 裁决出处：`docs/Aurora-OS-未完成步骤审计-2026-11-19.md` §一 D1 行、
  §三末段、§四；裁决代号 **④A**
- 上位：[硬件驱动体系总设计](../Aurora-OS-硬件驱动体系总设计-V1.0.md) §3.4

---

## 0. 先说清本文的地位

原设计草案把 "AHE-06 USB Host（xHCI + 枚举 + HID）" 排进必做序列。
**这与已生效的裁决 ④A 冲突**——那条裁决明确跳过 D1（USB Host/HID），
理由是没有 xHCI、没有 USB 栈，且它不是第一阶段的前置。

所以本文**不是**一份待执行的设计。它的用途只有一个：
**当决定重开时，不用从零想**。

**重开条件**（写清条件，避免"因为想做所以做"）：

1. 物理机验收明确要求"USB 键盘可用"是硬需求——**理由是成立的**：
   现代 PC 普遍没有 PS/2 口，只有 USB。这一条足以推翻"PS/2 够用"的前提。
2. 且 `docs/hardware/bringup.md` §1 的机型表已填（知道目标机有没有 EHCI/xHCI）。
3. 且重开走"先裁决、后实现、再登记"：**新 ADR（162 起）** + BACKLOG 记
   "裁决 ④A 被取代，理由与替代裁决"。

**在这三条满足之前，本文件里任何数字都不许引用来做里程碑承诺。**

---

## 1. 为什么 USB 比 PS/2 难一个量级（写清代价，不是劝退）

| 项 | PS/2（已实施） | USB |
|---|---|---|
| 控制器 | i8042，两个端口，几个命令字节 | xHCI：寄存器组 + 命令环 + 事件环 + 设备上下文基址数组 + 4 种传输环 |
| 枚举 | 无（设备插上就报） | **必须枚举**：复位 → 地址分配 → 描述符链（设备/配置/接口/端点/HID/报告描述符） |
| 数据 | 固定 3 字节包（鼠标）/ 扫描码（键盘） | **报告描述符驱动的变长报表**（要解析 HID 描述符才知道怎么解） |
| 错误恢复 | 端口超时 | 端点 stall / 传输错误 / 设备掉线重枚举（"USB 设备消失"是真事件） |
| 中断 | IRQ1 / IRQ12 | 事件环轮询或 MSI-X；**没有"按设备的中断"** |
| 时序 | 无握手 | 复位后必须等 ≥10 ms；SET_ADDRESS 后必须等 ≥2 ms |

**结论**：这不是"再接一种键盘"，是一个**新的子系统**（控制器驱动 + 协议栈 +
描述符解析 + 报告翻译）。原草案把它排在显示之后、物理驱动之前，低估了它。

---

## 2. 若重开，最小可行的切法

### 2.1 只做 xHCI + Boot Protocol（不做报告描述符）

**关键取舍**：HID 有一个叫 **Boot Protocol** 的子集——键盘固定 8 字节报表、
鼠标固定 3 字节报表，布局写死在规范里。

用 Boot Protocol 可以**完全跳过报告描述符解析**。代价是只支持"启动兼容"设备
（几乎所有 BIOS 兼容键鼠都支持）。这是第一阶段唯一合理的范围。

### 2.2 切法（四片，每片可独立验收）

```text
U-1  xHCI 控制器认领与寄存器读数
     - PCI 找 class 0x0C / subclass 0x03 / progif 0x30
     - map_mmio BAR0、读 CAPLENGTH/HCSPARAMS1/HCCPARAMS1/USBSTS
     - 判据：读数与 QEMU `-device qemu-xhci` 的期望一致（宿主机第二台仪器可用 `info qtree`）

U-2  复位 + 命令环 + 事件环（还不碰设备）
     - USBCMD.RS、DCBAAP、CRCR、ERSTSZ/ERDP
     - 判据：发一条 No-Op 命令，收到 Command Completion Event

U-3  Port Reset + Enable Slot + Address Device（还是不碰 HID）
     - 判据：Slot State 变 Addressed/Configured；设备描述符读回 vendor/product

U-4  HID Boot Protocol 键盘/鼠标
     - 配一个 Interrupt IN 端点、定期收 8 字节 / 3 字节报表
     - 翻译成已有 InputEvent（见 键盘驱动设计 §2.3 / 鼠标驱动设计 §3）
     - 判据：QMP `-device usb-kbd` 注入的按键到达 InputEvent
```

**每片的宿主机第二台仪器**：

| 片 | 仪器 |
|---|---|
| U-1 | `-device qemu-xhci` 的 `info qtree` 读容量；内核读数对账 |
| U-2 | 无（事件环自证 + 命令/事件计数） |
| U-3 | QEMU `info usb` 看设备是否被枚举 |
| U-4 | QMP `input-send-event` 注入 → 断言事件到达（**这也是鼠标/键盘缺的那台仪器**） |

U-4 那台仪器与 PS/2 的缺口**是同一台**（见 [鼠标驱动设计](鼠标驱动设计.md) §4.3）。
所以**即使不做 USB，QMP 注入也该先接进链**——它同时解锁 PS/2 的端到端判据。

---

## 3. 与既有架构的接口影响（重开时必须先算这笔账）

| 项 | 影响 | 是否需 ADR |
|---|---|---|
| 中断向量 | 事件环常见做法是轮询；若用 MSI-X 要 1 颗（今天 16 格，剩 ~9 颗） | 否 |
| `MMIO_SLOTS`/`DMA_SLOTS` | xHCI 至少 1 MMIO + 2 DMA（命令环/事件环/DCBAA 各一页起） | **是**（要扩容，见总设计 §3.11） |
| `MAX_TASKS` | 若用独立轮询任务，**每 CPU 只有 9 格且零余量** | **是** |
| 新逻辑模块 | `network` 还没有；USB 也不属于 `input`（它先归 `driver`？） | **是** |
| `input` 逻辑模块 | HID 翻译进 `input/`，要改 `source_modules` | 否（登记表可改） |
| QEMU 接线 | `-device qemu-xhci -device usb-kbd -device usb-mouse`（**已核实三者存在**） | 否 |

**"新逻辑模块"这一行最容易被忽略**：今天 `module-interfaces.toml` 里
18 个逻辑模块**没有 network、没有 usb**。新开一个会改 `known_scc` ⇒ 门禁红 ⇒
必须走 ADR。这与物理网卡是**同一个前置**。

---

## 4. 不做什么（写清以免被当成遗漏）

1. **不做 xHCI 的 Isochronous 传输**（音频/摄像头），只做 Control + Interrupt。
2. **不做 USB Hub**（只支持 root port 直连）。Hub 要枚举拓扑，是另一倍工作量。
3. **不做 USB Mass Storage**（`Block` 的第五个实现）。它有独立的 bug 面。
4. **不做 HID 报告描述符解析**（只 Boot Protocol，§2.1）。
5. **不做热插拔的优雅处理**：设备掉线时只报 `Failed`，不自动重枚举
   （重枚举要先把旧 slot 彻底拆掉，那是 U-2/U-3 的额外工作）。

---

## 5. 现在的正确动作

**不是**开始写 xHCI。是：

1. **把 QMP 注入接进 `tools/aurora.py`** —— 它不依赖 USB，却能立刻补上
   PS/2 键鼠缺的第二台仪器。**这是唯一"现在就该做"的一件**。
2. 把本文登记为候选里程碑（总设计 §4.2 的"候选"行已这么做）。
3. 等重开条件满足，再按 §2.2 的四片立项。

---

## 6. 未验证（诚实清单）

- QEMU `qemu-xhci` 的 CAPLENGTH/HCSPARAMS 具体数值：**未读**（没跑）。
- Boot Protocol 键盘报表的确切字节序：**未核**（本文按规范描述写，未对代码验证）。
- xHCI 在 QEMU 上的 MSI-X 支持与向量数：**未查**。
- `-device usb-kbd` 与 QMP `input-send-event` 的配合行为：**未试**。

上述任一条在重开时都要先量再用，不许按本文当事实。
