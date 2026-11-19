# ADR-162：推翻裁决 ④A，把 USB Host/HID 重新纳入范围

状态：已采纳（2026-11-20，使用者裁决）
关联：取代 `docs/Aurora-OS-未完成步骤审计-2026-11-19.md` 的**裁决 ④A**（D1 USB Host/HID 跳过）；
依赖 ADR-161（按域分层）；影响 `docs/hardware/input/USB-HID设计.md`

> 写作纪律：本文记的是**裁决本身**（谁决定、推翻什么、替代方案是什么），
> 不是实施计划。实施细节在 `docs/hardware/input/USB-HID设计.md`。

## 背景

`docs/Aurora-OS-未完成步骤审计-2026-11-19.md` 第 28 行与第 153 行记着：

> **D1** USB Host/HID | **未开始** | 无 xHCI、无 USB 栈（按裁决④A 跳过）
>
> 按使用者裁决 **④A / ⑤A / ⑥A 跳过**（无 xHCI、无 HDA、无安装器）。
> 这三项**不是遗漏，是显式决定**。

那条裁决在当时是合理的：PS/2 键鼠已经能工作（`input/kbd.rs` 392 行、
`input/mouse.rs` 308 行，都在 `ps2-kbd`/`ps2-mouse` 特性档里跑通），
而 USB 要 xHCI + 协议栈 + 描述符解析，工作量与"再做一种键盘"完全不是一个量级。

**现在推翻它的理由**（使用者 2026-11-20 裁决）：

**现代 PC 普遍没有 PS/2 口，只有 USB。** 这意味着在真实硬件上，
"能打字、能用鼠标"这件事**只有 USB 一条路**——PS/2 支持在目标机型上很可能是零。
`docs/hardware/testing/真机测试规范.md` 的 H-37/H-40 两条待测项正是问这个：
目标机有没有 PS/2 口、USB 是不是唯一输入。

所以 ④A 不是"省掉一个可选功能"，而是**省掉了真机上唯一的输入路径**。
这与"按完整的操作系统设计来"的要求直接冲突。

## 决策

**推翻裁决 ④A。USB Host/HID 重新纳入范围**，按下列约束实施：

1. **只做 xHCI，不做 EHCI/UHCI/OHCI**。xHCI 是 2010 年后的通用标准；
   再往下兼容会让控制器驱动变成四份。
2. **只做 Boot Protocol，不做 HID 报告描述符解析**。
   键盘固定 8 字节报表、鼠标固定 3 字节报表，布局写在规范里。
   代价：只支持"启动兼容"设备（几乎所有 BIOS 兼容键鼠都支持）。
   **这个取舍是有意的**——报告描述符解析是另一个子系统。
3. **不做 USB Hub**，只支持 root port 直连。
4. **不做 USB Mass Storage**，不做 Isochronous 传输（音频/摄像头）。
5. **分四片，每片独立验收**（详见 `input/USB-HID设计.md` §2.2）：
   - U-1 控制器认领与寄存器读数
   - U-2 复位 + 命令环 + 事件环（不碰设备）
   - U-3 Port Reset + Enable Slot + Address Device（不碰 HID）
   - U-4 HID Boot Protocol 键盘/鼠标
6. **QMP 注入先于 U-4**：`input-send-event` 进 `tools/aurora.py` 是 U-4 的判据前置，
   而且它**同时**解锁 PS/2 键鼠缺的第二台仪器（见 ADR-165）。

## 备选方案

| 方案 | 不选它的理由 |
|---|---|
| 保留 ④A，只做 PS/2 | 现代 PC 多数没有 PS/2 口 ⇒ 真机上"能输入"这件事无法达成 |
| 用 UEFI 的 Simple Text Input 代替 USB 驱动 | UEFI Runtime Services 需要 `SetVirtualAddressMap` 之后的调用约定，本内核**没有** Runtime Services 调用路径；而且它只在固件阶段可用，进入内核后要靠 `EXIT_BOOT_SERVICES` 保留的接口，那是另一套契约 |
| 只做 xHCI + HID 报告描述符（不用 Boot Protocol） | 报告描述符解析是独立子系统（HID 规范 200+ 页）；Boot Protocol 能用 1/10 的代码覆盖 95% 的键鼠 |
| 一步做完全部 USB（含 Hub / Mass Storage） | Hub 要枚举拓扑、Mass Storage 要 SCSI 子集，两者都是独立工作量；先让"能输入"成立 |

## 影响

**正面**：

- 真机上"能打字、能用鼠标"从"很可能不能"变成"可以"；
- `input/` 域有了第二套后端，`InputEvent` 的形状（键盘文档 §2.3、鼠标文档 §3）
  会同时被两条路径验证——**这是"抽象是否成立"的检验**；
- QMP 注入进链之后，PS/2 的端到端判据也跟着补上（今天两者都没有）。

**负面 / 代价（必须记账）**：

- **这是数周量级的活，不是顺手能做**。xHCI 寄存器组 + 命令/事件环 +
  四种传输环 + 设备上下文基址数组，比 AHCI 复杂一个量级。
- `MMIO_SLOTS`/`DMA_SLOTS` 会再吃格子（xHCI 至少 1 MMIO + 2 DMA）——
  已由 ADR-163 扩到 16/16，但 8 格时代"加一台就满"的教训要记住。
- 中断：事件环可以轮询（0 颗向量），也可以 MSI-X（1 颗）。今天 16 格剩约 9 颗。
- **`MAX_TASKS = 9` 每 CPU 零余量**：若用独立轮询任务会撞墙，已由 ADR-165 扩。
- 新增 `unsafe` 会进 `unsafe-whitelist.toml`，需要七项登记。
- 需要新逻辑模块吗？**不需要**：USB 属 `driver` 域的成员（`driver/xhci.rs`），
  与 `ahci.rs`/`virtio.rs` 同级。HID 翻译进 `input/`。

## 验收与负样本

**每一片都要有自己的判据与负样本**（`AGENTS.md`：每条新判据都配一个能让它变红的变异）：

| 片 | 判据 | 负样本 | 第二台仪器 |
|---|---|---|---|
| U-1 | CAPLENGTH/HCSPARAMS1/HCCPARAMS1/USBSTS 读数 | 把 CAPLENGTH 读成 0 ⇒ 红 | QEMU `info qtree` |
| U-2 | 发一条 No-Op 命令、收到 Command Completion Event | 不写 CRCR ⇒ 事件永不到 | 无（计数自证） |
| U-3 | Slot State 变 Addressed/Configured；读回 vendor/product | 不发 SET_ADDRESS ⇒ 状态不动 | QEMU `info usb` |
| U-4 | QMP 注入的按键到达 `InputEvent` | 报表偏移写错 ⇒ 按键错位 ⇒ 红 | **QMP `input-send-event`** |

**U-4 的判据依赖 QMP 注入**，而那是 ADR-165 的内容。若 QMP 注入没做，
U-4 做完也判不出来——**顺序不能换**。

## 未决

1. **QEMU 上 xHCI 的具体读数未量**：`-device qemu-xhci` 的 CAPLENGTH、
   HCSPARAMS1 数值、MSI-X 支持与向量数，全部**未读**。实施前必须先量。
2. **Boot Protocol 报表的确切字节序未核**：本文按规范描述写，未对代码验证。
3. **真机 xHCI 与 QEMU 的差异未测**：真机的 port status 变化时序、USB 2.0/3.0
   端口的枚举差异，都要进 `docs/hardware/bringup.md` 的待测清单（新增 H-52 起）。
4. **本 ADR 只推翻"跳过"，不承诺完成时间**。USB 栈是数周量级的独立里程碑，
   不应挤进当前正在收尾的阶段。
