# ADR-213：xHCI 命令环消费者（**阻塞：CRR 位不置**）

状态：**部分采纳**（2026-11-23：代码与判据就位，`enable_slot` 阻塞在 CRR 不置位）

关联：ADR-211（真实初始化）、ADR-212（事件环）

> 切片 H 第六层。**`enable_slot` 超时，命令不被控制器消费。**
> 代码已就位但**门控在默认关闭的 `xhci-slot` 特性下**。

## 已落地（可复用）

```rust
pub struct State { ctx, mmio, cmd, event, dcbaa, cmd_bus, event_bus, op, rt,
                   doorbell_offset, cmd_enqueue, cmd_cycle, event_dequeue, event_cycle, seg_trbs }
pub fn bring_up(dev) -> Result<RunReading, RunError>
pub fn build_cmd_trb(&mut [u8;16], ty, slot_id, parameter, cycle) -> bool
pub fn enable_slot() -> Result<SlotReading, CmdError>
```

`bring_up` 是 ADR-211 `run_device` 的替代：同样序列，但**保存句柄**而不是 `forget`，
这样后续才能写命令环（没有 `DmaHandle` 就只能按总线地址硬算，违反 `DriverCtx` 纪律）。

## 实测撞出的两个错（都已修）

### 错 1：锁序违规 ⇒ 整机 39

第一版 `STATE_LOCK` 用 `RANK_BLOCK(37)`，而 `bring_up` 在持锁时调 `alloc_dma`（取 `RANK_VMM(20)`）：

```
[fatal] L4 sync: 锁序违规，外层 rank=37 本次 rank=20
```

改成 `RANK_GROW(4)`（比 TIMER/RUNQ/HEAP/VMM 都浅）。

**教训**：锁的 rank 必须按「它内部会取什么锁」来定，不是按「它属于哪个子系统」。

### 错 2：CRCR 写在 RS=1 之前

第一版顺序是 `HCRST → DCBAAP → CRCR → CONFIG → RS=1`。

实测 `crcr_lo=0x91001`（RCS=1 但 **CRR=0**）。**CRR = Command Ring Running**，
它不置位意味着控制器认为命令环没在运行 ⇒ 敲 Doorbell 无效。

改成 `HCRST → DCBAAP → CONFIG → RS=1（等 HCH=0）→ CRCR` 之后 —— **`crcr_lo` 仍是 `0x91001`**。

## 阻塞点（如实记录）

`enable_slot` 超时的完整现场：

```
xhci: enable_slot 投递 trb_ctrl=0x2401 读回=0x2401 crcr_lo=0x91001 db=0x0
      cmd_bus=0x91000 ev_bus=0x92000
xhci: enable_slot 超时 crcr=0x000091001 usbsts=0x0 iman=0x2 erstsz=1
      ev0_ctrl=0x0 cmd_idx=0 ev_deq=0 cycle=true/true
```

逐项排除：

| 项 | 读数 | 判断 |
|---|---|---|
| 命令 TRB 写进去了吗 | `trb_ctrl=0x2401`，读回一致 | **是**（type=9 EnableSlot、cycle=1）|
| CRCR 指向对吗 | `crcr_lo=0x91001` | 地址 0x91000、RCS=1 —— 对 |
| **CRR 置位了吗** | `crcr_lo` bit3 = 0 | **否 ← 根因** |
| 控制器在跑吗 | `usbsts=0x0`（HCH=0）| **是** |
| 事件中断使能了吗 | `iman=0x2`（IE=1）| **是** |
| 事件环配好了吗 | `erstsz=1` | **是** |
| 事件来了吗 | `ev0_ctrl=0x0` | **没有** |

**CRR 不置位是核心。** 按 spec §5.4.5，CRR 是**只读**位，由控制器在命令环运行时置位；
软件只能通过 `CRCR.RCS` 与 `USBCMD.RS` 间接影响它。

已排除的可能：Doorbell 地址（`0x2000`，与 CAP 读回一致）、Doorbell 值（非 0）、
TRB 类型/cycle、CRCR 地址对齐（0x91000 是 64 字节对齐）、事件环 ERSTSZ/ERDP/IMAN。

**未排除的可能**（按怀疑度排序）：

1. **DCBAA 内容无效**：我清零了 DCBAA 页，但 xHCI 可能要求 `DCBAA[0]` 指向一个有效的
   Scratchpad Array（若 `max_scratchpad > 0`）。本机 `scratch=0`，所以这一条存疑但不排除。
2. **CONFIG.MaxSlotsEn 与 HCSPARAMS1.MaxSlots 的关系**：我写 `max_slots()`（64），
   但 spec 说 `MaxSlotsEn` 不能超过 `MaxSlots` —— 相等应该合法。
3. **QEMU 的 xHCI 需要 `USBCMD.INTE` 之外的额外使能**（如 `USBCMD.EWE`）。
4. **命令环第 0 格可能需要 Link TRB 预置**：我只写了 Enable Slot TRB 在第 0 格，
   而 spec 要求环尾有 Link TRB —— 但第 0 格不需要。

## 为什么门控而不是继续死磕

按项目纪律「**先记录问题，不要死磕**」：

- 代码与判据已就位（`build_cmd_trb` / `bring_up` / `enable_slot` 都编得过）；
- `xhci-slot` 特性**默认关**，开了只会红；
- 默认档与 `xhci` 档都 `PASS(33)`。

## 读数

| 档 | 结果 |
|---|---|
| `handles` | **`PASS(33)`** |
| `handles,xhci` | **`PASS(33)`** |
| `handles,xhci,xhci-slot` | **FAIL**（`enable_slot 失败 Timeout`）|

## 未决

1. **CRR 不置位**（本 ADR 的核心阻塞）—— 需要逐条排除上面四项
2. **端口枚举**（Enable Slot 之后的 Address Device / Configure Endpoint）
3. **MSI/MSI-X**
4. **Link TRB 真的写进环尾** —— 今天只是游标跳过（ADR-208 未决 3）
5. **Scratchpad Buffer 分配**
## 第二轮排查（2026-11-23）

### 已排除：Bus Master

`driver/mod.rs:198` 的 `map_mmio` 里已置 `enable_command(0b110)`
（bit1=Memory Space、bit2=Bus Master）。**不是这个原因。**

### 新发现：CRCR 只能在 RS=0 时写

把 CRCR 移到 RS=1 之后，读回 **`crcr=0x0`**（写入被硬件拒绝）。
移回 RS=1 之前，读回 `crcr=0x84001`（地址 + RCS=1 都在）。

**结论：CRCR 只能在控制器停止时写。** 这一条已确认并写进代码注释。

### 仍未解决：CRR 不置位

```
xhci: 终值 usbcmd=0x5 usbsts=0x0 config=0x40 dcbaap=0x86000
      crcr=0x84001 erdp=0x85000 erstba=0x94000 cmd0=0x0
```

寄存器终值全部正确：

| 寄存器 | 值 | 判断 |
|---|---|---|
| USBCMD | `0x5` | RS=1 + INTE=1 ✓ |
| USBSTS | `0x0` | HCH=0，控制器在跑 ✓ |
| CONFIG | `0x40` | MaxSlotsEn=64 ✓ |
| DCBAAP | `0x86000` | 页对齐 ✓ |
| CRCR | `0x84001` | 地址 + RCS=1 ✓ |
| ERDP | `0x85000` | 段地址 ✓ |
| ERSTBA | `0x94000` | 表地址 ✓ |
| **CRR (bit3)** | **0** | **不置位** |

### 一个待验证的假设

**CRR 可能只在「命令环上有待处理命令」时置位** —— 若是这样，CRR=0 在空环时是正常的，
而真正的问题是 Doorbell 没让控制器看到命令。

这需要读 QEMU 的 `hcd-xhci.c` 源码确认（本轮网络取不到）。

### 本轮停止的理由

按项目纪律「**先记录问题，不要死磕**」：已经排除 Bus Master、CRCR 时序两个方向，
剩下的必须靠读 QEMU 源码或逻辑分析仪，那不是本轮能完成的。
