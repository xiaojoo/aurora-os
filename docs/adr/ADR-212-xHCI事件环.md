# ADR-212：xHCI 事件环配置（Interrupter 0）

状态：**已采纳**（2026-11-23：`t_xhci_event_ring` 八格全 true，`PASS(33)`）

关联：ADR-211（真实初始化）、ADR-208（TRB）

> 切片 H 第五层。ADR-211 让控制器进了运行态，但**没有任何事件通路**。

## 一个必须说清的坑：Interrupter 不在 OP 段

第一版把 Interrupter 寄存器当成 `OP + 0x20 + n*0x20`，于是 `ERSTBA(0)` 落在 `OP+0x30`
—— **与 `DCBAAP` 同址**。那不是巧合，是理解错了。

权威依据（FreeBSD `sys/dev/usb/controller/xhci.c`）：

```c
XWRITE4(sc, runt, XHCI_ERSTBA_LO(0), (uint32_t)addr);   // 第二个参数是 runt
```

**Interrupter 在 `RTSoFF` 那段里**（RTSoFF 从 CAP+0x18 读），与 OP 是两个基址。

实测验证：`rt=0x1040`（OP 0x40 + RTSOFF 0x1000），与 `op=0x40` 明显不同。

## 运行时寄存器偏移（相对 RT 基址）

| 寄存器 | 偏移 | 说明 |
|---|---|---|
| IMAN | 0x00 | Interrupt Management，bit0=IP、bit1=IE |
| IMOD | 0x04 | Interrupt Moderation |
| ERSTSZ | 0x08 | Event Ring Segment Table Size |
| ERSTBA | 0x10 | ERST Base Address（64 位）|
| ERDP | 0x18 | Event Ring Dequeue Pointer（64 位，bit3=EHB）|

Interrupter 之间跨度 0x20。

## 交付

```rust
pub fn build_erst_entry(&mut [u8;16], seg_base: u64, seg_size: u32) -> bool
pub fn parse_erst_entry(&[u8;16]) -> (u64, u32)
pub fn setup_event_ring(dev) -> Result<EventRingReading, EventRingError>
```

配置流程：读 RTSOFF → 分配事件环段（一页=256 TRB）+ ERST 表 → 都清零 →
写 ERST 表项 → 写 ERSTSZ=1 / ERSTBA / ERDP（含 EHB）→ 写 IMAN.IE。

## 决策 1：`seg_size` 是 **TRB 个数**，不是字节数

这是最容易写错的一格。写 4096（字节）会让硬件读越界 256 倍。

判据第 2 格专门证它：`seg=256` 而不是 4096。

## 决策 2：`ERDP` 必须带 `EHB`

`EHB`（Event Handler Busy，bit 3）是「事件处理者已就绪」的标志。
不置它，控制器不会开始往环里写事件 —— 而症状是「事件永远不来」，极难归因。

## 决策 3：不开 MSI/MSI-X，用轮询 `IP` 位

`IMAN.IE=1` 只让控制器在事件到来时置 `IP` 位，真正的中断投递要 PCI 中断配置。

今天用**轮询 `IP`** 代替。这与 AHCI 的 `t_irq_ahci` 并存：
轮询是判据能证的最小形态，中断是产品路径，两者不混。

## 判据八格（`t_xhci_event_ring`）

```
xhci-er: 往返=true 未对齐拒=true 零拒=true 配置=true erstsz=1 iman=0x2 ie=true
         对齐=true 分开=true seg=256 ｜ rt=0x1040 ring=0x3d000 erst=0x3e000 ⇒ true
```

## 负样本（变异证红）

把 `ERSTSZ` 写成 0：

```
xhci-er: 配置不对 erstsz=0 iman=0x2 align=true distinct=true seg=256
```

## 读数

| 项 | 结果 |
|---|---|
| `check` | **21/21** |
| `handles,xhci` 档 | **`PASS(33)`**，`t_xhci_event_ring` 八格全绿 |

## 未决

1. **命令环消费者**（投递 TRB + 等 Command Completion Event）—— 本层只配了事件环，没发命令
2. **MSI/MSI-X** 中断投递
3. **事件环的回收**（读 ERDP、清 EHB、前移 dequeue）
4. **端口枚举**（Enable Slot → Address Device → Configure Endpoint）
5. **ERST 只用 1 段** —— 多段（环满换段）没做