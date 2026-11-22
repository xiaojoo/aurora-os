# ADR-210：xHCI 真设备 probe（QEMU 挂设备 + 读 CAP）

状态：**已采纳**（2026-11-22：`t_xhci_probe` 七格全 true，`PASS(33)`）

关联：ADR-208（TRB 字节层）、ADR-209（能力解码与初始化序列）、ADR-196（驱动注册表）

> 切片 H 第三层。**前两层都是纯函数判据** —— 这一层第一次真的读设备。

## 为什么必须先挂设备

在此之前 QEMU 只有 6 台 PCI 设备、**没有 xHCI**。于是 ADR-208/209 只能证「推导对」，
不能证「真的能跑」。AGENTS.md 那条「涉及硬件的结论要有第二台仪器对账」在这里的含义是：

> **没有设备参与时，判据只能证明逻辑自洽，不能证明它对硬件成立。**

## 交付

### 1. QEMU 挂 xHCI（`tools/aurora.py`）

```python
XHCI_FEATURES = {"xhci"}
if XHCI_FEATURES & set(features):
    cmd += ["-device", "qemu-xhci,id=xhci0,p2=2,p3=0"]
```

**`p2=2` 是可对账的期望值**：判据断言 `MaxPorts == 2`，改 QEMU 参数就会红。

### 2. `xhci::probe_device`（真读寄存器）

映射 BAR0 → 读 CAP → 用 ADR-209 的解码器校验形状 → 返回读数。

**不写任何寄存器**：初始化序列（`plan_init` 的 5 步）留到下一层。

### 3. 驱动注册表匹配

`MatchRule::new(0x0c, 0x03)` + `probe_xhci`，与 AHCI/virtio/NVMe 同一个 probe 链。

## 实测撞出的两个错

### 错 1：CAP 寄存器偏移全错了一格

第一版写：

```rust
pub const CAP_HCCPARAMS1: usize = 0x08;      // 错，0x08 是 HCSPARAMS2
pub const CAP_DOORBELL_OFFSET: usize = 0x0C; // 错，0x0C 是 HCSPARAMS3
```

实测症状：`db=0x00000000` ⇒ `BadCap`。因为 0x0C 是 HCSPARAMS3（QEMU 上是 0）。

正确的 xHCI spec §5.3 布局：

```
0x00 CAPLENGTH(1B) + RSVD(1B) + HCIVERSION(2B)
0x04 HCSPARAMS1
0x08 HCSPARAMS2   <- 我原来当成了 HCCPARAMS1
0x0C HCSPARAMS3   <- 我原来当成了 DBOFF
0x10 HCCPARAMS1
0x14 DBOFF
0x18 RTSOFF
0x1C HCCPARAMS2
```

**教训**：寄存器偏移必须逐字核对规范，不能凭「相邻字段」的直觉排。

### 错 2：诊断必须先打原始值

第一版只报 `BadCap`，不知道哪个字段不对。加了诊断后才看到 `db=0x0`。

**形状校验失败时，「哪个字段不对」比「失败了」重要得多。**

## 判据七格（`t_xhci_probe`）

```
xhci-probe: 找到=true caplen=0x40 slots=64 intrs=16 ports=2 ac64=true csz=false scratch=0
            db=0x2000 bar=16384 ⇒ true
```

`ports=2` 正是 QEMU 命令行写的 `p2=2`。

## 负样本（**这条最有价值**）

把 QEMU 参数改成 `p2=4`：

```
xhci-probe: MaxPorts=4 期望 2（QEMU p2=2）
xhci-probe: ... ports=4 ... ⇒ false
```

**这条负样本证明判据真的在读设备**，而不是自说自话 —— 前两层做不到这一点。

## 读数

| 项 | 结果 |
|---|---|
| `check` | **21/21** |
| `handles,xhci` 档 | **`PASS(33)`**，`t_xhci_probe` 七格全绿 |
| QEMU 设备数 | 6 → **7**（多了 class 0x0c/0x03）|

## 未决

1. **不写任何寄存器** —— 初始化序列还没执行
2. **等 CNR=0** 的轮询没做
3. **命令环 / DCBAA 分配** 没做（`plan_init` 只算序列，不分配缓冲）
4. **端口枚举**（Enable Slot → Address Device → Configure Endpoint）
5. **中断**（MSI/MSI-X 与事件环）
6. **默认档没挂 xHCI** —— 只有 `xhci` 特性开时才挂，避免影响既有判定矩阵