# ADR-196：驱动注册表与 probe 链

状态：**已采纳**（2026-11-22：`register`/`probe_device` 落地，`drv` 六格全 true）

关联：ADR-195（dentry 缓存）

> 五样对象化第六片（F）的第一小步。**热插拔与 sysfs 还没做**，这一步只做「设备 → 驱动」的匹配。

## 背景：驱动是硬编码调用的

```rust
// main.rs
match ahci::init() { ... }
```

**加一块新设备就要改一次 `main.rs`。** 这不是「少了某个功能」，而是**设备模型不存在**。

## 决策

### 决策 1：只按 PCI class/subclass 匹配

| 规则 | 驱动 |
|---|---|
| `0x01/0x06` | AHCI（SATA 控制器）|
| `0x01/0x00` | virtio-blk |
| `0x02/0x00` | virtio-net |
| `0x01/0x08` | NVMe（`nvme` 特性门控）|

**不按 vendor/device 匹配**：那会把规则变成一张永远填不完的表，而 class 是设备自己声明的能力。

### 决策 2：`ProbeOutcome` 三态，不用 `Result`

```rust
pub enum ProbeOutcome {
    Claimed,                  // 认领成功
    NotMine,                  // 不是我的（规则匹配了但驱动自己判断不是）。**不是错误**
    Failed(DriverError),      // 是我的但坏了。**是错误**
}
```

`Claimed` 与 `NotMine` 是两种完全不同的结果，而「probe 失败」又要和「不是我的设备」分开。

### 决策 3：probe 链的四种语义

| 驱动回 | 链的行为 | 理由 |
|---|---|---|
| 规则不匹配 | 跳过 | 不算失败 |
| `NotMine` | **继续试下一个** | 规则是粗筛，驱动自己知道得更细 |
| `Claimed` | **立即返回** | 一台设备只归一个驱动 |
| `Failed` | **立即返回** | 是我的但坏了，不该让下一个驱动再试 —— **那会掩盖错误** |

## 判据六格（`t_driver_match`）

```
drv: 内置=3 匹配=true class_only=true Claimed停=true NotMine续=true Failed停=true ⇒ true
```

（`nvme` 特性下内置是 4 个，判据自动放宽。）

## 负样本（变异证红）

把 `Failed` 那支改成 `continue`：

```
drv: Failed 之后链没停（会掩盖错误）
drv: ... Failed停=false ⇒ false
```

**精准咬住。**

## 一个刻意的选择：启动路径只记匹配数，不真 probe

`stage_acpi_and_pci` 里对每台设备只打一行「类别 + 匹配几条规则」，**不调 `probe_device`**：

- 驱动的 `init()` 会真去动设备，而今天 AHCI 是在 `stage_storage_guard_crash` 里认领的；
- 在这里再 probe 一次会重复初始化（虽然幂等，但日志会乱）；
- **probe 链本身的正确性由 `t_driver_match` 单独证**，不靠启动路径。

这是「先有可证的机制，再谈接线」的顺序 —— 与 ADR-190 那次「先加锁再验证」的教训一致。

## 读数

| 项 | 结果 |
|---|---|
| `check` | **20/20** |
| `handles` 档 | `drv` 全绿，启动日志 `boot: 驱动注册 3 个（上限 8）` |

实测启动日志：

```
pci:   类别=0x06/0x00 匹配=0
pci:   类别=0x03/0x00 匹配=0
```

（QEMU 那几台是 ISA bridge / VGA，确实没有驱动认领 —— **匹配 = 0 是对的**。）

## 未决

1. **真 probe**（把 `probe_device` 接进启动路径，替代 `main.rs` 里的硬编码调用）
2. **热插拔**（uevent / devtmpfs / udev 接口）
3. **sysfs**（用户态枚举设备）
4. **按 vendor/device 的细规则**（今天只有 class）
5. **切片 G/H/I**：TCP、USB、GPU