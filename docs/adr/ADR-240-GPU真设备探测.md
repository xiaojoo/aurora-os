# ADR-240：GPU 真设备探测（切片 I 第二层）

状态：**已采纳**（2026-11-23：`t_gpu_probe` 七格全 true）

关联：ADR-239（字节层）、ADR-210（USB 真读，同一步）

> ADR-239 是纯函数（喂 ID 回型号）。这一层**真的去读 QEMU 的显卡**。

## 交付

```rust
pub struct GpuReading { kind, vendor, device, class, subclass, progif, bar0, bar0_len, bar0_64 }
pub enum GpuProbeError { NotDisplay, UnknownVendor, NoMmio, BadBar }
pub fn probe_device(dev: &pci::Dev) -> Result<GpuReading, GpuProbeError>
pub fn probe_first() -> Option<(GpuReading, pci::Dev)>
```

## 决策 1：识别逻辑与取 ID 分开

`GpuKind::from_ids` 是**纯函数**（ADR-239），本层**从设备取 ID** 再喂给它。

这样「识别逻辑」能被纯函数判据完整证伪，「取 ID」能被真设备判据证。两者分开。

## 决策 2：`UnknownDisplay` 不算失败

```rust
if kind == GpuKind::UnknownDisplay {
    // 不算失败：这是「认得出是显卡但不认识型号」，要能被计数
}
```

「认得出是显卡但不认识」与「这不是显卡」是两件事 —— 前者 BAR 还是要读。

## 决策 3：BAR 尺寸必须成形状

`size == 0 || !size.is_power_of_two()` 都报 `BadBar`。

这与 `pci.rs` 的 `size_mem_bar` 同一条纪律：尺寸不成形状是**量具/设备**的问题，
不该被当成「映射失败」。

## 实测读数

```
gpu-probe: 找到=true 型号=bochs vendor=0x1234 device=0x1111 class=0x03/0x00
           bar0=0x80000000 len=0x1000000 64=false
           自洽=true 一致=true 非显示拒=true ⇒ true
```

**`0x1234:0x1111` = QEMU std VGA（Bochs 兼容）**，BAR0 = 16 MiB。

## 判据七格（`t_gpu_probe`）

1. PCI 枚举里能找到 class 0x03 的设备；
2. `probe_device` 成功；
3. 识别出的型号与 `from_ids` 自洽；
4. BAR0 是 2 的幂且非 0；
5. `class == 0x03`；
6. `probe_first` 与直接 `probe_device` 一致；
7. **负样本**：非显示类设备 ⇒ `NotDisplay`。

## 负样本（外部，最有价值的一条）

给 QEMU 加 `-vga none`：

```
gpu-probe: PCI 里没有可探测的显示设备
FAIL t_gpu_probe
```

**这条证明判据真的在读设备**，而不是在自说自话。

## 读数

| 项 | 结果 |
|---|---|
| `check` | **21/21** |
| `handles` 档 | `t_gpu_probe` 七格全绿；唯一失败是既有 `t_reap_premise` |
| 负样本 | **咬住**（`-vga none` ⇒ 找不到设备 ⇒ 红）|

## 未决

1. **没有映射 MMIO** —— `BOCHS_REG_*` 常量仍没人用
2. **没有读 Bochs 寄存器** —— 不知道当前模式
3. **`Frame` 仍从 Limine 取帧缓冲** —— 本层还没接进去
4. **只探第一台** —— 多显卡没做
5. **`probe_first` 跳过 `probe_device` 失败的设备** —— 那些失败没有被计数