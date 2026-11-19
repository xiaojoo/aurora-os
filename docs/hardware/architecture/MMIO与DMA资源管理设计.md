# MMIO 与 DMA 资源管理设计

状态：**设计（资源管理已实施；"先停设备再还页"的判据未实施）**

- 前置：`ADR-030`（驱动的唯一接口是能力句柄表）、`ADR-018`/`ADR-026`（堆上限 2048）、
  `ADR-066`（`map_hole` 高地址 UC 窗口）、`ADR-081`（等锁时开窗）、
  `lock-order.md`（RANK_VMM=20 / RANK_PMM=30 / RANK_LEDGER=40）

---

## 1. 已实施的部分（实测，不要重做）

### 1.1 MMIO

`kernel/src/driver/mod.rs` 的 `DriverCtx::map_mmio(bar)`：

```text
1. apic::in_isr() → WrongContext        （中断里不许建）
2. dev.size_mem_bar(bar)                写全 1 读掩码、立刻还原、读回对账
3. dev.mem_bar(bar)                     查是不是内存型、是不是 64 位
4. dev.enable_command(0b110)            置 MSE|BME 并**读回**
   → 读回值不是 0b110 ⇒ Denied("命令寄存器没接受 MSE|BME")
5. MmioRegion::map(pa & !0xFFF, size)   UC 映射
6. 表里记 MmioEntry { gen, owner, region, authorized }
```

四条硬性质（每条都有用例，`KT_DRIVER_CTX`）：

1. 撤销后旧句柄必被拒（`StaleHandle`，世代号变化）
2. 句柄认主人（`NotOwner`，表项记 `ModuleId`）
3. 窗口与对齐由表检查，不靠驱动自觉（底层是 `hw::MmioRegion`）
4. 建/撤不许在中断上下文（`WrongContext`）

**驱动拿不到物理地址，也拿不到指针。** 这是 ADR-030 决定 1 的原话。

### 1.2 DMA

`alloc_dma(len)`：

```text
1. in_isr() → WrongContext
2. len 必须非零且整页（"向上取整"不许藏在接口里）
3. mm::phys_alloc(order, owner)         连续物理帧（2 的幂）
4. mm::alloc_va_range(n) + mm::map(..., PageFlags::DEVICE)   UC 别名
5. 表里记 DmaEntry { gen, owner, map, bus, len }
```

**不交出 `&[u8]` / `&mut [u8]`**（ADR-030 决定 4）。给的是：

`dma_read8/16/32`、`dma_write8/16/32`、`dma_copy_in`、`dma_copy_out`、`dma_fill`、
`bus_addr()`（**整数**，填描述符用，解不开引用）。

为什么不能交切片：设备随时会写那块内存，把它当成 Rust 可读写的切片
就是语言层面的 UB。这条**不是洁癖**——它代价明确：内容对账从"对一段切片算哈希"
变成"逐字节问答"（实测 131 584 次）。

### 1.3 容量（会直接卡住后续）

| 项 | 值 | 位置 |
|---|---|---|
| `MMIO_SLOTS` | **8** | `driver/mod.rs` |
| `DMA_SLOTS` | **8** | 同上 |
| DMA 对齐粒度 | 整页、2 的幂 | `alloc_dma` 的 `order` |

**实测的占用形状**：`virtio::probe()` 映射一次 MMIO（取证），`bind_one()` 再映射一次
⇒ 同一台设备短暂 2 格。今天在线的是 AHCI(1+1) + 2×virtio-blk(2+2) + virtio-net(1+2)，
**已接近上限**。要加 NVMe + virtio-gpu + 物理网卡，8 格必然不够。

---

## 2. 本设计要补的第一件事：`inflight` 与 `Busy`

### 2.1 问题（实测缺口）

`release_dma(h)` 今天只做：

```rust
Self::dma_of(h, self.owner)?;                    // 校验
unsafe { &mut *TABLE.0.get() }.dma[i].take()     // 摘走 → DmaEntry 被 drop
```

`DmaEntry` 里的 `Mapping` 被 drop 时解映射 + 还帧（台账跟着减）。
**没有任何一步检查设备是否还在用这块内存。**

今天不出事，是因为所有调用点都是"先 quiesce 队列再 release"的**手写顺序**，
靠人记。这就是 [总设计 §3.9](../Aurora-OS-硬件驱动体系总设计-V1.0.md) 指出的缺口。

### 2.2 补法（小，不需要新 ADR）

```rust
struct DmaEntry {
    ...
    /// 设备手上有几个描述符指向这块内存。驱动在"把描述符交给设备"时 +1、
    /// "收到完成"时 -1。**只由驱动在提交/完成两处动它**，句柄表不代劳。
    inflight: AtomicUsize,
}

// 新错误变体
DriverError::Busy { slot: u16, gen: u32, inflight: usize }

pub fn release_dma(&self, h: DmaHandle) -> Result<(), DriverError> {
    ...
    if e.inflight.load(Ordering::Acquire) != 0 {
        return Err(DriverError::Busy { slot: h.slot, gen: h.gen, inflight: n });
    }
    ...
}
```

**为什么放在 `driver/mod.rs` 而不是驱动里**：这是"表能不能放手"的判断，
与 `StaleHandle`/`NotOwner` 同一层级——都是句柄表的责任。放在驱动里就变成
每个驱动各写一份会漂的算术。

### 2.3 判据

| 判据 | 形状 |
|---|---|
| 正向 | 提交 1 个描述符不完成 ⇒ `release_dma` 返回 `Busy{inflight:1}`；完成后 ⇒ `Ok` |
| 负样本 | 去掉 `inflight` 检查 ⇒ 判据必须红 |
| 交叉 | `release_dma` 失败后 `occupancy()` 的 DMA 计数**不变**（表没动） |

---

## 3. 相关既有机制（不要重复实现）

| 机制 | 在哪 | 用途 |
|---|---|---|
| `mm::map_hole(va, size)` | `memory/mm.rs`（ADR-066） | 4 GiB 之上 MMCFG/PCI MMIO 的 UC 窗口 |
| `split_huge` | 同上（ADR-066） | 大页里落 4 KiB 映射（MMIO 对齐时常撞） |
| 等锁开窗 | `sync/mod.rs`（ADR-081） | 等 VMM(20)/PMM(30) 时按条件开中断窗口 |
| 台账 | `resource/mod.rs`（RANK_LEDGER=40，叶子） | 按 `ModuleId` 聚合存活帧 |

**`ModuleId(19)` 撞车必须知道**：`driver/virtio.rs` 用 `MOD_VIRTIO = ModuleId(19)`，
`memory/vmo.rs` 用 `MOD_VMO = ModuleId(19)`。今天不出事是因为两条账从不放在一起比，
但台账**按模块聚合** ⇒ 拿 19 号查"virtio 占了多少帧"会读到 VMO 的数。
**新增驱动前先分开这两个号**（已记入 ADR-161 §未决 与总设计 §9.1）。

---

## 4. "先停设备再还页"——今天没有机器判据，这是本文档要说的重点

### 4.1 为什么这条重要

设备仍在 DMA 时还帧 ⇒ 那块物理内存被下一个使用者拿走、清零、改成页表页。
表现**不是错误码**，是随机内存损坏，而且往往在很久之后。

### 4.2 今天有什么、缺什么

| 有 | 缺 |
|---|---|
| `DmaHandle` 不交切片（内容不会逃逸） | `inflight` 计数 |
| `release_dma` 会解映射并按台账还帧 | 还帧前的 `inflight != 0` 拒绝 |
| 调用点手写"先 quiesce"顺序 | 这条顺序的**判据** |

### 4.3 落法（两片）

**第一片（本文档范围内，不需要新 ADR）**：`inflight` + `Busy`（§2）。

**第二片（要 ADR，编号 162 起）**：真正的 IOMMU 隔离。

今天的现状（实测）：`bus/acpi.rs` 只解析 DMAR 的 `host_address_width`（偏移 36）
与 `flags`（偏移 37），**不建任何映射表**；本机 DMAR 缺席。

所以第二片的验证必须用 `-device intel-iommu,intremap=on`（QEMU 11.1.0 已核实支持），
真机另测。第二片要回答的问题：**未映射的 DMA 地址到达设备时，是 IOMMU 拒绝还是设备报错？**
这决定了错误归因能不能落到驱动层。

---

## 5. 约束清单（新驱动必读）

| 约束 | 值 / 规则 | 违反的表现 |
|---|---|---|
| 堆单次分配 | ≤ 2048 字节（`LARGE_MAX`） | `OOM_COUNT` +1，`alloc` 返回 None ⇒ `handle_alloc_error` |
| 大缓冲 | 走 `alloc_dma`（`phys_alloc` + UC 别名），**不进堆** | 同上 |
| DMA 长度 | 非零整页，2 的幂 | `Denied("长度必须是整页的非零倍数")` |
| 中断上下文 | 不许 `map_mmio` / `alloc_dma` / `request_irq` | `WrongContext` |
| 裸访问 | `driver/` 下（除 `mod.rs`）不许 `read_volatile`/`write_volatile`/`ptr::`/`from_raw_parts` | `check-driver-ctx` 红 |
| 新增 `unsafe` | 登记 `unsafe-whitelist.toml`（七项：来源/范围/对齐/生命周期/并发/上下文/谁保证） | `check-unsafe` 红 |

**`driver/mod.rs` 故意不在裸访问黑名单里**：它就是 `DriverCtx` 自己的实现，
按 ADR-030 决定 4 必须含 volatile 访问器。`ADR-030` 决定 3 的尺子自证原文就写着
「把清单临时指向 `driver.rs` ⇒ 门禁报出裸访问 ⇒ 它能红」。

---

## 6. 未实施清单

1. `DmaEntry::inflight` + `DriverError::Busy`（§2，小）。
2. `release_dma` 的 `Busy` 判据 + 负样本。
3. `driver::occupancy()` 扩成"已用/总量"两格。
4. IOMMU 表（第二片，需 ADR）。
5. `ModuleId(19)` 分开（需 ADR，改台账归属语义）。
