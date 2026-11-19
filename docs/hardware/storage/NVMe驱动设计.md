# NVMe 驱动设计

状态：**未实施**（全仓零行 NVMe 代码；QEMU `nvme` 设备已核实存在）

- 相关 ADR：`ADR-110`（块设备请求层）、`ADR-112`（virtio 设备表化）、
  `ADR-113`（块设备身份与按盘分桶）、`ADR-030`（驱动唯一接口）
- 上位：[硬件驱动体系总设计](../Aurora-OS-硬件驱动体系总设计-V1.0.md)
- 相关：[MMIO与DMA资源管理设计](../architecture/MMIO与DMA资源管理设计.md)

---

## 1. 为什么 NVMe 是"真设备"里性价比最高的一台

| 理由 | 说明 |
|---|---|
| **不需要新裁决** | 它不是 USB、不是硬件矩阵，不撞任何已生效裁决 |
| **能立刻接进既有块层** | `filesystem/vfs.rs` 的 `Block` trait 已有 **5 个实现**：`AhciDisk` / `VirtioDisk` / `MemDisk` / `PartitionView` / `RwDisk`（+ ktest 的 `TestDisk`）。NVMe 是第 6 个 |
| **判据可复用** | 判定表已有"virtio 写落盘与宿主机对账"（第 31 行）与"FS写方向与可写卷对账"（第 61 行）两条，形状完全适用 |
| **真 DMA + 真 MSI-X** | 它能验证"驱动框架能不能撑住一个有深度的队列设备" |
| **QEMU 模型齐全** | `nvme` / `nvme-ns` / `nvme-subsys`（已核实） |

---

## 2. 协议要点

### 2.1 结构

```text
BAR0：控制器寄存器（CAP / VS / INTMS / INTMC / CC / CSTS / AQA / ASQ / ACQ / …）
     注意：CAP 是 64 位，偏移 0x0；VS 在 0x8；CC 在 0x14；CSTS 在 0x1C
     这些偏移必须**先读回验证**（ADR-029 的口径：手册上的表要由设备作证）

队列：
  Admin Queue（ASQ/ACQ）—— 建 I/O 队列用
  I/O Queues（1..N）—— 读写用
  每条队列是一对环：Submission Queue（命令）+ Completion Queue（完成）

命令：64 字节定长
  DWORD0: opcode | fuse | CID
  DWORD1: NSID
  DWORD2-3: 保留
  DWORD4-5: metadata ptr
  DWORD6-9: PRP1（数据指针）
  DWORD10-11: PRP2 或 SGL
  DWORD12-15: command-specific
完成：16 字节（result + 保留 + SQHD | SQID | CID | status）
```

### 2.2 PRP（Physical Region Page）

**这是 NVMe 与 AHCI/virtio 最大的不同**：数据指针不是"地址+长度"，
而是"PRP1 + PRP2"，且**物理页可以不连续**。

```text
一次传输 ≤ 1 页    ：PRP1 指那一页
1 页 < 传输 ≤ 2 页 ：PRP1 首页、PRP2 第二页
传输 > 2 页        ：PRP1 首页、PRP2 指一个 PRP List（该表里每项指一页）
```

**我们的 `alloc_dma` 保证连续物理内存**（`phys_alloc(order)`），
所以第一阶段**可以只用 PRP1**（一次一页）。这是**大幅简化**的关键：
不实现 PRP List，只做"每命令一页"。

**代价**：大块传输要拆成多次命令。对判据没有影响（块请求层
`filesystem/block_io.rs` 本来就是**逐扇区提交**，见 ADR-110 决策 1）。

### 2.3 为什么 PRP 简化是安全的

`block_io` 的语义就是"逐扇区提交、失败时 `sectors_done` 小于请求数"。
所以 NVMe 驱动每次只搬 512 字节（一页足够），完全落在 `block_io` 的期望里。

**如果将来要做大块 DMA**，才需要 PRP List；那时要先有"连续多页 DMA"的接口，
而 `alloc_dma(order)` 已经能拿 2 的幂次连续页 ⇒ 一次最多 `8 * PAGE`（order=3）。

---

## 3. 五片

```text
N-1  PCI 识别 + 寄存器读数
     - class 0x01 / subclass 0x08 / progif 0x02（NVMe 的三件套）
     - map_mmio BAR0，读 CAP（64 位）/ VS / CSTS
     判据：CAP 的 MQES（队列深度上限）与 QEMU 的 `-device nvme` 声明一致；
           CSTS.RDY 初始为 0（未使能）

N-2  控制器使能 + Admin 队列
     - 写 AQA（队列深度）、ASQ/ACQ（DMA 地址）
     - CC.EN=1，等 CSTS.RDY=1（**有界等待**）
     - 发 Identify Controller（opcode 0x06）读回型号/序列号
     判据：Identify 的 model/serial 与 QEMU 的 `serial=` 参数对账
           ← 与 e1000e 的 MAC 对账同一形状（最便宜的第一条判据）

N-3  建 I/O 队列 + Identify Namespace
     - Create I/O Completion Queue / Submission Queue（opcode 0x05/0x01）
     - Identify Namespace（CNS=0）读 NSZE（命名空间大小，单位 LBA）
     判据：NSZE × LBA 大小 == 宿主机 `qemu-img info` 的 virtual-size
           ← 判定表已有同形状的对账（"virtio 两台并存"那条的第 2 格）

N-4  读一个扇区
     - Read（opcode 0x02），PRP1 指一页 DMA，等完成
     - 实现 `Block for NvmeDisk`
     判据：读回的字节与宿主机 qemu-io 写下的图案逐字节相同
           ← 判定表第 31 行的形状可直接复用

N-5  写一个扇区 + 中断
     - Write（opcode 0x01）
     - MSI-X 或 INTx；两本账（`irq::counts`）
     判据：写后**宿主机从 qemu-img 读回**校验（判定表第 31/61 行的形状）
```

### 3.1 顺序说明

**N-1 → N-2 → N-3 → N-4 → N-5 不能跳**：每片的判据都依赖前一片
（没有 Identify 就不知道命名空间大小；没有 I/O 队列就不能读）。

**N-4 先于 N-5**：读路径比写路径简单（写要验落盘，读只要验内容），
且 `block_io` 的读方向已经是最成熟的路径。

---

## 4. 与既有块层的关系（这是本设计最省事的地方）

```text
filesystem/block_io.rs   死线、取消、sectors_done、错误归因不合并（ADR-110）
        ↑
filesystem/vfs.rs 的 Block trait
        ↑ 断言"这一扇区读成了没有"
   ┌────┴────┬──────────┬────────────┬──────────┐
AhciDisk  VirtioDisk  MemDisk  PartitionView  RwDisk   ← 5 个已有实现
        ↑
NvmeDisk  ← 第 6 个，只要实现 read_sectors / write_sectors
```

**所以 NVMe 驱动只需要**：

```rust
impl Block for NvmeDisk {
    fn read_sectors(&self, lba: u64, dst: &mut [u8]) -> Result<(), BlockError> { ... }
    fn write_sectors(&self, lba: u64, src: &[u8]) -> Result<(), BlockError> { ... }
}
```

**死线、取消、半途读数全部由 `block_io` 负责**，NVMe 驱动不用重复实现。
这一点要写清——否则会有人在新驱动里再写一遍超时逻辑，
然后两份算术开始漂（ADR-110 存在的理由就是这句话）。

---

## 5. 判据与负样本

| 片 | 判据 | 第二台仪器 | 负样本 |
|---|---|---|---|
| N-1 | CAP/VS/CSTS 读数 | 无（QEMU 无 `info nvme`；可用启动日志对照） | CAP 读错 64 位（只读低 32 位）⇒ 红 |
| N-2 | Identify model/serial | QEMU `serial=` 参数 | 序列号读错偏移 ⇒ 红 |
| N-3 | NSZE × LBA == virtual-size | `qemu-img info --output=json` | 只读 NSZE 低 32 位 ⇒ 红 |
| N-4 | 读回图案 | `qemu-io` 写下的图案 | LBA 高半写错（照抄 `fault-ahci-highlba`）⇒ 红 |
| N-5 | 写后宿主机读回 | `qemu-img`/`qemu-io` | 扇区数按 1 编程（照抄 `fault-ahci-write-partial`）⇒ 红 |

**N-3 的判据与"virtio 两台并存"那条同形状**：容量对账已经证明过这条路能走。

---

## 6. 容量与约束

| 约束 | 值 | 影响 |
|---|---|---|
| `MMIO_SLOTS` | **8**（`driver/mod.rs`） | NVMe 占 1 格（BAR0） |
| `DMA_SLOTS` | **8** | 至少要：Admin SQ + Admin CQ + 1 I/O SQ + 1 I/O CQ + 数据页 = **5 格** |
| 中断向量 | 16（剩 ~9） | MSI-X 1 颗；INTx 也用 1 颗 |
| 堆单次上限 | 2048 | 队列必须在 `alloc_dma` 里，不能进堆 |
| 队列深度 | 由 CAP.MQES 定（QEMU 与真机不同） | 需要**读回**，不写死 |

**`DMA_SLOTS` = 5 格给一台设备，是本文档最该被看见的数字**：
今天 8 格，virtio-blk 已占 2 格/台 ×2 台 + AHCI 1 格 + net 2 格
⇒ **加 NVMe 会溢出**。这是 AHE-01 必须排在最前面的直接证据。

**一个可选的节省**：把 Admin SQ/CQ 与 I/O SQ/CQ 放在**同一块 `alloc_dma`** 里
（连续页，自己切偏移）。那样 5 格能压到 2 格。**建议这么做**，
因为 `driver/mod.rs` 的 `DmaHandle` 支持带偏移访问（`dma_write8/16/32` 都收 `off`）。

---

## 7. 未实施清单

1. 新文件 `kernel/src/driver/nvme.rs`（**尚未创建**，进 `DRIVER_MODULES`）。
2. N-1..N-5 五片。
3. `Block for NvmeDisk`（第 6 个实现）。
4. 判定表加 2 行（读对账 / 写对账）+ 2 条负样本。
5. **前置 AHE-01（`MMIO_SLOTS`/`DMA_SLOTS` 重算）**。

---

## 8. 未验证

- QEMU `nvme` 的 CAP.MQES / TO / DSTRD 实际值：**未读**。
- Identify 报文的确切长度与字段偏移：**未核**（本文按规范写，未对代码验证）。
- QEMU `nvme` 是否支持 MSI-X（还是只有 INTx）：**未查**。
- `-device nvme` 与 `nvme-ns` 的接线（是否需要显式建 namespace）：**未试**。

**上述任一条在实施前都要先量。**
