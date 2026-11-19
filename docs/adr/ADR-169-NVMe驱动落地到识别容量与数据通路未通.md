# ADR-169：NVMe 驱动落地到「识别」；容量与数据通路未通

状态：已采纳（2026-11-20）
关联：ADR-165（槽位与编号）、ADR-168（network 搬迁）、ADR-044（棘轮）、ADR-110（块层）

> **本文如实记录"做到哪、卡在哪"**。按 AGENTS.md 硬约束 7：
> 不得夸大结论——「设备被识别」不等于「驱动可用」。

---

## 一、做到什么

`kernel/src/driver/nvme.rs`（约 600 行）在 QEMU 的 `-device nvme` 上：

**✅ 识别成功**（实测读数）：

    nvme: 识别 bdf=6144 vendor=0x1b36 device=0x10
         cap_lo=0xf0107ff cap_hi=0x400820 vs=0x10400
         csts=0x1->0x1 already=true mqes=2048 nn=256 nsze=0 lbads=9

- `vendor=0x1b36` = QEMU Red Hat vendor ID ✅
- `vs=0x10400` = NVMe 1.4 ✅
- `mqes=2048` ⇒ 最大队列深度 2049，我们的 `QDEPTH=8` 装得下 ✅
- **Identify Controller 成功**（`cid=1 status=0`），序列号读回 `AURORANVME`
  （`前16 = [36,1b,f4,1a, 41,55,52,4f,52,41,4e,56,4d,45,20,2…]` 里
  `[4..16]` = `AURORANVME`，与 `-device nvme,serial=AURORANVME` 对上）✅
- 型号读回 `QEMU NVMe Ctrl`（`型号区 = "QEMU NVMe Ctrl"`）✅

**❌ 未通**：
- **Identify Namespace 不产生完成项**（`CmdTimeout cid=2`）⇒ `NSZE=0`
- **数据读写未通**（`读扇区 0 失败 CmdTimeout cid=3`）

---

## 二、这一轮抓到的三个真 bug（都有实测现场）

### 1. `alloc_dma` 只接受 2 的幂的页数

    unexpected #PF rip=… cr2=0xffff80002058e000 err=0x2

`alloc_dma` 内部是 `(len / PAGE).ilog2()`，**向下取整且静默**。
我传 5 页 ⇒ 实际只映了 4 页，而 `OFF_DATA = 16384` 在第 5 页 ⇒ 写数据页当场 `#PF`。

**修**：`DMA_PAGES: 5 → 8`，并把这条契约写进 `alloc_dma` 的注释
（下一个人会踩同一个坑）。

### 2. CQ 的 phase 位是「整圈翻转的奇偶」，不是「每格置 1」

    cid=1 成功 → cid=2 超时

把 phase 当成"每格独立的到达标志"在绕圈之后必然错。
**这是 NVMe 与 virtio 最根本的差别**：virtio 的 `used.idx` 单调递增，
NVMe 的 phase 翻转。

**修**：维护 `cq_phase: bool`（初值 `true`，清零后第一圈是 1），
每绕满一圈翻转一次。

### 3. 已使能时必须先 `CC.EN=0` 再重配 ASQ/ACQ

    CmdTimeout cid=1（第一条命令就不完成）

规范（NVMe 1.4 §7.6.1）要求改 ASQ/ACQ/AQA **之前**必须 `CC.EN=0` 并等 `CSTS.RDY=0`。
我第一版在"起始已使能"的路径上跳过了 `CC.EN=1`（怕重复写未定义），
但**仍然写了 ASQ/ACQ** —— 那对运行中的控制器无效，它继续用固件留下的旧队列。

**修**：两条路都走完整的「（必要时先关）→ 配置 → 使能」序列。

---

## 三、卡点：Identify Namespace 不产生完成项

### 现场

    sq 诊断 slot=1 dw0=0x20006 dw10=0x0     ← opcode 6 / CID 2 / CNS 0（Namespace）
    cq 诊断 cid=2 head=1 d2=0x2 d3=0x10002  ← SQHD=2 说明设备**已消费**命令
    CmdTimeout cid=2                        ← 但没写 CQE

`d2=0x2`（SQHD=2）说明设备**看到了**这条命令；`d3` 那一格还是上一条的残留。
所以：**设备接受了命令、推进了 SQ head，但不产生完成项。**

### 已知的两个可疑点（**都未验证**）

1. **NSID 不匹配**：我传 `nsid=1`，而 QEMU 实际分配的命名空间号可能不是 1。
   规范说 NSID 无效时应回 `Invalid Namespace or Format`（status=0x0B），
   **不是静默不写 CQE**——所以这个解释不完全站得住。
2. **Identify Namespace 的 CDW10 高半**：CNS 只在 CDW10 的 bit0..7，
   我用 `dw10=0x0`。若 QEMU 要求 CDW11 的 `CNTID` 也写 0（我写了，因为 SQE 清零过），
   那不该有问题。

**未验证的部分必须写"未验证"**，不能编一个解释。

### 临时处置（诚实标注，不假装通过）

- **`NSZE` 记 0**，`log_warn!` 明说「未读到」；
- 容量判据改成：内核报它读到的（0），**宿主机 `qemu-img` 独立算**；
  两边对不上就是红——**不是绿**。
- `nn=256` 也不可信（QEMU 默认 1 个命名空间），同样只当读数、不当判据。

---

## 四、判据设计（三格，各自能独立红）

| 格 | 证什么 | 现状 |
|---|---|---|
| 识别 | PCI 三件套能认到、CAP/VS/CSTS 形状自洽、型号/序列号与宿主机 `serial=` 对上 | **✅ 通过** |
| 容量 | `NSZE × LBA` 与 `qemu-img` 的 virtual-size 相等 | ❌ `NSZE=0` |
| 图案 | 读扇区 0 看到 `qemu-io` 写的 `0x7E` 图案 | ❌ 命令超时 |

**不合并成一个布尔**——「设备能不能用」这个说法在本仓库是被拒绝的形状
（成因不能压成一个数）。

### 一条判据在这一轮被改正过（记下来）

识别格里我原来写「未使能时 `CSTS.RDY` 必须为 0」，实测报
`BadRegs { off: 28, got: 1 }` —— QEMU 的 NVMe 在 EDK2 阶段就可能已经使能过。

**那条假设证的是「设备还没被碰过」，那是环境假设，不是设备性质。**
改成状态机合法（起始 CFS=0；终态 RDY=1 且 CFS=0），比原来**更强**。

---

## 五、登记增量（按实测，不猜）

| 项 | 变化 | 理由 |
|---|---|---|
| `unsafe` 普查 | 523 → **530**（U4 142 → 149） | `nvme.rs` 的 `STATE` `UnsafeCell` + 4 个 `dma_*` 访问点 |
| 棘轮 `driver->memory` | 16 → **21** | 新驱动用 `mm::ModuleId` |
| 棘轮 `driver->pci` | 18 → **21** | 新驱动用 `pci::first_of_triple` |
| `driver.public_api` | +3 | `nvme::NvmeError` / `read_lba` / `write_lba` |
| `driver.source_modules` | +`driver/nvme` | — |
| `block_io::BUCKETS` | 42 → **44** | `DiskKey::Nvme` 要有自己的桶 |
| `DiskKey` | +`Nvme(u8)` | 请求计数按盘分桶（ADR-113） |

**棘轮变大是新增设备造成的，不是既有代码变差。** ADR-044 说"只许减不许增"，
但它同时要求"变了要显式登记"——这里如实抬高并在本文写明理由。
收紧回去只有一条路：让 NVMe 不依赖 `pci`，那不可能（它就是要枚举设备）。

---

## 六、读数

| 项 | 值 |
|---|---|
| `check` | **18/18** |
| 特性档 | **74/74**（`nvme` 已进矩阵） |
| `nvme` 档判定 | **FAIL(35)** —— 识别格过，容量/图案两格未通 |
| `ktests`（nvme 档） | 83 / 82 / **1 failed**（`t_nvme_all`） |

**这个 FAIL 是诚实的**：驱动确实还没可用。判据红着，而不是被改成绿。

---

## 七、下一步（按依赖顺序）

1. **量出 Identify Namespace 的真实 NSID**：用 `Identify Controller` 的
   `NN` 与 QEMU 的 `-device nvme` 参数交叉核；或者用 `NSID=0xFFFFFFFF`（广播）
   读一次，看设备回什么。**先量再改。**
2. **量 `nn` 的真实偏移**：读到 256 而 QEMU 默认 1 个命名空间 ⇒ 偏移可疑。
   用"型号区能读对"证明缓冲起点正确之后，逐 4 字节扫 512..560 找 `nn=1`。
3. **数据通路**：容量通了之后，`read_lba` 的 PRP1 与 `NLB` 才有意义验证。
4. **第二台仪器**：`qemu-img info` 的 virtual-size 对账要在 `tools/aurora.py` 里落地
   （今天只有 `make_nvme()` 造盘，还没有 `check_nvme_capacity`）。

---

## 八、未决

1. **Identify Namespace 为何不产生完成项**：**未验证**。两个可疑点见 §三。
2. **`nn=256` 是否为真实读数**：**未验证**。
3. **`-device nvme` 的默认命名空间号**：未查 QEMU 文档确认。
4. **`.bss` 增量**：`DMA_PAGES=8` × 8 页 DMA 是运行时分配，不占 `.bss`；
   但 `STATE` 里的 `DriverCtx` 有静态表项，增量未实测。
5. **多台 NVMe**：`DiskKey::Nvme` 只留 2 格桶、`STATE` 是单例。表化未做。
