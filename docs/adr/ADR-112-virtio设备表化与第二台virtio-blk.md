# ADR-112：virtio 设备表化与第二台 virtio-blk（ADR-110 决策 3 的 110-b）

状态：**采纳**（2026-11-17；使用者拍板先清这块欠账。实现见 `kernel/src/virtio.rs` 与 BACKLOG §372）。
关联：ADR-030（所有资源经 DriverCtx）、ADR-044（环基线棘轮）、ADR-110（块请求层；决策 3 指定本刀单开）、
BACKLOG 78h-3（virtio-blk 的 `Block` 实现，已在 §370 交付单设备适配器）。

## 背景

- `virtio.rs` 的 `DEV` 是**单设备静态**，`bind()` 只找 PCI 枚举里的第一台 storage-class 设备。
  于是"第二台 virtio-blk"在当时是硬性不可能，ADR-110 决策 3 把它单列成 110-b，理由是那一刀会
  动到已绿的第 22/33 行与 MSI-X 变体。
- §370 已交付 `VirtioDisk` 的 `Block` 适配器，但它同样只认第 0 台。没有设备表，"多块 virtio 盘"
  这件事在驱动侧就没有位置。

## 决策

### 决策 1：`DEV` 改成固定表，顺序 = PCI 枚举顺序（即 BDF 升序）

```text
DEVS: [DevCell; MAX_VBLK]   // MAX_VBLK = 4，静态常量
DEV_COUNT: AtomicUsize      // 只在 bind_all 里逐台增长
```

`bind_all()` 枚举全部 vendor=0x1AF4、class=storage 的设备，逐台 `bind_one(dev, slot)` 建独立队列
（每台自己的 `DriverCtx` / MMIO 映射 / DMA 环）。`bind()` 保留为"绑全部、第 0 台当主设备"的旧名字。
幂等：`DEV_COUNT > 0` 直接返回现有台数。

**上界是显式的**：第 5 台不会被绑（`MAX_VBLK=4`），这不是"暂时"——多到 4 台以上要重新量
`.bss`/帧预算，那是另一次容量裁决。

### 决策 2：`used_seen` 跟着设备走

表化之前 `USED_SEEN` 是**全局一格**；两台设备共用它时，第二台的第一次 I/O 会把第一台的
`used.idx` 基线改掉（症状是"偶发 UsedTimeout"）。它移进 `Bound`，每台各自一份。
`do_io` 改成 `do_io_at(i, …)`；`read_block`/`write_block` 仍是槽 0 的薄壳。

### 决策 3：取证是"两台同时在"，不是"代码里有个数组"

新变体 `virtio-two-probe`（Cargo 依赖 `virtio-blk`）：挂两块**容量不同**的 qcow2
（64 MiB / 96 MiB，第 0 扇区图案 `0x5C` / `0x3C`）。核内 `t_virtio_two` 判：

1. 台数 = 2，且 `bdf0 < bdf1`（枚举序）；
2. 两句容量 `{131072, 196608}` 扇区，与宿主机 `qemu-img info` 读两份文件得到的集合相等；
3. 每台 LBA0 的图案与它自报容量一一对应（64M→0x5C、96M→0x3C；串环/读错设备立刻露）；
4. 在 dev1 的扇区 1 写一段按 LBA 绑定的图案再读回（两台不共用环）；
5. 两台的 `status_at(i).qsize > 0`。

判定行 `virtio 两台并存`：同一跑的串口那行由宿主机按 `qemu-img` 的虚拟容量与 BDF 序复核；
内核绿而对不上 ⇒ `CONTENT-MISMATCH`。

### 决策 4：老行的设备集**不变**

`virtio-blk` / `virtio-msix-probe` 这两档的 QEMU 命令行只有一台设备，`bind()` 绑全部（=1 台），
行为与表化前逐字一致。MSI-X 那格仍只对第 0 台的队列 0 编程。

## 后果

- `storage -> pci` 的环内站点数由 13 升到 **15**（`pci::info` + `pci::dev` 的枚举是真边，
  不是短名误撞）；棘轮显式改大并注明来路。
- `virtio` 的 unsafe 站点由 10 降到 **8**（拆掉了"幂等读"与 `status()` 里两处对静态的
  `unsafe` 取用，改成经 `b_at` 的统一入口）；白名单与审计表同步收紧。
- 另一条真边：`block_io` 的计数器仍是**全局一份**（ADR-110 已记"等 Block 有身份"）；设备表化
  没有顺带解决它——那是 `Block` 接口的另一刀。

## 验证（2026-11-17）

- `run --features virtio-two-probe` = **PASS(33)**、ktests **86/86**（ELF `d987bf8045f6`）：
  `vblk2: 判据 台数=2 bdf0=6144 bdf1=8192 容量0=131072 容量1=196608 图案对=true 写读回=true 队列=true`。
- 判定行 `virtio 两台并存` = **符合**；宿主仪器自检：伪造 `bdf0>bdf1` ⇒ `BDF 序不对`，
  伪造 `容量1=999999` ⇒ `容量集合不符`（内核=[131072, 999999] 宿主机=[131072, 196608]）。
- 变异：`bind_all` 绑完一台就停 ⇒ `台数=1`、`t_virtio_two` 红；还原后 86/86。
- 老档：`virtio-blk` PASS(33)（ELF `a6fbb771a2ad`）、`virtio-msix-probe` PASS(33)
  （`4ed37be9c147`）；默认档 PASS(33)；`check` **17/17**。
