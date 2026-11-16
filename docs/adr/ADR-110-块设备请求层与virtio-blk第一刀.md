# ADR-110：块设备请求层（deadline / 取消 / 完成通知）与 virtio-blk 的第一刀

状态：**采纳**（2026-11-16 起草；同日拍板：请求层在 `Block` 之上、deadline 用 **tick 传值**、
全部调用点一次接入。实现见 `filesystem/block_io.rs` 与 BACKLOG §360）。
关联：ADR-078（AHCI 分片与分区视图）、ADR-107（只读 VFS）、ADR-108（未决：块设备失败没有 `-7=EIO`）、
BACKLOG 78h-3（virtio-blk 的 `Block` 实现与它的理由）、AGENTS.md 里程碑缺口 4。

## 背景

- 今天的 `vfs::Block` 只有一条同步承诺：`read_sectors(lba, &mut [u8])`〔`kernel/src/filesystem/vfs.rs:111`〕。
  四个实现：`AhciDisk`、`MemDisk`、`PartitionView`、ktest 里的 `TestDisk`。
- 超时**有**，但在驱动里：AHCI 的 `read_bytes` 自带 `CmdTimeout` 与有界等待〔`ahci.rs:1501`〕；
  文件系统这一侧拿到的是已经扁平化的 `BlockError::NotSettled`，**不知道**这次读发了几个扇区、
  第几个扇区超的时、能不能半途放弃。
- 取消**没有**：一次多扇区读在 `AhciDisk` 里是逐扇区循环〔`vfs.rs:135`〕，循环没有出口条件，
  调用方也没有"别再发了"的手段。
- 完成通知**没有**：整条链是同步的，`Block` 返回即完成。将来 `w`m/服务化要靠中断或工作队列，
  而现在没有任何地方能挂"完成时做什么"。
- `virtio-blk` 的 `Block` 实现没做，理由写在 `vfs.rs` 的头注释里：`virtio.rs` 的 `DEV` 是**单设备静态**，
  挂第二台要把它改成按 BDF 的表，会动到已绿的第 22/33 行与 MSI-X 变体。

## 决策（提议）

### 决策 1：请求层放在 `Block` **之上**，不塞进每个驱动

新增 `filesystem/block_io.rs`：

```rust
pub struct Budget { pub sectors: u32, pub deadline_tsc: u64, pub cancel: &AtomicBool }
pub struct Outcome { pub sectors_done: u32, pub error: Option<BlockError> }
pub fn read_at(disk: &dyn Block, lba: u64, dst: &mut [u8], budget: &Budget) -> Outcome;
```

三条语义，必须写死：

1. **逐扇区提交，逐扇区判死线**：`sectors_done` 是"真落了地的扇区数"，失败时它小于请求数——
   这一格是"半途放弃"与"整条没发"的唯一区别；
2. **取消只在扇区边界生效**：`cancel` 置位的下一扇区不再下发，返回 `Option<BlockError> = Some(Refused)`
   且 `sectors_done` 停在当时的数。**不做**占用中撤销（那要驱动支持，见 110-b）；
3. **错误归因不合并**：`Outcome.error` 原样带 `BlockError`，`sectors_done` 与它一起上报；
   上层（句柄层）再用 ADR-108 的映射表把它变成 `-7 EIO`。

计数（`AtomicU64`）：`requests / sectors_ok / timeouts / cancels / refused`。
**落地第一版只有一份**，不是这里写的"每块盘一份"：`Block` 没有身份，`read_at` 拿不到
"这块盘是谁"；凭空造一个 id 没有调用方会填对。等 virtio-blk/`Block` 有了按 BDF 的身份再分桶。
"形状被拒"算一次 `requests`（它是"试过"），只计入 `refused` 而不碰盘。
判定行读这五个数，不读串口里的字符串。

### 决策 2：`Block` 接口这一刀**只加 `write_sectors`**，S2 复用同一层

写与读共用 `Budget/Outcome`，只有 `Block` 多一条方法（默认实现返回 `Refused`，`MemDisk` 与
`TestDisk` 保持只读）。这样 S2（syscall 23）只需实现 `AhciDisk::write_sectors` 与分区写界，
不用再动一次接口。

### 决策 3：virtio-blk 拆成 110-b，**不**与本 ADR 同轮落地

它真正的前置是把 `virtio::DEV` 从单设备静态改成按 BDF 的表，而那张表会改到第 22/33 行与
MSI-X 变体的取证形状。那一刀需要：`DEV` 表化 + 两台设备并存的最小证据（口序、能力表、队列数）
+ 老行重钉。放在本 ADR 里一起做，等于让"块层"和"设备表"两个原因的红混在一个读数里。

## 后果

- 调用点**一次接完**（2026-11-16 拍板；原草案只接一条链）：`fat32.rs` 七处、`vfs_ro.rs` 五处、
  `gpt.rs` 四处，共 16 处，全部经 `block_io::read_checked(…, &Budget::UNBOUNDED)` 走请求层；
  计数因此覆盖全部生产读。`PartitionView` 与 `TestDisk` 是**实现**（转发/委托给另一个 Block），
  不是调用点，保持原样——把它们也塞进请求层会重复计数并逐扇区绕两圈。
- `BlockError` 不新增变体（`Refused` 复用为"取消"）——新增变体会让现有 7 个 `tag()` 与两张映射表
  同时变宽；等 S2 有真实写失败用例时再议。
- 判据（已落地，`fs-ro` 档）：`t_block_io_budget` 用可编排的盘测"半途失败/死线 0/中途取消/
  两种形状被拒"四格 + 五计数的**增量**。三条变异各证红一次（不判死线、不判取消、吞掉盘错误）。
  **判定行已加（2026-11-17，§368）**：`块请求层超时取消半途`（`fs-ro` 档）。五个数由核内按增量
  断言；宿主机只做链级确认（那一行在、四个 bool 为 true、五项增量仍为 6/7/1/1/2），因为计数器在
  内核内存里，没有第二台仪器能独立读它。

- 落地时发现的量具误检（`core::sync::atomic` 被算成 storage→sync 的真边）已在 BACKLOG §363
  修正并重钉基线：该"边"整条消失，本 ADR 不再向环基线贡献虚假站点。

## 未决

1. ~~`Budget.deadline_tsc` 用 TSC 还是 tick？~~ **已裁（2026-11-16）：tick**，由调用方把
   "读 tick 的函数"放进 `Budget`；`block_io` 不依赖 `sched`，全不设死线时该函数不被调用。
2. 完成通知：本 ADR **不**承诺回调/工作队列，只承诺 `Outcome`。（真正的异步要等中断驱动，
   那是 110-b 之后的事；现在就加回调等于给一个没有异步的地方造异步。）
3. `MemDisk` 是否也该走请求层（判据更一致）还是继续"直连以标定基线"（当前 `TestDisk`
   就是用来做对照的）。倾向：请求层的 ktest 用 `TestDisk`，`MemDisk` 不动。
