# ADR-110：块设备请求层（deadline / 取消 / 完成通知）与 virtio-blk 的第一刀

状态：**提议**（2026-11-16 起草。等拍板；采纳前不动 `Block` 接口，也不动 virtio 的设备表）。
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

计数（每块盘一份，`AtomicU64`）：`requests / sectors_ok / timeouts / cancels / refused`。
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

- 读路径（`fat32.rs` 七处、`vfs_ro.rs` 四处、`gpt.rs` 四处）**先只接 `vfs_ro`/`fs_open` 这一条链**：
  让它带上 `Budget` 之后，判据能问"超时那次落了多少扇区"。其余调用点保持直接调 `Block`，
  它们没有 deadline 需求（引导期 GPT/FAT 探测是一次性的）。
- `BlockError` 不新增变体（`Refused` 复用为"取消"）——新增变体会让现有 7 个 `tag()` 与两张映射表
  同时变宽；等 S2 有真实写失败用例时再议。
- 判定行：新增一行"块请求层：超时/取消/半途"（`fs-ro` 档内跑，`TestDisk` 注入第 N 扇区失败），
  期望 PASS，配两条负样本：死线设成 0（必须立刻 `NotSettled` 且 `sectors_done=0`）、
  取消在中途（必须停在扇区边界）。

## 未决

1. `Budget.deadline_tsc` 用 TSC 还是 tick？TSC 在 qemu 下不稳（本仓库多处注明），
   倾向 tick；但 `Block` 层拿不到 `ticks()`，要么传值进来（当前写法），要么把时钟注入成参数。
   本 ADR 按"传值"写，等第一版读数出来再定。
2. 完成通知：本 ADR **不**承诺回调/工作队列，只承诺 `Outcome`。（真正的异步要等中断驱动，
   那是 110-b 之后的事；现在就加回调等于给一个没有异步的地方造异步。）
3. `MemDisk` 是否也该走请求层（判据更一致）还是继续"直连以标定基线"（当前 `TestDisk`
   就是用来做对照的）。倾向：请求层的 ktest 用 `TestDisk`，`MemDisk` 不动。
