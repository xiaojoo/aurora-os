# ADR-248：AHCI 入口拒绝外层高 rank 嵌套，默认 L4 不再级联

状态：已采纳（2026-11-24）。关联：ADR-031（崩溃落盘只许降级）、ADR-190/222（XFER 互斥与 rank=4）、
ADR-081（锁序严格递增）、BACKLOG §570。

## 背景

默认档软件 L4 仍走 `exit::finish → crash::ensure_dumped → state_store → AHCI → XFER(4)`。
当首条 L4 由 HEAP(10) 重入或 VMM(20) shootdown 超时触发时，落盘路径反向获取 XFER：

    [fatal] L4 sync: 重入获取 rank=10
    [fatal] L4 sync: 锁序违规，外层 rank=10(HEAP) 本次 rank=4(GROW)

第二次违规再次进入 `finish`。若 XFER 已被第一次违规持有，`OpenSpinLock` 没有重入/超时检测，
落盘会永久自旋。kdump 特性绕过了普通落盘，但默认档仍有这条级联。

## 决定

1. `OpenSpinLock` 增加 `lock_checked()`：CAS 前检查本 CPU 外层 rank，非法嵌套直接返回 `None`，
   不获取锁、不增加 `ACQUIRES`、不改 `INNERMOST`；合法路径仍走原有 `lock()` 等待互斥。
2. AHCI 的所有公共传输入口统一经 `with_transfer_lock`：写方向先取锁再填 DMA，读方向在
   `transfer` 取锁；非法嵌套返回 `AhciError::Denied`。
3. 拒绝发生在任何缓冲区写入、命令表编程和 MMIO 之前；正常无外层锁的调用路径不变。
4. 持锁 L4 的崩溃摘要因此降级为串口 + 现有无锁 `FATAL_RECORD`，明确打印“摘要写不进盘 Denied”，
   然后正常写 debugexit 39。状态区 V1/V2 格式、槽位、seq 与锁等级均不改。
5. 负样本特性 `fault-ahci-no-rank-guard` 移除入口闸，恢复 `RANK_TEST(60) -> XFER(4)` 级联。

## 调用点核对

普通产品 AHCI 调用都在锁外：启动验签、`state_store`、`AhciDisk` 直读直写；
`block_io` 的请求/回调队列先拷出再放锁，`cached_read` 的缓存锁也只包住查表/写回；
句柄文件读写在 `begin_read/begin_write` 返回票后全程锁外。没有发现合法的高 rank -> AHCI 路径。

## 验收

- 新 `KT_AHCI_LOCK_RANK_GUARD`：持既有 `CONTENTION_LOCK(60)` 调 `read_bytes`，必须 `Denied`，
  且不新增 `order_violations` / `reentrant_hits`；放锁后正常读盘仍成功。全内核 `acquires`
  增量只打印、不判等号，因为 AP 会并发取别的锁。
- `fault-lock-reentrant`：只保留首条 HEAP 重入 L4，随后 `Denied` 与 `qemu-exit=39`。
- `fault-shootdown-noack`：只保留首条 VMM shootdown L4，随后 `Denied` 与 `qemu-exit=39`。
- `fault-double-free`：无外层锁，崩溃摘要仍正常落盘。
- `fault-ahci-no-rank-guard`：确定性用例在 `外层 rank=60 本次 rank=4` 处重新级联并卡住，
  证明入口闸不是永远拒绝的空装饰。
- `build`、`ktests`、`check`、完整矩阵；真机未验证。

## 后果与边界

- 这是一条**入口契约**，不是新锁：任何未来持 rank>=4 的 AHCI 调用都会在驱动边界被拒，
  必须在锁外重新取票/提交，不能靠调高 XFER rank 绕过。
- 持锁崩溃不再保证落盘；这是 ADR-031“停机路径只许降级”的明确取舍，不宣称检测到等于已恢复。
- `OpenSpinLock` 本身仍缺重入/超时检测；本 ADR 只堵住 AHCI 入口，不把它推广成通用锁修复。
