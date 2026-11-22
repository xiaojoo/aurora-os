# ADR-222：修 `XFER` 的锁序（`fs-open` 档从此能跑）

状态：**已采纳**（2026-11-23：`fs-open` 档不再 HANG）

关联：ADR-221（发现者）、ADR-190（`XFER` 的引入）、ADR-081（开窗条件）

> 修的是 ADR-221 发现的既有缺陷：**`fs-open` 档在 HEAD 就 HANG。**

## 根因

`driver/ahci.rs` 的 `XFER` 原本用 `RANK_BLOCK(37)`，注释写着：

> 传输内部不取任何别的锁（纯 MMIO + 轮询）⇒ 37 是安全下界。

**那个假设是错的。**

`transfer_inner` 里的 `wait_settled` / `wait_ms` 等的是**完成中断**，
而中断处理里取 `RANK_TIMER(6)`。

而 `XFER` 是 `OpenSpinLock`（**不动 IF** —— 那正是它存在的理由，见 ADR-191 补记），
所以持锁期间中断照进：

```
[fatal] L4 sync: 锁序违规，外层 rank=37(BLOCK) 本次 rank=6(TIMER)
```

后果是整机 HANG。`fs-open` 档因此从未跑通过。

## 修法

```rust
static XFER: OpenSpinLock<()> = OpenSpinLock::new(RANK_GROW, ());
```

取 `GROW(4)`：与 `CACHE_LOCK` / `STATE_LOCK` 同一档，都是「持锁期间会走到更深的锁」。

`RANK_BLOCK(37)` 现在只剩 `block_io` 的两把叶子锁（`QUEUE_LOCK` / `CB_LOCK`），
它们确实不调任何更深的东西 —— 那条注释对它们是对的。

## 一个让这件事浪费了一整轮的诊断缺陷（**顺手修了**）

锁序违规的日志原来只说：

```
外层 rank=37 本次 rank=6
```

**37 是哪把锁、6 是哪把锁，得靠人肉去数。**

实测为此浪费了一整轮：先怀疑 `QUEUE_LOCK`、再怀疑 `CB_LOCK`、最后才发现是 `XFER`。

补了 `LockRank::name()`（只读常量、不进临界区、不分配，可在崩溃路径调用）：

```
[fatal] L4 sync: 锁序违规，外层 rank=37(BLOCK) 本次 rank=6(TIMER)
```

**一眼就定位了。**

### 这条应当推广

> **诊断日志里的「数字」应该带上「它是什么」。**
>
> 一个只打编号的断言失败，会让下一个人重复一遍「枚举所有可能」的过程。

## 修好之后暴露的新问题

`fs-open` 档第一次跑到底，`t_fs_open_ring3` 当场红：

```
fs-open-ring3: 不成立 magic got=0 want=6075158342540415046
fs-open-ring3: 不成立 done got=0 want=3694445171683840070
```

**这是新暴露的、真实的 ring3 路径缺陷**，不是本 ADR 引入的 —— 它此前被 HANG 挡住了。
记为未决 1。

## 读数

| 档 | 修复前 | 修复后 |
|---|---|---|
| `check` | 21/21 | **21/21** |
| `handles` | `PASS(33)` | **`PASS(33)`** |
| `handles,fs-ro` | `PASS(33)` | **`PASS(33)`** |
| `handles,fs-open` | **HANG**（120s）| **跑到底**（`t_fs_open_ring3` 红）|

## 未决

1. **`t_fs_open_ring3` 的 `magic got=0`** —— 新暴露，ring3 路径读不到数据
2. **`read_chunk` 仍用不缓存版**（ADR-221 的回退）—— 现在 `XFER` 修好了，可以再试
3. **`RANK_BLOCK` 的语义收窄了** —— 从「块设备传输」变成「块层队列」，文档已同步
4. **`OpenSpinLock` 的通用风险** —— 任何 `OpenSpinLock` 持锁期间收中断都可能撞 TIMER，
   不只是 `XFER`。今天只有它一个使用者，将来新增必须按这条检查