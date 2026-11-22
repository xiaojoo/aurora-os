# ADR-217：superblock

状态：**已采纳**（2026-11-23：`t_superblock` 七格全 true）

关联：ADR-216（inode）、ADR-195（dentry 缓存）

> VFS 三层的第三层。**页缓存还没做。**

## 它记什么、不记什么

| 记 | 不记 |
|---|---|
| 卷指纹（与 dentry/inode 同一套）| 目录内容（那是 dentry 的活）|
| 几何（簇大小、簇数、FAT 类型）| 具体文件的元数据（那是 inode 的活）|
| **只读标志** | 页缓存 |
| 挂载引用计数 | 挂载点路径（单根挂载，固定 `/`）|

## 交付

```rust
pub const SB_MAX: usize = 8;
pub struct Superblock { vol, fat32, cluster_bytes, clusters, total_sectors, readonly, refs, used }
pub fn sb_mount(vol, fat32, cluster_bytes, clusters, total_sectors, readonly) -> Option<u32>
pub fn sb_umount(vol) -> bool
pub fn sb_get(vol) -> Option<Superblock>
pub fn sb_writable(vol) -> bool
pub fn sb_stats() -> (u32, u32)
```

## 决策 1：挂载是幂等的（`refs` 加一）

同一个卷被挂两次不该占两个槽 —— 这与 inode 的 `iget` 同一条思路。

## 决策 2：`sb_writable` 对**未挂载**的卷回 `false`

**不知道它是否只读时，保守拒绝。**

「默认可写」是那种「看起来方便、实际会静默写坏东西」的默认值。

## 判据七格（`t_superblock`）

```
sb: 挂载=true 幂等=true 卸载=true 只读=true 未挂载拒写=true 表满=true 统计=true ⇒ true
```

## 负样本（变异证红）

把 `sb_writable` 的未挂载分支改成 `true`：

```
sb: 未挂载的卷竟然可写
```

## 一个我踩了三次的坑（必须记下来）

`t_inode` 与 `t_superblock` 都出现过「统计不对」，成因完全相同：

**判据中途调了 `clear()`，而统计是在最后才查的。**

修正历史：

| 次 | 用例 | 错误 |
|---|---|---|
| 1 | `t_inode` | 最后才查 `inode_stats()`，中途 `inode_clear()` 清零 |
| 2 | `t_superblock` | 把统计移到 ⑥ 之前 —— 但 ④ 还有一次 `sb_clear()` |
| 3 | `t_superblock` | 移到 ③ 之后、④ 之前 —— 这次对 |

**教训：判据里凡有「累计计数」，必须在第一个可能清零它的调用之前取快照。**
这条应当写进写判据的检查清单。

## 读数

| 项 | 结果 |
|---|---|
| `check` | **21/21** |
| `handles,fs-ro` 档 | **`PASS(33)`**，`t_superblock` 七格全绿 |

## 未决

1. **页缓存** —— 每次 `open` 仍要 3 次块 I/O
2. **inode / dentry / superblock 三者未联动** —— 各自独立，没有「dentry 指向 inode、inode 指向 sb」
3. **没有 `i_op` / `f_op` 间接层**
4. **没有挂载点路径** —— 单根挂载，固定 `/`
5. **没有脏标记与回写** —— 只读卷不需要，`fs-rw` 档需要