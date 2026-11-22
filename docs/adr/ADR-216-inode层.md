# ADR-216：inode 层

状态：**已采纳**（2026-11-23：`t_inode` 八格全 true）

关联：ADR-195（dentry 缓存）、ADR-107（只读 VFS 适配层）

> 五样对象化第五片（E）的第二步。**superblock 与页缓存还没做。**

## inode 号从哪来

**用 FAT 的首簇号**（根目录 = 0）。这是天然稳定的：

- 同一个文件在不同路径下首簇相同 ⇒ inode 号相同；
- 跨卷复用同一个首簇号时会撞，所以键是 **`(卷指纹, 首簇)`**（与 dentry 缓存同一条教训）。

**不是 POSIX 的 `ino_t`**（那是文件系统自己的编号空间），但语义等价：
「同一文件在同一卷内的稳定标识」。

## 交付

```rust
pub const INODE_MAX: usize = 64;
pub struct Inode { vol, cluster, size, attr, refs, used }
pub fn inode_get(vol, cluster, size, attr) -> Option<u32>
pub fn inode_put(vol, cluster) -> bool
pub fn inode_peek(vol, cluster) -> Option<Inode>
pub fn inode_stats() -> (u32, u32, u32)
```

## 决策 1：`refs` 在「取」的时候加（POSIX 的 `iget`/`iput`）

没有引用计数的 inode 表无法安全淘汰（会拔掉别人正在用的项）。

## 决策 2：`refs` 减到 0 **不立即淘汰**

淘汰是 `inode_get` 在表满时做的。这样「用完就还」不会让缓存失效 ——
与 dentry 缓存同一条思路。

## 决策 3：淘汰策略是「找第一个 `refs == 0`」

不是 LRU：64 个槽的规模下 LRU 的收益不显著，而「第一个 refs==0」可预测，判据好写。

## 判据八格（`t_inode`）

```
inode: 首次=true 命中=true 不串=true put=true 全引用满拒=true 淘汰=true
       统计=true clear=true ⇒ true
```

## 负样本（变异证红）

把复合键退化成只看 `cluster`：

```
inode: 不同卷串了 a=Some(0) c=Some(0)
```

**不同卷的同簇号拿到了同一个槽** —— 与 ADR-195 那条「dentry 缓存必须带卷指纹」
是同一个错误的两种表现。

## 一个判据顺序的坑

第一版在最后才查 `inode_stats()`，而中途的 `inode_clear()` 把计数清零了，实测 `hits=0`。

**修法**：在 `clear` 之前记录一次统计。**这是判据顺序的错，不是代码的错。**

## 读数

| 项 | 结果 |
|---|---|
| `check` | **21/21** |
| `handles,fs-ro` 档 | **`PASS(33)`**，`t_inode` 八格全绿 |

## 未决

1. **superblock** 还没做（卷级元数据、挂载参数、只读标志）
2. **页缓存** 还没做（每次 `open` 仍要 3 次块 I/O）
3. **inode 与 dentry 未联动** —— dentry 缓存存的是 `Entry`，没有指向 inode 号
4. **没有 `i_op` / `f_op` 间接层** —— 仍按 FAT 硬编码
5. **淘汰是「第一个 refs==0」而不是 LRU**