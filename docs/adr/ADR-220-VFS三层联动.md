# ADR-220：VFS 三层联动

状态：**已采纳**（2026-11-23：`t_three_layers` 九格全 true）

关联：ADR-195（dentry）、ADR-216（inode）、ADR-217（superblock）

> 把三个**各自独立**的层串成一套。

## 为什么需要这一层

三层此前各有判据全绿：

| 层 | 它知道 | 它不知道 |
|---|---|---|
| dentry 缓存 | 名字 → `Entry` | 这个 Entry 的 inode 是谁 |
| inode 表 | `(vol, cluster)` → 元数据 | 这个 inode 属于哪个挂载 |
| superblock | 卷 → 几何/只读/引用 | 卷里有哪些文件 |

**没有任何东西保证它们说的是同一个文件。**

## 交付

```rust
pub struct VfsNode { sb_slot, inode_slot, vol, cluster, size, attr }
pub enum NodeError { NotMounted, NoInode, Vfs(VfsError) }
pub fn open_node(disk, bpb, path, readonly) -> Result<VfsNode, NodeError>
pub fn close_node(n: &VfsNode) -> bool
pub fn node_consistent(n: &VfsNode) -> (bool, bool, bool)
pub fn sb_slot_of(i: u32) -> Option<Superblock>
pub fn volume_fingerprint_pub(disk, bpb) -> u64
```

## 决策 1：顺序是「superblock → 路径 → inode」

**先查 superblock**：没挂载的卷不该被解析（否则会读到未验证的字节）。

反过来（先 dentry 再 superblock）会让「未挂载卷的 dentry 命中」泄漏结果 ——
与 ADR-195 那条「坏卷结果泄漏给好卷」是同一类错误。

## 决策 2：未挂载时**自动挂载**（幂等）

`open_node` 内部调 `sb_mount`。这不是「静默容忍」，而是「打开一个卷上的文件」
本身就隐含「这个卷被挂载了」。

`sb_mount` 是幂等的（ADR-217 决策 1），所以重复调用安全。

## 决策 3：`close_node` 不卸载 superblock

挂载是**卷级**状态，节点关闭不该影响它。
这与 POSIX 的 `iput` 不触发 `umount` 同一条思路。

## 判据九格（`t_three_layers`）

```
3l: 句柄=true sb=true inode=true vol=true 独立对账=true
    同路径同槽=true close=true 自动挂载=true 不同路径=true ⇒ true
```

## 本 ADR 最有价值的一课：**自证抓不到自己的错**

第一版的九格是「八格」，而且**负样本咬不动**。

我把 `open_node` 里的 `vol` 改成 `volume_fingerprint(...) ^ 0xDEAD`（故意算错），
跑出来：

```
3l: 句柄=true sb=true inode=true vol=true 同路径同槽=true close=true 自动挂载=true 不同路径=true ⇒ true
```

**八格全绿。**

原因：`node_consistent` 用的是「句柄里自己带的 `vol`」，去比对「superblock 里存的 `vol`」——
而 superblock 里的那个也是**同一个错误函数**算出来的。**两边都错，于是「一致」。**

这就是**自证**：用被测物自己的输出验证被测物。

### 修法：加第 9 格，用独立来源对账

```rust
let indep_vol = volume_fingerprint_pub(&disk, &bpb);  // 独立算一遍
let indep_ok = n.vol == indep_vol;
```

同一个负样本再跑：

```
3l: 卷指纹与独立来源不符 句柄=0x1d87c2001bc77eda 独立=0x1d87c2001bc7a077
3l: ... 独立对账=false ⇒ false
```

**抓住了。**

## 这条应当推广

AGENTS.md 已经写了「涉及硬件、存储、网络、签名的结论，要有宿主机侧的第二台仪器对账」。
本 ADR 把它推广到**任何判据**：

> **如果一个判据的所有输入都来自被测物自己，它证明不了任何东西。**
> 至少要有一格，其输入来自一条**独立于被测路径**的计算。

这在本会话里已经出现过三次同源问题：

| 位置 | 自证形态 | 独立对账 |
|---|---|---|
| ADR-195 dentry | 缓存键不带卷 | 判据喂两个卷 |
| ADR-219 页缓存 | 「命中」只看返回值 | `memdisk_read_calls()` 计数 |
| ADR-220 三层 | 句柄的 vol vs superblock 的 vol | `volume_fingerprint_pub` 独立算 |

## 读数

| 项 | 结果 |
|---|---|
| `check` | **21/21** |
| `handles,fs-ro` 档 | **`PASS(33)`**，`t_three_layers` 九格全绿 |

## 未决

1. **`open_node` 没有接进产品路径** —— `handle.rs` 仍走 `lookup` + 自己的句柄表
2. **没有 `i_op` / `f_op` 间接层** —— 仍按 FAT 硬编码
3. **dentry 不存 inode 号** —— 每次 `open_node` 仍要重算 `(vol, cluster)`
4. **没有 `VfsNode` 的生命周期管理** —— 泄漏一个就少一个 inode 引用
5. **单根挂载** —— 没有挂载点路径