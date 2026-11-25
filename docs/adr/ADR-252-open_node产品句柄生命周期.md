# ADR-252：open_node 产品句柄生命周期

状态：**已采纳**（2026-11-25：加法接入，不改变旧 `fs_open::open` 与 exec 路径）

关联：ADR-108（VFS 句柄）、ADR-114（挂载表）、ADR-216（inode 引用）、ADR-220（三层联动）

## 背景

ADR-220 的 `open_node` 已走完 superblock → dentry → inode，但只返回 `VfsNode`，产品
`file_open` 仍走 `ReadOnlyFs::lookup + open`，随后手工算卷指纹并 grant。结果是 inode 层没有
真实产品调用者，也没有生命周期管理。

## 决策 1：一次解析同时返回节点与 Entry

新增 `open_node_entry(disk, bpb, path, readonly) -> Result<(VfsNode, Entry), NodeError>`；
`open_node` 变为它的薄包装。产品不再二次 lookup，dentry 与 inode 来自同一次解析。

`fs_open` 增加 `OpenedNode` 与 `open_node_product`，旧 `Opened` / `open` 保留给 exec 与既有测试。
节点后的游标/DirState 构造失败必须 `close_node`，不能留下 inode 引用。

## 决策 2：节点引用归 open-file-description

`VfsFile` / `VfsDir` 增加 `node: Option<VfsNode>`；目录增加 `share`。共享 cell 同时保存
游标（文件）与节点引用。第一次 `dup` 时建立 cell，之后所有名字共享同一份 inode 引用：

- `dup` 不再调用 `inode_get`；
- 关闭一条名字只减 cell 引用；
- 最后一个名字关闭时才 `close_node` 一次；
- `revoke_task` / `reset_for_test` 也按同一规则归还，不能留下孤儿 inode。

关闭与撤销时，HANDLE 锁内只摘下对象/更新 cell；`close_node` 在锁外调用。批量撤销用
`INODE_MAX` 个 `(node, count)` 槽去重收集，计数最多 `MAX_HANDLES`，栈数组不随容量线性增长。

## 决策 3：产品授句柄失败必须回滚

`file_open` 使用 `grant_vfs_file_node` / `grant_vfs_dir_node`。若句柄表满，调用方立即
`close_node`；成功则由句柄生命周期接管。旧无节点 grant API 保留给既有测试。

## 判据与负样本

- 产品 `file_open` 后 inode refs 精确加一，node_consistent 为真，卷指纹有独立对账；
- `dup` 两次关闭：第一条 refs 不变，最后一条 refs 减一；
- `revoke_task` 撤共享名字后 refs 归零，reset 后无残留；
- 授句柄失败/游标构造失败不增加 refs；
- 不同卷同簇不串；
- 变异：产品 open 绕过 open_node、最后一次 close 不 put、dup 重复 iget、grant 失败不 close，
  分别定点红。

## 验证读数

| 场景 | 结果 |
|---|---|
| `handles,fs-open` | **160/160**，`run-14753`，ELF `69a10f03c01d…` |
| `fs-rw` | **164/164**，`run-14703`，ELF `ccd3f039dced…` |
| 默认 / handles | **92/92 / 132/132** |
| `check` | **22/22** |
| 完整矩阵 | **82/82 符合**，退出码 0 |

六次定点变异分别红在：末关 `refs=1`、dup 重复 `inode_get`、满表 grant 后
`refs=Some(1)`、reset 后 `reset=false`、产品 open 未持节点、syscall 退回旧路径后
`refs1=false` 且满表 `refs=None`。第一次完整矩阵暴露非 `fs-open` 档仍引用 `VfsNode`
的编译错误；用 cfg 类型别名隔离节点载荷后，handles 单跑与最终矩阵均通过。

## 未决

1. `i_op` / `f_op` 间接层仍未引入，本 ADR 只接现有 FAT 操作。
2. dentry 仍不直接存 inode 号，每次 open 重算 `(vol, cluster)`。
3. 单根/多挂载的 superblock refs 生命周期仍按 ADR-220/217，节点关闭不卸载。
