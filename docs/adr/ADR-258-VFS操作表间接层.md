# ADR-258：VFS i_op/f_op 间接层

状态：**已采纳**（2026-11-26）。关联：ADR-107（薄 VFS）、ADR-111（写）、
ADR-189（大句柄槽）、ADR-220/252（产品节点）、ADR-250（产品页缓存）、BACKLOG §587。

## 背景

`ReadOnlyFs::open/read/seek` 与产品句柄的 read/seek/write 都直接调用 FAT 自由函数。
FAT 解析、游标提交、页缓存与写路径已经各自有判据，但“产品调用必须经过哪组操作”
没有可机读的接缝；将来增加第二种文件系统时只能继续散落分支。

## 决定

1. 在 `vfs_ro` 内新增 crate 私有的 `InodeOps` 与 `FileOps`。`InodeOps` 负责
   `open_file`；`FileOps` 负责 `read/read_cached/seek`，`fs-rw` 下增加 `write`。
   今天只有 `FatInodeOps/FatFileOps` 两个零大小实现，不宣称已经支持第二种文件系统。
2. `ReadOnlyFs` 保存 `&'static dyn InodeOps`；`ReadCursor` 保存
   `&'static dyn FileOps`。产品 open 经 i_op，产品句柄 read/seek/write 经 f_op。
   错误类型、锁外 I/O、游标失败不提交、页缓存与原子 RMW 语义均不改变。
3. 旧自由函数保留给 exec 与既有测试；`open` 也经 FAT i_op，避免旧入口再造一份构造逻辑。
   不新增公开 ABI、syscall、锁、unsafe 或模块依赖边。
4. 五格原子计数 `(i_open, f_read, f_cached, f_write, f_seek)` 只作取证，不参与权限、
   错误或游标判定。测试可装入自定义 i_op/f_op：返回值与调用数必须改变，证明走的是
   trait-object 分派而不只是 FAT 计数。`ReadCursor` 实测 136 字节；容量文档保留 ADR-189
   的 760 字节历史读数，当前句柄槽实测 `len=16384 pages=3200`，即 800 字节/槽，
   `MAX_HANDLES=16384` 不变（131072 槽为 100 MiB，16384 槽为 12.5 MiB）。
5. `fault-vfs-ops-bypass` 改调旧自由函数，计数必须归零；`fault-vfs-ops-static`
   直接调 FAT 操作实现，计数与字节仍正确，但自定义操作表探针必须失败。

## 验收

| 场景 | 读数 |
|---|---|
| i_op/f_op 分派 | `run-16574`：`cursor=136 i_open=1 f_read=1 f_cached=1 f_write=0 f_seek=1 字节同=true 间接=true`，fs-ro **104/104** PASS |
| 产品句柄读/seek | `run-16576`：`f_op=true`，fs-open **166/166** PASS |
| 产品 open 的 i_op | `run-16576`：`open=true i_op=true`，节点生命周期全绿 |
| 产品句柄写 | `run-16577`：`写4=4 f_op=true 内容对=true`，fs-rw **170/170** PASS |
| 绕过 VFS 操作表 | `run-16578`：计数 `0/0/1/0/0 间接=false`，104 条仅 `t_vfs_ops_dispatch` FAIL |
| 绕过产品操作表 | `run-16579`：166 条仅 `t_vfs_ops_dispatch`、`t_fs_open_dup_shared`、`t_fs_open_node_lifecycle` FAIL；`run-16580`：170 条仅这三格与 `t_fs_rw_syscall23` FAIL |
| 静态直调 FAT | `run-16575`：计数 `1/1/1/0/1 字节同=true 间接=false`，104 条仅 `t_vfs_ops_dispatch` FAIL；`run-16581` 在 fs-rw 下同样仅该格 FAIL，覆盖 write 分派 |
| 静态门禁 | `check` **21/21** |
| 完整矩阵 | **82/82 符合**，`AURORA_MATRIX_DONE rc=0` |

## 边界

- 间接层目前是真实调用接缝，不是可注册文件系统框架；没有虚构第二实现或空方法。
- 操作表指针是 `'static` 零大小 FAT 实现，不增加堆分配或生命周期管理。
- dentry 仍只保存 inode 槽提示，未内嵌完整 inode 对象。
- 真机未验证；AOCI MCP 本片不可用，索引未更新。
