# ADR-257：dentry 内嵌 inode 身份与目录失效

状态：**已采纳**（2026-11-26）。关联：ADR-195（dentry）、ADR-216（inode）、
ADR-220/252（三层与产品节点）、ADR-256（目录项 RMW）、BACKLOG §586。

## 背景

dentry 缓存只保存 `Entry`，每次 `open_node` 都重新按 `(vol, cluster)` 调 `inode_get`；
产品 open 又每次显式挂载并清空 dentry，缓存提示活不到第二次 open。create/unlink 后
正 dentry 不失效，已删文件仍可被 lookup 命中。

## 决定

1. `DentrySlot` 保存 `inode_slot` 提示（`u32::MAX` = 未绑定）。提示不持引用；open 时
   `inode_get_at(slot, vol, cluster, size, attr)` 在锁内校验 `used/vol/cluster`、更新元数据、
   增加引用。槽被淘汰或复用则回退 `inode_get` 并重绑。
2. `inode_get` 命中时同步更新 size/attr；bare lookup 仍不使用缓存。
3. 新增 `ReadOnlyFs::mount_cached`：同一已挂载卷的后续产品 open 复用 dentry/page cache；
   显式 `mount` 仍清空，保留 ADR-195 的“换卷/坏卷必须清缓存”契约。产品
   `fs_open::open` 与 `open_node_product` 改走 `mount_cached`。
4. create/unlink 成功后失效整个 `(vol, parent_cluster)` 目录，覆盖大小写与长短名别名。
   dentry 增加 `generation`：miss 读盘期间目录已失效时，旧解析结果不得回填；连续四次
   竞争仍失败则保守返回 `NotFound`，不无界重试。
5. 不新增 rename 空壳：当前 VFS 没有 rename 调用点。i_op/f_op 与 dentry 内嵌完整 inode
   对象仍是任务 #39/#40 的后续设计，不在本 ADR 假装交付。

## 验收

| 场景 | 读数 |
|---|---|
| 槽提示与引用 | `run-16434`：`复用=true refs=true/true/true inode命中=0->1 异键占槽=true 槽校验=true`，fs-ro **103/103** PASS |
| 产品二次 open | `run-16422`：`产品复用=true refs=true`，fs-open **164/164** PASS |
| unlink 大小写别名 | `run-16434`：`别名=true 删后查无=true/true` |
| 读中删除的旧 miss | `run-16434`：`读中删除=true 结果=Err(NotFound)`；`run-16435` 关闭 generation 后返回旧 `Ok(Entry)`，`t_dentry_generation_race` 精确 FAIL |
| 关闭目录失效 | `run-16420`：`删后查无=false/false`，`t_dentry_inode_link` 精确 FAIL（103 条仅此 1 红） |
| 关闭槽校验 | `run-16421`：`复用=false refs=true/false/true 槽校验=false`，同一用例精确 FAIL（103 条仅此 1 红） |
| 静态门禁 | `check` **21/21** |
| 完整矩阵 | 原始链 **81/82**；唯一 `FS写方向` 红在同跑 `t_sdkdemo` 的 `0x100002000` 未映射，同 ELF `e05e3c3dc3bd` 单跑 `run-16524` PASS，记环境形状、不归因 |

## 边界

- dentry 提示不是 inode 引用；生命周期仍由 `VfsNode`/handle 的 `inode_get_at` 与
  `close_node` 平衡。
- 目录失效按父簇整组清除，代价是丢弃该目录的热项；容量只有 64，收益高于按名字精确删。
- generation 只防旧 miss 回填，不把多步目录操作变成事务。
- 真机未验证；AOCI MCP 本片不可用，索引未更新。
