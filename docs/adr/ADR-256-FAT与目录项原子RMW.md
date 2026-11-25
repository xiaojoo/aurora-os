# ADR-256：FAT 项与目录项原子 RMW

状态：**已采纳**（2026-11-26）。关联：ADR-111（写方向）、ADR-177（文件族）、
ADR-254（块层原子 RMW）、BACKLOG §585。

## 背景

ADR-254 关闭了文件数据 Partial-sector 覆盖写的并发丢更新，但 FAT 项与目录项仍是
“读整扇区→改几字节→写整扇区”。两个 create/unlink 或 FAT 更新可在同一扇区交错，
后写者用旧副本覆盖前写者的邻居项。

## 决定

1. `fat_set_disk` 对每个 FAT 副本调用 `Block::read_modify_write`，只写 2 字节（FAT16）
   或 4 字节（FAT32）。FAT32 先读旧项，保留高 4 位，只替换低 28 位；两份 FAT 都写。
2. `create_in_dir` 找到空槽后直接对 32 字节目录项调用 RMW，不再先读整扇区。
3. `unlink_in_dir` 对目录项首字节的 `0xE5` 调用 1 字节 RMW；目录项先落盘、再释放簇链的
   顺序不变。
4. 元数据写后仍调用既有 `cache_invalidate()`；本 ADR 不改变页缓存或 dentry 缓存语义。
5. 负样本特性 `fault-metadata-rmw-split` 恢复三处旧拆分路径，测试盘在写前注入竞争修改，
   必须让 create/unlink/FAT 三格同时变红。

## 边界

- 只保证单扇区内的项更新原子性，不把“分配簇 + 改两份 FAT + 写目录项”提升为多步崩溃事务。
- 不支持原子 RMW 的块设备继续返回 `Refused`；virtio/NVMe 不宣称支持元数据写。
- 本轮发现 unlink 后 dentry 正缓存不会自动失效，`lookup` 仍可能返回已删项；归任务 #40，
  本 ADR 只用原始盘字节验证 unlink，不把该缺陷藏进 RMW 绿格。
- 真机未验证。

## 验收

| 场景 | 读数 |
|---|---|
| 正常路径 | `run-16325`：`create原子=true(32B) unlink原子=true(1B) FAT原子=true(2×4B)`，两份 FAT 均 `a1234567`，fs-ro **101/101** PASS |
| 旧拆分路径 | `run-16326`：三格同时 `原子=false`，`t_metadata_rmw_atomic` 精确 FAIL（101 条仅此 1 红） |
| 静态门禁 | `check` **21/21** |
| 完整矩阵 | 原始链 **81/82**；唯一 `sig-check` 红在两次 PIT 标定均 `WindowVsIntervals`，同 ELF `501b7f138c75` 单跑 `run-16415` PASS，记环境形状、不归因 |
