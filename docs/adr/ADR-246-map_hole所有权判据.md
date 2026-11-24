# ADR-246：map_hole 往返判据改为本次映射的所有权直查

状态：**已采纳**（2026-11-24）。纯测试判据更正，产品代码未改。

关联：ADR-066（map_hole）、ADR-178/179（计数与布局取证）、BACKLOG §568。

## 问题

`t_map_hole` 旧判据用全局 `reservation_count` 与 `free_frames` 的基线差判断往返。
AP 工人在窗口内并发分配/释放时，这两个全局量会被无关任务推动，产生假红。

实际红跑 `run-12198`：

    reservation 17 -> 13 -> 12
    free_frames 97445 -> 97453
    a保留+1=false b回基线=false c帧回=false d已解映=true

保留数先下降 4、再下降 5，页框增加 8；这不是 `map_hole` 漏资源，而是其他上下文
在同一窗口内完成了多次分配与回收。旧判据把全局噪声误记成自身回滚失败。

## 决策

只核对本次 `MmioMapping` 的所有权链：

1. 映射建成后，`mm::is_reserved(va.0)` 必须为真；
2. drop 后，同一 base 的保留必须消失；
3. drop 后，`mm::leaf_value(va.0)` 必须为 `None`；
4. drop 后，`mm::is_mapped(va.0)` 必须为假。

不再用全局页框/保留计数作往返判据。它们仍可作为诊断读数，但不参与判定。

这不是放宽：新判据直接验证“这次分配的 VA 登记和页表叶子是否交还”，比全局差值
更具体，也不会被其他任务的分配掩盖或误伤。

## 负样本

只删除 `MmioMapping::drop` 中的 `release_va_locked(self.virt.0)`，默认档得到：

    a已登记=true b已放手=false c叶已清=true d未映射=true

`run-12232` 的 `t_map_hole` 精确变红。还原后同一判据恢复通过。

## 实测

| 项 | 读数 |
|---|---|
| 新判据 handles 重复采样 | **32/32** 个 map_hole 读数全绿 |
| 默认档 | `run-12233` PASS |
| handles 档 | `run-12234` PASS |
| `check` | **21/21** |

## 未决

- 全局计数仍会被并发分配推动，其他使用全局基线差的用例需要按同一原则审查。
- 本轮没有改 `map_hole` 产品实现，也没有改变锁序或资源释放语义。
