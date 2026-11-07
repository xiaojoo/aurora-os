# ADR-041：VA 保留容量归 memory，调度器用编译期断言适配

状态：已采纳（2026-11-08，V1.0 §2.2/§9.2；ADR-040 之后）
关联：ADR-039（依赖基线）、ADR-040（arch↔sched 回调表）、ADR-018（堆上限与可失败分配）、
V1.0 §3.3（Memory 拥有 VA 保留表）、§3.4（Scheduler 拥有任务槽）

## 背景

`arch -> sched` 消掉后，依赖图里还剩 `memory -> sched`。实际调用点只有一处，而且是**编译期**
的：

```rust
// mm.rs
const MAX_VA_RESERVATIONS: usize =
    crate::arch::x86_64::cpu::MAX_CPUS * crate::sched::MAX_TASKS + 16;
```

`MAX_VA_RESERVATIONS` 是 VA 保留表的静态容量；`sched::MAX_TASKS` 是每 CPU 运行队列的任务槽数。
两者相乘再加 16 条固定用途，是这个表的最坏需求。问题不在于“多一个间接调用”，而在于
**memory 为了知道自己的表多大，必须依赖调度器的策略常量**：调度器改槽数，内存层的静态数组
大小跟着变；而按 V1.0 §3.3，VA 保留表是 memory 拥有的状态，容量应由 memory 决定。

`boot -> sched` 经核查**不存在**：boot 的依赖是 diagnostics/sync；环里经过 boot 的路径是
`sched -> boot -> diagnostics -> sched`，不是 boot 直接调 sched。

## 决策

1. memory 新增 `pub const MAX_TASKS_SUPPORTED: usize = 8;`，并用自己的常量定义
   `MAX_VA_RESERVATIONS = MAX_CPUS * MAX_TASKS_SUPPORTED + 16`。VA 容量由 memory 拥有。
2. sched 保留 `MAX_TASKS`（调度策略归 sched），并加一条编译期断言：

   ```rust
   const _: () = assert!(MAX_TASKS <= crate::mm::MAX_TASKS_SUPPORTED);
   ```

   调度器要扩槽，必须同时把 memory 的容量抬上去；漏改会在编译期红，而不是运行时越界。
3. 不引入新的运行时 hook，也不新增 `limits` 模块：这里要消的是**所有权倒置**，不是调用倒置。
   一个常量不值得一个新模块；双方用“容量 + 断言”表达契约更直接。

## 备选方案

- **新建 `limits` 中性模块**：拒绝。只有一个常量、两个调用者，新增模块会让依赖图多两个节点，
  而契约可以用 const 断言表达得更紧。
- **mm 里复制一个 8，不写断言**：拒绝。复制会漂移；断言把“改一处必须改另一处”变成编译器的事。
- **把容量改成运行时分配**：拒绝。VA 保留表是静态数组，当前阶段不引入动态表（ADR-039 的
  接口登记里也把 `MAX_VA_RESERVATIONS` 视为固定容量）。
- **把 `MAX_TASKS` 搬进 memory**：拒绝。任务槽是调度器策略；memory 不该定义调度容量。

## 影响

- `memory.dependencies` 去掉 `sched`；`sched -> memory` 保留（调度器使用内存接口，允许）。
- 14 模块 SCC **可能仍不缩小**：`memory -> diagnostics -> sched -> memory` 仍闭合；
  本 ADR 只消这一条直接边。
- 新增一个 `pub const`（`mm::MAX_TASKS_SUPPORTED`），登记进 module-interfaces 的 public_api。
- 无运行时行为变化；默认/矩阵/日志应逐行不变。

## 验收与负样本

- `check` 16/16；`memory.dependencies` 不含 `sched`，`memory.known_violations` 为空。
- 默认启动日志抹数字后与改前**逐行同序、多重集差异 0**；`test` 41/41；默认 53/53。
- 负样本：把 `mm::MAX_TASKS_SUPPORTED` 改成 7（< sched 的 8）⇒ `const _: () = assert!(...)`
  编译失败；还原后构建通过。这证明契约不是注释，而是编译器强制的。
- 另一条由既有门禁覆盖：若有人在 mm 里重新写 `sched::MAX_TASKS`，
  `check-module-interfaces` 会把 `memory.dependencies` 对不上点名。

## 迁移与回滚

- 无数据/ABI 迁移；回滚只需把容量公式改回 `sched::MAX_TASKS` 并删断言。
- 回滚后 `memory -> sched` 会重新出现在依赖门禁里，必须按 Task B 流程登记。

## 未决

- 14 模块 SCC 的其它环边（`memory -> diagnostics -> sched`、`sched -> boot -> diagnostics` 等）
  不在本 ADR 范围。
- `MAX_TASKS_SUPPORTED = 8` 与 `MAX_CPUS = 8` 都是当前固定值；未来动态化需要新的容量模型。
