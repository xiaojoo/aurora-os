# ADR-040：arch 与 sched 之间用回调表反转依赖（V1.0 §9.2 前置）

状态：已采纳（2026-11-07，V1.0 §2.2/§9.2；BACKLOG §92；Task A/B 冻结的 `arch -> sched` 违例）
关联：V1.0 §2.2（禁止 trap 依赖 user 业务实现）、§9.2 第一步之后、ADR-021（IF 归属）、
ADR-027（任务结束与资源回账）、ADR-039（依赖基线）

## 背景

Task A/B 的登记表冻结了一条 §2.2 明示禁止的反向依赖：`arch -> sched`。实际调用点是：

- `apic.rs` 的本地定时器 ISR：`crate::sched::mark_tick()`（两处）；
- `trap.rs` 的异常返回：`Action::Exit => crate::sched::exit_current(cpu)`，以及
  每次中断出口的 `crate::sched::preempt_point(frame, cpu)`；
- `smp.rs` 的 AP 启动：`sched::init_idle_task(...)`、`sched::spawn(ap_worker)`；
  AP 工人体内还直接读 `sched::current_id()` 与 `sched::WORK[me]`。

后果不是“代码不好看”，而是三件具体的事：
1. 任何按层拆 crate 的尝试都会把 `arch` 与 `sched` 绑成同一个 crate；
2. `arch` 的单元测试必须链接整个调度器；
3. 依赖矩阵只能把它记成 `known_violations`，无法真正消掉。

## 决策

新增中性模块 `kernel/src/hooks.rs`，只放一张 `SchedHooks` 函数表（不依赖 `sched`）：

```rust
pub struct SchedHooks {
    pub mark_tick: fn(),
    pub init_idle_task: fn(u64, u64, bool),
    pub spawn: fn(fn() -> !) -> Result<usize, crate::mm::MmError>,
    pub bump_current_work: fn(),
    pub exit_current: fn(usize),
    pub preempt_point: unsafe fn(u64, usize),
}
```

- `sched` 新增 `pub fn install_arch_hooks()` 与 `pub fn bump_current_work()`；
  前者在 `after_switch` 的最开头调用一次（早于 AP 释放与任何定时器窗口）。
- `arch` 的三处调用改成 `crate::hooks::sched().<field>(...)`；`arch` 源码里不再出现
  `sched::`（注释除外，门禁剥注释）。
- `hooks` 的默认表全是**安全桩**（no-op / `Err(Unsupported)`），安装前也能安全调用；
  安装发生在单核、关中断的启动早期，之后只读。`hooks.rs` 的 `UnsafeCell` 与 `Sync`
  按 U4 登记。
- AP 工人不再直接碰 `sched::WORK`，改调 `bump_current_work()`；工人本身仍由
  `sched::spawn` 创建，但入口经 hook 表传递。
- 不改任何调度/中断语义：`mark_tick`、`init_idle_task`、`spawn`、`exit_current`、
  `preempt_point` 的函数体与调用顺序保持原样；只是把“谁调用谁”反过来。

## 备选方案

- **保持现状**：拒绝。§2.2 明示禁止，且 14 模块环是拆 crate 的硬前置。
- **把回调注册进 sched 内部的静态函数指针**：拒绝。arch 仍要 `use crate::sched` 才能
  注册，依赖没有反转。
- **把 trap 的整个入口搬进 sched**：拒绝。范围过大，且会越过 ADR-021 的 IF/上下文边界。
- **只改 apic 的两处 mark_tick**：拒绝。trap 的 preempt_point/exit_current 与 smp 的
  AP 启动仍是反向边，登记表不会变绿。

## 影响

- `arch.dependencies` 去掉 `sched`；`arch.known_violations` 清空。
- 新增 `hooks` 模块（归入 `arch` 逻辑模块）；`sched -> arch` 依赖保持（服务层调用架构层，允许）。
- 热路径多一次函数指针间接调用（定时器 ISR 的 `mark_tick`、中断出口的 `preempt_point`）。
  这是本 ADR 的主要代价，必须用 bench 量：P1（切换）与 P5（ISR）的 min/mean 要贴出前后读数；
  若劣化超出噪声，先归因，不写成“无影响”。
- 14 模块强连通分量**可能不会因此缩小**（arch→memory→sched 等边仍能闭合环）。
  消环是后续 ADR 的事；本 ADR 只负责消除这一条 forbidden 边。
- 新增 U4 unsafe：`hooks.rs` 的 `UnsafeCell` / `Sync` / 读写。白名单与 census 同步。

## 验收与负样本

- `check` 16/16；`check-module-interfaces` 中 `arch.dependencies` 不含 `sched`、
  `arch.known_violations` 为空。
- 默认启动：抹掉数字后的串口行与改前**逐行同序、多重集差异 0**（不新增日志）。
- `test` 41/41；所有 feature 变体编译通过。
- bench：P1/P5 前后读数贴出；P4 `serial_bytes` 对照。
- 负样本：把 `install_arch_hooks()` 改成空实现（默认桩生效）⇒ 调度/AP/用例至少一处红；
  还原后绿。这证明 hook 不是没有调用者的空接口。
- 另做一次“只让 `mark_tick` 桩失效”的细化？若整表空实现的红已经点名到调度，
  不再重复造第二个同类负样本。

## 迁移与回滚

- 迁移是一次性接口反转，无数据格式变化；回滚只需恢复 `arch` 的三处直接调用与删除 `hooks`。
- 回滚后 `arch.known_violations` 要按 Task B 的流程重新登记（不能悄悄消失）。

## 未决

- 14 模块 SCC 里还有 `memory -> sched`、`boot -> sched` 等反向边；本 ADR 不处理。
- 间接调用对 P1/P5 的长期影响需要多轮 bench 才能定容忍度；本轮只给一次前后对照。
- `serial` 专属禁止项与“低层不得引用 main 测试函数”仍未机器化（Task B §1 欠账）。
