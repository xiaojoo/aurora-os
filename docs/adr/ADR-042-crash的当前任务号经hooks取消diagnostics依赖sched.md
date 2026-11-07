# ADR-042：crash 的当前任务号经 hooks 取，消 diagnostics→sched

状态：已采纳（2026-11-08，V1.0 §2.2/§9.2；ADR-040/041 之后）
关联：ADR-039（依赖基线）、ADR-040（hooks 表）、ADR-041（memory→sched）、
V1.0 §3.10（Diagnostics 不得依赖业务模块私有结构）、§3.4（Scheduler 拥有当前任务）

## 背景

ADR-040/041 之后，依赖图里还剩一条 `diagnostics -> sched` 的直接边，实际调用点只有一处：

```rust
// crash.rs
thread_id: crate::sched::current_id() as u32,
```

崩溃记录需要“出事时是哪个任务”。但按 V1.0 §3.10，Diagnostics 属于 core，不得依赖
Scheduler 的业务实现；按 §3.4，“当前任务”归 Scheduler 拥有，外部只能通过受控接口读。
这条边不是 forbidden_dependencies 里明示的一条，但它是 core→service 的反向依赖，属于
14 模块环的一部分。

## 决策

1. `SchedHooks` 增加 `current_id: fn() -> usize`；默认桩返回 0。
2. `sched::install_arch_hooks()` 安装 `current_id`。
3. `crash.rs` 改成 `(crate::hooks::sched().current_id)()`。
4. 不改崩溃记录格式，也不改 `thread_id` 的取值语义：安装后仍是同一个 `current_id()`。
5. 负样本用既有依赖门禁：若有人在 crash.rs 里重新写 `crate::sched::current_id()`，
   `check-module-interfaces` 会点名 `diagnostics.dependencies` 多出 `sched` 并变红。

## 备选方案

- **把 thread_id 作为参数传给 crash::record**：拒绝。会改所有调用点（panic/异常/软锁死），
  而当前只有一个记录点需要它；hooks 更小。
- **在 neutral 静态里缓存当前任务号**：拒绝。多一个可变全局与一份同步协议；hooks 已是
  sched→arch 的单向发布。
- **保持现状**：拒绝。core→service 反向依赖，拆 crate 时会把 sched 拖进 diagnostics。

## 影响

- `diagnostics.dependencies` 去掉 `sched`；`diagnostics -> arch` 已存在（hooks 归 arch）。
- SCC：可能与 ADR-040/041 一起把 diagnostics 移出 14 模块环；以重算后的
  `[baseline].known_scc` 为准。若环缩小，在本轮显式更新基线并记录。
- 无运行时行为变化（同一次 `current_id()` 读取，只是多一次函数指针间接调用）；
  crash 记录字段与格式不变。
- 不新增 unsafe。

## 验收与负样本

- `check` 16/16；`diagnostics.dependencies` 不含 `sched`。
- 默认启动日志抹数字后与改前逐行相同；`test` 41/41；默认 53/53。
- 负样本：在 `crash.rs` 临时写回 `crate::sched::current_id()` ⇒ `check-interface` 报
  `diagnostics.dependencies` 不符；还原后绿。
- `thread_id` 没有独立判据（这条字段目前只被记录、不被用例比较）；不把它写成“已验证的语义”。

## 迁移与回滚

- 无数据格式迁移；回滚只需把 crash 的一行改回直接调用并删 hook 字段。
- 回滚后 `diagnostics -> sched` 会重新出现在门禁里，按 Task B 流程登记。

## 未决

- 剩余环边：`sched -> boot`（user.rs 的 Safe 模式检查）、`sched -> storage`
  （user.rs 从盘装载）仍需单独 ADR。
- `thread_id` 目前没有判据，是否要加一条（崩溃记录的 thread_id 与同跑当前任务对账）未定。
