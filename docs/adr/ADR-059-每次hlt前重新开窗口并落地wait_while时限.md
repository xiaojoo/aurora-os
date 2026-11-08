# ADR-059：每次 hlt 前重新开窗口（更正 ADR-057 决策 1），并落地 wait_while 的时限

状态：已采纳（2026-11-08，S1/W1 的 P6b；更正 ADR-057 决策 1 的"入口开一次、永不关"）
关联：ADR-057（idle/工人 hlt 化）、ADR-021（IF 属于 CPU）、ADR-058（定时器轮与 P6b 形状）、
ADR-053（放锁后切走）、BACKLOG 82（with_interrupts 不检测嵌套）、§131/§134

## 背景

P6b 的新用例 `t_wait_timeout` **确定性 HANG 3/3**，而 `t_sleep_until` 同时是过的。
QMP 现场把原因钉死：BSP 停在 `sched::idle_entry`，**`HLT=1` 而 `RFL=0x7`（IF=0）**——
halt 时中断是关的，永远醒不来，于是定时器轮永远没人扫，阻塞者永远等不到到期。

根因是 **ADR-057 决策 1 的形状有潜在缺陷**：idle/工人只在**入口**开一次窗口就"永不关"。
但窗口牌是 **per-CPU** 的，而 `apic::with_interrupts` 返回时**一律把牌置 false**（不恢复原值，
BACKLOG 82 早记过它不检测嵌套）。所以当 idle 不在 CPU 上时，任何调用 `with_interrupts`
的代码都会把牌关掉；idle 被换回来时 `context_load` 按牌供 IF ⇒ **IF=0 的 hlt** ⇒ 死停。
P6b 的用例正好调了 `apic::wait_ticks`（内部就是 `with_interrupts`），于是把它确定性触发出来。

**这意味着 P5 的 hlt 化当时是"过了自己的判据但带着潜在缺陷"**：P5 的用例没有在
idle  off-CPU 期间关牌的动作，所以没暴露。这条要如实记，不能因为 P5 矩阵全绿就当它没问题。

## 决策

1. **每次 `hlt` 之前重新开窗口**（`idle_entry` 与 `ap_worker` 都改），而不是入口开一次。
   这样无论被换回来时牌是什么状态，halt 那一刻 IF 必定为 1。
   "永不关"仍然成立（任务不退出），所以换入的下个任务按 ADR-021 由 `context_load` 供 IF，
   语义不变；变的只是**每次 halt 前自己把牌立起来**。
2. **不改 `with_interrupts` 的"返回即置 false"语义**。那会影响所有既有调用点与
   `t_if_belongs_to_cpu`/`t_if_patch_both_branches` 的判据，属 ADR-021 的范围，要另开 ADR。
   本轮让 halt 的一方自己去保证前提，代价最小、面最窄。
3. **P6b 按 ADR-058 决策 5/6 落地**：`WaitOps` 加 `timer_add`/`timer_del` 两个回调
   （`sync` 仍不引用 `sched`），新增 `wait_while_until(qid, cond, deadline) -> WaitOutcome`；
   等待槽与轮项**共用同一 token**，条件唤醒与到期唤醒谁先都认，后到者 `wake_task` 返回 false；
   持 WAITQ(5) 调 `timer_add` 取 TIMER(6)（方向已在锁序表里）；**放锁后**才 `yield_now`；
   醒来先摘两处注册再按 `cond()` 分 `Condition`/`TimedOut`。
   `timer_add` 失败时要把已标的 `Blocked` 自己改回去（调 `wake`），否则永久阻塞。
4. **无时限的 `wait_while` 保留不动**（既有调用者与判据不受影响）。

## 备选方案

- **修 `with_interrupts` 让它恢复原牌值**：拒绝（决策 2）。它是被广泛使用的原语，
  改语义要重验所有 IF 相关判据，属 ADR-021 的范围；本轮只在 halt 一侧保证前提。
- **idle 不用 hlt、退回自旋**：拒绝。那会把 P5 的成果退掉，而且自旋同样有
  "停表期间没人查 need 牌"的问题（ADR-057 已记），不是解法。
- **给 idle 一个私有 IF 状态、绕开 per-CPU 牌**：拒绝。那等于引入第二套 IF 归属，
  与 ADR-021 直接冲突。
- **`wait_while_until` 用两个 token（队列一个、轮一个）**：拒绝。任务只能带一个
  `Blocked(token)`，两个 token 就无法被 `wake_task` 同时认；共用一个是唯一自洽的形状。

## 影响

- 代码：`sched.rs`（`idle_entry` 每次 halt 前开窗口 + `timer_add_for_wait`/`timer_del_for_wait`
  + 装表）、`smp.rs`（`ap_worker` 同改）、`sync.rs`（`WaitOutcome`、两个回调、
  `wait_while_until`）、`ktests/sched.rs`（`t_wait_timeout` 两场景）。用例数 61 → **62**。
- **登记面零变化**：`WaitOutcome` 只被 ktest 引用（ADR-043/045 口径不进 `public_api`）；
  `WaitOps`/`install_wait_ops` 已登记；`RANK_TIMER` 与 5→6 的嵌套在 P6a 已进锁序表；
  无新增 unsafe。依赖图与环内站点数不变。
- **对 ADR-057 的更正**：决策 1 的"入口开一次、永不关"以本 ADR 决策 1 为准。
  ADR-057 原文不回改（已采纳 ADR 不追加修订），差异记在这里与 BACKLOG §134。

## 验收与负样本

- **正向（实测）**：默认档 **3/3 PASS、62/62**，
  `wait 时限(P6b): d≈63M 场景1=Ok(TimedOut) elapsed=66~99M 场景2=Ok(Condition) elapsed≈33M
  fired 1->2 残留=0` ⇒ 场景1 落在 `[d, d+2tick]`、场景2 提前返回且轮项被取消。
  P5 的 `t_idle_hlt_wakes` 仍绿（`bsp_hlt` 增量 1，≤4 的上界仍成立）。
- **MUTATION-T2（实测确定性）**：条件唤醒后不取消轮项 ⇒ `残留=1` → FAIL(35)。
- **MUTATION-T3（实测确定性）**：结局分类永远返回 `Condition` ⇒
  `场景1=Ok(Condition)`（应为 TimedOut）→ FAIL(35)。
- **MUTATION-T1（实测，不作为证据）**：把注册 deadline 改成 0（立刻到期）⇒ **HANG**，
  不是预期的红，所以**不拿它当精度格的证人**。精度格的证人是 P6a 的 MUTATION-T
  （同一条轮路径，`elapsed=1.1M ≪ d` ⇒ FAIL 35）。这条与 ADR-054 的"裸变异 A 未触发"
  同一口径：**没按预期咬的变异不算证据**。
- 三条变异还原后回到 PASS(33)。

## 迁移与回滚

- 回滚 P6b：删 `wait_while_until`/`WaitOutcome`/两个回调与用例；`wait_while` 不受影响。
- 回滚决策 1：把开窗口移回入口——**不建议**，那会把确定性 HANG 放回来。
- 迁移：任何将来新增的"halt 等待"路径都必须遵守"每次 halt 前自己立牌"，
  这条要写进 `lock-order.md`/ADR-021 的相关注记（本轮先在代码注释与本 ADR 里写明）。

## 未决

1. `with_interrupts` 不恢复原牌值这件事本身仍是隐患（BACKLOG 82），本轮绕开而非修复。
2. 轮槽 64 与等待槽 16×16 都仍无 workload 依据。
3. 异常出口取锁前应先查被中断上下文是否持锁（ADR-058 未决 3、§128 的 L4 级联），仍未做。
4. 真机/KVM 上 `[d, d+2tick]` 的余量与 P5 的两个 hlt 上界都要重测。
