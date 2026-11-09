# ADR-072：shootdown 按 AS 位图收窄，内核半区改动仍全广播

状态：已采纳（2026-11-09，W3 P2；前置 P1/ADR-070 已交付）
关联：ADR-023（shootdown 协议）、ADR-070（AddressSpace / running_on 位图）、
ADR-044（棘轮）、BACKLOG §148/§149、手册 §6.6

## 背景

P1 交付了 `AddressSpace` 对象与 `aspace_switch`，但 shootdown 仍然全广播
（`shootdown_others` 通知所有在线 CPU）。多 AS 之后，用户半区的 unmap 只需要通知
**曾跑过该 AS 的 CPU**——其它 CPU 的 TLB 里根本没有那个 AS 的条目，通知它们是浪费。
内核半区（HHDM、内核镜像）在所有 AS 里共享，改动仍须全广播。

`SD_VA` 今天由 VMM 锁串行化（所有 unmap 都持 VMM），**不是并发 bug**。
将来若引入 per-AS VMM 锁才需要多槽；本轮不改它，只记"今天安全的原因"。

## 决策

1. **`AspaceEntry.running_on: u8`**（cpumask，bit i = CPU i 曾切入过该 AS）。
   - **登记**：`aspace_switch(pml4, me)` 写 CR3 成功后，把 `me` 位 OR 进去。
   - **不摘**：换走时不清（ADR-070 决策 5②：摘除要证明"不再有该 AS 的 TLB 条目"，TCG 观测不到）。
     位图只会保守偏大，通知多余是安全的。
   - **销毁清零**：`aspace_release` 把表项置 `AS_EMPTY`（`running_on: 0`）。
     P1 的用户半区为空，所以"按位图逐 CPU 冲刷"今天是 no-op；P4 有映射后该路径才真走。
2. **`shootdown_inner(va, mask: Option<u8>)`**：原 `shootdown_others` 重命名为公共实现，
   `None` = 全广播（原行为），`Some(m)` = 只通知位图里的在线 CPU（除自己）。
   两个 wrapper：`shootdown_others(va)` 调 `None`；`shootdown_masked(va, mask)` 调 `Some`。
   **架构引用全在 `shootdown_inner` 里**（与原来的 `shootdown_others` 同一批行），
   wrapper 零新增站点 ⇒ 棘轮 `memory->arch` 仍 64。
3. **`aspace_switch` 签名加 `me: usize`**（调用方传 CPU 槽号）。
   理由：避免在 mm.rs 新增 `crate::arch::` 引用行撞棘轮。
   登记用 `1u8.checked_shl(me as u32)`（u8 宽度 = MAX_CPUS = 8），零 arch:: 引用。
4. **见证**：`aspace_running_on(slot) -> Option<u8>`、`aspace_register_cpu(slot, cpu) -> Option<u8>`
   （用例专用：模拟"那颗 CPU 也曾跑过"）。
5. **内核半区 / HHDM 改动仍走 `shootdown_others`（全广播）**，不走 `shootdown_masked`。
   今天内核半区已冻结（ADR-070 决策 2），所以没有运行期内核半区 shootdown；
   这条规则是写给将来"冻结解除"那天用的。
6. **SD_VA 不改**：VMM 锁串行化所有请求方，单槽今天安全。记为"不是 bug，是前提"。

## 备选方案

- **在 `aspace_switch` 里直接调 `cpu::self_slot()`**：拒绝（+1 arch:: 站点撞棘轮）。
  改用参数传入 + `checked_shl`。
- **新开 `shootdown_masked` 函数独立写一遍 IPI 逻辑**：拒绝（重复代码 + 新增 arch:: 站点）。
  改用 wrapper + 公共实现。
- **换走时摘除位图**：拒绝（ADR-070 决策 5② 原文）。
- **SD_VA 改多槽**：拒绝（今天 VMM 串行化，不是 bug；改了反而引入"哪个槽给哪个请求"的新复杂度）。

## 影响

- 代码：`mm.rs`（`running_on` 字段 + 登记 + `shootdown_inner` 重构 + 两个 wrapper + 见证）、
  `ktests/mm.rs`（P1 用例签名更新 + 新用例 `t_shootdown_masked`）。
- 用例数 73 → **74**；unsafe 334 → **336**（ktests/mm U6 +2：两个 `unsafe` 调用）。
- 登记面：`public_api` 不变（新 pub 符号只被 ktests 引用，不构成产品路径引用边）；
  棘轮 `memory->arch` **仍 64**（wrapper 零站点 + `checked_shl` 零 arch::）。
- 负面：位图保守偏大 ⇒ 通知多余（安全但浪费）；真机上要量"多余通知"的频率。

## 验收与负样本

**正向**（`build/_p2-serial1.log:685`，74/74、PASS/33）：
`sd-mask(P2): 登记=true 位图=0x3 narrowed_ack=[0, 1, 0, 0, 0, 0, 0, 0] broadcast_ack=[0, 1, 1, 1, 0, 0, 0, 0] 在线AP=3 销毁后位图=None`

| 格 | 判据 | 读数 |
| --- | --- | --- |
| ① | 切入后位图含 BSP | `登记=true 位图=0x3`（BSP+AP1） |
| ② | narrowed 只通知位图里的 CPU（除 self） | `narrowed_ack=[0,1,0,0,…]`（只 AP1） |
| ③ | broadcast 通知全在线 | `broadcast_ack=[0,1,1,1,…]`（3 AP 各 +1） |
| ④ | 销毁后位图清零 | `销毁后位图=None`（槽已清） |

**MUTATION-P2**：`shootdown_masked` 忽略 mask、调 `shootdown_inner(va, None)` ⇒
② 的 ack 增量变成 [0,1,1,1,…]（与③相同）⇒ `narrowed_ok=false` ⇒ 红。

## 迁移与回滚

- 回滚：删 `running_on` 字段、`shootdown_masked` wrapper、见证函数；
  `shootdown_inner` 改回 `shootdown_others`（删 mask 参数）；用例签名还原。
- 迁移：P4 的 `aspace_map`/`unmap` 路径在用户半区 unmap 时调 `shootdown_masked(va, running_on)`；
  内核半区 / HHDM 仍调 `shootdown_others`。

## 未决

1. 位图保守偏大的代价（多余 IPI）在真机上要量。
2. `AS_PT_SLOTS=16` 在 P4 真铺映射时不够（最坏 769），届时要重定。
3. per-AS VMM 锁引入那天，SD_VA 要改多槽（今天不是 bug）。
4. TCG 观测不到 TLB 陈旧性 ⇒ 收窄的正确性只能验协议计数，不能验效应（ADR-023 原文）。
