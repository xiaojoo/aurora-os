# ADR-057：idle 与 AP 工人改 hlt；判据必须能分辨 regime，而不是只判"跑过"

状态：已采纳（2026-11-08，S1/W1 的 P5）
关联：ADR-021（IF 属于 CPU）、ADR-024（per-CPU 与 TCG 读数边界）、ADR-047（W1 接口，T1.4）、
ADR-051/052（兜底 idle 与回落）、ADR-055（跨核 resched IPI）、ADR-044（站点棘轮）、BACKLOG 82/86

## 背景

只读准备修正了 P5 的范围：**AP 的空闲上下文早就在 hlt**（`smp.rs` 步骤 8/9：
`open_cpu_window` 之后 `loop { 查相位; hlt }`）。设计文档说的"AP 常驻自旋"指的是
`ap_worker` 这个**任务**，不是空闲上下文——两者不是一回事。真正剩下的自旋体只有两个：
`ap_worker()`（`loop { bump_current_work(); tsc::spin(3_000) }`）与 P3b-2 造的
`idle_entry()`（`loop { spin_loop() }`）。

## 决策

1. **两个都改成 hlt，并且自己开窗口、永不关**（任务不退出），与 AP 空闲上下文同一形状。
   **不用 `with_interrupts`**：它返回时把牌一律置 `false`（不恢复原值），在任务里用等于
   关掉别人开的窗口（BACKLOG 82 的嵌套隐患）。牌开着，换入的下个任务由 `context_load`
   按 ADR-021 供 IF，语义不变。
2. **不退掉 `ap_worker`**：它的 `WORK` 计数仍是 `t_percpu_queues` 的 `worked_aps` 证人。
   改成 hlt 就已经达成"不烧 CPU"的目标，同时保住证人 ⇒ **不需要换证人**
   （ADR-047/§113a 要求的"换证人"只在**退掉**它时才适用）。这比退掉它风险小得多。
3. **见证计数是内核自报，不是独立见证**：`sched::idle_hlt_count(cpu)`、
   `smp::ap_worker_hlt(cpu)`，由 `main.rs` 打一行供宿主机解析。
   **`-d int` 不记录 hlt，仓库里没有数它的仪器**（§97a 已实测确认），
   所以这条对账只能算"宿主机读懂了内核的自报数"，**不得宣称是独立见证**。
4. **判据必须能分辨 regime，不能只判 `> 0`**（本轮最重要的一条，实测打出来的）：
   第一版计数在 hlt **前一步**自增，于是把 hlt 换成 `spin_loop` 它照样涨——
   **两条变异都没咬**（H1 得 `bsp_hlt=133` 仍 PASS、H2 得 `halted=3` 仍 PASS）。
   它量的是"idle 跑过"，不是"idle 真的停住了"。改成上界判据：
   - BSP idle：`h1 > h0 && h1 - h0 <= 4`。实测真 hlt 增量 **1**，自旋版 **133/170**。
   - AP 工人：`loops > 0 && loops <= ticks_of(ap) * 32 + 64`。实测 hlt 版 **≈140**、
     ticks ≈40（约 3.5 倍）；自旋版 **≈120000~147000**（约 3000 倍）。
   两个上界都是**regime 分界**，不是性能 SLA（与 ADR-056 的慢轮比例同一口径）。
5. **新增 `t_idle_hlt_wakes` 把 BSP 的 idle 逼出来跑**：清场（本 CPU 只剩启动上下文与 idle）
   → 启动上下文在等待队列上阻塞 → `pick_next` 回落 idle → idle 进 hlt →
   AP 跨核唤醒发 IPI 把它叫醒。没有这一条，BSP idle 的 hlt 路径在整个用例链里
   **一次都不会执行**（实测 `bsp=0`），等于改了没验。
6. **AP 侧必须等"计数前进"而不是"current 换了人"**：`s.current = next` 写在 `context_load`
   **之前**，所以"换了人"那一刻 idle 可能还没跑；此时发 IPI，它会在 idle 刚 `sti` 时
   立刻被取走，idle 连第一条 hlt 都执行不到（实测 `idle_runs=1` 而 `bsp_hlt=0`）。
   等 `idle_hlt_count` 前进才是"它已经停在 hlt 上"的证人。

## 备选方案

- **退掉 `ap_worker` 并换证人**：拒绝（决策 2）。改 hlt 已达成目标，换证人要动
  `t_percpu_queues` 的论证面，风险更大而收益相同。
- **用 `with_interrupts(|| hlt)`**：拒绝，见决策 1（会关掉别人的窗口）。
- **判据只判计数 `> 0`**：拒绝，见决策 4（实测两条变异都不咬，是空判据）。
- **宣称宿主机对账是独立见证**：拒绝，见决策 3（没有仪器数 hlt）。
- **不造 `t_idle_hlt_wakes`**：拒绝，见决策 5（BSP idle 的 hlt 会一次都不执行）。

## 影响

- 代码：`sched.rs`（`idle_entry` 改 hlt + 计数与访问器）、`smp.rs`（`ap_worker` 改 hlt +
  计数与访问器）、`main.rs`（一行见证读数）、`ktests/sched.rs`
  （`halted_aps` 上界判据 + `t_idle_hlt_wakes`）。用例数 59 → **60**。
- **棘轮要求收紧一处**：`arch->time` 站点数 23 → **22**（`ap_worker` 不再调 `tsc::spin`）。
  这是**进度**，按 ADR-044 必须显式登记收紧，否则余量会被下一个人悄悄用掉。
- 登记面：`sched` U1 3→4、`arch/x86_64/smp` U1 4→5（两处 hlt asm），
  普查 total 293→295、U1 54→56；`public_api` +2（`sched::idle_hlt_count`、`smp::ap_worker_hlt`）。
- P1/P4 的绝对值从此才可解读（BACKLOG 86 的原话）：AP 不再常驻自旋抢宿主 CPU。
  但**本轮不引用任何耗时数字做结论**，那要 bench 四跑另行取证。

## 验收与负样本

- **正向（实测）**：默认档 **3/3 PASS、60/60**，
  `idle hlt(P5): bsp_hlt 0 -> 1 idle_runs=1 AP见到换人=3 被唤醒=true ack超时=0`、
  `percpu sched: … worked=3 halted=3 checked=3`、`idle hlt: bsp=1 ap=[145,146,120]`。
- **MUTATION-H1（实测确定性）**：`idle_entry` 退回 `spin_loop` ⇒ `bsp_hlt 0 -> 170`（>4）
  → `t_idle_hlt_wakes -> failed` → FAIL(35)。
- **MUTATION-H2（实测确定性）**：`ap_worker` 退回 `tsc::spin` ⇒ `halted=0`、
  `ap=[140947,126124,147210]` → `t_percpu_queues -> failed` → FAIL(35)。
- 两条还原后回到 PASS。**第一版判据下这两条变异都不咬**，那次的读数（133 / halted=3）
  留在 BACKLOG 作为"空判据"的证据。
- 过程中还实测到两个时序竞态，都由用例适配而不是改内核：
  AP 太早唤醒（赶在 `yield_now` 之前）⇒ 回落分支 0 次命中；
  AP 在 `current` 刚换人就发 IPI ⇒ idle 执行不到第一条 hlt。两者都是 ADR-053/052
  既有语义的**正确行为**，改用例的等待条件即可。

## 迁移与回滚

- 回滚：两处 hlt 改回自旋、删计数与访问器、删新用例与 `halted_aps` 判据，
  并把 `arch->time` 的登记放回 23、还原 census 与 `public_api`。
- 迁移：P6 的定时器轮落地后，idle 的唤醒源除了 tick/IPI 还会多了到期唤醒，
  两个上界（4 与 32×ticks）要重新测分布再定，不能直接沿用。

## 未决

1. **hlt 的独立见证仍然没有**：需要 QEMU 侧能数"进入 halted 状态"的通道
   （`-d int` 不行，`-trace` 是否有对应事件未查）。在找到之前，这一格只能算自报数被宿主机读懂。
2. `ap_worker` 若将来真要退掉，`worked_aps` 换证人仍是前置（ADR-047/§113a）。
3. 两个上界是 TCG 下测出来的 regime 分界；真机/KVM 上要重测（ADR-024 口径）。
