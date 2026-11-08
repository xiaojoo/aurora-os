# ADR-058：每 CPU 定时器轮放 sched、RANK_TIMER=6、扫轮必须在 need 闸之后

状态：已采纳（2026-11-08，S1/W1 的 P6a）
关联：ADR-047（W1 决策 7：定时器轮与 sleep）、ADR-053（放锁后切走）、ADR-044（棘轮）、
ADR-021（IF 属于 CPU）、ADR-024（两本 tick 账不许混）、ADR-036（有界等待）、
`docs/architecture/lock-order.md`、BACKLOG 66/67/87

## 背景

`wait_while` 今天没有时限参数，因为**阻塞期间没有东西能按时叫醒它**（ADR-054 未决 2）：
"卡住"只能由调用方的有界让出发现。要有 `sleep_until` 与真正的超时，就得有每 CPU 的定时器轮。
落地前有三个结构问题必须先定：轮放哪个模块、用什么锁等级、在哪个位置扫。

## 决策

1. **轮放 `sched`，不放 `time`**：轮到点要叫醒任务。放 `time` 就新增 `time -> sched` 边，
   而 `time` 在环 A 内、`sched` 是环外单点 ⇒ 会把 `sched` 拉进强连通分量，
   SCC 闸与 ADR-044 棘轮同时红。放 `sched` 只用到已有的 `sched -> sync`（锁）与
   `sched -> time`（TSC）边，**依赖图不变**。
2. **`RANK_TIMER = 6`**，夹在 `WAITQ(5)` 与 `RUNQ(8)` 之间，因为两个方向都要嵌套它：
   `wait_while` 持 WAITQ 注册到期项（5→6，P6b）、tick 扫轮持 TIMER 叫醒要取 RUNQ（6→8）。
   0 是"没持锁"哨兵、5/8 已占，1..9 里只剩 6/7/9，取 6 给两侧留余地。
   `lock-order.md` 同轮加行（硬约束 4：先改表再改代码）。
3. **轮用 `IrqSpinLock<Wheel>`，不再包 UnsafeCell**：`Wheel` 全是普通数据 ⇒ `Send` ⇒
   锁自动 `Sync`。所以本轮**零新增 unsafe 站点**（与 `RoleCell`/`OpsCell` 那种
   "必须包 UnsafeCell + 显式 Sync"的形状不同，少三处 U4）。
4. **扫轮必须在 `need` 闸之后**（本轮最重要的一条，实测打出来的）：
   第一版放在闸之前，于是**每次异常出口**都扫轮，包括**持 VMM(20) 时发生的同步 #PF**
   ⇒ `L4 sync: 锁序违规，外层 rank=20 本次 rank=6`，**3/3 判定 39**。
   移到闸之后：`need` 只由 tick / resched IPI 立，而那些只在 IF=1 时被取走 ⇒
   被中断的上下文不可能持着锁。既有的 RUNQ 取锁本来就在闸之后，所以以前没暴露这个问题。
5. **`sleep_until` 放锁后再切走**（ADR-053 决策 2）：注册与标 Blocked 各在自己的锁内完成，
   放掉后才 `yield_now()`。返回值区分两种醒来：条目已被轮摘掉 ⇒ **到期**（true）；
   条目还在 ⇒ 被别人提前叫醒，自己摘掉并回 false。
6. **保留队列号 `TIMER_QID = u8::MAX`**：不与任何 `WaitQueue`（0..15）冲突，
   所以定时器的世代号不会被误当成某个等待队列的唤醒（`wake_task` 按 token 匹配）。
7. **容量 `WHEEL_SLOTS = 64` 是上限**，不是 workload 钉出来的（与 ADR-054 的 16×16 同一口径）；
   槽满时 `sleep_until` 回 false，**不阻塞**，调用方必须处理。
8. **精度判据按被睡 CPU 自己的 tick 源**：`[d, d+2 tick]`，tick 取标定值
   （`clock::current().tick_period_cycles`，未标定则用 `max_tick_period_cycles()` 保守上界）。
   BSP 的 tick 来自 PIT→IOAPIC 向量 32、AP 来自本地 LAPIC 0xF1，**两本账不许混**
   （`watchdog.rs` 与 ADR-024 的既有口径），所以用例 **BSP 与 AP 各测一档**。
9. **用例必须自足于时钟状态**：`.ktests` 顺序由链接器定，前面的用例可能把表停了。
   不保证就直接 **HANG 3/3**（实测）。所以用例先量"进来时心跳有没有在走"，
   不在走就开表，收尾按原样放回（`t_watchdog` 的既有做法）。

## 备选方案

- **轮放 `time`**：拒绝，见决策 1（会把 sched 拉进环 A）。
- **`RANK_TIMER` 取 7 或 9**：可行但取 6 让"5→6→8"这条链在数字上连续可读，
  且给 7/9 留了未来更外层/更内层的余地。
- **扫轮放 ISR 顶半**：拒绝。顶半不许取锁（ADR-020/034），而轮需要锁；
  ADR-047 决策 7 本来就写"顶半只置标志、到点唤醒在 Rust 垫片里做"。
- **扫轮放 need 闸之前**：拒绝，见决策 4（实测 3/3 39）。
- **`sleep_until` 持轮锁切走**：拒绝（ADR-053 决策 2：锁会在整段睡眠里不释放）。
- **精度只测 BSP**：拒绝，见决策 8（两个 tick 源，混测等于没测 AP）。

## 影响

- 代码：`sync.rs`（`RANK_TIMER`）、`sched.rs`（轮 + `sleep_until` + `wheel_tick` +
  `timer_stats` + 抢占点里的一处调用）、`ktests/sched.rs`（`t_sleep_until`，BSP/AP 两档）。
  用例数 60 → **61**。
- 登记面：`sync.public_api` +1（`RANK_TIMER`）、`lock-order.md` 加一行；
  **unsafe 普查零变化**（决策 3）。依赖图与环内边站点数不变。
- `wait_while` 的时限参数留 **P6b**：它要在持 WAITQ 时注册轮项（5→6），
  并让"条件唤醒"与"到期唤醒"共用同一个 token（谁先谁生效，后到者 `wake_task` 返回 false）。

## 验收与负样本

- **正向（实测）**：默认档 **3/3 PASS、61/61**，
  `sleep(P6): tick≈32.3M d≈64.6M BSP elapsed=66.5M/66.4M/71.3M ok=true
  registered 0->1 fired 0->1 残留=0 AP档=true min=65~97M max=94~99M ack=Ok(0)`
  ⇒ BSP 与 AP 都落在 `[d, d+2 tick]` 内。
- **MUTATION-T（实测确定性）**：`wheel_tick` 不看到期就立刻叫醒 ⇒
  `BSP elapsed=1129942`（≈1.1M ≪ d=64.9M）、`AP档=false` → `t_sleep_until -> failed`
  → FAIL(35)。还原 ⇒ PASS。
- **两次实测失败都记下来**：①扫轮在 need 闸之前 ⇒ `锁序违规 外层 rank=20 本次 rank=6`，3/3 39；
  ②用例不保证时钟在走 ⇒ 3/3 HANG。前者是代码位置错，后者是用例不自足，
  两者都不是"定时器轮不工作"。

## 迁移与回滚

- 回滚：删轮与三个函数、抢占点里那一处调用、`RANK_TIMER` 与锁序表那行、用例；
  `public_api` 还原。无 unsafe 变化，所以普查不用动。
- 迁移：P6b 给 `wait_while` 加时限；P5 的两个 hlt 上界（增量 ≤4、loops ≤ ticks*32+64）
  在轮落地后唤醒源变多，要重测分布再定（ADR-057 未决 2 已挂）。

## 未决

1. **P6b**：`wait_while` 的时限与超时返回（共用 token 的形状已在决策 5/6 定好）。
2. 槽数 64 无 workload 依据；要钉住它需要"同时到期项接近上限"的用例。
3. **残留隐患**：need 闸之后仍可能在"上一次 tick 立了牌、随后本任务取锁并发生同步异常"时
   扫轮 ⇒ 与决策 4 同形状。彻底解法是"异常出口取锁前先看被中断上下文是否持锁"
   （`sync` 需暴露一个只读的 innermost 查询），这与 §128 记的 L4 退出路径级联反向嵌套
   是同一处欠账，一并挂着，不在本轮悄悄扩大。
4. 真机/KVM 上的 tick 精度与 `[d, d+2 tick]` 的余量未测（ADR-024 口径）。
