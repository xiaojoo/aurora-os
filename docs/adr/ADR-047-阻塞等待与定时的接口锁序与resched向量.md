# ADR-047：阻塞、等待与定时的接口、锁序与 resched 向量

状态：已采纳（2026-11-08，S1/W1 的 P1；前置取证见 BACKLOG §97a，锁序表已先改）
关联：ADR-020（向量与 EOI 纪律）、ADR-021（IF 属于 CPU）、ADR-023（shootdown 不建帧）、
ADR-024（0xF1 走建帧路径的 reasons）、ADR-034（中断认领表）、ADR-040（arch↔sched 走 hooks）、
ADR-045/046（登记面）、手册 §7.1 R16/§12.3 R19/§14 M3b 遗留、完整化方案 §5 W1 与 §6 T1.1–T1.7

## 背景

W1 要拆的是"没有阻塞"这道墙。P0 的取证（BACKLOG §97a，全部实测）给出四条硬事实，
决定了接口只能长成什么形状：

1. **运行队列锁不存在**：`sched::RQ` 是 per-CPU `UnsafeCell`，SAFETY（`sched.rs:337-344`）
   的前提是"每条队列只由它自己的 CPU 读写 + 任务不迁移"。而跨 CPU 唤醒的定义就是"投进别人的队列"。
2. **等级空间只剩 1..9**：0 是"没持锁"的哨兵（`sync.rs:254` 判据带 `prev_rank != 0`），
   现有 10/20/30/35/40/50/60 占中高段；而 `spawn` 在队列锁内要任务栈 ⇒ 新锁必须 <10。
3. **`loads_closed` 今天结构恒 0**：唯一的调度入口是异常出口（`trap.rs:1099`），
   用例注释自己写着"没有触发源"（`ktests/sched.rs:356`）。
4. **没有 resched 向量**：具名向量实测 7 条（ADR-046 的表），核间 IPI 只有 shootdown 一条，
   而它**故意不建帧**——不建帧就不能换人。

另外三条口径约束：全仓 0 处 `debug_assertions`（断言只能做成注入变体 + 判定表行）；
`arch` 的 `forbidden_dependencies=["sched"]` 且 `known_violations=[]`（反向调用只能走 hooks）；
`docs/architecture/vectors.toml` 的名字双向相等规则**不允许预告源码里还不存在的向量**
（所以本 ADR 只定号，登记行到 P5 才加）。

## 决策

1. **状态机**：`TaskState` 增加 `Blocked(WaitToken)`。`WaitToken { queue: u8, seq: u64 }`
   是唤醒世代号——`wake` 与 `timeout` 两条路都可能改状态，没有世代号就无法证明
   "叫醒的是这次等待，不是上一次遗留的那次"。状态字段仍是非原子裸字段，但从此有一条写入规则：
   **只有持有该任务所在队列的 `RANK_RUNQ` 才能改 `state`**；跨核只读快照（`state_of`）
   继续只许用于观察，不许用于调度决定（`sched.rs:528` 的旧话）。
2. **运行队列所有权（P2，先于任何阻塞代码）**：`RQ` 换成 `IrqSpinLock<RunQueue>`，
   rank = `RANK_RUNQ(8)`；SAFETY 注释重写为"跨核写入必须持目标队列锁，且本 CPU 在 IF=0 窗口内"。
   **这一步不引入迁移**——它只把"没人会碰"这种靠人守的论证换成可证的锁。
   默认 `run` 53/53 与串口日志多重集逐条不变是这一步的判据（零行为变化证明）。
3. **等待队列**：`sync::WaitQueue`，全局静态 `MAX_WAIT_QUEUES = 16` 把、每把
   `MAX_WAITERS = 16` 槽，侵入式单向链表 + 空闲位图，**不进堆**。
   理由要写对：不是被 ISR 禁令逼的（ISR 内分配是 L3 拒绝、可观察，`heap.rs:75`），
   而是 `LARGE_MAX = 2048`（ADR-018/026）与"故障路径不分配"（AGENTS 硬约束 6）。
   拿不到 waiter 槽 ⇒ `WaitError::NoCapacity`（B 类），调用方必须处理；
   **不许**在等待路径上顺手 `Vec::new()`。
4. **防丢唤醒协议**（这是 W1 的核心不变式）：
   - `wait_until(cond, deadline)`：持 `WAITQ(5)` → 查 `cond` → 占槽 → 标 `Blocked(token)`
     → 取 `RUNQ(8)` → 换人。三个动作在同一把等待队列锁内，所以"检查完条件到入队之间"
     不可能插进一次 `wake`。
   - `wake_one()` / `wake_all()`：持 `WAITQ(5)` → 出队 → 取 `RUNQ(8)` → 标 `Runnable` 并投进
     目标 CPU 队列 → 若目标 ≠ 本 CPU，发 resched IPI。
   - 嵌套方向唯一：`WAITQ → RUNQ`；反向在同 CPU 上是锁序违规 ⇒ L4（机制 `sync.rs:253-257`）。
5. **resched 向量取 `0xF0`（`VEC_RESCHED` = 240）**，并**新建专属桩 `isr_stub_240`**
   （实测今天不存在：`grep isr_stub_240 trap.rs` = 0，240 落在 48..254 的共用桩里；
   建法与 M3b-2b 给 0xF1 单独生成 `STUB_NOERR 241` 同法），**走建帧路径**
   （`isr_common → 抢占点`），与 0xF1 同类而不与 0xF2 同类：它的目的就是把人换掉，
   不建帧就没有续跑点（ADR-024 对 0xF1 的理由在这里原样成立）。
   顶半只允许"置本 CPU 的 need 标志 + EOI"，不取锁、不分配、不打印（ADR-034/ADR-020 纪律）。
   号段选择：240 与 241/242 相邻，语义一致（核间 IPI），且在 48..254 段内不需要新开区间；
   要动别的段必须先改 `vectors.toml` 的 `[[range]]` 保持铺满 0..255。
6. **hooks 扩两个字段**（`hooks::SchedHooks`）：`mark_need_from_isr()` 与 `resched_pending()`，
   供 arch 顶半回调 sched。每个字段新增 1 处 U4，落地那轮同步登记
   `unsafe-whitelist.toml` 的 `[modules."hooks"]` 与 `unsafe-census.md` 小节。
   `arch` 仍然不许直接 `use crate::sched`（ADR-040 与 `forbidden_dependencies` 不变）。
7. **定时**：每 CPU 一个定时器轮 `TIMER_WHEEL[cpu]`，64 格、粒度 = 该 CPU 自己的 tick 源
   （BSP 是 PIT→IOAPIC 向量 32，AP 是 LAPIC 周期 0xF1 / 10 ms）。
   `sleep_until(deadline: u64 tsc)` 挂轮；tick 顶半**只置标志**，到点唤醒在 Rust 垫片里做，
   遵守"完成路径只叫醒不放行"（ADR-044 的 M5-g② 教训在这里同样成立）。
   判据里 `[d, d+2 tick]` 的 tick 一律按**被睡 CPU 自己的源**计，BSP 与 AP 各跑一档，
   两本 tick 账不许混数（`watchdog.rs:5,34-43`）。HPET/RTC 不在 W1（墙钟是 W9）。
8. **睡眠锁**：`Mutex` / `Semaphore` / `Event` 建在 `WaitQueue` 上。规则
   "持自旋锁、持 `RUNQ`/`WAITQ`、或 IF=0 窗口内不得睡"的兑现方式是**注入变体**
   `fault-hold-sleep`（全仓没有 `debug_assertions`，这是本仓库唯一的"运行时断言"形态），
   进判定表一行，期望 39。
9. **上下文与错误分类**：`BOOT` 不许睡（启动路径继续用 `tsc::spin`/`apic::wait_ticks`）；
   `ISR_TOP` 只许置标志；`KERNEL` 可 wait；`IRQ_OFF` 里 wait = 自死锁，归 **C 契约违例** 直接 L4。
   `Timeout` 与 `NoCapacity` 归 B。三类沿用登记表已有的 `error_classes`。
10. **证人交接（P5）**：`ktests/sched.rs:679` 的 `worked_aps == checked_aps` 现在靠内置
    AP 工人任务的 `WORK` 计数当证人，而 idle 真 `hlt` 正是要取代那个工人。
    落地时必须**换成用例自己 spawn 的任务**当证人；把等式放宽成 `>= 0` 属于放宽判据，禁止。

## 备选方案

- **无锁 CAS 运行队列**：拒绝。跨核"入队 + 换人"是复合操作，CAS 保证不了原子组合，
  而丢唤醒判据（变异 A）要的正是"这两步之间插不进 wake"。
- **等待队列放在 `sched` 而不是 `sync`**：拒绝。驱动、IPC、块层都要用它，而它们不能依赖 sched；
  `sync` 已经是叶子层且 `sched -> sync` 边本就存在。
- **resched 走不建帧快路径（学 shootdown）**：拒绝。见决策 5——不建帧就没有换人的续跑点。
- **`sleep` 用 LAPIC TSC-deadline 模式**：推迟。QEMU 下 deadline 与现有周期模式的 TMCCT
  读数混在一起，会让 `[d, d+2 tick]` 变成两本账（决策 7 的"源要统一"就先破了）；列入未决。
- **waiter 槽走堆**：拒绝。见决策 3 的真实理由。
- **用 `debug_assertions` 实现"持锁不得睡"**：拒绝。本仓库的构建矩阵里没有任何配置开它，
  写了就是永不执行的判据（AGENTS：每条新判据要能被证红）。

## 影响

- 正面：W1 之后驱动可以写"等完成"而不是自旋（BACKLOG 62 那条"等待型驱动写不出来"从这里开始解）；
  `loads_closed` 有了触发源（M3b 遗留那一格）；AP 常驻自旋可以被 idle 取代，
  P1/P4 的绝对值从此才可解读（BACKLOG 86）。
- 代价与风险：
  1. `RANK_RUNQ` 一旦引入，`spawn`/`preempt_point`/`reap` 都在锁内，P1（切换成本）会**变高**，
     而 P1 的历史数字本来就不可比（M3b-2b 分行），所以只能同构建内比——写进 BACKLOG 而不是解释成变好。
  2. `reap` 只认 `Free/Done`（`sched.rs:265`），Blocked 槽会被跳过；"释放延迟到本 CPU 上跑的
     已经不是它"这条未写下的前提（BACKLOG 144）在阻塞下失效 ⇒ P3 必须同时改 `reap` 的状态集，
     并把这条前提**写进代码注释与用例**，不能继续靠默认成立。
  3. 新增向量顶半会进 P5 的样本桶：`ktests/time.rs:130-132` 的逐桶 + 非 ISA 桶对照式
     已经会逼迫"新向量必须显式表态"，P5 落地时要给 `VEC_RESCHED` 单独一桶而不是混进 `non_irq`。
- 登记面：`sync` 的 `public_api` 会增加（`WaitQueue`/`WaitToken`/`WaitError`/两个新 rank）；
  `hooks` 的 `unsafe_scope` U4 计数 +2；`vectors.toml` 到 P5 才加 `VEC_RESCHED` 行；
  `lock-order.md` 已按"先改表再改代码"写了 5/8 两级并标注"裁决已定、代码未落地"。
- 本 ADR 不改任何代码；P2 起才动 `sched.rs`/`sync.rs`/`hooks.rs`。

## 验收与负样本

判据分两层：**每一片的完成判据在它自己的落地轮兑现**（P2..P7），本 ADR 只把它们钉成清单。

| 编号 | 判据 | 红法（变异证红） | 落地轮 |
| --- | --- | --- | --- |
| V1 | P2 引入 `RANK_RUNQ` 后默认 `run` 53/53 且串口日志**多重集**不变 | 故意让 `spawn` 在锁外写队列 ⇒ 竞争用例红（对照组） | P2 |
| V2 | 同 CPU 连取两次 `RUNQ` ⇒ L4(39) | 还原 ⇒ 33 | P2 |
| V3 | 持 `RUNQ` 时取 `WAITQ` ⇒ `order_violations` 非 0 且 L4 | 反向链做成注入 ⇒ 红；同 CPU 才可判（跨核不在判据射程） | P4 |
| V4 | 4 核 N 生产者 N 消费者 10 万条消息：`wake` 与 `block` 计数差 ≤ 在途数，丢唤醒 = 0 | 变异 A：把"入队"移出 `WAITQ` 锁 ⇒ 丢唤醒 > 0 或 HANG(-1) | P4 |
| V5 | `sleep_until` 落在 `[d, d+2·tick]`，BSP/AP 各一档 | 变异：轮子到期不叫醒 ⇒ 该档 HANG；把 2 tick 上界去掉则红在判据行 | P6 |
| V6 | idle 真 `hlt`：内核自计数 `idle_hlt[cpu]` 进串口，宿主机按行数核对；AP 工人不再自旋 | `worked_aps` 证人换新任务后仍 `== checked_aps`；不换证人直接放宽 ⇒ 视为未交付 | P5 |
| V7 | resched IPI 投递由宿主机数到（`-trace events=...apic_deliver_irq`，ADR-037 通道），与内核 `resched_sent/resched_taken` 对账 | 去掉 IPI ⇒ 跨核唤醒延迟超界（变异 B） | P5 |
| V8 | `fault-hold-sleep` 注入 ⇒ 39 | 还原 ⇒ 33 | P7 |

V7 特别说明：设计文档写的 `-d int 见 hlt` **今天没有仪器**（`check_irq_trace` 只对账
`0x21..0x2F`，且 kvm 档零产出、tcg 档自扰动），所以本 ADR 把它换成两条可执行的证人——
内核自计数（数量）+ `-trace` 通道（投递事实）。这一改动本身就是"不放宽判据，换更硬的证人"。

## 迁移与回滚

- 迁移顺序即 P2 → P3 → P4 → P5 → P6 → P7，每一步都能独立过门禁；P2 是纯加锁，
  回滚就是把 `RQ` 换回 `UnsafeCell` 并删 rank（同一提交内删 `lock-order.md` 的两行）。
- 不能回滚的部分：一旦 `TaskState::Blocked` 进了枚举，`reap`/`state_of` 的取值域就变了，
  所有按状态取数的用例要一起回——所以 P3 之后每片都必须在**默认构建**上验，不留特性后面。

## 未决

1. `MAX_WAITERS = 16` / `MAX_WAIT_QUEUES = 16` 现在是拍的，缺 workload 证据；
   W5/W6（块层与中断化驱动）会用真实并发度回来钉它——**容量数字要么有测量来源，要么写成上限**。
2. LAPIC TSC-deadline 模式（`apic.rs:648` 注释承认位存在未用）作为 sleep 的更细粒度源，
   与 `[d, d+2 tick]` 的定义冲突，需单独 ADR。
3. 迁移协议（P9）：`QueueCell` 的 SAFETY 重写只做到"两边关中断 + 持锁"，
   真正的时间片迁移与负载判断另议。
4. `wait()` 雏形与 `MAX_TASKS` 6→64（P8）要同时抬 `mm::MAX_TASKS_SUPPORTED`（ADR-041）；
   Done 槽回收与 Blocked 槽回收在同一张表里，别分两次改。
5. 号段政策：0xF0 由本 ADR 定了；下一个核间向量（例如 suspend/resume 通知）要新 ADR，
   并且必须先改 `vectors.toml` 的区间表。
