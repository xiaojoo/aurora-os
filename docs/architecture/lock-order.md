# 锁等级表（手册 §7.1）

规则：嵌套获取时等级必须**严格递增**。表中"可被谁持有"这一列就是唯一的依据来源——
新增一把锁或改动一条嵌套关系，必须先改这张表，再改代码；两边不一致就是 §12.3 的门禁项。

| 锁 | 等级 | 保护的量 | 允许在它内部获取 | 依据（实测的调用关系） |
| --- | --- | --- | --- | --- |
| `RANK_WAITQ` | 5 | `sync::WaitQueue` 的链表头尾、waiter 槽与计数 | RUNQ(8)、HEAP(10)、VMM(20)、PMM(30)、台账(40) | **已落地（ADR-053/P4b，2026-11-08）**：持等待队列锁时叫醒别人即取运行队列锁；实测负样本 `重入获取 rank=5` ⇒ 39、`锁序违规，外层 rank=8 本次 rank=5` ⇒ 39 |
| `RANK_TIMER` | 6 | 每 CPU 定时器轮的到期项与计数（`sched::WHEELS`） | RUNQ(8)、HEAP(10)、VMM(20)、PMM(30)、台账(40) | **已落地（ADR-058/P6，2026-11-08）**：`wait_while` 持 WAITQ(5) 注册到期项（5→6），tick 扫轮持 TIMER 叫醒要取 RUNQ(8)（6→8）。扫轮**必须在 need 闸之后**，否则持 VMM 时的同步 #PF 会撞 `外层 rank=20 本次 rank=6`（实测 3/3 39） |
| `RANK_RUNQ` | 8 | 每 CPU 运行队列的所有权（`sched::RQ` 的 `QueueCell.lock`） | HEAP(10)、VMM(20)、PMM(30)、台账(40) | **已落地（ADR-048，2026-11-08）**：`spawn` 在队列锁内要任务栈 ⇒ 向下要页；实测取证跑 `acquires=348877 order_violations=0 reentrant_hits=0 wait_events=2556 wait_timeouts=0`，重入负样本 `L4 sync: 重入获取 rank=8` ⇒ 39 |
| `RANK_HEAP` | 10 | `heap::Heap` 的光标/自由链表 | VMM(20)、PMM(30)、台账(40) | `try_alloc` → `map_more_through` → `mm::map` → `new_table_frame` → `phys_alloc` → 台账 |
| `RANK_VMM` | 20 | 页表结构与 VA 保留登记表 | PMM(30)、台账(40) | `map`/`alloc_va_range` 内部要新页表页，走 `phys_alloc` |
| `RANK_PMM` | 30 | 物理帧位图与 `free_frames` 计数 | 台账(40) | `phys_alloc`/`phys_free` 结束时记账 |
| `RANK_HANDLE` | 35 | 用户句柄表（`kernel/src/handle.rs`，`handles` 特性） | 台账(40) | ADR-007 裁决 E（2026-11-07 批准，同日落地）：第一版对象是只读文件、**不持有页框** ⇒ 表锁内只许调台账、不许调 mm；盘 I/O 在锁外（取票/提交两段） |
| `RANK_LEDGER` | 40 | `resource::Ledger` 的每模块计数 | （叶子） | 不再获取别的锁 |
| `RANK_ACPI` | 50 | ACPI 解析结果静态量 | （叶子，目前只在启动期单独使用） | 解析路径不分配物理帧 |
| `RANK_TEST` | 60 | 无（跨核竞争用例的自旋占位） | （叶子，**故意**是叶子） | `smp::contention_round`；临界区里只有一次 volatile 读改写 + 一段 `tsc::spin` |

`RANK_TEST` 单独占一级而不是复用 40/50，是为了让"测试锁混进真实嵌套链"这种错误
当场报成锁序违规，而不是安静地共用别人的数字。

`RANK_HANDLE`(35) **已落地**（`kernel/src/handle.rs`，2026-11-07，`handles` 特性）：硬约束 4 的四件事齐全——
表、代码里的 rank、用例、重入负样本（变异 M6：同一把锁再取 ⇒ 当场 L4 `重入获取 rank=35`）。
盘 I/O **不在锁内**（取票 → 锁外读 → 锁内提交）：AHCI 同步读在关中断下拿不到完成中断，只能走轮询宽限窗。
重定级的条件不变：第一版对象是只读文件、表锁内不归还页框，所以 35 够用；
接内存缓冲区对象（要归还页框、要调 VMM(20)/PMM(30)）那天，要么把这一级降到 20 以下，
要么把释放移到锁外——两条路都要先改这张表再改代码，并各自配锁序/重入负样本。

## ADR-047 新增的两级：等级空间与单向嵌套（RUNQ 已落地 ADR-048；WAITQ 已落地 ADR-053）

**为什么只能落在 1..9。** `sync::INNERMOST` 是 `[AtomicU8; MAX_CPUS]`，初值 0，
而违规判据是 `rank <= prev_rank && prev_rank != 0`（`sync.rs:254`）——**0 是"当前没持锁"的哨兵，
不能当等级用**。现有 10/20/30/35/40/50/60 全在中高段，所以任何"比堆更外层"的新锁只有
1..9 这九个位置可取。本次用掉 5 与 8，剩 1..4、6、7、9。

**方向只有一条。** `WAITQ(5) → RUNQ(8)` 是唯一合法的嵌套方向：唤醒方先锁住等待队列，
再把任务投进目标 CPU 的运行队列。反方向（持运行队列锁去取等待队列锁）在同一 CPU 上就是
锁序违规，机制当场把它升成 L4——这不是文字约定，`sync.rs:253-257` 就是执行它的地方。
所以两把锁落地那天必须各配一条负样本：

- 重入样本：同一 CPU 连取两次 `RANK_RUNQ` ⇒ L4（沿用 `RANK_HANDLE`/rank 35 与堆/rank 10 的做法）。
- 反向嵌套样本：在持 `RUNQ(8)` 的路径上调一次会取 `WAITQ(5)` 的函数 ⇒ `order_violations` 非 0 且 L4。
  这条只能同 CPU 触发：per-CPU 等级栈看不见别的核的嵌套（见下一节），跨核反向锁不在判据射程里。

**为什么 8 而不是 9。** 留 9 是给"将来某把比运行队列更外层、但仍在堆之下"的锁；
而 8 与 10 之间留出 9 这一格，也让人不能顺手把 `RANK_RUNQ` 与 `RANK_HEAP` 写成同一级。

**与 shootdown 那条规则的关系。** "处理方不得取任何锁"（下面 M3b-2a 那条）对 resched IPI
同样成立在**同一层**意义上：它的顶半只允许置标志 + EOI，真正的换人动作发生在被中断的
上下文恢复 IF 之后（走 `preempt_point`），否则就是拿等待队列锁的 ISR 撞上请求方。

## M3b-1：等级栈必须是 per-CPU 的

`sync::INNERMOST` 今天是一个 `[AtomicU8; cpu::MAX_CPUS]`。**之前是一份全局值**，
那在多核下是错的：这张栈描述的是"本 CPU 此刻嵌套到哪一层"，
两个 CPU 交错取锁会互相读到对方的残值——A 核拿堆锁(10) 释放、B 核拿 VMM(20)、
A 核再拿堆锁……任何交错顺序都可能造出 `外层 rank >= 本次 rank` 这种**根本不存在的嵌套**，
报成 L4 锁序违规。这条不是推理出来的：放 AP 之后第一次跑竞争用例，
`order_violations` 就是靠这个非 0 才被要求去解释的。

配套的一条：`IrqGuard` 里存了获取时的 `slot`，`Drop` 只还原**那一个 CPU** 的等级栈。
守卫不可能跨 CPU 移交，因为持锁期间本 CPU 的 IF=0（`save_and_cli`），不会被抢占；
这条也是"持锁期间禁止开中断"的真正理由——一旦允许，per-CPU 等级栈和重入判据同时失效。

## 有界自旋与看门狗（§7.1 R16 的那一条，M3b-1 落地）

| 项 | 值 | 依据 |
| --- | --- | --- |
| 等待上界 | `LOCK_WATCHDOG_CYCLES = 200_000_000` 周期（本机 tsc≈3.32 GHz ⇒ ≈60 ms） | 必须明显大于**最慢的一次合法持锁**；实测最长一次等待 `wait_max=232,076` 周期（≈70 µs），余量约三个数量级 |
| 检查频率 | 每 256 次自旋取一次 TSC | 看门狗自己不能成为被测开销；代价是最坏超界 256 次自旋才被看见 |
| 到期动作 | `L4 sync: 等锁超时 …` → EXCEPTION(39) | 与"重入即 L4"同级：等待方已经无法区分持有者的死活 |
| 竞争记账 | `wait_events / wait_spins_total / wait_max_cycles / wait_timeouts` | 没有这四个数，"锁验证过了"只能指着一句 `violations=0` 空谈 |

实测（`-smp 4`，4 个 CPU 同时抢 `RANK_TEST` 这一把锁，每 CPU 4,000 次临界区）：

```
contention: participants=4 rounds_per_cpu=4000 unlocked_lost=10204 locked_lost=0 wait_events=5358 wait_max=232076
contention lockdep: acquires=16121 order_violations=0 reentrant_hits=0 ack_timeouts=0
contention: 无锁丢数 10204 / 16000 = 6377 bp（这条数字是尺子能分辨的证据）
```

`unlocked_lost > 0` 与 `wait_events > 0` 是这条用例的**对照组**：前者证明这把尺子能分辨
"有没有锁"，后者证明两个 CPU 真的撞上过。少了它们，`locked_lost=0` 可能只是因为压根没有竞争。

## 为什么顺序是这样，而不是按"重要性"排

等级顺序 = **调用方向**，不是抽象层次的高低。堆在最外面，因为它会向下要页；
台账在最里面，因为它谁也不叫。把顺序写反不会立即出错，只会在真正嵌套时变成
自死锁——而自死锁在单核上的表现是"关中断自旋直到溢出"，归因极难，所以这张表
先于代码存在。

## 尚未覆盖的（写清楚，不留白）

- **持锁期间禁止**（§7.1）：睡眠、堆分配（`RANK_HEAP` 自己除外，它是分配器的叶子锁）、
  调用未知回调、丢弃 `Mapping`。堆锁内部确实会走到 `mm::map`，这是**有意保留**的例外，
  代价是堆锁不能在被 `Mapping` 丢弃路径上获取。
  **M3b-2a 之后这条有了机制**：`Mapping::drop` → `unmap_pages`（持 VMM(20)）→ 等 shootdown 回执
  → 才 `drop(frames)` 归还物理帧。所以"丢弃 Mapping 可阻塞"是真的会阻塞在**别的 CPU 的中断响应**上。
- **shootdown 的处理方不得取任何锁**（新增，依据 ADR-023）：请求方正拿着 VMM(20) 等回执，
  处理方再取同一把锁就是跨 CPU 死锁，而 `sync` 的重入检测只比令牌（= 本 CPU 的 LAPIC id），
  令牌属于别的 CPU 时**判不出来**。所以 `trap::isr_stub_shootdown` → `mm::shootdown_self`
  这条路径上只有：一次原子读、一条 `invlpg`、两次原子加、一次 EOI 写。
  同理 `isr_stub_cpu_timer`（AP 本地 tick）也不拿锁。
- **等回执的上界** `SHOOTDOWN_DEADLINE_CYCLES = 20_000_000`（≈6 ms）与看门狗同理：
  目标 CPU 可能正关着中断在另一个持锁临界区里，那条 IPI 要等它恢复 IF 才被取走。
  到期动作是 L4（`L4 mm: shootdown 超时`），因为"收不齐回执就归还帧"= 允许两个主人同一块页。
- **多 CPU 并发解映射今天只有一个请求方**（AP 只做映射不做解除映射），所以"VMM 锁串行化
  `SD_VA`"这条论证还没有反例测试，已挂 BACKLOG。
- **AP 侧的取锁样本只有两类**：`trap::install_exception_stack`（AP 进门时走 VMM/PMM/台账）
  与竞争用例。AP 上的**中断上下文取锁**没有被测过，因为两条快路径（tick / shootdown）
  刻意不碰任何锁——这是规则，不是遗漏。
- **看门狗阈值与 §9.6 的配对仍未定**：本实现给的是"等锁上界"，§9.6 要的"持锁者卡死"
  是另一半（需要持锁时间与调用点关联），手册 §12.4.2 明列"有意留空"。
