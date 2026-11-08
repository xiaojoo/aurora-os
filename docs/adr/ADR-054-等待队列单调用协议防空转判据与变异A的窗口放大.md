# ADR-054：等待队列的落地形状——单调用协议、防空转判据、以及变异 A 在单核下必须放大窗口

状态：已采纳（2026-11-08，S1/W1 的 P4b；落地 ADR-053 决策 1/2/3）
关联：ADR-053（依赖反转与放锁后切走）、ADR-047（W1 接口）、ADR-048（运行队列锁）、
ADR-049（自陷让出）、ADR-050（用例收尾纪律）、ADR-018/026（堆上限与故障路径不分配）、
`docs/architecture/lock-order.md`

## 背景

ADR-053 定了方向（回调表反转、放锁后切走、`WaitToken` 放 `sync`），P4b 落地时又出现三件
必须当场裁决的事，其中两件是**实测打出来的**：

1. 第一版用例全绿，但读数是 `blocks=0 wakes=0 empty_wakes=24`——**消费者一次都没阻塞**：
   生产者总是跑在前面，消费者查条件时 flag 已置位。判据其余各格（轮数推进、链上无残留、
   blocks==wakes）在"根本没走阻塞路径"时**全部成立**。这是 §12.3 R19 要防的"绿而无效"。
2. 变异 A（把查条件移到锁外）在单核上连跑 **4 发都没触发**：锁外查条件到取锁之间的天然
   窗口太窄，需要同一个 CPU 恰好在那几条指令之间被 tick 换走。
3. API 形状：`wait_while` 要不要把"让出"包进去。包进去则调用方一行搞定、但 `sync` 必须
   通过回调表拿到 `yield_now`；不包则调用方要自己记住"放锁后必须让出"，那是把协议的正确性
   分散到每个调用点。

## 决策

1. **单调用协议**：`WaitQueue::wait_while(qid, cond)` 内部完成"持锁查条件 → 占槽 →
   经回调标 `Blocked` → **放锁** → 经回调 `yield_now()` → 回来摘链 → 复查条件"。
   `yield_now` 走 `WaitOps`（ADR-053 的反转），所以 `sync` 仍不引用 `sched`。
   `cond` 必须是**廉价谓词**：它在锁内被调用，不得睡眠、不得取比 `WAITQ` 更外层的锁。
2. **判据必须含"防空转"一格**：`blocks > 0`。用例每轮**先让出一次**让消费者去阻塞，
   再置位并 `wake_one`。实测这样得到 `blocks=24 wakes=24 empty_wakes=0`（24 轮全走阻塞路径）。
   没有这一格，"生产者永远跑在前面"也能让其余各格全绿。
3. **`empty_wakes` 单独计数且必须与 `blocks/wakes` 一起读**：生产者跑在消费者阻塞之前是
   **合法**情形（那一次 wake 落在空队列上，消费者随后查条件直接成立、不阻塞）。
   把它当错误会造出假红；不看它则丢唤醒变异少一个证人。
4. **变异 A 在单核下必须放大窗口**：把查条件移到锁外**并在窗口里让出一次**
   （MUTATION-A2）。实测 2/2 确定性触发，签名是教科书式的丢唤醒：
   `blocks=1 wakes=0 empty_wakes=1 仍在链上=1 卡住=1` ⇒ FAIL(35)。
   **不放大窗口的裸变异 A 在单核上 4 发未触发**，所以"变异 A 已证红"这句话只对 A2 成立；
   真正的并发证明留到 P4c 的 4 核压力（那时生产者与消费者在不同 CPU 上同时跑）。
5. **容量是上限，不是测量结果**：`MAX_WAIT_QUEUES=16 × MAX_WAITERS=16`，定长不进堆。
   槽满回 `WaitError::NoCapacity`（B 类），回调表未装或当前上下文不是任务回 `NotInstalled`。
   调用方**不得**在等待路径上分配。这两个数还没有 workload 依据（ADR-053 未决 1 仍然开着）。
6. **`remove_task` 公开**：杀死阻塞任务时摘链用（ADR-053 决策 4）。
   `terminate_task` 与它的**自动**挂接仍未做，用例 presently 自己先摘链再终止；
   这条欠账写明，不假装已经接好。
7. **锁序落地**：`RANK_WAITQ(5)` 进 `sync`，`lock-order.md` 那一行转"已落地"，
   并按硬约束 4 配两条负样本（见验收）。

## 备选方案

- **两步 API（enqueue 后由调用方自己 yield）**：拒绝。协议正确性会分散到每个调用点，
  而"放锁后必须让出"正是最容易忘的一步；忘了就变成持锁睡眠或永不阻塞。
- **判据只看轮数推进与链上无残留**：拒绝，见背景 1（实测绿而无效）。
- **把 `empty_wakes` 当错误**：拒绝，见决策 3（会造假红）。
- **只用裸变异 A 就宣称防丢唤醒已证**：拒绝，见决策 4（4 发未触发；宣称它证红是不诚实的）。
- **槽位走堆**：拒绝（ADR-018/026 与故障路径不分配）。

## 影响

- 代码：`sync.rs`（`RANK_WAITQ`、`WaitError`、`WaitOps` + 装表、`WaitQueue` 与五个方法、
  静态队列数组）、`sched.rs`（`install_wait_ops`）、`main.rs`（启动期装表）、
  `ktests/sched.rs`（`t_waitqueue`）。
- 登记面（门禁点名后补）：`public_api` +3（`sched::install_wait_ops`、`sync::WaitOps`、
  `sync::install_wait_ops`）；`sync` 的 U4 3→6（`OpsCell` 的 `Sync`/装/读），
  普查 total 286→289、U4 109→112。`WaitQueue`/`wait_queue`/`WaitError`/`RANK_WAITQ`
  目前只被 ktest 引用，按 ADR-043/045 口径**不进** `public_api`。
- 用例数 56 → **57**。
- 依赖图不变：`sync` 没有新增出边到 `sched`（回调表反转），环 A 与棘轮不动。

## 验收与负样本

- **正向（实测）**：`waitqueue(ADR-053): rounds=24 done=24 blocks=24 wakes=24 empty_wakes=0
  仍在链上=0 卡住=0`，默认档 **3/3 PASS、57/57**。
- **MUTATION-A（裸，实测未触发）**：查条件移到锁外，单核连跑 4 发全 PASS ⇒ **不作为证红证据**。
- **MUTATION-A2（放大窗口，实测确定性）**：再在窗口里让出一次 ⇒ 2/2 FAIL(35)，
  `blocks=1 wakes=0 empty_wakes=1 仍在链上=1 卡住=1`。判据把它读成**红**而不是挂死，
  靠的是用例里"有界让出 200 次"那一段。
- **MUTATION-L1（WAITQ 重入，实测）**：持 `WAITQ` 再取 `WAITQ` ⇒
  `L4 sync: 重入获取 rank=5` ⇒ EXCEPTION(39)。
- **MUTATION-L3（反向嵌套，实测）**：在只持 `RUNQ` 的 `reap` 里取 `WAITQ` ⇒
  `L4 sync: 锁序违规，外层 rank=8 本次 rank=5` ⇒ EXCEPTION(39)。
  注意第一次尝试（MUTATION-L2，放在 `wake_task` 里）打到的是**重入**而非锁序违规，
  因为 `wake_task` 本来就在 `WAITQ` 锁内被调用——负样本必须挑对路径，这条记下来。
- 三条变异还原后回到 PASS(33)。

## 迁移与回滚

- 回滚：`WaitOps` 退回默认 no-op 即等价于"没有等待队列"（`wait_while` 回 `NotInstalled`），
  但**必须在没有阻塞任务时回滚**，否则已阻塞者永不被唤醒。
- 迁移：P4c 把跨核唤醒接上（hooks `mark_need` + resched IPI），届时 `wake_one` 之后
  目标 CPU 才会立刻重新调度；今天同核靠 `yield_now`、跨核要等目标的下一次 tick。

## 未决

1. 容量 16×16 仍无 workload 依据；P4c 的 4 核压力会给出第一个真实并发度。
2. `deadline`/超时：今天 `wait_while` 没有时限参数，因为阻塞期间没有定时器轮能叫醒它
   （P6）。所以"卡住"只能由**调用方**的有界让出发现，不是队列自己超时。
3. `terminate_task` 与 `remove_task` 的自动挂接（决策 6）。
4. 防丢唤醒的**并发**证明在 P4c；本轮只有放大窗口后的单核证明。
