# ADR-073：进程与 Job 对象、"僵尸留到被收走"的结局记录，以及上限的 workload 实测

状态：**已采纳**（2026-11-09，W3 P3 落地并实测；读数见"验收与负样本"）
关联：ADR-070（`AddressSpace`）、ADR-071（等待与上限分开）、ADR-072（shootdown 收窄）、
ADR-069（收尾判据与显式名单）、ADR-068（IF 窗口）、ADR-063/065（帧引用计数与 VA 保留表）、
ADR-047 决策 2 / ADR-048 决策 3（持锁不跨未知回调、拿队列不等跨 CPU 的锁）、
手册 §5.2/§6.6/§7.1、设计文档 §10.1、`docs/design/w3-立项-依赖图与切片计划.md` §3 的 P3 与 §4 的 Q2/Q7、
BACKLOG §149/§150

> 写作纪律：本文的"实测"都指本轮 run-of-record（`ktests: total=76 passed=76`、判定 PASS=33）；
> 没跑过的写"未验证"，推断的写"推断"。

## 背景

W3 依赖图里 P3 要一次解决四件事，每件都在代码里有可核对的空缺：

- **N11 `Job` 配额对象不存在**：设计文档 §10.1 已裁决要加，`spawn` 炸弹今天挡不住（没有额度，也没有进程数上限）。
- **N9 槽位上限同时是进程上限**：`MAX_TASKS = 8` 每 CPU（`kernel/src/sched.rs:28`）既是线程容量也是
  "最多几个进程"，而这两个数不该绑在一起（Q2 裁"先实测再定数"）。
- **N16 没有"等一个任务收工"的原语**：最接近的是纯自旋的 `wait_for_boot_task`；
  三个收工出口（`finish_current`/`kill_current`/`trampoline`）都不置结局、不唤醒任何人。
- **N17 收尾判据只覆盖任务**（ADR-069）：新对象（进程/Job）如果不进同一本账，
  "用例造了什么就得自己收干净"这条律就有了一个新缺口。

P1/P2 已经交付 AS 对象与按位图收窄的 shootdown，但**映射还没有主人**：P4 的 `aspace_map` 要知道
页属于哪个进程，P5 的 `thread_create` 要知道线程挂到哪个进程上。所以 P3 必须在 P4 之前。

## 决策

### 1. 归属与形状

- 新增 `kernel/src/proc.rs`，**逻辑模块归入 `sched`**（`module-interfaces.toml` 的
  `[modules."sched"].source_modules` 加 `proc`）：进程与线程是同一条生命周期的两端，
  今天没有第三条线要分开记账。P4 之后若 `VMO`/句柄面扩大，再单开逻辑模块。
- 两张**定长表**：`MAX_PROCESSES = 4`、`MAX_JOBS = 4`。形状与 ADR-069 的常驻名单同律——
  定长、显式、越界与占空一律失败返回，不做动态容器（硬约束 6 的"故障路径不分配"）。
- `Task` 增加 `proc_id: u16`，哨兵 `NO_PROC = 0xFFFF`。**今天没有 syscall**：
  这些对象只能由内核/ktest 创建，用户态看不见（P4/P5 才接）。
- `MAX_PROCESSES = 4` 这一格是 Q2 参考形状（init + 3 子进程）的直接读数，**不是**余量后的终值；
  终值等 §决策 9 的裁剪。

### 2. 结局的记录必须比等待者活得久（僵尸语义）

- 一条线程收工 ⇒ 线程计数减一；**减到 0** 时把进程的 `signal` 置成 `TERMINATED | 退出码`。
- 置完之后**槽位与 Job 额度都不还**：还它们的是 `proc_reap`（收尸，返回退出码）。
  理由很具体：如果最后一条线程就地清表，等待者醒来时 `proc_is_terminated` 已经是 false，
  退出码无处可读——本轮第一版就是这么写的，实测 ① 格红在 `terminated=false`（见验收表脚注）。
- 一条线程都没建成的进程（创建成功但 `spawn` 失败）走 `proc_discard`：它只放行
  `threads == 0 且未终止`，其余一律 `Denied`。这条分界是 P6"中途失败回滚"的同一块地基。
- 额度口径：僵尸**继续占** Job 的 `used_procs`（主流对照：Linux 的 zombie 仍占 `task_struct` 与 PID，
  Zircon 的进程对象在最后一个 handle 关闭前不消失）。所以"②额度格"里第二个进程能建、
  第三个被拒，依赖的正是这条。

### 3. `signal` 的位布局（关掉 ADR-071 未决 1 的内核侧一半）

- 一个 `AtomicU32`：`bit31 = 1` 表示已终止，**低 31 位是退出码**；`bit31 = 0` 表示还在跑。
- 退出码取值今天只有两个来源：工人正常返回 / `finish_current` ⇒ `0`；`kill_current` ⇒ `1`。
  （"被杀"要不要占一个更大的编码空间，等 19 号 `object_wait` 对外时一起裁——见未决 3。）
- `NO_PROC` 与空槽一律读成"已终止、码 0"：读这一格的是等待方，给它"永不终止"会空转到超时。

### 4. `proc_id` 是一次性边令牌

- 收工边取走 `proc_id` 之后**立刻置回 `NO_PROC`** ⇒ 同一个任务无论走过几条出口（自己调
  `finish_current` 又从工人函数返回），线程计数只减一次。
- `terminate_task` 释放槽位时把 `proc_id` 与 `resident` 一起清掉：身份跟着槽位走，
  留着的话复用这条槽的任务会把**别人的**进程线程计数减一次（ADR-061 未决 1 那条 ABA 的同一家族）。

### 5. 锁的三条分界（硬约束 6：故障路径不等锁）

| 动作 | 锁 | 为什么 |
| --- | --- | --- |
| 表结构（占槽/还槽/额度） | **只在 VMM(20) 内**：`job_create`、`proc_create`、`proc_attach_thread`、`proc_reap`、`proc_discard`、`job_destroy` | 与 AS 表同一把锁，**不新增锁级**（`lock-order.md` 本轮零改动） |
| 收工出口 `proc_thread_exited` | **零锁**，只动原子量（`used`/`threads`/`signal`） | `kill_current` 会在故障路径上被调，那一刻 VMM 可能已被本 CPU 持有；取锁就是自死锁 |
| 计数读数 `proc_residual`/`job_residual` | **零锁** | 用例收尾扫描（`main.rs::finish_sweep`）按 ADR-069 是"只读快照、不拿锁"；为此两张表的 `used` 都是 `AtomicBool` |

因此 `RUNQ(8) → VMM(20)` 这条嵌套**不存在**：收工点放掉队列锁之后才碰进程表，而收工边本身根本不碰表。

### 6. 顺序：先置结局，再摘牌

三个收工出口都写成"取 `proc_id` → 置 signal → 标 `Done`"。等待方以 `Done` 当"结局可读"的凭据，
反序就给它一个看到 `Done` 却读不到退出码的空窗（ADR-071 决策 1 的同一条线，也是 ADR-054 防空转的形状）。

### 7. 等待：`wait_for_task` 今天只有"有界 + 推进"，没有唤醒边

- `sched::wait_for_task(target, deadline_cycles) -> bool`：轮询 `state_of(target)`，
  每轮 `yield_now()` 推进（停表时靠 0xF0 自陷换人，ADR-049），超时返回 `false`，**不升 L4**
  （目标永不收工是业务事实，不是契约违例，§7.1）。
- **调用方必须在开着的 IF 窗口里**（ADR-068）。这不是风格而是机制：换到工人之后要靠一次 tick
  换回来。本轮第一版没包 `with_interrupts`，实测整机 HANG 120 s——现场是 `wait_ticks` 返回时
  窗口已经关掉，工人带着 `IF=0` 跑，没人能抢占它。这条要写进判据的前置，见验收表 A7。
- `TASK_QID` 与唤醒边**不在本轮**：P3 只落"置 signal"这一半，等待仍是轮询；
  唤醒那半随 P6 的 `object_wait` 一起落地并单独证红（未决 2）。

### 8. 收尾判据扩到进程与 Job（ADR-069 同律）

`finish_sweep()` 的 `Sweep` 多出四格：`procs/first_proc`、`jobs/first_job`；
用例之间那道门从"没有未登记的可运行任务、没有阻塞任务"变成**再加**"没有没交出去的进程记录、
没有没销毁的 Job"，两条 fatal 各自点名首个槽号。这样"造了不收"在下一个用例边界就被抓住，
而不是等台账在几百行之后不平。

### 9. Q7 的页数额度：本轮只做收窄检查，不做用量

Q7 裁的是"进程数 + 页数"两项。**页数要有"进程名下有哪些页"才有得可加**，而进程到 AS/VMO 的
归属是 P4 的东西。所以今天 `max_pages` 只参与"子 Job 额度只能 ≤ 父"这一条检查（有独立判据与
独立变异），`used_pages` 与"超页拒绝"留到 P4。**这是裁决没被完整执行的部分，写在这里而不是藏在代码注释里。**

### 10. Q2 的上限：先实测，数留给使用者裁

本轮交付 workload 用例 `t_q2_workload_slots`（参考形状 init + 3 子进程 × 2 线程）。
读数（run-of-record，`q2(P3)` 那一行）：

```
请求=7 成功=4 拒绝=3 峰值同活=4 active基线=7 active峰值=11 收工=4 收尸=3 回滚=1
每CPU槽上限=8 参考需线程+boot+idle=9 回基线=(drained true free116238->116238 va23->23 active7)
```

结论与限制逐条写清：

1. **参考形状在单颗 CPU 上装不下**：7 条线程 + boot 上下文 + 兜底 idle = **9 格**，
   而 `MAX_TASKS = 8`。这个数是算出来的（编译期容量），不依赖环境。
2. 实测只成功 4 条：用例跑在中途，别的用例已经留下了活跃任务（`active基线=7`，
   其中含 3 颗 AP 的常驻工人）。所以**"能装几条"的观测值受链接顺序影响**，
   而"需要 9 格"这个结论不受——引用 Q2 读数时只允许引用第 1 条。
3. 没有迁移（`sched.rs` 头注释第 2 条）⇒ 全部线程挤在调用者那颗 CPU 上，
   这是 Q2 题面预告过的偏小方向。
4. **本轮不改 `MAX_TASKS`**：提它要同时重算 `sched.rs:30` 那条编译期断言
   （⇒ `mm::MAX_TASKS_SUPPORTED`，ADR-041）、VA 前沿（ADR-065 的 256 格保留表）与
   `.bss`/`free frames` 三本账，并按 Q4 重跑 bench 的 P1 格——那是另一个决定（未决 1）。

## 备选方案

- **线程退出就地清表还额度**：拒绝（决策 2）。等待者读不到退出码，`process_wait` 的契约写不出来；
  本轮第一版就是这么写的，被自己的判据打回（不是理论反对，是实测红）。
- **收工出口取 VMM 做表操作**：拒绝（决策 5 的第二行）。`kill_current` 在故障路径上会被调，
  而故障现场可能正持着 VMM；硬约束 6 的原文就是"故障路径不等待可能已损坏的锁"。
- **给进程表新开一把锁**：拒绝。今天能覆盖它的只有 VMM(20)（AS 表已经在里面），
  新增锁级要改 `lock-order.md` 的 rank、测试与负样本一整套（硬约束 4），收益只是"名字好看"。
- **现在就提 `MAX_TASKS` 到 16**：拒绝（决策 10）。Q2 明写"先实测再定数"，
  且这件事的代价面（VA 前沿、断言、`.bss`、bench 地板）比 P3 的其余部分都大。
- **`spawn(entry, proc)` 把归属放进创建参数**：考虑过，留给 P5。
  今天 `spawn` 有十几个调用点，改签名会让 P3 的改动面从"新增模块"变成"全树扫一遍"；
  本轮用"先 `proc_attach_thread` 再 `spawn` 再 `set_proc_id`" + 一条前提格代替，
  并把两种顺序各自的前提写在用例注释里（顺序错了的症状是空转到超时，不是崩溃）。
- **`resident` 复用成进程级名单**：拒绝（决策 8）。进程级常驻身份今天一个都没有，
  开一格空名单正是硬约束 2 禁止的"没有调用者的空结构"；等 init 落地再开（未决 4）。

## 影响

- 正面：`spawn` 炸弹有了第一道闸（进程数额度）；结局有了能等到、能读到的形状；
  收尾律覆盖到新对象；P4/P5 有了归属主体；Q2 有了实测而不是拍数。
- 负面/代价：
  1. 三个收工出口各多一次原子减（热路径）——量级见 bench 的 P1 格（本轮同 AS 格与历史地板对账，见验收）。
  2. 僵尸占额度 ⇒ 用例必须自己收尸，否则收尾判据点名（这是有意的，但确实多一处纪律）。
  3. `used`/`threads`/`signal` 用原子量换来"收工边零锁"，代价是 `proc_discard`/`proc_reap`
     的状态判断只能看原子快照，不能看表的其他字段。
  4. 等待仍是轮询：没有唤醒边之前，`wait_for_task` 的最坏延迟是**一次 tick**，不是"目标一收工就醒"。
- 登记面：`module-interfaces.toml`（`source_modules += proc`、`public_api += proc::NO_PROC /
  proc::proc_residual / proc::job_residual / proc::proc_thread_exited`、`unsafe_scope += proc:U4`、
  `test_targets += t_proc_job_wait / t_q2_workload_slots`）；
  `unsafe-whitelist.toml`（`[modules."proc"] U4 = 3`、`sched` 的 U4 14→15、
  `[unsafe-census] total 336→340`、`U4 121→125`）；`unsafe-census.md` 汇总行与逐处小节；
  `lock-order.md` **零改动**（没有新锁级，也没有新嵌套）。

## 补记：落地时撞出来的四条（都是量具/用例侧，逐条带读数）

决策 1–10 的形状没变，但**用例要成立的前提**比草案多四条。每条都是某一档实测打回来的，
不是先想到的：

1. **登记启动上下文必须在任何 `spawn`/`yield` 之前**。链接顺序可能把本用例排在第一个
   "依赖任务上下文"的测试之前，那一刻 `current_of` 还是 `usize::MAX`，`yield_now` 的抢占点
   就在错误的槽位上记账。现场（`ahci-scratch` 档）：`runs_g=1` 而 `st_g=Running` 永不下降、
   `switches=0`、`active=1`，等待方一次都等不到，接着整机静默 45 s。
   把 `init_boot_task()`/`start_workers()` 从"等待之前"移到"用例第一句"之后，该档 **78/78 PASS**。
2. **排在时钟标定之前的档位里，`yield_now` 自己推不动换人**。`fault-resched-ipi` 档现场：
   `apic_ticks 0->0`、`sched_tick0=0`、`runs_g=0`、`st_g=Runnable`、`switches=0`——
   自陷只把牌立起来，真正换人发生在中断出口路过 `preempt_point` 的那一刻，而那时还没有 tick 源。
   修法与 `smp::bringup` 同一个入口：`clock::current().is_none()` 就补一次幂等标定
   （`crate::calibrate_clock_once()`），再自己 `timer_start()`、收尾还原。该档修完 **73/73 PASS**。
   ⇒ 决策 7 的"有界 + 推进"要读成"**有界 + 由 tick 驱动的推进**"，`yield` 只是让出，不是发动机。
3. **工人收工之后要让出，不能纯自旋**。`finish_current` 把状态标成 Done，但它还占着 CPU；
   `pick_next` 第二遍只在 prev 不再可运行时才回落 idle，而 idle 要等一次 tick 才能被换下。
   所以两个工人（`p3_worker`/`q2_worker`）的收尾循环都是 `loop { yield_now(); }`。
   纯自旋那版在停表档位里就是第 1/2 条现场的一部分。
4. **有界等待要先问"事件是不是已经发生了"，再决定要不要花那个窗口**。
   两条用例第一版都无条件调 `drain_reap()`，而回收早在窗口开始之前就地完成了
   ⇒ 每跑一次白烧 1G 周期（≈300 ms）客时，两条合计 ≈0.6 s，还各留一条
   `reap: 窗口内没看到回收` 的 warn（看起来像失败，其实不是）。
   改成 `reap_released() > 基线 || drain_reap()` 之后：warn 消失、正常构建启动用时 5.0 s → **4.2 s**，
   而矩阵里挂 `-d int` 的那一行不再被挤成 `HANG(-1)`（`-d int` 会把客时放大成墙钟，
   这条与 `docs/testing/p4-tolerance.md` 的"挂 `-d int` 的那一跑"同源）。

## 验收与负样本（全部为本轮实测）

| # | 判据 | 实测读数 | 负样本（变异证红） |
| --- | --- | --- | --- |
| A1 | 建 Job/进程、挂一条线程、等到收工、退出码读得到 | `proc(P3): 登记=true wait=true terminated=true code=0` | **MUT-P3b** 拿掉 `finish_current` 的收工边 ⇒ `terminated=false`、`release=false`，且残留进程被收尾判据点名（98 条 fatal） |
| A2 | 进程数额度：僵尸仍占额度 ⇒ 第二个能建、第三个 `QuotaProcs` | `quota=true`、`job_used_procs == Some(2)` | **MUT-P3a** 去掉 `used_procs >= max_procs` 检查 ⇒ `quota=false`（②格独红），残留 1 进程/1 Job 被点名，下游 51 格红 |
| A3 | 子 Job 额度只能收窄（进程数、页数各一条） | `narrow=true`（放大进程数 ⇒ Denied，放大页数 ⇒ Denied，两项都收 ⇒ ok） | 未单独跑变异；这一格的检查与 A2 是同一条代码路径的另一半，页数量格随 P4 一起证（§决策 9） |
| A4 | 两种还槽的分界：僵尸走 `proc_reap`（带回退出码）、没起线程的走 `proc_discard`，走反了一律拒 | `release=true`（`reap(running)=Denied`、`discard(zombie)=Denied`、`reap(zombie)=Ok(0)`、`discard(已收)=NoSuchProc`） | **MUT-P3c** 去掉 `proc_discard` 的状态闸 ⇒ 只有 `release=false`，其余全绿（76 条里 failed=1，红得很干净） |
| A5 | 造的进程/Job 必须自己收干净（ADR-069 同律） | `baseline=(pc0 jc0)`、收尾门本轮无 fatal | A2/A1 两条变异的副产物就是这一格的证人：`用例收尾不变量破坏：test=t_proc_job_wait 之后仍有 1 个进程记录没交出去（首个 #2）` |
| A6 | `wait_for_task` 的失败结局是超时而不是 L4 | `wait=true`（收工在 8 个窗内到达）；超时路径本轮**未验证**（要一个永不收工的工人，留给 P6 与唤醒边同批做） | — |
| A7 | 等待必须在开着的 IF 窗口里（ADR-068 的前置） | 第一版没包 ⇒ **整机 HANG，qemu_rc=-1，120 s**；包上之后 `wait=true` | 这一格的红就是第一版那次 HANG，已发生、已修；不另设变异 |
| A8 | 参考 workload 的容量读数（Q2） | `请求=7 成功=4 拒绝=3 峰值同活=4 active基线=7 active峰值=11 收工=4 收尸=3 回滚=1` | **MUT-P3d** 让 `spawn` 满槽路径 `forget(owned)` ⇒ 只有 `rollback=false`（`free116224->116212`、`va23->26`），failed=1。反证今天这条失败路径的回滚是真的 |
| A9 | 额度可见性：`used_procs` 与收尸数对得上 | `job_used_procs(job) == Some(0)`、`收尸=3 + 回滚=1 == 4 个进程` | A1 变异下这一格同时红（`reaped=0`） |
| A10 | 门禁与矩阵：`check` 17/17、`ktests` 76/76、判定 PASS=33、**矩阵 45/45 全符合**、`bench` 4/4 | 本轮 run-of-record（同一个代码状态，ELF `a3176d6b1919`）：`check` rc=0（17 道全 ok）；矩阵 `test` rc=0、45 行全"符合"（`.scratch/p3-test-final.log`）；`bench` rc=0、四把尺子全"能分辨=符合"、P4 地板 0.89 %、P1 同构建地板 1010 周期（`baselines/2026-11-09T09-37-44Z-p3p4.txt`） | `check-interface-change` 在 ADR 落地前红（`module-interfaces.toml` 有改动而工作树无 ADR），落地后转绿——这条就是"接口变更先有决策"的证人 |
| A11 | 用例自足：换一个链接顺序/故障档位也成立 | 四档各跑一遍：normal **76/76**、`fault-resched-ipi` **73/73**、`ahci-scratch` **78/78**、`fault-ahci-highlba` 两条 P3 用例全绿（该档唯一红的是它自己的负样本 `t_ahci_high_lba`，期望就是 FAIL） | 补记的四条前提各自都有一次"不满足就红/挂"的现场读数（`runs=1/st=Running/switches=0`、`apic_ticks 0->0`、`HANG 45 s`、`-d int` 行 `HANG(-1)`） |

涉及硬件的部分仍然只能验协议：本轮没有新的 TLB/设备结论，A8 的"回滚"格读的是内核自己的
`free frames` 与 `reservations` 两个计数，第二台仪器（宿主机侧）本轮未接——写"未验证"。

### 取证方法的一条修正（本轮现场）

`还原 = 同一个 ELF sha` 这条证人**不成立**：`proc_discard` 里一个 `if` 条件折行（多一行、语义不变）
就把 sha 从 `46ca075fb32f` 变成 `2ee917cce9f8`，而**同一份代码连续两次构建的 sha 相同**
（`touch` 之后重建实测一致）。原因是 debug 构建里行号进了调试信息，而 `check`/判定链吃的是 ELF 摘要。
所以本轮起：**变异还原的证人改用"逐格读数一致 + 判定 PASS"**，sha 只用来确认"这一次跑的 ELF 就是这一次构建的"。
另外本轮实测还有一次 `free frames` 绝对值随 ELF 体积变化（116262 ↔ 116275）——
跨轮比这一格只能比"回到自己本轮的基线"，不能比大小（BACKLOG 79g-4 那条口径的具体化）。

## 迁移与回滚

- `proc.rs` 是纯新增，其余全是三处收工点 + 一处槽位释放 + 收尾扫描四格 + 用例两条。
  回滚顺序：撤收尾判据的两本账 → 撤 `finish_sweep` 的四格 → 撤三个收工边与 `terminate_task` 的
  `proc_id` 清理 → 删 `proc.rs` 与两条用例 → 撤登记面。**没有不可回滚的部分**：
  ADR-069 的常驻名单与本轮的四格是并列的两本账，撤一边不影响另一边。
- 不做迁移：今天没有任何用户态或持久状态依赖进程记录的存在。

## 未决

1. **`MAX_THREADS_PER_CPU` / `MAX_PROCESSES` 的终值**（Q2 的裁决要求"最大观测值 + 余量"）：
   实测显示参考形状需要 9 格 > `MAX_TASKS = 8`。**要不要把 `MAX_TASKS` 提上去（以及提到几）
   留给使用者裁**，因为它同时牵动 ADR-041 的编译期断言、VA 前沿、`.bss` 与 bench 的 P1 地板。
   候选与代价：9 = 刚好够、零余量；12 = 余量 3 格，`.bss` 与 VA 保留各 +50 %；16 = 翻倍，
   `MAX_TASKS_TOTAL` 64→128，收尾扫描与句柄世代的口径要重看。
2. **唤醒边（`TASK_QID`）**：本轮只有"置 signal"这一半，等待是轮询 ⇒ 最坏延迟一次 tick。
   随 P6 的 `object_wait` 落地，同批补"去掉唤醒 ⇒ 结局格红"的变异（ADR-071 的 B1）。
3. **signal 对外的宽度**：内核侧已定（决策 3），19 号调用暴露给用户态时的位宽与"被杀"的编码
   仍未裁（ADR-071 未决 1 的对外那一半）。
4. **进程级常驻名单**（ADR-071 决策 4 的后半）：今天常驻进程数为 0，格没开。
   init 进产品启动路径时（P7）必须开，并配一条"忘记登记 ⇒ 注入格点名"的负样本。
5. **跨 CPU 登记**：`set_proc_id` 只允许登记本 CPU 的任务（`QueueCell` 的"每 CPU 队列只由本 CPU 写"）。
   有迁移之后这条要重开，届时 `gidx` 与进程归属的关系要一起写。
6. **页数额度**（§决策 9）：随 P4 的 `aspace_map`/VMO 落地并单独证红。
7. **台账格的顺序盲区**：`t_resource_ledger_balanced` 在链接顺序上排在
   `t_q2_workload_slots` **之前**，所以 A8 的变异（满槽泄漏）不会被它抓到——
   本轮它确实是绿的（`live=395 violation=false`）。要不要把台账格挪到全部用例之后重算，
   属于"量具的排布"问题，未做（改它要动 `ktest` 段的顺序口径，AGENTS.md 明写逐行 diff 类判据要先归一）。
