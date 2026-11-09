# ADR-071：内核线程能等待、Done 槽的回收有确定时刻、任务槽上限与进程上限分开

状态：**部分采纳**（2026-11-09 立项为草案；同日 W3 P3 落了决策 1 的"置 signal"那一半、
决策 2 的"确定回收时刻"判据、决策 4 的进程/Job 那本账；**决策 3 只交付了 workload 实测，
数值待使用者裁；`TASK_QID` 与唤醒边未落地**，所以本文还不升"已采纳"。读数在 ADR-073 与本文补记）
关联：ADR-050/061/069（用例收尾的三类残留）、ADR-051/052（兜底 idle 与"没人可换"）、
ADR-053/054/058/059（等待队列单调用协议、世代 token、定时器轮、`wait_while_until`）、
ADR-027（释放推迟到"不是它"）、ADR-063（FrameInfo）、ADR-070（`AddressSpace`/`Process`）、
手册 §6.6/§7.1、设计文档 §10.6 第 3/4 条

## 背景：三件事各自卡在哪

**一、内核里今天没有"等一个任务结束"的原语。**
- 最接近的是 `wait_for_boot_task`，而它是**纯自旋**（`sched.rs:1377-1386`），
  既不看等待队列也不看轮，超时就是烧 cycles。ktest 里"等搭档收工"全靠这种自旋或 `yield` 环
  （`ktests/mm.rs` 的 `dz_wait_free` 就是 40 次 `yield_now` + `wait_ticks`）。
- `WaitQueue` 用不了：`wait_while` 要求 `me != usize::MAX`，否则 `NotInstalled`（`sync.rs:199`），
  也就是**只有正在被调度的任务**能等。启动上下文（slot 0，`init_boot_task` 的 `Running`）
  在等待队列眼里不是"一个能阻塞的任务"。
- `process_wait`（W3 的八个原语之一）要等的正是"某个进程的最后一条线程收工"，
  而收工的三个出口 `finish_current`（`sched.rs:1394-1397`）、`kill_current`（`sched.rs:1404-1409`）、
  `trampoline` 收尾标 `Done`（`sched.rs:1346`）**今天都不唤醒任何人**。
  所以 `process_wait` 落地的第一步不是加 syscall，而是补这条唤醒边。

**二、`Done` 槽的回收时刻是"顺手"而不是"确定"。**
`reap` 在抢占点扫一遍，`skip = current`（`sched.rs:299-349`、`sched.rs:325`），
顺手做句柄回收 `handle::revoke_task`（`sched.rs:333`）。单任务模型下"顺手"没问题；
一旦 `process_wait` 返回**必须**意味着"槽与名下资源已经不再是它的"，
调用方紧接着就要读台账判断"回基线"，而"下一次不知道哪个上下文跑起来时才收"这件事
让验收写不出来。ADR-027 决策 3 那条不变量（**释放推迟到本 CPU 上跑的不是它**）不能放宽，
所以这里要的不是"立刻释放"，而是"**在等待者醒来之前，已经有一个确定的时刻把该做的都做完**"。

**三、任务槽的上限同时是进程数的上限，而这两个数不该绑在一起。**
- `MAX_TASKS = 8` **每 CPU**（`sched.rs:28`），`MAX_TASKS_TOTAL = 8 × MAX_CPUS = 32`（`sched.rs:32`），
  静态数组 `[Task; MAX_TASKS]` 每 CPU 一份（`sched.rs:371-376`），空闲槽是 find-first-free
  （`sched.rs:1235`、`sched.rs:1294`）。
- `AGENTS.md:105` 的已知脆性里写着 `MAX_CPUS = 8`、`MAX_OWNED = 8`；
  `sched.rs:30` 还有一条编译期断言 `MAX_TASKS <= mm::MAX_TASKS_SUPPORTED`（`mm.rs:72`）——
  任务数与**VA 前沿容量**绑着，动一个要同时看另一个（ADR-065 把保留表扩到 256 格正是为了这个）。
- 一个进程至少 1 条线程，`spawn` 又只能挂在**调用者所在 CPU**（`sched.rs:7-9` 的头注释写明
  今天没有迁移），所以"8 个进程"今天意味着每 CPU 只剩 7 格给别的用例用——
  `t_finish_sweep_names_worker` 一次注入 4 个工人就已经把这件事量出来了（ADR-069）。
- `gidx` 的编码 `(cpu, slot)`（`sched.rs:39-51`）**被句柄与台账吃进去了**：
  `Entry { owner_gidx, owner_id }`（`handle.rs:112-129`）、句柄值的 `slot:u16 + gen:u48`。
  所以任何"槽位改小/改大/改语义"的动法都会牵动句柄世代的口径，这不是可以直接改的数。

## 决策（草案，待验收）

### 1. 等待：内核侧 `wait_for_task`，用户侧**通用** `object_wait`（Q3 已裁决，2026-11-09）

使用者按主流口径选了通用对象等待（Zircon `zx_object_wait_async` / Linux `pidfd_open`+`waitid(P_PIDFD)` /
Windows `WaitForSingleObject`+`GetExitCodeProcess`），所以**原语从八个变九个**：
`object_wait(handle, signals, deadline) -> (observed_signals, exit_code)` 占 **19 号**，
`process_wait`（17 号）与将来的 `thread_wait` 都是它的薄壳。退出码由 signal 带出，
不另开一个"取退出码"的调用。设计文档 §10 的"八原语"因此需要勘误（那份文档未跟踪，
差异记在 `docs/design/w3-立项-依赖图与切片计划.md` §6 与 BACKLOG §146）。

内核侧的地基仍然是这一条：

- 复用 ADR-054/059 已验证的形状：**一个 token 同时挂在等待链与轮项上**，
  条件唤醒与到期唤醒谁先到都认，后到者返回 false。
- 新增一个保留队列号（与 `TIMER_QID = u8::MAX` 同一手法）`TASK_QID`，
  被等待者的 `Blocked` 槽注册在它上面；三个收工出口（`finish_current`/`kill_current`/
  `trampoline` 的 `Done`）都必须唤醒 `TASK_QID` 上的等待者，**并把对象的 signal 置成
  `TERMINATED` + 退出码**——`object_wait` 等的就是这个 signal，不是任务槽的状态。
  这条顺序很重要：先置 signal 再唤醒，否则等待者醒来会看到"醒了但没有 signal"的空转
  （ADR-054 的"单调用协议防空转"就是防这个）。
- **允许启动上下文等待**：这就要放开 `sync.rs:199` 那条 `me == usize::MAX ⇒ NotInstalled`。
  本文的取舍是：**不放开 `WaitQueue`**，而是给 `wait_for_task` 一条自己的阻塞路径
  （调用者 = 本 CPU 的当前槽，`block_current(token)` 已经存在，`sched.rs:790-800`），
  等与醒都走 scheduler，不走 `WaitQueue` 的 16×16 槽位表。
  理由：`WaitQueue` 的槽是给"用户任务条件变量"用的，把内核等待塞进去会让
  "队列满"这种业务错误码去承载内核契约违例，两种错误的升级级别不同（§7.1 的错误分类）。
- 时限必须有界（继承 ADR-059 决策 3、`SHOOTDOWN_DEADLINE` 那条口径）：
  `wait_for_task` 超时返回 `TimedOut`，**不升 L4**——因为"目标进程永远不收工"是业务事实而不是契约违例；
  但**等待时长超过一个已声明的上界**要能被 watchdog 看到（§9.6 那本账已经在数窗口）。
- 上下文约束：调用者必须在 KERNEL/BOOT 且**不持任何锁**（等待会放锁，放锁后切走，ADR-053）；
  故障/中断路径不许调用。

### 2. `Done` 槽的确定回收时刻

- 定义**两条**时刻并写清谁负责：
  ① **收工点**（本 CPU 上该任务最后一次交出 CPU：`finish_current`/`kill_current`/`trampoline`）
     ⇒ 此刻起它的 `state` 是 `Done`/`Free`，且**必须已经**把自己从等待链与轮里摘干净
     （ADR-061 决策 1/2 的形状，`sched.rs:238-243`）。
  ② **回收点**（`reap` 在下一次"跑的不是它"时） ⇒ 释放名下资源、回收句柄、清 `resident`
     （ADR-069 已经要求清）。
- `process_wait` 的契约写成"**返回时 ① 已完成，且②要么已完成要么被显式登记为待收**"，
  并把"待收"计数暴露成读数（今天 `REAP_PENDING`/`reap_released` 已经有这两个数，
  `drain_reap` 就是等它涨，`ktests/common.rs:35-53`）。
  这样验收可以写："wait 返回 + 一次 `drain_reap` ⇒ 台账必须回基线"，而不是赌抢占点何时发生。
- 最后一条线程的进程：①之后由**内核**（不是等待者）负责把该进程名下 AS 的引用计数减一；
  等待者醒来看到的是"已经没有线程可选中"，不做遍历。这条顺序很重要，否则等待者
  会在别的 CPU 还在跑该进程的线程时提前减引用。

### 3. 上限分开：`MAX_THREADS_PER_CPU` 与 `MAX_PROCESSES`（Q2 已裁决：先实测再定数）

- **本文不做动态任务表**，也**不改 `gidx` 编码**（编码一动，句柄世代、台账、收尾名单三处口径同时变，
  属于 ADR-069/`handle.rs` 的账，不该搭在 W3 第一刀上）。
- **数值不拍**（使用者裁定）：P3 开工前先加一条 workload 用例（init + 3 子进程 × 2 线程），
  量"每 CPU 同时存活线程数"的最大观测值，再按**最大观测值 + 余量**定
  `MAX_THREADS_PER_CPU` 与 `MAX_PROCESSES`，写回本 ADR 的补记。
  下面那句"从 8 提到 16"是**举例说明绑定关系**，不是裁决出来的数。
- 做法（**数值是举例，等 workload 实测回填**）：`MAX_TASKS` 从 8 提到某个实测值（例如 16），
  同时新增独立的 `MAX_PROCESSES`（例如 8）与一张定长进程表；编译期断言那条
  （`sched.rs:30` ⇒ `mm::MAX_TASKS_SUPPORTED`，`mm.rs:72`）要一起重算，
  并且**必须重新量 VA 前沿**：按"每 CPU 16 线程 × 每线程 2 页栈"这种量级估，
  与 ADR-065 的 256 格保留表第一次真正接近上限，这条要写成 P3 的前置而不是"到时候再说"。
- 提上限的**依据必须是 workload**，不是拍数：ADR-054 的口径是"上限由 workload 钉出来"，
  而 `WHEEL_SLOTS = 64`、`MAX_OWNED = 8` 今天都还欠着这条（`AGENTS.md` 的已知脆性）。
  本文要求 P3 之前先有一次实测："一个 init + 三个子进程、每个两条线程" 这种形状下
  每 CPU 实际同时存活多少条线程，取**最大观测值 + 余量**，写回 ADR 补记。
- 静态数组变大 ⇒ `.bss` 涨；`Task` 结构里有 `owned: OwnedSet`（8 条）与若干 u64，
  这条要给出台账读数（`free frames` 那一行今天就在报，`mm: … free frames now 128794`）。

### 4. 与收尾判据（ADR-069）的接口

- 线程不是常驻工人 ⇒ 用例造出来的线程/进程必须在用例内收干净，否则第一个 checkpoint 点名。
- **进程表也要有"显式名单"**：`init` 的进程与内核自带的进程（如果有）是常驻身份，
  与 `resident` 同一规则、同一红法。今天 `resident` 挂在 `Task` 上，进程级要另开一格
  （`Process::resident`），不许用"它是内核任务"这种 blanket 理由。

## 备选方案

- **直接放开 `WaitQueue` 让 boot 上下文也能等**：拒绝（决策 1）。业务错误码与内核契约违例
  混在一本账上，§7.1 的错误分类就废了。
- **`process_wait` 用自旋轮询 `state_of`**：拒绝。`wait_for_boot_task` 那种形状
  （`sched.rs:1377-1386`）在停表时一次都不推进，而"等待期间不许别人前进"正是今天
  某些用例的常态（`t_if_belongs_to_cpu` 会停表），会重演 §111 那一类挂死。
- **让等待者自己去回收槽位**：拒绝。等待者可能跑在**另一颗 CPU**，
  而释放必须在"本 CPU 上跑的不是它"之后（ADR-027 决策 3）——跨 CPU 释放正是 ADR-047 决策 2
  禁止的形状。
- **任务表改成堆上动态**：拒绝。全局分配器在 `LARGE_MAX = 2048` 之外要失败出口
  （ADR-018/026、`fault-heap-oom` 那条构建），把"能不能等一个进程"绑在堆上不划算，
  而且 `gidx` 与句柄世代的映射会失去定长数组这个前提。
- **把线程也做成句柄对象，`thread_wait` 先于 `process_wait`**：留作未决 Q3（设计文档 §10.6 第 3 条
  本来就挂着），本文不预先摆。

## 影响

- 正面：`process_wait` 有地基；回收有确定时刻 ⇒ 验收能写"回基线"；进程数与线程数不再互相挤。
- 负面/代价：①三个收工出口都要加一条唤醒边，收工路径变长（今天它是几条指令 + 一次让出）；
  ②`Task` 数组翻倍带来的 `.bss`/VA 前沿/保留表三本账要一起重算，最容易红的是
  `t_va_interval_table`（ADR-065）与 `t_resource_ledger_balanced`；
  ③`sync.rs:199` 的语义保持不变，但它意味着"内核等待"与"用户条件变量"是两条路，
  以后有人想合并要重新论证；④`resident` 与进程级名单是两份名单，多一处要登记。
- 登记面：`module-interfaces.toml` 要加 `sched::wait_for_task`（被 `proc`/`user` 在产品路径上引用时）、
  `sync`/`sched` 的 `public_api` 与依赖边；`lock-order.md` 里 `TASK_QID` 这条新嵌套
  （RUNQ 8 → 放锁 → 唤醒）要同轮写进去并配负样本（硬约束 4）。

## 验收与负样本（设计，落地时同轮换判据与负样本）

| # | 判据 | 负样本（变异证红） |
| --- | --- | --- |
| B1 | 等待者能在**有界时限**内被 `finish_current` 唤醒，且 `WaitOutcome` 分得出 `Condition`/`TimedOut` | 去掉收工出口的一条唤醒 ⇒ 只能等超时 ⇒ 结局格红（与 ADR-059 的 MUTATION-T3 同形） |
| B2 | `wait` 返回 + 一次 `drain_reap` ⇒ 台账、`reap_released`、句柄回收计数全部回基线 | 让等待者跨 CPU 就地释放 ⇒ `lock-order`/重入检测当场 L4，或 `order_violations` 涨 |
| B3 | 最后一条线程之外的线程退出时，进程 AS 的引用**不减** | 在每条线程收工处都减引用 ⇒ 另一个还在跑的线程当场 `#PF`（错因要在现场可读，否则判据算空） |
| B4 | `MAX_THREADS_PER_CPU` 提上去之后，`free frames`/`reservations`/`page_table_pages` 三本账都有读数，且 `MAX_TASKS <= mm::MAX_TASKS_SUPPORTED` 那条编译期断言重新算过 | 只提 `MAX_TASKS` 不动 VA 前沿 ⇒ 断言编译期就红（这条是" cheapest 的红"，先写断言再改数） |
| B5 | 用例造的线程/进程在收尾判据里必须清零；`init` 进程走显式名单 | 忘记登记 ⇒ ADR-069 的注入格形状复现（`stray` 被点名） |

## 迁移与回滚

- 回滚顺序：先撤 `MAX_TASKS` 与 `MAX_PROCESSES`（回到 8/无进程表），再撤 `wait_for_task`
  与三个唤醒边；`resident`/收尾判据不回滚（ADR-069 的结论与本文无关）。
- 迁移：任何"等一个任务"的 ktest 自旋环（`dz_wait_free` 一类）在 `wait_for_task` 落地后要改写，
  因为**等待条件变了**，那些用例的判据读数因此与历史不可比——这条要按 §12.4.1 规则 2 写清来路。

## 未决

**Q1–Q8 已由使用者裁决**（2026-11-09，逐条见 `docs/design/w3-立项-依赖图与切片计划.md` §4）。
与本文相关的三条已闭：Q3 ⇒ 通用 `object_wait`（决策 1 已改写，`thread_wait` 将来免费得到）；
Q2 ⇒ 上限先实测再定（决策 3 的数值改成举例）；Q7 ⇒ `Job` 额度只管**进程数 + 页数**
（落在 P3 的 ADR-073，不在本文）。仍然开着的是：

1. **signal 位布局与退出码宽度**：Q3 裁了"退出码由 signal 带出"，没裁位怎么分
   （Zircon 把退出码放在 signal 的高位）。今天 `kill_current`（`sched.rs:1404-1409`）只有"杀"没有码，
   所以宽度与"被杀"和"正常退出"怎么区分要在起草 19 号调用时一起定。
2. 任务槽与 `gidx` 编码的长期形状（进程/线程两套 id 还是同一套）；本文选择"不改编码"，
   但 `MAX_PROCESSES` 一旦超过 `MAX_TASKS_TOTAL` 就必须重开这条。
3. 跨 CPU 迁移仍未做（`sched.rs:7-9`）；`spawn` 只能建在调用者 CPU 上，
   这会让"一个进程的多条线程全挤在同一 CPU"成为默认形状，负载均衡是 W3 之后的事。
   **Q2 的 workload 实测要在这个前提下量**，否则量出来的"每 CPU 存活线程数"会偏小。
4. 真机：`TimedOut` 的上界与轮槽 64 都没有 workload 依据（ADR-059 未决 2 同一条）。
5. `object_wait` 的等待者上限：今天 `WaitQueue` 是 16 队列 × 16 等待者（`sync.rs:86-87`），
   而决策 1 刻意**不走**那张表；内核侧等待槽要另定一个数，同样欠 workload 依据。

## 补记（2026-11-09，W3 P3 实测之后）

草案与落地的差异只有四处，逐条写明，不改上面的原文：

1. **决策 1 只落了"置 signal"，没落"唤醒"**。三个收工出口现在都把自己的 `proc_id`
   换成"线程计数减一 + 最后一条置 `TERMINATED|码`"，但等待仍然是
   `wait_for_task` 的"有界 + `yield_now` 推进"轮询；`TASK_QID` 与唤醒边随 P6 的
   `object_wait` 一起落地并单独证红。⇒ 今天 `wait_for_task` 的最坏延迟是**一次 tick**，
   草案里"醒来即读到 signal"的顺序保证已经成立（决策见 ADR-073 决策 6：先置结局再摘牌）。
2. **决策 2 的"确定回收时刻"变成判据而不是契约**：`wait_for_task` 返回 + 一次 `drain_reap`
   ⇒ `reap_released` 必须涨、空闲帧与 VA 保留必须回本轮基线。实测两格都成立
   （`proc(P3)` 的 `released38->39`、`q2(P3)` 的 `free116238->116238 va23->23`）。
   就地回收那条路径不等窗口，所以判据靠**增量**认它（`drain_reap() || reap_released > released0`）。
3. **决策 3 的数值已裁并落地**（2026-11-09，使用者在 9 / 12 / 16 三个候选里选定 **9**）：
   `MAX_TASKS` 8 → **9**，`mm::MAX_TASKS_SUPPORTED` 同步 8 → 9（`sched.rs:30` 那条编译期断言
   因此重新成立），`MAX_TASKS_TOTAL` 64 → **72**。依据是 Q2 的算术：参考形状
   （init + 3 子进程 × 2 线程 = 7 条线程）+ boot 上下文 + 兜底 idle = **9 格，零余量**。
   三本账的实测代价（同一份代码只动这两个常数，ELF `a3176d6b1919` → `ba1a2e7edcb0`）：

   | 账 | 8 格 | 9 格 |
   | --- | --- | --- |
   | ELF 字节 | 5,334,112 | 5,368,768（**+34,656** = 8 颗 CPU 各多一个 `Task`） |
   | 收尾 `free frames` | 128,790 | 128,788（−2） |
   | 启动 `VA reservations in force` | 3 | 3 |
   | `page_table_pages` / `map_calls` / `mapped_pages` | 15 / 161 / 631 | 15 / 161 / 631 |

   VA 保留表仍是 ADR-065 的定长 **256**，不随任务数派生（9×8=72 条满配、每条 5 页也只用 72 格）。
   门禁与尺子：`check` **17/17**、矩阵 **45/45**、`ktests` **76/76**、`bench` **4/4**
   （P4 地板 2.32 %、P1 同构建地板 70 周期，`baselines/2026-11-09T09-53-04Z-p3p4.txt`）。
   **必须同时读的一条限制**：9 格只是算术上够。收尾那一跑实测
   `本CPU先占=4（其中 Done 待收=2）` ⇒ 有效容量 5，参考形状的 7 条线程只成功 **5** 条、拒绝 2 条。
   吃掉余量的不是这个常数，而是 BACKLOG ⑫ 那笔"内核任务 Done 槽不回收"的欠账
   （本文决策 2 / P6 要解的那条）。⇒ 结论只能写成：**上限提到 9 之后，参考 workload 能不能全装上
   取决于 Done 槽回收，而不是取决于这个数**；要真余量得重开 Q2。
4. **决策 4 的进程本账已开，进程级 `resident` 名单没开**：`finish_sweep` 多了
   `procs/first_proc` 与 `jobs/first_job`，用例之间那道门现在会点名"没交出去的进程记录"。
   常驻进程今天数量为 0，开一格空名单就是硬约束 2 禁止的东西；等 init 进产品启动路径（P7）再开。

另外两条本轮新发现，草案里没有：

- `proc_id` 必须是**一次性边令牌**（取走即置回 `NO_PROC`），并且 `terminate_task` 释放槽位时要
  清它——草案只要求清 `resident`。留着的效果是"复用这条槽的任务替别人的进程减了一次线程计数"，
  症状是那个进程永远等不到结局。
- **等待必须在开着的 IF 窗口里**（ADR-068）。草案写"调用者不持任何锁"就够了，
  实测不够：`wait_ticks` 返回时窗口关闭，工人带着 `IF=0` 跑，没有任何东西能把它抢占下来 ⇒
  整机 HANG（qemu_rc=-1，120 s）。判据的前置因此多一条，见 ADR-073 的 A7。
