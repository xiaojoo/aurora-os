# ADR-075：每进程一份 AS、`thread_create`/`process_start` 与 `StartupInfo` 的内核回填

状态：提议（2026-11-09，W3 P5 开工前草案；**本文只有设计，无实测读数**，落地时按 ADR-070/073/074 的同一办法回填）
关联：ADR-007（capability 与裁决 E）、ADR-027（释放推迟到"不是它"）、ADR-041/065（VA 保留表归 memory、定长 256）、
ADR-044（环内边棘轮）、ADR-047 决策 2 / ADR-048 决策 3（持锁不跨未知回调、拿队列锁不等跨 CPU 的锁）、
ADR-070（每进程一份 PML4、内核半区冻结、不做 PCID/KPTI）、ADR-071（等待与上限分开）、
ADR-072（shootdown 按位图收窄）、ADR-073（Process/Job 与僵尸结局）、ADR-074（VMO 与句柄表只存引用）、
手册 §5.2/§6.4/§6.6/§7.2、设计文档 §10.1–10.6（**未跟踪**，本文引用它但不改它）、
`docs/design/w3-立项-依赖图与切片计划.md` §3 的 P5 与 §4 的 Q1/Q8、BACKLOG §154/§155

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计。本文与既有裁决冲突的地方
> **逐条列在"未决"里**，不自行改动已验证的结论；每条结论标「实测」「推断」或「设计」。

## 背景：今天缺的四件事，各有可核对的证据

1. **进程还没有自己的地址空间**。`proc.rs` 的 `ProcEntry` 只有 `used/job/threads/signal`
   （ADR-073），**没有 AS 字段**；`mm::aspace_new` 造出来的 AS 今天只有 ktest 在用。
   调度路径**一次 CR3 都不写**：`sched.rs`/`trap.rs` 里没有任何 `aspace_switch` 调用点（实测 grep 为零），
   所以"每进程一份 PML4"这件事在 P1 只证明了机制，还没接进换人路径。
2. **句柄表只有两种对象引用**。`ObjRef = File(FileObj) | Vmo { slot }`（ADR-074），
   没有 `Job`/`Proc`/`ASpace`/`Thread`；`RIGHT_TRANSFER = 16` 这个位早就定义了（`handle.rs:37`），
   但**没有任何 transfer 函数**（实测 grep 只有常量定义那一处）。
3. **用户任务的入口不能带参数**。`spawn_user(entry_rip, user_stack_top, res)`（`sched.rs:1309`）
   合成的首帧里 `rdi` 是 0（`frame` 数组全零起底），而设计 §10.2 要求"新线程第一条指令时
   `rdi` = `StartupInfo` 的用户 VA"。
4. `StartupInfo` 与角色编号**在代码里一处都没有**（实测 grep `MAX_STARTUP`/`NS_ROOT`/`SELF_PROC` 为零）。
   另有一处结构性冲突：`TRAMPOLINE_VA = mm::USER_VA_TOP - PAGE`（`user.rs:455`）是**全局唯一**的一个 VA，
   靠 `reserve_va_at` 占住（`user.rs:470`）；而 VA 保留表按 Q5/3a 的裁决是**全局一张**，
   所以"每进程一份 AS、各自在同一 VA 上映射跳板"会在保留表里撞车（未决 2）。

已经有的地基（本文不重做）：P1 的 AS 建/切/销与内核半区等价、P2 的按位图收窄 shootdown、
P3 的 Process/Job 与 `wait_for_task`、P4 的 VMO/`aspace_map`/句柄两段式释放、
P4b 的 12/13/14 三个号、P5-0 的两道门禁扫全部成员。

## 决策（草案）

### 1. 分三刀落地，每刀独立过门禁

P5 的目标形状一次做完会同时动"换人热路径 + 句柄对象种类 + ABI + 新产物"，红了分不清成因。
所以切成三刀，顺序有依赖：

| 刀 | 范围 | 为什么它能独立验 |
| --- | --- | --- |
| **P5a** | 新 `user/<probe>` 产物 + 第二套构建常量与夹具 + 登记面（crates.toml / license.pending / sbom / 新包的 unsafe） | 不改内核语义：它只是给已有的 12/13/14 一个**真 ring3 调用方**。判据是"新产物自己打三个号并读回"，与既有 hello.elf 的 6 行判据来路无关 |
| **P5b** | 每进程一份 AS 接进换人路径：`Task` 加 AS 归属、换人时按"不同才写 CR3"、跳板与保留表的冲突处置、进程退出时还 AS | 内核侧 ktest 就能证（两个 AS 同 VA 互不影响、CR3 写次数、退出回基线），**不需要新 syscall** |
| **P5c** | 句柄的四种新 kind + 11 `process_create` / 15 `thread_create` / 16 `process_start` + `StartupInfo` 回填与转移 | 由 P5a 的产物在 ring3 真打；判据取设计 §10.5 那五条 |

**11 `process_create` 归 P5c**（不是 P5b）：它要返回 `proc` 与 `aspace` 两个**句柄**，
所以必须等句柄表有那两种 kind。设计 §10.3 的七步序列里它是第 1 步，但落地顺序上它依赖 P5b 的 AS 归属。

### 2. 每进程一份 AS：归属挂在 `Task` 上，换人时"不同才写"

- `Task` 新增 `as_slot: u8`（`NO_ASPACE = 0xFF` = 内核 AS）。**内核任务恒为 `NO_ASPACE`**，
  所以既有路径一次 CR3 都不多写（这是"矩阵 45 行不该变"的论证基础）。
- 换人点（`preempt_point` 里装 `TSS.rsp0` 的同一处）比较 `prev.as_slot` 与 `next.as_slot`：
  不同才调 `mm::aspace_switch(pml4, me)`（ADR-070 A2 的"只在不同时变"已经有计数与负样本）。
  **CR3 写落在 P1 尺子的被测区间里**（与 `RSP0_WRITES` 同一处），所以 Q4 的"跨 AS 那一格"从这一刀起有真读数。
- 不做 PCID、不做 KPTI（Q6 已裁）⇒ 每次跨 AS 切换是**全 TLB 冲刷**，代价单列一格，不许写成看起来免费。
- 进程的最后一条线程收工时由**内核**还 AS（ADR-071 决策 2 的那条顺序：等待者不做遍历）。
  归还顺序：先丢掉它名下的 `AspaceMapping`（清叶子 + 还帧参考 + 放手 VA），再丢 `AspaceHandle`
  （还它自己建的表页）——**反了会少一次清叶子**（ADR-074 已记这条契约）。
- `running_on` 位图由 `aspace_switch` 自己登记（P2 已落地，只增不减），所以跨 AS 的 shootdown
  收窄在 P5b 之后第一次有**产品路径**的多 CPU 样本。

### 3. `StartupInfo`：一页只读 VMO，句柄数值由内核回填

形状照设计 §10.2，**两侧独立声明同一组偏移**（照 `.slots` 那条成法，`user.rs` 的既有纪律）：

```text
StartupInfo { magic: u32, abi_major: u16, abi_minor: u16,
              nhandles: u32, args_off: u32, args_len: u32,
              handles: [HandleDesc; MAX_STARTUP_HANDLES] }
HandleDesc  { role: u32, kind: u32, handle: u64 }
```

- 页由**调用方**建（`vmo_create` + `vmo_write` 写 magic/args，`handles` 留空），映射进子 AS 时**只读**
  （`PageFlags::USER_R`，P4b 的 14 号已经能给只读）。内核回填走 VMO 的帧（HHDM），
  **不需要子 AS 的写权限**——这条是"只读页也能被内核填"的实现点。
- `process_start(proc, thread, startup_vmo, transfers[{role, handle}])` 的顺序**不可换**：
  ①校验（Job 额度、proc/thread 归属、startup 页形状与 magic）→ ②**原子地**转移句柄（改 owner + bump gen）
  → ③用转移后的**新句柄值**回填 `handles[]` 与 `nhandles` → ④置线程可运行 + `rdi = startup_va`。
  ②③ 任一步失败必须回滚②（把 owner 改回去、gen 再 bump 一次让中间态句柄失效），
  并按设计 §10.3 第 7 步回滚整条装载序列（帧、VA、句柄、Job 额度全部回基线）。
- **转移即失效**：发送方的旧句柄在②之后立刻 `Stale`（gen 已变），这条有现成的世代机制可用，
  不需要新计数器；判据要读 `counters().stale` 的增量而不是只看"父进程用不了"。
- 角色编号初版取设计 §10.2 那七个（`SELF_PROC`/`SELF_ASPACE`/`SELF_THREAD`/`PARENT_CHAN`/`LOG`/`NS_ROOT`/`JOB`），
  但 **P5c 只实现内核今天真有的对象**：`SELF_PROC`/`SELF_ASPACE`/`SELF_THREAD`/`JOB`。
  `PARENT_CHAN`（Channel 对象不存在）、`LOG`（控制台对象不存在）、`NS_ROOT`（要 FAT16+GPT 或 initramfs）
  **一律不传** ⇒ 按 §10.2 的语义"没传的角色就是不存在"，进程凭空取不到。
  这条要写进 ABI 文档，不许摆一个没人填的角色槽。
- `MAX_STARTUP_HANDLES` 初版 **8**（不是设计举例的 16）：今天能传的角色只有 4 个，
  句柄表本身也只有 16 格；取 8 是"接缝够用 + 余量一倍"，**欠 workload 依据**（未决 3）。

### 4. 句柄表：P5 仍用全局 16 格，转移 = 改 owner + bump gen

- `ObjRef` 增加 `Job { slot }` / `Proc { slot }` / `ASpace { slot }` / `Thread { gidx }` 四种 Copy 引用，
  本体分别住 `proc.rs`（Job/Proc）、`mm` 的 AS 表、`sched` 的任务表 —— **沿用 ADR-074 决策 1 的形状**：
  表里只存引用，归还发生在放掉 HANDLE(35) 之后。
- **不做每进程一张句柄表**（那是 W4 的事）：今天 `owner = (gidx, id)` 两格已经起到隔离作用，
  "移进新进程的表"= 把 owner 改成新进程主线程的两格 + bump gen。
  判据"子进程只拿到传给它的句柄"因此要这样证：子进程对**全表 16 格**逐个试 `dup`/`close`，
  只有 `StartupInfo` 里列出的那几个成功，其余回 `NotOwner`/`NoSuch`（**不是** `Stale`——
  别人的槽根本没发给它，这两种拒绝要分开数）。
- `process_create(job_handle)` 必须出示带 `CREATE` 的 Job 句柄。`CREATE` 是 Q7 裁的唯一新权限位，
  今天 `handle.rs` 还没有这个常量 ⇒ P5c 新增 `RIGHT_CREATE = 32`（`RIGHT_TRANSFER` 已占 16）。
  根 Job 只交给 init（设计 §10.1）；**今天没有 init**，所以 P5c 的根 Job 由 ktest/内核持有，
  产品启动路径不授予（与 ADR-007 第一刀同一姿态，不许写成"安全启动已接通"）。

### 5. `thread_create` 与入口参数

- `spawn_user` 增加一个 `arg: u64` 参数（写进首帧的 `rdi`），既有调用点传 0 ⇒ 行为逐字不变。
  **不改 `gidx` 编码**（ADR-071 决策 3 的约束），线程仍是一个 `Task` 槽。
- `thread_create(proc, entry, sp, arg)` 的用户态形状：entry/sp/arg 都是**子 AS 里的用户 VA**，
  内核要校验它们落在该 AS 的用户半区且已映射（`mm::aspace_leaf` 是现成的第二台仪器，P4a 落地）。
  校验不过明确拒绝，不静默造一个跑起来就 `#PF` 的线程。
- 每 CPU 线程上限今天 = `MAX_TASKS = 9`（Q2 裁决、零余量），**且 Done 槽不回收的欠账还在**
  （BACKLOG §151：实测有效容量只有 5）⇒ P5c 的 spawn 炸弹用例要按"有效容量"写判据，
  不能按 9 写，否则红会落在回收欠账上而不是额度上。

## 备选方案

- **一刀做完 P5**：拒绝（决策 1）。换人热路径、句柄种类、ABI、新产物四件事一起动，
  红了之后归因成本远高于分三刀；而且 P5a 不改内核语义，可以先给 12/13/14 一个真 ring3 调用方。
- **每进程一张句柄表**：本轮拒绝（决策 4）。那是 W4 的对象模型，今天 `owner` 两格已经够隔离；
  提前做要同时改 `revoke_task`、`dup`、`close` 的查找口径与 16 格容量的语义。
- **`StartupInfo` 由父进程自己填句柄值**：拒绝。句柄值含世代号，转移之后才确定，
  父进程填不了（设计 §10.3 第 6 步的原话）；让它填就等于把世代号暴露成可预测的东西。
- **`StartupInfo` 映射成可写**：拒绝。子进程就能改自己的角色表（把 `NS_ROOT` 的句柄值改成别的槽），
  只读是这条协议的安全前提；内核回填走帧的 HHDM 别名，不需要子 AS 的写权限。
- **跳板搬进内核半区共享**：列为未决 2 的候选，不在本文自行裁决（它要动 ADR-070 的冻结前置）。
- **给"往别的 AS 按指定 VA 映射"新开一个号（20）**：列为未决 1 的候选。
  Q1 裁的是 11–19 九个号，追加 20 要重开那一题；本文倾向**兼容扩展 14 号的参数**而不是新号。

## 影响

- 正面：进程有了自己的地址空间与启动协议；`spawn` 可以在用户态组合（D1 的方案 A）；
  跨 AS 切换第一次有产品路径读数（Q4 的第二格）；句柄转移第一次有真语义。
- 负面/代价：
  1. **换人热路径多一次比较与可能的 CR3 写**：跨 AS 是全 TLB 冲刷（无 PCID），
     P1 尺子的均值会变，且按 Q4 要分成 same-as / cross-as 两格 ⇒ **与历史 P1 不可直接比**，
     第一次分格的那份基线头上要写这条（`p4-tolerance.md` 的既有纪律）。
  2. `Task` 多一个字段 ⇒ `.bss` 涨（每格约 4.3 KB 的 `Task`，8 颗核；BACKLOG §151 已记这笔账）。
  3. 句柄表多四种 kind ⇒ `close`/`dup`/`revoke` 的两段式要对每种 kind 各写一遍归还路径，
     而它们分别归 `proc`/`mm`/`sched` 三个模块管 ⇒ **HANDLE(35) 锁外要调三个模块**，
     锁序表那条"释放移到锁外"的注记要扩写（硬约束 4：先改表再改代码）。
  4. 14 号若按未决 1 兼容扩展，`ABI_MINOR` 要再 bump 一次，且 `user-abi-capability.md` §4.4 要同轮改。
- 登记面：`module-interfaces.toml`（新 kind 的 public_api、capability↔sched 的边）、
  `unsafe-whitelist.toml` 与 `unsafe-census.md`（新产物包的 unsafe，P5-0 之后门禁会真的扫到它）、
  `crates.toml` + 根 `Cargo.toml` + `license.pending` + `docs/release/sbom.json`、
  `lock-order.md`（HANDLE 锁外归还扩到三个模块）、`docs/design/user-abi-capability.md`、
  `docs/testing/p4-tolerance.md`（P1 分格）。

## 验收与负样本（设计；落地时同轮回填读数）

取设计 §10.5 的五条，加上本文新增的三条：

| # | 判据 | 负样本（变异证红） |
| --- | --- | --- |
| D1 | 子进程**只拿到传给它的句柄**：对全表 16 格逐个试 `dup`/`close`，只有 `StartupInfo` 列出的成功，其余 `NotOwner`/`NoSuch`（两种拒绝分开数） | 转移时不校验 owner ⇒ 子进程能操作父进程的槽，本格红 |
| D2 | **回填正确**：子进程读 `StartupInfo.handles` 里某个角色并真用它（P5c 用 `SELF_PROC`/`JOB`，因为 `NS_ROOT` 今天不存在） | `process_start` 不回填 ⇒ 子进程读到空句柄，红 |
| D3 | **转移即失效**：`process_start` 之后父进程用旧句柄 ⇒ `Stale`，且 `counters().stale` 增量对得上 | 转移后不 bump gen ⇒ 父进程还能用，红 |
| D4 | **中途失败回滚**：在装载序列第 3 步注入失败 ⇒ 帧、VA 保留、句柄、Job 额度全部回基线 | 去掉回滚 ⇒ 台账/保留表红（与 ADR-074 的 M8 同形） |
| D5 | **无 Job 不能造进程**：不带 `CREATE` 的 Job 句柄或额度已满 ⇒ 拒绝 | 去掉 `CREATE` 校验 ⇒ 无权限也能造，红；去掉额度检查 ⇒ spawn 炸弹红（ADR-073 的 M1 同形） |
| D6 | **W^X**：装载器试图映射 RWX ⇒ 拒绝 | 绕开 `PageFlags::new` ⇒ `t_wx_construction_rejected` 与 14 号那格双红（ADR-074 C5 已有证人） |
| D7 | **每进程 AS 隔离**：同一 VA 在两个进程里各自映射互不影响；`running_on` 只含真跑过它的 CPU | 换人时不写 CR3 ⇒ 子进程跑在父的表上，隔离格红；位图漏登记 ⇒ ADR-072 的收窄格红 |
| D8 | **CR3 只在不同 AS 时写**：同 AS 连续换人 N 次 ⇒ 写 0 次；跨 AS 一次 ⇒ 写 1 次 | 去掉"不同才写" ⇒ 计数变成 N（ADR-070 A2 的同一证人，本轮扩到产品路径） |
| D9 | **新产物自己打号**：`user/<probe>` 在 ring3 打 12/13/14 并读回，宿主机按它自己的 ELF 独立对账 | 探针不真打号（只内核侧模拟）⇒ 宿主机对账缺行，红 |

涉及 TLB 陈旧性的部分仍然只能验协议（TCG 观测不到），真机 M7 的待测清单要带 D7/D8 重做一遍。

## 迁移与回滚

- **P5a 可独立回滚**：删新包与第二套构建常量、撤登记面；`hello.elf` 与吃它 sha 的 6 行判据来路不变（Q8）。
- **P5b 回滚**：撤 `Task.as_slot` 与换人点的 CR3 写、撤跳板处置；`aspace_switch` 本身留在 mm（P1 的机制不动）。
  **不可回滚的部分**：一旦产品路径写过 CR3，P1 尺子的历史基线就断了一格（Q4 的分格），
  回滚代码也要在 `p4-tolerance.md` 上写明断裂点，不许把两段的均值混着比。
- **P5c 回滚**：撤三个号（**号标成保留而不是删掉**，Q1：号只追加永不复用）、撤四种 kind 与 transfer、
  撤 `StartupInfo`；`ABI_MINOR` 不回退（版本号单调），在 ABI 文档里记"这几个号已保留"。
- 迁移：既有 ktest 里"内核侧模拟 syscall"的用例（`t_vmo_syscalls` 等）在 P5a 之后**不删**，
  它们证的是内核侧判据；新产物证的是 ring3 真路径，两者是两台仪器，不互相替代。

## 未决（**需要裁决，本文不自行决定**）

1. **14 `aspace_map` 的参数要不要兼容扩展**。设计 §10.3 第 2 步要求
   `aspace_map(proc, vmo, va, rights)`——**指定 AS、指定 VA**（ELF 的 `p_vaddr` 是容器定死的）。
   而 ADR-074/P4b 已落地的 14 号是"映进自己的 AS、VA 由内核发"。两条路：
   - **(a) 兼容扩展 14**：`rdx` = AS 句柄（0 = 自己的）、`r10` = 请求 VA（0 = 内核发）。
     既有调用方两个寄存器都传 0 ⇒ 行为不变；号不复用、`ABI_MINOR` bump。**本文倾向这条**。
   - **(b) 新开 20 号**：语义清晰但要重开 Q1（11–19 已裁完）。
   这条不定下来，P5c 的用户态装载器就没有合法的映射入口。
2. **跳板（`TRAMPOLINE_VA`）在多 AS 下怎么放**。今天是全局一个 VA + 全局保留表占位（`user.rs:455/470`）。
   - **(a) 每 AS 一份、各自占用保留表里不同的 VA**：保留表是全局一张（3a 裁决），
     所以 N 个进程要 N 条保留 ⇒ 256 格的表被跳板吃掉 N 格，且 `TRAMPOLINE_VA` 不再是常量。
   - **(b) 搬进内核半区共享一份**（`USER_RX`，ring3 可达）：所有 AS 的内核半区本来就共享下层表，
     一份就够；但它在 boot 期映射、**必须早于第一个 AS 创建**（否则撞 ADR-070 的冻结闸），
     而且要确认 SYSCALL/SYSRET 与 kill 落脚处的论证在"内核半区的用户可达页"上仍然成立。
   - **(c) 每 AS 一份但走"按地址登记"且不占保留表**：等于给保留表开例外，本文不推荐。
   这条属于 ADR-070 的冻结语义与 ADR-025 的 swapgs 窗口，**要单独裁**。
3. **`MAX_STARTUP_HANDLES` 的取值**：本文提议 8（今天只有 4 个角色真能传），
   设计举例是 16，而句柄表本身只有 16 格。取值与"每进程句柄表上限"（W4）绑定，欠 workload 依据。
4. **`CREATE` 权限位与根 Job 的授予**：Q7 裁了"CREATE 是唯一新权限位"，但**根 Job 交给谁**今天没有 init。
   P5c 由 ktest/内核持有 ⇒ 产品启动路径不授予。要不要在 P5 就造一个最小 init（设计 §10.4 说 init 来自签名包/initramfs），
   还是留到 P7，需要裁。
5. **`process_start` 的原子性边界**：②转移与③回填跨两个模块（handle 表与 VMO 帧），
   今天没有一把锁能同时盖住两者。本文的处置是"顺序 + 失败回滚"，**不是真原子**：
   在②③之间另一个 CPU 能看到"句柄已转移但 StartupInfo 还没填"的中间态。
   子线程此时还没被置可运行（④在最后），所以**它看不到中间态**；但父进程若并发查询自己的旧句柄会看到 `Stale`。
   这条够不够称作"原子地转移"（设计 §10.3 第 6 步的原话），要裁；要真原子就得引入一把覆盖两者的锁或一个提交标记。
6. **Done 槽回收欠账与线程上限**：Q2 裁的 9 格是零余量，而实测有效容量只有 5（BACKLOG §151）。
   P5c 的 spawn 用例按哪个数写判据？本文主张按"有效容量"并把欠账显式写进读数，
   但这也意味着**上限那笔账在 P6 之前都不算结清**。
7. **`Thread` 对象要不要独立句柄**：设计 §10.6 第 3 条把 `thread_wait` 列为"由用例逼出来再定"。
   Q3 已裁通用 `object_wait`（19 号，P6），所以线程级等待免费得到；但 `Thread` 作为一种 kind
   是否要在 P5c 就发句柄（还是只用 `gidx` 内部标识），本文提议**只内部标识**，等 P6 真需要 wait 它时再发。
