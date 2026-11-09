# ADR-075：每进程一份 AS、`thread_create`/`process_start` 与 `StartupInfo` 的内核回填

状态：提议（2026-11-09 起草；**P5a 与 P5b 的跳板那一半已落地并回填读数**，见两份补记；P5b 的 AS 换人接线与 P5c 仍是设计，未验证）
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
  > **落地勘误（P5b 第二半，2026-11-09，见下面的补记）**：这一条比较的**基准写错了**。
  > 不能拿"上一个任务的记录"与实际 CR3 混着比：`set_aspace` 只改记录、不改 CR3，
  > 所以记录与实际可以不一致，按记录比会**漏写**。正确写法是拿**下一个任务的目标表**与
  > **实际 CR3** 比（即 `aspace_switch` 内部那条 `cur == pml4` 判据），代价是每次换人多一条特权读。
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
- `MAX_STARTUP_HANDLES` = **16**（使用者裁决，2026-11-10：选"照设计举例，不留返工"）。
  本文原先提议 8（"接缝够用 + 余量一倍"），改裁的理由是加角色不该再动一页布局与 ABI。
  **代价要一起写死**：表里会有 12 格永久为空，而"空槽"会被读成"该传但没传"。
  口径 ⇒ 读取方只许信 `handles[0..nhandles]`，`nhandles` 之后必须全零；
  `process_start` 校验"越界非零"直接拒绝，判据里要有一格专喂"nhandles 之后有垃圾"。
  `24 × 16 + 表头 24 = 408 ≤ 4096`，一页装得下。

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
  今天 `handle.rs` 还没有这个常量 ⇒ P5c 新增 `RIGHT_CREATE = 32`（`RIGHT_TRANSFER` 已占 16，**已落地 P5c-1**）。
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

### 6. 14 `aspace_map` 兼容扩展（使用者裁决，2026-11-09：选"兼容扩展"，不新开 20 号）

参数布局扩成四个，**既有调用方行为逐字不变**（它们传 `rdx=r10=0`、`rsi` 只有 bit0）：

| 寄存器 | 扩展后语义 | 传 0 / 旧值时 |
| --- | --- | --- |
| `rdi` | VMO 句柄 | 不变 |
| `rsi` | **flags 位图**：bit0 可写、bit1 可执行 | 旧调用方传 0/1 ⇒ 只有 bit0 ⇒ 与 P4b 的 `USER_R`/`USER_RW` 逐字相同 |
| `rdx` | AS 句柄（`ObjRef::ASpace`） | 0 = 调用者自己的 AS（今天 = `aspace_map_self`） |
| `r10` | 请求的用户 VA | 0 = 内核从动态区发（P4b 的行为） |

- **W+X 仍然在构造期拒绝**：`rsi` 的 bit0|bit1 同时置位 ⇒ 走 `PageFlags::new(true, true, true)` ⇒ `WxViolation` ⇒ `-1`。
- **勘误 ADR-074/P4b 的一句结论**：那里写"14 **永远不给 X**"。扩展形**可以给 X**（装载器要映 ELF 的 `RX` 代码段，
  设计 §10.3 第 2 步），只是不许同时给 W。旧行为（`rsi` 只有 bit0）仍然不给 X，所以已发布的调用方不受影响；
  `ABI_MINOR` 落地时再 bump 一次（6 → 7），`docs/design/user-abi-capability.md` §4.4 同轮改。
- **请求 VA 的校验**：必须页对齐、落在目标 AS 的用户半区（`idx(va,3) < 256`）、
  且经 `mm::reserve_va_at` 登记成功（全局一张保留表，3a 裁决）⇒ 与装载器窗口/别的进程的保留冲突时明确拒绝。
  这条是"ELF 的 `p_vaddr` 搬不动"与"两个主人不能同信一段 VA"的交点，不许静默改地址。
- **依赖顺序**：`rdx` 要认 `ObjRef::ASpace`，所以这个扩展**与 P5c 的四种 kind 同刀落地**，不提前。

### 7. 跳板搬进内核半区共享一份（使用者裁决，2026-11-09）

- `TRAMPOLINE_VA` 从"用户窗口顶端一页"改成**内核半区里一个固定 VA**，`USER_RX`（U/S=1 ⇒ ring3 可达），
  **boot 期映射一次**，所有 AS 共享：`aspace_new` 复制 PML4 高 256 项、下层表本来就共享（ADR-070 决策 2），
  所以子 AS 自动继承同一份跳板，**不占全局保留表的 N 格**。
- **必须在第一个非内核 AS 创建之前映射**：否则撞 ADR-070 的内核半区冻结闸。
  今天它在 `user::init()` 里映射，而 AS 只在 ktest/P5c 之后才创建 ⇒ 顺序天然成立，
  但这条要变成**判据**（映射失败/被冻结闸拒 ⇒ 明确 L4，不静默）。
- 要重验的三件事（落地时各配读数，不许只写"应该没问题"）：
  ①SYSCALL/SYSRET 快路径与 `swapgs` 窗口（ADR-025）在"内核半区的用户可达页"上仍成立；
  ②kill 的落脚处论证（`user.rs:394` 那条注释指向的正是 `TRAMPOLINE_VA`）；
  ③SMEP：内核**执行**一个 U/S=1 的页会故障——今天跳板也在用户窗口（同样 U/S=1），
  所以这条约束不变，但要确认没有任何内核路径跳进它。
- ADR-070 的 A1（内核半区逐项相等）**不受影响**：跳板在 boot 期就进了 `AS_KERNEL`，
  子 AS 复制的是同一批项；判据仍然逐位对照。

## 补记：P5a 落地（第二个用户产物，2026-11-09，实测）

决策 1 的第一刀已落地：`user/probe`（`aurora-user-probe`，bin 名 `probe`，26,264 字节，
sha `929bb4598f0e`），基址 **0x100080000** 与 hello 的 0x100000000 错开（两者都在加载器窗口
`[USER_VA_BASE, USER_MMAP_BASE)` 里 ⇒ 可以共存）。它真在 ring3 打 `abi_info` + 12/13/14，
自己从映射读回比对，把七个结果写进 `.slots`；**不自己 exit**（退出即回收、槽就读不到了），
由用例 `terminate_task` + 回收收场，走的是同一条 reap/revoke 路径。

**读数**（run-of-record：矩阵与 bench 同一代码状态，normal ELF `3861ba5f6916`）：
`check` **17/17**、`release` **符合**（sbom 三个成员）、矩阵 **45/45**、`handles` 档 ktests **81/81**、
`bench` **4/4**（P4 地板 **0.17 %**、P1 同构建地板 **1908** 周期，`baselines/2026-11-09T14-16-33Z-p3p4.txt`）。
```
probe(P5a): 魔数=true ABI位=true 句柄=true 写=true VA=true 自读回=true
            生效位=Some(user:true writable:true executable:false levels:4) 内核读回=true
            收场=(drained true free116071->116071 va21->21 live0->0 vmo0->0) served=4
```
变异 **M10**（探针不打 14）⇒ `VA=false 自读回=false 生效位=None 内核读回=false`、`served=3`、failed=1，
而收场格仍绿（VMO 与句柄照样归还）⇒ 红得很局部。

### P5a 撞出来的三件事（都不在草案里）

1. **旁观者终止不撤销句柄（真漏洞，已修）**。`terminate_task` 的"不在 CPU 上"分支就地
   `release_owned`，而句柄撤销只在 `reap` 里做；就地释放之后袋子空了 ⇒ `reap` 的 `has_bag` 闸
   把这一格跳过 ⇒ **句柄与它背后的 VMO/帧永远回不来**。第一版探针用例的收场格就是这么红的：
   `live0->1 vmo0->1 free 少 2 帧`（留档 `.scratch/p5a-revoke-leak-evidence.log`）。
   修法：在那个分支里、放掉 RUNQ 之后调 `revoke_task(task, dead_id)`（`id` 在锁内一并读出）。
   自退出路径不变（还在跑就撤销会让它手上的句柄当场失效，所以留给 reap）。
   **这条红→绿本身就是负样本**，不另造变异。
2. **链接期陷阱：基址在 4 GiB 之上时 `addr_of!(静态量)` 会退化成 `R_X86_64_32S`**。
   hello 的模块头记过这个坑，本轮实测又撞一次（`relocation out of range … references .rodata`）。
   改用 **RIP 相对 `lea`** 取 `.slots`/`.rodata` 基址（`slots_base()`/`src_addr()`），两处 asm 进 U1 账。
3. **`run` 不重建用户产物**：只有 `build`/`do_image` 会调 `do_build_user`/`do_build_probe`。
   还原探针源码之后直接 `run`，镜像被判"新鲜"（内核 sha 没变，因为夹具没变）⇒ 跑的还是变异那份。
   实测现场：还原后 `served=3`、ELF sha 与变异跑相同；先 `build` 再 `run` 才回到 `served=4`。
   ⇒ **改了用户程序必须先 `build`**（这条对 hello 同样成立，是既有行为，本轮才撞明白）。

### 登记面与规则改动

- 新包进 `Cargo.toml` members、`crates.toml`（`crate.` 与 `license.pending.` 各一条）、
   sbom 由 `release` 重生成（三个成员、外部 crate 仍 0）。
- unsafe：新包 **U1 6 / U5 3**，总数 355 → **364**。**分类规则改了一处**：原来写死
  `if module == "user/hello"`，新包会掉进 U2 兜底；改成 `module.starts_with("user/")`
  （按"类别判错了改规则、不改登记数去凑"的口径）。`user/hello` 的 U1 12 / U5 22 **一格未变**。
- **P5-0 留下的那一半证人本轮补上了**：登记之前 `check-unsafe` 报
  `aurora-user-probe: 有 9 处含 unsafe 的行但未登记` ⇒ 证明普查范围真的覆盖新包，
  不是只对既有的两个根生效。

## 补记：P5b 第一半落地（跳板搬进内核半区，2026-11-09，实测）

决策 7 已落地，**决策 2（AS 接进换人路径）还没做**——本节只覆盖跳板那一半，别把它读成 P5b 完成。

- `TRAMPOLINE_VA` 从 `USER_VA_TOP - PAGE` 改成 **`0xffff_ffff_6ff0_0000`**：内核半区、
  动态分配区上界（`0xffff_ffff_7000_0000`）之下一页，不在镜像（`0xffffffff80000000` 起）也不在 HHDM 里；
  `reserve_va_at` 占住之后分配器跳过它 ⇒ **一份共享、不占 N 条保留**。
- `ensure_trampoline()` 加**冻结前置**：`mm::aspace_count() != 0` 时明确拒绝并打 fatal
  （已有非内核 AS 之后再往内核半区铺新映射就是违反 ADR-070 决策 2），不靠调用顺序的运气。
- 决策 7 要求重验的三件事，读数如下（`handles` 档 **81/81**）：
  ①kill 落脚处：`user: killed=true kills=1 bad_state=Free runs=0 落脚页用户可达=true`；
  ②生效位：两处 `tramp_ok` 都绿（`user && executable && !writable`）；
  ③SYSCALL/SYSRET 与 swapgs 窗口：`abi: … served=35 分区=true 落脚页=true` 那一格绿，
  且全程无 SMEP 相关故障（内核没有执行过那一页）。
- **门禁与矩阵**：`check` 17/17；矩阵跑了**两次**：第一次 44/45，红的是挂 `-d int` 的
  "目的地由宿主机按 SP 数到"，成因 `L4 mm: shootdown 超时 va=0xffff800020597000 还差 1 个回执`；
  **同一 ELF（`ffa7a00ffa56`）复跑 45/45**。归因：仪器把 AP 的回执拖过 6 ms 上界
  （`p4-tolerance.md` 已有同源记录：挂 trace 的 30 跑里 3 跑标定被拒），
  **不归因到跳板改动**——超时那条 VA 是 HHDM 别名，跳板在 `0xffff_ffff_6ff0_0000`，两者无关。
- `bench` 4/4（P4 地板 1.35 %、P1 同构建地板 3981 周期，`baselines/2026-11-09T15-19-04Z-p3p4.txt`）。
- **未做/未验证**：冻结前置那条新规则的**负样本没做**——今天构造不出它的前提
  （`TRAMP` 一旦建好就幂等，而所有 AS 用例都自己收干净，所以"有 AS 且跳板未建"这个状态不可达）。
  它防的是将来有人把第一次 `ensure_trampoline` 挪到 AS 创建之后；要证红得加一个 test-only 的
  TRAMP 复位入口，本轮不加（那是为变异造 API）。**记为未验证，不写成已证。**

## 补记：P5b 第二半落地（AS 接进换人路径）+ 收尾（换人路径不碰 VMM），2026-11-10，实测

决策 2 已落地 ⇒ **P5b 完整**。落到的位置：`Task` 多 `as_slot: u8` / `as_pml4: u64`
（六处 `Task` 字面量全部初始化成 `NO_ASPACE`/`0`），`sched::set_aspace` / `aspace_of`，
`mm::aspace_pml4_of` / `mm::AspaceHandle::slot`，换人点在
[kernel/src/sched.rs:1781-1785](file:///H:/aurora-os/kernel/src/sched.rs#L1781-L1785)，
`terminate_task` 收身份时把 `as_slot`/`as_pml4` 一并清掉（身份随槽走，与 P3 的 `resident`/`proc_id` 同一条）。

- **登记与热路径分开**：`set_aspace` 在登记那一刻取一次 VMM 读根表（`aspace_pml4_of`），
  把根表与槽号一起缓存进 `Task`；换人点只读这两个 Copy 字段 ⇒ **换人路径上一次锁都不取**
  （RUNQ 自身除外）。`NO_ASPACE` 缓存成 `0`/`None`，所以**内核任务恒不写表**
  （决策 2 那句"既有路径一次 CR3 都不多写"实测成立，见下面 D8）。
- **草案那句"比较 `prev.as_slot` 与 `next.as_slot`"是错的**（已在决策 2 下面留了勘误指针）：
  `set_aspace` 只改记录、不改 CR3，记录与实际可以不一致 ⇒ 按记录比会**漏写**。
  最终写法是拿**下一个任务的目标表**与**实际 CR3** 比，比较留在 `aspace_switch` 内部那条
  `cur == pml4` 判据上；代价是每次换人多一条特权读 `CR3`，它落在 P1 区间里、如实计入。
- **本刀撞出来的第二条（使用者裁决"同轮修掉"）**：`aspace_switch` 原来在真的写表之后要取
  **VMM(20)** 去登记 `running_on`，而它的调用点之一 `preempt_point` 跑在 **IF=0** 的异常出口
  （[kernel/src/arch/x86_64/trap.rs:1124](file:///H:/aurora-os/kernel/src/arch/x86_64/trap.rs#L1124)，
  出口在 `iretq` 之前不 `sti`）。于是：别的 CPU 持 VMM 等 shootdown 回执 → 给本 CPU 发 IPI →
  本 CPU 卡在取 VMM 的自旋里、IF 一直是 0 → 取不到那枚 IPI → 互等到 6 ms 上界 ⇒ L4。
  这不是推演：M13（见下）把它跑成了实测的 `L4 mm: shootdown 超时`。
  **修法**：位图从 `AspaceEntry` 搬进 `static AS_ON: [AtomicU8; MAX_ADDR_SPACES]`
  （[kernel/src/mm.rs:1736](file:///H:/aurora-os/kernel/src/mm.rs#L1736)），
  `aspace_switch` 多收一个调用方本来就有的槽号，登记变成一次 `fetch_or`
  （[kernel/src/mm.rs:2139](file:///H:/aurora-os/kernel/src/mm.rs#L2139)）。复位只在 `aspace_new`
  发布槽位之前，所以不存在"复位吃掉并发登记"的窗口；最坏只会把 IPI 集合**放宽**，不会漏。
  规则与两条证据写进 `docs/architecture/lock-order.md` 的新节"换人路径在 IF=0 下运行"。
- **新用例 `t_aspace_switch_isolation`（KT_ASPACE_SWITCH）四格判据与取证读数**：
  `assw(P5b): 同AS段=(换人18 写CR31) 隔离=(r0=0x1122334455667788 r1=0x8877665544332211 期望 0x1122334455667788/0x8877665544332211) 跨AS写=2 不取锁=(增量0 位图0x1/应含0x1) 映射=true 收场=true free116146->116146`
  - D7 隔离：两个工人在**同一个 VA** `0x2_0000_0000` 读到各自 VMO 的内容且互不相等。
  - D8 同 AS 不写表：写 CR3 **恒为 1 次**（只有第一次从内核表切进 a1）；跨 AS 段 2 次写。
    `换人` 那一格**跨跑散布 18~21**（同一份 ELF 的矩阵四跑里两种都出现过）——那是抢占散布，
    判据只要求 `>= 3` 与 `写 CR3 <= 1`；引数时要写清是哪一路。
  - D9 换人不取锁：单独一次 `aspace_switch(目标根, me, Some(槽))` 的 `sync::stats().acquires`
    **增量为 0**，且位图照样登记。前置那句"先把 CR3 定回内核根"是防**空转出来的绿**：
    CR3 已经在目标表上时提前返回会同时短路掉取锁与登记，增量 0 就成了假证人。
  - **D8 的第一版前提写错过**：只把两个工人登记进 a1、启动任务留在内核 AS，
    于是 boot↔工人 每次都算跨 AS（21 次换人 / 14 次写）。三方都登记之后才是"同 AS 段"。
- **三条变异各咬哪一格（2026-11-10 复跑取证，读数以这一版为准）**：
  - M13 = 把"相同就不写"那条提前返回短路掉 ⇒ `同AS段=(换人18 写CR354)` 红，
    `t_aspace_create_switch_destroy`（P1 那条"只在不同时变"）一起红，
    该跑最后落在 `L4 mm: shootdown 超时 va=0xffff8000205a5000 还差 1 个回执` ⇒ **EXCEPTION(39)**。
    **54 比换人数还大**不是记账错：登记段每次都要取 VMM ⇒ 把 VMM 的流量挂在了换人频率上，
    这正是上面那条互等的成因。
  - M14 = 换人点根本不写 CR3 ⇒ 工人跑在内核表上读自己 AS 的 VA：
    `unexpected #PF rip=0xffffffff8003eb32 cr2=0x200000000 err=0x0 cpu_cpl=0` 升 **EXCEPTION(39)**。
  - M15 = 把 `let _g = vmm();` 原样加回 `aspace_switch` ⇒ **确定性**红：
    `不取锁=(增量1 位图0x1/应含0x1)`、`判据不成立 … 不换锁=false`、`ktests 79/80`、判定 **FAIL(35)**。
  三条都已还原；还原后同一份代码 `判定=PASS qemu_rc=33`、`ktests 80/80`。
- **收场顺序是撞出来的**（决策 2 只写了"先丢映射再丢 AS"，没写"先把本 CPU 的 CR3 换回内核"）：
  只 `set_aspace(boot, NO_ASPACE)` 而实际 CR3 还指着 a1，`drop(a1)` 之后本 CPU 就站在一张
  已经还掉的表上 ⇒ 用例里显式切回内核根，并把判据从"又写了一次"改成"CR3 确实在内核根上"
  （D9 已经切回去一次，再判"写没写"会假红）。
- **门禁读数**：`check` **17/17**；`ktests` 默认档 **80/80**、`handles` 档 **82/82**（P5a 是 81/81）；
  矩阵 **45/45 符合**（`normal/elf 0bc1586a66e4`，收尾前后各跑过一轮，
  收尾前那一轮第一次 44/45、红在挂设备的"边沿与消息由设备事件数到"行、同一 ELF 复跑 45/45，
  成因仍是 `L4 mm: shootdown 超时` 那个仪器边缘家族——**但本轮已经把它与上面那条真隐患区分开**：
  隐患由 M13/M15 确定性复现，不靠那一跑的运气）；
  `bench` **4/4**，P4 地板 **0.21 %**（21 bp），`baselines/2026-11-09T16-41-13Z-p3p4.txt`。
- **unsafe 普查 364 → 372**（本半刀累计 +8：`ktests/mm` U2 1→2、U6 13→18；`sched` U2 6→7、U4 15→16），
  白名单 `[modules]` 与 `[unsafe-census]` 汇总、`unsafe-census.md` 汇总行与 ktests/mm 逐处节同轮重算；
  `module-interfaces.toml` 加 `mm::aspace_pml4_of`、`sched::NO_ASPACE`、`sched::set_aspace`、
  `sched::aspace_of` 与新用例名（`mm::aspace_switch` 已在册，只改签名；`AspaceHandle::slot` 归在已有的
  `mm::AspaceHandle` 条目下）。

**这一刀之后仍开着的**：跨 AS 是**全 TLB 冲刷**（无 PCID/KPTI，Q6 已裁），
P5c 的 `process_start` 会把这条代价带到产品路径上——**那时换人路径的零取锁就是硬前提**；
`AS_ON` 只增不减 + 4 个槽的容量 ⇒ P5c 若把 AS 数提上去要一并重算 `MAX_ADDR_SPACES`；
决策 3–7（`StartupInfo`、转移、`MAX_STARTUP_HANDLES`、根 Job、`process_start` 原子性边界）仍未落地。

## 补记：P5c-1 落地（四种句柄 kind + `RIGHT_CREATE` + 对象世代号，2026-11-10，实测）

三刀（使用者裁决）里的第一刀：**纯内核侧**，不开新 syscall、不动 14 号。落到的形状与两处
**草案没写到的东西**：

- **对象世代号是新增的（草案里没有）**。决策 4 说"表里只存引用"，但 `proc.rs` 的
  `JobEntry`/`ProcEntry` 只有 `used`，`mm` 的 `AspaceEntry` 只有 `used`+`pml4`——
  **槽号是复用的**，只存槽号会让新 Job 继承旧进程留下的句柄（ADR-073 给 `Task::id` 记过同一条坑）。
  ⇒ `JobEntry.gen` / `ProcEntry.gen` / `AspaceEntry.gen`：`*_create`/`aspace_new` 在旧值上 +1，
  **销毁不复位**；句柄存 `(slot, gen)`，对不上就是"这个对象不是当初那个"。
  配套读接缝：`proc::job_gen`/`proc_gen`/`job_live`/`proc_live`、`mm::aspace_gen`/`aspace_live`、
  `sched::id_of`/`thread_live`。`Thread` 用现成的 `Task::id`（全局单调 `NEXT_ID`），不新造号。
- **`close`/`revoke` 对这四种 kind 不销毁本体**（与 VMO 不同）。撤掉的是一份名字，
  销毁仍走各自的显式路径（`job_destroy` / `proc_reap`+`proc_discard` / `AspaceHandle::drop` /
  `terminate_task`）。**这条与本文"影响 3"不同**：那里写"四种 kind ⇒ HANDLE(35) 锁外要调
  `proc`/`mm`/`sched` 三个模块"，实际只有 VMO 需要；这四种连锁外调用都没有。
  判据 `hkind(P5c-1)` 的 `close不动本体` / `revoke` 两格把这条例言变成读数。
- **`capability → sched` 这条边会造成新的强连通分量——所以活性判定不能放在句柄层**。
  第一版把 `proc::job_live` / `proc::proc_live` / `sched::thread_live` 放进 `handle::resolve`，
  `check-module-interfaces` 立刻报：
  `强连通分量 … [['capability','sched']]，基线 [[…核心 11 模块…]]`，
  连带 `环内新边 capability->sched(4) / capability->memory(13) / capability->storage(4) /
  capability->sync(1)` 与 **`sched` 的十来条边全部要登记棘轮**（`sched->memory` 113、
  `sched->arch` 258…）——因为 `proc.rs`/`user.rs`/`elf.rs` 都属于 **`sched` 模块组**，
  而 `sched → capability`（`revoke_task`）本来就有，一条反向边就把 `sched` 从单例拖进冻结的核心环。
  ⇒ 最终形状：**`ObjRef::Job`/`Proc`/`Thread` 的活性由 `sched` 侧的消费方判**（c-3 的 11/15/16
  在用之前自己核 `(slot, gen)` / `(gidx, id)`）；只有 `ASpace` 在句柄层判
  （`capability → memory` 是登记过的边，不形成环）。`grant_job/grant_proc/grant_thread`
  因此改成**由调用方把世代号读好传进来**。
  这条分工不是散文：用例的 `活性分工` 与 `线程撤销` 两格判的就是
  "句柄层 `resolve` 仍然 Ok，而 `proc::job_live` / `sched::thread_live` 已经 false"。
  **没有损失安全性**：线程/进程槽位的生死本来就在 `sched` 的入口判。
- **新用例 `t_handle_kinds`（KT_HANDLE_KINDS，`handles` 档）取证读数**：
  `hkind(P5c-1): CREATE=true proc=true 活性分工=true AS活=true AS世代=true 线程活=true 线程撤销=true close不动本体=true revoke=true 锁序=(viol0->0/reent0->0) 基线=(live0->0 AS0->0 job0->0 proc0->0)`
  ⇒ `handles` 档 **83/83**（P5b 收尾是 82/82）、默认档 **80/80** 不变（用例是 `cfg(handles)`），
  两档都 `判定=PASS qemu_rc=33`。
- **四条变异各咬哪一格**：
  M16 = `ObjRef::ASpace` 不判世代 ⇒ `AS世代=false`，`failed=1`，FAIL(35)。
  M17 = `RIGHT_CREATE` 改成 0 ⇒ `CREATE=false`，FAIL(35)。
  M18 = `revoke_task` 只撤 File/Vmo ⇒ `revoke=false` **且 `failed=19`**：
  漏撤的名字把后面每一格用例的收尾闸都打红了（这正是"撤销漏一种 kind"应付的代价，
  不是只漏那一格）。
  M19 = 把活性判定留在 HANDLE(35) **锁内** ⇒ `L4 sync: 锁序违规，外层 rank=35 本次 rank=20`
  ⇒ **EXCEPTION(39)**。这条是给"活性必须在锁外"配的门禁证人，不是给 kind 配的。
  四条都已还原。
- **门禁读数**：`check` **17/17**（含 `check-module-interfaces` 的 SCC/棘轮全绿——
  即核心环仍是 11 个模块，`capability` 与 `sched` 仍是单例）；矩阵与 bench 见 BACKLOG §159。
- **unsafe 普查 372 → 373**（`sched` U4 16→17，就是 `id_of` 那次每 CPU 快照读）；
  `module-interfaces.toml` 只登记了产品路径真引用的 `mm::aspace_gen` / `mm::aspace_live`
  （`proc::*`、`sched::*` 那几个只被 `testing` 用，不在登记射程内）。

**这一刀之后仍开着的**：`MAX_STARTUP_HANDLES = 16` 的布局与"越界非零"校验在 **P5c-3**；
`RIGHT_CREATE` 还没有产品调用方（11 号在 c-3）；`ASpace` 句柄的 `gen` 与 `MAX_ADDR_SPACES = 4`
的容量要在 c-3 真给进程发 AS 时一并重算。

## 补记：P5c-2 落地（14 号兼容扩展 + `ABI_MINOR` 7 + 探针新格），2026-11-10，实测

决策 6 已落地。四参形状与旧行为逐字不变这一条都有证人（详见 `user-abi-capability.md` §4.4b）：
`mm::aspace_map_slot` / `vmo::vmo_map_slot` / `handle::aspace_of` 三个新接缝 + `sys_aspace_map` 的分派。

- **W+X 给的是 `-1`，不是 `-4`**：位图直接进 `PageFlags::new(w, x, true)`，构造期就失败。
  非对齐与越界也是 `-1`，"地址已被占"才是 `-6` ⇒ **两种拒绝在码上分得开**，
  这条分不开的话 `M22`（去掉对齐预检、让它落到 `reserve_va_at` 的 `-6`）就不会被抓住。
- **X 第一次进了产品路径**：探针按请求 VA 拿到一块 `user && executable && !writable`，
  自己从那儿读回内容比对（`effective_flags` 是第二台仪器）。
- **两条撞出来的调用方纪律（都写进了 ABI 文档，不是推演）**：
  ① "旧调用方行为不变"的前提是**新参数显式传 0**。`t_vmo_syscalls` 复用同一合成帧，
     13 号留下的 `r10=8` 被当成请求 VA、留下的 `rdx=用户 VA` 被当成 AS 句柄，两次都把 14 打成 `-1`。
  ② 请求的 VA **跨 2 MiB 块要多花一张永久页表页**（内核 AS 的下级表页记 `MOD_BOOT`、
     不归还）⇒ "帧回基线"那类判据会永久少一帧。探针的候选改成"步进 64 页、不跨块"，
     同时**不能贴着动态边界**：M21 实测发现紧贴的候选会被分配器顺手给出来，
     "返回==请求"就退化成运气证人（那一轮只有非对齐那格抓到了变异）。
     ⇒ 这是本轮最重要的一条量具结论：**"不许静默改地址"的证人必须让内核不可能碰巧答应。**
- **`rdx`=AS 句柄那一支今天还没有 ring3 调用方**（要等 c-3 把 AS 句柄交到用户手里），
  所以它的证人在内核侧：`t_aspace_map_vmo` 新增 `按槽铺`/`死槽拒`/`丢掉后没了` 三格。
  **没验证**的部分如实写着：syscall 层的 `rdx!=0` 分支今天只有实体被测、分派未被 ring3 触达。
- **读数**：`check` **17/17**；`ktests` 默认档 **80/80**、`handles` 档 **83/83**；
  `probe(P5c-2): … 扩展形=(请求0x100146000 返回0x100146000 判据true 读回1) W+X拒=true 非对齐拒=true … served=7`；
  `asmap(P5c-2): … 按槽铺=true 死槽拒=true 丢掉后没了=true …`；矩阵 **45/45**、`bench` **4/4**
  的取证读数见 BACKLOG §160。探针 ELF 从 26,264 → **30,936 字节**（sha `101a9aaacde4`，
  仍不进签名链、仍小于 32,768）。
- **四条变异**（各咬一格、全部还原）：M20 不给 X ⇒ `扩展形 判据false`；
  M21 静默改用内核发的地址 ⇒ 判据 false 且 `非对齐拒` 也 false；
  M22 去掉对齐预检 ⇒ `非对齐拒=false`（错误码从 -1 变 -6）；
  M23 `aspace_map_slot` 忽略槽号铺进内核表 ⇒ `按槽铺=false 死槽拒=false`。
- **登记面**：`module-interfaces.toml` 加 `mm::aspace_map_slot`、`vmo::vmo_map_slot`、`handle::aspace_of`；
  unsafe **373 → 374**（`user/probe` U5 3→4：新增"从请求 VA 读回"那一处，
  判据是先要求返回逐字等于请求值才解引用）；`ABI_MINOR` 6→**7**，
  `user-abi-capability.md` §4.4 第 2/3 条的勘误块改成落地事实并新增 §4.4b；
  ADR-074 号表那条勘误指针标上"已落地"。

## 补记：P5c-3a 的底座落地（转移/回滚、停线程、内核侧 AS、ABA 修复），2026-11-10，实测

11/15/16 三个号还没接，本补记只覆盖**它们要用的四样原语**，外加一条**上一刀留下的真洞**。
这四样原语在接号之前没有产品调用者（硬约束 2），所以同轮补了 `t_handle_transfer`
（KT_HANDLE_TRANSFER）当它们的真实调用者兼证人。

- **ABA：P5c-1 加的世代号原本防不住槽位复用**。`aspace_release` / `proc_reap` / `proc_discard` /
  `job_destroy` 都是整项写回 `*_EMPTY`，而 `gen` 在项里 ⇒ 销毁把 gen 复位成 0，
  下一次 create 复用同格又变 1 ⇒ **旧句柄的 `(slot, gen)` 重新匹配上**。
  `AS世代` 那格当时是绿的，只因为用例销毁后没有复用槽位（**绿而无效**的典型）。
  修法：四处都保留 `gen`；用例改成"销毁 → 复用同格再建 → 旧句柄仍须解析不过"，
  AS 与 Job 两张表各一格。变异 **M24**（去掉 mm 那处保留）实测咬中 `AS复用ABA=false`，
  `failed=1`、FAIL(35)。
- **`handle::transfer` / `transfer_rollback`**（决策 4 的实体）：改 owner 两格 + bump 世代；
  回滚再 bump 一次让中间态那个新句柄当场失效。新增 `counters().transfers` 作正向计数
  （D3 的证人仍是 `stale` 增量，两个数不能互相替代）。
  **实测撞出来的连带后果**：回滚 bump 之后**发送方手里那个旧句柄也失效了** ⇒ 那格名字谁都
  `close` 不掉，只有 `revoke_task(from)` 收得走。只回滚不 revoke 的代价不是"少一格名字"，
  而是永久漏一份 VMO 引用与一帧：现场 `live0->1 vmo1 free 少 1 帧`，
  把后面 **14 格**用例的收尾闸全打红。⇒ **16 号的失败路径必须连着 `revoke_task` 一起走**，
  这是设计 §10.3 第 7 步"整条装载序列回滚"的一部分，不能只调 `transfer_rollback`。
  这条已经写成用例里的 `回滚需revoke` 一格（红→绿即证人）。
- **`sched::block_task(gidx, token)`**（使用者裁决的方案 B）：停一个**不是当前**的 `Runnable`，
  复用 `Blocked`/`wake_task`/ADR-061 的杀阻塞清理，**不给 token 注册任何等待队列项**
  （它不等事件，只等 16 号）。**一格判据被证伪并降级**：`停自己` 那一格在变异 **M27**
  （删掉 `current_of(cpu) == gidx` 守卫）之后**仍然全绿**——当前任务的状态是 `Running`，
  前一个条件已经把它挡住了，那道守卫今天走不到。按 ADR-054 的口径把它降级成
  **结构性论证**（防将来有人先标 Runnable 再来停），判据改名为 `停Running拒`，
  注释里写明它证的不是那道守卫。**不写成"已实测"。**
- **`mm::aspace_new_kernel()` / `aspace_destroy(slot)`**（使用者批准的形状）：进程名下那张 AS 的
  主人是 proc 表，与 `aspace_new` 共用 `aspace_new_slot` 实体，差别只在谁负责收；
  ktest 自己的 AS 继续用 RAII。`aspace_destroy` 的越界守卫用 `get` 而不是 `min` 夹到最后一格
  （第一版写成 `min` 就是"销毁别人的 AS"）。变异 **M28**（两道守卫都去掉）以 **EXCEPTION(39)**
  形态咬中越界那一格（`aspace_release` 先下标后判 `used`）；**M28b**（只去 `used`、留边界）
  精确咬中幂等那一格 `AS=false`、FAIL(35)。
- **`spawn_user` 加第 4 参 `arg`**（决策 5）：写进首帧 `rdi`（`TrapFrame` 第 10 格），
  **13 个调用点全部补 0** ⇒ 既有行为逐字不变。
- **`MAX_ADDR_SPACES` 4 → 8**：依据写在代码注释里（进程 4 格 + 用例族实测会同时要的 2 格 = 6，
  留一格余量），代价是 `.bss` 每格约 152 字节。
- **取证读数**：`check` **17/17**；`ktests` 默认档 **80/80**、`handles` 档 **84/84**（新增这一条）；
  `tr(P5c-3a): 转移后可用=true 旧句柄Stale=true 计数=(transfers0->2) 同对象=true 无权限拒=true
  自转拒=true 回滚到位=true 二次回滚拒=true 回滚需revoke=true AS建销=(1true 2false 越界false)
  ABA=true 停=true 停Running拒=true 陈旧wake=true 唤醒=true 基线=(live0->0 vmo0 free116022->116022 as0)`；
  矩阵与 bench 的取证读数见 BACKLOG §161。变异 **M25**（转移不 bump）咬 `旧Stale=false` 与 `计数=false`；
  **M26**（回滚不 bump）咬 `回滚=false`；M24/M27/M28/M28b 见上。
- **登记面**：`module-interfaces.toml` 的 capability 加 `RIGHT_CREATE`/四个 `grant_*`/`resolve`/`has`/
  `aspace_of`/`transfer`/`transfer_rollback` 与两个新用例名，memory 加 `aspace_new_kernel`/`aspace_destroy`，
  sched 加 `block_task`。

**接 11/15/16 之前还要裁的两件（本文不自行决定）**：
① `process_create` 要交回 **Proc 与 ASpace 两个句柄**，而 syscall 只有一个返回值——
   倾向"`rax` 给 Proc、`rsi` 给一个 8 字节出参指针装 AS 句柄"（与 `peek_buf`/`poke_buf` 同形），
   备选是再开一个号（要重开 Q1 的号表）。
② **启动映射的归属**：14 号铺出来的映射今天挂在**创建者任务的资源袋**里（ADR-074 按任务归属），
   父进程先退，子线程的代码/栈映射就当场没了。这一版照现状实现并配"父先退"的负样本让它可判，
   改成进程级归属是本文留给 P7 的那笔账，不在 c-3 偷偷做。

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

**已裁五条**：原未决 1（14 号参数）⇒ **兼容扩展 14**，见决策 6（2026-11-09）；
原未决 2（跳板位置）⇒ **搬进内核半区共享一份**，见决策 7（2026-11-09）；
原未决 3（`MAX_STARTUP_HANDLES`）⇒ **16**，见下面决策 3 那一节的修订（2026-11-10，代价是 12 格永久为空，
判据要专门喂"nhandles 之后有垃圾"）；原未决 4（根 Job 归谁）⇒ **内核持有、只在 ktest 出示，产品路径不授予**
（2026-11-10，与 ADR-007 第一刀同一姿态，不许写成"进程创建已接通"）；
原未决 7（`Thread` 要不要独立句柄）⇒ **要，四种 kind 照决策 4**（2026-11-10，本文原先提议"只内部标识"已被推翻；
P5c-1 落地时按四种做，`ObjRef::Thread { gidx, id }` 已在表里）。
下面保留原编号，方便与草案对照。

3. ~~**`MAX_STARTUP_HANDLES` 的取值**~~（**已裁 16**，见上面的日期行）。本文原提议 8（今天只有 4 个角色真能传），
   设计举例是 16，而句柄表本身只有 16 格。取值与"每进程句柄表上限"（W4）绑定，欠 workload 依据。
4. ~~**`CREATE` 权限位与根 Job 的授予**~~（**已裁：内核持有、只在 ktest 出示**；`RIGHT_CREATE=32` 已随 P5c-1 落地）。Q7 裁了"CREATE 是唯一新权限位"，但**根 Job 交给谁**今天没有 init。
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
7. ~~**`Thread` 对象要不要独立句柄**~~（**已裁：要**，P5c-1 已发 `ObjRef::Thread`）。设计 §10.6 第 3 条把 `thread_wait` 列为"由用例逼出来再定"。
   Q3 已裁通用 `object_wait`（19 号，P6），所以线程级等待免费得到；但 `Thread` 作为一种 kind
   是否要在 P5c 就发句柄（还是只用 `gidx` 内部标识），本文提议**只内部标识**，等 P6 真需要 wait 它时再发。
