# ADR-052：兜底 idle 的落地形状——两遍扫描、只在 prev 不再可运行时回落、静态栈必须落可写段

状态：已采纳（2026-11-08，S1/W1 的 P3b-2；落地 ADR-051 决策 3/4，并收窄其中一条）
关联：ADR-051（前提变判据与落地顺序）、ADR-049（自陷让出）、ADR-021（IF 属于 CPU）、
ADR-027（任务结束与资源回账）、ADR-048（运行队列锁）、BACKLOG 144、§111、§121

## 背景

ADR-051 定了"每 CPU 一个专属 idle，`pick_next` 在没有别的 Runnable 时回落到它"。
落地时有三件事必须当场定，否则要么扰动既有判据，要么造出新的挂死：

1. 若 idle 与真任务一起参与轮转，那么"只有一个真任务在跑"的每个时间片都会切到 idle，
   切换次数、P1 样本、轮转用例的期望值全部要重取基线——扰动面太大。
2. 若"没有别的 Runnable"就**无条件**回落 idle，那么一个**活着的**任务在关窗口/停表时
   让出，就会被切到 idle；idle 只自旋、不依赖 tick 让回，于是再也回不来——
   这正是 §111 那一类挂死，等于自己造一个新的。
3. idle 的栈必须是静态且**可写**的。第一版写成
   `static IDLE_STACKS: [IdleStack; N] = [const { IdleStack([0; N]) }; N]`，
   LLVM 把它当编译期常量放进了 **`.rodata`**（实测 `llvm-objdump -t` 段名 `.rodata`），
   往里写首帧当场 `#PF err=0x3`（写只读页），随后在持队列锁时进故障路径又重入 rank=8 升 L4。

## 决策

1. **两遍扫描**：第一遍在**排除 idle** 的候选里按原轮转顺序选；只要还有真任务可跑，
   行为与 P3b-2 之前逐字相同（既有轮转判据与 P1 样本形状不受扰动）。
2. **回落条件收窄**（对 ADR-051 决策 3 的收窄，按本 ADR 为准）：
   第二遍只在 **`prev` 自己已不再可运行**（状态不是 `Runnable`/`Running`）时才回落 idle。
   要治的形状是"已标 Done/Free 却仍占着 CPU"——返回 `prev` 会让它永远不被换下，
   `reap` 的 `skip = current` 永远跳过它、资源永不回账（BACKLOG 144）。
   `prev` 还活着时返回 `prev` 是**正确且安全**的：它继续跑，不依赖 tick 才能回来。
3. **静态栈用 `UnsafeCell` 包装并显式 `Sync`**：`IdleStackCell(UnsafeCell<IdleStack>)`，
   SAFETY 写明"每 CPU 只碰自己那格、写帧只在持本 CPU 队列锁且 IF=0 的那一次"。
   实测段名变为 **`.bss`**（可写），与 `QueueCell` 同一论证形状。
   `owned` 为空、栈终身持有 ⇒ `reap` 永远不会解映射一条还在用的 CPU 栈。
4. **`tasks_active()` 排除 idle**（ADR-051 决策 4 的落地），并由用例**独立重算**对账，
   不是读同一个函数自证。
5. **第一版只自旋**，`hlt` 留 P5（那要动 IF 语义，属 ADR-021）。
6. **BSP 由 `main.rs` 在跑用例前调 `init_idle()`**；AP 侧今天已有 slot 0 的空闲上下文
   （`smp.rs:420` 调 `init_idle_task`），本轮不动它，避免同时扰动 AP 的读数。
   `init_idle` 幂等，且**不用 slot 0**（那格会被 `init_boot_task`/`init_idle_task` 重写）。

## 备选方案

- **idle 参与正常轮转（单遍扫描）**：拒绝。实测变异 MUTATION-I2 直接 **HANG(120 s)**——
   机器在到达断言之前就死了。它证明"排除 idle"是**活性**所必需，不只是读数好看。
- **无条件回落 idle**：拒绝，见决策 2（会造出新的 §111 类挂死）。
- **idle 栈走分配器（`spawn`）**：拒绝。idle 必须在堆/VA 保留表耗尽时仍然存在，
   它是最后的兜底；而且挂到任务名下会被 `reap` 解映射。
- **裸 `const {}` 静态数组**：拒绝，见背景 3（落 `.rodata`，写即 #PF）。
- **`static mut`**：拒绝。本仓库用 `UnsafeCell` + 显式 `Sync` 表达内部可变性
   （`QueueCell` 就是先例），`static mut` 的引用规则与 lint 姿态都不合适。

## 影响

- 代码：`sched.rs`（静态栈 + `idle_of`/`init_idle`/`idle_entry` + 两遍 `pick_next` +
  `tasks_active` 排除）、`main.rs`（登记与一行读数）、`ktests/sched.rs`
  （新用例 `t_idle_fallback`，以及让出前扫残留时**跳过 idle**）。
- 登记面（由门禁点名后补）：`sched.public_api` +2（`idle_of`、`init_idle`）；
  `sched` U2 5→6、U4 12→13；普查 total 284→286、U2 60→61、U4 108→109。
- 用例数 54 → **55**；新增两行读数（`sched idle: …`、`idle(ADR-051): …`）。
- 二进制 4436168 → 4459336 字节（静态栈进 .bss，不占镜像文件体积）。
- **覆盖缺口（写明，不藏）**：回落分支本身无法由用例直接触发——那要求跑用例的上下文
  自己不再可运行，等于把测试 runner 结束掉。所以 `t_idle_fallback` 验的是使那条分支
  安全的三个前提（在册且可运行、名下无资源、不被优先选中、active 排除对账），
  分支本身留待 P4 的阻塞用例间接覆盖。

## 验收与负样本

- **正向（实测）**：`sched idle: 登记=true 下标=1`；
  `idle(ADR-051): 下标=1 状态=Runnable 名下=0 active=7 独立重算=7 idle_runs 0 -> 0 搭档runs=1`；
  `reap 前提(BACKLOG144): worker=#4 状态=Free 名下=0 released 44 -> 47`；
  `判定=PASS(33)`、**55/55**、`check` 17/17（登记补齐后）。
- **MUTATION-I1（确定性红，实测）**：`tasks_active` 不排除 idle ⇒
  `active=8 独立重算=7` → `[FAIL] t_idle_fallback -> failed` → FAIL(35)。
  独立重算这条对账因此被证明有用（不是自证）。
- **MUTATION-I2（实测，比预期更强）**：第一遍不排除 idle ⇒ **HANG(120 s)**，
  机器在到达断言前就死了。它证明排除 idle 是活性所必需；
  同时也说明"用 HANG 当负样本"信息量低——所以决策 1/2 的形状要在代码注释里写清理由。
- 两条变异还原后都回到 `PASS(33)`、二进制哈希 `5aa87c0a2f9b`。
- **落地过程中真实抓到的一次错（实测）**：`.rodata` 那次 #PF 由 `llvm-objdump -t` 的段名
  与 `llvm-nm` 的符号定位共同钉死（`init_idle+0x1a7` 写 `IDLE_STACKS+0x1f48`），
  不是靠猜"权限大概是只读"。这条方法记进 BACKLOG。

## 迁移与回滚

- 回滚：删 idle 的静态栈与三个函数、还原 `pick_next`/`tasks_active`、删 `main.rs` 的调用
  与新用例，并还原两处登记。回落逻辑退回"返回 prev"，即 BACKLOG 144 的前提重新变成假设。
- 迁移：P5 把 `idle_entry` 从自旋换成 `hlt` 时，要同轮处理 IF 语义（ADR-021）与
  "停表期间 idle 也醒不来"的边界；P4 的阻塞用例将间接覆盖回落分支。

## 未决

1. AP 侧仍用 slot 0 的空闲上下文当兜底，没有专属 idle 任务；要不要统一，等 P5 一起决定。
2. 回落分支的直接覆盖（见影响一节的覆盖缺口）。
3. `idle` 是否计入 P1 分母：本轮因为它不参与正常轮转，实际上不增加切换；
   P5 换 `hlt` 之后要重新说明口径。
