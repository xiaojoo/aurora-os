# ADR-055：跨核 resched 用独立向量并发 EOI；no_eoi 锚点改成结构判据

状态：已采纳（2026-11-08，S1/W1 的 P4c-1）
关联：ADR-020（EOI 纪律与 spurious 不发 EOI 的理由）、ADR-049（自陷让出与 0xF0 不发 EOI）、
ADR-046（向量登记表与三处特例的源码锚点）、ADR-023（shootdown 回执）、ADR-053/054（等待队列）

## 背景

P4c-1 把跨核唤醒接上时，第一版**复用** `VEC_RESCHED = 0xF0` 发 IPI。0xF0 的处理分支按
ADR-049 是"软件自陷、不置 ISR 位 ⇒ 不发 EOI"。但**经 ICR 发来的真实 IPI 会置目标 LAPIC 的
ISR 位**，于是同一个向量出现了两种来源、两种 EOI 要求。后果实测：

- 见证用例本身通过（`在线AP=3 送达=3 IPI失败=0`），但**它之后立刻**
  `L4 mm: shootdown 超时 va=0xffff800020591000 还差 3 个回执`，
  随后崩溃路径又撞 `L4 sync: 锁序违规，外层 rank=20 本次 rank=8`（级联），判定 39。

**三个实验把根因钉死**（都不是猜）：
1. 只去掉 `mark_need`（IPI 照发照收）⇒ **仍然超时** ⇒ 不是"AP 侧调度引发 reap/unmap"
   （我第一个假设错了，就地记下来）。
2. 保留全部机制、只摘掉新用例的 `.ktests` 注册 ⇒ **2/2 PASS** ⇒ 与用例的执行有关，
   而不是单纯链接顺序。
3. 保留用例、让 `request_resched` 只返回不发 ⇒ **无超时**，见证用例按预期红（`送达=0`）
   ⇒ **是 IPI 本身**。结合 0xF0 分支不发 EOI，根因就是 ISR 位滞留。

## 决策

1. **跨核 IPI 用独立向量 `VEC_RESCHED_IPI = 0xF3`（243）**：`STUB_NOERR 243` 建帧，
   IDT 表把 242..254 的 `.rept 13` 拆成 `.rept 1`(242) + `.quad isr_stub_243` + `.rept 11`(244..254)。
   它的处理分支在分类链里（与 `VEC_CPU_TIMER` 同层），**不提前 return**，因此走正常 EOI。
2. **`VEC_RESCHED = 0xF0` 保持自陷专用、不发 EOI**（ADR-049 不变）。
   两个向量记在**同一本** `RESCHED` 账里，所以 `Counts.resched` 同时覆盖两者，
   P5 的 `p5_delta == rust_delta` 对照式仍然平衡（两边都 >47，都进 `p5_non_irq`）。
3. **hooks 加 `mark_need: fn()`**（默认 no-op），由 `sched::mark_need_self` 实现：
   记一次 per-CPU 见证计数 + 立本 CPU 的 need 牌。**不借 `mark_tick`**——那会灌 tick 数，
   破坏"两台仪器数到同一个数"（ADR-049 决策 3 的同一理由）。
4. **`request_resched(cpu)` 失败只计数、不升 L4**：目标任务的状态已经是 `Runnable`，
   IPI 失败只意味着要等它自己的下一次 tick 才被选上，**唤醒不丢**。
   这与 shootdown 不同——那边收不齐回执必须升 L4，因为正确性依赖回执（ADR-023）。
5. **`no_eoi` 锚点改成结构判据**（修 ADR-046 那道闸自己的缺陷）：
   旧版是"匹配后 400 字符内找 `return`"，实测**两头都错**——
   给 0xF0 分支加注释与调用后 `return` 被挤出窗口（**漏判**），
   而 else-if 链上没有同缩进收尾花括号时又一路吞到后面的 `return`（**误判 0xF3**）。
   改为**花括号配对取分支体 + 剥 `//` 注释**再判 `return`
   （不剥注释时，分支注释里写的"不 return"也会被命中，实测误判过一次）。

## 备选方案

- **共用 0xF0 并总是发 EOI**：拒绝。自陷没有 ISR 位，给它发 EOI 就是 ADR-020 对 spurious
   写明的那种错（多确认一个不存在的服务中断）。
- **共用 0xF0，在 handler 里读 ISR 位决定要不要 EOI**：可行但更脆——它把"两种来源"
   藏进一个运行时判断，而向量表与登记面看不出区别；独立向量让差别**写在号上**，
   登记表与闸都能直接对账。
- **让 AP 侧不做 reap/unmap 以避开 shootdown**：拒绝，那是掩盖（而且实验 1 已证明
   根因不在那里）。
- **保留 400 字符启发式、只把窗口调大**：拒绝。调大只是把漏判推后，误判仍在；
   结构判据才是对的形状。

## 影响

- 代码：`trap.rs`（常量 + 桩 + IDT 拆格）、`apic.rs`（分类链新增一支，走 EOI）、
  `hooks.rs`（`mark_need` 字段与默认桩）、`sched.rs`（见证计数、`request_resched`、
  `wake_task` 对远端发 IPI、装表）、`ktests/sched.rs`（见证用例）、
  `tools/aurora.py`（锚点改结构判据）。
- 登记面：`vectors.toml` 加 `VEC_RESCHED_IPI` 行（`no_eoi` 列表**不变**，因为它发 EOI）；
  `arch.public_api` +1（`trap::VEC_RESCHED_IPI`）。用例数 57 → **58**。
- 跨核唤醒从此可用；`wake_task` 对非本 CPU 的目标会立刻发 IPI，不必等目标的下一次 tick。

## 验收与负样本

- **正向（实测）**：分开向量后默认档 **3/3 PASS**，
  `resched 跨核(ADR-055): 在线AP=3 送达=3 发送被拒=0 IPI失败累计=0`，`shootdown 超时` 命中 **0**。
- **变异 B（实测，即实验 3）**：让 `request_resched` 不发 IPI ⇒ `送达=0` ⇒
  `t_cross_cpu_resched -> failed` ⇒ FAIL(35)。这是**机制层**的变异 B；
  "去掉 IPI ⇒ 跨核唤醒**延迟**超界"的量化版本属 P4c-2 的四核压力。
- **闸的自检（实测）**：给 0xF3 分支真加一行 `return;` ⇒ 修好后的锚点立刻点名
  `源码点名 ['VEC_RESCHED','VEC_RESCHED_IPI','VEC_SPURIOUS'] ≠ 登记 [...]`；删掉即绿。
  这证明改成结构判据之后它**仍然会咬**，不是被改松了。
- 三个定位实验的读数都记进 BACKLOG §127，包括**我第一个假设被证伪**那一条。

## 迁移与回滚

- 回滚：删 0xF3 的常量/桩/IDT 格/分类支，`request_resched` 退回不发（跨核唤醒退化为
   "等目标下一次 tick"，语义仍正确、只是慢），并还原两处登记与闸的锚点。
- 迁移：P4c-2 的四核压力直接建立在 `request_resched` 上；容量 16×16 的第一个真实
   workload 依据也在那一轮取。

## 未决

1. P4c-2：4 核生产者/消费者压力 + 唤醒延迟上界 + 容量依据。
2. `resched_ipi_fail()` 目前只计数、没有判据看着它；要不要给它一条阈值判据，等 P4c-2
   有真实并发度之后再定（现在加阈值就是拍数字）。
3. 多请求方 shootdown 的并发论证仍然没有反例测试（lock-order.md 挂着的那条）——
   本轮**没有**触发它，第一个假设已被实验 1 证伪，不要把它记成已解决。
