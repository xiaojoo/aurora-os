# ADR-049：resched 向量用自陷建帧，单独记账且不发 EOI

状态：已采纳（2026-11-08，S1/W1 的 P3a；兑现 ADR-047 决策 5 的向量与决策 3 的让出语义）
关联：ADR-020（EOI 纪律与 spurious 不发 EOI 的理由）、ADR-021（IF 属于 CPU）、
ADR-024（0xF1 为什么必须建帧）、ADR-046（向量登记表与三处特例的源码锚点）、
ADR-047（W1 接口）、ADR-048（运行队列锁）、BACKLOG §113a/§114

## 背景

三件事凑在一起决定了这个形状：

1. `preempt_point` 的契约是"**异常帧就在当前任务栈上**"，而普通内核上下文调让出时没有帧。
   所以让出不能直接调它，必须让硬件压帧。
2. `loads_closed`（关着窗口换入）这一格**结构上恒为 0**：唯一的调度入口是异常出口，
   而所有换入都发生在开着的窗口里。用例注释自己写着"没有触发源，等主动让出时补"。
3. `apic::Counts` 只有 `{irq[16], unexpected, spurious, eois}`，而 `p5_non_irq`
   （`trap.rs:684`，>47 的向量）会把任何新向量收进去 ⇒ 两台仪器的对照式
   `p5_delta == rust_delta` 必然失衡。代码里那句注释早预言了："新增一类会进 P5 的向量
   必须在这里显式表态"。

## 决策

1. **`VEC_RESCHED = 0xF0`（240）**，`STUB_NOERR 240` 生成**建帧**桩，IDT 表里把 240 那一格
   从 `.rept 112`（129..240 共用意外桩）拆成 `.rept 111` + `.quad isr_stub_240`。
   建帧的理由与 0xF1 同（ADR-024）：不建帧就换不了人。
2. **`sched::yield_now()` = 立 need 牌 + `int 0xF0`**。软件中断不受 IF 影响，
   所以**关着窗口也能让出**——这就是 `loads_closed` 缺的触发源。
   门是中断门（不是陷阱门），硬件进来清 IF、`iretq` 按保存的 rflags 还原，
   窗口状态不被这次让出改掉（ADR-021）。asm 不带 `nomem/nostack`：`int` 会压栈。
3. **不发 EOI**：`int` 不置 LAPIC 的 ISR 位，多确认一个不存在的服务中断会让别的中断收不到
   （ADR-020 对 spurious 的理由原样适用）。所以 `on_interrupt` 里它是**提前 return** 的一支：
   只 `RESCHED += 1`，不进 ISR 深度、不发 EOI、**不借 `mark_tick`**（借了就把 tick 数灌进去，
   "两台仪器数到同一个数"那条判据当场废）。
4. **单独一格账**：`Counts` 加 `resched: usize`，并同轮改三处求和——
   `main.rs` 的 `rust_irq_total`、`ktests/time.rs` 的 `rust0` 与 `rust_total`。
   它不占 IRQ 那 16 格（那是 I/O APIC 的线），也不算 tick。
5. **登记面同轮**：`vectors.toml` 加 `VEC_RESCHED` 行，且 `no_eoi` 从
   `["VEC_SPURIOUS"]` 变成 `["VEC_RESCHED", "VEC_SPURIOUS"]`——ADR-046 那道按
   **分支形状**（块内提前 `return`）解析的闸当场点名要求两边一起改，这就是它存在的意义。
   `arch.public_api` 补 `trap::VEC_RESCHED`；`sched` 的 U1 2→3（那条 asm），
   普查 total 282→283、U1 53→54。
6. **hooks 新字段推迟到 P5**：P3a 的发送方就是让出者自己，它在自陷前立牌即可；
   跨 CPU 唤醒（别的核替你立牌）才需要 `mark_need_from_isr`，那是 P5 的事。
   少一个字段就少一处 U4，也少一次"没有真实调用者的接口"。

## 备选方案

- **直接调 `preempt_point`**：拒绝。没有帧，它的"帧在不在这条栈上"检查会直接否掉，
  等于让出无效；伪造一个帧则是把硬件该做的事搬到软件里，且与 `context_load` 的契约打架。
- **借 `mark_tick` 立牌**：拒绝。tick 数是"发生过一次时钟"的记录，借给别的理由会让
  P5/ticks 与真实 tick 对不上（`mark_need` 的注释里已经写过这条教训）。
- **给它发 EOI**：拒绝，见决策 3。
- **只进 `p5_non_irq`、不给 `Counts` 加字段**：拒绝。对照式会失衡，而且失衡的方向是
  "P5 比驱动多"，看起来像量具坏了而不是像新增了一类向量。
- **把门做成 DPL3 让用户态也能自陷让出**：拒绝。让出是内核动作；用户态将来走系统调用，
  而 DPL3 门会让 ring3 任意触发调度路径，扩大攻击面（与 ADR-025 只给 0x80 开 DPL3 一致）。

## 影响

- 代码：`trap.rs`（常量 + 桩 + IDT 格）、`apic.rs`（计数器 + Counts 字段 + 分类分支）、
  `sched.rs`（`yield_now`）、`main.rs` 与 `ktests/time.rs`（三处求和）、
  `ktests/sched.rs`（判据与搭档）。
- **`loads_closed` 从恒 0 变成 2**（实测），M3b 遗留那一格关闭；新判据要求它真的前进过
  且搭档确实被换入过（`closed_after > closed_before && partner_runs >= 1`）。
- 新增两行可见读数：`yield: 清掉残留任务 #N` 与 `yield(ADR-049): …`。
- **顺带暴露了 P2.5 的根因**（见 BACKLOG §114）：本 CPU 上残留着 **4 个**仍可被选中的任务，
  其中一个是 ring3 里永久自旋的用户任务（`RIP=0x100102040`）。关窗口让出时
  `pick_next` 会把它选上来，而此后没有任何抢占来源 ⇒ 整机静默。
  所以 §112 的修复①只拆掉了**一个触发路径**，根因仍在；本用例靠"让出前清残留"自足，
  但**残留本身要单独定位并修**，不能靠每个用例各自扫一遍。

## 验收与负样本

- **MUTATION-Y（确定性）**：把 `yield_now` 里的 `mark_need(...)` 去掉 ⇒
  `yield(ADR-049): 关窗口让出 closed 0 -> 0 搭档runs=0 自陷计数=1` →
  `[FAIL] t_if_belongs_to_cpu -> failed` → 宿主 `FAIL(35)`。
  注意 `自陷计数=1`：陷进去了但没换人，所以这条判据量的是**换人**，不是"有没有自陷"。
  还原 ⇒ `closed 0 -> 2 搭档runs=1 自陷计数=2`、PASS(33)。
- 重复性：还原后默认档 **5/5 PASS**，`loads_closed=2`、`清残留=4`、`窗口还原=true`、53/53。
- 门禁自证：`check-vector-table` 在登记补齐前点名两件事——
  `具名向量 VEC_RESCHED=0xf0 … 却没登记` 与
  `「不发 EOI 的判定」源码点名 ['VEC_RESCHED','VEC_SPURIOUS'] ≠ 登记 ['VEC_SPURIOUS']`；
  `check-module-interfaces` 点名 `public_api 漏登记：trap::VEC_RESCHED`；
  `check-unsafe` 点名 `sched U1 登记 2 处、源码 3 处`。四处补齐后转绿。

## 迁移与回滚

- 回滚：删常量/桩/IDT 格/分类分支/Counts 字段与三处求和/`yield_now`，
  并把四处登记还原；`t_if_belongs_to_cpu` 的新判据要一起退回原来那句"必然 0"。
- 迁移：P3b（`Blocked`/idle/`reap`）与 P5（跨 CPU 唤醒）都建立在这个向量上；
  P5 加 hooks 字段时**不改**本 ADR 的记账归属。

## 未决

1. **残留的 Runnable ring3 自旋任务是哪条用例留下的**——要单独定位并在那条用例收尾修掉。
   这是 P2.5 的真正根因，也是"任何关窗口让出/停表都会挂死"的公共前提。
2. P3b：`TaskState::Blocked(WaitToken)`、每 CPU 兜底 idle、`reap` 状态集、
   `tasks_active()` 的语义说明、BACKLOG 144 那条未写下前提的显式化。
3. `yield_now` 目前只有用例在调，产品路径无调用者 ⇒ 按 ADR-045 的口径它**不进** `public_api`
   （登记表只收产品路径的跨模块引用）。等 P3b/P5 有产品调用者时再登记。
