# ADR-062：resched IPI 失败计数由注入证明它会咬，且失败不丢唤醒

状态：已采纳（2026-11-08，W1 收尾欠账第 7 条 / BACKLOG §138）
关联：ADR-055（跨核 resched 独立向量并发 EOI）、ADR-053（放锁后切走、防丢唤醒）、
ADR-051（兜底 idle 与回落条件）、ADR-046（具名向量登记表）、手册 §9.2 / §12.3

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计。每条结论标「实测」或「推断」。

## 背景

`request_resched` 发跨核 resched IPI 失败时走 `Err` 分支：`RESCHED_IPI_FAIL.fetch_add(1)` 并返回
false。注释写明这条失败**不丢唤醒**——目标任务的状态已经是 `Runnable`，IPI 只是催它立刻换人，
没有 IPI 它也会在自己的下一次 tick 被选上（与 shootdown 不同：那边正确性依赖回执，收不齐要升 L4）。

问题是 `resched_ipi_fail()` **只被日志打印，没有任何断言看着它**（§135 未决 7）。
`t_cross_cpu_resched` 把它打进一行日志，但判据只查 `delivered == checked`，失败计数是 0 还是 999
那一行都绿。这与 P5 那次"hlt 计数没有判据"是同一类缺口。

更难的一半：健康 QEMU 上 `send_ipi_to` **从不失败**（ICR 投递位很快清零），所以这个计数平时恒 0。
"它会不会在真失败时涨"这件事，靠健康跑永远测不到——必须造一次失败。

## 决策

1. **健康跑那一半**：`t_cross_cpu_resched` 的判据加 `fails == 0`。它本来就有
   `delivered == checked && checked > 0` 作反空转对照（每一发都送达），所以"失败计数必须 0"
   不是空转——计数若误涨，这条当场红。这是"计数不误报"的见证。
2. **注入那一半**：新增 cargo 特性 `fault-resched-ipi`。带它时 `request_resched` 在**记账点**
   强制走 `Err` 分支（`let sent = Err(ApicError::MapFailed)`），与真失败同一条处置：计数 + 返回 false。
   注入放在 `request_resched`（sched.rs）而**不是** `send_ipi_to`（apic.rs），理由见备选方案。
3. **三条依赖跨核 IPI 送达的用例在本特性下不注册**（`#[cfg(not(feature = "fault-resched-ipi"))]`）：
   `t_cross_cpu_resched`、`t_cross_cpu_wait`、`t_idle_hlt_wakes`。前两条要 `ipi > 0`/送达，
   第三条靠 AP 发 IPI 叫醒 **BSP 的 hlt idle**——注入下 IPI 失败，BSP idle 没有本地 tick 源
   （它的 tick 是 PIT→IOAPIC，hlt 时靠 IPI 醒），会永远停住（实测 HANG）。所以它们不是"改断言"
   能救的，整条不注册，由新用例取代。
4. **新用例 `t_resched_ipi_fail_fallback`**（只在注入构建注册）：每个在线 AP 跑一个消费者，
   真的阻塞一次；BSP 观察者等它阻塞后置位并 `wake_all`——这次 wake 的 IPI 必失败。四格判据：
   `ack == 0`（相位跑完）、`done == 1`（消费者真跑完 ⇒ **没丢唤醒**）、`fail > fail0`（**计数会咬**）、
   `received == 0`（注入确实把 IPI 打掉了）。消费者跑在 AP 的空闲上下文里，AP 有本地 LAPIC tick
   （`mark_sched` 在 bringup 已开），所以失败之后靠自己的 tick 仍被选上——这正是"失败不丢唤醒"。
5. **宿主机第二台仪器**：`check_resched_ipi_fail` 独立解那行见证（正则四个数），核
   `ack==0 / done==1 / f1>f0 / ipi==0`。判定表新增一行（第 42 行）：期望 `PASS(33)`
   （失败不丢唤醒，整体仍绿）；内核绿而宿主机这三件事对不上 ⇒ `CONTENT-MISMATCH`，两种成因分得开。

不涉及：锁序、rank、syscall 号、崩溃记录格式、日志契约（新增一行 info 与一行 fatal 点名都是判据证据）。
`module-interfaces.toml` 补 `apic::ApicError`（sched 现在在产品路径上引用它做注入的类型标注）；
环内棘轮不变（sched 不在环 A 里，注入不新增环内引用）。

## 备选方案

- **注入放 `send_ipi_to`（apic.rs）**：本帖第一版就是这么做的，被门禁否掉。
  `check-vector-table` 的 no_eoi 判据按**分支形状**扫 apic.rs 里所有 `vector == VEC_*` 的提前 return，
  把它读成"不发 EOI 的分支"（实测：`no_eoi` 多出 `VEC_RESCHED_IPI`，与 vectors.toml 不符 ⇒ 红）。
  那个 return 其实是注入故障，不是 EOI 决定。与其为它放宽门禁或改 vectors.toml（那会污染真正的
  EOI 登记），不如把注入挪到记账点 `request_resched`——那里不被该门禁扫，且测的是同一份处置逻辑。
- **只加健康跑 `fails == 0`、不做注入**：拒绝。那只能证"计数不误报"，证不了"真失败时会涨"。
  用户明确选了注入这条路（2026-11-08）。
- **改三条 IPI 用例的断言让它们容忍失败**：拒绝。`t_idle_hlt_wakes` 的 BSP idle 在注入下根本醒不来
  （HANG），不是断言松紧的问题；`t_cross_cpu_wait` 的 200 轮靠 tick 回落要 ~2 s，远超相位 60 ms 上界。
  整条不注册比改断言诚实。
- **把失败升成 L4**：拒绝。resched 失败的正确处置就是不丢唤醒、靠 tick 兜底，升 L4 会把一条
  可恢复的退化变成停机（与 shootdown 的语义相反，那边才依赖回执）。

## 影响

- 正面：失败计数两面都有见证——健康跑不误报（`fails==0`）、注入下会咬（`fail>fail0`）；
  "失败不丢唤醒"由 `done==1` 直接证明，不再是注释里的推断。
- 代价：注入构建少三条用例、多一条（63 → **61**）；那三条的覆盖在注入构建里由新用例部分取代
  （跨核送达本身在注入下无从测起）。正常构建一条没少，仍 63。
- 登记面：`arch.public_api` 补 `apic::ApicError`。判定表 41 → **42** 行。
- 注入是**记账点模拟**：它走的是与真失败相同的 `Err` 处置，但没有真把 ICR 卡在投递中。
  真硬件那条路径（`send_ipi_to` 的 `ICR_POLL_LIMIT` 超时）在本机仍然测不到（见未决）。

## 验收与负样本

**注入构建（`run --features fault-resched-ipi`，实测 `build/run-001.log`）**：

```
resched IPI失败注入(ADR-062): ack超时=0 完成=1 失败计数 0->3 收到IPI=0
t_resched_ipi_fail_fallback -> ok
ktests: total=61 passed=61 failed=0
判定=PASS qemu_rc=33
```

三个 AP 消费者各占一格等待槽，`wake_all` 发三发 IPI 全失败 ⇒ 计数 `0->3`；收到 IPI 为 0；
三个消费者都靠自己的 tick 跑完（`完成=1`）。宿主机 `check_resched_ipi_fail` 独立解出同样四个数。

**健康构建（实测）**：`resched 跨核 … IPI失败累计=0`、`ktests total=63 passed=63 failed=0`、`PASS`。
`fails == 0` 与 `delivered == checked` 同时成立——计数不误报，且不是空转。

**负样本就是注入本身**：健康跑计数恒 0、注入跑计数涨到 3，两相对照证明这个计数分辨得出
"有没有失败"。宿主机那行判据的证红：把见证行的 `失败计数 0->3` 改成 `0->0`（或删掉该行），
`check_resched_ipi_fail` 返回 False ⇒ 第 42 行 `CONTENT-MISMATCH`（矩阵复验时单独跑一遍确认）。

**踩坑（量具错，记下来当提醒）**：第一版注入放 apic.rs，被 check-vector-table 误读成 no_eoi 分支；
第一版没 gate `t_idle_hlt_wakes`，注入下 BSP idle 醒不来 ⇒ HANG（实测 120 s）。两处都不是被测物错。

## 迁移与回滚

- 无数据格式迁移。回滚＝删特性、删注入两行、删新用例与三条 gate、删第 42 行与宿主机判据、
  删 `apic::ApicError` 登记、还原 `t_cross_cpu_resched` 的判据。回滚后缺口（计数无判据）回来。
- 今后若 `send_ipi_to` 的真失败路径要在真机上测，按 ADR-024 口径另列待测项，不在本帖假装已测。

## 未决

1. **真硬件 ICR 卡死路径未测**：注入是记账点模拟，`send_ipi_to` 的 `ICR_POLL_LIMIT` 超时分支
   在本机走不到。真机（M7）要重测这一格。
2. **BSP idle 靠 IPI 醒**这条路径在注入下被 gate 掉了，没有"失败后 BSP idle 靠别的源醒"的用例
   （BSP 没有本地 tick，hlt 时本就依赖 IPI/PIT）。这是架构事实，不是本帖能补的；记在这里。
3. 新用例的消费者跑在 AP（有本地 tick），所以"失败不丢唤醒"只在**有本地 tick 的 CPU** 上被证明。
   把它推广到 BSP 需要 BSP 有独立 tick 源，那是另一个里程碑的事。