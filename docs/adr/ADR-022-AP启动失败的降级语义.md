# ADR-022: 「部分 AP 起不来」算什么——降级继续跑，但判定不放过

状态：已采纳（2026-11-05，M3b-1 实测）
关联：手册 §13.1（R20 五项清单的第 4 项）、§12.3 判定契约、§14 M3b 验收行、ADR-014、ADR-019、ADR-021、里程碑 M3b

## 背景

§13.1 的 SMP 清单在 M2-c 关掉了 1/2/3/5 四项，**第 4 项一直挂着**，原文是：

> 「AP 启动**失败**时的语义——协议只给核数与入口，不给失败语义。必须在 M3b 开跑前出一份 ADR
> 定义"部分核起不来算不算过"」

这不是可以边写代码边定的东西。Limine 协议（本仓库固定的 v11.4.1）在 MP 特性里只给了四句话：
请求存在 ⇒ bootloader 会 bootstrap 二级处理器；`cpu_count` 含 BSP；`goto_address` 首次交给 BSP 时
保证为 NULL；释放 = 一次 release 语义的原子写。**没有任何一句**描述"某个 AP 没被带起来"该怎么算。
所以失败语义只能由本项目定，而定晚了会有两种具体的坏法：

* 定成"停机"：一台有一个核接触不良的真机会**拒绝启动**——违背手册的立项理由（最小影响）。
* 定成"忽略"：QEMU 上 3 个 AP 全都起不来也照样报 PASS，"多核验证过"变成一句空话。

## 决定

分成**三层**，每层各自的出口码不同：

| 情形 | 本项目的语义 | 判定 |
| --- | --- | --- |
| **前置不成立**（bootloader 没给 MP 响应 / 还没切到自己的页表 / LAPIC 没映射 / TSC 没标定） | 不是"核坏了"，是"这台机器我们不理解"或"启动顺序写错了" | 内核**不**在这里停机（那些前置在更早的 Stage 各有 boot_invalid 出口）；到用例这一层报 **FAIL(35)** 并打出 `bringup 失败 <原因>` |
| **部分核起不来**（`refused > 0`：核数超过 `MAX_CPUS` 容量、LAPIC id 重复、栈分配失败；或释放后没报到 / 本地定时器没走通） | 降级继续跑：单核路径仍然自洽，系统不该为一个核的故障整机拒绝服务 | **FAIL(35)**。用例要求 `released == expected`（MP 报的非 BSP 核数），少一个就红 |
| **全部核正常** | 多核这件事被验证过 | PASS(33)，并把 `released/online/timer_init/id_mismatch` 这些数字打出来当证据 |

三条理由：

1. **为什么不是 EXCEPTION(39)**：39 归 L4——"继续跑就是不可恢复的状态"（重复释放、锁重入、
   中断里分配）。少一个核不是那种状态：调度器、锁、页表都只在 online 集合上工作，
   单核路径本身是完整自洽的。为它升 L4 等于把"能力不足"当成"状态损坏"。
2. **为什么不是 BootInvalid(37)**：37 是"这次启动根本没进入可判定的状态"。AP 起不来是
   **理解之内、能力之外**的失败，必须能一路跑到用例结尾并交出数字。
3. **为什么仍然要 FAIL**：M3b 的验收项是"多核压力测试通过"。把"3 个 AP 一个都没起来"
   记成过，等于用一台 4 核机器交付了 1 核的验证。容量不足（核数 > `MAX_CPUS=8`）也走同一条：
   **红**，并指名"容量不足"——静默忽略多余核就是这件事最坏的写法。

降级这件事在代码里的落点（可观察，不是口头）：

* `cpu::reserve_ap_slot` **拒绝重复 LAPIC id** 并返回 None；这是"两个 CPU 挤同一个槽位"的防线，
  也是 `sync::held_by` 重入判据的地基（令牌 = LAPIC id，id 撞了判据就废）。
* `smp::REFUSED`、`READY_TIMEOUT`、`AP_TIMER_FAILED`、`AP_ID_MISMATCH`、`AP_LAPIC_FAILED`、
  `AP_EXSTACK_FAILED` 六个计数器，全部由 BSP 打进日志。
* `t_ap_released_and_ticking` 的判据里 `refused == 0 && released == expected && online_aps == released
  && lapic_failed == 0 && isr_depth_stuck == 0`，一条不满足就红。

## 实测：这份语义第一次兑现的机会是同一次开发里我自己写错的标定

AP 的本地定时器要按周期模式装载，而 APIC 计数率必须实测（写死一个初值就是猜）。
第一版把 `spent * 1e6 / window_us` 这个**每秒计数**当成了**每微秒计数**，于是 10 ms 的初值
算成 `0x983be6a400`——远超 32 位量程，被量程检查挡下。当时的串口读数：

```
smp: mp_cpus=4 expected_ap=3 released=3 refused=0 online_ap=0 timer_failed=3 id_mismatch=0 ready_timeout=0
smp: bsp_lapic=0 cpu_ticks=[0, 0, 0, 0, 0, 0, 0, 0] ap_stages=[0, 0, 0, 0] ap_timer_init=[0, 0, 0, 0]
smp: ap timer_err=5 cal_dbg[tmcct=0xfffe012f spent=130768 dt_cycles=6628101 counts_per_us=65384000 initial=0x983be6a400]
contention: 测不成 NoApOnline
```

注意这一串数字的形状：`released=3` 而 `online_ap=0`——释放动作成功了，
但三个 AP 全部停在"定时器标定失败"这条降级分支上，各自 `mark_ready` 之后停机。
**内核没有停机，用例也没有报绿**：`t_ap_released_and_ticking` 红、`t_cross_cpu_lock_contention`
红并指名 `NoApOnline`。这正是本 ADR 要的形状；修好定点算法之后（`initial = spent * period / window`，
不在中间量上取整）：

```
smp: mp_cpus=4 expected_ap=3 released=3 refused=0 online_ap=3 timer_failed=0 id_mismatch=0 ready_timeout=0 isr_depth_stuck=0
smp: cpu_ticks=[0, 6, 6, 6, 0, 0, 0, 0] ap_stages=[2, 2, 2, 0] ap_timer_init=[653769, 656123, 657310]
smp: cal_dbg[tmcct=0xfffdfe79 spent=131462 dt_cycles=6647379 counts_per_sec=65731000 initial=0xa079e]
cpu ids: checked=4 mismatches=0 unmatched_self_lookups_delta=0 (madt_ids=[0, 1, 2, 3] mp_ids=[0, 1, 2, 3])
```

三个 `ap_timer_init` 分别是 653,769 / 656,123 / 657,310 个计数。按实测
`counts_per_sec = 65,731,000`（即分频后 65.7 MHz，对应 QEMU 的 1 GHz APIC 总线 ÷16，
与 Intel 文档"总线频率"的说法量级一致），换算 tick 周期 = 9.95 ms，与目标 10 ms 差 0.5%。
**这个 0.5% 是标定读数的换算结果，不是被测周期**：本里程碑没有每 CPU 的 tick 时间戳表，
所以用例只验"复发性"（隔一段已知时间再数一次，必须变大），不声称量到了周期精确度。
这条限制写在这里，也记在 BACKLOG。

`checked=4 mismatches=0`：MP 响应、MADT 表、以及**每个 CPU 自己读回的 LAPIC 寄存器**三个来源互相吻合；
`unmatched_self_lookups_delta=0` 说明没有哪个 CPU 在用没登记过的 id 跑（那种情况会让 per-CPU 数组
悄悄退化成 BSP 那一份）。

## 今天仍然没做到的（不算已验证）

| 缺口 | 现状 | 归属 |
| --- | --- | --- |
| 真机上"某个核彻底起不来"的**故障注入** | QEMU 上构造不出这种 AP；本 ADR 只保证了这种情形**会被看见**（六个计数器 + 用例判红），没保证它在真机上的行为 | M6/M7 可靠性验收：需要在真机或能注入 AP 启动失败的平台上重跑这一条 |
| 降级启动的**对外报告** | 只进串口日志与用例判据；没有"在线核数"这种能被上层查询的产品接口 | M4 之后的可观测面（§6.7 的台账之外） |
| AP 跑调度器 | AP 的 tick 走独立快路径（`trap::isr_stub_cpu_timer`），不建异常帧、不到抢占点；`cpu::runs_sched` 只有 BSP 为真 | M3b 下一段 |
| AP 停机之后回收 bootloader 可回收区 | ADR-019 的显式回收还没调用（AP 最初是被停车代码唤醒的） | M3b 下一段 |

## 后果

* §13.1 的第 4 项从"仍未决"变成本 ADR，§14 的 M3b 验收行因此可以写"降级语义有 ADR"这一半已闭合。
* 本 ADR 不引入新的退出码；判定矩阵当时是 9 行里的 8 行（ADR-021 那一行是本 ADR 之外新增的），
  ADR-023 之后是 9 行。
* `MAX_CPUS=8` 现在是**会导致判红**的容量上限（`refused>0` 就红），不再是静默截断；
  容量该定成多少要等真机的核数，已记 BACKLOG。
* `smp::bringup` 自己补 `apic::get_or_init` 与 TSC 标定这两件前置：`.ktests` 的枚举顺序由链接
  顺序决定，把"谁先跑过"当前提会造出一条只有换顺序才红的用例（本 ADR 落地时就撞上过：
  `t_cpu_ids_agree` 排在所有 APIC 用例之前，当时静默返回 false，一行线索都不留）。
