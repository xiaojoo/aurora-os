# Aurora OS 开发手册（企业级）V1.2

**文档编号**：AUR-DEV-1.2　**日期**：2026-11-04　**状态**：草案，待架构评审　**取代**：AUR-DEV-1.1（V1.1 文件保留在同目录，作为评审基线，不再维护）　**适用范围**：第一阶段（x86-64 内核）为强制规范；用户空间、图形、商业发布章节为前瞻性规范。

V1.2 只处理**文档内部自相矛盾与排期错位**（对 V1.1 的 11 条修订 + 1 条撤回），不引入新的功能章节。上一轮评审中提出的“仍属空白”项（Limine 交接状态清单、中断重映射、线程化中断选型、设备重置协议、可恢复内存错误处置、crash dump 宿主侧解码工具、host 平台声明、术语表、性能基线）留在 V1.3 处理，见 A.5。

## 0 阅读指南

### 0.1 相对 V1.1 的修订摘要（V1.2）

| 编号 | 修订 | 冲突类型 | 章节 |
| --- | --- | --- | --- |
| R9 | ADR-009 拆为 009a（可引入依赖的许可证白名单，M0）与 009b（发布许可证与贡献协议，公开前） | “M0 截止”与 M1 起就开始的依赖引入不相干 | 1.4, 11.2, 15.4, A.4 |
| R10 | §2.5 补齐正文已引用的 5 个 crate，并新增“crate 清单以 §2.5 为唯一来源”的 CI 断言 | 正文与仓库树不一致 ⇒ M0 验收项走不通 | 2.5, 12.1, 14 |
| R11 | ACPI 拆成“固定布局表”（M2/M3b）与“AML 解释器”（M5）两级；ADR-012 相应拆为 012a/012b | IOMMU(DMAR/IVRS) 与 SMP(MADT) 都被排在 M5，而 M3b 在其之前 | 4.1, 13, 14, A.4 |
| R12 | 可信持久存储合并为单条 ADR-011，并补“验签就绪前的临时策略” | 保护能力在 M1 生效，决策却排在 M2，正式验签在 M6/M7 | 9.4, 9.5, 11.1, A.4 |
| R13 | §6.3 页所有权改为 `map` 返回 `Mapping`、`unmap` 归还 `OwnedFrames`；`DoubleFree` 明确升 L4 | 宣称的 RAII 不变量在该 API 上不成立；`Drop` 里的错误无处传播 | 6.3, 6.7, 9.2 |
| R14 | §5.3 撤回上一轮的 CS 偏移结论（量具已核，原文正确），改为补两条入口缺口：`CR2` 未入 `TrapFrame`、`syscall` 入口 `swapgs` 窗口的嵌套中断面 | — | 5.3, 10.1, 12.1 |
| R15 | `.cargo/config.toml` 不再设 `[build] target`，改由 `just` 显式传 `--target`；`cargo test` 只跑宿主可测 crate | 设了 `build.target` 后 `cargo test` 会把测试二进制编成 bare-metal 再回宿主执行 | 3.2, 3.5, 12.1 |
| R16 | §7.1 `IrqSpinLock` 加持有者检测（防重入）、`lockdep` 移到 CAS 成功之后、守卫加 `#[must_use]`、快路径用 `Relaxed` 预读；并规定关中断自旋时长上限与 §9.6 看门狗的阈值关系 | 重入即关中断死锁；`lockdep` 会报假阳性进而被关掉 | 7.1, 9.6 |
| R17 | SMEP/SMAP 从“强烈建议”改列**必需**（或写明降级路径）；M4 打开的用户态攻击面与其防护到位时间对齐 | §6.4/§10.3 把 SMAP 当不变量用，§5.1 却允许缺失 | 5.1, 6.4, 10.3, 11.1, 14 |
| R18 | §12.4 增加四条性能基线与回归门禁，§12.3 的三档门禁纳入性能项 | 多处架构决策以“性能代价”为理由，但全局无任何性能度量 | 12.3, 12.4, 2.4, 8.5 |
| R19 | unsafe 白名单改为单一登记表并与实际统计对账；补 `exit_qemu` 的归属 crate；`[workspace.lints]` 必须逐 crate 显式接入并加 CI 断言 | 白名单数量与正文引用不齐；lints 未接入 ⇒ 门禁静默失效 | 1.3, 2.5, 10.5, 12.1, 12.2, 12.3 |
| R20 | §13 SMP 行改写为“待核实清单”（trampoline 与低 1MiB 归属、AP 初始状态、失败降级），并标注**本版本未核实** | 上一轮断言无法核实：`PROTOCOL.md` 的 SMP 章节本会话取不到（两条分支 raw 均 404） | 13, B.3 |
| R21 | §6.5 的 OOM 条款按 ADR-018 改写为“全局分配器失败即 L4 + 需 `Result` 者显式用可失败分配”，落 §6.5.1 分配规则表；§6.4 补两条 VA 不变量（取得即登记、不得在大页内铺叶子）；§6.7 补三条已实现的诊断项 | 原文两条要求在 `GlobalAlloc::alloc` 的签名上不能同时成立；M2-b 实测给出故障根因、注入证据与两处静默损坏路径 | 6.4, 6.5, 6.7, 9.2, 12.3 |
| R22 | §13.1 的 SMP 五项待核实清单换成“结论 + 依据”（4 项关闭、第 4 项仍是决策）；§6.7 补资源台账与回收两行；新增 §12.3.1 注入构建清单 | M2-c 发出 MP 请求并解析 ACPI 固定布局表，用实测取代“待核实”；过早回收 reclaimable 的代价已被量化（ADR-019） | 6.7, 12.3, 12.4.1, 13.1, 14 |
| R24 | §6.4 的 guard page 拆成"已兑现 / 仍缺"两半；§12.3.1 补 `bench-switch-load` 与 `trace-switch`；§12.4.1 记下 P1 已实现且判别只能下在 `min` | M3a 的抢占调度落地后，三条原本只能写成承诺的不变量有了实测归属；同时暴露 IF 归属未定（ADR-020、BACKLOG） | 6.4, 12.3.1, 12.4.1 |
| R23 | §7.1 登记锁的落地状态与“跨 CPU 今天测不到”的边界；§12.3.1 补两条注入构建并把中断内分配的期望改判 39；§12.4.1 新增 P5，并写下“小于离散度地板的效应不能用 P4 判” | M3a 真的开了中断、真的上了锁：多条原本停留在约定层级的条目现在有了实测归属 | 7.1, 12.3.1, 12.4.1 |
| R25 | §6.4 的异常栈 guard 补齐并逐 CPU 验证；§7.1 的"跨 CPU 测不到"作废并写下三条多核才暴露的错；§12.3.1 加 `fault-if-carriage`（期望 **HANG**）；§12.4.1 记下 P3/P5 的样本来源只有 BSP；§13.1 第 4 项由 ADR-022 关闭；§14 的 M3b 行登记已闭合的前半 | M3b-1 放了 AP：IF 归属（ADR-021）与降级语义（ADR-022）都由实测兑现，跨核锁竞争第一次有了对照组数字 | 6.4, 7.1, 12.3.1, 12.4.1, 13.1, 14 |
| R26 | §6.6 登记 shootdown 的落地状态与三条没做到的；§12.3.1 加 `fault-shootdown-noack`（期望 **EXCEPTION**）；§14 的 M3b 行登记 ADR-019 的那次显式回收已执行 | M3b-2a：解映射第一次在归还物理页**之前**等齐回执；45 MiB 的"扣着的钱"收回来并入账（实测 11,764 帧） | 6.6, 12.3.1, 14 |
| R54 | §9.7.3 那句"只敢按行比"改成两条都判；§14 的 M6 行登记 L3-A 并把"日志的整行原子性"从未完项收掉；新增 ADR-035（含被否掉的"关中断打一行"） | **L3-A：日志的整行原子性**。`serial::line` 一颗行锁（`OWNER` = 槽号+1）， 序号改在锁里取，四本账各一个成因（取锁/竞争/重入/超时），同 CPU 重入**不阻塞**而是直接输出并计数， L4 出口第一步 `unlock_for_halt()` 之后不再排队。两台仪器：内核数账（`holds == 总行=96`、`nested=0`、 `timeouts=0`、用完 `owner=0`），宿主机数形状（第 **31** 行：`整行数=96/96 tag混行=0 tag错主=0`）。 **撤锁的变异 E 才是这格的证据**：同一构建撤掉锁 ⇒ `整行数=65/96`、`10 行有两种 tag`、`3 行张冠李戴`、 `取锁=0`、`ktests 53/54` ⇒ 第 27 行那句"连续"的 claim 从修辞变成判据（⑤ 条，本轮读数 `逐行=4/4 连续=是`）。 两条点名：①`contended` 只报不判（四跑 1/2/4/6，硬写进判据就是照样本拟数，与 71a 同一错法）； ②序号递增这一条在撤锁后仍 0 逆序 ⇒ 它今天只是不变量，**没有证明能力**，不许写成"证过红"。 真机代价写在 ADR-035：一行 ≈130 字节 ≈11 ms 占住通道，所以"关中断打一行"被否掉。 矩阵 30 → **31 行**、`ktests` 正常 53 / 变体 54、`check` 13、正常构建串口量 149,717（不加字节）、 P4 地板 1.32 %、P1 地板仍按最大观测 661 | 9.7.3, 14 |
| R55 | §8.5.1 补 `irq_set_affinity`/`irq_dest` 两颗方法与那条边界；§14 的 M5 行把"中断亲和性"收成"半格已交付"；ADR-034 加补记四；BACKLOG 68f-2 那句推断就地改掉 | **L3-B 第一半：亲和性**。认领表每格带目的地（默认 BSP），`message()` 从表里读；`set_affinity` 只认已上线的 CPU（新增 `NoSuchCpu`/`Offline` 两种拒绝形状）并把新消息**交回驱动编程**——MSI 那一段从 `arm_irq` 抽成 `program_msi()`，接入与移动共用一颗。两台仪器各数归属：内核 `by_cpu()`，宿主机数 `-d int` 的 `SP` 高位 ⇒ `内核=6 宿主机=6（BSP栈=5 AP栈=1 其它=0）`，判定表加第 **32** 行。三个变异：F1 分类器一律算 BSP ⇒ 两条"对不上"红（证明归属不是抄来的）；F3 不编程且伪造回读 ⇒ 核外红而**内核漏**；**F3b 不编程而回读照真 ⇒ 内核 `回读逐字=false` 红 + 核外两条红**（这条才守住"写了不等于收下了"）。（本行里「实测改掉 68f-2」那句已被 R56 按 n=12 收回：目的地在 AP 时 BSP **不再**记 `中断落定`，12/12 记进 `赛跑`；73f 那格待办由 R56 交付。）边界点名：没有静默（不 mask 就移动）、核下线时中断往哪搬没有答案、只有一个用户（AHCI）、第 28 行**没有放宽**。矩阵 31 → **32 行**、`ktests` 正常 53 / 变体 54、`check` 13、串口量 149,729、P4 地板 1.08 %（P1 地板仍 661） | 8.5.1, 14 |
| R56 | §14 的 M5 行把 73f 那格待办收掉；BACKLOG 73c 整段作废并按 n=12 重写；ADR-034 加补记五；p4-tolerance 登记 P4 地板离群值与"阈值不动"的理由 | **73f 交付：服务侧的按 CPU 分账**（`ISR_ENTRY_CPU` / `RACE_HITS_CPU` / `RACE_MAX_CPU` + 两个出口），`KT_IRQ_AHCI` 加第 **⑦** 格"分账之和 == 总账"（正常构建就判），`t_irq_affinity` 每步多打 `顶半按CPU=[…]` 并判两件事：目的地在 AP 那一步顶半只能出现在 AP 那格、搬回之后反过来。**同一批把 73c 那句推断收回**：上一轮我写"旗子是全局的，目的地在 AP 时 BSP 照样记 `中断落定=1`"——那是三跑的样本；n=12 的结果是 `中断落定 0/12、赛跑 12/12、轮询 0/12`，搬回 BSP 才是 `4/8/0`。⇒ 搬目的地等于把"叫醒"改成"赛跑"，正确性不变但角色变了，MSI-X（一向量一目的地）必须按这条算代价。两条变异各自有牙：G1 分账恒记 BSP ⇒ `t_irq_affinity` 红；G2 总账不记 ⇒ **正常构建** `t_irq_ahci` 红（`ktests 52/53`）。另一条登记不处理：同一份 ELF 的 P4 地板三次是 **8.70 % / 1.58 % / 0.32 %**，8.70 % 那一次 P1 差 647、DMA `min` 70,998 一起偏高，形状像宿主负载但没证 ⇒ **阈值仍停 8 %**，待办是把地板量到 ≥10 个样本再决定。门禁：`check` 13/13、判定表 **32/32**、`ktests` 正常 53 / 变体 54、串口量 149,785（+56 B 是第 ⑦ 格读数的永久成本） | 14, 12.4.1 |
| R57 | §12.3.1 加“第二台宿主机：WSL 里同一颗 QEMU 只换 `-accel`”那一格；§13.1 那条“跨 CPU 结论的时钟前提”补上它的一般式（窗口长度必须是**时间单位**，且估计器换成相邻间隔）；§14 的 M5 行**作废** M5-g① 那句“表在 `BIR=1` 偏移 `0x800`”；新增 ADR-036 | **KVM 对照档第一次跑通就照出两条错法**。① 等墙钟事件的窗口按**轮数**封界：同一颗 10.2.1 只换 `-accel`，kvm 档当场 `FAIL(35)`，红在 `t_cpu_ids_agree` 与 `t_timer_ticks_recur`，链路 `clock: calibration refused: NoSamples`；而**同一份构建第二次调用标定却有 4 个样本**（`clock: 4 ticks in 101191740 cycles`）⇒ 样本数压在 `ticks < 4` 那条门槛上，结果取决于窗口起点落在 tick 相位的哪一侧。对照实测（改完之后 16 跑）：同一个 200,003,016 cycles 的上界，tcg 走 3609~3936 轮、kvm 走 7830~8913 轮（2.2×）。上界改成 `clock::window_cycles(s) = MAX_TSC_HZ × PIT_DIVISOR / PIT_HZ × s`（本机 s=4 ⇒ 200,003,016 cycles），跟着 TSC 区间那两个端点走，**没按任何一次观测调过**。② `t_timer_ticks_recur` 的“关 IF 空转”段原来只有 0.13 个 tick 周期长 ⇒ **那条判据是空转的**：注入“空转窗口其实开着 IF”，旧长度三档全绿（K2b），新长度三档 `if_gates=false`（K2）。加长以后逼出两格：`drained`（挡下的必须重新开中断才交出来——**挡住≠丢掉**）与 `again`（基线取在排空之后）。第一版没排空，实测 `第二段 2 ticks / 10,363,532 cycles` 对第一段同样 2 个 `67,609,419 cycles`——**同一个量差 6.5 倍说明有一次没在测它声称的东西**。③ 估计器换掉并作废旧数：`总 cycles ÷ tick 数` 因窗口两端切边而系统性偏高，改用 ISR 量的相邻间隔均值；对表用与虚机无关的第三个仪器（WSL `dmesg: tsc: Detected 3187.201 MHz`），16 跑：旧 **+4.59 %**，新 tcg −0.76 %~−0.03 %、kvm −0.15 %~+0.15 %。BACKLOG 56 那行 `period ~ 14.4M cycles/tick ⇒ TSC≈1.44 GHz` 一并作废——那是拿第二段 cycles 除四段 tick 数，**除错了量**，不是“估计保守”。④ 两条仪器事实：`-accel kvm` 下 `-d int` **0 行**（tcg 档同时给 `-trace file=` 也 0 行，与 67/68 那条一致）；`-trace events` 挂在设备上、两档都有（`raise` 483 对 466）。`check` 13/13、判定表 **32/32**、`ktests` 正常 53/53、msix 变体在 WSL 两档各 8 跑 56/56、串口量 150,611 B（上一轮 149,785 ⇒ +826 B，逐行可归因 813 B）、P4 地板 0.10 %（阈值不动）、P1 地板 339（最大观测仍 661） | 12.3.1, 13.1, 14 |
| R52 | §12.3.1 给 `-d int` 那一挂法补上它自己的副作用；§14 的 M5 行登记第 28 行的偶发红已定位、处置未定；ADR-034 补记二加第 4 条 | **第 28 行 1/10 的假红定位完成，红不在中断**：那一跑的六个维度全对，真正失败的是 `t_cpu_ids_agree`，链是 `clock: calibration refused: MissedTicks` ⇒ AP 上机被拒 ⇒ 用例红 ⇒ 判定 `FAIL(35)`。幅度读数 1.59 与 1.75 倍（门槛 `max_tick_gap > mean + mean/2`＝1.5，真漏 tick 应是 2.0）⇒ 形状是「一次间隔被拉长」而不是「少了一发」；对照是同一构建**不挂 trace 连跑 20 次 0 次**、挂 trace 30 次 3 次（Fisher p≈0.09，归因写成当前最省的解释，不写成已证）。内核行为是对的：宁可不给可用的 ns 换算。本轮进代码的只有核外读数：`check_irq_trace` 尾部多 `内核用例=52/53 红用例=[t_cpu_ids_agree] 标定被拒=MissedTicks`，**判据没放宽、没加豁免**。两条新规则生效：①挂 `-d int` 的那一跑不许引用任何耗时数字；②`mark_healthy()` 只在 `failed==0` 时清计数 ⇒ 期望 PASS 的行会不会落进安全模式取决于它前面连着几行不健康（本轮否掉了「第 28 行红是跨跑残留」这个第一反应，但这条脆性本身留着） | 12.3.1, 14 |
| R53 | §13.1 补写"跨 CPU 结论的时钟前提"；§12.3.1 登记 `-trace events` 这一条通道与新变体； §14 的 M5 行登记 M5-g④ 并把 68f-3、69f-2 两格待办收掉 | **矩阵 28 → 30 行**：第 29 行在正常构建上数 「边沿与被吸收的 raise」（`raise=483 边沿=6 被吸收=477 投递=4`），第 30 行用变体 `irq-sticky-pxis` 从反方向夹同一条模型（`raise == 边沿 == 投递 == 106,753`、期望 `HANG(-1)`、窗口 6 秒）。 两条新事实：①**先清端口 `PxIS`、后清全局 `IS` 这个顺序是风暴开关**——不清源时驱动自己清全局位那一步 每次都成为新边沿，180 秒 4,747,919 条消息并挂死，日志 7.4 GiB；②**容差必须按机制给**： `abs(边沿−投递)<=1` 是照一个样本拟的，边沿从 5 变 6 就假红，现在写成方向式（投递绝不许多于边沿）。 三条变异（D1 放宽投递数法 ⇒ 红；D2 注入取反 ⇒ 不再挂死且三条红话全发；D3 八份档案喂放行器 ⇒ 8/8 如设计）。 69f 那颗三选一选了"窄化版 (a)"：只有 `t_cpu_ids_agree` + `MissedTicks` 比值落在 [1.5,2.0) 才放行， 六个维度对不上绝不放行。同一批 24 连跑另抓到一条**不属于本轮**的偶发：`t_task_exit` 1/24， 红在"回收没在有界 tick 窗口里被看见"，放行器正确地拒绝了它 ⇒ 挂了待办。 正常构建 ELF `33e1c39beb08 → 5d10dcadc6bf`（helper 进了代码），四把尺子重量：P4 地板 0.32 %、 P1 同构建差 661（本轮最大观测）、P2 读 529 / 写 1,381、串口量 149,732。`check` 仍 13 道、`ktests` 仍 53 条 | 13.1, 12.3.1, 14 |
| R51 | §14 的 M5 行把「投递风暴机制」从未完项收掉；ADR-034 的「没做到的」①②就地更正并加「补记二」；§12.4.1 那条「一台仪器只数一件事」在这里有了具体形式（`irq_hits` 由「完成计数」改口为「投递计数」） | **4→387 发风暴的机制查明，结论与上一轮的登记相反**：设备侧 `raise` 次数两边几乎一样（正常 482／变异 391），`cmd_done` 也一样（687／669）——差的不是设备重投，而是**正常那一跑有 477 次 raise 落在「线本来就高」的窗口里、没变成消息**（口 0 的 `PxIS` 留着不清 ⇒ `irqstatus` 恒 1 ⇒ 电平不翻转 ⇒ MSI 不发）；变异把目的地搬到 AP 之后顶半勤清源（W1C 206→583），每次完成都成了新边沿 ⇒ 387 发。证据形状是「每次 raise 之前那次 `check_irq` 的 old→new」这张表（5 边沿↔4 发、381 边沿↔387 发），仪器是同一次 QEMU 跑的第二条日志通道 `-trace events=…`（`-d int` 与 `-trace file` 同给会合成一份，实测）。**边界点名**：`qemu_irq_raise` 以下那层本机无源码，「只有边沿才发消息」是按对应关系**推**的，把它坐实的那一行判据（留着 `PxIS` 不清 ⇒ raise 继续涨而投递停在 1）已带截止点挂进 BACKLOG 68f。两条连带：①`SP` 高位分辨得出 BSP／AP，67a 那句「读不出投给了谁」说过头了，已收回；②中断亲和性必须与「消费完成的那一侧」同侧，否则第 28 行 `sum(by_cpu[1:]) == 0` 会把正常行为判红。本轮**没改内核代码**：`check` 13、矩阵 28、`ktests` 53、串口量全部不动 | 8.5.1, 12.4.1, 14 |
| R50 | §14 的 M5 行登记 M5-g③；§12.3.1 记录 `-d int` 那一跑的挂法；ADR-034 的「没做到的」第 1 条关闭 | M5-g③：判定矩阵 27 → **28 行**。仪器读的是 QEMU 自己打的投递日志（`-d int -D build/irq-trace.log`），与内核两本账对六个维度；**这台 QEMU 的格式里没有 CPU 编号**（前导字段 0..1273 单调递增而 `-smp 4`）⇒ 「投给了谁」必须由内核 `irq::by_cpu()` 报，核外那侧负责总数/`cpl`/`pc` 窗口。「pc 是出事瞬间被中断的指令地址」这条也是量出来的：固件阶段的投递 pc 是平坦地址，所以「IDT 在不在场」这条界用它划，越界的单独报红而不混进相等式。三条变异（删 trace／目的地改 AP／放宽过滤）各自红。`check` 仍 13 道（这是判定表的一行，不是静态门禁），`ktests` 仍 53 条，P4 地板 0.15 %、串口量 +40 B。仍欠：MSI-X 与共享电平 INTx、中断亲和性、ISR 里 `request_irq` 被拒的判据（那 4→387 发的风暴机制已由 R51 查明） | 12.3.1, 14 |
| R49 | §8.5 新增 §8.5.1（M5-g② 落地状态）；§14 的 M5 行登记 M5-g②、把"中断认领"从未完项收成只剩 M5-g③；新增 ADR-034 | M5-g②：核内认领表（向量 `0x21..=0x2F`、句柄=槽号+世代号）+ `DriverCtx` 第一次长新方法（`request_irq`/`irq_message`/`irq_counts`/`release_irq`）+ AHCI 的 MSI 接入（`arm_irq`，独立一步）+ 顶半 + `wait_settled` 三本账 + `KT_IRQ_AHCI` 六格。`ktests` 正常 52 → **53**、矩阵仍 27 行、`check` 仍 13 道。三条必须点名：①**"中断到过"不等于"数据搬完了"**——第一版一看见旗子就返回，宿主机对账当场报 `槽0 对不上：…failed=0，内核报…failed=1` 而内核 53 条全绿，旗子的角色降为叫醒、放行仍验 `PxCI`+BSY/DRQ；②**接入不能藏在认领里**，因为 `ahci::init()` 比 APIC 初始化早（实测 `Denied("本地 APIC 还没初始化")`）；③**P2 的 MMIO 写 `min` 625 → 1,374** 由 A/B 实测归因到一次中断服务落在采样窗口里，比值判据照常符合，但绝对数与本轮之前不可比（§12.4.1 规则 2）。仍欠：M5-g③ 核外对账、ISR 里 `request_irq` 被拒的判据、中断亲和性、virtio 的 MSI-X 表条目、共享电平 INTx | 8.5.1, 14 |
| R48 | §9.7 新增 §9.7.3（崩溃栈与最近日志的落地状态）；§14 的 M6 行登记 M6-e/M6-f 并**作废** M6-d 那句"产物没有帧指针"的归因 | M6-e/M6-f：返回地址的门禁从"8 字节对齐"换成"生效权限说它可执行"（x86-64 指令变长，实测第一层返回地址 `0xffffffff80010517` 被旧判据判死 ⇒ `帧数` 停在 1；M6-d 归因成"产物没有帧指针"是错的，开关早在 `.cargo/config.toml` 里，本轮实测 P1/P3/串口量三项都没挪 ⇒ 那笔"基线重算"的账作废）。真实现场现在 3 帧，由宿主机拿 `.symtab` 逐条解成函数名（新仪器，`.symtab` 不在运行时镜像里 ⇒ 只能核外判；`st_size==0` 的符号不收）。`log_tail` 落地：`[AtomicU8; 4096]` 旁路挂在 `READY` 检查之前 + 状态区第三条记录 `kind=3`（16 固定 + 464 文本 ⇒ 实测 3~4 行）、三道读侧自洽（长度/末字节换行/行数=换行符数）、`crash_seq` 配对。矩阵 26 → **27 行**、`ktests` 正常仍 52 条（`KT_CRASH` 十一格 → 十五格）、`check` 仍 13 道（`check-state-window` 扩两条常量 + 一条**推导**对账）。两条必须点名：①第 27 行**按行集合比而不是按连续子串比**，因为 `serial::line` 今天没有整行原子性，SMP 现场"连续"这条 claim 本来就可能是假的；②多这一条记录的代价是量的（stage6 +10,238 字节，办法是临时关掉 `write_log` 再跑同一构建）⇒ **状态区成本按记录条数走，不按字节数走** | 9.7.3, 14 |
| R47 | §11.2 补 SBOM 与可复现构建的落地状态（含两条边界）；§14 的 M9 行登记 M9-b | M9-b：`tools/aurora.py release` 一次跑完"两次全量编译比 ELF 摘要 + 独立走一遍 FAT 打印 6 个条目的内容摘要 + 生成 `docs/release/sbom.json`"，新门禁用 `cargo metadata` 全图与 SBOM 对账，许可证要么在 `crates.toml` 的白名单里、要么是**登记过的留空**（带理由）。三条必须点名：①**外部 crate 实测 0 个** ⇒ `cargo deny`/`cargo vet`/vendoring 今天没有可管对象，这不是把它们省掉的许可，是门禁先立着等依赖进来；②两个成员都没声明许可证（ADR-009b 未定），我**没有**替他把许可证填成 MIT，而是登记留空——把自己的决定冒充成上游的决定是这类流程最常见的腐败方式；③可复现只做到**同机同 `target` 目录**那一层，换目录/换机器/换 CPU 没测，所以结论就这么写（Limine 的 `BOOTX64.EFI` 是预编译产物，它的可复现不在本仓库手里，今天只做哈希固定，与 ADR-017 同一形状）。`check` 12 → **13 道**；三道红证里第三条抓的是我这轮刚写的门禁本身（`license_policy()` 按整篇文本搜，注释掉的豁免照样算数 ⇒ 撤掉豁免读不出来；改成只数活行才红） | 11.2, 14 |
| R46 | §11.1 签名那一格补落地状态（并写明**没接到启动决策**）；§12.3 加第 11、12 道门禁；§12.3.1 加 `sig-check` 与它的第二遍；§14 的 M9 行登记已交付的两格与不成立的验收句；新增 ADR-033 | M9-a①②：核内零依赖 SHA-256（三道仪器：按定义重算 K/IV、`hashlib` 判 13 条长度向量、内核自评五格）+ Lamport 一次性签名的验签链（锚点内置=整张公钥的摘要，公钥/签名/载荷随包交付，包在状态区之后同一段 GPT 空隙 LBA 67_664 起 113 扇区）。矩阵 24 → **26 行**、`check` 10 → **12 道**、`ktests` 正常 52 条 / `sig-check` 变体 54 条；P4 同构建地板 **0.18 %**（上一轮 159 字节的串口差**没复现**，仍不归因）。四条必须点名：①改 `σ1` 一个旋转量时**内核五格全真、判定仍 PASS(33)**，只有 hashlib 看得见 ⇒ 密码原语上自我一致等于零证据；②我凭记忆写的锚点 32 个字节里 24 个是编的，被 `check-sig-anchor` 判红 ⇒ 常数交给工具生成 + 每轮重算，这条是自曝不是发现；③"负样本要指到它点名的那一格"重演：载荷长度字段翻在低字节得到 `BitMismatch(0)` 而不是界检查，改翻高字节才走到 `PayloadTooLong`，九条现在各走一个不同分支；④验签今天跑在一条用例里，**"验不过就不启动"没有落进 boot 路径**（要 ADR-011 正式 + §9.5 槽位身份），生产钥匙的保管/轮换/吊销一条都没有 | 11.1, 12.3, 12.3.1, 14 |
| R45 | §8.6 那句"RX 未做"作废并补上第一条协议往返；§12.3.1 加 `virtio-net` 的第二遍（协议对账）；§14 的 M8 行登记 M8-a②；ADR-032 加 M8-a② 补记 | M8-a②：对端不是我写的桩，而是 QEMU 用户网络**自带的 DHCP 服务器**——内核发 DISCOVER、收一条 590 字节的回话，`yiaddr` 必须等于宿主机自己定的 `dhcpstart=10.0.2.15`（内核猜不到这个数 ⇒ 这一行唯一"答案在核外"的判据），并由**两条独立实现**（内核 `parse_reply` / 宿主机 `bootp_of`）逐一比对 `op/xid/msg/yiaddr`。DISCOVER 那 290 字节也被宿主机重算逐字节核对，第一次比就抓出**宿主机那份**的错（IP 总长度字段只数了首部 20 字节）。四条实测进 BACKLOG 59：用户网络**不答 ARP**（42 字节的请求确实上线了，零回话）⇒ 触发器只能选 DHCP；`magic cookie` 我凭记忆写成 99,130,131,15，而 **slirp 不校验入站 cookie ⇒ 内核里没有任何一格能抓到它**，把它纠正的是对端写回来的 `0x63825363` ⇒ "寄存器表要设备自己作证"这条经验扩到**协议字段**；收方向 `used.len = 头长 + 帧长`（实测 600 = 10 + 590）⇒ 帧长要减头并验上下界，`used.id` 必须是**我们挂上去的那条链**；同一份构建两次跑出 OFFER(2) 与 ACK(5) 各一次 ⇒ 判据接受两者，为什么没有解释、不归因。矩阵 23 → **24 行**、net 变体 `ktests` 53 → **54 条**、`check` 仍 10 道（对账表扩大）。P4 地板这一轮报 **0.00 %** ——那是千分比整数除法压出来的（绝对差 21,371 周期），**不拿它收紧阈值**；且两遍串口量差 159 字节，说明那"两遍之差"里含一件真发生过的事（未归因，已挂带截止点的待办） | 8.6, 12.3.1, 14 |
| R44 | §8.6 加一段"virtio-net 已到第一帧可判"；§12.3 加第 10 道门禁；§12.3.1 加 `virtio-net` 那一行；§14 的 M8 行**只登记能判的那一半**并写明验收句未成立；新增 ADR-032 | M8-a①：virtio-net 的 TX 队列建起来，两帧上线，**帧的每个字节由宿主机的 pcap 判**（矩阵第 22 → **23 行**、`check` 9 → **10 道**、`ktests` 正常 52 条 / net 变体 53 条）。四条只有现场能给的读数：不接受特性时设备按 **10 字节**剥头（pcap 里那帧的第一个字节就是目的地址，头长错一格当场露）、QEMU 给 transitional 网卡的 PCI device id 是 **`0x1000`**（规范式子算出 `0x1001` ⇒ "我是网卡"改由"队列数 ≥ 2 且 RX/TX 门位不同"判，实测 `队列数=3 门位rx/tx=0/1`）、配置区**只有 8 字节存在**（`mtu`/`max_pairs` 读回 `0xFF` 是"这一格不存在"，我第一版的宽度证人因此是**假绿**——它比的是同一串填充字节，改成 `Option<bool>` 后取 `None` 并照样打印）、`filter-dump` 是**双向**的（抓包文件里另有一条源 MAC 与本机完全相同的 IPv6 报文 ⇒ 分内外只能按只属于我们的 ethertype，"包数 == 帧数"这版判据就是这么红的）。P4 同构建地板 1.20 %（串口量 +8 字节，不归因；阈值仍停 8 %） | 8.6, 12.3, 12.3.1, 14 |
| R43 | §8.7.1 补一句"第二台控制器已经能跑 I/O"；§12.3.1 加 `virtio-blk` 的第二遍（宿主机对账）；§14 的 M5 行登记 M5-f② | M5 的"存储读写"从只有一条路径变成**两条**：virtio-blk 建 split queue 并跑通第一条读与写，资源同样全部经 `DriverCtx`（`check-driver-ctx` 扫 `virtio.rs` 为绿）。四条只有现场能给的读数：队列地址三格**确实可回读**（这条以前只能按规范假设，所以现在存成 `Option<bool>`）、`queue_enable` 读回 1、`notify=0x3000`/`multiplier=4`、一条读请求 `used.len=513`。两条必须点名的做法：①**写落盘的字节由第二台仪器核**（矩阵第 22 行：宿主机 `qemu-io` 读扇区 8 的哈希 == 内核写前 == 内核读回），只比内核自己那两个哈希证明不了"盘上真是那样"；②夹具图案字节 `0x5C` 在两边各写一份 ⇒ 新增第 **9** 道门禁 `check-virtio-pattern`，它是**我自己先写错成 `0x5A` 时被现场抓出来的**，不是事后补的门禁。顺带补 `DriverCtx` 的 `dma_read16`/`dma_write16`/`dma_copy_in`（u16 字段用两次字节访问拼会造出设备能看见的中间态）| 8.7, 12.3.1, 14 |
| R42 | §9.7.1 的"落点"那一格标注**作废**并新增 §9.7.2（V2 落地状态）；§12.3.1 加 `fault-crash-oops`；§14 的 M6 行登记 M6-d | M6-d：崩溃记录从"三样摘要"变成 V2 的 12 个字段 + 最多 32 帧，**并且删掉了"跨槽续块"这个设计**——算过上界（`64 + 8×32 = 320 ≤ 480`）后一个槽就装得下，多槽只会把"撕裂只毁一个槽"复杂化而不换来容量。三条必须点名：①扫描改为"头部一次扫 + 该种类的**候选表**"，因为头部过校验 != 正文解得开，只挑最新那一条会让一条自相矛盾的记录**锁死整个种类**（那是 §9.4"坏记录不许把状态机卡住"的反面），新增的三条退回判据（尾帧撕裂 / 帧数与长度不自洽且校验和是对的 / `size` 指到区外）各自能红；②新增 `fault-crash-oops` 构建（核心态故意读未映射地址 ⇒ #PF(14) 无恢复项 ⇒ 39），第 21 行验"记录里的向量=14、CR2=注入地址、且与同一遍串口那条现场同数"——没有这一行，那 12 个字段测的只是搬运工；③**真实现场今天只走得出 1 帧**（实测 `向量=14 cr2=0xffffc00000000008 帧数=1`），同一套代码在合成三层链上走出 4 帧 ⇒ 机制成立、缺的是被走的现场（产物没有帧指针）。开 `force-frame-pointers`/CFI 会挪 P1/P3 基线，所以记在 BACKLOG 而不是悄悄改 | 9.7, 9.8, 12.3.1, 14 |
| R41 | §9.6 新增 §9.6.1（只交付"软锁死的检测与可见"，另两格写明今天量不出来、不冒充已交付）；§14 的 M6 行登记 M6-c① | M6-c①：`watchdog` 用**每核自己的定时器 tick** 当心跳，连续 3 个 50 ms 窗口不前进就算锁死；轮询点挂在 `tsc::stage()` 的阶段边界上（花费算进同一段 delta）。处置今天没有——`actions` 恒 0 且有判据钉住它不许偷偷变非 0（把核摘线要 §8.2 的隔离，而它按驱动组织、没有 CPU 这一维）。三条实测形状：①BSP 的心跳来自 `PIT→I/O APIC` 那条线、AP 来自本地 LAPIC 的 `VEC_CPU_TIMER`，**两台来源不能混**（BSP 的 `cpu_ticks` 永远是 0，照读就每个窗口都报警；接错来源时"消警"那格当场红）；②报警允许落在第 3 **或**第 4 个窗口——`timer_stop()` 之后还有一个在途 tick 会落进计数，同一份构建跑两遍实测读到 3 与 4 各一次，写成"恰好第 3"就是一条会自己飘红的判据；③用例进来时先量"心跳原本在不在前进"，因为 `.ktests` 顺序由链接器决定而有用例会把表停掉（第一版没读这个事实，报警窗口整个错位、当场红） | 9.6, 14 |
| R40 | §9.7 新增 §9.7.1（只落成摘要的落地状态与七格判据）；§14 的 M6 行登记 M6-b①/②；`§9.7` 正文那句"字段覆盖 V1.0 列出的所有项"按实测改成目标而非现状 | M6-b②：崩溃摘要在停机前落到 ADR-031 的状态区（`kind=2`，只有向量/CPU/RIP 三格），下次启动读回来。三条必须点名：①**写入收口在 `exit::finish(ExceptionFatal)` 而不是逐个 L4 调用点**——漏一处的表现是"盘上安静地没有记录"，这条链上没有别的尺子会报，实测把收口去掉之后矩阵第 20 行立刻 `SEQ-BROKEN`；②**注入"设备坏了"要选对那一格**：`DEAD_PORT` 只拦 `start_port`，而崩溃摘要这一步端口早就起好了、命令照样跑，用它注入会得到假通过，改用非法命令码才真拿到 `Err`；③**用例自己会污染"上一条崩溃"这条链**，必须存/还两种记录，还要把"已经落过"的旗子放回启动值，否则假记录会吞掉后面真崩溃的那一条。矩阵 19 → **20 行**、`ktests` 50 → **51 条** | 9.7, 12.3.1, 14 |
| R39 | §9.4.1 加"安全模式出得来"那一行与两条实测；§12.3.1 补齐 M5/M6 那 8 行注入清单（含 `ahci-scratch`、`virtio-blk`、跑四遍的 `negative-probe`）；§14 的 M6 行按 M6-a①/②/③ 分段登记 | M6-a③：验收句"注入故障后系统可自动恢复或进入安全模式"里**进得去也出得来**这一半第一次成为判定行（矩阵第 19 行，实际值是三遍启动的序列）。四条必须点名：①**健康判据拿理想态基线比降级现场** ⇒ 一次偶发=永久锁死（实测连红 9 遍），改成比"进入时那个模式的应有数"；②本机 QEMU **偶发吞掉一次 `PxCI` 发射**（写 1 读回 0，24 连跑抓到 1 次），它的下游正是 §9.4 的"读不到⇒最坏情况"，处置是 `recover` 后重发一次、第二次仍被吞才交 `Err`；③`t_copy_user` 用 `served()` 当"程序跑完了"，而那计数在 syscall **入口**就 +1 ⇒ 红绿两遍只差一格 `buf_err`（`Some(0)` 对 `Some(-3)`），改成为那一格有界等待并把轮数打出来；④判定表里两行**共用同一份证据变量**，其中一行静默变成另一行的副本而矩阵照样全绿 ⇒ 新增第 8 道门禁 `check-matrix-wiring`。矩阵 18 → **19 行**、`check` 8 道、`ktests` 50 条本轮全绿；P4 同构建地板 0.38 %（不归因，阈值仍停 8 %） | 9.4, 12.3, 12.3.1, 14 |
| R38 | §9.4 新增 §9.4.1（落地状态与四条没做到的），§9.4 正文那句"持久化位置是待定决策 ADR-011"改成"011-临时 已按 ADR-031 落地 / 011-正式 仍排 M6 后半"；§14 的 M6 行按 M6-a①/② 分段登记 | §9.4 那句"读不到就按最坏情况"第一次跨重启可判。**同一份镜像不重建连跑四遍**：读到的连续失败 `[0,1,2,3]`、模式 `Normal/Normal/Normal/Safe`，判定成为矩阵第 18 行；健康启动清回 0（不清的话一次成功之后计数照样一路涨）。安全模式的后果只落到今天真的存在的那件事上：AHCI 起口数实测 6→1，模式经 `F_SAFE_MODE` 位可见。**第三条必须点名**：判定表里"启动循环"那行把 `lv/lrc/llog` 复用成了循环变量，于是"泄漏注入被检出"读的是负样本构建的第四次启动——两行恰好都期望 `FAIL(35)` ⇒ 矩阵 18/18 全符合而那条判据已经不再测它点名的东西。新增第 8 道门禁 `check-matrix-wiring`（行名不重、每行有自己的证据、两行不许共用日志或退出码变量，并给门禁自己配了"解析行数 == 元组行数"的对账），它是**先对着带 bug 的现场红过一次**再修的，不是靠注入造出来的红 | 9.4, 12.3, 14 |
| R37 | §8.7.1 的"未定"关掉（class 解码表由 `KT_PCI` 六行钉住，要求 ≥4 台）并登记 BAR 尺寸探测/`DriverCtx` 已交付、MSI-X 仍待做；§12.4 的 P2 行从"首次可用 M5"改成实测数字与两条量具自检；§14 的 M5 行按 M5-a→M5-e 分段登记已交付与未完 | M5 的"存储读写 + 驱动故障可重置或隔离"两半验收句成立，P2 上线。三个必须点名的实测：①**带错完成时本机不释放 `PxCI`** ⇒ 只看 `PxCI` 的轮询会把"设备报了个错"读成"设备卡死"；②**恢复结束时端口里可能还挂着旧命令**（实测一次：请求 8 扇区、`PRDBC` 只有 512 字节）；③**`DriverCtx` 的代价分成两档**——一次寄存器读 554 周期，一次 DMA 映射+撤销 37 674 周期（68 倍），所以"微内核迁移值不值"这句话从此有数可对。门禁从 5 道到 **6 道**（新增 `check-driver-ctx`） | 8.3, 8.7.1, 12.3, 14 |
| R36 | §8.3 补 MMIO 抽象的落地状态、新增 §8.7.1（M5-a：ECAM/CAM 两条配置路径 + 枚举表 + 判据）；§14 的 M5 行登记已交付的那一块 | M5 开工。实测这台 q35：ECAM `pa=0xe0000000`、6 台设备、`1f.2` 是 ICH9 AHCI（M5-b 的存储入口就是它）。两个诚实记录：①第一版把"越界"写成 `write32(4092)`——那是范围内合法偏移，**量具错了不是代码错了**；②`0x08` 的 class 字节没被证据钉住 ⇒ 字段改名 `cfg08`、`first_of_class()` 不写、并规定"要用类别先钉解码表" | 8.3, 8.7, 14 |
| R35 | 注释清扫（无功能改动）：`main.rs` 新增 §12.3.2「M4 用户态用例的判据清单」、§12.4.1.1「跨 CPU 读计数表的发布顺序」，ADR-024 新增「GDT/IDT/TSS/异常栈为什么成套 per-CPU」一节 | 代码里 44 个 ≥10 行的注释块压到 2 个（剩下的是 `sched.rs`/`cpu.rs` 的文件头，一条事实一行、没有历史现场）。**压缩前逐条 grep 确认文档里已有同一句话**，缺的两条（发布顺序、成套复制）先补进文档再删代码里的。留下的判据原则：注释只写"改这段代码必须知道的事实 + 去哪看论证"，现场、归因过程与实测数字一律进文档 | 12.3, 12.4, A.4 |
| R34 | §10.1 登记 `syscall`/`sysret` 快路径已落地（ADR-025 的 GS 窗口那一半兑现）；§10.2 的调用号表加 `7=abi_info`、"破坏寄存器"那一行从**承诺**变成实测；§12.4.1 把 P7 拆成 `int0x80` 与 `syscall` 两套格子并写下本机对比；§5.1 加"SYSCALL/SYSRET 是可选特性"一行；A.5 的 swapgs 窗口那一格关闭 | M4-4 实测：程序自己读回 `cs=0x23 ss=0x1b`（选择子是硬件从 `IA32_STAR[63:48]` 加出来的，内核里的常数说了不算）、`abi=0x40007`、`efer=0xd01`；`ktests total=44 passed=44`。**本机结论与 V1.2 的暗示相反**：`int 0x80` warm `min=312` vs `syscall` warm `min=324` —— 换入口没有可测收益，贵的从来是"某条内核分支第一次执行"（见 §12.4.1 与 ADR-025） | 5.1, 10.1, 10.2, 12.4.1, 14, A.5 |
| R33 | §10.2 加"错误码表（M4 冻结）"行；§10.7 的 `MAX_OWNED` 行换成按段分配的实测值；§10.3.1 的 `UserSlice` 欠账降级为"表达力问题而不是安全问题" | M4 三条容量/ABI 欠账落地：①`user::load` 按段连续分配（夹具的映射数 7 → **6 / 8**，余量判据 ≥ 2；向上取整会多占 VA ⇒ 下一条段 `VaTaken`，那是 ADR-028 病因的第三种形态）；②错误码 `-1/-2/-3` 冻结，**每个号都有一条真实调用作证**（`-3` 由程序故意超限打出来），且不预先摆出还没有返回分支的码；③`read_slot`/`read_at`/`write_at` 三条"自己 `stac` 包一次裸访、唯一把关人是 SAFETY 注释"的入口全部改走带校验的拷贝，`stac`/`clac` 从 Rust 的 `extern` 声明里删掉——白捡一条硬保证：`read_at` 打在已回收的 VA 上现在返回 `None` 而**不再是**一次 ring0 的 #PF（⑭ 那条"量具自己把整机打死"从此结构上不可能）。同一轮把 M4-2 抄在文件里的三组读数按当前构建改正（`live` 基线 0 → 1、`reservations 16→16` → `17→17`） | 10.2, 10.3, 10.7, 14 |
| R32 | §10.3.1 从"四条"改成"六条"并登记**跨页拷贝 + 窗口内可恢复故障**已落地（`KT_COPY_USER` 七格）；§10.2 加 `5=peek_buf`/`6=poke_buf`；§10.7 的容量行改成实测值（一个任务的映射数 7 / `MAX_OWNED = 8`）；§12.4.1 的 P4 地板补一个数据点 | 这一段最贵的收获不是功能而是一条纪律：**注释在承诺代码没做的事**——上一版 `peek_u64` 的注释写着"校验与读在同一次持锁期内"，代码是锁外校验、锁内读，而单 CPU 用例永远测不出来。同类的还有"上限写成 `len.min(COPY_MAX)`"（注释却写"明确拒绝不是截短"）与"`0xF00+0x100` 并不跨页"（那条编译期断言把它抓住了） | 10.2, 10.3, 10.7, 12.4.1, 14 |
| R31 | 新增 ADR-028（用户窗口分成**镜像区/动态区** + 内核拥有的**用户态落脚页**）；§10.3.1 登记 M4-3 第一段已经落地的四条校验规则与仍欠的那一半（`UserSlice`、跨页、可恢复故障）；§10.2 加 `4=peek` 与 `-EFAULT`（并写明"完整错误码表仍未冻结"）；§10.7 加两行分区规则、落脚页一行、生命周期表加"被杀要登记待回收 / `kills` 判精确值"两行；§14 的 M4 行登记 M4-3 第一段 | M4-3 第一次跑就撞上容器 `VaTaken` 而**账目完全平的**——那次读数的形状骗过我一次（以为回收坏了），真相是"固定地址的请求与随机地址的请求共用一条前沿"，成败由 `.ktests` 的链接顺序决定。同轮拆出四个缺陷（⑪–⑭，原文在 BACKLOG），其中两个是量具自己的问题：`read_at` 一个已回收的页会亲口把整机打到 39；`kills >= 1` 对"故障重演几十次"照样绿 | 10.2, 10.3, 10.7, 14, A.4 |
| R30 | 新增 ADR-027（任务结束与资源回账：释放**必须**延迟到"本 CPU 上跑的已经不是它"）；§10.7 加"生命周期与回账"表 + `SYS_EXIT` 进 §10.2 的调用号表；§12.4.1 把 `p5 cross-check` 升级成逐向量比对并记下"一条规则写在两处就要有两处各自的判据" | M4-2 第三段：`KT_TASK_EXIT` 三轮（旁观者结束 / 自己退出 / 第三次重装）全过，`reservations 16→16`、`live 0→0`；这一轮又拆出四个缺陷（⑦–⑩，原文在 BACKLOG） | 10.2, 10.7, 12.4.1, 14, A.4 |
| R29 | 新增 §10.7（用户程序的容器与加载，记的是**已在代码里的规则**）；§12.4.1 加 P7（系统调用往返）并写下 P5 被 `int 0x80` 污染的那次分流修正；§14 的 M4 行登记 M4-2 前两段；`docs/security/unsafe-whitelist.toml` 与 `docs/architecture/crates.toml` 各加一个新包 | M4-2 把真 ELF 装进用户半区跑起来了，而"分配器上限 2048 字节"这条约束改变了加载器的形状（逐页流式，不按段开缓冲） | 10.7, 12.4.1, 14 |
| R28 | §5.1 那条"必需项"从一句话变成启动判定（实测负样本 `fault-no-smap` → BOOT-INVALID 37）；§10.1/§10.2 登记 M4-1 的实际入口与五条判据；§12.4.1 写下 P4 的重复性地板与新阈值依据；§14 的 M4 行登记 M4-1 已交付；A.4 补 ADR-025/026 | M4-1 的 ring3 闭环绿了，而它拆出的五个缺陷里有三个的共同形状是"代码意图正确、硬件据以决策的是另一样东西"（生效位、架构偏移、登记的成对性） | 5.1, 10.1, 10.2, 12.3.1, 12.4.1, 14, A.4 |
| R27 | §12.4.1 写下 P3/P5/P1 的**边界移动**（记账从异常桩搬到 Rust 垫片）与新旧数字不可比；§7.1 新增一条数量级依据：一次 UC- 的 LAPIC 寄存器读在本机约 600 周期；§14 的 M3b 行闭合 | M3b-2b：运行队列与计时表都按 CPU 分行，AP 跑自己的队列；P1 读数变化的归因做了四轮排除法，前三轮被自己的数据否掉 | 7.1, 12.4.1, 14 |

### 0.1.1 V1.1 相对 V1.0 的修订摘要（历史，原表保留不改）

| 编号 | 修订 | 原因 | 章节 |
| --- | --- | --- | --- |
| R1 | 增加威胁模型、TCB 与 unsafe 预算 | V1.0 只要求“unsafe 需有理由”，无法审计 | 1.2–1.3 |
| R2 | 增加 IOMMU 与 DMA 隔离 | 设备 DMA 可绕过所有软件隔离 | 8 |
| R3 | 增加启动循环保护、驱动隔离（quarantine）、A/B 回滚 | 崩溃后无法自恢复是 CrowdStrike 事件的核心教训 | 9 |
| R4 | 增加 ACPI、USB、NVMe、virtio、电源管理、混合核心调度 | 真机必需，V1.0 缺失 | 13 |
| R5 | 用户态与 capability 权限模型提前 | 系统调用 ABI 会反向约束内核设计 | 10, 14 |
| R6 | 固化工具链决策（stable、内置目标、集成汇编器） | V1.0 汇编器未定、nightly 依赖不明 | 1.4, 3 |
| R7 | 增加 fuzz、Miri、Kani、loom、真机矩阵 | 仅 QEMU 不足以支撑企业级质量 | 12 |
| R8 | 增加许可证、供应链、生态与差异化定位 | 商业化阻塞项 | 15 |

### 0.2 证据约定

- **\[S#\]**：本次会话中实际检索到的来源，地址见附录 B.1。
- **\[R#\]**：通用权威参考，地址见附录 B.2。**本次会话未逐条核验页面内容**，采用前请自行打开确认。
- **\[V#\]**：**已逐字核对原文**的一手来源，地址与核对范围见附录 B.3。V1.2 的新增结论只允许引 \[V#\] 或标注“待核实”。
- **待核实**：本手册提出但**未取得一手依据**的条目，采用前必须自行验证；不得当作事实写进代码注释或对外文档。
- **决策**：本手册提出的建议，需评审后固化为 ADR，**不是**来源中的事实。

### 0.3 代码约定

代码是设计骨架，用于固化接口与不变量，**未经完整编译与测试**。第三方 crate（如 limine、x86\_64）的 API 随版本变化，必须固定版本并以该版本文档为准。

## 1 治理、威胁模型与决策

### 1.1 行业教训与本手册对策

| 来源事实 | 本手册对策 |
| --- | --- |
| Linux 维护者称每天面对约 13 个漏洞报告，归因于 C 的内存与错误处理缺陷 [S1](https://blog.desdelinux.net/en/Rust-Linux--Greg-Kroah-Hartman--end-of-security-experiment/)；Rust 已不再被视为实验特性 [S2](https://www.i-programmer.info/news/98-languages/18527-rust-for-linux-no-longer-experimental.html) | Rust 为主体语言（ADR-004） |
| 内存安全问题占比有两种说法：约三分之二 \[S2\]，以及约 15.9%（Rust 设计上可避免的类别）[S3](https://blog.desdelinux.net/en/linux-kernel-rust-official-android-16-drivers-drm-debate/)。口径不同，不可混用 | 文档中不承诺具体比例，只承诺 unsafe 可度量（1.3） |
| 实证研究认为 Rust 能降低但不能消除内核漏洞，处理不当还带来运行时与开发成本 [S4](https://atcosdi24.sched.com/event/1fLd7/an-empirical-study-of-rust-for-linux-the-success-dissatisfaction-and-compromise) | unsafe 预算、审计、性能基线（1.3, 12） |
| CrowdStrike 事件：内核态驱动发生越界读取 [S8](https://prog.world/lessons-learned-from-the-crowdstrike-global-outage)，据报道影响约 850 万台 PC [S10](https://mspoweruser.com/microsoft-mulls-restricing-third-party-access-to-windows-kernel-after-crowdstrike-outage)；微软复盘提出减少对内核驱动的依赖 [S9](https://www.darkreading.com/application-security/microsoft-lowballs-crowdstrike-outage-impact) | 禁止第三方内核态代码、启动循环保护、驱动隔离（9） |
| 微软曾因安全厂商与欧盟监管的反对而难以收紧内核访问 [S11](https://businessof.tech/2024/07/30/microsofts-security-strategy-lessons-from-crowdstrike-outage-and-potential-kernel-access-restrictions/)；也有观点认为仅移除内核访问只能解决一小部分问题 [S7](https://www.securityweek.com/microsoft-convenes-endpoint-security-firms-following-crowdstrike-incident/amp/) | 从第一天就把“第三方扩展只能在用户态”写入政策（1.4 ADR-010） |
| Asterinas 的 framekernel 用 Rust 在内核内部做特权分离，以缩小 TCB 并兼容 Linux ABI [S12](https://arxiv.org/abs/2506.03876)；其经验是安全的驱动开发依赖安全的底层资源抽象 [S13](https://www.usenix.org/node/309439) | 首期采用“内核内 unsafe 特权分离”（2.3, 2.4） |
| Rust 系统当前的主要工作量在驱动、文件系统与 ABI 兼容 [S16](https://news.lavx.hu/article/asterinas-0-18-lands-a-rust-written-memory-safe-linux-alternative-targets-containers)；Redox 的实践表明贡献者招募对此类项目至关重要 [S19](https://www.webpronews.com/redox-os-the-rust-written-operating-system-that-refuses-to-stay-niche/) | 生态与差异化策略（15） |

### 1.2 威胁模型

| 攻击者 | 能力 | 受保护资产 | 主要对策 |
| --- | --- | --- | --- |
| 恶意用户进程 | 任意系统调用与参数 | 内核内存、其他进程 | 参数校验、SMEP/SMAP、capability、地址空间隔离 |
| 缺陷或恶意驱动 | 内核态执行或内存破坏 | 全系统完整性 | 驱动白名单与签名、unsafe 预算、驱动隔离接口、后期用户态驱动 |
| 恶意设备 | 发起任意 DMA | 物理内存 | 强制 IOMMU，设备只能访问被映射的缓冲区 |
| 恶意存储介质 | 构造畸形文件系统 | 内核解析器 | 文件系统解析器用安全 Rust、fuzz、资源上限 |
| 远程网络攻击者 | 构造畸形报文 | 网络栈 | 安全 Rust 协议解析、fuzz、速率限制 |
| 供应链攻击者 | 篡改依赖或更新包 | 构建产物、更新通道 | 依赖锁定与审查、SBOM、可复现构建、签名更新 |

**不在范围内**（首期）：具备物理接触的攻击、侧信道的完整防护（仅做主流缓解，见 11）。

### 1.3 TCB 与 unsafe 预算

规则（强制，CI 检查）：

1. `unsafe` 只允许出现在**登记表** `docs/security/unsafe-whitelist.toml` 列出的 crate 中。本手册正文涉及的首批条目：`aurora-arch`、`aurora-hw`（MMIO、端口、DMA、§12.2 的 `exit_qemu` I/O 写）、`aurora-mm-core`（页表与帧分配）、`aurora-ctx`（上下文切换）、`aurora-sync`（§7.1 自旋锁，`unsafe impl Sync` 与 `DerefMut`）、`aurora-ffi`（§10.5 边界）。**该表是唯一来源**；§1.3、§2.5 与 §7.1/§10.5 不再各自抄一份名单。
2. 其余所有 crate 在 `lib.rs` 顶部声明 `#![forbid(unsafe_code)]`。
3. 每个 `unsafe` 块必须有 `// SAFETY:` 注释，说明依赖的不变量；启用 `clippy::undocumented_unsafe_blocks`。
4. CI 统计**登记表内** crate 的 unsafe 块数量与行数，**增长需要评审批准**。
5. 每个发布周期做一次 unsafe 专项审计，结果归档到 `docs/security/`。
6. **（V1.2 新增，R19）登记表与实际必须对账，两个方向都判失败**：登记表里有但实际统计 unsafe 为 0 ⇒ 报“白名单虚报”；实际有 unsafe 但不在登记表 ⇒ 报“越权 unsafe”。V1.1 的 §7.1 与 §10.5 是**在正文里临时补登记**的，这种做法会让“谁在白名单里”变成三份互不齐的清单。
7. **（V1.2 新增，R19）`[workspace.lints]` 不会自动作用于成员 crate**：每个 crate 的 `Cargo.toml` 必须显式写 `[lints] workspace = true`，否则 §2.5 定义的 `forbid/deny` 系列（含 `undocumented_unsafe_blocks`、`unwrap_used`、`expect_used`）对该 crate **完全不生效**，而 CI 依旧是绿的。M1 起 CI 增加一条断言：遍历 `members`，凡缺 `[lints] workspace = true` 即失败。
   豁免范围要显式写出：`build.rs`（§3.4 用了 `.expect`）、§12.2 的 `loop { spin_loop() }`、宿主测试代码——按 crate 或按 `#[allow]` + 理由注释登记，**不允许**用整文件关闭 lint 的方式绕过（与 §12.3“不允许关闭测试绕过门禁”同源）。

```rust
// 不在 unsafe 登记表内的 crate，lib.rs 头部
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks, missing_docs)]
```

### 1.4 初始架构决策记录（ADR）

| 编号 | 决策 | 状态 |
| --- | --- | --- |
| ADR-001 | 使用 Rust 内置目标 `x86_64-unknown-none` 与 stable 工具链，不使用自定义目标 JSON，不依赖 nightly | 建议 |
| ADR-002 | 汇编统一使用 LLVM 集成汇编器（`.S` 文件，经 clang 编译），不引入 NASM | 建议 |
| ADR-003 | Bootloader 使用 Limine（Limine 启动协议） | 建议 |
| ADR-004 | Rust 为内核主体语言；C 仅用于确无替代的底层与兼容部分，新增 C 需评审 | 建议 |
| ADR-005 | 内核使用 `panic = abort`；panic 进入统一故障流程 | 建议 |
| ADR-006 | 首期模块静态链接，不做动态内核模块（Rust 无稳定 ABI） | 建议 |
| ADR-007 | 权限模型采用 capability（句柄）而非仅 uid | 建议 |
| ADR-008 | 所有支持 DMA 的设备必须经 IOMMU，无 IOMMU 的平台降级并告警 | 建议 |
| ADR-009a | 可引入依赖的**许可证白名单**与 copyleft 处置规则（含 vendoring 边界、`cargo deny` 的许可证清单） | **建议，M0 必决**（V1.2 由 009 拆出） |
| ADR-009b | 项目**发布**许可证与贡献协议（CLA/DCO）、商标 | **待定，不阻塞编码，阻塞对外发布与招募** |
| ADR-010 | 不提供第三方内核态扩展机制；安全软件等通过用户态事件接口接入 | 建议 |

> **V1.2 对 ADR-009 的更正（R9）**：原表把“项目许可证与贡献协议”排在 M0，理由是“阻塞商业化”。但真正按时间顺序逼我们表态的动作发生得更早也更具体：ADR-003 已定 Limine（BSD-2）、§11.2 已定“关键依赖 **vendoring**（进源码树）”、§13 的 ACPI/AML 已写“复用现有库（需审查许可证）”、§15.3 已写“复用其他系统的驱动代码涉及 GPL”。**决定“项目用什么许可证发布”是发布时的事；决定“这些源码能不能放进我们的树”是 M1 之前的事。** 因此拆成 009a（M0 必决，工程门禁）与 009b（公开/招募前定，法律与治理）。`cargo deny` 的许可证检查属于 009a，必须在 M1 前接入 CI，否则 vendoring 已经发生、再改要重搬。

> 对 V1.0 的更正：V1.0 与我此前的口头建议中提到“内核开发通常需要 nightly”。内置 `x86_64-unknown-none` 目标在 stable 上可用 [V1](https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-none.html)（**V1.2 已逐字核对，见 B.3**），因此 ADR-001 选择 stable。代价是不使用不稳定特性（例如 `x86-interrupt` 调用约定），中断入口改用汇编桩（5.3）。

## 2 总体架构

### 2.1 分层与依赖方向

```text
┌──────────────────────────────────────────────────────────────────┐
│ L5 内核接口层   syscall · 对象/句柄接口 · ABI 版本               │
├──────────────────────────────────────────────────────────────────┤
│ L4 系统功能层   VFS · 文件系统 · 驱动框架 · 网络栈 · 安全 · 诊断 │
├──────────────────────────────────────────────────────────────────┤
│ L3 内核基础服务 PMM · VMM · 堆 · 调度 · 进程/线程 · 同步 · IPC   │
├──────────────────────────────────────────────────────────────────┤
│ L2 硬件抽象层   PCI · MMIO · DMA/IOMMU · 定时器 · 中断控制器     │
├──────────────────────────────────────────────────────────────────┤
│ L1 架构层       boot · CPU · GDT/IDT/TSS · APIC · 页表 · 上下文  │
└──────────────────────────────────────────────────────────────────┘
   依赖方向：只允许上层依赖下层；横向依赖必须经 trait 接口
```

### 2.2 依赖规则与自动化强制

- 低层不得依赖高层；同层模块之间只依赖对方的 `*-api` crate（只含 trait、类型、错误码）。
- 每个模块拆成 `xxx-api`（接口）与 `xxx`（实现），上层只引用 api crate，这样替换实现不影响调用者。
- 强制手段：CI 用 `cargo metadata` 生成依赖图，与 `docs/architecture/deps.toml` 中的允许清单比对，不在清单内的边直接失败；用 `cargo deny` 检查外部依赖的许可证与来源。

### 2.2.1 三层隔离的实现阶段

| 隔离层 | 含义 | 首期手段 | 后期手段 |
| --- | --- | --- | --- |
| 编译隔离 | 模块独立编译与测试 | crate 工作区、api/impl 拆分 | 同左 |
| 接口隔离 | 禁止访问对方内部状态 | `pub(crate)` 默认、`forbid(unsafe_code)`、依赖图检查 | 同左 |
| 运行隔离 | 一个模块出错不拖垮其他模块 | unsafe 特权分离、IOMMU、驱动健康监测、设备重置 | 用户态驱动、服务进程重启 |

宏内核模块默认同特权级、同地址空间，**接口隔离不等于运行隔离**。首期通过缩小 unsafe 区域与 IOMMU 获得部分运行隔离，真正的故障域隔离要等到用户态驱动阶段。

### 2.3 内核内特权分离（framekernel 思路）

把“可能破坏内存安全的操作”收敛到小的 TCB 中，其余代码全部是安全 Rust：

```text
┌───────────────────── 内核地址空间 ─────────────────────┐
│  安全 Rust 区（forbid unsafe）                          │
│   调度策略 · VFS · 文件系统 · 网络协议 · 驱动逻辑       │
│              │ 只能通过安全抽象调用                      │
│              ▼                                          │
│  TCB（允许 unsafe，体积受预算限制）                      │
│   页表 · 帧分配 · MMIO/端口 · DMA 映射 · 上下文切换     │
└─────────────────────────────────────────────────────────┘
```

这一思路来自 Asterinas 的 framekernel 与 OSTD 设计 \[S12\][S14](https://zhou-diyu.github.io/files/asterinas-atc25.pdf)，其公开材料称已支持 210 余个 Linux 系统调用并专门处理 MMIO/DMA 这类外部可修改内存。**注意**：我们借用的是架构思想，不依赖其代码，也不声称达到其形式化验证目标（相关计划见 [S21](https://hn.jakechampion.name/reader/https://lwn.net/SubscriberLink/1022920/ad60263cd13c8a13)）。

### 2.4 架构路线对比

| 方案 | 优点 | 缺点 | 本项目定位 |
| --- | --- | --- | --- |
| 加强的宏内核 | 性能好、开发快 | 驱动缺陷仍可摧毁内核 | 首期基础 |
| framekernel（内核内特权分离） | 单地址空间性能，缩小可信代码范围 | 依赖语言与抽象的正确性；较新，案例少 | **首期采用其思想** |
| 微内核（驱动在用户态） | 故障域天然隔离，Redox 采用 [S18](https://www.redox-os.org/home/) | IPC 开销与设计复杂度；真机驱动成熟度需要时间 [S17](https://doc.redox-os.org/book/our-goals.html) | 后期演进目标 |

**决策**：首期“宏内核 + 内核内特权分离”，并在驱动框架层预留“驱动运行于独立域”的接口，使后期迁移到用户态驱动不需要重写驱动逻辑（8.4）。

### 2.5 仓库与工作区

```text
aurora-os/
├── Cargo.toml                 # workspace
├── rust-toolchain.toml
├── .cargo/config.toml
├── justfile
├── boot/limine.conf
├── c/                         # 受限 C 代码（CMake）
├── kernel/
│   ├── linker.ld
│   ├── build.rs
│   └── src/main.rs            # 仅负责组装与初始化顺序
├── crates/
│   ├── aurora-arch/            # [unsafe 登记表] CPU/描述符表/中断入口
│   ├── aurora-hw/              # [unsafe 登记表] 端口 · MMIO · DMA · exit_qemu I/O 写
│   ├── aurora-ctx/             # [unsafe 登记表] 上下文切换（§7.2）
│   ├── aurora-sync/            # [unsafe 登记表] 锁与 lockdep（§7.1）
│   ├── aurora-ffi/             # [unsafe 登记表] C ABI 边界（§10.5）
│   ├── aurora-mm-api/  aurora-mm-core/  aurora-mm/
│   ├── aurora-alloc-api/  aurora-alloc/     # try_* 可失败分配封装（§6.5）
│   ├── aurora-resource-api/  aurora-resource/  # 资源登记表（§9.1）
│   ├── aurora-sched-api/  aurora-sched/
│   ├── aurora-driver-api/ aurora-driver/
│   ├── aurora-fs-api/  aurora-vfs/  aurora-fat32/
│   └── aurora-diag/            # 日志、panic、crash dump、故障注入（**不在登记表内**）
├── tests/  tools/  docs/{architecture,adr,security,testing}/
└── userland/
```

> **V1.2 更正（R10）**：V1.1 的这棵树缺 `aurora-ctx`（§1.3/§7.2）、`aurora-sync`（§7.1）、`aurora-resource-api`（§9.1）、`aurora-alloc`（§6.5）、`aurora-ffi`（§10.5）——五个都在正文被当作既有依赖引用。后果不是文档难看：M0 的验收项是“**一条命令完成构建、镜像、QEMU 启动**”，而 §2.2 的依赖图检查是拿 `cargo metadata` 与实际 crate 比对，缺注册会当场失败。
> 规则（写进 CI）：**本树是 crate 清单的唯一来源**。正文每引入一个新 crate 名，必须同时出现在这里与 `docs/architecture/deps.toml`；评审清单 A.3 增加一条“新增 crate 已登记”。
> 命名规则同步明确：`xxx-api` 只含 trait/类型/错误码且必须 `#![forbid(unsafe_code)]`；`xxx-core` 是允许 unsafe 的实现主体；无后缀的 `xxx` 是对外的组装与默认实现。一个 crate 只能属于其一。
>
> **`aurora-diag` 有意不进登记表**：日志/panic/crash dump 看起来“底层”，但它的每条硬件出口（端口 I/O、`exit_qemu`、halt）都已经由 `aurora-hw`/`aurora-arch` 提供，所以 diag 应能保持无 unsafe。这样 diag 才可以在 §12.1 的 L2 里进 `HOST_TESTABLE` 名单（§3.5）——**故障诊断代码本身可被宿主机单元测试覆盖，是它必须保持安全的主要理由**。若实现中确实需要 `unsafe`（例如直接写 MMIO），走 §1.3 第 1 条改登记表，**不要**在这里加注释了事。
>
> `kernel/` 目录的包名为 `aurora-kernel`（§3.5 的 `-p aurora-kernel` 依赖这个名字），它是唯一的二进制 crate，不参与 `HOST_TESTABLE`。

```toml
# Cargo.toml（根）
[workspace]
resolver = "2"
members = ["kernel", "crates/*"]

[workspace.lints.rust]
unsafe_op_in_unsafe_fn = "deny"
missing_docs = "warn"

[workspace.lints.clippy]
undocumented_unsafe_blocks = "deny"
unwrap_used = "deny"
expect_used = "deny"
panic = "warn"

# V1.2（R19）：以上 [workspace.lints] 对成员 crate **不自动生效**。
# 每个 crates/*/Cargo.toml 必须写：
#     [lints]
#     workspace = true
# CI 断言“每个 member 都写了这一行”，否则 §12.3 的 lint 门禁是空转的。

[profile.release]
panic = "abort"
lto = "thin"
codegen-units = 1
debug = "line-tables-only"

[profile.dev]
panic = "abort"
```

## 3 工具链与构建

### 3.1 版本固定

```toml
# rust-toolchain.toml —— channel 必须写成具体版本号，升级需走评审
[toolchain]
channel = "<固定的 stable 版本号>"
components = ["rust-src", "clippy", "rustfmt", "llvm-tools"]
targets = ["x86_64-unknown-none"]
```

Clang/LLVM、LLD、QEMU、OVMF 的版本同样写入 `tools/versions.toml`，CI 与本地使用同一容器镜像，保证可复现构建。

### 3.2 Cargo 配置

```toml
# .cargo/config.toml
# V1.2（R15）：**故意不在这里写 [build] target**。
# 一旦设了 [build] target = "x86_64-unknown-none"，`cargo test` 也会用该 target 编译测试
# 二进制，然后试图在宿主上执行它 —— 直接失败。V1.1 的 §3.5 `test: cargo test --workspace --lib`
# 与本节配置互斥，第一次本地跑 `just test` 就会撞上（请在 M1 验证本条）。
# 目标只在构建/运行命令上显式传 `--target`（见 §3.5）。

[target.x86_64-unknown-none]
rustflags = [
  "-C", "link-arg=-Tkernel/linker.ld",
  "-C", "force-frame-pointers=yes",   # 便于栈回溯
]

[env]
AURORA_TARGET_BARE = "x86_64-unknown-none"
```

内置目标的默认设置以 [V1](https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-none.html) 平台支持页为准，**V1.2 已逐字核对**该页，结论如下（这三条直接支持 ADR-001 与 §5.4）：

| 项 | 核到的默认值（原文口径） |
| --- | --- |
| 向量/浮点 | 该目标生成的 Rust 代码**默认不使用任何向量或浮点寄存器（SSE、AVX）**；可用 `-C target-feature=` 或 `#[target_feature]` 打开 |
| 代码模型 | 默认 **`kernel`** code model |
| 红区 | `extern "C"` 为 System V **without red zones** |
| 层级 | **Tier 2**，ELF 自由站立（固件、内核等），stable 可用（自 1.62） |

**注意 §5.4 的成立条件**：正因为默认不发 SSE/x87，§5.3 的入口桩不保存浮点状态才是安全的。但这条保证是**可以被单个 `#[target_feature(enable = "sse")]` 或 C 侧编译选项悄悄拆掉的**，而拆掉的后果是内核踩坏用户线程浮点寄存器——不崩、只在浮点结果里出现，是最难查的一类缺陷。因此 §12.1 L1 增加两条客观门禁（数字必须为 0，不做“看起来没问题”的判断）：

- 对内核镜像反汇编，统计出现 `xmm|ymm|fld|fst|fist|paddd` 的指令条数；
- `nm` 断言未引用 `memcmp/memcpy/memset/strlen` 之外的 compiler-rt 符号（浮点/向量代码常以库符号形式漏进来）。

C 侧（§3.4）已显式带 `-mno-sse -mno-mmx -mno-red-zone -mcmodel=kernel`，与本目标一致；`entry.S` 同样受上面两条门禁覆盖。

### 3.3 链接脚本（higher-half，段权限满足 W^X）

```text
/* kernel/linker.ld */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain)

PHDRS {
  text   PT_LOAD FLAGS(5);   /* R+X */
  rodata PT_LOAD FLAGS(4);   /* R   */
  data   PT_LOAD FLAGS(6);   /* R+W */
}

SECTIONS {
  . = 0xffffffff80000000;

  .text : { *(.text .text.*) } :text
  . = ALIGN(4K);
  .rodata : { *(.rodata .rodata.*) } :rodata
  . = ALIGN(4K);
  .requests : {
    KEEP(*(.requests_start_marker))
    KEEP(*(.requests))
    KEEP(*(.requests_end_marker))
  } :rodata
  . = ALIGN(4K);
  .data : { *(.data .data.*) } :data
  .bss  : { *(.bss .bss.*) *(COMMON) } :data

  /DISCARD/ : { *(.eh_frame*) *(.note .note.*) }
}
```

链接脚本与 Limine 协议的段要求以 Limine 官方文档与模板为准 [R3](https://github.com/limine-bootloader/limine)。

### 3.4 C 代码与 Rust 的集成（ADR-004 的执行方式）

C 代码由 CMake 编译成静态库，Cargo 在 `build.rs` 中链接：

```cmake
# c/CMakeLists.txt
add_library(aurora_c STATIC src/early.c src/asm/entry.S)
target_compile_options(aurora_c PRIVATE
  --target=x86_64-unknown-none-elf -ffreestanding -fno-stack-protector
  -mno-red-zone -mno-sse -mno-mmx -mcmodel=kernel -fno-pic
  -Wall -Wextra -Werror)
```

```rust
// kernel/build.rs
fn main() {
    let dir = std::env::var("AURORA_C_LIB_DIR").expect("set by justfile");
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=static=aurora_c");
    println!("cargo:rerun-if-changed=../c");
}
```

新增 C 文件须在评审单中说明“为何不能用 Rust”，C 代码量作为指标长期追踪，目标是只减不增。

### 3.5 统一命令入口

```text
# justfile（节选）—— V1.2 按 R15 改：target 只在需要时显式传
T       := "x86_64-unknown-none"

build:    cmake --build build/c && cargo build --release --target {{T}} -p aurora-kernel
image:    build && tools/image/make_image.sh
run:      image && qemu-system-x86_64 -M q35 -m 512M -smp 4 \
            -bios $OVMF -drive format=raw,file=aurora.img \
            -serial stdio -display none -no-reboot -no-shutdown \
            -device isa-debug-exit,iobase=0xf4,iosize=0x04

# 宿主可测 crate 的名单是唯一来源，CI 与本地都从这里取；
# 内核 crate（依赖 aurora-arch/aurora-hw/aurora-ctx 的）不进这张表，它们走 L3/L4。
HOST_TESTABLE := "aurora-mm-api aurora-sched-api aurora-driver-api aurora-resource-api aurora-fat32 aurora-vfs aurora-sched aurora-diag"
test:  cargo test -p {{HOST_TESTABLE}}          # 宿主目标，不带 --target
test-qemu: build && tools/qemu_tests.sh          # L3/L4：镜像内 .ktests 段，退出码判定（12.2）

lint:  cargo fmt --check && cargo clippy --workspace --target {{T}} --all-targets -- -D warnings
check-lints-wired: tools/ci/assert_lints_workspace.sh   # R19：每个 member 都写了 [lints] workspace = true
check-unsafe:     tools/ci/assert_unsafe_whitelist.sh    # R19：登记表 ⇄ 实际统计 双向对账
check-nofloat:    tools/ci/assert_no_fp_in_image.sh      # R15：镜像内浮点/向量指令数必须为 0
```

OVMF 固件路径随发行版不同，由环境变量 `OVMF` 提供。

> **（R15）`cargo clippy --workspace --target x86_64-unknown-none` 与 `cargo test` 的 target 不同**，两者会各自建一套 `target/<triple>/`，这是预期行为；但 `--workspace` 在 clippy 下会试图为 bare-metal 目标检查所有 crate 的**测试代码**，`#[cfg(test)]` 里若引用宿主-only API 会失败。因此 clippy 用 `--all-targets` 时必须按 target 分别跑（宿主一次、bare-metal 一次），并允许在 bare-metal 那一趟跳过 test profile。这条在 M1 首次接 CI 时验证。

## 4 启动流程

### 4.1 启动链路

```text
UEFI 固件 ─▶ Limine（读 limine.conf、加载内核 ELF、建立 higher-half 与直接映射、传递启动信息）
      │
      ▼
  kmain（已处于长模式、已开分页、栈由 Limine 提供）
      │
      ▼
 Stage0  串口 → 日志 → 校验启动信息          （无堆、无锁、单核）
 Stage1  CPU 特性检测 → GDT/TSS/IDT          （无堆）
 Stage2  内存图解析 → PMM → VMM 接管页表 → 内核堆
 Stage3 ACPI **固定布局表**解析（RSDP/XSDT/MADT/FADT）→ APIC/定时器 → 调度器 → 启动其他 CPU
 Stage4 PCI 枚举（MCFG/ECAM）→ IOMMU（DMAR/IVRS）→ 驱动框架 → 存储 → VFS
 Stage5 用户态接口（syscall、第一个用户进程）
```

> **V1.2 更正（R11）**：V1.1 把“ACPI 解析”当成一个整体排在 Stage3，却在 §13/§14 把它落到 **M5**，同时在 §4.3 已经在内核入口就请求了 RSDP、§8.4 的 IOMMU 依赖 DMAR/IVRS、M3b 的 SMP 依赖 MADT。**M3b 不可能等到 M5 才拿到 MADT。** 故拆两级：
>
> | 级别 | 内容 | 依赖它的下游 | 排期 |
> | --- | --- | --- | --- |
> | **ACPI 固定布局表** | RSDP→XSDT 校验、MADT（ LAPIC id / IOAPIC / NMI 结构）、FADT（PM 寄存器块地址）、MCFG（ECAM）、DMAR/IVRS | M3b SMP、§8.7 设备枚举、ADR-008 IOMMU | **M2–M3b** |
> | **AML 解释器** | DSDT/SSDT 命名空间、`_CRS`/`_PRW`/`_PS0.._PS5`、热插拔、温控 | §13 电源/睡眠/休眠、§13 混合核心信息 | M5 之后（ADR-012b） |
>
> 首期只声明**固定布局表**是硬依赖；AML 未就绪时的行为必须是显式的：“无 `_PS0/_PSx` ⇒ 不提供睡眠，并在 `sys_abi_info()` 特性位中标记”，禁止静默当作“支持但失败”。

Bootloader 只负责加载与传参，不承担策略逻辑。Limine 的请求/响应机制与配置项以官方文档为准 [R3](https://github.com/limine-bootloader/limine)。

### 4.2 初始化阶段约束

| 阶段 | 可用能力 | 禁止 |
| --- | --- | --- |
| Stage0–1 | 静态缓冲区、串口 | 堆分配、锁等待、线程 |
| Stage2 | PMM（堆就绪前仅用静态元数据） | 依赖堆的类型 |
| Stage3–4 | 堆、锁、定时器 | 阻塞等待尚未存在的调度器 |
| Stage5 | 全部内核基础服务 | — |

每个阶段的失败都必须输出阶段名与错误码，并进入统一故障流程（9）。

### 4.3 Limine 请求与内核入口

```rust
// kernel/src/boot.rs —— 示意骨架：limine crate 的 API 以固定版本文档为准
use limine::request::{
    FramebufferRequest, HhdmRequest, MemoryMapRequest, RequestsEndMarker, RequestsStartMarker,
    RsdpRequest,
};
use limine::BaseRevision;

#[used]
#[link_section = ".requests"]
static BASE_REVISION: BaseRevision = BaseRevision::new();
#[used]
#[link_section = ".requests"]
static MEMMAP: MemoryMapRequest = MemoryMapRequest::new();
#[used]
#[link_section = ".requests"]
static HHDM: HhdmRequest = HhdmRequest::new();
#[used]
#[link_section = ".requests"]
static RSDP: RsdpRequest = RsdpRequest::new();
#[used]
#[link_section = ".requests"]
static FB: FramebufferRequest = FramebufferRequest::new();

#[used]
#[link_section = ".requests_start_marker"]
static START: RequestsStartMarker = RequestsStartMarker::new();
#[used]
#[link_section = ".requests_end_marker"]
static END: RequestsEndMarker = RequestsEndMarker::new();

#[no_mangle]
pub extern "C" fn kmain() -> ! {
    // 启动信息不被支持时无法继续：尽早失败并输出诊断
    if !BASE_REVISION.is_supported() {
        aurora_diag::early_fatal("boot: unsupported Limine base revision");
    }
    let Some(hhdm) = HHDM.get_response() else {
        aurora_diag::early_fatal("boot: missing HHDM response");
    };
    let Some(memmap) = MEMMAP.get_response() else {
        aurora_diag::early_fatal("boot: missing memory map");
    };
    let info = crate::init::BootInfo::from_limine(hhdm, memmap, RSDP.get_response(), FB.get_response());
    crate::init::run_all_stages(info)
}
```

### 4.4 初始化编排

```rust
// kernel/src/init.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage { Serial, Cpu, Memory, Interrupts, Sched, Devices, Userland }

pub struct InitError { pub stage: Stage, pub code: aurora_diag::ErrorCode }

type StageFn = fn(&BootInfo) -> Result<(), aurora_diag::ErrorCode>;

const STAGES: &[(Stage, StageFn)] = &[
    (Stage::Serial,     stage_serial),
    (Stage::Cpu,        stage_cpu),
    (Stage::Memory,     stage_memory),
    (Stage::Interrupts, stage_interrupts),
    (Stage::Sched,      stage_sched),
    (Stage::Devices,    stage_devices),
    (Stage::Userland,   stage_userland),
];

pub fn run_all_stages(info: BootInfo) -> ! {
    for (stage, f) in STAGES {
        aurora_diag::log_info!("init: stage {:?} begin", stage);
        if let Err(code) = f(&info) {
            // 统一进入故障流程，不允许带着未完成的阶段继续
            aurora_diag::fatal(InitError { stage: *stage, code });
        }
        aurora_diag::log_info!("init: stage {:?} ok", stage);
    }
    crate::sched::enter_idle_loop()
}
```

规则：阶段顺序在一处声明；模块不得自行“悬挂”初始化到其他位置。模块销毁顺序为初始化顺序的逆序。

### 4.5 早期串口日志（首个可观测能力）

```rust
// crates/aurora-hw/src/port.rs —— unsafe 登记表内 crate
pub struct Port8(u16);
impl Port8 {
    pub const fn new(p: u16) -> Self { Self(p) }
    pub fn write(&self, v: u8) {
        // SAFETY: 调用者通过平台表获得端口号；I/O 写不访问内存，不违反 Rust 内存模型。
        unsafe { core::arch::asm!("out dx, al", in("dx") self.0, in("al") v, options(nomem, nostack, preserves_flags)); }
    }
    pub fn read(&self) -> u8 {
        let v: u8;
        // SAFETY: 同上。
        unsafe { core::arch::asm!("in al, dx", in("dx") self.0, out("al") v, options(nomem, nostack, preserves_flags)); }
        v
    }
}
```

串口（16550）初始化与发送循环的寄存器细节参考 OSDev 指南 [R6](https://wiki.osdev.org/)。日志必须带级别、CPU 号、单调时间戳，并支持环形缓冲以便 crash dump 读取。

## 5 CPU 与中断

### 5.1 CPU 特性检测与最低要求

内核启动时检测并记录 CPU 特性，不满足“必需”项则拒绝启动，“可选”项决定使用哪一条实现路径。

| 类别 | 特性 | 缺失时 |
| --- | --- | --- |
| 必需 | long mode、NX、SYSCALL/SYSRET、APIC、原子指令 | 拒绝启动并输出原因 |
| 可选（M4-4 起） | SYSCALL/SYSRET（CPUID `0x8000_0001.EDX[11]`） | **不列为必需项**：缺失就不装 `LSTAR`，`sys_abi_info()` 的 bit0 报 false，程序退回 `int 0x80`。快路径的收益本机测不出来（§12.4.1 的 M4-4 对比），为它把一台机器挡在启动之外是不成比例的代价 |
| **必需（M4 起）** | **SMEP、SMAP** | 拒绝启动并输出原因。**V1.2 变更，理由见下（R17）**。<br>**M4-1 已兑现（R28）**：判定是两条而不是两条的一半——CPUID 说支持 **且** 写完 `CR4` 读回来那两位为 1，任一不成立就 `BOOT-INVALID(37)`；每台 CPU 进门各自设一次（CR4 是每 CPU 的）。尺子能分辨由负样本证明：`--features fault-no-smap` 清掉 SMAP 位，实测 `BOOT-INVALID(rc=37)` 符合 |
| 强烈建议 | XSAVE、PCID | 告警；XSAVE 缺失时用户线程浮点状态按 x87/SSE 逐项保存（待核实路径），PCID 缺失时 TLB shootdown 退化为全刷 |
| 可选 | x2APIC、INVPCID、RDRAND/RDSEED、1 GiB 大页 | 回退到通用路径 |

> **V1.2 更正（R17）**：V1.1 把 SMEP/SMAP 放在“强烈建议、缺失只告警”，但文档另外三处已经把它们当**不变量**使用：§6.4 “用户页在内核态不可执行（SMEP）、默认不可访问（SMAP），只有 `copy_*_user` 用 STAC/CLAC 短暂开放”、§10.3 的拷贝路径依赖 STAC/CLAC、§14 的 **M4 验收项“非法访问被拒绝”**。这三条在没有 SMAP 的机器上都只是“约定”，不是硬件强制。**允许 M4 在一台 SMAP 缺失的真机上通过验收，等于验收结论随硬件漂移**——而这正是 §12.4 想避免的那类不可复现判定。故提为必需。
>
> 若评审决定保留旧支持面（如面向 2012 年前的 x86-64），必须同时补三件事，缺一项就退回“必需”：① 无 SMAP 时的降级拷贝路径与其**独立测试**；② §14 的 M4 验收改为“在有 SMAP 与无 SMAP 两种配置下各自通过”；③ §11.1 表格里把 SMAP 行标注为“可降级，降级即取消商业支持声明”，与本表口径一致。
>
> 连带时序问题（一并处理）：M4 就把用户态攻击面打开了，而 §11.1 把“顶级推测执行缓解”排在 **M7**、IOMMU 排在 **M5**。本手册不新增章节，只把约束写清：**M4 之前至少要有 SYSCALL/SYSRET 入口的寄存器与栈不变量（§10.1）与 SMEP/SMAP**；推测执行缓解在 M4–M7 期间处于“已知未完成”状态，须进 A.1 风险登记册并对外标注，不能只在 §11.1 表里显示成一个未来的行。

```rust
// crates/aurora-arch/src/cpuid.rs
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuFeatures {
    pub nx: bool, pub smep: bool, pub smap: bool, pub pcid: bool,
    pub x2apic: bool, pub xsave: bool, pub rdrand: bool,
}

pub fn detect() -> CpuFeatures {
    // SAFETY: CPUID 在 x86-64 上总是可用，且无副作用。
    let l1 = unsafe { core::arch::x86_64::__cpuid(1) };
    let l7 = unsafe { core::arch::x86_64::__cpuid_count(7, 0) };
    let ext = unsafe { core::arch::x86_64::__cpuid(0x8000_0001) };
    CpuFeatures {
        nx:     ext.edx & (1 << 20) != 0,
        smep:   l7.ebx & (1 << 7)  != 0,
        smap:   l7.ebx & (1 << 20) != 0,
        pcid:   l1.ecx & (1 << 17) != 0,
        x2apic: l1.ecx & (1 << 21) != 0,
        xsave:  l1.ecx & (1 << 26) != 0,
        rdrand: l1.ecx & (1 << 30) != 0,
    }
}
```

位位置以 Intel SDM 与 AMD APM 的 CPUID 章节为准 [R1](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)，代码中的位号需在评审时逐项核对。通用内核代码只依赖 `CpuFeatures`，不得依赖具体 CPU 型号。

### 5.2 GDT、TSS 与 IST

| IST 项 | 用途 | 要求 |
| --- | --- | --- |
| IST1 | Double Fault | 独立栈 + guard page |
| IST2 | NMI | 独立栈 |
| IST3 | Machine Check | 独立栈 |
| RSP0 | 用户态进入内核 | 每线程独立内核栈 |

每个 CPU 拥有自己的 GDT、TSS 与异常栈（保存在 CPU-local 区域），栈之间用不可访问的页隔开，避免栈溢出惄悄改写相邻数据。可使用 rust-osdev 的 `x86_64` crate 提供的类型 [R7](https://github.com/rust-osdev/x86_64)，但需固定版本并审查其 unsafe。

```rust
// crates/aurora-arch/src/gdt.rs —— 示意骨架
pub const DOUBLE_FAULT_IST: u16 = 0;   // 对应 IST1（库内索引从 0 计，以所用版本为准）

pub struct CpuTables {
    tss: x86_64::structures::tss::TaskStateSegment,
    gdt: x86_64::structures::gdt::GlobalDescriptorTable,
    selectors: Selectors,
}

impl CpuTables {
    /// 为当前 CPU 创建表；三个异常栈由调用方在 Stage2 后分配并传入。
    pub fn new(df_stack_top: VirtAddr, nmi_stack_top: VirtAddr, mc_stack_top: VirtAddr) -> Self { /* ... */ }
    /// SAFETY: 必须在该 CPU 上只调用一次，且 `self` 在 CPU 生命周期内不被移动或释放。
    pub unsafe fn load(&'static self) { /* lgdt, ltr, reload segments */ }
}
```

### 5.3 中断入口（汇编桩）

由于 ADR-001 不使用 nightly 的 `x86-interrupt` 调用约定，所有向量走统一的汇编桩，再进入 Rust 分发函数。汇编量保持最小，只做保存现场、调用、恢复。

```rust
// crates/aurora-arch/src/trap.rs
#[repr(C)]
pub struct TrapFrame {
    pub cr2: u64,                     // V1.2 新增（R14）：最低地址字段，由桩最后 push
    pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
    pub r11: u64, pub r10: u64, pub r9: u64,  pub r8: u64,
    pub rbp: u64, pub rdi: u64, pub rsi: u64, pub rdx: u64,
    pub rcx: u64, pub rbx: u64, pub rax: u64,
    pub vector: u64, pub error_code: u64,
    pub rip: u64, pub cs: u64, pub rflags: u64, pub rsp: u64, pub ss: u64,
}

core::arch::global_asm!(r#"
.macro ISR_NOERR vec
.global isr_\\vec
isr_\\vec:
    push 0
    push \\vec
    jmp isr_common
.endm
.macro ISR_ERR vec
.global isr_\\vec
isr_\\vec:
    push \\vec
    jmp isr_common
.endm

isr_common:
    // 来自用户态（CS 低 2 位不为 0）时必须 swapgs，请见 10.1 的入口不变量
    test qword ptr [rsp + 24], 3
    jz 1f
    swapgs
1:
    push rax; push rbx; push rcx; push rdx; push rsi; push rdi; push rbp
    push r8;  push r9;  push r10; push r11
    push r12; push r13; push r14; push r15
    // V1.2 新增（R14）：CR2 必须在进入 Rust 处理函数之前取走。
    // 放在 GPR 入栈之后：此时 rax 已在栈上，可安全用作暂存；读 CR2 本身不访存、不会再次异常。
    // 若在 Rust 里才 mov rax, cr2，则处理路径上任何一次嵌套 #PF 都会把它覆盖掉。
    mov rax, cr2
    push rax
    mov rdi, rsp
    cld
    call interrupt_dispatch
    add rsp, 8                       // 丢弃 frame.cr2
    pop r15; pop r14; pop r13; pop r12
    pop r11; pop r10; pop r9;  pop r8
    pop rbp; pop rdi; pop rsi; pop rdx; pop rcx; pop rbx; pop rax
    add rsp, 16
    test qword ptr [rsp + 8], 3
    jz 2f
    swapgs
2:
    iretq

ISR_NOERR 0
ISR_NOERR 6
ISR_ERR   8
ISR_ERR   13
ISR_ERR   14
// ... 其余向量由构建脚本生成
"#);

#[no_mangle]
extern "C" fn interrupt_dispatch(frame: &mut TrapFrame) {
    crate::irq::enter();                    // 标记进入中断上下文
    match frame.vector {
        14 => crate::fault::page_fault(frame),
        8  => crate::fault::double_fault(frame),   // 走 IST，不可恢复
        v  => crate::irq::dispatch(v as u8, frame),
    }
    crate::irq::exit();
}
```

汇编语法采用 Intel 语法（Rust `global_asm!` 默认），`.S` 文件内使用 `.intel_syntax noprefix`，保持全项目一致（ADR-002）。**评审要点**：栈对齐、向量 8/10/11/12/13/14/17/21 的错误码表、来自用户态时的 `swapgs`、NMI 与机器检查的重入性都必须有独立测试。异常向量与错误码语义以 Intel SDM 第 3 卷为准 \[R1\]。

> **V1.2 撤回一条上一轮的外部意见（R14）**：有评审意见称本节 `test qword ptr [rsp + 24], 3` 对“带错误码的向量”读到的不是 CS（理由是 NOERR 宏多推了一层占位值会让两条路径的栈深度错开）。**该结论是错的，V1.1 的写法是对的**：`ISR_NOERR` 的 `push 0` 正是用来补齐 CPU 未推的错误码槽位，使两条路径在 `isr_common` 处的栈布局完全一致——`[rsp]`=vec、`[rsp+8]`=error\_code、`[rsp+16]`=rip、**`[rsp+24]`=cs**、`[rsp+32]`=rflags；出口经 15 次 pop + `add rsp,16` 后 `[rsp+8]` 仍是 cs**，且 `iretq` 看到的序列是 rip→cs→rflags→rsp→ss，正确。核对用的量具（按两种宏分别模拟 push/pop 序列并打印各偏移命中的字段）留档在 `.scratch/trapframe_offset_check.js`，两条路径输出一致。
>
> **同一轮核对真正暴露的两条缺口，已补进本节**：
>
> 1. `TrapFrame` 原本**没有 `cr2`**，而 §9.7 的 `CrashRecord` 有 `cr2`、§5.6 的 #PF 处理要靠它判“合法补页还是终止进程”。现已加入字段并在桩内取走（见上方注释）。**约定**：`fault::page_fault` 只读 `frame.cr2`，禁止在处理函数里再 `mov rax, cr2`。
> 2. §10.1 的 `syscall_entry` 在 `swapgs` 与“切到内核栈”之间存在一个窗口，此时 GS 是内核 GS 而 IF 未必为 0；若在这个窗口里来中断/NMI，进入的正是本节这段依赖 `gs:[PerCpu]` 的桩。业界对此的标准处置是给这类入口配 IST 影子栈做“ paranoid entry”。**本手册目前未规定这一路径**（评审项，需在 M4 用户态闭环前定；具体指令级依据待核实 Intel SDM 的 SYSRET/swapgs 相关章节，不在本版本断言）。

### 5.4 FPU/SIMD 状态

- 内核代码使用软浮点，不触碰 x87/SSE/AVX，因此中断入口不保存浮点状态。
- 用户线程在上下文切换时按 XSAVE（若支持）保存扩展状态，状态区大小从 CPUID 枚举获得，不硬编码。
- 如需在内核里使用 SIMD（例如加密），必须用 RAII 守卫显式保存和恢复。

### 5.5 中断上下文约束

| 规则 | 强制方式 |
| --- | --- |
| 不得阻塞、不得睡眠 | 阻塞原语内部 `debug_assert!(!irq::in_irq())`，测试环境下违反即 panic |
| 不得使用普通堆分配 | 中断上下文只能使用预留的原子池 |
| 不得持有可睡眠锁 | 锁类型区分 `IrqSpinLock` 与普通锁（见 7） |
| 复杂工作下半部 | 投递到延迟工作队列，由内核线程执行 |
| 中断风暴防护 | 每设备中断率统计，超限则屏蔽该设备中断并触发二级故障（9） |

### 5.6 异常处理策略

| 异常 | 来自用户态 | 来自内核态 |
| --- | --- | --- |
| #PF 页错误 | 合法则补页，否则终止进程 | 仅 `copy_*_user` 路径允许并恢复，其余为四级故障 |
| #GP、#UD、#DE | 终止进程 | 四级故障 |
| #DF | — | 四级故障（IST 栈上输出现场） |
| NMI | — | 记录后按来源处理（watchdog 或硬件错误） |
| #MC | — | 记录 MCA 信息，按严重程度分级 |

## 6 内存管理

### 6.1 地址空间布局（示例，非定案）

```text
0x0000_0000_0000_0000 ── 0x0000_7FFF_FFFF_FFFF   用户空间（47 位地址）
         … 非规范地址空洞 …
0xFFFF_8000_0000_0000 ── …                     直接映射（HHDM，偏移以 Limine 响应为准，不硬编码）
0xFFFF_A000_0000_0000 ── …                     内核堆
0xFFFF_B000_0000_0000 ── …                     MMIO 映射区
0xFFFF_C000_0000_0000 ── …                     CPU-local 区
0xFFFF_FFFF_8000_0000 ── …                     内核镜像（higher-half，W^X）
```

内核镜像 KASLR 的支持与开关以 Limine 配置文档为准 \[R3\]。非内核代码不得依赖上述具体数值，只通过 `aurora-mm-api` 获取区域。

### 6.2 分层

```text
Boot Memory Map ─▶ Boot Allocator（一次性、只增不减）
                          │ 移交
                          ▼
        PMM（伙伴/位图，按 order 分配） ── 统计、毒化、所有权标签
                          │
                          ▼
        VMM（页表、映射、权限、TLB 管理）
                          │
                          ▼
        内核堆（slab 大小类，建立在 VMM 之上）
```

### 6.3 接口与所有权

```rust
// crates/aurora-mm-api/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MmError {
    OutOfMemory, InvalidAddress, Misaligned, AlreadyMapped, NotMapped,
    PermissionDenied, DoubleFree, WxViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysAddr(u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(u64);

impl VirtAddr {
    /// 拒绝非规范地址：高 17 位必须与第 47 位相同。
    pub fn new(a: u64) -> Result<Self, MmError> {
        let top = a >> 47;
        if top == 0 || top == 0x1_FFFF { Ok(Self(a)) } else { Err(MmError::InvalidAddress) }
    }
    pub const fn as_u64(self) -> u64 { self.0 }
}

/// 模块标识，用于资源所有权追踪（9.1 资源模型）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleId(pub u16);

/// 拥有一段物理页的 RAII 句柄：丢弃即释放，类型系统保证不重复释放。
pub struct OwnedFrames { base: PhysAddr, order: u8, owner: ModuleId }

impl OwnedFrames {
    pub fn base(&self) -> PhysAddr { self.base }
    pub fn order(&self) -> u8 { self.order }
    pub fn owner(&self) -> ModuleId { self.owner }
}

impl Drop for OwnedFrames {
    fn drop(&mut self) {
        // 释放路径由实现 crate 注册；重复释放在分配器内部由状态位检测并记录 MmError::DoubleFree
        crate::registry::release(self.base, self.order, self.owner);
    }
}

pub trait FrameAllocator: Sync {
    fn alloc(&self, order: u8, owner: ModuleId) -> Result<OwnedFrames, MmError>;
    fn stats(&self) -> FrameStats;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode { WriteBack, Uncacheable, WriteCombining }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageFlags { writable: bool, executable: bool, user: bool, cache: CacheMode }

impl PageFlags {
    /// W^X 在构造时强制：同时可写与可执行直接失败。
    pub fn new(w: bool, x: bool, user: bool, cache: CacheMode) -> Result<Self, MmError> {
        if w && x { return Err(MmError::WxViolation); }
        Ok(Self { writable: w, executable: x, user, cache })
    }
}

pub trait AddressSpace {
    /// V1.2 变更（R13）：收下 `OwnedFrames` 的**所有权**，返回 `Mapping`。
    fn map(&mut self, va: VirtAddr, frames: OwnedFrames, flags: PageFlags) -> Result<Mapping, MmError>;
    /// 归还物理页所有权；调用方无法再持有失效的 `OwnedFrames`。
    fn unmap(&mut self, m: Mapping) -> Result<OwnedFrames, MmError>;
    fn query(&self, va: VirtAddr) -> Result<(PhysAddr, PageFlags), MmError>;
}

/// 一段生效中的映射。丢弃即解映射（并已在内部完成 §6.6 的 shootdown 等待）。
pub struct Mapping {
    va: VirtAddr,
    frames: OwnedFrames,     // 所有权在这里，不在调用方
    len_pages: usize,
}

impl Mapping {
    pub fn virt(&self) -> VirtAddr { self.va }
    pub fn frames(&self) -> &OwnedFrames { &self.frames }
}
```

> **V1.2 更正（R13）**：V1.1 的签名是 `map(&mut self, va, frames: &OwnedFrames, flags) -> Result<(), MmError>` 与 `unmap(va, pages) -> Result<(), MmError>`，而本节末尾宣称“物理页所有权由 RAII 表达”。**这两件事不能同时成立**：
>
> - `map` 按共享引用收下 `OwnedFrames` ⇒ 函数返回后调用方仍可让它离开作用域，于是**释放一页仍被映射着的物理页**；
> - `unmap` 返回 `()` ⇒ 所有权永远回不到调用方，只能靠“约定”再自己造一个 `OwnedFrames`，而 RAII 的“不重复释放”保证恰好建立在这个约定之外。
>
> 改为 `map` 取所有权、`Mapping` 持有、`unmap` 归还。附带三条必须一起定的规则，否则 `Mapping` 只是把问题挪了个位置：
>
> 1. **`Mapping` 不可 `Clone`**；需要共享时用 `Handle`（§10.4）而不是句柄值复制。
> 2. **`Drop for Mapping` 会做跨 crate 调用（解映射 + shootdown + 释放）**，而 §1.3 第 3 条要求每个 `unsafe` 有 SAFETY 注释：`Mapping` 落在 `aurora-mm-api` 里、该 crate 又必须 `#![forbid(unsafe_code)]`。因此 **`Mapping` 的实现体放 `aurora-mm-core`，api crate 只留类型声明与 trait**（`Drop` 不能出现在 forbid-unsafe 的 api crate 里，除非它只调用同样无 unsafe 的注册表函数）。这一条在评审时确认落点。
> 3. **解映射必须等待 §6.6 的 TLB shootdown 完成后**才能释放页；`Drop` 里做等待 ⇒ `Mapping` 的丢弃是**可阻塞**操作。因此规定：`Mapping` 不得在任何自旋锁临界区内丢弃，此约束写进 §7.1 的“持锁期间禁止”列表，并由 §12 的 lockdep 在调试构建下断言。

`FrameStats`、`registry` 等辅助类型按相同风格定义，略。设计核心是：**地址类型不可混用、页权限不可非法构造、物理页所有权由 RAII 表达**——第三条在 V1.2 起才在 API 形状上成立（R13）。

**重复释放的处置（V1.2 明确，R13）**：`impl Drop for OwnedFrames` 里检测到的 `MmError::DoubleFree` **无法向上传播**（`Drop` 没有返回值），所以“记录”这个词在 V1.1 里是没有落点的。现规定为：

- 调试构建：`DoubleFree` 立即按 **L4 完整性错误**处理（§9.2），进入统一故障流程，并在 panic 前打印 `owner`、`base`、`order` 与创建点（§6.5 的 `#[track_caller]` 标签）；
- 发布构建：同样升 L4，**不允许**退化为“计数 + 继续运行”——继续运行意味着同一物理页正在被两个所有者写；
- §6.7 表格中“重复释放检测”一行的“实现”列补一句判定归属：**检出即 L4，不由调用方决定**。

### 6.4 权限与保护不变量

- 任何页不同时可写与可执行（W^X）；内核镜像代码段只读可执行，只读数据段不可执行，其余不可执行。
- 用户页在内核态不可执行（SMEP）、默认不可访问（SMAP），只有 `copy_*_user` 路径用 STAC/CLAC 短暂开放（10.3）。
- 所有内核栈、异常栈、堆区头尾都有 guard page。
  **M3a 进度（R24）**：任务栈已兑现并验证——保留 5 页、最低一页永不映射，用例实测
  `guard_unmapped && guard_faults && first_mapped && !first_faults`（`KT_TASK_STACK_GUARD`）。
  **M3b-1 进度（R25）**：异常栈那一半也补上了——每个 CPU 的 #DF IST 栈由
  `trap::install_exception_stack(slot)` 向 VMM 要 2 页、只映射高那一页，低那一页永不映射；
  AP 的入口栈同样是 5 页保留 + 最低一页 guard。用例 `KT_EXSTACK_GUARD` 逐 CPU 验四条
  （guard 未映射、访问 guard 故障、首映射页存在、访问它不故障）并另验 IST1 落在段内且 16 字节对齐，
  实测 `exstack guard: checked=4 bad=0`（4 = BSP + 3 个 AP）。
  `t_ap_boot_abi` 还钉住"AP 的栈顶页映射着、guard 页在**最低那一格**"——
  第一版把它当成"栈顶下面那一页"，于是把映射着的第 3 页报成 guard 不成立，这条判据才把它抓住。
  **仍然没有** guard page 的只剩启动栈（`.bss` 里的静态数组，协议要求它在换页表之前就可执行，
  迁到 VMM 之上等于把交接状态改成我们自己造的东西）。这条缺口挂 BACKLOG，不许写成已兑现。
- 内核空间映射只由 VMM 创建，其他模块通过 `AddressSpace` 接口申请。
- **新 VA 只能经 `alloc_va_range` 一类“取得即登记”的接口获得**（V1.2 R21，M2-b）：
  找空闲页的扫描与使用者（堆窗口）若各查各的页表，会把同一段 VA 发给两个主人。
  本机实测过这个故障：堆写在窗口内 1.06 MiB 处 `#PF err=0x2`，那一页正是探针先“找未映射”找走的。
- **不得在 2 MiB 大页覆盖的 VA 内铺 4 KiB 叶子**。`map` 对此返回 `HugeConflict` 而不是部分生效
  （M2-b 实测：加这条之前 `map` 会**返回 Ok**、计入映射次数、且不消耗任何页表页——
  因为遍历把大页背后的**数据帧当成了下一级页表**，`set_leaf` 的冲突检查只看叶子位，看不见大页父项）。
  拆分大页（split）本里程碑**未实现**，见 BACKLOG 的 M5 条目。

### 6.5 内核堆与 OOM 策略

> **V1.2 更正（R21，由 M2-b 实现回灌）**：本节第二条原文要求“分配失败作为三级资源错误向上传播（§9）”，
> 但一旦 `#[global_allocator]` 接上，`alloc` 里所有 `Vec`/`Box` 的分配点**在类型上就没有可传播的出口**——
> 稳定版 `GlobalAlloc::alloc` 返回 `*mut u8`，null 之后唯一的去向是 `handle_alloc_error` → panic →
> `panic=abort`（ADR-005）→ L4。两条要求在同一个 API 上不能同时成立，故按 **ADR-018** 拆成分工：
> 全局分配器路径失败即 L4（实测：注入一次 `Vec::with_capacity(LARGE_MAX+1)`，退出码 39，
> panic 位置落在 `library/alloc/src/alloc.rs`）；**要 `Result` 的调用方必须显式用可失败分配接口**。
> “禁止隐式 OOM 崩溃”因此从“禁止停机”改写为“禁止**未核算预算的代码路径**依赖隐式分配”。

M2-b 实际落地的参数（都是本机实测值，不是设计余量）：

- 大小类 8 档：`[16, 32, 64, 128, 256, 512, 1024, 2048]`，`LARGE_MAX = 2048`。**超过上限一律返回 `None` 并计入 `OOM_COUNT`**，
  不做“看起来能用”的大对象路径——`GlobalAlloc` 的签名里无处安放 `mm::Mapping` 的物理页所有权，
  硬做要先建一张自身需要分配的全局表（循环依赖），代价大于收益。
- 堆窗口 4 MiB，起始处**一整页永不映射**当 guard（§6.4 第 3 条在此兑现）；预映射 16 chunk（64 KiB），
  之后按需以 4 KiB 为单位补足。
- **两条前沿必须分开**：分配光标 `bump` 与映射前沿 `map_next`。把它们合成一条会让分配器把
  从未映射的页交出去（本机现象：写在窗口内 1.06 MiB 处 `#PF err=0x2`）。判据只能是
  `map_next < 槽位末`，用例 `KT_HEAP_SLOTS_MAPPED` 逐页问页表来盯这条不变量。
- **VA 只能经 `mm::alloc_va_range` 取得**，取得即登记（§6.3）。堆窗口与“找未映射页”的扫描
  原本共用同一段地址空间，双方各自都认为它空闲——这就是上面那次故障的根因，不是堆一家的 bug。
- 不做碎片合并：自由链表只回收同类槽位，`peak/live` 比值即碎片读数（已记 BACKLOG）。
- 每次分配带 `ModuleId` 标签（§6.7 泄漏报告的前提）；`#[track_caller]` 创建点记录尚未做。
- 中断上下文只能使用预留原子池（见 5.5）——**该原子池 M2-b 未实现**，目前这条只是约定，
  列为 M3a 之前的门禁项。

### 6.5.1 新代码的分配规则（评审清单可逐条对照）

| 场景 | 允许 | 理由 |
| --- | --- | --- |
| 启动/测试等已核算预算的单线程路径 | `Vec`/`Box`（全局分配器） | 失败即 L4，且这条路径的峰值用量有用例兜着 |
| 驱动、服务、任何要往上传错误的路径 | `try_alloc` / `aurora-alloc::try_*`（M2-c） | 只有这条能表达 L3 |
| 中断上下文 | 禁止堆分配 | §5.5、§7.1“持锁期间禁止睡眠/分配” |
| `> 2048` 字节 | 本里程碑禁止（返回 None） | 见上；需要它就先解决 `Mapping` 所有权安放问题 |


### 6.6 多核 TLB 一致性

修改或撤销映射后需对所有可能缓存该映射的 CPU 做 TLB shootdown（IPI）。VMM 记录每个地址空间正在运行的 CPU 集合，仅向该集合发送。支持 PCID 时用 PCID 减少全刷。解映射过程必须等待 shootdown 完成后才释放物理页。

> **M3b-2a 落地状态（R26，见 ADR-023）**：后半句第一次变成代码——`mm::unmap_pages` 在归还帧
> 之前逐 CPU 点名发 IPI（向量 `0xF2`）、等每个在线 CPU 各回一次执，收不齐就升 L4；
> 处理方是不建异常帧、不拿锁的快路径（请求方正拿着 VMM 锁，处理方取任何锁都是跨 CPU 死锁）。
> 实测 `shootdown: online=4 requests=2 timeouts=0 acks=[0,3,3,3,…] invlpg=[0,3,3,3,…]`，
> 负样本 `fault-shootdown-noack`（照常 flush 但不回执）实测 **EXCEPTION(39)**。
> 三条**没有**做到，不许写成已完成：① **QEMU 观测不到"旧条目还在"这件事**（TCG 会因页表被写
> 自行失效），所以这条用例验的是协议不是硬件效应；② "VMM 记录每个地址空间正在运行的 CPU 集合"
> 今天只有全内核单一地址空间 + `cpu::is_online` 名单，per-地址空间的 cpumask 还没有；
> ③ PCID 在本机 `-cpu max` 下仍为 false（BACKLOG 从 M2-c 就记着），"用 PCID 减少全刷"
> 这条路径在本平台**测不到**，退化分支才是主路径。

### 6.7 内存诊断

| 能力 | 实现 | 阶段 |
| --- | --- | --- |
| 重复释放检测 | PMM 状态位 + RAII | M2（已实现，注入构建 `fault-double-free` 实测升 39） |
| 释放后毒化填充 | 调试构建下释放时填充固定字节 | M2（已实现，`0xa5`） |
| 泄漏报告 | 按模块标签汇总存活分配 | M2（`live_bytes/live_count` 已有；按模块汇总待 M2-c） |
| **VA 双重记账检测** | `alloc_va_range` 单一取址入口 + 保留登记表；越界映射报 `AlreadyMapped` 并升 L4 | M2（已实现，M2-b 的故障根因） |
| **堆前沿一致性** | 逐页问页表：分配光标走过的每页都必须已映射；guard 页必须未映射 | M2（已实现，`KT_HEAP_SLOTS_MAPPED`） |
| **全局分配器失败出口** | 注入 `> LARGE_MAX` 的分配，必须落到 39 | M2（已实现，`fault-heap-oom`） |
| **大页内铺叶子** | `map` 返回 `HugeConflict`，用例同时断言“不新增页表页 / 不计入 map_calls / 物理页随 Drop 归还” | M2（已实现，`KT_HUGE_CONFLICT`；**拆分大页仍未实现**，M5 扩表前必须补） |
| **按模块资源台账** | `Σ live == Σ alloc − Σ free`、测试模块必须清零、堆台账 == 堆自己报的映射页数（两台仪器对账） | M2（已实现，`KT_LEDGER`；负样本 `fault-resource-leak`） |
| **bootloader 信息区回收** | 默认不回收，改由 `reclaim_bootloader_regions()` 显式一次性回收并计数 | M2（已实现判定侧；回收动作本身待 M3b，代价实测 45 MiB，见 ADR-019） |
| 映射摊销记账 | `map_calls / mapped_pages / unmapped_pages / page_table_pages / early_pool` 计数进启动日志 | M2（已实现，作为 §12.4.1 P 基线的输入） |
| 堆越界 canary | slab 头尾 canary | M3 |
| 类 ASan 影子内存 | 评估后再决定 | 后期 |

## 7 并发与调度

### 7.1 锁规则与锁序

- 所有锁必须声明**锁等级（rank）**，获取锁时等级必须严格递增，调试构建用锁依赖检查器（lockdep 思路）在运行时断言。
- 进入中断可能再次获取的锁，必须使用 `IrqSpinLock`（获取时关中断）。
- 持锁期间禁止：睡眠、堆分配（除非该锁标记为可分配）、调用未知回调、**丢弃 `Mapping`（§6.3 R13 第 3 条：其 `Drop` 会等 TLB shootdown，属可阻塞）**。
- 锁等级表维护在 `docs/architecture/lock-order.md`，新增锁必须先更新该表。
- `aurora-sync` 登记在 `docs/security/unsafe-whitelist.toml`（V1.2 起不再有“就地补白名单”的写法，见 §1.3 第 1/6 条）。
- **M3b-1 落地状态（R25，见 ADR-020 / ADR-021 / 锁表）**：跨 CPU 的真实竞争**已经测到了**，
  上一段那句"今天测不到"作废。放 AP 之后有三条错是多核才暴露的，都改了：
  ① 预读说空闲而 CAS 失败被当成"状态被写坏"升 L4 —— 多核下这是正常竞争，现在重试点；
  ② 等级栈 `INNERMOST` 是一份全局值 —— 两个 CPU 交错取锁会互相伪造"外层等级"，
  报出根本不存在的嵌套，现在按 CPU 槽位各存一份，`IrqGuard` 记下自己属于哪个槽位；
  ③ 等锁上界是"自旋计数回绕" —— 那不是看门狗，现在按时间界判（`LOCK_WATCHDOG_CYCLES`）。
  实测（4 CPU 各 4,000 次临界区）：`unlocked_lost=10204/16000`（无锁对照组确实丢数，
  尺子能分辨）、`locked_lost=0`、`wait_events=5358`、`wait_max=232,076` 周期、
  `order_violations=0 reentrant_hits=0 wait_timeouts=0`。**"持锁期间禁止开中断"从约定升级为
  正确性前提**：`IrqGuard` 释放时还原的是获取时那个 CPU 的等级栈，靠的是"持锁期间本 CPU 不会被
  抢占"（`save_and_cli`），而不是靠没人去试。
  仍然没做的：`mm::State` 仍是一份全局值（VMM 锁已经盖住它，缺的是"锁外的快照读"那类调用点）；
  计时表已经 per-CPU（M3b-2b，见 ADR-024），但**热路径上"我是谁"只许查一次**这条
  是新规则：一次 UC- 的 LAPIC 寄存器读实测约 600 周期，所以 `trap`/`sched` 的记录接口都
  收 `cpu` 参数而不是自己查。`Mapping::drop` 依赖的 TLB shootdown 见 §6.6（M3b-2a 已实现）。
- **M3a 落地状态（R23，见 ADR-020）**：五条修改已在 `kernel/src/sync.rs` 实现
  （等级、`held_by` 重入检测、lockdep 移到 CAS 成功之后、`#[must_use]` 守卫、`Relaxed` 预读），
  等级表在 `docs/architecture/lock-order.md`（§7.1 要求表先于代码存在）。
  其中"`Relaxed` 预读"这一条已在 M3b-1 删除（见上一条 ①）。
  已上锁的有**堆(10)、VMM(20)、PMM(30)、台账(40)**与竞争用例的测试锁(60)。
  M3a 当时已上锁的只有**堆(10)**与**台账(40)**；`mm::State`、VA 保留表、P3/P5 计时表仍是单核无锁。
  其中 VA 保留表在 M2-c 之后随 `alloc_va_range` 上了 VMM 锁，`mm::State` 与 P3/P5 计时表
  **到今天仍是全局一份**（上一条已写明后果）。
  M3a 那句"跨 CPU 的真实竞争今天测不到"（当时 AP 还停在 bootloader 的停车点）在 M3b-1 作废——
  但它当时是**必要的**：正因为写了这句，放 AP 之后第一件事就是去补那四个等待计数器，
  而不是把 `violations=0` 当成锁验证过了。
- **（V1.2，R16）关中断自旋时长上限**：单次 `IrqSpinLock` 等待超过阈值即记为一次中断延迟事件，喂给 §9.6 的软锁死检测器。阈值的**具体数值有意不预设**（避免无依据的数字），但关系必须现在写明：若 §9.6 硬锁死检测器的 NMI 周期短于“最坏持锁时长”，正常负载就会误报 L4；两者必须出自同一张时序表，评审时一起定。

```rust
// crates/aurora-sync/src/irq_spin.rs —— unsafe 登记表内 crate
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockRank(pub u8);

pub struct IrqSpinLock<T> {
    locked: AtomicBool,
    held_by: AtomicU64,       // V1.2 新增（R16）：重入检测
    rank: LockRank,
    data: UnsafeCell<T>,
}

const UNHELD: u64 = u64::MAX;

// SAFETY: 访问 `data` 只能在持有 `locked` 时进行，因此 T: Send 即可跨 CPU 共享。
unsafe impl<T: Send> Sync for IrqSpinLock<T> {}

#[must_use = "丢弃守卫会立即释放锁，等于什么都没锁（V1.2 R16）"]
pub struct IrqGuard<'a, T: Send> { lock: &'a IrqSpinLock<T>, irq_was_enabled: bool }

impl<T: Send> IrqSpinLock<T> {
    pub const fn new(rank: LockRank, v: T) -> Self {
        Self { locked: AtomicBool::new(false), held_by: AtomicU64::new(UNHELD), rank, data: UnsafeCell::new(v) }
    }

    /// V1.2 变更（R16）三处，逐条对应可判定的后果：
    /// ① 重入检测放在**关中断之前**：同一持有者二次获取本锁时，V1.1 的写法是
    ///    “先关中断再自旋”，于是该 CPU 上不可能再有任何进展 —— 不可恢复死锁。
    ///    现在它变成一条必然触发的 fatal 断言（不再需要看现场才能知道是重入）。
    /// ② `lockdep::on_acquire` 移到 CAS **成功之后**：V1.1 在自旋前登记，竞争失败也计数
    ///    ⇒ 假阳性；而报假阳性的检查器最终会被人关掉，关掉就等于没有这个检查。
    /// ③ 快路径先 `Relaxed` 预读再 `swap`：V1.1 的循环每轮都做一次完整 `lock cmpxchg`，
    ///    竞争时反复夺锁缓存行；这一条要靠 §12.4 的锁竞争基线来确认改对了。
    pub fn lock(&self) -> IrqGuard<'_, T> {
        let me = aurora_ctx::current_holder_id();   // M3a 前返回 CPU 号，M3a 后返回线程号
        if self.held_by.load(Ordering::Relaxed) == me {
            aurora_diag::fatal_holder(self.rank, me);   // 调试与发布构建同样停机
        }
        while self.locked.load(Ordering::Relaxed) {
            core::hint::spin_loop();
        }
        let irq_was_enabled = aurora_arch::irq_save();
        while self.locked.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        self.held_by.store(me, Ordering::Relaxed);
        crate::lockdep::on_acquire(self.rank);           // 调试构建：等级必须严格递增
        IrqGuard { lock: self, irq_was_enabled }
    }
}

impl<T: Send> core::ops::Deref for IrqGuard<'_, T> {
    type Target = T;
    // SAFETY: 守卫存在期间独占锁。
    fn deref(&self) -> &T { unsafe { &*self.lock.data.get() } }
}
impl<T: Send> core::ops::DerefMut for IrqGuard<'_, T> {
    // SAFETY: 同上，且守卫不可克隆（未 derive Clone/Copy），不会出现别名的可变引用。
    fn deref_mut(&mut self) -> &mut T { unsafe { &mut *self.lock.data.get() } }
}

impl<T: Send> Drop for IrqGuard<'_, T> {
    fn drop(&mut self) {
        // 顺序不可颠倒（V1.2 R16）：必须在 Release 释放锁**之前**清 held_by。
        // 若放在之后，另一个 CPU 可能已抢到锁并写入它自己的 id，随后本 CPU 迟到的
        // store(UNHELD) 会把新主人的 id 抹掉 —— 这条锁的重入检测从此静默失效。
        self.lock.held_by.store(UNHELD, Ordering::Relaxed);
        self.lock.locked.store(false, Ordering::Release);
        crate::lockdep::on_release(self.lock.rank);
        aurora_arch::irq_restore(self.irq_was_enabled);
    }
}
```

> **（R16）本手册不主张“V1.1 的写法会跨 CPU 死锁”**：持锁期间中断是关着的，同 CPU 不会被时钟中断抢占，跨 CPU 的等待者最终能拿到锁，V1.1 在这一点上自洽。真正要改的是上面三条（重入不可恢复、lockdep 假阳性、每轮完整 `cmpxchg`），外加一条测试要求：§7.4 的 `loom` 用例必须包含**“同持有者二次获取”**这一条交错，否则 `held_by` 检测等于没测过。
>
> `current_holder_id()` 的可得性有阶段依赖：M3a 之前没有线程概念，只能退化为 CPU 号（此时“同 CPU 不同线程重入”抓不到，但那一场景在 M3a 之前也不存在）。这条退化必须在 §14 的 M3a 验收里写清：**M3a 完成时，重入检测的语义从 CPU 粒度切换到线程粒度，且两侧各有一条用例。**

内存序规则：同步原语用 Acquire/Release；`Relaxed` 只用于纯统计计数器**与锁内不跨对象共享的 bookkeeping 字段（如 `held_by`，其可见性由配套的 Release/Acquire 保证）**；每个原子操作需在注释中说明为什么该序足够。

### 7.2 调度策略与上下文切换分离

```rust
// crates/aurora-sched-api/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState { New, Ready, Running, Blocked, Zombie }

pub struct ThreadId(pub u64);

/// 策略只决定“下一个运行谁”，不碰寄存器、不碰页表。
pub trait SchedPolicy: Send {
    fn enqueue(&mut self, t: ThreadId, prio: u8);
    fn dequeue(&mut self, t: ThreadId);
    fn pick_next(&mut self) -> Option<ThreadId>;
    fn on_tick(&mut self, running: ThreadId) -> bool;   // 返回 true 表示需要抢占
}
```

```rust
// crates/aurora-ctx/src/switch.rs —— 上下文切换（unsafe 登记表内）
core::arch::global_asm!(r#"
.global switch_context
switch_context:            // rdi = &mut old_rsp, rsi = new_rsp
    push rbp; push rbx; push r12; push r13; push r14; push r15
    mov [rdi], rsp
    mov rsp, rsi
    pop r15; pop r14; pop r13; pop r12; pop rbx; pop rbp
    ret
"#);

extern "C" { fn switch_context(old_rsp: *mut u64, new_rsp: u64); }
```

设计要点：只保存被调用者保存寄存器（System V ABI）；切换地址空间（写 CR3）、切换用户 FPU 状态、更新 TSS RSP0 都在 Rust 侧完成，再调用汇编。新线程的栈预先摆好“寄存器初值 + 入口蹦板地址”，使 `ret` 跳进蹦板。

### 7.3 调度与 SMP 策略

- 首期：单核抢占式优先级调度先稳定；SMP 拆为独立里程碑（见 14），避免 V1.0 中 M3 一次交付多线程、调度和 SMP 的风险。
- SMP：每 CPU 独立运行队列，跨 CPU 迁移用 IPI，负载均衡由低频任务完成。
- 混合架构 CPU（性能核/能效核）的调度提示依赖平台提供的核心类型信息，列入 13 的真机阶段。

### 7.4 并发正确性验证

- `loom` 对锁和原子逻辑做穷举交错测试（在宿主机上运行纯逻辑部分）；内核集成测试用 QEMU 多核压力运行。
- 每个共享状态写明“由哪把锁保护”。

## 8 驱动与设备模型

### 8.1 设备模型

```text
 Bus（PCI/ACPI/虚拟） ──枚举──▶ Device（id、资源、状态）
                                    │ 匹配 id 表
                                    ▼
                               Driver（状态机）
                                    │ 只能通过
                                    ▼
                            DriverCtx（能力句柄集合）
                 MMIO · DMA · IRQ · 定时器 · 日志 · 内存预算
```

### 8.2 驱动生命周期

```text
Registered ─▶ Probing ─▶ Running ─▶ Stopping ─▶ Stopped ─▶ Unregistered
                 │            │                                  ▲
                 │            └──▶ Resetting ──▶ Running（恢复成功）
                 └──────────┴──────▶ Quarantined（超过重试预算，撤销全部资源）
```

```rust
// crates/aurora-driver-api/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverState {
    Registered, Probing, Running, Resetting, Stopping, Stopped, Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health { Ok, Degraded, Failed }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DriverError { NoDevice, Timeout, Io, ResourceExhausted, Unsupported, Internal }

pub trait Driver: Send {
    fn probe(&mut self, dev: &DeviceInfo, ctx: &mut dyn DriverCtx) -> Result<(), DriverError>;
    fn start(&mut self, ctx: &mut dyn DriverCtx) -> Result<(), DriverError>;
    fn stop(&mut self, ctx: &mut dyn DriverCtx);
    /// 将设备重置回已知状态；失败则上层将驱动隔离。
    fn reset(&mut self, ctx: &mut dyn DriverCtx) -> Result<(), DriverError>;
    fn health(&self) -> Health;
}

/// 驱动能触达内核的全部途径。不允许原始指针、不允许物理地址。
pub trait DriverCtx {
    fn map_mmio(&mut self, bar: u8) -> Result<MmioHandle, DriverError>;
    fn alloc_dma(&mut self, len: usize) -> Result<DmaHandle, DriverError>;
    fn request_irq(&mut self, line: IrqLine, h: IrqHandlerFn) -> Result<IrqHandle, DriverError>;
    fn set_timer(&mut self, ms: u32, cb: TimerFn) -> Result<TimerHandle, DriverError>;
    fn log(&self, level: LogLevel, msg: &str);
}
```

### 8.3 安全的 MMIO 与 DMA 抽象

Asterinas 团队总结的经验是，安全的驱动开发需要安全的底层资源抽象 [S13](https://www.usenix.org/node/309439)，并专门处理了 MMIO/DMA 这类可被外部修改的内存 [S14](https://zhou-diyu.github.io/files/asterinas-atc25.pdf)。下面是我们的对应设计：**DMA 缓冲区不暴露为 `&[u8]`/`&mut [u8]`**（设备随时可能写入，这会造成语言层面的未定义行为），只提供 volatile 访问器。

```rust
// crates/aurora-hw/src/mmio.rs —— unsafe 登记表内 crate
pub struct MmioRegion { base: *mut u8, len: usize }

impl MmioRegion {
    /// SAFETY: [base, base+len) 必须是已经由 VMM 以 Uncacheable 映射的设备窗口，
    /// 且在本对象生命周期内保持映射。
    pub(crate) unsafe fn new(base: *mut u8, len: usize) -> Self { Self { base, len } }

    pub fn read32(&self, off: usize) -> Result<u32, HwError> {
        self.check(off, 4)?;
        // SAFETY: check 保证对齐且在映射范围内。
        Ok(unsafe { core::ptr::read_volatile(self.base.add(off) as *const u32) })
    }
    pub fn write32(&self, off: usize, v: u32) -> Result<(), HwError> {
        self.check(off, 4)?;
        // SAFETY: 同上。
        unsafe { core::ptr::write_volatile(self.base.add(off) as *mut u32, v) };
        Ok(())
    }
    fn check(&self, off: usize, w: usize) -> Result<(), HwError> {
        if off % w != 0 || off.checked_add(w).map_or(true, |e| e > self.len) {
            return Err(HwError::OutOfBounds);
        }
        Ok(())
    }
}
```

```rust
// crates/aurora-hw/src/dma.rs
pub struct DmaBuffer {
    frames: OwnedFrames,      // 物理页所有权
    cpu_ptr: *mut u8,         // 内核侧映射
    bus: BusAddr,             // 设备看到的 IOVA（经 IOMMU）
    domain: IommuDomainId,
    len: usize,
}

impl DmaBuffer {
    pub fn bus_addr(&self) -> BusAddr { self.bus }
    pub fn len(&self) -> usize { self.len }

    pub fn read_u32(&self, off: usize) -> Result<u32, HwError> { /* check + read_volatile */ todo!() }
    pub fn write_u32(&self, off: usize, v: u32) -> Result<(), HwError> { /* check + write_volatile */ todo!() }
    pub fn copy_out(&self, off: usize, dst: &mut [u8]) -> Result<(), HwError> { /* volatile 逐字节拷贝 */ todo!() }
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        // 顺序不可颠倒：先撤销 IOMMU 映射并等待 IOTLB 刷新，再让 `frames` 被释放，
        // 否则设备可能继续写入已被重新分配给别人的页。
        iommu::unmap_and_flush(self.domain, self.bus, self.len);
    }
}
```

`todo!()` 标记的方法体略去。注意 `todo!()` 会 panic，正式代码中禁止保留。

**M5-a 已交付的最小版本（R36）**：`hw::MmioRegion::map(pa, len)` 就是本节那张表里
"边界检查 + volatile + 不暴露 `&mut [u8]`"的实现——未对齐回 `NotAligned`、越过长度回 `OutOfRange`，
页标志固定 `PageFlags::DEVICE`（PCD ⇒ PAT2 = UC-，不可执行、不给用户态）。
它的 RAII 与 `Mapping` 只有一处不同：**drop 不还页框、不动 `free_frames()` 与资源台账**
（设备区间从来不是 PMM 发出去的帧）。这条区别由 `KT_PCI` 用前后两次 `free_frames()` 读数钉住。

### 8.4 IOMMU 策略（ADR-008）

- 平台通过 ACPI 的 DMAR（Intel VT-d）或 IVRS（AMD-Vi）表提供 IOMMU 信息，表格式以 ACPI 与厂商 IOMMU 规范为准 [R2](https://uefi.org/acpi/specs)（本次未核验）。
- 每个设备（或隔离组）一个域，设备只能访问被显式映射的缓冲区。
- 无 IOMMU 的平台：启动时告警，只允许使用从低端内存分配的“弹跳缓冲区”，并在商业版支持声明中标明隔离能力降级。
- 驱动被隔离（Quarantined）时，立即撤销其 IOMMU 域与 MMIO 映射，阻止失控设备继续访问内存。

### 8.5 为用户态驱动预留的接口形态

`DriverCtx` 是驱动与内核之间唯一的接口，驱动不持有原始指针。首期由内核内实现直接支撑，后期同一组 trait 可由“系统调用代理”支撑，驱动代码无需改动即可迁移到用户态：

```text
          驱动逻辑（同一份代码）
                │ DriverCtx
      ┌────────┴────────┐
      ▼                 ▼
 内核内实现（首期）   系统调用代理（后期，用户态驱动）
 直接映射 MMIO/DMA    经 capability 授权的 MMIO/DMA/IRQ 句柄
```

这样的迁移路径与 Redox 的“驱动运行在用户态”思路一致 [S18](https://www.redox-os.org/home/)，但我们不在首期承担它的 IPC 与性能代价。

#### 8.5.1 M5-g② 落地状态（R49，实测 2026-11-06）

`DriverCtx` 今天第一次长出新方法：`request_irq` / `irq_message` / `irq_counts` / `release_irq`
（调用者是 AHCI 与 `KT_IRQ_AHCI`，仍然遵守"只写有调用者的方法"那条）。这一格里有三个选择不是风格：

1. **认领表在核内（`irq.rs`），消息也由核内算**。向量区间 `0x21..=0x2F`：`0x20` 是定时器
   （它的主人就是 `apic::on_interrupt` 自己），`0x30` 往上 IDT 没有桩。要写进设备 MSI 结构的
   三个 DWORD 不许有第二个实现——位数算错的失败形状是"安静地一个中断都不来"，所以判据只能是
   "写下去设备读回来同数 + 设备真发一发 + 内核数到那个向量"。本轮实测
   `写=(0xfee00000,0x00000000,0x00000021) 读回=(0xfee00000,0x00000000,0x00000021) ctrl=0x0081 逐字一致=true`。
2. **"接入中断"与"认领控制器"是两步**。依据是一条启动顺序事实：`ahci::init()` 由启动早期的
   状态区读回触发（`main.rs` 那一处），而本地 APIC 是后来才 `get_or_init` 的 ⇒ 在 `init` 里
   算不出消息目的地。合成一步的写法会静默退化，本轮就退化过一次，被打成
   `ahci: 认领的消息算不出来 Denied("本地 APIC 还没初始化") ⇒ 撤销认领，全程轮询`。
3. **中断只负责"叫醒"，不负责"放行"**。第一版把旗子当成落定，宿主机那台仪器当场报
   `内容对账: 槽0 对不上：宿主机解出 种类=1 seq=1 failed=0，内核报 种类=1 seq=1 failed=1`
   ——而内核 53 条用例全绿。D2H 到达时 DMA 数据可能还没搬完，读回来的就是缓冲里上一条命令的旧字节。
   放行条件因此必须是 `PxCI` 落下（或带错完成那条形状）**并且** `PxTFD` 的 BSY/DRQ 都清。
   三种成因三本账：`irq_hits`（旗子叫醒过我）/ `race_hits`（条件先成立、宽限窗内旗子也到了）/
   `poll_hits`（旗子从没来）。寄存器落定与消息落地实测差 16,260 周期（≈5 µs），
   合成一本就会拿赛跑的输赢当"中断配没配上"的结论，那是偶发红的形状。

代价与可比性：P2 的 MMIO **写** `min` 由 625 变 1,374（A/B 实测——把接入这一步跳过就回到 625；
读方向 530/535 不动）。那 ~750 周期是一次中断服务落在写的采样窗口里。P2 的判据是比值
（1 遍 vs 4 遍、DMA vs 一次读），本轮照常符合，但**它的绝对数从这一格起与之前不可比**。
串口量 145,224 → 149,681/149,683（+4.5 KB；其中我自己打的行 ≈2.9 KB，其余落在块层取证那一族）。

没做到的：M5-g③ 的 `-d int` 核外对账；`request_irq` 在 ISR 里被拒那一格只有守卫没有判据
（要一次 `fault-request-in-irq` 注入）；中断亲和性**半格已交付（R55，BACKLOG 73）**：目的地能动、归属由两台仪器各数一遍（判定表第 32 行），缺的是静默（不 mask 就移动）与核下线时的搬运；NCQ 多命令在飞时一面旗子不够；
virtio 的 MSI-X 表条目（`BIR=1` 偏移 `0x800`）；共享电平的 INTx 那条路。

### 8.6 驱动优先级

| 优先级 | 驱动 | 理由 |
| --- | --- | --- |
| P0 | 串口、Framebuffer（Limine 提供）、定时器 | 可观测性 |
| P1 | virtio-blk / virtio-net | 在 QEMU 中低成本验证驱动框架 |
| P2 | NVMe、xHCI + USB HID | 现代 PC 的存储与输入 |
| P3 | AHCI、常见有线网卡 | 兼容性 |
| 后期 | Wi-Fi、GPU、音频 | 工作量大，依赖生态策略（15） |

**P1 的 virtio-net 已经到"第一帧可判"这一步（M8-a①，ADR-032）**：TX 队列（编号 1）由
`KT_NET_TX` 八格判，而**帧的内容由宿主机的 pcap 判**（矩阵第 23 行）——内核自己那八格全在
"驱动知道"的范围内，"线上真有这些字节"必须由核外的仪器答。三条现场事实进了 BACKLOG 58：
不接受特性时头长 10 字节、配置区只有 8 字节存在（`mtu` 读回 `0xFF` 是"这一格不存在"）、
QEMU 给 transitional 网卡的 PCI device id 是 `0x1000`（与规范式子不符，所以"我是网卡"改由
"队列数 ≥ 2 且 RX/TX 门位不同"来判）。**RX 已通（M8-a②，R45）**：内核发一份 DHCP DISCOVER，收的是 **QEMU 用户网络自带的那台服务器**的回话
（590 字节），`yiaddr` 与宿主机自己的 `dhcpstart=10.0.2.15` 对账，回话由内核与宿主机**两条独立实现**
各解一遍。**协议上层、fuzz、审计仍未做**，§14 的 M8 验收句不成立。

### 8.7 设备枚举

PCIe 配置空间通过 ACPI MCFG 表的 ECAM 访问；MSI/MSI-X 优先于传统引脚中断；BAR 映射一律由 `DriverCtx::map_mmio` 经边界检查后提供。

#### 8.7.1 M5-a 落地状态（R36，实测 2026-11-05）

已经能跑的：`hw::MmioRegion`（§8.3 的边界检查访问器）+ `mm::map_mmio`（映射**已存在的物理区间**）
+ `pci::init`（ECAM 优先，缺 MCFG 退回 CAM）+ 枚举表。这台 QEMU/q35 的实测：

| 读数 | 值 |
| --- | --- |
| MCFG 给的 ECAM | `pa=0xe0000000`，声明跨度 1 MiB（一条总线），映射到内核 VA `0xffff80002041f000` |
| 枚举结果 | 6 台设备、33 个不存在的槽位（vendor=0xFFFF）、未截断 |
| 设备身份 | `00:00.0` 8086:29c0（Q35 宿主）、`00:01.0` 1234:1111、`00:02.0` 8086:10d3、`1f.0` 82801IB、`1f.2` ICH9 **AHCI(2922)**、`1f.3` SMBus |
| 两条硬件路径 | `KT_PCI` 同时用 ECAM（内存映射）与 CAM（`0xCF8/0xCFC`）读同一个配置 DWORD，实测两边都是 `0x03000002`，**一致** |
| MMIO 不占页框账 | 二次映射 LAPIC 那一页、读 ID 寄存器与 `apic::self_id()` 一致；drop 之后 `free_frames()` 117,223 → 117,223，VA 保留条数回到原值 |
| 边界与对齐 | 范围内 `read32(0x20)` 成功；`read32(4096)`、`write32(4096)` 拒为 `OutOfRange`；`read32(1)` 拒为 `NotAligned` |

**M5-a 当时明挂着的一条已经关掉（R36 → M5-a 收尾）**：配置偏移 `0x08` 里**哪个字节是 class**
曾经没有被证据钉住——"应当是 VGA 类 0x03"的那台设备读回 `0x0300_0002`，而 ECAM 与 CAM 两路一致，
所以**不是访问路径错，是解读没被证实**。当时的处理不是猜一个掩码往下盖，而是把字段改名叫 `cfg08`、
`first_of_class()` 先不写，并规定"要用类别之前先钉解码表"（BACKLOG ㉑）。
现在这张表由 `KT_PCI` 的六行判据钉住：同一台设备在 ECAM 与 CAM 两条路径上，
`class=bits31:24 / subclass=23:16 / progif=15:8 / revision=7:0` 必须**四台已知设备同时成立**
（少于 4 台就不算钉住），对不上就红。`first_of_class(0x01)` 因此才有依据，AHCI 认领走的就是它。

本节其余部分的落地状态：**BAR 尺寸探测已交付**（M5-b：`size_mem_bar` 写全 1 再还原，
补码按 BAR 自身宽度取；`KT_PCI` 判 ABAR 尺寸/边界/`MSE|BME`）；**`DriverCtx` 已交付**（M5-e，ADR-030：
能力句柄表 + P2 数字）；**virtio-blk 已经是第二个能跑 I/O 的驱动**（M5-f②：split queue + 第一条读写，
偏移/步长/回执长度都由设备现场给，见 ADR-030 的补记）；**MSI/MSI-X 仍待做**（现在只有轮询）。

## 9 故障隔离与可靠性

### 9.1 资源模型

每个内核资源（物理页、堆对象、IRQ、DMA 映射、设备、句柄等）登记到统一的资源表，模块故障时可按所有者一次性撤销。

```rust
// crates/aurora-resource-api/src/lib.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind { PhysFrames, HeapObject, IrqLine, DmaMapping, MmioMapping, Device, Handle }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceState { Live, Revoked, Released }

pub struct ResourceRecord {
    pub id: u64,
    pub kind: ResourceKind,
    pub owner: ModuleId,        // 当前所有者
    pub creator: ModuleId,      // 创建者
    pub created_tick: u64,
    pub state: ResourceState,
}

pub trait ResourceRegistry: Sync {
    fn register(&self, kind: ResourceKind, owner: ModuleId) -> Result<u64, ResError>;
    fn transfer(&self, id: u64, new_owner: ModuleId) -> Result<(), ResError>;
    /// 故障恢复：撤销某模块名下的全部存活资源（先撤销 IOMMU/MMIO，再释放内存）。
    fn revoke_all(&self, owner: ModuleId) -> RevokeReport;
}
```

### 9.2 四级故障与升级规则

```text
 L1 可恢复错误  ── 返回 Result，调用者处理
   │ 重复超限
   ▼
 L2 模块错误    ── 停止该模块→设备重置→重新初始化（有重试预算）
   │ 重置失败 / 预算用尽
   ▼
 L3 资源错误    ── 隔离模块（Quarantined）、撤销其全部资源、限制相关操作
   │ 完整性可能已被破坏
   ▼
 L4 完整性错误  ── 停止其他 CPU、保存现场、Crash Dump、重启或停机
```

```rust
// crates/aurora-diag/src/fault.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FaultLevel { Recoverable = 1, Module = 2, Resource = 3, Integrity = 4 }

pub struct FaultReport {
    pub level: FaultLevel,
    pub module: ModuleId,
    pub code: ErrorCode,
    pub cpu: u32,
}

pub fn handle(r: FaultReport, budget: &mut RetryBudget) -> Action {
    match r.level {
        FaultLevel::Recoverable => Action::ReturnError,
        FaultLevel::Module if budget.try_consume(r.module) => Action::ResetModule(r.module),
        FaultLevel::Module | FaultLevel::Resource => Action::Quarantine(r.module),
        FaultLevel::Integrity => Action::Panic,
    }
}
```

### 9.3 诚实的能力边界

- `panic = abort`（ADR-005）意味着 **panic 永远是系统级故障**，不能靠“捕获 panic”来局部恢复。可恢复的驱动错误必须通过 `Result`、超时检测与设备重置表达。
- **不支持**在内核态中途强杀某个驱动线程并继续运行：它可能持有锁或留下不一致的内部状态。L3 的隔离是“撤销它能触及的资源，让卡住的线程留在泄漏状态”，而不是继续执行它。
- 内存破坏类错误（例如 TCB 内的 unsafe 缺陷）属于 L4。这正是 CrowdStrike 事件中内核态驱动越界访问后内核必须停机的原因；微软侧也有观点认为这种情况下内核失败是预期且安全的行为 [S6](https://www.techtarget.com/it-infrastructure/news/366599066/Microsoft-SecOps-pros-weigh-kernel-access-post-CrowdStrike)。因此重点不是“避免停机”，而是“停机后能自动恢复到可用状态”（9.4、9.5）。

### 9.4 启动循环保护与安全模式

```text
 启动 ─▶ 读取“连续失败启动计数” n
          │
          ├─ n ≥ 阈值 ─▶ 安全模式：仅加载必要驱动、忽略第三方配置
          └─ 否则 ─▶ 正常启动
          │
          写入 n+1 ─▶ 运行……达到“健康”条件（Stage5 完成且稳定一段时间）
                                │
                                ▼
                          计数清零，标记当前槽位为 good
```

```rust
// kernel/src/boot_guard.rs
pub enum BootMode { Normal, Safe }

pub fn decide_boot_mode(store: &mut dyn BootStateStore, max_failures: u32) -> BootMode {
    let n = store.failed_boots().unwrap_or(max_failures);  // 读不到就按最坏情况处理
    let _ = store.set_failed_boots(n.saturating_add(1));    // 先计数，再进入可能崩溃的路径
    if n >= max_failures { BootMode::Safe } else { BootMode::Normal }
}

pub fn mark_boot_healthy(store: &mut dyn BootStateStore) {
    let _ = store.set_failed_boots(0);
    let _ = store.mark_current_slot_good();
}
```

计数与隔离名单的持久化位置：011-临时 已按 **ADR-031** 落地（盘上状态区，明文不验签），011-正式（验签）仍排在 M6 后半。安全模式下连续崩溃的驱动会被写入隔离名单，下次启动自动跳过——**这一句还没有落地**，见 §9.4.1。

#### 9.4.1 M6-a②/③ 落地状态（R38、R39，实测 2026-11-06）

上面那段伪代码现在是真的在跑，形状与差异都按实测登记：

| 项 | 落地情况 |
| --- | --- |
| 读计数 → 定模式 | `boot_guard::decide()`，在 `ahci::init()` 之后、`ktest::run_all()` 之前。**先计数再进可能崩溃的路径**：`decide()` 里读到的数立刻 +1 写回盘，驱动认领之后的整条路径都在这次写回之后 |
| "读不到就按最坏情况" | `state_store::read()` 只有 `Ok`/`Err` 两个出口，默认值在这里没有藏身处；`Err` 时传进阈值的同一个数，模式定为 `Safe`，串口打 `boot: 状态区读不到 …` |
| 模式对外可见 | 两处：串口一行 `boot: 模式=… 读到的连续失败=… 阈值=… 读不到=…`；`sys_abi_info()` 的 `F_SAFE_MODE` 位由 `user::abi_word()` **直接读这里的真实状态**，不是读"我打算开" |
| 安全模式的处置 | 只做了一件今天真的存在的事：`optional_devices_allowed()` 为假时 AHCI 枚举起到**第一块有盘的口为止**，其余口一个寄存器都不写。用例侧实测：正常模式 6 个口全起，安全模式起口数=1 |
| 跨重启真的 +1 | 同一份镜像**不重建**连跑四遍（`negative-probe` 变体）：读到的连续失败 = `[0, 1, 2, 3]`，模式 = `Normal/Normal/Normal/Safe`。这一行是矩阵的第 18 行，且它的"实际值"是**四遍的序列**而不是某一遍的退出码——序列不对报 `SEQ-BROKEN`，与"内核自己红了"分得开 |
| 健康清零 | `ktest::run_all()` 之后：`failed == 0 && !table_invalid` ⇒ `mark_healthy()` 写回 0（其余字段原样）。没有这条，一次成功启动之后计数还会一路涨到安全模式 |
| **安全模式出得来**（R39，矩阵第 19 行） | 宿主机把槽 0 直接改成 `seq=200 连续失败=99` ⇒ 下一遍必须 `模式=Safe 读到的连续失败=99` 且仍然 `PASS(33)` 且打出 `boot: 健康清零` ⇒ 再下一遍必须 `模式=Normal 读到的连续失败=0`。这个现场以前只能靠偶发撞，撞上还出不来（实测一次偶发把机器锁在 Safe 里连红 9 遍），现在是做出来的 ⇒ 判据确定 |

两条 R39 顺带钉住的实测（都属于"降级态出得来"这一类，写在这里而不是代码注释里）：
**健康判据不许拿理想态的基线去比降级现场**——`KT_BOOT_GUARD` 的还原格原来是
"还原后的起口数 == 正常模式那个数"，于是在安全模式里启动的那一遍**永远**不算健康、
计数永远清不掉，一次偶发就变成永久安全模式；现在比的是"进入时那个模式的应有数"。
**"读不到"的上游必须先证明自己不是被吞掉的命令**——本机 QEMU 偶发把一次 `PxCI` 写丢掉
（写 1 读回 0），而这条路径的下游正是 §9.4 的最坏情况；驱动现在在 `recover` 之后重发一次
（命令没进设备，重发一条写也是安全的），第二次仍被吞才把 `Err` 交出去。详见 ADR-029 的
"M6-a③ 补"。

没做到的四条，逐条都在 BACKLOG：①**隔离名单**（§9.4 后半句）没有——本内核还没有驱动加载器可以挂它，与 §8.2 的 registry 一起做；②"稳定一段时间"没有——现在的健康判据是"用例全绿且表不是空的"，没有时间窗；③`mark_current_slot_good()`（§9.5 的 A/B 槽位标记）没有——记录里留了 `kind` 字段，槽位状态字节还没写；④`seq` 只保证"在一次可读的生命周期内单调"，整区损坏后从 1 重来 ⇒ §9.7 的崩溃记录要用它排序，得先把 `seq` 做成全局单调。


> **V1.2 更正（R12）**：ADR-011 原本只问“计数存 UEFI 变量还是 ESP 文件”，截止排在 M2。但 §9.4 的保护**在 M1 第一次能启动时就要起作用**；而同一份存储还要装 §9.5 的 A/B 槽位状态、§9.7 的 crash dump 落盘、§13 的 UEFI 变量与运行时服务。这四件事的取舍不是“选个地址写整数”，而是**“我们能不能信任这块存储”**——而信任来自 §9.5 的验签（M6）与 §11.1 的安全启动/度量启动（M7）。因此：
>
> | 合并后的 ADR-011「可信持久存储」 | 内容 | 截止 |
> | --- | --- | --- |
> | 011-临时 | M1 起生效的**明文、不验签**存储及其能做的判定 | **M1 前**（否则 §9.4 无处落地） |
> | 011-正式 | 验签后的存储载体、密钥来源、掉电原子性、并发写 | M6 前 |
> | 011-信任根 | 与安全启动/度量启动（§11.1 M7）的关系：谁先谁后、能否独立成立 | M7 前 |
>
> **临时策略（011-临时）现在就要写死，因为它决定 M1 的验收**：验签就绪前，该存储**只用于可靠性判定（跳安全模式、槽位回退），不用于任何安全判定**；数据视为可被任意本地代码篡改。由此推出三条硬约束：① §9.4 的 `decide_boot_mode` 里“读不到就按最坏情况处理”是对的，但“读到就被信任”不行——安全模式**不得**因为名单里有一条记录就跳过必选驱动之外的任何签名校验步骤（该步骤此时尚不存在，故写“不得假定有”）；② §9.5 的 trial/good 标记在 011-正式 之前只是“尽力而为”，A/B 的验收不能依赖它来证明回滚有效；③ 任何把该存储当“防篡改证据”的用法都要在评审时被驳回。
>
> 写序还须定义**掉电原子性**：`set_failed_boots(n+1)` 发生在进入可能崩溃的路径**之前**（代码已如此），但一次写一半的存储必须能被判为“读不到”，而不是读出一个看似合法的中间值——这与 §10.2 的 size-first 结构同源，建议同样用“首字段 size + magic + 版本”并要求 CRC。

### 9.5 A/B 更新与回滚

```text
  槽位 A（当前 good）          槽位 B（正在更新）
        │                             │ 写入、验签
        │                             ▼
        │                      标记 B 为 trial（下次尝试启动）
        │                             │
        │          B 启动成功并达到健康条件 ─▶ B 升为 good
        │          B 连续失败 ─▶ 自动回到 A
```

更新包必须签名验证；内容/配置类更新与代码更新分开校验和分阶段发布，并支持灰度。这是 CrowdStrike 事件中“一个数据文件触发驱动崩溃”教训的直接对应 \[S8\]。

### 9.6 Watchdog

| 类型 | 机制 | 动作 |
| --- | --- | --- |
| 软锁死 | 每 CPU 定时器心跳未更新 | 记录并告警，超限升级 |
| 硬锁死 | NMI 检测关中断下的长时间无进展 | 输出现场，进入 L4 |
| 驱动超时 | 驱动自身的健康与请求超时 | 重置→隔离（L2→L3） |
| 硬件看门狗 | 平台提供时才启用 | 到期自动复位 |

#### 9.6.1 M6-c① 落地状态（R41，实测 2026-11-06）

**只交付了"软锁死"这一格，而且只到检测与可见为止。**四格里今天做不了的两格不写"已交付"：
硬锁死要平台真给 NMI、硬件看门狗要平台真有那个器件——这台 QEMU 都量不出来（表里那句
"平台提供时才启用"就是它自己的前提）。驱动超时那一格走的是 §8.2 与 §8.7 的存储路径，另计。

| 项 | 落地情况（实测） |
| --- | --- |
| 心跳是什么 | 这个核的**定时器 tick**。来源两台不一样，必须各读各的：BSP 走 `PIT(100 Hz) → I/O APIC → ISA IRQ`（`apic::ticks()`），AP 走本地 LAPIC 定时器、向量 `VEC_CPU_TIMER`（`apic::cpu_ticks(slot)`）。BSP 那一格的 `cpu_ticks` 永远是 0（它的定时器不从这个向量来），照读就变成"每个窗口 BSP 都卡死"——把 BSP 错接到 LAPIC 来源上，用例的"消警"那格当场红 |
| 什么算锁死 | 连续 `STALL_LIMIT = 3` 个 `WINDOW_MS = 50 ms` 窗口不前进（≈150 ms 无心跳，比 10 ms 的周期宽 15 倍，正常抖动不误报） |
| 轮询点 | `tsc::stage()` 的阶段边界，也就是开机路径上唯一"保证有界时间过去了一次"的位置。它的花费算进同一段 delta，不藏在没人数的地方 |
| 处置 | **没有**。`actions` 恒为 0 并有判据钉住（要 §8.2 那套隔离，而它按驱动组织、没有 CPU 这一维）。超限升级今天只是"多打一行" |
| 可见 | 报警一行 `watchdog: 心跳停 位图=0x1 连续窗口限=3 已采样=4 处置=0`（只在新出现的核上打，同一核连续 N 窗不刷 N 行）+ 收尾一条账本 `watchdog: 采样=… 报警窗口=… 核次=… 末位图=… 处置=…` |
| 判据 | `KT_WATCHDOG` 七格。两条必须点名的形状：①报警允许落在第 3 **或**第 4 个窗口——`timer_stop()` 之后还有一个在途 tick 会落进计数（同一份构建跑两遍实测读到 3 和 4 各一次），写成"恰好第 3"就是一条会自己飘红的判据；②用例进来时先量"心跳原本在不在前进"再决定要不要为它起表，收尾按进来时的状态放回——`.ktests` 顺序由链接器决定，而有用例（`t_copy_user`）会把表停掉，第一版没读这个事实，报警窗口整个错位、当场红 |

没做到的：CPU 维度的隔离/摘线（要先有 §8.2 的 registry）、硬锁死的 NMI 路径、硬件看门狗、
把报警送进 §9.7 那条崩溃摘要（今天的报警只到串口与账本）。

### 9.7 Crash Dump

```rust
// crates/aurora-diag/src/crash.rs
#[repr(C)]
pub struct CrashRecord {
    pub magic: u64,            // 用于下次启动识别有效记录
    pub version: u32,
    pub cpu: u32,
    pub fault_level: u8,
    pub vector: u8,
    pub error_code: u64,
    pub rip: u64, pub rsp: u64, pub cr2: u64, pub cr3: u64,
    pub thread_id: u64, pub process_id: u64,
    pub module_id: u16,
    pub backtrace_len: u16,
    pub backtrace: [u64; 32],
    pub log_tail_len: u32,     // 后接最近日志
}
```

记录先写入重启后保留的内存区域并同时从串口输出，下次启动在存储就绪后持久化；字段覆盖 V1.0 列出的所有项（错误类型、CPU、线程、进程、RIP、RSP、CR2、错误码、调用栈、模块、最近日志）。预留内存在各平台上是否真的跨重启保留需要实机验证，不可假设。

#### 9.7.1 M6-b② 落地状态（R40，实测 2026-11-06）

**这一段的结构，只落成了摘要**。已经能跑的与没落的必须分开写，否则"crash dump 持久化"这句话会替我说话：

| 项 | 状态 |
| --- | --- |
| 落点 | `crates` 版那张 `CrashRecord` **没有**实现。今天落的是 ADR-031 状态区里的一条 `kind=2` 记录，字段只有**向量号、CPU 槽位、RIP**（那 28 字节里本来就留着的三格）。调用栈 32 项、最近日志、错误码、线程/进程号、模块号**都在上面那张表里，都在"没做到的"里**：它们超出一个槽，要走 `VERSION=2` 的续块 + 把校验和覆盖范围一起扩大 |<br>**这一格已被 §9.7.2（M6-d）取代，且"要走续块"那句作废**：算过上界之后一个槽装得下全部字段（`64 + 8×32 = 320 ≤ 480`），续块这个设计被删掉而不是被实现。
| 写入时机 | 收口在 `exit::finish(ExceptionFatal)`——**不是**每个 L4 调用点。理由写在 ADR-031 的 M6-b② 补记：调用点会长，漏一处的表现是"盘上安静地没有记录"，而这条链上没有别的尺子会报 |
| 没有异常现场的 L4 | 落 `NO_VECTOR = 0` + `rip = 0`（`panic`、`mm::free_violation`、`heap` 的两处）。真异常那条路给真向量与真 RIP，所以"0"和"13"分得开 |
| 写不进去时 | **只降级**：`dump` 全程走 `Result`，失败就只留串口那一行并把"没写进去"本身打出来（实测注入非法命令码读到 `Io(BadCompletion { status: 0x41, error: 0x04 })`）。停机路径上不许二次故障 |
| 下次启动读回 | `crash::report_previous()` 在 `boot_guard::decide()` 之后打一行 `crash: 上一条 槽=… seq=… 向量=… cpu=… rip=…`。位置是故意的：手册要求"存储就绪后"，而串口现场已经在停机前打过了 |
| 判据 | `KT_CRASH` 七格（字段往返 / `seq` 轮转 / 取该种类最新 / 不踩别的种类 / 设备坏了只降级 / 之后还能读 / 现场还原）+ 判定矩阵第 20 行 `崩溃记录跨重启读回`：同一变体连跑两遍，第二遍读回的槽、`seq`、三样字段必须与第一遍落盘那行逐字段相同，且宿主机按同一套偏移重解那条记录也相同 |
| 预留内存那一半 | **没做**。QEMU 上量不出"这块内存真的跨重启保留"，所以 M6-b② 落的是"落盘 + 下次启动读回"，跨重启内存排在 M7 的硬件矩阵 |


#### 9.7.2 M6-d 落地状态：V2 记录（R42，实测 2026-11-06）

V1 那 28 字节只装得下三样，所以这一格做两件事：**载荷变长**、**现场由 CPU 给**。

| 项 | 实测状态 |
| --- | --- |
| 一条记录现在装什么 | `vector` `error_code` `cpu` `module_id` `fault_level` `thread_id` `process_id` `frame_count` + `rip` `rsp` `rbp` `cr2` + 最多 **32 个返回地址**（`64 + 8×帧数`，上界 320 字节 ≤ 一个槽的 480）。**没有跨槽续块**：那个设计在算完上界之后被删，因为多槽会把"撕裂只毁一个槽"复杂化而不换来任何容量 |
| 两个版本并存 | `header()` 同时认 V1/V2；`decode`（V1，28 字节）与 `decode_crash`（V2）各自再验形状。旧记录照读是判据（`KT_CRASH` 的 `种类隔离=true/true`）；不认识的 `version` 走 `StoreError::Version(_)` ⇒ 按"读不到"处理，不猜字段 |
| 扫描只看头部 | 一次扫描给出"整块区最大 `seq`"（定下一个槽）与"该种类的全部候选"。候选是**一个表而不是最大那一条**：头部过校验 != 正文解得开，只挑最新就会让一条自相矛盾的记录锁死整个种类 —— 那是 §9.4"坏记录不许把状态机卡住"的反面。实测的两条退回判据（`尾帧撕裂退回` / `帧数不自洽退回`）就是钉这条路径的 |
| 栈走的真实边界 | **真异常现场今天只走得出 1 帧**：`fault-crash-oops` 构建实测 `向量=14 错误码=0 cr2=0xffffc00000000008 帧数=1`。原因是产物没有帧指针，`rbp` 里不是链。同一套代码在合成的三层链上走出 4 帧（`KT_CRASH` 的 `走三层=true`）⇒ **机制成立，缺的是被走的那个现场**。开 `-C force-frame-pointers` 或上 CFI 是剩下的活，且它会挪 P1/P3 基线，所以不许悄悄改 |
| 现场是谁给的 | 第 21 行验的就是这件事：记录里的 `向量` 必须是 14、`CR2` 必须等于用例注入的那个地址，并且与**同一遍启动串口打的那条 `cpu] vec=… rip=… rsp=…`** 逐字段同数。没有这一行，V2 那 12 个字段测的只是搬运工 |
| 仍然没有 | `log_tail`（最近日志）：要一个停机路径可读的环形日志缓冲，另开一格；`process_id` 恒 0（进程模型还没长出来）、`module_id` 在异常路径上恒 0（现场不知道是哪个模块，只有驱动路径能给）——两个字段**留位但如实填 0**，比不填更能被读到的人发现 |
| 判据 | `KT_CRASH` 十三格（新增的四格：断链只一帧 / 合成链走出四层 / 尾帧撕裂也拒 / 帧数与长度不自洽也拒 / `size` 指到区外也拒）+ 矩阵第 20、21 行 + `esp_image.state_decode` 同步认 V2（两台仪器必须逐字段同判，包括"声明帧数与长度不自洽"这一条两边都拒） |

#### 9.7.3 M6-e/M6-f 落地状态（R48，实测 2026-11-06）

**调用栈这一半（M6-e）**——V2 的 `frames` 数组一直是空的吗？不是：机制对，被走的现场也对，
是我给返回地址设的门禁形状错了。第一版要求"8 字节对齐 + 内核半区 + 已映射"，而 x86-64 的指令是
变长的，`call` 的下一条指令可以落在任何字节边界上：真实现场第一层返回地址实测 `0xffffffff80010517`
（`& 7 == 7`），于是链在第一层就被判死，`帧数` 停在 1。M6-d 那一轮把这件事归因成"产物没有帧指针"，
并挂了一笔"开 `-C force-frame-pointers` 要重算 P1/P3 基线"的账——**那句归因现在作废**：
开关早在 `.cargo/config.toml` 里（文件时间 11-04 23:58，早于那一跑），而"能走出链"本身就是帧指针存在的证据；
本轮实测 P1 `min` 846/719 → 640/851、P3 `min` 314/330 → 318/310、串口量 130,915/130,916 → 130,911/130,916，
**没有基线要重算**（见 `docs/testing/p4-tolerance.md` 的 M6-e 行）。

换成什么：返回地址要**内核半区 + 生效权限说它可执行**（`mm::effective_flags` 的 NX 逐级相或）。
这不是放松——栈、堆、`.data` 全是 NX，拿数据冒充返回地址照样拒；这条判据变严之后第一个被抓出来的是
我自己的测试夹具（合成链那格原本把"返回地址"指在本函数的局部变量上，旧门禁照收）。
真实现场现在实测 **3 帧**：`t_crash_oops+0x3e` ← `ktest::run_all+0x126` ← `after_switch+0x1127`。

判据为什么写 `>= 2` 而不是实测的 3：出事函数与它的调用者是**结构**决定的（用例是被运行器调进去的），
第三层往上取决于内联——把 3 写死就是拿编译器今天的形状当判据。函数名这一维只能由核外判：
`.symtab` 不在运行时镜像里（Limine 只加载段），所以判定表第 21 行新加一台仪器——用内核 ELF 的符号表
把每条返回地址解成"函数 + 偏移"，并先验 `image-info.txt` 里的 `elf_sha256` 与当前产物同数
（帧地址配上另一个构建的符号表会解出**另一个函数**而照样"解得通"）。`st_size == 0` 的符号不收：
收了就等于"任何地址都落在某个函数里"，那台仪器会永远说对。

**最近日志这一半（M6-f）**——§9.7 表里"最近日志"那一格从今天起有真数了，形状是四件事：

1. **环形缓冲是旁路不是第二条通道**：`serial.rs` 里 `[AtomicU8; 4096]` + 一个不取模的逻辑计数，
   挂在 `putb` 的 `READY` 检查**之前**。放在前面是刻意的：真机上串口坏掉那一档恰恰最需要盘上这段话。
2. **`kind = 3` 的记录**：固定 16 字节（`crash_seq` / `lines` / `bytes`）+ 文本，文本上界
   `LOG_TEXT_MAX = MAX_PAYLOAD - LOG_FIXED = 464` 字节 ⇒ 实测本机平均行长约 4 **行**只装得下 3~4 条。
   要更多只有跨槽续块（那个设计在 56 那一节算过上界之后删过，不复活）或另开一块连续日志区。
3. **整行是硬规矩，而且在读侧也被验**：声明长度必须等于 `size - 16`、末字节必须是换行、
   声明行数必须等于文本里换行符的真实个数。后两条就是"存进去的必须是整行"在读侧的判据——
   写侧（`recent_tail`）已经保证过一次，这里不许只靠上层自觉。`KT_CRASH` 从十一格到**十五格**，
   其中"小缓冲装不下最新那一行 ⇒ 一行都不给"这一格是机制结论（本用例每行都超过 24 字节），不是实测巧合。
4. **配对靠 `crash_seq` 这个数字**，不靠"两条记录的 seq 相邻"这个巧合；`KT_CRASH` 的 ④⑤ 两格把它钉住，
   同时钉住"日志尾确实占了一个 `seq`"（一条崩溃落盘 = 两条记录 ⇒ 游标一次走两步，这是 M6-b①
   那条"整块区全局单调"的续集）。

判定表因此从 26 行到 **27 行**：第 27 行把盘上那段与**同一遍启动的串口原文**逐行对账，
并要求末行等于落盘行之前那最后一条 `[cpu]` 现场行。M6-f 当时**只敢**按行集合比而不是按连续子串比，因为
`serial::line` 没有整行原子性（不加锁，两个 CPU 同时打就互相插花）——那一格抓的是内容错、
取错时刻、环里是旧货，而"连续"这个更强的 claim 要等日志加了行锁才许写。
**L3-A（R54，ADR-035，BACKLOG 72）把锁加上了**：第 27 行从此两条都判（本轮 `逐行=4/4 连续=是`），
判定表另加第 **31** 行数行的形状；把锁撤掉的变异实测 `整行数=65/96`、10 行出现两种 tag、3 行张冠李戴，
所以那句"在 SMP 现场本来就可能是假的"在本机不是修辞。

**这一格的代价是量出来的**：多一条记录 ⇒ 状态区多扫一遍全区 8 槽 + 多写一槽，而块层每条命令打一行
现场取证，实测 stage6 串口量 130,880 → 141,118（**+10,238 字节**；归因办法是把 `write_log` 那一句
临时关掉再跑同一构建）。⇒ 写进设计里的一句话：**状态区的成本按记录条数走，不按字节数走**；
以后要"更大的日志"应该是另开一块连续区顺序写，而不是把文本塞进同一批槽。

仍未落地的（不许因为交付了机制就宣布 §9.7 整节完成）：~~日志的**整行原子性**~~ **已由 L3-A 交付（R54/ADR-035）**——
锁的排序确实带进了 L4 出口，处理是出口第一步 `unlock_for_halt()` 之后不再排队（只能降级、不能再故障）；
同 CPU 重入（中断里打印）仍不保证整行，它靠 §6.5 那条纪律而不是靠锁；A/B 槽位标记（§9.5，卡在装载侧身份）；
`module_id` / `process_id` 仍按约定填 0；真机上这份记录还没有读者（A.5 的"crash dump 解码工具"那一项仍开）。

### 9.8 故障注入点



```rust
// crates/aurora-diag/src/inject.rs
#[macro_export]
macro_rules! fault_point {
    ($name:literal, $err:expr) => {{
        #[cfg(feature = "fault-injection")]
        { if $crate::inject::should_fail($name) { return Err($err); } }
    }};
}

// 使用示例
fn alloc(&self, order: u8, owner: ModuleId) -> Result<OwnedFrames, MmError> {
    aurora_diag::fault_point!("pmm.alloc", MmError::OutOfMemory);
    /* 正常路径 */
    # todo!()
}
```

故障注入只在测试构建中启用，由测试脚本按名称、概率或第 N 次触发，覆盖 OOM、设备超时、DMA 错误、初始化失败等场景（12）。

## 10 内核接口：系统调用、capability 与 FFI

### 10.1 系统调用入口

> **M4-1 落地状态（R28）→ M4-4 已补齐（R34，见 ADR-025）**：下面写的 SYSCALL/SYSRET 现在**实现了**，
> 但 M4-1 当时**故意不做**——那是决策不是拖延。M4-1 的入口是 **`int 0x80`**（`VEC_SYSCALL = 0x80`，
> IDT 里唯一一条 DPL3 的中断门）：硬件按 `TSS.rsp0` 自动换到内核栈并自动关 IF，
> 异常帧完整落在那个任务自己的内核栈上，于是 §5.3 R14 第 2 条那个
> "`swapgs` 之后、切栈之前"的窗口在这条路径上**不存在**（本内核没有 per-CPU GS 基址，
> 身份来自 `cpu::self_slot()`，见 ADR-024）。
> **M4-4 的答案**：`syscall_entry` 的第一条指令就是 `swapgs`，之后 `gs:[...]` 指向本 CPU 的
> `FastArea`（用户任务内核栈顶、槽位、rip/nr/用户 rsp/帧基址）。窗口安全的论证不是"我们小心处理"，
> 而是一条可核对的事实：**本内核零处依赖 `gs:`**，所以 NMI 落在窗口里也拿不到"错误但被使用"的 GS；
> 哪天有代码在非快路径里读 `gs:`，这个论证就作废、必须回头补 paranoid entry（论证与装机参数全在 ADR-025）。
> 快路径是**可选特性**：CPUID 没有 SYSCALL/SYSRET 就不装 LSTAR，由 `sys_abi_info()` 的 bit0 报 false，
> 程序退回 `int 0x80`。入口不借任何被调用方保存寄存器，出口 `sysretq` 前按本 CPU 的窗口写 IF（ADR-021 第三个实现点）。
> `STAR` 的选择子算式要求 GDT 保持
> 0x08/0x10/0x1B/0x23 这个排布——**这一条现在由 `t_user_roundtrip` 的判据 0 钉住**。
>
> 一条 ABI 可见的差别必须写在这里，不能等 M4-2 再说：`int 0x80` **不破坏 `rcx`/`r11`**，
> 而 SYSCALL 把它们当作 RIP/RFLAGS 的隐式存放处。所以按本表下面那行"破坏寄存器"
> 写的程序在两条入口下行为不同；M4-1 的用户态测试代码因此不依赖 `rcx`/`r11` 的丢失。

使用 SYSCALL/SYSRET，通过 MSR（LSTAR、STAR、SFMASK）配置，入口汇编只做切栈和保存现场，其余进入 Rust：

```rust
core::arch::global_asm!(r#"
.global syscall_entry
syscall_entry:
    swapgs                          // 切到内核 GS（指向 PerCpu）
    mov gs:[{USER_RSP}], rsp        // 保存用户栈指针（不信任它的值）
    mov rsp, gs:[{KERNEL_RSP}]      // 切到当前线程的内核栈
    // 构建 SyscallFrame：rax(编号)、rdi/rsi/rdx/r10/r8/r9(参数)、rcx(用户 RIP)、r11(用户 RFLAGS)、用户 RSP
    // ... push ...
    mov rdi, rsp
    call syscall_dispatch
    // ... pop，返回前校验用户 RIP 为规范地址 ...
    mov rsp, gs:[{USER_RSP}]
    swapgs
    sysretq
"#, USER_RSP = const PERCPU_USER_RSP, KERNEL_RSP = const PERCPU_KERNEL_RSP);
```

**入口不变量**（评审必查）：

1. 进入内核后立即切换到内核栈，不使用用户提供的 RSP。
2. `SFMASK` 在入口处清除 IF 与 DF，保证切栈前不被中断。
3. 用 `SYSRET` 返回前必须检查返回地址（RCX）是否为规范地址，非规范则改走 `IRET` 路径，避免在特权级 0 上触发异常后使用用户栈（已知的 SYSRET 类问题，细节以 Intel SDM 与 AMD APM 为准 \[R1\]）。
4. 中断与异常入口在来自用户态时必须 `swapgs`（见 5.3）。

### 10.2 ABI 约定

| 项 | 约定 |
| --- | --- |
| 调用号 | `rax`：<br>`1=ping`、`2=add`、`3=exit`（**M4-2 已实现**：标 Free + 立重调度牌，释放延迟到下一个上下文，见 ADR-027）、`4=peek`（**M4-3 已实现**：把用户给的一个 `u64` 读回来，走 §10.3.1 那条"校验 → 持锁 → 开窗口 → 读 → 关窗口"的路，是 `copy_*_user` 的最小形状）、`5=peek_buf`、`6=poke_buf`（**M4-3 第二段已实现**：`rdi`=缓冲区地址、`rsi`=长度，两个方向各一次；读回的是内核算的 FNV-1a 校验和，写进去的是 `0xA5 ^ j` 这个模式，由程序逐字节核对 —— 跨页拷贝是否准，**必须由被影响的那一边说**）、`7=abi_info`（**M4-4 已实现**：返回 `(major<<32)|(minor<<16)|features`，特性位 bit0=快路径已装、bit1=SMAP、bit2=SMEP，全部读回真实状态；**程序必须先看到 bit0 才敢打 `syscall`** —— LSTAR 没装就打它就是跳到 `rip=0`，那是 ring0 的取指故障，一个用户程序不该有能力把整机打死）、`99=` 故意不存在的号（回 `-EINVAL`） |
| 参数 | `rdi, rsi, rdx, r10, r8, r9`（最多 6 个） |
| 返回值 | `rax`：非负为成功值，负数为 `-ErrorCode`。<br>**M4-1 实测**：未知调用号回 `-1`（`user::E_INVALID` = `u64::MAX`，即 -EINVAL）而不是崩溃——`served=3 unknown=1 slots=[Some(1),Some(42),Some(18446744073709551615)]`，第三个槽就是那个 `-1`；参数 `rdi/rsi` 确实穿过边界（`0x2a + 0 = 42`）<br>**M4-3 加了 `-2`（`user::E_FAULT` = -EFAULT）**：坏指针的专用码。**为什么两个方向都要数**：内核替用户读内核页 = 提权，因为传了个坏参数就杀用户 = 拒绝服务，两者都不会让机器挂，只有各自的计数器（`bad_ptrs` / `kills`）能把它们分开。§10.2 那句"负数是 -ErrorCode"的**完整数值表仍未冻结**，已在 BACKLOG 记为 ABI 前置项 |
| 破坏寄存器 | `rcx`、`r11`（**仅 SYSCALL 路径**的硬件行为）、`rax`；`int 0x80` 不动 `rcx`/`r11`（见 §10.1 的 M4-1 状态）。**M4-4 起这一行是实测的**：快路径入口不借任何被调用方保存寄存器（`rbx/rbp/r12-r15` 与全部参数原样进帧、原样回去），用户程序在快调用之后**自己读回 CS/SS = 0x23/0x1B** 作为硬件选择子算对了的证据 |
| 版本 | `sys_abi_info()` 返回 major.minor 与特性位 |
| **错误码表（M4 冻结，R33）** | `user::AbiError`：`-1 = EINVAL`（未知调用号 / 参数形状不对）、`-2 = EFAULT`（指针是坏的：不在用户半区 / 没映射 / 不对用户开放 / 往不可写页里写，以及跨页拷贝中途被接住的故障）、`-3 = ETOOLONG`（长度超过 `COPY_MAX`）。**每个号都要有一条真实的调用走到它**：`-1` 由 `KT_ELF_LOAD` 的 `unk` 槽作证，`-2` 由 `KT_USER_POINTER` 的 `peek_kernel`/`peek_unmapped` 两格作证，`-3` 由 `KT_COPY_USER` 的 `buf_err` 作证（程序故意拿 `COPY_MAX + 1` 打一次，实测 `buf_err=-3` 且 `kills=0`）。判据里写的是**数字本身**而不是常量名——常量也是会被人改的代码，而错误码是公开 ABI。<br>**这张表故意不完整**：`Denied` / `NoMemory` / `WouldBlock` 都还没有返回它们的分支，预先编号只会在真做的时候撞上已占用的数字，或者留下一堆"看起来公开过却没人走过"的码 |
| 兼容性 | 调用号、错误码、结构布局**只增不改**；废弃需完整周期 |

可扩展参数结构采用“首字段为 size”的模式，老程序与新内核、新程序与老内核都能工作：

```rust
#[repr(C)]
pub struct OpenArgs {
    pub size: u32,       // 调用方填写 sizeof(自己知道的版本)
    pub flags: u32,
    pub path_ptr: u64,
    pub path_len: u64,
    // 未来新增字段只能追加在末尾
}
// 内核：只拷贝 min(size, size_of::<OpenArgs>()) 字节，其余字段取默认值 0；
// 调用方传入内核不认识的非零新字段时返回 Unsupported。
```

### 10.3 用户指针与拷贝

内核不直接解引用用户指针。所有用户地址先封装为 `UserSlice`，校验后才允许拷贝：

```rust
pub const USER_MAX: u64 = 0x0000_7FFF_FFFF_F000;

pub struct UserSlice { addr: u64, len: usize }

impl UserSlice {
    pub fn new(addr: u64, len: usize) -> Result<Self, SysError> {
        let end = addr.checked_add(len as u64).ok_or(SysError::Fault)?;  // 防止溢出
        if end > USER_MAX { return Err(SysError::Fault); }
        Ok(Self { addr, len })
    }
    /// 拷贝路径在 STAC/CLAC 包裹内运行，并登记到异常修复表；
    /// 页错误时返回 Err(Fault) 而不是内核态 #PF 升级。
    pub fn copy_to_kernel(&self, dst: &mut [u8]) -> Result<(), SysError> { /* ... */ Ok(()) }
}
```

### 10.3.1 M4-3 落地状态（R31 + R32，实测 2026-11-05）

上面那段是**目标形状**：`UserSlice` 封装还没做，但它依赖的三条机制已经全部落地——
逐页校验、一次持锁内的拷贝、以及窗口内的可恢复故障。已经在代码里的规则是这六条，
它们各自挡的方向不同，所以不合并成一条"检查指针"：

| 已落地 | 在做什么 | 挡住的是 |
| --- | --- | --- |
| `user::validate_range(va, len, need_write)` | **逐页**校验 `[va, va+len)`：`checked_add` 防溢出、每一页各自走 `mm::effective_flags`（整条链相与之后的生效位）要求 `user=true`，写还要求 `writable` | 用 `is_mapped` 判断会得出"映射着"而用户态其实碰不到（ADR-026 那次），于是内核替用户读了一页内核页 —— **那是提权，不是越权**。逐页而不是只看第一页：只看第一页是同一类"意图对、据以决策的是另一样东西" |
| `copy_from_user` / `copy_to_user` / `copy_into_scratch` / `poke_pattern_into` | **一次持锁、一段窗口、逐页搬**；`rep movsb` 一次只跨一页，故障时 `rcx` 还计着没搬的那一个元素，所以**返回的字节数是精确的部分长度** | ①校验与读之间插进一次解映射（TOCTOU）——**这一段修的正是它**：上一版 `peek_u64` 的注释写着"同一次持锁期内没人能撤掉这一页"，代码却是锁外校验、锁内读，**注释在承诺代码没做的事**；②"半抄半猜"：部分长度说不清是第几字节，跨页坏了就只表现为内容错位 |
| SMAP 窗口 = `ucopy_from` / `ucopy_to` 里那对 `STAC`/`CLAC` | 复用 `stac`/`clac` 这两个符号本身（与 `read_slot`、`peek_u64` **同一份**开关代码）；窗口里不分配、不打印、不取第二把锁 | 各写各的开关动作会漂。另外 `VMM` 锁是 `IrqGuard`（关中断），所以"窗口里 IF 必须是 0"从一条自觉规矩变成**持锁的推论** |
| **窗口内的可恢复故障**（§10.3 要的修复表） | 拷贝把 `[PF_LO, PF_HI)` 与恢复地址登记进 `trap`；#PF 落在区间内就跳回修复地址、返回部分长度，**不**升 L4。`PF_RESUME/PF_EXPECT/PF_LO/PF_HI` 四格在 `dispatch` 里一次读齐并清空，所以不留"活着的地雷" | 内核替用户读了一页恰好没映射的地址 ⇒ 整机崩溃。证据是 `trap::COPY_RECOVERED`；用例还**反向**用它：三条"应当在校验阶段就失败"的调用要求这个计数不动，涨了才说明校验形同虚设 |
| `ABI_SLOT_*` / `FLAG_*` 两组常量 + 程序侧 `offset_of!` 断言 | 内核按名字读写槽，程序在编译期核对字段顺序 | **字段顺序就是 ABI**，而内核看不见那个结构。上一版把三个 peek 格子插在 `flag` 前面，内核写的 48 落在 `peek_ok` 上，表现是"一个实验都没跑"，读起来像退出路径坏了 |
| `-EINVAL` / `-EFAULT` / `TooLong` / `NotWritable` | 未知调用号回 `-1`；坏指针（不在用户半区 / 没映射 / 不对用户开放 / 往不可写页里写）回 `-2` 且**任务继续活着**；长度超 `COPY_MAX` **明确拒绝而不是取小** | 三个方向相反的错误：内核替用户读内核页（提权）、因为坏参数就杀用户（拒绝服务）、把"被截短"读成"拷贝坏了"。都不会让机器挂，所以必须各自数（`bad_ptrs` / `kills` / `COPY_RECOVERED`） |

实测（同一次正向构建）：

- `KT_USER_POINTER` 四档：`peek ok=0xa7`（合法指针读出真值，挡"校验永远失败"那种装饰）、
  `kernel/unmapped` 两个坏指针都回 `-EFAULT`、`bad_ptrs=2 kills=0`、`ac_active=false`（独立读回的 rflags.AC）；
  第四档"ring3 自己写 guard 页"`kills=1`（**精确等于 1**：抓故障重演，`>=1` 对 M4-2 那次三十多行重复 `#GP` 照样绿）、
  槽位回到 `Free`、页与 VA 保留回账。
- `KT_COPY_USER` 七格：`buf_ok=1 buf_n=512`（内核写 512 字节跨页，程序逐字节核对）、
  `buf_sum == expect_sum == 5839799940456469285`（内核算的实际值，用例算的期望值，两台仪器）、
  `超长=true 写代码页=true 跨未映射页=true 三条里恢复计数=0`、
  恢复路径 `搬成=8 接住次数=1 ac=false 登记干净=true pf_stale_hits=0`。

仍然欠的：`UserSlice` 封装（今天长度与地址是分开传的两个寄存器，没有"一次构造、到处安全"的类型。
它当初要解决的问题——"不经校验就碰用户页"——**已经由另一条路关掉了**：内核里所有开 SMAP 窗口的入口
都必须走带校验的拷贝，`read_slot`/`read_at`/`write_at` 三条以前"自己 `stac` 包一次裸访、唯一把关人
是 SAFETY 注释"的路径已改走校验，`stac`/`clac` 也从 Rust 的 `extern` 声明里删掉，只剩 asm 内部复用。
所以这个类型现在是**表达力**问题而不是**安全**问题，不再列为 M4 的阻塞项），
**同一缓冲区两次系统调用之间的原子性**（今天每次调用各自持锁，语义上没有"一段事务"），
以及把 `trap::probe_page_fault` 那条单点探针收敛到区间登记上（现在是两台机器、一套硬件）。
故意保留的两个不校验入口都写明用途且各自有判据：`probe_slot_without_window`（验 SMAP 真的生效）、
`probe_copy_from`（验恢复路径真的被走过）。全部欠账写在 BACKLOG。


### 10.4 Capability 句柄模型（ADR-007）



进程只能通过**句柄**访问内核对象（文件、内存对象、线程、设备窗口等），每个句柄带权限位，没有“全局命名空间里的任意路径”。可参考 seL4、Fuchsia 等 capability 系统的设计 [R8](https://sel4.systems/)、[R9](https://fuchsia.dev/)（本次未核验具体页面）。

```rust
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rights(u32);
impl Rights {
    pub const READ: Self = Self(1);     pub const WRITE: Self = Self(2);
    pub const MAP: Self = Self(4);      pub const DUP: Self = Self(8);
    pub const TRANSFER: Self = Self(16);
    pub fn contains(self, o: Self) -> bool { self.0 & o.0 == o.0 }
}

/// 句柄 = 槽位索引 + 代数，防止重用槽位后的旧句柄被误用。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Handle(u32);

impl HandleTable {
    pub fn get(&self, h: Handle, need: Rights) -> Result<&KernelObject, SysError> { /* 检查代数与权限 */ todo!() }
    /// 复制句柄只能缩小权限，不能扩大。
    pub fn dup(&mut self, h: Handle, new: Rights) -> Result<Handle, SysError> { /* 需要 DUP 且 new ⊆ old */ todo!() }
}
```

### 10.5 C 与 Rust 的 FFI 规范

| 规则 | 说明 |
| --- | --- |
| 数据布局 | 跨语言结构一律 `#[repr(C)]`，禁止跨边界传 Rust 枚举带数据、切片、`&str` |
| 缓冲区 | 必须指针 + 长度成对传递，入口处校验非空、长度上限 |
| 所有权 | 每个接口在注释中写明谁分配、谁释放 |
| 错误 | 统一整数错误码，不使用异常 |
| panic | 内核为 `panic = abort`，FFI 入口必须无 panic 路径（禁用 `unwrap/expect`，开启 clippy 规则） |
| 参数校验 | 所有 FFI 入口先校验再使用 |
| 登记表 | FFI 边界代码集中在 `aurora-ffi`（V1.2 起统一登记在 §1.3 的 `unsafe-whitelist.toml`，不再就地补名单） |

```rust
// crates/aurora-ffi/src/log.rs
#[repr(C)]
pub struct AuBuf { pub ptr: *const u8, pub len: usize }

pub const AU_OK: i32 = 0;
pub const AU_EINVAL: i32 = -22;   // 错误码表统一维护在 docs/interfaces/errors.md

#[no_mangle]
pub extern "C" fn aurora_log_write(level: u32, msg: AuBuf) -> i32 {
    let Some(level) = LogLevel::from_u32(level) else { return AU_EINVAL };
    if msg.ptr.is_null() || msg.len == 0 || msg.len > MAX_LOG_LEN { return AU_EINVAL; }
    // SAFETY: 接口契约要求 C 调用方保证 [ptr, ptr+len) 可读；非空与长度上限已在上方校验。
    let bytes = unsafe { core::slice::from_raw_parts(msg.ptr, msg.len) };
    aurora_diag::log_bytes(level, bytes);
    AU_OK
}
```

### 10.6 版本与兼容策略

| 对象 | 版本规则 |
| --- | --- |
| 内核 | 语义化版本 |
| 系统调用 ABI | major 不兼容、minor 只增不改 |
| 驱动接口（`DriverCtx`） | 独立版本号，变更需 ADR |
| 文件系统磁盘格式 | 格式版本写入超级块，支持前向检测 |
| 更新包 | 包格式版本 + 签名版本 |

### 10.7 用户程序的容器与加载（M4-2 落地，R29）

本节记的是**已经在代码里的那套规则**（`kernel/src/elf.rs` 与 `user::load`），不是计划。
每条"明确拒绝"都有一条负样本盯着（§12.4.1 规则 3：尺子必须先能分辨）。

| 规则 | 拒绝码 / 落地位置 | 为什么不能省 |
| --- | --- | --- |
| 只收 ELF64 + 小端 + `e_machine=x86-64` + `ET_EXEC` | `Not64Bit` / `NotLittleEndian` / `WrongMachine` / `NotExecutableImage` | `.o`、别的架构、别的字节序都是"看起来像但语义不同"，收下就是后面某处故障 |
| `ET_DYN`（PIE）**明确拒绝** | `RelocationUnsupported` | 本版本没有重定位器。硬当 `ET_EXEC` 用的现场是"程序进去了、一跳转就故障"，比拒绝难查一个数量级 |
| 段的 VA 必须页对齐，且落在加载器窗口 `[4 GiB, 1 TiB)` | `SegmentNotPageAligned` / `SegmentOutsideWindow` | 窗口比 `elf` 层允许的"低半区"**窄**：窗口之内，那条页表链由用户映射自己建（上级表项带 U/S=1）；窗口之外就得去放宽内核半区的共享上级表项（ADR-026） |
| **窗口内再分两段**（M4-3，R31）：固定镜像只能要 `[USER_VA_BASE, USER_MMAP_BASE)`，内核挑的地址（用户栈、脚手架）只在 `USER_MMAP_BASE` 之上发；按**整份镜像的跨度**判，不逐段判 | `ImageInDynamicRegion` / `user::check_image_span` | 两半共用一条前沿时，**先到的赢**：`user::init()`（测试脚手架）扫走了 `0x100000000`，`ET_EXEC` 夹具就要不回来（`VaTaken`），而那一刻 `reservations` 与 `live_of(MOD_USER)` 都回到基线——账完全是平的，读数长得像"回收坏了"。真正的规则缺失是"固定地址的请求与随机地址的请求共用一条前沿"，成败于是由 `.ktests` 段的**链接顺序**决定。分区之后这条与顺序无关 |
| 权限按容器给**最小的一组**：`r-x`→`USER_RX`、`rw-`→`USER_RW`、`r--`→`USER_R`；`W+X` 一律拒 | 加载器三个分支 / `WxViolation` | 只有 RX/RW 两种组合时，`r--` 段只能多给 X 或多给 W——把 §6.4 的承诺变成"看容器作者的心情"。第三个分支由程序自己的第四个槽证明它被走过 |
| **逐页装**：取帧 → 整页清零 → 拷文件字节 → 装叶子 | `user::load` 的页循环 | 两件事同一条动作解决：`memsz > filesz` 的 bss 尾巴必须是 0，而新页框带着上一个主人的内容（不清零就是把内核内存交给 ring3 读）。**不能按段开缓冲**：本内核分配器上限是 `heap::LARGE_MAX = 2048` 字节，22 KB 的 `Vec` 当场把整机打到 39 |
| 填内容一律经 HHDM，装完叶子之后不再写 | 同 ADR-026 决策一 | `USER_RX` 装好之后写不进去（W^X），SMAP 也挡内核直接碰用户页——这两条 M4-1 都实测过 |
| 入口必须落在某个可读可执行段里 | `EntryNotLoaded` / `EntryNotExecutable` | 否则"跳到数据页执行"要靠硬件事后拦，判据就从"拒绝理由"退化成"故障现场" |
| 目标 VA 已被登记或已映射 → 拒绝 | `VaTaken` | 两个容器不能抢同一段地址；这条与 §6.3 的所有权是同一条规则在容器层的形状 |
| **内核拥有一页用户态落脚页**（`user::TRAMPOLINE_VA`，窗口最顶上一页 `USER_RX`，内容只有 `jmp .`，建好之后永不撤销） | `user::ensure_trampoline()`，由 `init()` 与 `load()` 两条入口各自先调 | 被杀的任务此刻站在自己要交出去的内核栈上，而异常桩出口照样要 `iretq` 回 ring3：rip 不改就是"再故障一次、再被杀一次"（实测每秒几十次）。这一页**以前是手写镜像那一页**（`prog().park`），于是"容器任务被杀之后跳进一个只有某条用例才会建的页"——依赖看不见，还要靠用例顺序才成立。`rsp/cs/ss` 现在保持故障帧原样：那是这个任务自己的栈与选择子 |

**判据**：`KT_ELF`（正样本收下真产物 + 二十二条负样本，每条各命中一格）与
`KT_ELF_LOAD`（把 `user/hello` 的真产物装进去跑起来：四个结果槽、生效位、P7 样本数三条仪器）。
夹具由 `python tools/aurora.py build` 从 `user/hello` 重新产出并写入
`kernel/fixtures/hello.elf`，**只在字节真的变了时才覆写**——`include_bytes!` 的依赖挂在 mtime 上，
每次无脑重写会让"增量构建"这件事静默失效。

**生命周期与回账（M4-2 第三段，ADR-027）**：

| 规则 | 为什么 |
| --- | --- |
| 映射的所有权跟着任务走（`Task::owned`，定长 `MAX_OWNED = 8`） | §6.3 R13 的"主人负责解映射与归还"第一次有了能活到任务结束载体；不再 `forget`（那是"有去无回"的实现）。**上限数的是"块"而不是"页"**（R33）：`user::load` 按段做连续分配，每段切成"剩余页数里最大的 2 的幂"若干块。实测这份夹具：镜像 5 页 ⇒ 4 条映射，加用户栈与内核栈共 **6 / 8**（改之前是 7 / 8），证人两处——`elfload: 容量 owned=6 上限=8 余量=2` 与 `收尾回收 released=6`。判据是**余量 ≥ 2**，不是"等于 6"（等于 6 只是这一版夹具的快照，改夹具就红的那种红不代表容量坏了）。为什么不向上取整到 2 的幂：**那会多占 VA**，于是下一条段的 `reserve_va_at` 撞 `VaTaken`——ADR-028 那条病因的第三种形态 |
| 结束 = 标 Free + 资源**留在槽里** + 立重调度牌；**不当场释放** | 任务自己 `SYS_EXIT` 那一刻 `rsp` 就在要交出去的那条内核栈上，当场解映射 = ring0 故障 = L4 |
| 释放点 = 本 CPU 的下一个抢占点路过 `reap`（且 `reap` 排除 `current`） | 唯一能保证"没人站在那条栈上"的时刻。代价写进 ADR-027 的后果：**这条依赖"该 CPU 还会出现一次抢占"** |
| `Mapping::drop` 连 VA 保留一起放手（按包含找、逐页确认无映射） | 任务栈是"保留 5 页只映射 4 页"（guard 页），按基址相等匹配永远还不回去 |
| `kills` 与 `exits` 分开数 | 混成一个数就看不出"隔离生效"与"生命周期走完"哪条还在欠账 |
| **被杀那条路径要登记待回收**（`kill_current`），而 `finish_current`（内核任务跑完）不登记 | M4-3 拆出来的静默漏：只标 `Done` 而不给 `REAP_PENDING` 计数，`reap` 开头读到 0 就直接返回，于是容器任务被杀之后名下 5 条映射（含它的内核栈）永远留在槽里——**不崩、不报错，只是不还**。为什么不合并成一个：内核任务也带一条内核栈（`spawn` 把它放进 `owned`），合并之后 `KT_PREEMPT` 那种"事后读这格发生过什么"的判据会在被观测之前就被归化清掉（那次回归是实测到的：`state1=Free runs1=0`）。内核任务自己的槽位回收是欠账，见 BACKLOG |
| **`kills` 判"精确等于 1"，不是 `>= 1`** | 故障重演的现场就是"同一个异常每秒进来几十次"，`>=1` 对它照样绿。能分辨的读数才是判据（§12.4.1 规则 3） |

**M4-2 实测**（同一构建）：`elfload: segs=3 pages=3 entry=0x100000000 data=0x100002000`、
`magic=0xa5a55a5a12345678 ping=1 add=60 unk=-1 rodata=0xa7 served=3`、
`eff code={user:true,writable:false,executable:true} data={user:true,writable:true,executable:false}`。
**（`pages` 这条读数 M4-3 第二段之后是 5，不是 3**：跨页拷贝实验要让可写段真的有第二页，
所以夹具的 `.bss` 加了 `PAD`——见下面那条容量行。）

**M4-3 实测**（`KT_USER_POINTER`，同一构建）：`image=[0x100000000..0x100003000)`（第二段之后是 `..0x100004100`）而
`栈页=0x100101000`、`分界=0x100100000`（分区两半各读一次，不信"装上了就是没抢"）；
`tramp=0xfffffff000` 的生效位 = 用户可达 + 可执行 + 不可写；
`peek ok=0xa7 kernel=-EFAULT unmapped=-EFAULT bad_ptrs=2 kills=0 ac_active=false`；
越界写那一档 `kills=1 那一页仍没映射=true 槽位=Free 页已回收=true 等到回收=true`。
`elfload: segs=3 pages=3` 那一批读数为之一变：`stack_top` 从 `0x100004ff0` 变成 `0x100101ff0`
——**这就是分区那条规则在串口上的样子**，不是回归。

## 11 安全与供应链

### 11.1 缓解措施清单（默认开启，关闭需 ADR）

| 机制 | 阶段 | 说明 |
| --- | --- | --- |
| W^X、NX | M2 | 页权限构造即强制（6.3） |
| SMEP / SMAP | M4 | 硬件支持时强制开启 |
| KASLR | M2 | 依赖 Limine 配置 \[R3\] |
| 守卫页 | M2 | 所有栈与堆区 |
| 栈保护（C 代码） | M1 | `-fstack-protector-strong` |
| CFI | 评估 | 工具链支持情况需实测后决定 |
| 顶级推测执行缓解 | M7 | 按 CPU 型号与微码能力选择，不硬编码型号 |
| IOMMU | M5 | 见 8.4 |
| 随机数 | M4 | 硬件随机源与其他熵混合，不单独依赖 RDRAND |
| 安全启动、度量启动（TPM） | M7 | 需评估 Limine 与签名链支持 \[R3\] |
| 驱动、更新包签名 | M6 | 见 9.5 |
| 审计日志 | M6 | 权限拒绝与关键操作记录 |

**签名那一格的实际落地状态（M9-a②，ADR-033）**：验签的**机制与判据**已经落地——Lamport 一次性签名、
锚点是内置的"整张公钥的摘要"、包放在状态区之后同一段 GPT 空隙（LBA 67_664 起 113 扇区）、
九种篡改各自走到一个不同的拒绝分支，且**两份实现必须逐条给同一个答案**。
但**它还没有接到启动决策上**：今天验签发生在一条用例里，"未签名或验不过就不启动"要等 ADR-011 正式
方案与 §9.5 的槽位身份。这一句必须和"签名已实现"一起说，否则就是把机制当成策略。
生产钥匙（离线保管、轮换、吊销）同样没做——现在的锚点是测试种子导出的，只能证明机制对。

### 11.2 供应链规范

- `Cargo.lock` 入库；关键依赖 vendoring，禁止构建时联网拉取。**“哪些许可证允许进树”由 ADR-009a 定义，且必须在 M1 之前接入 CI**——vendoring 这个动作本身就发生在依赖出现的第一天，等 ADR-009b（发布许可证）定下来再查就晚了（V1.2 R9）。
- `cargo deny`（许可证、来源、已知漏洞）[R14](https://github.com/EmbarkStudios/cargo-deny) 与 `cargo vet`（依赖审计记录）[R15](https://github.com/mozilla/cargo-vet) 纳入 CI。
- 生成 SBOM，发布产物可复现构建并签名；签名根密钥离线保存。

**这两条今天的落地状态（M9-b，BACKLOG 62）**：`python tools/aurora.py release` 做两件事——
①两次全量编译（中间 `cargo clean -p aurora-kernel`）比内核 ELF 的 sha256，实测同摘要
（`84c27191f859…`），所以**同机同路径的可复现**成立；**跨机/跨路径没测，不写"跨机可复现"**；
②生成 `docs/release/sbom.json`（成员、版本、许可证、来源 + 产物与镜像内逐文件摘要），
由第 **13** 道门禁 `check-sbom` 与 `cargo metadata` 的全依赖图对账。
两条必须一起说：全图只有 **2 个包、外部 crate 0 个** ⇒ `cargo deny`/`cargo vet`/vendoring
今天没有可管对象（门禁先立着，依赖出现的第一天就管）；两个成员都**没有声明许可证**
（ADR-009b 未定），处理方式是在 `crates.toml` 里登记**带理由的留空**而不是随手填一个 MIT。
签名那一半仍未做（根密钥、轮换、SBOM 进发布产物都要等 ADR-009b/ADR-033 的没做到的那些条目）。
- 任何新增依赖需说明理由、许可证、unsafe 量；内核 TCB 内的依赖需双人评审。

### 11.3 漏洞响应

公开 `SECURITY.md`（报告渠道、响应 SLA、披露时限），设立安全负责人与应急发布流程（支持单独的安全补丁发布，不捷带功能更新）。具体 SLA 数值由安全委员会在 M9 前确定，本手册不预设。

## 12 测试与质量保障

### 12.1 七级测试体系（对 V1.0 五级的扩展）

| 级别 | 内容 | 工具 / 运行位置 |
| --- | --- | --- |
| L1 静态 | fmt、clippy、clang-tidy、依赖图、unsafe 统计、**§3.5 的四条 `check-*`（登记表对账 / `[lints]` 已接入 / 镜像内浮点指令数为 0 / crate 清单一致）**、**每条门禁的固定负样本（§12.3 R19）** | CI 每次提交 |
| L2 宿主机单元 | **仅限 §3.5 `HOST_TESTABLE` 名单内的 crate**（V1.2 R15：不带 `--target`，故内核 crate 天然进不来）；分配器算法、调度策略、解析器、**diag 的分级判定**，用 `cargo test` + Miri [R10](https://github.com/rust-lang/miri) + loom [R11](https://github.com/tokio-rs/loom)；**loom 必含“同持有者二次获取”交错（§7.1 R16）** | 宿主机 |
| L3 内核集成 | 模块接口、初始化顺序、资源生命周期 | QEMU 测试运行器 |
| L4 系统 | 异常、中断、多核、virtio 设备 | QEMU |
| L5 故障与压力 | 故障注入（9.8）、中断风暴、内存压力、长时间运行 | QEMU + 多种硬件配置 |
| L6 模糊 | 文件系统镜像、网络报文、ELF、系统调用参数 | cargo-fuzz [R13](https://github.com/rust-fuzz/cargo-fuzz)（宿主机解析器）；系统调用模糊可参考 syzkaller 思路 [R12](https://github.com/google/syzkaller) |
| L7 真机 | 硬件矩阵夜间回归 | 自建实验室 |

关键数据结构（伙伴分配器、句柄表、页表操作）可用 Kani [R16](https://github.com/model-checking/kani) 做有界模型检查作为补充。这些工具的适用范围与限制需在引入前实际试用验证。

### 12.2 QEMU 测试运行器

使用 QEMU 的 `isa-debug-exit` 设备把测试结果映射为进程退出码，串口输出详细过程，这是内核开发常见做法 [R4](https://os.phil-opp.com/testing/)：

```rust
#[repr(u32)]
pub enum QemuExit { Success = 0x10, Failed = 0x11 }

pub fn exit_qemu(code: QemuExit) -> ! {
    // SAFETY: 0xf4 是测试环境中 isa-debug-exit 的 I/O 端口（见 justfile 的 QEMU 参数）。
    unsafe { core::arch::asm!("out dx, eax", in("dx") 0xf4u16, in("eax") code as u32, options(nomem, nostack)); }
    loop { core::hint::spin_loop(); }
}
// QEMU 进程退出码 = (写入值 << 1) | 1：Success→33，Failed→35，CI 脚本把 33 视为通过。
```

> **两处必须一起核对的约定（V1.2，依据 \[V8\]）**：① `isa-debug-exit` 的**默认** iobase 是 `0x501`，本手册用的是 `0xf4`，完全依赖 §3.5 里 `-device isa-debug-exit,iobase=0xf4,iosize=0x04` 这一行；改一处忘改另一处的后果是内核写往一个不存在的端口，**测试既不通过也不失败，而是一直跑到超时**。② 因此 CI 判据不能只写“退出码 != 33 即失败”——那会把“QEMU 没起来”“镜像没引导”“跑挂了没退出”三种情况压成同一个红。请分级：`未产生退出码 + 串口有 boot-ok` ⇒ 判“挂死”，`未产生退出码 + 串口无 boot-ok` ⇒ 判“启动失败”，二者与 Failed 分开统计，并按 §12.4 各自的采集法入库。**这条分级本身就是 §12.3 R19 所说的“尺子要能分辨”的第一个用例。**

稳定版 Rust 没有自定义测试框架，因此用“段注册”收集测试：

```rust
pub struct KTest { pub name: &'static str, pub run: fn() }

#[macro_export]
macro_rules! ktest {
    ($name:ident, $body:block) => {
        #[used] #[link_section = ".ktests"]
        static $name: $crate::KTest = $crate::KTest { name: stringify!($name), run: || $body };
    };
}
```

链接脚本（3.3）需补充：`.ktests : { __ktests_start = .; KEEP(*(.ktests)) __ktests_end = .; } :rodata`，运行器遍历两个符号之间的条目。

### 12.3 CI 门禁

| 触发 | 必须通过 |
| --- | --- |
| 每次合并请求 | L1、L2、L3、QEMU 启动测试、unsafe 统计不超预算、cargo deny、**§1.3 第 6/7 条的两项对账（登记表⇄实际、`[lints] workspace` 已接入）**、**§3.5 的 `check-nofloat`**、**夹具图案字节两边对账 `check-virtio-pattern`（M5-f②：宿主机写进 qcow2 的图案与内核用例期望的图案各写一份，不核对就会有人改一边把它改绿——实测我就是先写错成 `0x5A` 被现场抓出来的）**、**网卡那一帧的形状 `check-net-pattern`（M8-a①：宿主机要按同一张表重算 pcap 里那 60 字节才能对账，所以内核与 `aurora.py` 各写一份；实测它第一次跑就红在自己身上——正则只吃 `0x…` 写法而内核把步长写成十进制 `11`，"按渲染比而不是按数值比"）**、**判定表自身的接线 `check-matrix-wiring`（每一行的"实际值/期望/证据日志"必须来自自己那一跑——R38 抓到过两行共用同一个变量，其中一行静默变成了另一行的副本而矩阵照样全绿）**、**SHA-256 的两张常数表按定义重算对账 `check-sha-primitives`（M9-a①：64 个轮常数与 8 个初始值是最容易凭记忆写错的东西，而写错的表现是"自洽地错"——实测改一个旋转量，内核自己的五格全部为真）**、**签名的形状/锚点/篡改表三方对账 `check-sig-anchor`（M9-a②：内核与镜像生成器各写一份，锚点还要等于生成器按导出式子重算的 `sha256(pk)`——我凭记忆写的那份锚点就是被这道门禁判红的）**、**P1–P4 基线不劣化超过阈值** |
| 每夜 | L4、L5、L6（限时）、重复启动 N 次的成功率、P1–P4 全量重测并入库 |
| 发布前 | L7 硬件矩阵、长时间运行、unsafe 审计报告、SBOM 与签名验证、P1–P4 与上一发布版对比报告 |

不允许通过关闭测试或忽略警告绕过门禁；有例外需 ADR 记录与到期日。

**（R19）门禁本身要有“会红”的证据**：上表任何一项若在某次改动后**从未变红过**，就无法区分“代码一直没问题”和“这项检查根本没跑”。M1 起为每条门禁配一条**固定的负样本用例**（故意注入一次违例，断言门禁必须失败），并纳入 §12.1 的 L1；`check-lints-wired` 与 `check-unsafe` 两条尤其需要，因为它们防的正是“看起来绿、实际空转”。


#### 12.3.1 注入构建清单（M2-c 落地，`python tools/aurora.py test` 逐条跑）

| 构建（`--features`） | 注入什么 | 期望判定 | 它防的那条“绿而无效” |
| --- | --- | --- | --- |
| `negative-probe` | 让一条 ktest 故意返回 false | **FAIL(35)** | 判定链根本没生效 |
| `fault-double-free` | 对同一物理帧真的释放两次 | **EXCEPTION(39)** | §9.2 的“检出即 L4”只是文档 |
| `fault-heap-oom` | 向全局分配器要 `LARGE_MAX+1` 字节 | **EXCEPTION(39)** | ADR-018 的失败出口不存在却没人发现 |
| `fault-resource-leak` | 故意泄漏一帧给测试模块 | **FAIL(35)** | §6.7 的“按模块汇总存活分配”其实看不见泄漏 |
| `fault-alloc-in-irq` | 在定时器中断的处理路径里走一次全局分配器 | **EXCEPTION(39)** | §6.5“中断上下文禁止堆分配”只是注释。守卫**先拒绝再取锁**（否则 ISR 与持锁的临界区自死锁），容器路径随即走 `handle_alloc_error`——ADR-018 的稳定版唯一去向，所以期望是 39 不是 35 |
| `fault-lock-reentrant` | 同一上下文重复获取堆锁 | **EXCEPTION(39)** | §7.1 R16 的 `held_by` 重入检测其实不存在；单核上的真实后果是关中断自旋死锁 |
| `fault-if-carriage`（M3b-1，R25） | 把"IF 属于 CPU"改回硬件默认的"任务自己带 IF"，其余一律不动 | **HANG(rc=-1)** | ADR-021 只是一句决定的话。实测：第一个被换入的新任务带着 IF=0 跑，再没有 tick 能抢占任何人，串口停在抢占测试的第一行之前 —— 与 M3a 记录的症状同一条形状。**期望不是报红而是挂死**，所以这一行单独用 60 s 超时（注定要等到超时） |
| `fault-no-smap`（M4-1，R28） | 写完 `CR4` 之后把 **SMAP 位清掉** | **BOOT-INVALID(37)** | §5.1 把 SMEP/SMAP 列成必需项，而"必需项"若只写成一句 `if` 就永远是绿的：正常机器上两位都为真，没人知道那条判断是不是装饰。清掉一位之后必须停在**启动**而不是运行中停机（37 与 39 的差别就是 §9.2 的分级：前提不满足 vs 运行时故障） |
| `fault-shootdown-noack`（M3b-2a，R26） | 被通知的 CPU 照常 `invlpg`，但**不回执** | **EXCEPTION(39)** | §6.6 那句"等 shootdown 完成之后才释放物理页"。这条负样本同时补上 QEMU 的一个先天缺陷：TCG 会因页表被写自行失效条目，所以"不通知也读得对"在这台机器上永远成立（KT_SHOOTDOWN 只能验协议）；把回执拿掉之后，请求方必须超时升 L4，实测 `L4 mm: shootdown 超时 … 还差 3 个回执` → 39 |
| `fault-ahci-lba`（M5-b③，R37） | 内核一切正常，只把读回来的数据**标到另一个 LBA** | **CONTENT-MISMATCH(rc=33)** | 判定链若只有"内核自己说"这一级，内核全绿而标签错了谁也看不见：这条靠宿主机按 qcow2 字节重算哈希。它同时是新的一级 `CONTENT-MISMATCH` 的负样本 |
| `fault-ahci-count-hi`（M5-c②） | 16 位扇区数按高字节在前编程 | **FAIL(35)** | "跨 255 扇区那次读"是扇区数高字节唯一的现场判据：短读在这台 QEMU 上照样成功完成，放错位置只在长读的尾巴上露出来（BACKLOG ㉜ 记的是我原先的推测错了——红在用例而不是超时） |
| `fault-ahci-highlba`（M5-c②） | LBA 高 32 位按 `>>32` 写（第一版的写法） | **FAIL(35)** | 与 `ahci-scratch` 那行配成一对：那行证明"字节 8 写对了就读得到 128 GiB 外那一格"，这行把它改回去必须红，否则前一行是空转 |
| `ahci-scratch`（M5-c②/③，R37） | 不注入故障：多挂一块 **130 GiB** 的 qcow2，把图案写到 LBA 268 435 456 再读回，并做一次写方向 | **PASS(33)**（宿主机对账必须过） | 扇区数与 LBA 的宽度问题只有越过 2^32 扇区才存在；这一行是对照组，少了它就无法区分"写对了"与"这台机器根本测不出写错" |
| `fault-ahci-write-partial`（M5-c③） | 写命令少编程扇区数（只搬前半） | **FAIL(35)** | 写方向打通之后必须有人验"真的落盘了"：回读逐字节当场不一致，这条才让"写成功"不等于"设备回了个状态" |
| `fault-ahci-write-dir`（M5-c③） | 丢掉 DW0 的 **W 位**，其余不动 | **PASS(33)** | 期望按**实测**写成 PASS：本机 QEMU 的命令方向由命令字节（0x35/0x39）决定，不看 W 位。这一行是**记录不是判据**——真机上必须重测这一格（BACKLOG 挂着） |
| `virtio-blk`（M5-f①） | 不注入：第三块盘走 virtio-blk，内核把能力链与 `common_cfg` 的十格证人读回来 | **PASS(33)** | 驱动寄存器表凭记忆写必错（本机已错过五处）。这一行任何一格读不懂都由内核自己报红，而"读回一个数"不算过：判据是**选择器对**（换 `device_feature_select` 那格读数要跟着变）与"越界选择读回 0" |
| `virtio-blk` × 第二遍（M5-f②，R43） | 不注入故障：把同一个变体**再跑一遍**，然后宿主机用 `qemu-io` 读那块 qcow2 的扇区 8 | **PASS(33)**；三个哈希必须同数（内核写前、内核读回、宿主机读到的），不符报 **CONTENT-MISMATCH** | 第一条 I/O 的内容判据全在客户机一个进程里，"落到盘上"这句话不能由它自己说。这一遍同时是幂等性检查：同一份图案写两次，盘上还是那份 |
| `virtio-net`（M8-a①，R44） | 不注入故障：挂一张 virtio-net，内核把 **TX 队列**（编号 1）建起来发两帧，图案里带序号 | **PASS(33)**；宿主机读 `filter-dump` 写下的 pcap，逐帧三处对账（包字节 == 宿主机按同一张表重算、包哈希 == 内核自报、源 MAC == 命令行 `mac=` 那一份），不符报 **CONTENT-MISMATCH** | 内核那八格全在"驱动自己知道"的范围里（队列起来了、回执来了、缓冲没被动过）；**"这一帧真的上了线，而且是我声称的那些字节"这句话只能由核外的抓包器答**。它同时钉住三条现场事实：不接受特性时头长是 10 字节、设备配置区只有 8 字节存在（`mtu` 读回 0xFF 是"这一格不存在"而不是"值是 0xFFFF"）、QEMU 给 transitional 网卡的 PCI device id 是 `0x1000`（所以"我是网卡"不能拿 device id 当依据，改用"队列数 ≥ 2 且 RX/TX 门位不同"） |
| `virtio-net` × 第二遍（M8-a②，R45） | 不注入故障：同一变体再跑一遍，内核发一份 DHCP DISCOVER 并收一条回话（对端 = QEMU 用户网络自带的服务器） | **PASS(33)**；pcap 里必须找到①与宿主机**逐字节重算**相同的那份 DISCOVER、②内核读到的那一条（哈希同数），且两份独立实现解出的 `op/xid/msg/yiaddr` 一致、`yiaddr` 等于 `dhcpstart=10.0.2.15`、回话里的 `chaddr` 等于这块网卡的 MAC，否则 **CONTENT-MISMATCH** | "内核解开了"与"宿主机也解开了"是两条实现，只对得上才算解析器正确；`yiaddr` 这个数**内核不可能猜到**（是宿主机的配置），所以它是这一行里唯一答案在核外的判据。第一遍的 TX 判据全在"驱动自己知道"的范围里，这一遍把"对端真的答了、答的真是我"变成判定行。顺带钉住两条现场事实：用户网络不答 ARP、`used.len` 在收方向 = 头长 + 帧长 |
| `sig-check`（M9-a①，R46） | 不注入故障：核内那套零依赖 SHA-256 对 13 条长度向量各算一遍，边界取 55\|56、63\|64、111\|112、119\|120 | **PASS(33)**；每条摘要必须与 CPython `hashlib` 逐字相同，否则 **CONTENT-MISMATCH** | 改一个轮常数或一个旋转量时，内核自己的五格**全部照样为真**（实测 `rotate_right(6)→(7)`：判定 `PASS(33)`、`互不相同=true`、`雪崩=31/32`），只有第二台实现看得见。密码原语上"自我一致"等于零证据 |
| `sig-check` × 第二遍（M9-a②，R46） | 不注入故障：同一变体再跑一遍，内核从固定 LBA（67_664 起 113 扇区）读整份签名包（15 次块读）、核锚点、逐比特验签，再对九种篡改各验一遍 | **PASS(33)**；两份实现（内核 `check_package` / 宿主机 `pkg_reason`）必须对**每一条**畸形输入给同名同数的理由；包内载荷摘要 == 内核手上那份夹具 == 宿主机那份文件；否则 **CONTENT-MISMATCH** | "内核拒了"不是判据——拒错东西也叫拒。九条各须走到**不同分支**（`AnchorMismatch`/`BitMismatch(i)`/`PayloadTooLong`/`BadLen`/`BadHeader`）：第一版把载荷长度翻在低字节，得到的是 `BitMismatch(0)`，界检查那条根本没测到。手工改掉盘上公钥的一个 bit 再对账，必须**同时**报"宿主机自己验不过"与"两份实现答案不同"，这才是更新流程要的"内核验过的字节 == 现在盘上的字节" |
| `negative-probe` × **4 遍**（M6-a②，R38） | 不注入新东西：同一份镜像**不重建**连跑四遍 | 四遍的**序列**：连续失败 `[0,1,2,3]`、模式 `Normal/Normal/Normal/Safe`；不对报 **SEQ-BROKEN**（与 FAIL 分开） | §9.4 的验收句是"注入故障后系统可*自动*走向安全模式"，这在单遍启动里原理上不可见。SEQ-BROKEN 与 FAIL 必须分开：序列不对的成因在状态区/持久化，内核自己红了的成因在判定链，两件事不能用同一个词 |
| `fault-crash-oops` × **2 遍**（M6-d，R42） | 核心态故意读一个未映射地址（`0xffffc00000000008`）⇒ #PF(14) 在核心态没有恢复项 ⇒ `Action::Fatal` | 第一遍 `EXCEPTION(39)` 并落一条 V2 记录：**向量必须是 14、CR2 必须等于注入地址**，且与同一遍串口打的 `cpu] vec=14 … rip=… rsp=…` 逐字段同数；第二遍必须把那条读回来；不对报 **SEQ-BROKEN** | 第 20 行只证明"字段搬得对"。这一行证明"字段是 CPU 给的"——没有它，V2 那 12 个格子完全可以由用例自己填数通过，等于没验。顺带实测出边界：真实现场今天只走得出 1 帧（产物没有帧指针），所以 `frame_count >= 1` 而不是"栈深度足够" |
| `force_boot_state(99)`（M6-a③，R39；不是 `--features`，是宿主机直接改盘） | 用生成器那份编码器把状态区槽 0 写成 `seq=200 连续失败=99` | 三遍的**序列**：强制 Safe 遍 `模式=Safe 读到的连续失败=99` 且 `PASS(33)` 且打出 `boot: 健康清零`；下一遍 `模式=Normal 读到的连续失败=0` 且 `PASS(33)`；不对报 **SEQ-BROKEN** | §9.4 只写"进安全模式"，没写"出得去"。这条判据把降级态的**退出路径**钉住：健康判据若拿理想态基线比降级现场，安全模式就变成单行道（实测一次偶发把机器锁在里面连红 9 遍）。也是"偶发现场必须做出来、不能等多遍撞"这条规矩的第一个用例 |
| `fault-double-free` × **2 遍**（M6-b②，R40） | 同一份镜像**不重建**连跑两遍：第一遍崩之前把摘要写进状态区 | 两遍的**序列**：第一遍 `crash: 落盘 槽=A seq=S 向量=V cpu=C rip=R 种类=2`，第二遍 `crash: 上一条 槽=A seq=S …` 逐字段相同，且宿主机按同一套偏移重解那条记录也相同；两遍判定都必须是 `EXCEPTION(39)`，不对报 **SEQ-BROKEN** | §9.7 的"下次启动持久化"在单遍启动里原理上不可证。这一行同时是"落点收口在唯一出口"那条决定的量具：把 `exit::finish` 里的 `ensure_dumped()` 去掉，落盘行与上一条行同时消失，当场 `SEQ-BROKEN` |
| `bench-switch-load`（走 `bench`，不进 test 矩阵） | 在切换发出前的**被测区间之内**加一次 `invlpg` + 空转 | 仍 **PASS(33)**，但 P1 的 `min` 必须超出同构建两次的噪声地板 | §12.4.1 规则 3 对 P1 的等价要求。第一次注入写在记账之后，被这条当场判"不符合"——它当时报得对 |
| `trace-switch`（诊断构建，不进判定） | 每次切换在 ISR 里打一行 `sw#N 从->到 帧地址 状态表` | 不判 | 调度类故障目前唯一有效的观测手段：本轮两次挂死（Done 任务霸占 CPU、帧不在栈上）都靠它当场定位。真机上这么干会把中断窗口拖长，所以它不是产品路径 |
| `bench-pf-load`（走 `bench`，不进 test 矩阵） | 在 `#PF` 恢复路径上加一段确定性空循环 | 仍 **PASS(33)**，但 P3 的 min 必须显著变大 | §12.4.1 规则 3：量具分不出已知差异 |

退出码集合固定为 `33 / 35 / 37 / 39`，且**必须再加两类宿主侧分级**：超时（`HANG`/`NOBOOT`）
与 **QEMU 以约定外的码退出**（实测客户机三重故障走 `-no-reboot` 会以 `rc=0` 收场，
见 ADR-019）。任何"约定外退出码"都判失败，不许映射成通过。
### 12.3.2 M4 用户态用例的判据清单（R35，从 `main.rs` 的用例头搬进来）

原则：**一条判据只挡一类错法**，挡不住的就是装饰。M4 四条用例的判据全列在这里，
代码里不再重复（用例函数头只留"这条测什么 + 编号对应函数体顺序"）。

| 用例 | 判据 | 挡的是 |
| --- | --- | --- |
| `KT_USER_ROUNDTRIP` | 0 每台 CPU 的段描述符自检 | 选择子的**值**与描述符的**内容**是两处独立事实，只验其一都会漏（QEMU 还会把错误码的 RPL 抹掉） |
| | 0b 生效位：代码页 user+X+不可写、数据页 user+可写+不可执行、内核页**不可**用户可达 | 只验"意图 `PageFlags`"；内核页那一格是对照组，分不清"放宽一格"与"放宽整条内核映射" |
| | 0c TSS 的架构偏移按字节位置读回 | `#[repr(C, align(16))]` 把 `rsp0` 挪到偏移 8（CPU 从 4 读）⇒ 三重故障且零判据 |
| | 1 三个槽都被用户代码写过且值对上（槽先填哨兵） | "进过内核"分不清"回来的值是 1"与"根本没写、页里本来就有数" |
| | 2 未知调用号回 -1 | ABI 的错误路径变成崩溃 |
| | 3 不开窗口读用户页必须故障 | §5.1 那条 SMAP 必需项只是 CPUID 上好看 |
| | 4 从不可执行页取指 ⇒ `kills == 1`（精确）且内核继续跑 | `>= 1` 对"同一个故障每秒重演几十次"照样绿；指到指令中间又可能恰好是合法指令，抓不到东西 |
| | 5 探针登记表回干净 + `pf_stale_hits == 0` | 旧登记的"活地雷"劫持下一次无关 #PF，几百行之后才炸 |
| | 6 全程没把内核打成 39/35 | 能跑到这里本身就是判据 |
| `KT_TASK_EXIT` | 同一个固定 VA 连续装载三次成功 + `owned == 0` + 代码页不再映射 + `reap_released` 增长 | "能再装载一次"单独看会漏掉"装得上是因为它换了地址"，所以两台仪器一起数 |
| `KT_USER_POINTER` | 合法指针回真值 / 两个坏指针回 -EFAULT 且 `kills == 0`、`bad_ptrs >= 2` / `ac_active == false` / ring3 写 guard 只杀该任务并回账 / `partition_ok` / `tramp_ok` | 详见 §10.3.1 第一张表（每一格都对应一类"看着安全其实没用"的写法） |
| `KT_COPY_USER` | 跨页写由被写方逐字节核对 / 跨页读两台仪器算同一个 FNV / 超长 `TooLong` / 写代码页 `NotWritable` / 校验阶段就拒且恢复计数不动 / 恢复路径恰好搬成 8 且计数 +1 | 见 §10.3.1。**"部分长度"必须能被证明**，否则恢复机器就是一条没证据的分支 |
| `KT_SYSCALL_FAST` | 程序自己读回 `cs=0x23 ss=0x1B` / `abi` 特性位与内核读回的 `CR4` 一致 / `ping >= 1` / 快路径样本数与 warm `min` 非零 / `wait_for_boot_task` 收场（= IF 是对的） / `rsp0 == 快路径区栈顶` | 见 ADR-025 的"兑现"一节。**只读用户那一侧回来的事实**，不读内核里的常数 |

**变体与挂法（M5-g③ 新增，R50）**：判定表里「中断投递由宿主机数到」那一行跑的是**正常构建**，只多挂两个 QEMU 参数 `-d int -D build/irq-trace.log`（`do_run` 的 `extra` 形参，跑前跑后各 unlink 一次）。四把尺子的构建不挂它 ⇒ 不改变任何基线。这一挂法有一个必须知道的副作用（BACKLOG 69 实测）：`-d int` 每发中断都往宿主机写一整段寄存器现场，
写的窗口里 vCPU 被按住 ⇒ tick 间隔被拉长 ⇒ 标定可能拒（挂 trace 的 30 跑里 3 跑，`max_tick_gap/mean` = 1.59、1.75，
门槛 1.5），连带 AP 上机被拒、`t_cpu_ids_agree` 红；同一构建不挂 trace 连跑 20 跑 0 次。
**所以挂 `-d int` 的那一跑不许引用它的任何耗时数字，只引用「发了几发」。**

手工实验另有 `AURORA_QEMU_EXTRA` 环境变量那条逃生口，两者会拼接，都按空白切分（路径里有空格会被切开——本机没有，哪天有就改成传列表）。

**第二条日志通道（M5-g④ 新增，R53）**：`-trace events=<清单> -trace file=<某文件>` 数的是
设备模型自己的事件（`ahci_check_irq` / `ahci_irq_raise` / `ahci_trigger_irq` / `ahci_cmd_done` /
`ahci_port_write`）。清单由 `tools/aurora.py` 自己写（`write_events`），不留手工文件。两条实测的坑：
`-d help` 里**没有** ahci 项（事件只能走这条通道）；`-d int -D A` 与 `-trace file=B` 同给时**只落 B**，
A 不生成——所以判定表第 28 行仍然单独跑（只有 `-d int`），第 29、30 行读合并文件。
变体 `irq-sticky-pxis` 的注入点只有一颗（`ahci::clear_pxis()`），那一跑的窗口写死 6 秒
（`STORM_TIMEOUT`），解析有硬上限（`cap`），日志跑完即删：不设上限时实测 180 秒写出 7.4 GiB。

**第二台宿主机（R57，BACKLOG 75a/75b）**：WSL2 里 apt 走清华源装了 QEMU **10.2.1**（Debian 1:10.2.1+ds-1ubuntu3.3），加速器清单 `tcg/mshv/kvm`，`/dev/kvm` 可用（`KVM_GET_API_VERSION=12`）。它今天的用途是**对照**而不是判定：同一颗二进制、同一份镜像与夹具，只换 `-accel`，才能把“TCG 的产物”和“设备/规范的事实”分开量。两条通道在这种档下的形状：① `-accel kvm` 时 `-d int` **一行都不产出**（那是 TCG 的输出），判定表里靠它的 28/29/30/32 四行在 kvm 档是瞎的；② `-trace events` 挂在设备上，两档都有（AHCI `raise` 483 对 466）。⇒ 凡要在多档下都成立的判据必须走 `-trace`，或者把“这几行只在 tcg 档判”写明。Windows 侧 `-accel whpx` 不可用（我们的镜像在 OVMF PlatformPei 卡死，57 行串口 + 寄存器 dump，117 秒杀掉）。两颗 QEMU 的 `isa-debug-exit` 退出码映射**一致**（`PASS⇒33`、`FAIL⇒35`），换机器不需要动 `(val<<1)|1` 那张表。

### 12.4 稳定性指标

沿用 V1.0 的指标（连续启动成功率、内核异常次数、分配失败率、模块初始化失败率、资源泄漏数、锁竞争与死锁、故障恢复成功率、长时间稳定性），每项由验收负责人在里程碑开始时定义采集方法与阈值。**阈值不在本手册中预设**，避免无依据的数字。

### 12.4.1 性能基线（V1.2 新增，R18）

V1.1 的 §12.4 只有可靠性指标，但本手册至少四处以“性能代价”作为**架构决策的理由**：§2.4（“framekernel 有单地址空间性能”）、§2.4 与 §8.5（“不在首期承担微内核的 IPC 与性能代价”）、§15.2（兼容路线取舍）。**没有基线，这四处的判断就都是修辞。** 更要紧的是：一旦某个改动把 `DriverCtx` 的调用变贵、或让 IOMMU 刷新进了快速路径，没有任何指标会告诉我们。

因此从 M2 起采集并入库四条基线，每次里程碑存一份原始输出（数值本身随硬件与工具链变化，**不在手册里预设**；预设的是“必须存在、必须可比、劣化必须阻断合入”）：

| 编号 | 指标 | 为什么现在就要 | 首次可用 |
| --- | --- | --- | --- |
| P1 | 上下文切换（一次 `switch_context` + 必要的地址空间切换）耗时 | §7.2 的设计（“CR3 写与 TSS RSP0 更新在 Rust 侧”）是否把成本放错了地方 | M3a（**已实现**，见 ADR-020：实测 `min` 676/733 周期，注入几千周期负载后 27,708；判别只能下在 `min`，因为 `mean` 被一次 ~29 万周期的冷启动样本拉着走。M3b-1 重跑：`min` 510/686 → 注入后 28,657，地板 177，仍然"符合"） |
| P2 | `DriverCtx` 一次 MMIO 读写 / 一次 DMA 映射+撤销的往返开销 | §8.5 的“同一份驱动代码迁到用户态”到底要付多少——**没有 P2 就无法论证微内核迁移是否值得**，这正是 §2.4 那张表缺的那一列 | M5（**已实现**，ADR-030。基线 `baselines/2026-11-05T15-38-39Z-p3p4.txt`：一次 MMIO 读 `min` 554 / `mean` 2 890、一次 MMIO 写 `min` 552 / `mean` 2 494、一次 DMA 映射+撤销 `min` 37 674 / `mean` 60 324 ⇒ **建/撤一块 DMA 缓冲 ≈ 68 次寄存器读**。同构建两次的散布是 554/541 与 37 674/35 350，所以"68 倍"可以讲、"552 还是 554"不能当结论。判别不写在阈值上，写在两条量具自检：同一采样做 1 遍 vs 4 遍的 `min` 比值 >2×（实测 3.5×），以及"DMA 往返必须比一次寄存器读贵"） |
| P3 | `#PF` 处理到返回的延迟（合法补页 与 非法访问终止 两条路径分别计） | §5.6 的分支与 §6.3 的 RAII 层数是否会叠成隐性开销 | M2 |
| P4 | 启动时间到 Stage5 完成，**按 Stage 分段** | §4.1 的阶段划分是否合理；也是 §9.4 健康判定的时间基准 | M1 |
| **P7** | 系统调用往返：从进 Rust 垫片到出垫片的周期数（`samples / mean / min / max`，按 CPU 分行）。**M4-4 起按入口分两套格子**（`int 0x80` 与 `syscall`），因为 ADR-025 规定的对比是 warm `min` 与 `cold` 两格，合在一张表里就永远比不了；分流规则收成单点 `is_syscall_vector()` + `p7_record()`，两个调用点共用（⑧ 的根治） | 用户态一开放，"进内核一次的代价"就必须有自己的表。**它不能并进 P5**（见下面的分流修正） | M4-2（本表新增，依据 ADR-025） |
| **P5** | 外部中断从进桩到 `iretq` 前的延迟（`samples / mean / min / max`） | M3a 加定时器之后才发现**必须与 P3 分表**：混在一张表里实测 `samples` 2→7 而 `mean` 反而变小，两条基线同时失效。判据还包含“两台仪器数到同一个数”（asm 出口样本数 == 驱动侧各类计数之和） | M3a（本表新增，依据 ADR-020） |
| **P6** | 跨 CPU 锁等待：`wait_events / wait_spins / wait_max_cycles / wait_timeouts`，以及"没有锁时丢多少更新"的对照数 | §12.4 沿用 V1.0 的"锁竞争与死锁"一项一直只有名字没有采集方法。M3b-1 的实测：4 CPU 各 4,000 次临界区，无锁对照丢 10,204/16,000（6377 bp），加锁丢 0，`wait_events=5358`，`wait_max=232,076` 周期——这组数同时也是**看门狗阈值的依据**（阈值 2e8 周期，余量三个数量级） | M3b-1（本表新增，依据 ADR-021/ADR-020 的同一套"量具必须先能分辨"规则） |

**M3b-2b 之后：三处移动，必须一起读**（依据 ADR-024，新旧数字**不可比**）

1. **样本来源不再只有 BSP**。`P3/P5/P1` 三张表都按 CPU 分行（`p percpu cpuN: ...` 与
   `p1 percpu cpuN: ...` 各一行），AP 的本地 tick 从这一版起走异常帧，所以它进 AP 自己那一行。
   `p3 resume / p5 irq / p1 switch` 三行**仍然只报 BSP 那一行**——`tools/aurora.py bench`
   的解析格式从这个形状来，改成跨 CPU 汇总会让历史基线全部作废，也看不出是哪个核。
2. **测量边界移动了**：记账从 `isr_common` 整段搬到 `aurora_trap_entry`。
   新下界 = 进 Rust 垫片后的第一次读数（不含异常桩保存 15 个 GPR + CR2）；
   新上界 = 垫片末尾的出口记账（不含寄存器恢复与 `iretq`）。
   也就是说这两把尺子现在量"进 Rust 到出 Rust"，异常桩那 16+16 次 push/pop 落在测量之外。
   移动后的实测：`p3 resume min` 2164 → **199**、`p5 irq min` 7302 → **3486**、
   `p1 min(BSP)` 2603 → **735**。三条量具自检仍然全部"符合"
   （注入之后 min 分别到 223,824 / — / 24,942），说明移动没有把尺子弄废。
3. **P4 的容忍度：按重复性地板定，不按手感**（R28，`tools/aurora.py bench` 实测）
   同一构建连跑两次取离散度：M3b-2b 是 2.54%（三个 AP 常驻工人之前 0.85~1.24%），
   M4-1 这次是 **3.13%**，两次的观测上界 5.15%。判据说的是"劣化必须阻断合入"，
   所以阈值必须**严格大于最差一次的重复性离散度**，否则第一次回归就是误报。
   取 **8%**（≈ 最差观测值 5.15% 的 1.5 倍）作为 P4 的回归阈值，并保留
   "`bench` 里 P4 只作对照、不作判据"的现状——注入 `bench-pf-load` 的增量换算到 P4
   只有 1 bp，低于地板，这条尺子本来就分辨不了 P4 量级的变化。
   下一次里程碑交界再复算这个地板（AP 工人改成"只在被要求时忙"之后大概率会掉回去）。

4. **为什么记账非搬不可，附带一条新的数量级依据**：asm 里要按 CPU 索引这张表，就得先知道
   "我是哪个 CPU"，而那一刻 15 个 GPR 全属于被打断的任务，没有空闲寄存器可用。
   Rust 侧查槽位要读一次 LAPIC ID（UC- 的 MMIO）。四轮排除法定位到：被测区间里多三次这种读，
   就把 P1 的 min 从 735 抬到 2536 ⇒ **一次这种读在本机 QEMU 约 600 周期**。
   于是规则定为"槽位在异常入口取一次、往下传，不许在被测区间内部再查"，
   并给 §7.1 的"中断路径禁止分配/打印"补了一条可比的数量级。

**M4-2 的分流修正（P5 曾被系统调用污染，R29）**：`record_sample` 原来按
"`vector >= VEC_IRQ_BASE(32)` 进 P5，否则进 P3"分流。`int 0x80` 的向量号是 0x80，
数值上落在 ≥32 的区间里，于是**每次系统调用都被记成一次"外部中断延迟"**。
抓到它的不是代码审查，是 §12.4.1 规则 2 那条老判据——"两台仪器必须数到同一个数"：
把真 ELF 跑起来之后 `asm_samples=44 / rust_samples=41`，**差的正好是那三次调用**。
现在按**来源**分流：`VEC_SYSCALL → P7`、外部中断(≥32)→ P5、其余异常 → P3，
`timer 判据` 与 `p5 cross-check` 重新为 `agree=true`（41/41）。

**同一类错在两天后又犯了一次，这次是判据的形状救的**（R30）：分流规则我写在两处
（出口记账 `record_sample` 与换出路径 `p3_record_irq`），只改了第一处。
"两边总数相等"这条老判据只报出 `48 vs 47`（差 1，几乎看不出所以然），
把它升级成**逐向量分桶 + "各桶之和 == P5 总数"的自洽检查**之后，
现场立刻摊成 `P5=[15,...]` vs `驱动=[47,...]` —— 差的不是"一个样本"，是一整类路径。
元规则写进 ADR-027：**一条规则写在两处，就要有两处各自的判据**。

**P7 的读数与归因（两次实验，BSP）**。第一次只有 3 个样本，读数是
`min=24803 mean=47562 max=89658` —— 我当时把它写成"量级未归因，不能当基线"，
那句批评的是自己的数，而那组数本身后来也被更大的样本量推翻了：
**3 个样本的 `min` 根本不是 warm 值**。现在让夹具连打 32 次调用，
并把前四次按到达顺序存下来（`trap::p7_lead()`）：

| 读数 | 周期 |
| --- | --- |
| warm：第 4 次之后的 `min` | **182 ~ 371** |
| 第一次陷入 | 85,291 |
| 每个**新分支**的第一次 | 23,317 ~ 25,853 |
| `cold(>=10k)` 的样本数 | 3 = 分发器的分支数 |

判别实验是**换位**：把第二次调用改成与第一次同一个调用号，读数变成
`lead=[85291, 727, 25853, 23317]` —— 同分支的第二次直接落到 727，
而第三、第四次（各自第一次走的分支）仍然两万多。
`runs=1` 又独立否掉了另一条解释（"每次被换上来都冷"）：任务只被换上来一次却打出 3 个冷样本。
所以结论是：**贵的不是"陷入"，而是"某条内核代码第一次被执行"**。

这条改变了 P7 的用法，也改变了 ADR-025 的优先级：入口机制本身约 200 周期，
SYSCALL 快路径能动的那部分以此为上界；它动不了 2 万多周期的冷启动。
以后的前后对比因此**只比 `min`（warm）与 `cold` 两格，不比 `mean`**——
`mean` 被"第一次执行"支配，换了入口指令也不会明显动。

**M4-4 把这条规则兑现成两条入口的对比（同一构建，BSP）**：

| 入口 | 样本 | warm `min` | `mean` | `max` | `cold(>=10k)` | 前四次按到达顺序 |
| --- | --- | --- | --- | --- | --- | --- |
| `int 0x80` | 165 | **312** | 21,882 | 1,494,828 | 8 | （累计，含各用例第一次走分发分支） |
| `syscall` | 8 | **324** | — | — | 1 | `378,773 → 1,014 → 328 → 328` |

两句要分开说。**能确定的**：快路径的第一个样本 378,773 周期（`syscall_entry`/`sysretq` 这条路第一次被执行），
第二个就落到 1,014，第三、四个 328 —— "分支第一次执行"这条结论在**新入口**上第二次成立。
**不能确定的**：warm `min` 的 312 与 324 谁"更快"。P7 从来没量过"同构建两次的重复性地板"
（P1/P4 量过，见 `docs/testing/p4-tolerance.md`），12 周期这个差不比噪声更有资格，
所以本机结论只到这一层：**换入口没有带来可测的收益**。
由此立一条工程规矩：**以后入口类改动要用"少一次 MMIO / 少一把锁 / 少一次跨 CPU 写"来论证，不能用"更快"来论证。**

仍然没测到的：**多核中断延迟的分布形状**。现在每核有一行 P5，但样本都来自同一台 QEMU、
同一批任务；跨机只比比值（规则 2）。真机上的分布、以及 AP 上故障会写哪张表这类问题，
仍挂在 BACKLOG。

三条规则：

1. **回归即阻断**：任一指标劣化超过评审确定的容忍度，合入需 ADR 说明原因（与 §1.3 第 4 条“unsafe 增长需批准”同构）。
2. **可比性优先于绝对值**（M3a 先给出一条实测地板）：同一构建连跑两次，P4 的离散度约 **1%–3%**；
   而一次已知注入负载只让 P4 动 0.65% —— **小于离散度地板的效应不能用 P4 判**，
   所以判别下在 P3/P5 的 `min` 上（实测 1094→8156、1383→230562 两个量级），P4 只作对照。
   以后定容忍度必须从这条地板往上定。同一 CI 镜像、同一 QEMU 参数、同一 CPU 拓扑（§3.5 已固定 `-smp 4 -m 512M`），并记录 host CPU 型号；跨机对比只能看比值。**每条指标必须同时记录采样次数与离散度**，否则一次抖动就会被读成回归。
3. **量具先验证能分辨**：P1/P2 上线前先做一组“已知不同”的样本（例如人为在 `switch_context` 前后插一次额外 `invlpg`），确认基线数值确实动了，再开始用它判回归。

外部参照（用于校准直觉，**不是本项目目标**）：公开微基准里微内核 IPC 往返为 seL4 986 cycles、Fiasco.OC 2717、Zircon 8157 \[V5\]；SPDK 用户态 NVMe 驱动每核 IOPS 比内核驱动高 6–10 倍 \[V6\]（说明“搬到用户态”并非只有代价）；Linux 的 KPTI 代价为每次内核 entry/exit 约 100 cycles、每进程多 4KiB 页表，syscall 密集负载实测 2%–7%+ \[V7\]（说明任何缓解机制都应在 P 系列基线里留一条对应的对比项）。

#### 12.4.1.1 计数表被跨 CPU 读时的发布顺序（V1.2，R35）

P3/P5/P7 这些格子**只由它自己的 CPU 写**（写的时候本 CPU IF=0），别的 CPU 只读来汇总。
读一方要看的不是单个格子而是一组，所以发布顺序是有意的，写死在 `StatsRow` 的注释里也不够，立为规则：

1. **写方**：先写 `sum / last / min / max`，**最后**才把 `count` 加一，并且那一次用 `Release`。
2. **读方**：先用 `Acquire` 读 `count`，再读其余格子。
3. 为什么必须这样：反过来的话，读方可能看见"总数已经 +1、但那一个样本的 sum/min 还没写完"，
   于是 `mean = sum / count` 的分母来自一个还没成形的样本——**出来的数看着完全正常**。
4. 旧的全局单份版本不需要这套顺序（只有本 CPU 读，读到的一定是自己刚写的）；
   **M3b-2b 让"别的 CPU 也来读"这件事第一次成立**，这条顺序就变成必需的了。
5. 这条属于 §12.4.1 规则 2（跨机只比值）的同一族：它管的是**同一台机器内跨 CPU 读**的可信度。

## 12.4.2 未预设的阈值清单

以下数字**有意留空**，由各里程碑验收负责人在开始时定义并写进 `docs/testing/`，评审时逐条确认“这把尺子能分辨”：§12.4 八项可靠性阈值、§12.3 的 N 次重启成功率、§9.6 看门狗周期与最坏持锁时长（见 §7.1 R16）、§11.3 漏洞响应 SLA、§12.4.1 的容忍度、§15.5 各渠道支持周期。

## 13 真机必备能力（对 V1.0 的补全）

| 能力 | 要点 | 待决 |
| --- | --- | --- |
| ACPI 固定布局表 | RSDP/XSDT 校验与 MADT/FADT/MCFG/DMAR-IVRS 解析；**M3b 与 §8.4 的硬前置** | ADR-012a（M2 前）：结构定义自研，无外部依赖 |
| ACPI AML 解释器 | DSDT/SSDT 命名空间、`_CRS`/`_PSx`、热插拔、温控 | ADR-012b（M5 前）：自研最小实现 vs 复用现有库（**受 ADR-009a 约束**） \[R2\] |
| 关机 / 重启 | ACPI 复位寄存器、备用方式、最后手段 | 真机验证 |
| 睡眠 / 休眠 | S3/S4 状态保存与恢复 | M7 之后 |
| 时钟 | LAPIC 定时器、TSC（需检测是否恒定）、HPET 校准 | — |
| APIC | xAPIC/x2APIC、IOAPIC、MSI/MSI-X | — |
| SMP | 见下方 **SMP 待核实清单（R20）**；TLB shootdown 见 §6.6 | M3b（**清单必须在 M2 结束前关闭**） |
| 混合核心 | 性能核/能效核识别与调度提示 | M7 |
| USB | xHCI + HID（真机键鼠基本都是 USB，不能推迟到“不做”） | M7 |
| UEFI 运行时服务 | 时间、变量、复位 | 与 ADR-011 联动 |
| 桥接调试 | 真机常无串口：需 framebuffer 日志 + 持久化 crash dump + 可选网络日志 | M5 |

### 13.1 SMP 待核实清单（V1.2 新增，R20）

> **V1.2 R22（M2-c）更新**：R20 当时这份清单只能挂“待核实”，因为 SMP 章节取不到原文。现已从固定版本 11.4.1 的 `include/limine.h` / `PROTOCOL.md` 逐字核对，并且**真的发出了 MP 请求跑通**（`KT_MP_VS_MADT`）——下表把“待核实”换成了结论与依据。剩下的只有第 4 项，那是决策不是事实。

V1.1 把这一行写成“通过 Limine 的多处理器请求启动 AP”。**这句话本身可能是对的，但本版本无法为它背书**：上一轮逐字核对 `PROTOCOL.md` 时覆盖的是 HHDM 基址、PAT 缓存属性、交接时的寄存器与中断控制器状态、base revision 协商这几项，**SMP 章节未核对**；本轮尝试抓取该章节失败（两条分支的 raw 地址均返回 404）。因此这里不写结论，只写必须在 M2 结束前关闭的问题：

| # | 必须查清的事 | 现在的结论（M2-c 关闭） | 依据 |
| --- | --- | --- | --- |
| 1 | SMP 请求需要哪个**最低 base revision**，以及支持性判定口径 | MP 请求是**独立请求**（自带 ID 与 revision），不是靠 base revision 门槛；不支持时响应指针为空，`collect()` 把它当 `Option` 处理而不是当成 0 个核 | 固定版本 11.4.1 的 `include/limine.h` + `kernel/src/limine.rs::read_mp` |
| 2 | AP 的**入口与初始状态** | 与 BSP 的 Machine State 相同；入口收到 `RDI = *limine_mp_info`；栈由 bootloader 提供（大小跟 Stack Size 请求），**位于 bootloader-reclaimable 区** | 原文 + **ADR-019**（这条直接决定那块内存能不能回收） |
| 3 | **16 位 trampoline 与低 1MiB 区域的归属** | **bootloader 自备**。内核镜像里没有任何 16 位代码，4 个核仍被引导并停住 | 实测：`limine: mp present cpus=4` |
| 4 | AP 启动**失败**时的语义 | **已决：ADR-022**。三层——前置不成立 / 部分核起不来 / 全部正常，分别是 `FAIL(35)` 带原因、**降级继续跑但用例判红**、`PASS(33)` 带数字。既不升 L4（少一个核不是"不可恢复的状态"）也不是 `BootInvalid(37)`（那是"这次启动根本不可判定"）。可观察面：`released/refused/ready_timeout/timer_failed/id_mismatch/lapic_failed/isr_depth_stuck` 七个计数器 | ADR-022 + 第一次兑现就是自己写错的标定（`released=3 online_ap=0 timer_failed=3` → 用例红，而不是静默单核跑绿） |
| 5 | LAPIC id 与 MADT 的对应关系由谁提供 | **两边都给，且必须互相印证**：Limine 的 `lapic_id`/`processor_id` 自称取自 MADT；本机实测 MP `[0,1,2,3]` 全部落在 MADT 使能清单内，`bsp_lapic_id=0` 也在其中。**M3b-1 加了第三个来源**：每个 CPU 自己读回的 LAPIC 寄存器 —— `cpu ids: checked=4 mismatches=0`（`KT_CPU_IDS`），并且要求 `unmatched_self_lookups_delta=0`，否则说明有 CPU 在用没登记过的 id 跑 | 用例 `KT_MP_VS_MADT`（两台仪器对账）+ `KT_CPU_IDS`（三台仪器对账） |

**规则（M2-c 之后）**：第 1/2/3/5 项已随 **ADR-014（状态：已核实）** 关闭，其代价与副作用记在 **ADR-019**；第 4 项已随 **ADR-022** 关闭（M3b-1）。任何“AP 由 Limine 直接带起”的表述现在才允许出现在 §4.1 的 Stage3——注意它带的代价是 bootloader-reclaimable 区**不能提前回收**（实测扣 45 MiB）。

**第 2 项在 M3b-1 被实测细化了一次**：AP 确实"与 BSP 交接时状态相同"，其中包括
**页表还是 bootloader 的那一份**。所以入口例程必须自己 `mov cr3`，而顺序只能是
"读 `extra_argument` → 读栈顶与 PML4 → 换 `rsp` → 换 `cr3` → `call`"：先换表再换栈的话，
`call` 会把返回地址压进一张只有旧表认得的栈，而那一帧随时可能被我们分配给别人。
AP 的实际入口栈是内核自己用 VMM 建的（5 页保留、最低一页永不映射），
由 `KT_AP_ABI` 逐槽位核对"栈顶页映射着、guard 页未映射、写入的槽位号与期望 id 都与登记表一致"。

**跨 CPU 的结论有一条隐含前提：时钟标定得成功**（M5-g④，BACKLOG 69 与 71）。链路是
`clock::from_pit_window` 拒了（`MissedTicks`）⇒ `smp` 的 AP 上机被拒（`ClockNotCalibrated`）⇒
`t_cpu_ids_agree` 红。而标定读的是 tick 之间的间隔，**宿主机把 vCPU 按住就会拉长它**：
挂 `-d int` 的 30 跑里 3 跑被拒（比值 1.59、1.75，门槛 1.5），不挂 trace 的 20 跑 0 次。
所以"哪个核上机了""几个核在跑"这类结论，在任何一次让宿主机忙于写日志的跑里都要重新看一遍，
而那一跑里的耗时数字一概不引用（§12.3.1 同条）。

更一般的那半是：**窗口长度必须是时间单位**。上面那条链路在第二台宿主机（WSL 的 QEMU 10.2.1，只换 `-accel kvm`）上是**当场断的**——标定窗口原来按自旋轮数封界，而“一轮值多少时间”是宿主机的函数：同一个 200,003,016 cycles 的上界，tcg 档走 3609~3936 轮、kvm 档走 7830~8913 轮（16 跑实测，`build/_kvm_repeat.txt`）。现在上界由 `clock::window_cycles()` 从 PIT 的 10.00016 ms 与 TSC 区间 `[100 MHz, 5 GHz]` 的最坏端点推出来，样本数与判定不再取决于宿主机的执行速度（ADR-036，BACKLOG 75c/75d）。
标定的**估计器**也是这轮换掉的：`总 cycles ÷ tick 数` 因为窗口两端各切掉一段不完整的间隔而系统性偏高，改成 ISR 自己量的**相邻间隔均值**（`sum/n`，n≥3）。对表用与虚机无关的第三个仪器——WSL 里 Linux 自己标的 `dmesg: tsc: Detected 3187.201 MHz`：16 跑实测旧估计器 **+4.59 %**，新估计器 tcg −0.76 %~−0.03 %、kvm −0.15 %~+0.15 %。µs 那一列的标尺因此从 2026-11-06 起挪了 −4.6 %（同一批 cycles 换出的 µs 大 4.8 %）；已 grep 核对，仓库文档里没有引用过 µs 绝对值。

## 14 修订后的开发路线

调整要点：隔离与诊断提前至 M2；SMP 从 M3 拆出；用户态 + capability 提前到 M4；设备与真机独立成阶段。

| 里程碑 | 内容 | 验收 |
| --- | --- | --- |
| M0 工程基础 | 仓库、固定工具链、CI、ADR 基线、**ADR-009a（许可证白名单）**、crate 清单登记（§2.5） | 一条命令完成构建、镜像、QEMU 启动；**§2.5 树与 `cargo metadata` 一致** |
| M1 最小启动 | 串口、日志、CPU 检测、panic 框架、QEMU 测试运行器、**门禁负样本（§12.3 R19）**、**ADR-011 临时策略落地**、`check-lints-wired`/`check-unsafe`/`check-nofloat` 三条接入 | 重复启动稳定，测试结果可自动判定；**每条门禁至少变红过一次** |
| M2 CPU、异常、内存 | GDT/IDT/TSS、PMM/VMM/堆、**`Mapping` 所有权改造（§6.3 R13）**、资源登记、故障注入框架、诊断、**ACPI 固定布局表（§13 R11）**、**P3/P4 基线（§12.4.1）** | 分配/释放/映射正确，预期异常可诊断；**DoubleFree 用例必须升 L4**。<br>**M2-a/b/c 已交付**：页表接管 + 所有权、内核堆 + `GlobalAlloc` + VA 保留登记、资源台账、5 个注入构建、ACPI 固定布局（RSDP/XSDT/FADT/MADT/MCFG，本机实测 6 张表全过校验）、P3/P4 基线与量具自检、MP 请求与 MADT 对账。**M2 未完**：AML（M5b 按计划）、IOMMU 表内容（DMAR 缺席于本机，见 BACKLOG）、`split_huge`、台账逐句柄追踪 |
| M3a 单核线程与调度 | 内核线程、上下文切换、抢占调度、锁与 lockdep（含 §7.1 R16 的重入检测）、**P1 基线** | 多线程稳定并发；**重入检测的粒度从 CPU 切到线程，两侧各一条用例** |
| M3b SMP | **MADT 解析（ADR-012a 已就绪）**、AP 启动（§13.1 清单已关闭）、TLB shootdown、每 CPU 队列 | 多核压力测试通过；**“部分 AP 起不来”的降级语义有 ADR**。<br>**M3b 已交付（三段）**：① ADR-021（IF 归 CPU，配 `fault-if-carriage` 负样本，实测 HANG）+ ADR-022（降级语义）+ per-CPU 描述符表与带 guard 的异常栈 + AP 释放（协议规定的 release 原子写）+ 每 CPU 本地 APIC 定时器（计数率按 TSC 实测标定）+ 跨 CPU 锁竞争/有界自旋/看门狗（P6）；② ADR-023（§6.6 shootdown：归还物理页前等齐回执、处理方不拿锁、收不齐升 L4，负样本实测 39）+ ADR-019 的显式回收（11,764 帧 = 45 MiB 回账）；③ ADR-024（每 CPU 运行队列 + AP 跑自己的调度器 + 计时表 per-CPU，"一次 UC- 的 LAPIC 读 ≈600 周期"由四轮排除法定位）。本机 4 vCPU 实测：`released=3 online=3 refused=0`、`switches=[27,43,43,42]`、`bad_owner=0 misfiled=0`、`unlocked_lost=10204 / locked_lost=0 / wait_events=5358`、`shootdown requests=2 timeouts=0`；判定矩阵 9 行全"符合"、37/37 用例绿、`bench` 四道门禁符合。<br>**M3b 遗留（不阻塞 M4）**：任务迁移（要同步与 per-AS cpumask 一起设计）、`schedule()` 主动让出（`loads_closed` 那条路径的触发源）、P4 容忍度阈值未按多核重设（离散度从 0.85~1.24% 涨到 2.86~5.15%）、QEMU 观测不到的 TLB 陈旧性等真机项（ADR-023） |
| M4 用户态闭环 | syscall、capability、ELF 加载、用户指针拷贝、第一个用户进程、**SMEP/SMAP 为必需（R17）**、**§5.3 R14 第 2 条（swapgs 窗口）已定** | 用户程序运行，非法访问被拒绝（**在 SMEP/SMAP 开启的硬件上判定**）。<br>**M4-1 已交付（R28，ADR-025/ADR-026）**：入口取 `int 0x80`（唯一一条 DPL3 的门，硬件按 `TSS.rsp0` 换栈 ⇒ 这条路径不需要 GS，§5.3 R14 第 2 条那个窗口在此**不存在**，留给 M4-2 的 SYSCALL 一起决定）；用户页住进低半区独立窗口；SMEP/SMAP 成为启动判定并有负样本。实测：`served=3 unknown=1 kills=1 slots=[Some(1),Some(42),Some(18446744073709551615)] smap_blocks_kernel_read=true bad_state=Done`（**这条 `bad_state` 读数 M4-3 之后变成 `Free`**：被杀的任务现在会走完"登记待回收 → 抢占点归化"，见 ADR-028）——三次往返、参数与返回穿过边界、未知调用号回 `-1`、**从不可执行页取指只杀那个任务而内核继续跑**。<br>**M4-2 前两段已交付（R29，§10.7 + ADR-026）**：① ELF64 容器解析（`KT_ELF`：正样本 + 22 条负样本各命中一格拒绝码，夹具是 `rustc`/`lld` 真产物，不是手编字节）；② 装进用户半区跑起来（`KT_ELF_LOAD`：`segs=3 pages=3`、四个结果槽 `magic/ping/add/unk/rodata` 全对、生效位两条 + guard 页未映射 + P7 样本数三条仪器）。P5 曾被 `int 0x80` 污染，由"两台仪器必须数到同一个数"抓出并分流成 P7（§12.4.1）。<br>**M4 未完**：capability 句柄（§10.4）、`copy_*_user` 与用户指针校验（M4-3，§10.3；**逐页校验、跨页拷贝与窗口内可恢复故障都已在 M4-3 两段落地，见 §10.3.1；仍欠的是 `UserSlice` 封装与一段缓冲区两次调用之间的原子性**）、~~SYSCALL 快路径与 GS 窗口（ADR-025）~~ **已在 M4-4 交付**、P7 的归因已完成（warm `min=182`，贵的是"分支第一次执行"，见 §12.4.1 与 ADR-025）、<br>**M4-2 第三段已交付（R30，ADR-027）**：`SYS_EXIT` + 任务名下映射的延迟回收 + `Mapping::drop` 连 VA 保留一起放手。判据 `KT_TASK_EXIT` 三轮：旁观者结束 / 自己退出 / 第三次重装同一个固定 VA —— "装得上"本身就是回收发生的证据，`reservations 16→16`、`live_of(MOD_USER) 0→0`、`reap_released 5→15`。**`MAX_TASKS` 6→8 那条临时措施从此只是容量，不再是在躲回收缺失**。<br>**M4-3 第一段已交付（R31，§10.3.1 + ADR-028）**：`KT_USER_POINTER` 四档——合法指针读出真值（`peek ok=0xa7`）、内核地址与未映射地址各回 `-EFAULT` 且任务活着（`bad_ptrs=2 kills=0`）、`ac_active=false` 独立读回 rflags.AC、ring3 越界写自己的 guard 页 ⇒ `kills=1`（精确）+ 槽位 `Free` + 页与 VA 保留回账。顺带把用户地址窗口切成**镜像区/动态区**（那次 `VaTaken` 的根因是"固定地址与随机地址共用一条前沿"，成败由用例的链接顺序决定），并把 kill 的落脚页改成内核自己拥有的一页 `USER_RX`（`TRAMPOLINE_VA`）——容器任务的故障归属不再依赖测试脚手架。<br>**M4-3 第二段已交付（R32，§10.3.1）**：`KT_COPY_USER` 七格——内核→用户跨页写 512 字节由**程序逐字节**核对（`buf_ok=1 buf_n=512`），用户→内核跨页读由两台仪器各算一遍 FNV-1a 且必须相等，超长回 `TooLong`（**拒绝而不是取小**），往代码页写回 `NotWritable`，第 2 页没映射的区间在校验阶段就回 `NotMapped` 且恢复计数不动，而恢复路径本身用 `probe_copy_from` 走一次真故障：`搬成=8 接住次数=1 ac=false 登记干净=true`。这一段最贵的收获是抓出一条**注释在承诺代码没做的事**：`peek_u64` 写着"校验与读在同一次持锁期内"，代码却是锁外校验、锁内读（单 CPU 用例永远测不出来）——现在四条拷贝路径一律锁内校验、锁内搬。<br>**M4 三条容量/ABI 欠账已清（R33）**：①装载改成**按段连续分配**（每段贪心切成 2 的幂的块；向上取整会多占 VA，于是下一条段撞 `VaTaken`——ADR-028 那条病因的第三种形态），夹具的映射数 `7 → 6 / 8`，判据是"余量 ≥ 2"而不是"等于 6"；②**错误码表冻结**：`-1=EINVAL / -2=EFAULT / -3=ETOOLONG`，每个号各有一条真实调用作证（`-3` 由程序故意拿 `COPY_MAX+1` 打一次，实测 `buf_err=-3` 且 `kills=0`），且**不**预先摆出还没有返回分支的码；③内核里**不再存在"不经校验就开 SMAP 窗口"的入口**（`read_slot`/`read_at`/`write_at` 全改走带校验的拷贝，`stac`/`clac` 从 Rust 的 `extern` 声明里删掉，只剩 asm 内部复用），白捡一条硬保证：读一个已回收的 VA 现在返回 `None` 而不是把整机打到 39。<br>**M4-4 已交付（R34，ADR-025 的"兑现"一节）**：
`syscall`/`sysret` 快路径装上，GS 窗口按"入口第一条就是 `swapgs`、窗口内不访存不碰段寄存器"处理，
安全性论证落在一条可核对的事实上（本内核零处依赖 `gs:`）。判据全部读**用户那一侧回来**的事实：
`KT_SYSCALL_FAST` 实测 `cs=0x23 ss=0x1B`（硬件从 `STAR[63:48]` 算出的选择子）、`abi=0x40007`（major/minor/特性位，
其中 fast/smap/smep 三位与内核读回的 `CR4` 交叉核对）、`efer=0xd01`（SCE=1）、`ping=34`（返回值穿过边界）、
`rsp0 == 快路径区的栈顶`（一个写入点喂两个消费者，仍然交叉核对）、`wait_for_boot_task` 能收场（这条本身就是 IF 判据：
出口写 IF=0 的话任务就关着中断死转，M4-1 实测过那个形状）。P7 从此按入口分两套格子，
本机对比结果见 §12.4.1：**换入口没有可测收益**（warm `min` 312 vs 324，而 P7 没有重复性地板） |
| M5 设备与存储 | PCI（MCFG/ECAM）、IOMMU、virtio、驱动生命周期与隔离、NVMe、VFS/initramfs/FAT32、**P2 基线**、**ADR-009b 若涉及外部贡献者则在此之前** | 存储读写，驱动故障可重置或隔离 <br>**M5-a 已交付（R36，§8.7.1）**：`hw::MmioRegion` + `mm::map_mmio` + ECAM/CAM 两条配置路径与枚举表。ECAM 与 CAM 读同一 DWORD 实测一致；MMIO 映射不动页框账；边界与对齐检查正反两向都有判据。`0x08` 的 class 解码**未定**（不猜，见 §8.7.1）。<br>**M5-a 收尾**：class 解码表由 `KT_PCI` 的六行"已知设备 ⇒ 已知类别"钉住（要求 ≥4 台同时成立），`first_of_class()` 从此才有依据。<br>**M5-b/c 已交付（ADR-029）**：ABAR 尺寸探测 → HBA 认领与端口枚举 → 第一条 DMA 读 → 257 扇区长读钉住扇区数高字节 → 第二块 130 GiB qcow2 钉住 LBA 字节 8 → 写方向（`WRITE DMA EXT`）＋宿主机 `qemu-io` 内容对账。**"存储读写"这一半验收句已成立**；每台设备都自己作证寄存器偏移（driver-register-witnesses 那条经验的落地形状）。<br>**M5-d 已交付**：§8.2 的状态机在存储上的形状——错误分类（卡住才重置、干净错误只计数）、按口重试预算 3、超预算隔离且隔离后一个寄存器不碰、粒度是端口（引导口 `resets=0`）。附带三条本机实测写进 ADR-029：**越界读不报错**、**带错完成时 `PxCI` 不释放**、**恢复结束时端口里可能还挂着旧命令**。<br>**M5-e 已交付（ADR-030）**：`DriverCtx` 能力句柄表（槽号+世代号、四种拒绝形状、DMA 不交出切片）＋ AHCI 全量改走这条路（驱动侧数据路径上的 `unsafe` 清零）＋ 新门禁 `check-driver-ctx`（6 道）＋ **P2 基线**。<br>**M5-f① 已交付**：virtio-blk 的现场取证（能力链定寄存器位置、字段按自身宽度访问、容量与宿主机对账），矩阵从 16 行到 **17 行**。三条实测进了 BACKLOG ㊵㊶㊷，其中 ㊷ 是本节那条"要用类别先钉解码表"的续集：**多挂一台存储控制器之后"第一台 class 0x01"不再是 AHCI**，认领必须按三件套（`01/06/01`）找。<br>**M5-f② 已交付（ADR-030 的 M5-f② 补记，R43）**：virtqueue 建起来并跑通第一条 I/O —— split queue 三段环（描述符/avail/used）加请求头、数据、状态全在**一段 `alloc_dma` 的连续区**里按固定偏移切，`check-driver-ctx` 把 `virtio.rs` 一起扫且为绿；读扇区 0 得到夹具图案、写扇区 8 再读回的哈希与**宿主机 qemu-io 读回来的哈希**同数（矩阵第 22 行）。四条现场事实：`queue_desc/driver/device` 三格**确实能回读**（以前只是"规范说在"，所以代码存成 `Option<bool>` 而不是断言）、`queue_enable` 读回 1、`notify=0x3000` 配 `multiplier=4`、一条读请求的 `used.len=513`（设备把数据 512 与状态 1 都算进长度）。顺带补了 `DriverCtx` 的 `dma_read16`/`dma_write16`/`dma_copy_in`——不是为了对称：描述符的 `flags`/`next` 与 avail 的 `idx` 都是 `u16`，用两次字节访问拼会造出设备可能看见的中间态。<br>**M5-g① 已交付（BACKLOG 65，变体 `irq-probe`，只取证不改路径）**：每台设备的 MSI/MSI-X 块与 INTx pin/line 全读回来了——AHCI `00:1f.2` 有 MSI（`@0x80`、`en=0`、`mmc=0` ⇒ 一条向量、64 位地址能力、无 per-vector masking）而无 MSI-X；两台 virtio 只有 MSI-X（**旧读数作废（R57，BACKLOG 75h）**：当时 `pci.rs` 从能力头 `+8/+12` 读表/PBA，而 MSI-X 结构里表 DWORD 在 `cap+4`、PBA 在 `cap+8`——把 PBA 当成了表，症状是“表条目读回来全零”。修好后设备自己作证：表 `BIR=1 偏移=0x0`、PBA `0x800`、条目 5，写 `(0xfee00000,0,0x22)` 逐字读回。原句是 表在 `BIR=1` 偏移 `0x800`，条目 5/4）；SMBus `hops=0`（没有能力表）。OVMF **把 GSI 写进了设备的 Interrupt Line**（`0x0a`/`0x0b`）却**没有编程对应的 RTE**（`lo=0x00010000`：向量 0、屏蔽 1、触发位是复位值的 0）；IOAPIC 24 条表项、`gsi_base=0`。⇒ 三条结论：①INTx 今天可用、**不需要 `_PRT`/AML**（原以为要等 M5b，这一支划掉）；②但这台机器上 INTx 是**共享线**（GSI 10 挂 AHCI+SMBus，GSI 11 挂两台 virtio）⇒ 走它就必须做归属判定与先服务后 EOI，且触发位要显式置电平；③第一颗认领的中断走 **AHCI 的 MSI**（向量与目的地我们自己写、不涉共享线），MSI 那两个格式常数按「写下去读回来 → 设备真发一发 → `-d int` 数到同一次投递」定，不凭记忆写。`KT_IRQ_PROBE` 挂在 feature 后面 ⇒ 正常构建仍 52 条用例、四把尺子的构建不受影响。<br>**M5-g② 已交付（ADR-034，R49，BACKLOG 66）**：核内认领表 + `DriverCtx::request_irq` 等四颗方法 + AHCI 的一颗 MSI（`向量=0x21`，消息由核内算并写进设备 `@0x80`，读回逐字一致）+ 顶半只读 `PxIS`/W1C/立旗 + `wait_settled` 三本账。`KT_IRQ_AHCI` 六格全过，`ktests` 52 → **53**；两处由判据抓出的自身错误记在 66a/66b（接入必须独立于认领；中断只叫醒不放行）。<br>**M5-g④ 已交付（BACKLOG 71，R53）**：判定矩阵 28 → **30 行**。第 29 行把 68 那条"只有边沿才发消息"
从对应关系升成判据（方向式：`投递 ≤ 边沿`、`被吸收 ≥ 20`、解析自洽；实测 `raise=483 边沿=6 被吸收=477 投递=4`）；
第 30 行是新变体 `irq-sticky-pxis`（`clear_pxis` 一处开关），期望 `HANG(-1)`，实测
`raise == 边沿 == 投递 == 106,753` ⇒ 同一模型从反方向被夹住。三条事实必须点名：
①**先清端口 `PxIS` 再清全局 `IS` 是风暴开关**，不清源时 180 秒造出 4,747,919 条消息；
②**容差按机制给而不是按样本**（照一个样本写的 `abs(边沿−投递)<=1` 换个跑就假红）；
③仪器自身的账由 `instrument_caused_red` 管：只认 `t_cpu_ids_agree` + `MissedTicks` 且比值在 [1.5, 2.0)，
六个维度对不上绝不放行——24 连跑里那条 `t_task_exit` 的偶发就是被它正确拒绝的（待办挂 71e）。<br>**M5-g③ 已交付（BACKLOG 67，R50）**：判定矩阵第 **28** 行——跑正常构建挂 `-d int -D build/irq-trace.log`，宿主机自己数投递并与内核两本账对：区间内且 `pc` 落在内核窗口的投递数 == `irq1..15`（实测 4==4）、`by_cpu()[0]` == 宿主机数到的、非 BSP 那些必须为 0、`cpl` 全 0、`窗口外` 必须为 0、且投递数 ≥ 1（相等而两边都是 0 不算过）。先量格式再写解析：前导字段单调递增到 1273 而 `-smp 4` ⇒ **它不是 CPU 编号**（但 `SP` 高位分辨得出 BSP／AP，见 BACKLOG 68e），所以目的地那一维以内核的 `irq::by_cpu()` 为权威、由核外用总数/cpl/pc 约束。三条变异各自红且各自点名：删 trace 里两发（只动核外）⇒ 2 vs 4；目的地写成 1 号 CPU ⇒ `[0, 389, 0…]`（67c 那一跑）两条红话 + 一个风暴现场（4 发涨到 **387~392 发**，重放五次是 389、392、390、387、387；机制由 R51 查明：边沿吸收被关掉，不是设备重投）；放宽向量过滤 ⇒ 896 vs 4 且暴露 `窗口外=381`（证明那一维不是摆设）。内核侧为它多打 `按CPU=[…]`：串口量 +40 B（149,721~149,724），P4 地板 0.15 %。<br>**M5 未完**：MSI-X（virtio 的**旧读数作废（R57，BACKLOG 75h）**：当时 `pci.rs` 从能力头 `+8/+12` 读表/PBA，而 MSI-X 结构里表 DWORD 在 `cap+4`、PBA 在 `cap+8`——把 PBA 当成了表，症状是“表条目读回来全零”。修好后设备自己作证：表 `BIR=1 偏移=0x0`、PBA `0x800`、条目 5，写 `(0xfee00000,0,0x22)` 逐字读回。原句是 表在 `BIR=1` 偏移 `0x800`）与共享电平的 INTx 两条路仍未走；中断亲和性半格已交付（R55/73：能动、能判归属；缺静默与搬运；服务侧按 CPU 的分账已由 R56 交付，同时测出「搬目的地 = 把叫醒改成赛跑」）；ISR 里 `request_irq` 被拒那一格仍只有守卫没有判据；投递风暴的机制与判据都已交付（R51 查明、R53 落成矩阵第 29、30 行；不清源那一侧的形状与 68 的推断相反，见 BACKLOG 71）、第 28 行的仪器链处置已定（R53：窄化放行 + 读数点名）、IOMMU 表内容（本机 DMAR 缺席）、NVMe、VFS/initramfs/FAT32、`DriverCtx` 还剩 `set_timer`/`log` 两个方法没兑现（`request_irq` 已由 M5-g② 交付，见 §8.5.1）、句柄表容量写死 8+8（BACKLOG 的 M5-e 清单）、virtio 的长请求与间接描述符（今天一次一个扇区、单链） |
| M5b ACPI AML 与电源 | AML 解释器（ADR-012b）、`_PSx`、睡眠/休眠 | **无 AML 时“不提供睡眠”必须在 `sys_abi_info()` 特性位可见，不得静默失败** |
| M6 可靠性 | 启动循环保护、A/B 回滚、crash dump 持久化、watchdog、fuzz、**ADR-011 正式方案** | 注入故障后系统可自动恢复或进入安全模式 <br>**M6-a① 已交付（ADR-031）**：§9.4/§9.5/§9.7 共同需要的持久落点——8 槽 × 512 字节的状态区（`size` 首字段 + magic + version + kind + seq + FNV-1a 校验和、轮转写、取最新有效、全坏则重来），"读不到"只有 `Err` 一个出口，绝不"当 0 看"。两条新门禁：`check-state-window`（内核与镜像生成器两份常量对账）与核外的 `check_state_record`（宿主机按同一格式重解那条记录），各自证过一次能红 <br>**M6-a② 已交付（§9.4.1，R38）**：`boot_guard` 的决策落地，"先计数再进可能崩溃的路径"与"读不到按最坏情况"都有能变红的判据；**同一份镜像不重建连跑四遍**实测连续失败 `[0,1,2,3]`、模式 `Normal/Normal/Normal/Safe`，这是矩阵的第 18 行（它的实际值是**四遍的序列**，序列不对报 `SEQ-BROKEN` 而不是 `FAIL`）；安全模式的后果实测到"AHCI 起口数 6→1"，模式经 `sys_abi_info()` 的 `F_SAFE_MODE` 位可见；健康启动（用例全绿且表非空）把计数清回 0。第三道自证：新增 `check-matrix-wiring` 抓到判定表里两行**共用同一份串口日志变量**（"泄漏注入被检出"因此静默变成第 18 行的副本，两行恰好都期望 `FAIL(35)` ⇒ 矩阵照样 18/18 符合），门禁从 7 道到 **8 道** <br>**M6-a③ 已交付（§9.4.1，R39）**：安全模式**出得来**。这个现场以前只能靠偶发撞、撞上还出不来（实测一次偶发把机器锁在 `Safe` 里连红 9 遍），现在由 `force_boot_state` 把"已连续失败 99 次"做到盘上，矩阵第 19 行验三遍序列（强制 Safe ⇒ 那一遍健康清零 ⇒ 下一遍回 Normal），序列不对报 `SEQ-BROKEN`。顺带修掉两条把偶发放大的故障：①健康判据原来拿**正常模式的基线**比安全模式现场 ⇒ 降级态永远不算健康 ⇒ 一次抖动=永久锁死；②本机 QEMU **偶发吞掉一次 `PxCI` 发射**（写 1 读回 0，实测 24 连跑抓到 1 次），而这条路径的下游就是 §9.4 的"读不到⇒最坏情况"——驱动现在 `recover` 之后重发一次，第二次仍被吞才交 `Err`（ADR-029 的"M6-a③ 补"）。另一条同形状的量的问题：`t_copy_user` 原来用 `served()` 当"程序跑完了"，而那个计数在 `syscall_dispatch` **入口**就 +1 ⇒ 红的那遍与绿的那遍只差一格（`buf_err=Some(0)` 对 `Some(-3)`），现在改成有界等那一格落定并把等了几轮打出来。<br>**M6-b① 已交付（ADR-031 补记，BACKLOG 52）**：`seq` 改成**整块区**全局单调，`read(kind)`/`write(kind,…)` 按种类分家，`KIND_CRASH=2` 落定——这是 §9.7 与 §9.5 共用这块区的硬前置（各数各的 `seq` 时"谁新"没有定义，而下一个槽写哪儿也由它决定）。`KT_STATE_STORE` 加四格，并用**两条互补变异**各自证过能红：把写的依据换回"本种类自己那条"⇒ `seq全局单调(1→2→2)=false`；把种类过滤作废 ⇒ "只有一种时另一种读不到"红而 `seq` 那条照常 true。<br>**M6-b② 已交付（§9.7.1，R40）**：崩溃摘要在停机前落进这块区（`kind=2`，字段只有向量/CPU/RIP），下次启动读回来；写入收口在 `exit::finish(ExceptionFatal)` 这一颗唯一出口上，写不进去只降级不二次故障（实测注入非法命令码 ⇒ `Io(BadCompletion {status:0x41, error:0x04})`）。判据是 `KT_CRASH` 七格 + 矩阵第 20 行（同一变体连跑两遍，第二遍读回的槽/`seq`/三样字段与第一遍落盘那行逐字段相同，宿主机按同一套偏移重解亦然）。**§9.7 那张完整 `CrashRecord`（调用栈 32 项、最近日志、线程/进程/模块号、错误码）没有落**：它超出一个槽，要走 `VERSION=2` 的续块并同步扩大校验和覆盖范围。<br>**M6-c① 已交付（§9.6.1，R41）**：软锁死的**检测与可见**——每核自己的定时器 tick 当心跳（BSP 走 PIT/I-O APIC、AP 走本地 LAPIC，两条来源不许混），连续 3 × 50 ms 窗口不前进就算卡住，轮询点在 `tsc::stage()` 的阶段边界上；处置没有（`actions` 恒 0 由判据钉住，摘线要 §8.2 那套按驱动组织的隔离，今天没有 CPU 这一维）。硬锁死（要真 NMI）与硬件看门狗（要那个器件）在这台 QEMU 上量不出来，不写已交付。<br>**M6-d 已交付（§9.7.2，R42）**：崩溃记录升到 V2 —— 12 个字段 + 最多 32 帧（**不需要跨槽续块**，算过上界后一槽装得下，那个设计被删）；扫描改成"头部一次扫 + 该种类的候选表"，因为头部过校验不等于正文解得开，只挑最新会让一条自相矛盾的记录锁死整个种类；新增 `fault-crash-oops` 构建与矩阵第 21 行，验"记录里的向量/CR2/RIP/RSP 与同一遍串口的异常现场同数"。**仍差两半**：真实现场今天只有 1 帧（产物无帧指针，开 `force-frame-pointers`/CFI 会挪 P1/P3 基线，故单列）、`log_tail` 要停机路径可读的环形日志缓冲。**M6-e 已交付（§9.7.3，R48，BACKLOG 63）**：真实现场的调用栈从 1 帧走到 **3 帧**，而 M6-d 那句归因「产物没有帧指针」「开帧指针要重算 P1/P3 基线」**作废**——开关早在 `.cargo/config.toml` 里，本轮实测 P1 `min` 846/719→640/851、P3 `min` 314/330→318/310、串口量 130,915/130,916→130,911/130,916 三项都没挪。真因是我给返回地址设的「8 字节对齐」：x86-64 指令变长，实测第一层返回地址 `0xffffffff80010517`（`& 7 == 7`）被判死。换成「内核半区 + 生效权限说它可执行」（NX 逐级相或），这条判据变严之后第一个被抓出来的是我自己的夹具（合成链那格把返回地址指在本函数的局部变量上，旧门禁照收）。宿主机新增一台仪器：用内核 ELF 的 `.symtab` 把每条返回地址解成函数名 + 偏移（`.symtab` 不在运行时镜像里，Limine 只加载段 ⇒ 只能核外判），并先验 `image-info.txt` 的 `elf_sha256` 与当前产物同数（帧地址配上另一个构建的符号表会解出另一个函数而照样「解得通」）；`st_size == 0` 的符号不收（收了就等于「任何地址都落在某个函数里」，仪器永远说对）。判据写 `帧数 >= 2` 而**不写**实测的 3：前两层是结构决定的（出事函数与它的调用者 `ktest::run_all`），第三层往上取决于内联。两条变异：换回对齐判据 ⇒ `帧数=1` 行红；把点名的调用者换成 `after_switch` ⇒ 自报/宿主机/深度三格全绿而只有符号化红。<br>**M6-f 已交付（§9.7.3，R48，BACKLOG 64）**：§9.7 那张表里「最近日志」那一格从今天起有真数——`serial.rs` 里 `[AtomicU8; 4096]` 环形旁路（挂在 `READY` 检查**之前**：真机上串口坏掉那一档恰恰最需要盘上这段话），状态区第三条记录 `kind = 3`（固定 16 字节 `crash_seq`/`lines`/`bytes` + 文本 464 字节 ⇒ 实测 3~4 行），停机路径的顺序定死为「取尾 → 写摘要 → 落盘行 → 写日志尾 → 日志尾行」。读侧三条自洽（声明长度必须等于 `size - 16`、末字节必须是换行、声明行数必须等于文本里换行符的真实个数）；`KT_CRASH` 十一格 → **十五格**（配对、尾行整段、装不下就不给、行数不符拒、截断拒），矩阵 26 → **27 行**。第 27 行把盘上那段与**同一遍启动的串口原文**逐行对账，并要求末行等于落盘行之前那最后一条 `[cpu]` 现场行——锚点第一次错锚在「落盘行的前一行」，实测红在这里：写这条记录本身会往串口插进块层的 `ahci: 取证` 行。**按行集合比而不是按连续子串比**，因为 `serial::line` 今天没有整行原子性（不加锁，两个 CPU 同时打就互相插花），「连续」这条更强的 claim 要等日志加了行锁才许写。代价是量出来的：多这一条记录 ⇒ stage6 串口量 130,880 → 141,118（**+10,238 字节**；归因办法是把 `write_log` 那一句临时关掉再跑同一构建，另外六个阶段逐字节不变），成因是每条记录要扫全区 8 个槽 + 写一槽，而块层每条命令打一行取证 ⇒ **状态区的成本按记录条数走，不按字节数走**。三条变异：取晚了一点名 `ahci: 取证` 行（红）；文本改 1 个字节并重算校验和 ⇒ `逐行=3/4` 红；只把 `crash_seq` 加一 ⇒ `逐行=4/4` 而配对红（第一版把这笔叠在前一笔之后跑，两笔成因混在一行读不出来，重跑了一遍单独的）。`check` 仍 13 道，`check-state-window` 扩两条常量与一条**推导**对账（内核侧 `LOG_TEXT_MAX` 是 `MAX_PAYLOAD - LOG_FIXED` 推出来的，生成器侧是字面量 464）。<br>**L3-A 已交付（R54，ADR-035，BACKLOG 72）**：日志的整行原子性。`serial::line` 一颗行锁 + 序号改在锁里取 +
四本账（取锁/竞争/重入/超时）+ L4 出口 `unlock_for_halt()`。两台仪器：内核 `t_serial_atomic` 数账
（`holds == 总行 96`），宿主机判定表第 **31** 行数形状（`整行数=96/96 tag混行=0 tag错主=0`）；
第 27 行补上第 ⑤ 条"盘上那段必须整段连续"。撤锁的变异 E：`整行数=65/96`、`tag 混行 10`、`取锁=0`
⇒ 判据能红。<br>**M6 未完**：隔离名单（要驱动加载器）、A/B 槽位标记（§9.5，卡在装载侧身份）、watchdog 的处置那一半、464 字节之外的更早现场（容量欠账，要更多只有另开一块连续日志区）、真机上这份记录的读者（A.5 的「crash dump 解码工具」仍开）、fuzz、011-正式的验签 |
| M7 真机 | USB HID、电源、硬件矩阵、安全/度量启动、**推测执行缓解（M4–M7 期间为已知未完成，见 A.1）** | 目标硬件清单通过 |
| M8 网络与安全加固 | 网络栈、审计、漏洞响应演练 | 协议 fuzz 无高危缺陷 <br>**M8-a① 已交付（ADR-032，R44）**：virtio-net 的 TX 路径建起来并发出两帧，**帧的每个字节由核外的仪器判**——QEMU 的 `filter-dump` 写 pcap，宿主机逐帧三处对账（包字节 == 按同一张表重算、包哈希 == 内核自报、源 MAC == 命令行 `mac=` 那一份，而内核那一份是从设备配置空间读的）。矩阵 22 → **23 行**、`check` 9 → **10 道**（新增 `check-net-pattern`）、`ktests` 正常 52 条 / net 变体 53 条。三条只有现场能给的读数进 BACKLOG 58：不接受特性时头长 **10 字节**、设备配置区**只有 8 字节存在**（`mtu` 读回 `0xFF` 是"这一格不存在"而不是"值是 0xFFFF"）、QEMU 给 transitional 网卡的 PCI device id 是 **`0x1000`**（与规范式子不符 ⇒ 身份判据改走"队列数 ≥ 2 且 RX/TX 门位不同"）。<br>**M8-a② 已交付（ADR-032 的补记，R45）**：RX 队列真的建起来（`queue_enable` 读回 1、门 `0x3000` 与 TX 的 `0x3004` 不同、地址三格可回读），内核发一份 DHCP DISCOVER（290 字节，IPv4/UDP/BOOTP 自己构造，首部校验和真算），收到的是 **QEMU 用户网络自带服务器**的回话（590 字节，`used.len=600` = 头 10 + 帧 590）。判据七格 + 矩阵第 24 行：宿主机重算那份 DISCOVER **逐字节**核对、那条回话按哈希认出、再由**第二条独立实现**解出 `op/xid/msg/yiaddr` 与内核逐一相同，`yiaddr` 必须等于 `dhcpstart=`（内核猜不到的数）、回话里的 `chaddr` 必须等于这块网卡的 MAC。三条实测进 BACKLOG 59：用户网络**不答 ARP**；`magic cookie` 凭记忆写错过而 **slirp 不校验入站 cookie ⇒ 内核里没有任何判据能抓到它**（是对端写回的那四个字节纠正的）⇒ 协议常数也要设备作证；同一份构建两次跑出 OFFER(2) 与 ACK(5) ⇒ 判据接受两者、不归因。<br>**M8 未完，且这一行的验收句不成立**：协议上层（解出来的四个数就是终点，没有 socket、没有地址绑定、`REQUEST`/`ACK` 完整四次握手没走）、控制队列、多缓冲接收、中断认领（仍全轮询）、审计日志、漏洞响应演练，以及**"协议 fuzz 无高危缺陷"这句本身——一条 fuzz 都还没跑**。 |
| M9 图形准备与商业化 | 显示、输入接口、安装、更新、签名、发布流程 | 可发布候选版本 <br>**M9-a① 已交付（BACKLOG 60，R46）**：核内零依赖、零 `unsafe` 的 SHA-256，配三道独立仪器——`check-sha-primitives`（按**定义**重算 K/IV 与源码逐字对账）、`check_sha256`（13 条长度向量的摘要由 `hashlib` 各算一遍，矩阵第 25 行）、`KT_SHA256` 五格（互不相同/幂等/空串形状/雪崩 31/32/端序自洽）。本轮最该记住的一条：改 `σ1` 的一个旋转量时**内核五格全真、判定仍是 PASS(33)**，只有 hashlib 红 ⇒ 密码原语上"自我一致"等于零证据。<br>**M9-a② 已交付（ADR-033，R46）**：Lamport 一次性签名的验签链——锚点是内置的"整张公钥的摘要"、公钥与签名随包交付、包放在状态区之后同一段 GPT 空隙（LBA 67_664 起 113 扇区 = 头 512 + 公钥 16384 + 签名 8192 + 载荷 32768，载荷是真夹具 `hello.elf` 的字节）。判据是**两份实现逐条同答案**：九种篡改各走到一个不同的拒绝分支（`AnchorMismatch`×2、`BitMismatch(0/128/255/0)`、`PayloadTooLong`、`BadLen`、`BadHeader`），矩阵第 26 行由宿主机的第二条实现重算同一批答案。两条实测教训进了 BACKLOG 61：我凭记忆写的锚点 32 个字节里有 24 个是编的（被 `check-sig-anchor` 抓出来，第 12 道门禁），以及"负样本要指到它点名的那一格"——载荷长度翻在低字节得到的是签名不符而不是界检查，那条分支当时没被测到。<br>**M9-b 已交付（BACKLOG 62，R47）**：`tools/aurora.py release` 做两件事——两次全量编译（中间 `cargo clean -p aurora-kernel`）比内核 ELF 的 sha256（实测同摘要 `84c27191f859…` ⇒ **同机同 target 目录**这一层的可复现成立；跨机/跨路径没测，不写成"跨机可复现"），以及生成 `docs/release/sbom.json`（成员/版本/许可证/来源 + 产物与镜像内 6 个条目的内容摘要）。新门禁 `check-sbom`（第 **13** 道）拿 `cargo metadata` 的全图与 SBOM 对账。两条边界必须一起读：**外部 crate 实测 0 个** ⇒ `cargo deny`/`cargo vet`/vendoring 今天没有可管对象（门禁先立着）；两个成员都**没有声明许可证**（ADR-009b 未定），处理是登记**带理由的留空**而不是随手填一个 MIT。<br>**M9 未完，"可发布候选版本"不成立**：验签**还没有接到启动决策**（今天跑在一条用例里；"验不过 ⇒ `BOOT-INVALID(37)` 不启动"要等 ADR-011 正式方案与 §9.5 的槽位身份）；生产钥匙的离线保管、轮换、吊销一条都没有（现在的锚点是测试种子导出的，只能证明机制对）；安装与更新要 VFS/FAT32 与块层通用化（M5 未完）；输入接口要 xHCI/USB HID（M7 真机）；显示要 framebuffer 与它的第二台仪器（QEMU 抓屏）；SBOM 进发布产物（归档、渠道、签名）与跨机可复现未做。 |

> **V1.2 对排期的四处更正**：① ADR-009 → 009a（M0）/009b（公开前），见 §15.4（R9）；② ACPI 拆两级，固定布局表提前到 M2/M3b、AML 独立成 M5b（R11），因为 §8.4 的 IOMMU 要 DMAR/IVRS、M3b 的 SMP 要 MADT；③ SMEP/SMAP 从“建议”变“M4 必需”（R17），并新增 M5b 一行，避免 V1.1 里“M4 验收结论随硬件漂移”；④ §13.1 的 SMP 待核实清单必须在 **M2 结束前**关闭，否则 M3b 无法定义“AP 起不来算不算过”（R20）。

## 15 商业化、生态与治理

### 15.1 差异化定位（ADR-013，待定）

直接做通用桌面 PC 系统，要同时面对硬件驱动和应用生态。已有 Rust 系统的公开进展也表明工作量主要在驱动、文件系统与 ABI 兼容 \[S16\]。建议在 M5 前完成定位评审，候选切入点：

| 切入点 | 硬件范围 | 生态压力 | 参考 |
| --- | --- | --- | --- |
| 虚拟机/容器客体系统 | 虚拟硬件（virtio），极小 | 需要运行标准应用 | Asterinas 面向 Kata/机密容器 \[S16\]，最新版 0.19 于 2026 年 10 月发布 [S15](https://www.opennet.ru/opennews/art.shtml?num=66460) |
| 工业/边缘 x86 设备 | 可控、可认证 | 应用少且自有 | — |
| 安全敏感专用终端 | 可控 | 强隔离与可审计是卖点 | — |
| 通用桌面 | 极大 | 最强 | 远期目标 |

### 15.2 应用生态策略

| 方案 | 说明 | 代价 |
| --- | --- | --- |
| 自有 API + Rust std 移植 | Redox 已支持 Rust 标准库并在 Rust 平台支持中为 Tier 2/3 \[S18\] | 应用少 |
| POSIX 子集 + libc 移植 | 把常见命令行工具跑起来 | 中等 |
| Linux ABI 兼容 | Asterinas 路线，已支持 210 余个系统调用 \[S14\] | 工作量大，需评估许可证与维护负担 |

**建议**：首期“自有 API + 最小 POSIX 子集”，并把 Linux ABI 兼容作为独立评估课题（等 M4 之后有真实数据再决定）。

### 15.3 驱动与硬件认证

- 公布硬件兼容清单（HCL）与“已验证/已知问题/不支持”三档状态，不方便承诺“支持所有 PC”。
- 复用其他系统的驱动代码涉及许可证（如 GPL）与接口假设，需法务与架构双评审后再决定。

### 15.4 许可证与治理（V1.2 拆为 ADR-009a / 009b，R9）

| 项 | 编号 | 截止 | 内容 | 性质 |
| --- | --- | --- | --- | --- |
| 可引入依赖的许可证白名单、copyleft 处置、vendoring 边界 | **ADR-009a** | **M0（CI 于 M1 前生效）** | 工程门禁：`cargo deny` 的 licenses 清单、§11.2 的 vendoring、§13 的 AML 库候选、§15.3 的驱动复用 | 技术+法务咨询 |
| 项目发布许可证、贡献协议（CLA/DCO）、商标 | **ADR-009b** | 对外公开或招募贡献者之前 | 发布与治理：宽松型（如 Redox 采用 MIT \[S20\]）vs copyleft、DCO/CLA、命名与商标 | **法律判断，由律师确认** |

V1.1 把这两件事合成一条排在 M0，理由写“阻塞商业化”——但真正按时间顺序先撞上的是 009a：**Limine（ADR-003）已经决定要引入，`Cargo.lock` 与 vendoring（§11.2）在第一次构建时就会把第三方源码放进树**。009b 晚定不影响编码，009a 晚定要重搬依赖树并可能推翻已写好的抽象。

补充一条与 009a 直接相关的取舍依据（供评审，不构成法律结论）：内核若采用 GPL 系，则第三方专有驱动无法链接内部符号——Linux 的官方表述是这会让内核被标上 “P” taint，且模块加载器拒绝链接 `EXPORT_SYMBOL_GPL()` 导出的符号 \[V4\]。这与 §1.4 ADR-010“不提供第三方内核态扩展”方向一致，因此**许可证选择与 ADR-010 要一起评**，不能一个 M0 定许可证、另一个 M9 定扩展政策。

### 15.5 发布与支持

沿用 V1.0 的四个渠道（开发、测试、稳定、LTS）。每个渠道需定义：支持周期、安全补丁范围、回滚要求、签名密钥轮换与吃紧恢复流程。具体周期由产品和安全负责人在 M9 前确定。

### 15.6 团队与流程

- unsafe 与密码相关改动需双人评审。
- 关键模块至少两人熟悉，避免单点依赖。
- Redox 的公开报道强调贡献者招募对这类项目是生死政题 [S19](https://www.webpronews.com/redox-os-the-rust-written-operating-system-that-refuses-to-stay-niche/)，项目组织要把人才计划写进路线图。

## 附录 A 风险与模板

### A.1 风险登记册（负责人、阈值待填）

| 风险 | 影响 | 缓解 | 关联章节 |
| --- | --- | --- | --- |
| 驱动与硬件兼容不足 | 无法商用 | virtio 先行、HCL、定位收敛 | 8, 13, 15 |
| TCB 内 unsafe 缺陷 | 全系统崩溃或被攻破 | unsafe 预算、审计、Miri/Kani | 1.3, 12 |
| 工具链升级破坏构建 | 进度阻塞 | 固定版本、容器镜像 | 3 |
| 真机行为与 QEMU 不同 | 隐藏缺陷 | 真机矩阵从 M5 开始建立 | 12, 13 |
| 应用生态缺失 | 无人使用 | 明确切入点与兼容策略 | 15 |
| 许可证与法律风险 | 无法发布 | 尽早决策、律师审查 | 15.4 |
| 范围蔓延 | 延期 | 每个里程碑有写明的“不做”清单 | 14 |
| 关键人员依赖 | 项目停摆 | 文档、双人评审、招募 | 15.6 |
| **M4–M7 期间用户态已开放而推测执行缓解未到位**（V1.2 新增，R17） | 该区间内的对外演示/早期采用者暴露于已知未完成的缓解面 | 在 `sys_abi_info()` 特性位与发布说明中**显式标注未完成**；不作为“安全”对外承诺 | 5.1, 11.1, 14 |
| **门禁静默空转**（V1.2 新增，R19） | 绿而无效：lints 未接入、白名单与实际不齐、浮点代码进内核 | §1.3 第 6/7 条两条对账 + §12.3 每条门禁的固定负样本用例 | 1.3, 3.5, 12.3 |
| **§13.1 的 Limine SMP 细节未核实就开工**（V1.2 新增，R20） | M3b 返工：低 1MiB 归属、AP 初始状态、失败语义 | 清单在 M2 结束前关闭并落 ADR | 13.1, 14 |

### A.2 ADR 模板

```text
# ADR-NNN: 标题
状态：提议 / 已采纳 / 已废弃（被 ADR-MMM 取代）
背景：要解决的问题与约束
选项：至少两个，写明优缺点
决策：选择哪个、为什么
后果：对其他模块、测试、发布的影响
回退：如果错了如何撤回
```

### A.3 模块评审清单

- 有 `DESIGN.md`（职责、接口、依赖、资源策略、错误策略、并发说明、已知限制）。
- 拆为 `-api` 与实现两个 crate，依赖图通过检查；**crate 名已登记进 §2.5 树与 `deps.toml`（V1.2 R10）**。
- 默认 `forbid(unsafe_code)`；若在**登记表内**则每个 unsafe 有 SAFETY 注释，且已登记进 `docs/security/unsafe-whitelist.toml`（V1.2 R19，不再有就地补名单）。
- **本 crate 的 `Cargo.toml` 写了 `[lints] workspace = true`（V1.2 R19）**——没写不等于 lint 宽松，等于这一整个 crate 的门禁不存在。
- 错误类型独立、无 `unwrap/expect`（豁免须按 §1.3 第 7 条登记理由）、所有分配可失败。
- 锁等级已登记，中断上下文规则已遵守；**新增锁有“同持有者二次获取”用例（V1.2 R16）**。
- **不持有裸物理页所有权跨 `map` 调用**；映射以 `Mapping` 表达，`Drop` 不在自旋临界区内（V1.2 R13）。
- 资源全部经资源表登记，模块故障时可撤销。
- 单元测试、集成测试、故障注入点均已提供。
- 有验收记录与性能基线（对应 §12.4.1 的 P1–P4 中相关项）。

### A.4 待决 ADR 清单

| 编号 | 主题 | 需在何时前决定 |
| --- | --- | --- |
| **ADR-009a** | 可引入依赖的许可证白名单与 copyleft 处置（工程门禁） | **M0**，CI 于 M1 前生效 |
| **ADR-009b** | 项目发布许可证、贡献协议、商标 | 对外公开或招募前（不阻塞编码） |
| **ADR-011** | **可信持久存储**：011-临时（明文，仅可靠性判定）/ 011-正式（验签）/ 011-信任根 | **M1 前 / M6 前 / M7 前**（V1.2 R12，原“M2”过晚） |
| **ADR-012a** | ACPI 固定布局表的最小实现（MADT/FADT/MCFG/DMAR-IVRS） | **M2**（V1.2 R11 提前，M3b 的硬前置） |
| **ADR-012b** | AML 解释器：自研 vs 复用现有库（受 009a 约束） | M5b 前 |
| **ADR-014** | Limine SMP 五项待核实结论（§13.1） | **M2 结束前**（V1.2 R20） |
| **ADR-015** | `Mapping` 的实现落点与可阻塞 `Drop` 的约束（§6.3 R13） | M2 前 |
| **ADR-016** | host 平台与统一命令入口：纯 Windows 便携链进 `.tools`，`tools/aurora.py` 为唯一入口 | 已采纳（M0，本机实测） |
| **ADR-017** | Limine 版本与 `requested_base_revision` 固定（含 sha512 校验） | 已采纳（M0） |
| **ADR-018** | 内核堆的 OOM 出口：`GlobalAlloc` 失败即 L4，需 `Result` 者显式用可失败分配（§6.5 R21） | 已采纳（M2-b，注入实测 39） |
| **ADR-019** | bootloader-reclaimable 区的回收时机：默认不回收 + 显式一次性回收（§6.7、§13.1） | 已采纳（M2-c，实测三重故障与 45 MiB） |
| **ADR-020** | 中断向量分配与 EOI 纪律、第一把锁（堆）与中断上下文守卫、P5 基线（§7.1、§12.4.1） | 已采纳（M3a，7 条判定全绿实测） |
| **ADR-021** | IF 的归属：**中断窗口属于 CPU，不属于任务**；`context_load` 换入时改写异常帧 IF 位；合成帧只写保留位。配 `fault-if-carriage` 负样本（实测 **HANG**）与"第二段窗口必须还收得到 tick"的判据 | 已采纳（M3b-1；当时 8 行判定全绿，ADR-023 之后是 9 行） |
| **ADR-022** | **部分 AP 起不来的语义**（§13.1 第 4 项）：降级继续跑、用例判红、七个计数器可观察；不升 L4、不算 BootInvalid。第一次兑现就是本里程碑自己写错的 AP 定时器标定 | 已采纳（M3b-1） |
| **ADR-023** | **TLB shootdown**（§6.6）：解映射在归还物理页之前等齐每个在线 CPU 的回执；处理方不拿锁；收不齐升 L4。含一次"SDM 的 ICR 目的缩写在 QEMU 上收不到"的实测差异，与"QEMU 观测不到硬件旧条目"这条先天限制 | 已采纳（M3b-2a，9 条判定全绿实测） |
| **ADR-024** | **per-CPU 化到哪一层**（§5.2、§12.4.1）：运行队列每 CPU 一条且任务不迁移；P3/P5/P1 离开 asm、边界移动、新旧数字不可比；P1 读数变化用四轮排除法定位到"一次 UC- 的 LAPIC 寄存器读 ≈600 周期"，据此定了"槽位在异常入口取一次、往下传" | 已采纳（M3b-2b，M3b 收尾） |
| **ADR-025** | **ring3↔ring0 的入口先用 `int 0x80`**（§10.1、§5.3 R14 第 2 条）：中断门由硬件按 `TSS.rsp0` 换栈并自动关 IF，这条路径不需要 GS ⇒ swapgs 窗口"不存在"而不是"处理得好"；SYSCALL/SYSRET 与该窗口的两个候选（`rdtscp`+`TSC_AUX` 或 IST 影子栈）一起在 M4-2 决定。附带登记一条 ADR-021 的缺口：异常桩自己的出口不经过 `if_patch`，靠"任务只在窗口开着时被打断"这条不变量才安全，`park_current` 写 IF=0 造成整机构挂死就是它的第一次兑现 | 已采纳（M4-1，实测 ring3 往返） |
| **ADR-028** | **用户地址窗口分成镜像区/动态区，落脚页归内核所有**（§10.7、§10.3.1）：`alloc_user_va_range` 与 `reserve_va_at` 不能共用一条前沿——否则"容器装不装得上"由 `.ktests` 的**链接顺序**决定（实测现场是 `VaTaken` 而账目完全平的，第一解释"回收坏了"是错的）；`USER_MMAP_BASE` 一刀两断 + `check_image_span` 按整份跨度拒；被杀任务的 `rip` 落在内核拥有的 `TRAMPOLINE_VA`（vsyscall 那一族），不再是测试脚手架那一页，`rsp/cs/ss` 保持故障帧原样；被杀路径登记待回收（`kill_current`），内核任务的 `finish_current` 不登记（合并会让 `KT_PREEMPT` 的事后读数在观测之前被归化清掉——先合并、跑出回归、再拆开） | 已采纳（M4-3 第一段，实测四档） |
| **ADR-027** | **任务结束时谁松手**（§10.7、§6.3 R13）：所有权跟着任务走（`Task::owned`，定长 8 条）；结束只做"标 Free + 立牌"，**释放延迟到本 CPU 上跑的已经不是它**（当场解映射 = 抽掉自己正站的栈 = ring0 故障 = L4）；`Mapping::drop` 连 VA 保留一起放手（按包含找、逐页确认无映射）；`kills` 与 `exits` 分开数。附一条元规则：一条规则写在两处就要有两处各自的判据 | 已采纳（M4-2 第三段，实测三轮回收） |
| **ADR-026** | **用户半区、生效位与按架构偏移声明的字段**（§6.3、§6.4、§10.2）：用户 VA 单独一段窗口且共用登记表；`map` 装完用户叶子必须把整条链读回来验（`UserChainBlocked`）；`effective_flags` 按 P/W/U/S 相与、NX 相或算"生效位"，判据落在它而不是落在 `PageFlags` 的意图上；`Tss` 改 `packed` 并按字节位置核对 RSP0@4/IST1@36；`PF_RESUME` 必须有配对的 `PF_EXPECT` | 已采纳（M4-1，五个缺陷各有串口原文） |
| ADR-013 | 产品切入点与应用生态策略 | M5 前 |

### A.5 留给 V1.3 的空白项（本轮不处理）

V1.2 只修内部矛盾与排期。上一轮评审中“仍属空白”的九项**没有**在本版本落地，逐条登记如下，供 V1.3 一并处理；每项都标了它会在哪个里程碑变成墙：

| 空白项 | 内容 | 撞上它的里程碑 |
| --- | --- | --- |
| Limine 交接状态清单 | FS/GS base = 0、IDT undefined、bootloader 已备 7 项 GDT、PIC/IO-APIC 全 masked、IOMMU 关闭、PAT 缓存属性 | **M1**（§10.1 的 `gs:[PerCpu]` 依赖自己建 GS_BASE） |
| 中断重映射与 DMAR fault 处置 | §8.4 只做了地址翻译域；伪造 MSI 与 fault 后的 L2/L3 归属未定 | M5 |
| 线程化中断选型 | §5.5 只说“下半部”，§8.2 的 `IrqHandlerFn` 未写可否睡眠 | M5 |
| 设备重置的具体协议 | PCIe FLR/SBR、NVMe、AHCI、USB port reset 语义差异；在途 DMA 与 `revoke_all` 的先后 | M5–M6 |
| 可恢复内存错误处置 | §5.6 的 #MC 停在“分级”；缺页面下线/毒化（L4→L3 的唯一降级手段） | M6 |
| crash dump 宿主侧解码工具 | §9.7 只定义了写，没定义读；`tools/debug/crashdecode` | M2 |
| host 开发平台声明 | §3.5 全为 sh + `$OVMF`，未写 `HOST=Linux`，亦未定 CI runner | **M0** |
| 术语表 | “模块”同时指 crate / 子系统 / 可隔离驱动；`ModuleId` 属哪一层未定 | M2（§9.1 资源归属） |
| SYSRET/swapgs 窗口的 paranoid entry | §5.3 R14 第 2 条已登记为评审项，本版本未规定。**M4-1 部分处置（ADR-025）**：M4-1 的入口是 `int 0x80`，硬件按 `TSS.rsp0` 换栈、不需要 GS ⇒ 这条路径上窗口不存在；本项**仍然空白**，因为它绑在 SYSCALL 上，M4-2 决定入口时必须与它一起定 | M4-2 |

## 附录 B 参考文献

### B.1 本次会话实际检索到的来源（\[S#\]）

编号沿用检索序号，未被引用的来源已省略。这些来源中有若干是二次报道或博客，重要结论采用前建议回溯一手来源（如论文、官方文档、厂商事故报告）。

| 编号 | 标题 | 地址 |
| --- | --- | --- |
| S1 | Rust will save Linux（Rust Week 2026 报道） | https://blog.desdelinux.net/en/Rust-Linux--Greg-Kroah-Hartman--end-of-security-experiment/ |
| S2 | Rust For Linux No Longer Experimental | https://www.i-programmer.info/news/98-languages/18527-rust-for-linux-no-longer-experimental.html |
| S3 | Rust is here to stay（Maintainers Summit 报道） | https://blog.desdelinux.net/en/linux-kernel-rust-official-android-16-drivers-drm-debate/ |
| S4 | An Empirical Study of Rust for Linux（ATC/OSDI 2024） | https://atcosdi24.sched.com/event/1fLd7/an-empirical-study-of-rust-for-linux-the-success-dissatisfaction-and-compromise |
| S6 | Microsoft, SecOps pros weigh kernel access post-CrowdStrike | https://www.techtarget.com/it-infrastructure/news/366599066/Microsoft-SecOps-pros-weigh-kernel-access-post-CrowdStrike |
| S7 | Microsoft convenes endpoint security firms（SecurityWeek） | https://www.securityweek.com/microsoft-convenes-endpoint-security-firms-following-crowdstrike-incident/amp/ |
| S8 | Lessons Learned from the CrowdStrike Global Outage | https://prog.world/lessons-learned-from-the-crowdstrike-global-outage |
| S9 | Microsoft Talks Kernel Drivers Post CrowdStrike Outage（Dark Reading） | https://www.darkreading.com/application-security/microsoft-lowballs-crowdstrike-outage-impact |
| S10 | Microsoft mulls restricting third-party access to Windows kernel | https://mspoweruser.com/microsoft-mulls-restricing-third-party-access-to-windows-kernel-after-crowdstrike-outage |
| S11 | Microsoft's Security Strategy（Business of Tech） | https://businessof.tech/2024/07/30/microsofts-security-strategy-lessons-from-crowdstrike-outage-and-potential-kernel-access-restrictions/ |
| S12 | Asterinas: A Linux ABI-Compatible, Rust-Based Framekernel OS（arXiv） | https://arxiv.org/abs/2506.03876 |
| S13 | Asterinas: A Rust-Based Framekernel（USENIX ;login:） | https://www.usenix.org/node/309439 |
| S14 | Asterinas ATC'25 论文 | https://zhou-diyu.github.io/files/asterinas-atc25.pdf |
| S15 | Asterinas 0.19 发布报道（OpenNET） | https://www.opennet.ru/opennews/art.shtml?num=66460 |
| S16 | Asterinas 0.18 Lands | https://news.lavx.hu/article/asterinas-0-18-lands-a-rust-written-memory-safe-linux-alternative-targets-containers |
| S17 | Redox OS 项目目标 | https://doc.redox-os.org/book/our-goals.html |
| S18 | Redox OS 主页 | https://www.redox-os.org/home/ |
| S19 | Redox OS 进展报道（WebProNews） | https://www.webpronews.com/redox-os-the-rust-written-operating-system-that-refuses-to-stay-niche/ |
| S20 | Redox: An operating system in Rust（LWN） | https://lwn.net/Articles/979524 |
| S21 | Asterinas: a new Linux-compatible kernel project（LWN 转载） | https://hn.jakechampion.name/reader/https://lwn.net/SubscriberLink/1022920/ad60263cd13c8a13 |

### B.2 通用参考（\[R#\]，本次会话未核验页面内容）

这些地址是常见的官方规范或开源项目主页，按记忆给出，**采用前请打开确认内容与版本**。

| 编号 | 资料 | 地址 |
| --- | --- | --- |
| R1 | Intel 软件开发者手册（SDM）；AMD APM 需另查 AMD 官网 | https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html |
| R2 | UEFI / ACPI 规范 | https://uefi.org/acpi/specs、https://uefi.org/specifications |
| R3 | Limine 引导程序与启动协议 | https://github.com/limine-bootloader/limine |
| R4 | Writing an OS in Rust（测试篇） | https://os.phil-opp.com/testing/ |
| R5 | Rust `x86_64-unknown-none` 目标平台支持页 | https://doc.rust-lang.org/nightly/rustc/platform-support/x86\_64-unknown-none.html |
| R6 | OSDev Wiki | https://wiki.osdev.org/ |
| R7 | rust-osdev/x86\_64 | https://github.com/rust-osdev/x86\_64 |
| R8 | seL4 | https://sel4.systems/ |
| R9 | Fuchsia | https://fuchsia.dev/ |
| R10 | Miri | https://github.com/rust-lang/miri |
| R11 | loom | https://github.com/tokio-rs/loom |
| R12 | syzkaller | https://github.com/google/syzkaller |
| R13 | cargo-fuzz | https://github.com/rust-fuzz/cargo-fuzz |
| R14 | cargo-deny | https://github.com/EmbarkStudios/cargo-deny |
| R15 | cargo-vet | https://github.com/mozilla/cargo-vet |
| R16 | Kani | https://github.com/model-checking/kani |

### B.3 已逐字核对的一手来源（\[V#\]，V1.2 新增）

**核对范围写在括号里**——只核到该条结论所需的段落，不等于核对全文；引用时请连带范围一起带走。

| 编号 | 资料 | 地址 | 本手册用到并已核对的结论 |
| --- | --- | --- | --- |
| V1 | Rust 平台支持：`x86_64-unknown-none` | https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-none.html | 默认不生成向量/浮点寄存器（SSE/AVX）使用；默认 `kernel` code model；`extern "C"` 为 System V 无红区；Tier 2、stable 可用（1.62）——**本会话逐字核对，支持 ADR-001 与 §5.4** |
| V2 | Limine 启动协议 PROTOCOL.md | https://github.com/limine-bootloader/limine-protocol | 上一轮核对过：higher-half 地址下限、HHDM 基址不得硬编码、PAT 属性约定、交接时的寄存器与中断控制器状态（含 **FS/GS base = 0、IDT undefined、IOMMU 关闭**）、base revision 协商。**SMP 章节本轮未取到（两条分支 raw 均 404），故 §13.1 全部标“待核实”** |
| V3 | Linux 内核官方流程文档 `stable-api-nonsense`（Greg KH 署名） | https://docs.kernel.org/process/stable-api-nonsense.html | “内核既无二进制接口也无稳定内部接口”，只有 syscall 接口非常稳定；树外驱动的重复编译代价——**用于 §10.2/§10.6 把 syscall 表当唯一长期 ABI 的论证** |
| V4 | Linux 内核许可证规则 | https://docs.kernel.org/process/license-rules.html | 专有模块会打上 “P” taint，且模块加载器拒绝链接 `EXPORT_SYMBOL_GPL()` 符号——**§15.4 的 009a/ADR-010 联动依据** |
| V5 | LionsOS 论文（含微内核 IPC 微基准汇编） | https://arxiv.org/html/2501.06234v1 | seL4 986 cycles / Fiasco.OC 2717 / Zircon 8157 每次 IPC——**§12.4.1 的外部参照，非本项目目标** |
| V6 | SPDK（Intel，CloudCom'17） | https://ieeexplore.ieee.org/document/8241103/ | 用户态 NVMe 驱动每核 IOPS 高 6–10 倍——**同上，用于“搬到用户态并非只有代价”** |
| V7 | Linux KPTI 文档 + 实测记录 | https://www.kernel.org/doc/html/next/x86/pti.html 、https://www.brendangregg.com/blog/2018-02-09/kpti-kaiser-meltdown-performance.html | entry/exit 约 100 cycles、每进程多 4KiB 页表、syscall 密集 2%–7%+——**§11.1 任何缓解项都应在 P 系列留一条对比的依据** |
| V8 | QEMU `isa-debug-exit` 设备实现 | https://github.com/qemu/qemu/blob/master/hw/misc/debugexit.c | 退出码 = `(val << 1) \| 1`；**该设备默认 iobase 为 0x501，§3.5/§12.2 的 0xf4 是靠 `-device` 显式覆盖的**——两处必须一致，否则测试写不到端口、CI 只能等到超时 |
| V9 | ext4 官方文档 journal 节 | https://docs.kernel.org/filesystems/ext4/journal.html | journal 只保证 metadata 一致，默认模式下数据块“不保证”崩溃后一致——**§10.6 磁盘格式版本化那条的背景** |

**口径提醒（沿袭 §0.2）**：\[S#\] 里 S1/S3 是二次报道博客，S4 才是同行评议论文；上一轮我提过的“内核 CVE 中内存安全占比”的**具体百分比没有一手出处**，微软官方口径是“每年约 70% 的 CVE 属内存安全问题”，其统计对象是**微软产品**而非 Linux 内核。因此 §1.1 保留“口径不同，不可混用”的结论，并在评审时把那两个百分比改为引用 MSRC 并注明统计对象。

---

**本手册的局限**：代码未编译验证；新闻类来源为二次报道；ADR 为建议而非已评审结论；所有“阈值”“SLA”“支持周期”均有意留空。在架构评审会上逐章确认后，再把所有 ADR 固化到 `docs/adr/`。

**V1.2 额外声明三件事**：

1. **本版只修矛盾，不扩范围。** 12 条修订（R9–R20）全部来自“文档内部两处说法不能同时成立”或“决策截止晚于它保护的能力”。上一轮的九项空白如实登记在 A.5，没有假装已解决。
2. **有一处外部意见被撤回（R14）。** 上一轮对 §5.3 的 CS 偏移批评是误读，V1.1 的写法正确，核对脚本留档在 `.scratch/trapframe_offset_check.js`（两种宏路径输出一致）。同轮核对真正暴露的是 `cr2` 缺失与 swapgs 窗口，前者已补，后者登记为 M4 前的评审项。
3. **本版本有一处明确“取不到依据”：** Limine 的 SMP 章节（§13.1，V2 标注的 404）。它被写成待核实清单而不是结论；在 M2 结束前，任何代码注释、`limine.conf` 说明或对外文档都不得把它当事实。凡是这类条目，本手册统一用 `待核实` 标记，与 \[V#\]（已核对）、\[R#\]（未核对）、\[S#\]（二次报道）区分开。
