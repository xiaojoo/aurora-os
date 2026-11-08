# ADR-067: W2 只修 ring3 未填充页的 demand-zero 接缝，区间本体住 mm 定长表、OwnedSet 挂柄

状态：提议（2026-11-08，W2 内存分层 P5；证据来源 kernel/src/mm.rs、arch/x86_64/trap.rs:950-998、user.rs:786-856、sched.rs:110-116/1587 当前实现 + BACKLOG §139/§136/§140）
关联：手册 §6.6 §9.2 §10.2、ADR-023（shootdown 与 TCG 限制）、ADR-026（HHDM 直写页配方、生效位）、
ADR-027（OwnedSet 所有权与延迟释放）、ADR-028（用户窗口分区）、ADR-040/045（回调表与登记口径）、
ADR-060/§136（修复路径不得级联取锁）、ADR-063/064（清零纪律）、ADR-066（unmap 的 HHDM 别名约束）、
完整化方案 §6 W2 条目 5、BACKLOG §139（W2/W3 边界）

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计；发现冲突先记差异，
> 不要为了让文档一致去改已经验证的结论。每条结论标「实测」或「推断」。
> 本帖决策先于实现：定接缝形状与修复条件，实现与证红在 P5 切片。

## 背景

原文与边界（BACKLOG.md:4929-4930，实测）：切片顺序 P4 之后是 **P5 demand-zero**；
「完整缺页修复（COW/按进程杀）要 W3 的每-AS VmaTable，**W2 只落内核修复接缝+单 AS
demand-zero**」。方案原文（:147）的完整形状是"用户半区缺页 → 查所属 AS 的 VMA 表 →
按需清零页 / 栈增长 / COW / 非法则只杀该进程（现在是一律杀）"，本帖只兑现其中
"按需清零 + 接缝"两格。

现状（实测，源码行号）：

- #PF 分发在 trap.rs:950-998：先消费恢复登记（PF_RESUME/PF_EXPECT/PF_LO/HI），
  不命中就 ring3 ⇒ `Action::Kill`、ring0 ⇒ `Fatal`；**没有任何"补页"分支**。
- `copy_from_user/copy_to_user` 持 VMM 且**先** `validate_range`（user.rs:794：逐页
  `effective_flags`，未映射直接 `NotMapped`）⇒ 内核拷贝路径触到未填充用户页**不会发生 #PF**，
  在验证层就失败返回（阶段 A 报告已更正任务书里"copy 触到未填充页触发 #PF"的例子）。
- `Task::owned: OwnedSet` 定长 8 格、每格一条 `mm::Mapping`（sched.rs:110-116，ADR-027）；
  `release_owned` 在**放掉 RUNQ 之后**逐条 drop（sched.rs:215-224，§136 同款纪律）。
- hooks 回调表由 sched 在启动期安装（sched.rs:1587，ADR-040）；arch 只认这张表。
- KBuf 的"分配即清零"纪律（ADR-064 决策 2：自由帧毒化 0xA5，不清零即泄漏）。
- ADR-066 已交 `unmap`，并写明约束：**不得清还将释放的 RAM 帧的 HHDM 别名**——
  本帖的惰性区间住**用户窗口 VA**（非 HHDM 别名），其 drop 用 unmap/Mapping 语义不受该约束。

结构性前提（推断，源码走读）：用户窗口（`[USER_VA_BASE, USER_VA_TOP)`，4 GiB 起）低半区
没有恒等映射也没有 HHDM 大页——该段链由用户映射自建、逐页 4 KiB（mm.rs:555-561 与
walk_leaf 的 share 论证）⇒ 惰性页未填充时 `huge_block_of` 必为 None，`map` 不会撞
HugeConflict，无需依赖 P4 的 split。实现期由用例首格自证。

## 决策

1. **惰性区间登记（mm 侧，定长不进堆）**：`pub const MAX_LAZY_REGIONS = 8`、
   `MAX_LAZY_PAGES = 16`。mm 内部定长表 `LAZY`：每项
   `{ used: u8, base: u64, pages: u16, filled: u16(位图，占用唯一真相，ADR-065 同律), owner: ModuleId, maps: [Option<Mapping>; 16] }`。
   `pub fn lazy_new(pages, owner) -> Option<LazyHandle { slot: u8 }>`：
   pages≤MAX_LAZY_PAGES；VA 经 `alloc_user_va_range(pages)` 发放（动态区、进共用保留表；
   与镜像区分区规则 ADR-028 结构上兼容）。表项读写全在 VMM(20) 内（与 va_res 同律）。
2. **所有权 = OwnedSet 挂柄**：OwnedSet 项型改
   `enum OwnedItem { Map(Mapping), Lazy(LazyHandle) }`；新增 `push_lazy(handle)`，
   既有 `push(Mapping)` 语义不变。`LazyHandle::drop ⇒ mm::lazy_release(slot)`：
   先逐个 drop 已填充 `maps[i]`（既有 Mapping::drop：解映射+归还帧+按包含放手保留），
   最后 `release_va(base)` 放手整段保留（未填充页本无映射，包含检查自然通过——
   ADR-027 决策 4 的按包含纪律原样兑现）。reap/release_owned 的搬运逻辑逐字不变，
   只是元素类型换成枚举。**这是对 ADR-027 的扩展，不改其语义**：计数规则、释放时机
   （"本 CPU 上跑的已经不是它"）、判据（owned_of、回基线）全部保持。
   **与任务书建议的差异（要求论证处）**：任务书建议把"区间+位图"整体塞进 OwnedSet 的一项。
   否决理由（硬）：填充动作发生在 #PF 处理路径，任务书同时规定"修复发生时不得持有任何
   sync 锁"——而 `Task::owned` 的可变访问必须经 RUNQ(8)（§136 的教训正是持锁现场级联
   出第二条 L4）。把本体放 mm 表（VMM 纪律）、柄放 OwnedSet，修复路径取锁序列只有
   PMM(30)→VMM(20) 的合法方向（phys_alloc 后 map，依次获取不算嵌套），drop 归还路径
   与 ADR-027 完全同行。定长、不进堆两点均保持。
3. **修复条件（写死为三条合取，缺一只字都不修）**：
   - `from_user(frame)`——内核态 #PF **不修**（copy 路径由 validate_range 先拒，见背景；
     内核直接触未映射地址保持 Fatal 原路）。
   - `(err & bit0)==0`（页不存在）且 `(err & bit4)==0`（非取指）——区间内取指故障仍
     Kill（区间是 USER_RW，W^X 不许"修出可执行页"）。
   - `hooks::sched().demand_zero(cr2)` 返回 true——mm 扫 LAZY 表命中已登记区间才填。
   三条任一不成立 ⇒ 现有 kill/fatal 路径**逐字不变**（任务书要求"其余情形保持不变"）。
   恢复动作 = `frame.rip` 不动、返回 `Action::Resume` 重执行原指令（fault 已消除）。
   插入点在恢复登记消费之后（trap.rs:978 与 :986 之间）——**不得**排在恢复判定之前，
   否则 ADR-026 的 PF_EXPECT 地雷教训重演（探针登记被补页分支劫持）。
4. **接缝 = hooks 表加一字段**：`SchedHooks` 加 `pub demand_zero: fn(u64) -> bool`，
   默认桩 `false`（安装前被调用也安全，与现有桩同律）；sched.rs:1587 安装时指向
   `mm::demand_zero_try` 的包装。**否决**"trap 直调 mm::"：环内 `arch->memory` 棘轮现值 21，
   只许降不许升，多一处引用即红——ADR-040 的回调表正是为这个形状准备的。
   `demand_zero_try(cr2)`：持 VMM 扫表；未命中 ⇒ false；命中且该页已填 ⇒ true；
   未填 ⇒ `phys_alloc(0, region.owner)` → 经 HHDM 清零（ADR-064 同律，新增 1 处 U2）→
   `map(va, frames, USER_RW)`：Ok ⇒ `filled` 置位、`demand_zero_count++`、返回 true；
   `AlreadyMapped` ⇒ **输家**：frames 随 map 的 Err 路径 Drop 归还（refcnt→0、毒化、
   台账，结构自带），返回 true（页此刻已填充，重执行必然成功）；OutOfMemory ⇒ false
   ⇒ 走 Kill 原判据路径（分配失败不吞错、不降级）。
5. **并发（双核竞争的真实形状）**：生产路径"两个 CPU 同时 fault 同一未填充页"要 W3 的
   每-AS/多线程才可达；本帖机制层用两个 AP worker 并发调 `demand_zero_try(同一 cr2)`
   构造竞争（smp 工人 + 有界等待，沿用 t_cross_cpu_* 的形状）。判据：**恰好填充 1 页**
   （count +1）、`filled` 位图恰 1 位、台账与 free_frames 回基线（输家帧确实归还）、
   两个 worker 都返回 true。输家还帧不靠自觉，靠决策 4 的 map-Err 结构。
6. **用例与 ring3 触达**：不增大 hello.elf（任务书红线；`PKG_PAYLOAD_BYTES=32768`、
   现余量 96 字节，BACKLOG:3131-3133）。用例自配最小 ring3 stub：按 ADR-026 配方
   （经 HHDM 直写机器码 + USER_RX 装叶），内容为"读惰性页第 0 页首 u64 → 写回结果槽 →
   SYS_EXIT"。用例 `t_demand_zero`（单条，内含六格 + 双核竞争段）：
   ① lazy_new 后区间首读为 0（污染空闲帧先行——先 drop 若干帧留 0xA5，first-fit 必捞到，
   沿用 KBuf 污染做法）；② 修复计数 +1、任务继续跑到 EXIT；③ 区间外未映射地址 ⇒
   仍只杀该任务（kills+1、内核继续）；④ 内核 `copy_from_user` 触未填充页 ⇒ `NotMapped`、
   不修复（count 不动）、不杀；⑤ 区间内取指 ⇒ 不修复仍杀；⑥ 任务退出后：已填充帧、
   区间 VA 保留、`LAZY` 槽位、台账全部回基线；⑦ 双核竞争格（决策 5）。
7. **日志契约**：新增一行（格式预注册）：
   `demand-zero(P5): 修复计数=+1 首读全0=true 区间外仍杀=true copy不修=true 取指仍杀=true 退出回基线=true 竞争填充=1 输家还帧=true`
   宿主机独立解析并与内核自判对账（内核绿而宿主机对不上 ⇒ 正向行 CONTENT-MISMATCH）。
   **不新增矩阵行**（无新构建档；矩阵保持 44 行）；用例 69→**70**。
8. **登记面**：public_api 补 `mm::lazy_new`/`mm::demand_zero_try`/`mm::demand_zero_count`；
   test_targets 补 `t_demand_zero`；`SchedHooks` 新字段属 hooks（arch 逻辑模块）既有结构。
   sched↔mm 无新边（sched 已引用 mm；hooks 字段是 fn 指针）；环内棘轮不动。
   unsafe 逐处新增登记（清零写 1 处 U2；LAZY 静态 cell 视实现形态定 U4/U2），census 重算对账。
   lock-order.md 不改（复用 VMM/PMM，方向合法，无新锁）。不新增 syscall 号、不新增向量。
   **unmap/HHDM 别名约束（ADR-066 落地记录）**：惰性区间 drop 解映射的是用户窗口 VA，
   不是 RAM 帧的 HHDM 别名；其物理帧经 Mapping::drop 归还，毒化走 HHDM 时别名仍在——
   不受该约束伤害，约束本身继续有效。

## 备选方案

- **区间本体（含位图+帧数组）塞进 OwnedSet 的一项**（任务书建议的原形状）：拒绝，见决策 2
  的差异论证（修复路径必须避 RUNQ）。
- **trap.rs 直调 mm::demand_zero_try**：拒绝（棘轮 21 只许降；ADR-040 已有先例通道）。
- **copy_*_user 对未填充惰性页做"锁内修复"**：拒绝。validate_range 持 VMM 时再取 VMM
  即重入 L4；放开验证让它 #PF 进修复又违反"修复不持锁"。W2 的诚实形状就是 NotMapped；
  真需要（init/产品路径）在 W3 的 VmaTable 上另裁"预故障入口"。
- **惰性区间登记进 VA 保留表之外自管地址**：拒绝。绕开共用登记表正是 M2-b 立表的初衷
  （双重发放事故）；alloc_user_va_range 已把分区与登记一起做对。
- **填充用 `phys_alloc(order)` 连续大块摊薄成本**：拒绝。W2 用量小（≤16 页），逐页分配
  才能把"输家还帧"做成 map-Err 的结构性质；大块共享要 ADR-063 的弱引用 get，本帖不提供。

## 影响

- 正面：方案 :147 的"按需清零页"第一格落地；#PF 从"一律杀"长出**唯一一条**受控修复分支，
  且每条不修的情形都有用例钉住（内核态/取指/区间外/分配失败）。
- 代价：LAZY 表静态约 8×(16×32B+头) ≈ 3 KiB .bss（推断）；每页填充首次建链多 1 页表页
  （MOD_BOOT 纪律，与既有用户映射同形）；正向串口 +1 行。
- 对已有 ADR：扩展 ADR-027（OwnedSet 项型）与 ADR-040（表多一个字段）；不改其已验证语义；
  ADR-026 的恢复登记优先级、ADR-028 的分区、ADR-066 的 unmap 约束原样。
- W3 的每-AS VmaTable 会**取代** mm 全局表与"扫 current 即可"的简化——本帖的接缝字段、
  修复条件三条合取、柄式所有权都直接沿用，被替换的只是查表逻辑。
- 时序：本帖结论都是可数的（计数/位图/台账），无 TCG 精度依赖；双核竞争是机制形状不是时长。

## 验收与负样本（P5 实现时兑现，本帖预注册）

- 判据即决策 6 的七格 + 决策 5 的并发四判据；见证行由宿主机独立解析（决策 7）。
- **变异证红（每条先红后绿）**：
  - M5-1 去掉填充前清零 ⇒ 污染帧图案（0xA5）泄漏到 ring3 首读 ⇒ 首读全0 格红。
  - M5-2 输家路径 `mem::forget(frames)` ⇒ 竞争格"输家还帧/台账回基线"红。
  - M5-3 修复条件放宽到"用户半区内任意未映射地址" ⇒ "区间外仍杀"格红（kills 不涨、
    count 虚涨，两种点名都要红）。
  - M5-4 把 demand-zero 判在恢复登记消费之前 ⇒ 探针用例 `t_pf_probe_recovers` 红
    （ADR-026 地雷的形状被反向钉住——接缝顺序不是洁癖）。
- 量具自查：见证行逐字段改坏/删行 ⇒ 宿主机 False；真行 True。
- 整轮：check 17/17；默认 run 70/70；矩阵整轮复验 44 行全符合（无新行）。

## 迁移与回滚

- 迁移：实现按 ADR 顺序：mm 表+lazy_new/lazy_release/demand_zero_try → OwnedSet 枚举 →
  hooks 字段+安装 → trap 接缝 → 用例+见证+登记。每步独立过门禁。
- 回滚：删 LAZY 表/三 API/柄分支/hooks 字段/接缝分支/用例与登记；OwnedSet 回
  `[Option<Mapping>;8]`；#PF 回"一律杀"。不动盘上格式、不动 syscall ⇒ 无不可回滚部分。
  回滚先后有依赖：用例必须先于机制删（否则红的是矩阵而不是产品）。

## P5 落地记录（2026-11-09，实测；BACKLOG §141）

- **读数**：check 17/17；默认 PASS 70/70；race-demand-zero 3/3 PASS、输家还帧 {3,3,1}；
  矩阵整轮复验 **45/45 全符合（exit 0；见证 36 份留档宿主机全过、用例零失败）**。
- **预注册形状与实现的两处差异**（原文不回改，差异记这里）：
  1. 见证行扩展了原始数四格（`就位/发令/回执/持页/ack`）与 `独占账回0`：竞争窗口的绝对
     帧账会被别的用例落在 AP 队列的延迟回收污染（实测 ±28 帧），所以"恰留一页"改用
     专用 `ModuleId(40)` 记账 + `demand_zero_lost` 计数，判据只看自己；`修复计数=+2`
     （ring3 1 页 + 竞争格 1 页），预注册的 +1 只是 ring3 段。
  2. 等待环从周期预算改为 **40×tick 事件驱动**（`wait_ticks(base,1,window_cycles(1))`）：
     纯周期预算在 tick 没开的上下文里空转——这是排障排出来的，不是风格选择。
- **用例自足三条（实测坑）**：`init_boot_task()`（fault-double-free 档把本用例排在它前面，
  §86e 同族）、`start_workers()`（fault-resched-ipi 档门掉了设置 RUN 的三条用例）、
  `apic::timer_start().ok()`（链上有用例停表不带回，t_user_roundtrip 同一形状）。
- **桩代码空洞（"绿而无效"的活案例）**：`mov rax,3` 与 `int 0x80` 之间留了两字节 `00 00`，
  ring3 执行到空洞 `add [rax],al` 写地址 3 —— M5-3 之前每一跑"区间外仍杀=true"都涨在
  错误原因上。这条与"变异 v5 饿死"一起构成 §134 口径的两次现场：**判据绿 ≠ 判据在量
  它点名的东西**。
- **暂门两档（机制未归因，不冒充已修）**：`fault-resched-ipi` 与 `ahci-scratch` 家族
  （write-dir 单跑 3/3 静默死，同族 highlba/write-partial 符合）——按 §138 先例整条不注册，
  W3 排产归因；归因前两档的绿不算本接缝的证据。
- **M5-4 不采信**：接缝排在恢复登记消费之前的变异，在 W2 结构上构造不出预期红
  （恢复登记只可能由内核态设置、接缝要求 ring3——`from_user` 一条已经把劫持路径挡死）；
  按 ADR-054"没按预期咬的变异不算证据"，顺序保证降级为结构性论证 + 代码注释钉位。
- **量具错两笔**（脚本转行尾、预算误抬 4G 后回退）见 BACKLOG §141 排障记录第 3 条。
- **登记面**：public_api +6、test_targets +1、unsafe 318→320（mm U2 +1、ktests/mm U2 +1
  与 U6 +1）；lock-order.md / vectors.toml / 棘轮零改动。
- **状态**：仍"提议"，与 063/064/065/066 同例；采纳随 W2 收尾裁决。

## 未决

1. **完整缺页矩阵**（栈增长/COW/写保护错误分级）在 W3 的 VmaTable（方案 :147 后半），
   本帖只交"按需清零 + 单 AS 接缝"。
2. **copy_*_user 对惰性页的预故障入口**：W2 拒（NotMapped）；W3 若 init 路径需要，
   须另裁"先填后拷"或"验证放行+窗口内修复且放锁填充"两条之一。
3. **每-AS 隔离**：mm 全局表今天跨任务可读（单地址空间事实）；W3 后 demand_zero_try
   必须按 current 的 AS 过滤，届时补"别的 AS 的同 VA 不许被本任务故障填出"的负样本。
4. 双核竞争在生产路径的可达性依赖 W3（本帖机制层已证）；真机/KVM 无新时长结论（ADR-024 口径）。
5. `MAX_LAZY_REGIONS=8 / MAX_LAZY_PAGES=16` 无 workload 依据（与轮槽/等待槽同一批欠账，
   有真实调用者时按数据改）。