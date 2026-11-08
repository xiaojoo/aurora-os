# ADR-066: split_huge 以翻译等价方式拆 2 MiB 大页，map_hole 建 HHDM 未覆盖的高地址 UC 窗口

状态：提议（2026-11-08，W2 内存分层 P4；证据来源 kernel/src/mm.rs 当前实现 + BACKLOG M2-a/M2-c/§139）
关联：手册 §6.3（R13 所有权）§6.6（shootdown）、ADR-023（协议与 TCG 量不到的那一半）、
ADR-026（生效位）、ADR-063（FrameInfo/台账/MOD_BOOT 页表页永不归还）、ADR-064（HHDM 直接寻址）、
ADR-065（VA 区间表）、ADR-045（登记口径）、完整化方案 §6 W2 条目 4、BACKLOG §139（P4 切片）

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计；发现冲突先记差异，
> 不要为了让文档一致去改已经验证的结论。每条结论标「实测」或「推断」。
> 本帖决策先于实现：定接口与协议，实现与证红在 P4 切片。

## 背景

原始定义原文（三处，本帖语义以它们为准）：

- BACKLOG M2-a（BACKLOG.md:18）：「**4 GiB 之上的 MMCFG / PCI MMIO 窗口没有映射**，M5 做
  PCIe ECAM 与 MMIO 时必须扩表（大页或高地址窗口）」；对策「**M5 前**：`map_hole(va, size)`
  一类接口，且要按 PAT 用 UC」。
- BACKLOG M2-c（BACKLOG.md:33）：「**拆分 2 MiB 大页（split）未实现**，`map` 落在大页覆盖的
  VA 里只能返回 `HugeConflict`」；对策「实现 `split_huge(va)`（把 PD 大页换成 512 个 PT 叶子，
  物理帧沿用同一块），并补一条"拆分前后翻译等价"的用例」；动机原文：「M5 要在 HHDM 尾部
  **未对齐**的物理上界附近铺 4 KiB 映射、**或按 PAT=UC 重铺 MMIO** 时，拒绝就等于做不了事」。
- 完整化方案（:146）：「`split_huge`（M2 未完项）与 MMIO 高地址窗口 `map_hole(va, size, UC)`，
  供 ECAM 多段、MSI-X 表、NVMe BAR」；验收（:155）：「`split_huge` 前后翻译等价」。

现状（实测，源码行号）：

- HHDM 用 2 MiB 大页铺到 `align_up(map_top, LARGE_PAGE)`（mm.rs:838-842）；`map` 与
  `map_mmio` 对落进大页的显式 VA 返回 `HugeConflict`（mm.rs:1077-1080、611-614）。
- `walk_leaf` 遇大页拒绝下钻（mm.rs:980-986）；`huge_block_of` 单独报块基址（mm.rs:1017-1035）。
- 页表页走 `new_table_frame`：`phys_alloc(0, MOD_BOOT)` + forget + `PT_PAGES+1`，永不归还
  （mm.rs:938-952；ADR-063 保留不变量）。
- shootdown 协议：请求方持 VMM(20)，逐 CPU 点名 IPI，等回执，上界 20M 周期、到期 L4
  （mm.rs:1202-1251）；处理方不拿任何锁（mm.rs:1186-1198）。**TCG 观测不到陈旧 TLB**，
  本机只能验协议计数（ADR-023 原文）。
- 旧负样本 `KT_HUGE_CONFLICT`（ktests/mm.rs:297-324）：不拆仍拒绝，且无新页表页、无
  map_calls、帧随 Drop 归还。**本帖保留它原样**。

两条结构性事实（推断，源码走读，实现期由用例确认）：

1. `alloc_va_range` 跳过 `is_mapped` 的 VA，而 `is_mapped` 对大页返回 true（mm.rs:1321）
   ⇒ 自动发 VA 的路径（`map_mmio`/`map_device`）**今天发不进大页内部**；`HugeConflict`
   真正卡的是"显式 VA 铺 4 KiB"与"按页改属性"，即原文点名的两种形状。
2. `map_device`（mm.rs:1124）**没有** HugeConflict 检查，显式落大页时经 `walk_leaf` 拒绝
   下钻而误报 `OutOfMemory`。本轮不顺手修（硬约束：不顺手重构），记未决 2。

与阶段 A 任务书的两处差异（按"以原文为准"记录，不藏）：

- 任务书把 map_hole 描述为"去掉 HHDM 里那份 WB 映射或换成设备属性"。原文的主语义是
  "给 HHDM **未覆盖**的窗口建 UC 映射"；"按 PAT=UC 重铺"是 split 的动机之一，但原文没给
  重铺的语义与基线。本帖交付主语义 + split 机制；**覆盖内重铺推迟**（决策 5），因为
  它与"页表页 MOD_BOOT 永不归还"不变量相撞（见该决策）。
- 任务书验收 e 的"drop 后页表回基线"按字面不可能：新 VA 链的页表页与 split 的 PT 页同形，
  永久挂账（ADR-063）。本帖把"回基线"重新定义为 **VA 保留/叶子翻译/帧账回基线，页表页
  增量永久且被台账见证**（决策 4）。这是对任务书措辞的显式 reinterpretation，不是放宽判据。

## 决策

1. **`pub fn split_huge(va: VirtAddr) -> Result<(), MmError>`**（mm.rs，memory 模块）：
   - 语义：va 可为块内任意页对齐地址；块基址 `block = va & !(LARGE_PAGE-1)`。走到 level-1
     表项：不 present ⇒ `Err(NotMapped)`（A 类，调用方契约错）；带 `P_HUGE` ⇒ 拆分；
     已是 PT ⇒ `Ok(())` **幂等空操作**（不分页、不发 IPI、所有计数不变）。
   - 锁与上下文：全程持 VMM(20)；内部 `new_table_frame` 取 PMM(30)→LEDGER(40)，方向合法
     （lock-order.md:12-13）。KERNEL/IRQ_OFF；**可能阻塞**（等 shootdown 回执）；ISR 禁用。
     不新增锁 ⇒ lock-order.md 不改。
   - 步骤（顺序有意义）：
     a. `new_table_frame()` 取清零 PT 页；失败 ⇒ `Err(OutOfMemory)`（B 类），**原大页原样**
        （此刻尚未碰 PD 项）。注入变体 `fault-split-oom` 在此调用点强制 None（内核侧 cfg
        注入，沿用 fault-shootdown-noack 形状；宿主机改盘注入不适用本帖）。
     b. 经 HHDM 向 PT 写 512 个叶子：`phys = 旧大页物理基 + k*PAGE`；属性位复制旧项的
        P/W/U/NX/PWT/PCD；**PAT 位翻译：大页的 bit12 → 叶子的 bit7**（SDM Vol.3A 4.5；
        本内核今天大页未置 bit12，实测 HHDM 全 RW⇒WB，规则仍写明）；**不复制 P_HUGE**
        （bit7 在叶子里是 PAT，复制即改缓存类型，等价判据会红）。
     c. 单次 8 字节对齐写替换 PD 项：`pt_phys | 旧项的 P/W/U/NX`（上级权限位不许变窄，
        `effective_flags` 逐级相与/相或，ADR-026）。PWT/PCD 只进叶子（它们决定数据页缓存
        类型；非叶级只影响页表页自身的缓存，推断）。
     d. 本 CPU `invlpg(block)` + `shootdown_others(block)` **一次**。
   - shootdown 论证（推断，SDM Vol.3A 4.10.4）：INVLPG 失效覆盖该地址的**任意**条目，含
     2 MiB 条目 ⇒ 块基址一次足够。c 到收齐回执之间别的核若仍用旧大页条目，其翻译与权限
     与新 PT 逐页同构 ⇒ 窗口内无害；收齐后无旧条目。**TCG 会自行失效 ⇒ 本机只验协议计数**
     （requests 增量=1、其它每个在线 CPU 的 acks/invlpg 各 +1、timeouts=0），不宣称验到
     "无陈旧项"（ADR-023 原文，真机/KVM 待重测，ADR-024 口径）。
   - 台账：PT 页经 `new_table_frame` 原样（逐帧 ledger、MOD_BOOT、永不归还）⇒ 成功拆分
     `free_frames` 永久 −1、`page_table_pages` +1，这是拆分的明码代价，与所有页表页同形。
     失败路径（OOM/NotMapped）消耗为零，台账与 free_frames 回基线。
2. **`pub fn unmap(va: VirtAddr, pages: usize)`**：持 VMM 调既有 `unmap_pages`（clear_leaf +
   逐页 shootdown + UNMAPPED_PAGES，mm.rs:1151-1161），**不放手 VA 保留**（调用方自理；
   HHDM VA 本无保留）。只作用于 4 KiB 叶子；对大页/不 present 幂等空操作（调用方要先拆）。
   KERNEL；可能阻塞。真实调用者：本帖验收 b（块内空一叶再 map）与 P5 惰性区间 drop。
   不改 `Mapping::drop`/`MmioMapping::drop` 语义。
3. **`pub fn phys_of(va: u64) -> Option<u64>`**：只读翻译遍历，前提与 `is_mapped` 同（刻意
   不加锁，所有写者在 VMM 内）。返回 va 所在 4 KiB 页的物理基址：叶子 ⇒ 叶子物理基 +
   页内偏移下取整；大页 ⇒ 块物理基 + 块内偏移再下取整到 4 KiB。用途：翻译等价的第二台
   仪器（与金丝雀互证）。不 present/非规范 ⇒ None。
4. **`pub fn map_hole(pa: u64, pages: usize) -> Result<MmioMapping, MmError>`**（原文主语义）：
   - 前置检查（顺序有意义）：① pa 页对齐、pages>0、ready，否则 InvalidAddress/NotInit；
     ② 区间与任何 **usable** _region 相交 ⇒ `Err(InvalidAddress)`（不许把 RAM 的 HHDM
     别名 UC 化）；③ 区间内任一页 `is_mapped(hhdm()+pa)` 为 true（即 HHDM 已覆盖）⇒
     `Err(Unsupported)` + log_warn（覆盖内重铺推迟，决策 5）。
   - 建映射：VA 走 `alloc_va_range`（进登记表），`PageFlags::DEVICE`（PCD⇒UC-，协议固定
     PAT2，mm.rs:32-34 原文），逐页 set_leaf + tlb_invalidate，失败回滚（map_mmio 同形）。
     返回 `MmioMapping`（drop 解映射 + 放手保留、不还帧，mm.rs:593-599 既有语义）。
   - 与 map_mmio 分工：map_mmio 是今天 PCI BAR 路径（自动发 VA、无覆盖检查），**不动**；
     map_hole 是带 usable/覆盖检查的高地址窗口入口，供 ECAM 多段/MSI-X/NVMe BAR（方案原文）。
   - "只剩一种属性"：受支持区间 HHDM 本不映射 ⇒ 映射后仅一份 UC 别名。判据：
     `is_mapped(hhdm+pa)==false` 且新 VA 的 `effective_flags` = user:false/writable:true/
     executable:false/levels:4；UC- 位由见证行打出叶子值，宿主机按 `pa|P|W|NX|PCD` 独立
     重算对账（第二台仪器）。
   - 往返回基线（reinterpretation，见背景）：drop 后 `reservation_count` 与 `free_frames`
     回操作前；叶子清掉；新 VA 链若需页表页则永久挂账 MOD_BOOT（与 map_mmio 今天同形），
     台账 Σlive==Σalloc−Σfree 不变。
5. **覆盖内重铺推迟**：本帖不改任何 HHDM 叶子属性。理由：改属性后 drop 要还 WB 才算
   "回基线"，而 split 的 PT 页按 ADR-063 永不归还 ⇒ 字面基线不可达；coalesce 回大页也还不
   回 PT 帧，且动的是内核活依赖的 HHDM。等 ECAM 真落地（M5/W3）另起草 ADR 定基线语义。
   本帖 map_hole 对覆盖内区间明确拒绝并配负样本。**差异已在背景记录**。
6. **登记面**：`memory.public_api` 补 `mm::split_huge`/`mm::map_hole`/`mm::unmap`/`mm::phys_of`
   （本轮调用者在 ktests；P5 产品路径将用 unmap；ADR-045 单向规则允许先登记）。四个函数
   全在 mm.rs 内、复用既有内部件 ⇒ 环内边站点数不变，棘轮不动（现值 memory->arch 64 /
   resource 2 / diagnostics 7，module-interfaces.toml:673-678）。不新增锁、不新增向量 ⇒
   lock-order.md / vectors.toml 不改。新增 unsafe 逐处登记白名单（叶子填充写、phys_of 读
   遍历），类别由 tools/aurora.py 重算对账，每处 SAFETY 写明指针来源/范围/对齐/生命周期/并发。
7. **日志契约**：只新增两行见证（格式预注册如下），既有行不动；旧负样本日志原样。
   - 默认跑：`split(P4): 等价=true 金丝雀=true 跨别名=true 幂等=true map成功=true 永久PT=1 requests增量=1`
   - 默认跑：`map_hole(P4): 单属性=true 拒覆盖=true 拒usable=true 往返=true leaf={:#x}`
   - 注入跑：`split OOM(P4): err=OutOfMemory 原样=true 回基线=true`
   宿主机各写独立解析函数，逐字段对账；内核绿而宿主机对不上 ⇒ CONTENT-MISMATCH。

## 备选方案

- **拆后叶子填不 present、按需故障**：拒绝。HHDM 是活映射，拆完内核立刻经它访存，
  不 present 等于 ring0 立刻 #PF。
- **shootdown 逐页发 512 次**：拒绝。INVLPG 覆盖大页条目（决策 1 论证），一次块基址足够；
  512 次 IPI 往返纯浪费，协议计数判据也变复杂。
- **叶子复制 P_HUGE**：拒绝。bit7 在叶子是 PAT，WB 变 UC- 族，等价判据红（M1 族变异）。
- **map_hole 同时做覆盖内换属性**：拒绝/推迟，见决策 5（不变量相撞，基线语义未定）。
- **不公开 unmap，验收 b 靠 MmioMapping drop 空叶**：拒绝。MmioMapping 的 VA 来自
  alloc_va_range，进不了大页块内部，空不了块内叶子；P5 也需要 unmap，此刻立并配证红。
- **顺手把 map_device 对齐 HugeConflict**：拒绝（不顺手重构），记未决 2。

## 影响

- 正面：显式 VA 的 4 KiB 铺设解拒；高地址 UC 窗口有带检查的入口；P5 拿到 unmap/phys_of。
- 代价：每次成功拆分永久 −1 帧（PT，MOD_BOOT）；map_hole 新链页表页同形永久；split 持
  VMM 等回执（多核一次往返个位数 µs，ADR-023 实测口径）。
- 对已有：KT_HUGE_CONFLICT 原样绿（它不拆）；ADR-023 协议复用不改；ADR-063 不变量不改；
  `Mapping::drop` 不改。用例数 67 → 69（t_split_huge、t_map_hole；注入变体下 t_split_huge
  改走 OOM 断言，不另加用例）；矩阵 43 → 44（新增 `fault-split-oom` 行，期望 PASS(33)，
  吃自己那一跑的日志与退出码，check-matrix-wiring 会盯）。

## 验收与负样本（P4 实现时兑现，本帖预注册）

- **翻译等价**（t_split_huge，默认跑）：块不写死地址——`phys_alloc(9, MOD_TEST)` 交出的
  2MiB 对齐全自由块即被测块（前提自证：分配成功；各变体都成立，因为它就是分配器扫描）。
  逐页写 `magic^k` 金丝雀（旧翻译），记 `effective_flags`（levels==3）；split 后逐页读回
  金丝雀、权限三字段相等且 levels==4、`phys_of(va)==块物理基+k*PAGE`。
- **反向/跨别名**：拆分后为块内某叶 `unmap(va_k,1)` 再 `map(va_k, 新帧, RW)` 成功（验收 b；
  不拆时同动作仍 HugeConflict，旧负样本已钉）；经新 VA 写金丝雀、经该帧 HHDM 别名读回，
  及反向（两个不同 VA 同物理，双向）。"旧翻译读回"在时间上互斥，由 phys_of 独立遍历充当
  第二台仪器（背景已记此 reinterpretation）。
- **幂等**：二次 split 返回 Ok，PT_PAGES/free_frames/requests 增量全 0。
- **OOM**（fault-split-oom 跑）：err==OutOfMemory；大页原样（is_mapped、levels==3、金丝雀
  完好）；free_frames/PT_PAGES/台账 live 回基线。矩阵该行期望 PASS(33)。
- **map_hole**（t_map_hole）：pa 取 HHDM 覆盖外的 Reserved 窗口（实测 q35 的 IOAPIC
  0xFEC00000，在 map_top 之上）；单属性/有效位/leaf 位宿主机重算/往返回基线四格。
  拒覆盖：pa=0（低 4KiB，Reserved 且 HHDM 映射着）⇒ Unsupported；拒 usable：pa=32MiB
  ⇒ InvalidAddress。
- **变异证红**（每条先红后绿，贴终端原文）：
  - M1：叶子填充物理偏移错一页（k+1）⇒ 金丝雀/phys_of 等价判据红。
  - M2：split 漏 `shootdown_others` ⇒ requests 增量=0，内核与宿主机协议计数判据红。
  - M3：split 的 PT 改走 `early_frame`（绕开 phys_alloc/台账/free_frames）⇒ 永久PT 格与
    台账 Σlive 判据红。
  - M4：map_hole 去 PCD ⇒ 宿主机 leaf 位重算对账红。
- **量具自查**：宿主机解析函数各喂一次改坏的留档日志（改一个字段/删行）⇒ False；真日志
  ⇒ True（§138 同形）。新矩阵行故意共用日志变量 ⇒ check-matrix-wiring 红一次，还原绿。
- **整轮**：check 17/17；默认 run 69/69；矩阵 44 行整轮复验全符合。所有时序/协议结论
  TCG 下测，真机/KVM 待重测（ADR-024 口径）。

## 迁移与回滚

- 迁移：P4 加四函数 + 两用例 + 注入特性 + 矩阵行 + 登记；P5 用 unmap/phys_of（届时 ADR-067
  自己登记引用面）。ECAM 落地时覆盖内重铺另起草。
- 回滚：删四函数、用例、特性、矩阵行与登记；`HugeConflict` 回到"明确拒绝"现状；旧负样本
  不受影响。不动盘上格式、不动 syscall、不动日志既有行 ⇒ 无不可回滚部分。

## P4 落地记录（2026-11-09，实测；BACKLOG §140）

- **读数**：check 17/17；默认 PASS 69/69；矩阵 **44/44 全符合**。split 见证 44 份留档宿主机
  逐格全过；map_hole 45 份全过；OOM 注入档 69/69 PASS、矩阵第 44 行符合。四条变异（M1 错页 /
  M2 漏 shootdown / M3 绕台账 / M4 去 PCD）各自证红后还原绿；M4 内核自判绿而宿主机重算红，
  第二台仪器成立。量具自查与 check-matrix-wiring 负样本各咬一次（原文见 BACKLOG §140）。
- **实现期修正三条**（预注册原文不回改，差异记这里）：
  1. 见证行 `永久PT`/`requests增量` 由 1 改 **2**：用例拆两个块——被测块（phys_alloc(9) 交出）
     做翻译等价，HHDM 尾块做验收 b。原因见下一条约束。
  2. **新约束**：`unmap` 不得清"还将被释放的 RAM 帧"的 HHDM 别名——`fi_final_free` 毒化经
     HHDM 直写，别名缺失即 ring0 #PF（第一版用例现场 cr2=hhdm+0x207000 err=0x2）。验收 b 改在
     尾块**尾页**（≥max_phys、PMM 覆盖外）做"空一叶再 map"，清它无害。该约束已写进 `unmap`
     文档；**P5 的惰性区间住用户窗口（非 HHDM 别名），其 drop 用 unmap 由此约束解释**。
  3. 补 `pub fn leaf_value`（只读回叶子原始值）：决策 7 预注册的 leaf 见证需要读侧，决策 3 的
     phys_of 只给物理地址。与 is_mapped 同纪律，登记进 public_api。
- **两处量具错**（用例自己的，非被测物）：基线取在 frames 分配后致 drop 回帧抬高基线（改取
  分配前）；OOM 见证误打 Option 包壳（改打内层 MmError）。均先红后绿，记 BACKLOG。
- **登记面**：public_api +5（split_huge/map_hole/unmap/phys_of/leaf_value）、test_targets +2；
  unsafe 305→315（mm U2 +6、ktests/mm U6 +4，逐处 SAFETY 见 census）；棘轮/锁表/向量表零改动。
- **状态**：仍"提议"，与 ADR-063/064/065 同例；采纳与否随 W2 收尾裁决。

## 未决

1. **覆盖内重铺**（原文动机②）推迟到 ECAM 落地 ADR；届时先裁"PT 永久 vs 字面回基线"的
   基线语义（本帖背景的 reinterpretation 只覆盖本帖范围）。
2. `map_device` 的 HugeConflict 误报 OutOfMemory 未修（本轮不顺手），随 ECAM ADR 一起裁。
3. TCG 量不到陈旧 TLB：split 的 shootdown 只验协议，真机补（ADR-023 欠账继承）。
4. "持 VMM 等回执 vs 别核持 VMM 等本核回执"的循环等待形状在 map/unmap 并发已潜伏
   （lock-order.md「多 CPU 并发解映射今天只有一个请求方」），split 不发明新种类但加宽
   窗口；有界结局是请求方 6ms L4。W2 不构造该样本，W3 per-AS shootdown 时重测。
5. `phys_of` 锁外读是无保证快照（与 is_mapped 同纪律）；用例只在 BSP 关窗口读，多核压力
   不依赖它。