# ADR-063：页帧元数据 FrameInfo 与引用计数替换静态位图

状态：提议（2026-11-08，W2 内存分层地基切片 P0；证据来源 kernel/src/mm.rs 当前实现）
关联：ADR-019（PMM 只 free Usable、回收幂等）、ADR-023（归还帧前的 shootdown 顺序）、
ADR-027（固定 MAX_OWNED=8 的所有权）、ADR-018（堆 ≤2048，大缓冲另走）、
完整化方案 §6 W2 条目 1、BACKLOG M2-a/M2-c、lock-order.md（PMM 30 / LEDGER 40）

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计。每条结论标「实测」或「推断」。
> 本帖是 P0（决策先于实现）：只定形状与协议，不改产品代码。实现与证红在 P1 切片。

## 背景

PMM 今天每帧只有 **1 bit**（实测：`State.bitmap: [AtomicU64; BITMAP_WORDS]`，mm.rs:274；
`BITMAP_WORDS = 4GiB/PAGE/64 = 16384` ⇒ **128 KiB 静态**，mm.rs:51；`MAX_PHYS_COVER=4GiB`，mm.rs:50）。
所有权是**每_handle_**的（`OwnedFrames{base,order,owner}`，mm.rs:163）加**每模块**台账
（`resource::account_alloc`，mm.rs:1451），没有任何**每帧**元数据（实测：mm.rs 无 refcnt/FrameInfo）。

这挡住三件事（完整化方案 §6 W2）：COW、共享内存、页缓存——它们都要"同一帧有几个主人"。
台账也答不出"哪一帧还活着"（BACKLOG M2-c，resource.rs:4-6 按模块聚合）。
位图按 4 GiB 最坏情况静态背 128 KiB，而本机 usable 只到 ~503 MiB（mm.rs:46 注释），
方案要求"按内存映射动态分配，顺手替换静态位图"。

引用计数是这三件事的**共同前提**，所以它必须先于 KBuf 共享、缺页 COW 落地。

## 决策

1. **FrameInfo 形状**（每帧一条，按帧号索引）：
   ```rust
   struct FrameInfo {
       refcnt: AtomicU32,   // 0 = 自由；>=1 = 活着的主人个数
       flags: u8,           // FREE/USED/RESERVED/EARLY（位标志）
       owner: ModuleId,     // 最后一个 alloc 的模块（台账归账用；共享时记首个主人）
   }
   ```
   大小约 **8 字节/帧**（推断：AtomicU32=4 + flags=1 + ModuleId=u16 见 mm.rs:106 =2，按 4 对齐 ⇒ 8）。
   **refcnt 取代位图**：`refcnt==0 && flags&FREE` ⇔ 今天的 `bit_get==false`。
   `free_frames`/`total_frames` 聚合计数保留（mm.rs:275-276），语义不变。
2. **动态分配 + 两阶段引导**（解决"元数组自己也要占帧"的循环）：
   - 数组大小按 `max_phys/PAGE`（实际内存映射）算，经 HHDM 直接寻址，**不占 VA 保留表**。
   - `init_allocator`（mm.rs:1389）改两阶段：**阶段 A** 仍用现位图把 Usable 放开、
     从中 `phys_alloc` 出 FrameInfo 数组自身的帧并标 USED；**阶段 B** 把位图状态平移进
     FrameInfo（每帧 refcnt = 已用?1:0），置 `frame_info_ready`，之后分配/释放走 FrameInfo。
     位图在阶段 B 之后**退役**（删除或留作引导期临时量，P1 定）。
   - 这样元数组的帧由"它要替换的那个分配器"分出，不必另造一套 bootstrap 分配器；
     早期池（EARLY_POOL_PAGES=24，.bss，mm.rs:48）只管页表页，不背 FrameInfo。
   - **元数组自身的帧归 `MOD_BOOT`、永不归还**（与页表页同形，mm.rs:1448）：阶段 A 分出即标 USED，
     阶段 B 平移后 refcnt=1/flags USED，台账上一直挂着——这是对的，不是泄漏。
     数组覆盖到它自己的帧是**正常**的（它覆盖全部帧），不是循环：阶段 B 把这些帧标 USED 即可。
3. **引用计数协议**：
   - `phys_alloc` 分出一帧 ⇒ `refcnt=1`（独占主人，与今天 OwnedFrames 语义一致）。
   - 共享：`frame_get(frame)` ⇒ `refcnt.fetch_add(1)`，返回一个共享凭证；
     `frame_put(frame)` ⇒ `fetch_sub(1)`，**减到 0 才归还**（清 FREE、毒化、`account_free`、`free_frames++`）。
   - **并发前置（多核安全的关键，AP 也会 phys_alloc，smp.rs:208）**：`frame_get` 只能由**已持有一个参考**
     的上下文调用（手里有 `OwnedFrames`/共享凭证，或正在一段已锁住该帧的临界区里）。
     这条保证 get 不会与"1→0 归还"竞争：只要还有人能 get，refcnt 就不会到 0。
     **弱引用 get**（不持参考、按帧号查表再 get）本帖**不提供**——它需要 RCU/类型标记那套，留到真有
     调用者（页缓存查表）那天另起草。`put` 用 `fetch_sub` 的返回值判 0：只有看到旧值==1 的那个上下文
     进 PMM 锁归还，别的 put 不归还；0 之后再 put ⇒ DoubleFree。
   - **多一次 put**（refcnt 已 0 再 put，或 put 一个 FREE 帧）⇒ `MmError::DoubleFree` ⇒ 沿用
     `free_violation` 升 L4（mm.rs:1512）。这是今天位图 DoubleFree（mm.rs:1474）的等价物。
   - `OwnedFrames::drop`（mm.rs:181）改为走 `frame_put`；独占帧 refcnt 1→0 即归还，行为与今天逐字相同。
4. **锁与上下文**：
   - refcnt 用 `AtomicU32`，`get`/`put` 的增减**无锁**（原子）；但"减到 0 → 归还自由池 + 改计数 + 台账"
     这一段在 **PMM(30)** 锁内做（与今天 phys_free 持 pmm() 一致，mm.rs:1462）。
   - 台账 `account_free` 在最终归还时调（PMM→LEDGER(40)，方向合法，lock-order.md:13）。
     **共享帧的中间 get/put 不动台账**（台账记"活着多少帧"，不是"多少凭证"）；只在 1→0 与 0→1 记。
   - **记账粒度不变**：`OwnedFrames`（独占、order 段）释放时仍按**整段 n 帧**一次 `account_free(owner, n)`，
     与今天 phys_free（mm.rs:1485）的调用次数一致——`free_calls`/`alloc_calls` 是用例观测的量
     （ktests/heap.rs:18 断言 alloc_calls、ktests/resource.rs:19 打印 calls），逐帧记账会把它们放大 n 倍。
     所以引用计数逐帧管生死，台账按段记调用：`frame_put` 内部逐帧减 refcnt，但台账由释放整段的那一层
     （OwnedFrames::drop）一次记。共享凭证（P1 定形状）若单帧 put 到 0，则按单帧记一次。
   - 归还若涉及解映射，仍走 ADR-023 的 shootdown 顺序（本帖不改它；COW 的解映射在 W3）。
   - 上下文 KERNEL/IRQ_OFF/PANIC；不睡眠、不在持堆锁时归还（`Mapping::drop` 禁持堆锁，lock-order.md:103-107）。
5. **保留的不变量**（替换位图不许丢）：
   - 释放后毒化 0xA5（mm.rs:1481-1484）；低 4KiB 不用（mm.rs:1412）；只 free Usable（ADR-019）；
     页表页 owner=MOD_BOOT 永不归还（mm.rs:1448）；`fault-double-free` 注入链（mm.rs:1494）继续有效。
6. **登记面**：FrameInfo/共享凭证若成为 pub，补 `memory.public_api`（同轮带本帖，check-interface-change）。
   mm.rs 内部新增引用是**模块内**（memory.source_modules=["mm","heap"]），不新增环内边 ⇒ 棘轮不动；
   若 P1 实测某条环内边站点数变了，按 ADR-044 收紧登记（不许抬数）。

不涉及：VA 保留表（另帖 supersede ADR-041）、KBuf 大缓冲（另帖扩展 ADR-018）、
COW/缺页/每-AS（W3）、锁序表数值（PMM/LEDGER 不变）、syscall 号、日志契约。

## 备选方案

- **静态最坏情况 FrameInfo 数组（1M 帧 × 8B ≈ 8 MiB .bss）**：拒绝。方案明确要"按内存映射动态分配"；
  本机 usable ~503 MiB 只需 ~1 MiB，静态背 8 MiB 是位图 128 KiB 的放大版浪费，且 >4GiB 仍要扩。
- **FrameInfo 与位图并存（位图管自由/已用，FrameInfo 只加 refcnt）**：拒绝。两套真相会漂移
  （"位图说自由、refcnt 说活着"），DoubleFree 判定要同时查两处。refcnt==0 即自由，单一真相。
- **refcnt 放台账里（resource 按帧记）**：拒绝。台账是 core 层按模块聚合（resource.rs），
  让它背每帧数组会改它的职责与锁（LEDGER 40 是叶子）；帧元数据归 PMM 拥有（ADR-019 的所有权先例）。
- **引导期另造一套 bootstrap 分配器供 FrameInfo 用**：拒绝。两阶段复用现位图最省，
  位图本来就是已验证的分配器；另造一套等于在替换它之前先维护它的两份。
- **refcnt 用锁保护而非原子**：拒绝。get/put 会在共享路径上频繁调用，原子增减无锁更轻；
  只有"归还自由池"那段需要 PMM 锁（与今天一致）。

## 影响

- 正面：每帧有 refcnt/owner ⇒ COW/共享/页缓存有了地基；台账能答"哪帧活着"（M2-c）；
  元数组按实际内存定尺（M2-a 的静态 128 KiB 退役）。
- 代价：每帧 1 bit → 约 8 字节，元数据内存约放大 64 倍（本机 ~128K 帧 × 8 ≈ 1 MiB，推断），
  且这 1 MiB 从 usable 里扣（位图那 128 KiB 是 .bss 不扣 usable）⇒ free_frames 比今天少约 256 帧，
  等价用例的基线要按"扣除元数组"重算；两阶段引导增加 init 复杂度；`OwnedFrames::drop` 与 `phys_free` 要改走 frame_put。
- 对已有 ADR：扩展 ADR-027（固定 8 条所有权之外有了每帧引用计数）；ADR-019/023 的语义保留不改。
- 不直接交付 COW/共享内存（那是 W3 + 本帖地基）；本帖只交付"计数会咬、独占行为不变"。
- 用例数与矩阵：P1 落地时新增 refcount 用例与负样本，矩阵整轮复验（本帖 P0 不改运行行为）。

## 验收与负样本（P1 实现时兑现，本帖预注册）

- **独占行为等价**：同一组 alloc/释放模式，替换位图前后 `free_frames`/`total_frames` 逐次相同
  （基线按"扣除元数组自身帧"重算）；台账 `Σlive==Σalloc−Σfree` 不变、`alloc_calls`/`free_calls` 不变
  （记账按段，见决策 4）；`fault-double-free` 仍升 L4（39），`L4 integrity: DoubleFree` 那条不变。
- **计数会咬**：共享帧 N 次 get、N 次 put 才归还（`free_frames` 在第 N 次 put 才 +1）；
  第 N+1 次 put ⇒ DoubleFree 升 L4。变异：把 `frame_put` 的"减到 0 才归还"改成"每次都归还" ⇒ 红。
- **漏 put 回不了基线**：get 之后故意不 put ⇒ 台账 live 与 free_frames 不回基线（变异证红，
  沿用方案 §6 W2 验收"漏 put ⇒ 红"）。
- **引导自洽**：FrameInfo 数组自身的帧在阶段 B 后 refcnt==1/flags USED，不被当自由帧分出去；
  init 后 `free_frames` 与"位图口径独立重算"一致（第二台仪器，沿用 M2 的对账形态）。
- 第二台仪器：宿主机解析 init 日志的 frame_info 尺寸/引导占用，与内核自报对账（P1 定行格式）。

## 迁移与回滚

- 迁移：P1 先加 FrameInfo 与两阶段 init（位图仍在），跑等价用例；再让 phys_alloc/phys_free 走
  FrameInfo、退役位图；最后接 frame_get/frame_put 与共享凭证。每一步独立过门禁。
- 回滚：恢复位图路径（FrameInfo 留作只读影子或删除）。回滚后 COW/共享地基没了，但独占行为不变。
- 不可回滚的部分：无（本帖不动盘上格式、不动 syscall）。

## P1a 落地记录（2026-11-08，影子模式实测）

- **引导读数（实测，build/run-001.log）**：`frame_info 影子 帧条目=130780 字节=1046240 引导自洽=true`。
  8 字节/帧证实（审查记录第 4 条）；元数组占 256 帧（1 MiB / 4 KiB），free_frames 比改前少 256
  （116787 → 116531），与"元数组从 usable 扣"一致。`ktests total=63 passed=63 failed=0`，判定 PASS。
- **影子模式**：位图仍驱动分配，FrameInfo 只在引导时被填充并与位图逐帧对账；P1b 才接管。
- **诊断路由（实现期发现，补决策 4）**：引导失败/影子不符**不在 mm 里打 fatal**——`init_allocator`
  改返回 `Result<(), MmError>`，`frame_info_shadow_mismatch()` 是 pub 谓词，由 main（integration）
  记日志/停机。原因：环内 `memory->diagnostics` 受 ADR-044 棘轮约束（登记 7），mm 里新增两处
  `log_fatal!`+`exit::finish` 会把它涨到 9 ⇒ 红。integration->diagnostics 不套棘轮，故路由出去。
  这是"新规则配负样本"之外的另一条纪律：**新增致命路径不许喂胖环内诊断边**。
- **登记**：`memory.public_api` 补 `mm::frame_info_size`、`mm::frame_info_shadow_mismatch`；
  unsafe 普查 mm U2 21→23（引导写入 + 只读对账两处，白名单已写指针来源/范围/对齐/生命周期/并发）。
- **负样本（P1a 预注册，P1b/P1c 兑现）**：影子对账本身是引导见证；把平移循环改成"全填 0"
  ⇒ `frame_info_shadow_mismatch` 返回首个已用帧 ⇒ main 停机（证它对漂移会咬）。

## 审查记录（2026-11-08，P0 起草后自审，对照源码）

方向不变（refcnt 单一真相、两阶段引导、保留不变量都成立），收紧七处：
1. **并发前置**（关键）：决策 3 补"frame_get 只能由已持参考的上下文调用"，弱引用 get 本帖不提供。
   依据：AP 也并发 phys_alloc（smp.rs:208），不写清这条则 get 与 1→0 归还竞争。
2. **记账粒度**（关键）：决策 4 补"台账按段记调用"，保住 alloc_calls/free_calls（ktests/heap.rs:18、
   resource.rs:19 观测它）；逐帧 put 只管内生死，不逐帧记台账。
3. **引导帧归属**：决策 2 补"元数组帧归 MOD_BOOT、永不归还"，与页表页同形。
4. **尺寸**：ModuleId 实为 u16（mm.rs:106）⇒ FrameInfo ≈ 8 字节（非 12）；放大 64 倍、本机 ~1 MiB；
   并补"元数组从 usable 扣、free_frames 基线要重算"。
5. **等价判据**：验收补台账 Σlive 不变量与 call counts。
6. **未决 5 重述**：真实风险是阶段 A/B 一致性，"自指"是伪问题。
7. **状态**：P0 仍"提议"；P1 实现并证红后转"已采纳"。

## 未决

1. **FrameInfo 精确尺寸与对齐**（owner 收窄到 u8 还是 u16、flags 位定义）P1 按实测内存占用定。
2. **共享凭证的所有权形状**（`SharedFrame` RAII 还是裸 get/put + 台账）P1 定；本帖只定 refcnt 协议。
3. **>4GiB 支持**：本帖仍按 `MAX_PHYS_COVER=4GiB` 定尺（与今天一致）；动态定尺已为扩到真内存铺路，
   但 >4GiB 的 HHDM/位图退役要另测（真机 M7，ADR-024 口径）。
4. **COW/缺页/每-AS VMA** 全在 W3；本帖的 refcount 是它的必要非充分前提。
5. **两阶段引导的真实风险是阶段 A/B 一致性**（不是"自指"——数组覆盖自己的帧是正常的，
   决策 2 已写明阶段 B 标 USED 即可）：元数组的帧必须在阶段 B 平移**之前**就被位图标 USED，
   否则平移后它们被当自由帧分出去。验收"引导自洽"那条盯这个。P1 实测若两阶段对不上，
   改用早期预留一段连续帧兜底，届时在本帖补记。