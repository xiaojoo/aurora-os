# ADR-064：KBuf 大块分配经 HHDM 直接寻址，填 ADR-018 留的大缓冲口子

状态：提议（2026-11-08，W2 内存分层 P2；证据来源 kernel/src/mm.rs 当前实现 + ADR-018）
关联：ADR-018（堆 ≤2048、大缓冲路径明确推迟）、ADR-063（FrameInfo/引用计数、phys_alloc 走 refcnt）、
ADR-029§4（DMA 大缓冲先例）、完整化方案 §6 W2 条目 2 / §6.5.1、BACKLOG M2-b

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计。每条结论标「实测」或「推断」。
> 本帖决策先于实现：定 KBuf 形状与协议，实现与证红在 P2 切片。

## 背景

ADR-018 决策 2 把"超过 LARGE_MAX=2048 字节的请求"明确失败，**不做大对象的看起来能用路径**，
理由是 `GlobalAlloc` 接口里无处安放 `mm::Mapping` 的物理页所有权（硬做要另建全局表，表自己又需要
分配器 ⇒ 循环依赖）。后果节明说这条"不覆盖物理帧耗尽时的降级策略，那些各自需要独立 ADR"。

方案 §6 W2 条目 2 指定的口子正是：**`phys_alloc(order)`（已有）经 HHDM 直接寻址交出连续大缓冲，
不占 VA 保留表**，API 形状 `KBuf`（RAII，带台账模块号）；堆仍 ≤2048。§6.5.1 规则：凡按外部输入
大小开缓冲的路径，必须用 KBuf 或流式。BACKLOG M2-b 点名"网络 mbuf / 块层 / 帧缓冲拿不到内存"。

关键事实（实测，mm.rs）：
- HHDM 用 2MiB 大页映射到 `max_phys`（mm.rs:8 注释、take_over 的 HHDM 铺映射）；
  `PhysAddr::via_hhdm`（mm.rs:244）= phys + hhdm()。
- `phys_alloc(order, owner)`（mm.rs:1525）分 2^order 连续帧，限制在 `max_phys/PAGE` 内 ⇒
  分出的帧**必然落在 HHDM 覆盖区**，无需另建页表映射、无需占 VA 保留表。
- P1 之后 phys_alloc/phys_free 走 FrameInfo refcnt，归还逐帧记账（ADR-063 P1c）。

## 决策

1. **KBuf 形状**（mm.rs，memory 模块）：
   ```rust
   pub struct KBuf { frames: OwnedFrames, ptr: *mut u8, len: usize }
   impl KBuf {
       pub fn new(bytes: usize, owner: ModuleId) -> Result<KBuf, MmError>;
       pub fn as_ptr(&self) -> *const u8;
       pub fn as_mut_ptr(&mut self) -> *mut u8;
       pub fn len(&self) -> usize;
       pub fn as_slice(&self) -> &[u8];
       pub fn as_mut_slice(&mut self) -> &mut [u8];
   }
   ```
   - `new`：`pages = bytes.div_ceil(PAGE)`，`order = pages.next_power_of_two().trailing_zeros()`，
     `phys_alloc(order, owner)?`；`ptr = via_hhdm(base)`；`len = bytes`。
   - **不占 VA 保留表、不建页表映射**：直接用 HHDM 别名（它已映射全部 max_phys）。这是与
     `Mapping`（占 VA、建映射）的根本区别，也是 ADR-018 循环依赖的解法——KBuf 不经 GlobalAlloc，
     所有权就在 KBuf 自己的 `OwnedFrames` 字段里，无需全局表。
2. **分配即清零**（eager zero）：`new` 里 `write_bytes(ptr, 0, frames.count()*PAGE)`。
   理由：自由帧上次释放被毒化成 0xA5（mm.rs fi_final_free），不清零会把陈旧物理内存交给调用方，
   调用方若转给用户/设备就是信息泄漏。这与 P5 的 **demand-zero**（懒清零、缺页触发）是两回事：
   KBuf 是 eager，分配时一次 memset。
3. **RAII 归还**：KBuf 无自定义 Drop——`OwnedFrames` 字段随 KBuf 析构自动 drop，走 phys_free
   → refcnt 到 0 → 毒化 + 台账 + free_frames（ADR-063）。KBuf 是独占主人（refcnt 1）；若要共享
   其中某帧，走 frame_get（P1c），但 KBuf 本身这一段连续帧的设计用途是独占 I/O 缓冲。
4. **台账**：owner 由调用方传入（ModuleId），phys_alloc 逐帧记 account_alloc(owner,1)，
   归还逐帧 account_free(owner,1)（ADR-063 P1c 的 ledger_alloc/ledger_free）。KBuf 不新增记账路径。
5. **失败出口**：`new` 返回 `Result`，phys_alloc 的 OutOfMemory/NotInit 原样上传——**可传播**，
   不走 GlobalAlloc 的 L4 停机（那才是 ADR-018 的堆路径）。调用方按 §9 三级资源错误处置。
6. **上下文**：KERNEL（可睡眠/可阻塞的路径）；**中断上下文禁用**（phys_alloc 取 PMM 锁、可能 OOM，
   与堆同律，§6.5）。不在持堆锁时构造/丢弃 KBuf（drop 走 phys_free 取 PMM，堆锁 10 < PMM 30 方向虽合法，
   但 drop 可能阻塞，禁持堆锁丢弃 Mapping 同理）。
7. **登记面**：`memory.public_api` 补 `mm::KBuf`。KBuf 在 mm.rs 内，引用 phys_alloc/hhdm/OwnedFrames
   都是模块内（无边）；对 resource 的引用仍走 ledger_* 两助手（环内 memory->resource 棘轮不动）。
   unsafe（write_bytes/from_raw_parts/from_raw_parts_mut）登记 U2，写明指针来源/范围/对齐/生命周期/并发。

不涉及：堆 LARGE_MAX（仍 2048，ADR-018 不动）、VA 保留表（P3）、GlobalAlloc 出口（ADR-018 不动）、
锁序数值、syscall 号、日志契约。

## 备选方案

- **经 GlobalAlloc 做大对象（Vec/Box 大缓冲）**：拒绝（ADR-018 已决）。接口无处放帧所有权，
  硬做建全局表 ⇒ 循环依赖。KBuf 是显式 Result + 自持所有权，绕开这条。
- **KBuf 占 VA 保留表 + 建映射（像 Mapping）**：拒绝。大缓冲按外部输入大小开，会吃光 VA 表
  （BACKLOG M2-b 的"表满拒绝"）；HHDM 已映射全部物理内存，直接寻址零额外页表/VA 成本。
- **KBuf 不清零（交给调用方写满）**：拒绝作默认。陈旧帧毒化是 0xA5 不是 0，转给用户/设备会泄漏；
  eager zero 一次 memset 相对 I/O 成本可忽略。调用方若要免清零可另议 `new_unzeroed`（本帖不提供）。
- **KBuf 自定义 Drop 手动 phys_free**：拒绝。OwnedFrames 字段自动 drop 已走 refcnt 归还，
  再写一遍 Drop 是重复且易错（drop 顺序、双重释放）。让字段析构做事。

## 影响

- 正面：内核第一次能拿 64KiB–16MiB 连续大缓冲（mbuf/块层/帧缓冲的前置），不占 VA 表、不经堆 L4。
- 代价：eager zero 每次分配 memset 整段（最大 16MiB）；KBuf 独占一段连续帧，大 order 在碎片化时
  可能 OOM（phys_alloc 线性扫连续 run）——这是连续分配的固有代价，调用方按 Result 处置。
- 对已有 ADR：填 ADR-018 后果节留的口子（不改 ADR-018 的堆决策）；复用 ADR-063 的 refcnt/台账。
- 产品调用者：本帖交付 KBuf + 验收用例；mbuf/块层/帧缓冲的真实接入在 W5/W6（与 P1 地基先于 COW 同形）。
- 用例数与矩阵：P2 新增 KBuf 验收用例，矩阵整轮复验。

## 验收与负样本（P2 实现时兑现，本帖预注册）

- **各规格回基线**：64KiB–16MiB（2 的幂共 9 档）逐档 `new`→写满图案→读回逐字节同→drop，
  每档 drop 后 `free_frames` 与台账 live 回该档分配前基线。反空转：alloc 后 free_frames 必须减少。
- **清零见证**：new 之后、写之前首字节读回 0（eager zero 生效）；变异"不清零" ⇒ 读回 0xA5 ⇒ 红。
- **泄漏证红**：变异 `new` 里 `mem::forget(frames)`（KBuf 不持所有权）⇒ drop 不归还 ⇒
  free_frames 不回基线 ⇒ 红。
- **越界拒绝**：`new(0)` 返回 Err（InvalidAddress）；超大 order 分不出连续帧返回 OutOfMemory（可传播，非 L4）。
- 第二台仪器：宿主机解析验收用例日志的各档 base/alloc/free 读数，与内核自报对账（P2 定行格式）。

## 迁移与回滚

- 迁移：P2 加 KBuf + 验收用例；W5/W6 把 mbuf/块层的大缓冲路径改走 KBuf（届时各带 ADR/用例）。
- 回滚：删 KBuf 与用例、删 public_api 登记与 unsafe 普查行。回滚后大缓冲口子回到 ADR-018 的"明确失败"。
- 不可回滚部分：无（不动盘上格式、不动 syscall）。

## P2 落地记录（2026-11-08，实测）

- **验收读数（build/run-001.log）**：`kbuf(P2): 9档64KiB-16MiB 回基线=true 清零=true 写满读回=true`，
  `t_kbuf_large_alloc -> ok`，`ktests total=66 passed=66 failed=0`，判定 PASS（用时 4.2s，16MiB 档仅增 ~0.2s）。
  写满/读回用 u64 字图案（各档皆 8 的倍数，无尾字节），等价逐字节写满读回。
- **负样本（两条都咬，实测）**：
  - MUT-P2-1（`new` 去掉清零 write_bytes）⇒ `清零=false`、判定 FAIL(35)（首末字节读回 0xA5 非 0）。
  - MUT-P2-2（`frames` 字段改 ManuallyDrop，KBuf 不归还）⇒ 9 档全 `不回基线`（free 停在 alloc 水位、
    live回=false）、判定 FAIL(35)。泄漏逐档累积，证 RAII 归还是回基线的唯一来源。
  - 两条还原后均回 PASS。
- **登记**：`memory.public_api` 补 `mm::KBuf`；unsafe 普查 mm U2 28→31（write_bytes/from_raw_parts/
  from_raw_parts_mut），total 302→305。环内棘轮不动（KBuf 在 mm.rs 内，对 resource 仍走 ledger_* 两助手）。
- **new(0) 拒绝**：验收用例首格断言 `KBuf::new(0).is_ok()==false`（实测通过）。
- **矩阵复验**：首跑 42/43，唯一不符是"投递三层由控制器事件数到"行的 **timer-window 格**
  （第一段窗口 取到=2>投出=1，PIT trace 窗口边界竞态），**与 KBuf 无关**；定向复跑该变体 5/5 全过，
  全矩阵重跑 **43/43 全符合**。KBuf 见证在 50 份留档里 44 份跑到、三格全 true、零失败。
  偶发备注见 BACKLOG（不松判据，那是 71a 同源错法）。

## 未决

1. **大 order 碎片化**：16MiB 连续 run 在长跑碎片化后可能分不出。本帖验收在新鲜启动跑；
   长跑/真机的连续分配成功率要另测（必要时补 buddy/compaction，那是另一个里程碑）。
2. **免清零变体**（new_unzeroed）与 **KBuf 共享**（frame_get 其中帧）本帖不提供，等有真实调用者再议。
3. **中断上下文禁用**目前同堆是约定（§6.5），无机制门禁；列为 M3a 前门禁项（ADR-018 已记）。