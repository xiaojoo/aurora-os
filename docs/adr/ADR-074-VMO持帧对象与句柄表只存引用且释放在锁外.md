# ADR-074：VMO 是持帧对象、句柄表只存引用，释放在表锁之外；`aspace_map` 按 AS 写表

状态：**已采纳**（2026-11-09，W3 P4a 落地并实测；两条路线由使用者裁决，读数见"验收读数"）
关联：ADR-007（capability 第一刀与裁决 E）、ADR-063（FrameInfo 引用计数）、ADR-065（VA 保留表）、
ADR-066（`unmap`/`map_hole`）、ADR-067（惰性区间与 demand-zero）、ADR-070（`AddressSpace`）、
ADR-072（shootdown 按位图收窄）、ADR-073（Process/Job）、ADR-047 决策 2 / ADR-048 决策 3（持锁不跨未知回调、
拿队列锁不等跨 CPU 的锁）、`docs/architecture/lock-order.md:22-27`（预先写好的重定级条件）、
手册 §6.3 R13 / §6.4 / §7.1、设计文档 §3.3、`docs/design/w3-立项-依赖图与切片计划.md` §3 的 P4 与 §4 的 Q1

> 写作纪律：本文的决策部分现在有两条**使用者裁决**（2026-11-09）；其余是设计。
> 落地之后按 ADR-070/072 的同一办法把实测读数回填到"验收"，没跑过的一律写"未验证"。

## 背景：三处接缝今天长什么样

1. **句柄表里的对象是 Copy 值、不持帧**：`Entry.obj: Option<FileObj>`（`handle.rs:119`），
   `FileObj = { port, cursor }`（`handle.rs:105-109`）。`close`（`handle.rs:229-240`）与
   `revoke_task`（`handle.rs:355-369`）都在 **RANK_HANDLE(35) 锁内**直接 `e.obj = None`。
   换成持帧对象之后，这一句就变成"持 35 丢 `Mapping` → 取 VMM(20)"的反向嵌套。
   `lock-order.md:25-27` 早就把这一天的两条路写好了：**降到 20 以下**，或**把释放移到锁外**。
2. **页表遍历只认内核那份 PML4**：`walk_leaf` 从 `s().pml4_phys` 起走（`mm.rs:990`），
   不是从当前 CR3 起走。所以 P1 交付的 `aspace_switch` 之后调 `map()`，写的仍然是内核表——
   `mm.rs:1636-1639` 的注释明写这是 P1 故意留下的（"产品路径今天仍然只认 AS_KERNEL"）。
   P4 要把"往指定 AS 写叶子"这件事做出来，就必须让遍历入口认识根表。
3. **新建页表页一律记 `MOD_BOOT` 且永不归还**：`new_table_frame`（`mm.rs:966-980`）
   `phys_alloc(0, MOD_BOOT)` 之后 `core::mem::forget(f)`。而 `AspaceEntry.pt_frames`
   （`mm.rs:1651-1657`）已经预留了"PML4 那张 + 之后按需的"清单，P1 只用了第一张。
   往非内核 AS 铺用户叶子会按需建下级表页，这些页**必须记进那个 AS 的清单并记 `MOD_AS_PT`**，
   否则 AS 销毁之后它们永远回不来（BACKLOG §147 的第 1 条结论）。

另外两条现成先例决定了本文的形状，不是新发明：
- `LazyRegion` 明写"存**数值**而不是 `Option<Mapping>`：后者非 Copy 不能 const 初始化，
  且 `Mapping::drop` 会在已持 VMM 的编排里重入 VMM（重入即 L4）"（`mm.rs:1892-1895`）。
- `release_owned` 是"一次持锁把映射搬出槽位，`drop(bag)` 留在锁外"（`sched.rs:265-287`），
  理由写在 ADR-048 决策 3：拿队列锁去等一把跨 CPU 的锁等于把两条不变量绑成一条。

## 决策

### 1. 锁序走"释放移到锁外"，`RANK_HANDLE` 保持 35（使用者裁决，2026-11-09）

- 句柄表里**只存 Copy 的对象引用**：`ObjRef` 枚举 = `File(FileObj)` | `Vmo { slot: u8 }`。
  对象本体（帧号清单、引用计数）住在 `vmo.rs` 自己的定长表里，由 **VMM(20)** 保护。
- `close` / `dup` / `revoke_task` 的两段式：
  **锁内**校验 + 取走引用（并 bump 世代，让旧句柄立刻 `Stale`）→ **放锁** → `vmo::unref(slot)`。
  `unref` 到 0 才真归还帧，归还路径与 `LazyHandle::drop` 同律（依次取锁，不在锁内做可能阻塞的事）。
- `revoke_task` 的产品调用点在 `sched.rs:343`，**不在 RUNQ 锁内**（前一个 guard 已析构），
  所以"放掉 HANDLE 之后才 unref"这条路上没有 RUNQ⇒VMM 的跨 CPU 等待。这一条是实测核对过的，不是假设。
- `lock-order.md` 要改的只有那段**条件注记**：把"两条路"改成"已选第二条"，并写清新规则
  （表里只存 Copy 引用；对象本体在 VMM 的表里；归还发生在表锁之外）。rank 与"允许在它内部获取 = 台账(40)"**都不动**。
- 为什么不选第一条（降到 20 以下）：那要把 HANDLE 写成 `lock-order.md:103-107`
  "持锁期间禁止丢弃 `Mapping`"的**第二个故意例外**（第一个是 HEAP），而 `Mapping::drop` 会等
  别的 CPU 的 shootdown 回执（上界 `SHOOTDOWN_DEADLINE_CYCLES` ≈ 6 ms）——
  那 6 ms 里全局句柄表带着 IF=0 被堵住，所有 CPU 的每一次句柄操作都排在后面。
  降一级换来的便利，代价是把一个已验证的禁令改出例外，不值。

### 2. VMO 第一刀用**即时帧**，不接 lazy 后端（使用者裁决，2026-11-09）

- `vmo_create(pages)` 当场 `phys_alloc` 并清零 N 页，表里存**帧号数值**（照 `LazyRegion` 同律），
  容量按"接缝够用"定尺：`MAX_VMOS = 8`、`MAX_VMO_PAGES = 16`（与 `MAX_LAZY_REGIONS/PAGES` 同一口径，
  同样欠 workload 依据，写进未决）。
- `vmo_write(offset, bytes)` 经 HHDM 直写帧（ADR-064 同律），`vmo_read_back` 供判据读回；
  两者都要求 `offset + len <= pages * PAGE`，越界明确失败，不静默截断。
- 引用计数：`refs` 从 1 起（创建者那一份），`dup`/`grant` 加一，`close`/`revoke` 减一，到 0 归还全部帧。
  **没有引用计数就不能有 `dup`**：两个句柄各丢一次同一个帧就是 `DoubleFree`（ADR-063 的负样本形状）。
- lazy 后端与"查表带 AS 的 demand-zero"（依赖图 N19）**不在本轮**：lazy 区间今天登记在
  当前 AS 的用户窗口里（`mm.rs:1977` 走 `alloc_user_va_range`），把它改成带 AS 要动 `mm`/`trap`/`hooks`
  三处，改动面比 P4 的其余部分加起来还大。本轮的 VMO 与 lazy 区间是**两种对象**，不互相替代。

### 3. `aspace_map`：按 AS 写叶子，W^X 在构造期拒绝

- 形状：`mm::aspace_map(as: &AspaceHandle, frames: &[u64], va: VirtAddr, flags: PageFlags)
  -> Result<AspaceMapping, MmError>`。**mm 不认识 VMO**（依赖方向：`vmo`/`user` 调 `mm`，反过来不行），
  帧号清单由调用方给。
- W^X 不用新写检查：`PageFlags::new(writable, executable, user)` 已经在构造期拒绝 W+X
  （`mm.rs:148-153`，`MmError::WxViolation`，`t_wx_construction_rejected` 是它的证人）。
  `aspace_map` 只收 `PageFlags`，所以**不可能**收到一个 W+X 的意图——这条是"结构上排掉"，不是"再查一遍"。
- 遍历入口参数化：新增 `walk_leaf_in(root, as_slot, va, create, huge, user)`，
  既有 `walk_leaf(va, …)` 变成 `walk_leaf_in(s().pml4_phys, None, …)` 的薄壳。
  **所有既有调用点一行不改**，所以内核路径的语义逐字不变（矩阵 45 行因此不该有任何一行变）。
  `walk_leaf` 头注释那句"唯一的页表遍历入口"仍然成立：入口还是一个，只是多了一个根参数。
- 按需建的下级表页：`as_slot = Some(i)` 时记 `MOD_AS_PT` 并 push 进 `AspaceEntry.pt_frames`；
  `None` 时保持今天的 `MOD_BOOT` + `forget`。清单满（`AS_PT_SLOTS = 16`）⇒ 明确失败并回滚已铺的叶子，
  不发一条"表页没人还"的映射。
- 每页先 `frame_get(pa)`（ADR-063）再写叶子：映射**不拥有**帧，拥有者仍是 VMO。
  `AspaceMapping::drop` 反过来：逐页 `clear_leaf` + `shootdown_masked(va, running_on)`（ADR-072，
  **这是它的第一个产品调用者**）→ `frame_put(pa)`。顺序不能反：收不齐回执就还帧 = 两个主人同一块页。
- 同一 VA 在两个 AS 里各自映射互不影响（ADR-070 的 A4）：因为根表不同，`AlreadyMapped` 的判定
  也必须在**那棵树**里做，不能查内核树。

### 4. 用户可见面分两步落地（本轮先内核侧）

- **P4a（本轮）**：`vmo.rs` + `mm::aspace_map` + 句柄表的 `ObjRef`/两段式释放 + 三条 ktest。
  号还没有接，所以用户态看不见（与 P3 同一口径）。
- **P4b（紧接着）**：12 `vmo_create` / 13 `vmo_write` / 14 `aspace_map` 三个号按 Q1 的裁决接进
  `user.rs` 那张手写 match，ABI 位与 `docs/design/user-abi-capability.md` 同轮改。
  `aspace_map` 的用户态形状是"映射进**调用者自己的** AS"（今天没有 AS 句柄这种对象，
  11 `process_create` 在 P5 才给每个进程一份 AS）——这条要在 P4b 的 ADR 补记里写清，不许含糊。
- 分两步的理由：每一步都能独立过门禁；把"对象与锁序"和"ABI 号"混在一刀里，
  红了之后分不清是锁序错还是号表错。

## 备选方案

- **降 `RANK_HANDLE` 到 20 以下**：拒绝（决策 1 末段）。要改一条已验证的禁令并制造 6 ms 的全局阻塞窗口。
- **句柄表直接存 `Option<VmoHandle>`（非 Copy）**：拒绝。`Entry` 今天是 `Copy`（`dup` 靠按位复制表项），
  改成非 Copy 要重写 `dup`/`EMPTY`/`reset_for_test` 三处，而且"在锁内 drop 一个持帧对象"这条错法
  会从"编译不过"变成"运行期 L4"——把结构性的防护换成运行期的防护是倒退。
- **VMO 直接包一个 lazy region**：本轮拒绝（使用者裁决），理由见决策 2 末段；留作后续后端之一。
- **`aspace_map` 靠"切到那个 AS 再调既有 `map()`"**：拒绝。`walk_leaf` 用的是 `s().pml4_phys`
  而不是 CR3（`mm.rs:990`），切 CR3 根本不改它写哪棵树；要靠切 CR3 生效就得把遍历改成读 CR3，
  那会让**每一次**内核映射都多一次特权读，并且把"内核表是哪份"从一个静态事实变成一个运行期变量。
- **临时改 `s().pml4_phys` 指向目标根、调完再改回来**：拒绝。那是全局可变状态上的编排，
  另一个 CPU 或一次中断里的 `is_mapped` 会读到别人的根；这种错法在现场表现为"随机页故障"，最难归因。

## 影响

- 正面：持帧对象有了不违反锁序的归宿；`shootdown_masked` 第一次有产品调用者；
  同一 VA 双 AS 的判据（ADR-070 A4）第一次可证；页表页归还得以扩展到"按需建的下级表页"。
- 负面/代价：
  1. `close`/`revoke` 变成两段式，中间有一个"引用已取走但还没 unref"的窗口；
     世代在锁内就 bump，所以旧句柄立刻 `Stale`，但**帧的归还滞后于句柄失效**——
     判据要读 `unref` 之后的台账，不能读 `close` 返回那一刻（与 `read` 的取票/提交同一条口径）。
  2. `walk_leaf` 多一个根参数与一个 AS 槽参数，`new_table_frame` 多一条记账分支：
     这两处是**已验证代码**，改动必须靠"既有调用点一行不改 + 矩阵 45 行不变"来证明没有扰动。
  3. VMO 即时分配 ⇒ 创建就吃帧（16 页上限 = 64 KiB/对象，8 个对象 = 512 KiB），
     比 lazy 后端贵；这是裁决过的取舍，不是遗漏。
  4. `MAX_VMOS`/`MAX_VMO_PAGES`/`AS_PT_SLOTS` 三个数都欠 workload 依据（与 ADR-067 未决 5 同一条）。
- 登记面：`module-interfaces.toml`（新逻辑模块或并入 `memory`/`capability`，落地时定）、
  `unsafe-whitelist.toml` 与 `unsafe-census.md`（`vmo.rs` 的 `UnsafeCell` 与 `walk_leaf_in` 的指针运算）、
  `lock-order.md` 的条件注记、`docs/design/user-abi-capability.md`（P4b）。

## 验收与负样本（设计判据；实测读数在下一节回填）

| # | 判据 | 负样本（变异证红） |
| --- | --- | --- |
| C1 | `vmo_write` 之后读回逐字节一致；越界明确失败不截断 | 去掉长度检查 ⇒ 越界写踩到别的帧，读回格红（或台账红） |
| C2 | 最后一个引用消失后帧全部归还：`free frames`/台账 `live`/`MOD_VMO` 回基线 | `unref` 不还帧 ⇒ 台账红；多还一次 ⇒ `DoubleFree` 升 L4 |
| C3 | `dup` 出来的两个句柄共享同一份帧：close 一个之后另一个仍读得到，两个都 close 才还帧 | 去掉引用计数（每个句柄各持一份所有权）⇒ 第一次 close 就还帧，第二个句柄读到毒化值/`#PF` |
| C4 | **释放在 HANDLE 锁之外**：`close`/`revoke` 的 unref 发生在放锁之后 | 把 unref 搬进锁内 ⇒ `锁序违规，外层 rank=35 本次 rank=20` 当场 L4（这条是裁决那条路线的唯一证人） |
| C5 | `aspace_map` 拒绝 W+X（构造期） | 绕开 `PageFlags::new` 直接构造 W+X 位 ⇒ `t_wx_construction_rejected` 与本格双红 |
| C6 | 同一 VA 在两个 AS 里各自映射成功、互不影响；`AlreadyMapped` 只在**同一棵树**里判 | 遍历仍用 `s().pml4_phys` ⇒ 第二个 AS 撞 `AlreadyMapped`，或写进了内核树（A1 的叶项对照当场不一致） |
| C7 | `AspaceMapping::drop` 之后帧经 `frame_put` 归还，且 shootdown 只通知 `running_on` 位图里的 CPU | 改成全广播 ⇒ ADR-072 的 narrowed 格红；不 `frame_put` ⇒ 台账红 |
| C8 | 非内核 AS 按需建的下级表页记 `MOD_AS_PT` 并进 `pt_frames`，AS 销毁后全部归还 | 仍记 `MOD_BOOT` + `forget` ⇒ `page_table_pages` 与台账 `live` 不回基线（BACKLOG §147 第 1 条的形状） |
| C9 | 收尾判据（ADR-069/073）扩到 VMO：用例造的 VMO 与句柄必须清零 | 造一个不 close ⇒ 收尾门点名（与 P3 的进程/Job 两本账同形） |
| C10 | 内核路径零扰动：矩阵 45 行一行不变、`check` 17/17、既有 ktest 全绿 | 改 `walk_leaf` 时动了既有调用点的语义 ⇒ 矩阵某行变（这一格是"参数化没扰动"的证人） |

涉及硬件的部分（TLB 陈旧性）仍然只能验协议：C7 的收窄格读的是内核自己的回执计数，
真机 M7 的待测清单要带着它重做一遍（ADR-070 A5 的同一条限制）。

## 验收读数（回填，2026-11-09，P4a）

run-of-record：ELF `98a675c5a5e5`，矩阵与 bench 都取自这一个代码状态。
三档各跑一遍：normal **78/78**、`handles` **79/79**、`fat32-exec` **87/87**（后者含既有文件句柄用例，
所以 `ObjRef` 改造没有扰动它们）。门禁 `check` **17/17**、矩阵 **45/45 全符合**（C10 成立：内核路径零扰动）、
`bench` **4/4**（P4 地板 0.44 %、P1 同构建地板 729 周期，`baselines/2026-11-09T10-51-57Z-p3p4.txt`）。

三条用例的逐格读数（`fat32-exec` 那一跑）：

```
vmo(P4):   写读=true 越界=true 清零=true 基线=(free114773->114773 n0 created0->1 released0->1 bytes0->6)
asmap(P4): 双AS=true 同树拒=true W^X=true 高半区拒=true 叶同帧=true 互不影响=true 收窄=(reg true ack1) 基线=(free114770->114770 as0 vmo0)
hvmo(P4):  dup共享=true close一个还活着=true 两个都close才还=true revoke=true 类型拒=true 锁序=(viol0->0/reent0->0) 基线=(live0->0 free114770->114770)
```

六条变异各自咬中预测的格（日志留档 `.scratch/p4a-m{1,2,3,4,5,6}-serial.log`）：

| 变异 | 改哪 | 实测结果 | 判据 |
| --- | --- | --- | --- |
| M1 | `vmo_write` 不再拒长度 0 | `越界=false`，failed=1 | C1 |
| M2 | `vmo_unref` 不还帧 | 两条用例的基线格红（`free…->…` 少 2 / 少 1），failed=2 | C2 |
| M3 | `dup` 不给对象加引用 | `dup共享=false`、`close一个还活着=false`，failed=1 | C3 |
| **M4** | **把 `vmo_unref` 搬进 HANDLE 锁内** | **`L4 sync: 锁序违规，外层 rank=35 本次 rank=20` ⇒ EXCEPTION(39)** | **C4（裁决那条路线的唯一证人）** |
| M5 | `aspace_map` 仍用内核根 | `双AS=false 叶同帧=false 互不影响=false 收窄=false`，并连带 `t_elf_load_run` 红（内核树的用户的窗口被污染） | C6 |
| M6 | 去掉高半区闸 | `高半区拒=false`，failed=1 | C11 |

M1 只拿掉"长度 0"那一条，**越界与溢出两条留着**：让变异跑真的写越界会踩坏别人的帧，
那样红是红在现场不可读的地方，判据就失去归因价值（这条取舍写在这里，不藏在代码里）。
M6 预测的连带伤害（ADR-070 的 A1 内核半区对照）**没有发生**——A1 那一跑自己新建 AS，
被污染的那份已经销毁；所以这一格的证人只有它自己，不写成"A1 也会红"。

### 落地时被棘轮改回来的两处设计（与草案的差异）

1. **VMO 的三本计数不用原子量，放进 VMM 保护的表里**。草案写的是三个 `AtomicUsize`；
   落地时 `check` 报 `环内边 memory->sync 站点数 10 > 登记 9`——因为计数站点按行匹配
   `sync::`，而 `use core::sync::atomic::…` 这一行也算一站（与 `core::arch::` 撞 arch 棘轮同形）。
   棘轮只许减不许增 ⇒ 把计数搬进表（与表同锁，本来就该同锁），站点回到 9。
2. **归还失败走 `mm::free_violation`，不在 `vmo.rs` 自己升 L4**。草案里 `put_or_die` 自己
   `log_fatal! + exit::finish`，那会新增一站 `memory->diagnostics`（8 > 7）。
   改成复用 mm 的同一个升级入口（`pub(crate)`），站点回到 7，而且升级文案从此只有一处。

这两处都是"门禁把设计改瘦了"，不是放宽判据；登记面因此多了 `mm::free_violation` 与 `mm::PhysAddr`
两条 `public_api`（它们现在被别的产品文件引用）。

### 本轮没做（与草案一致的部分不再重复）

- **C7 的第二台仪器只到协议层**：收窄格读的是内核自己的回执计数（`ack1`），
  TLB 陈旧性在 TCG 上观测不到 ⇒ 真机 M7 待测清单要带着它重做（ADR-070 A5 的同一条限制）。
- **C8 的表页归还**由 `free frames` 回基线间接证明（`as0 vmo0` 且帧数不差），
  没有单独打 `MOD_AS_PT` 的台账行；要逐模块对账得等 P4b 或 P5 顺手加。
- **C9（收尾判据扩到 VMO）本轮没做**：`finish_sweep` 今天只数任务/进程/Job，不数 VMO 与句柄。
  三条用例各自在结尾查了 `vmo_count()==0`，所以泄漏会在用例内红，但"用例之间"那道门还没长这一格。
  留给 P4b 与 syscall 一起补（那时才有产品路径会造 VMO）。
- 12/13/14 三个号还没接（P4b）。

## 补记：P4b 落地（三个号接进 ABI，2026-11-09）

决策 4 说的"P4b 紧接着"已落地。签名与语义定在这里（号按 Q1 的裁决，不再问）：

| 号 | 签名 | 语义与拒绝 |
| --- | --- | --- |
| 12 `vmo_create` | `rdi = pages` → 句柄值 | `1..=MAX_VMO_PAGES`，越界 `-1`；表满/帧不够 `-6`。权限给 `READ|WRITE|MAP|DUP`；**创建者那一份引用交给句柄**（所以 refs 最终是 1 不是 2），grant 失败也要 unref，否则漏帧 |
| 13 `vmo_write` | `rdi=h, rsi=offset, rdx=用户缓冲, r10=len` → 字节数 | 第四参走 **r10**（`syscall` 吃掉 rcx/r11）。`len=0 ⇒ -1`、`len>COPY_MAX ⇒ -3`、对象里放不下 ⇒ `-1`。**整段先校验再动手**，不留半截写；搬运按 512 字节一块（与 `sys_file_read` 同一手法，不按用户的数开缓冲） |
| 14 `aspace_map` | `rdi=h, rsi=writable` → 用户 VA | **VA 由内核从动态区发**（`alloc_user_va_range`），不接受用户指定地址——那会与装载器的窗口撞。`writable≠0 ⇒ USER_RW`，否则 `USER_R`；**永远不给 X**，所以 W^X 在这一层就排掉了。需要 `RIGHT_MAP`，只读句柄调它 ⇒ `-4` |

> **后续勘误（ADR-075 决策 6，2026-11-09 使用者裁决"兼容扩展 14"）**：上表 14 那一行与"永远不给 X"
> 只描述 **P4b 落地的形状**。P5c 会把 14 扩成四参（`rsi` 改 flags 位图、`rdx` = AS 句柄、`r10` = 请求 VA），
> 扩展形**可以给 X**（用户态装载器要映 ELF 的 RX 代码段），但 W+X 仍在构造期拒绝；
> 旧调用方传 `rdx=r10=0`、`rsi` 只有 bit0 ⇒ 行为逐字不变。落地时同轮改 `user-abi-capability.md` §4.4 与 `ABI_MINOR`。

三个号都只在 `handles` 构建里存在，ABI 的 **`F_VMO = 32`** 与 `F_HANDLES` 同一条件、读回真实状态；
别的构建里三个号走默认分支回 `-1` 且该位为 0（`t_vmo_numbers_absent` 与 `t_vmo_syscalls` 互斥注册，各证一边）。

### 落地时定的三件事

1. **"调用者自己的 AS"今天就是 `AS_KERNEL`**：所有任务共用它，所以新增 `mm::aspace_map_self`
   （根 = 内核 PML4、新表页记 `MOD_BOOT`、解映射时**全广播** shootdown），与 `aspace_map` 共用铺设体。
   P5 起每进程一份 AS，14 的入口改成查任务的 AS 槽，`aspace_map_self` 留给内核自己的映射。
2. **映射挂进任务的资源袋**：`OwnedItem` 多一臂 `AsMap(mm::AspaceMapping)`，syscall 走新的
   `sched::own_current`。它**满了先放 RUNQ 再 drop**——`AspaceMapping::drop` 要取 VMM 并等别的 CPU 的
   shootdown 回执，持着队列锁做那件事正是 ADR-047 决策 2 禁止的形状（`push_item` 的就地丢弃只在装载路径用，
   那条路径不持 RUNQ）。退出时由 `release_owned` 在锁外 drop，所以清叶子、还帧参考、放手 VA 都在安全的时刻。
3. **C9 落地**：`finish_sweep` 多三格（`vmos/first_vmo/handles`），用例之间那道门现在也点名
   "没归还的 VMO"与"没关的句柄"。实测两档都没有遗留（`fat32-exec` 88/88），所以这道门没有把既有判据改红。

### 用例为什么在工人任务里打号（以及第一版怎么红的）

14 返回的映射挂进的是**当前任务**的袋子，只有任务退出才还。在用例上下文（启动任务）里打号，
那份映射会活到整机停机 ⇒ 帧参考与 VA 保留回不来。所以 `t_vmo_syscalls` 把三个号放在一个工人任务里打，
父任务等它收工、`terminate_task` + 回收，再读基线——**顺带把"退出 ⇒ 映射/VA/帧一起回来"证了**。
第一版还红过一次：工人收工之后不再返回（它在自旋让出里等着被回收），所以它局部的用户缓冲页 `Mapping`
**永远不会析构** ⇒ 基线红在"少 1 帧、多 1 条 VA 保留"。修法是收工前显式 `drop(user_buf)`，
这条写进用例注释：凡是不返回的工人，局部 RAII 都要显式收尾。

### P4b 的实测读数

run-of-record：ELF `cc2faeae5f78`，矩阵与 bench 同一代码状态。`check` **17/17**、矩阵 **45/45**、
ktests 四档：normal **79/79**、`fat32-exec` **88/88**、`fault-resched-ipi` **76/76**、`ahci-scratch` **81/81**；
`bench` **4/4**（P4 地板 2.59 %、P1 同构建地板 1557 周期，`baselines/2026-11-09T11-59-57Z-p3p4.txt`）。逐格：
`vmosys(P4b): 建=true 写=true 长度三态=true 映射双向=true 权限=true ABI=true 退出回基线=(drained true free…->free… va21->21 vmo0 live0)`；
无 `handles` 的构建：`vmosys-absent(P4b): 三号返回=[-1,-1,-1] F_VMO位=0`。
"映射双向"那一格是两次拷贝：从映射读回等于写进去的图案，再往映射写新值、对象那边读得到新值
⇒ 证的是**同一份帧**，不是"两份内容碰巧一样"。

三条变异（`.scratch/p4b-m{7,8,9}-serial.log`）：M7 去掉 13 的整段预校验 ⇒ `长度三态=false`；
M8 让 14 不挂任务袋（`forget` 映射）⇒ `退出回基线=false`（少 2 帧、多 1 条 VA 保留）；
M9 不置 `F_VMO` ⇒ `ABI=false`。三条都只红自己那一格（failed=1）。

### 落地时撞出来的一条仪器账：**收工后自旋让出 = 中断风暴**

P3 为了让等待方不依赖 tick，把工人收尾写成 `loop { yield_now() }`。这在挂 `-d int` 的矩阵行里
是灾难：每次让出是一条 `int 0xF0`，而那一行把**每条中断**写进宿主机日志 ⇒ 工人一边自旋一边让出，
宿主机一边写日志一边按住 vCPU，tick 更慢、让出更多。实测三轮矩阵：43/45、44/45，
红的都是挂核外仪器的行，且 `用时=120.0s`（**正好是预算上限**，不是客死），
串口停在 `t_q2_workload_slots -> ok` 之后没有下一行。

改成"**让出一次 + 之后有界自旋**"（一条中断把 CPU 还给等待方，换不动就等 tick）之后，
同一份判据整轮 **45/45**，那一行回到 4.9 s。顺带做了一次 A/B：纯自旋尾（不让出）时
P4 总量 **10.4 G** 周期，让出一次 + 采样按 tick 走之后 **8.34~8.56 G** ⇒ 差值归因到
"每次换人都等满一个 tick"的自等待，与 M6-c① 同一类（用例自等待，不是产品变慢）。
规则写进用例注释：**收尾只让出一次；等发令的自旋里不许让出**；采样环按 tick 计轮，不按让出计轮。

## 迁移与回滚

- P4a 全是新增（`vmo.rs`、`aspace_map`、`ObjRef` 的一个新臂）加两处参数化薄壳；
  回滚顺序：撤 ktest → 撤句柄表的 `Vmo` 臂与两段式 → 撤 `aspace_map`/`AspaceMapping` →
  撤 `walk_leaf_in` 的参数（薄壳还原）→ 删 `vmo.rs` → 撤登记面。
- **不可回滚的部分**：`lock-order.md` 那段注记一旦改成"已选第二条"，回滚代码时必须同轮把注记改回"两条路都开着"，
  否则表与代码分家（硬约束 4）。这条写在回滚步骤里，不靠记性。
- P4b 的号一旦接进 ABI 就不许复用（Q1：号只追加、永不复用），所以 P4b 回滚 = 把号标成保留而不是删掉。

## 未决

1. **`MAX_VMOS` / `MAX_VMO_PAGES` / `AS_PT_SLOTS` 的终值**：今天都是"接缝够用"，欠 workload 依据。
   P5 的 `process_start` 真起进程之后要按"一个进程几个 VMO、每个几页"重量一次（与 Q2 同一办法）。
2. **lazy 后端与带 AS 的 demand-zero**（依赖图 N19）：本轮不做，理由见决策 2。
   做的时候要先决定"惰性区间属于 AS 还是属于 VMO"，那是另一份 ADR。
3. **`aspace_map` 的用户态形状**：P4b 只能是"映射进调用者自己的 AS"。
   等 11 `process_create` 落地之后要不要允许"往别的 AS 映射"（需要 AS 句柄这种对象与 `RIGHT_MAP` 的授权链），
   留到 P5 与 `StartupInfo` 一起裁。
4. **VMO 的 `RIGHT_MAP`/`RIGHT_WRITE` 授权链**：本轮 `grant_vmo` 由内核直接发，权限位按 Q7 的"CREATE 是唯一新权限位"
   口径给；用户态 `dup` 收窄已有先例（`handle.rs:244-274`），但"映射权能不能从写权派生"要在 P4b 写清。
5. **多 CPU 并发解映射**：`lock-order.md:116-117` 那条"今天只有一个请求方"的欠账，
   P4 之后有两个 AS 就可能有多个请求方；`SD_VA` 单槽的论证要重做（ADR-072 未决的同一条）。
