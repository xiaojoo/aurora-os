# ADR-175：跨 AS 读用户内存走物理地址（HHDM 别名），不切 CR3

状态：已采纳（2026-11-20，证据来源：BACKLOG §461 / chain10 串口 7 次拒绝 / 本轮静态重算）
关联：§461（现场）、§459（`unwrap_or` 把读失败伪装成值不对）、ADR-026（用生效位而不是 `is_mapped`）、
ADR-070 A4（同一 VA 在两棵树里各自映射）、ADR-072（AS 世代与 TLB 回执）、
`docs/architecture/lock-order.md` 的 VMM(20)、AGENTS.md 硬约束 5 / 6 / 7

> 本 ADR 只裁决「跨 AS 读用户内存走哪条路」。它**不**改 `mm` / `sched` 的既有语义，
> 也**不**切 CR3、**不**动 TLB 与任务回收。
> 本轮落地的是 API 与登记；**调用点还没有切过去**，所以「7 次拒绝消失」这句话
> 本轮**未验证**，见 §六 与 §八。

---

## 一、背景

### 1.1 现场（实测，chain10）

chain10 的串口里有 **7 次**同一形状的行：

    abi: 读用户页被拒 va=0x100002028 —— 页表链没走完（没映射）
    abi: 读用户页被拒 va=0x1000c20e0 —— 页表链没走完（没映射）
    abi: 读用户页被拒 va=0x1000c2160 —— 同上
    abi: 读用户页被拒 va=0x1000c2168 —— 同上
    （共 7 次，两个地址组）

两个地址组分别是 `elfdisk` 的数据段（`sdkdemo` 读 `base+32`）与 `fs-open` 探针的数据段。
后果落在判据上：`sdkdemo: 读得到=false`、`fs-open-ring3: 不成立 done 哨兵`。

### 1.2 根因（实测 + 读码）

整条链是：

    read_at(user.rs:3943) → peek_u64(3535) → copy_from_user(3386)
      → validate_range(3360) → mm::current_effective_flags(mm.rs:1487)
      → unsafe { aspace_cr3_read() }(mm.rs:1492)

`current_effective_flags` 读的是**当前 CR3**。用例跑在**内核上下文**里，CR3 是内核页表；
而用户容器的映射在**容器自己的 AS** 里 ⇒ 走内核这棵树翻译不出来 ⇒ `NotMapped`。

仓库里早有按槽取根的 API：`mm::aspace_effective_flags(slot, va)`（`user.rs:753 / 755 / 1186`
三处已经在用）。`read_at` 是**漏改的那一处**——不是没有正确工具，是有人选了另一件。

### 1.3 为什么是间歇性的（推断，与实测一致）

用例与容器**同在一个 CPU 上轮转**：

- 容器在跑时 CR3 是容器的 ⇒ 同一份代码读得到；
- 用例在跑时 CR3 是内核的 ⇒ 读不到。

**落在哪一侧取决于 tick**，所以同一份 ELF、同一条判据，单跑绿、整链红。
这一条与 ADR-173（量具边界太紧）、ADR-174（判据写错）都不同：
**它是内核代码里真实的上下文错用**，只是它的可见性由调度决定。

### 1.4 为什么现在必须决定

`read_at` 的签名里**没有 AS 这个参数**，它只能猜"当前 CR3 就是目标 AS"。
只要跨 AS 读这件事存在（用例读容器的信箱、调试路径读别的进程），
就必须有一条**在签名上写清目标 AS** 的路；否则下一个调用点还会再选错一次。

---

## 二、决策

### 2.1 跨 AS 读走物理地址，经 HHDM 别名，不切 CR3

新增两个正式 API（本轮已落地在源码里）：

| API | 位置 | 语义 |
|---|---|---|
| `mm::aspace_root(slot: u8) -> Option<u64>` | `memory/mm.rs:1508` | 从槽号取那台 AS 的 PML4 物理地址（从 `aspace_effective_flags` 里提出来的，取根只此一份） |
| `mm::phys_of_in(root: u64, va: u64) -> Option<u64>` | `memory/mm.rs:1575` | `phys_of` 的按根版本：走 `root` 这张表把 `va` 翻成物理基址 |
| `user::copy_from_user_in(aslot, va, dst) -> Result<usize, PtrError>` | `sched/user.rs:3885` | 用户 → 内核，**按指定 AS** 逐页搬 |
| `user::read_at_in(aslot, va) -> Option<u64>` | `sched/user.rs:3922` | 跨 AS 读一个 `u64`；跨 AS 读**应该用这个**，不是 `read_at` |

数据通路（每一步都可核对）：

    aslot → mm::aspace_root → mm::phys_of_in(root, va)
          → mm::PhysAddr(pa).via_hhdm() → 该帧的内核别名 → read_volatile 1 字节

- **上下文**：KERNEL（用例/调试路径）。不要求 IRQ_OFF，不要求 USER_ENTRY。
- **资源所有权**：不分配、不登记、不持帧引用；只读翻译 + 一次读。
- **错误分类**：全部是 **C 契约违例**（`PtrError`），没有 A 业务错误、没有 D 完整性判定。
  失败向上回 `PtrError`，由调用方决定是否打日志；`read_at_in` 打 `log_info` 并把 `None` 交给判据。
- **是否可能阻塞**：不阻塞。`aspace_root` 短暂取 VMM(20)（`IrqGuard`，关中断），
  `aspace_effective_flags` / `phys_of_in` 与 `effective_flags` 同一纪律**不取锁**。

### 2.2 不切 CR3

切 CR3 要付三笔账，而收益只是「读几个字节」：

1. **TLB shootdown**：换 CR3 之后原来那些翻译不再有效，本 CPU 与别的 CPU 上的
   AS 相关项要按 ADR-072 的世代与回执纪律处理；为一个读操作引入一条新的
   跨 CPU 同步路径，风险与收益不成比例。
2. **持锁期不能被打断**：校验与拷贝必须在同一次持锁期内（§10.3 的原话），
   而切 CR3 本身要求"此刻没有别人在这颗 CPU 上跑"，这条约束会把
   `copy_from_user_in` 从"可在 VMM 锁内调用"变成"只能在最外层调用"。
3. **PTI 下要走 shadow PGD**：用户 AS 的根在内核态与用户态各有一份，
   切过去之后取到的根与 `aspace_root` 返回的 `e.pml4` 不是同一个数，
   "按槽取根"这件事会多出一层只在开了 PTI 时才错的形态。

主流内核的选择是同一句话。Linux `access_process_vm` 的注释（`mm/memory.c`）：

> Do not walk the page table directly, use get_user_pages

它拿到的是一页的 `struct page`，再经 `kmap` / direct map 访问，**不切 CR3**。
见 <https://elixir.bootlin.com/linux/v6.12/source/mm/memory.c> 与
<https://gitlab.com/Linaro/lkft/mirrors/stable/linux-stable-rc-queues/-/blob/7b8a0403ef7a6115167bc8f4071ca1de7bf7851b/mm/memory.c>。

Windows 的 MDL 读写同理：`MmProbeAndLockPages` 锁定并填出物理页数组，
`MmGetSystemAddressForMdlSafe` 把那些物理页映射到系统空间，文档给的理由正是
「**regardless of process context**」：

> This ensures that the driver can continue to access the pages safely regardless of process context.

见 <https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls> 与
<https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmmaplockedpages>。

**切 CR3 只用于「代表目标进程执行」（`aspace_switch` 今天就在做这件事），
不用于「读目标进程的内存」。** 这两件事在 Linux 与 Windows 上是分开的两条路。

### 2.3 不需要 stac/clac

SMAP 拦的是**内核态访问 U/S=1 的页**。这里访问的是

    HHDM 别名 = 该物理帧在内核半区的直映地址

HHDM 那些页表项是**内核页（U/S=0）**，SMAP 不拦。
换句话说：读的是「那台 AS 的物理页经 direct map 的别名」，**不是用户映射本身**。

这条推论有一个直接后果，必须写进纪律：**这是全仓唯一一条不经 stac/clac 读用户内存的路径**，
所以它不能靠「反正会 #PF」兜底——它根本不会 #PF。

### 2.4 仍然逐页校验（不因为走物理地址就跳过）

`copy_from_user_in` 每一页都问一次 `mm::aspace_effective_flags(aslot, page)`，
并要求 `eff.user`：

    let eff = mm::aspace_effective_flags(aslot, page).ok_or(PtrError::NotMapped)?;
    if !eff.user {
        return Err(PtrError::NotSharedWithUser);
    }

**为什么不能省**：`phys_of_in` 只回答「这一页在不在、在哪」，它不回答「用户能不能碰」。
少了这一步，内核就会**替用户去读它自己的内核页**——用户给一个内核半区的 VA，
内核照样翻译得出来、照样读得到。那正是 `PtrError::NotSharedWithUser` 挡的事
（`describe` 的原话：这一页没对用户开放（U/S=0））。

同一段校验还保留了两条既有判据：`va`/`end` 必须在 `USER_VA_TOP` 以下（`NotUserRange`），
一次拷贝不超过 `COPY_MAX = 4096`（`TooLong`，**拒绝而不截短**）。

### 2.5 选 B2（正式 API），不选 B1（取证旁路）

B1 是"再写一个只在用例里用的旁路读"，B2 是"把它做成 `mm`/`sched` 的正式 API"。

今天出错的形状**不是"没有能用的函数"，而是"两套语义并存、用的人选错了"**：
`read_at` 走当前 CR3、`aspace_effective_flags` 走槽号，两个都在，都叫得像对的。
再补一条 B1 旁路，系统里就有**三条**读用户内存的路，下一次仍然要人选。

做成 B2 之后，「跨 AS 读」只有一条路：签名里带 `aslot`。
**签名本身就是判据**——写 `read_at(va)` 的时候，缺的那个参数会自己冒出来。

---

## 三、备选方案

| 方案 | 做法 | 不选的理由 |
|---|---|---|
| **A** 切 CR3 读 | `aspace_switch(slot)` → `ucopy_from` → `aspace_switch_kernel` | §2.2 三笔账（TLB shootdown / 持锁期 / PTI shadow PGD）。且它会把一条只读路径变成"改全局 CPU 状态"的路径，故障归属复杂一倍 |
| **B1** 取证旁路 | 只在 ktest 里加一个 `read_at_in`，不进 `mm`/`sched` 的正式面 | §2.5：系统里会有三条路，而错的那条仍在最顺手的名字上（`read_at`） |
| **C** 让容器自己写共享区 | 用户程序把结果写进内核能直接读的共享页 | 要改用户程序与 ABI；`ABI_SLOT_*` 已经是这个思路的一半，但**不是所有跨 AS 读都能提前约定一个槽**（`fs-open` 探针读的是它自己的数据段，`sdkdebug` 读的是任意 `base+off`） |
| **D** 让 `read_at` 自己猜 AS | 从 `current_id()` 反查当前任务的 AS | 用例跑在内核上下文，`current_id()` 是内核任务；猜错的形态与今天一样是**静默的 `None`**。签名里没有目标，就只能猜 |

**A 不是错的，只是代价与收益不匹配**；将来真需要"代表目标进程执行"（比如在目标 AS 里
跑一段代码）时，A 是那条路——那时它叫 `aspace_switch`，不叫读内存。

---

## 四、影响

### 正面

- 「跨 AS 读」有了**签名上写清目标**的唯一入口，`read_at` 不再是唯一的读法。
- 不引入新的锁、不引入新的跨 CPU 同步、不改 TLB 语义 ⇒ 与 ADR-072 / lock-order.md 无冲突。
- 取根只有一份实现（`aspace_root`），`aspace_effective_flags` 与 `copy_from_user_in` 共用，
  不会出现"两处各写一遍、有一处忘了判 `e.used`"。

### 负面 / 代价

- **多一处 unsafe**：HHDM 别名的单字节 `read_volatile`（`sched/user.rs:3909`）。
  已登记进 `docs/security/unsafe-whitelist.toml`（`sched/user` U2 9 → 10），
  census 重算 530 → 531。
- **逐字节**：8 字节一次 `read_volatile`，没有批量优化（§八 未决 1）。
- **校验与读已同在一次持锁期**（本文修订）：`copy_from_user_in` 现在用
  `mm::with_vmm_lock` 把「取根 → 校验 → 翻译 → 读」整段包住，与 `copy_from_user`
  同一条纪律。见 §八 未决 2 的处置记录——那里记了为什么不能直接在外层包
  （`VMM_LOCK` 不可重入），以及为此拆出的 `aspace_root_locked`。
- **本轮不消灭那 7 次拒绝**：调用点（`ktests/security/sdkdemo.rs` 的 `read_at`、
  `ktests/storage/fs_open.rs` 的探针）**还没有切到 `read_at_in`**，所以 chain 上仍会复现。

### 对已有 ADR / 测试 / 基线的影响

- 不改 ADR-026 / ADR-070 A4 / ADR-072 的任何语义。
- `mm::phys_of` 的行为不变（改成 `phys_of_in(s().pml4_phys, va)` 的薄壳，行号整体后移 6 行）。
- 接口登记补两条：`mm::aspace_root`、`mm::phys_of_in`（`module-interfaces.toml`）。
  这也是 `check-interface-change` 要求本 ADR 在场的原因。
- 判定表**本轮未重跑**（只跑了静态门禁），§六 的读数只覆盖 `check`。

---

## 五、验收与负样本

### 5.1 判据在哪

| 判据 | 在哪一跑 | 期望 |
|---|---|---|
| 源码里 `read_at` 的调用链仍是当前 CR3 | 静态：`grep aspace_cr3_read` + `validate_range` | `validate_range` 只被 `copy_from_user` / `copy_to_user_locked` / `poke_pattern_into` 用 |
| 新 API 的签名带 `aslot` | 静态：`copy_from_user_in` / `read_at_in` 的定义 | 首参是 `u8` |
| unsafe 登记与实际一致 | `python tools/aurora.py check`（`check-unsafe`） | `sched/user` U2 = 10、total = 531、U2 = 120 |
| 接口登记完整 | 同上（`check-module-interfaces`） | `mm::aspace_root` / `mm::phys_of_in` 在 `public_api` 里 |
| 接口变更配 ADR | 同上（`check-interface-change`） | 本文件在场 |

### 5.2 负样本表（每条新判据怎么变红）

| # | 判据 | 负样本（怎么造） | 红在哪 |
|---|---|---|---|
| N1 | 逐页校验不能省 | 删掉 `copy_from_user_in` 里的 `if !eff.user` 那一行，改传一个内核半区的 VA（如 `0xffff_8000_0000_0000` 附近已映射的页） | 本应回 `NotSharedWithUser`，实际**读成功**——「内核替用户读它的内核页」 |
| N2 | 地址范围判据 | 传 `va = USER_VA_TOP - 4` 且 `len = 8` | 回 `NotUserRange`（`end > USER_VA_TOP`），不是"读半截" |
| N3 | 长度上限是拒绝不是截短 | 传 `len = COPY_MAX + 1` | 回 `TooLong`（`-ETOOLONG`），不是搬 `COPY_MAX` 字节 |
| N4 | 取根必须判 `e.used` | 用一个从未 `aspace_new*` 过的槽号（如 63） | 回 `NotMapped`；若把 `e.used` 判删掉，会拿一个陈旧的 `pml4` 去翻译——**读出来的可能是别的进程的页** |
| N5 | 按根翻译必须用**那台** AS 的根 | 把 `phys_of_in(root, at)` 改成 `phys_of(at)`（走 `s().pml4_phys`） | 在用例上下文里恒 `NotMapped` ⇒ 7 次拒绝原样复现（这正是 §1.1 的现场） |
| N6 | unsafe 登记不能虚报 | 把 `[modules."sched/user"]` 的 `U2` 从 10 改回 9 | `check-unsafe` 红：登记 9、源码算出 10 |
| N7 | unsafe 登记不能越权 | 删掉白名单里 `sched/user` 的 `U2` 那一行 | `check-unsafe` 红：有 10 处 U2 但没登记 |
| N8 | 接口登记不能漏 | 从 `public_api` 删掉 `mm::phys_of_in` | `check-module-interfaces` 红：`public_api 漏登记：mm::phys_of_in` |
| N9 | 接口变更必须配 ADR | 把本 ADR 移出工作树（`git stash` 它），只留 `module-interfaces.toml` 的改动 | `check-interface-change` 红：接口有未提交改动但没有 ADR 改动 |

**N5 是本 ADR 的核心负样本**：它把"选错根"这件事变成一条**必然红**的判据，
而不是"取决于 tick"。

### 5.3 第二台仪器

- **宿主机侧**：`phys_of_in` 的翻译结果可以与宿主机读同一份串口里打印的
  `diag: as_slot=... our_cr3=...` 行对账（`ktests/security/sdkdemo.rs:58` 已经在打）。
  本轮**没有**做这项对账（调用点未切换，读数不存在）⇒ **未验证**。
- **页表侧**：`phys_of_in` 与 `effective_flags_in` 共用同一段遍历形状，
  `phys_of` 已有 ADR-066 的翻译等价仪器；按根版本**还没有**对应的 ktest。

---

## 六、迁移与回滚

### 迁移（未做，按此顺序）

1. **先切只读用例**：`ktests/security/sdkdemo.rs` 的 `read_at(base+off)` 改成
   `read_at_in(aslot, base+off)`；`aslot` 从 `crate::sched::aspace_of(t)` 取
   （`terminate_task` 之前取，之后槽号可能已被回收）。判据形状不变，仍是
   `读得到` 那一格。
2. **再切 `fs-open` 探针**：`ktests/storage/fs_open.rs` 的读同样换成 `read_at_in`。
3. **最后判 `read_at` 的去留**：切完之后若 `read_at` 只剩"同 AS"用途，
   在它头上写明「只在当前 CR3 就是目标 AS 时正确」；若一处不剩，删掉它比留着安全
   （留着就还是"两套语义并存"）。

### 回滚

- 回滚点：删掉 `copy_from_user_in` / `read_at_in` 与 `aspace_root` / `phys_of_in`
  的 `pub`，把 `phys_of` 还原成原来的单函数。**`aspace_effective_flags` 的行为不变**，
  所以回滚不会动任何已实测的语义。
- 不能回滚的部分：一旦调用点切过去，"跨 AS 读"就依赖 `phys_of_in` 的按根翻译；
  回滚必须同时回滚调用点，否则会退回 §1.1 的现场。

---

## 七、为什么不写"已修复"

本轮**没有**重跑判定表，调用点**没有**切换，所以：

- 那 7 次 `读用户页被拒` **仍然会复现**；
- `sdkdemo: 读得到=false` 与 `fs-open-ring3: 不成立 done 哨兵` **仍然是红的**；
- 本 ADR 证明的是"路选对了、工具在位、登记齐了"，**不是"现象消失了"**。

按硬约束 7：**「检测到」不等于「已恢复」**。这里的对应说法是
**「API 到位」不等于「调用点已切」**。

---

2. ~~**`copy_from_user_in` 缺 `with_vmm_lock`**~~ **已修（本文修订）**。

   原来的形态是：`aspace_root` 自取锁，而 `aspace_effective_flags` 与 `phys_of_in`
   都不取锁 ⇒ 「校验说这一页对用户开放」与「按翻译出来的帧去读」之间有一个窗口，
   另一颗 CPU 可以在这中间 `aspace_destroy` 并归还帧，于是读到的是**已被复用的
   物理内存**——那是把别人的数据当这个容器的数据交出去。

   **为什么不能直接在外层包一层**：`VMM_LOCK` 是 rank 锁、**不可重入**
   （`IrqGuard` + rank 断言），而 `aspace_root` 自己会取它 ⇒ 外层再包会撞
   「重入获取 rank=20」。

   **怎么修的**：把取锁从 `aspace_root` 里提出来，拆成两个版本——

       pub fn aspace_root(slot)         // 自取锁，单次查询用
       pub fn aspace_root_locked(slot)  // 要求调用方已持锁，组合操作用

   `copy_from_user_in` 改用 `_locked` 那个，整段包在 `with_vmm_lock` 里。
   `aspace_effective_flags` 仍用自取锁版，语义不变。

   **负样本**：把 `copy_from_user_in` 的 `with_vmm_lock` 去掉，
   `check-driver-ctx` 不红（它只看驱动），但**这条缺口没有任何门禁能自动抓**——
   它只在「另一颗 CPU 恰好在那个窗口里 destroy」时才显现。所以它靠的是
   **与 `copy_from_user` 的结构一致性**，而不是一条会红的判据。
   **这一点必须如实记着：它是纪律，不是判据。**
3. **`write_at_in`（写方向）还没做**：写要额外要求 `eff.writable`（`NotWritable`），
   并且要决定"写穿过 COW 怎么办"——本内核今天没有 COW，但这条判据的占位得先想清楚。
4. **`aspace_root` 失败原因的合并**：`None` 同时表示"槽号越界""槽位未使用""MM 未就绪"
   三种情况，`copy_from_user_in` 一律折成 `NotMapped`（日志里读成"页表链没走完"）。
   要分开就得改 `PtrError` 的形状，那是改契约，需先问。
5. **没有 ktest**：按根翻译（`phys_of_in`）与跨 AS 读（`copy_from_user_in`）今天
   **零个用例**。ADR-066 给 `phys_of` 配了翻译等价仪器，按根版本还没有。
   在补上之前，§5.2 的 N1–N5 只是"设计上会红"，**没有实测过一次**。
6. **PTI 未开**：本内核今天没有 PTI，所以 §2.2 第 3 条（shadow PGD）是**推断**，
   不是实测。开 PTI 的那一轮要回来重读这一节。
