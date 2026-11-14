# ADR-098：会话自己记账——每会话一张 VA 表，关会话时逐条放手

状态：采纳（2026-11-14，用户裁决"B：会话自己记账"；**代码未动**，前置普查见 BACKLOG §268）
关联：ADR-070（单地址空间 + 全局 VA 保留表）、ADR-073（Process/Job 与回收）、
ADR-074（VMO/aspace_map 的锁外释放）、ADR-092（每会话镜像环与控制台会话号）、
ADR-097（停机改成显式动作——本 ADR 是它的前置）、BACKLOG §260（三道资源墙）、§267（四条读数）、§268（普查）

## 背景

ADR-097 的前置测量（§267）与普查（§268）把"关掉一个会话之后资源没回来"落到了函数：

1. `terminate_task` 把槽位**当场标 Free**（不是 `Done`），跳过 reap 扫描；
2. `proc_reap` 在产品路径**零调用者** ⇒ 僵尸进程与它的子 AS 从不销毁；
3. `aspace_release` 只还自己建的表页与表项，**不碰用户半区**；
4. `si_va` 走的是 `sys_aspace_map` 的固定地址分支，那里调的是**全局** `reserve_va_at`
   ⇒ 不显式 `release_va`，同一地址第二次必 -6（这正是实测 `si_va=0xfffffffffffffffa` 的来源）。

## 决策

1. **每会话一张 VA 小表**（`user` 模块内，定长、原子量、无锁、零 unsafe）：

   ```text
   SESSION_VA_CAP = 8
   SVA: [[AtomicU64; SESSION_VA_CAP]; SESSIONS]
   SVA_N: [AtomicUsize; SESSIONS]
   ```

   装载路径在**每一处** `reserve_va_at` / 固定地址 `aspace_map` 之后调
   `user::session_note_va(sid, base)`；表满或重复时**如实打读数并计数**，不静默丢。
2. **`user::session_release_va(sid) -> (released, failed)`**：逐条 `mm::release_va(base)`，
   清表。返回两个数，调用方必须把 `failed` 打进串口——"放了几条/几条没放掉"是这一刀的判据面。
3. **关会话的顺序**（两条关闭路径共用）：
   `读 proc_id` → `terminate_task`（袋与槽位照旧由它收）→ `proc_reap(proc_id)`（销毁 AS）
   → `session_release_va(sid)`（放手 VA 保留）。
   `proc_reap` 在锁序上合法：它自取 VMM，而调用点不持 RUNQ（点击处理跑在 park 的任务上下文）。
4. **不动 `mm` 的语义**：不改进 `aspace_release`，不新增 unmap 路径。本 ADR 的回收全部落在
   `user` 的记账与显式 `release_va` 上——这是选 B 而不是 A 的全部理由。
5. 新增接口（会触发 `check-interface-change`，故需本 ADR）：
   `user::session_note_va` / `user::session_release_va` / `sched::task_proc_id`。

   第一步（本片已落地，登记进 `docs/architecture/module-interfaces.toml` 的 `user` 组）：

   ```text
   user::SESSION_VA_CAP        8
   user::begin_session_load    （sid）  起一个"给这个会话装载"的作用域
   user::end_session_load      （）     关作用域
   user::session_note_va       （sid, base）-> bool   返回 false = 表满（调用方必须打读数）
   user::session_va_count      （sid）-> usize
   user::session_va_at         （sid, i）-> u64
   ```

   `session_release_va` 留到第二步：它要在关闭路径上与 `proc_reap` 一起接，单独先落一张
   能记账的表，才能先把"记了几条"这个读数拿出来对账（先有账，才谈放账）。

## 必须先核对的一条矛盾（排查记录，不是结论）

`user::Loaded.owned` 的注释写着"任务结束时由 `sched::reap` 释放（**解映射 + 归还页框 + 放手 VA 保留**，
§6.3 R13）"。而实测：同一地址第二次 `reserve_va_at` 返回 false。二者只能有一个成立：

· 要么那句注释对**映射项**成立、对 `si` 这一页不成立（`si` 由 `sys_aspace_map` 在**子 AS** 里建，
  它的所有权是否进了某个袋子没被证过）；
· 要么 `release_va` 只在某个我们没走到的分支里。

本 ADR 不替它下结论：实施第一步就是**量**——关会话前后 `reserve_va_at` 的同址返回值、
`SVA` 表里记了几条、`session_release_va` 放掉几条。注释说谎的话，这一刀会把它揪出来。

## 验收

沿用 `build/s6v-close-check.py` 九格，并加两格读数：

· 正：连点两次 0 号 `×`，两次 `si_va` 都是**真地址**（`< 0xffffffffffffffff-…`，非 -6），
  `创建者袋` 回到 4，`BSP 槽占用` 回到 `0b000000111`；
· 正：`session_release_va` 的 `released/failed` 两次都写进串口，`failed == 0`；
· 负样本：去掉 `session_release_va` 那一行 ⇒ 第二次 `si_va` 回到 -6（今天的形状就是证人）；
· 回归：正常 `exit` 与全局 `×` 仍 `qemu-exit=33`；`s6p`/`s6q`/`s6r`/`s6t` 不劣化。

## 补记一（2026-11-14）：16 号的 `-6` 需要一个"占格数"读数

ADR-097 的重开在 16 号 `SYS_PROCESS_START` 上返 `start_ret=-6`、`跑过次数=0`（BACKLOG §271）。
`-6` 在 16 号里有多个来源（`resolve` / `transfer` / `grant_*` / `vmo_read`），
而**唯一能从外面读出来**的是句柄表占了几格。故新增两个只读符号：

```text
handle::used()        -> usize    取一次表锁，返回 Table::live()
handle::MAX_HANDLES   16          日志里带上限，免得读数离开源码就说不清
```

打点位置：`stage_init_user` 的 16 号前后各读一次，一行输出
`16号句柄占格={}→{}（上限 {}）start_ret={}`。判据：
若重开时**前值已等于上限** ⇒ 归因落到"表满"（谁没还）；若前值明显小于上限 ⇒ 去查
`transfer` 的权限与世代。**在拿到这个读数之前不改 16 号任何分支。**

## 补记三（2026-11-14，裁决：**si 页归子任务**）

裁决依据：§274 的读数——重开时 16 号前占格 14/16，只剩 2 个空位，而 16 号要 3 个；
两格永久漏在创建者身上（`hi` = si 的 VMO、`foreign` = 只 sid 0 的控制台反例）。

三处改动：

1. `hi` 的授予补 `RIGHT_TRANSFER`（原来没有 ⇒ 写进描述表也转不走）；
2. si 描述表加 `ROLE_SI`（=7）指向 `hi`，`nhandles` 由 2 变 3；
3. `foreign` 同路：补 `RIGHT_TRANSFER` + `ROLE_CONSOLE_ECHO`（=8），`nhandles` 再加 1（仅 sid 0）。

**偏移 512 那格保持不变**：它写的是"值"，16 号转移之后旧值会 Stale，仍属"被拒"那一类，
但理由码可能从"权限"变成"世代"——这一条要 `s6p` / `console-probe` 跑过才算数。
`ROLE_SI` / `ROLE_CONSOLE_ECHO` 对用户态是未知角色，shell 只认 `ROLE_LOG`、其余跳过。

## 补记四（2026-11-14）：关闭请求是进程级事实

`live_wait_and_redraw` 与 park 各开一份 `LiveTerm`，各自的 `closed[]`。启动等待期间来的点击写进
**等待那份**，park 永远读到 false ⇒ 任务被杀但"用户按的"标记丢了 ⇒ 判成自愿收工。
裁决：新增 `static CLOSE_REQ: [AtomicBool; SESSIONS]`，两条关闭路径置位，
park 用 `swap(false)` **消费一次请求**；`self.closed[i]` 降级为纯视图状态。
九格 `s6v-close-check.py` 全绿（含第二次关、全局 `×`）。

## 补记五（2026-11-15，实测）：关闭链补 `job_destroy`——Job 槽才是先撞的那道墙

· 症状：反复点标签的 `×`（或从面板重开）三、四次后，**整个程序退出**（qemu-exit=33，
  看起来像"正常退出"）。串口末尾是 `init-user: job_create 失败 TableFull` +
  `站点 1196`，上一行是 `会话 0 重开失败 ⇒ 按旧语义收工`。
· 成因：关闭链只做了 `terminate_task → proc_reap → session_release_va`。`proc_reap`
  只把 Job 的 `used_procs` 减一，**从不销毁 Job**；每次重开 `job_create` 又占一个新槽，
  `MAX_JOBS` 一下就满。
· 修法：`proc::job_of(proc_id)` 在**收尸之前**读出 Job 号（reap 会清进程记录），
  收尸成功后 `job_destroy`。标签条 `×` 与浮窗 `×` 两条链都补上，日志加
  `Job销毁={}` 一格（关闭两行：`窗口: 关闭会话 …` / `wm: 关闭窗口 …`）。
· 为什么不在 `proc_reap` 里顺手销毁：Job 可能在收尸之后还有别的进程（未来多进程 Job），
  而且 ktest 里有"建 Job → 收尸 → 显式 job_destroy"的序列，reap 自动销毁会把那条用例
  变成双重销毁。职责留给**产品关闭链**，读数是显式的。
