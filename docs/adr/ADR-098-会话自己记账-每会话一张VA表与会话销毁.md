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
