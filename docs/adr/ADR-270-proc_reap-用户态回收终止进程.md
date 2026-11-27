# ADR-270：83 号 `proc_reap` —— 用户态回收已终止进程（R42 选 A，使用者 2026-11-27 批准）

状态：**已采纳**（R42 选 A，使用者 2026-11-27 批准；实现已合入并验证）。关联：ADR-269 §0/§1（缺口与方案）、ADR-073/075（Job/Proc）、ADR-098（会话关闭收僵尸）、
ADR-180（fd 表）、ADR-176（号在功能不在回 NOSYS）、ADR-134（kill 的句柄语义）。

## 1. 决策
新增 **83 = `SYS_PROC_REAP`**：`rdi` = Proc 句柄（要 `RIGHT_WRITE`）→ 成功返回**退出码**（与 17/19 号等到的值同一个）。
号核对：本仓库最大声明号 82（81/82 防火墙）；78/79 作废保持空闲；83 在全仓零引用。

## 2. 语义（逐条有判据，见 `ktests/sched/proc_reap.rs`）
| 情形 | 返回 | 副作用 |
|---|---|---|
| 进程**还在跑** | `E_DENIED` | **无**（不是杀；要杀用 18/29） |
| 句柄缺 `WRITE`（`dup` 收窄的副本）/ 不是 Proc | `E_DENIED` | 无 |
| 句柄失效 / 世代不符（已被收过） | `E_BAD_HANDLE` | 无 |
| 想收自己所在进程 | `E_DENIED` | 无（与 18 号同口径） |
| 已终止（僵尸） | **退出码** | 清进程槽、还 Job `used_procs`、锁外销毁子 AS 与 **fd 表**、**关闭调用方这个句柄** |
* **句柄副本**：由 `dup` 派生的其它 Proc 句柄不会被一并关闭，它们靠 `(slot, gen)` 世代失效；`proc_reap` 保留 `gen` 防 ABA（P5c-3a 既有设计），所以**复用同一槽的新进程不会被旧副本误伤**（判据 ⑥b 专门验这一点）。
* **先 reap、后关句柄**：反过来的话 reap 失败时调用方已丢句柄、僵尸永远收不掉。
* **锁序**：`resolve`（HANDLE 35 放掉）→ `proc_info/proc_reap`（VMM 20）→ 锁外 `aspace_destroy`/`release_fd_table`（PMM 30）→ `handle::close`（HANDLE 35）。**无嵌套、不新增锁**，与 `sys_process_create` 同形。

## 3. 连带修复一个既有缺陷（本 ADR 的前提）
读 `sched/proc.rs` 时发现：**`proc_discard` 归还 fd 表（ADR-180），`proc_reap` 不归还**。
`*p = PROC_EMPTY` 之后 `fd_table` 基址直接丢失 ⇒ **任何用过 fd 表的进程（调用过 `fd_install/fd_lookup/fd_io`，即任何走 stdio 的程序）每 reap 一次就永久漏一页**。
这是 ADR-180 引入 fd 表时漏改 reap 的既有缺陷；它会让 83 号的"页数回基线"判据变红，所以必须同批修。
修法与 `proc_discard` **逐字同形**：锁内抄地址、放锁后 `mm::release_fd_table(base, FD_TABLE_BYTES)`（归还走 PMM(30)，在 VMM(20) 内取会在 `frame_put` 失败回头记账时反向嵌套 ⇒ L4）。
**影响面**：所有 `proc_reap` 调用者（`notify_broker`、会话关闭、各 ktest）从此也会还 fd 表页——这是**行为变化**（页数读数会比以前多回收），需要你本机跑 `ktests/test` 看判定表是否有依赖"reap 后 free_frames 恰好等于某值"的格子（我无法验证）。
**变异**：`fault-reap-leak-fdtable` 复现旧缺陷（不抄地址），`t_proc_reap_syscall` 的 ④ 格必红。

## 4. 对 S5c 的意义
监督者每次 `process_wait` 拿到结局后调 `proc_reap`，Job 额度/进程槽/子 AS/fd 表全部回来 ⇒ "1000 次重启"不再被 `max_procs` 卡住。
**这只解决了回收；`runtime::exec::launch` 失败路径无回滚、只传 argv[0] 与 1 个句柄的问题仍在（ADR-269 §3，R44）。**

## 5. 验证与剩余边界（2026-11-28）

- default、`fw`、`fs-rw`、`fs-rw,fs-dirloc`、`fw,fs-rw` 五种构建通过；`check` 21/21。
- `t_proc_reap_syscall` 九格全真；`fault-reap-leak-fdtable` 下第④格精确变红（fd 归还 0→0）。
- 修复并发 reap 的 TOCTOU：syscall 现在调用 `proc_reap_gen(pid, gen)`，在 VMM 锁内复核世代；旧句柄不能收掉复用槽位的新进程。
- 修复 fd 表释放尺寸：`proc_reap`/`proc_discard` 按 `fd_cap * 8` 归还，不再固定 512 B。
- **仍未做**：并发双 reap 的专门竞态用例；`runtime::exec` 产品路径调用 reap；`user/init` 监督者与 `runtime::spawn`（R43/R44）。
- **已知遗漏**：fd 表 `grow()` 的旧表仍按 ADR-180 设计留在进程销毁时归还，但当前没有登记旧表地址；扩容后旧表仍会泄漏。当前表本身的归还尺寸已修。
