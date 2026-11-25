# ADR-255：XFER 持锁期间禁止换出与终止

状态：**已采纳**（2026-11-25；使用者在三条路线中选择“禁止持锁换出/终止”）。
关联：ADR-190/222/248（XFER 互斥、rank=4、入口闸）、ADR-253（CAS 元数据窗口）、
ADR-075（终止契约）、BACKLOG §583。

## 背景

`OpenSpinLock` 当前只有 AHCI `XFER` 一个使用者。它不动 IF，因此持锁期间 tick/resched
可以进入 `preempt_point` 并执行 `context_load`；Rust guard 被留在原任务内核栈上。
`terminate_task` 又可直接把 Running/Runnable 标 Free，随后 `reap` 释放该栈。此时 guard
的 Drop 不会执行，`locked` 可能永久为 1，后续 AHCI 传输永久自旋。

正常 Err/`?` 与 IssueStuck 重发都由 RAII 释放；缺口只在“持锁换出后被终止/回收”。
实际发生率未验证，但代码路径已证实可达。

## 决定

1. `OpenSpinLock` 增加 per-CPU 持锁深度。CAS 成功、rank 发布、深度增加都在短暂 IF=0
   窗口内完成；获取后恢复原 IF，设备等待仍允许中断进入。
2. `preempt_point` 见当前 CPU 持锁深度非 0 时，只清 need 并返回，不执行 `context_load`。
   回收与其他 CPU 的释放不受影响；同一 CPU 的持锁者仍是唯一 guard 所有者。
3. `terminate_task` 若目标是当前 CPU 且该 CPU 持锁深度非 0，只置既有
   `on_cpu` bit3 终止待办、立 need 并返回 false；不改 state/frame/proc_id、不释放资源。
   待办先发布再二次核对深度，归零则撤销待办并立即走正常终止，关闭与 Drop 的竞态。
   `OpenGuard` 用 `PhantomData<*mut ()>` 明确 `!Send`，禁止跨 CPU Drop。
4. guard Drop 在 IF=0 内还原 rank、放锁、减深度；深度归零且有待办时，恢复 IF 后用
   `int 0xF0` 立即制造抢占点。抢占点见待办且深度为 0，清待办并调用 `terminate_task`，
   然后照常选下一个任务。
5. 不新增 Task 字段：复用既有 `on_cpu` bit3 与 `take_termination_pending`。不新增锁、
   不改锁等级；`sync -> sched` 反向依赖不引入，Drop 只调用架构层 resched 自陷。
6. 新增统计：持锁抢占让出数、持锁终止延期数、Drop 强制 resched 数。负样本特性
   `fault-xfer-term-no-defer` 只关闭终止延期，必须让新用例精确红。

## 边界

- 本 ADR 保证同步 AHCI guard 不会被换出后丢失；不解决异步回调 panic、设备永久不落定，
  也不把 `OpenSpinLock` 推广成通用可终止锁。
- XFER 仍可在持锁期间接收完成中断；改变的是上下文切换与终止，不是中断驱动证据。
- 真机未验证。

## 验收

| 场景 | 读数 |
|---|---|
| 正常档 | `run-16047`：`AP调用=3 accepted=false runs=1->1`，`换出延期=2 终止延期=3 强制resched=1`，Free/owned=0，默认 **93/93** PASS |
| 关闭终止延期 | `run-16048`：`accepted=true 终止延期=0 强制resched=0`，`t_open_lock_defer` 精确 FAIL（93 条仅此 1 红） |
| handles,fs-ro / fs-rw / fat32-exec | `run-16049` / `run-16050` / `run-16051` 全 PASS |
| 静态门禁 | `check` **21/21** |
| 完整矩阵 | `build/matrix-final.log`：**82/82 符合**，`AURORA_MATRIX_DONE rc=0` |

用例由 BSP 工人持锁并主动 yield，AP 侧调用 `terminate_task`；yield 前后 runs 相等、
三个 AP 都返回 false、Drop 后强制 resched 一次并回收，直接证明“未换出 + 跨 CPU 终止延期”。
