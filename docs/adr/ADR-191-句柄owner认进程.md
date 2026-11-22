# ADR-191：句柄 owner 认进程（线程共享 fd）

状态：**已采纳**（2026-11-22：`owner_proc` 落地，`hproc` 七格全 true）

关联：ADR-180（per-process fd 表）、ADR-186（fd 号段）

> 这是「五样对象化」的第一片（A）。后四片：引用计数、VMA 归属、块层队列、VFS 三层。

## 背景：三处「看起来有、语义不成立」之一

`Entry` 原来只有 `owner_gidx` + `owner_id`，那是**任务**身份。于是：

**同一进程的两个线程不能共享 fd** —— 线程 B 用线程 A 装的 fd 会拿到 `-4 NotOwner`。

Linux 里 fd 属于 `files_struct`，线程共享（`CLONE_FILES`）。这是**语义级差距**，
不是性能差距，且现有判据全是单线程单进程，**测不出来**。

## 决策

### 决策 1：`Entry` 加 `owner_proc` 一格

```rust
owner_gidx: u16,   // 任务全局下标（原语义保留）
owner_id: u32,     // 任务 id（原语义保留）
owner_proc: u16,   // 进程 id（新增，ADR-191）
```

### 决策 2：`check` 放行「同任务**或**同进程」

```rust
let same_task = e.owner_gidx == owner.0 && e.owner_id == owner.1;
let same_proc = !same_task && e.owner_proc != NO_PROC
    && proc_id_of(owner.0) == e.owner_proc;
if !same_task && !same_proc { return Err(NotOwner); }
```

**顺序有讲究**：先比任务（快、无依赖），不等再查进程。

**无进程身份（`NO_PROC`）时不走同进程那条路**：否则两个 boot 任务会因为「都是 `NO_PROC`」
互相通过，那是提权。这一格有专门判据。

### 决策 3：`capability` **不直接调 `sched`**，用函数指针注入

这是本 ADR 最值得记的一条。

`capability` 直接调 `sched::proc_id_of` 会形成**双向依赖**：`sched` 已经依赖 `capability`
（`revoke_task`、`FdTable`），再加反向边就是新的强连通分量 `[capability, sched]`。

`check-module-interfaces` **当场红**：

```
强连通分量与 baseline.known_scc 不符：源码 [...], ['capability', 'sched']
```

仓库里已有解法（`sync::install_wait_ops` 同一模式）：**被依赖方提供注入点，依赖方启动期装进去**。

```rust
// capability/handle.rs
static PROC_OF: AtomicU64 = AtomicU64::new(0);
pub fn install_proc_of(f: fn(usize) -> u16) { ... }
fn proc_of(gidx: usize) -> u16 { ... }   // 没装时回 NO_PROC，不 panic

// sched/mod.rs
pub fn install_proc_of() {
    const _: () = assert!(crate::proc::NO_PROC == u16::MAX);
    crate::handle::install_proc_of(proc_id_of);
}
```

### 决策 4：`NO_PROC` 用字面量 `u16::MAX`，不用符号

**这看起来是坏味道，但它是门禁逼出来的**：`crate::proc::NO_PROC` 属于 `sched` 模块，
在**非测试函数**里引用它会造出那条反向边。门禁剥离 `fn t_*` 与 `mod tests`，但剥离不了
`check` 与 `EMPTY` 常量里的引用。

一致性由 `sched::install_proc_of` 里的 `const _: () = assert!(NO_PROC == u16::MAX);` 守 ——
改一边不改另一边**编译期就崩**。

## 判据七格（`t_handle_proc_owner`）

```
hproc: jobs=[Some(0), Some(1)] pids=[0, 1] 线程=4 同任务=true 同进程=true
       别进程拒=true 无进程不跨=true 转移后=true 旧拒=true 句柄=0->0 ⇒ true
```

**用真线程测**：`proc_attach_thread` + `set_proc_id` 造两条同进程的内核线程。

第一版在 boot 任务上跑，两格都打「无对象可测」——**判据绿但关键路径没验**。
这是本会话第四次同类错误。

## 五个实测撞出来的坑

**① `halt_forever()` 让用例链卡死**：那个函数关中断永久停住，`terminate_task` 收不掉。
改成「有界自旋等标志 + `finish_current()`」（与 `p3_worker` 同一套）。

**② `transfer` 要 `RIGHT_TRANSFER`**：只给 `RIGHT_READ` 时第 5 格红，测的是权限不是归属。

**③ `transfer` 返回新句柄值**：拿旧值去 `resolve` 新主人恒 `Stale`。

**④ 提前 `return` 漏 Job**：`job_create` 失败时直接返回，前面已建的 Job 留在表里 ⇒
后面每个用例的收尾闸都红（一次漏 2 个 ⇒ 3 个用例级联失败）。改成记 `ok = false` 后继续。

**⑤ 哨兵值冲突**：`job_create` 返回的第一个 id 就是 **0**，我用 `!= 0` 判「有没有」⇒
把合法 job 0 当成没有 ⇒ 漏销毁 1 个。改成 `Option<u16>`。

## 未决

1. **`close_on_exec`**（fd 继承语义，本片没做）
2. **引用计数**（切片 B：`close` 递减，最后一引用才销毁）
3. **`revoke_task` 按进程清**：现在仍按任务清，线程退出不回收它装的 fd

## 补记：`OpenSpinLock`（ADR-190 的锁打断了 AHCI 中断）

**这是本切片最意外的发现。**

ADR-190 给块传输加的 `XFER` 锁是 `IrqSpinLock`，而它的 `lock()` **无条件 `save_and_cli()`**。
于是持锁期间中断进不来，而 `t_irq_ahci` 的判据要求「开中断后 ISR 真的进过」
（`ahci::isr_entry() > 0`）⇒ `开中断到过=false`，**4/4 失败**。

实测证据（git 二分）：

| 版本 | 开中断到过 | 判定 |
|---|---|---|
| 去掉 `XFER.lock()` | **true** | **PASS(33)** |
| `IrqSpinLock`（ADR-190） | false | FAIL(35) |

**同一把锁：修好了 `t_fat32`（22% → 5/5 全绿），打断了 `t_irq_ahci`。**

### 修法：新增 `sync::OpenSpinLock`

只做互斥、**不动 IF** 的自旋锁。与 `IrqSpinLock` 共用同一套 rank 与 `INNERMOST` 记账。

**为什么安全**（写进类型文档的三条）：

1. **它不在 ISR 里取** —— AHCI 的 ISR 只读寄存器与计数，不调 `transfer`。
   若将来 ISR 要调，必须换回 `IrqSpinLock`（那会自死锁）。
2. **临界区不分配内存** —— `transfer_inner` 只用 MMIO 与固定栈缓冲。
3. **不自死锁** —— 中断处理不取这把锁 ⇒ 中断里没有第二个获取者。

**代价（如实记）**：持锁期间中断可以进来，临界区必须假设自己被随时打断。
`transfer_inner` 的每一步都是「读/写本端口寄存器 + 自旋等 PxCI」，被打断只影响延迟不影响正确性。

### 仍然没完全修好

换成 `OpenSpinLock` 之后 `开中断到过=true`，但 `t_irq_ahci` **仍偶发红**。

对比读数：

```
PASS: 开中断到过=true  赛跑最大间隔=848
FAIL: 开中断到过=false 赛跑最大间隔=0
```

**`赛跑=0` 说明中断一次都没在轮询之前到达** —— 这是**时序**问题：锁的粒度是「一次传输」，
而一次传输只有几十微秒，中断窗口太短。

**这是 ADR-190 锁粒度的遗留问题，不是本切片引入的**，也不是切片 A 该修的。
如实记为未决 4。

