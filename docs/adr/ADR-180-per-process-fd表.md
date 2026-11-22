# ADR-180：per-process fd 表（对齐 POSIX 的前置）

状态：**已采纳**（2026-11-22，使用者裁决「继续」，承接 ADR-178 的 Linux 对齐目标）

关联：ADR-179（句柄表运行时分配）、ADR-178（容量基线）、ADR-007（句柄权限模型）、
ADR-075（每 AS 页表）、ADR-108（FS-03 文件 ABI）

> 写作纪律：每条结论标「实测」或「推断」。

## 背景

### 现状（实测）

| 项 | 现状 |
|---|---|
| 内核句柄 | **全局一张表**，131072 格，带权限位与世代号 |
| 用户态表示 | `pub type Handle = u64`（`user/runtime/src/lib.rs:32`）|
| fd 概念 | **完全不存在**——`grep -r "\bfd\b" user/` 零命中 |
| 文件打开 | 22 号返回一个 `Handle`（带 `RIGHT_READ|RIGHT_WRITE`）|

### 为什么必须改

**Linux/Windows 的 socket 第一个参数是地址族**：

```c
int socket(int domain, int type, int protocol);
//         ^^^^^^ AF_INET / AF_INET6
```

支持 IPv6 的硬前提是 `domain` 参数存在。而 fd 是「进程私有索引」——
没有 fd 表，`socket()` 就只能返回一个全局句柄，**IPv6 无处安放**。

**所以 ADR-180 是 socket + IPv6 的前置，不是可选项。**

## 决策

### 决策 1：采用「ProcEntry 存指针、首次 open 时分配」的形状（与 Linux 等价）

三种候选（都算过代价）：

| 方案 | 代价 | 判断 |
|---|---|---|
| A. `ProcEntry` 内嵌 `[u32; 64]` | 256 B × 32768 = **8 MiB `.bss`** | ❌ 正是 ADR-179 那个坑 |
| B. `ProcEntry` 存指针，按需分配 | ProcEntry +8 B × 32768 = 256 KiB | ✅ **采用** |
| C. 全局 fd 池 + 每进程位图 | 池 2 MiB + 位图 256 KiB | 可行但更复杂 |

**选 B 的理由**：Linux 的 `files_struct` 就是 kmem_cache 按需分配、fd 数组按需增长。
不活跃进程零成本，这是 Linux 与「定长内嵌」的本质区别。

### 决策 2：fd 是 `u32`，从 0 开始，0/1/2 是标准流

| fd | 含义 | 来源 |
|---|---|---|
| 0 | stdin | `StartupInfo` 授的 Console 句柄 |
| 1 | stdout | 同上 |
| 2 | stderr | 同上（今天与 stdout 同句柄）|
| 3.. | 动态分配 | `open`/`socket`/`dup` |

**为什么 0/1/2 必须预置**：POSIX 程序不传 fd 就写 1，`printf` 走的就是这条。
不预置等于「任何 libc 程序的第一行输出就失败」。

### 决策 3：fd 表是**每进程**的，容量 64 起步、可增长

Linux 默认 `RLIMIT_NOFILE=1024`（`include/uapi/linux/limits.h` `NR_OPEN`）。
我们起步 64（`NR_OPEN_DEFAULT`，`include/linux/fdtable.h`），按需翻倍到 1024。

**为什么起步 64 而不是 1024**：64 × 4 B = 256 B/活跃进程，1024 × 4 B = 4 KiB/活跃进程。
按需增长让「开 3 个文件的 shell」与「开 900 个文件的服务器」各自付自己的成本。

### 决策 4：fd → 句柄的映射放在 `handle` 模块，不放 `proc`

理由：fd 表里存的是**句柄值**，而句柄的活性判定在 `capability`（`RANK_HANDLE=35`）。
放进 `proc` 会让 `proc` 依赖 `capability`，而今天 `sched → capability` 已经存在，
反向再加一条会成环。

**形状**：`handle::fd_table_of(proc_slot) -> &mut FdTable`，内部按 `proc_slot` 索引。

### 决策 5：ABI 只增不改

**旧号一个不动**：8/9/10/22/24/25/26 继续收/回 `Handle`。
新增一组 fd 号（**下一轮定号**，本轮不动 ABI）。

这样：

- 现有 7 个用户程序**一行不用改**；
- 新 fd 号与旧句柄号**可以并存**，迁移是渐进的；
- 失败可回退（旧路径一直在）。

## 影响

1. **`ProcEntry` 加一个 `fd_table: AtomicU64`**（HHDM 虚地址，0 = 未分配）。
2. **`handle` 加 `FdTable` 类型 + 5 个操作**（alloc/free/lookup/dup/close）。
3. **`unsafe` 计数会上升**（FdTable 的指针解引用），必须登记白名单。
4. **既有 ktest 全绿是硬要求**——本轮不改 ABI，所以判定表不该出现新的红。

## 补记一（2026-11-22 同日）：把 fd 表接进 `proc_create`，以及一条环的修正

### 第 4 项落地：`fd_table` 不再是空壳

ADR-180 正文的未决 6 是「把 fd 表接进 `proc_create`」。补记这一轮做完了，
并且**发现原设计会泄漏页帧**，改成了懒分配。

**第一版（错）**：`proc_create` 时 `FdTable::allocate()` 分配 1 页。

实测：`proc(P3): baseline=(drained free101500->101498 ...)` —— **少 2 帧**。
因为 `t_proc_job_wait` 这类用例会建很多进程再逐个收，中间态必然「分了还没收」，
下游的 `baseline=false` 就被顶红，连带 5 个用例级联失败。

**第二版（对）**：**懒分配**——`proc_create` 不预分配，`proc_fd_table` 首次被调时才分。

    先查（只持 VMM）→ 没有就锁外分（走 PMM）→ 锁内装 → 竞争兜底（别人先装了就把自己那份还回去）

实测：`proc(P3): baseline=(drained free101486->101486 ...)` —— **完全一致，零泄漏**。

**这与 Linux 的 `files_struct` 语义一致**：`copy_files` 只在真正需要时创建。

### 一条环：`check-module-interfaces` 抓到并纠正了我

把 `FdTable::allocate` 放进 `capability/handle.rs` 之后，门禁报：

    memory.dependencies 不符：源码多 ['capability']
    capability.allowed_callers 不符：源码多 ['memory']
    强连通分量与 baseline.known_scc 不符：源码 [[arch, boot, capability, ...]]
    环内新边 capability->memory（站点 23）未登记棘轮

**根因有两处，我一开始只找到一处：**

| # | 位置 | 为什么成环 | 修法 |
|---|---|---|---|
| 1 | `handle.rs` 里 `phys_alloc_above` | 分配动作本身让 `capability` 出现在 `memory` 的调用者集合 | 改成 `mm::alloc_handle_slots` / `mm::alloc_fd_table_pages`，分配在 mm 侧 |
| 2 | **`mm.rs` 里 `crate::handle::FD_TABLE_INIT`** | 这是真正的**反向边** `memory -> capability` | `release_fd_table(base, bytes)` 收参数，`mm` 不引用 `capability` |

第 2 条是最隐蔽的：它只是一个常量引用，看起来无害，但它就是让两个模块进同一个 SCC 的那条边。

**纪律**：依赖方向必须单向——**`capability` 可以依赖 `memory`，反之不行**。
常量也不行：要传参。

### 读数

| 项 | 结果 |
|---|---|
| `check` | **20/20**（环消除后）|
| `procfd` | `取到=true 独立=true 可用=true ⇒ true` |
| `proc(P3)` 基线 | `free101486->101486`，**零泄漏** |
| ktests | 102 条（新增 `t_proc_fd_table`）|

### 补记二（2026-11-22）：fd 表扩容落地（未决 3 关闭）

### 形状

`FD_TABLE_INIT = 64` 起步，**满了自动翻倍**，到 `FD_TABLE_MAX = 1024` 为止（对齐 Linux `RLIMIT_NOFILE`）。

### 发布协议（决策 3 的实现）

    1. 分配新表（锁外，走 PMM）
    2. 拷旧内容 + 清尾巴
    3. 一次性 store 新 base（Release）
    4. **旧表不立即归还**

第 4 步是刻意的：`lookup` 走 `as_slice` 拿的是**当时那个 base**，换指针之后它手里的旧切片仍然有效（内容还在）。
若立刻归还旧页，那个读者就读到已回收的内存。旧表由 `proc` 侧在进程销毁时一并还。

### 一个必踩的坑：容量记在主人身上，不在视图上

`FdTable` 只是那块内存的一个**视图**；主人是 `ProcEntry`。

所以 `ProcEntry` 加了两个字段：

| 字段 | 作用 |
|---|---|
| `fd_table: AtomicU64` | 表本体地址 |
| `fd_cap: AtomicUsize` | **当前容量** |

**第一版只写回 `cap` 不写 `base`**，实测：

    fdgrow: 重建视图看不见扩容后的 fd（容量没写回主人？）
    fdgrow: 装=65 第65个=Some(64) 旧数据保留=true 重建可见=false ⇒ false

`grow()` 换了一张新表（新 base），但主人还指着**旧表** ⇒ 重建的视图 base 是旧的、cap 是新的 ——
它按 128 格去读一张 64 格的旧表，读到的是旧表之后的内存（脏的）。

修法：`proc_set_fd_table(proc_id, gen, base, cap)` **两个一起写**。

### 判据四格（`t_fd_table_grow`）

     fdgrow: 装=65 第65个=Some(64) 旧数据保留=true 重建可见=true ⇒ true

| 格 | 验什么 |
|---|---|
| 1 | 装满 64 格全成功 |
| 2 | 第 65 个触发扩容，返回 fd 64（不是 Exhausted） |
| 3 | **扩容后旧数据不丢**（fd 0..63 逐个还在） |
| 4 | **容量与基址都写回主人**（重建视图看得见 fd 64） |

### 负样本（变异证红）

把 `proc_set_fd_table` 里 `store(base)` 那一步去掉：

    fdgrow: 装=65 第65个=Some(64) 旧数据保留=true 重建可见=false ⇒ false

**只有第 4 格红**，前三格仍绿 —— 证明第 4 格确实在验「base 与 cap 一起写回」，不是空转。

### 读数

| 项 | 结果 |
|---|---|
| `check` | **20/20** |
| `handles` 档 | **PASS(33)**，103 条 ktest |

### 未决 3 已关闭

fd 表可扩到 1024。剩下的未决是 1（fd 号段）、2（`dup2`）、5（用户态 fd API）。

## 未决 6 已关闭

`fd_table` 字段现在**有真实调用者**（`proc_fd_table`），不再是空壳。

## 未决

1. **fd 号段的分配**（哪个 syscall 号做 `open_fd`/`read_fd`/`close_fd`）——下一轮裁决。
2. **`dup2` 语义**（覆盖目标 fd）——要动 `dup` 的既有语义，需单独 ADR。
3. **fd 表的释放时机**（进程退出时逐项 close，还是整表丢弃）——影响 `revoke_task` 的形状。
4. **用户态 runtime 是否同步提供 fd API**——7 个程序一行不改是硬要求，
   但新 API 需要有人写；本轮只做内核侧。