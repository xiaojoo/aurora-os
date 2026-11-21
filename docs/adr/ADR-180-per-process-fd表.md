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

## 未决

1. **fd 号段的分配**（哪个 syscall 号做 `open_fd`/`read_fd`/`close_fd`）——下一轮裁决。
2. **`dup2` 语义**（覆盖目标 fd）——要动 `dup` 的既有语义，需单独 ADR。
3. **fd 表的释放时机**（进程退出时逐项 close，还是整表丢弃）——影响 `revoke_task` 的形状。
4. **用户态 runtime 是否同步提供 fd API**——7 个程序一行不改是硬要求，
   但新 API 需要有人写；本轮只做内核侧。