# ADR-186：fd 号段（socket 与文件返回 fd，不再返回句柄）

状态：**已采纳**（2026-11-22：72–75 四个 fd 号落地，socket 返回 fd）

关联：ADR-180（per-process fd 表）、ADR-181（socket 族）、ADR-183（双栈）

> 写作纪律：每条结论标「实测」或「推断」。

## 背景

ADR-180 建了 per-process fd 表，ADR-181 把 socket 接上了，但**`socket()` 返回的是句柄**，
不是 fd。ADR-181 决策 3 当时写的就是「等 fd 号段定了，只需在句柄外面包一层」。

### 为什么必须做

| 项 | 句柄 | fd |
|---|---|---|
| 值域 | 64 位带世代号 | **小整数**（0/1/2 是标准流）|
| POSIX 兼容 | 否 | 是 |
| `read`/`write`/`close` 通用 | 否（要按 kind 分派）| 是 |

**没有 fd，任何 libc 都无法工作**：`printf` 写 fd 1，`open` 返回 fd，`close` 收 fd。

## 决策

### 决策 1：新增 72–75 四个号，**旧号一个不动**

| 号 | 名字 | 语义 |
|---|---|---|
| 72 | `SYS_FD_INSTALL` | 把一个句柄装进当前进程的 fd 表，返回 fd |
| 73 | `SYS_FD_LOOKUP` | fd → 句柄（用户态要拿它去调别的号时用）|
| 74 | `SYS_FD_CLOSE` | 释放 fd（**不销毁对象**，对象仍归句柄层）|
| 75 | `SYS_FD_LIST` | 枚举当前进程的 fd（判据与 `ls /proc/self/fd` 用）|

**为什么是四个而不是一个 `fd_open`**：

- `install` 与 `lookup` 是**双向映射**，缺一个就只能在用户态猜；
- `close` 必须与 `lookup` 分开——它要 `&mut` 表，语义不同；
- `list` 是**判据的证人**：没有它，`install` 之后「表里到底有什么」无法从用户态验。

### 决策 2：fd 是 `u32`，0/1/2 保留给标准流

`install` 从 3 开始分配。0/1/2 由 `preset_std` 在进程创建时填（ADR-180 决策 2）。

**今天 `preset_std` 还没被任何路径调用**——那是未决 1。

### 决策 3：`socket()` 返回 fd，不再是句柄

`sys_sock_create` 改成：

```
grant_socket(owner, slot, gen, rights)  →  Handle
fd_install(handle)                      →  fd
返回 fd
```

**旧行为（返回句柄）不能保留**：同一个号返回两种东西，用户态无法分辨。
这是**破坏性变更**，但它只影响我们自己写的 7 个用户程序——而那些程序今天没调过 48 号
（`grep SOCK_CREATE user/` 零命中，实测）。

### 决策 4：`fd_close` 只释放 fd，不销毁对象

```
fd_close(fd):
    h = fd_table.release(fd)     // 只清这一格
    // **不调 handle::close(h)**：
    // 句柄可能还被别的 fd 或别的进程引用（dup 之后）。
    // 销毁走 handle::close，那是另一件事。
```

**这是 POSIX 的语义**：`close(fd)` 减少一个引用，最后一个引用消失时才销毁。
我们今天的句柄层没有引用计数，所以**保守地只释放 fd**——泄漏一个句柄比误销毁好。

已写进未决 2。

### 决策 5：`fd_list` 的输出是紧凑的 `(fd, kind)` 数组

```
struct FdEntry { fd: u32, kind: u32 }   // 8 字节
```

**为什么带 kind**：用户态光知道「fd 3 存在」没用，它要知道「这是 socket 还是文件」。
`kind` 复用 `KIND_*` 常量（`KIND_FILE`/`KIND_SOCKET`/…）。

## 本轮范围

| 项 | 本轮 |
|---|---|
| 72–75 四个号 | **做** |
| `socket()` 返回 fd | **做** |
| `preset_std` 接进进程创建 | 未做 |
| `read`/`write` 通用 fd 版 | 未做 |

## 未决

1. **`preset_std` 接进 `proc_create`**：0/1/2 今天还是空的，`printf` 会失败。
2. **句柄引用计数**：`fd_close` 现在只释放 fd，不减少句柄引用（见决策 4）。
3. **`read`/`write` 的 fd 版**：今天要 `fd_lookup` 再调旧的号，两步。
4. **`dup2`**（覆盖目标 fd）。