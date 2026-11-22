# ADR-188：`read`/`write` 的 fd 版（76/77）

状态：**已采纳**（2026-11-22：76/77 落地，`fd_read`/`fd_write` 一步到位）

关联：ADR-186（fd 号段）、ADR-187（stdio 惰性预置）

> 写作纪律：每条结论标「实测」或「推断」。

## 背景

ADR-186/187 之后，一个 POSIX 程序的 `printf` 要走两步：

```
h = fd_lookup(1)        // 73 号：fd → 句柄
console_write(h, buf, n)  // 20 号：句柄 → 写
```

**两步不是 libc 的形状**：`write(fd, buf, n)` 是一个 syscall。

## 决策

### 决策 1：新增 76/77，语义是「fd + 缓冲 + 长度」

| 号 | 名字 | 签名 |
|---|---|---|
| 76 | `SYS_FD_READ` | `(fd, buf_ptr, len)` → 读到的字节数 |
| 77 | `SYS_FD_WRITE` | `(fd, buf_ptr, len)` → 写出的字节数 |

**参数顺序与 POSIX 一致**：`read(fd, buf, count)` / `write(fd, buf, count)`。

### 决策 2：按 fd 指向的对象类型分派，**不新写一套 IO**

```
fd_read/write(fd, buf, len):
    h = fd_table.lookup(fd)
    obj = handle.resolve(h)
    match obj:
        Console(sid) → 复用 sys_console_io 的逻辑
        VfsFile{..}  → 复用 10/23 号的逻辑
        Socket{..}   → 复用 53/54 号的逻辑
        其它          → -95（EOPNOTSUPP）
```

**为什么不新写**：每种对象的 IO 都已经有实现，而且都带实测过的边界检查
（`COPY_MAX`、`CONSOLE_MAX`、`UDP_PAYLOAD_MAX`）。重写一遍等于把那些检查再写一次，
漏一处就是一个越界。

### 决策 3：本轮只接 Console，其余回 `-95` 并记日志

Console 是 stdio 的载体，**接上它 `printf` 就能用**。

文件与 socket 的分派留着，但**不假装实现**：遇到它们回 `-95` 并打日志点名
（「fd_write 遇到 VfsFile，本轮未接」）。

**不静默降级成 Console**：那会把文件内容写到串口上。

## 本轮范围

| 项 | 本轮 |
|---|---|
| 76 `fd_read` / 77 `fd_write` | **做** |
| Console 分派 | **做** |
| VfsFile / Socket 分派 | 未做（回 -95 并记日志）|

## 未决

1. **VfsFile 分派**（复用 10/23 号，但那个要 `ReadTicket`，锁序要重新审）。
2. **Socket 分派**（复用 53/54，但 socket 的 `send` 要 `connect` 过）。
3. **`readv`/`writev`**（分散/聚集 IO）。
4. **`lseek` 的 fd 版**（24 号今天要句柄）。