# ADR-187：stdio 惰性预置（0/1/2）

状态：**已采纳**（2026-11-22：`ensure_stdio` 落地，`fdnum` 七格全 true）

关联：ADR-180（per-process fd 表）、ADR-186（fd 号段，未决 1 就是本 ADR 要解决的）

> 写作纪律：每条结论标「实测」或「推断」。

## 背景

ADR-186 把 fd 号段（72–75）做完了，`socket()` 也返回 fd 了，**但 0/1/2 是空的**。

**任何 POSIX 程序的第一行 `printf` 都会失败**——那是让 fd 这条线真正「能用」的最后一块。

## 三个方案，前两个都错

### 方案 A（错）：在 `proc_create` 里预置

句柄的 owner 是 `(任务全局下标, 任务 id)`，而 `proc_create` 时**还没有线程**——
没有 owner 就无法建句柄。

### 方案 B（错）：在 `process_start` 里无条件预置

`process_start` 是「这个进程能跑了」的时刻，看起来对。但实测：

```
psys: 判据不成立 ... 收场=false
```

建 Console 句柄让 `handle::live()` 涨 1，而 `psys` 的收场判据是 `live == h0`
（「比基线，不比 0」）。**那个判据是对的**——启动一个进程不该凭空多占句柄名额。

而且 `start_ok` 的 `nhandles == 4` 也跟着红（那个 4 = 1 转移 + 3 个 `SELF_*`，
**不是 stdio**）。

### 方案 C（对）：惰性

`ensure_stdio(gidx, tid, pid, pgen)` 只在**进程第一次真的要用 fd 0/1/2** 时
（`fd_lookup` / `fd_list`）才建句柄。

这样「启动一个进程」零成本，「真的要用 stdio」时它就在。

**一个 Console 句柄服务三个 fd**（不是 `dup` 出三份）：Console 对象同时支持读写，
所以这是正确的最小实现。

第一版建了三个，`handle::live()` 涨 3，同样把 `psys` 顶红——
这条也写进了代码注释，防止下一个人再踩。

## 判据

`t_fd_number` 七格：

```
fdnum: fd小整数=true lookup=true list=true after=true fd分支=true stdio=true 坏句柄拒=true ⇒ true
```

### 负样本（变异证红）

把 `preset_std` 那一步短路：

```
fdnum: 惰性 stdio 不成立
fdnum: ... stdio=false ... ⇒ false，FAIL(35)
```

## 一条差点漏掉的判据（本 ADR 最值得记的）

**第一版加完惰性 stdio，108/108 全绿，但 `stdio` 日志一次都没打印**——
说明 `ensure_stdio` 从没被触发过。**判据绿但功能没跑。**

补了一格之后立刻发现：原来的写法走 `fd_list` syscall，而那条路要 `current_proc()`，
用例跑在 boot 任务上（`proc_id == NO_PROC`）⇒ 它验的是「有没有进程上下文」，不是 stdio。

改成**直接验 `preset_std` 在真表上能填 0/1/2**，才真的覆盖。

**这是本会话第三次同类错误**：

| ADR | 判据声称覆盖 | 实际覆盖 |
|---|---|---|
| 184 | NDP 投递 | 只验了「槽还活着」|
| 186 | fd 分支 | 只验了 fd 表本身 |
| 187 | 惰性 stdio | 只验了 syscall 有没有进程上下文 |

**模式一样：加了一条判据，但没验它真的走那条路。**

对策（下一个人该照做）：**加判据之后，先把它依赖的那条路故意弄坏一次，看它红不红。**

## 读数

| 项 | 结果 |
|---|---|
| `check` | **20/20** |
| `handles` 档 | **108/108**，连跑 5 次 **4 次全绿** |

那次失败是既有 `t_sdkdemo`（历史 8%）。

## 未决

1. **三个独立的 stdio 对象**（今天 0/1/2 指向同一个 Console；
   stderr 单独重定向需要三份 `dup`）。
2. **`read`/`write` 的 fd 版**（今天要 `fd_lookup` 再调旧的号，两步）。
3. **句柄引用计数**（`fd_close` 只释放 fd，不减少句柄引用）。
4. **`dup2`**。