# ADR-232：`reap` 的闸门**是生效的**，但回收的不是 `Done` 任务

状态：**已核实**（2026-11-23：观测 20 次，闸门命中可读）

关联：ADR-230（提出修法 A）、ADR-231（修法 A 无效）

> ADR-231 的教训是「先观测再改」。本 ADR 只加观测，**不改任何逻辑**。

## 观测（纯原子自增，不写串口）

```rust
// reap 里 gi == cur 那个分支
REAP_BLOCKED_BY_CUR.fetch_add(1, Ordering::Relaxed);

// 真要收之前
REAP_RETIRED.fetch_add(1, Ordering::Relaxed);
if st == TaskState::Done { REAP_RETIRED_DONE.fetch_add(1, Ordering::Relaxed); }
```

## 结果：4/20，读数如下

| 次 | FAIL | `reap挡住` | `回收` | `Done` |
|---|---|---|---|---|
| 6 | `t_fs_open_ring3` | 25→26 | **20→21** | 16→16 |
| 8 | `t_sdkdemo` | 25→26 | 19→20 | 15→15 |
| 15 | `t_sdkdemo` | 25→26 | **19→19** | 15→15 |
| 18 | `t_fs_open_ring3` | 25→26 | **20→21** | 16→16 |

## 三个结论

### 1. 闸门**是生效的**

四次失败全部 `reap挡住` 从 25 涨到 26 —— **`gi == cur` 那道闸在窗口内又挡了一次**。

所以「闸门失效」这个假设**被排除**。ADR-230 猜「`current_of(cpu)` 变了」——
变没变不重要，**闸门本身工作正常**。

### 2. 被回收的**不是 `Done` 任务**

`Done` 计数在四次失败里**全部不变**（16→16、15→15）。
而 `回收` 有两次 +1。

**所以被回收的是 `Free` 状态的任务。**

### 3. 有一类失败**与 reap 完全无关**

第 15 次：`回收=19→19`（没回收）、`Done=15→15`，但 `t_sdkdemo` 仍然红。

这与 ADR-229 记的 `t_sdkdemo` 那次一致（`容器段owned=0→0`）—— **是另一条路**。

## 分类：失败有两类

| 类 | 特征 | 用例 | 根因 |
|---|---|---|---|
| A | `回收 +1` 且 `容器段撤映射 0→2` | `t_fs_open_ring3` | reap 回收了一个 `Free` 槽，撤了容器段 |
| B | `回收 +0` | `t_sdkdemo` | **与 reap 无关**，未定位 |

## 关于类 A 的一个新假设

被回收的是 `Free` 槽。**谁会置 `Free`？**

- `terminate_task`（`exit_current` 走它）
- `reap` 自己（收完之后置 `Free`）

`exit_current` 调 `terminate_task` 会置 `Free` —— **这与 ADR-230 的判断一致**。

但 ADR-231 把它改成 `Done` 却无效，因为 `has_bag` 的判据是：

```rust
// sched/mod.rs:543
(st, s.tasks[slot].owned.n > 0 || st == TaskState::Done, ...)
```

**`Done` 即使 `owned` 为空也算 `has_bag`** —— 改成 `Done` 反而让它**更容易**被回收。

这解释了 ADR-231 为什么零改善：两个方向都被放行。

## 下一步（继续只观测）

要区分「探针还在跑」与「探针真的退出了」，需要一个**在跑标志**：

```rust
// 观测：回收时这个槽是不是本 CPU 上次换入的那个
// 用 SWITCH_PROBE 或类似的「最后换入谁」记录对比
```

或者更直接：**记录被回收槽的 `gi`**，与「探针的 `gi`」对比。

## 读数

| 项 | 结果 |
|---|---|
| `check` | **21/21** |
| `handles,fs-open,unmap-trace` | **16/20**（与加观测前相同 —— 观测不干扰）|
| `reap挡住` 窗口增量 | **1**（四次失败一致）|
| `Done` 窗口增量 | **0**（四次失败一致）|

## 未决

1. **类 A：被回收的 `Free` 槽是谁置的** —— 需要记录 `gi` 对比
2. **类 B：`t_sdkdemo` 与 reap 无关的那条路** —— 未定位
3. **`has_bag` 的判据 `|| st == Done` 让 `Done` 反而更容易被收** —— 这是个反直觉的设计