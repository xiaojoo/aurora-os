# ADR-206：修 `t_handle_proc_owner` 的两处遗留缺陷（HANG 率下降）

状态：**已采纳**（2026-11-22：HANG 从 8 轮 1 次降到 6 轮 0 次；`hproc` 六次全 true）

关联：ADR-191（句柄 owner 认进程，这个用例就是它的证人）

## 背景：HANG 的统计口径必须先纠正

统计「HANG 率」时第一版把 `qemu-exit=39` 全算成故障，得出 13% —— **那是错的**。

按日志标记剔除「故障注入跑」之后：

| 类别 | 份数（800 份样本）|
|---|---|
| 故障注入跑（`fault-*` / `按设计` / `故意读` / `L3 违规`）| **35** |
| 真实异常 | 13 |
| 真 HANG（无 verdict、无退出码）| 39 |

**「故障注入跑」有四种标记，漏一种就会把设计内运行算成缺陷。**
这条记在这里，因为它是本次分析的第一个坑。

## 定位：HANG 发生在第 35/36 条之间

对比 HANG 跑与正常跑的用例序列：

```
HANG 跑了 35 条，正常跑 122 条
前 35 条完全一致：True
HANG 的最后一条: t_syscall_abi_arms
正常跑的第 36 条: t_handle_proc_owner   ← 就是它
```

## 两处缺陷

### 缺陷 1：`ktest!` 前面残留着调试注释

```rust
// NEGATIVE SAMPLE: 暂时不收集，看 t_irq_ahci 是否恢复
#[cfg(feature = "handles")]
ktest!(KT_HANDLE_PROC_OWNER, t_handle_proc_owner);
```

这是我早前调 `t_irq_ahci` 时留下的，**注释在、收集也在** —— 所以用例其实一直跑着，
但那条注释让后来的人（包括我）以为它没跑。**注释与代码不一致本身就是缺陷。**

### 缺陷 2：第 ④ 格提前 `return false`（**ADR-191 的教训又漏了一次**）

用例自己的注释（第 1571-1573 行）写着：

> **失败不提前返回**（实测教训）：提前 `return` 会把前面已建的 Job 留在表里，
> 后面每个用例的「收尾不变量」闸都会红（一次漏 2 个 Job ⇒ 3 个用例级联失败）。

而第 ④ 格（`grant_console` 失败）**又写了一个提前 `return false`**：

```rust
Err(_) => {
    crate::log_fatal!("hproc: 第二个 grant 失败");
    return false;          // ← 没有 HPROC_GO.store(1)，也没销毁 jobs
}
```

后果两条：

1. **`HPROC_GO` 永远是 0** ⇒ 4 条 worker 各白转 0.126 s（`400_000_000` TSC cycles）；
2. **`jobs` 全部泄漏** ⇒ 收尾不变量闸红（`t_handle_reap 之后仍有 1 个 Job 没销毁`）。

## 修法

第 ④ 格改成「取值 → 判 → 立刻关」的局部块，不跨语句持有：

```rust
let mut no_proc_cross = false;
match handle::grant_console(me, RIGHT_READ, 0) {
    Ok(h_np) => {
        no_proc_cross = handle::resolve(h_np, owner_a, RIGHT_READ).is_err();
        let _ = handle::close(h_np, me);   // 只用一格，立刻关
    }
    Err(_) => {
        crate::log_fatal!("hproc: 第二个 grant 失败");
        ok = false;          // ← 不 return
    }
}
```

**「立刻关」比「用 Option 跨语句持有再在收场关」好**：前者让句柄的生命周期只有三行，
不依赖收场路径；后者正是缺陷 2 的形状。

## 读数

| 项 | 改前 | 改后 |
|---|---|---|
| 8 轮 / 6 轮的 HANG | **1/8** | **0/6** |
| `hproc` 判据 | 未观察到（用例被注释误导，以为没跑）| **六次全 true** |
| `jobs` 销毁 | 泄漏（收尾闸红）| `jobs=[Some(0), Some(1)]` 正确销毁 |
| `check` | 20/20 | **20/20** |

剩下的 FAIL 是既有偶发：`t_map_hole`(~1%)、`t_process_startup`、`t_sdkdemo`(8.9%)、
`t_q2_workload_slots`(2.8%) —— **与本 ADR 无关**。

## 未决

1. **HANG 还有其他来源**：`t_ifaddr`(15)、`t_handle_reap`(4)、`t_block_merge`(4)、
   `t_cross_cpu_lock_contention`(3) —— 本 ADR 只修了最大那一个（第 36 条位置）
2. **6 轮样本太小**：要 20+ 轮才能给出可信的 HANG 率
3. **「注释与代码不一致」没有门禁** —— 这次靠人眼发现