# ADR-231：修法 A **无效**（`Done` 不解决问题，`reap` 本来就接受 `Done`）

状态：**拒绝**（2026-11-23：修法 A 实施后 4/20，与修复前完全相同，已回退）

关联：ADR-230（提出修法 A/B/C）、ADR-229（slot 分桶）

> ADR-230 提出三个修法，A 是「`terminate_task` 置 `Done` 而不是 `Free`」。
> **实施了，无效。** 本 ADR 记录为什么。

## 实施内容

```rust
pub fn exit_current(cpu: usize) {
    let me = current_of(cpu);
    terminate_task(me);
    // ADR-231 加的：置回 Done 并登记待回收
    { let mut s = rq(cpu); s.tasks[slot_of(me)].state = TaskState::Done; }
    REAP_PENDING[cpu].fetch_add(1, Ordering::AcqRel);
    mark_need(cpu);
}
```

## 结果：4/20，与修复前完全相同

| | 修复前 | 修复后 |
|---|---|---|
| 失败数 | 4/20 | **4/20** |
| `容器段撤映射=0→2` | 出现 | **仍出现** |
| 失败用例 | `t_fs_open_ring3` ×3、`t_sdkdemo` ×1 | `t_fs_open_ring3` ×2、`t_sdkdemo` ×1、`t_block_wake` ×1 |

**零改善。**

## 为什么无效：我读漏了一行

ADR-230 的推理是「`reap` 接受 `Free`，所以置 `Done` 就不会被收」。

**但 `reap` 的判据本来就有 `|| st == Done`：**

```rust
// sched/mod.rs:508
if st != TaskState::Free && st != TaskState::Done {
    continue;
}
```

注释还写着「`Done` 的判定带 `|| st == Done` 是因为「被杀但映射为空」也要归化成 `Free`」。

**所以 `Free` 与 `Done` 对 `reap` 是等价的 —— 换过去当然没用。**

ADR-230 里我自己引用了这行注释，却没有把它和「修法 A 无效」联系起来。

## 真正的保护是 `gi == cur`，而它失效了

`reap` 里唯一能挡住的是：

```rust
// sched/mod.rs:514
if gi == cur {
    waiting += 1;
    continue;
}
```

`cur = current_of(cpu)`。**若 `exit_current` 返回后 `current_of(cpu)` 仍是探针，这道闸就该生效。**

而实测它在失效 —— 说明 `cur` 已经不是探针了。

**这才是要查的：`current_of(cpu)` 在什么时候变了？**

可能的答案（都未验证）：

1. `terminate_task` 内部某处改了 `s.current`；
2. 探针的 `SYS_EXIT` 在 `loop` 里反复调，**第二次调用时 `current_of` 已经是别人**；
3. `mark_need` 之后、`iretq` 之前的某条路径换过人。

## 为什么回退而不是继续改

1. **我的修法没有实测依据** —— 加 `Done` 是推理，不是验证；
2. **4/20 说明它无效** —— 留着只会让代码多一层没人验证的语义；
3. **AGENTS.md 硬约束 1** —— 不改已实测的调度语义，除非有证据。

回退后 `git diff` 为空，代码与 `bd7c495` 完全一致。

## 这轮的教训

> **「读到了那行注释」不等于「理解了它的含义」。**
>
> ADR-230 引用了 `reap` 接受 `Done` 的注释，却用它去论证「置 `Done` 更安全」——
> 而那行注释恰好说明两者**等价**。

还有一个更实用的：**修法必须先证明「它能改变读数」再实施**。

正确顺序应该是：

1. 先加一个**观测**（比如「`reap` 时 `gi == cur` 的命中次数」）；
2. 看它在失败跑里是 0 还是非 0；
3. 再决定改哪里。

我跳过了第 1、2 步，直接改代码 —— 结果改了也不动。

## 读数

| 项 | 结果 |
|---|---|
| `check` | **21/21**（代码已回退）|
| `git diff` | 空（与 `bd7c495` 一致）|
| 修复前后失败率 | 4/20 → 4/20（**无变化**）|

## 未决

1. **`current_of(cpu)` 何时变成别人** —— 这是下一个要查的（用观测，不是推理）
2. **修法 B/C 未试**
3. **本 ADR 的实施与回退都在一轮内** —— 没有留下未验证的代码