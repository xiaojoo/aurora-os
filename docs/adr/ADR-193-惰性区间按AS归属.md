# ADR-193：惰性区间按地址空间归属

状态：**已采纳**（2026-11-22：`LazyRegion.as_slot` 落地，`lazyas` 五格全 true）

关联：ADR-191（句柄 owner 认进程）、ADR-192（对象引用计数）

> 五样对象化第三片（C）。

## 背景：惰性区间表没有地址空间标识

`LazyRegion` 原来只有 `{ used, base, pages, filled, owner, frames }`，**没有 `as_slot`**。

于是 `lazy_find(va)` 与 `demand_zero_try(cr2)` 都**只按 VA 匹配**：

- 两个 AS 各自 `mmap` 到相同 VA ⇒ 表里命中**对方的区间**；
- `munmap(va)` 可能释放别人的映射。

**今天不可见的原因**：所有 ktest 都是单 AS。

## 决策

### 决策 1：`LazyRegion` 加 `as_slot: u16`

`u16::MAX` = 无 AS（内核 AS 或未绑定）。

### 决策 2：`lazy_find` 与 `demand_zero_try` 都按 AS 过滤

`demand_zero_try` 里 `cr3` 是**故障那个 AS 的**（硬件进 #PF 时已切到故障 AS 的地址空间），
所以 `as_slot_of_cr3(our_cr3())` 是唯一正确的归属判据。

**归属不符时 `continue` 而不是 `return false`**：同一个 VA 在不同 AS 里可能各有一条区间。

### 决策 3：`lazy_new` 记**调用方任务的 AS**，不记 CR3

**这是本 ADR 最关键的修正，也是我第一版做错的地方。**

第一版写 `as_slot_of_cr3(our_cr3())`。实测回归：

```
unexpected #PF rip=0x100103000 cr2=0x100103000 err=0x15 cpu_cpl=3
```

**根因**：mmap syscall 在**内核上下文**里跑，那时的 CR3 可能还是内核表（boot 任务的），
而 #PF 发生在**用户 AS** 里 ⇒ 记下的归属与故障 AS 不符 ⇒ `demand_zero_try` 找不到 ⇒ 任务被杀。

正确做法：取 `sched::current_as_slot()`（任务登记的 `as_slot` 那一格），
它才是这段 VA 将来真正会被访问时所在的地址空间。

### 决策 4：`memory` 不直接调 `sched`，用函数指针注入

与 ADR-191 同一个环问题：`memory -> sched` 会造出新强连通分量。

```rust
// memory/mm.rs
pub fn install_as_of_task(f: fn() -> Option<u16>) { ... }
fn current_as_slot() -> Option<u16> { ... }   // 没装时回 None

// sched/mod.rs
pub fn install_as_of_task() { crate::mm::install_as_of_task(current_as_slot); }
```

## 判据五格（`t_lazy_as_owner`）

```
lazyas: 当前AS=0xffff 别人的AS=0x0 自己找得到=true 改归属前=true
        改后找不到=true 改回找得到=true 释放后没了=true ⇒ true
```

### 判据的第一版是假绿（本会话第五次同类错误）

第一版在 boot 任务上跑（`当前AS=0xffff`），而 `as_slot == cur_as` 在那种情况下**恒成立** ⇒
**负样本（去掉过滤）也不会红**（实测）。

修法：加 `LazyHandle::force_as_slot`（测试专用），造**两条区间**——一条归当前 AS、
一条强行改成别的 AS，后者必须找不到。这才真的验到归属过滤。

## 负样本（变异证红）

去掉 `r.as_slot == cur_as`：

```
lazyas: AS 过滤没生效 改之前找得到=true 改之后找不到=false
```

**FAIL(35)。** 判据精准咬住。

## 读数

| 项 | 结果 |
|---|---|
| `check` | **20/20** |
| `handles` 档 | 3 次跑 **3 次全绿（112/112）** |

## 未决

1. **区间拆分**（`munmap` 只收整段，不能切子区间）—— Linux 的 `do_munmap` 可以
2. **`mprotect` 要求整段覆盖**
3. **`MAX_LAZY_PAGES = 64`**（单次 mmap 上限 256 KiB）
4. **切片 D/E**：块层队列、VFS 三层