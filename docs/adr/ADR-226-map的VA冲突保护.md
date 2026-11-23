# ADR-226：`mm::map` 的 VA 冲突保护（**否掉 ADR-225 的假设 1**）

状态：**已核实**（2026-11-23：读了实现，假设 1 不成立）

关联：ADR-225（提出三个假设，本 ADR 否掉第一个）

> ADR-225 的假设 1 是「`mm::map` 不检查 VA 冲突」。
> **读了实现：它有保护。假设不成立。**

## 证据

`mm::map`（`mm.rs:1382`）→ `set_leaf`（`mm.rs:1287`）→ `set_leaf_in`（`mm.rs:1293`）：

```rust
if unsafe { *e } & P_PRESENT != 0 {
    return Err(MmError::AlreadyMapped);
}
```

注释也写着：**「已存在的映射报 `AlreadyMapped` 而不是静默覆盖」**。

而 `mm::map` 在 `set_leaf` 失败时会**回滚已建立的部分**（`mm.rs:1401-1403`）：

```rust
if let Err(e) = set_leaf(a, p | flags.bits(), false, flags.user) {
    for j in 0..k {
        clear_leaf(VirtAddr(va.0 + (j as u64) * PAGE as u64));
    }
    return Err(e);
}
```

所以「同一 VA 被映射两次、第二个覆盖第一个」这条路径**不存在**。

## 这条假设被否掉的价值

ADR-225 把「`mm::map` 不查冲突」列为**最可疑**的假设，理由是它能同时解释多个偶发。
现在它被排除了 —— **多个偶发不能用这一个根因解释**，得分别查。

这比继续在错误方向上找要省时间。

## 顺带确认的两件事

### 1. 唯一的解映射路径是 `Mapping::drop`

`Mapping::drop`（`mm.rs:264`）→ `unmap_pages` + `release_va_locked`。

全仓库只有 `unmap_pages` / `unmap` / `unmap_locked` 三处，都在这条链上。
**所以「窗口内页被撤掉」只能是某个 `Mapping` 被 drop 了。**

### 2. `release_va_locked` 按「包含」找，不按「基址相等」

```rust
if base >= r.base && base < r.base + r.len {
```

注释解释了为什么（`KT_TASK_EXIT` 第一版栽在按基址相等匹配上）。
**这一条是对的**，而且 ADR-207 的位图批扫也还在。

## 修正后的假设集

| 编号 | 假设 | 状态 |
|---|---|---|
| 1 | `mm::map` 不查 VA 冲突 | **已排除**（本 ADR）|
| 2 | `is_mapped` 与 `peek_u64` 判据不同 | 待验证 |
| 3 | 窗口内有 `Mapping` 被 drop | 待验证（**唯一可能**）|

假设 3 现在是唯一的解释，而它的范围已经收窄到：

**「哪个 `Mapping` 会在窗口内被 drop，而它的 `virt` 落在 `data_va` 附近？」**

## 下一步（具体到可执行）

在 `Mapping::drop` 里加一行**仅在 `t_fs_open_ring3` 关心范围内的日志**：

```rust
if self.virt.0 >= 0x1000c0000 && self.virt.0 < 0x1000d0000 {
    crate::log_info!("unmap 命中容器段 va={:#x} pages={}", self.virt.0, frames.count());
}
```

窗口内若出现这行，就抓到了「谁在撤页」。

## 读数

| 项 | 结果 |
|---|---|
| `check` | **21/21**（本 ADR 只读代码，无改动）|

## 未决

1. **假设 2、3 未验证**
2. **下一步的日志插桩未做** —— 它需要改 `mm.rs`，属于「不改已实测语义」的边缘，
   应只加日志、不加分支