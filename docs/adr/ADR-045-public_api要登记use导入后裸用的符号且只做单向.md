# ADR-045：public_api 要登记 use 导入后裸用的符号（反向规则，单向）

状态：已采纳（2026-11-08，S1/W1 前置 P0-1；证据见 BACKLOG §97）
关联：ADR-039（接口登记与依赖矩阵基线）、ADR-043（依赖图只统计产品路径）、
V1.0 §2.2/§2.3、AGENTS.md 工作协议"先读相关文件与 ADR"

## 背景

`public_api` 的定义（ADR-039 §决策 1）是"只登记产品路径实际跨模块引用到的 pub 符号"，
但 `check-module-interfaces` 只验了**登记的符号真存在**（registered → source），
没有验反方向（source-referenced → registered）。于是有一类引用系统性逃逸：

```text
kernel/src/handle.rs:25   use crate::sync::{IrqSpinLock, RANK_HANDLE};
kernel/src/handle.rs:165  static TABLE: IrqSpinLock<Table> = IrqSpinLock::new(RANK_HANDLE, ...);
```

`RANK_HANDLE` 在产品路径上被真实引用，却从来没进过登记表——因为扫描只认
`模块::符号` 这种全限定文本，而这里是"导入后裸用"。

用 `.scratch/w1/measure_file_granularity.py` 实测两种口径的差额（剥注释、排除 `ktests/*`
作为引用方与被引用方、跳过 `mod *tests*` / `fn t_*` / `ktest!`，与 ADR-043 同口径）：

- 口径 A（现行文本规则）：登记 283 条，**需要新增 0 条**——现行规则下登记表是自洽的，
  这解释了为什么门禁一直绿而盲区一直存在。
- 口径 B（加上 `use` 树的导入名）：**需要新增 18 条**，分布在 9 个源文件：
  `sync::{IrqGuard, RANK_HANDLE}`、`driver::{DmaHandle, DriverError, IrqHandle, MmioHandle}`、
  `state_store::{BootState, CrashRecord, KIND_CRASH, MAX_FRAMES}`、
  `vfs::{Block, BlockError, FileStat}`、`fat32::{FileCursor, FsError}`、`ahci::AhciError`、
  `hw::MmioRegion`、`x86_64::smp`。
- 另有 **9 条登记了但两口径都查不到引用**：`main::{kmain, mp_snapshot, calibrate_clock_once,
  exit_fatal_from_exception}`（asm/extern 与 ktests 引用）、`sign::{PKG_BYTES,
  PKG_PAYLOAD_BYTES, check_package, digest}`（ktests 引用）、`ktest::KTest`（由 `ktest!` 宏
  展开引用，展开文本不在扫描面里）。**它们不是死条目**——这一条直接决定了规则只能单向。

顺带确证了一件事：登记表的实际粒度是**源文件**（`apic::TimerError` 这种短名规格），
不是逻辑模块——`arch` 逻辑模块 99 条里大半是同模块内跨文件引用（`smp`→`apic`）。
ADR-039 没写清这一点，本 ADR 补上。

## 决策

1. `check-module-interfaces` 增加**反向登记规则**：对每个产品路径源文件（`ktests/*` 除外），
   收集它对别的源文件 pub 符号的引用，两种形式都算：
   - 全限定文本 `…::短名::符号`；
   - `use …短名::{A, B as C, self};` 与 `use …短名::符号;` 里导入的名字（`self` 不计，
     `as` 取原名）。
   凡被引用而所属模块的 `public_api` 没有登记 ⇒ 红，点名 `public_api 漏登记：<文件>::<符号>
   （被 <引用方> 在产品路径上引用）`。
2. **只做单向**。不要求"登记的都是被引用的"：`ktest::KTest`、`main::kmain`、`sign::*` 那 9 条
   是"只被测试/宏/asm 引用"的入口，双向相等会把它们判成死条目并逼人删掉真接口。
3. 粒度写明为**源文件级**；`public_api` 的规格保持 `短名::符号`，由 `short2path` 归一。
4. `ktests/*` 既不作为引用方也不作为被引用方进入这条规则（与 ADR-043 口径一致）。

不涉及：运行语义、锁序、syscall 号、日志契约。本轮内核源码零改动。

## 备选方案

- **双向相等（登记 == 被引用）**：拒绝。见决策 2 的 9 条实测；那会逼出"为了让门禁绿而删接口"
  的反向动作。
- **只补 18 条登记、不改门禁**：拒绝。盲区是规则的性质问题，不是数据问题——W1 要新增
  `WaitQueue`/`RANK_WAITQ`/`RANK_RUNQ` 这批接口，按现有写法它们一定走 `use` 导入裸用，
  不改规则就仍然全部逃逸。
- **按逻辑模块粒度对账**：拒绝。登记表实际是文件粒度（实测 arch 99 条 vs 跨逻辑模块引用 74 条），
  改成模块粒度要删 25 条真实接口信息。
- **把 `ktests/*` 的引用也算进来以覆盖 sign::***：拒绝。那等于推翻 ADR-043 已采纳的口径。

## 影响

- `tools/aurora.py`：`check_module_interfaces` 新增 `imported_names()` 与反向规则（+58 行）。
- `docs/architecture/module-interfaces.toml`：`public_api` 补 18 条（arch 1、storage 6、
  driver 4、pci 1、diagnostics 4、sync 2）。
- 今后任何新增跨模块接口必须在同一轮把 `public_api` 填上，否则 `check` 红——这正是 W1 需要的
  前置：让"接口变大"这件事在门禁里可见，而不是在文档里可见。
- 内核二进制未变：不重跑 41 行矩阵；默认 `run` 53/53 沿用 ADR-044 那一跑的判定。

## 验收与负样本

- `check` 16/16；`public_api` 总数 283 → 301。
- 负样本（在 python 进程内直接调 `check_module_interfaces()`）：
  1. **删登记**：从 `sync` 的 `public_api` 里删掉 `"sync::RANK_HANDLE"` ⇒ 红，点名
     `public_api 漏登记：sync::RANK_HANDLE（被 handle 在产品路径上引用）`；还原 ⇒ 绿。
     这一条同时是盲区的证明：口径 A 下删它**不会**红（实测"口径 A 需要新增 0 条"）。
  2. **新引用未登记**：在 `driver.rs` 产品作用域临时加
     `use crate::sync::LOCK_WATCHDOG_CYCLES; const _: u64 = LOCK_WATCHDOG_CYCLES;` ⇒ 红，点名
     `sync::LOCK_WATCHDOG_CYCLES`；删除 ⇒ 绿。证明规则对**将来**的代码有效，而不只是补了历史账。
  3. **宏/测试面不误伤**：本轮 9 条"登记了但查不到引用"的条目在单向规则下保持绿，
     未被迫删除。

## 迁移与回滚

- 迁移：新增接口时按门禁点名的 `<文件>::<符号>` 填进对应模块的 `public_api`。
- 回滚：删掉反向规则那一段（`imported_names` 可留），并把 18 条登记还原；
  反向规则是纯读检查，不影响任何运行时行为。

## 未决

1. **宏展开与 asm 引用仍是盲区**：`ktest!` 展开出的 `ktest::KTest`、`entry.s` 里对
   `kmain`/`on_interrupt` 的引用，文本扫描看不见——所以本规则只能单向。要闭合需要
   把"入口符号白名单"显式登记（如 `[baseline].entry_symbols`），留给后续。
2. `use` 嵌套花括号（`use a::{b::{c, d}}`）未解析；当前仓库无此写法，出现时按"改量具 +
   负样本"处理。
3. ADR-039 §决策 1 那句"实际跨模块引用"没有定义粒度；本 ADR 把粒度定为源文件级，
   ADR-039 原文不回改（已采纳 ADR 不追加修订），以本 ADR 为准。
4. W1 的前置 P0-2（ADR-020 非 ISA 向量先例）与 P0-3（绝对断言 delta 化）不在本 ADR 范围。
