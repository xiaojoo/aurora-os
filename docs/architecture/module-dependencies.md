# 模块依赖矩阵（架构规范 V1.0 Task B）

机器可读的唯一来源是 [`module-interfaces.toml`](module-interfaces.toml)：
`dependencies`、`forbidden_dependencies`、`known_violations` 与 `[baseline].known_scc`
都由 `python tools/aurora.py check` 的 `check-module-interfaces` 逐项对账。
本文只解释这张矩阵怎么读、当前欠什么、改依赖时怎么做。

## 1. 目标方向（规范 §2.1/§2.2）

依赖只能从高层指向低层：

```text
Kernel Integration  (main)
Kernel Services     (sched / storage / security / testing)
Kernel Core         (memory / sync / time / resource / capability / diagnostics)
Driver Framework / HAL (driver / pci / irq)
Architecture        (arch)
Boot / Platform     (boot)
```

规范 §2.2 明示的禁止项：

| 禁止 | 当前源码 | 状态 |
| --- | --- | --- |
| `mm` → `ahci` / `virtio` | 无 | 干净 |
| `trap` → `user` 业务实现 | 无（ADR-040：trap 经 `hooks` 调 `user::syscall_dispatch` / `park_current`） | 干净 |
| `pci` → 具体 AHCI | 无 | 干净 |
| `driver` → `ahci.rs` / `virtio.rs` | 无（唯一命中的 `ahci::RING` 在注释里，扫描已剥注释） | 干净 |
| `resource` → 调度器内部任务结构 | 无 | 干净 |
| `serial` → 业务模块私有状态 | 尚未做**源码级**判定（逻辑模块 `diagnostics` 经 state_store/crash 依赖 storage/sched，但那是别的源模块） | **门禁未覆盖**（欠账） |
| 低层模块 → `main.rs` 的集成测试函数 | 尚未做源码级判定；`handle.rs` 的 cfg 测试用 `crate::{HELLO_ELF,P7_CALLS,drain_reap}`（仅测试） | **门禁未覆盖**（欠账） |

## 2. 当前实际矩阵（实测，`//` 注释已剥离，`ktests/*` 除外）

| 逻辑模块 | 实际依赖（`dependencies`） |
| --- | --- |
| boot | diagnostics, sync |
| arch | boot, diagnostics, irq, memory, pci, sync, time |
| memory | arch, boot, diagnostics, resource, sync, time |
| sched | arch, boot, capability, diagnostics, input, memory, storage, sync, time |
| sync | arch, diagnostics, time |
| driver | arch, irq, memory, pci |
| pci | arch, memory, sync |
| irq | arch, memory, sync |
| storage | arch, boot, driver, irq, memory, pci, sync, time |
| diagnostics | arch, memory, storage, sync, time |
| security | （无产品路径出边；签名目前只在用例里调用） |
| time | arch, diagnostics, sync |
| capability | storage, sync |
| resource | memory, sync |
| testing | diagnostics |
| display (S6b) | boot, diagnostics, memory, pci, sync |
| input (S6c) | arch, diagnostics, irq, memory, pci, sync |
| integration (main) | arch, boot, capability, diagnostics, display, driver, input, irq, memory, pci, resource, sched, storage, sync, testing, time |

## 3. 循环依赖基线（实测）

当前实际图有**一个 11 模块的强连通分量**（ADR-043 后实测）：

```text
环 A（11）：arch · boot · diagnostics · driver · irq · memory · pci
            · resource · storage · sync · time
```

`capability`、`sched`、`testing`、`security`、`integration` 是单点。这意味着目标分层
目前**没有成立**：任何“低层不得反向依赖高层”的说法，在环 A 的 11 个模块之间都还不成立。
`[baseline].known_scc` 把现状冻结：**新增环成员或改变环的划分 ⇒ `check-module-interfaces`
红**。拆环是好事，但必须显式更新 baseline，并在 BACKLOG 记一条“环缩小了”。

消环记录：ADR-040 消 `arch -> sched`；ADR-041 消 `memory -> sched`；ADR-042 消
`diagnostics -> sched`。ADR-043 修正量具：产品文件内的 `mod *tests*` / `fn t_*` / `ktest!`
不计入依赖边——`capability ↔ sched` 的二元环其实是 handle.rs 的 `mod tests` 造成的假环；
修正后它消失，`testing` 也离开环 A，SCC 从 12+2 变成 11。`sched -> boot` /
`sched -> storage` 是单向跨层依赖，不在环里但仍是欠账。

## 4. 门禁规则（`check-module-interfaces`）

1. main.rs 每个顶层 `mod` 恰好被一个逻辑模块覆盖；`main.rs` 本体也必须登记。
2. `public_api` 的每个符号在声称的源模块里真的是 `pub`/`pub(crate)`。
3. `dependencies` / `allowed_callers` 与源码实际引用边**双向相等**（剥 `//` 注释、排除 `ktests/*`，并跳过产品文件内的 `mod *tests*` / `fn t_*` / `ktest!`）。
4. 实际命中 `forbidden_dependencies` 的边必须列在 `known_violations`；基线过期也红。
5. `unsafe_scope` 的模块×类别在 `unsafe_sites()` 重算里确实存在。
6. `[baseline].known_scc` 与实际强连通分量相等。
7. `test_targets` 的 `t_*` 函数确实存在。
8. **环内边的引用站点数棘轮**（ADR-044）：`[baseline].ring_edge_sites` 与实际站点数**相等**。
   增一处红（"只许减不许增"），减一处也红（"请把登记一起收紧"）——只登记上界会被下一个人
   悄悄用掉余量。环外的单向边（`sched -> boot` 这类）不套棘轮。

负样本（每条都实际跑过，先红后绿）：删一个逻辑模块、伪造 `public_api` 符号、删一条真实
`dependencies`、删一条 `known_violations`、伪造 `unsafe_scope` 类别、从 `known_scc` 删一个成员、
棘轮三向（环内 +1 红 / 环内 −1 红 / 非环边 +1 绿）。
原文见 `BACKLOG.md` §88/§89/§96 与 `.scratch/ringcut/`。

## 5. 改依赖时怎么做

1. 先改源码；`python tools/aurora.py check` 会在 `check-module-interfaces` 上点名
   “源码多/登记多”。
2. 同步 `module-interfaces.toml` 的 `dependencies` / `allowed_callers`；
   若新增了 forbidden 方向，先决定是**消除**还是**登记 `known_violations`**（后者必须写理由与
   移除任务，不许只写“历史原因”）。
3. 若环变了，更新 `[baseline].known_scc`，并在 BACKLOG 记”哪一个环扩大/缩小”。
4. 若环内某条边的引用数变了，同步 `[baseline].ring_edge_sites`（ADR-044 棘轮；消掉一整条边
   就删那一行）。
5. 跑 `check`；确认 16/16。改坏一处做一次负样本，再还原。
6. 涉及模块边界的决策先写 ADR（规范 §2.2/§12.1；`check-interface-change` 会拦住”改了登记表
   却没写 ADR”）。

## 6. 已知边界

- 现在只有一个内核 crate，**没有 Cargo 依赖图**可查；本门禁是源码级替代。
- 扫描按”短名::符号”识别引用，字符串字面量里的同名文本可能被误算；注释已剥离。
- 站点数按**行**计：同一行里两处 `mm::` 只算 1。棘轮因此是”引用面”的量，不是”调用次数”的量。
- `serial` 专属禁止项与“低层不得引用 main 测试函数”两条尚未机器化，列在 §1 的欠账里。
- `known_violations` 是**冻结基线，不是许可**；ADR-040 后 `arch` 这一条已消掉，其余按同样流程处理。
- `hooks` 归入 `arch` 逻辑模块；`arch` 源码不再直接引用 `sched` / `user`（注释除外，扫描已剥注释）。
- `memory` 不再引用 `sched`；VA 保留容量由 `mm::MAX_TASKS_SUPPORTED` 拥有，sched 的
  `MAX_TASKS` 用 `const _: () = assert!(...)` 适配。
- `diagnostics` 不再引用 `sched`；崩溃记录的 `thread_id` 经 `hooks::sched().current_id` 取。
- 依赖图只统计产品路径：产品文件内的 `mod *tests*` / `fn t_*` / `ktest!` 不计入
  （ADR-043）；`capability ↔ sched` 的假二元环因此消失。
- `sched -> boot` / `sched -> storage` 是单向依赖，不在环里但仍是分层欠账。

## 7. 环的最小割分析（实测，ADR-044）

问题：环 A 还能不能再靠"消一条边"缩小？量具是 `.scratch/ring_scenarios.py`
（同一套剥注释/排测试的规则，DP over subsets 求精确最小反馈边集，权重=先最小化边数、
再最小化站点数）。

**事实一：没有任何一条边能拆环。** 环内 46 条边、449 个引用站点（`check-module-interfaces`
实测），其中**互为双向的有 11 组**——`arch` 对 `diagnostics/irq/memory/pci/sync/time` 六组，
`diagnostics` 对 `memory/sync/time` 三组，`memory<->resource`、`sync<->time` 各一组。每一组
至少要断一条，所以最小割的下界是 11；精确解是 **12 条边 / 90 个站点**。

**事实二：把模块拆开不会让割变小，只会让它变大。** 拆 `diagnostics`（把 `serial`、`exit`
独立）或按关注点拆 `arch`（`smp`/`trap`/`apic` 独立）之后：

| 操作（实测） | 环大小 | 最小割边数 | 割的站点成本 |
| --- | --- | --- | --- |
| S0 现状 | 11 | 12 | 90 |
| S1 `serial` 独立为 console | 12 | 12 | 75 |
| S2 S1 + `exit` 独立 | 13 | 12 | 69 |
| A1 `smp` 独立到 arch 之上 | 11 | 12 | 68 |
| A2 A1 + `trap` 独立 | 12 | 15 | 63 |
| A3 A2 + `apic`/`hooks` 独立 | 14 | 18 | 51 |
| A4 A3 + `irq` 并入 lapic | 13 | 17 | 49 |

每条割边变细了（51~75 vs 90），但要割的刀数涨了——这是**记账口径的改善，不是耦合的改善**。

**事实三：只有"合并"能减少割的刀数。** 把本质同层的双向对并成一个逻辑模块：

| 操作（实测） | 环大小 | 最小割边数 | 割的站点成本 |
| --- | --- | --- | --- |
| M1 `sync`+`clock`+`tsc` 并入 arch | 9 | 8 | 73 |
| M2 M1 + `resource` 并入 memory | 8 | 7 | 72 |
| M3 M2 + `irq` 并入 arch | 7 | 6 | 71 |
| M4 M3 + `pci`/`hw`/`acpi` 并入 arch | 6 | 5 | 76 |
| M5 M4 + `serial` 并入 arch | 6 | 5 | 55 |

M 系列不是架构改进而是**改标签**：`arch` 会膨胀成装着 20 个源文件的"底层"，规范 §1.3
反对的正是这种为了图好看的重划。所以不采纳。

**事实四：规范 §2.1 的六层图与当前图差得更远。** 按声明的 `layer` 取值统计"低层引用高层"
的边：**36 条 / 644 个站点**（实测）。六层是 crate 拆分阶段的目标，不是再写几份 ADR 能达到的。

**结论（采纳）**：ADR-040/041/042/043 那四刀能消，是因为它们消的是**真实多余的边**
（arch/memory/diagnostics 对 sched 的反向调用、以及量具把测试算成依赖）。剩下的 11 模块环
是单 crate 下 `arch` 同时充当"原语层"和"SMP/中断入口/APIC 驱动层"的必然形状——
**继续消环的边际收益为零**。本轮把它冻结为基线，并加第 8 道棘轮规则，让环只能变瘦：
将来任何一次真实解耦都会把某个登记数字逼小，而那必须显式改登记表——进度从此落在门禁里，
不落在文档里。

若日后真要拆环（例如拆 crate 时），S0 的 12 条割边工作清单是：
`resource->memory`(1) `arch->irq`(2) `time->sync`(2) `sync->diagnostics`(3) `time->arch`(3)
`time->diagnostics`(3) `arch->pci`(4) `memory->diagnostics`(7) `boot->diagnostics`(11)
`sync->arch`(14) `arch->diagnostics`(19) `arch->memory`(21)。
