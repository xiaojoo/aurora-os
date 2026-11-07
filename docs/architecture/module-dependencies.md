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
| sched | arch, boot, capability, diagnostics, memory, storage, sync, time |
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
| integration (main) | arch, boot, capability, diagnostics, driver, irq, memory, pci, resource, sched, storage, sync, testing, time |

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

负样本（每条都实际跑过，先红后绿）：删一个逻辑模块、伪造 `public_api` 符号、删一条真实
`dependencies`、删一条 `known_violations`、伪造 `unsafe_scope` 类别、从 `known_scc` 删一个成员。
原文见 `BACKLOG.md` §88/§89 与 `.scratch/t01/`。

## 5. 改依赖时怎么做

1. 先改源码；`python tools/aurora.py check` 会在 `check-module-interfaces` 上点名
   “源码多/登记多”。
2. 同步 `module-interfaces.toml` 的 `dependencies` / `allowed_callers`；
   若新增了 forbidden 方向，先决定是**消除**还是**登记 `known_violations`**（后者必须写理由与
   移除任务，不许只写“历史原因”）。
3. 若环变了，更新 `[baseline].known_scc`，并在 BACKLOG 记“哪一个环扩大/缩小”。
4. 跑 `check`；确认 15/15。改坏一处做一次负样本，再还原。
5. 涉及模块边界的决策先写 ADR（规范 §2.2/§12.1；Task E 的流程尚未建立）。

## 6. 已知边界

- 现在只有一个内核 crate，**没有 Cargo 依赖图**可查；本门禁是源码级替代。
- 扫描按“短名::符号”识别引用，字符串字面量里的同名文本可能被误算；注释已剥离。
- 产品文件内的 `#[cfg]` 测试代码也计入依赖（例如 `ahci.rs` 里注册 ktest 产生
  `storage -> testing`）；这是真实编译期依赖，保留。
- `serial` 专属禁止项与“低层不得引用 main 测试函数”两条尚未机器化，列在 §1 的欠账里。
- `known_violations` 是**冻结基线，不是许可**；ADR-040 后 `arch` 这一条已消掉，其余按同样流程处理。
- `hooks` 归入 `arch` 逻辑模块；`arch` 源码不再直接引用 `sched` / `user`（注释除外，扫描已剥注释）。
- `memory` 不再引用 `sched`；VA 保留容量由 `mm::MAX_TASKS_SUPPORTED` 拥有，sched 的
  `MAX_TASKS` 用 `const _: () = assert!(...)` 适配。
- `diagnostics` 不再引用 `sched`；崩溃记录的 `thread_id` 经 `hooks::sched().current_id` 取。
- 依赖图只统计产品路径：产品文件内的 `mod *tests*` / `fn t_*` / `ktest!` 不计入
  （ADR-043）；`capability ↔ sched` 的假二元环因此消失。
- `sched -> boot` / `sched -> storage` 是单向依赖，不在环里但仍是分层欠账。
