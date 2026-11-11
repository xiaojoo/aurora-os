# ADR-082：产品启动路径**真起 ring3**（S4a）——判据是用户态信箱，不是串口

状态：**已采纳**（2026-11-12；使用者裁决"先做整体代码开发、先串口 CLI 再图形、测试只做基础"，
本文是那条裁决下的第一片 S4a）
关联：ADR-075（用户 ABI 与 `StartupInfo`）、ADR-026（映射生效位）、ADR-073（进程/Job 与等待）、
ADR-007（capability，**产品路径授予留 S4b**）；`docs/design/完整化路线-M0至M9-依赖重排与四裁决.md` W5；
BACKLOG §229（转向与切片计划）

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计；每条结论标「实测」或「计划」。

## 背景

**产品启动路径此前根本不起 ring3**（实测：`main.rs` 里搜不到 `spawn_user`/`enter_ring3`），
用户态执行**只在 ktest 里**。⇒ 没有 init 进程，也就不可能有 shell。
这是 CLI/UI 的第一道闸门，与显示/输入硬件**无关**（BACKLOG §229）。

## 决策

### 1. 在 ktests 之后、判定之前加 `stage_init_user()`（实测已落地）

位置：`run_ktests_and_finish()` 里，P3 量具自检之后、`clean` 判定之前。
**为什么放这里**：用例读数（`s`）已经算完，产品路径起用户程序**不影响 ktests 判定**；
同时 hello 的执行痕迹能进同一份串口，便于对账。

### 2. 装载用与 ktest 同源的嵌入式夹具（实测已落地）

`crate::ktests::common::HELLO_ELF`（`include_bytes!`）。
**从卷上取 ELF 那条路已在 L3-C 交付，本片不重做**；S5 的 shell 再决定从哪里取。

### 3. **判据是用户态信箱，不是串口字符串**（实测，本片最重要的一条）

`user/hello` **不打印**，它往自己的数据段写 `magic/ping/add/...`（`user/hello` 的 `OFF_*` 常量）。
⇒ "产品路径真跑过 ring3"的证据是**这几个槽被用户态写过**：
`user::read_at(loaded.data_va + 0/8/16)`。
**第一版把判据写成"串口出现 hello 输出"是错的**，跑起来串口什么都没有、差点误判成失败。

### 4. `bounded_wait_done=false` 是**预期**，不是失败（实测）

hello 写完信箱就停在自旋里，**不会自己收工**。所以有界等待返回 false 是正常的；
判据只看信箱，不看它是否收工。**本片不 terminate 它**（它是常驻 init 的雏形）。

### 5. 明确**不在本片**做的

- **句柄授予**（权限只从句柄来）⇒ **S4b**。本片仍是内核直接把映射交给任务。
- **`MAX_TASKS = 9` 零余量重算** ⇒ **S4c**。init 常驻会占一格，ktest 的 spawn 炸弹判据要跟着改。
- 串口输入、shell 命令、framebuffer、PS/2 ⇒ S5/S6。

## 备选方案

- **在 ktests 之前起 init**：否。会让用例的残留扫描（`finish_sweep`）把 init 当成未登记的可运行任务而红。
- **用 `user/probe` 而不是 `hello`**：否。probe 是 syscall 探针（18 KB），本片只要"跑起来并留下痕迹"，
  hello 更小且信箱契约已成熟。
- **等 S4b 一起做**：否。使用者要求小步、每片独立过基础测试；先把"产品路径能起 ring3"这件事单独证掉。

## 影响

- `main.rs` 新增 `stage_init_user()`；`module-interfaces.toml` 登记 4 个 public_api
  （`sched::wait_for_task`、`user::load`、`user::describe_load`、`user::read_at`）——
  它们本来只在 ktest 里用，现在**产品路径也引用**，登记是正当后果。
- **不改** syscall 号、不改锁序、不改日志契约（只新增一行 `init-user:` info）。
- 退出码与 ktests 判定不变（实测 PASS/33、81/81）。

## 验收与负样本

- **实测（run-922，elf `c1851dd91436`）**：
  `init-user: 产品路径起 ring3 任务=2 entry=0x100000000 栈顶=0x100105ff0 段=3 页=5 等待收工=false`
  `信箱 magic=Some(11936045730314344056) ping=Some(33) add=Some(60)`；
  `ktests: total=81 passed=81 failed=0`；`verdict: PASS`、`qemu_rc=33`。
  magic 与 ktest 里 `elfload:` 那行的值**逐字相同** ⇒ 同一份产物、同一套契约。
- **负样本（计划，未做）**：把 `spawn_user` 的入口地址改成未映射页 ⇒ 应当 #PF 升 L4；
  把信箱判据的偏移改错 ⇒ 应当读回 None 而判红。**本片尚未配负样本，记为欠账。**
- 基础测试口径（使用者裁决）：`build` + `ktests` + `check` + 1–2 行矩阵；**不跑猎挂**。

## 迁移与回滚

- 迁移：无旧接口要迁。
- 回滚：删掉 `stage_init_user()` 的调用即回到"产品路径不起 ring3"。
- 不可回滚部分：无。

## 未决

1. **S4b 的句柄授予形状**：init 的句柄由谁授予、`StartupInfo` 怎么回填（ADR-075 决策 3）。
2. **S4c 的 `MAX_TASKS` 余量**：init 常驻占一格后，ktest 的 spawn 炸弹判据与三本账要重算。
3. **init 该不该收工**：本片让它常驻自旋；S5 的 shell 才是真正常驻交互程序，届时 hello 要不要换成 shell。
4. **本片没有负样本**（见验收），要补。