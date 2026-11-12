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

## 补记（2026-11-12）：S4b-1 与 S4b-2 已落地

### S4b-1：`user::load_into(aslot, bytes)`（实测）

此前 `load()` 只往**当前 AS** 映射，子 AS 只映过 `jmp .` 桩 ⇒ "真 ELF 进子 AS"是缺口（BACKLOG §231）。
新入口与 `load()` 三点不同：**不做全局 VA 保留**（ADR-070 A4：同一 VA 在两个 AS 里互不影响，
冲突在那棵树里判）、**逐段走 `mm::aspace_map_slot`**（返回 `AspaceMapping`，`OwnedSet::push_asmap` 收）、
**栈 VA 从 `USER_MMAP_BASE` 起**（镜像按设计在它下面）。
用例 `t_load_into_child_as`：生效位对=true、销毁=true、**帧账与 AS 数都回原值**（run-923，ktests 82/82）。

### S4b-2：产品路径**句柄驱动**的启动（实测）

`stage_init_user()` 按 `handles` 特性二选一：
- **无 `handles`**：保持 S4a 的 `spawn_user` 路径（默认档不变）。
- **有 `handles`**：`job_create → grant_job`（两个：一个**无 CREATE**、一个有）→
  `process_create` → `load_into` → `vmo_create` 写 `StartupInfo`（魔数+ABI+一条 `ROLE_JOB` 转移）→
  `grant_vmo` → 14 号铺 si 页进子 AS → 15 号 `thread_create`（**停住**）→ 16 号 `process_start` 放行。

**判据①（权限只从句柄来）实测命中**：`无CREATE拒=true`（无 CREATE 的 Job 句柄造进程返回 `E_DENIED`）。
**实测读数**（run-925，`handles` 档，elf `870a8db7e866`）：
`Proc句柄=327682 子AS=0 段=3 页=5 线程停住=true start_ret=0 跑过次数=1 等待收工=true si_va=0x250000000`；
ktests **89/89**、verdict **PASS(33)**。默认档 run-924 仍 **82/82 PASS(33)**、S4a 信箱读数不变。

**为什么用 `syscall_dispatch` 而不是直接调内核函数**：15/16 号的权限校验、句柄转移、
`StartupInfo` 回填都长在 syscall 层；产品路径走同一条 ABI 才是"权限只从句柄来"的真实证明，
绕过去就等于自己给自己发权限。

### 本补记的欠账

- **信箱判据在子 AS 里读不到**：`user::read_at` 走当前 AS 的 `peek_u64`，
  所以 S4b-2 改用 `runs_of(gidx) > 0` 作"真跑过"的判据。**AS 感知的 peek 尚未做**。
- S4b-2 **没有独立负样本**（`E_DENIED` 那条是内建判据，但"把 CREATE 去掉就拒"的变异未做）。
- `handles` **仍是可选特性**，默认档不走句柄路径；把它变成默认是 W5 的后续决定。

## 补记（2026-11-12）：S5 控制台接口裁决与 S5a 边界

使用者选择**控制台句柄**而非裸控制台 syscall，授权新号 **20＝console_write、21＝console_read**。
两者均以 Console 句柄为入口，分别检查 WRITE/READ；启动时通过句柄转移授予，不能凭 syscall 号获得权限。
这是后续 S5b 的接口方向，**本片尚未实现这些号、Console 对象或启动角色，也未交付 shell**。

S5a 先完成核内串口接收：BSP 上认领 IRQ4，经 MADT 查 GSI/RTE，仅支持当前已映射 IOAPIC 的
独占高有效边沿线；拒绝未知极性/触发配置、活跃 RTE、越界向量，目的地取硬件读回的 BSP ID。
串口仍是核心内核端口 I/O，不把它伪装成 PCI DriverCtx 设备；既有 PIT/MSI/EOI 语义不变。
ISR 不分配、不打印、不取锁，每次最多搬 8 字节；进入时关闭 UART RX 中断，退出时重新使能，
让尚未排空的输入还能产生后续中断。256 格环留一格，**有效容量 255**；满时丢弃新字节并单独计数。
消费者目前限定为一个任务，**多读者同步、阻塞读/唤醒、硬件 UART 错误统计及真机验证未做**。

新增 `serial-rx-probe` 验证档，宿主机在三条 ready 标记之后分别发送 16/300/32 字节：
关闭 IER 时硬件确有输入但软件计数不动，恢复后收到 16 字节；暂停消费时保留前 255、丢弃 45；
读空后再收 32 字节证明回绕与恢复。核内检查内容，宿主独立对账长度、哈希、丢弃数与中断非空转。
仅该档把 COM1 接为回环 TCP（127.0.0.1、宿主随机端口），默认文件日志接线不变；探针与 QMP 组合明确拒绝。
stdio 方案在本机两跑都少收，首批均只收到前 14/16 字节；同一 ELF 改 TCP 后三批全部正确。
这只定位到宿主后端路径，不声称已查明 QEMU 内部丢失机制。Windows 的 debug-exit 可令 TCP 以 RST 结束，
按流结束处理，但缺失/残缺记录、发送失败和非 PASS 退出仍拒绝，不以连接正常关闭代替内容验收。

接口登记同步实际新增依赖：串口认领 IRQ、查询 APIC 上下文及接收 MADT 参数；`apic::ioapic_route`
与 `mm::MOD_BOOT` 纳入实际跨模块接口，环内引用站点据静态扫描登记，不重划模块或放松检查器。
实测见 BACKLOG §235：run-934 RX 83/83、run-935 handles+RX 90/90、run-937 默认 82/82，均 PASS(33)；
关闭 ISR 重启中断与翻转入环字节两条代码变异均 FAIL(35)，还原后绿；宿主对账器 18 条坏记录均证红，check 17/17。
产品路径尚未启用 RX，默认启动与日志接线不变；完整矩阵、bench、长稳及真机未验证。

## 补记（2026-11-12）：S5c-2 —— shell 成为 handles 档的 init，三个真 bug 与三条判据

### 1. `handles` 档的 init 换成 `user/shell`（实测）

决策 3 的"判据是信箱不是串口"**只适用于默认档**。默认档没有控制台句柄可授，shell 进去只会
`exit(1)`，所以它仍装 hello、仍读信箱。`handles` 档按 `ROLE_LOG(5)` 授予 Console 句柄之后，
判据换成**宿主机侧的一问一答**：喂 `help/echo/ping/abi/exit`，逐条读应答，6/6 命中（BACKLOG §236）。
这不是"拿串口字符串当判据"的回潮——差别在于**命令是宿主机真喂进去的**，不是程序自己打印的。

### 2. `aspace_map_slot` 收帧号，不是物理地址（契约，实测踩过）

`load_into` 第一版把 PA 直接传进去。它自己乘 PAGE（mm.rs 的 `f * PAGE`），所以叶子指向 PA×4096；
更糟的是 `frame_get(PA)` → `fi_inc_refcnt` 做的是**无边界检查**的 `arr.add(f)` ⇒ 越界原子写 FrameInfo。
**决策**：凡是往 `aspace_map_slot` / `frame_get` / `frame_put` 传的地址，一律 `pa / PAGE`。
这不是新规则，是把既有契约在"子 AS 装载"这条新路径上兑现；证红见 run-949（代码叶子 `0x85000005`）。

### 3. 装载器交回的 `OwnedSet` 必须归创建者（决策）

`load_into` 把映射柄**交回调用方**而不自动入袋（用例要能自己丢弃并核账）。产品路径因此必须在
16 号之前 `into_current()`，否则 `adopt_asmaps` 搬不到东西，映射会随创建者栈帧解映射。
**判据是 `子袋=5`，不是横幅**：去掉归属之后横幅照样出（等待发生在函数内部，解映射在返回时），
所以这一格只能由袋计数作证（run-950 证红）。"init 在函数返回后仍存活"**未验证**——内核紧接着就退出。

### 4. 用户缓冲校验必须走**当前 CR3 那棵树**（决策，新增 `mm::current_effective_flags`）

`effective_flags` 走 `pml4_phys`（启动树，只在 `take_over` 写一次），而 `aspace_switch` 只动 CR3。
子进程跑在自己的 AS 里 ⇒ 校验的树与拷贝用的树不是同一张，`console_write` 恒 `E_FAULT`。
新函数读 CR3 后走 `effective_flags_in`，**不取锁**（所有写者都在 VMM(20) 里），
因此能在 `with_vmm_lock` 内部调用——这是它不能复用 `aspace_effective_flags`（要取锁）的原因。
ADR-070 A4"同一 VA 在两棵树里各自映射"由此在用户缓冲这条路上兑现。证红见 run-948。

### 5. `等待收工` 不能单独当"干净退出"的证人（判据更正）

`wait_for_task` 对"被杀"与"自己 exit"返回同一个 true。S4b-2 记的"自己收工了"其实是入口 #PF 被杀
（BACKLOG §233 已就地更正）。**今后这个布尔必须配串口上的 kill 行一起读。**

### 6. 本片不做

- 不改 syscall 号（20/21 已由 S5b 裁决授权）、不改锁序、不改判定表。
- 不延长默认档的等待窗口：交互取证走已有的 `console-probe` 档（1000 窗口，约 16 s）。
- 不动 `run_serial_rx`（另一路在飞）；交互判据暂时只活在一次性夹具里，durable 矩阵行仍欠。
- 阻塞读/唤醒不做：shell 目前是忙等（没有 yield syscall 可用）。

## 未决

1. **S4b 的句柄授予形状**：init 的句柄由谁授予、`StartupInfo` 怎么回填（ADR-075 决策 3）。
2. **S4c 的 `MAX_TASKS` 余量**：init 常驻占一格后，ktest 的 spawn 炸弹判据与三本账要重算。
3. ~~**init 该不该收工**：本片让它常驻自旋；S5 的 shell 才是真正常驻交互程序，届时 hello 要不要换成 shell。~~
   **已决（S5c-2）**：`handles` 档换成 shell，收到 `exit` 才收工；默认档仍是 hello（没有控制台句柄可授）。
   仍开：**常驻 init 在 `stage_init_user` 返回之后的存活未验证**——内核紧接着就 `debug-exit`，
   要让它真常驻，得先决定"判定之后退不退出"，那是下一片的事。
4. **本片没有负样本**（见验收），要补。