# ADR-131：A3 用户态装载器——外部 ELF 的装载与启动（14 号记账、容量与挂根）

状态：**已采纳**（2026-11-17，使用者授权："继续，每阶段 commit 一次，直到 D 阶段完成"）。
作者：workbuddy（总设计 V1.0 阶段 A3，`docs/Aurora-OS-完整操作系统架构与Shell命令体系建设总设计-V1.0.md` §9 A3）。
关联：ADR-130（A2：argv 区 / 标准句柄 / 退出码寄存器）、ADR-108/109（FS-03 文件 ABI 与挂载根）、
ADR-044（模块依赖棘轮）、ADR-047（持锁不许 drop 取锁的项）、ADR-074/098（共享映射与 VA 记账）、
总设计 §6.3（不按命令设计 syscall）。

## 背景

A2 让**内核**能按 A2 语义启动一个外部 ELF（argv 区 + std 句柄 + 退出码）。
A3 的验收句要的是**用户态自己装载**：命令解释器读到卷上的 ELF，把它装进一个新进程并启动，
拿回退出码——内核只提供机制（22/12/13/14/11/15/16/17），不参与"命令怎么找、怎么装"。

本轮把这条链在一次真实启动上跑通了。判据面（串口原文，`build/run-632.log`）：

```
run:HELLO.ELF open=0x1000a read=0x4388 entry=0x100000000 spawn=0x0 wait=exit:0x0
```

四格分别是：22 号打开卷上 `/HELLO.ELF`、顺序读满 17288 字节（`0x4388`）、段表解析出入口
`0x100000000`、16 号放行且 17 号拿到**真实退出码 0**。`verdict: PASS`。

**不新增任何 syscall 号**。本轮的全部内核侧改动都是既有机制的语义收紧/容量修正，
下面五条决策逐条给出"为什么必须改、改的边界在哪、谁能证伪"。

## 决策 1：14 号的固定镜像区按 AS 记账，不再进全局 VA 表

`sys_aspace_map` 的显式 VA 分支此前无条件调 `mm::reserve_va_at`，而全局 VA 表是**跨 AS** 的。
固定镜像区 `[USER_VA_BASE, USER_MMAP_BASE)` 的地址是 ET_EXEC 的 `p_vaddr`——每个进程镜像都从
`0x1_0000_0000` 起。于是：

- 父（命令解释器）自己坐在 `0x1_0000_0000`（内核装载器登记过）；
- 父经 14 号把子镜像也铺到 `0x1_0000_0000` ⇒ `reserve_va_at` 必失败 ⇒ 14 号回 `-6`。

实测：`map_segs` 第一段就回 -6，而 `map_shared` 一次都没被调到（它的 per-AS 整段查重才是正确的冲突判据）。

**决策**：显式 VA 落在固定镜像区时**不占全局 VA 表**（`va_reserved=false`），
冲突判定交给 `aspace_map_slot` → `map_shared` 的"先整段查冲突再铺"；失败回滚也不再 `release_va`。
动态区（`>= USER_MMAP_BASE`）保持原样占全局账——那里是内核发号，跨 AS 也不该重号。

依据：内核自己的装载器 `user::load_into` **从不进全局 VA 表**，它直接 `aspace_map_slot`。
本决策不是新发明，是把 14 号的记账口径与装载器对齐（此前的不一致恰好被"一个进程一个镜像"掩盖）。

**判据**：`t_va_interval_table`（区间表增删与基线）、`t_abi_pointer_checks`（越界仍杀）两行不变；
A3 行本身在"子镜像与父镜像同址"这个形状上跑——这是最直接的证人。

## 决策 2：`MAX_OWNED` 8 → 16（A3 让一个任务同时持有两份镜像）

`OwnedSet` 的容量是 8，量测基准是"**一份**镜像"（§10.7 的 6/8 与余量 ≥ 2）。
A3 的语义要求父在执行期同时持有：自己的镜像映射（约 5 条）＋ 子进程的全部映射（约 4 条），
因为子线程在 15 号才存在，而 16 号的 `adopt_asmaps` 才能把这批 `AsMap` 搬到子线程名下。
8 必满，`own_current` 满了会**先放 RUNQ 再 drop**（ADR-047 决策 2）——`AsMap::Drop` 要取 VMM，
所以那条路只能明确拒绝，表现为 14 号回 `-6`（实测：映射 hello 第 3 段时 -6）。

**决策**：提到 16，并在注释里写明"两份镜像 + 余量"这个新基准；子进程启动后 `adopt_asmaps`
整批搬走，父的袋子随即回落，所以不需要按子进程数线性增长。
内存代价：每条约 `size_of(OwnedItem)`（主要是 `AspaceMapping` 的 `frames[16]`），16 条约 3 KiB/任务，
per-CPU 静态任务数组可接受。`ktests/elf.rs` 的"余量 ≥ 2"判据仍成立（容量变大只会更宽松）。

## 决策 3：`MAX_VMOS` 8 → 16（父子同时持 VMO）

同一形状的容量问题：用户的装载器要为每段建 VMO，父持子段 VMO 直到 16 号，
子自己也持装载器给的段 VMO；两代 3 段 ELF 就要 6 格，再加 si/栈/临时，8 格必满。
实测：建第 3 个段 VMO 时回 `-6`（内核侧直调 `vmo_create(1/1/3)` 三次全 OK，
说明不是帧不够——诊断值 `free_frames=128473` 前后不变）。

## 决策 4：`fs_open` 的挂根改成**运行期一次切换**（默认口 5 不变）

A3 的目标是卷A（口 3，根目录有 `HELLO.ELF`），而 fs-open 的判据是口 5 的 deep 卷。
第一版用编译期 cfg 分档，代价立刻显形：`a3-exec` 依赖 `fs-open`（22 号的模块门），
同一份构建里 fs-open 的用例也在跑，`PORT` 被改成 3 让 `t_fs_open_ring3` / `t_fs_open_syscalls` 两行红。

**决策**：`PORT` 保持 5（用例口径不变）；新增 `port()` / `set_port()`，
`a3-exec` 的编排在任何用户任务起来之前调一次 `set_port(3)`。约定写进注释：
**只允许在任何 VFS 句柄创建之前切换**（句柄里存的是口号）。

实现细节（受 ADR-044 约束）：本模块属 `storage` 组，引入 `core::sync::atomic` 会新增
`storage -> sync` 的 3 个引用站点，撞"环内引用只许减不许增"的棘轮。
所以用单写者 `static mut` + `addr_of!`/`addr_of_mut!` 的 volatile 读/写（2 处，U2 已登记）：
单字节、单写者、跑在任何用户任务之前，不需要原子语义。

## 决策 5：判定载体 = `user/execprobe` 的 A3 分支 + `a3-exec` 特性

`a3-exec = ["a2-exec", "fs-open"]`：A2 语义启动探针，探针执行 A3（自己 open/装载/启动）。
argv 换成 `/HELLO.ELF`（**绝对路径**：`vfs_ro::lookup` 拒相对路径，实测 `NotAbsolute`），
`args_len=11`。目标卷由 `fat32-probe` 装到口 3；deep 卷（口 5）也一并装配，因为同构建里 fs-open 用例要它。

**第四格为什么是"真实退出码"而不是"超时"**：hello 在没人写 `FLAG_EXIT` 时会自旋不退出，
`wait=timeout` 分不清"跑起来了没退"与"根本没跑"。探针改为**通过段 VMO 往目标数据段首
（hello 的 `.slots`）写 `FLAG_EXIT`**，hello 自检完自己打 3 号退出 ⇒ 17 号拿到 `exit:0x0`。
这一格同时证伪了三条链路：段 VMO 的写入位置正确、子进程真的从入口跑起来了、退出码寄存器经
收尸路径回到 17 号。

## 用户态装载器的形状（`user/runtime`）

- `elf.rs`：最小 ELF64 解析（ET_EXEC、段页对齐/offset 同余/界内/memsz≥filesz/段数上限/有可执行段），
  以及三段式装载 `create_seg_vmos` / `write_chunk`（无 24 号 seek 时的"顺序读块 + 段过滤"）/ `map_segs`。
- `vmo_create` / `vmo_write` / `vmo_map`（12/13/14）三个 safe 封装。
- **全整数结构体**（`Seg` 的 `w/x` 是 `0/1` 而不是 `bool`）：`bool` 数组的零值会被 LLVM 降成
  `.rodata` 常量模板 + memcpy，而用户程序链接基址在 +4 GiB，模板取址的 `R_X86_64_32S` 装不下
  ——本轮实测撞了四次（`to_le_bytes` 临时、bool 结构、切片越界的 panic location 表、字面量）。
  统一改法：字面量并进静态 blob、切片用 `get()`、`div_ceil` 换 `checked_*`、结构体全整数。

## 落地清单（本轮实际改动）

- `kernel/src/user.rs`：决策 1（`va_reserved` 四处分支）；22 号句柄口号走 `fs_open::port()`。
- `kernel/src/sched.rs`：决策 2（`MAX_OWNED=16`，`OwnedSet::new` 改命名常量 repeat）。
- `kernel/src/vmo.rs`：决策 3（`MAX_VMOS=16`）。
- `kernel/src/filesystem/fs_open.rs`：决策 4（`port()`/`set_port()`，`disk()` 双静态）。
- `kernel/src/main.rs`：`a3-exec` 档认领 AHCI、切挂根、argv 换绝对路径、期望退出码按档。
- `kernel/Cargo.toml`：`a3-exec` 特性。
- `user/runtime`：`elf` 模块 + VMO 三封装 + `RIGHT_*` 常量。
- `user/execprobe`：A3 分支（装载 + 11/15/16/17）、`.bss` 块缓冲、`FLAG_EXIT` 写入。
- `user/execprobe/link.ld`：段地址改 `ALIGN(4K)` 自动推进（写死地址在 `.text` 超过 4 KiB 后与 `.rodata` 重叠）、
  **补 `.bss` 段**（orphan `.bss` 不进 PT_LOAD ⇒ 用户缓冲被内核判 `E_FAULT`）。
- `tools/aurora.py`：A3 判定行（第 64 行）、`a3-exec` 档装配 deep + 卷A。
- 登记：unsafe 白名单/census（463）、module-interfaces（`fs_open::port`/`set_port`）。

## 补记（同日）：shell 的 `run` 命令与编排层下沉

装载链路的下沉版本落在 `user/runtime/src/exec.rs`（`load` / `launch` / `wait_exit` / `run`，
静态 4 KiB 读块 + SI 页构造都收在库里），shell 侧只剩：
`run <path>` → 补绝对路径 → 按 `ROLE_JOB` 取 Job 句柄 → `rt::exec::run(path, console, job, 5000)`
→ 打 `run: <path> exit=<码>` / `(timeout)` / ` error=<码>`。

**交互路径的端到端验证被一件量具通道的事卡住，如实记录**：
为验证"人手打一条命令"，我加了 `a3-shell` 档（宿主经串口 RX socket 等提示符 → 注入
`run /HELLO.ELF` → 见结果行后注入 `exit`）。实测该档能跑通命令本身（串口出现
`run: /HELLO.ELF`，随后是卷A 的逐扇区读），但**同一份构建里 `t_fs_open_ring3` 转红**
（1/1 复现；`fs-open` 单特性、`a3-exec,fat32-probe` 都绿）。对照实验排除了内核侧代码：
把 a3-shell 的内核块整段停用后仍然红；而该档与 `fs-open` 单特性的差别只剩"串口走 socket
而不是 file"。结论：**RX 通道让整跑的输出吞吐掉一半（7 s → 16-19 s），把时间窗判据拖红**。
所以该档没有进判定表，代码保留（`run` 本身不改任何既有行的行为）。

**第二轮尝试（同日晚些）与结论**：改走 **QMP `sendkey` 键盘注入**（`ps2-kbd` 让
`sys_console_io` 的读路径回退到键盘环，串口保持 `-serial file:`，不动传输）。结果仍然不行，
而且这次暴露了两个独立的阻断点，都**与装载器无关**：

1. socket 通道的背压确实存在（`nodelay=on` 无效）：整跑 7 s → 16-19 s，`t_fs_open_ring3` 红。
2. 换成 QMP 键盘后**时序恢复**（8.0 s），但 `t_fs_open_ring3` 仍然红；把 a3-shell 的两处内核块
   全部停用（只剩特性名）也照样红 —— 说明红点来自**这条验证路径本身的组合**，不是本片的代码。
   单独测 `fs-open,ps2-kbd,fat32-probe` 时 ring3 **转绿**但整跑 HANG，两个症状互相矛盾，
   需要单独一轮把它当作**量具问题**来查（候选：QMP 端口/QEMU 主循环、`ps2-kbd` 与 `irq-ahci`
   用例对 IRQ1 的占用、`-display none` 下 i8042 的行为）。

**处置**：验证档整段撤掉（特性、内核编排、注入通道、卷装配一并移除），工作树回到
`check 17/17` + a3-exec/默认 run 双绿。shell 的 `run` 命令本身保留（它不改任何既有行的行为，
只是暂时没有端到端判据）。下一片要动的是量具，不是内核。

## 未做 / 留给下一片

1. **shell 的 `run` 命令**还没有接线到这条装载器（今天由探针驱动；shell 集成要 argv 解析 +
   命令查找 + `PATH` 语义，属 A3 的下一片）。
2. **子进程映射的释放时机**：现在归父任务持有，16 号 `adopt_asmaps` 搬给子线程。
   若父先退而子长期存活，映射会随父的 `release_owned` 消失——A3 的 shell 集成必须处理
   "父短命、子长命"这条边（今天的探针等子退出后才收尾，所以没暴露）。
3. **envp / `PATH` 搜索**：内核不做，留给用户态（ADR-130 已裁）。
4. `code-model=large` 被实测否决：手工 PT_LOAD 链接脚本与它不兼容（大模型段成 orphan、不进段表），
   症状是内核装载器报"入口所在段不可执行"。要用它得先重写链接脚本，不在本片范围。
