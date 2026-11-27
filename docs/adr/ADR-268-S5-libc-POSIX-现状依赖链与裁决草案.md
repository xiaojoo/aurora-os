# ADR-268: S5 libc/POSIX MVP 现状、依赖链与待裁决 R30–R41

状态：**已起草**（草案，不实施）。2026-11-27。关联：S5 手册 S5.1–S5.5、ADR-176（号在功能不在回 NOSYS）、ADR-186/187/188（fd 表与 stdio）、
ADR-130/131（argv 区 + 外部 ELF）、ADR-177（64–66 mmap 族）、ADR-263（**不新增 futex**）、ADR-264（`>` 走 unlink+create+append）、
ADR-259（常驻 broker）、AGENTS.md「待裁决项不得进入实施」。
**本文件只产出裁决材料，不含任何实现代码。所有"读源码得到"的事实均给出符号名，未编译未运行。**

## 0. 先读结论（三句话）
1. **S5 手册的出口判据 `busybox 核心 applet 通过` 在今天不可达，且不是因为 S5 做得不够，而是手册写 S5 时假设了三样已被后续裁决否掉或根本不存在的东西**：
   futex 两号（ADR-263 已裁决不新增）、内核 pipe 对象（不存在）、`dup2` 语义（fd 表只能装到"最小空闲号"）。
2. **S5 不能一个会话做完**。按依赖拆成 **S5a → S5e 五片**，每片独立可验、可回退；其中只有 S5a/S5b 不需要你裁决新 syscall。
3. **"服务崩溃自动重启 1000 次"是 S5 里最接近可交付的**，不依赖 musl；**但缺回收能力（更正见 ADR-269 §0，R42）**，不是"只缺一个监督者"。

## 1. 手册 S5 与仓库现实的逐条对账
| 手册步骤 | 手册假设 | 仓库现实（符号/位置） | 判定 |
|---|---|---|---|
| 1 syscall 适配层 | 映射 1–77 号 | 实际有 **~70 个号、不连续**（2 号历史空缺、5–7 是探针号、62–63 保留、78/79 作废、81/82 是防火墙）。手册案例 14 里 `SYS_FD_READ_OR_FILE_READ` 这个名字**不存在**；`exit`→3、`mmap`→64 对 | 可做，**表要按 `user.rs` 重生成**，不能抄手册 |
| 1 续 | 入口用 `syscall` 指令 | 用户态入口是 **`int 0x80`**（`user/shell/main.rs` 头注释；`runtime::syscall_abi`）。SYSCALL 快路径只在内核侧"M4-4 已交付"，用户 ELF 全仓都走 int 0x80；`syscall` 指令会破坏 `rcx/r11`，调用约定与现有 ELF 不同 | **手册案例 14 的汇编与现状不符**；musl 的 `__syscall` 要写成 `int 0x80` 版（R30） |
| 2 musl 移植 | "线程原语基于 futex 两号" | **无 futex**（ADR-263）。`brk` 无；有 `mmap/munmap/mprotect`(64–66)，`mmap` 的 VA 由内核发、**不收长度**（munmap 整段） | 单线程 musl 可行；**多线程 pthread 不可行**，需 R31 |
| 3 posix_spawn | `process_create+thread_create+process_start` | 11/15/16 真存在；**StartupInfo 里 fd 的角色号是固定枚举**（`ROLE_STDIN=9/STDOUT=10/STDERR=11`…），不能任意指定 `child_fd=7` | **`adddup2(child_fd=N)` 对 N∉{0,1,2} 无处安放**，需 R32 |
| 4 pipe/dup2 | 用户态 VMO 环 + futex，或内核 pipe（需 R5） | **没有 Pipe 对象**：`fd_io` 只分派 `ObjRef::{Console, VfsFile}`，Socket 回 `-95`；**没有 `dup2`**：`SYS_FD_INSTALL` 回"最小空闲 fd"；`SYS_HANDLE_DUP`(9) 是"收窄权限的复制"，不是 `dup2` | **整步依赖 R5/R32**。shell 的 `a | b` 今天是**单进程内存缓冲**（`main.rs::sink_*`），不是真管道 |
| 5 fork | 可选 | 无 COW 进程克隆原语（有页级 demand-zero/COW，但无进程级） | **建议不做**（手册自己也说"默认不推荐"） |
| 6 init | 读服务单元、依赖图、退避重启 | **没有用户态 init**。`init` 是内核 `stage_init_user` 起的单个 ring3 任务（现为 hello/shell），`park_until_init_exits` 在内核里轮询它。无服务概念、无重启 | 全新；**可纯用户态做**（S5c） |
| 7 login | argon2id | 凭据是内核表（`cred_create(uid,gid,caps,name)`），**没有口令、没有用户数据库、没有 `setuid` 类 syscall**；会话凭据由内核 `set_cred` 在启动时设 | 需要"切换凭据"的新能力 ⇒ R35 |

## 2. 依赖链（决定 S5 怎么拆）
```
S5a  用户态 libc 骨架 + hello(C)             ← 依赖：R30（int 0x80 约定）、R33（C 工具链）
S5b  posix_spawn（仅 0/1/2 + 显式传句柄）    ← 依赖：S5a；不需要新 syscall
S5c  用户态 init/服务监督（崩溃重启+退避）   ← 依赖：S5b；不需要 musl，可用现有 Rust 用户 crate
S5d  pipe + dup2                              ← 依赖：R5/R32（新 syscall）或 R36（纯用户态 VMO 环）
S5e  busybox applet / login                   ← 依赖：S5a–S5d 全部 + R31 + R35
```
**关键判断**：S5c 与 S5a 互相独立（监督者用现有 Rust `aurora-user-runtime` 即可，不需要 libc）。
**建议先做 S5c**：它直接兑现手册 S5.1 的"服务崩溃自动重启 1000 次"这一条出口。
> **更正（ADR-269，同日）**：此处原写"零新 syscall"**是错的**——用户态没有任何办法回收已终止进程（`proc_reap` 仅内核调用；`handle_close(Proc)` 不触发），僵尸永久占 Job 额度与地址空间，1000 次出口需新增回收 syscall（R42）。见 ADR-269 §0。

## 3. 各片的方案与证据
### 3.1 S5a：musl 目标移植（最大不确定项）
* 现状：仓库 **没有任何 C 代码**（AGENTS.md 硬约束 2「不为了引入 C 而引入 C」）。引入 musl = 引入 C 工具链与第二套构建（`clang`/`lld` 交叉、musl 源码 vendoring）。
  **这直接触及 AGENTS 硬约束 2**，且 `rust-toolchain.toml` 固定 1.99.1 的理由（"工具链漂移使每个用户 ELF 字节变化"）对 C 同样成立 ⇒ 必须同样固定 clang 版本并纳入"同源码两次构建同产物"(`do_release`)。
* 可选路线（R33）：
  | 路线 | 做法 | 优 | 劣 |
  |---|---|---|---|
  | A | 引入 musl（C）+ clang 交叉 | 手册原案；busybox 现成可编 | 违反硬约束 2 需先裁决；构建/SBOM/可复现性成本大 |
  | B | **Rust 写最小 libc 子集**（`aurora-libc`，`#![no_std]`，导出 C ABI 符号） | 不引 C；沿用现有工具链与门禁；unsafe 登记现成流程 | 覆盖面窄，busybox **不能直接用**；需自己补 printf/字符串/stdio |
  | C | 先不要 libc，S5 只做 Rust 侧 `posix_spawn`/init/管道，把 libc 推迟 | 最快兑现 G2 的"服务重启"部分 | G2 里"busybox/C hello"不满足 |
* 我的建议：**C 路线先推迟，先做 S5c + S5b + S5d**；R33 在 S5b 完成后再议。
### 3.2 S5b：posix_spawn
* 可映射部分：`process_create(11)` → `aspace_map/vmo_write` 装载（`runtime::exec` 已有用户态装载器，`execprobe`/shell `run` 已用）→ `thread_create(15)` → `process_start(16)`（SI 页带 argv + 句柄描述表）。**这条链今天就在产品路径上跑**（`a3-exec`/`a3-shell`），不需要新东西。
* 不可映射部分：`posix_spawn_file_actions_adddup2(fa, srcfd, N)` 的 `N` 任意值。`process_start` 只按**角色**转移句柄，子进程用 `find_console(si_va)` / `handle_of_role` 找。
  方案对比（R32）：
  | 方案 | 做法 | 新 syscall | 说明 |
  |---|---|---|---|
  | 1 | 子进程启动期由 libc 读 SI 页描述表，**按角色自己 `fd_install` 到想要的号** | 否 | `fd_install` 只给最小空闲号 ⇒ 顺序装即可得到 0,1,2,3…；任意号要先用占位填洞再 `fd_close`。**纯用户态可做，丑但够用** |
  | 2 | 新增 `fd_install_at(fd, h)`（即 dup2 原语） | **是**（83） | 干净；要裁决号与 fd 表重入语义 |
  | 3 | 只支持 0/1/2，其余 `-ENOSYS` | 否 | 够 busybox 绝大多数 applet；`2>&1` 之外的重定向不可用 |
* 我的建议：**方案 3 起步**（与现状一致、零风险），方案 1 作为补充；方案 2 等 S5d 一起决定。
### 3.3 S5c：用户态 init / 服务监督（建议第一个做）
* 已有可用件：`process_wait(17)`/`object_wait(19)` 返回 `(WAIT_TERMINATED<<32)|exit_code`；`process_kill(18)` 与 `proc_kill_by_pid(29)`；`proc_enum(27)`/`proc_stat(28)`；`sleep_ms`(19 的特例，**必须传 `ROLE_SELF_PROC`**，ADR-263 已记)；`aurora-user-runtime::exec` 的装载器。
* 缺口（诚实）：
  1. **无"子进程退出事件"推送**：监督者只能轮询 `process_wait(h, 0)` 或对多个子进程逐个 `object_wait` 带超时。**一个监督者同时盯 N 个服务只能轮询**（`object_wait` 一次只等一个对象）。1000 次重启测试可接受，但服务多时是 O(N) 轮询——**这是设计取舍不是缺陷**，需写进文档。
  2. **监督者自己崩溃谁来重启？** 今天内核 `park_until_init_exits` 只盯**一个** init 任务；init 退出 ⇒ 内核 `debug-exit` 收工。**监督者就是 init**，它崩 = 系统停。手册没谈这点（R37）。
  3. **服务单元文件格式**：手册案例 16 用 TOML。`no_std` 用户程序里**没有 TOML 解析器**，也不能引外部依赖（SBOM/许可证 R7 未决）。建议用**定长二进制或 `key=value` 行文本**（沿用 `parser.rs` 风格），不引 TOML。
  4. **能力声明**（`caps = ["net:tcp:listen:8080"]`）：内核凭据只有 6 个位（READ/WRITE/KILL/LOG/DEV/ADMIN，`security/cred.rs`），**没有按端口/路径的细粒度能力**。手册的"逐项授予"今天**无法表达** ⇒ 只能映射到现有 6 位 + 句柄集合（R38）。
  5. **预算**（`mem_mib`/`cpu_pct`）：无 cgroup 类机制；内核有 `resident`/`ledger` 的**模块级**台账，没有**进程级**配额接口 ⇒ `[budget]` 段**今天不能执行**，只能解析并记录"未强制"（R39）。
* 可测判据（均不需要新内核代码）：
  - 随机杀 1000 次：监督者 `process_kill(29)` 之外由**测试进程**随机杀服务，监督者必须在退避窗口内重启；判据 = 终态服务存活 + 重启计数 ≥ 杀次数 + 无句柄/内存泄漏（读 `proc_stat`/`sysinfo`）。
  - 熔断：`max_per_minute` 超限 ⇒ 状态 `Failed` 不再重启（手册案例 16）。**负样本**：把熔断比较改恒假 ⇒ 重启风暴格必红。
  - 退避表：`next_delay` 是纯函数，**可放进宿主 crate 做 `cargo test`**（沿用 host-* 惯例）。
### 3.4 S5d：pipe 与 dup2（R5 的实质内容）
| 方案 | 做法 | 优 | 劣 |
|---|---|---|---|
| P1 | **内核 Pipe 对象**：新 `ObjRef::Pipe`、新 syscall（`pipe_create`）、`fd_io` 加分派、阻塞读写靠 WaitQueue | 语义最接近 POSIX，阻塞/EOF/SIGPIPE 都能做对 | 新 syscall + 新对象 + **新锁**（要改 `lock-order.md`）+ 句柄表容量；触碰 AGENTS「新增 syscall/锁序须裁决」 |
| P2 | **用户态 VMO 环缓冲**（两进程映射同一 VMO，原子读写指针；等待用 ADR-263 的自旋+睡眠退避） | 零内核改动、零新 syscall | **无唤醒**：读端空时只能 ≥1 ms 退避轮询，吞吐/延迟差；**无 EOF/断开检测**（写端崩了读端不知道，除非另走 `process_wait`）；VMO 要能被两个进程各自 `aspace_map`——**需确认 VMO 句柄能经 16 号转移给子进程并可映射**（`SYS_ASPACE_MAP` 的 `h` 要 `RIGHT_MAP`，`a2-exec` 已有 VMO 页传递先例，未验证"两进程共享可写 VMO"） |
| P3 | 维持现状：shell 管道 = 单进程内存缓冲 | 已工作（`ls | grep`） | **不是进程间管道**；外部命令之间不能 `|` |
* 我的建议：**P1 是正路，但必须单独成 ADR 并等你批准新 syscall**；P2 只适合作为"在 R5 未批准前的演示"。P3 是现状。
### 3.5 S5e：busybox / login
* busybox 的硬依赖：libc（printf/stdio/字符串/`getenv`/`opendir`…）、`fork` 或 `vfork`（大量 applet 用 `fork`；`NOMMU` 配置下用 `vfork`+`exec`——**这恰好与 Aurora 的"只有 spawn"模型契合，是个好消息**）、`pipe/dup2`、`waitpid`、信号。
  ⇒ S5e 在 S5a–S5d 全部完成前**无从开始**。我**不建议把它放进近期计划**。
* login/argon2id：argon2id 需要 **内存硬**（RFC 9106 推荐 ≥64 MiB 级参数；轻量档也要几 MiB）。用户态 `no_std` 无堆（`LARGE_MAX=2048` 是**内核**堆上限；用户态有 `mmap`）⇒ 可行但要先有用户态分配器。
  口令存储需要**可写且受保护的文件**；现在 FAT32 无权限位。会话凭据切换需要内核新能力（`set_cred` 目前仅内核内部可用，**没有 syscall**）⇒ R35。**不建议近期做**。

## 4. 待裁决项（编号接 ADR-267 的 R29）
| 编号 | 问题 | 选项 | 我的建议 | 不裁决的后果 |
|---|---|---|---|---|
| **R30** | 用户态 syscall 入口：musl/libc 用 `int 0x80`（与现有一致）还是切到 `syscall` 指令 | A int 0x80 / B 切 syscall | **A**（改 B 要重做全部用户 ELF 的入口并重验 `rcx/r11` 约定） | S5a 无法定 ABI |
| **R31** | 多线程 libc（pthread）是否在 v1.0 范围 | 否（单线程）/ 是（需内核 futex，推翻 ADR-263） | **否** | 若选"是"，必须重开 ADR-263 |
| **R32** | `posix_spawn` 的任意目标 fd | 方案 1/2/3（见 3.2） | **3 起步**，1 补充 | 无法做 `dup2`；busybox 的 `2>&1` 外重定向不可用 |
| **R33** | libc 路线 | A musl(C) / B Rust 最小 libc / C 推迟 | **C 先行，随后 B**；A 触及 AGENTS 硬约束 2 | S5a 不能开工 |
| **R34** | 是否新增 `83=fd_install_at`（dup2 原语）与 `pipe_create` | 批准 / 暂缓 | **暂缓，S5d 前再议** | S5d 只能走 P2/P3 |
| **R35** | 是否新增"切换会话凭据"能力（login 需要） | 批准 / 暂缓 | **暂缓** | login 无法实现真正的权限降级 |
| **R36** | 在 R5/R34 未批准时，是否接受 P2（用户态 VMO 环）作为过渡 | 接受 / 不接受 | **仅作演示，不进产品路径** | — |
| **R37** | 监督者即 init：它崩溃时的处置 | A 内核重启它（扩 `park_until_init_exits`，动 resident-init 编排）/ B 视为系统故障（现状）/ C 双监督者互监 | **B 起步**，写入文档为已知限制 | 与"服务可用性"出口自相矛盾，需明说 |
| **R38** | 服务能力声明如何映射 | 现有 6 个 cred 位 + 显式句柄集 / 新增细粒度能力 | **前者**；手册 `net:tcp:listen:8080` 这类**标为"不可强制"** | 文档会夸大安全性 |
| **R39** | `[budget]`（mem/cpu）今天无法强制 | 解析并记录"未强制" / 等进程级配额 ADR | **前者** | 同上 |
| **R40** | 服务单元文件格式 | `key=value` 行文本 / 定长二进制 / TOML（需引依赖） | **行文本**（不引依赖，R7 未决） | 引依赖要先过 SBOM/许可证 |
| **R41** | S5 范围 | 全部 S5a–e / **S5c+S5b 先行** / 只做文档 | **S5c+S5b 先行** | 否则会写出一堆无法编译验证的 C/libc 代码 |
沿用待裁决：R1–R4、R7、R8–R12、R13–R29。其中 **R4（验签拒启）** 与 S5 的"验签拒启所需身份/槽位/生产钥匙"强相关，**未裁决前 S5 不得声称"安全启动"**（AGENTS 硬约束 7）。

## 5. 推荐的第一片（S5c）的验收设计（供你批准后实施）
| 判据 | 对象 | 证人/负样本 |
|---|---|---|
| `next_delay` 退避表（纯函数） | host crate `cargo test` | 变异：表索引越界不 `last()` ⇒ 红 |
| 熔断：窗口内次数 > `max_per_minute` ⇒ `Failed` | host crate | 变异：比较改 `<` ⇒ 红 |
| 崩溃检测：杀服务后 ≤(退避+轮询间隔) 内被重启 | QEMU ktest（`resident-init` 档） | 防空转证人：**重启计数必须 >0**；负样本：监督者不调 `process_wait` ⇒ 红 |
| 随机杀 N 次（先 100，再 1000）后服务存活且无泄漏 | QEMU | 读 `proc_stat` 前后句柄数/页数；拆不开的差值**写"不归因"** |
| 服务不继承 ambient 权限：未授予的句柄在子进程里**不存在** | QEMU | 负样本：多授一个句柄 ⇒ 子进程 `fd_list` 里出现它 ⇒ 判据红 |
**不做**：能力细粒度强制、预算强制、依赖图以外的服务发现、热重载。每一项写入"已知限制"，不得写成已实现。

## 6. 风险与不确定项（如实）
* **已核实**：`sched/proc.rs::proc_reap` 清槽、还 Job 额度（`used_procs`）、锁外 `aspace_destroy`，并保留 `gen` 防 ABA；`MAX_PROCESSES = 32768`、`MAX_JOBS = 1024`（`capacity-baseline.toml`），所以 1000 次重启**在容量上不是瓶颈**。
  **未核实**：`runtime::exec` 装载器全文，以及 `thread_create` 失败路径是否仍有名额/页泄漏（BACKLOG §581 修过一次 thread_create 双扣，说明这一带出过 bug）。真正的风险是**泄漏**而不是容量——**S5c 开工第一步应先做 1000 次 spawn→exit→reap 的泄漏取证**（读 `proc_stat`/`sysinfo` 前后页数与句柄数；拆不开的差值写"不归因"），再谈监督逻辑。
* `object_wait` 一次只等一个对象 ⇒ 多服务监督是轮询；服务数 >几十时轮询间隔与 CPU 占用需要实测，我没有数。
* 本草案对 busybox 的 `NOMMU/vfork` 判断来自对 busybox 通用构建选项的了解，**未对照其源码核实**。
* 全部"读源码得到"的断言可被 `rg` 复核；若与你本机 HEAD 不符，以你本机为准。
