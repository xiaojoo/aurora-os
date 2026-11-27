# ADR-269: S5c 用户态服务监督与 S5b posix_spawn 设计、阻塞与更正

状态：**已起草**（草案）。2026-11-27。依据：使用者对 R41 的裁决"S5c + S5b 先行"。
> **R42 已裁决（2026-11-27）：选 A，新增 83=`proc_reap`，已实现（ADR-270，未编译）。** 其余 R43–R46 仍待裁决。
关联：ADR-268（S5 总览）、ADR-073/075（Job/Proc 对象与 StartupInfo）、ADR-098（会话关闭收僵尸）、ADR-130/131（argv 区与外部 ELF）、
ADR-134（按 pid 杀）、ADR-176（号在功能不在回 NOSYS）、ADR-263（不新增 futex）。
**未编译、未运行。下面每条"读源码得到"的事实都给出符号名，可用 `rg` 复核。**

## 0. 先更正 ADR-268（我上一轮写错了）
ADR-268 §0/§2 说 **"S5c 零新 syscall"**。这次读 `sched/proc.rs`、`capability/handle.rs`、`sched/user.rs` 后发现**这不成立**：

> **用户态没有任何办法回收一个已终止的进程。**
> * `proc_reap` 全仓只有内核自己调：`notify_broker.rs`（broker 收尾）、`main.rs` 的会话关闭路径（ADR-098）、各 ktest。`user.rs` 里**零调用**。
> * `handle::close` 对 `ObjRef::Proc` **不触发 reap**（它只处理 VMO 引用与 VFS 节点）；8 号 `handle_close` 关掉 Proc 句柄只释放那一格句柄。
> * `proc.rs` 模块头明写：收工出口"代价是额度要等到 `proc_reap` 才归还——这正是主流的'僵尸仍占额度'口径"。

后果（对 S5c 是致命的，所以放在最前面）：
| 资源 | 一次"启动→退出"后的状态 | 上限 | 能撑多少次 |
|---|---|---|---|
| 进程表槽 | **僵尸永久占用** | `MAX_PROCESSES = 32768` | 约 3 万次（够 1000 次） |
| **Job 进程额度** `used_procs` | 僵尸**不归还** | `max_procs`（Job 创建时定；测试里用 2/4，broker 用 2） | **= `max_procs` 次**，之后 `proc_create` 回 `QuotaProcs` ⇒ 11 号回 `E_EXHAUSTED` |
| 子 AS（含页表、映射页） | `aspace_destroy` 只在 `proc_reap` 里调 | `MAX_ADDR_SPACES = 32768`；Job `max_pages` | 同上，且**页不回来** ⇒ `free_frames` 单调下降 |
| fd 表（ADR-180，每进程 1 页懒分配） | 同上 | — | 同上 |
所以"1000 次随机杀服务后系统可用"**今天会在第 `max_procs` 次或物理页耗尽时失败**，与监督逻辑写得多好无关。
**这是内核能力缺口，不是用户态逻辑问题。** 同样的缺口也让今天 shell 的 `run` 每跑一次外部命令就永久漏一个进程槽 + 一张 AS（交互使用者短期看不出来）。

## 1. 因此 S5c 必须先解决"回收"——三个方案（R42）
| 方案 | 做法 | 新 syscall | 触碰什么 | 评价 |
|---|---|---|---|---|
| **A** | 新增 `proc_reap(proc_handle) -> exit_code`（建议号 **83**）：要 `RIGHT_WRITE`+已终止；成功回退出码并**使该句柄失效** | **是** | AGENTS「新增 syscall 须裁决」；`handle` 需把 Proc 句柄销毁与 `proc_reap` 配成一体（避免句柄悬空/ABA） | **最干净**。语义等同 POSIX `waitpid` 的"收尸"半边；17/19 仍只"等"不"收" |
| **B** | 让 `process_wait`(17) 在**读到结局的同一次调用里 reap**（"等即收"）并使句柄失效 | 否（改 17 号语义） | **改已采纳 ABI 语义**（17/19 被 `execprobe`/`shell run`/ADR-130 多处依赖；一个 Proc 句柄等两次会失败） | 省一个号但**破坏兼容**；`shell run` 超时后"还在跑"提示、`top` 等都读同一句柄，风险高 |
| **C** | `handle_close(Proc)` 在进程**已终止**时顺带 reap | 否（改 8 号语义） | 句柄层首次与进程表耦合：`handle` → `sched`，**可能造 `capability → sched` 新边**（`module-interfaces.toml` 的 SCC/环边基线登记过 `capability/sched/storage` 一个环，加边要重对账；P5c-1 记过同形状问题） | 无新号，但耦合最重；关句柄=收尸也与 Linux 习惯不符（close ≠ waitpid） |
| **D** | 监督者**不回收**，改为**复用同一个进程槽**（不可行：进程一旦终止不能重启，`proc_start` 对已起过线程的进程拒） | — | — | 排除 |
**建议 A**，号取 **83**（81/82 防火墙已占；78/79 作废保持空闲）。工作量：内核实现体约 40 行（先 `resolve`→校验 `Proc`+`RIGHT_WRITE`→`proc_info.terminated`→`proc_reap`→`handle::close(h)`），锁序 `HANDLE(35)` 放掉之后再取 `VMM(20)`（`proc_reap` 内部取 VMM；与 `sys_process_create` 同形），**不新增锁**。
**如不批准 A**：S5c 的"1000 次"出口只能降级为"≤ `max_procs` 次"，并**必须在文档里写成已知限制**（AGENTS 硬约束 7）。

## 2. S5c 本体设计（在回收问题解决之后）
### 2.1 进程模型（沿用，不新造）
* 监督者 = 一个用户态 ring3 程序（`user/init`，新 crate），由内核 `stage_init_user` 起（取代今天 hello/shell 作为 init 的位置，或由 shell 的 `run init` 起——**R37 已建议先当作系统故障处理**：init 崩 = 系统停）。
* 起服务：`runtime::exec::{load, launch}`（已有，产品路径在用）。**`launch` 今天只传一个句柄（控制台副本，`nhandles=1`）并硬编码角色 `ROLE_LOG`**（`exec.rs`）——这对 S5b/S5c 都不够，见 §3。
* 等服务：`process_wait(h, 0)` 轮询（`object_wait` 一次只等一个对象 ⇒ N 个服务 = N 次轮询；见 §2.4）。
* 杀服务：`process_kill(18)`（持 `RIGHT_WRITE` 的 Proc 句柄）。
### 2.2 服务单元文件格式（R40 取 key=value 行文本）
```
# /etc/aurora/svc/httpd.svc   （示意；不是 TOML）
name=httpd
exec=/HTTPD.ELF
restart=on-failure          # never | on-failure | always
backoff_ms=200,1000,5000
max_per_minute=5
```
* 容量沿用 FAT 8.3：路径只到**根目录**（`fs_create/unlink/append` 都只支持根；`name.contains('/')` ⇒ `E_NOT_SUPPORTED`）。**所以单元文件放根目录，如 `/HTTPD.SVC`**，不是手册的 `/etc/aurora/services/`——这是现状限制，要写明。
* `needs`/`after`（依赖）：v1 只做**线性启动顺序**（文件名序），**不做依赖图**。理由：服务数个位数、无服务间通信机制（无 pipe/socket 绑定），依赖图无可依附的"就绪"信号。
* `caps`/`[budget]`：**解析并忽略、日志打 `unenforced`**（R38/R39）。
### 2.3 纯函数部分 → 宿主 crate `host-svc`（可 `cargo test`）
```
pub fn parse_unit(bytes:&[u8], out:&mut Unit)->Result<(),ParseErr>   // key=value，全程 get()，无下标
pub fn next_delay(tries:u32, table:&[u32])->Option<u32>               // 手册案例 16
pub struct Breaker{ recent:[u64; N] , n:usize }                        // 定长环，无堆
pub fn on_exit(&mut Svc, status:ExitStatus, now_ms:u64)->Action        // RestartAfter(ms) | MarkFailed | None
```
* **无堆**：手册案例用 `Vec` 的 `recent.push/retain`——用户态 `no_std` 无分配器（`LARGE_MAX=2048` 是内核堆；用户态有 `mmap` 但没人建分配器）。改为**定长环形缓冲**（`max_per_minute ≤ 16`）。这是对手册案例的**必要更正**。
* 宿主 crate 只含上述纯逻辑；**不含任何 syscall**，所以内核/用户 ELF 字节不受影响（符合 ELF 字节稳定性纪律）。
* 预期 `#[test]` ≥ 25：解析（合法/缺键/重复键/超长/非 UTF-8/无换行结尾）、退避表（空表、越界取末项、单项）、熔断（窗口边界 59999/60000 ms、`max=0`、时间回绕）。
### 2.4 监督循环（用户态，只用已有 syscall）
```
loop {
  for svc in services { match process_wait(svc.proc, 0) {
        Ok(Some(o)) => { reap(svc.proc) /*需 R42-A*/ ; act = on_exit(svc, o, now) ; schedule(act) }
        Ok(None)    => {}                   // 还活着
        Err(_)      => mark_failed }  }
  due = earliest(svc.restart_at)            // 到点就 spawn
  sleep_ms(self_proc, min(due - now, POLL_MS))   // ADR-263：句柄必须是 ROLE_SELF_PROC
}
```
* `POLL_MS` 取 **10 ms**（`sleep_ms` 最小粒度 1 ms；10 ms 在 TCG 下的 CPU 占用**未实测**，写"待测"）。
* **监督者自己不能睡死**：无唤醒，轮询延迟上界 = `POLL_MS`；这是 ADR-263 选 C 的**同一个代价**，不新增。
### 2.5 验收判据（每条配"能让它变红"的负样本）
| # | 判据 | 在哪跑 | 防空转证人 | 负样本（变异证红） |
|---|---|---|---|---|
| 1 | 单元解析/退避/熔断 | host `cargo test -p host-svc` | 测试数 ≥25 | 去掉熔断比较 / 退避索引不 clamp ⇒ 对应测试红 |
| 2 | 杀服务后被重启，**重启计数 ≥ 杀次数** | QEMU `resident-init` 档 | 计数 >0；服务每次起来写一行含**递增序号**（不是同一进程假装重启） | 监督者不调 `process_wait` ⇒ 计数 0 ⇒ 红 |
| 3 | 熔断：窗口内第 `max+1` 次退出后**不再重启**并报 `Failed` | 同上 | 服务被连杀 `max+1` 次，断言第 `max+1` 次后 `proc_enum` 里无新 pid | 熔断比较改恒假 ⇒ 重启风暴 ⇒ 红 |
| 4 | **无泄漏**：N 次后 `free_frames`、`proc_count`、Job `used_procs` 回基线 | 同上（**依赖 R42-A**） | 基线在第 1 次启动**之前**读，不是之后 | 监督者故意不 reap ⇒ `used_procs` 单调涨 ⇒ 红 |
| 5 | 服务不继承 ambient 权限：只有显式授予的句柄 | 同上 | `fd_list` 里的条数 == 授予数 | 多授一个句柄 ⇒ 条数+1 ⇒ 红 |
读数纪律：只记取证跑那一轮；拆不开的差值写"不归因"；不为文档好看重跑整链（AGENTS）。
**规模**：先 N=100，再 N=1000；1000 次的**耗时未知**（每次启动要 `load` 读盘 + 逐段 VMO + `vmo_write`，TCG 下可能是秒级/次）——所以 N=1000 可能要数十分钟到数小时，需要先测单次耗时再定超时。

## 3. S5b：`posix_spawn`（受限形态）
### 3.1 今天 `launch` 能做什么 / 不能做什么（`exec.rs`）
| 能力 | 现状 |
|---|---|
| 传 argv | 只传 **argv[0]**（路径），`args_len` 上限 512；**无 argv[1..]**、无 envp |
| 传句柄 | 只传 **1 个**（`console` 副本，角色硬编码 `ROLE_LOG`）；`nhandles=1` 写死 |
| 传 stdin/stdout/stderr | **未传**（`ROLE_STDIN/STDOUT/STDERR=9/10/11` 内核已认，A2 `a2-exec` 档用过，但 `launch` 没接） |
| 失败回滚 | **无**：`process_create` 之后任一步失败，已建的 proc/stack VMO/SI VMO/`con_dup` 句柄全部泄漏（对比内核 `notify_broker` 的 `Cleanup` RAII） |
### 3.2 设计：`aurora-user-runtime::spawn`（扩展 `exec.rs`，**不新建 crate**，**不新增 syscall**）
```
pub struct SpawnAttr<'a> { pub argv: &'a [&'a [u8]], pub stdin: Option<Handle>, pub stdout: Option<Handle>, pub stderr: Option<Handle>, pub extra: &'a [(u32 /*role*/, Handle)] }
pub fn spawn(l:&Loaded, job:Handle, a:&SpawnAttr) -> Result<Handle /*proc*/, RTError>
```
* **argv 打包**：`args` 区按 NUL 分隔连续存放（内核已按 `args_off/args_len` 校验；`rt::args_at` 返回整块、shell 的 `split(0)` 已在用）。上限仍 512 字节，**超出返回 `TOOLONG` 而不截断**。
* **fd 语义**：只支持 0/1/2（R32 取方案 3）。子进程 `fd_lookup(0/1/2)` 经 `ensure_stdio`（ADR-187）惰性建 Console——**这与"传 ROLE_STDIN/OUT/ERR 句柄"的关系需要核实**：`a2-exec` 路径是把 3 个独立 Console 句柄按角色转移；惰性 stdio 是另一条。**我没读 `ensure_stdio` 全文，这一点未核实**，实施前须先读并写判据，防止两条路径互相覆盖。
* **回滚**：用 RAII 守卫（用户态 `Drop`），失败时 `process_kill`(若已 start) + `handle_close` 各句柄 + （R42-A 后）`proc_reap`。**守卫里不得 panic、不得分配**。
* **不做**：`adddup2` 任意 fd、`posix_spawnattr`（信号掩码/调度）、`envp`（无环境概念；`PATH` 搜索是 shell 的事，`registry.rs` 已有）。
### 3.3 判据
| # | 判据 | 负样本 |
|---|---|---|
| 1 | spawn 10 000 次（或 ≤`max_procs`，取决于 R42）后句柄数/页数回基线 | 失败路径不关句柄 ⇒ 句柄数涨 ⇒ 红 |
| 2 | argv[0..2] 子进程读回逐字节一致（`execprobe` 已有 argv 回显先例） | 打包少一个 NUL ⇒ 红 |
| 3 | stdout 重定向到文件句柄：子进程写 → 父读文件一致 | **依赖 `fd_io` 对 `VfsFile` 的写路径**（`fs-rw` 档已有） |
| 4 | 失败注入：`process_start` 前人为失败 ⇒ 无半截进程（`proc_enum` 计数不变） | 去掉回滚 ⇒ 红 |
手册"spawn 压测 1 万次无泄漏"在 R42-A 之前**同样不可达**（`max_procs` 限制）。

## 4. 待裁决项（编号接 ADR-268 的 R41）
| 编号 | 问题 | 选项 | 建议 |
|---|---|---|---|
| **R42** | 用户态如何回收已终止进程 | A 新增 83=`proc_reap` / B 改 17 号"等即收" / C `handle_close(Proc)` 顺带收 / 都不做（出口降级） | **A**。B 破坏已采纳 ABI；C 引入 capability→sched 耦合 |
| **R43** | `user/init`（监督者）怎么起 | a 内核 `stage_init_user` 直接起 / b 由 shell `run /INIT.ELF` 起 / c 作为 `resident-init` 的新子档 | **b 起步**（零内核改动，先证监督逻辑），a/c 待 R37 |
| **R44** | `launch` 是否扩展为可传多句柄与 argv[1..]（§3.2 的 `spawn`），并**保持旧 `launch` 签名不变** | 扩展（新增 `spawn`，旧函数留着）/ 原地改 | **新增、不改旧**（`shell run`/`execprobe` 依赖旧行为，ELF 字节稳定性纪律） |
| **R45** | 服务单元放根目录 `/*.SVC`（8.3） | 接受 / 等子目录写支持 | **接受**，写入已知限制 |
| **R46** | `host-svc` 是否新建 crate（又一个 `host-*`） | 新建 / 并入 `user/runtime`（不可：runtime 是 no_std 二进制依赖、不能 `cargo test`） | **新建**；沿用 R14 命名待定 |
沿用：R30–R41、R1–R29。**R42 不批准 ⇒ S5c 只能交付"监督逻辑 + ≤max_procs 次的重启"，不得宣称 G2 的"1000 次重启"达成。**

## 5. 实施顺序（批准后；每步独立可验、可回退）
1. `host-svc` 纯函数 crate + `cargo test`（**零内核/ELF 影响**，可先做）。
2. R42-A：内核 83 号 + `runtime::proc_reap` 封装 + ktest（含 `check-syscall-abi-arms` 三条判据 + unsafe 登记 + 负样本）。
3. `runtime::spawn`（新增，含回滚守卫）+ 泄漏取证 ktest。
4. `user/init` 监督者 + QEMU 判据 #2–#5。
5. 文档与 BACKLOG；`check` 21/21、`test` 判定表回归。
**每步之后跑 `check`/`ktests`/`test`，贴前后读数**（AGENTS 工作协议）。

## 6. 如实声明
* **未读**：`ensure_stdio` 全文、`sys_process_start` 对 `nhandles`/角色的完整校验、`runtime::elf::map_segs`。§3.2 的 stdio 结论因此标"未核实"。
* **未测**：`sleep_ms(10)` 轮询的 CPU 占用；单次 spawn 耗时；1000 次总耗时。
* **没有编译**；`host-svc` 的预期测试数是设计目标，不是已有数。
* 本 ADR 修正了 ADR-268 的一处错误（"S5c 零新 syscall"）。
