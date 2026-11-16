# ADR-130：A2 用户运行时——argv 区语义、标准句柄角色与退出码寄存器

状态：**已采纳**（2026-11-16，使用者授权："继续，每阶段 commit 一次，直到 D 阶段完成"）。
作者：workbuddy（总设计 V1.0 阶段 A2，`docs/Aurora-OS-完整操作系统架构与Shell命令体系建设总设计-V1.0.md` §9 A2）。
关联：ADR-075（决策 3：SI 页两侧独立声明同一组偏移）、ADR-108（FS-03 文件 ABI）、
`docs/design/A2-用户运行时与外部命令执行-内核侧设计草案.md`（方案 A 的论证全文）、
总设计 §6.3（不按命令设计 syscall）。

## 背景

A2 的验收句（总设计 §9）："Shell 能运行独立 ELF 命令程序；命令输出和退出码返回 Shell。"
实现它需要三样今天没有的东西：argv 传递、标准句柄继承、退出码传递。
本 ADR 的约束：**不新增任何 syscall 号**（user.rs 的号表一字不动）。

## 决策 1：SI 页 argv 区——给既有偏移赋义，零布局变更

`SI_OFF_ARGS_OFF=12` / `SI_OFF_ARGS_LEN=16`（user.rs:109-110，声明已久、零消费方）
赋义为"页内 argv 区的偏移与长度"：创建方把 argv 字节（NUL 分隔）写进页内该区，
子进程从自己那页直接读（**零拷贝**——SI 页整页已映射给子进程，只读）。

**内核只校验，不解析**（`sys_process_start`）：
`args_off/args_len` 全零 = 无 argv（既有产物默认形状，向后兼容）；
非零时必须满足 `args_len > 0 && args_off >= SI_OFF_HANDLES + n*SI_DESC_BYTES
&& args_off+args_len <= 页大小 && args_len <= 512`，违反 ⇒ `E_INVALID`。
依据：console-probe 探针参数（512/8）已在用这两格传页内数据——本决策把既有用法升格为正式语义。
**envp 本决策不做**（头部 24 字节已满，扩头是布局变更；等有真实调用者再裁——总设计 §6.3"由用例逼出来再定"）。

## 决策 2：标准句柄角色 ROLE_STDIN/STDOUT/STDERR = 9/10/11

机制面零改动：16 号 transfer 对任意 role 可用（实测：S4b 的 shell 会话已转移 ROLE_LOG/ROLE_JOB）。
本决策只把"stdin/stdout/stderr"从约定升格成常量；创建方 grant **三份独立句柄**
（同一句柄填两个描述符 = 第二次 transfer 必 NoSuch——transfer 移走即失效，2026-11-16 实测）。
内核不做"隐式默认挂控制台"：不配 std 句柄的子进程拿不到控制台（fail-closed，可判）。

## 决策 3：3 号 SYS_EXIT 的 `rdi` 赋义为退出码

此前 3 号的 `rdi` 无语义，分派器只置 exit 标志；收尸路径（terminate_task/kill_current）
写死常量（终止 1、自然收工 0），**17/19 号的等待者拿不到进程真正的退出码**
（execprobe 实测 `Some(1)`，而它 `exit(7)`）。

新语义：分派器记 `rdi` 进**每任务退出码寄存器**（sched::EXIT_CODES，原子表、无锁序新增——
3 号写、收尸读，不新增任何锁）；`terminate_task` 收尸时**自记过（含 0）按自记值，
没记过（被杀/故障终止）仍按口径 1**——kill_current 的"非正常"口径不变。

**行为变化与兼容性**：自然收工的进程结局从写死 0 变为 `rdi`——旧调用方（shell `exit(0)`）语义不变；
判定表整链重验兜底（2026-11-16：63 行 63 符合，见本 ADR 的验收段）。

## 决策 4：判定夹具 execprobe 与两行判定

`user/execprobe`（第六个用户产物，`a2-exec` 构建内嵌）：**第一个经 A2 语义启动的外部 ELF**——
读 argv → 写**继承的 stdout** → `exit(7)`。判定两行（进判定表）：
- 正向（a2-exec）：三格判据 = 串口出现 execprobe 自打的 argv 行 + 收工退出码 Some(7)；
- 负样本（a2-exec-bad）：`args_len` 覆盖句柄表 ⇒ 16 号校验拒 `E_INVALID` 且**不放行**
  （串口不得出现 execprobe 输出）。

## 验收（2026-11-16 实测）

- `run --features a2-exec`：PASS/33，串口 `execprobe: argv[0]=execprobe`，收工 `Some(7)`；
- `run --features a2-exec-bad`：`argv 校验拒 ret=0xffffffffffffffff`，无 execprobe 输出；
- check 17/17（unsafe 白名单/census 同轮重登记：execprobe U1=2/U5=3、runtime U1=5/U5=32）；
- 判定表 **63 行 63 符合**（2026-11-16 整链，`build/matrix-workbuddy-*.txt`）。

## 未决（留给后续 ADR）

- envp：头部扩到 32 字节的布局变更（等第一个真实调用者）；
- stderr 的独立语义（今天三口同指 console，无重定向）；
- PATH 搜索（总设计 §6.3：内核零改动，用户态 runtime 做）。
