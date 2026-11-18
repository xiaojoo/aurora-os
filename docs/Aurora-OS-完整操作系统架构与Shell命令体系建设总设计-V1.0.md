# Aurora OS 完整操作系统架构与 Shell 命令体系建设总设计 V1.0

**项目：** Aurora OS  
**文档版本：** V1.0  
**文档性质：** 总体架构、内核子系统、用户空间、Shell 命令体系与工程实施路线  
**源码基线：** `aurora-os-main`，提交快照 `94c896fc129969a3efa3207d475b8a1a8e9d7b1d`（仓库压缩包内记录）  
**源码日期：** 2026-11-15  
**目标平台：** x86-64 Intel / AMD PC，Limine 启动，QEMU 优先验证  
**主要语言：** Rust；必要的 x86-64 汇编；C/FFI 仅在确有 ABI 或驱动需求时引入  
**内核路线：** 模块化宏内核 + 内核内特权/unsafe 边界收敛；为后续用户态驱动和服务隔离预留接口  
**首期产品形态：** 可启动、可交互、可运行用户程序的命令行操作系统；图形能力按已有代码继续演进，但不作为基础内核闭环的前置条件。

---

# 0. 文档目的与使用规则

本文件是 Aurora OS 后续系统能力建设的总规划，回答四个问题：

1. 一个完整的通用操作系统由哪些子系统组成？
2. 每个子系统需要提供哪些内核能力、用户空间服务和 Shell 命令？
3. 当前 Aurora OS 已经有哪些真实实现，哪些只有局部实现，哪些尚未开始？
4. 应按什么依赖顺序写代码，怎样验收，避免先写出一堆没有内核支撑的空命令？

本文件不是要求一次性实现所有 Linux 命令，也不是承诺 Aurora OS 立即兼容 Linux/POSIX。命令清单是长期目标目录；每条命令必须等其依赖能力真实存在后才能标记为完成。

## 0.1 设计原则

- **以内核能力为中心：** 先实现对象、接口、权限、错误处理和资源生命周期，再实现命令。
- **内核与用户空间分离：** `ls`、`ps`、`grep`、`ip` 等命令原则上属于用户空间；内核提供受控 API。
- **模块化宏内核：** 首期内核服务仍可在内核态运行，但模块必须有清晰接口、依赖登记和资源所有权。
- **安全 Rust 优先：** `unsafe` 集中在架构、页表、MMIO、DMA、上下文切换等必要边界；业务逻辑尽量安全 Rust。
- **能力句柄优先：** 用户程序通过内核授予的句柄访问对象；不默认赋予任意全局对象访问权。
- **ABI 只增不改：** 系统调用号、错误码、结构布局和能力位按版本策略扩展，不复用已发布编号。
- **增量开发：** 每个里程碑有独立范围、文件清单、正反测试和回归基线。
- **真实验收：** 命令必须访问真实内核对象或设备；不允许硬编码输出冒充实现。
- **诚实标记：** 区分“已实现”“特性门控实现”“探针/测试实现”“部分实现”“规划中”。
- **故障分级：** 可恢复错误返回错误；用户程序故障优先隔离到进程；只有内核不变量被破坏才升级为致命故障。

## 0.2 本文与现有文档的关系

本文件扩展而不是取代仓库中的：

- `docs/Aurora OS 开发手册（企业级）V1.2.md`
- `docs/architecture/module-interfaces.toml`
- `docs/architecture/module-dependencies.md`
- `docs/architecture/lock-order.md`
- `docs/adr/ADR-*.md`
- `BACKLOG.md`

若本文与已采纳 ADR 或现有 ABI 冲突，以已采纳 ADR、当前代码和机器可读接口登记表为准。需要改变已采纳决策时，新增 ADR，不得静默覆盖历史决定。

---

# 1. 完整操作系统的组成

一个可持续演进的桌面/通用 PC 操作系统，至少由以下系统域组成。

| 编号 | 系统域 | 主要职责 | 代表命令/工具 |
|---|---|---|---|
| OS-01 | 启动与系统初始化 | 固件交接、引导、内核初始化、init 启动 | `bootctl`、`reboot`、`poweroff` |
| OS-02 | CPU 与体系结构 | CPU 特性、特权级、上下文、SMP | `uname`、`arch`、`lscpu` |
| OS-03 | 中断与定时器 | 异常、中断、时钟源、定时器 | `irqstat`、`timerstat` |
| OS-04 | 物理/虚拟内存 | PMM、VMM、堆、映射、共享内存 | `free`、`vmstat`、`pmap` |
| OS-05 | 进程与线程 | 进程、线程、装载、退出、回收 | `ps`、`top`、`kill`、`jobs` |
| OS-06 | 调度与同步 | 调度策略、等待队列、锁、唤醒 | `schedstat`、`taskset` |
| OS-07 | IPC 与对象能力 | 句柄、消息、事件、管道、共享内存 | `ipcstat`、`handle` |
| OS-08 | 系统调用与运行时 | 用户/内核边界、ABI、用户库 | `abi`、`syscall`（诊断工具） |
| OS-09 | 文件系统与存储 | 块设备、分区、VFS、文件系统、缓存 | `ls`、`cp`、`mount`、`df` |
| OS-10 | 设备与驱动 | PCI、设备枚举、驱动生命周期、DMA | `lspci`、`lsdev`、`devctl` |
| OS-11 | 控制台与终端 | TTY、输入输出、终端行规程、多会话 | `tty`、`stty`、`clear` |
| OS-12 | 输入子系统 | 键盘、鼠标、输入事件、设备热插拔 | `inputctl`、`evtest` |
| OS-13 | 显示与图形 | framebuffer、显示模式、合成、窗口管理 | `displayctl`、`wmctl`、`screenshot` |
| OS-14 | 网络协议栈 | 网卡、Ethernet、IP、TCP/UDP、DNS | `ip`、`ping`、`ss`、`curl` |
| OS-15 | 用户、身份与权限 | 用户、组、登录、访问控制、审计 | `whoami`、`id`、`passwd` |
| OS-16 | 安全启动与安全机制 | 启动信任、签名、隔离、权限、密钥 | `verify`、`securebootctl` |
| OS-17 | 时间与电源管理 | RTC、时区、睡眠、关机、ACPI | `date`、`uptime`、`powerctl` |
| OS-18 | 日志与诊断 | 内核日志、服务日志、崩溃现场、追踪 | `dmesg`、`journalctl`、`crashctl` |
| OS-19 | 服务管理与 init | PID 1、服务依赖、启动/停止、重启策略 | `service`、`systemctl` 风格工具 |
| OS-20 | 配置与系统信息 | 主机名、环境、系统参数、配置文件 | `hostname`、`env`、`sysctl` |
| OS-21 | 软件包与更新 | 包格式、仓库、安装、升级、回滚 | `pkg`、`update`、`rollback` |
| OS-22 | Shell 与基础工具 | 命令解析、脚本、Coreutils、管道 | `sh`、`ls`、`grep`、`find` |
| OS-23 | 开发与调试工具 | 编译、链接、反汇编、调试、测试 | `readelf`、`objdump`、`ktest` |
| OS-24 | 音频与多媒体 | 声卡、音频混音、媒体设备 | `audioctl`、`aplay`（后期） |
| OS-25 | USB 与外设生态 | USB Host、HID、存储、摄像头等 | `lsusb`、`usbctl` |
| OS-26 | 国际化与区域设置 | Unicode、键盘布局、语言、时区格式 | `locale`、`keymap` |
| OS-27 | GUI 桌面与应用平台 | 桌面会话、窗口、应用生命周期 | `desktopctl`（后期） |
| OS-28 | 安装、恢复与运维 | 安装介质、恢复环境、诊断、备份 | `installer`、`rescue` |

**注意：** 并非所有系统域都必须进入首个可启动版本。文件系统、进程、内存、驱动、控制台、网络、安全和更新是长期产品能力；音频、USB、完整 GUI、包管理器等可按产品定位分期建设。

# 2. 当前 Aurora OS 源码基线盘点

以下判断依据本次上传源码快照的目录、模块、系统调用、Cargo feature、ADR 与开发手册。状态不是对未来的承诺。

状态定义：

- **已有：** 产品路径已有实现，并有对应测试/调用。
- **部分：** 已有基础实现，但能力不完整，或仅特性门控。
- **探针：** 有测试、枚举或硬件验证代码，尚不等于产品服务。
- **未实现：** 当前源码没有可用产品实现。
- **后期：** 建议进入未来阶段。

| 系统域 | 当前源码/证据 | 状态 | 主要缺口 |
|---|---|---|---|
| 启动 | `limine.rs`、`boot_guard.rs`、`main.rs` | 已有/部分 | 启动项配置工具、恢复环境、产品 init 服务化 |
| x86-64 CPU | `arch/x86_64/{cpu,cpuid,trap,apic,smp}.rs` | 已有 | 真机矩阵、更多 CPU/固件差异验证 |
| 中断/定时器 | `irq.rs`、`clock.rs`、APIC、TSC | 已有/部分 | 完整设备 IRQ 路由和长期时钟源策略 |
| 内存 | `mm.rs`、`frame.rs`、`heap.rs`、`vmo.rs` | 已有/部分 | 完整用户态映射 API、回收/诊断产品接口 |
| 进程/线程 | `proc.rs`、`sched.rs`、`user.rs`、`elf.rs`、ADR-073/075/076 | 已有/部分 | 通用进程管理 ABI、命令行进程工具、完整 exec/wait 语义 |
| 调度/同步 | `sched.rs`、`sync.rs`、等待队列、SMP | 已有/部分 | 迁移、优先级策略、调度观测 API |
| IPC/句柄 | `handle.rs`、VMO、console handles | 部分/特性门控 | 通用消息 IPC、pipe/event/socket、能力委派完整化 |
| 系统调用 | `user.rs`、`int 0x80`、SYSCALL 快路径 | 已有/部分 | 文件/目录、网络、用户/服务等 API 扩展 |
| 存储 | `ahci.rs`、`virtio.rs`、`filesystem.rs` | 部分 | 块设备统一服务、写入与错误处理完善 |
| GPT/FAT | `filesystem/gpt.rs`、`filesystem/fat32.rs`、ADR-038/078 | 部分/只读 | 分区挂载产品路径、VFS、目录完整读写 |
| 驱动/PCI/ACPI | `pci.rs`、`acpi.rs`、`driver.rs`、`hw.rs` | 部分 | 驱动注册/匹配/卸载/重置完整化、设备服务 |
| 控制台 | `serial.rs`、`fbcon.rs`、console syscalls | 已有/部分 | 完整 TTY 行规程、stdin/out/err 语义与终端控制 |
| 输入 | `kbd.rs`、`mouse.rs`、PS/2 features | 部分/特性门控 | 通用输入事件、USB HID、设备抽象 |
| 显示/窗口 | `frame.rs`、`fbcon.rs`、main 中 WM/session 路径 | 部分/特性门控 | 通用显示驱动、GPU 加速、稳定 compositor API |
| 网络 | `ktests/net.rs`、`virtio-net` feature | 探针/部分 | 完整网卡驱动产品路径、协议栈、socket API、DNS |
| 安全 | SMEP/SMAP、签名、boot guard、handle rights | 部分 | 用户身份、ACL、审计、密钥管理、安全策略 |
| 时间/电源 | `clock.rs`、`tsc.rs`、ACPI 部分 | 部分 | RTC/时区、睡眠/恢复、关机/重启硬件路径 |
| 日志/崩溃 | `serial.rs`、`crash.rs`、`watchdog.rs`、`state_store.rs` | 已有/部分 | 持久化日志服务、用户态日志、崩溃转储管理工具 |
| init/服务管理 | `main.rs` 启动编排、resident init/session | 部分 | 产品化 PID 1、服务描述、依赖和重启策略 |
| Shell | `user/shell/src/main.rs` | 已有但非常基础 | 目前主要为 help/echo/ping/abi/exit；缺少通用 parser、外部命令、管道重定向 |
| 用户工具 | `user/hello`、`user/probe`、`user/shell` | 部分 | 用户运行库、独立 Coreutils crate、程序搜索和启动器 |
| 软件包/更新 | 签名包、状态区、A/B 相关设计 | 部分 | 通用包格式、仓库、依赖求解、安装卸载 CLI |
| USB/音频/GUI 桌面 | 未见完整产品子系统 | 未实现/后期 | 控制器、驱动、服务、API 和用户工具 |

## 2.1 当前已经存在的系统调用

当前 `kernel/src/user.rs` 已使用的调用号包括：

| 调用号 | 名称 | 说明 |
|---:|---|---|
| 1 | `SYS_PING` | ABI/连通性探针 |
| 3 | `SYS_EXIT` | 用户任务退出 |
| 4 | `SYS_PEEK` | 用户指针读取验证探针 |
| 5 | `SYS_PEEK_BUF` | 用户缓冲读取探针 |
| 6 | `SYS_POKE_BUF` | 用户缓冲写入探针 |
| 7 | `SYS_ABI_INFO` | ABI 版本与 feature bits |
| 8 | `SYS_HANDLE_CLOSE` | 关闭句柄（handles feature） |
| 9 | `SYS_HANDLE_DUP` | 复制/收窄句柄权限（handles feature） |
| 10 | `SYS_FILE_READ` | 从已授予的文件句柄读取（handles feature） |
| 11 | `SYS_PROCESS_CREATE` | 创建进程对象（handles feature） |
| 12 | `SYS_VMO_CREATE` | 创建 VMO（handles feature） |
| 13 | `SYS_VMO_WRITE` | 写 VMO（handles feature） |
| 14 | `SYS_ASPACE_MAP` | 地址空间映射（handles feature） |
| 15 | `SYS_THREAD_CREATE` | 创建线程（handles feature） |
| 16 | `SYS_PROCESS_START` | 启动已准备线程/进程（handles feature） |
| 17 | `SYS_PROCESS_WAIT` | 等进程收工，返回 `(observed<<32)\|退出码`（handles feature） |
| 18 | `SYS_PROCESS_KILL` | 终止进程（handles feature） |
| 19 | `SYS_OBJECT_WAIT` | 通用对象等待（今天只支持 Proc；17 号是它的薄壳） |
| 20 | `SYS_CONSOLE_WRITE` | 控制台输出 |
| 21 | `SYS_CONSOLE_READ` | 控制台输入 |
| 22 | `SYS_FILE_OPEN` | 打开卷上路径（fs-open feature） |
| 24 | `SYS_FILE_SEEK` | 移动文件游标（fs-open feature） |
| 25 | `SYS_FILE_STAT` | 取 StatV1 固定记录（fs-open feature） |
| 26 | `SYS_DIR_READ` | 读 DirentV1 目录记录（fs-open feature） |
| 27 | `SYS_PROC_ENUM` | 游标式枚举自己 Job 名下的进程（handles feature，ADR-132） |
| 28 | `SYS_PROC_STAT` | 取一个进程的 ProcStatV1 统计（handles feature，ADR-132） |
| 29 | `SYS_PROC_KILL_BY_PID` | 按 pid 杀进程：内核在调用者名下反查带 WRITE 的 Proc 句柄后走 18 号同一路径（handles feature，ADR-134） |
| 30 | `SYS_LOG_READ` | 把串口日志环的最近整行拷进用户缓冲（handles feature，ADR-135） |
| 31 | `SYS_PCI_ENUM` | PCI 设备清单按 32 字节定长记录拷给用户（handles feature，ADR-136） |
| 32 | `SYS_CLOCK_UPTIME` | 返回启动以来的微秒数（锚点+PIT 标定，没标定回 -1；handles feature，ADR-137） |

此表是当前源码快照的调用号清单，不代表所有 feature 在默认构建中都启用。用户程序必须先通过 `SYS_ABI_INFO` 读取 ABI 版本与能力位，再使用对应接口。新增调用必须登记、测试和版本化；不得自行选择空号后就视为已批准。

**两处必须连读的事实**（否则会拿这张表去挑空号而撞车）：

- **`23` 已被 ADR-110/111 的方向占住**（块设备写方向的 `write`），任何新调用都不得取它。
- **`2` 从来没用过**、`17/19/22/24/25/26` 在本表早前版本里漏登（本轮补齐，依据 `kernel/src/user.rs`
  的 `pub const SYS_*` 逐条核对，2026-11-17，HEAD `8a20947`）。漏登的后果不是"少一行文档"：
  AGENTS.md 明确"新增调用不得自行选空号"，一张不全的表会让下一个人把已占的号当成空的。
- A4（进程观测）**已批号并落地**：27/28 由 ADR-132 采纳（2026-11-17，使用者批准"批号 27/28"），
  方案全文与备选对比仍见 `docs/design/A4-进程观测API-草案.md`（该文件状态已改为"已采纳"）。

**基线快照**：本节的号表与结论按 `feat/wb-dev` 的 ADR-132 提交（A4 进程观测落地）核对；
此后的新增号只以 `kernel/src/user.rs` 为准，本表随 ADR 更新。

## 2.2 现阶段不得误判为已完成的能力

- 有 `virtio-net` 测试 feature，不代表已有可供用户程序使用的 TCP/IP 网络栈。
- 有 `gpt.rs` 解析器，不代表已经有通用分区管理器和 mount 命令。
- 有 FAT 文件读取，不代表 FAT 写入、目录创建和完整 VFS 已完成。
- 有进程创建/线程启动调用，不代表完整 POSIX `fork/exec/wait` 或 Linux 进程语义。
- 有窗口管理器实验路径，不代表完整桌面图形栈。
- 有签名验证和 A/B 更新设计，不代表通用软件包管理器已经完成。
- 有 `ps2-kbd`/`ps2-mouse` feature，不代表 USB/HID 通用输入栈已经完成。

---

# 3. 目标系统分层与模块边界

## 3.1 五层结构

沿用开发手册 V1.2 的分层方向：

```text
L5 用户/内核接口层
   syscall · ABI · capability handle · user runtime · FFI

L4 系统功能层
   VFS · 文件系统 · 网络栈 · 驱动框架 · 安全 · 诊断 · 输入/显示服务

L3 内核基础服务层
   PMM · VMM · heap · 进程/线程 · 调度 · 同步 · IPC · 资源管理

L2 硬件抽象层
   PCI · MMIO · DMA/IOMMU · 块设备 · 网卡 · 定时器 · 中断控制器

L1 架构层
   boot · x86-64 CPU · GDT/IDT/TSS · APIC · 页表 · 上下文切换
```

依赖原则：上层依赖下层；同层模块通过明确接口协作；低层不得反向调用高层业务。现有模块依赖登记与实际依赖图以 `module-interfaces.toml` 为准，不能只靠文档画图。

## 3.2 内核与用户空间职责

| 能力 | 内核负责 | 用户空间负责 |
|---|---|---|
| 进程 | 创建、调度、地址空间、退出、句柄 | `ps`、`top`、任务控制、启动器 |
| 内存 | 页帧、映射、保护、VMO | `free`、`vmstat`、`pmap` |
| 文件 | VFS、文件对象、权限检查、块 I/O | `ls`、`cp`、`grep`、`find`、压缩工具 |
| 网络 | 网卡驱动、协议栈、socket、路由对象 | `ip`、`ping`、`curl`、DNS 工具 |
| 设备 | 枚举、驱动接口、DMA、IRQ、设备对象 | `lspci`、`lsdev`、`devctl` |
| 用户权限 | 身份凭据、对象权限、访问控制 | `login`、`passwd`、`id`、`sudo`（若设计需要） |
| 日志 | 内核日志缓冲、事件、崩溃记录 | `dmesg`、`journalctl`、日志轮转 |
| 服务 | 进程、IPC、服务监督所需原语 | init/service manager 与服务程序 |
| Shell | 不负责业务命令 | 解析、内置命令、外部命令、脚本、管道 |

## 3.3 用户空间程序模型

目标目录（按真实调用者逐步创建，不要一次性生成空 crate）：

```text
user/
├── runtime/             # syscall 封装、错误码、字符串、IO、句柄
├── shell/               # 交互 Shell
├── coreutils/            # ls/cat/cp/mv/rm 等基础命令
├── procutils/            # ps/top/kill 等进程工具
├── memutils/             # free/vmstat/pmap 等
├── netutils/             # ip/ping/ss/curl 等
├── devutils/             # lspci/lsdev/devctl 等
├── sysutils/             # uname/date/uptime/dmesg 等
├── package/              # pkg/update/rollback
└── services/             # init、日志、网络配置等服务
```

用户空间各命令可先作为独立 ELF 产物；等通用程序装载、参数传递、标准句柄继承和进程等待接口稳定后，再统一组织成用户空间库和包。

---

# 4. 系统域详细设计与 Shell 命令总表

以下每个域都分为“内核/服务能力”和“命令”。命令状态标记：

- **P0：** 基础系统可用必须有。
- **P1：** 日常使用重要，基础闭环完成后实现。
- **P2：** 系统管理/开发者工具。
- **P3：** 高级、可选或桌面生态能力。
- **内置：** 应由 Shell 本身实现。
- **用户态：** 独立用户程序，不进入内核。
- **服务：** 需要后台系统服务或守护进程。
- **特权：** 需要管理员/能力句柄授权。

## 4.1 OS-01 启动、初始化与关机

**内核/服务能力：** Limine 启动交接、启动信息校验、内核初始化阶段、启动模式、安全模式、init 启动、系统关机/重启、启动失败保护、恢复模式。

**命令：**

| 命令 | 优先级 | 类型 | 功能/依赖 |
|---|---|---|---|
| `bootctl` | P2 | 特权 | 查看/选择启动项；依赖启动配置存储与启动器协议 |
| `reboot` | P1 | 特权 | 重启；依赖 ACPI/平台复位路径 |
| `poweroff` | P1 | 特权 | 关机；依赖 ACPI 电源管理 |
| `shutdown` | P2 | 特权 | 定时/延迟关机、取消关机 |
| `initctl` | P2 | 特权 | 查看 init 状态、切换运行级别/目标 |
| `rescue` | P2 | 特权 | 进入恢复模式 |
| `bootlog` | P1 | 用户态 | 查看启动阶段记录 |

**验收：** 正常启动、启动失败独立退出码、安全模式状态可见、关机/重启路径有硬件或 QEMU 证据。不得只打印“rebooting”就算完成。

## 4.2 OS-02 CPU 与体系结构

**内核能力：** CPUID、CPU 特性策略、GDT/IDT/TSS、特权级、上下文切换、FPU/SIMD 状态、SMP、CPU online/offline。

| 命令 | 优先级 | 类型 | 功能/依赖 |
|---|---|---|---|
| `arch` | P1 | 用户态 | 显示体系结构 |
| `uname` | P1 | 用户态 | 内核名称、版本、架构 |
| `lscpu` | P2 | 用户态 | CPU 数量、型号、特性、拓扑 |
| `cpuinfo` | P2 | 用户态 | Aurora 扩展 CPU 诊断 |
| `smpstat` | P2 | 用户态 | CPU 在线状态、调度统计 |
| `cpuctl` | P3 | 特权 | CPU 上下线/亲和性管理 |

## 4.3 OS-03 中断、异常与定时器

**内核能力：** 异常向量、IRQ 路由、APIC/IOAPIC、MSI/MSI-X、EOI、时钟源、定时器、超时与等待。

| 命令 | 优先级 | 类型 | 功能/依赖 |
|---|---|---|---|
| `irqstat` | P2 | 用户态 | 各 IRQ/CPU 中断计数 |
| `timerstat` | P2 | 用户态 | 时钟源、tick、定时器统计 |
| `irqctl` | P3 | 特权 | 中断路由诊断/控制 |
| `watchdogctl` | P2 | 特权 | 看门狗状态与阈值 |

这些命令依赖内核只读诊断接口。不能让用户程序直接读写 APIC/MMIO。

## 4.4 OS-04 内存管理

**内核能力：** 物理帧分配、虚拟地址空间、页表、内核堆、用户映射、COW（后期）、VMO、共享内存、内存回收、OOM 策略、TLB shootdown。

| 命令 | 优先级 | 类型 | 功能/依赖 |
|---|---|---|---|
| `free` | P1 | 用户态 | 总内存、已用、空闲、缓存 |
| `vmstat` | P2 | 用户态 | 页分配、缺页、回收、映射统计 |
| `pmap` | P2 | 用户态 | 指定进程地址空间映射 |
| `meminfo` | P1 | 用户态 | Aurora 内存摘要 |
| `memtest` | P3 | 特权/恢复环境 | 内存诊断；不能随意破坏运行内存 |
| `slabtop` | P3 | 用户态 | 内核对象缓存统计（若实现 slab） |

## 4.5 OS-05 进程与线程管理

**内核能力：** Process/Thread 对象、任务 ID、创建、启动、阻塞、唤醒、退出、终止、回收、退出码、父子关系、程序装载、标准句柄继承、等待子进程。

**目标命令：**

| 命令 | 优先级 | 类型 | 功能/依赖 |
|---|---|---|---|
| `ps` | P0 | 用户态 | 列出进程/线程、状态、ID |
| `top` | P1 | 用户态 | 动态显示 CPU/内存占用 |
| `kill` | P1 | 用户态/特权 | 请求终止进程；依赖权限与进程控制 API |
| `jobs` | P1 | 内置 | 当前 Shell 作业列表 |
| `fg` | P2 | 内置 | 前台作业 |
| `bg` | P2 | 内置 | 后台作业 |
| `wait` | P1 | 内置/系统调用 | 等待子任务结束 |
| `pidof` | P2 | 用户态 | 按程序名查询 PID |
| `pgrep` | P2 | 用户态 | 按条件查询进程 |
| `pkill` | P2 | 用户态 | 按条件终止进程 |
| `nice` | P3 | 用户态 | 以指定优先级启动任务 |
| `renice` | P3 | 特权 | 修改任务优先级 |
| `taskset` | P3 | 特权 | CPU 亲和性 |
| `time` | P1 | 内置 | 测量命令运行时间 |

**关键前置：** 当前已有进程/线程创建、启动和终止的部分 ABI；`ps` 仍需要安全的只读进程快照接口。不要为 `ps` 直接暴露内核任务结构指针。

## 4.6 OS-06 调度与同步

**内核能力：** 运行队列、抢占、优先级、时间片、等待队列、锁、条件等待、CPU 亲和性、调度统计。

| 命令 | 优先级 | 类型 | 功能 |
|---|---|---|---|
| `schedstat` | P2 | 用户态 | 调度切换、等待、抢占统计 |
| `runqueue` | P3 | 用户态 | 每 CPU 运行队列摘要 |
| `taskctl` | P3 | 特权 | 任务策略/优先级控制 |

这些属于诊断工具，正常用户不应拥有任意修改调度器内部状态的能力。

## 4.7 OS-07 IPC、句柄与能力系统

**内核能力：** capability handle、owner、rights、dup/transfer、VMO、消息通道、事件、信号量、共享内存、管道、socket 句柄。

| 命令 | 优先级 | 类型 | 功能 |
|---|---|---|---|
| `ipcstat` | P2 | 用户态 | IPC 对象与消息队列统计 |
| `handle` | P2 | 用户态/调试 | 当前进程句柄摘要（仅允许查看自身或授权对象） |
| `pipe` | P2 | 用户态 | 管道诊断/测试工具 |
| `eventctl` | P3 | 特权 | 事件对象诊断 |

Shell 的 `|` 管道必须由内核管道对象或受控缓冲对象支持，不应通过临时文件伪装长期管道语义。

## 4.8 OS-08 系统调用与用户运行时

**内核能力：** syscall ABI、参数验证、用户指针安全拷贝、错误码、句柄权限、ABI 版本与能力位。

| 命令 | 优先级 | 类型 | 功能 |
|---|---|---|---|
| `abi` | P0 | 内置/诊断 | 显示 ABI 版本和 feature bits（当前已有） |
| `syscall` | P3 | 调试 | 受控系统调用探针，不允许任意内核调用 |
| `runtime-info` | P2 | 用户态 | 用户运行时版本与能力 |

必须先建设 `user/runtime`，否则每个用户程序都将重复实现 `int 0x80` 汇编、参数校验和错误转换。

## 4.9 OS-09 文件系统与存储

本域的详细设计由《Aurora OS 文件系统与 Shell 命令体系建设设计文档 V1.0》承接；本总规划只登记命令范围。

**命令：**

| 类别 | 命令 |
|---|---|
| 路径/目录 | `pwd`、`cd`、`ls`、`tree`、`mkdir`、`rmdir` |
| 文件操作 | `touch`、`cat`、`cp`、`mv`、`rm`、`ln` |
| 元数据 | `stat`、`file`、`basename`、`dirname` |
| 文本查看 | `head`、`tail`、`less`、`more`、`nl` |
| 搜索/统计 | `find`、`grep`、`wc`、`sort`、`uniq`、`diff` |
| 空间 | `df`、`du` |
| 权限 | `chmod`、`chown`、`chgrp`、`umask`、`getfacl`、`setfacl` |
| 磁盘 | `lsblk`、`blkid`、`fdisk`、`parted`、`mount`、`umount`、`fsck`、`sync` |
| 压缩 | `tar`、`gzip`、`gunzip`、`zip`、`unzip`、`xz` |

优先顺序：目录只读 → VFS/路径 → 文件读 API → 文件写 API → FAT 写入 → Coreutils → mount/df/du → 高级格式。

## 4.10 OS-10 设备与驱动

**内核能力：** PCI 枚举、ACPI、设备对象、驱动匹配、驱动启动/停止、资源分配、MMIO、DMA、IOMMU、IRQ、设备重置、热插拔事件。

| 命令 | 优先级 | 类型 | 功能/依赖 |
|---|---|---|---|
| `lspci` | P1 | 用户态 | PCI 设备枚举 |
| `lsdev` | P1 | 用户态 | Aurora 设备树/设备清单 |
| `devctl` | P2 | 特权 | 设备启停、重置、诊断 |
| `driverctl` | P3 | 特权 | 驱动绑定/解绑 |
| `iommu-info` | P2 | 用户态 | IOMMU 状态与映射统计 |
| `hwinfo` | P2 | 用户态 | 硬件摘要 |
| `acpidump` | P3 | 用户态 | 导出 ACPI 表 |

禁止用户态命令直接对任意物理地址做 MMIO。所有设备控制必须通过驱动能力句柄或受控管理服务。

## 4.11 OS-11 控制台、TTY 与终端

**内核能力：** console object、TTY、输入输出缓冲、标准句柄、终端行规程、回显、控制字符、会话、前台进程组、终端尺寸和属性。

| 命令 | 优先级 | 类型 | 功能 |
|---|---|---|---|
| `tty` | P1 | 用户态 | 当前终端标识 |
| `stty` | P2 | 用户态 | 终端参数 |
| `clear` | P1 | 内置 | 清屏 |
| `reset` | P2 | 用户态 | 重置终端状态 |
| `setterm` | P3 | 用户态 | 终端显示控制 |
| `login` | P2 | 用户态服务 | 登录会话（身份系统完成后） |

现有 console read/write 和多会话/图形终端路径应逐步统一成 TTY/Terminal API；不能让 Shell 直接依赖串口或 framebuffer 内部实现。

## 4.12 OS-12 输入子系统

**内核/服务能力：** 输入设备枚举、键盘扫描码、布局映射、鼠标事件、输入队列、设备热插拔、HID。

| 命令 | 优先级 | 类型 | 功能 |
|---|---|---|---|
| `inputctl` | P2 | 特权 | 输入设备状态与配置 |
| `evtest` | P2 | 用户态 | 实时观察输入事件 |
| `keymap` | P2 | 用户态 | 键盘布局 |
| `mousectl` | P3 | 特权 | 鼠标设备配置 |

先将现有 PS/2 逻辑抽象为统一 Input API，再接 USB HID；不要让应用直接读取 i8042 端口。

## 4.13 OS-13 显示、图形与窗口管理

**能力：** 显示设备发现、framebuffer 映射、显示模式、像素格式、终端绘制、窗口、输入命中、合成、脏矩形、截图、未来 GPU 加速。

| 命令 | 优先级 | 类型 | 功能 |
|---|---|---|---|
| `displayctl` | P2 | 特权 | 显示设备/分辨率/模式 |
| `wmctl` | P2 | 用户态 | 窗口管理器状态 |
| `screenshot` | P2 | 用户态 | 截取屏幕 |
| `sessionctl` | P1 | 用户态/特权 | 创建、切换、关闭会话 |
| `desktopctl` | P3 | 用户态 | 桌面会话管理 |
| `fontctl` | P3 | 用户态 | 字体资产与渲染设置 |

当前已有 framebuffer、fbcon、PS/2 鼠标、窗口/多会话实验代码；本阶段不重写这些实现，应先抽取稳定的 display/input/window API。

## 4.14 OS-14 网络协议栈

**内核/服务能力：** 网卡驱动、Ethernet、ARP、IPv4/IPv6、ICMP、UDP、TCP、路由表、socket、DNS 客户端、DHCP、网络接口状态。

| 命令 | 优先级 | 类型 | 功能/依赖 |
|---|---|---|---|
| `ip` | P1 | 用户态/特权 | 网卡、地址、路由配置 |
| `ping` | P1 | 用户态 | ICMP 连通性（当前 Shell ping 是 ABI 探针，不等于网络 ping） |
| `ss` | P2 | 用户态 | socket 连接统计 |
| `netstat` | P2 | 用户态 | 网络状态兼容工具 |
| `route` | P2 | 用户态 | 路由信息 |
| `ifconfig` | P2 | 用户态 | 兼容式网卡配置 |
| `hostname` | P1 | 用户态 | 主机名查看/设置 |
| `nslookup` | P2 | 用户态 | DNS 查询 |
| `dig` | P3 | 用户态 | DNS 详细诊断 |
| `dhclient` | P2 | 服务/特权 | DHCP 获取地址 |
| `curl` | P2 | 用户态 | HTTP/HTTPS 客户端 |
| `wget` | P2 | 用户态 | 文件下载 |
| `nc` | P3 | 用户态 | TCP/UDP 调试 |
| `tcpdump` | P3 | 特权 | 抓包，需要受控 packet capture API |

建议网络建设顺序：VirtIO-net/网卡驱动 → Ethernet → ARP/IPv4 → ICMP → UDP → TCP → socket API → DNS/DHCP → CLI 工具。TLS/HTTPS 与证书验证属于后续安全与加密能力。

## 4.15 OS-15 用户、身份与权限

**内核能力：** 进程凭据、用户 ID、组 ID、对象 ACL/rights、登录会话、权限检查、审计。

| 命令 | 优先级 | 类型 | 功能 |
|---|---|---|---|
| `whoami` | P1 | 用户态 | 当前用户 |
| `id` | P1 | 用户态 | 用户/组身份 |
| `users` | P2 | 用户态 | 登录用户 |
| `who` | P2 | 用户态 | 会话列表 |
| `passwd` | P2 | 特权 | 修改密码 |
| `useradd` | P3 | 特权 | 创建用户 |
| `userdel` | P3 | 特权 | 删除用户 |
| `usermod` | P3 | 特权 | 修改用户 |
| `groupadd` | P3 | 特权 | 创建组 |
| `groups` | P2 | 用户态 | 当前用户组 |
| `su` | P3 | 特权 | 切换身份 |
| `sudo` | P3 | 特权 | 临时授权执行 |

**设计约束：** 现有 capability handle 的对象权限与传统 Unix UID/GID 是两套不同模型。需要先决定身份凭据如何映射到 capability 授权，不能为了实现 `chmod` 就把所有对象权限逻辑硬编码成 Linux 模式。

## 4.16 OS-16 安全、签名与审计

**内核/服务能力：** SMEP/SMAP、W^X、用户指针校验、句柄最小权限、启动签名验证、更新包验证、密钥存储、审计事件、权限撤销。

| 命令 | 优先级 | 类型 | 功能 |
|---|---|---|---|
| `security-info` | P1 | 用户态 | 当前安全能力与安全模式 |
| `verify` | P1 | 用户态 | 验证文件/包签名 |
| `securebootctl` | P2 | 特权 | 安全启动状态 |
| `auditctl` | P2 | 特权 | 审计策略 |
| `auditlog` | P2 | 用户态 | 查看审计记录 |
| `keyctl` | P3 | 特权 | 密钥管理（需安全设计） |
| `capstat` | P2 | 用户态 | 能力句柄/授权诊断 |

不得把私钥写入普通配置文件或日志；签名验证通过也不能直接宣称系统已具备完整 Secure Boot 信任链。

## 4.17 OS-17 时间、RTC 与电源管理

**能力：** 单调时钟、墙上时钟、RTC、时区、定时器、睡眠/唤醒、ACPI 电源状态、重启与关机。

| 命令 | 优先级 | 类型 | 功能 |
|---|---|---|---|
| `date` | P1 | 用户态 | 查看/设置系统时间 |
| `uptime` | P1 | 用户态 | 系统运行时间与负载摘要 |
| `timedatectl` | P2 | 特权 | 时间源、RTC、时区 |
| `powerctl` | P2 | 特权 | 电源状态 |
| `sleep` | P1 | 用户态 | 休眠指定秒数（依赖阻塞定时器） |
| `rtcctl` | P2 | 特权 | RTC 诊断 |

## 4.18 OS-18 日志、监控与崩溃诊断

**能力：** 日志级别、并发日志、环形缓冲、持久化日志、事件 ID、崩溃记录、panic 现场、看门狗、trace。

| 命令 | 优先级 | 类型 | 功能 |
|---|---|---|---|
| `dmesg` | P1 | 用户态 | 查看内核日志 |
| `journalctl` | P2 | 用户态 | 查询持久化日志 |
| `logctl` | P2 | 特权 | 日志级别与目标 |
| `crashctl` | P2 | 用户态/特权 | 崩溃记录与 dump 管理 |
| `trace` | P3 | 特权 | 内核/进程追踪 |
| `perf` | P3 | 特权 | 性能计数与采样 |
| `watchdogctl` | P2 | 特权 | 看门狗状态 |
| `sysmon` | P2 | 用户态 | 系统资源监控 |

## 4.19 OS-19 init 与服务管理

**能力：** PID 1/init、服务描述文件、依赖顺序、启动/停止、重启策略、服务健康检查、日志关联、关机编排。

| 命令 | 优先级 | 类型 | 功能 |
|---|---|---|---|
| `service` | P1 | 特权 | 启动/停止/查看服务 |
| `servicectl` | P2 | 特权 | 服务管理接口 |
| `systemctl` | P3 | 特权 | 若未来决定采用 systemd 风格语义 |
| `initctl` | P2 | 特权 | init 控制 |
| `runlevel` | P3 | 用户态 | 运行目标/模式 |

不要求照搬 systemd。先实现简单、可审计的 init 与服务监督协议，再决定是否需要复杂依赖图、socket activation 和 unit 兼容。

## 4.20 OS-20 系统信息与配置

| 命令 | 优先级 | 类型 | 功能 |
|---|---|---|---|
| `hostname` | P1 | 用户态 | 主机名 |
| `env` | P1 | 内置 | 环境变量 |
| `export` | P1 | 内置 | 导出变量 |
| `unset` | P1 | 内置 | 删除变量 |
| `printenv` | P2 | 用户态 | 查看环境变量 |
| `sysctl` | P2 | 用户态/特权 | 查看/设置受控内核参数 |
| `getconf` | P3 | 用户态 | 系统配置值 |
| `locale` | P3 | 用户态 | 区域设置 |
| `version` | P1 | 内置/用户态 | Aurora 版本 |

## 4.21 OS-21 软件包、安装与更新

**能力：** 包格式、包清单、依赖、文件清单、签名、仓库索引、安装/卸载、升级、A/B 更新、回滚、启动健康标记。

| 命令 | 优先级 | 类型 | 功能 |
|---|---|---|---|
| `pkg` | P2 | 用户态/特权 | 安装、卸载、查询软件包 |
| `pkg list` | P2 | 用户态 | 已安装包 |
| `pkg install` | P2 | 特权 | 安装包 |
| `pkg remove` | P2 | 特权 | 卸载包 |
| `pkg update` | P2 | 特权 | 更新仓库索引 |
| `update` | P1 | 特权 | 系统升级 |
| `rollback` | P1 | 特权 | A/B 回滚 |
| `verify-system` | P2 | 用户态/特权 | 系统文件完整性 |
| `installer` | P3 | 恢复环境 | 安装操作系统 |

软件包管理器依赖文件系统写入、签名验证、网络下载、事务/回滚和权限系统。不能在这些能力未完成前先做一个只会复制文件的 `pkg` 命令并宣称包管理完成。

## 4.22 OS-22 Shell、脚本与 Coreutils

### Shell 内置命令

```text
help  exit  echo  pwd  cd  clear  history
export  unset  alias  unalias  type  which
jobs  fg  bg  wait  source  set
```

### 基础 Coreutils

```text
ls  cat  touch  mkdir  rmdir  cp  mv  rm  ln
stat  file  basename  dirname  readlink
head  tail  less  more  wc  nl  tee
sort  uniq  cut  tr  paste  diff  cmp
find  grep  xargs  printf  env  date  sleep
```

### Shell 语法能力

| 功能 | 示例 | 依赖 |
|---|---|---|
| 参数解析 | `ls -lah /home` | Lexer/Parser |
| 引号 | `echo "hello world"` | Lexer |
| 转义 | `echo a\ b` | Lexer |
| 环境变量 | `echo $HOME` | Environment |
| 命令查找 | `ls` → `/bin/ls` | PATH/程序加载 |
| 输入重定向 | `sort < a.txt` | 文件句柄 |
| 输出重定向 | `echo hi > a.txt` | open/write |
| 追加重定向 | `echo hi >> a.txt` | append |
| 管道 | `cat a \| grep hi` | pipe IPC |
| 顺序执行 | `a ; b` | Executor |
| 条件执行 | `a && b`、`a \|\| b` | Exit status |
| 后台任务 | `sleep 10 &` | Process/job control |
| 脚本 | `sh script.au` | Script parser |
| 通配符 | `ls *.txt` | Glob expansion |
| 命令替换 | `echo $(pwd)` | Subshell/process |

**实现顺序：** 先词法分析和简单参数，再内置命令和外部程序；之后重定向、管道、退出码；最后后台作业、信号/任务控制、脚本和通配符。不要第一版就实现完整 POSIX Shell。

## 4.23 OS-23 开发与调试工具

| 命令 | 优先级 | 类型 | 说明 |
|---|---|---|---|
| `ktest` | P1 | 特权/测试构建 | 执行内核测试；现有 `tools/aurora.py` 是开发入口 |
| `check` | P1 | 宿主机工具 | 仓库架构/门禁检查 |
| `build` | P1 | 宿主机工具 | 构建内核和镜像 |
| `run` | P1 | 宿主机工具 | QEMU 启动 |
| `readelf` | P2 | 用户态/SDK | ELF 信息 |
| `objdump` | P2 | 用户态/SDK | 反汇编 |
| `nm` | P2 | 用户态/SDK | 符号表 |
| `hexdump` | P2 | 用户态 | 十六进制查看 |
| `od` | P3 | 用户态 | 数据转储 |
| `gdb` | P3 | SDK/宿主 | 调试器，需远程调试 stub |
| `rustc` / `cargo` | P3 | SDK | 开发工具链，不要求内核内置 |

注意区分“宿主机开发工具”和“操作系统内部命令”。`python tools/aurora.py` 是当前仓库开发/测试工具，不等于 Aurora OS 用户态命令。

## 4.24 OS-24 音频

后期能力：音频设备枚举、HDA/USB Audio、PCM、混音、音量、音频会话。

目标命令：`audioctl`、`aplay`、`arecord`、`mixer`。首期不实现。

## 4.25 OS-25 USB 与外设

后期能力：xHCI、USB Hub、USB enumeration、控制/批量/中断传输、HID、Mass Storage、USB Audio、摄像头。

目标命令：`lsusb`、`usbctl`、`usbtest`。先完成 PCI/中断/DMA/IOMMU/驱动模型，再进入 USB Host Controller。

## 4.26 OS-26 国际化

能力：UTF-8、Unicode 字符分类、终端宽度、字体回退、键盘布局、区域格式、时区数据库。

命令：`locale`、`keymap`、`localectl`。必须先统一字符串和终端显示宽度模型，避免中文双宽字符破坏终端布局。

## 4.27 OS-27 GUI 桌面与应用平台

能力：显示驱动、合成器、窗口管理、应用生命周期、输入焦点、剪贴板、字体、主题、桌面服务。

命令：`desktopctl`、`wmctl`、`sessionctl`、`screenshot`。当前仓库已有部分 framebuffer/窗口/多会话代码，应先整理边界，不要把它当成基础内核文件系统的阻塞项。

## 4.28 OS-28 安装、恢复与运维

能力：安装器、磁盘分区、系统镜像写入、恢复 shell、离线修复、备份、日志导出、硬件诊断。

命令：`installer`、`rescue`、`backup`、`restore`、`support-bundle`。后期实现。

---

# 5. 统一命令目录与分类

以下是长期目标命令目录，按域归类。此表是规划清单，不是当前实现清单。

```text
Shell 内置：
help echo exit pwd cd clear history export unset alias unalias type which
jobs fg bg wait source set

文件/目录：
ls tree pwd cd touch cat cp mv rm mkdir rmdir ln stat file
basename dirname readlink head tail less more nl tee wc
find grep xargs sort uniq cut tr paste diff cmp

磁盘/文件系统：
df du lsblk blkid fdisk parted mount umount fsck sync

权限/身份：
chmod chown chgrp umask getfacl setfacl whoami id groups users who
login passwd useradd userdel usermod groupadd su sudo

进程/调度：
ps top kill pgrep pkill pidof jobs fg bg wait nice renice taskset time
schedstat runqueue

内存：
free meminfo vmstat pmap memtest slabtop

系统/硬件：
uname arch lscpu cpuinfo hwinfo lspci lsdev devctl driverctl
acpidump iommu-info irqstat timerstat

终端/输入/显示：
tty stty reset setterm inputctl evtest keymap mousectl
 displayctl wmctl screenshot sessionctl desktopctl fontctl

网络：
ip ping ss netstat route ifconfig hostname nslookup dig dhclient
curl wget nc tcpdump

时间/电源：
date uptime timedatectl powerctl sleep rtcctl reboot poweroff shutdown

日志/安全：
dmesg journalctl logctl crashctl trace perf watchdogctl sysmon
security-info verify securebootctl auditctl auditlog keyctl capstat

服务/配置：
service servicectl systemctl initctl runlevel env printenv sysctl getconf locale version

软件包/更新：
pkg update rollback verify-system installer

开发/诊断：
ktest check build run readelf objdump nm hexdump od gdb

外设/多媒体：
lsusb usbctl audioctl aplay arecord mixer
```

---

# 6. 系统调用与 ABI 建设总原则

## 6.1 不按命令设计 syscall

错误做法：给 `ls` 增加一个 `SYS_LS`，给 `cp` 增加一个 `SYS_CP`。

正确做法：内核提供稳定的通用对象操作；用户空间命令组合这些接口完成工作。

例如：

```text
ls
  -> directory_open / directory_read
  -> metadata query
  -> format output

cp a b
  -> source open/read
  -> destination create/write
  -> close

ps
  -> process_snapshot capability
  -> read process records
  -> format output

ip addr
  -> network-admin capability
  -> enumerate/configure interface objects
```

## 6.2 ABI 规则

1. 使用当前已存在的 ABI 入口与寄存器约定。
2. 调用号只追加，不复用。
3. 每个新增调用必须有真实调用者、正向用例和错误路径用例。
4. 用户指针必须先验证并通过受控 copy API 访问。
5. 长度必须有上限；禁止根据用户输入无限分配内核缓冲。
6. 对象通过句柄访问；句柄检查 owner、generation 和 rights。
7. 能力位反映真实构建能力，不得只表示“计划支持”。
8. 结构体使用稳定布局，扩展字段只能追加，并采用 size/version 协议。
9. ABI 错误码新增需评审；不要把 I/O 错误伪装成参数错误。
10. 更新 `user/runtime`、ABI 文档、机器可读登记、内核测试和用户程序测试。

## 6.3 系统调用候选族（不预分配编号）

| API 族 | 候选接口 | 对应命令域 |
|---|---|---|
| 文件 | open/read/write/seek/stat/readdir/create/unlink/rename | 文件命令 |
| 目录 | mkdir/rmdir/opendir/readdir | 目录命令 |
| 进程 | process_snapshot/process_wait/process_signal/process_info | ps/kill/jobs |
| 线程 | thread_info/thread_yield/thread_sleep/thread_set_priority | top/schedstat |
| 内存 | memory_info/address_space_query/vmo_create/map/unmap | free/pmap |
| IPC | channel_create/send/recv/event_wait/pipe_create | Shell 管道/服务 |
| 时间 | clock_get/clock_set/timer_create/sleep | date/uptime/sleep |
| 设备 | device_enumerate/device_open/device_control | lspci/lsdev/devctl |
| 网络 | netif_list/socket/bind/connect/send/recv/route | ip/ping/curl |
| 用户安全 | credential_get/access_check/audit_read | whoami/id/auditlog |
| 服务 | service_list/start/stop/status | service |
| 日志 | log_read/log_subscribe/crash_read | dmesg/journalctl/crashctl |

这些是接口族，不是已批准的 ABI 编号或最终签名。应在真实调用者出现时按 ADR 设计。

---

# 7. 推荐仓库结构演进

当前仓库是单个 `aurora-kernel` crate 加 `user/hello`、`user/probe`、`user/shell` 产物 crate。当前 `module-interfaces.toml` 和 `crates.toml` 是机器可读登记来源。不要立即按理想树大规模搬迁。

## 7.1 目标结构（分阶段形成）

```text
aurora-os/
├── boot/
├── kernel/
│   └── src/
│       ├── arch/x86_64/
│       ├── boot/
│       ├── memory/
│       ├── sched/
│       ├── process/
│       ├── ipc/
│       ├── capability/
│       ├── syscall/
│       ├── driver/
│       ├── device/
│       ├── storage/
│       ├── filesystem/
│       ├── network/
│       ├── input/
│       ├── display/
│       ├── console/
│       ├── security/
│       ├── time/
│       ├── power/
│       ├── diagnostics/
│       └── init/
├── user/
│   ├── runtime/
│   ├── shell/
│   ├── coreutils/
│   ├── procutils/
│   ├── sysutils/
│   ├── netutils/
│   └── services/
├── crates/                 # 仅在真实接口稳定后逐步拆 crate
├── tools/
├── docs/
│   ├── design/
│   ├── adr/
│   ├── architecture/
│   ├── interfaces/
│   └── testing/
└── tests/
```

## 7.2 文件/模块迁移规则

- 先在现有文件中定义并验证接口，再决定是否拆目录或 crate。
- 新模块先登记 `module-interfaces.toml`，并按现有门禁维护依赖边。
- 新 crate 必须同时登记根 `Cargo.toml` 和 `docs/architecture/crates.toml`。
- 接口变更必须同步 ADR、依赖矩阵和测试目标。
- 不为了目录看起来整齐而搬动稳定代码。
- 先消除真实依赖，再拆 crate；避免把现有 11 模块 SCC 简单改名或包装成更多空壳。

---

# 8. 端到端架构依赖矩阵

| 命令/能力 | 必须依赖的内核/服务接口 | 必须先完成的里程碑 |
|---|---|---|
| `pwd`/`cd` | 当前工作目录状态 | Shell Runtime / Path |
| `ls` | VFS 路径解析、目录读取 | FS-02 |
| `cat` | 文件句柄读取 | FS-03 |
| `touch`/`mkdir` | 文件创建/目录创建 | FS-04/05 |
| `cp`/`mv`/`rm` | 读写/rename/unlink | FS-05 |
| `df`/`du` | filesystem statfs/目录遍历 | FS-09 |
| `ps` | 安全进程快照 | PROC-02 |
| `kill` | 进程控制能力 | PROC-03 + Security |
| `free` | 内存统计快照 | MEM-02 |
| `top` | 进程快照 + CPU 时间统计 | PROC-02 + TIME-02 |
| `lspci` | PCI 只读枚举接口 | DEV-02 |
| `ip` | 网络接口/地址/路由对象 | NET-04 |
| `ping`（网络） | ICMP socket/raw capability | NET-03 |
| `date` | realtime clock + timezone | TIME-02 |
| `uptime` | monotonic clock + boot time | TIME-01 |
| `dmesg` | 有界日志读取接口 | DIAG-02 |
| `journalctl` | 持久化日志服务 | DIAG-04 + FS write |
| `service` | init/service manager IPC | INIT-02 + IPC |
| `pkg` | FS write + signature + network + transaction | PKG-01~05 |
| Shell `|` | pipe/channel IPC | IPC-02 |
| Shell `>`/`>>` | 文件打开标志、write、append | FS-04 |
| 外部命令 | ELF loader + process start + argv/env/stdio | USER-02 |

---

# 9. 工程实施路线图

必须按依赖关系推进。建议将路线分为基础内核、系统服务、命令工具、生态能力四个大阶段。

## 阶段 A：基础内核与用户程序运行环境

> **实施记录（2026-11-17，按代码与判定表实测更新；本表是"做到哪了"，不改上面的验收句）**
>
> | 阶段 | 状态 | 依据 |
> |---|---|---|
> | A0 基线 | ✅ | `check` 17 道门禁、判定表整链可复现；配方记在 COORD.md §8 |
> | A1 VFS/文件系统 | 部分 | FS-01~FS-10 的**读方向**已交付（ADR-108/109）；写方向由 qoder 推进（ADR-110/111，`fs-rw`） |
> | A2 用户运行时 | ✅ 前后两半都落地 | `user/runtime` 库 + argv 区/std 句柄/退出码（ADR-130）；判定行 `A2 argv/std…`、`A2越界argv…` |
> | A3 Shell 解析器与外部命令 | ✅ 解析器与 `run` 已落地，交互判据待量具 | 解析器/注册表（A3 首片）、**用户态装载器**（ADR-131，判定行 `A3 用户态装载器执行卷上ELF`）、shell `run <path>`；交互端到端被 `t_fs_open_ring3` 的 160 ms 窗口挡住（原因见 ADR-131 补记） |
> | A4 进程观测 | ✅ 四条命令全部落地（`ps`/`free`/`top`/`kill`） | ADR-132：27 号枚举 + 28 号统计 + 按 AS 的映射页计数；用户态 `rt::proc_enum/proc_stat` 与 shell 的 `ps`/`free`；ADR-133：shell `top`（27 号第二个调用方，pages 降序 + 19 号薄壳 `rt::sleep_ms` 定时，纯用户态内核零改动）；ADR-134：shell `kill <pid>`（**29 号** `SYS_PROC_KILL_BY_PID`，pid 只寻址、授权靠调用者名下的 `RIGHT_WRITE` Proc 句柄，内核反查后走与 18 号同一实现）；判定行 `A3 shell执行argv命令并ps/free读数`（argv `run/ps/free/top 2; kill 9999`，串口原文见 ADR-132 §决策 5、ADR-133 §验收、ADR-134 §落地） |
>
> 三条与上表配套的事实：① `ps`/`free`/`top`/`kill` 均有真实数据（27 号的聚合）；
> `kill` 走 29 号，capability 语义不变（ADR-134）；
> ② `run` 的退出码显示路径已实现但缺"会自己退出的样例命令"（卷上的 hello 是内核探针，不写 FLAG_EXIT 就自旋）；
> ③ 重定向/管道/`ls -lah` 属 A3 的后续片，尚未开始（A3 验收句的 `ls/cat/grep` 那半未达成）。

### A0：仓库与现状基线冻结

- 核对 HEAD、开发手册 V1.2、BACKLOG、ADR 和 feature matrix。
- 跑现有 `python tools/aurora.py check`、`test`、`run` 中适用的完整基线。
- 保存串口日志、QEMU 配方、测试矩阵、性能基线。
- 建立本总文档与各专项设计文档的索引。

**验收：** 不修改产品代码也能复现现有基线；记录实际通过数和未完成项。

### A1：VFS 与文件系统（承接 FS-01~FS-10）

- VFS 数据模型与路径解析。
- FAT16/FAT32 目录遍历与 LFN。
- 用户文件 API。
- FAT 写入、创建、删除、重命名。
- mount/umount 与文件系统统计。
- 第一批 Coreutils。

**验收：** 创建、写入、复制、重命名、删除、重启后读回的持久化闭环。

### A2：用户运行时与外部命令执行

- 建立 `user/runtime`。
- 统一 syscall 封装、错误码、句柄和 I/O。
- 定义 `StartupInfo` 扩展策略。
- 程序装载参数 argv/envp。
- 标准输入/输出/错误句柄继承。
- 程序搜索路径 PATH。
- 退出码、wait、父子进程关系。

**验收：** Shell 能运行独立 ELF 命令程序；命令输出和退出码返回 Shell。

### A3：Shell 解析器与基础命令

- Lexer。
- Parser。
- 参数与选项解析。
- 内置命令注册。
- 外部程序执行。
- 退出码。
- history、补全。
- 重定向和管道分阶段实现。

**验收：** `ls -lah /`、`cat file`、`echo hi > file`、`cat file | grep hi` 在真实文件系统上工作。

### A4：进程管理与系统观测 API

- 进程/线程快照对象。
- 资源统计。
- 进程等待和控制。
- 进程优先级/亲和性策略。
- 安全的用户态查询接口。

**验收：** `ps`、`top`、`kill`、`free` 有真实数据，不直接暴露内核结构。

## 阶段 B：设备、网络与系统服务

> **实施记录（2026-11-18，按代码与判定表实测更新；本表是"做到哪了"，不改上面的验收句）**
>
> | 阶段 | 状态 | 依据 |
> |---|---|---|
> | B1 设备模型 | 部分（`lspci` 已达成） | PCI ECAM/CAM 枚举 `pci.rs`、统一 `DriverCtx`、AHCI 错误恢复、virtio 设备表（ADR-030/112）；ADR-136 新增 **31 号 `SYS_PCI_ENUM`**（内核判据 `t_pci_enum` 七格全绿 + 变异证红）与 shell `lspci`（判定格 `_lspci_rows`，变异证红；q35 实测 6 台真实数据）；**缺** Device/Driver trait、设备树、`lsdev`/`devctl`（B1 后续片） |
> | B2 网络协议栈 | 部分（只到以太网帧 + 单次 DHCP） | virtio-net + 手搓 Ethernet 实验帧 + DHCP DISCOVER 回包解析（ADR-032，判定行 网卡第一帧/第一条协议往返）；**缺** ARP/ICMP/TCP/Socket API/路由/DNS 与 `ip`/`ping` 命令 |
> | B3 时间电源 | 部分（`uptime` 已达成） | TSC/PIT 标定、LAPIC/PIT 定时器、健康标记、停机（ADR-036）；ADR-137 新增 **启动锚点 + 32 号 `SYS_CLOCK_UPTIME`**（内核判据 `t_clock_uptime` 四格 + 变异证红）与 shell `uptime`（判定格 `_uptime_row`，变异证红）；**缺** 墙钟/RTC/时区（`date`）、`sleep`/`service`/ACPI 电源/重启 |
> | B4 日志诊断 | **`dmesg` 已达成** | 环 4096B + 整行规则、持久日志尾、crash dump V2 及 3 条既有判定行；ADR-135 新增 **30 号 `SYS_LOG_READ`**（内核判据 `t_log_read` 十格全绿 + 变异证红）与 shell `dmesg`（判定格 `_dmesg_repeats`：表头后首行必须在表头前出现过 ⇒ 真打了一遍内核日志；变异证红已做）；`journalctl` 未做 |
>
> 与上表配套的事实：① B 阶段四片里 B4 已把**内核底座 + 判据 + 用户态出口**三件都凑齐
> （环、持久尾、dump、30 号、`dmesg`），其余三片仍要先建设备树 / 协议栈 / 电源状态机；
> ② 新增的两个调用号 **29（kill）/ 30（log_read）** 均已按"先裁决、后实现、再登记"走完
> （总设计 §2.1、`module-interfaces`、unsafe 白名单/审计表同步）；
> ③ 本阶段曾把 `dmesg` 误判成「输出为零」（量具骗人，复盘见 BACKLOG §398）；
> 纪律已补：判据不能用「看起来像」来定位。

### B1：设备模型完善

- 统一 Device/Driver API。
- PCI 设备树与能力句柄。
- 驱动匹配和生命周期。
- DMA/IOMMU 安全映射。
- 设备状态和错误恢复。
- 块设备/网卡/输入设备纳入统一模型。

**验收：** `lspci`、`lsdev`、`devctl status` 读取真实设备对象。

### B2：网络协议栈

- VirtIO-net 或选定网卡驱动。
- Ethernet。
- ARP。
- IPv4。
- ICMP。
- UDP。
- TCP。
- Socket API。
- 路由、DNS、DHCP。

**验收：** `ip link`、`ip addr`、网络 `ping`、UDP/TCP 客户端可在 QEMU 网络环境运行。

### B3：时间、电源与系统服务

- monotonic/realtime clock。
- RTC 与时区。
- ACPI 电源状态。
- 关机/重启。
- init/service manager。
- 服务 IPC 与健康状态。

**验收：** `date`、`uptime`、`sleep`、`service status`、`reboot`/`poweroff` 有实际效果。

### B4：日志与诊断服务

- 统一日志记录。
- 用户态日志接口。
- 持久化日志。
- Crash dump 导出。
- Trace 与性能计数。

**验收：** `dmesg` 可读内核日志，`journalctl` 可查询持久化记录，崩溃 dump 可导出并校验。

## 阶段 C：系统安全与管理工具

### C1：身份与权限模型

- 用户凭据对象。
- UID/GID 或 Aurora 原生身份标识。
- capability 与身份映射。
- 文件/设备/进程访问策略。
- ACL（如确有需求）。
- 登录会话与审计。

**验收：** 不同用户访问同一资源产生可验证的授权差异；`whoami`、`id`、`passwd` 按策略工作。

### C2：软件包与系统更新

- 包清单和版本。
- 包签名与哈希。
- 依赖关系。
- 文件安装事务。
- 卸载和回滚。
- A/B 更新状态。
- 启动健康标记。

**验收：** 安装、升级、失败回滚、重启后验证都可重复。

### C3：磁盘管理与恢复工具

- 磁盘/分区只读查询。
- 分区创建/删除（先有备份和保护机制）。
- 文件系统检查工具。
- 离线恢复环境。
- 镜像备份与恢复。

**验收：** 在测试镜像上可恢复已知故障；不允许对宿主机真实磁盘做默认写操作。

## 阶段 D：外设、桌面和生态

### D1：USB Host 与 HID
### D2：音频设备与混音
### D3：稳定显示 API、合成器与桌面会话
### D4：应用 SDK、开发工具和包生态
### D5：硬件兼容矩阵、安装器和正式发行

这些阶段不阻塞基础 CLI 操作系统，但决定后续桌面化和商业化能力。

---

# 10. 第一版产品命令范围（建议冻结）

不要把第五章的全部长期命令都当成第一版范围。建议先定义“第一版可用命令集”。

## 10.1 Shell 内置（第一版）

```text
help
exit
echo
pwd
cd
clear
history
abi
version
```

## 10.2 第一版文件命令

```text
ls
cat
touch
mkdir
rmdir
cp
mv
rm
stat
file
find
grep
head
tail
wc
df
du
```

`find/grep/head/tail/wc` 可先在用户态基于读取 API 实现；`df/du` 依赖 statfs/目录遍历。

## 10.3 第一版系统命令

```text
uname
arch
ps
free
meminfo
lspci
lsdev
dmesg
date
uptime
reboot
poweroff
```

未完成对应 API 的命令先不加入正式 help 输出；可以在开发构建中通过 `help --all` 显示“规划中/未启用”，但不得伪装可用。

## 10.4 第一版网络命令（后续启用）

```text
ip
ping
ss
hostname
nslookup
```

注意：当前 Shell 的 `ping` 是内核 ABI 探针命令，不应直接沿用为网络 ping 的最终实现；网络 ping 应明确其网络协议语义。

---

# 11. 测试、质量与验收制度

## 11.1 每个系统域必须有四类测试

1. **单元测试：** 数据结构、解析、状态机、错误码。
2. **内核集成测试：** syscall、句柄、资源、并发、权限。
3. **用户态端到端测试：** 命令真实调用内核能力。
4. **负样本/故障注入：** 非法指针、越界、资源耗尽、I/O 失败、权限不足、设备失联。

## 11.2 命令完成的定义

一条命令只有同时满足以下条件才可标记“已完成”：

- 命令可被 Shell 正确解析。
- 参数和选项有明确语义。
- 使用真实用户空间 API。
- 对应内核能力已实现。
- 正常场景测试通过。
- 不存在/权限不足/参数错误/资源不足等异常有明确输出。
- 不会因用户输入导致内核 panic。
- 有集成测试证明端到端路径。
- help/man 文档与实际行为一致。

## 11.3 回归要求

每个 PR/里程碑至少执行：

```bash
python tools/aurora.py check
python tools/aurora.py test
```

并按改动范围执行：

```bash
python tools/aurora.py build
python tools/aurora.py run
python tools/aurora.py bench
```

具体参数以当前 `tools/aurora.py --help` 和仓库开发手册为准。不得因新功能而删除旧测试、放宽旧判据或把“未注册的测试”计为通过。

## 11.4 每个里程碑交付模板

```text
Milestone: OS-XX / 子任务编号

1. 目标
2. 现状与证据
3. 设计决策 / ADR
4. 新增文件
5. 修改文件
6. 接口与 ABI 变化
7. 模块依赖登记变化
8. 正向测试
9. 负样本
10. QEMU/真机验证
11. 回归结果
12. 未完成项
13. 下一里程碑准入条件
```

---

# 12. 安全、可靠性与故障隔离

## 12.1 故障域

| 故障对象 | 期望处置 |
|---|---|
| 普通命令参数错误 | 返回用户可读错误，不影响其他命令 |
| 用户程序非法内存访问 | 终止该用户任务，回收其资源 |
| 单个服务异常 | 由服务管理器按策略重启或进入降级状态 |
| 单个设备故障 | 隔离设备/驱动，记录错误，不影响无关设备 |
| 单个文件系统卷损坏 | 卷级失败/只读保护，不破坏其他卷 |
| 内核可恢复资源错误 | 返回明确错误，释放已取得资源 |
| 内核不变量被破坏 | 记录现场，进入致命故障路径 |

宏内核中模块接口隔离不等于运行时故障隔离。真正的驱动故障域隔离需要用户态驱动、IOMMU 和受控 IPC，必须在后续阶段明确建设。

## 12.2 禁止事项

- 不把 Shell 命令直接放进内核。
- 不允许用户态直接读写任意物理地址/端口。
- 不允许任意用户进程读取全局内核对象表。
- 不允许 syscall 接受未校验用户指针。
- 不允许使用用户提供长度直接申请任意内核内存。
- 不允许静默吞掉块设备、网络和文件系统 I/O 错误。
- 不允许把未支持操作伪装成成功。
- 不允许新增 ABI 号而没有真实调用者和测试。
- 不允许未经 ADR 改动已采纳架构决策。

---

# 13. 开始写代码前的任务拆分

建议第一轮不是立刻实现几十条命令，而是将总工程拆成可合并的工作包。

## WP-00：基线核对

交付：当前 HEAD、check/test/run/bench 结果、现有 ADR 冲突清单、功能状态矩阵。

## WP-01：模块能力地图

交付：每个系统域的 owner、当前源文件、对外 API、调用者、测试目标、未完成项。

## WP-02：用户运行时

交付：统一 syscall 封装、错误码、标准句柄、用户字符串/缓冲 API、ABI capability 查询。

## WP-03：VFS/FS

交付：文件系统专项设计和 FS-01 开始实施。

## WP-04：进程管理 API

交付：进程快照、wait/exit code、程序 argv/env、标准句柄继承设计。

## WP-05：Shell Parser

交付：Lexer/Parser/Executor 的纯用户态实现和宿主机可测用例。

## WP-06：Coreutils

交付：ls/cat/pwd/cd/touch/mkdir/cp/mv/rm/stat 等真实命令。

## WP-07：系统观测 API

交付：process/memory/device/log/time 快照接口及 ps/free/lspci/dmesg 等命令。

**并行边界：** WP-01 可与设计评审并行；WP-02 与 WP-03 可并行做接口设计，但运行时文件 API 依赖 FS/ABI 决策；WP-05 的纯 Lexer/Parser 可独立开发；WP-06 必须等真实 API 稳定。不得让多个 Agent 同时修改 `user.rs`、`main.rs`、ABI 号表或模块登记表而不指定唯一集成负责人。

---

# 14. 推荐的实际编码顺序

按照“先让系统能运行程序，再让程序能管理系统”的原则：

1. 冻结当前源码基线和现有测试结果。
2. 完成文件系统 VFS 接口与目录只读能力。
3. 完成用户态 Runtime 最小版本。
4. 完成文件/目录系统调用和安全句柄语义。
5. 完成 FAT 写入与持久化闭环。
6. 完成第一批 Coreutils。
7. 完成外部 ELF 命令执行、argv/env/stdio。
8. 完成 Shell Lexer/Parser/Executor。
9. 完成 pipe 和重定向。
10. 完成进程快照、wait、kill 和 `ps/top`。
11. 完成内存、设备、日志、时间只读诊断 API 与命令。
12. 完成网络栈和网络命令。
13. 完成 init/service manager。
14. 完成用户身份与权限管理。
15. 完成软件包和更新工具。
16. 完成 USB、音频、桌面和 SDK 生态。

这条路线不是说网络、GUI 不重要，而是文件、程序执行、Shell、进程管理是命令行操作系统最核心的闭环。

---

# 15. 项目治理与变更规则

1. `BACKLOG.md` 记录实测事实、欠账和下一步，不把推测写成完成状态。
2. `docs/adr/` 记录架构决策；已采纳 ADR 不回写历史结论。
3. `docs/architecture/module-interfaces.toml` 是模块接口/依赖的机器可读基线。
4. `docs/architecture/crates.toml` 与 Cargo workspace 双向登记 crate。
5. 新增命令必须登记其依赖 API、权限要求和测试目标。
6. 新增 syscall 必须同步 ABI 版本/能力位、用户运行时、内核测试、文档和负样本。
7. 新增设备必须登记设备资源、DMA/IRQ、错误处置和驱动生命周期。
8. 新增后台服务必须定义启动、停止、健康检查、重启和关机顺序。
9. 任何跨模块接口变更先检查依赖方向和锁序。
10. 不能为“完成命令数量”牺牲稳定性、可验证性和真实数据路径。

---

# 16. 总结与立项结论

Aurora OS 的完整建设不只是文件系统和 Shell，而是至少包含：

- 启动与体系结构；
- CPU、中断、定时器；
- 内存管理；
- 进程、线程、调度和同步；
- IPC、句柄和 capability；
- 系统调用与用户运行时；
- 文件系统与块存储；
- 设备与驱动；
- 控制台、输入和显示；
- 网络协议栈；
- 用户身份、安全与审计；
- 时间、电源、日志和诊断；
- init 与服务管理；
- 软件包、更新和恢复；
- Shell、Coreutils、开发工具和应用生态。

**正式建议：以“命令行可用的通用操作系统”为第一个产品里程碑。**

第一阶段优先完成：VFS/文件写入、用户 Runtime、外部程序执行、Shell Parser、Coreutils、进程管理与系统诊断命令。网络、服务管理、身份、安全增强和包管理随后推进；USB、音频和完整桌面生态放到后续阶段。

最终验收标准不是“Shell 里能输入很多命令”，而是：每条命令都由真实的用户空间程序实现，通过稳定 ABI 访问内核对象，具备明确权限和错误语义，并且有可重复的端到端测试。

---

**文档结束**  
**下一执行入口：WP-00 基线核对 → WP-01 模块能力地图 → WP-03 FS / WP-02 Runtime 接口评审。**
