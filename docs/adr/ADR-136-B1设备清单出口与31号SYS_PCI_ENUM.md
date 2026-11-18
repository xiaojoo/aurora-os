# ADR-136：B1 设备清单出口——31 号 `SYS_PCI_ENUM` 与 shell `lspci`

状态：采纳（2026-11-18，证据来源 / 总设计阶段 B1 / 使用者裁决新增 31 号）
**内核侧已交付并进判定行**（`t_pci_enum` 七格全绿 + 变异证红）；
**shell 侧 `lspci` 已接线并进判定行**（`_lspci_rows`，变异证红）。
关联：手册 §4.1（PCI 枚举）、ADR-030/112（DriverCtx 与 virtio 设备表）、
ADR-132（27/28 号 proc_enum/stat，本号的形状母本）、总设计
《Aurora-OS-完整操作系统架构与Shell命令体系建设总设计-V1.0》§阶段 B1
（验收句 `lspci`、`lsdev`、`devctl status` 读取真实设备对象——本片交付 `lspci` 那一半）

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计；发现冲突先记差异，
> 不要为了让文档一致去改已经验证的结论。每条结论标「实测」或「推断」。

## 背景

总设计阶段 B1 的验收句是"`lspci`、`lsdev`、`devctl status` 读取真实设备对象"。
开工前的基线盘点结论：内核侧 PCI 清单**早已齐了**——`pci::info()`（后端/条数/截断/
缺席计数）与 `pci::dev(i)`（bdf/vendor/device/cfg08/hdr/bar0），启动时扫好放进
只读快照表（`TABLE`，BSP 单写、之后全读）；`ktests/driver.rs` 已有大量判据
（IRQ caps 三态、MSI/MSI-X 解析、BAR 尺寸/对齐、两台挑对）。

缺的只是**用户态出口**：没有任何办法把这份清单拿到 ring3。

⇒ 使用者裁决：**新增 31 号 `SYS_PCI_ENUM`**（23 占、29 kill、30 log_read 已用）。

## 决策

### 决策 1：形状照抄 27 号 `proc_enum`，无 capability

`pci_enum(buf, cursor, len) -> (next<<32)|n`：32 字节定长记录、`APC1` 魔数、
游标分页、`(next<<32)|n` 返回——与 27 号同族，用户侧 runtime 独立声明同一组偏移。

**无 capability 要求**：PCI 表是启动设施（与 `serial::RING` 同级），不是某次申请
的资源；谁都能读清单不构成权限提升（清单里没有可操作的句柄）。但仍要求调用者
有**任务身份**（与 27 号同口径）——`current_identity().is_none() ⇒ -5`。

记录布局：`bdf@8、vendor|device@12、cfg08@16、hdr@20、bar0@24`，`0..6` 是
魔数/版本/kind，**长度字段在 6..10 且与 bdf 共用 8..10 两字节**——这是 27 号
`proc_enum_record` 的既有形状（user.rs:1515/1516 同位），用户侧按 16 位读。
判据也按同一口径核（初版判据读满 4 字节对 32，实测红在"魔数自洽"，
按 16 位口径修绿）。

### 决策 2：`lspci` 十进制输出，每台一行

shell 只有十进制打印（`put_u64`），十六进制属后续片。每台一行
`bus dev func vendor device class`（全十进制、空格分隔）。
判据用**结构性形状**（六数字行 × ≥2 行），不依赖任何具体 vendor/device 值，
换 QEMU 机型也成立。

### 决策 3：判据放内核 + shell 两处

内核 `t_pci_enum` 七格：① 全量（`n == info.n && next == 0`）
② **与内核表逐字段一致** ③ 魔数/版本/记录长自洽 ④ 游标续读
（容量只够 1 条 ⇒ `n=1 && next=1`；从 `next` 续读拿到其余且归 0）
⑤ `len < 32` ⇒ `-3` ⑥ `len > COPY_MAX` ⇒ `-3` ⑦ 只读页 ⇒ `-2`。

**为什么 ② 不违反"别拿被测物自己对账"**：31 号走 syscall→记录打包→copy_to_user
→用户缓冲→`copy_from_user` 读回这条**长路径**，每一环都可能错位/丢字段；
`pci::dev(i)` 是**直读表**的另一条路径。两条路径共享的只有源数据本身
（启动扫好的 TABLE）——这与 logread 初版的"recent_tail 自己对账自己"不同，
那一条连源读法都是同一份函数。

**变异证红**（已做）：把记录里 bdf 写错位（`d.bdf ^ 0x100`）⇒ ② 格红 ⇒ FAIL(35)；
还原 ⇒ 七格全绿。

shell 判定格 `_lspci_rows`：回显后首行必须六数字、且再跟一行同形状。
**变异证红**（已做）：在行尾追加非数字词破坏形状 ⇒ `False`；还原 ⇒ `True`。

## 落地时撞到的两件事（实测）

1. **`syscall_abi` 的参数位次**（本片最大坑）：31 号内核读 `r10` 当 len，
   runtime 初版把 `buf.len()` 传到了第 3 位（映射 `rdx`）⇒ 内核见 `r10=0` ⇒
   `-3`（E_TOO_LONG），shell 打出 `-3`。`syscall_abi(nr, a1, a2, a3, a4)` 的
   第 4 位才映射 `r10`。修法：`syscall_abi(SYS_PCI_ENUM, ptr, cursor, 0, len)`。
   教训：**27 号同族的 len 永远走 r10**（`SYS_PROC_ENUM` 的注释里就写着），
   新号照抄形状时连参数位次也要照抄。
2. **判据的长度字段口径**：照 27 号抄记录布局时，长度字段与 bdf 共用 2 字节；
   初版判据按 32 位读 ⇒ 红。按 16 位口径核（与 27 号用户侧一致）⇒ 绿。

## 备选方案

1. **不加号，`lspci` 只在内核 ktest 打**：B1 验收句是**命令**读真实设备对象，
   不进用户态就不算。不选。
2. **把 PCI 表做成 VMO 预映射**：零新号但要动装载路径与 VA 布局，风险高于一个号。
   不选。
3. **31 号返回文本行**而不是定长记录：解析权应在调用方（27 号同族的先例），
   文本行会让宿主机判据绑死格式。不选。

## 影响

正面：用户态第一次有了 PCI 清单的合法通路；`lspci` 是 B1 三条命令里第一条
有真实数据进判定行的。

负面：`lsdev` / `devctl status` 未做（前者要 Device/Driver trait 先落地，
后者要设备控制通道，都是 B1 后续片）；31 号一次最多 `COPY_MAX/32 = 128` 条，
`MAX_DEVICES = 64` ⇒ 单次全量够用，无翻页压力。

## 验收与负样本

- 内核侧：`t_pci_enum` 七格，`handles` 档全绿（PASS 33）；
  变异证红（bdf 错位 ⇒ 红还原绿）。
- shell 侧：`lspci` 进 a3 判定行（`_lspci_rows`），变异证红（破坏行形状 ⇒ 红）。
- `check` 17/17（unsafe runtime U5 39→40、census 470→471；
  module-interfaces 登记 **sched→pci** 依赖边与 pci 的 `allowed_callers += sched`）。

## 迁移与回滚

31 号是**新增号**，回滚 = 删常量/分派/实现 + `t_pci_enum` + runtime 封装 +
shell `cmd_lspci`，互相可分步撤。`lspci` 未进判定行时撤它不影响任何既有判据
（现在进了：撤它要先撤 `_lspci_rows` 那一格）。

## 未决

1. **`lsdev` / `devctl status`**：前者要统一的 Device/Driver trait（B1 的
   "统一 Device/Driver API"那半），后者要设备控制通道。都是 B1 后续片。
2. **PCI 子树（桥后设备）**：今天的扫描只下到 `hdr & 0x80` 的多功能位，
   **不下桥**（hdr type 1 的 PCI-PCI 桥不递归）。本机 QEMU q35 的设备都在
   bus 0，判据不咬；真机上有桥后设备时要补递归扫描（记在 B1 欠账）。
3. **十六进制输出**：`lspci` 目前全十进制，十六进制要给 shell 加 `%x` 打印
   （`put_u64` 的兄弟）。纯显示层，属后续片。
