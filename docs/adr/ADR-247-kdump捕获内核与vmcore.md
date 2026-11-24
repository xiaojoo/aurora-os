# ADR-247：kdump 风格捕获内核、crash-only AHCI 与 vmcore

状态：**已采纳**（2026-11-24；已落地，`kdump` 特性门控，真机未验证）。使用者批准阶段 1+2+3 一次推进。

关联：ADR-031（持久状态区）、ADR-042（崩溃现场）、ADR-080/115/116（验签边界）、
ADR-190/214/215/222（块层与 AHCI 锁）、ADR-245（宿主栈生命周期）、BACKLOG §569。

## 目标

把 L4 从普通内核的锁、堆和文件系统栈中彻底移出：

1. 每 CPU 先保存现场并进入隔离捕获上下文；
2. AP 由 NMI 停车，leader 使用预初始化 crash-only AHCI 资源；
3. 跳转独立 capture kernel，由其生成并写出 vmcore；
4. 任一阶段失败只保留串口/内存快照并停机，不再级联。

## 阶段 1：捕获上下文

- 新增 per-CPU 静态 capture 栈，生命周期为整个内核，不归任何任务所有。
- 异常 Fatal 在 `trap::aurora_trap_entry` 进入捕获入口；软件 L4 由 `exit::finish`
  进入同一入口。入口先 `cli`，保存现场到每 CPU `SNAPSHOTS`，再切 capture 栈。
- 快照由 `CaptureBootInfo` 的版本/长度/校验和绑定，保留现有 `FATAL_RECORD` 八格布局不变。
- 每 CPU 先发布 `CAPTURE_ENTERED`，leader 用 CAS 选出；向在线 AP 发 NMI。
- NMI/IST2 极小桩只保存寄存器、发布 `CAPTURE_PARKED`、`cli+hlt`，不取锁、不打印。
- 不等待不可靠回执；未停车 AP 只记录原因，禁止进入阶段 2 写盘。

## 阶段 2：crash-only AHCI

- AHCI 初始化后预留独立 `CaptureIo`：命令槽、命令表、PRDT、RxFIS、DMA 数据区、
  MMIO 别名和端口号。资源在整个内核生命周期内不回收、不共享。
- 写盘前必须证明 `PxCI == 0 && PxSACT == 0`，且所有运行 AP 已停车。
- 专用路径不取 `XFER/HEAP/VMM/RUNQ`，不分配，不调用 `boot_port/enumerate/recover`。
- 只做一次 capture 记录写；完成、字节数、状态校验失败写原子原因后停机。
  实施为**一份 2 MiB vmcore 分块写、无重试**；每块要求新 D2H 回执、TFD 与完整 32 位 PRDBC 一致。

## 阶段 3：第二内核与 vmcore

- 新增 `aurora-capture` no_std 二进制，独立链接脚本，固定虚拟基址
  `0xffffffff_c000_0000`，物理载荷由主内核启动时预留并拷贝。
- 主内核在 PMM 初始化阶段预留 8 MiB 连续物理区，排除普通分配（32 MiB 在本机 memmap
  下找不到连续块，已实测收紧）；在 kernel PML4
  建立 capture VA→PA 映射，并缓存物理基址。
- capture kernel 接收 `CaptureBootInfo`，建立最小独立页表（自身镜像 + HHDM + AHCI
  MMIO），切 CR3 后只使用自己的代码、栈和预初始化资源。
- vmcore 使用 ELF64：`PT_NOTE` 包含 `NT_PRSTATUS`（每 CPU 寄存器）与 Aurora
  `NT_AURORA_CAPTURE`（控制寄存器、向量、CR2、来源、校验）；物理内存段来自启动时
  缓存的 E820/Limine memmap 快照。
- capture 写盘布局新增 `KIND_CAPTURE`，不改变 V1/V2 解码；宿主读取器独立校验 ELF、
  note、段范围和寄存器。
  **实施修正**：不新增 `KIND_CAPTURE`，而是使用 AHCI 口 1 的专用 raw 捕获盘，LBA 0 起写
  2 MiB ELF64 vmcore；既有 V1/V2 状态区完全不变。这样 capture 口可与普通块传输彻底隔离。

## 安全与失败边界

- 捕获路径禁止分配、禁止普通锁、禁止未知回调、禁止恢复式重试。
- NMI 嵌套、APIC 失效、用户 CR3、坏 RBP、DMA≥4GiB、端口非静止、超时、坏完成、
  capture 载荷校验失败、第二内核切换失败都必须留下原子原因并以 39 停机。
- 验签/身份/槽位仍受 ADR-080/W5/W12 约束；kdump 不宣称安全启动。

## 实施记录（2026-11-24）

- 主内核 `kernel/src/capture.rs`：每 CPU 16 KiB static capture 栈、无锁快照、leader CAS、
  NMI/IST2 停车；`Site`/`TrapFrame` 在切栈后复制。软件 L4 经启动期安装的函数指针进入，
  避免 diagnostics→integration 新环。
- `capture/`：独立 no_std 第二内核，固定 VA `0xffffffffc0000000`；前 64 KiB 文本 RX，
  后续数据 RW/NX，64 KiB 栈位于 256 KiB DMA 区之前。BootInfo 校验按字段序列计算，
  排除 repr(C) 填充；payload 长度、入口标记与 FNV 校验都过才切独立 CR3。
- AHCI 口 1 在普通枚举前接管：命令环/RxFIS/DMA 常驻，启动期用一条 255 扇区写命令预检，
  证明命令可发射且 PRDBC/D2H/TFD 三本账一致；普通传输随后拒绝再碰该口。
- vmcore 是**稀疏 ELF 元数据**：`ET_CORE/EM_X86_64`、`PT_NOTE`、标准 336 字节 x86-64
  `NT_PRSTATUS` 与 Aurora 私有 note；`PT_LOAD` 用 `p_filesz=0` 描述物理区间。
  文件本身不含 512 MiB 物理内存内容，内容需宿主 QMP/`pmemsave` 第二台仪器另取。
- `tools/aurora.py` 在 kdump 构建前生成 payload，并在 `run` 后用独立 Python 解析器校验
  ELF、note 校验和、CPU/停车数、PRSTATUS 与 Aurora note 一致性、段范围和写入字节数。

## 实测

| 场景 | 读数 |
|---|---|
| `kdump,fault-lock-reentrant` | 首条 L4 后无第二条锁序违规；单核 vmcore 2 MiB，宿主对账绿 |
| `kdump-ap-probe` | 4 CPU、AP 停车 3/3、38 个 PT_LOAD、2 MiB，宿主对账绿；同 ELF 两跑均绿 |
| `kdump,fault-shootdown-noack` | VMM shootdown L4 后停车 3/3，无 HEAP→GROW 级联，vmcore 绿 |
| `kdump,fault-crash-oops` | note `vector=14`、`CR2=0xffffc00000000008`，与注入常量一致 |
| 坏 payload / DMA / 完成 / AP 停车 | 分别红在校验和、DMA 下界、PRDBC、停车 0/3；均未写 vmcore |
| 宿主篡改 | Aurora note 校验和、PT_LOAD 范围、PRSTATUS RIP 三类变异全部精确变红 |
| 提交前捕获口隔离补证 | `run-12937` 去掉入口闸后读/两种写全部穿透并破坏命令环，精确红；`run-12939` 恢复后三拒全 true、kdump ktests **92/92** |
| 提交前四核捕获复验 | `run-12940`：4 CPU、停车 3/3、38 PT_LOAD、2 MiB、宿主对账绿，退出 39 |

提交前审查还发现 `write_lba/write_bytes` 曾绕过 `transfer` 的捕获口检查；现将隔离闸上移到
所有普通读写共用的 `with_transfer_lock(num, ...)`，并让 AHCI 认领测试只对普通命令环要求
`PxCLB/PxFB` 相等。捕获口由独立三格用例与第二内核的 DMA 布局校验负责，不再污染普通环判据。

提交前最终矩阵原始读数 **67/82 符合、15 不符**。其中 12 条仍是既有 FAT32/P7/A3 基线；
另 3 条（设备事件对账、A2 正向及同轮 `t_block_wake`）用矩阵同一 ELF 单跑清除：
`run-13030` 默认档 `da4ddcb48ac2`、`run-13029` A2 `0200404e7a1a`，均 PASS。

最终默认构建通过，`ktests` 90/90，`check` 21/21，capture `clippy -D warnings` 通过；
完整矩阵 **68/82 符合、14 不符**，14 条全为既有 L4 级联、FAT32/P7 与 A3 基线偏差。
**真机未验证，默认档未启用 kdump。**

## 未验证与保留边界

1. 真机 AHCI 口 1、NMI/IST2、UC DMA 与持久捕获盘全部未测。
2. 稀疏 vmcore 只含元数据/寄存器，不是可直接交给 Linux `crash` 的完整内存转储。
3. 软件 L4 没有 TrapFrame，完整 GPR 快照只覆盖真异常路径；控制寄存器与旧 RSP/RBP 仍有。
4. 真实 `PxCI!=0` 与第二内核入口错两类负样本尚未单独注入；坏完成由 PRDBC 变异覆盖。
5. capture 初始化完成前的 panic 入口尚未单独取证；默认 L4 HEAP→GROW 级联已由 ADR-248 关闭。
6. kdump 不提供安全启动/身份/槽位信任根，仍受 ADR-080/W5/W12 约束。

## 回滚

通过特性 `kdump` 门控整条链。关闭特性恢复普通 `state_store` L4 落盘；默认档是否启用
由本轮实测决定，未验证前不得把 kdump 设为默认。
