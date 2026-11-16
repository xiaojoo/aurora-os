# 文件系统与 Shell 命令体系建设设计：基线校正与实施约束（V1.1 补充）

**基线**：`docs/design/Aurora OS 文件系统与 Shell 命令体系建设设计文档 V1.0.md`（用户提供的 V1.0，已原样入库）
**核对时点**：2026-11-15，仓库 HEAD `94c896f`（工作树另有未跟踪文档，不影响本补充）
**关系**：V1.0 保留不动；本文件是它的增量。两者冲突时以本文件为准，冲突处均给出源码依据。
**口径**：本文引用的事实来自读源码，未重跑整链；凡未实测的结论显式写“未验证”。

---

## 0. 结论摘要

V1.0 的方向（保留存储层 → VFS → FAT 完善 → syscall → Runtime → Coreutils → Shell）与仓库现状一致，可以继续用。但它有三类需要修正的内容：

1. **事实性偏差**：把“已有能力”说得比实际宽。FAT16/GPT 只在专用特性档编译；Shell 只在 `handles`/`wm` 变体运行；产品启动路径不授予文件句柄 ⇒ 今天用户态拿不到任何文件句柄。
2. **缺少仓库硬约束**：堆上限 2048、锁序登记、unsafe 白名单、17 道 `check`、41 行判定表、负样本纪律、GBK 控制台、夹具与行尾规则——这些不是“工程建议”，是改代码时会让门禁变红的硬条件。
3. **把设计当成可直接落地的顺序**：V1.0 的 FS-01…FS-10 没有标出前置欠账（virtio-blk 的 `Block` 实现、写盘夹具、argv/exec、fd 抽象、墙钟时间）。不补这些，里程碑会在中途卡住。

建议保留 V1.0 的章节结构，按本文第 2、3、4 节修订后作为 V1.1 正文；第 5 节列出必须先裁决的问题。

---

## 1. 事实校正表

| # | V1.0 的说法 | 源码事实 | 影响 |
|---|---|---|---|
| 1 | 目录树写 `kernel/src/filesystem/mod.rs` | 实际是 `kernel/src/filesystem.rs` 门面 + `kernel/src/filesystem/` 子模块（2018 edition 风格），没有 `mod.rs` | 文档示例会误导新人去建 `mod.rs` |
| 2 | “已有 FAT16 文件系统解析” | 是，`fat32.rs` 同时实现 FAT16/FAT32 判型与读路径（ADR-078 / W4 S2a）；但只在 `fat16-probe` 档注册用例，默认构建不编译这条读路径 | 能力存在，但不在产品构建里 |
| 3 | “GPT 分区表解析（特性门控）” | 正确；`gpt-probe` 与 `esp-probe` 两档才编译（`kernel/src/filesystem.rs:8`，`tools/aurora.py` 的 `GPT_FEATURES`） | 默认构建没有 GPT；不要把 GPT 当既成产品能力 |
| 4 | “文件句柄管理” | 仅在 `handles` 特性；`kernel/src/handle.rs` 是 16 格表 + Rights + 世代号 | 默认构建没有句柄表 |
| 5 | “用户空间文件读取系统调用” | `SYS_FILE_READ=10` 存在；但产品路径（`init-user`，`main.rs:1208`，`handles` 门控）只授予 console/job/proc 句柄，**不授予文件句柄**；`grant_file` 的调用点只在 `ktests/fs.rs` 与 `ktests/esp.rs` | Shell 里今天没有可用的文件命令数据源 |
| 6 | “用户空间交互式 Shell” | `user/shell` 存在，命令恰为 `help/echo/ping/abi/exit`（`user/shell/src/main.rs:43`）；默认构建装的是 hello 不是 shell；shell 在 `handles`/`wm` 变体里由 `init-user` 装载（`main.rs:1280`） | 不能说“默认系统启动就是交互式文件 Shell” |
| 7 | 只提了 `user/shell` | 还有一条**内核侧**图形终端 `LiveTerm`（`main.rs:1612`，`wm` 变体），带多会话/窗口管理（ADR-104/105）；两者互不共享命令实现 | V1.0 的 Shell 重构必须说明改的是哪一个，或如何统一 |
| 8 | “Shell 通过 `int 0x80` 进入内核” | 正确；另有一条 `syscall` 快路径（ADR-025），`hello` 先读 `abi_info` 的 bit0 才敢用（`user/hello/src/main.rs:79`） | 扩展 ABI 时两条入口的返回路径都要覆盖 |
| 9 | §7.4 直接列 POSIX errno | 现有 ABI 只有六个负值 `AbiError`（`kernel/src/user.rs:217-222`）：-1 参数/-2 用户内存/-3 超长/-4 拒绝/-5 坏句柄/-6 耗尽；`-7=EIO` 仍未定（AGENTS.md 里程碑缺口 1） | 不能另立一套 errno 返回空间；要么映射到现有负值，要么开 ADR 扩号 |
| 10 | §7 未给号段 | 1、3–21 已占用，99 是负样本号；22 起为未登记区（2 也未见登记，需核 ADR） | 新增 syscall 号必须先裁决再写代码（AGENTS.md 工作协议） |
| 11 | §6.2 建议新增 `BlockWrite` | 块层确实只有 `read_sectors`（`vfs.rs:101`）；但 AHCI 驱动已有 `write_lba/write_bytes`（`ahci.rs:1329/1351`），被持久状态区直接使用（`state_store.rs:532`） | 写能力不是从零；缺的是“经过分区视图/文件系统的写路径”，不是驱动写 |
| 12 | “virtio-blk”只出现在目标图 | `impl Block` 只有 `AhciDisk`、`MemDisk`、`PartitionView`；virtio-blk 的 `Block` 实现是未清欠账（BACKLOG 78h-3） | FS-09 的多设备挂载被这条卡住 |
| 13 | 验收示例树 `/home/user/readme.txt` | 现有夹具是两块 mtools 合成卷 + 宿主机现算的 `fat32-mem.img`/`fat16-mem.img`，根目录 8.3 名；真实 ESP 是 FAT16 固定根区 | 示例树在今天的卷上不存在；FS-02 前要先造夹具 |
| 14 | §5.4 文件时间属性 | 本机 OVMF/QEMU 上 RTC 不可用（`apic.rs:46` 的实测注释），今天没有墙钟时间源 | FAT 的创建/修改时间无法填真实时间；先裁决“合成时间”还是“补 RTC” |
| 15 | §2.2.2 说缺口含“完整多级目录遍历/LFN” | 正确；补充两条既有边界：`MAX_CLUSTERS_WALKED=65535`（`fat32.rs:109`），每簇一次 FAT 读；`entries_seen`/`lfn_entries` 是覆盖面读数，不是装饰 | readdir 必须带游标与覆盖面计数，否则“枚举过了”无法证明 |
| 16 | §2.2.3 职责分离 | 正确且已有 ADR：`Volume::mount` 认“LBA0 就是引导扇区”，分区偏移只活在 `PartitionView`（ADR-078）；越界必须在翻译前拒（`vfs.rs:72-79`） | 新的写路径必须复制这条“先判界、后翻译”的顺序 |
| 17 | 文末“六、正式实施顺序”与“0/8 项完成” | 是聊天/看板残留，不是设计正文 | 合入 V1.1 时删除或并入 §12 |

---

## 2. 必须写进设计的仓库硬约束

以下条目在 V1.0 中缺失或只有一句泛泛的“注意”。它们会直接决定 FS 代码能不能过门禁。

### 2.1 内存：没有“按输入大小分配”

- 全局堆上限 `LARGE_MAX = 2048` 字节（`kernel/src/heap.rs:27`），超过即按 ADR-018 变 39。
- 因此 VFS 的内部实现**不许**出现 `String`、`Vec`、按路径名长度开的缓冲。路径、文件名、目录项都必须用固定上限数组或流式遍历。
- V1.0 §4.4 的 `lookup(&self, parent, name: &str)` 作为**接口参数**可以保留；但实现只能引用调用方缓冲，不能克隆。
- 若确实需要大块缓冲（例如整目录快照），必须先走 ADR 引入大块分配或大小类，不许在 FS 里偷开 static 数组逃过检查。

### 2.2 锁与并发

- 新增挂载表锁、卷表锁、目录缓存锁，必须同步改 `docs/architecture/lock-order.md`、代码里的 rank、测试与负样本（AGENTS.md 硬约束 4）。
- 设备 I/O 期间不得持有全局表锁（V1.0 §2.2.4 已有此约束，需扩到写路径）。
- 读路径今天是“句柄票 + 分块读 + 不提交失败游标”（`user.rs:981-1022`）；写路径要定义对应的“失败不提交”语义，并给出负样本。

### 2.3 unsafe 与驱动边界

- 新增存储后端或写 DMA 必须经 `DriverCtx`；`check-driver-ctx` 是文本网关，扫 `ahci.rs`/`virtio.rs`，禁用 `read_volatile`/`write_volatile`/`ptr::`/`from_raw_parts`。
- 新增 `unsafe` 必须登记 `docs/security/unsafe-whitelist.toml`，写明指针来源、地址范围、对齐、生命周期、并发规则、上下文约束与不变量保证者。
- 直接改 `ahci.rs` 的写路径会同时触碰已经实测的驱动资源语义（AGENTS.md 硬约束 1），应先开 ADR。

### 2.4 模块与静态门禁

- 新模块（`vfs/`、`tmpfs.rs`、`mount.rs` 等）必须登记进 `docs/architecture/module-interfaces.toml`：`public_api`、`dependencies`、`allowed_callers`、`forbidden_dependencies`、`context`、`error_classes`、`unsafe_scope`、`test_targets`。漏登记会让 `check-module-interfaces` 变红或让新代码无门禁。
- `check` 当前 17 道。`check-fat32-ports` 是文本网关，只覆盖它扫描的文件；把代码搬进 `vfs/` 或新增 `fat16` 专门文件后，必须确认这道闸仍能咬到，否则等于没有门禁。
- 把 `vfs.rs` 的块设备部分迁到 `block.rs` 时，`module-interfaces.toml`、`crates.toml`、`module-dependencies.md` 三处都要同步；V1.0 §4.2 只说“评估”，应写成“迁移即登记”。

### 2.5 负样本与测试口径

- **每条新规则/新判据都要配一个能让它变红的负样本**（变异证红），且负样本自己也要被证明会咬。
- 两种注入不许混：内核侧 `cfg!` 注入是 cargo 特性；宿主机侧改盘注入**不许**做成特性（特性名进 `-C metadata` 会改符号哈希与链接布局，BACKLOG §80a）。
- 判定表当前 41 行，每行拿自己那一跑的串口日志与退出码；判定值 `PASS=33 / FAIL=35 / BOOT-INVALID=37 / EXCEPTION=39 / HANG=-1`，另有 CONTENT-MISMATCH / SEQ-BROKEN。
- 新增 FS 行时，`check-matrix-wiring` 会检查行名不重、每行有自己的日志变量与退出码变量，两行不得共用证据。
- “没看到红”不是绿；“检测到”不等于“已恢复”；文件系统读失败不等于卷损坏（V1.0 §9.4 的 `fsck` 一条已接近这个口径，应升为总则）。

### 2.6 取证环境

- 本机控制台 GBK：跑任何 Python 入口要带 `PYTHONIOENCODING=utf-8 PYTHONUTF8=1`，否则按中文锚点的判据会静默读成零条。
- 跨轮比较串口量只能用 `bench` 的 `p4: serial_bytes`，不能拿 `build/serial.log` 的文件字节去比基线（BACKLOG 78g 的仪器错）。
- `tools/aurora.py` 与 `tools/make_fat32_mem.py` 必须保持 CRLF；整文件转 LF 会把 diff 变成几千行噪音。
- 夹具：`kernel/fixtures/fat32-mem.img`、`fat16-mem.img` 被 `.gitignore` 挡着，由 `tools/make_*.py` 现算；两块真卷的配方是 `.img.zz`，本机没有 mtools；单文件替换用 `tools/patch_fat32_file.py`，整卷 mformat 仍卡着（78h-6 / 80f-1）。

---

## 3. 对 V1.0 各章的补充

### 3.1 §2 现有基线

- 明确区分**编译期存在**与**产品构建存在**：FAT16、GPT、文件句柄、shell 都在特性档里；默认档装 hello、跑信箱判据。
- 补充“两种终端”：ring3 串口 shell（`user/shell`）与内核侧 `LiveTerm`（`wm` 档）。V1.0 的 Shell 章节应指定改造对象，或给出统一路线（例如先把文件 API 接进 ring3 shell，再让 LiveTerm 调用同一用户程序）。
- 文件句柄的真实数据流应画出来：`init-user` 授予 console → shell 读控制台 → `SYS_FILE_READ` 需要文件句柄，但今天没有授予点。这条断链是 FS-03 的真正起点。

### 3.2 §4 VFS

- **FAT 没有 inode**。稳定身份只能是“目录项所在位置 + 首簇”；rename/移动会改身份。V1.0 的 `InodeMetadata.inode_id` 必须定义生成规则，否则 `stat`/打开句柄/缓存会互相矛盾。
- 明确 dentry 缓存的失效策略；没有缓存也可以先做，但接口要允许以后加。
- 明确路径解析的边界：长度上限、分量上限、重复 `/`、`.`/`..`、大小写（FAT 8.3 大写存储）、非法字符。
- 明确 **CWD 属于谁**：V1.0 把 `cd` 放 Shell 内置，那么相对路径由 Shell 拼成绝对路径后交给内核，还是内核接收 `(dir_handle, name)`？两种都要写清，不能两处各解析一遍。
- 明确挂载命名空间：先做单根单卷，还是多根；多根需要 ADR（挂载点、查找顺序、卸载时仍有打开句柄的处理）。
- `FileSystem` trait 的 `&self` 与可变操作（create/unlink）不匹配；要么内部同步，要么用 `&mut self`/显式事务对象。Rust 类型层面先定下来，避免实现时返工。

### 3.3 §5 FAT 完善

- 目录读取阶段应复用现有 `Bpb`/`fat_next`/`cluster_to_lba`，不要另写第二套几何；FAT16 固定根区与 FAT32 根目录簇的分支已经存在。
- LFN：现有判据要求 `lfn_entries == 0`，含义是“长名今天没实现”；实现 LFN 后这条判据必须改，否则会把新能力判成红。
- 写入补充：
  - 簇分配策略（从 FSInfo 的 `next_free` 开始还是从 2 扫）、FSInfo 不可信时的回退。
  - 两份 FAT 的更新顺序与失败窗口；部分写必须显式报告，不许静默成功。
  - 目录项时间戳来源（见 §1 第 14 条）。
  - 坏簇标记与“空间不足”的判定。
  - FAT12 明确拒绝；只读卷标志（`BS_Reserved`/属性）明确返回只读错。
- **不宣称事务/断电恢复**（V1.0 已写），补充一句：也不宣称“掉电后卷仍可挂载”；这需要单独的 fsck 与夹具。

### 3.4 §6 块层与分区

- `BlockWrite` 与 `Block` 分离是对的；但要补 `flush` 的真实能力：AHCI 的 FLUSH CACHE EXT 是否可用、virtio-blk 的 flush 语义，需实测，未验证前不许写“已支持持久化屏障”。
- 写路径同样要“先判分区界、后翻译”（复制 `PartitionView::read_sectors` 的顺序），并保留 `BeyondPartition` 与 `Refused` 的区分。
- `capacity_sectors` 的来源要定：设备自报、GPT、还是调用方给的区间。不要新开第三份容量账（`vfs.rs:105` 已明确块层不维护第二份容量账）。
- virtio-blk 的 `Block` 实现是 FS-09 的前置；V1.0 应把它列成显式欠账，而不是目标图上的一个框。

### 3.5 §7 系统调用 ABI

- 现有号表：1、3–21 已用，99 为负样本；新增号从 22 起，且必须开 ADR、更新 `docs/design/user-abi-capability.md` 与手册 §10.2。
- `open` 返回句柄，路径解析放内核还是用户，必须先裁决；放内核就要定义根目录/挂载点、CWD 句柄的传递方式；放用户就要多个 syscall（lookup/readdir）并接受性能代价。
- `seek` 与现有游标：`SYS_FILE_READ` 今天隐式推进句柄里的游标；加 `seek` 前要定义“游标在句柄还是文件对象”，以及 `dup` 是否共享（今天是复制游标，AGENTS.md 已列为欠账）。
- `readdir` 的目录游标属于句柄还是调用方缓冲；重复调用从哪儿继续。
- `stat` 返回什么：大小、首簇、属性、时间；时间源未定（见 §1 第 14 条）。
- `close` 已有（8 号），但“关闭最后一个句柄时释放卷/缓存”的语义要写。
- 错误码：给出“errno → `AbiError`”映射表；`ENOENT/EACCES/ENOTDIR/...` 不能都压成 -1，否则负样本分不开成因（与 `BlockError` 七格分开的理由同构）。
- 新调用必须在 `syscall_dispatch` 的未知号分支之前登记，并重验“没协商就打新号回 -1”的旧负样本（`user-abi-capability.md` 第 8 格）。

### 3.6 §8 用户空间 Runtime

- `no_std`、无分配器：Runtime 的文件 API 不能返回 `String`/`Vec`；路径与目录项用调用方缓冲。
- 需要 ABI 协商：用户程序先读 `abi_info`，看到对应特性位再调用新号（现有快路径就是这样）。
- 首期不做完整 POSIX libc 的判断正确；但要补“错误转换表”和“句柄生命周期”的具体函数签名。

### 3.7 §9 Coreutils

- `cp/mv/find` 等依赖写路径；`ls/cat` 依赖 `open/read/readdir`。V1.0 已分优先级，需补前置：
  - `cd/pwd` 依赖 CWD 归属裁决；
  - `cp/mv` 依赖写路径与 `rename`；
  - `find/tree` 依赖多级目录与 LFN；
  - 独立命令程序依赖 argv/exec/PATH，而今天 `StartupInfo` 没有 argv/env，`SYS_PROCESS_START` 也不是 exec。
- “不允许 Shell 自己解析 FAT 目录项”应升为门禁或负样本（例如源码扫描 `user/` 下不得出现 `fat32` 引用），否则只是口号。

### 3.8 §10 Shell

- 需要先回答：改造 `user/shell` 还是 `LiveTerm`，或两者共用一套 `coreutils` 库。
- Lexer/Parser 可以在用户态用固定缓冲实现；`history` 需要存储位置（内存 or 文件），不能默认文件系统已可用。
- 管道/重定向依赖 fd 抽象：当前句柄是对象句柄（带 owner/rights/世代号），没有 fd 号、没有 `dup2`、没有 pipe 对象。V1.0 §10.7 应标注为“需先开 ADR”。
- 自动补全需要目录枚举与路径解析，排在 FS-02 之后。

### 3.9 §11 安全与稳定性

- 补充块层已有的隔离语义：`BlockError::Quarantined`（端口被 §8.2 摘线）必须原样上抛，FS 不许重试到成功再报“正常”。
- 簇链循环已有上界 `MAX_CLUSTERS_WALKED=65535`；新增的目录遍历也要有上界，不能只靠“目录项 0 结束”。
- 并发场景中“一个进程删除另一个进程正在打开的文件”需要裁决：FAT 没有引用计数，要么拒绝删除（EBUSY），要么延迟回收；不许静默让旧句柄读到错数据。
- “单个卷损坏不影响其他卷”要落到结构上：卷对象持有自己的 `Block` 与缓存，不共享可变全局状态；错误按卷隔离并计数。

### 3.10 §12 里程碑

V1.0 的 FS-01…FS-10 顺序基本合理，但缺前置。建议改成：

| 里程碑 | 新增前置/边界 |
|---|---|
| FS-01 | 先裁决 syscall 号、errno 映射、CWD 归属；本阶段只读、不新增 syscall，用 ktest 验证 |
| FS-02 | 先把 FAT16/GPT 从 probe 档接入一个“只读挂载”产品路径；夹具要造出多级目录与 LFN |
| FS-03 | 需要“文件句柄授予点”（`open` 或启动时授予根句柄）；否则 Runtime 无对象可用 |
| FS-04 | 需要 `BlockWrite` + 分区写界 + 写盘夹具；时间戳来源先定 |
| FS-05 | 依赖 FS-04；删除打开中的文件要先裁决 |
| FS-06 | `cp/mv` 依赖写路径；独立命令依赖 argv/exec |
| FS-07 | 依赖 FS-02 的路径解析；历史/补全先做内存版 |
| FS-08 | 依赖多级目录与 LFN；`find` 需要遍历上界 |
| FS-09 | 依赖 virtio-blk 的 `Block` 实现与挂载管理 ADR |
| FS-10 | tmpfs 与 VMO/帧的关系需 ADR；符号链接/权限在 FAT 上要明确“有限语义” |

### 3.11 §13 测试

- 保留 V1.0 的分类，补充：
  - **双仪器对账**：内核解析结果与宿主机 Python 解析同一块卷逐格对账（现有 `tools/validate_esp.py` 是雏形）。
  - **持久化测试的镜像身份**：跨重启测试必须控制镜像是否被 `ensure_image` 重造（sha/变体名），否则测的是另一份产物（BACKLOG 79g-4 的同类坑）。
  - **负样本矩阵**：目录项损坏、簇链循环、非法簇号、越界路径、坏句柄、用户指针非法，每格一个注入。
  - **性能量具**：每簇一次 FAT 读的 readdir 会显著增加串口与块命令数；量具开销不算进产品基线。

### 3.12 §14 工程管理

- 补提交纪律：一个会话只做一件事；按显式文件名 stage；每步跑 `build/ktests/check/test` 并贴前后读数；未验证写“未验证”。
- ADR 编号从 **106** 起（当前最新 `ADR-105`）；不要改 ADR-078（分区/mount 分离）与 ADR-080（验签只检测不拒启）的既定语义。
- 新增接口同步 `module-interfaces.toml`、`lock-order.md`、`unsafe-whitelist.toml`；文档、BACKLOG 同步更新。

---

## 4. 建议的第一刀（FS-01 重写版）

目标：把“只读 VFS 适配层”做成可验证的最小闭环，不碰写路径、不新增 syscall。

1. 新增 `vfs` 门面（可先在 `filesystem/vfs/` 子模块里长），只包一层：
   - `Lookup(parent, name) -> EntryRef`（固定缓冲名，无分配）；
   - `ReadDir(dir, cursor) -> Option<Entry>`（8.3 + LFN 计数，带 `entries_seen`）；
   - `Read(file, offset, buf)`（复用 `FileCursor`）；
   - `Stat(entry) -> FileStat`（现有字段 + 类型）。
2. 第一个实现是 FAT16/FAT32 只读适配器，直接调现有 `Volume`，不重写解析器。
3. 单根挂载：`Volume::mount` 的“LBA0 = 引导扇区”契约不变；分区偏移仍由 `PartitionView` 提供。
4. 测试：
   - ktest `t_vfs_readonly`：路径解析、目录枚举覆盖面、越界、簇链循环各一格；
   - 负样本：把 `..` 解析改坏、把 `entries_seen` 固定为 1、把越界判断挪到翻译之后，各证一次会红；
   - 判定表加一行，拿自己那一跑的日志与退出码；
   - 现有 41 行不退化，`check` 17/17，三档构建 0 error。
5. 明确不做：写路径、新 syscall、Shell 改造、tmpfs、virtio-blk。

验收语：用户态仍拿不到文件句柄；本刀只证明“内核里有一个无分配的只读 VFS 层，且它的每条判据都能变红”。

---

## 5. 待裁决清单（2026-11-15 已全部裁决，结论见 §7）

1. 新增 syscall 号段与 errno 扩展方案（映射到 `AbiError` 还是新增 `-7…`）。
2. 文件句柄的授予点：`open` 系统调用，还是启动时授予根目录句柄。
3. 路径解析与 CWD 的归属（内核 VFS 还是用户 Runtime）。
4. FAT 写路径的持久化口径：是否支持 flush、是否宣称断电一致性。
5. 时间戳来源：补 RTC/ACPI，还是先用单调合成时间（并明确“不是墙钟”）。
6. tmpfs 与 VMO/帧的关系；是否先不做。
7. 单根单卷还是多根挂载命名空间。
8. 两个 Shell（`user/shell` 与 `LiveTerm`）的长期关系。
9. FAT16/GPT 是否并进默认产品构建，还是继续特性门控。
10. 删除“正在被打开的文件”的语义（拒绝还是延迟回收）。

这十项都涉及已采纳语义或新 ABI，按仓库协议应先记录差异、再起草 ADR，不能在设计文档里默认拍板。

---

## 6. 文档管理建议

- V1.0 原样保留为基线；本补充作为 V1.1 的修订依据，评审通过后再合并成单篇 V1.1。
- 合并时删除 V1.0 文末的“六、正式实施顺序”与“0/8 项完成”看板残留。
- 后续实现接口、ADR、测试判据分别维护：`docs/design/filesystem-abi.md`、`docs/design/shell-architecture.md`、`docs/adr/`。
- 本文件中的源码行号以 HEAD `94c896f` 为准；改代码后引用前先核对。

---

## 7. 裁决记录（2026-11-15）

第 5 节十项已由使用者逐项确认，全部按补充稿建议通过。落档：本表 + ADR-106 + ADR-107。

| # | 裁决 | 落点 |
|---|---|---|
| 1 | 新 syscall 号从 **22** 起；错误码在现有 -1…-6 之后扩到 **-7…-16**（-7 EIO、-8 ENOENT、-9 EEXIST、-10 ENOTDIR、-11 EISDIR、-12 ENOSPC、-13 ENOTEMPTY、-14 EROFS、-15 ENOTSUP、-16 EBUSY）；旧号 8/9/10 返回集合不变 | **ADR-106** |
| 2 | 文件句柄**只在 `open` 时授予**；启动路径不授予文件句柄，也不授予根目录句柄 | **ADR-107** §1 |
| 3 | **内核解析绝对路径**；Shell/Runtime 维护 CWD 并用固定缓冲拼成绝对路径；首刀不新增 `chdir/getcwd` | **ADR-107** §2 |
| 4 | 写路径口径：**写返回成功即可见，不承诺断电一致性**；flush 仅在设备支持时提供；不宣称日志/断电恢复 | 记录于本表与 **ADR-107** §0；写路径本身另开 ADR |
| 5 | 时间戳先用**单调合成时间**（1980-01-01 + 启动后单调秒），明确不是墙钟；RTC 另立 bring-up | **ADR-107** §6 |
| 6 | **首期不做 tmpfs**；`FileSystem` trait 留位置，tmpfs 与 VMO/帧的关系另开 ADR | **ADR-107** §0 |
| 7 | **单根单卷**挂载；`Volume::mount` 语义不变；多根与路径前缀匹配另开 ADR | **ADR-107** §3 |
| 8 | 文件 API **先接 ring3 `user/shell`**；`LiveTerm` 保持内核侧展示终端不动；统一另开 ADR | **ADR-107** §8 |
| 9 | FAT16/GPT **继续特性门控**；先加 `fs-ro` 变体承载只读挂载判据；默认构建 ELF 与串口量不变；并入默认需单独 ADR 并重跑基线 | **ADR-107** §7 |
| 10 | 删除正在被打开的文件**回 -16 `EBUSY`**；不做延迟回收；卷内维护已打开文件表 | **ADR-107** §4 |

裁决后的直接约束：

- 下一步实现 FS-01 时，**先按 ADR-106 §1 逐号登记**，不要在代码里先写号；`-7…-16` 的每一格都要有负样本。
- FS-01 只读、单根、绝对路径、无分配；不新增 syscall，先用 ktest 验证（ADR-107 §0/§2/§5）。
- 新增模块进 `module-interfaces.toml`，新增锁进 `lock-order.md`，新增 unsafe 进 `unsafe-whitelist.toml`。
- ADR 编号：106、107 已用；下一份从 **108** 起。

