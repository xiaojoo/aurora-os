# ADR-107：只读 VFS 第一刀——open 授予句柄、内核解析绝对路径、单根单卷挂载

状态：**已采纳**（2026-11-15，使用者逐项裁决；实现未开始，本文关于新行为的句子均为推断）
关联：ADR-007（capability 句柄）、ADR-018/026（堆上限 2048、先验上界再用）、
ADR-070/075/076（每进程 AS、Proc/Thread/StartupInfo）、ADR-078（分区能力与 mount 语义分离）、
ADR-080（验签只检测不拒启）、ADR-106（文件类号段与错误码）、
`docs/design/user-abi-capability.md`、`docs/design/FS-设计补充-V1.1-基线校正与实施约束.md`、
BACKLOG 78f/78h-3

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计；发现冲突先记差异，
> 不要为了让文档一致去改已经验证的结论。每条结论标「实测」或「推断」。

## 背景

**已有能力（实测）**：
- 块层只有 `read_sectors`（`kernel/src/filesystem/vfs.rs:101`），实现有 `AhciDisk`、`MemDisk`、
  `PartitionView`；virtio-blk 的 `Block` 实现未做（BACKLOG 78h-3）。
- FAT16/FAT32 解析、mount、open、walk、游标读已存在（`fat32.rs`，ADR-078/W4 S2a），
  FAT16 只在 `fat16-probe` 档注册；GPT 只在 `gpt-probe`/`esp-probe` 档编译。
- `Volume::mount` 的契约是“这块 `Block` 的 LBA0 就是引导扇区”；分区偏移只活在
  `PartitionView`，越界必须在翻译前拒（`vfs.rs:72-79`）。
- 没有任何 VFS 门面：没有 inode/dentry/path/mount 抽象。

**产品路径的断链（实测）**：`init-user` 只授予 console/job/proc 句柄；
`grant_file` 的调用点只在 `ktests/fs.rs` 与 `ktests/esp.rs`。因此今天用户态
（包括 `user/shell`）拿不到任何文件句柄，`SYS_FILE_READ` 在产品路径没有对象可读。

**为什么现在必须决定**：FS-01/FS-02 要新增 VFS 与目录访问，FS-03 要让用户态打开文件。
若不先钉死“句柄从哪儿来、路径谁解析、挂载几个根”，实现会在三处各自发明一套。

## 决策

### 0. 范围：第一刀只读

- 本 ADR 只覆盖只读 VFS 与目录访问；**不包含**写路径、tmpfs、fd/pipe、文件锁。
- 写路径的持久化口径另开 ADR；本 ADR 只记录已裁决的口径：**写返回成功即可见，不承诺断电一致性**，
  文档与发布说明不得宣称日志或断电恢复。

### 1. 文件句柄只在 `open` 时授予

- 启动路径（`init-user`）**不授予任何文件句柄**，也不授予根目录句柄；继续只授予 console/job/proc。
- `open(path, flags)` 解析成功后返回一个带 Rights 的句柄；owner = 调用者身份
  （现有 `sched::current_identity` 口径）。Rights 由打开标志推导，至少区分 `RIGHT_READ`，
  首刀不产生可写文件句柄。
- `close` 复用 8 号；关闭最后一个句柄时释放该次打开占用的游标/元数据，**不**卸载卷。
- 失败不返回句柄；失败原因用 ADR-106 的错误码。

### 2. 内核解析绝对路径，Shell 维护 CWD

- 首刀只接受**绝对路径**（以 `/` 开头）；相对路径、`.`、`..` 由 Shell/Runtime 在固定缓冲里
  规范化成绝对路径后再交给内核。
- 内核只做一次统一解析与校验：重复 `/` 折叠、分量长度上限、总长度上限、非法字符、
  越界/逃逸拒绝。
- Shell 的 CWD 是用户态状态，不新增 `chdir/getcwd`；`cd` 只改 Shell 自己的变量。
- 路径与文件名**不许在内核里按输入长度分配**：使用固定上限数组与流式遍历（见 §5）。
- 文件身份：FAT 没有 inode；`EntryRef` 用“卷标识 + 目录项位置 + 首簇”表示，
  rename/移动会改变身份。打开句柄持有自己的元数据与游标，不承诺跨 rename 跟踪。

### 3. 单根单卷挂载

- 首刀只有一个挂载点 `/`，一次只挂一个只读卷；多根挂载与路径前缀匹配另开 ADR。
- `Volume::mount` 的“LBA0 = 引导扇区”契约不变；分区偏移仍由 `PartitionView` 提供，
  不做自动发现，不把分区逻辑塞进 `Volume::mount`（ADR-078）。
- 卸载要求该卷**无任何打开句柄**，否则回 -16 `EBUSY`；卸载语义进后续 ADR，首刀可以只做启动期挂载。

### 4. 删除打开中的文件：拒绝

- 卷内维护已打开文件表；`unlink` 命中仍被打开的项时回 -16 `EBUSY`，不删除、不打删除标记。
- 选择理由：FAT 没有引用计数；“延迟回收”需要额外的删除标记、打开表与崩溃后清理规则，
  首刀不做。将来若做，必须单独 ADR 并定义断电后残留删除标记的处置。

### 5. 无分配实现

- 遵守 `heap::LARGE_MAX = 2048`：VFS 内部不出现 `String`、`Vec`、按路径/目录项长度开的缓冲。
- 建议的首刀常数（实现时按夹具校准，不先写死为永久值）：
  名字上限 12 字节（8.3 + 点）、路径上限 256 字节、目录游标为固定大小结构体。
- 目录遍历必须有上界：沿用 `MAX_CLUSTERS_WALKED` 的思路，给“目录项扫描”独立计数；
  不许只靠“遇到 0 项就结束”。
- 目录枚举必须返回覆盖面读数（`entries_seen`、`lfn_entries`），判据要求后者为 0 表示
  “长名今天没实现”，实现 LFN 后同步改判据。

### 6. 时间戳：先用单调合成时间

- 本机 OVMF/QEMU 上 RTC 不可用（`apic.rs:46` 的实测注释），今天没有墙钟时间源。
- FAT 目录项的创建/修改时间先填“1980-01-01 + 单调秒”（启动时刻 + TSC 折算），
  并在 `stat` 与文档里明确标注**不是墙钟时间**。
- RTC/ACPI 时间源另立 bring-up；补上后由新 ADR 决定是否替换合成时间。

### 7. 产品化路径：新增 `fs-ro` 变体，默认构建不动

- FAT16/GPT 继续特性门控；默认构建的 ELF 与串口量**保持不变**。
- 只读挂载与 VFS 先用 `fs-ro` 变体承载判据；稳定后再由单独 ADR 评估是否并入默认构建，
  并入时必须重跑四把尺子与 41 行判定表。
- 新模块必须登记 `docs/architecture/module-interfaces.toml`；新增锁必须登记
  `docs/architecture/lock-order.md` 与 rank；新增 unsafe 必须登记
  `docs/security/unsafe-whitelist.toml`。

### 8. Shell 接入目标：先 ring3 `user/shell`

- 文件 API 先在 ring3 串口 shell 闭环；`LiveTerm`（内核侧图形终端）保持现状，不接文件系统。
- 两者长期是否统一，另开 ADR；首刀不把命令实现搬进内核。

### 9. 与验签/启动路径的边界

- 从 ESP 读 FAT 与“验签拒启”是两件事；ADR-080 仍只检测不拒启。
- 本 ADR 不改变签名、启动循环保护或 `boot_guard` 的任何语义；文件系统挂载失败不得
  被解释为“镜像不可信”。

## 备选方案

1. **启动时授予根目录句柄**：少一次路径解析，但初始权限面更大，且每个会话都要管理根句柄生命周期。
   不选。
2. **内核维护每进程 CWD**：更接近 POSIX，但要动进程对象与新增号；首刀不做，留给后续 ADR。
3. **用户态全解析（lookup/readdir）**：省内核路径解析，但每个命令都会长出一套路径逻辑，
   与 V1.0“统一解析”冲突。不选。
4. **多根挂载从第一天做**：需要挂载表、前缀匹配、卸载并发语义；首刀体量会失控。推迟。
5. **合成 inode 号**：在 FAT 上维护一份“路径/簇号 → 号”的映射，需要分配与失效策略；
   首刀直接用 `EntryRef`，不发明 inode。不选。
6. **延迟回收打开中的文件**：语义更接近 Unix，但没有引用计数与崩溃清理；首刀用 `EBUSY`。

## 影响

- **正面**：用户态终于有文件对象可拿；路径/挂载/身份口径一次钉死；默认构建与既有基线零变化。
- **负面**：单根单卷与绝对路径限制会让 Shell 先承担路径拼接；多根、相对路径、`chdir` 都要后续 ADR。
- **对已有测试**：默认构建与 41 行不变；`fs-ro` 变体新增行，必须各自带日志与退出码；
  FAT16/GPT 的既有 probe 档读数不动。
- **对模块登记**：`vfs` 门面与 `fs-ro` 相关模块必须进 `module-interfaces.toml`，否则
  `check-module-interfaces` 会红或新代码无门禁。

## 验收与负样本

FS-01 的首刀验收（全部在 `fs-ro` 或 ktest 档，不改默认构建）：

- 正样本：绝对路径 lookup、根目录 readdir、多级目录 readdir、游标读、stat；
  目录枚举的 `entries_seen` 非零、`lfn_entries` 为 0（未实现 LFN 时）。
- 负样本（每条都要能变红）：
  - 越出 `PartitionView` 区间 → `BeyondPartition`，且在翻译前拒；
  - `..` 逃逸根目录 → -8/-1，不读到别的区间；
  - 重复 `/`、超长名字、超长路径 → -1/-3；
  - 目录项损坏/簇链循环 → 有界错误，不无限循环；
  - 删除打开中的文件 → -16 `EBUSY`；
  - 非绝对路径 → -1（首刀）。
- 双仪器：内核解析结果与宿主机 Python 解析同一块卷逐格对账（`tools/validate_esp.py` 的 FAT16
  读表是雏形）；存储失败另用 QEMU/`bench` 的块命令读数对账。
- 回归：现有 41 行判定表、`check` 17 道、三档构建 0 error 不退化。

## 迁移与回滚

- 迁移是包装而非重写：在现有 `Volume`/`FileCursor` 外包一层只读 VFS，`fat32.rs` 的解析与
  走链不重写；`Volume::mount` 契约不动。
- 回滚：删除 VFS 门面与 `fs-ro` 变体即可；默认构建从未引用它，回滚不影响既有基线。
- 不可回滚的部分：一旦用户态拿到文件句柄并形成命令，`EBUSY`/绝对路径等语义需要按 ABI 兼容处理。

## 未决

1. 路径/名字的最终上限常数（首刀按夹具校准）。
2. LFN 何时实现；实现后 `lfn_entries==0` 判据如何改。
3. `open` 的 flags 位定义与 Rights 映射；只读之外何时开写。
4. `readdir` 游标归句柄还是调用方缓冲；重复调用的继续规则。
5. 多根挂载、相对路径、`chdir/getcwd` 的后续 ADR。
6. 写路径 ADR（簇分配、两份 FAT、部分写、flush、断电口径）。
7. `fs-ro` 是否/何时并入默认构建（需重跑基线）。
8. 两种 Shell 的统一路线。
9. RTC/ACPI 墙钟时间源。

## 补记（2026-11-15，FS-02 落地）

- **未决 2 关闭**：LFN 已实现——序号/0x40/组内校验和/与短名校验和绑定、UTF-16→UTF-8；
  校验失败退回短名并计入 `DirCursor::lfn_bad`，不把坏长名当成“文件不存在”。
- **未决 1 部分回答**：`NAME_MAX=12`、`LONG_NAME_MAX=255`（UTF-8 字节，超限置
  `long_truncated`）、`PATH_MAX=256`。非 ASCII 长名匹配按字节精确，不做 Unicode 大小写折叠。
- `Entry` 增加只读/隐藏/系统/归档属性与 FAT 创建/访问/写时间字段（原样，不是墙钟）；
  长名可用于路径分量，8.3 短别名仍可命中。
- **ESP 真卷**：`fs-ro` 下 `filesystem/gpt` 门控改为 `any(gpt-probe, fs-ro)`；
  `GPT → PartitionView → ReadOnlyFs` 读引导盘 ESP 的 `LIMINE.CON` 762 字节，与
  `boot/limine.conf` 逐字节相同；`base=0` 读到保护性 MBR 必须拒。
- **宿主工具缺陷（已修，见 BACKLOG §333）**：`tools/esp_image.py` 与
  `tools/validate_esp.py` 共用同一份错误的 VFAT 校验和算法（丢掉 rotate-right 的最高位），
  且校验器的 LFN 物理倒序判据写反；修后 `validate_esp.py` 独立通过。它**仍未接进门禁**。
- 仍开：未决 3–9；`fs-ro` 是否并入默认构建；长名截断的码点边界；目录游标并发；
  FAT32 真卷；`validate_esp.py` 接线。
