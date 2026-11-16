# ADR-108：FS-03 文件 ABI——open/seek/stat/readdir、卷A 单根与 VFS 句柄对象

状态：**已采纳**（2026-11-15；使用者选定完整 FS-03 与 FAT32 卷A，本 ADR 把 ADR-106 的建议号批准为逐号方案。实现分四个可红切片，本文是共同边界）
关联：ADR-007、ADR-074/075/077、ADR-078、ADR-106、ADR-107、BACKLOG §332/333、`docs/design/user-abi-capability.md`

> 本文关于新 ABI 的行为句子在实现与实跑前均为推断；各切片的验收只负责把它们逐条变成实测。

## 背景

- 现有产品句柄文件对象只存 `FileObj { port, part, FileCursor }`（`handle.rs:112-121`），
  游标来自根目录 `Volume::open_cursor`，不能携带 FS-02 的多级目录/长名元数据。
- `vfs_ro` 已有 `ReadOnlyFs::lookup/open/read`、`DirCursor`、`ReadCursor`（FS-01/02），但没有把游标
  交给句柄表的生命周期接口；`DirCursor` 是 Copy 固定结构，可进表槽。
- FAT32 卷A 只在 `fat32-probe`/`fat32-exec` 下接线（`tools/aurora.py:364-378`）；FS-03 需要一个
  只挂卷A、不引入昂贵 `t_fat32` 取证跑的 `fs-open` 变体。
- 产品 `init-user` 今天不授予文件句柄；若 FS-03 仍由内核代授，就不是 ADR-107 的“open 时授予”。
- ABI 现值 `0.11`；新增号段不改版本，调用方无法从 `abi_info` 读出能力是否存在。

## 决策

### 1. 特性与挂载根

- 新特性 `fs-open = ["handles", "fs-ro"]`。默认、`handles`、`wm` 构建都不编译新对象与新号。
- `fs-open` 的 QEMU 只额外挂 FAT32 卷A（口 3，`fat32-small`），不挂卷B，也不因依赖编译
  `t_fat32`。宿主机与内核的口号/夹具指纹必须同一格对账。
- 根挂载为整盘（`Partition` 为 `None`），挂载点 `/`；每次 syscall 按口 3 现建 `ReadOnlyFs`。
  FS-03 **不建全局 mount table**：表里没有跨调用的卷借用，失败语义更直接；以后多根再开 ADR。
- 当前真卷根目录只有 8.3 文件。多级路径由 FS-01/02 合成卷证明；FS-03 真卷只测根文件，
  **不许把“真卷根文件可开”写成“真卷多级已交付”**。

### 2. 系统调用号与 ABI 协商

- `ABI_MINOR` 升 `11 → 12`；新增特性位 `F_FS_OPEN = 512`，仅在 `fs-open` 构建读回真实状态。
- 逐号批准：

| 号 | 名称 | 参数 | 成功返回 | 首要错误 |
|---:|---|---|---|---|
| 22 | `SYS_FILE_OPEN` | `rdi`=路径 VA，`rsi`=字节长，`rdx`=flags | 文件/目录句柄 | -2 / -3 / -8 / -10 / -15 / -6 |
| 24 | `SYS_FILE_SEEK` | `rdi`=句柄，`rsi`=i64 偏移，`rdx`=whence（0/1/2） | 新偏移（`u64`） | -4 / -5 / -8 / -11 / -15 |
| 25 | `SYS_FILE_STAT` | `rdi`=句柄，`rsi`=StatV1 VA，`rdx`=缓冲区长 | `0` | -2 / -3 / -4 / -5 |
| 26 | `SYS_DIR_READ` | `rdi`=目录句柄，`rsi`=缓冲区 VA，`rdx`=字节长 | 写出的记录数（0=EOF） | -2 / -3 / -4 / -5 / -10 |

- 10 `SYS_FILE_READ`、8 `SYS_HANDLE_CLOSE` **不新增号**；10 扩展为同时接受既有 `FileObj`
  与新 VFS 文件对象。对既有句柄的返回值与游标提交规则逐字不变。
- 23 留给未来 write，不空占；27+ 继续按 ADR-106 逐号批准。

### 3. flags、权限与错误映射

- FS-03 只允许 `flags=0`（只读）。任何非零位回 `-15 ENOTSUP`，不是 `-14 EROFS`：
  此刻拒绝的是**尚未实现的 ABI**，不是“卷本身只读”这一设备状态。
- open 成功给句柄 `RIGHT_READ`；目录句柄也走同一对象类型，只是 `read` 返回 `-11 EISDIR`。
- 现有 `HErr` 映射保持；新 `VfsError` 映射如下（新增 ABI 负值按 ADR-106）：

| `VfsError` / 条件 | ABI |
|---|---|
| `BadPath`、`NotAbsolute`、flags 形状错 | -1 |
| `TooLong`、路径 len > `PATH_MAX`、缓冲记录不满 | -3 |
| `NotFound` | -8 |
| `NotDir`（把文件当目录 readdir） | -10 |
| `IsDir`（read 目录） | -11 |
| `DirTooLong`、簇链越界等卷损坏 | -7 |
| 非零 flags | -15 |
| 盘设备 `BlockError` | -7 |
| `Quarantined` | -7，并在日志点名 `已隔离` |

- 用户缓冲区故障一律 -2；已复制到用户内存但后续失败时不得提交游标，沿用 10 号形状。

### 4. StatV1 固定布局

内核侧与 `user/fileprobe` 侧各写一份布局，由测试读回对账；两边共用偏移表就只剩一台仪器。
记录长度固定 48 字节，小端：

| 偏移 | 字段 |
|---:|---|
| 0 | magic `u32` = `0x5346_5541`（"AUFS"） |
| 4 | `record_len u16` = 48 |
| 6 | `version u8` = 1 |
| 7 | `kind u8`：1=文件，2=目录，3=根 |
| 8 | `size u32` |
| 12 | `attr u8` |
| 13 | `short_len u8` |
| 14 | `long_len u16` |
| 16 | `first_cluster u32` |
| 20 | `entries_seen u32` |
| 24 | `lfn_entries u32` |
| 28 | `lfn_bad u32` |
| 32 | `create_time u16` |
| 34 | `create_date u16` |
| 36 | `access_date u16` |
| 38 | `write_time u16` |
| 40 | `write_date u16` |
| 42 | `create_tenths u8` |
| 43 | `flags u8`：bit0=`long_truncated` |
| 44 | reserved `u32`=0 |

`entries_seen`/`lfn_*` 是**本次打开扫过的覆盖面**，不是文件属性；保留它们是为了让“枚举确实走过”
可判，不允许调用方把它们当稳定值。

### 5. DirentV1 固定布局

记录长度固定 512 字节，一次 syscall 最多写 `floor(len/512)` 条且总长不得超过 `COPY_MAX`，
所以单调用上限 8 条；返回条数，0=EOF：

| 偏移 | 字段 |
|---:|---|
| 0 | magic `u32` = `0x4446_5541`（"AUFD"） |
| 4 | `record_len u16` = 512 |
| 6 | `version u8` = 1 |
| 7 | `kind u8`：1=文件，2=目录 |
| 8 | `short_len u8` |
| 9 | reserved `u8`=0 |
| 10 | `long_len u16`（0=无有效长名） |
| 12 | `attr u8` |
| 13 | `flags u8`：bit0=`long_truncated` |
| 14 | reserved `u16`=0 |
| 16 | `size u32` |
| 20 | `first_cluster u32` |
| 24 | `create_time u16` |
| 26 | `create_date u16` |
| 28 | `access_date u16` |
| 30 | `write_time u16` |
| 32 | `write_date u16` |
| 34 | reserved `u16`=0 |
| 36 | `entries_seen u32` |
| 40 | `lfn_entries u32` |
| 44 | `lfn_bad u32` |
| 48 | `short_name[12]` |
| 60 | reserved `[4]`=0 |
| 64 | `long_name[255]`（UTF-8；`long_len` 之外补 0） |
| 319 | reserved `[193]`=0 |

目录游标只保存调用者已消费到的位置；每次 syscall 成功后才提交。中途写用户内存失败，游标不动。

### 6. 句柄对象与容量

- `ObjRef` 在 `fs-open` 下新增：
  ```rust
  VfsFile { port: u8, cursor: ReadCursor, stat: Entry }
  VfsDir { port: u8, cursor: DirCursor, stat: Entry }
  ```
  `stat` 保存打开那一刻的目录项读数；它不是实时元数据，FS-03 没有写路径，因此不会变化。
- 既有 `FileObj` 与 10 号行为逐字保留。`ReadTicket` 扩展为 enum，只给文件对象产生票；
  `DirCursor` 不进入 read ticket。
- `MAX_HANDLES=64`。64 个 `VfsDir` 槽会显著增加 `.bss`，只在 `fs-open` 档承担；默认/handles/wm
  不变。容量负样本必须填满 64 格，第 65 格回 -6。
- `dup` 只复制游标值，两个句柄之后可各自推进；`close` 只撤名字，没有外部资源需要释放。

### 7. seek 语义

- 只支持文件句柄；目录回 `-15`。
- `whence`：0=自 0、1=自当前、2=自 EOF；`rdx` 的 i64 偏移可为负。
- 新位置必须 `0 <= new <= size`；越出 EOF 回 `-1`。FS-03 **不承诺稀疏 seek**，
  因为 FAT 游标需要保持簇号与 `clusters` 账同步。
- seek 是独立 syscall；10 号不隐式重置位置。

### 8. ring3 独立探针

- 新增第四个用户产物 `aurora-user-fileprobe`（包 `aurora-user-fileprobe`），只在 `fs-open`
  构建嵌入，不进签名链。它不依赖 Shell，从固定信箱槽回传：
  1. `abi_info` 的 major/minor/F_FS_OPEN；
  2. `SMALL.BIN` 的 open/read/seek/stat/EOF 字节数与首 8 字节 FNV；
  3. `NOTES` 的跨 chunk 读取与 seek 回 0 后同字节比较；
  4. `/` 的 `readdir` 三条记录、magic/record_len/短名/大小；
  5. 故意失败格：非绝对路径、不存在、read 目录、stat 缓冲过短、flags 非零、close 后用旧句柄。
- 宿主机第二台仪器独立解析卷A，算同名文件的大小/FNV/目录顺序；判定表行拿同一跑串口对账。
- 没有独立 ring3 探针时，`syscall_dispatch` ktest 只算 ABI 形状验证，不能把 FS-03 写成“用户空间已可访问文件”。

## 备选方案

1. **`open` 只支持根 8.3，复用现有 `FileCursor`**：实现最小，但 seek/stat/readdir 与多级路径
   会再逼出第二套游标；不选。
2. **每次 read 从路径重新 open**：表项只需存路径，但两个句柄的游标身份、打开时覆盖面读数与
   坏卷中途变化全被重开掩盖；不选。
3. **全局 mount table**：以后多根需要，但 FS-03 只有一个硬挂载点；先引入表只会让卸载与
   句柄生命周期没有判据。推迟。
4. **用 Shell 内置命令代替独立探针**：违背 V1.0 “文件系统操作由用户空间命令完成”，也会让
   Shell 与 ABI 的边界糊掉。不选。
5. **只升 feature bit、不升 ABI minor**：旧调用方会无法从版本号区分这一族 ABI 的出现；
   号表既然冻结在 `0.11`，新增必须升 `minor`。不选。

## 影响

- 正面：用户态第一次通过 `open` 拿文件句柄；10/8/24/25/26 形成可测的只读文件 API；
  默认与既有 wm/handles 行为不动。
- 负面：`ObjRef` 新变体增大 `fs-open` 句柄表；Stat/Dirent 是新的用户侧 ABI，以后修改要版本化；
  新增产物要进 unsafe 普查、SBOM、许可证留空与构建工具。
- 对既有测试：`ABI_MINOR` 从 11 到 12 会命中所有硬编码 `abi=` 读数的判据与文档，必须同轮改，
  不能只改内核。
- 对门禁：模块接口新增 `fs-open` 源与 test_targets；`check-fat32-ports` 必须同时识别口 3 在
  `fs-open` 下挂载且不得被别的盘占；interface-change 门禁依赖本文与代码同轮出现。

## 验收与负样本

### 切片 A：open/read/close

- 正样本：`/SMALL.BIN` open→read 100→EOF 0；`/NOTES` 分两次读，两次字节同宿主机对账。
- 负样本：
  - 未协商 `fs-open` 时打 22 回 -1；
  - flags≠0 回 -15；`SMALL.BIN` 路径 len 0、非绝对、不存在、>PATH_MAX；
  - open 目录成功，read 该句柄回 -11；
  - owner 用别的任务句柄读回 -4，close 后旧句柄 -5，填满 64 格后 -6。
- 证红：删掉 flags 校验或把 `VfsDir` 当文件打开，至少一格必须从 true 变 false。

### 切片 B：seek/stat

- 正样本：seek(0/50/EOF)、seek(-10 from EOF)、stat 48 字节逐字段与内核直接 VFS 读数同数。
- 负样本：new<0 或 >size；目录 seek -15；stat len=47；写坏用户缓冲后 seek 不提交。
- 证红：seek 不检查 EOF 时 `>size` 格必须红；stat magic/record_len 任一抄错，用户侧独立表必须红。

### 切片 C：readdir

- 正样本：根目录一次 1/2/3/8 条，多次推进无重复；每条 magic、len、kind、size、短名与宿主机同数。
- 负样本：文件句柄 readdir -10；len 不是 512 倍数 -3；len>COPY_MAX -3；中途写失败游标不提交；
  损坏簇链/目录项上界 -7；删除项/LFN 计数只计不解析。
- 证红：游标在 syscall 成功前提交，则失败重放那一格必须出现重复记录。

### 切片 D：ring3 fileprobe

- 正样本：探针信箱五项全对；宿主机独立读同一卷A，同 size/FNV/目录顺序。
- 负样本：
  - 注入 stat 偏移（内核表改、用户表不改）⇒ 探针点名字段错；
  - 注入 readdir 提交顺序 ⇒ 探针看到重复/跳项；
  - 不给 `fs-open` 特性而打 22 ⇒ 信箱 `abi_no_fs` 与内核默认 -1 两半同真；
  - 挂载根从口 3 改到不存在的口 ⇒ 探针不卡死，内核点名 -7。
- 判定表新增一行，拿自己那一跑的日志和退出码；`check-matrix-wiring` 验行名/日志变量互不共用。

## 迁移与回滚

- 纯增量：既有 `handles`、`fat32-exec`、`wm` 不获得新对象变体与新号；只新增 `fs-open`。
- 回滚 `fs-open`：删特性、盘线与 test_targets；若 ABI_MINOR 已发布给测试判据，回滚需把 11/12
  的硬编码一起还原，不能只关特性。
- StatV1/DirentV1 一旦探针进入测试基线，字段偏移视为 ABI；新增字段只能加版本化记录或末尾预留区。

## 未决

1. 真卷多级目录夹具：本机没有 mtools，现配方不能往卷A 加子目录；FS-02 合成卷只证解析器。
2. 23 write 的 `BlockWrite` 与分区写界；只读句柄到可写句柄的 rights 映射。
3. `readdir` 512 记录布局是否长期保留；未来可换更窄版本，但旧版本不能原地改义。
4. 多根 mount table 与卸载时已有句柄（`EBUSY`）的 ABI 号。
5. 是否把 `fs-open` 并入 `wm`，让图形终端真的从卷上开文件；需重跑显示与会话基线。

## 补记一（2026-11-16，切片 A/B/C 实跑）

决策 6 的 `VfsDir { cursor: DirCursor }` **按实现改成了 `state: DirState`**，理由是被实跑打回：
`DirCursor` 带 512 字节目录扇区与 LFN 片段缓存（约 1.5 KB/槽），第一版直接把它放进句柄表槽，
`fs-open` 档实跑 **HANG**。`DirState{bpb,dir,skipped,exhausted}` 不缓存扇区，每次从目录头走到
`skipped` 之后再取一条——代价是 O(n²)，这是取证形状而不是产品吞吐（未决 6 见下）。槽尺寸因此
与既有 `FileObj` 同量级，决策 6 关于 `.bss` 的判断照旧成立。其余偏移、号、错误映射逐字按本文。

同轮实测（BACKLOG §334）：

- 取证行：`fs-open: 取证 读回=100 摘要=0x6d8f5d947de075cd stat大小=100 首簇=67 条目1=HELLO.ELF/32672 条目2=NOTES/1000`，
  `ktests 94/94`，`判定=PASS(33)`，ELF sha `c900b3d50696`。
- `check` 17/17；default / `handles` / `fs-ro` / `fs-open` / `fat32-exec,handles` / `wm,ps2-kbd,ps2-mouse`
  六档全编译；判定表 58 行 58 符合 / 0 不符合（新增"FS-03文件ABI与卷A对账"一行）。
- 决策 3 的两格实测口径：`seek` 越 EOF 回 **-1**，目录 `seek` 回 **-15**，与本文表格一致。
- 前置修复：`t_handle_table` 把 slot 16 当非法而 `MAX_HANDLES=64`，改为按 `MAX_HANDLES` 派生
  （BACKLOG §334）。这是 FS-03 的第 65 格容量负样本能成立的前提。
- 新增的宿主机仪器：`fat32_host_volume` 多返回一个 `dirlist`（按盘上顺序列**可见项**，含子目录，
  跳卷标/LFN 片段/已删除）。readdir 的判据是序列而不是查表，原来的 `files` 字典没有顺序语义。
- **未决 6**：切片 D 的 ring3 `fileprobe` 仍未交付，因此本文决策 8 那句话现在成立为反面：
  只有 `syscall_dispatch` ktest，就**不能**写"用户空间已可访问文件"。

## 补记二（2026-11-16，切片 D 实跑：ring3 探针交付）

决策 8 交付了 `user/fileprobe`（第四个用户产物，基址 0x1000c0000，`.slots` 独占一页），
`t_fs_open_ring3` 真装载真跑，判定表新增第 43 行"FS-03ring3探针与卷A对账"。读数与欠账见 BACKLOG §335。

真 ring3 调用者抓到两件 ktest 没抓到的事，本文据此**改口径**：

1. 决策 3 那句"目录句柄也走同一对象类型，只是 `read` 返回 `-11 EISDIR`"**当初并不成立**：
   `handle::begin_read` 的兜底分支把 `VfsDir` 读成类型不符 ⇒ ring3 收到 `-4`。已补 `VfsDir` 那一格。
   这条判据现在由 ring3 那行与 `t_fs_open_syscalls` 一起成立；**它是探针交付的直接收益**，
   也印证了本文决策 8 的理由——没有真调用者，`-11` 那句话只是表格里的字符。
2. 探针必须把**目录句柄也 close**，否则"表清空"那一格 `live=1`。`close 只撤名字` 的判据
   因此按"每个开过的句柄都撤过"来写，而不是"打了一次 close"。

两条实测边界，写进本文而不是留给读者想象：

- **栈预算**：ring3 的 22 号那条链在 4 页用户任务内核栈上用到 16,760 字节，越过 guard 页 ⇒
  `#DF(8)` 死循环（判定 HANG）。`vfs_ro::lookup` 单帧实测 4,568 字节。本轮的处理是
  `sched::USER_KSTACK_PAGES`：只有 `fs-open` 档的用户任务栈 4→8 页。
  **这不等于那条链被修好了**——把 VFS 的帧压回 4 页以内是本 ADR 的欠账 ①，
  在它还清掉之前，任何"从 ring3 打开更深的多级路径"的设计都必须先重算这段峰值。
- **对照量不用哈希**：决策 8 原写"回传首 8 字节 FNV"。ring3 自己那份 FNV 与核内、宿主机的
  低 32 位逐次相同、高 32 位不同，**这个数字没解释，就不当判据**（BACKLOG §335 欠账 ②）。
  两侧契约因此换成大小、首簇、首尾 8 字节、字节和、条数、名字字节和——同一句话，
  用的量没有实现依赖。`t_fs_open_syscalls` 那行的核内 FNV 与宿主机 FNV 仍然一致，不动。

未决更新：本文开头"未决 6"关闭（探针已交付并实跑）；仍未做的是**产品启动路径不 spawn 它**
（`init` 那边一个文件句柄都不领），以及真卷多级目录夹具（未决 1）。

## 补记三（2026-11-16，两项欠账的处理）

**欠账②（ring3 那份 FNV 高 32 位分歧）结案**，根因在本文决策 8 的探针实现里：素数字面量被写成
12 位十六进制 `0x1000_0000_01b3`（= 2^44+435），正确值是 2^40+435 = `0x0000_0100_0000_01b3`。
追查靠的是差值全为 2^40 的整数倍这一形状——FNV 的 435 是奇数，所以"读错字节"必然污染低 32 位，
低 40 位一致就排除了输入差异。结案之后把它升成判据，而不是留成故事：

- 探针同一份字节跑两种写法（`wrapping_mul` 与 `t*435 + (t<<40)`），两格**必须同数**；
- `FNVMUL` 还必须等于 `expect::SMALL_FNV`，也就是核内 `ahci::fnv1a64` 与宿主机 `fnv1a64` 那份
  ⇒ 决策 4/5 那条"两侧各写一份、由读回的数对账"从 StatV1/DirentV1 扩到了摘要本身。
- 修字面量**之前**那一跑就是这判据的证红：`ktests 94/95`、`判定=FAIL(35)`，红在新加的那一格。

**欠账①（那条链的栈峰值）没修好，本轮只交出了量尺**。实测：`lookup` 入口之前上游已经吃掉
17,088 字节，`lookup` 单帧 4,568 字节 ⇒ 峰值 ≈21.7 KB；4 页（16,384）必撞 guard 页，8 页 PASS。
两次拆帧试验（四个 FS 号从 `syscall_dispatch` 拆出、`next_entry_disk` 从 `find_child` 拆出）
在撞栈读数上一位都不变，已撤；页数二分因 `mm::phys_alloc` 只按 2 的幂开（5/6/7 页会变成 1 页）而作废。
因此本 ADR 现在的立场要写准：**决策 6 之外还有一条未兑现的尺寸前提**——`fs-open` 的用户任务内核栈
被提到 8 页（`sched::USER_KSTACK_PAGES`），这是补偿不是修复。真正的修法是一个设计决定，二选一：

1. 把 1.1 KiB 的 `DirCursor` 从栈搬到堆（`LARGE_MAX = 2048` 之内，且只在 syscall 路径分配——
   故障路径仍然不许分配，ADR-018/026 的口径不动）；
2. 先把上游那 17 KB 里**目前解释不到的 ~9.7 KB 归因**（`dispatch 4,096 + open 1,496 + mount 1,656 + trap 帧`
   只到 7.4 KB），归因之后再谈要不要搬。

在它归掉之前，任何"往这条链上再叠东西"（例如 23 号 write 的缓冲、多级路径的额外游标）都必须先重算这个峰值。

## 补记四（2026-11-16，欠账①结案，并撤回补记三里的两条错读数）

补记三把欠账①写成"没修好，8 页是 shipped 补偿"。**现在它修好了，补偿已撤**（`sched.rs` 回到 HEAD，
用户任务内核栈仍是所有档共同的 4 页）。结案的同时必须撤回两条量具错：

1. `syscall_dispatch` 的帧**不是 4,096 字节，是 10,584**。脚本对每个函数只取单个 `subq $N,%rsp` 的最大值，
   而 rustc 对超过一页的帧发两段栈探测（`sub 0x1000` 之后再 `sub 余量`）。按序言里 `sub` 的累加重算才是对的。
2. "拆帧之后撞栈读数一位都不变"这个证据**无效**：撞 guard 页时 `rsp` 钉在边界上，超出 400 字节与超出 9 KB
   打出同一个字。据它撤掉的正是正确的修法。要量这条链，得在**调用方一侧**读 `rsp`。

结案后的实测（BACKLOG §337）：22 号那条链沿帧相加 = `dispatch 144 + sys_file_open 1,352 +
fs_open::open 1,496 + Volume::mount 1,656 + lookup 4,520 + next_entry_disk 648 + read_disk 1,224
= 11,040 字节`，4 页 = 16,384 ⇒ 余约 5.3 KB（未扣 trap 帧与中断窗口）。`fs-open` 档 `ktests 95/95`、
判定表 59 行 59 符合 / 0 不符合。

**因此本 ADR 的尺寸前提改成一条可核对的约束，而不是补偿**：往 `syscall_dispatch` 里再内联任何带缓冲的分支，
就是把那条缓冲的钱付在**每一个** syscall 上；新增号请一律 `#[inline(never)]`。
补记三列的两个设计选项（把 `DirCursor` 搬上堆 / 先归因上游那 ~9.7 KB）里，第二个已经通过归因结案；
第一个不再需要——它当初是为补救一个被读错的帧尺寸而提的。

## 补记五（2026-11-16）：未决 1 结案（两级调用者都已跨到三级）

`fs-open` 的挂载根换到多级真卷之后（ADR-109 补记二 / BACKLOG §342），

- **ring0 的 `t_fs_open_syscalls`** 在真盘上走过了三级 `lookup`、跨两簇目录、子目录 LFN 与首簇高半非零；
- **ring3 的 `user/fileprobe`** 本轮补上同一段（开 `/PROJECT/DOCS/NESTED.TXT` 读到底 + stat + close，
  开 `/PROJECT` 读目录），十二个槽位在探针与用例两处各写一份，见 BACKLOG §343。

所以本文"未决 1：真卷只测根文件"**结案**。仍开着的是它的边界：`MAX_COMPONENTS = 16` 这条上限
没有被真深链喂过（夹具只有三层，十七级路径的负样本要另造一条深链）——那是夹具的事，
不是"多级路径没证过"。

## 补记六（2026-11-16）：块设备/VFS 的盘失败统一 `-7`（EIO）

用户裁决：`HErr::Io(_)` 从旧的 `-2` 改成 `-7`（`AbiError::Io`）。旧口径的理由是"避免 10 号
旧调用方的返回集合变宽"，但全仓没有任何一格钉住 `-2`（`E_FAULT` 只被坏指针用），所以这次换掉：
分区越界、设备报错、超时/取消都从 `BlockError` 原样上来，不再降级成"参数坏了"。

证据：`t_fs_rw_syscall23` 授一个**空分区区间**（`Partition{base:0,last:0}`）的 VfsFile，
`handle::read` 在翻译之前被 `PartitionView` 拒 ⇒ `HErr::Io(BeyondPartition)` ⇒
同一张 `user::handle_err` 表给 `-7`（串口 `盘失败=-7`）。变异：把 `E_IO` 改回 `E_FAULT` ⇒
`盘失败=-2` 且该格红；还原后 `fs-rw` 99/99。`handle_err` 因此升成 `pub(crate)`，只为了让用例
拿同一张表而不是另抄一份。

**未决 7（新记）**：`sys_file_read`/`sys_file_write` 拿到票后**没有**按 `ticket.partition()` 包
`PartitionView`——今天所有 `VfsFile` 都是 `part=None` 所以读不到症状，但一旦有分区内的文件句柄，
syscall 会读到分区外的字节而那看起来"读成功了"。试过补它：运行期对 `None` 等价，却让
`t_fs_open_ring3` 从"偶发绿"变成**同 ELF 连续 6 次红**、撤回后 3 次连绿（`fs-open` 97/97，
ELF `299b60dfaff5`）⇒ 这是一个布局/栈敏感的下游，**不能靠"语义等价"就合入**；要另开一刀
先把它定位（BACKLOG §364）。
