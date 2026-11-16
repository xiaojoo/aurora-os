下面这份文档以你上传的 `aurora-os-main.zip`（2026-11-15 源码快照）为基线编写，不是从零设计一套新文件系统。

我特别调整了一个重要判断：**Aurora OS 已经有 FAT16/FAT32 解析、文件游标读取、GPT 只读解析和块设备抽象。真正需要建设的是从现有只读存储能力向通用文件系统、用户空间文件 API 和 Shell 命令体系的演进。**

文档会保留现有架构和已采纳 ADR 的约束，不把已经完成的能力重复开发。

# Aurora OS 文件系统与 Shell 命令体系建设设计文档 V1.0

**项目名称：** Aurora OS\
**文档版本：** V1.0\
**文档类型：** 系统架构与工程实施设计\
**基线版本：** aurora-os-main 源码快照（2026-11-15）\
**开发语言：** Rust\
**目标架构：** x86-64\
**内核架构：** 模块化宏内核\
**文档状态：** 初版设计，待实施评审

---

# 1. 项目背景

## 1.1 建设背景

Aurora OS 已经具备基础的存储设备访问能力，并且完成了部分文件系统解析、文件读取和用户空间 Shell 的开发。

当前系统已经具备：

- AHCI 块设备读取。
- GPT 分区表解析（特性门控）。
- FAT16 文件系统解析。
- FAT32 文件系统解析。
- 文件元数据读取。
- 文件簇链遍历。
- 文件游标与偏移读取。
- 文件句柄管理。
- 用户空间文件读取系统调用。
- 用户空间交互式 Shell。

但目前文件系统仍以只读访问和专项验证为主，尚未形成完整的通用文件系统服务。

Shell 也只具备基础交互能力，缺少大量常用文件和目录管理命令。

因此，需要建设一套完整的文件系统基础设施及用户空间命令体系，使 Aurora OS 从基础文件读取能力逐步发展为具备实际文件管理能力的操作系统。

## 1.2 建设目标

本项目的总体目标是：

建立统一、可扩展、模块化的文件系统架构，完善内核文件系统接口、用户空间文件 API、Shell 命令执行机制，并逐步实现常见 Linux 风格文件系统命令。

最终实现：

1. 支持文件和目录的完整访问。
2. 支持文件创建、读取、写入、删除和重命名。
3. 支持多级目录和路径解析。
4. 支持文件属性和权限管理。
5. 支持多个文件系统实例及挂载管理。
6. 支持用户空间独立命令程序。
7. 支持 Shell 参数解析、管道和重定向。
8. 为未来扩展其他文件系统预留统一接口。
9. 确保文件系统异常不会无故扩大为整个内核故障。

## 1.3 非目标

本阶段不以完整复制 Linux 为目标。

以下能力暂不纳入首期：

- ext4 完整实现。
- Btrfs。
- ZFS。
- 分布式文件系统。
- 网络文件系统。
- 完整 POSIX 兼容。
- 完整 Linux GNU Coreutils 兼容。
- 复杂文件系统日志恢复。
- 文件系统加密。

这些能力应在基础架构稳定后逐步评估。

---

# 2. 现有系统架构与源码基线

本章以本次提供的源码为依据。

## 2.1 现有目录结构

当前文件系统相关源码主要分布在：

```
aurora-os-main/
├── kernel/
│   └── src/
│       ├── filesystem/
│       │   ├── mod.rs
│       │   ├── fat32.rs
│       │   ├── gpt.rs
│       │   └── vfs.rs
│       ├── handle.rs
│       ├── user.rs
│       └── ktests/
│           ├── syscall.rs
│           └── user.rs
│
├── user/
│   ├── shell/
│   │   ├── Cargo.toml
│   │   ├── link.ld
│   │   └── src/
│   │       └── main.rs
│   ├── hello/
│   └── probe/
│
├── tools/
├── docs/
├── BACKLOG.md
└── Cargo.toml
```

说明：

当前 `fat32.rs` 实际已经包含 FAT16 与 FAT32 两种文件系统的结构判型和读取逻辑，不应因为文件名而误认为只支持 FAT32。

`vfs.rs` 当前主要提供块设备抽象和分区视图等能力，还不能视为已经完成了完整的 VFS（Virtual File System）。

## 2.2 已有能力

### 2.2.1 块设备抽象

文件位置：

`kernel/src/filesystem/vfs.rs`

当前已有：

- `Block` 块设备读取接口。
- `BlockError` 错误分类。
- `AhciDisk` 生产实现。
- `MemDisk` 内存测试实现。
- `Partition` 分区范围。
- `PartitionView` 分区偏移视图。

块设备接口目前采用按扇区读取的方式：

```
pub trait Block {
    fn read_sectors(
        &self,
        lba: u64,
        dst: &mut [u8],
    ) -> Result<(), BlockError>;
}
```

当前块层以只读访问为主。

未来需要在保持原有只读接口语义的前提下，设计独立的写入能力。

### 2.2.2 FAT 文件系统

文件位置：

`kernel/src/filesystem/fat32.rs`

已经实现：

- FAT16/FAT32 结构判型。
- BPB 解析。
- 文件系统几何计算。
- FAT 簇链读取。
- 文件查找。
- 文件大小和起始簇读取。
- 文件流式读取。
- 文件游标。
- 文件偏移读取。
- 文件链完整性检查。
- FAT16 固定根目录区处理。
- FAT32 根目录簇处理。

已有主要接口：

```
Volume::mount()
Volume::open()
Volume::walk()
Volume::open_cursor()

FileCursor::read()
FileCursor::position()
FileCursor::stat()
```

当前仍存在的功能缺口：

- 完整的多级目录遍历。
- 长文件名完整解析。
- 目录项统一枚举。
- 文件创建。
- 文件写入。
- 文件删除。
- 文件重命名。
- 目录创建。
- 目录删除。
- 文件属性修改。

注意：现有 `Volume::mount()` 语义必须保持兼容，不能擅自把分区自动发现逻辑塞进去。

### 2.2.3 GPT 分区管理

文件位置：

`kernel/src/filesystem/gpt.rs`

当前 GPT 解析通过特性门控，已经具有独立的只读解析方向。

需要区分：

- GPT 负责分区表解析。
- 分区视图负责分区范围内的块访问。
- FAT 负责具体卷的文件系统解析。
- 挂载管理负责把文件系统实例接入统一文件系统服务。

不能把这些职责合并成一个模块。

### 2.2.4 用户空间文件读取

文件位置：

`kernel/src/user.rs`

当前已有：

`SYS_FILE_READ = 10`

并通过文件句柄、读取票据、用户缓冲复制和游标提交机制完成读取。

当前设计中的重要约束必须继续保留：

- 用户缓冲区必须经过安全校验。
- 文件读取采用分块方式。
- 不允许按照用户任意输入大小直接分配内核缓冲区。
- 设备 I/O 期间不能持有不必要的全局表锁。
- 用户缓冲复制失败时不能错误提交文件游标。
- 句柄必须检查所有权和访问权限。

### 2.2.5 Shell

文件位置：

`user/shell/src/main.rs`

当前 Shell 是独立的用户空间程序。

已有命令：

```
help
echo
ping
abi
exit
```

当前采用简单命令分派，尚未形成完整的命令解析器和独立命令程序体系。

Shell 使用 `no_std`、`no_main`，并通过 `int 0x80` 进入内核。

后续不能直接假设标准 Linux 用户空间库、POSIX API 或完整进程执行接口已经存在。

---

# 3. 总体架构设计

## 3.1 架构原则

本项目采用分层架构。

主要原则：

1. 内核只负责基础系统能力。
2. 文件系统驱动不直接依赖具体磁盘驱动。
3. 文件系统格式解析与统一文件访问接口分离。
4. 文件系统操作尽可能由用户空间命令完成。
5. Shell 不直接操作文件系统内部结构。
6. 所有系统调用必须经过权限、句柄和内存安全检查。
7. 各层之间使用明确的数据结构和接口。
8. 保留现有模块，采用渐进式扩展。

## 3.2 目标架构

```
┌─────────────────────────────────────────────┐
│                 User Space                  │
│                                             │
│  ┌───────────────────────────────────────┐  │
│  │              Aurora Shell             │  │
│  │                                       │  │
│  │  Parser / Executor / Pipeline / I/O   │  │
│  └───────────────────┬───────────────────┘  │
│                      │                      │
│  ┌───────────────────▼───────────────────┐  │
│  │             Coreutils                 │  │
│  │                                       │  │
│  │ ls cat cp mv rm mkdir rmdir stat      │  │
│  │ find grep head tail wc df du ...      │  │
│  └───────────────────┬───────────────────┘  │
│                      │                      │
│  ┌───────────────────▼───────────────────┐  │
│  │           User Runtime / LibC         │  │
│  │                                       │  │
│  │ File API / String / Memory / Error    │  │
│  └───────────────────┬───────────────────┘  │
└──────────────────────┼──────────────────────┘
                       │
                 System Call ABI
                       │
┌──────────────────────▼──────────────────────┐
│                  Kernel                     │
│                                             │
│  ┌───────────────────────────────────────┐  │
│  │          System Call Interface        │  │
│  └───────────────────┬───────────────────┘  │
│                      │                      │
│  ┌───────────────────▼───────────────────┐  │
│  │          File Handle Manager           │  │
│  │                                       │  │
│  │ Ownership / Rights / Cursor / Lifetime│  │
│  └───────────────────┬───────────────────┘  │
│                      │                      │
│  ┌───────────────────▼───────────────────┐  │
│  │          Virtual File System           │  │
│  │                                       │  │
│  │ Path / Inode / Dentry / File / Mount  │  │
│  └───────────────────┬───────────────────┘  │
│                      │                      │
│  ┌───────────────────▼───────────────────┐  │
│  │         Filesystem Implementations    │  │
│  │                                       │  │
│  │          FAT16 / FAT32 / tmpfs         │  │
│  └───────────────────┬───────────────────┘  │
│                      │                      │
│  ┌───────────────────▼───────────────────┐  │
│  │          Block Device Layer            │  │
│  │                                       │  │
│  │         AHCI / VirtIO / MemDisk        │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

## 3.3 模块职责

| 模块             | 职责               |
| -------------- | ---------------- |
| Shell          | 命令解析和执行          |
| Coreutils      | 实际命令实现           |
| User Runtime   | 用户空间统一 API       |
| Syscall        | 用户态与内核态接口        |
| Handle Manager | 句柄和权限管理          |
| VFS            | 统一文件访问抽象         |
| FAT            | FAT16/FAT32 格式实现 |
| tmpfs          | 内存文件系统           |
| Block Device   | 块设备访问            |
| GPT            | 分区表解析            |
| Mount Manager  | 文件系统挂载           |

---

# 4. VFS 虚拟文件系统设计

## 4.1 建设目标

VFS 是本项目的核心基础设施。

其目的不是重新实现 FAT，而是为不同文件系统提供统一的文件和目录访问接口。

未来增加新的文件系统时，Shell 和 Coreutils 不需要感知底层文件系统类型。

## 4.2 模块设计

建议逐步建立：

```
kernel/src/filesystem/
├── mod.rs
├── vfs.rs
├── gpt.rs
│
├── vfs/
│   ├── inode.rs
│   ├── dentry.rs
│   ├── file.rs
│   ├── path.rs
│   ├── mount.rs
│   ├── directory.rs
│   ├── metadata.rs
│   └── error.rs
│
├── fat32.rs
│
└── tmpfs.rs
```

注意：

当前 `vfs.rs` 已经承载块设备抽象。实施时应先评估是否将块设备部分迁移为 `block.rs`，并保留原接口的兼容层。

不允许一次性移动整个文件系统模块。

## 4.3 核心数据结构

### Inode

表示文件系统中的文件对象。

建议字段：

```
pub struct InodeMetadata {
    pub inode_id: u64,
    pub file_type: FileType,
    pub size: u64,
    pub permissions: u16,
    pub links: u32,
}
```

文件类型：

```
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    Device,
}
```

其中，符号链接和设备文件属于未来扩展能力，首期可以暂不开放。

### Dentry

表示目录项和路径关系。

主要职责：

- 目录项名称。
- 父目录关系。
- 对应 inode。
- 路径解析缓存。
- 生命周期管理。

### File

表示一个已经打开的文件实例。

建议管理：

- 文件对象。
- 当前偏移。
- 打开标志。
- 访问权限。
- 文件系统引用。

### Mount

表示挂载实例。

建议包含：

- 挂载 ID。
- 挂载点。
- 文件系统类型。
- 文件系统根目录。
- 底层设备引用。
- 挂载状态。

## 4.4 文件系统统一接口

建议采用 Rust trait。

```
pub trait FileSystem {
    fn root(&self) -> Result<InodeRef, FsError>;

    fn lookup(
        &self,
        parent: &InodeRef,
        name: &str,
    ) -> Result<InodeRef, FsError>;

    fn read(
        &self,
        inode: &InodeRef,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, FsError>;

    fn write(
        &self,
        inode: &InodeRef,
        offset: u64,
        buffer: &[u8],
    ) -> Result<usize, FsError>;

    fn create(
        &self,
        parent: &InodeRef,
        name: &str,
        file_type: FileType,
    ) -> Result<InodeRef, FsError>;

    fn unlink(
        &self,
        parent: &InodeRef,
        name: &str,
    ) -> Result<(), FsError>;

    fn rename(
        &self,
        old_parent: &InodeRef,
        old_name: &str,
        new_parent: &InodeRef,
        new_name: &str,
    ) -> Result<(), FsError>;

    fn readdir(
        &self,
        inode: &InodeRef,
        cursor: &mut DirCursor,
    ) -> Result<Option<DirEntry>, FsError>;
}
```

以上是目标接口草案，不是可以直接替换现有代码的完整实现。

实际落地时必须处理：

- 目录和文件类型约束。
- 引用生命周期。
- 文件系统实例所有权。
- 并发访问。
- 目录遍历游标。
- 文件系统错误映射。
- 读写权限。
- 不支持的操作。

不支持的能力必须明确返回错误，不能静默成功。

## 4.5 路径解析

统一支持：

```
/
 /home
 /home/user
 /home/user/file.txt
```

目标支持：

- 绝对路径。
- 相对路径。
- 当前工作目录。
- `.`。
- `..`。
- 多级目录。
- 重复斜杠规范化。
- 路径长度限制。
- 文件名长度限制。

路径解析必须在 VFS 中统一处理，不能让 FAT、Shell 和各个命令分别实现不同版本。

---

# 5. FAT16 / FAT32 文件系统完善

## 5.1 基本原则

继续复用：

`kernel/src/filesystem/fat32.rs`

不重新编写 FAT16/FAT32 解析器。

在当前只读实现基础上，逐步增加目录遍历和写入能力。

## 5.2 第一阶段：目录读取

实现：

- 根目录枚举。
- 子目录读取。
- 多级目录。
- 目录项类型判断。
- 长文件名 LFN。
- 目录遍历游标。
- 文件属性读取。
- 目录项错误检查。

验收示例：

```
/
├── boot/
│   ├── kernel.elf
│   └── config.txt
├── home/
│   └── user/
│       └── readme.txt
└── system/
```

执行：

```
ls /
ls /boot
ls /home/user
```

必须读取真实目录项，而不是返回预设文本。

## 5.3 第二阶段：文件写入

实现：

- 文件创建。
- 文件覆盖。
- 文件追加。
- 文件截断。
- 文件扩展。
- 簇分配。
- 簇释放。
- FAT 表更新。
- 多份 FAT 同步。
- 目录项更新。

建议将写入能力独立封装，避免影响当前读取路径。

写入必须遵守：

1. 写入前验证目标卷。
2. 检查可用簇。
3. 检查目标目录项。
4. 检查写入范围。
5. 更新 FAT 链。
6. 更新文件长度。
7. 更新目录项。
8. 处理设备写入失败。
9. 明确报告可能存在的部分写入。

第一版 FAT 写入不宣称具备日志事务和断电恢复能力。

## 5.4 第三阶段：目录修改

实现：

- `mkdir`
- `rmdir`
- 目录重命名。
- 目录删除。
- 目录项创建。
- 目录项回收。

必须禁止：

- 删除非空目录。
- 删除正在使用且受保护的系统对象。
- 把普通文件当作目录。
- 把目录当作普通文件写入。

## 5.5 第四阶段：文件属性

支持：

- 文件大小。
- 创建时间（文件系统有记录时）。
- 修改时间。
- 文件属性。
- 只读标志。
- 隐藏标志。
- 系统文件标志。

FAT 原生权限能力有限，不能直接宣称已经具备完整 Unix 权限语义。

---

# 6. 块设备与分区管理

## 6.1 现有能力

当前已有：

- AHCI 块设备读取。
- GPT 只读解析。
- 分区视图。
- MemDisk 测试实现。

现有分区能力与文件系统挂载必须保持分离。

## 6.2 块设备接口扩展

建议新增独立写入能力：

```
pub trait BlockWrite {
    fn write_sectors(
        &self,
        lba: u64,
        src: &[u8],
    ) -> Result<(), BlockError>;
}
```

不要直接改变现有 `Block` 只读接口的语义。

后续可以增加：

```
pub trait BlockDevice: Block + BlockWrite {
    fn capacity_sectors(&self) -> Result<u64, BlockError>;

    fn flush(&self) -> Result<(), BlockError>;
}
```

实际是否合并为一个 trait，应根据现有驱动和设备能力确定。

## 6.3 分区管理

目标支持：

- 查看磁盘。
- 查看分区。
- 获取分区类型。
- 获取分区大小。
- 获取分区 UUID。
- 挂载指定分区。
- 卸载指定分区。

GPT 解析仍保持独立，不将分区发现隐式加入现有 `Volume::mount()`。

---

# 7. 系统调用 ABI 设计

## 7.1 建设目标

目前用户空间只有基础文件读取能力。

后续需要形成统一的文件系统系统调用接口。

所有调用都必须遵循现有 `int 0x80` ABI 约定。

新增调用必须登记唯一编号，并更新 ABI 文档及相关测试。

不能覆盖现有系统调用号。

## 7.2 目标系统调用

| 接口       | 功能     | 优先级    |
| -------- | ------ | ------ |
| open     | 打开文件   | P0     |
| read     | 读取文件   | 已有基础   |
| write    | 写入文件   | P0     |
| close    | 关闭句柄   | 已有句柄基础 |
| seek     | 修改文件偏移 | P0     |
| stat     | 获取文件信息 | P0     |
| readdir  | 读取目录   | P0     |
| mkdir    | 创建目录   | P0     |
| rmdir    | 删除目录   | P1     |
| unlink   | 删除文件   | P1     |
| rename   | 重命名    | P1     |
| truncate | 截断文件   | P1     |
| fsync    | 同步文件   | P1     |
| mount    | 挂载文件系统 | P2     |
| umount   | 卸载文件系统 | P2     |

以上为目标 API，不代表这些接口已经存在。

## 7.3 文件打开标志

建议定义：

```
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
    pub append: bool,
}
```

约束：

- 不能无权限写入。
- 不能无权限删除。
- 不能访问未授权句柄。
- 不能通过非法参数绕过文件系统边界。
- 不能将用户提供的指针直接用于内核解引用。

## 7.4 错误码

建立统一错误映射：

```
EINVAL       参数错误
ENOENT       文件不存在
EEXIST       文件已存在
ENOTDIR      不是目录
EISDIR       是目录
ENOSPC       空间不足
EACCES       权限不足
EBADF        无效句柄
EIO          设备 I/O 错误
ENOTEMPTY    目录非空
EROFS        只读文件系统
ENOTSUP      不支持的操作
```

实际错误码需要与当前 ABI 已批准的错误码兼容，不能直接更改既有错误语义。

---

# 8. 用户空间运行库设计

## 8.1 建设目标

避免每个命令重复编写系统调用汇编和参数检查。

建立用户空间统一运行库。

建议目录：

```
user/
├── runtime/
│   └── src/
│       ├── syscall.rs
│       ├── file.rs
│       ├── directory.rs
│       ├── error.rs
│       ├── string.rs
│       └── io.rs
│
├── shell/
├── coreutils/
└── programs/
```

## 8.2 文件 API

建议统一提供：

```
open()
read()
write()
close()
seek()
stat()
mkdir()
rmdir()
unlink()
rename()
readdir()
```

这些 API 负责：

- 参数转换。
- 系统调用封装。
- 错误转换。
- 缓冲区管理。
- 文件句柄生命周期。

首期不要求完整 POSIX libc。

---

# 9. Coreutils 命令体系

## 9.1 命令设计原则

所有文件系统命令原则上放在用户空间。

命令通过统一 Runtime API 访问文件系统。

不允许：

- Shell 自己解析 FAT 目录项。
- 每个命令直接访问 AHCI。
- 为了实现命令而在内核中增加同名功能。
- 用固定文本伪造文件系统结果。

## 9.2 第一批：基础命令

| 命令    | 功能     | 依赖          |
| ----- | ------ | ----------- |
| pwd   | 当前目录   | 工作目录        |
| cd    | 切换目录   | 工作目录        |
| ls    | 查看目录   | readdir     |
| cat   | 输出文件   | open/read   |
| touch | 创建文件   | open/create |
| mkdir | 创建目录   | mkdir       |
| rmdir | 删除目录   | rmdir       |
| rm    | 删除文件   | unlink      |
| cp    | 复制文件   | read/write  |
| mv    | 移动文件   | rename      |
| stat  | 查看属性   | stat        |
| file  | 查看文件类型 | stat        |

说明：

`cd` 由 Shell 内部处理，因为它修改当前 Shell 的工作目录。

## 9.3 第二批：文件查看与搜索

| 命令       | 功能     |
| -------- | ------ |
| head     | 查看文件开头 |
| tail     | 查看文件末尾 |
| less     | 分页查看   |
| more     | 分页查看   |
| wc       | 统计文件   |
| grep     | 文本搜索   |
| find     | 递归查找   |
| sort     | 排序     |
| uniq     | 去重     |
| diff     | 比较文件   |
| tree     | 树状目录   |
| basename | 获取文件名  |
| dirname  | 获取目录名  |

这一批主要依赖已有文件读取能力和目录遍历能力。

## 9.4 第三批：磁盘和权限管理

| 命令     | 功能     |
| ------ | ------ |
| df     | 文件系统空间 |
| du     | 目录空间统计 |
| mount  | 挂载文件系统 |
| umount | 卸载文件系统 |
| blkid  | 查看分区标识 |
| lsblk  | 查看块设备  |
| sync   | 同步存储   |
| chmod  | 修改权限   |
| chown  | 修改所有者  |
| chgrp  | 修改所属组  |
| umask  | 默认权限掩码 |
| fsck   | 检查文件系统 |

注意：

这些命令需要对应的内核接口、设备管理能力和文件系统能力。

例如 FAT 的权限语义不能直接等同于 Unix 权限。

`fsck` 需要独立的检查和修复工具，不能直接把读取失败当成文件系统损坏。

## 9.5 第四批：压缩和打包

| 命令     | 功能       |
| ------ | -------- |
| tar    | 文件打包     |
| gzip   | gzip 压缩  |
| gunzip | gzip 解压  |
| zip    | ZIP 打包   |
| unzip  | ZIP 解压   |
| xz     | xz 压缩    |
| bzip2  | bzip2 压缩 |

压缩算法属于用户空间能力，不应进入内核。

---

# 10. Aurora Shell 重构设计

## 10.1 当前问题

目前 Shell 通过简单字符串匹配实现命令分派。

随着命令增加，会出现：

- 参数解析复杂。
- 选项处理困难。
- 引号处理困难。
- 命令代码越来越集中。
- 命令执行与交互逻辑耦合。

因此需要逐步改成分层结构。

## 10.2 目标结构

```
user/shell/src/
├── main.rs
├── terminal.rs
├── line_editor.rs
├── lexer.rs
├── parser.rs
├── executor.rs
├── builtin.rs
├── environment.rs
├── history.rs
└── error.rs
```

## 10.3 命令解析

支持：

```
ls -lah /home
cat readme.txt
mkdir project
cp source.txt target.txt
```

参数解析必须区分：

- 命令名称。
- 普通参数。
- 选项。
- 引号字符串。
- 转义字符。

## 10.4 Shell 内置命令

首期内置：

```
help
echo
exit
pwd
cd
clear
history
```

## 10.5 外部命令

逐步支持独立用户程序：

```
/bin/ls
/bin/cat
/bin/cp
/bin/mkdir
```

在完整程序执行机制可用之前，可以采用现有内核支持的用户程序装载路径逐步接入。

不能假设已经存在完整的 PATH 搜索、fork/exec 和环境变量继承机制。

## 10.6 管道

目标：

```
cat file.txt | grep hello
```

## 10.7 重定向

目标：

```
echo hello > file.txt
echo world >> file.txt
cat < file.txt
```

管道和重定向依赖文件描述符、进程执行和 I/O 资源管理，应在基础命令稳定后实现。

---

# 11. 文件系统安全与稳定性

## 11.1 核心原则

文件系统属于内核关键基础设施。

必须优先保证：

- 内存安全。
- 数据边界安全。
- 句柄安全。
- 设备访问安全。
- 目录结构安全。
- 资源生命周期安全。

## 11.2 文件系统隔离

不同文件系统实例之间必须隔离。

单个 FAT 卷出现损坏时：

- 不允许直接破坏其他卷。
- 不允许导致其他进程句柄失效。
- 不允许造成内核无限循环。
- 不允许产生越界磁盘访问。

## 11.3 并发访问

必须考虑：

- 多进程同时读取。
- 多进程同时写入。
- 一个进程删除另一个进程正在打开的文件。
- 多进程同时创建同名文件。
- 挂载期间访问文件。
- 卸载期间仍有打开句柄。

## 11.4 故障处理

至少处理：

- 文件不存在。
- 文件系统损坏。
- 簇链循环。
- 非法簇号。
- 目录项损坏。
- 磁盘空间不足。
- 磁盘 I/O 失败。
- 无效句柄。
- 用户缓冲区非法。
- 读写权限不足。

不能将所有错误统一转成一个模糊的失败码。

---

# 12. 工程实施路线

本项目采用里程碑推进，不进行一次性大规模重构。

## FS-01：文件系统接口梳理与 VFS 基础

优先级：P0

目标：

- 审查当前文件系统代码。
- 明确现有 Block 与 VFS 的边界。
- 设计 Inode。
- 设计 Dentry。
- 设计 File。
- 设计 Path。
- 设计 Mount。
- 定义统一错误类型。
- 制定与现有 FAT 读取接口的适配方案。

验收：

- 现有 FAT16/FAT32 读取测试不退化。
- 现有 GPT 测试不退化。
- 现有 AHCI 测试不退化。
- 不破坏现有文件句柄管理。
- 新接口可以承载一个只读文件系统实例。

## FS-02：目录读取与路径解析

优先级：P0

目标：

- 根目录枚举。
- 子目录枚举。
- 多级路径解析。
- 目录游标。
- LFN。
- 文件属性。

验收：

```
ls /
ls /boot
ls /home/user
stat /home/user/readme.txt
```

必须使用真实文件系统数据。

## FS-03：用户空间文件 API

优先级：P0

目标：

- open。
- read。
- close。
- seek。
- stat。
- readdir。

验收：

用户空间程序可以独立访问文件，不需要 Shell 参与。

## FS-04：文件创建与写入

优先级：P0

目标：

- write。
- create。
- truncate。
- append。
- FAT 簇分配。
- FAT 表更新。
- 目录项更新。

验收：

```
touch test.txt
echo hello > test.txt
cat test.txt
echo world >> test.txt
cat test.txt
```

重启后重新读取，验证数据真实持久化。

## FS-05：文件和目录删除

优先级：P1

目标：

- unlink。
- mkdir。
- rmdir。
- rename。
- 簇回收。

验收：

```
mkdir project
touch project/a.txt
mv project/a.txt project/b.txt
rm project/b.txt
rmdir project
```

## FS-06：基础 Coreutils

优先级：P1

完成：

- pwd。
- cd。
- ls。
- cat。
- touch。
- mkdir。
- rmdir。
- cp。
- mv。
- rm。
- stat。
- file。

## FS-07：Shell 增强

优先级：P1

完成：

- Lexer。
- Parser。
- 参数解析。
- 选项解析。
- 引号。
- 命令历史。
- 自动补全。
- 错误输出。

## FS-08：搜索和文本工具

优先级：P2

完成：

- find。
- grep。
- head。
- tail。
- wc。
- sort。
- diff。
- tree。

## FS-09：磁盘管理

优先级：P2

完成：

- 块设备写入。
- 文件系统挂载管理。
- 多分区挂载。
- df。
- du。
- mount。
- umount。
- sync。

## FS-10：高级文件系统能力

优先级：P3

评估：

- tmpfs。
- 符号链接。
- 硬链接。
- 文件权限。
- 用户与用户组。
- 文件锁。
- ext4。
- 文件系统检查和修复。

---

# 13. 测试体系与验收标准

## 13.1 测试分类

### 单元测试

验证：

- 路径解析。
- 目录项解析。
- 文件名处理。
- FAT 簇链。
- 文件偏移。
- 文件大小。
- 权限判断。

### 内核测试

验证：

- 系统调用。
- 文件句柄。
- 资源释放。
- 错误码。
- 并发访问。
- 用户内存校验。

### 集成测试

验证：

- Shell 到 Coreutils。
- Coreutils 到 Runtime。
- Runtime 到 Syscall。
- Syscall 到 VFS。
- VFS 到 FAT。
- FAT 到块设备。

### 持久化测试

验证：

- 创建文件后重启。
- 写入文件后重启。
- 删除文件后重启。
- 重命名后重启。
- 目录创建后重启。

### 异常测试

验证：

- 磁盘空间不足。
- 磁盘写入失败。
- FAT 表损坏。
- 文件簇链循环。
- 非法路径。
- 非法句柄。
- 非法用户指针。

## 13.2 核心验收场景

完整文件管理闭环：

```
mkdir /home/test

touch /home/test/hello.txt

echo "Aurora OS Filesystem" > /home/test/hello.txt

cat /home/test/hello.txt

cp /home/test/hello.txt /home/test/copy.txt

mv /home/test/copy.txt /home/test/backup.txt

stat /home/test/backup.txt

find /home -name "*.txt"

rm /home/test/hello.txt

rm /home/test/backup.txt

rmdir /home/test
```

要求：

1. 每个命令真实执行。
2. 每次文件操作都更新真实文件系统数据。
3. 不允许返回模拟结果。
4. 错误时必须输出明确原因。
5. 文件操作完成后数据能够持久化。
6. 不得导致内核崩溃。
7. 现有回归测试必须保持通过。

---

# 14. 开发管理与代码约束

## 14.1 修改原则

采用小步增量开发。

每个里程碑必须：

1. 明确修改文件。
2. 明确新增文件。
3. 明确接口变化。
4. 明确依赖关系。
5. 明确测试范围。
6. 明确回归结果。
7. 更新 BACKLOG。
8. 必要时更新 ADR。
9. 更新模块接口登记。

## 14.2 不允许的行为

- 不允许无关模块重写。
- 不允许大规模重构现有代码。
- 不允许擅自改变已经采纳的 ADR。
- 不允许破坏现有系统调用 ABI。
- 不允许删除已有测试来获得通过结果。
- 不允许将未实现功能伪装成已实现。
- 不允许在内核中直接堆积所有 Shell 命令。
- 不允许将用户输入大小直接作为内核分配大小。
- 不允许未经验证就启用磁盘写入。

## 14.3 回归要求

每次开发都必须执行项目现有构建与测试入口。

优先沿用：

```
python tools/aurora.py
```

根据实际修改范围执行相关测试矩阵。

不能只使用宿主机 `cargo test` 代替真实内核和 QEMU 集成测试。

## 14.4 文档管理

需要同步维护：

```
docs/
├── design/
│   ├── filesystem-architecture.md
│   ├── filesystem-abi.md
│   └── shell-architecture.md
│
├── adr/
│   └── 后续新增架构决策
│
└── architecture/
    └── module-interfaces.toml
```

本文件作为整体建设规划文档。

具体实现接口、架构决策和测试判据分别维护，避免一份文档承担所有职责。

---

# 15. 最终建设目标

完成本项目后，Aurora OS 应具备以下能力：

## 文件系统

- 统一 VFS。
- FAT16。
- FAT32。
- 多级目录。
- 长文件名。
- 文件读写。
- 文件创建和删除。
- 目录创建和删除。
- 文件属性。
- 多分区挂载。
- 基础权限管理。

## Shell

- 交互式 Shell。
- 命令参数解析。
- 独立用户空间命令。
- 命令历史。
- 自动补全。
- 管道。
- 输入输出重定向。
- 环境变量。

## 基础命令

```
文件：
ls cat touch cp mv rm stat file

目录：
pwd cd mkdir rmdir tree find

文本：
head tail less more grep wc sort diff

磁盘：
df du lsblk blkid mount umount sync

权限：
chmod chown chgrp umask

系统：
help echo clear history exit
```

上述列表为目标能力，不代表全部命令必须在第一版完成。

---

# 16. 第一轮实施任务：FS-01

本设计文档批准后，正式启动：

**FS-01：Aurora OS 文件系统接口梳理与 VFS 基础建设。**

第一轮仅允许开展以下工作：

1. 重新核对现有文件系统实现。
2. 梳理 `Block`、`PartitionView`、`Volume`、`FileCursor` 之间的关系。
3. 梳理现有文件句柄和 `SYS_FILE_READ` 的数据流。
4. 明确 VFS 所需的核心数据结构。
5. 定义文件系统统一接口。
6. 定义目录访问接口。
7. 定义路径解析接口。
8. 定义挂载管理接口。
9. 编写接口适配方案。
10. 制定 FS-02 的实施计划。

本轮暂不实现：

- FAT 写入。
- 文件删除。
- 目录创建。
- 大规模系统调用扩展。
- Shell 大规模重构。
- ext4。
- 新的磁盘驱动。

**FS-01 的最终交付物：**

- VFS 架构设计。
- Rust 接口定义。
- 数据结构定义。
- 现有模块适配方案。
- 文件和目录访问数据流。
- 模块依赖关系。
- 测试验收方案。
- 变更文件清单。

完成评审后，再进入 FS-02。

---

**文档结论**

Aurora OS 文件系统建设采用：

**现有存储层保留 → VFS 统一抽象 → FAT 文件系统完善 → 系统调用扩展 → 用户空间运行库 → Coreutils → Shell 增强。**

通过逐层建设，最终形成一套独立、可扩展、可持续维护的操作系统文件系统和命令体系。

本项目坚持增量开发、接口稳定、模块隔离和真实测试，不以增加命令数量作为唯一完成标准，而以完整、可靠的文件操作闭环作为最终验收依据。

## **六、正式实施顺序**

我建议先不要直接进入 FAT 写入。先把架构接口钉死，尤其是现有文件句柄和 VFS 的衔接。

**FS-01 第一轮任务清单**

0/8 项完成

0%

梳理 Block / PartitionView / Volume / FileCursor 数据流

梳理 handle.rs 与 SYS_FILE_READ 句柄生命周期

设计 Inode / Dentry / File / Mount 数据结构

确定 VFS 与 FAT16/FAT32 的适配接口

确定路径解析和目录遍历接口

确定系统调用 ABI 扩展策略

输出新增文件及修改文件清单

制定 FS-01 回归测试方案

**我的建议：下一步直接开始 FS-01，而不是继续扩充命令列表。** 先把 VFS 的接口设计和现有代码的适配关系确定下来，再进入实际代码修改。