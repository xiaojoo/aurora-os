//! A2 切片：Aurora OS 用户态运行时库。
//!
//! 封装内核**已存在**的系统调用（`kernel/src/user.rs`），不新增任何调用号
//! （23 号预留给未来 write，见 user.rs:53 的注释，本库不许占用）。
//!
//! 三条与内核侧文档绑定的约定（与 user/hello、user/shell 的模块头同源）：
//!
//! 1. 入口走 `int 0x80`（ADR-025）。`int N` 不动 `rcx`/`r11`（那是 SYSCALL 的硬件行为），
//!    所以不声明它们为 clobber。
//! 2. 号在 `rax`，参数 `rdi/rsi/rdx`，第四参走 `r10`（user.rs:44 的号表注释：
//!    "第四个参数走 **r10**（syscall 指令吃掉 rcx/r11）"），返回 `rax`，负数是 `-ErrorCode`
//!    （user.rs:18 的 ABI 行，错误码表在 user.rs:189-243）。
//! 3. 全库 no_std、无堆分配、不 panic：长度与形状检查全部在 safe 层完成，
//!    不给内核传未校验的长度。
//!
//! unsafe 只有一处：本文件底部的 `syscall_abi`（照抄 user/shell/src/main.rs:90 的
//! `syscall3` 模式，多带一个 `r10` 以支持 15/16 号的第四参）。其余接口全部 safe。

#![no_std]

/// A3 用户态装载器（最小 ELF64：解析 + 逐段 VMO 映射 + 栈顶）。
pub mod elf;
/// A3 外部 ELF 的装载与启动编排层（22/25 → 12/13/14 → 11/15/16/17）。
pub mod exec;

// ---------------------------------------------------------------------------
// 句柄
// ---------------------------------------------------------------------------

/// capability 句柄。内核侧是 `handle::Handle(u64)`（user.rs 各分派分支直接把 `frame.rdi`
/// 当 `Handle` 用），用户侧独立声明为裸 `u64` 别名。
pub type Handle = u64;

// ---------------------------------------------------------------------------
// 调用号（与 kernel/src/user.rs 同一组数，用户侧独立声明——同 user/shell/main.rs:20 的口径）
// 每条注明 user.rs 的行号；**一个新号都不加**。
// ---------------------------------------------------------------------------

/// 1 `ping`。返回内核侧"第几次被服务"的全局计数（分派：user.rs:1803）。
pub const SYS_PING: u64 = 1;
/// 3 任务自己结束（user.rs:179）。
pub const SYS_EXIT: u64 = 3;
/// 7 返回 ABI 版本与特性位（user.rs:35；`abi_word` 的形状在 user.rs:145）。
pub const SYS_ABI_INFO: u64 = 7;
/// 8 关闭一个句柄（user.rs:37；分派 user.rs:1847）。
pub const SYS_HANDLE_CLOSE: u64 = 8;
/// 9 `dup` 到新权限，只能收窄（user.rs:39；分派 user.rs:1855）。
pub const SYS_HANDLE_DUP: u64 = 9;
/// 10 从游标继续读（user.rs:41；实现 user.rs:1068）。
pub const SYS_FILE_READ: u64 = 10;
/// 11 带 `CREATE` 的 Job 句柄 → Proc 句柄（user.rs:89；实现 user.rs:531）。
pub const SYS_PROCESS_CREATE: u64 = 11;
/// 15 子 AS 里建线程，建出来即停住（user.rs:92；实现 user.rs:583）。第四参走 `r10`。
pub const SYS_THREAD_CREATE: u64 = 15;
/// 16 校验 → 转移 → 回填 → 放线程跑（user.rs:99；实现 user.rs:683）。第四参走 `r10`。
pub const SYS_PROCESS_START: u64 = 16;
/// 17 等进程收工，19 号的薄壳（user.rs:874；实现 user.rs:935）。
pub const SYS_PROCESS_WAIT: u64 = 17;
/// 18 收掉一个进程的全部线程（user.rs:96；实现 user.rs:958）。
pub const SYS_PROCESS_KILL: u64 = 18;
/// ADR-134 (29): rdi=pid -> threads killed. pid is only an address; the kernel
/// still requires a RIGHT_WRITE Proc handle in the caller own name table.
pub const SYS_PROC_KILL_BY_PID: u64 = 29;
/// ADR-135 (30): log_read(buf,len) -> (lines<<32)|bytes. Reads the serial log ring
/// as whole lines only (half lines are dropped by the kernel). 0 means success.
pub const SYS_LOG_READ: u64 = 30;
/// ADR-136 (31): pci_enum(buf,cap,cursor) -> (next<<32)|n. Fixed 32-byte records,
/// magic "APC1". PCI table is a boot snapshot; no capability required.
pub const SYS_PCI_ENUM: u64 = 31;
/// ADR-137 (32): clock_uptime() -> micros since boot (u64). No args, no buffer,
/// no capability. Unanchored/uncalibrated => -1 (never a guessed default).
pub const SYS_CLOCK_UPTIME: u64 = 32;
/// 19 通用对象等待，今天只支持 Proc（user.rs:879；实现 user.rs:946）。
pub const SYS_OBJECT_WAIT: u64 = 19;
/// 20 控制台写（user.rs:51；实现 `sys_console_io` user.rs:1006）。
pub const SYS_CONSOLE_WRITE: u64 = 20;
/// 21 控制台读，**不阻塞**（user.rs:52；实现 `sys_console_io` user.rs:1006）。
pub const SYS_CONSOLE_READ: u64 = 21;
/// 22 `open(path,len,flags)`，flags 目前必须为 0（user.rs:55；实现 user.rs:1136）。
pub const SYS_FILE_OPEN: u64 = 22;
/// 24 `seek(handle,newpos,whence)`（user.rs:57；实现 user.rs:1190）。
pub const SYS_FILE_SEEK: u64 = 24;
/// 25 `stat(handle,buf,len)`，写一份 StatV1（user.rs:58；实现 user.rs:1232）。
pub const SYS_FILE_STAT: u64 = 25;
/// 26 `readdir(dir_handle,buf,len)`（user.rs:61；实现 user.rs:1263）。
pub const SYS_DIR_READ: u64 = 26;
/// 27 `proc_enum(job,cursor,buf,len)`（ADR-132；user.rs 的实现见 `sys_proc_enum`）。
pub const SYS_PROC_ENUM: u64 = 27;
/// 28 `proc_stat(proc,buf,len)`（ADR-132）。
pub const SYS_PROC_STAT: u64 = 28;
/// 12 `vmo_create(pages)`（user.rs:43）——A3 用户态装载器的底座。
pub const SYS_VMO_CREATE: u64 = 12;
/// 13 `vmo_write(handle,off,buf,len)`（user.rs:46）。
pub const SYS_VMO_WRITE: u64 = 13;
/// 14 `aspace_map(vmo,flags,proc,va)`（user.rs:50）。
pub const SYS_ASPACE_MAP: u64 = 14;

// ---------------------------------------------------------------------------
// 长度上限（用户侧独立声明，两侧不一致时 safe 层先拒绝，不给内核传超限长度）
// ---------------------------------------------------------------------------

/// 一次拷贝的容量上限（user.rs:2019）。file_read / dir_read / file_stat 的缓冲都受它约束。
pub const COPY_MAX: usize = 4096;
/// 控制台一次读写的上限（user.rs:62）。
pub const CONSOLE_MAX: usize = 256;
/// `open` 路径长度上限。内核侧出处是 `vfs_ro::PATH_MAX`
///（user.rs:1142 引用；常量本体在 kernel/src/filesystem/vfs_ro.rs:33）。
pub const PATH_MAX: usize = 256;
/// stat 记录长度（kernel/src/filesystem/fs_open.rs:19；user.rs:1234 要求 buf.len ≥ 此值）。
pub const STAT_RECORD_LEN: usize = 48;
/// 目录项记录长度（kernel/src/filesystem/fs_open.rs:27；user.rs:1268 要求 buf.len 是它的倍数）。
pub const DIRENT_RECORD_LEN: usize = 512;
/// stat 记录第 7 字节 = 文件（fs_open.rs:21）。
pub const STAT_KIND_FILE: u8 = 1;
/// stat 记录第 7 字节 = 目录（fs_open.rs:22）。
pub const STAT_KIND_DIR: u8 = 2;
/// 根目录（`/`）单独一个 kind：挂载根的 stat 记录用 3，不是 2。
pub const STAT_KIND_ROOT: u8 = 3;
/// 等待信号位：bit0 = 对象已终止（user.rs:882）。用户侧稳定位图，与内核内部布局无关。
pub const WAIT_TERMINATED: u64 = 1;
/// 等待时限上限毫秒，必须有界（user.rs:885）。
pub const WAIT_MAX_MS: u64 = 60_000;

// ---------------------------------------------------------------------------
// ABI 字与特性位（user.rs:67-84、868-871；`abi_word` 的形状在 user.rs:145-169）
// ---------------------------------------------------------------------------

/// ABI 主版本（user.rs:67）。用户侧独立声明。
pub const ABI_MAJOR: u64 = 0;
/// ABI 次版本（user.rs:68）。用户侧独立声明。
pub const ABI_MINOR: u64 = 12;
/// `syscall` 快路径可用（user.rs:69）。
pub const F_FASTPATH: u64 = 1;
/// SMAP 生效（user.rs:70）。
pub const F_SMAP: u64 = 2;
/// SMEP 生效（user.rs:71）。
pub const F_SMEP: u64 = 4;
/// 安全模式（§9.4；user.rs:75）。
pub const F_SAFE_MODE: u64 = 8;
/// capability 句柄表存在（user.rs:78）。
pub const F_HANDLES: u64 = 16;
/// VMO 三个号（12/13/14）可用（user.rs:81）。
pub const F_VMO: u64 = 32;
/// 11/15/16 三个号可用（user.rs:84）。
pub const F_PROC: u64 = 64;
/// 17/19 两个等待号可用（user.rs:868）。
pub const F_WAIT: u64 = 128;
/// 控制台句柄族可用（user.rs:63）。**与 `CONSOLE_MAX` 恰好同为 256 是巧合，语义无关**。
pub const F_CONSOLE: u64 = 256;
/// 22/24/25/26 与 VFS 句柄可用（user.rs:871）。
pub const F_FS_OPEN: u64 = 512;

/// 从 ABI 字取主版本。形状：`(major << 32) | (minor << 16) | features`（user.rs:168）。
#[must_use]
pub const fn abi_major(word: u64) -> u32 {
    (word >> 32) as u32
}

/// 从 ABI 字取次版本。
#[must_use]
pub const fn abi_minor(word: u64) -> u16 {
    (word >> 16) as u16
}

/// 从 ABI 字取特性位图。
#[must_use]
pub const fn abi_features(word: u64) -> u64 {
    word & 0xffff
}

// ---------------------------------------------------------------------------
// StartupInfo 布局（ADR-075 决策 3；与 user.rs:103-142 同一组数，用户侧独立声明）
// ---------------------------------------------------------------------------

/// 魔数：证明读到的确实是这一页（user.rs:103）。
pub const SI_MAGIC: u32 = 0x4155_524f;
/// 魔数偏移（user.rs:104）。
pub const SI_OFF_MAGIC: usize = 0;
/// u16（user.rs:105）。
pub const SI_OFF_ABI_MAJOR: usize = 4;
/// u16（user.rs:106）。
pub const SI_OFF_ABI_MINOR: usize = 6;
/// u32：调用方写"我传了几条"，内核回填成"总共几条"（user.rs:108）。
pub const SI_OFF_NHANDLES: usize = 8;
/// 参数区偏移（u32，user.rs:109）。
pub const SI_OFF_ARGS_OFF: usize = 12;
/// 参数区长度（u32，user.rs:110）。
pub const SI_OFF_ARGS_LEN: usize = 16;
/// 句柄描述区起点（user.rs:111）。
pub const SI_OFF_HANDLES: usize = 24;
/// `HandleDesc { role: u32, kind: u32, handle: u64 }`（user.rs:113）。
pub const SI_DESC_BYTES: usize = 16;
/// 描述内 role 的偏移（user.rs:114）。
pub const SI_DESC_ROLE: usize = 0;
/// 描述内 kind 的偏移（user.rs:115）。
pub const SI_DESC_KIND: usize = 4;
/// 描述内 handle 的偏移（user.rs:116）。
pub const SI_DESC_HANDLE: usize = 8;
/// 读取方只许信 `handles[0..nhandles]`（user.rs:119 的使用者裁决）。
pub const MAX_STARTUP_HANDLES: usize = 16;
/// 角色号：内核自己 grant 的三个 SELF_* 与控制台（user.rs:122-127）。
pub const ROLE_SELF_PROC: u32 = 0;
/// 角色号（user.rs:123）。
pub const ROLE_SELF_ASPACE: u32 = 1;
/// 角色号（user.rs:124）。
pub const ROLE_SELF_THREAD: u32 = 2;
/// 控制台句柄的角色号（user.rs:127）。shell 只认角色号，不认"第几条"。
pub const ROLE_LOG: u32 = 5;

// ---------------------------------------------------------------------------
// 错误码映射（user.rs:189-243 的 `AbiError`：rax 里的负数就是 `-ErrorCode`）
// ---------------------------------------------------------------------------

/// 系统调用的错误返回。内核约定（user.rs:18/180）：`rax` 为负数即 `-ErrorCode`。
/// 编号与 `AbiError`（user.rs:190-219）一一对应；**未知负值映射到 [`RTError::Unknown`]，
/// 不吞掉**——内核只增不改的编号规则意味着将来可能出现新码，静默吞掉会掩盖 ABI 漂移。
/// 系统调用的错误返回。内核约定（user.rs:18/180）：`rax` 为负数即 `-ErrorCode`。
/// **A2 接线后从 enum 改成 i64 newtype**（2026-11-16，实测驱动）：
/// 12 变体 enum 的映射 match 被 LLVM（SimplifyCFG lookup-table 转换）降成查表，
/// 且 black_box 也拦不住聚合常量进 `.rodata` 模板——而**用户程序链接脚本基址在 +4 GiB
/// （正数）**，查表/模板引用的 `R_X86_64_32S`（有符号 32 位）装不下 ⇒ 链接期 out of range
/// （内核 higher-half 地址作为有符号 32 位恰好可表达，所以同一张表在内核侧从不炸——
/// shell MSGS 手写 lea、ctrl_c 防降级是同一族坑）。错误码域本来就是 `rax` 的 i64 负值，
/// newtype 直接透传：无 discriminant、无查表、无聚合模板，三类问题一并消失。
/// 编号与 `AbiError`（user.rs:190-219）一一对应（见下方关联常量）；**未知负值原样携带
/// （[`Self::code`]），不吞掉**——内核只增不改的编号规则意味着将来可能出现新码，
/// 静默吞掉会掩盖 ABI 漂移。调用方判读用关联常量比较，语义与旧枚举逐项一致。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RTError(pub i64);

impl RTError {
    /// -1：未知调用号，或参数的形状就不对（user.rs:192）。
    pub const INVALID: RTError = RTError(-1);
    /// -2：访了不可访的内存（user.rs:194）。
    pub const FAULT: RTError = RTError(-2);
    /// -3：长度超限（user.rs:196）。
    pub const TOOLONG: RTError = RTError(-3);
    /// -4：权限不够 / 越权句柄操作（user.rs:198）。
    pub const DENIED: RTError = RTError(-4);
    /// -5：句柄不存在或已关（user.rs:200）。
    pub const BADHANDLE: RTError = RTError(-5);
    /// -6：资源耗尽（表满 / 帧不够，user.rs:202）。
    pub const EXHAUSTED: RTError = RTError(-6);
    /// -7：设备 I/O 失败（user.rs:204）。
    pub const IO: RTError = RTError(-7);
    /// -8：路径不存在（user.rs:206）。
    pub const NOTFOUND: RTError = RTError(-8);
    /// -10：对目录打了文件操作（user.rs:208）。
    pub const NOTDIR: RTError = RTError(-10);
    /// -11：对文件打了目录操作（user.rs:210）。
    pub const ISDIR: RTError = RTError(-11);
    /// -15：该对象不支持此操作（user.rs:212）。
    pub const NOTSUPPORTED: RTError = RTError(-15);
}

/// 负数 → 错误；非负 → 成功计数（10/20/21/26 号的返回形状）。
fn ret_len(ret: i64) -> Result<usize, RTError> {
    if ret < 0 {
        Err(RTError(ret))
    } else {
        Ok(ret as usize)
    }
}

/// 负数 → 错误；非负 → 成功（8/16/25 号的成功返回约定：user.rs:1849、865、1249）。
fn ret_zero(ret: i64) -> Result<(), RTError> {
    if ret < 0 {
        Err(RTError(ret))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 唯一的 unsafe 入口（照抄 user/shell/src/main.rs:90 的 `syscall3` 模式）
// ---------------------------------------------------------------------------

/// `int 0x80` 系统调用。号走 `rax`、参数 `rdi/rsi/rdx`、第四参 `r10`、返回 `rax`。
///
/// 为什么要 `r10`：15/16 号的第四个参数约定走 `r10`（user.rs:44 的号表注释、user.rs:92/99
/// 的签名注释；快路径下 SYSCALL 指令吃掉 rcx/r11 所以选了 r10）。`int 0x80` 路径下
/// `r10` 原样进 TrapFrame，内核按 `frame.r10` 读（user.rs:597、717）。
/// 不需要第四参的调用传 0，内核忽略它。
///
/// # Safety
/// 只有内核能处理这条中断；`a1..a4` 必须是各号 ABI 约定的寄存器语义
/// （指针必须指向本任务可访问的用户内存，长度必须已过 safe 层校验）。
#[inline]
unsafe fn syscall_abi(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    let ret: i64;
    // SAFETY: 只有内核能处理这条中断；号走 rax、参数 rdi/rsi/rdx/r10、返回 rax。
    // preserves_flags 是对的：中断门清的是内核的 IF，iretq 把用户帧那份 rflags 原样装回
    //（user/shell/main.rs:93 的同一条论证）。不声明 nomem：系统调用的语义就是内核可能
    // 读写用户内存（user/hello/main.rs:305 的同一条论证）。
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            options(preserves_flags)
        );
    }
    ret
}

// ---------------------------------------------------------------------------
// 基础三件套：ping / exit / abi_info
// ---------------------------------------------------------------------------

/// 打 1 号（`SYS_PING`，user.rs:19）。返回内核侧"第几次被服务"的全局计数
///（分派：user.rs:1803），大于 0 即证明往返成立。
#[must_use]
pub fn ping() -> u64 {
    // SAFETY: 1 号无参数语义，四个参数位都传 0。
    let ret = unsafe { syscall_abi(SYS_PING, 0, 0, 0, 0) };
    if ret < 0 {
        // 1 号今天的分派不会回负数（user.rs:1803）；真出现说明 ABI 漂了，回 0 让调用方察觉。
        0
    } else {
        ret as u64
    }
}

/// 打 3 号（`SYS_EXIT`，user.rs:179）：任务自己结束。
///
/// 内核侧把 `exit` 作为显式控制流状态处理（user.rs:1798 的注释：不是"看返回值像不像 0"）。
/// 若退出请求被吞掉而返回了，就留在自旋里等内核抢占收走——用户态没有 `hlt`/`cli` 权
///（ring3 下是 #GP(0)，user/hello/main.rs:146 的实测），也不能再打退出号空转。
pub fn exit(code: u64) -> ! {
    // SAFETY: 3 号 `rdi` = 退出码，其余参数位无语义。
    let _ = unsafe { syscall_abi(SYS_EXIT, code, 0, 0, 0) };
    loop {
        core::hint::spin_loop();
    }
}

/// 打 7 号（`SYS_ABI_INFO`，user.rs:35）：返回 ABI 字。
/// 形状 `(major << 32) | (minor << 16) | features`（user.rs:145-168），
/// 用 [`abi_major`] / [`abi_minor`] / [`abi_features`] 拆；特性位常量见 `F_*`。
#[must_use]
pub fn abi_info() -> u64 {
    // SAFETY: 7 号无参数语义，四个参数位都传 0。
    let ret = unsafe { syscall_abi(SYS_ABI_INFO, 0, 0, 0, 0) };
    ret as u64
}

// ---------------------------------------------------------------------------
// 句柄族（8 / 9 号）
// ---------------------------------------------------------------------------

/// 打 8 号（`SYS_HANDLE_CLOSE`，user.rs:37）：关闭一个句柄。成功 `0`（user.rs:1849）。
pub fn handle_close(h: Handle) -> Result<(), RTError> {
    // SAFETY: 8 号 `rdi` = 句柄，其余参数位无语义。
    let ret = unsafe { syscall_abi(SYS_HANDLE_CLOSE, h, 0, 0, 0) };
    ret_zero(ret)
}

/// 打 9 号（`SYS_HANDLE_DUP`，user.rs:39）：dup 到新权限（只能收窄），成功返回新句柄
///（user.rs:1855-1864：`rsi` 以 u32 传给内核）。
pub fn handle_dup(h: Handle, rights: u32) -> Result<Handle, RTError> {
    // SAFETY: 9 号 `rdi` = 句柄、`rsi` = 新权限位图，其余参数位无语义。
    let ret = unsafe { syscall_abi(SYS_HANDLE_DUP, h, rights as u64, 0, 0) };
    if ret < 0 {
        Err(RTError(ret))
    } else {
        Ok(ret as u64)
    }
}

// ---------------------------------------------------------------------------
// 文件族（10 / 22 / 24 / 25 / 26 号）
// ---------------------------------------------------------------------------

/// 打 10 号（`SYS_FILE_READ`，user.rs:41）：从游标继续读。成功返回字节数，**0 = EOF**。
///
/// 长度检查在 safe 层（与内核 user.rs:1069-1075 同一形状）：空缓冲 → [`RTError::INVALID`]、
/// 超过 [`COPY_MAX`] → [`RTError::TOOLONG`]，都不打内核。
pub fn file_read(h: Handle, buf: &mut [u8]) -> Result<usize, RTError> {
    if buf.is_empty() {
        return Err(RTError::INVALID);
    }
    if buf.len() > COPY_MAX {
        return Err(RTError::TOOLONG);
    }
    // SAFETY: 10 号 `rdi` = 句柄、`rsi` = 用户缓冲、`rdx` = 长度；长度已过上面的校验，
    // 缓冲是调用方自己的可写内存。
    let ret = unsafe { syscall_abi(SYS_FILE_READ, h, buf.as_mut_ptr() as u64, buf.len() as u64, 0) };
    ret_len(ret)
}

/// 打 22 号（`SYS_FILE_OPEN`，user.rs:55）：按路径打开文件或目录，成功返回句柄。
/// `flags` 目前必须为 0（只读；user.rs:54 的注释），非 0 由内核回 [`RTError::NOTSUPPORTED`]。
///
/// 长度检查在 safe 层（与内核 user.rs:1138-1144 同一形状）：空路径 → [`RTError::INVALID`]、
/// 超过 [`PATH_MAX`] → [`RTError::TOOLONG`]。内核还要求路径是合法 UTF-8
///（user.rs:1161），非 UTF-8 由内核回 [`RTError::INVALID`]，safe 层不再复制一份判定。
pub fn file_open(path: &[u8], flags: u64) -> Result<Handle, RTError> {
    if path.is_empty() {
        return Err(RTError::INVALID);
    }
    if path.len() > PATH_MAX {
        return Err(RTError::TOOLONG);
    }
    // SAFETY: 22 号 `rdi` = 路径指针、`rsi` = 路径长度、`rdx` = flags；长度已过上面的校验。
    let ret = unsafe { syscall_abi(SYS_FILE_OPEN, path.as_ptr() as u64, path.len() as u64, flags, 0) };
    if ret < 0 {
        Err(RTError(ret))
    } else {
        Ok(ret as u64)
    }
}

// ---- ADR-130：标准句柄角色与 argv 区（A2 内核侧配套的用户侧声明）----

/// ADR-130：stdin 的 SI 描述角色。与内核 user.rs 的同名常量独立声明（两侧同数的既有成法）。
pub const ROLE_STDIN: u32 = 9;
/// ADR-130：stdout 的 SI 描述角色。
pub const ROLE_STDOUT: u32 = 10;
/// ADR-130：stderr 的 SI 描述角色（内核与 shell 今天都还没有 stderr 语义，常量先立）。
pub const ROLE_STDERR: u32 = 11;
/// Job 角色（A2 的 SI 描述里由创建方给出，带 CREATE 权限；A3 用它调 11 号）。
pub const ROLE_JOB: u32 = 3;

/// 句柄权限位（与内核 handle.rs:38-46 同名常量同值）。
/// `RIGHT_TRANSFER` 是 16 号**转移**描述句柄的硬要求：少这一位 `transfer` 会回 -4
/// （A3 实测：dup 只给 READ|WRITE 时 process_start 拒 E_DENIED）。
pub const RIGHT_READ: u32 = 1 << 0;
pub const RIGHT_WRITE: u32 = 1 << 1;
pub const RIGHT_MAP: u32 = 1 << 2;
pub const RIGHT_DUP: u32 = 1 << 3;
pub const RIGHT_TRANSFER: u32 = 1 << 4;
pub const RIGHT_CREATE: u32 = 1 << 5;

/// 从 SI 页的描述表按**角色号**取句柄（A2：stdin/stdout/stderr 走这里，不再认 ROLE_LOG）。
///
/// # Safety
/// `si_va` 必须是内核映射好的那一页（`process_start` 校验过 user+只读），且在读取期间
/// 不被解映射。与 [`find_console`] 同一条契约。
pub unsafe fn handle_of_role(si_va: u64, role: u32) -> Option<Handle> {
    let base = si_va as *const u8;
    // SAFETY: 见上；头 24 字节与描述表都在那一页内。
    let magic = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_MAGIC) as *const u32) };
    if magic != SI_MAGIC {
        return None;
    }
    let n = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_NHANDLES) as *const u32) } as usize;
    let n = if n > 16 { 16 } else { n };
    for i in 0..n {
        let d = unsafe { base.add(SI_OFF_HANDLES + i * SI_DESC_BYTES) };
        let r = unsafe { core::ptr::read_unaligned(d.add(SI_DESC_ROLE) as *const u32) };
        if r == role {
            return Some(unsafe { core::ptr::read_unaligned(d.add(SI_DESC_HANDLE) as *const u64) });
        }
    }
    None
}

/// 读 SI 页的 **argv 区**（ADR-130：`SI_OFF_ARGS_OFF/LEN` 赋义后的那一块）。
/// 返回 `None` = 这页没带 argv（`args_off/args_len` 全零，既有产物的默认形状）。
///
/// # Safety
/// 同 [`handle_of_role`]：那一页由内核校验，argv 区已被内核 process_start 校验
/// "在页内且不与句柄表重叠"（ADR-130 决策 2），本函数不再二次判界。
pub unsafe fn args_at(si_va: u64) -> Option<&'static [u8]> {
    let base = si_va as *const u8;
    // SAFETY: 见上；头 24 字节都在那一页内。
    let magic = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_MAGIC) as *const u32) };
    if magic != SI_MAGIC {
        return None;
    }
    let off = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_ARGS_OFF) as *const u32) } as usize;
    let len = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_ARGS_LEN) as *const u32) } as usize;
    if off == 0 || len == 0 {
        return None;
    }
    // SAFETY: 界内性已由内核校验（ADR-130 决策 2）；这里只按内核背书过的范围切片。
    Some(unsafe { core::slice::from_raw_parts(base.add(off) as *const u8, len) })
}

// ---------------------------------------------------------------------------
// VMO 族（12 / 13 / 14 号）——A3 用户态装载器的底座（ADR-131 草案）
// ---------------------------------------------------------------------------

/// 12 号（`SYS_VMO_CREATE`，user.rs:43）：建一个 `pages` 页的 VMO，返回句柄。
/// 句柄权限由内核给全（READ|WRITE|MAP|DUP，user.rs:53 附近）。
pub fn vmo_create(pages: usize) -> Result<Handle, RTError> {
    if pages == 0 {
        return Err(RTError::INVALID);
    }
    // SAFETY: 12 号 `rdi` = 页数，其余参数无语义。
    let ret = unsafe { syscall_abi(SYS_VMO_CREATE, pages as u64, 0, 0, 0) };
    if ret < 0 {
        Err(RTError(ret))
    } else {
        Ok(ret as u64)
    }
}

/// 13 号（`SYS_VMO_WRITE`，user.rs:46）：往 VMO 的 `off` 起写 `buf`，返回写入字节数。
pub fn vmo_write(h: Handle, off: u64, buf: &[u8]) -> Result<usize, RTError> {
    if buf.is_empty() {
        return Ok(0);
    }
    // SAFETY: 13 号 `rdi` = 句柄、`rsi` = 偏移、`rdx` = 缓冲指针、`r10` = 长度；
    // 缓冲是调用方的可读内存，长度由调用方保证与 VMO 容量匹配（越界由内核回 -1/-2）。
    let ret = unsafe { syscall_abi(SYS_VMO_WRITE, h, off, buf.as_ptr() as u64, buf.len() as u64) };
    if ret < 0 {
        Err(RTError(ret))
    } else {
        Ok(ret as usize)
    }
}

/// 14 号（`SYS_ASPACE_MAP`，user.rs:50）：把 VMO 映射进 `proc` 的 AS 的 `va` 起，返回实际 VA。
/// `w`/`x` 由调用方按段属性给（W+X 同段内核拒 -1，user.rs:56 附近的形状校验）。
pub fn vmo_map(proc: Handle, vmo: Handle, va: u64, w: bool, x: bool) -> Result<u64, RTError> {
    let flags = (w as u64) | ((x as u64) << 1);
    // SAFETY: 14 号 `rdi` = VMO 句柄、`rsi` = 权限位、`rdx` = Proc 句柄别名、`r10` = 目标 VA。
    let ret = unsafe { syscall_abi(SYS_ASPACE_MAP, vmo, flags, proc, va) };
    if ret < 0 {
        Err(RTError(ret))
    } else {
        Ok(ret as u64)
    }
}

// ---------------------------------------------------------------------------
// 进程观测（27 / 28 号，ADR-132）
// ---------------------------------------------------------------------------

/// 一条记录的定长（枚举与统计同为 32 字节，布局见 ADR-132 §2.2）。
pub const PROC_RECORD_LEN: usize = 32;

/// 一条枚举记录（解码后）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcEntry {
    /// 槽号（今天的 pid）。
    pub pid: u32,
    /// 世代号。
    pub gen: u32,
    /// 还活着的线程数。
    pub threads: u32,
    /// 是否已终止（僵尸也算）。
    pub terminated: bool,
    /// 名下 AS 的**映射页数**（不是常驻页）。
    pub pages: u32,
    /// 所属 Job 的槽号。
    pub job: u32,
}

/// 一条统计记录（比枚举多一个退出码）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcStat {
    /// 槽号。
    pub pid: u32,
    /// 世代号。
    pub gen: u32,
    /// 线程数。
    pub threads: u32,
    /// 是否已终止。
    pub terminated: bool,
    /// 终止时的退出码（活着时无意义）。
    pub exit_code: u32,
    /// 映射页数。
    pub pages: u32,
}

fn le32(b: &[u8], off: usize) -> u32 {
    match b.get(off..off + 4) {
        Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        None => 0,
    }
}

/// 27 号：枚举自己 Job 名下的进程。返回 `(下一个游标, 本次条数)`；**游标 0 = 扫完**。
pub fn proc_enum(job: Handle, cursor: u32, buf: &mut [u8]) -> Result<(u32, u32), RTError> {
    if buf.len() < PROC_RECORD_LEN {
        return Err(RTError::TOOLONG);
    }
    // SAFETY: 27 号 `rdi` = Job 句柄（要 READ）、`rsi` = 游标、`rdx` = 缓冲、`r10` = 字节数；
    // 缓冲由调用方给出，长度已在上行校验，内核侧还有 `COPY_MAX` 与 `copy_to_user` 的窗口校验。
    let ret = unsafe {
        syscall_abi(
            SYS_PROC_ENUM,
            job,
            u64::from(cursor),
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    };
    if ret < 0 {
        return Err(RTError(ret));
    }
    let v = ret as u64;
    Ok(((v >> 32) as u32, (v & 0xffff_ffff) as u32))
}

/// 27 号的解码：`buf` 里第 `i` 条（越界/魔数不对回 `None`，不 panic）。
#[must_use]
pub fn proc_enum_at(buf: &[u8], i: usize) -> Option<ProcEntry> {
    let off = i.checked_mul(PROC_RECORD_LEN)?;
    let rec = buf.get(off..off + PROC_RECORD_LEN)?;
    if le32(rec, 0) != 0x3150_5541 || rec.get(4) != Some(&1) {
        return None;
    }
    Some(ProcEntry {
        pid: le32(rec, 8),
        gen: le32(rec, 12),
        threads: le32(rec, 16),
        terminated: le32(rec, 20) != 0,
        pages: le32(rec, 24),
        job: le32(rec, 28),
    })
}

/// 28 号：取一个进程的统计。成功后记录在 `buf` 的前 32 字节里。
pub fn proc_stat(proc: Handle, buf: &mut [u8]) -> Result<(), RTError> {
    if buf.len() < PROC_RECORD_LEN {
        return Err(RTError::TOOLONG);
    }
    // SAFETY: 28 号 `rdi` = Proc 句柄（要 READ）、`rsi` = 缓冲、`rdx` = 字节数。
    let ret = unsafe {
        syscall_abi(SYS_PROC_STAT, proc, buf.as_mut_ptr() as u64, buf.len() as u64, 0)
    };
    if ret < 0 {
        return Err(RTError(ret));
    }
    Ok(())
}

/// 28 号的解码。
#[must_use]
pub fn proc_stat_at(buf: &[u8]) -> Option<ProcStat> {
    let rec = buf.get(..PROC_RECORD_LEN)?;
    if le32(rec, 0) != 0x3153_5541 || rec.get(4) != Some(&1) {
        return None;
    }
    Some(ProcStat {
        pid: le32(rec, 8),
        gen: le32(rec, 12),
        threads: le32(rec, 16),
        terminated: le32(rec, 20) != 0,
        exit_code: le32(rec, 24),
        pages: le32(rec, 28),
    })
}

/// 24 号的基准（user.rs:56 的 whence 约定：0=SET、1=CUR、2=END）。
/// **A2 接线后从 enum 改成 i64 newtype**，理由同 [`RTError`]（枚举映射会被 LLVM 降成
/// 查表，用户链接基址 +4 GiB 下 `R_X86_64_32S` 溢出）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Whence(pub i64);

impl Whence {
    /// 0：相对文件头。
    pub const SET: Whence = Whence(0);
    /// 1：相对当前游标。
    pub const CUR: Whence = Whence(1);
    /// 2：相对文件尾。
    pub const END: Whence = Whence(2);
}

/// 打 24 号（`SYS_FILE_SEEK`，user.rs:57）：移动游标，成功返回新位置。
/// 对目录 seek 内核回 [`RTError::NOTSUPPORTED`]（user.rs:1199-1200）。
pub fn file_seek(h: Handle, whence: Whence, offset: i64) -> Result<u64, RTError> {
    // SAFETY: 24 号 `rdi` = 句柄、`rsi` = 位置（有符号数按补码进 rsi，user.rs:1209 取 i64）、
    // `rdx` = whence。whence 的合法性由枚举保证（内核侧非法值也是 -1，user.rs:1214）。
    let ret = unsafe { syscall_abi(SYS_FILE_SEEK, h, offset as u64, whence.0 as u64, 0) };
    if ret < 0 {
        Err(RTError(ret))
    } else {
        Ok(ret as u64)
    }
}

/// 25 号（`SYS_FILE_STAT`，user.rs:58）写回的 StatV1 原始记录（48 字节）。
/// 布局的唯一来源是内核 `fs_open::stat_record`（fs_open.rs:60 附近），本侧不解读字段、
/// 只提供 `kind()` 一个访问器；其余字节调用方按内核文档自行判读。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatRecord {
    /// 原始 48 字节，小端布局同内核。
    pub bytes: [u8; STAT_RECORD_LEN],
}

impl StatRecord {
    /// 记录第 8..12 字节的文件大小（fs_open.rs 的 `put_u32(&mut b, 8, e.size)`）。
    #[must_use]
    pub const fn size(&self) -> u32 {
        let b = &self.bytes;
        (b[8] as u32) | ((b[9] as u32) << 8) | ((b[10] as u32) << 16) | ((b[11] as u32) << 24)
    }

    /// 记录第 7 字节的 kind（fs_open.rs:66-68）：[`STAT_KIND_FILE`] / [`STAT_KIND_DIR`]。
    #[must_use]
    pub const fn kind(&self) -> u8 {
        self.bytes[7]
    }
}

/// 打 25 号（`SYS_FILE_STAT`，user.rs:58）：读一份 StatV1。
///
/// 缓冲由本函数在栈上准备，长度恒为 [`STAT_RECORD_LEN`]——天然满足内核的两条检查
///（len ≥ 48 且 ≤ [`COPY_MAX`]，user.rs:1233-1239；len < 48 内核也回 -3，那是它的 ABI 形状），
/// 不给内核传未校验长度。
pub fn file_stat(h: Handle) -> Result<StatRecord, RTError> {
    let mut rec = StatRecord { bytes: [0; STAT_RECORD_LEN] };
    // SAFETY: 25 号 `rdi` = 句柄、`rsi` = 缓冲指针、`rdx` = 缓冲长度；缓冲是本函数栈上的
    // 可写内存，长度恒为 STAT_RECORD_LEN。
    let ret = unsafe {
        syscall_abi(SYS_FILE_STAT, h, rec.bytes.as_mut_ptr() as u64, rec.bytes.len() as u64, 0)
    };
    ret_zero(ret)?;
    Ok(rec)
}

/// 打 26 号（`SYS_DIR_READ`，user.rs:61）：读目录项，成功返回**条目数**，0 = EOF。
///
/// 长度检查在 safe 层（与内核 user.rs:1264-1270 同一形状）：空缓冲 → Ok(0)
///（内核对 len==0 直接回 0，user.rs:1265-1267，不打内核）；超过 [`COPY_MAX`] 或
/// 不是 [`DIRENT_RECORD_LEN`] 的整数倍 → [`RTError::TOOLONG`]。
pub fn dir_read(h: Handle, buf: &mut [u8]) -> Result<usize, RTError> {
    if buf.is_empty() {
        return Ok(0);
    }
    if buf.len() > COPY_MAX || buf.len() % DIRENT_RECORD_LEN != 0 {
        return Err(RTError::TOOLONG);
    }
    // SAFETY: 26 号 `rdi` = 目录句柄、`rsi` = 缓冲指针、`rdx` = 缓冲长度；长度已过上面的校验。
    let ret = unsafe { syscall_abi(SYS_DIR_READ, h, buf.as_mut_ptr() as u64, buf.len() as u64, 0) };
    ret_len(ret)
}

/// 一条目录记录的解码结果（内核 `filesystem/fs_open.rs::dirent_record` 写的那张 512 字节表）。
/// `name` 是**短名（8.3）**；记录里另有长名（偏移 64），今天 `ls` 只显示短名。
pub struct DirEnt<'a> {
    /// 1 = 文件，2 = 目录（与内核 `DIRENT_KIND_*` 同数）。
    pub kind: u8,
    /// 短名（8.3）。
    pub name: &'a [u8],
    /// 长名（LFN）；没有就是空串。显示优先用长名。
    pub long: &'a [u8],
    pub size: u32,
}

/// `DIRENT_MAGIC`（"AUFD"）与版本：解码前先核，形状不对按 `INVALID` 拒（不猜）。
const DIRENT_MAGIC: u32 = 0x4446_5541;
const DIRENT_NAME_AT: usize = 48;
const DIRENT_LONG_AT: usize = 64;
const DIRENT_LONG_LEN_AT: usize = 10;
const DIRENT_SIZE_AT: usize = 16;

fn le32_at(b: &[u8], at: usize) -> u32 {
    let mut v = 0u32;
    let mut i = 0usize;
    while i < 4 {
        if let Some(x) = b.get(at + i) {
            v |= u32::from(*x) << (8 * i);
        }
        i += 1;
    }
    v
}

/// 列一个目录：把 26 号的记录逐条解码后回调。返回**条数**（游标耗尽为止）。
/// 缓冲用本模块那份 4 KiB（`chunk()`，单线程程序、无并发窗口，与 `load` 同一条约定）。
pub fn dir_list<F: FnMut(&DirEnt)>(path: &[u8], mut f: F) -> Result<u32, RTError> {
    let h = file_open(path, 0)?;
    let buf = crate::exec::chunk();
    let cap = buf.len() / DIRENT_RECORD_LEN;
    let mut n = 0u32;
    let mut bad = None;
    loop {
        let k = match dir_read(h, &mut buf[..cap * DIRENT_RECORD_LEN]) {
            Ok(k) => k,
            Err(e) => {
                bad = Some(e);
                break;
            }
        };
        if k == 0 {
            break;
        }
        let mut i = 0usize;
        while i < k {
            let rec = match buf.get(i * DIRENT_RECORD_LEN..(i + 1) * DIRENT_RECORD_LEN) {
                Some(r) => r,
                None => {
                    bad = Some(RTError::INVALID);
                    break;
                }
            };
            if le32_at(rec, 0) != DIRENT_MAGIC || rec[6] != 1 {
                bad = Some(RTError::INVALID);
                break;
            }
            let nl = rec[8] as usize;
            let name = match rec.get(DIRENT_NAME_AT..DIRENT_NAME_AT + nl) {
                Some(s) if nl > 0 => s,
                _ => {
                    bad = Some(RTError::INVALID);
                    break;
                }
            };
            let ll = usize::from(rec.get(DIRENT_LONG_LEN_AT).copied().unwrap_or(0))
                | (usize::from(rec.get(DIRENT_LONG_LEN_AT + 1).copied().unwrap_or(0)) << 8);
            // 长名：长度字段在 10（u16），内容在 64 起；越界按空串（短名兜底，不因长名坏整条）。
            let long = if ll == 0 {
                &rec[DIRENT_LONG_AT..DIRENT_LONG_AT]
            } else {
                rec.get(DIRENT_LONG_AT..DIRENT_LONG_AT + ll).unwrap_or(&rec[DIRENT_LONG_AT..DIRENT_LONG_AT])
            };
            f(&DirEnt { kind: rec[7], name, long, size: le32_at(rec, DIRENT_SIZE_AT) });
            n += 1;
            i += 1;
        }
        if bad.is_some() || k < cap {
            break;
        }
    }
    let _ = handle_close(h);
    match bad {
        Some(e) => Err(e),
        None => Ok(n),
    }
}

/// 顺序读一个文件，把每块交给回调（`cat` 用）。返回总字节数。
pub fn cat_each<F: FnMut(&[u8])>(path: &[u8], mut f: F) -> Result<u64, RTError> {
    let h = file_open(path, 0)?;
    let buf = crate::exec::chunk();
    let mut total = 0u64;
    loop {
        let n = match file_read(h, buf) {
            Ok(n) => n,
            Err(e) => {
                let _ = handle_close(h);
                return Err(e);
            }
        };
        if n == 0 {
            break;
        }
        if let Some(part) = buf.get(..n) {
            f(part);
        }
        total += n as u64;
    }
    let _ = handle_close(h);
    Ok(total)
}

// ---------------------------------------------------------------------------
// 控制台族（20 / 21 号）
// ---------------------------------------------------------------------------

/// 打 20 号（`SYS_CONSOLE_WRITE`，user.rs:51）：往控制台写，成功返回写出的字节数。
///
/// 长度检查在 safe 层（与内核 user.rs:1015-1021 同一形状）：超过 [`CONSOLE_MAX`] →
/// [`RTError::TOOLONG`]；空缓冲 → Ok(0)（内核对 want==0 直接回 0，不打内核）。
pub fn console_write(h: Handle, buf: &[u8]) -> Result<usize, RTError> {
    if buf.len() > CONSOLE_MAX {
        return Err(RTError::TOOLONG);
    }
    if buf.is_empty() {
        return Ok(0);
    }
    // SAFETY: 20 号 `rdi` = 控制台句柄、`rsi` = 缓冲指针、`rdx` = 长度；长度已过上面的校验。
    let ret = unsafe { syscall_abi(SYS_CONSOLE_WRITE, h, buf.as_ptr() as u64, buf.len() as u64, 0) };
    ret_len(ret)
}

/// 打 21 号（`SYS_CONSOLE_READ`，user.rs:52）：从控制台读，**不阻塞**（无输入回 0，
/// user/shell/main.rs:112 的同一口径）。
///
/// 长度检查在 safe 层：超过 [`CONSOLE_MAX`] → [`RTError::TOOLONG`]；空缓冲 → Ok(0)。
pub fn console_read(h: Handle, buf: &mut [u8]) -> Result<usize, RTError> {
    if buf.len() > CONSOLE_MAX {
        return Err(RTError::TOOLONG);
    }
    if buf.is_empty() {
        return Ok(0);
    }
    // SAFETY: 21 号 `rdi` = 控制台句柄、`rsi` = 缓冲指针、`rdx` = 长度；长度已过上面的校验，
    // 缓冲是调用方自己的可写内存。
    let ret = unsafe { syscall_abi(SYS_CONSOLE_READ, h, buf.as_mut_ptr() as u64, buf.len() as u64, 0) };
    ret_len(ret)
}

// ---------------------------------------------------------------------------
// 进程线程族（11 / 15 / 16 / 17 / 18 / 19 号）
// ---------------------------------------------------------------------------

/// 打 11 号（`SYS_PROCESS_CREATE`，user.rs:89）：`rdi` = 带 `CREATE` 的 Job 句柄，
/// 成功返回 **Proc 句柄**（决策 8：只返回一个名字，子进程的 AS 由内核建）。
pub fn process_create(job: Handle) -> Result<Handle, RTError> {
    // SAFETY: 11 号 `rdi` = Job 句柄，其余参数位无语义。
    let ret = unsafe { syscall_abi(SYS_PROCESS_CREATE, job, 0, 0, 0) };
    if ret < 0 {
        Err(RTError(ret))
    } else {
        Ok(ret as u64)
    }
}

/// 打 15 号（`SYS_THREAD_CREATE`，user.rs:92）：在子进程的 AS 里建一条线程，
/// **建出来就停住**（Blocked），等 16 号回填完才放它跑。成功返回 Thread 句柄。
///
/// 参数（user.rs:597-598 的读取顺序）：`entry` = 子 AS 里的入口 VA、`stack_top` = 子 AS
/// 里的用户栈顶、`arg` = 首参。入口/栈的可执行与可写校验由内核做（user.rs:602-608）。
/// 第四参走 `r10`，由 [`syscall_abi`] 的 `a4` 位传入。
pub fn thread_create(proc_h: Handle, entry: u64, stack_top: u64, arg: u64) -> Result<Handle, RTError> {
    // SAFETY: 15 号 `rdi` = Proc 句柄（要 WRITE）、`rsi` = 入口 VA、`rdx` = 栈顶、
    // `r10` = 首参。VA 合法性由内核校验（user.rs:599-608）。
    let ret = unsafe { syscall_abi(SYS_THREAD_CREATE, proc_h, entry, stack_top, arg) };
    if ret < 0 {
        Err(RTError(ret))
    } else {
        Ok(ret as u64)
    }
}

/// 打 16 号（`SYS_PROCESS_START`，user.rs:99）：校验 → 转移 → 回填 → 放线程跑，
/// 成功返回 0（user.rs:865）。
///
/// 参数（user.rs:97 的签名注释与 user.rs:717 的读取）：`si_vmo` = StartupInfo 那一页的
/// VMO 句柄、`si_va` = 它在**子 AS** 里的只读 VA（页对齐、必须已映射且只读，
/// user.rs:718-725）。第四参走 `r10`。
pub fn process_start(proc_h: Handle, thread: Handle, si_vmo: Handle, si_va: u64) -> Result<(), RTError> {
    // SAFETY: 16 号 `rdi` = Proc 句柄、`rsi` = Thread 句柄、`rdx` = SI 页的 VMO 句柄、
    // `r10` = SI 页在子 AS 里的只读 VA。形状校验全部由内核做（user.rs:714-725）。
    let ret = unsafe { syscall_abi(SYS_PROCESS_START, proc_h, thread, si_vmo, si_va) };
    ret_zero(ret)
}

/// 17/19 号（user.rs:873 的返回形状）的解码结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitOutcome {
    /// 观测到的信号位图（今天只会是 [`WAIT_TERMINATED`]）。
    pub signals: u64,
    /// 目标进程的退出码（u32）。
    pub exit_code: u32,
}

/// `(observed << 32) | 退出码` 的公共解码（user.rs:873/876 的返回形状、user.rs:917/924 的构造）。
/// `0` = 超时（user.rs:873 明文：**0 = 超时**）。observed 非 0 恒成立
///（`WAIT_TERMINATED` = bit0），所以 `rax == 0` 与"观测到了什么"不会撞。
fn decode_wait(ret: i64) -> Result<Option<WaitOutcome>, RTError> {
    if ret < 0 {
        return Err(RTError(ret));
    }
    if ret == 0 {
        return Ok(None); // 超时
    }
    let v = ret as u64;
    Ok(Some(WaitOutcome { signals: v >> 32, exit_code: (v & 0xffff_ffff) as u32 }))
}

/// 打 17 号（`SYS_PROCESS_WAIT`，user.rs:874）：等一个进程收工。它是 19 号的薄壳
///（user.rs:929），默认等"已终止"。返回 `None` = 超时（含 ms==0 的"只查一次"，user.rs:914）。
///
/// 时限检查在 safe 层：超过 [`WAIT_MAX_MS`] → [`RTError::INVALID`]（内核 user.rs:900 同此）。
pub fn process_wait(proc_h: Handle, timeout_ms: u64) -> Result<Option<WaitOutcome>, RTError> {
    if timeout_ms > WAIT_MAX_MS {
        return Err(RTError::INVALID);
    }
    // SAFETY: 17 号 `rdi` = Proc 句柄（要 READ）、`rsi` = 时限毫秒，其余参数位无语义。
    let ret = unsafe { syscall_abi(SYS_PROCESS_WAIT, proc_h, timeout_ms, 0, 0) };
    decode_wait(ret)
}

/// 打 18 号（`SYS_PROCESS_KILL`，user.rs:96）：收掉一个进程的全部线程，成功返回**真收掉的
/// 线程数**。杀自己的进程由内核回 [`RTError::DENIED`]（user.rs:971-974），那条路要交给
/// [`exit`]，本库不做包装。
pub fn process_kill(proc_h: Handle) -> Result<u64, RTError> {
    // SAFETY: 18 号 `rdi` = Proc 句柄（要 WRITE），其余参数位无语义。
    let ret = unsafe { syscall_abi(SYS_PROCESS_KILL, proc_h, 0, 0, 0) };
    if ret < 0 {
        Err(RTError(ret))
    } else {
        Ok(ret as u64)
    }
}

/// 29 号：按 pid 杀进程。pid 只是寻址——内核只在**调用者自己名下**反查带
/// `RIGHT_WRITE` 的 Proc 句柄，再走与 18 号同一个杀路径（ADR-134）。
/// 成功返回真收掉的线程数；没有对应句柄/权限不够 ⇒ `Err(-5)`。
pub fn process_kill_pid(pid: u16) -> Result<u64, RTError> {
    // SAFETY: 29 号 rdi = pid，其余参数无语义（runtime 的 syscall_abi 统一置零）。
    let ret = unsafe { syscall_abi(SYS_PROC_KILL_BY_PID, u64::from(pid), 0, 0, 0) };
    if ret < 0 {
        Err(RTError(ret))
    } else {
        Ok(ret as u64)
    }
}

/// 30 号：把**串口日志环**的最近整行读进 `buf`。返回 `(行数, 字节数)`。
///
/// 内核侧保证：只给整行（开头/结尾的半行丢掉），所以拿回来的段一定以 `\n` 结尾
/// 或为空。**0 行是成功**（环里还没有完整行），不是错误。
/// `buf` 长度必须 ≥ 1 且 ≤ `COPY_MAX`（内核 user.rs 的容量边界）。
pub fn log_read(buf: &mut [u8]) -> Result<(u32, u32), RTError> {
    if buf.is_empty() || buf.len() > COPY_MAX {
        return Err(RTError::TOOLONG);
    }
    // SAFETY: 30 号 rdi = 用户缓冲、rsi = 字节数；缓冲由调用方给出，长度已在上行校验，
    // 内核侧还有 COPY_MAX 与 copy_to_user 的窗口校验。
    let ret = unsafe {
        syscall_abi(SYS_LOG_READ, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0)
    };
    if ret < 0 {
        return Err(RTError(ret));
    }
    let v = ret as u64;
    Ok(((v >> 32) as u32, (v & 0xffff_ffff) as u32))
}

/// 31 号：PCI 设备清单。`cursor` 从 0 起逐页取，返回 `(next, n)`。
/// 每条 32 字节定长记录（魔数 `APC1`），布局见 ADR-136：
/// bdf@8、vendor|device@12、cfg08@16、hdr@20（低 8 位）、bar0@24。
/// 长度字段在 6..10 且与 bdf 共用 8..10 两字节（27 号同族形状），按 16 位读。
pub fn pci_enum(buf: &mut [u8], cursor: u64) -> Result<(u32, u32), RTError> {
    if buf.is_empty() || buf.len() > COPY_MAX || buf.len() % PCI_ENUM_REC != 0 {
        return Err(RTError::TOOLONG);
    }
    // SAFETY: 31 号 rdi=缓冲、rsi=游标、r10=字节长度（与 27 号同族：len 走 r10，
    // 不是 rdx——syscall_abi 的第 4 个参数才映射到 r10）。缓冲由调用方给出，
    // 长度已在上行校验，内核侧还有 COPY_MAX 与 copy_to_user 的窗口校验。
    let ret = unsafe {
        syscall_abi(SYS_PCI_ENUM, buf.as_mut_ptr() as u64, cursor, 0, buf.len() as u64)
    };
    if ret < 0 {
        return Err(RTError(ret));
    }
    let v = ret as u64;
    Ok(((v >> 32) as u32, (v & 0xffff_ffff) as u32))
}

/// 32 号：启动以来的微秒数。**没锚点/没标定 ⇒ `Err(-1)`**（内核不编默认值）。
/// 单调不减；两次调用相等是可能的（间隔小于 1 µs）。
pub fn uptime_us() -> Result<u64, RTError> {
    // SAFETY: 32 号无参数语义（四个参数位全置零）；无缓冲、无 capability。
    let ret = unsafe { syscall_abi(SYS_CLOCK_UPTIME, 0, 0, 0, 0) };
    if ret < 0 {
        Err(RTError(ret))
    } else {
        Ok(ret as u64)
    }
}

/// 31 号记录的定长。
pub const PCI_ENUM_REC: usize = 32;

/// 打 19 号（`SYS_OBJECT_WAIT`，user.rs:879）：通用对象等待。今天只支持 Proc 对象，
/// 拿别的 kind 来等内核回 [`RTError::DENIED`]（user.rs:877-878）。
/// 返回 `None` = 超时。
///
/// 形状检查在 safe 层（与内核 user.rs:896-902 同一形状）：`signals` 里有不认识的位 →
/// [`RTError::INVALID`]；`timeout_ms` 超过 [`WAIT_MAX_MS`] → [`RTError::INVALID`]。
pub fn object_wait(h: Handle, signals: u64, timeout_ms: u64) -> Result<Option<WaitOutcome>, RTError> {
    if signals & !WAIT_TERMINATED != 0 {
        return Err(RTError::INVALID);
    }
    if timeout_ms > WAIT_MAX_MS {
        return Err(RTError::INVALID);
    }
    // SAFETY: 19 号 `rdi` = 对象句柄、`rsi` = 信号位图、`rdx` = 时限毫秒。
    let ret = unsafe { syscall_abi(SYS_OBJECT_WAIT, h, signals, timeout_ms, 0) };
    decode_wait(ret)
}

// ---------------------------------------------------------------------------
// 定时等待（`top` 的睡眠原语，不新增调用号）
// ---------------------------------------------------------------------------

/// `signals = 0` 的 [`object_wait`]：等一个**永远不会置位**的信号图，唯一出路是
/// `timeout_ms` 到期。语义上这就是"睡指定毫秒"——返回值只有两种：
/// `Ok(None)` = 睡满了，`Ok(Some(_))` = 提前醒来（只可能发生在被等对象真是 Proc
/// 且已终止时；拿 Thread/ASpace 句柄来睡时内核 resolve 到非 Proc 直接 `-4`，
/// 永远不会走到这一支）。`Err(_)` = 句柄不能等（`-4`）或参数形状不对。
///
/// **为什么不用忙等**：内核的 19 号带时限等待走 `TASK_WAITERS` 槽 + `task_wake_tick`
/// 的超时唤醒（sched.rs:1748），等待期间任务真阻塞，不让 CPU 空转——这正是
/// `top` 每秒刷新需要的形状。**时限上限**沿用 [`WAIT_MAX_MS`]（内核 user.rs:885
/// 与本库 108 行同数），调用方传更大的毫秒回 [`RTError::INVALID`]。
///
/// `h` 通常传 16 号回填进 SI 表的 `ROLE_SELF_THREAD` 句柄（Thread 对象，永不终止）；
/// 传 Proc 句柄则退化为"最多睡 ms 毫秒、提前醒来当真醒了"的形状，调用方自行判别。
pub fn sleep_ms(h: Handle, ms: u64) -> Result<(), RTError> {
    match object_wait(h, 0, ms) {
        // 超时 = 睡满；提前醒来（拿到信号）也按"睡到了"交付——本原语的语义是
        // "至少间隔 ms 毫秒后才继续"，不是"精确睡满"。
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// StartupInfo 读取
// ---------------------------------------------------------------------------

/// 从 StartupInfo 里按**角色号**取控制台句柄。找不到就返回 None。
///
/// 照抄 user/shell/src/main.rs:171-188 的实现（只读前 24 字节头 + 最多
/// [`MAX_STARTUP_HANDLES`] 条描述，都在那一页内；句柄以 `u64` 直接取，描述是 16 字节
/// 对不齐的 `{ role: u32, kind: u32, handle: u64 }`，所以用 `read_unaligned`）。
///
/// # Safety
/// `si_va` 必须是内核映射好的那一页（`process_start` 校验过 user+只读，user.rs:722），
/// 且在本函数读取期间不被解映射。
pub unsafe fn find_console(si_va: u64) -> Option<Handle> {
    let base = si_va as *const u8;
    // SAFETY: 见函数契约；只读前 24 字节头，都在那一页内，u32 读取用 read_unaligned 对齐无所谓。
    let magic = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_MAGIC) as *const u32) };
    if magic != SI_MAGIC {
        return None;
    }
    // SAFETY: 头部 8 字节处的 nhandles（u32），同在那一页内。
    let n = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_NHANDLES) as *const u32) } as usize;
    let n = if n > MAX_STARTUP_HANDLES { MAX_STARTUP_HANDLES } else { n };
    for i in 0..n {
        // SAFETY: 第 i 条描述的起点 = 24 + i*16，最多 16 条 ⇒ 最远 24+15*16+16 = 280 字节，
        // 仍在那一页内。
        let d = unsafe { base.add(SI_OFF_HANDLES + i * SI_DESC_BYTES) };
        // SAFETY: 描述内 role 字段（u32），落在该条 16 字节内。
        let role = unsafe { core::ptr::read_unaligned(d.add(SI_DESC_ROLE) as *const u32) };
        if role == ROLE_LOG {
            // SAFETY: 描述内 handle 字段（u64），落在该条 16 字节内。
            return Some(unsafe { core::ptr::read_unaligned(d.add(SI_DESC_HANDLE) as *const u64) });
        }
    }
    None
}

/// 33/34/35（ADR-143）：网卡三原语（帧收发 + 读数包）。
pub const SYS_NET_SEND: u64 = 33;
pub const SYS_NET_RECV: u64 = 34;
pub const SYS_NET_INFO: u64 = 35;
/// 网卡读数包（18 字节定长）：MAC6 + 本机 IP4 + 网关4 + DNS4。
/// 读数包 24 字节（ADR-144 从 18 扩到 24）：MAC6 + 本机IP4 + 网关4 + DNS4 + mtu2 + link2。
pub const NET_INFO_BYTES: usize = 24;
/// 36/37ï¼ADR-145ï¼ï¼ARP è¡¨çä¸¤ä¸ªè¯»å£ï¼`ip neigh`ï¼ã
pub const SYS_NET_ARP_LEN: u64 = 36;
pub const SYS_NET_ARP_ENUM: u64 = 37;
/// æ¯æ¡è¡¨é¡¹çå®é¿è®°å½ï¼IP4 + MAC6ï¼ã
pub const ARP_RECORD_LEN: usize = 10;

/// 36ï¼ARP è¡¨é¡¹æ°ã
pub fn arp_len() -> Result<u32, RTError> {
    // SAFETY: 36 å·æ åæ°ã
    let ret = unsafe { syscall_abi(SYS_NET_ARP_LEN, 0, 0, 0, 0) } as i64;
    if ret < 0 { Err(RTError(ret)) } else { Ok(ret as u32) }
}

/// 37ï¼ææ¸¸æ è¯»é¡¹ãè¿å `(n, next)`ï¼`n` æ¬æ¬¡æ¡æ°ï¼`next` ä¸æ¸¸æ¸¸æ ï¼ä¸ 27/31 å·åå½¢ï¼ã
pub fn arp_enum(cursor: u32, buf: &mut [u8]) -> Result<(u32, u32), RTError> {
    if buf.is_empty() || buf.len() > 128 || buf.len() % ARP_RECORD_LEN != 0 {
        return Err(RTError::INVALID);
    }
    // SAFETY: 37 å· rdi=cursorãrsi=bufãrdx=lenãr10=ååå°åã
    let ret = unsafe { syscall_abi(SYS_NET_ARP_ENUM, u64::from(cursor), buf.len() as u64, buf.len() as u64, buf.as_mut_ptr() as u64) } as i64;
    if ret < 0 { return Err(RTError(ret)); }
    Ok((((ret as u64) >> 32) as u32, (ret as u64 & 0xFFFF_FFFF) as u32))
}



/// 33：把一帧交给网卡。`frame` ≤ 1514；成功 Ok(())，形状/IO 错误如实回。
pub fn net_send(frame: &[u8]) -> Result<(), RTError> {
    if frame.is_empty() || frame.len() > 1514 {
        return Err(RTError::INVALID);
    }
    // SAFETY: 33 号 rdi=帧指针、rsi=len（内核 copy_from_user 校验用户半区）。
    let ret = unsafe { syscall_abi(SYS_NET_SEND, frame.as_ptr() as u64, frame.len() as u64, 0, 0) };
    if ret == 0 { Ok(()) } else { Err(RTError(ret as i64)) }
}

/// 34：有界等一帧。`Ok(0)` = 超时；`Ok(n)` = 收到 n 字节（写进 `buf`，帧从 eth 头起）。
pub fn net_recv(buf: &mut [u8], timeout_ms: u64) -> Result<usize, RTError> {
    if buf.is_empty() || buf.len() > 2048 || timeout_ms > 60_000 {
        return Err(RTError::INVALID);
    }
    // SAFETY: 34 号 rdi=buf、rsi=cap、rdx=timeout_ms（内核 copy_to_user 写回）。
    let ret = unsafe { syscall_abi(SYS_NET_RECV, buf.as_mut_ptr() as u64, buf.len() as u64, timeout_ms, 0) };
    Ok(ret as usize)
}

/// 35：读网卡读数包（MAC/本机 IP/网关/DNS，18 字节）。
pub fn net_info() -> Result<[u8; NET_INFO_BYTES], RTError> {
    let mut blk = [0u8; NET_INFO_BYTES];
    // SAFETY: 35 号 rdi=buf（内核 copy_to_user 写回 18 字节定长）。
    // 检查用**符号位**（实测 35 号成功回写入字节数 18 而不是 0，按 ret==0 判会把成功读成 Err(18)）。
    let ret = unsafe { syscall_abi(SYS_NET_INFO, blk.as_mut_ptr() as u64, 0, 0, 0) } as i64;
    if ret < 0 { Err(RTError(ret)) } else { Ok(blk) }
}

/// 构造一帧 ICMP echo request（ADR-140 的内核形状在用户库的镜像）。
/// `gw_mac` 来自 ARP（用户态自己发 request 解），填到 60（最小帧）。
pub fn net_build_icmp(gw_mac: &[u8; 6], our_mac: &[u8; 6], our_ip: &[u8; 4], dst_ip: &[u8; 4], seq: u16) -> [u8; 60] {
    let mut f = [0u8; 60];
    f[0..6].copy_from_slice(gw_mac);
    f[6..12].copy_from_slice(our_mac);
    f[12..14].copy_from_slice(&[0x08, 0x00]);
    f[14] = 0x45;
    f[16] = 0; f[17] = 40;
    f[20] = 0x40; f[22] = 64; f[23] = 1;
    f[26..30].copy_from_slice(our_ip);
    f[30..34].copy_from_slice(dst_ip);
    // **IPv4 头校验和必须算**（实测：漏掉它的帧→slirp 丢弃，永远等不到 echo reply；pcap 里只有发出的 t=8）。
    let mut isum: u32 = 0;
    let mut ik = 14usize;
    while ik < 34 {
        isum += u32::from(f[ik]) << 8 | u32::from(f[ik + 1]);
        ik += 2;
    }
    isum = (isum >> 16) + (isum & 0xFFFF);
    isum = (isum >> 16) + (isum & 0xFFFF);
    let icks = !(isum as u16);
    f[24] = (icks >> 8) as u8;
    f[25] = icks as u8;
    let ic = 34;
    f[ic] = 8;
    f[ic+4..ic+6].copy_from_slice(&0xA5A5u16.to_be_bytes());
    f[ic+6..ic+8].copy_from_slice(&seq.to_be_bytes());
    for k in 0..16 { f[ic+8+k] = 0xA5; }
    let mut sum: u32 = 0;
    let mut k = 0usize;
    while k + 1 < 20 {
        sum += u32::from(f[ic+k]) << 8 | u32::from(f[ic+k+1]);
        k += 2;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    let cks = !(sum as u16);
    f[ic+2] = (cks >> 8) as u8;
    f[ic+3] = cks as u8;
    f
}

/// 构造一帧 ARP request（问谁有 `target_ip`）。42 字节。
pub fn net_build_arp(our_mac: &[u8; 6], our_ip: &[u8; 4], target_ip: &[u8; 4]) -> [u8; 42] {
    let mut f = [0u8; 42];
    f[0..6].copy_from_slice(&[0xFF; 6]);
    f[6..12].copy_from_slice(our_mac);
    f[12..14].copy_from_slice(&[0x08, 0x06]);
    f[14..16].copy_from_slice(&1u16.to_be_bytes());
    f[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    f[18] = 6; f[19] = 4;
    f[20..22].copy_from_slice(&1u16.to_be_bytes());
    f[22..28].copy_from_slice(our_mac);
    f[28..32].copy_from_slice(our_ip);
    f[38..42].copy_from_slice(target_ip);
    f
}