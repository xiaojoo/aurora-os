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
