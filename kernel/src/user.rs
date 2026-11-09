//! M4：用户态闭环 —— 进得去、回得来、越界只杀这个任务。
//!
//! 两条入口：`int 0x80`（IDT 门，硬件按 `TSS.rsp0` 换内核栈并自动关 IF）与
//! `syscall`/`sysret` 快路径（不查 IDT、不换栈，第一条指令是 `swapgs`）。
//! 本文件还留着 M4-1 那页**手写机器码**镜像（测试脚手架），容器那条走真 ELF（`load`）。
//!
//! 决定这段代码形状的规则不在这里重复，在文档里：入口与 GS 窗口 ADR-025、
//! 生效位与架构偏移 ADR-026、结束与回收 ADR-027、地址分区与落脚页 ADR-028，
//! 手册 §10.1 / §10.2 / §10.3.1 / §10.7。

use core::sync::atomic::{AtomicU64, Ordering};

use crate::{elf, mm};
use crate::mm::{ModuleId, PageFlags, VirtAddr};

pub const MOD_USER: ModuleId = ModuleId(16);

/// 系统调用号（§10.2 的 ABI：号在 rax，参数 rdi/rsi/…，返回值 rax，负数是 -ErrorCode）
pub const SYS_PING: u64 = 1;
/// 读用户给的一个 `u64`（§10.3 `copy_from_user` 的最小心智模型：
/// 校验 → 持锁 → 开 SMAP 窗口 → 读 → 关窗口）。
/// **指向内核地址不是"越界"，是"坏参数"**：回 `-EFAULT`，任务继续跑。
/// 这条区分是整个 §10.3 的目的：内核如果因为用户传了个坏指针就杀掉用户，那是拒绝服务；
/// 如果因为传了个坏指针就自己去读了内核页，那是提权。两种都不许发生。
pub const SYS_PEEK: u64 = 4;
/// 把用户给的一段缓冲区读进内核暂存，返回它的 FNV-1a 校验和（§10.3 的跨页形状）。
/// 校验和而不是"拷贝成功与否"：用例要能证明**逐字节准确**，而只看返回值证不了这件事。
pub const SYS_PEEK_BUF: u64 = 5;
/// 内核把 `0xA5 ^ j` 这个模式写进用户给的缓冲区，返回写成的字节数。
/// 程序侧自己按同一个函数核对每一个字节 —— 跨页拷贝"只写满第一页"这种错法只有对面能抓到。
pub const SYS_POKE_BUF: u64 = 6;
/// 返回 ABI 版本与特性位（§10.6）。程序**必须先看到 bit0 才敢用 `syscall`**：
/// LSTAR 没装就打 `syscall` 会跳到 rip=0，那是 ring0 的取指故障 ——
/// 一个用户程序不该有能力把整机打死（§9.2）。
pub const SYS_ABI_INFO: u64 = 7;
/// P7（ADR-007 决定 5）：关闭一个句柄。`rdi`=句柄；成功 `0`。
pub const SYS_HANDLE_CLOSE: u64 = 8;
/// P7：`dup` 到新权限（只能收窄）。`rdi`=句柄、`rsi`=新权限；成功返回新句柄。
pub const SYS_HANDLE_DUP: u64 = 9;
/// P7：从游标继续读。`rdi`=句柄、`rsi`=用户缓冲、`rdx`=长度；成功返回字节数，`0`=EOF。
pub const SYS_FILE_READ: u64 = 10;
/// 12 `vmo_create(pages) -> handle`（ADR-074 / Q1 的号表）。页数 1..=MAX_VMO_PAGES，越界 -1。
pub const SYS_VMO_CREATE: u64 = 12;
/// 13 `vmo_write(h, offset, buf, len) -> n`。第四个参数走 **r10**（syscall 指令吃掉 rcx/r11）。
/// len 0 ⇒ -1，len > COPY_MAX ⇒ -3，对象里放不下 ⇒ -1（**整段先校验，不留半截写**）。
pub const SYS_VMO_WRITE: u64 = 13;
/// 14 `aspace_map(h, writable) -> va`。**VA 由内核从动态区发**，不接受用户指定地址
/// （那会与装载器的窗口撞）；writable 非 0 ⇒ USER_RW，否则 USER_R。**永远不给 X**，
/// 所以 W^X 在这一层就不可能被违反。返回的映射挂进当前任务的资源袋，退出时归还。
pub const SYS_ASPACE_MAP: u64 = 14;

/// ABI 版本。minor=4 对应用户态闭环这一段（M4）；minor=5 追加 capability 句柄族（P7）；
/// minor=6 追加 VMO 三个号（12/13/14）与 `F_VMO` 位（W3 P4b，ADR-074）。号只追加不复用（Q1）。
pub const ABI_MAJOR: u64 = 0;
pub const ABI_MINOR: u64 = 6;
pub const F_FASTPATH: u64 = 1;
pub const F_SMAP: u64 = 2;
pub const F_SMEP: u64 = 4;
/// §9.4 的安全模式。手册反复要的那条是"少了什么必须看得见"：
/// 进安全模式不是"悄悄少起几台设备"，而是让调用方能从这一位读出"现在就是少起的状态"。
/// 位的值直接读 `boot_guard` 的真实状态，不读"我打算开"
pub const F_SAFE_MODE: u64 = 8;
/// P7：capability 句柄表在这份构建里存在（设计 §4.3）。**读回真实状态**：
/// 表只在 `handles` 特性里编译，正常构建这一位必须是 0，8/9/10 也必须走默认分支回 `-1`。
pub const F_HANDLES: u64 = 16;
/// P4b（ADR-074）：VMO 三个号在这份构建里可用。它依赖句柄表，所以与 `F_HANDLES` 同一条件；
/// 读回真实状态，不读"我打算开"。
pub const F_VMO: u64 = 32;

/// `(major << 32) | (minor << 16) | features`。位一律**读回真实状态**，不读"我打算开"。
pub fn abi_word() -> u64 {
    let (smep, smap) = crate::arch::x86_64::cpu::user_protections_active();
    let mut f = 0u64;
    if crate::arch::x86_64::trap::fastpath_on() {
        f |= F_FASTPATH;
    }
    if smap {
        f |= F_SMAP;
    }
    if smep {
        f |= F_SMEP;
    }
    if crate::boot_guard::mode() == crate::boot_guard::BootMode::Safe {
        f |= F_SAFE_MODE;
    }
    #[cfg(feature = "handles")]
    {
        f |= F_HANDLES | F_VMO;
    }
    (ABI_MAJOR << 32) | (ABI_MINOR << 16) | f
}
/// 故意留一个没人认领的号，用来测"未知调用号返回错误码而不是崩"
pub const SYS_NOT_A_NUMBER: u64 = 99;
/// 任务自己结束（§10.2 的 ABI：号在 rax）。
///
/// 为什么必须有一条"自己结束"：没有它，跑完的用户任务会以 Runnable 的身份永远留在
/// run queue 里吃时间片，而它名下的页框、VA 保留与那个槽位**有去无回**
/// （M4-1/M4-2 的台账就是这条）。槽位/页框/保留的归还路径见 `sched::terminate_task`
/// 与 `sched::reap`——两边分开是硬性的：结束的动作在任务自己的栈上做，
/// 释放必须等到"本 CPU 上跑的已经不是它"。
pub const SYS_EXIT: u64 = 3;
/// §10.2 的返回约定：`rax` 里的负数就是 `-ErrorCode`。这张表里**每个号都要有一条真实的
/// 调用走到它**，否则那个号就是装饰（§12.4.1 规则 3：尺子先要能分辨）。
///
/// 编号规则与 §10.2 那句"只增不改"是同一条：新码只能追加在末尾；已公开的号永远不许换含义
///（换含义 = 旧程序把失败读成成功）。
///
/// 为什么**不**在这里预先摆出 `Denied` / `NoMemory` / `WouldBlock` 那一族：capability、
/// 内存压力与阻塞语义今天都没有会返回它们的代码。预先编号只有两种下场——真做的时候撞上已占用的
/// 数字，或者留下一堆"看起来公开过却没人走过"的码。每加一条返回分支，就同时加一条判据。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiError {
    /// -1：未知调用号，或参数的形状就不对。
    /// 证人：`KT_ELF_LOAD` 的 `unk` 槽（程序故意打 `SYS_NOT_A_NUMBER`）
    Invalid = 1,
    /// -2：指针是坏的——不在用户半区 / 没映射 / 不对用户开放 / 往不可写页里写，
    /// 以及跨页拷贝中途被恢复路径接住的故障。
    /// 证人：`KT_USER_POINTER` 的 `peek_kernel` 与 `peek_unmapped` 两格
    Fault = 2,
    /// -3：长度超过 `COPY_MAX`。与 -2 分开是因为**处置方向不同**：调用方把 -2 读成
    /// "我递了个坏地址"，把 -3 读成"我要得太多，换个长度再来"。合成一个号就是把这两种
    /// 混成一种（而 M4-3 第二段刚因为"被截短"与"拷贝坏了"读不出来改过一次）。
    /// 证人：`KT_COPY_USER` 的 `buf_err` 槽（程序故意拿 `COPY_MAX + 1` 打一次）
    TooLong = 3,
    /// -4：句柄权限不够 / 不是主人 / 表项已撤销（P7，设计 §5.1）。
    Denied = 4,
    /// -5：槽不存在或世代号不对（核内 `NoSuch`/`Stale` 分开计数、对用户合成一个）。
    BadHandle = 5,
    /// -6：16 格全满（第一版无配额）。
    Exhausted = 6,
}

/// `ErrorCode` → `rax` 里那个补码。写成 `const fn` 是为了让下面三个公开常量在编译期就算出来，
/// 而不是运行时各自拼一遍——拼错一个符号的现场是"错误码全是正的"，而调用方会当成成功值。
pub const fn err_ret(e: AbiError) -> u64 {
    (-(e as i64)) as u64
}

impl AbiError {
    pub fn describe(e: AbiError) -> &'static str {
        match e {
            AbiError::Invalid => "-EINVAL（未知调用号或参数形状不对）",
            AbiError::Fault => "-EFAULT（指针是坏的）",
            AbiError::TooLong => "-ETOOLONG（长度超过上限）",
            AbiError::Denied => "-EDENIED（权限不够 / 不是主人 / 已撤销）",
            AbiError::BadHandle => "-EBADHANDLE（槽不存在或世代不符）",
            AbiError::Exhausted => "-EEXHAUSTED（句柄表满）",
        }
    }
}

/// §10.2 冻结的三个返回值。**判据里写的是数字本身**（-1 / -2 / -3），不是"等于 `E_TOO_LONG`"——
/// 常量自己也会被人改，改错了要能被看见（同一条纪律见 `elf.rs`：不可想的地方要 checked）。
pub const E_INVALID: u64 = err_ret(AbiError::Invalid);
pub const E_FAULT: u64 = err_ret(AbiError::Fault);
pub const E_TOO_LONG: u64 = err_ret(AbiError::TooLong);
pub const E_DENIED: u64 = err_ret(AbiError::Denied);
pub const E_BAD_HANDLE: u64 = err_ret(AbiError::BadHandle);
pub const E_EXHAUSTED: u64 = err_ret(AbiError::Exhausted);

#[cfg(feature = "handles")]
fn handle_err(e: crate::handle::HErr) -> u64 {
    use crate::handle::HErr;
    match e {
        HErr::Invalid => E_INVALID,
        HErr::NoSuch | HErr::Stale => E_BAD_HANDLE,
        HErr::NotOwner | HErr::Denied => E_DENIED,
        HErr::Exhausted => E_EXHAUSTED,
        // ABI 表里还没有 EIO 码（设计 §5.1 只批了 -4/-5/-6）。块设备失败**不许被抹成别的成因**：
        // 打一行点名，再按 -2 带出去；新增 EIO 需要 ADR 级批准（BACKLOG 登记）。
        HErr::Io(_) => {
            crate::log_info!("abi: file_read 块设备失败（{}）⇒ 暂按 -2 带出", e.tag());
            E_FAULT
        }
    }
}

/// `SYS_FILE_READ`：rdi=句柄，rsi=用户缓冲，rdx=长度。长度是用户给的数：先判形状再碰盘。
/// 读是**分块**的（一块一个扇区）：表锁不在盘 I/O 内，复制失败时票作废、游标一格不动。
#[cfg(feature = "handles")]
/// 12：建一个 VMO 并把创建者那一份引用**交给句柄**（所以 refs 最终是 1，不是 2）。
#[cfg(feature = "handles")]
fn sys_vmo_create(frame: &crate::arch::x86_64::trap::TrapFrame) -> u64 {
    let pages = frame.rdi as usize;
    if pages == 0 || pages > crate::vmo::MAX_VMO_PAGES {
        return E_INVALID;
    }
    let Some(owner) = crate::sched::current_identity() else { return E_BAD_HANDLE };
    let id = match crate::vmo::vmo_create(pages) {
        Ok(v) => v,
        // 表满与帧不够都按 -6 带出：今天 ABI 没有单独的 ENOMEM（新增要 ADR 级批准）
        Err(_) => return E_EXHAUSTED,
    };
    let rights = crate::handle::RIGHT_READ | crate::handle::RIGHT_WRITE
        | crate::handle::RIGHT_MAP | crate::handle::RIGHT_DUP;
    let r = crate::handle::grant_vmo(owner, id, rights);
    // 句柄拿到了自己那份引用，创建者这份必须交出去；grant 失败也一样要还，否则漏帧
    crate::vmo::vmo_unref(id);
    match r {
        Ok(h) => h.0,
        Err(e) => handle_err(e),
    }
}

/// 13：把用户缓冲写进 VMO。512 字节一块搬（与 `sys_file_read` 同一手法，不按用户的数开缓冲）。
/// **整段先校验长度**：放不下就一个字节都不写，不留"写了一半再报错"的中间态。
#[cfg(feature = "handles")]
fn sys_vmo_write(frame: &crate::arch::x86_64::trap::TrapFrame) -> u64 {
    let want = frame.r10 as usize;
    if want == 0 {
        return E_INVALID;
    }
    if want > COPY_MAX {
        return E_TOO_LONG;
    }
    let Some(owner) = crate::sched::current_identity() else { return E_BAD_HANDLE };
    let id = match crate::handle::vmo_of(crate::handle::Handle(frame.rdi), owner, crate::handle::RIGHT_WRITE) {
        Ok(v) => v,
        Err(e) => return handle_err(e),
    };
    let offset = frame.rsi as usize;
    let pages = match crate::vmo::vmo_pages(id) {
        Some(n) => n,
        None => return E_BAD_HANDLE,
    };
    match offset.checked_add(want) {
        Some(end) if end <= pages * mm::PAGE => {}
        _ => return E_INVALID,
    }
    let mut chunk = [0u8; crate::filesystem::vfs::SECTOR_BYTES];
    let mut done = 0usize;
    while done < want {
        let ask = core::cmp::min(chunk.len(), want - done);
        match copy_from_user(frame.rdx + done as u64, &mut chunk[..ask]) {
            Ok(n) if n == ask => {}
            _ => {
                BAD_PTRS.fetch_add(1, Ordering::Relaxed);
                crate::log_info!("abi: vmo_write 读用户缓冲失败，已搬 {}/{} 字节", done, want);
                return E_FAULT;
            }
        }
        match crate::vmo::vmo_write(id, offset + done, &chunk[..ask]) {
            Ok(n) => done += n,
            Err(_) => return E_BAD_HANDLE,
        }
    }
    done as u64
}

/// 14：把 VMO 铺进调用者自己的 AS（今天 = AS_KERNEL），VA 由内核从动态区发。
/// 映射挂进当前任务的资源袋 ⇒ 任务退出时由 `release_owned` 在锁外 drop（清叶子 + 还参考 + 放手 VA）。
#[cfg(feature = "handles")]
fn sys_aspace_map(frame: &crate::arch::x86_64::trap::TrapFrame) -> u64 {
    let Some(owner) = crate::sched::current_identity() else { return E_BAD_HANDLE };
    let id = match crate::handle::vmo_of(crate::handle::Handle(frame.rdi), owner, crate::handle::RIGHT_MAP) {
        Ok(v) => v,
        Err(e) => return handle_err(e),
    };
    let pages = match crate::vmo::vmo_pages(id) {
        Some(n) => n,
        None => return E_BAD_HANDLE,
    };
    // 永远不给 X：写权由用户选，执行权不给，所以 W^X 在这一层就排掉了
    let flags = if frame.rsi != 0 { mm::PageFlags::USER_RW } else { mm::PageFlags::USER_R };
    let va = match mm::alloc_user_va_range(pages) {
        Some(v) => v,
        None => return E_EXHAUSTED,
    };
    let m = match crate::vmo::vmo_map_self(id, va, flags) {
        Ok(m) => m,
        Err(_) => {
            // 铺不成就要把刚发的 VA 还回去，否则动态区会被失败调用吃光
            mm::release_va(va.0);
            return E_EXHAUSTED;
        }
    };
    match crate::sched::own_current(crate::sched::OwnedItem::AsMap(m)) {
        Ok(()) => va.0,
        // 袋子满了：own_current 会**先放 RUNQ 再 drop**，映射与 VA 都由那个 Drop 还掉
        Err(_) => E_EXHAUSTED,
    }
}

#[cfg(feature = "handles")]
fn sys_file_read(frame: &crate::arch::x86_64::trap::TrapFrame) -> u64 {
    let want = frame.rdx as usize;
    if want == 0 {
        return E_INVALID;
    }
    if want > COPY_MAX {
        return E_TOO_LONG;
    }
    let Some(owner) = crate::sched::current_identity() else {
        return E_BAD_HANDLE;
    };
    let mut ticket = match crate::handle::begin_read(crate::handle::Handle(frame.rdi), owner) {
        Ok(t) => t,
        Err(e) => return handle_err(e),
    };
    let disk = crate::filesystem::vfs::AhciDisk { port: ticket.port() };
    let mut chunk = [0u8; crate::filesystem::vfs::SECTOR_BYTES];
    let mut done = 0usize;
    while done < want {
        let ask = core::cmp::min(chunk.len(), want - done);
        match ticket.read_chunk(&disk, &mut chunk[..ask]) {
            Ok(0) => break, // EOF
            Ok(n) => match copy_to_user(&chunk[..n], frame.rsi + done as u64) {
                Ok(m) if m == n => done += n,
                _ => {
                    // 中途写用户内存失败：**不提交游标**（重试会重新交付这几字节）。
                    BAD_PTRS.fetch_add(1, Ordering::Relaxed);
                    crate::handle::abort(ticket);
                    crate::log_info!("abi: file_read 写用户缓冲失败，游标未提交");
                    return E_FAULT;
                }
            },
            Err(e) => {
                // 盘读失败：票作废，游标一格不动
                crate::handle::abort(ticket);
                return handle_err(e);
            }
        }
    }
    match crate::handle::finish(ticket, done) {
        Ok(()) => done as u64,
        Err(e) => handle_err(e),
    }
}

/// 容器镜像里 `.slots` 的布局（§10.7）。这一份与 `user/hello/src/main.rs` 里那一份是
/// **两次独立声明**：程序侧用 `offset_of!` 在编译期核对字段顺序，内核侧靠装载之后
/// 读回来的魔数核对。两边都写死同一组数字不是重复——那正是这条 ABI 的两个取证点，
/// 少一个就变成"只有写字节的人自己说它对"。
///
/// 上一版的教训是具体的：把三个 peek 格子插在 `flag` 前面，内核写的 48 落在了
/// `peek_ok` 上、真的 `flag` 停在 72 没人写，表现是"一个实验都没跑"，
/// 读起来像退出路径坏了。字段顺序 = ABI，它必须由两台仪器分别量。
pub const ABI_SLOT_MAGIC: u64 = 0;
pub const ABI_SLOT_PING: u64 = 8;
pub const ABI_SLOT_ADD: u64 = 16;
pub const ABI_SLOT_UNKNOWN: u64 = 24;
pub const ABI_SLOT_RODATA: u64 = 32;
pub const ABI_SLOT_LOOPS: u64 = 40;
/// **输入**格：内核在装载之后写进来，决定这个任务跑完调用序列之后怎么走。
pub const ABI_SLOT_FLAG: u64 = 48;
pub const ABI_SLOT_PEEK_OK: u64 = 56;
pub const ABI_SLOT_PEEK_KERNEL: u64 = 64;
pub const ABI_SLOT_PEEK_UNMAPPED: u64 = 72;
/// 内核在装载之后把**可写段自己的页基址**写进来。程序要算一段跨页缓冲区的地址，
/// 而 `relocation-model=static` 下"取某个静态量的地址"会退化成 32 位绝对重定位
/// （镜像基址在 4 GiB 之上，`R_X86_64_32S` 直接装不下——M4-2 踩过一次）。
/// 由内核把地址递进来，程序只做加法：这既绕开重定位，也更接近真实 ABI
/// （参数由调用方给，不由被调用方猜）。
pub const ABI_SLOT_SELF_VA: u64 = 80;
/// `SYS_POKE_BUF` 的核对结果：`1` = 每个字节都对，其余 = 第一个不对的字节序号 + 1。
pub const ABI_SLOT_BUF_OK: u64 = 88;
/// `SYS_PEEK_BUF` 的返回值（内核算出的校验和），程序原样存回来。
pub const ABI_SLOT_BUF_SUM: u64 = 96;
/// 缓冲区实验里内核报回的字节数（`SYS_POKE_BUF` 那一次）。
pub const ABI_SLOT_BUF_N: u64 = 104;
/// 故意要一个超限长度时内核回的错误码（`AbiError::TooLong` = `-3`）。
/// 这一格存在的理由是"每个号都要有人走过"：没有它，`-3` 就只是一个写在表里的数。
pub const ABI_SLOT_BUF_ERR: u64 = 112;
/// `sys_abi_info()` 的字、以及快路径回来后**程序自己读回的 CS/SS** 与第一次快调用的返回值。
pub const ABI_SLOT_ABI_WORD: u64 = 120;
pub const ABI_SLOT_FAST_CS: u64 = 128;
pub const ABI_SLOT_FAST_SS: u64 = 136;
pub const ABI_SLOT_FAST_PING: u64 = 144;
/// P7：装载器授予容器的文件句柄（指向容器自己的镜像），以及 ring3 那六格的读数。
/// 偏移与程序侧 `OFF_H*` 是**两次独立声明**（同 `.slots` 的既有纪律）。
pub const ABI_SLOT_HANDLE: u64 = 152;
pub const ABI_SLOT_H_MAGIC: u64 = 160;
pub const ABI_SLOT_H_DONE: u64 = 168;
/// `flag` 的位（与程序侧 `FLAG_*` 同一套编号）
pub const FLAG_EXIT: u64 = 1;
pub const FLAG_GUARD_STORE: u64 = 2;
pub const FLAG_PEEK: u64 = 4;
/// 跨页缓冲区实验：内核写一段模式进来、程序核对；程序再写另一段模式、让内核读走算校验和。
pub const FLAG_BUF: u64 = 8;
/// 快路径那一档（`sys_abi_info` + 八次 `syscall`）。
pub const FLAG_FASTPATH: u64 = 16;
/// P7：ring3 句柄实验（读自己镜像 / dup 收窄 / 越权 / close / 旧句柄）。
pub const FLAG_HANDLE: u64 = 32;
/// 跨页实验用的缓冲区：从可写段第一页的 `0xF00` 开始、长 `0x200` 字节 ⇒ **最后 0x100 字节在第 2 页**。
pub const BUF_OFF: u64 = 0xF00;
pub const BUF_LEN: usize = 0x200;

/// 用户页的布局（一个 blob + 三个结果槽 + 一条用户栈）
const CODE_OFF: u64 = 0;
pub const SLOT_PING: u64 = 0x00;
pub const SLOT_ADD: u64 = 0x08;
pub const SLOT_UNKNOWN: u64 = 0x10;
/// `jmp .`（机器码 EB FE）在代码页里的偏移：手写镜像打完三次调用之后就停在这儿等换出。
/// **它不是 kill 的落脚处**——那是 `TRAMPOLINE_VA` 的职责（见那里的注释：让被杀的容器任务
/// 跳进"只有测试脚手架才会建的页"，是一条看不见也保不住的依赖）。
const PARK_OFF: u64 = 64;
/// RFLAGS.IF（bit9）。`park_current` 要按本 CPU 的窗口把它写进返回用户态的那张帧。
const RFLAGS_IF: u64 = 1 << 9;

pub struct UserProg {
    pub code_va: u64,
    pub data_va: u64,
    pub stack_va: u64,
    pub stack_top: u64,
    pub entry: u64,
}

static PROG: AtomicU64 = AtomicU64::new(0); // 非 0 = 已建好；结构本身放下面那个 cell
struct ProgCell(core::cell::UnsafeCell<Option<UserProg>>);
// SAFETY: `init` 只在启动期由 BSP 调一次（与 apic::StateCell 同一条前提），之后只读
unsafe impl Sync for ProgCell {}
static PROG_PTR: ProgCell = ProgCell(core::cell::UnsafeCell::new(None));

static SYSCALLS_SERVED: AtomicU64 = AtomicU64::new(0);
static UNKNOWN_NR: AtomicU64 = AtomicU64::new(0);
static KILLS: AtomicU64 = AtomicU64::new(0);
static EXITS: AtomicU64 = AtomicU64::new(0);
/// 被指针校验挡下来的次数（判据要能区分"内核拒了"与"内核根本没检查"）
static BAD_PTRS: AtomicU64 = AtomicU64::new(0);

pub fn served() -> u64 {
    SYSCALLS_SERVED.load(Ordering::Relaxed)
}
pub fn unknown_nr() -> u64 {
    UNKNOWN_NR.load(Ordering::Relaxed)
}
pub fn kills() -> u64 {
    KILLS.load(Ordering::Relaxed)
}

/// 自己结束的任务数（与 `kills` 分开数：**被杀**与**自己退出**是两件事，
/// 混成一个数就看不出"隔离生效"和"生命周期走完"哪个还在欠账）。
pub fn exits() -> u64 {
    EXITS.load(Ordering::Relaxed)
}

/// 被 `validate_user_ptr` 拒绝过几次。
pub fn bad_ptrs() -> u64 {
    BAD_PTRS.load(Ordering::Relaxed)
}

fn reset_counters() {
    SYSCALLS_SERVED.store(0, Ordering::Relaxed);
    UNKNOWN_NR.store(0, Ordering::Relaxed);
    KILLS.store(0, Ordering::Relaxed);
    EXITS.store(0, Ordering::Relaxed);
    BAD_PTRS.store(0, Ordering::Relaxed);
}

/// **内核拥有的用户态落脚页**（vsyscall 那一族的形状）：`USER_RX` 一页，内容只有 `jmp .`，
/// 建好之后永不撤销。kill 的出口必须跳进一个**不属于任何任务**的可执行用户地址，
/// 否则同一个故障每秒重演几千次；它不能由测试脚手架提供，否则"容器被杀往哪儿跳"
/// 取决于 `.ktests` 的链接顺序。论证、现场与判据（`tramp_ok`）：ADR-028、§10.7。
///
/// **W3 P5b（ADR-075 决策 7，使用者裁决）：从用户窗口顶端搬进内核半区共享一份。**
/// 原来它是 `USER_VA_TOP - PAGE`，每个 AS 都得各自映一份，而 VA 保留表是**全局一张**
/// （3a 裁决）⇒ N 个进程要 N 条保留、`TRAMPOLINE_VA` 也不再是常量。
/// 搬进内核半区之后：所有 AS 的高 256 项复制自 AS_KERNEL、下层表本来就共享（ADR-070 决策 2），
/// 一份就够，且不占动态区的保留格。选址在动态分配区的**上界之下一页**
/// （`alloc_va_range` 扫到 `0xffff_ffff_7000_0000` 为止），既不在镜像（`0xffffffff80000000` 起）
/// 也不在 HHDM 里；`reserve_va_at` 占住它之后分配器会跳过。
/// **必须在第一个非内核 AS 创建之前建**（否则就是往冻结后的内核半区铺新映射），
/// 这条下面变成显式拒绝，不靠调用顺序的运气。
pub const TRAMPOLINE_VA: u64 = 0xffff_ffff_6ff0_0000;

static TRAMP: AtomicU64 = AtomicU64::new(0);

/// 已经建好时返回它的 VA，否则现场建一页。**幂等**，失败返回 None（调用方必须拒绝建任务）。
///
/// 只在**进程上下文**调用（`init` / `load` 的开头）：这里要拿 VMM 锁、要发页框，
/// 而 §6.3 那条"中断上下文不许分配"的约束就是针对这种动作。
/// 不做并发保护是有前提的：今天只有 BSP 跑用例，两条入口都在持锁的那一段里；
/// 真正多任务 exec 的时候这一页改由启动序列建（已记 BACKLOG）。
pub fn ensure_trampoline() -> Option<u64> {
    let got = TRAMP.load(Ordering::Acquire);
    if got != 0 {
        return Some(got);
    }
    // 冻结前置（ADR-070 决策 2 / ADR-075 决策 7）：跳板现在住内核半区，
    // 已有非内核 AS 之后再建它就是往冻结后的共享表里铺新映射 ⇒ 明确拒绝，不静默。
    let aspaces = mm::aspace_count();
    if aspaces != 0 {
        crate::log_fatal!(
            "user: trampoline 必须在第一个 AS 之前建（此刻已有 {} 个非内核 AS）", aspaces);
        return None;
    }
    if !mm::reserve_va_at(TRAMPOLINE_VA, 1) {
        crate::log_fatal!("user: trampoline 的 VA 被占了（{:#x}）", TRAMPOLINE_VA);
        return None;
    }
    let f = match mm::phys_alloc(0, MOD_USER) {
        Ok(f) => f,
        Err(e) => {
            mm::release_va(TRAMPOLINE_VA);
            crate::log_fatal!("user: trampoline 发不出页框 {:?}", e);
            return None;
        }
    };
    // 内容经 HHDM 直写，再来装叶子——与 `init()` 里同一条理由：`USER_RX` 装完叶子就写不进去，
    // 而直写路径不碰 SMAP 窗口。整页清零 + 头两条字节是 `jmp .`。
    // SAFETY: HHDM 别名、恰好一页、这块帧除了我们没有任何主人（还没装叶子）
    unsafe {
        core::ptr::write_bytes(f.base().via_hhdm().0 as *mut u8, 0, mm::PAGE);
        core::ptr::write_volatile(
            f.base().via_hhdm().0 as *mut u16,
            u16::from_le_bytes([0xEB, 0xFE]),
        );
    }
    let m = match mm::map(VirtAddr(TRAMPOLINE_VA), f, PageFlags::USER_RX) {
        Ok(m) => m,
        Err(e) => {
            mm::release_va(TRAMPOLINE_VA);
            crate::log_fatal!("user: trampoline 映射失败 {:?}", e);
            return None;
        }
    };
    // 这一页的所有权**故意不交给任何任务**：它是内核的设施，不是任务名下的资源。
    core::mem::forget(m);
    TRAMP.store(TRAMPOLINE_VA, Ordering::Release);
    // 快路径与落脚页同批装：两条都是"让 ring3 进得来"的设施，装不装不该看调用顺序。
    // 不在 `init_cpu_tables` 里装，是因为那一刻 MM 还没接管，GS 基址指向的内核 VA
    // 与换页表之后的含义还没对上。快路径是**可选**的：CPUID 不支持就返回 false 照常跑。
    crate::arch::x86_64::trap::install_fastpath(crate::arch::x86_64::cpu::self_slot());
    Some(TRAMPOLINE_VA)
}

/// 用例读的那一格：0 = 还没建。
pub fn trampoline() -> u64 {
    TRAMP.load(Ordering::Acquire)
}

/// 手写机器码。每段后面注的就是它对应的指令，偏移要和 `PARK_OFF` 对得上。
/// `moffs` 形式（`48 A3` + 8 字节绝对地址）避开了 RIP 相对位移的计算：
/// 用户页的 VA 在建页时才知道，绝对地址直接填进去，少一处只有跑起来才会暴露的错。
fn blob(store: u64) -> [u8; 66] {
    let d0 = (store + SLOT_PING).to_le_bytes();
    let d1 = (store + SLOT_ADD).to_le_bytes();
    let d2 = (store + SLOT_UNKNOWN).to_le_bytes();
    let mut b = [0u8; 66];
    let mut i = 0usize;
    // mov rax, 1
    b[i..i + 7].copy_from_slice(&[0x48, 0xC7, 0xC0, 1, 0, 0, 0]);
    i += 7;
    // int 0x80
    b[i..i + 2].copy_from_slice(&[0xCD, 0x80]);
    i += 2;
    // mov [SLOT_PING], rax
    b[i..i + 2].copy_from_slice(&[0x48, 0xA3]);
    b[i + 2..i + 10].copy_from_slice(&d0);
    i += 10;
    // mov rax, 2
    b[i..i + 7].copy_from_slice(&[0x48, 0xC7, 0xC0, 2, 0, 0, 0]);
    i += 7;
    // mov rdi, 0x2a
    b[i..i + 7].copy_from_slice(&[0x48, 0xC7, 0xC7, 0x2a, 0, 0, 0]);
    i += 7;
    // int 0x80
    b[i..i + 2].copy_from_slice(&[0xCD, 0x80]);
    i += 2;
    // mov [SLOT_ADD], rax
    b[i..i + 2].copy_from_slice(&[0x48, 0xA3]);
    b[i + 2..i + 10].copy_from_slice(&d1);
    i += 10;
    // mov rax, 99（一个没人认领的号）
    b[i..i + 7].copy_from_slice(&[0x48, 0xC7, 0xC0, 99, 0, 0, 0]);
    i += 7;
    // int 0x80
    b[i..i + 2].copy_from_slice(&[0xCD, 0x80]);
    i += 2;
    // mov [SLOT_UNKNOWN], rax
    b[i..i + 2].copy_from_slice(&[0x48, 0xA3]);
    b[i + 2..i + 10].copy_from_slice(&d2);
    i += 10;
    // jmp .（ park：任务被杀掉之后就停在这儿，等下一次 tick 把它换下去）
    b[i..i + 2].copy_from_slice(&[0xEB, 0xFE]);
    i += 2;
    // 长度必须正好填满到 PARK_OFF + 2：不等就说明上面某段的字节数写错了，
    // 而写错的后果是"park 落在别人的指令中间"，读起来像随机 #UD。
    // （第一次跑就把这条撞上了：断言写成 `i == PARK_OFF`，而 `i` 是加完 jmp 之后的
    // 总长，于是每次 init 都 panic —— 断言自己也会错，错了要能看见。）
    assert!(i == (PARK_OFF + 2) as usize, "blob 长度与 PARK_OFF 不一致");
    b
}

/// 建脚手架镜像：一页代码（USER_RX）、一页数据（USER_RW）、一页栈（USER_RW，下面留 guard 页）。
/// **内容一律经 HHDM 写好，再来装叶子**：`USER_RX` 装完叶子就写不进去（W^X），
/// 而直写路径不需要 SMAP 窗口，于是"内核构造用户内存"与"内核事后读用户内存"分成两条路。
/// 两条理由与实测现场：§10.7 的 HHDM 那一行、ADR-026 决策一。
pub fn init() -> Result<&'static UserProg, mm::MmError> {
    if PROG.load(Ordering::Acquire) != 0 {
        // SAFETY: 见 ProgCell
        return Ok(unsafe { (*PROG_PTR.0.get()).as_ref().unwrap() });
    }
    // 先有落脚页，再建用户任务：`init` 建的镜像不再是 kill 的前提，但它自己也要有
    // 一条"故障时往哪儿跳"的路（顺序在这里没有特例——两条入口做同一件事）。
    if ensure_trampoline().is_none() {
        return Err(mm::MmError::OutOfMemory);
    }
    // 栈：保留 2 页，低那一页永不映射当 guard。
    // **三段都走 `alloc_user_va_range`**：用户页的整条页表链必须带 U/S=1，
    // 而内核半区的上级表项是为内核建的（见 mm::USER_VA_BASE 的注释）。
    let swin = mm::alloc_user_va_range(2).ok_or(mm::MmError::OutOfMemory)?;
    let stack_guard = swin.0;
    let stack_va = swin.0 + mm::PAGE as u64;
    // 代码 + 数据：两段独立的单页保留（不是一段两页：W^X 要求它们各自只有自己的属性）
    let cwin = mm::alloc_user_va_range(1).ok_or(mm::MmError::OutOfMemory)?;
    let dwin = mm::alloc_user_va_range(1).ok_or(mm::MmError::OutOfMemory)?;
    let sf = mm::phys_alloc(0, MOD_USER)?;
    let cf = mm::phys_alloc(0, MOD_USER)?;
    let df = mm::phys_alloc(0, MOD_USER)?;

    let bytes = blob(dwin.0);
    // SAFETY: 三个 `base().via_hhdm()` 落在内核的直接映射里（RW、恒等覆盖全部物理内存），
    // 每个恰好一页；这些页框刚由 phys_alloc 发出来，还没有别的主人，也还没有被映射成
    // 用户页——所以这段写既不碰 SMAP（不是 U/S 页），也不碰 W^X（不是 RX 页）。
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), cf.base().via_hhdm().0 as *mut u8, bytes.len());
        // 三个槽先填"没写过"的哨兵，用例才能区分"用户真写了"与"页本来就是 0"
        for k in 0..3u64 {
            core::ptr::write_volatile((df.base().via_hhdm().0 + k * 8) as *mut u64, 0xdead_beef);
        }
        core::ptr::write_volatile(sf.base().via_hhdm().0 as *mut u64, 0);
    }
    let m = mm::map(VirtAddr(stack_va), sf, PageFlags::USER_RW)?;
    // 手写镜像这一份**故意不交给任务**：它是测试脚手架，两个任务共用同一套页
    // （blob 的代码页 + 数据页），交给其中一个就会在它退出时把另一个还在用的页抽掉。
    // 容器那条路径不一样：`load` 一次一份，所以那份资源归装它的任务所有。
    core::mem::forget(m);
    let mc = mm::map(cwin, cf, PageFlags::USER_RX)?;
    core::mem::forget(mc);
    let md = mm::map(dwin, df, PageFlags::USER_RW)?;
    core::mem::forget(md);

    let code_va = cwin.0;
    let data_va = dwin.0;
    let stack_top = stack_va + mm::PAGE as u64 - 16;
    let p = UserProg {
        code_va,
        data_va,
        stack_va,
        stack_top,
        entry: code_va + CODE_OFF,
    };
    // SAFETY: 见 ProgCell
    unsafe {
        *PROG_PTR.0.get() = Some(p);
        PROG.store(1, Ordering::Release);
    }
    // guard 页必须真的没映射，否则"栈溢出"会变成"写到别人的页上"
    if mm::is_mapped(stack_guard) {
        return Err(mm::MmError::AlreadyMapped);
    }
    // SAFETY: 上面已置 Some
    Ok(unsafe { (*PROG_PTR.0.get()).as_ref().unwrap() })
}

/// 读用户页里的一个槽。**这条路径就是 §10.3 的最小版本**：
/// 内核直接碰用户页必须开 SMAP 窗口（STAC/CLAC），否则就是 #PF。
///
/// 现在它是 `peek_u64` 的一层薄封装（以前这里是**自己开窗口**、不校验任何事，
/// 唯一把关人是函数头上那句 SAFETY 注释——而注释拦不住下一个调用点）。
/// 改成走校验之后，内核里"不经校验就能开窗口读用户页"的入口只剩两个，
/// 而且都是写明用途的探针：`probe_slot_without_window`（故意**不**开窗，验 SMAP 生效）
/// 与 `probe_copy_from`（故意跳过校验，验恢复路径）。
pub fn read_slot(off: u64) -> Option<u64> {
    let p = prog()?;
    read_at(p.data_va + off)
}

/// 内核**经校验地写**用户页的一个 `u64`（走 `copy_to_user`，所以带校验、带恢复登记）。
///
/// 这一条以前是"自己 `stac`/`clac` 包一次裸写"，唯一把关人是函数头上那句 SAFETY 注释。
/// **注释拦不住下一个调用点**：它不检查目标是不是用户页、可不可写，也不管窗口里会不会故障。
/// 现在两条入口（读 / 写）都必须过校验，而"被拒"是要被看见的：这里打 `fatal` 行并计数，
/// 因为调用方是用例，用例的铺垫没落地就必须留下名字，不能安静地变成一个"没跑成的实验"
///（M4-2 撞过一次：flag 没写进去，表现是"退出路径坏了"）。
pub fn write_at(va: u64, v: u64) {
    match copy_to_user(&v.to_le_bytes(), va) {
        Ok(n) if n == 8 => {}
        Ok(n) => {
            BAD_PTRS.fetch_add(1, Ordering::Relaxed);
            crate::log_fatal!("abi: 内核写用户页只落地 {n}/8 字节 va={va:#x}（中途被恢复路径接住）");
        }
        Err(e) => {
            BAD_PTRS.fetch_add(1, Ordering::Relaxed);
            crate::log_fatal!("abi: 拒绝了一次内核侧的用户页写 va={va:#x} —— {}", PtrError::describe(e));
        }
    }
}

/// 故意**不开** SMAP 窗口去读用户页：CR4.SMAP 打开时这必须故障。
/// 返回"故不故障"由用例判：没故障 = 隔离根本没生效（§5.1 R17 的必需项就是靠这条撑着）。
pub fn probe_slot_without_window(off: u64) -> Option<u64> {
    let p = prog()?;
    crate::arch::x86_64::trap::probe_page_fault(p.data_va + off)
}

pub fn prog() -> Option<&'static UserProg> {
    if PROG.load(Ordering::Acquire) == 0 {
        return None;
    }
    // SAFETY: 见 ProgCell
    unsafe { (*PROG_PTR.0.get()).as_ref() }
}

/// `int 0x80` 的内核侧。只读寄存器、不读用户内存 —— M4-1 的参数都在寄存器里，
/// 所以这条路径今天**不需要** SMAP 窗口；这也是一条要守住的设计约束
/// （入口里一开窗口，故障归属就复杂一倍）。
/// 返回 `true` = 这个任务要求结束（分发层据此给 `Action::Exit`）。
///
/// 这里**只立请求，不释放任何东西**：此刻的上下文就是要求结束的那个任务，
/// 它正站在自己要交出去的内核栈上。真正的解映射与归还由 `sched::reap` 在
/// 本 CPU 换别人上来之后做（§6.3 R13 的主人负责 + §9.2 的"别在故障点上自杀")。
pub fn syscall_dispatch(frame: &mut crate::arch::x86_64::trap::TrapFrame) -> bool {
    let n = SYSCALLS_SERVED.fetch_add(1, Ordering::Relaxed) + 1;
    // `exit` 是一个显式的控制流状态，**不是**"看返回值像不像 0"。
    // 后者是拿值的巧合当控制流：将来任何一个回 0 的调用（`sys_nop`、成功的
    // `sys_close(0)`……）都会顺手把调用它的任务杀掉，那种 bug 不会报错，只会少进程。
    let mut exit = false;
    frame.rax = match frame.rax {
        SYS_PING => n,
        2 => frame.rdi.wrapping_add(frame.rsi), // 参数确实穿过来了：0x2a + 0x12
        SYS_EXIT => {
            EXITS.fetch_add(1, Ordering::Relaxed);
            exit = true;
            0 // §10.2：非负为成功值
        }
        SYS_PEEK => {
            // 参数是**用户给的指针**：坏指针回 -EFAULT，绝不因为"传了个坏值"就杀任务，
            // 也绝不去读内核半区的地址（那是提权）。见 SYS_PEEK 的注释。
            match peek_u64(frame.rdi) {
                Ok(v) => v,
                Err(e) => {
                    BAD_PTRS.fetch_add(1, Ordering::Relaxed);
                    match e {
                        PtrError::NotUserRange | PtrError::NotSharedWithUser => {
                            crate::log_info!("abi: 拒绝了一个指向内核侧的用户指针（{}）", PtrError::describe(e))
                        }
                        _ => {}
                    }
                    E_FAULT
                }
            }
        }
        SYS_PEEK_BUF => {
            // rdi = 缓冲区地址，rsi = 长度。**长度也是用户给的数**，所以两件事都要判：
            // 超过 `COPY_MAX` 明确拒绝（不是悄悄截短），跨页的每一页各自校验。
            let want = frame.rsi as usize;
            match copy_into_scratch(frame.rdi, want) {
                Ok((n, sum)) if n == want => sum,
                Ok((n, _)) => {
                    BAD_PTRS.fetch_add(1, Ordering::Relaxed);
                    crate::log_info!("abi: 跨页拷贝中途故障，只搬成 {}/{} 字节", n, want);
                    E_FAULT
                }
                Err(e) => {
                    BAD_PTRS.fetch_add(1, Ordering::Relaxed);
                    crate::log_info!("abi: 拒绝了一个缓冲区指针（{}）", PtrError::describe(e));
                    ptr_err_to_ret(e)
                }
            }
        }
        SYS_ABI_INFO => abi_word(),
        #[cfg(feature = "handles")]
        SYS_HANDLE_CLOSE => match crate::sched::current_identity() {
            Some(owner) => match crate::handle::close(crate::handle::Handle(frame.rdi), owner) {
                Ok(()) => 0,
                Err(e) => handle_err(e),
            },
            None => E_BAD_HANDLE,
        },
        #[cfg(feature = "handles")]
        SYS_HANDLE_DUP => match crate::sched::current_identity() {
            Some(owner) => match crate::handle::dup(
                crate::handle::Handle(frame.rdi),
                owner,
                frame.rsi as u32,
            ) {
                Ok(h) => h.0,
                Err(e) => handle_err(e),
            },
            None => E_BAD_HANDLE,
        },
        #[cfg(feature = "handles")]
        SYS_FILE_READ => sys_file_read(frame),
        #[cfg(feature = "handles")]
        SYS_VMO_CREATE => sys_vmo_create(frame),
        #[cfg(feature = "handles")]
        SYS_VMO_WRITE => sys_vmo_write(frame),
        #[cfg(feature = "handles")]
        SYS_ASPACE_MAP => sys_aspace_map(frame),
        SYS_POKE_BUF => {
            // 内核 → 用户。写成 `Ok(n)` 而不是布尔：`n != want` 就是"中途被接住的故障"，
            // 程序核对字节时看得见的差异与内核报回的数必须一致（两台仪器不能各说各话）。
            let want = frame.rsi as usize;
            match poke_pattern_into(frame.rdi, want) {
                Ok(n) => n as u64,
                Err(e) => {
                    BAD_PTRS.fetch_add(1, Ordering::Relaxed);
                    crate::log_info!("abi: 拒绝了一个写缓冲区指针（{}）", PtrError::describe(e));
                    ptr_err_to_ret(e)
                }
            }
        }
        _ => {
            UNKNOWN_NR.fetch_add(1, Ordering::Relaxed);
            E_INVALID
        }
    };
    exit
}

/// 从 ring3 来的故障：终止这个任务，内核继续跑。三件事，顺序有意义：
/// ①`kill_current` 标结束**并登记待回收**——只标 Done 是静默的漏（BACKLOG ⑫）；
/// ②立重调度牌，让同一次异常出口就把 CPU 换给别人——少了它"杀掉"只是一条注释；
/// ③把出口 `iretq` 要回去的 rip 换成内核的落脚页——不改 rip 回内核，是替用户造一个
/// 新的未验证状态；跳进一条内核拥有的 `jmp .` 什么都做不了，只等下一次抢占换下去。
/// `rsp/cs/ss` 保持故障帧原样：那是这个任务自己的用户栈与选择子。论证与现场见 ADR-028。
pub fn park_current(frame: &mut crate::arch::x86_64::trap::TrapFrame) {
    KILLS.fetch_add(1, Ordering::Relaxed);
    crate::sched::kill_current();
    crate::sched::mark_need(crate::arch::x86_64::cpu::self_slot());
    let tramp = match TRAMP.load(Ordering::Acquire) {
        0 => {
            // 走到这里说明有用户任务在跑却没有落脚页——`init()` / `load()` 两条入口
            // 都先建它，所以这一刻只能是内核自己的不变量破了。按原样返回会把整机拖进
            // 故障风暴（那就是 §9.2 说的"一个用户的错变成整台机器的错"），
            // 所以宁可在这里停机并说清楚缺的是哪一格。
            crate::log_fatal!("user: kill 没有落脚页（trampoline 没建起来）rip={:#x}", frame.rip);
            crate::exit::finish(crate::exit::Code::ExceptionFatal);
            #[allow(unreachable_code)]
            return;
        }
        t => t,
    };
    frame.rip = tramp;
    // **IF 由 CPU 的窗口决定，不是由这张帧自己决定**（ADR-021），而这条出口走的是
    // 异常桩的 `iretq`，**不经过 `if_patch`**——所以这里必须自己按 `CPU_IF` 写对。
    // 写错的下场是实测过的：留给用户态 IF=0，那个被标结束的任务就在 `jmp .` 里关着中断
    // 死转，本 CPU 再也没有 tick，启动上下文永远回不来（整机判成"挂死"，一条读数都拿不到）。
    frame.rflags = if crate::arch::x86_64::apic::interrupts_enabled(crate::arch::x86_64::cpu::self_slot()) {
        0x2 | RFLAGS_IF
    } else {
        0x2
    };
}

// ------------------------------------------------------------ M4-2：按容器加载
//
/// 一次加载的产物：入口、可写段的起点（结果槽就在那一页的开头）、装了多少页与用户栈顶。
pub struct Loaded {
    pub entry: u64,
    /// 第一个可写段的页基址。`.slots` 是它的第一页开头，而魔数会证明这一点
    ///（`KT_ELF_LOAD` 先把魔数读回来再按固定偏移取结果——不靠"我记得链接脚本怎么排的"）。
    pub data_va: u64,
    pub stack_top: u64,
    pub segs: usize,
    pub pages: u64,
    /// 镜像占的跨度：`[image_lo, image_hi)`。判据用它证明"固定段确实待在镜像区里"，
    /// 而不是只相信"装载成功了"（成功也可能是因为脚手架那次没先跑）。
    pub image_lo: u64,
    pub image_hi: u64,
    /// 这些页的**所有权**，交给 `sched::spawn_user` 之后由任务带着；
    /// 任务结束时由 `sched::reap` 释放（解映射 + 归还页框 + 放手 VA 保留，§6.3 R13）。
    pub owned: crate::sched::OwnedSet,
}

/// 用户指针的校验结果。**每一条都是一次明确的拒绝**，不是一个"大概不行"。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PtrError {
    /// 地址不在低半区（内核地址空间）——传这种东西进来就是想让内核替它读自己的内存
    NotUserRange,
    /// 整条页表链走完某一级的 P 位是 0（`effective_flags` 给 None）
    NotMapped,
    /// 生效位里没有 U/S=1：这一页是内核页，用户态读不到，内核也不该替它读
    NotSharedWithUser,
    /// 往**不可写**的用户页里写。`copy_to_user` 专用：读只需要"在 + 对用户开放"，
    /// 写还要那一页真的可写——否则就是内核替用户绕过 W^X（§6.4）。
    NotWritable,
    /// 一次拷贝超过 `COPY_MAX`。这是**容量**边界，不是"跨页"边界（跨页从 M4-3 第二段起是支持的）
    TooLong,
}

impl PtrError {
    pub fn describe(e: PtrError) -> &'static str {
        match e {
            PtrError::NotUserRange => "地址不在用户半区",
            PtrError::NotMapped => "页表链没走完（没映射）",
            PtrError::NotSharedWithUser => "这一页没对用户开放（U/S=0）",
            PtrError::NotWritable => "往不可写的用户页里写",
            PtrError::TooLong => "一次拷贝超过 COPY_MAX",
        }
    }
}

/// 校验失败 → ABI 返回值。**两个缓冲区调用共用这一个函数**：
/// "回哪个号"是一条规则，而这条规则今天已经因为"写在两处、只改了一处"错过一次
///（BACKLOG 的 ⑧：P5 的分流我只加在出口记账，漏了换出路径，总数只差 1 看不出来）。
pub fn ptr_err_to_ret(e: PtrError) -> u64 {
    match e {
        // 长度超限与地址坏掉分开回：调用方对这两种的处置方向不一样（见 `AbiError::TooLong`）
        PtrError::TooLong => E_TOO_LONG,
        _ => E_FAULT,
    }
}

/// 一次拷贝的上限（也是内核侧那块定长暂存的大小）。
///
/// 为什么是定长而不是"调用方给多少就开多少"：本内核的分配器上限是 `heap::LARGE_MAX = 2048`，
/// 而系统调用的 `len` 是**用户给的数**。"按外部输入的大小开缓冲"这条写法 M4-2 已经踩过一次
/// （`HELLO_ELF.to_vec()` → 串口只剩一行 `kernel panic at .../alloc.rs`，判定 39）。
/// 所以这里要么明确拒绝（`TooLong`），要么用这块静态暂存——两条都不给用户开"用一个数打死内核"的门。
pub const COPY_MAX: usize = 4096;

/// 内核侧的定长暂存。**只在 `with_vmm_lock` 里面碰**，所以跨 CPU 的串行化由那把锁给出；
/// 不用 `Vec` 的理由同 `COPY_MAX`。
struct Scratch(core::cell::UnsafeCell<[u8; COPY_MAX]>);
// SAFETY: 唯一的读写路径是 `copy_into_scratch`，它整段在 VMM 锁里跑（见该函数）
unsafe impl Sync for Scratch {}
static SCRATCH: Scratch = Scratch(core::cell::UnsafeCell::new([0u8; COPY_MAX]));

/// 逐页校验 `[va, va+len)` 能不能被内核访问。三点不显然：
/// 判据用 `mm::effective_flags`（整条链相与之后的生效位）而不是 `is_mapped`（ADR-026 的教训）；
/// 读不检查 X/W，写额外要求可写；跨页要**每一页各自校验**而不是只看第一页。
/// 全部页的校验与后面的拷贝必须在同一次持锁期内完成，否则第二页的结论在拷贝之前就过期。见 §10.3.1。
fn validate_range(va: u64, len: u64, need_write: bool) -> Result<(), PtrError> {
    let end = va.checked_add(len).ok_or(PtrError::NotUserRange)?;
    if va >= elf::USER_VA_TOP || end > elf::USER_VA_TOP {
        return Err(PtrError::NotUserRange);
    }
    let pg = mm::PAGE as u64;
    let mut page = va / pg * pg;
    while page < end {
        let eff = mm::effective_flags(page).ok_or(PtrError::NotMapped)?;
        if !eff.user {
            return Err(PtrError::NotSharedWithUser);
        }
        if need_write && !eff.writable {
            return Err(PtrError::NotWritable);
        }
        page += pg;
    }
    Ok(())
}

/// 用户 → 内核：一次持锁、一段窗口、逐页搬。`Ok(n)` 的 `n` 是**实际搬成的字节数**——
/// `n < len` 只有一种成因：窗口里故障并被恢复路径接住（`trap::COPY_RECOVERED` 数着这件事）。
/// 部分长度不折成 `Err`："半页进了内核"与"一页都没进"是两种结果，藏进错误码就是把区别丢掉。
/// **校验与拷贝在同一次持锁期内**是这一层真正修的东西：上一版是锁外校验、锁内读，
/// 而注释承诺的恰好相反（BACKLOG ⑮"注释在承诺代码没做的事"）。
/// `VMM` 锁是关中断的 guard，所以"窗口里 IF=0"是持锁的推论而不是自觉。详见 §10.3.1。
pub fn copy_from_user(va: u64, dst: &mut [u8]) -> Result<usize, PtrError> {
    if dst.len() > COPY_MAX {
        return Err(PtrError::TooLong);
    }
    // 校验在锁*里面*：见函数头那句"校验与拷贝必须在同一次持锁期内"
    mm::with_vmm_lock(|| {
        validate_range(va, dst.len() as u64, false)?;
        let mut done = 0usize;
        while done < dst.len() {
            let at = va + done as u64;
            // 这一页里还剩多少字节 —— `rep movsb` 一次只跨一页，故障与部分长度才好归因
            let room = (mm::PAGE as u64 - at % mm::PAGE as u64) as usize;
            let want = room.min(dst.len() - done);
            let got = unsafe { ucopy_from(dst.as_mut_ptr().add(done), at as *const u8, want) };
            done += got;
            if got < want {
                break;
            }
        }
        Ok(done)
    })
}

/// 内核 → 用户。方向反过来，多要求一条：目标页必须**可写**。
/// SAFETY 与持锁纪律同 `copy_from_user`。
pub fn copy_to_user(src: &[u8], va: u64) -> Result<usize, PtrError> {
    if src.len() > COPY_MAX {
        return Err(PtrError::TooLong);
    }
    mm::with_vmm_lock(|| {
        validate_range(va, src.len() as u64, true)?;
        let mut done = 0usize;
        while done < src.len() {
            let at = va + done as u64;
            let room = (mm::PAGE as u64 - at % mm::PAGE as u64) as usize;
            let want = room.min(src.len() - done);
            let got = unsafe { ucopy_to(at as *mut u8, src.as_ptr().add(done), want) };
            done += got;
            if got < want {
                break;
            }
        }
        Ok(done)
    })
}

/// `SYS_POKE_BUF` 写进用户缓冲区的模式：`j` 是**这次拷贝内的字节序号**，不是绝对地址。
/// 两边（内核与用户程序）各自独立实现同一个函数，跨页拷贝是否逐字节准确就由它证明。
pub fn poke_pattern(j: usize) -> u8 {
    0xA5 ^ (j as u8)
}

/// 内核 → 用户的一段模式写。与 `copy_into_scratch` 同一套持锁纪律：
/// 暂存的 `&mut` 在锁*里面*造，校验与写在同一次持锁期内。
pub fn poke_pattern_into(va: u64, len: usize) -> Result<usize, PtrError> {
    if len > COPY_MAX {
        // **明确拒绝，不悄悄截短**：用户要求 8 KiB 而内核只写 4 KiB，程序核对字节时会看见
        // "后半段没写"，那读起来像拷贝坏了，而真相是这次调用被截了。长度是用户给的数，
        // 所以它的上限必须是**拒绝**而不是"取小"（§10.3）。
        return Err(PtrError::TooLong);
    }
    mm::with_vmm_lock(|| {
        validate_range(va, len as u64, true)?;
        let buf = unsafe { &mut *SCRATCH.0.get() };
        for (j, b) in buf[..len].iter_mut().enumerate() {
            *b = poke_pattern(j);
        }
        let mut done = 0usize;
        while done < len {
            let at = va + done as u64;
            let room = (mm::PAGE as u64 - at % mm::PAGE as u64) as usize;
            let want = room.min(len - done);
            let got = unsafe { ucopy_to(at as *mut u8, buf.as_ptr().add(done), want) };
            done += got;
            if got < want {
                break;
            }
        }
        Ok(done)
    })
}

/// 用例的第二台仪器：同一个 FNV-1a，跑在**期望的**模式上。
/// 内核那边算的是"我实际看到了什么"，这里算的是"我应该看到什么"；
/// 两个数相等才叫跨页读逐字节准确——只看返回的字节数 `n` 是看不出内容的。
pub fn fnv1a_over_pattern(len: usize, f: impl Fn(usize) -> u8) -> u64 {
    let mut sum: u64 = 0xcbf2_9ce4_8422_2325;
    for j in 0..len {
        sum ^= f(j) as u64;
        sum = sum.wrapping_mul(0x100_0000_01b3);
    }
    sum
}

/// 把用户内存读进内核的静态暂存，并返回它的 FNV-1a 校验和。
/// 两个用途：系统调用 `SYS_PEEK_BUF` 递给用户一个"内核确实看到了什么"的数，
/// 以及用例自己拿同一份期望值算一遍作**第二台仪器**（拷贝是不是逐字节准确，
/// 只看返回值是看不出来的）。
///
/// SAFETY: 那块静态只在**这一次持锁期内**被取用（`&mut` 是在锁*里面*造的，
/// 不是造好再进锁）——否则另一个 CPU 可能在指针活着的时候写完同一块内存，
/// 那才是真正的别名问题。
pub fn copy_into_scratch(va: u64, len: usize) -> Result<(usize, u64), PtrError> {
    if len > COPY_MAX {
        return Err(PtrError::TooLong);
    }
    mm::with_vmm_lock(|| {
        validate_range(va, len as u64, false)?;
        let buf = unsafe { &mut *SCRATCH.0.get() };
        let mut done = 0usize;
        while done < len {
            let at = va + done as u64;
            let room = (mm::PAGE as u64 - at % mm::PAGE as u64) as usize;
            let want = room.min(len - done);
            let got = unsafe { ucopy_from(buf.as_mut_ptr().add(done), at as *const u8, want) };
            done += got;
            if got < want {
                break;
            }
        }
        let mut sum: u64 = 0xcbf2_9ce4_8422_2325;
        for b in buf[..done].iter() {
            sum ^= *b as u64;
            sum = sum.wrapping_mul(0x100_0000_01b3);
        }
        Ok((done, sum))
    })
}

/// **只走恢复路径**的探针：跳过校验，直接从 `va` 读 `len` 字节进暂存，返回搬成的字节数。
/// 恢复机器必须能被证明存在过，否则它就是一条没有证据的分支；而真路径在校验阶段就拒绝了，轮不到它。
/// 与 `trap::probe_page_fault` 同地位、同约束：**只有用例调它**。见 §10.3.1 与 BACKLOG ⑰。
pub fn probe_copy_from(va: u64, len: usize) -> usize {
    let len = len.min(COPY_MAX);
    mm::with_vmm_lock(|| {
        let buf = unsafe { &mut *SCRATCH.0.get() };
        unsafe { ucopy_from(buf.as_mut_ptr(), va as *const u8, len) }
    })
}

/// 从用户内存读一个 `u64`：**校验 → 持 VMM 锁 → 开 SMAP 窗口 → 读 → 立刻关窗口**。
///
/// 它就是 `copy_from_user` 的 8 字节特例（同一份窗口代码，见 `ucopy_from` 那条注释：
/// AC 位的开关动作必须和 `read_slot`/拷贝用的是**同一份**）。
///
/// SAFETY: 见 `copy_from_user`。
pub fn peek_u64(va: u64) -> Result<u64, PtrError> {
    let mut b = [0u8; 8];
    if copy_from_user(va, &mut b)? != 8 {
        // 校验都过了还搬不满，只剩"中途故障被接住了"这一种解释。对 8 字节的读取来说
        // 没有"部分有用"这回事，所以直接报没映射，而不是发明第三种错误码。
        return Err(PtrError::NotMapped);
    }
    Ok(u64::from_le_bytes(b))
}

/// 本 CPU 现在的 AC 位（SMAP 窗口是否开着）。**这是一台独立仪器**：
/// 判据不能只信"代码里 clac() 写在最后一行"——那行可能被提前 return 跳过、
/// 也可能被优化顺序挪走。读回真实的 rflags 才算"窗口关上了"这件事被验证过。
pub fn ac_active() -> bool {
    let f: u64;
    // SAFETY: pushfq 压一个标志值再取出，不碰内存语义、不动栈之外的事
    unsafe { core::arch::asm!("pushfq", "pop {}", out(reg) f, options(nomem, preserves_flags)) };
    f & (1 << 18) != 0
}

#[derive(Clone, Copy, Debug)]
pub enum LoadError {
    /// 容器本身没过解析（每条理由由 `elf::describe` 给出）
    Elf(elf::ElfError),
    /// 页框/映射这一层拒绝（`OutOfMemory`、`AlreadyMapped`……）
    Mm(mm::MmError),
    /// 段不在加载器的窗口里。窗口比 `elf::parse` 允许的"低半区"**更窄**，
    /// 这是刻意的：窗口之外、低半区之内的地址会落在**为内核建的页表链**上，
    /// 装用户页就得去放宽共享的上级表项（ADR-026 把这条列为要避免的做法）。
    SegmentOutsideWindow { va: u64, end: u64 },
    /// 固定段落在**动态分配区**里（`>= mm::USER_MMAP_BASE`）。
    ///
    /// 这条与 `VaTaken` 的区别是要点：`VaTaken` 是"这一刻有人占着"（跟顺序有关），
    /// 这一条是"这段地址根本不该由固定镜像来要"（跟顺序无关，分区规则直接拒）。
    /// M4-3 的第一版没有这条，于是同一份容器能不能装上取决于 `.ktests` 段里
    /// 谁先跑——那种"绿与红由链接顺序决定"的判据不能留。
    ImageInDynamicRegion { va: u64, end: u64 },
    /// 段不是从页边界开始。支持它要做"半个页属于这个段、另半个属于那个段"的处理，
    /// 而本版本没有那种处理；明确拒绝而不是悄悄把整页都给出去（那多给了权限）。
    SegmentNotPageAligned { va: u64 },
    /// 目标 VA 已经被登记或被映射：两个容器不能抢同一段地址
    VaTaken { va: u64 },
    /// `elf::parse` 已经保证 `offset + filesz <= 文件长度`，所以取不到这段切片
    /// **只可能是解析器与加载器对同一份字节的判断不一致**。那种不一致必须报出来，
    /// 不能当成"不可能发生"而省掉（§9.2 的一致态度）。
    FileSliceGone { at: u64, len: usize },
}

/// 装页之前的**地址分区**检查（`mm::USER_MMAP_BASE`）。
/// 按**整份镜像的跨度**判而不是逐段判：这条规则是"固定段与动态分配不许抢同一段地址"。
/// 落在动态区 ⇒ `ImageInDynamicRegion`（与运行顺序无关）；窗口外 ⇒ `SegmentOutsideWindow`
/// （那些地址坐在为内核建的页表链上，放宽它就是 ADR-026 要避免的事）。两种失败理由不同，所以分开拒。
/// 病因、现场与负样本：ADR-028、§10.7、BACKLOG ⑪。
fn check_image_span(p: &elf::Program) -> Result<(u64, u64, u64), LoadError> {
    let mut lo = u64::MAX;
    let mut hi = 0u64;
    let mut pages = 0u64;
    for seg in p.segments() {
        if seg.vaddr < mm::USER_VA_BASE || seg.va_end() > mm::USER_VA_TOP {
            return Err(LoadError::SegmentOutsideWindow { va: seg.vaddr, end: seg.va_end() });
        }
        if seg.vaddr >= mm::USER_MMAP_BASE || seg.va_end() > mm::USER_MMAP_BASE {
            return Err(LoadError::ImageInDynamicRegion { va: seg.vaddr, end: seg.va_end() });
        }
        lo = lo.min(seg.vaddr);
        hi = hi.max(seg.va_end());
        pages += (seg.memsz + (mm::PAGE as u64 - 1)) / mm::PAGE as u64;
    }
    if lo == u64::MAX {
        // 一条 PT_LOAD 都没有是解析器的职责（`NoLoadSegment`）；这里不往下算，避免把
        // `lo = u64::MAX` 当成"镜像跨度"报出去。
        return Err(LoadError::Elf(elf::ElfError::NoLoadSegment));
    }
    Ok((lo, hi, pages))
}

/// 按 ELF 容器把程序装进窗口，并配一条用户栈（含 guard）。三条规则决定这段代码的形状：
/// ①逐页流式，**不开段大小的缓冲**（`heap::LARGE_MAX = 2048`，超了当场 39）；
/// ②每页先整页清零再拷文件字节（bss 尾巴必须为 0，新页框也不能把上一个主人的内容交给 ring3）；
/// ③填内容一律经 HHDM，装完叶子不再写（ADR-026 决策一）。
/// 三条的实测现场与各自判据：§10.7 的规则表。
pub fn load(bytes: &[u8]) -> Result<Loaded, LoadError> {
    // 装容器之前先有落脚页：被杀的容器任务往哪儿跳，不能取决于"某条用例是否先跑过"。
    if ensure_trampoline().is_none() {
        return Err(LoadError::Mm(mm::MmError::OutOfMemory));
    }
    let p = elf::parse(bytes).map_err(LoadError::Elf)?;
    let (image_lo, image_hi, image_pages) = check_image_span(&p)?;
    let mut data_va = 0u64;
    // 装出来的每一段都由**要运行它的任务**持有（`spawn_user` 再加一条内核栈）。
    // 之前这里 `forget`，于是 exec/exit 循环会把 `MAX_VA_RESERVATIONS` 吃光，
    // 现场是一句 `L4: VA 保留登记表已满` —— 进程生命周期的问题被报成内核故障。
    let mut owned = crate::sched::OwnedSet::new();

    for seg in p.segments() {
        if seg.vaddr % mm::PAGE as u64 != 0 {
            return Err(LoadError::SegmentNotPageAligned { va: seg.vaddr });
        }
        // 地址分区（窗口 + 镜像区/动态区）已经在 `check_image_span` 里按**整份跨度**判过了，
        // 这里不再逐段重复：重复的两条规则一旦有一边改了，就会出现"跨度合格、单页不合格"
        // 这种只在某条顺序下才成立的形状（M4-3 那次 `VaTaken` 就是"两条规则各管一段地址、
        // 却共用一条前沿"的账，不该再用第二处 `if` 糊起来）。
        let pages = (seg.memsz + (mm::PAGE as u64 - 1)) / mm::PAGE as u64;
        if pages == 0 {
            // 零长度段（`memsz == 0`）不需要映射，也不该登记一段空保留
            continue;
        }
        if !mm::reserve_va_at(seg.vaddr, pages as usize) {
            return Err(LoadError::VaTaken { va: seg.vaddr });
        }
        // 权限按容器给**最小的一组**：可执行 → RX，可写 → RW，其余 → 只读。
        // `elf::parse` 已经排除了 W+X，所以这三个分支互斥。
        let flags = if seg.executable {
            PageFlags::USER_RX
        } else if seg.writable {
            PageFlags::USER_RW
        } else {
            PageFlags::USER_R
        };
        // **一段一次连续分配**（M4 容量欠账的第一条）：页框按"剩余页数里最大的 2 的幂"
        // 贪心切成若干块，一块一条 `Mapping`。为什么是贪心而不是"整段向上取整到 2 的幂"：
        // 向上取整会**多占 VA**——那几页不属于这条段，却已经被这条段的分配吃掉，
        // 下一条段的 `reserve_va_at` 就会撞 `VaTaken`，又变回"顺序决定谁赢"那个形状
        //（ADR-028 的同一条病因换了地方复发）。贪心不多占一页，代价是长段会切成
        // popcount 量级的几块（5 页 = 4+1 两块），仍然远好于"一页一块"。
        // 效果实测：夹具原来 5 页 ⇒ 5 条映射，现在 ⇒ 4 条（`kt` 那行 `released` 是证人）。
        let mut k = 0u64;
        while k < pages {
            let order = (pages - k).ilog2() as u8;
            let block = 1u64 << order;
            let frame = mm::phys_alloc(order, MOD_USER).map_err(LoadError::Mm)?;
            let block_base = frame.base().via_hhdm().0;
            for j in 0..block {
                let page_in_seg = k + j;
                let fill = block_base + j * mm::PAGE as u64;
                let copy = seg
                    .filesz
                    .saturating_sub(page_in_seg * mm::PAGE as u64)
                    .min(mm::PAGE as u64) as usize;
                // SAFETY: `fill` 是刚拿到手的连续页框块里第 j 页在 HHDM 下的别名，恰好一页；
                // 这块帧除了我们没有任何主人（phys_alloc 刚发出来，还没装叶子）
                unsafe { core::ptr::write_bytes(fill as *mut u8, 0, mm::PAGE) };
                if copy > 0 {
                    let at = seg.offset + page_in_seg * mm::PAGE as u64;
                    let src = bytes
                        .get(at as usize..at as usize + copy)
                        .ok_or(LoadError::FileSliceGone { at, len: copy })?;
                    // SAFETY: `src` 是文件缓冲里 `copy` 个字节（上面刚 checked），
                    // 目标是刚清零的那一页内部，`copy <= PAGE`
                    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), fill as *mut u8, copy) };
                }
            }
            let m = mm::map(VirtAddr(seg.vaddr + k * mm::PAGE as u64), frame, flags).map_err(LoadError::Mm)?;
            owned.push(m).map_err(LoadError::Mm)?;
            k += block;
        }
        if seg.writable && data_va == 0 {
            data_va = seg.vaddr;
        }
    }

    // 用户栈：**动态区**里取 2 页，低那一页永不映射当 guard（与 `init()` 同一条形状）。
    // 它和镜像分属两段，所以"动态分配把镜像的位置吃掉"这类事在结构上不会发生
    // （见 `mm::USER_MMAP_BASE`——这一刀就是 M4-3 那次 `VaTaken` 换来的）。
    let swin = mm::alloc_user_va_range(2).ok_or(mm::MmError::OutOfMemory).map_err(LoadError::Mm)?;
    if mm::is_mapped(swin.0) {
        return Err(LoadError::VaTaken { va: swin.0 });
    }
    let stack_va = swin.0 + mm::PAGE as u64;
    let sf = mm::phys_alloc(0, MOD_USER).map_err(LoadError::Mm)?;
    // SAFETY: 同 `init()` 里那条——HHDM 别名、恰好一页、还没有别的主人
    unsafe { core::ptr::write_volatile(sf.base().via_hhdm().0 as *mut u64, 0) };
    let m = mm::map(VirtAddr(stack_va), sf, PageFlags::USER_RW).map_err(LoadError::Mm)?;
    owned.push(m).map_err(LoadError::Mm)?;

    Ok(Loaded {
        entry: p.entry,
        data_va,
        stack_top: stack_va + mm::PAGE as u64 - 16,
        segs: p.n,
        pages: image_pages,
        image_lo,
        image_hi,
        owned,
    })
}

/// 内核开 SMAP 窗口读用户页里的**任意**一个 VA（`read_slot` 的通用版，
/// 容器加载出来的程序槽位地址不固定，所以按 VA 而不是按段内偏移）。
///
/// 走 `peek_u64` ⇒ 每一次这样的读都带"逐页校验 + 一次持锁 + 可恢复窗口"。
/// 读不出来就是 `None`，并把理由留下：调用方是用例，`None` 与"读到了 0"必须能分开，
/// 而只有日志能把"为什么没读到"说清楚。
pub fn read_at(va: u64) -> Option<u64> {
    match peek_u64(va) {
        Ok(v) => Some(v),
        Err(e) => {
            crate::log_info!("abi: 读用户页被拒 va={va:#x} —— {}", PtrError::describe(e));
            None
        }
    }
}

/// 容器加载那条路径的判据要能自己说明失败原因，这里给一份人话（同 `elf::describe`）。
pub fn describe_load(e: LoadError) -> &'static str {
    match e {
        LoadError::Elf(x) => elf::describe(x),
        LoadError::Mm(mm::MmError::OutOfMemory) => "页框或页表页不够（PMM 拒绝）",
        LoadError::Mm(mm::MmError::AlreadyMapped) => "目标页已经有映射",
        LoadError::Mm(mm::MmError::HugeConflict) => "目标 VA 落在 2 MiB 大页里",
        LoadError::Mm(_) => "内存层拒绝（其它错误码）",
        LoadError::SegmentOutsideWindow { .. } => "段不在加载器的用户窗口里",
        LoadError::ImageInDynamicRegion { .. } => "固定段落在了动态分配区里（分区规则拒绝）",
        LoadError::SegmentNotPageAligned { .. } => "段不是从页边界开始",
        LoadError::VaTaken { .. } => "目标 VA 已被登记或已映射",
        LoadError::FileSliceGone { .. } => "解析器与加载器对文件长度的判断不一致",
    }
}

/// 用例用：把计数器清零，好让"这一轮新增了多少"成为可判定的读数。
pub fn clear_counters() {
    reset_counters();
}

core::arch::global_asm!(
    r#"
    .text
    .code64
    // STAC/CLAC 各是一条指令，但必须成对出现在同一个 asm 块外面由 Rust 顺序保证；
    // 这里分开两个符号而不是写成一个"包一层闭包"的宏，是因为 IF 在窗口里必须是关的
    // （开着一个"能访问用户页"的窗口被打断，中断处理就白拿了这个权限）。
    .global stac
stac:
    pushfq
    pop rax
    or rax, 0x40000        // RFLAGS.AC（bit18）
    push rax
    popfq
    ret

    .global clac
clac:
    pushfq
    pop rax
    and rax, ~0x40000
    push rax
    popfq
    ret

// §10.3 的拷贝路径：一次一页，整段在 SMAP 窗口里，并把"这一段地址内的页故障可恢复"
// 登记进 trap 的区间表（PF_LO/PF_HI/PF_RESUME，见 trap.rs）。
// 用 `rep movsb`：它故障时不写那一个元素、`rcx` 还计着它，所以 `copied = len - rcx` 是精确的部分长度。
// `call stac`/`call clac` 复用上面两个符号——AC 的开关动作必须与别的窗口同一份代码；
// 它们会毁掉 rax，所以下面登记用的临时值都在 `call stac` 之后才算。
// `.Lucopy_from_fail` 复活时 rdi/rsi/rcx/rdx 保持故障那一刻的值，但必须自己关窗口并清登记。
    .global ucopy_from
ucopy_from:                      // rdi = 内核侧目标, rsi = 用户侧源, rdx = 长度 → rax = 实际搬成
    push rbp
    mov  rbp, rsp
    cld
    call stac
    mov  [rip + PF_LO], rsi      // 读的是用户侧：故障地址落在 [src, src+len)
    mov  rax, rsi
    add  rax, rdx
    mov  [rip + PF_HI], rax
    lea  rax, [rip + .Lucopy_from_fail]
    mov  [rip + PF_RESUME], rax
    mov  rcx, rdx
    rep  movsb
    call clac
    jmp  .Lucopy_from_out
.Lucopy_from_fail:
    call clac
.Lucopy_from_out:
    mov  rax, rdx
    sub  rax, rcx
    mov  qword ptr [rip + PF_RESUME], 0
    mov  qword ptr [rip + PF_LO], 0
    mov  qword ptr [rip + PF_HI], 0
    pop  rbp
    ret

    // 反方向。唯一的实质区别是**故障落在写的那一侧**，所以登记的是 `[dst, dst+len)`。
    .global ucopy_to
ucopy_to:                        // rdi = 用户侧目标, rsi = 内核侧源, rdx = 长度 → rax = 实际搬成
    push rbp
    mov  rbp, rsp
    cld
    call stac
    mov  [rip + PF_LO], rdi
    mov  rax, rdi
    add  rax, rdx
    mov  [rip + PF_HI], rax
    lea  rax, [rip + .Lucopy_to_fail]
    mov  [rip + PF_RESUME], rax
    mov  rcx, rdx
    rep  movsb
    call clac
    jmp  .Lucopy_to_out
.Lucopy_to_fail:
    call clac
.Lucopy_to_out:
    mov  rax, rdx
    sub  rax, rcx
    mov  qword ptr [rip + PF_RESUME], 0
    mov  qword ptr [rip + PF_LO], 0
    mov  qword ptr [rip + PF_HI], 0
    pop  rbp
    ret
"#
);

extern "C" {
    // `stac` / `clac` 不在这里声明：Rust 侧已经没有"自己开窗口"的入口了
    //（`read_slot`/`read_at`/`write_at` 全部改走带校验的拷贝路径）。它们只被下面
    // `ucopy_from` / `ucopy_to` 用 `call` 复用，所以留在 asm 里，不进 Rust 的符号表——
    // 少一个声明就少一个"看起来可以随手开窗"的入口。
    fn ucopy_from(dst: *mut u8, src: *const u8, len: usize) -> usize;
    fn ucopy_to(dst: *mut u8, src: *const u8, len: usize) -> usize;
}
