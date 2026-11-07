//! 第一个用户程序（手册 §10.7 的容器与加载那条链上的产物）。
//!
//! 它做的事与 M4-1 那段手写机器码 blob 一样，差别在**容器**：
//! blob 是内核里手写的 66 字节，这个是 `rustc` 为 `x86_64-unknown-none` 真产出的 ELF64，
//! 于是解析器面对的是"带 `.eh_frame`/`.note`/多段/有 bss 尾巴"的真实形状，
//! 而不是我为了方便编出来的形状。
//!
//! 三条与内核侧文档绑定的约定：
//!
//! 1. **入口走 `int 0x80`**（ADR-025）。所以这里**不**声明 `rcx`/`r11` 被破坏：
//!    那是 SYSCALL 的硬件行为，`int N` 不动它们。把这两个当 clobber 写上去不会算错，
//!    但会把"两条入口的 ABI 差别"这条已经写进 §10.2 的事实藏起来。
//! 2. **槽位的地址由哨兵证明**，不由"我记得链接脚本怎么排的"证明：`.slots` 的第一个
//!    8 字节是魔数，内核用例先读回它，再按固定偏移取三个结果（`elf.rs` 的模块头第 1 条
//!    同一条纪律：不可信/不可想的地方要 checked，不要靠记忆）。
//! 3. 调用号、参数与返回值的形状照 §10.2：号在 `rax`，参数 `rdi/rsi`，返回 `rax`，
//!    负数是 `-ErrorCode`。第三个调用故意用一个没人认领的号，看内核回不回 `-1`
//!    而不是把系统调用打挂。

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};

/// `.slots` 段的第一个 8 字节：内核用例靠它确认槽基址。
pub const SLOTS_MAGIC: u64 = 0xa5a5_5a5a_1234_5678;
/// `ping` 槽相对 `.slots` 起点的偏移。三个偏移与下面 `Slots` 的字段顺序一一对应；
/// 内核侧的 `KT_ELF` 用例先读魔数、再按这三个偏移取值，所以这份对应关系是**量出来的**。
pub const OFF_PING: u64 = 8;
/// `add` 槽的偏移。
pub const OFF_ADD: u64 = 16;
/// `unknown`（没人认领的调用号）槽的偏移。
pub const OFF_UNKNOWN: u64 = 24;
/// 第四个槽：程序把 `.rodata` 段的第一字节读回来写在这里。
/// 它证明的是"内核装的那条 `r--` 段在 ring3 真能读"——加载器给这条段选的是
/// `PageFlags::USER_R`（不可执行、不可写、用户可读），三个分支里唯一
/// 没有别的证据看着的一个。**没有它，那个分支就是写好了却没人走过的代码。**
pub const OFF_RODATA: u64 = 32;
/// 第六个槽（偏移 48）：**输入**，不是输出。内核在装载完之后写一个非 0 进来，
/// 程序就跑完最后一条 `SYS_EXIT` 自己结束；写 0 就一直跑到收尾自跳转。
/// 为什么用"内核写、程序读"而不是编两个程序：容器是同一份字节，
/// 生命周期这一条判据要能在**同一个镜像**上同时测"退"与"不退"两种收场。
pub const OFF_FLAG: u64 = 48;
/// `flag` 的位。**每一位开一个实验**，同一个镜像就能测完"退 / 被杀 / 校验"三种收场
/// （编两个程序只会让"两条路径共用同一套装载代码"这件事变成假设）。
pub const FLAG_EXIT: u64 = 1;
/// 往自己栈下面那一页（guard）写一次 —— ring3 的 #PF，内核侧应当只杀这个任务。
pub const FLAG_GUARD_STORE: u64 = 2;
/// 三次 `SYS_PEEK`：合法用户指针 / 内核地址 / 未映射地址。
pub const FLAG_PEEK: u64 = 4;
/// 三个 `SYS_PEEK` 的结果槽。
pub const OFF_PEEK_OK: u64 = 56;
pub const OFF_PEEK_KERNEL: u64 = 64;
pub const OFF_PEEK_UNMAPPED: u64 = 72;
/// 第五个槽：额外把 `SYS_PING` 连打 `PINGS_EXTRA + 1` 次的**计数**。
/// 它是 P7 归因实验的证据：没有它，"循环真的跑了"只能靠调用次数间接推。
pub const OFF_LOOPS: u64 = 40;
/// 内核在装载之后写进来的**本页页基址**。跨页缓冲区的地址由它加出来。
/// 为什么不直接 `addr_of!(某个静态量)`：`relocation-model=static` 下取静态量地址会退化成
/// 32 位绝对重定位，而镜像基址在 4 GiB 之上 —— `R_X86_64_32S out of range` 在链接期就炸
/// （M4-2 踩过）。内核把地址递进来也更贴近真实 ABI：参数由调用方给，不由被调用方猜。
pub const OFF_SELF_VA: u64 = 80;
/// `SYS_POKE_BUF` 的核对结果：`1` = 每个字节都对且字节数等于请求长度；
/// 其它值是 `0x1000 + 第一个不匹配的字节序号`（加 0x1000 是为了让它永远不等于 1，
/// 否则"第 0 个字节不匹配"与"全对"会撞成同一个数）。
pub const OFF_BUF_OK: u64 = 88;
/// `SYS_PEEK_BUF` 的返回值：内核算出的 FNV-1a 校验和，程序原样存回来。
pub const OFF_BUF_SUM: u64 = 96;
/// `SYS_POKE_BUF` 那一次内核报回的字节数。
pub const OFF_BUF_N: u64 = 104;
/// 故意要一个超限长度时内核回的错误码（应该是 `-3` = `-ETOOLONG`）。
pub const OFF_BUF_ERR: u64 = 112;
/// 一次拷贝的上限。这一份与内核侧 `user::COPY_MAX` 是**两次独立声明**（同槽位偏移那条纪律）：
/// 两边不一致的话，本程序这第三次调用就不会超限，读回来的码不是 `-3`，判据当场红——
/// 也就是说这个数被改坏是有证人的，不会安静地漂。
pub const COPY_MAX: u64 = 4096;
/// 跨页缓冲区实验的开关。
pub const FLAG_BUF: u64 = 8;
/// 快路径实验：先读 `sys_abi_info()`，看到 bit0 才敢打 `syscall`。
pub const FLAG_FASTPATH: u64 = 16;
/// `sys_abi_info()` 返回值的低位特性位（与内核侧 `user::F_*` 各自独立声明的同一套）。
pub const F_FASTPATH: u64 = 1;
pub const F_SMAP: u64 = 2;
pub const F_SMEP: u64 = 4;
/// 三个新格子：ABI 字、快路径回来后**自己读回的 CS/SS**、以及第一次快调用回的值。
pub const OFF_ABI_WORD: u64 = 120;
pub const OFF_FAST_CS: u64 = 128;
pub const OFF_FAST_SS: u64 = 136;
pub const OFF_FAST_PING: u64 = 144;
/// 快路径一共打几次（warm 样本要够 P7 那套格子取 min）。
pub const FAST_CALLS: u64 = 8;
/// 缓冲区在这个镜像可写段里的起点与长度：`0xF00..0x1100` ⇒ **跨过 +0x1000 这条页边界**
///（最后一格在第 2 页里）。这个数字是编译期那条 `const assert` 盯着的，不是注释。
/// 不是随便挑的：跨页拷贝最容易坏在"第一页满、第二页没动"，而那只有让区间真的跨过边界才看得见。
pub const BUF_OFF: u64 = 0xF00;
pub const BUF_LEN: u64 = 0x200;
/// 内核 `SYS_POKE_BUF` 写进来的模式（与内核侧 `user::poke_pattern` 各自独立实现的同一个函数）。
const fn poke_pattern(j: u64) -> u8 {
    0xA5 ^ (j as u8)
}
/// 本程序自己写进去、让内核读走的模式（与内核用例里那份"期望值"是同一个函数）。
const fn write_pattern(j: u64) -> u8 {
    0x5A ^ (j as u8)
}
/// 额外打的调用次数（第一次 ping 已经在主序列里）。
pub const PINGS_EXTRA: u64 = 28;
/// `.rodata` 第一字节的期望值：内核用例照着它比对（同一个常量的第二台仪器）。
pub const RODATA_FIRST: u64 = 0xa7;

/// 本任务用户栈所在页的页基址。用 `mov rsp` 现取而不是编一个常数：
/// 栈的位置由内核分配（`alloc_user_va_range`），换了大小/顺序就不能假设。
fn stack_base() -> u64 {
    let rsp: u64;
    // SAFETY: 只读本任务的 rsp（ring3 自己的寄存器），不碰内存
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    rsp & !0xfff
}

/// §10.2 的调用号。1 = ping，2 = add，99 = **故意不存在**的那个。
const SYS_PING: u64 = 1;
const SYS_ADD: u64 = 2;
const SYS_NOBODY: u64 = 99;
/// 自己结束（§10.2）。
const SYS_EXIT: u64 = 3;
/// 读一个用户给的指针（§10.3 的最小版本）
const SYS_PEEK: u64 = 4;
/// 返回 ABI 版本与特性位
const SYS_ABI_INFO: u64 = 7;
const SYS_HANDLE_CLOSE: u64 = 8;
const SYS_FILE_READ: u64 = 10;
/// 让内核把一段缓冲区读走并算校验和（跨页形状）
const SYS_PEEK_BUF: u64 = 5;
/// 让内核把一段模式写进这块缓冲区（跨页形状，方向反过来）
const SYS_POKE_BUF: u64 = 6;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // 用户态没有停机权：这里只能停住自己，等时钟把任务换下去。
    // 内核侧的语义（§9.2）是"用户程序的错不变成整台机器的错"，所以这里**不**能
    // 走 debugexit、也不能碰任何内核对象。
    loop {
        // **不能停在自己的 `hlt` 上**（下面 `_start` 的循环同理）：`hlt` 需要 CPL<=IOPL，
        // 而本内核不改 IOPL（保持 0）也不是全特权任务 —— ring3 的 `hlt` 就是 #GP(0)。
        // 实测的第一版就是这么挂的：`unexpected vector=13 err=0x0 rip=0x100000060`
        // 反复出现，那条 rip 正好是 .text 末尾那个循环。
        // SAFETY: cli 是特权指令吗？——不是：`cli` 只需要 CPL<=IOPL(=0) 才允许，
        // 所以这里也**不能**用 cli。只留一个自跳转。
        unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) };
    }
}

#[repr(C, align(4096))]
struct Slots {
    /// 哨兵，见模块头第 2 条
    magic: AtomicU64,
    ping: AtomicU64,
    add: AtomicU64,
    unknown: AtomicU64,
    rodata_first: AtomicU64,
    loops: AtomicU64,
    /// 内核写进来的实验开关，见 `OFF_FLAG` 与那几个位常量。
    /// 用 `AtomicU64` 而不是裸 `u64` + `read_volatile`：这个值由**另一个所有者**
    /// （内核，经 SMAP 窗口）在我们开始跑之前写好，`load(Relaxed)` 就是这件事的
    /// 合法表达；写成 unsafe 读反而要多一段解释为什么要 unsafe。
    ///
    /// **字段顺序就是 ABI**：内核按下面 `OFF_*` 那组常量读写这些格子，而它看不到这个结构。
    /// 上一版我把三个 peek 格子插在 `flag` 前面，于是内核写的 48 落在了 `peek_ok` 上、
    /// 真的 `flag` 停在 72 没人写 —— 表现是"程序一个实验都没跑"，读起来像退出路径坏了。
    /// 所以偏移不再靠注释维持：见下面的 `const _: () = assert!(offset_of!...)`。
    flag: AtomicU64,
    peek_ok: AtomicU64,
    peek_kernel: AtomicU64,
    peek_unmapped: AtomicU64,
    self_va: AtomicU64,
    buf_ok: AtomicU64,
    buf_sum: AtomicU64,
    buf_n: AtomicU64,
    buf_err: AtomicU64,
    abi_word: AtomicU64,
    fast_cs: AtomicU64,
    fast_ss: AtomicU64,
    fast_ping: AtomicU64,
    handle: AtomicU64,
    h_magic: AtomicU64,
    h_done: AtomicU64,
}

// 初始值全是 0：用例在外面先把它们填成 `0xdeadbeef` 之类的哨兵是不可能的
//（那是 blob 时代的做法，页由内核建），所以这里由程序自己写魔数，
// 而"三个槽是否被写过"的判据仍然是"值是否等于内核该回的那三个数"。
#[used]
#[link_section = ".slots"]
static SLOTS: Slots = Slots {
    magic: AtomicU64::new(0),
    ping: AtomicU64::new(0),
    add: AtomicU64::new(0),
    unknown: AtomicU64::new(0),
    rodata_first: AtomicU64::new(0),
    loops: AtomicU64::new(0),
    peek_ok: AtomicU64::new(0),
    peek_kernel: AtomicU64::new(0),
    peek_unmapped: AtomicU64::new(0),
    flag: AtomicU64::new(0),
    self_va: AtomicU64::new(0),
    buf_ok: AtomicU64::new(0),
    buf_sum: AtomicU64::new(0),
    buf_n: AtomicU64::new(0),
    buf_err: AtomicU64::new(0),
    abi_word: AtomicU64::new(0),
    fast_cs: AtomicU64::new(0),
    fast_ss: AtomicU64::new(0),
    fast_ping: AtomicU64::new(0),
    handle: AtomicU64::new(0),
    h_magic: AtomicU64::new(0),
    h_done: AtomicU64::new(0),
};

// **偏移是编译期核对的，不是注释里的约定**。内核侧按 `OFF_*` 这组数字读写，
// 而它看不见这个结构；字段插错一位的表现是"实验一个都没跑"，读起来像被测代码坏了。
const _: () = assert!(core::mem::offset_of!(Slots, magic) as u64 == 0);
const _: () = assert!(core::mem::offset_of!(Slots, ping) as u64 == OFF_PING);
const _: () = assert!(core::mem::offset_of!(Slots, add) as u64 == OFF_ADD);
const _: () = assert!(core::mem::offset_of!(Slots, unknown) as u64 == OFF_UNKNOWN);
const _: () = assert!(core::mem::offset_of!(Slots, rodata_first) as u64 == OFF_RODATA);
const _: () = assert!(core::mem::offset_of!(Slots, loops) as u64 == OFF_LOOPS);
const _: () = assert!(core::mem::offset_of!(Slots, flag) as u64 == OFF_FLAG);
const _: () = assert!(core::mem::offset_of!(Slots, peek_ok) as u64 == OFF_PEEK_OK);
const _: () = assert!(core::mem::offset_of!(Slots, peek_kernel) as u64 == OFF_PEEK_KERNEL);
const _: () = assert!(core::mem::offset_of!(Slots, peek_unmapped) as u64 == OFF_PEEK_UNMAPPED);
const _: () = assert!(core::mem::offset_of!(Slots, self_va) as u64 == OFF_SELF_VA);
const _: () = assert!(core::mem::offset_of!(Slots, buf_ok) as u64 == OFF_BUF_OK);
const _: () = assert!(core::mem::offset_of!(Slots, buf_sum) as u64 == OFF_BUF_SUM);
const _: () = assert!(core::mem::offset_of!(Slots, buf_n) as u64 == OFF_BUF_N);
const _: () = assert!(core::mem::offset_of!(Slots, buf_err) as u64 == OFF_BUF_ERR);
const _: () = assert!(core::mem::offset_of!(Slots, abi_word) as u64 == OFF_ABI_WORD);
const _: () = assert!(core::mem::offset_of!(Slots, fast_cs) as u64 == OFF_FAST_CS);
const _: () = assert!(core::mem::offset_of!(Slots, fast_ss) as u64 == OFF_FAST_SS);
const _: () = assert!(core::mem::offset_of!(Slots, fast_ping) as u64 == OFF_FAST_PING);
const _: () = assert!(core::mem::offset_of!(Slots, handle) as u64 == OFF_HANDLE);
const _: () = assert!(core::mem::offset_of!(Slots, h_magic) as u64 == OFF_H_MAGIC);
const _: () = assert!(core::mem::offset_of!(Slots, h_done) as u64 == OFF_H_DONE);
// `BUF_OFF + BUF_LEN` 必须**真的跨过一条页边界**，否则整个跨页实验就退化成同页实验，
// 而"第一页满、第二页没动"那种错法正好只有跨页才抓得到。
const _: () = assert!(BUF_OFF / 4096 != (BUF_OFF + BUF_LEN - 1) / 4096);

/// 撑大 `.bss`，让可写段**至少两页**：`BUF_OFF..BUF_OFF+BUF_LEN` 的第二半落在第二页上，
/// 而没映射的第二页会让校验直接拒绝（`NotMapped`），跨页拷贝这条路就走不到。
/// `#[used]` + `.bss`：不占文件字节（NOBITS），但 `p_memsz` 会覆盖到它。
#[used]
#[link_section = ".bss"]
static PAD: [u8; 0x1100] = [0u8; 0x1100];

/// 放在 `.rodata`（内核按 `USER_R` 装：可读、不可写、不可执行）的字节。
/// 必须被真正读一次，否则链接器会把整段丢掉，`r--` 那条分支就不存在了。
#[used]
#[link_section = ".rodata"]
static BANNER: [u8; 8] = [0xa7, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7];

/// `syscall` 指令的快路径（ADR-025 / §10.1）。
///
/// `rcx` 与 `r11` 必须声明成破坏：硬件把返回 rip 写进 rcx、把进入前的 rflags 写进 r11。
/// 这就是 §10.2 那行"破坏寄存器：**仅 SYSCALL 路径**"的出处 —— 它和 `int 0x80` 的
/// ABI 差别是真实存在的，写成 clobber 不是形式主义。
#[inline]
unsafe fn syscall_fast(nr: u64, a1: u64, a2: u64) -> u64 {
    let ret: u64;
    let mut c0: u64;
    let mut c1: u64;
    // SAFETY: 只有内核能处理它；参数走 rax/rdi/rsi，返回走 rax。
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            lateout("rcx") c0,
            lateout("r11") c1,
            options(preserves_flags)
        );
    }
    let _ = (c0, c1);
    ret
}

/// 读自己的 CS/SS：快路径回来后这两个值由硬件从 `IA32_STAR[63:48]` 算出来，
/// 所以"装对了"这件事只能由**用户这一侧**读回来证明（内核里的常数说了不算）。
#[inline]
fn self_cs() -> u64 {
    let v: u16;
    // SAFETY: 只读段寄存器，不访存
    unsafe { core::arch::asm!("mov {}, cs", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v as u64
}

#[inline]
fn self_ss() -> u64 {
    let v: u16;
    // SAFETY: 只读段寄存器，不访存
    unsafe { core::arch::asm!("mov {}, ss", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v as u64
}

/// `int 0x80` 系统调用。
///
/// SAFETY: 只有内核能处理这条指令；它按 §10.2 用 `rax/rdi/rsi` 传参并把返回值放回 `rax`。
/// 没有声明 `nomem`：系统调用的语义**就是**内核可能读写内存，声明成无副作用会让
/// LLVM 把前后的内存访问挪到调用之前——那才是真的不安全。
#[inline]
unsafe fn syscall(nr: u64, a1: u64, a2: u64) -> u64 {
    let ret: u64;
    // SAFETY: 见上。`preserves_flags` 是对的：中断门在内核侧清掉的是**内核**的 IF，
    // iretq 把用户帧里那份 rflags 原样装回来，用户程序看到的标志位不变。
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            options(preserves_flags)
        );
    }
    ret
}

/// P7：capability 句柄实验（ring3 调用 10/8；越权与旧句柄两格由内核用例覆盖）。
pub const FLAG_HANDLE: u64 = 32;
/// 内核授予的文件句柄（指向卷上的 HELLO.ELF）。
pub const OFF_HANDLE: u64 = 152;
/// 读到的前 4 字节（成功时是 ELF 魔数的 LE u32）。
pub const OFF_H_MAGIC: u64 = 160;
/// 收尾哨兵；内核等它非 0 才读上面两格。
pub const OFF_H_DONE: u64 = 168;
const HANDLE_DONE: u64 = 0x4844_4f4e_45; // "HDONE"

/// 三参数版本（`file_read` 要 `rdx`=长度）。与两参数版本同一条 ABI，只多一个寄存器。
#[inline]
unsafe fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    // SAFETY: 同 `syscall`；rdx 只是第三个参数。
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            options(preserves_flags)
        );
    }
    ret
}

/// 入口（`link.ld` 的 `ENTRY(_start)`）。链接脚本给的地址就是 `e_entry`，
/// 落在 `.text` 那一页——`elf.rs` 要求入口所在的段既可读又可执行，这一条由 ktest 复核。
#[no_mangle]
pub extern "C" fn _start() -> ! {
    SLOTS.magic.store(SLOTS_MAGIC, Ordering::Relaxed);
    // 1) ping 回的是"第几次被服务"，所以只要 >0 就证明往返成立
    let n = unsafe { syscall(SYS_PING, 0, 0) };
    SLOTS.ping.store(n, Ordering::Relaxed);
    // **P7 归因的换位实验**（第一次归因给出 lead=[87193, 25898, 23762, 371]：
    // 冷的是前三个样本，而前三次正好是三个不同的调用号）。两种解释在那组数里分不开：
    //   (A) `syscall_dispatch` 的三个分支各自第一次执行时代码是冷的；
    //   (B) 陷入机制整体要三次才热。
    // 判别办法就是让前两次调用**走同一个分支**：如果 (A)，lead 应当是
    // [冷, 热, 冷, 冷]；如果 (B)，lead 仍然是 [冷, 冷, 冷, 热]。
    // 这次实验没有新增任何机制，只是把同一个调用的第二次插在前面。
    let _ = unsafe { syscall(SYS_PING, 1, 0) };
    // 2) 参数确实穿过边界：0x2a + 0x12 = 0x3c
    let sum = unsafe { syscall(SYS_ADD, 0x2a, 0x12) };
    SLOTS.add.store(sum, Ordering::Relaxed);
    // 3) 没人认领的号必须回 -1（错误码），而不是把系统调用打挂
    let bad = unsafe { syscall(SYS_NOBODY, 0, 0) };
    SLOTS.unknown.store(bad, Ordering::Relaxed);
    // 读一次 .rodata 再写进第四个槽：这条动作同时证明"那段装了、且 ring3 读得到"
    SLOTS.rodata_first.store(BANNER[0] as u64, Ordering::Relaxed);
    // **P7 的归因实验**：同一个任务、同一条入口、连续再打 29 次同样的调用。
    // 冷热假设的预测很具体——第一次明显比后面贵；若结构成本假设成立，
    // 这一批的 min 会和第一次同量级。让数字自己选一个（不写结论，见 BACKLOG）。
    let mut n = 0u64;
    while n < PINGS_EXTRA {
        let _ = unsafe { syscall(SYS_PING, n, 0) };
        n += 1;
    }
    SLOTS.loops.store(n, Ordering::Relaxed);
    // **生命周期**：内核在装载之后往第六格写了非 0，就走 `SYS_EXIT`。
    // `load(Relaxed)`：不需要顺序保证（写入发生在任务被换上来之前，有 tick 与
    // 中断关闭这两道天然屏障），需要的只是"别被优化掉、别被提前"。
    let flag = SLOTS.flag.load(Ordering::Relaxed);
    // **指针校验实验**（§10.3）：三个调用都是"把用户给的指针交给内核去读"。
    // 期望是：合法的那个读成功并回值；两个坏的都回 `-EFAULT` 且**任务继续活着**——
    // 内核不能因为坏指针就杀用户（那是拒绝服务），更不能自己去读内核半区（那是提权）。
    if flag & FLAG_PEEK != 0 {
        // **踩到的坑（这就是它长这样的原因）**：第一版这里传的是 `.rodata` 里 `BANNER` 的地址，
        // `rust-lld` 直接报
        //   relocation R_X86_64_32S out of range: 4294971392 is not in [-2147483648, 2147483647]
        // ——镜像基址在 4 GiB 之上，而 `relocation-model=static` 下"取某个节的地址"
        // 可以退化成 32 位绝对重定位。改成**栈上的局部量**：它的地址是 rsp 相对的，
        // 不需要任何绝对重定位，而且这才是系统调用真正常见的形状（调用方递一个自己的指针）。
        let probe: u64 = RODATA_FIRST;
        let good = unsafe { syscall(SYS_PEEK, core::ptr::addr_of!(probe) as u64, 0) };
        SLOTS.peek_ok.store(good, Ordering::Relaxed);
        // `probe` 被取过地址，不能被优化掉；这里再读一次，明确它还在。
        if unsafe { core::ptr::read_volatile(core::ptr::addr_of!(probe)) } == 0 {
            SLOTS.peek_ok.store(0, Ordering::Relaxed);
        }
        let kern = unsafe { syscall(SYS_PEEK, 0xffff_ffff_8000_0000, 0) };
        SLOTS.peek_kernel.store(kern, Ordering::Relaxed);
        // 自己栈页下面那一页的末尾 8 字节：那一页**永不映射**（`mm::alloc_user_va_range(2)`
        // 留的 guard）。这里拿它当"用户半区里但没映射"的地址，比随手编一个数更硬：
        // 它离这个任务的栈只差一页，"没检查就读"的下场就是踩到自己的 guard。
        let guard = stack_base() - 8;
        let unmapped = unsafe { syscall(SYS_PEEK, guard, 0) };
        SLOTS.peek_unmapped.store(unmapped, Ordering::Relaxed);
    }
    if flag & FLAG_BUF != 0 {
        // **跨页拷贝**（§10.3 完整版，两个方向各试一次）。缓冲区地址 = 内核写进来的
        // 页基址 + `BUF_OFF`，长度 `BUF_LEN` ⇒ 区间正好跨过这一段的第一条页边界
        //（上面那条编译期 `const assert` 盯着这件事，它不是注释里的约定）。
        let base = SLOTS.self_va.load(Ordering::Relaxed);
        let ptr = base + BUF_OFF;
        // 1) 内核 → 用户：`SYS_POKE_BUF` 按 `poke_pattern(j)` 写进来，程序逐字节核对。
        //    为什么由被写的一方核对：内核报"写了 256 字节"证不了内容对不对，
        //    而"写满第一页、第二页没动"这种错法只有对面那半页能看见。
        let n = unsafe { syscall(SYS_POKE_BUF, ptr, BUF_LEN) };
        SLOTS.buf_n.store(n, Ordering::Relaxed);
        let mut ok: u64 = 1;
        let mut j = 0u64;
        while j < BUF_LEN {
            // SAFETY: `ptr+j` 落在本任务自己的可写段里，且内核刚写过这一整段
            let v = unsafe { core::ptr::read_volatile((ptr + j) as *const u8) };
            if v != poke_pattern(j) {
                ok = 0x1000 + j;
                break;
            }
            j += 1;
        }
        if n != BUF_LEN && ok == 1 {
            // 内容全对但字节数不对：另一种失败，要分开编码，否则两种症状读成同一个数
            ok = 0x2000;
        }
        SLOTS.buf_ok.store(ok, Ordering::Relaxed);
        // 2) 用户 → 内核：本程序写**另一种**模式进去，让内核读走并算 FNV-1a；
        //    内核侧用例独立算同一个期望和，两个数相等才叫"逐字节读准了"。
        let mut j = 0u64;
        while j < BUF_LEN {
            // SAFETY: 同上面那条，这段是可写页，且这个区间就是本次实验的场地
            unsafe { core::ptr::write_volatile((ptr + j) as *mut u8, write_pattern(j)) };
            j += 1;
        }
        let sum = unsafe { syscall(SYS_PEEK_BUF, ptr, BUF_LEN) };
        SLOTS.buf_sum.store(sum, Ordering::Relaxed);
        // 3) 故意要一个**超限**的长度：内核必须回 `-3`（`-ETOOLONG`），
        //    既不能回 `-2`（那是"地址坏了"，处置方向不同），也不能悄悄只搬前 4 KiB。
        //    这一格存在的理由是 ABI 表里那个号得有人走过（§10.2 的"每个号都有证人"）。
        //    **长度不是越界**：这次调用之后任务还得活着，所以用例同时判 `kills == 0`。
        let err = unsafe { syscall(SYS_PEEK_BUF, ptr, COPY_MAX + 1) };
        SLOTS.buf_err.store(err, Ordering::Relaxed);
    }
    if flag & FLAG_FASTPATH != 0 {
        // 先看特性位，再决定打不打 `syscall`：LSTAR 没装就打它就是跳到 rip=0，
        // 那是 ring0 的取指故障 —— 用户程序不该有能力把整机打死。
        let word = unsafe { syscall(SYS_ABI_INFO, 0, 0) };
        SLOTS.abi_word.store(word, Ordering::Relaxed);
        if word & F_FASTPATH != 0 {
            let n = unsafe { syscall_fast(SYS_PING, 0, 0) };
            SLOTS.fast_ping.store(n, Ordering::Relaxed);
            SLOTS.fast_cs.store(self_cs(), Ordering::Relaxed);
            SLOTS.fast_ss.store(self_ss(), Ordering::Relaxed);
            let mut k = 1u64;
            while k < FAST_CALLS {
                let _ = unsafe { syscall_fast(SYS_PING, k, 0) };
                k += 1;
            }
        }
    }
    if flag & FLAG_HANDLE != 0 {
        // P7 ring3 句柄：内核按"这个容器"的身份授了 READ|DUP 句柄，指向卷上的 HELLO.ELF。
        // ① 读 4 字节必须是 ELF 魔数；② close 必须回 0（越权/旧句柄两格由内核用例覆盖）。
        // 缓冲用栈上的局部量：`relocation-model=static` 下取 `.rodata` 地址会退化成 32 位
        // 绝对重定位（见上面 peek 那段注释）。
        let mut buf = [0u8; 4];
        let ptr = core::ptr::addr_of!(buf) as u64;
        let h = SLOTS.handle.load(Ordering::Relaxed);
        let n = unsafe { syscall3(SYS_FILE_READ, h, ptr, 4) };
        let magic = if n == 4 {
            // SAFETY: `ptr` 指向本任务栈上这 4 个字节，内核刚写满
            (unsafe { core::ptr::read_volatile(ptr as *const u32) }) as u64
        } else {
            0xdead_0000 | (n & 0xffff)
        };
        SLOTS.h_magic.store(magic, Ordering::Relaxed);
        // close 的返回值不单占一格：它成功与否由内核的 `live()==0` 判（表清空就是见证）
        let _ = unsafe { syscall(SYS_HANDLE_CLOSE, h, 0) };
        // 最后一个写：内核等这一格非 0 才读上面三格
        SLOTS.h_done.store(HANDLE_DONE, Ordering::Relaxed);
    }
    if flag & FLAG_GUARD_STORE != 0 {
        // 从 ring3 直接写 guard 页：这**不经过**任何指针校验（校验管的是"内核替谁读"），
        // 硬件的页表就是唯一的把关人，而它必须把这次访问变成"只杀这个任务"。
        let p = (stack_base() - 8) as *mut u64;
        // SAFETY: 这一条是**故意的越界**，目的就是让硬件拒掉它。地址由本任务自己的
        // 栈底减 8 算出，落在内核给它留的 guard 页里（永不映射）。
        unsafe { core::ptr::write_volatile(p, 0xdead) };
        // 写成功了 = 隔离没生效。这里不猜结论：把"居然成功了"这件事写回槽位，
        // 由内核侧的判据去红（红得有数字，而不是靠有没有走到下一行）。
        SLOTS.peek_unmapped.store(0x911c, Ordering::Relaxed);
    }
    if flag & FLAG_EXIT != 0 {
        let _ = unsafe { syscall(SYS_EXIT, 0, 0) };
        // 正常不会回到这里：内核标了 Free 并把 CPU 换给别人了。
        // 万一回来了（退出请求被吞掉），就停在自跳转里，等旁观者 `terminate_task` 收——
        // 判据看的是 `exits()` 与资源回账，这两种收场读出来不一样，不会互相掩盖。
        loop {
            // SAFETY: 自跳转，见 panic 处理器那条注释（ring3 不能用 hlt）
            unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) };
        }
    }

    loop {
        // 没有 SYS_EXIT（那是 M4-2 下一段的事，且要先解决"谁来回收这个任务的栈"，
        // 见 BACKLOG 的 M4 一节）：跑完之后停在自己身上，等时钟把它换下去。
        // 自跳转而不是 `hlt`：理由见上面 panic 处理器那段（ring3 的 hlt = #GP(0)）。
        // SAFETY: 只停本 CPU 上的一段用户代码；内核随时可以按时钟接管。
        unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) };
    }
}
