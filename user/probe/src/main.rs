//! 第二个用户程序（W3 P5a，ADR-075 决策 1 的第一刀）：**第一个真在 ring3 打 VMO 三个号的调用方**。
//!
//! 它做的事很短：`abi_info` 读回特性位 → `vmo_create(2)` → `vmo_write` 把自己 `.rodata` 里的
//! 8 字节图案写进对象 → `aspace_map` 拿到一个用户 VA → **自己从那个 VA 读回**并逐字节比对
//! → 写 done → `exit`。每一步的返回值都写进 `.slots`，内核用例读走判定。
//!
//! 三条与 hello 同源的约定（`user/hello/src/main.rs` 模块头）：
//! 1. 入口走 `int 0x80`，所以不声明 `rcx`/`r11` 被破坏（那是 SYSCALL 的硬件行为，`int N` 不动它们）。
//!    13 号有四个参数，第四个走 **r10**（ADR-074 的 P4b 号表）。
//! 2. 槽基址由**哨兵魔数**证明，不靠"我记得链接脚本怎么排的"。
//! 3. 号/参数/返回值照 ABI：号在 rax，返回 rax，负数是 `-ErrorCode`。
//!
//! **为什么读回要在用户态自己做**：内核说"映射成功了"与"ring3 真能读到那些字节"是两件事。
//! 这一格由程序自己判（读回比对写 1/0），内核只读走那个数 ⇒ 两台仪器各说各的话。

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};

/// `.slots` 第一个 8 字节：内核用例靠它确认槽基址（与 hello 的魔数**不同**，免得读错容器）。
pub const SLOTS_MAGIC: u64 = 0xa5a5_5a5a_8765_4321;
/// `abi_info` 返回值的槽偏移。
pub const OFF_ABI: u64 = 8;
/// 12 号返回的句柄值槽偏移。
pub const OFF_HANDLE: u64 = 16;
/// 13 号返回的字节数槽偏移。
pub const OFF_WRITTEN: u64 = 24;
/// 14 号返回的用户 VA 槽偏移。
pub const OFF_MAP_VA: u64 = 32;
/// 程序自己从映射读回比对的结果（1=一致）。
pub const OFF_READBACK: u64 = 40;
/// 跑完标记：内核等的是这一格，不是"开始跑了"。
pub const OFF_DONE: u64 = 48;
/// 14 号扩展形（ADR-075 决策 6）实际**请求**的 VA；0 = 四次候选都没拿到。
pub const OFF_X_REQ: u64 = 56;
/// 那一次调用的原始返回值（判据要求它与 `OFF_X_REQ` **逐字相等** ⇒ 不许静默改地址）。
pub const OFF_X_RET: u64 = 64;
/// 从请求 VA 读回比对的结果（1=一致）⇒ 拿到了地址还不算，得真翻译到同一份帧。
pub const OFF_X_READ: u64 = 72;
/// W+X（rsi=3）的原始返回，必须是 -1。
pub const OFF_WX_RET: u64 = 80;
/// 非对齐请求（+8）的原始返回，必须是 -1。
pub const OFF_UN_RET: u64 = 88;
/// 页大小（与内核 `mm::PAGE` 同一事实的第二次声明，靠读回对账）。
const PAGE: u64 = 4096;
/// 写进对象、再从映射读回来比对的图案。内核用例里有同一份常量的第二份声明。
pub const PATTERN: [u8; 8] = [0x5A, 0xA5, 1, 2, 3, 4, 5, 6];
/// ABI 的 VMO 特性位（`user.rs` 的 `F_VMO`）。
pub const F_VMO: u64 = 32;

const SYS_EXIT: u64 = 3;
const SYS_ABI_INFO: u64 = 7;
const SYS_VMO_CREATE: u64 = 12;
const SYS_VMO_WRITE: u64 = 13;
const SYS_ASPACE_MAP: u64 = 14;
const SYS_HANDLE_DUP: u64 = 9;
const SYS_PROCESS_CREATE: u64 = 11;
const SYS_THREAD_CREATE: u64 = 15;
const SYS_PROCESS_START: u64 = 16;
/// StartupInfo 的布局常量：**用户侧独立声明**（与内核 `user.rs` 同一组数，靠读回对账）。
const SI_MAGIC: u32 = 0x4155_524F;
const ROLE_JOB: u32 = 3;
/// 11 号返回的 Proc 句柄。
pub const OFF_PROC_H: u64 = 96;
/// 15 号返回的 Thread 句柄。
pub const OFF_THREAD_H: u64 = 104;
/// 16 号的返回值（0 = 成功）。
pub const OFF_START_RET: u64 = 112;
/// 子进程写结果那一页的 VMO 句柄（内核用它读走子进程写的四个数）。
pub const OFF_DATA_H: u64 = 120;
/// StartupInfo 那一页的 VMO 句柄（内核用它交叉核对回填值）。
pub const OFF_SI_H: u64 = 128;
/// 四次 14 号（铺进子 AS）的原始返回值，用来分辨"哪一页没铺成"。
pub const OFF_M1: u64 = 136;
pub const OFF_M2: u64 = 144;
pub const OFF_M3: u64 = 152;
pub const OFF_M4: u64 = 160;

#[repr(C, align(4096))]
struct Slots {
    magic: AtomicU64,
    abi: AtomicU64,
    handle: AtomicU64,
    written: AtomicU64,
    map_va: AtomicU64,
    readback: AtomicU64,
    done: AtomicU64,
    x_req: AtomicU64,
    x_ret: AtomicU64,
    x_read: AtomicU64,
    wx_ret: AtomicU64,
    un_ret: AtomicU64,
    proc_h: AtomicU64,
    thread_h: AtomicU64,
    start_ret: AtomicU64,
    data_h: AtomicU64,
    si_h: AtomicU64,
    m1: AtomicU64,
    m2: AtomicU64,
    m3: AtomicU64,
    m4: AtomicU64,
}

#[link_section = ".slots"]
static SLOTS: Slots = Slots {
    magic: AtomicU64::new(0),
    abi: AtomicU64::new(0),
    handle: AtomicU64::new(0),
    written: AtomicU64::new(0),
    map_va: AtomicU64::new(0),
    readback: AtomicU64::new(0),
    done: AtomicU64::new(0),
    x_req: AtomicU64::new(0),
    x_ret: AtomicU64::new(0),
    x_read: AtomicU64::new(0),
    wx_ret: AtomicU64::new(0),
    un_ret: AtomicU64::new(0),
    proc_h: AtomicU64::new(0),
    thread_h: AtomicU64::new(0),
    start_ret: AtomicU64::new(0),
    data_h: AtomicU64::new(0),
    si_h: AtomicU64::new(0),
    m1: AtomicU64::new(0),
    m2: AtomicU64::new(0),
    m3: AtomicU64::new(0),
    m4: AtomicU64::new(0),
};

/// 写进对象的源缓冲。放 `.rodata`（加载器给 `USER_R`）：13 号只需要**读**用户缓冲，
/// 所以这一格顺带证明"只读段也能当 syscall 的源"。
#[link_section = ".rodata"]
static SRC: [u8; 8] = PATTERN;

/// `.slots` 的真实基址。**必须用 RIP 相对 lea 算**：镜像基址在 4 GiB 之上，
/// `relocation-model=static` 下 `addr_of!(静态量)` 会退化成 `R_X86_64_32S` 绝对重定位，
/// 链接期就报 out of range（hello 的模块头记过同一个坑，本轮实测又撞了一次）。
fn slots_base() -> u64 {
    let b: u64;
    // SAFETY: lea 只算地址不访存、不动栈；RIP 相对 ⇒ 不产生 32 位绝对重定位
    unsafe {
        core::arch::asm!("lea {}, [rip + {sym}]", out(reg) b, sym = sym SLOTS,
                         options(nomem, nostack, preserves_flags));
    }
    b
}

/// 源缓冲的真实地址（同上，RIP 相对）。
fn src_addr() -> u64 {
    let b: u64;
    // SAFETY: 同 slots_base
    unsafe {
        core::arch::asm!("lea {}, [rip + {sym}]", out(reg) b, sym = sym SRC,
                         options(nomem, nostack, preserves_flags));
    }
    b
}

fn put(off: u64, v: u64) {
    // SAFETY: slots_base() 是本程序 .slots 段的真实基址，off 是 Slots 内字段偏移（0..=48，
    // 结构 64 字节）；单任务访问、无并发，原子写保证内核读走的是完整值。
    unsafe {
        let p = (slots_base() + off) as *const AtomicU64;
        (*p).store(v, Ordering::Release);
    }
}

/// 四参数入口。`int 0x80` 不动 rcx/r11，所以不声明它们被破坏（模块头第 1 条）。
unsafe fn sys4(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let ret: u64;
    // SAFETY: 只有内核能处理这条中断；号走 rax、参数 rdi/rsi/rdx/r10、返回 rax。
    // 不加 nomem：处理侧会压帧并访存。preserves_flags 与 hello 的同一入口一致。
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

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // 用户态没有停机权，也不能 hlt（IOPL=0 ⇒ ring3 的 hlt 是 #GP）与 cli。只留自跳转。
    loop {
        // SAFETY: 自跳转不访存、不动栈，只把本任务停在这里等时钟换人
        unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) };
    }
}

/// 子进程那一页代码：**手写 ring3 桩**（本刀没有第三个用户产物，装载器要映的"段"就是它）。
/// 它做四件事，每件都往数据页写一个数，让内核与探针各读各的：
/// ①`[rdi]` 的 magic ②`[rdi+8]` 的 nhandles（**只有内核回填之后才是 4**）
/// ③`handles[0].handle`（转移后的新值）④拿那个句柄真调一次 `dup`（9 号）并写回返回值。
/// ④ 是 D2 的硬证人：`dup` 只有在**主人已经是子线程**时才成功，所以它证明转移真的生效了，
/// 而不只是"表里有个看起来像句柄的数"。
fn child_stub(data_va: u64) -> [u8; 49] {
    let mut s: [u8; 49] = [
        0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0, // movabs rdx, data_va
        0x8B, 0x07,                         // mov eax, [rdi]        ; magic
        0x89, 0x02,                         // mov [rdx], eax
        0x8B, 0x47, 0x08,                   // mov eax, [rdi+8]      ; nhandles
        0x89, 0x42, 0x04,                   // mov [rdx+4], eax
        0x48, 0x8B, 0x47, 0x20,             // mov rax, [rdi+32]     ; handles[0].handle
        0x48, 0x89, 0x42, 0x08,             // mov [rdx+8], rax
        0x48, 0x89, 0xC7,                   // mov rdi, rax
        0xBE, 0x01, 0x00, 0x00, 0x00,       // mov esi, 1            ; RIGHT_READ
        0xB8, 0x09, 0x00, 0x00, 0x00,       // mov eax, 9            ; SYS_HANDLE_DUP
        0xCD, 0x80,                         // int 0x80
        0x48, 0x89, 0x42, 0x10,             // mov [rdx+16], rax
        0xEB, 0xFE,                         // jmp .                 ; 停在这里等内核收场
    ];
    s[2..10].copy_from_slice(&data_va.to_le_bytes());
    s
}

/// 装载器序列（ADR-075 决策 1/3/5/8 的**用户态**那一半）：
/// 11 造进程 → 建四个 VMO（代码桩/栈/StartupInfo/数据）→ 14 用 `rdx = Proc 句柄` 铺进**子 AS**
/// → 15 建线程（停住）→ 16 转移 + 回填 + 放行。每一步的返回值都写进 `.slots`。
fn load_child(job_h: u64, abi: u64) {
    // SAFETY: 以下都是本程序自己的系统调用，号与参数照 ABI 文档（§4.4c）
    unsafe {
        let proc_h = sys4(SYS_PROCESS_CREATE, job_h, 0, 0, 0);
        put(OFF_PROC_H, proc_h);
        if (proc_h as i64) <= 0 {
            return;
        }
        // **只建三个对象、只铺三次**：栈与数据共用一张 RW 页。
        // 这不是省事，是容量账：装载器自己已占 5 格（3 段 + 用户栈 + spawn_user 的内核栈），
        // `MAX_OWNED = 8` ⇒ 只剩 3 格。四页各铺一次会在第二页上撞 `-6`（本刀实测过），
        // 而那条容量账写着"实测 6/8、余量 ≥ 2"，不该为了用例去改它。
        // 桩不压栈（`int 0x80` 从 ring3 进来走 TSS 的内核栈），所以栈与数据同页不冲突：
        // 数据写在页首 24 字节，栈顶取页尾 -16。
        let code = sys4(SYS_VMO_CREATE, 1, 0, 0, 0);
        let si = sys4(SYS_VMO_CREATE, 1, 0, 0, 0);
        let data = sys4(SYS_VMO_CREATE, 1, 0, 0, 0);
        put(OFF_DATA_H, data);
        put(OFF_SI_H, si);
        if (code as i64) <= 0 || (si as i64) <= 0 || (data as i64) <= 0 {
            return;
        }
        // 子 AS 是空的，四个 VA 随便挑（但仍按"请求 VA"那条路走，顺带再证一次不许静默改地址）
        let cbase: u64 = 0x3_0000_0000;
        let code_va = cbase;
        let data_va = cbase + PAGE; // 同时当栈（见上面那段容量账）
        let si_va = cbase + 2 * PAGE;
        let stack_va = data_va;
        let stub = child_stub(data_va);
        let n = sys4(SYS_VMO_WRITE, code, 0, stub.as_ptr() as u64, stub.len() as u64);
        if n != stub.len() as u64 {
            put(OFF_START_RET, u64::MAX);
            return;
        }
        // StartupInfo：调用方只写 magic/ABI/nhandles 与**自己那一条**转移（ROLE_JOB），
        // 三个 SELF_* 由内核 grant 并回填（替它填会被 16 号拒）
        let mut hdr = [0u8; 24];
        hdr[0..4].copy_from_slice(&SI_MAGIC.to_le_bytes());
        // **从 abi_info 的返回值里取**，不写死：内核 bump 一次 minor 就把写死的那份打红
        // （本轮实测：内核到 9 而探针写死 8 ⇒ 16 号的版本校验拒了整页）
        hdr[4..6].copy_from_slice(&((abi >> 32) as u16).to_le_bytes());
        hdr[6..8].copy_from_slice(&((abi >> 16) as u16).to_le_bytes());
        hdr[8..12].copy_from_slice(&1u32.to_le_bytes()); // 我传一条
        let w = sys4(SYS_VMO_WRITE, si, 0, hdr.as_ptr() as u64, hdr.len() as u64);
        let mut d = [0u8; 16];
        d[0..4].copy_from_slice(&ROLE_JOB.to_le_bytes());
        d[8..16].copy_from_slice(&job_h.to_le_bytes());
        let w2 = sys4(SYS_VMO_WRITE, si, 24, d.as_ptr() as u64, d.len() as u64);
        if w != 24 || w2 != 16 {
            put(OFF_START_RET, u64::MAX - 1);
            return;
        }
        let r1 = sys4(SYS_ASPACE_MAP, code, 2, proc_h, code_va); // X
        let r2 = sys4(SYS_ASPACE_MAP, data, 1, proc_h, data_va); // W（兼栈）
        let r3 = sys4(SYS_ASPACE_MAP, si, 0, proc_h, si_va); // 只读
        put(OFF_M1, r1);
        put(OFF_M2, r2);
        put(OFF_M3, r3);
        put(OFF_M4, 0);
        if r1 != code_va || r2 != data_va || r3 != si_va {
            put(OFF_START_RET, u64::MAX - 2);
            return;
        }
        let th = sys4(SYS_THREAD_CREATE, proc_h, code_va, stack_va + PAGE - 16, 0);
        put(OFF_THREAD_H, th);
        if (th as i64) <= 0 {
            return;
        }
        let sr = sys4(SYS_PROCESS_START, proc_h, th, si, si_va);
        put(OFF_START_RET, sr);
    }
}
/// `mailbox` 是内核交进来的一页用户 VA：根 Job 由内核持有、只在这条用例里出示
/// （使用者裁决 2026-11-10），所以句柄值由内核 grant 给本任务之后写进那一格，本程序轮询它。
/// **首参走 rdi**（15/16 号那条 ABI 的同一个位置），不是全局变量。
#[no_mangle]
pub extern "C" fn _start(mailbox: u64) -> ! {
    put(0, SLOTS_MAGIC);
    // SAFETY: 以下都是本程序自己的系统调用，号与参数照 ABI 文档
    unsafe {
        let abi = sys4(SYS_ABI_INFO, 0, 0, 0, 0);
        put(OFF_ABI, abi);
        // 实验格只在**非装载器**实例里跑：装载器实例的资源袋要留给子进程那三页
        // （`MAX_OWNED = 8`，装载器自己占 5 格，再做实验就只剩 1 格 ⇒ 实测撞 `-6`）。
        if mailbox == 0 {
            let h = sys4(SYS_VMO_CREATE, 2, 0, 0, 0);
            put(OFF_HANDLE, h);
            let n = sys4(SYS_VMO_WRITE, h, 0, src_addr(), 8);
            put(OFF_WRITTEN, n);
            // rsi=1 ⇒ 可写、不可执行（P4b 的形状：执行权不给）
            let va = sys4(SYS_ASPACE_MAP, h, 1, 0, 0);
            put(OFF_MAP_VA, va);
            let mut ok = 1u64;
            // 只有真拿到一个 VA 才读；负数是错误码，解引用它就是自找 #PF
            if (va as i64) > 0 {
                let p = va as *const u8;
                for i in 0..8usize {
                    // SAFETY: va 是 14 号返回的用户 VA，长度 8 字节落在它那一页里（对象 2 页）；
                    // 只读、不越界。这一格正是要证"ring3 真能翻译到这个地址"。
                    if unsafe { core::ptr::read_volatile(p.add(i)) } != PATTERN[i] {
                        ok = 0;
                    }
                }
            } else {
                ok = 0;
            }
            put(OFF_READBACK, ok);
            // ---- 14 号的扩展形（ADR-075 决策 6）：rsi=bit1 ⇒ 只给执行位，r10 ⇒ 请求地址
            // 候选步进 **64 页（256 KiB），但仍落在第一次映射那同一个 2 MiB 块里**：
            // ① 不能贴着动态边界（M21 实测：紧贴的候选会被分配器"顺手"给出来，
            //    "返回==请求"就变成运气证人，只有非对齐那一格抓得到变异）；
            // ② 不能跨 2 MiB 块（另一轮实测：内核 AS 里新块要新建一张页表页，而它记 MOD_BOOT、
            //    **生命周期=内核**，于是"帧回基线"那格永久少一帧——那不是漏，是这条路径的固有代价）。
            // 允许全部失败（保留表今天还可能被别的用例占着），但成功那一次必须读回一致。
            let mut asked = 0u64;
            let mut got = u64::MAX;
            if ok == 1 {
                for k in 1..=4u64 {
                    let req = (va + k * 64 * PAGE) & !(PAGE - 1);
                    let r = sys4(SYS_ASPACE_MAP, h, 2, 0, req);
                    asked = req;
                    got = r;
                    if r == req {
                        break;
                    }
                }
            }
            let mut x_read = 0u64;
            if got == asked {
                let p = asked as *const u8;
                x_read = 1;
                for i in 0..8usize {
                    // SAFETY: asked 是 14 号按请求值返回的**本对象**映射（2 页），
                    // 这里只读前 8 字节；只读、不越界。
                    if unsafe { core::ptr::read_volatile(p.add(i)) } != PATTERN[i] {
                        x_read = 0;
                    }
                }
            }
            put(OFF_X_REQ, asked);
            put(OFF_X_RET, got);
            put(OFF_X_READ, x_read);
            // W+X 与非对齐都必须被拒成 -1（拿的是第一次成功的那个请求值）
            put(OFF_WX_RET, sys4(SYS_ASPACE_MAP, h, 3, 0, asked));
            put(OFF_UN_RET, sys4(SYS_ASPACE_MAP, h, 2, 0, asked + 8));
        }
        // 装载器那一半：等内核把 Job 句柄放进邮箱，然后真打 11/14/15/16
        if mailbox != 0 {
            let mut job_h = 0u64;
            for _ in 0..4_000_000u32 {
                // SAFETY: mailbox 是内核传进来的用户 VA，已映射且可读写；只读一个 u64。
                // 轮询上限是硬的，读不到就放弃（不无限自旋）
                let v = unsafe { core::ptr::read_volatile(mailbox as *const u64) };
                if v != 0 {
                    job_h = v;
                    break;
                }
                core::hint::spin_loop();
            }
            if job_h != 0 {
                load_child(job_h, abi);
            }
        }
        put(OFF_DONE, 1);
        // **故意不自己 exit**：退出即被 reap，映射与数据页当场解映射，内核用例就读不到槽了。
        // 由用例 terminate_task + 回收来收场，走的是同一条 reap/revoke_task 路径（句柄与 VMO 一样归还），
        // 但槽在收场之前一直可读。hello 的默认收场也是这个形状（它的 FLAG_EXIT 才走自退出）。
    }
    let _ = SYS_EXIT;
    loop {
        // SAFETY: 同 panic handler
        unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) };
    }
}
