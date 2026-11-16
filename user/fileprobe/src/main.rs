//! FS-03 切片 D：ring3 文件探针（ADR-108 决策 8）。
//!
//! 它是**第一个在 ring3 打 22/24/25/26 的调用方**。为什么不往 shell 里加一条命令了事：
//! V1.0 那句"文件系统操作由用户空间命令完成"讲的是产品，而这里要量的是 ABI 本身；
//! 塞进 shell 会把"命令的行为"和"号的行为"糊成一格，红了也分不清是谁。
//!
//! 三条与前三个产物相同的约定：
//! 1. 入口走 `int 0x80`，所以**不**声明 `rcx`/`r11` 被破坏（那是 SYSCALL 的硬件行为）。
//! 2. 号在 `rax`，参数 `rdi/rsi/rdx`，返回 `rax`，负数是 `-ErrorCode`。
//! 3. 结果写进 `.slots` 的**固定字节偏移**，内核用例按同一组偏移读回。偏移表两边各写一份
//!    （这里一份，`kernel/src/ktests/fs_open.rs` 一份）——共用一份就只剩一台仪器。
//!
//! 路径与缓冲都用 `.slots` 里的字节，而且路径是用两个 u64 **立即数**写进去的：镜像基址在
//! 4 GiB 之上，静态数据的取址在 `relocation-model=static` 下会退化成绝对重定位，
//! 而本产物没有重定位器（probe 的模块头记过这个实测）。全程只有一个 `lea` 拿 `.slots` 基址。

#![no_std]
#![no_main]

// ---- 调用号（与 kernel/src/user.rs 同一组数，用户侧独立声明）----
const SYS_EXIT: u64 = 3;
const SYS_ABI_INFO: u64 = 7;
const SYS_HANDLE_CLOSE: u64 = 8;
const SYS_FILE_READ: u64 = 10;
const SYS_FILE_OPEN: u64 = 22;
const SYS_FILE_SEEK: u64 = 24;
const SYS_FILE_STAT: u64 = 25;
const SYS_DIR_READ: u64 = 26;

// ---- 信箱布局（偏移单位：字节，从 `.slots` 基址算；结果格一律 8 字节对齐）----
const SLOT_MAGIC: u64 = 0;
const SLOT_ABI: u64 = 8;
const SLOT_OPEN: u64 = 16;
const SLOT_READ_TOTAL: u64 = 24;
const SLOT_HEAD: u64 = 32;
const SLOT_EOF: u64 = 40;
const SLOT_SUM_FULL: u64 = 232;
const SLOT_SUM_TAIL: u64 = 240;
const SLOT_DIR_CLOSE: u64 = 248;
/// 诊断格（欠账②，BACKLOG §335）：同一份字节、同一个 `h`，一次用 `wrapping_mul`、
/// 一次用展开式 `t*435 + (t<<40)`。两格不同 ⇒ 分歧在乘法的降级；两格相同但与核内不同
/// ⇒ 分歧在写入通路或字节本身。**不参与判据**，只把数字打出来。
const SLOT_FNVMUL: u64 = 256;
const SLOT_FNVADD: u64 = 264;
const SLOT_SEEK50: u64 = 48;
const SLOT_READ50_TOTAL: u64 = 56;
const SLOT_TAIL_HEAD: u64 = 64;
const SLOT_CUR60: u64 = 72;
const SLOT_END80: u64 = 80;
const SLOT_SEEK_FAR: u64 = 88;
const SLOT_STAT: u64 = 96;
const SLOT_STAT_SIZE: u64 = 104;
const SLOT_STAT_FIRST: u64 = 112;
const SLOT_STAT_MAGIC: u64 = 120;
const SLOT_STAT_SHORT: u64 = 128;
const SLOT_DIR: u64 = 136;
const SLOT_DIR_RECORDS: u64 = 144;
const SLOT_DIR_NAME_SUM: u64 = 152;
const SLOT_DIR_SIZE_SUM: u64 = 160;
const SLOT_READ_DIR: u64 = 168;
const SLOT_DIR_SEEK: u64 = 176;
const SLOT_REL: u64 = 184;
const SLOT_MISSING: u64 = 192;
const SLOT_FLAGS: u64 = 200;
const SLOT_CLOSE: u64 = 208;
const SLOT_STALE: u64 = 216;
const SLOT_DONE: u64 = 224;

/// 缓冲也放在 `.slots` 这一页里：读回的字节、stat 记录、一条 dirent、拼出来的路径与短名拼接。
const BUF_SMALL: u64 = 512;
const BUF_SMALL_CAP: u64 = 128;
const BUF_STAT: u64 = 640;
const BUF_DIR: u64 = 688;
const BUF_PATH: u64 = 1200;


/// 第一个 8 字节：内核靠它确认槽基址，不靠"我记得链接脚本怎么排的"（与 probe 同一条纪律）。
const MAGIC_VAL: u64 = 0x544f_4c53_315f_5046; // "FP_1SLOT"
/// 收尾哨兵：内核等这一格非零，而不是等"打了几个号"——调用数会被代码生成挪顺序。
const DONE_VAL: u64 = 0x3345_4e4f_445f_5046; // "FP_DONE3"

/// StatV1 的字段偏移（用户侧独立声明，与 ADR-108 决策 4 那张表各自写一遍）。
const ST_MAGIC_AT: u64 = 0;
const ST_SIZE_AT: u64 = 8;
const ST_FIRST_AT: u64 = 16;
/// DirentV1 的字段偏移（决策 5）。
const DE_SIZE_AT: u64 = 16;
const DE_NAME_LEN_AT: u64 = 8;
const DE_NAME_AT: u64 = 48;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // 用户态没有停机权，也不能用 hlt/cli（ring3 下都是 #GP，hello 的注释里记过实测）。
    loop {
        unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) };
    }
}

/// `.slots` 的真实基址。**必须用 RIP 相对 lea 算**，理由见模块头。
fn slots_base() -> u64 {
    let b: u64;
    // SAFETY: lea 只算地址、不访存、不动栈；RIP 相对 ⇒ 不产生 32 位绝对重定位。
    unsafe {
        core::arch::asm!("lea {}, [rip + {sym}]", out(reg) b, sym = sym SLOTS,
                         options(nomem, nostack, preserves_flags));
    }
    b
}

/// 三参 syscall。`int 0x80` 不动 rcx/r11，所以不声明它们为 clobber（模块头第 1 条）。
#[inline]
unsafe fn sys3(nr: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    // SAFETY: 只有内核能处理这条中断；号走 rax、参数 rdi/rsi/rdx、返回 rax。
    // preserves_flags 是对的：中断门清的是内核的 IF，iretq 把用户帧那份 rflags 原样装回。
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

fn put(off: u64, v: u64) {
    // SAFETY: 基址来自 slots_base()（本程序 `.slots` 段的真实基址），off 是上面那张表里的常量，
    // 一律 8 对齐且落在本页 [0, 1536) 内；单任务、无并发。volatile 保证结果格的写不会被
    // 重排到 `done` 哨兵之后——内核就是靠那个顺序判定"这一跑真的跑完了"。
    unsafe { core::ptr::write_volatile((slots_base() + off) as *mut u64, v) };
}

fn put_byte(off: u64, b: u8) {
    // SAFETY: 同 put（这里是 1 字节写，偏移同样落在本页内）。
    unsafe { core::ptr::write_volatile((slots_base() + off) as *mut u8, b) };
}

fn get_byte(off: u64) -> u8 {
    // SAFETY: 同 get，1 字节读。
    unsafe { core::ptr::read_volatile((slots_base() + off) as *const u8) }
}

fn get_u32(off: u64) -> u32 {
    // SAFETY: 同 put；偏移都取自上面那两张 4 字节对齐的字段表。
    unsafe { core::ptr::read_volatile((slots_base() + off) as *const u32) }
}

/// 把一条路径写成 16 字节里的低 `len` 个字节（两个 u64 立即数）。
fn set_path(lo: u64, hi: u64) {
    put(BUF_PATH, lo);
    put(BUF_PATH + 8, hi);
}

/// 同一个 `h` 用两种写法各推一步：`wrapping_mul(素数)` 与展开式 `t*435 + (t<<40)`。
/// 模 2^64 下这是同一个式子，所以两格**必须同数**——这一格当场抓住过一次真错：
/// 素数写成 12 位十六进制 `0x1000_0000_01b3`（值成了 2^44+435），低 40 位照对、高 24 位全错。
/// 那笔"未归因"的 FNV 分歧就是这么来的（BACKLOG §335 欠账②）。
fn fnv_pair(off: u64, len: u64) -> (u64, u64) {
    let mut a = 0xcbf2_9ce4_8422_2325u64;
    let mut b = 0xcbf2_9ce4_8422_2325u64;
    let mut i = 0u64;
    while i < len {
        let x = get_byte(off + i) as u64;
        a = (a ^ x).wrapping_mul(0x0000_0100_0000_01b3);
        let t = b ^ x;
        b = t
            .wrapping_mul(435)
            .wrapping_add(t.wrapping_shl(40));
        i += 1;
    }
    (a, b)
}

/// 缓冲里前 8 字节的 u64（小端）。**不做哈希**：三处各写一遍哈希，红的时候分不清是谁的算法
/// 与别人不同来（本轮实测：ring3 那份 FNV 低 32 位与核内/宿主机一致、高 32 位不一致，
/// 值得单独查，但不该由 FS-03 的验收替它背书）。改成"首 8 字节 + 字节和"这两个没有算法的量。
fn word8(off: u64) -> u64 {
    let mut v = 0u64;
    let mut i = 0u64;
    while i < 8 {
        v |= (get_byte(off + i) as u64) << (8 * i);
        i += 1;
    }
    v
}

/// 缓冲里 `[off, off+len)` 的字节和。
fn byte_sum(off: u64, len: u64) -> u64 {
    let mut s = 0u64;
    let mut i = 0u64;
    while i < len {
        s = s.wrapping_add(get_byte(off + i) as u64);
        i += 1;
    }
    s
}

/// 反复读到 EOF（或读到错误）。返回（总字节数, 最后一次的返回值）。
fn read_all(h: u64, off: u64, cap: u64) -> (u64, u64) {
    let mut total = 0u64;
    let mut last = 0u64;
    while total < cap {
        // SAFETY: 本程序自己的系统调用，缓冲地址在本页内（模块头第 2 条的 ABI）。
        let n = unsafe { sys3(SYS_FILE_READ, h, slots_base() + off + total, cap - total) };
        last = n;
        if (n as i64) <= 0 {
            break;
        }
        total += n;
    }
    (total, last)
}

/// `readdir` 一次一条（缓冲只给 512 字节）直到 0。
/// 返回（条数, 短名字节和, 大小累加）——三个量都不依赖任何哈希实现。
fn read_dir_all(h: u64) -> (u64, u64, u64) {
    let mut records = 0u64;
    let mut name_sum = 0u64;
    let mut size_sum = 0u64;
    loop {
        // SAFETY: 同 read_all。
        let n = unsafe { sys3(SYS_DIR_READ, h, slots_base() + BUF_DIR, 512) };
        if (n as i64) <= 0 || records >= 64 {
            break;
        }
        records += 1;
        let sl = get_byte(BUF_DIR + DE_NAME_LEN_AT) as u64;
        let mut i = 0u64;
        while i < sl {
            name_sum = name_sum.wrapping_add(get_byte(BUF_DIR + DE_NAME_AT + i) as u64);
            i += 1;
        }
        size_sum += get_u32(BUF_DIR + DE_SIZE_AT) as u64;
    }
    (records, name_sum, size_sum)
}

/// 探针主体。`_mailbox` 恒 0：本产物不靠内核预先交句柄，**所有句柄都由 22 号自己挣**
/// （ADR-107 的"open 时授予"要在 ring3 这一侧成立，这才是它要量的东西）。
#[no_mangle]
pub extern "C" fn _start(_mailbox: u64) -> ! {
    put(SLOT_MAGIC, MAGIC_VAL);
    // SAFETY: 以下全是本程序自己的系统调用，号与参数照 ADR-108 那张表。
    unsafe {
        put(SLOT_ABI, sys3(SYS_ABI_INFO, 0, 0, 0));

        // ---- 22 打开 /SMALL.BIN，10 读到底 ----
        set_path(0x422e_4c4c_414d_532f, 0x0000_0000_0000_4e49); // "/SMALL.BIN"
        let open = sys3(SYS_FILE_OPEN, slots_base() + BUF_PATH, 10, 0);
        put(SLOT_OPEN, open);
        if (open as i64) >= 0 {
            let (total, eof) = read_all(open, BUF_SMALL, BUF_SMALL_CAP);
            put(SLOT_READ_TOTAL, total);
            let (ma, mb) = fnv_pair(BUF_SMALL, total);
            put(SLOT_FNVMUL, ma);
            put(SLOT_FNVADD, mb);
            put(SLOT_HEAD, word8(BUF_SMALL));
            put(SLOT_SUM_FULL, byte_sum(BUF_SMALL, total));
            put(SLOT_EOF, eof);

            // ---- 24 seek：SET 50 → 读尾 50 → CUR +10 → END -20 → 越 EOF ----
            put(SLOT_SEEK50, sys3(SYS_FILE_SEEK, open, 50, 0));
            let (t2, _) = read_all(open, BUF_SMALL, 50);
            put(SLOT_READ50_TOTAL, t2);
            put(SLOT_TAIL_HEAD, word8(BUF_SMALL));
            put(SLOT_SUM_TAIL, byte_sum(BUF_SMALL, t2));
            // 尾段读到了 EOF，先回 50 再量 CUR，否则 CUR+10 落在 EOF 之外（实测 -1）。
            let _ = sys3(SYS_FILE_SEEK, open, 50, 0);
            put(SLOT_CUR60, sys3(SYS_FILE_SEEK, open, 10, 1));
            put(SLOT_END80, sys3(SYS_FILE_SEEK, open, (-20i64) as u64, 2));
            put(SLOT_SEEK_FAR, sys3(SYS_FILE_SEEK, open, 101, 0));

            // ---- 25 stat：出参是结构体，字段由用户侧按自己的偏移表解 ----
            put(SLOT_STAT, sys3(SYS_FILE_STAT, open, slots_base() + BUF_STAT, 48));
            put(SLOT_STAT_SIZE, get_u32(BUF_STAT + ST_SIZE_AT) as u64);
            put(SLOT_STAT_FIRST, get_u32(BUF_STAT + ST_FIRST_AT) as u64);
            put(SLOT_STAT_MAGIC, get_u32(BUF_STAT + ST_MAGIC_AT) as u64);
            put(SLOT_STAT_SHORT, sys3(SYS_FILE_STAT, open, slots_base() + BUF_STAT, 47));

            // ---- 22/26 打开根目录并 readdir 到 EOF ----
            set_path(0x0000_0000_0000_002f, 0); // "/"
            let dir = sys3(SYS_FILE_OPEN, slots_base() + BUF_PATH, 1, 0);
            put(SLOT_DIR, dir);
            if (dir as i64) >= 0 {
                let (recs, names, sizes) = read_dir_all(dir);
                put(SLOT_DIR_RECORDS, recs);
                put(SLOT_DIR_NAME_SUM, names);
                put(SLOT_DIR_SIZE_SUM, sizes);
                // read 目录 ⇒ -11；seek 目录 ⇒ -15。
                put(SLOT_READ_DIR, sys3(SYS_FILE_READ, dir, slots_base() + BUF_SMALL, 8));
                put(SLOT_DIR_SEEK, sys3(SYS_FILE_SEEK, dir, 0, 0));
                // 目录句柄也要还回去：不关就是"表清空"那一格的假红（实测 live=1）。
                put(SLOT_DIR_CLOSE, sys3(SYS_HANDLE_CLOSE, dir, 0, 0));
            }

            // ---- 失败格：相对路径、不存在、非零 flags ----
            set_path(0x4942_2e4c_4c41_4d53, 0x0000_0000_0000_004e); // "SMALL.BIN"
            put(SLOT_REL, sys3(SYS_FILE_OPEN, slots_base() + BUF_PATH, 9, 0));
            set_path(0x0000_0000_4550_4f4e_2f, 0); // "/NOPE"
            put(SLOT_MISSING, sys3(SYS_FILE_OPEN, slots_base() + BUF_PATH, 5, 0));
            set_path(0x422e_4c4c_414d_532f, 0x0000_0000_0000_4e49);
            put(SLOT_FLAGS, sys3(SYS_FILE_OPEN, slots_base() + BUF_PATH, 10, 1));

            // ---- 8 close，之后旧句柄必须 -5 ----
            put(SLOT_CLOSE, sys3(SYS_HANDLE_CLOSE, open, 0, 0));
            put(SLOT_STALE, sys3(SYS_FILE_READ, open, slots_base() + BUF_SMALL, 8));
        }
    }

    put(SLOT_DONE, DONE_VAL);
    loop {
        // SAFETY: 3 号只回不来（任务被摘下 CPU）；回得来就再打一次，不静默往下跑。
        let _ = unsafe { sys3(SYS_EXIT, 0, 0, 0) };
    }
}

/// 整个信箱页：结果格、缓冲、路径都在这里，偏移由上面那张表定。
/// 4096 字节 = 512 个 u64，正好独占一页：结果格在 0..256，缓冲从 512 起。
/// 类型选 `AtomicU64` 而不是 `UnsafeCell<u64>`：`static` 要 `Sync`（probe 那份信箱同一条理由），
/// 而实际的读写仍按上面那张偏移表走 volatile 指针，原子类型在这里只是让段的存在与对齐成立。
#[link_section = ".slots"]
static SLOTS: [core::sync::atomic::AtomicU64; 512] = [const { core::sync::atomic::AtomicU64::new(0) }; 512];
