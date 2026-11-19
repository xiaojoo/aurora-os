//! D4（ADR-154）：**应用 SDK 的第一个样板**。
//!
//! 这不是"空 SDK 骨架"——AGENTS 硬约束 2 禁止没有真实调用者的空 trait/空模块。
//! 这个程序是一个**真能跑起来的用户程序**，把"怎么写一个 Aurora 应用"写成可执行的
//! 样子，演示两件事：
//!
//! 1. **只经 `aurora-user-runtime` 调号**：本文件没有一处 `int 0x80`；
//! 2. **38/40 号读凭据并做授权判定**（C1 的凭据出口）——
//!    打印 `uid/gid/caps` 与一次 `CAP_DEV` 判定的结果（`allow`/`deny`）。
//!
//! 判据锚（ADR-154）：串口出现
//! `sdkdemo: uid=<n> gid=<n> caps=<n> dev=<allow|deny>`
//! ——四个数各自可核，`dev=` 是授权差异的直接读数。
//!
//! ## 两条硬纪律（都是踩出来的）
//!
//! 1. **提示串是一个 `static [u8; N]` + RIP 相对 `lea`**。字面量取址或
//!    `MSGS.get(..)` 的边界检查都会生成 `.rodata..Lanon`（24 字节 panic location），
//!    取址走 `R_X86_64_32S` ⇒ 4 GiB 基址下链接期 out of range（实测 rust-lld 崩）。
//! 2. **不用 `from_le_bytes([..])` / `get()` / 索引**：同一条，数组字面量与边界
//!    检查都会带出 panic location。全部改裸指针 + 手写移位。
//!
//! 这两条不是风格偏好，是这个镜像基址（`0x100000000`）下的硬约束。

#![no_std]
#![no_main]

use aurora_user_runtime as rt;

/// 提示串。布局（偏移/长度）由本文件下面的常量与 `tools/aurora.py` 的
/// 长度对账共同保证：
/// `0|9 "sdkdemo: "` · `9|4 "uid="` · `13|5 " gid="` · `18|6 " caps="`
/// · `24|5 " dev="` · `29|5 "allow"` · `34|4 "deny"` · `38|1 "\n"`
static MSGS: [u8; 39] = *b"sdkdemo: uid= gid= caps= dev=allowdeny\n";

const M_PFX_O: usize = 0;
const M_PFX_L: usize = 9;
const M_UID_O: usize = 9;
const M_UID_L: usize = 4;
const M_GID_O: usize = 13;
const M_GID_L: usize = 5;
const M_CAPS_O: usize = 18;
const M_CAPS_L: usize = 6;
const M_DEV_O: usize = 24;
const M_DEV_L: usize = 5;
const M_ALLOW_O: usize = 29;
const M_ALLOW_L: usize = 5;
const M_DENY_O: usize = 34;
const M_DENY_L: usize = 4;
const M_NL_O: usize = 38;
const M_NL_L: usize = 1;

/// 取 `MSGS` 基址。**必须 RIP 相对 `lea`**（见文件头的纪律 1）。
#[inline]
fn msgs_base() -> *const u8 {
    let p: *const u8;
    // SAFETY: `lea` 只做地址计算，不读内存；`MSGS` 是 'static 定长数组。
    unsafe {
        core::arch::asm!(
            "lea {0}, [rip + {1}]",
            out(reg) p,
            sym MSGS,
            options(nostack, preserves_flags, readonly)
        );
    }
    p
}

/// 写一段 blob 切片到控制台。**裸指针，不做边界检查**（见纪律 1）。
fn out(h: rt::Handle, off: usize, len: usize) {
    // SAFETY: `off + len <= MSGS.len()` 由本文件的常量保证（最大 38+1=39）；
    // `msgs_base()` 返回 'static 数组首字节。
    let s = unsafe { core::slice::from_raw_parts(msgs_base().add(off), len) };
    let _ = rt::console_write(h, s);
}

/// 把 `v` 的十进制写进 `buf`，返回字节数。**裸指针 + 手写除法**（见纪律 2）。
fn put_u32(buf: &mut [u8], mut v: u32) -> usize {
    if v == 0 {
        // SAFETY: 调用方给的是 `[u8; 10]`，第 0 字节可写。
        unsafe { core::ptr::write(buf.as_mut_ptr(), b'0') };
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut n = 0usize;
    while v > 0 && n < 10 {
        let d = (v % 10) as u8;
        // SAFETY: `n < 10`，`tmp` 是 10 字节。
        unsafe { core::ptr::write(tmp.as_mut_ptr().add(n), b'0' + d) };
        v /= 10;
        n += 1;
    }
    let mut k = 0usize;
    while k < n {
        // SAFETY: `n - 1 - k < 10`；`k < n <= 10` 而 `buf` 是 10 字节。
        let src = unsafe { core::ptr::read(tmp.as_ptr().add(n - 1 - k)) };
        unsafe { core::ptr::write(buf.as_mut_ptr().add(k), src) };
        k += 1;
    }
    n
}

/// **结果信箱**：内核用例按 `.slots` 段的哨兵魔数找到这块，读出六个 u64。
///
/// 为什么要有信箱：本程序**不假定自己有控制台句柄**（`spawn_user` 的第 3 参为 0
/// 时没有），所以"结果"必须走一条不依赖句柄的路。hello 也是这么做的
/// （`user/hello` 的 `Slots` 结构 + `.slots` 段），这是仓库里已验证过的形状。
///
/// **必须是"不可变 `static` + `#[link_section]`"**：`static mut` 加 `#[used]`
/// 实测不会进对象文件（`llvm-objdump -h` 里根本没有 `.slots`），于是链接脚本
/// 收不到、`data_va` 指不到魔数。写的时候用裸指针 `write_volatile`（与 hello 同一条）。
#[repr(C)]
struct Slots {
    magic: u64,
    uid: u64,
    gid: u64,
    caps: u64,
    dev: u64,
    consistent: u64,
    pad: [u64; 2],
}

#[link_section = ".slots"]
static SLOTS: Slots = Slots {
    // 哨兵：内核用例靠它确认"我以为的槽位地址"就是真的槽位地址
    magic: 0x5344_4B31,
    uid: u64::MAX,
    gid: u64::MAX,
    caps: 0,
    dev: 0,
    consistent: 0,
    pad: [0; 2],
};

#[no_mangle]
pub extern "C" fn _start(si_va: u64) -> ! {
    // 控制台句柄是**可选**的：有就打串口（便于人看），没有也不影响信箱。
    //
    // **`si_va == 0` 时必须跳过 `find_console`**：`spawn_user` 的第 3 参就是
    // 用户入口的第一个参数；传 0 表示"没有 StartupInfo 页"。而 `find_console(0)`
    // 会去读地址 0 ⇒ #PF，程序在写信箱之前就崩了。
    // 实测症状：信箱里所有槽都是**初值**（魔数恰好等于期望值、uid 恰好等于
    // `u64::MAX`），看起来像"写入没生效"，其实是**根本没跑到那一步**。
    // SAFETY: `si_va != 0` 时由内核映射并校验（user+只读），读取期间不会被解映射
    // ——与 shell 同一条契约。`si_va == 0` 时不解引用任何东西。
    let h = if si_va == 0 {
        None
    } else {
        unsafe { rt::find_console(si_va) }
    };

    if let Some(handle) = h {
        out(handle, M_PFX_O, M_PFX_L);
    }

    // ① 凭据（38 号）。没有凭据就打 4294967295（`u32::MAX`），不编一个 uid=0。
    let (uid, gid, caps) = match rt::cred_self() {
        Ok(rec) => {
            // SAFETY: 偏移 5/9/13 加 3 都远小于 28（`cred_self` 返回定长 28 字节）；
            // `rec` 是本栈帧里的数组，读期间有效。
            let rd = |off: usize| -> u32 {
                u32::from(unsafe { core::ptr::read_unaligned(rec.as_ptr().add(off)) })
            };
            let u = rd(5) | (rd(6) << 8) | (rd(7) << 16) | (rd(8) << 24);
            let g = rd(9) | (rd(10) << 8) | (rd(11) << 16) | (rd(12) << 24);
            let c = rd(13) | (rd(14) << 8) | (rd(15) << 16) | (rd(16) << 24);
            (u, g, c)
        }
        Err(_) => (u32::MAX, u32::MAX, 0),
    };

    // ② 授权判定（40 号）：问"我能枚举设备吗"。**拒绝不是错误**。
    let got_dev = rt::cred_allows(rt::CAP_DEV).unwrap_or(false);

    // ③ 写信箱（不依赖句柄）。
    //
    // SAFETY: `SLOTS` 是 'static 的定长结构（8 项 u64）；偏移都是常量且 < 8；
    // 单线程（本程序只有一个线程，内核只在它 exit 之后才读这块）。
    // 用 `write_volatile` 而不是 `static mut`：后者不进对象文件（见 `Slots` 的注释）。
    unsafe {
        let p = core::ptr::addr_of!(SLOTS) as *mut u64;
        core::ptr::write_volatile(p.add(1), u64::from(uid));
        core::ptr::write_volatile(p.add(2), u64::from(gid));
        core::ptr::write_volatile(p.add(3), u64::from(caps));
        core::ptr::write_volatile(p.add(4), u64::from(got_dev));
        let expect_dev = (caps & rt::CAP_DEV) == rt::CAP_DEV;
        // `consistent` 写 **1 表示自洽**。注意 `caps=0`（无凭据）时
        // `expect_dev=false`，而 `got_dev=false`，所以仍然自洽 ⇒ 1。
        let consistent: u64 = if got_dev == expect_dev { 1 } else { 0 };
        core::ptr::write_volatile(p.add(5), consistent);
        // 回读确认：`write_volatile` 之后 `read_volatile` 必须是刚才那个值。
        // 读不回来就把 `consistent` 写成 2（内核判据据此区分"写失败"与"不自洽"）。
        let back = core::ptr::read_volatile(p.add(5));
        if back != consistent {
            core::ptr::write_volatile(p.add(5), 2u64);
        }

    }

    // ④ 有句柄就顺便打一行（便于人读；判据不依赖它）。
    if let Some(handle) = h {
        let mut num = [0u8; 10];
        out(handle, M_UID_O, M_UID_L);
        let n = put_u32(&mut num, uid);
        let _ = rt::console_write(handle, unsafe {
            core::slice::from_raw_parts(num.as_ptr(), n)
        });
        out(handle, M_GID_O, M_GID_L);
        let n = put_u32(&mut num, gid);
        let _ = rt::console_write(handle, unsafe {
            core::slice::from_raw_parts(num.as_ptr(), n)
        });
        out(handle, M_CAPS_O, M_CAPS_L);
        let n = put_u32(&mut num, caps);
        let _ = rt::console_write(handle, unsafe {
            core::slice::from_raw_parts(num.as_ptr(), n)
        });
        out(handle, M_DEV_O, M_DEV_L);
        if got_dev {
            out(handle, M_ALLOW_O, M_ALLOW_L);
        } else {
            out(handle, M_DENY_O, M_DENY_L);
        }
        out(handle, M_NL_O, M_NL_L);
    }

    // 自洽检查失败就 exit(1)（内核用例另按信箱判，这个只做人读信号）。
    let expect_dev = (caps & rt::CAP_DEV) == rt::CAP_DEV;
    if got_dev != expect_dev {
        rt::exit(1);
    }
    rt::exit(0)
}

/// `no_std` panic 出口：直接 `exit(2)`。**不递归**。
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    rt::exit(2)
}
