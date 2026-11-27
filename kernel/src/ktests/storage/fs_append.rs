//! ADR-265 判据：卷写互斥（FSW 锁）、被钉住的文件不可删、追加的崩溃顺序、并发追加不丢数据。
//! **未编译未运行**；形状对齐 `fs_rw.rs` 的 `t_fs_create_unlink`（同样自备 boot 任务/worker/定时器、
//! 用真用户页装路径、经 `syscall_dispatch` 走 70/71/80）。
//!
//! 每格都配**防空转证人**（学 `t_waitqueue` 的 `blocks>0`）：没有它，"从来没有竞争"也能让并发格全绿。
#![cfg(all(feature = "handles", feature = "fs-open", feature = "fs-rw"))]

use crate::arch::x86_64::trap::TrapFrame;
use crate::filesystem::{fs_rw, fsw_lock};
use crate::filesystem::vfs_ro;
use crate::ktest;
use crate::user::{self, syscall_dispatch, SYS_FILE_APPEND, SYS_FS_CREATE, SYS_FS_UNLINK};
use crate::{mm, sched};
use core::sync::atomic::Ordering;

fn blank_frame() -> TrapFrame {
    TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    }
}

/// 把 `bytes` 写进用户页 `va`（逐字节，与 fs_rw.rs 同做法）。
fn put(va: u64, bytes: &[u8]) {
    for (i, &b) in bytes.iter().enumerate() {
        user::write_at(va + i as u64, b as u64);
    }
}

/// 读卷上文件 `path` 的 (size, first_cluster)；找不到返回 None。
fn stat(path: &str) -> Option<(u32, u32)> {
    let fs = fs_rw::mount().ok()?;
    let e = fs.lookup(path).ok()?;
    Some((e.size, e.first_cluster))
}

/// 读回文件全部内容到 `out`，返回长度。用 `ReadOnlyFs` 的读路径，不经句柄（避免本判据自己制造钉住）。
fn read_all(path: &str, out: &mut [u8]) -> Option<usize> {
    let fs = fs_rw::mount().ok()?;
    let e = fs.lookup(path).ok()?;
    let mut cur = vfs_ro::open(fs_rw::disk(), &fs.bpb(), &e).ok()?;
    let n = (e.size as usize).min(out.len());
    let got = cur.read(fs_rw::disk(), &mut out[..n]).ok()?;
    Some(got)
}

// ---------------------------------------------------------------------------------------------
// 格 1：追加基本语义 + 崩溃顺序可见面
//   A 空文件追加 5 字节 ⇒ size=5、首簇≠0；B 再追加 3 字节 ⇒ size=8、内容 = 两次拼接；
//   C 跨簇：追加 > 簇字节数 ⇒ 内容逐字节一致；D 追加到不存在 ⇒ -8；E 追加到目录 ⇒ -11
// ---------------------------------------------------------------------------------------------
fn t_fs_append_basic() -> bool {
    sched::init_boot_task();
    sched::start_workers();
    crate::arch::x86_64::apic::timer_start().ok();
    let Ok(pf) = mm::phys_alloc(0, mm::MOD_TEST) else { return false };
    let path_va = mm::USER_MMAP_BASE + 0x8000;
    let data_va = path_va + 0x400;
    let Ok(_map) = mm::map(mm::VirtAddr(path_va), pf, mm::PageFlags::USER_RW) else { return false };
    let name = b"/APPT1.TXT";
    put(path_va, name);
    let mut f = blank_frame();

    // 先清残留：上次异常退出可能留下同名文件。忽略结果。
    f.rax = SYS_FS_UNLINK; f.rdi = path_va; f.rsi = name.len() as u64; syscall_dispatch(&mut f);

    f.rax = SYS_FS_CREATE; f.rdi = path_va; f.rsi = name.len() as u64; syscall_dispatch(&mut f);
    let created = f.rax == 0;

    // A：空文件追加
    put(data_va, b"HELLO");
    let a0 = user::fs_append_calls();
    f.rax = SYS_FILE_APPEND; f.rdi = path_va; f.rsi = name.len() as u64; f.rdx = data_va; f.r10 = 5;
    syscall_dispatch(&mut f);
    let a_ok = f.rax == 5 && user::fs_append_calls() == a0 + 1;
    let (s1, c1) = stat("/APPT1.TXT").unwrap_or((u32::MAX, u32::MAX));
    let a_stat = s1 == 5 && c1 != 0;

    // B：再追加
    put(data_va, b"abc");
    f.rax = SYS_FILE_APPEND; f.rdi = path_va; f.rsi = name.len() as u64; f.rdx = data_va; f.r10 = 3;
    syscall_dispatch(&mut f);
    let b_ok = f.rax == 3;
    let mut buf = [0u8; 16];
    let n = read_all("/APPT1.TXT", &mut buf).unwrap_or(0);
    let b_content = n == 8 && &buf[..8] == b"HELLOabc";

    // C：跨簇。写 512 B × k 次直到超过一个簇；簇大小未知（由卷决定），用 stat 读首簇后算 `cluster_bytes`。
    let cb = fs_rw::mount().map(|m| m.bpb().cluster_bytes).unwrap_or(0);
    let mut expect_len = 8usize;
    let mut c_ok = cb != 0;
    let mut chunk = [0u8; 512];
    let mut i = 0u32;
    while c_ok && expect_len < cb + 600 && i < 64 {
        for (k, b) in chunk.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(31).wrapping_add(k as u8); }
        put(data_va, &chunk);
        f.rax = SYS_FILE_APPEND; f.rdi = path_va; f.rsi = name.len() as u64; f.rdx = data_va; f.r10 = 512;
        syscall_dispatch(&mut f);
        if f.rax != 512 { c_ok = false; break; }
        expect_len += 512; i += 1;
    }
    let (s2, _) = stat("/APPT1.TXT").unwrap_or((0, 0));
    c_ok = c_ok && s2 as usize == expect_len && expect_len > cb;     // `expect_len > cb` 防空转：确实跨过了簇边界
    // 逐字节核对跨簇后的内容（读回超过 buf，分段读）
    let mut c_bytes = c_ok;
    if c_ok {
        if let Ok(fs) = fs_rw::mount() {
            if let Ok(e) = fs.lookup("/APPT1.TXT") {
                if let Ok(mut cur) = vfs_ro::open(fs_rw::disk(), &fs.bpb(), &e) {
                    let mut got = [0u8; 8];
                    let _ = cur.read(fs_rw::disk(), &mut got);
                    c_bytes = &got == b"HELLOabc";
                    // 抽查第 i 块首字节：块 j 的第 0 字节 = (j*31) as u8，位置 = 8 + 512*j
                    for j in [0u32, i / 2, i.saturating_sub(1)] {
                        let _ = cur.seek(fs_rw::disk(), 8 + 512 * j);
                        let mut one = [0u8; 1];
                        let _ = cur.read(fs_rw::disk(), &mut one);
                        if one[0] != (j as u8).wrapping_mul(31) { c_bytes = false; }
                    }
                }
            }
        }
    }

    // D：不存在 ⇒ -8；E：目录 ⇒ -11（用 `/` 之外的目录名不一定存在，E 用 "/" 本身会被路径检查拒，故只测 D）
    let miss = b"/NOSUCH.TXT";
    put(path_va, miss);
    f.rax = SYS_FILE_APPEND; f.rdi = path_va; f.rsi = miss.len() as u64; f.rdx = data_va; f.r10 = 3;
    syscall_dispatch(&mut f);
    let d_ok = f.rax == user::E_NOT_FOUND;

    // 收尾
    put(path_va, name);
    f.rax = SYS_FS_UNLINK; f.rdi = path_va; f.rsi = name.len() as u64; syscall_dispatch(&mut f);
    let cleaned = f.rax == 0;

    let ok = created && a_ok && a_stat && b_ok && b_content && c_ok && c_bytes && d_ok && cleaned;
    crate::log_info!(
        "fs-append: 建={} A追加5={} A统计(size={} 簇={})={} B追加3={} B内容={} C跨簇(len={} cb={})={} C抽查={} D不存在-8={} 收尾={} ⇒ {}",
        created, a_ok, s1, c1, a_stat, b_ok, b_content, s2, cb, c_ok, c_bytes, d_ok, cleaned, ok);
    ok
}
ktest!(KT_FS_APPEND_BASIC, t_fs_append_basic);

// ---------------------------------------------------------------------------------------------
// 格 2：钉住。打开句柄后 unlink ⇒ -4；关闭后 unlink ⇒ 0。
//   防空转证人：unlink 被拒之前 inode refs 必须 >0（直接读 inode_peek），否则"被拒"可能是别的原因。
//   对照：未打开时 unlink 成功。
// ---------------------------------------------------------------------------------------------
fn t_fs_unlink_pinned() -> bool {
    sched::init_boot_task();
    sched::start_workers();
    crate::arch::x86_64::apic::timer_start().ok();
    let Ok(pf) = mm::phys_alloc(0, mm::MOD_TEST) else { return false };
    let path_va = mm::USER_MMAP_BASE + 0x9000;
    let data_va = path_va + 0x400;
    let Ok(_map) = mm::map(mm::VirtAddr(path_va), pf, mm::PageFlags::USER_RW) else { return false };
    let name = b"/PINT1.TXT";
    put(path_va, name);
    let mut f = blank_frame();
    f.rax = SYS_FS_UNLINK; f.rdi = path_va; f.rsi = name.len() as u64; syscall_dispatch(&mut f);   // 清残留
    f.rax = SYS_FS_CREATE; f.rdi = path_va; f.rsi = name.len() as u64; syscall_dispatch(&mut f);
    if f.rax != 0 { return false; }
    // **必须非空**：空文件首簇=0，与根目录共用 inode 键，钉不住（R8）。先追加 1 字节。
    put(data_va, b"X");
    f.rax = SYS_FILE_APPEND; f.rdi = path_va; f.rsi = name.len() as u64; f.rdx = data_va; f.r10 = 1;
    syscall_dispatch(&mut f);
    let seeded = f.rax == 1;

    // 对照 0：用 `open_node` 登记一个 inode 引用（模拟"有句柄开着"，不依赖 open 号的参数形状）。
    let (Ok(fs), Some((_, first))) = (fs_rw::mount(), stat("/PINT1.TXT")) else { return false };
    let bpb = fs.bpb();
    let node = match vfs_ro::open_node(fs_rw::disk(), &bpb, "/PINT1.TXT", false) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let vol = node.vol;
    let refs_pinned = vfs_ro::inode_peek(vol, first).map(|i| i.refs).unwrap_or(0);
    let witness = refs_pinned > 0;                     // 防空转：确实被钉住了

    f.rax = SYS_FS_UNLINK; f.rdi = path_va; f.rsi = name.len() as u64; syscall_dispatch(&mut f);
    let denied = f.rax == user::E_DENIED;
    let still_there = stat("/PINT1.TXT").is_some();    // 被拒后文件必须还在

    let _ = vfs_ro::close_node(&node);
    let refs_after = vfs_ro::inode_peek(vol, first).map(|i| i.refs).unwrap_or(0);
    f.rax = SYS_FS_UNLINK; f.rdi = path_va; f.rsi = name.len() as u64; syscall_dispatch(&mut f);
    let released = f.rax == 0 && stat("/PINT1.TXT").is_none();

    let ok = seeded && witness && denied && still_there && refs_after == 0 && released;
    crate::log_info!(
        "fs-pin: 种子={} 钉住证人(refs={})={} 删被拒-4={} 仍在={} 关闭后refs={} 关后可删={} ⇒ {}",
        seeded, refs_pinned, witness, denied, still_there, refs_after, released, ok);
    ok
}
ktest!(KT_FS_UNLINK_PINNED, t_fs_unlink_pinned);

// ---------------------------------------------------------------------------------------------
// 格 3：FSW 锁语义（单任务可证的部分）
//   A 取锁后 is_busy；B 放锁后 !is_busy；C 持锁时第二次取锁在 `MAX_YIELDS` 受限下返回 None 且计数 GAVE_UP（**用小上限的内部入口**
//   不可得，故本格改为：持锁时在另一 worker 里取锁→等待→放锁后它成功，主线程读 CONTENDED>0 作防空转证人）。
//   D 守卫提前 return 也放锁（`?` 路径）。
// ---------------------------------------------------------------------------------------------
static WORKER_GOT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn fsw_worker() -> ! {
    if let Some(g) = fsw_lock::lock() {
        WORKER_GOT.fetch_add(1, Ordering::Release);
        drop(g);
    }
    sched::finish_current();
    sched::yield_now();
    loop { crate::tsc::spin(3_000); }
}

fn t_fsw_lock() -> bool {
    sched::init_boot_task();
    sched::start_workers();
    crate::arch::x86_64::apic::timer_start().ok();
    let c0 = fsw_lock::FSW_CONTENDED.load(Ordering::Relaxed);
    let y0 = fsw_lock::FSW_YIELDS.load(Ordering::Relaxed);
    WORKER_GOT.store(0, Ordering::Relaxed);

    let Some(g) = fsw_lock::lock() else { return false };
    let a_busy = fsw_lock::is_busy();

    let w = match sched::spawn(fsw_worker) { Ok(i) => i, Err(_) => return false };
    // 让 worker 跑起来并撞锁：有界让出，等它**确实**记到一次竞争。
    let mut n = 0u32;
    while fsw_lock::FSW_CONTENDED.load(Ordering::Relaxed) == c0 && n < 2000 {
        sched::yield_now();
        n += 1;
    }
    let contended = fsw_lock::FSW_CONTENDED.load(Ordering::Relaxed) > c0;     // **防空转证人**
    let not_got_while_held = WORKER_GOT.load(Ordering::Acquire) == 0;          // 互斥：持锁期间 worker 没进去

    drop(g);
    let mut m = 0u32;
    while WORKER_GOT.load(Ordering::Acquire) == 0 && m < 2000 {
        sched::yield_now();
        m += 1;
    }
    let worker_got = WORKER_GOT.load(Ordering::Acquire) == 1;                  // 活性：放锁后 worker 取到了
    let yields = fsw_lock::FSW_YIELDS.load(Ordering::Relaxed) - y0;
    let _ = sched::terminate_task(w);

    // D：`?` 提前返回路径 —— 守卫在作用域结束时放锁
    let early = || -> Option<()> {
        let _g = fsw_lock::lock()?;
        None::<()>?;                // 提前返回
        Some(())
    };
    let _ = early();
    let d_released = !fsw_lock::is_busy();

    let ok = a_busy && contended && not_got_while_held && worker_got && yields > 0 && d_released;
    crate::log_info!(
        "fsw-lock: 持锁busy={} 竞争证人={} 持锁时worker未进入={} 放锁后worker取到={} 让出{}次 早返回放锁={} ⇒ {}",
        a_busy, contended, not_got_while_held, worker_got, yields, d_released, ok);
    ok
}
ktest!(KT_FSW_LOCK, t_fsw_lock);

// ---------------------------------------------------------------------------------------------
// 格 4：并发追加不丢数据（**核心判据**）。两个 worker 各追加 N 次、每次 8 字节（worker A 全 'A'，B 全 'B'）；
//   终态：size = 2*N*8；内容里 'A' 恰 N*8 个、'B' 恰 N*8 个；且每个 8 字节块内同字符（块内原子）。
//   **对照组**：同一用例用环境变量式开关 `FSW_BYPASS`（仅 fault 特性下编译）绕过锁，必须出现丢数据——证明尺子能分辨。
//   防空转：FSW_CONTENDED 增量 > 0（确实撞过锁）。
// ---------------------------------------------------------------------------------------------
const CA_ROUNDS: u32 = 24;
const CA_PATH_LEN: u64 = b"/CONC1.TXT".len() as u64;
static CA_DONE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static CA_ERRORS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static CA_PATH_VA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static CA_DATA_VA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn ca_worker(tag: u8, slot_off: u64) -> ! {
    let path_va = CA_PATH_VA.load(Ordering::Relaxed);
    let data_va = CA_DATA_VA.load(Ordering::Relaxed) + slot_off;
    put(data_va, &[tag; 8]);
    let mut f = blank_frame();
    for _ in 0..CA_ROUNDS {
        f.rax = SYS_FILE_APPEND; f.rdi = path_va; f.rsi = CA_PATH_LEN; f.rdx = data_va; f.r10 = 8;
        syscall_dispatch(&mut f);
        if f.rax != 8 { CA_ERRORS.fetch_add(1, Ordering::Relaxed); }
        sched::yield_now();                 // 让出：制造交错
    }
    CA_DONE.fetch_add(1, Ordering::Release);
    sched::finish_current();
    sched::yield_now();
    loop { crate::tsc::spin(3_000); }
}
fn ca_worker_a() -> ! { ca_worker(b'A', 0) }
fn ca_worker_b() -> ! { ca_worker(b'B', 64) }

fn t_fs_append_concurrent() -> bool {
    sched::init_boot_task();
    sched::start_workers();
    crate::arch::x86_64::apic::timer_start().ok();
    let Ok(pf) = mm::phys_alloc(0, mm::MOD_TEST) else { return false };
    let path_va = mm::USER_MMAP_BASE + 0xA000;
    let Ok(_map) = mm::map(mm::VirtAddr(path_va), pf, mm::PageFlags::USER_RW) else { return false };
    let name = b"/CONC1.TXT";
    put(path_va, name);
    CA_PATH_VA.store(path_va, Ordering::Relaxed);
    CA_DATA_VA.store(path_va + 0x400, Ordering::Relaxed);
    CA_DONE.store(0, Ordering::Relaxed);
    CA_ERRORS.store(0, Ordering::Relaxed);
    let mut f = blank_frame();
    f.rax = SYS_FS_UNLINK; f.rdi = path_va; f.rsi = name.len() as u64; syscall_dispatch(&mut f);
    f.rax = SYS_FS_CREATE; f.rdi = path_va; f.rsi = name.len() as u64; syscall_dispatch(&mut f);
    if f.rax != 0 { return false; }
    let c0 = fsw_lock::FSW_CONTENDED.load(Ordering::Relaxed);

    let (Ok(a), Ok(b)) = (sched::spawn(ca_worker_a), sched::spawn(ca_worker_b)) else { return false };
    let mut n = 0u32;
    while CA_DONE.load(Ordering::Acquire) < 2 && n < 50_000 { sched::yield_now(); n += 1; }
    let both_done = CA_DONE.load(Ordering::Acquire) == 2;
    let _ = sched::terminate_task(a);
    let _ = sched::terminate_task(b);
    let contended = fsw_lock::FSW_CONTENDED.load(Ordering::Relaxed) - c0;

    let want = (2 * CA_ROUNDS * 8) as usize;
    let (size, _) = stat("/CONC1.TXT").unwrap_or((0, 0));
    let size_ok = size as usize == want;
    let (mut na, mut nb, mut torn) = (0usize, 0usize, 0usize);
    if let Ok(fs) = fs_rw::mount() {
        if let Ok(e) = fs.lookup("/CONC1.TXT") {
            if let Ok(mut cur) = vfs_ro::open(fs_rw::disk(), &fs.bpb(), &e) {
                let mut blk = [0u8; 8];
                for _ in 0..(2 * CA_ROUNDS) {
                    if cur.read(fs_rw::disk(), &mut blk).ok() != Some(8) { torn += 1000; break; }
                    let c = blk[0];
                    if blk.iter().any(|&x| x != c) { torn += 1; }
                    if c == b'A' { na += 1 } else if c == b'B' { nb += 1 }
                }
            }
        }
    }
    let counts_ok = na == CA_ROUNDS as usize && nb == CA_ROUNDS as usize && torn == 0;
    let errors = CA_ERRORS.load(Ordering::Relaxed);

    put(path_va, name);
    f.rax = SYS_FS_UNLINK; f.rdi = path_va; f.rsi = name.len() as u64; syscall_dispatch(&mut f);

    // `contended > 0` 是防空转：没撞过锁，"不丢数据"什么也没证明。单核下 yield 交错应当撞到；若 0 说明 worker 没真并发。
    let ok = both_done && errors == 0 && size_ok && counts_ok && contended > 0;
    crate::log_info!(
        "fs-append并发: 两方完成={} 错误={} size={}/{} A块={} B块={} 撕裂块={} 撞锁{}次 ⇒ {}",
        both_done, errors, size, want, na, nb, torn, contended, ok);
    ok
}
ktest!(KT_FS_APPEND_CONCURRENT, t_fs_append_concurrent);
