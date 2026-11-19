//! FS-03：22/24/25/26 与 VFS 句柄对象的 syscall 取证用例（ADR-108）。
//!
//! 这个文件把三条链分开证明：
//! 1 `fs_open` 直接解析卷A得到的字节/目录项，是 ABI 的**被测物**；
//! 2 `syscall_dispatch` 经用户页走 22/10/24/25/26/8，是 ABI 的**形状**；
//! 3 失败路径（坏指针、类型错、越 EOF、表满、旧句柄）必须点名且不提交游标。
//!
//! 宿主机那台独立 FAT 仪器不在本文件里判内容对错；它接在后续判定表行上。

use crate::arch::x86_64::trap::TrapFrame;
use crate::filesystem::fs_open;
use crate::filesystem::vfs::AhciDisk;
use crate::filesystem::vfs_ro::{self, ReadOnlyFs, VfsError};
use crate::handle::{self, Handle, MAX_HANDLES, RIGHT_READ};
use crate::{ahci, ktest, mm, sched, user};
use crate::ktests::common::{call, frame0, get_user, put_user};

const SMALL: &[u8] = b"/SMALL.BIN";
const ROOT: &[u8] = b"/";
// ---- ADR-109 多级真卷上的路径：三级文件、中间层目录、跨簇目录与它的两种叫法 ----
const NESTED: &[u8] = b"/PROJECT/DOCS/NESTED.TXT";
const PROJ: &[u8] = b"/PROJECT";
const DOCS: &[u8] = b"/PROJECT/DOCS";
const ALIAS: &[u8] = b"/PROJECT/DOCS/AURORA~1.TXT";
const LONGPATH: &[u8] = b"/PROJECT/DOCS/AuroraLongDocument.txt";
const NOTDIR: &[u8] = b"/SMALL.BIN/X";
const DOT: &[u8] = b"/./PROJECT";
// `MAX_COMPONENTS = 16` 的两侧：16 个组件要能解开，17 个必须在第 17 次查找之前被拒。
// 夹具里那条 `/D1/…/D16` 是**真深链**（16 层目录各占一簇），不是字符串凑出来的。
const DEPTH16: &[u8] = b"/D1/D2/D3/D4/D5/D6/D7/D8/D9/D10/D11/D12/D13/D14/D15/D16";
const DEPTH17: &[u8] = b"/D1/D2/D3/D4/D5/D6/D7/D8/D9/D10/D11/D12/D13/D14/D15/D16/F.TXT";
const DATA_OFF: usize = 256;
// DirentV1 一条就 512 字节，与文件缓冲、路径字符串错开页内偏移：三样东西共用这一页。
const REC_OFF: usize = 768;

fn u16_le(b: &[u8], off: usize) -> u16 {
    (b[off] as u16) | ((b[off + 1] as u16) << 8)
}

fn u32_le(b: &[u8], off: usize) -> u32 {
    (b[off] as u32) | ((b[off + 1] as u32) << 8) | ((b[off + 2] as u32) << 16) | ((b[off + 3] as u32) << 24)
}

fn open_path(fr: &mut TrapFrame, va: u64, path: &[u8]) -> Result<Handle, u64> {
    if !put_user(va, 0, path) {
        return Err(user::E_FAULT);
    }
    let r = call(fr, user::SYS_FILE_OPEN, va, path.len() as u64, 0);
    if (r as i64) < 0 {
        Err(r)
    } else {
        Ok(Handle(r))
    }
}

fn read_to_user(fr: &mut TrapFrame, h: Handle, va: u64, off: usize, len: usize) -> u64 {
    call(fr, user::SYS_FILE_READ, h.0, va + off as u64, len as u64)
}

fn fail(name: &str, got: u64, want: u64) -> bool {
    if got != want {
        crate::log_fatal!("fs-open: 不成立 {} got={} want={}", name, got, want);
        return false;
    }
    true
}

fn t_fs_open_syscalls() -> bool {
    if ahci::init().is_err() {
        crate::log_fatal!("fs-open: AHCI 未认领");
        return false;
    }
    sched::init_boot_task();
    let Some(ident) = sched::current_identity() else {
        crate::log_fatal!("fs-open: 没有当前任务身份");
        return false;
    };
    handle::reset_for_test();
    handle::reset_counters_for_test();

    // 被测物：直接走 VFS，拿到字节与目录项。
    let disk = AhciDisk { port: fs_open::PORT };
    let fs = match ReadOnlyFs::mount(&disk) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("fs-open: 卷A 挂载被拒 {:?}", e);
            return false;
        }
    };
    let small = match fs.lookup("/SMALL.BIN") {
        Ok(e) => e,
        Err(e) => {
            crate::log_fatal!("fs-open: 直接查 SMALL.BIN 被拒 {:?}", e);
            return false;
        }
    };
    if small.size != 100 || small.is_dir() {
        crate::log_fatal!("fs-open: 夹具 SMALL.BIN 形状变了 size={}", small.size);
        return false;
    }
    let mut direct_cursor = match fs.open(&small) {
        Ok(c) => c,
        Err(e) => {
            crate::log_fatal!("fs-open: 直接打开 SMALL.BIN 被拒 {:?}", e);
            return false;
        }
    };
    let mut direct = [0u8; 100];
    if fs.read(&mut direct_cursor, &mut direct) != Ok(100) {
        crate::log_fatal!("fs-open: 直接读 SMALL.BIN 不是 100 字节");
        return false;
    }
    // 下层 `seek_disk` 自己必须拦越 EOF；不能只靠 syscall 在外面查，否则这格是空转。
    let mut lower_seek = match fs.open(&small) {
        Ok(c) => c,
        Err(e) => {
            crate::log_fatal!("fs-open: 下层 seek 游标打开失败 {:?}", e);
            return false;
        }
    };
    let lower_eof_ok = matches!(
        vfs_ro::seek_disk(&disk, &mut lower_seek, 101),
        Err(VfsError::BadOffset)
    );
    if !lower_eof_ok {
        crate::log_fatal!("fs-open: 下层 seek 越 EOF 没被拒");
        return false;
    }

    syscall_cells(&fs, &small, &direct)
}

/// 22/10/24/25/26/8 这串**形状判据**：真用户页 + 真 `syscall_dispatch`。
///
/// **`#[inline(never)]` 是栈预算，不是风格**：ktest 跑在 16 KiB 的内核任务栈上，而
/// `vfs_ro::lookup` 单帧实测 4,568 字节（内联的 `find_child` 带着 1.2 KiB 的 `DirCursor`）。
/// 把两条 512 字节的 dirent、两份 100 字节缓冲和二十来个 `log` 的临时量摊进用例自己的帧，
/// 用例帧与 `lookup` 帧就叠在同一处峰值上；拆出来之后这一段只剩几份 `Entry`。
/// （本轮先撞到的 HANG 是 ring3 那条链，见 BACKLOG §335 与 `sched::USER_KSTACK_PAGES`；
/// 这一格是同一笔栈预算在用例侧的收口。）
#[inline(never)]
fn syscall_cells(fs: &ReadOnlyFs<'_>, small: &vfs_ro::Entry, direct: &[u8; 100]) -> bool {
    let Some(ident) = sched::current_identity() else {
        crate::log_fatal!("fs-open: 没有当前任务身份");
        return false;
    };
    // 用户页：真实映射，路径/输出都通过 SMAP 窗口走。
    let Some(va) = mm::alloc_user_va_range(1) else {
        crate::log_fatal!("fs-open: 用户 VA 分配失败");
        return false;
    };
    let Ok(frames) = mm::phys_alloc(0, mm::MOD_TEST) else {
        crate::log_fatal!("fs-open: 用户页帧分配失败");
        return false;
    };
    let Ok(flags) = mm::PageFlags::new(true, false, true) else {
        crate::log_fatal!("fs-open: 页标志构造失败");
        return false;
    };
    let Ok(map) = mm::map(va, frames, flags) else {
        crate::log_fatal!("fs-open: 用户页映射失败");
        return false;
    };
    let mut fr = frame0();

    let h = match open_path(&mut fr, va.0, SMALL) {
        Ok(h) => h,
        Err(r) => return fail("open SMALL.BIN", r, 0) && false,
    };
    let mut ok = h.0 < (1u64 << 63);
    ok &= fail("open 返回句柄形状", (h.0 >> 63) as u64, 0);

    let n = read_to_user(&mut fr, h, va.0, DATA_OFF, 100);
    let mut got = [0u8; 100];
    let bytes_ok = n == 100 && get_user(va.0, DATA_OFF, &mut got) && got == *direct;
    ok &= fail("首次读字节数", n, 100);
    ok &= bytes_ok;
    let eof = read_to_user(&mut fr, h, va.0, DATA_OFF, 100);
    ok &= fail("EOF 后续读", eof, 0);

    let record_ret = call(&mut fr, user::SYS_FILE_STAT, h.0, va.0, 48);
    let mut record = [0u8; 48];
    let mut stat_ok = record_ret == 0 && get_user(va.0, 0, &mut record);
    stat_ok &= u32_le(&record, 0) == fs_open::STAT_MAGIC;
    stat_ok &= u16_le(&record, 4) == fs_open::STAT_RECORD_LEN;
    stat_ok &= record[6] == fs_open::STAT_VERSION;
    stat_ok &= record[7] == fs_open::STAT_KIND_FILE;
    stat_ok &= u32_le(&record, 8) == small.size;
    stat_ok &= record[12] == small.attr;
    stat_ok &= record[13] == small.name().len() as u8;
    stat_ok &= u16_le(&record, 14) == small.long_len() as u16;
    stat_ok &= u32_le(&record, 28) == small.lfn_bad;
    ok &= fail("stat 返回", record_ret, 0);
    ok &= stat_ok;

    let seek50 = call(&mut fr, user::SYS_FILE_SEEK, h.0, 50, 0);
    ok &= fail("seek SET 50", seek50, 50);
    let mid_n = read_to_user(&mut fr, h, va.0, DATA_OFF, 50);
    let mut mid = [0u8; 50];
    ok &= fail("seek 后读长度", mid_n, 50);
    ok &= mid_n == 50 && get_user(va.0, DATA_OFF, &mut mid) && mid[..] == direct[50..];
    let back50 = call(&mut fr, user::SYS_FILE_SEEK, h.0, 50, 0);
    ok &= fail("二次 seek SET 50", back50, 50);
    let cur10 = call(&mut fr, user::SYS_FILE_SEEK, h.0, 10, 1);
    ok &= fail("seek CUR +10", cur10, 60);
    let n10 = read_to_user(&mut fr, h, va.0, DATA_OFF, 10);
    ok &= fail("seek CUR 后读长度", n10, 10);
    let end_back = call(&mut fr, user::SYS_FILE_SEEK, h.0, (-20i64) as u64, 2);
    ok &= fail("seek END -20", end_back, 80);
    let too_far = call(&mut fr, user::SYS_FILE_SEEK, h.0, 101, 0);
    ok &= fail("seek 越 EOF", too_far, user::E_INVALID);
    let bad_whence = call(&mut fr, user::SYS_FILE_SEEK, h.0, 0, 3);
    ok &= fail("seek 非法 whence", bad_whence, user::E_INVALID);

    let dir = match open_path(&mut fr, va.0, ROOT) {
        Ok(h) => h,
        Err(r) => return fail("open 根目录", r, 0) && false,
    };
    let dir_seek = call(&mut fr, user::SYS_FILE_SEEK, dir.0, 0, 0);
    ok &= fail("目录 seek", dir_seek, user::E_NOT_SUPPORTED);

    // readdir 一次一条：第二次必须从提交后的游标继续，不能重复第一条。
    let r1 = call(&mut fr, user::SYS_DIR_READ, dir.0, va.0, 512);
    let mut d1 = [0u8; 512];
    let mut dir_ok = r1 == 1 && get_user(va.0, 0, &mut d1);
    dir_ok &= u32_le(&d1, 0) == fs_open::DIRENT_MAGIC;
    dir_ok &= u16_le(&d1, 4) == fs_open::DIRENT_RECORD_LEN;
    dir_ok &= d1[6] == fs_open::DIRENT_VERSION;
    dir_ok &= d1[8] > 0;
    ok &= fail("readdir 第一条", r1, 1);
    ok &= dir_ok;
    let r2 = call(&mut fr, user::SYS_DIR_READ, dir.0, va.0, 512);
    let mut d2 = [0u8; 512];
    let moved = r2 == 1 && get_user(va.0, 0, &mut d2)
        && d1[48..60] != d2[48..60]
        && u32_le(&d2, 36) > u32_le(&d1, 36);
    ok &= fail("readdir 第二条返回数", r2, 1);
    ok &= moved;

    let file_readdir = call(&mut fr, user::SYS_DIR_READ, h.0, va.0, 512);
    ok &= fail("文件 readdir", file_readdir, user::E_NOT_DIR);

    // 路径与权限形状。
    let len0 = call(&mut fr, user::SYS_FILE_OPEN, va.0, 0, 0);
    ok &= fail("open len 0", len0, user::E_INVALID);
    if put_user(va.0, 0, &SMALL[1..]) {
        let rel = call(&mut fr, user::SYS_FILE_OPEN, va.0, (SMALL.len() - 1) as u64, 0);
        ok &= fail("open 非绝对路径", rel, user::E_INVALID);
    } else {
        ok = false;
    }
    if put_user(va.0, 0, b"/NOPE") {
        let missing = call(&mut fr, user::SYS_FILE_OPEN, va.0, 5, 0);
        ok &= fail("open 不存在", missing, user::E_NOT_FOUND);
    } else {
        ok = false;
    }
    let long_len = call(&mut fr, user::SYS_FILE_OPEN, va.0, (vfs_ro::PATH_MAX + 1) as u64, 0);
    ok &= fail("open 路径过长", long_len, user::E_TOO_LONG);
    if put_user(va.0, 0, SMALL) {
        // bit0=写意图现在合法（fs-rw 档），这一格打的是**未知位**；2 在两档都必须 -15。
        let flags = call(&mut fr, user::SYS_FILE_OPEN, va.0, SMALL.len() as u64, 2);
        ok &= fail("open flags 未知位", flags, user::E_NOT_SUPPORTED);
    } else {
        ok = false;
    }

    // 坏指针不能推进游标：下一次合法读必须仍从当前未提交位置开始。
    let h2 = match open_path(&mut fr, va.0, SMALL) {
        Ok(h) => h,
        Err(r) => return fail("open for rollback", r, 0) && false,
    };
    let bad_ptr = call(&mut fr, user::SYS_FILE_READ, h2.0, 0, 100);
    ok &= fail("read 坏指针", bad_ptr, user::E_FAULT);
    let retry_n = read_to_user(&mut fr, h2, va.0, DATA_OFF, 100);
    let mut retry = [0u8; 100];
    ok &= fail("坏指针后重读长度", retry_n, 100);
    ok &= retry_n == 100 && get_user(va.0, DATA_OFF, &mut retry) && retry == *direct;

    let close_ret = call(&mut fr, user::SYS_HANDLE_CLOSE, h2.0, 0, 0);
    ok &= fail("close", close_ret, 0);
    let stale = read_to_user(&mut fr, h2, va.0, DATA_OFF, 1);
    ok &= fail("close 后用旧句柄", stale, user::E_BAD_HANDLE);

    ok &= nested_cells(&mut fr, va.0, fs);

    // 新对象容量：63 个直授 + 1 个 open 填满 64，第 65 个必须是 -6。
    handle::reset_for_test();
    handle::reset_counters_for_test();
    let fill_cursor = match fs.open(&small) {
        Ok(c) => c,
        Err(e) => {
            crate::log_fatal!("fs-open: 容量格重开游标失败 {:?}", e);
            return false;
        }
    };
    let mut filled = true;
    for _ in 0..MAX_HANDLES - 1 {
        if handle::grant_vfs_file(ident, fs_open::PORT, None, fill_cursor, *small, RIGHT_READ).is_err() {
            filled = false;
            break;
        }
    }
    ok &= filled;
    if put_user(va.0, 0, SMALL) {
        let last = call(&mut fr, user::SYS_FILE_OPEN, va.0, SMALL.len() as u64, 0);
        ok &= fail("第 64 格 open 成功", (last >> 63) as u64, 0);
        let overflow = call(&mut fr, user::SYS_FILE_OPEN, va.0, SMALL.len() as u64, 0);
        ok &= fail("第 65 格 open", overflow, user::E_EXHAUSTED);
    } else {
        ok = false;
    }

    let counters = handle::counters();
    // ABI 0.13（ADR-108 补记八）：写意图位只在 `fs-rw` 置位。
    let abi = user::abi_word();
    let abi_ok = abi & user::F_FS_OPEN != 0 && abi & user::F_FS_VERIFY_EXEC != 0
        && user::ABI_MINOR == 17
        && if cfg!(feature = "fs-rw") {
            abi & user::F_FS_WRITE_OPEN != 0 && abi & user::F_FS_WRITE_ROOT != 0
        } else {
            abi & user::F_FS_WRITE_OPEN == 0 && abi & user::F_FS_WRITE_ROOT == 0
        };
    ok &= abi_ok;
    handle::reset_for_test();
    drop(map);

    evidence_line(n, &got, &record, &d1, &d2);
    crate::log_info!(
        "fs-open: 判据={} direct={} bytes={} grants={} closes={} reads={} exhausted={}",
        ok,
        small.size,
        counters.bytes,
        counters.grants,
        counters.closes,
        counters.reads,
        counters.exhausted
    );
    ok
}

/// ADR-109 多级真卷的第一格取证：三级路径、跨簇目录、子目录 LFN 的两种叫法，
/// 以及「中间层是文件」与「`.` 不是路径语法糖」这两种拒绝。
///
/// FS-01/02/03 一直挂在卷A 上——那里只有根目录一层，`lookup` 的多级分支、「目录本身也要走簇链」、
/// 「三级文件的首簇高半非零」三件事从来没被真盘喂过（ADR-108 未决 1 记的就是这个缺口）。
/// 判的全是**没有算法的量**：条数、大小和、字节和、首 8 字节、以及「两种叫法读到同一份字节」。
#[inline(never)]
fn nested_cells(fr: &mut TrapFrame, va: u64, fs: &ReadOnlyFs<'_>) -> bool {
    let mut ok = true;
    let nested = match open_path(fr, va, NESTED) {
        Ok(h) => h,
        Err(r) => {
            crate::log_fatal!("fs-open: 三级 open 被拒 ret={}", r);
            return false;
        }
    };
    let n = read_to_user(fr, nested, va, DATA_OFF, expect::NESTED_BYTES as usize);
    let mut body = [0u8; 64];
    let mut h8 = [0u8; 8];
    let (head, sum) = if n == expect::NESTED_BYTES && get_user(va, DATA_OFF, &mut body) {
        h8.copy_from_slice(&body[..8]);
        (u64::from_le_bytes(h8), body.iter().fold(0u64, |a, b| a + u64::from(*b)))
    } else {
        ok = false;
        (0, 0)
    };
    ok &= fail("三级读回字节", n, expect::NESTED_BYTES);
    ok &= fail("三级首 8 字节", head, expect::NESTED_HEAD);
    ok &= fail("三级字节和", sum, expect::NESTED_SUM);
    let st = call(fr, user::SYS_FILE_STAT, nested.0, va, 48);
    let mut rec = [0u8; 48];
    ok &= fail("三级 stat 返回", st, 0);
    let (st_size, st_first) = if st == 0 && get_user(va, 0, &mut rec) {
        (u64::from(u32_le(&rec, 8)), u64::from(u32_le(&rec, 16)))
    } else {
        ok = false;
        (0, 0)
    };
    ok &= fail("三级 stat 大小", st_size, expect::NESTED_BYTES);
    // 这一格是整块卷存在的理由之一：65,600 的高半是 1，只拼低半会读到 64 号簇的字节。
    ok &= fail("三级 stat 首簇两半", st_first, expect::NESTED_FIRST);

    // 同一份字节的两种叫法：8.3 别名与长名必须打开**同一个对象**（读回的字节逐字节相同）。
    let alias = match open_path(fr, va, ALIAS) {
        Ok(h) => h,
        Err(r) => {
            crate::log_fatal!("fs-open: 短别名 open 被拒 ret={}", r);
            return false;
        }
    };
    let na = read_to_user(fr, alias, va, DATA_OFF, 48);
    let mut a_body = [0u8; 48];
    ok &= fail("别名读回字节", na, 48);
    ok &= na == 48 && get_user(va, DATA_OFF, &mut a_body);
    // 长名这一格**不早退**：那三条目录项正好落在 DOCS 的第二簇开头，是这块卷最难的一段。
    // 早退会把 readdir 的读数一起吞掉，红就只能看到「打不开」，看不到盘上到底有什么。
    let long_ret = open_ret(fr, va, LONGPATH);
    let mut long_same = 0u64;
    if (long_ret as i64) > 0 {
        let nl = read_to_user(fr, Handle(long_ret), va, DATA_OFF, 48);
        let mut l_body = [0u8; 48];
        if nl == 48 && get_user(va, DATA_OFF, &mut l_body) && l_body == a_body {
            long_same = expect::LONG_NAME_LEN;
        }
        ok &= fail("长名句柄归还", call(fr, user::SYS_HANDLE_CLOSE, long_ret, 0, 0), 0);
    }
    // 成功时 `long_ret` 是一枚句柄（不是 0）：判"没报错"只能看最高位，与 open 那一格同一条法。
    ok &= fail("子目录长名 open 不是错误", (long_ret >> 63) as u64, 0);
    // 「长名同字节」用长度当读数：0 = 没打开成或字节不同，22 = 两种叫法读到同一份 48 字节。
    ok &= fail("长名与别名字节相同", long_same, expect::LONG_NAME_LEN);

    // 目录侧：中间层一条、跨簇目录十七条（一次一条，逼着游标跨过扇区与簇的边界）。
    let Some((proj_recs, proj_sum, proj_long, _)) = walk_dir(fr, va, PROJ) else {
        return false;
    };
    let Some((docs_recs, docs_sum, long_count, long_sum)) = walk_dir(fr, va, DOCS) else {
        return false;
    };
    ok &= fail("中间层条目", proj_recs, expect::PROJ_RECORDS);
    ok &= fail("中间层大小和", proj_sum, 0);
    // 中间层只有一条 `DOCS` 且它没有长名：这一格把「长名条数 0」与「根本没读到这里」分开。
    ok &= fail("中间层长名条数", proj_long, 0);
    ok &= fail("跨簇目录条目", docs_recs, expect::DOCS_RECORDS);
    ok &= fail("跨簇目录大小和", docs_sum, expect::DOCS_SIZE_SUM);
    // 只有一条带长名，且 DirentV1 的长名字段就是那 22 个 UTF-8 字节（短名另有其格）。
    ok &= fail("跨簇目录长名条数", long_count, expect::LONG_COUNT);
    ok &= fail("跨簇目录长名字节和", long_sum, expect::LONG_NAME_SUM);

    // 底层单游标与 syscall 重放路径必须给同一个长名条数：不一致就是状态在重放里丢了。
    let (diag_recs, diag_long) = docs_diag(fs);
    ok &= fail("底层单游标条目", diag_recs, expect::DOCS_RECORDS);
    ok &= fail("底层单游标长名条数", diag_long, long_count);

    // 拒绝路径：中间层是文件 ⇒ -10；`.` 不当成语法糖 ⇒ -1。
    let notdir = open_ret(fr, va, NOTDIR);
    let dot = open_ret(fr, va, DOT);
    ok &= fail("open 中间层是文件", notdir, user::E_NOT_DIR);
    ok &= fail("open 带点号的路径", dot, user::E_INVALID);
    // `MAX_COMPONENTS = 16` 的两侧都用真深链喂：16 级是目录（返回不是错误），17 级是 -3。
    let depth16 = open_ret(fr, va, DEPTH16);
    let depth17 = open_ret(fr, va, DEPTH17);
    ok &= fail("open 16 级路径不是错误", (depth16 >> 63) as u64, 0);
    ok &= fail("open 17 级路径被拒", depth17, user::E_TOO_LONG);
    if (depth16 as i64) > 0 {
        ok &= fail("16 级目录句柄归还", call(fr, user::SYS_HANDLE_CLOSE, depth16, 0, 0), 0);
    }

    for h in [nested, alias] {
        ok &= fail("多级句柄归还", call(fr, user::SYS_HANDLE_CLOSE, h.0, 0, 0), 0);
    }
    nested_evidence(head, sum, st_first, docs_recs, docs_sum, long_count, long_sum,
                    notdir, dot, proj_recs, long_same, depth16, depth17);
    ok
}

/// 失败路径用的 open：返回原始返回值（负数本身就是判据，不转成 `Handle`）。
fn open_ret(fr: &mut TrapFrame, va: u64, path: &[u8]) -> u64 {
    if !put_user(va, 0, path) {
        return user::E_FAULT;
    }
    call(fr, user::SYS_FILE_OPEN, va, path.len() as u64, 0)
}

/// 打开目录、`readdir` 一次一条到 EOF，累计（条数, 声明大小和, 长名条数, 长名字节和）。
///
/// 一次只取一条是刻意的：512 字节的记录缓冲装不下整个 DOCS 目录，而这条链必须跨过
/// 「第一簇最后一项 / 第二簇第一项」那个边界——一次读到底的实现永远碰不到它。
///
/// 长名读的是 DirentV1 的**长名字段**（长度在偏移 10，内容在偏移 64），不是名字字段：
/// 名字字段按 ABI 就是 8.3 短名，拿它当「有没有长名」会把这一格读成永真。
#[inline(never)]
fn walk_dir(fr: &mut TrapFrame, va: u64, path: &[u8]) -> Option<(u64, u64, u64, u64)> {
    let h = match open_path(fr, va, path) {
        Ok(h) => h,
        Err(r) => {
            crate::log_fatal!("fs-open: 目录 open 被拒 ret={}", r);
            return None;
        }
    };
    let (mut recs, mut size_sum, mut long_count, mut long_sum) = (0u64, 0u64, 0u64, 0u64);
    loop {
        let n = call(fr, user::SYS_DIR_READ, h.0, va + REC_OFF as u64, 512);
        if (n as i64) <= 0 || recs >= 64 {
            break;
        }
        recs += 1;
        let mut head = [0u8; 64];
        if !get_user(va, REC_OFF, &mut head) {
            crate::log_fatal!("fs-open: 目录记录头读不回");
            return None;
        }
        size_sum += u64::from(u32_le(&head, 16));
        let long_len = u64::from(u16_le(&head, 10));
        if long_len > 0 {
            long_count += 1;
            let take = long_len.min(48) as usize;
            let mut name = [0u8; 48];
            if !get_user(va, REC_OFF + 64, &mut name[..take]) {
                crate::log_fatal!("fs-open: 目录长名读不回");
                return None;
            }
            long_sum += name[..take].iter().fold(0u64, |a, b| a + u64::from(*b));
        }
    }
    if call(fr, user::SYS_HANDLE_CLOSE, h.0, 0, 0) != 0 {
        crate::log_fatal!("fs-open: 目录句柄没还回去");
        return None;
    }
    Some((recs, size_sum, long_count, long_sum))
}

/// 诊断：同一个 DOCS 目录，用**一个底层游标**走到底，返回（条数, 带长名的条数）。
///
/// 两条路的差别是 `DirState::advance` 每次重放都新建 `DirCursor`——长名的组装状态
/// （`lfn_active`/`lfn_units`）活在一个游标里，所以「跨扇区那组 LFN 挂得上吗」在两条路上
/// 可以给出相反的答案。这一格把两边同时打出来，红了才分得清是谁的锅。
///
/// 它也是本轮抓住夹具造假的那一格：盘上长名按物理顺序拼只有 9 个字符，
/// 按**序号**落位才是 22 个（BACKLOG §342）。
#[inline(never)]
fn docs_diag(fs: &ReadOnlyFs<'_>) -> (u64, u64) {
    let de = match fs.lookup("/PROJECT/DOCS") {
        Ok(e) => e,
        Err(err) => {
            crate::log_fatal!("fs-open: 诊断 lookup DOCS 被拒 {:?}", err);
            return (0, 0);
        }
    };
    let mut cur = match fs.dir_cursor(&de) {
        Ok(c) => c,
        Err(err) => {
            crate::log_fatal!("fs-open: 诊断 dir_cursor DOCS 被拒 {:?}", err);
            return (0, 0);
        }
    };
    let (mut n, mut with_long) = (0u64, 0u64);
    loop {
        match fs.next_entry(&mut cur) {
            Ok(None) => break,
            Err(err) => {
                crate::log_fatal!("fs-open: 诊断 next_entry 出错 {:?}（已走 {} 条）", err, n);
                return (n, with_long);
            }
            Ok(Some(e)) => {
                n += 1;
                if e.long_len() > 0 {
                    with_long += 1;
                }
            }
        }
    }
    crate::log_info!(
        "fs-open: 诊断 docs单游标 条目={} 带长名={} lfn条目={} lfn坏={} 扫过={}",
        n, with_long, cur.lfn_entries(), cur.lfn_bad(), cur.entries_seen());
    (n, with_long)
}

/// 多级那一段的对账读数：全部来自 syscall 路径（22/10/25/26/8），宿主机按同一份盘独立重算。
///
/// **`#[inline(never)]` 是栈预算**，与 `evidence_line` 同一条理由（`vfs_ro::lookup` 单帧 4,568 字节）。
#[inline(never)]
fn nested_evidence(head: u64, sum: u64, first: u64, docs_recs: u64, docs_sum: u64,
                   long_count: u64, long_sum: u64, notdir: u64, dot: u64, proj_recs: u64,
                   long_len: u64, depth16: u64, depth17: u64) {
    crate::log_info!(
        "fs-open: 多级取证 首8={:#x} 和={} 首簇={} proj条目={} docs条目={} docs大小和={} 长名条数={} 长名和={} 长名同字节={} 非目录={} 点路径={} 16级={} 17级={}",
        head, sum, first, proj_recs, docs_recs, docs_sum, long_count, long_sum, long_len,
        notdir as i64, dot as i64, (depth16 >> 63) as i64, depth17 as i64);
}
/// 宿主机那台独立仪器对账用的读数：全部来自 **syscall 路径**（22 打开、10 读、25 stat、26 readdir），
/// 不是上面那些自校验的中间变量。名字用原始字节打出来，宿主机按 latin1 拼回去比。
///
/// **`#[inline(never)]` 是栈预算**：打印的机器码摊进用例自己的帧，就会与 `vfs_ro::lookup`
/// 那 4,568 字节的帧叠在同一处峰值上（16 KiB 的任务栈装不下，见 `syscall_cells` 的说明）。
#[inline(never)]
fn evidence_line(n: u64, got: &[u8], record: &[u8], d1: &[u8], d2: &[u8]) {
    let s1 = u8::from(d1[8]) as usize;
    let s2 = u8::from(d2[8]) as usize;
    crate::log_info!(
        "fs-open: 取证 读回={} 摘要={:#x} stat大小={} 首簇={} 条目1={:?}/{} 条目2={:?}/{}",
        n,
        ahci::fnv1a64(got),
        u32_le(record, 8),
        u32_le(record, 16),
        &d1[48..48 + s1],
        u32_le(d1, 16),
        &d2[48..48 + s2],
        u32_le(d2, 16),
    );
}

ktest!(KT_FS_OPEN_SYSCALLS, t_fs_open_syscalls);

// ---------------------------------------------------------------- 切片 D：ring3 探针
//
/// ring3 信箱的偏移表（`user/fileprobe/src/main.rs` 里**另有独立的一份**）。
/// 这里故意不引用那一份：两边各写一遍、由读回的数对账，才是两台仪器（ADR-108 决策 8）。
/// 信箱快照的格数：偏移表里最大一格是 `FNVADD=264`，40 格留余量。
const FP_CELLS: usize = 46;

mod fp {
    pub const MAGIC: u64 = 0;
    pub const ABI: u64 = 8;
    pub const OPEN: u64 = 16;
    pub const READ_TOTAL: u64 = 24;
    pub const HEAD: u64 = 32;
    pub const EOF: u64 = 40;
    pub const SEEK50: u64 = 48;
    pub const READ50_TOTAL: u64 = 56;
    pub const TAIL_HEAD: u64 = 64;
    pub const CUR60: u64 = 72;
    pub const END80: u64 = 80;
    pub const SEEK_FAR: u64 = 88;
    pub const STAT: u64 = 96;
    pub const STAT_SIZE: u64 = 104;
    pub const STAT_FIRST: u64 = 112;
    pub const STAT_MAGIC: u64 = 120;
    pub const STAT_SHORT: u64 = 128;
    pub const DIR: u64 = 136;
    pub const DIR_RECORDS: u64 = 144;
    pub const DIR_NAME_SUM: u64 = 152;
    pub const DIR_SIZE_SUM: u64 = 160;
    pub const READ_DIR: u64 = 168;
    pub const DIR_SEEK: u64 = 176;
    pub const REL: u64 = 184;
    pub const MISSING: u64 = 192;
    pub const FLAGS: u64 = 200;
    pub const CLOSE: u64 = 208;
    pub const STALE: u64 = 216;
    pub const DONE: u64 = 224;
    pub const SUM_FULL: u64 = 232;
    pub const SUM_TAIL: u64 = 240;
    pub const DIR_CLOSE: u64 = 248;
    pub const FNVMUL: u64 = 256;
    // ADR-109 / §343：多级路径与中间层目录（探针侧同一组偏移，各写一份）。
    pub const N_OPEN: u64 = 272;
    pub const N_TOTAL: u64 = 280;
    pub const N_HEAD: u64 = 288;
    pub const N_SUM: u64 = 296;
    pub const N_STAT: u64 = 304;
    pub const N_SIZE: u64 = 312;
    pub const N_FIRST: u64 = 320;
    pub const N_CLOSE: u64 = 328;
    pub const P_OPEN: u64 = 336;
    pub const P_RECS: u64 = 344;
    pub const P_NAMES: u64 = 352;
    pub const P_CLOSE: u64 = 360;
    pub const FNVADD: u64 = 264;

    pub const MAGIC_VAL: u64 = 0x544f_4c53_315f_5046;
    pub const DONE_VAL: u64 = 0x3345_4e4f_445f_5046;
}

fn slot(data: u64, off: u64) -> u64 {
    user::read_at(data + off).unwrap_or(0)
}

/// 一格判据：拿**回收前**读好的快照与期望比，红就点名。
/// 比对不再自己去走用户页——见下面 `box_` 那段：容器被 reap 之后那些地址就不再有页表链了。
fn cell_eq(got: u64, want: u64, name: &str) -> bool {
    if got == want {
        return true;
    }
    crate::log_fatal!("fs-open-ring3: 不成立 {} got={} want={}", name, got, want);
    false
}

/// 对照物：全部由**宿主机那台独立仪器**从 `build/fat32-small.img` 现算（BACKLOG §335），
/// 内核里不重算。判定表那一行每一跑都拿同一份盘把这些数再算一遍 ⇒ 夹具换了就当场红。
/// 这里**只用没有算法的量**（大小、首簇、首尾 8 字节、字节和、条数、名字字节和）：
/// 三处各写一遍哈希，红了分不清是谁的算法不同来（实测 ring3 那份 FNV 低 32 位一致、高位不一致）。
mod expect {
    // 下面每一个数都是**照着多级真卷量的**（`tools/validate_esp.py --deep-tree` 与
    // `tools/aurora.py` 的独立解析各算一遍，判定表那两行每一跑再算一遍）。配方一改就得重算——
    // 挂在跑之前的指纹闸先把"配方与期望数分家"报出来，而不是让解析器背这个锅。
    pub const SMALL_BYTES: u64 = 100;
    pub const SMALL_FIRST: u64 = 3;
    pub const SMALL_HEAD: u64 = 0xe0c1_a283_6445_2607;
    pub const SMALL_SUM: u64 = 12_838;
    pub const SMALL_TAIL_HEAD: u64 = 0xeecf_b091_7253_3415;
    pub const SMALL_TAIL_SUM: u64 = 6_257;
    /// 根目录的可见项是 `SMALL.BIN` 与 `PROJECT`：那条 `GONE.BIN` 带删除标记，
    /// 跳过但仍计入扫过项——"跳过"与"数过"是两格，不能合并成一格。
    pub const ROOT_RECORDS: u64 = 3;
    pub const ROOT_NAME_SUM: u64 = 1_292;
    pub const ROOT_SIZE_SUM: u64 = 100;
    /// 同一份 100 字节的 FNV-1a/64：宿主机 `fnv1a64`、核内 `ahci::fnv1a64`、ring3 探针自己那两份
    /// 必须同数。这个数字由 `tools/aurora.py` 的独立解析现算（BACKLOG §335 欠账②的结案读数）。
    pub const SMALL_FNV: u64 = 0xf275_ebb2_a87c_0581;
    // ---- 三级那一刀：`/PROJECT/DOCS/NESTED.TXT` 的首簇是 65,600 ⇒ 目录项高半为 1 ----
    // 卷B 在根目录那一层证过"只取低半会读到别处"；这一格证的是**多级 lookup 之后**那次拼接。
    pub const NESTED_BYTES: u64 = 64;
    pub const NESTED_FIRST: u64 = 65_600;
    pub const NESTED_HEAD: u64 = 0xe7c8_a98a_6b4c_2d0e;
    pub const NESTED_SUM: u64 = 8_096;
    pub const PROJ_RECORDS: u64 = 1;
    /// `/PROJECT` 里那条 `DOCS` 的 8.3 短名字节和（探针累计的是名字字段，不是长名字段）。
    pub const PROJ_NAME_SUM: u64 = 297;
    /// 跨两簇的目录：15 条填充 + NESTED + 长名那条 = 17 条可见项，声明大小合计 232 字节。
    pub const DOCS_RECORDS: u64 = 17;
    pub const DOCS_SIZE_SUM: u64 = 15 * 8 + 64 + 48;
    pub const LONG_NAME_SUM: u64 = 2_247;
    pub const LONG_NAME_LEN: u64 = 22;
    /// 跨簇目录里带长名的条目数：只有 `AURORA~1.TXT` 那一对 LFN 片段属于它。
    pub const LONG_COUNT: u64 = 1;
}

/// FS-03 切片 D：把 `fileprobe` 装进用户窗口真跑一遍，读回它自己写的 29 格。
///
/// 这一条与 `t_fs_open_syscalls` 的分工是刻意的：那条在 ring0 里经真用户页打 `syscall_dispatch`，
/// 量的是**ABI 的形状**；这条让**真 ring3 任务**去打 22/10/24/25/26/8，量的是"用户空间能不能
/// 真的靠这套号读到文件"。两条都要绿，才轮得到宿主机那台独立仪器（判定表那一行）。
///
/// 等的是探针自己写的 `done` 哨兵；容器**不预先领任何句柄**，两个句柄都是它自己用 22 号挣的
/// （ADR-107 决策 1 要在 ring3 这一侧成立，这才是这一格要证的东西）。
fn t_fs_open_ring3() -> bool {
    use crate::ktests::common::{drained_or_free, FILEPROBE_ELF};
    if ahci::init().is_err() {
        crate::log_fatal!("fs-open-ring3: AHCI 未认领");
        return false;
    }
    let loaded = match user::load(FILEPROBE_ELF) {
        Ok(l) => l,
        Err(e) => {
            crate::log_fatal!("fs-open-ring3: 容器装载失败 —— {}", user::describe_load(e));
            return false;
        }
    };
    sched::init_boot_task();
    sched::start_workers();
    handle::reset_for_test();
    handle::reset_counters_for_test();
    user::clear_counters();

    let rel0 = sched::reap_released();
    let t = match sched::spawn_user(loaded.entry, loaded.stack_top, 0, loaded.owned) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("fs-open-ring3: spawn_user 失败 {:?}", e);
            return false;
        }
    };
    let data = loaded.data_va;
    if slot(data, fp::MAGIC) != 0 {
        crate::log_fatal!("fs-open-ring3: 跑之前信箱不是空的（槽基址读错了？）");
        return false;
    }
    let tick_in = crate::arch::x86_64::apic::ticks();
    let timer_was_running =
        crate::arch::x86_64::apic::wait_ticks(tick_in, 2, crate::clock::window_cycles(2)).ticks >= 2;
    crate::arch::x86_64::apic::timer_start().ok();
    let mut rounds = 0u64;
    let mut in_window = true;
    let mut box_ = [0u64; FP_CELLS];
    // 两段窗口：第一段只等 `DONE`，看到就**退出**——`with_interrupts` 退出时 `cli`，
    // 于是下面的整页快照与异步 reaper 互斥（reap 只在 tick 的抢占点上跑）。
    // 旧版把快照放在整段窗口之后、中间还隔着 2M 周期自旋：那期间任何一次 tick 都会把
    // 已 Done 的容器回收、把它的页还掉，`read_at` 便读到"页表链没走完"的全 0（§366）。
    crate::arch::x86_64::apic::with_interrupts(|| {
        let t0 = crate::tsc::now();
        // 等**哨兵**，不等"打了几个号"：调用数会被代码生成挪顺序（`elfdisk` 那段同样的教训）。
        // 窗口是"探针跑完"的**超时上限**，不是精确时序判据——判据是 `DONE` 哨兵到位与否，
        // 放宽上限不会让"探针没跑"假绿（DONE 永远不到位）。原 4×10^8（≈160 ms）把
        // **串口吞吐算进了时间预算**：fileprobe 读多个文件，每次 AHCI 块传输都打一行
        // ~150 字节取证日志（115200 8N1 ≈ 13 ms/行），任何让 `.ktests` 布局变一点、多打
        // 两行的构建都会把它顶红（ADR-131 补记第三轮实测；A4 加 procinfo 用例后复现，1/1）。
        // 放宽到 1.6×10^9（≈640 ms）给探针留出串口预算，其它判据一个不动。
        while crate::tsc::now().wrapping_sub(t0) < 1_600_000_000 {
            rounds += 1;
            if slot(data, fp::DONE) == fp::DONE_VAL {
                return;
            }
            crate::tsc::spin(20_000);
        }
    });
    // IF 关着：先复核哨兵，再整页取快照。这两步之间不会有 tick。
    in_window = slot(data, fp::DONE) == fp::DONE_VAL;
    if in_window {
        let mut nread = 0usize;
        while nread < FP_CELLS {
            box_[nread] = slot(data, (nread as u64) * 8);
            nread += 1;
        }
    }
    // 第二段窗口：让容器退出、启动上下文回到 CPU（这两件都要 tick）。
    crate::arch::x86_64::apic::with_interrupts(|| {
        crate::tsc::spin(2_000_000);
        if !sched::wait_for_boot_task(300_000_000) {
            crate::log_fatal!("fs-open-ring3: 窗口收不了场（启动上下文没回到 CPU）");
        }
    });
    if !timer_was_running {
        crate::arch::x86_64::apic::timer_stop().ok();
    }
    // 快照已在上面（第一段窗口退出、IF 关着时）取走：容器一被 reap，它名下的页就还给分配器，
    // 之后再 `read_at` 读到的就是"页表链没走完"（§366）。
    let reaped = drained_or_free(rel0, t);
    let table_clean = handle::live() == 0;

    if !in_window {
        crate::log_fatal!("fs-open-ring3: 不成立 done 哨兵（窗口内没等到）");
    }
    if !reaped {
        crate::log_fatal!("fs-open-ring3: 不成立 回收（容器任务没被 reap）");
    }
    if !table_clean {
        crate::log_fatal!("fs-open-ring3: 不成立 表清空（live={}）", handle::live());
    }
    let mut ok = in_window && reaped && table_clean;
    ok &= cell_eq(box_[(fp::MAGIC / 8) as usize], fp::MAGIC_VAL, "magic");
    ok &= cell_eq(box_[(fp::DONE / 8) as usize], fp::DONE_VAL, "done");
    ok &= cell_eq(box_[(fp::READ_TOTAL / 8) as usize], 100, "读回总字节");
    ok &= cell_eq(box_[(fp::HEAD / 8) as usize], expect::SMALL_HEAD, "首 8 字节");
    ok &= cell_eq(box_[(fp::SUM_FULL / 8) as usize], expect::SMALL_SUM, "整份字节和");
    ok &= cell_eq(box_[(fp::EOF / 8) as usize], 0, "EOF 返回");
    ok &= cell_eq(box_[(fp::SEEK50 / 8) as usize], 50, "seek SET 50");
    ok &= cell_eq(box_[(fp::READ50_TOTAL / 8) as usize], 50, "尾段字节数");
    ok &= cell_eq(box_[(fp::TAIL_HEAD / 8) as usize], expect::SMALL_TAIL_HEAD, "尾段首 8 字节");
    ok &= cell_eq(box_[(fp::SUM_TAIL / 8) as usize], expect::SMALL_TAIL_SUM, "尾段字节和");
    ok &= cell_eq(box_[(fp::CUR60 / 8) as usize], 60, "seek CUR +10");
    ok &= cell_eq(box_[(fp::END80 / 8) as usize], 80, "seek END -20");
    ok &= cell_eq(box_[(fp::SEEK_FAR / 8) as usize], user::E_INVALID, "seek 越 EOF");
    ok &= cell_eq(box_[(fp::STAT / 8) as usize], 0, "stat 返回");
    ok &= cell_eq(box_[(fp::STAT_SIZE / 8) as usize], expect::SMALL_BYTES, "stat 大小");
    ok &= cell_eq(box_[(fp::STAT_FIRST / 8) as usize], expect::SMALL_FIRST, "stat 首簇");
    ok &= cell_eq(box_[(fp::STAT_MAGIC / 8) as usize], fs_open::STAT_MAGIC as u64, "stat 魔数");
    ok &= cell_eq(box_[(fp::STAT_SHORT / 8) as usize], user::E_TOO_LONG, "stat 缓冲短");
    ok &= cell_eq(box_[(fp::DIR_RECORDS / 8) as usize], expect::ROOT_RECORDS, "readdir 条数");
    ok &= cell_eq(box_[(fp::DIR_NAME_SUM / 8) as usize], expect::ROOT_NAME_SUM, "readdir 名字字节和");
    ok &= cell_eq(box_[(fp::DIR_SIZE_SUM / 8) as usize], expect::ROOT_SIZE_SUM, "readdir 大小和");
    ok &= cell_eq(box_[(fp::READ_DIR / 8) as usize], user::E_IS_DIR, "read 目录");
    ok &= cell_eq(box_[(fp::DIR_SEEK / 8) as usize], user::E_NOT_SUPPORTED, "目录 seek");
    ok &= cell_eq(box_[(fp::REL / 8) as usize], user::E_INVALID, "相对路径");
    ok &= cell_eq(box_[(fp::MISSING / 8) as usize], user::E_NOT_FOUND, "不存在");
    ok &= cell_eq(box_[(fp::FLAGS / 8) as usize], user::E_NOT_SUPPORTED, "非零 flags");
    ok &= cell_eq(box_[(fp::CLOSE / 8) as usize], 0, "close 文件");
    ok &= cell_eq(box_[(fp::DIR_CLOSE / 8) as usize], 0, "close 目录");
    // ---- ADR-109：ring3 侧的三级路径与中间层目录 ----
    ok &= cell_eq(box_[(fp::N_TOTAL / 8) as usize], expect::NESTED_BYTES, "多级读回字节");
    ok &= cell_eq(box_[(fp::N_HEAD / 8) as usize], expect::NESTED_HEAD, "多级首 8 字节");
    ok &= cell_eq(box_[(fp::N_SUM / 8) as usize], expect::NESTED_SUM, "多级字节和");
    ok &= cell_eq(box_[(fp::N_STAT / 8) as usize], 0, "多级 stat 返回");
    ok &= cell_eq(box_[(fp::N_SIZE / 8) as usize], expect::NESTED_BYTES, "多级 stat 大小");
    ok &= cell_eq(box_[(fp::N_FIRST / 8) as usize], expect::NESTED_FIRST, "多级 stat 首簇两半");
    ok &= cell_eq(box_[(fp::N_CLOSE / 8) as usize], 0, "close 多级文件");
    ok &= cell_eq(box_[(fp::P_RECS / 8) as usize], expect::PROJ_RECORDS, "中间层条目");
    ok &= cell_eq(box_[(fp::P_NAMES / 8) as usize], expect::PROJ_NAME_SUM, "中间层名字字节和");
    ok &= cell_eq(box_[(fp::P_CLOSE / 8) as usize], 0, "close 中间层目录");
    ok &= cell_eq(box_[(fp::STALE / 8) as usize], user::E_BAD_HANDLE, "close 后旧句柄");
    // 探针自己的两种乘法写法必须同数：这一步抓住过素数字面量多打一组下划线（2^44+435）。
    let (mul, add) = (box_[(fp::FNVMUL / 8) as usize], box_[(fp::FNVADD / 8) as usize]);
    ok &= cell_eq(box_[(fp::FNVMUL / 8) as usize], expect::SMALL_FNV, "整份 FNV 三实现同数");
    if mul != add {
        crate::log_fatal!("fs-open-ring3: 不成立 两种乘法写法同数 mul={:#x} add={:#x}", mul, add);
        ok = false;
    }
    // 三格是"形状"而不是定值：句柄值与 abi_word 都是当跑现生成的数，只能判位与符号。
    let abi = box_[(fp::ABI / 8) as usize];
    let open = box_[(fp::OPEN / 8) as usize];
    let dir = box_[(fp::DIR / 8) as usize];
    if abi & user::F_FS_OPEN == 0 || (abi >> 16) & 0xFFFF != user::ABI_MINOR {
        crate::log_fatal!(
            "fs-open-ring3: 不成立 abi abi={:#x} 期望位={:#x} minor={}",
            abi, user::F_FS_OPEN, user::ABI_MINOR);
        ok = false;
    }
    let nested_h = box_[(fp::N_OPEN / 8) as usize];
    let proj_h = box_[(fp::P_OPEN / 8) as usize];
    for (name, h) in [("open", open), ("dir", dir), ("多级", nested_h), ("/PROJECT", proj_h)] {
        if (h as i64) < 0 || h >> 63 != 0 {
            crate::log_fatal!("fs-open-ring3: 不成立 句柄形状 {}={:#x}", name, h);
            ok = false;
        }
    }

    // §355 附：这格不过探针、不过槽、不过快照——用来把"abi=0"钉到链上的哪一段。
    crate::log_info!("fs-open-ring3: abi直读={:#x} 探针槽={:#x}", crate::user::abi_word(), abi);
    crate::log_info!(
        "fs-open-ring3: 取证 读回={} 首8={:#x} 字节和={} 尾字节数={} 尾首8={:#x} 尾和={} stat大小={} 首簇={} 条目={} 名字和={} 大小和={} 多级读回={} 多级首8={:#x} 多级和={} 多级首簇={} proj条目={} proj名字和={} 表清空={} 回收={} rounds={} served={} 诊断mul={:#x} 诊断add={:#x} ⇒ {}",
        box_[(fp::READ_TOTAL / 8) as usize],
        box_[(fp::HEAD / 8) as usize],
        box_[(fp::SUM_FULL / 8) as usize],
        box_[(fp::READ50_TOTAL / 8) as usize],
        box_[(fp::TAIL_HEAD / 8) as usize],
        box_[(fp::SUM_TAIL / 8) as usize],
        box_[(fp::STAT_SIZE / 8) as usize],
        box_[(fp::STAT_FIRST / 8) as usize],
        box_[(fp::DIR_RECORDS / 8) as usize],
        box_[(fp::DIR_NAME_SUM / 8) as usize],
        box_[(fp::DIR_SIZE_SUM / 8) as usize],
        box_[(fp::N_TOTAL / 8) as usize],
        box_[(fp::N_HEAD / 8) as usize],
        box_[(fp::N_SUM / 8) as usize],
        box_[(fp::N_FIRST / 8) as usize],
        box_[(fp::P_RECS / 8) as usize],
        box_[(fp::P_NAMES / 8) as usize],
        table_clean,
        reaped,
        rounds,
        user::served(),
        box_[(fp::FNVMUL / 8) as usize],
        box_[(fp::FNVADD / 8) as usize],
        ok
    );
    handle::reset_for_test();
    ok
}

/// dup 共享读取位置（ADR-108 补记二），VFS 文件那一支：产品路径（22/24 号）用的正是这种句柄。
#[cfg(feature = "fs-open")]
fn t_fs_open_dup_shared() -> bool {
    if ahci::init().is_err() {
        return false;
    }
    sched::init_boot_task();
    let Some(ident) = sched::current_identity() else {
        return false;
    };
    let disk = AhciDisk { port: fs_open::PORT };
    let fs = match ReadOnlyFs::mount(&disk) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let st = match fs.lookup("/SMALL.BIN") {
        Ok(e) => e,
        Err(_) => return false,
    };
    // 参考字节：直接走 VFS（不经句柄），句柄读出来的每一段都必须与它相同。
    let mut refb = [0u8; 64];
    let mut rc = match fs.open(&st) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let got = match vfs_ro::read_disk(&disk, &mut rc, &mut refb) {
        Ok(n) => n,
        Err(_) => return false,
    };
    if got != 64 {
        return false;
    }
    handle::reset_for_test();
    let cur = match fs.open(&st) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let h1 = match handle::grant_vfs_file(
        ident,
        fs_open::PORT,
        None,
        cur,
        st,
        handle::RIGHT_READ | handle::RIGHT_DUP,
    ) {
        Ok(h) => h,
        Err(_) => return false,
    };
    let mut a = [0u8; 16];
    let first = handle::read(h1, ident, &mut a) == Ok(16) && a == refb[..16];
    let h2 = match handle::dup(h1, ident, handle::RIGHT_READ) {
        Ok(h) => h,
        Err(_) => return false,
    };
    // 同一条顺序：dup 之后先让原名字推进，再读第二个名字（复制语义会读到 16..32）。
    let mut b = [0u8; 16];
    let advanced = handle::read(h1, ident, &mut b) == Ok(16) && b == refb[16..32];
    let mut c = [0u8; 16];
    let shared = handle::read(h2, ident, &mut c) == Ok(16) && c == refb[32..48];
    let closed1 = handle::close(h1, ident).is_ok();
    let mut d = [0u8; 16];
    let survive = handle::read(h2, ident, &mut d) == Ok(16) && d == refb[48..64];
    let closed2 = handle::close(h2, ident).is_ok();
    crate::log_info!(
        "fs-open-dup: 首读={} 原名字推进={} 第二名字共享={} 关一条仍续读={} 端点={}",
        first, advanced, shared, survive, closed1 && closed2
    );
    first && advanced && shared && survive && closed1 && closed2
}
ktest!(KT_FS_OPEN_DUP_SHARED, t_fs_open_dup_shared);

ktest!(KT_FS_OPEN_RING3, t_fs_open_ring3);
