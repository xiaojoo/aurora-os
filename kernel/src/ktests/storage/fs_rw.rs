//! ADR-111：可写卷（口 4）上的判据——写进去的字节真的落了盘，没写的地方没动；
//! 第二格把 23 号经 `syscall_dispatch` 跑一遍。

use crate::arch::x86_64::trap::TrapFrame;
use crate::filesystem::fs_rw;
use crate::filesystem::vfs::AhciDisk;
use crate::filesystem::vfs_ro::{self, ReadOnlyFs, VfsError};
use crate::handle::{self, Handle, RIGHT_READ, RIGHT_WRITE};
use crate::{ahci, ktest, mm, sched, user};
use crate::ktests::common::{call, frame0, get_user, put_user};

/// `/LOG.TXT` 64 字节、`/DATA.BIN` 1024 字节（跨两簇）。写 `LOG.TXT` 的 `[8,12)`，
/// 再证 `DATA.BIN` 的头 16 字节与 `LOG.TXT` 的邻居字节都没变。
fn t_fs_rw_write() -> bool {
    let disk = AhciDisk { port: fs_rw::PORT };
    let fs: ReadOnlyFs<'static> = match fs_rw::mount() {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("fs-rw: 可写卷挂载被拒 成因={}", e.tag());
            return false;
        }
    };
    let log = match fs.lookup("/LOG.TXT") {
        Ok(e) => e,
        Err(e) => {
            crate::log_fatal!("fs-rw: 查 /LOG.TXT 被拒 成因={}", e.tag());
            return false;
        }
    };
    let data = match fs.lookup("/DATA.BIN") {
        Ok(e) => e,
        Err(e) => {
            crate::log_fatal!("fs-rw: 查 /DATA.BIN 被拒 成因={}", e.tag());
            return false;
        }
    };
    if log.size != 64 || data.size != 1024 {
        crate::log_fatal!("fs-rw: 夹具形状变了 log={} data={}", log.size, data.size);
        return false;
    }

    // 基线：LOG.TXT 的 64 字节 + DATA.BIN 的头 16 字节
    let mut cur = match fs.open(&log) {
        Ok(c) => c,
        Err(e) => {
            crate::log_fatal!("fs-rw: 打开 LOG 被拒 成因={}", e.tag());
            return false;
        }
    };
    let mut before = [0u8; 64];
    let base_ok = match fs.read(&mut cur, &mut before) {
        Ok(n) => n == 64,
        Err(_) => false,
    };
    let mut dcur = match fs.open(&data) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let mut dhead = [0u8; 16];
    let d_ok = match fs.read(&mut dcur, &mut dhead) {
        Ok(n) => n == 16,
        Err(_) => false,
    };

    // 写 [8,12)
    let seek_ok = vfs_ro::seek_disk(&disk, &mut cur, 8).is_ok();
    let mut wrote = false;
    if seek_ok {
        if let Ok(n) = vfs_ro::write_at(&disk, &mut cur, &[0xDE, 0xAD, 0xBE, 0xEF]) {
            wrote = n == 4;
        }
    }

    // 读回
    let back_seek = vfs_ro::seek_disk(&disk, &mut cur, 0).is_ok();
    let mut after = [0u8; 64];
    let read_back = back_seek
        && match fs.read(&mut cur, &mut after) {
            Ok(n) => n == 64,
            Err(_) => false,
        };
    let mut cells_ok = read_back;
    if read_back {
        let mut i = 0usize;
        while i < 64 {
            let want = if (8..12).contains(&i) { [0xDEu8, 0xAD, 0xBE, 0xEF][i - 8] } else { before[i] };
            if after[i] != want {
                cells_ok = false;
                break;
            }
            i += 1;
        }
    }

    // 另一个文件没动
    let mut dcur2 = match fs.open(&data) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let mut dhead2 = [0u8; 16];
    let data_ok = match fs.read(&mut dcur2, &mut dhead2) {
        Ok(n) => n == 16,
        Err(_) => false,
    } && dhead2 == dhead;

    crate::log_info!(
        "fs-rw: 写读 基线={} DATA基线={} 写4字节={} 读回={} 内容对={} 邻文件未动={}",
        base_ok, d_ok, wrote, read_back, cells_ok, data_ok
    );
    base_ok && d_ok && wrote && read_back && cells_ok && data_ok
}

ktest!(KT_FS_RW_WRITE, t_fs_rw_write);

// ---------------------------------------------------------------- 23 号：帧级判据
const LOG_LEN: usize = 64;

/// 23 号走 `syscall_dispatch`（授两个句柄 → 真用户页 → 读/写/负样本 → 各自 close）。
///
/// §354 的成因已从那一跑的串口看清：用例本体是绿的，但它**漏关了授出去的两格**，
/// 于是收尾不变量在之后每一条用例上都红一次（42 条连带），看起来像"清表把别人打坏了"。
/// 这一版不再碰 `reset_for_test`：只授自己用的两格，末了经 8 号各自关掉，末态由收尾检查判。
fn t_fs_rw_syscall23() -> bool {
    if ahci::init().is_err() {
        crate::log_fatal!("fs-rw-23: AHCI 未认领");
        return false;
    }
    sched::init_boot_task();
    let Some(ident) = sched::current_identity() else {
        crate::log_fatal!("fs-rw-23: 没有当前任务身份");
        return false;
    };
    let fs: ReadOnlyFs<'static> = match fs_rw::mount() {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("fs-rw-23: 可写卷挂载被拒 成因={}", e.tag());
            return false;
        }
    };
    let log = match fs.lookup("/LOG.TXT") {
        Ok(e) => e,
        Err(e) => {
            crate::log_fatal!("fs-rw-23: 查 /LOG.TXT 被拒 成因={}", e.tag());
            return false;
        }
    };
    let data = match fs.lookup("/DATA.BIN") {
        Ok(e) => e,
        Err(e) => {
            crate::log_fatal!("fs-rw-23: 查 /DATA.BIN 被拒 成因={}", e.tag());
            return false;
        }
    };
    if log.size != LOG_LEN as u32 || data.size != 1024 {
        crate::log_fatal!("fs-rw-23: 夹具形状变了 log={} data={}", log.size, data.size);
        return false;
    }
    let log_cur = match fs.open(&log) {
        Ok(c) => c,
        Err(e) => {
            crate::log_fatal!("fs-rw-23: 打开 LOG 被拒 成因={}", e.tag());
            return false;
        }
    };
    let data_cur = match fs.open(&data) {
        Ok(c) => c,
        Err(e) => {
            crate::log_fatal!("fs-rw-23: 打开 DATA 被拒 成因={}", e.tag());
            return false;
        }
    };

    // 两格：LOG 拿读写权；DATA 只拿读权，专门用来证"只读句柄写 ⇒ -4"。
    let hw = match handle::grant_vfs_file(ident, fs_rw::PORT, None, log_cur, log, RIGHT_READ | RIGHT_WRITE) {
        Ok(h) => h,
        Err(e) => {
            crate::log_fatal!("fs-rw-23: 授写句柄被拒 {}", e.tag());
            return false;
        }
    };
    let hr = match handle::grant_vfs_file(ident, fs_rw::PORT, None, data_cur, data, RIGHT_READ) {
        Ok(h) => h,
        Err(e) => {
            let _ = handle::close(hw, ident);
            crate::log_fatal!("fs-rw-23: 授只读句柄被拒 {}", e.tag());
            return false;
        }
    };
    // 第三格：授一个**空分区区间**（0..=0）的文件句柄。读在翻译之前就会被 `PartitionView` 拒，
    // 所以这是确定性的盘侧失败（不需要真让 AHCI 坏掉），专门量"块失败 ⇒ -7"（BACKLOG §364）。
    let ghost_cur = match fs.open(&log) {
        Ok(c) => c,
        Err(e) => {
            let _ = handle::close(hw, ident);
            let _ = handle::close(hr, ident);
            crate::log_fatal!("fs-rw-23: 空区间句柄的游标打开失败 {}", e.tag());
            return false;
        }
    };
    let hbad = match handle::grant_vfs_file(
        ident,
        fs_rw::PORT,
        Some(crate::filesystem::vfs::Partition { base: 0, last: 0 }),
        ghost_cur,
        log,
        RIGHT_READ,
    ) {
        Ok(h) => h,
        Err(e) => {
            let _ = handle::close(hw, ident);
            let _ = handle::close(hr, ident);
            crate::log_fatal!("fs-rw-23: 授空区间句柄被拒 {}", e.tag());
            return false;
        }
    };
    syscall23_cells(hw, hr, hbad)
}

/// **`#[inline(never)]` 是栈预算**（同 `fs_open.rs::syscall_cells` 的理由）：用例跑在 16 KiB
/// 内核栈上，`mount`/`lookup` 的帧与 `syscall_dispatch` 的帧不该叠在同一个峰值上。
///
/// 返回之前一定走完两个 close——中途任何一格红都只是 `ok = false`，不是提前 `return`。
#[inline(never)]
fn syscall23_cells(hw: Handle, hr: Handle, hbad: Handle) -> bool {
    let Some(va) = mm::alloc_user_va_range(1) else {
        crate::log_fatal!("fs-rw-23: 用户 VA 分配失败");
        return false;
    };
    let Ok(frames) = mm::phys_alloc(0, mm::MOD_TEST) else {
        crate::log_fatal!("fs-rw-23: 用户页帧分配失败");
        return false;
    };
    let Ok(flags) = mm::PageFlags::new(true, false, true) else {
        crate::log_fatal!("fs-rw-23: 页标志构造失败");
        return false;
    };
    let Ok(map) = mm::map(va, frames, flags) else {
        crate::log_fatal!("fs-rw-23: 用户页映射失败");
        return false;
    };
    let mut fr = frame0();
    let mut ok = true;

    // 基线：经 10 号读整份 LOG.TXT，并确认游标到了 EOF。
    let base_n = call(&mut fr, user::SYS_FILE_READ, hw.0, va.0, LOG_LEN as u64);
    let mut before = [0u8; LOG_LEN];
    let base_ok = base_n == LOG_LEN as u64 && get_user(va.0, 0, &mut before);
    ok &= base_ok;
    ok &= call(&mut fr, user::SYS_FILE_READ, hw.0, va.0, 1) == 0;

    // 写 [4,8)：偏移刻意避开 `t_fs_rw_write` 那格的 [8,12)，两条用例不依赖链接顺序。
    let pattern = [0xD3u8, 0xA5, 0x5A, 0xC3];
    let w_seek = call(&mut fr, user::SYS_FILE_SEEK, hw.0, 4, 0);
    let put_ok = put_user(va.0, 64, &pattern);
    let wrote = call(&mut fr, user::SYS_FILE_WRITE, hw.0, va.0 + 64, 4);
    ok &= w_seek == 4 && put_ok && wrote == 4;

    // 读回：只有 [4,8) 变，其余 60 字节与基线逐字节相同。
    let r_seek = call(&mut fr, user::SYS_FILE_SEEK, hw.0, 0, 0);
    let read_n = call(&mut fr, user::SYS_FILE_READ, hw.0, va.0, LOG_LEN as u64);
    let mut after = [0u8; LOG_LEN];
    let mut cells_ok = r_seek == 0 && read_n == LOG_LEN as u64 && get_user(va.0, 0, &mut after);
    if cells_ok {
        let mut i = 0usize;
        while i < LOG_LEN {
            let want = if (4..8).contains(&i) { pattern[i - 4] } else { before[i] };
            if after[i] != want {
                cells_ok = false;
                break;
            }
            i += 1;
        }
    }
    ok &= cells_ok;

    // 空写 ⇒ -1。
    let empty = call(&mut fr, user::SYS_FILE_WRITE, hw.0, va.0, 0);
    ok &= empty == user::E_INVALID;
    // 越 EOF ⇒ -1，且票作废、游标不提交：从 62 读两字节仍是原样。
    let s62 = call(&mut fr, user::SYS_FILE_SEEK, hw.0, (LOG_LEN - 2) as u64, 0);
    let over = call(&mut fr, user::SYS_FILE_WRITE, hw.0, va.0 + 64, 4);
    let tail_n = call(&mut fr, user::SYS_FILE_READ, hw.0, va.0 + 128, 2);
    let mut tail = [0u8; 2];
    ok &= s62 == (LOG_LEN - 2) as u64 && over == user::E_INVALID;
    ok &= tail_n == 2 && get_user(va.0, 128, &mut tail) && tail == [after[62], after[63]];
    // 只读句柄写 ⇒ -4（`HErr::Denied`，与 10 号读同一条映射）。
    let ro_w = call(&mut fr, user::SYS_FILE_WRITE, hr.0, va.0 + 64, 4);
    ok &= ro_w == user::E_DENIED;
    // 坏用户指针 ⇒ -2，且游标不提交（重读必须仍从 0 开始）。
    let s0 = call(&mut fr, user::SYS_FILE_SEEK, hw.0, 0, 0);
    let bad = call(&mut fr, user::SYS_FILE_WRITE, hw.0, 0, 4);
    let head_n = call(&mut fr, user::SYS_FILE_READ, hw.0, va.0 + 128, 4);
    let mut head = [0u8; 4];
    ok &= s0 == 0 && bad == user::E_FAULT;
    ok &= head_n == 4 && get_user(va.0, 128, &mut head) && head == [after[0], after[1], after[2], after[3]];
    // 块侧失败 ⇒ -7（EIO），不是 -2：空区间句柄在第一扇区翻译之前就被 `PartitionView` 拒。
    // 走 10 号 syscall 本身——分区包装在 `sys_file_read` 里（ADR-108 补记七）。
    // 这条同时咬两件事：映射表是 -7，且 syscall 真的按 `ticket.partition()` 翻地址
    // （没有包装的话这次读会从真盘上读到 1 字节，而不是 -7）。
    let eio = call(&mut fr, user::SYS_FILE_READ, hbad.0, va.0, 1);
    ok &= eio == user::E_IO;

    // 各自 close（经 8 号，与 ring3 调用方同一条路）；关后旧句柄必须是 -5。
    let c1 = call(&mut fr, user::SYS_HANDLE_CLOSE, hw.0, 0, 0);
    let c2 = call(&mut fr, user::SYS_HANDLE_CLOSE, hr.0, 0, 0);
    let c3 = call(&mut fr, user::SYS_HANDLE_CLOSE, hbad.0, 0, 0);
    let stale_w = call(&mut fr, user::SYS_FILE_WRITE, hw.0, va.0, 1);
    let stale_r = call(&mut fr, user::SYS_FILE_READ, hr.0, va.0, 1);
    ok &= c1 == 0 && c2 == 0 && c3 == 0;
    ok &= stale_w == user::E_BAD_HANDLE && stale_r == user::E_BAD_HANDLE;

    let live = handle::used();
    crate::log_info!(
        "fs-rw-23: 写4={} 空写={} 越EOF={} 只读句柄={} 坏指针={} 盘失败={} 读回={} 内容对={} 基线={} 关={} 关后活={}",
        wrote,
        empty as i64,
        over as i64,
        ro_w as i64,
        bad as i64,
        eio as i64,
        read_n,
        cells_ok,
        base_ok,
        c1 == 0 && c2 == 0 && c3 == 0,
        live
    );
    drop(map);
    ok && live == 0
}

ktest!(KT_FS_RW_SYSCALL23, t_fs_rw_syscall23);

/// ADR-111 决策 1（2026-11-17 裁决）：写意图 open（`flags=1`）在 `fs-rw` 档路由到可写卷（口 4）
/// 并授 `READ|WRITE`；读意图仍走只读根（口 5）。两个根的命名空间是**分开的**——同一个路径
/// `/LOG.TXT` 在只读根上必须 `-8`。这条用例只碰 [16,20)，避开另两条的 [4,8)/[8,12)。
fn t_fs_rw_open_write() -> bool {
    if ahci::init().is_err() {
        crate::log_fatal!("fs-rw-open-w: AHCI 未认领");
        return false;
    }
    sched::init_boot_task();
    let Some(va) = mm::alloc_user_va_range(1) else {
        crate::log_fatal!("fs-rw-open-w: 用户 VA 分配失败");
        return false;
    };
    let Ok(frames) = mm::phys_alloc(0, mm::MOD_TEST) else {
        crate::log_fatal!("fs-rw-open-w: 用户页帧分配失败");
        return false;
    };
    let Ok(flags) = mm::PageFlags::new(true, false, true) else {
        crate::log_fatal!("fs-rw-open-w: 页标志构造失败");
        return false;
    };
    let Ok(map) = mm::map(va, frames, flags) else {
        crate::log_fatal!("fs-rw-open-w: 用户页映射失败");
        return false;
    };
    let mut fr = frame0();
    let mut ok = true;

    let path = b"/w/LOG.TXT";
    ok &= put_user(va.0, 0, path);
    // 写意图：`/w` 前缀落在可写卷（口 4），能开出来就说明挂载表解析生效。
    let h = call(&mut fr, user::SYS_FILE_OPEN, va.0, path.len() as u64, 1);
    let handle = Handle(h);
    let open_ok = (h as i64) > 0;
    ok &= open_ok;
    // 读意图走根上的同名路径 ⇒ -8（只读根没有它）；对它写意图 ⇒ -15（根不可写）。
    ok &= put_user(va.0, 0, b"/LOG.TXT");
    let miss = call(&mut fr, user::SYS_FILE_OPEN, va.0, 8, 0);
    let root_w = call(&mut fr, user::SYS_FILE_OPEN, va.0, 8, 1);
    ok &= miss == user::E_NOT_FOUND && root_w == user::E_NOT_SUPPORTED;
    // 读意图在 `/w` 下是允许的（可写挂载也能读），但本用例只需证它会落到口 4：
    // 由写/读回那几格覆盖，这里把路径换回去。
    ok &= put_user(va.0, 0, path);

    let pat = [0x5Au8, 0xA5, 0x3C, 0xC3];
    let s16 = call(&mut fr, user::SYS_FILE_SEEK, handle.0, 16, 0);
    ok &= s16 == 16 && put_user(va.0, 64, &pat);
    let wrote = call(&mut fr, user::SYS_FILE_WRITE, handle.0, va.0 + 64, 4);
    ok &= wrote == 4;
    let s16b = call(&mut fr, user::SYS_FILE_SEEK, handle.0, 16, 0);
    let n = call(&mut fr, user::SYS_FILE_READ, handle.0, va.0 + 128, 4);
    let mut back = [0u8; 4];
    let back_ok = s16b == 16 && n == 4 && get_user(va.0, 128, &mut back) && back == pat;
    ok &= back_ok;

    // flags=2 ⇒ -15；写意图打目录 ⇒ -15。
    let bad_flags = call(&mut fr, user::SYS_FILE_OPEN, va.0, path.len() as u64, 2);
    ok &= bad_flags == user::E_NOT_SUPPORTED;
    ok &= put_user(va.0, 0, b"/w");
    let dir_w = call(&mut fr, user::SYS_FILE_OPEN, va.0, 2, 1);
    ok &= dir_w == user::E_NOT_SUPPORTED;
    // ABI 0.15：写意图位与写根位在这档都必须置位（0.14 的挂载表 + 0.15 的 dup 共享游标）。
    ok &= user::abi_word() & user::F_FS_WRITE_OPEN != 0
        && user::abi_word() & user::F_FS_WRITE_ROOT != 0
        && user::ABI_MINOR == 17;

    let c = if open_ok {
        call(&mut fr, user::SYS_HANDLE_CLOSE, handle.0, 0, 0)
    } else {
        user::E_BAD_HANDLE
    };
    let live = handle::used();
    crate::log_info!(
        "fs-rw-open-w: 写意图开={} 读根未见={} 写4={} 读回={} 非法flags={} 目录={} 关={} 关后活={}",
        open_ok,
        miss == user::E_NOT_FOUND,
        wrote,
        back_ok,
        bad_flags as i64,
        dir_w as i64,
        c,
        live
    );
    drop(map);
    ok && open_ok && c == 0 && live == 0
}
ktest!(KT_FS_RW_OPEN_WRITE, t_fs_rw_open_write);
