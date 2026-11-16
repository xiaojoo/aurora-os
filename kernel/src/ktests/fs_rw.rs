//! ADR-111：可写卷（口 6）上的第一格判据——写进去的字节真的落了盘，没写的地方没动。

use crate::filesystem::fs_rw;
use crate::filesystem::vfs::AhciDisk;
use crate::filesystem::vfs_ro::{self, ReadOnlyFs, VfsError};
use crate::ktest;

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
