//! FS-03：FAT32 多级真卷单根与 StatV1/DirentV1 的固定记录布局（ADR-108 / ADR-109）。
//!
//! 这一层**不依赖 capability 句柄表**，避免 `storage -> capability` 新增一条产品依赖边。
//! 它只做挂载、路径解析、打开游标和 ABI 记录编码；授予句柄与提交游标由 user 调度层编排。
//! 记录布局在这里写一份，`user/fileprobe` 再独立读一份；两台仪器共同核对偏移与魔数。
//!
//! ADR-109 把挂载根从卷A（只有根目录一层）换成了 `tools/make_fat32_deep.py` 现算的那块卷：
//! 多级 `lookup`、跨两簇的目录、子目录里的 LFN、以及**首簇高半非零的三级文件**在卷A 上
//! 一个形状都没有，挂在那里等于"用例里写着三级路径、盘上根本没有"。

use crate::filesystem::vfs::AhciDisk;
use crate::filesystem::vfs_ro::{self, DirState, Entry, ReadOnlyFs, VfsError};

/// 挂载口。口号与 `tools/aurora.py` 的 `FS_OPEN_PORTS` 各写一份，由 `check-fat32-ports` 对账。
pub const PORT: u8 = 5;
pub const OPEN_READ_ONLY: u64 = 0;
/// ADR-111 决策 1（2026-11-17 裁决）：写意图。**只在 `fs-rw` 档有意义**——调用方把这类 open
/// 路由到可写卷；本模块的 `open()`（只读根）拿到它当场拒。
pub const OPEN_WRITE: u64 = 1;

pub const STAT_MAGIC: u32 = 0x5346_5541; // "AUFS"
pub const STAT_RECORD_LEN: u16 = 48;
pub const STAT_VERSION: u8 = 1;
pub const STAT_KIND_FILE: u8 = 1;
pub const STAT_KIND_DIR: u8 = 2;
pub const STAT_KIND_ROOT: u8 = 3;
pub const STAT_FLAG_LONG_TRUNCATED: u8 = 1;

pub const DIRENT_MAGIC: u32 = 0x4446_5541; // "AUFD"
pub const DIRENT_RECORD_LEN: u16 = 512;
pub const DIRENT_VERSION: u8 = 1;
pub const DIRENT_KIND_FILE: u8 = 1;
pub const DIRENT_KIND_DIR: u8 = 2;
pub const DIRENT_FLAG_LONG_TRUNCATED: u8 = 1;

static DISK: AhciDisk = AhciDisk { port: PORT };

/// open 成功后、进入句柄表之前的一份状态。调用方负责把其中的游标与元数据放进
/// capability 对象；这层不能反过来调用 capability，否则 storage 会被迫认识句柄表。
#[derive(Debug, Clone, Copy)]
pub enum Opened {
    File { cursor: vfs_ro::ReadCursor, stat: Entry },
    Dir { state: DirState, stat: Entry },
}

pub fn mount() -> Result<ReadOnlyFs<'static>, VfsError> {
    ReadOnlyFs::mount(&DISK)
}

/// 在**指定的口**上打开。调用方按 flags 选口：读意图 → 只读根（`PORT`），写意图 → 可写卷。
/// 两个根各自挂载、命名空间分开——这里不做跨根查找（那要挂载表，ADR-108 未决 4）。
pub fn open_on(port: u8, path: &str, flags: u64) -> Result<Opened, VfsError> {
    if flags != OPEN_READ_ONLY && flags != OPEN_WRITE {
        return Err(VfsError::BadFlags);
    }
    let disk = AhciDisk { port };
    let fs = ReadOnlyFs::mount(&disk)?;
    let stat = fs.lookup(path)?;
    if stat.is_dir() {
        // 写意图打在目录上没有意义（创建/截断是另一刀）。
        if flags == OPEN_WRITE {
            return Err(VfsError::BadFlags);
        }
        let state = DirState::new(&fs.bpb(), &stat)?;
        Ok(Opened::Dir { state, stat })
    } else {
        let cursor = fs.open(&stat)?;
        Ok(Opened::File { cursor, stat })
    }
}

pub fn open(path: &str, flags: u64) -> Result<Opened, VfsError> {
    // 只读根（口 5）上不许写意图：它的 sha256 就是判据（ADR-111 决策 3）。
    if flags == OPEN_WRITE {
        return Err(VfsError::BadFlags);
    }
    open_on(PORT, path, flags)
}

pub fn stat_record(e: &Entry) -> [u8; 48] {
    let mut b = [0u8; 48];
    put_u32(&mut b, 0, STAT_MAGIC);
    put_u16(&mut b, 4, STAT_RECORD_LEN);
    b[6] = STAT_VERSION;
    b[7] = if e.is_root { STAT_KIND_ROOT } else if e.is_dir() { STAT_KIND_DIR } else { STAT_KIND_FILE };
    put_u32(&mut b, 8, e.size);
    b[12] = e.attr;
    b[13] = e.name().len() as u8;
    put_u16(&mut b, 14, e.long_len() as u16);
    put_u32(&mut b, 16, e.first_cluster);
    put_u32(&mut b, 20, e.entries_seen);
    put_u32(&mut b, 24, e.lfn_entries);
    put_u32(&mut b, 28, e.lfn_bad);
    put_u16(&mut b, 32, e.create_time);
    put_u16(&mut b, 34, e.create_date);
    put_u16(&mut b, 36, e.access_date);
    put_u16(&mut b, 38, e.write_time);
    put_u16(&mut b, 40, e.write_date);
    b[42] = e.create_tenths;
    if e.long_truncated {
        b[43] |= STAT_FLAG_LONG_TRUNCATED;
    }
    b
}

pub fn dirent_record(e: &Entry) -> [u8; 512] {
    let mut b = [0u8; 512];
    put_u32(&mut b, 0, DIRENT_MAGIC);
    put_u16(&mut b, 4, DIRENT_RECORD_LEN);
    b[6] = DIRENT_VERSION;
    b[7] = if e.is_dir() { DIRENT_KIND_DIR } else { DIRENT_KIND_FILE };
    b[8] = e.name().len() as u8;
    put_u16(&mut b, 10, e.long_len() as u16);
    b[12] = e.attr;
    if e.long_truncated {
        b[13] |= DIRENT_FLAG_LONG_TRUNCATED;
    }
    put_u32(&mut b, 16, e.size);
    put_u32(&mut b, 20, e.first_cluster);
    put_u16(&mut b, 24, e.create_time);
    put_u16(&mut b, 26, e.create_date);
    put_u16(&mut b, 28, e.access_date);
    put_u16(&mut b, 30, e.write_time);
    put_u16(&mut b, 32, e.write_date);
    put_u32(&mut b, 36, e.entries_seen);
    put_u32(&mut b, 40, e.lfn_entries);
    put_u32(&mut b, 44, e.lfn_bad);
    b[48..48 + e.name().len()].copy_from_slice(e.name());
    let l = e.long_len();
    b[64..64 + l].copy_from_slice(&e.long_name().unwrap_or(b"")[..l]);
    b
}

fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
