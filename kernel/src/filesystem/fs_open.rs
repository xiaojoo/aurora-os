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

/// `/` 这一项的**运行期根**（0 = 用 [`PORT`] 的默认值 5）。A3（ADR-131）在起命令解释器
/// 之前 `set_port(3)` 把 `/` 换到卷A（根目录有 HELLO.ELF）。与 `/w` 无关：可写挂载的表项
/// 自带口号，不受它影响。
///
/// **单写者**（boot 期编排一次，此后只读）、单字节、无并发窗口；约定"只允许在任何 VFS
/// 句柄创建之前调用"（句柄里存的是解析后的口号）。用 volatile 把这件事写清楚，不引原子。
static mut ROOT_PORT: u8 = 0;

/// 当前 `/` 的根口号。
#[must_use]
pub fn port() -> u8 {
    // SAFETY: 单字节；唯一写者 `set_port` 在任何用户任务之前跑完，之后整机只读。
    let p = unsafe { core::ptr::addr_of!(ROOT_PORT).read_volatile() };
    if p == 0 { PORT } else { p }
}

/// 切 `/` 的根（见 [`port`] 的约定）。
pub fn set_port(p: u8) {
    // SAFETY: 同上——唯一写者、单字节、跑在任何用户任务之前。
    unsafe { core::ptr::addr_of_mut!(ROOT_PORT).write_volatile(p) }
}
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

/// open 成功后、进入句柄表之前的一份状态。`port` 由挂载表决定（ADR-114）：
/// 调用方按它授句柄，不要再自己从 flags 推一个口——那会让"路径落在哪个根"有两份答案。
#[derive(Debug, Clone, Copy)]
pub enum Opened {
    File { port: u8, cursor: vfs_ro::ReadCursor, stat: Entry },
    Dir { port: u8, state: DirState, stat: Entry },
}

/// 一个挂载点：`prefix` 是命名空间里的前缀，`writable` 决定写意图能不能在这儿过。
#[derive(Debug, Clone, Copy)]
pub struct MountEntry {
    pub prefix: &'static str,
    pub port: u8,
    pub writable: bool,
}

/// 静态挂载表（ADR-114）：最长前缀先匹配。`/` 是只读根（口 5）；
/// `/w` 是可写卷（口 4），只在 `fs-rw` 档存在。
#[cfg(feature = "fs-rw")]
pub const MOUNTS: &[MountEntry] = &[
    MountEntry { prefix: "/w", port: crate::filesystem::fs_rw::PORT, writable: true },
    MountEntry { prefix: "/", port: PORT, writable: false },
];
#[cfg(not(feature = "fs-rw"))]
pub const MOUNTS: &[MountEntry] = &[MountEntry { prefix: "/", port: PORT, writable: false }];

/// 把绝对路径解析成（挂载点，去掉前缀后的路径）。不跨根拼接：一个路径只落一个根。
fn resolve(path: &str) -> Result<(&'static MountEntry, &str), VfsError> {
    if !path.starts_with('/') {
        return Err(VfsError::BadPath);
    }
    let mut best: Option<(&'static MountEntry, &str)> = None;
    for m in MOUNTS {
        let sub = if m.prefix == "/" {
            Some(path)
        } else if path == m.prefix {
            Some("/")
        } else {
            path.strip_prefix(m.prefix).filter(|rest| rest.starts_with('/'))
        };
        if let Some(sub) = sub {
            if best.map_or(true, |(b, _)| m.prefix.len() > b.prefix.len()) {
                best = Some((m, sub));
            }
        }
    }
    best.ok_or(VfsError::BadPath)
}

// 每口一份 `'static` 盘描述：`mount()` 的返回把盘借进去，不能按口号临时构造。
static DISK_DEEP: AhciDisk = AhciDisk { port: PORT };
static DISK_SMALL: AhciDisk = AhciDisk { port: 3 };

fn disk() -> &'static AhciDisk {
    if port() == 3 { &DISK_SMALL } else { &DISK_DEEP }
}

pub fn mount() -> Result<ReadOnlyFs<'static>, VfsError> {
    ReadOnlyFs::mount(disk())
}

fn open_on(port: u8, path: &str, flags: u64) -> Result<Opened, VfsError> {
    let disk = AhciDisk { port };
    let fs = ReadOnlyFs::mount(&disk)?;
    let stat = fs.lookup(path)?;
    if stat.is_dir() {
        // 写意图打在目录上没有意义（创建/截断是另一刀）。
        if flags == OPEN_WRITE {
            return Err(VfsError::BadFlags);
        }
        let state = DirState::new(&fs.bpb(), &stat)?;
        Ok(Opened::Dir { port, state, stat })
    } else {
        let cursor = fs.open(&stat)?;
        Ok(Opened::File { port, cursor, stat })
    }
}

/// 按挂载表打开。`flags`：0 = 读意图；1 = 写意图（只允许落在可写挂载上）；
/// 其余位 ⇒ `BadFlags`（对用户 `-15`）。写意图打在目录上同样 `BadFlags`。
pub fn open(path: &str, flags: u64) -> Result<Opened, VfsError> {
    if flags != OPEN_READ_ONLY && flags != OPEN_WRITE {
        return Err(VfsError::BadFlags);
    }
    let (m, sub) = resolve(path)?;
    if flags == OPEN_WRITE && !m.writable {
        return Err(VfsError::BadFlags);
    }
    // `/` 是运行期根（`set_port` 换的就是它）；其余表项用自己登记的口号。
    let port = if m.prefix == "/" { self::port() } else { m.port };
    open_on(port, sub, flags)
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
