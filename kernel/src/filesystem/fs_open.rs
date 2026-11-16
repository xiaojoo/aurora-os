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

/// 默认挂载口。口号与 `tools/aurora.py` 的 `FS_OPEN_PORTS` 各写一份，由 `check-fat32-ports` 对账。
///
/// **A3 切片（ADR-131）：从"编译期分档"改成"运行期单次切换"。** 编译期切口的代价是：
/// `a3-exec` 依赖 `fs-open`（22 号的模块门），于是同一份构建里 fs-open 的用例也在跑，
/// 而它们要口 5 的 deep 卷——编译期把 `PORT` 改成 3 会让那一批用例当场红
/// （2026-11-17 实测：`t_fs_open_ring3`/`t_fs_open_syscalls` 两行 failed）。
/// 现在：默认仍是 5（用例口径不变）；`a3-exec` 的编排在启动命令解释器**之前**
/// 调 [`set_port(3)`](set_port) 把挂根换到卷A（根目录有 HELLO.ELF）。
/// **约定**：`set_port` 只允许在"还没有任何 VFS 句柄"时调用（句柄里存的是口号，
/// 换口之后旧句柄会挂到新卷上）。今天的调用点只有 a3-exec 的 stage，在用例跑完之后。
pub const PORT: u8 = 5;

/// 运行期挂根（0 = 用 [`PORT`] 的默认值）。A3 的 a3-exec 档在起命令解释器前设成 3。
///
/// **为什么是 `static mut` 而不是 `AtomicU8`**：本模块属于 `storage` 组，ADR-044 的棘轮
/// 规定"环内引用只许减不许增"——引入 `core::sync::atomic` 会在这个模块上新增
/// `storage -> sync` 的引用站点（实测 3 处），那要动棘轮登记，而这条开关不需要原子语义：
/// **单写者**（boot 期 a3-exec 编排一次 `set_port`，此后只读）、单字节、无并发窗口
/// （调用点在任何一个用户任务跑起来之前）。所以用 volatile 读写把这件事写清楚，
/// 而不是借一个"看起来更安全"的原子类型去撞模块棘轮。
static mut PORT_LIVE: u8 = 0;

/// 当前生效的挂根口号。
#[must_use]
pub fn port() -> u8 {
    // SAFETY: 单字节；唯一的写者 `set_port` 在 boot 期、任何用户任务起来之前跑完，
    // 之后整机只读。`addr_of!` 不创造引用（`static_mut_refs` 那条 lint 的正当写法）。
    let p = unsafe { core::ptr::addr_of!(PORT_LIVE).read_volatile() };
    if p == 0 {
        PORT
    } else {
        p
    }
}

/// 切挂根（见 [`PORT`] 的约定：只允许在任何 VFS 句柄创建之前调用）。
pub fn set_port(p: u8) {
    // SAFETY: 同上——唯一的写者、单字节、跑在任何用户任务之前。
    unsafe { core::ptr::addr_of_mut!(PORT_LIVE).write_volatile(p) }
}
pub const OPEN_READ_ONLY: u64 = 0;

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

// 每口一份 `'static` 盘描述：`ReadOnlyFs::mount` 要 `&'static AhciDisk`（它把盘借进
// 挂载结果里），所以不能按当前口号临时构造一个。
static DISK_DEEP: AhciDisk = AhciDisk { port: 5 };
static DISK_SMALL: AhciDisk = AhciDisk { port: 3 };

/// 当前口号对应的盘描述。
fn disk() -> &'static AhciDisk {
    if port() == 3 {
        &DISK_SMALL
    } else {
        &DISK_DEEP
    }
}

/// open 成功后、进入句柄表之前的一份状态。调用方负责把其中的游标与元数据放进
/// capability 对象；这层不能反过来调用 capability，否则 storage 会被迫认识句柄表。
#[derive(Debug, Clone, Copy)]
pub enum Opened {
    File { cursor: vfs_ro::ReadCursor, stat: Entry },
    Dir { state: DirState, stat: Entry },
}

pub fn mount() -> Result<ReadOnlyFs<'static>, VfsError> {
    ReadOnlyFs::mount(disk())
}

pub fn open(path: &str, flags: u64) -> Result<Opened, VfsError> {

    if flags != OPEN_READ_ONLY {
        return Err(VfsError::BadFlags);
    }
    let fs = mount()?;
    let stat = fs.lookup(path)?;
    if stat.is_dir() {
        let state = DirState::new(&fs.bpb(), &stat)?;
        Ok(Opened::Dir { state, stat })
    } else {
        let cursor = fs.open(&stat)?;
        Ok(Opened::File { cursor, stat })
    }
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
