//! FS-01/FS-02：只读 VFS 适配层（ADR-107/108）。
//!
//! 这一层只做四件事：统一路径解析、目录枚举、查表、顺序读。它**不重写 FAT 解析**：
//! 几何、簇链、EOC、FAT16/FAT32 的差异仍由 `fat32.rs` 拥有；这里只按 ADR-107 的口径
//! 把“绝对路径 + 目录项 + 游标”包成一层可判据的接口。
//!
//! 三条硬约束写在这里，改动前先读：
//! 1. **不分配**：路径、名字、游标全是固定上限数组。`heap::LARGE_MAX = 2048`，按输入长度
//!    开缓冲会当场走 ADR-018 的失败出口。
//! 2. **有界**：目录项扫描有 `MAX_DIR_ENTRIES`，簇链有 `MAX_CLUSTERS_WALKED`；损坏镜像
//!    的表现必须是 `Err`，不是“不返回”。
//! 3. **绝对路径**：只收 `/` 开头的路径；`.`/`..` 与组件超限一律拒，不在内核里做
//!    相对路径解析（ADR-107 §2）。
//!
//! FS-02 增补：LFN（校验和/序号/UTF-16→UTF-8）与属性/时间字段。长名固定缓冲
//! `LONG_NAME_MAX` 字节（UTF-8），超限置 `long_truncated`；校验和或序号不对时**退回短名**
//! 并计入 `lfn_bad`，不把坏长名当成“文件不存在”。
//!
//! FS-03 增补：`ReadCursor`/`DirCursor` 自带 `Bpb`，读写/枚举不再借用 `Volume`。句柄表因此
//! 可以存值、放锁后再做盘 I/O；`seek` 从首簇重建簇号，越出 EOF 明确回 `BadOffset`。

use crate::filesystem::fat32::{
    self, Bpb, FatType, FsError, Volume, ATTR_DIR, ATTR_LFN, ATTR_VOLUME, ENTRY_BYTES, MIN_CLUSTER,
};
use crate::filesystem::block_io;
use crate::filesystem::vfs::{Block, BlockError, FileStat, SECTOR_BYTES};

/// 8.3 名字的最长字节数（8 + 点 + 3）。
pub const NAME_MAX: usize = 12;
/// LFN 的 UTF-8 产出上限（字节）。FAT 的长名最多 255 个 UTF-16 单元，UTF-8 可能更长；
/// 这里按常用上限截断并置 `long_truncated`，不按输入长度分配。
pub const LONG_NAME_MAX: usize = 255;
/// 路径长度上限（含开头的 `/`）。
pub const PATH_MAX: usize = 256;
/// 路径分量上限。
pub const MAX_COMPONENTS: usize = 16;
/// 单次目录枚举最多看多少条目录项。与簇链上界分开：固定根目录没有簇链，仍然需要上界。
pub const MAX_DIR_ENTRIES: u32 = 4096;
/// 一条 LFN 最多 20 个片段（每个 13 个 UTF-16 单元）。
const LFN_MAX_ENTRIES: u16 = 20;
const LFN_PER_ENTRY: usize = 13;
const LFN_UNITS: usize = 255;

const OFF_ATTR: usize = 11;
const OFF_CREATE_TENTHS: usize = 13;
const OFF_CREATE_TIME: usize = 14;
const OFF_CREATE_DATE: usize = 16;
const OFF_ACCESS_DATE: usize = 18;
const OFF_CLUSTER_HI: usize = 20;
const OFF_WRITE_TIME: usize = 22;
const OFF_WRITE_DATE: usize = 24;
const OFF_CLUSTER_LO: usize = 26;
const OFF_SIZE: usize = 28;
/// LFN 条目里 13 个 UTF-16 单元的字节偏移。
const LFN_OFFS: [usize; LFN_PER_ENTRY] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
const FIRST_BYTE_FREED: u8 = 0xE5;
const FIRST_BYTE_END: u8 = 0x00;
const ENTRIES_PER_SECTOR: usize = SECTOR_BYTES / ENTRY_BYTES;
/// 与 `fat32::FileCursor` 的坏簇界保持一致：FAT16 从 0xFFF8 起、FAT32 从 0x0FFF_FFF0 起。
const FAT16_DATA_LIMIT: u32 = 0xFFF8;
const FAT32_DATA_LIMIT: u32 = 0x0FFF_FFF0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    /// FAT 解析/块设备层的错误，原样带上去，不在这里抹平成因
    Fs(FsError),
    /// 只接受绝对路径
    NotAbsolute,
    /// 空分量以外的形状错误：`.`、`..`
    BadPath,
    /// 名字、路径或分量数超过固定上限
    TooLong,
    NotFound,
    /// 把普通文件当目录用
    NotDir,
    /// 对目录做文件读取
    IsDir,
    /// 目录项扫描超过上限（损坏的卷或没有结束标记的超大目录）
    DirTooLong,
    /// seek 目标越过 EOF（FS-03 不承诺稀疏 seek）
    BadOffset,
    /// open flags 含本构建尚未批准的能力位
    BadFlags,
}

impl VfsError {
    pub fn tag(self) -> &'static str {
        match self {
            VfsError::Fs(e) => e.tag(),
            VfsError::NotAbsolute => "非绝对路径",
            VfsError::BadPath => "路径形状非法",
            VfsError::TooLong => "路径或名字过长",
            VfsError::NotFound => "目录无此项",
            VfsError::NotDir => "不是目录",
            VfsError::IsDir => "是目录",
            VfsError::DirTooLong => "目录项超限",
            VfsError::BadOffset => "偏移越过 EOF",
            VfsError::BadFlags => "open flags 非法",
        }
    }
}

impl From<FsError> for VfsError {
    fn from(e: FsError) -> Self {
        VfsError::Fs(e)
    }
}

/// 一个目录项在 VFS 层的只读视图。短名恒有；长名仅在 LFN 校验通过时存在。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    name: [u8; NAME_MAX],
    name_len: u8,
    long_name: [u8; LONG_NAME_MAX],
    long_len: u16,
    pub first_cluster: u32,
    pub size: u32,
    pub attr: u8,
    /// 根目录是合成项，没有目录项位置；`first_cluster` 对 FAT16 固定根区无意义。
    pub is_root: bool,
    /// 扫描到这一项时一共看过多少条目录项（含 LFN/删除项），用于证明扫描覆盖面
    pub entries_seen: u32,
    /// 扫描到这一项时一共数到多少条 LFN 项
    pub lfn_entries: u32,
    /// 扫描到这一项时已经拒收多少组坏 LFN（校验和/序号/孤项）
    pub lfn_bad: u32,
    /// 长名超出 `LONG_NAME_MAX` 时置位；内容前缀仍可用
    pub long_truncated: bool,
    /// FAT 目录项的时间/日期字段，**原样**带出（不是墙钟，见 ADR-107 §6）
    pub create_tenths: u8,
    pub create_time: u16,
    pub create_date: u16,
    pub access_date: u16,
    pub write_time: u16,
    pub write_date: u16,
}

impl Entry {
    /// 8.3 短名（恒有）。
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// 长名（LFN 校验通过时才有）。
    pub fn long_name(&self) -> Option<&[u8]> {
        if self.long_len == 0 {
            None
        } else {
            Some(&self.long_name[..self.long_len as usize])
        }
    }

    pub fn long_len(&self) -> usize {
        self.long_len as usize
    }

    /// 展示名：有长名用长名，否则短名。
    pub fn display_name(&self) -> &[u8] {
        self.long_name().unwrap_or_else(|| self.name())
    }

    pub fn is_dir(&self) -> bool {
        self.is_root || self.attr & ATTR_DIR != 0
    }

    pub fn is_readonly(&self) -> bool {
        self.attr & 0x01 != 0
    }

    pub fn is_hidden(&self) -> bool {
        self.attr & 0x02 != 0
    }

    pub fn is_system(&self) -> bool {
        self.attr & 0x04 != 0
    }

    pub fn is_archive(&self) -> bool {
        self.attr & 0x20 != 0
    }

    pub fn is_volume(&self) -> bool {
        self.attr & ATTR_VOLUME != 0
    }

    pub fn is_root_dir(&self) -> bool {
        self.is_root
    }
}

/// 目录枚举的位置：FAT16 根目录是固定区，其余目录（含 FAT32 根）都是簇链。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loc {
    Fixed,
    Cluster,
}

/// 目录游标。固定大小、无分配；自带 `Bpb`，所以句柄可以存值并在锁外继续推进。
#[derive(Debug, Clone, Copy)]
pub struct DirCursor {
    bpb: Bpb,
    loc: Loc,
    cluster: u32,
    lba: u64,
    cluster_left: u32,
    fixed_left: u64,
    in_sector: u8,
    loaded: bool,
    done: bool,
    sector: [u8; SECTOR_BYTES],
    entries_seen: u32,
    lfn_entries: u32,
    walked: u32,
    // 当前短名条目之前那组 LFN 片段的组装状态（FAT 里片段是倒序存放的）。
    lfn_units: [u16; LFN_UNITS],
    lfn_count: u16,
    lfn_mask: u32,
    lfn_sum: u8,
    lfn_active: bool,
    lfn_bad: u32,
}

impl DirCursor {
    pub fn entries_seen(&self) -> u32 {
        self.entries_seen
    }

    pub fn lfn_entries(&self) -> u32 {
        self.lfn_entries
    }

    /// 校验和/序号/孤项不对的 LFN 组数。坏长名退回短名，但这一格必须看得见。
    pub fn lfn_bad(&self) -> u32 {
        self.lfn_bad
    }

    pub fn exhausted(&self) -> bool {
        self.done
    }
}

/// 顺序读取游标。位置只在**整次读成功之后**提交，失败时调用方丢弃 dst 前缀即可重试。
#[derive(Debug, Clone, Copy)]
pub struct ReadCursor {
    bpb: Bpb,
    stat: FileStat,
    cluster: u32,
    position: u32,
    clusters: u32,
}

impl ReadCursor {
    pub fn position(&self) -> u32 {
        self.position
    }

    pub fn size(&self) -> u32 {
        self.stat.size
    }

    pub fn first_cluster(&self) -> u32 {
        self.stat.first_cluster
    }
}

/// 句柄可持久化的目录游标。它不缓存 512 字节目录扇区，也不缓存 LFN 片段；
/// 每次从目录开头走到 `skipped` 之后再取下一条。卷小、只读，这样句柄表不会被
/// `DirCursor` 撑成 1.5 KiB/槽；代价由 FS-03 测试承担，不能当产品吞吐。
#[derive(Debug, Clone, Copy)]
pub struct DirState {
    bpb: Bpb,
    dir: Entry,
    skipped: u32,
    exhausted: bool,
}

impl DirState {
    pub fn new(bpb: &Bpb, dir: &Entry) -> Result<Self, VfsError> {
        new_dir_cursor(bpb, dir)?;
        Ok(DirState { bpb: *bpb, dir: *dir, skipped: 0, exhausted: false })
    }

    pub fn advance(&mut self, disk: &dyn Block) -> Result<Option<Entry>, VfsError> {
        if self.exhausted {
            return Ok(None);
        }
        let mut cur = new_dir_cursor(&self.bpb, &self.dir)?;
        for _ in 0..self.skipped {
            match next_entry_disk(disk, &mut cur)? {
                Some(_) => {}
                None => {
                    self.exhausted = true;
                    return Ok(None);
                }
            }
        }
        match next_entry_disk(disk, &mut cur)? {
            Some(e) => {
                self.skipped += 1;
                self.exhausted = cur.exhausted();
                Ok(Some(e))
            }
            None => {
                self.exhausted = true;
                Ok(None)
            }
        }
    }
}

/// 单根只读文件系统（ADR-107 §3）：一次挂一个卷，挂载点固定在 `/`。
pub struct ReadOnlyFs<'a> {
    vol: Volume<'a>,
}

impl<'a> ReadOnlyFs<'a> {
    pub fn mount(disk: &'a dyn Block) -> Result<Self, VfsError> {
        Volume::mount(disk).map(|vol| ReadOnlyFs { vol }).map_err(VfsError::Fs)
    }

    pub fn bpb(&self) -> Bpb {
        self.vol.bpb
    }

    pub fn root(&self) -> Entry {
        root_entry(&self.vol.bpb)
    }

    /// 解析绝对路径。重复 `/` 折叠；`.`/`..` 一律拒（内核不做相对路径）。
    pub fn lookup(&self, path: &str) -> Result<Entry, VfsError> {
        lookup(self.vol.disk, &self.vol.bpb, path)
    }

    pub fn dir_cursor(&self, dir: &Entry) -> Result<DirCursor, VfsError> {
        new_dir_cursor(&self.vol.bpb, dir)
    }

    pub fn next_entry(&self, cur: &mut DirCursor) -> Result<Option<Entry>, VfsError> {
        next_entry_disk(self.vol.disk, cur)
    }

    /// 打开一个文件的顺序读取游标。目录在 `open` 阶段就拒，避免读路径里再分叉。
    pub fn open(&self, e: &Entry) -> Result<ReadCursor, VfsError> {
        open(self.vol.disk, &self.vol.bpb, e)
    }

    pub fn read(&self, cur: &mut ReadCursor, dst: &mut [u8]) -> Result<usize, VfsError> {
        read_disk(self.vol.disk, cur, dst)
    }

    pub fn seek(&self, cur: &mut ReadCursor, newpos: u32) -> Result<u32, VfsError> {
        seek_disk(self.vol.disk, cur, newpos)
    }
}

pub fn root_entry(bpb: &Bpb) -> Entry {
    let is16 = bpb.fat_type == FatType::Fat16;
    Entry {
        name: [0u8; NAME_MAX],
        name_len: 0,
        long_name: [0u8; LONG_NAME_MAX],
        long_len: 0,
        first_cluster: if is16 { 0 } else { bpb.root_cluster },
        size: 0,
        attr: ATTR_DIR,
        is_root: true,
        entries_seen: 0,
        lfn_entries: 0,
        lfn_bad: 0,
        long_truncated: false,
        create_tenths: 0,
        create_time: 0,
        create_date: 0,
        access_date: 0,
        write_time: 0,
        write_date: 0,
    }
}

/// 独立路径解析器：`disk` 只负责取扇区，`bpb` 是同一挂载的几何快照。
pub fn lookup(disk: &dyn Block, bpb: &Bpb, path: &str) -> Result<Entry, VfsError> {

    if !path.starts_with('/') {
        return Err(VfsError::NotAbsolute);
    }
    if path.len() > PATH_MAX {
        return Err(VfsError::TooLong);
    }
    let mut cur = root_entry(bpb);
    let mut comps = 0usize;
    for part in path.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." {
            return Err(VfsError::BadPath);
        }
        if part.len() > LONG_NAME_MAX {
            return Err(VfsError::TooLong);
        }
        comps += 1;
        if comps > MAX_COMPONENTS {
            return Err(VfsError::TooLong);
        }
        if !cur.is_dir() {
            return Err(VfsError::NotDir);
        }
        cur = find_child(disk, bpb, &cur, part.as_bytes())?;
    }
    Ok(cur)
}

/// 在一个目录里找一个名字。
fn find_child(disk: &dyn Block, bpb: &Bpb, dir: &Entry, want: &[u8]) -> Result<Entry, VfsError> {
    let mut cur = new_dir_cursor(bpb, dir)?;
    while let Some(e) = next_entry_disk(disk, &mut cur)? {
        if entry_matches(&e, want) {
            return Ok(e);
        }
    }
    Err(VfsError::NotFound)
}

pub fn new_dir_cursor(bpb: &Bpb, dir: &Entry) -> Result<DirCursor, VfsError> {
    if !dir.is_dir() {
        return Err(VfsError::NotDir);
    }
    let v = *bpb;
    let (loc, cluster, lba, cluster_left, fixed_left) = if dir.is_root {
        if v.fat_type == FatType::Fat16 {
            let root_lba = v.reserved_sectors as u64 + v.fat_count as u64 * v.sectors_per_fat as u64;
            (Loc::Fixed, 0, root_lba, 0, v.root_dir_sectors)
        } else {
            let c = v.root_cluster;
            check_entry_cluster(&v, c)?;
            (Loc::Cluster, c, cluster_to_lba(&v, c), v.sectors_per_cluster as u32, 0)
        }
    } else {
        let c = dir.first_cluster;
        check_entry_cluster(&v, c)?;
        (Loc::Cluster, c, cluster_to_lba(&v, c), v.sectors_per_cluster as u32, 0)
    };
    Ok(DirCursor {
        bpb: v,
        loc,
        cluster,
        lba,
        cluster_left,
        fixed_left,
        in_sector: 0,
        loaded: false,
        done: false,
        sector: [0u8; SECTOR_BYTES],
        entries_seen: 0,
        lfn_entries: 0,
        walked: 0,
        lfn_units: [0u16; LFN_UNITS],
        lfn_count: 0,
        lfn_mask: 0,
        lfn_sum: 0,
        lfn_active: false,
        lfn_bad: 0,
    })
}

/// 取下一条目录项。跳过删除项、卷标、`.`/`..`；LFN 组装成功才挂长名。
pub fn next_entry_disk(disk: &dyn Block, cur: &mut DirCursor) -> Result<Option<Entry>, VfsError> {
    loop {
        if cur.done {
            return Ok(None);
        }
        if !cur.loaded && !load_sector(disk, cur)? {
            return Ok(None);
        }
        let off = cur.in_sector as usize * ENTRY_BYTES;
        let mut e = [0u8; ENTRY_BYTES];
        e.copy_from_slice(&cur.sector[off..off + ENTRY_BYTES]);
        cur.in_sector += 1;
        if cur.in_sector as usize == ENTRIES_PER_SECTOR {
            cur.loaded = false;
        }
        if e[0] == FIRST_BYTE_END {
            // 没有短名条目接住的 LFN 是孤项：计数并丢弃，不把它挂到下一项上。
            if cur.lfn_active {
                cur.lfn_bad += 1;
                reset_lfn(cur);
            }
            cur.done = true;
            return Ok(None);
        }
        cur.entries_seen += 1;
        if cur.entries_seen > MAX_DIR_ENTRIES {
            return Err(VfsError::DirTooLong);
        }
        if e[0] == FIRST_BYTE_FREED {
            if cur.lfn_active {
                cur.lfn_bad += 1;
                reset_lfn(cur);
            }
            continue;
        }
        let attr = e[OFF_ATTR];
        if attr == ATTR_LFN {
            cur.lfn_entries += 1;
            note_lfn(cur, &e);
            continue;
        }
        if attr & ATTR_VOLUME != 0 {
            if cur.lfn_active {
                cur.lfn_bad += 1;
                reset_lfn(cur);
            }
            continue;
        }
        if e[0] == b'.' {
            if cur.lfn_active {
                cur.lfn_bad += 1;
                reset_lfn(cur);
            }
            continue;
        }
        let mut name = [0u8; NAME_MAX];
        let name_len = build_name(&e, &mut name);
        if name_len == 0 {
            reset_lfn(cur);
            continue;
        }
        let mut long_name = [0u8; LONG_NAME_MAX];
        let (long_len, long_truncated) = take_lfn(cur, &e, &mut long_name);
        let first = if cur.bpb.fat_type == FatType::Fat16 {
            u16_at(&e, OFF_CLUSTER_LO) as u32
        } else {
            ((u16_at(&e, OFF_CLUSTER_HI) as u32) << 16) | u16_at(&e, OFF_CLUSTER_LO) as u32
        };
        let size = u32_at(&e, OFF_SIZE);
        let is_dir = attr & ATTR_DIR != 0;
        // 目录项里的簇号先核界，再交给上层；越界不是“读失败”，是卷坏了。
        if is_dir || size > 0 {
            check_entry_cluster(&cur.bpb, first)?;
        }
        return Ok(Some(Entry {
            name,
            name_len: name_len as u8,
            long_name,
            long_len,
            first_cluster: first,
            size,
            attr,
            is_root: false,
            entries_seen: cur.entries_seen,
            lfn_entries: cur.lfn_entries,
            lfn_bad: cur.lfn_bad,
            long_truncated,
            create_tenths: e[OFF_CREATE_TENTHS],
            create_time: u16_at(&e, OFF_CREATE_TIME),
            create_date: u16_at(&e, OFF_CREATE_DATE),
            access_date: u16_at(&e, OFF_ACCESS_DATE),
            write_time: u16_at(&e, OFF_WRITE_TIME),
            write_date: u16_at(&e, OFF_WRITE_DATE),
        }));
    }
}

fn load_sector(disk: &dyn Block, cur: &mut DirCursor) -> Result<bool, VfsError> {
    let v = cur.bpb;
    match cur.loc {
        Loc::Fixed => {
            if cur.fixed_left == 0 {
                cur.done = true;
                return Ok(false);
            }
            block_io::read_checked(disk, cur.lba, &mut cur.sector, &block_io::Budget::UNBOUNDED).map_err(io)?;
            cur.lba += 1;
            cur.fixed_left -= 1;
        }
        Loc::Cluster => {
            if cur.cluster_left == 0 {
                let next = fat_next_disk(disk, &v, cur.cluster).map_err(VfsError::Fs)?;
                if next >= v.eoc_marker {
                    cur.done = true;
                    return Ok(false);
                }
                check_entry_cluster(&v, next)?;
                cur.walked += 1;
                if cur.walked > fat32::MAX_CLUSTERS_WALKED {
                    return Err(VfsError::Fs(FsError::ChainTooLong));
                }
                cur.cluster = next;
                cur.lba = cluster_to_lba(&v, next);
                cur.cluster_left = v.sectors_per_cluster as u32;
            }
            block_io::read_checked(disk, cur.lba, &mut cur.sector, &block_io::Budget::UNBOUNDED).map_err(io)?;
            cur.lba += 1;
            cur.cluster_left -= 1;
        }
    }
    cur.loaded = true;
    cur.in_sector = 0;
    Ok(true)
}

pub fn open(disk: &dyn Block, bpb: &Bpb, e: &Entry) -> Result<ReadCursor, VfsError> {
    if e.is_dir() {
        return Err(VfsError::IsDir);
    }
    if e.size > 0 {
        data_lba(bpb, e.first_cluster)?;
    }
    Ok(ReadCursor {
        bpb: *bpb,
        stat: FileStat {
            size: e.size,
            first_cluster: e.first_cluster,
            entries_seen: e.entries_seen,
            lfn_entries: e.lfn_entries,
        },
        cluster: e.first_cluster,
        position: 0,
        clusters: 0,
    })
}

/// 独立顺序读。Err 时游标不变；成功时只提交真正交付给调用方的字节数。
pub fn read_disk(disk: &dyn Block, cur: &mut ReadCursor, dst: &mut [u8]) -> Result<usize, VfsError> {

    if cur.position >= cur.stat.size || dst.is_empty() {
        return Ok(0);
    }
    let v = cur.bpb;
    let want = core::cmp::min(dst.len(), (cur.stat.size - cur.position) as usize);
    let mut pending = *cur;
    let mut done = 0usize;
    let mut sector = [0u8; SECTOR_BYTES];
    while done < want {
        if pending.clusters >= fat32::MAX_CLUSTERS_WALKED {
            return Err(VfsError::Fs(FsError::ChainTooLong));
        }
        let cluster_off = pending.position as usize % v.cluster_bytes;
        let lba = data_lba(&v, pending.cluster)? + (cluster_off / SECTOR_BYTES) as u64;
        block_io::read_checked(disk, lba, &mut sector, &block_io::Budget::UNBOUNDED).map_err(io)?;
        let sector_off = cluster_off % SECTOR_BYTES;
        let take = core::cmp::min(want - done, SECTOR_BYTES - sector_off);
        dst[done..done + take].copy_from_slice(&sector[sector_off..sector_off + take]);
        pending.position += take as u32;
        done += take;
        if cluster_off + take == v.cluster_bytes || pending.position == pending.stat.size {
            let next = fat_next_disk(disk, &v, pending.cluster).map_err(VfsError::Fs)?;
            let at_end = pending.position == pending.stat.size;
            if next >= v.eoc_marker {
                if !at_end {
                    return Err(VfsError::Fs(FsError::ChainEndsEarly {
                        bytes: pending.position as usize,
                        size: pending.stat.size,
                        cluster: pending.cluster,
                        next,
                    }));
                }
            } else {
                if at_end {
                    return Err(VfsError::Fs(FsError::ChainEndsLate {
                        bytes: pending.position as usize,
                        size: pending.stat.size,
                        cluster: pending.cluster,
                        next,
                    }));
                }
                data_lba(&v, next)?;
                pending.cluster = next;
            }
            pending.clusters += 1;
        }
    }
    *cur = pending;
    Ok(done)
}

/// seek 从首簇重建簇号；只允许 `0..=size`，FS-03 不承诺稀疏 seek。
pub fn seek_disk(disk: &dyn Block, cur: &mut ReadCursor, newpos: u32) -> Result<u32, VfsError> {
    if newpos > cur.stat.size {
        return Err(VfsError::BadOffset);
    }
    let v = cur.bpb;
    if newpos == cur.position {
        if newpos < cur.stat.size {
            data_lba(&v, cur.cluster)?;
        }
        return Ok(newpos);
    }
    let mut pending = *cur;
    pending.position = newpos;
    pending.cluster = cur.stat.first_cluster;
    pending.clusters = 0;
    if newpos == cur.stat.size {
        *cur = pending;
        return Ok(newpos);
    }
    let target = (newpos as usize / v.cluster_bytes) as u32;
    if target > fat32::MAX_CLUSTERS_WALKED {
        return Err(VfsError::Fs(FsError::ChainTooLong));
    }
    let mut cluster = cur.stat.first_cluster;
    data_lba(&v, cluster)?;
    for _ in 0..target {
        let next = fat_next_disk(disk, &v, cluster).map_err(VfsError::Fs)?;
        if next >= v.eoc_marker {
            return Err(VfsError::Fs(FsError::ChainEndsEarly {
                bytes: newpos as usize,
                size: cur.stat.size,
                cluster,
                next,
            }));
        }
        data_lba(&v, next)?;
        cluster = next;
    }
    pending.cluster = cluster;
    pending.clusters = target;
    *cur = pending;
    Ok(newpos)
}

fn cluster_to_lba(v: &Bpb, c: u32) -> u64 {
    v.data_start + (c as u64 - MIN_CLUSTER as u64) * v.sectors_per_cluster as u64
}

fn fat_next_disk(disk: &dyn Block, v: &Bpb, cluster: u32) -> Result<u32, FsError> {
    if cluster < MIN_CLUSTER {
        return Err(FsError::BadCluster(cluster));
    }
    let byte_off = cluster as usize * v.fat_entry_bytes;
    let lba = v.reserved_sectors as u64 + (byte_off / SECTOR_BYTES) as u64;
    let mut sec = [0u8; SECTOR_BYTES];
    block_io::read_checked(disk, lba, &mut sec, &block_io::Budget::UNBOUNDED).map_err(FsError::Io)?;
    let in_sec = byte_off % SECTOR_BYTES;
    if in_sec + v.fat_entry_bytes > SECTOR_BYTES {
        return Err(FsError::BadCluster(cluster));
    }
    Ok(if v.fat_entry_bytes == fat32::FAT16_ENTRY_BYTES {
        u32::from(u16_at(&sec, in_sec)) & v.cluster_mask
    } else {
        u32_at(&sec, in_sec) & v.cluster_mask
    })
}

fn check_entry_cluster(v: &Bpb, c: u32) -> Result<(), VfsError> {
    if c < MIN_CLUSTER || c > v.max_good_cluster || (c - MIN_CLUSTER) as u64 >= v.clusters {
        return Err(VfsError::Fs(FsError::EntryOutsideData(c)));
    }
    Ok(())
}

/// 覆盖写（ADR-111 决策 1）：从游标当前位置开始，**只覆盖已有区间**。
///
/// 这一层刻意不做创建/截断/扩展：那要分配簇、改两份 FAT、改 FSInfo、改目录项大小，
/// 是另一刀。越 EOF 时**整次拒绝**（`BadOffset`）并且一个字节都不写——部分写会让调用方
/// 以为成功，而它拿到的是"写了一半"。
///
/// 非整扇区的那几段必须**读-改-写**：直接写整扇区会把同一扇区里没被请求的邻居字节一起改掉，
/// 这是写方向最典型的一种错，`vfs-ro: 写方向` 那几格专门盯着它。
pub fn write_at(disk: &dyn Block, cur: &mut ReadCursor, src: &[u8]) -> Result<usize, VfsError> {
    if src.is_empty() {
        return Ok(0);
    }
    let start = cur.position as usize;
    let end = start.checked_add(src.len()).ok_or(VfsError::BadOffset)?;
    if end > cur.stat.size as usize {
        return Err(VfsError::BadOffset);
    }
    let mut done = 0usize;
    while done < src.len() {
        let pos = cur.position as usize;
        seek_disk(disk, cur, pos as u32)?;
        let v = cur.bpb;
        let base = data_lba(&v, cur.cluster)?;
        let off_in_cluster = pos % v.cluster_bytes;
        let in_sector = pos % SECTOR_BYTES;
        let lba = base + (off_in_cluster / SECTOR_BYTES) as u64;
        let take = core::cmp::min(SECTOR_BYTES - in_sector, src.len() - done);
        if in_sector != 0 || take != SECTOR_BYTES {
            let mut sec = [0u8; SECTOR_BYTES];
            block_io::read_checked(disk, lba, &mut sec, &block_io::Budget::UNBOUNDED).map_err(io)?;
            sec[in_sector..in_sector + take].copy_from_slice(&src[done..done + take]);
            disk.write_sectors(lba, &sec).map_err(io)?;
        } else {
            disk.write_sectors(lba, &src[done..done + take]).map_err(io)?;
        }
        done += take;
        cur.position += take as u32;
    }
    Ok(done)
}

fn data_lba(v: &Bpb, c: u32) -> Result<u64, VfsError> {
    let limit = if v.fat_type == FatType::Fat16 { FAT16_DATA_LIMIT } else { FAT32_DATA_LIMIT };
    if c < MIN_CLUSTER || c >= limit || (c - MIN_CLUSTER) as u64 >= v.clusters {
        return Err(VfsError::Fs(FsError::BadCluster(c)));
    }
    Ok(v.data_start + (c - MIN_CLUSTER) as u64 * v.sectors_per_cluster as u64)
}

fn io(e: BlockError) -> VfsError {
    VfsError::Fs(FsError::Io(e))
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    (b[off] as u16) | ((b[off + 1] as u16) << 8)
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    (b[off] as u32) | ((b[off + 1] as u32) << 8) | ((b[off + 2] as u32) << 16) | ((b[off + 3] as u32) << 24)
}

/// 从 32 字节目录项拼 8.3 短名：去尾随空格，扩展名非空才补点。
/// 第一字节 0x05 是规范里的“真名以 0xE5 开头”，按 0xE5 还原。
fn build_name(e: &[u8], out: &mut [u8; NAME_MAX]) -> usize {
    let mut n = 0usize;
    let mut first = e[0];
    if first == 0x05 {
        first = 0xE5;
    }
    if first != b' ' {
        out[n] = first;
        n += 1;
    }
    let mut i = 1usize;
    while i < 8 {
        if e[i] == b' ' {
            break;
        }
        out[n] = e[i];
        n += 1;
        i += 1;
    }
    let mut has_ext = false;
    let mut j = 8usize;
    while j < 11 {
        if e[j] == b' ' {
            break;
        }
        if !has_ext {
            out[n] = b'.';
            n += 1;
            has_ext = true;
        }
        out[n] = e[j];
        n += 1;
        j += 1;
    }
    n
}

/// FAT 的短名校验和（对 11 个原始字节做 rotate-right-1 累加）。LFN 条目用它绑定短名。
fn short_checksum(e: &[u8]) -> u8 {
    let mut sum = 0u8;
    for i in 0..11 {
        sum = sum.rotate_right(1).wrapping_add(e[i]);
    }
    sum
}

fn reset_lfn(cur: &mut DirCursor) {
    cur.lfn_active = false;
    cur.lfn_count = 0;
    cur.lfn_mask = 0;
    cur.lfn_sum = 0;
}

/// 收一条 LFN 片段。FAT 把片段**倒序**放：最后一条带 0x40 且序号最大，先到。
fn note_lfn(cur: &mut DirCursor, e: &[u8]) {
    let ord = (e[0] & 0x1F) as u16;
    let last = e[0] & 0x40 != 0;
    let sum = e[13];
    if ord == 0 || ord > LFN_MAX_ENTRIES {
        cur.lfn_bad += 1;
        reset_lfn(cur);
        return;
    }
    if last {
        if cur.lfn_active {
            cur.lfn_bad += 1;
        }
        cur.lfn_active = true;
        cur.lfn_count = ord;
        cur.lfn_sum = sum;
        cur.lfn_mask = 0;
        cur.lfn_units = [0u16; LFN_UNITS];
    } else if !cur.lfn_active || sum != cur.lfn_sum || ord > cur.lfn_count {
        cur.lfn_bad += 1;
        reset_lfn(cur);
        return;
    }
    let bit = 1u32 << (ord - 1);
    if cur.lfn_mask & bit != 0 {
        cur.lfn_bad += 1;
        reset_lfn(cur);
        return;
    }
    cur.lfn_mask |= bit;
    let base = (ord as usize - 1) * LFN_PER_ENTRY;
    for (k, &off) in LFN_OFFS.iter().enumerate() {
        if base + k < LFN_UNITS {
            cur.lfn_units[base + k] = u16_at(e, off);
        }
    }
}

/// 短名条目到达时收尾：序号齐、校验和匹配才产出长名；否则退回短名并计数。
fn take_lfn(cur: &mut DirCursor, short: &[u8], out: &mut [u8; LONG_NAME_MAX]) -> (u16, bool) {
    if !cur.lfn_active {
        return (0, false);
    }
    let count = cur.lfn_count as u32;
    let expected = if count >= 32 { u32::MAX } else { (1u32 << count) - 1 };
    let valid = count >= 1
        && cur.lfn_count <= LFN_MAX_ENTRIES
        && cur.lfn_mask == expected
        && cur.lfn_sum == short_checksum(short);
    reset_lfn(cur);
    if !valid {
        cur.lfn_bad += 1;
        return (0, false);
    }
    let units = count as usize * LFN_PER_ENTRY;
    let slice = &cur.lfn_units[..units.min(LFN_UNITS)];
    match decode_lfn(slice, out) {
        Some((n, trunc)) => (n as u16, trunc),
        None => {
            cur.lfn_bad += 1;
            (0, false)
        }
    }
}

/// UTF-16LE 单元 → UTF-8。遇到 0 截止，跳过 0xFFFF 填充；孤立代理项按坏长名处理。
fn decode_lfn(units: &[u16], out: &mut [u8; LONG_NAME_MAX]) -> Option<(usize, bool)> {
    let mut n = 0usize;
    let mut i = 0usize;
    let mut trunc = false;
    while i < units.len() {
        let u = units[i];
        if u == 0 {
            break;
        }
        if u == 0xFFFF {
            i += 1;
            continue;
        }
        let (cp, adv) = if (0xD800..=0xDBFF).contains(&u) {
            if i + 1 >= units.len() {
                return None;
            }
            let lo = units[i + 1];
            if !(0xDC00..=0xDFFF).contains(&lo) {
                return None;
            }
            (0x10000 + (((u as u32) - 0xD800) << 10) + ((lo as u32) - 0xDC00), 2)
        } else if (0xDC00..=0xDFFF).contains(&u) {
            return None;
        } else {
            (u as u32, 1)
        };
        let ch = core::char::from_u32(cp)?;
        let mut tmp = [0u8; 4];
        let s = ch.encode_utf8(&mut tmp).as_bytes();
        if n + s.len() > out.len() {
            trunc = true;
            break;
        }
        out[n..n + s.len()].copy_from_slice(s);
        n += s.len();
        i += adv;
    }
    Some((n, trunc))
}

fn bytes_eq_ci(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).all(|(x, y)| {
        if x.is_ascii() && y.is_ascii() {
            x.eq_ignore_ascii_case(y)
        } else {
            x == y
        }
    })
}

/// 路径分量可以命中短名或长名；ASCII 大小写不敏感，非 ASCII 按字节精确比。
fn entry_matches(e: &Entry, want: &[u8]) -> bool {
    if bytes_eq_ci(e.name(), want) {
        return true;
    }
    match e.long_name() {
        Some(n) => bytes_eq_ci(n, want),
        None => false,
    }
}
