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
    /// 名字不合 8.3（含长名、非法字符、双点）：ADR-118 明写长名创建不在这一刀
    BadName,
    /// 同目录里已有同名短名项（`create` 的拒绝格）。
    /// **与 `BadFlags` 分开**：这是「目标已存在」，调用方该去 open 而不是改参数。
    /// 今天映射成 `-1`——`EEXIST` 没有号位（ADR-177 决策 4：不预先编号）。
    AlreadyExists,
    /// 目录里没有空槽了（整条目录链都满）
    DirFull,
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
            VfsError::BadName => "名字不合 8.3",
            VfsError::AlreadyExists => "目标已存在",
            VfsError::DirFull => "目录已满",
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
// ---------------------------------------------------------------- 写方向：创建与删除
// （ADR-177 决策 1 的文件族 70/71；ADR-118 的原意，换号后落地）

/// 一条目录项的固定长度（FAT32 规范）。
const DIR_ENTRY: usize = 32;
/// 目录项首字节的两个哨兵：`0x00` = 本扇区之后再无条目；`0xE5` = 已删除、可复用。
const DIR_END: u8 = 0x00;
const DIR_FREED: u8 = 0xE5;
/// 普通文件属性（目录是 0x10，长名是 0x0F）。
const ATTR_ARCHIVE: u8 = 0x20;

/// 把一份 FAT 表里某个簇的项写成 `value`（`v.fat_count` 份都要写，否则两份 FAT 不一致）。
///
/// **为什么两份都要写**：只改一份，另一份就是坏的。某些工具与 Windows 的 chkdsk 会读第二份，
/// 而本仓的宿主机对账（`fat32_host_volume`）也读它。少写一份 = 卷在另一个读者眼里是坏的。
fn fat_set_disk(disk: &dyn Block, v: &Bpb, cluster: u32, value: u32) -> Result<(), FsError> {
    if cluster < MIN_CLUSTER {
        return Err(FsError::BadCluster(cluster));
    }
    let byte_off = cluster as usize * v.fat_entry_bytes;
    let in_sec = byte_off % SECTOR_BYTES;
    if in_sec + v.fat_entry_bytes > SECTOR_BYTES {
        return Err(FsError::BadCluster(cluster));
    }
    // FAT 区从保留扇区开始，第 i 份在 i * sectors_per_fat 之后
    for copy in 0..v.fat_count as u64 {
        let lba = v.reserved_sectors as u64
            + copy * v.sectors_per_fat as u64
            + (byte_off / SECTOR_BYTES) as u64;
        let mut sec = [0u8; SECTOR_BYTES];
        block_io::read_checked(disk, lba, &mut sec, &block_io::Budget::UNBOUNDED).map_err(FsError::Io)?;
        if v.fat_entry_bytes == fat32::FAT16_ENTRY_BYTES {
            // 高 16 位在 FAT16 里是保留的，写 0 而不是把 value 的高位带进去
            let le = (value as u16).to_le_bytes();
            sec[in_sec..in_sec + 2].copy_from_slice(&le);
        } else {
            // **只改低 28 位**：高 4 位是保留位，规范要求写 0，
            // 而读出时 `& cluster_mask` 会掩掉它们——不在这里清，两份 FAT 就会在保留位上分叉。
            let old = u32_at(&sec, in_sec);
            let merged = (old & !v.cluster_mask) | (value & v.cluster_mask);
            sec[in_sec..in_sec + 4].copy_from_slice(&merged.to_le_bytes());
        }
        disk.write_sectors(lba, &sec).map_err(FsError::Io)?;
    }
    Ok(())
}

/// 找**第一个空闲簇**并把它标成链尾（EOC）。返回簇号。
///
/// 从 `MIN_CLUSTER` 线性扫到 `max_good_cluster`：没有 FSInfo 的空闲簇提示就退化成线性扫，
/// 这是慢但**正确**的路。用 FSInfo 的提示要先证明提示可信，而今天没有那个证明。
fn alloc_cluster(disk: &dyn Block, v: &Bpb) -> Result<u32, FsError> {
    let mut c = MIN_CLUSTER;
    while c <= v.max_good_cluster && ((c - MIN_CLUSTER) as u64) < v.clusters {
        let next = fat_next_disk(disk, v, c)?;
        if next == 0 {
            // 空闲：标成链尾
            let eoc = if v.fat_entry_bytes == fat32::FAT16_ENTRY_BYTES {
                fat32::FAT16_EOC_MARKER
            } else {
                fat32::EOC_MARKER
            };
            fat_set_disk(disk, v, c, eoc)?;
            return Ok(c);
        }
        c += 1;
    }
    Err(FsError::NoFreeCluster)
}

/// 把 8.3 短名编码成 11 字节的目录项名字段（名字 8 字节 + 扩展名 3 字节，空格填充）。
///
/// 只收 8.3：带长名或含非法字符一律 `None`（ADR-118：长名创建不在这一刀）。
fn encode_short_name(path: &[u8]) -> Option<[u8; 11]> {
    let mut out = [b' '; 11];
    if path.is_empty() || path.len() > 12 {
        return None;
    }
    let mut name_len = 0usize;
    let mut ext_len = 0usize;
    let mut in_ext = false;
    for &b in path {
        if b == b'.' {
            if in_ext || name_len == 0 {
                return None; // 双点、点开头都不合法
            }
            in_ext = true;
            continue;
        }
        let up = b.to_ascii_uppercase();
        // 合法字符：字母数字与 $%'-_@~`!(){}^#&
        let ok = up.is_ascii_alphanumeric()
            || matches!(up, b'$' | b'%' | b'\'' | b'-' | b'_' | b'@' | b'~' | b'`' | b'!' | b'(' | b')' | b'{' | b'}' | b'^' | b'#' | b'&');
        if !ok {
            return None;
        }
        if in_ext {
            if ext_len == 3 {
                return None;
            }
            out[8 + ext_len] = up;
            ext_len += 1;
        } else {
            if name_len == 8 {
                return None;
            }
            out[name_len] = up;
            name_len += 1;
        }
    }
    if name_len == 0 {
        return None;
    }
    Some(out)
}

/// 在一段目录链里找第一个可写的空槽。返回 `(扇区 LBA, 扇区内偏移)`。
///
/// 两种空槽都算：`0x00`（此后再无条目）与 `0xE5`（已删除）。
/// **`0x00` 之后的部分不需要清零**：规范规定 `0x00` 就是结尾，后面本来就不被读。
fn find_free_slot(disk: &dyn Block, v: &Bpb, dir_cluster: u32) -> Result<Option<(u64, usize)>, FsError> {
    let mut c = dir_cluster;
    let mut guard = 0u32;
    loop {
        guard += 1;
        if guard > 4096 {
            return Err(FsError::BadCluster(dir_cluster)); // 链成环
        }
        let base = cluster_to_lba(v, c);
        for s in 0..v.sectors_per_cluster as u64 {
            let lba = base + s;
            let mut sec = [0u8; SECTOR_BYTES];
            block_io::read_checked(disk, lba, &mut sec, &block_io::Budget::UNBOUNDED).map_err(FsError::Io)?;
            for i in 0..(SECTOR_BYTES / DIR_ENTRY) {
                let off = i * DIR_ENTRY;
                if sec[off] == DIR_END || sec[off] == DIR_FREED {
                    return Ok(Some((lba, off)));
                }
            }
        }
        let next = fat_next_disk(disk, v, c)?;
        if next == 0 || next >= fat32::EOC_MARKER {
            return Ok(None); // 链走完，目录满
        }
        c = next;
    }
}

/// 在 `dir_cluster` 目录里建一个**空文件**（size 0、首簇 0），返回它的目录项位置。
///
/// 空文件不分配簇：FAT32 规范允许 `first_cluster=0` + `size=0` 表示空文件。
/// 第一次写入时才分配（那是扩展那一刀，不在本切片）。
///
/// 已存在同名 ⇒ `AlreadyExists`（调用方映射成 `-1`：今天没有 `EEXIST`，见 ADR-177 决策 4）。
pub fn create_in_dir(
    disk: &dyn Block,
    v: &Bpb,
    dir_cluster: u32,
    name: &[u8],
) -> Result<(u64, usize), VfsError> {
    let short = encode_short_name(name).ok_or(VfsError::BadName)?;
    // 先查重名：同目录里已有这个 8.3 名就不建
    let mut c = dir_cluster;
    let mut guard = 0u32;
    loop {
        guard += 1;
        if guard > 4096 {
            return Err(VfsError::Fs(FsError::BadCluster(dir_cluster)));
        }
        let base = cluster_to_lba(v, c);
        for s in 0..v.sectors_per_cluster as u64 {
            let lba = base + s;
            let mut sec = [0u8; SECTOR_BYTES];
            block_io::read_checked(disk, lba, &mut sec, &block_io::Budget::UNBOUNDED).map_err(io)?;
            for i in 0..(SECTOR_BYTES / DIR_ENTRY) {
                let off = i * DIR_ENTRY;
                let first = sec[off];
                if first == DIR_END {
                    break; // 这一段之后没有条目了，跳出去看下一个扇区/簇
                }
                if first == DIR_FREED {
                    continue;
                }
                if sec[off + OFF_ATTR] & 0x0F == 0x0F {
                    continue; // 长名项，不是短名
                }
                if sec[off..off + 11] == short {
                    return Err(VfsError::AlreadyExists);
                }
            }
        }
        let next = fat_next_disk(disk, v, c)?;
        if next == 0 || next >= fat32::EOC_MARKER {
            break;
        }
        c = next;
    }
    // 找空槽并写目录项
    let (lba, off) = find_free_slot(disk, v, dir_cluster)?.ok_or(VfsError::DirFull)?;
    let mut sec = [0u8; SECTOR_BYTES];
    block_io::read_checked(disk, lba, &mut sec, &block_io::Budget::UNBOUNDED).map_err(io)?;
    let mut e = [0u8; DIR_ENTRY];
    e[..11].copy_from_slice(&short);
    e[OFF_ATTR] = ATTR_ARCHIVE;
    // 时间戳：ADR-107 §6 的「合成时间」口径——不写墙钟，写卷内既有约定。
    // 这里全 0 是**刻意的**：本仓没有可信墙钟源，编一个时间戳比留 0 更糟。
    e[OFF_CREATE_TENTHS] = 0;
    e[OFF_CREATE_TIME] = 0;
    e[OFF_CREATE_DATE] = 0;
    e[OFF_ACCESS_DATE] = 0;
    e[OFF_WRITE_TIME] = 0;
    e[OFF_WRITE_DATE] = 0;
    // first_cluster 高 16 位在 FAT32 才有意义，FAT16 写 0
    if v.fat_entry_bytes == 4usize {
        e[OFF_CLUSTER_HI..OFF_CLUSTER_HI + 2].copy_from_slice(&0u16.to_le_bytes());
    }
    e[OFF_CLUSTER_LO..OFF_CLUSTER_LO + 2].copy_from_slice(&0u16.to_le_bytes());
    e[OFF_SIZE..OFF_SIZE + 4].copy_from_slice(&0u32.to_le_bytes());
    sec[off..off + DIR_ENTRY].copy_from_slice(&e);
    disk.write_sectors(lba, &sec).map_err(io)?;
    Ok((lba, off))
}

/// 删除 `dir_cluster` 目录里名为 `name` 的文件：目录项首字节置 `0xE5`，簇链归还。
///
/// **只删文件不删目录**：目录删除要判「空不空」，那是另一条判据。
/// **不校验打开中的句柄**：句柄层在 `capability`，`vfs_ro` 看不到它；
/// 这一条留给 syscall 侧（ADR-118 原意是 `-16 EBUSY`，今天没有那个码）。
pub fn unlink_in_dir(
    disk: &dyn Block,
    v: &Bpb,
    dir_cluster: u32,
    name: &[u8],
) -> Result<(), VfsError> {
    let short = encode_short_name(name).ok_or(VfsError::BadName)?;
    let mut c = dir_cluster;
    let mut guard = 0u32;
    loop {
        guard += 1;
        if guard > 4096 {
            return Err(VfsError::Fs(FsError::BadCluster(dir_cluster)));
        }
        let base = cluster_to_lba(v, c);
        for s in 0..v.sectors_per_cluster as u64 {
            let lba = base + s;
            let mut sec = [0u8; SECTOR_BYTES];
            block_io::read_checked(disk, lba, &mut sec, &block_io::Budget::UNBOUNDED).map_err(io)?;
            let mut dirty = false;
            for i in 0..(SECTOR_BYTES / DIR_ENTRY) {
                let off = i * DIR_ENTRY;
                let first = sec[off];
                if first == DIR_END {
                    break;
                }
                if first == DIR_FREED {
                    continue;
                }
                if sec[off + OFF_ATTR] & 0x0F == 0x0F {
                    continue;
                }
                if sec[off..off + 11] != short {
                    continue;
                }
                if sec[off + OFF_ATTR] & 0x10 != 0 {
                    return Err(VfsError::IsDir); // 目录不在这一刀
                }
                // 先读首簇与大小，再改目录项
                let hi = if v.fat_entry_bytes == 4usize {
                    u16_at(&sec, off + OFF_CLUSTER_HI) as u32
                } else {
                    0
                };
                let lo = u16_at(&sec, off + OFF_CLUSTER_LO) as u32;
                let first_cluster = (hi << 16) | lo;
                sec[off] = DIR_FREED;
                dirty = true;
                disk.write_sectors(lba, &sec).map_err(io)?;
                // 释放簇链：**目录项先落盘再放链**。
                // 反过来的话，中途掉电会留下一条「指向已释放簇的目录项」——
                // 那是比泄漏更糟的形状（读它会读到别人的数据）。
                if first_cluster >= MIN_CLUSTER {
                    let mut cc = first_cluster;
                    let mut g2 = 0u32;
                    while cc >= MIN_CLUSTER && cc <= v.max_good_cluster {
                        g2 += 1;
                        if g2 > 1_000_000 {
                            return Err(VfsError::Fs(FsError::BadCluster(cc)));
                        }
                        let next = fat_next_disk(disk, v, cc)?;
                        fat_set_disk(disk, v, cc, 0)?;
                        if next == 0 || next >= fat32::EOC_MARKER {
                            break;
                        }
                        cc = next;
                    }
                }
                let _ = dirty;
                return Ok(());
            }
        }
        let next = fat_next_disk(disk, v, c)?;
        if next == 0 || next >= fat32::EOC_MARKER {
            break;
        }
        c = next;
    }
    Err(VfsError::NotFound)
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
