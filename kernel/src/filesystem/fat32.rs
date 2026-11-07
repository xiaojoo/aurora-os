//! FAT32 的只读解析（手册 §8.4「文件系统」那一格，任务 L3-C）。
//!
//! ## 判型这件事不能照"簇数分档"写
//!
//! 微软 FAT 规范给的是一条经验阈值：簇数 < 4085 是 FAT12、< 65525 是 FAT16、再多是 FAT32。
//! 真实卷不遵守它，本机两块卷就是反例（都由 `mtools 4.0.49` 的 `mformat -F` 造出，
//! 数值取自 `minfo` 与镜像字节，两个方向各一块）：
//!
//! | 卷 | 簇数 | 按阈值 | 按结构 | 结论 |
//! |---|---|---|---|---|
//! | `fat32-small` | 64,496 | **FAT16** | FAT32 | 阈值会拒绝一块读得动的卷 |
//! | `fat32-wide` | 129,022 | FAT32 | FAT32 | 两者一致，不提供信息 |
//! | `aurora.img` 的 LBA0 | — | — | 不是 FAT | 那是保护性 MBR，必须拒（见下） |
//!
//! ⇒ 判型先看**结构**：`root_entries == 0 && sectors_per_fat16 == 0 && sectors_per_fat32 != 0`。
//! 阈值只用来在 FAT12/16 之间分家，并且只用来**报数**（`band_type`）——用例把"卷A 的阈值判型是
//! FAT16 而我们收了"当成一格判据，这样哪天夹具换成一簇数落在 FAT32 档的卷， witness 会当场失效变红，
//! 而不是悄悄变成一条空转的断言。
//!
//! ## 偏移表全部由设备作证
//!
//! 下面每个偏移都由"从镜像读回来 + `minfo` 的原文"两处对出来过，**没有一个是从记忆里写的**。
//! 这一条不是形式主义：第一版把 `BPB_BkBootSec` 写成 49，读回来是 **1536**（= 字节 49..50 拼出的
//! 0x0600）——一个看着完全合理的数，而 minfo 说备份引导扇区在 **6**。同一次对表还确认了
//! FSInfo 的结构签名在 **484**（`0x41615272` 的反序 `0x61417272`）而不是 488：488 那一格是
//! 自由簇数（卷A 读出 64,430 = 64,496 − 66 已用，自洽）。写错 4 个字节会把"自由簇数"读成
//! "结构签名"，而它俩都是 32 位、都不为 0，任何"非 0 即通过"的检查都拦不住。
//!
//! ## 今天交付的与不交付的
//!
//! 交付：只读、只 FAT32、只看根目录（`root_cluster` 那条链）、8.3 名字。
//! **不交付**：LFN（长名条目被数进 `lfn_entries` 并报出，判据要求它为 0，等于"这条判据跑在真被
//! 实现的那条路上"）、子目录、写路径、分区偏移（引导盘的 LBA0 是 MBR，不是卷；要读 ESP 里那份
//! FAT 得先有 GPT 分区这一层，且那份是固定根目录的 FAT16 形状）、通用 VFS 门面（inode/dentry）。
//! 这些都记在 BACKLOG 78 的欠账里。

use super::vfs::{Block, BlockError, FileStat, SECTOR_BYTES};

// ---------------------------------------------------------------- BPB 偏移（引导扇区，512 字节）

pub const OFF_BYTES_PER_SEC: usize = 11;
pub const OFF_SECS_PER_CLUSTER: usize = 13;
pub const OFF_RESERVED: usize = 14;
pub const OFF_FAT_COUNT: usize = 16;
pub const OFF_ROOT_ENTRIES: usize = 17;
pub const OFF_TOTAL_SECS16: usize = 19;
pub const OFF_MEDIA: usize = 21;
pub const OFF_SECS_PER_FAT16: usize = 22;
pub const OFF_TOTAL_SECS32: usize = 32;
pub const OFF_SECS_PER_FAT32: usize = 36;
pub const OFF_ROOT_CLUSTER: usize = 44;
pub const OFF_FSINFO: usize = 48;
/// 备份引导扇区的位置。规范里是 **50**；写成 49 会得到 1536 这样一个"合理"的错数（模块头）。
pub const OFF_BACKUP_BOOT: usize = 50;
pub const OFF_DRV_NUM: usize = 64;
/// `BS_BootSig`：0x28/0x29 表示扩展字段（卷号、卷标、文件系统名）在位。
/// 不先看这一格就去读 82 的 `BS_FilSysType`，读到的是保留区里的随机字节。
pub const OFF_BOOT_SIG: usize = 66;
pub const OFF_FS_TYPE: usize = 82;
/// 引导扇区（以及 FSInfo 扇区）末尾的 0x55AA。小端拼出来是 0xAA55，这里按字节比，不玩这个花活。
pub const OFF_SIG: usize = 510;
pub const SIGNATURE: [u8; 2] = [0x55, 0xAA];

// ------------------------------------------------- FSInfo 扇区内部偏移（由 minfo + 镜像对出来）

pub const FSINFO_LEAD: u32 = 0x4161_5252;
/// 结构签名在 **484**（0x1E4）。488 是自由簇数，492 是下一空闲簇。
pub const OFF_FSINFO_STRUCT: usize = 484;
pub const FSINFO_STRUCT: u32 = 0x6141_7272;
pub const OFF_FSINFO_FREE: usize = 488;
pub const OFF_FSINFO_NEXT: usize = 492;

// -------------------------------------------------------------------- 目录项偏移（32 字节一条）

pub const ENTRY_BYTES: usize = 32;
const OFF_NAME: usize = 0;
const OFF_EXT: usize = 8;
const OFF_ATTR: usize = 11;
/// 簇号的**高 16 位**。FAT32 把簇号劈成两半放，低 16 位在 26。
const OFF_CLUSTER_HI: usize = 20;
const OFF_CLUSTER_LO: usize = 26;
const OFF_SIZE: usize = 28;

pub const ATTR_VOLUME: u8 = 0x08;
pub const ATTR_DIR: u8 = 0x10;
pub const ATTR_LFN: u8 = 0x0F;

/// 目录项名字第一字节的三个特殊值（规范里就这三个，其余按字符处理）。
const FIRST_BYTE_FREED: u8 = 0xE5;
const FIRST_BYTE_REMOVED: u8 = 0x05;
const FIRST_BYTE_END: u8 = 0x00;

/// 簇号下界：0/1 保留。`>= 0x0FFF_FFF8` 是"链尾/坏簇"，一律不当数据簇用。
pub const MIN_CLUSTER: u32 = 2;
pub const MAX_GOOD_CLUSTER: u32 = 0x0FFF_FFF7;
pub const EOC_MARKER: u32 = 0x0FFF_FFF8;
/// FAT32 的簇号只有低 **28** 位有效，高 4 位保留必须忽略。
///
/// 这条掩码错过一次 nibble（写成 `0x00FF_FFFF`），后果不是"少几位簇号"而是**所有卷的链尾都读不出来**：
/// 真卷的 EOC 是 `0x0FFF_FFFF`，被截成 `0x00FF_FFFF` 之后小于 `EOC_MARKER`，走链于是认为"链还没完"，
/// 而字节已经喂完 ⇒ 每一格元数据都自洽，只有结尾那格不认。`EOC_MARKER` 与它是同一族常数，
/// 改一个必须对另一个（两块真卷与内存夹具三处同时红，就是这一条的取证）。
pub const FAT32_CLUSTER_MASK: u32 = 0x0FFF_FFFF;

/// 一次打开/读取允许走多少个簇。**必须有界**：卷可以被截断、FAT 可以被打成环，
/// 而没有上界的解析器在损坏镜像上的表现是"内核里一次永不返回的循环"——
/// 那不 panic、不报错，只是不回来，是 L4 之外没人认领的第三种死法。
pub const MAX_CLUSTERS_WALKED: u32 = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

#[derive(Debug, Clone, Copy)]
pub struct Bpb {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fat_count: u8,
    pub sectors_per_fat: u32,
    pub root_cluster: u32,
    pub fsinfo_sector: u16,
    pub backup_boot_sector: u16,
    pub total_sectors: u64,
    /// 数据区起点（扇区）= 保留区 + FAT 份数 × 每份扇区数。`cluster_to_lba` 的基准。
    pub data_start: u64,
    /// 数据簇数 =（总扇区 − 数据区起点）/ 每簇扇区数。阈值判型用的就是这个数。
    pub clusters: u64,
    pub cluster_bytes: usize,
    pub fat_type: FatType,
    /// `BS_FilSysType` 前五个字节是不是 "FAT32"（只有 `BS_BootSig` 在位时才有意义）
    pub fs_name_ok: bool,
}

/// 从引导扇区与 FSInfo 扇区读回来的"设备自述"，只用于报数与两侧对账。
#[derive(Debug, Clone, Copy)]
pub struct Witness {
    pub media: u8,
    pub boot_sig: u8,
    pub drv_num: u8,
    pub fs_type_name: [u8; 8],
    pub fsinfo_lead: u32,
    pub fsinfo_struct: u32,
    pub free_clusters: u32,
    pub next_free: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// 0x55AA 不在位上：这不是一个引导扇区（引导盘的 LBA0 走的就是这条——那是保护性 MBR）
    NoSignature,
    /// 每扇区字节数不是 2 的幂、不在 128..4096 内，或为 0
    BadBytesPerSector(u16),
    /// 扇区是 2 的幂但不是 512：块层没这一维，今天拒绝
    UnsupportedSectorSize(u16),
    /// 每簇扇区数不是 2 的幂（含 0）
    BadSectorsPerCluster(u8),
    /// 介质描述符不在 0xF0..0xFF：规范说这个字节必须在这个范围里
    BadMedia(u8),
    /// 判型结果是 FAT12/FAT16：今天没实现，明确拒绝而不是"试试看"
    UnsupportedFat(FatType),
    /// FAT 份数或几何算不出来（0 份 FAT、保留区为 0 之类）
    MalformedBpb,
    /// 数据区起点已经不在镜像里了
    GeometryBeyondVolume { data_start: u64, total: u64 },
    /// FSInfo 扇区的三处签名不是规范给的那三个值（带回报数，便于分辨"偏移错"与"盘错"）
    FsinfoSignature { lead: u32, struct_sig: u32, trail: u16 },
    /// 备份引导扇区与 0 号扇区不相同（规范要求逐字节相同），带第一个差异的字节序号
    BackupDiffers { first_diff: usize },
    /// 簇号越界（< 2 或 >= 坏簇下界）
    BadCluster(u32),
    /// 走链超过 `MAX_CLUSTERS_WALKED`：环，或者损坏
    ChainTooLong,
    /// 簇链在读完大小之前就到了 EOC：元数据说 N 字节，链只给到 M（M < N）。
    /// `cluster`/`next` 是出事那一刻的簇号与它在 FAT 里的读数：没有它们，"链短了"与
    /// "我算错了 EOC"这两种成因在日志里长成同一个数（本轮 `FAT32_CLUSTER_MASK` 少一个 nibble
    /// 就是这么藏住的——字节已经喂完，却报"链超出大小"）。
    ChainEndsEarly { bytes: usize, size: u32, cluster: u32, next: u32 },
    /// 大小已经喂完而链还没到 EOC：反过来的那种不自洽（M > N）。
    /// 这一格不只是"报得细一点"：没有它，一个被指到长链中间的簇号会一直走到
    /// `MAX_CLUSTERS_WALKED` 才回头——在本机那就是六万次块命令，用例先超时。
    ChainEndsLate { bytes: usize, size: u32, cluster: u32, next: u32 },
    /// 目录里没找到
    NoEntry,
    /// 目录项的簇号落在数据区之外
    EntryOutsideData(u32),
    /// 底层块设备失败，**原样带出去**（成因不许被文件系统层抹平）
    Io(BlockError),
}

impl FsError {
    /// 日志里的一格成因。升成字符串而不是直接用 `{:?}`，是因为判定链的锚点要稳定。
    pub fn tag(self) -> &'static str {
        match self {
            FsError::NoSignature => "无引导签名",
            FsError::BadBytesPerSector(_) => "扇区字节数非法",
            FsError::UnsupportedSectorSize(_) => "扇区不是512",
            FsError::BadSectorsPerCluster(_) => "每簇扇区数非法",
            FsError::BadMedia(_) => "介质字节非法",
            FsError::UnsupportedFat(_) => "非FAT32",
            FsError::MalformedBpb => "几何算不出",
            FsError::GeometryBeyondVolume { .. } => "几何越出镜像",
            FsError::FsinfoSignature { .. } => "FSInfo签名不符",
            FsError::BackupDiffers { .. } => "备份扇区不符",
            FsError::BadCluster(_) => "簇号越界",
            FsError::ChainTooLong => "簇链超长",
            FsError::ChainEndsEarly { .. } => "簇链提前收尾",
            FsError::ChainEndsLate { .. } => "簇链超出大小",
            FsError::NoEntry => "目录无此项",
            FsError::EntryOutsideData(_) => "项落在数据区外",
            FsError::Io(_) => "块设备失败",
        }
    }
}

const fn u16_at(b: &[u8], off: usize) -> u16 {
    (b[off] as u16) | ((b[off + 1] as u16) << 8)
}

const fn u32_at(b: &[u8], off: usize) -> u32 {
    (b[off] as u32) | ((b[off + 1] as u32) << 8) | ((b[off + 2] as u32) << 16) | ((b[off + 3] as u32) << 24)
}

fn is_pow2(v: u32) -> bool {
    v != 0 && v & v.wrapping_sub(1) == 0
}

/// **只按簇数**分档（微软那条经验阈值）。
///
/// 这个函数不参与任何判定，它存在的唯一理由是"把阈值的答案报出来，让反例留在串口上"。
/// 拿它当判型依据就是本模块头那张表里第一行的错法。
pub fn band_type(clusters: u64) -> FatType {
    if clusters < 4085 {
        FatType::Fat12
    } else if clusters < 65525 {
        FatType::Fat16
    } else {
        FatType::Fat32
    }
}

/// 解析引导扇区。不做任何 I/O，所以可以被宿主机按同一份字节重算（`tools/aurora.py` 就重算了一遍）。
pub fn parse_boot_sector(b: &[u8]) -> Result<Bpb, FsError> {
    if b.len() < SECTOR_BYTES {
        return Err(FsError::NoSignature);
    }
    if b[OFF_SIG] != SIGNATURE[0] || b[OFF_SIG + 1] != SIGNATURE[1] {
        return Err(FsError::NoSignature);
    }
    let bps = u16_at(b, OFF_BYTES_PER_SEC);
    if !is_pow2(bps as u32) || bps < 128 || bps > 4096 {
        return Err(FsError::BadBytesPerSector(bps));
    }
    if bps as usize != SECTOR_BYTES {
        return Err(FsError::UnsupportedSectorSize(bps));
    }
    let spc = b[OFF_SECS_PER_CLUSTER];
    if !is_pow2(spc as u32) {
        return Err(FsError::BadSectorsPerCluster(spc));
    }
    let media = b[OFF_MEDIA];
    if media & 0xF0 != 0xF0 {
        return Err(FsError::BadMedia(media));
    }
    let reserved = u16_at(b, OFF_RESERVED);
    let fat_count = b[OFF_FAT_COUNT];
    let root_entries = u16_at(b, OFF_ROOT_ENTRIES);
    let spf16 = u16_at(b, OFF_SECS_PER_FAT16);
    let spf32 = u32_at(b, OFF_SECS_PER_FAT32);
    let mut total = u16_at(b, OFF_TOTAL_SECS16) as u64;
    if total == 0 {
        total = u32_at(b, OFF_TOTAL_SECS32) as u64;
    }
    // 判型顺序就是这个顺序：先看结构，阈值只在"不是 FAT32"时用来给个名字。
    let fat_type = if root_entries == 0 && spf16 == 0 && spf32 != 0 {
        FatType::Fat32
    } else {
        if total == 0 || fat_count == 0 {
            return Err(FsError::MalformedBpb);
        }
        let spf = if spf16 != 0 { spf16 as u64 } else { spf32 as u64 };
        let clusters = total.saturating_sub(reserved as u64 + fat_count as u64 * spf) / spc as u64;
        band_type(clusters)
    };
    if fat_type != FatType::Fat32 {
        return Err(FsError::UnsupportedFat(fat_type));
    }
    if fat_count == 0 || reserved == 0 {
        return Err(FsError::MalformedBpb);
    }
    let sectors_per_fat = spf32;
    let data_start = reserved as u64 + fat_count as u64 * sectors_per_fat as u64;
    if data_start >= total {
        return Err(FsError::GeometryBeyondVolume { data_start, total });
    }
    let clusters = (total - data_start) / spc as u64;
    let boot_sig = b[OFF_BOOT_SIG];
    Ok(Bpb {
        bytes_per_sector: bps,
        sectors_per_cluster: spc,
        reserved_sectors: reserved,
        fat_count,
        sectors_per_fat,
        root_cluster: u32_at(b, OFF_ROOT_CLUSTER),
        fsinfo_sector: u16_at(b, OFF_FSINFO),
        backup_boot_sector: u16_at(b, OFF_BACKUP_BOOT),
        total_sectors: total,
        data_start,
        clusters,
        cluster_bytes: SECTOR_BYTES * spc as usize,
        fat_type,
        // 只有 BS_BootSig 在位（0x28/0x29）时 82 那 8 个字节才是文件系统名，否则它是保留区
        fs_name_ok: matches!(boot_sig, 0x28 | 0x29) && &b[OFF_FS_TYPE..OFF_FS_TYPE + 5] == b"FAT32",
    })
}

/// 一个挂载起来的只读卷：`Bpb` + 设备自述的几格数。
pub struct Volume<'a> {
    /// 块设备这一维是 trait 对象而不是具体驱动：同一套判据要能对着真控制器与内存夹具各跑一遍。
    pub disk: &'a dyn Block,
    pub bpb: Bpb,
    pub witness: Witness,
    /// 备份引导扇区与 0 号扇区逐字节相同（规范要求；这一格是"读对了偏移"的旁证）
    pub backup_same: bool,
}

impl<'a> Volume<'a> {
    /// 读 0 号扇区、解析、再读 FSInfo 与备份引导扇区做自校验。
    ///
    /// FSInfo 的三处签名与备份扇区的逐字节相同**都在挂载这一步判**，因为它们判的是
    /// "我的偏移表对不对"，而不是"这个文件存不存在"——偏移错的时候必须在还没有任何
    /// 上层读数之前就红，否则后面每一格数都是从错的基准上算出来的。
    pub fn mount(disk: &'a dyn Block) -> Result<Volume<'a>, FsError> {
        let mut bs = [0u8; SECTOR_BYTES];
        disk.read_sectors(0, &mut bs).map_err(FsError::Io)?;
        let bpb = parse_boot_sector(&bs)?;
        let mut info = [0u8; SECTOR_BYTES];
        disk.read_sectors(u64::from(bpb.fsinfo_sector), &mut info)
            .map_err(FsError::Io)?;
        let lead = u32_at(&info, 0);
        let struct_sig = u32_at(&info, OFF_FSINFO_STRUCT);
        let trail = u16_at(&info, OFF_SIG);
        if lead != FSINFO_LEAD || struct_sig != FSINFO_STRUCT || trail != 0xAA55 {
            return Err(FsError::FsinfoSignature { lead, struct_sig, trail });
        }
        let mut backup = [0u8; SECTOR_BYTES];
        disk.read_sectors(u64::from(bpb.backup_boot_sector), &mut backup)
            .map_err(FsError::Io)?;
        let mut first_diff = None;
        for i in 0..SECTOR_BYTES {
            if backup[i] != bs[i] {
                first_diff = Some(i);
                break;
            }
        }
        if let Some(i) = first_diff {
            return Err(FsError::BackupDiffers { first_diff: i });
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&bs[OFF_FS_TYPE..OFF_FS_TYPE + 8]);
        Ok(Volume {
            disk,
            bpb,
            backup_same: true,
            witness: Witness {
                media: bs[OFF_MEDIA],
                boot_sig: bs[OFF_BOOT_SIG],
                drv_num: bs[OFF_DRV_NUM],
                fs_type_name: name,
                fsinfo_lead: lead,
                fsinfo_struct: struct_sig,
                free_clusters: u32_at(&info, OFF_FSINFO_FREE),
                next_free: u32_at(&info, OFF_FSINFO_NEXT),
            },
        })
    }

    /// FAT 里某簇的后继。每次单独读一个扇区：简单、有界，且不需要回答"缓存什么时候失效"。
    pub fn fat_next(&self, cluster: u32) -> Result<u32, FsError> {
        if cluster < MIN_CLUSTER {
            return Err(FsError::BadCluster(cluster));
        }
        let byte_off = cluster as usize * 4;
        let lba = self.bpb.reserved_sectors as u64 + (byte_off / SECTOR_BYTES) as u64;
        let mut sec = [0u8; SECTOR_BYTES];
        self.disk.read_sectors(lba, &mut sec).map_err(FsError::Io)?;
        let in_sec = byte_off % SECTOR_BYTES;
        if in_sec + 4 > SECTOR_BYTES {
            // 一项跨在两个 FAT 扇区之间。FAT32 里只有 `cluster*4 % 512 > 508` 才会这样，
            // 也就是簇号 ≡ 128 (mod 128) 附近——真卷上会出现，所以这不是"不可能分支"。
            return Err(FsError::BadCluster(cluster));
        }
        Ok(u32_at(&sec, in_sec) & FAT32_CLUSTER_MASK)
    }

    pub fn cluster_to_lba(&self, cluster: u32) -> u64 {
        self.bpb.data_start + (cluster as u64 - MIN_CLUSTER as u64) * self.bpb.sectors_per_cluster as u64
    }

    /// 在根目录里按 8.3 名字找一项（大小写不敏感）。
    pub fn open(&self, want: &str) -> Result<FileStat, FsError> {
        let v = &self.bpb;
        let mut cluster = v.root_cluster;
        let mut entries_seen: u32 = 0;
        let mut lfn: u32 = 0;
        let mut walked: u32 = 0;
        let mut sector = [0u8; SECTOR_BYTES];
        loop {
            if cluster < MIN_CLUSTER || cluster > MAX_GOOD_CLUSTER {
                return Err(FsError::NoEntry);
            }
            for s in 0..v.sectors_per_cluster as u32 {
                self.disk
                    .read_sectors(self.cluster_to_lba(cluster) + s as u64, &mut sector)
                    .map_err(FsError::Io)?;
                let mut o = 0usize;
                while o + ENTRY_BYTES <= sector.len() {
                    let e = &sector[o..o + ENTRY_BYTES];
                    o += ENTRY_BYTES;
                    if e[0] == FIRST_BYTE_END {
                        return Err(FsError::NoEntry);
                    }
                    entries_seen += 1;
                    let attr = e[OFF_ATTR];
                    if attr == ATTR_LFN {
                        lfn += 1;
                        continue;
                    }
                    if attr & ATTR_VOLUME != 0 || attr & ATTR_DIR != 0 || e[0] == FIRST_BYTE_FREED {
                        continue;
                    }
                    if !name_matches(e, want) {
                        continue;
                    }
                    // 簇号是**两半**拼的。只读低半会在一越过 65,535 簇的卷上把文件指到别处，
                    // 而目录项里的字节数还是对的——本模块最难查的那类错，`fat32-wide` 就是为它造的。
                    let c = (u16_at(e, OFF_CLUSTER_HI) as u32) << 16 | u16_at(e, OFF_CLUSTER_LO) as u32;
                    if c < MIN_CLUSTER || c > MAX_GOOD_CLUSTER {
                        return Err(FsError::EntryOutsideData(c));
                    }
                    return Ok(FileStat {
                        size: u32_at(e, OFF_SIZE),
                        first_cluster: c,
                        entries_seen,
                        lfn_entries: lfn,
                    });
                }
            }
            walked += 1;
            if walked > MAX_CLUSTERS_WALKED {
                return Err(FsError::ChainTooLong);
            }
            cluster = self.fat_next(cluster)?;
            if cluster >= EOC_MARKER {
                return Err(FsError::NoEntry);
            }
        }
    }

    /// 把文件一段一段喂给 `feed`（每段最多一个簇），返回走链的账。
    ///
    /// 为什么是流式而不是一次读进一个大缓冲：文件可以比任何一次块设备传输都大
    /// （`MAX_SECTORS` 由环形结构的容量决定），而"按外部输入的大小开缓冲"在这台内核里
    /// 还有一条 2048 字节的分配器上限挡着（BACKLOG ⑤ 那笔账）。流式把这两件事都绕开了，
    /// 代价是哈希必须在调用方累加——这正是 `ahci::fnv1a_step` 当初逐字节推的理由。
    pub fn walk<F: FnMut(&[u8])>(&self, st: &FileStat, mut feed: F) -> Result<Walk, FsError> {
        let v = &self.bpb;
        let mut w = Walk { bytes: 0, clusters: 0, tail_bytes: 0, last_cluster: 0, after_last: 0 };
        if st.size == 0 {
            return Ok(w);
        }
        let mut cluster = st.first_cluster;
        let mut left = st.size as usize;
        let mut sector = [0u8; SECTOR_BYTES];
        loop {
            if cluster < MIN_CLUSTER || cluster > MAX_GOOD_CLUSTER {
                return Err(FsError::BadCluster(cluster));
            }
            let want = core::cmp::min(v.cluster_bytes, left);
            for s in 0..((want + SECTOR_BYTES - 1) / SECTOR_BYTES) as u32 {
                self.disk
                    .read_sectors(self.cluster_to_lba(cluster) + s as u64, &mut sector)
                    .map_err(FsError::Io)?;
                // 尾格只喂真的属于文件的那几个字节。多喂一个字节，"文件末尾之后"的盘上内容
                // 就会被当成文件内容算进哈希（注入 `fault-fat32-tail` 就是让它多喂，必须红）。
                let take = core::cmp::min(SECTOR_BYTES, want - s as usize * SECTOR_BYTES);
                // 负样本 `fault-fat32-tail`：尾格多喂一个字节。只在真的短的那一格动手——
                // 整扇区时 +1 会越出 `sector` 的界，那不是注入而是量具自己先死。
                let take = if cfg!(feature = "fault-fat32-tail") && take < SECTOR_BYTES {
                    take + 1
                } else {
                    take
                };
                feed(&sector[..take]);
                w.bytes += take;
                w.tail_bytes = take;
            }
            w.clusters += 1;
            w.last_cluster = cluster;
            left -= want;
            let next = self.fat_next(cluster)?;
            w.after_last = next;
            if next >= EOC_MARKER {
                if left != 0 {
                    return Err(FsError::ChainEndsEarly { bytes: w.bytes, size: st.size, cluster, next });
                }
                return Ok(w);
            }
            if left == 0 {
                return Err(FsError::ChainEndsLate { bytes: w.bytes, size: st.size, cluster, next });
            }
            if w.clusters > MAX_CLUSTERS_WALKED {
                return Err(FsError::ChainTooLong);
            }
            cluster = next;
        }
    }
}

/// 一次流式读取的账。每一格都可能与目录项里的元数据互相矛盾，矛盾就是判据。
#[derive(Debug, Clone, Copy)]
pub struct Walk {
    /// 真正属于文件并喂出去的字节数，判据要求它等于 `FileStat::size`
    pub bytes: usize,
    /// 走过的簇数，判据要求它等于 `ceil(size / cluster_bytes)`
    pub clusters: u32,
    /// 最后一个簇里被喂出的字节数（`size % cluster_bytes == 0` 时它等于 cluster_bytes）
    pub tail_bytes: usize,
    pub last_cluster: u32,
    /// 末簇在 FAT 里的后继，判据要求它是 EOC
    pub after_last: u32,
}

/// 名字按"8.3、去尾随空格、大小写不敏感"比对。
///
/// 没有扩展名时**不补那个点**：`NOTES` 拼成 `NOTES.` 就永远匹配不上，而这块卷上恰好有这么一个文件。
fn name_matches(e: &[u8], want: &str) -> bool {
    if e[0] == FIRST_BYTE_END || e[0] == FIRST_BYTE_FREED {
        return false;
    }
    let mut buf = [0u8; 13];
    let mut n = 0usize;
    buf[0] = if e[0] == FIRST_BYTE_REMOVED { b'?' } else { e[0] };
    n += 1;
    for i in OFF_NAME + 1..OFF_EXT {
        if e[i] == b' ' {
            break;
        }
        buf[n] = e[i];
        n += 1;
    }
    let mut has_ext = false;
    for i in OFF_EXT..OFF_EXT + 3 {
        if e[i] == b' ' {
            break;
        }
        if !has_ext {
            buf[n] = b'.';
            n += 1;
            has_ext = true;
        }
        buf[n] = e[i];
        n += 1;
    }
    let Some(got) = core::str::from_utf8(&buf[..n]).ok() else {
        return false;
    };
    let w = want.as_bytes();
    got.len() == w.len() && got.as_bytes()[..w.len()].eq_ignore_ascii_case(&w[..got.len()])
}
