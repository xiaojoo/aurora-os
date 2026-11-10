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
pub const OFF_DRV_NUM16: usize = 36;
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

// FAT16 那一族的常数（ADR-078 / W4 S2a）。**与 FAT32 的分开写**，不共用一个"看起来差不多的数"：
// 项宽 2 vs 4、掩码 16 位 vs 28 位、EOC 0xFFF8 vs 0x0FFF_FFF8，混用会把链走飞而字节数还好看。
pub const OFF_BOOT_SIG16: usize = 38;
pub const OFF_FS_TYPE16: usize = 54;
pub const FAT16_ENTRY_BYTES: usize = 2;
pub const FAT16_CLUSTER_MASK: u32 = 0xFFFF;
pub const FAT16_MAX_GOOD_CLUSTER: u32 = 0xFFF6;
pub const FAT16_EOC_MARKER: u32 = 0xFFF8;

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
    /// 固定根目录区的项数（FAT16 非零、FAT32 恒 0）。**判型只看结构**就看它与 spf16/spf32。
    pub root_entries: u16,
    /// 固定根目录区占几个扇区（FAT16 = ceil(root_entries×32/512)，FAT32 = 0）。
    /// FAT16 的 `data_start` 要把它加进去，FAT32 加 0 ⇒ 那条路的算术一个数没变。
    pub root_dir_sectors: u64,
    /// FAT 项宽（FAT32=4、FAT16=2）。走链与游标共用这一个数，不各写一份。
    pub fat_entry_bytes: usize,
    /// 簇号掩码 / 合法上界 / EOC 下界：三族各一份，由 `fat_type` 决定，走链只问 Bpb。
    pub cluster_mask: u32,
    pub max_good_cluster: u32,
    pub eoc_marker: u32,
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
    // 判型顺序就是这个顺序：**先看结构**，阈值只在"两族结构都不匹配"时用来给拒因起名字。
    // FAT16 的接受闸是 `root_entries != 0 && spf16 != 0`，与 FAT32 的闸天然互斥。
    // **不许再加 `spf32 == 0` 这一条**：FAT16 根本没有 spf32 这个字段，偏移 36..40 那四字节是
    // 它的扩展引导记录（36=BS_DrvNum、38=BS_BootSig、39..43=BS_VolID），真实 FAT16 卷那里**非零**
    // （本仓 ESP 就是 0x29 + 卷标）。本轮第一版加了那一条，合成卷因为写了 BootSig=0x29 当场被拒，
    // 而真 ESP 同样会被拒——合成卷里那个"看起来多余"的字节正是抓到它的证人。
    // 也**绝不用簇数阈值分流**：卷A 64,496 簇按阈值是 FAT16、按结构是 FAT32，
    // 用阈值分流会把它误路由进 FAT16 读路径，`a_counter` 那格反例当场红（ADR-038 决策 1）。
    let fat_type = if root_entries == 0 && spf16 == 0 && spf32 != 0 {
        FatType::Fat32
    } else if root_entries != 0 && spf16 != 0 {
        FatType::Fat16
    } else {
        if total == 0 || fat_count == 0 {
            return Err(FsError::MalformedBpb);
        }
        let spf = if spf16 != 0 { spf16 as u64 } else { spf32 as u64 };
        let clusters = total.saturating_sub(reserved as u64 + fat_count as u64 * spf) / spc as u64;
        return Err(FsError::UnsupportedFat(band_type(clusters)));
    };
    if fat_count == 0 || reserved == 0 {
        return Err(FsError::MalformedBpb);
    }
    let is16 = fat_type == FatType::Fat16;
    let sectors_per_fat = if is16 { u32::from(spf16) } else { spf32 };
    // FAT16 的根目录是**固定区**不是簇链，数据区起点要把它加进去；FAT32 加 0
    // ⇒ FAT32 那条路的 data_start 算术一个数没变（34–39 行与十三格判据靠这一点保持绿）。
    let root_dir_sectors = if is16 {
        (u64::from(root_entries) * ENTRY_BYTES as u64 + SECTOR_BYTES as u64 - 1) / SECTOR_BYTES as u64
    } else {
        0
    };
    let data_start = reserved as u64 + fat_count as u64 * sectors_per_fat as u64 + root_dir_sectors;
    if data_start >= total {
        return Err(FsError::GeometryBeyondVolume { data_start, total });
    }
    let clusters = (total - data_start) / spc as u64;
    // 扩展引导记录两族布局不同：FAT16 的 BootSig 在 38、名字在 54；FAT32 在 66 / 82。
    let (boot_sig, fs_type_off, fs_name): (u8, usize, &[u8]) = if is16 {
        (b[OFF_BOOT_SIG16], OFF_FS_TYPE16, &b"FAT16"[..])
    } else {
        (b[OFF_BOOT_SIG], OFF_FS_TYPE, &b"FAT32"[..])
    };
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
        // 只有 BS_BootSig 在位（0x28/0x29）时那 8 个字节才是文件系统名，否则它是保留区
        fs_name_ok: matches!(boot_sig, 0x28 | 0x29) && &b[fs_type_off..fs_type_off + 5] == fs_name,
        root_entries,
        root_dir_sectors,
        fat_entry_bytes: if is16 { FAT16_ENTRY_BYTES } else { 4 },
        cluster_mask: if is16 { FAT16_CLUSTER_MASK } else { FAT32_CLUSTER_MASK },
        max_good_cluster: if is16 { FAT16_MAX_GOOD_CLUSTER } else { MAX_GOOD_CLUSTER },
        eoc_marker: if is16 { FAT16_EOC_MARKER } else { EOC_MARKER },
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
        let is16 = bpb.fat_type == FatType::Fat16;
        // FAT16 **没有 FSInfo 也没有备份引导扇区**（规范如此，本仓 ESP 就是这个形状）。
        // 不去读那两处：读了就是把 FAT32 的自校验强加给一个没有那两格的卷。
        // FAT32 那条路的三处签名与逐字节比较**一个字没动**，`backup_same` 仍是 true。
        let (lead, struct_sig, free_clusters, next_free, backup_same) = if is16 {
            (0u32, 0u32, 0u32, 0u32, false)
        } else {
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
            (lead, struct_sig, u32_at(&info, OFF_FSINFO_FREE), u32_at(&info, OFF_FSINFO_NEXT), true)
        };
        let mut name = [0u8; 8];
        let name_off = if is16 { OFF_FS_TYPE16 } else { OFF_FS_TYPE };
        name.copy_from_slice(&bs[name_off..name_off + 8]);
        Ok(Volume {
            disk,
            bpb,
            backup_same,
            witness: Witness {
                media: bs[OFF_MEDIA],
                boot_sig: if is16 { bs[OFF_BOOT_SIG16] } else { bs[OFF_BOOT_SIG] },
                drv_num: bs[if is16 { OFF_DRV_NUM16 } else { OFF_DRV_NUM }],
                fs_type_name: name,
                fsinfo_lead: lead,
                fsinfo_struct: struct_sig,
                free_clusters,
                next_free,
            },
        })
    }

    /// FAT 里某簇的后继。每次单独读一个扇区：简单、有界，且不需要回答"缓存什么时候失效"。
    pub fn fat_next(&self, cluster: u32) -> Result<u32, FsError> {
        if cluster < MIN_CLUSTER {
            return Err(FsError::BadCluster(cluster));
        }
        let v = &self.bpb;
        let byte_off = cluster as usize * v.fat_entry_bytes;
        let lba = v.reserved_sectors as u64 + (byte_off / SECTOR_BYTES) as u64;
        let mut sec = [0u8; SECTOR_BYTES];
        self.disk.read_sectors(lba, &mut sec).map_err(FsError::Io)?;
        let in_sec = byte_off % SECTOR_BYTES;
        if in_sec + v.fat_entry_bytes > SECTOR_BYTES {
            // 一项跨在两个 FAT 扇区之间。FAT32 里只有 `cluster*4 % 512 > 508` 才会这样，
            // 也就是簇号 ≡ 128 (mod 128) 附近——真卷上会出现，所以这不是"不可能分支"。
            // FAT16 的项宽是 2、512 整除它，这一支在那一族不可达。
            return Err(FsError::BadCluster(cluster));
        }
        Ok(if v.fat_entry_bytes == FAT16_ENTRY_BYTES {
            u32::from(u16_at(&sec, in_sec)) & v.cluster_mask
        } else {
            u32_at(&sec, in_sec) & v.cluster_mask
        })
    }

    pub fn cluster_to_lba(&self, cluster: u32) -> u64 {
        self.bpb.data_start + (cluster as u64 - MIN_CLUSTER as u64) * self.bpb.sectors_per_cluster as u64
    }

    /// 在根目录里按 8.3 名字找一项（大小写不敏感）。
    pub fn open(&self, want: &str) -> Result<FileStat, FsError> {
        let v = &self.bpb;
        let is16 = v.fat_type == FatType::Fat16;
        let mut cluster = v.root_cluster;
        let mut entries_seen: u32 = 0;
        let mut lfn: u32 = 0;
        let mut walked: u32 = 0;
        let mut sector = [0u8; SECTOR_BYTES];
        // 根在哪由类型决定：FAT32 走根簇链，FAT16 走**固定根目录区**（保留区 + FAT 份数×每份扇区）。
        // 固定区按扇区流式扫，512 项 × 32 = 16 KiB 也不进堆（堆上限 2048，ADR-018/026）。
        // 目录项那段解析两族共用，只有"根在哪"与"簇号有没有高半"两处不同。
        let mut fixed_left = v.root_dir_sectors;
        let mut fixed_lba = v.reserved_sectors as u64 + v.fat_count as u64 * v.sectors_per_fat as u64;
        loop {
            let (lba, nsec) = if is16 {
                if fixed_left == 0 {
                    return Err(FsError::NoEntry);
                }
                let l = fixed_lba;
                fixed_lba += 1;
                fixed_left -= 1;
                (l, 1u32)
            } else {
                if cluster < MIN_CLUSTER || cluster > v.max_good_cluster {
                    return Err(FsError::NoEntry);
                }
                (self.cluster_to_lba(cluster), v.sectors_per_cluster as u32)
            };
            for s in 0..nsec {
                self.disk
                    .read_sectors(lba + s as u64, &mut sector)
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
                    // FAT32 的簇号是**两半**拼的。只读低半会在一越过 65,535 簇的卷上把文件指到别处，
                    // 而目录项里的字节数还是对的——本模块最难查的那类错，`fat32-wide` 就是为它造的。
                    // FAT16 **没有高半**（偏移 20 那两字节是 EA 索引，不是簇号），读了就会把文件指飞。
                    let c = if is16 {
                        u32::from(u16_at(e, OFF_CLUSTER_LO))
                    } else {
                        (u16_at(e, OFF_CLUSTER_HI) as u32) << 16 | u16_at(e, OFF_CLUSTER_LO) as u32
                    };
                    if c < MIN_CLUSTER || c > v.max_good_cluster {
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
            if is16 {
                continue;
            }
            walked += 1;
            if walked > MAX_CLUSTERS_WALKED {
                return Err(FsError::ChainTooLong);
            }
            cluster = self.fat_next(cluster)?;
            if cluster >= v.eoc_marker {
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
            if cluster < MIN_CLUSTER || cluster > v.max_good_cluster {
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
            if next >= v.eoc_marker {
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

#[derive(Debug, Clone, Copy)]
pub struct FileCursor {
    bpb: Bpb,
    stat: FileStat,
    cluster: u32,
    position: u32,
    clusters: u32,
}

impl Volume<'_> {
    pub fn open_cursor(&self, name: &str) -> Result<FileCursor, FsError> {
        let stat = self.open(name)?;
        Ok(FileCursor { bpb: self.bpb, stat, cluster: stat.first_cluster, position: 0, clusters: 0 })
    }
}

impl FileCursor {
    pub fn stat(&self) -> FileStat {
        self.stat
    }

    pub fn position(&self) -> u32 {
        self.position
    }

    fn data_lba(&self, cluster: u32) -> Result<u64, FsError> {
        // 坏簇/保留标记那一档两族不同：FAT32 从 0x0FFFFFF0 起、FAT16 从 0xFFF8 起。
        // FAT32 的那个数逐字保留（改成 eoc_marker 会把 [0x0FFFFFF0,0x0FFFFFF7] 这一段放行）。
        let limit = if self.bpb.fat_type == FatType::Fat16 { FAT16_EOC_MARKER } else { 0x0FFF_FFF0 };
        if cluster < MIN_CLUSTER || cluster >= limit
            || u64::from(cluster - MIN_CLUSTER) >= self.bpb.clusters
        {
            return Err(FsError::BadCluster(cluster));
        }
        Ok(self.bpb.data_start + u64::from(cluster - MIN_CLUSTER) * u64::from(self.bpb.sectors_per_cluster))
    }

    fn next_cluster(&self, disk: &dyn Block, sector: &mut [u8; SECTOR_BYTES]) -> Result<u32, FsError> {
        let v = &self.bpb;
        let byte_off = u64::from(self.cluster) * v.fat_entry_bytes as u64;
        let fat_sector = byte_off / SECTOR_BYTES as u64;
        if fat_sector >= u64::from(v.sectors_per_fat) {
            return Err(FsError::BadCluster(self.cluster));
        }
        disk.read_sectors(u64::from(v.reserved_sectors) + fat_sector, sector).map_err(FsError::Io)?;
        let in_sec = (byte_off % SECTOR_BYTES as u64) as usize;
        Ok(if v.fat_entry_bytes == FAT16_ENTRY_BYTES {
            u32::from(u16_at(sector, in_sec)) & v.cluster_mask
        } else {
            u32_at(sector, in_sec) & v.cluster_mask
        })
    }

    /// disk 必须仍是打开时的只读卷；Err 时游标不变，dst 中可能已写入的前缀必须丢弃。
    pub fn read(&mut self, disk: &dyn Block, dst: &mut [u8]) -> Result<usize, FsError> {
        let want = dst.len().min((self.stat.size - self.position) as usize);
        let mut pending = *self;
        let mut done = 0;
        let mut sector = [0u8; SECTOR_BYTES];
        while done < want {
            if pending.clusters >= MAX_CLUSTERS_WALKED {
                return Err(FsError::ChainTooLong);
            }
            let cluster_off = pending.position as usize % pending.bpb.cluster_bytes;
            let lba = pending.data_lba(pending.cluster)? + (cluster_off / SECTOR_BYTES) as u64;
            disk.read_sectors(lba, &mut sector).map_err(FsError::Io)?;
            let sector_off = cluster_off % SECTOR_BYTES;
            let take = (want - done).min(SECTOR_BYTES - sector_off);
            dst[done..done + take].copy_from_slice(&sector[sector_off..sector_off + take]);
            pending.position += take as u32;
            done += take;
            if cluster_off + take == pending.bpb.cluster_bytes || pending.position == pending.stat.size {
                let next = pending.next_cluster(disk, &mut sector)?;
                let at_end = pending.position == pending.stat.size;
                if next >= pending.bpb.eoc_marker {
                    if !at_end {
                        return Err(FsError::ChainEndsEarly {
                            bytes: pending.position as usize, size: pending.stat.size, cluster: pending.cluster, next,
                        });
                    }
                } else {
                    if at_end {
                        return Err(FsError::ChainEndsLate {
                            bytes: pending.position as usize, size: pending.stat.size, cluster: pending.cluster, next,
                        });
                    }
                    pending.data_lba(next)?;
                    pending.cluster = next;
                }
                pending.clusters += 1;
            }
        }
        *self = pending;
        Ok(done)
    }
}

#[cfg(feature = "fat32-probe")]
mod cursor_tests {
    use super::*;
    use super::super::vfs::{AhciDisk, MemDisk};
    use core::cell::Cell;

    const IMAGE: &[u8] = include_bytes!("../../fixtures/fat32-mem.img");

    struct TestDisk {
        reads: Cell<u32>,
        mount_reads: Cell<u32>,
        fat_reads: Cell<u32>,
        fail_lba: Cell<Option<u64>>,
        fat_patch: Option<(usize, u32)>,
        size: Option<u32>,
        wide: bool,
        /// Some(簇号)：BPB 自述 200 个数据簇而 FAT 只有 1 扇区（128 项），LONG~1.TXT 的目录项
        /// 指到那个簇号。数据区第 135/136 扇区由本适配器供字节——卷的 FAT 盖不住自己的数据区
        /// 正是 next_cluster 那道 sectors_per_fat 闸要拦的形状。
        short_fat: Option<u16>,
    }

    impl TestDisk {
        fn new() -> Self {
            Self {
                reads: Cell::new(0), mount_reads: Cell::new(0), fat_reads: Cell::new(0),
                fail_lba: Cell::new(None), fat_patch: None, size: None, wide: false, short_fat: None,
            }
        }
    }

    impl Block for TestDisk {
        fn read_sectors(&self, lba: u64, dst: &mut [u8]) -> Result<(), BlockError> {
            self.reads.set(self.reads.get() + 1);
            if self.fail_lba.get() == Some(lba) {
                return Err(BlockError::NotSettled);
            }
            if self.short_fat.is_some() && matches!(lba, 135 | 136) {
                for (i, b) in dst.iter_mut().enumerate() {
                    *b = (i * 3 + 0x11) as u8;
                }
            } else {
                MemDisk { img: IMAGE }.read_sectors(lba, dst)?;
            }
            if let Some(cluster) = self.short_fat {
                if matches!(lba, 0 | 6) {
                    dst[32..36].copy_from_slice(&210u32.to_le_bytes());
                }
                if lba == 10 {
                    // LONG~1.TXT 是根目录第 4 项（偏移 96）：簇号高半 116、低半 122
                    dst[116..118].copy_from_slice(&0u16.to_le_bytes());
                    dst[122..124].copy_from_slice(&cluster.to_le_bytes());
                }
            }
            if matches!(lba, 0 | 1 | 6) {
                self.mount_reads.set(self.mount_reads.get() + 1);
            }
            if lba == 8 {
                self.fat_reads.set(self.fat_reads.get() + 1);
                if let Some((cluster, value)) = self.fat_patch {
                    dst[cluster * 4..cluster * 4 + 4].copy_from_slice(&value.to_le_bytes());
                }
                if self.short_fat.is_some() {
                    // 夹具把未用簇填成 0x0FFF_FFF7（坏簇标记，掩码后 < EOC）——对照组簇 127
                    // 要的是"最后一项且是合法链尾"，不改这一格它会红在 BadCluster 而不是量具想量的闸。
                    dst[508..512].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
                }
            }
            if lba == 10 {
                if let Some(size) = self.size {
                    dst[124..128].copy_from_slice(&size.to_le_bytes());
                }
            }
            if self.wide {
                if matches!(lba, 0 | 6) {
                    dst[13] = 2;
                }
                if lba == 8 {
                    dst[16..20].copy_from_slice(&EOC_MARKER.to_le_bytes());
                }
                if (12..=15).contains(&lba) {
                    for (i, b) in dst.iter_mut().enumerate() {
                        *b = (i * 3 + 0x11 + (lba - 12) as usize * 29) as u8;
                    }
                }
            }
            Ok(())
        }
    }

    fn pattern(bytes: &[u8], start: usize) -> bool {
        // 与配方同一式子：扇区序号*29 那一项让相邻扇区逐字节不同——只按文件偏移算的话
        // 512*3 ≡ 0 (mod 256)，多扇区簇读错扇区也会绿（P7 审查抓到的盲点）。
        bytes.iter().enumerate().all(|(i, b)| {
            let n = start + i;
            *b == ((n / SECTOR_BYTES) * 29 + (n % SECTOR_BYTES) * 3 + 0x11) as u8
        })
    }

    fn t_fat32_cursor_memory() -> bool {
        let result = memory_cases();
        match result {
            Ok(ok) => ok,
            Err(e) => {
                crate::log_info!("fat32-cursor: memory unexpected={:?}", e);
                false
            }
        }
    }

    fn memory_cases() -> Result<bool, FsError> {
        let mut buf = [0u8; 1024];
        let mut chunks_ok = true;
        let mut eof_ok = true;
        let mut io_count_ok = true;
        let mut content_sum = 0u64;
        for chunk in [1, 511, 512, 513, 777, 1024] {
            let disk = TestDisk::new();
            let mut cursor = Volume::mount(&disk)?.open_cursor("LONG~1.TXT")?;
            let mut sum = crate::ahci::FNV_OFFSET;
            let mut n = 0;
            for _ in 0..2001 {
                buf.fill(0xA5);
                let got = cursor.read(&disk, &mut buf[..chunk])?;
                chunks_ok &= pattern(&buf[..got], n) && buf[got..].iter().all(|b| *b == 0xA5);
                for b in &buf[..got] {
                    sum = crate::ahci::fnv1a_step(sum, *b);
                }
                n += got;
                if got == 0 { break; }
            }
            chunks_ok &= n == 2000 && cursor.position() == 2000 && cursor.stat().size == 2000
                && sum == 0xf73f_3e28_ec8b_b345;
            content_sum = sum;
            let before = disk.reads.get();
            eof_ok &= cursor.read(&disk, &mut buf)? == 0 && cursor.read(&disk, &mut [])? == 0
                && disk.reads.get() == before;
            io_count_ok &= disk.mount_reads.get() == 3 && disk.fat_reads.get() == 4;
        }

        let disk = TestDisk::new();
        let mut detached = {
            let temporary = MemDisk { img: IMAGE };
            Volume::mount(&temporary)?.open_cursor("LONG~1.TXT")?
        };
        fn owned<T: Copy + 'static>(value: T) -> T { value }
        detached = owned(detached);
        let detached_ok = detached.read(&disk, &mut buf[..17])? == 17
            && pattern(&buf[..17], 0) && disk.mount_reads.get() == 0;
        let before = disk.reads.get();
        let empty_ok = detached.read(&disk, &mut [])? == 0 && detached.position() == 17
            && disk.reads.get() == before;

        let disk = TestDisk { size: Some(0), ..TestDisk::new() };
        let mut empty = Volume::mount(&disk)?.open_cursor("LONG~1.TXT")?;
        let before = disk.reads.get();
        let zero_ok = empty.read(&disk, &mut buf)? == 0 && empty.position() == 0 && disk.reads.get() == before;

        let disk = TestDisk::new();
        let mut cursor = Volume::mount(&disk)?.open_cursor("LONG~1.TXT")?;
        disk.fail_lba.set(Some(12));
        let data_error = cursor.read(&disk, &mut buf[..777]);
        let data_rollback = data_error == Err(FsError::Io(BlockError::NotSettled)) && cursor.position() == 0;
        disk.fail_lba.set(None);
        let retry_ok = cursor.read(&disk, &mut buf[..777])? == 777 && pattern(&buf[..777], 0)
            && cursor.position() == 777;

        let disk = TestDisk::new();
        let mut cursor = Volume::mount(&disk)?.open_cursor("LONG~1.TXT")?;
        let prefix = cursor.read(&disk, &mut buf[..511])?;
        disk.fail_lba.set(Some(8));
        let fat_error = cursor.read(&disk, &mut buf[..1]);
        let fat_rollback = prefix == 511 && fat_error == Err(FsError::Io(BlockError::NotSettled))
            && cursor.position() == 511;
        disk.fail_lba.set(None);
        let boundary_retry = cursor.read(&disk, &mut buf[..513])? == 513
            && pattern(&buf[..513], 511) && cursor.position() == 1024;

        let disk = TestDisk::new();
        let mut short = Volume::mount(&disk)?.open_cursor("SHORTCHN.BIN")?;
        let early_ok = short.read(&disk, &mut buf) == Err(FsError::ChainEndsEarly {
            bytes: 512, size: 4096, cluster: 12, next: EOC_MARKER,
        }) && short.position() == 0;
        let disk = TestDisk { size: Some(10), ..TestDisk::new() };
        let mut long = Volume::mount(&disk)?.open_cursor("LONG~1.TXT")?;
        let late_ok = long.read(&disk, &mut buf) == Err(FsError::ChainEndsLate {
            bytes: 10, size: 10, cluster: 3, next: 4,
        }) && long.position() == 0;

        let mut bad_cluster_ok = true;
        for value in [0, 1, 14, 0x0FFF_FFF0, 0x0FFF_FFF7] {
            let disk = TestDisk { fat_patch: Some((3, value)), ..TestDisk::new() };
            let mut cursor = Volume::mount(&disk)?.open_cursor("LONG~1.TXT")?;
            let before = disk.reads.get();
            bad_cluster_ok &= cursor.read(&disk, &mut buf) == Err(FsError::BadCluster(value))
                && cursor.position() == 0 && disk.reads.get() == before + 2;
        }

        let disk = TestDisk { wide: true, ..TestDisk::new() };
        let mut cursor = Volume::mount(&disk)?.open_cursor("LONG~1.TXT")?;
        let first = cursor.read(&disk, &mut buf[..1023])?;
        let wide_first = first == 1023 && pattern(&buf[..first], 0) && disk.fat_reads.get() == 0;
        let last = cursor.read(&disk, &mut buf)?;
        let wide_ok = wide_first && last == 977 && pattern(&buf[..last], 1023)
            && cursor.position() == 2000 && disk.fat_reads.get() == 2 && disk.mount_reads.get() == 3;

        let disk = TestDisk::new();
        let mut cyclic = Volume::mount(&disk)?.open_cursor("CYCLIC.BIN")?;
        let mut successes = 0;
        let mut bounded = false;
        for _ in 0..=MAX_CLUSTERS_WALKED {
            match cyclic.read(&disk, &mut buf[..512]) {
                Ok(512) => successes += 1,
                Err(FsError::ChainTooLong) => { bounded = true; break; }
                _ => break,
            }
        }
        let limit_ok = bounded && successes == MAX_CLUSTERS_WALKED
            && cyclic.position() == MAX_CLUSTERS_WALKED * 512;

        // FAT 表越界：BPB 自述 200 簇而 FAT 只有 128 项。簇 128 的数据读得动（适配器供字节），
        // 它的 FAT 项却在表外——必须在发 FAT 读之前拒，而不是读回数据区的字节当后继。
        let disk = TestDisk { short_fat: Some(128), size: Some(512), ..TestDisk::new() };
        let mut oob = Volume::mount(&disk)?.open_cursor("LONG~1.TXT")?;
        let fat_oob_ok = oob.read(&disk, &mut buf[..512]) == Err(FsError::BadCluster(128))
            && oob.position() == 0 && disk.fat_reads.get() == 0;
        // 对照组：簇 127 是 1 扇区 FAT 的最后一项（byte_off 508），必须读得动——
        // 没有这一格，"全拒"也能混出上面那格的绿。
        let disk = TestDisk { short_fat: Some(127), size: Some(512), ..TestDisk::new() };
        let mut edge = Volume::mount(&disk)?.open_cursor("LONG~1.TXT")?;
        let fat_edge_ok = edge.read(&disk, &mut buf[..512]) == Ok(512) && pattern(&buf[..512], 0)
            && edge.position() == 512 && disk.fat_reads.get() == 1;

        // 跨簇失败重试：第一跳已提交（簇 3→4），第二跳的数据读完、FAT 读失败——
        // 回滚必须落在**已提交的簇边界**（position 512、当前簇 4），不是 0 也不是 1024。
        // 重试若从簇 3 重读，逐扇区不同的内容会当场红（旧夹具在这里是盲的）。
        let disk = TestDisk::new();
        let mut cursor = Volume::mount(&disk)?.open_cursor("LONG~1.TXT")?;
        let hop1 = cursor.read(&disk, &mut buf[..512])?;
        disk.fail_lba.set(Some(8));
        let hop2_err = cursor.read(&disk, &mut buf[..512]);
        let cross_rollback = hop1 == 512 && hop2_err == Err(FsError::Io(BlockError::NotSettled))
            && cursor.position() == 512;
        disk.fail_lba.set(None);
        let cross_cluster_ok = cross_rollback
            && cursor.read(&disk, &mut buf[..512])? == 512
            && pattern(&buf[..512], 512) && cursor.position() == 1024;

        // 累计预算回滚：环链走到只剩最后一格预算时 FAT 读失败——失败的那一跳不许吃掉预算，
        // 否则重试会提前撞 ChainTooLong，而盘本身已经恢复。
        let disk = TestDisk::new();
        let mut budget_cursor = Volume::mount(&disk)?.open_cursor("CYCLIC.BIN")?;
        let mut budget_ok = true;
        for _ in 0..MAX_CLUSTERS_WALKED - 1 {
            budget_ok &= budget_cursor.read(&disk, &mut buf[..512]) == Ok(512);
        }
        let spent = (MAX_CLUSTERS_WALKED - 1) * 512;
        budget_ok &= budget_cursor.position() == spent;
        disk.fail_lba.set(Some(8));
        budget_ok &= budget_cursor.read(&disk, &mut buf[..512]) == Err(FsError::Io(BlockError::NotSettled))
            && budget_cursor.position() == spent;
        disk.fail_lba.set(None);
        budget_ok &= budget_cursor.read(&disk, &mut buf[..512]) == Ok(512) && budget_cursor.position() == spent + 512;
        budget_ok &= budget_cursor.read(&disk, &mut buf[..512]) == Err(FsError::ChainTooLong);

        let checks = [chunks_ok, eof_ok, io_count_ok, detached_ok, empty_ok, zero_ok,
            data_rollback, retry_ok, fat_rollback, boundary_retry, early_ok, late_ok, bad_cluster_ok, wide_ok, limit_ok,
            fat_oob_ok, fat_edge_ok, cross_cluster_ok, budget_ok];
        crate::log_info!("fat32-cursor: memory checks={:?} sum={:#018x} bound_reads={} position={}",
            checks, content_sum, successes, cyclic.position());
        Ok(checks.iter().all(|v| *v))
    }

    fn t_fat32_cursor_disks() -> bool {
        if crate::ahci::init().is_err() { return false; }
        let mut ok = true;
        for port in [crate::FAT_PORT_A, crate::FAT_PORT_B] {
            match disk_file(port) {
                Ok(good) => ok &= good,
                Err(e) => {
                    crate::log_info!("fat32-cursor: port={} error={:?}", port, e);
                    ok = false;
                }
            }
        }
        ok
    }

    fn disk_file(port: u8) -> Result<bool, FsError> {
        let disk = AhciDisk { port };
        let volume = Volume::mount(&disk)?;
        let mut cursor = volume.open_cursor("HELLO.ELF")?;
        let stat = cursor.stat();
        let mut old_hash = crate::ahci::FNV_OFFSET;
        let walk = volume.walk(&stat, |chunk| {
            for b in chunk { old_hash = crate::ahci::fnv1a_step(old_hash, *b); }
        })?;
        let mut hash = crate::ahci::FNV_OFFSET;
        let mut bytes = 0;
        let mut buf = [0u8; 777];
        for _ in 0..=stat.size as usize / buf.len() + 1 {
            let n = cursor.read(&disk, &mut buf)?;
            if n == 0 { break; }
            bytes += n;
            for b in &buf[..n] { hash = crate::ahci::fnv1a_step(hash, *b); }
        }
        let ok = bytes == stat.size as usize && bytes == walk.bytes && hash == old_hash
            && cursor.position() == stat.size;
        crate::log_info!("fat32-cursor: port={} size={} bytes={} first_cluster={} hash={:#018x} agree={}",
            port, stat.size, bytes, stat.first_cluster, hash, ok);
        Ok(ok)
    }

    crate::ktest!(KT_FAT32_CURSOR_MEMORY, t_fat32_cursor_memory);
    crate::ktest!(KT_FAT32_CURSOR_DISKS, t_fat32_cursor_disks);
}
