//! GPT 只读解析（ADR-078，W4 S1）。
//!
//! 这一格**只把盘上的分区结构当结构读**：核完整性、按条目流式回调、按 type GUID 查一条。
//! 它不挂载任何文件系统，也不认识 FAT —— `fat32::Volume::mount` 的语义一个字没动
//! （仍读整盘 LBA0、仍把保护性 MBR 拒为 `BadBytesPerSector(0)`，那条拒因被内核与宿主机
//! 两台仪器盯着）。分区偏移是 S2b 的事，由调用者显式传 base，本模块不替它决定。
//!
//! 三条设计取舍各有理由：
//! 1. **不存分区名单表**。今天盘上只有一个非空条目（ESP），新造一张 `MAX_PARTITIONS` 定长表
//!    就是给假想需求设计，还要多养一本容量账。改成流式回调 + 查询，状态全在调用者那边。
//! 2. **零 unsafe、零分配**。条目数组今天 16 KiB、根目录那一族 16 KiB，都远超堆上限 2048
//!    （ADR-018/026；按外部输入大小开缓冲在这台机上第一次分配就走 `handle_alloc_error`）。
//!    所以数组**按扇区流式扫**，栈上只要一个扇区缓冲 + 一个条目装配缓冲（合计 1 KiB，
//!    任务栈 16 KiB 也装得下），上界先验再用。
//! 3. **找到也不提前退出**。CRC 必须覆盖整个数组，提前退出就等于没核完整性 ——
//!    `find_by_type` 因此照样扫完，只是不再往回调里记第二条。

use crate::filesystem::vfs::{Block, BlockError, SECTOR_BYTES};

/// 保护性 MBR 在整盘 LBA0。
pub const MBR_LBA: u64 = 0;
/// 主 GPT 头在 LBA1。
pub const HEADER_LBA: u64 = 1;
/// UEFI 2.x 的 `EFI PART` 头 revision。
pub const GPT_REVISION: u32 = 0x0001_0000;
/// 头至少 92 字节（UEFI 布局到 `partition_entry_array_crc32` 为止）。
pub const MIN_HEADER_BYTES: u32 = 92;
/// 条目至少 128 字节（规范下限；名字字段占 56..128）。
pub const MIN_ENTRY_BYTES: u32 = 128;

/// **访问上限，不是"盘上应该有几个条目"**。与宿主机 `tools/validate_esp.py` 的
/// `entry_count(=128)` 逐字对账；两边各写一份数字而不核对正是手册 V8 点名的形状。
pub const MAX_ENTRIES: u32 = 128;
/// 一个条目最多装进一个扇区：装配缓冲只有这么大，再大就点名拒（不是静默截断）。
/// 今天盘上是 128，这个上限是**缓冲上限**而不是"应该长这样"，真机上要重测。
pub const MAX_ENTRY_BYTES: usize = SECTOR_BYTES;
/// 头最多读一个扇区：`parse_header` 只拿到 512 字节，再大就点名拒。
pub const MAX_HEADER_BYTES: usize = SECTOR_BYTES;
/// 走数组的字节预算（`MAX_ENTRIES × MAX_ENTRY_BYTES`）。今天实际是 128×128 = 16 KiB。
/// 没有界的时候，损坏镜像的表现不是报错而是**一次永不返回的循环**（ADR-038 决策 4 同族）。
pub const MAX_ARRAY_BYTES: u32 = MAX_ENTRIES * MAX_ENTRY_BYTES as u32;

/// EFI System Partition 的 type GUID `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`。
/// **混合端序**：前三段小端、后两段大端（与 `tools/esp_image.py` 的 `guid_bytes` 同一规矩）。
/// 写错端序不会编译不过，只会"找不到 ESP"——真盘那一格就是它的证人。
pub const ESP_TYPE_GUID: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];

// 头字段偏移。这是**第二份**偏移表（宿主机那份在 validate_esp.py / esp_image.py），
// 故意不共用：共用一张表就退化成一台仪器，两边错得一样时发现不了（ADR-038 决策 2）。
const OFF_REVISION: usize = 8;
const OFF_HEADER_SIZE: usize = 12;
const OFF_HEADER_CRC: usize = 16;
const OFF_MY_LBA: usize = 24;
const OFF_ALTERNATE_LBA: usize = 32;
const OFF_FIRST_USABLE: usize = 40;
const OFF_LAST_USABLE: usize = 48;
const OFF_DISK_GUID: usize = 56;
const OFF_ENTRY_LBA: usize = 72;
const OFF_ENTRY_COUNT: usize = 80;
const OFF_ENTRY_SIZE: usize = 84;
const OFF_ARRAY_CRC: usize = 88;

/// 每一格一个成因，**不许合并**：合并之后"盘坏了"和"参数写错"会长成同一个数。
/// 负样本要求红在**点名**的那一道闸上，所以每道闸各有一个变体。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptError {
    /// 块层失败原样透传，不吞不改名（`BlockError` 自己已经一格一个成因）。
    Io(BlockError),
    /// LBA0 不是保护性 MBR（`55 aa` 或第一个分区项类型 `0xEE` 不在位）。
    NoProtectiveMbr,
    /// 喂进来的扇区不足 512 字节（外部输入的边界，先验再用）。
    ShortSector(usize),
    BadSignature,
    BadRevision(u32),
    HeaderTooSmall(u32),
    HeaderTooBig(u32),
    /// 头 CRC 不符：`want` 是盘上说的，`got` 是自己算的。
    HeaderCrc { want: u32, got: u32 },
    EntryTooSmall(u32),
    EntryTooBig(u32),
    TooManyEntries(u32),
    ArrayCrc { want: u32, got: u32 },
    /// 备份头那一份的签名/CRC 单独命名，否则"主头坏了"与"备份坏了"分不开。
    BackupSignature,
    BackupCrc { want: u32, got: u32 },
    /// 交叉核不符：`field` 点名哪一格，两个数分别是主头说的与备份说的。
    BackupMismatch { field: &'static str, primary: u64, backup: u64 },
}

/// 主 GPT 头里读回的事实。**不含完整性结论**——结论由 `scan` 的 `Result` 给，
/// 免得到处都是"读到了但没核"的中间状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub revision: u32,
    pub header_size: u32,
    /// 盘上写着的头 CRC（核过的就是它）。
    pub header_crc: u32,
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub first_usable: u64,
    pub last_usable: u64,
    pub disk_guid: [u8; 16],
    pub entry_lba: u64,
    pub entry_count: u32,
    pub entry_size: u32,
    /// 盘上写着的条目数组 CRC。
    pub array_crc: u32,
}

/// 一条分区条目。**名字字段本轮不读不解码**（ADR-078 未决 3：今天只有 `Aurora ESP` 一条，
/// 解码涉及非 ASCII 与串口量）。`index` 是它在数组里的序号，从 0 起。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub index: u32,
    pub type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub attrs: u64,
}

impl Entry {
    /// 空条目 = type GUID 全零。UEFI 用它在 128 格里表示"这一格没分区"。
    pub fn is_empty(&self) -> bool {
        self.type_guid == [0u8; 16]
    }
}

/// 扫完一张表之后交回来的事实与**覆盖面**。`entries_seen` 与 `used` 不是装饰：
/// 前者证明真走过了若干条而不是"第一条就命中"，后者是回调次数的独立 recount
/// （调用者自己数一遍回调，两个数必须相等）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Table {
    pub header: Header,
    /// 交叉核通过的那份备份头。
    pub backup: Header,
    pub entries_seen: u32,
    pub used: u32,
    /// 自己流式算出来的数组 CRC（与 `header.array_crc` 相等才会返回 `Ok`）。
    pub array_crc: u32,
    pub array_bytes: u32,
}

/// CRC-32/ISO-HDLC（反射多项式 `0xEDB8_8320`），与宿主机 `binascii.crc32` 同一算法。
/// 内核今天零 CRC32 实现，这是第一处；它住在 `gpt.rs` 里而不是新开一个"通用校验和模块"，
/// 因为今天只有一个调用者（AGENTS 硬约束 2）。公开是为了让用例喂**已知答案向量**
/// （空串 = 0、`"123456789"` = `0xCBF4_3926`）——那两个常数是外部的，不是自己算给自己看。
pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(0, data)
}

/// 增量形式：流式扫一个扇区就喂一段。进出各取一次反，所以**可以链式调用**
/// （`crc32_update(crc32_update(0, a), b)` 等于一次算 `a ++ b`）。
fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    crc = !crc;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off], b[off + 1], b[off + 2], b[off + 3], b[off + 4], b[off + 5], b[off + 6], b[off + 7],
    ])
}

/// LBA0 是不是保护性 MBR：`55 aa` 在位**且**第一个分区项的类型字节是 `0xEE`。
/// 只认签名不够——FAT 卷的引导扇区也有 `55 aa`，那会把一块 superfloppy 当 GPT 盘收下。
pub fn protective_mbr(sector: &[u8]) -> bool {
    sector.len() >= SECTOR_BYTES && sector[510] == 0x55 && sector[511] == 0xAA && sector[446 + 4] == 0xEE
}

/// 解一个 512 字节的头扇区，并把签名/字段/头 CRC 三道闸走完。
/// `my_lba` 只读回来报数，不在这里判它等于 1：那由宿主机对账（它知道盘有多大）。
pub fn parse_header(sector: &[u8]) -> Result<Header, GptError> {
    if sector.len() < SECTOR_BYTES {
        return Err(GptError::ShortSector(sector.len()));
    }
    // 下面所有偏移都 < 92 <= header_size <= 512 <= sector.len()，索引不会越界。
    if &sector[0..8] != b"EFI PART" {
        return Err(GptError::BadSignature);
    }
    let revision = u32_at(sector, OFF_REVISION);
    if revision != GPT_REVISION {
        return Err(GptError::BadRevision(revision));
    }
    let header_size = u32_at(sector, OFF_HEADER_SIZE);
    if header_size < MIN_HEADER_BYTES {
        return Err(GptError::HeaderTooSmall(header_size));
    }
    if header_size as usize > MAX_HEADER_BYTES {
        return Err(GptError::HeaderTooBig(header_size));
    }
    let want = u32_at(sector, OFF_HEADER_CRC);
    let mut zeroed = [0u8; SECTOR_BYTES];
    zeroed.copy_from_slice(sector);
    zeroed[OFF_HEADER_CRC..OFF_HEADER_CRC + 4].fill(0);
    let got = crc32(&zeroed[..header_size as usize]);
    if got != want {
        return Err(GptError::HeaderCrc { want, got });
    }
    let mut disk_guid = [0u8; 16];
    disk_guid.copy_from_slice(&sector[OFF_DISK_GUID..OFF_DISK_GUID + 16]);
    Ok(Header {
        revision,
        header_size,
        header_crc: want,
        my_lba: u64_at(sector, OFF_MY_LBA),
        alternate_lba: u64_at(sector, OFF_ALTERNATE_LBA),
        first_usable: u64_at(sector, OFF_FIRST_USABLE),
        last_usable: u64_at(sector, OFF_LAST_USABLE),
        disk_guid,
        entry_lba: u64_at(sector, OFF_ENTRY_LBA),
        entry_count: u32_at(sector, OFF_ENTRY_COUNT),
        entry_size: u32_at(sector, OFF_ENTRY_SIZE),
        array_crc: u32_at(sector, OFF_ARRAY_CRC),
    })
}

fn parse_entry(b: &[u8], index: u32) -> Entry {
    let mut type_guid = [0u8; 16];
    type_guid.copy_from_slice(&b[0..16]);
    let mut unique_guid = [0u8; 16];
    unique_guid.copy_from_slice(&b[16..32]);
    Entry {
        index,
        type_guid,
        unique_guid,
        first_lba: u64_at(b, 32),
        last_lba: u64_at(b, 40),
        attrs: u64_at(b, 48),
    }
}

/// 核完整张表并按条目流式回调。**只对非空条目回调**（空条目不是分区），
/// 回调次数因此等于 `Table::used`；`entries_seen` 是扫过的总格数，两个数分开报。
///
/// 上下文：BOOT/KERNEL，调用者**不持任何锁**（要做块读，AHCI 可能等完成）。
/// 不分配内存；失败不升 L4、不 panic，`BlockError` 原样带上去。
pub fn scan(disk: &dyn Block, visit: &mut dyn FnMut(&Entry)) -> Result<Table, GptError> {
    let mut sector = [0u8; SECTOR_BYTES];
    disk.read_sectors(MBR_LBA, &mut sector).map_err(GptError::Io)?;
    if !protective_mbr(&sector) {
        return Err(GptError::NoProtectiveMbr);
    }
    disk.read_sectors(HEADER_LBA, &mut sector).map_err(GptError::Io)?;
    let header = parse_header(&sector)?;

    // 先验上界再用：这三个数都来自盘上，照着它们去读/开缓冲就是 BACKLOG 61a 那种死法。
    if header.entry_count > MAX_ENTRIES {
        return Err(GptError::TooManyEntries(header.entry_count));
    }
    if header.entry_size < MIN_ENTRY_BYTES {
        return Err(GptError::EntryTooSmall(header.entry_size));
    }
    if header.entry_size as usize > MAX_ENTRY_BYTES {
        return Err(GptError::EntryTooBig(header.entry_size));
    }
    // 上面两道闸之后乘积 <= 128×512 = MAX_ARRAY_BYTES，不会溢出 u32，
    // 所以**不再设第三道"数组太大"的闸**——那一道永远不可能 fire，留着就是死判据。
    let array_bytes = header.entry_count * header.entry_size;

    let entry_size = header.entry_size as usize;
    let mut carry = [0u8; MAX_ENTRY_BYTES];
    let mut carry_len = 0usize;
    let mut crc = 0u32;
    let mut remaining = array_bytes as usize;
    let mut lba = header.entry_lba;
    let mut index = 0u32;
    let mut used = 0u32;
    while remaining > 0 {
        disk.read_sectors(lba, &mut sector).map_err(GptError::Io)?;
        let take = remaining.min(SECTOR_BYTES);
        crc = crc32_update(crc, &sector[..take]);
        // 条目可以跨扇区（entry_size 不必整除 512），所以装够一条才解析、然后清空重装。
        let mut fed = 0usize;
        while fed < take {
            let n = (entry_size - carry_len).min(take - fed);
            carry[carry_len..carry_len + n].copy_from_slice(&sector[fed..fed + n]);
            carry_len += n;
            fed += n;
            if carry_len == entry_size {
                let e = parse_entry(&carry, index);
                index += 1;
                if !e.is_empty() {
                    used += 1;
                    visit(&e);
                }
                carry_len = 0;
            }
        }
        remaining -= take;
        lba += 1;
    }
    if crc != header.array_crc {
        return Err(GptError::ArrayCrc { want: header.array_crc, got: crc });
    }

    disk.read_sectors(header.alternate_lba, &mut sector).map_err(GptError::Io)?;
    if &sector[0..8] != b"EFI PART" {
        return Err(GptError::BackupSignature);
    }
    let backup = match parse_header(&sector) {
        Ok(h) => h,
        Err(GptError::HeaderCrc { want, got }) => return Err(GptError::BackupCrc { want, got }),
        Err(e) => return Err(e),
    };
    // 交叉核只核 ADR-078 决策 3 列的那五格。**不实现从备份恢复**：主头坏了就是坏了，
    // 备份头是第二份证词，不是回落路径（悄悄换一份会让判据更难写）。
    for (field, primary, backup_val) in [
        ("my_lba", header.alternate_lba, backup.my_lba),
        ("alternate_lba", header.my_lba, backup.alternate_lba),
        ("first_usable", header.first_usable, backup.first_usable),
        ("last_usable", header.last_usable, backup.last_usable),
        ("array_crc", u64::from(header.array_crc), u64::from(backup.array_crc)),
    ] {
        if primary != backup_val {
            return Err(GptError::BackupMismatch { field, primary, backup: backup_val });
        }
    }

    Ok(Table { header, backup, entries_seen: index, used, array_crc: crc, array_bytes })
}

/// 按 type GUID 找第一条命中的条目。找不到返回 `Ok(None)` 而不是错误——
/// "这块盘上没有 ESP"是业务事实（A 类），不是完整性失败。
pub fn find_by_type(disk: &dyn Block, type_guid: &[u8; 16]) -> Result<Option<Entry>, GptError> {
    let mut found: Option<Entry> = None;
    scan(disk, &mut |e| {
        if found.is_none() && e.type_guid == *type_guid {
            found = Some(*e);
        }
    })?;
    Ok(found)
}

/// 找 ESP。今天唯一的真实查询入口（S2b 会拿它的 `first_lba` 当挂载 base）。
pub fn find_esp(disk: &dyn Block) -> Result<Option<Entry>, GptError> {
    find_by_type(disk, &ESP_TYPE_GUID)
}