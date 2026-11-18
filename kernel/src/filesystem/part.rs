//! C3（ADR-152）：磁盘/分区的**只读**查询出口。
//!
//! 总设计 C3 的验收句是"在测试镜像上可恢复已知故障；不允许对宿主机真实磁盘做
//! 默认写操作"。本片只做**只读查询**（`parted -l` 风格的 `part`），写操作
//! （创建/删除分区）按使用者裁决 ③A **不做**——那需要备份与保护机制先落地，
//! 是独立 ADR 的事。
//!
//! 形状纪律：
//! 1. **不缓存分区表**：每次调用重新扫（`gpt::scan`），所以"盘变了"立刻可见。
//!    代价是每次 32 个扇区读；对一个交互命令完全可接受。
//! 2. **无堆**：记录写进调用方给的缓冲，`gpt::scan` 的回调逐条填。
//! 3. **分页**：与 27/31/37/39 号同族，`(next<<32)|n`，`n == 0` 是表尾。
//! 4. **失败不猜**：扫不出来就是错误码，不返回"零个分区"（那是"盘上没有分区"
//!    与"读盘失败"混成一个结果，正是总设计 §12.2 禁止的那条）。

use crate::filesystem::gpt;
use crate::filesystem::vfs::{AhciDisk, Block};

/// 同一套记录形状，但**盘由调用方给**——ktest 用 `MemDisk` 的合成 GPT 测它，
/// 产品路径用 `AhciDisk`。两个入口共用 `fill_records`，形状只有一份。
pub fn part_read_block(
    disk: &dyn Block,
    cursor: u32,
    out: &mut [u8],
) -> Result<(PartInfo, usize), PartError> {
    fill_records(disk, cursor, out)
}

/// 一条分区记录的定长。
///
/// 布局（小端）：`index4 | first_lba8 | last_lba8 | attrs8 | type_guid16 = 44`，
/// 垫到 **48**（8 字节对齐）。**不带 unique_guid**：今天的命令（`part`）不显示它，
/// 而 16 字节会让一条记录涨到 60+；真要显示时扩形状比现在白占更合适。
pub const PART_RECORD_LEN: usize = 48;

/// 只读查询的失败面。**两种失败分开**：找不到盘（`NoDisk`）与表读不出来（`Gpt`）——
/// 把两者合成一个错误码就等于"盘坏了"和"盘不在"看起来一样。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartError {
    /// 认不出引导盘（今天由 `fs_open::port()` 给，恒有值；保留这个失败面）
    NoDisk,
    /// GPT 解析失败（保护性 MBR 不对、CRC 不符、条目越界……）
    Gpt(gpt::GptError),
}

/// 分区表本身的读数（`part` 的头部行）。
#[derive(Clone, Copy, Default)]
pub struct PartInfo {
    /// 分区条目总数（GPT 头里的 `entry_count`）
    pub entries: u32,
    /// 真正被用到的条目数（`type_guid` 非零）
    pub used: u32,
    /// 第一个可用 LBA（GPT 头 `first_usable`）
    pub first_usable: u64,
    /// 最后一个可用 LBA
    pub last_usable: u64,
}

/// 扫**指定端口**的分区表，把**用到的**条目按游标写进 `out`。
///
/// **为什么端口是参数而不是内部扫全盘**：实测 `gpt-probe` 档的口 0 是一块
/// 故意坏的盘（`wedge_port`），读它会重试到取证耗尽（几百行 ahci 取证、
/// 一行表都打不出来）。"扫全盘找一个有 GPT 的"在**故障盘存在**的机器上
/// 不是一个能终止的策略——盘选择必须由调用方给。
///
/// 返回 `(PartInfo, 写入条数)`。`cursor` 是"跳过前多少个**用到的**条目"，
/// 不是条目下标——分页的语义要跟"用户看到几条"一致，不是跟 GPT 的 128 格一致。
pub fn part_read_from(port: u8, cursor: u32, out: &mut [u8]) -> Result<(PartInfo, usize), PartError> {
    // **坏盘/空口一律不碰**：口 0 在多数档里是故意 wedge 的盘，任何 I/O
    // （包括一次扇区读）都会重试到取证耗尽、命令永不返回（实测刷几百行 ahci 取证）。
    let hw = match crate::ahci::info() {
        Some(i) => i,
        None => return Err(PartError::NoDisk),
    };
    if port >= hw.ports || (hw.pi & (1u32 << port)) == 0 {
        return Err(PartError::NoDisk);
    }
    if !matches!(crate::ahci::state(port), crate::ahci::State::Running) {
        return Err(PartError::NoDisk);
    }
    let disk = AhciDisk { port };
    fill_records(&disk, cursor, out)
}

/// 记录填充：两个入口（真盘 / 合成盘）共用这一份形状。
fn fill_records(
    disk: &dyn Block,
    cursor: u32,
    out: &mut [u8],
) -> Result<(PartInfo, usize), PartError> {
    // **先只读 LBA1 探 GPT 签名**（8 字节 "EFI PART"），是才跑完整 scan。
    // 没有 GPT 的盘（FAT32 根卷）直接回 `NoDisk`——那是正确的失败面，
    // 不是"盘上零个分区"。
    let mut sig = [0u8; 512];
    if disk.read_sectors(gpt::HEADER_LBA, &mut sig).is_err() {
        return Err(PartError::NoDisk);
    }
    if sig.get(0..8) != Some(&b"EFI PART"[..]) {
        return Err(PartError::NoDisk);
    }
    let mut info = PartInfo::default();
    let mut seen = 0u32;
    let mut n = 0usize;
    let table = gpt::scan(disk, &mut |e| {
        if e.is_empty() {
            return;
        }
        if seen < cursor {
            seen += 1;
            return;
        }
        seen += 1;
        if (n + 1) * PART_RECORD_LEN > out.len() {
            return;
        }
        let at = n * PART_RECORD_LEN;
        out[at..at + 4].copy_from_slice(&e.index.to_le_bytes());
        out[at + 4..at + 12].copy_from_slice(&e.first_lba.to_le_bytes());
        out[at + 12..at + 20].copy_from_slice(&e.last_lba.to_le_bytes());
        out[at + 20..at + 28].copy_from_slice(&e.attrs.to_le_bytes());
        out[at + 28..at + 44].copy_from_slice(&e.type_guid);
        n += 1;
    }).map_err(PartError::Gpt)?;
    info.entries = table.header.entry_count;
    info.used = seen;
    info.first_usable = table.header.first_usable;
    info.last_usable = table.header.last_usable;
    Ok((info, n))
}
