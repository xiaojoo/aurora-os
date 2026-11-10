//! 文件系统对下只要一样东西：**按扇区读**。
//!
//! 为什么是 trait 而不是直接叫 `ahci::read_bytes`：同一个解析器要能对着 AHCI 的第二块盘、
//! virtio-blk，以及**内存里的夹具镜像**跑同一套判据。第三条尤其关键——没有它，
//! "解析器对不对"只能靠真盘上的真文件验证，而那次失败没法区分是解析错还是传输错。
//! 今天有两个实现：`AhciDisk`（真控制器，两块卷挂在两个口）与 `MemDisk`（内存里那块
//! 11,264 字节的合成卷）。第三个——virtio-blk——**没做**：`virtio.rs` 的 `DEV` 是单设备静态，
//! 挂第二台就要把它改成按 BDF 的表，会动到已绿的第 22/33 行与 MSI-X 变体，那是另一次改动
//! （BACKLOG 78 的欠账带着这个理由，不是"还没来得及"）。
//!
//! 三个互相作证的实现之外还有两台仪器：宿主机 `tools/aurora.py` 用 Python 把同一块卷再解析一遍，
//! 以及造夹具的 `mtools`（`minfo` 的原文记在 BACKLOG 78）。

use crate::ahci::{self, AhciError};

/// 块设备的一次读失败。**每一格一个成因**，不许合并——合并之后"设备没接走这条命令"和
/// "上层参数写错"会长成同一个数，而那正是最该分开的两种。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// 控制器、端口或句柄根本不在位：这一次读没发出去
    NoDevice,
    /// 写了 `PxCI` 读回来是 0：设备没把命令接走
    NotIssued,
    /// 命令被接走但没在完成时限内落定（`wait_settled` 那一族超时）
    NotSettled,
    /// 设备正常完成了，但状态里带着错
    DeviceError,
    /// §8.2 的隔离把这个端口摘线了：命令没有下发
    Quarantined,
    /// 参数形状被拒（长度不是整扇区、扇区数超过环形缓冲容量、句柄层拒绝）
    Refused,
    /// 分区视图里越过了 GPT 给的那个区间（S2b）。**与 `Refused` 分开**：
    /// 一个是"这次请求的形状不对"，一个是"请求的形状对但要读的字节不属于这个分区"。
    /// 合成一个码，负样本就再也分不开"越界被拒"与"长度不是整扇区被拒"。
    BeyondPartition,
}

/// 一个分区在整盘上的区间，两端都是**整盘 LBA**、含末扇区。
/// 来源只有一个：GPT 条目（`gpt::Entry` 的 `first_lba`/`last_lba`）。
/// **这不是块层新开的容量账**：`Block` 那条"越过盘末尾由设备自己报"的承诺不变，
/// 这里判的是"这个分区到哪儿为止"，而那个界是分区表说的，不是块层猜的。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Partition {
    pub base: u64,
    pub last: u64,
}

impl Partition {
    /// 区间里的扇区数。`last < base` ⇒ 0（空区间，任何读都该被拒，而不是绕回整盘）。
    pub fn sectors(&self) -> u64 {
        self.last.checked_sub(self.base).map_or(0, |d| d + 1)
    }
}

/// 分区视图：把"分区内 LBA"翻成"整盘 LBA"，**翻之前**按 GPT 给的区间判越界。
///
/// 为什么是包装而不是给 `Volume::mount` 加一个 base 参数：ADR-078 决定"分区能力与 mount
/// 语义分离"，`mount` 认的一直是"这块 Block 的 LBA0 就是引导扇区"。偏移只活在这一层，
/// 于是 FAT12/16/32 那三族解析、游标、走链**一个字都不用改**，两块 superfloppy 真卷的
/// 读数也天然逐字不动（它们走的是 `AhciDisk`/`MemDisk`，根本不经过这里）。
pub struct PartitionView<'a> {
    pub inner: &'a dyn Block,
    pub part: Partition,
}

impl Block for PartitionView<'_> {
    fn read_sectors(&self, lba: u64, dst: &mut [u8]) -> Result<(), BlockError> {
        if dst.is_empty() || dst.len() % SECTOR_BYTES != 0 {
            return Err(BlockError::Refused);
        }
        let n = (dst.len() / SECTOR_BYTES) as u64;
        // 越界必须在**翻译之前**拒。交给 inner 去拒的话，`base + lba` 已经落到下一个分区
        // 或整盘末尾：那可能是"读成功但读到别人的字节"，判据就分不开"拒了"与"读错了"。
        let end = lba.checked_add(n).ok_or(BlockError::BeyondPartition)?;
        if end > self.part.sectors() {
            return Err(BlockError::BeyondPartition);
        }
        let abs = self.part.base.checked_add(lba).ok_or(BlockError::BeyondPartition)?;
        self.inner.read_sectors(abs, dst)
    }
}

impl BlockError {
    pub fn tag(self) -> &'static str {
        match self {
            BlockError::NoDevice => "无设备",
            BlockError::NotIssued => "未接走",
            BlockError::NotSettled => "未落定",
            BlockError::DeviceError => "设备报错",
            BlockError::Quarantined => "已隔离",
            BlockError::Refused => "参数被拒",
            BlockError::BeyondPartition => "越出分区",
        }
    }
}

/// 块层唯一承诺的扇区大小。`fat32` 用的是同一个常数，不是"看起来一样的第二个 512"。
pub const SECTOR_BYTES: usize = 512;

/// 一次能读多少字节由调用方给的缓冲区决定，所以这里只承诺"读完这些扇区"。
pub trait Block {
    /// 从 `lba` 开始读 `dst.len() / 512` 个扇区填进 `dst`。
    /// 长度必须是 512 的整数倍且不为 0——不是的话返回 `Refused`，不许静默截断。
    ///
    /// 越过盘末尾不单独设一种错误：那是设备自己报的（`DeviceError`），块层不维护第二份容量账。
    fn read_sectors(&self, lba: u64, dst: &mut [u8]) -> Result<(), BlockError>;
}

/// 打开一个文件要交回来的东西：大小、起始簇，以及**扫描的覆盖面**。
///
/// `entries_seen` 与 `lfn_entries` 不是装饰：前者证明扫描真的走过了若干条目录项而不是
/// "第一条就命中"（后者在别的夹具上会假绿），后者是"长名今天没实现"这件事的现场计数——
/// 判据要求它为 0，等于要求这条判据跑在真被实现的那条路上。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStat {
    pub size: u32,
    pub first_cluster: u32,
    pub entries_seen: u32,
    pub lfn_entries: u32,
}

/// `Block` 的唯一生产实现：AHCI 上的第 `port` 号口。
///
/// 适配器放在这一侧而不是 `ahci.rs` 里，是因为依赖方向只有一条：文件系统压在块设备上面。
/// 让驱动去 `impl` 文件系统的 trait，就把这条边反过来了。
#[derive(Debug, Clone, Copy)]
pub struct AhciDisk {
    pub port: u8,
}

impl Block for AhciDisk {
    fn read_sectors(&self, lba: u64, dst: &mut [u8]) -> Result<(), BlockError> {
        if dst.is_empty() || dst.len() % SECTOR_BYTES != 0 {
            return Err(BlockError::Refused);
        }
        for (i, chunk) in dst.chunks_mut(SECTOR_BYTES).enumerate() {
            // `Xfer` 里的取证读数（完成状态、内容哈希）在这一层被丢掉：上层要的是字节本身。
            // 丢掉的是**这一层用不上的读数**，成因仍从 `Err` 一路带上去。
            ahci::read_bytes(self.port, lba + i as u64, chunk).map_err(block_err)?;
        }
        Ok(())
    }
}

/// 内存里的夹具卷：整块镜像是一段 `.rodata`，读扇区就是切片拷贝。
///
/// 它的用途不是"另一台设备"，而是**便宜的分支覆盖**：环链走到 `MAX_CLUSTERS_WALKED`
/// 在真卷上是六万次块命令，在这里是一次循环。几何/偏移表的可信度由另一处担保——
/// 同一个 `parse_boot_sector` 必须也把 mtools 造的两块真卷读成同样的形状。
#[derive(Debug, Clone, Copy)]
pub struct MemDisk<'a> {
    pub img: &'a [u8],
}

impl Block for MemDisk<'_> {
    fn read_sectors(&self, lba: u64, dst: &mut [u8]) -> Result<(), BlockError> {
        if dst.is_empty() || dst.len() % SECTOR_BYTES != 0 {
            return Err(BlockError::Refused);
        }
        let start = lba as usize * SECTOR_BYTES;
        let end = start + dst.len();
        // 越界在这里是**参数错**而不是设备错：这块"盘"没有会回话的对端，
        // 而真盘上越界读是设备自己报的（M5-d ㉞）。两种读法不能混成一个成因。
        if end > self.img.len() {
            return Err(BlockError::Refused);
        }
        dst.copy_from_slice(&self.img[start..end]);
        Ok(())
    }
}

/// 逐个变体列举、**不写通配分支**：将来 `AhciError` 加一种错，这里会编译不过，
/// 而不是被悄悄归成一类。
fn block_err(e: AhciError) -> BlockError {
    match e {
        AhciError::NoController
        | AhciError::NotAhci(_)
        | AhciError::NoBar
        | AhciError::NotDecoding
        | AhciError::NoApic
        | AhciError::NoMsi
        | AhciError::MsiMismatch
        | AhciError::NotClaimed
        | AhciError::Ctx(_) => BlockError::NoDevice,
        AhciError::IssueStuck(_) => BlockError::NotIssued,
        AhciError::CmdTimeout
        | AhciError::CrTimeout(_)
        | AhciError::FrTimeout(_)
        | AhciError::StopTimeout(_)
        | AhciError::DrainStuck(_)
        | AhciError::ResetTimeout(_)
        | AhciError::AeStuck(_)
        | AhciError::PortCmdNotWritable(_)
        | AhciError::ResetScope(..) => BlockError::NotSettled,
        AhciError::BadCompletion { .. } => BlockError::DeviceError,
        AhciError::Quarantined => BlockError::Quarantined,
        AhciError::TooBig(_) | AhciError::Denied(_) => BlockError::Refused,
        AhciError::PhysAbove4G(_) | AhciError::VersionTooOld(_) => BlockError::NoDevice,
        AhciError::PortsDisagree { .. } | AhciError::RegionTooSmall { .. } | AhciError::TooManyPorts(_) => {
            BlockError::NoDevice
        }
    }
}
