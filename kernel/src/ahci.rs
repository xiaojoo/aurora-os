//! §8.7.2 AHCI（SATA）主机控制器：认领、端口枚举、第一条 DMA 读（M5-b）。
//!
//! 五条决定本文件形状的规则：
//! 1. **决策只用没有歧义的仪器**。端口数由 `PI` 位图与 `CAP.NP+1` 两处**互相判相等**
//!    （字段位置经规范逐行核对，所以这次可以互证）；`CAP` 里其他计数只打印。
//! 2. **每个偏移都要有设备自己给的证据**：往端口 0 的 `PxCMD` 写 `FRE` 必须读得回来，
//!    随后 `HR` 复位必须把它清成 0（规范 §3.3.7 的复位值 + §10.4.3 的作用域）——
//!    这一组同时验住 GHC 的偏移、HR 的位、端口块基址 `0x100` 与 `PxCMD` 的偏移。
//!    再起端口时 `FRE→FR`、`ST→CR` 各验一次：任一位写错就等不到，有界等待当场 `Err`。
//! 3. **签名的两台仪器**：端口侧 `PxSIG`（0x24）与 `FRE` 打开时设备写进接收区 +0x40 的
//!    D2H FIS 里的分类字段，必须数到同一个 `0x0000_0101`。
//! 4. **最后一条判据落在内容上**：读回来的 512 字节必须与宿主机镜像对应偏移逐字节相同
//!    （`tools/aurora.py` 用同一个哈希函数对账）。表里任何一格错位只会读不到数据，
//!    不可能读成绿。
//! 5. **驱动的失败只降级、不打死系统**（§8.2）：所有失败路径都是 `Err`，用例把它读成
//!    一格红然后继续跑；没有 `panic`，也没有无界等待。
//!
//! 偏移与位的出处：Intel **AHCI 1.3.1 规范**（§3.1、§3.3、§4.2.3）、Linux
//! `drivers/ata/ahci.h`、**本机 QEMU 11.1.0 的 `hw/ide/ahci.c`**（就是我要驱动的那台设备）。
//! 三处不一致的地方在 ADR-029 里逐条记了以谁为准、为什么。

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use crate::acpi::Madt;
use crate::arch::x86_64::apic;
use crate::driver::{DmaHandle, DriverCtx, DriverError, IrqHandle, MmioHandle};
use crate::irq::Msg;
use crate::mm::{self, ModuleId};
use crate::pci;
use crate::tsc;

pub const MOD_AHCI: ModuleId = ModuleId(17);

// ---------------------------------------------------------------- HBA 全局寄存器
pub const REG_CAP: usize = 0x00;
pub const REG_GHC: usize = 0x04;
pub const REG_IS: usize = 0x08;
pub const REG_PI: usize = 0x0C;
pub const REG_VS: usize = 0x10;
pub const REG_CAP2: usize = 0x24;
pub const REG_GHC_AE: u32 = 1 << 31;
pub const REG_GHC_HR: u32 = 1 << 0;
/// GHC.IE：全局中断使能。这一格不是照抄规范写的——本机实测 QEMU 把 GHC 的写掩成
/// `0x3|AE`（`init` 里那句注释），也就是说 bit1 可写；可写这件事由"写下去读回来"判，
/// 判据在 `KT_IRQ_AHCI` 第二格。
pub const REG_GHC_IE: u32 = 1 << 1;
/// CAP 字段（§3.1.1）：`NP` 在 bits[4:0] 且是 **0 基**（端口数 = NP+1），
/// `NCS` 在 bits[12:8] 同样 0 基（每端口命令槽数 = NCS+1）
const CAP_NP: u32 = 0x1F;
const CAP_NCS: u32 = 0x1F00;
/// SAM（bits 19:18）：1 = 只做 AHCI 模式。它决定 `GHC.AE` 是不是只读，
/// 也就决定了"清掉 AE 再置起来"这种证法在这台机器上成不成立
const CAP_SAM: u32 = 3 << 18;
const CAP_S64A: u32 = 1 << 31;

// ---------------------------------------------------------------- 端口寄存器块
//
// AHCI 1.0 起端口块从 `0x100` 开始、每端口 0x80 字节（§3.3；0.9x 时代的 0x400 不用，
// 所以 `REG_VS` 的主版本号是这一格的判据之一）。
pub const PORTS_BASE: usize = 0x100;
pub const PORT_STRIDE: usize = 0x80;
const P_CLB: usize = 0x00; // 命令列表基址（低 32 位，要求 1024 字节对齐）
const P_FB: usize = 0x08; // 接收 FIS 区基址（要求 256 字节对齐）
const P_IS: usize = 0x10; // 中断状态（W1C）。M5-g② 起 `PxIE`(0x14) 会被 `start_port` 置起，
// 命令完成由中断告知；两张基址表的高半 (`PxCLBU` 0x04 / `PxFBU` 0x0C) 仍不写：物理内存只有
// 512 MiB，而 `init` 判过 `pa < 4 GiB`，复位后那两格本来就是 0
const P_IE: usize = 0x14; // 端口中断使能。这一格的**偏移与可写性**由 `KT_IRQ_AHCI` 第二格判，
// 不是我按规范认定的：写 1 之后读回来不含那一位，就如实报"这一格不是那一位"并退回轮询
const P_CMD: usize = 0x18;
const P_TFD: usize = 0x20; // bits 7:0 = ATA 状态（复位值 0x7F），15:8 = 错误
const P_SIG: usize = 0x24; // 设备签名（复位值 0xFFFFFFFF）
const P_SSTS: usize = 0x28; // SATA PHY 状态
const P_SERR: usize = 0x30;
const P_CI: usize = 0x38; // 命令发射：写 1 发第 0 槽，完成后硬件自己清
const P_SACT: usize = 0x34; // 活动命令位（设备接走哪一槽）

pub const CMD_ST: u32 = 1 << 0;
/// 只读旁证：`FR` 跟着 `FRE`、`CR` 跟着 `ST`
pub const CMD_FRE: u32 = 1 << 4;
const P_CMD_FR: u32 = 1 << 14;
const P_CMD_CR: u32 = 1 << 15;

const SSTS_DET: u32 = 0xF;
const SSTS_DET_PRESENT: u32 = 0x3;
pub const SIG_SATA_DISK: u32 = 0x0000_0101;

const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_STATUS_ERR: u8 = 1 << 0;
const ATA_STATUS_DRQ: u8 = 1 << 3;
// ATA 状态位里只有 ERR/BUSY 参与判定；本机 QEMU 空闲时报 0x50 = DRDY|DSC（0x04/0x40），
// 那两个名字不写成常量——写了没人判就是修辞
const ATA_STATUS_BUSY: u8 = 1 << 7;

// ---------------------------------------------------------------- 接收 FIS 区内部偏移
//
// §4.2.3 图 6：DSFIS 0x00、PSFIS 0x20、**D2H 0x40**、SDB 0x58。
const RX_D2H: u64 = 0x40;
/// FIS 类型：H2D 寄存器 = **0x27**，D2H 寄存器 = **0x34**。
/// 这两个数很容易记反（我自己一开始就写反了），所以它们各自有判据：
/// 设备完成后写回的 D2H 第一个字节必须是 0x34（`Read::cfis` 与 `Port::d2h_type`），
/// 而我们发出去的那条必须是 0x27 —— 写反了 QEMU 直接静默丢命令，`PxCI` 永远不落，
/// 有界等待当场 `CmdTimeout`。
const FIS_TYPE_H2D: u8 = 0x27;
pub const FIS_TYPE_D2H: u8 = 0x34;

// ---------------------------------------------------------------- 一条命令要的四块内存
//
// 一次 `DriverCtx::alloc_dma` 拿到连续物理内存，四片的对齐要求由偏移本身满足，
// 不必四次分配去赌对齐。UC 属性由 ctx 那层的 `PageFlags::DEVICE`（PCD）给：
// 设备写完我们立刻读，拿到缓存里的旧值会被读成"没搬回来"。
//
// **order=6 ⇒ 64 页 = 256 KiB，物理上就是 256 KiB 对齐**。之所以要这么大：M5-c 要把
// "扇区数高字节"从出处结论变成现场结论，那需要一次跨 255 扇区的传输（257 × 512 = 131584 字节），
// 一条 PRD 项的字段上限是 23 位（8 MiB − 1）所以装得下，但**数据缓冲必须真有那么大**——
// 这是"读得动的上限 = 缓冲大小"这条容量关系的第一个真实刻度。
const RING_ORDER: u8 = 6;
pub const RING_PAGES: usize = 1 << RING_ORDER;
const OFF_CLIST: u64 = 0x0000; // 命令列表：32 条表头 × 32 字节 = 1024
const OFF_CTBL: u64 = 0x01000; // 命令表（CFIS 在 +0x00，PRDT 在 +0x80）
pub const RX_BYTES: u64 = 0x100; // 规范要求每端口**各自**一条 256 字节的接收 FIS 区
pub const OFF_RXFIS: u64 = 0x02000; // 到 0x05FFF ⇒ 16 KiB = 64 个端口的槽位
const OFF_DATA: u64 = 0x06000; // 数据缓冲：256 KiB − 24 KiB = 232 KiB
const CTBL_CFIS: u64 = 0x00; // 命令表里 CFIS 的起点（§4.2.3 图 13）
const CTBL_PRDT: u64 = 0x80;
const HDW0: u64 = 0x00; // bits[4:0] CFL、bit6 W、bits[15:12] PMP、bits[31:16] PRDTL
const HDW1: u64 = 0x04; // PRDBC：设备自报"已搬多少字节"
const HDW2: u64 = 0x08; // 命令表物理基址（低 32 位，要求 128 字节对齐）
const HDW3: u64 = 0x0C;
/// DW0 的方向位：1 = 主机到设备（写）
const HDW_W: u32 = 0x40;
/// H2D 寄存器 FIS = 20 字节 = 5 个 DWORD（Linux 也固定用 5）
const CFL_H2D: u32 = 5;
pub const SECTOR: u64 = 512;
/// 一次传输的扇区数上限 = 数据缓冲 ÷ 512。**这是容量判据**：超了是 `TooBig`，
/// 不是悄悄截短（截短就是把"读 257 个扇区"变成"读 8 个"而没人报）。
pub const DATA_BYTES: u64 = (RING_PAGES as u64) * (mm::PAGE as u64) - OFF_DATA;
pub const MAX_SECTORS: u16 = (DATA_BYTES / SECTOR) as u16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AhciError {
    /// 枚举表里没有 class 0x01（mass storage）的设备
    NoController,
    /// 有存储控制器但不是 AHCI 接口（0x00 旧式 ATA、0x02 兼容模式）
    NotAhci(u8),
    /// ABAR 量不出尺寸，或尺寸探测后没能还原（配置空间被动坏，不许继续碰它）
    NoBar,
    /// 经 `DriverCtx` 的那条路拒绝了这次访问（映射、窗口、句柄、页框都在里面）
    Ctx(DriverError),
    /// 区域读回来全是 1：MMIO 没被解码
    NotDecoding,
    /// `GHC.AE` 置不上（规范 §3.1.2：碰任何其他寄存器之前必须先置起来）
    AeStuck(u32),
    /// `GHC.HR` 在有界窗口内没自己清零
    ResetTimeout(u32),
    /// `FRE` 写不进 `PxCMD`：端口块基址、`PxCMD` 的偏移、`FRE` 的位三者之一不对
    PortCmdNotWritable(u32),
    /// `FRE` 写得进去却清不掉：`HR` 的作用域没覆盖到端口块
    ResetScope(u32, u32),
    /// 主版本号不到 1：那端口块基址就不该按 0x100 走
    VersionTooOld(u32),
    /// `PI` 位图与 `CAP.NP + 1` 数不到同一个端口数
    PortsDisagree { pi: u32, cap_ports: u8 },
    /// ABAR 尺寸装不下 `PI` 说的那些端口
    RegionTooSmall { need: u64, have: u64 },
    /// 实现的端口数超过接收 FIS 区的容量（每端口 256 字节 × 16 格 = 一页）。
    /// 这是一条**容量**判据，不是"多出来的端口悄悄看不见"
    TooManyPorts(u8),
    /// 环形结构的物理地址到了 4 GiB 之外，而两张基址表只写了低 32 位
    PhysAbove4G(u64),
    /// 停端口时 `CR`/`FR` 不落
    StopTimeout(u32),
    /// 恢复前排不空挂着的那条旧命令（有界窗口内 `PxCI` 不落）：它的回执不属于任何
    /// 后来的命令，带着它继续就会把"读到旧命令的 DMA"当成"恢复了"
    DrainStuck(u32),
    /// `FRE` 置起后 `FR` 没跟上来
    FrTimeout(u32),
    /// `ST` 置起后 `CR` 没跟上来
    CrTimeout(u32),
    /// 命令发射后 `PxCI` 一直不落
    CmdTimeout,
    /// 写 `PxCI` 后读回来是 0：命令根本没被接走
    IssueStuck(u32),
    /// 请求的扇区数超出数据缓冲
    TooBig(u16),
    /// 参数形状不对（长度不是整扇区……），理由写成字符串免得靠猜
    Denied(&'static str),
    /// 完成状态不对：设备报 ERR/BUSY，或端口侧与 D2H 两台仪器不一致
    BadCompletion { status: u8, error: u8, dw1: u32, want: u32 },
    /// 还没认领成功就调了后面的接口
    NotClaimed,
    /// M5-g②：能力链里没有 MSI 块（`pci::irq_caps` 读回来的事实）。
    /// 与下一条的区别要说清：这一条是"这台设备不给我们中断"，下一条是"我们写进去的东西
    /// 不是我们算出来的那个" —— 前者的处置是退回轮询，后者必须先查自己的位段再谈退路
    NoMsi,
    /// M5-g②：写进设备 MSI 结构的三个 DWORD 读回来与核内算的消息不一致（或 enable 位没置上）
    MsiMismatch,
    /// M5-g②：接入中断需要 APIC 状态（消息里的目的地就是它的 id），而它没能初始化
    NoApic,
    /// §8.2：这个端口超过重试预算被隔离，命令**没有下发**就返回
    Quarantined,
}

#[derive(Clone, Copy, Debug)]
pub struct Info {
    pub bdf: u32,
    pub abar: u64,
    /// ABAR 的尺寸（BAR 探测实测，不是规范里的"应当"）
    pub size: u64,
    pub cap: u32,
    pub cap2: u32,
    pub vs: u32,
    pub pi: u32,
    /// `CAP.NP + 1`：与 `popcount(PI)` 判成相等
    pub cap_ports: u8,
    /// `CAP.NCS + 1`：每端口命令槽数（本驱动只用第 0 槽，这个数拿来打印）
    pub slots: u8,
    /// `popcount(PI)`：本驱动认这个数
    pub ports: u8,
    /// GHC 的四步读数：认领前 / 置 AE 后 / 写 HR 那一瞬 / 复位完成后
    pub ghc_before: u32,
    pub ghc_ae: u32,
    pub ghc_hr: u32,
    pub ghc_after: u32,
    /// 复位作用域证据的两格：写 `FRE` 之后读回来的 `PxCMD`、`HR` 之后读回来的 `PxCMD`
    pub cmd_fre_written: u32,
    pub cmd_after_hr: u32,
    /// 复位后 0 号端口的 `PxSIG`（应当是全 1）与 `PxCLB`
    pub sig_after_hr: u32,
    pub clb_after_hr: u32,
    pub sam: bool,
    pub s64a: bool,
    /// CAP/GHC/PI/VS/CAP2 里读到全 1 的个数（应当是 0）
    pub reads_ff: u8,
    pub ring_pa: u64,
}

/// 一个端口的取证读数。
#[derive(Clone, Copy, Debug)]
pub struct Port {
    pub num: u8,
    pub cmd: u32,
    pub clb: u32,
    pub fb: u32,
    pub is: u32,
    pub tfd: u32,
    pub sig: u32,
    pub ssts: u32,
    /// 接收区里那条 FIS 的类型字节：`FRE` 打开后设备必须写来一条 D2H（0x34）
    pub d2h_type: u8,
    pub fr: bool,
    pub cr: bool,
}

impl Port {
    pub fn det(&self) -> u32 {
        self.ssts & SSTS_DET
    }
    /// 在位的 SATA 磁盘 = PHY 认到设备（det=0b0011）且签名认出类型
    pub fn is_sata_disk(&self) -> bool {
        self.det() == SSTS_DET_PRESENT && self.sig == SIG_SATA_DISK
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Enum {
    pub ports: [Port; 32],
    pub n: usize,
    /// 第一台在位的 SATA 磁盘在哪一口；没有就 `None`，各口读数照样都在 `ports` 里
    pub disk: Option<u8>,
    /// **所有**在位的 SATA 磁盘口（M5-c 的高 LBA 实验要拿第二块盘）
    pub disks: [u8; 32],
    pub n_disks: usize,
}

/// 一次块传输的完成取证（读与写共用这一份结构，字段含义见各处注释）。`hash` 由用例打印、由 `tools/aurora.py` 与宿主机文件对账。
#[derive(Clone, Copy, Debug)]
pub struct Xfer {
    pub port: u8,
    pub want: u32,
    /// 命令表头 DW1 的**原值**（规范说 bits 31:16 是 PRDBC；本机 QEMU 报在低 16 位）
    pub dw1: u32,
    pub status: u8,
    /// 签名的两台仪器：端口侧 `PxSIG` 与接收区 D2H 的分类字段
    pub sig_port: u32,
    pub sig_d2h: u32,
    /// 接收区那条 D2H 的类型字节（必须 0x34）
    pub d2h_type: u8,
    /// 数据缓冲里仍然等于哨兵 `0xEE` 的字节数（只打印，见上面那段撞车的事）
    pub untouched: u32,
    pub hash: u64,
}

/// 驱动从 `DriverCtx` 拿到的三样东西：令牌、寄存器窗口句柄、DMA 缓冲句柄。
/// 全部**没有指针、没有映射对象**——资源本体留在句柄表里（§8.5），
/// 这份结构被 drop 也不会解映射，因为句柄是复制出去的整数（见 `RingCell` 那条注释）。
struct Ring {
    ctx: DriverCtx,
    mmio: MmioHandle,
    dma: DmaHandle,
    info: Info,
}

struct RingCell(UnsafeCell<Option<Ring>>);
// SAFETY: 只有 BSP 在 ktest 序列里写一次，之后只读（与 `pci::TABLE` 同一条理由）
unsafe impl Sync for RingCell {}
static RING: RingCell = RingCell(UnsafeCell::new(None));

// ------------------------------------------------------------------ §8.2 的生命周期
//
// `Resetting` 只存在于一次调用内部（进来→尝试→出去），所以对外只有两个稳定态；
// 但**计数是分开的**：`resets` 说"重置了几次"，`quarantines` 说"隔离了几个口"，
// 少了后者就没法证明"隔离之后不再碰设备"这件事真的发生过。
pub const RETRY_BUDGET: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Running,
    /// 超过重试预算：此后所有命令直接 `Err(Quarantined)`，一个寄存器都不再碰
    Quarantined,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    /// 每个口的 reset 尝试次数（含失败的）
    pub resets: u32,
    /// 因失败而被隔离的端口数
    pub quarantines: u32,
    /// 干净错误（设备正常完成但带 ERR/ABRT）的次数：这类**不该**触发 reset
    pub clean_errors: u32,
}

static PORT_STATE: [AtomicU8; 32] = [const { AtomicU8::new(0) }; 32];
static PORT_RESETS: [AtomicU32; 32] = [const { AtomicU32::new(0) }; 32];
/// 每个端口因"发射被吞"而重置的次数，与 §8.2 的故障预算分开数（见 `recover_for_issue`）
static PORT_ISSUE_RESETS: [AtomicU32; 32] = [const { AtomicU32::new(0) }; 32];
static QUARANTINES: AtomicU32 = AtomicU32::new(0);
static CLEAN_ERRORS: AtomicU32 = AtomicU32::new(0);
/// 0 = 没有；否则存的是"端口号 + 1"
static DEAD_PORT: AtomicU32 = AtomicU32::new(0);
/// 0 = 没查过；否则存的是"引导盘所在端口 + 1"（见 `boot_port`）
static BOOT_PORT: AtomicU32 = AtomicU32::new(0);
/// 0 = 不覆盖
static OP_OVERRIDE: AtomicU32 = AtomicU32::new(0);

const ST_RUNNING: u8 = 0;
const ST_QUARANTINED: u8 = 1;

fn state_of(num: u8) -> State {
    match PORT_STATE[usize::from(num & 31)].load(Ordering::Relaxed) {
        ST_QUARANTINED => State::Quarantined,
        _ => State::Running,
    }
}

pub fn stats() -> Stats {
    let resets = PORT_RESETS.iter().map(|c| c.load(Ordering::Relaxed)).sum();
    Stats {
        resets,
        quarantines: QUARANTINES.load(Ordering::Relaxed),
        clean_errors: CLEAN_ERRORS.load(Ordering::Relaxed),
    }
}

/// 错误分类：只有"卡住类"才值得重置端口。
///
/// 这条分界不是审美，是量出来的：干净错误（设备正常完成但带 ERR/ABRT，非法命令码
/// 就是这一类）之后同一个端口接着读完全正常。
/// 对这种错误去 reset，等于把"检测"和"处置"混成一个动作，坏一次就抖整个控制器。
fn wedges(e: &AhciError) -> bool {
    matches!(
        e,
        AhciError::CmdTimeout | AhciError::IssueStuck(_) | AhciError::CrTimeout(_) | AhciError::StopTimeout(_)
    )
}

/// §8.2 的 `Resetting`：把端口停干净再重新起一次（`start_port` 本身就是这个动作）。
/// 成功 ⇒ 回到 `Running`；失败累加预算，超了就 `Quarantined`。
fn recover(num: u8) -> State {
    PORT_RESETS[usize::from(num & 31)].fetch_add(1, Ordering::Relaxed);
    match start_port(num) {
        Ok(_) => State::Running,
        Err(_) => {
            if PORT_RESETS[usize::from(num & 31)].load(Ordering::Relaxed) >= RETRY_BUDGET {
                PORT_STATE[usize::from(num & 31)].store(ST_QUARANTINED, Ordering::Relaxed);
                QUARANTINES.fetch_add(1, Ordering::Relaxed);
                State::Quarantined
            } else {
                State::Running
            }
        }
    }
}

/// 因"发射被吞"而做的重置**不进 §8.2 的故障预算**：设备没报错，是那条命令根本没进设备，
/// 重发一次就好了；预算是给"反复失败的口"准备的。分开数而不是合并，是因为合并之后
/// 引导口一次被吞就会顶掉 `引导口resets == 0` 那条"故障没跨口传染"的判据 ——
/// 红的是一桩根本没发生的传染（实测飘红过一次）。分开之后两件事都还看得见：这一格单独计数、
/// 一起打印，不许藏。
fn recover_for_issue(num: u8) {
    PORT_ISSUE_RESETS[usize::from(num & 31)].fetch_add(1, Ordering::Relaxed);
    start_port(num).ok();
}

/// 单个端口因被吞而重置的次数（合计用 `issue_resets_total`）。
pub fn issue_resets_of(num: u8) -> u32 {
    PORT_ISSUE_RESETS[usize::from(num & 31)].load(Ordering::Relaxed)
}

pub fn issue_resets_total() -> u32 {
    PORT_ISSUE_RESETS.iter().map(|c| c.load(Ordering::Relaxed)).sum()
}

/// 端口的当前状态（用例据此判"隔离真的发生了"而不是"返回了个 Err"）。
pub fn state(num: u8) -> State {
    state_of(num)
}

/// 单个端口的重置次数。全局 `stats().resets` 说不了"粒度"这件事：
/// 引导口的这一格恒为 0，才是"一个口的故障没抖到另一个口"的证据。
pub fn resets_of(num: u8) -> u32 {
    PORT_RESETS[usize::from(num & 31)].load(Ordering::Relaxed)
}

/// 端口里还挂着哪几条没答完的命令（`PxCI` 原值）。恢复的收尾判据用它：
/// `start_port` 返回时必须是 0，否则下一条命令读到的回执可能不是它自己的。
pub fn pending_cmds(num: u8) -> Result<u32, AhciError> {
    r32(port_off(num, P_CI))
}

/// 把端口放回 `Running` 并重新起一次。**这不是 §8.2 状态机的一条边**
/// （真机上隔离是终态，要等热插拔或驱动重载），它存在的理由是 `.ktests` 的顺序
/// 由链接器决定，用例不许把后面那个用例的盘留在隔离态。
pub fn release_quarantine(num: u8) -> Result<Port, AhciError> {
    PORT_STATE[usize::from(num & 31)].store(ST_RUNNING, Ordering::Relaxed);
    start_port(num)
}

/// 关掉端口引擎（清 `ST`）⇒ 命令没人接走 ⇒ `PxCI` 恒为 1 ⇒ 卡住类错误。
pub fn wedge_port(num: u8) -> Result<(), AhciError> {
    let base = port_off(num, P_CMD);
    let cmd = r32(base)?;
    w32(base, cmd & !CMD_ST)
}

/// 注入"这个口修不好"：让 `start_port` 对它必然失败。
/// 这是**设备侧**的注法（不是把驱动的代码改坏），否则测的是驱动自己写的分支而不是恢复逻辑。
pub fn inject_dead_port(num: u8) {
    DEAD_PORT.store(u32::from(num) + 1, Ordering::Relaxed);
}

pub fn revive_port() {
    DEAD_PORT.store(0, Ordering::Relaxed);
}

/// 注入"非法命令码"：设备会以 ERR 完成（干净错误），用来验"检测到了但不该抖控制器"。
pub fn set_op_override(op: u8) {
    OP_OVERRIDE.store(u32::from(op), Ordering::Relaxed);
}

pub fn info() -> Option<Info> {
    // SAFETY: 见 RingCell
    unsafe { (*RING.0.get()).as_ref().map(|r| r.info) }
}

/// 寄存器窗口经句柄表访问。返回的是 `(令牌, 句柄)` 两个 Copy 值——
/// 驱动侧从这里 onward 拿不到指针，也拿不到能解引用的映射对象。
fn mmio_ref() -> Result<(DriverCtx, MmioHandle), AhciError> {
    // SAFETY: 见 RingCell。`RING` 只在 `init` 里写过一次，此后并发只读
    unsafe { (*RING.0.get()).as_ref().map(|r| (r.ctx, r.mmio)).ok_or(AhciError::NotClaimed) }
}

/// DMA 缓冲同理：句柄 + 总线地址。总线地址是整数，只用来填描述符。
fn dma_ref() -> Result<(DriverCtx, DmaHandle), AhciError> {
    // SAFETY: 见 RingCell
    unsafe { (*RING.0.get()).as_ref().map(|r| (r.ctx, r.dma)).ok_or(AhciError::NotClaimed) }
}

/// 环形结构基址（总线地址）。两张基址表与 PRDT 都从它算偏移。
fn ring_bus() -> Result<u64, AhciError> {
    let (ctx, h) = dma_ref()?;
    ctx.bus_addr(h).map_err(AhciError::Ctx)
}

/// 偏移全部由上面的常量算出，整块窗口 `RING_PAGES * PAGE`（256 KiB）⇒ 必然落在 usize 里
fn idx(at: u64) -> usize {
    at as usize
}

fn r32(off: usize) -> Result<u32, AhciError> {
    let (ctx, h) = mmio_ref()?;
    ctx.read32(h, off).map_err(AhciError::Ctx)
}

fn w32(off: usize, v: u32) -> Result<(), AhciError> {
    let (ctx, h) = mmio_ref()?;
    ctx.write32(h, off, v).map_err(AhciError::Ctx)
}

fn port_off(num: u8, reg: usize) -> usize {
    PORTS_BASE + PORT_STRIDE * usize::from(num) + reg
}

/// 有界自旋等一个条件成立。`ms` 按实测 TSC 频率换算周期；取不到频率就按 4 GHz 估一个
/// **上界**（宁可多等也要有界）。返回"有没有等到"，绝不无限循环。
fn wait_ms(f: impl Fn() -> bool, ms: u64) -> bool {
    let t0 = tsc::now();
    let budget = crate::clock::hz().map_or(ms * 4_000_000, |hz| hz * ms / 1000);
    loop {
        if f() {
            return true;
        }
        core::hint::spin_loop();
        if tsc::now().wrapping_sub(t0) > budget {
            return false;
        }
    }
}

// ------------------------------------------------------------------ M5-g② 中断认领
//
// 一颗 MSI、一条向量、一面旗子。**三本账分开**：顶半进来过几次（`ISR_ENTRY`）、
// 它认领了几发（`irq::counts` 里的 hits）、命令是靠中断落定的还是靠寄存器落定的
// （`IRQ_HITS` / `POLL_HITS`）。合成一本就没法回答"这条盘是不是其实还在轮询"。

/// 顶半立起来的那面旗：一次命令落定过。取法用 `swap`——谁取到算谁的，
/// 所以同一发不会既进 `IRQ_HITS` 又进 `POLL_HITS`（一次命令只有一个成因）。
static IRQ_FLAG: AtomicBool = AtomicBool::new(false);
static IRQ_HITS: AtomicUsize = AtomicUsize::new(0);
static POLL_HITS: AtomicUsize = AtomicUsize::new(0);
/// 寄存器先落定、中断随后到过（`wait_settled` 的 ②）
static RACE_HITS: AtomicUsize = AtomicUsize::new(0);
/// ② 里量到的最大间隔（周期）：它决定 `RACE_GRACE` 是实测还是拍的
static RACE_MAX: AtomicU64 = AtomicU64::new(0);
static ISR_ENTRY: AtomicUsize = AtomicUsize::new(0);
/// L3-B（BACKLOG 73f）：**谁在服务**。总账与分账同时记，两边必须同数（那条不变量由用例判）。
/// 只有总账的时候，"目的地搬到 AP 之后到底是谁在执行顶半"这件事只能从投递分布反推；
/// MSI-X 一上来就是一向量一目的地，反推就不够用了。
static ISR_ENTRY_CPU: [AtomicUsize; crate::arch::x86_64::cpu::MAX_CPUS] =
    [const { AtomicUsize::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];
/// 同理，宽限窗那两笔按"等的那一侧是谁"分开数：`RACE_HITS` 是总数，这里是分账与每核最大间隔。
static RACE_HITS_CPU: [AtomicUsize; crate::arch::x86_64::cpu::MAX_CPUS] =
    [const { AtomicUsize::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];
static RACE_MAX_CPU: [AtomicU64; crate::arch::x86_64::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];

/// 顶半。规矩：不分配、不打印、不碰命令表、不发命令——只读 `PxIS`、按 W1C 原样写回、
/// 清全局 `IS` 里本端口那一位、把旗子立起来。
/// 返回"这一发是不是我的"：今天 MSI 一台一条向量，答案原则上恒真，但接口留成布尔——
/// 本机 GSI 10/11 是**共享线**（`irq_caps` 实测），将来走 INTx 时不必改签名。
/// 把 `PxIS` 里读到的那几位写回去清掉（W1C）。
///
/// 这颗函数存在的唯一理由是 `irq-sticky-pxis` 变体需要一个**只有一颗**的注入点：
/// 顶半与起口路径上的清都从这里走，而接入时那次初始清（`arm_irq` 里）不从这里走——
/// 初始清是在开使能**之前**，它不是"服务后清源"这件事的一部分。
fn clear_pxis(num: u8, bits: u32) -> Result<(), AhciError> {
    #[cfg(feature = "irq-sticky-pxis")]
    {
        let _ = (num, bits);
        Ok(())
    }
    #[cfg(not(feature = "irq-sticky-pxis"))]
    w32(port_off(num, P_IS), bits)
}

fn ahci_isr() -> bool {
    ISR_ENTRY.fetch_add(1, Ordering::Relaxed);
    ISR_ENTRY_CPU[crate::arch::x86_64::cpu::self_slot()].fetch_add(1, Ordering::Relaxed);
    // 引导口还没定下来 ⇒ 不认领这一发。宁可让轮询那条路把命令收掉，
    // 也不在中断上下文里走 `boot_port()`：它会 `enumerate()` 并**发射命令**（递归进自己）。
    let cached = BOOT_PORT.load(Ordering::Relaxed);
    if cached == 0 {
        return false;
    }
    let num = (cached - 1) as u8;
    let Ok(is) = r32(port_off(num, P_IS)) else { return false };
    if is == 0 {
        return false;
    }
    // 端口侧先清、全局侧后清（与 `start_port` 里那条 §10.1.2 的清理顺序同一形状）。
    // 清掉的位**只写回读到的那些**：`PxIS` 是 W1C，写 1 是"清"而不是"置"，写全 F 会把
    // 别人刚挂上的位一起抹掉——今天这台设备只有我们在用，那条性质今天用不上，但先不违反它。
    let _ = clear_pxis(num, is);
    let _ = w32(REG_IS, 1 << num);
    IRQ_FLAG.store(true, Ordering::Release);
    true
}

/// 靠中断落定的命令数
pub fn irq_hits() -> usize {
    IRQ_HITS.load(Ordering::Relaxed)
}

/// 靠寄存器读数落定的命令数（正常路径必须是 0，见 `KT_IRQ_AHCI` 第三格）
pub fn poll_hits() -> usize {
    POLL_HITS.load(Ordering::Relaxed)
}

/// 顶半被叫起来的次数（含它说"不是我的"的那些）
pub fn isr_entry() -> usize {
    ISR_ENTRY.load(Ordering::Relaxed)
}

/// 只给用例：三本账归零 + 旗子放下（"这一格涨了没有"必须有起点）
pub fn irq_counters_reset() {
    IRQ_HITS.store(0, Ordering::Relaxed);
    POLL_HITS.store(0, Ordering::Relaxed);
    RACE_HITS.store(0, Ordering::Relaxed);
    RACE_MAX.store(0, Ordering::Relaxed);
    ISR_ENTRY.store(0, Ordering::Relaxed);
    for c in ISR_ENTRY_CPU.iter() {
        c.store(0, Ordering::Relaxed);
    }
    for c in RACE_HITS_CPU.iter() {
        c.store(0, Ordering::Relaxed);
    }
    for c in RACE_MAX_CPU.iter() {
        c.store(0, Ordering::Relaxed);
    }
    IRQ_FLAG.store(false, Ordering::Relaxed);
}

/// 赛跑那一格的两本账：`(寄存器先落定而中断随后到过的次数, 窗内量到的最大间隔周期)`
pub fn race_stats() -> (usize, u64) {
    (RACE_HITS.load(Ordering::Relaxed), RACE_MAX.load(Ordering::Relaxed))
}

/// 顶半按 CPU 的分账（索引是槽号）。与 `irq::by_cpu()` 不同源：那本数"投递到过哪颗核"，
/// 这本数"顶半在哪颗核上跑过"——两者不等就说明派发与执行之间还有别的东西。
pub fn isr_entry_by_cpu() -> [usize; crate::arch::x86_64::cpu::MAX_CPUS] {
    let mut out = [0usize; crate::arch::x86_64::cpu::MAX_CPUS];
    for (i, c) in ISR_ENTRY_CPU.iter().enumerate() {
        out[i] = c.load(Ordering::Relaxed);
    }
    out
}

/// 宽限窗那笔的分账：`(每核命中数, 每核最大间隔)`。
pub fn race_by_cpu() -> ([usize; crate::arch::x86_64::cpu::MAX_CPUS], [u64; crate::arch::x86_64::cpu::MAX_CPUS]) {
    let mut hits = [0usize; crate::arch::x86_64::cpu::MAX_CPUS];
    let mut maxs = [0u64; crate::arch::x86_64::cpu::MAX_CPUS];
    for i in 0..crate::arch::x86_64::cpu::MAX_CPUS {
        hits[i] = RACE_HITS_CPU[i].load(Ordering::Relaxed);
        maxs[i] = RACE_MAX_CPU[i].load(Ordering::Relaxed);
    }
    (hits, maxs)
}

/// 中断链路上那三位的此刻读数：`(GHC, 引导口的 PxIE, 引导口的 PxIS)`。
/// **"写下去读回来"必须在判据里做一次，而不是只在我打日志的那一次**——
/// 打印的那一刻它成立，不代表下一格命令时它还成立。
pub fn irq_gates() -> Result<(u32, u32, u32), AhciError> {
    let num = boot_port()?;
    Ok((r32(REG_GHC)?, r32(port_off(num, P_IE))?, r32(port_off(num, P_IS))?))
}

/// 接入中的那颗中断（`arm_irq` 写，`irq_handle` 读）。
///
/// 为什么单独一格而不塞进 `Ring`：`Ring` 的不变量是"`init` 里写一次、之后只读"，
/// 而中断接入是**另一件事的前置**（要有 APIC 状态），它发生的时刻比 `init` 晚、
/// 次数也比 `init` 少（幂等）。把两者做成一格，就会有人为了在 `init` 里接中断而放宽那条不变量。
struct ArmCell(UnsafeCell<Option<IrqHandle>>);
// SAFETY: 只有 BSP 在 ktest 序列里写（`arm_irq`），读方是任务上下文与顶半——
// 顶半只读句柄里的向量号，而写发生在没有中断可来之前（enable 位还没置上）。
unsafe impl Sync for ArmCell {}
static ARM: ArmCell = ArmCell(UnsafeCell::new(None));

/// 把这颗控制器的完成通知接到中断上。**四步一步不许少，也不许改顺序**：
/// ① 先把前置要齐（APIC 状态：消息目的地是 BSP 的 LAPIC id，没有它就算不出那三个 DWORD）；
/// ② 向核内要一颗向量；③ 把**核内算出的**消息写进设备的 MSI 结构，并在同一格里逐字回读对账；
/// ④ 对上了才置 `GHC.IE` 与本口 `PxIE`。
/// 任何一步不成就退回轮询并说明原因——退回不是遮掩：`wait_settled` 那本账会数进
/// `poll_hits`/`race_hits`，而 `KT_IRQ_AHCI` ③ 要求正常路径"完全没等到中断"那一本是 0。
/// 顺序反了（先开闸门再对账）会打开一条没人认领的线，那一发的归属就说不清了。
/// 幂等：已经接上就直接回报那颗向量，不许再要一格（重复调用要是在表里攒下三颗向量，
/// 撤销与复用那格的判据就会被自己的历史污染）。
pub fn arm_irq(m: &Madt) -> Result<u8, AhciError> {
    if let Some(h) = irq_handle() {
        return Ok(h.vector);
    }
    let st = apic::get_or_init(m).map_err(|_| AhciError::NoApic)?;
    let (ctx, _) = mmio_ref()?;
    let dev = ctx.device();
    let caps = dev.irq_caps();
    let h = ctx.request_irq(ahci_isr).map_err(AhciError::Ctx)?;
    let Some(msi) = caps.msi else {
        crate::log_warn!(
            "ahci: 接入 MSI 块不存在（pin={} line={:#04x}）⇒ 撤销认领{}，这台控制器全程轮询",
            caps.pin, caps.line, h.vector
        );
        let _ = ctx.release_irq(h);
        return Err(AhciError::NoMsi);
    };
    let (alo, ahi, data) = ctx.irq_message(h).map_err(AhciError::Ctx)?;
    let (same, back_lo, back_hi, back_data, back_ctrl) =
        program_msi(&msi, &Msg { addr_lo: alo, addr_hi: ahi, data })?;
    crate::log_info!(
        "ahci: 接入 MSI 块={:#04x} 向量={:#04x} 目的地={:#04x} 64位={} mmc={} 写=({:#010x},{:#010x},{:#010x}) 读回=({:#010x},{:#010x},{:#010x}) ctrl={:#06x} 逐字一致={}",
        msi.off, h.vector, st.id, msi.sixtyfour, msi.mmc, alo, ahi, data,
        back_lo, back_hi, back_data, back_ctrl, same
    );
    if !same {
        crate::log_warn!("ahci: 接入回读不一致 ⇒ 撤销认领，这台控制器全程轮询");
        let _ = ctx.release_irq(h);
        return Err(AhciError::MsiMismatch);
    }
    let ghc = r32(REG_GHC)?;
    w32(REG_GHC, ghc | REG_GHC_IE)?;
    let ghc_back = r32(REG_GHC)?;
    // 本口的挂起位先清干净再开使能：反序的话初始 D2H 那一发会在闸门后面等着，
    // 第一条命令就把"上一条的余温"当成自己的回执。
    let num = boot_port()?;
    let is = r32(port_off(num, P_IS))?;
    w32(port_off(num, P_IS), is)?;
    w32(REG_IS, 1 << num)?;
    let ie = r32(port_off(num, P_IE))?;
    w32(port_off(num, P_IE), ie | 1)?;
    let ie_back = r32(port_off(num, P_IE))?;
    crate::log_info!(
        "ahci: 接入 闸门 GHC 写={:#010x} 读回={:#010x} IE位={} ｜ 口{} PxIE 写={:#010x} 读回={:#010x} 那一位={} IS残留={:#010x}",
        ghc | REG_GHC_IE, ghc_back, (ghc_back >> 1) & 1, num, ie | 1, ie_back, ie_back & 1,
        r32(port_off(num, P_IS))?
    );
    // SAFETY: 见 ArmCell；此刻 enable 位刚置上，之前没有中断可来，所以没有并发写者
    unsafe { *ARM.0.get() = Some(h) };
    Ok(h.vector)
}

/// 把核内算好的那条 MSI 消息写进设备的 MSI 块，再原样读回来对一遍。
///
/// `arm_irq`（接入）与 `set_affinity`（换目的地）共用这一颗：编程只该有一个地方，
/// 否则两条路各写一套位段，"移动之后中断还来不来"量的就成了我自己的抽象而不是设备。
/// 数据 DWORD 的位置跟着地址形态走（64 位 +12、32 位 +8），这一格由回读判不由我认定；
/// ctrl 只置 enable 那一位，能力头与 mmc 保持设备自报的形状。
fn program_msi(msi: &pci::Msi, m: &Msg) -> Result<(bool, u32, u32, u32, u32), AhciError> {
    let (ctx, _) = mmio_ref()?;
    let dev = ctx.device();
    let data_off = if msi.sixtyfour { 12 } else { 8 };
    let base = u32::from(msi.off);
    dev.cfg_write(base + 4, m.addr_lo);
    if msi.sixtyfour {
        dev.cfg_write(base + 8, m.addr_hi);
    }
    dev.cfg_write(base + data_off, m.data);
    let hdr = dev.cfg32(base);
    let ctrl = ((hdr >> 16) & 0xFFFF) | 1;
    dev.cfg_write(base, (hdr & 0xFFFF) | (ctrl << 16));
    let back_lo = dev.cfg32(base + 4);
    let back_hi = if msi.sixtyfour { dev.cfg32(base + 8) } else { 0 };
    let back_data = dev.cfg32(base + data_off);
    let back_ctrl = (dev.cfg32(base) >> 16) & 0xFFFF;
    let same =
        back_lo == m.addr_lo && back_hi == m.addr_hi && back_data == m.data && back_ctrl & 1 != 0;
    Ok((same, back_lo, back_hi, back_data, back_ctrl))
}

/// L3-B：把这颗中断的目的地换成 `lapic_id`，并重编程设备。返回 `(回读逐字一致, 目的地槽, 消息)`。
///
/// 边界要点名：今天**没有做静默**（不 mask 就换目的地）。在这台 QEMU 上换目的地之后仍按序投递，
/// 但真机上移动途中在飞的那一发归谁处理没有保证——那要等 `DriverCtx` 有 mask 能力再说。
pub fn set_affinity(lapic_id: u8) -> Result<(bool, usize, Msg), AhciError> {
    let (ctx, _) = mmio_ref()?;
    let dev = ctx.device();
    let caps = dev.irq_caps();
    let Some(msi) = caps.msi else { return Err(AhciError::NoMsi) };
    let h = irq_handle().ok_or(AhciError::NotClaimed)?;
    let m = ctx.irq_set_affinity(h, lapic_id).map_err(AhciError::Ctx)?;
    let slot = crate::arch::x86_64::cpu::slot_of_lapic(u64::from(lapic_id)).ok_or(AhciError::NotClaimed)?;
    let (same, bl, bh, bd, bc) = program_msi(&msi, &m)?;
    crate::log_info!(
        "ahci: 亲和性 目的地={:#04x} 槽={} 向量={:#04x} 写=({:#010x},{:#010x},{:#010x})          读回=({:#010x},{:#010x},{:#010x}) ctrl={:#06x} 逐字一致={}",
        lapic_id, slot, h.vector, m.addr_lo, m.addr_hi, m.data, bl, bh, bd, bc, same
    );
    Ok((same, slot, m))
}

/// 现在的目的地是哪颗 CPU（表里说的，没读设备）。
pub fn affinity_dest() -> Option<u8> {
    let (ctx, _) = mmio_ref().ok()?;
    let h = irq_handle()?;
    ctx.irq_dest(h).ok()
}

/// 接到哪颗中断上了。`None` = 还没接入（没调用、能力链里没有 MSI、或回读不一致），
/// 此后所有命令都走寄存器读数那本账 —— 那个"照旧"会被 `poll_hits`/`race_hits` 数出来，
/// 不靠注释声明。
pub fn irq_handle() -> Option<IrqHandle> {
    // SAFETY: 见 ArmCell
    unsafe { *ARM.0.get() }
}

/// 那颗向量的编号。用例拿它去对 `apic::counts()` 里按线号索引的那一格。
pub fn irq_vector() -> Option<u8> {
    irq_handle().map(|h| h.vector)
}

/// 只给用例：把接入状态抹掉（撤销路径自己走完，不留一颗"表里还挂着但设备已关"的认领）
pub fn disarm_irq_for_test() {
    if let Some(h) = irq_handle() {
        let _ = set_msi_enabled(false);
        if let Ok((ctx, _)) = mmio_ref() {
            let _ = ctx.release_irq(h);
        }
    }
    // SAFETY: 见 ArmCell
    unsafe { *ARM.0.get() = None };
}

/// 这颗控制器的 MSI 结构在哪：`(设备, 块偏移)`。没认领过就没有，返回 `NotClaimed`。
fn msi_loc() -> Result<(pci::Dev, u8), AhciError> {
    if irq_handle().is_none() {
        return Err(AhciError::NotClaimed);
    }
    let (ctx, _) = mmio_ref()?;
    let dev = ctx.device();
    let m = dev.irq_caps().msi.ok_or(AhciError::NoMsi)?;
    Ok((dev, m.off))
}

/// 设备 MSI 结构里此刻写着的四个数：`(addr_lo, addr_hi, data, ctrl)`。
/// 判据靠它——**内核算的消息必须与设备里的读数逐字相同**，否则"写进去了"只是我说的。
/// 数据那一格的偏移跟着地址形态走（64 位 = 块首 +12，32 位 = +8），这里重算而不是记住：
/// 记住它就是我第二次实现同一个位段（见 `irq.rs` 开头那条"不许有第二个实现"）。
pub fn msi_witness() -> Option<(u32, u32, u32, u32)> {
    let (dev, off) = msi_loc().ok()?;
    let m = dev.irq_caps().msi?;
    let base = u32::from(off);
    let data_off = if m.sixtyfour { 12 } else { 8 };
    Some((
        dev.cfg32(base + 4),
        dev.cfg32(base + 8),
        dev.cfg32(base + data_off),
        (dev.cfg32(base) >> 16) & 0xFFFF,
    ))
}

/// 负样本的旋钮：把设备 MSI 的 enable 位开/关。**只动那一位**——先读回 ctrl，
/// 再连同能力头（低 16 位，只读的那半）一起写回去。把 mmc 顺手写掉的话，
/// "关掉中断"就变成"改坏了设备配置"，红的那一格就不是它声称的那件事了。
pub fn set_msi_enabled(on: bool) -> Result<(), AhciError> {
    let (dev, off) = msi_loc()?;
    let hdr = dev.cfg32(u32::from(off));
    let ctrl = (hdr >> 16) & 0xFFFF;
    let new = if on { ctrl | 1 } else { ctrl & !1 };
    dev.cfg_write(u32::from(off), (hdr & 0xFFFF) | (new << 16));
    Ok(())
}

/// 命令发射之后等它落定。三种成因，**三本账**：
/// ① `IRQ_HITS`：旗子先到；② `RACE_HITS`：条件先成立，宽限窗内旗子也到了；
/// ③ `POLL_HITS`：宽限窗到点旗子始终没来 ⇒ 这才是"真在靠轮询"（负样本那一格走这里）。
///
/// **旗子的作用是"提前醒来"，不是"可以不看落定条件"**。这一条是本轮实测出来的教训：
/// 第一版把"中断到过"直接当成落定返回，宿主机对账当场报
/// `槽0 对不上：宿主机解出 种类=1 seq=1 failed=0，内核报 种类=1 seq=1 failed=1`
/// ——接收区那条 D2H 到达时 DMA 数据还没搬完，读回来的就是缓冲里上一条命令留下的旧字节。
/// 所以这里的"条件"必须是 `PxCI` 落下（或带错完成那条形状）**并且** `PxTFD` 的 BSY/DRQ 都清，
/// 也就是把原来的两级等待合成一个判据，而不是让中断那一路绕过它。
///
/// 保留 ②③ 不是偷懒：一次配置错误就把整块启动盘变成"不可用"，那个半径我们承担不起
/// （§8.2 会把端口推进隔离，进而让启动判定进 Safe，而"降级出得来"是 M6-a③ 立过的规矩）。
/// 代价说清楚：判据不是"没有轮询就红"，而是"中断一次都没来过就红"——仍然可红，
/// 只是红话要说成计数。今天一次只在飞行一条命令（第 0 槽），一面旗子配得上一条；
/// NCQ 多命令并发时这面旗子不够，那一格欠在 BACKLOG。
fn wait_settled(ci: usize, d2h: u64, tfd_off: usize) -> bool {
    // 落定的完整条件：两种"命令不再挂着"的形状之一，**加上**传输真的结束（BSY/DRQ 清）
    let settled_hard = || {
        let Ok(tfd) = r32(tfd_off) else { return false };
        if (tfd as u8) & (ATA_STATUS_BUSY | ATA_STATUS_DRQ) != 0 {
            return false;
        }
        if r32(ci).map_or(true, |v| v & 1 == 0) {
            return true;
        }
        if rb(d2h).unwrap_or(0) != FIS_TYPE_D2H {
            return false;
        }
        let s = rb(d2h + 2).unwrap_or(0);
        s & ATA_STATUS_ERR != 0 && s & (ATA_STATUS_BUSY | ATA_STATUS_DRQ) == 0
    };
    let t0 = tsc::now();
    let budget = crate::clock::hz().map_or(1_000 * 4_000_000, |hz| hz);
    let mut woken = false;
    loop {
        if IRQ_FLAG.swap(false, Ordering::AcqRel) {
            woken = true;
        }
        if settled_hard() {
            if woken {
                IRQ_HITS.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            // 条件先成立。给中断一个宽限窗，看它是不是"设备发过、只是晚了几微秒"——
            // 不把这一格与"真没来"分开数，就会拿赛跑的输赢当"中断配没配上"的结论（偶发红的形状）。
            // 窗内量到的最大间隔记进 `RACE_MAX`，所以 `RACE_GRACE` 是实测的还是拍的，账上看得见。
            let g0 = tsc::now();
            loop {
                if IRQ_FLAG.swap(false, Ordering::AcqRel) {
                    let gap = tsc::now().wrapping_sub(g0);
                    RACE_HITS.fetch_add(1, Ordering::Relaxed);
                    RACE_MAX.fetch_max(gap, Ordering::Relaxed);
                    let w = crate::arch::x86_64::cpu::self_slot();
                    RACE_HITS_CPU[w].fetch_add(1, Ordering::Relaxed);
                    RACE_MAX_CPU[w].fetch_max(gap, Ordering::Relaxed);
                    return true;
                }
                if tsc::now().wrapping_sub(g0) > RACE_GRACE {
                    break;
                }
                core::hint::spin_loop();
            }
            POLL_HITS.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        core::hint::spin_loop();
        if tsc::now().wrapping_sub(t0) > budget {
            return false;
        }
    }
}

/// 宽限窗的周期数（见 `wait_settled`）。本机 `tsc_hz≈3.4 G` ⇒ 约 100 µs，比一次 tick（10 ms）
/// 短两个数量级。"它比命令完成到消息落地的间隔长"这一半不许我说了算：窗内量到的最大间隔
/// 记进 `RACE_MAX` 并由用例打出来（本轮实测 16,260 周期 ⇒ 窗是它的 21 倍）。
const RACE_GRACE: u64 = 350_000;

// ------------------------------------------------------------------ 环形结构内存
// 全部走 `DriverCtx` 的 volatile 访问器：窗口边界由句柄表检查，本模块不再自己算 VA。
fn rb(at: u64) -> Result<u8, AhciError> {
    let (ctx, h) = dma_ref()?;
    ctx.dma_read8(h, idx(at)).map_err(AhciError::Ctx)
}

fn rl(at: u64) -> Result<u32, AhciError> {
    let (ctx, h) = dma_ref()?;
    ctx.dma_read32(h, idx(at)).map_err(AhciError::Ctx)
}

fn wl(at: u64, v: u32) -> Result<(), AhciError> {
    let (ctx, h) = dma_ref()?;
    ctx.dma_write32(h, idx(at), v).map_err(AhciError::Ctx)
}

fn wb(at: u64, v: u8) -> Result<(), AhciError> {
    let (ctx, h) = dma_ref()?;
    ctx.dma_write8(h, idx(at), v).map_err(AhciError::Ctx)
}

/// 填一段。数据缓冲在每次发射命令前重新填成哨兵 `0xEE` 而不是清零：
/// **"DMA 一个字节都没搬"和"搬回来一堆 0"必须分得开**。
fn fill(at: u64, pat: u8, n: usize) -> Result<(), AhciError> {
    let (ctx, h) = dma_ref()?;
    ctx.dma_fill(h, idx(at), pat, n).map_err(AhciError::Ctx)
}

// ------------------------------------------------------------------ 认领

/// 认领 AHCI 设备：量 BAR → 开 MSE|BME → 映射 ABAR → 核对端口数与版本 → 置 AE →
/// HBA 复位并检查复位作用域 → 建 DMA 环形结构。
///
/// 任何一步不成立就回 `Err`，并且**不会**留下半初始化的静态表：后面的用例因此不会把
/// 一个没认领成功的设备读成"驱动坏了"。
pub fn init() -> Result<Info, AhciError> {
    // 幂等：认领只做一次。两条用例谁先跑都由这条兜住（`.ktests` 段的顺序不跟着源码顺序，
    // 实测过第二次认领会再分配一次环形结构并把前一份的映射与页框一起 drop 掉）。
    if let Some(i) = info() {
        return Ok(i);
    }
    // 认领按三件套（class 0x01 / subclass 0x06 / progif 0x01），不是"第一台存储设备"：
    // 挂上 virtio-blk 之后那台槽位在前，只按 class 找会认领错设备。两种失败分得开——
    // 一台存储设备都没有 vs 有但不是 SATA-AHCI
    let dev = match pci::first_of_triple(0x01, 0x06, 0x01) {
        Some(d) => d,
        None if pci::count_of_class(0x01) > 0 => {
            return Err(AhciError::NotAhci(pci::first_of_class(0x01).map(|d| d.progif()).unwrap_or(0)));
        }
        None => return Err(AhciError::NoController),
    };
    // §8.5：认领设备要的资源全部从 ctx 出去——量 BAR、开 `MSE|BME`、映射窗口都在表里做，
    // 驱动拿到的是句柄。`abar` 只是**报告**用的配置空间读数（`mem_bar` 不映射任何东西）。
    let ctx = DriverCtx::for_device(MOD_AHCI, dev);
    let mmio = ctx.map_mmio(5).map_err(AhciError::Ctx)?;
    let (abar, _is64) = dev.mem_bar(5).ok_or(AhciError::NoBar)?;
    let size = ctx.mmio_len(mmio).map_err(AhciError::Ctx)? as u64;
    // bit1 = Memory Space Enable（不开它寄存器读回来全是 1），bit2 = Bus Master Enable。
    // 授权是句柄里读回来的证据，不是"map 返回了 Ok"就默认成立
    let authorized = ctx.mmio_authorized(mmio).map_err(AhciError::Ctx)?;
    if authorized & 0b110 != 0b110 {
        crate::log_fatal!("ahci: 命令寄存器置位后读回 {:#06x}，MSE|BME 没成立", authorized);
        return Err(AhciError::NotDecoding);
    }
    let read = |off: usize| ctx.read32(mmio, off).unwrap_or(0xFFFF_FFFF);
    // `init` 之内只能用这两个闭包碰设备：静态表要到本函数最后才写，
    // 而 `r32/w32` 走的是那张表——在那里调用只会得到 `NotClaimed`。
    let rd = |off: usize| ctx.read32(mmio, off).map_err(AhciError::Ctx);
    let wr = |off: usize, v: u32| ctx.write32(mmio, off, v).map_err(AhciError::Ctx);

    let cap = read(REG_CAP);
    let (pi, vs) = (read(REG_PI), read(REG_VS));
    let pi_ones = pi.count_ones();
    let cap_ports = (cap & CAP_NP) + 1;
    // 两条独立来源必须数到同一个端口数：`PI` 是位图、`CAP.NP` 是 0 基计数
    if pi_ones == 0 || pi_ones != cap_ports {
        return Err(AhciError::PortsDisagree { pi, cap_ports: cap_ports as u8 });
    }
    // 端口块基址 0x100 只适用于 1.0 及以后（0.9x 是 0x400）：主版本号由 `REG_VS` 供
    if (vs >> 16) < 1 {
        return Err(AhciError::VersionTooOld(vs));
    }
    let need = PORTS_BASE as u64 + PORT_STRIDE as u64 * u64::from(pi_ones);
    if need > size {
        return Err(AhciError::RegionTooSmall { need, have: size });
    }
    if pi_ones > (mm::PAGE as u32 / RX_BYTES as u32) {
        return Err(AhciError::TooManyPorts(pi_ones as u8));
    }

    // 环形结构先建好：复用的哨兵值要写进 `PxCLB`，那需要一个真实的总线地址。
    // 一页页框 + UC 别名由 `alloc_dma` 做（连续物理内存按 2 的幂，所以 `len` 就是
    // `RING_PAGES * PAGE`）；驱动侧之后只有句柄与偏移，没有 VA。
    let dma = ctx.alloc_dma(RING_PAGES * mm::PAGE).map_err(AhciError::Ctx)?;
    let pa = ctx.bus_addr(dma).map_err(AhciError::Ctx)?;
    if pa >= 0x1_0000_0000 {
        // 两张基址表与 PRDT 都只写了低 32 位 ⇒ 这条盘在这台机器上必须落在 4 GiB 之下。
        // 真正的解法是 64 位基址（`PxCLB` 高半已经留了格子）或 IOMMU，都还没做（BACKLOG）
        return Err(AhciError::PhysAbove4G(pa));
    }

    // AE：这一台 `CAP.SAM` 说控制器只做 AHCI 模式 ⇒ 复位值就是 1 且清不掉，
    // 所以"先清再置"这种证法在这台机器上不成立（QEMU 把 GHC 的写掩成 `0x3|AE`）。
    // 判据换成"置得起，且 SAM 读回来解释得清它为什么只读"——SAM 自己也是一格实测。
    let sam = cap & CAP_SAM != 0;
    let ghc_before = read(REG_GHC);
    wr(REG_GHC, ghc_before | REG_GHC_AE)?;
    let ghc_ae = read(REG_GHC);
    if ghc_ae & REG_GHC_AE == 0 {
        return Err(AhciError::AeStuck(ghc_ae));
    }
    // 复位作用域的证据：先证明端口 0 的 `PxCMD` 真能收 `FRE`（写下去读得回来），
    // 再打 `HR`，之后 `PxCMD` 必须回到复位值 0。这一组一起验住：`REG_GHC` 的偏移、
    // `HR` 的位、端口块基址 `0x100`、`P_CMD` 的偏移、`FRE` 的位。
    let port0_cmd = port_off(0, P_CMD);
    wr(port0_cmd, CMD_FRE)?;
    let cmd_fre_written = rd(port0_cmd)?;
    if cmd_fre_written & CMD_FRE == 0 {
        return Err(AhciError::PortCmdNotWritable(cmd_fre_written));
    }
    let sentinel = (pa + OFF_CLIST) as u32;
    wr(port_off(0, P_CLB), sentinel)?;
    wr(REG_GHC, ghc_ae | REG_GHC_HR)?;
    let ghc_hr = read(REG_GHC);
    let reset_done = wait_ms(|| read(REG_GHC) & REG_GHC_HR == 0, 1000);
    let ghc_after = read(REG_GHC);
    if !reset_done {
        return Err(AhciError::ResetTimeout(ghc_after));
    }
    let cmd_after_hr = rd(port0_cmd)?;
    if cmd_after_hr & CMD_FRE != 0 {
        return Err(AhciError::ResetScope(cmd_fre_written, cmd_after_hr));
    }
    // `PxSIG` 与 `PxCLB` 这两格只打印不判：规范说 `PxCLB` 不在 `HR` 复位的名单里，
    // 而 QEMU 的复位作用域比规范窄（它把端口寄存器也清了）。**谁说了算由读数定**，
    // 所以两格都留着，等这一轮的日志来指哪条是错的。
    let sig_after_hr = read(port_off(0, P_SIG));
    let clb_after_hr = read(port_off(0, P_CLB));
    let cap2 = read(REG_CAP2);
    let reads_ff = [cap, ghc_after, pi, vs, cap2].iter().filter(|v| **v == 0xFFFF_FFFF).count() as u8;
    if reads_ff != 0 {
        return Err(AhciError::NotDecoding);
    }

    // M5-g②：接入中断**不在这里做**，见 `arm_irq`。理由是一条读数，不是风格：
    // 本模块的 `init` 由启动早期的状态区读回触发（`main.rs` 那一处 `ahci::init()`），
    // 而本地 APIC 是后来才 `get_or_init` 的 ⇒ 在这里算不出消息目的地。
    // 把"认领控制器"与"接入中断"合成一步，就等于把两件事的前置条件合成一件事的前置条件。
    let info = Info {
        bdf: dev.bdf,
        abar,
        size,
        cap,
        cap2,
        vs,
        pi,
        cap_ports: cap_ports as u8,
        slots: (((cap & CAP_NCS) >> 8) + 1) as u8,
        ports: pi_ones as u8,
        ghc_before,
        ghc_ae,
        ghc_hr,
        ghc_after,
        cmd_fre_written,
        cmd_after_hr,
        sig_after_hr,
        clb_after_hr,
        sam,
        s64a: cap & CAP_S64A != 0,
        reads_ff,
        ring_pa: pa,
    };
    // SAFETY: 见 RingCell
    unsafe { *RING.0.get() = Some(Ring { ctx, mmio, dma, info }) };
    fill(0, 0xEE, RING_PAGES * mm::PAGE)?;
    Ok(info)
}

/// 第 `num` 号端口的接收 FIS 区偏移。**每端口一格**：所有端口共用一格的话，
/// 后起的那个会把前一个的 D2H 盖掉，"这条端口有没有设备"就变成"最后起的那个口有没有"。
fn rx_off(num: u8) -> u64 {
    OFF_RXFIS + RX_BYTES * u64::from(num)
}

/// 引导盘挂在哪个口：**LBA 1 写着 `EFI PART` 的那块盘**，不是记死的端口号。
/// 第一次问要读一次 LBA 1，之后用缓存值 —— 不能拿 `enumerate()` 当常态入口，
/// 它会把每个端口都重起一遍（那是恢复路径，不是查询）。
///
/// 这条路径在启动判定链的最前面，而它的 `Err` 在上面的定义就是"最坏情况"（进安全模式），
/// 所以一次**被丢掉的命令**不能直接变成"读不到"：只在 `Err` 上重试（`transfer` 已经先走过
/// `recover()`，第二次发射落在一个干净的口上），并且每次失败都打出来——静默 `continue`
/// 曾经让一次偶发的首命令丢失变成永久安全模式（BACKLOG ㊿）。读得回来但不是 GPT ⇒ 不重试。
pub fn boot_port() -> Result<u8, AhciError> {
    let cached = BOOT_PORT.load(Ordering::Relaxed);
    if cached != 0 {
        return Ok((cached - 1) as u8);
    }
    let e = enumerate()?;
    for i in 0..e.n_disks {
        let p = e.disks[i];
        for attempt in 1..=3u8 {
            match read_lba(p, 1, 1) {
                Ok(_) => {
                    if data_head(8).map(|h| &h[0..8] == b"EFI PART").unwrap_or(false) {
                        BOOT_PORT.store(u32::from(p) + 1, Ordering::Relaxed);
                        return Ok(p);
                    }
                    break;
                }
                Err(err) => crate::log_warn!(
                    "ahci: 认引导盘 口{} 第{}次读 LBA1 失败 {:?}",
                    p,
                    attempt,
                    err
                ),
            }
        }
    }
    Err(AhciError::NoController)
}

/// 一个端口的取证读数（含它自己那条接收区里的 D2H FIS 类型字节）。
pub fn read_port(num: u8) -> Result<Port, AhciError> {
    let cmd = r32(port_off(num, P_CMD))?;
    Ok(Port {
        num,
        cmd,
        clb: r32(port_off(num, P_CLB))?,
        fb: r32(port_off(num, P_FB))?,
        is: r32(port_off(num, P_IS))?,
        tfd: r32(port_off(num, P_TFD))?,
        sig: r32(port_off(num, P_SIG))?,
        ssts: r32(port_off(num, P_SSTS))?,
        d2h_type: rb(rx_off(num) + RX_D2H)?,
        fr: cmd & P_CMD_FR != 0,
        cr: cmd & P_CMD_CR != 0,
    })
}

/// 起一个端口：停干净 → 装两张基址表 → 开 `FRE`（等 `FR`）→ 按规范顺序清残留中断 →
/// 开 `ST`（等 `CR`）。
///
/// `FR` 跟 `FRE`、`CR` 跟 `ST` 是这一段最硬的位置证据：`P_CMD` 或任一位错，
/// 这里必然在有界窗口内等不到，不可能假绿。
fn start_port(num: u8) -> Result<Port, AhciError> {
    if DEAD_PORT.load(Ordering::Relaxed) == u32::from(num) + 1 {
        // 模拟"重置也修不好"：设备不回话
        return Err(AhciError::CrTimeout(0xFFFF_FFFF));
    }
    let base = port_off(num, P_CMD);
    let ci_reg = port_off(num, P_CI);
    // 排空"上一条还没答完的命令"再停引擎。本机 `PxCI` 只在 `ST` 由 1→0 那一刻被清，
    // 而恢复路径进来时 `ST` 往往已经是 0（楔子就打在清 `ST` 上），那位挂着的命令会在
    // 端口重新拉起时被再跑一遍——实测出现过：恢复后第一条命令请求 8 个扇区，
    // 而 `PRDBC` 只有 512 字节（读到的是旧命令的 DMA 与回执）。
    // 规范给的处置是 `CLO` + COMRESET（错误恢复那一章），本机不理 `CLO`（`PxCMD` 里
    // 没有任何代码读这一位），所以这里把引擎短暂拉起让它答完，再走下面那次真正的
    // 1→0 边沿。排不空就当这次恢复失败：带着一条"不知道属于谁的"命令继续，
    // 下一条命令读到的就可能是它的回执。
    if r32(ci_reg)? != 0 {
        let cmd = r32(base)?;
        w32(base, cmd | CMD_ST)?;
        if !wait_ms(|| r32(ci_reg).map_or(true, |v| v == 0), 200) {
            return Err(AhciError::DrainStuck(r32(ci_reg)?));
        }
    }
    let cmd = r32(base)?;
    w32(base, cmd & !(CMD_ST | CMD_FRE))?;
    if !wait_ms(|| r32(base).map_or(true, |v| v & (P_CMD_CR | P_CMD_FR) == 0), 500) {
        return Err(AhciError::StopTimeout(r32(base)?));
    }
    let pa = ring_bus()?;
    w32(port_off(num, P_CLB), (pa + OFF_CLIST) as u32)?;
    w32(port_off(num, P_FB), (pa + rx_off(num)) as u32)?;
    let mut cmd = r32(base)?;
    cmd |= CMD_FRE;
    w32(base, cmd)?;
    if !wait_ms(|| r32(base).map_or(false, |v| v & P_CMD_FR != 0), 1000) {
        return Err(AhciError::FrTimeout(r32(base)?));
    }
    // 规范 §10.1.2 的清理顺序：先 `PxSERR`、再 `PxIS`、最后全局 `IS` 里这一位。
    // `FRE` 一置起设备就会写一条初始 D2H 并置 `PxIS.DHRS`，留着它会让"完成后读到的
    // 中断状态"变成一锅粥，所以按顺序清掉。
    w32(port_off(num, P_SERR), 0xFFFF_FFFF)?;
    let is = r32(port_off(num, P_IS))?;
    clear_pxis(num, is)?; // W1C：把读到的位原样写回去
    w32(REG_IS, 1 << num)?;
    // M5-g②：这一口的中断使能。**顺序是"先清后开"**：反过来初始 D2H 那一发会在
    // `ST` 还没置起的时候就把旗子立起来，第一条命令就会把上一条的余温当成自己的回执。
    // 认领没成功（`irq` 是 None）就不开：那时候开一位只会攒下没人清的挂起位。
    let claimed = irq_handle().is_some();
    let mut ie_back = 0u32;
    if claimed {
        let off = port_off(num, P_IE);
        let ie = r32(off)?;
        w32(off, ie | 1)?;
        ie_back = r32(off)?;
        crate::log_info!(
            "ahci: 认领 口{} PxIE 写={:#010x} 读回={:#010x} 那一位={} IS残留={:#010x}",
            num, ie | 1, ie_back, (ie_back >> 0) & 1, r32(port_off(num, P_IS))?
        );
    }
    cmd |= CMD_ST;
    w32(base, cmd)?;
    if !wait_ms(|| r32(base).map_or(false, |v| v & P_CMD_CR != 0), 1000) {
        return Err(AhciError::CrTimeout(r32(base)?));
    }
    // 起口的瞬间 `PxCI` 里有没有旧命令还挂着：这条日志是"恢复后第一条命令读到的是
    // 自己的回执还是上一条的回执"的判别仪器（本机的 `PxSACT` 只跟 NCQ，读不出这件事）
    crate::log_info!(
        "ahci: 起口{} CMD={:#010x} CI={:#010x} SACT={:#010x}",
        num,
        r32(base)?,
        r32(port_off(num, P_CI))?,
        r32(port_off(num, P_SACT))?
    );
    read_port(num)
}

/// 起所有实现的端口并取证。不做 COMRESET：QEMU 只要那一口挂着块设备就把
/// `PxSSTS` 报成 det=3、`PxSIG` 报成 `0x101`，不需要真的走一次链路训练。
pub fn enumerate() -> Result<Enum, AhciError> {
    let i = info().ok_or(AhciError::NotClaimed)?;
    let mut ports = [Port {
        num: 0,
        cmd: 0,
        clb: 0,
        fb: 0,
        is: 0,
        tfd: 0,
        sig: 0,
        ssts: 0,
        d2h_type: 0,
        fr: false,
        cr: false,
    }; 32];
    let mut n = 0usize;
    for num in 0..32u8 {
        if i.pi & (1u32 << num) == 0 {
            continue;
        }
        ports[n] = start_port(num)?;
        n += 1;
        // 安全模式（§9.4）：起到"第一块有盘的口"为止，后面的口一个寄存器都不再写。
        // 这就是"仅加载必要驱动"在本机今天真的存在的那种形状 —— 处置只到这里，
        // 隔离名单要等驱动加载器（见 `boot_guard` 模块头）
        if !crate::boot_guard::optional_devices_allowed()
            && ports[..n].iter().any(|p| p.is_sata_disk())
        {
            break;
        }
    }
    let mut disks = [0u8; 32];
    let mut n_disks = 0usize;
    for p in ports[..n].iter().filter(|p| p.is_sata_disk()) {
        if n_disks < disks.len() {
            disks[n_disks] = p.num;
            n_disks += 1;
        }
    }
    let disk = if n_disks > 0 { Some(disks[0]) } else { None };
    Ok(Enum { ports, n, disk, disks, n_disks })
}

/// FNV-1a 64 位。`tools/aurora.py` 里有一份逐字一样的实现——两台仪器算同一个数。
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// 逐字节推一步。数据缓冲那条路只能一问一答（缓冲区不交出切片），它必须与
/// `fnv1a64` 是同一个式子，否则哈希对账就变成了两台仪器各算各的。
pub const fn fnv1a_step(h: u64, b: u8) -> u64 {
    (h ^ b as u64).wrapping_mul(FNV_PRIME)
}

pub fn fnv1a64(buf: &[u8]) -> u64 {
    let mut h: u64 = FNV_OFFSET;
    for b in buf {
        h = fnv1a_step(h, *b);
    }
    h
}

/// 读 `count` 个扇区到数据缓冲，返回取证读数与内容哈希（轮询完成，不认领中断）。
///
/// H2D FIS（类型 `0x27`）的字段位置（规范 §4.2.3.2 的图，Linux `ata_tf_to_fis` 与 QEMU
/// `ahci_init_move_sglist` 三方一致）：命令在字节 2；LBA 在 4/5/6/7(低 4 位)/8/9/10 = 位
/// 7:0/15:8/23:16/27:24/31:24/39:32/47:40；扇区数在字节 12（低）与 13（高）；字节 14 与
/// 16..19 必须写 0。**字节 1 必须正好是 `0x80`**：低 4 位是端口号（直连设备必须 0）、
/// bits 6:4 保留、bit 7 才是"这是一条命令"——QEMU 对前两种情况**静默丢掉命令**
/// （`PxCI` 永远不落），所以这一格不是"写什么都行"。
/// 本机这条盘只有 131072 个扇区、一次只读 1 个 ⇒ 字节 8/9/10/13 恒为 0，
/// **没有任何判据走到它们**（要读 >255 扇区或高偏移之前先按 ADR-029 那条实验钉住）。
pub fn read_lba(num: u8, lba: u64, count: u16) -> Result<Xfer, AhciError> {
    transfer(num, lba, count, false)
}

/// 把 `count` 个扇区从数据缓冲写到磁盘。**图案与 LBA 绑定**（`pattern_byte`），
/// 所以"什么都没写"、"写到别的偏移去了"、"只写了第一个扇区"三种错法都过不了对读。
/// 返回的是完成取证；真正的判据在调用方：写完之后**再用一条读命令**回读比对，
/// 并由 `tools/aurora.py` 在 QEMU 退出后用 `qemu-io` 读那个偏移当第二台仪器。
pub fn write_lba(num: u8, lba: u64, count: u16) -> Result<Xfer, AhciError> {
    let bytes = u32::try_from(count).ok().filter(|c| *c != 0).map(|c| c as u64 * SECTOR);
    let bytes = match bytes {
        Some(b) if b <= DATA_BYTES => b as u32,
        _ => return Err(AhciError::TooBig(count)),
    };
    // 先把图案填进数据缓冲：这里**不填哨兵**（填了就把要写的内容覆盖了）
    for i in 0..bytes as u64 {
        wb(OFF_DATA + i, pattern_byte(lba, i))?;
    }
    transfer(num, lba, count, true)
}

/// 与 LBA 绑定的图案字节。刻意选成**一行就能在 Python 里逐字重写**的形状：
/// 宿主机那边用同一个式子算出该出现在盘上的内容，两台仪器才对得上。
pub const fn pattern_byte(lba: u64, i: u64) -> u8 {
    (((i as u8).wrapping_mul(7)).wrapping_add(lba as u8)) ^ 0x3C
}

/// 把一段**任意字节**写到盘上：状态区、崩溃记录走这条，而不是 `write_lba` 那个测试图案。
/// `src.len()` 必须是整扇区且不为 0 —— 半个扇区的写要读-改-写，那是块层的事，
/// 藏在接口里会让调用方以为自己只写了这 40 字节（其实动了整个扇区）。
pub fn write_bytes(num: u8, lba: u64, src: &[u8]) -> Result<Xfer, AhciError> {
    let count = match src.len() {
        0 => return Err(AhciError::TooBig(0)),
        n if n as u64 % SECTOR != 0 => return Err(AhciError::Denied("长度不是整扇区")),
        n => n as u64 / SECTOR,
    };
    let count = u16::try_from(count).map_err(|_| AhciError::TooBig(u16::MAX))?;
    if count > MAX_SECTORS {
        return Err(AhciError::TooBig(count));
    }
    for (i, b) in src.iter().enumerate() {
        wb(OFF_DATA + i as u64, *b)?;
    }
    transfer(num, lba, count, true)
}

/// 从盘上读一段任意字节进调用方的缓冲（内容判据用 `Xfer.hash`，逐字节比对用 `dst`）。
pub fn read_bytes(num: u8, lba: u64, dst: &mut [u8]) -> Result<Xfer, AhciError> {
    let count = match dst.len() {
        0 => return Err(AhciError::TooBig(0)),
        n if n as u64 % SECTOR != 0 => return Err(AhciError::Denied("长度不是整扇区")),
        n => n as u64 / SECTOR,
    };
    let count = u16::try_from(count).map_err(|_| AhciError::TooBig(u16::MAX))?;
    if count > MAX_SECTORS {
        return Err(AhciError::TooBig(count));
    }
    let x = transfer(num, lba, count, false)?;
    copy_out(0, dst)?;
    Ok(x)
}

/// 读与写共用的骨架：填 FIS、PRDT、表头，发射，等落定，取证。
/// 收成一个函数而不是复制一份，是因为"写"最容易出的错就是复制时把完成判据改掉一格
/// （§12.4.1 规则 3 与 BACKLOG ⑧ 同一课：两条路径上有一条永远不红的判据）。
fn transfer(num: u8, lba: u64, count: u16, write: bool) -> Result<Xfer, AhciError> {
    let mut r = transfer_inner(num, lba, count, write);
    // 发射被吞（写 `PxCI`=1 读回 0）时，这条命令**设备根本没收到**——不是"可能已经落盘的写
    // 失败了"，所以恢复之后重发一次是安全的。实测本机偶发就打在"刚起完口的第一条命令"上
    // （`IssueStuck(0)`），而它的下游是启动判定链："读不到" ⇒ 按最坏情况进安全模式。
    // 只重发一次：第二次还被吞就是真的有问题，必须把 Err 交出去而不是无限重试。
    if matches!(r, Err(AhciError::IssueStuck(_))) {
        crate::log_warn!("ahci: 发射被吞 口{}（读回 0）⇒ 恢复后重发一次", num);
        recover_for_issue(num);
        r = transfer_inner(num, lba, count, write);
    }
    // 错误分三类处置：卡住 ⇒ 走 §8.2 的 `Resetting`；干净错误（设备正常完成但带 ERR/ABRT）
    // ⇒ 只计数；其余（参数、隔离、未认领）⇒ 什么都没发生。
    // 不分类就会出现"设备回一个 ABRT，驱动就把控制器抖一遍"的过度反应。
    match &r {
        Err(e) if wedges(e) => {
            recover(num);
        }
        Err(AhciError::BadCompletion { .. }) => {
            CLEAN_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
    r
}

fn transfer_inner(num: u8, lba: u64, count: u16, write: bool) -> Result<Xfer, AhciError> {
    if count == 0 || count > MAX_SECTORS {
        return Err(AhciError::TooBig(count));
    }
    // 隔离之后一个寄存器都不再碰：这条判据靠"`resets` 计数不再增长"来验，
    // 不是靠"返回了 Err"——返回 Err 也可能是真的又试了一次
    if state_of(num) == State::Quarantined {
        return Err(AhciError::Quarantined);
    }
    // 注入的是"计数被少编程"：命令里写 1 个扇区，而缓冲与回读都按 `count` 个准备。
    // PRD 长度跟着命令走，所以这注入的是**驱动自己的不一致**，不是设备行为。
    let programmed = if INJECT_SHORT_WRITE && write { 1 } else { count };
    let bytes = u32::from(count) * u32::try_from(SECTOR).expect("512 落在 u32 里");
    let prd_bytes = u32::from(programmed) * SECTOR as u32;
    let pa = ring_bus()?;
    if !write {
        // 读方向先填哨兵（"没搬"与"搬回一堆 0"要分得开）；写方向的缓冲已经是待写内容
        fill(OFF_DATA, 0xEE, bytes as usize)?;
    }

    // 1. 命令表：CFIS 在 +0x00（§4.2.3 图 13）；QEMU 硬编码 PRDT 在 +0x80 并且不理 CFL
    let f = OFF_CTBL + CTBL_CFIS;
    fill(f, 0, 64)?;
    wb(f, FIS_TYPE_H2D)?;
    wb(f + 1, 0x80)?; // C=1、端口 0、保留位 0
    let op = OP_OVERRIDE.load(Ordering::Relaxed);
    wb(f + 2, if op != 0 { op as u8 } else if write { ATA_WRITE_DMA_EXT } else { ATA_READ_DMA_EXT })?;
    wb(f + 4, (lba & 0xFF) as u8)?;
    wb(f + 5, ((lba >> 8) & 0xFF) as u8)?;
    wb(f + 6, ((lba >> 16) & 0xFF) as u8)?;
    wb(f + 7, 0xE0 | ((lba >> 24) & 0x0F) as u8)?; // bits 3:0 = LBA 27:24，bit 6 = LBA 模式
    // LBA 31:24。第一版我按 `>>32` 写这一格（整段地址搬错一格），而这条 64 MiB 的盘
    // 让字节 8/9/10 恒为 0 ⇒ 没有任何判据读得出来。`fault-ahci-highlba` 就是把这个错误
    // 重新装回去，好让 M5-c② 那条高 LBA 判据自证它真的在量这件事。
    let lba_hi_shift = if INJECT_HIGH_LBA { 32 } else { 24 };
    wb(f + 8, ((lba >> lba_hi_shift) & 0xFF) as u8)?;
    wb(f + 9, ((lba >> 32) & 0xFF) as u8)?; // LBA 39:32
    wb(f + 10, ((lba >> 40) & 0xFF) as u8)?; // LBA 47:40
    wb(f + 12, (programmed & 0xFF) as u8)?; // 扇区数低字节（Linux `ata_tf_to_fis` 的 `fis[12]=tf->nsect`）
    // 扇区数高字节。负样本 `fault-ahci-count-hi` 把它挪到**字节 11**（Features Exp，设备不看那格）。
    // 我原先照源码注释推测"QEMU 判 `bytes > count*512` 成立会 `-1` 丢掉命令 ⇒ `PxCI` 不落"，
    // 实测**不是**：它搬完 `count` 个扇区就清 `PxCI`、状态报 `0x50` 完成任务——
    // 少搬 131072 字节而每一格回执都好看。所以这一格的判据不能是"命令有没有完成"，
    // 只能是**内容的覆盖范围**：长读的最后一个扇区必须与单独读那一扇区逐字节相同
    // （`main.rs` 的同长度对读）。**必须挑字节 11 而不是 8**：字节 8 是 LBA 31:24，
    // 写到那里会把"计数放错"和"地址越界"混成一件，红了也说不清是哪一条。
    let count_hi = if cfg!(feature = "fault-ahci-count-hi") { 11 } else { 13 };
    wb(f + count_hi, (count >> 8) as u8)?;
    wb(f + 15, 0)?; // 设备控制：C=1 的命令里这一格必须 0

    // 2. PRDT 第 0 条：缓冲区物理地址 + 字节数。规范与 QEMU 都按"字段值 = 字节数 − 1"算，
    //    所以 512 字节写 511；写 512 会多搬一字节，而哈希对账当场能翻出来。
    //    bit 31 的"I"（完成即发中断）不置：本驱动不认领中断，Linux 也不置它。
    let p = OFF_CTBL + CTBL_PRDT;
    wl(p, (pa + OFF_DATA) as u32)?;
    wl(p + 4, 0)?;
    wl(p + 8, 0)?; // 保留 dword：规范说必须写 0
    wl(p + 12, prd_bytes - 1)?;

    // 3. 命令表头第 0 槽：CFL = 5、1 条 PRDT、方向是读（W=0）、不是 ATAPI
    // DW0：1 条 PRDT、CFL = 5、方向位 W = bit6（写必须置起来）
    let w_bit = if INJECT_DROP_W { 0 } else if write { HDW_W } else { 0 };
    wl(OFF_CLIST + HDW0, (1 << 16) | CFL_H2D | w_bit)?;
    wl(OFF_CLIST + HDW1, 0)?;
    wl(OFF_CLIST + HDW2, (pa + OFF_CTBL) as u32)?;
    wl(OFF_CLIST + HDW3, 0)?;

    // 4. 发射：PxCI 写 1 = 跑第 0 槽，硬件完成后自己清这一格
    // 发射前先把本端口接收区那条 D2H 的类型字节盖成"设备永远不会写"的值，
    // 之后"这条命令有没有新回执"就读得出来（不是"上一条的余温"）。
    let d2h = rx_off(num) + RX_D2H;
    wb(d2h, 0)?;
    let ci = port_off(num, P_CI);
    w32(ci, 1)?;
    let issued = r32(ci)?;
    if issued & 1 == 0 {
        return Err(AhciError::IssueStuck(issued));
    }
    // 落定有两种形状（M5-g② 起还有第三种来源，见 `wait_settled`）：`PxCI` 落下（规范那条），
    // 或接收区出现一条 `ERR` 置起、`BSY`/`DRQ` 已清的新 D2H。第二种是必需的：本机在命令带错时
    // **不释放 `PxCI`**（QEMU `ahci_clear_cmd_issue` 只在 `!ERR && !BSY && !DRQ` 时清这一格），
    // 只看 `PxCI` 会把"设备报了个错"读成"设备卡死"，于是每条错误命令都抖一次控制器。
    // 真实硬件按规范在错误完成时也清 `PxCI`，那这条支路只是不会走到。
    // M5-g②：`wait_settled` 的落定条件里已经含 BSY/DRQ 清这一项（旗子只负责叫醒，不负责放行），
    // 下面这一次是同一条件的**第二台仪器**：它今天几乎必然立刻通过，留着是因为
    // "谁放行数据拷贝"这件事不该只有一处判断。
    let tfd_off = port_off(num, P_TFD);
    let settled = wait_settled(ci, d2h, tfd_off);
    if !settled {
        return Err(AhciError::CmdTimeout);
    }
    // `PxCI` 落下去不等于传输已结束：QEMU 在把命令交给 IDE 核心时就清了这一格，
    // 而 DMA 还在走。规范给的判据是 ATA 状态里的 BSY/DRQ 落定，所以这里再等有界的一轮，
    // 之后读到的 `PRDBC` 才是"搬完了的字节数"而不是"此刻为止的"。
    if !wait_ms(|| r32(tfd_off).map_or(true, |v| (v as u8) & (ATA_STATUS_BUSY | ATA_STATUS_DRQ) == 0), 1000) {
        let t = r32(tfd_off)?;
        return Err(AhciError::BadCompletion { status: (t & 0xFF) as u8, error: ((t >> 8) & 0xFF) as u8, dw1: 0, want: bytes });
    }

    // 5. 事后取证：状态用端口侧 `PxTFD`（RO，§3.3.8），字节数用表头 DW1 的 PRDBC，
    //    另外把接收区那条 D2H 的状态字节读回来当第二台仪器
    let tfd = r32(port_off(num, P_TFD))?;
    let (status, error) = ((tfd & 0xFF) as u8, ((tfd >> 8) & 0xFF) as u8);
    // 表头 DW1：规范说 bits 31:16 是 PRDBC（设备自报已搬字节数）。本机 QEMU 把同一个数
    // 报在**低位**：1 个扇区 → `0x200`、8 个扇区的写 → `0x1000`、257 个扇区的读 → `0x20200`
    // （我先前在这里写过"QEMU 不累计这一格"，那是对着一次 `0` 读数下的错结论）。
    // 位置都不对，就更不能拿它当判据：整格原样打印，"搬够了没有"判在内容与对读上。
    let dw1 = rl(OFF_CLIST + HDW1)?;
    let mut cfis8 = [0u8; 8];
    for k in 0..8u64 {
        cfis8[k as usize] = rb(f + k)?;
    }
    let d2h_type = rb(d2h)?;
    let mut rx8 = [0u8; 8];
    for k in 0..8u64 {
        rx8[k as usize] = rb(d2h + k)?;
    }
    // 命令里编程的扇区数（表内 FIS 字节 12/13）、设备回执里的扇区数（D2H 字节 12/13）、
    // 以及 PRDT 第 0 条的字节数（读回来，不凭我写进去的那个数）。
    // 这几个数不一致就说明"这条回执不是刚才那条命令的"或"设备只按 PRD 搬"。
    let want_lo = rb(f + 12)?;
    let want_hi = rb(f + 13)?;
    let echo_lo = rb(d2h + 12)?;
    let echo_hi = rb(d2h + 13)?;
    let prd_dw3 = rl(p + 12)?;
    let rx_lo = u64::from_le_bytes(rx8);
    let d2h_status = rb(d2h + 2)?;
    // ATA 的设备分类只看 `lbam`/`lbah` 两格（Linux 与 QEMU 都这么判），低位恒为 0x0101
    let sig_d2h = (u32::from(rb(d2h + 5)?) << 8 | u32::from(rb(d2h + 6)?)) << 8 | 0x0101;
    // 哈希与哨兵计数走同一趟逐字节 volatile 读：数据缓冲不交出切片（§8.3 那条），
    // 所以"内容是什么"只能一问一问答。代价记在这里：长读那一次要问 131 584 个字节，
    // 具体多少周期由 `bench` 的 P4 那一行读，不在注释里预设。
    let (dctx, dh) = dma_ref()?;
    let mut hash: u64 = FNV_OFFSET;
    let mut untouched = 0u32;
    for i in 0..bytes as usize {
        let b = dctx.dma_read8(dh, OFF_DATA as usize + i).map_err(AhciError::Ctx)?;
        hash = fnv1a_step(hash, b);
        untouched += (b == 0xEE) as u32;
    }
    crate::log_info!(
        "ahci: 取证 口{} tfd={:#06x} 表头DW1={:#010x} ci落定={:#010x} 中断态={:#010x} 哨兵剩={} 表内FIS={:#018x} 接收区FIS={:#018x} 哈希={:#018x} 编程计数={} 回执计数={} PRDT字节={}",
        num,
        tfd,
        dw1,
        r32(ci)?,
        r32(port_off(num, P_IS))?,
        untouched,
        u64::from_le_bytes(cfis8),
        rx_lo,
        hash,
        u16::from(want_lo) | (u16::from(want_hi) << 8),
        u16::from(echo_lo) | (u16::from(echo_hi) << 8),
        (prd_dw3 & 0x001F_FFFF) + 1
    );
    // 两台仪器不一致 = 有一台根本没在动
    if status != d2h_status || d2h_type != FIS_TYPE_D2H {
        return Err(AhciError::BadCompletion { status: d2h_status, error, dw1, want: bytes });
    }
    if status & (ATA_STATUS_ERR | ATA_STATUS_BUSY) != 0 {
        return Err(AhciError::BadCompletion { status, error, dw1, want: bytes });
    }
    // `untouched` **不判**：保护 MBR 的第 4 字节（分区类型）本来就是 `0xEE`，
    // 拿哨兵当"搬够了吗"的判据会把一次成功的读判成失败（实测：哈希与宿主机逐位相同，
    // 而 `untouched = 1`）。它只在日志里当辅助取证，真判据是内容本身。
    Ok(Xfer {
        port: num,
        want: bytes,
        dw1,
        status,
        sig_port: r32(port_off(num, P_SIG))?,
        sig_d2h,
        d2h_type,
        untouched,
        hash,
    })
}

/// 数据缓冲的开头若干字节（用例据此打印可辨认的 ASCII 见证）。
pub fn data_head(n: usize) -> Result<[u8; 16], AhciError> {
    let mut out = [0u8; 16];
    for k in 0..n.min(16) {
        out[k] = rb(OFF_DATA + k as u64)?;
    }
    Ok(out)
}

/// 数据缓冲第一个扇区的末尾两字节：MBR 的签名 `0x55AA` 就在这一格
pub fn mbr_tail() -> Result<[u8; 2], AhciError> {
    Ok([rb(OFF_DATA + SECTOR - 2)?, rb(OFF_DATA + SECTOR - 1)?])
}

/// 全局寄存器入口：用例拿它把"认领时记下的 `GHC`/`PI`"与"现在再读一次"对账。
/// 这是**时间**上的两次读数，不是两台仪器（路径同一条），别把它当成独立证据。
pub fn global(off: usize) -> Option<u32> {
    r32(off).ok()
}

/// 数据缓冲里指定偏移那一字节：位置敏感的见证要用绝对偏移，不能用"前 16 个字节"凑
pub fn data_at(at: usize) -> Result<u8, AhciError> {
    if at >= mm::PAGE {
        return Err(AhciError::TooBig(u16::MAX));
    }
    rb(OFF_DATA + at as u64)
}

/// 把数据缓冲的 `[at, at+out.len())` 抄出来。用例用它做**同长度对读**：
/// 一次长读的最后一个扇区，必须与单独读那一个扇区的结果逐字节相同——
/// 这条不需要任何阈值或"内容应当是什么"的先验，也不依赖宿主机。
pub fn copy_out(at: u64, out: &mut [u8]) -> Result<(), AhciError> {
    // `at` 与 `data_at`/`data_head` 同一套坐标：**从数据缓冲起算**。
    // 第一版这里漏了 `OFF_DATA`，于是"长读尾巴 vs 单独读那一扇区"变成"长读尾巴 vs 命令列表"，
    // 一个恒不成立的比较看起来像判据（实测：`尾扇区一致=false` 而两次哈希都是对的）
    if at + out.len() as u64 > DATA_BYTES {
        return Err(AhciError::TooBig(u16::MAX));
    }
    let (ctx, h) = dma_ref()?;
    // 句柄那一侧的偏移是**从环形结构基址起算**的，而这里的 `at` 从数据缓冲起算，
    // 所以必须加上 `OFF_DATA`——第一次改这里漏掉它，`尾扇区一致` 当场变红
    ctx.dma_copy_out(h, idx(OFF_DATA + at), out).map_err(AhciError::Ctx)
}

/// 负样本用：把 LBA 的字节 8 按 `>>32` 写（= 我第一版的真错误）。
/// `fault-ahci-highlba` 构建里为真，正常构建里恒为假。
pub const INJECT_HIGH_LBA: bool = cfg!(feature = "fault-ahci-highlba");
/// 负样本：写命令忘记置 DW0 的 W 位（真驱动最常犯的方向错）。
/// 这台 QEMU 会不会因此少写/不写，正是本轮要量出来的事实，不靠推测写进结论。
pub const INJECT_DROP_W: bool = cfg!(feature = "fault-ahci-write-dir");
/// 负样本：写命令里把扇区数按 1 个编程（内容却按 `count` 个准备）——
/// 就是"只搬了第一个扇区"这一类真错。8 个扇区的回读会当场露出来。
pub const INJECT_SHORT_WRITE: bool = cfg!(feature = "fault-ahci-write-partial");

/// 数据缓冲前 `n` 字节里**不等于** `pat` 的个数。0 就是"整段都等于这个图案"。
/// 为什么判"不等于的个数"而不是"内容对不对"：第二块盘的图案是宿主机按配方写的，
/// 于是"读回来的内容 == 配方"是两台仪器对账，而不是驱动自己说它对。
pub fn data_diff_count(pat: u8, n: usize) -> Result<usize, AhciError> {
    let mut bad = 0usize;
    for k in 0..n {
        if rb(OFF_DATA + k as u64)? != pat {
            bad += 1;
        }
    }
    Ok(bad)
}
