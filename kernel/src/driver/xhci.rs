//! xHCI 寄存器层与 TRB 环（ADR-208）。
//!
//! ## 为什么只做字节层
//!
//! USB 与前面几片都不同：它有真正的**硬件状态机**（xHCI 控制器），判据要证的东西
//! 大多必须有真实设备（或 QEMU 的 xHCI 模拟）才有意义。
//!
//! 所以这一片只做**能被纯函数判据完整证伪**的部分：
//!
//! | 做 | 不做 |
//! |---|---|
//! | TRB 的构造 / 解析 | 控制器的实际初始化 |
//! | 环的游标（生产者/消费者索引）| 端口枚举 |
//! | 寄存器偏移常量 | 设备类驱动（HID/大容量存储）|
//!
//! 这与 TCP 分层（ADR-197 先做段格式）是同一个思路：**先让字节层可证，再接硬件**。
//!
//! ## 一条硬约束
//!
//! TRB 是**设备读写的 DMA 内存**。按 `driver/mod.rs` 的纪律，不把它当
//! `&[u8]` 切片直接读写 —— 这里只构造/解析**自己的字节缓冲**，
//! 真正放进 DMA 环时走 `DmaHandle` 的 volatile 访问器。

/// TRB 大小（xHCI spec §4.11）：16 字节 = 4 个 32 位 DWORD。
pub const TRB_BYTES: usize = 16;

/// 一个 TRB 环的最大项数。
///
/// **为什么是 256**：每个 TRB 16 字节 ⇒ 256 × 16 = 4096 字节 = **正好一页**。
/// 一页对齐的环是 xHCI 的要求（TR Dequeue Pointer 低 4 位必须是 0），
/// 而 256 项给到足够深的命令/传输队列。
///
/// 这是**推导值**，不是接缝尺：`TRB_BYTES × N == PAGE` 且 N 是 2 的幂。
pub const TRB_RING_SIZE: usize = 4096 / TRB_BYTES;

/// TRB 类型（xHCI spec §4.11 的 `TRB Type` 字段，bit 15:10）。
///
/// 只列这一片需要的几种；完整类型表在要用时再补（避免造没有调用者的枚举）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrbType {
    /// Normal TRB：传输一段数据。
    Normal = 1,
    /// Setup Stage TRB：控制传输的建立阶段。
    SetupStage = 2,
    /// Data Stage TRB：控制传输的数据阶段。
    DataStage = 3,
    /// Status Stage TRB：控制传输的状态阶段。
    StatusStage = 4,
    /// Link TRB：把环首尾相接（**每个环必须有一个**）。
    Link = 6,
    /// Enable Slot Command。
    EnableSlot = 9,
    /// Address Device Command。
    AddressDevice = 11,
    /// Configure Endpoint Command。
    ConfigureEndpoint = 12,
    /// Transfer Event TRB：传输完成事件。
    TransferEvent = 32,
    /// Command Completion Event TRB。
    CommandCompletionEvent = 33,
}

impl TrbType {
    /// 从原始 TRB 的第 3 个 DWORD 里取出类型（bit 15:10）。
    pub fn from_raw(raw: u32) -> Option<Self> {
        let t = (raw >> 10) & 0x3F;
        match t {
            1 => Some(Self::Normal),
            2 => Some(Self::SetupStage),
            3 => Some(Self::DataStage),
            4 => Some(Self::StatusStage),
            6 => Some(Self::Link),
            9 => Some(Self::EnableSlot),
            11 => Some(Self::AddressDevice),
            12 => Some(Self::ConfigureEndpoint),
            32 => Some(Self::TransferEvent),
            33 => Some(Self::CommandCompletionEvent),
            _ => None,
        }
    }
}

/// 一个 TRB 的解析视图。
///
/// 借用输入缓冲，不复制 —— 与 TCP 的 `Segment` 同一个形状。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trb<'a> {
    pub parameter: u64,
    pub status: u32,
    pub control: u32,
    pub ty: TrbType,
    /// Cycle bit（bit 0 of control）—— **环的所有权标志**，见 `Ring`。
    pub cycle: bool,
    raw: &'a [u8; TRB_BYTES],
}

impl<'a> Trb<'a> {
    pub fn raw(&self) -> &'a [u8; TRB_BYTES] {
        self.raw
    }
    /// Completion Code（Transfer Event / Command Completion 的 bit 31:24 of status）。
    pub fn completion_code(&self) -> u8 {
        ((self.status >> 24) & 0xFF) as u8
    }
    /// TRB Transfer Length（bit 16:0 of status）。
    pub fn transfer_len(&self) -> u32 {
        self.status & 0x1_FFFF
    }
}

/// 解析一个 16 字节的 TRB。类型不认识就回 `None`（**不猜**）。
pub fn parse_trb(buf: &[u8; TRB_BYTES]) -> Option<Trb<'_>> {
    let parameter = u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    let status = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let control = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    Some(Trb {
        parameter,
        status,
        control,
        ty: TrbType::from_raw(control)?,
        cycle: control & 1 != 0,
        raw: buf,
    })
}

/// 构造一个 TRB 到 `out`。返回写入是否成功。
///
/// `cycle` 由调用方给 —— 它是**环的状态**，不是 TRB 自身能推导的东西。
pub fn build_trb(
    out: &mut [u8; TRB_BYTES],
    ty: TrbType,
    parameter: u64,
    status: u32,
    cycle: bool,
) -> bool {
    out[0..8].copy_from_slice(&parameter.to_le_bytes());
    out[8..12].copy_from_slice(&status.to_le_bytes());
    let control = ((ty as u32) << 10) | if cycle { 1 } else { 0 };
    out[12..16].copy_from_slice(&control.to_le_bytes());
    true
}

/// TRB 环的游标（ADR-208）。
///
/// ## 为什么是「纯游标」而不是「环本身」
///
/// 真正的环住在 DMA 内存里（`DmaHandle`），这里只管**索引与 cycle 位** ——
/// 那才是软件拥有、能被判据完整验证的部分。DMA 字节的读写走 volatile 访问器。
///
/// ## xHCI 的 cycle 规则（spec §4.9）
///
/// 生产者把 TRB 的 Cycle bit 写成当前的 `producer_cycle`，写完把 Enqueue 指针前移；
/// 消费者看到 Cycle bit 与自己的 `consumer_cycle` 相同才认为「有新项」。
/// **环绕回时（经过 Link TRB）cycle 位翻转** —— 这是 xHCI 最容易写错的地方之一。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingCursor {
    /// 下一个写入位置（0..TRB_RING_SIZE）。
    pub enqueue: usize,
    /// 下一个读取位置（0..TRB_RING_SIZE）。
    pub dequeue: usize,
    /// 生产者当前 cycle 位。
    pub producer_cycle: bool,
    /// 消费者当前 cycle 位。
    pub consumer_cycle: bool,
}

impl RingCursor {
    pub const fn new() -> Self {
        Self {
            enqueue: 0,
            dequeue: 0,
            producer_cycle: true,
            consumer_cycle: true,
        }
    }

    /// 空闲格数（生产者追上消费者之前还能写几条）。
    pub fn free(&self) -> usize {
        // **可写格数不含 Link TRB 那一格**：环共 SIZE 格，最后一格固定是 Link，
        // 所以最多只能装 SIZE-2 条 TRB（还要留一格区分满/空）。
        let capacity = TRB_RING_SIZE - 2;
        let used = if self.enqueue >= self.dequeue {
            self.enqueue - self.dequeue
        } else {
            TRB_RING_SIZE - self.dequeue + self.enqueue
        };
        capacity - used
    }

    /// 已用格数。
    pub fn used(&self) -> usize {
        TRB_RING_SIZE - 2 - self.free()
    }

    /// **生产者前移一格**。绕回时翻转 `producer_cycle`。
    ///
    /// 返回写在那个位置的 cycle 位（调用方据此填 TRB 的 bit 0）。
    pub fn advance_enqueue(&mut self) -> Option<bool> {
        // **先绕回、再判满**（ADR-208 实测）：
        // 当 Enqueue 停在 Link 前一格（SIZE-2）且环满时，下一次写入
        // 不是「拒绝」，而是「写到 Link 位置 → 硬件绕回 0 → cycle 翻转」。
        // 若先判 `free()==0` 就返回，游标会永远卡在 SIZE-2，cycle 永不翻转。
        if self.enqueue == TRB_RING_SIZE - 2 && self.free() == 0 {
            let cycle = self.producer_cycle;
            self.enqueue = 0;
            self.producer_cycle = !self.producer_cycle;
            return Some(cycle);
        }
        if self.free() == 0 {
            return None; // 满（且不在 Link 前一格）
        }
        let cycle = self.producer_cycle;
        self.enqueue += 1;
        // **绕回阈值是 `SIZE-1` 而不是 `SIZE`**（ADR-208 实测）：
        // Link TRB 固定在最后一格（index SIZE-1），软件写到 SIZE-2 后，
        // 下一次 Enqueue 指向 Link，硬件遇到 Link 才绕回 0 并翻 cycle。
        // 若用 SIZE 当阈值，游标会停在 255（满环）而永远不绕回 ——
        // 实测 `enqueue=255 pc=true flips=0`。
        if self.enqueue == TRB_RING_SIZE - 1 {
            self.enqueue = 0;
            self.producer_cycle = !self.producer_cycle;
        }
        Some(cycle)
    }

    /// **消费者前移一格**。绕回时翻转 `consumer_cycle`。
    /// 返回是否真的有可消费项。
    pub fn advance_dequeue(&mut self) -> bool {
        if self.used() == 0 {
            return false;
        }
        self.dequeue += 1;
        if self.dequeue == TRB_RING_SIZE - 1 {
            self.dequeue = 0;
            self.consumer_cycle = !self.consumer_cycle;
        }
        true
    }
}

/// xHCI 能力寄存器偏移（spec §5.3）。
/// 只列初始化路径会读的，避免造没有调用者的常量表。
// **偏移必须逐个核对**（ADR-210 实测撞过）：
//
// 第一版把 HCCPARAMS1 写在 0x08、DBOFF 写在 0x0C —— 那是错的。
// xHCI spec §5.3 的实际布局是：
//
//   0x00 CAPLENGTH(1B) + RSVD(1B) + HCIVERSION(2B)
//   0x04 HCSPARAMS1
//   0x08 HCSPARAMS2   <- 我原来当成了 HCCPARAMS1
//   0x0C HCSPARAMS3   <- 我原来当成了 DBOFF
//   0x10 HCCPARAMS1
//   0x14 DBOFF
//   0x18 RTSOFF
//   0x1C HCCPARAMS2
//
// 实测症状：`db=0x00000000`（读到 HCSPARAMS3=0）⇒ `BadCap`。
// 而 `hccp=0x0000000f` 其实是 HCSPARAMS2（Max Scratchpad 位）。
pub const CAP_CAPLENGTH: usize = 0x00;
pub const CAP_HCSPARAMS1: usize = 0x04;
pub const CAP_HCSPARAMS2: usize = 0x08;
pub const CAP_HCSPARAMS3: usize = 0x0C;
pub const CAP_HCCPARAMS1: usize = 0x10;
pub const CAP_DOORBELL_OFFSET: usize = 0x14;
pub const CAP_RTSOFF: usize = 0x18;
pub const CAP_HCCPARAMS2: usize = 0x1C;

/// 运行寄存器偏移（spec §5.4）。
pub const OP_USBCMD: usize = 0x00;
pub const OP_USBSTS: usize = 0x04;
pub const OP_FRINDEX: usize = 0x0C;
pub const OP_CRCR: usize = 0x18;
pub const OP_DCBAAP: usize = 0x30;
pub const OP_CONFIG: usize = 0x38;

// ---------------------------------------------------------------- ADR-209：xHCI 能力解码与初始化序列

/// **能力寄存器快照**（ADR-209）。
///
/// 只含初始化真正要读的四个寄存器。判据可以喂任意快照（包括损坏的），
/// 而不需要真的 xHCI 设备 —— 这是这一层能被纯函数证伪的关键。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapSnapshot {
    pub cap_length: u8,
    pub hcsparams1: u32,
    pub hccparams1: u32,
    pub doorbell_offset: u32,
}

impl CapSnapshot {
    /// MaxSlotsEn（HCSPARAMS1 bit 7:0）。**0 表示这个控制器不支持任何槽**，
    /// 初始化必须拒绝而不是继续。
    pub fn max_slots(&self) -> u8 {
        (self.hcsparams1 & 0xFF) as u8
    }

    /// MaxIntrs（bit 18:8）。
    pub fn max_intrs(&self) -> u16 {
        ((self.hcsparams1 >> 8) & 0x7FF) as u16
    }

    /// MaxPorts（bit 31:24）。
    pub fn max_ports(&self) -> u8 {
        ((self.hcsparams1 >> 24) & 0xFF) as u8
    }

    /// AC64（HCCPARAMS1 bit 0）：1 = 支持 64 位寻址，0 = 只有 32 位。
    pub fn ac64(&self) -> bool {
        self.hccparams1 & 1 != 0
    }

    /// CSZ（bit 3）：1 = 控制端点用 64 字节 TRB，0 = 32 字节。
    pub fn csz(&self) -> bool {
        self.hccparams1 >> 3 & 1 != 0
    }

    /// Max Scratchpad Buffers（bit 12:7）。**acyclic 的数目**，
    /// 决定要分配几张 Scratchpad Buffer Array 表项。
    pub fn max_scratchpad(&self) -> u16 {
        ((self.hccparams1 >> 7) & 0x1F) as u16
    }

    /// 运行寄存器的基址偏移 = CAPLength（spec §5.3）。
    ///
    /// **必须是 32 的倍数**（spec 要求 CAPLength 是 4 的倍数且最小 0x20）。
    pub fn op_offset(&self) -> Option<usize> {
        let n = self.cap_length as usize;
        if n < 0x20 || n % 4 != 0 {
            return None;
        }
        Some(n)
    }

    /// Doorbell 数组基址偏移（spec §5.3）。
    ///
    /// **必须落在 CAP 区域内**（`doorbell_offset >= cap_length`），
    /// 而且不能是 0（0 表示这个寄存器不存在）。
    pub fn doorbell_offset(&self) -> Option<usize> {
        let n = self.doorbell_offset as usize;
        let cap = self.cap_length as usize;
        if n == 0 || n < cap || n % 4 != 0 {
            return None;
        }
        Some(n)
    }
}

/// 初始化失败原因（ADR-209）。
///
/// **不用 `bool`**：「没有设备」「寄存器形状非法」「能力不支持」是三种不同的处置。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    /// MaxSlotsEn == 0：控制器不支持任何设备槽。
    NoSlots,
    /// CAPLength 非法（< 0x20 或不是 4 的倍数）。
    BadCapLength(u8),
    /// Doorbell 偏移非法（0 / 在 CAP 内 / 没对齐）。
    BadDoorbell(u32),
    /// 32 位 DMA 与要求不符（今天要求 AC64=1 —— 见决策）。
    No64Bit,
    /// MaxPorts == 0：没有下游端口。
    NoPorts,
    /// DMA 缓冲没有 64 字节对齐（命令环 / DCBAA）。
    ///
    /// 原本这里复用了 `BadCapLength(0)`，那是错的：
    /// 「能力寄存器形状」和「软件给的缓冲没对齐」是完全不同的成因，
    /// 混成一个码会让调用方无法区分该改驱动还是改分配器。
    BadAlignment(u64),
}

/// 初始化要写的 OP 寄存器（ADR-209）。
///
/// **只描述「写什么」，不真的写** —— 真写要经 `DriverCtx::write32`，
/// 而那需要真实设备。分开之后，判据可以验证整条初始化序列。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpWrite {
    /// USBCMD：先写 HCRST=1 复位，再等 CNR=0，再写 RS=1 运行。
    UsbCmd { reset: bool, run: bool, interrupts: bool },
    /// CRCR：Command Ring Control（低 6 位标志 + 指针）。
    Crcr { ring: u64, cycle: bool },
    /// DCBAAP：Device Context Base Address Array 指针。
    Dcbaap { table: u64 },
    /// CONFIG：MaxSlotsEn 写回（启用槽）。
    Config { max_slots: u8 },
}

/// **从能力快照推导初始化序列**（ADR-209 的核心纯函数）。
///
/// 输入：CAP 寄存器快照 + 两个 DMA 缓冲的总线地址（命令环、DCBAA 表）。
/// 输出：`Ok(序列)` 或 `Err(具体失败)`。
///
/// ## 为什么返回序列而不是直接操作
///
/// 与前几片同一条纪律：**只有纯函数能被判据完整证伪**。
/// 真机接线是下一步的事；先把「序列推导对不对」证了。
pub fn plan_init(
    cap: &CapSnapshot,
    cmd_ring_bus: u64,
    dcbaa_bus: u64,
) -> Result<[OpWrite; 5], InitError> {
    // 顺序有意义：先形状校验，再能力校验，最后才产出写序列。
    if cap.op_offset().is_none() {
        return Err(InitError::BadCapLength(cap.cap_length));
    }
    if cap.doorbell_offset().is_none() {
        return Err(InitError::BadDoorbell(cap.doorbell_offset));
    }
    if cap.max_slots() == 0 {
        return Err(InitError::NoSlots);
    }
    if cap.max_ports() == 0 {
        return Err(InitError::NoPorts);
    }
    if !cap.ac64() {
        return Err(InitError::No64Bit);
    }
    // 命令环必须 64 字节对齐（spec §4.9: CRCR 低 6 位是标志）。
    if cmd_ring_bus & 0x3F != 0 {
        return Err(InitError::BadAlignment(cmd_ring_bus));
    }
    // DCBAA 必须 64 字节对齐。
    if dcbaa_bus & 0x3F != 0 {
        return Err(InitError::BadAlignment(dcbaa_bus));
    }
    Ok([
        // 1) 复位：HCRST=1（硬件会自清）
        OpWrite::UsbCmd { reset: true, run: false, interrupts: false },
        // 2) DCBAA 指针
        OpWrite::Dcbaap { table: dcbaa_bus },
        // 3) 命令环指针（cycle=1 初始）
        OpWrite::Crcr { ring: cmd_ring_bus, cycle: true },
        // 4) CONFIG：启用全部槽
        OpWrite::Config { max_slots: cap.max_slots() },
        // 5) 运行：RS=1 + IE=1（中断使能）
        OpWrite::UsbCmd { reset: false, run: true, interrupts: true },
    ])
}

// ---------------------------------------------------------------- ADR-210：真设备 probe

/// xHCI 的 `ModuleId`（驱动资源台账用）。
///
/// **必须唯一**：`driver/mod.rs` 的台账按 ModuleId 聚合，撞了就会互相顶账。
const MOD_XHCI: crate::mm::ModuleId = crate::mm::ModuleId(88);

/// 一次真实 probe 的读数（ADR-210）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    pub cap_length: u8,
    pub max_slots: u8,
    pub max_intrs: u16,
    pub max_ports: u8,
    pub ac64: bool,
    pub csz: bool,
    pub scratchpad: u16,
    pub doorbell_offset: u32,
    /// BAR 长度（字节）—— 用来证「映射窗口够大」。
    pub bar_len: usize,
}

/// probe 失败原因（ADR-210）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeError {
    NoDevice,
    /// BAR0 不是内存型，或映射失败。
    NoMmio,
    /// 读寄存器失败。
    Io,
    /// CAP 形状非法（见 `InitError`）。
    BadCap,
}

/// **对一个 xHCI 设备做真实 probe**（ADR-210）：映射 BAR0、读 CAP、校验形状。
///
/// ## 今天不做什么
///
/// **不写任何寄存器**。`plan_init`（ADR-209）算出的 5 步序列还没执行 ——
/// 那一步要等 CNR=0、要分配命令环与 DCBAA、要处理 HCRST 的时序。
///
/// 今天证的是三件事：**设备在、BAR 能映射、CAP 能读出且形状合法**。
/// 这三件事是后续一切的前提，而且它们**失败时成因清楚**。
pub fn probe_device(dev: &crate::bus::pci::Dev) -> Result<Reading, ProbeError> {
    use crate::driver::{DriverCtx, DriverError};
    let ctx = DriverCtx::for_device(MOD_XHCI, *dev);
    let mmio = ctx.map_mmio(0).map_err(|e| match e {
        DriverError::NoDevice => ProbeError::NoMmio,
        _ => ProbeError::NoMmio,
    })?;
    let bar_len = ctx.mmio_len(mmio).map_err(|_| ProbeError::Io)?;
    // CAP 在偏移 0：先读 CAPLENGTH/HCSPARAMS1/HCCPARAMS1/DOORBELL。
    // **顺序按 spec**：CAPLENGTH 在 0x00 的低字节，HCSPARAMS1 在 0x04。
    let cap0 = ctx.read32(mmio, CAP_CAPLENGTH).map_err(|_| ProbeError::Io)?;
    let hcsparams1 = ctx.read32(mmio, CAP_HCSPARAMS1).map_err(|_| ProbeError::Io)?;
    let hccparams1 = ctx.read32(mmio, CAP_HCCPARAMS1).map_err(|_| ProbeError::Io)?;
    let doorbell = ctx.read32(mmio, CAP_DOORBELL_OFFSET).map_err(|_| ProbeError::Io)?;
    let cap = CapSnapshot {
        cap_length: (cap0 & 0xFF) as u8,
        hcsparams1,
        hccparams1,
        doorbell_offset: doorbell,
    };
    // 形状校验：复用 ADR-209 的解码（那两个 `Option` 就是校验器）。
    if cap.op_offset().is_none() || cap.doorbell_offset().is_none() {
        // **把读到的原始值打出来**：形状校验失败时，「哪个字段不对」比「失败了」重要得多。
        crate::log_fatal!(
            "xhci: CAP 形状非法 cap0={:#010x} caplen={:#x} hcsp={:#010x} hccp={:#010x} db={:#010x}",
            cap0, cap.cap_length, hcsparams1, hccparams1, doorbell
        );
        return Err(ProbeError::BadCap);
    }
    Ok(Reading {
        cap_length: cap.cap_length,
        max_slots: cap.max_slots(),
        max_intrs: cap.max_intrs(),
        max_ports: cap.max_ports(),
        ac64: cap.ac64(),
        csz: cap.csz(),
        scratchpad: cap.max_scratchpad(),
        doorbell_offset: cap.doorbell_offset,
        bar_len,
    })
}