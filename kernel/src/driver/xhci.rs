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
pub const CAP_CAPLENGTH: usize = 0x00;
pub const CAP_HCSPARAMS1: usize = 0x04;
pub const CAP_HCCPARAMS1: usize = 0x08;
pub const CAP_DOORBELL_OFFSET: usize = 0x0C;

/// 运行寄存器偏移（spec §5.4）。
pub const OP_USBCMD: usize = 0x00;
pub const OP_USBSTS: usize = 0x04;
pub const OP_FRINDEX: usize = 0x0C;
pub const OP_CRCR: usize = 0x18;
pub const OP_DCBAAP: usize = 0x30;
pub const OP_CONFIG: usize = 0x38;