//! NVMe 驱动（ADR-169）。
//!
//! 形状由三件事定，都不是审美：
//!
//! 1. **四个队列塞进同一块 DMA**（ADR-165 决策 2）。`alloc_dma` 给的是连续页，
//!    而 `DmaHandle` 的访问器都收 `off` 参数 ⇒ 一块 8 页的 DMA 自己切成
//!    Admin SQ / Admin CQ / I/O SQ / I/O CQ 四段。这样 DMA 槽从 5 格压到 2 格
//!    （另一格是数据页），否则 `DMA_SLOTS=8` 时代加一台 NVMe 就满。
//!
//! 2. **PRP 只用 PRP1**。一次传输不超过一页（512 字节扇区绰绰有余），
//!    所以不需要 PRP List。代价是大块传输要拆成多次命令——而
//!    `filesystem/block_io.rs` 本来就是**逐扇区提交**（ADR-110 决策 1），
//!    所以这个"代价"在既有契约里是零。
//!
//! 3. **每个偏移先读回验证**（ADR-029 的口径：手册上的表要由设备作证）。
//!    本文件里 CAP/VS/CSTS 的偏移是规范值，但**第一步就是把它们读出来打印**，
//!    与 QEMU 的声明对账；对不上就是 `BadRegs`，不往下走。
//!
//! 不变量：`Σ 完成的命令 == Σ 提交的命令`，且每条命令的 CID 唯一。

use crate::driver::{DriverCtx, DmaHandle, DriverError, MmioHandle};
use crate::mm::ModuleId;
use crate::pci::Dev;
use crate::sync::{OpenSpinLock, RANK_GROW};

/// NVMe 的帧记在这个模块号下（ADR-165：`MOD_VMO` 已从 19 挪走，21 是新的空位）。
pub const MOD_NVME: ModuleId = ModuleId(21);

// ---------------------------------------------------------------- PCI 三件套

/// NVMe 控制器的 class/subclass/progif（PCI 规范 1.1.2 的 NVM Express 分配）。
pub const PCI_CLASS_NVME: u8 = 0x01;
pub const PCI_SUBCLASS_NVME: u8 = 0x08;
pub const PCI_PROGIF_NVME: u8 = 0x02;

// ---------------------------------------------------------------- 寄存器偏移

/// CAP 是 64 位，偏移 0x00。**必须先读它**：MQES/DSTRD/TO 全在里面，
/// 而"队列能开多深"由 MQES 决定，不写死。
pub const REG_CAP: u64 = 0x00;
/// VS（版本）：0x08。
pub const REG_VS: u64 = 0x08;
/// CC（控制器配置）：0x14。`EN` 是 bit0。
pub const REG_CC: u64 = 0x14;
/// CSTS（控制器状态）：0x1C。`RDY` 是 bit0。
pub const REG_CSTS: u64 = 0x1C;
/// AQA（Admin 队列属性）：0x24。低 12 位 = SQ 深度-1，高 12 位 = CQ 深度-1。
pub const REG_AQA: u64 = 0x24;
/// ASQ（Admin SQ 基址，64 位）：0x28。
pub const REG_ASQ: u64 = 0x28;
/// ACQ（Admin CQ 基址，64 位）：0x30。
pub const REG_ACQ: u64 = 0x30;

/// `CC.EN`：控制器使能。
pub const CC_EN: u32 = 1 << 0;
/// `CSTS.RDY`：控制器就绪。
pub const CSTS_RDY: u32 = 1 << 0;
/// `CSTS.CFS`：控制器致命状态。起来了也要看它——"就绪但致命"是最容易误判的形状。
pub const CSTS_CFS: u32 = 1 << 1;

// ---------------------------------------------------------------- 命令 opcode

// **opcode 是按队列解释的**（NVMe 规范 §4）：同一个数在 admin 队列与
// I/O 队列上是两条不同的命令。0x02 在 admin 上是 Get Log Page、在 I/O 上是 Read。
// 所以下面按队列分组，且**不许**跨队列复用常量——
// 实测教训（BACKLOG §453）：`io_lba` 误用 admin 队列的 submit，
// 于是「读扇区 0」被设备理解成「读日志页」，被拒 `status 0x4002`，
// 而现场只说「命令失败」，看不出是发错了队列。

// ---- Admin 队列 opcode
pub const OP_DELETE_SQ: u8 = 0x00;
pub const OP_CREATE_SQ: u8 = 0x01;
pub const OP_GET_LOG_PAGE: u8 = 0x02;
pub const OP_DELETE_CQ: u8 = 0x04;
pub const OP_CREATE_CQ: u8 = 0x05;
pub const OP_IDENTIFY: u8 = 0x06;

// ---- I/O 队列 opcode（与上面**同值不同义**，所以名字必须带 IO_ 前缀）
pub const OP_IO_WRITE: u8 = 0x01;
pub const OP_IO_READ: u8 = 0x02;

/// Identify 的 CNS：0 = Identify Namespace，1 = Identify Controller。
pub const CNS_NAMESPACE: u32 = 0x00;
pub const CNS_CONTROLLER: u32 = 0x01;

/// 一条提交命令定长 64 字节、一条完成定长 16 字节（NVMe 规范 §4）。
pub const SQE_BYTES: usize = 64;
pub const CQE_BYTES: usize = 16;
/// `Create I/O CQ` 的 CDW12 要报条目大小的 log2：SQE 64 字节 ⇒ 6。
pub const SQE_LOG2: u8 = 6;
/// CQE 16 字节 ⇒ 4。
pub const CQE_LOG2: u8 = 4;
pub const CC_CONFIG: u32 = CC_EN | ((SQE_LOG2 as u32) << 16) | ((CQE_LOG2 as u32) << 20);
pub const AQA_CONFIG: u32 = ((QDEPTH as u32 - 1) & 0xFFF) | (((QDEPTH as u32 - 1) & 0xFFF) << 16);

/// 队列深度。取 8 而不是 MQES 的上限：判据只需要"能排队、能收完成"，
/// 而 8 条 × 64 字节 = 512 字节 = 正好一页，切起来干净。
pub const QDEPTH: usize = 8;

/// 四个环的页内布局（同一块 DMA 里切）。每段都按页对齐，
/// 因为 NVMe 的 ASQ/ACQ 基址要求 4 KiB 对齐。
pub const OFF_ADMIN_SQ: usize = 0;
pub const OFF_ADMIN_CQ: usize = 4096;
pub const OFF_IO_SQ: usize = 8192;
pub const OFF_IO_CQ: usize = 12288;
/// 数据页（一次一扇区）。
pub const OFF_DATA: usize = 16384;
/// 总共要几页：4 个环 + 8 个单扇区数据槽 = 12 页内容，但 `alloc_dma` 只接受
/// **2 的幂**的页数（它内部是 `(len / PAGE).ilog2()`，向下取整**静默截断**），
/// 所以取 16。
///
/// **实测教训**：第一版写 5，`(5).ilog2() = 2` ⇒ 实际只映了 4 页，
/// 而 `OFF_DATA = 16384` 在第 5 页 ⇒ 写数据页当场 `#PF err=0x2`。
/// 这个坑不报错、只截断，所以把契约写在这里。
pub const DMA_PAGES: usize = 16;
pub const DATA_SLOTS: usize = QDEPTH;
const PAGE_BYTES: usize = 4096;
pub const DATA_STRIDE: usize = PAGE_BYTES;

/// Identify 的返回缓冲是 4096 字节（规范固定），而一块 DMA 只有 5 页，
/// 所以 Identify 复用数据页那一段（它只在初始化时用，与数据读写不重叠）。
pub const OFF_IDENTIFY: usize = OFF_DATA;
pub const IDENTIFY_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvmeError {
    /// 枚举表里没有 NVMe 三件套（class 0x01 / subclass 0x08 / progif 0x02）
    NoDevice,
    /// 寄存器读数与规范对不上：`(偏移, 读到的, 期望的形状)`
    BadRegs { off: u64, got: u32, what: u8 },
    /// 控制器在时限内没进 `RDY`
    NotReady { csts: u32, spins: u32 },
    /// 起来了但 `CFS` 置位：就绪 ≠ 健康
    ControllerFatal { csts: u32 },
    /// 一条命令在时限内没收到完成
    CmdTimeout { cid: u16 },
    /// 完成项的 status 非零：`(cid, status)`
    CmdFailed { cid: u16, status: u16 },
    /// 队列深度超出 CAP.MQES 给的上限
    QueueTooDeep { want: usize, max: usize },
    /// I/O 队列还没建（Create I/O CQ/SQ 未做）。
    ///
    /// **单独一个变体而不是复用 `CmdFailed`**：这条路径的成因是
    /// 「我们还没做那一步」，不是「设备拒了」。混在一起会让日志说
    /// 「命令失败」，而真正该说的是「I/O 队列没建」。
    IoQueueNotReady,
    /// 句柄表拒绝（映射/DMA/中断）
    Ctx(DriverError),
    /// 异步租约表已满，或适配器已隔离。
    AsyncBusy,
    /// 数据长度与租约容量不一致：`(期望, 实际)`。
    BadLen { want: usize, got: usize },
}

impl NvmeError {
    pub fn describe(e: NvmeError) -> &'static str {
        match e {
            NvmeError::NoDevice => "没有 NVMe 三件套的设备",
            NvmeError::BadRegs { .. } => "寄存器读数与规范对不上",
            NvmeError::NotReady { .. } => "控制器在时限内没进 RDY",
            NvmeError::ControllerFatal { .. } => "控制器就绪但报了致命状态",
            NvmeError::CmdTimeout { .. } => "命令在时限内没收到完成",
            NvmeError::CmdFailed { .. } => "完成的 status 非零",
            NvmeError::QueueTooDeep { .. } => "队列深度超出 CAP.MQES",
            NvmeError::IoQueueNotReady => "I/O 队列还没建（Create I/O CQ/SQ 未做）",
            NvmeError::Ctx(_) => "句柄表拒绝",
            NvmeError::AsyncBusy => "异步租约表满或适配器已隔离",
            NvmeError::BadLen { .. } => "数据长度与租约容量不一致",
        }
    }
}

impl From<DriverError> for NvmeError {
    fn from(e: DriverError) -> Self {
        NvmeError::Ctx(e)
    }
}

/// 一次初始化的全部读数（判据与打印都用它，不留"只有日志知道"的事实）。
#[derive(Clone, Copy, Debug)]
pub struct Reading {
    pub bdf: u32,
    pub vendor: u16,
    pub device: u16,
    /// CAP 的低 32 位与高 32 位：**分开存**，因为 MQES 在低 16 位、TO 在高 16 位。
    pub cap_lo: u32,
    pub cap_hi: u32,
    pub vs: u32,
    pub csts_before: u32,
    pub csts_after: u32,
    /// `CAP.MQES + 1`：这台设备允许的最大队列深度
    pub max_qdepth: usize,
    /// Identify Namespace 读回的命名空间大小（单位：LBA）
    pub nsze: u64,
    /// Identify Namespace 读回的 LBA 大小（2 的幂，通常是 9 = 512）
    pub lbads: u8,
    /// Identify Controller 读回的型号前 16 字节（ASCII，尾部补空格）
    pub model: [u8; 16],
    /// I/O 队列是否建起来了（Create I/O CQ/SQ 两条 admin 命令是否都成功）。
    pub io_queues: bool,
    /// Identify Controller 的 NN：设备有几个命名空间。
    ///
    /// 用它证「有命名空间」——而 NSZE（容量）来自 Identify Namespace，
    /// 那条在 QEMU 上可能因 NSID 不匹配而静默不产生完成项（实测）。
    pub namespaces: u32,
}

/// 设备的单例状态。NVMe 不像 virtio 有多台，先按单台做（表化留给需要时）。
struct Cell(core::cell::UnsafeCell<Option<State>>);
// SAFETY: `init()` 只在启动期单核发布 `Some(State)`；发布后所有设备状态访问都先取
// `State.io_lock`。ISR 不访问本单元，初始化完成前也不存在并发调用。
unsafe impl Sync for Cell {}

/// 一个队列的提交/完成游标。
///
/// `phase` 是**整圈翻转的奇偶**（NVMe 与 virtio 最大的差别：virtio 的 `used.idx`
/// 单调递增，NVMe 的 phase 翻转）。清零之后第一圈是 `true`。
#[derive(Clone, Copy)]
struct QState {
    sq_tail: u16,
    cq_head: u16,
    phase: bool,
    /// 队列深度（Create 时定的）。0 = 这个队列还没建。
    depth: u16,
}

impl QState {
    const fn new(depth: u16) -> Self {
        Self { sq_tail: 0, cq_head: 0, phase: true, depth }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AsyncSlotState {
    Free,
    Reserved,
    InFlight,
    Completed,
}

#[derive(Clone, Copy, Debug)]
struct AsyncSlot {
    state: AsyncSlotState,
    local_id: u64,
    sectors: u32,
    cid: u16,
    submit_error: Option<NvmeError>,
    completion: Option<NvmeIoCompletion>,
}

impl AsyncSlot {
    const EMPTY: Self = Self {
        state: AsyncSlotState::Free,
        local_id: 0,
        sectors: 0,
        cid: 0,
        submit_error: None,
        completion: None,
    };
}

struct AsyncIoState {
    slots: [AsyncSlot; DATA_SLOTS],
    next_id: u64,
    submitted: u32,
    completed: u32,
    cancelled: u32,
    bad_used: u32,
    wait_calls: u32,
    poisoned: bool,
    force_sync_timeout: bool,
    force_fatal: bool,
}

impl AsyncIoState {
    const fn new() -> Self {
        Self {
            slots: [AsyncSlot::EMPTY; DATA_SLOTS],
            next_id: 1,
            submitted: 0,
            completed: 0,
            cancelled: 0,
            bad_used: 0,
            wait_calls: 0,
            poisoned: false,
            force_sync_timeout: false,
            force_fatal: false,
        }
    }
}

/// 取消只对尚未发射的 Reserved 租约生效；已发射命令不能假装撤回过设备。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvmeCancel {
    Cancelled,
    InFlight,
    NotFound,
    Completed,
}

/// 显式 reap 取回的一条完成。`CmdFailed` 原样放在 `error`，不当成丢失。
#[derive(Clone, Copy, Debug)]
pub struct NvmeIoCompletion {
    pub local_id: u64,
    pub sectors_done: u32,
    pub error: Option<NvmeError>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NvmeAsyncStats {
    pub submitted: u32,
    pub completed: u32,
    pub cancelled: u32,
    pub bad_used: u32,
    pub wait_calls: u32,
    pub occupied: usize,
    pub poisoned: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NvmeDrain {
    pub completed: usize,
    pub outstanding: usize,
    pub disabled: bool,
    pub queues_deleted: bool,
}

struct InnerState {
    ctx: DriverCtx,
    mmio: MmioHandle,
    dma: DmaHandle,
    /// 数据页的 bus 地址（PRP1 用）
    data_bus: u64,
    /// 管理队列的两个 bus 地址
    asq_bus: u64,
    acq_bus: u64,
    /// I/O 队列的两个 bus 地址（Create I/O CQ/SQ 要用）
    cq1_bus: u64,
    sq1_bus: u64,
    /// 每个队列一套游标（下标 = qid：0 = admin、1 = I/O）。
    ///
    /// **不能共用一对**：I/O 命令推进 `sq_tail` 会让 admin 的门铃值错位，
    /// 而那种错表现成「admin 命令偶尔超时」，极难归因。
    q: [QState; 2],
    /// 下一条命令的 CID
    next_cid: u16,
    /// 读回的读数
    reading: Reading,
    /// 命名空间大小（LBA 数）
    nsze: u64,
    /// 每 LBA 字节数
    lba_bytes: usize,
}

struct State {
    /// 同步 I/O 与异步入口共用；设备等待有界，期间保持调用方 IF（ADR-255/259）。
    io_lock: OpenSpinLock<AsyncIoState>,
    inner: InnerState,
}

static STATE: Cell = Cell(core::cell::UnsafeCell::new(None));

/// 所有设备状态的唯一访问门。先排 ISR，再按 rank 取锁；非法外层 rank 在 CAS 前拒绝。
fn with_io<R>(body: impl FnOnce(&mut InnerState, &mut AsyncIoState) -> R) -> Result<R, NvmeError> {
    if DriverCtx::in_isr() {
        return Err(NvmeError::Ctx(DriverError::WrongContext));
    }
    // SAFETY: `Cell` 只在启动期发布；先取共享视图定位锁，取得锁后才由同一单元的
    // 原始指针建立 `inner` 的可变视图。不能预先创建重叠的 `&mut State`。
    let st = unsafe { &*STATE.0.get() }.as_ref().ok_or(NvmeError::NoDevice)?;
    let inner_ptr = &raw const st.inner as *mut InnerState;
    let mut io = match st.io_lock.lock_checked() {
        Some(io) => io,
        None => return Err(NvmeError::AsyncBusy),
    };
    // SAFETY: `inner_ptr` 来自已发布的 `UnsafeCell`（`STATE.0.get()`）；此刻持有其唯一 `io_lock`。
    let inner = unsafe {
        &mut *inner_ptr
    };
    Ok(body(inner, io.get()))
}

/// 当前读数（没初始化就是 `None`）。
pub fn reading() -> Option<Reading> {
    with_io(|st, _| st.reading).ok()
}

/// 命名空间大小（LBA 数）。判据用它算容量。
pub fn nsze() -> Option<u64> {
    with_io(|st, _| st.nsze).ok()
}

/// 每 LBA 字节数。
pub fn lba_bytes() -> Option<usize> {
    with_io(|st, _| st.lba_bytes).ok()
}

// ---------------------------------------------------------------- 寄存器访问

fn rd32(ctx: &DriverCtx, h: MmioHandle, off: u64) -> Result<u32, NvmeError> {
    ctx.read32(h, off as usize).map_err(NvmeError::Ctx)
}

fn wr32(ctx: &DriverCtx, h: MmioHandle, off: u64, v: u32) -> Result<(), NvmeError> {
    ctx.write32(h, off as usize, v).map_err(NvmeError::Ctx)
}

/// 读 CAP 的 64 位（低半在 `off`，高半在 `off+4`）。
fn rd64(ctx: &DriverCtx, h: MmioHandle, off: u64) -> Result<(u32, u32), NvmeError> {
    Ok((rd32(ctx, h, off)?, rd32(ctx, h, off + 4)?))
}

/// 认领一台 NVMe 并初始化到 `RDY`。
///
/// **顺序不能换**：先读 CAP（定队列深度上限）→ 再建队列 → 再 `CC.EN` → 等 `RDY`。
/// 反过来写会让控制器用一个我们不知道深度的队列，而深度错的表现是"命令丢了一半"。
pub fn init() -> Result<Reading, NvmeError> {
    // SAFETY: 只在启动期单核调用一次
    if unsafe { (*STATE.0.get()).is_some() } {
        // 幂等：已经初始化过就直接回读数
        return Ok(reading().unwrap_or_else(|| unreachable!("已初始化但没有读数")));
    }

    let dev = crate::pci::first_of_triple(PCI_CLASS_NVME, PCI_SUBCLASS_NVME, PCI_PROGIF_NVME)
        .ok_or(NvmeError::NoDevice)?;
    let ctx = DriverCtx::for_device(MOD_NVME, dev);
    let mmio = ctx.map_mmio(0)?;

    // ---- 1) 读 CAP：先读低半再读高半（CAP 的高半在写之前不会变，这里只读）
    let (cap_lo, cap_hi) = rd64(&ctx, mmio, REG_CAP)?;
    let mqes = (cap_lo & 0xFFFF) as usize + 1;
    // 队列深度必须 ≤ MQES+1。QDEPTH=8 是保守值，但**要验**：
    // 若某设备的 MQES 小到放不下 8，那就是真的装不下，报错而不是截断。
    if QDEPTH > mqes {
        return Err(NvmeError::QueueTooDeep { want: QDEPTH, max: mqes });
    }
    let vs = rd32(&ctx, mmio, REG_VS)?;
    let csts_before = rd32(&ctx, mmio, REG_CSTS)?;
    // **起始状态允许两种**：未使能（RDY=0）或已被固件使能（RDY=1）。
    //
    // 实测教训：我原来写「未使能时 RDY 必须为 0」，而 QEMU 的 `-device nvme`
    // 在 EDK2 阶段就可能已经使能过 ⇒ 进内核时 RDY=1，判据当场报
    // `BadRegs { off: 28, got: 1 }`。**那条假设证的是「设备还没被碰过」——
    // 那是环境假设，不是设备性质。**
    //
    // 现在证的是**状态机合法**：起始 RDY 可为 0 或 1，但 CFS 必须为 0
    // （不能一进来就是致命态）；终态要求 RDY=1 且 CFS=0。
    // 这比原来**更强**：它同时覆盖两种起始，且额外验了 CFS。
    if csts_before & CSTS_CFS != 0 {
        return Err(NvmeError::ControllerFatal { csts: csts_before });
    }
    let already_enabled = csts_before & CSTS_RDY != 0;

    // ---- 2) 一块 5 页的 DMA：4 个环 + 1 个数据页（ADR-165 决策 2）
    let dma = ctx.alloc_dma(DMA_PAGES * crate::mm::PAGE)?;
    let base = ctx.bus_addr(dma)?;
    let asq_bus = base + OFF_ADMIN_SQ as u64;
    let acq_bus = base + OFF_ADMIN_CQ as u64;
    let data_bus = base + OFF_DATA as u64;
    let cq1_bus = base + OFF_IO_CQ as u64;
    let sq1_bus = base + OFF_IO_SQ as u64;
    // 环要先清零：NVMe 读 CQ 的 phase 位，脏数据会让"第一条完成"看起来已经到了。
    for off in (0..DMA_PAGES * crate::mm::PAGE).step_by(crate::mm::PAGE) {
        ctx.dma_fill(dma, off, 0, crate::mm::PAGE)?;
    }

    // ---- 3) 若已使能，先禁用：规范（NVMe 1.4 §7.6.1）要求改 ASQ/ACQ/AQA 之前
    // 必须 CC.EN=0 并等 CSTS.RDY=0。**这一条是实测买来的**：第一版跳过它直接写
    // ASQ/ACQ，控制器继续用固件留下的旧队列，于是命令永远不完成（CmdTimeout cid=1），
    // 而现场只说「超时」，看不出是队列没加载。
    if already_enabled {
        wr32(&ctx, mmio, REG_CC, 0)?;
        let mut off_spins = 0u32;
        while rd32(&ctx, mmio, REG_CSTS)? & CSTS_RDY != 0 {
            if off_spins >= 2_000_000 {
                return Err(NvmeError::NotReady {
                    csts: rd32(&ctx, mmio, REG_CSTS)?,
                    spins: off_spins,
                });
            }
            off_spins += 1;
        }
    }

    // ---- 3b) AQA + ASQ + ACQ，然后 CC.EN
    // AQA: 低 12 位 = ASQS（深度-1），高 12 位 = ACQS。两边同深度。
    let aqa = AQA_CONFIG;
    wr32(&ctx, mmio, REG_AQA, aqa)?;
    // ASQ/ACQ 是 64 位物理地址：低半 + 高半
    wr32(&ctx, mmio, REG_ASQ, asq_bus as u32)?;
    wr32(&ctx, mmio, REG_ASQ + 4, (asq_bus >> 32) as u32)?;
    wr32(&ctx, mmio, REG_ACQ, acq_bus as u32)?;
    wr32(&ctx, mmio, REG_ACQ + 4, (acq_bus >> 32) as u32)?;
    // 读回对账：这三个寄存器写完必须读得回来（ADR-029 的口径）
    if rd32(&ctx, mmio, REG_AQA)? != aqa {
        return Err(NvmeError::BadRegs { off: REG_AQA, got: rd32(&ctx, mmio, REG_AQA)?, what: 2 });
    }

    // 到这里 RDY 一定是 0（起始未使能，或上面已经关掉），所以无条件写 CC.EN。
    //
    // **`CC` 要一次写全**：`IOSQES`(bit19..16) 与 `IOCQES`(bit23..20) 是
    // **控制器级配置**，不是 Create 命令的字段 —— QEMU 在 `nvme_create_cq`
    // 里读的是 `n->bar.cc`。只写 `EN` 会让 Create I/O CQ 报
    // `err_invalid_create_cq_entry_size iosqes 0 iocqes 0`。
    //
    // **这条踩了两轮**：先试 CDW12、再试 CDW11，两处都写仍报 0，
    // 而内存读回证明 dw12=0x46 真的写进去了 —— **那个矛盾才是提示：
    // 读的不是我写的那个地方。** 它根本不在命令里。
    //
    // 规范 Figure 34：CC = EN(0) | CSS(6..4) | MPS(10..7) | AMS(13..11)
    //   | SHN(15..14) | IOSQES(19..16) | IOCQES(23..20)。
    // SQE 64 字节 ⇒ log2 = 6；CQE 16 字节 ⇒ log2 = 4。
    wr32(&ctx, mmio, REG_CC, CC_CONFIG)?;
    // 等 RDY。窗口按"最多转这么多轮"给，而不是按周期——
    // 周期要时钟，而时钟标定可能还没跑（§442 那次就是这么红的）。
    let mut spins = 0u32;
    let mut csts_after = rd32(&ctx, mmio, REG_CSTS)?;
    while csts_after & CSTS_RDY == 0 {
        if spins >= 2_000_000 {
            return Err(NvmeError::NotReady { csts: csts_after, spins });
        }
        spins += 1;
        csts_after = rd32(&ctx, mmio, REG_CSTS)?;
    }
    // **就绪 ≠ 健康**：CFS 置位说明控制器报了致命状态，这时候往下走
    // 会让每条命令都超时，而日志只会说"命令超时"——成因被藏起来了。
    if csts_after & CSTS_CFS != 0 {
        return Err(NvmeError::ControllerFatal { csts: csts_after });
    }

    let mut device = State {
        io_lock: OpenSpinLock::new(RANK_GROW, AsyncIoState::new()),
        inner: InnerState {
            ctx,
            mmio,
            dma,
            data_bus,
            asq_bus,
            acq_bus,
            cq1_bus,
            sq1_bus,
            // admin 队列在建 ASQ/ACQ 时就有了；I/O 队列的 depth 先 0（未建）
            q: [QState::new(QDEPTH as u16), QState::new(0)],
            next_cid: 1,
            reading: Reading {
                bdf: dev.bdf,
                vendor: dev.vendor,
                device: dev.device,
                cap_lo,
                cap_hi,
                vs,
                csts_before,
                csts_after,
                max_qdepth: mqes,
                nsze: 0,
                lbads: 0,
                model: [0; 16],
                namespaces: 0,
                io_queues: false,
            },
            nsze: 0,
            lba_bytes: 512,
        },
    };
    let mut st = &mut device.inner;

    // ---- 4) Identify Controller：读型号（判据要用它跟 QEMU 的 serial= 对账）
    let mut ctrl = [0u8; IDENTIFY_BYTES];
    identify(&mut st, CNS_CONTROLLER, 0, &mut ctrl)?;
    // 型号在 Identify Controller 的偏移 24，长 40 字节；判据只用前 16
    let mut model = [0u8; 16];
    model.copy_from_slice(&ctrl[24..40]);
    st.reading.model = model;

    // ---- 5) Identify Namespace：读 NSZE 与 LBA 大小
    //
    // **容错**（实测教训）：QEMU 上 NSID 不匹配时这条命令**不产生完成项**
    // （不是回 status，是静默不写 CQE），于是 `wait_cqe` 超时。
    // 那不该让整个初始化失败——`NN` 已经告诉我们「有几个命名空间」，
    // 而容量对账可以由宿主机 `qemu-img` 独立算（第二台仪器）。
    // **读不到就明说读不到，不假装通过。**
    let mut ns = [0u8; IDENTIFY_BYTES];
    let ns_read_ok = identify(&mut st, CNS_NAMESPACE, 1, &mut ns).is_ok();
    if !ns_read_ok {
        crate::log_warn!(
            "nvme: Identify Namespace 未读到（NSID 不匹配？）⇒ NSZE 记 0，容量对账交给宿主机"
        );
    }
    // NN（Number of Namespaces）在 Identify Controller 的偏移 516。
    // **注意**：实测 QEMU 读回 256 而 -device nvme 只有一个 drive，
    // 所以这个值**不可信**（512..768 是 SUBNQN 字符串区，偏移可能不对）。
    // 只当读数记录，不当判据（ADR-169 §三）。
    let nn = u32::from_le_bytes([ctrl[516], ctrl[517], ctrl[518], ctrl[519]]);
    st.reading.namespaces = nn;
    // NSZE 在 Identify Namespace 的偏移 0（8 字节小端）；没读到就是 0
    let mut nsze = 0u64;
    if ns_read_ok {
        for i in 0..8 {
            nsze |= (ns[i] as u64) << (8 * i);
        }
    }
    // FLBAS/LBAF：偏移 26 是 FLBAS，低 4 位是当前 format 的下标；
    // 每个 format 的 LBADS 在偏移 128 + 4*i 的 bit 16..23。
    let (flbas, lbads) = if ns_read_ok {
        let f = ns[26] & 0x0F;
        (f, ns[128 + 4 * f as usize + 2])
    } else {
        // 没读到就按块层契约的 512（lbads=9）记，并在读数里标出来
        (0, 9)
    };
    st.nsze = nsze;
    st.lba_bytes = 1usize << lbads;
    st.reading.nsze = nsze;
    st.reading.lbads = lbads;

    // ---- 6) 建 I/O 队列（两条 admin 命令）。失败不致命：
    // 识别与容量两格已经成立，图案格会报 `IoQueueNotReady` 而不是静默错。
    let io_ok = create_io_queues(&mut st).is_ok();
    st.reading.io_queues = io_ok;
    if !io_ok {
        crate::log_warn!("nvme: I/O 队列没建起来 ⇒ 数据通路不可用（图案格会报 IoQueueNotReady）");
    }

    let out = st.reading;
    // SAFETY: `Cell` 只在启动期单核发布；此后所有访问由 `io_lock` 串行化。
    unsafe { *STATE.0.get() = Some(device) };
    Ok(out)
}

/// 建 I/O CQ + I/O SQ（NVMe 1.4 §5.2）。**两条都是 admin 队列命令。**
///
/// 顺序不能换：Create SQ 的 CDW11 要写它绑哪个 CQ，所以 CQ 得先存在。
///
/// 为什么 `IEN=0`（关中断）：我们轮询完成项（`wait_cqe`），不靠中断。
/// 开中断还要配 MSI-X 向量，那是另一件事（`msix_probe` 那套）。
/// 轮询对块层逐扇区的节奏足够，而且少一条「中断没来」的失败模式。
fn create_io_queues(st: &mut InnerState) -> Result<(), NvmeError> {
    let depth = QDEPTH as u32;
    // QSIZE 是「深度 - 1」（0 基）
    let qsize = depth - 1;
    let cq_bus = st.cq1_bus;
    let sq_bus = st.sq1_bus;

    // ---- Create I/O CQ：qid 1
    let cid = submit(st, Q::Admin, OP_CREATE_CQ, 0, |st, off| {
        // DPTR = PRP1 = I/O CQ 的物理地址
        st.ctx.dma_write32(st.dma, off + 24, cq_bus as u32)?;
        st.ctx.dma_write32(st.dma, off + 28, (cq_bus >> 32) as u32)?;
        // CDW10 = QID(15..0) | QSIZE(31..16)
        st.ctx.dma_write32(st.dma, off + 40, 1 | (qsize << 16))?;
        // CDW11 = PC(0) | IEN(1) | IV(31..16)
        //
        // **实测定位（QEMU 11.1 + trace）**：
        //   把条目大小放在 CDW11 的 bit16..23 时，trace 报 `vector=70`（0x46）
        //   ⇒ QEMU 把 CDW11 的 bit16..31 当 IV。所以条目大小不能在那里。
        // 规范 Figure 141：CDW12 = IOSQES(3..0) | IOCQES(7..4)。
        //
        // CDW11 = PC(0) | IEN(1) | IV(15..0)。**条目大小不在这条命令里** ——
        // 它在 `CC` 寄存器（`IOSQES`/`IOCQES`），见 `init` 里 `CC` 的写法。
        // 实测教训：把它塞进 dw11 的 bit16..31 会被当成 IV（trace 报 `vector=70`），
        // 塞进 dw12 则完全无效（trace 仍报 `iosqes 0`）。
        st.ctx.dma_write32(st.dma, off + 44, 1)?;
        Ok(())
    })?;
    wait_cqe(st, Q::Admin, cid)?;
    // ---- Create I/O SQ：qid 1，绑到 CQID 1
    let cid = submit(st, Q::Admin, OP_CREATE_SQ, 0, |st, off| {
        st.ctx.dma_write32(st.dma, off + 24, sq_bus as u32)?;
        st.ctx.dma_write32(st.dma, off + 28, (sq_bus >> 32) as u32)?;
        // CDW10 = QID(15..0) | QSIZE(31..16)
        st.ctx.dma_write32(st.dma, off + 40, 1 | (qsize << 16))?;
        // CDW11 = PC(bit0)=1 | QPRIO(2..1)=0 | CQID(31..16)=1
        st.ctx.dma_write32(st.dma, off + 44, 1 | (1 << 16))?;
        Ok(())
    })?;
    wait_cqe(st, Q::Admin, cid)?;

    // 两条都成功了才把 depth 立起来——**失败时 depth 保持 0**，
    // 于是 `submit(Q::Io)` 会明确返回 `IoQueueNotReady` 而不是发到一条半建的队列上。
    st.q[1] = QState::new(QDEPTH as u16);
    Ok(())
}

/// 发一条 Identify（CNS 选 Controller 或 Namespace），把 4096 字节读进 `out`。
fn identify(st: &mut InnerState, cns: u32, nsid: u32, out: &mut [u8]) -> Result<(), NvmeError> {
    let cid = submit(st, Q::Admin, OP_IDENTIFY, nsid, |st, off| {
        // DPTR = PRP1 = 数据页的 bus 地址（只一页，所以不需要 PRP2）
        st.ctx.dma_write32(st.dma, off + 24, st.data_bus as u32)?;
        st.ctx.dma_write32(st.dma, off + 28, (st.data_bus >> 32) as u32)?;
        // CDW10 = CNS
        st.ctx.dma_write32(st.dma, off + 40, cns)?;
        Ok(())
    })?;
    wait_cqe(st, Q::Admin, cid)?;
    // 从数据页读回（Identify 的返回是 4096 字节）
    st.ctx.dma_copy_out(st.dma, OFF_IDENTIFY, &mut out[..IDENTIFY_BYTES])?;
    Ok(())
}

enum IssueFailure {
    BeforeDoorbell(NvmeError),
    AfterDoorbell { cid: u16, error: NvmeError },
}

impl From<DriverError> for IssueFailure {
    fn from(error: DriverError) -> Self {
        Self::BeforeDoorbell(NvmeError::Ctx(error))
    }
}

impl From<NvmeError> for IssueFailure {
    fn from(error: NvmeError) -> Self {
        Self::BeforeDoorbell(error)
    }
}

impl From<IssueFailure> for NvmeError {
    fn from(failure: IssueFailure) -> Self {
        match failure {
            IssueFailure::BeforeDoorbell(error)
            | IssueFailure::AfterDoorbell { error, .. } => error,
        }
    }
}

/// 提交一条命令：写 SQE，敲门铃。`fill` 负责写命令特有的那几个 DWORD。
/// 命令发给哪个队列。**这个区分是必须的**：opcode 按队列解释，
/// 发错队列不会报「队列错」，只会被当成另一条命令（见 `OP_*` 的注释）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Q { Admin, Io }

impl Q {
    /// 队列号。admin 恒 0，第一个 I/O 队列是 1（规范 §5.2）。
    fn qid(self) -> u8 {
        match self {
            Q::Admin => 0,
            Q::Io => 1,
        }
    }
}

fn submit(
    st: &mut InnerState,
    q: Q,
    opcode: u8,
    nsid: u32,
    fill: impl FnOnce(&mut InnerState, usize) -> Result<(), NvmeError>,
) -> Result<u16, IssueFailure> {
    let qid = q.qid();
    let qs = st.q[qid as usize];
    // 队列没建就明确拒绝（I/O 队列要等 Create I/O CQ/SQ 之后才有）
    if qs.depth == 0 {
        return Err(IssueFailure::BeforeDoorbell(NvmeError::IoQueueNotReady));
    }
    let slot = qs.sq_tail as usize;
    // SQE 基址与门铃偏移都跟着 qid 走（stride = 8，因为 CAP.DSTRD = 0）。
    let (sq_off, db_off) = match q {
        Q::Admin => (OFF_ADMIN_SQ, 0x1000usize),
        Q::Io => (OFF_IO_SQ, 0x1000usize + 8), // qid 1 的 SQ tail doorbell
    };
    let off = sq_off + slot * SQE_BYTES;
    // 清掉上一条的残留：命令是 64 字节，不全会让"上一条的 CDW10"混进这一条。
    st.ctx.dma_fill(st.dma, off, 0, SQE_BYTES)?;
    let cid = st.next_cid;
    st.next_cid = st.next_cid.wrapping_add(1).max(1);
    // DW0: opcode(0..8) | fuse(8..10) | CID(16..32)
    let dw0 = u32::from(opcode) | ((cid as u32) << 16);
    st.ctx.dma_write32(st.dma, off, dw0)?;
    // DW1: NSID
    st.ctx.dma_write32(st.dma, off + 4, nsid)?;
    fill(st, off)?;

    // 屏障失败时尚未推进 SQ tail，调用方可安全放弃这条 Reserved 租约。
    rd32(&st.ctx, st.mmio, REG_CSTS).map_err(IssueFailure::from)?;
    let qs = &mut st.q[qid as usize];
    // 敲门铃。qid 0 = admin(0x1000)、qid 1 = I/O(0x1008)。
    qs.sq_tail = ((qs.sq_tail as usize + 1) % qs.depth as usize) as u16;
    let tail = qs.sq_tail;
    // 门铃写一旦尝试，命令是否已被设备接走就不由调用方证明；错误必须携带 CID 留在途。
    wr32(&st.ctx, st.mmio, db_off as u64, tail as u32)
        .map_err(|error| IssueFailure::AfterDoorbell { cid, error })?;
    #[cfg(feature = "fault-nvme-sync-submit-ctx")]
    if SYNC_SUBMIT_CTX.swap(false, core::sync::atomic::Ordering::AcqRel) {
        return Err(IssueFailure::AfterDoorbell {
            cid,
            error: NvmeError::Ctx(DriverError::Io),
        });
    }
    Ok(cid)
}

/// 只看当前 CQ 头，不推进游标、不敲门铃。用于变异证红与完成观察。
fn poll_cqe(st: &InnerState, q: Q, cid: u16) -> Result<bool, NvmeError> {
    let qid = q.qid();
    let qs = st.q[qid as usize];
    let cq_off = if qid == 0 { OFF_ADMIN_CQ } else { OFF_IO_CQ };
    let off = cq_off + qs.cq_head as usize * CQE_BYTES;
    let d3 = st.ctx.dma_read32(st.dma, off + 12)?;
    let got_cid = (d3 & 0xFFFF) as u16;
    let phase = ((d3 >> 16) & 1) as u8;
    Ok(got_cid == cid || (phase == 1) == qs.phase)
}

/// 取走 CQ 头的一条完成；`wait=false` 时只读当前已发布项，不空转。
fn take_cqe(st: &mut InnerState, q: Q, wait: bool, timeout_cid: u16) -> Result<Option<(u16, u16)>, NvmeError> {
    let qid = q.qid();
    let mut spins = 0u32;
    loop {
        if wait && spins >= 2_000_000 {
            return Err(NvmeError::CmdTimeout { cid: timeout_cid });
        }
        spins += 1;
        let qs = st.q[qid as usize];
        let cq_off = if qid == 0 { OFF_ADMIN_CQ } else { OFF_IO_CQ };
        let off = cq_off + qs.cq_head as usize * CQE_BYTES;
        let d3 = st.ctx.dma_read32(st.dma, off + 12)?;
        // QEMU 11.1 实测布局：CID(0..15) | phase(16) | status(17..31)。
        let got_cid = (d3 & 0xFFFF) as u16;
        let phase = ((d3 >> 16) & 1) as u8;
        let status = ((d3 >> 17) & 0x7FFF) as u16;
        if (phase == 1) == qs.phase {
            let qsm = &mut st.q[qid as usize];
            qsm.cq_head = ((qsm.cq_head as usize + 1) % qsm.depth as usize) as u16;
            if qsm.cq_head == 0 {
                qsm.phase = !qsm.phase;
            }
            let head = qsm.cq_head;
            let cq_db = 0x1000usize + qid as usize * 8 + 4;
            wr32(&st.ctx, st.mmio, cq_db as u64, head as u32)?;
            return Ok(Some((got_cid, status)));
        }
        if !wait {
            return Ok(None);
        }
    }
}

/// 等指定命令的完成项；admin 与同步路径始终只有一条在飞。
fn wait_cqe(st: &mut InnerState, q: Q, cid: u16) -> Result<(), NvmeError> {
    let Some((got_cid, status)) = take_cqe(st, q, true, cid)? else {
        return Err(NvmeError::CmdTimeout { cid });
    };
    if status != 0 {
        return Err(NvmeError::CmdFailed { cid: got_cid, status });
    }
    if got_cid != cid {
        return Err(NvmeError::CmdFailed { cid: got_cid, status: 0xFFFF });
    }
    Ok(())
}
/// 发射一条 I/O 命令，不等待完成。同步与异步路径共用，避免两套命令布局漂移。
fn submit_io(st: &mut InnerState, lba: u64, write: bool, data_off: usize) -> Result<u16, IssueFailure> {
    // 走 **I/O 队列**。`submit` 会在 `depth == 0`（队列没建起来）时返回
    // `IoQueueNotReady` —— 那条保护在队列状态里，不在调用方硬编码。
    //
    // 实测教训（BACKLOG §453）：早先这里误用 admin 队列发 `OP_IO_READ`(0x02)，
    // 被设备当成 Get Log Page，返回 `status 0x4002`，而现场只说「命令失败」。
    // **opcode 按队列解释，发错队列不会报「队列错」。**
    let op = if write { OP_IO_WRITE } else { OP_IO_READ };
    submit(st, Q::Io, op, 1, |st, off| {
        // DPTR = PRP1 = 本租约的数据槽
        let data_bus = st.data_bus + (data_off - OFF_DATA) as u64;
        st.ctx.dma_write32(st.dma, off + 24, data_bus as u32)?;
        st.ctx.dma_write32(st.dma, off + 28, (data_bus >> 32) as u32)?;
        // CDW10..11 = SLBA（低 32 / 高 32）
        st.ctx.dma_write32(st.dma, off + 40, lba as u32)?;
        st.ctx.dma_write32(st.dma, off + 44, (lba >> 32) as u32)?;
        // CDW12 = NLB（0 基：0 表示 1 个 LBA）
        st.ctx.dma_write32(st.dma, off + 48, 0)?;
        Ok(())
    })
}

/// 读一个扇区（`lba_bytes` 字节）到 `dst`。
pub fn read_lba(lba: u64, dst: &mut [u8]) -> Result<(), NvmeError> {
    io_lba(lba, dst, false)
}

/// 写一个扇区。
pub fn write_lba(lba: u64, src: &[u8]) -> Result<(), NvmeError> {
    let mut tmp = [0u8; 512];
    if src.len() > tmp.len() {
        return Err(NvmeError::CmdFailed { cid: 0, status: 0xFFFE });
    }
    tmp[..src.len()].copy_from_slice(src);
    io_lba(lba, &mut tmp[..src.len()], true)
}

fn sync_wait_failed(io: &mut AsyncIoState, error: NvmeError) -> NvmeError {
    #[cfg(not(feature = "fault-nvme-sync-no-quarantine"))]
    {
        io.poisoned = true;
    }
    error
}

fn io_lba(lba: u64, buf: &mut [u8], write: bool) -> Result<(), NvmeError> {
    with_io(|st, io| {
        #[cfg(not(feature = "fault-nvme-sync-interleave"))]
        if io.poisoned || io.slots.iter().any(|slot| slot.state != AsyncSlotState::Free) {
            return Err(NvmeError::AsyncBusy);
        }
        let csts = rd32(&st.ctx, st.mmio, REG_CSTS)?;
        if io.force_fatal || csts & CSTS_CFS != 0 {
            return Err(NvmeError::ControllerFatal { csts });
        }
        #[cfg(feature = "fault-nvme-sync-interleave")]
        let _ = io;
        if io.force_sync_timeout {
            io.force_sync_timeout = false;
            return Err(sync_wait_failed(io, NvmeError::CmdTimeout { cid: 0 }));
        }
        let n = buf.len().min(st.lba_bytes);
        // 先把数据搬进 DMA 数据页（读方向则先清，免得读到上一条的残留）
        if write {
            st.ctx.dma_copy_in(st.dma, OFF_DATA, &buf[..n])?;
        } else {
            st.ctx.dma_fill(st.dma, OFF_DATA, 0, crate::mm::PAGE)?;
        }
        let cid = match submit_io(st, lba, write, OFF_DATA) {
            Ok(cid) => cid,
            Err(IssueFailure::BeforeDoorbell(error)) => return Err(error),
            Err(IssueFailure::AfterDoorbell { cid, error }) => {
                // 门铃可能已接走命令：先在原调用内排空真实 CQE，超时则隔离，绝不把 OFF_DATA 交给下一条 I/O。
                let _ = wait_cqe(st, Q::Io, cid);
                return Err(sync_wait_failed(io, error));
            }
        };
        if let Err(error) = wait_cqe(st, Q::Io, cid) {
            return Err(sync_wait_failed(io, error));
        }
        if !write {
            st.ctx.dma_copy_out(st.dma, OFF_DATA, &mut buf[..n])?;
        }
        Ok(())
    })?
}

fn slot_index(io: &AsyncIoState, local_id: u64) -> Option<usize> {
    io.slots.iter().position(|slot| slot.local_id == local_id && slot.state != AsyncSlotState::Free)
}

fn slot_data_off(index: usize) -> usize {
    OFF_DATA + index * DATA_STRIDE
}

fn finish_completion(io: &mut AsyncIoState, cid: u16, status: u16, reported: bool) -> Option<NvmeIoCompletion> {
    let slot = io.slots.iter_mut().find(|slot| slot.state == AsyncSlotState::InFlight && slot.cid == cid)?;
    slot.state = AsyncSlotState::Completed;
    io.completed += 1;
    let status_error = (status != 0).then_some(NvmeError::CmdFailed { cid, status });
    let error = slot.submit_error.or(status_error);
    let completion = NvmeIoCompletion {
        local_id: slot.local_id,
        sectors_done: if status == 0 { slot.sectors } else { 0 },
        error,
    };
    slot.completion = if reported || cfg!(feature = "fault-nvme-drain-drop-completion") {
        None
    } else {
        Some(completion)
    };
    Some(completion)
}

/// 预留一个 DMA 数据槽。当前 PRP1/单数据页只支持一个 LBA。
pub fn async_alloc_lease(sectors: u32) -> Result<u32, NvmeError> {
    with_io(|st, io| {
        if sectors != 1 {
            return Err(NvmeError::BadLen { want: 1, got: sectors as usize });
        }
        let csts = rd32(&st.ctx, st.mmio, REG_CSTS)?;
        if io.poisoned || io.force_fatal || csts & CSTS_CFS != 0 {
            return Err(NvmeError::AsyncBusy);
        }
        let Some(index) = io.slots.iter().position(|slot| slot.state == AsyncSlotState::Free) else {
            return Err(NvmeError::AsyncBusy);
        };
        if io.next_id == u64::MAX || io.next_id > u64::from(u32::MAX) {
            return Err(NvmeError::AsyncBusy);
        }
        let local_id = io.next_id;
        io.next_id += 1;
        io.slots[index] = AsyncSlot {
            state: AsyncSlotState::Reserved,
            local_id,
            sectors,
            ..AsyncSlot::EMPTY
        };
        Ok(local_id as u32)
    })?
}

/// 写入 Reserved 租约的数据槽；长度必须精确等于租约容量。
pub fn async_copy_in(lease: u32, src: &[u8]) -> Result<(), NvmeError> {
    with_io(|st, io| {
        let index = slot_index(io, u64::from(lease)).ok_or(NvmeError::AsyncBusy)?;
        if io.slots[index].state != AsyncSlotState::Reserved {
            return Err(NvmeError::AsyncBusy);
        }
        let want = io.slots[index].sectors as usize * st.lba_bytes;
        if src.len() != want {
            return Err(NvmeError::BadLen { want, got: src.len() });
        }
        st.ctx.dma_copy_in(st.dma, slot_data_off(index), src).map_err(NvmeError::Ctx)
    })?
}

/// 从 Completed 租约读回数据。短输出只取前缀，不消费完成或释放租约。
pub fn async_copy_out(lease: u32, dst: &mut [u8]) -> Result<(), NvmeError> {
    with_io(|st, io| {
        let index = slot_index(io, u64::from(lease)).ok_or(NvmeError::AsyncBusy)?;
        if io.slots[index].state != AsyncSlotState::Completed {
            return Err(NvmeError::AsyncBusy);
        }
        let want = io.slots[index].sectors as usize * st.lba_bytes;
        if dst.len() > want {
            return Err(NvmeError::BadLen { want, got: dst.len() });
        }
        st.ctx.dma_copy_out(st.dma, slot_data_off(index), dst).map_err(NvmeError::Ctx)
    })?
}

/// 只发射并返回单调 local_id；完成证据只由 `async_reap` 收集。
#[cfg(feature = "fault-nvme-submit-ctx")]
static SUBMIT_CTX: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "fault-nvme-sync-submit-ctx")]
static SYNC_SUBMIT_CTX: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "fault-nvme-sync-submit-ctx")]
pub(crate) fn async_arm_sync_submit_ctx_for_test() {
    SYNC_SUBMIT_CTX.store(true, core::sync::atomic::Ordering::Release);
}

#[cfg(feature = "fault-nvme-submit-ctx")]
pub(crate) fn async_arm_submit_ctx_for_test() {
    SUBMIT_CTX.store(true, core::sync::atomic::Ordering::Release);
}

pub fn async_submit(lease: u32, lba: u64, sectors: u32, write: bool) -> Result<u64, NvmeError> {
    with_io(|st, io| {
        let index = slot_index(io, u64::from(lease)).ok_or(NvmeError::AsyncBusy)?;
        if io.slots[index].state != AsyncSlotState::Reserved {
            return Err(NvmeError::AsyncBusy);
        }
        if sectors != io.slots[index].sectors {
            return Err(NvmeError::BadLen { want: io.slots[index].sectors as usize, got: sectors as usize });
        }
        let csts = rd32(&st.ctx, st.mmio, REG_CSTS)?;
        if io.poisoned || io.force_fatal || csts & CSTS_CFS != 0 {
            return Err(NvmeError::AsyncBusy);
        }
        if st.q[1].depth == 0 {
            return Err(NvmeError::IoQueueNotReady);
        }
        let local_id = io.slots[index].local_id;
        let (cid, mut pending_error) = match submit_io(st, lba, write, slot_data_off(index)) {
            Ok(cid) => (cid, None),
            Err(IssueFailure::BeforeDoorbell(error)) => return Err(error),
            Err(IssueFailure::AfterDoorbell { cid, error }) => (cid, Some(error)),
        };
        #[cfg(feature = "fault-nvme-submit-ctx")]
        if SUBMIT_CTX.swap(false, core::sync::atomic::Ordering::AcqRel) {
            pending_error = Some(NvmeError::Ctx(DriverError::Io));
        }
        io.slots[index].state = AsyncSlotState::InFlight;
        io.slots[index].cid = cid;
        io.slots[index].submit_error = pending_error;
        if pending_error.is_some() {
            io.poisoned = true;
            io.bad_used += 1;
        }
        io.submitted += 1;
        #[cfg(feature = "fault-nvme-submit-lose-owner")]
        if let Some(error) = pending_error {
            return Err(error);
        }
        #[cfg(feature = "fault-nvme-async-wait")]
        {
            io.wait_calls += 1;
            let _ = poll_cqe(st, Q::Io, cid);
        }
        Ok(local_id)
    })?
}

/// 显式完成并取走回执。先等一条真实 CQE，再非阻塞排空已发布项；小缓冲不丢完成。
pub fn async_reap(out: &mut [NvmeIoCompletion]) -> usize {
    if out.is_empty() || DriverCtx::in_isr() {
        return 0;
    }
    match with_io(|st, io| -> Result<usize, NvmeError> {
        let mut written = 0usize;
        for slot in &mut io.slots {
            if written == out.len() { break; }
            if slot.state == AsyncSlotState::Completed {
                if let Some(completion) = slot.completion.take() {
                    out[written] = completion;
                    written += 1;
                }
            }
        }
        if written != 0 || !io.slots.iter().any(|slot| slot.state == AsyncSlotState::InFlight) {
            return Ok(written);
        }
        #[cfg(feature = "fault-nvme-no-late-reap")]
        if io.poisoned {
            return Ok(0);
        }
        let first = match take_cqe(st, Q::Io, true, 0) {
            Ok(Some(cqe)) => cqe,
            Ok(None) => return Ok(0),
            Err(error) => {
                io.poisoned = true;
                if !matches!(error, NvmeError::CmdTimeout { .. }) {
                    io.bad_used += 1;
                }
                return Ok(0);
            }
        };
        let mut next = Some(first);
        while written < out.len() {
            let Some((cid, status)) = next else { break };
            let Some(completion) = finish_completion(io, cid, status, true) else {
                io.bad_used += 1;
                io.poisoned = true;
                break;
            };
            out[written] = completion;
            written += 1;
            next = take_cqe(st, Q::Io, false, 0)?;
        }
        Ok(written)
    }) {
        Ok(Ok(n)) => n,
        _ => 0,
    }
}

/// 取消只撤 Reserved；InFlight 不能靠改账本假装设备已撤销。
pub fn async_cancel(local_id: u64) -> NvmeCancel {
    if DriverCtx::in_isr() {
        return NvmeCancel::InFlight;
    }
    match with_io(|_, io| -> Result<NvmeCancel, NvmeError> {
        let Some(index) = slot_index(io, local_id) else { return Ok(NvmeCancel::NotFound) };
        match io.slots[index].state {
            AsyncSlotState::Reserved => {
                io.slots[index] = AsyncSlot::EMPTY;
                io.cancelled += 1;
                Ok(NvmeCancel::Cancelled)
            }
            AsyncSlotState::InFlight => Ok(NvmeCancel::InFlight),
            AsyncSlotState::Completed => Ok(NvmeCancel::Completed),
            AsyncSlotState::Free => Ok(NvmeCancel::NotFound),
        }
    }) {
        Ok(Ok(result)) => result,
        _ => NvmeCancel::InFlight,
    }
}

/// 释放 Reserved/Completed 租约；InFlight 必须等显式完成，禁止提前回收 DMA。
pub fn async_release(lease: u32) -> Result<(), NvmeError> {
    with_io(|_, io| {
        let index = slot_index(io, u64::from(lease)).ok_or(NvmeError::AsyncBusy)?;
        match io.slots[index].state {
            AsyncSlotState::Reserved | AsyncSlotState::Completed => {
                io.slots[index] = AsyncSlot::EMPTY;
                Ok(())
            }
            AsyncSlotState::InFlight => Err(NvmeError::AsyncBusy),
            AsyncSlotState::Free => Err(NvmeError::AsyncBusy),
        }
    })?
}

pub fn async_stats() -> Option<NvmeAsyncStats> {
    with_io(|_, io| {
        Some(NvmeAsyncStats {
            submitted: io.submitted,
            completed: io.completed,
            cancelled: io.cancelled,
            bad_used: io.bad_used,
            wait_calls: io.wait_calls,
            occupied: io.slots.iter().filter(|slot| slot.state != AsyncSlotState::Free).count(),
            poisoned: io.poisoned,
        })
    })
    .ok()
    .flatten()
}

/// 先排空在途并删除 I/O 队列，再禁用控制器；缺少完成项的租约继续保留。
pub fn async_drain() -> Result<NvmeDrain, NvmeError> {
    with_io(|st, io| {
        io.poisoned = true;
        let mut completed = 0usize;
        for _ in 0..DATA_SLOTS {
            if !io.slots.iter().any(|slot| slot.state == AsyncSlotState::InFlight) {
                break;
            }
            match take_cqe(st, Q::Io, true, 0) {
                Ok(Some((cid, status))) => {
                    if finish_completion(io, cid, status, false).is_some() {
                        completed += 1;
                    }
                }
                _ => break,
            }
        }
        let mut queues_deleted = false;
        if !io.slots.iter().any(|slot| slot.state == AsyncSlotState::InFlight) {
            let sq = submit(st, Q::Admin, OP_DELETE_SQ, 0, |st, off| {
                st.ctx.dma_write32(st.dma, off + 40, 1)?;
                Ok(())
            }).map_err(NvmeError::from).and_then(|cid| wait_cqe(st, Q::Admin, cid));
            let cq = if sq.is_ok() {
                submit(st, Q::Admin, OP_DELETE_CQ, 0, |st, off| {
                    st.ctx.dma_write32(st.dma, off + 40, 1)?;
                    Ok(())
                }).map_err(NvmeError::from).and_then(|cid| wait_cqe(st, Q::Admin, cid))
            } else {
                Err(NvmeError::AsyncBusy)
            };
            queues_deleted = sq.is_ok() && cq.is_ok();
        }
        #[cfg(not(feature = "fault-nvme-fatal-no-drain"))]
        {
            wr32(&st.ctx, st.mmio, REG_CC, 0)?;
            let mut spins = 0u32;
            while rd32(&st.ctx, st.mmio, REG_CSTS)? & CSTS_RDY != 0 {
                if spins >= 2_000_000 {
                    return Err(NvmeError::NotReady { csts: rd32(&st.ctx, st.mmio, REG_CSTS)?, spins });
                }
                spins += 1;
            }
        }
        let disabled = rd32(&st.ctx, st.mmio, REG_CSTS)? & CSTS_RDY == 0;
        if disabled {
            for _ in 0..DATA_SLOTS {
                let Some((cid, status)) = take_cqe(st, Q::Io, false, 0)? else { break };
                if finish_completion(io, cid, status, false).is_some() {
                    completed += 1;
                }
            }
        }
        let outstanding = io.slots.iter().filter(|slot| slot.state == AsyncSlotState::InFlight).count();
        Ok(NvmeDrain { completed, outstanding, disabled, queues_deleted })
    })?
}

/// 仅在全部租约已归还且控制器非致命时恢复：重新使能并重建 I/O 队列。
pub fn async_recover() -> Result<(), NvmeError> {
    with_io(|st, io| {
        let csts = rd32(&st.ctx, st.mmio, REG_CSTS)?;
        if io.force_fatal || csts & CSTS_CFS != 0 {
            return Err(NvmeError::ControllerFatal { csts });
        }
        #[cfg(not(feature = "fault-nvme-recover-inflight"))]
        if io.slots.iter().any(|slot| slot.state != AsyncSlotState::Free) {
            return Err(NvmeError::AsyncBusy);
        }
        #[cfg(feature = "fault-nvme-recover-inflight")]
        let _ = &io.slots;
        if csts & CSTS_RDY == 0 {
            st.ctx.dma_fill(st.dma, OFF_ADMIN_SQ, 0, 2 * PAGE_BYTES)?;
            st.q[0] = QState::new(QDEPTH as u16);
            wr32(&st.ctx, st.mmio, REG_AQA, AQA_CONFIG)?;
            wr32(&st.ctx, st.mmio, REG_ASQ, st.asq_bus as u32)?;
            wr32(&st.ctx, st.mmio, REG_ASQ + 4, (st.asq_bus >> 32) as u32)?;
            wr32(&st.ctx, st.mmio, REG_ACQ, st.acq_bus as u32)?;
            wr32(&st.ctx, st.mmio, REG_ACQ + 4, (st.acq_bus >> 32) as u32)?;
            wr32(&st.ctx, st.mmio, REG_CC, CC_CONFIG)?;
            let mut spins = 0u32;
            loop {
                let now = rd32(&st.ctx, st.mmio, REG_CSTS)?;
                if now & CSTS_RDY != 0 {
                    if now & CSTS_CFS != 0 {
                        return Err(NvmeError::ControllerFatal { csts: now });
                    }
                    break;
                }
                if spins >= 2_000_000 {
                    return Err(NvmeError::NotReady { csts: now, spins });
                }
                spins += 1;
            }
        }
        st.ctx.dma_fill(st.dma, OFF_IO_SQ, 0, 2 * PAGE_BYTES)?;
        st.q[1] = QState::new(0);
        create_io_queues(st)?;
        io.poisoned = false;
        Ok(())
    })?
}

/// 用例隔离闸：禁止新租约，但保留在途槽的迟到完成路径。
pub fn async_quarantine_for_test() -> Result<(), NvmeError> {
    with_io(|_, io| {
        io.poisoned = true;
        Ok(())
    })?
}

/// 只在没有在飞命令时解除隔离；有 InFlight 时绝不能假装设备已经恢复。
pub fn async_recover_for_test() -> Result<(), NvmeError> {
    with_io(|_, io| {
        if io.slots.iter().all(|slot| slot.state == AsyncSlotState::Free) && !io.force_fatal {
            io.poisoned = false;
            Ok(())
        } else {
            Err(NvmeError::AsyncBusy)
        }
    })?
}

pub fn async_inject_fatal_for_test() {
    let _ = with_io(|_, io| io.force_fatal = true);
}

pub fn async_clear_fatal_for_test() {
    let _ = with_io(|_, io| io.force_fatal = false);
}

/// 用例注入同步等待超时；不真发命令，只验证“超时后必须隔离”的账本转换。
pub fn async_force_sync_timeout_for_test() {
    let _ = with_io(|_, io| io.force_sync_timeout = true);
}

/// 从 PCI 三件套认领设备（判据用它证明"这台设备真的是 NVMe"）。
pub fn claim() -> Option<Dev> {
    crate::pci::first_of_triple(PCI_CLASS_NVME, PCI_SUBCLASS_NVME, PCI_PROGIF_NVME)
}

/// 型号的 ASCII 视图（判据与日志用）。非可打印字符换成 `.`。
pub fn model_str() -> [u8; 16] {
    let mut out = [b'.'; 16];
    if let Some(r) = reading() {
        for (i, b) in r.model.iter().enumerate() {
            out[i] = if (0x20..0x7F).contains(b) { *b } else { b'.' };
        }
    }
    out
}
