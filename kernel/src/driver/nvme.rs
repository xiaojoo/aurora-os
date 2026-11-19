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
use crate::pci::Dev;
use crate::mm::ModuleId;

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

pub const OP_DELETE_SQ: u8 = 0x00;
pub const OP_CREATE_SQ: u8 = 0x01;
pub const OP_GET_LOG_PAGE: u8 = 0x02;
pub const OP_DELETE_CQ: u8 = 0x04;
pub const OP_CREATE_CQ: u8 = 0x05;
pub const OP_IDENTIFY: u8 = 0x06;
pub const OP_READ: u8 = 0x02;
pub const OP_WRITE: u8 = 0x01;

/// Identify 的 CNS：0 = Identify Namespace，1 = Identify Controller。
pub const CNS_NAMESPACE: u32 = 0x00;
pub const CNS_CONTROLLER: u32 = 0x01;

/// 一条提交命令定长 64 字节、一条完成定长 16 字节（NVMe 规范 §4）。
pub const SQE_BYTES: usize = 64;
pub const CQE_BYTES: usize = 16;

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
/// 总共要几页：4 个环 + 1 个数据页 = 5 页**内容**，但 `alloc_dma` 只接受
/// **2 的幂**的页数（它内部是 `(len / PAGE).ilog2()`，向下取整**静默截断**），
/// 所以取 8。
///
/// **实测教训**：第一版写 5，`(5).ilog2() = 2` ⇒ 实际只映了 4 页，
/// 而 `OFF_DATA = 16384` 在第 5 页 ⇒ 写数据页当场 `#PF err=0x2`。
/// 这个坑不报错、只截断，所以把契约写在这里。
pub const DMA_PAGES: usize = 8;

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
    /// 句柄表拒绝（映射/DMA/中断）
    Ctx(DriverError),
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
            NvmeError::Ctx(_) => "句柄表拒绝",
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
    /// Identify Controller 的 NN：设备有几个命名空间。
    ///
    /// 用它证「有命名空间」——而 NSZE（容量）来自 Identify Namespace，
    /// 那条在 QEMU 上可能因 NSID 不匹配而静默不产生完成项（实测）。
    pub namespaces: u32,
}

/// 设备的单例状态。NVMe 不像 virtio 有多台，先按单台做（表化留给需要时）。
struct Cell(core::cell::UnsafeCell<Option<State>>);
// SAFETY: 唯一的写入点是 `init()`，它只在启动期单核跑一次；之后只读。
unsafe impl Sync for Cell {}

struct State {
    ctx: DriverCtx,
    mmio: MmioHandle,
    dma: DmaHandle,
    /// 数据页的 bus 地址（PRP1 用）
    data_bus: u64,
    /// 管理队列的两个 bus 地址
    asq_bus: u64,
    acq_bus: u64,
    /// 提交/完成的游标（各队列共用一对，因为判据是串行的）
    sq_tail: u16,
    cq_head: u16,
    /// CQ 的 phase 位：**整圈翻转的奇偶**，不是每格独立的到达标志
    /// （与 virtio 的 `used.idx` 单调递增不同）。清零后第一圈是 `true`。
    cq_phase: bool,
    /// 下一条命令的 CID
    next_cid: u16,
    /// 读回的读数
    reading: Reading,
    /// 命名空间大小（LBA 数）
    nsze: u64,
    /// 每 LBA 字节数
    lba_bytes: usize,
}

static STATE: Cell = Cell(core::cell::UnsafeCell::new(None));

/// 当前读数（没初始化就是 `None`）。
pub fn reading() -> Option<Reading> {
    // SAFETY: 见 `Cell`——只读，写入只发生在 `init()`
    unsafe { (*STATE.0.get()).as_ref().map(|s| s.reading) }
}

/// 命名空间大小（LBA 数）。判据用它算容量。
pub fn nsze() -> Option<u64> {
    // SAFETY: 同上
    unsafe { (*STATE.0.get()).as_ref().map(|s| s.nsze) }
}

/// 每 LBA 字节数。
pub fn lba_bytes() -> Option<usize> {
    // SAFETY: 同上
    unsafe { (*STATE.0.get()).as_ref().map(|s| s.lba_bytes) }
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
    let aqa = ((QDEPTH as u32 - 1) & 0xFFF) | (((QDEPTH as u32 - 1) & 0xFFF) << 16);
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
    wr32(&ctx, mmio, REG_CC, CC_EN)?;
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

    let mut st = State {
        ctx,
        mmio,
        dma,
        data_bus,
        asq_bus,
        acq_bus,
        sq_tail: 0,
        cq_head: 0,
        cq_phase: true, // 清零后第一圈 phase 是 1
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
        },
        nsze: 0,
        lba_bytes: 512,
    };

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
    // NN（Number of Namespaces）在 Identify **Controller** 的偏移 516（4 字节小端）。
    // 用它证「有命名空间」——这条命令已验成功（cid=1 status=0）。
    // 诊断：型号区（24..40）应读成可打印 ASCII；NN 区（512..520）用来反推偏移。
    crate::log_info!(
        "nvme: idc 型号区={:02x?} nn区={:02x?} 前16={:02x?}",
        &ctrl[24..40], &ctrl[512..520], &ctrl[0..16]
    );
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

    let out = st.reading;
    // SAFETY: 见 `Cell`
    unsafe { *STATE.0.get() = Some(st) };
    Ok(out)
}

/// 发一条 Identify（CNS 选 Controller 或 Namespace），把 4096 字节读进 `out`。
fn identify(st: &mut State, cns: u32, nsid: u32, out: &mut [u8]) -> Result<(), NvmeError> {
    let cid = submit(st, OP_IDENTIFY, nsid, |st, off| {
        // DPTR = PRP1 = 数据页的 bus 地址（只一页，所以不需要 PRP2）
        st.ctx.dma_write32(st.dma, off + 24, st.data_bus as u32)?;
        st.ctx.dma_write32(st.dma, off + 28, (st.data_bus >> 32) as u32)?;
        // CDW10 = CNS
        st.ctx.dma_write32(st.dma, off + 40, cns)?;
        Ok(())
    })?;
    wait_cqe(st, cid)?;
    // 从数据页读回（Identify 的返回是 4096 字节）
    st.ctx.dma_copy_out(st.dma, OFF_IDENTIFY, &mut out[..IDENTIFY_BYTES])?;
    Ok(())
}

/// 提交一条命令：写 SQE，敲门铃。`fill` 负责写命令特有的那几个 DWORD。
fn submit(
    st: &mut State,
    opcode: u8,
    nsid: u32,
    fill: impl FnOnce(&mut State, usize) -> Result<(), NvmeError>,
) -> Result<u16, NvmeError> {
    let slot = st.sq_tail as usize;
    let off = OFF_ADMIN_SQ + slot * SQE_BYTES;
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

    st.sq_tail = ((st.sq_tail as usize + 1) % QDEPTH) as u16;
    // 敲门铃：管理队列的 SQ0 tail doorbell 在 0x1000
    wr32(&st.ctx, st.mmio, 0x1000, st.sq_tail as u32)?;
    Ok(cid)
}

/// 等一条命令的完成项。返回时已经把 CQ 的头推进过。
fn wait_cqe(st: &mut State, cid: u16) -> Result<(), NvmeError> {
    let mut spins = 0u32;
    loop {
        if spins >= 2_000_000 {
            return Err(NvmeError::CmdTimeout { cid });
        }
        spins += 1;
        let off = OFF_ADMIN_CQ + st.cq_head as usize * CQE_BYTES;
        // CQE 的 DW3：bit0 = phase，bit1..16 = status，bit16..32 = CID。
        //
        // **phase 是整圈翻转的奇偶**：只有「当前格的 phase == 本圈期望值」
        // 才说明设备写过了这一格。把它当成「每格置 1」时，第一圈过后
        // 第二条命令永远等不到（实测 cid=1 过、cid=2 超时）。
        // 这条与 virtio 的 `used.idx` 单调递增是**根本差别**。
        let dw3 = st.ctx.dma_read32(st.dma, off + 12)?;
        if (dw3 & 1 == 1) == st.cq_phase {
            let got_cid = (dw3 >> 16) as u16;
            let status = ((dw3 >> 1) & 0x7FFF) as u16;
            st.cq_head = ((st.cq_head as usize + 1) % QDEPTH) as u16;
            // 绕回 0 = 走满一圈 ⇒ phase 翻转
            if st.cq_head == 0 {
                st.cq_phase = !st.cq_phase;
            }
            // 推 CQ 门铃（0x1004），让设备知道这一格可以复用了
            wr32(&st.ctx, st.mmio, 0x1004, st.cq_head as u32)?;
            if status != 0 {
                return Err(NvmeError::CmdFailed { cid: got_cid, status });
            }
            // CID 对不上是「完成项串了」——比超时更严重，必须点名
            if got_cid != cid {
                return Err(NvmeError::CmdFailed { cid: got_cid, status: 0xFFFF });
            }
            return Ok(());
        }
    }
}
/// 读一个扇区（`lba_bytes` 字节）到 `dst`。
pub fn read_lba(lba: u64, dst: &mut [u8]) -> Result<(), NvmeError> {
    io_lba(lba, dst, false)
}

/// 写一个扇区。
pub fn write_lba(lba: u64, src: &[u8]) -> Result<(), NvmeError> {
    // SAFETY: 见 `Cell`——`io_lba` 需要 &mut State，而这里是唯一的入口
    let mut tmp = [0u8; 512];
    if src.len() > tmp.len() {
        return Err(NvmeError::CmdFailed { cid: 0, status: 0xFFFE });
    }
    tmp[..src.len()].copy_from_slice(src);
    io_lba(lba, &mut tmp[..src.len()], true)
}

fn io_lba(lba: u64, buf: &mut [u8], write: bool) -> Result<(), NvmeError> {
    // SAFETY: 单台设备、单线程调用（块层逐扇区串行）；`Cell` 的写入只发生在 init
    let st = unsafe { (*STATE.0.get()).as_mut() }.ok_or(NvmeError::NoDevice)?;
    let n = buf.len().min(st.lba_bytes);
    // 先把数据搬进 DMA 数据页（读方向则先清，免得读到上一条的残留）
    if write {
        st.ctx.dma_copy_in(st.dma, OFF_DATA, &buf[..n])?;
    } else {
        st.ctx.dma_fill(st.dma, OFF_DATA, 0, crate::mm::PAGE)?;
    }
    let op = if write { OP_WRITE } else { OP_READ };
    let cid = submit(st, op, 1, |st, off| {
        // DPTR = PRP1 = 数据页
        st.ctx.dma_write32(st.dma, off + 24, st.data_bus as u32)?;
        st.ctx.dma_write32(st.dma, off + 28, (st.data_bus >> 32) as u32)?;
        // CDW10..11 = SLBA（低 32 / 高 32）
        st.ctx.dma_write32(st.dma, off + 40, lba as u32)?;
        st.ctx.dma_write32(st.dma, off + 44, (lba >> 32) as u32)?;
        // CDW12 = NLB（0 基：0 表示 1 个 LBA）
        st.ctx.dma_write32(st.dma, off + 48, 0)?;
        Ok(())
    })?;
    wait_cqe(st, cid)?;
    if !write {
        st.ctx.dma_copy_out(st.dma, OFF_DATA, &mut buf[..n])?;
    }
    Ok(())
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
