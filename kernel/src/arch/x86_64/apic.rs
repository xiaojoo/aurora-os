//! 本地 APIC + I/O APIC + PIT（M3a-1：让真实硬件中断能进来并且还能再来）。
//!
//! 三条不是可选项的规则，本文件的形状就是被它们决定的：
//!
//! 1. **寄存器窗口必须不可缓存**。协议固定的 PAT 表里 `PAT2 = UC-`，所以设备页只要
//!    PCD=1 就落到 UC-（见 `mm::PageFlags::DEVICE`）。缓存了的 LAPIC/IO-APIC 寄存器
//!    读出来是旧值、写会被合并，表现是"中断偶发丢失"这种最难归因的故障。
//! 2. **EOI 的规则按向量分两类**。普通中断（32..47 与 48..254）处理完必须写 EOI，
//!    否则 ISR 位一直挂着，同优先级及更低优先级的中断再也进不来——第一次 tick 之后
//!    就安静了，看起来像"定时器只走了一次"。而 **spurious（0xFF）不能发 EOI**：
//!    它没有对应的 ISR 位，发了就等于多确认了一个并不存在的服务中端。
//! 3. **交接状态是协议规定的，不是我们假设的**（base revision ≥ 5）：本地 APIC 已硬件
//!    使能（`IA32_APIC_BASE` bit11）且软件使能（SVR bit8），SVR = `0x1FF`，TPR = 0，
//!    所有 LVT（含 Timer）被屏蔽；传统 PIC 全部 IRQ 已屏蔽；I/O APIC 里 Fixed /
//!    Lowest Priority 的条目已屏蔽（NMI/ExtINT 在 rev≥5 也被屏蔽），其余按固件设置。
//!    本文件把这些当"可核对的前提"，全部**读回来打进日志**，不当既成事实。

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::acpi::Madt;
use crate::mm::{self, ModuleId};

pub const MOD_APIC: ModuleId = ModuleId(11);

/// xAPIC 寄存器偏移（Intel SDM Vol.3A 表 11-2；MMIO 窗口内偏移，均为 32 位访问）
const LAPIC_ID: u64 = 0x0020;
const LAPIC_VER: u64 = 0x0030;
const LAPIC_EOI: u64 = 0x00b0;
const LAPIC_SVR: u64 = 0x00f0;
/// I/O APIC 的两个 32 位端口：选择寄存器 + 窗口
const IOREGSEL: u64 = 0x0000;
const IOWIN: u64 = 0x0010;
/// 重定向表第 n 条的低/高 32 位分别在选择索引 0x10 + 2n / 2n+1
const IORTE_BASE: u64 = 0x0010;

pub const PIT_CH0_DATA: u16 = 0x40;
pub const PIT_CMD: u16 = 0x43;
/// 打一个**窗口游标**：给 PIT 通道 0 下 latch 命令（`0x43 <- 0x00`），再把锁下来的计数读走。
///
/// 为什么要有它：QEMU 的 simple trace 后端不打时间戳，宿主机只能按顺序读事件，于是
/// "这一发投递落在哪个窗口里"原本读不出来（实测：全跑的 `vector 32` 投递 101 发对内核
/// 累计 101 完全吻合，但落不到 `t_timer_ticks_recur` 那一段上）。latch 在 trace 里的形状是
/// `pit_ioport_write [0x3] <- 0x00`，与我们平时下的 `0x34`/`0x30` 不同值，所以它就是边界；
/// 读回来的计数另外给出这一时刻在 10 ms 周期里的相位。
///
/// 为什么不用 RTC 的用户 RAM（0x70/0x71）当游标：实测这台 OVMF/QEMU 上它走不到 RTC 设备——
/// 写进去读回来不等，且 trace 里 `mc146818rzy_*` 一条都不产出。
///
/// 返回 `None` 表示锁下来的计数不在 `[1, PIT_DIVISOR]` 里：那说明这台设备的通道 0 不是
/// 我们以为的那个 100 Hz 速率发生器，游标本身不可信，调用方必须把这件事打出来而不是默默用。
pub fn pit_mark() -> Option<u16> {
    crate::serial::out8(PIT_CMD, 0x00); // SC=00 RL=00(锁存) M=000 BCD=0：只锁存，不改模式
    let lo = u16::from(crate::serial::in8(PIT_CH0_DATA));
    let hi = u16::from(crate::serial::in8(PIT_CH0_DATA));
    let v = lo | (hi << 8);
    if v >= 1 && u64::from(v) <= crate::clock::PIT_DIVISOR {
        Some(v)
    } else {
        None
    }
}

/// ISA IRQ0 由 PIT **通道 0** 的 OUT0 驱动（标准 PC 与 q35 都是这样；通道 2 接的是喇叭门）。
/// 一开始这里写成通道 2，中断永远不会来——那是只有实测才能纠正的错。
pub const TIMER_ISA_IRQ: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApicError {
    /// MADT 没给出可用的 LAPIC 基址
    NoLapic,
    /// MADT 里没有一个 GSI 起点覆盖目标中断的 I/O APIC
    NoIoApicForGsi,
    /// 映射设备页失败（VA 保留用尽或表项冲突）
    MapFailed,
}

/// 交接时读回来的事实，全部进日志。
#[derive(Debug, Clone, Copy)]
pub struct State {
    pub lapic_va: u64,
    pub lapic_phys: u64,
    pub id: u32,
    pub version: u32,
    pub max_lvt: u32,
    pub svr: u32,
    /// 我们进来时 SVR 的使能位（bit8）已经是 1 吗——协议说 rev≥5 应该已经是
    pub svr_was_enabled: bool,
    pub ioapic_va: u64,
    pub ioapic_phys: u64,
    pub ioapic_id: u8,
    pub gsi_base: u32,
    /// 重定向表条目数 = 读回的最大索引 + 1
    pub irt_entries: u32,
    /// 我们分配到的定时器向量与 RTE 索引
    pub timer_vector: usize,
    pub timer_gsi: u32,
    pub timer_rte: u8,
}

static STATE: AtomicU64 = AtomicU64::new(0); // 0 = 未初始化，只当存在性哨兵
static LAPIC_VA: AtomicU64 = AtomicU64::new(0);
static IOAPIC_VA: AtomicU64 = AtomicU64::new(0);

/// 中断计数：按 IRQ 下标（0..16）分开，`TICKS` 是定时器那一路的别名计数。
static IRQ_COUNTS: [AtomicUsize; 16] = [const { AtomicUsize::new(0) }; 16];
static UNEXPECTED: AtomicUsize = AtomicUsize::new(0);
static SPURIOUS: AtomicUsize = AtomicUsize::new(0);
static EOIS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy)]
pub struct Counts {
    pub irq: [usize; 16],
    pub unexpected: usize,
    pub spurious: usize,
    pub eois: usize,
}

pub fn counts() -> Counts {
    let mut irq = [0usize; 16];
    for (i, c) in IRQ_COUNTS.iter().enumerate() {
        irq[i] = c.load(Ordering::Relaxed);
    }
    Counts { irq, unexpected: UNEXPECTED.load(Ordering::Relaxed), spurious: SPURIOUS.load(Ordering::Relaxed), eois: EOIS.load(Ordering::Relaxed) }
}

/// 相邻两次 tick 之间的 TSC 差（采样用）。0 表示还不够样本。
static TICK_TSC_PREV: AtomicU64 = AtomicU64::new(0);
static TICK_TSC_DELTA: AtomicU64 = AtomicU64::new(0);
static TICK_TSC_MAX_DELTA: AtomicU64 = AtomicU64::new(0);
/// 同一个窗口里**相邻间隔的和与个数**。有了它才能把"窗口均值"和"真间隔"分开口算：
/// 窗口两端各切掉一段不完整的间隔，所以 `总 cycles ÷ tick 数` 一定**偏高**，
/// 偏高量最多 `2 × 最大间隔 ÷ tick 数`。这条以前只能嘴上说说，现在能判。
static TICK_TSC_SUM: AtomicU64 = AtomicU64::new(0);
static TICK_TSC_N: AtomicU64 = AtomicU64::new(0);
static TICK_TSC_LAST: AtomicU64 = AtomicU64::new(0);

pub fn tick_delta_cycles() -> u64 {
    TICK_TSC_DELTA.load(Ordering::Relaxed)
}

/// 观察到的**最大**相邻 tick 间隔。用它证明窗口里没有漏 tick：
/// 漏一个就会让最大值跳到均值的两倍以上，那频率就是假的。
/// 但它**不能**代替从干净窗口起算（见 `reset_tick_stats`）：第一次标定的 4.78 GHz
/// 来自跨窗口的陈旧时间戳，那种读数看着完全正常——只有同窗口采样加均值/最大值一致性
/// 两个条件一起才拦得住。
pub fn tick_delta_max_cycles() -> u64 {
    TICK_TSC_MAX_DELTA.load(Ordering::Relaxed)
}

/// 窗口内所有**相邻间隔**的和与个数（`n=0` 表示还不够样本）。
pub fn tick_delta_sum() -> (u64, u64) {
    (TICK_TSC_SUM.load(Ordering::Relaxed), TICK_TSC_N.load(Ordering::Relaxed))
}

/// 清掉间隔统计并把当前 tick 数交回去，供"从一个干净窗口起算"的调用方使用。
pub fn reset_tick_stats() -> usize {
    TICK_TSC_LAST.store(0, Ordering::Relaxed);
    TICK_TSC_DELTA.store(0, Ordering::Relaxed);
    TICK_TSC_MAX_DELTA.store(0, Ordering::Relaxed);
    TICK_TSC_SUM.store(0, Ordering::Relaxed);
    TICK_TSC_N.store(0, Ordering::Relaxed);
    ticks()
}

/// LAPIC 窗口是否已经映射。per-CPU 数组的下标要靠它区分"早期只有 BSP"与"真的多核了"。
pub fn is_lapic_mapped() -> bool {
    LAPIC_VA.load(Ordering::Relaxed) != 0
}

pub fn ticks() -> usize {
    IRQ_COUNTS[TIMER_ISA_IRQ as usize].load(Ordering::Relaxed)
}

/// 有界自轮询等 PIT tick 的一组读数。
#[derive(Debug, Clone, Copy)]
pub struct TickWait {
    /// 窗口内实际数到的 tick
    pub ticks: u64,
    /// 窗口实际跨过的 cycles
    pub cycles: u64,
    /// 转了多少轮（只用于报告，不参与判定）
    pub rounds: u64,
}

/// 在开中断的窗口里等 `want` 次 tick，最多给 `deadline_cycles`。
///
/// **上界必须是 cycles，不能是轮数**：一轮值多少 cycles 是宿主机的函数，而 tick 是墙钟的
/// 函数。KVM 对照档实测（同一颗 QEMU 10.2.1 只换 `-accel`）：同样 4000 轮 `spin(50_000)`，
/// tcg 档走 208,349,505 cycles 数到 6 个 tick，kvm 档只走 101,191,740 cycles 数到 4 个——
/// 按轮数给的窗口在快档上会先耗尽轮数，样本数就压在判据的门槛上（第一次调用只有 3 个 ⇒
/// `NoSamples`，同一个窗口第二次却有 4 个 ⇒ 结果取决于窗口起点落在 tick 相位的哪一侧，
/// 这是判据本身的缺陷，不是机器的）。窗口长度改由 `clock::window_cycles()` 按 TSC 区间的
/// 最坏端点推出来，两边共用同一个数。
///
/// `base` 必须是调用方在自己窗口开始之前取的 `ticks()`：它是全局累计值，
/// 拿绝对数当门槛会重演"一次都没等"那次（见 `t_timer_ticks_recur`）。
pub fn wait_ticks(base: usize, want: u64, deadline_cycles: u64) -> TickWait {
    with_interrupts(|| {
        let start = crate::tsc::now();
        let mut rounds = 0u64;
        let mut got = (ticks() - base) as u64;
        let mut spent = 0u64;
        while got < want && spent < deadline_cycles {
            crate::tsc::spin(50_000);
            rounds += 1;
            got = (ticks() - base) as u64;
            spent = crate::tsc::now().wrapping_sub(start);
        }
        TickWait { ticks: got, cycles: spent, rounds }
    })
}

/// 等**第一个** tick，最多烧 `cycles` 个计数；不碰中断状态（调用方自己决定开还是关）。
///
/// 这条长度本身就是"IF=0 期间计数必须不动"判据的一部分：比一个 tick 周期还短的空白窗口，
/// 就算 IF 其实是开的也来不及漏一个 tick 进来，判据就变成空转——原先那里写的是
/// "20 轮 × spin(200_000)"，本机 tcg 档实测只跨约 4M cycles，而 tick 周期是 34.7M。
/// 反过来，IF 真关着时它必然跑满 `cycles` 才出来，所以报出来的 cycles 也是读数。
pub fn wait_tick_count(cycles: u64) -> TickWait {
    let base = ticks();
    let start = crate::tsc::now();
    let mut rounds = 0u64;
    let mut got = (ticks() - base) as u64;
    let mut spent = 0u64;
    while got == 0 && spent < cycles {
        crate::tsc::spin(50_000);
        rounds += 1;
        got = (ticks() - base) as u64;
        spent = crate::tsc::now().wrapping_sub(start);
    }
    TickWait { ticks: got, cycles: spent, rounds }
}

/// 每个 CPU 的**本地**定时器 tick 数（向量 `trap::VEC_CPU_TIMER`）。
/// 它与 `ticks()`（BSP 经 I/O APIC 收到的 PIT tick）是两条独立来源，不能混着数：
/// 混了之后 `t_timer_ticks_recur` 那台"两台仪器必须数到同一个数"的仪器就会当场对不上。
static CPU_TICKS: [AtomicUsize; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicUsize::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];

pub fn cpu_ticks(slot: usize) -> usize {
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS {
        return 0;
    }
    CPU_TICKS[slot].load(Ordering::Relaxed)
}

/// 所有 CPU 的本地 tick 快照，供日志一行打完。
pub fn cpu_ticks_all() -> [usize; crate::arch::x86_64::cpu::MAX_CPUS] {
    let mut out = [0usize; crate::arch::x86_64::cpu::MAX_CPUS];
    for (i, v) in out.iter_mut().enumerate() {
        *v = cpu_ticks(i);
    }
    out
}

pub fn is_initialized() -> bool {
    STATE.load(Ordering::Acquire) != 0
}

pub fn state() -> Option<State> {
    if is_initialized() {
        // SAFETY: 见 StateCell——init 只在启动期单核跑一次，之后本函数只读
        unsafe { *STATE_COPY.0.get() }
    } else {
        None
    }
}

struct StateCell(core::cell::UnsafeCell<Option<State>>);
// SAFETY: 单核 + IF=0 的启动阶段写入一次，之后只读（与 mm::State 同一条前提）
unsafe impl Sync for StateCell {}
static STATE_COPY: StateCell = StateCell(core::cell::UnsafeCell::new(None));

#[inline]
fn mmio_read32(base: u64, off: u64) -> u32 {
    // SAFETY: base 来自 mm::map_device 的返回值，页已映射且标成 UC-；
    // off 全是本模块的 4 字节对齐常量，跨度不超过一个 32 位访问。
    unsafe { core::ptr::read_volatile((base + off) as *const u32) }
}

#[inline]
fn mmio_write32(base: u64, off: u64, v: u32) {
    // SAFETY: 同上，写也是 4 字节对齐的单次访问
    unsafe { core::ptr::write_volatile((base + off) as *mut u32, v) };
}

#[inline]
fn ioapic_read(base: u64, reg: u32) -> u32 {
    mmio_write32(base, IOREGSEL, reg);
    mmio_read32(base, IOWIN)
}

#[inline]
fn ioapic_write(base: u64, reg: u32, v: u32) {
    mmio_write32(base, IOREGSEL, reg);
    mmio_write32(base, IOWIN, v);
}

/// 初始化：映射 LAPIC 与覆盖目标 GSI 的那个 I/O APIC，读回交接状态，并把定时器
/// 那条 RTE 配好（**先屏蔽着配，配完再放开**，避免半程状态触发一次意外中断）。
/// 已初始化就返回同一份状态。
///
/// 用例之间不能假设"谁先跑"（ktest 的枚举顺序由 `.ktests` 段的链接顺序决定，不由
/// 源码顺序决定），所以两个用例都可能第一个到。重复 `init` 会多占一个设备页 VA、
/// 并把 RTE 重写一遍，因此这里给一个明确的复用入口。
pub fn get_or_init(m: &Madt) -> Result<State, ApicError> {
    if let Some(s) = state() {
        return Ok(s);
    }
    init(m)
}

pub fn init(m: &Madt) -> Result<State, ApicError> {
    let lapic_phys = m.lapic_base;
    if lapic_phys == 0 || lapic_phys & 0xfff != 0 {
        return Err(ApicError::NoLapic);
    }
    // 设备页是固定物理地址，不走 phys_alloc；映射之后长期有效（frames:None 的
    // Mapping 丢弃时不解映射，见 mm::map_device 的注释），所以这里交出所有权。
    let lm = mm::map_device(lapic_phys, 1).map_err(|_| ApicError::MapFailed)?;
    let lapic_va = lm.virt().0;
    core::mem::forget(lm);
    LAPIC_VA.store(lapic_va, Ordering::Relaxed);

    let svr_before = mmio_read32(lapic_va, LAPIC_SVR);
    let svr_was_enabled = svr_before & (1 << 8) != 0;
    if !svr_was_enabled || (svr_before & 0xff) != 0xff {
        // 协议说 rev≥5 应该是 0x1FF。不是的话我们**自己**置成同样状态并记录：
        // 静默假设"bootloader 一定做了"会让后面每条中断结论都失去依据。
        mmio_write32(lapic_va, LAPIC_SVR, 0x1ff);
    }
    let ver = mmio_read32(lapic_va, LAPIC_VER);
    let id = mmio_read32(lapic_va, LAPIC_ID) >> 24;
    // 把 BSP 的槽位登记在**硬件读回的 id** 上，而不是 MP 响应里的 bsp_lapic_id：
    // 两者应当一致，而那正是 `t_cpu_ids_agree` 要证的（用其中一个去填另一个就是循环论证）。
    crate::arch::x86_64::cpu::init_bsp(id);

    // 定时器走哪条线：ISA IRQ0 -> GSI -> (哪个 IOAPIC, 第几条 RTE)
    let gsi = crate::acpi::gsi_for(m, TIMER_ISA_IRQ);
    let (which, rte) = crate::acpi::ioapic_for(m, gsi).ok_or(ApicError::NoIoApicForGsi)?;
    let io = m.ioapic[which];
    if io.addr == 0 || io.addr & 0xfff != 0 {
        return Err(ApicError::NoIoApicForGsi);
    }
    let im = mm::map_device(io.addr, 1).map_err(|_| ApicError::MapFailed)?;
    let ioapic_va = im.virt().0;
    core::mem::forget(im);
    IOAPIC_VA.store(ioapic_va, Ordering::Relaxed);

    let max_entry = ioapic_read(ioapic_va, 0x01) >> 16;
    let irt_entries = max_entry + 1;
    if rte as u32 >= irt_entries {
        // MADT 说这个 GSI 属于本 APIC，但表里没有那一条：固件/表不自洽，
        // 绝不能"就近写别的一条"，直接报错。
        crate::log_fatal!("apic: GSI {} -> RTE {} 超出 I/O APIC {} 的 {} 条表项", gsi, rte, io.id, irt_entries);
        return Err(ApicError::NoIoApicForGsi);
    }
    let vector = crate::arch::x86_64::trap::VEC_IRQ_BASE + TIMER_ISA_IRQ as usize;

    // 两段式写：先带屏蔽位写低半（向量/模式），再写高半（目标），最后清屏蔽
    let low_masked: u32 = (vector as u32 & 0xff) | (1 << 16);
    ioapic_write(ioapic_va, (IORTE_BASE + 2 * rte as u64) as u32, low_masked);
    ioapic_write(ioapic_va, (IORTE_BASE + 2 * rte as u64 + 1) as u32, 0); // 目的字段：xAPIC 下 31:24 = 0 = BSP
    ioapic_write(ioapic_va, (IORTE_BASE + 2 * rte as u64) as u32, vector as u32 & 0xff);

    let s = State {
        lapic_va,
        lapic_phys,
        id,
        version: ver & 0xff,
        max_lvt: (ver >> 16) & 0xff,
        svr: mmio_read32(lapic_va, LAPIC_SVR),
        svr_was_enabled,
        ioapic_va,
        ioapic_phys: io.addr,
        ioapic_id: io.id,
        gsi_base: io.gsi_base,
        irt_entries,
        timer_vector: vector,
        timer_gsi: gsi,
        timer_rte: rte,
    };
    // SAFETY: 见 STATE_COPY
    unsafe { *STATE_COPY.0.get() = Some(s) };
    STATE.store(1, Ordering::Release);
    Ok(s)
}

/// 把 PIT 通道 2 设成模式 2（速率发生器），按 1.193182 MHz 分频到约 100 Hz。
/// 分频 11932 -> 99.998 Hz。这里**不声称拿到了 100.000 Hz**：真实频率要等 M3a 的
/// 时钟源标定（本机 invariant TSC 为 false，不能拿 TSC 当尺子反推）。
pub fn pit_start_100hz() {
    crate::serial::out8(PIT_CMD, 0x34); // SC=00(通道 0) RL=11(先低后高) M=010(模式 2 速率发生器) BCD=0
    crate::serial::out8(PIT_CH0_DATA, 0x9c);
    crate::serial::out8(PIT_CH0_DATA, 0x2e);
}

/// 关掉 PIT 的输出：把通道 2 停在计数状态，避免测试窗口之外还持续进中断。
pub fn pit_stop() {
    // 先把该 IRQ 的 RTE 屏蔽，再动 PIT：只停 PIT 的话，窗口里已经排队的电平信号仍可能再进一次
    crate::serial::out8(PIT_CMD, 0x30); // SC=00 RL=11 M=000(模式 0 中断一次) 写满计数值
    crate::serial::out8(PIT_CH0_DATA, 0xff);
    crate::serial::out8(PIT_CH0_DATA, 0xff);
}

/// 打开定时器中断：先配 PIT，**最后**才放开 RTE。
/// 顺序是有意的：先放开再配 PIT，中间可能吃到一次固件遗留的电平沿。
pub fn timer_start() -> Result<(), ApicError> {
    let s = state().ok_or(ApicError::NoLapic)?;
    pit_start_100hz();
    ioapic_mask(s.timer_rte, false);
    Ok(())
}

/// 关掉定时器中断：先屏蔽 RTE，再停 PIT。
/// 反过来就会留下一个"已经拉高但没人屏蔽"的线——PIT 在模式 0 下还会再拉一次，
/// 那次会落在测试窗口之外，把下一个用例的计数起点弄脏。
/// （实测踩过：两个用例各自 mask 却谁都不 unmask，于是后跑的那个永远收不到 tick。）
pub fn timer_stop() -> Result<(), ApicError> {
    let s = state().ok_or(ApicError::NoLapic)?;
    ioapic_mask(s.timer_rte, true);
    pit_stop();
    Ok(())
}

/// 屏蔽/放开一条 RTE。关定时器窗口时用屏蔽而不是"留着不动"，
/// 因为 PIT 在模式 0 下最后还会再拉一次线。
pub fn ioapic_mask(rte: u8, masked: bool) {
    let base = IOAPIC_VA.load(Ordering::Relaxed);
    if base == 0 {
        return;
    }
    let lo = ioapic_read(base, (IORTE_BASE + 2 * rte as u64) as u32);
    let new = if masked { lo | (1 << 16) } else { lo & !(1 << 16) };
    ioapic_write(base, (IORTE_BASE + 2 * rte as u64) as u32, new);
}

/// 读一条 RTE 的两个原始 DWORD。**只有读**，M5-g① 取证与 M5-g② 的"写下去读得回来"都用它。
/// 界检查在核内做（`irt_entries` 是 MADT + `0x01` 两处读数里的那个），越界回 `None`
/// 而不是"就近读别的一条"——那条规矩在 `init` 里已经立过一次（GSI 映射不自洽时宁可报错）。
pub fn rte_raw(rte: u8) -> Option<(u32, u32)> {
    let base = IOAPIC_VA.load(Ordering::Relaxed);
    if base == 0 {
        return None;
    }
    let entries = state()?.irt_entries;
    if u32::from(rte) >= entries {
        return None;
    }
    let reg = (IORTE_BASE + 2 * u64::from(rte)) as u32;
    Some((ioapic_read(base, reg), ioapic_read(base, reg + 1)))
}

static ISR_DEPTH: [AtomicUsize; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicUsize::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];
/// 中断上下文里发生过的"分配尝试"次数。§6.5/§7.1 一直只有约定（"中断里禁止堆分配"），
/// 没有机制就等于没有：这里把它变成可数的违规，正常构建必须是 0，
/// 而 `fault-alloc-in-irq` 构建专门用来证明这个检测器**不是摆设**。
static IRQ_ALLOC_TRIES: AtomicUsize = AtomicUsize::new(0);

/// 本 CPU 的 LAPIC id（每次直接读寄存器，不缓存）。
///
/// 读寄存器而不是读 init 时存的那份，是因为 `sync::cpu_token` 在锁路径上用它判自死锁：
/// 缓存值一旦与实际不符就会漏判，而读一次 MMIO 是 30 周期量级、本来就在关中断的窗口里。
/// APIC 尚未映射（启动早期）时返回 0 —— 那条路径只有 BSP 会走，返回 0 是对的。
pub fn self_id() -> u64 {
    let lapic = LAPIC_VA.load(Ordering::Relaxed);
    if lapic == 0 {
        return 0;
    }
    (mmio_read32(lapic, LAPIC_ID) >> 24) as u64
}

pub fn in_isr() -> bool {
    ISR_DEPTH[crate::arch::x86_64::cpu::self_slot()].load(Ordering::Relaxed) > 0
}

/// 本 CPU 的 ISR 嵌套深度（用例用它验证"每个 CPU 各数各的"）。
pub fn isr_depth(slot: usize) -> usize {
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS {
        return 0;
    }
    ISR_DEPTH[slot].load(Ordering::Relaxed)
}

pub fn irq_alloc_tries() -> usize {
    IRQ_ALLOC_TRIES.load(Ordering::Relaxed)
}

/// 由 `heap::try_alloc` 在入口调用。只加计数——本函数**不许**打印或分配。
pub fn note_alloc_in_isr() {
    IRQ_ALLOC_TRIES.fetch_add(1, Ordering::Relaxed);
}

pub const PIC_MASTER_IMR: u16 = 0x21;
pub const PIC_SLAVE_IMR: u16 = 0xA1;

/// 读两块 8259 的 IMR。协议说交接时传统 PIC 全部 IRQ 已屏蔽——
/// 那是**继承来的状态**，不读回来就写进依据里等于引用文档当实测。
/// 返回 (master, slave)，完整屏蔽应当是 (0xff, 0xff)。
pub fn pic_imr() -> (u8, u8) {
    (crate::serial::in8(PIC_MASTER_IMR), crate::serial::in8(PIC_SLAVE_IMR))
}

/// 异常桩对每个外部中断的唯一入口。
///
/// 纪律：这里**不许**堆分配、不许打印（串口按字节忙等，会把中断窗口拖长几十微秒），
/// 只做计数和一次 EOI。日志留给被中断的线程自己读 `counts()`。
pub fn on_interrupt(vector: usize) {
    if vector == crate::arch::x86_64::trap::VEC_SPURIOUS {
        SPURIOUS.fetch_add(1, Ordering::Relaxed);
        return; // spurious 没有 ISR 位，按规范不发 EOI
    }
    // 深度自增：此刻起 in_isr() 为真，任何分配尝试都会被记成违规。
    // **按 CPU 分开数**：全局一份深度会让 AP 正在服务中断时把 BSP 也标成"在中断里"，
    // 于是 BSP 的正常分配被拒（L3），现场是一个说不清来源的失败。
    let slot = crate::arch::x86_64::cpu::self_slot();
    ISR_DEPTH[slot].fetch_add(1, Ordering::Relaxed);
    if (crate::arch::x86_64::trap::VEC_IRQ_BASE..=crate::arch::x86_64::trap::VEC_IRQ_LAST).contains(&vector) {
        let i = vector - crate::arch::x86_64::trap::VEC_IRQ_BASE;
        IRQ_COUNTS[i].fetch_add(1, Ordering::Relaxed);
        // 时钟标定用的两次相邻 tick 的间隔。读 TSC 在 EOI **之前**做：
        // 我们要的是"中断到达的节奏"，不是"处理完的节奏"。
        if i == TIMER_ISA_IRQ as usize {
            // 抢占的唯一触发源（BSP 这一侧）。这里只置标志 + 两次原子加，不拿锁、不打印、不分配。
            crate::sched::mark_tick();
            let now = crate::tsc::now();
            let prev = TICK_TSC_LAST.swap(now, Ordering::Relaxed);
            if prev != 0 {
                TICK_TSC_PREV.store(prev, Ordering::Relaxed);
                TICK_TSC_DELTA.store(now - prev, Ordering::Relaxed);
                TICK_TSC_MAX_DELTA.fetch_max(now - prev, Ordering::Relaxed);
                TICK_TSC_SUM.fetch_add(now - prev, Ordering::Relaxed);
                TICK_TSC_N.fetch_add(1, Ordering::Relaxed);
            }
        }
        // 负样本：在中断上下文里真的走一次全局分配器。检测器必须抓到，
        // 抓不到就说明 §6.5 那条禁令只存在于注释里。
        #[cfg(feature = "fault-alloc-in-irq")]
        {
            let mut v: ::alloc::vec::Vec<u8> = ::alloc::vec::Vec::with_capacity(32);
            v.push(1);
            core::mem::forget(v);
        }
        // M5-g②：设备中断的落点。**必须在 EOI 之前**：电平触发的线上，先服务设备才能让线落回去；
        // 顺序反过来就变成"EOI 已经发出去、线还高着"，那一发之后要么不再来（丢中断），
        // 要么立刻重复来（风暴）。这一格今天的凭据不是规范，是 `KT_IRQ_AHCI` 的计数。
        // 定时器那一格（`0x20`）不进认领表：它的主人就是这个函数自己。
        if crate::irq::in_range(vector) {
            crate::irq::dispatch(vector);
        }
    } else if vector == crate::arch::x86_64::trap::VEC_CPU_TIMER {
        // 每个 CPU 的本地定时器（M3b-2b 起它走异常帧，所以会进到这儿来）。
        // 三件事要注意：
        // * **不占** `IRQ_COUNTS` 那 16 格——那 16 格是 I/O APIC 的 16 条线，
        //   把它算进去会让"两台仪器数到同一个数"那条对照变成假的一致（P5 侧记了样本，
        //   而这台仪器不记，或者反过来）。
        // * 也不算 `unexpected`：它是设计内的中断。
        // * `mark_tick()` 置的是**本 CPU** 的重调度标志，各条队列各排各的人。
        CPU_TICKS[slot].fetch_add(1, Ordering::Relaxed);
        crate::sched::mark_tick();
    } else {
        UNEXPECTED.fetch_add(1, Ordering::Relaxed);
    }
    let lapic = LAPIC_VA.load(Ordering::Relaxed);
    if lapic != 0 {
        mmio_write32(lapic, LAPIC_EOI, 0);
        EOIS.fetch_add(1, Ordering::Relaxed);
    }
    ISR_DEPTH[slot].fetch_sub(1, Ordering::Relaxed);
}

/// 本 CPU 的"中断窗口开着"状态。**IF 属于 CPU，不属于任务**（ADR-021）。
///
/// 这条不是风格问题：x86 的 `iretq` 会把栈上那份 rflags 整个装回 CPU，包括 IF 位，
/// 所以"被抢占的任务恢复时带回它自己的 IF"是硬件默认行为。M3a 就踩在它上面——
/// 两段窗口的测试里第二段一条 tick 都收不到，因为第一段的 `cli` 由"当时持有 CPU 的那个
/// 任务"执行，而下一个任务又自带 IF=1。要么规定任务永不携带 IF，要么规定 rflags 归任务、
/// 窗口只等不关；这里选前者，并且把它做成**可测的**：换入时按这张表改写异常帧的 IF 位
/// （见 `sched::preempt_point` 与 `context_load` 的第二个参数）。
static CPU_IF: [AtomicBool; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicBool::new(false) }; crate::arch::x86_64::cpu::MAX_CPUS];

/// 本 CPU 的中断窗口是否开着。调度器换入任务时要按它改写异常帧的 IF 位。
pub fn interrupts_enabled(slot: usize) -> bool {
    slot < crate::arch::x86_64::cpu::MAX_CPUS && CPU_IF[slot].load(Ordering::Acquire)
}

/// AP 进门时开自己那条中断窗口用的：**立牌 + `sti` 一起做**。
///
/// 为什么必须两个动作一起：ADR-021 之后 `context_load` 换入任何人时都按 `CPU_IF[slot]`
/// 改写异常帧的 IF 位。AP 只 `sti` 而不立牌的话，那块牌一直写着"关着"，
/// 于是第一次换入会被强行清掉 IF —— 那条 CPU 从此收不到 tick，也就再也换不回人。
/// 这正是 M3a 记录过的"接手的人带着关中断的状态跑"的形状，只是换到了 AP 上。
/// （M3b-1 时 AP 不跑调度器，这个缺口不会显形；跑调度器之后它就是死锁，见任务 #11。）
pub fn open_cpu_window(slot: usize) {
    if slot < crate::arch::x86_64::cpu::MAX_CPUS {
        CPU_IF[slot].store(true, Ordering::Release);
    }
    // SAFETY: sti 只置 EFLAGS.IF，不访问内存、不动栈
    unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
}

/// AP 停机时把窗口关回去（立牌 + `cli`），与 `open_cpu_window` 成对。
pub fn close_cpu_window(slot: usize) {
    // SAFETY: cli 只清 EFLAGS.IF
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
    if slot < crate::arch::x86_64::cpu::MAX_CPUS {
        CPU_IF[slot].store(false, Ordering::Release);
    }
}

/// 只在 `f()` 这段时间里开着 IF，返回前关回去。
///
/// 用 `sti`/`cli` 而不是 `pushfq/or/popfq`：后者会改标志位，就不能再声明
/// `preserves_flags`，而 `sti` 本身就是"只改 IF"的一条指令，不需要碰栈。
/// 声明里刻意**不带** `preserves_flags`（sti/cli 确实改标志），带 `nomem, nostack`。
///
/// 顺序是"先立牌再 `sti`"、"`cli` 之后再倒牌"：中间这段如果发生抢占，换进来的任务
/// 必须看到"窗口是开的"，否则它会带着 IF=0 跑下去，而开窗口的那个上下文还在 `Runnable`
/// 里等 CPU——那正是 M3a 挂死过的形状。反过来（先 sti 后立牌）会留下一个
/// "窗口开着但牌上写着关"的窗口，被抢占的那个任务换回来时会被强行关掉 IF。
#[inline]
pub fn with_interrupts<T>(f: impl FnOnce() -> T) -> T {
    let slot = crate::arch::x86_64::cpu::self_slot();
    CPU_IF[slot].store(true, Ordering::Release);
    // SAFETY: sti 只置 EFLAGS.IF，不访问内存、不动栈
    unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
    let r = f();
    // SAFETY: cli 只清 EFLAGS.IF，同上
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
    CPU_IF[slot].store(false, Ordering::Release);
    r
}

// ------------------------------------------------------------------ AP 侧

/// LAPIC 定时器相关的寄存器（Intel SDM Vol.3A 表 11-2）。
/// ICR（核间中断）这一组今天有了调用者：§6.6 的 TLB shootdown（见 `ipi_all_excluding_self`）。
const LAPIC_LVT_TIMER: u64 = 0x0320;
const LAPIC_ICR_LO: u64 = 0x0300;
const LAPIC_ICR_HI: u64 = 0x0310;
const LAPIC_TMICT: u64 = 0x0380;
const LAPIC_TMCCT: u64 = 0x0390;
const LAPIC_TDCR: u64 = 0x03e0;
/// 定时器分频：TDCR 的低 4 位，0b0011 = 除以 16。
/// 选 16 的理由不是"常用"，是它能把 APIC 总线计数（QEMU 上是 1 GHz 量级）压进
/// 一个 32 位初值装得下的 10 ms 周期：不除以 16 时 10 ms 需要 1e7 计数，仍然装得下，
/// 但 100 ms 就要 1e8——先按 16 分频，留出两个数量级的余量。
const TIMER_DIVIDE: u32 = 0b0011;
/// LVT 位域：bit16=屏蔽，bits18:17=模式（00=单发，01=周期性，10=起始计数），bit17 单独置 1 是 TSC-deadline
const LVT_MASKED: u32 = 1 << 16;
const LVT_PERIODIC: u32 = 1 << 17;

/// AP 自己把本地 APIC 软件使能并读回 id。
///
/// `init()` 已经在 BSP 上把 LAPIC 窗口映射好了，多核共享同一份页表，所以 AP 直接沿用
/// 同一个 VA（每个 CPU 的 LAPIC 都在**同一个物理地址** 0xfee00000，靠处理器自身区分）。
/// 这也是为什么这里不能"再 map_device 一次"：那是同一个物理页的第二个主人。
pub fn ap_enable_lapic() -> Result<u32, ApicError> {
    let lapic = LAPIC_VA.load(Ordering::Relaxed);
    if lapic == 0 {
        // BSP 还没映射设备页就释放了 AP：这是启动顺序错误，不是硬件问题
        return Err(ApicError::NoLapic);
    }
    mmio_write32(lapic, LAPIC_SVR, 0x1ff);
    Ok(mmio_read32(lapic, LAPIC_ID) >> 24)
}

/// 标定过程的读数。**诊断用**：AP 侧不许打印（串口会互相插字），所以把现场交给 BSP 打印。
/// 多个 AP 同时写就是"最后一个赢"——这里可以接受，因为要回答的问题是
/// "为什么三个 AP 都算不出初值"，而任何一份现场都能回答它。
static CAL_DBG: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

pub fn cal_dbg() -> [u64; 5] {
    let mut o = [0u64; 5];
    for (i, v) in o.iter_mut().enumerate() {
        *v = CAL_DBG[i].load(Ordering::Relaxed);
    }
    o
}

/// 用 TSC 反推本 CPU 的 APIC 定时器计数率，并按周期模式装好它。
///
/// 为什么要现算而不是写死一个初值：APIC 定时器的输入频率是**平台相关**的
/// （Intel 文档说是总线频率，QEMU/真机各不相同），任何写死的数都是猜。
/// 方法就一条：先让计数器从 0xFFFFFFFF 往下跑一段"用 TSC 量出来的已知时长"，
/// 读回当前计数值得到每秒多少个 APIC 计数，再按目标周期换算初值。
///
/// `tsc_hz` 来自 BSP 的 PIT 标定（`clock::current()`）。这里继承两条已记录的限制：
/// 本机 `tsc_inv=false`，所以 tsc_hz 是采样那一刻的瞬时值；AP 的 tick 周期因此是**估计值**。
/// 用例只验"在走"（复发性）而**不**验周期精确度：量精确度需要每 CPU 的 tick 时间戳表，
/// 那还没做，已记 BACKLOG。不要在这里写"10 ms ±25%"，因为没人量过。
/// 标定失败的种类。**每一种都带当时的读数**：这条路径的全部意义就是
/// "为什么这台机器/这个模拟器上的 APIC 计数器是这个样子"，不给读数的错误码等于没诊断。
#[derive(Debug, Clone, Copy)]
pub enum TimerError {
    NoLapic,
    /// tsc_hz 或目标周期是 0：没有换算基准
    NoCalibration,
    /// 灌了满量程、跑完窗口，TMCCT 却没动过
    CounterFrozen { tmcct: u32, spent: u64, dt_cycles: u64 },
    /// 窗口短到换算不出微秒（整数除法会直接给 0）
    WindowTooShort { dt_cycles: u64 },
    /// 算出来的初值为 0 或超出 32 位量程
    RateOutOfRange { counts_per_sec: u64, initial: u64, window_us: u64 },
}

impl From<TimerError> for ApicError {
    fn from(v: TimerError) -> ApicError {
        match v {
            TimerError::NoLapic => ApicError::NoLapic,
            // 其余三种都是"标定不出可用初值"，对调用方而言与没有 APIC 是同一级失败；
            // 具体哪一种由 TimerError 自己进日志，不在这里丢信息。
            _ => ApicError::NoLapic,
        }
    }
}

/// 把一次标定的现场写进诊断表（顺序：tmcct, spent, dt_cycles, counts_per_sec, initial）。
fn note_cal_dbg(v: [u64; 5]) {
    for (i, x) in v.iter().enumerate() {
        CAL_DBG[i].store(*x, Ordering::Relaxed);
    }
}

pub fn ap_timer_start(period_us: u64, tsc_hz: u64) -> Result<u32, TimerError> {
    let lapic = LAPIC_VA.load(Ordering::Relaxed);
    if lapic == 0 {
        return Err(TimerError::NoLapic);
    }
    if tsc_hz == 0 || period_us == 0 {
        return Err(TimerError::NoCalibration);
    }
    // 1) 分频器 + LVT 先按"屏蔽"状态配好，再放开：与 BSP 配 I/O APIC 同一条纪律
    mmio_write32(lapic, LAPIC_TDCR, TIMER_DIVIDE);
    mmio_write32(lapic, LAPIC_LVT_TIMER, LVT_MASKED | LVT_PERIODIC | (crate::arch::x86_64::trap::VEC_CPU_TIMER as u32 & 0xff));
    // 2) 标定窗口：先把计数器灌满量程再跑一段已知 TSC 时长。
    // 这里**不用** `tsc::spin(n)`：那个函数的 n 是循环次数不是周期数，每轮代价随
    // 优化等级变；标定窗口必须用"读到 TSC 差够数为止"的绝对界限，否则量出来的
    // 计数率会跟着构建方式漂。
    let measure_us = 2_000u64; // 2 ms 的采样窗，够跑掉几百万个计数又不至于太长
    mmio_write32(lapic, LAPIC_TMICT, 0xffff_ffff);
    let want_cycles = tsc_hz * measure_us / 1_000_000;
    let t0 = crate::tsc::now();
    let mut raw = 0u32;
    while crate::tsc::now().wrapping_sub(t0) < want_cycles {
        raw = mmio_read32(lapic, LAPIC_TMCCT);
    }
    let dt_cycles = crate::tsc::now().wrapping_sub(t0);
    let spent = 0xffff_ffffu64.wrapping_sub(raw as u64);
    if spent == 0 {
        // 计数器根本没动：不能返回一个"看起来能用"的 0 初值
        note_cal_dbg([raw as u64, spent, dt_cycles, 0, 0]);
        return Err(TimerError::CounterFrozen { tmcct: raw, spent, dt_cycles });
    }
    let window_us = (dt_cycles as u128 * 1_000_000 / tsc_hz as u128) as u64;
    if window_us == 0 {
        note_cal_dbg([raw as u64, spent, dt_cycles, 0, 0]);
        return Err(TimerError::WindowTooShort { dt_cycles });
    }
    let counts_per_sec = (spent as u128 * 1_000_000 / window_us as u128) as u64;
    // 初值直接用"窗口里跑了多少计数"按比例折算，**不在中间量上取整**：
    // 先算 counts_per_us（=65）再乘 10000，整数截断就把周期推偏了 1.5%；
    // 而 spent*period/window 一步算完，本机实测 130,768 * 10,000 / 1,990 = 657,125。
    // 这里踩过一次更狠的：把 counts_per_sec 当成 counts_per_us 用，
    // 10 ms 的初值直接超出 32 位量程，标定"失败"得毫无道理（现场见 cal_dbg 的 initial 列）。
    let initial = (spent as u128 * period_us as u128 / window_us as u128) as u64;
    if initial == 0 || initial > 0xffff_ffff {
        note_cal_dbg([raw as u64, spent, dt_cycles, counts_per_sec, initial]);
        return Err(TimerError::RateOutOfRange { counts_per_sec, initial, window_us });
    }
    // 3) 装入初值并**最后**放开屏蔽：与 BSP 那条 RTE 的两段式写同一条顺序纪律
    mmio_write32(lapic, LAPIC_TMICT, initial as u32);
    mmio_write32(lapic, LAPIC_LVT_TIMER, LVT_PERIODIC | (crate::arch::x86_64::trap::VEC_CPU_TIMER as u32 & 0xff));
    note_cal_dbg([raw as u64, spent, dt_cycles, counts_per_sec, initial]);
    Ok(initial as u32)
}

/// 关掉本 CPU 的本地定时器：先屏蔽 LVT，再把当前计数值回灌成初值，
/// 免得下一次启动的第一拍是个剩余值（那种"第一个间隔特别短"的现象最难归因）。
pub fn ap_timer_stop() {
    let lapic = LAPIC_VA.load(Ordering::Relaxed);
    if lapic == 0 {
        return;
    }
    mmio_write32(lapic, LAPIC_LVT_TIMER, LVT_MASKED | LVT_PERIODIC | (crate::arch::x86_64::trap::VEC_CPU_TIMER as u32 & 0xff));
    // 屏蔽之后计数器还在跑；把它停在初值上，避免下一次启动的第一拍是个剩余值
    let cur = mmio_read32(lapic, LAPIC_TMCCT);
    mmio_write32(lapic, LAPIC_TMICT, cur);
}

/// ICR 低半的位域（Intel SDM Vol.3A 图 11-15）：[7:0] 向量、[10:8] 投递模式、
/// [11] 目的模式、[12] 投递中(RO)、[19:18] 触发模式、[27:25] 目的缩写。
/// 缩写这一组今天没用上，理由写在 `send_ipi_to` 的注释里（实测收不到）。
const ICR_DELIVERY_PENDING: u32 = 1 << 12;
/// 等 ICR 空闲的上界（轮询次数）。这一位由**本地 APIC** 自己清，与对方有没有处理无关，
/// 所以正常值是个位数次轮询；4,000 次纯粹是防"硬件卡住时我们把 VMM 锁一直占着"。
const ICR_POLL_LIMIT: u32 = 4_000;

/// 向**一个**指定 LAPIC id 发 IPI。
///
/// 为什么不用"除本 CPU 外全体"的目的缩写（shorthand）：**实测它收不到**。
/// 第一次实现按 SDM 图 11-15 的编码写 `0b010 << 25`，结果是 3 个在线 AP 一个回执都没回、
/// 请求方走满 20M 周期限后升 L4（`L4 mm: shootdown 超时 ... 还差 3 个回执`）。
/// 要么是本机 QEMU 对缩写的位域解释与 SDM 不同，要么是我对这个字段的理解错——
/// 在能读到差异之前，逐点名是唯一"发出去就能验证对方收没收到"的写法，
/// 所以这里选它，并把缩写那次失败留在注释里而不是悄悄改掉。
///
/// 目的字段在 xAPIC 下是 ICR 高半的 [31:24]；投递模式 Fixed(000)、Assert、Physical。
pub fn send_ipi_to(dest_lapic_id: u32, vector: u32) -> Result<(), ApicError> {
    let lapic = LAPIC_VA.load(Ordering::Relaxed);
    if lapic == 0 {
        return Err(ApicError::NoLapic);
    }
    mmio_write32(lapic, LAPIC_ICR_HI, dest_lapic_id << 24);
    mmio_write32(lapic, LAPIC_ICR_LO, vector & 0xff);
    let mut spins = 0u32;
    while mmio_read32(lapic, LAPIC_ICR_LO) & ICR_DELIVERY_PENDING != 0 {
        core::hint::spin_loop();
        spins += 1;
        if spins >= ICR_POLL_LIMIT {
            // ICR 卡在投递中 = 本 CPU 的 APIC 状态不可信。调用方（mm）把它记成一次
            // shootdown 失败，由那里决定升级——错误处置不在这里发明。
            return Err(ApicError::MapFailed);
        }
    }
    Ok(())
}

/// 快路径桩用的 EOI（不经过 `on_interrupt`，所以那里没有本 CPU 的 EOI 计数）。
pub fn eoi_self() {
    let lapic = LAPIC_VA.load(Ordering::Relaxed);
    if lapic != 0 {
        mmio_write32(lapic, LAPIC_EOI, 0);
        EOIS.fetch_add(1, Ordering::Relaxed);
    }
}

