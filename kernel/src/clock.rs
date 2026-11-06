//! 时钟标定（手册 §13“时钟”一行、§12.4.1 的可比性依据）。
//!
//! 结论的形态由一条实测事实决定：本机 `tsc_inv=false`（启动日志 `cpu:` 行），
//! 所以 **TSC 不能当成已知的墙上时钟**——它可能随功耗/频率变化跳变。
//! 但协议规定 PIT 的输入振荡器是 1.193182 MHz，这是硬件常量，不随 host 状态漂；
//! 于是"用 PIT 的 tick 反推 TSC 频率"是唯一此刻站得住的标定法：
//!
//! ```text
//! tsc_hz = tick周期内的cycles × 1_193_182 / 11_932      (divisor=11932 -> 99.9985 Hz)
//! ```
//!
//! 三个诚实的限制，写在这里而不是藏在代码里：
//! 1. **标定值是瞬时值**：`invariant=false` 时它只描述采样那一刻，长时间跨度上的
//!    µs 换算只能算估计。要当权威时延要等 HPET（MADT 里有 HPET 表，本机存在）
//!    或 RTC 做参照。
//! 2. 单次 tick 的抖动会直接进标定值，所以取多个样本的中位数在 M3a 之后补；
//!    今天至少把"几个样本"报出来，不给单一数字冒充精确。
//! 3. 换算全部用整数定点，内核里不引浮点（`check-nofloat` 门禁会数指令）。

use core::sync::atomic::{AtomicU64, Ordering};

/// PIT 输入振荡器，单位 Hz（1.193182 MHz，Intel 8253/8254 常量）
pub const PIT_HZ: u64 = 1_193_182;
/// 我们把通道 0 分频到的计数值（`apic::pit_start_100hz`）
pub const PIT_DIVISOR: u64 = 11_932;
/// 标定的合理范围：低于 10 MHz 或高于 10 GHz 一律认为标定失败，不做"看起来能用"的换算
/// 合理区间：低于 100 MHz 或高于 5 GHz 都不像现代 x86-64 的 TSC。
/// 这不是"物理定律"，是把明显荒唐的读数挡在换算之前——第一次标定报 4.78 GHz
/// 时这个上限差点放过它，所以真正的防线是上面的漏 tick 检查，这里只是兜底。
const MIN_TSC_HZ: u64 = 100_000_000;
const MAX_TSC_HZ: u64 = 5_000_000_000;
/// 一次标定至少要几个 tick 间隔。`from_pit_window` 和"要等多久"共用这一个数：
/// 两边各写一份的话，改判据的人不知道窗口该跟着变（KVM 对照档就是栽在这对上）。
pub const MIN_SAMPLES: u64 = 4;

/// 一个 PIT tick 的周期，单位是"最坏（最快）可信 TSC 下"的 cycles：
/// `MAX_TSC_HZ × PIT_DIVISOR / PIT_HZ` ≈ 5.0e7。任何能通过区间检查的 TSC，
/// 它的真实 tick 周期都不会比这个数长。
pub const fn max_tick_period_cycles() -> u64 {
    MAX_TSC_HZ * PIT_DIVISOR / PIT_HZ
}

/// 攒够 `samples` 个 tick 需要给的窗口上界（cycles）。推导：周期为 p 的周期性事件，
/// 任何长度 L 的窗口里至少出现 `floor(L/p)` 次；取 `L = samples × max_tick_period_cycles()`
/// 就对**任何**落在 `[MIN_TSC_HZ, MAX_TSC_HZ]` 的 TSC 都保证能数到 `samples` 次。
/// 比这个还慢的机器要么样本已经够了，要么标定本来就该因 `OutOfRange` 拒——
/// 所以这条上界不需要按某一次观测值调，它跟着上面那两个端点走。
///
/// **前提**：窗口内 TSC 不跳变。本机 `tsc_inv=false`，跳了就会让 `MissedTicks`
/// 那条先红（它比这条更早发现），所以这里不额外为跳变留余量。
pub const fn window_cycles(samples: u64) -> u64 {
    max_tick_period_cycles() * samples
}

#[derive(Debug, Clone, Copy)]
pub struct Calibration {
    pub tick_period_cycles: u64,
    pub tsc_hz: u64,
    /// 采样来自几次 tick 间隔
    pub samples: usize,
    /// ISR 自己量的**相邻间隔**均值（cycles），以及它数了几段
    pub interval_mean: u64,
    pub interval_n: usize,
    /// CPUID 0x8000_0007 EDX bit8；false 意味着下面所有 µs 都是估计值
    pub invariant: bool,
}

static CAL: AtomicU64 = AtomicU64::new(0);
static CAL_META: AtomicU64 = AtomicU64::new(0);
static CAL_SUM: AtomicU64 = AtomicU64::new(0);
static CAL_N: AtomicU64 = AtomicU64::new(0);
static CAL_SAMPLES: AtomicU64 = AtomicU64::new(0);

/// 由"N 个 tick 的总周期数"标定。
///
/// 为什么必须用 N 个 tick 的总时长，而不是单次相邻间隔：
/// 第一次标定取的就是单次间隔，报出 4.78 GHz（真值的约 1.4 倍）。根因是**跨窗口的陈旧状态**：
/// 上一轮用例停掉 PIT 之后 TICK_TSC_LAST 还留着那次的时间戳，新一轮第一个 tick 与它相减，
/// 得到的是隔着若干个窗口的间隔，根本不是 tick 周期。（原先我以为是长日志把 tick 挤掉了，
/// 但 QEMU 串口后端不按波特率节流，那条理由不成立——见 serial.rs 的实测改正。）
/// 因此调用方必须
/// (a) 在一个不开串口、不打印的窗口里取样本，(b) 同时把最大相邻间隔交进来，
/// 由这里判断"有没有漏 tick"。漏了就是 NoSamples，不给一个看起来能用的假数。
pub fn from_pit_window(
    total_cycles: u64,
    ticks: u64,
    max_tick_gap: u64,
    intervals: (u64, u64),
    invariant: bool,
) -> Result<Calibration, CalibrationError> {
    if ticks < MIN_SAMPLES || total_cycles == 0 {
        return Err(CalibrationError::NoSamples);
    }
    let (sum, n) = intervals;
    // 窗口均值：`总 cycles ÷ tick 数`。窗口两端各切掉一段不完整的间隔，所以它**系统性偏高**。
    let window_mean = total_cycles / ticks;
    // 估计器优先用 ISR 量的相邻间隔均值。本机有第三个仪器可以对表——WSL 里 Linux 自己标的
    // `tsc: Detected 3187.201 MHz processor`（dmesg）：
    //   相邻均值 31,634,941 cycles/tick ⇒ 3163 MHz，比宿主机的数低 0.75%；
    //   窗口均值 33,335,409 cycles/tick ⇒ 3334 MHz，比宿主机的数**高 4.6%**。
    // 也就是说偏高那 4.6% 不是抖动，是切边造成的结构性偏差，样本越少越大（4000 轮封顶的旧窗口
    // 读出过 3.47 GHz，差 8.9%）。所以 n 够就按相邻间隔定周期，n 不够才退回窗口均值。
    let period = if n >= 3 { sum / n } else { window_mean };
    // 漏 tick 的直接后果：最大间隔 >= 2 倍真周期。留 1.5 倍余量当门槛，
    // 因为单次间隔本身有抖动（实测 P5 的 min/max 差两个数量级）。
    if max_tick_gap == 0 || max_tick_gap > period + period / 2 {
        return Err(CalibrationError::MissedTicks { mean: period, max_tick_gap });
    }
    // 第二道守卫是两把尺子之间的硬不等式，红起来当场拒标定而不是印个数：
    //   `sum ≤ total`（窗口不可能比它包含的间隔还短，违反就是有一把尺子在撒谎）；
    //   `total ≤ sum + 2 × max_tick_period_cycles()`（两端各最多切掉一个完整间隔，
    //   而任何比这个上界还长的间隔意味着 TSC 已越过 MAX_TSC_HZ，本来就该 OutOfRange）。
    if n > 0 && (total_cycles < sum || total_cycles > sum + 2 * max_tick_period_cycles()) {
        return Err(CalibrationError::WindowVsIntervals { total_cycles, sum, n });
    }
    // 定点：先乘后除，u128 中间量。周期单位是 cycles，换算回 Hz 用的是 PIT 的 10.00016 ms。
    let hz = (period as u128 * PIT_HZ as u128 / PIT_DIVISOR as u128) as u64;
    if hz < MIN_TSC_HZ || hz > MAX_TSC_HZ {
        return Err(CalibrationError::OutOfRange(hz));
    }
    let c = Calibration {
        tick_period_cycles: period,
        tsc_hz: hz,
        samples: ticks as usize,
        interval_mean: if n > 0 { sum / n } else { 0 },
        interval_n: n as usize,
        invariant,
    };
    CAL.store(period, Ordering::Release);
    CAL_META.store(hz, Ordering::Release);
    CAL_SUM.store(sum, Ordering::Release);
    CAL_N.store(n, Ordering::Release);
    CAL_SAMPLES.store(ticks, Ordering::Release);
    Ok(c)
}

#[derive(Debug, Clone, Copy)]
pub enum CalibrationError {
    NoSamples,
    /// 相邻 tick 的最大间隔远大于均值 => 窗口里漏了 tick，频率不可信
    MissedTicks { mean: u64, max_tick_gap: u64 },
    /// 窗口总时长与 ISR 量的相邻间隔对不上（`total < sum` 或两端切掉的比一个间隔还多）
    /// ⇒ 两把尺子至少有一把错，标出来的频率不能要
    WindowVsIntervals { total_cycles: u64, sum: u64, n: u64 },
    OutOfRange(u64),
}

/// TSC 频率（Hz）。**没有标定就返回 None**：AP 的定时器初值要靠它反推，
/// 返回一个"差不多"的默认值会让那个初值看起来是测出来的，而它其实是猜的。
pub fn hz() -> Option<u64> {
    let h = CAL_META.load(Ordering::Acquire);
    if h == 0 {
        None
    } else {
        Some(h)
    }
}

pub fn current() -> Option<Calibration> {
    let d = CAL.load(Ordering::Acquire);
    let hz = CAL_META.load(Ordering::Acquire);
    let sum = CAL_SUM.load(Ordering::Acquire);
    let n = CAL_N.load(Ordering::Acquire);
    let s = CAL_SAMPLES.load(Ordering::Acquire);
    if d == 0 || hz == 0 {
        return None;
    }
    Some(Calibration {
        tick_period_cycles: d,
        tsc_hz: hz,
        samples: s as usize,
        interval_mean: if n > 0 { sum / n } else { 0 },
        interval_n: n as usize,
        invariant: false,
    })
}

/// cycles -> 微秒。**没有标定就返回 None**，绝不回退成"假设 1 GHz"那种方便但骗人的默认值。
pub fn micros(cycles: u64) -> Option<u64> {
    let hz = CAL_META.load(Ordering::Acquire);
    if hz == 0 {
        return None;
    }
    Some((cycles as u128 * 1_000_000 / hz as u128) as u64)
}

/// 同一个 cycles 值换两次单位应当线性翻倍——这条用来证明换算本身没写反数量级。
pub fn micros_of_two_ticks_is_double(cycles: u64) -> bool {
    match (micros(cycles), micros(cycles.saturating_mul(2))) {
        (Some(a), Some(b)) => b >= a * 2 - 2 && b <= a * 2 + 2,
        _ => false,
    }
}
