//! TSC 相对计时：§12.4.1 P 系列的量具。
//!
//! **只报周期数，不报 ns**。换算成时间需要一个已知频率的参照，而本机
//! `tsc_inv=false`（启动日志 `cpu:` 行）且还没有 PIT/HPET 校准表——在 M3a 定
//! 时钟源之前，任何 ns 数字都是编的。周期数在“同一台机 + 同一组 QEMU 参数”下可比，
//! 跨机只看比值（§12.4.1 规则 2）。
//!
//! 用 `rdtsc` 而不是 `rdtscp`：`rdtsc` 不是 load/store 序列化指令，所以**下界**
//! 这一端可能被后面的工作提前取走。本模块只把它用在两处有意的边界上：
//! 阶段打点（相邻两次打点之间隔着串口 IO，MMIO 写本身序列化，乱序窗口可忽略）
//! 和异常桩的第一条/最后一条指令。要更严的界需要 `rdtscp`，那是 CPUID 特性位，
//! 由 `serializing_available()` 报，**不用它就不假装有序**。

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// 取当前 TSC。
///
/// 本工具链的 `asm!` **没有** `options(rdtsc)` 这一项（编译期就被拒：可选列表只有
/// `att_syntax/may_unwind/nomem/noreturn/nostack/preserves_flags/pure/raw/readonly`），
/// 所以只能手工交代它的副作用边界：`nomem`（它不访问内存）+ `preserves_flags`，
/// 而 **不能** 加 `readonly`/`pure`——TSC 每次读都不同，标成 pure 会让 LLVM 把两次读数合并。
/// 代价是 `rdtsc` 本身不序列化，编译器仍可能把它和相邻的内存操作对调；
/// 因此本模块只在两个"两侧都有 IO 或显式屏障"的边界上用它（阶段打点走串口输出，
/// 异常桩的两次读数中间隔着 `call`，都是自然屏障）。真要严格有序就上 `rdtscp`，
/// 由 `rdtscp_available()` 报可用性，**不用它就不假装有序**。
#[inline]
pub fn now() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: rdtsc 只读时间戳计数器，不访问内存、不改条件码，也不需要栈。
    unsafe {
        core::arch::asm!(
            "rdtsc",
            lateout("eax") lo,
            lateout("edx") hi,
            options(nomem, preserves_flags)
        );
    }
    ((hi as u64) << 32) | lo as u64
}

/// `IA32_TSC_AUX`/`RDTSCP` 可用性（CPUID 0x8000_0001 EDX bit27）。
/// 目前只用于如实标注量具的界有多紧，不参与判定。
pub fn rdtscp_available() -> bool {
    let ext = core::arch::x86_64::__cpuid(0x8000_0001);
    ext.edx & (1 << 27) != 0
}

/// 忙等 `n` 次空循环。用途只有一个：**证明尺子能分辨**（§12.4.1 规则 3）——
/// 在已知会多花时间的负载下，P 系列的数必须真的动。
#[inline(never)]
pub fn spin(n: usize) -> u64 {
    let mut acc = 0usize;
    for i in 0..n {
        acc = acc.wrapping_add(i | (i >> 3));
    }
    acc as u64
}

// ------------------------------------------------------------- P4：阶段打点

/// 上一次打点的 TSC；0 表示还没打过（即 Stage0 之前）
static LAST: AtomicU64 = AtomicU64::new(0);
static T0: AtomicU64 = AtomicU64::new(0);
static STAGE_NO: AtomicUsize = AtomicUsize::new(0);
static LOG_BYTES: AtomicU64 = AtomicU64::new(0);

/// 打一个阶段点并立刻输出。返回本次与上次的间隔周期数。
///
/// 第一次调用只把 t0 定为这一刻，所以它的 delta 是 0：Stage0 之前的时间属于
/// bootloader，本项目的 P4 不从那里起算。
pub fn stage(name: &str) -> u64 {
    let t = now();
    if T0.load(Ordering::Relaxed) == 0 {
        T0.store(t, Ordering::Relaxed);
    }
    let prev = LAST.swap(t, Ordering::Relaxed);
    let delta = if prev == 0 { 0 } else { t - prev };
    let n = STAGE_NO.fetch_add(1, Ordering::Relaxed);
    // §9.6 的轮询点就挂在阶段边界上：这是开机路径上唯一"保证有界时间过去了一次"的位置。
    // 它的花费因此算进这一段 delta —— 而不是藏在某个没人数的地方。
    crate::watchdog::poll();
    // 串口是忙等字节输出的，日志本身就是这段间隔里的大头：把字节数一起交出去，
    // 读 P4 的人能把“打印的钱”和“干活的钱”分开算，而不是被我的日志喂一个假数字。
    let bytes_now = crate::serial::bytes_out();
    let bytes = bytes_now - LOG_BYTES.swap(bytes_now, Ordering::Relaxed);
    crate::serial::line(
        "p4",
        format_args!(
            "stage{} {}: delta={} cycles since_t0={} cycles log_bytes_since_last={}",
            n, name, delta, t - T0.load(Ordering::Relaxed), bytes
        ),
    );
    delta
}

pub fn total_stages() -> usize {
    STAGE_NO.load(Ordering::Relaxed)
}

/// 从 t0 到现在的总周期数（P4 的“到 Stage5 完成”那一条）
pub fn elapsed() -> u64 {
    let t0 = T0.load(Ordering::Relaxed);
    if t0 == 0 { 0 } else { now() - t0 }
}
