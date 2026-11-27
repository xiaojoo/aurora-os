//! S2 步骤 3（ADR-263 选 C）：纯用户态同步原语。**无新增 syscall、无堆、无 panic、无新增 unsafe。**
//!
//! 只用 runtime 已有件：`uptime_us`（32 号）、`sleep_ms`（19 号 `object_wait(signals=0)`）、`core::hint::spin_loop`。
//!
//! ## 睡眠句柄（务必读）
//! `sleep_ms` 内核侧只接受 **Proc** 对象（`user.rs:2056-2059`，其余 kind 回 `-4`）。因此睡眠句柄必须取
//! `ROLE_SELF_PROC`（角色 0），**不是** `ROLE_SELF_THREAD`（角色 2）。传错会得到 `-4`——本模块把它当作
//! “睡不成”，**降级为纯自旋并置 `degraded` 标志**，而不是像 `cmd_top` 那样静默忽略。
//!
//! ## 取舍（ADR-263 量化，沙箱 Python 模型，非仓库实测）
//! 自旋 1 ms；之后睡 1,2,4,8,16 ms（封顶 16）。短临界区基本不进内核；长等待 p99 唤醒延迟 ≈ 16 ms。
//! **没有 wake**：持有者 `unlock` 无法叫醒等待者，延迟由退避间隔决定。
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::{sleep_ms, uptime_us, Handle};

/// 自旋窗口（µs）。ADR-263 决策 3。
pub const SPIN_US: u64 = 1_000;
/// 退避起点/封顶（ms）。`sleep_ms` 最小粒度 1 ms，上限 `WAIT_MAX_MS`。
pub const BACKOFF_START_MS: u64 = 1;
pub const BACKOFF_MAX_MS: u64 = 16;
/// 自旋阶段每多少轮取一次时间（摊薄 `uptime_us` 的 int 0x80 开销）。
pub const SPIN_CHECK_EVERY: u32 = 64;
/// 自旋轮数硬上限（时钟停滞/取时失败的兜底；以 ~20ns/轮估约 1 ms，TCG 下会更久，故按“最坏也有界”取值）。
pub const SPIN_ITERS_MAX: u32 = 200_000;
/// 时钟未标定时的固定自旋轮数（约等价 SPIN_US，粗略；不精确，仅保证短临界区仍有机会不进睡眠）。
pub const SPIN_ITERS_NO_CLOCK: u32 = 20_000;

/// 睡眠能力。`None` = 取不到 `ROLE_SELF_PROC` 句柄 → 只能自旋。
#[derive(Clone, Copy)]
pub struct Sleeper(Option<Handle>);
impl Sleeper {
    /// `self_proc`：`handle_of_role(si_va, ROLE_SELF_PROC)` 的结果。
    pub const fn new(self_proc: Option<Handle>) -> Self { Sleeper(self_proc) }
    pub const fn none() -> Self { Sleeper(None) }
}

/// 锁获取的结果，用于观测（测试与降级判别）。
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct LockStats {
    /// 本次调用实际 `sleep_ms` 成功的次数。
    pub slept: u32,
    /// 睡眠被拒/不可用（`-4` 等）后降级为自旋的次数。**非 0 说明句柄传错或内核等待不可用。**
    pub degraded: u32,
    /// 无时钟时累计的退避毫秒数（仅用于在没有 `uptime_us` 的情形下近似实现 timeout；有时钟时恒 0）。
    pub slept_ms_hint: u64,
}

/// 三态 mutex：0 空闲 / 1 占用 / 2 占用且“有人睡过”。选 C 下 2 **不触发任何 wake**，仅保留语义，
/// 便于将来若重开内核 futex（ADR-263 重开条件）而不改 ABI。
pub struct Mutex(AtomicU32);

impl Mutex {
    pub const fn new() -> Self { Mutex(AtomicU32::new(0)) }

    /// 尝试获取，不等待。
    pub fn try_lock(&self) -> bool {
        self.0.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    /// 获取。返回 `LockStats` 供观测；**永不 panic**；`timeout_ms=None` 表示一直等。
    /// 超时返回 `Err(stats)`（锁未获得）。
    ///
    /// ## 自旋阶段的实现取舍（沙箱模型量化，非实测）
    /// 早期写法“每轮 `try_lock` + `uptime_us()`”会让 1 ms 窗口内发起约 100~3000 次 `int 0x80`
    /// （syscall 0.3~10 µs；项目实际跑在 TCG 软件模拟下偏向后者），自旋本身变成系统调用风暴。
    /// 改为**按迭代次数自旋**：每 `SPIN_CHECK_EVERY` 轮才取一次时间，把取时开销摊薄 64 倍。
    /// 代价：窗口长度不再精确等于 `SPIN_US`（取决于 CPU 速度），但**上界仍由时间保证**。
    /// **时钟未标定**（`uptime_us()` 回 `Err`）时：用固定轮数 `SPIN_ITERS_NO_CLOCK` 兜底自旋，**不再跳过自旋**
    /// （上一版在此情形下直接进睡眠，短临界区会退化到 ≥1 ms 延迟）。
    pub fn lock(&self, sl: Sleeper, timeout_ms: Option<u64>) -> Result<LockStats, LockStats> {
        let mut st = LockStats::default();
        if self.try_lock() { return Ok(st); }
        let t0 = uptime_us();
        // 阶段 1：有界自旋（按迭代次数，周期性取时）
        let mut i: u32 = 0;
        loop {
            if self.try_lock() { return Ok(st); }
            core::hint::spin_loop();
            i = i.wrapping_add(1);
            match t0 {
                Ok(t) => {
                    if i % SPIN_CHECK_EVERY == 0 {
                        if uptime_us().unwrap_or(t).saturating_sub(t) >= SPIN_US { break; }
                    }
                    if i >= SPIN_ITERS_MAX { break; }              // 取时失败/时钟停滞的兜底，防止永远自旋
                }
                Err(_) => { if i >= SPIN_ITERS_NO_CLOCK { break; } } // 时钟未标定：固定轮数
            }
        }
        // 阶段 2：指数睡眠退避；标记“有人在等”
        let t0_us = t0.unwrap_or(0);
        let mut clock_ok = t0.is_ok();
        let mut b = BACKOFF_START_MS;
        let deadline = timeout_ms.map(|m| t0_us.saturating_add(m.saturating_mul(1000)));
        loop {
            // swap(2)：若发现空闲(0)则同时拿到锁（保持三态语义）
            if self.0.swap(2, Ordering::Acquire) == 0 { return Ok(st); }
            if let Some(d) = deadline {
                match uptime_us() {
                    Ok(now) if now >= d => return Err(st),
                    Err(_) => clock_ok = false,
                    _ => {}
                }
            }
            match sl.0 {
                Some(h) => match sleep_ms(h, b) {
                    Ok(()) => st.slept += 1,
                    Err(_) => {                                       // 例如句柄角色错误 → -4
                        st.degraded += 1;
                        for _ in 0..2_000 { core::hint::spin_loop(); } // 降级：短自旋，下一轮再试
                    }
                },
                None => {
                    st.degraded += 1;
                    for _ in 0..2_000 { core::hint::spin_loop(); }
                }
            }
            b = (b.saturating_mul(2)).min(BACKOFF_MAX_MS);
            st.slept_ms_hint = st.slept_ms_hint.saturating_add(b);
            // 时钟未标定或中途失效时，用累计退避毫秒做有界兜底；不能永久轮询。
            if !clock_ok {
                if let Some(m) = timeout_ms {
                    if st.slept_ms_hint >= m { return Err(st); }
                }
            }
        }
    }

    /// 释放。**无 wake**（ADR-263）。对未持有的锁调用是调用方错误：返回 false 而非 panic。
    pub fn unlock(&self) -> bool { self.0.swap(0, Ordering::Release) != 0 }
}

/// 一次性事件（轮询式）：置位后等待者在下一次醒来时看到。**不是** futex——延迟 ≈ 退避间隔。
pub struct Event(AtomicBool);
impl Event {
    pub const fn new() -> Self { Event(AtomicBool::new(false)) }
    pub fn set(&self) { self.0.store(true, Ordering::Release); }
    pub fn is_set(&self) -> bool { self.0.load(Ordering::Acquire) }
    pub fn clear(&self) { self.0.store(false, Ordering::Release); }
    /// 轮询等待；超时返回 false。退避规则同 `Mutex::lock`。
    pub fn wait_timeout_poll(&self, sl: Sleeper, timeout_ms: u64) -> (bool, LockStats) {
        let mut st = LockStats::default();
        let t0 = uptime_us();
        let t0_us = t0.unwrap_or(0);
        let mut clock_ok = t0.is_ok();
        let mut b = BACKOFF_START_MS;
        loop {
            if self.is_set() { return (true, st); }
            match uptime_us() {
                Ok(now) if clock_ok => {
                    if now.saturating_sub(t0_us) >= timeout_ms.saturating_mul(1000) { return (false, st); }
                }
                Err(_) => clock_ok = false,
                _ => {}
            }
            if !clock_ok && st.slept_ms_hint >= timeout_ms { return (false, st); }
            match sl.0 {
                Some(h) => match sleep_ms(h, b) { Ok(()) => st.slept += 1, Err(_) => { st.degraded += 1; core::hint::spin_loop(); } },
                None => { st.degraded += 1; core::hint::spin_loop(); }
            }
            b = (b.saturating_mul(2)).min(BACKOFF_MAX_MS);
            st.slept_ms_hint = st.slept_ms_hint.saturating_add(b);
        }
    }
}

/// 压测计数器（ktest 用）：非原子读-改-写的“临界区内计数”，用来证明互斥——被保护的数据放在 `Mutex` 外。
pub struct Counter(AtomicU64);
impl Counter {
    pub const fn new() -> Self { Counter(AtomicU64::new(0)) }
    /// **故意非原子**：load 后 store。互斥被破坏时终值会小于 N×M（变异 M1 依赖它）。
    pub fn bump_non_atomic(&self) { let v = self.0.load(Ordering::Relaxed); self.0.store(v + 1, Ordering::Relaxed); }
    pub fn get(&self) -> u64 { self.0.load(Ordering::Relaxed) }
}
