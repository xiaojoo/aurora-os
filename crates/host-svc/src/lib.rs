//! S5c 用户态服务监督的纯函数层（ADR-269 §2.3）。
//!
//! ## 定位
//! * 只放**无副作用**的逻辑：①单元文件 `key=value` 解析；②重启退避表取值；③熔断（滑动窗口内重启次数）。
//! * **不含 syscall、不读时钟**：时间由调用方以毫秒传入；`init` 监督者（用户态 ring3）负责 `process_wait/sleep_ms`。
//! * **无堆、无 `unsafe`、任何输入不 panic**：所有读取走 `get()`，没有下标访问；容量全是编译期常量。
//!
//! ## 对手册案例 16 的更正
//! 手册的 `svc.recent.push(now_ms); svc.recent.retain(..)` 需要 `Vec`——用户态 `no_std` 没有分配器。
//! 这里改为**定长环**（[`Breaker`]，容量 [`RING_MAX`]）；`max_per_minute > RING_MAX` 的单元在解析期被**拒绝**，
//! 而不是静默截断（否则熔断会比声明的更松）。
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// 单元名最大长度（字节）。
pub const NAME_MAX: usize = 16;
/// 可执行路径最大长度（字节）。与 runtime `PATH_MAX` 同数 256 太大，服务路径只到根目录 8.3，64 足够。
pub const EXEC_MAX: usize = 64;
/// 退避表最多项数。
pub const BACKOFF_MAX: usize = 8;
/// 熔断环容量：`max_per_minute` 的上限。
pub const RING_MAX: usize = 16;
/// 熔断统计窗口（毫秒）。
pub const WINDOW_MS: u64 = 60_000;

/// 重启策略。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restart {
    /// 退出后不重启。
    Never,
    /// 仅失败（退出码非 0 或被杀）时重启。
    OnFailure,
    /// 无论如何都重启。
    Always,
}

/// 解析错误。每个变体对应一类拒绝，判据能区分是哪一格拒的。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseErr {
    /// 不是合法 UTF-8 / 含 NUL。
    BadBytes,
    /// 行里没有 `=`。
    NoEquals,
    /// 未知键。
    UnknownKey,
    /// 同一键出现两次。
    DupKey,
    /// 值为空，或超长。
    BadValue,
    /// 数字解析失败/溢出。
    BadNumber,
    /// 缺必填键（`name`、`exec`）。
    Missing,
    /// `max_per_minute` 超过环容量。
    TooManyPerMinute,
    /// 退避表项数超限或为空。
    BadBackoff,
}

/// 一个服务单元（定长，无堆）。
#[derive(Clone, Copy, Debug)]
pub struct Unit {
    name: [u8; NAME_MAX],
    name_len: usize,
    exec: [u8; EXEC_MAX],
    exec_len: usize,
    /// 重启策略（缺省 `OnFailure`）。
    pub restart: Restart,
    backoff: [u32; BACKOFF_MAX],
    backoff_len: usize,
    /// 每分钟最多重启次数（缺省 5）。
    pub max_per_minute: u32,
}

impl Unit {
    /// 空单元（缺省值）。
    pub const fn blank() -> Self {
        Unit {
            name: [0; NAME_MAX],
            name_len: 0,
            exec: [0; EXEC_MAX],
            exec_len: 0,
            restart: Restart::OnFailure,
            backoff: [0; BACKOFF_MAX],
            backoff_len: 0,
            max_per_minute: 5,
        }
    }
    /// 单元名。
    pub fn name(&self) -> &[u8] {
        self.name.get(..self.name_len).unwrap_or(&[])
    }
    /// 可执行路径。
    pub fn exec(&self) -> &[u8] {
        self.exec.get(..self.exec_len).unwrap_or(&[])
    }
    /// 退避表（毫秒）。
    pub fn backoff(&self) -> &[u32] {
        self.backoff.get(..self.backoff_len).unwrap_or(&[])
    }
}

fn parse_u32(v: &[u8]) -> Result<u32, ParseErr> {
    if v.is_empty() {
        return Err(ParseErr::BadNumber);
    }
    let mut acc: u32 = 0;
    for &b in v {
        if !b.is_ascii_digit() {
            return Err(ParseErr::BadNumber);
        }
        acc = acc
            .checked_mul(10)
            .and_then(|x| x.checked_add(u32::from(b - b'0')))
            .ok_or(ParseErr::BadNumber)?;
    }
    Ok(acc)
}

fn trim(mut b: &[u8]) -> &[u8] {
    while let Some((&c, rest)) = b.split_first() {
        if c == b' ' || c == b'\t' || c == b'\r' {
            b = rest;
        } else {
            break;
        }
    }
    while let Some((&c, rest)) = b.split_last() {
        if c == b' ' || c == b'\t' || c == b'\r' {
            b = rest;
        } else {
            break;
        }
    }
    b
}

fn copy_into(dst: &mut [u8], src: &[u8]) -> Result<usize, ParseErr> {
    if src.is_empty() || src.len() > dst.len() {
        return Err(ParseErr::BadValue);
    }
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
    }
    Ok(src.len())
}

/// 解析一份单元文件（`key=value`，`#` 开头为注释，空行忽略）。
///
/// 键：`name`、`exec`、`restart`（`never|on-failure|always`）、`backoff_ms`（逗号分隔 1..=8 个 u32）、`max_per_minute`。
/// 拒绝而不是容忍：未知键、重复键、非 UTF-8、含 NUL、超长值、`max_per_minute > RING_MAX`。
pub fn parse_unit(bytes: &[u8]) -> Result<Unit, ParseErr> {
    if bytes.contains(&0) || core::str::from_utf8(bytes).is_err() {
        return Err(ParseErr::BadBytes);
    }
    let mut u = Unit::blank();
    let (mut s_name, mut s_exec, mut s_rst, mut s_bo, mut s_max) = (false, false, false, false, false);
    for raw in bytes.split(|&b| b == b'\n') {
        let line = trim(raw);
        if line.is_empty() || line.first() == Some(&b'#') {
            continue;
        }
        let eq = line.iter().position(|&b| b == b'=').ok_or(ParseErr::NoEquals)?;
        let key = trim(line.get(..eq).unwrap_or(&[]));
        let val = trim(line.get(eq + 1..).unwrap_or(&[]));
        let dup = |seen: &mut bool| -> Result<(), ParseErr> {
            if *seen && !cfg!(feature = "fault-svc-parse-accept-dup") {
                return Err(ParseErr::DupKey);
            }
            *seen = true;
            Ok(())
        };
        match key {
            b"name" => {
                dup(&mut s_name)?;
                u.name_len = copy_into(&mut u.name, val)?;
            }
            b"exec" => {
                dup(&mut s_exec)?;
                u.exec_len = copy_into(&mut u.exec, val)?;
            }
            b"restart" => {
                dup(&mut s_rst)?;
                u.restart = match val {
                    b"never" => Restart::Never,
                    b"on-failure" => Restart::OnFailure,
                    b"always" => Restart::Always,
                    _ => return Err(ParseErr::BadValue),
                };
            }
            b"backoff_ms" => {
                dup(&mut s_bo)?;
                let mut n = 0usize;
                for part in val.split(|&b| b == b',') {
                    let v = parse_u32(trim(part))?;
                    let slot = u.backoff.get_mut(n).ok_or(ParseErr::BadBackoff)?;
                    *slot = v;
                    n += 1;
                }
                if n == 0 {
                    return Err(ParseErr::BadBackoff);
                }
                u.backoff_len = n;
            }
            b"max_per_minute" => {
                dup(&mut s_max)?;
                let v = parse_u32(val)?;
                if v as usize > RING_MAX {
                    return Err(ParseErr::TooManyPerMinute);
                }
                u.max_per_minute = v;
            }
            _ => return Err(ParseErr::UnknownKey),
        }
    }
    if u.name_len == 0 || u.exec_len == 0 {
        return Err(ParseErr::Missing);
    }
    if u.backoff_len == 0 {
        // 缺省退避：200 ms、1 s、5 s（手册案例 16 的数）。
        u.backoff = [200, 1000, 5000, 0, 0, 0, 0, 0];
        u.backoff_len = 3;
    }
    Ok(u)
}

/// 第 `tries` 次重启前要等的毫秒数：取表中对应项，超出则取**末项**；空表返回 `None`。
pub fn next_delay(tries: u32, table: &[u32]) -> Option<u32> {
    if cfg!(feature = "fault-svc-backoff-no-clamp") {
        return table.get(tries as usize).copied();
    }
    table.get(tries as usize).copied().or_else(|| table.last().copied())
}

/// 进程结局（由监督者从 `process_wait` 的退出码折算）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// 退出码 0。
    Clean,
    /// 退出码非 0，或被 `process_kill`（内核口径：被杀的退出码恒为 1，见 `sched/mod.rs` 退出码寄存器注释）。
    Failed,
}

impl Exit {
    /// 由退出码折算。
    pub const fn from_code(code: u32) -> Self {
        if code == 0 { Exit::Clean } else { Exit::Failed }
    }
}

/// 监督动作。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// 不重启。
    None,
    /// `delay_ms` 之后重启。
    RestartAfter(u32),
    /// 熔断：窗口内次数超限，**不再重启**。
    MarkFailed,
}

/// 熔断环：记录最近若干次退出的时间戳（毫秒），窗口 [`WINDOW_MS`]。
#[derive(Clone, Copy, Debug)]
pub struct Breaker {
    ts: [u64; RING_MAX + 1],
    n: usize,
}

impl Breaker {
    /// 空环。
    pub const fn new() -> Self {
        Breaker { ts: [0; RING_MAX + 1], n: 0 }
    }
    /// 窗口内当前记录数（用于判据读数）。
    pub const fn len(&self) -> usize {
        self.n
    }
    /// 是否为空。
    pub const fn is_empty(&self) -> bool {
        self.n == 0
    }
    /// 记一次退出并返回**窗口内次数**（含本次）。窗口外的旧记录被丢弃。
    /// `now_ms` 回绕/倒退（`now < 旧记录`）时按"差为 0"处理（`saturating_sub`），不 panic。
    pub fn record(&mut self, now_ms: u64) -> usize {
        // 先挤掉窗口外的：保持升序，从头删。
        let mut keep = 0usize;
        let mut i = 0usize;
        while i < self.n {
            let t = self.ts.get(i).copied().unwrap_or(0);
            if now_ms.saturating_sub(t) < WINDOW_MS {
                if let Some(slot) = self.ts.get_mut(keep) {
                    *slot = t;
                }
                keep += 1;
            }
            i += 1;
        }
        self.n = keep;
        // 容量比 max_per_minute 的上限多 1：第 17 次必须还能留下证人，不能在第 16 次就丢最旧。
        if self.n == RING_MAX + 1 {
            let mut j = 1usize;
            while j < RING_MAX + 1 {
                let v = self.ts.get(j).copied().unwrap_or(0);
                if let Some(slot) = self.ts.get_mut(j - 1) {
                    *slot = v;
                }
                j += 1;
            }
            self.n = RING_MAX;
        }
        if let Some(slot) = self.ts.get_mut(self.n) {
            *slot = now_ms;
        }
        self.n += 1;
        self.n
    }
}

impl Default for Breaker {
    fn default() -> Self {
        Self::new()
    }
}

/// 一次退出之后该做什么（手册案例 16 `on_exit` 的无堆版本）。
///
/// * 先记入熔断环，窗口内次数 **> `max_per_minute`** ⇒ [`Action::MarkFailed`]（`>` 不是 `>=`：恰好等于上限仍允许重启）。
/// * 否则按策略与结局决定；`tries` 是**本窗口内已重启次数**（调用方在 `MarkFailed`/成功稳定运行后清零）。
pub fn on_exit(u: &Unit, br: &mut Breaker, tries: u32, exit: Exit, now_ms: u64) -> Action {
    let in_window = br.record(now_ms);
    let tripped = if cfg!(feature = "fault-svc-breaker-never-trips") {
        false
    } else {
        in_window as u32 > u.max_per_minute
    };
    if tripped {
        return Action::MarkFailed;
    }
    let want = match (u.restart, exit) {
        (Restart::Always, _) => true,
        (Restart::OnFailure, Exit::Failed) => true,
        _ => false,
    };
    if !want {
        return Action::None;
    }
    match next_delay(tries, u.backoff()) {
        Some(d) => Action::RestartAfter(d),
        None => Action::None,
    }
}

#[cfg(test)]
mod tests;
