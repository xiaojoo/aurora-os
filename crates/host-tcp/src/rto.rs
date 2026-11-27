//! RFC 6298 重传定时器（SRTT / RTTVAR / RTO）。
//!
//! 整数实现：α=1/8、β=1/4、K=4（RFC 6298 §2）。时间单位 µs。
//! * 首个样本 R：SRTT=R，RTTVAR=R/2，RTO=SRTT+max(G, 4·RTTVAR)。
//! * 后续样本 R'：RTTVAR=(1-β)·RTTVAR+β·|SRTT-R'|；SRTT=(1-α)·SRTT+α·R'。**先更新 RTTVAR 再更新 SRTT**（§2.3）。
//! * RTO 下限：RFC 6298 (2.4) 建议 1 s。**使用者已裁决改 1 s（S2 裁决 1，ADR-203 补记）**；下限仍做成参数 `min_rto_us`，
//!   这样历史 200 ms 口径可用 `legacy_200ms()` 做回归对照。现有判定行不会变慢：它们直接调 `on_retx_timeout`，不真等定时器。
//! * RTO 上限：RFC 6298 (2.5) 允许任意上限但须 ≥ 60 s；这里 `max_rto_us` 同样做参数。
//! * 超时退避：RTO ← min(2·RTO, max)（§5.5）。
//! * Karn 算法（§3）：**重传过的段不得取 RTT 样本**——由 `retx` 模块在 `tries>0` 时不调用 `on_sample` 保证。

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rto {
    srtt_us: u32,
    rttvar_us: u32,
    rto_us: u32,
    have_sample: bool,
    min_rto_us: u32,
    max_rto_us: u32,
    /// 时钟粒度 G（µs）。
    granularity_us: u32,
}

impl Rto {
    /// `initial_rto_us`：尚无样本时的 RTO（RFC 6298 (2.1) 建议 1 s；仓库现为 200 ms）。
    pub const fn new(initial_rto_us: u32, min_rto_us: u32, max_rto_us: u32, granularity_us: u32) -> Self {
        Rto { srtt_us: 0, rttvar_us: 0, rto_us: initial_rto_us, have_sample: false,
              min_rto_us, max_rto_us, granularity_us }
    }
    /// **与仓库常量同口径**（S2 裁决 1：ADR-203 补记后）：初值 1 s、下限 1 s、上限 60 s
    /// = `tcp_conn::RETX_BASE_US` / `RETX_BASE_US` / `RETX_MAX_BACKOFF_US`。接入内核时用它，并由门禁对账三个数相等。
    pub const fn adr203() -> Self { Rto::new(1_000_000, 1_000_000, 60_000_000, 10_000) }
    /// 历史口径（ADR-203 原值）：初值/下限 200 ms、上限 3.2 s。仅供回归对照与“RTO 下限变更”的差分测试。
    pub const fn legacy_200ms() -> Self { Rto::new(200_000, 200_000, 3_200_000, 10_000) }
    /// 与 `adr203()` 当前同值；保留此名表示“贴近 RFC 6298”，若将来 ADR 再改仓库口径，二者可能分叉。
    pub const fn rfc6298() -> Self { Rto::new(1_000_000, 1_000_000, 60_000_000, 10_000) }

    pub fn rto_us(&self) -> u32 { self.rto_us }
    pub fn srtt_us(&self) -> Option<u32> { if self.have_sample { Some(self.srtt_us) } else { None } }
    pub fn rttvar_us(&self) -> Option<u32> { if self.have_sample { Some(self.rttvar_us) } else { None } }

    fn clamp(&self, v: u64) -> u32 {
        let v = v.max(self.min_rto_us as u64).min(self.max_rto_us as u64);
        v as u32
    }

    /// 喂入一个**干净**的 RTT 样本（调用方已按 Karn 过滤）。
    pub fn on_sample(&mut self, r_us: u32) {
        if !self.have_sample {
            self.srtt_us = r_us;
            self.rttvar_us = r_us / 2;
            self.have_sample = true;
        } else {
            let err = self.srtt_us.abs_diff(r_us);
            // RTTVAR = 3/4·RTTVAR + 1/4·|SRTT - R'|
            self.rttvar_us = ((3u64 * self.rttvar_us as u64 + err as u64) / 4) as u32;
            // SRTT = 7/8·SRTT + 1/8·R'
            self.srtt_us = ((7u64 * self.srtt_us as u64 + r_us as u64) / 8) as u32;
        }
        let k = 4u64 * self.rttvar_us as u64;
        let var = k.max(self.granularity_us as u64);
        self.rto_us = self.clamp(self.srtt_us as u64 + var);
    }

    /// 重传定时器到期：RTO 翻倍（封顶）。
    pub fn on_timeout(&mut self) {
        self.rto_us = self.clamp(self.rto_us as u64 * 2);
    }

    /// 收到新数据的 ACK 后，若此前因超时退避过，RFC 6298 (5.7) 要求保持退避值直到下一个**干净样本**；
    /// 本实现不额外重置——下一次 `on_sample` 会重新计算。
    pub fn is_backed_off(&self) -> bool {
        self.have_sample && self.rto_us > self.clamp(self.srtt_us as u64 + (4u64 * self.rttvar_us as u64).max(self.granularity_us as u64))
    }
}
