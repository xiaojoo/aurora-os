//! ADR-110 决策 1：块请求层——在 `Block` **之上**逐扇区提交，带死线、取消与半途读数。
//!
//! 为什么放在 `Block` 之上而不是塞进每个驱动：`Block` 的四个实现（`AhciDisk`、`MemDisk`、
//! `PartitionView`、ktest 的 `TestDisk`）各自只该回答"这一扇区读成了没有"。死线、取消与
//! "失败时已经落地几个扇区"是**调用方的策略**，每个驱动各写一份就是四份会漂的算术。
//!
//! 三条语义（ADR-110 写死的那三条）：
//! 1. **逐扇区提交**：`Outcome::sectors_done` 是"真落了地的扇区数"，失败时小于请求数；
//!    "半途放弃"与"整条没发"靠这个数分开。
//! 2. **取消只在扇区边界生效**：下一扇区不再下发，`error = Some(Refused)`（复用，不新增变体）。
//!    不在占用中撤销——那要驱动支持，属于 110-b。
//! 3. **错误归因不合并**：盘给的 `BlockError` 原样带出，`sectors_done` 与它一起上报；
//!    句柄层再走 ADR-108 的映射。
//!
//! 时钟由 `Budget` 注入（用户裁决 2026-11-16：**用 tick，不用 TSC**；本仓库多处记过
//! QEMU 下 TSC 不稳）。`block_io` 不依赖 `sched`：调用方把"读 tick 的函数"放进 `Budget`，
//! 全不设死线时（`deadline == u64::MAX`）这个函数一次都不会被调。

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::vfs::{Block, BlockError, DiskKey, SECTOR_BYTES};

/// 一次请求的预算。`deadline` 是**绝对 tick**，`clock` 是"现在几点"的注入源；
/// `cancel` 指向调用方那一格旗（通常是它自己任务里的一个 `AtomicBool`）。
pub struct Budget<'a> {
    pub deadline: u64,
    pub clock: fn() -> u64,
    pub cancel: &'a AtomicBool,
}

static NEVER_CANCEL: AtomicBool = AtomicBool::new(false);

fn no_clock() -> u64 {
    0
}

impl<'a> Budget<'a> {
    /// 没有死线、没有取消位。16 处既有调用点用它接入请求层：读路径的**形状**先统一，
    /// 死线与取消由真正需要的调用方（今天只有判据；将来是 23 号/异步路径）自己构造。
    pub const UNBOUNDED: Budget<'static> = Budget {
        deadline: u64::MAX,
        clock: no_clock,
        cancel: &NEVER_CANCEL,
    };
}

/// 一次请求的结果。`error == None` 当且仅当 `sectors_done == 请求的扇区数`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub sectors_done: u32,
    pub error: Option<BlockError>,
}

/// 五计数（ADR-110 / ADR-113）。**按盘分桶**：桶由 `Block::disk_key()` 决定。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// 调用次数（形状被拒的也算——它是"试过"，不是"没发生"）
    pub requests: u64,
    /// 真落了地的扇区数
    pub sectors_ok: u64,
    /// 撞死线而停的次数
    pub timeouts: u64,
    /// 观察到取消位而停的次数
    pub cancels: u64,
    /// 形状被拒（空/非整扇区/`lba` 越界）的次数
    pub refused: u64,
}

struct Bucket {
    requests: AtomicU64,
    sectors_ok: AtomicU64,
    timeouts: AtomicU64,
    cancels: AtomicU64,
    refused: AtomicU64,
}

impl Bucket {
    const fn new() -> Self {
        Bucket {
            requests: AtomicU64::new(0),
            sectors_ok: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            cancels: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        }
    }
}

/// 桶号：Unknown=0、Ahci(p)=1+p(0..31)、Virtio(i)=33+i(0..7)、Mem=41。
/// 超出表宽的 key 折回 0——宁可少数一台，也不越界写静态。
const BUCKETS: usize = 42;
static STATS: [Bucket; BUCKETS] = [const { Bucket::new() }; BUCKETS];

fn bucket_of(k: DiskKey) -> &'static Bucket {
    let i = match k {
        DiskKey::Unknown => 0,
        DiskKey::Ahci(p) => 1 + (p as usize & 31),
        DiskKey::Virtio(v) => 33 + (v as usize & 7),
        DiskKey::Mem => 41,
    };
    &STATS[i]
}

/// 全部桶的合计（既有判据读的就是这个数，语义不变）。
pub fn stats() -> Stats {
    let mut s = Stats::default();
    for b in STATS.iter() {
        s.requests += b.requests.load(Ordering::Relaxed);
        s.sectors_ok += b.sectors_ok.load(Ordering::Relaxed);
        s.timeouts += b.timeouts.load(Ordering::Relaxed);
        s.cancels += b.cancels.load(Ordering::Relaxed);
        s.refused += b.refused.load(Ordering::Relaxed);
    }
    s
}

/// 单台盘的五个数（ADR-113）。读不到的就是 0，不区分"没这台"与"它一次都没动过"。
pub fn stats_of(k: DiskKey) -> Stats {
    let b = bucket_of(k);
    Stats {
        requests: b.requests.load(Ordering::Relaxed),
        sectors_ok: b.sectors_ok.load(Ordering::Relaxed),
        timeouts: b.timeouts.load(Ordering::Relaxed),
        cancels: b.cancels.load(Ordering::Relaxed),
        refused: b.refused.load(Ordering::Relaxed),
    }
}

/// 从 `lba` 读 `dst.len() / 512` 个扇区，逐扇区判取消与死线。
///
/// 顺序是**先判停、再下发**：取消位在上一扇区的驱动里被置起时，这一扇区不再发；
/// 死线同样在扇区边界判。两者都不做"占用中撤销"（那要驱动配合）。
pub fn read_at(disk: &dyn Block, lba: u64, dst: &mut [u8], budget: &Budget<'_>) -> Outcome {
    let b = bucket_of(disk.disk_key());
    b.requests.fetch_add(1, Ordering::Relaxed);
    if dst.is_empty() || dst.len() % SECTOR_BYTES != 0 {
        b.refused.fetch_add(1, Ordering::Relaxed);
        return Outcome { sectors_done: 0, error: Some(BlockError::Refused) };
    }
    let n = (dst.len() / SECTOR_BYTES) as u32;
    let bounded = budget.deadline != u64::MAX;
    for i in 0..n {
        if budget.cancel.load(Ordering::Relaxed) {
            b.cancels.fetch_add(1, Ordering::Relaxed);
            return Outcome { sectors_done: i, error: Some(BlockError::Refused) };
        }
        if bounded && (budget.clock)() >= budget.deadline {
            b.timeouts.fetch_add(1, Ordering::Relaxed);
            return Outcome { sectors_done: i, error: Some(BlockError::NotSettled) };
        }
        let Some(cur) = lba.checked_add(u64::from(i)) else {
            b.refused.fetch_add(1, Ordering::Relaxed);
            return Outcome { sectors_done: 0, error: Some(BlockError::Refused) };
        };
        let off = i as usize * SECTOR_BYTES;
        match disk.read_sectors(cur, &mut dst[off..off + SECTOR_BYTES]) {
            Ok(()) => {
                b.sectors_ok.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => return Outcome { sectors_done: i, error: Some(e) },
        }
    }
    Outcome { sectors_done: n, error: None }
}

/// 既有调用点用的薄包装：只要 `Result`，不要 `Outcome`。
///
/// 它不是"绕过请求层"的路——计数、取消、死线都在 `read_at` 里，这里只是把
/// `Outcome.error` 摊回 `Result`。有意让 `Budget` 出现在签名里：将来接死线的调用点
/// 不该为了这件事再改一次调用形状。
pub fn read_checked(
    disk: &dyn Block,
    lba: u64,
    dst: &mut [u8],
    budget: &Budget<'_>,
) -> Result<(), BlockError> {
    match read_at(disk, lba, dst, budget).error {
        None => Ok(()),
        Some(e) => Err(e),
    }
}
