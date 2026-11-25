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

    /// 有没有可能被取消（ADR-194）。
    ///
    /// 合并窗口用它决定段长：有取消位时段要短，否则取消要等一整个大段读完。
    /// 判据是「指针不是那个永假静态量」——**不是**读它的值（值随时可能被置位，
    /// 而「会不会被取消」是构造时决定的）。
    #[inline]
    pub fn has_cancel(&self) -> bool {
        !core::ptr::eq(self.cancel, &NEVER_CANCEL)
    }
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

/// 桶号：Unknown=0、Ahci(p)=1+p(0..31)、Virtio(i)=33+i(0..7)、Mem=41、
/// Nvme(s)=42+s(0..1)。
///
/// **2026-11-20（ADR-169）：42 → 44**，给 NVMe 两格。
/// 只留 2 格是因为 NVMe 表化（多台）还没做——把 8 格留给一个不存在的场景
/// 是过度设计；真要多台时再扩，扩桶表是纯机械改动。
///
/// 「超出表宽的 key 折回 0」那条规则是为了**不越界写静态**，
/// 不是为了**让新设备默默消失**：新设备必须有自己的桶，否则它的请求计数永远读不到。
const BUCKETS: usize = 44;
static STATS: [Bucket; BUCKETS] = [const { Bucket::new() }; BUCKETS];

fn bucket_index(k: DiskKey) -> usize {
    match k {
        DiskKey::Unknown => 0,
        DiskKey::Ahci(p) => 1 + (p as usize & 31),
        DiskKey::Virtio(v) => 33 + (v as usize & 7),
        DiskKey::Mem => 41,
        // 今天只支持单台 NVMe，所以 & 1 只是防越界；表化时把 1 改大。
        DiskKey::Nvme(s) => 42 + (s as usize & 1),
    }
}

fn bucket_of(k: DiskKey) -> &'static Bucket {
    &STATS[bucket_index(k)]
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
    // **合并传输**（ADR-194）：连续扇区合成一次 `read_sectors`。
    //
    // 第一版逐扇区调（每次 512 字节）⇒ 读 64 KiB 要发 128 条命令，每条约 20 µs，
    // 多花 2.5 ms；而 AHCI 单次能吃 928 扇区。
    //
    // 段长：无界 128 扇区（64 KiB），有死线/取消时 8 扇区（粒度细）。
    // **内联而不抽函数**：抽成 `impl Iterator` 会让 `.text` 布局变化，
    // 实测那个变化触发了收尾路径的 `unexpected vector=13`（本轮踩过）。
    // **有死线或取消位时，段长必须是 1**（ADR-194 补记）：
    //
    // 第一版写 8，实测 `t_block_io_budget` 的「半途」与「取消」两格都变 false ——
    // 因为取消只在**段边界**检查，段长 8 意味着最坏要等 8 个扇区读完才停。
    // 而那两个判据要求的是「读了几扇区就停在第几扇区」。
    //
    // 合并只在**完全无界**时做：那时没有任何东西要求中途停。
    // 段长 = min(设备上限, 128)；有死线/取消时压到 1（见上面那条补记）。
    let dev_cap = disk.max_transfer_sectors().max(1).min(128);
    let cap: u32 = if budget.deadline == u64::MAX && !budget.has_cancel() {
        dev_cap
    } else {
        1
    };
    let mut done = 0u32;
    while done < n {
        let mut take = (n - done).min(cap);
        while take > 0 && lba.checked_add(u64::from(done) + u64::from(take)).is_none() {
            take -= 1;
        }
        if take == 0 {
            b.refused.fetch_add(1, Ordering::Relaxed);
            return Outcome { sectors_done: done, error: Some(BlockError::Refused) };
        }
        let at = lba + u64::from(done);
        if budget.cancel.load(Ordering::Relaxed) {
            b.cancels.fetch_add(1, Ordering::Relaxed);
            return Outcome { sectors_done: done, error: Some(BlockError::Refused) };
        }
        if bounded && (budget.clock)() >= budget.deadline {
            b.timeouts.fetch_add(1, Ordering::Relaxed);
            return Outcome { sectors_done: done, error: Some(BlockError::NotSettled) };
        }
        let off = done as usize * SECTOR_BYTES;
        let end = off + take as usize * SECTOR_BYTES;
        match disk.read_sectors(at, &mut dst[off..end]) {
            Ok(()) => {
                b.sectors_ok.fetch_add(take as u64, Ordering::Relaxed);
                done += take;
            }
            Err(e) if take > 1 => {
                // **段读失败时退回逐扇区**（ADR-194 补记）：
                //
                // 合并把「第 3 个扇区坏」变成「整段失败」⇒ `sectors_done` 语义变了。
                // 实测 `t_block_io_budget` 的「半途」那一格：期望 `sectors_done=2`，
                // 合并后拿到 0。
                //
                // 退回逐扇区重试这一段，保住原语义（代价只在**出错路径**上）。
                let mut k = 0u32;
                while k < take {
                    let so = off + k as usize * SECTOR_BYTES;
                    match disk.read_sectors(at + u64::from(k), &mut dst[so..so + SECTOR_BYTES]) {
                        Ok(()) => {
                            b.sectors_ok.fetch_add(1, Ordering::Relaxed);
                            done += 1;
                            k += 1;
                        }
                        Err(e2) => {
                            return Outcome { sectors_done: done, error: Some(e2) };
                        }
                    }
                }
            }
            Err(e) => return Outcome { sectors_done: done, error: Some(e) },
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

// ---------------------------------------------------------------- ADR-214：请求队列

/// 队列容量（ADR-214）。
///
/// ## 为什么是 32
///
/// 每条 `Request` 约 40 字节 ⇒ 32 条 = **1.25 KiB**，进 `.bss` 可忽略。
///
/// 需求侧：一次文件读可能拆成十几条块请求（FAT 链跳转 + 目录项扫描），
/// 32 覆盖「一条路径解析」的量级。满了 `submit` 回 `None`（不静默丢弃）。
pub const QUEUE_MAX: usize = 32;

/// 一条待执行的请求（ADR-214）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub lba: u64,
    pub sectors: u32,
    /// 调用方的标识（回调时原样带回）。**不解释它的含义** —— 那是调用方的事。
    pub token: u64,
    /// 提交顺序（用于稳定排序：同 LBA 时保持提交序）。
    pub seq: u32,
}

/// 队列的执行结果（ADR-214）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrainReport {
    /// 实际下发的请求数（合并之后）。
    pub issued: u32,
    /// 合并掉了多少条（原始提交数 - issued）。
    pub merged: u32,
    /// 成功完成的扇区总数。
    pub sectors_ok: u64,
    /// 第一条失败的请求（`None` = 全成功）。
    pub failed_at: Option<u64>,
}

struct Queue {
    items: [Request; QUEUE_MAX],
    /// 已入队的条数（未排序）。
    len: usize,
    /// 提交序号（单调递增，用于稳定排序）。
    seq: u32,
    /// 累计统计（判据用）。
    submitted: u32,
    drained: u32,
    refused: u32,
}

struct QueueCell(core::cell::UnsafeCell<Queue>);
// SAFETY: 读写全在 `QUEUE_LOCK` 内；载荷全为 Copy。
unsafe impl Sync for QueueCell {}

static QUEUE: QueueCell = QueueCell(core::cell::UnsafeCell::new(Queue {
    items: [Request { lba: 0, sectors: 0, token: 0, seq: 0 }; QUEUE_MAX],
    len: 0,
    seq: 0,
    submitted: 0,
    drained: 0,
    refused: 0,
}));

/// 队列的锁。**叶子锁**：临界区里只读写那 32 条 `Request`。
static QUEUE_LOCK: crate::sync::IrqSpinLock<()> =
    crate::sync::IrqSpinLock::new(crate::sync::RANK_BLOCK, ());

/// **提交一条请求**（ADR-214）。
///
/// 返回 `false` = 队列满（**不静默丢弃**，调用方必须处理）。
///
/// ## 为什么不在这里执行
///
/// 与 ADR-201 的定时器同一条纪律：**入队与执行分开**。
/// 入队要能在任何上下文（包括中断）里做；执行要碰设备。
pub fn submit(lba: u64, sectors: u32, token: u64) -> bool {
    if sectors == 0 {
        return false;
    }
    let _g = QUEUE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &mut *QUEUE.0.get() };
    if q.len >= QUEUE_MAX {
        q.refused += 1;
        return false;
    }
    q.seq = q.seq.wrapping_add(1);
    q.items[q.len] = Request { lba, sectors, token, seq: q.seq };
    q.len += 1;
    q.submitted += 1;
    true
}

/// 队列里排着几条（判据用）。
pub fn pending() -> usize {
    let _g = QUEUE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    unsafe { (*QUEUE.0.get()).len }
}

/// `(提交, 执行, 拒收)` 累计（判据用）。
pub fn queue_stats() -> (u32, u32, u32) {
    let _g = QUEUE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &*QUEUE.0.get() };
    (q.submitted, q.drained, q.refused)
}

/// 清空队列（判据用）。
pub fn queue_clear() {
    let _g = QUEUE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &mut *QUEUE.0.get() };
    q.len = 0;
    q.seq = 0;
    q.submitted = 0;
    q.drained = 0;
    q.refused = 0;
}

/// **把队列排序并合并相邻请求**（ADR-214）。
///
/// ## 排序：按 LBA 升序，同 LBA 按提交序
///
/// 这是**电梯算法的静态形态**：把「按提交顺序下发」换成「按盘上位置下发」，
/// 减少磁头/寻道来回（对 AHCI 是减少命令切换，对真盘是减少寻道）。
///
/// 同 LBA 按提交序保持**稳定**：判据要能预期输出。
///
/// ## 合并规则
///
/// 两条请求满足「前一条的末尾 == 后一条的开头」就合并成一条。
/// 合并后 `token` 取**前一条的** —— 这是有意的简化：一条合并请求只回调一次，
/// 用第一个提交者的 token。已写进未决 1。
fn sort_and_merge(items: &mut [Request], len: usize) -> usize {
    // 插入排序：len <= 32，且它**稳定**（同 LBA 保持提交序）。
    for i in 1..len {
        let key = items[i];
        let mut j = i;
        while j > 0 {
            let prev = items[j - 1];
            let swap = prev.lba > key.lba || (prev.lba == key.lba && prev.seq > key.seq);
            if !swap {
                break;
            }
            items[j] = items[j - 1];
            j -= 1;
        }
        items[j] = key;
    }
    // 合并相邻
    let mut out = 0usize;
    for i in 0..len {
        if out > 0 {
            let prev = items[out - 1];
            if let Some(end) = prev.lba.checked_add(u64::from(prev.sectors)) {
                if end == items[i].lba {
                    if let Some(sectors) = prev.sectors.checked_add(items[i].sectors) {
                        items[out - 1].sectors = sectors;
                        continue;
                    }
                }
            }
        }
        items[out] = items[i];
        out += 1;
    }
    out
}

#[cfg(feature = "handles")]
fn t_block_merge_overflow() -> bool {
    let mut items = [Request { lba: 0, sectors: 0, token: 0, seq: 0 }; 2];
    items[0] = Request { lba: 0, sectors: u32::MAX, token: 1, seq: 1 };
    items[1] = Request { lba: u32::MAX as u64, sectors: 1, token: 2, seq: 2 };
    let issued = sort_and_merge(&mut items, 2);
    let ok = issued == 2 && items[0].sectors == u32::MAX && items[1].sectors == 1;
    crate::log_info!("block-merge-overflow: 不合并={} 前请求完整={} 后请求完整={} ⇒ {}",
        issued == 2, items[0].sectors == u32::MAX, items[1].sectors == 1, ok);
    ok
}
#[cfg(feature = "handles")]
crate::ktest!(KT_BLOCK_MERGE_OVERFLOW, t_block_merge_overflow);

/// **执行整个队列**（ADR-214）。
///
/// 排序 → 合并 → 逐条调 `disk.read_sectors`（经 `read_at` 保留死线/取消语义）。
///
/// 返回执行报告；**第一条失败就停**（不继续发后面的，因为失败通常意味着盘没了）。
pub fn drain(disk: &dyn Block, budget: &Budget<'_>) -> DrainReport {
    let mut items = [Request { lba: 0, sectors: 0, token: 0, seq: 0 }; QUEUE_MAX];
    let len = {
        let _g = QUEUE_LOCK.lock();
        // SAFETY: 持锁期间独占。
        let q = unsafe { &mut *QUEUE.0.get() };
        let n = q.len;
        items[..n].copy_from_slice(&q.items[..n]);
        q.len = 0;
        q.drained += 1;
        n
    };
    if len == 0 {
        return DrainReport { issued: 0, merged: 0, sectors_ok: 0, failed_at: None };
    }
    let issued = sort_and_merge(&mut items, len);
    let mut sectors_ok = 0u64;
    let mut failed_at = None;
    for i in 0..issued {
        let r = items[i];
        // 逐扇区读（保持 `read_at` 的死线/取消语义）
        let mut buf = [0u8; 512];
        let mut done = 0u32;
        while done < r.sectors {
            let out = read_at(disk, r.lba + u64::from(done), &mut buf, budget);
            if let Some(e) = out.error {
                sectors_ok += u64::from(done);
                failed_at = Some(r.token);
                break;
            }
            done += 1;
        }
        if failed_at.is_some() {
            break;
        }
        sectors_ok += u64::from(r.sectors);
    }
    DrainReport {
        issued: issued as u32,
        merged: (len - issued) as u32,
        sectors_ok,
        failed_at,
    }
}

// ---------------------------------------------------------------- ADR-215：完成回调

/// 完成回调的签名（ADR-215）。
///
/// 收「原始提交者的 token」与「结果」。**不回传数据** —— 数据在调用方自己的缓冲里，
/// 回调只负责「好了/错了」。
pub type OnComplete = fn(token: u64, result: Result<u32, BlockError>);

/// 带回调的请求（ADR-215）。
#[derive(Clone, Copy)]
pub struct Pending {
    pub req: Request,
    pub cb: Option<OnComplete>,
}

struct CbQueue {
    items: [Pending; QUEUE_MAX],
    len: usize,
    seq: u32,
    /// 回调投递计数（判据用）。
    delivered: u32,
    /// 回调失败计数。
    failed: u32,
}

struct CbQueueCell(core::cell::UnsafeCell<CbQueue>);
// SAFETY: 读写全在 `CB_LOCK` 内；载荷全为 Copy。
unsafe impl Sync for CbQueueCell {}

static CB_QUEUE: CbQueueCell = CbQueueCell(core::cell::UnsafeCell::new(CbQueue {
    items: [Pending {
        req: Request { lba: 0, sectors: 0, token: 0, seq: 0 },
        cb: None,
    }; QUEUE_MAX],
    len: 0,
    seq: 0,
    delivered: 0,
    failed: 0,
}));

static CB_LOCK: crate::sync::IrqSpinLock<()> =
    crate::sync::IrqSpinLock::new(crate::sync::RANK_BLOCK, ());

/// **提交一条带回调的请求**（ADR-215）。
///
/// ## 与 `submit` 的区别
///
/// `submit` 的完成是 `drain` 的返回值（汇总）；这里的完成是**逐条回调**。
///
/// 两个队列分开，是因为它们的语义不同：
///
/// - `QUEUE` 是「批量提交、一次执行、一个汇总」；
/// - `CB_QUEUE` 是「逐条提交、逐条回调」。
///
/// **混在一起会让「谁的回调该被调」变得含糊。**
pub fn submit_with_cb(lba: u64, sectors: u32, token: u64, cb: OnComplete) -> bool {
    if sectors == 0 {
        return false;
    }
    let _g = CB_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &mut *CB_QUEUE.0.get() };
    if q.len >= QUEUE_MAX {
        return false;
    }
    q.seq = q.seq.wrapping_add(1);
    q.items[q.len] = Pending {
        req: Request { lba, sectors, token, seq: q.seq },
        cb: Some(cb),
    };
    q.len += 1;
    true
}

/// 带回调的队列里排着几条。
pub fn cb_pending() -> usize {
    let _g = CB_LOCK.lock();
    // SAFETY: 持锁期间独占。
    unsafe { (*CB_QUEUE.0.get()).len }
}

/// `(投递, 失败)` 累计（判据用）。
pub fn cb_stats() -> (u32, u32) {
    let _g = CB_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &*CB_QUEUE.0.get() };
    (q.delivered, q.failed)
}

/// 清空带回调的队列（判据用）。
pub fn cb_clear() {
    let _g = CB_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &mut *CB_QUEUE.0.get() };
    q.len = 0;
    q.seq = 0;
    q.delivered = 0;
    q.failed = 0;
}

/// **执行带回调的队列**（ADR-215）：逐条执行、逐条回调。
///
/// ## 回调在锁外调
///
/// **这是本 ADR 最关键的一条**：回调可能再调 `submit_with_cb`（链式请求），
/// 如果在持锁时调，就会自死锁（同 rank 重入）。
///
/// 所以先把队列拷出来、放锁、再逐条执行并回调。
pub fn drain_with_cb(disk: &dyn Block, budget: &Budget<'_>) -> DrainReport {
    let mut items = [Pending {
        req: Request { lba: 0, sectors: 0, token: 0, seq: 0 },
        cb: None,
    }; QUEUE_MAX];
    let len = {
        let _g = CB_LOCK.lock();
        // SAFETY: 持锁期间独占。
        let q = unsafe { &mut *CB_QUEUE.0.get() };
        let n = q.len;
        items[..n].copy_from_slice(&q.items[..n]);
        q.len = 0;
        n
    };
    if len == 0 {
        return DrainReport { issued: 0, merged: 0, sectors_ok: 0, failed_at: None };
    }
    // 排序（与 `drain` 同一套：按 LBA，稳定）
    let mut reqs = [Request { lba: 0, sectors: 0, token: 0, seq: 0 }; QUEUE_MAX];
    for i in 0..len {
        reqs[i] = items[i].req;
    }
    // 手工插入排序（保持 items 与 reqs 同步）
    for i in 1..len {
        let key = items[i];
        let mut j = i;
        while j > 0 {
            let prev = items[j - 1];
            if !(prev.req.lba > key.req.lba || (prev.req.lba == key.req.lba && prev.req.seq > key.req.seq)) {
                break;
            }
            items[j] = items[j - 1];
            j -= 1;
        }
        items[j] = key;
    }
    let mut sectors_ok = 0u64;
    let mut failed_at = None;
    let mut buf = [0u8; 512];
    for i in 0..len {
        let it = items[i];
        let mut done = 0u32;
        let mut err = None;
        while done < it.req.sectors {
            let out = read_at(disk, it.req.lba + u64::from(done), &mut buf, budget);
            if let Some(e) = out.error {
                sectors_ok += u64::from(done);
                err = Some(e);
                break;
            }
            done += 1;
        }
        // **回调在锁外**（见文档注释）
        if let Some(cb) = it.cb {
            match err {
                None => {
                    cb(it.req.token, Ok(it.req.sectors));
                    let _g = CB_LOCK.lock();
                    // SAFETY: 持锁期间独占。
                    unsafe { (*CB_QUEUE.0.get()).delivered += 1; }
                }
                Some(e) => {
                    cb(it.req.token, Err(e));
                    let _g = CB_LOCK.lock();
                    // SAFETY: 持锁期间独占。
                    unsafe { (*CB_QUEUE.0.get()).failed += 1; }
                    if failed_at.is_none() {
                        failed_at = Some(it.req.token);
                    }
                }
            }
        }
        if err.is_none() {
            sectors_ok += u64::from(it.req.sectors);
        }
    }
    let _ = reqs;
    DrainReport { issued: len as u32, merged: 0, sectors_ok, failed_at }
}

// ---------------------------------------------------------------- ADR-251：按目标延迟完成

/// 调用方定义的块地址空间身份。DiskKey 只是统计桶，不能单独区分同口分区或多个 MemDisk。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetId(pub u64);

const EMPTY_REQUEST: Request = Request { lba: 0, sectors: 0, token: 0, seq: 0 };

#[derive(Clone, Copy)]
struct KeyedRequest {
    req: Request,
    target: TargetId,
}

const EMPTY_KEYED: KeyedRequest = KeyedRequest { req: EMPTY_REQUEST, target: TargetId(0) };

struct KeyedQueue {
    items: [KeyedRequest; QUEUE_MAX],
    len: usize,
    seq: u32,
    submitted: u32,
    drained: u32,
    refused: u32,
}

impl KeyedQueue {
    const fn new() -> Self {
        Self {
            items: [EMPTY_KEYED; QUEUE_MAX],
            len: 0,
            seq: 0,
            submitted: 0,
            drained: 0,
            refused: 0,
        }
    }
}

struct KeyedQueueCell(core::cell::UnsafeCell<KeyedQueue>);
// SAFETY: 读写全在既有 QUEUE_LOCK 内；载荷全为 Copy。
unsafe impl Sync for KeyedQueueCell {}

static DISK_QUEUE: KeyedQueueCell = KeyedQueueCell(core::cell::UnsafeCell::new(KeyedQueue::new()));

/// 按目标提交一条批量请求；只入队，不碰设备（ADR-251）。
pub fn submit_for(target: TargetId, lba: u64, sectors: u32, token: u64) -> bool {
    if sectors == 0 {
        return false;
    }
    let _g = QUEUE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &mut *DISK_QUEUE.0.get() };
    if q.len >= QUEUE_MAX {
        q.refused += 1;
        return false;
    }
    q.seq = q.seq.wrapping_add(1);
    q.items[q.len] = KeyedRequest {
        req: Request { lba, sectors, token, seq: q.seq },
        target,
    };
    q.len += 1;
    q.submitted += 1;
    true
}

/// 该目标仍在队列里、尚未被 drain 摘出的请求数；不包含正在执行的快照。
pub fn pending_for(target: TargetId) -> usize {
    let _g = QUEUE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &*DISK_QUEUE.0.get() };
    q.items[..q.len].iter().filter(|r| r.target == target).count()
}

/// 新批量池的 `(提交, drain调用次数, 拒收)` 累计；drained 含空调用。
pub fn disk_queue_stats() -> (u32, u32, u32) {
    let _g = QUEUE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &*DISK_QUEUE.0.get() };
    (q.submitted, q.drained, q.refused)
}

/// 清掉该目标尚未摘出的请求，其他目标原样保留；不清累计统计。
pub fn queue_clear_for(target: TargetId) {
    let _g = QUEUE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &mut *DISK_QUEUE.0.get() };
    let mut out = 0usize;
    for i in 0..q.len {
        let item = q.items[i];
        if item.target != target {
            q.items[out] = item;
            out += 1;
        }
    }
    q.len = out;
}

/// 清空新批量池与累计统计（判据用）。
pub fn disk_queue_clear() {
    let _g = QUEUE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &mut *DISK_QUEUE.0.get() };
    q.len = 0;
    q.seq = 0;
    q.submitted = 0;
    q.drained = 0;
    q.refused = 0;
}

/// 只执行该目标的请求；target 必须唯一对应传入 disk 的地址空间。
pub fn drain_for(target: TargetId, disk: &dyn Block, budget: &Budget<'_>) -> DrainReport {
    let mut items = [EMPTY_REQUEST; QUEUE_MAX];
    let len = {
        let _g = QUEUE_LOCK.lock();
        // SAFETY: 持锁期间独占。
        let q = unsafe { &mut *DISK_QUEUE.0.get() };
        let mut taken = 0usize;
        let mut kept = 0usize;
        for i in 0..q.len {
            let item = q.items[i];
            if item.target == target {
                items[taken] = item.req;
                taken += 1;
            } else {
                q.items[kept] = item;
                kept += 1;
            }
        }
        q.len = kept;
        q.drained += 1;
        taken
    };
    if len == 0 {
        return DrainReport { issued: 0, merged: 0, sectors_ok: 0, failed_at: None };
    }
    let issued = sort_and_merge(&mut items, len);
    let mut sectors_ok = 0u64;
    let mut failed_at = None;
    for i in 0..issued {
        let r = items[i];
        let mut done = 0u32;
        while done < r.sectors {
            let out = read_at(disk, r.lba + u64::from(done), &mut [0u8; SECTOR_BYTES], budget);
            if let Some(e) = out.error {
                sectors_ok += u64::from(done);
                failed_at = Some(r.token);
                break;
            }
            done += 1;
        }
        if failed_at.is_some() {
            break;
        }
        sectors_ok += u64::from(r.sectors);
    }
    DrainReport {
        issued: issued as u32,
        merged: (len - issued) as u32,
        sectors_ok,
        failed_at,
    }
}

/// 带调用方上下文的完成回调；ctx 只按值传递，不做指针解释。
pub type OnCompleteCtx = fn(ctx: u64, token: u64, result: Result<u32, BlockError>);

#[derive(Clone, Copy)]
struct ContextPending {
    req: Request,
    target: TargetId,
    ctx: u64,
    cb: OnCompleteCtx,
}

fn noop_complete_ctx(_: u64, _: u64, _: Result<u32, BlockError>) {}

const EMPTY_CONTEXT: ContextPending = ContextPending {
    req: EMPTY_REQUEST,
    target: TargetId(0),
    ctx: 0,
    cb: noop_complete_ctx,
};

struct ContextQueue {
    items: [ContextPending; QUEUE_MAX],
    len: usize,
    seq: u32,
    delivered: u32,
    failed: u32,
    refused: u32,
}

impl ContextQueue {
    const fn new() -> Self {
        Self {
            items: [EMPTY_CONTEXT; QUEUE_MAX],
            len: 0,
            seq: 0,
            delivered: 0,
            failed: 0,
            refused: 0,
        }
    }
}

struct ContextQueueCell(core::cell::UnsafeCell<ContextQueue>);
// SAFETY: 读写全在既有 CB_LOCK 内；载荷全为 Copy。
unsafe impl Sync for ContextQueueCell {}

static CTX_QUEUE: ContextQueueCell = ContextQueueCell(core::cell::UnsafeCell::new(ContextQueue::new()));

/// 按目标提交一条带上下文的延迟完成请求。
pub fn submit_with_cb_ctx(
    target: TargetId,
    lba: u64,
    sectors: u32,
    token: u64,
    ctx: u64,
    cb: OnCompleteCtx,
) -> bool {
    if sectors == 0 {
        return false;
    }
    let _g = CB_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &mut *CTX_QUEUE.0.get() };
    if q.len >= QUEUE_MAX {
        q.refused += 1;
        return false;
    }
    q.seq = q.seq.wrapping_add(1);
    q.items[q.len] = ContextPending {
        req: Request { lba, sectors, token, seq: q.seq },
        target,
        ctx,
        cb,
    };
    q.len += 1;
    true
}

/// 该目标仍在队列里、尚未被 drain 摘出的请求数；不包含正在回调的快照。
pub fn cb_pending_for(target: TargetId) -> usize {
    let _g = CB_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &*CTX_QUEUE.0.get() };
    q.items[..q.len].iter().filter(|r| r.target == target).count()
}

/// 新上下文池的 `(投递, 失败, 拒收)` 累计。
pub fn ctx_cb_stats() -> (u32, u32, u32) {
    let _g = CB_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &*CTX_QUEUE.0.get() };
    (q.delivered, q.failed, q.refused)
}

/// 清掉该目标尚未摘出的请求，其他目标原样保留；不清累计统计。
pub fn cb_clear_for(target: TargetId) {
    let _g = CB_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &mut *CTX_QUEUE.0.get() };
    let mut out = 0usize;
    for i in 0..q.len {
        let item = q.items[i];
        if item.target != target {
            q.items[out] = item;
            out += 1;
        }
    }
    q.len = out;
}

/// 清空新上下文池与累计统计（判据用）。
pub fn ctx_cb_clear() {
    let _g = CB_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let q = unsafe { &mut *CTX_QUEUE.0.get() };
    q.len = 0;
    q.seq = 0;
    q.delivered = 0;
    q.failed = 0;
    q.refused = 0;
}

/// 显式推进该目标的延迟完成：逐 token 执行并回调，回调全程不持队列锁。
pub fn drain_with_cb_ctx(target: TargetId, disk: &dyn Block, budget: &Budget<'_>) -> DrainReport {
    let mut items = [EMPTY_CONTEXT; QUEUE_MAX];
    let len = {
        let _g = CB_LOCK.lock();
        // SAFETY: 持锁期间独占。
        let q = unsafe { &mut *CTX_QUEUE.0.get() };
        let mut taken = 0usize;
        let mut kept = 0usize;
        for i in 0..q.len {
            let item = q.items[i];
            if item.target == target {
                items[taken] = item;
                taken += 1;
            } else {
                q.items[kept] = item;
                kept += 1;
            }
        }
        q.len = kept;
        taken
    };
    for i in 1..len {
        let key_item = items[i];
        let mut j = i;
        while j > 0 {
            let prev = items[j - 1];
            if !(prev.req.lba > key_item.req.lba
                || (prev.req.lba == key_item.req.lba && prev.req.seq > key_item.req.seq))
            {
                break;
            }
            items[j] = prev;
            j -= 1;
        }
        items[j] = key_item;
    }
    let mut sectors_ok = 0u64;
    let mut failed_at = None;
    let mut buf = [0u8; SECTOR_BYTES];
    for i in 0..len {
        let item = items[i];
        let mut done = 0u32;
        let mut err = None;
        while done < item.req.sectors {
            let out = read_at(disk, item.req.lba + u64::from(done), &mut buf, budget);
            if let Some(e) = out.error {
                sectors_ok += u64::from(done);
                err = Some(e);
                break;
            }
            done += 1;
        }
        let result = match err {
            None => Ok(item.req.sectors),
            Some(e) => Err(e),
        };
        {
            let _g = CB_LOCK.lock();
            // SAFETY: 持锁期间独占。
            let q = unsafe { &mut *CTX_QUEUE.0.get() };
            if err.is_none() {
                q.delivered += 1;
                sectors_ok += u64::from(item.req.sectors);
            } else {
                q.failed += 1;
                if failed_at.is_none() {
                    failed_at = Some(item.req.token);
                }
            }
        }
        // 统计先提交、锁已放；回调重入看到当前请求，panic=abort 边界见 ADR-251。
        (item.cb)(item.ctx, item.req.token, result);
    }
    DrainReport { issued: len as u32, merged: 0, sectors_ok, failed_at }
}
