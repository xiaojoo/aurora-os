//! 资源台账（手册 §6.7 的“按模块标签汇总存活分配”，§9.1 的 L3 资源记账）。
//!
//! 形状由三件事决定，都不是审美：
//! 1. **O(1) 记账**。`phys_alloc` 在页表路径上被调用，台账不能变成线性扫描；
//!    代价是这里只能按 `ModuleId` 聚合，答不出"哪一帧还活着"。要逐句柄追踪得等
//!    M2-c 之后的调试构建专用影子表。
//! 2. **静态容量，按模块号索引**。`MAX_MODULES` 之外的模块号一律拒绝登记并计数，
//!    因为"新模块忘了注册"如果表现成静默不计数，泄漏报告就会永远好看。
//! 3. **不平衡的归还必须当场叫**。free 比 alloc 多就是台账被写坏（或双重释放绕过了
//!    mm 的判定），继续记下去整个模块的存活数都不可信——按 §9.2 这是 L4。
//!
//! 不变量（用例逐条盯）：`Σ live == Σ alloc - Σ free`。

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::mm::ModuleId;
use crate::sync::{self, IrqSpinLock};

pub const MAX_MODULES: usize = 64;

#[derive(Clone, Copy)]
struct Entry {
    live_frames: usize,
    alloc_frames: usize,
    free_frames: usize,
    alloc_calls: usize,
    free_calls: usize,
}

const ZERO: Entry = Entry { live_frames: 0, alloc_frames: 0, free_frames: 0, alloc_calls: 0, free_calls: 0 };

/// 台账本体由 `RANK_LEDGER` 这把锁保护。等级 40 是叶子：它内部不再获取别的锁，
/// 而 `phys_alloc`(PMM 30) 会叫到它里面，所以顺序必须是 30 < 40
/// （依据 `docs/architecture/lock-order.md`）。
/// 条目本身用普通整数而不是原子量：互斥由这把锁提供，原子只会让人误以为
/// "不用锁也行"，那是要命的误导。
static LEDGER: IrqSpinLock<[Entry; MAX_MODULES]> = IrqSpinLock::new(sync::RANK_LEDGER, [ZERO; MAX_MODULES]);

static UNKNOWN_MODULES: AtomicUsize = AtomicUsize::new(0);
static VIOLATION: AtomicBool = AtomicBool::new(false);

/// 记一笔分配。`frames` 是物理页框数（不是字节）。
pub fn account_alloc(m: ModuleId, frames: usize) {
    let idx = m.0 as usize;
    if idx >= MAX_MODULES {
        UNKNOWN_MODULES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mut g = LEDGER.lock();
    let e = &mut g.get()[idx];
    e.alloc_frames += frames;
    e.alloc_calls += 1;
    e.live_frames += frames;
}

/// 记一笔归还。返回 false 表示台账被写坏（free 多于 alloc），调用方升 L4。
pub fn account_free(m: ModuleId, frames: usize) -> bool {
    let idx = m.0 as usize;
    if idx >= MAX_MODULES {
        return true;
    }
    let mut g = LEDGER.lock();
    let e = &mut g.get()[idx];
    if e.live_frames < frames {
        VIOLATION.store(true, Ordering::Release);
        crate::log_fatal!("L4 resource: module {} free {} > live {}", m.0, frames, e.live_frames);
        return false;
    }
    e.free_frames += frames;
    e.free_calls += 1;
    e.live_frames -= frames;
    true
}

#[derive(Clone, Copy)]
pub struct Snapshot {
    pub module: u16,
    pub live_frames: usize,
    pub alloc_frames: usize,
    pub free_frames: usize,
    pub alloc_calls: usize,
}

pub struct Totals {
    pub sum_live: usize,
    pub sum_alloc: usize,
    pub sum_free: usize,
    pub unknown_module_hits: usize,
    pub violation: bool,
}

/// 取第 `i` 个有条目的模块（跳过全零槽位，日志不打印 64 行空账）
pub fn entry(i: usize) -> Option<Snapshot> {
    let mut g = LEDGER.lock();
    let l = g.get();
    let mut seen = 0usize;
    for (idx, e) in l.iter().enumerate() {
        if e.alloc_calls == 0 && e.live_frames == 0 {
            continue;
        }
        if seen == i {
            return Some(Snapshot { module: idx as u16, live_frames: e.live_frames, alloc_frames: e.alloc_frames, free_frames: e.free_frames, alloc_calls: e.alloc_calls });
        }
        seen += 1;
    }
    None
}

pub fn totals() -> Totals {
    let mut g = LEDGER.lock();
    let l = g.get();
    let (mut sl, mut sa, mut sf) = (0usize, 0usize, 0usize);
    for e in l.iter() {
        sl += e.live_frames;
        sa += e.alloc_frames;
        sf += e.free_frames;
    }
    Totals {
        sum_live: sl,
        sum_alloc: sa,
        sum_free: sf,
        unknown_module_hits: UNKNOWN_MODULES.load(Ordering::Relaxed),
        violation: VIOLATION.load(Ordering::Acquire),
    }
}

pub fn live_of(m: ModuleId) -> usize {
    let mut g = LEDGER.lock();
    g.get().get(m.0 as usize).map(|e| e.live_frames).unwrap_or(0)
}
