//! M2-b：内核堆（小对象大小类）+ GlobalAlloc。M3a：加上 `IrqSpinLock`。
//!
//! 本文件的边界是刻意收窄的：
//! * **只做 ≤ 2048 字节的 8 档大小类**。大对象需要长期持有 `mm::Mapping`（它拥有物理页），
//!   而 `GlobalAlloc` 的接口里没有任何地方能安放这个所有权；硬做就只能另建一张全局表，
//!   那张表本身又需要分配器——先不做，`> LARGE_MAX` 一律返回 None，按 ADR-018 变成
//!   可观察的停机，而不是留一条静默坏掉的路。
//! * 不做碎片合并：free 链表只回收同类槽位。后果是 peak/live 比值会暴露碎片，
//!   这是记账不是掩饰（已记 BACKLOG）。
//! * 堆窗口起始处留一整页**永不映射**当 guard；窗口用尽只能返回 None，
//!   不会越过 guard 写出去。
//! * `GlobalAlloc::alloc` 在稳定版上不能返回错误：失败只能走 handle_alloc_error
//!   → panic → panic=abort → L4。需要 `Result` 的调用方必须显式用 `heap::try_alloc`。
//!
//! M3a 的锁带来的不只是"套一层"，而是一次**结构改动**：锁在入口处取一次，然后把
//! `&mut Heap` 显式交给内部函数。之前满篇 `h()` 随手取状态，直接套锁就等于在同一
//! 上下文里重复获取同一把锁——那是自死锁，会被 `sync` 的重入检测当场判 L4。
//! 现在没有任何内部函数自己取锁，"谁持有什么"从签名上就能看出来。

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::mm::{self, MmError, ModuleId, PageFlags, VirtAddr};
use crate::sync::{self, IrqSpinLock};

const CLASSES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];
pub const LARGE_MAX: usize = 2048;
const CHUNK: usize = 4096;
const WINDOW: usize = 4 * 1024 * 1024;
const PREMAP_CHUNKS: usize = 16;

pub const MOD_HEAP_CORE: ModuleId = ModuleId(10);

struct Heap {
    base: usize,
    /// 分配光标：下一个槽位的起点（不保证落在 4 KiB 边界上）
    bump: usize,
    /// **映射前沿**：下一个还没映射的 4 KiB 页。它和 bump 是两条不同的线——
    /// 把它们合成一条是上一版 #PF(err=0x2) 的直接原因：槽位对齐到 cls 后
    /// `bump` 恰好压在页边界上，"是否需要补映射"的判据 `need < aligned` 不成立，
    /// 于是把一个从未映射的页交了出去。
    map_next: usize,
    end: usize,
    free: [usize; CLASSES.len()],
    live_slots: [usize; CLASSES.len()],
}

/// 堆状态整体由这把锁保护。RANK_HEAP=10 是最外层，因为它内部要往下叫
/// VMM/PMM/台账——顺序依据见 `docs/architecture/lock-order.md`。
static HEAP: IrqSpinLock<Heap> = IrqSpinLock::new(
    sync::RANK_HEAP,
    Heap { base: 0, bump: 0, map_next: 0, end: 0, free: [0usize; CLASSES.len()], live_slots: [0usize; CLASSES.len()] },
);

static READY: AtomicBool = AtomicBool::new(false);
static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE_COUNT: AtomicUsize = AtomicUsize::new(0);
static ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static DEALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static OOM_COUNT: AtomicUsize = AtomicUsize::new(0);
/// 因"中断上下文"而被拒绝的分配/释放次数（§6.5 的机制化，正常构建必须是 0）
static ISR_REFUSED: AtomicUsize = AtomicUsize::new(0);

fn class_of(size: usize) -> Option<usize> {
    CLASSES.iter().position(|&c| c >= size)
}

/// 中断上下文守卫；返回 true 表示这次操作**必须被拒绝**。
///
/// 调用位置是硬要求：**必须在取锁之前**。定时器中断随时可能在持锁的临界区里到达，
/// 若 ISR 也来取同一把 `IrqSpinLock`，单核上就是自死锁（IF 已被硬件清零，持有者
/// 不可能让出）——那时表现不是"分配失败"而是整个内核卡在关中断的自旋里。
#[inline]
fn refuse_if_isr(op: &str) -> bool {
    if !crate::arch::x86_64::apic::in_isr() {
        return false;
    }
    crate::arch::x86_64::apic::note_alloc_in_isr();
    let n = ISR_REFUSED.fetch_add(1, Ordering::Relaxed);
    if n < 4 {
        // 只打前四条：这是错误路径，但不能让它变成"把中断窗口拖长"的第二个故障源
        crate::log_fatal!("L3 违规：中断上下文里尝试 {}，已拒绝（累计 {} 次）", op, n + 1);
    }
    OOM_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

/// 把映射前沿推到覆盖 `hi`（不含）为止。只在页边界推进：`mm::map` 要求 VA 4 KiB 对齐。
///
/// 两条纪律：**判据只有 `map_next < hi` 这一条**（上一版让调用方拿 `bump` 当判据，
/// 两者一脱钩就把未映射的页发出去）；`st` 必须由持锁的调用方交进来，本函数不取锁。
enum Grow {
    Covered,
    /// 窗口用尽或物理页耗尽：调用方转成可观察的 OOM 计数
    Out,
}

/// ADR-081 决策 4：增长的**核**不碰 `Heap`，只吃/吐前沿值 ⇒ 调用方可以在**不持 HEAP** 时调它。
/// GROW 锁保证同一时刻只有一个 CPU 在增长，所以 `map_next` 在核运行期间不会被别人改。
fn grow_core(mut map_next: usize, end: usize, hi: usize) -> (usize, Grow) {
    while map_next < hi {
        let at = map_next;
        if at + CHUNK > end {
            return (map_next, Grow::Out);
        }
        let frames = match mm::phys_alloc(0, MOD_HEAP_CORE) {
            Ok(f) => f,
            Err(_) => return (map_next, Grow::Out),
        };
        let Some(va) = VirtAddr::new(at as u64) else { return (map_next, Grow::Out) };
        // Mapping 必须活到堆结束为止：forget 交出所有权，物理页就此长期占用（设计上如此）
        match mm::map(va, frames, PageFlags::RW) {
            Ok(m) => {
                core::mem::forget(m);
                map_next = at + CHUNK;
            }
            // 窗口是自己 reserve 下来的，这里读到 AlreadyMapped 只可能是别的代码
            // 绕过登记表写进了来。继续跑等于同一物理页有两个主人，按 §9.2 升 L4。
            Err(MmError::AlreadyMapped) => {
                crate::log_fatal!("L4: heap window at {:#x} was mapped by someone else", at);
                crate::exit::finish(crate::exit::Code::ExceptionFatal);
            }
            Err(_) => return (map_next, Grow::Out),
        }
    }
    (map_next, Grow::Covered)
}

/// `init()` 用的薄包装（ADR-081 决策 5：启动期单核、无竞争，**故意**保持持 HEAP 增长）。
fn map_more_through(st: &mut Heap, hi: usize) -> Grow {
    let (next, g) = grow_core(st.map_next, st.end, hi);
    st.map_next = next;
    g
}

/// 堆增长锁（ADR-081 决策 4）。**只保护"增长"这件事**，不保护堆状态本身（那是 HEAP）。
/// 必须**先于 HEAP** 取（4 → 10 严格递增），所以调用方要先放掉 HEAP 再来取它。
static GROW: IrqSpinLock<()> = IrqSpinLock::new(sync::RANK_GROW, ());

/// 需要增长时的分配路径：GROW(4) → HEAP(10) 读快照 → 放 HEAP → 只持 GROW 映射 → 再取 HEAP 提交+bump。
/// 进来时**不得持任何锁**（调用方已 drop HEAP）。
fn grow_and_alloc(ci: usize, cls: usize) -> Option<*mut u8> {
    let _grow = GROW.lock();
    let mut g = HEAP.lock();
    let (mut next, end) = (g.get().map_next, g.get().end);
    let mut aligned = ((g.get().bump + cls - 1) / cls) * cls;
    if aligned + cls > end {
        drop(g);
        OOM_COUNT.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    if next < aligned + cls {
        // 放掉 HEAP 再映射：等 VMM 时只持 GROW(4)，满足 ADR-081 决策 1 的条件 2。
        drop(g);
        let (n, r) = grow_core(next, end, aligned + cls);
        next = n;
        g = HEAP.lock();
        g.get().map_next = next;
        if let Grow::Out = r {
            drop(g);
            OOM_COUNT.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        // 不拿旧快照当依据：按当前 bump 重算一次（bump 只在持 HEAP 时推进，这里仍重算以保守）。
        aligned = ((g.get().bump + cls - 1) / cls) * cls;
        if aligned + cls > g.get().map_next {
            drop(g);
            OOM_COUNT.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    }
    let st = g.get();
    st.bump = aligned + cls;
    st.live_slots[ci] += 1;
    drop(g);
    bump_counters(cls);
    Some(aligned as *mut u8)
}

/// 初始化堆。返回预映射的 chunk 数，供启动日志与 P 基线用。
pub fn init() -> Result<usize, MmError> {
    // 窗口必须**先登记再使用**：否则 mm 的空闲页扫描会把堆窗口内部的页当未映射发出去
    let win = mm::alloc_va_range(WINDOW / mm::PAGE).ok_or(MmError::OutOfMemory)?;
    let mut g = HEAP.lock();
    let st = g.get();
    st.base = win.0 as usize + mm::PAGE; // 窗口第一页留作 guard，永不映射
    st.bump = st.base;
    st.map_next = st.base;
    st.end = win.0 as usize + WINDOW;
    if let Grow::Out = map_more_through(st, st.base + PREMAP_CHUNKS * CHUNK) {
        return Err(MmError::OutOfMemory);
    }
    let mapped = (st.map_next - st.base) / CHUNK;
    if mapped == 0 {
        return Err(MmError::OutOfMemory);
    }
    READY.store(true, Ordering::Release);
    Ok(mapped)
}

pub fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// 不变量：分配光标走过的每一页都必须**真的映射过**。
///
/// 这条单独成为一个用例，因为上一版违反它的现象是"写在未映射页上的 #PF"，
/// 从故障现场看不出错在分配器的判据里。只比 `map_next >= bump` 是用同一把尺子
/// 量自己，所以这里逐页问页表。
pub fn frontier_covered() -> bool {
    let mut g = HEAP.lock();
    let st = g.get();
    if st.base == 0 || st.map_next < st.bump || st.bump > st.end {
        return false;
    }
    let mut va = st.base;
    while va < st.bump {
        if !mm::is_mapped(va as u64) {
            return false;
        }
        va += mm::PAGE;
    }
    // guard 页：窗口第一页（base 之前那一页）永远不该被映射
    !mm::is_mapped((st.base - mm::PAGE) as u64)
}

pub struct Stats {
    pub live_bytes: usize,
    pub peak_bytes: usize,
    pub live_count: usize,
    pub alloc_calls: usize,
    pub dealloc_calls: usize,
    pub oom_count: usize,
    pub isr_refused: usize,
    /// 分配光标走过的字节
    pub window_used: usize,
    /// 实际映射过的字节（映射前沿）——它必须恒 >= window_used，
    /// 不相等的那一刻就是双重记账/光标脱钩的现场
    pub window_mapped: usize,
    pub free_slots: usize,
}

pub fn stats() -> Stats {
    let mut g = HEAP.lock();
    let st = g.get();
    Stats {
        live_bytes: LIVE_BYTES.load(Ordering::Relaxed),
        peak_bytes: PEAK_BYTES.load(Ordering::Relaxed),
        live_count: LIVE_COUNT.load(Ordering::Relaxed),
        alloc_calls: ALLOC_CALLS.load(Ordering::Relaxed),
        dealloc_calls: DEALLOC_CALLS.load(Ordering::Relaxed),
        oom_count: OOM_COUNT.load(Ordering::Relaxed),
        isr_refused: ISR_REFUSED.load(Ordering::Relaxed),
        window_used: st.bump - st.base,
        window_mapped: st.map_next - st.base,
        free_slots: st.free.iter().map(|&f| usize::from(f != 0)).sum(),
    }
}

/// 显式可失败分配：需要把失败当 L3 资源错误往上传的调用方走这里（ADR-018）
pub fn try_alloc(layout: Layout) -> Option<*mut u8> {
    if refuse_if_isr("分配") {
        return None;
    }
    if !is_ready() || layout.size() == 0 || layout.size() > LARGE_MAX || layout.align() > 16 {
        OOM_COUNT.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let ci = class_of(layout.size())?;
    let cls = CLASSES[ci];
    ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);

    let mut g = HEAP.lock();
    let st = g.get();

    // 1) 自由链表命中
    if st.free[ci] != 0 {
        let p = st.free[ci];
        // SAFETY: 槽位至少 16 字节，链指针存在上一次释放时写入的前 8 字节里
        st.free[ci] = unsafe { *(p as *const usize) };
        st.live_slots[ci] += 1;
        drop(g);
        bump_counters(cls);
        return Some(p as *mut u8);
    }

    // 2) 从 bump 区切一个槽位。**先按槽位末（aligned + cls）把映射补足**，
    //    再推进光标；顺序反过来就会把跨页的槽位发到未映射的页上。
    let aligned = ((st.bump + cls - 1) / cls) * cls;
    if aligned + cls > st.end {
        drop(g);
        OOM_COUNT.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    if st.map_next < aligned + cls {
        // ADR-081 决策 4：增长移出 HEAP 临界区（GROW 必须先于 HEAP 取，所以先放锁）。
        drop(g);
        return grow_and_alloc(ci, cls);
    }
    st.bump = aligned + cls;
    st.live_slots[ci] += 1;
    drop(g);
    bump_counters(cls);
    Some(aligned as *mut u8)
}

fn bump_counters(cls: usize) {
    let live = LIVE_BYTES.fetch_add(cls, Ordering::Relaxed) + cls;
    PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
    LIVE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// 归还小对象槽位（不合并，进同类自由链表）
pub unsafe fn dealloc_small(ptr: *mut u8, size: usize) -> bool {
    let Some(ci) = class_of(size) else { return false };
    if refuse_if_isr("释放") {
        return false;
    }
    let mut g = HEAP.lock();
    let st = g.get();
    let p = ptr as usize;
    if p < st.base || p >= st.bump {
        return false;
    }
    let cls = CLASSES[ci];
    // SAFETY: 槽位至少 16 字节，且此后再无人持有该指针（调用方契约）
    unsafe { *(ptr as *mut usize) = st.free[ci] };
    st.free[ci] = p;
    st.live_slots[ci] = st.live_slots[ci].saturating_sub(1);
    drop(g);
    LIVE_BYTES.fetch_sub(cls, Ordering::Relaxed);
    LIVE_COUNT.fetch_sub(1, Ordering::Relaxed);
    DEALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
    true
}

/// 故障注入（§7.1 R16 / §12.3 R19）：在**同一上下文**里重复获取堆锁。
///
/// 单核上这就是自死锁：第一次获取把 IF 清了，持有者不可能让出，第二次获取只能
/// 一直关中断自旋。`held_by` 用的是 CPU 号而不是栈帧地址，正是为了在这种
/// "同一个 CPU 的第二个栈帧"场景下也能认出来（见 sync::cpu_token 的注释）。
#[cfg(feature = "fault-lock-reentrant")]
pub fn force_reentrant_lock_for_test() {
    let _g1 = HEAP.lock();
    let _g2 = HEAP.lock();
    crate::log_fatal!("fault-lock-reentrant: 重入获取没有被抓住，§7.1 的检测是假的");
    crate::exit::finish(crate::exit::Code::Failed);
}

/// 故障注入（ADR-081 决策 4）：同一上下文重复获取 GROW(4)。形状与 `force_reentrant_lock_for_test`
/// 逐字同型——新锁必须自带重入负样本，否则"rank 4 填对了"这句话没有证据可指（硬约束 4）。
#[cfg(feature = "fault-grow-reentrant")]
pub fn force_reentrant_grow_for_test() {
    let _g1 = GROW.lock();
    let _g2 = GROW.lock();
    crate::log_fatal!("fault-grow-reentrant: 重入获取没有被抓住，§7.1 的检测是假的");
    crate::exit::finish(crate::exit::Code::Failed);
}

pub struct AuroraGlobal;

unsafe impl GlobalAlloc for AuroraGlobal {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // 返回空指针 = 走 handle_alloc_error = L4。这是稳定版接口给的唯一选项，
        // 不是我们的选择；要 Result 请用 heap::try_alloc（ADR-018）。
        try_alloc(layout).unwrap_or(core::ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        // SAFETY: 本函数契约由调用方（全局分配器）保证 ptr 来自同一次 alloc
        if !unsafe { dealloc_small(ptr, layout.size()) } {
            crate::log_fatal!("L4: dealloc 参数无法归入任何大小类 size={} ptr={:p}", layout.size(), ptr);
            crate::exit::finish(crate::exit::Code::ExceptionFatal);
        }
    }
}
