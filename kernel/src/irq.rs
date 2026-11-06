//! 核内中断认领表：向量 →（处理函数, 主人），外加"设备里该写什么数"由核内算。
//!
//! 为什么这张表在内核而不是在驱动里：向量的**分配**是全局决定（定时器已经占了 `0x20`，
//! IDT 的桩只铺到 `0x2F`），驱动不许自己挑一个数往设备里写；而驱动要写进设备的
//! 消息地址/数据也不该自己算 APIC 魔术——那两串位数算错的方式恰好是"安静地一个中断都不来"。
//! 所以这里发出去的还是 `槽号 + 世代号`（与 `driver.rs` 同一条规矩），
//! 换回来的消息值是核内算的，**并且设备读回来必须等于它**（判据在 `KT_IRQ_AHCI`）。
//!
//! 三条硬性质：
//! 1. **建/撤不许在中断上下文**（§7.1 同一条例，`driver.rs` 的 `map_mmio`/`alloc_dma` 已经有）。
//!    这一条今天只有守卫没有判据——判据要一次"在 ISR 里调用"的注入，排在 M5-g② 之后（BACKLOG 记着）。
//! 2. **处理函数不许分配、不许睡**：它跑在 EOI 之前，用的就是异常栈。
//!    表里放的是函数指针而不是闭包，就是为了这条能被看出来。
//! 3. **归属判断在设备侧**：处理函数返回"这一发是不是我的"。本机 GSI 10/11 各挂两台设备，
//!    将来走 INTx 时这一格就是"读 ISR 位判归属"的落点；今天 MSI 一台一条向量，恒回 true 也能过，
//!    但接口先按共享的形状留出来，免得以后改所有签名。
//!
//! 消息位段（地址 = `0xFEE0_0000 | (目的地 << 12)`，数据低 8 位是向量，其余位 0 =
//! Fixed / 物理目的地 / 边沿 / deassert）**不是抄下规范就算数的**：这台机器上的凭据是
//! "写进设备 → 设备读回来同数 → 设备真发一发 → 内核数到那个向量"。
//! 位数算错不会报错，只会一个中断都不来，所以判据必须是"计数在涨"，而不是"没报错"。

use crate::apic;
use crate::mm::ModuleId;
use crate::trap;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 可分配的向量区间：`0x20` 是定时器（`apic` 里已经编程过），`0x30` 往上没有桩。
const VEC_FIRST: usize = trap::VEC_IRQ_BASE + 1;
const VEC_LAST: usize = trap::VEC_IRQ_LAST;
const SLOTS: usize = VEC_LAST - VEC_FIRST + 1;

/// xAPIC 形态下 MSI 地址的基址前缀（bits 31:20）
const MSI_ADDR_BASE: u32 = 0xFEE0_0000;

/// 要写进设备 MSI 结构的三个 DWORD。64 位形态高半也给出来；设备没那能力时写 0 就行
/// （有没有这个能力由 `pci::Msi::sixtyfour` 说，不靠猜）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msg {
    pub addr_lo: u32,
    pub addr_hi: u32,
    pub data: u32,
}

/// 发给驱动侧的句柄：槽号 + 世代号 + 分到的向量
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle {
    pub slot: u16,
    pub gen: u32,
    pub vector: u8,
}

/// 表里的一项。`calls` 数"这一发到过处理函数手里"，`hits` 数"处理函数认领了它"：
/// 两个数不等就是归属判断在骗人（共享线上这是常态而不是故障）。
struct Entry {
    gen: u32,
    owner: ModuleId,
    handler: fn() -> bool,
    vector: u8,
    /// L3-B：这一颗中断的目的地（本地 APIC id）。默认 = 认领那一刻的 BSP；
    /// 移动它必须由 `set_affinity` 走，因为它一改，`message()` 算出来的地址就得重编程到设备，
    /// 两边不是同一份就会变成"内核以为投给 1 号 CPU、设备还在往 0 号投"。
    dest: u8,
    calls: AtomicUsize,
    hits: AtomicUsize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqError {
    /// 区间内没有空闲向量（本机 15 格）
    Exhausted,
    /// 在中断上下文里建/撤认领
    WrongContext,
    /// 本地 APIC 还没初始化，算不出目的地
    NoApic,
    /// 表里没有这一格
    NoSuchHandle(u16),
    /// 槽号对而世代号不对：这颗中断已撤销，或这一格已换成别人的
    StaleHandle { slot: u16, want: u32, have: u32 },
    /// 句柄是发给别的模块的
    NotOwner { slot: u16, owner: ModuleId },
    /// 这个本地 APIC id 不在这台机的登记表里（写错 id 与写错目的地是两种不同的故障）
    NoSuchCpu(u8),
    /// id 认得出但那颗 CPU 没上线：投给它的中断不会有回执，也不会有任何一台仪器报出来
    Offline(usize),
}

struct Table {
    slots: [Option<Entry>; SLOTS],
    next_gen: u32,
}

impl Table {
    const fn empty() -> Self {
        Self { slots: [const { None }; SLOTS], next_gen: 1 }
    }

    fn fresh_gen(&mut self) -> u32 {
        let g = self.next_gen;
        self.next_gen = if g + 1 == 0 { 1 } else { g + 1 };
        g
    }
}

struct TableCell(UnsafeCell<Table>);
// SAFETY: 与 `driver.rs::TABLE` 同一条理由——写表只发生在 BSP 的驱动初始化与 ktest 序列里，
// 中断上下文在建/撤门口就被 `WrongContext` 挡住；读表方（`dispatch`）只读函数指针并做原子自增。
unsafe impl Sync for TableCell {}
static TABLE: TableCell = TableCell(UnsafeCell::new(Table::empty()));
/// 落进这张表之外的那几发（向量没有主人）。它是"分配与编程两边不一致"的证人。
static UNCLAIMED: AtomicUsize = AtomicUsize::new(0);
/// 被派发到本模块的外部中断总数（含区间外的）
static DISPATCHED: AtomicUsize = AtomicUsize::new(0);
/// **按 CPU** 数认领区间里到过几发。为什么需要这一格：`apic` 那个 16 格计数是全局的，
/// 目的地写错（投到别的核上）时它照样涨，所以"投给了谁"这件事今天没有任何一台仪器能答。
/// M5-g③ 把它与宿主机 `qemu -d int` 数到的投递总数交叉：两个数必须相等，
/// 而非 BSP 那几格必须是 0。
static PER_CPU: [AtomicUsize; crate::cpu::MAX_CPUS] = [const { AtomicUsize::new(0) }; crate::cpu::MAX_CPUS];
/// L3-B：目的地被移动过几次（与"落到哪颗核"分开数，见 `moves()`）。
static MOVES: AtomicUsize = AtomicUsize::new(0);

/// 按 CPU 的投递分布（索引是槽号，不是 LAPIC id）。
pub fn by_cpu() -> [usize; crate::cpu::MAX_CPUS] {
    let mut out = [0usize; crate::cpu::MAX_CPUS];
    for (i, slot) in PER_CPU.iter().enumerate() {
        out[i] = slot.load(Ordering::Relaxed);
    }
    out
}

/// 认领一颗外部中断：在 `0x21..=0x2F` 里找第一个空闲向量并登记处理函数与主人。
pub fn request(owner: ModuleId, handler: fn() -> bool) -> Result<Handle, IrqError> {
    if apic::in_isr() {
        return Err(IrqError::WrongContext);
    }
    // SAFETY: 见 TableCell，写者只有 BSP 的任务上下文
    let t = unsafe { &mut *TABLE.0.get() };
    let Some(slot) = t.slots.iter().position(|e| e.is_none()) else {
        return Err(IrqError::Exhausted);
    };
    let gen = t.fresh_gen();
    let vector = (VEC_FIRST + slot) as u8;
    t.slots[slot] = Some(Entry {
        gen,
        owner,
        handler,
        vector,
        dest: apic::state().map_or(0, |st| st.id as u8),
        calls: AtomicUsize::new(0),
        hits: AtomicUsize::new(0),
    });
    Ok(Handle { slot: slot as u16, gen, vector })
}

/// 撤销认领。**不动设备的 MSI 结构**：谁开的关谁负责关，那是驱动侧的事。
/// 这里只保证旧句柄之后被拒、这一格向量能被下一个人复用。
pub fn release(owner: ModuleId, h: Handle) -> Result<(), IrqError> {
    if apic::in_isr() {
        return Err(IrqError::WrongContext);
    }
    // SAFETY: 见 TableCell
    let t = unsafe { &mut *TABLE.0.get() };
    let i = h.slot as usize;
    if i >= SLOTS {
        return Err(IrqError::NoSuchHandle(h.slot));
    }
    let Some(e) = t.slots[i].as_ref() else {
        return Err(IrqError::NoSuchHandle(h.slot));
    };
    if e.gen != h.gen {
        return Err(IrqError::StaleHandle { slot: h.slot, want: h.gen, have: e.gen });
    }
    if e.owner != owner {
        return Err(IrqError::NotOwner { slot: h.slot, owner: e.owner });
    }
    t.slots[i] = None;
    Ok(())
}

/// 这颗中断要往设备里写的三个 DWORD。目的地取 `apic::state().id`——也就是 BSP 自己：
/// 今天没有中断亲和性这件事，所以"投给谁"必须是读得出来的一个确定数，不能留给读者猜。
pub fn message(h: Handle, owner: ModuleId) -> Result<Msg, IrqError> {
    let Some(st) = apic::state() else { return Err(IrqError::NoApic) };
    let vector = checked(h, owner)?;
    // SAFETY: 见 TableCell；只读
    // SAFETY: 见 TableCell；只读
    let dest = {
        let t = unsafe { &*TABLE.0.get() };
        t.slots[usize::from(vector) - VEC_FIRST].as_ref().map_or(st.id as u8, |e| e.dest)
    };
    Ok(Msg { addr_lo: MSI_ADDR_BASE | (u32::from(dest) << 12), addr_hi: 0, data: u32::from(vector) })
}

/// 换目的地并**把新的那条消息交回**——调用方（驱动）必须立刻把它编程进设备，
/// 否则表里说的与设备发的不是同一颗 CPU（这一句不是提醒，是判据：`KT_IRQ_AFFINITY` 第三格量它）。
///
/// 目的地只认"已经上线的 CPU"，因为把一个中断投给没上机的核，失败形状是"一个中断都不来"，
/// 那种故障没有别的尺子会报出来（§13.1 那条时钟前提之外，这是第二条跨 CPU 的隐含前提）。
pub fn set_affinity(h: Handle, owner: ModuleId, lapic_id: u8) -> Result<Msg, IrqError> {
    if apic::in_isr() {
        return Err(IrqError::WrongContext);
    }
    let vector = checked(h, owner)?;
    let Some(slot) = crate::cpu::slot_of_lapic(u64::from(lapic_id)) else {
        return Err(IrqError::NoSuchCpu(lapic_id));
    };
    if !crate::cpu::is_online(slot) {
        return Err(IrqError::Offline(slot));
    }
    // SAFETY: 见 TableCell；写者只有 BSP 的任务上下文
    let t = unsafe { &mut *TABLE.0.get() };
    let e = t.slots[usize::from(vector) - VEC_FIRST]
        .as_mut()
        .ok_or(IrqError::NoSuchHandle(h.slot))?;
    e.dest = lapic_id;
    MOVES.fetch_add(1, Ordering::Relaxed);
    Ok(Msg { addr_lo: MSI_ADDR_BASE | (u32::from(lapic_id) << 12), addr_hi: 0, data: u32::from(vector) })
}

/// 这颗中断现在的目的地（本地 APIC id）。
pub fn dest(h: Handle, owner: ModuleId) -> Result<u8, IrqError> {
    let vector = checked(h, owner)?;
    // SAFETY: 见 TableCell；只读原子以外的字段
    let t = unsafe { &*TABLE.0.get() };
    t.slots[usize::from(vector) - VEC_FIRST]
        .as_ref()
        .map(|e| e.dest)
        .ok_or(IrqError::NoSuchHandle(h.slot))
}

/// 移动过几次目的地。这一格与"按 CPU 的投递分布"分开数：一个说我们动过没有，一个说动完之后落到哪。
pub fn moves() -> usize {
    MOVES.load(Ordering::Relaxed)
}

/// 这颗中断的两次计数：`(到过处理函数手里的发数, 它认领了的发数)`
pub fn counts(h: Handle, owner: ModuleId) -> Result<(usize, usize), IrqError> {
    let vector = checked(h, owner)?;
    // SAFETY: 见 TableCell；只读原子
    let t = unsafe { &*TABLE.0.get() };
    let e = t.slots[usize::from(vector) - VEC_FIRST].as_ref();
    Ok((
        e.map_or(0, |x| x.calls.load(Ordering::Relaxed)),
        e.map_or(0, |x| x.hits.load(Ordering::Relaxed)),
    ))
}

/// 句柄的三关检查：这一格存在吗、世代号对吗、主人对吗。`owner` 由调用方（`DriverCtx`）带进来，
/// 因为句柄本身只是两个数——把主人塞进句柄就等于把钥匙和门锁做成同一件东西，
/// 跨世代复用那一关（`StaleHandle`）就没法单独证了。
fn checked(h: Handle, owner: ModuleId) -> Result<u8, IrqError> {
    // SAFETY: 见 TableCell
    let t = unsafe { &*TABLE.0.get() };
    let i = h.slot as usize;
    if i >= SLOTS {
        return Err(IrqError::NoSuchHandle(h.slot));
    }
    let Some(e) = t.slots[i].as_ref() else {
        return Err(IrqError::NoSuchHandle(h.slot));
    };
    if e.gen != h.gen {
        return Err(IrqError::StaleHandle { slot: h.slot, want: h.gen, have: e.gen });
    }
    if e.owner != owner {
        return Err(IrqError::NotOwner { slot: h.slot, owner: e.owner });
    }
    Ok(e.vector)
}

/// 这个向量归不归认领表管。`0x20`（定时器）由 `apic` 自己处理，**不许**流进这里：
/// 否则每一次 tick 都会被数成"一发没人认领"，那本账就成了噪声，真正的分配错误反而看不见。
pub fn in_range(vector: usize) -> bool {
    (VEC_FIRST..=VEC_LAST).contains(&vector)
}

/// 收到过但没人认领的那几发：`vector` 落进不了这张表，或表里那一格是空的
pub fn dispatch(vector: usize) -> bool {
    DISPATCHED.fetch_add(1, Ordering::Relaxed);
    if !in_range(vector) {
        UNCLAIMED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    // 先记"到过哪台 CPU"再决定归属：目的地写错的那一发也是真到过，
    // 把它按"没到"数就正好丢掉了 M5-g③ 要抓的那个形状。
    PER_CPU[crate::cpu::self_slot()].fetch_add(1, Ordering::Relaxed);
    // SAFETY: 见 TableCell。这里只读函数指针并做原子自增：不分配、不睡、不碰句柄表以外的写
    let ran = unsafe {
        let t = &*TABLE.0.get();
        match t.slots[vector - VEC_FIRST].as_ref() {
            Some(e) => {
                let mine = (e.handler)();
                e.calls.fetch_add(1, Ordering::Relaxed);
                if mine {
                    e.hits.fetch_add(1, Ordering::Relaxed);
                }
                Some(mine)
            }
            None => None,
        }
    };
    match ran {
        Some(mine) => mine,
        None => {
            UNCLAIMED.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

/// 账本：`(派发到本模块的总发数, 没人认领的发数)`
pub fn stats() -> (usize, usize) {
    (DISPATCHED.load(Ordering::Relaxed), UNCLAIMED.load(Ordering::Relaxed))
}

