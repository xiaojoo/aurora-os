//! M2：页表接管 + 物理内存分配 + 映射与所有权。
//!
//! 接管策略的四条依据（协议原文与实测，不是偏好）：
//! * Limine 的页表与它的栈都在 **bootloader 可回收内存**里 ⇒ 建自己的 PML4，一次切换。
//! * 切换后能访问的只有「内核镜像 ∪ HHDM」⇒ 切 CR3 **之前**先把 rsp 挪进 .bss 的启动栈。
//! * rev>=4 保证 HHDM 覆盖 usable / reclaimable / ACPI / 内核镜像 / 帧缓冲 ⇒ 切换后启动信息仍可读；
//!   但**内存映射表要先拷进本模块**，之后才允许回收可回收内存。
//! * HHDM 用 2 MiB 大页（512 MiB 按 4 KiB 铺要 13 万个 PTE），其余 4 KiB；
//!   手册"首期 4 KiB 基础页"指的是**分配粒度**，不约束区域映射。

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::sync::{self, IrqGuard, IrqSpinLock};

use crate::limine;

extern "C" {
    static __text_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __bss_end: u8;
}

pub const PAGE: usize = 4096;
pub const LARGE_PAGE: u64 = 2 * 1024 * 1024;

// 页表项位（Intel SDM Vol.3A 4.5）
const P_PRESENT: u64 = 1 << 0;
const P_WRITE: u64 = 1 << 1;
const P_USER: u64 = 1 << 2;
/// PWT/PCD 与 PAT 位决定缓存类型。协议固定了 PAT 表（PROTOCOL.md「x86-64」一节原文：
/// PAT0=WB, PAT1=WT, **PAT2=UC-**, PAT3=UC, PAT4=WP, PAT5=WC），
/// 所以设备页只要 PCD=1、PWT=0、PAT=0 就落在 UC- ——对 LAPIC / I/O APIC 的 MMIO 够用。
const P_PWT: u64 = 1 << 3;
const P_PCD: u64 = 1 << 4;
const P_HUGE: u64 = 1 << 7;
const P_NX: u64 = 1 << 63;
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// 接管前唯一的物理页来源：静态数组，属于内核镜像，切换后仍映射。
///
/// 容量按 `MAX_PHYS_COVER`（4 GiB）的最坏情况推，不是按本机实测拍：
/// PML4 1 页 + 镜像侧 PDPT/PD/PT 3 页 + HHDM 每 1 GiB 一对 PDPT/PD（4 GiB → 8 页）
/// = **12**，取两倍余量定 24。本机（usable 顶到 503 MiB）实测用 6 页，
/// 这个数字每次启动都打进日志（`pool=`），所以余量是真余量而不是猜测。
/// 用尽不会静默：`early_frame` 先打印再返回 None → `take_over` 以 Err 结束 → 判定 37。
const EARLY_POOL_PAGES: usize = 24;
/// 位图覆盖 4 GiB；超出部分本里程碑明确不支持（BACKLOG 已记）
const MAX_PHYS_COVER: u64 = 4 * 1024 * 1024 * 1024;
const BITMAP_WORDS: usize = (MAX_PHYS_COVER as usize / PAGE) / 64;
const MAX_REGIONS: usize = 96;

/// 每帧元数据（ADR-063，W2 P1a）。P1a 阶段它是**影子**：位图仍驱动分配，
/// 它在 init_allocator 两阶段引导里被填好并与位图逐帧对账；P1b 才让它接管分配/释放。
/// `refcnt==0` ⇔ 自由（取代位图的 free 位）；`>=1` ⇔ 活着的主人个数。
#[repr(C)]
struct FrameInfo {
    refcnt: AtomicU32,
    flags: u8,
    owner: ModuleId,
}
const FI_FREE: u8 = 0;
const FI_USED: u8 = 1;
const FI_PINNED: u8 = 2;
const FRAME_INFO_BYTES: usize = core::mem::size_of::<FrameInfo>();
/// VA 保留登记表容量。**memory 拥有的固定上限**（ADR-065 supersede ADR-041 的派生公式）：
/// 定长 256 + 空闲位图，给 W3 每进程 VA 保留留余量。旧派生公式 `MAX_CPUS*MAX_TASKS_SUPPORTED+16`
/// （当时 8×8+16=80）在 M4 开用户态后就撞过 `L4: VA 保留登记表已满`；24 更是 M2 旧值。
/// 容量与 sched 任务槽策略解耦——`MAX_TASKS_SUPPORTED` 仍管"sched 每 CPU 最多几个任务"的契约
/// （sched.rs 的 const 断言），不再派生 VA 容量。W3 P3 随 sched 的 8→9 同步抬到 9（Q2 裁决），
/// **VA 表仍是 256，不跟着派生**：每任务栈占 5 页 VA，9×8=72 条满配也只用 72 格。
/// 登记不下时**明确失败**而不是发一条没登记的 VA（见 alloc_va_range 的注释）。
pub const MAX_TASKS_SUPPORTED: usize = 9;
const MAX_VA_RESERVATIONS: usize = 256;
/// 占用位图字数（bit i=1 表示槽 i 已用）。所有访问都在 VMM 锁内，普通 u64 即可（非原子）。
const VA_BITMAP_WORDS: usize = MAX_VA_RESERVATIONS / 64;
// 位图按整 word 找空槽，容量必须是 64 的倍数，否则末 word 会找出越界槽号。
const _: () = assert!(MAX_VA_RESERVATIONS % 64 == 0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysAddr(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(pub u64);

impl VirtAddr {
    /// 拒绝非规范地址：高 17 位必须是第 47 位的符号扩展
    pub const fn new(a: u64) -> Option<Self> {
        let top = a >> 47;
        if top == 0 || top == 0x1_FFFF {
            Some(Self(a))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmError {
    OutOfMemory,
    InvalidAddress,
    Misaligned,
    AlreadyMapped,
    /// 目标 VA 落在一个 2 MiB 大页之内：想在这里铺 4 KiB 叶子，就必须先把大页拆开。
    /// 本里程碑**没有**实现拆分，所以这是一条明确的拒绝，不是"再等等就好"。
    HugeConflict,
    NotMapped,
    DoubleFree,
    /// 台账发现某模块归还的比借出的多：所有权判定已经被绕过（或重复释放走了没登记的路）
    UnbalancedFree,
    WxViolation,
    /// 叶子写了 U/S=1，但**上级表项不让 ring3 走到它**（逐级相与的规则见 walk_leaf）。
    /// 这条必须是**明确失败**而不是"映射成功但用户态一碰就 #PF"：后者的现场
    /// 长得像用户态入口写错了，M4-1 就是这样白排了一次。
    UserChainBlocked,
    NotInit,
    Unsupported,
    /// 已有非内核地址空间存在之后，再往**内核半区**铺新映射（ADR-070 决策 2 的冻结前置）。
    /// 这不是资源不够，是契约违例：内核半区在第一个 AS 创建时就定形，之后只许读。
    KernelHalfFrozen,
    /// 句柄指的 AS 槽已经不存在（ADR-074：柄先丢、映射后丢的契约被反着用了）。
    NoSuchAspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModuleId(pub u16);

pub const MOD_BOOT: ModuleId = ModuleId(1);
pub const MOD_STACK: ModuleId = ModuleId(2);
pub const MOD_TEST: ModuleId = ModuleId(3);
/// 非内核地址空间自己的页表页（ADR-070 决策 6 / BACKLOG §147）。
/// 与 `MOD_BOOT` 的区别就是"有没有主人"：boot 的表页永不归还（内核生命期），
/// 这里的表页在 AS 销毁时经 `frame_put` 归还，台账 live 必须回基线。
pub const MOD_AS_PT: ModuleId = ModuleId(18);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageFlags {
    writable: bool,
    executable: bool,
    user: bool,
    /// 设备/MMIO 页：PCD=1 → 缓存类型 UC-（协议固定的 PAT2）。
    /// 用它的是 LAPIC(0xFEE00000) 与 I/O APIC(0xFEC00000) 这类**寄存器窗口**：
    /// 缓存了的寄存器读出来是旧值，写可能被合并，表现是"中断偶发丢失"这种最难查的故障。
    device: bool,
}

impl PageFlags {
    /// W^X 在构造时强制：同时可写与可执行直接失败
    pub const fn new(writable: bool, executable: bool, user: bool) -> Result<Self, MmError> {
        if writable && executable {
            return Err(MmError::WxViolation);
        }
        Ok(Self { writable, executable, user, device: false })
    }
    pub const RX: PageFlags = PageFlags { writable: false, executable: true, user: false, device: false };
    pub const RW: PageFlags = PageFlags { writable: true, executable: false, user: false, device: false };
    /// 设备页一律不可执行、不给用户态，且不可缓存
    pub const DEVICE: PageFlags = PageFlags { writable: true, executable: false, user: false, device: true };
    // 用户态组合（M4）。W^X 由 new() 强制，这两条就是它存在的理由：
    // 用户代码页永远不可写、用户数据/栈页永远不可执行。
    pub const USER_RX: PageFlags = PageFlags { writable: false, executable: true, user: true, device: false };
    /// 只读且**不可执行**的用户页。第三条是必须的：只有 `USER_RX`/`USER_RW` 时，
    /// 加载器碰到 ELF 的 `r--` 段（`.rodata`）只能二选一——多给 X 或者多给 W，
    /// 两者都比容器要求宽，而"按容器给的最小权限"才是 §6.4 那条承诺的内容。
    pub const USER_R: PageFlags = PageFlags { writable: false, executable: false, user: true, device: false };
    pub const USER_RW: PageFlags = PageFlags { writable: true, executable: false, user: true, device: false };

    const fn bits(self) -> u64 {
        let mut b = P_PRESENT;
        if self.writable {
            b |= P_WRITE;
        }
        if self.user {
            b |= P_USER;
        }
        if self.device {
            b |= P_PCD;
        }
        if !self.executable {
            b |= P_NX;
        }
        b
    }
}

/// 拥有一段物理页：丢弃即释放
pub struct OwnedFrames {
    base: PhysAddr,
    order: u8,
    owner: ModuleId,
}

impl OwnedFrames {
    pub fn base(&self) -> PhysAddr {
        self.base
    }
    pub fn count(&self) -> usize {
        1usize << self.order
    }
    pub fn owner(&self) -> ModuleId {
        self.owner
    }
}

impl Drop for OwnedFrames {
    fn drop(&mut self) {
        if let Err(e) = phys_free(self.base, self.order, self.owner) {
            // Drop 里错误无法向上传播，所以按 §9.2 直接升 L4：
            // 继续运行等于让同一物理页同时属于两个所有者
            free_violation(e, self.base, self.owner);
        }
    }
}

/// 一段生效中的映射；丢弃即解映射并把物理页所有权还回来（§6.3 R13）
pub struct Mapping {
    virt: VirtAddr,
    frames: Option<OwnedFrames>,
}

impl Mapping {
    pub fn virt(&self) -> VirtAddr {
        self.virt
    }
    pub fn is_none_mapped(&self) -> bool {
        self.frames.is_none()
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        let Some(frames) = self.frames.take() else { return };
        // 解映射必须用**当初映射时的那个 VA**。曾经写成 frames.base.into_va(...)，
        // 那清掉的是 HHDM 别名下的表项，真实映射原封不动地留着——测试报
        // “解映射后仍已映射”才暴露。
        {
            let _g = vmm();
            unmap_pages(self.virt, frames.count());
            // **VA 保留跟着映射一起放手**（M4-2 的任务退出需要它）。不放手的话，
            // 反复 exec/exit 会把 `MAX_VA_RESERVATIONS` 吃光，表现是
            // `L4: VA 保留登记表已满` —— 一个进程生命周期的问题被报成内核故障。
            // 放在这把锁里面而不是再取一次锁：`IrqSpinLock` 的重入检测会把
            // "同一上下文再拿一次 VMM"当场升 L4（§7.1 R16 的注入就验这条）。
            release_va_locked(self.virt.0);
        }
        // 物理页在 VMM 释放之后才归还：顺序反过来也合法（20 之内叫 30），
        // 但写清楚更省事——`unmap` 之后这块页表项已经不存在，归还时机不该再依赖锁序。
        drop(frames);
    }
}

impl PhysAddr {
    /// HHDM 别名下的虚地址（只在已经确认该帧被 HHDM 覆盖时使用）
    pub fn via_hhdm(self) -> VirtAddr {
        VirtAddr(self.0 + hhdm())
    }
}

#[derive(Clone, Copy)]
#[repr(C, align(4096))]
struct Page([u64; 512]);

#[derive(Debug, Clone, Copy)]
pub struct Region {
    pub base: u64,
    pub length: u64,
    pub kind: limine::MemmapType,
    /// 现在就可以自由分配的 Usable 区间
    pub usable: bool,
    /// bootloader 信息区。**默认不回收**：协议原文说这些区域里可能还住着
    /// 硬件在用的东西（"or, in some cases, hardware, such as for MP trampolines"），
    /// 并且要求可执行文件"make absolutely sure that no data contained in these
    /// regions is still needed"之后才回收。实测：加了 MP 请求之后 AP 是被
    /// bootloader 停在这些区域里的，我们一写过去就是三重故障 -> QEMU 以 0 退出。
    pub boot_reclaimable: bool,
}

#[derive(Clone, Copy)]
struct VaReservation {
    base: u64,
    len: u64,
    // 占用与否由 State.va_used 位图决定（ADR-065，单一真相），这里不再存 used。
}

#[repr(C)]
struct State {
    early_pool: [Page; EARLY_POOL_PAGES],
    early_used: usize,
    /// 镜像 VA 起点与物理基址：早期池在 .bss 内，它的物理地址只能靠这两个值算出来
    img_va_lo: u64,
    img_phys_lo: u64,
    pml4_phys: u64,
    boot_stack: [u8; 64 * 1024],
    region_count: usize,
    va_res: [VaReservation; MAX_VA_RESERVATIONS],
    /// VA 槽占用位图（bit i=1 表示槽 i 已用，ADR-065）。访问都在 VMM 锁内，普通 u64。
    va_used: [u64; VA_BITMAP_WORDS],
    hhdm: u64,
    max_phys: u64,
    bitmap: [AtomicU64; BITMAP_WORDS],
    free_frames: AtomicUsize,
    total_frames: AtomicUsize,
    ready: AtomicBool,
    /// FrameInfo 影子数组的 HHDM 虚地址（0 = 未引导）；P1a 由 init_allocator 分出并填充。
    frame_info: AtomicU64,
    frame_info_frames: usize,
}

struct StateCell(UnsafeCell<State>);
// SAFETY: 单核、IF=0 的启动与测试路径内使用；M3b 起 AP 前必须换成带锁版本。
// 这个前提是整个模块的前提，不是局部实现细节。
unsafe impl Sync for StateCell {}

static S: StateCell = StateCell(UnsafeCell::new(State {
    early_pool: [Page([0; 512]); EARLY_POOL_PAGES],
    early_used: 0,
    img_va_lo: 0,
    img_phys_lo: 0,
    pml4_phys: 0,
    boot_stack: [0u8; 64 * 1024],
    region_count: 0,
    va_res: [VaReservation { base: 0, len: 0 }; MAX_VA_RESERVATIONS],
    va_used: [0; VA_BITMAP_WORDS],
    hhdm: 0,
    max_phys: 0,
    bitmap: [const { AtomicU64::new(0) }; BITMAP_WORDS],
    free_frames: AtomicUsize::new(0),
    total_frames: AtomicUsize::new(0),
    ready: AtomicBool::new(false),
    frame_info: AtomicU64::new(0),
    frame_info_frames: 0,
}));

/// memmap 副本单独成一个 static。
///
/// 理由不是审美，是实测：`MemmapType::Reserved` 的判别值是 1（0 是 Usable，
/// 这是协议规定的），所以只要这个非零初值留在 State 里，LLVM 就把**整个 1.8 MiB**
/// 的 State 降级成有文件内容的 `.data`——`objdump -h` 量到 .data=0x1c3068 / .bss=0x100，
/// 拆开后 .data=0x1318 / .bss=0x1c1100。镜像里少背着 1.8 MiB 的零字节走。
#[repr(C, align(64))]
struct RegionsCell(UnsafeCell<[Region; MAX_REGIONS]>);
// SAFETY: 与 StateCell 同一条前提（单核 + IF=0）
unsafe impl Sync for RegionsCell {}

static REGIONS: RegionsCell = RegionsCell(UnsafeCell::new(
    [Region { base: 0, length: 0, kind: limine::MemmapType::Reserved, usable: false, boot_reclaimable: false }; MAX_REGIONS],
));

/// 取 memmap 副本。**只能读 `..region_count()`**：后面的槽位是占位的 Reserved。
#[inline]
fn regs() -> &'static mut [Region; MAX_REGIONS] {
    unsafe { &mut *REGIONS.0.get() }
}

/// 取可变状态。
///
/// SAFETY: 见 StateCell——单核 + IF=0，不存在并发访问；调用方不得持有跨越
/// 其它 mm 调用的引用（本模块内部已按值传递标量规避）。
#[inline]
fn s() -> &'static mut State {
    unsafe { &mut *S.0.get() }
}

const fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) & !(a - 1)
}

fn idx(va: u64, level: u8) -> usize {
    ((va >> (12 + 9 * level as u64)) & 0x1ff) as usize
}

pub fn hhdm() -> u64 {
    s().hhdm
}
pub fn max_phys() -> u64 {
    s().max_phys
}
pub fn is_ready() -> bool {
    s().ready.load(Ordering::Relaxed)
}
pub fn free_frames() -> usize {
    s().free_frames.load(Ordering::Relaxed)
}
pub fn total_frames() -> usize {
    s().total_frames.load(Ordering::Relaxed)
}
pub fn usable_bytes() -> u64 {
    let n = s().region_count;
    let mut sum = 0u64;
    for r in &regs()[..n] {
        if r.usable {
            sum += r.length;
        }
    }
    sum
}

/// bootloader 信息区有多大：这部分现在是"扣着的钱"，M3b 处理完 AP 才该放出来。
/// 报出来是为了让这笔代价是可观察的数字，而不是一个看不见的决定。
pub fn boot_reclaimable_bytes() -> u64 {
    let n = s().region_count;
    let mut sum = 0u64;
    for r in &regs()[..n] {
        if r.boot_reclaimable {
            sum += r.length;
        }
    }
    sum
}

/// 已经回收过的 bootloader 区数（幂等哨兵）
static BOOT_RECLAIMED: AtomicBool = AtomicBool::new(false);

/// **显式**回收全部 bootloader 信息区。调用前提：已经确认这些区域里没有任何
/// 还在被使用的东西——具体到本机，就是"所有 AP 都已经从 bootloader 给的启动栈上
/// 走开"。M3b 之前不该有人调用它；留在这里是因为"默认不回收"必须是**可关的**，
/// 否则就变成"永远浪费这 几 MiB"，那也是一种没有依据的决定。
#[must_use = "回收了多少帧是要记进内存账的数字，丢弃它等于没记账"]
pub fn reclaim_bootloader_regions() -> usize {
    if BOOT_RECLAIMED.swap(true, Ordering::AcqRel) {
        return 0;
    }
    let _g = pmm();
    let n = s().region_count;
    let limit = s().max_phys / PAGE as u64;
    let mut freed = 0usize;
    for r in &regs()[..n] {
        if !r.boot_reclaimable {
            continue;
        }
        let first = r.base / PAGE as u64;
        for f in first..first + r.length.div_ceil(PAGE as u64) {
            if f < limit && bit_get(f) {
                bit_set(f, false);
                freed += 1;
                s().free_frames.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    freed
}
pub fn region(i: usize) -> Option<Region> {
    let n = s().region_count;
    (i < n).then(|| regs()[i])
}

pub fn region_count() -> usize {
    s().region_count
}

// --------------------------------------------------------- VA 保留登记
//
// 规则：**取新 VA 的唯一入口是 `alloc_va_range`**，找到空闲段就顺手登记；登记过的不再发出。
// 为什么必须是登记而不是"查页表看有没有映射"：`find_unmapped_*` 与堆各自只看页表，
// 会把同一段 VA 各自当成空闲发出去（双重记账）。现场与实测见 §6.3 的 VA 保留那一节。
// 保留区间现在由 `Mapping::drop` 按**包含**关系放手（见 `release_va_locked`）。

/// `va` 落在某条保留里时返回该保留的末（不含），否则 0
fn reserved_end(va: u64) -> u64 {
    let st = s();
    for i in 0..MAX_VA_RESERVATIONS {
        if st.va_used[i / 64] >> (i % 64) & 1 == 1 {
            let r = &st.va_res[i];
            if va >= r.base && va < r.base + r.len {
                return r.base + r.len;
            }
        }
    }
    0
}

/// 归还一段 VA 保留。**只有当整条保留里一页都没有映射了才真的放手**。
///
/// 这条检查不是洁癖：今天保留与映射大多是 1:1，但"保留 5 页只映射 4 页"
/// （任务栈 + guard 页）这种形状已经存在，"一段保留里铺多个映射"也一定会出现。
/// 少了这道检查，放手就会让下一次 `alloc_va_range` 把**还有主人正在用**的地址发出去——
/// 那正是 M2-b 立登记表要防的同一条错法，只是换了方向（先发给两个人，而第一个还在用）。
/// 不放手就返回 false，由调用方的日志/用例判据暴露，而不是静默留着一条没人用的保留。
///
/// 前置：调用方**已经**持有 VMM 锁（`Mapping::drop` 就是这种调用点）。
fn release_va_locked(base: u64) -> bool {
    let st = s();
    let mut idx = usize::MAX;
    let mut len = 0u64;
    // **按"包含"找，不按"基址相等"找**。`KT_TASK_EXIT` 第一版就是栽在这里：
    // 任务栈与用户栈都是"保留 5 页 / 2 页，只映射上面那几页"（低那一页是 guard，
    // 永不映射），所以 `Mapping` 手里的 `virt` 等于 `保留基址 + 一页`。
    // 按基址相等匹配的结果是那两条保留**永远还不回去**：`reservations` 每轮 +3 地涨，
    // 而页框（`live`）却是 0 —— 两个计数器各说对了一半，只看"重装能不能成功"根本看不出来。
    for i in 0..MAX_VA_RESERVATIONS {
        if st.va_used[i / 64] >> (i % 64) & 1 == 1 {
            let r = &st.va_res[i];
            if base >= r.base && base < r.base + r.len {
                idx = i;
                len = r.len;
                break;
            }
        }
    }
    if idx == usize::MAX {
        return false;
    }
    // 放手要用**保留自己的基址**去逐页检查，不是用传进来的这个映射的基址
    let res_base = st.va_res[idx].base;
    let pages = len / PAGE as u64;
    for k in 0..pages {
        if is_mapped(res_base + k * PAGE as u64) {
            crate::log_warn!(
                "va: 保留 {:#x}(+{}B) 第 {} 页仍已映射，不放手（本次来自 {:#x}）",
                res_base, len, k, base
            );
            return false;
        }
    }
    st.va_used[idx / 64] &= !(1u64 << (idx % 64));
    st.va_res[idx].base = 0;
    st.va_res[idx].len = 0;
    VA_RELEASED.fetch_add(1, Ordering::Relaxed);
    true
}

/// 已经放手的保留条数（用例判"回收真的发生过"的第二台仪器：
/// 光看 `reservation_count()` 变小还不够，它也可能是别的路径没登记上）。
static VA_RELEASED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn va_released() -> u64 {
    VA_RELEASED.load(Ordering::Relaxed)
}

/// 带锁版本（给不在 VMM 临界区里的调用方与用例用）。
pub fn release_va(base: u64) -> bool {
    let _g = vmm();
    release_va_locked(base)
}

/// 某个 base 是否还登记着保留。用例靠它判断"退出的进程有没有把地址空间还回来"。
pub fn is_reserved(base: u64) -> bool {
    let _g = vmm();
    let st = s();
    (0..MAX_VA_RESERVATIONS).any(|i| {
        st.va_used[i / 64] >> (i % 64) & 1 == 1 && st.va_res[i].base == base
    })
}

pub fn reservation_count() -> usize {
    let _g = vmm();
    s().va_used.iter().map(|w| w.count_ones() as usize).sum()
}

fn register_va(base: u64, len: u64) -> bool {
    let st = s();
    // 空闲位图找空槽（O(1) 定位）：4 个 word 里第一个非全 1 的，取反 trailing_zeros 即空位。
    for w in 0..VA_BITMAP_WORDS {
        if st.va_used[w] != u64::MAX {
            let b = (!st.va_used[w]).trailing_zeros() as usize;
            st.va_used[w] |= 1u64 << b;
            st.va_res[w * 64 + b] = VaReservation { base, len };
            return true;
        }
    }
    false
}

/// 用户态 VA 窗口的底部。
///
/// **为什么单独一段，而不是复用 `alloc_va_range` 那条内核前沿**：内核的 VA 全在高半区
/// （HHDM 之上）与引导期恒等映射里，那些链上的上级表项是为内核建的（U/S=0）。
/// 用户页要 ring3 可达，整条链都得带 U/S=1；把用户页塞进内核半区就只能靠放宽
/// **共享**的上级表项——那等于把整条内核映射的可达性一起拖进判据，风险远大于收益。
/// 取 4 GiB：正好在恒等映射（`0..max_phys`，本机 512 MiB）之上、属于低半区规范地址，
/// 而 PML4 下标 2 那一整条链是全新的，只可能被用户页用到。
pub const USER_VA_BASE: u64 = 0x0000_0001_0000_0000;
/// 用户窗口上界：1 TiB 为止。够用、且绝不越进高半区。
/// **加载器的窗口比容器的合法范围窄**：`elf::parse` 只要求"低半区"（<2^47），
/// 而加载器只把页装进 `[USER_VA_BASE, USER_VA_TOP)`——那条链上的上级表项必须由
/// 用户映射自己建（见 ADR-026），装到窗口外就得去放宽内核半区的共享条目。
pub const USER_VA_TOP: u64 = 0x0000_0100_0000_0000;
/// 用户窗口内**动态分配**的起点，把窗口切成两段：`[USER_VA_BASE, USER_MMAP_BASE)` 只给
/// 固定镜像（`ET_EXEC` 的 `p_vaddr`），`[USER_MMAP_BASE, USER_VA_TOP)` 只给内核挑的地址（用户栈、脚手架）。
/// 病因是"固定地址的请求与随机地址的请求共用一条前沿"⇒ 谁先跑谁赢，容器装不装得上取决于
/// `.ktests` 的链接顺序。1 MiB 是照 `MAX_OWNED` 那条容量账挑的，两处要一起重看。
/// 论证、现场、负样本与判据：ADR-028、§10.7、BACKLOG ⑪。
pub const USER_MMAP_BASE: u64 = USER_VA_BASE + 0x0000_0000_0010_0000;

/// §8.3：把**已存在的物理区间**（设备 MMIO）映射进来的所有权句柄。
/// 与 `Mapping` 的区别只有一条：这些页框不是 PMM 发出去的，所以 drop 时**不还页框、
/// 不动 free_frames 与资源台账**——只解映射并放手 VA 保留。这条区别是判据要看的
/// （`KT_PCI` 里"一次 map/drop 往返前后 `free_frames()` 不变"）。
pub struct MmioMapping {
    virt: VirtAddr,
    pages: usize,
}

impl MmioMapping {
    pub fn virt(&self) -> VirtAddr {
        self.virt
    }
    pub fn pages(&self) -> usize {
        self.pages
    }
}

impl Drop for MmioMapping {
    fn drop(&mut self) {
        let _g = vmm();
        unmap_pages(self.virt, self.pages);
        release_va_locked(self.virt.0);
    }
}

/// 映射一段设备物理地址。VA 走 `alloc_va_range`（所以它进登记表，drop 时放手），
/// 页标志应当用 `PageFlags::DEVICE`（PCD ⇒ UC-，不可执行、不给用户态）。
pub fn map_mmio(pa: u64, pages: usize) -> Result<MmioMapping, MmError> {
    if pages == 0 || (pa % PAGE as u64) != 0 {
        return Err(MmError::InvalidAddress);
    }
    if !is_ready() {
        return Err(MmError::NotInit);
    }
    let va = alloc_va_range(pages).ok_or(MmError::OutOfMemory)?;
    if let Some(block) = huge_block_of(va.0) {
        crate::log_warn!("map_mmio refused: {:#x} lies inside 2 MiB huge page {:#x}", va.0, block);
        return Err(MmError::HugeConflict);
    }
    let flags = PageFlags::DEVICE;
    {
        let _g = vmm();
        for k in 0..pages {
            let a = va.0 + (k as u64) * PAGE as u64;
            let p = pa + (k as u64) * PAGE as u64;
            if let Err(e) = set_leaf(a, p | flags.bits(), false, false) {
                for j in 0..k {
                    clear_leaf(VirtAddr(va.0 + (j as u64) * PAGE as u64));
                }
                return Err(e);
            }
            tlb_invalidate(a);
        }
    }
    MAP_CALLS.fetch_add(1, Ordering::Relaxed);
    MAPPED_PAGES.fetch_add(pages, Ordering::Relaxed);
    Ok(MmioMapping { virt: va, pages })
}

/// 取 `pages` 页连续、未映射、且未被登记过的内核 VA，并**就地登记**。
///
/// 失败（包括登记表满）一律返回 None，不发一条没登记的地址：宁可用例红，
/// 也不能让两个主人同时相信一段 VA 属于自己。
pub fn alloc_va_range(pages: usize) -> Option<VirtAddr> {
    let (hhdm, max_phys) = {
        let st = s();
        if !st.ready.load(Ordering::Relaxed) {
            return None;
        }
        (st.hhdm, st.max_phys)
    };
    // 扫描从 HHDM 覆盖上界之后开始：那里以下是引导期铺好的恒等映射，不该再动
    alloc_va_range_in(align_up(hhdm + max_phys, PAGE as u64), 0xffff_ffff_7000_0000, pages)
}

/// 用户窗口版，且**只从动态区发**（见 `USER_MMAP_BASE`）：登记与冲突检查走的是**同一张**
/// `va_res` 表，所以"内核段与用户段各自发了一段重叠 VA"这种错法在结构上就不可能出现
/// （而不是靠两边都守规矩）；而"动态分配把固定镜像的位置吃掉"这一类，靠上面那一刀
/// 在结构上排掉，不靠用例的运行顺序。
pub fn alloc_user_va_range(pages: usize) -> Option<VirtAddr> {
    alloc_va_range_in(USER_MMAP_BASE, USER_VA_TOP, pages)
}

fn alloc_va_range_in(start: u64, top: u64, pages: usize) -> Option<VirtAddr> {
    // 扫描 + 登记必须整体加锁：否则两个上下文会各自认定同一段 VA 属于自己（M2-b 的故障）
    let _g = vmm();
    if pages == 0 {
        return None;
    }
    let want = pages as u64 * PAGE as u64;
    let mut va = align_up(start, PAGE as u64);
    for _ in 0..64 * 1024 {
        if va.checked_add(want)? > top {
            return None;
        }
        if VirtAddr::new(va).is_none() {
            return None;
        }
        let end = reserved_end(va);
        if end != 0 {
            va = end;
            continue;
        }
        let mut busy = false;
        for k in 0..pages {
            if is_mapped(va + (k as u64) * PAGE as u64) {
                busy = true;
                break;
            }
        }
        if !busy {
            if !register_va(va, want) {
                crate::log_fatal!("L4: VA 保留登记表已满（{} 条），拒绝发放未登记的 VA", MAX_VA_RESERVATIONS);
                crate::exit::finish(crate::exit::Code::ExceptionFatal);
            }
            return Some(VirtAddr(va));
        }
        va += PAGE as u64 * 64;
    }
    None
}

/// **按指定地址**登记一段 VA。ELF 的 `p_vaddr` 是容器定死的（`ET_EXEC` 搬不动，
/// 搬就是 M4-2 还没做的重定位），所以这里的方向与 `alloc_va_range` 相反：
/// 那边是"发一段没人要过的"，这里是"别人要过就必须当场拒绝"。
/// 两道检查都不可省：①不与任何已登记区间重叠；②区间内一页都没映射。
/// 只留②的话会走到 `map` 的 `AlreadyMapped`，那仍然是失败，但已经装好的前几页
/// 要回滚第二遍——把"拒绝"放在登记这一步，回滚就只有没登记的那几种情况。
pub fn reserve_va_at(base: u64, pages: usize) -> bool {
    if pages == 0 || (base % PAGE as u64) != 0 {
        return false;
    }
    let _g = vmm();
    if !s().ready.load(Ordering::Relaxed) {
        return false;
    }
    let want = pages as u64 * PAGE as u64;
    if VirtAddr::new(base).is_none() || base.checked_add(want).is_none() {
        return false;
    }
    for k in 0..pages {
        let va = base + (k as u64) * PAGE as u64;
        if reserved_end(va) != 0 || is_mapped(va) {
            return false;
        }
    }
    register_va(base, want)
}

/// 在 VMM 锁里跑一段。**为什么要把锁交给调用方而不是塞进某个具体操作里**：
/// §10.3 的 `copy_*_user` 需要"校验 + 开窗 + 拷贝"三者**互相之间不被解映射插队**，
/// 而唯一的保证是它们在同一次持锁期内完成。反过来，窗口内部**不许再取锁**
/// （带着 AC=1 去等锁 = 等待期间整段代码都能读用户页，那才是 §10.3 真正防的事），
/// 所以这条只能拿到锁、不能在锁里再开一层窗口套窗口。
pub fn with_vmm_lock<R>(f: impl FnOnce() -> R) -> R {
    let _g = vmm();
    f()
}

/// 单页版便利入口（#PF 与 guard 探针用）
pub fn alloc_va_page() -> Option<VirtAddr> {
    alloc_va_range(1)
}

// ------------------------------------------------------------ 接管：建表并切换

core::arch::global_asm!(
    r#"
    .text
    .code64
    // rdi = 新 PML4 物理地址, rsi = 新栈顶, rdx = 续体, rcx = 传给续体的参数
    //
    // 必须是 jmp 而不是 ret：这里同时换了 rsp 和 cr3，换栈之后栈上已经没有
    // 调用者的返回地址，`ret` 会弹出新栈顶的垃圾（实测表现为 rip=0、err 的
    // bit4=1 取指令故障），且没有任何可读的错误信息。
    .global mm_relocate
mm_relocate:
    mov rsp, rsi
    mov cr3, rdi
    mov rdi, rcx
    jmp rdx

    // ADR-070（W3 P1）：CR3 读/写原语。放在这里而不是新开 global_asm! 块，
    // 是因为 `core::arch::` 的每一行都算 memory->arch 的引用站点（ADR-044 棘轮只许减），
    // 复用已有的块 = 零新增站点。这两个函数只动 CR3，不碰栈、不碰标志。
    .global aspace_cr3_read
aspace_cr3_read:
    mov rax, cr3
    ret
    .global aspace_cr3_write
aspace_cr3_write:
    mov cr3, rdi
    ret
"#
);

extern "C" {
    /// 读本 CPU 的 CR3（ADR-070 A2 的证人输入）。
    fn aspace_cr3_read() -> u64;
    /// 写本 CPU 的 CR3。调用方保证目标是内核半区等价的有效 PML4。
    fn aspace_cr3_write(pml4: u64);
}

/// 建我们自己的页表并切换。失败即**不切换**，调用方据此尽早失败。
/// 建自己的页表、切栈、切 CR3，然后尾跳进 cont。
/// 成功时本函数不返回（续体是 -> !）；失败时返回 Err 且不改动当前页表。
pub fn take_over(info: &limine::BootInfo, cont: extern "C" fn(usize) -> !, arg: usize) -> Result<(), MmError> {
    let hhdm = info.hhdm_offset;
    if hhdm == 0 || hhdm >= 0xffff_ffff_ffff_f000 || (hhdm & (PAGE as u64 - 1)) != 0 {
        return Err(MmError::InvalidAddress);
    }
    let st = s();
    st.hhdm = hhdm;

    let mut map_top = 0u64;
    let mut phys_top = 0u64;
    let mut n = 0usize;
    for &p in info.mmap_entries {
        // SAFETY: entries 与 entry_count 均来自 bootloader 的 memmap 响应
        let e = unsafe { &*p };
        if n >= MAX_REGIONS {
            return Err(MmError::Unsupported);
        }
        let kind = limine::MemmapType::from_raw(e.kind);
        let end = match e.base.checked_add(e.length) {
            Some(v) => v,
            None => return Err(MmError::InvalidAddress),
        };
        let usable = matches!(kind, limine::MemmapType::Usable);
        let boot_reclaimable = matches!(kind, limine::MemmapType::BootloaderReclaimable);
        // HHDM 上界只按“会用到的内存”算。q35 在 4 GiB 之上放 MMCFG / PCI MMIO，
        // 若把 Reserved 也算进来就会把上界推到 8 GiB+，既浪费页表又把支持范围白白收窄。
        if (usable || boot_reclaimable) && end > map_top {
            map_top = end;
        }
        if end > phys_top {
            phys_top = end;
        }
        // 接管时就拷表：切换后这些结构位于可回收内存，一旦我们把该帧分配出去，
        // 再读原始 entry 就是读别人的内存
        regs()[n] = Region { base: e.base, length: e.length, kind, usable, boot_reclaimable };
        n += 1;
    }
    st.region_count = n;
    if map_top == 0 || map_top > MAX_PHYS_COVER {
        return Err(MmError::Unsupported);
    }
    st.max_phys = align_up(map_top, PAGE as u64);

    // 1) 先定镜像边界。早期页表池在 .bss 里，early_frame 要靠 img_va_lo/img_phys_lo
    //    把自己的虚地址换算成物理地址，因此必须在分配任何表之前存好。
    //
    //    镜像 VA 在 higher half，**不在 HHDM 区间内**，物理基址只能取 memmap 的
    //    ExecutableAndModules 项，不能靠 VA - hhdm 反推。
    //    下取整用掩码：`align_up(x)-4096` 对本来已对齐的地址会多退一页，
    //    整张映射就错开一页（表现为切换后无声挂死）。
    let img_lo = (unsafe { &raw const __text_start } as u64) & !(PAGE as u64 - 1);
    let split = align_up(unsafe { &raw const __rodata_end } as u64, PAGE as u64);
    let data_lo = (unsafe { &raw const __data_start } as u64) & !(PAGE as u64 - 1);
    let img_hi = align_up(unsafe { &raw const __bss_end } as u64, PAGE as u64);
    let image_phys = exec_region_phys_base().ok_or(MmError::InvalidAddress)?;
    st.img_va_lo = img_lo;
    st.img_phys_lo = image_phys;
    if image_phys == 0 || image_phys >= st.max_phys {
        return Err(MmError::InvalidAddress);
    }
    let phys_of = |va: u64| va.checked_sub(img_lo)?.checked_add(image_phys);
    if phys_of(img_hi - 1).map_or(true, |p| p >= st.max_phys) {
        // 推导出的物理范围必须落在已知内存内，否则每次访问都是未知内存
        return Err(MmError::InvalidAddress);
    }

    // 2) PML4 与所有早期表都来自静态池
    let pml4 = early_frame().ok_or(MmError::OutOfMemory)?;
    st.pml4_phys = pml4;

    // 3) 内核镜像：[text..rodata_end) RX、[data..bss_end) RW
    map_image_range(img_lo, split, PageFlags::RX, image_phys)?;
    map_image_range(data_lo.max(split), img_hi, PageFlags::RW, phys_of(data_lo.max(split)).ok_or(MmError::InvalidAddress)?)?;

    // 4) HHDM：2 MiB 大页
    let mut off = 0u64;
    while off < align_up(map_top, LARGE_PAGE) {
        map_huge(hhdm + off, off, PageFlags::RW)?;
        off += LARGE_PAGE;
    }

    // 5) 换栈 + 换表，并尾跳到续体（换栈之后不可能再 ret 回来）
    let stack_top = (core::ptr::addr_of!(st.boot_stack) as u64) + st.boot_stack.len() as u64 - 16;
    crate::log_info!(
        "mm: switching: pml4={:#x} image=[{:#x}..{:#x}) phys_base={:#x} hhdm_top={:#x} stack_top={:#x} pool={}",
        st.pml4_phys, img_lo, img_hi, image_phys, st.max_phys, stack_top, st.early_used
    );
    // 续体依赖 ready 已置位（map/alloc 都先查它），所以在跳之前设
    st.ready.store(true, Ordering::Relaxed);
    // SAFETY: mm_relocate 只做换 rsp、换 cr3、尾跳；新表已覆盖内核镜像与全部已知物理内存。
    unsafe {
        core::arch::asm!(
            "call mm_relocate",
            in("rdi") st.pml4_phys,
            in("rsi") stack_top,
            in("rdx") cont,
            in("rcx") arg,
        );
    }
    // 走到这里说明续体返回了——它被声明为 -> !，所以这是真实不可达的防御分支
    Err(MmError::Unsupported)
}

/// 切换完成后由 `mm_relocate` 尾跳进入，运行在一个全新的栈上。
pub fn mark_switched() {
    // 把内核 PML4 的物理地址交给 asm 侧：AP 是带着 **bootloader 的页表** 进
    // `goto_address` 的（协议："Other than that, the CPU state will be the same as
    // described for the bootstrap processor"——交接时 BSP 用的就是 bootloader 的表）。
    // 所以 AP 的入口例程必须自己 `mov cr3`，而它那一刻能读到的只有内核镜像与 HHDM，
    // 这个量必须放在 .data 里用 RIP 相对寻址取，不能靠参数传。
    let p = s().pml4_phys;
    AURORA_KERNEL_CR3.store(p, Ordering::Release);
    crate::log_info!("mm: page tables switched ok (running on our own stack)");
}

/// 内核自己的 PML4 物理地址（0 = 还没切换）。释放 AP 前必须确认它非 0。
pub fn our_cr3() -> u64 {
    AURORA_KERNEL_CR3.load(Ordering::Acquire)
}

/// asm 侧可见的内核 CR3。写在 `.data`：AP 入口在换表**之前**读它，
/// 放 `.bss` 也一样能读，但 `.bss` 的符号在链接脚本里没有单独的段属性要求，
/// 这里跟着 `trap.rs` 里那几张计时表的做法统一放 `.data`，少一种"到底谁映射了它"的疑问。
#[used]
#[no_mangle]
#[link_section = ".data"]
pub static AURORA_KERNEL_CR3: AtomicU64 = AtomicU64::new(0);

fn early_frame() -> Option<u64> {
    let st = s();
    if st.early_used >= EARLY_POOL_PAGES {
        crate::log_fatal!("early page-table pool exhausted ({} pages)", EARLY_POOL_PAGES);
        return None;
    }
    let va = core::ptr::addr_of!(st.early_pool[st.early_used]) as u64;
    st.early_used += 1;
    // 早期池在 .bss 里，属于**内核镜像**而不是 HHDM 区间：
    // 物理地址 = 镜像物理基址 + (VA - 镜像 VA 起点)。用 VA - hhdm 会算出
    // 0x7fff8000xxxx 这种不可能的地址，切换后立刻挂死且没有任何错误信息。
    if st.img_phys_lo == 0 || va < st.img_va_lo {
        return None;
    }
    Some(st.img_phys_lo + (va - st.img_va_lo))
}

/// 取 bootloader 报告的“内核镜像与模块”区间的物理基址。
fn exec_region_phys_base() -> Option<u64> {
    let count = s().region_count;
    regs()[..count]
        .iter()
        .find(|r| r.kind == limine::MemmapType::ExecutableAndModules)
        .map(|r| r.base)
}

/// 内核镜像的 VA 区间映射到 image_phys 起始的物理区间（ Limine 把镜像连续加载）
fn map_image_range(lo: u64, hi: u64, flags: PageFlags, phys_lo: u64) -> Result<(), MmError> {
    let max_phys = s().max_phys;
    let mut va = lo & !(PAGE as u64 - 1);
    let mut phys = phys_lo;
    while va < hi {
        if phys >= max_phys {
            return Err(MmError::InvalidAddress);
        }
        set_leaf(va, phys | flags.bits(), false, flags.user)?;
        va += PAGE as u64;
        phys += PAGE as u64;
    }
    Ok(())
}

fn map_huge(va: u64, phys: u64, flags: PageFlags) -> Result<(), MmError> {
    set_leaf(va, phys | flags.bits() | P_HUGE, true, flags.user)
}

/// 取一个清零的页表页（内核表：生命周期 = 内核，不归还）。
fn new_table_frame() -> Option<u64> {
    new_table_frame_in(None)
}

/// 取一个清零的页表页，**按它属于哪棵树记账**（ADR-074 决策 3）。
/// `None` = 内核表：`MOD_BOOT` + `forget`，与今天逐字相同。
/// `Some(slot)` = 那个 AS 自己的表页：`MOD_AS_PT`，帧号记进 `pt_frames`，
/// AS 销毁时由 `aspace_release` 逐帧 `frame_put` 归还。清单满了就**把这张还回去并失败**，
/// 不发一张没人还的表页（那正是 BACKLOG §147 第 1 条的形状）。
fn new_table_frame_in(as_slot: Option<u8>) -> Option<u64> {
    let phys = if is_ready() {
        let owner = if as_slot.is_some() { MOD_AS_PT } else { MOD_BOOT };
        let f = phys_alloc(0, owner).ok()?;
        let p = f.base().0;
        core::mem::forget(f); // 主人改记在表里（内核表不记，AS 表记 pt_frames）
        if let Some(slot) = as_slot {
            let t = aspaces();
            let e = &mut t.items[usize::from(slot)];
            if !e.used || e.pt_count >= AS_PT_SLOTS {
                // 这里持 VMM(20)，frame_put 取 PMM(30)：正向嵌套，合法（lock-order.md）
                if let Err(err) = frame_put(p / PAGE as u64) {
                    free_violation(err, PhysAddr(p), owner);
                }
                return None;
            }
            e.pt_frames[e.pt_count] = p / PAGE as u64;
            e.pt_count += 1;
            AS_PT_LIVE.fetch_add(1, Ordering::Relaxed);
        }
        p
    } else {
        early_frame()?
    };
    PT_PAGES.fetch_add(1, Ordering::Relaxed);
    let st = s();
    // SAFETY: phys 来自分配器或静态池，HHDM 覆盖全部物理内存
    unsafe { core::ptr::write_bytes((phys + st.hhdm) as *mut u8, 0, PAGE) };
    Some(phys)
}

/// 沿 VA 走到叶子表项。**唯一**的页表遍历入口，避免多处各写一遍而错法不同。
/// `user` 必须**逐级传下去**：Intel 的规则是逐级相与，任一上级 U/S=0 就让用户叶子失效，
/// 而后果不是报错而是"映射成功、ring3 一取指就 #PF"（M4-1 的 `err=0x15`）。
/// 对已存在的上级表项**或**进 P_USER 是安全的：内核自己的叶子都带 U/S=0，相与之后仍只有内核可达
/// ——这条不是推测，`t_user_roundtrip` 用 `effective_flags` 复量了一个内核页。
/// SAFETY: 调用方保证 `va` 是规范地址，且 pml4/hhdm 已初始化。
unsafe fn walk_leaf(va: u64, create: bool, huge: bool, user: bool) -> Option<*mut u64> {
    // SAFETY: 同 walk_leaf_in；根取内核那份 PML4，所以既有调用点的语义逐字不变（ADR-074 决策 3）
    unsafe { walk_leaf_in(s().pml4_phys, None, va, create, huge, user) }
}

/// 带根表与 AS 归属的遍历（ADR-074 决策 3）。**入口仍然只有这一个**：
/// `walk_leaf` 是它 `root = 内核 PML4、as_slot = None` 的薄壳。
/// `as_slot = Some(i)` 时按需建的下级表页记进那个 AS 的清单（`new_table_frame_in`）。
/// SAFETY: 调用方保证 `root` 是一份有效 PML4 的物理地址、`va` 规范、持 VMM。
unsafe fn walk_leaf_in(
    root: u64,
    as_slot: Option<u8>,
    va: u64,
    create: bool,
    huge: bool,
    user: bool,
) -> Option<*mut u64> {
    let hhdm = s().hhdm;
    let mut table = (root + hhdm) as *mut Page;
    let stop: u8 = if huge { 1 } else { 0 };
    let mut level = 3u8;
    let share = if user { P_USER } else { 0 };
    loop {
        // SAFETY: 调用方保证 table 是有效页表页、va 是规范地址
        let entry = unsafe { &mut (*table).0[idx(va, level)] as *mut u64 };
        if level == stop {
            return Some(entry);
        }
        // SAFETY: 同上
        let cur = unsafe { *entry };
        if cur & P_PRESENT == 0 {
            if !create {
                return None;
            }
            // SAFETY: 同上
            unsafe { *entry = new_table_frame_in(as_slot)? | P_PRESENT | P_WRITE | share };
        } else if cur & P_HUGE != 0 {
            // 还要继续下钻，但这一级已经是 2 MiB 大页：**拒绝**。
            // 继续走会把那块数据帧当成下一级页表，页表项就写进了数据里；
            // 而硬件的翻译仍然是那个大页，所以 `set_leaf` 看不到冲突、"映射成功"，
            // 之后每次访问落到的是大页背后的物理帧。HHDM 尾部按 2 MiB 对齐铺大页，
            // 未对齐的区间正好被这样盖住，这条不是假想路径。
            return None;
        } else if user {
            // 上级已经存在：用户叶子需要它也对 ring3 开放（见函数头的论证）
            unsafe { *entry = cur | P_USER };
        }
        // SAFETY: 表项里的物理地址经 HHDM 可达
        table = unsafe { ((*entry & ADDR_MASK) + hhdm) as *mut Page };
        level -= 1;
    }
}

/// 写叶子表项；已存在的映射报 AlreadyMapped 而不是静默覆盖
fn set_leaf(va: u64, value: u64, huge: bool, user: bool) -> Result<(), MmError> {
    set_leaf_in(s().pml4_phys, None, va, value, huge, user)
}

/// 往**指定根表**写叶子（ADR-074）。`AlreadyMapped` 在那棵树里判，不查内核树——
/// 这是"同一 VA 在两个 AS 里各自映射互不影响"（ADR-070 A4）的实现点。
fn set_leaf_in(
    root: u64,
    as_slot: Option<u8>,
    va: u64,
    value: u64,
    huge: bool,
    user: bool,
) -> Result<(), MmError> {
    // SAFETY: va 由调用方保证规范，root 是调用方给的有效 PML4，持 VMM
    let e = unsafe { walk_leaf_in(root, as_slot, va, true, huge, user).ok_or(MmError::OutOfMemory)? };
    // SAFETY: 上一步返回的是有效表项指针
    if unsafe { *e } & P_PRESENT != 0 {
        return Err(MmError::AlreadyMapped);
    }
    // SAFETY: 同上
    unsafe { *e = value };
    Ok(())
}

// ------------------------------------------------------------------ 映射 API

/// 该 VA 是否落在某个 2 MiB 大页之内；是则返回那个大页覆盖的 VA 块基址。
///
/// 单独写一遍遍历而不是复用 `walk_leaf`：`walk_leaf` 现在遇到大页会**拒绝下钻**，
/// 而这里正是要把"遇到大页"这件事本身报出来。两级 huge 只认 level 1（2 MiB），
/// 本内核不在 level 2/3 铺大页，真出现说明表被写坏了，不该在这里猜。
fn huge_block_of(va: u64) -> Option<u64> {
    let st = s();
    let hhdm = st.hhdm;
    // SAFETY: 只读遍历自建表，前提与 is_mapped 相同
    unsafe {
        let mut table = (st.pml4_phys + hhdm) as *const Page;
        for level in (1u8..=3u8).rev() {
            let entry = (*table).0[idx(va, level)];
            if entry & P_PRESENT == 0 {
                return None;
            }
            if entry & P_HUGE != 0 {
                return if level == 1 { Some(va & !(LARGE_PAGE - 1)) } else { None };
            }
            table = ((entry & ADDR_MASK) + hhdm) as *const Page;
        }
        None
    }
}

/// 映射侧记账（§12.4.1 P 基线的输入）。
///
/// 为什么要单独计：`t_map_write_unmap` 早就量到“映射一页数据要额外吃掉一整页页表”
/// （free 128991 → 128989），但那是一次性差值，只在那条用例的断言里有意义。
/// 基线要的是**累计**：`page_table_pages / mapped_pages` 就是页表内存的摊销系数。
static MAP_CALLS: AtomicUsize = AtomicUsize::new(0);
static MAPPED_PAGES: AtomicUsize = AtomicUsize::new(0);
static UNMAPPED_PAGES: AtomicUsize = AtomicUsize::new(0);
static PT_PAGES: AtomicUsize = AtomicUsize::new(0);
/// 非内核 AS 的表页**当前存活**数（ADR-070 A3 的证人）。与 `PT_PAGES`（累计）分开：
/// 销毁回基线判的是"现在还剩几张"，不是"一共取过几张"。
static AS_PT_LIVE: AtomicUsize = AtomicUsize::new(0);
/// CR3 实际写入次数（ADR-070 A2 的证人）。只数**真的执行了 `mov cr3`** 的次数，
/// 不数"调用了切换函数"的次数——后者会把"同 AS 不写"这条判据变成空转。
static CR3_WRITES: AtomicUsize = AtomicUsize::new(0);

pub struct MmCounters {
    pub map_calls: usize,
    pub mapped_pages: usize,
    pub unmapped_pages: usize,
    /// 为建表取用的页表页数（含接管期从早期池取的）
    pub page_table_pages: usize,
    /// 早期池占用，用于判断 `EARLY_POOL_PAGES` 的余量是不是真余量
    pub early_pool_used: usize,
    /// 非内核 AS 的表页当前存活数（ADR-070 A3）
    pub as_pt_live: usize,
    /// CR3 实际写入次数（ADR-070 A2）
    pub cr3_writes: usize,
}

pub fn counters() -> MmCounters {
    MmCounters {
        map_calls: MAP_CALLS.load(Ordering::Relaxed),
        mapped_pages: MAPPED_PAGES.load(Ordering::Relaxed),
        unmapped_pages: UNMAPPED_PAGES.load(Ordering::Relaxed),
        page_table_pages: PT_PAGES.load(Ordering::Relaxed),
        early_pool_used: s().early_used,
        as_pt_live: AS_PT_LIVE.load(Ordering::Relaxed),
        cr3_writes: CR3_WRITES.load(Ordering::Relaxed),
    }
}

/// 建立映射并**收下物理页所有权**（§6.3 R13）
pub fn map(va: VirtAddr, frames: OwnedFrames, flags: PageFlags) -> Result<Mapping, MmError> {
    if !is_ready() {
        return Err(MmError::NotInit);
    }
    if VirtAddr::new(va.0).is_none() || (va.0 & (PAGE as u64 - 1)) != 0 {
        return Err(MmError::InvalidAddress);
    }
    // 落在 2 MiB 大页里的 VA 必须先拆大页才能铺叶子；没拆就直接拒绝，
    // 让 `frames` 走 Drop 归还物理页（不能静默把页表项写进那块数据帧里）。
    if let Some(block) = huge_block_of(va.0) {
        crate::log_warn!("map refused: {:#x} lies inside 2 MiB huge page {:#x}", va.0, block);
        return Err(MmError::HugeConflict);
    }
    let _g = vmm();
    for k in 0..frames.count() {
        let a = va.0 + (k as u64) * PAGE as u64;
        let p = frames.base().0 + (k as u64) * PAGE as u64;
        if let Err(e) = set_leaf(a, p | flags.bits(), false, flags.user) {
            // 回滚已建立的部分，不留半截映射
            for j in 0..k {
                clear_leaf(VirtAddr(va.0 + (j as u64) * PAGE as u64));
            }
            return Err(e);
        }
        tlb_invalidate(a);
    }
    // **装完必须验"生效的位"**：`PageFlags` 是意图，可达与否由整条链相与决定。
    // 不做这一步的话，上级表项漏了 U/S=1 会被报成"映射成功"，
    // 而现场是几百行之后一次 ring3 取指故障（M4-1 实测：`err=0x15`，叶子全对）。
    // 失败就整段回滚：宁可不映射，也不留一条对 ring3 假装存在的映射。
    if flags.user {
        for k in 0..frames.count() {
            let a = va.0 + (k as u64) * PAGE as u64;
            if effective_flags(a).is_none_or(|f| !f.user) {
                for j in 0..frames.count() {
                    clear_leaf(VirtAddr(va.0 + (j as u64) * PAGE as u64));
                }
                crate::log_warn!("map refused: {:#x} 是用户叶子但上级表项没放行 eff={:?}", a, effective_flags(a));
                return Err(MmError::UserChainBlocked);
            }
        }
    }
    MAP_CALLS.fetch_add(1, Ordering::Relaxed);
    MAPPED_PAGES.fetch_add(frames.count(), Ordering::Relaxed);
    Ok(Mapping { virt: va, frames: Some(frames) })
}

/// 把一段**固定物理地址**（设备 MMIO 窗口）映射到一个新保留的 VA 上，缓存类型 UC-。
///
/// 与 `map` 的三点不同，都是必要的：
/// 1. 物理地址由调用方指定，不经过 `phys_alloc`——寄存器窗口不在内存映射的可用区间里，
///    把它当页框分配会双重记账（LAPIC 那 4 KiB 在 memmap 里是 Reserved）。
/// 2. VA 由本函数自己经 `alloc_va_range` 保留，所以不会被别的模块再要走。
/// 3. 返回的 `Mapping` **没有** `OwnedFrames`：MMIO 不是我们的内存，丢弃时不该"归还"，
///    也不该解映射（`Mapping::drop` 对 `frames: None` 直接返回）。设备窗口在本内核里
///    是永久映射，M3a 不需要撤销它；真要撤销时得先有新的所有权类型，不能靠静默。
pub fn map_device(phys: u64, pages: usize) -> Result<Mapping, MmError> {
    if !is_ready() {
        return Err(MmError::NotInit);
    }
    if pages == 0 || (phys & (PAGE as u64 - 1)) != 0 {
        return Err(MmError::Misaligned);
    }
    let va = alloc_va_range(pages).ok_or(MmError::OutOfMemory)?;
    if VirtAddr::new(va.0 + (pages as u64 - 1) * PAGE as u64).is_none() {
        return Err(MmError::InvalidAddress);
    }
    let _g = vmm();
    for k in 0..pages {
        let a = va.0 + (k as u64) * PAGE as u64;
        if let Err(e) = set_leaf(a, (phys + (k as u64) * PAGE as u64) | PageFlags::DEVICE.bits(), false, false) {
            for j in 0..k {
                clear_leaf(VirtAddr(va.0 + (j as u64) * PAGE as u64));
            }
            return Err(e);
        }
        tlb_invalidate(a);
    }
    MAP_CALLS.fetch_add(1, Ordering::Relaxed);
    MAPPED_PAGES.fetch_add(pages, Ordering::Relaxed);
    Ok(Mapping { virt: va, frames: None })
}

fn unmap_pages(va: VirtAddr, count: usize) {
    for k in 0..count {
        let a = va.0 + (k as u64) * PAGE as u64;
        clear_leaf(VirtAddr(a));
        // **§6.6 的正身**：本 CPU 清了条目，别的 CPU 还留着。物理帧在 `Mapping::drop` 里
        // 是在本函数返回之后才归还的，所以"等回执"必须发生在归还之前——晚一步就是
        // 另一个 CPU 还在用旧条目翻译，而那块页已经被发给别人写。
        shootdown_others(a);
    }
    UNMAPPED_PAGES.fetch_add(count, Ordering::Relaxed);
}

// ------------------------------------------------------------ §6.6 TLB shootdown

/// 正在被 shootdown 的 VA（0 = 没有）。请求方**持有 VMM 锁**，所以它是唯一写者，
/// 多个 shootdown 不会互相覆盖；处理方在快路径中断里读它，不需要任何锁。
static SD_VA: AtomicU64 = AtomicU64::new(0);
static SD_REQUESTS: AtomicUsize = AtomicUsize::new(0);
static SD_TIMEOUTS: AtomicUsize = AtomicUsize::new(0);
static SD_ACKS: [AtomicUsize; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicUsize::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];
static SD_INVLPG: [AtomicUsize; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicUsize::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];

/// 等回执的上界（周期）。本机 ≈6 ms；一次 shootdown 的真实代价见用例读数。
/// 定这么宽不是为了宽容，而是**目标 CPU 可能正关着中断在一个持锁的临界区里**
/// （比如它也在建自己的异常栈），那条 IPI 要等它把 IF 恢复回去才被取走。
const SHOOTDOWN_DEADLINE_CYCLES: u64 = 20_000_000;

/// 处理方（任意 CPU，由 `trap::isr_stub_shootdown` 调进来）。
///
/// 纪律与 AP 的 tick 快路径相同：**不拿锁、不分配、不打印**。这里连计数都用原子量，
/// 因为请求方正拿着 VMM(20) 锁等回执，处理方再取任何一把锁都可能变成跨 CPU 死锁——
/// 而 `sync` 的重入检测只比令牌，令牌属于别的 CPU，判不出来。
///
/// 一个细节不能省：**即使 `SD_VA` 读出来是 0 也要回执**。请求方是按名单数回执的，
/// 少一个就是它一直等到超时然后把整件事升成 L4——把"我没活儿"当成"我没到账"是错的。
pub fn shootdown_self() {
    let slot = crate::arch::x86_64::cpu::self_slot();
    let va = SD_VA.load(Ordering::Acquire);
    if va != 0 {
        tlb_invalidate(va);
        SD_INVLPG[slot].fetch_add(1, Ordering::Relaxed);
    }
    // 负样本（§12.3.1）：别的都做，**就是不回执**。请求方必须在看门狗到期时把这件事升成 L4，
    // 否则"等不齐也照样归还物理帧"这条路就是两个主人同一块页。
    #[cfg(not(feature = "fault-shootdown-noack"))]
    SD_ACKS[slot].fetch_add(1, Ordering::Release);
    crate::arch::x86_64::apic::eoi_self();
}

/// 请求方：让所有**其它在线** CPU 各回一次执，收不齐就升 L4。
/// 调用前提：持有 VMM 锁（`unmap_pages` 内部）。
fn shootdown_others(va: u64) {
    shootdown_inner(va, None)
}

/// 收窄版（ADR-072）：只通知 `mask` 位图里的在线 CPU（除自己）。
/// 调用前提：持有 VMM 锁。`mask` 的 bit i = CPU i 曾跑过该 AS（`running_on`）。
/// 内核半区 / HHDM 改动仍走 `shootdown_others`（全广播），不走这里。
pub fn shootdown_masked(va: u64, mask: u8) {
    shootdown_inner(va, Some(mask))
}

/// 公共实现：`mask=None` 全广播（原 `shootdown_others`），`Some(m)` 只通知位图里的。
/// 架构引用全在这个函数里（与原来的 `shootdown_others` 同一批行），两个 wrapper 零新增站点。
fn shootdown_inner(va: u64, mask: Option<u8>) {
    let me = crate::arch::x86_64::cpu::self_slot();
    let mut want = 0usize;
    let mut base = [0usize; crate::arch::x86_64::cpu::MAX_CPUS];
    for s2 in 0..crate::arch::x86_64::cpu::MAX_CPUS {
        let in_mask = mask.map_or(true, |m| m & (1 << s2) != 0);
        if s2 != me && in_mask && crate::arch::x86_64::cpu::is_online(s2) {
            base[s2] = SD_ACKS[s2].load(Ordering::Acquire);
            want += 1;
        }
    }
    SD_REQUESTS.fetch_add(1, Ordering::Relaxed);
    if want == 0 {
        return; // 单核或位图里没有别人：本 CPU 的条目已经在 clear_leaf 里清掉了
    }
    SD_VA.store(va, Ordering::Release);
    // 逐点名（不用"除本 CPU 外全体"的缩写：本机实测收不到，理由写在 apic::send_ipi_to 上）。
    // 顺序是"先发布 VA，再发 IPI"：处理方读的就是 SD_VA，反过来它可能读到上一条请求的 VA。
    for s2 in 0..crate::arch::x86_64::cpu::MAX_CPUS {
        let in_mask = mask.map_or(true, |m| m & (1 << s2) != 0);
        if s2 == me || !in_mask || !crate::arch::x86_64::cpu::is_online(s2) {
            continue;
        }
        let Some(dest) = crate::arch::x86_64::cpu::lapic_id_of(s2) else { continue };
        if crate::arch::x86_64::apic::send_ipi_to(dest, crate::arch::x86_64::trap::VEC_SHOOTDOWN as u32).is_err() {
            SD_VA.store(0, Ordering::Release);
            crate::log_fatal!("L4 mm: shootdown 的 IPI 发不出去（ICR 卡在投递中）va={:#x} 目标={:#x}", va, dest);
            crate::exit::finish(crate::exit::Code::ExceptionFatal);
        }
    }
    let t0 = crate::tsc::now();
    loop {
        let missing = (0..crate::arch::x86_64::cpu::MAX_CPUS).filter(|&s2| {
            let in_mask = mask.map_or(true, |m| m & (1 << s2) != 0);
            s2 != me && in_mask && crate::arch::x86_64::cpu::is_online(s2) && SD_ACKS[s2].load(Ordering::Acquire) == base[s2]
        }).count();
        if missing == 0 {
            break;
        }
        if crate::tsc::now().wrapping_sub(t0) > SHOOTDOWN_DEADLINE_CYCLES {
            SD_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            SD_VA.store(0, Ordering::Release);
            // 收不齐回执就归还物理帧 = 允许两个主人同时持有同一块页（§9.2 直接 L4）。
            crate::log_fatal!(
                "L4 mm: shootdown 超时 va={:#x} 还差 {} 个回执（每个在线 CPU 各等一次，上界 {} 周期）",
                va, missing, SHOOTDOWN_DEADLINE_CYCLES
            );
            crate::exit::finish(crate::exit::Code::ExceptionFatal);
        }
        core::hint::spin_loop();
    }
    SD_VA.store(0, Ordering::Release);
}

#[derive(Clone, Copy)]
pub struct ShootdownStats {
    pub requests: usize,
    pub timeouts: usize,
    pub acks: [usize; crate::arch::x86_64::cpu::MAX_CPUS],
    pub invlpg: [usize; crate::arch::x86_64::cpu::MAX_CPUS],
}

pub fn shootdown_stats() -> ShootdownStats {
    let mut acks = [0usize; crate::arch::x86_64::cpu::MAX_CPUS];
    let mut invlpg = [0usize; crate::arch::x86_64::cpu::MAX_CPUS];
    for (i, (a, v)) in acks.iter_mut().zip(invlpg.iter_mut()).enumerate() {
        *a = SD_ACKS[i].load(Ordering::Relaxed);
        *v = SD_INVLPG[i].load(Ordering::Relaxed);
    }
    ShootdownStats {
        requests: SD_REQUESTS.load(Ordering::Relaxed),
        timeouts: SD_TIMEOUTS.load(Ordering::Relaxed),
        acks,
        invlpg,
    }
}

/// 单核 TLB 失效。多核时这条只清本 CPU，别的 CPU 由 `shootdown_others` 通知（§6.6）。
fn tlb_invalidate(va: u64) {
    // SAFETY: invlpg 只作用于本 CPU 的 TLB，不访存
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nomem)) };
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

fn clear_leaf(va: VirtAddr) {
    // SAFETY: 只走已存在的表
    if let Some(e) = unsafe { walk_leaf(va.0, false, false, false) } {
        // SAFETY: walk_leaf 只返回有效表项
        unsafe { *e = 0 };
        tlb_invalidate(va.0);
    }
}

/// 启动上下文那条栈的 VA 区间。`sched` 用它登记任务 0 的栈边界，
/// 这样被抢占时能判断"异常帧确实就在这条栈上"。
pub fn boot_stack_range() -> (u64, u64) {
    let st = s();
    let lo = core::ptr::addr_of!(st.boot_stack) as u64;
    (lo, lo + st.boot_stack.len() as u64)
}

/// 该 VA 是否已映射（探针必须“确认未映射”，不能猜）。
///
/// **刻意不加锁**：`alloc_va_range` / `map` 在持 VMM 的循环里要读它，加了就是自死锁。
/// 多核之后的正确性论证不是"没人并发写"，而是**所有写者都在 VMM(20) 锁里**：
/// 所以持锁调用（`alloc_va_range` 的扫描、`map` 的冲突检查）看到的必然是稳定状态。
/// 锁**外**的调用（探针、用例、`frontier_covered`）读到的是无保证快照——
/// 今天这些点只出现在 BSP 且中断窗口关着的时候，多核压力测试不能依赖这一点。
pub fn is_mapped(va: u64) -> bool {
    if !is_ready() || VirtAddr::new(va).is_none() {
        return false;
    }
    let hhdm = s().hhdm;
    // SAFETY: 只读遍历自建表
    unsafe {
        let mut table = (s().pml4_phys + hhdm) as *const Page;
        let mut level = 3u8;
        loop {
            let entry = (*table).0[idx(va, level)];
            if entry & P_PRESENT == 0 {
                return false;
            }
            if level == 0 || entry & P_HUGE != 0 {
                return true;
            }
            table = ((entry & ADDR_MASK) + hhdm) as *const Page;
            level -= 1;
        }
    }
}

/// 一个 VA **真正生效**的访问权限。两位规则不同，必须分开算：
/// **P / W / U/S 逐级相与**（每级都许可才许可），**NX 逐级相或**（任一级置了不可执行就算）。
/// 为什么需要它而不是只看叶子：上级表项的 U/S=0 在叶子里根本看不见（ADR-026）。
/// `None` = 这条链没走通（某一级不存在，或撞上 2 MiB 大页而 VA 不在大页首项）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectiveFlags {
    pub user: bool,
    pub writable: bool,
    pub executable: bool,
    /// 沿途用到的表项数（2..=4）：用例用它确认自己真的走完了整条链
    pub levels: u8,
}

pub fn effective_flags(va: u64) -> Option<EffectiveFlags> {
    if !is_ready() {
        return None;
    }
    effective_flags_in(s().pml4_phys, va)
}

/// 按**槽号**读另一张 AS 里某个 VA 的生效位（P5c-3：15/16 号要校验 entry 可执行、
/// 栈页可写、StartupInfo 页**只读**，而那些页都在子 AS 里，不在当前 CR3 上）。
/// 与 `effective_flags` 共用同一段遍历，差别只有根从哪来。
pub fn aspace_effective_flags(slot: u8, va: u64) -> Option<EffectiveFlags> {
    if !is_ready() {
        return None;
    }
    let root = {
        let _g = vmm();
        let e = aspaces().items.get(usize::from(slot))?;
        if !e.used {
            return None;
        }
        e.pml4
    };
    effective_flags_in(root, va)
}

fn effective_flags_in(root: u64, va: u64) -> Option<EffectiveFlags> {
    if VirtAddr::new(va).is_none() {
        return None;
    }
    let hhdm = s().hhdm;
    // SAFETY: 只读遍历自建表，前提与 `is_mapped` 相同（所有写者都在 VMM(20) 锁里）
    unsafe {
        let mut table = (root + hhdm) as *const Page;
        let mut level = 3u8;
        let mut permit = !0u64;
        let mut nx_any = 0u64;
        let nlevels;
        loop {
            let entry = (*table).0[idx(va, level)];
            if entry & P_PRESENT == 0 {
                return None;
            }
            permit &= entry;
            nx_any |= entry & P_NX;
            if level == 0 || entry & P_HUGE != 0 {
                nlevels = 4 - level;
                break;
            }
            table = ((entry & ADDR_MASK) + hhdm) as *const Page;
            level -= 1;
        }
        Some(EffectiveFlags {
            user: permit & P_USER != 0,
            writable: permit & P_WRITE != 0,
            executable: nx_any == 0,
            levels: nlevels,
        })
    }
}

// ------------------------------------------------------------------ ADR-066（W2 P4）

/// 只读翻译遍历，返回 va 所在 4 KiB 页的物理基址（ADR-066 翻译等价的第二台仪器）。
/// 前提与 `is_mapped` 同：刻意不加锁，所有写者都在 VMM(20) 内；锁外读是无保证快照。
/// 大页 ⇒ 块物理基 + 块内偏移再下取整到 4 KiB；叶子 ⇒ 叶子物理基。不 present/非规范 ⇒ None。
pub fn phys_of(va: u64) -> Option<u64> {
    if !is_ready() || VirtAddr::new(va).is_none() {
        return None;
    }
    let hhdm = s().hhdm;
    // SAFETY: 只读遍历自建表，前提与 is_mapped 相同
    unsafe {
        let mut table = (s().pml4_phys + hhdm) as *const Page;
        let mut level = 3u8;
        loop {
            let entry = (*table).0[idx(va, level)];
            if entry & P_PRESENT == 0 {
                return None;
            }
            if level == 0 {
                return Some(entry & ADDR_MASK);
            }
            if entry & P_HUGE != 0 {
                let span = 1u64 << (12 + 9 * level as u64);
                return Some(((entry & ADDR_MASK) + (va & (span - 1))) & !(PAGE as u64 - 1));
            }
            table = ((entry & ADDR_MASK) + hhdm) as *const Page;
            level -= 1;
        }
    }
}

/// 只读回叶子表项原始值（ADR-066 见证行用：宿主机按 PAT 规则独立重算属性位对账）。
/// 大页 VA 返回大页项本身。前提与 `is_mapped` 同。
pub fn leaf_value(va: u64) -> Option<u64> {
    if !is_ready() || VirtAddr::new(va).is_none() {
        return None;
    }
    let hhdm = s().hhdm;
    // SAFETY: 只读遍历自建表，前提与 is_mapped 相同
    unsafe {
        let mut table = (s().pml4_phys + hhdm) as *const Page;
        let mut level = 3u8;
        loop {
            let entry = (*table).0[idx(va, level)];
            if entry & P_PRESENT == 0 {
                return None;
            }
            if level == 0 || entry & P_HUGE != 0 {
                return Some(entry);
            }
            table = ((entry & ADDR_MASK) + hhdm) as *const Page;
            level -= 1;
        }
    }
}

/// 把覆盖 va 的 2 MiB 大页换成 512 个**翻译等价**的 4 KiB 叶子（ADR-066，W2 P4）。
///
/// 协议（顺序有意义）：先取清零 PT 页（失败 ⇒ OutOfMemory，原大页原样）；填 512 叶子
/// （物理沿用同块、属性复制旧项、PAT 从大页 bit12 翻译到叶子 bit7、不复制 P_HUGE）；
/// 单次对齐写换 PD 项（上级 P/W/U/NX 不许变窄）；本 CPU invlpg + 块基址一次 shootdown
/// （INVLPG 失效覆盖该地址的任意条目含 2MiB，ADR-023 协议；TCG 只验协议计数）。
/// 已是 PT ⇒ 幂等空操作；不 present ⇒ NotMapped。PT 页走 new_table_frame 同形
/// （MOD_BOOT、永不归还）⇒ 成功拆分 free_frames 永久 −1，这是明码代价。
/// 上下文 KERNEL/IRQ_OFF，持 VMM(20)，可能阻塞（等回执）；ISR 禁用。
pub fn split_huge(va: VirtAddr) -> Result<(), MmError> {
    if !is_ready() {
        return Err(MmError::NotInit);
    }
    if VirtAddr::new(va.0).is_none() || (va.0 & (PAGE as u64 - 1)) != 0 {
        return Err(MmError::InvalidAddress);
    }
    let block = va.0 & !(LARGE_PAGE - 1);
    let _g = vmm();
    let hhdm = s().hhdm;
    // SAFETY: va 已验规范；自建表经 HHDM 可达；持 VMM，写者串行化
    let pd_entry: *mut u64 = unsafe {
        let mut table = (s().pml4_phys + hhdm) as *mut Page;
        let e3 = &mut (*table).0[idx(block, 3)] as *mut u64;
        if *e3 & P_PRESENT == 0 {
            return Err(MmError::NotMapped);
        }
        if *e3 & P_HUGE != 0 {
            return Err(MmError::Unsupported); // 1 GiB 大页本内核不铺，真出现说明表被写坏
        }
        table = ((*e3 & ADDR_MASK) + hhdm) as *mut Page;
        let e2 = &mut (*table).0[idx(block, 2)] as *mut u64;
        if *e2 & P_PRESENT == 0 {
            return Err(MmError::NotMapped);
        }
        if *e2 & P_HUGE != 0 {
            return Err(MmError::Unsupported);
        }
        table = ((*e2 & ADDR_MASK) + hhdm) as *mut Page;
        &mut (*table).0[idx(block, 1)] as *mut u64
    };
    // SAFETY: pd_entry 是上一步走到的有效 level-1 表项；持 VMM
    let old = unsafe { *pd_entry };
    if old & P_PRESENT == 0 {
        return Err(MmError::NotMapped);
    }
    if old & P_HUGE == 0 {
        return Ok(()); // 已拆过：幂等空操作，不分页、不发 IPI、计数不变
    }
    // 故障注入（ADR-066 验收 OOM 格）：在取 PT 页的调用点强制失败，验证原大页原样。
    let pt: Option<u64> = if cfg!(feature = "fault-split-oom") { None } else { new_table_frame() };
    let Some(pt_phys) = pt else {
        return Err(MmError::OutOfMemory); // 此刻尚未碰 PD 项，原大页原样
    };
    let attr = old & (P_WRITE | P_USER | P_NX | P_PWT | P_PCD);
    // 大页的 PAT 在 bit12，叶子的 PAT 在 bit7：翻译而不复制（复制 P_HUGE 会把 WB 变 UC- 族）
    let pat_leaf = if old & (1 << 12) != 0 { 1 << 7 } else { 0 };
    let base_phys = old & ADDR_MASK;
    // SAFETY: pt_phys 来自 new_table_frame（清零、HHDM 覆盖）；512 项在一页内；
    // PT 尚未挂进 PD，无并发读者；持 VMM
    unsafe {
        let pt_page = (pt_phys + hhdm) as *mut Page;
        for k in 0..512u64 {
            (*pt_page).0[k as usize] = (base_phys + k * PAGE as u64) | P_PRESENT | attr | pat_leaf;
        }
    }
    // 单次 8 字节对齐写发布：读者要么见旧大页、要么见填好的 PT，无半截状态
    let new_pd = pt_phys | P_PRESENT | (old & (P_WRITE | P_USER | P_NX));
    // SAFETY: pd_entry 有效且持 VMM；对齐 8 字节写在 x86 上原子
    unsafe { *pd_entry = new_pd };
    tlb_invalidate(block);
    shootdown_others(block);
    Ok(())
}

/// 公开解映射入口（ADR-066：P4 验收"块内空一叶再 map"、P5 惰性区间 drop 的真实调用者）。
/// 持 VMM 调既有 unmap_pages（逐页 clear_leaf + shootdown）。**不放手 VA 保留**（调用方自理；
/// HHDM VA 本无保留）。只作用于 4 KiB 叶子；对大页/不 present 幂等空操作（要先拆）。
/// **约束（P4 实测踩出）**：不得清"还将被释放的 RAM 帧"的 HHDM 别名——fi_final_free 的毒化
/// 经 HHDM 直写，别名缺失会 ring0 #PF。调用方要么先恢复叶子，要么只用非 HHDM 别名 VA
/// （P5 惰性区间住用户窗口）或 PMM 覆盖外的尾页（P4 用例）。
/// KERNEL；可能阻塞。不改 Mapping::drop 语义。
pub fn unmap(va: VirtAddr, pages: usize) {
    if VirtAddr::new(va.0).is_none() {
        return;
    }
    let _g = vmm();
    unmap_pages(va, pages);
}

/// 把一段 **HHDM 未覆盖** 的物理 MMIO 窗口映射到保留 VA，UC-（ADR-066，原文主语义：
/// 4 GiB 之上的 MMCFG/PCI MMIO 没有映射，按 PAT 用 UC；供 ECAM 多段/MSI-X/NVMe BAR）。
///
/// 检查顺序：参数/ready → 与 usable 相交拒（InvalidAddress，不许把 RAM 别名 UC 化）→
/// 区间内任一页已被 HHDM 映射拒（Unsupported，覆盖内重铺推迟，ADR-066 决策 5）。
/// 与 map_mmio 分工：后者是今天 PCI BAR 路径（自动发 VA、无覆盖检查），不动。
/// 返回 MmioMapping：drop 解映射 + 放手保留、不还帧（既有语义）。
pub fn map_hole(pa: u64, pages: usize) -> Result<MmioMapping, MmError> {
    if pages == 0 || (pa % PAGE as u64) != 0 {
        return Err(MmError::InvalidAddress);
    }
    if !is_ready() {
        return Err(MmError::NotInit);
    }
    // ADR-070 决策 2：第一个非内核 AS 创建之后，内核半区冻结。map_hole 是今天唯一的
    // 运行期内核半区写点，所以闸在这里；拒绝是契约违例（KernelHalfFrozen），不是资源不够。
    if kernel_half_frozen() {
        return Err(MmError::KernelHalfFrozen);
    }
    let len = pages as u64 * PAGE as u64;
    let n = s().region_count;
    for r in &regs()[..n] {
        if r.usable && pa < r.base + r.length && r.base < pa + len {
            return Err(MmError::InvalidAddress);
        }
    }
    let hhdm = s().hhdm;
    for k in 0..pages as u64 {
        if is_mapped(hhdm + pa + k * PAGE as u64) {
            crate::log_warn!("map_hole refused: {:#x} 已被 HHDM 覆盖（覆盖内重铺推迟，ADR-066）", pa);
            return Err(MmError::Unsupported);
        }
    }
    let va = alloc_va_range(pages).ok_or(MmError::OutOfMemory)?;
    let flags = PageFlags::DEVICE;
    {
        let _g = vmm();
        for k in 0..pages {
            let a = va.0 + (k as u64) * PAGE as u64;
            let p = pa + (k as u64) * PAGE as u64;
            if let Err(e) = set_leaf(a, p | flags.bits(), false, false) {
                for j in 0..k {
                    clear_leaf(VirtAddr(va.0 + (j as u64) * PAGE as u64));
                }
                return Err(e);
            }
            tlb_invalidate(a);
        }
    }
    MAP_CALLS.fetch_add(1, Ordering::Relaxed);
    MAPPED_PAGES.fetch_add(pages, Ordering::Relaxed);
    Ok(MmioMapping { virt: va, pages })
}

// ------------------------------------------------------ ADR-070（W3 P1）地址空间
//
// 第一刀的形状：**没有用户进程**。能建一个"用户半区为空、内核半区与 AS_KERNEL 逐位相等"
// 的地址空间，能在它上面跑一段内核代码（切换按"不同才写 CR3"），能销毁并回基线。
// 产品路径（map/unmap/walk/只读判据）今天仍然只认 AS_KERNEL——把"当前 AS"接进那些路径
// 是 P3 之后进程真跑起来时的事，本轮不动它们（矩阵 45 行因此一行都不该变）。

/// 非内核地址空间的定长表容量。与 `MAX_LAZY_REGIONS` 同一口径：今天无 workload 依据，
/// 按"接缝够用"定尺；P3 的 workload 实测（Q2）之后再重定。
/// AS 表容量。**P5c-3a 从 4 提到 8**，依据是两条真实并存的用量，不是"凑个 2 的幂"：
/// - 进程侧：`proc::MAX_PROCESSES = 4`，而 `process_create` 一进程一张 AS ⇒ 上限 4；
/// - 用例侧：`t_aspace_switch_isolation` 同时持有 2 张（a1/a2，跑的过程中不与进程重叠，
///   但 `t_aspace_map_vmo`/P1 那一族的 2 张与 c-3 用例的 4 张**可能同 boot 串行共存**，
///   因为它们都在 `.ktests` 里注册、彼此只要求"进来得是空的"，不是"全局只许两张"）；
/// - 4 + 2 = 6 是实测会同时要格子的最大组合，取 8 留一格余量。
///   **代价如实写**：`AS_ON` 与表项数组同步变大（每格 `AspaceEntry` 约 152 字节 ⇒ 8 格 1.2 KB，
///   在 `.bss`），且槽号位宽不变（`u8`），`running_on` 只增不减的语义不变。
pub const MAX_ADDR_SPACES: usize = 8;

/// 表项。全 Copy 数值（与 `LazyRegion` 同律）：PML4 物理地址 + 它自己建的表页帧号清单。
/// **只记自己建的**：高 256 项复制的是*项*，下层表是共享的内核表，销毁时绝不能还它们
/// （BACKLOG §147 的第 1 条结论——还了就是把内核半区抽掉）。
#[derive(Clone, Copy)]
struct AspaceEntry {
    used: bool,
    pml4: u64,
    /// 本 AS 自己取的表页帧号（PML4 那张 + 之后按需的）。0 = 空槽（帧 0 永不可分配）。
    /// 上限：PML4 1 张 + 低半区 256 项 × 每项一棵 3 层树的最坏 3 张 = 769，
    /// 但 P1 只建空 AS（1 张），给 16 是"接缝够用"的尺，不是推导值。
    pt_frames: [u64; AS_PT_SLOTS],
    pt_count: usize,
    /// **对象世代号**（P5c-1，ADR-075 决策 4 的补充）：`aspace_new` 在旧值上 +1，
    /// `aspace_release` 不清零 ⇒ 槽位复用后旧句柄的 `(slot, gen)` 必然对不上。
    gen: u32,
}

const AS_PT_SLOTS: usize = 16;
const AS_EMPTY: AspaceEntry =
    AspaceEntry { used: false, pml4: 0, pt_frames: [0; AS_PT_SLOTS], pt_count: 0, gen: 0 };

#[derive(Clone, Copy)]
struct AspaceTable {
    items: [AspaceEntry; MAX_ADDR_SPACES],
}

struct AspaceCell(UnsafeCell<AspaceTable>);
// SAFETY: 与 LazyCell 同律——读写全在 VMM(20) 内，互斥由锁提供；载荷全 Copy，无别名逃逸。
unsafe impl Sync for AspaceCell {}

static ASPACES: AspaceCell = AspaceCell(UnsafeCell::new(AspaceTable { items: [AS_EMPTY; MAX_ADDR_SPACES] }));

/// "这颗 CPU 曾跑过这个 AS"的位图，**从表项里搬出来单独放**（ADR-075 决策 2 的实现约束）。
/// bit i = CPU i 曾切入过；只增不减（换走时不摘：摘除要证明"不会再有该 AS 的 TLB 条目"，TCG 观测不到）。
/// 唯一的写点是 `aspace_switch`（换人路径）与 `aspace_register_cpu`（用例），**都不取 VMM**：
/// 换人点在 IF=0 下运行，为了登记位图去取 VMM(20) 会把本 CPU 的 shootdown 回执
/// 绑在"别的 CPU 正持着 VMM 等回执"上 ⇒ 跨 CPU 互等（实测见 M13：每次换人都登记 = `L4 mm: shootdown 超时`）。
/// 复位只发生在 `aspace_new` 发布槽位**之前**：那时还没有任何任务能切进这个槽，
/// 所以不存在"复位吃掉并发登记"的窗口；槽位被复用时同理。
static AS_ON: [AtomicU8; MAX_ADDR_SPACES] = [const { AtomicU8::new(0) }; MAX_ADDR_SPACES];

#[inline]
fn aspaces() -> &'static mut AspaceTable {
    // SAFETY: 调用方持 VMM（本模块内所有调用点都在 vmm() _guard 之后）
    unsafe { &mut *ASPACES.0.get() }
}

/// 地址空间柄（RAII）。丢弃即销毁：解映射低半区（今天为空）、归还**自己建的**表页、
/// 清表项。与 `LazyHandle` 同形：表里记帧号，归还走 `frame_put`（ADR-063 的共享归还路径，
/// 到 0 才真还），不在锁内做可能阻塞的事。
#[must_use = "地址空间柄丢弃即销毁，随手丢弃等于这个 AS 不存在"]
pub struct AspaceHandle {
    slot: u8,
}

impl AspaceHandle {
    /// 这个 AS 的槽号（`AS_ON` 的索引，也是 `Task::as_slot` 里存的那个数）。
    /// 纯数值，不取锁；柄本身已经保证槽号是当初那个 AS 的。
    pub fn slot(&self) -> u8 {
        self.slot
    }

    /// 这个 AS 的 PML4 物理地址（切换要用；表读在 VMM 内）。
    pub fn pml4(&self) -> Option<u64> {
        let _g = vmm();
        let e = aspaces().items[usize::from(self.slot)];
        if e.used { Some(e.pml4) } else { None }
    }

    /// 内核半区（PML4 高 256 项）与 `AS_KERNEL` **逐项相等**的见证（ADR-070 A1）。
    /// 返回 (比对项数, 不等项数)。读的是两张表的 raw 项，含缓存属性位——
    /// "翻译等价"必须连属性一起等价，否则 UC 窗口在两个 AS 里属性不同就是错。
    pub fn kernel_half_matches(&self) -> Option<(usize, usize)> {
        let _g = vmm();
        let e = aspaces().items[usize::from(self.slot)];
        if !e.used {
            return None;
        }
        let hhdm = s().hhdm;
        // SAFETY: 两张表都是本内核自建的页表页，经 HHDM 可达；持 VMM，写者串行化
        unsafe {
            let mine = (e.pml4 + hhdm) as *const Page;
            let kernel = (s().pml4_phys + hhdm) as *const Page;
            let mut diff = 0usize;
            for i in 256..512 {
                if (*mine).0[i] != (*kernel).0[i] {
                    diff += 1;
                }
            }
            Some((256, diff))
        }
    }

    /// 用户半区（PML4 低 256 项）此刻的 present 项数。P1 建的 AS 必须是 0。
    pub fn user_half_present(&self) -> Option<usize> {
        let _g = vmm();
        let e = aspaces().items[usize::from(self.slot)];
        if !e.used {
            return None;
        }
        let hhdm = s().hhdm;
        // SAFETY: 同上
        unsafe {
            let mine = (e.pml4 + hhdm) as *const Page;
            Some((0..256).filter(|&i| (*mine).0[i] & P_PRESENT != 0).count())
        }
    }
}

impl Drop for AspaceHandle {
    fn drop(&mut self) {
        aspace_release(self.slot);
    }
}

/// 建一个非内核地址空间：新 PML4 页（`MOD_AS_PT`，有主人），高 256 项从 `AS_KERNEL`
/// **复制项**（下层表共享，Linux `pgd_alloc` 的形状，Q5 裁决），低 256 项清零。
/// 表满/分配失败返回 None（已取的帧就地归还，不留无主帧）。上下文 KERNEL，取 VMM。
fn aspace_new_slot() -> Option<(u8, u32)> {
    if !is_ready() {
        return None;
    }
    let _g = vmm();
    let t = aspaces();
    let slot = (0..MAX_ADDR_SPACES).find(|&i| !t.items[i].used)?;
    // 取 PML4 页：走 frame_get/frame_put 的共享归还路径（ADR-063），owner 记 MOD_AS_PT。
    // 这里不能拿 OwnedFrames 然后 forget——那正是 MOD_BOOT 的老路，台账回不了基线。
    let f = match phys_alloc(0, MOD_AS_PT) {
        Ok(f) => f,
        Err(_) => return None,
    };
    let pml4 = f.base().0;
    let frame = pml4 / PAGE as u64;
    core::mem::forget(f); // 主人改记在表里（pt_frames），归还走 aspace_release
    let hhdm = s().hhdm;
    // SAFETY: pml4 刚分配、HHDM 覆盖全部物理内存；持 VMM
    unsafe {
        let mine = (pml4 + hhdm) as *mut Page;
        core::ptr::write_bytes(mine as *mut u8, 0, PAGE);
        let kernel = (s().pml4_phys + hhdm) as *const Page;
        for i in 256..512 {
            (*mine).0[i] = (*kernel).0[i];
        }
    }
    AS_ON[slot].store(0, Ordering::Release);
    let gen = t.items[slot].gen.wrapping_add(1);
    t.items[slot] = AspaceEntry { used: true, pml4, pt_frames: [0; AS_PT_SLOTS], pt_count: 0, gen };
    t.items[slot].pt_frames[0] = frame;
    t.items[slot].pt_count = 1;
    AS_PT_LIVE.fetch_add(1, Ordering::Relaxed);
    Some((slot as u8, gen))
}

/// 建一张 AS 并交出一个 **RAII 柄**（丢弃即销毁）。用例与内核自己的映射继续用它。
pub fn aspace_new() -> Option<AspaceHandle> {
    let (slot, _) = aspace_new_slot()?;
    Some(AspaceHandle { slot })
}

/// 建一张**内核侧持有**的 AS，返回 `(槽号, 世代)`，**不给 RAII 柄**（P5c-3a，ADR-075 决策 2/3）。
///
/// 为什么要另一种入口：`AspaceHandle` 是 non-Copy 且 `Drop` 里要取 VMM，
/// 放进 `proc::ProcEntry` 既不能 const 初始化、也不可能在 VMM 锁内安全丢弃（P1 就撞过这条）。
/// 所以进程名下那张 AS 的**主人是 proc 表**：`process_create` 记下 `(slot, gen)`，
/// `proc_discard`/`proc_reap` 归还名额时调 `aspace_destroy`。
/// 与 `aspace_new` 共用同一段实体（同一格 `gen` 递增、同一份 `AS_ON` 复位、同样只记自建表页），
/// 差别只在"谁负责收"——ktest 自己的 AS 继续用 RAII，两条路各配自己的证人。
pub fn aspace_new_kernel() -> Option<(u8, u32)> {
    aspace_new_slot()
}

/// 销毁内核侧持有的那张 AS（`aspace_new_kernel` 的另一半）。
/// 槽不存在返回 false（幂等：`proc_reap` 与显式收场都调它，第二次就是无效操作）。
/// **调用前提是这张 AS 上没有活着的任务**（ADR-074 的契约顺序：任务先死、映射再丢、AS 最后销），
/// 这条前提不由本函数检查——它由 `proc` 的 `threads == 0` 闸保证。
pub fn aspace_destroy(slot: u8) -> bool {
    let live = {
        let _g = vmm();
        // `get` 而不是下标：槽号越界必须是"没有这张 AS"，
        // 而不是把越界夹到最后一格去销毁别人的 AS（第一版写成 min 就是这个错）
        aspaces().items.get(usize::from(slot)).map_or(false, |e| e.used)
    };
    if !live {
        return false;
    }
    aspace_release(slot);
    true
}

/// 销毁一个 AS（柄丢弃时调）。P1 的低半区为空，所以今天只做"归还自己建的表页 + 清表项"。
/// **归还顺序**：先清表项（别的上下文从此查不到它），再逐帧 `frame_put`。
/// `frame_put` 自己取 PMM——所以这里**必须先放 VMM**（20 之内取 30 合法，但 frame_put
/// 到 0 会走 fi_final_free → 台账，那条路今天与 VMM 无嵌套冲突；保持"依次获取"最稳）。
fn aspace_release(slot: u8) {
    let frames = {
        let _g = vmm();
        let t = aspaces();
        let e = &mut t.items[usize::from(slot)];
        if !e.used {
            return;
        }
        let n = e.pt_count;
        let mut out = [0u64; AS_PT_SLOTS];
        out[..n].copy_from_slice(&e.pt_frames[..n]);
        // **gen 活过销毁**（P5c-3a 修的那条 ABA，`proc::job_destroy` 同一形状）：
        // 整项写回 AS_EMPTY 会把 gen 复位成 0，下一张 AS 复用这格又变 1
        // ⇒ 旧句柄的 `(slot, gen)` 重新匹配上，世代号就白加了。
        let gen = e.gen;
        *e = AS_EMPTY;
        e.gen = gen;
        (out, n)
    };
    // 锁外归还：frame_put 到 0 才真还（毒化 + 台账 + free_frames），与 SharedFrame::drop 同律
    for i in 0..frames.1 {
        if let Err(e) = frame_put(frames.0[i]) {
            free_violation(e, PhysAddr(frames.0[i] * PAGE as u64), MOD_AS_PT);
        }
    }
    AS_PT_LIVE.fetch_sub(frames.1, Ordering::Relaxed);
}

/// 按槽号读它的 PML4 物理地址（槽不存在返回 None）。**给登记路径用一次**：
/// 换人热路径不该为了查根表去取 VMM——那会把别的 CPU 的 shootdown 等待绑到本 CPU 上，
/// 而本 CPU 此刻 IF=0（ADR-075 决策 2 的实现约束）。
pub fn aspace_pml4_of(slot: u8) -> Option<u64> {
    let _g = vmm();
    let e = aspaces().items.get(usize::from(slot))?;
    if e.used { Some(e.pml4) } else { None }
}

/// 这个 AS 槽**当前这次使用**的世代号（不存在返回 None）。句柄要存 `(slot, gen)` 两格，
/// 理由同 `proc::job_gen`：只比槽号会让新 AS 继承旧 AS 的句柄（槽号是复用的）。
pub fn aspace_gen(slot: u8) -> Option<u32> {
    let _g = vmm();
    let e = aspaces().items.get(usize::from(slot))?;
    if e.used { Some(e.gen) } else { None }
}

/// `(槽号, 世代)` 两者都对才算活着（句柄使用前的活性判据）。
pub fn aspace_live(slot: u8, gen: u32) -> bool {
    aspace_gen(slot) == Some(gen)
}

/// 此刻存在的非内核 AS 数（收尾判据与用例自足用）。
pub fn aspace_count() -> usize {
    let _g = vmm();
    aspaces().items.iter().filter(|e| e.used).count()
}

/// 读一个 AS 的 CPU 位图（ADR-072 见证）。slot 不存在返回 None。
/// 位图本体是 `AS_ON`（不取锁的原子）；这里取 VMM 只为了判"这个槽还在不在"。
pub fn aspace_running_on(slot: u8) -> Option<u8> {
    let _g = vmm();
    let e = aspaces().items.get(usize::from(slot))?;
    if e.used { Some(AS_ON[usize::from(slot)].load(Ordering::Acquire)) } else { None }
}

/// 手动把一颗 CPU 登记进 AS 的位图（**用例专用**：产品路径由 `aspace_switch` 自动登记）。
/// 返回登记前的位图。slot 不存在返回 None。
pub fn aspace_register_cpu(slot: u8, cpu: usize) -> Option<u8> {
    let bit = 1u8.checked_shl(cpu as u32)?;
    let _g = vmm();
    let e = aspaces().items.get(usize::from(slot))?;
    if !e.used { return None; }
    let cell = &AS_ON[usize::from(slot)];
    let old = cell.fetch_or(bit, Ordering::AcqRel);
    Some(old)
}

// ------------------------------------------------------ ADR-074（W3 P4）往指定 AS 铺映射

/// 一次 `aspace_map` 能铺的最大页数。与 `MAX_LAZY_PAGES` 同一口径：接缝够用，欠 workload 依据。
pub const MAX_AS_MAP_PAGES: usize = 16;

/// 读**指定 AS** 里某个 VA 的叶子表项（第二台仪器：不靠切 CR3、不碰用户页，所以与 SMAP 无关）。
/// 不存在/不 present 返回 None。ADR-074 的 C6/C7 用它对照两棵树。
/// `aspace_leaf` 的按槽号版（P5c-3：15/16 号要校验 entry/sp/StartupInfo 的 VA 在**子 AS** 里已映射，
/// 而那时手里只有 proc 表记的槽号，没有 RAII 柄）。判据与它逐字相同：槽在、根有效、只走已存在的表。
pub fn aspace_leaf_slot(slot: u8, va: VirtAddr) -> Option<u64> {
    if VirtAddr::new(va.0).is_none() {
        return None;
    }
    let _g = vmm();
    let e = aspaces().items.get(usize::from(slot))?;
    if !e.used {
        return None;
    }
    // SAFETY: 根是表里核对过的有效 PML4，va 规范，持 VMM，create=false 只走已存在的表
    let leaf = unsafe { walk_leaf_in(e.pml4, None, va.0, false, false, false)? };
    // SAFETY: 上一行返回的是有效表项指针
    let v = unsafe { *leaf };
    if v & P_PRESENT == 0 { None } else { Some(v) }
}

pub fn aspace_leaf(space: &AspaceHandle, va: VirtAddr) -> Option<u64> {
    aspace_leaf_slot(space.slot, va)
}

/// 往指定 AS 铺的一段**共享**映射（ADR-074 决策 3）。帧的主人不是它（是 VMO），
/// 这里每页只持一个 `frame_get` 参考。丢弃即"清叶子 + 按位图 shootdown + 逐帧 put"。
///
/// 生命周期契约：**映射柄先丢、AS 柄后丢**。反了也不泄漏帧（Drop 里核对 AS 还在不在，
/// 不在就只还参考——表页已经归还，没有叶子可清），但少一次清叶子，所以用例按契约写。
#[must_use = "映射柄丢弃即解映射并还参考，随手丢弃等于这段映射不存在"]
pub struct AspaceMapping {
    /// `None` = 内核那份 AS（今天所有任务共用它，见 `aspace_map_self`）。
    as_slot: Option<u8>,
    root: u64,
    va: VirtAddr,
    pages: usize,
    frames: [u64; MAX_AS_MAP_PAGES],
    /// 只用于归还失败时的 L4 文案（真正的归属在 FrameInfo 里）。
    owner: ModuleId,
}

impl AspaceMapping {
    /// 这份映射铺在哪张 AS 里（`None` = 内核那份）。P6b 的归属搬迁用它认人：
    /// 只搬"目标 AS 是子进程那张"的项，创建者自己的镜像映射不动。
    pub fn as_slot(&self) -> Option<u8> {
        self.as_slot
    }
    pub fn virt(&self) -> VirtAddr {
        self.va
    }
    pub fn pages(&self) -> usize {
        self.pages
    }
}

impl Drop for AspaceMapping {
    fn drop(&mut self) {
        let n = self.pages.min(MAX_AS_MAP_PAGES);
        let mut out = [0u64; MAX_AS_MAP_PAGES];
        out[..n].copy_from_slice(&self.frames[..n]);
        {
            let _g = vmm();
            // 内核 AS 没有表项可核对，它永远在；非内核 AS 要核对"还是当初那一棵"
            let live = match self.as_slot {
                None => true,
                Some(slot) => {
                    let e = &aspaces().items[usize::from(slot)];
                    e.used && e.pml4 == self.root
                }
            };
            if live {
                let mask = match self.as_slot {
                    None => None,
                    Some(slot) => Some(AS_ON[usize::from(slot)].load(Ordering::Acquire)),
                };
                for k in 0..n {
                    let a = self.va.0 + (k as u64) * PAGE as u64;
                    // SAFETY: root 刚核对过（或就是内核根），这段叶子是本结构铺的，持 VMM
                    if let Some(leaf) = unsafe { walk_leaf_in(self.root, None, a, false, false, false) } {
                        // SAFETY: 上一行返回的是有效表项指针
                        unsafe { *leaf = 0 };
                        tlb_invalidate(a);
                        // 清完叶子才等回执，回执收齐之前不还帧（ADR-023/072）。
                        // 非内核 AS 只通知跑过它的 CPU；内核 AS 的改动仍全广播。
                        match mask {
                            Some(m) => shootdown_masked(a, m),
                            None => shootdown_others(a),
                        }
                    }
                }
                // VA 保留跟着映射一起放手（与 Mapping::drop 同律）。用例里那个固定 VA 没有保留，
                // 这一句就是无效操作；syscall 路径的 VA 是 alloc_user_va_range 发的，必须还。
                release_va_locked(self.va.0);
                UNMAPPED_PAGES.fetch_add(n, Ordering::Relaxed);
            }
        }
        // 锁外还参考：frame_put 到 0 才真还（毒化 + 台账 + free_frames），与 aspace_release 同律
        for f in out.iter().take(n) {
            if let Err(err) = frame_put(*f) {
                free_violation(err, PhysAddr(*f * PAGE as u64), self.owner);
            }
        }
    }
}

/// 把 `frames`（帧号清单，主人仍是调用方）铺进 `space` 的用户半区 `va` 处。
///
/// 四条前置，每条都是结构性的而不是"再查一遍"：
/// 1. **W^X**：收的是 `PageFlags`，而它只能由 `PageFlags::new` 造，W+X 在构造期就失败了。
/// 2. **只许用户半区**：高 256 项的下层表是与内核**共享**的，写那里等于改内核表
///    （ADR-070 决策 2 的冻结），所以直接 `KernelHalfFrozen`。
/// 3. **冲突在那棵树里判**：`AlreadyMapped` 查的是 `space` 的根，不是内核根——
///    这是"同一 VA 在两个 AS 里各自映射互不影响"（ADR-070 A4）的实现点。
/// 4. **不拥有帧**：每页 `frame_get` 拿一个参考，Drop 里 `frame_put` 还它。
///
/// 上下文 KERNEL，取 VMM；可能阻塞（Drop 里等 shootdown 回执）。失败不留半截映射。
pub fn aspace_map(
    space: &AspaceHandle,
    frames: &[u64],
    va: VirtAddr,
    flags: PageFlags,
    owner: ModuleId,
) -> Result<AspaceMapping, MmError> {
    let _g = vmm();
    let e = &aspaces().items[usize::from(space.slot)];
    if !e.used {
        return Err(MmError::NoSuchAspace);
    }
    let root = e.pml4;
    map_shared(root, Some(space.slot), frames, va, flags, owner)
}

/// 铺进**内核那份 AS** 的用户半区（ADR-074 决策 4 的 P4b 形状）。
/// 今天所有任务共用 AS_KERNEL，所以 syscall 14 的"映射进调用者自己的 AS"就是这一份；
/// P5 起每进程一份 AS，那个入口改成查任务的 AS 槽，本函数留给内核自己的映射用。
/// 与 `aspace_map` 的三点不同：根是内核 PML4、新建表页记 `MOD_BOOT`（内核生命周期）、
/// 解映射时**全广播** shootdown（内核 AS 在每颗在线 CPU 上都跑过）。
pub fn aspace_map_self(
    frames: &[u64],
    va: VirtAddr,
    flags: PageFlags,
    owner: ModuleId,
) -> Result<AspaceMapping, MmError> {
    map_shared(s().pml4_phys, None, frames, va, flags, owner)
}

/// 按**槽号**铺映射（ADR-075 决策 6：14 号的 `rdx`=AS 句柄那条路）。
/// 与 `aspace_map` 是同一实体，差别只在引用的来源：那里是"当初建它的 RAII 柄"，
/// 这里是句柄表里核过世代号的槽号 ⇒ 没有柄可依赖，`used` 必须自己核。
/// 槽位在这一步之后被销毁也不危险：`AspaceMapping::drop` 本来就要重核
/// `e.used && e.pml4 == self.root`，核不过就不清叶子（ADR-074 的契约）。
///
/// 上下文 KERNEL，取 VMM；失败不留半截映射。
pub fn aspace_map_slot(
    slot: u8,
    frames: &[u64],
    va: VirtAddr,
    flags: PageFlags,
    owner: ModuleId,
) -> Result<AspaceMapping, MmError> {
    let _g = vmm();
    let e = aspaces().items.get(usize::from(slot)).ok_or(MmError::NoSuchAspace)?;
    if !e.used {
        return Err(MmError::NoSuchAspace);
    }
    map_shared(e.pml4, Some(slot), frames, va, flags, owner)
}

/// 两个入口共用的铺设体。调用方已持 VMM 并核对过根。
fn map_shared(
    root: u64,
    as_slot: Option<u8>,
    frames: &[u64],
    va: VirtAddr,
    flags: PageFlags,
    owner: ModuleId,
) -> Result<AspaceMapping, MmError> {
    if !is_ready() {
        return Err(MmError::NotInit);
    }
    if frames.is_empty() || frames.len() > MAX_AS_MAP_PAGES {
        return Err(MmError::InvalidAddress);
    }
    if VirtAddr::new(va.0).is_none() || (va.0 & (PAGE as u64 - 1)) != 0 {
        return Err(MmError::InvalidAddress);
    }
    // 用户半区 = PML4 下标 0..256。高半区的下层表与内核共享，写它就是改内核表。
    if idx(va.0, 3) >= 256 {
        return Err(MmError::KernelHalfFrozen);
    }
    let n = frames.len();
    let mut got = [0u64; MAX_AS_MAP_PAGES];
    // 先整段查冲突：不留"铺了一半才发现冲突"的中间态
    for k in 0..n {
        let a = va.0 + (k as u64) * PAGE as u64;
        // SAFETY: root 是调用方核对过的有效 PML4，va 规范且页对齐，持 VMM
        if let Some(leaf) = unsafe { walk_leaf_in(root, None, a, false, false, false) } {
            // SAFETY: 上一行返回的是有效表项指针
            if unsafe { *leaf } & P_PRESENT != 0 {
                return Err(MmError::AlreadyMapped);
            }
        }
    }
    for k in 0..n {
        let a = va.0 + (k as u64) * PAGE as u64;
        let f = frames[k];
        // frame_get 取 PMM(30)，这里持 VMM(20)：正向嵌套（lock-order.md）
        let shared = frame_get(f);
        got[k] = f;
        // 参考改记在返回的 AspaceMapping 里（与 aspace_new 记 pt_frames 同一手法）
        core::mem::forget(shared);
        if let Err(err) = set_leaf_in(root, as_slot, a, f * PAGE as u64 | flags.bits(), false, flags.user) {
            // 回滚：清掉已铺的叶子，还掉已拿的参考（含这一次）
            for j in 0..=k {
                let b = va.0 + (j as u64) * PAGE as u64;
                // SAFETY: 同上；j == k 那一页可能没写成，清它是幂等空操作
                if let Some(leaf) = unsafe { walk_leaf_in(root, None, b, false, false, false) } {
                    // SAFETY: 有效表项指针
                    unsafe { *leaf = 0 };
                    tlb_invalidate(b);
                }
            }
            for j in 0..=k {
                if let Err(e2) = frame_put(got[j]) {
                    free_violation(e2, PhysAddr(got[j] * PAGE as u64), owner);
                }
            }
            return Err(err);
        }
        tlb_invalidate(a);
    }
    MAP_CALLS.fetch_add(1, Ordering::Relaxed);
    MAPPED_PAGES.fetch_add(n, Ordering::Relaxed);
    let mut out = AspaceMapping { as_slot, root, va, pages: n, frames: [0; MAX_AS_MAP_PAGES], owner };
    out.frames[..n].copy_from_slice(&got[..n]);
    Ok(out)
}

/// 把本 CPU 切到给定 PML4。**只在目标与当前 CR3 不同时才写**（ADR-070 决策 4 / A2 判据）。
/// 返回"这次真的写了 CR3 吗"。调用方必须保证目标表的内核半区与 AS_KERNEL 等价
/// （否则一切换内核代码就取不到指）——这个前提由 `aspace_new` 的构造保证，
/// 而 A1 的见证函数负责把它变成可判的。
///
/// `me` 是调用方的 CPU 槽号（由调用方传入，避免本函数新增 arch:: 引用撞棘轮）。
/// `as_slot` 是目标 AS 的槽号（`None` = 切回内核表）；切换成功后把 `me` 登记进
/// `AS_ON[as_slot]`（ADR-072：只增不减）。
///
/// **本函数不取任何锁**（ADR-075 决策 2 的实现约束）：它的调用点之一是 IF=0 下的换人路径
/// （`sched::preempt_point`，异常出口），在那里取 VMM(20) 会让本 CPU 停在自旋里、
/// 取不到别的 CPU 发来的 shootdown IPI，而那个 CPU 正持着 VMM 等本 CPU 的回执 ⇒ 互等 6 ms 到 L4。
/// 槽号由调用方（`Task.as_slot`，登记时已核对过）传入，所以这里不需要为查表而拿锁。
///
/// # Safety
/// `pml4` 必须是本内核自建、内核半区已复制等价的有效 PML4 物理地址；
/// `as_slot` 必须是 `pml4` 所属 AS 的槽号（错传只会把一个多余的 CPU 位写进别的 AS 的位图，
/// 后果是收窄范围放大，不会漏通知）；调用时 IF 状态由调用方负责（本函数不动 IF）。
pub unsafe fn aspace_switch(pml4: u64, me: usize, as_slot: Option<u8>) -> bool {
    // SAFETY: 读 CR3 是特权读，调用方在 ring0；原语在上方 global_asm 里，只动 CR3
    let cur = unsafe { aspace_cr3_read() };
    if cur == pml4 {
        return false;
    }
    // SAFETY: 调用方保证 pml4 有效且内核半区等价；原语只换表不动栈
    unsafe { aspace_cr3_write(pml4) };
    CR3_WRITES.fetch_add(1, Ordering::Relaxed);
    // ADR-072：登记"这颗 CPU 曾跑过这个 AS"。只增不减（换走时不摘）。
    // 位图在 `AS_ON`（原子，不取锁）——见上面那段"本函数不取任何锁"。
    // 位图是 u8（8 位 = MAX_CPUS），checked_shl 在 me>=8 时返回 None，不引入 arch:: 引用。
    if let (Some(slot), Some(bit)) = (as_slot, 1u8.checked_shl(me as u32)) {
        if let Some(cell) = AS_ON.get(usize::from(slot)) {
            cell.fetch_or(bit, Ordering::AcqRel);
        }
    }
    true
}

/// 切回内核 AS 的便利入口。返回是否真的写了。`me` 同 `aspace_switch`。
///
/// # Safety
/// 同 `aspace_switch`；`our_cr3()` 非 0（启动已切换）。
pub unsafe fn aspace_switch_kernel(me: usize) -> bool {
    // SAFETY: our_cr3 是启动时建的内核表，前提由 take_over 保证；内核表没有 AS 槽
    unsafe { aspace_switch(our_cr3(), me, None) }
}

/// 已有非内核 AS 之后，内核半区的新映射一律拒绝（ADR-070 决策 2 的冻结前置，判据 A6）。
/// 今天唯一的运行期内核半区写点是 `map_hole`（`map`/`map_device` 的 VA 都在启动期定形），
/// 所以闸放在它的入口；将来若新增内核半区写点，必须同样过这道闸。
fn kernel_half_frozen() -> bool {
    let _g = vmm();
    aspaces().items.iter().any(|e| e.used)
}

// ------------------------------------------------------ ADR-067（W2 P5）惰性区间

/// 惰性区间容量（ADR-067 未决 5：今天无 workload 依据，按"接缝够用"定尺）。
pub const MAX_LAZY_REGIONS: usize = 8;
pub const MAX_LAZY_PAGES: usize = 16;

/// 表项。存**数值**而不是 `Option<Mapping>` 数组：后者非 Copy 不能 const 初始化，
/// 且 Mapping::drop 会在已持 VMM 的编排里重入 VMM（重入即 L4）。归还走
/// `unmap + phys_free` 的依次取锁编排，与 Mapping::drop 同律（解映射在归还之前，
/// shootdown 由 unmap_pages 内部兑现，ADR-023）。
#[derive(Clone, Copy)]
struct LazyRegion {
    used: bool,
    base: u64,
    pages: u16,
    /// 已填充位图：占用唯一真相（ADR-065 同律）。
    filled: u16,
    owner: ModuleId,
    /// 已填充页的物理基（帧 0 永不可分配 ⇒ 0 可作"无帧"哨兵）。
    frames: [u64; MAX_LAZY_PAGES],
}

const LAZY_EMPTY: LazyRegion =
    LazyRegion { used: false, base: 0, pages: 0, filled: 0, owner: ModuleId(0), frames: [0; MAX_LAZY_PAGES] };

#[derive(Clone, Copy)]
struct LazyTable {
    items: [LazyRegion; MAX_LAZY_REGIONS],
}

struct LazyCell(UnsafeCell<LazyTable>);
// SAFETY: 表的读写全部在 VMM(20) 内（lazy_new/demand_zero_try/lazy_release/查询），
// 互斥由锁提供；锁外只读快照不存在（调用方都持锁）。载荷全为 Copy 数值，无别名逃逸。
unsafe impl Sync for LazyCell {}

static LAZY: LazyCell = LazyCell(UnsafeCell::new(LazyTable { items: [LAZY_EMPTY; MAX_LAZY_REGIONS] }));

#[inline]
fn lazy_items() -> &'static mut LazyTable {
    unsafe { &mut *LAZY.0.get() }
}

static DEMAND_ZERO_COUNT: AtomicUsize = AtomicUsize::new(0);
/// 输家计数：分配了帧、但 map 撞 AlreadyMapped 而把帧归还的次数（ADR-067 决策 5 的证人）。
static DEMAND_ZERO_LOST: AtomicUsize = AtomicUsize::new(0);

/// 输家还帧次数（竞争格的直接判据；绝对帧差不用它，因为别的用例的延迟回收会污染窗口）。
pub fn demand_zero_lost() -> usize {
    DEMAND_ZERO_LOST.load(Ordering::Relaxed)
}

/// 已填页数（需求修复计数，用例与宿主机对账用，ADR-067 决策 7）。
pub fn demand_zero_count() -> usize {
    DEMAND_ZERO_COUNT.load(Ordering::Relaxed)
}

/// 在用区间数（"槽位回基线"判据的证人）。
pub fn lazy_region_count() -> usize {
    let _g = vmm();
    lazy_items().items.iter().filter(|r| r.used).count()
}

/// 惰性区间柄（ADR-067 决策 2）：OwnedSet 的一项挂这个；**丢弃即归还**——
/// 解映射全部已填充页、归还全部帧、放手整段 VA 保留。非 Copy：所有权唯一。
pub struct LazyHandle {
    slot: u8,
}

impl LazyHandle {
    /// 区间起始 VA（用例装桩代码与竞争格需要；表读在 VMM 内）。
    pub fn base(&self) -> Option<u64> {
        let _g = vmm();
        let r = lazy_items().items[usize::from(self.slot)];
        if r.used { Some(r.base) } else { None }
    }
}

impl Drop for LazyHandle {
    fn drop(&mut self) {
        lazy_release(self.slot);
    }
}

/// 登记一段用户窗口内的惰性区间（决策 1/2）。VA 走 `alloc_user_va_range`（动态区、
/// 进共用保留表，ADR-028 分区规则结构兼容）。表满/参数错返回 None（已发的 VA 就地放手，
/// 不留无主保留）。上下文 KERNEL，取 VMM。
#[must_use = "惰性区间柄丢弃即归还，随手丢弃等于区间不存在"]
pub fn lazy_new(pages: usize, owner: ModuleId) -> Option<LazyHandle> {
    if pages == 0 || pages > MAX_LAZY_PAGES || !is_ready() {
        return None;
    }
    let va = alloc_user_va_range(pages)?;
    let _g = vmm();
    for i in 0..MAX_LAZY_REGIONS {
        let r = &mut lazy_items().items[i];
        if !r.used {
            *r = LazyRegion { used: true, base: va.0, pages: pages as u16, filled: 0, owner, frames: [0; MAX_LAZY_PAGES] };
            return Some(LazyHandle { slot: i as u8 });
        }
    }
    release_va_locked(va.0);
    None
}

/// #PF 修复入口（ADR-067 决策 3/4）。命中已登记区间才动手：
/// 查表（VMM 内）→ 放锁 → phys_alloc（PMM）→ 清零（HHDM，ADR-064 同律）→ map（VMM）→
/// 回表置位（VMM，并核验槽位身份未变——变了就自我清理走原 Kill 路径）。
/// 依次获取不算嵌套（lock-order.md）；**本路径绝不碰 RUNQ**（§136 教训）。
/// 返回 true = 页此刻已映射，重执行将成功；false = 不修，走既有 Kill/Fatal 判据。
pub fn demand_zero_try(cr2: u64) -> bool {
    if !is_ready() {
        return false;
    }
    let va = cr2 & !(PAGE as u64 - 1);
    let hit = {
        let _g = vmm();
        let mut found = None;
        for (i, r) in lazy_items().items.iter().enumerate() {
            if !r.used || cr2 < r.base || cr2 >= r.base + r.pages as u64 * PAGE as u64 {
                continue;
            }
            let idx = (va - r.base) as usize / PAGE;
            found = Some((i, idx, r.filled & (1 << idx) != 0, r.owner));
            break;
        }
        found
    };
    let Some((slot, idx, already, owner)) = hit else { return false };
    if already {
        return true;
    }
    let Ok(frames) = phys_alloc(0, owner) else {
        return false; // 分配失败不吞错、不降级：false ⇒ 走原 Kill 路径
    };
    let p = frames.base().0;
    // 分配即清零：自由帧毒化是 0xA5，不清零就是把陈旧物理内存交出去（ADR-064 决策 2 同理）
    // SAFETY: p 来自 phys_alloc，HHDM 覆盖全部 max_phys；页对齐；帧此刻归本路径独占
    unsafe { core::ptr::write_bytes((p + s().hhdm) as *mut u8, 0, PAGE) };
    // 竞争变体（ADR-067 验收⑥的确定性构造）：把"已查未填 → 分配 → 装页"的窗口拉宽，
    // 让四路竞争者重叠；默认构建不睡，重叠与否由 TCG 现实时序决定。
    // 用定圈 pause 而不是 `tsc::spin`：后者会给环内 memory->time 加引用站点（棘轮只许降）。
    #[cfg(feature = "race-demand-zero")]
    for _ in 0..20_000 {
        core::hint::spin_loop();
    }
    let m = match map(VirtAddr(va), frames, PageFlags::USER_RW) {
        Ok(m) => m,
        // 输家：别人刚填了同一页。frames 已随 map 的 Err 路径 Drop 归还（毒化+台账），
        // 页此刻已映射 ⇒ 返回 true 让赢家填的那页被重执行读到（结构自带还帧，决策 5）。
        Err(MmError::AlreadyMapped) => {
            DEMAND_ZERO_LOST.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        Err(_) => return false,
    };
    core::mem::forget(m); // 归还唯一入口是 lazy_release（表里记帧号），这里不留柄
    let _g = vmm();
    let r = &mut lazy_items().items[slot];
    if !r.used || r.base != va - idx as u64 * PAGE as u64 {
        // 槽位在锁间隙被回收/复用（W2 单 AS 里构造不出来，防御性走自我清理）
        unmap_locked(VirtAddr(va), 1);
        if let Err(e) = phys_free(PhysAddr(p), 0, owner) {
            free_violation(e, PhysAddr(p), owner);
        }
        return false;
    }
    r.filled |= 1 << idx;
    r.frames[idx] = p;
    DEMAND_ZERO_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

/// 归还一个区间（决策 2）。编排：VMM 内快照并清槽 → 放锁 → 逐页 unmap（内含
/// shootdown）+ phys_free（解映射在归还之前，ADR-023）→ release_va 放手整段保留。
/// **不得持有任何锁调用**（handle drop 发生在 release_owned 放掉 RUNQ 之后，§136/ADR-027）。
fn lazy_release(slot: u8) {
    let snap = {
        let _g = vmm();
        let r = &mut lazy_items().items[usize::from(slot)];
        if !r.used {
            return;
        }
        let s = *r;
        *r = LAZY_EMPTY;
        s
    };
    for i in 0..snap.pages as usize {
        if snap.filled & (1 << i) == 0 {
            continue;
        }
        unmap(VirtAddr(snap.base + i as u64 * PAGE as u64), 1);
        if let Err(e) = phys_free(PhysAddr(snap.frames[i]), 0, snap.owner) {
            free_violation(e, PhysAddr(snap.frames[i]), snap.owner);
        }
    }
    if !release_va(snap.base) {
        crate::log_warn!("lazy: 区间 {:#x} 的 VA 保留没放手（还有映射？）", snap.base);
    }
}

/// demand_zero_try 的锁内变体：仅在**已经**持 VMM 的防御清理分支里用
/// （直接调 unmap 会重入 VMM ⇒ L4）。
fn unmap_locked(va: VirtAddr, pages: usize) {
    unmap_pages(va, pages);
}

// ------------------------------------------------------------------ 锁
// 两把**只当令牌用**的锁（载荷是空元组）：保证"同一时刻只有一个上下文在改结构"，
// 状态本体仍住在 `State` 里（`s()` 这套访问已遍布本模块，塞进锁里改动量远大于收益）。
// 顺序依据 `docs/architecture/lock-order.md`：VMM(20) 之内可以叫 PMM(30)，反过来绝不许可。
// **先取后放再取下一个**是合法的（依次获取不算嵌套），前提是 `IrqGuard::drop` 会还原等级栈。
static VMM_LOCK: IrqSpinLock<()> = IrqSpinLock::new(sync::RANK_VMM, ());
static PMM_LOCK: IrqSpinLock<()> = IrqSpinLock::new(sync::RANK_PMM, ());

#[inline]
fn vmm() -> IrqGuard<'static, ()> {
    VMM_LOCK.lock()
}

#[inline]
fn pmm() -> IrqGuard<'static, ()> {
    PMM_LOCK.lock()
}

// ------------------------------------------------------------------ 物理分配

fn bit_get(frame: u64) -> bool {
    let st = s();
    let w = (frame / 64) as usize;
    if w >= BITMAP_WORDS {
        return true;
    }
    st.bitmap[w].load(Ordering::Relaxed) >> (frame % 64) & 1 == 1
}

fn bit_set(frame: u64, used: bool) {
    let st = s();
    let w = (frame / 64) as usize;
    if w >= BITMAP_WORDS {
        return;
    }
    if used {
        st.bitmap[w].fetch_or(1 << (frame % 64), Ordering::Relaxed);
    } else {
        st.bitmap[w].fetch_and(!(1 << (frame % 64)), Ordering::Relaxed);
    }
}

/// 接管之后再解析内存映射：全标已用 -> 只放开 Usable ->
/// 再把**已被我们的页表占用的物理页**从空闲里收回（早期池 + PML4 都在 .bss，
/// 属于内核镜像区间，而内核镜像被 memmap 标成 ExecutableAndModules，天然不放开）。
pub fn init_allocator() -> Result<(), MmError> {
    let _g = pmm();
    let st = s();
    for w in &st.bitmap {
        w.store(u64::MAX, Ordering::Relaxed);
    }
    let mut free = 0usize;
    let count = st.region_count;
    let max_phys = st.max_phys;
    // 只放开 Usable。bootloader 信息区由 reclaim_bootloader_regions() 显式回收，
    // 因为里面可能住着 AP 的停车点（实测：过早回收 = 三重故障 = QEMU rc=0）。
    for r in &regs()[..count] {
        if r.usable {
            let first = r.base / PAGE as u64;
            let count = r.length.div_ceil(PAGE as u64);
            for f in first..first + count {
                if f < (max_phys / PAGE as u64) {
                    bit_set(f, false);
                }
            }
        }
    }
    // 低 4 KiB 不用（协议允许 rev>=3 把它标成 usable，但踩它没有好处）
    bit_set(0, true);
    let limit = max_phys / PAGE as u64;
    for f in 0..limit {
        if !bit_get(f) {
            free += 1;
        }
    }
    let st = s();
    st.total_frames.store(limit as usize, Ordering::Relaxed);
    st.free_frames.store(free, Ordering::Relaxed);
    // P1a（ADR-063）：两阶段引导的第二步——分出 FrameInfo 元数组并把位图状态平移进去。
    // 位图仍是分配的唯一真相（影子模式），元数组只供对账；P1b 才接管。
    // 引导失败往上传 MmError，由 integration（main）记日志/停机——mm 不新增 diagnostics 引用
    // （环内 memory->diagnostics 受 ADR-044 棘轮约束，只许减不许增）。
    bootstrap_frame_info(limit)
}

/// 引导 FrameInfo 影子数组（ADR-063 决策 2）。**调用方已持 PMM 锁**（init_allocator）。
/// 阶段 A：用现位图分出元数组自身的连续帧（归 MOD_BOOT、永不归还，与页表页同形）；
/// 阶段 B：逐帧把位图状态平移进 FrameInfo（已用⇒refcnt 1，自由⇒0）。
/// 元数组覆盖到它自己的帧是正常的——那些帧在阶段 A 已被位图标 USED，平移后 refcnt=1。
fn bootstrap_frame_info(limit: u64) -> Result<(), MmError> {
    let st = s();
    let bytes = limit as usize * FRAME_INFO_BYTES;
    let pages = bytes.div_ceil(PAGE);
    if pages == 0 {
        return Ok(());
    }
    let order = (usize::BITS - 1 - pages.leading_zeros()) as u8;
    // 阶段 A：分出元数组帧。forget 掉 OwnedFrames——这些帧永久持有，不走 Drop 归还。
    let frames = phys_alloc_locked(order, MOD_BOOT)?;
    let base = frames.base().0;
    core::mem::forget(frames);
    let hhdm = st.hhdm;
    let arr = (hhdm + base) as *mut FrameInfo;
    // 阶段 B：平移位图状态。每个条目都写满（refcnt/flags/owner），不留引导期的脏字节。
    for f in 0..limit {
        let used = bit_get(f);
        // SAFETY: arr 指向刚分出的 2^order 帧（>= limit 个条目），f<limit 在界内；
        // 此刻单核 IF=0（init），无并发；元数组帧归 MOD_BOOT 永不归还，生命周期是整个内核。
        unsafe {
            let e = &mut *arr.add(f as usize);
            e.refcnt = AtomicU32::new(if used { 1 } else { 0 });
            e.flags = if used { FI_USED } else { FI_FREE };
            e.owner = if used { MOD_BOOT } else { ModuleId(0) };
        }
    }
    st.frame_info.store(hhdm + base, Ordering::Release);
    st.frame_info_frames = limit as usize;
    Ok(())
}

/// FrameInfo 数组的规模（帧条目数, 占用字节）。供启动日志与宿主机对账。
pub fn frame_info_size() -> (usize, usize) {
    let st = s();
    (st.frame_info_frames, st.frame_info_frames * FRAME_INFO_BYTES)
}

/// 分配 2^order 个连续物理页
pub fn phys_alloc(order: u8, owner: ModuleId) -> Result<OwnedFrames, MmError> {
    let _g = pmm();
    phys_alloc_locked(order, owner)
}

/// FrameInfo 是否已接管（引导完成后 frame_info 非 0）。P1b：接管后分配/释放走 refcnt，
/// 位图退化为**仅引导期**的临时分配器（分出元数组那一次）。
fn frame_info_active() -> bool {
    s().frame_info.load(Ordering::Relaxed) != 0
}

/// 读一个帧的 refcnt（FrameInfo 已接管时才有意义）。SAFETY: 调用方持 PMM 锁、f<frame_info_frames。
fn fi_refcnt(f: u64) -> u32 {
    let st = s();
    let arr = st.frame_info.load(Ordering::Relaxed) as *const FrameInfo;
    // SAFETY: arr 覆盖 frame_info_frames 个条目，f 在界内（调用方保证）；只读原子量。
    unsafe { (*arr.add(f as usize)).refcnt.load(Ordering::Relaxed) }
}

/// 读一个帧的 owner（台账归账用）。SAFETY: 调用方持 PMM 锁、f<frame_info_frames。
fn fi_owner(f: u64) -> ModuleId {
    let st = s();
    let arr = st.frame_info.load(Ordering::Relaxed) as *const FrameInfo;
    // SAFETY: arr 覆盖 frame_info_frames 个条目，f 在界内；只读 owner（PMM 锁下不变）。
    unsafe { (*arr.add(f as usize)).owner }
}

/// 把一个帧标为已用/自由（独占：refcnt 1/0）。SAFETY: 调用方持 PMM 锁、f<frame_info_frames。
fn fi_set_used(f: u64, used: bool, owner: ModuleId) {
    let st = s();
    let arr = st.frame_info.load(Ordering::Relaxed) as *mut FrameInfo;
    // SAFETY: arr 覆盖 frame_info_frames 个条目，f 在界内；PMM 锁保证互斥；元数组帧永不归还。
    unsafe {
        let e = &mut *arr.add(f as usize);
        e.refcnt.store(if used { 1 } else { 0 }, Ordering::Relaxed);
        e.flags = if used { FI_USED } else { FI_FREE };
        e.owner = if used { owner } else { ModuleId(0) };
    }
}

/// refcnt 加一（共享）。SAFETY: 调用方持 PMM 锁、f<frame_info_frames、该帧活着（调用方已持参考）。
fn fi_inc_refcnt(f: u64) {
    let st = s();
    let arr = st.frame_info.load(Ordering::Relaxed) as *mut FrameInfo;
    // SAFETY: 同上；PMM 锁互斥，fetch_add 原子。
    unsafe { (*arr.add(f as usize)).refcnt.fetch_add(1, Ordering::Relaxed); }
}

/// refcnt 减一（不归还）。SAFETY: 调用方持 PMM 锁、f<frame_info_frames、refcnt>=1。
fn fi_dec_refcnt(f: u64) {
    let st = s();
    let arr = st.frame_info.load(Ordering::Relaxed) as *mut FrameInfo;
    // SAFETY: 同上；PMM 锁互斥，fetch_sub 原子。
    unsafe { (*arr.add(f as usize)).refcnt.fetch_sub(1, Ordering::Relaxed); }
}

/// 共享一个已持有的帧（ADR-063 决策 3，P1c）：refcnt++，返回共享凭证。
/// **前置**：调用方必须已持有一个参考（OwnedFrames 或 SharedFrame）——这保证 get 不会与
/// "1→0 归还"竞争（只要还有人能 get，refcnt 就不会到 0）。弱引用 get（不持参考按帧号查表）
/// 本帖不提供，留到页缓存真有查表调用者那天另起草。frame 是帧号（phys_alloc 的 base/PAGE）。
pub fn frame_get(frame: u64) -> SharedFrame {
    let _g = pmm();
    fi_inc_refcnt(frame);
    SharedFrame { frame }
}

/// 归还一个参考（ADR-063 决策 3，P1c）：refcnt--，**减到 0 才归还**（毒化 + 台账 + free_frames）。
/// refcnt 已 0 再 put ⇒ DoubleFree（沿用 free_violation 升 L4 的语义，这里返回 Err 由调用方处置）。
pub fn frame_put(frame: u64) -> Result<(), MmError> {
    let _g = pmm();
    let rc = fi_refcnt(frame);
    if rc == 0 {
        return Err(MmError::DoubleFree);
    }
    let owner = fi_owner(frame);
    if rc == 1 {
        fi_set_used(frame, false, ModuleId(0));
        fi_final_free(frame, owner)?;
    } else {
        fi_dec_refcnt(frame);
    }
    Ok(())
}

/// 共享帧的 RAII 凭证（P1c）：丢弃即 frame_put。与 OwnedFrames 的区别——OwnedFrames 是
/// 分配器交出的**独占**主人（一段连续帧），SharedFrame 是 frame_get 出来的**共享**参考（单帧）。
pub struct SharedFrame {
    frame: u64,
}

impl SharedFrame {
    pub fn frame(&self) -> u64 {
        self.frame
    }
}

impl Drop for SharedFrame {
    fn drop(&mut self) {
        if let Err(e) = frame_put(self.frame) {
            free_violation(e, PhysAddr(self.frame * PAGE as u64), ModuleId(0));
        }
    }
}

/// 内核大块缓冲（ADR-064，W2 P2）：一段连续物理帧经 **HHDM 直接寻址**交出，不占 VA 保留表、
/// 不建页表映射（HHDM 已映射全部 max_phys）。填 ADR-018 留的大缓冲口子——**不经 GlobalAlloc**，
/// 所有权就在自己的 `OwnedFrames` 字段里，失败返回 Result 可传播（不是堆那条 L4 停机路径）。
/// 分配即清零（eager zero）：自由帧上次释放被毒化成 0xA5，不清零会泄漏陈旧物理内存。
/// RAII：无自定义 Drop，`frames` 字段析构自动走 phys_free → refcnt 到 0 归还（ADR-063）。
pub struct KBuf {
    frames: OwnedFrames,
    ptr: *mut u8,
    len: usize,
}

impl KBuf {
    /// 分配至少 `bytes` 字节的连续缓冲（向上取整到 2^order 帧），清零后交出。owner 记台账。
    /// `bytes==0` 拒绝；分不出连续帧返回 OutOfMemory（可传播）。中断上下文禁用（取 PMM 锁、可能 OOM）。
    pub fn new(bytes: usize, owner: ModuleId) -> Result<KBuf, MmError> {
        if bytes == 0 {
            return Err(MmError::InvalidAddress);
        }
        let pages = bytes.div_ceil(PAGE);
        let order = pages.next_power_of_two().trailing_zeros() as u8;
        let frames = phys_alloc(order, owner)?;
        let ptr = frames.base().via_hhdm().0 as *mut u8;
        let cap = frames.count() * PAGE;
        // SAFETY: ptr = HHDM + phys_alloc 分出的连续帧基址，cap 字节都在 max_phys 内（HHDM 覆盖）；
        // 帧归 KBuf 独占，此刻无并发访问；write_bytes 按 u8 对齐（任意对齐合法）。
        unsafe { core::ptr::write_bytes(ptr, 0, cap) };
        Ok(KBuf { frames, ptr, len: bytes })
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }
    /// 请求的字节数（<= 实际容量 frames.count()*PAGE）。
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr 指向 KBuf 独占的连续帧，len<=cap 在界内；&self 期间帧不被归还（Drop 才归还）；
        // u8 对齐任意合法；调用方不得跨 KBuf 析构持有该切片（生命周期绑定 &self）。
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: 同 as_slice；&mut self 保证独占访问，无别名。
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

/// `phys_alloc` 的持锁内核：调用方**必须已持 PMM 锁**。init_allocator 的两阶段引导在
/// 自己那把 pmm() 里分出 FrameInfo 元数组，不能再取一次 PMM（重入会升 L4），故拆出此函数。
/// 引导期（frame_info 未就绪）走位图；接管后走 FrameInfo 的 refcnt（P1b）。
fn phys_alloc_locked(order: u8, owner: ModuleId) -> Result<OwnedFrames, MmError> {
    let st = s();
    if !st.ready.load(Ordering::Relaxed) {
        return Err(MmError::NotInit);
    }
    let n = 1usize << order;
    let limit = st.max_phys / PAGE as u64;
    let active = frame_info_active();
    let mut f = 1u64 << order;
    while f + n as u64 <= limit {
        let mut ok = true;
        for k in 0..n as u64 {
            let used = if active { fi_refcnt(f + k) >= 1 } else { bit_get(f + k) };
            if used {
                ok = false;
                break;
            }
        }
        if ok {
            for k in 0..n as u64 {
                if active {
                    fi_set_used(f + k, true, owner);
                } else {
                    bit_set(f + k, true);
                }
            }
            let st = s();
            st.free_frames.fetch_sub(n, Ordering::Relaxed);
            // 台账按模块聚合"活着多少"。页表页（owner=MOD_BOOT）永不归还，账上一直挂着——对，不是泄漏。
            // 早期池不记（来自 .bss，没经过分配器）。P1c：记账改**逐帧**，因为共享帧按单帧归还
            // （frame_put 到 0 才记 free），段级记账会在部分归还时把账写坏。Σlive==Σalloc−Σfree 不变；
            // call counts 随帧数变（修订 P1b 的"按段保 call counts"）。记账集中在 ledger_* 两个助手，
            // 全模块对 resource 的引用只此两处（环内 memory->resource 棘轮，ADR-044）。
            ledger_alloc(owner, n);
            return Ok(OwnedFrames { base: PhysAddr(f * PAGE as u64), order, owner });
        }
        f += n as u64;
    }
    Err(MmError::OutOfMemory)
}

/// 台账分配记账（逐帧）。全模块对 resource::account_alloc 的引用**只此一处**（memory->resource 棘轮）。
fn ledger_alloc(owner: ModuleId, n: usize) {
    for _ in 0..n {
        crate::resource::account_alloc(owner, 1);
    }
}

/// 台账归还记账（逐帧）。全模块对 resource::account_free 的引用**只此一处**（memory->resource 棘轮）。
fn ledger_free(owner: ModuleId, n: usize) -> bool {
    for _ in 0..n {
        if !crate::resource::account_free(owner, 1) {
            return false;
        }
    }
    true
}

/// 一个帧最终归还（refcnt 已到 0）：毒化 + 台账单帧归还 + free_frames++。
/// 调用方已持 PMM 锁、已把该帧标自由。phys_free 与 frame_put 共用，保证毒化/记账口径一致。
fn fi_final_free(frame: u64, owner: ModuleId) -> Result<(), MmError> {
    let st = s();
    let base = frame * PAGE as u64;
    // 释放后毒化，让 use-after-free 变成可观察的错误值（§6.7）
    for b in 0..PAGE as u64 {
        // SAFETY: base+off 在 max_phys 内，HHDM 覆盖全部物理内存
        unsafe { core::ptr::write_volatile((st.hhdm + base + b) as *mut u8, 0xa5) };
    }
    if !ledger_free(owner, 1) {
        return Err(MmError::UnbalancedFree);
    }
    s().free_frames.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// 释放：FrameInfo 接管后逐帧减 refcnt，**减到 0 才归还**（共享帧需要，P1c）；位图期整段释放。
/// `owner` 只用于台账——所有权判定靠 refcnt/位图，不靠调用方自报。
fn phys_free(base: PhysAddr, order: u8, owner: ModuleId) -> Result<(), MmError> {
    let _g = pmm();
    let st = s();
    if !st.ready.load(Ordering::Relaxed) {
        return Err(MmError::NotInit);
    }
    let n = 1usize << order;
    if base.0 % (PAGE * n) as u64 != 0 {
        return Err(MmError::Misaligned);
    }
    let first = base.0 / PAGE as u64;
    let active = frame_info_active();
    for k in 0..n as u64 {
        let used = if active { fi_refcnt(first + k) >= 1 } else { bit_get(first + k) };
        if !used {
            return Err(MmError::DoubleFree);
        }
    }
    if active {
        // 逐帧减 refcnt：独占帧 1→0 当场归还；被 frame_get 共享过的帧 >1，只减不归还，
        // 留给最后一个 frame_put 收。这样丢弃 OwnedFrames 不会把别人还持有的共享帧毒化掉。
        for k in 0..n as u64 {
            let f = first + k;
            let rc = fi_refcnt(f);
            if rc == 1 {
                fi_set_used(f, false, ModuleId(0));
                fi_final_free(f, owner)?;
            } else {
                fi_dec_refcnt(f);
            }
        }
    } else {
        for k in 0..n as u64 {
            bit_set(first + k, false);
        }
        for b in 0..(n * PAGE) as u64 {
            // SAFETY: base+off 在 max_phys 内，HHDM 覆盖全部物理内存
            unsafe { core::ptr::write_volatile((st.hhdm + base.0 + b) as *mut u8, 0xa5) };
        }
        if !ledger_free(owner, n) {
            return Err(MmError::UnbalancedFree);
        }
        s().free_frames.fetch_add(n, Ordering::Relaxed);
    }
    Ok(())
}

/// 故障注入：真的做两次释放，用来验证 §9.2 的 L4 升级不是纸面规则。
/// 只在 `fault-double-free` 构建里被调用。
#[cfg(feature = "fault-double-free")]
pub fn force_double_free_for_test() -> bool {
    let f = match phys_alloc(0, MOD_TEST) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let base = f.base();
    // 第一次正常释放；再构造一个同址的 OwnedFrames 并丢弃，让它走 Drop ->
    // phys_free 返回 Err(DoubleFree) -> free_violation -> L4 停机。
    // 直接调两次 phys_free 是测不到这条链的（那样只会拿到一个 Err 被忽略）。
    core::mem::forget(f);
    let _ = phys_free(base, 0, MOD_TEST);
    let again = OwnedFrames { base, order: 0, owner: MOD_TEST };
    drop(again);
    // 走到这里说明 L4 升级没生效
    false
}

/// 故障注入（P1c / ADR-063）：共享帧归还到 0 之后**再 put 一次**，必须升 L4。
/// 只在 `fault-put-double-free` 构建里被调用。走 frame_put → Err(DoubleFree) → free_violation → L4。
#[cfg(feature = "fault-put-double-free")]
pub fn force_put_double_free_for_test() -> bool {
    let f = match phys_alloc(0, MOD_TEST) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let frame = f.base().0 / PAGE as u64;
    core::mem::forget(f); // 独占主人不自动 drop，手动 put 到 0
    let _ = frame_put(frame); // refcnt 1 -> 0，归还
    let again = SharedFrame { frame }; // 再构造一个凭证并丢弃 -> frame_put -> DoubleFree -> L4
    drop(again);
    false // 走到这里说明 L4 升级没生效
}

pub(crate) fn free_violation(e: MmError, base: PhysAddr, owner: ModuleId) -> ! {
    crate::log_fatal!("L4 integrity: {:?} base={:#x} owner={}", e, base.0, owner.0);
    crate::exit::finish(crate::exit::Code::ExceptionFatal)
}
