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
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

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
/// VA 保留登记表容量。**按能数清楚的用量算，不按"当时跑起来够用"拍**：
/// 每个任务栈一条（最坏 `MAX_CPUS * MAX_TASKS` = 48 条）+ 固定用途 16 条
/// （内核堆窗口、每个 CPU 的 #DF 栈、AP 栈、LAPIC/串口设备窗口、M4 的用户三页）。
/// 24 那个数是 M2 时代拍的，M4 一开用户态就撞上：现场是
/// `L4: VA 保留登记表已满` 而不是任何页表错误，所以容量也得跟着里程碑复算。
/// 登记不下时**明确失败**而不是发一条没登记的 VA（见 alloc_va_range 的注释）。
const MAX_VA_RESERVATIONS: usize = crate::arch::x86_64::cpu::MAX_CPUS * crate::sched::MAX_TASKS + 16;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModuleId(pub u16);

pub const MOD_BOOT: ModuleId = ModuleId(1);
pub const MOD_STACK: ModuleId = ModuleId(2);
pub const MOD_TEST: ModuleId = ModuleId(3);

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
    used: bool,
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
    hhdm: u64,
    max_phys: u64,
    bitmap: [AtomicU64; BITMAP_WORDS],
    free_frames: AtomicUsize,
    total_frames: AtomicUsize,
    ready: AtomicBool,
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
    va_res: [VaReservation { base: 0, len: 0, used: false }; MAX_VA_RESERVATIONS],
    hhdm: 0,
    max_phys: 0,
    bitmap: [const { AtomicU64::new(0) }; BITMAP_WORDS],
    free_frames: AtomicUsize::new(0),
    total_frames: AtomicUsize::new(0),
    ready: AtomicBool::new(false),
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
    for r in &st.va_res {
        if r.used && va >= r.base && va < r.base + r.len {
            return r.base + r.len;
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
    for (i, r) in st.va_res.iter().enumerate() {
        if r.used && base >= r.base && base < r.base + r.len {
            idx = i;
            len = r.len;
            break;
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
    st.va_res[idx].used = false;
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
    s().va_res.iter().any(|r| r.used && r.base == base)
}

pub fn reservation_count() -> usize {
    let _g = vmm();
    s().va_res.iter().filter(|r| r.used).count()
}

fn register_va(base: u64, len: u64) -> bool {
    let st = s();
    for r in &mut st.va_res {
        if !r.used {
            *r = VaReservation { base, len, used: true };
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
"#
);

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

/// 取一个清零的页表页
fn new_table_frame() -> Option<u64> {
    let phys = if is_ready() {
        let f = phys_alloc(0, MOD_BOOT).ok()?;
        let p = f.base().0;
        core::mem::forget(f); // 页表生命周期 = 内核生命周期，不归还
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
    let hhdm = s().hhdm;
    let mut table = (s().pml4_phys + hhdm) as *mut Page;
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
            unsafe { *entry = new_table_frame()? | P_PRESENT | P_WRITE | share };
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
    // SAFETY: va 由调用方保证规范，表已初始化
    let e = unsafe { walk_leaf(va, true, huge, user).ok_or(MmError::OutOfMemory)? };
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

pub struct MmCounters {
    pub map_calls: usize,
    pub mapped_pages: usize,
    pub unmapped_pages: usize,
    /// 为建表取用的页表页数（含接管期从早期池取的）
    pub page_table_pages: usize,
    /// 早期池占用，用于判断 `EARLY_POOL_PAGES` 的余量是不是真余量
    pub early_pool_used: usize,
}

pub fn counters() -> MmCounters {
    MmCounters {
        map_calls: MAP_CALLS.load(Ordering::Relaxed),
        mapped_pages: MAPPED_PAGES.load(Ordering::Relaxed),
        unmapped_pages: UNMAPPED_PAGES.load(Ordering::Relaxed),
        page_table_pages: PT_PAGES.load(Ordering::Relaxed),
        early_pool_used: s().early_used,
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
    let me = crate::arch::x86_64::cpu::self_slot();
    let mut want = 0usize;
    let mut base = [0usize; crate::arch::x86_64::cpu::MAX_CPUS];
    for s2 in 0..crate::arch::x86_64::cpu::MAX_CPUS {
        if s2 != me && crate::arch::x86_64::cpu::is_online(s2) {
            base[s2] = SD_ACKS[s2].load(Ordering::Acquire);
            want += 1;
        }
    }
    SD_REQUESTS.fetch_add(1, Ordering::Relaxed);
    if want == 0 {
        return; // 单核：本 CPU 的条目已经在 clear_leaf 里清掉了
    }
    SD_VA.store(va, Ordering::Release);
    // 逐点名（不用"除本 CPU 外全体"的缩写：本机实测收不到，理由写在 apic::send_ipi_to 上）。
    // 顺序是"先发布 VA，再发 IPI"：处理方读的就是 SD_VA，反过来它可能读到上一条请求的 VA。
    for s2 in 0..crate::arch::x86_64::cpu::MAX_CPUS {
        if s2 == me || !crate::arch::x86_64::cpu::is_online(s2) {
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
            s2 != me && crate::arch::x86_64::cpu::is_online(s2) && SD_ACKS[s2].load(Ordering::Acquire) == base[s2]
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
    if !is_ready() || VirtAddr::new(va).is_none() {
        return None;
    }
    let hhdm = s().hhdm;
    // SAFETY: 只读遍历自建表，前提与 `is_mapped` 相同（所有写者都在 VMM(20) 锁里）
    unsafe {
        let mut table = (s().pml4_phys + hhdm) as *const Page;
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
pub fn init_allocator() {
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
}

/// 分配 2^order 个连续物理页
pub fn phys_alloc(order: u8, owner: ModuleId) -> Result<OwnedFrames, MmError> {
    let _g = pmm();
    let st = s();
    if !st.ready.load(Ordering::Relaxed) {
        return Err(MmError::NotInit);
    }
    let n = 1usize << order;
    let limit = st.max_phys / PAGE as u64;
    let mut f = 1u64 << order;
    while f + n as u64 <= limit {
        let mut ok = true;
        for k in 0..n as u64 {
            if bit_get(f + k) {
                ok = false;
                break;
            }
        }
        if ok {
            for k in 0..n as u64 {
                bit_set(f + k, true);
            }
            let st = s();
            st.free_frames.fetch_sub(n, Ordering::Relaxed);
            // 台账按模块聚合"活着多少"。页表页也是从这里取的（owner=MOD_BOOT）且
            // 永不归还，所以它们在账上一直挂着——这是对的，不是泄漏。
            // 早期池不记：那部分来自 .bss，没经过分配器。
            crate::resource::account_alloc(owner, n);
            return Ok(OwnedFrames { base: PhysAddr(f * PAGE as u64), order, owner });
        }
        f += n as u64;
    }
    Err(MmError::OutOfMemory)
}

/// 释放：位图已是“已用”以外的状态即为重复释放。
/// `owner` 只用于台账——所有权判定靠位图，不靠调用方自报。
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
    for k in 0..n as u64 {
        if !bit_get(first + k) {
            return Err(MmError::DoubleFree);
        }
    }
    for k in 0..n as u64 {
        bit_set(first + k, false);
    }
    // 释放后毒化，让 use-after-free 变成可观察的错误值（§6.7）
    for b in 0..(n * PAGE) as u64 {
        // SAFETY: base+off 在 max_phys 内，HHDM 覆盖全部物理内存
        unsafe { core::ptr::write_volatile((st.hhdm + base.0 + b) as *mut u8, 0xa5) };
    }
    if !crate::resource::account_free(owner, n) {
        return Err(MmError::UnbalancedFree);
    }
    s().free_frames.fetch_add(n, Ordering::Relaxed);
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

fn free_violation(e: MmError, base: PhysAddr, owner: ModuleId) -> ! {
    crate::log_fatal!("L4 integrity: {:?} base={:#x} owner={}", e, base.0, owner.0);
    crate::exit::finish(crate::exit::Code::ExceptionFatal)
}
