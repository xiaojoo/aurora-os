//! per-CPU 身份与槽位（M3b）。
//!
//! 为什么需要"槽位"这层间接：LAPIC id 不保证密集、不保证从 0 开始（x2APIC 能跳到很大），
//! 而所有 per-CPU 数组都要一个 `0..MAX_CPUS` 的下标 ⇒ 必须有一张 id→槽位的表。
//!
//! 三条决定本文件形状的规则：
//! 1. **槽位只由 BSP 分配**，AP 拿 `extra_argument` 里预写的槽位、再用自己的 LAPIC 寄存器**验证**
//!    （`t_cpu_ids_agree`）。验证比"自登记 + 一把登记表锁"便宜且没有竞争。
//! 2. **`self_slot()` 走 MMIO**，与 `sync::cpu_token` 同一个来源（`apic::self_id`）：
//!    缓存值与实际不符就会漏判重入（同一把尺子量自己）。代价是一次 UC- 读 ≈600 周期（ADR-024）。
//! 3. **LAPIC 未映射时退到 0**：早期只有 BSP 在跑，返回 0 号槽是对的。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// per-CPU 数组的容量。**多于这个数的核不释放**，由 `smp::bringup` 明确报出来，
/// 不做"静默忽略多余核"那件事（§9.2：说不清的状态必须变成可观察的数字）。
pub const MAX_CPUS: usize = 8;
/// BSP 固定占 0 号槽：`apic::self_id()` 在 LAPIC 映射之前返回 0，两者必须对得上。
pub const BSP_SLOT: usize = 0;

/// 空槽的哨兵。LAPIC id 是 8 位（x2APIC 下 32 位），u32::MAX 不可能是真实 id。
const NO_ID: u32 = u32::MAX;

static LAPIC_ID: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(NO_ID) }; MAX_CPUS];
static ONLINE: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];
/// 哪些 CPU 跑调度器。**M3b-2b 起四个 CPU 都跑**：AP 的本地定时器已经改走
/// 建帧路径（`trap::isr_stub_241` → `isr_common` → 抢占点），不建帧就不可能换人。
/// 这条开关仍然是"哪个 CPU 可以被人换下"的唯一事实来源：`preempt_point` 第一句就读它，
/// 没登记的 CPU 只会把重调度标志倒掉，不会去动别人的队列。
static RUNS_SCHED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];
/// 每个槽位观察到的硬件 LAPIC id（AP 自己读寄存器写进来，供交叉验证）。
static HW_ID_SEEN: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(NO_ID) }; MAX_CPUS];
static READY_SLOTS: AtomicU64 = AtomicU64::new(0);

/// CR4 的 SMEP/SMAP 位。写成模块级常量而不是函数里的：`enable_user_protections`
/// （写）与 `user_protections_active`（读回核对）必须用同一个数，抄两遍就会有一天不一致。
pub const CR4_SMEP: u64 = 1 << 20;
pub const CR4_SMAP: u64 = 1 << 21;

/// 打开 `CR4.SMEP`(bit20) 与 `CR4.SMAP`(bit21)，把**读回的 CR4** 交回去。
/// 放在 cpu.rs 而不是 mm.rs：这两位管的是"按 CPL 区分取指与访存"，与页表位是两套机制；
/// §5.1（R17）把两者列成 M4 必需项 ⇒ 必须有"没开成功怎么办"的判断，依据是 CPUID 不是页表。
/// **每台 CPU 都要设一次**：CR4 是每 CPU 的寄存器，只在 BSP 上调一次的话，
/// ring3 跑到 AP 上那两位就是 0，"内核不许执行用户页"只在一条核上成立。
pub fn enable_user_protections() -> (bool, bool, u64) {
    let f = crate::arch::x86_64::cpuid::detect();
    let want = CR4_SMEP | CR4_SMAP;
    let mut cr4: u64;
    // SAFETY: 只读写 CR4，不碰内存；`ldmxcsr` 一类不涉及。cr4 的读写对是特权指令，
    // 本函数只在 ring0 调用（启动期与 AP 进门第一步）。
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, preserves_flags));
        // 只加要加的位，绝不整份覆盖：bootloader/QEMU 可能已经放了别的位（PAE 之类）
        let _ = (f.smep, f.smap);
        let next = cr4 | want;
        core::arch::asm!("mov cr4, {}", in(reg) next, options(nomem, preserves_flags));
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, preserves_flags));
    }
    (cr4 & CR4_SMEP != 0, cr4 & CR4_SMAP != 0, cr4)
}

/// 本 CPU 的 CR4 读回值（用例核对用）。
pub fn cr4() -> u64 {
    let v: u64;
    // SAFETY: 只读 CR4
    unsafe { core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, preserves_flags)) };
    v
}

/// SMEP/SMAP 此刻在本 CPU 上**是否真的生效**。
/// 只认读回来的 CR4，不认 CPUID、也不认"我写过"：这两位是每 CPU 的，
/// 而且写下去可能被 CPU 忽略，所以判断依据只能是读回值。
pub fn user_protections_active() -> (bool, bool) {
    let v = cr4();
    (v & CR4_SMEP != 0, v & CR4_SMAP != 0)
}

// ------------------------------------------------------------------ MSRs

pub const MSR_STAR: u32 = 0xC000_0081;
pub const MSR_LSTAR: u32 = 0xC000_0082;
pub const MSR_SFMASK: u32 = 0xC000_0084;
pub const MSR_GS_BASE: u32 = 0xC000_0100;
pub const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// 读一个 64 位 MSR。只在 ring0、装机阶段用（`rdmsr` 是特权指令）。
/// SAFETY: `msr` 必须是已知存在的编号；不存在的编号就是 #GP。
pub fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, lateout("eax") lo, lateout("edx") hi,
                         options(nomem, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

/// 写一个 64 位 MSR。**写完读回来**：`wrmsr` 可能被 CPU 忽略保留位，
/// 而"装了但没生效"和"没装"在下一条用户指令上才暴露，那时候已经查不到是谁干的。
pub fn wrmsr(msr: u32, v: u64) -> u64 {
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32,
                         options(nomem, preserves_flags));
    }
    rdmsr(msr)
}

/// 故障注入（§12.3 R16）：把 `CR4.SMAP` **清掉**，用来证明 Stage2c 那条
/// "必需项没满足就不启动"的判断真的会动。没有这一行，那条判据在正常机器上永远为真，
/// 也就永远没人知道它是不是装饰——§12.4.1 规则 3（先证明尺子能分辨）在这里的应用。
#[cfg(feature = "fault-no-smap")]
pub fn clear_smap_for_test() {
    // SAFETY: 只清 CR4 的一位，且紧跟一次读回；本函数只在 ring0 启动期调用。
    unsafe {
        let mut v: u64;
        core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, preserves_flags));
        v &= !CR4_SMAP;
        core::arch::asm!("mov cr4, {}", in(reg) v, options(nomem, preserves_flags));
    }
}

/// 登记 BSP（启动早期调用一次，幂等）。返回 0 = BSP 槽位。
pub fn init_bsp(lapic_id: u32) -> usize {
    LAPIC_ID[BSP_SLOT].store(lapic_id, Ordering::Relaxed);
    ONLINE[BSP_SLOT].store(true, Ordering::Relaxed);
    RUNS_SCHED[BSP_SLOT].store(true, Ordering::Relaxed);
    HW_ID_SEEN[BSP_SLOT].store(lapic_id, Ordering::Relaxed);
    BSP_SLOT
}

/// 为一个即将释放的 AP 占一个槽位。BSP 单线程调用，所以不需要锁（规则 1）。
/// 返回 None 表示槽位已满或 id 重复——调用方必须把它变成可观察的失败，不能跳过。
pub fn reserve_ap_slot(lapic_id: u32) -> Option<usize> {
    if (1..MAX_CPUS).any(|i| LAPIC_ID[i].load(Ordering::Relaxed) == lapic_id) {
        return None;
    }
    let slot = (1..MAX_CPUS).find(|&i| LAPIC_ID[i].load(Ordering::Relaxed) == NO_ID)?;
    LAPIC_ID[slot].store(lapic_id, Ordering::Release);
    Some(slot)
}

/// 已登记的槽位总数（含 BSP）。
pub fn registered() -> usize {
    (0..MAX_CPUS).filter(|&i| LAPIC_ID[i].load(Ordering::Relaxed) != NO_ID).count()
}

/// 这个槽位有没有被登记过（与"在线"不同：登记只代表 BSP 给它分了名额）。
pub fn is_registered(slot: usize) -> bool {
    slot < MAX_CPUS && LAPIC_ID[slot].load(Ordering::Acquire) != NO_ID
}

pub fn lapic_id_of(slot: usize) -> Option<u32> {
    if slot >= MAX_CPUS {
        return None;
    }
    let id = LAPIC_ID[slot].load(Ordering::Relaxed);
    if id == NO_ID {
        None
    } else {
        Some(id)
    }
}

/// 本 CPU 观察到的硬件 id（AP 自己写的）。None = 这个 CPU 还没上报过。
pub fn hw_id_seen(slot: usize) -> Option<u32> {
    if slot >= MAX_CPUS {
        return None;
    }
    let id = HW_ID_SEEN[slot].load(Ordering::Relaxed);
    if id == NO_ID {
        None
    } else {
        Some(id)
    }
}

pub fn note_hw_id(slot: usize, id: u32) {
    if slot < MAX_CPUS {
        HW_ID_SEEN[slot].store(id, Ordering::Relaxed);
    }
}

pub fn slot_of_lapic(id: u64) -> Option<usize> {
    let id = id as u32;
    (0..MAX_CPUS).find(|&i| LAPIC_ID[i].load(Ordering::Relaxed) == id)
}

/// 本 CPU 的槽位。
///
/// APIC 还没映射时**直接返回 BSP 槽位且不计数**：那一刻 AP 还停在 bootloader 的停车点上，
/// 系统里确实只有一个运行中的 CPU，返回 0 是构造出来的事实而不是猜测。
/// 反过来，APIC 已就绪却查不到登记，才是要报的异常——那说明有人在没分槽位的情况下跑了别的 id。
pub fn self_slot() -> usize {
    if !crate::arch::x86_64::apic::is_lapic_mapped() {
        return BSP_SLOT;
    }
    let id = crate::arch::x86_64::apic::self_id();
    match slot_of_lapic(id) {
        Some(s) => s,
        None => {
            UNMATCHED_SELF.fetch_add(1, Ordering::Relaxed);
            BSP_SLOT
        }
    }
}

static UNMATCHED_SELF: AtomicU64 = AtomicU64::new(0);

pub fn unmatched_self_lookups() -> u64 {
    UNMATCHED_SELF.load(Ordering::Relaxed)
}

pub fn mark_online(slot: usize) {
    if slot < MAX_CPUS {
        ONLINE[slot].store(true, Ordering::Release);
    }
}

pub fn is_online(slot: usize) -> bool {
    slot < MAX_CPUS && ONLINE[slot].load(Ordering::Acquire)
}

/// 把一个 CPU 移出在线名单。
///
/// 这条不是装饰：`mm::shootdown_others` 按 `is_online` 决定等谁的回执。
/// AP 停机（`cli` + `hlt`）之后 IF=0，那条 IPI 永远不会被取走 —— 如果它还算在线，
/// 之后任何一次解映射都会等到看门狗到期并把正常构建判成 L4。
/// 所以停机流程必须**先摘名再停**。
pub fn mark_offline(slot: usize) {
    if slot < MAX_CPUS {
        ONLINE[slot].store(false, Ordering::Release);
    }
}

/// 在线 CPU 数（BSP 计入）。
pub fn online_count() -> usize {
    (0..MAX_CPUS).filter(|&i| is_online(i)).count()
}

/// 这个 CPU 是否跑调度器（决定 `preempt_point` 要不要动作）。
pub fn runs_sched(slot: usize) -> bool {
    slot < MAX_CPUS && RUNS_SCHED[slot].load(Ordering::Relaxed)
}

/// 让一个 AP 开始跑自己的运行队列。由 **AP 自己**在异常栈与本 CPU 队列都就绪之后调用
/// （`preempt_point` 会读本 CPU 的队列，队列还没建好就开闸是拿未初始化的栈边界做判断）。
///
/// 这一步必须和 `apic::open_cpu_window` 成对：一个 CPU 要能被抢占，
/// 既要有异常帧这条续跑格式，也要真的收得到 tick。
pub fn mark_sched(slot: usize) {
    if slot < MAX_CPUS {
        RUNS_SCHED[slot].store(true, Ordering::Release);
    }
}

/// AP 是否已经进入"自己维护状态"的阶段（ready 位图，供 BSP 等待）。
pub fn mark_ready(slot: usize) {
    if slot < MAX_CPUS {
        READY_SLOTS.fetch_or(1u64 << slot, Ordering::Release);
    }
}

pub fn is_ready(slot: usize) -> bool {
    slot < MAX_CPUS && READY_SLOTS.load(Ordering::Acquire) & (1u64 << slot) != 0
}
