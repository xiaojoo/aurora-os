//! 释放二级处理器并把它变成**证据来源**（M3b-1）。
//!
//! 这一段的目标不是"多核能用"，而是把 M3a/M3b 之间那几句口头结论变成读数：
//!
//! 1. 「AP 由 Limine 直接带起」——协议只说了"请求存在 ⇒ bootloader 会 bootstrap 二级处理器"
//!    和"释放 = 一次 release 语义的原子写 `goto_address`"。本文件照这两句写，不做任何
//!    "通常内核都是这么启动 AP"的补充。
//! 2. AP 进来时用的是 **bootloader 的页表**（协议：CPU 状态与 BSP 交接时相同）。
//!    所以入口例程必须自己 `mov cr3`，而那一刻它能读的只有内核镜像与 HHDM。
//! 3. 「部分核起不来算不算过」由 **ADR-022** 定：起不来就降级继续跑，但降级必须可观察
//!    （`released` / `ready` / `timer_failed` / `ack_timeouts` 四个数字全都进日志）。
//!
//! 今天还没有做的（写清楚，不留到"看起来已经做了"）：
//! * AP **不跑调度器**：它的定时器走 `trap::isr_stub_cpu_timer` 独立快路径，不建异常帧、
//!   不到抢占点。`cpu::runs_sched` 只有 BSP 为真，`preempt_point` 第一句就按它闸住。
//!   连带欠着一条：AP 打开 IF 时**没有**写进 `apic::CPU_IF` 那张表（那张表是给调度器
//!   改写异常帧用的）。已记 BACKLOG，AP 接入调度器时必须同时接上。
//! * 没有 TLB shootdown（§6.6）：`Mapping::drop` 的阻塞语义仍然只有单核依据。
//! * bootloader 可回收区还没回收（ADR-019）：AP 已经换到我们自己的带 guard 栈上跑，
//!   但它最初是被 bootloader 的停车代码唤醒的，回收要等确认那些代码不再被执行。

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::{clock, limine, mm, sync, tsc};
use crate::arch::x86_64::{apic, cpu, trap};

/// AP 的入口栈：4 页 + 1 页 guard（与任务栈同一条 §6.4 规则）
const AP_STACK_PAGES: usize = 4;
const AP_STACK_VA_PAGES: usize = AP_STACK_PAGES + 1;
pub const MOD_STACK_AP: mm::ModuleId = mm::ModuleId(14);

/// 释放一个 AP 之前必须写好的三个值。asm 侧按下标读：0=栈顶、1=槽位、2=期望的 LAPIC id。
/// 布局由 `ap_entry` 里的偏移决定，所以这里必须是 `#[repr(C)]` 的三个 u64；
/// `t_ap_boot_abi` 用 `size_of`/`offset_of` 的等式把这条钉住，改字段顺序会当场红。
#[repr(C)]
pub struct ApBoot {
    pub stack_top: u64,
    pub slot: u64,
    pub expect_lapic: u64,
}

#[repr(C, align(64))]
struct ApBootCell(UnsafeCell<ApBoot>);
// SAFETY: 每个槽位只由 BSP 在**释放该 CPU 之前**写一次，之后本 CPU 只读。
// 释放动作本身是协议要求的 release 语义原子写，所以 AP 读到的必然是完整的三份。
unsafe impl Sync for ApBootCell {}
static AP_ARGS: [ApBootCell; cpu::MAX_CPUS] =
    [const { ApBootCell(UnsafeCell::new(ApBoot { stack_top: 0, slot: 0, expect_lapic: 0 })) }; cpu::MAX_CPUS];

pub fn ap_boot_layout(slot: usize) -> (u64, u64, u64) {
    // SAFETY: 只读自己的槽位；本函数在释放之后调用也安全（值不再变）
    let a = unsafe { &*AP_ARGS[slot].0.get() };
    (a.stack_top, a.slot, a.expect_lapic)
}

// ------------------------------------------------------------ AP 的相位与握手

pub const PHASE_OFF: usize = 0;
pub const PHASE_RACE_UNLOCKED: usize = 1;
pub const PHASE_RACE_LOCKED: usize = 2;
pub const PHASE_STOP: usize = 3;
/// L3-A：整行原子性的并发相位。每个在线 CPU 打 `PRINT_LINES` 行，
/// 行的 tag 是本 CPU 独有的字母——被插进一半的行会当场现形（一行里出现两个字母）。
pub const PHASE_PRINT_LINES: usize = 4;
/// P4c-2：跨核阻塞/唤醒压力相位。BSP 当**生产者兼观察者**（永不阻塞，所以丢唤醒时
/// 它能报红而不是整机静默），各 AP 当消费者，在 `sync::WaitQueue` 上真的阻塞。
pub const PHASE_WAIT_WAKE: usize = 5;

/// 当前相位。BSP 写、所有 CPU 读。
static PHASE: AtomicUsize = AtomicUsize::new(PHASE_OFF);
/// 每个 CPU「已进入本相位」与「已干完本相位」的回执，值就是相位号。
static ENTERED: [AtomicUsize; cpu::MAX_CPUS] = [const { AtomicUsize::new(0) }; cpu::MAX_CPUS];
static DONE: [AtomicUsize; cpu::MAX_CPUS] = [const { AtomicUsize::new(0) }; cpu::MAX_CPUS];
/// AP 的自检阶段：0=还没起来，1=本地定时器没走通，2=已进入等待，3=已停机。
static AP_STAGE: [AtomicUsize; cpu::MAX_CPUS] = [const { AtomicUsize::new(0) }; cpu::MAX_CPUS];
/// AP 本地定时器的标定初值（把"周期是估出来的"这件事留个读数）。
static AP_TIMER_INIT: [AtomicUsize; cpu::MAX_CPUS] = [const { AtomicUsize::new(0) }; cpu::MAX_CPUS];
static AP_TIMER_FAILED: AtomicUsize = AtomicUsize::new(0);
/// 标定失败的**种类**（最后一个失败的 AP 写的）：1=没映射 2=没基准 3=计数器没动
/// 4=窗口太短 5=初值出量程。编号与 `timer_err_kind` 一一对应，日志里直接打数字。
static AP_TIMER_ERR: AtomicUsize = AtomicUsize::new(0);

fn timer_err_kind(e: apic::TimerError) -> usize {
    match e {
        apic::TimerError::NoLapic => 1,
        apic::TimerError::NoCalibration => 2,
        apic::TimerError::CounterFrozen { .. } => 3,
        apic::TimerError::WindowTooShort { .. } => 4,
        apic::TimerError::RateOutOfRange { .. } => 5,
    }
}

pub fn ap_timer_err_kind() -> usize {
    AP_TIMER_ERR.load(Ordering::Acquire)
}
static AP_EXSTACK_FAILED: AtomicUsize = AtomicUsize::new(0);
static AP_LAPIC_FAILED: AtomicUsize = AtomicUsize::new(0);
/// 期望的 LAPIC id 与硬件读回值不一致的次数（槽位分配之后由 AP 自己核对）
static AP_ID_MISMATCH: AtomicUsize = AtomicUsize::new(0);
static RELEASED: AtomicUsize = AtomicUsize::new(0);
/// 因为"没有槽位 / 栈分配失败"而没有释放的 CPU 数（ADR-022 要求它可观察）
static REFUSED: AtomicUsize = AtomicUsize::new(0);
static READY_TIMEOUT: AtomicUsize = AtomicUsize::new(0);
static ACK_TIMEOUTS: AtomicUsize = AtomicUsize::new(0);
static BRINGUP_DONE: AtomicBool = AtomicBool::new(false);

/// 释放一个 AP 之后等它自报到家的上限（周期）。本机 tsc≈3.33 GHz 时约 60 ms，
/// 而 AP 从 `goto_address` 到 `mark_ready` 之间只有建表 + 一次 2 ms 的标定窗。
/// 超时只计数、不死等：等待方必须能区分"还没到"和"永远不到"。
const AP_DEADLINE_CYCLES: u64 = 200_000_000;

pub fn released_count() -> usize {
    RELEASED.load(Ordering::Relaxed)
}
pub fn refused_count() -> usize {
    REFUSED.load(Ordering::Relaxed)
}
pub fn ready_timeouts() -> usize {
    READY_TIMEOUT.load(Ordering::Relaxed)
}
pub fn ap_stage(slot: usize) -> usize {
    if slot >= cpu::MAX_CPUS {
        return 0;
    }
    AP_STAGE[slot].load(Ordering::Relaxed)
}
pub fn ap_timer_init(slot: usize) -> usize {
    if slot >= cpu::MAX_CPUS {
        return 0;
    }
    AP_TIMER_INIT[slot].load(Ordering::Relaxed)
}
pub fn ap_timer_failures() -> usize {
    AP_TIMER_FAILED.load(Ordering::Relaxed)
}
pub fn ap_id_mismatches() -> usize {
    AP_ID_MISMATCH.load(Ordering::Relaxed)
}
/// AP 在进门那两步上的失败次数：(#DF 栈没换上, 本地 APIC 使能失败)。
/// 两个都是"AP 起来了但没完全起来"的现场，必须能被 BSP 侧的用例读到。
pub fn ap_failures() -> (usize, usize) {
    (AP_EXSTACK_FAILED.load(Ordering::Relaxed), AP_LAPIC_FAILED.load(Ordering::Relaxed))
}

// ------------------------------------------------------------------- 入口 asm

core::arch::global_asm!(
    r#"
    .text
    .code64
    // AP 的入口。协议交给我们的东西只有这些：
    //   RDI = *limine_mp_info（processor_id@0 / lapic_id@4 / reserved@8 /
    //                          goto_address@16 / extra_argument@24）
    //   rsp = bootloader 提供的栈（大小按 Stack Size 特性；指针记在 reserved 里）
    //   其余与 BSP 交接时相同 —— 关键是**页表还是 bootloader 的那一份**。
    //
    // 所以顺序必须是：
    //   1) 在旧表下读 mp_info.extra_argument（它住在可回收内存，HHDM 在两张表里都有）
    //   2) 读栈顶、内核 PML4（内核镜像两张表都映射，同一份物理）
    //   3) 换 rsp —— 放在换表之前是安全的：中间没有任何碰栈的指令
    //   4) 换 cr3
    //   5) call（此时压栈用的是我们自己的栈）
    // 反过来（先 cr3 后换栈）会让 `call` 把返回地址压进一张旧表才认得的栈，
    // 而那一帧随时可能被我们当成普通物理帧分配给别人 —— 那是最难查的一种坏法。
    .global ap_entry
ap_entry:
    mov r11, [rdi + 24]              // extra_argument = &ApBoot
    mov rax, [r11]                   // stack_top
    mov rdx, [r11 + 8]               // slot
    mov rcx, [r11 + 16]              // expect_lapic（AP 自己读寄存器核对）
    mov rsp, rax
    mov rax, [rip + AURORA_KERNEL_CR3]
    mov cr3, rax
    mov rdi, rdx
    mov rsi, rcx
    call aurora_ap_main
    // aurora_ap_main 声明为 -> !。真回到这里就是上面某一步算错了：
    // 停在 hlt 循环里比乱跳更容易归因，BSP 侧的超时读数会把这件事报出来。
1:  hlt
    jmp 1b

    .section .rodata
    .align 8
    // Rust 侧要拿这个地址去做那次 release 发布。走与 trap.rs 的 isr_table 同一条通道：
    // 不用 `ap_entry as u64` 那种依赖 fn 指针表示的写法。
    .global ap_entry_gate
ap_entry_gate:
    .quad ap_entry
"#
);

extern "C" {
    static ap_entry_gate: [u64; 1];
}

pub fn ap_entry_addr() -> u64 {
    unsafe { ap_entry_gate[0] }
}

// ------------------------------------------------------------------ BSP 侧动作

/// 给即将释放的 AP 建一条带 guard page 的内核栈。由 BSP 做：
/// 此刻分配器仍然只有单线程访问，而 AP 一进门就要用这条栈，不能让它自己现alloc。
fn alloc_ap_stack(slot: usize) -> Result<u64, mm::MmError> {
    let win = mm::alloc_va_range(AP_STACK_VA_PAGES).ok_or(mm::MmError::OutOfMemory)?;
    let map_lo = win.0 + mm::PAGE as u64;
    let frames = mm::phys_alloc(AP_STACK_PAGES.trailing_zeros() as u8, MOD_STACK_AP)?;
    let m = mm::map(mm::VirtAddr(map_lo), frames, mm::PageFlags::RW)?;
    core::mem::forget(m); // 与内核同寿命：没有"忘记解映射"这条路
    // 记下**映射起点**：guard 页在它下面，而"栈顶所在页下面那一页"仍然是这条栈的一部分。
    // 少记这一个数，`t_ap_boot_abi` 就会把"映射着的第 3 页"当成 guard 未映射不成立来报。
    AP_STACK_LO[slot].store(map_lo, Ordering::Release);
    Ok((win.0 + (AP_STACK_VA_PAGES as u64) * mm::PAGE as u64 - 16) & !0xf)
}

static AP_STACK_LO: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];

/// AP 内核栈的映射起点（0 = 没建过）。guard 页 = 它减去一页。
pub fn ap_stack_lo(slot: usize) -> u64 {
    if slot >= cpu::MAX_CPUS {
        return 0;
    }
    AP_STACK_LO[slot].load(Ordering::Acquire)
}

/// 释放所有已登记的 AP，并等它们各自把本地定时器跑起来。
/// 幂等：用例之间不能假设谁先跑（`.ktests` 的枚举顺序由链接顺序决定）。
pub fn bringup() -> Result<(), BringupError> {
    if BRINGUP_DONE.load(Ordering::Acquire) {
        return Ok(());
    }
    let Some(mp) = crate::mp_snapshot() else {
        return Err(BringupError::NoMpResponse);
    };
    if mm::our_cr3() == 0 {
        return Err(BringupError::Cr3NotPublished);
    }
    // LAPIC 设备页必须先映射好，AP 进门才能写自己的 SVR/LVT。
    // 这件事在 bringup 里补，而不是假设"某个用例已经跑过 apic::init"：
    // `.ktests` 的枚举顺序由链接顺序决定，把顺序当前提会得到一条偶发红的用例。
    if apic::state().is_none() {
        let m = crate::acpi::summary().and_then(|s| s.madt).ok_or(BringupError::LapicNotReady)?;
        apic::get_or_init(&m).map_err(|_| BringupError::LapicNotReady)?;
    }
    let Some(bst) = apic::state() else {
        return Err(BringupError::LapicNotReady);
    };
    // AP 的定时器初值要用 tsc_hz 反推。标定这件事不做成"用例之间的隐含顺序"，
    // 而是当场补一次（`crate::calibrate_clock_once` 自己幂等）。
    if clock::current().is_none() {
        crate::calibrate_clock_once();
    }
    let Some(hz) = clock::hz() else {
        return Err(BringupError::ClockNotCalibrated);
    };
    if mp.ptr_count == 0 {
        return Err(BringupError::NoMpResponse);
    }

    let mut released = 0usize;
    for i in 0..mp.n {
        let lapic_id = mp.lapic_ids[i];
        if lapic_id == bst.id {
            continue; // BSP 自己：它的 goto_address 按协议根本不参与（"unused for the BSP"）
        }
        let Some(slot) = cpu::reserve_ap_slot(lapic_id) else {
            // 槽位不够或 id 重复。跳过并把次数报出去——ADR-022 要求降级可观察
            REFUSED.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let Ok(top) = alloc_ap_stack(slot) else {
            REFUSED.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        // 1) 先初始化 AP 要观察的数据（协议原文的顺序要求：extra_argument 必须在发布入口之前写好）
        // SAFETY: 本槽位此刻只有 BSP 在写，目标 CPU 还没被释放
        unsafe {
            *AP_ARGS[slot].0.get() = ApBoot { stack_top: top, slot: slot as u64, expect_lapic: lapic_id as u64 };
        }
        // 2) 写进协议结构并**用 release 语义发布入口**
        // SAFETY: cpu_ptrs[i] 由 bootloader 填充并指向 mp_info；该结构住在可回收内存，
        // 而 ADR-019 规定此刻**不回收**，所以这块内存的主人还是 bootloader 给我们的那份。
        unsafe {
            limine::release_mp_cpu(mp.cpu_ptrs[i] as *mut limine::MpInfo, AP_ARGS[slot].0.get() as u64, ap_entry_addr());
        }
        released += 1;
    }
    RELEASED.store(released, Ordering::Release);

    // 3) 逐个等到自报到家。超时只计数，不无限自旋，也不因为超时就不敢继续跑别的用例。
    for slot in 1..cpu::MAX_CPUS {
        if !cpu::is_registered(slot) {
            continue;
        }
        if !wait_until(|| cpu::is_ready(slot), AP_DEADLINE_CYCLES) {
            READY_TIMEOUT.fetch_add(1, Ordering::Relaxed);
        }
    }
    let _ = hz;
    BRINGUP_DONE.store(true, Ordering::Release);
    Ok(())
}

/// `bringup` 失败的去向：一律**降级继续跑**，但原因进日志、数字进用例。
/// 依据 ADR-022：内核不能因为"少一个核"拒绝启动，也不能因为"少一个核"假装多核验证过了。
#[derive(Debug)]
pub enum BringupError {
    /// bootloader 没给 MP 响应，或响应里的 cpu_ptrs 没能拷出来
    NoMpResponse,
    /// 还没切到自己的页表：此刻释放出去的 AP 会带着 bootloader 的表跑进我们的代码
    Cr3NotPublished,
    /// LAPIC 还没映射，AP 无从初始化自己的中断
    LapicNotReady,
    /// 没有 TSC 频率标定，AP 的定时器初值只能是猜的
    ClockNotCalibrated,
}

/// 有界等待：只自旋，不 hlt（等待方随时可能被别人的进展叫醒，但不能靠中断）。
fn wait_until(f: impl Fn() -> bool, deadline_cycles: u64) -> bool {
    let t0 = tsc::now();
    while !f() {
        core::hint::spin_loop();
        if tsc::now().wrapping_sub(t0) > deadline_cycles {
            return false;
        }
    }
    true
}

/// 让所有 AP 停机：关掉它们的本地定时器与 IF，之后不再碰任何共享状态。
///
/// **必须逐个摘下线**（`cpu::mark_offline`）：AP 停机是 `cli` + `hlt`，IF=0 之后
/// 那条 shootdown 的 IPI 永远取不走；只要它还算在线，之后任何一次解映射都会
/// 等到看门狗到期并把正常构建判成 L4（依据见 `cpu::mark_offline` 的注释）。
pub fn stop_aps() {
    PHASE.store(PHASE_STOP, Ordering::Release);
    for s in 1..cpu::MAX_CPUS {
        if !cpu::is_registered(s) {
            continue;
        }
        // 等这个 CPU 报告"我已经把定时器关掉、IF 关掉"，然后立刻把它移出在线名单
        let ok = wait_until(|| AP_STAGE[s].load(Ordering::Acquire) >= 3, AP_DEADLINE_CYCLES);
        if !ok {
            STUCK_ONLINE.fetch_add(1, Ordering::Relaxed);
        }
        cpu::mark_offline(s);
    }
}

static STUCK_ONLINE: AtomicUsize = AtomicUsize::new(0);

/// 停机阶段没能按时交回"已停机"信号的 CPU 数。非 0 意味着有一个 CPU 还卡在
/// 在线名单里被摘掉——那之后的解映射不会再等它的回执，这件事必须能被看见。
pub fn stuck_online_count() -> usize {
    STUCK_ONLINE.load(Ordering::Relaxed)
}

// ------------------------------------------------------------------- AP 侧动作

/// `ap_entry` 跳进来的 Rust 侧入口。
///
/// # Safety 契约（由 asm 保证）
/// 此刻本 CPU 已经用上我们自己的页表，`rsp` 指向 `alloc_ap_stack` 建的那条带 guard 的栈，
/// `slot` 是 BSP 事先分配好的槽位号，`expect_lapic` 是 MP/MADT 给的 id，本 CPU IF=0。
#[no_mangle]
pub extern "C" fn aurora_ap_main(slot: u64, expect_lapic: u64) -> ! {
    let slot = slot as usize;
    // 1) 本 CPU 的描述符表。IF 还是 0（交接状态），所以建表期间不会有中断看到半初始化状态。
    trap::init_cpu_tables(slot);
    // 2) 本 CPU 的 #DF 栈换成带 guard page 的那一页（§6.4）。
    // 这一步会走 VMM(20)/PMM(30) 锁，而 BSP 此刻也在动页表——正是 BACKLOG 要的
    // "跨核真实竞争"样本之一。失败不打印（BSP 可能正在输出），只记次数。
    if trap::install_exception_stack(slot).is_err() {
        AP_EXSTACK_FAILED.fetch_add(1, Ordering::Relaxed);
    }
    // 3) 本 CPU 的本地 APIC：软件使能 + 读回 id 核对
    let id = match apic::ap_enable_lapic() {
        Ok(v) => v,
        Err(_) => {
            AP_LAPIC_FAILED.fetch_add(1, Ordering::Relaxed);
            cpu::mark_ready(slot); // 报到，但阶段停在 0：BSP 的用例会把"有槽位没 tick"读成失败
            halt_forever()
        }
    };
    cpu::note_hw_id(slot, id);
    if id as u64 != expect_lapic {
        AP_ID_MISMATCH.fetch_add(1, Ordering::Relaxed);
    }
    // CR4 是每 CPU 的寄存器：BSP 开了 SMEP/SMAP 不等于这条核也开了。
    // 不设的后果不是立刻出错，而是"ring3 跑到这条核上时内核页可执行"——只在调度
    // 把它分过去的那天出问题，所以必须在进门第一步就设并核对。
    cpu::enable_user_protections();
    cpu::mark_online(slot);
    // 4) 本地定时器：先按 TSC 标定计数率，再按周期模式装载
    let hz = match clock::hz() {
        Some(v) => v,
        None => {
            AP_TIMER_FAILED.fetch_add(1, Ordering::Relaxed);
            cpu::mark_ready(slot);
            halt_forever();
        }
    };
    match apic::ap_timer_start(AP_TIMER_PERIOD_US, hz) {
        Ok(init) => AP_TIMER_INIT[slot].store(init as usize, Ordering::Relaxed),
        Err(e) => {
            // AP 侧不许打印（串口会互相插字，而且这里可能正卡在 BSP 的测量窗口里）。
            // 所以把"哪一种失败"编成数字交给 BSP 打印，现场读数在 `apic::cal_dbg()`。
            AP_TIMER_ERR.store(timer_err_kind(e), Ordering::Release);
            AP_TIMER_FAILED.fetch_add(1, Ordering::Relaxed);
            cpu::mark_ready(slot);
            halt_forever();
        }
    }
    // 5) 登记本 CPU 的空闲上下文。栈边界用的是 `alloc_ap_stack` 那条栈自己的区间——
    // 不能沿用 BSP 的 `init_boot_task`：它读的是 BSP 的 `.bss` 启动栈，
    // 边界错了的后果不是崩溃，而是"帧不在这条栈上"永远判否、这条 CPU 再也不换人。
    let stack_lo = ap_stack_lo(slot);
    if stack_lo == 0 {
        cpu::mark_ready(slot);
        halt_forever(); // 没建过栈就不要开调度：队列的边界校验会一直失败，那是更难的现场
    }
    (crate::hooks::sched().init_idle_task)(stack_lo, stack_lo + (AP_STACK_PAGES as u64) * mm::PAGE as u64, true);
    // 6) 在这条 CPU 自己的队列里放一个工人。它和上面的空闲上下文轮流跑，
    //    这就是"AP 在跑调度器"的唯一可数证据（BSP 那边读 `stats_of(ap).0`）。
    match (crate::hooks::sched().spawn)(ap_worker) {
        Ok(t) => AP_TASK[slot].store(t + 1, Ordering::Release), // +1：0 留给"没建成"
        Err(e) => {
            AP_SPAWN_FAILED.fetch_add(1, Ordering::Relaxed);
            let _ = e;
        }
    }
    // 7) 开闸 + 开本 CPU 的窗口。**这两步必须成对**，理由写在 `apic::open_cpu_window` 上：
    // 只开闸不立牌的话，第一次换入会被按"窗口关着"改写 IF，那条 CPU 从此收不到 tick。
    cpu::mark_sched(slot);
    apic::open_cpu_window(slot);
    // 8) 确认自己的定时器真的在走。**有界**，且这一段绝不能 hlt：
    // hlt 之后叫得醒它的正是还没确认能用的那个定时器。
    let t0 = tsc::now();
    while apic::cpu_ticks(slot) == 0 && tsc::now().wrapping_sub(t0) < AP_DEADLINE_CYCLES {
        core::hint::spin_loop();
    }
    if apic::cpu_ticks(slot) == 0 {
        AP_TIMER_FAILED.fetch_add(1, Ordering::Relaxed);
        cpu::mark_ready(slot);
        halt_forever();
    }
    AP_STAGE[slot].store(2, Ordering::Release);
    cpu::mark_ready(slot);

    // 9) 这就是本 CPU 空闲上下文的主体：等 BSP 派活。这里可以 hlt——
    //    本地 tick 每 ~10 ms 叫一次，而 BSP 那边的等待同样有界，不会两个都在等就挂死。
    //    现在这段是**可以被抢占的**（它跑在自己的队列上），所以下面 break 之前
    //    看到的一切状态都可能是"换回来之后"的读数，不能假设中间没人动过。
    loop {
        let p = PHASE.load(Ordering::Acquire);
        if p == PHASE_STOP {
            break;
        }
        if p != PHASE_OFF && DONE[slot].load(Ordering::Acquire) != p {
            ENTERED[slot].store(p, Ordering::Release);
            run_race_round();
            DONE[slot].store(p, Ordering::Release);
        }
        // SAFETY: hlt 等到下一个中断（本 CPU 的 tick）为止
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
    // 10) 停机：先关窗口（立牌 + `cli`）再关定时器，之后不再碰任何共享状态。
    // 顺序是"关牌在前"：换人时读的是牌，牌还写着开而 IF 已经关了，就会出现
    // "帧里 IF=1 而 CPU 收不到中断"的自相矛盾状态（虽然此刻已经没有别的任务可换了）。
    apic::close_cpu_window(slot);
    apic::ap_timer_stop();
    // SAFETY: cli 只清 EFLAGS.IF
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
    AP_STAGE[slot].store(3, Ordering::Release);
    halt_forever()
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: cli+hlt 是停机惯用法；asm! 没有输出，LLVM 不会把它当纯表达式删掉
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

// --------------------------------------------------------- AP 自己的运行队列

/// AP 在自己队列里建的那个工人任务的全局下标 + 1（0 = 没建成）。
static AP_TASK: [AtomicUsize; cpu::MAX_CPUS] = [const { AtomicUsize::new(0) }; cpu::MAX_CPUS];
static AP_SPAWN_FAILED: AtomicUsize = AtomicUsize::new(0);

pub fn ap_task_of(slot: usize) -> Option<usize> {
    if slot >= cpu::MAX_CPUS {
        return None;
    }
    match AP_TASK[slot].load(Ordering::Acquire) {
        0 => None,
        v => Some(v - 1),
    }
}

pub fn ap_spawn_failures() -> usize {
    AP_SPAWN_FAILED.load(Ordering::Relaxed)
}

/// AP 队列里的工人：只往自己的格子里加计数。
///
/// 它**不看** `sched::should_run()`：那条全局收工标志是 BSP 那批用例在用，
/// 让 AP 的工人被它关掉，就会出现"BSP 跑过一条用例之后 AP 再也无事可做"，
/// 而那条用例的判据根本没打算管 AP。不收工也没关系：
/// `stop_aps()` 会让空闲上下文跳出主循环，这条 CPU 之后不再取任务。
fn ap_worker() -> ! {
    let slot = cpu::self_slot();
    // P5：从"常驻自旋"改成 hlt 等中断。自己开窗口、永不关（本任务不退出），
    // 与 AP 空闲上下文同一形状；不用 `with_interrupts`，理由见 sched::idle_entry。
    // **没有退掉这个任务**：它的 WORK 计数仍是 t_percpu_queues 的 `worked_aps` 证人，
    // 退掉它就得先换证人（ADR-047/§113a）。改成 hlt 既不再烧 CPU，又保住证人。
    apic::open_cpu_window(slot);
    loop {
        (crate::hooks::sched().bump_current_work)();
        if slot < cpu::MAX_CPUS {
            AP_WORKER_HLT[slot].fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: hlt 停到下一个中断；窗口已开，本地 tick（~10ms）与 resched IPI 都能叫醒。
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
}

/// 每个 AP 的工人进入 hlt 的次数（P5 的见证读数，内核自报）。
static AP_WORKER_HLT: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];

/// AP 工人的 hlt 次数。与 `idle_hlt_count` 一样是自报数，不是独立见证。
pub fn ap_worker_hlt(cpu: usize) -> u64 {
    if cpu >= cpu::MAX_CPUS { return 0; }
    AP_WORKER_HLT[cpu].load(Ordering::Relaxed)
}

// ------------------------------------------------------ 跨核竞争：一把锁两个人抢

/// AP 本地定时器的目标周期（微秒）。与 BSP 的 PIT 100 Hz 对齐，是为了让
/// "两个 CPU 的 tick 数应当接近"这件事可以当判据用；不严格相等，用例只按 ±50% 收。
pub const AP_TIMER_PERIOD_US: u64 = 10_000;

/// 竞争用例的共享数据。**故意用非原子的读改写**：
/// 无锁那一轮要量的正是"丢了几个增量"。换成原子量就丢不了，那把尺子当场失效。
#[repr(C, align(64))]
struct RaceCell(UnsafeCell<u64>);
// SAFETY: 互斥由被测的那把锁提供。无锁那一轮是**故意制造的**数据竞争，
// 它只存在于用例的临界区、只在 PHASE_RACE_* 期间被访问，用途是证明那把锁确实在挡东西。
// 这不是产品路径，别把它当成"这里可以没有锁"的依据。
unsafe impl Sync for RaceCell {}
static RACE: RaceCell = RaceCell(UnsafeCell::new(0));

/// 被测的锁。等级用最内层的 `RANK_TEST`：临界区里只有一次读改写和一段自旋，
/// 不调分配器、不碰页表、不打日志，所以它不可能嵌套任何别的锁。
pub static CONTENTION_LOCK: sync::IrqSpinLock<()> = sync::IrqSpinLock::new(sync::RANK_TEST, ());

/// 每一轮的自增次数，与临界区里"占着锁磨一下"的自旋长度。
/// 这两个旋钮决定竞争到底会不会发生：太小则两个 CPU 几乎撞不上
/// （`wait_events` 会是 0，"锁挡住了竞争"这句话就没有证据），太大则整个用例要跑好几秒。
const RACE_ROUNDS: u64 = 4_000;
const RACE_GAP: usize = 200;

/// L3-A 的并发打印：每个在线 CPU 各打 `PRINT_LINES` 行，tag 是本 CPU 独有的字母。
/// 判据分两台仪器：内核数自己的账（每 CPU 行数 + 行锁四本账的增量），宿主机数行的形状
/// （`tools/aurora.py:check_line_atomicity`——序号列全局严格递增、tag 单一、行数齐）。
/// 常态构建里这条通道没人调用，相位机与锁本身是产品代码。
#[cfg(feature = "serial-atomic-probe")]
const PRINT_LINES: u64 = 24;
#[cfg(feature = "serial-atomic-probe")]
const TAGS: [&str; cpu::MAX_CPUS] = [
    "aaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccc",
    "dddddddddddddddddddddddd", "eeeeeeeeeeeeeeeeeeeeeeee", "ffffffffffffffffffffffff",
    "gggggggggggggggggggggggg", "hhhhhhhhhhhhhhhhhhhhhhhh",
];
/// 每个 CPU 在本相位里实际打完的行数——自己数自己，别人替它数不作数。
#[cfg(feature = "serial-atomic-probe")]
static PRINTED: [AtomicUsize; cpu::MAX_CPUS] = [const { AtomicUsize::new(0) }; cpu::MAX_CPUS];
/// "一起开始"的牌。没有它，AP 会在自己的 tick 里打完才轮到 BSP 开口——
/// 那时 `contended` 只有一两次，"竞争下仍然整行"这句话就只剩空话（实测 96 行里竞争 1 次）。
#[cfg(feature = "serial-atomic-probe")]
static PRINT_GO: AtomicUsize = AtomicUsize::new(0);
/// 等 GO 的有界自旋：到期也照样打。宁可窗口歪一点，也不要为了漂亮数字挂死机器。
#[cfg(feature = "serial-atomic-probe")]
const PRINT_GO_MAX: u64 = 20_000_000;

/// 一个 CPU 在本相位里该做的事：`RACE_ROUNDS` 次"读—磨—写"。
/// 锁只在 `PHASE_RACE_LOCKED` 时拿；无锁那一轮是对照组。
fn run_race_round() {
    let phase = PHASE.load(Ordering::Acquire);
    if phase == PHASE_WAIT_WAKE {
        run_ap_role_body();
        return;
    }
    #[cfg(feature = "serial-atomic-probe")]
    if phase == PHASE_PRINT_LINES {
        let slot = crate::arch::x86_64::cpu::self_slot();
        // 等 BSP 的那块牌，四个 CPU 才真的同时在开口
        let mut spins = 0u64;
        while PRINT_GO.load(Ordering::Acquire) != phase && spins < PRINT_GO_MAX {
            core::hint::spin_loop();
            spins += 1;
        }
        for i in 0..PRINT_LINES {
            crate::log_info!("atomic: cpu={} n={} tag={}", slot, i, TAGS[slot]);
        }
        PRINTED[slot].store(PRINT_LINES as usize, Ordering::Release);
        return;
    }
    let locked = phase == PHASE_RACE_LOCKED;
    let mut n = 0u64;
    while n < RACE_ROUNDS {
        if locked {
            let _g = CONTENTION_LOCK.lock();
            bump();
        } else {
            bump();
        }
        n += 1;
    }
}

#[inline(never)]
fn bump() {
    // SAFETY: 见 RaceCell。本函数的全部意义就是"读和写之间可能被别人插一脚"，
    // 所以必须 volatile：优化器把 read/write 折成一次 add 就没有丢数可数了。
    unsafe {
        let p = RACE.0.get();
        let v = core::ptr::read_volatile(p);
        // 持有时间撑到别人一定会等：tsc::spin 是 #[inline(never)] 的实函数，不会被删。
        tsc::spin(RACE_GAP);
        core::ptr::write_volatile(p, v + 1);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RaceOutcome {
    /// 无锁那一轮丢掉的增量数。期望 **> 0**：它证明这把尺子能分辨"有没有锁"
    pub unlocked_lost: u64,
    /// 有锁那一轮丢掉的增量数。期望 **== 0**
    pub locked_lost: u64,
    /// 有锁那一轮里"真的为别人等过一次"的取锁次数。期望 **> 0**：
    /// 没有它，"加锁那一轮没丢数"可能只是因为两个 CPU 根本没撞上
    pub wait_events: usize,
    /// 最长一次等待的周期数（看门狗余量的证据）
    pub wait_max_cycles: u64,
    /// 参与竞争的 CPU 数（含 BSP）
    pub participants: usize,
    /// 每一侧应有的自增总数，用来把"丢了多少"换算成百分比
    pub rounds_per_cpu: u64,
    /// 等回执超时的次数（非 0 就是这一轮没测成，返回值里没有它就无法解释丢数）
    pub ack_timeouts: usize,
}

#[derive(Debug)]
pub enum RaceError {
    NoApOnline,
    /// 某个 CPU 没在期限内进入或完成相位：竞争没测成，必须报出来而不是给一个"丢数 0"
    AckTimeout,
    Bringup(BringupError),
}

/// 一个 AP 是否算"活着且能干活"：登记过、在线、报过到、并且自己的本地定时器确实在走。
/// 四个条件缺一个都不能进参与者名单——否则它不会来抢锁，却占了名额。
pub fn participant_slots() -> (usize, [usize; cpu::MAX_CPUS]) {
    let mut list = [0usize; cpu::MAX_CPUS];
    let mut n = 0usize;
    for s in 1..cpu::MAX_CPUS {
        if cpu::is_registered(s) && cpu::is_online(s) && cpu::is_ready(s) && apic::cpu_ticks(s) > 0 {
            list[n] = s;
            n += 1;
        }
    }
    (n, list)
}

/// 跨核锁竞争的完整一轮（对照组 + 实验组）。由 BSP 调用。
///
/// 顺序是"先让所有 AP 进入本相位，BSP 再跑自己那份"：反过来（BSP 先跑完再叫 AP）
/// 两个 CPU 的工作不重叠，`wait_events` 会是 0，那"锁挡住了竞争"就只剩空话。
pub fn contention_round() -> Result<RaceOutcome, RaceError> {
    bringup().map_err(RaceError::Bringup)?;
    let (n, aps) = participant_slots();
    if n == 0 {
        return Err(RaceError::NoApOnline);
    }
    for &s in &aps[..n] {
        ENTERED[s].store(0, Ordering::Relaxed);
        DONE[s].store(0, Ordering::Relaxed);
    }

    // ---- 对照组：无锁
    let unlocked_lost = run_phase(PHASE_RACE_UNLOCKED, &aps[..n])?;
    // ---- 实验组：加锁。等待次数只统计这一段，所以先取基线
    let wait0 = sync::stats().wait_events;
    let locked_lost = run_phase(PHASE_RACE_LOCKED, &aps[..n])?;
    let st = sync::stats();
    Ok(RaceOutcome {
        unlocked_lost,
        locked_lost,
        wait_events: st.wait_events.saturating_sub(wait0),
        wait_max_cycles: st.wait_max_cycles,
        participants: n + 1,
        rounds_per_cpu: RACE_ROUNDS,
        ack_timeouts: ACK_TIMEOUTS.load(Ordering::Relaxed),
    })
}

// ---- P4c-2：把 AP 编组进一个相位去跑**调用方给的角色**（ADR-056）----
//
// 为什么只给原语、不把压力逻辑写在这里：压力逻辑要引用 `sync::WaitQueue` 与 `clock`，
// 写在 arch 层会让环内边 `arch->sync`、`arch->time` 变胖，ADR-044 的棘轮当场红。
// 而它本来就是**测试**逻辑，放 ktests 里既合层次又不计产品依赖边（ADR-043）。
// arch 只负责它真正知道的事：哪些 AP 活着、怎么编组、怎么收回执。

/// 角色函数表：调用方在启动相位前装一次，相位期间只读。
struct RoleCell(core::cell::UnsafeCell<Option<fn()>>);
// SAFETY: 由 BSP 在发布相位**之前**写入，AP 只在相位期间读；相位收齐回执后 BSP 才可能再写。
// 与 `hooks::HooksCell`/`sync::OpsCell` 同一论证形状（单点写、发布后只读）。
unsafe impl Sync for RoleCell {}
static AP_ROLE: RoleCell = RoleCell(core::cell::UnsafeCell::new(None));

/// 让所有在线 AP 各跑一遍 `role`，BSP **不跑**（BSP 通常是生产者/观察者）。
/// 返回本相位新增的 ack 超时数；AP 起不来/取不到名单/回执超期都回 Err，不静默。
pub fn run_ap_role(role: fn(), bsp_role: fn()) -> Result<u64, RaceError> {
    bringup().map_err(RaceError::Bringup)?;
    let (n, aps) = participant_slots();
    if n == 0 {
        return Err(RaceError::NoApOnline);
    }
    // SAFETY: 见 RoleCell；此刻还没有发布相位，没有 AP 在读它。
    unsafe { *AP_ROLE.0.get() = Some(role) };
    for &s in &aps[..n] {
        ENTERED[s].store(0, Ordering::Relaxed);
        DONE[s].store(0, Ordering::Relaxed);
    }
    let ack0 = ACK_TIMEOUTS.load(Ordering::Relaxed);
    PHASE.store(PHASE_WAIT_WAKE, Ordering::Release);
    for &s in &aps[..n] {
        if !wait_until(|| ENTERED[s].load(Ordering::Acquire) == PHASE_WAIT_WAKE, AP_DEADLINE_CYCLES) {
            return Err(ack_fail(PHASE_WAIT_WAKE, RaceError::AckTimeout));
        }
    }
    // BSP 跑自己那一份（通常是生产者/观察者），与 AP 重叠——与 run_phase 同一形状
    bsp_role();
    let mut ack_ok = true;
    for &s in &aps[..n] {
        if !wait_until(|| DONE[s].load(Ordering::Acquire) == PHASE_WAIT_WAKE, AP_DEADLINE_CYCLES) {
            ack_ok = false;
        }
    }
    PHASE.store(PHASE_OFF, Ordering::Release);
    // SAFETY: 相位已收回 OFF 且回执收齐（或超时），此刻没有 AP 再读它。
    unsafe { *AP_ROLE.0.get() = None };
    if !ack_ok {
        return Err(ack_fail(PHASE_WAIT_WAKE, RaceError::AckTimeout));
    }
    Ok((ACK_TIMEOUTS.load(Ordering::Relaxed) - ack0) as u64)
}

/// AP 侧在相位里要跑的角色（由 `run_ap_role` 的调用方提供）。
fn run_ap_role_body() {
    // SAFETY: 见 RoleCell；相位期间只读，且调用方保证已装入 Some。
    let role = unsafe { *AP_ROLE.0.get() };
    if let Some(f) = role {
        f();
    }
}

/// L3-A：并发打印一轮的读数。行数字段是"每个 CPU 自己数的"，锁那几本是差值——
/// 差值而不是绝对值，因为启动过程本身要打几千行。
#[cfg(feature = "serial-atomic-probe")]
#[derive(Clone, Copy, Debug)]
pub struct PrintOutcome {
    pub participants: usize,
    pub lines_per_cpu: usize,
    pub ap_total: usize,
    pub bsp_total: usize,
    pub holds: usize,
    pub contended: usize,
    pub nested: usize,
    pub timeouts: usize,
    pub owner_after: usize,
    pub halting: bool,
    pub ack_timeouts: usize,
}

/// 让每个在线 CPU 同时打一批行，收齐回执后交账。由 BSP 调用。
///
/// 顺序与 `contention_round` 同一形状：先等 AP 声称进入，BSP 再打自己那份——
/// 反过来（BSP 先打完再叫 AP）两边的输出窗口不重叠，`contended` 就是 0，
/// "整行原子性是在竞争下成立的"这句话只剩空话。
#[cfg(feature = "serial-atomic-probe")]
pub fn print_round() -> Result<PrintOutcome, RaceError> {
    bringup().map_err(RaceError::Bringup)?;
    let (n, aps) = participant_slots();
    if n == 0 {
        return Err(RaceError::NoApOnline);
    }
    for s in aps[..n].iter().chain([cpu::BSP_SLOT].iter()) {
        PRINTED[*s].store(0, Ordering::Relaxed);
    }
    for &s in &aps[..n] {
        ENTERED[s].store(0, Ordering::Relaxed);
        DONE[s].store(0, Ordering::Relaxed);
    }
    PRINT_GO.store(0, Ordering::Relaxed);
    let base = crate::serial::line_stats();
    PHASE.store(PHASE_PRINT_LINES, Ordering::Release);
    for &s in &aps[..n] {
        if !wait_until(|| ENTERED[s].load(Ordering::Acquire) == PHASE_PRINT_LINES, AP_DEADLINE_CYCLES) {
            return Err(ack_fail(PHASE_PRINT_LINES, RaceError::AckTimeout));
        }
    }
    // 牌举起来，四个 CPU 同时开口；BSP 自己也在这批里
    PRINT_GO.store(PHASE_PRINT_LINES, Ordering::Release);
    run_race_round();
    for &s in &aps[..n] {
        if !wait_until(|| DONE[s].load(Ordering::Acquire) == PHASE_PRINT_LINES, AP_DEADLINE_CYCLES) {
            return Err(ack_fail(PHASE_PRINT_LINES, RaceError::AckTimeout));
        }
    }
    PHASE.store(PHASE_OFF, Ordering::Release);
    let st = crate::serial::line_stats();
    Ok(PrintOutcome {
        participants: n + 1,
        lines_per_cpu: PRINT_LINES as usize,
        ap_total: aps[..n].iter().map(|s| PRINTED[*s].load(Ordering::Relaxed)).sum(),
        bsp_total: PRINTED[cpu::BSP_SLOT].load(Ordering::Relaxed),
        holds: st.holds - base.holds,
        contended: st.contended - base.contended,
        nested: st.nested - base.nested,
        timeouts: st.timeouts - base.timeouts,
        owner_after: st.owner,
        halting: st.halting,
        ack_timeouts: ACK_TIMEOUTS.load(Ordering::Relaxed),
    })
}

/// 推进一个相位并收回结果，返回"丢掉的增量数"。
fn run_phase(phase: usize, aps: &[usize]) -> Result<u64, RaceError> {
    // SAFETY: 见 RaceCell——相位边界处由 BSP 单点清零，此刻没有任何 CPU 在临界区里
    // （上一相位已经收齐回执，下一相位还没发布）。
    unsafe { core::ptr::write_volatile(RACE.0.get(), 0) };
    PHASE.store(phase, Ordering::Release);
    // 1) 等所有 AP 声称"已进入本相位"（它们会立刻开始跑，与 BSP 重叠）
    for &s in aps {
        if !wait_until(|| ENTERED[s].load(Ordering::Acquire) == phase, AP_DEADLINE_CYCLES) {
            return Err(ack_fail(phase, RaceError::AckTimeout));
        }
    }
    // 2) BSP 跑自己那一份
    run_race_round();
    // 3) 等所有 AP 干完——此刻才读数，否则读到的是一半
    for &s in aps {
        if !wait_until(|| DONE[s].load(Ordering::Acquire) == phase, AP_DEADLINE_CYCLES) {
            return Err(ack_fail(phase, RaceError::AckTimeout));
        }
    }
    PHASE.store(PHASE_OFF, Ordering::Release);
    // SAFETY: 所有参与者都已交回回执，本 CPU 现在是唯一的写者
    let observed = unsafe { core::ptr::read_volatile(RACE.0.get()) };
    let expected = (aps.len() as u64 + 1) * RACE_ROUNDS;
    // 少的那一部分就是被并发覆盖掉的更新
    Ok(expected.saturating_sub(observed))
}

/// 相位失败时必须把 PHASE 收回 OFF：否则那个没交回执的 AP 会一直卡在同一个相位里，
/// 下一次运行时它数到的"丢数"就是上一轮的残渣。
fn ack_fail(phase: usize, e: RaceError) -> RaceError {
    ACK_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
    let _ = phase;
    PHASE.store(PHASE_OFF, Ordering::Release);
    e
}

/// 编译期就钉住 asm 依赖的偏移：`ApBoot` 必须正好是三个 u64（`ap_entry` 按 +0/+8/+16 读它），
/// `limine_mp_info` 的 `extra_argument` 必须在 +24（`ap_entry` 也按这个偏移读它）。
const _: () = assert!(core::mem::size_of::<ApBoot>() == 24);
const _: () = assert!(core::mem::size_of::<limine::MpInfo>() == 32);
