//! Aurora OS 内核 · 第一条垂直切片（手册 §14 的 M1）
//!
//! 链路：Limine 进入 -> 串口自检 -> 校验启动信息 -> 自建 GDT/IDT/TSS ->
//! 受控 #PF 并异常返回 -> 跑 `.ktests` 表 -> 用 isa-debug-exit 的退出码交付判定。
//!
//! 这一条切片同时验掉文档里六个“写了但没测过”的假设：
//! base revision 协商、HHDM 偏移不可硬编码、RSDP 的地址语义（rev4+ 虚拟 / rev3 物理）、
//! 异常栈与 CR2 取值时机、`.ktests` 段注册、以及退出码判定契约本身。

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

#[global_allocator]
static GLOBAL: heap::AuroraGlobal = heap::AuroraGlobal;

mod acpi;
mod arch;
mod ahci;
mod boot_guard;
mod clock;
mod crash;
mod driver;
mod elf;
mod filesystem;
mod heap;
mod hooks;
#[cfg(feature = "handles")]
mod handle;
mod hw;
mod irq;
mod exit;
mod ktest;
mod ktests;

// T0.1：跨文件引用保持 `crate::HELLO_ELF` / `crate::P7_CALLS` / `crate::drain_reap` 可用。
pub(crate) use ktests::common::{HELLO_ELF, P7_CALLS, drain_reap};
#[cfg(feature = "fat32-probe")]
pub(crate) use ktests::fs::{FAT_PORT_A, FAT_PORT_B};
mod limine;
mod mm;
mod sched;
mod serial;
mod sign;
mod sync;
mod resource;
mod user;
mod pci;
mod state_store;
mod watchdog;
mod tsc;
mod virtio;

use crate::arch::x86_64::{apic, cpu, cpuid, smp, trap};
use core::cell::UnsafeCell;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

/// 供 #PF 探针使用的地址，运行期算出来并**验证过确实未映射**
pub(crate) static PROBE_ADDR: AtomicU64 = AtomicU64::new(0);

/// 多处理器响应的快照。换页表之后响应结构就在 bootloader 可回收内存里，
/// 那些帧随时可能被我们自己分配走，所以**必须在切换前拷出来**（与 memmap 同一条理由）。
#[derive(Clone, Copy)]
struct MpSlot(Option<limine::Mp>);
struct MpCell(UnsafeCell<MpSlot>);
// SAFETY: 单核启动阶段写入一次，之后只读（与 mm::State 同一条前提）
unsafe impl Sync for MpCell {}
static MP_SNAP: MpCell = MpCell(UnsafeCell::new(MpSlot(None)));

#[inline]
fn mp_store(m: limine::Mp) {
    // SAFETY: 见 MpCell
    unsafe { (*MP_SNAP.0.get()) = MpSlot(Some(m)) };
}

pub fn mp_snapshot() -> Option<limine::Mp> {
    // SAFETY: 写入发生在 kmain 早期、任何用例之前，此后本文件不再写
    unsafe { (*MP_SNAP.0.get()).0 }
}

/// 切换页表前落下来的 RSDP 虚地址（0 表示 bootloader 没给）。
/// 不能等切换后再读启动信息：它位于可回收内存，帧被分配走之后就是别人的数据。
pub(crate) static RSDP_VA: AtomicU64 = AtomicU64::new(0);

#[panic_handler]
fn on_panic(info: &PanicInfo) -> ! {
    // panic=abort（ADR-005）：这里是终点，不是可恢复错误。
    // 只打印位置：PanicInfo::message() 返回 PanicMessage，在 no_std 下没有可移植的
    // payload 读法，凭空包一层 Display 只会打出骗人的内容。
    let loc = info.location().map_or("<unknown location>", |l| l.file());
    crate::log_fatal!("kernel panic at {}", loc);
    exit::finish(exit::Code::ExceptionFatal)
}

/// 异常里判定为致命的出口：打印现场后给独立退出码（ExceptionFatal=39）。
pub fn exit_fatal_from_exception(frame: &trap::TrapFrame) -> ! {
    // P3 的第二条路径：**在打现场之前**取时间。dump_frame 要吐几百字节，而串口是按字节
    // 忙等的，把它算进"终止路径延迟"就等于让日志长度冒充处置成本。
    // 也就是说这里量的是"判定到可以停机"，崩溃现场打印的成本另有一条字节数可以换算。
    // 槽位在这里读一次是允许的：这条路径马上就要停机，不在任何被测区间之内。
    let cpu = cpu::self_slot();
    let cost = tsc::now().wrapping_sub(trap::entry_tsc_of(cpu));
    trap::p3_record_fatal(cpu, cost);
    trap::dump_frame(frame);
    crash::dump_site(
        crash::Site {
            vector: frame.vector as u32,
            error_code: frame.error_code as u32,
            cr2: frame.cr2,
            rip: frame.rip,
            rsp: frame.rsp,
            rbp: frame.rbp,
        },
        cpu,
    )
    .ok();
    exit::finish(exit::Code::ExceptionFatal)
}

/// 内核入口。Limine 在完成长模式、分页、higher-half 映射后直接跳到这里，
/// 交接状态由协议规定（IF=0、IDT 未定义、FS/GS base=0、栈 ≥64KiB）。
#[no_mangle]
pub extern "C" fn kmain() -> ! {
    // ---- Stage0：串口。先自证能收发，否则后面每条“成功”日志都是假证据
    serial::init();
    if !serial::is_ready() {
        // 这里已经不可能输出原因了，只能靠独立退出码把“串口是哑的”和其它失败分开
        exit::finish(exit::Code::BootInvalid);
    }
    crate::log_info!("boot-ok: aurora stage0 serial up (com1 0x3f8)");
    tsc::stage("serial");

    // ---- Stage1：校验启动信息
    if !limine::BASE_REVISION.is_supported() {
        exit::boot_invalid("bootloader rejected requested base revision 5");
    }
    match limine::BASE_REVISION.negotiated() {
        Some(v) => crate::log_info!("limine: negotiated base revision = {}", v),
        None => crate::log_warn!("limine: base revision tag not rewritten (impl is pre-rev3 behaviour)"),
    }

    let Some(info) = limine::collect() else {
        exit::boot_invalid("missing HHDM or memory map response");
    };
    crate::log_info!("hhdm offset = {:#x}", info.hhdm_offset);
    crate::log_info!("memmap entries = {}", info.mmap_entries.len());
    match info.bootloader_name {
        Some(n) => crate::log_info!("bootloader = {}", n),
        None => crate::log_warn!("bootloader did not provide its name/version"),
    }

    let feats = cpuid::detect();
    if let Some(missing) = feats.missing_required() {
        // 必需项缺失就拒绝启动（§5.1），并给独立退出码，不与“测试失败”混在一起
        crate::log_fatal!("required CPU feature missing: {}", missing);
        exit::finish(exit::Code::BootInvalid);
    }
    crate::log_info!("cpu: nx={} smep={} smap={} pcid={} x2apic={} xsave={} rdrand={} tsc_inv={}", feats.nx, feats.smep, feats.smap, feats.pcid, feats.x2apic, feats.xsave, feats.rdrand, feats.tsc_inv);
    crate::log_info!("tsc: rdtscp_available={}", tsc::rdtscp_available());
    tsc::stage("bootinfo+cpu");

    // ---- Stage2：自己的 GDT/TSS/IDT。协议保证交接时 IDT 状态未定义、FS/GS base = 0，
    // 所以这一步不做，任何异常都是三重故障。
    trap::init_cpu_tables(cpu::BSP_SLOT);
    crate::log_info!("cpu tables: gdt/idt/tss loaded for bsp slot 0, 256 gates installed");
    tsc::stage("idt");

    // ---- Stage2：页表接管（M2）。这一步**不返回**：它换栈后尾跳进 after_switch。
    // 因此凡是在切换之后还要用的启动信息，都必须先落到静态量里——`info` 住在旧栈上，
    // 切换后它就是悬垂引用；而 memmap 原始结构位于可回收内存，一旦该帧被分配走也会被复用。
    RSDP_VA.store(info.rsdp.unwrap_or(0), Ordering::Relaxed);
    // MP 必须在 take_over 之前读并拷出来：见 MpSlot 的注释
    if let Some(m) = info.mp {
        crate::log_info!(
            "limine: mp present cpus={} bsp_lapic={} x2apic={} all_goto_null={} ids={:?}",
            m.cpu_count, m.bsp_lapic_id, m.x2apic_enabled, m.all_goto_null, &m.lapic_ids[..m.n]
        );
        mp_store(m);
    } else {
        crate::log_warn!("limine: MP request not supported (no response) -- M3b cannot start APs from this boot");
    }
    if let Err(e) = mm::take_over(&info, after_switch, 0) {
        // boot_invalid 是 -> !，原因必须先打出来
        crate::log_fatal!("mm::take_over failed: {:?}", e);
        exit::boot_invalid("mm take_over failed");
    }
    unreachable!()
}

/// 页表切换完成后运行在自己的栈上。`_` 是续体参数，留着以便将来传启动句柄。
extern "C" fn after_switch(_: usize) -> ! {
    // ADR-040：先把调度器实现装进 arch 的回调表，早于 AP 释放与任何定时器窗口。
    sched::install_arch_hooks();
    // Task C（V1.0 §14）：启动编排按阶段函数组织；顺序与日志契约不变。
    stage_memory();
    stage_cpu_protections();
    stage_probe_addr();
    stage_acpi_and_pci();
    stage_fault_injections();
    stage_storage_guard_crash();
    run_ktests_and_finish()
}

/// Stage2a/2b：页表接管后的内存统计与内核堆。
fn stage_memory() {
    mm::mark_switched();
    mm::init_allocator();
    if !mm::is_ready() {
        crate::log_fatal!("mm not ready after takeover");
        exit::finish(exit::Code::BootInvalid);
    }
    crate::log_info!("mm: frames total={} free={} max_phys={:#x}", mm::total_frames(), mm::free_frames(), mm::max_phys());
    crate::log_info!("mm: usable memory = {} MiB over {} regions", mm::usable_bytes() / (1024 * 1024), mm::region_count());
    crate::log_info!("mm: bootloader regions held back = {} MiB (AP park area; reclaim is explicit, M3b)", mm::boot_reclaimable_bytes() / (1024 * 1024));
    tsc::stage("mm-takeover");

    // ---- Stage2b：内核堆（M2-b）。堆未就绪时 GlobalAlloc 会返回空指针，
    // 所以在任何可能分配的路径之前先把它建起来。
    match heap::init() {
        Ok(chunks) => crate::log_info!("heap: window ready, pre-mapped {} chunks ({} KiB)", chunks, chunks * 4),
        Err(e) => {
            crate::log_fatal!("heap::init failed: {:?}", e);
            exit::finish(exit::Code::BootInvalid);
        }
    }
    tsc::stage("heap");
}

/// Stage2c：SMEP/SMAP 必需项与 BSP 的 #DF guard 栈。
fn stage_cpu_protections() {
    // ---- Stage2c：把 BSP 的 #DF 栈从 .bss 那一页换成**带 guard page** 的栈（§6.4）。
    // 顺序要求：MM 就绪之后（要走分配器和页表）、任何 AP 释放之前（IST1 是 per-CPU 的）。
    // 换的只是 TSS 里的一个字段，IDT/GDT 不用重装——硬件每次取 IST 都读 TSS。
    // ---- Stage2c：SMEP/SMAP（§5.1 R17 的 M4 必需项）。开完必须读回来，
    // 因为"设了位"与"这位真的生效"是两件事；cpuid 说支持而 CR4 读不回两位，就是启动失败。
    let (smep_on, smap_on, cr4) = cpu::enable_user_protections();
    // 注入点放在这里而不是别处：这条判据要能动，就必须有人**真的**看到"位没开成"。
    // 见 `tools/aurora.py test` 的 BOOT-INVALID 那一行。
    #[cfg(feature = "fault-no-smap")]
    cpu::clear_smap_for_test();
    let feat = cpuid::detect();
    let (act_smep, act_smap) = cpu::user_protections_active();
    crate::log_info!(
        "cr4: smep={} smap={} cr4={:#x} 复核=({},{}) cpuid=({},{})",
        smep_on, smap_on, cr4, act_smep, act_smap, feat.smep, feat.smap
    );
    // §5.1（R17）把 SMEP/SMAP 列为**必需项**，必需项就得回答"没开成功怎么办"。
    // 答案是 BOOT-INVALID(37)：这两条保护的是"内核不许执行用户页 / 不许随手读用户页"，
    // 带着半开的边界继续跑，M4 之后所有隔离承诺都是空的——这不是可以降级的运行时故障，
    // 是机器不满足前提（§9.2 把"前提不满足"与"故障"分成两级，就是因为处置方式不同：
    // 故障要分级止损，前提不满足要**不启动**）。判据用两位：CPUID 说支持 **且** CR4 读回为 1。
    if !(feat.smep && feat.smap && act_smep && act_smap) {
        crate::log_fatal!(
            "SMEP/SMAP 必需项未满足：cpuid=({},{}) cr4=({},{}) —— 不启动",
            feat.smep, feat.smap, act_smep, act_smap
        );
        exit::finish(exit::Code::BootInvalid);
    }

    match trap::install_exception_stack(cpu::BSP_SLOT) {
        Ok(si) => crate::log_info!(
            "exstack bsp: guard={:#x} stack=[{:#x}..{:#x}) ist1={:#x} guard_mapped={}",
            si.guard_va, si.stack_lo, si.stack_hi, si.top, mm::is_mapped(si.guard_va)
        ),
        Err(e) => crate::log_fatal!("exstack bsp: 装不上（继续用 .bss 那一页，没有 guard page）: {:?}", e),
    }
}

/// Stage3：用真实页表挑一个确定未映射的探针地址。
fn stage_probe_addr() {
    // ---- Stage3：探针地址现在按**真实页表**判定，不再靠算术推算
    match pick_probe_addr() {
        Some(a) => {
            PROBE_ADDR.store(a, Ordering::Relaxed);
            crate::log_info!("probe address (page-table-verified unmapped) = {:#x}", a);
        }
        None => crate::log_fatal!("no validatable probe address; #PF probe will fail"),
    }
    // 把登记表条数打出来：堆窗口和探针地址必须各占一条，少一条就说明有人在绕过登记发放 VA
    crate::log_info!("mm: VA reservations in force = {}", mm::reservation_count());
    tsc::stage("probe");
}

/// Stage3b/M5-a：ACPI 固定表与 PCI 枚举的只读快照。
fn stage_acpi_and_pci() {
    // ---- Stage3b：ACPI 固定布局表（M2-c / ADR-012a）。放在堆建好之后：解析要用的
    // 缓冲区都是栈上的，但日志格式化会走全局分配器，顺序反了就是"堆未就绪 -> 空指针"。
    match acpi::init(RSDP_VA.load(Ordering::Relaxed)) {
        Ok(s) => crate::log_info!(
            "acpi: root={} tables={} checksum_fail={} unmapped_reads={} rsdp_rev={} rsdp_va={:#x} root_phys={:#x}",
            if s.used_xsdt { "XSDT" } else { "RSDT" },
            s.tables, s.checksum_failures, s.unmapped_reads, s.rsdp_revision, s.rsdp_va, s.root_phys
        ),
        Err(e) => crate::log_fatal!("acpi::init failed: {:?}", e),
    }
    if let Some(s) = acpi::summary() {
        if let Some(m) = s.madt {
            crate::log_info!(
                "acpi: madt lapic_base={:#x} pcat_compat={} cpu={} (enabled {}) ioapic={} overrides={} lapic_ids={:?} acpi_ids={:?}",
                m.lapic_base, m.pcat_compat, m.cpu_total, m.cpu_enabled, m.n_ioapic, m.n_overrides,
                &m.lapic_ids[..m.n_ids], &m.acpi_ids[..m.n_ids]
            );
        }
        if let Some(f) = s.fadt {
            crate::log_info!("acpi: fadt rev={} len={} boot_arch={:?} hw_reduced={:?}", f.revision, f.length, f.boot_arch, f.hw_reduced);
        }
        crate::log_info!(
            "acpi: mcfg={:?} bus={}..{} dmar_haw={:?} dmar_flags={:?} ivrs={}",
            s.mcfg_base, s.mcfg_bus_start.unwrap_or(0), s.mcfg_bus_end.unwrap_or(0), s.dmar_host_address_width, s.dmar_flags, s.ivrs_present
        );
    }

    // ---- M5-a：PCI 配置空间与设备枚举（§8.7）。放在 ACPI 之后：ECAM 的基址来自 MCFG。
    // 只读配置空间、只映射一段 MMIO，不认领任何中断，所以它对启动判定与性能基线的影响
    // 只体现在多出来的那几行日志上。
    let (mcfg_base, mcfg_bs, mcfg_be) = acpi::summary()
        .map(|s| (s.mcfg_base, s.mcfg_bus_start.unwrap_or(0), s.mcfg_bus_end.unwrap_or(0)))
        .unwrap_or((None, 0, 0));
    match pci::init(mcfg_base, mcfg_bs, mcfg_be) {
        pi => crate::log_info!(
            "pci: backend={} n={} absent={} va={:#x} truncated={}",
            match pi.backend {
                pci::Backend::Ecam => "ECAM",
                pci::Backend::Cam => "CAM",
            },
            pi.n,
            pi.absent,
            pi.va,
            pi.truncated
        ),
    }
    if let Some(pi) = pci::info() {
        for k in 0..pi.n.min(8) {
            if let Some(d) = pci::dev(k) {
                crate::log_info!(
                    "pci: {:04x}:{:02x}.{} vend={:#06x} dev={:#06x} cfg08={:#010x} hdr={:#02x} bar0={:#010x}",
                    d.bdf >> 16,
                    (d.bdf >> 11) & 31,
                    (d.bdf >> 8) & 7,
                    d.vendor,
                    d.device,
                    d.cfg08,
                    d.hdr,
                    d.bar0
                );
            }
        }
    }
}

/// 构建级故障注入（heap OOM / 资源泄漏）；正常构建为空。
fn stage_fault_injections() {
    // ---- 故障注入（ADR-018）：向全局分配器要一个超过大小类上限的分配。
    // `GlobalAlloc::alloc` 返回 null 之后，稳定版唯一的去向是 handle_alloc_error
    // → panic → panic=abort → 我们的 handler → 39。这条只能靠注入证明，
    // 正常构建里永远不会有人真的把堆要空，所以它不能只在文档里写"应该会停机"。
    #[cfg(feature = "fault-heap-oom")]
    {
        crate::log_warn!(
            "fault-heap-oom: 按设计向全局分配器要 {} 字节（LARGE_MAX={}）",
            heap::LARGE_MAX + 1,
            heap::LARGE_MAX
        );
        let mut big: Vec<u8> = Vec::with_capacity(heap::LARGE_MAX + 1);
        big.push(1);
        // 走到这里说明失败没有升级成 L4：那 ADR-018 的出口就是假的，报 FAIL 而不是继续跑绿。
        crate::log_fatal!("fault-heap-oom: 分配失败却没有停机，ADR-018 的 L4 出口不成立");
        exit::finish(exit::Code::Failed);
    }

    // ---- 故障注入（§12.3 R19 的"每道门禁都要有负样本"）：故意泄漏一帧给测试模块，
    // 台账必须把它报出来。如果 t_resource_ledger_balanced 照样绿，说明泄漏检测是假的。
    #[cfg(feature = "fault-resource-leak")]
    {
        // 这里不能用 unwrap/expect（§2.5 的 lint 门禁），所以把"注入没做成"写成分支
        if let Ok(leak) = mm::phys_alloc(0, mm::MOD_TEST) {
            core::mem::forget(leak);
            crate::log_warn!("fault-resource-leak: 已按设计泄漏 1 帧，台账必须抓到");
        } else {
            crate::log_fatal!("fault-resource-leak: 分配失败，注入没有发生（这条构建就没意义了）");
            exit::finish(exit::Code::BootInvalid);
        }
    }
}

/// 存储认领、启动循环保护与上一次崩溃的读回。
fn stage_storage_guard_crash() {
    // ---- §9.4 的启动循环保护：必须先有存储，才谈得上"跨重启的那个计数"。
    // 认领提到启动路径里不是顺手多调一次（`ahci::init` 本来就幂等）：`decide()` 要在
    // 任何可能崩的路径**之前**把 `n+1` 写回盘，而驱动与用例都在后面。
    // 存储没起来 ⇒ 状态区读不到 ⇒ 按最坏情况进安全模式（这正是"读不到"该有的处置）。
    match ahci::init() {
        Ok(i) => crate::log_info!("boot: 存储已认领 abar={:#x} 端口={}", i.abar, i.ports),
        Err(e) => {
            crate::log_warn!("boot: 存储没认领上 {:?}，状态区读不到 ⇒ 按最坏情况处理", e)
        }
    }
    boot_guard::decide();
    // §9.7 的另一半：上一条崩溃在存储就绪之后才读得回来，所以它一定在串口现场之后。
    crash::report_previous();
}

/// Stage4：跑 .ktests、报 P1–P5/P4 读数并交付退出码。
fn run_ktests_and_finish() -> ! {
    // ---- Stage4：跑用例并交付判定
    let s = ktest::run_all();
    crate::log_info!("ktests: total={} passed={} failed={} table_invalid={}", s.total, s.passed, s.failed, s.table_invalid);
    // §9.6 的账本：开机到现在看过几次心跳、报过几次、处置过几次。处置次数今天必须是 0，
    // 它变成非 0 的那一天就是"把核摘线"真的实现了的那一天（在那之前它只是个计数器）。
    let (wd_samples, wd_windows, wd_events, wd_mask, wd_actions) = watchdog::stats();
    crate::log_info!(
        "watchdog: 采样={} 报警窗口={} 核次={} 末位图={:#x} 处置={}",
        wd_samples,
        wd_windows,
        wd_events,
        wd_mask,
        wd_actions
    );
    // 健康条件：本轮用例一条没红且表不是空的 ⇒ 把连续失败计数清回 0
    if s.failed == 0 && !s.table_invalid {
        boot_guard::mark_healthy();
    }
    // 用例跑完才让 AP 停机（放在用例之间会让同一条用例在两种链接顺序下给出两种结论）。
    // 停机之后再把 per-CPU 的数打出来，免得 hlt 之前的读数被后面的 tick 追改。
    smp::stop_aps();
    // ADR-019 的那次**显式**回收：前提条件此刻才成立——所有 AP 都已经从 bootloader 给的
    // 启动栈上走开并停机（stop_aps 里逐个等到"已关定时器 + 已关 IF"的信号，并把它们摘下线）。
    // 回收必须在 stop_aps 之后、也必须在最后一次用到 mp.cpu_ptrs 之后：
    // 那些 mp_info 结构本身就住在可回收内存里。
    let reclaimed = mm::reclaim_bootloader_regions();
    crate::log_info!(
        "smp final: released={} online={} stuck_online={} cpu_ticks={:?} bsp_ticks={}",
        smp::released_count(), cpu::online_count(), smp::stuck_online_count(), apic::cpu_ticks_all(), sched::ticks_of(cpu::BSP_SLOT)
    );
    crate::log_info!(
        "mm: bootloader regions reclaimed = {} frames ({} MiB) ; free frames now {}",
        reclaimed, reclaimed * mm::PAGE / (1024 * 1024), mm::free_frames()
    );
    let ls = sync::stats();
    crate::log_info!(
        "sync: acquires={} order_violations={} reentrant_hits={} wait_events={} wait_spins={} wait_max={} wait_timeouts={}",
        ls.acquires, ls.order_violations, ls.reentrant_hits, ls.wait_events, ls.wait_spins_total,
        ls.wait_max_cycles, ls.wait_timeouts
    );
    crate::log_info!("percpu: registered={} unmatched_self_lookups={}", cpu::registered(), cpu::unmatched_self_lookups());
    let c = mm::counters();
    crate::log_info!(
        "mm counters: map_calls={} mapped_pages={} unmapped_pages={} page_table_pages={} early_pool={}",
        c.map_calls, c.mapped_pages, c.unmapped_pages, c.page_table_pages, c.early_pool_used
    );
    tsc::stage("ktests");

    // ---- P3 / P4 交付（§12.4.1）。P3 的两条路径分开报；一条都没取到就是量具坏了，
    // 必须让它进判定条件而不是留一行空数字——量具不出数不等于出数为 0。
    let pr = trap::p3_resume_stats();
    let pf = trap::p3_fatal_stats();
    let p5 = trap::p5_irq_stats();
    let c = apic::counts();
    let rust_irq_total: usize = c.irq.iter().sum::<usize>() + c.unexpected + c.spurious + c.resched;
    let (n1, mean1, min1, max1) = sched::p1_stats();
    crate::log_info!("p1 switch: samples={} mean={} min={} max={} cycles", n1, mean1, min1, max1);
    // P1 也按 CPU 分行（M3b-2b）。注意这里**不能**写"之前 min 涨了是因为混样"：
    // 分行之后 BSP 自己那一行还是 2603（AP 的行 3090~3572），而 AP 不参与调度的 M3b-1
    // 是同一条尺子的 462~987。涨的原因尚未归因（最可能是宿主侧争用），已挂任务 #11。
    // 这一行的用途是让"哪个核的样本进了哪个数"变成可见的，而不是给出因果。
    for (cpu, n, mean, min, max) in sched::p1_with_samples() {
        crate::log_info!("p1 percpu cpu{}: samples={} mean={} min={} max={} cycles", cpu, n, mean, min, max);
    }
    // P2（§12.4 的"驱动接口往返开销"）在这里采：ktests 已经跑完，设备与页框都在
    // 稳态里，探针自己认领、自己撤销
    p2_probe();
    crate::log_info!(
        "p5 irq: samples={} mean={} min={} max={} last_vec={:#x} cycles | rust total={} irq0={} irq1..15={} 按CPU={:?} unexpected={} spurious={} eoi={} | PF_TAKEN={}",
        p5.faults, p5.mean_cycles, p5.min_cycles, p5.max_cycles, trap::p5_last_vec(),
        rust_irq_total, c.irq[0], c.irq[1..].iter().sum::<usize>(), irq::by_cpu(), c.unexpected, c.spurious, c.eois,
        trap::PF_TAKEN.load(Ordering::Relaxed)
    );
    crate::log_info!(
        "p3 resume: faults={} mean={} min={} max={} cycles",
        pr.faults, pr.mean_cycles, pr.min_cycles, pr.max_cycles
    );
    // 边界移动之后的读数说明（ADR-021 同段记录）：P3/P5 的下界从"异常桩第一条指令"
    // 移到"进 Rust 垫片"，上界从"寄存器恢复之后"移到"垫片末尾"，并且整张表按 CPU 分行。
    // 所以这三行与 M3a/M3b-1 存档里的数字**不可直接比**；能比的只有同一构建内部的比值
    // （那正是 §12.4.1 规则 3 的判别方式，bench 就是这么判的）。
    for ps in trap::p_stats_all().iter() {
        if ps.cpu >= crate::arch::x86_64::cpu::registered() && ps.cpu != crate::arch::x86_64::cpu::BSP_SLOT {
            continue;
        }
        if ps.cpu != crate::arch::x86_64::cpu::BSP_SLOT && ps.irq.faults == 0 && ps.resume.faults == 0 {
            continue; // 没登记或没样本的槽位不占一行
        }
        crate::log_info!(
            "p percpu cpu{}: p3(faults={} min={}) p5(faults={} mean={} min={} max={} last_vec={:#x}) fatal(faults={} min={}) p7(faults={} mean={} min={})",
            ps.cpu, ps.resume.faults, ps.resume.min_cycles, ps.irq.faults, ps.irq.mean_cycles,
            ps.irq.min_cycles, ps.irq.max_cycles, ps.last_vec, ps.fatal.faults, ps.fatal.min_cycles,
            ps.syscall.faults, ps.syscall.mean_cycles, ps.syscall.min_cycles
        );
    }
    crate::log_info!(
        "p totals across cpus: p5_samples={} p3_faults={} (对照：apic 侧计数与 PF_TAKEN)",
        trap::p5_samples_total(), trap::p3_faults_total()
    );
    crate::log_info!(
        "p3 fatal: faults={} mean={} min={} max={} cycles (fatal path = detect + stop prep, excludes crash dump emission)",
        pf.faults, pf.mean_cycles, pf.min_cycles, pf.max_cycles
    );
    // µs 列只有在标定成功之后才出现；没标定就只报 cycles，**不回退成"假设 1 GHz"**
    let us = clock::micros(tsc::elapsed());
    match us {
        Some(v) => crate::log_info!(
            "p4: stages={} total={} cycles = ~{} us (estimated: TSC not invariant, so long spans drift) serial_bytes={}",
            tsc::total_stages(), tsc::elapsed(), v, serial::bytes_out()
        ),
        None => crate::log_info!(
            "p4: stages={} total={} cycles (no calibration -> cycles only) serial_bytes={}",
            tsc::total_stages(), tsc::elapsed(), serial::bytes_out()
        ),
    }

    // 量具自检：样本数>0 且 min<=mean<=max。这一条不是装饰——asm 里 min/max 的分支方向
    // 写反时，mean 看着完全正常而 min 停在 u64::MAX、max 停在 0，只有这条链能抓住它。
    // 它不进 ktest 表而进判定，因为表的枚举顺序不由源码顺序决定，用例之间不能假设
    // "前面已经有人触发过故障"。
    let ruler_ok = pr.faults > 0 && pr.min_cycles <= pr.mean_cycles && pr.mean_cycles <= pr.max_cycles;
    crate::log_info!("p3 ruler: samples_ok={} min<=mean<=max={}", pr.faults > 0, pr.min_cycles <= pr.mean_cycles && pr.mean_cycles <= pr.max_cycles);

    // 判定必须同时满足：表可用且非空、无失败、异常确实被取到过、且 P3 的量具真的收到过样本
    let clean = !s.table_invalid
        && s.total > 0
        && s.failed == 0
        && trap::PF_TAKEN.load(Ordering::Relaxed) > 0
        && ruler_ok;
    if clean {
        crate::log_info!("verdict: PASS");
        exit::finish(exit::Code::Success);
    }
    crate::log_warn!("verdict: FAIL");
    exit::finish(exit::Code::Failed)
}


/// 用页表本身找一个确定未映射的页：先问 `mm::is_mapped`，不再靠区间算术推断。
/// 取到即登记，堆窗口之后不可能再拿到同一页。
fn pick_probe_addr() -> Option<u64> {
    mm::alloc_va_page().map(|v| v.0)
}

// ------------------------------------------------------------------ 用例

// ---------------------------------------------------------------- M2 内存用例

// ---------------------------------------------------------------- ACPI 用例

// ---------------------------------------------------------------- M3a：中断

/// **幂等**的标定：已经标定过就直接回读数。
///
/// 为什么要有这个函数而不是让用例自己标定：AP 的本地定时器初值要用 `tsc_hz` 反推，
/// 而 `.ktests` 的枚举顺序由链接顺序决定、不由源码顺序决定。把"谁先跑"当成前提
/// 就等于写一个偶发的"AP 起不来"。所以 `smp::bringup` 自己补一次标定，
/// 用例也走同一个入口——两个调用点，一份实现。
pub fn calibrate_clock_once() -> Option<clock::Calibration> {
    if let Some(c) = clock::current() {
        return Some(c);
    }
    let s = acpi::summary()?;
    let m = s.madt?;
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("clock: APIC 起不来，标定无从谈起");
        return None;
    }
    if apic::timer_start().is_err() {
        crate::log_fatal!("clock: cannot start timer");
        return None;
    }
    // 窗口里**一行日志都不打**：串口按字节忙等，一次输出就是几十毫秒，
    // 期间必然跳过好几个 tick，而"观察到的相邻间隔"会把漏掉的 tick 算成更长的周期
    // （第一次标定报 4.78 GHz 就是这么来的）。
    let base_ticks = apic::reset_tick_stats();
    // 窗口按 cycles 给上界，样本目标 20 次；上界 `window_cycles(MIN_SAMPLES)` 是
    // "任何可信 TSC 都至少能数到 MIN_SAMPLES 次"的那个长度（推导见 clock::window_cycles）。
    // 原先这里写的是 `r < 4000` 轮：KVM 对照档实测同一颗 QEMU 只换 accel，
    // 4000 轮在 tcg 档值 2.08 亿 cycles（数到 6 个 tick）、在 kvm 档只值 1.01 亿（数到 4 个），
    // 样本数正好压在门槛上——第一次调用 3 个就报 NoSamples，第二次同样代码却有 4 个。
    let w = apic::wait_ticks(base_ticks, 20, clock::window_cycles(clock::MIN_SAMPLES));
    apic::timer_stop().ok();
    let inv = cpuid::detect().tsc_inv;
    let ints = apic::tick_delta_sum();
    let cal = match clock::from_pit_window(w.cycles, w.ticks, apic::tick_delta_max_cycles(), ints, inv) {
        Ok(c) => c,
        Err(e) => {
            crate::log_fatal!("clock: calibration refused: {:?}", e);
            return None;
        }
    };
    crate::log_info!(
        "clock: {} ticks in {} cycles -> tsc_hz={} Hz, tick ~ {:?} us, max_gap={} (PIT divisor {} Hz/{} Hz, invariant={}) 窗口={} cycles 轮数={}",
        cal.samples, w.cycles, cal.tsc_hz, clock::micros(cal.tick_period_cycles),
        apic::tick_delta_max_cycles(), clock::PIT_HZ, clock::PIT_DIVISOR, inv,
        clock::window_cycles(clock::MIN_SAMPLES), w.rounds
    );
    // 两把尺子并排印出来：窗口均值（含两端切掉的半段，必然偏高）与 ISR 自己量的相邻间隔均值。
    // 那条硬不等式在 `clock::from_pit_window` 里判——红起来是标定当场拒，不是一个打印出来的数。
    crate::log_info!(
        "clock 两把尺子: 窗口 total={} ÷ ticks={} ⇒ 窗口均值={}；ISR 相邻间隔 n={} 和={} ⇒ 均值={}（估计器用后者）；容许区间={}..{}（上界=和+2×每 tick 最长 {} cycles）",
        w.cycles, cal.samples, w.cycles / cal.samples as u64,
        cal.interval_n, ints.0, cal.interval_mean,
        ints.0, ints.0 + 2 * clock::max_tick_period_cycles(), clock::max_tick_period_cycles(),
    );
    Some(cal)
}


// ---------------------------------------------------------------- M3b：多核

// ---------------------------------------------------------------- M4：用户态

/// P2 的采样次数与单条测量的窗口（写成模块级常量，`p2_one` 是被测闭包的通用包装，
/// 闭包参数不能是 `impl Trait` ⇒ 只能做成泛型函数而不是嵌套闭包）
const P2_SAMPLES: u64 = 64;

fn p2_one<F: Fn()>(inner: F) -> (u64, u64, u64) {
    let (mut sum, mut mn, mut mx) = (0u64, u64::MAX, 0u64);
    for _ in 0..P2_SAMPLES {
        let a = tsc::now();
        inner();
        let d = tsc::now().wrapping_sub(a);
        sum += d;
        mn = mn.min(d);
        mx = mx.max(d);
    }
    (sum / P2_SAMPLES, mn, mx)
}

/// §12.4 的 P2：`DriverCtx` 一次 MMIO 读 / 一次 MMIO 写 / 一次 DMA 映射+撤销的往返开销。
/// 手册给它的理由是"§8.5 那条'同一份驱动代码迁到用户态'到底要付多少"——没有这一行，
/// §2.4 那张表里"微内核的 IPC 代价"那一列就永远是修辞。
///
/// 三条线之外还有一条 `p2 ruler`：同一次测量做 1 遍与做 4 遍，`min` 必须按比例走。
/// 不按比例说明这把尺子量的不是这件事（§12.4.1 规则 3：先证明量具能分辨，再谈数字）。
fn p2_probe() {
    let Some(dev) = pci::first_of_triple(0x01, 0x06, 0x01) else {
        crate::log_warn!("p2: 枚举表里没有 SATA-AHCI 设备，这条基线出不了数");
        return;
    };
    // 自己认领一份 ctx（owner 用 MOD_TEST：这条探针不是驱动的一部分，不该记到驱动台账上）。
    // 用完必须撤销，否则 `mm counters` 与句柄表占用会把"探针跑过"当成常态状态留给后面的读数。
    let ctx = driver::DriverCtx::for_device(mm::MOD_TEST, dev);
    let Ok(h) = ctx.map_mmio(5) else {
        crate::log_warn!("p2: 映射 BAR5 失败，这条基线出不了数");
        return;
    };
    // 写方向选 `GHC`：先读回当前值再原样写回去，这一格是幂等的（AE 已经置着，
    // 绝不能测 `HR`——那位一写就是整个控制器复位，会把 AHCI 的端口全打回复位态）
    let ghc = ctx.read32(h, ahci::REG_GHC).unwrap_or(0);
    let (rd_mean, rd_min, rd_max) = p2_one(|| {
        core::hint::black_box(ctx.read32(h, ahci::REG_CAP).unwrap_or(0));
    });
    let (wr_mean, wr_min, wr_max) = p2_one(|| {
        core::hint::black_box(ctx.write32(h, ahci::REG_GHC, ghc).is_err());
    });
    let (dma_mean, dma_min, dma_max) = p2_one(|| {
        if let Ok(d) = ctx.alloc_dma(mm::PAGE) {
            core::hint::black_box(ctx.bus_addr(d).unwrap_or(0));
            ctx.release_dma(d).ok();
        }
    });
    // 尺子自证：一次读 vs 连着四次读。四次里省掉的是两次 `tsc::now()`，
    // 所以要求不是严格的 4 倍，而是"至少两倍"——连两倍都不到就说明这两次测量
    // 测的是同一个别的东西（比如被外层循环摊平了）
    let (_, four_min, _) = p2_one(|| {
        for _ in 0..4 {
            core::hint::black_box(ctx.read32(h, ahci::REG_CAP).unwrap_or(0));
        }
    });
    let ruler_ok = four_min > rd_min.saturating_mul(2);
    ctx.release_mmio(h).ok();
    crate::log_info!(
        "p2 mmio-rd: samples={} mean={} min={} max={} cycles",
        P2_SAMPLES,
        rd_mean,
        rd_min,
        rd_max
    );
    crate::log_info!("p2 mmio-wr: samples={} mean={} min={} max={} cycles", P2_SAMPLES, wr_mean, wr_min, wr_max);
    crate::log_info!("p2 dma: samples={} mean={} min={} max={} cycles", P2_SAMPLES, dma_mean, dma_min, dma_max);
    crate::log_info!(
        "p2 ruler: 1次min={} 4次min={} 比值x100={} 能分辨={}",
        rd_min,
        four_min,
        four_min.saturating_mul(100) / rd_min.max(1),
        ruler_ok
    );
    if !ruler_ok {
        crate::log_fatal!("p2: 这把尺子分辨不出 1 次与 4 次，上面的数字不能当基线用");
    }
}









