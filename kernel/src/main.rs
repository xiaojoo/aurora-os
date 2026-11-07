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
mod hw;
mod irq;
mod exit;
mod ktest;
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
static PROBE_ADDR: AtomicU64 = AtomicU64::new(0);

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
static RSDP_VA: AtomicU64 = AtomicU64::new(0);

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
    let rust_irq_total: usize = c.irq.iter().sum::<usize>() + c.unexpected + c.spurious;
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

fn t_revision_tag_rewritten() -> bool {
    // rev>=3 的 bootloader 必须把 tag 第 2 分量改写为实际 revision
    limine::BASE_REVISION.negotiated().is_some_and(|v| (3..=5).contains(&v))
}
ktest!(KT_REV, t_revision_tag_rewritten);

fn t_memmap_usable_ge_32mib() -> bool {
    // 读 mm 里**拷出来的**表，不读 bootloader 原始结构：那些帧现在是可分配的
    let mut i = 0usize;
    let mut usable = 0u64;
    while let Some(r) = mm::region(i) {
        if r.kind == limine::MemmapType::Usable {
            usable = usable.saturating_add(r.length);
        }
        i += 1;
    }
    crate::log_info!("memmap usable = {} MiB over {} entries", usable / (1024 * 1024), i);
    usable >= 32 * 1024 * 1024
}
ktest!(KT_MEMMAP, t_memmap_usable_ge_32mib);

fn t_hhdm_is_canonical_and_below_kernel() -> bool {
    let o = mm::hhdm();
    o != 0 && o < 0xffff_ffff_8000_0000 && (o >> 47) == 0x1_ffff
}
ktest!(KT_HHDM, t_hhdm_is_canonical_and_below_kernel);

/// RSDP 的地址语义随 base revision 变化（rev3 物理、rev4+ 虚拟）。
/// 我们请求 rev5，因此必须是**可直接读的虚拟地址**；签名读不对就是启动信息不可信。
fn t_rsdp_signature_at_virtual_addr() -> bool {
    let Some(negotiated) = limine::BASE_REVISION.negotiated() else {
        return false;
    };
    let raw = RSDP_VA.load(Ordering::Relaxed);
    if raw == 0 {
        crate::log_warn!("rsdp: bootloader did not provide it");
        return false;
    }
    let hhdm = mm::hhdm();
    if raw < hhdm {
        crate::log_fatal!("rsdp={:#x} 低于 HHDM({:#x})：这是 rev3 的物理地址语义，与协商到的 rev{} 不符", raw, hhdm, negotiated);
        return false;
    }
    if !mm::is_mapped(raw) {
        crate::log_fatal!("rsdp={:#x} 在我们的页表里没有映射", raw);
        return false;
    }
    const SIG: &[u8; 8] = b"RSD PTR ";
    for i in 0..8 {
        // SAFETY: 上面已确认地址已映射；RSDP 至少 20 字节，只读前 8 字节签名
        let got = unsafe { core::ptr::read_volatile((raw as *const u8).add(i)) };
        if got != SIG[i] {
            crate::log_fatal!("rsdp signature mismatch at byte {}: got {:#02x} want {:#02x}", i, got, SIG[i]);
            return false;
        }
    }
    true
}
ktest!(KT_RSDP, t_rsdp_signature_at_virtual_addr);

/// 受控 #PF：异常被取到、CR2 与故障地址一致、且 iretq 后确实回到恢复点
fn t_pf_probe_recovers() -> bool {
    let addr = PROBE_ADDR.load(Ordering::Relaxed);
    if addr == 0 {
        return false;
    }
    match trap::probe_page_fault(addr) {
        Some(1) => trap::PF_TAKEN.load(Ordering::Relaxed) > 0,
        Some(other) => {
            crate::log_fatal!("pf probe resumed with unexpected rax={}", other);
            false
        }
        None => {
            crate::log_fatal!("pf probe did NOT fault: {:#x} is apparently mapped", addr);
            false
        }
    }
}
ktest!(KT_PF, t_pf_probe_recovers);

fn t_all_32_vectors_distinct() -> bool {
    trap::handler_count_distinct() == 32
}
ktest!(KT_IDT, t_all_32_vectors_distinct);

// ---------------------------------------------------------------- M2 内存用例

/// 分配-释放是否真的回到基线（不比对基线就等于没测）
fn t_alloc_free_returns_frames() -> bool {
    let base = mm::free_frames();
    let f = match mm::phys_alloc(0, mm::MOD_TEST) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("phys_alloc failed: {:?}", e);
            return false;
        }
    };
    let after_alloc = mm::free_frames();
    let addr = f.base().0;
    drop(f);
    let after_free = mm::free_frames();
    crate::log_info!("alloc/free: base={} alloc={} free={} frame={:#x}", base, after_alloc, after_free, addr);
    // 释放后该帧被毒化成 0xa5，读回来才说明“释放”真的发生了
    let poisoned = {
        // SAFETY: addr 来自分配器且在 max_phys 内，HHDM 覆盖全部物理内存
        let p = mm::hhdm() + addr;
        let v = unsafe { core::ptr::read_volatile(p as *const u8) };
        v == 0xa5
    };
    base > after_alloc && after_free == base && poisoned
}
ktest!(KT_ALLOC_FREE, t_alloc_free_returns_frames);

/// 映射 -> 写入 -> 读回 -> 解映射，且所有权随 Mapping 归还（§6.3 R13）
fn t_map_write_unmap() -> bool {
    const MAGIC: u64 = 0x5176_0dae_1234_beef;
    let va = match mm::alloc_va_range(1) {
        Some(v) => v,
        None => {
            crate::log_fatal!("no unmapped range for map test");
            return false;
        }
    };
    let base_free = mm::free_frames();
    let frames = match mm::phys_alloc(0, mm::MOD_TEST) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("map test alloc failed: {:?}", e);
            return false;
        }
    };
    let m = match mm::map(va, frames, mm::PageFlags::RW) {
        Ok(m) => m,
        Err(e) => {
            crate::log_fatal!("map failed: {:?}", e);
            return false;
        }
    };
    // SAFETY: m.virt() 刚建立的映射，页框来自分配器
    unsafe { core::ptr::write_volatile(m.virt().0 as *mut u64, MAGIC) };
    // SAFETY: 同上
    let got = unsafe { core::ptr::read_volatile(m.virt().0 as *mut u64) };
    let mapped_before = mm::is_mapped(m.virt().0);
    let after_alloc = mm::free_frames();
    let virt = m.virt();
    drop(m); // Mapping::drop -> unmap，然后 OwnedFrames::drop -> 释放
    // 端到端不变量：**数据页**必须归还；解映射后映射必须消失。
    // 注意 map() 建叶子表时会按 create=true 要一整页当页表页，那一页是长期占用，
    // 不该在 unmap 时回来（实测 base=128991 -> after_alloc=128989，正是数据页 + 页表页各一）。
    // 因此这里比的是 after_alloc + 1，而不是 base_free——第一版断言写成后者是错的。
    let ok = got == MAGIC && mapped_before && !mm::is_mapped(virt.0) && mm::free_frames() == after_alloc + 1;
    if !ok {
        crate::log_fatal!(
            "map/unmap wrong: got={:#x} mapped_before={} mapped_after={} free base={} after_alloc={} final={}",
            got,
            mapped_before,
            mm::is_mapped(virt.0),
            base_free,
            after_alloc,
            mm::free_frames()
        );
    }
    ok
}
ktest!(KT_MAP_UNMAP, t_map_write_unmap);

/// guard page：只映射第二页，第一页必须仍未映射且访问它要能取到异常。
/// 这是 M1 时我在 §5.2 注释里承认“还没有 guard page”的那一项。
fn t_guard_page_blocks_access() -> bool {
    let va = match mm::alloc_va_range(2) {
        Some(v) => v,
        None => {
            crate::log_fatal!("no unmapped range for guard test");
            return false;
        }
    };
    let frames = match mm::phys_alloc(1, mm::MOD_STACK) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("guard test alloc failed: {:?}", e);
            return false;
        }
    };
    // 只映射高地址那一页，低地址那页留作 guard
    let stack_va = mm::VirtAddr(va.0 + 4096);
    let m = match mm::map(stack_va, frames, mm::PageFlags::RW) {
        Ok(m) => m,
        Err(e) => {
            crate::log_fatal!("guard map failed: {:?}", e);
            return false;
        }
    };
    let guard = stack_va.0 - 4096;
    let stack_faults = trap::probe_page_fault(stack_va.0).is_some();
    let guard_faults = trap::probe_page_fault(guard).is_some();
    drop(m);
    crate::log_info!("guard: mapped_page_faulted={} guard_page_faulted={}", stack_faults, guard_faults);
    // 映射页不该故障，guard 页必须故障
    !stack_faults && guard_faults
}
ktest!(KT_GUARD_PAGE, t_guard_page_blocks_access);

/// W^X 在构造层面不可表达。**这只测 API**，硬件强制要等 M4 的执行路径探针，
/// 不把前者说成后者。
fn t_wx_construction_rejected() -> bool {
    mm::PageFlags::new(true, true, false) == Err(mm::MmError::WxViolation)
        && mm::PageFlags::new(true, false, false).is_ok()
}
ktest!(KT_WX_API, t_wx_construction_rejected);

/// 2 MiB 大页覆盖的 VA 里铺 4 KiB 叶子必须被**拒绝**（`HugeConflict`）。
///
/// 加这条的用例而不是只改 `walk_leaf`：修之前它会直接钻进大页表项，把那块**数据帧**
/// 当成下一级页表——`set_leaf` 检查的是叶子位，看不见大页父项的冲突，于是“映射成功”，
/// 而翻译仍然是那个大页。HHDM 尾部按 2 MiB 对齐铺大页，未对齐的物理上界正好被这样盖住，
/// 所以这不是假想路径。断言里有三条是"没留下痕迹"：不新增页表页、不计入 map_calls、
/// 物理页随 Drop 归还。
fn t_map_refused_inside_huge_page() -> bool {
    let va = mm::VirtAddr(mm::hhdm() + mm::PAGE as u64);
    if !mm::is_mapped(va.0) {
        crate::log_fatal!("huge probe va {:#x} is not mapped; 用例前提不成立", va.0);
        return false;
    }
    let before = mm::counters();
    let free_before = mm::free_frames();
    let frames = match mm::phys_alloc(0, mm::MOD_TEST) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("huge probe alloc failed: {:?}", e);
            return false;
        }
    };
    let err = mm::map(va, frames, mm::PageFlags::RW).err();
    let after = mm::counters();
    let back = mm::free_frames() == free_before;
    let no_table = after.page_table_pages == before.page_table_pages;
    let no_call = after.map_calls == before.map_calls;
    let still_mapped = mm::is_mapped(va.0);
    crate::log_info!(
        "huge conflict: err={:?} frames_back={} no_new_table={} no_map_call={} hhdm_alias_still_mapped={}",
        err, back, no_table, no_call, still_mapped
    );
    err == Some(mm::MmError::HugeConflict) && back && no_table && no_call && still_mapped
}
ktest!(KT_HUGE_CONFLICT, t_map_refused_inside_huge_page);

/// 全局分配器是否真的挂上了：直接用 `Vec`，走的就是 `AuroraGlobal`。
/// 这比单测 `try_alloc` 更实在——它证明 `alloc` 钩子被 std/alloc  machinery 调用且没走到
/// handle_alloc_error（那会变成 panic → 39，这里要求的是它正常返回）。
fn t_global_allocator_backs_vec() -> bool {
    let before = heap::stats();
    let mut v: Vec<u64> = Vec::new();
    for i in 0..64u64 {
        v.push(i * i);
    }
    let mid = heap::stats();
    let sum_ok = v.len() == 64 && v[8] == 64 && v[63] == 3969;
    let grew = mid.alloc_calls > before.alloc_calls;
    drop(v);
    let after = heap::stats();
    crate::log_info!(
        "heap vec: alloc {} -> {} -> {}, live {} -> {} -> {}",
        before.alloc_calls, mid.alloc_calls, after.alloc_calls, before.live_bytes, mid.live_bytes, after.live_bytes
    );
    // 释放后存活字节必须回到基线，否则就是分配器把内存吞了
    sum_ok && grew && after.live_bytes == before.live_bytes && after.live_count == before.live_count
}
ktest!(KT_VEC_ALLOC, t_global_allocator_backs_vec);

/// 释放后再分配同一大小类，应当复用槽位（不继续吃 bump 指针）
fn t_heap_reuses_freed_slot() -> bool {
    let l = match core::alloc::Layout::from_size_align(100, 8) {
        Ok(l) => l,
        Err(_) => return false,
    };
    let a = heap::try_alloc(l);
    let bump_after_first = heap::stats().window_used;
    let Some(p) = a else {
        crate::log_fatal!("heap try_alloc(100) failed");
        return false;
    };
    // SAFETY: p 是刚分配的 128 字节槽位
    unsafe { core::ptr::write_bytes(p, 0x5a, 100) };
    // SAFETY: 同一槽位归还
    unsafe {
        if !heap::dealloc_small(p, 100) {
            return false;
        }
    }
    let b = heap::try_alloc(l);
    let reused = b == Some(p);
    let bump_after = heap::stats().window_used;
    crate::log_info!("heap reuse: reused={} window_used {} -> {}", reused, bump_after_first, bump_after);
    reused && bump_after == bump_after_first
}
ktest!(KT_HEAP_REUSE, t_heap_reuses_freed_slot);

/// 超过大小类上限的请求必须**显式失败**并计入 OOM 计数（ADR-018），
/// 而不是悄悄走进一条没做完的大对象路径。
fn t_heap_rejects_oversize() -> bool {
    let l = match core::alloc::Layout::from_size_align(heap::LARGE_MAX + 1, 8) {
        Ok(l) => l,
        Err(_) => return false,
    };
    let before = heap::stats().oom_count;
    let got = heap::try_alloc(l);
    let after = heap::stats().oom_count;
    crate::log_info!("heap oversize: got={:?} oom {} -> {}", got.is_none(), before, after);
    got.is_none() && after == before + 1
}
ktest!(KT_HEAP_OVERSIZE, t_heap_rejects_oversize);

/// 交出去的每一个槽位，首尾两字节所在页都必须**真的映射过**。
///
/// 这条是 M2-b 第一版故障的复现用例：当时补映射的判据拿分配光标当映射前沿，
/// 光标恰好压在页边界上时 `need < aligned` 不成立，于是把从未映射的页发了出去，
/// 现场是写在窗口内 1.06 MiB 处的 #PF(err=0x2)。用例刻意越过预映射的 16 个 chunk，
/// 让补映射这条真路被走到——不走过它的分配器测不出这个 bug。
fn t_heap_slots_are_mapped() -> bool {
    let oom_before = heap::stats().oom_count;
    let mut held: Vec<(*mut u8, usize)> = Vec::new();
    for cls in [heap::LARGE_MAX, 1024usize, 16usize] {
        let l = match core::alloc::Layout::from_size_align(cls, 8) {
            Ok(l) => l,
            Err(_) => return false,
        };
        for i in 0..40 {
            let Some(p) = heap::try_alloc(l) else {
                crate::log_fatal!("heap slots: cls={} alloc #{} failed", cls, i);
                return false;
            };
            let tail = (p as usize) + cls - 1;
            let head_page = (p as u64) & !(mm::PAGE as u64 - 1);
            let tail_page = (tail as u64) & !(mm::PAGE as u64 - 1);
            // 先问页表再写：顺序反过来时故障会先进异常处理器，
            // 现象从“一条 FAIL(35) 的用例”变成“整个构建 39”，归因难度差一个量级。
            if !mm::is_mapped(head_page) || !mm::is_mapped(tail_page) {
                crate::log_fatal!("heap slot {:#x}..{:#x} lands on unmapped page", p as usize, tail);
                return false;
            }
            // SAFETY: p 是刚交出的 cls 字节槽位，上一步已确认首尾页都在
            unsafe {
                core::ptr::write_volatile(p, 0x4c);
                core::ptr::write_volatile(p.add(cls - 1), 0x7a);
            }
            // SAFETY: 同上，且写入紧接在读回之前，中间没有释放
            let head_ok = unsafe { core::ptr::read_volatile(p) } == 0x4c;
            let tail_ok = unsafe { core::ptr::read_volatile(p.add(cls - 1)) } == 0x7a;
            if !(head_ok && tail_ok) {
                crate::log_fatal!("heap slot {:#x} read-back wrong", p as usize);
                return false;
            }
            held.push((p, cls));
        }
    }
    let st = heap::stats();
    crate::log_info!("heap slots: {} held, window used={} mapped={}", held.len(), st.window_used, st.window_mapped);
    let frontier = heap::frontier_covered();
    // 归还，别把这些槽位留在存活计数里污染后面用例的读数
    for (p, cls) in held {
        // SAFETY: 每个指针都来自上面那次 try_alloc，大小一致
        unsafe {
            if !heap::dealloc_small(p, cls) {
                return false;
            }
        }
    }
    frontier && st.window_mapped >= st.window_used && st.oom_count == oom_before
}
ktest!(KT_HEAP_SLOTS_MAPPED, t_heap_slots_are_mapped);

// ---------------------------------------------------------------- ACPI 用例

/// 每张表都要过校验和；同时**自证这把尺子能分辨**：把某个字节取反后的和必须不为 0。
/// 后者不是走过场——`checksum` 若把长度算错（比如只算了表头 36 字节），
/// "所有表都通过"会一起变成假话，而这条断言必然先炸。
fn t_acpi_tables_and_checksums() -> bool {
    let Some(s) = acpi::summary() else {
        crate::log_fatal!("acpi: no summary, init 没成功");
        return false;
    };
    if s.tables == 0 {
        crate::log_fatal!("acpi: 登记到 0 张表——根表读到的条目全是空的");
        return false;
    }
    let mut probe_len = 0usize;
    let mut probe_va = 0u64;
    let mut i = 0usize;
    while let Some(t) = acpi::table(i) {
        crate::log_info!(
            "acpi: table{} sig={:#010x} va={:#x} len={} rev={} checksum_zero={}",
            i, acpi::sig_be(t), t.va, t.length, t.revision, t.checksum_zero
        );
        if t.length >= 40 && probe_va == 0 {
            probe_va = t.va;
            probe_len = t.length;
        }
        i += 1;
    }
    // 尺子自检：合法表的整表和必须为 0，翻转一字节后必须不为 0（数学上恒成立，见 acpi.rs）
    let (real, flipped) = if probe_len >= 40 {
        (acpi::checksum(probe_va, probe_len).ok(), acpi::checksum_with_byte_flipped(probe_va, probe_len, 36).ok())
    } else {
        (None, None)
    };
    crate::log_info!(
        "acpi ruler: tables={} failures={} unmapped_reads={} probe_sum={:?} flipped_sum={:?}",
        s.tables, s.checksum_failures, s.unmapped_reads, real, flipped
    );
    s.checksum_failures == 0
        && s.unmapped_reads == 0
        && real == Some(0)
        && flipped.is_some_and(|f| f != 0)
}
ktest!(KT_ACPI_CHECKSUMS, t_acpi_tables_and_checksums);

/// MADT 是 M3b 起 AP 的硬前置：LAPIC 基址、IO APIC 数、中断覆盖、BSP id 都得是真值。
fn t_acpi_madt_shape() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else {
        crate::log_fatal!("acpi: MADT 缺席，M3b 无从起核");
        return false;
    };
    // LAPIC 基址必须是页对齐的 MMIO 地址（规范给的是 0xFEE00000 一类）
    let lapic_ok = m.lapic_base != 0 && m.lapic_base & 0xfff == 0 && (m.lapic_base >> 20) != 0;
    // 清单完整性：列出的 id 数必须等于使能数（没有溢出），且每个 id 都 < 255
    // （保留/无效值）。这条是 M3b 起核的直接输入，缺一个 CPU 起不来时必须现在就叫。
    let ids_ok = m.ids_overflow == 0 && m.n_ids == m.cpu_enabled && m.lapic_ids[..m.n_ids].iter().all(|&id| id < 255);
    crate::log_info!(
        "acpi madt: lapic_ok={} ids_ok={} pcat_compat={} cpu_total={} cpu_enabled={} online_capable={} ioapics={} overrides={} skipped={}",
        lapic_ok, ids_ok, m.pcat_compat, m.cpu_total, m.cpu_enabled, m.cpu_online_capable, m.n_ioapic, m.n_overrides, m.skipped_entries
    );
    lapic_ok && ids_ok && m.cpu_enabled >= 1 && m.cpu_total >= m.cpu_enabled && m.n_ioapic >= 1 && m.skipped_entries == 0
}
ktest!(KT_ACPI_MADT, t_acpi_madt_shape);

/// FADT / MCFG / IOMMU 表的形状。MCFG 是 M5 PCIe ECAM 的入口，缺它就要在 M2 说出来，
/// 不能等到 M5 才发现"没有 ECAM 地址"。
fn t_acpi_fadt_and_mcfg() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let fadt_ok = s.fadt.map_or(false, |f| f.revision >= 2 && f.length >= 36 && f.boot_arch.is_some());
    let mcfg_ok = s.mcfg_base.map_or(false, |b| b & (1024 * 1024 - 1) == 0 && b != 0)
        && s.mcfg_bus_start.map_or(false, |b| s.mcfg_bus_end.map_or(false, |e| b <= e));
    let iommu_ok = s.dmar_host_address_width.map_or(true, |w| (39..=57).contains(&w));
    crate::log_info!("acpi shapes: fadt_ok={} mcfg_ok={} dmar_haw={:?} ivrs={} iommu_ok={}", fadt_ok, mcfg_ok, s.dmar_host_address_width, s.ivrs_present, iommu_ok);
    fadt_ok && mcfg_ok && iommu_ok
}
ktest!(KT_ACPI_SHAPES, t_acpi_fadt_and_mcfg);

/// ADR-014 的第一条待核实项**用实测关闭**：limine 的 MP 响应与 MADT 是两台独立仪器，
/// 它们对"这台机器有几个 CPU、LAPIC id 是多少"必须给出相容的答案。
/// 顺带验协议那句"首次交给 BSP 时 goto_address 保证为 NULL"——释放 AP 是一次原子发布，
/// 前提就是那个字段初始为空；不成立就不能盲目释放。
fn t_mp_agrees_with_madt() -> bool {
    let Some(m) = mp_snapshot() else {
        crate::log_fatal!("mp: no response, ADR-014 的这条没法在本机构闭上");
        return false;
    };
    let Some(s) = acpi::summary() else { return false };
    let Some(md) = s.madt else { return false };
    let n = core::cmp::min(m.n, md.n_ids);
    // 每个 limine 报的 lapic_id 都要在 MADT 的使能清单里出现
    let mut subset = m.overflow == 0 && m.n == m.cpu_count;
    for i in 0..m.n {
        if !md.lapic_ids[..md.n_ids].contains(&m.lapic_ids[i]) {
            subset = false;
        }
    }
    let bsp_listed = md.lapic_ids[..md.n_ids].contains(&m.bsp_lapic_id);
    crate::log_info!(
        "mp vs madt: mp_cpus={} madt_enabled={} overlap={} bsp_in_madt={} all_goto_null={} x2apic={} processor_id[0]={}",
        m.cpu_count, md.cpu_enabled, n, bsp_listed, m.all_goto_null, m.x2apic_enabled, m.processor_ids[0]
    );
    // cpu_count 与 MADT 使能数相等：本机 QEMU 上两者都是 4。真机上如果固件
    // 禁用了某个核，这条会红——那时改的是**判定依据**（子集关系），不是把断言删掉。
    m.all_goto_null && subset && bsp_listed && m.cpu_count == md.cpu_enabled
}
ktest!(KT_MP_VS_MADT, t_mp_agrees_with_madt);

/// **合成 MADT**：偏移纪律的唯一可靠尺子。
///
/// 为什么必须用合成表：本机 QEMU 的 type-0 条目里 `ACPI processor id`(+2) 与
/// `APIC id`(+3) 恰好都是 0..3，取错偏移**在这台机器上读不出任何差别**——
/// 上一版就取的 +2，跨仪器对账照样全绿。真机上两者可以完全不同，那时才炸就太晚了。
/// 这里造一张两个核、两组 id 故意不同的表，再验 GSI 映射与畸形表的行为。
fn t_madt_offsets_synthetic() -> bool {
    // 36 字节表头 + lapic_base(4) + flags(4) = 44 起是条目
    let mut b = [0u8; 44 + 8 * 3 + 12 + 10]; // 表头 + 三条 CPU 条目 + 一个 I/O APIC + 一条覆盖
    let total = b.len() as u32;
    b[..4].copy_from_slice(b"APIC");
    b[4..8].copy_from_slice(&total.to_le_bytes());
    b[36..40].copy_from_slice(&0xFEE0_0000u32.to_le_bytes());
    b[40..44].copy_from_slice(&1u32.to_le_bytes()); // PCAT_COMPAT
    // 核 A：ACPI id=5, APIC id=1, enabled
    b[44] = 0; b[45] = 8; b[46] = 5; b[47] = 1; b[48..52].copy_from_slice(&1u32.to_le_bytes());
    // 核 B：ACPI id=6, APIC id=2, enabled；再加一条**被禁用**的核 C（ACPI 7 / APIC 3）
    b[52] = 0; b[53] = 8; b[54] = 6; b[55] = 2; b[56..60].copy_from_slice(&1u32.to_le_bytes());
    b[60] = 0; b[61] = 8; b[62] = 7; b[63] = 3; b[64..68].copy_from_slice(&0u32.to_le_bytes());
    // I/O APIC 0：GSI base 0，地址 0xFEC00000
    b[68] = 1; b[69] = 12; b[70] = 0; b[71] = 0;
    b[72..76].copy_from_slice(&0xFEC0_0000u32.to_le_bytes());
    b[76..80].copy_from_slice(&0u32.to_le_bytes());
    // Override：ISA IRQ0 -> GSI 2，极性/触发位都置上（q35 上IRQ0 就是这样被改写的）
    b[80] = 2; b[81] = 10; b[82] = 0; b[83] = 0;
    b[84..88].copy_from_slice(&2u32.to_le_bytes());
    b[88..90].copy_from_slice(&0xdu16.to_le_bytes());

    let m = acpi::madt_from_bytes(&b);
    // 关键三条：id 取自 +3 而不是 +2；被禁用的核不进清单；ISA0 经覆盖落到 GSI2
    let ids_ok = m.n_ids == 2 && m.lapic_ids[0] == 1 && m.lapic_ids[1] == 2
        && m.acpi_ids[0] == 5 && m.acpi_ids[1] == 6;
    let counts_ok = m.cpu_total == 3 && m.cpu_enabled == 2 && m.ids_overflow == 0 && m.skipped_entries == 0;
    let gsi0 = acpi::gsi_for(&m, 0) == 2;
    let gsi5 = acpi::gsi_for(&m, 5) == 5; // 没有覆盖的 ISA 走 1:1
    let route = acpi::ioapic_for(&m, 2) == Some((0, 2));
    let no_route = acpi::ioapic_for(&m, 40).is_none(); // 不许"就近塞给第一个 APIC"
    // 畸形表：长度不足 44 必须被标 truncated，且不能报出漂亮的 CPU 数
    let bad = acpi::madt_from_bytes(&b[..30]);
    crate::log_info!(
        "synthetic madt: ids_ok={} counts_ok={} gsi0={} gsi5={} route={:?} out_of_range_none={} bad_truncated={} bad_cpus={}",
        ids_ok, counts_ok, gsi0, gsi5, acpi::ioapic_for(&m, 2), no_route, bad.truncated, bad.cpu_total
    );
    ids_ok && counts_ok && gsi0 && gsi5 && route && no_route && bad.truncated && bad.cpu_total == 0
}
ktest!(KT_MADT_SYNTH, t_madt_offsets_synthetic);

// ---------------------------------------------------------------- M3a：中断

/// 交接状态是不是协议说的那样：逐条**读回来**，不引用文档当结论。
fn t_apic_handoff_state() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    // 两个用例都要用，而表的枚举顺序不由源码顺序决定，所以 init 必须可重复调用：
    // get_or_init 已建好就复用同一份状态，不会多占一个设备页 VA。
    let st = match apic::get_or_init(&m) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("apic::init failed: {:?}", e);
            return false;
        }
    };
    crate::log_info!(
        "apic handoff: id={} version={:#x} max_lvt={} svr={:#x} was_enabled={} ioapic_id={} gsi_base={} irt={} timer gsi={} rte={} vec={}",
        st.id, st.version, st.max_lvt, st.svr, st.svr_was_enabled, st.ioapic_id, st.gsi_base, st.irt_entries, st.timer_gsi, st.timer_rte, st.timer_vector
    );
    // LAPIC id 必须与 MP 响应给的 BSP id 一致，且出现在 MADT 的使能清单里：
    // 这是第三台仪器（硬件寄存器本身）对上前两台。
    let Some(mp) = mp_snapshot() else { return false };
    let id_matches = st.id == mp.bsp_lapic_id && m.lapic_ids[..m.n_ids].contains(&st.id);
    let svr_ok = st.svr & 0x100 != 0 && (st.svr & 0xff) == 0xff;
    let shape_ok = st.irt_entries >= 16 && st.max_lvt >= 4 && st.version != 0;
    id_matches && svr_ok && shape_ok
}
ktest!(KT_APIC_HANDOFF, t_apic_handoff_state);

/// 真实定时器中断：开 IF 的窗口里必须**周期性**收到，且 spurious / 意外向量为 0。
/// 分两段采样，是因为"来过一次"和"在走"是两回事——EOI 漏写就是前者：第一条之后
/// ISR 位一直挂着，中断再也不来，而单次采样看不出任何毛病。
fn t_timer_ticks_recur() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    let st = match apic::get_or_init(&m) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("timer test: apic::init failed: {:?}", e);
            return false;
        }
    };
    if apic::timer_start().is_err() {
        crate::log_fatal!("timer test: 打不开定时器中断");
        return false;
    }
    let before = apic::counts();
    let c0 = apic::ticks();
    // 基线必须是**相对的**：`apic::ticks()` 是全局累计值，前面跑过的抢占用例
    // 已经把它推到 9，用绝对数 2 判断"等到两次 tick"就永远立刻成立（实测踩过：
    // 窗口一次都没等，t1==c0，用例红）。表的枚举顺序不由源码顺序决定，
    // 所以每条用例都只能看自己开始之后的增量。
    //
    // 三段窗口的长度一律按 cycles 给，不再按轮数：轮数值多少时间是宿主机的函数，
    // 同一颗 QEMU 10.2.1 只换 `-accel`，kvm 档 400 轮连两个 tick 都攒不齐（第一轮
    // 实测只走了 1 个），tcg 档 318 轮就攒齐了——于是这条判据测的是宿主机，不是中断。
    // 游标：窗口前后各写一格 RTC 用户 RAM 并读回。宿主机拿这两个游标把 trace 里的
    // `vector 32` 投递切进这一段——simple trace 不带时间戳，没有游标就只知道全跑投了几发。
    let mk0 = apic::pit_mark();
    let w1 = apic::wait_ticks(c0, 2, clock::window_cycles(2));
    let mk1 = apic::pit_mark();
    let t1 = apic::ticks();
    // 窗口已关（with_interrupts 退出时 cli）：此刻起计数必须冻住。
    // 这一段用 wait_tick_count 而不是固定轮数——它的长度必须够一个 tick 周期，
    // 否则"IF 真开着也测不出来"（原先 20 轮只值 tick 周期的八分之一）。
    let w_idle = apic::wait_tick_count(clock::window_cycles(1));
    let t_after_cli = apic::ticks();
    // 关 IF 那一段里 PIT 的边沿没有消失，只是被挡在 IRR 上。重新开中断必须把它们交出来——
    // 这一格证的是"挡住"而不是"丢掉"。三段判据原本没有这一条，"计数冻住"和"再开还能收到"
    // 就混成了同一件事。
    let w_drain = apic::wait_ticks(t_after_cli, 1, clock::window_cycles(1));
    let t_drained = apic::ticks();
    // 第三段从**排空之后**起算，数的必须是新到的两个 tick。不排空就会被攒下的 backlog
    // 当场填满（实测：那一段 2 个 tick 只花 10,363,532 cycles，而第一段同样 2 个花
    // 68,040,996——同一个量两次读数差 6.6 倍，说明其中一次没在测它声称的东西）。
    let mk2 = apic::pit_mark();
    let w2 = apic::wait_ticks(t_drained, 2, clock::window_cycles(2));
    let mk3 = apic::pit_mark();
    let t2 = apic::ticks();
    // 四格游标单独打一行：宿主机按游标的**先后**把 trace 切成段（simple trace 不带时间戳），
    // 所以这四个数是段边界本身，读数出格（None）就等于证人不在场。
    crate::log_info!("timer 游标: 段1={:?}..{:?} 段2={:?}..{:?}（PIT latch 计数，None=出格）",
        mk0, mk1, mk2, mk3);
    let _ = st;
    apic::timer_stop().ok();
    let after = apic::counts();
    crate::log_info!(
        "timer: ticks {} -> {} (第一段 {} ticks cycles={} 轮数={} 游标={:?}..{:?}) ; after_cli={} (关IF 空转 {} ticks cycles={} 轮数={}) ; 排空={} (+{} cycles={}) ; second_window={} (第二段 {} ticks cycles={} 轮数={})",
        c0, t1, w1.ticks, w1.cycles, w1.rounds, mk0, mk1, t_after_cli, w_idle.ticks, w_idle.cycles, w_idle.rounds,
        t_drained, w_drain.ticks, w_drain.cycles, t2, w2.ticks, w2.cycles, w2.rounds
    );
    crate::log_info!(
        "timer counters: eois={} spurious={} unexpected={:?} irq[0]={}",
        after.eois - before.eois, after.spurious - before.spurious, after.unexpected - before.unexpected, after.irq[0]
    );
    // 四段判据：开着 IF 的窗口里确实在走；关 IF 后**不再增长**（IF 真的管住了这条线）；
    // 挡下的那批重新开中断要交出来（挡住≠丢掉）；排空之后还要能再收到新鲜的两个。
    // 加上没有意外向量、没有 spurious，且每个进来的中断都写过一次 EOI。
    let recurring = w1.ticks >= 2;
    let if_gates = t_after_cli == t1 && w_idle.ticks == 0;
    let drained = w_drain.ticks >= 1;
    let again = w2.ticks >= 2;
    let clean = after.spurious == before.spurious && after.unexpected == before.unexpected;
    let eoi_per_irq = after.eois - before.eois >= (t2 - c0);
    // 两台仪器必须数到同一个数：asm 出口记账的样本数 == Rust 侧各类中断计数之和。
    // 不相等就是有一类向量绕过了记账（或者被记了两次），那 P5 的每个数字都不可信。
    let p5 = trap::p5_irq_stats();
    let cc = apic::counts();
    let rust_total: usize = cc.irq.iter().sum::<usize>() + cc.unexpected + cc.spurious;
    // 对齐式子现在写全了：P5 的样本 == 驱动数到的外部中断 + 那些**驱动刻意不数**的
    // 非 ISA 向量（本地 APIC 定时器 0xF1 是第一条）。只写"两边相等"的话，多出一个
    // 非 IRQ 样本只会让它变红且不告诉你差哪一类；写全之后它红得明白，
    // 并且逼迫"新增一类会进 P5 的向量"必须在这里显式表态。
    let non_irq = trap::p5_non_irq();
    // **逐向量比对**，不是只比总数：总数相等可以藏住"IRQ0 多一个、IRQ1 少一个"，
    // 而这一轮要查的正是一个样本的来路（`asm=47 / rust=46`、非 ISA 桶 = 0 ⇒
    // 差的那一个落在 32..47 里面，总数判据到此已经给不出更多信息了）。
    let hist = trap::p5_hist_of(crate::arch::x86_64::cpu::BSP_SLOT);
    let mut hist_bad = 0usize;
    let mut first_diff = "";
    for i in 0..hist.len() {
        if hist[i] != cc.irq[i] as u64 {
            hist_bad += 1;
            if first_diff.is_empty() {
                first_diff = "见下行";
                crate::log_fatal!(
                    "p5 逐向量不一致 vec={}：P5样本={} 驱动计数={}",
                    trap::VEC_IRQ_BASE + i, hist[i], cc.irq[i]
                );
            }
        }
    }
    // 逐桶相等 + "P5 总数 == 各桶之和 + 非 ISA 桶"（后者是**自洽检查**：
    // 它抓的是"有一次进桩没进任何桶"，那种漏法逐桶比对看不出来）。
    let bucketed: u64 = hist.iter().sum::<u64>() + non_irq;
    let instruments_agree =
        hist_bad == 0 && p5.faults as usize == rust_total && bucketed == p5.faults;
    crate::log_info!(
        "timer 判据逐项: recurring={} drained={} again={} if_gates={} clean={} eoi_per_irq={} (eoi_delta={} ticks_delta={}) instruments_agree={}",
        recurring, drained, again, if_gates, clean, eoi_per_irq, after.eois - before.eois, t2 - c0, instruments_agree
    );
    crate::log_info!(
        "p5 cross-check: asm_samples={} rust_samples={} 非ISA样本={} 入桶合计={} 不一致桶={}({}) agree={}",
        p5.faults, rust_total, non_irq, bucketed, hist_bad, first_diff, instruments_agree
    );
    crate::log_info!(
        "p5 hist: P5={:?} 驱动={:?}",
        hist,
        &cc.irq[..hist.len()]
    );
    // 这个数只能叫**窗口均值**，不能叫周期：窗口里第一个间隔可能不完整，均值必然是周期的
    // 下界（实测 2 ticks / 47,831,965 cycles ⇒ 均值 23.9M，而标定给的真周期是 33.3M）。
    // 原先这里更糟——拿第二段的 cycles 除**四段合计**的 tick 数，印出来 14.9M cycles/tick
    // 而同一跑标定是 34.7M，差 2.3 倍正好是多算进去的那一半 tick 数；那个数不是"偏保守的
    // 估计"，是除错了（BACKLOG 56 那一行按它反推过 1.44 GHz，已就地作废）。
    let dt = t2 - c0;
    let mean = if w2.ticks > 0 { w2.cycles / w2.ticks } else { 0 };
    crate::log_info!(
        "timer: 四段合计 {} ticks / {} cycles ⇒ 第二段窗口均值 {} cycles/tick（均值的第一个间隔可能不完整，它是周期的**下界**不是周期）；ISR 自己量的相邻间隔 last={} max={}（第二段窗口：{} ticks / {} cycles）",
        dt, w1.cycles + w_idle.cycles + w_drain.cycles + w2.cycles, mean,
        apic::tick_delta_cycles(), apic::tick_delta_max_cycles(), w2.ticks, w2.cycles
    );
    recurring && drained && again && if_gates && clean && eoi_per_irq && instruments_agree
}
ktest!(KT_TIMER_TICKS, t_timer_ticks_recur);

/// §6.5/§7.1 的中断上下文分配禁令**有没有机制**。
/// 本用例自己再开一次窗口，不依赖表里谁先跑（枚举顺序由链接顺序决定，不由源码决定）。
/// 正常构建必须 `tries == 0`；`fault-alloc-in-irq` 构建必须让它变成非 0——
/// 那条注入构建就是这把尺子的"已知能坏"样本。
fn t_no_alloc_in_isr() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    let st = match apic::get_or_init(&m) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("isr-alloc test: apic::init failed: {:?}", e);
            return false;
        }
    };
    let t0 = apic::ticks();
    let tries0 = apic::irq_alloc_tries();
    if apic::timer_start().is_err() {
        crate::log_fatal!("isr-alloc test: 打不开定时器中断");
        return false;
    }
    // 窗口长度按 cycles 给（同一个理由：轮数是宿主机的函数）。这里只要 1 个 tick，
    // 因为判据看的是"ISR 里发生过一次分配尝试没有"，多等只是让变异样本更难对齐。
    let w = apic::wait_ticks(t0, 1, clock::window_cycles(1));
    let _ = st;
    apic::timer_stop().ok();
    let tries = apic::irq_alloc_tries() - tries0;
    crate::log_info!(
        "isr-alloc guard: ticks_in_window={} alloc_attempts_in_isr={} (窗口={} cycles 轮数={})",
        w.ticks, tries, w.cycles, w.rounds
    );
    w.ticks >= 1 && tries == 0
}
ktest!(KT_ISR_ALLOC_GUARD, t_no_alloc_in_isr);

/// 时钟标定：用 PIT 的已知 tick 周期反推 TSC 频率，并把"换算必须自洽"当成判据。
/// 本用例自己开窗口取样本，不依赖表里谁先跑。
fn t_clock_calibrated_by_pit() -> bool {
    let Some(cal) = calibrate_clock_once() else { return false };
    let tick_us = clock::micros(cal.tick_period_cycles);
    let linear = clock::micros_of_two_ticks_is_double(cal.tick_period_cycles);
    // 第一格要说清楚它挡什么：`micros(period)` 与 `tsc_hz` 是同一个 period 换两次单位，
    // 所以 10 ms 这个读数**按构造**就落在区间里——它挡的是定点乘除把数量级写反
    // （写反就读成 10 µs 或 10^7 µs），不是"频率量出来正好 10 ms"。真正的频率对不对
    // 由下面那条跨仪器等式与宿主机的 `tsc: Detected ...` 对表来管。
    let unit_ok = tick_us.is_some_and(|v| (9_000..=11_000).contains(&v)) && linear;
    // 两把尺子数的是同一条事件流：窗口里数到 s 个 tick，ISR 就该记到 s-1 段相邻间隔。
    // 差一段就是"有一次 tick 被数了两次"或"有一间隔没记"，那 tsc_hz 直接不可信。
    let cross = cal.samples >= 2 && cal.interval_n + 1 == cal.samples;
    crate::log_info!(
        "clock 判据: 单位自洽={} 跨仪器等式={}（samples={} interval_n={} interval_mean={} tsc_hz={}）",
        unit_ok, cross, cal.samples, cal.interval_n, cal.interval_mean, cal.tsc_hz
    );
    unit_ok && cross
}
ktest!(KT_CLOCK, t_clock_calibrated_by_pit);

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


/// 继承状态自证：传统 PIC 必须仍是全屏蔽（协议这么保证，但读回来才算实测）。
/// 不成立就意味着同一条 IRQ 可能同时从 8259 与 I/O APIC 各来一次，
/// 典型现象是 spurious IRQ7 —— 那种故障最难归因。
fn t_pic_still_masked() -> bool {
    let (m, s) = apic::pic_imr();
    crate::log_info!("pic imr readback: master={:#02x} slave={:#02x} (want 0xff/0xff)", m, s);
    m == 0xff && s == 0xff
}
ktest!(KT_PIC_MASKED, t_pic_still_masked);

/// 工作任务：数自己的圈数，收工时把自己标 Done。
fn sched_worker() -> ! {
    let me = sched::current_id();
    while sched::should_run() {
        sched::WORK[me].fetch_add(1, Ordering::Relaxed);
        tsc::spin(3_000);
    }
    sched::finish_current();
    loop {
        tsc::spin(3_000);
    }
}

/// **不收工**的工作任务。给"需要在别人收工之后再被调度两次"的用例用。
///
/// 为什么要有第二条：`RUN` 是全局的收工标志，`t_preempt_round_robin` 跑过之后它就是 false 了，
/// 而 `.ktests` 的枚举顺序由链接顺序决定——于是同一份 `sched_worker` 在有的顺序下
/// 一进门就 Done、runs 永远停在 1。用例不能靠"我恰好排在谁后面"来拿到样本，
/// 所以这里要一个不看 `RUN` 的入口。代价：这一槽会一直占着队列，
/// 后面的轮转用例因此多一个可调度任务（无害，它只数自己的圈）。
fn sched_worker_forever() -> ! {
    let me = sched::current_id();
    loop {
        sched::WORK[me].fetch_add(1, Ordering::Relaxed);
        tsc::spin(3_000);
    }
}

/// 时钟抢占的轮转：两个任务 + 启动上下文必须**都**推进过，且切换次数、
/// 每个任务的 runs 都要非零。只证明"能进中断"不够——必须证明
/// "被换下去的任务后来又被换回来并继续跑"，否则轮转是假的。
fn t_preempt_round_robin() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("sched: APIC 起不来，抢占测不了");
        return false;
    }
    sched::init_boot_task();
    sched::start_workers();
    if sched::spawn(sched_worker).is_err() || sched::spawn(sched_worker).is_err() {
        crate::log_fatal!("sched: spawn 失败");
        return false;
    }
    let (sw0, tk0, _) = sched::stats();
    let boot0 = sched::WORK[0].load(Ordering::Relaxed);
    apic::timer_start().ok();
    // 第一段窗口。原先整个测试只有一段，因为分成两段时**第二段一条 tick 都收不到**，
    // 现场是 `sw=6 ticks=6 irr0=0 isr0=0 svr=0x1ff rte2 未屏蔽` —— LAPIC 使能、EOI 干净、
    // 表项没关，说明请求根本没送到 CPU：第一段出口那句 `cli` 是在"当时持有 CPU 的那个上下文"
    // 里执行的，而被抢占过的任务恢复时又带回自己保存的 rflags(IF=1)。也就是说 IF 的归属没定。
    // ADR-021 把这条定成"**IF 属于 CPU**"，所以下面必须再开第二段：
    // 那不是补充测试，是那条决定的唯一故障复现证据——机制没生效时这里就是 0 个 tick。
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        // 目标切换次数从 6 提到 24：P1 的 min 在样本只有 9~11 个时本身抖得厉害，
        // 多采样才让"注入几千周期"这件事判得出来（§12.4.1 规则 3 要求先证明尺子能分辨）。
        while sched::stats().0 < sw0 + 24 && tsc::now() - t0 < 900_000_000 {
            sched::WORK[0].fetch_add(1, Ordering::Relaxed);
            tsc::spin(20_000);
            #[cfg(feature = "trace-switch")]
            if sched::WORK[0].load(Ordering::Relaxed) % 30 == 0 {
                let (sw, tk, act) = sched::stats();
                crate::log_info!("loop1 poll: sw={} ticks={} active={} cur={} lapic_irr0={:#x}", sw, tk, act, sched::current_id(), apic::lapic_debug().0);
            }
        }
        sched::stop_workers();
        // 收工标志要真的落到 Done 状态上：工人得再被调度到一次才会去检查它
        let t1 = tsc::now();
        while (sched::state_of(1) != sched::TaskState::Done || sched::state_of(2) != sched::TaskState::Done)
            && tsc::now() - t1 < 400_000_000
        {
            sched::WORK[0].fetch_add(1, Ordering::Relaxed);
            tsc::spin(20_000);
        }
        // 关中断必须由开窗口的上下文来做
        let back = sched::wait_for_boot_task(400_000_000);
        sched::WORK[0].fetch_add(if back { 100 } else { 1 }, Ordering::Relaxed);
    });
    apic::timer_stop().ok();
    // ---- 第二段窗口（ADR-021 的故障复现位置）
    // 此刻所有任务都已经 Done、没有新的抢占发生，被测的只有一件事：**这个 CPU 还能不能收到 tick**。
    // IF 的归属没定时，这里观测到的增量是 0；归属定成"属于 CPU"之后，
    // 换入的上下文带的 IF 由窗口状态供，第二段窗口就必然收得到。
    apic::timer_start().ok();
    let tick_a = apic::ticks();
    // 这一段本来就是按 cycles 封的界（400_000_000），换成同一个推导式上界，
    // 免得"这一格该给多少"在文件里有两本账。
    let w_pre = apic::wait_ticks(tick_a, 2, clock::window_cycles(2));
    let tick_b = apic::ticks();
    apic::timer_stop().ok();
    let boot1 = sched::WORK[0].load(Ordering::Relaxed);
    let (sw1, tk1, active) = sched::stats();
    let (n, mean, min, max) = sched::p1_stats();
    crate::log_info!(
        "preempt: switches {} -> {} (ticks {} -> {}), work boot={} w1={} w2={}, active_left={}, runs1={} runs2={}, state1={:?} state2={:?}",
        sw0, sw1, tk0, tk1, boot1 - boot0,
        sched::WORK[1].load(Ordering::Relaxed), sched::WORK[2].load(Ordering::Relaxed),
        active, sched::runs_of(1), sched::runs_of(2),
        sched::state_of(1), sched::state_of(2)
    );
    crate::log_info!("p1 switch: samples={} mean={} min={} max={} cycles (excludes iretq and the new task's first instruction)", n, mean, min, max);
    let rotated = sw1 >= sw0 + 24;
    let all_worked = boot1 > boot0
        && sched::WORK[1].load(Ordering::Relaxed) > 0
        && sched::WORK[2].load(Ordering::Relaxed) > 0;
    let resumed = sched::runs_of(1) >= 1 && sched::runs_of(2) >= 1;
    let p1_sane = n > 0 && min <= mean && mean <= max && mean > 0;
    let second_window = tick_b >= tick_a + 2;
    crate::log_info!(
        "preempt: 第二段窗口 ticks {} -> {} (收到 {} cycles={} 轮数={}) ; if_loads closed/open={}/{}",
        tick_a, tick_b, w_pre.ticks, w_pre.cycles, w_pre.rounds, sched::if_loads().0, sched::if_loads().1
    );
    rotated && all_worked && resumed && p1_sane && second_window
}
ktest!(KT_PREEMPT, t_preempt_round_robin);

/// 任务栈的 guard page（§6.4 从 V1.0 就承诺、M2 之后才具备实现条件的那条）。
/// 栈底那一页必须**未映射**且访问它就故障，栈内第一页必须已映射且不故障——
/// 两条一起测，否则"访问 guard 故障"可能只是因为整段都没映射。
fn t_task_stack_guard() -> bool {
    let slot = match sched::spawn(sched_worker) {
        Ok(i) => i,
        Err(e) => {
            crate::log_fatal!("guard: spawn 失败 {:?}", e);
            return false;
        }
    };
    let Some((lo, _hi, guarded)) = sched::stack_bounds(slot) else {
        crate::log_fatal!("guard: 拿不到任务栈边界");
        return false;
    };
    let guard_va = lo - mm::PAGE as u64;
    let guard_unmapped = !mm::is_mapped(guard_va);
    let first_mapped = mm::is_mapped(lo);
    let guard_faults = trap::probe_page_fault(guard_va).is_some();
    let first_faults = trap::probe_page_fault(lo).is_some();
    crate::log_info!(
        "task stack guard: lo={:#x} guarded={} guard_unmapped={} guard_faults={} first_mapped={} first_faults={}",
        lo, guarded, guard_unmapped, guard_faults, first_mapped, first_faults
    );
    guarded && guard_unmapped && guard_faults && first_mapped && !first_faults
}
ktest!(KT_TASK_STACK_GUARD, t_task_stack_guard);

// ---------------------------------------------------------------- M3b：多核

/// AP 有没有真的被释放，并且各自把**本地**定时器跑起来了。
///
/// 三条判据都要成立，缺一不可：
/// 1. 释放数 == MP 报的非 BSP 核数（少了就是 ADR-022 说的降级，必须可见而不是被平均掉）；
/// 2. 每个登记槽位都 online + 自报到 + 自己读到过硬件 id；
/// 3. **复发性**：隔一段已知时间再数一次 tick，必须变大。第一次就非 0 不等于在走
///    （ADR-020 里 EOI 漏写就是这个形状：来过一次，之后再没有）。
fn t_ap_released_and_ticking() -> bool {
    let Some(mp) = mp_snapshot() else {
        crate::log_fatal!("smp: 没有 MP 响应，AP 起不来（这不是硬件故障，是启动信息缺失）");
        return false;
    };
    if let Err(e) = smp::bringup() {
        crate::log_fatal!("smp: bringup 失败 {:?}", e);
        return false;
    }
    let bsp = match apic::state() {
        Some(s) => s.id,
        None => return false,
    };
    // MP 里除 BSP 之外应当有几个 AP（含"超出容量没登记"的那部分，所以按 id 数不按槽位数）
    let expected = (0..mp.n).filter(|&i| mp.lapic_ids[i] != bsp).count();
    let released = smp::released_count();
    let refused = smp::refused_count();
    let hz = clock::hz().unwrap_or(0);
    let mut per_cpu = [0usize; cpu::MAX_CPUS];
    let mut all_ticked_before = true;
    for s in 0..cpu::MAX_CPUS {
        per_cpu[s] = apic::cpu_ticks(s);
        if cpu::is_registered(s) && s != cpu::BSP_SLOT && per_cpu[s] == 0 {
            all_ticked_before = false;
        }
    }
    // 等约 50 ms（BSP 不需要开自己的窗口：AP 的 IF 由它自己打开）
    if hz > 0 {
        let t0 = tsc::now();
        while tsc::now().wrapping_sub(t0) < hz / 20 {
            core::hint::spin_loop();
        }
    } else {
        tsc::spin(2_000_000);
    }
    let mut recurred = true;
    let mut online_aps = 0usize;
    for s in 1..cpu::MAX_CPUS {
        if !cpu::is_registered(s) {
            continue;
        }
        let now_ticks = apic::cpu_ticks(s);
        if now_ticks <= per_cpu[s] {
            recurred = false;
        }
        if cpu::is_online(s) && cpu::is_ready(s) && smp::ap_stage(s) >= 2 {
            online_aps += 1;
        }
    }
    let (exstack_failed, lapic_failed) = smp::ap_failures();
    // ISR 深度必须每个 CPU 都回到 0。残留的深度会让那个 CPU 上**每一次**堆分配
    // 都被 `refuse_if_isr` 拒掉（L3），现场是"只有那个核的用例红"，极难归因。
    let depth_stuck: usize =
        (0..cpu::MAX_CPUS).filter(|&s| cpu::is_registered(s) && apic::isr_depth(s) != 0).count();
    crate::log_info!(
        "smp: mp_cpus={} expected_ap={} released={} refused={} online_ap={} timer_failed={} id_mismatch={} ready_timeout={} isr_depth_stuck={}",
        mp.cpu_count, expected, released, refused, online_aps, smp::ap_timer_failures(),
        smp::ap_id_mismatches(), smp::ready_timeouts(), depth_stuck
    );
    crate::log_info!(
        "smp: bsp_lapic={} cpu_ticks={:?} ap_exstack_failed={} ap_lapic_failed={} ap_stages={:?} ap_timer_init={:?}",
        bsp, apic::cpu_ticks_all(), exstack_failed, lapic_failed,
        [smp::ap_stage(1), smp::ap_stage(2), smp::ap_stage(3), smp::ap_stage(4)],
        [smp::ap_timer_init(1), smp::ap_timer_init(2), smp::ap_timer_init(3), smp::ap_timer_init(4)]
    );
    // AP 定时器标定的现场（最后一次写者赢）：tmcct, spent, dt_cycles, counts_per_sec, initial
    crate::log_info!(
        "smp: ap timer_err={} cal_dbg[tmcct={:#x} spent={} dt_cycles={} counts_per_sec={} initial={:#x}]",
        smp::ap_timer_err_kind(),
        apic::cal_dbg()[0], apic::cal_dbg()[1], apic::cal_dbg()[2], apic::cal_dbg()[3], apic::cal_dbg()[4]
    );
    // 容量不足也要报红：把 8 核机器当 4 核机验证，等于没验证
    let capacity_ok = refused == 0 && released == expected;
    capacity_ok && all_ticked_before && recurred && online_aps == released && lapic_failed == 0
        && depth_stuck == 0
}
ktest!(KT_AP_TICKING, t_ap_released_and_ticking);

/// 三个来源的 CPU id 必须互相吻合：MP 响应、MADT 表、以及**每个 CPU 自己读回的 LAPIC 寄存器**。
/// 前两个都是"别人告诉我们的"，只有第三个是硬件当场说的；少一个来源，
/// "槽位分对了"这句话就只是自证（`t_mp_agrees_with_madt` 已经对过前两个）。
fn t_cpu_ids_agree() -> bool {
    // 每一个提前返回都要留一句话。这一条用例第一次跑就是这么静悄悄 false 掉的
    // （bringup 的前置没满足，见 `smp::bringup` 里补 apic::get_or_init 那段），
    // 日志里什么线索都没有——"量具不出数不等于出数为 0"，用例不解释为什么不算数更糟。
    let Some(mp) = mp_snapshot() else {
        crate::log_fatal!("cpu ids: 没有 MP 响应");
        return false;
    };
    let Some(s) = acpi::summary() else {
        crate::log_fatal!("cpu ids: ACPI 没解析出摘要");
        return false;
    };
    let Some(m) = s.madt else {
        crate::log_fatal!("cpu ids: 没有 MADT");
        return false;
    };
    if let Err(e) = smp::bringup() {
        crate::log_fatal!("cpu ids: bringup 失败 {:?}", e);
        return false;
    }
    let unmatched0 = cpu::unmatched_self_lookups();
    let mut mismatches = 0usize;
    let mut checked = 0usize;
    for slot in 0..cpu::MAX_CPUS {
        let Some(registered) = cpu::lapic_id_of(slot) else { continue };
        let Some(seen) = cpu::hw_id_seen(slot) else {
            crate::log_warn!("cpu ids: slot={} 还没上报过硬件 id", slot);
            mismatches += 1;
            continue;
        };
        // MADT 里必须也有这一条：否则我们释放的是一个表里不存在的核
        let in_madt = m.lapic_ids[..m.n_ids].contains(&registered);
        let in_mp = mp.lapic_ids[..mp.n].contains(&registered);
        if seen != registered || !in_madt || !in_mp {
            mismatches += 1;
            crate::log_fatal!(
                "cpu ids: slot={} 登记={:#x} 硬件读回={:#x} 在MADT={} 在MP={}",
                slot, registered, seen, in_madt, in_mp
            );
        }
        checked += 1;
    }
    let unmatched = cpu::unmatched_self_lookups() - unmatched0;
    crate::log_info!(
        "cpu ids: checked={} mismatches={} unmatched_self_lookups_delta={} (madt_ids={:?} mp_ids={:?})",
        checked, mismatches, unmatched, &m.lapic_ids[..m.n_ids], &mp.lapic_ids[..mp.n]
    );
    // 两个数都要 0：id 不一致 = 槽位表不可信；自查找落空 = 有人在没登记的情况下跑了别的 id
    mismatches == 0 && unmatched == 0 && checked >= 1
}
ktest!(KT_CPU_IDS, t_cpu_ids_agree);

/// ADR-021 的读数：IF 由 CPU 供，不由任务帧携带。
///
/// 这条用例的形状是**故意**的：先看一个新任务的合成帧里 IF 位是 0（`spawn` 写 0x2），
/// 再让它在开窗口的窗口里第一次被换入并至少被换下一次，然后读它**此刻存的帧**——
/// 那是硬件在它被抢占时压下来的现场，IF=1 就证明它当时真的带着开着的 IF 在跑。
/// 如果换入时没人改写这一位（旧行为），它会一直是 0，窗口里再也没有第二个 tick，
/// 整条用例直接挂不住——那正是 M3a 记录过的"合成帧写 0x2 就整机卡死"的故障形状。
fn t_if_belongs_to_cpu() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        return false;
    }
    let slot = match sched::spawn(sched_worker_forever) {
        Ok(i) => i,
        Err(e) => {
            crate::log_fatal!("if-rule: spawn 失败 {:?}", e);
            return false;
        }
    };
    let before = sched::frame_rflags_of(slot);
    let if_before = sched::frame_if_bit(slot).unwrap_or(true);
    sched::init_boot_task();
    apic::timer_start().ok();
    let (sw0, _) = sched::stats_of(cpu::BSP_SLOT);
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        // 要求这一槽被**换入过并且换下过**：runs>=2 之后它存的必然是自己的抢占现场
        while (sched::runs_of(slot) < 2 || sched::stats_of(cpu::BSP_SLOT).0 < sw0 + 4)
            && tsc::now() - t0 < 600_000_000
        {
            tsc::spin(20_000);
        }
        sched::stop_workers();
        let back = sched::wait_for_boot_task(400_000_000);
        if !back {
            crate::log_fatal!("if-rule: 启动上下文没能回到 CPU（窗口收场不了）");
        }
    });
    apic::timer_stop().ok();
    let after = sched::frame_rflags_of(slot);
    let if_after = sched::frame_if_bit(slot).unwrap_or(false);
    let runs = sched::runs_of(slot);
    let (loads_closed, loads_open) = sched::if_loads();
    crate::log_info!(
        "if-rule(ADR-021): slot={} runs={} frame_before={:?}(IF={}) frame_after={:?}(IF={}) loads_open={} loads_closed={}",
        slot, runs, before, if_before, after, if_after, loads_open, loads_closed
    );
    // 判据：换入前 IF=0（帧里带的）→ 换入后跑过 ≥2 次且它的现场里 IF=1（CPU 给的）。
    // `loads_closed` 今天**必然**是 0：所有换入都发生在开窗口的窗口之内，关着窗口换入
    // 这条分支没有触发源（既不能造 tick，又不能造没有 tick 的抢占）。这不是"测过了"，
    // 已在 BACKLOG 挂账，等 AP 接入调度器或加入主动让出时补。
    !if_before && runs >= 2 && if_after && loads_open > 0
}
ktest!(KT_IF_BELONGS_TO_CPU, t_if_belongs_to_cpu);

/// `if_patch` 两条分支的直接覆盖，以及 asm 偏移与 Rust 结构体的对账。
///
/// 为什么这条用例存在：ADR-021 的"关着窗口换入"分支今天**没有触发源**
/// （所有换入都发生在开窗口的窗口之内，见上一条用例里 `loads_closed=0` 那段说明）。
/// 写好了却没走过的代码不能算验证过，但也不该为了凑覆盖去伪造一次调度。
/// 解法是把那段位操作从 `context_load` 里拆成一个可调用的例程，用例走**同一条指令序列**：
/// 1. `TrapFrame::rflags` 的偏移必须等于 asm 里写死的 160 —— 这条接缝没有类型系统保护；
/// 2. 置位/清位只能动 bit9，其余 22 个字与 rflags 里其它位（这里是 bit63）都不许变。
///    第 2 条就是当年 `and qword ptr [rsp+160], 0xfffffdff` 那一类掩码/符号扩展错误会被抓住的形状。
fn t_if_patch_both_branches() -> bool {
    let off = {
        let f = core::mem::MaybeUninit::<trap::TrapFrame>::zeroed();
        let base = f.as_ptr() as u64;
        // SAFETY: 只取字段地址，不读未初始化的值（zeroed 的 MaybeUninit 每个字节都是 0）
        unsafe { core::ptr::addr_of!((*f.as_ptr()).rflags) as u64 - base }
    };
    let size_ok = core::mem::size_of::<trap::TrapFrame>() == 23 * 8;
    let mut words = [0u64; 23];
    for (i, w) in words.iter_mut().enumerate() {
        *w = 0x1000 + i as u64;
    }
    // bit63 置起来：清位那条分支如果写成 imm32 符号扩展错，这一位最容易先被抹掉
    words[20] = 0x8000_0000_0000_0002;
    // SAFETY: words 是本用例自己的 23 个 u64，if_patch 只写 [ptr+160] 这一格
    unsafe { sched::if_patch(words.as_mut_ptr() as u64, 1) };
    let opened = words[20];
    // SAFETY: 同上
    unsafe { sched::if_patch(words.as_mut_ptr() as u64, 0) };
    let closed = words[20];
    // 另外还要确认"置位"这条分支幂等，且不会顺手清掉别的位
    words[20] = 0x8000_0000_0000_0202;
    // SAFETY: 同上
    unsafe { sched::if_patch(words.as_mut_ptr() as u64, 1) };
    let idempotent = words[20];
    let untouched = words
        .iter()
        .enumerate()
        .all(|(i, &v)| i == 20 || v == 0x1000 + i as u64);
    crate::log_info!(
        "if_patch: rflags_off={} (asm 写死 160) size_ok={} opened={:#x} closed={:#x} idempotent={:#x} others_untouched={}",
        off, size_ok, opened, closed, idempotent, untouched
    );
    off == 160
        && size_ok
        && opened == 0x8000_0000_0000_0202
        && closed == 0x8000_0000_0000_0002
        && idempotent == 0x8000_0000_0000_0202
        && untouched
}
ktest!(KT_IF_PATCH, t_if_patch_both_branches);

/// 跨 CPU 抢同一把锁。这条用例的**全部价值**在于它自带对照组：
/// 同一个共享数据、同样的"读—磨—写"，无锁那一轮必须**丢数**，加锁那一轮必须**不丢**。
/// 如果无锁那轮也丢 0，说明两个 CPU 根本没撞上，那"锁挡住了竞争"这句话就没有证据——
/// 所以 `wait_events > 0` 和 `unlocked_lost > 0` 两条都是判据，不是装饰。
fn t_cross_cpu_lock_contention() -> bool {
    let o = match smp::contention_round() {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("contention: 测不成 {:?}", e);
            return false;
        }
    };
    let st = sync::stats();
    crate::log_info!(
        "contention: participants={} rounds_per_cpu={} unlocked_lost={} locked_lost={} wait_events={} wait_max={}",
        o.participants, o.rounds_per_cpu, o.unlocked_lost, o.locked_lost, o.wait_events, o.wait_max_cycles
    );
    crate::log_info!(
        "contention lockdep: acquires={} order_violations={} reentrant_hits={} ack_timeouts={}",
        st.acquires, st.order_violations, st.reentrant_hits, o.ack_timeouts
    );
    // 每 CPU 4000 次自增，丢数比例报出来才有可比性（全丢和丢 1 个是两件事）
    let total = o.participants as u64 * o.rounds_per_cpu;
    let loss_bps = if total > 0 { o.unlocked_lost * 10_000 / total } else { 0 };
    crate::log_info!(
        "contention: 无锁丢数 {} / {} = {} bp（这条数字是尺子能分辨的证据）",
        o.unlocked_lost, total, loss_bps
    );
    // 这里**不**停 AP：停机放在所有用例跑完之后（见 after_switch）。
    // 停在这里的话，链接顺序在后面的那条 AP 用例就会看到"tick 不再增长"，
    // 于是同一条用例在两种顺序下给出两种结论——那属于"只有跑的时候才知道顺序错了"的那类故障。
    o.unlocked_lost > 0 && o.locked_lost == 0 && o.wait_events > 0 && o.ack_timeouts == 0
        && st.order_violations == 0 && st.reentrant_hits == 0 && st.wait_timeouts == 0
}
ktest!(KT_CONTENTION, t_cross_cpu_lock_contention);

/// AP 入口 ABI：asm 按 `ApBoot` 的 +0/+8/+16 读三个 u64，而 `size_of` 的编译期断言
/// 只钉住总大小。这里再钉住**内容**：槽位号与登记一致、期望 id 与登记表一致、
/// 栈顶落在一条已映射的页上（它下面那一页是 guard，永远不该映射）。
/// 这条用例存在的理由：AP 的入口例程一旦拿错栈或拿错槽位，表现是三重故障或
/// 跑进别人的栈，两者都没有可读的错误信息。
fn t_ap_boot_abi() -> bool {
    if let Err(e) = smp::bringup() {
        crate::log_fatal!("smp: bringup 失败（本用例无法验证多核）{:?}", e);
        return false;
    }
    let mut checked = 0usize;
    let mut bad = 0usize;
    for slot in 1..cpu::MAX_CPUS {
        if !cpu::is_registered(slot) {
            continue;
        }
        let (top, got_slot, expect_id) = smp::ap_boot_layout(slot);
        let Some(registered) = cpu::lapic_id_of(slot) else { continue };
        let stack_page = top & !(mm::PAGE as u64 - 1);
        // guard 页在**这条栈的最低那一格**，不是"栈顶下面那一页"——后者仍然是映射着的栈
        let lo = smp::ap_stack_lo(slot);
        let guard_unmapped = lo != 0 && !mm::is_mapped(lo - mm::PAGE as u64);
        let first_mapped = lo != 0 && mm::is_mapped(lo);
        let top_mapped = top != 0 && mm::is_mapped(stack_page);
        if got_slot != slot as u64 || expect_id != registered as u64 || !top_mapped || !first_mapped || !guard_unmapped {
            bad += 1;
            crate::log_fatal!(
                "ap abi: slot={} 写入槽位={} 期望id={:#x} 登记id={:#x} top={:#x} lo={:#x} 栈顶页已映射={} 首映射页={} guard未映射={}",
                slot, got_slot, expect_id, registered, top, lo, top_mapped, first_mapped, guard_unmapped
            );
        }
        checked += 1;
    }
    crate::log_info!("ap abi: checked={} bad={} (size_of::<ApBoot>()={} size_of::<MpInfo>()={})",
        checked, bad, core::mem::size_of::<smp::ApBoot>(), core::mem::size_of::<limine::MpInfo>());
    checked >= 1 && bad == 0
}
ktest!(KT_AP_ABI, t_ap_boot_abi);

/// §6.4 里那句"所有内核栈头尾都有 guard page"的**异常栈**那一半。
/// 每个 CPU 都要过一遍：guard 未映射、访问它故障、栈内第一页已映射且不故障——
/// 四条一起测，否则"访问 guard 故障"可能只是因为整段都没映射（与任务栈那条同一把尺子）。
fn t_exception_stack_guard() -> bool {
    if let Err(e) = smp::bringup() {
        crate::log_fatal!("smp: bringup 失败（本用例无法验证多核）{:?}", e);
        return false;
    }
    let mut checked = 0usize;
    let mut bad = 0usize;
    for slot in 0..cpu::MAX_CPUS {
        let Some(si) = trap::ex_stack_info(slot) else {
            if slot != cpu::BSP_SLOT && cpu::is_registered(slot) {
                crate::log_fatal!("exstack: slot={} 登记了但没有换上带 guard 的异常栈", slot);
                bad += 1;
            }
            continue;
        };
        let guard_unmapped = !mm::is_mapped(si.guard_va);
        let first_mapped = mm::is_mapped(si.stack_lo);
        let guard_faults = trap::probe_page_fault(si.guard_va).is_some();
        let first_faults = trap::probe_page_fault(si.stack_lo).is_some();
        // ist1 必须落在这一段的最后一格，并且 16 字节对齐（IST 的硬件要求）
        let top_ok = si.top > si.stack_lo && si.top <= si.stack_hi && si.top & 0xf == 0;
        if !(guard_unmapped && first_mapped && guard_faults && !first_faults && top_ok) {
            bad += 1;
            crate::log_fatal!(
                "exstack: slot={} guard={:#x} lo={:#x} hi={:#x} ist1={:#x} guard_unmapped={} guard_faults={} first_mapped={} first_faults={} top_ok={}",
                slot, si.guard_va, si.stack_lo, si.stack_hi, si.top,
                guard_unmapped, guard_faults, first_mapped, first_faults, top_ok
            );
        }
        checked += 1;
    }
    crate::log_info!("exstack guard: checked={} bad={}", checked, bad);
    checked >= 1 && bad == 0
}
ktest!(KT_EXSTACK_GUARD, t_exception_stack_guard);

/// §6.6 的 TLB shootdown：解映射之前必须让**每个其它在线 CPU**清掉那一条 VA 并回执。
///
/// 这条用例测的是**协议**，不测"硬件里真的没有旧条目"：QEMU 的 TCG 会因为页表被写
/// 而自行失效相关条目，所以"没通知也能读对"在这台机器上永远成立。
/// 因此判据全部落在可数的东西上：请求次数 == 解掉的页数、每个在线 CPU 的 invlpg 与回执
/// 各自都增长、超时次数为 0、以及帧确实回到 PMM。
/// "没通知也能读对"这件事由 `fault-shootdown-noack` 反过来验：只把回执拿掉，
/// 请求方必须升 L4（判定矩阵第 9 行）。
fn t_tlb_shootdown() -> bool {
    if let Err(e) = smp::bringup() {
        crate::log_fatal!("shootdown: bringup 失败 {:?}", e);
        return false;
    }
    let online = cpu::online_count();
    if online < 2 {
        crate::log_fatal!("shootdown: 只有 {} 个在线 CPU，多核那半没法测", online);
        return false;
    }
    let before = mm::shootdown_stats();
    let free0 = mm::free_frames();
    // 映射 2 页、写一遍（确认这块页真的在用），然后 drop —— 归还 Mapping 会走
    // unmap_pages -> clear_leaf -> shootdown_others，每页一次 IPI 往返
    let win = match mm::alloc_va_range(2) {
        Some(v) => v,
        None => {
            crate::log_fatal!("shootdown: 拿不到 VA");
            return false;
        }
    };
    let frames = match mm::phys_alloc(1, mm::MOD_TEST) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("shootdown: 拿不到 2 连续帧 {:?}", e);
            return false;
        }
    };
    let m = match mm::map(win, frames, mm::PageFlags::RW) {
        Ok(m) => m,
        Err(e) => {
            crate::log_fatal!("shootdown: map 失败 {:?}", e);
            return false;
        }
    };
    // SAFETY: win 是刚映射的 2 页 RW，长度与 phys_alloc(1) 的 2 页一致
    unsafe { core::ptr::write_volatile(win.0 as *mut u64, 0x5a5a_5a5a_5a5a_5a5a) };
    let written = unsafe { core::ptr::read_volatile(win.0 as *const u64) };
    drop(m);
    let after = mm::shootdown_stats();
    let requests = after.requests - before.requests;
    let mut acked_all = true;
    for s in 0..cpu::MAX_CPUS {
        if s == cpu::BSP_SLOT || !cpu::is_online(s) {
            continue;
        }
        // 每个别的在线 CPU 都应当：invlpg 至少 2 次、回执至少比 BSP 自己那一份多
        if after.invlpg[s] - before.invlpg[s] < 2 || after.acks[s] - before.acks[s] < 2 {
            acked_all = false;
        }
    }
    let frames_back = mm::free_frames() >= free0; // 归还了 2 帧（别的用例也可能同时在动，只判不回退）
    crate::log_info!(
        "shootdown: online={} requests={} timeouts={} written={:#x} frames_back={} acks={:?} invlpg={:?}",
        online, requests, after.timeouts - before.timeouts, written, frames_back,
        after.acks, after.invlpg
    );
    requests == 2 && after.timeouts == before.timeouts && acked_all && written == 0x5a5a_5a5a_5a5a_5a5a && frames_back
}
ktest!(KT_SHOOTDOWN, t_tlb_shootdown);

/// 每 CPU 运行队列 + AP 真的在跑自己的调度器。三条判据各挡一种错法：
/// ①AP 自己换过人且它的工人跑过 ⇒ 挡"AP 只是活着但从没被调度"（那 per-CPU 队列就是摆设）；
/// ②每个跑调度的 CPU，其 `current` 必须归属它自己 ⇒ 挡"两个核选中同一个任务"（同一个帧被 iretq 两次）；
/// ③非空任务的 `on_cpu` 必须等于它所在的队列 ⇒ 挡 `gidx/cpu_of/slot_of` 这对新算术写错。
/// 顺带记 `ticks_of(ap)`：AP 的 tick 从这一段起走异常帧路径，所以 tick 数与 P5 样本数一起涨。
fn t_percpu_queues() -> bool {
    if let Err(e) = smp::bringup() {
        crate::log_fatal!("percpu sched: bringup 失败 {:?}", e);
        return false;
    }
    let deadline = 400_000_000;
    let mut checked_aps = 0usize;
    let mut switched_aps = 0usize;
    let mut worked_aps = 0usize;
    let mut bad_owner = 0usize;
    for ap in 1..cpu::MAX_CPUS {
        if !cpu::runs_sched(ap) {
            continue;
        }
        checked_aps += 1;
        let Some(task) = smp::ap_task_of(ap) else {
            bad_owner += 1; // 队列开闸了却没有工人任务：这条 CPU 只有一个上下文，换不了人
            continue;
        };
        // 等这条 CPU 至少换过两次人（AP 的 tick 目标周期 10 ms，两次换人约 20~30 ms）
        let t0 = tsc::now();
        while sched::stats_of(ap).0 < 2 && tsc::now().wrapping_sub(t0) < deadline {
            core::hint::spin_loop();
        }
        if sched::stats_of(ap).0 >= 2 {
            switched_aps += 1;
        }
        if sched::runs_of(task) >= 1 && sched::WORK[task].load(Ordering::Relaxed) > 0 {
            worked_aps += 1;
        }
        // 归属不变量：本 CPU 的 current 必须落在自己的队列里。
        // **不要求它是 Running** —— 这是一次跨核快照读，实测就会读到换人做到一半的样子
        // （`cpu1 的 current=6 归属=1 状态=Runnable`：那条 CPU 上 `preempt_point` 已经把
        // 空闲上下文降级成 Runnable，还没写 `current`）。所以跨核只能断言"归属对不对"，
        // "状态对不对"这条只在**自己读自己**的时候成立，见下面 BSP 那一条。
        let cur = sched::current_of(ap);
        if sched::cpu_of(cur) != ap || sched::state_of(cur) == sched::TaskState::Free {
            bad_owner += 1;
            crate::log_fatal!(
                "percpu sched: cpu{} 的 current={} 归属={} 状态={:?}",
                ap, cur, sched::cpu_of(cur), sched::state_of(cur)
            );
        }
    }
    // BSP 读自己的队列：这里可以要求 Running，因为没有别的可能并发改它
    {
        let cur = sched::current_of(cpu::BSP_SLOT);
        if sched::state_of(cur) != sched::TaskState::Running || sched::cpu_of(cur) != cpu::BSP_SLOT {
            bad_owner += 1;
            crate::log_fatal!(
                "percpu sched: bsp 的 current={} 状态={:?}（自读，应当是 Running 且归属 0）",
                cur, sched::state_of(cur)
            );
        }
    }
    // 所有 CPU 的队列都查一遍归属（含 BSP）
    let mut misfiled = 0usize;
    let mut nonempty = 0usize;
    for i in 0..sched::MAX_TASKS_TOTAL {
        if sched::state_of(i) == sched::TaskState::Free {
            continue;
        }
        nonempty += 1;
        if sched::on_cpu_of(i) != Some(sched::cpu_of(i)) {
            misfiled += 1;
            crate::log_fatal!("percpu sched: 任务 {} 的 on_cpu={:?} 与所在队列 {} 不一致", i, sched::on_cpu_of(i), sched::cpu_of(i));
        }
    }
    crate::log_info!(
        "percpu sched: aps_with_sched={} switched={} worked={} checked={} bad_owner={} misfiled={} nonempty={}",
        checked_aps, switched_aps, worked_aps, checked_aps, bad_owner, misfiled, nonempty
    );
    crate::log_info!(
        "percpu sched: ticks 每个 CPU ={:?} ; switches 每个 CPU ={:?}",
        [sched::ticks_of(0), sched::ticks_of(1), sched::ticks_of(2), sched::ticks_of(3)],
        [sched::stats_of(0).0, sched::stats_of(1).0, sched::stats_of(2).0, sched::stats_of(3).0]
    );
    checked_aps >= 1 && switched_aps == checked_aps && worked_aps == checked_aps
        && bad_owner == 0 && misfiled == 0 && nonempty >= 1
}
ktest!(KT_PERCPU_QUEUES, t_percpu_queues);

// ---------------------------------------------------------------- M4：用户态

/// M4-1 的用户态闭环：进得去、回得来、参数与返回穿得过去、越界只杀这个任务。
/// 它从红到绿拆出的五个缺陷（①–⑤）现场在 BACKLOG 的 M4-1 表里。
/// **本条用例的判据清单（0 / 0b / 0c / 1…6，以及每条各挡一类什么错法）已搬进手册 §12.3.2**；
/// 下面的编号与函数体顺序一致，改判据要同时改那张表。
fn t_user_roundtrip() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("user: APIC 起不来，跑不了时间片");
        return false;
    }
    if user::init().is_err() {
        crate::log_fatal!("user: 建用户镜像失败");
        return false;
    }
    // prog 要在**任何一次 iretq 之前**就读回来：判据 0/0b 靠它拿页号去量生效位。
    let Some(prog) = user::prog() else {
        crate::log_fatal!("user: init 返回了 Ok 但 prog() 读不回来");
        return false;
    };
    sched::init_boot_task();
    // **判据 0：段描述符自检（每台 CPU 都查），跑在任何一次 iretq 之前。**
    // 这条是 M4-1 那次 #GP 直接教出来的：选择子的值(0x1b/0x23)全对，而 GDT 里
    // 用户数据段漏了 S 位(bit4) ⇒ 那条目变成"系统描述符，类型 2 = LDT"，
    // 装 SS 就是非法段 ⇒ #GP；而 QEMU 把错误码的 RPL 两位抹掉，报成 0x18，
    // 现场读起来像"选择子写错了"，指不到真正错的那一位。选择子与描述符是两处独立事实，
    // 只验其一都会漏，所以这里两边都验，并且按**选择子推出来的下标**去查描述符
    //（下标写错与段属性写错都会被同一条判据抓到；而 0x23/0x1b 这两个值是 ADR-025
    // 里 STAR 隐式加 0x20/0x10 的前提，也必须钉住）。
    let (ui, ci) = (trap::udata_sel() >> 3, trap::ucode_sel() >> 3);
    let mut segs_ok = ui == 3 && ci == 4 && trap::udata_sel() & 3 == 3 && trap::ucode_sel() & 3 == 3;
    for slot in 0..crate::arch::x86_64::cpu::registered() {
        let (Some(d), Some(c)) = (trap::gdt_entry(slot, ui as usize), trap::gdt_entry(slot, ci as usize)) else {
            crate::log_fatal!("user: cpu{slot} 读不到 GDT 条目");
            segs_ok = false;
            break;
        };
        let (da, ca) = ((d >> 40) & 0xff, (c >> 40) & 0xff);
        let ok = (da >> 4) & 1 == 1          // S=1：是代码/数据段，不是系统描述符
            && (ca >> 4) & 1 == 1
            && (da >> 7) & 1 == 1            // P=1
            && (ca >> 7) & 1 == 1
            && (da >> 5) & 3 == 3            // DPL=3
            && (ca >> 5) & 3 == 3
            && (da & 0x8) == 0               // 数据段：type 的 E 位为 0
            && (da & 0x2) != 0               //        且可写
            && (ca & 0x8) != 0               // 代码段：可执行
            && (c >> 53) & 1 == 1            // L=1（64 位代码段）
            && (c >> 52) & 1 == 0;           // 而 long mode 下 D/B 必须为 0
        if !ok {
            crate::log_fatal!("user: cpu{slot} 段描述符不对 data={d:#x} code={c:#x}");
            segs_ok = false;
        }
    }
    crate::log_info!(
        "user: segs udata={:#x} ucode={:#x} idx=[{},{}] segs_ok={}",
        trap::udata_sel(), trap::ucode_sel(), ui, ci, segs_ok
    );
    if !segs_ok {
        return false;
    }
    // **判据 0b：页的"生效位"（W^X + SMEP/SMAP 的地基）**。
    // 这里量的是 `mm::effective_flags`（整条页表链逐级相与之后的结果），不是 `PageFlags`
    // 这个意图：M4-1 那次"映射成功但 ring3 一取指就 #PF"就是因为只验意图，
    // 而上级表项的 U/S=0 在叶子里根本看不见。
    // 三条都要成立，缺一不可：
    //   代码页 = 用户可达 + 可执行 + **不可写**；数据/栈页 = 用户可达 + 可写 + **不可执行**；
    //   内核页 = **不可**用户可达（这一条是上一条的对照组：
    //   映射用户页时会把 U/S=1 传到共享的上级表项，没有这条对照就分不清
    //   "放宽了一格"与"放宽了整条内核映射"）。
    let (Some(code), Some(data), Some(kern)) = (
        mm::effective_flags(prog.code_va),
        mm::effective_flags(prog.data_va),
        sched::stack_bounds(0).and_then(|(lo, _, _)| mm::effective_flags(lo)),
    ) else {
        crate::log_fatal!("user: 页表链读不回来（code/data/内核栈）");
        return false;
    };
    let wx_ok = code.user && code.executable && !code.writable
        && data.user && data.writable && !data.executable
        && !kern.user
        && code.levels >= 2 && data.levels >= 2;
    crate::log_info!(
        "user: eff code={:?} data={:?} kernel_stack={:?}",
        code, data, kern
    );
    if !wx_ok {
        crate::log_fatal!("user: 生效位不对（W^X 或 内核页用户可达）");
        return false;
    }
    sched::start_workers();
    user::clear_counters();
    let entry = prog.entry;
    let stop = prog.stack_top;
    // `OwnedSet::new()` 不是占位：手写镜像那三页是**测试脚手架**，两个任务共用同一套页，
    // 所以它们不属于任何一个任务（属于谁就该在谁结束时释放）。容器那条路径
    // （`t_elf_load_run`）才是"一次装载一份资源"，那份资源交给任务持有。
    let utask = match sched::spawn_user(entry, stop, sched::OwnedSet::new()) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("user: spawn_user 失败 {:?}", e);
            return false;
        }
    };
    // 两条用户任务的**内核栈顶**要在换入之前就记下来：TSS 那条判据比它晚，
    // 而被杀的那一条此刻可能已经被回收（`release_owned` 会把 `kstack_top` 清零），
    // 到时候读出来是 None —— 那不是"rsp0 装错了"，是量具在自己被测的那一瞬间之后才按下快门。
    let good_top = sched::kstack_top_of(utask);
    // "越界的那条"故意从**数据页**取指：这一页对 ring3 可达、可写、但不可执行，
    // 所以取指必然 #PF(err=0x15) —— 判据不依赖"我猜这条指令的第二个字节会解码成什么"。
    // （之前写成 `entry + 1`，实测那条字节串 `C7 C0 01 00 00 00` = `mov eax,1` 是**合法**
    // 指令，任务照常跑完三次调用，`kills` 读出 0：判据抓不到任何东西。）
    let bad = match sched::spawn_user(prog.data_va, stop, sched::OwnedSet::new()) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("user: 第二条（从数据页取指）任务建不起来 {:?}", e);
            return false;
        }
    };
    let bad_top = sched::kstack_top_of(bad);
    apic::timer_start().ok();
    // **换入之前**把两条用户任务的异常帧逐格读回来。这条打印不是装饰：
    // iretq 的字段没有类型系统保护，"写进去的值"与"CPU 读到的值"之间唯一的证人就是它。
    //（M4-1 第一次红的现场是 #GP(0x18)——那是"SS 选择子的 RPL 不是 3"的号码，
    // 而 `udata_sel()` 明明写的是 0x1b，所以必须看真内存里那一格是什么。）
    for (name, gi) in [("good", utask), ("bad", bad)] {
        let Some(f) = sched::task_frame(gi) else {
            crate::log_fatal!("user: {name} 任务没有帧地址");
            return false;
        };
        // SAFETY: f 是 spawn_user 刚写好的 23 格帧，落在它自己那条已映射的内核栈区间内
        //（`t_percpu_queues` 那条判据已经验过栈边界），这里只读不改。
        let w = unsafe {
            [
                core::ptr::read_volatile(f as *const u64),
                core::ptr::read_volatile((f + 144) as *const u64),
                core::ptr::read_volatile((f + 152) as *const u64),
                core::ptr::read_volatile((f + 160) as *const u64),
                core::ptr::read_volatile((f + 168) as *const u64),
                core::ptr::read_volatile((f + 176) as *const u64),
            ]
        };
        crate::log_info!(
            "user: {name} frame={f:#x} cr2={:#x} [rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} ss={:#x}]",
            w[0], w[1], w[2], w[3], w[4], w[5]
        );
    }
    // 两段窗口：先让好的那个跑完三次调用，再让坏的那个故障。
    // 分开是因为 kill 会把任务标 Done，同一个窗口里两个都要不到时间片就会互相干扰读数。
    for (i, focus) in [utask, bad].iter().enumerate() {
        let _ = focus;
        apic::with_interrupts(|| {
            let t0 = tsc::now();
            while tsc::now() - t0 < 120_000_000 && user::served() < 3 + (i as u64 * 0) {
                if i == 1 && user::kills() >= 1 {
                    break;
                }
                tsc::spin(20_000);
            }
            let back = sched::wait_for_boot_task(300_000_000);
            if !back {
                crate::log_fatal!("user: 窗口收不了场（启动上下文没回到 CPU）");
            }
        });
    }
    apic::timer_stop().ok();
    let slot0 = user::read_slot(user::SLOT_PING);
    let slot1 = user::read_slot(user::SLOT_ADD);
    let slot2 = user::read_slot(user::SLOT_UNKNOWN);
    // SMAP：不开窗口直接读用户页必须故障（probe_page_fault 返回 Some 表示"确实故障并恢复了"）
    let smap_blocks = user::probe_slot_without_window(user::SLOT_PING).is_some();
    // 探针登记表必须回到"没有待恢复"的状态：留着非 0 就是下一次无关故障的劫持目标
    //（M4-1 第一次红就是这么坏的：`user::init` 的 SMAP 写故障被上一次没故障的探针
    // 留下的 PF_RESUME 劫持，跳进探针尾巴上的 `ret`，内核带着 0x3a000 去取指）。
    let probes_clean = trap::probe_registers_clear();
    let stale_hits = trap::PF_STALE_HITS.load(core::sync::atomic::Ordering::Relaxed);
    crate::log_info!(
        "user: served={} unknown={} kills={} slots=[{:?},{:?},{:?}] smap_blocks_kernel_read={} utask_state={:?} bad_state={:?}",
        user::served(), user::unknown_nr(), user::kills(), slot0, slot1, slot2, smap_blocks,
        sched::state_of(utask), sched::state_of(bad)
    );
    crate::log_info!(
        "user: code={:#x} mapped={} data={:#x} stack={:#x} entry={:#x} tramp={:#x} pf_stale_hits={} probes_clean={}",
        prog.code_va, mm::is_mapped(prog.code_va), prog.data_va, prog.stack_va, prog.entry,
        user::trampoline(), stale_hits, probes_clean
    );
    // **判据 0c：TSS 的架构偏移**。这里读的是"按 Intel 那张表的位置"上的字节，
    // 不是按 Rust 声明的字段名——`#[repr(C, align(16))]` 会把 `rsp0` 挪到偏移 8，
    // 而 CPU 从偏移 4 取 8 个字节，于是换栈换到一个被截断的地址（M4-1 的三重故障）。
    // ist1 与 iomap_base 此刻就装好了；rsp0 只有在换入过用户任务之后才非 0，
    // 所以三种合法读数都接受：还没装(0)、两条用户任务各自的内核栈顶。
    let ex_top = trap::ex_stack_info(crate::arch::x86_64::cpu::BSP_SLOT).map_or(0, |i| i.top);
    let (rsp0_now, ist1_now, iomap_now) = trap::tss_offsets(crate::arch::x86_64::cpu::BSP_SLOT).unwrap_or((0, 0, 0));
    let tops = [good_top, bad_top];
    let tss_ok = ist1_now == ex_top
        && iomap_now == 104
        && (rsp0_now == 0 || tops.iter().any(|t| *t == Some(rsp0_now)));
    // `rsp0` 可能指向**已经被回收**的那条内核栈（被杀的任务换下去之后资源就还了）。
    // 这不构成"ring3 一陷入就踩已释放的页"：`rsp0` 只在 ring3→ring0 转换时被 CPU 取用，
    // 而那一刻本 CPU 上跑的必然是用户任务，换入它的那一步（`preempt_point` 里
    // `if tasks[nslot].user { set_rsp0(..) }`）先把它自己的栈顶装了进去。
    // 也就是说这条不变量是"rsp0 与当前任务同源"，不是"rsp0 永远指向活着的栈"。
    // 上面那句 `tops` 用**换入前记下的**两个栈顶，正是为了让这条判据在回收之后照样读得出。
    crate::log_info!(
        "user: tss rsp0={:#x} ist1={:#x}(期望 {:#x}) iomap={} tss_ok={}",
        rsp0_now, ist1_now, ex_top, iomap_now, tss_ok
    );
    let ping_ok = slot0.is_some_and(|v| v >= 1);
    let add_ok = slot1 == Some(0x2a);
    let unk_ok = slot2 == Some(user::E_INVALID);
    // 判 `kills == 1`（精确）而不是 `>= 1`：唯一能分辨"真杀掉"与"同一个故障每秒重演几十次"
    // 的就是这个数（M4-2 的现场是三十多行重复 `#GP`，`>= 1` 对它照样绿）。
    // 状态判"不再可运行"而不是"等于 Done"：被杀的任务现在会走完 标 Done → 登记待回收 →
    // 抢占点归化成 Free 并放手资源，停在哪个状态取决于窗口里过了几次 tick。
    // "被杀之后资源真的回账"不在这里判——手写镜像的 owned 只有它自己的内核栈；
    // 那条判据在 `KT_USER_POINTER` 第四档（有容器资源可还）。见 ADR-028、BACKLOG ⑫。
    let not_runnable = !matches!(sched::state_of(bad), sched::TaskState::Runnable | sched::TaskState::Running);
    let killed = user::kills() == 1
        && not_runnable
        && sched::runs_of(bad) <= 1
        // 落脚页存在且是"内核拥有、对用户开放、不可写"的一页：kill 的出口要跳的就是它
        && user::trampoline() == user::TRAMPOLINE_VA
        && mm::effective_flags(user::TRAMPOLINE_VA)
            .is_some_and(|e| e.user && e.executable && !e.writable);
    crate::log_info!(
        "user: killed={} kills={} bad_state={:?} runs={} 落脚页用户可达={}",
        killed,
        user::kills(),
        sched::state_of(bad),
        sched::runs_of(bad),
        mm::effective_flags(user::TRAMPOLINE_VA).is_some_and(|e| e.user)
    );
    ping_ok && add_ok && unk_ok && smap_blocks && killed && user::unknown_nr() >= 1
        && stale_hits == 0 && probes_clean && tss_ok
}
ktest!(KT_USER_ROUNDTRIP, t_user_roundtrip);

// ---------------------------------------------------------------- M4-2：ELF 容器
//
/// 第一个用户程序的 ELF 产物。由 `python tools/aurora.py build` 从 `user/hello`
/// 构建后写到这里（ADR-016：一条命令做完全套），所以它是**真工具链的产物**：
/// `rustc`/`lld` 会产出多段、带 `.debug_*` 但不进 PT_LOAD、`filesz == memsz` 这类
/// 我手编不出来的形状。手编的字节只能证明"我读的位置和我写的位置一致"，
/// 证明不了"我假设的那个形状真的存在"。
static HELLO_ELF: &[u8] = include_bytes!("../fixtures/hello.elf");

/// 用例的可变副本缓冲。**这里不能用 `Vec`**：本内核的分配器上限是
/// `heap::LARGE_MAX = 2048` 字节（`t_heap_rejects_oversize` 验的就是这条），
/// 而真产物有 18 KB —— 本用例第一版写的是 `HELLO_ELF.to_vec()`，
/// 第一次分配就走 `handle_alloc_error`，整机构成 39：
/// `kernel panic at /rustc/.../library/alloc/src/alloc.rs`。
/// 这条不是测试的小修补，它是 M4-2 的一条硬约束：**加载器不许按段大小分配内存**，
/// 只能从文件缓冲区流式取字节（已记 BACKLOG）。
const ELF_SCRATCH: usize = 32 * 1024;
struct ElfScratch(UnsafeCell<[u8; ELF_SCRATCH]>);
// SAFETY: 只在 ktest 自己的上下文里用，调用点在关中断窗口内，且每次借用都被
// `with_elf_copy` 限制在一次调用的函数体内——不同时存在两份可变引用。
unsafe impl Sync for ElfScratch {}
static ELF_BUF: ElfScratch = ElfScratch(UnsafeCell::new([0u8; ELF_SCRATCH]));

/// 把夹具拷进静态缓冲，交出一个**只在这次调用内活着**的可变切片。
/// 返回 `None` = 缓冲不够大。那是一种"用例自己失效"的状态，必须逐条算失败，
/// 绝不能让"跳过这条负样本"读成"这条负样本通过了"。
fn with_elf_copy<R>(f: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
    let n = HELLO_ELF.len();
    if n > ELF_SCRATCH {
        return None;
    }
    // SAFETY: 见 ElfScratch——单一持有者、关中断窗口内的用例上下文，
    // 且返回的切片在本次调用内就失效（不外泄 `&'static mut`）
    let buf = unsafe { &mut *ELF_BUF.0.get() };
    buf[..n].copy_from_slice(HELLO_ELF);
    Some(f(&mut buf[..n]))
}

fn put16(v: &mut [u8], at: usize, x: u16) {
    v[at..at + 2].copy_from_slice(&x.to_le_bytes());
}
fn put32(v: &mut [u8], at: usize, x: u32) {
    v[at..at + 4].copy_from_slice(&x.to_le_bytes());
}
fn put64(v: &mut [u8], at: usize, x: u64) {
    v[at..at + 8].copy_from_slice(&x.to_le_bytes());
}
fn get16(v: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([v[at], v[at + 1]])
}
fn get64(v: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&v[at..at + 8]);
    u64::from_le_bytes(a)
}

/// 一条负样本必须命中**它自己那一格**错误码。
///
/// 只要求"解析失败"的话，任何一条提前生效的检查都能让其余的门看起来像在工作——
/// 这正是 §12.4.1 规则 3 要防的那种绿。所以这里比对具体变体，
/// 并把没命中的那条单独打一行（`want`/`got` 两边都给名字，不给数字）。
fn rejects(name: &str, want: elf::ElfError, mutate: impl FnOnce(&mut [u8]), ok: &mut usize, bad: &mut usize) {
    let Some(r) = with_elf_copy(|v| {
        mutate(v);
        elf::parse(v)
    }) else {
        *bad += 1;
        crate::log_fatal!(
            "elf 负样本 {name}: 夹具 {}B 超出用例缓冲 {ELF_SCRATCH}B（本条没跑成，不算通过）",
            HELLO_ELF.len()
        );
        return;
    };
    match r {
        Err(got) if got == want => *ok += 1,
        Err(got) => {
            *bad += 1;
            crate::log_fatal!(
                "elf 负样本 {name}: 期望 {} 实际 {}",
                elf::describe(want),
                elf::describe(got)
            );
        }
        Ok(_) => {
            *bad += 1;
            crate::log_fatal!("elf 负样本 {name}: 期望被拒绝（{}）但通过了", elf::describe(want));
        }
    }
}

/// M4-2 第一段：ELF64 程序头解析。判据两层——正样本收下真产物，
/// 二十来条负样本每条各命中一格拒绝理由。
fn t_elf_container() -> bool {
    // 头部字段**直接从夹具读**：`elf::parse` 不改动输入，只有负样本需要副本
    // （而副本走静态缓冲，理由见 `ELF_SCRATCH` 那段——一次 `to_vec()` 就是把整机打到 39）。
    let h: &[u8] = HELLO_ELF;
    if h.len() > ELF_SCRATCH {
        crate::log_fatal!("elf: 夹具 {}B 超出用例缓冲 {ELF_SCRATCH}B", h.len());
        return false;
    }
    let phoff = get64(h, 32) as usize;
    let phent = get16(h, 54) as usize;
    let phnum = get16(h, 56) as usize;
    if phent < 56 || phnum < 2 {
        crate::log_fatal!("elf: 夹具本身不像预期（phent={} phnum={}）", phent, phnum);
        return false;
    }
    // ELF64 的程序头是定长 56 字节，字段偏移写在一处，下面十几条负样本共用
    let (i_type, i_flags, i_off, i_vaddr, i_filesz, i_memsz, i_align) = (0usize, 4, 8, 16, 32, 40, 48);

    let p = match elf::parse(h) {
        Ok(p) => p,
        Err(e) => {
            crate::log_fatal!("elf: 真产物被拒绝 —— {}", elf::describe(e));
            return false;
        }
    };
    // **正样本的不变量**。不写死地址与长度：那些随 `user/hello` 的改动而变，
    // 写死会让"改了用户程序"与"解析器坏了"读起来是同一件事。
    let segs = p.segments();
    let entry_in_text = segs.iter().any(|s| s.contains_va(p.entry) && s.executable && s.readable);
    let congruent = segs
        .iter()
        .all(|s| s.vaddr % mm::PAGE as u64 == s.offset % mm::PAGE as u64);
    let wx = segs.iter().all(|s| !(s.writable && s.executable));
    let user_half = segs.iter().all(|s| s.vaddr < elf::USER_VA_TOP);
    let no_overlap = segs.windows(2).all(|w| w[0].va_end() <= w[1].vaddr);
    crate::log_info!(
        "elf: fixture={}B entry={:#x} phnum={} load={} segs={}",
        h.len(),
        p.entry,
        p.phnum,
        p.n,
        segs.len()
    );
    for s in segs {
        crate::log_info!(
            "elf:   seg off={:#x} va={:#x} fsz={:#x} msz={:#x} {}{}{} pages={}",
            s.offset,
            s.vaddr,
            s.filesz,
            s.memsz,
            if s.readable { 'r' } else { '-' },
            if s.writable { 'w' } else { '-' },
            if s.executable { 'x' } else { '-' },
            s.pages().unwrap_or(0)
        );
    }
    if !(entry_in_text && congruent && wx && user_half && no_overlap && p.n >= 1) {
        crate::log_fatal!(
            "elf: 正样本不变量不成立 entry_in_text={} congruent={} wx={} user_half={} no_overlap={}",
            entry_in_text,
            congruent,
            wx,
            user_half,
            no_overlap
        );
        return false;
    }

    let mut ok = 0usize;
    let mut bad = 0usize;
    // ---- 头部字段：每改一处，必须命中对应那一格
    // "太短"这条不用副本：`parse` 不改输入，直接把夹具的前 63 个字节给它就行
    match elf::parse(&h[..63]) {
        Err(elf::ElfError::TooShort) => ok += 1,
        Err(other) => {
            bad += 1;
            crate::log_fatal!(
                "elf 负样本 太短: 期望 {} 实际 {}",
                elf::describe(elf::ElfError::TooShort),
                elf::describe(other)
            );
        }
        Ok(_) => {
            bad += 1;
            crate::log_fatal!("elf 负样本 太短: 期望被拒绝（截断成 63 字节）但它通过了");
        }
    }
    rejects("魔数", elf::ElfError::BadMagic, |v| v[1] = b'X', &mut ok, &mut bad);
    rejects("非 64 位", elf::ElfError::Not64Bit, |v| v[4] = 1, &mut ok, &mut bad);
    rejects("大端", elf::ElfError::NotLittleEndian, |v| v[5] = 2, &mut ok, &mut bad);
    rejects("ident 版本", elf::ElfError::BadVersion, |v| v[6] = 0, &mut ok, &mut bad);
    rejects("e_version", elf::ElfError::BadVersion, |v| put32(v, 20, 2), &mut ok, &mut bad);
    rejects(
        "不是 x86-64",
        elf::ElfError::WrongMachine,
        |v| put16(v, 18, 0x28),
        &mut ok,
        &mut bad,
    );
    rejects(
        "ET_DYN",
        elf::ElfError::RelocationUnsupported,
        |v| put16(v, 16, 3),
        &mut ok,
        &mut bad,
    );
    rejects(
        "ET_REL",
        elf::ElfError::NotExecutableImage,
        |v| put16(v, 16, 1),
        &mut ok,
        &mut bad,
    );
    rejects(
        "每项过小",
        elf::ElfError::BadPhEntSize,
        |v| put16(v, 54, 48),
        &mut ok,
        &mut bad,
    );
    rejects(
        "表越界",
        elf::ElfError::PhdrsOutOfBounds,
        |v| put16(v, 56, 0xffff),
        &mut ok,
        &mut bad,
    );

    // ---- 段级：拿夹具里真实存在的前两段来改
    let s0 = phoff;
    let s1 = phoff + phent;
    let va0 = get64(h, s0 + i_vaddr);
    let va1 = get64(h, s1 + i_vaddr);
    let fsz0 = get64(h, s0 + i_filesz);
    let off1 = get64(h, s1 + i_off);
    rejects(
        "align 不是 2 的幂",
        elf::ElfError::BadAlignment,
        |v| put64(v, s0 + i_align, 0x3000),
        &mut ok,
        &mut bad,
    );
    rejects(
        "W+X",
        elf::ElfError::WxViolation,
        |v| put32(v, s0 + i_flags, 4 | 2 | 1),
        &mut ok,
        &mut bad,
    );
    rejects(
        "装进内核地址",
        elf::ElfError::NotUserRange,
        |v| put64(v, s0 + i_vaddr, 0xffff_ffff_8000_0000),
        &mut ok,
        &mut bad,
    );
    rejects(
        "文件区间越界",
        elf::ElfError::SegmentOutOfBounds,
        |v| put64(v, s0 + i_filesz, fsz0 + 0x400_0000),
        &mut ok,
        &mut bad,
    );
    rejects(
        "memsz<filesz",
        elf::ElfError::SegmentOutOfBounds,
        |v| put64(v, s1 + i_memsz, 4),
        &mut ok,
        &mut bad,
    );
    rejects(
        "vaddr/offset 不同余",
        elf::ElfError::MisalignedSegment,
        |v| put64(v, s1 + i_off, off1 + 1),
        &mut ok,
        &mut bad,
    );
    rejects(
        "两段重叠",
        elf::ElfError::OverlappingSegments,
        |v| put64(v, s1 + i_vaddr, va0),
        &mut ok,
        &mut bad,
    );
    rejects(
        "没有可加载段",
        elf::ElfError::NoLoadSegment,
        |v| {
            for i in 0..phnum {
                put32(v, phoff + i * phent + i_type, 2); // 全改成 PT_DYNAMIC
            }
        },
        &mut ok,
        &mut bad,
    );
    rejects(
        "入口不可执行",
        elf::ElfError::EntryNotExecutable,
        |v| put64(v, 24, va1),
        &mut ok,
        &mut bad,
    );
    // 0x401000 落在两个段之间的**空洞**里：段的范围是 [0x400000,+0x53) 与 [0x402000,+0x1000)。
    // （第一次写的是 0x400000，那正好是段首、也就是合法入口——负样本自己写错时
    //  报的是"解析器放过了坏容器"，那条红是它的证据，不是解析器的。）
    rejects(
        "入口不在任何段里",
        elf::ElfError::EntryNotLoaded,
        |v| put64(v, 24, 0x40_1000),
        &mut ok,
        &mut bad,
    );

    // ---- 段数上限：把 phnum 扩到 9，多出来的项写成"零长度、互不重叠、只读"，
    // 让它们都通过前面每一道门，最后必须撞在 TooManySegments 上。
    // 这是唯一能证明"上限真在起作用"而不是装饰的负样本。
    let base_off = get64(h, s0 + i_off);
    rejects(
        "段数超上限",
        elf::ElfError::TooManySegments,
        |v| {
            put16(v, 56, 9);
            for i in phnum..9 {
                let at = phoff + i * phent;
                put32(v, at + i_type, 1);
                put32(v, at + i_flags, 4);
                put64(v, at + i_off, base_off);
                put64(v, at + i_vaddr, 0x800_0000 + (i as u64) * mm::PAGE as u64 * 64);
                put64(v, at + i_filesz, 0);
                put64(v, at + i_memsz, 0);
                put64(v, at + i_align, mm::PAGE as u64);
            }
        },
        &mut ok,
        &mut bad,
    );

    crate::log_info!("elf: 负样本 命中={} 未命中={}（未命中的每条已单独报）", ok, bad);
    bad == 0 && ok >= 21
}
ktest!(KT_ELF, t_elf_container);

/// M4-2 第二段：把**真 ELF** 装进用户窗口并跑起来。
///
/// 与 `t_user_roundtrip` 的分工是刻意的：那条继续用内核自己编的 66 字节镜像，
/// 它管"入口/ABI/kill/SMAP"这套机制；这条管"容器 → 页表 → ring3"这段路，
/// 判据因此全在**装完之后的生效位与程序自己写回的数**上。
/// 两条一起才完整：blob 那条不经过加载器，容器这条不经过手写机器码。
/// 夹具这一版会打的系统调用总数：1 次 ping + 29 次归因用的 ping + add + unknown。
/// 改了 `user/hello` 的调用次数就要改这里——**用例等的是"打完"而不是"开始打了"**。
const P7_CALLS: u64 = 32;

fn t_elf_load_run() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("elfload: APIC 起不来，跑不了时间片");
        return false;
    }
    let h = HELLO_ELF;
    let loaded = match user::load(h) {
        Ok(l) => l,
        Err(e) => {
            crate::log_fatal!("elfload: 加载失败 —— {}", user::describe_load(e));
            return false;
        }
    };
    crate::log_info!(
        "elfload: segs={} pages={} entry={:#x} data={:#x} stack_top={:#x}",
        loaded.segs,
        loaded.pages,
        loaded.entry,
        loaded.data_va,
        loaded.stack_top
    );
    // **生效位**（ADR-026 的判据落点）：入口那一页必须 user+可执行+不可写，
    // 可写段必须 user+可写+不可执行。这里读的是整条页表链相与/相或之后的结果，
    // 不是加载器"打算给什么"。
    let code_eff = mm::effective_flags(loaded.entry);
    let data_eff = mm::effective_flags(loaded.data_va);
    let eff_ok = code_eff.is_some_and(|f| f.user && f.executable && !f.writable)
        && data_eff.is_some_and(|f| f.user && f.writable && !f.executable);
    // 加载器给的三个权限分支里，`USER_R`（`r--` 那条）**不在上面两条里**。
    // 它由程序自己的第四个槽证明（见 user/hello 的 OFF_RODATA 注释）：
    // 分支没有证据 = 写好了却没人走过的代码。
    crate::log_info!(
        "elfload: eff code={:?} data={:?}",
        code_eff,
        data_eff
    );
    if !eff_ok {
        crate::log_fatal!("elfload: 生效位不对（见上一行）");
        return false;
    }

    sched::init_boot_task();
    sched::start_workers();
    user::clear_counters();
    // 装载产物（代码/数据/用户栈）连同 `spawn_user` 自己加的内核栈一起归这个任务
    let t = match sched::spawn_user(loaded.entry, loaded.stack_top, loaded.owned) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("elfload: spawn_user 失败 {:?}", e);
            return false;
        }
    };
    apic::timer_start().ok();
    // **容量的证人**（M4 欠账第一条的落点）：一个任务名下的映射条数。
    // 按段切块之前它是"页数 + 2"（这份夹具 5 页 ⇒ 7 条）；现在每段按"剩余页数的二进制位数"
    // 切块 ⇒ 同一份夹具 6 条（串口上那行 `收尾回收 released=6` 是第二台仪器）。
    // 判的是**余量**而不是"等于 6"：等于 6 只是这一版夹具的快照，改夹具就会红，
    // 而那种红不代表容量坏了。真正要挡的是"再加一段就撞 `MAX_OWNED`，
    // 而失败长得像 `MmError::Unsupported` 而不是像容量到了头"。
    let owned_now = sched::owned_of(t);
    let headroom = sched::MAX_OWNED.saturating_sub(owned_now);
    crate::log_info!(
        "elfload: 容量 owned={} 上限={} 镜像页数={} 余量={}",
        owned_now,
        sched::MAX_OWNED,
        loaded.pages,
        headroom
    );
    if headroom < 2 {
        crate::log_fatal!("elfload: 容量余量不足 2 条映射（要么改 `MAX_OWNED`，要么把夹具收小）");
    }
    // 程序第一件事就是把魔数写进它自己的数据页，所以"魔数到位"就是"跑到第 X 行"的证人。
    // 超时用周期数上限而不是"等多久"：这台机器上 TSC 非 invariant（§12.4.1 规则 2），
    // 只保证有界，不承诺毫秒。
    let mut rounds = 0u64;
    // `P7_CALLS` = 夹具这一版会打的调用总数（1 次 ping + 29 次归因 ping + add + unknown）。
    // 等的是"打完"而不是"开始打了"：窗口收得太早，第五个槽（loops）还没被写，
    // 读回来不是 29 就是判据红——那条红是真的，但原因在用例的等待条件，不在被测代码。

    // **读用户页必须发生在窗口之外**。SMAP 窗口的约束是"开着 AC 的那几行里不许有中断"
    // （`user.rs::read_slot` 的注释），而 `with_interrupts` 内 IF=1 —— 所以在窗口里轮询
    // 魔数是错的（第一版就是这么写的，那条 SAFETY 注释本身也不成立）。
    // 正确的形状：窗口内只做"让任务跑起来 + 看内核自己的计数器"，关掉之后才碰用户页。
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        // `served` 是内核 .data 里的原子量，读它不需要 SMAP 窗口
        while user::served() < P7_CALLS && tsc::now().wrapping_sub(t0) < 200_000_000 {
            rounds += 1;
            tsc::spin(20_000);
        }
        // 程序在第三次调用之后还要读一次 .rodata 再写第四个槽，给一小段落地时间；
        // 它写完就停在 `hlt`，所以下面 `wait_for_boot_task` 一定会把 CPU 还回来。
        tsc::spin(2_000_000);
        if !sched::wait_for_boot_task(300_000_000) {
            crate::log_fatal!("elfload: 窗口收不了场（启动上下文没回到 CPU）");
        }
    });
    apic::timer_stop().ok();
    let magic = user::read_at(loaded.data_va);
    // 偏移 8/16/24/32 是夹具的约定（`user/hello` 的 `OFF_*`）。它们不是内核读出来的，
    // 但**魔数在偏移 0 到位**证明了这一页就是那个结构、且程序的写入落在这里；
    // 值本身对不对则由下面四条各判一格（往返、参数、错误码、只读段可读）。
    let ping = user::read_at(loaded.data_va + 8);
    let add = user::read_at(loaded.data_va + 16);
    let unk = user::read_at(loaded.data_va + 24);
    let rod = user::read_at(loaded.data_va + 32);
    let served = user::served();
    let state = sched::state_of(t);
    // 第二台仪器：这个任务被换上来过几次（`runs`）。如果冷样本数 == 换入次数，
    // 说明"冷"发生在**每次重新进入之后的第一次调用**，而不是发生在入口指令本身；
    // 如果冷样本只有 1 次而 runs 远大于 1，那才是"一次性预热"。
    // 这两个数是独立计数的（一个来自 P7 的门槛分类，一个来自 run queue 的换入计数）。
    let runs = sched::runs_of(t);
    // **P7 的样本数必须等于内核服务过的调用数**：一张表按"进了出口记账"计数，
    // 另一张按"分发器被调到"计数，两者不等就说明有一类向量绕过了记账（或记了两次）。
    // 这条同时是 P5 干净的反证：把系统调用错并进 P5 的那版实现里，
    // `timer 判据` 的两台仪器差 3（= 这 3 次调用），现在它们各自对得上。
    let sc = trap::stats_syscall_of(crate::arch::x86_64::cpu::BSP_SLOT);
    crate::log_info!(
        "elfload: magic={:?} ping={:?} add={:?} unk={:?} rodata={:?} served={} unknown_nr={} rounds={} runs={} state={:?} guard_unmapped={}",
        magic,
        ping,
        add,
        unk,
        rod,
        served,
        user::unknown_nr(),
        rounds,
        runs,
        state,
        !mm::is_mapped(loaded.stack_top - mm::PAGE as u64 - 8)
    );
    let loops = user::read_at(loaded.data_va + 40);
    // **P7 归因**：`first` = 这个 CPU 第一次被记账的代价，`min` = 同一条路径
    // 连续 30 多次调用里最小的那一次。两者之比就是"冷启动"与"结构成本"的分界读数。
    // 这里刻意只报比值不报结论：判据要能分辨，但"为什么"要另做一次实验才能写。
    let ratio = if sc.min_cycles > 0 {
        sc.first_cycles / sc.min_cycles
    } else {
        0
    };
    crate::log_info!(
        "elfload: p7 samples={} lead={:?} min={} mean={} max={} first/min={} cold(>={}周期)={} runs={} loops={:?} (served={}) p5_last_vec={:#x}",
        sc.faults,
        trap::p7_lead(),
        sc.min_cycles,
        sc.mean_cycles,
        sc.max_cycles,
        ratio,
        trap::P7_COLD_CYCLES,
        sc.cold_samples,
        runs,
        loops,
        served,
        trap::p5_last_vec()
    );
    // 栈的 guard：栈页下面那一页必须没映射（这条与 `init()` 的形状同源）。
    // `stack_top` 在栈页内，`- PAGE` 落到 guard 页；`- 8` 是因为栈顶留了 16 字节。
    let guard_ok = !mm::is_mapped(loaded.stack_top - mm::PAGE as u64 - 8);
    // **尺子必须能分辨**（§12.4.1 规则 3）：`ImageInDynamicRegion` 没人走就是装饰。
    // 做法：把夹具第一条可执行 PT_LOAD 连同 `e_entry` 一起向上平移 1 MiB，让它跨过
    // `USER_MMAP_BASE` 那条线。两个坑都踩过才写在这儿：①只动段不动 `e_entry` 会先在
    // `EntryNotLoaded` 上失败，那条证人不是这一格；②程序头偏移要照 `elf.rs` 那张表
    // （`p_vaddr` 在 +16，不是 +0x20——那是 `p_filesz`，凭记忆写会命中 `SegmentOutOfBounds`）。
    // 教训本身是 ADR-026"按架构偏移声明字段"在防的事。详见 BACKLOG ⑪。
    let mut partition_reject = false;
    if let Some(r) = with_elf_copy(|v| {
        let phoff = get64(v, 0x20) as usize;
        let phentsize = get16(v, 0x36) as usize;
        let phnum = get16(v, 0x38) as usize;
        let mut vaddr_at = 0usize;
        for i in 0..phnum {
            let base = phoff + i * phentsize;
            let ty = u32::from_le_bytes([v[base], v[base + 1], v[base + 2], v[base + 3]]);
            let flags = u32::from_le_bytes([
                v[base + 4],
                v[base + 5],
                v[base + 6],
                v[base + 7],
            ]);
            if ty == 1 && flags & 4 != 0 {
                vaddr_at = base + 16;
                break;
            }
        }
        if vaddr_at == 0 {
            crate::log_fatal!("elfload: 分区负样本找不到可执行的 PT_LOAD（本条没跑成，不算通过）");
            return false;
        }
        let shift = 0x0010_0000u64;
        put64(v, 0x18, get64(v, 0x18) + shift);
        put64(v, vaddr_at, get64(v, vaddr_at) + shift);
        match user::load(v) {
            Err(user::LoadError::ImageInDynamicRegion { va, end }) => {
                crate::log_info!(
                    "elfload: 分区负样本按预期被拒 va={va:#x} end={end:#x}（分界={:#x}）",
                    mm::USER_MMAP_BASE
                );
                true
            }
            Err(e) => {
                crate::log_fatal!("elfload: 分区负样本命中了别的拒绝码 —— {}", user::describe_load(e));
                false
            }
            Ok(_) => {
                crate::log_fatal!("elfload: 分区负样本**装上了**（分区规则没生效）");
                false
            }
        }
    }) {
        partition_reject = r;
    }
    let roundtrip_ok = loops == Some(28)
        && magic == Some(0xa5a5_5a5a_1234_5678)
        && ping.is_some_and(|v| v >= 1)
        && add == Some(0x2a + 0x12)
        && unk == Some(user::E_INVALID)
        && rod == Some(0xa7)
        && served >= P7_CALLS
        && user::unknown_nr() >= 1
        && guard_ok
        && headroom >= 2
        && partition_reject
        && sc.faults >= served;
    if !roundtrip_ok {
        crate::log_fatal!("elfload: 判据不成立（上面一行是全部读数）");
    }
    // 收尾：本用例只验"装得上、跑得通"，资源要还回去——夹具的 VA 是容器定死的
    // （`ET_EXEC` 搬不动），留着就会让后面任何一次 `user::load` 撞 `VaTaken`。
    // 这一句同时也是 `terminate_task` 的第二个使用点：它必须能在"任务不在 CPU 上"时
    // 就地回收，而不需要等一次 tick。
    if sched::terminate_task(t) {
        crate::log_info!("elfload: 收尾回收 slots={} released={}", mm::reservation_count(), sched::reap_released());
    }
    roundtrip_ok
}
ktest!(KT_ELF_LOAD, t_elf_load_run);

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

/// 让本 CPU 过一次抢占点，把"标了 Free 但还牵着映射"的槽位放手。
///
/// 为什么需要它而不是在测试里直接释放：正在 CPU 上跑的那个任务的映射**不能**由它自己解映射
/// （rsp 就在里面）。回收只发生在"本 CPU 上跑的已经不是它"的那一刻，
/// 而那一刻的唯一来源是中断出口路过 `preempt_point` ⇒ 想回收就得开一次窗口让 tick 进来。
fn drain_reap() -> bool {
    // **等的是"回收发生了"，不是"过了多少毫秒"**。第一版这里写的是固定时长 30M 周期
    // (≈9 ms)，而 tick 的周期是 10 ms —— 于是一轮 tick 都可能进不来，
    // 判据读到的就是"还没回收"（`released` 不动、`reservations` 还 +5），
    // 而那**不是被测代码的错，是用例的等待条件不成立**。
    // 改成轮询 `reap_released()` 真的涨之后，上限仍留了一次实测的坑：本机 `bench` 连着
    // 第二次启动（宿主正忙）时，120M 周期(≈36 ms，只够 3 轮 tick)到过窗 ⇒ `KT_USER_POINTER`
    // 报假红。上限抬到 1G 周期(≈300 ms)，并且**失败时把窗口里到底进来了几轮 tick 一起打**——
    // 下一次再红，就能分清"tick 没进来"（环境）与"tick 进来了但没回收"（被测代码）。
    let before = sched::reap_released();
    let ticks_before = sched::ticks_of(0);
    let mut hit = false;
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        while tsc::now().wrapping_sub(t0) < 1_000_000_000 {
            if sched::reap_released() > before {
                hit = true;
                break;
            }
            tsc::spin(20_000);
        }
    });
    if !hit {
        // `warn` 而不是 `fatal`：这个函数有三个调用点，其中两个把返回值当判据（红会从
        // 用例本身出来），第三个明确"可能本来就没有待收的"（旁观者路径已就地回收）。
        // 在这里打 fatal 会让每一跑都固定有一条不失败的 fatal，看惯之后就没人看 fatal 了。
        crate::log_warn!(
            "reap: 窗口内没看到回收 released={}→{} 窗口内 tick {}→{}（调用方自己决定这算不算失败）",
            before,
            sched::reap_released(),
            ticks_before,
            sched::ticks_of(0)
        );
    }
    hit
}

/// M4-2 第三段：任务的结束与资源回账。两条收场路径都要走，各判一件事：
/// **旁观者结束**（用例调 `terminate_task`，对应"被杀/被回收"）与
/// **自己退出**（程序打 `SYS_EXIT`，对应"进程正常走完"）。
///
/// 最硬的一条判据是**同一个固定 VA 连续装载三次都成功**：
/// `ET_EXEC` 的地址是容器定死的，只要上一次的映射或 VA 保留没还回来，
/// `load` 就会撞 `VaTaken`；所以"第三次装得上"本身就是回收发生了的证据，
/// 不依赖我去读自己写的计数器。计数（reservation / live frames / exits / reap_released）
/// 只是把"为什么成功"说清楚的第二台仪器。
fn t_task_exit() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("exit: APIC 起不来");
        return false;
    }
    let base_res = mm::reservation_count();
    let base_live = resource::live_of(user::MOD_USER);
    let base_released = sched::reap_released();
    sched::init_boot_task();
    sched::start_workers();
    apic::timer_start().ok();

    // ---- 一轮 = 装载 → 跑 → 结束（mode 决定谁发起结束）→ 回收 → 检查账目
    let mut one_ok = true;
    let mut two_ok = true;
    let mut three_ok = true;

    // === 第一轮：旁观者结束（terminate_task，此时该任务已不在 CPU 上 ⇒ 就地回收） ===
    let l1 = match user::load(HELLO_ELF) {
        Ok(l) => l,
        Err(e) => {
            crate::log_fatal!("exit: 第一次装载失败 —— {}", user::describe_load(e));
            return false;
        }
    };
    let entry_page = l1.entry;
    let t1 = match sched::spawn_user(l1.entry, l1.stack_top, l1.owned) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("exit: 第一个任务建不起来 {:?}", e);
            return false;
        }
    };
    user::clear_counters();
    let run1 = sched::state_of(t1);
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        while user::served() < 8 && tsc::now().wrapping_sub(t0) < 200_000_000 {
            tsc::spin(20_000);
        }
        if !sched::wait_for_boot_task(300_000_000) {
            crate::log_fatal!("exit: 第一轮窗口收不了场");
        }
    });
    // 此刻 current 是启动上下文，所以 terminate 走的是"就地回收"那条分支
    let term1 = sched::terminate_task(t1);
    // 旁观者路径（任务已不在 CPU 上）是**就地回收**，不需要等 tick，
    // 所以这里不能要求 drain_reap 命中——它可能本来就已经是零待收了。
    let _ = drain_reap();
    let reload1 = user::load(HELLO_ELF).is_ok();
    crate::log_info!(
        "exit: 一轮(旁观者) 结束前状态={:?} terminate返回={} 装载的映射数回账={} 再装载成功={} reservations={}→{} live={}→{}",
        run1,
        term1,
        sched::state_of(t1) == sched::TaskState::Free,
        reload1,
        base_res,
        mm::reservation_count(),
        base_live,
        resource::live_of(user::MOD_USER)
    );
    one_ok = term1
        && reload1
        && sched::state_of(t1) == sched::TaskState::Free
        && !mm::is_reserved(entry_page)
        && mm::reservation_count() <= base_res
        && resource::live_of(user::MOD_USER) <= base_live;
    // `reload1` 那次装载没有泄漏：返回值被丢掉 ⇒ 它的 `OwnedSet` 立刻 drop ⇒
    // 解映射 + 归还页框 + 放手保留。这正是 `Mapping` 的 RAII 在收尾——
    // "没接住所有权"不等于"资源还在"，第三轮装得上就是这件事的证据。
    // （`l1` 的 `owned` 字段已经在 `spawn_user` 那一步移走了，这里不能整体借用它。）

    // === 第二轮：自己退出（程序读 flag 打 SYS_EXIT ⇒ 释放必须延迟到下一个上下文） ===
    let l2 = match user::load(HELLO_ELF) {
        Ok(l) => l,
        Err(e) => {
            // 第一次已经回收过了还装不上，就是回账没发生：直接判红，不必再跑后面两轮
            crate::log_fatal!("exit: 第二次装载失败（说明第一轮的回收没真正放手）—— {}", user::describe_load(e));
            return false;
        }
    };
    let mut two_ran = false;
    if l2.segs >= 1 {
        user::clear_counters();
        // 通过 SMAP 窗口往它的 flag 格写非 0：程序跑完调用序列之后就自己结束。
        // 这一步同时是 §10.3 的最小预览（内核开窗口**写**用户页），不是测试专用的后门。
        user::write_at(l2.data_va + 48, 1);
        match sched::spawn_user(l2.entry, l2.stack_top, l2.owned) {
            Ok(t2) => {
                apic::with_interrupts(|| {
                    let t0 = tsc::now();
                    while user::served() < P7_CALLS && tsc::now().wrapping_sub(t0) < 200_000_000 {
                        tsc::spin(20_000);
                    }
                    if !sched::wait_for_boot_task(300_000_000) {
                        crate::log_fatal!("exit: 第二轮窗口收不了场");
                    }
                });
                // SYS_EXIT 的释放是**延迟**的（那一刻它还站在自己的内核栈上），
                // 必须等到本 CPU 出现下一次抢占，所以这一处 `drain` 是真判据。
                let drained = drain_reap();
                let exits = user::exits();
                // 回收前后的两个独立读数：槽里还牵着几条映射、代码页还在不在。
                // 只看"能不能再装载一次"会漏掉"装得上是因为它换了地址"这类假绿。
                let owned_after = sched::owned_of(t2);
                let code_after = mm::is_mapped(l2.entry);
                let reload2 = user::load(HELLO_ELF).is_ok();
                crate::log_info!(
                    "exit: 二轮(自己退出) exits={} 等到回收={} 槽位Free={} 槽内还剩映射={} 代码页还在={} 再装载成功={} released={}→{} reservations={} live={}",
                    exits,
                    drained,
                    sched::state_of(t2) == sched::TaskState::Free,
                    owned_after,
                    code_after,
                    reload2,
                    base_released,
                    sched::reap_released(),
                    mm::reservation_count(),
                    resource::live_of(user::MOD_USER)
                );
                two_ran = true;
                two_ok = exits >= 1
                    && drained
                    && reload2
                    && sched::state_of(t2) == sched::TaskState::Free
                    && !mm::is_mapped(l2.data_va)
                    && sched::reap_released() > base_released
                    && mm::reservation_count() <= base_res
                    && resource::live_of(user::MOD_USER) <= base_live;
            }
            Err(e) => {
                crate::log_fatal!("exit: 第二个任务建不起来 {:?}", e);
                one_ok = false;
            }
        }
    }

    // === 第三轮：什么都不做，只证明"上两轮的账目是平的" ===
    if two_ran {
        let l3 = user::load(HELLO_ELF);
        match l3 {
            Ok(l) => {
                three_ok = true;
                let _ = l.segs;
                // l 在这里被 drop ⇒ 它的映射与保留立刻归还；三次都能装 ⇒ 回收是真的在发生
            }
            Err(e) => {
                crate::log_fatal!("exit: 第三次装载失败 —— {}", user::describe_load(e));
                three_ok = false;
            }
        }
    }
    apic::timer_stop().ok();
    crate::log_info!(
        "exit: 判定 一轮={} 二轮={} 三轮={} 最终 reservations={} live={}",
        one_ok,
        two_ok,
        three_ok,
        mm::reservation_count(),
        resource::live_of(user::MOD_USER)
    );
    one_ok && two_ok && three_ok
}
ktest!(KT_TASK_EXIT, t_task_exit);

/// 一轮实验的读数。`base` = 可写段的页基址（`.slots` 就在那一页的开头），
/// `stack_top` 用来算**这个任务自己的** guard 页，`state` 是窗口结束、回收等完之后槽位的状态。
struct Round {
    base: u64,
    stack_top: u64,
    t: usize,
    served: u64,
    state: sched::TaskState,
    /// `None` = 这一档根本没有东西要回收（任务还活着），所以"等回收"这个动作不成立。
    /// 把"没等"与"等了没等到"分开放进类型里，判据才不会把前者读成后者。
    drained: Option<bool>,
    image_lo: u64,
    image_hi: u64,
}

/// 装载一份镜像、按 `flag` 写进输入格、跑一轮、把 CPU 还给启动上下文，然后交回全部读数。
/// 三档实验共用这一个动作，差别只在 `flag` 的位与"这一档会不会把任务结束掉"。
///
/// `expect_end` 必须显式给：`drain_reap` 等的是"`reap_released()` 真的涨"，而任务还活着时
/// 没有任何槽登记待回收 —— 那时它只会白等一个 120M 周期的窗口再返回 false，
/// 读数就成了"回收没发生"，而真实原因是"等待条件不成立"。这一课在 `KT_TASK_EXIT` 上付过学费。
fn run_one(flag: u64, calls: u64, tag: &str, expect_end: bool) -> Option<Round> {
    let l = match user::load(HELLO_ELF) {
        Ok(l) => l,
        Err(e) => {
            crate::log_fatal!("abi {tag}: 装载失败 —— {}", user::describe_load(e));
            return None;
        }
    };
    let (base, stack_top, entry, owned) = (l.data_va, l.stack_top, l.entry, l.owned);
    let (image_lo, image_hi) = (l.image_lo, l.image_hi);
    user::write_at(base + user::ABI_SLOT_FLAG, flag);
    let t = match sched::spawn_user(entry, stack_top, owned) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("abi {tag}: 任务建不起来 {:?}", e);
            return None;
        }
    };
    user::clear_counters();
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        while user::served() < calls && tsc::now().wrapping_sub(t0) < 200_000_000 {
            tsc::spin(20_000);
        }
        // 被杀那一档不打 `SYS_EXIT`：任务停在内核给的落脚页里等换出，
        // 所以这里只能靠 tick，再由 `wait_for_boot_task` 把 CPU 还给启动上下文。
        if !sched::wait_for_boot_task(300_000_000) {
            crate::log_fatal!("abi {tag}: 窗口收不了场");
        }
    });
    // 先等回收、再读状态：反过来就会读到"Done 但还没归化成 Free"的中间态，
    // 而那个中间态不代表任何事，只代表快门按早了。
    let drained = if expect_end { Some(drain_reap()) } else { None };
    let state = sched::state_of(t);
    Some(Round { base, stack_top, t, served: user::served(), state, drained, image_lo, image_hi })
}

/// M4-3 第一段：用户指针校验，以及"坏指针既不杀用户、也不许内核替它读内核页"。
/// 四档各挡一类错法（内容已写进 §10.3.1 的表，这里只留名字）：
/// 1 合法指针读出真值（挡"校验永远失败"那种永远 -EFAULT 的装饰）；
/// 2 内核地址与未映射地址都回 -EFAULT 且任务活着、`kills == 0`、`bad_ptrs >= 2`
///   （提权与拒绝服务这两个方向相反的错误都不会让机器挂，所以必须各自数）；
/// 3 `ac_active() == false` 独立读回 rflags.AC（挡"CLAC 被某条 `?` 提前 return 跳过"）；
/// 4 ring3 自己写 guard 页 ⇒ 只杀这个任务并且资源回账（这条不经过指针校验，把关人只能是页表+故障归属）。
/// 顺带守住两条结构性规则：地址分区（`partition_ok`）与落脚页（`tramp_ok`）。
fn t_user_pointer_checks() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("abi: APIC 起不来");
        return false;
    }
    // 这里**不**调 `user::init()`。以前那一句的含义是"容器任务的 kill 要靠手写镜像那一页
    // 当地脚页"，而这条依赖在代码里看不见，还要靠 `.ktests` 段里的先后顺序才成立
    //（段顺序由链接器决定，不由源码决定）。现在 `user::load()` 自己会建内核的落脚页。
    sched::init_boot_task();
    sched::start_workers();
    apic::timer_start().ok();

    // ---- (1)(2)(3)：三档指针实验。这一档不把任务结束掉，收尾由下面的旁观者路径做
    let peek_calls = P7_CALLS + 3;
    let r1 = match run_one(user::FLAG_PEEK, peek_calls, "peek", false) {
        Some(v) => v,
        None => {
            apic::timer_stop().ok();
            return false;
        }
    };
    // **地址分区**的读数：镜像整段在 `[USER_VA_BASE, USER_MMAP_BASE)`，
    // 内核发的用户栈在 `USER_MMAP_BASE` 之上。两条分别量——"装上了"不是证据，
    // 装上也可能是"脚手架那次没先跑"，而这条规则要的是与顺序无关。
    let page_mask = (mm::PAGE as u64) - 1;
    let stack_page = r1.stack_top & !page_mask;
    let partition_ok = r1.image_lo >= mm::USER_VA_BASE
        && r1.image_hi <= mm::USER_MMAP_BASE
        && stack_page >= mm::USER_MMAP_BASE;
    let tramp_ok = user::trampoline() == user::TRAMPOLINE_VA
        && mm::effective_flags(user::TRAMPOLINE_VA)
            .is_some_and(|e| e.user && e.executable && !e.writable);
    let peek_ok = user::read_at(r1.base + user::ABI_SLOT_PEEK_OK);
    let peek_kernel = user::read_at(r1.base + user::ABI_SLOT_PEEK_KERNEL);
    let peek_unmapped = user::read_at(r1.base + user::ABI_SLOT_PEEK_UNMAPPED);
    let ac_after = user::ac_active();
    let kills_after_peek = user::kills();
    let bad = user::bad_ptrs();
    crate::log_info!(
        "abi: peek ok={:?} kernel={:?} unmapped={:?} bad_ptrs={} kills={} ac_active={} served={} 分区={} 落脚页={} 槽位={:?}",
        peek_ok,
        peek_kernel,
        peek_unmapped,
        bad,
        kills_after_peek,
        ac_after,
        r1.served,
        partition_ok,
        tramp_ok,
        r1.state
    );
    crate::log_info!(
        "abi: 地址 image=[{:#x}..{:#x}) 栈页={:#x} 分界={:#x}",
        r1.image_lo,
        r1.image_hi,
        stack_page,
        mm::USER_MMAP_BASE
    );
    let peek_ok_good = peek_ok == Some(0xa7);
    let rejects = peek_kernel == Some(user::E_FAULT) && peek_unmapped == Some(user::E_FAULT);
    let survived = kills_after_peek == 0 && bad >= 2 && r1.served >= peek_calls;
    let window_closed = !ac_after;
    // 收尾：旁观者路径（任务已不在 CPU 上 ⇒ `terminate_task` 就地回收）。
    // 资源是否真的还回来读**两台**仪器：计数涨了 + 那两页不再映射。
    // 只看"能不能再装载一次"会漏掉"装得上是因为它换了地址"这类假绿。
    let rel_before = sched::reap_released();
    let peek_cleanup = sched::terminate_task(r1.t);
    let peek_pages_back = !mm::is_mapped(r1.base) && !mm::is_mapped(r1.stack_top);
    let peek_released = sched::reap_released() > rel_before;

    // ---- (4) 从 ring3 越界写自己的 guard 页：会被杀，所以要等回收
    let r2 = match run_one(user::FLAG_GUARD_STORE, P7_CALLS, "guard", true) {
        Some(v) => v,
        None => {
            apic::timer_stop().ok();
            return false;
        }
    };
    let kills = user::kills();
    // 程序写的是"自己栈页下面那一页"的最后一个 8 字节。**判据不去读那一格**：
    // 它从未映射，内核去读就是一次 ring0 的 #PF ⇒ 按 §9.2 直接 L4，而现场看起来
    // 像"用例把内核写坏了"。量具自己先把整机打死是最坏的一种红。
    // "有没有落地"换一台能分辨的仪器：那一页现在是不是**仍然**没映射。
    let guard_va = (r2.stack_top & !page_mask) - mm::PAGE as u64;
    let guard_still_unmapped = !mm::is_mapped(guard_va);
    let pages_back = !mm::is_mapped(r2.base) && !mm::is_mapped(r2.stack_top);
    crate::log_info!(
        "abi: guard kills={} kills精确={} 那一页仍没映射={} 槽位={:?} 页已回收={} 等到回收={:?}",
        kills,
        kills == 1,
        guard_still_unmapped,
        r2.state,
        pages_back,
        r2.drained
    );

    apic::timer_stop().ok();
    let ok = peek_ok_good
        && rejects
        && survived
        && window_closed
        && partition_ok
        && tramp_ok
        && peek_cleanup
        && peek_pages_back
        && peek_released
        && kills == 1
        && guard_still_unmapped
        && r2.state == sched::TaskState::Free
        && pages_back
        && r2.drained == Some(true);
    if !ok {
        crate::log_fatal!("abi: 判定不成立（上面四行是全部读数）");
    }
    ok
}
ktest!(KT_USER_POINTER, t_user_pointer_checks);
/// M4-3 第二段：跨页拷贝、窗口内的可恢复故障，以及"长度也是用户给的数"。
/// 七格判据与各自挡的错法在 §10.3.1 的表里，这里是清单：
/// ①② 内核→用户跨页写 512 字节由**程序逐字节**核对（`buf_ok == 1`、`buf_n == 0x200`；
///     "写满第一页、第二页没动"在内核侧看返回值看不出来，所以核对的一方必须是被写的那一边）；
/// ③ 用户→内核跨页读：内核算 FNV-1a，用例独立算同一个期望和，两数必须相等；
/// ④ 超 `COPY_MAX` 回 `TooLong`（拒绝而不是取小）；⑤ 往代码页写回 `NotWritable`；
/// ⑥ 第 2 页没映射要在校验阶段就回 `NotMapped` 且 `COPY_RECOVERED` 不动；
/// ⑦ 恢复路径本身用 `probe_copy_from` 走一次真故障：恰好搬成 8、计数 +1、AC 关、登记干净。
fn t_copy_user() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("copy: APIC 起不来");
        return false;
    }
    sched::init_boot_task();
    sched::start_workers();
    apic::timer_start().ok();
    let page_mask = (mm::PAGE as u64) - 1;
    let l = match user::load(HELLO_ELF) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("copy: 装载失败 —— {}", user::describe_load(e));
            apic::timer_stop().ok();
            return false;
        }
    };
    // 两个输入格都由内核经 SMAP 窗口写进去：`self_va` 给程序算跨页缓冲区的地址，
    // `flag` 选这一档实验。这就是 §10.3 "内核写用户内存"那一半，不是测试专用的后门。
    user::write_at(l.data_va + user::ABI_SLOT_SELF_VA, l.data_va);
    user::write_at(l.data_va + user::ABI_SLOT_FLAG, user::FLAG_BUF);
    let (base, entry, stack_top, owned) = (l.data_va, l.entry, l.stack_top, l.owned);
    let t = match sched::spawn_user(entry, stack_top, owned) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("copy: 任务建不起来 {:?}", e);
            apic::timer_stop().ok();
            return false;
        }
    };
    user::clear_counters();
    let calls = P7_CALLS + 3; // 主序列 + poke_buf + peek_buf + 那一次故意超限
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        while user::served() < calls && tsc::now().wrapping_sub(t0) < 200_000_000 {
            tsc::spin(20_000);
        }
        if !sched::wait_for_boot_task(300_000_000) {
            crate::log_fatal!("copy: 窗口收不了场");
        }
    });
    // `served()` 只证明那条超限请求**进过内核**，不证明程序已经回到用户态把返回值
    // 写进它自己的格子（实测：偶发一次读到 `buf_err=Some(0)`，而其余三格与全部计数器
    // 逐位相同 ⇒ 红了也说不出是谁的错）。这一格是程序最后写的那格，所以等它本身就等于
    // 等前面几格都落定；等不到就照原样失败，并把等了几轮打出来。
    let e_toolong_wait: u64 = (-(3i64)) as u64;
    let mut settle_reads = 0u32;
    let t_settle = tsc::now();
    while user::read_at(base + user::ABI_SLOT_BUF_ERR) != Some(e_toolong_wait) && settle_reads < 200_000 {
        settle_reads += 1;
        if tsc::now().wrapping_sub(t_settle) > 200_000_000 {
            break;
        }
        tsc::spin(20_000);
    }
    // 四格读数（页此刻还映射着、任务还活着，所以这里读得到；回收之后就读不到了）
    let self_back = user::read_at(base + user::ABI_SLOT_SELF_VA);
    let buf_ok = user::read_at(base + user::ABI_SLOT_BUF_OK);
    let buf_sum = user::read_at(base + user::ABI_SLOT_BUF_SUM);
    let buf_n = user::read_at(base + user::ABI_SLOT_BUF_N);
    let buf_err = user::read_at(base + user::ABI_SLOT_BUF_ERR);
    let kills_now = user::kills();
    let served_now = user::served();
    let expect_sum = user::fnv1a_over_pattern(user::BUF_LEN, |j| 0x5A ^ (j as u8));
    // **数值本身**，不是常量自己：`E_*` 也是会被人改的代码，而错误码是公开的 ABI，
    // 改错了的表现是旧程序把失败读成成功（§10.2"只增不改"那条的实际代价）。
    let e_inval: u64 = (-(1i64)) as u64;
    let e_fault: u64 = (-(2i64)) as u64;
    let e_toolong: u64 = (-(3i64)) as u64;
    crate::log_info!(
        "copy: buf_ok={:?} buf_n={:?} buf_sum={:?} expect_sum={:?} buf_err={:?} self_back={:?} 回填正确={} kills={} served={}/{} 等回填={} 周期={}",
        buf_ok,
        buf_n,
        buf_sum,
        expect_sum,
        buf_err,
        self_back,
        self_back == Some(base),
        kills_now,
        served_now,
        calls,
        settle_reads,
        tsc::now().wrapping_sub(t_settle)
    );
    crate::log_info!(
        "copy: 错误码数值 E_INVALID={:#x} E_FAULT={:#x} E_TOO_LONG={:#x} 三个都不同={}",
        user::E_INVALID,
        user::E_FAULT,
        user::E_TOO_LONG,
        user::E_INVALID != user::E_FAULT && user::E_FAULT != user::E_TOO_LONG
    );

    // ---- ④⑤⑥：三条必须在**拷贝之前**就失败的调用（不经 ABI，直接调函数）
    let too_long = user::copy_into_scratch(base, user::COPY_MAX + 1);
    let mut sink = [0u8; 16];
    let stack_page = stack_top & !page_mask;
    // 这一段的前 8 字节在栈页里、后 8 字节在**没映射**的那一页上：校验应当逐页看到第二页
    let straddle_unmapped = user::copy_from_user(stack_page + mm::PAGE as u64 - 8, &mut sink);
    let next_mapped = mm::is_mapped(stack_page + mm::PAGE as u64);
    let write_rx = user::copy_to_user(&[0u8; 16], entry);
    let rec_after_three = trap::COPY_RECOVERED.load(core::sync::atomic::Ordering::Relaxed);
    crate::log_info!(
        "copy: 超长={} 写代码页={} 跨未映射页={} 上面那页映射着={} 三条里恢复计数={}",
        matches!(too_long, Err(user::PtrError::TooLong)),
        matches!(write_rx, Err(user::PtrError::NotWritable)),
        matches!(straddle_unmapped, Err(user::PtrError::NotMapped)),
        next_mapped,
        rec_after_three
    );

    // ---- ⑦：恢复路径。`probe_copy_from` 跳过校验，所以这次访**真的**会故障。
    let got = user::probe_copy_from(stack_page + mm::PAGE as u64 - 8, 0x10);
    let recovered = trap::COPY_RECOVERED.load(core::sync::atomic::Ordering::Relaxed) - rec_after_three;
    let ac = user::ac_active();
    let probes_clean = trap::probe_registers_clear();
    let stale = trap::PF_STALE_HITS.load(core::sync::atomic::Ordering::Relaxed);
    crate::log_info!(
        "copy: 恢复路径 搬成={} 期望=8 接住次数={} ac={} 登记干净={} pf_stale_hits={} 槽位={:?}",
        got,
        recovered,
        ac,
        probes_clean,
        stale,
        sched::state_of(t)
    );
    let cleanup = sched::terminate_task(t);
    apic::timer_stop().ok();
    let pages_back = !mm::is_mapped(base) && !mm::is_mapped(stack_top);
    crate::log_info!(
        "copy: 判定 收尾={} 页已回收={} 恢复不重复={}",
        cleanup,
        pages_back,
        recovered == 1
    );
    buf_ok == Some(1)
        && buf_n == Some(user::BUF_LEN as u64)
        && buf_sum == Some(expect_sum)
        // `-3` 这一格是"每个号都得有人走过"那条规则的证人：程序故意超限，内核分开回
        && buf_err == Some(e_toolong)
        && user::E_INVALID == e_inval
        && user::E_FAULT == e_fault
        && user::E_TOO_LONG == e_toolong
        && self_back == Some(base)
        && kills_now == 0
        && served_now >= calls
        && matches!(too_long, Err(user::PtrError::TooLong))
        && matches!(write_rx, Err(user::PtrError::NotWritable))
        && matches!(straddle_unmapped, Err(user::PtrError::NotMapped))
        && !next_mapped
        && rec_after_three == 0
        && got == 8
        && recovered == 1
        && !ac
        && probes_clean
        && stale == 0
        && cleanup
        && pages_back
}
ktest!(KT_COPY_USER, t_copy_user);
/// M4-4：`syscall`/`sysret` 快路径。判据的原则是**读用户这一侧回来的事实**，
/// 不读内核里的常数（ADR-025 的"装机参数"表就是靠这一格兑现的）。
fn t_syscall_fastpath() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("fast: APIC 起不来");
        return false;
    }
    sched::init_boot_task();
    sched::start_workers();
    apic::timer_start().ok();
    let l = match user::load(HELLO_ELF) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("fast: 装载失败 —— {}", user::describe_load(e));
            apic::timer_stop().ok();
            return false;
        }
    };
    user::write_at(l.data_va + user::ABI_SLOT_FLAG, user::FLAG_FASTPATH);
    let (base, entry, stack_top, owned) = (l.data_va, l.entry, l.stack_top, l.owned);
    let t = match sched::spawn_user(entry, stack_top, owned) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("fast: 任务建不起来 {:?}", e);
            apic::timer_stop().ok();
            return false;
        }
    };
    user::clear_counters();
    // 主序列 32 次（`int 0x80`）+ `sys_abi_info` 1 次 + 快路径 8 次
    const FAST_CALLS: u64 = 8;
    let calls = P7_CALLS + 1 + FAST_CALLS;
    let back = apic::with_interrupts(|| {
        let t0 = tsc::now();
        while user::served() < calls && tsc::now().wrapping_sub(t0) < 200_000_000 {
            tsc::spin(20_000);
        }
        // 这条等待能收场**本身就是 IF 的判据**：快路径出口若把 IF 写成 0，
        // 这个任务就在自己的 `jmp .` 里关着中断死转，boot 上下文永远回不来（M4-1 实测过）。
        sched::wait_for_boot_task(300_000_000)
    });
    let abi = user::read_at(base + user::ABI_SLOT_ABI_WORD);
    let fast_ping = user::read_at(base + user::ABI_SLOT_FAST_PING);
    let fast_cs = user::read_at(base + user::ABI_SLOT_FAST_CS);
    let fast_ss = user::read_at(base + user::ABI_SLOT_FAST_SS);
    let kills = user::kills();
    let served = user::served();
    let (efer, star, lstar) = trap::fast_readback();
    let (fc, fmin, fcold, flead) = trap::p7_fast_of(crate::arch::x86_64::cpu::BSP_SLOT);
    let ints = trap::stats_syscall_of(crate::arch::x86_64::cpu::BSP_SLOT);
    let (area_kstack, area_slot) = trap::fast_area_of(crate::arch::x86_64::cpu::BSP_SLOT).unwrap_or((0, 0));
    let rsp0 = trap::rsp0_of(crate::arch::x86_64::cpu::BSP_SLOT);
    let (smep, smap) = crate::arch::x86_64::cpu::user_protections_active();
    let bits = abi.unwrap_or(0) & 0xFFFF;
    crate::log_info!(
        "fast: abi={:#x} major={} minor={} 位=[fast={} smap={} smep={}] ping={:?} cs={:?} ss={:?}",
        abi.unwrap_or(0),
        (abi.unwrap_or(0) >> 32) as u32,
        ((abi.unwrap_or(0) >> 16) & 0xFFFF) as u64,
        bits & user::F_FASTPATH != 0,
        bits & user::F_SMAP != 0,
        bits & user::F_SMEP != 0,
        fast_ping,
        fast_cs,
        fast_ss
    );
    crate::log_info!(
        "fast: 装机读回 efer={:#x} star={:#x} lstar={:#x} on={} 槽位={} rsp0={:#x} 区={:#x} 同源={}",
        efer,
        star,
        lstar,
        trap::fastpath_on(),
        area_slot,
        rsp0,
        area_kstack,
        rsp0 == area_kstack
    );
    crate::log_info!(
        "fast: P7 对比 int0x80[样本={} min={} mean={} max={} cold={}] vs syscall[样本={} min={:?} cold={} lead={:?}]",
        ints.faults,
        ints.min_cycles,
        ints.mean_cycles,
        ints.max_cycles,
        ints.cold_samples,
        fc,
        fmin,
        fcold,
        flead
    );
    let cleanup = sched::terminate_task(t);
    apic::timer_stop().ok();
    let ok = trap::fastpath_on()
        && efer & 1 != 0
        // 特性位：程序读到的那一位与内核自己读回的 CR4 两位必须讲同一件事（两台仪器）
        && (bits & user::F_FASTPATH != 0)
        && (bits & user::F_SMAP != 0) == smap
        && (bits & user::F_SMEP != 0) == smep
        && (abi.unwrap_or(0) >> 32) as u32 == user::ABI_MAJOR as u32
        && ((abi.unwrap_or(0) >> 16) & 0xFFFF) as u64 == user::ABI_MINOR
        // 返回值穿过边界 + 硬件从 STAR 算出的选择子被用户读回来
        && fast_ping.is_some_and(|v| v >= 1)
        && fast_cs == Some(0x23)
        && fast_ss == Some(0x1b)
        && fc >= FAST_CALLS
        && fmin > 0
        && served >= calls
        && back
        && kills == 0
        && trap::PF_STALE_HITS.load(core::sync::atomic::Ordering::Relaxed) == 0
        && rsp0 == area_kstack
        && cleanup
        && !mm::is_mapped(base);
    if !ok {
        crate::log_fatal!("fast: 判定不成立（上面四行是全部读数）");
    }
    ok
}
ktest!(KT_SYSCALL_FAST, t_syscall_fastpath);

/// M5-a：PCI 配置空间。判据的原则同 §10.3：**能互相独立的两台仪器优先**。
/// 这里配置读同时走 ECAM 与 CAM 两条硬件路径，两边必须数到同一个数。
fn t_pci_config() -> bool {
    let Some(i) = pci::info() else {
        crate::log_fatal!("pci: 没跑过 init（表是空的）");
        return false;
    };
    // ① 根复合体必须是 bus0 dev0 func0 且属于"桥"类；这条不依赖任何我对 Q35 的记忆
    let root = pci::dev(0);
    let root_bdf0 = root.is_some_and(|d| d.bdf == 0);
    // ② 定长表不许静默截断
    let no_truncate = !i.truncated && i.n >= 1;
    // ③ 不存在的槽位不许被记成设备（vendor 既不能是 0 也不能是 0xFFFF）
    let all_real = (0..i.n).filter_map(pci::dev).all(|d| d.vendor != 0 && d.vendor != 0xFFFF);
    // ④ **两条硬件路径读同一个 DWORD**：ECAM 是内存映射，CAM 是 0xCF8/0xCFC 端口，
    //    它们错不到一起去。先按 vendor/device 找一台设备，再比它的 class DWORD。
    let target = (0..i.n).filter_map(pci::dev).find(|d| d.bar0 != 0).or(root);
    let (via_ecam, via_cam, t_bdf) = match target {
        Some(d) => {
            let (b, dv, f) = (d.bdf >> 16, (d.bdf >> 11) & 31, (d.bdf >> 8) & 7);
            let e = pci::ecam_class(b, dv, f);
            let c = pci::cam_class(b, dv, f);
            (e, c, d.bdf)
        }
        None => (0, 0, 0),
    };
    let agree = target.is_some() && via_ecam == via_cam && via_ecam & 0xFFFF_FFFF != 0xFFFF_FFFF;
    crate::log_info!(
        "pci: 判据 root_bdf0={} 不截断={} 槽位真实={} 目标={:04x}:{:02x}.{} ECAM@08={:#010x} CAM@08={:#010x} 两路一致={}",
        root_bdf0,
        no_truncate,
        all_real,
        t_bdf >> 16,
        (t_bdf >> 11) & 31,
        (t_bdf >> 8) & 7,
        via_ecam,
        via_cam,
        agree
    );
    // ⑤ **MMIO 映射不占页框账**（§8.3 与 §6.3 的边界）：设备区间不是 PMM 发出去的帧，
    //    所以一次 map/drop 前后 `free_frames()` 与保留条数都必须回到原值。
    let lapic = acpi::summary().and_then(|s| s.madt).map(|m| m.lapic_base).unwrap_or(0);
    let frames_before = mm::free_frames();
    let res_before = mm::reservation_count();
    let mut mmio_ok = false;
    let mut cross_ok = false;
    let mut bounds_ok = false;
    if lapic != 0 {
        match hw::MmioRegion::map(lapic & !0xFFF, mm::PAGE) {
            Ok(r) => {
                // 与 apic 模块的读数交叉核对：同一个寄存器、两条访问路径
                let raw = r.read32(0x20).unwrap_or(0xFFFF_FFFF);
                // 0x20 是 LAPIC 的 ID 寄存器，xAPIC 下 ID 在 bits 31:24
                cross_ok = (raw >> 24) as u8 == apic::self_id() as u8;
                // 三格都要判，缺一就不知道检查是不是"永远拒绝"那种假安全：
                // 范围内必须成功、越界必须拒、未对齐必须拒。
                bounds_ok = r.read32(0x20).is_ok()
                    && matches!(r.read32(4096), Err(hw::HwError::OutOfRange))
                    && matches!(r.read32(1), Err(hw::HwError::NotAligned))
                    && matches!(r.write32(4096, 0), Err(hw::HwError::OutOfRange));
                drop(r);
                mmio_ok = mm::free_frames() == frames_before && mm::reservation_count() == res_before;
            }
            Err(e) => crate::log_fatal!("pci: LAPIC 二次映射失败 {:?}", e),
        }
    }
    crate::log_info!(
        "pci: MMIO lapic={:#x} 与 apic 读数一致={} 边界检查生效={} 页框与保留不变={} frames={}→{}",
        lapic,
        cross_ok,
        bounds_ok,
        mmio_ok,
        frames_before,
        mm::free_frames()
    );
    // ㉑ 的收尾：**已知设备 ⇒ 已知类别**。这不是"我读出来什么就承认什么"——
    // 期望值来自 PCI 规范给这几台设备的类别，读回来必须一致；四台不同族的设备
    // 同时成立才叫钉住解码表，字节序差一位就会崩在其中某一台上。
    const PIN: [(&str, u16, u16, u8, u8); 6] = [
        ("Q35 宿主", 0x8086, 0x29C0, 0x06, 0x00),
        ("Q35 宿主桥的另一半(SIC)", 0x8086, 0x29C1, 0x08, 0x00),
        ("virtio-vga/STD VGA", 0x1234, 0x1111, 0x03, 0x00),
        ("e1000 网卡", 0x8086, 0x10D3, 0x02, 0x00),
        ("ICH9 AHCI", 0x8086, 0x2922, 0x01, 0x06),
        ("ICH9 SMBus", 0x8086, 0x2930, 0x0C, 0x05),
    ];
    let mut pinned = 0usize;
    let mut wrong = 0usize;
    let mut hit_names = 0usize;
    for (name, vend, dev_id, want_class, want_sub) in PIN.iter() {
        match (0..i.n).filter_map(pci::dev).find(|d| d.vendor == *vend && d.device == *dev_id) {
            Some(d) => {
                hit_names += 1;
                if d.class() == *want_class && d.subclass() == *want_sub {
                    pinned += 1;
                } else {
                    wrong += 1;
                    crate::log_fatal!(
                        "pci: 解码表对不上 {} cfg08={:#010x} 解出 class={:#x}/sub={:#x} 期望 {:#x}/{:#x}",
                        name, d.cfg08, d.class(), d.subclass(), want_class, want_sub
                    );
                }
            }
            None => crate::log_info!("pci: 跳过 {}（这台机器上没有）", name),
        }
    }
    crate::log_info!(
        "pci: class 解码表 命中{}台 / 钉住{}台 / 对不上{}台（少于 4 台就不算钉住）",
        hit_names, pinned, wrong
    );
    let decode_pinned = wrong == 0 && pinned >= 4 && first_class_lookup_ok(&pinned);
    // M5-b①：BAR 尺寸探测与命令寄存器。**这一步会临时改设备的 BAR**，所以判据的重点
    // 不是"读到了数"，而是"改完能复原，且复原出来的尺寸真的管得住访问边界"。
    let mut restore_ok = false;
    let mut sizing_ok = false;
    let mut sized_bounds_ok = false;
    let mut cmd_ok = false;
    let mut abar_size = 0u64;
    if let Some(hba) = pci::first_of_triple(0x01, 0x06, 0x01) {
        let (b, dv, f) = hba.bdf_str();
        let cmd_before = hba.cfg32(0x04);
        crate::log_info!(
            "pci: 存储控制器 {:04x}:{:02x}.{} progif={:#04x} cmd={:#06x} bar=[{:#010x},{:#010x},{:#010x},{:#010x},{:#010x},{:#010x}]",
            b,
            dv,
            f,
            hba.progif(),
            cmd_before,
            hba.cfg32(0x10),
            hba.cfg32(0x14),
            hba.cfg32(0x18),
            hba.cfg32(0x1c),
            hba.cfg32(0x20),
            hba.cfg32(0x24)
        );
        // progif 必须是 0x01（AHCI）才轮到 M5-b 往下走：0x00 是旧式 ATA、0x02 是兼容模式，
        // 按它们写代码等于拿错整张寄存器表。class/subclass 已由上面的解码表钉住，这里读回来再判一次。
        let is_ahci = hba.class() == 0x01 && hba.subclass() == 0x06 && hba.progif() == 0x01;
        let bar5_before = hba.mem_bar(5);
        let sized = hba.size_mem_bar(5);
        abar_size = sized.size;
        restore_ok = sized.restored;
        sizing_ok = is_ahci && sized.size != 0 && bar5_before.is_some();
        // 尺寸不是读来好看的：按它建区间，最后一格必须读得到、越过一格必须被拒
        if let (Some((pa, _64)), true) = (bar5_before, sizing_ok) {
            match hw::MmioRegion::map(pa & !0xFFF, abar_size as usize) {
                Ok(r) => {
                    sized_bounds_ok = r.read32(0).is_ok()
                        && r.read32((abar_size - 4) as usize).is_ok()
                        && matches!(r.read32(abar_size as usize), Err(hw::HwError::OutOfRange));
                    drop(r);
                }
                Err(e) => crate::log_fatal!("pci: ABAR {:#x} 映射失败 {:?}", pa, e),
            }
        }
        // MSE(bit1)+BME(bit2) 置位后必须**读回**成立。DMA 要的是 BME：只开 MSE 的现场是
        // "寄存器读得好好的、传输永远不完成"。
        let after = hba.enable_command(0b110);
        cmd_ok = after & 0b110 == 0b110;
        crate::log_info!(
            "pci: ABAR 取证 bar5={:?} 尺寸={:#x} 还原={} AHCI判据成立={} 尺寸管住边界={} cmd {:#06x}→{:#06x} MSE|BME={}",
            bar5_before.map(|(a, _)| a),
            abar_size,
            restore_ok,
            sizing_ok,
            sized_bounds_ok,
            cmd_before,
            after,
            cmd_ok
        );
    }
    let ok = root_bdf0
        && no_truncate
        && all_real
        && agree
        && mmio_ok
        && cross_ok
        && bounds_ok
        && decode_pinned
        && restore_ok
        && sizing_ok
        && sized_bounds_ok
        && cmd_ok;
    if !ok {
        crate::log_fatal!("pci: 判定不成立（上面两行是全部读数）");
    }
    ok
}
/// 解码表钉住之后，"按类别找回 AHCI"才算有依据。这一格现在同时读两条路：
/// 三件套（`first_of_triple`）与单按 class（`first_of_class`）——后者**只用来暴露风险**，
/// 不作依据（挂上 virtio-blk 之后它的结果是"扫描顺序里的第一台存储设备"，不是 AHCI）。
fn first_class_lookup_ok(pinned: &usize) -> bool {
    if *pinned < 4 {
        return false;
    }
    // 三件套必须找回 ICH9 AHCI，**不管 class 0x01 有几台**。多挂一块 virtio-blk 之后这条
    // 从"能找回"变成"能在两台里挑对"，判据变强而不是变松（`first_of_class` 那一台是谁
    // 由扫描顺序决定，所以它不能再当依据）
    let (tv, td, ok) = match pci::first_of_triple(0x01, 0x06, 0x01) {
        Some(d) => (d.vendor, d.device, d.vendor == 0x8086 && d.device == 0x2922),
        None => (0, 0, false),
    };
    crate::log_info!(
        "pci: class 0x01 共 {} 台；三件套 01/06/01 找回 vend={:#06x} dev={:#06x}；单按 class 找回 vend={:#06x}",
        pci::count_of_class(0x01),
        tv,
        td,
        pci::first_of_class(0x01).map(|d| d.vendor).unwrap_or(0)
    );
    ok
}

ktest!(KT_PCI, t_pci_config);

/// M5-g①：中断认领**之前**的现场取证。这一格不改任何路径、不写"已交付"，
/// 它只回答一个问题：这台 QEMU + OVMF 上，我们从哪条路认领得到中断。
///
/// 三个读数决定 M5-g② 的形状：
/// ① 固件有没有往配置空间写 Interrupt Line。写了 ⇒ INTx 只要编程那条 RTE 就能试；
///    没写 ⇒ pin↔GSI 的表只能从 ACPI `_PRT` 拿，而 `_PRT` 要 AML ⇒ **那是 M5b，不在今天**。
/// ② `ich9-ahci` 有没有 MSI 块。有 ⇒ 向量与目的地由我们自己写进设备，**不需要那张表**。
/// ③ virtio（vendor `0x1AF4`）是 MSI-X 还是 INTx，表在哪块 BAR 的什么偏移。
///
/// 四条结构自洽判据是给我自己的读数立的门禁（偏移/掩码/链读错位时它们必须红），
/// 不是对硬件的要求——硬件给什么数都照打，打不出来才算失败。
#[cfg(feature = "irq-probe")]
fn t_irq_probe() -> bool {
    let Some(info) = pci::info() else {
        crate::log_fatal!("irq: 枚举表是空的，取证没法做");
        return false;
    };
    // 逐台设备的读数先攒着，判据只看"我这台仪器自不自洽"
    let mut n_pin = 0usize;
    let mut n_line_none = 0usize;
    let mut n_msi = 0usize;
    let mut n_msix = 0usize;
    let mut n_broken = 0usize;
    let mut n_virtio_msix = 0usize;
    let mut size_ok = true;
    let mut align_ok = true;
    let mut distinct_ok = true;
    let mut hops_ok = true;
    let mut shown = 0usize;

    for i in 0..info.n {
        let Some(d) = pci::dev(i) else { continue };
        let c = d.irq_caps();
        let (bus, dev, func) = d.bdf_str();
        shown += 1;
        if c.pin != 0 {
            n_pin += 1;
            if c.line == 0 {
                n_line_none += 1;
            }
        }
        if c.msi.is_some() {
            n_msi += 1;
        }
        if c.msix.is_some() {
            n_msix += 1;
            if d.vendor == 0x1AF4 {
                n_virtio_msix += 1;
            }
        }
        if c.broken.is_some() {
            n_broken += 1;
        }
        // 判据 A/B/C/D：都是"我读错位就会红"的形状
        if let Some(x) = c.msix {
            // A 表大小字段是"条数 - 1"，加回来之后不可能是 0
            if x.table_size == 0 {
                size_ok = false;
            }
            // B 表/PBA 的偏移按规范以 16 字节为粒度（低 4 位是保留位 + BIR）
            if x.table_off & 0xF != 0 || x.pba_off & 0xF != 0 {
                align_ok = false;
            }
        }
        // C 同一台设备上 MSI 与 MSI-X 不可能共用一个偏移（id 匹配错了才会）
        if let (Some(m), Some(x)) = (c.msi, c.msix) {
            if m.off == x.off {
                distinct_ok = false;
            }
        }
        // D 链上跳的次数不会比数到的块数少
        let blocks = usize::from(c.msi.is_some()) + usize::from(c.msix.is_some());
        if blocks > usize::from(c.hops) {
            hops_ok = false;
        }
        crate::log_info!(
            "irq: 取证 {:02x}:{:02x}.{} vid={:#06x} class={:02x}/{:02x}/{:02x} pin={} line={:#04x} hops={} 断={} msi={} msix={}",
            bus, dev, func, d.vendor, d.class(), d.subclass(), d.progif(),
            c.pin, c.line, c.hops, c.broken.unwrap_or("无"),
            match c.msi { Some(m) => alloc::format!("@{:#04x} en={} mmc={} 64={} pvm={}", m.off as u32, u8::from(m.enabled), m.mmc, u8::from(m.sixtyfour), u8::from(m.per_vector)), None => alloc::string::String::from("无") },
            match c.msix { Some(x) => alloc::format!("@{:#04x} 表={} fm={} BIR={}/偏移={:#x}", x.off as u32, x.table_size, u8::from(x.function_mask), x.table_bir, x.table_off), None => alloc::string::String::from("无") },
        );
    }

    // 第二遍：每台 `pin != 0` 且 `line != 0` 的设备，把它那条 RTE 的原样读数解出来。
    // 为什么必须读而不是引用规范：触发模式（电平/边沿）与极性决定"先服务还是先 EOI"，
    // 而这两格本内核**从来没写过**（`init` 只写了向量与屏蔽位），所以"固件留下来的是什么"
    // 只有从 IOAPIC 读回来才知道。规范说 PCI INTx 是电平，那是设备引脚的性质，
    // 不等于这张表里那一位被编程成了什么——两者不一致时以读数为准，并把不一致打出来。
    let io = apic::state();
    let mut shared_vec = false;
    for i in 0..info.n {
        let Some(d) = pci::dev(i) else { continue };
        let c = d.irq_caps();
        if c.pin == 0 || c.line == 0 {
            continue;
        }
        let (bus, dev, func) = d.bdf_str();
        match &io {
            Some(st) if u32::from(c.line) < st.gsi_base => crate::log_info!(
                "irq: RTE {:02x}:{:02x}.{} gsi={:#04x} 低于本 APIC 的 GSI 基 {} ⇒ 这条线不归它管（多 APIC 平台，M5-g② 之前必须先解决）",
                bus, dev, func, c.line, st.gsi_base
            ),
            Some(st) if u32::from(c.line) - st.gsi_base >= st.irt_entries => crate::log_info!(
                "irq: RTE {:02x}:{:02x}.{} gsi={:#04x} 超出本 APIC 的 {} 条表项",
                bus, dev, func, c.line, st.irt_entries
            ),
            Some(st) => {
                let rte = (c.line as u32 - st.gsi_base) as u8;
                match apic::rte_raw(rte) {
                    Some((lo, hi)) => {
                        let vec = (lo & 0xFF) as usize;
                        if vec == st.timer_vector {
                            shared_vec = true;
                        }
                        crate::log_info!(
                            "irq: RTE {:02x}:{:02x}.{} gsi={:#04x} 编号={} lo={:#010x} 向量={:#04x} 屏蔽={} 触发={} 极性={} 投递={} hi={:#010x} 目的地={:#04x}",
                            bus, dev, func, c.line, rte, lo, vec,
                            (lo >> 16) & 1, (lo >> 15) & 1, (lo >> 13) & 1, (lo >> 8) & 7, hi, hi >> 24
                        );
                    }
                    None => crate::log_info!("irq: RTE {:02x}:{:02x}.{} gsi={:#04x} 读不回来", bus, dev, func, c.line),
                }
            }
            None => crate::log_fatal!("irq: APIC 状态还没建起来，RTE 这一遍没法做"),
        }
    }

    // AHCI 那台（M5-g② 的第一颗候选）单独点名，读数决定走 MSI 还是 INTx
    let hba = pci::first_of_triple(0x01, 0x06, 0x01);
    let hba_found = hba.is_some();
    let hba_caps = hba.map(|d| d.irq_caps());
    // 定时器那条 RTE 的原样读数：触发模式/极性**今天没人写过它们**，所以"固件留的是什么"
    // 只能读回来。后面 EOI 与重发的规矩要建在这个数上，不是建在"规范说电平"上。
    let timer_rte = apic::state().and_then(|st| apic::rte_raw(st.timer_rte).map(|v| (v, st.timer_rte, st.timer_gsi, st.timer_vector)));

    let ok = size_ok && align_ok && distinct_ok && hops_ok && hba_found;
    crate::log_info!(
        "irq: 取证判据 台数={} 有pin={} 有pin而line为0={} MSI={} MSI-X={} 链断={} virtio有MSIX={} 仪器自洽={}/{}/{}/{} AHCI={} AHCI的msi={} AHCI的msix={} AHCI的pin={} 有设备线与定时器共用同一向量={}",
        shown, n_pin, n_line_none, n_msi, n_msix, n_broken, n_virtio_msix,
        size_ok, align_ok, distinct_ok, hops_ok,
        hba_found,
        hba_caps.map_or(false, |c| c.msi.is_some()),
        hba_caps.map_or(false, |c| c.msix.is_some()),
        hba_caps.map_or(0, |c| c.pin),
        shared_vec,
    );
    match timer_rte {
        Some(((lo, hi), rte, gsi, want_vec)) => crate::log_info!(
            "irq: 取证 RTE gsi={} 编号={} 表项={} gsi基={:#x} lo={:#010x} hi={:#010x} 解码向量={:#04x} 与内核写的一致={} 屏蔽={} 触发={} 极性={} 投递模式={} 目的地={:#04x}",
            gsi, rte, io.as_ref().map_or(0, |s| s.irt_entries), io.as_ref().map_or(0, |s| s.gsi_base),
            lo, hi, lo & 0xFF, (lo as usize & 0xFF) == want_vec,
            (lo >> 16) & 1, (lo >> 15) & 1, (lo >> 13) & 1, (lo >> 8) & 7, hi >> 24
        ),
        None => crate::log_fatal!("irq: 定时器 RTE 读不回来（IOAPIC 没映射上或编号越界）⇒ 认领那一步的界检查没有依据"),
    }
    crate::log_info!(
        "irq: 已用向量 定时器={:#x} 每核定时器={:#x} shootdown={:#x} 杂凑={:#x} 外部向量区间={:#x}..{:#x}；认领表=还没做（这一格只取证）",
        trap::VEC_IRQ_BASE, trap::VEC_CPU_TIMER, trap::VEC_SHOOTDOWN, trap::VEC_SPURIOUS,
        trap::VEC_IRQ_BASE, trap::VEC_IRQ_LAST
    );
    if !ok {
        crate::log_fatal!("irq: 取证判据不成立（上面每台设备一行读数）");
    }
    ok
}
#[cfg(feature = "irq-probe")]
ktest!(KT_IRQ_PROBE, t_irq_probe);

/// M5-b②：认领 AHCI 主机控制器并枚举端口（到"认得出哪一口挂着盘"为止）。
///
/// 判据的形状是"**位写得进去、也经得起复位清；基址读回来就是我们写的那两个数**"：
/// 1 `GHC.AE` 读回成立，`GHC.HR` 在有界窗口内自己清零。
/// 2 端口 0 的 `PxCMD` 收得住 `FRE`，`HR` 之后又回到复位值 0——这一条同时验住 GHC 的
///   偏移、HR 的位、端口块基址 `0x100`、`PxCMD` 的偏移、`FRE` 的位（五件事一次过）。
/// 3 `PI` 位图与 `CAP.NP+1` 必须数到同一个端口数：两个独立字段互证。
/// 4 `VS` 主版本号 ≥ 1：端口块基址 `0x100` 只对 AHCI 1.0 及以后成立。
/// 5 每一口的 `PxCLB`/`PxFB` 读回来等于写进去的数（对齐保留位是只读 0，所以这一条
///   同时验住偏移、基址和那张表的对齐）。
/// 6 `FRE→FR`、`ST→CR` 每口都跟上：任一位写错就等不到，不可能假绿。
/// 7 认得出在位的 SATA 磁盘：`det=0b0011` 且 `PxSIG=0x00000101`，而设备写来的那条 FIS
///   的类型字节必须是 D2H（`0x34`）。
/// 8 页框账对得上：`free_frames` 少掉的数必须等于"环形结构 4 帧 + 新建页表页"，
///   而资源台账里 `MOD_AHCI` 的存活帧数必须报同一个 4（§6.7 那本账在真设备上也要平）。
fn t_ahci_claim() -> bool {
    let Some(dev) = pci::first_of_triple(0x01, 0x06, 0x01) else {
        crate::log_fatal!("ahci: 枚举表里没有 SATA-AHCI 那台（PCI 那条用例先红了）");
        return false;
    };
    let bar_before = dev.mem_bar(5);
    // 先幂等地确保认领已完成，再量"这一次调用本身"动了什么：`.ktests` 段的顺序不跟着
    // 源码顺序走（实测），所以"谁做第一次认领"不能写死在判据里
    let _ = ahci::init();
    let frames_before = mm::free_frames();
    let pt_before = mm::counters().page_table_pages;
    let live_before = resource::live_of(ahci::MOD_AHCI);
    let i = match ahci::init() {
        Ok(i) => i,
        Err(e) => {
            crate::log_fatal!("ahci: 认领失败 {:?}", e);
            return false;
        }
    };
    let e = match ahci::enumerate() {
        Ok(e) => e,
        Err(err) => {
            crate::log_fatal!("ahci: 端口枚举失败 {:?}", err);
            return false;
        }
    };
    let frames_used = frames_before.saturating_sub(mm::free_frames());
    let pt_delta = mm::counters().page_table_pages.saturating_sub(pt_before);
    let live_now = resource::live_of(ahci::MOD_AHCI);
    let ghc_now = ahci::global(ahci::REG_GHC).unwrap_or(0xFFFF_FFFF);
    let pi_now = ahci::global(ahci::REG_PI).unwrap_or(0xFFFF_FFFF);
    let ae_ok = ghc_now & ahci::REG_GHC_AE != 0 && ghc_now & ahci::REG_GHC_HR == 0;
    // 只咬"写进去的那一位被复位清掉了"：`HR` 之后 `PxCMD` 实测读回 0x6（SUD|POD 亮），
    // 那是 QEMU 给挂着设备的端口置的位，不是我写的——要求整寄存器归 0 是我多要了一格
    let scope_ok = i.cmd_fre_written & ahci::CMD_FRE != 0 && i.cmd_after_hr & ahci::CMD_FRE == 0;
    let ports_agree =
        i.ports == i.cap_ports && u8::try_from(pi_now.count_ones()) == Ok(i.ports) && pi_now == i.pi;
    let version_ok = (i.vs >> 16) >= 1;
    let space_ok = ahci::PORTS_BASE as u64 + ahci::PORT_STRIDE as u64 * u64::from(i.ports) <= i.size;
    let started_all = if boot_guard::optional_devices_allowed() {
        e.n == usize::from(i.ports)
    } else {
        // 安全模式：只该起到第一块有盘的口为止
        e.n == 1 && e.n_disks >= 1
    };
    let handshakes = e.ports[..e.n].iter().all(|p| p.fr && p.cr);
    let tables_ok = e.ports[..e.n].iter().all(|p| {
        p.clb == i.ring_pa as u32
            && p.fb == (i.ring_pa + ahci::OFF_RXFIS + ahci::RX_BYTES * u64::from(p.num)) as u32
    });
    let disk = e.disk.map(|n| e.ports[usize::from(n)].num);
    let cfg_intact = dev.mem_bar(5) == bar_before && dev.cfg32(0x04) & 0b110 == 0b110;
    // 第二次认领不许再分配：`live_before` 已经是一份环形结构的量
    let accounted =
        frames_used == pt_delta && live_before == ahci::RING_PAGES && live_now == ahci::RING_PAGES;
    crate::log_info!(
        "ahci: 认领 {:04x}:{:02x}.{} abar={:#x} 尺寸={:#x} cap={:#010x} vs={:#010x} 槽={} 端口={}(PI)/{}(CAP) ghc {:#010x}→{:#010x}→{:#010x}→{:#010x} cap2={:#010x} 复位后sig={:#010x} clb={:#010x} SAM={} S64A={}",
        i.bdf >> 16,
        (i.bdf >> 11) & 31,
        (i.bdf >> 8) & 7,
        i.abar,
        i.size,
        i.cap,
        i.vs,
        i.slots,
        i.pi.count_ones(),
        i.cap_ports,
        i.ghc_before,
        i.ghc_ae,
        i.ghc_hr,
        i.ghc_after,
        i.cap2,
        i.sig_after_hr,
        i.clb_after_hr,
        i.sam,
        i.s64a
    );
    for p in e.ports[..e.n].iter() {
        crate::log_info!(
            "ahci: 口{} cmd={:#010x} clb={:#010x} fb={:#010x} is={:#010x} tfd={:#06x} sig={:#010x} ssts={:#010x} d2h={:#04x}",
            p.num,
            p.cmd,
            p.clb,
            p.fb,
            p.is,
            p.tfd,
            p.sig,
            p.ssts,
            p.d2h_type
        );
    }
    crate::log_info!(
        "ahci: 判据 AE且HR清={} 复位作用域={} 端口数互证={} 版本>=1={} 区域够={} 口起齐={} FR|CR={} 表读回={} 磁盘口={:?} 无全1={} 配置没坏={} 本次页框用掉={} 页表新增={} 台账存活={}+={} 本次没多分配={}",
        ae_ok,
        scope_ok,
        ports_agree,
        version_ok,
        space_ok,
        started_all,
        handshakes,
        tables_ok,
        disk,
        i.reads_ff == 0,
        cfg_intact,
        frames_used,
        pt_delta,
        live_before,
        live_now,
        accounted
    );
    let ok = ae_ok
        && scope_ok
        && ports_agree
        && version_ok
        && space_ok
        && started_all
        && handshakes
        && tables_ok
        && disk.is_some()
        && i.reads_ff == 0
        && cfg_intact
        && accounted;
    if !ok {
        crate::log_fatal!("ahci: 判定不成立（上面几行是全部读数）");
    }
    ok
}
ktest!(KT_AHCI, t_ahci_claim);

/// M5-b③：第一条真 DMA 读。判据的落点是**内容**，不是寄存器。
///
/// 1 LBA 0：扇区末尾两字节必须是 MBR 签名 `0x55AA`。
/// 2 LBA 1：前 8 字节必须是 `EFI PART`（GPT 头）。这两条都是人眼能核的见证。
/// 3 两次读的哈希**必须不同**：LBA 那几格要是没起作用，两次就是同一个块，而
///   "同一个块读两次都一样"看着比现在还绿。
/// 4 设备自报的 PRDBC 等于请求字节数，而且数据缓冲里一个哨兵 `0xEE` 都不剩
///   （"没搬"与"搬回一堆 0"必须分得开，见 `ahci::fill` 那段注释）。
/// 5 两台仪器一致：端口侧 `PxTFD` 与接收区那条 D2H 的状态必须相等；签名也一样。
/// 6 哈希本身由 `tools/aurora.py` 与宿主机上的镜像对账——那是**另一个进程里的仪器**，
///   所以这条判据不受"驱动自己说自己对"污染。
fn t_ahci_disk() -> bool {
    if ahci::info().is_none() {
        let _ = ahci::init();
    }
    let e = match ahci::enumerate() {
        Ok(e) => e,
        Err(err) => {
            crate::log_fatal!("ahci: 读块之前枚举端口失败 {:?}", err);
            return false;
        }
    };
    let Some(disk) = e.disk else {
        crate::log_fatal!("ahci: 没有端口报在位的 SATA 磁盘（上面每口的读数就是证据）");
        return false;
    };
    let r0 = match ahci::read_lba(disk, 0, 1) {
        Ok(r) => r,
        Err(err) => {
            crate::log_fatal!("ahci: 读 LBA0 失败 {:?}", err);
            return false;
        }
    };
    let tail0 = ahci::mbr_tail().unwrap_or([0; 2]);
    // 保护 MBR 的分区表项：引导标志（0x1BE）必须是 0，类型（0x1C2）必须是 `0xEE`（GPT 的要求）。
    // 偏移按 GPT 的固定布局给（表项从 0x1BE 起、类型是表项内第 4 字节）。宿主机上量回来的
    // 整个扇区里 `0xEE` **只出现在 0x1C2 这一格** —— 也就是前面"哨兵剩 1"的那一格。
    // 位置敏感的见证要用绝对偏移，而且**必须在下一次读覆盖缓冲之前取**（第一版取晚了，
    // 量到的是 LBA1 的 GPT 头，读出来 0x00 就报假失败）。
    let pmbr_ok = ahci::data_at(0x1BE) == Ok(0x00) && ahci::data_at(0x1C2) == Ok(0xEE);
    let r1 = match ahci::read_lba(disk, 1, 1) {
        Ok(r) => r,
        Err(err) => {
            crate::log_fatal!("ahci: 读 LBA1 失败 {:?}", err);
            return false;
        }
    };
    let head1 = ahci::data_head(16).unwrap_or([0; 16]);
    // M5-c：**跨 255 扇区边界**的一次读（257 × 512 = 131584 字节）。
    // 这条是"扇区数高字节"唯一的现场判据：单扇区的读对计数放错位置不敏感
    // （`count=0` 时 QEMU 用 PRD 的字节数封顶，两边都读成 1 个扇区），而这次
    // PRD 与 count 必须互相对上，否则 `ahci_populate_sglist` 直接 `-1` 把命令丢掉 ⇒ 当场红。
    let big = match ahci::read_lba(disk, 0, 257) {
        Ok(r) => r,
        Err(err) => {
            crate::log_fatal!("ahci: 读 257 个扇区失败 {:?}", err);
            return false;
        }
    };
    // 缓冲现在装着 LBA 0..257：**开头那一扇区必须还是同一条 MBR**（证明长传输的起点没错），
    // 而整段哈希必须与单扇区那次不同（证明它真的搬了 257 个扇区而不是 1 个）
    let big_prefix_ok = ahci::data_at(0x1C2) == Ok(0xEE) && ahci::data_at(0x1FF) == Ok(0xAA);
    let big_wider = big.hash != r0.hash;
    // **同长度对读**：长读的最后一个扇区，必须等于单独读那一个扇区的结果。
    // 这条不需要阈值，也不需要"内容该是什么"的先验：负样本把扇区数高字节放错时，
    // QEMU 只搬第一个扇区就报完成，长读的尾巴还是哨兵 ⇒ 这里当场不相等（内核里就红）。
    let mut big_tail = [0u8; 512];
    let mut one_sector = [0u8; 512];
    let mut r_last = None;
    if ahci::copy_out(big.want as u64 - 512, &mut big_tail).is_ok() {
        if let Ok(r) = ahci::read_lba(disk, 256, 1) {
            if ahci::copy_out(0, &mut one_sector).is_ok() {
                r_last = Some(r);
            }
        }
    }
    let tail_same = r_last.is_some() && big_tail == one_sector && big_tail != [0xEEu8; 512];
    if let Some(r) = &r_last {
        crate::log_info!(
            "ahci: 读 lba=256 计数=1 端口={} 请求={}字节 状态={:#04x} 尾扇区一致={} 哈希={:#018x}",
            r.port,
            r.want,
            r.status,
            tail_same,
            r.hash
        );
    } else {
        crate::log_fatal!("ahci: 长读收尾对读没做成（tail_same=false 的成因是这条读不到）");
    }
    crate::log_info!(
        "ahci: 读 lba=0 计数=257 端口={} 请求={}字节 状态={:#04x} 前缀同一段={} 比单扇区长={} 哈希={:#018x}",
        big.port,
        big.want,
        big.status,
        big_prefix_ok,
        big_wider,
        big.hash
    );
    // 负样本：只改**报出去的标签**，不改读的东西。注入下内核自判的每一格都还成立，
    // 必须让宿主机那台仪器来叫（`tools/aurora.py` 的 `check_disk_content`）
    let printed1 = if cfg!(feature = "fault-ahci-lba") { 0 } else { 1 };
    crate::log_info!(
        "ahci: 读 lba=0 计数=1 端口={} 表头DW1={:#010x} 请求={}字节 状态={:#04x} 签名={:#010x}/{:#010x} 哨兵剩={} 哈希={:#018x} 尾两字节={:#04x}{:#04x}",
        r0.port,
        r0.dw1,
        r0.want,
        r0.status,
        r0.sig_port,
        r0.sig_d2h,
        r0.untouched,
        r0.hash,
        tail0[0],
        tail0[1]
    );
    crate::log_info!(
        "ahci: 读 lba={} 计数=1 端口={} 表头DW1={:#010x} 请求={}字节 状态={:#04x} 签名={:#010x}/{:#010x} 哨兵剩={} 哈希={:#018x} 头8字节={}{}{}{}{}{}{}{}",
        printed1,
        r1.port,
        r1.dw1,
        r1.want,
        r1.status,
        r1.sig_port,
        r1.sig_d2h,
        r1.untouched,
        r1.hash,
        head1[0] as char,
        head1[1] as char,
        head1[2] as char,
        head1[3] as char,
        head1[4] as char,
        head1[5] as char,
        head1[6] as char,
        head1[7] as char
    );
    let mbr_ok = tail0 == [0x55, 0xAA];
    let gpt_ok = &head1[0..8] == b"EFI PART";
    let distinct = r0.hash != r1.hash;
    // "搬到位"判在内容上，不判在设备自报的字节数上：本机 QEMU 把已搬字节数报在表头
    // DW1 的低 16 位，而规范的 PRDBC 在 bits 31:16（两者都对不上"判据"这个词）。
    let content_ok = mbr_ok && gpt_ok && distinct && pmbr_ok;
    let instruments = r0.status == r1.status
        && r0.sig_port == ahci::SIG_SATA_DISK
        && r0.sig_d2h == r0.sig_port
        && r0.d2h_type == ahci::FIS_TYPE_D2H;
    let ok = content_ok && instruments && big_prefix_ok && big_wider && tail_same;
    if !ok {
        crate::log_fatal!(
            "ahci: 内容判据不成立 MBR={} 保护类型0xEE={} GPT={} 两次不同={} 两台仪器={} 长读前缀={} 长读更宽={} 尾扇区一致={}",
            mbr_ok,
            pmbr_ok,
            gpt_ok,
            distinct,
            instruments,
            big_prefix_ok,
            big_wider,
            tail_same
        );
    }
    ok
}
ktest!(KT_AHCI_DISK, t_ahci_disk);

#[cfg(feature = "ahci-scratch")]
/// M5-c②：把 LBA 的**高位三格**从"只有出处"变成"有判据"。
///
/// 需要第二块盘（`tools/aurora.py` 造 130 GiB 的 qcow2 挂在口 2，并在 `LBA = 2^28` 那一格写
/// 512 字节的 `0xA5`）。为什么只有这条路：这条 64 MiB 的引导盘最大 LBA 是 `0x1FFFF` ⇒
/// 字节 8/9/10 恒为 0，写错也没人看得见（我第一版就把字节 8 按 `>>32` 写过）。
/// 判据是**配方对账**，不是驱动自证：
/// 1 高 LBA 那一格必须 512 个字节全是 `0xA5`（不等于它的个数 = 0）；
/// 2 同一块盘的 LBA 0 必须全是 0 —— 控制组：证明这两次读读的是**不同**的地方；
/// 3 引导盘（LBA 1 写着 `EFI PART` 的那一口）不许被当成第二块盘；
/// 4 两次的哈希必须不同。
/// 负样本 `fault-ahci-highlba` 把字节 8 改回 `>>32` ⇒ 设备读到 LBA 0 的全零扇区 ⇒ 必须红。
fn t_ahci_high_lba() -> bool {
    let e = match ahci::enumerate() {
        Ok(e) => e,
        Err(err) => {
            crate::log_fatal!("high: 枚举失败 {:?}", err);
            return false;
        }
    };
    if e.n_disks < 2 {
        crate::log_fatal!("high: 带 ahci-scratch 的构建只认到 {} 块在位的盘，第二块没挂上", e.n_disks);
        return false;
    }
    // 引导盘的身份证是内容，不是口号：它的 LBA 1 写着 `EFI PART`
    let mut boot = None;
    let mut scratch = None;
    for i in 0..e.n_disks {
        let p = e.disks[i];
        if let Err(err) = ahci::read_lba(p, 1, 1) {
            crate::log_fatal!("high: 口{} 读 LBA1 失败 {:?}", p, err);
            return false;
        }
        let is_gpt = ahci::data_head(8).map(|h| &h[0..8] == b"EFI PART").unwrap_or(false);
        if is_gpt {
            if boot.is_none() {
                boot = Some(p);
            }
        } else if scratch.is_none() {
            scratch = Some(p);
        }
    }
    let Some(sc) = scratch else {
        crate::log_fatal!("high: 没找到第二块盘（引导盘口={:?}）", boot);
        return false;
    };
    let hi = match ahci::read_lba(sc, 1 << 28, 1) {
        Ok(r) => r,
        Err(err) => {
            crate::log_fatal!("high: 读 LBA 2^28 失败 {:?}", err);
            return false;
        }
    };
    let hi_bad = ahci::data_diff_count(0xA5, 512).unwrap_or(usize::MAX);
    let lo = match ahci::read_lba(sc, 0, 1) {
        Ok(r) => r,
        Err(err) => {
            crate::log_fatal!("high: 读第二块盘的 LBA 0 失败 {:?}", err);
            return false;
        }
    };
    let lo_bad = ahci::data_diff_count(0x00, 512).unwrap_or(usize::MAX);
    crate::log_info!(
        "ahci: 高LBA 第二块盘口={} 引导盘口={:?} LBA2^28 里非A5的字节={} 哈希={:#018x}",
        sc,
        boot,
        hi_bad,
        hi.hash
    );
    crate::log_info!(
        "ahci: 高LBA 控制组 LBA0 里非零的字节={} 哈希={:#018x} 两次不同={}",
        lo_bad,
        lo.hash,
        hi.hash != lo.hash
    );
    let ok = hi_bad == 0 && lo_bad == 0 && hi.hash != lo.hash && boot.is_some() && boot != Some(sc);
    if !ok {
        crate::log_fatal!("high: 高位判据不成立（上面两行是全部读数）");
    }
    ok
}
#[cfg(feature = "ahci-scratch")]
ktest!(KT_AHCI_HIGH_LBA, t_ahci_high_lba);

#[cfg(feature = "ahci-scratch")]
/// M5-c③：写方向。判据全部落在**内容**上，不看"命令有没有完成"。
///
/// 只允许写第二块盘（scratch）：引导盘是这套测试自己的产物，写坏一次就得重造镜像才能复现，
/// 那种"顺手把被测对象改了"的做法在这里不接受。目标偏移选 LBA 4096 起 8 个扇区——
/// 离高 LBA 图案那一格（`2^28`）和读用例碰过的区间都远，互不污染。
///
/// 四格判据（缺一格就有一种错法能混过去）：
/// 1 **写之前的哈希 ≠ 写之后的哈希**：什么都不写、或写被静默丢掉，这一格先拦住；
/// 2 回读内容与 `pattern_byte(LBA, 序号)` **逐字节相同**：图案与 LBA 绑定，所以
///   "写到别的偏移去了"和"只写了第一个扇区"都过不了；
/// 3 紧接着在**另一个 LBA** 再写一段，然后回读第一段：图案必须仍然逐字节相同。
///   这一条才有咬合——"扇区数没生效、只搬了 1 个扇区"其实已经被第 2 条抓住了
///   （其余 7 个扇区还是旧内容，逐字节比对当场就不等），而我第一版在这里写的是
///   "第 1 与第 8 个扇区的首字节必须不同"，那是条**恒不成立也不报错的错判据**：
///   图案按 256 字节取模，两个扇区的首字节天然相同（实测两条都读出 `0x3c`）。
///   换成不覆盖判据：第二次的写如果落到了第一段上（地址没生效），第 2 条就会红；
/// 4 读回的哈希由 `tools/aurora.py` 与宿主机对账（QEMU 退出后用 `qemu-io` 读那个偏移）——
///   内核这一侧的 2、3 两条都在同一个进程里算，只有这一条是另一台仪器。
fn t_ahci_write() -> bool {
    let e = match ahci::enumerate() {
        Ok(e) => e,
        Err(err) => {
            crate::log_fatal!("write: 枚举失败 {:?}", err);
            return false;
        }
    };
    let mut boot = None;
    let mut scratch = None;
    for i in 0..e.n_disks {
        let p = e.disks[i];
        if let Err(err) = ahci::read_lba(p, 1, 1) {
            crate::log_warn!("write: 口{} 读 LBA1 失败 {:?}，这块不参与分类", p, err);
            continue;
        }
        let is_gpt = ahci::data_head(8).map(|h| &h[0..8] == b"EFI PART").unwrap_or(false);
        crate::log_info!("write: 候选口={} GPT={}", p, is_gpt);
        if is_gpt && boot.is_none() {
            boot = Some(p);
        } else if !is_gpt && scratch.is_none() {
            scratch = Some(p);
        }
    }
    let Some(sc) = scratch else {
        crate::log_fatal!(
            "write: 没找到可写的那块盘（引导盘口={:?} 起口数={} 枚举到的盘数={}）",
            boot,
            e.n,
            e.n_disks
        );
        return false;
    };
    const TARGET_LBA: u64 = 4096;
    const SECS: u16 = 8;
    let before = match ahci::read_lba(sc, TARGET_LBA, SECS) {
        Ok(r) => r.hash,
        Err(err) => {
            crate::log_fatal!("write: 写之前读 LBA{} 失败 {:?}", TARGET_LBA, err);
            return false;
        }
    };
    match ahci::write_lba(sc, TARGET_LBA, SECS) {
        Ok(r) => crate::log_info!(
            "write: 写完 口={} 状态={:#04x} 表头DW1={:#010x} 缓冲哈希={:#018x}",
            r.port,
            r.status,
            r.dw1,
            r.hash
        ),
        Err(err) => {
            crate::log_fatal!("write: 写 LBA{} 失败 {:?}", TARGET_LBA, err);
            return false;
        }
    }
    let back = match ahci::read_lba(sc, TARGET_LBA, SECS) {
        Ok(r) => r,
        Err(err) => {
            crate::log_fatal!("write: 回读 LBA{} 失败 {:?}", TARGET_LBA, err);
            return false;
        }
    };
    // 逐字节比对：图案由同一个式子供两头用（这里 + 宿主机的 `qemu-io` 那边）
    let mut mismatches = 0usize;
    for i in 0..(u64::from(SECS) * ahci::SECTOR) {
        let want = ahci::pattern_byte(TARGET_LBA, i);
        match ahci::data_at(i as usize) {
            Ok(got) => {
                if got != want {
                    mismatches += 1;
                }
            }
            Err(_) => mismatches += 1,
        }
    }
    let changed = back.hash != before;
    let exact = mismatches == 0;
    // 判据 3：在**下一段** LBA 上再写一次，然后回读第一段——还是原来的图案才算"地址真的生效"。
    // 第一版这里比的是"第 1 扇区与第 8 扇区的首字节不同"，那是条错的恒等式（图案周期 256 字节）
    let mut clobbered = 0usize;
    if ahci::write_lba(sc, TARGET_LBA + u64::from(SECS), SECS).is_ok() {
        if let Ok(r2) = ahci::read_lba(sc, TARGET_LBA, SECS) {
            for i in 0..(u64::from(SECS) * ahci::SECTOR) {
                if ahci::data_at(i as usize) != Ok(ahci::pattern_byte(TARGET_LBA, i)) {
                    clobbered += 1;
                }
            }
            let _ = r2;
        }
    }
    let no_clobber = clobbered == 0;
    crate::log_info!(
        "ahci: 写 lba={} 计数={} 端口={} 前哈希={:#018x} 后哈希={:#018x} 图案不一致={} 第二段没盖住第一段={} 被盖字节={}",
        TARGET_LBA,
        SECS,
        sc,
        before,
        back.hash,
        mismatches,
        no_clobber,
        clobbered
    );
    let ok = changed && exact && no_clobber && boot.is_some() && boot != Some(sc);
    if !ok {
        crate::log_fatal!(
            "write: 判据不成立 改了={} 逐字节={} 第二段没盖住第一段={}",
            changed,
            exact,
            no_clobber
        );
    }
    ok
}
#[cfg(feature = "ahci-scratch")]
ktest!(KT_AHCI_WRITE, t_ahci_write);

#[cfg(feature = "ahci-scratch")]
/// M5-d：§8.2 的"驱动故障可重置或隔离"，按手册那张状态机走。
///
/// 四格各挡一种错法（顺序就是函数体的顺序）：
/// 1 **干净错误不许触发 reset**：注入非法命令码，设备以 `ERR` 正常完成。
///   这一格同时给注入本身立判据（必须是 `BadCompletion` 且计数 +1），
///   否则"没抖控制器"会因为"根本没出错"而假绿。
/// 2 **卡住类错误必须走 `Resetting` 并恢复**：清掉 `ST` ⇒ 命令没人接走 ⇒ `PxCI`
///   恒为 1 ⇒ 超时；恢复里把端口重新起起来 ⇒ 下一条命令必须读回原来的内容。
/// 3 **修不好就必须隔离**：让 `start_port` 对这个口必然失败，重试到预算 ⇒
///   `Quarantined`，之后的命令**没下发就返回**——判据是 `resets` 不再增长，
///   不是"返回了 Err"（真又试一次也返回 Err，两种情形必须分得开）。
/// 4 **隔离的粒度是端口，不是驱动**：受害口的重置计数恰好停在预算上、引导口恒为 0，
///   且引导盘照常读出 `EFI PART`。
///   这一格才是"一个错误导致不了系统崩溃"的那条硬要求在本机的形状。
fn t_ahci_recovery() -> bool {
    let e = match ahci::enumerate() {
        Ok(e) => e,
        Err(err) => {
            crate::log_fatal!("recover: 枚举失败 {:?}", err);
            return false;
        }
    };
    let mut boot = None;
    let mut victim = None;
    for i in 0..e.n_disks {
        let p = e.disks[i];
        if ahci::read_lba(p, 1, 1).is_err() {
            continue;
        }
        let is_gpt = ahci::data_head(8).map(|h| &h[0..8] == b"EFI PART").unwrap_or(false);
        if is_gpt && boot.is_none() {
            boot = Some(p);
        } else if !is_gpt && victim.is_none() {
            victim = Some(p);
        }
    }
    let (Some(bt), Some(vi)) = (boot, victim) else {
        crate::log_fatal!("recover: 需要两块盘（引导盘口={:?} 受害口={:?}）", boot, victim);
        return false;
    };
    let Ok(baseline) = ahci::read_lba(vi, 4096, 8).map(|r| r.hash) else {
        crate::log_fatal!("recover: 受害口的基线读失败");
        return false;
    };
    let st0 = ahci::stats();
    // "整段都是自己的"：内容对得上基线，**且设备自报的字节数等于请求的字节数**。
    // 后半条不是装饰：恢复路径上端口里可能还挂着上一条没答完的命令，它完成后
    // 会把 DMA 和回执留在接收区里，只看哈希就会把"读到旧命令的回执"读成"恢复了"
    // （实测出现过：请求 8 个扇区、`PRDBC` 只有 512 字节，哈希因此不同）。
    let got_whole = |r: &Result<ahci::Xfer, ahci::AhciError>| match r {
        Ok(x) => x.hash == baseline && x.dw1 == x.want,
        Err(_) => false,
    };

    // 1 干净错误：非法命令码。设备以 READY|ERR 完成、命令位照样落下，所以这才是
    // "检测到了但不该抖控制器"那一格的形状（越界读在这台设备上根本不算错，见 BACKLOG ㉞）
    ahci::set_op_override(0xFF);
    let bad_op = ahci::read_lba(vi, 4096, 1);
    ahci::set_op_override(0);
    let s1 = ahci::stats();
    let clean_is_err = matches!(bad_op, Err(ahci::AhciError::BadCompletion { .. }));
    let clean_no_reset =
        clean_is_err && s1.resets == st0.resets && s1.clean_errors == st0.clean_errors + 1;
    let clean_read = ahci::read_lba(vi, 4096, 8);
    let clean_usable = got_whole(&clean_read);

    // 2 卡住 → `Resetting` → 恢复：关掉引擎，发出去的命令没人接
    let _ = ahci::wedge_port(vi);
    let stuck = ahci::read_lba(vi, 4096, 1);
    let s2 = ahci::stats();
    let stuck_is_timeout = matches!(stuck, Err(ahci::AhciError::CmdTimeout));
    let tried_reset =
        stuck_is_timeout && s2.resets == s1.resets + 1 && ahci::state(vi) == ahci::State::Running;
    let heal_read = ahci::read_lba(vi, 4096, 8);
    let healed = tried_reset && got_whole(&heal_read);
    // 恢复结束时端口里挂着几条命令。**只打印，不进判据**：实测把 `start_port` 里的
    // 排空整段关掉，这一格照样读到 0（旧命令在拉起 `ST` 那一刻同步答完了），
    // 也就是说它分辨不了"排空有没有发生"。真在量这件事的是上面 `healed` 的整段回执。
    let drained = ahci::pending_cmds(vi) == Ok(0);

    // 3 修不好 → 隔离：让恢复本身必然失败，重试到预算
    ahci::inject_dead_port(vi);
    let mut quarantined = false;
    let mut resets_at = 0u32;
    let mut tries = 0u32;
    for _ in 0..(ahci::RETRY_BUDGET + 2) {
        tries += 1;
        let _ = ahci::wedge_port(vi);
        let _ = ahci::read_lba(vi, 4096, 1);
        if ahci::state(vi) == ahci::State::Quarantined {
            quarantined = true;
            resets_at = ahci::stats().resets;
            break;
        }
    }
    // 隔离之后再发一条：必须"没下发就返回"，于是 `resets` 一格都不该再动
    let post = ahci::read_lba(vi, 4096, 1);
    let s3 = ahci::stats();
    let fails_fast = quarantined
        && matches!(post, Err(ahci::AhciError::Quarantined))
        && s3.resets == resets_at
        && s3.quarantines == st0.quarantines + 1
        // 预算是按口累计的：停在 RETRY_BUDGET 说明这一口自己试够了次数
        && ahci::resets_of(vi) == ahci::RETRY_BUDGET;

    // `.ktests` 的顺序由链接器决定，隔离态不能留给后面的用例（真机上它是终态）
    ahci::revive_port();
    let rel = ahci::release_quarantine(vi);
    let released = rel.is_ok();
    let after = ahci::read_lba(vi, 4096, 8);
    let usable_after_release = released && got_whole(&after);

    // 4 粒度：另一个端口必须照常，而且一次重置都没被牵连
    let boot_head = ahci::read_lba(bt, 1, 1).and_then(|_| ahci::data_head(8));
    let boot_ok =
        boot_head.map(|h| &h[0..8] == b"EFI PART").unwrap_or(false) && ahci::resets_of(bt) == 0;
    crate::log_info!(
        "recover: 干净错误={}(状态={:#04x}) 没抖控制器={} 之后照常读={} 卡住={} 走了重置={} 重置后恢复={} 恢复后排空={}",
        clean_is_err,
        match bad_op {
            Err(ahci::AhciError::BadCompletion { status, .. }) => status,
            _ => 0
        },
        clean_no_reset,
        clean_usable,
        stuck_is_timeout,
        tried_reset,
        healed,
        drained
    );
    crate::log_info!(
        "recover: 已隔离={}(第{}次命令) 隔离后快速失败且不再碰设备={} 撤销隔离后能用={} 引导盘照常={} 计数 全局resets={} 受害口resets={} 引导口resets={} 隔离数={} 干净错误={} 预算={} 被吞重发合计={} 引导口被吞={}",
        quarantined,
        tries,
        fails_fast,
        usable_after_release,
        boot_ok,
        s3.resets,
        ahci::resets_of(vi),
        ahci::resets_of(bt),
        s3.quarantines,
        s3.clean_errors,
        ahci::RETRY_BUDGET,
        ahci::issue_resets_total(),
        ahci::issue_resets_of(bt)
    );
    let rel_cmd = rel.as_ref().map(|p| p.cmd).unwrap_or(0xFFFF_FFFF);
    let (after_status, after_hash) = match after {
        Ok(r) => (r.status, r.hash),
        Err(ref e) => {
            crate::log_warn!("recover: 撤销隔离后的回读失败 {:?}", e);
            (0, 0)
        }
    };
    crate::log_info!(
        "recover: 撤销隔离 起口={} 端口CMD={:#010x} 回读状态={:#04x} 回读哈希={:#018x} 基线={:#018x}",
        released,
        rel_cmd,
        after_status,
        after_hash,
        baseline
    );
    let ok = clean_no_reset
        && clean_usable
        && tried_reset
        && healed
        && fails_fast
        && usable_after_release
        && boot_ok;
    if !ok {
        crate::log_fatal!("recover: 状态机判据不成立（上面两行是全部读数）");
    }
    ok
}
#[cfg(feature = "ahci-scratch")]
ktest!(KT_AHCI_RECOVERY, t_ahci_recovery);

/// 只给 `KT_IRQ_AHCI` 第六格用的一颗空处理函数：它永远说"不是我的"。
/// 要一颗**不接线到任何设备**的认领，是为了让"撤销→复用同一格→旧句柄必须被拒"
/// 这条路在不动 AHCI 那颗中断的前提下走完。
fn t_irq_noop_handler() -> bool {
    false
}

/// M5-g②：真的认领上一颗中断。判据六格，每格只挡一类错法（顺序就是函数体的顺序）：
/// ① **消息逐字对账**：核内算出的 `(addr_lo, addr_hi, data)` 与设备 MSI 结构里此刻的读数
///    三个全等、`ctrl` 的 enable 位读回 1。这一格与 `init` 里那次回读不是同一时刻：
///    中间隔了整段启动，别人（或恢复路径）动过它就得在这里露出来。
/// ② 链路上两道闸门真的开着：`GHC.IE` 与引导口 `PxIE` 各自读回含那一位。
/// ③ 开着中断窗口读一格：**中断到过**（三处同时 +1：本模块的 `irq_hits`+`race_hits`、
///    认领表的 `hits`、`apic` 那台按向量数的 `irq[vec-32]`），而内容仍是夹具的 GPT 头
///    （换了等待方式不许换数据），且"完全没等到中断"那本账 `poll_hits` 为 0。
/// ④ 负样本：关掉设备的 MSI enable 再读一格。命令**仍然成功**（退路必须出得来），
///    而 `irq_hits`/`race_hits` 都不涨、`poll_hits` 涨 ⇒ "其实还在轮询"读得出来。
/// ⑤ 恢复 enable 再读：中断又到过，且这一路没把端口推进隔离（§8.2 的账本读回来对）。
/// ⑥ 撤销一颗自己的认领后：旧句柄先被拒（`NoSuchHandle`），同一格被复用之后旧句柄必须变成
///    `StaleHandle` —— 这正是 ADR-030 那条"复用同一格"的规矩在中断上的续集；
///    而 `release` 不许动 `GHC.IE`：那颗闸门是控制器全局的。
///
/// ③ 里 `irq_hits` 与 `race_hits` 分成两本账：寄存器落定与消息落地之间只隔几十微秒，
/// 合成一本就把"赛跑输赢"读成"中断配没配上"，那是偶发红的形状。所以这一格要求的是
/// **中断到过**（两者之和 == 1），不是"我赢了赛跑"。
fn t_irq_ahci() -> bool {
    use crate::driver::DriverError;
    if ahci::init().is_err() {
        crate::log_fatal!("irq-ahci: AHCI 没认领上，中断判据没法做");
        return false;
    }
    // 接入中断的前置是 APIC 状态，而它不在启动路径上建（`main.rs` 早期那次 `ahci::init()`
    // 比它早）⇒ 这一格自己把前置要齐，而不是假定别人已经做过
    let Some(summary) = acpi::summary() else {
        crate::log_fatal!("irq-ahci: 没有 ACPI 摘要，拿不到 MADT ⇒ 接入中断的前置没法要齐");
        return false;
    };
    let Some(m) = summary.madt else {
        crate::log_fatal!("irq-ahci: MADT 不在摘要里");
        return false;
    };
    if let Err(e) = ahci::arm_irq(&m) {
        crate::log_fatal!("irq-ahci: 接入中断失败 {:?} ⇒ 后面的判据在量它没有的东西", e);
        return false;
    }
    let (Some(vec), Some(h)) = (ahci::irq_vector(), ahci::irq_handle()) else {
        crate::log_fatal!("irq-ahci: 这颗控制器没认领到中断 ⇒ 这一格在量它没有的东西");
        return false;
    };
    let num = match ahci::boot_port() {
        Ok(n) => n,
        Err(e) => {
            crate::log_fatal!("irq-ahci: 找不到引导盘 {:?}", e);
            return false;
        }
    };
    let Some(dev) = pci::first_of_triple(0x01, 0x06, 0x01) else {
        crate::log_fatal!("irq-ahci: 枚举表里没有 AHCI");
        return false;
    };
    let ctx = driver::DriverCtx::for_device(ahci::MOD_AHCI, dev);
    // `apic::counts()` 那 16 格是按 ISA 线号索引的（向量 - 0x20），不是按向量
    let vslot = usize::from(vec) - trap::VEC_IRQ_BASE;

    // ① 消息逐字对账
    let (msg_lo, msg_hi, msg_data) = match ctx.irq_message(h) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("irq-ahci: 消息算不出来 {:?}", e);
            return false;
        }
    };
    let (b_lo, b_hi, b_data, b_ctrl) = match ahci::msi_witness() {
        Some(v) => v,
        None => {
            crate::log_fatal!("irq-ahci: 设备里那三格读不回来 ⇒ 认领与设备没对上");
            return false;
        }
    };
    let msg_back = b_lo == msg_lo && b_hi == msg_hi && b_data == msg_data && b_ctrl & 1 != 0;

    // ② 两道闸门
    let (ghc, ie, _is) = match ahci::irq_gates() {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("irq-ahci: 闸门读数拿不到 {:?}", e);
            return false;
        }
    };
    let gates = (ghc & ahci::REG_GHC_IE != 0) && (ie & 1 != 0);

    // ③④⑤ 三个动作共用的读数器：一次"开窗口读 LBA 1"，回来报三本账的增量与内容
    let step = |who: &'static str| -> (usize, usize, usize, usize, usize, bool) {
        ahci::irq_counters_reset();
        let (calls0, hits0) = ctx.irq_counts(h).unwrap_or((0, 0));
        let c0 = apic::counts();
        let (disp0, uncl0) = irq::stats();
        // 旗子得有人来取：本地中断窗口要 IF=1，而 tick 是把被挂住的上下文往前推的那只手
        let timer = apic::timer_start().is_ok();
        let mut buf = [0u8; 512];
        let r = apic::with_interrupts(|| ahci::read_bytes(num, 1, &mut buf));
        let _ = apic::timer_stop();
        let c1 = apic::counts();
        let (calls1, hits1) = ctx.irq_counts(h).unwrap_or((0, 0));
        let (disp1, uncl1) = irq::stats();
        let content = &buf[0..8] == b"EFI PART";
        crate::log_info!(
            "irq-ahci: {} 中断={} 赛跑={} 轮询={} 顶半={} 认领表hits={}→{} calls={}→{} 按向量irq[{}]={}→{} 派发={} 没人认领={} 定时器开={} 判定={:?}",
            who, ahci::irq_hits(), ahci::race_stats().0, ahci::poll_hits(), ahci::isr_entry(),
            hits0, hits1, calls0, calls1, vslot,
            c1.irq[vslot].saturating_sub(c0.irq[vslot]),
            c0.irq[vslot], disp1 - disp0, uncl1 - uncl0, timer,
            r.as_ref().err()
        );
        (
            ahci::irq_hits() + ahci::race_stats().0,
            ahci::poll_hits(),
            hits1 - hits0,
            ahci::isr_entry(),
            c1.irq[vslot] - c0.irq[vslot],
            r.is_ok() && content,
        )
    };

    // ③ 开着中断读
    let (arrived3, polled3, tbl3, entry3, byvec3, good3) = step("③开中断");
    let third = arrived3 >= 1 && polled3 == 0 && tbl3 >= 1 && entry3 >= 1 && byvec3 >= 1 && good3;

    // ④ 负样本：关掉设备的 enable
    if ahci::set_msi_enabled(false).is_err() {
        crate::log_fatal!("irq-ahci: 关不上设备的 MSI enable");
        return false;
    }
    let (arrived4, polled4, _, _, _, good4) = step("④关掉enable");
    let fourth = arrived4 == 0 && polled4 == 1 && good4;
    // 恢复
    let restored = ahci::set_msi_enabled(true).is_ok();

    // ⑤ 恢复之后再读
    let (arrived5, polled5, _, _, _, good5) = step("⑤恢复enable");
    let resets5 = ahci::resets_of(num);
    let fifth = arrived5 >= 1 && polled5 == 0 && good5 && restored && resets5 == 0;

    // ⑥ 撤销 → 旧句柄被拒 → 同一格复用 → 旧句柄变成 StaleHandle；release 不许动 GHC.IE
    let extra = match ctx.request_irq(t_irq_noop_handler) {
        Ok(x) => x,
        Err(e) => {
            crate::log_fatal!("irq-ahci: 再要一颗认领失败 {:?}", e);
            return false;
        }
    };
    let released = ctx.release_irq(extra).is_ok();
    let after_release = ctx.irq_counts(extra);
    let ghc_after_release = ahci::irq_gates().map(|(g, _, _)| g).unwrap_or(0);
    // 复用同一格：表里第一格空出来，下一次要的就是它 ⇒ 槽号相同而世代号不同
    let again = ctx.request_irq(t_irq_noop_handler);
    let reused_same_slot = matches!(&again, Ok(x) if x.slot == extra.slot && x.gen != extra.gen);
    let stale_rejected = matches!(ctx.irq_counts(extra), Err(DriverError::StaleHandle { slot, .. }) if slot == extra.slot);
    let never_delivered = irq::stats().1 == 0;
    let _ = again.map(|x| ctx.release_irq(x));
    let sixth = released
        && matches!(after_release, Err(DriverError::NoSuchHandle(s)) if s == extra.slot)
        && reused_same_slot
        && stale_rejected
        && ghc_after_release == ghc
        && never_delivered;

    // ⑦ 分账与总账同数。这条不是装饰：只有"谁在服务"那本分账能对上总账，
    //    第 ⑥ 格与亲和性那一跑里的分账读数才许拿去当证据（BACKLOG 73f）。
    let isr_split = ahci::isr_entry_by_cpu();
    let (race_split, race_max_split) = ahci::race_by_cpu();
    let split_ok = isr_split.iter().sum::<usize>() == ahci::isr_entry()
        && race_split.iter().sum::<usize>() == ahci::race_stats().0;
    crate::log_info!(
        "irq-ahci: 判据 消息逐字={} GHC.IE={} PxIE={} 开中断到过={} 关enable纯轮询={} 恢复后又={} 撤销与复用={} 分账同数={} 向量={:#x} 赛跑最大间隔={} 端口={} 隔离计数={} 顶半按CPU={:?}",
        msg_back,
        ghc & ahci::REG_GHC_IE != 0,
        ie & 1 != 0,
        third,
        fourth,
        fifth,
        sixth,
        split_ok,
        vec,
        ahci::race_stats().1,
        num,
        resets5,
        isr_split
    );
    let ok = msg_back && gates && third && fourth && fifth && sixth && split_ok;
    if !ok {
        crate::log_fatal!("irq-ahci: 中断认领判据不成立（上面每个动作一行读数）");
    }
    ok
}
/// L3-B 亲和性：把 AHCI 那颗 MSI 的目的地移到一颗上线的 AP，做一次真读，看投递落到哪颗 CPU；
/// 再移回 BSP 做第二次。判据三件事，各管一种错法：
/// ① 消息里那条目的地位段与表里说的同一颗 CPU；② 设备**回读**逐字一致（写了不等于收下了）；
/// ③ 新投递只落在目的地上、BSP 那格一格都不许涨。
/// 宿主机另外拿 `-d int` 里 `SP` 的高位数一遍 BSP／非 BSP（矩阵第 32 行）——那是独立仪器。
#[cfg(feature = "irq-affinity-probe")]
fn t_irq_affinity() -> bool {
    let Some(h) = ahci::irq_handle() else {
        crate::log_fatal!("irq-aff: 这颗控制器没认领到中断 ⇒ 移动目的地没有对象");
        return false;
    };
    let Ok(num) = ahci::boot_port() else {
        crate::log_fatal!("irq-aff: 找不到引导盘 ⇒ 没有能触发中断的动作");
        return false;
    };
    let Some(bsp_id) = apic::state().map(|st| st.id as u8) else {
        crate::log_fatal!("irq-aff: 本地 APIC 没初始化 ⇒ 连目的地都算不出来");
        return false;
    };
    // 找一颗**上线**的 AP：目的地写成没上机的核，失败形状是"一个中断都不来"，
    // 那种故障没有别的尺子会报（§13.1 那条时钟前提之外的第二条跨 CPU 前提）
    let ap = (1..cpu::MAX_CPUS)
        .filter(|&s| cpu::is_registered(s) && cpu::is_online(s))
        .find_map(|s| cpu::lapic_id_of(s).map(|id| (s, id as u8)));
    let Some((ap_slot, ap_id)) = ap else {
        crate::log_fatal!("irq-aff: 没有第二颗上线的 CPU ⇒ 这一格在量它没有的东西");
        return false;
    };
    let before = irq::by_cpu();
    let moves0 = irq::moves();

    // ---- 一次"开中断窗口读 LBA 1"，回来报按 CPU 的分布 ----
    // 每个动作回来交两本分账：投递落到哪颗核（`by_cpu`），顶半在哪颗核跑过（`isr_entry_by_cpu`）。
    // 后者是 73f 那一格新加的出口——只有前者可用时，"谁在服务"只能从投递分布反推。
    let step = |who: &'static str| -> ([usize; cpu::MAX_CPUS], [usize; cpu::MAX_CPUS]) {
        ahci::irq_counters_reset();
        let timer = apic::timer_start().is_ok();
        let mut buf = [0u8; 512];
        let r = apic::with_interrupts(|| ahci::read_bytes(num, 1, &mut buf));
        let _ = apic::timer_stop();
        let now = irq::by_cpu();
        let (race, race_max) = ahci::race_stats();
        let served = ahci::isr_entry_by_cpu();
        crate::log_info!(
            "irq-aff: {} 读盘={} 内容={} 定时={} 中断落定={} 赛跑落定={} 轮询落定={} 顶半={} 赛跑最大间隔={} 按CPU={:?} 顶半按CPU={:?}",
            who,
            r.is_ok(),
            &buf[0..8] == b"EFI PART",
            timer,
            ahci::irq_hits(),
            race,
            ahci::poll_hits(),
            ahci::isr_entry(),
            race_max,
            now,
            served
        );
        (now, served)
    };

    // ① 移到 AP
    let (same_a, slot_a, msg_a) = match ahci::set_affinity(ap_id) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("irq-aff: 移到 AP 失败 {:?}", e);
            return false;
        }
    };
    let dest_a = ahci::affinity_dest() == Some(ap_id);
    let (mid, mid_served) = step("移到AP后");
    // ② 移回 BSP
    let (same_b, slot_b, msg_b) = match ahci::set_affinity(bsp_id) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("irq-aff: 移回 BSP 失败 {:?} ⇒ 目的地留在 AP 上，后面的判据没法读", e);
            return false;
        }
    };
    let (after, after_served) = step("移回BSP后");

    let want_a = msg_a.addr_lo == 0xFEE0_0000 | (u32::from(ap_id) << 12);
    let want_b = msg_b.addr_lo == 0xFEE0_0000 | (u32::from(bsp_id) << 12);
    let prog_ok = same_a && same_b && want_a && want_b && slot_a == ap_slot && slot_b == 0 && dest_a;
    // 新投递只许落在目的地；BSP 那一格在移动期间一格都不许涨
    let landed = mid[ap_slot] > before[ap_slot];
    let not_bsp = mid[0] == before[0];
    // 移回之后 BSP 继续涨、而非 BSP 一格都不再涨——这条排除"表里改了而设备没改"那种半程错
    let non_mid: usize = mid[1..].iter().sum();
    let non_after: usize = after[1..].iter().sum();
    let back_ok = after[0] > mid[0] && non_after == non_mid;
    let moves_ok = irq::moves() == moves0 + 2;
    // 73f：服务那一侧也要按 CPU 看得见。`step` 每步开头把账归零，所以读数就是"这一步里谁服务过"：
    // 目的地在 AP 那一步，顶半只能出现在 AP 那格；搬回 BSP 那一步反过来。
    // 第一版我写成"比移动前涨没涨"，那是拿归零后的数比归零前的数——`served0` 因此被删掉。
    let served_landed = mid_served[ap_slot] >= 1 && mid_served[0] == 0;
    let served_back = after_served[0] >= 1 && after_served[ap_slot] == 0;
    let served_split = after_served.iter().sum::<usize>() == ahci::isr_entry();
    let bsp_now = after[0] + after[1..].iter().sum::<usize>() > before[0] + before[1..].iter().sum::<usize>();
    crate::log_info!(
        "irq-aff: 判据 BSP id={:#04x} AP id={:#04x} 槽={} 移动期间落到AP={} AP前={} AP后={} BSP前={} BSP后={}          回读逐字={} 消息目的地对={} 表里说的={} 回到BSP={} 移动次数={}→{} 总投递动了={}              服务顶半搬到AP={} 服务顶半搬回={} 顶半分账同数={}",
        bsp_id,
        ap_id,
        ap_slot,
        landed,
        before[ap_slot],
        mid[ap_slot],
        before[0],
        mid[0],
        prog_ok,
        want_a && want_b,
        dest_a,
        back_ok,
        moves0,
        irq::moves(),
        bsp_now,
        served_landed,
        served_back,
        served_split
    );
    let _ = h;
    prog_ok && landed && not_bsp && back_ok && moves_ok && served_landed && served_back && served_split
}
#[cfg(feature = "irq-affinity-probe")]
ktest!(KT_IRQ_AFFINITY, t_irq_affinity);

/// L3-A：整行原子性。让每个在线 CPU 同时打一批行，内核这一侧只数**账**：
/// 每 CPU 自己数的行数、行锁四本账的增量、用完归还、没进停机放行。
/// 行的**形状**由另一台仪器判（矩阵第 31 行，`tools/aurora.py:check_line_atomicity`）——
/// 一台数账一台数形状，两边都过才算，任何一边单独绿都不算。
#[cfg(feature = "serial-atomic-probe")]
fn t_serial_atomic() -> bool {
    let o = match smp::print_round() {
        Ok(o) => o,
        Err(e) => {
            crate::log_fatal!("atomic: 一轮并发打印没跑起来 {:?}", e);
            return false;
        }
    };
    let total = o.bsp_total + o.ap_total;
    let lines_ok = o.ack_timeouts == 0
        && o.bsp_total == o.lines_per_cpu
        && o.ap_total == o.lines_per_cpu * (o.participants - 1);
    // 每一行恰好取一次锁：少了说明有行绕过了锁，多了说明同一行取了两次
    let holds_ok = o.holds == total;
    // `contended` 不进球：三跑里它分别是 1、2、6——它是"撞上了没有"的现场读数，不是
    // 能稳定判定的东西。非空转的举证放在核外那台仪器（变异 E：撤掉行锁后 96 行只剩
    // 65 个整行、10 行出现两种 tag、3 行张冠李戴），而不是押在这个计数上。
    let clean_ok = o.nested == 0 && o.timeouts == 0;
    let released_ok = o.owner_after == 0 && !o.halting;
    crate::log_info!(
        "atomic: 判据 参与核={} 每核行={} BSP行={} AP行={} 总行={} 取锁={} 竞争={} 重入={} 超时={} \
         回执超时={} 结束后持有者={} 停机放行={} 行数齐={} 每行一次锁={} 账干净={}",
        o.participants,
        o.lines_per_cpu,
        o.bsp_total,
        o.ap_total,
        total,
        o.holds,
        o.contended,
        o.nested,
        o.timeouts,
        o.ack_timeouts,
        o.owner_after,
        o.halting,
        lines_ok,
        holds_ok,
        clean_ok
    );
    lines_ok && holds_ok && clean_ok && released_ok
}
#[cfg(feature = "serial-atomic-probe")]
ktest!(KT_SERIAL_ATOMIC, t_serial_atomic);

/// KT_VIRTIO_MSIX：virtio 的 MSI-X 表条目一格。读数全来自设备回读，不来自我以为的偏移。
#[cfg(feature = "virtio-msix-probe")]
fn t_virtio_msix() -> bool {
    if let Err(e) = virtio::bind() {
        crate::log_fatal!("virtio-msix: 设备没绑上 {:?}", e);
        return false;
    }
    let p = match virtio::msix_probe() {
        Ok(p) => p,
        Err(e) => {
            crate::log_fatal!("virtio-msix: 编程一轮没跑起来 {:?}", e);
            return false;
        }
    };
    // ① 能力形状：条数与 BIR 对上 M5-g① 那次取证。**表偏移不当常数判**——
    //    它是设备的数，而"它到底落在哪一段"由第 ③⑦ 格的"写下去读得回来"判：
    //    上一轮我把 PBA 的偏移(0x800)当成表偏移记进了台账，就是因为这里没有写读对账。
    let caps_ok = p.table_size == 5 && p.bir == 1;
    let mask_all_ok = p.masked_all == p.table_size;
    let words_ok = p.back[0] == p.want[0] && p.back[1] == p.want[1] && p.back[2] == p.want[2]
        && p.back[3] == 0;
    let unmask_ok = p.fn_mask_off && p.masked_rest == p.table_size - 1;
    let handed_ok = p.qvector_back == p.entry as u16;
    // 到过的每一发都必须被认领——不等就是归属判断在骗人
    let claim_ok = p.claims == p.calls;
    let wake_ok = p.flag_seen == (p.calls > 0);
    let remask_ok = p.re_masked == p.table_size;
    crate::log_info!(
        "virtio-msix: 判据 表条数={} BIR={} 表偏移={:#x} 能力头={:#x} 向量={:#x} 条目={} \
         全遮读回={}/{} 写=({:#010x},{:#010x},{:#010x}) 读回=({:#010x},{:#010x},{:#010x},{:#010x}) \
         功能遮={} 解除后仍遮={}/{} 交队列读回={:#x} 到过={} 认领={} 旗子={} 撤销后重遮={}/{} \
         读盘={} 等了={} 轮 ⇒ 能力对={} 全遮={} 逐字={} 解除={} 交队列={} 认领一致={} 叫醒一致={} 重遮={}",
        p.table_size,
        p.bir,
        p.table_off,
        p.cap_off,
        p.vector,
        p.entry,
        p.masked_all,
        p.table_size,
        p.want[0],
        p.want[1],
        p.want[2],
        p.back[0],
        p.back[1],
        p.back[2],
        p.back[3],
        p.fn_mask_off,
        p.masked_rest,
        p.table_size,
        p.qvector_back,
        p.calls,
        p.claims,
        p.flag_seen,
        p.re_masked,
        p.table_size,
        p.content_ok,
        p.waited,
        caps_ok,
        mask_all_ok,
        words_ok,
        unmask_ok,
        handed_ok,
        claim_ok,
        wake_ok,
        remask_ok
    );
    let ok = caps_ok && mask_all_ok && words_ok && unmask_ok && handed_ok && claim_ok && wake_ok
        && remask_ok && p.content_ok;
    if !ok {
        crate::log_fatal!("virtio-msix: 判据不成立（上面一行是设备自己读回来的数）");
    }
    ok
}
#[cfg(feature = "virtio-msix-probe")]
ktest!(KT_VIRTIO_MSIX, t_virtio_msix);

ktest!(KT_IRQ_AHCI, t_irq_ahci);

#[cfg(feature = "fat32-probe")]
/// 三块盘挂在哪个口：0 是引导 ESP（也是"保护性 MBR 必须被拒"那一格的证人），
/// 3 与 4 是两块 FAT32 卷。②（`t_fat32_mem`）不用它们，③（`t_fat32_exec`）要再读一次卷A，
/// 所以这三个数从 `t_fat32` 的函数体里提到模块层——两处各写一份的话，
/// 改了接线那一处不会让另一处红，而串口只会说"挂载失败"。
/// 与 `tools/aurora.py` 的 `FAT_PORTS` 由门禁 `check-fat32-ports` 对账。
#[cfg(feature = "fat32-probe")]
const FAT_PORT_MBR: u8 = 0;
#[cfg(feature = "fat32-probe")]
const FAT_PORT_A: u8 = 3;
#[cfg(feature = "fat32-probe")]
const FAT_PORT_B: u8 = 4;

#[cfg(feature = "fat32-probe")]
/// 打开一条文件并走完整条链，把三本账收齐：目录项说的、链给的、内容算出来的。
/// 失败原样带出去——"设备没接走"与"这卷不是 FAT32"必须分开落在日志上，不许在这一层抹平。
fn fat32_file(
    vol: &filesystem::fat32::Volume<'_>,
    name: &str,
) -> Result<
    (
        filesystem::vfs::FileStat,
        filesystem::fat32::Walk,
        u64,
        [u8; 4],
    ),
    filesystem::fat32::FsError,
> {
    let st = vol.open(name)?;
    let mut h = ahci::FNV_OFFSET;
    let mut head = [0u8; 4];
    let mut fed = 0usize;
    let w = vol.walk(&st, |chunk| {
        for (i, b) in chunk.iter().enumerate() {
            h = ahci::fnv1a_step(h, *b);
            if fed + i < head.len() {
                head[fed + i] = *b;
            }
        }
        fed += chunk.len();
    })?;
    Ok((st, w, h, head))
}

#[cfg(feature = "fat32-probe")]
/// L3-C①：FAT32 只读解析的第一个真调用点。三本账各挡一种坏法——
/// 几何挡"偏移表是我编的"，目录挡"扫到第一条就像"，内容挡"簇号只取了低半"。
///
/// 两块卷的角色不能互相代替：卷A（32 MiB）是**阈值判型的反例**（64,496 簇按微软那条经验
/// 阈值算 FAT16，按结构算 FAT32，我们按结构收），卷B（64 MiB）里 FILLER.BIN 把后面三个文件
/// 推到 65,536 簇之上，于是目录项的簇号必须两半拼。每一格的期望数都来自夹具配方
/// （BACKLOG 78 的 mtools 那一节），没有一格是从解析器自己读回来的数抄的。
fn t_fat32() -> bool {
    use filesystem::fat32::{band_type, FsError, FatType, Volume, EOC_MARKER};
    use filesystem::vfs::{AhciDisk, FileStat};

    // 用例必须自足：`.ktests` 的顺序由链接器决定，不能假设别的用例已经认领过 AHCI
    if ahci::init().is_err() {
        crate::log_fatal!("fat32: AHCI 认领失败，没有块设备可读");
        return false;
    }
    // 卷挂在哪两个口由 `tools/aurora.py` 的 `FAT_PORTS` 定，两处由门禁 `check-fat32-ports` 对账
    let disk_a = AhciDisk { port: FAT_PORT_A };
    let disk_b = AhciDisk { port: FAT_PORT_B };

    // ⑥ 先判"必须被拒"的那一个。保护性 MBR 的 0x55AA **也在位上**，所以第一道崩下来的
    //    不是签名闸而是每扇区字节数闸（那 512 字节的 11..12 是全零）——这一格是量出来的。
    let mbr = Volume::mount(&AhciDisk { port: FAT_PORT_MBR });
    let mbr_rejected = matches!(mbr.as_ref().err(), Some(FsError::BadBytesPerSector(0)));
    crate::log_info!(
        "fat32: 引导盘 口{} 拒因={:?} 落在第一道闸={}",
        FAT_PORT_MBR,
        mbr.as_ref().err(),
        mbr_rejected
    );

    let va = match Volume::mount(&disk_a) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("fat32: 卷A（口{}）挂载失败 {:?}——盘没挂上就是红，不静默跳过", FAT_PORT_A, e);
            return false;
        }
    };
    let vb = match Volume::mount(&disk_b) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("fat32: 卷B（口{}）挂载失败 {:?}", FAT_PORT_B, e);
            return false;
        }
    };

    // ① 判型：结构收下、阈值拒绝的那一对。夹具哪天换成一簇数落在 FAT32 档的卷，
    //    这一格当场红，而不是悄悄变成一条空转的断言。
    let a_band = band_type(va.bpb.clusters);
    let b_band = band_type(vb.bpb.clusters);
    let a_counter = va.bpb.fat_type == FatType::Fat32 && a_band == FatType::Fat16;
    let b_struct = vb.bpb.fat_type == FatType::Fat32 && b_band == FatType::Fat32;
    let geo = va.bpb.data_start == 1040
        && va.bpb.clusters == 64_496
        && va.bpb.root_cluster == 2
        && vb.bpb.data_start == 2050
        && vb.bpb.clusters == 129_022;
    // 两卷同一组字段、各打一行：宿主机那台仪器按同一张表逐字段对账，字段集不对称时
    // 它对不到一半（把 卷B 写成"只有簇数与数据起点"就是这种半瞎状态）。
    // `自由簇` 内核自己不判——它是设备自报的数，判它的只有宿主机按偏移 488 重读那一遍。
    for (tag, vol, band) in [("A", &va, a_band), ("B", &vb, b_band)] {
        crate::log_info!(
            "fat32: 几何 卷{} 簇数={} 数据起点={} 每簇字节={} FAT份={} 每份扇区={} 根簇={} \
             FSInfo扇区={} 备份扇区={} 阈值判型={:?} 结构判型={:?} 名字串={} 备份逐字节同={} \
             自由簇={}(设备自报，内核不判)",
            tag,
            vol.bpb.clusters,
            vol.bpb.data_start,
            vol.bpb.cluster_bytes,
            vol.bpb.fat_count,
            vol.bpb.sectors_per_fat,
            vol.bpb.root_cluster,
            vol.bpb.fsinfo_sector,
            vol.bpb.backup_boot_sector,
            band,
            vol.bpb.fat_type,
            vol.bpb.fs_name_ok,
            vol.backup_same,
            vol.witness.free_clusters
        );
    }

    struct Want {
        name: &'static str,
        size: u32,
        cluster: u32,
        seen: u32,
        hi: u16,
        lo: u16,
    }
    let want_a = [
        Want { name: "HELLO.ELF", size: 31_320, cluster: 3, seen: 1, hi: 0, lo: 3 },
        Want { name: "NOTES", size: 1_000, cluster: 65, seen: 2, hi: 0, lo: 65 },
        Want { name: "SMALL.BIN", size: 100, cluster: 67, seen: 3, hi: 0, lo: 67 },
    ];
    let want_b = [
        Want { name: "HELLO.ELF", size: 31_320, cluster: 67_587, seen: 2, hi: 1, lo: 2_051 },
        Want { name: "NOTES", size: 1_000, cluster: 67_649, seen: 3, hi: 1, lo: 2_113 },
        Want { name: "SMALL.BIN", size: 100, cluster: 67_651, seen: 4, hi: 1, lo: 2_115 },
    ];

    let mut dir_ok = true;
    let mut walk_ok = true;
    let mut magic_ok = true;
    let mut lfn_zero = true;
    let mut hello_hash = [0u64; 2];
    for (vi, (vol, want)) in [(0usize, (&va, &want_a[..])), (1, (&vb, &want_b[..]))] {
        for w in want {
            let (st, wa, h, head) = match fat32_file(vol, w.name) {
                Ok(got) => got,
                Err(e) => {
                    crate::log_fatal!("fat32: 卷{} {} 读不成 {:?}", vi + 1, w.name, e);
                    dir_ok = false;
                    walk_ok = false;
                    continue;
                }
            };
            let clusters = (w.size as usize + vol.bpb.cluster_bytes - 1) / vol.bpb.cluster_bytes;
            let tail = w.size as usize - (clusters - 1) * vol.bpb.cluster_bytes;
            let d = st.size == w.size
                && st.first_cluster == w.cluster
                && st.entries_seen == w.seen
                && (st.first_cluster >> 16) as u16 == w.hi
                && (st.first_cluster as u16) == w.lo;
            let k = wa.bytes == w.size as usize
                && wa.clusters as usize == clusters
                && wa.tail_bytes == tail
                && wa.after_last >= EOC_MARKER;
            // HELLO.ELF 就是 `kernel/fixtures/hello.elf` 那份（宿主机独立知道它的头四字节），
            // 所以这一格是有已知常量的对照，不是"自己与自己一致"。
            let m = w.name != "HELLO.ELF" || head == [0x7f, b'E', b'L', b'F'];
            dir_ok &= d;
            walk_ok &= k;
            magic_ok &= m;
            lfn_zero &= st.lfn_entries == 0;
            if w.name == "HELLO.ELF" {
                hello_hash[vi] = h;
            }
            crate::log_info!(
                "fat32: 卷{} {:<9} 大小={} 簇={} 高半={} 低半={} 扫过项={} LFN={} \
                 走字节={} 走簇={} 尾字节={} 末簇后继={:#010x} 头四字节={:02x?} 哈希={:#018x} \
                 该到簇数={} 该到尾格={} 目录对={} 链对={} 头对={}",
                vi + 1,
                w.name,
                st.size,
                st.first_cluster,
                (st.first_cluster >> 16) as u16,
                (st.first_cluster as u16),
                st.entries_seen,
                st.lfn_entries,
                wa.bytes,
                wa.clusters,
                wa.tail_bytes,
                wa.after_last,
                head,
                h,
                clusters,
                tail,
                d,
                k,
                m
            );
        }
    }
    // ② 同一份文件从两个完全不同的簇号区间（3 与 67,587）读出来必须同一个哈希。
    //    这一格与 ⑦ 是一对：⑦ 证明"只取低半会指到别处"，② 证明"两半拼对了地方"。
    let cross_ok = hello_hash[0] != 0 && hello_hash[0] == hello_hash[1];

    // ④ 大小写不敏感是真的比过三个写法，不是抄了一遍期望名
    let notes = va.open("NOTES");
    let case_ok = match (va.open("notes"), va.open("NoTeS")) {
        (Ok(l), Ok(m)) => notes.ok().is_some_and(|u| u == l && l == m),
        _ => false,
    };
    // ⑤ 扫到目录末尾还没有 ⇒ NoEntry（证明 open 的退出条件不是"第一条不像就返回"）
    let absent_ok = matches!(va.open("NOFILE.TXT"), Err(FsError::NoEntry));

    // ⑦ 只取低半的对照：簇号拿 2,051 就落在 FILLER.BIN 的中间，链比元数据说的 31,320 字节长得多。
    //    期望 `ChainEndsLate`——它也是这个变体唯一的真调用点：没有这一格，那条分支没人走过。
    let lo_outcome = vb
        .open("HELLO.ELF")
        .map(|st| FileStat { first_cluster: (st.first_cluster as u16) as u32, ..st })
        .and_then(|wrong| vb.walk(&wrong, |_| {}));
    let lo_ok = matches!(lo_outcome, Err(FsError::ChainEndsLate { .. }));
    crate::log_info!(
        "fat32: 对照 卷A哈希={:#018x} 卷B哈希={:#018x} 同数={} 低半单独走的拒因={:?} | \
         大小写三写法同数={} 没有的那项被拒={}",
        hello_hash[0],
        hello_hash[1],
        cross_ok,
        lo_outcome.as_ref().err(),
        case_ok,
        absent_ok
    );

    let ok = mbr_rejected
        && a_counter
        && b_struct
        && geo
        && dir_ok
        && walk_ok
        && magic_ok
        && lfn_zero
        && cross_ok
        && case_ok
        && absent_ok
        && lo_ok;
    crate::log_info!(
        "fat32: 判据 引导盘被拒={} 卷A阈值反例={} 卷B结构={} 几何={} 目录={} 链={} ELF头={} \
         无长名={} 两卷同哈希={} 大小写={} 缺项被拒={} 低半单独被拒={} ⇒ {}",
        mbr_rejected,
        a_counter,
        b_struct,
        geo,
        dir_ok,
        walk_ok,
        magic_ok,
        lfn_zero,
        cross_ok,
        case_ok,
        absent_ok,
        lo_ok,
        ok
    );
    if !ok {
        crate::log_fatal!("fat32: 判据不成立（上面两行是卷自己读回来的数）");
    }
    ok
}
#[cfg(feature = "fat32-probe")]
ktest!(KT_FAT32, t_fat32);

#[cfg(feature = "fat32-probe")]
/// 内存夹具卷（11,264 字节，配方 `tools/make_fat32_mem.py`，布局表在那个文件头）。
/// 它进 `.rodata` 而不进镜像：这一格的用途是让"贵到没法在真卷上跑"的分支有个便宜的落点。
static FAT32_MEM: &[u8] = include_bytes!("../fixtures/fat32-mem.img");

#[cfg(feature = "fat32-probe")]
/// 把 0 号扇区拷一份、按 `f` 改一格、交给**与真卷同一个** `parse_boot_sector`。
/// 拷一份是因为这些是纯函数用例：改的是字节，不是盘。
fn fat32_mutate(f: fn(&mut [u8])) -> Result<filesystem::fat32::Bpb, filesystem::fat32::FsError> {
    let mut b = [0u8; 512];
    b.copy_from_slice(&FAT32_MEM[..512]);
    f(&mut b);
    filesystem::fat32::parse_boot_sector(&b)
}

#[cfg(feature = "fat32-probe")]
/// L3-C②：内存夹具那一本账。真卷上一次走链要发几百条块命令，所以三种"真卷上造不出来
/// 或造出来太贵"的形状放在这里：**环链撞界**、**已删除/目录/卷标条目被跳过**、
/// **LPN 计数那一格真的走过**（真卷上 `lfn_entries` 恒为 0，那条分支没人验证过）。
/// 负表 11 行走的是 `parse_boot_sector` 这个纯函数：每条必须命中**它点名的那一格**拒绝码，
/// 因为"只要求解析失败"的判据会让任何一条先生效的检查替其余的门背书（M4-2 那条老规矩）。
fn t_fat32_mem() -> bool {
    use filesystem::fat32::{band_type, FsError, FatType, Volume, Bpb, MAX_CLUSTERS_WALKED};
    use filesystem::vfs::{Block, BlockError, MemDisk};

    let disk = MemDisk { img: FAT32_MEM };
    let vol = match Volume::mount(&disk) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("fat32-mem: 挂载失败 {:?}", e);
            return false;
        }
    };
    // ① 几何：12 簇按阈值算 FAT12，按结构算 FAT32 —— 与卷A 同一类反例，但这里是我们自己造的，
    //    所以"阈值不是判型依据"这句话有两个独立来源（一个来自 mtools，一个来自合成卷）。
    let m_geo = vol.bpb.data_start == 10
        && vol.bpb.clusters == 12
        && vol.bpb.root_cluster == 2
        && vol.bpb.cluster_bytes == 512;
    let m_band = vol.bpb.fat_type == FatType::Fat32 && band_type(vol.bpb.clusters) == FatType::Fat12;
    crate::log_info!(
        "fat32-mem: 几何 簇数={} 数据起点={} 每簇字节={} FAT份={} 每份扇区={} 根簇={} 阈值判型={:?} \
         结构判型={:?} 名字串={} 备份逐字节同={} 自由簇={}(自报不判)",
        vol.bpb.clusters,
        vol.bpb.data_start,
        vol.bpb.cluster_bytes,
        vol.bpb.fat_count,
        vol.bpb.sectors_per_fat,
        vol.bpb.root_cluster,
        band_type(vol.bpb.clusters),
        vol.bpb.fat_type,
        vol.bpb.fs_name_ok,
        vol.backup_same,
        vol.witness.free_clusters
    );

    // ② 目录里那 12 条各挡一种坏法
    //    `?LD.TXT` 不是笔误：配方把首字节写成 0x05（"曾删除但还能留下"那一族），于是名字第一位
    //    的那个 `O` 在盘上**已经不存在了**，`name_matches` 只能按规范把它读成 '?'。
    //    上一轮这里查的是 `?OLD.TXT`，红在 NoEntry——那读的是配方的意图，不是盘上的字节。
    let long = vol.open("LONG~1.TXT");
    let old = vol.open("?LD.TXT");
    let noshort = vol.open("NOSHORT");
    let m_long = match long {
        Ok(st) => st.size == 2000 && st.first_cluster == 3 && st.entries_seen == 4 && st.lfn_entries == 2,
        Err(_) => false,
    };
    let m_old = match old {
        Ok(st) => st.size == 10 && st.first_cluster == 7 && st.entries_seen == 6 && st.lfn_entries == 2,
        Err(_) => false,
    };
    let m_noshort = match noshort {
        Ok(st) => st.size == 10 && st.first_cluster == 7 && st.entries_seen == 8,
        Err(_) => false,
    };
    // 卷标、子目录、已删除条目：三种"不能当成文件命中"。跳过它们的代码若删掉，
    // 前两格会从 NoEntry 变成 Ok。
    let m_skip = matches!(vol.open("MYVOLUME"), Err(FsError::NoEntry))
        && matches!(vol.open("MYDIR"), Err(FsError::NoEntry));
    crate::log_info!(
        "fat32-mem: 目录 LONG~1.TXT={:?} ?LD.TXT={:?} NOSHORT={:?} 卷标/子目录被跳过={} 界={}",
        long,
        old,
        noshort,
        m_skip,
        MAX_CLUSTERS_WALKED
    );

    // ③ 内容：2,000 字节、4 簇、尾格 464。前四字节是夹具配方里的已知常量（不是解析器自报的数）。
    let mut h = ahci::FNV_OFFSET;
    let mut head = [0u8; 4];
    let m_walk = match &long {
        Ok(st) => {
            let mut off = 0usize;
            match vol.walk(st, |chunk| {
                for (i, b) in chunk.iter().enumerate() {
                    h = ahci::fnv1a_step(h, *b);
                    // 只抓文件最前四字节。旧写法每段都覆写 head，等于抓"最后一段的前四字节的
                    // 残留"——旧夹具内容按偏移 4 周期重复，那个错法恰好绿；逐扇区不同内容后当场红。
                    if off + i < head.len() {
                        head[off + i] = *b;
                    }
                }
                off += chunk.len();
            }) {
                Ok(w) => {
                    w.bytes == 2000
                        && w.clusters == 4
                        && w.tail_bytes == 464
                        && w.after_last >= filesystem::fat32::EOC_MARKER
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    };
    let m_head = head == [0x11, 0x14, 0x17, 0x1a];

    // ④ 环链必须有界：8→9→10→**9** 永远走不完，而 size 写的是 0xFFFF_FFFF（左边的量永远不减到 0），
    //    所以唯一能停下来的东西就是 `MAX_CLUSTERS_WALKED`。这一格删掉，"有界"就只是注释。
    //    名字写的是盘上那一条（`CYCLIC.BIN`）：上一轮这里写成 `open("CYCLIC")`，于是这一格
    //    红在"条目读不出来"——而被判的那件事是"读出来之后走链有界"，两者差一整条路径。
    let m_cyclic = match vol.open("CYCLIC.BIN") {
        Ok(_) => true,
        Err(e) => {
            crate::log_fatal!("fat32-mem: CYCLIC 条目读不出来 {:?}", e);
            false
        }
    };
    let cyclic_err = vol
        .open("CYCLIC.BIN")
        .and_then(|st| vol.walk(&st, |_| {}));
    let m_bound = matches!(cyclic_err, Err(FsError::ChainTooLong));

    // ⑤ 链比元数据短：size=4096 而首簇直接就是链尾 ⇒ `ChainEndsEarly`，报出来的字节数是 512。
    //    簇号与那个 EOC 读数现在跟着错误一起出来：上一轮 `FAT32_CLUSTER_MASK` 少写一个 nibble 时，
    //    真卷报的是 `ChainEndsLate { bytes: 31320, size: 31320 }`——两个数相等，看起来像自相矛盾，
    //    而当时日志里没有末簇与它的 FAT 读数，只能靠宿主机重算扇区哈希才定位到掩码。
    let early = vol.open("SHORTCHN.BIN").and_then(|st| vol.walk(&st, |_| {}));
    let m_early = matches!(early, Err(FsError::ChainEndsEarly { bytes: 512, size: 4096, .. }));
    crate::log_info!("fat32-mem: 链不自洽的两格 短链={:?} 环链={:?}", early, cyclic_err);

    // ⑥ 目录项的簇号落在坏簇区 ⇒ 拒，而不是拿它去算一个地址
    let m_badclu = matches!(vol.open("BADCLU.BIN"), Err(FsError::EntryOutsideData(_)));

    // ⑦ 内存适配器自己的界：越过镜像末尾是参数错（没有对端会回话），与真盘上"设备报越界"分开数
    let mut junk = [0u8; 512];
    let m_bounds = disk.read_sectors(22, &mut junk) == Err(BlockError::Refused)
        && disk.read_sectors(0, &mut junk[..511]) == Err(BlockError::Refused)
        && disk.read_sectors(21, &mut junk).is_ok();

    // ⑧ 负表：11 行各命中一格拒绝码，外加一行"没改动的必须解析成功"当对照组
    let neg: [(&str, fn(&mut [u8]), fn(&FsError) -> bool); 11] = [
        ("签名挪走", |b| b[510] = 0x00, |e| matches!(e, FsError::NoSignature)),
        ("每扇区 0", |b| { b[11] = 0; b[12] = 0 }, |e| matches!(e, FsError::BadBytesPerSector(0))),
        ("每扇区 1024", |b| { b[11] = 0; b[12] = 4 }, |e| matches!(e, FsError::UnsupportedSectorSize(1024))),
        ("每扇区 3", |b| { b[11] = 3; b[12] = 0 }, |e| matches!(e, FsError::BadBytesPerSector(3))),
        ("每簇 3", |b| b[13] = 3, |e| matches!(e, FsError::BadSectorsPerCluster(3))),
        ("介质 0", |b| b[21] = 0, |e| matches!(e, FsError::BadMedia(0))),
        // 固定根目录区在位 ⇒ 结构上说它不是 FAT32；22 个扇区算出来 12 簇 ⇒ 阈值说 FAT12
        ("固定根区", |b| { b[17] = 224; b[18] = 0 }, |e| matches!(e, FsError::UnsupportedFat(FatType::Fat12))),
        // 软盘形状：固定根区在位、FAT16 的每份扇区在位、FAT32 的那格清零。
        // total32 按**小端**写：0x007F80 = 32,640 簇数落在 FAT16 档。上一轮这里写成
        // `0, 0x80, 0x7f, 0` ⇒ 读出来是 0x007F8000（835 万），阈值判型当场翻成 FAT32、
        // 于是这一行解析成功——一行字节序写反的负样本不会红，它会**绿着不测任何东西**。
        ("软盘形状", |b| {
            b[14] = 1; b[15] = 0;
            b[17] = 224; b[18] = 0;
            b[19] = 0; b[20] = 0;
            b[22] = 9; b[23] = 0;
            b[36] = 0; b[37] = 0; b[38] = 0; b[39] = 0;
            b[32] = 0x80; b[33] = 0x7f; b[34] = 0; b[35] = 0;   // total32 = 0x00007F80 = 32,640
        }, |e| matches!(e, FsError::UnsupportedFat(FatType::Fat16))),
        ("零份 FAT", |b| { b[16] = 0; b[17] = 224 }, |e| matches!(e, FsError::MalformedBpb)),
        ("几何越出镜像", |b| { b[36] = 0xFF; b[37] = 0xFF }, |e| matches!(e, FsError::GeometryBeyondVolume { .. })),
        // FAT32 结构分支里的 `fat_count == 0`：上一行那一格走的是**非 32 分支**的那道闸，
        // 两道闸在源码里差十几行，只测一道等于另一道没人验过。
        // （这里原本写的是"扩展字段不在位 ⇒ NoSignature"，那是错的期望：`BS_BootSig` 与
        //  510 那两字节的签名是两格，清 66 号字节只会让 `fs_name_ok` 变 false，解析照旧成功。
        //  那一格的期望由下面的 `m_boot_sig` 单独判，不该混在"必须被拒"这张表里。）
        ("FAT32 里零份 FAT", |b| b[16] = 0, |e| matches!(e, FsError::MalformedBpb)),
    ];
    let mut m_neg = true;
    let mut neg_detail = [0u8; 12];
    for (i, (tag, poke, want)) in neg.iter().enumerate() {
        match fat32_mutate(*poke) {
            Err(e) if want(&e) => neg_detail[i] = 1,
            other => {
                neg_detail[i] = 0;
                m_neg = false;
                crate::log_fatal!("fat32-mem: 负表【{}】没有命中那一格，实际={:?}", tag, other.as_ref().err());
            }
        }
    }
    // 对照组：一格没改的 0 号扇区必须解析成功——否则上面 11 行是"全都失败"混出来的绿
    let m_control = fat32_mutate(|_| {}).map(|b: Bpb| b.clusters == 12).unwrap_or(false);
    // 最后一行单独判：`BS_BootSig` 不在位时 82 那格是保留区，不许当文件系统名收
    let m_boot_sig = fat32_mutate(|b| b[66] = 0x00).map(|b| !b.fs_name_ok).unwrap_or(false);
    let m_pos = fat32_mutate(|_| {}).map(|b| b.fs_name_ok).unwrap_or(false);

    let ok = m_geo
        && m_band
        && m_long
        && m_old
        && m_noshort
        && m_skip
        && m_walk
        && m_head
        && m_cyclic
        && m_bound
        && m_early
        && m_badclu
        && m_bounds
        && m_neg
        && m_control
        && m_boot_sig
        && m_pos;
    crate::log_info!(
        "fat32-mem: 判据 几何={} 阈值反例={} 长名计数={} 问号名={} 无扩展名={} 卷标子目录跳过={} \
         内容={} 头四字节={} 环链撞界={} 短链={} 坏簇号={} 适配器界={} 负表11行={} 对照组={} \
         boot_sig不在位则名字不算={} ⇒ {}",
        m_geo,
        m_band,
        m_long,
        m_old,
        m_noshort,
        m_skip,
        m_walk,
        m_head,
        m_bound,
        m_early,
        m_badclu,
        m_bounds,
        m_neg,
        m_control,
        m_boot_sig,
        ok
    );
    if !ok {
        crate::log_fatal!("fat32-mem: 判据不成立（上面三行是卷自己读回来的数）");
    }
    ok
}
#[cfg(feature = "fat32-probe")]
ktest!(KT_FAT32_MEM, t_fat32_mem);

#[cfg(feature = "fat32-exec")]
/// 从盘上读出来的镜像最多接多少字节。**这不是"文件应该多大"**——文件多大由目录项说，
/// 这一格说的是"缓冲准备接多少"。§10.3 那条老规矩：先验上界再用（`sign::PKG_BYTES`
/// 那一族的第三个使用点，见 BACKLOG 61a：按外部输入的大小开缓冲在这台机上第一次分配就走
/// `handle_alloc_error`，整机构成 39，而分配器上限只有 2048 字节）。
const ELF_DISK_MAX: usize = 64 * 1024;

#[cfg(feature = "fat32-exec")]
struct ElfDiskScratch(UnsafeCell<[u8; ELF_DISK_MAX]>);
#[cfg(feature = "fat32-exec")]
// SAFETY: 只在 `fat32-exec` 变体的这一条用例里用；可变借用不越过那一次 `walk` 调用，
//         不外泄 `&'static mut`，同一时刻不存在两份借用（与 `PkgScratch` 同一条理由）。
unsafe impl Sync for ElfDiskScratch {}
#[cfg(feature = "fat32-exec")]
static ELF_DISK: ElfDiskScratch = ElfDiskScratch(UnsafeCell::new([0u8; ELF_DISK_MAX]));

#[cfg(feature = "fat32-exec")]
/// L3-C③：把用户镜像的来源从 `include_bytes!` 换成**卷A 上的 `HELLO.ELF`**，然后真的跑起来。
///
/// 七个现场、八条 bool（`②` 那一步同时判走链的账与整份字节）。顺序就是函数体的顺序：
/// ① 上界先验再用：`size` 来自盘上的目录项，不来自我对夹具的记忆
/// ② 走链的账（字节数/簇数/尾格/末簇后继）**加上**缓冲里那 31,320 个字节与 `include_bytes!`
///    那份逐字节相同——不是同哈希：`0xa4cd9301241b0161` 那一格由 `t_fat32` 判，
///    这里判的是"要交给加载器的那段字节本身"
/// ③ 两条来源的**段表**逐项相同（入口、每条段的 offset/vaddr/filesz/memsz 与三个权限位）
/// ④ 装得上、跑得通：五个槽的数与内嵌那条路径同一组期望（`elfload:` 那两行是同一跑的第二台仪器）
/// ⑤ 元数据把大小说大 4096 字节 ⇒ 走链必须先 `ChainEndsEarly`，**装载这一步根本不该发生**
/// ⑥ 把长度截到最后一条 PT_LOAD 的文件末尾减 1 ⇒ 加载器必须按 `SegmentOutOfBounds` 拒
/// ⑦ 收尾把 VA 还回去：结束时的保留数与开始时相同（不给后面任何一次 `user::load` 留 `VaTaken`）
///
/// ⑤ 与 ⑥ 是这一格特有的：**"容器对不对"以前只能信内嵌那份字节**，因为输入是我编的；
/// 现在输入来自一块真盘上的元数据，"目录项撒谎时不许往下装"才第一次成为可判的事。
fn t_fat32_exec() -> bool {
    use filesystem::fat32::{FsError, Volume, EOC_MARKER};
    use filesystem::vfs::{AhciDisk, FileStat};

    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if ahci::init().is_err() {
        crate::log_fatal!("elfdisk: AHCI 认领失败，没有卷可读");
        return false;
    }
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("elfdisk: APIC 起不来，跑不了时间片");
        return false;
    }
    let before = mm::reservation_count();
    let vol = match Volume::mount(&AhciDisk { port: FAT_PORT_A }) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("elfdisk: 卷A（口{}）挂载失败 {:?}", FAT_PORT_A, e);
            return false;
        }
    };
    let st = match vol.open("HELLO.ELF") {
        Ok(s) => s,
        Err(e) => {
            crate::log_fatal!("elfdisk: 打开 HELLO.ELF 失败 {:?}", e);
            return false;
        }
    };

    // ① 上界先验再用：`st.size` 是**盘上元数据给的数**，它必须先在界内才允许变成拷贝长度
    let size = st.size as usize;
    if size > ELF_DISK_MAX {
        crate::log_fatal!("elfdisk: 目录项说大小={} 超过缓冲上限={} ⇒ 拒，不看内容", size, ELF_DISK_MAX);
        return false;
    }
    let bound_ok = size == HELLO_ELF.len();
    crate::log_info!(
        "elfdisk: 目录 大小={} 首簇={} 扫过项={} 缓冲上限={} 与内嵌夹具同长={}",
        size,
        st.first_cluster,
        st.entries_seen,
        ELF_DISK_MAX,
        bound_ok
    );

    // ② 走链喂进**静态**缓冲。为什么不是一次读满整个文件：`heap::LARGE_MAX = 2048`
    //    决定了"按外部输入的大小分配"在这台机上第一次分配就走 `handle_alloc_error`（BACKLOG 61a
    //    那条老账，这里是它的第四个使用点）；而每段最多一个簇 ⇒ 一次拷贝最多 512 字节。
    let dst = ELF_DISK.0.get();
    let mut fed = 0usize;
    // 第一次"喂出来的已经比目录项说的还多"的现场（已喂了多少、这一段又要喂多少）。
    // 这个量必须存在：注入 `fault-fat32-tail` 就是让它多喂一个字节，而那正是
    // "写区间靠一个来自盘上元数据的计数"会越界的地方。
    let mut over: Option<(usize, usize)> = None;
    let walked = vol.walk(&st, |chunk| {
        if fed + chunk.len() > size {
            // **不再写**。写下去的下一步是越界，而那表现是 panic 不是判据红——
            // 量具自己把"用例红"升级成"内核挂"是本仓库最不能留的一类错（§9.2 态度的延伸）。
            if over.is_none() {
                over = Some((fed, chunk.len()));
            }
            return;
        }
        // SAFETY: 见 `ElfDiskScratch`。写区间的界由这一格自己判（上面那个 `fed + len > size`
        // 就是那道闸），而 `size` 已在 ① 验过 `<= ELF_DISK_MAX`。
        // 这里**不再**依赖"`walk` 承诺不超过 size"那句话：它正是 `fault-fat32-tail` 推翻的东西。
        unsafe {
            let buf = &mut *dst;
            buf[fed..fed + chunk.len()].copy_from_slice(chunk);
        }
        fed += chunk.len();
    });
    let (w, disk) = match walked {
        Ok(w) => {
            // 显式取数组首地址再切片：`&(*dst)[..size]` 会对裸指针的解引用做隐式 autoref，
            // 那条会静默加上一层别名要求（本工具链直接判错）。写明白反而更容易看出借用从哪来。
            let head = unsafe { (*dst).as_ptr() };
            (w, unsafe { core::slice::from_raw_parts(head, size) })
        }
        Err(e) => {
            crate::log_fatal!("elfdisk: 走链失败 {:?}", e);
            return false;
        }
    };
    if let Some((at, n)) = over {
        crate::log_fatal!(
            "elfdisk: 尾格溢出 已喂={} 这段还要喂={} 目录项说={} 走链自报字节={} ⇒ 不往下装",
            at,
            n,
            size,
            w.bytes
        );
        return false;
    }
    let walk_ok = w.bytes == size
        && w.clusters == 62
        && w.tail_bytes == size - (w.clusters as usize - 1) * vol.bpb.cluster_bytes
        && w.after_last >= EOC_MARKER
        && fed == size;
    let bytes_same = disk == &HELLO_ELF[..];

    // ③ 段表两处对比（这份容器是 `ET_EXEC`，地址搬不动，所以两处必须逐格相同）
    let prog_d = elf::parse(disk);
    let prog_e = elf::parse(HELLO_ELF);
    let mut segs_same = false;
    match (&prog_d, &prog_e) {
        (Ok(a), Ok(b)) => {
            segs_same = a.entry == b.entry
                && a.n == b.n
                && a.phnum == b.phnum
                && a.segments().iter().zip(b.segments()).all(|(x, y)| {
                    x.offset == y.offset
                        && x.vaddr == y.vaddr
                        && x.filesz == y.filesz
                        && x.memsz == y.memsz
                        && x.readable == y.readable
                        && x.writable == y.writable
                        && x.executable == y.executable
                });
            for (i, s) in a.segments().iter().enumerate() {
                crate::log_info!(
                    "elfdisk: 段{} off={} va={:#x} filesz={} memsz={} r={} w={} x={}",
                    i,
                    s.offset,
                    s.vaddr,
                    s.filesz,
                    s.memsz,
                    s.readable,
                    s.writable,
                    s.executable
                );
            }
        }
        (Err(e), _) => crate::log_fatal!("elfdisk: 盘上那份解析失败 {:?}", e),
        _ => crate::log_fatal!("elfdisk: 内嵌那份解析失败（对照物本身没了）"),
    }

    // ④ 装进用户窗口并跑起来。这一段与 `t_elf_load_run` 同形状，差别只有一处：
    //    `bytes` 来自一次走链而不是 `.rodata`——所以判据必须与那条**同一组数**，
    //    否则"换了来源就换了行为"这件事没人能发现（串口上 `elfload:` 那两行就是第二台仪器）。
    let loaded = match user::load(disk) {
        Ok(l) => l,
        Err(e) => {
            crate::log_fatal!("elfdisk: 加载失败 —— {}", user::describe_load(e));
            return false;
        }
    };
    let code_eff = mm::effective_flags(loaded.entry);
    let data_eff = mm::effective_flags(loaded.data_va);
    let eff_ok = code_eff.is_some_and(|f| f.user && f.executable && !f.writable)
        && data_eff.is_some_and(|f| f.user && f.writable && !f.executable);
    let same_image = loaded.segs == prog_d.as_ref().map(|p| p.n).unwrap_or(0)
        && loaded.pages > 0;

    sched::init_boot_task();
    sched::start_workers();
    user::clear_counters();
    let t = match sched::spawn_user(loaded.entry, loaded.stack_top, loaded.owned) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("elfdisk: spawn_user 失败 {:?}", e);
            return false;
        }
    };
    apic::timer_start().ok();
    let mut rounds = 0u64;
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        while user::served() < P7_CALLS && tsc::now().wrapping_sub(t0) < 200_000_000 {
            rounds += 1;
            tsc::spin(20_000);
        }
        tsc::spin(2_000_000);
        if !sched::wait_for_boot_task(300_000_000) {
            crate::log_fatal!("elfdisk: 窗口收不了场（启动上下文没回到 CPU）");
        }
    });
    apic::timer_stop().ok();
    let magic = user::read_at(loaded.data_va);
    let ping = user::read_at(loaded.data_va + 8);
    let add = user::read_at(loaded.data_va + 16);
    let unk = user::read_at(loaded.data_va + 24);
    let rod = user::read_at(loaded.data_va + 32);
    let loops = user::read_at(loaded.data_va + 40);
    let served = user::served();
    let guard_ok = !mm::is_mapped(loaded.stack_top - mm::PAGE as u64 - 8);
    crate::log_info!(
        "elfdisk: 跑后 entry={:#x} data={:#x} stack_top={:#x} segs={} pages={} magic={:?} ping={:?} \
         add={:?} unk={:?} rodata={:?} loops={:?} served={} rounds={} guard_unmapped={} code={:?} data={:?}",
        loaded.entry,
        loaded.data_va,
        loaded.stack_top,
        loaded.segs,
        loaded.pages,
        magic,
        ping,
        add,
        unk,
        rod,
        loops,
        served,
        rounds,
        guard_ok,
        code_eff,
        data_eff
    );
    let run_ok = magic == Some(0xa5a5_5a5a_1234_5678)
        && loops == Some(28)
        && add == Some(0x2a + 0x12)
        && unk == Some(user::E_INVALID)
        && rod == Some(0xa7)
        && ping.is_some_and(|v| v >= 1)
        && served >= P7_CALLS
        && eff_ok
        && guard_ok
        && same_image;

    // ⑤ 目录项把大小说大 4096：链在喂完之前就到 EOC ⇒ 必须红在走链那一步，装载无从发生。
    //    这一格是"来源换成盘"之后新增的那一类：内嵌夹具的 size 是我编的，改不动它。
    let big = FileStat { size: (size + 4096) as u32, ..st };
    let oversized = vol.walk(&big, |_| {});
    let early_ok = matches!(oversized, Err(FsError::ChainEndsEarly { .. }));

    // ⑥ 截到最后一条 PT_LOAD 的文件末尾减 1 ⇒ 加载器必须拒。界取"段表自己说的最远字节"
    //    而不是随便少几个：这份容器的尾部还有 `.symtab/.strtab`（`filesz` 不覆盖它们），
    //    截 5 个字节谁都发现不了——那一格会绿着不测任何东西（`fault-fat32-tail` 同族的形状）。
    let last_end = prog_d
        .as_ref()
        .map(|p| p.segments().iter().map(|s| s.offset + s.filesz).max().unwrap_or(0))
        .unwrap_or(0);
    let last_end_ok = last_end > 0 && (last_end as usize) <= size;
    let truncated = if last_end_ok {
        user::load(&disk[..last_end as usize - 1])
    } else {
        // 段表自己给的界不可信 ⇒ 这一格没跑成。这里造的是一条**别的**拒绝码，
        // 于是下面那句 `matches!` 必然红——而不是"跳过这一格"混成绿（§12.4.1 规则 3 的形状）。
        crate::log_fatal!("elfdisk: 段表给的文件末尾不可信 last_end={} size={}，⑥ 没跑成", last_end, size);
        Err(user::LoadError::SegmentNotPageAligned { va: 0 })
    };
    let short_ok =
        matches!(truncated, Err(user::LoadError::Elf(elf::ElfError::SegmentOutOfBounds)));

    // ⑦ 收尾：把本用例名下的资源还回去，然后与开始前的保留数对账。
    //    `terminate_task` 之后还要 `reap_released()`——`elfload` 那一条的串口读数
    //    （`收尾回收 released=`）证明这两步都真发生了才有 6 条这个数。
    let terminated = sched::terminate_task(t);
    let released = sched::reap_released();
    let after = mm::reservation_count();
    let clean_up = terminated && after == before;
    crate::log_info!(
        "elfdisk: 负格 元数据说大={:?} 截短={:?} | 收尾 终止={} 回收={} 保留{}→{}",
        oversized.as_ref().err(),
        truncated.as_ref().err(),
        terminated,
        released,
        before,
        after
    );

    let ok = bound_ok && walk_ok && bytes_same && segs_same && run_ok && early_ok && short_ok && clean_up;
    crate::log_info!(
        "elfdisk: 判据 同长={} 走链={} 字节同={} 段表同={} 跑通={} 元数据说大被拒={} 截短被拒={} 收尾干净={} ⇒ {}",
        bound_ok,
        walk_ok,
        bytes_same,
        segs_same,
        run_ok,
        early_ok,
        short_ok,
        clean_up,
        ok
    );
    if !ok {
        crate::log_fatal!("elfdisk: 判据不成立（上面三行是这一跑的读数）");
    }
    ok
}
#[cfg(feature = "fat32-exec")]
ktest!(KT_FAT32_EXEC, t_fat32_exec);



/// M5-e①：§8.2/§8.5 的能力句柄表。六格各挡一种"句柄系统会怎么坏"，
/// 每格都要能单独变红（顺序就是函数体的顺序）：
/// 1 映射成功且授权是看得见的证据；同一格寄存器经 ctx 与经驱动两条路读到同一个数
/// 2 窗口外的偏移与不对齐的偏移必须被拒（不靠驱动自觉）
/// 3 **撤销后同一格被复用**，旧句柄必须开不了新资源（`StaleHandle`），新句柄照常
/// 4 句柄认主人：槽号与世代号全对，换一个 `ModuleId` 也必须被拒
/// 5 DMA：页框进台账、边界按窗口判、内容写得进也读得回
/// 6 撤销 DMA：页框回到原位、表里的占用格子数回到原位
fn t_driver_ctx() -> bool {
    // 用例必须自足：`.ktests` 的顺序由链接器决定，不能假设 `ahci` 已经认领过设备
    if ahci::init().is_err() {
        crate::log_fatal!("ctx: AHCI 认领失败，没有设备可发句柄");
        return false;
    }
    let Some(dev) = pci::first_of_triple(0x01, 0x06, 0x01) else {
        crate::log_fatal!("ctx: 枚举表里没有 SATA-AHCI 设备");
        return false;
    };
    let ctx = driver::DriverCtx::for_device(mm::MOD_TEST, dev);
    // 第二个令牌：设备一样、主人不一样。只用它的"读"去碰别人的句柄，不经它分配任何东西
    let other = driver::DriverCtx::for_device(mm::MOD_BOOT, dev);
    let (occ_m0, occ_d0) = driver::occupancy();
    let live0 = resource::live_of(mm::MOD_TEST);
    // 第三本账：VA 保留登记数。M4-2 撞过一次"映射解了但 VA 没放手"，表现是
    // 反复跑之后 `L4: VA 保留登记表已满` —— 一个进程生命周期的问题被报成内核故障。
    let res0 = mm::reservation_count();

    let Ok(h) = ctx.map_mmio(5) else {
        crate::log_fatal!("ctx: 映射 BAR5 失败");
        return false;
    };
    // 授权值要**当场存下来**：日志打印时那两格句柄都已经撤销了，再读一次只会拿到失败值
    let auth_val = ctx.mmio_authorized(h).unwrap_or(0);
    let authorized = auth_val & 0b110 == 0b110;
    let cap_ctx = ctx.read32(h, ahci::REG_CAP);
    // 两台仪器：经 ctx 读到的 `CAP` 必须等于驱动自己那张表里记着的同一个数
    let two_instruments = cap_ctx.ok() == ahci::info().map(|i| i.cap);
    let len = ctx.mmio_len(h).unwrap_or(0);
    let oob = matches!(ctx.read32(h, len), Err(driver::DriverError::Access(hw::HwError::OutOfRange)));
    let unaligned =
        matches!(ctx.read32(h, 1), Err(driver::DriverError::Access(hw::HwError::NotAligned)));

    // 3 撤销 → 复用同一格 → 旧句柄必须失效。两种坏法分开挡：表里空着时是"没有这一格"，
    // 被别人（或下一次分配）复用之后是"世代号不对"——只测后者就看不出撤销到底有没有真的摘走表项
    let slot = driver::mmio_slot(h);
    let released = ctx.release_mmio(h).is_ok();
    let refused_empty =
        matches!(ctx.read32(h, 0), Err(driver::DriverError::NoSuchHandle(s)) if s == slot);
    let Ok(h2) = ctx.map_mmio(5) else {
        crate::log_fatal!("ctx: 第二次映射失败，复用那一格没测成");
        return false;
    };
    let reused_same_slot = driver::mmio_slot(h2) == slot;
    let gen_moved = driver::mmio_gen(h2) != driver::mmio_gen(h);
    let table_agrees = driver::mmio_gen_at(slot) == Some(driver::mmio_gen(h2));
    let new_handle_works = ctx.read32(h2, ahci::REG_CAP).is_ok();
    let old_handle_refused =
        matches!(ctx.read32(h, ahci::REG_CAP), Err(driver::DriverError::StaleHandle { .. }));
    // 4 别人拿着完全正确的句柄也必须被拒（这一条只有表里的 owner 挡得住）
    let not_owner = matches!(
        other.read32(h2, ahci::REG_CAP),
        Err(driver::DriverError::NotOwner { slot: s, .. }) if s == slot
    );
    // 5 表里没有的槽号：越界一个、以及表内但空着的一格
    let no_such_far = matches!(
        ctx.read32(driver::mmio_handle_at(999, 1), 0),
        Err(driver::DriverError::NoSuchHandle(999))
    );
    let no_such_empty = matches!(
        ctx.read32(driver::mmio_handle_at(7, 1), 0),
        Err(driver::DriverError::NoSuchHandle(7))
    );
    let released2 = ctx.release_mmio(h2).is_ok();

    // 6/7 DMA：两本账（页框台账 + 表的占用数）与一条内容往返
    let dma_len = 2 * mm::PAGE;
    let d = match ctx.alloc_dma(dma_len) {
        Ok(d) => d,
        Err(e) => {
            crate::log_fatal!("ctx: 分配 DMA 失败 {:?}", e);
            return false;
        }
    };
    let live_dma = resource::live_of(mm::MOD_TEST);
    let frames_charged = live_dma == live0 + 2;
    let bus = ctx.bus_addr(d).unwrap_or(0);
    let bus_sane = bus != 0 && bus % mm::PAGE as u64 == 0;
    let (occ_m1, occ_d1) = driver::occupancy();
    let occupied = occ_d1 == occ_d0 + 1 && occ_m1 == occ_m0;
    let edge_write = ctx.dma_write8(d, dma_len - 1, 0x5A).is_ok();
    let edge_read = ctx.dma_read8(d, dma_len - 1) == Ok(0x5A);
    let head = ctx.dma_write32(d, 0, 0xDEAD_BEEF).and_then(|_| ctx.dma_read32(d, 0));
    let head_ok = head == Ok(0xDEAD_BEEF);
    let dma_oob =
        matches!(ctx.dma_read8(d, dma_len), Err(driver::DriverError::Denied(_)));
    let dma_unaligned =
        matches!(ctx.dma_read32(d, 1), Err(driver::DriverError::Access(hw::HwError::NotAligned)));
    let fill_ok = ctx
        .dma_fill(d, 0, 0xA7, dma_len)
        .and_then(|_| ctx.dma_read8(d, dma_len / 2))
        .map(|v| v == 0xA7)
        .unwrap_or(false);
    let mut out = [0u8; 8];
    ctx.dma_copy_out(d, dma_len - 8, &mut out).ok();
    let copy_out_ok = out == [0xA7; 8];
    ctx.release_dma(d).ok();
    let live_back = resource::live_of(mm::MOD_TEST) == live0;
    let occ_back = driver::occupancy() == (occ_m0, occ_d0);
    let res_back = mm::reservation_count() == res0;

    crate::log_info!(
        "ctx: 授权={}({:#06x}) 两条路同一个数={:#010x}={} 窗口={} 越界拒={} 未对齐拒={}",
        authorized,
        auth_val,
        cap_ctx.unwrap_or(0xFFFF_FFFF),
        two_instruments,
        len,
        oob,
        unaligned
    );
    crate::log_info!(
        "ctx: 复用同格={} 撤销返回={} 空表拒={} 世代号前/后={}/{} 表里读到={} 新句柄能用={} 旧句柄被拒={} 别人被拒={} 空槽拒={}/{}",
        reused_same_slot,
        released && released2,
        refused_empty,
        driver::mmio_gen(h),
        driver::mmio_gen(h2),
        table_agrees,
        new_handle_works,
        old_handle_refused,
        not_owner,
        no_such_far,
        no_such_empty
    );
    crate::log_info!(
        "ctx: DMA 总线地址={:#018x} 正常={} 页框进台账={}/{} 占用={} 边界内读写={} 首字节={} 越界拒={} 未对齐拒={} 填与读回={} 拷出={} 撤销后页框/占用/VA保留回到原位={}/{}/{}",
        bus,
        bus_sane,
        live0,
        live_dma,
        frames_charged && occupied,
        edge_write && edge_read,
        head_ok,
        dma_oob,
        dma_unaligned,
        fill_ok,
        copy_out_ok,
        live_back,
        occ_back,
        res_back
    );
    crate::log_info!(
        "ctx: 三本账基线 页框={} VA保留={} 表占用 MMIO/DMA={}/{} 探针后 VA保留={}",
        live0,
        res0,
        occ_m0,
        occ_d0,
        mm::reservation_count()
    );
    let ok = authorized
        && two_instruments
        && len > 0
        && oob
        && unaligned
        && released
        && refused_empty
        && released2
        && reused_same_slot
        && gen_moved
        && table_agrees
        && new_handle_works
        && old_handle_refused
        && not_owner
        && no_such_far
        && no_such_empty
        && bus_sane
        && frames_charged
        && occupied
        && edge_write
        && edge_read
        && head_ok
        && dma_oob
        && dma_unaligned
        && fill_ok
        && copy_out_ok
        && live_back
        && occ_back
        && res_back;
    if !ok {
        crate::log_fatal!("ctx: 句柄表判据不成立（上面三行是全部读数）");
    }
    ok
}
ktest!(KT_DRIVER_CTX, t_driver_ctx);

#[cfg(feature = "virtio-blk")]
/// M5-f①：virtio-blk 的现场取证（不建环、不发 I/O）。十格判据，每格都是"偏移的证人"，
/// 形状与 ADR-029 的端口寄存器表同一套：
/// 1 vendor 必须是 `0x1AF4`，能力链里 COMMON/NOTIFY/ISR/DEVICE 四条都要在（找不到 COMMON
///   就是 legacy 呈现，整个 modern 布局的前提不成立）
/// 2 `device_feature_select`(0x00) 与 `device_feature`(0x04) 是一对：换选页读数必须跟着变、
///   同页连读两次必须相同（只读）、选页越界必须读回 0
/// 3 `df1` 的 bit0（= `VIRTIO_F_VERSION_1`，位 32）必须置起来：modern 设备不提供它就说明
///   我对"这台设备是 modern"的理解是错的
/// 4 `device_status` 是 0x14 那**一个字节**：写 `ACK|DRIVER` 读回要等于它，0x10 那个 dword
///   与 0x15 的 `config_generation` 都不能被这次字节写改动
/// 5 写 0 复位之后 `device_status` 必须读回 0
/// 6 **字段各有宽度**：`read32(0x10)` 的高半在这台设备上读回 0，而 `read16(0x12)` 的
///   `num_queues` 非 0 ⇒ "读宽了会把隔壁那半丢成 0"是设备的实际行为，钉成判据
/// 7 `queue_select`(0x16) 真的是选择器：写 0/1 读回 0/1、写越界的 `0xFFFF` 被忽略（读回还是 1）、
///   写 `num_queues` 读回 `num_queues`，而只读的 `queue_notify_off`(0x1e) 跟着选择器 +1
/// 8 `queue_size` 必须是 2 的幂且非 0，选了"合法但没配出来"的索引必须读回 0
/// 9 ISR 那条能力指向的字节在复位后必须读回 0（读不到就说明 ISR 的偏移/宽度不对）
/// 10 `num_queues` 与容量必须非 0；容量的绝对对账在宿主机那侧做（`qemu-img` 知道这块文件多大）
fn t_virtio_probe() -> bool {
    let r = match virtio::probe() {
        Ok(r) => r,
        Err(e) => {
            crate::log_fatal!("virtio: 取证失败 {:?}", e);
            return false;
        }
    };
    let has = |t: u8| -> bool {
        r.caps[..usize::from(r.n_caps)].iter().any(|c| c.cfg_type == t)
    };
    for i in 0..usize::from(r.n_caps) {
        let c = r.caps[i];
        crate::log_info!(
            "virtio: 能力 cfg_type={} bar={} offset={:#06x} length={:#06x} notify_mult={}",
            c.cfg_type,
            c.bar,
            c.offset,
            c.length,
            c.notify_mult
        );
    }
    let found = r.vendor == virtio::VENDOR && r.n_caps >= 4;
    let four_caps =
        has(virtio::CAP_COMMON_CFG) && has(virtio::CAP_NOTIFY_CFG) && has(virtio::CAP_ISR_CFG) && has(virtio::CAP_DEVICE_CFG);
    let select_pair = r.df0 != r.df1 && r.df0 == r.df0_again && r.df_bad_select == 0;
    let version1 = r.df1 & 1 != 0;
    let status_byte = r.status_after_set == virtio::ACKNOWLEDGE | virtio::DRIVER
        && (r.dword_10_before as u16) == r.msix_config
        && r.dword_10_before == r.dword_10_after
        && r.cfg_gen_after == r.cfg_gen_before;
    let reset_ok = r.status_after_reset == 0;
    // 越宽读的那一格必须**丢掉**隔壁：`read32(0x10)` 的高半读回 0，而 `read16(0x12)` 非 0。
    // 这一条把"字段各有宽度"钉成判据，而不是写在注释里的规矩
    let width_witness = r.num_queues != 0 && (r.dword_10_before >> 16) as u16 == 0;
    // 选择器：写进去要读得回来；越界的 `0xFFFF` 必须被忽略（读回还是 1）；
    // 换选择器时只读的 `queue_notify_off` 要跟着 +1 ⇒ 0x16/0x18/0x1e 三格的关系一起钉住
    let selector = r.sel0_back == 0
        && r.sel1_back == 1
        && r.sel_ffff_back == 1
        && r.sel_beyond_back == r.num_queues
        && r.noff_q1 == r.noff_q0 + 1;
    let queue_size_ok = r.q0_size != 0 && r.q0_size.is_power_of_two() && r.q_beyond_size == 0;
    let isr_ok = r.isr_after_reset == 0;
    let shape_ok = r.num_queues != 0 && r.capacity != 0;
    crate::log_info!(
        "virtio: 设备 bdf={:#010x} vend={:#06x} dev={:#06x} 三件套={:#02x}/{:#02x}/{:#02x} rev={:#02x} BAR尺寸={} modern_id={}",
        r.bdf,
        r.vendor,
        r.device,
        r.class,
        r.subclass,
        r.progif,
        r.rev,
        r.bar_size,
        virtio::is_modern_id(r.device)
    );
    crate::log_info!(
        "virtio: 特征页0={:#010x} 页1={:#010x} 越界选页读回={:#010x} 队列数={} msix={:#06x} 配置代={}→{}",
        r.df0,
        r.df1,
        r.df_bad_select,
        r.num_queues,
        r.msix_config,
        r.cfg_gen_before,
        r.cfg_gen_after
    );
    crate::log_info!(
        "virtio: 状态写后读回={:#04x} 复位后={:#04x} 超宽读0x10={:#010x} 按宽度读 msix={:#06x} 队列数={}",
        r.status_after_set,
        r.status_after_reset,
        r.dword_10_before,
        r.msix_config,
        r.num_queues
    );
    crate::log_info!(
        "virtio: 选择器读回={}/{}/{}(越界写0xFFFF) 队列数索引读回={} 尺寸 q0={} q1={} 越界={} notify_off {}→{} ISR={:#04x} 容量扇区={} mult={}",
        r.sel0_back,
        r.sel1_back,
        r.sel_ffff_back,
        r.sel_beyond_back,
        r.q0_size,
        r.q1_size,
        r.q_beyond_size,
        r.noff_q0,
        r.noff_q1,
        r.isr_after_reset,
        r.capacity,
        r.notify_mult
    );
    let ok = found
        && four_caps
        && select_pair
        && version1
        && status_byte
        && reset_ok
        && width_witness
        && selector
        && queue_size_ok
        && isr_ok
        && shape_ok;
    crate::log_info!(
        "virtio: 取证判据 设备与能力链={}/{} 选页对={} VERSION_1={} 状态字节={} 复位={} 宽度={} 选择器={} 队列尺寸={} ISR={} 形状={}",
        found,
        four_caps,
        select_pair,
        version1,
        status_byte,
        reset_ok,
        width_witness,
        selector,
        queue_size_ok,
        isr_ok,
        shape_ok
    );
    if !ok {
        crate::log_fatal!("virtio: 取证判据不成立（上面五行是全部读数）");
    }
    ok
}
#[cfg(feature = "virtio-blk")]
ktest!(KT_VIRTIO_PROBE, t_virtio_probe);

/// M5-f②：virtqueue 建起来之后第一条真 I/O。判据八格：
/// 1 `bind()` 的握手全过，且 `queue_enable` 写 1 读回 1
/// 2 队列地址那三格**设备到底回不回读**——回读一致就当判据，不回读就只能打出来当事实、
///    改用"后续 I/O 成功"当行为证据（这一格不许把"没测到"写成"测到了"）
/// 3 读扇区 0：整扇区 512 字节都等于宿主机写进夹具的那个图案字节
///    （图案值两边各写一份 ⇒ `check-virtio-pattern` 那道门禁逐字对账）
/// 4 读回来的不是哨兵：证明"设备真的搬了数据"，不是缓冲里留着自己的 `0xEE`
/// 5 位置敏感：读扇区 1 的哈希必须与扇区 0 不同（防"读到的是上一次留在缓冲里的"）
/// 6 回执三格：`used.id` 是我们挂的链头 0、`used.len == 513`（数据 512 + 状态 1）、状态字节 = `S_OK`
/// 7 写方向：把与 LBA 绑定的图案写进扇区 8，再读回来逐字节一致（哈希相同）
/// 8 两台控制器互不牵连：这一路做完之后再走一遍 AHCI 的引导盘读，仍要成功
#[cfg(feature = "virtio-blk")]
fn t_virtio_io() -> bool {
    const EXPECT_PATTERN: u8 = 0x5C; // 必须与 tools/aurora.py 的 VBLK_PATTERN 同数（check-virtio-pattern 对账）
    if let Err(e) = virtio::bind() {
        crate::log_fatal!("vq: 绑定/握手失败 {:?}", e);
        return false;
    }
    let (qsize, capacity, notify, mult, addr_back, enable_back) = match virtio::status() {
        Some(v) => v,
        None => {
            crate::log_fatal!("vq: 绑定之后拿不到读数");
            return false;
        }
    };
    let mut zero = [0u8; 512];
    let r0 = match virtio::read_block(0, &mut zero) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("vq: 读扇区 0 失败 {:?}", e);
            return false;
        }
    };
    let pattern_ok = zero.iter().all(|b| *b == EXPECT_PATTERN);
    let not_sentinel = r0.hash != ahci::fnv1a64(&[0xEEu8; 512]);
    let mut one = [0u8; 512];
    let r1 = match virtio::read_block(1, &mut one) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("vq: 读扇区 1 失败 {:?}", e);
            return false;
        }
    };
    let position_dependent = r1.hash != r0.hash;
    let receipt_ok = r0.used_id == 0 && r0.used_len == 513 && r0.status == 0;
    // 写方向：图案与 LBA 绑定，所以"没写"、"写到别处"、"只写了一半"三种错法都过不了回读
    let mut src = [0u8; 512];
    for i in 0..512usize {
        src[i] = ahci::pattern_byte(8, i as u64);
    }
    let want_hash = ahci::fnv1a64(&src);
    if let Err(e) = virtio::write_block(8, &src) {
        crate::log_fatal!("vq: 写扇区 8 失败 {:?}", e);
        return false;
    }
    let mut back = [0u8; 512];
    let rw = match virtio::read_block(8, &mut back) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("vq: 写完回读失败 {:?}", e);
            return false;
        }
    };
    let write_ok = rw.hash == want_hash && ahci::data_head(8).map(|h| &h[0..8] == b"EFI PART").unwrap_or(false) == false;
    // 两台控制器互不牵连：走完 virtio 之后再读一次引导盘的分区头
    let ahci_still_ok = ahci::read_lba(ahci::boot_port().unwrap_or(0), 1, 1).is_ok()
        && ahci::data_head(8).map(|h| &h[0..8] == b"EFI PART").unwrap_or(false);
    crate::log_info!(
        "vq: 判据 enable读回={} 地址回读={:?} 队列深={} 容量={} notify={:#x}×{} | 扇区0图案={} 非哨兵={} 位置敏感={} 回执={}/{}/{} 写完回读={} AHCI照常={}",
        enable_back == 1,
        addr_back,
        qsize,
        capacity,
        notify,
        mult,
        pattern_ok,
        not_sentinel,
        position_dependent,
        r0.used_id,
        r0.used_len,
        r0.status,
        write_ok,
        ahci_still_ok
    );
    crate::log_info!(
        "vq: 取证 扇区0哈希={:#018x} 扇区1哈希={:#018x} 扇区8写后哈希={:#018x} 期望写值哈希={:#018x} used前后进过=({},{})",
        r0.hash,
        r1.hash,
        rw.hash,
        want_hash,
        r0.avail_idx,
        r0.used_idx
    );
    let ok = enable_back == 1 && pattern_ok && not_sentinel && position_dependent && receipt_ok
        && write_ok && ahci_still_ok && capacity > 0;
    if !ok {
        crate::log_fatal!("vq: virtqueue 判据不成立（上面两行是全部读数）");
    }
    ok
}
#[cfg(feature = "virtio-blk")]
ktest!(KT_VIRTIO_IO, t_virtio_io);

/// M8-a①：第一帧从 virtio-net 出去。判据八格（帧的**内容**由宿主机的 pcap 判，见矩阵第 23 行；
/// 这一格只判内核自己知道的事）：
/// 1 TX 队列（编号 1）使能写 1 读回 1，且队列深由设备给的非 0 数
/// 2 这台设备是"有收发两扇门"的网卡：`num_queues >= 2` 且 RX 与 TX 的 `queue_notify_off` 不同。
///    （不用 PCI device id 当身份：本机 QEMU 给 transitional 网卡的是 `0x1000`，按规范的
///    `0x1000+类型` 解出来是 0 而不是 1 —— 那一格改成只打印，实测记 BACKLOG 58）
/// 3 配置空间里的 MAC 是个"能用的地址"：不全 0、不全 FF、首字节的组播位为 0
/// 4 两个宽度证人：MAC 逐字节 == `dword(0)+word(4)` 拼出来的；`max_pairs`/`mtu` 是一个 dword 的两半。
///    第二格是 `Option`：本机不接受任何特性时设备只给 8 字节配置（legacy 形状），
///    第 8..12 字节读回全 0xFF —— 那是"这一格不存在"，取 `None` 打印，不许用 `0xFF==0xFF` 充当 `true`
/// 5 第一帧有回执：`used.idx` 比它自己那次发布的 `avail.idx` 大 1，`used.id` 是链头 0，长度是整帧 60
/// 6 第二帧的回执紧接在第一帧之后（再 +1）且**内容不同**（图案里带了序号）—— 只发得出一次不算队列能用
///    （5、6 都按增量判：绝对 `used.idx` 会把"别的用例先敲过这扇门"读成故障，见代码里那条注释）
/// 7 回执之后从 DMA 再读那 60 字节哈希不变：TX 方向设备只许读，改了就是环与帧的地址摆重了
/// 8 走完网卡之后 AHCI 那条读仍成功：两台控制器互不牵连（与块设备那条同一格）
#[cfg(feature = "virtio-net")]
fn t_net_tx() -> bool {
    if let Err(e) = virtio::bind_net() {
        crate::log_fatal!("net: 绑定/握手失败 {:?}", e);
        return false;
    }
    let i = match virtio::net_info() {
        Some(v) => v,
        None => {
            crate::log_fatal!("net: 绑定之后拿不到读数");
            return false;
        }
    };
    let q_ok = i.enable_readback == 1 && i.qsize > 0;
    let nic_shape = i.num_queues >= 2 && i.noff_rx != i.noff_tx;
    let mac_shape = i.mac != [0u8; 6]
        && i.mac != [0xFF; 6]
        && i.mac[0] & 0x01 == 0;
    let width_ok = i.mac_width_ok && i.pairs_width_ok != Some(false);
    let f1 = match virtio::send_frame(1) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("net: 第一帧失败 {:?}", e);
            return false;
        }
    };
    let f2 = match virtio::send_frame(2) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("net: 第二帧失败 {:?}", e);
            return false;
        }
    };
    // 两格都按**增量**判：`used.idx` 的绝对值取决于别的用例有没有先敲过这扇门
    // （`.ktests` 的顺序由链接器决定，判据不许依赖用例先后——这条本轮又撞了一次：
    //   `KT_NET_RX` 先发了一次 DISCOVER，写成"必须等于 1/2"的绝对判据就当场红了）
    let tx1_ok = f1.used_id == 0
        && f1.len == virtio::NET_FRAME_BYTES
        && f1.used_idx == f1.avail_idx.wrapping_add(1);
    let tx2_ok = f2.used_idx == f1.used_idx.wrapping_add(1) && f2.hash != f1.hash;
    let untouched_ok = f1.hash_after == f1.hash && f2.hash_after == f2.hash;
    let ahci_still_ok = ahci::read_lba(ahci::boot_port().unwrap_or(0), 1, 1).is_ok();
    crate::log_info!(
        "net: 判据 enable读回={} 队列深={} 网卡形状={} MAC形状={} 宽度证人={}/{:?} 帧1={}/{}/{} 帧2={} 字节没动={} AHCI照常={}",
        i.enable_readback,
        i.qsize,
        nic_shape,
        mac_shape,
        i.mac_width_ok,
        i.pairs_width_ok,
        f1.used_idx,
        f1.used_id,
        f1.len,
        f2.used_idx,
        untouched_ok,
        ahci_still_ok
    );
    crate::log_info!(
        "net: 取证 bdf={:#010x} 设备id={:#06x} 解出类型={}(网卡={}) class={:#04x} 队列数={} 门={:#x}×{} 门位rx/tx={}/{} 地址回读={:?} 配置长={} mtu={} 队列对={} 链路={:#06x} 特性页0={:#010x} 有MAC位={}",
        i.bdf,
        i.device_id,
        virtio::dev_type(i.device_id),
        virtio::VIRTIO_ID_NET,
        i.class,
        i.num_queues,
        i.notify,
        i.notify_mult,
        i.noff_rx,
        i.noff_tx,
        i.addr_readback,
        i.cfg_len,
        i.mtu,
        i.max_pairs,
        i.link,
        i.df0,
        i.df0 & (1 << virtio::F_NET_MAC) != 0
    );
    crate::log_info!(
        "net: 配置原始 {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x}",
        i.cfg_raw[0], i.cfg_raw[1], i.cfg_raw[2], i.cfg_raw[3],
        i.cfg_raw[4], i.cfg_raw[5], i.cfg_raw[6], i.cfg_raw[7],
        i.cfg_raw[8], i.cfg_raw[9], i.cfg_raw[10], i.cfg_raw[11],
        i.cfg_raw[12], i.cfg_raw[13], i.cfg_raw[14], i.cfg_raw[15]
    );
    for f in [f1, f2] {
        crate::log_info!(
            "net: 帧 序号={} 长={} 哈希={:#018x} 源MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} 回执长={} 发后哈希={:#018x} avail/used=({},{})",
            f.seq,
            f.len,
            f.hash,
            i.mac[0],
            i.mac[1],
            i.mac[2],
            i.mac[3],
            i.mac[4],
            i.mac[5],
            f.used_len,
            f.hash_after,
            f.avail_idx,
            f.used_idx
        );
    }
    let ok = q_ok && nic_shape && mac_shape && width_ok && tx1_ok && tx2_ok && untouched_ok && ahci_still_ok;
    if !ok {
        crate::log_fatal!("net: 第一帧判据不成立（上面几行是全部读数）");
    }
    ok
}
#[cfg(feature = "virtio-net")]
ktest!(KT_NET_TX, t_net_tx);

/// M8-a②：第一次真协议往返（对端 = QEMU 的用户网络里那个 DHCP 服务器）。判据七格：
/// 1 RX 队列也建起来了：`queue_enable` 写 1 读回 1、队列深非 0、且 RX 与 TX 的门位不是同一个
/// 2 DISCOVER 发出去有回执（TX 那条路仍然通）
/// 3 收到一包：RX 的 `used.idx` 在有界等待之内前进（等不到就是 `UsedTimeout`，当场红）
/// 4 那一包解得开：ethertype 0x0800、IPv4 协议号 17、BOOTP `op=2`、选项 53 是 OFFER 或 ACK
/// 5 `xid` 等于我们发出去的那一个 —— 回话必须是答**这一次**请求的，不是答上一次启动留下的
/// 6 `yiaddr` 等于夹具里 `dhcpstart=` 那一个数（内核从线上读出来的地址，与宿主机自己配的对照）
/// 7 `used.id` 等于我们挂的那条链（今天只挂一条 ⇒ 只许是 0）：写错缓冲就是下一个包覆盖我
///    帧字节本身由第二台仪器判：矩阵第 24 行拿 pcap 里那条 inbound 包重算同一个哈希
#[cfg(feature = "virtio-net")]
fn t_net_rx() -> bool {
    if let Err(e) = virtio::bind_net() {
        crate::log_fatal!("rx: 绑定/握手失败 {:?}", e);
        return false;
    }
    let i = match virtio::net_info() {
        Some(v) => v,
        None => {
            crate::log_fatal!("rx: 绑定之后拿不到读数");
            return false;
        }
    };
    let q_ok = i.rx_enable_readback == 1 && i.rx_qsize > 0 && i.noff_rx != i.noff_tx;
    let (frame, want_hash) = virtio::build_dhcp_discover(&i.mac);
    match virtio::send_raw(&frame) {
        Ok(f) => crate::log_info!(
            "rx: 发 DISCOVER 长={} 哈希={:#018x} 自算={:#018x} 回执idx={} id={}",
            f.len,
            f.hash,
            want_hash,
            f.used_idx,
            f.used_id
        ),
        Err(e) => {
            crate::log_fatal!("rx: DISCOVER 发不出去 {:?}", e);
            return false;
        }
    }
    let (buf, n, used_idx, used_len, used_id) = match virtio::receive(3000) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("rx: 有界等待之内没等到回话 {:?}", e);
            return false;
        }
    };
    let r = match virtio::parse_reply(&buf[..n], used_idx, used_len, used_id) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("rx: 收到的那包解不开（长 {}）{:?} 前十六字节={:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x}",
                n, e, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
                buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
            return false;
        }
    };
    let parsed_ok = r.op == virtio::BOOTREPLY
        && (r.msg_type == virtio::DHCP_OFFER || r.msg_type == virtio::DHCP_ACK)
        && r.ethertype == virtio::NET_TYPE_IPV4;
    let xid_ok = r.xid == virtio::DHCP_XID;
    let ip_ok = r.yiaddr == virtio::DHCP_GUEST_IP;
    // 设备写回来的必须是**我们挂上去的那一条链**：今天只挂一条，所以合法 id 只有 0。
    // 这一格是"内存安全"那一侧的：写错缓冲就是别人（下一个包）覆盖我
    let id_ok = r.used_id == 0;
    crate::log_info!(
        "rx: 收到 长={} 哈希={:#018x} 类型={:#06x} op={} 消息={} xid={:#010x} yiaddr={}.{}.{}.{} used.idx={} 设备写={} used.id={}",
        r.len,
        r.hash,
        u16::from(r.ethertype[0]) << 8 | u16::from(r.ethertype[1]),
        r.op,
        r.msg_type,
        r.xid,
        r.yiaddr[0],
        r.yiaddr[1],
        r.yiaddr[2],
        r.yiaddr[3],
        r.used_idx,
        r.used_len,
        r.used_id
    );
    crate::log_info!(
        "rx: 判据 RX队列={} 解得开={} xid对={} 地址对={} 缓冲对={} RX门={:#x} 门位rx/tx={}/{} RX地址回读={:?}",
        q_ok,
        parsed_ok,
        xid_ok,
        ip_ok,
        id_ok,
        i.rx_notify,
        i.noff_rx,
        i.noff_tx,
        i.rx_addr_readback
    );
    // 第 2、3 格（发出去、收到包）是提前退出：任何一条失败就已经 `return false`
    let ok = q_ok && parsed_ok && xid_ok && ip_ok && id_ok;
    if !ok {
        crate::log_fatal!("rx: 第一条协议往返判据不成立（上面三行是全部读数）");
    }
    ok
}
#[cfg(feature = "virtio-net")]
ktest!(KT_NET_RX, t_net_rx);

/// M9-a①：SHA-256 的现场。判据五格（**对不对**由宿主机的 `hashlib` 判，见矩阵第 25 行；
/// 这一格只判内核自己知道的那些形状）：
/// 1 十三个长度向量两两摘要不同 —— 长度取 0/3/55/56/57/63/64/65/111/112/119/120/128，
///    把补位的四个边界（55|56、63|64、111|112、119|120）都各踩一次
/// 2 空串的八个字都不为 0，也不是全 F（护栏：写错初始值最容易塌成这两种）
/// 3 雪崩：把 payload 里一个 bit 翻掉，摘要至少 8/32 个字节不同
/// 4 同一输入两次算出的摘要相同（幂等，防"状态忘了复位"这种错法）
/// 5 `words()` 与字节数组的端序自洽：第一个字的高两字节就是摘要的前两个字节
#[cfg(feature = "sig-check")]
fn t_sha256() -> bool {
    fn payload_byte(i: usize) -> u8 {
        ((i * 7 + 0x5A) & 0xFF) as u8
    }
    const LENGTHS: [usize; 13] = [0, 3, 55, 56, 57, 63, 64, 65, 111, 112, 119, 120, 128];
    let mut digests: [[u8; sign::DIGEST_BYTES]; 13] = [[0; sign::DIGEST_BYTES]; 13];
    let mut same_as_prev = false;
    for (n, len) in LENGTHS.iter().enumerate() {
        let mut msg = [0u8; 128];
        for i in 0..*len {
            msg[i] = payload_byte(i);
        }
        digests[n] = sign::digest(&msg[..*len]);
        if n > 0 && digests[n] == digests[n - 1] {
            same_as_prev = true;
        }
        let w = sign::words(&digests[n]);
        crate::log_info!(
            "sha: 向量 长度={} 摘要={:#010x} {:#010x} {:#010x} {:#010x} {:#010x} {:#010x} {:#010x} {:#010x}",
            len, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]
        );
    }
    let distinct = !same_as_prev;
    let empty = sign::digest(&[]);
    let ew = sign::words(&empty);
    let shape_ok = ew.iter().all(|x| *x != 0 && *x != 0xFFFF_FFFF);
    // 雪崩：与"长度 64 的那个向量"只差一个 bit
    let mut flip = [0u8; 64];
    for i in 0..64 {
        flip[i] = payload_byte(i);
    }
    flip[10] ^= 0x01;
    let mut orig = [0u8; 64];
    for i in 0..64 {
        orig[i] = payload_byte(i);
    }
    let avalanche = sign::digest(&flip)
        .iter()
        .zip(sign::digest(&orig).iter())
        .filter(|(a, b)| a != b)
        .count();
    let again = sign::digest(&orig) == sign::digest(&orig);
    let endian_ok = (ew[0] >> 16) as u16 == u16::from_be_bytes([empty[0], empty[1]]);
    crate::log_info!(
        "sha: 判据 长度向量互不相同={} 空串形状={} 雪崩字节={}/32 幂等={} 端序自洽={}",
        distinct,
        shape_ok,
        avalanche,
        again,
        endian_ok
    );
    let ok = distinct && shape_ok && avalanche >= 8 && again && endian_ok;
    if !ok {
        crate::log_fatal!("sha: SHA-256 判据不成立（上面十四行是全部读数）");
    }
    ok
}
#[cfg(feature = "sig-check")]
ktest!(KT_SHA256, t_sha256);

/// 签名包的缓冲（57,856 字节 = 56.5 KiB）比分配器上限大两个数量级，理由与 `ELF_SCRATCH`
/// 同一条：按外部输入大小 `to_vec()` 第一次分配就走 `handle_alloc_error`，整机构成 39。
#[cfg(feature = "sig-check")]
struct PkgScratch(UnsafeCell<[u8; sign::PKG_BYTES]>);
#[cfg(feature = "sig-check")]
// SAFETY: 只在 `sig-check` 变体的这一条用例里用，调用点在关中断窗口内，
//         可变借用只在这一次调用内活着（不外泄 `&'static mut`），不同时存在两份
unsafe impl Sync for PkgScratch {}
#[cfg(feature = "sig-check")]
static PKG_BUF: PkgScratch = PkgScratch(UnsafeCell::new([0u8; sign::PKG_BYTES]));

/// M9-a②：盘上那份签名包的读取与验证。判据六格：
/// 1 从固定 LBA 分块读满一整包（`sign::PKG_BYTES` 个字节一次不少，读失败就直接红）
/// 2 头自洽：魔数、版本、三个长度字段各按自身宽度读，并且**先验上界再用**（§10.3 那条）
/// 3 真包验签通过（`check_package` 回 `Ok`）
/// 4 包里的载荷与内核手上那份夹具是同一段字节：长度同数、两条摘要同数
///    （一个来自盘上 15 次分块读，一个来自镜像里 `include_bytes!` 的那份）
/// 5 八种篡改**每一种都必须被拒**，并把拒绝理由与附带的数字打出来 —— 宿主机用自己的实现
///    对同一批输入算同一份答案，两边逐条相同（这就是"协议 fuzz"的第一个形状：畸形输入
///    必须被定性拒绝，不许崩、不许静默接受）
/// 6 走完这一大包之后，引导盘的 LBA 1 仍读得到 `EFI PART`：读盘 15 次不许把别的读者弄坏
#[cfg(feature = "sig-check")]
fn t_sig_package() -> bool {
    const CHUNK: usize = 4096;
    let port = match ahci::boot_port() {
        Ok(p) => p,
        Err(e) => {
            crate::log_fatal!("pkg: 找不到引导口 {:?}", e);
            return false;
        }
    };
    // SAFETY: 见 `PkgScratch` —— 单一持有者、关中断窗口内的用例上下文、借用不出本次调用
    let buf = unsafe { &mut *PKG_BUF.0.get() };
    let mut off = 0usize;
    let mut reads = 0usize;
    while off < sign::PKG_BYTES {
        let n = CHUNK.min(sign::PKG_BYTES - off);
        let lba = sign::PKG_START_LBA + (off / sign::SECTOR_BYTES) as u64;
        if let Err(e) = ahci::read_bytes(port, lba, &mut buf[off..off + n]) {
            crate::log_fatal!("pkg: 第 {} 次分块读失败 lba={} 长={} {:?}", reads, lba, n, e);
            return false;
        }
        off += n;
        reads += 1;
    }
    let load_ok = off == sign::PKG_BYTES;
    let accepted = sign::check_package(buf, &sign::PK_ANCHOR);
    let (hdr_ok, verify_ok, pay_len) = match accepted {
        Ok(n) => (true, true, n),
        Err(e) => {
            let h = !matches!(e, sign::PkgError::BadLen(_) | sign::PkgError::PayloadTooLong(_));
            crate::log_fatal!("pkg: 真包被拒 理由={} 附带={}", sign::reason(e), sign::reason_arg(e));
            (h, false, 0)
        }
    };
    // 载荷 vs 内核手上那份夹具：两条来源必须给同一个数
    let payload_same = pay_len == HELLO_ELF.len()
        && sign::digest(&buf[sign::PAY_OFF..sign::PAY_OFF + pay_len])
            == sign::digest(HELLO_ELF);
    crate::log_info!(
        "pkg: 取证 读满={} 次 字节={} 头自洽={} 验签={} 载荷长={}/{} 载荷同={} 锚点={:#010x}",
        reads,
        off,
        hdr_ok,
        verify_ok,
        pay_len,
        HELLO_ELF.len(),
        payload_same,
        u32::from_be_bytes([
            sign::PK_ANCHOR[0],
            sign::PK_ANCHOR[1],
            sign::PK_ANCHOR[2],
            sign::PK_ANCHOR[3]
        ])
    );
    // 八种篡改：改一个字节 → 必须被拒 → 打回理由 → 还原。还原是必须的，
    // 否则下一格测的就不是"那一种篡改"而是前一种的残留（用例自己污染现场，与 ㊻ 同形）
    let mut rejected = 0usize;
    for (i, t) in sign::TAMPERS.iter().enumerate() {
        buf[t.at] ^= t.mask;
        let r = match sign::check_package(buf, &sign::PK_ANCHOR) {
            Err(e) => {
                rejected += 1;
                (sign::reason(e), sign::reason_arg(e))
            }
            Ok(_) => ("ACCEPTED", 0u32),
        };
        buf[t.at] ^= t.mask;
        crate::log_info!(
            "pkg: 篡改 {} 位置={} 掩码={:#04x} 目的={} 理由={} 附带={}",
            i,
            t.at,
            t.mask,
            t.why,
            r.0,
            r.1
        );
    }
    let tamper_ok = rejected == sign::TAMPERS.len();
    // 大包读完之后引导盘那条路仍然完好
    let mut head = [0u8; 512];
    let ahci_still_ok = ahci::read_bytes(port, 1, &mut head).is_ok() && &head[0..8] == b"EFI PART";
    crate::log_info!(
        "pkg: 判据 读满={} 头自洽={} 验签={} 载荷同={} 篡改全拒={}/{} AHCI照常={}",
        load_ok,
        hdr_ok,
        verify_ok,
        payload_same,
        rejected,
        sign::TAMPERS.len(),
        ahci_still_ok
    );
    let ok = load_ok && hdr_ok && verify_ok && payload_same && tamper_ok && ahci_still_ok;
    if !ok {
        crate::log_fatal!("pkg: 签名包判据不成立（上面十行是全部读数）");
    }
    ok
}
#[cfg(feature = "sig-check")]
ktest!(KT_SIG_PACKAGE, t_sig_package);

/// M6-a①：§9.4/§9.7/ADR-011-临时 的共同地基 —— 一块跨重启保留的记录区。
///
/// 判据分两层，故意的：**格式判据不碰盘**（纯函数，跑一百次都一样），
/// **现场判据必须碰盘**（不碰盘就证明不了"下一次启动还看得见"）。
/// 1 `encode`→`decode` 往返：六个字段 + kind + seq 都要原样回来
/// 2 全 0 缓冲 ⇒ 判为"读不到"（这就是全新镜像那 4 KiB 的形状）
/// 3 payload 中间翻一个字节 ⇒ 判为"读不到"，**不许**读出一个看似合法的中间值
/// 4 `size` 被改成超出缓冲 ⇒ 必须挡住（它会让校验和指着缓冲外面）
/// 5 `version` 不认识 ⇒ 单独一种错误，不猜字段含义
/// 6 抹掉整块区域后 `read()` 必须是 `NoValidSlot`（最坏情况的入口）
/// 7 写→读要一致，且第二次写的 `seq` 严格 +1、槽位轮转
/// 8 **把最新那个槽弄坏，`read()` 必须退回上一槽的旧记录**——轮转只毁一个槽的全部意义
/// 9 全坏之后重新写：从 `seq=1` 起（坏记录不会把状态机永久卡住）
/// 10 跨种类（M6-b①）：区里只有一种记录时另一种必须读不到；写进第三种记录 `KIND_PROBE` 之后
///    `seq` 仍按**整块区**单调；`read(种类)` 取的是该种类自己的最新，不是"区里最新那条"
/// 11 弄坏"全局最新那一条"⇒ 只许毁它自己那一格：同种类的退回旧记录，隔壁种类一条不少
fn t_state_store() -> bool {
    use state_store as ss;
    let s1 = ss::BootState {
        failed_boots: 2,
        good_slot: 1,
        bad_slot: 3,
        last_vector: 14,
        last_cpu: 1,
        last_rip: 0xffff_8000_1234_5678,
    };
    // 1 往返
    let buf = ss::encode(ss::KIND_BOOT, 7, &s1);
    let back = ss::decode(0, &buf);
    let round_trip = matches!(back, Ok((kind, seq, ref st)) if kind == ss::KIND_BOOT && seq == 7 && *st == s1);
    // 2 全 0
    let zeroed = [0u8; ss::SLOT_BYTES];
    let blank_rejected = matches!(ss::decode(1, &zeroed), Err(ss::StoreError::Torn { slot: 1, .. }));
    // 3 撕裂：翻 payload 里的一个字节 ⇒ 校验和必须挡；翻校验和本身也一样
    let mut torn = buf;
    torn[30] ^= 0xFF;
    let torn_rejected = matches!(ss::decode(0, &torn), Err(ss::StoreError::Torn { .. }));
    let mut cut_sum = buf;
    cut_sum[52] ^= 0x80;
    let sum_rejected = matches!(ss::decode(0, &cut_sum), Err(ss::StoreError::Torn { .. }));
    // 3b 校验和**只覆盖头部 + payload**：翻填充区（第 256 字节）记录照旧可解。
    // 这一条不是说"那样也行"，是把保护范围写成能判的事实 —— 半条记录落在保护范围外
    // 的那种撕裂，本来就得靠"长度字段 + 校验和"这两个一起挡（上面两条已挡）。
    let mut padded = buf;
    padded[256] ^= 0xFF;
    let outside_range_ok = matches!(ss::decode(0, &padded), Ok((_, 7, _)));
    // 4 size 越界（把首字段改成 4000，仍保留原校验和位置 ⇒ 必须先在界检查上被挡）
    let mut huge = buf;
    huge[0..4].copy_from_slice(&4000u32.to_le_bytes());
    let size_rejected = matches!(ss::decode(0, &huge), Err(ss::StoreError::Torn { .. }));
    // 5 版本
    let mut future = buf;
    future[8..12].copy_from_slice(&7u32.to_le_bytes());
    let version_rejected = matches!(ss::decode(0, &future), Err(ss::StoreError::Version(7)));

    // 以下必须碰盘。先确保设备已认领（`.ktests` 顺序由链接器决定，不能假设别人跑过）
    if ahci::init().is_err() {
        crate::log_fatal!("state: AHCI 没认领上，现场判据没法做");
        return false;
    }
    let port = match ahci::boot_port() {
        Ok(p) => p,
        Err(e) => {
            crate::log_fatal!("state: 找不到引导盘 {:?}", e);
            return false;
        }
    };
    // **先存下启动时那条记录**：用例要在盘上折腾，最后必须原样放回。
    // 不放回会怎样是实测到的：本用例写的 `failed_boots=2` 留在盘上，下一次启动读到 2、
    // 再下一次还是 2 —— 跨重启的计数被用例冻住，而每一跑都"全绿"。
    let saved = ss::read(ss::KIND_BOOT).ok();
    let wiped = ss::wipe().is_ok();
    let empty_is_worst_case = matches!(ss::read(ss::KIND_BOOT), Err(ss::StoreError::NoValidSlot));

    let w1 = ss::write(ss::KIND_BOOT, &s1);
    let s2 = ss::BootState { failed_boots: 5, ..s1 };
    let w2 = ss::write(ss::KIND_BOOT, &s2);
    let (slot1, seq1) = match w1 {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("state: 第一次写失败 {:?}", e);
            return false;
        }
    };
    let (slot2, seq2) = match w2 {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("state: 第二次写失败 {:?}", e);
            return false;
        }
    };
    let read2 = ss::read(ss::KIND_BOOT);
    let persisted = matches!(read2, Ok((_, seq, ref st)) if seq == seq2 && st.failed_boots == 5 && st.good_slot == 1);
    let rotated = slot2 != slot1 && seq2 == seq1 + 1;
    // 8 把最新的槽弄坏 ⇒ 必须退回上一槽（seq1 那条，failed_boots=2）
    let mut broken = [0u8; ss::SLOT_BYTES];
    broken[3] = 0xE5;
    let corrupted = ahci::write_bytes(port, ss::slot_lba(slot2), &broken).is_ok();
    let fell_back = matches!(ss::read(ss::KIND_BOOT), Ok((slot, seq, ref st)) if slot == slot1 && seq == seq1 && st.failed_boots == s1.failed_boots);
    // 9 两个槽全坏 ⇒ NoValidSlot，然后重新写得起来（seq 从 1 重新开始）
    let _ = ahci::write_bytes(port, ss::slot_lba(slot1), &broken);
    let all_broken = matches!(ss::read(ss::KIND_BOOT), Err(ss::StoreError::NoValidSlot));
    let w3 = ss::write(ss::KIND_BOOT, &s1);
    let recovered = matches!(w3, Ok((_, 1)));
    let readable_after_recover = matches!(ss::read(ss::KIND_BOOT), Ok((_, _, ref st)) if st.failed_boots == s1.failed_boots);
    // 10 两种记录共用一块区 ⇒ `seq` 必须按**整块区**单调，"最新"必须按种类各取各的。
    //    这是 §9.7 崩溃记录（第二种 `kind`）的硬前置：各数各的 `seq` 时"谁新"没有定义。
    let (slot3, seq3) = match w3 { Ok(v) => v, Err(_) => (0, 0) };
    let crash_absent = matches!(ss::read(ss::KIND_PROBE), Err(ss::StoreError::NoValidSlot))
        && matches!(ss::read(ss::KIND_BOOT), Ok((_, seq, _)) if seq == seq3);
    let s_probe = ss::BootState { last_vector: 13, last_cpu: 2, ..s1 };
    let w4 = ss::write(ss::KIND_PROBE, &s_probe);
    let w5 = ss::write(ss::KIND_BOOT, &s2);
    let (slot4, seq4) = match w4 { Ok(v) => v, Err(_) => (0, 0) };
    let (slot5, seq5) = match w5 { Ok(v) => v, Err(_) => (0, 0) };
    let cross_seq_monotonic = seq4 == seq3 + 1 && seq5 == seq4 + 1;
    let per_kind_latest = matches!(ss::read(ss::KIND_BOOT), Ok((s, seq, ref st)) if s == slot5 && seq == seq5 && st.failed_boots == 5)
        && matches!(ss::read(ss::KIND_PROBE), Ok((s, seq, ref st)) if s == slot4 && seq == seq4 && st.last_vector == 13);
    // 11 弄坏"全局最新那一条"（它恰好是 boot 记录）⇒ boot 退回自己那条旧的，崩溃记录一条不少。
    //    这一格把"轮转只毁一个槽"从同种类的说法升级成跨种类的说法：撕裂不许把隔壁种类也带走。
    let _ = ahci::write_bytes(port, ss::slot_lba(slot5), &broken);
    let one_slot_only = matches!(ss::read(ss::KIND_BOOT), Ok((s, seq, ref st)) if s == slot3 && seq == seq3 && st.failed_boots == s1.failed_boots)
        && matches!(ss::read(ss::KIND_PROBE), Ok((s, seq, _)) if s == slot4 && seq == seq4);
    // 收尾：把盘放回启动时那条记录，然后按**放回之后的现场**打印对账用的那一行。
    // 顺序很重要：宿主机那台仪器读的是跑完之后的镜像，所以它必须看到这一行说的槽。
    ss::wipe().ok();
    let rest = match saved {
        Some((_, _, st)) => ss::write(ss::KIND_BOOT, &st),
        None => Ok((0u8, 0u64)),
    };
    let (final_slot, final_seq, final_failed) = match &rest {
        Ok((slot, seq)) => (*slot, *seq, saved.map(|(_, _, st)| st.failed_boots).unwrap_or(0)),
        Err(_) => (0, 0, 0),
    };
    let put_back = rest.is_ok()
        && matches!(ss::read(ss::KIND_BOOT), Ok((_, _, ref st)) if saved.map(|(_, _, s)| s.failed_boots == st.failed_boots).unwrap_or(true));

    crate::log_info!(
        "state: 格式判据 往返={} 全0拒={} 撕裂拒={}/{}（payload/校验和） 界外照解={} size拒={} 版本拒={}",
        round_trip,
        blank_rejected,
        torn_rejected,
        sum_rejected,
        outside_range_ok,
        size_rejected,
        version_rejected
    );
    crate::log_info!(
        "state: 现场判据 抹掉={} 空区按最坏={} 写后读回={} 轮转(槽{}→{} seq{}→{})={} 弄坏最新仍读旧的={} 全坏={} 重新写起={}/{}",
        wiped,
        empty_is_worst_case,
        persisted,
        slot1,
        slot2,
        seq1,
        seq2,
        rotated,
        corrupted && fell_back,
        all_broken,
        recovered,
        readable_after_recover
    );
    crate::log_info!(
        "state: 跨种类判据 只有一种时另一种读不到={} seq全局单调({}→{}→{})={} 各取各的最新={} 撕裂只毁一个种类={}",
        crash_absent,
        seq3,
        seq4,
        seq5,
        cross_seq_monotonic,
        per_kind_latest,
        one_slot_only
    );
    // 宿主机那台仪器要用的一行：**放回之后**留在盘上的那条记录是哪一槽、seq、failed 多少
    crate::log_info!(
        "state: 落盘 区LBA={} 槽={} 槽字节={} seq={} failed={} 种类={} 放回={}",
        ss::STATE_START_LBA,
        final_slot,
        ss::SLOT_BYTES,
        final_seq,
        final_failed,
        ss::KIND_BOOT,
        put_back
    );
    let ok = round_trip
        && blank_rejected
        && torn_rejected
        && sum_rejected
        && outside_range_ok
        && size_rejected
        && version_rejected
        && wiped
        && empty_is_worst_case
        && persisted
        && rotated
        && corrupted
        && fell_back
        && all_broken
        && recovered
        && readable_after_recover
        && crash_absent
        && cross_seq_monotonic
        && per_kind_latest
        && one_slot_only
        && put_back;
    if !ok {
        crate::log_fatal!("state: 状态区判据不成立（上面四行是全部读数）");
    }
    ok
}
ktest!(KT_STATE_STORE, t_state_store);

/// M6-a②：§9.4 的决策与"安全模式真的有后果"。四格：
/// 1 纯函数：阈值之下是正常、达到阈值是安全模式（`u32::MAX` 也要给安全模式，不许回绕）
/// 2 启动时那条决定自洽：模式 == `mode_for(读到的数)`；而"读不到"那次必须落在安全模式
/// 3 模式对外可见：`sys_abi_info()` 的 `F_SAFE_MODE` 位与内核内部状态一致（不一致就是装饰位）
/// 4 后果：安全模式下 AHCI 只起到第一块有盘的口；还原成正常模式后口数必须回到全数
fn t_boot_guard() -> bool {
    use boot_guard as bg;
    let pure = bg::mode_for(0) == bg::BootMode::Normal
        && bg::mode_for(bg::MAX_FAILED_BOOTS - 1) == bg::BootMode::Normal
        && bg::mode_for(bg::MAX_FAILED_BOOTS) == bg::BootMode::Safe
        && bg::mode_for(u32::MAX) == bg::BootMode::Safe;
    let decided_ok = bg::decided()
        && bg::mode() == bg::mode_for(bg::failed_seen())
        && (!bg::read_failed() || bg::mode() == bg::BootMode::Safe);
    let abi_agrees = (user::abi_word() & user::F_SAFE_MODE != 0) == (bg::mode() == bg::BootMode::Safe);

    let ports_all = ahci::info().map(|i| usize::from(i.ports)).unwrap_or(0);
    // 基线要在**已知的模式**下量：启动时的模式可能是安全模式（那正是第 3、4 格的现场），
    // 拿它当"正常模式的口数"会把两条判据混成一个数
    let pre = bg::mode();
    let _ = bg::force_for_test(bg::BootMode::Normal);
    let normal = ahci::enumerate();
    let _ = bg::force_for_test(bg::BootMode::Safe);
    let safe = ahci::enumerate();
    let _ = bg::force_for_test(pre);
    let after_restore = ahci::enumerate();
    let (n_normal, d_normal) = normal.as_ref().map(|e| (e.n, e.n_disks)).unwrap_or((0, 0));
    let (n_safe, d_safe) = safe.as_ref().map(|e| (e.n, e.n_disks)).unwrap_or((0, 0));
    let consequence = normal.is_ok()
        && safe.is_ok()
        && n_normal == ports_all
        && d_normal >= 1
        && n_safe == 1
        && d_safe >= 1;
    // 还原格比的是"回到进入时那个模式之后，口数是否等于**那个模式**的应有值"。
    // 上一版拿正常模式的基线去比安全模式下的还原现场 ⇒ 一次偶发的"状态区读不到"
    // 会把这台机器永久锁在安全模式里：那遍启动因此永远不健康、计数永远清不掉（BACKLOG ㊿）。
    let expect_after = if pre == bg::BootMode::Normal { n_normal } else { n_safe };
    let restored = bg::mode() == pre && after_restore.map(|e| e.n) == Ok(expect_after);

    crate::log_info!(
        "guard: 模式={:?} 读到的计数={} 读不到={} ABI位={} | 正常模式口={}/{} 盘={} 安全模式口={} 盘={} 还原={}/{} 期望口={}",
        bg::mode(),
        bg::failed_seen(),
        bg::read_failed(),
        user::abi_word() & user::F_SAFE_MODE != 0,
        n_normal,
        ports_all,
        d_normal,
        n_safe,
        d_safe,
        restored,
        after_restore.map(|e| e.n).unwrap_or(0),
        expect_after
    );
    let ok = pure && decided_ok && abi_agrees && consequence && restored;
    if !ok {
        crate::log_fatal!(
            "guard: 判据不成立 纯函数={} 决定自洽={} 可见={} 后果={} 还原={}",
            pure,
            decided_ok,
            abi_agrees,
            consequence,
            restored
        );
    }
    ok
}
ktest!(KT_BOOT_GUARD, t_boot_guard);

/// M6-d/M6-f：§9.7 的崩溃记录走 V2（变长载荷 + 有界栈走 + 最近日志）。判据十五格，逐条只挡一类错法：
/// 1 全字段往返：向量/错误码/CPU/RIP/RSP/RBP/CR2/帧数 写下去按同一种类读回来
/// 2 `rbp` 用不了（这里是 0）⇒ 帧数停在 1，而且不许 panic：走不下去就停，不是编一条链
/// 3 合成一条三层帧链 ⇒ 帧数 = 4、第一帧就是出事那条指令、后面三帧是我给的返回地址
/// 4 第二条记录 `seq` 比第一条大 2（**一条崩溃落盘 = 摘要 + 日志尾两条记录**）且换槽；
///    `read_crash` 取的是**该种类**最新那条
/// 5 配对：日志尾的 `crash_seq` 必须指回它配的那条摘要，自己的 `seq` 比它大 1
/// 6 区里只有崩溃记录时启动记录必须"读不到"；反过来 V1 的启动记录在新解码器下**照读**
///    （§10.2 只增不改在这一格的字面含义：认 version 1 也认 version 2）
/// 7 翻掉**最后一帧**的一个字节（不重算校验和）⇒ 该槽作废、退回上一条完整记录：
///    这一格证明校验和真的覆盖到尾部，而不是只管头部那几十字节
/// 8 声明帧数与长度不自洽（**校验和是对的**）⇒ 必须拒，并且同样退回上一条：
///    只看头部就选最新的话，一条自相矛盾的记录会把整个种类锁死
/// 9 `size` 指到区外（> 480）⇒ 必须在界检查上被拒，不许拿它去切片
/// 10 设备拒执行这条命令（注入非法命令码 ⇒ 以 `ERR` 干净完成）⇒ `dump` 只许返回 `Err`，
///    停机路径上不许二次故障。不选"端口死了"那格注入：它只拦 `start_port`，而这里端口
///    早就起好了、命令照样跑，那样注入会变成假通过
/// 11 第 10 格之后驱动还能用（撤掉注入之后读得回记录）
/// 12 环形取尾：刚打的三行按顺序在段尾、段末必须是换行、行数要等于换行符的真实个数；
///    再给一个比"最新一行"还短的小缓冲 ⇒ 一行都不许给（不许从半行中间开始）
/// 13 声明行数与换行符数不符（**校验和是对的**）⇒ 必须拒，且拒因要点名"行数与换行符数不符"
/// 14 文本超过一槽上界 ⇒ 编码侧截断出来的那半行必须被"末行不完整"拒，不许安静存下缺尾的一行
/// 15 收尾把盘放回用例开始时的样子（三种记录都放回去）：假记录不许留在盘上冒充真崩溃
fn t_crash() -> bool {
    use state_store as ss;
    if ahci::init().is_err() {
        crate::log_fatal!("crash: AHCI 没认领上，落盘判据没法做");
        return false;
    }
    let port = match ahci::boot_port() {
        Ok(p) => p,
        Err(e) => {
            crate::log_fatal!("crash: 找不到引导盘 {:?}", e);
            return false;
        }
    };
    let saved_boot = ss::read(ss::KIND_BOOT).ok();
    let saved_crash = ss::read_crash().ok();
    let saved_log = ss::read_log().ok();
    ss::wipe().ok();
    crash::reset_for_test();

    // ①② 现场给一个用不了的 rbp：帧链必须停在"只有出事那条指令"，不许猜、不许故障
    let s1 = crash::Site { vector: 13, error_code: 0x08, cr2: 0xdead_0000, rip: 0xffff_8000_1234_0000, rsp: 0xffff_8000_5678_0000, rbp: 0 };
    let d1 = crash::dump_site(s1, 1);
    let (slot1, seq1) = match d1 {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("crash: 第一条记录没写进去 {:?}", e);
            return false;
        }
    };
    let r1 = ss::read_crash();
    let fields_back = matches!(r1, Ok((s, q, ref rec)) if s == slot1 && q == seq1
        && rec.vector == 13 && rec.error_code == 0x08 && rec.cpu == 1
        && rec.rip == 0xffff_8000_1234_0000 && rec.rsp == 0xffff_8000_5678_0000
        && rec.cr2 == 0xdead_0000 && rec.fault_level == 4);
    let single_frame = matches!(r1, Ok((_, _, ref rec)) if rec.frame_count == 1 && rec.frames[0] == 0xffff_8000_1234_0000);
    crash::report_previous();

    // ③ 合成三层帧链（帧指针在低地址一侧，"返回地址"指到**真的代码**里）
    //   这一格原来是把返回地址指到本函数的一个局部变量上的，旧的"8 字节对齐"门禁照收 ——
    //   换成"可执行"之后它当场变红：数据不能冒充返回地址。改指 `t_crash` 自己的代码地址。
    let entry: fn() -> bool = t_crash;
    let code_va = entry as *const () as u64;
    let mut chain = [[0u64; 2]; 3];
    let chain_base = &chain as *const [u64; 2] as u64;
    for i in 0..3 {
        chain[i][1] = code_va;
        chain[i][0] = if i + 1 < 3 { chain_base + 16 * (i as u64 + 1) } else { 0 };
    }
    let s2 = crash::Site { vector: 14, error_code: 0, cr2: 0x1000, rip: 0xffff_8000_2222_0000, rsp: 0xffff_8000_4444_0000, rbp: chain_base };
    let d2 = crash::dump_site(s2, 2);
    let (slot2, seq2) = match d2 {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("crash: 第二条记录没写进去 {:?}", e);
            return false;
        }
    };
    let r2 = ss::read_crash();
    let walked = matches!(r2, Ok((_, _, ref rec)) if rec.frame_count == 4
        && rec.frames[0] == 0xffff_8000_2222_0000
        && rec.frames[1] == code_va && rec.frames[2] == code_va && rec.frames[3] == code_va);
    // ④ 轮转与"取该种类最新"。`seq` 一步不是 +1 而是 +2：**一条崩溃落盘是两条记录**
    //   （摘要 + 日志尾），而日志尾共用同一块区、同一个游标（M6-b① 立的规矩）。
    //   所以这一格同时钉两件事：日志尾确实占了 seq，以及两个种类的"谁最新"仍然有定义。
    let stepped = seq2 == seq1 + 2 && slot2 != slot1;
    // ⑤ 配对：日志尾必须指回它配的那条崩溃摘要（`crash_seq`），并且自己的 seq 比它大 1
    let tail_pair = matches!(ss::read_log(), Ok((_, lseq, lrec))
        if lseq == seq2 + 1 && lrec.crash_seq == seq2 && lrec.lines > 0 && lrec.bytes > 0);
    let newest_wins = matches!(r2, Ok((s, q, ref rec)) if s == slot2 && q == seq2 && rec.vector == 14);
    // ⑥ 只有崩溃记录时启动记录读不到；而 V1 的启动记录写下去在新解码器里照读
    let boot_absent = matches!(ss::read(ss::KIND_BOOT), Err(ss::StoreError::NoValidSlot));
    let st_v1 = ss::BootState { failed_boots: 7, good_slot: 1, bad_slot: 2, last_vector: 13, last_cpu: 1, last_rip: 9 };
    let w_v1 = ss::write(ss::KIND_BOOT, &st_v1);
    let v1_still_readable = matches!(&w_v1, Ok((s, q)) if ss::read(ss::KIND_BOOT).map(|(s2, q2, st)| s2 == *s && q2 == *q && st == st_v1).unwrap_or(false));

    // ⑦ 尾帧撕裂（不重算校验和）⇒ 这一槽作废，退回上一条完整记录（⑥ 写的那条 V1 启动记录不算）
    let rec2 = match &r2 { Ok((_, _, rec)) => *rec, Err(_) => ss::CrashRecord::default() };
    let mut torn = ss::encode_crash(seq2, &rec2);
    let last = ss::HDR_OFF + ss::CRASH_FIXED_OFF + 8 * (rec2.frame_count as usize - 1);
    torn[last] ^= 0xFF;
    let wrote_torn = ahci::write_bytes(port, ss::slot_lba(slot2), &torn).is_ok();
    let fell_back = matches!(ss::read_crash(), Ok((s, q, ref rec)) if s == slot1 && q == seq1 && rec.vector == 13);

    // ⑧ 声明帧数与长度不自洽，但**校验和是对的** ⇒ 仍然必须拒，并且退回上一条
    let mut bogus = ss::encode_crash(seq2 + 1, &rec2);
    bogus[ss::HDR_OFF + 28] = 32;
    ss::reseal(&mut bogus);
    let wrote_bogus = ahci::write_bytes(port, ss::slot_lba(slot2), &bogus).is_ok();
    let bogus_rejected = matches!(ss::read_crash(), Ok((s, _, _)) if s == slot1);

    // ⑨ `size` 指到区外 ⇒ 界检查先挡住（不许拿它去切片）
    let mut huge = ss::encode_crash(seq2 + 2, &rec2);
    huge[0..4].copy_from_slice(&4000u32.to_le_bytes());
    ss::reseal(&mut huge);
    let wrote_huge = ahci::write_bytes(port, ss::slot_lba(slot2), &huge).is_ok();
    let huge_rejected = matches!(ss::read_crash(), Ok((s, _, _)) if s == slot1);

    // ⑩⑪ 停机路径上的失败形状：只降级、不二次故障；撤掉注入后驱动照常
    ahci::set_op_override(0xFF);
    let degraded = crash::dump(15, 0, 0);
    ahci::set_op_override(0);
    let degrade_ok = degraded.is_err();
    let alive_after = ss::read_crash().is_ok();

    // ⑫ 环形取尾的整行规则（§9.7 的"最近日志"）：刚打的三行要按顺序出现在段尾，段末字节必须是
    //   换行；再给一个比"最新一行"还短的小缓冲 ⇒ 必须**一行都不给**，而不是从半行中间开始。
    //   "小缓冲 = 0 行"是机制结论而不是实测巧合：本用例自己打的每一行都超过 24 字节。
    crate::log_info!("m6f 尾行 A 0123456789abcdef0123456789abcdef");
    crate::log_info!("m6f 尾行 B 0123456789abcdef0123456789abcdef");
    crate::log_info!("m6f 尾行 C 0123456789abcdef0123456789abcdef");
    let mut big = [0u8; ss::LOG_TEXT_MAX];
    let t_big = serial::recent_tail(&mut big);
    let big_text = &big[..t_big.bytes as usize];
    let marks = ["m6f 尾行 A", "m6f 尾行 B", "m6f 尾行 C"]
        .iter()
        .try_fold(0usize, |pos, m| {
            core::str::from_utf8(big_text).ok().and_then(|s| s[pos..].find(*m).map(|p| pos + p))
        });
    let tail_whole = !big_text.is_empty()
        && big_text[big_text.len() - 1] == b'\n'
        && marks.is_some()
        && t_big.lines as usize == big_text.iter().filter(|b| **b == b'\n').count();
    let mut small = [0u8; 24];
    let t_small = serial::recent_tail(&mut small);
    let no_room_no_line = t_small.lines == 0 && t_small.bytes == 0;
    // ⑬ 声明行数与换行符数不符（**校验和是对的**）⇒ 必须拒，而且拒因必须是那一格
    let mut wrong_lines = ss::encode_log(seq2 + 3, seq2, 9, b"x\ny\n");
    ss::reseal(&mut wrong_lines);
    let lines_rejected = matches!(
        ss::decode_log(0, &wrong_lines),
        Err(ss::StoreError::Torn { why: "行数与换行符数不符", .. })
    );
    // ⑭ 文本给得超过一槽装得下的上界 ⇒ 编码侧截断，而截断造出的半行必须在解码侧被"末行不完整"拒掉，
    //    不许安静存下"缺了尾巴的那一行"（那等于伪造一段没说过的话）
    let mut long = [b'a'; ss::LOG_TEXT_MAX + 6];
    long[long.len() - 1] = b'\n';
    let truncated = ss::encode_log(seq2 + 4, seq2, 1, &long);
    let tail_rejected = matches!(
        ss::decode_log(0, &truncated),
        Err(ss::StoreError::Torn { why: "末行不完整", .. })
    );

    // ⑮ 收尾：抹掉假记录，把启动时那三条原样放回（崩溃后放 ⇒ 它的 seq 更大，链保持原样）
    ss::wipe().ok();
    crash::reset_for_test();
    let mut restored = v1_still_readable && wrote_torn && wrote_bogus && wrote_huge;
    if let Some((_, _, st)) = saved_boot {
        restored &= ss::write(ss::KIND_BOOT, &st).is_ok();
    }
    if let Some((_, _, rec)) = saved_crash {
        restored &= ss::write_crash(&rec).is_ok();
    }
    if let Some((_, _, rec)) = saved_log {
        restored &= ss::write_log(rec.crash_seq, rec.lines, &rec.text[..rec.bytes as usize]).is_ok();
    }

    crate::log_info!(
        "crash: 判据 引导口={} 全字段往返={} 断链只一帧={} 走三层={} 轮转(seq{}→{} 槽{}→{})={} 配对={} 取最新={} 种类隔离={}/{} 尾帧撕裂退回={} 帧数不自洽退回={} 长度越界退回={} 只降级={} 之后还能读={} 尾行整段={} 装不下就不给={} 行数不符拒={} 截断拒={} 现场还原={}",
        port,
        fields_back,
        single_frame,
        walked,
        seq1,
        seq2,
        slot1,
        slot2,
        stepped,
        tail_pair,
        newest_wins,
        boot_absent,
        v1_still_readable,
        fell_back,
        bogus_rejected,
        huge_rejected,
        degrade_ok,
        alive_after,
        tail_whole,
        no_room_no_line,
        lines_rejected,
        tail_rejected,
        restored
    );
    let ok = fields_back && single_frame && walked && stepped && tail_pair && newest_wins && boot_absent
        && v1_still_readable && fell_back && bogus_rejected && huge_rejected && degrade_ok
        && alive_after && tail_whole && no_room_no_line && lines_rejected && tail_rejected
        && restored;
    if !ok {
        crate::log_fatal!("crash: 崩溃记录判据不成立（上面一行是全部读数）");
    }
    ok
}
ktest!(KT_CRASH, t_crash);

/// M6-d：§9.7 的现场必须由 **CPU 给的数** 填出来。这条只在 `fault-crash-oops` 构建里存在：
/// 核心态读一个未映射地址 ⇒ #PF(14) 没有恢复项 ⇒ `Action::Fatal` ⇒ 停机前落一条 V2 记录。
/// 判据形状不是"崩了就算过"（那 39 已经是判定级的事了），而是：**没故障就是失败**——
/// 读得回来就说明这条构建根本没走到异常里，那它的记录里那些字段全是编的。
#[cfg(feature = "fault-crash-oops")]
fn t_crash_oops() -> bool {
    const BAD: u64 = 0xffff_c000_0000_0008;   // 规范化内核地址、8 字节对齐、保证没映射
    crate::log_info!("oops: 故意读 {:#x}，期待 #PF(14) 升 L4（cr2 应该等于这个数）", BAD);
    // SAFETY: 这是**故意**的一次非法核心态访问，用来制造真异常现场；它之前的日志已经打完，
    //        之后再没有需要保全的状态。判据是"这一行不许返回"，读回来的值只用于打印。
    let v = unsafe { (BAD as *const u64).read_volatile() };
    crate::log_fatal!("oops: 没有发生故障，读到 {:#x} ⇒ 这条构建没在量它声称的东西", v);
    false
}
#[cfg(feature = "fault-crash-oops")]
ktest!(KT_CRASH_OOPS, t_crash_oops);

/// M6-c①：§9.6 的软锁死。七格，每格只挡一类错法：
/// 1 健康窗口里所有在线核的心跳都在前进 ⇒ 位图为 0（这条先证明"不报"不是常量）
/// 2 头两个窗口必须静默：阈值 3 个窗口不是装饰（去掉阈值这条当场红）
/// 3 报警落在第 3 或第 4 个窗口 —— 不是"恰好第 3 个"：`timer_stop()` 之后还会有一个**在途
///    tick** 落进计数（实测两种都出现过），写成等式就变成一条自己会飘红的判据
/// 4 报的必须是停掉那一个核，别的核不许连坐（AP 用本地 LAPIC、BSP 用 PIT，两条来源）
/// 5 报警计数按窗口/按核各计（两个数不能混成一个），且处置次数恒为 0
/// 6 恢复心跳后**能消警**：下一窗口位图回 0（把 BSP 接到错的来源上，这条永远消不掉）
/// 7 用例自己停表，所以进来时先量"心跳原本在不在前进"，收尾按进来时的状态放回
/// 用例每格之间用 TSC 等 30 ms 真实时间（比 10 ms 的定时周期宽三倍）。
fn t_watchdog() -> bool {
    use watchdog as wd;
    let saved = wd::stats();
    let bsp = cpu::BSP_SLOT;
    // 每格之间的真实时间：30 ms 比 10 ms 的定时周期宽三倍，健康核一定前进，停掉的核一定不前进
    let settle = || {
        let budget = clock::hz().map_or(120_000_000, |hz| hz * 30 / 1000);
        let t0 = tsc::now();
        apic::with_interrupts(|| {
            while tsc::now().wrapping_sub(t0) < budget {
                tsc::spin(20_000);
            }
        });
    };
    // 进来时 BSP 的心跳未必在前进：`.ktests` 顺序由链接器决定，而有用例（`t_copy_user`）
    // 收尾会把表停掉。先量这个事实，再决定要不要为用例建立"健康窗口"这个前提，
    // 最后按进来时的状态放回 —— 不然本用例会把下一格的时钟弄活或弄死。
    let t_in = apic::ticks();
    settle();
    let running_on_entry = apic::ticks() != t_in;
    if !running_on_entry {
        apic::timer_start().ok();
    }

    settle();
    let healthy = wd::sample();
    // 停表之前把 streak 与基线清零：报警要出现在"从我这次注入起的第 STALL_LIMIT 个窗口"，
    // 而不是前面那些无关窗口的尾巴上（第一版就是这么红的：`限内不报=false(0x0/0x1)`）。
    wd::reset_for_test(false);
    apic::timer_stop().ok();
    let mut seq = [0u32; 4];
    for item in seq.iter_mut().take(4) {
        settle();
        *item = wd::sample();
    }
    apic::timer_start().ok();
    // 阈值那条线断的是"第几个窗口才报"，不是"第几次采样必须报"：`timer_stop()` 之后还有
    // 一个**在途 tick** 会落进计数（实测两种都有 —— 有时报在第 3 个窗口、有时第 4 个），
    // 把等式写成"恰好第 3 个"就变成一条会自己飘红的判据。
    let first_alarm = seq.iter().position(|m| *m != 0).map_or(0, |i| i + 1);
    let below_limit = seq[0] == 0 && seq[1] == 0;
    let alarmed = first_alarm == wd::STALL_LIMIT as usize || first_alarm == wd::STALL_LIMIT as usize + 1;
    let alarm = seq.iter().find(|m| **m != 0).copied().unwrap_or(0);
    let right_cpu = alarm == (1u32 << bsp);
    let no_collateral = seq.iter().all(|m| *m == 0 || *m == (1u32 << bsp));
    settle();
    let cleared = wd::sample() == 0;
    if !running_on_entry {
        apic::timer_stop().ok();
    }
    let (samples, windows, events, last_mask, actions) = wd::stats();
    let counters = windows >= 1 && events >= 1 && last_mask == 0 && actions == 0;
    crate::log_info!(
        "watchdog: 判据 进表时心跳前进={} 健康窗口不报={} 前两窗静默={} 第几窗报={}(限={}) 报的是本核={} 没连坐={} 计数(窗口={} 核次={} 采样={}) 消警={} 处置={} AP槽心跳={}",
        running_on_entry,
        healthy == 0,
        below_limit,
        first_alarm,
        wd::STALL_LIMIT,
        right_cpu,
        no_collateral,
        windows,
        events,
        samples,
        cleared,
        actions,
        apic::cpu_ticks(bsp + 1) > 0
    );
    wd::restore(saved);
    let ok = healthy == 0 && below_limit && alarmed && right_cpu && no_collateral && cleared && counters && actions == 0;
    if !ok {
        crate::log_fatal!(
            "watchdog: 判据不成立 健康={} 前两窗静默={} 第几窗报={}/限={} 报的是本核={} 没连坐={} 消警={} 计数={}",
            healthy == 0,
            below_limit,
            first_alarm,
            wd::STALL_LIMIT,
            right_cpu,
            no_collateral,
            cleared,
            counters
        );
    }
    ok
}
ktest!(KT_WATCHDOG, t_watchdog);







/// 故障注入（§7.1 R16）：同一上下文重复获取堆锁，必须被 `held_by` 认出并升 L4。
/// 走到注入函数内部之后就不会返回（重入被抓就是 39）；真的返回了说明检测器是假的。
#[cfg(feature = "fault-lock-reentrant")]
fn t_lock_reentry_must_escalate() -> bool {
    crate::log_warn!("fault-lock-reentrant: 按设计重复获取堆锁");
    heap::force_reentrant_lock_for_test();
    false
}
#[cfg(feature = "fault-lock-reentrant")]
ktest!(KT_LOCK_REENTRY, t_lock_reentry_must_escalate);

/// 资源台账（§6.7“按模块汇总存活分配”）的三条不变量 + 一台交叉仪器：
/// 1. `Σ live == Σ alloc − Σ free`（台账自洽）
/// 2. 测试模块结束时必须清零——用例自己不许漏内存
/// 3. 堆的台账帧数 == 堆自己报的映射页数（两个独立计数指同一批页框，缺一不可对不上）
/// 4. 没有模块号落在表外（`unknown_module_hits`），否则报告会长得好看但漏计
fn t_resource_ledger_balanced() -> bool {
    let tt = resource::totals();
    let balanced = tt.sum_live == tt.sum_alloc.saturating_sub(tt.sum_free);
    let test_live = resource::live_of(mm::MOD_TEST);
    let heap_live = resource::live_of(heap::MOD_HEAP_CORE);
    let heap_mapped = heap::stats().window_mapped / mm::PAGE;
    let mut i = 0usize;
    while let Some(e) = resource::entry(i) {
        crate::log_info!("ledger: module {} live={} frames alloc={} calls={}", e.module, e.live_frames, e.alloc_frames, e.alloc_calls);
        i += 1;
    }
    crate::log_info!(
        "ledger totals: live={} alloc={} free={} unknown_hits={} violation={} heap_live={} vs mapped={}",
        tt.sum_live, tt.sum_alloc, tt.sum_free, tt.unknown_module_hits, tt.violation, heap_live, heap_mapped
    );
    balanced && test_live == 0 && heap_live == heap_mapped && tt.unknown_module_hits == 0 && !tt.violation
}
ktest!(KT_LEDGER, t_resource_ledger_balanced);

/// 重复释放必须升 L4（退出码 39）。只在注入构建里存在，与 negative-probe 同构。
#[cfg(feature = "fault-double-free")]
fn t_double_free_must_escalate() -> bool {
    crate::log_warn!("fault-double-free: 这条用例按设计触发一次重复释放");
    mm::force_double_free_for_test()
}
#[cfg(feature = "fault-double-free")]
ktest!(KT_DOUBLE_FREE, t_double_free_must_escalate);

/// 负样本（§12.3 R19）：只在 `--features negative-probe` 构建里存在，且必然失败。
/// 它的作用是证明判定链会把失败真的报成失败（退出码 35），而不是“绿而无效”。
#[cfg(feature = "negative-probe")]
fn t_negative_probe_must_fail() -> bool {
    crate::log_warn!("negative-probe: 这条用例按设计返回 false");
    false
}
#[cfg(feature = "negative-probe")]
ktest!(KT_NEG, t_negative_probe_must_fail);
