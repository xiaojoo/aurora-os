use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use aurora_capture::{
    CaptureBootInfo, CaptureCpu, CaptureRegion, CAPTURE_DMA_BYTES, CAPTURE_DMA_OFFSET,
    CAPTURE_ENTRY_MAGIC, CAPTURE_MAGIC, CAPTURE_MAX_CPUS, CAPTURE_MAX_REGIONS,
    CAPTURE_PHYS_BYTES, CAPTURE_VA_BASE, CAPTURE_VERSION, checksum,
    CPU_CR2, CPU_CR3, CPU_CR4, CPU_CS, CPU_ERR, CPU_RAX, CPU_RBP, CPU_RBX,
    CPU_RCX, CPU_RDI, CPU_RDX, CPU_RFLAGS, CPU_RIP, CPU_RSI, CPU_RSP, CPU_R8,
    CPU_R9, CPU_R10, CPU_R11, CPU_R12, CPU_R13, CPU_R14, CPU_R15,
    CPU_SOURCE, CPU_SS, CPU_TSC, CPU_VALID, CPU_VECTOR,
};

use crate::arch::x86_64::{cpu, trap};
use crate::diag::{crash, serial};

const CAPTURE_STACK_BYTES: usize = 16 * 1024;
const PARK_DEADLINE_CYCLES: u64 = 100_000_000;
const CAPTURE_LBA: u64 = 0;
const CAPTURE_SECTORS: u32 = 2 * 1024 * 1024 / 512;
const _: () = assert!(CAPTURE_MAX_CPUS == cpu::MAX_CPUS);

#[repr(C, align(64))]
struct SnapshotCell(UnsafeCell<[CaptureCpu; CAPTURE_MAX_CPUS]>);
// SAFETY: 每 CPU 只写自己的快照，leader 只在 AP 停车后读取；发布顺序由原子 PARKED/ENTERED 保证。
unsafe impl Sync for SnapshotCell {}

static SNAPSHOTS: SnapshotCell = SnapshotCell(UnsafeCell::new([CaptureCpu::empty(); CAPTURE_MAX_CPUS]));
static ENTERED: [AtomicBool; CAPTURE_MAX_CPUS] = [const { AtomicBool::new(false) }; CAPTURE_MAX_CPUS];
static PARKED: [AtomicBool; CAPTURE_MAX_CPUS] = [const { AtomicBool::new(false) }; CAPTURE_MAX_CPUS];
static LEADER: AtomicUsize = AtomicUsize::new(usize::MAX);
static PARK_FAILURES: AtomicU32 = AtomicU32::new(0);
static IO_READY: AtomicBool = AtomicBool::new(false);

#[repr(C, align(64))]
struct CaptureStack {
    bytes: UnsafeCell<[u8; CAPTURE_STACK_BYTES]>,
}
// SAFETY: capture 栈只由对应 CPU 在进入捕获上下文后使用，生命周期为整个内核。
unsafe impl Sync for CaptureStack {}

static STACKS: [CaptureStack; CAPTURE_MAX_CPUS] = [const {
    CaptureStack { bytes: UnsafeCell::new([0; CAPTURE_STACK_BYTES]) }
}; CAPTURE_MAX_CPUS];

#[repr(C, align(64))]
struct RegionCell(UnsafeCell<[CaptureRegion; CAPTURE_MAX_REGIONS]>);
// SAFETY: init 在启动期单核写入，捕获路径只读。
unsafe impl Sync for RegionCell {}
static REGIONS: RegionCell = RegionCell(UnsafeCell::new(
    [CaptureRegion { base: 0, length: 0, kind: 0 }; CAPTURE_MAX_REGIONS],
));

struct BootInfoCell(UnsafeCell<CaptureBootInfo>);
// SAFETY: init 在启动期单核写入，leader 在停 AP 后更新并读取。
unsafe impl Sync for BootInfoCell {}
static BOOT_INFO: BootInfoCell = BootInfoCell(UnsafeCell::new(CaptureBootInfo {
    magic: 0,
    version: 0,
    size: 0,
    checksum: 0,
    hhdm_offset: 0,
    main_image_phys: 0,
    main_image_bytes: 0,
    capture_phys: 0,
    capture_bytes: 0,
    capture_payload_bytes: 0,
    capture_payload_checksum: 0,
    snapshots_phys: 0,
    snapshots_len: 0,
    regions_phys: 0,
    regions_len: 0,
    ahci_mmio_phys: 0,
    ahci_port: 0,
    ahci_dma_phys: 0,
    ahci_dma_bytes: 0,
    serial_port: 0x3f8,
    online_cpus: 0,
    parked_cpus: 0,
    capture_lba: 0,
    capture_sectors: 0,
}));

core::arch::global_asm!(
    r#"
    .global capture_switch
capture_switch:
    mov rsp, rcx
    and rsp, -16
    call aurora_capture_main
1:
    cli
    hlt
    jmp 1b
"#
);

extern "C" {
    fn capture_switch(
        site: *const crash::Site,
        frame: *const trap::TrapFrame,
        cpu: usize,
        stack_top: u64,
        old_rsp: u64,
        old_rbp: u64,
    ) -> !;
    fn capture_jump(entry: u64, boot: *const CaptureBootInfo) -> !;
}

core::arch::global_asm!(
    r#"
    .global capture_jump
capture_jump:
    mov rax, rdi
    mov rdi, rsi
    jmp rax
"#
);

fn static_phys(va: u64) -> Result<u64, crate::mm::MmError> {
    crate::mm::phys_of(va)
        .map(|page| page + (va & 0xfff))
        .ok_or(crate::mm::MmError::InvalidAddress)
}

pub fn init() -> Result<(), crate::mm::MmError> {
    let image_end = crate::mm::image_phys_end().ok_or(crate::mm::MmError::NotInit)?;
    let frames = crate::mm::phys_alloc_above(11, crate::mm::MOD_BOOT, image_end)?;
    let phys = frames.base().0;
    core::mem::forget(frames);
    crate::mm::map_capture(CAPTURE_VA_BASE, phys, CAPTURE_PHYS_BYTES / crate::mm::PAGE)?;

    let hhdm = crate::mm::hhdm();
    let dst = (hhdm + phys) as *mut u8;
    // SAFETY: phys 是刚预留的 8 MiB 连续区，HHDM 覆盖它；dst 对齐到页且长度正好 CAPTURE_PHYS_BYTES。
    unsafe { core::ptr::write_bytes(dst, 0, CAPTURE_PHYS_BYTES) };
    let payload = include_bytes!("../fixtures/capture.bin");
    if payload.len() < 18 || &payload[2..10] != CAPTURE_ENTRY_MAGIC || payload.len() > CAPTURE_DMA_OFFSET {
        return Err(crate::mm::MmError::Unsupported);
    }
    // SAFETY: payload 长度已限制在 capture 区前端，源为静态只读字节，目标区已清零。
    unsafe { core::ptr::copy_nonoverlapping(payload.as_ptr(), dst, payload.len()) };
    #[cfg(feature = "kdump-bad-payload")]
    // SAFETY: dst 是已清零 capture 区起点，+10 仍在已校验 payload 头内；仅测试档翻转保留字节。
    unsafe { core::ptr::write_volatile(dst.add(10), core::ptr::read_volatile(dst.add(10)) ^ 1) };
    let payload_checksum = checksum(payload);

    let mut region_count = 0usize;
    // SAFETY: REGIONS/BOOT_INFO 是 static，init 在启动期单核调用，之后只读。
    unsafe {
        let regions = &mut *REGIONS.0.get();
        for i in 0..crate::mm::region_count() {
            if region_count == CAPTURE_MAX_REGIONS {
                break;
            }
            let r = crate::mm::region(i).ok_or(crate::mm::MmError::InvalidAddress)?;
            if r.length == 0 {
                continue;
            }
            regions[region_count] = CaptureRegion { base: r.base, length: r.length, kind: r.kind as u64 };
            region_count += 1;
        }
        if region_count == 0 {
            return Err(crate::mm::MmError::InvalidAddress);
        }
        let boot = &mut *BOOT_INFO.0.get();
        *boot = CaptureBootInfo {
            magic: CAPTURE_MAGIC,
            version: CAPTURE_VERSION,
            size: core::mem::size_of::<CaptureBootInfo>() as u32,
            checksum: 0,
            hhdm_offset: hhdm,
            main_image_phys: crate::mm::image_phys_base().ok_or(crate::mm::MmError::InvalidAddress)?,
            main_image_bytes: crate::mm::image_phys_end().ok_or(crate::mm::MmError::InvalidAddress)?.saturating_sub(crate::mm::image_phys_base().ok_or(crate::mm::MmError::InvalidAddress)?),
            capture_phys: phys,
            capture_bytes: CAPTURE_PHYS_BYTES as u64,
            capture_payload_bytes: payload.len() as u32,
            capture_payload_checksum: payload_checksum,
            snapshots_phys: static_phys(core::ptr::addr_of!(SNAPSHOTS) as u64)?,
            snapshots_len: core::mem::size_of_val(&SNAPSHOTS) as u32,
            regions_phys: static_phys(core::ptr::addr_of!(REGIONS) as u64)?,
            regions_len: region_count as u32,
            ahci_mmio_phys: 0,
            ahci_port: 0,
            ahci_dma_phys: phys + CAPTURE_DMA_OFFSET as u64,
            ahci_dma_bytes: CAPTURE_DMA_BYTES as u32,
            serial_port: 0x3f8,
            online_cpus: cpu::registered() as u32,
            parked_cpus: 0,
            capture_lba: CAPTURE_LBA,
            capture_sectors: CAPTURE_SECTORS,
        };
    }
    crate::log_info!("kdump: capture reserved phys={:#x} bytes={} payload={}", phys, CAPTURE_PHYS_BYTES, payload.len());
    Ok(())
}

pub fn init_io() -> Result<(), crate::driver::ahci::AhciError> {
    const CAPTURE_PORT: u8 = 1;
    let (dma_phys, dma_bytes) = unsafe {
        let boot = &*BOOT_INFO.0.get();
        (boot.ahci_dma_phys, boot.ahci_dma_bytes as usize)
    };
    match crate::driver::ahci::prepare_capture(CAPTURE_PORT, dma_phys, dma_bytes) {
        Ok(io) => {
            unsafe {
                let boot = &mut *BOOT_INFO.0.get();
                boot.ahci_mmio_phys = io.abar;
                boot.ahci_port = u32::from(io.port);
                boot.ahci_dma_phys = io.dma_phys;
                boot.ahci_dma_bytes = io.dma_bytes;
                #[cfg(feature = "kdump-bad-dma")]
                {
                    boot.ahci_dma_bytes = aurora_capture::CAPTURE_AHCI_MIN_DMA_BYTES as u32 - 1;
                }
            }
            IO_READY.store(true, Ordering::Release);
            crate::log_info!(
                "kdump: capture AHCI ready abar={:#x} port={} dma={:#x} bytes={}",
                io.abar, io.port, io.dma_phys, io.dma_bytes
            );
            Ok(())
        }
        Err(e) => {
            IO_READY.store(false, Ordering::Release);
            crate::log_warn!("kdump: capture AHCI unavailable on port {}: {:?}", CAPTURE_PORT, e);
            Err(e)
        }
    }
}

pub unsafe extern "C" fn enter_capture(site: *const crash::Site, frame: *const trap::TrapFrame) -> ! {
    // SAFETY: 调用方处于 ring0 致命出口；cli 不访存，随后切到本 CPU 独占的 static capture 栈。
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
    let cpu = cpu::self_slot() % CAPTURE_MAX_CPUS;
    let stack = unsafe { &*core::ptr::addr_of!(STACKS[cpu]) };
    let stack_top = stack.bytes.get().cast::<u8>()
        .wrapping_add(CAPTURE_STACK_BYTES) as u64 & !0xf;
    let old_rsp: u64;
    let old_rbp: u64;
    // SAFETY: 只读当前 RSP/RBP，用于快照；不据此解引用。
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) old_rsp, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {}, rbp", out(reg) old_rbp, options(nomem, nostack, preserves_flags));
        capture_switch(site, frame, cpu, stack_top, old_rsp, old_rbp)
    }
}

#[no_mangle]
pub unsafe extern "C" fn aurora_capture_main(
    site: *const crash::Site,
    frame: *const trap::TrapFrame,
    cpu: usize,
    _stack_top: u64,
    old_rsp: u64,
    old_rbp: u64,
) -> ! {
    ENTERED[cpu].store(true, Ordering::Release);
    let words = unsafe { &mut (*SNAPSHOTS.0.get())[cpu].words };
    words.fill(0);
    words[CPU_VALID] = 1;
    words[CPU_RSP] = old_rsp;
    words[CPU_RBP] = old_rbp;
    words[CPU_CR3] = crate::mm::our_cr3();
    words[CPU_CR4] = cpu::cr4();
    words[CPU_TSC] = crate::time::tsc::now();
    if !site.is_null() {
        // SAFETY: site 由异常入口或软件 L4 入口在旧栈上构造，捕获路径停机前一直有效。
        let site = unsafe { &*site };
        words[CPU_VECTOR] = u64::from(site.vector);
        words[CPU_ERR] = u64::from(site.error_code);
        words[CPU_CR2] = site.cr2;
        words[CPU_RIP] = site.rip;
        words[CPU_RSP] = site.rsp;
        words[CPU_RBP] = site.rbp;
    }
    if !frame.is_null() {
        // SAFETY: frame 是当前异常栈上的真实 TrapFrame，进入捕获路径后不再返回普通 ISR。
        let frame = unsafe { &*frame };
        words[CPU_RAX] = frame.rax;
        words[CPU_RBX] = frame.rbx;
        words[CPU_RCX] = frame.rcx;
        words[CPU_RDX] = frame.rdx;
        words[CPU_RSI] = frame.rsi;
        words[CPU_RDI] = frame.rdi;
        words[CPU_R8] = frame.r8;
        words[CPU_R9] = frame.r9;
        words[CPU_R10] = frame.r10;
        words[CPU_R11] = frame.r11;
        words[CPU_R12] = frame.r12;
        words[CPU_R13] = frame.r13;
        words[CPU_R14] = frame.r14;
        words[CPU_R15] = frame.r15;
        words[CPU_RFLAGS] = frame.rflags;
        words[CPU_CS] = frame.cs;
        words[CPU_SS] = frame.ss;
    }

    let leader = LEADER.compare_exchange(usize::MAX, cpu, Ordering::AcqRel, Ordering::Acquire).is_ok();
    if leader {
        let parked = park_aps(cpu);
        let online = cpu::registered().max(1);
        let boot = unsafe { &mut *BOOT_INFO.0.get() };
        boot.online_cpus = online as u32;
        boot.parked_cpus = parked;
        boot.checksum = boot.canonical_checksum();
        let all_parked = parked as usize == online - 1;
        let io_ready = IO_READY.load(Ordering::Acquire);
        serial::line("kdump", format_args!("capture leader={} parked={}/{} failures={} io={}", cpu, parked, online - 1, PARK_FAILURES.load(Ordering::Relaxed), io_ready));
        if !all_parked || !io_ready {
            serial::out8(0xf4, 0x13);
            loop {
                // SAFETY: AP 未全部停车或 capture 盘未就绪时禁止进入第二内核。
                unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
            }
        }
        let boot_ptr = core::ptr::addr_of!(*boot);
        let entry = {
            #[cfg(feature = "kdump-bad-entry")]
            { CAPTURE_VA_BASE + 1 }
            #[cfg(not(feature = "kdump-bad-entry"))]
            { CAPTURE_VA_BASE }
        };
        if entry != CAPTURE_VA_BASE {
            serial::line("kdump", format_args!("capture entry invalid got={:#x} want={:#x}", entry, CAPTURE_VA_BASE));
            serial::out8(0xf4, 0x13);
            loop {
                core::hint::spin_loop();
            }
        }
        // SAFETY: 所有 AP 已停车，payload/校验/独立 DMA 已就绪；capture_entry 不返回。
        unsafe { capture_jump(entry, boot_ptr) };
    }
    loop {
        // SAFETY: 捕获路径的终点；cli+hlt 不访存，NMI 停车桩仍可进入。
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

fn park_aps(leader: usize) -> u32 {
    let mut targets = 0u32;
    let mut parked = 0u32;
    for slot in 0..cpu::MAX_CPUS {
        if slot == leader || !cpu::is_registered(slot) {
            continue;
        }
        targets += 1;
        if let Some(id) = cpu::lapic_id_of(slot) {
            #[cfg(feature = "kdump-no-park")]
            {
                let _ = id;
                PARK_FAILURES.fetch_add(1, Ordering::Relaxed);
            }
            #[cfg(not(feature = "kdump-no-park"))]
            if crate::arch::x86_64::apic::send_nmi_to(id).is_err() {
                PARK_FAILURES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    let start = crate::time::tsc::now();
    while crate::time::tsc::now().wrapping_sub(start) < PARK_DEADLINE_CYCLES {
        parked = 0;
        for slot in 0..cpu::MAX_CPUS {
            if slot != leader && cpu::is_registered(slot) && PARKED[slot].load(Ordering::Acquire) {
                parked += 1;
            }
        }
        if parked == targets {
            break;
        }
        core::hint::spin_loop();
    }
    parked
}

#[no_mangle]
pub extern "C" fn aurora_capture_nmi(regs: *const [u64; 20]) -> ! {
    let cpu = cpu::self_slot() % CAPTURE_MAX_CPUS;
    let words = unsafe { &mut (*SNAPSHOTS.0.get())[cpu].words };
    // SAFETY: regs 指向 NMI IST2 栈上的 15 个 GPR 与 CPU 压入的 SS/RSP/RFLAGS/CS/RIP。
    let regs = unsafe { &*regs };
    words.fill(0);
    words[CPU_VALID] = 1;
    words[CPU_SOURCE] = 1;
    words[CPU_VECTOR] = 2;
    words[CPU_RAX] = regs[0];
    words[CPU_RBX] = regs[1];
    words[CPU_RCX] = regs[2];
    words[CPU_RDX] = regs[3];
    words[CPU_RSI] = regs[4];
    words[CPU_RDI] = regs[5];
    words[CPU_RBP] = regs[6];
    words[CPU_R8] = regs[7];
    words[CPU_R9] = regs[8];
    words[CPU_R10] = regs[9];
    words[CPU_R11] = regs[10];
    words[CPU_R12] = regs[11];
    words[CPU_R13] = regs[12];
    words[CPU_R14] = regs[13];
    words[CPU_R15] = regs[14];
    words[CPU_SS] = regs[15];
    words[CPU_RSP] = regs[16];
    words[CPU_RFLAGS] = regs[17];
    words[CPU_CS] = regs[18];
    words[CPU_RIP] = regs[19];
    words[CPU_CR3] = crate::mm::our_cr3();
    words[CPU_CR4] = cpu::cr4();
    words[CPU_TSC] = crate::time::tsc::now();
    PARKED[cpu].store(true, Ordering::Release);
    loop {
        // SAFETY: NMI 捕获桩永久停车，不返回普通 ISR。
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}
