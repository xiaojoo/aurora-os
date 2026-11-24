//! Isolated x86-64 capture kernel entered by a kexec-style jump from the main kernel.

#![no_std]
#![no_main]

mod ahci;
mod paging;
mod serial;
mod vmcore;

use aurora_capture::{
    checksum, CaptureBootInfo, CaptureCpu, CaptureRegion, CAPTURE_DMA_OFFSET,
    CAPTURE_ENTRY_MAGIC, CAPTURE_MAGIC, CAPTURE_MAX_CPUS, CAPTURE_MAX_REGIONS,
    CAPTURE_PHYS_BYTES, CAPTURE_VA_BASE, CAPTURE_VERSION,
};

const VMCORE_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_SERIAL_PORT: u16 = 0x3f8;

// The main kernel jumps to CAPTURE_VA_BASE with a live CaptureBootInfo pointer in rdi.
// This entry does not rely on the old stack, GS base, IDT, allocator, or any kernel service.
core::arch::global_asm!(
    r#"
    .section .text.boot,"ax",@progbits
    .global capture_entry
capture_entry:
    jmp capture_entry_body
    .ascii "AURCAP01"
    .quad 0
capture_entry_body:
    cli
    cld
    mov rsp, -0x3f840010
    xor ebp, ebp
    and rsp, -16
    call capture_main
    ud2
"#
);

// The vmcore lives in the capture image's .bss, never on the small entry stack.
static mut VMCORE: [u8; VMCORE_BYTES] = [0; VMCORE_BYTES];

type Error = ahci::Error;

/// Fixed capture entry called by `capture_entry` after installing the reserved stack.
///
/// # Safety
/// The main kernel must pass a live, correctly aligned pointer to a complete initialized
/// `CaptureBootInfo` in `rdi`, with interrupts disabled and all APs parked.
#[no_mangle]
pub unsafe extern "C" fn capture_main(raw: *const CaptureBootInfo) -> ! {
    serial::init(DEFAULT_SERIAL_PORT);
    if raw.is_null() {
        serial::fatal("CaptureBootInfo pointer is null");
    }
    // SAFETY: the kexec ABI requires a live pointer to a complete CaptureBootInfo. It is
    // copied before CR3 changes, so later accesses never dereference the old address space.
    let boot = unsafe { raw.read_volatile() };
    if boot.magic != CAPTURE_MAGIC {
        serial::fatal("CaptureBootInfo magic mismatch");
    }
    if boot.version != CAPTURE_VERSION {
        serial::fatal("CaptureBootInfo version mismatch");
    }
    if boot.size != core::mem::size_of::<CaptureBootInfo>() as u32 {
        serial::fatal("CaptureBootInfo size mismatch");
    }
    let expected_checksum = boot.canonical_checksum();
    if boot.checksum != expected_checksum {
        serial::line("boot", "CaptureBootInfo checksum mismatch");
        serial::value("checksum.got", boot.checksum);
        serial::value("checksum.want", expected_checksum);
        serial::fatal("invalid CaptureBootInfo checksum");
    }
    if boot.serial_port == 0 {
        serial::fatal("CaptureBootInfo serial port is zero");
    }
    serial::init(boot.serial_port);

    let payload_bytes = boot.capture_payload_bytes as usize;
    if !(18..=CAPTURE_DMA_OFFSET).contains(&payload_bytes) {
        serial::fatal("capture payload length is invalid");
    }
    // SAFETY: CAPTURE_VA_BASE is the fixed executable image mapping and the checked length
    // stays inside the 8 MiB reservation, before its DMA area.
    let payload = unsafe {
        core::slice::from_raw_parts(CAPTURE_VA_BASE as *const u8, payload_bytes)
    };
    if &payload[2..10] != CAPTURE_ENTRY_MAGIC {
        serial::fatal("capture payload entry magic mismatch");
    }
    let payload_checksum = checksum(payload);
    if payload_checksum != boot.capture_payload_checksum {
        serial::line("payload", "capture payload checksum mismatch");
        serial::value("checksum.got", payload_checksum);
        serial::value("checksum.want", boot.capture_payload_checksum);
        serial::fatal("invalid capture payload checksum");
    }

    let validated = validate_boot_info(&boot);
    let (snapshots_count, snapshot_capacity) = match validated {
        Ok(counts) => counts,
        Err(error) => fail(error),
    };
    let root = match paging::activate(&boot) {
        Ok(root) => root,
        Err(reason) => fail(Error::new("paging", reason)),
    };
    serial::line("paging", "standalone CR3 active");
    serial::value("pml4", root);

    let mut snapshots = [CaptureCpu::empty(); CAPTURE_MAX_CPUS];
    for (index, slot) in snapshots[..snapshot_capacity].iter_mut().enumerate() {
        match read_physical::<CaptureCpu>(
            boot.hhdm_offset,
            physical_item(
                boot.snapshots_phys,
                index,
                core::mem::size_of::<CaptureCpu>(),
            ),
        ) {
            Ok(value) => *slot = value,
            Err(reason) => fail(Error::new("snapshot", reason)),
        }
    }
    let mut regions = [CaptureRegion {
        base: 0,
        length: 0,
        kind: 0,
    }; CAPTURE_MAX_REGIONS];
    for (index, slot) in regions[..boot.regions_len as usize].iter_mut().enumerate() {
        match read_physical::<CaptureRegion>(
            boot.hhdm_offset,
            physical_item(
                boot.regions_phys,
                index,
                core::mem::size_of::<CaptureRegion>(),
            ),
        ) {
            Ok(value) => *slot = value,
            Err(reason) => fail(Error::new("region", reason)),
        }
    }

    let ahci = match ahci::Ahci::new(&boot, boot.hhdm_offset) {
        Ok(ahci) => ahci,
        Err(error) => fail(error),
    };
    // SAFETY: VMCORE is one static byte array in the mapped capture image. The leader is
    // the only executing CPU, no reference to it exists, and the slice covers exactly
    // VMCORE_BYTES for the complete build/write sequence.
    let buffer = unsafe {
        &mut *core::ptr::slice_from_raw_parts_mut(
            core::ptr::addr_of_mut!(VMCORE).cast::<u8>(),
            VMCORE_BYTES,
        )
    };
    let core_len = match vmcore::build(
        &boot,
        &snapshots[..snapshots_count],
        &regions[..boot.regions_len as usize],
        buffer,
    ) {
        Ok(length) => length,
        Err(reason) => fail(Error::new("vmcore", reason)),
    };
    serial::value("vmcore.bytes", core_len as u64);

    let capacity = ahci.data_capacity();
    let mut written = 0usize;
    while written < core_len {
        let count = capacity.min(core_len - written);
        let lba = match boot.capture_lba.checked_add((written / 512) as u64) {
            Some(lba) => lba,
            None => fail(Error::new("ahci", "capture LBA range overflows")),
        };
        if let Err(error) = ahci.write_chunk(lba, &buffer[written..written + count]) {
            fail(error);
        }
        written += count;
        serial::value("ahci.written", written as u64);
    }
    if written != core_len {
        fail(Error::new(
            "ahci",
            "written byte count differs from vmcore length",
        ));
    }
    serial::line("capture", "vmcore write complete; halted");
    serial::exit(0x13);
}

fn validate_boot_info(boot: &CaptureBootInfo) -> Result<(usize, usize), Error> {
    if boot.main_image_phys == 0 || boot.main_image_bytes == 0 {
        return Err(Error::new("boot", "main kernel image range is empty"));
    }
    boot.main_image_phys
        .checked_add(boot.main_image_bytes)
        .ok_or_else(|| Error::new("boot", "main kernel image range overflows"))?;
    if boot.capture_phys == 0 || boot.capture_bytes != CAPTURE_PHYS_BYTES as u64 {
        return Err(Error::new(
            "boot",
            "capture image range is not the fixed 8 MiB reservation",
        ));
    }
    boot.capture_phys
        .checked_add(CAPTURE_PHYS_BYTES as u64)
        .ok_or_else(|| Error::new("boot", "capture physical range overflows"))?;

    let cpu_bytes = core::mem::size_of::<CaptureCpu>();
    if boot.snapshots_len == 0
        || !(boot.snapshots_len as usize).is_multiple_of(cpu_bytes)
        || boot.snapshots_len as usize / cpu_bytes > CAPTURE_MAX_CPUS
    {
        return Err(Error::new("boot", "snapshot byte length is invalid"));
    }
    let snapshots_count = boot.snapshots_len as usize / cpu_bytes;
    if boot.online_cpus == 0
        || boot.online_cpus as usize > CAPTURE_MAX_CPUS
        || snapshots_count < boot.online_cpus as usize
    {
        return Err(Error::values(
            "boot",
            "online CPU count exceeds snapshot array capacity",
            u64::from(boot.online_cpus),
            snapshots_count as u64,
        ));
    }
    if boot.parked_cpus != boot.online_cpus - 1 {
        return Err(Error::values(
            "boot",
            "not every non-leader CPU is parked",
            u64::from(boot.parked_cpus),
            u64::from(boot.online_cpus - 1),
        ));
    }
    if boot.regions_len == 0 || boot.regions_len as usize > CAPTURE_MAX_REGIONS {
        return Err(Error::new("boot", "region count is outside capacity"));
    }
    validate_physical_table(
        boot.snapshots_phys,
        boot.snapshots_len as usize,
        core::mem::align_of::<CaptureCpu>(),
        "snapshot",
    )?;
    validate_physical_table(
        boot.regions_phys,
        (boot.regions_len as usize)
            .checked_mul(core::mem::size_of::<CaptureRegion>())
            .ok_or_else(|| Error::new("boot", "region table byte length overflows"))?,
        core::mem::align_of::<CaptureRegion>(),
        "region",
    )?;
    if boot.capture_sectors == 0 || boot.capture_sectors as usize > VMCORE_BYTES / 512 {
        return Err(Error::values(
            "boot",
            "capture sector reservation exceeds the static vmcore buffer",
            u64::from(boot.capture_sectors),
            (VMCORE_BYTES / 512) as u64,
        ));
    }
    boot.capture_lba
        .checked_add(u64::from(boot.capture_sectors))
        .ok_or_else(|| Error::new("boot", "capture LBA range overflows"))?;
    Ok((boot.online_cpus as usize, snapshots_count))
}

fn validate_physical_table(
    phys: u64,
    bytes: usize,
    align: usize,
    name: &'static str,
) -> Result<(), Error> {
    if phys == 0 || phys & (align as u64 - 1) != 0 {
        return Err(Error::new("boot", "physical table address is unaligned"));
    }
    let end = phys
        .checked_add(bytes as u64)
        .ok_or_else(|| Error::new("boot", "physical table range overflows"))?;
    if end > 4 * 1024 * 1024 * 1024 {
        return Err(Error::new(
            "boot",
            "physical table is outside the HHDM's first 4 GiB",
        ));
    }
    let _ = name;
    Ok(())
}

fn physical_item(base: u64, index: usize, item_size: usize) -> u64 {
    // Only called inside a table whose complete byte range was already validated.
    base + (index as u64) * item_size as u64
}

fn read_physical<T: Copy>(hhdm_offset: u64, phys: u64) -> Result<T, &'static str> {
    if phys == 0 || phys & (core::mem::align_of::<T>() as u64 - 1) != 0 {
        return Err("physical item is unaligned");
    }
    let end = phys
        .checked_add(core::mem::size_of::<T>() as u64)
        .ok_or("physical item range overflows")?;
    if end > 4 * 1024 * 1024 * 1024 {
        return Err("physical item is outside HHDM coverage");
    }
    let va = hhdm_offset
        .checked_add(phys)
        .ok_or("physical item HHDM alias overflows")?;
    // SAFETY: validate_physical_table established the containing range in the first
    // 4 GiB; paging mapped it through HHDM. This item's alignment and complete size are
    // checked here, the reservation remains live, and APs are parked.
    Ok(unsafe { core::ptr::read_volatile(va as *const T) })
}

fn fail(error: Error) -> ! {
    serial::line(error.stage, error.reason);
    if error.a != 0 || error.b != 0 {
        serial::value("error.a", error.a);
        serial::value("error.b", error.b);
    }
    serial::fatal("capture aborted");
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    serial::fatal("Rust panic in capture kernel");
}
