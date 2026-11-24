//! Minimal standalone page tables built without the main kernel's VMM or allocator.

use aurora_capture::{CaptureBootInfo, CAPTURE_PHYS_BYTES, CAPTURE_TEXT_BYTES, CAPTURE_VA_BASE};

const PAGE: u64 = 4096;
const LARGE: u64 = 2 * 1024 * 1024;
const PRESENT: u64 = 1 << 0;
const WRITE: u64 = 1 << 1;
const LARGE_PAGE: u64 = 1 << 7;
const ACCESSED: u64 = 1 << 5;
const PCD: u64 = 1 << 4;
const NX: u64 = 1 << 63;

#[repr(align(4096))]
#[derive(Clone, Copy)]
struct PageTable([u64; 512]);

impl PageTable {
    const fn new() -> Self {
        Self([0; 512])
    }
}

struct Tables {
    pml4: PageTable,
    image_pdpt: PageTable,
    image_pd: [PageTable; 2],
    image_pt: [PageTable; 4],
    hhdm_pdpt: PageTable,
    hhdm_pd: [PageTable; 4],
    mmio_pt: PageTable,
    dma_pt: PageTable,
}

// This is deliberately in .bss, inside the 8 MiB image whose physical translation is
// fixed by CaptureBootInfo. No allocation and no access through the old CR3 after switch.
static mut TABLES: Tables = Tables {
    pml4: PageTable::new(),
    image_pdpt: PageTable::new(),
    image_pd: [PageTable::new(); 2],
    image_pt: [PageTable::new(); 4],
    hhdm_pdpt: PageTable::new(),
    hhdm_pd: [PageTable::new(); 4],
    mmio_pt: PageTable::new(),
    dma_pt: PageTable::new(),
};

fn index(va: u64, shift: u8) -> usize {
    ((va >> shift) & 0x1ff) as usize
}

fn image_phys(va: u64, capture_phys: u64) -> u64 {
    capture_phys + (va - CAPTURE_VA_BASE)
}

fn table_phys(table: *const PageTable, capture_phys: u64) -> u64 {
    image_phys(table as u64, capture_phys)
}

fn set(table: *mut PageTable, slot: usize, value: u64) {
    // SAFETY: every pointer is one of the 4 KiB-aligned tables in the static TABLES
    // object. Construction is single-threaded before CR3 activation; `slot` is masked
    // to nine bits by all callers, so the volatile store stays within that table.
    unsafe {
        let entries = core::ptr::addr_of_mut!((*table).0).cast::<u64>();
        entries.add(slot).write_volatile(value);
    }
}

/// Builds and activates the capture address space, returning the new CR3 for diagnostics.
pub fn activate(boot: &CaptureBootInfo) -> Result<u64, &'static str> {
    if boot.capture_phys == 0 || boot.capture_phys & (PAGE - 1) != 0 {
        return Err("capture physical base is not page aligned");
    }
    if boot.capture_bytes != CAPTURE_PHYS_BYTES as u64 {
        return Err("capture reservation is not 8 MiB");
    }
    boot.capture_phys
        .checked_add(CAPTURE_PHYS_BYTES as u64)
        .ok_or("capture physical range overflows")?;
    if boot.hhdm_offset == 0
        || boot.hhdm_offset & (LARGE * 512 - 1) != 0
        || boot
            .hhdm_offset
            .checked_add(4 * 1024 * 1024 * 1024)
            .is_none()
    {
        return Err("HHDM offset is zero, unaligned, or overflows");
    }
    if boot.ahci_mmio_phys == 0
        || boot.ahci_mmio_phys & (PAGE - 1) != 0
        || boot.ahci_mmio_phys >= 4 * 1024 * 1024 * 1024
    {
        return Err("AHCI MMIO is outside the mapped first 4 GiB");
    }

    let hhdm_pml4 = index(boot.hhdm_offset, 39);
    let image_pml4 = index(CAPTURE_VA_BASE, 39);
    if hhdm_pml4 == image_pml4 {
        return Err("HHDM aliases the capture PML4 slot");
    }

    // SAFETY: TABLES is a single static object accessed only by the capture leader before
    // activation. No AP enters this kernel and no reference escapes this setup call.
    let tables = unsafe { &mut *core::ptr::addr_of_mut!(TABLES) };
    let capture_phys = boot.capture_phys;

    // Image: all 2048 pages use 4 KiB translations. This also supports a capture base
    // that is only 4 KiB aligned; the VA/PA delta is exactly the handoff ABI's delta.
    let pml4 = core::ptr::addr_of_mut!(tables.pml4);
    let image_pdpt = core::ptr::addr_of_mut!(tables.image_pdpt);
    set(
        pml4,
        image_pml4,
        table_phys(image_pdpt, capture_phys) | PRESENT | WRITE,
    );
    for pd_slot in 0..2 {
        set(
            image_pdpt,
            index(CAPTURE_VA_BASE, 30) + pd_slot,
            table_phys(core::ptr::addr_of!(tables.image_pd[pd_slot]), capture_phys)
                | PRESENT
                | WRITE,
        );
    }
    for pt_slot in 0..4 {
        set(
            core::ptr::addr_of_mut!(tables.image_pd[0]),
            pt_slot,
            table_phys(core::ptr::addr_of!(tables.image_pt[pt_slot]), capture_phys)
                | PRESENT
                | WRITE,
        );
    }
    for page in 0..(CAPTURE_PHYS_BYTES / PAGE as usize) {
        let pt = core::ptr::addr_of_mut!(tables.image_pt[page / 512]);
        let flags = if page * (PAGE as usize) < CAPTURE_TEXT_BYTES {
            PRESENT | ACCESSED
        } else {
            PRESENT | WRITE | ACCESSED | NX
        };
        set(
            pt,
            page % 512,
            (capture_phys + (page as u64) * PAGE) | flags,
        );
    }

    // HHDM: exactly 4 GiB in 2 MiB pages. Limine's q35 HHDM is 2 MiB aligned.
    let hhdm_pdpt = core::ptr::addr_of_mut!(tables.hhdm_pdpt);
    set(
        pml4,
        hhdm_pml4,
        table_phys(hhdm_pdpt, capture_phys) | PRESENT | WRITE,
    );
    let hhdm_pd_first = index(boot.hhdm_offset, 30);
    if hhdm_pd_first > 508 {
        return Err("HHDM PDPT window would exceed its 512 slots");
    }
    for pd_slot in 0..4 {
        set(
            hhdm_pdpt,
            hhdm_pd_first + pd_slot,
            table_phys(core::ptr::addr_of!(tables.hhdm_pd[pd_slot]), capture_phys)
                | PRESENT
                | WRITE,
        );
        for pt_slot in 0..512 {
            let pa = ((pd_slot * 512 + pt_slot) as u64) * LARGE;
            set(
                core::ptr::addr_of_mut!(tables.hhdm_pd[pd_slot]),
                pt_slot,
                pa | PRESENT | WRITE | ACCESSED | LARGE_PAGE,
            );
        }
    }

    // Split only the AHCI-containing 2 MiB HHDM leaf. Its 4 KiB siblings remain ordinary
    // HHDM pages; the ABAR page gets PCD=1, which is UC- under this repository's PAT.
    let mmio_va = boot
        .hhdm_offset
        .checked_add(boot.ahci_mmio_phys)
        .ok_or("AHCI HHDM alias overflows")?;
    let mmio_pdpt_slot = index(mmio_va, 30)
        .checked_sub(hhdm_pd_first)
        .ok_or("AHCI PDPT precedes HHDM")?;
    if mmio_pdpt_slot >= 4 {
        return Err("AHCI MMIO translation leaves the first 4 GiB");
    }
    let mmio_pd = core::ptr::addr_of_mut!(tables.hhdm_pd[mmio_pdpt_slot]);
    let mmio_pt = core::ptr::addr_of_mut!(tables.mmio_pt);
    let chunk_pa = boot.ahci_mmio_phys & !(LARGE - 1);
    for slot in 0..512 {
        let pa = chunk_pa + (slot as u64) * PAGE;
        let cache = if slot == index(mmio_va, 12) { PCD } else { 0 };
        set(mmio_pt, slot, pa | PRESENT | WRITE | ACCESSED | cache);
    }
    set(
        mmio_pd,
        index(mmio_va, 21),
        table_phys(mmio_pt, capture_phys) | PRESENT | WRITE,
    );

    let dma_va = boot
        .hhdm_offset
        .checked_add(boot.ahci_dma_phys)
        .ok_or("AHCI DMA HHDM alias overflows")?;
    let dma_pdpt_slot = index(dma_va, 30)
        .checked_sub(hhdm_pd_first)
        .ok_or("AHCI DMA PDPT precedes HHDM")?;
    if dma_pdpt_slot >= 4 {
        return Err("AHCI DMA translation leaves the first 4 GiB");
    }
    let dma_pd = core::ptr::addr_of_mut!(tables.hhdm_pd[dma_pdpt_slot]);
    let dma_pt = core::ptr::addr_of_mut!(tables.dma_pt);
    let dma_chunk_pa = boot.ahci_dma_phys & !(LARGE - 1);
    for slot in 0..512 {
        let pa = dma_chunk_pa + (slot as u64) * PAGE;
        set(dma_pt, slot, pa | PRESENT | WRITE | ACCESSED | PCD);
    }
    set(
        dma_pd,
        index(dma_va, 21),
        table_phys(dma_pt, capture_phys) | PRESENT | WRITE,
    );

    // Publish every table entry before CR3. TLB invalidation is part of the CR3 write.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    let root = table_phys(pml4, capture_phys);
    // SAFETY: `root` is the 4 KiB-aligned physical address of our fully populated PML4;
    // the current mapping covers all image pages and the new mapping covers code, stack,
    // tables and all subsequently touched DMA/HHDM pages. Execution remains ring 0.
    unsafe { core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, nomem)) };
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    let active = current_cr3();
    if active != root {
        return Err("CR3 readback does not match the capture PML4");
    }
    Ok(active)
}

fn current_cr3() -> u64 {
    let value: u64;
    // SAFETY: reading CR3 is a non-memory ring-0 register operation on the capture CPU.
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) value, options(nostack, nomem)) };
    value
}
