//! Stable ABI shared by the main kernel's crash handoff and the isolated capture kernel.
//!
//! `CaptureBootInfo` is passed by pointer in `rdi`. CPU counts are compact counts, not
//! bitmaps; `parked_cpus` excludes the leader. Snapshot length is a byte length.

#![no_std]
// The pre-existing cross-crate ABI uses self-describing field/constant names; safety
// contracts are still documented at every unsafe operation rather than suppressed.
#![allow(missing_docs)]

pub const CAPTURE_MAGIC: u64 = 0x4155_524f_4b44_4d50;
pub const CAPTURE_VERSION: u32 = 1;
pub const CAPTURE_VA_BASE: u64 = 0xffff_ffff_c000_0000;
pub const CAPTURE_PHYS_BYTES: usize = 8 * 1024 * 1024;
pub const CAPTURE_DMA_OFFSET: usize = CAPTURE_PHYS_BYTES - 256 * 1024;
pub const CAPTURE_DMA_BYTES: usize = 256 * 1024;
pub const CAPTURE_STACK_BYTES: usize = 64 * 1024;
pub const CAPTURE_TEXT_BYTES: usize = 64 * 1024;
pub const CAPTURE_STACK_TOP: u64 = CAPTURE_VA_BASE + CAPTURE_DMA_OFFSET as u64 - 16;
const _: () = assert!(CAPTURE_PHYS_BYTES == 8 * 1024 * 1024);
const _: () = assert!(CAPTURE_STACK_TOP == 0xffff_ffff_c07b_fff0);
pub const CAPTURE_ENTRY_MAGIC: &[u8; 8] = b"AURCAP01";
pub const CAPTURE_MAX_CPUS: usize = 8;
pub const CAPTURE_MAX_REGIONS: usize = 96;

/// AHCI command-list base relative to `ahci_dma_phys` (1 KiB aligned).
pub const CAPTURE_AHCI_CLIST_OFFSET: usize = 0x0000;
/// Command table for slot zero relative to `ahci_dma_phys` (128 byte aligned).
pub const CAPTURE_AHCI_CTBL_OFFSET: usize = 0x1000;
/// Received-FIS area base; slot `n` starts at `base + n * 0x100`.
pub const CAPTURE_AHCI_RXFIS_OFFSET: usize = 0x2000;
/// Data area shared by the crash-only writer, relative to `ahci_dma_phys`.
pub const CAPTURE_AHCI_DATA_OFFSET: usize = 0x6000;
/// Minimum DMA reservation: command structures, 32 received-FIS slots and one sector.
pub const CAPTURE_AHCI_MIN_DMA_BYTES: usize = CAPTURE_AHCI_DATA_OFFSET + 512;

/// Standard ELF64 note type for x86-64 register state.
pub const NT_PRSTATUS: u32 = 1;
/// Aurora capture note: register/control snapshot plus an independent checksum.
pub const NT_AURORA_CAPTURE: u32 = 0x4155_5241;
/// Magic at the start of every `NT_AURORA_CAPTURE` descriptor.
pub const AURORA_NOTE_MAGIC: u64 = 0x4155_5243_4150_3100;
/// Version of the private Aurora note descriptor.
pub const AURORA_NOTE_VERSION: u32 = 1;

pub const CPU_VALID: usize = 0;
pub const CPU_SOURCE: usize = 1;
pub const CPU_VECTOR: usize = 2;
pub const CPU_ERR: usize = 3;
pub const CPU_CR2: usize = 4;
pub const CPU_RIP: usize = 5;
pub const CPU_RSP: usize = 6;
pub const CPU_RBP: usize = 7;
pub const CPU_RAX: usize = 8;
pub const CPU_RBX: usize = 9;
pub const CPU_RCX: usize = 10;
pub const CPU_RDX: usize = 11;
pub const CPU_RSI: usize = 12;
pub const CPU_RDI: usize = 13;
pub const CPU_R8: usize = 14;
pub const CPU_R9: usize = 15;
pub const CPU_R10: usize = 16;
pub const CPU_R11: usize = 17;
pub const CPU_R12: usize = 18;
pub const CPU_R13: usize = 19;
pub const CPU_R14: usize = 20;
pub const CPU_R15: usize = 21;
pub const CPU_RFLAGS: usize = 22;
pub const CPU_CS: usize = 23;
pub const CPU_SS: usize = 24;
pub const CPU_CR3: usize = 25;
pub const CPU_CR4: usize = 26;
pub const CPU_FS_BASE: usize = 27;
pub const CPU_GS_BASE: usize = 28;
pub const CPU_TSC: usize = 29;
pub const CPU_WORDS: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CaptureCpu {
    pub words: [u64; CPU_WORDS],
}

impl CaptureCpu {
    pub const fn empty() -> Self {
        Self {
            words: [0; CPU_WORDS],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CaptureRegion {
    pub base: u64,
    pub length: u64,
    pub kind: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CaptureBootInfo {
    pub magic: u64,
    pub version: u32,
    pub size: u32,
    /// FNV-1a over fields in declaration order, with this field represented as zero.
    pub checksum: u64,
    pub hhdm_offset: u64,
    pub main_image_phys: u64,
    pub main_image_bytes: u64,
    pub capture_phys: u64,
    pub capture_bytes: u64,
    pub capture_payload_bytes: u32,
    pub capture_payload_checksum: u64,
    pub snapshots_phys: u64,
    /// Byte length/capacity of the static `CaptureCpu` array. The first
    /// `online_cpus` entries are emitted; unused capacity slots are ignored.
    pub snapshots_len: u32,
    pub regions_phys: u64,
    pub regions_len: u32,
    pub ahci_mmio_phys: u64,
    pub ahci_port: u32,
    pub ahci_dma_phys: u64,
    pub ahci_dma_bytes: u32,
    pub serial_port: u16,
    /// Number of registered CPUs, including the leader.
    pub online_cpus: u32,
    /// Number of parked APs; the leader is not included.
    pub parked_cpus: u32,
    pub capture_lba: u64,
    pub capture_sectors: u32,
}

impl CaptureBootInfo {
    /// Computes the handoff checksum over fields in declaration order, excluding repr(C) padding.
    pub fn canonical_checksum(&self) -> u64 {
        let fields = [
            self.magic,
            u64::from(self.version),
            u64::from(self.size),
            0,
            self.hhdm_offset,
            self.main_image_phys,
            self.main_image_bytes,
            self.capture_phys,
            self.capture_bytes,
            u64::from(self.capture_payload_bytes),
            self.capture_payload_checksum,
            self.snapshots_phys,
            u64::from(self.snapshots_len),
            self.regions_phys,
            u64::from(self.regions_len),
            self.ahci_mmio_phys,
            u64::from(self.ahci_port),
            self.ahci_dma_phys,
            u64::from(self.ahci_dma_bytes),
            u64::from(self.serial_port),
            u64::from(self.online_cpus),
            u64::from(self.parked_cpus),
            self.capture_lba,
            u64::from(self.capture_sectors),
        ];
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for field in fields {
            for byte in field.to_le_bytes() {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        hash
    }
}

/// Fixed-layout private note descriptor. Its checksum also uses a zero checksum field.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuroraCaptureNote {
    pub magic: u64,
    pub version: u32,
    pub size: u32,
    pub checksum: u64,
    pub cpu_index: u32,
    pub reserved: u32,
    pub words: [u64; CPU_WORDS],
}

pub fn checksum(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
