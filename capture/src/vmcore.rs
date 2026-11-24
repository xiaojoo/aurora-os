//! Allocation-free ELF64 vmcore metadata writer.
//!
//! Region bytes are intentionally sparse: each PT_LOAD has `p_filesz = 0`, a physical
//! `p_paddr`, and the full memory size. The host reader must combine this metadata with
//! its physical-memory instrument; the capture file itself contains headers and notes.

use aurora_capture::{
    checksum, AuroraCaptureNote, CaptureBootInfo, CaptureCpu, CaptureRegion, AURORA_NOTE_MAGIC,
    AURORA_NOTE_VERSION, CPU_CS, CPU_R10, CPU_R11, CPU_R12, CPU_R13, CPU_R14,
    CPU_R15, CPU_R8, CPU_R9, CPU_RAX, CPU_RBP, CPU_RBX, CPU_RCX, CPU_RDI, CPU_RDX, CPU_RFLAGS,
    CPU_RIP, CPU_RSI, CPU_RSP, CPU_SS, NT_AURORA_CAPTURE, NT_PRSTATUS,
};

const SECTOR: usize = 512;
const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const ET_CORE: u16 = 4;
const EM_X86_64: u16 = 62;
const PF_R: u32 = 4;

struct Cursor<'a> {
    bytes: &'a mut [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn write(&mut self, src: &[u8]) -> Result<(), &'static str> {
        let end = self
            .pos
            .checked_add(src.len())
            .ok_or("vmcore writer position overflows")?;
        if end > self.bytes.len() {
            return Err("vmcore exceeds its static buffer");
        }
        self.bytes[self.pos..end].copy_from_slice(src);
        self.pos = end;
        Ok(())
    }

    fn zeros(&mut self, count: usize) -> Result<(), &'static str> {
        let end = self
            .pos
            .checked_add(count)
            .ok_or("vmcore padding overflows")?;
        if end > self.bytes.len() {
            return Err("vmcore padding exceeds its static buffer");
        }
        for byte in &mut self.bytes[self.pos..end] {
            *byte = 0;
        }
        self.pos = end;
        Ok(())
    }

    fn note(&mut self, name: &[u8], note_type: u32, desc: &[u8]) -> Result<(), &'static str> {
        let mut header = [0u8; 16];
        put_u32(&mut header, 0, name.len() as u32);
        put_u32(&mut header, 4, desc.len() as u32);
        put_u32(&mut header, 8, note_type);
        self.write(&header)?;
        self.write(name)?;
        self.zeros(pad4(name.len()))?;
        self.write(desc)?;
        self.zeros(pad4(desc.len()))
    }
}

fn pad4(len: usize) -> usize {
    (4 - (len & 3)) & 3
}

fn align_up(value: usize, alignment: usize) -> Result<usize, &'static str> {
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
        .ok_or("vmcore alignment overflows")
}

fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn prstatus(cpu: &CaptureCpu) -> Result<[u8; 336], &'static str> {
    if cpu.words[aurora_capture::CPU_VALID] != 1 {
        return Err("an online CPU snapshot is not marked valid");
    }
    let mut desc = [0u8; 336];
    // x86-64 elf_prstatus: the 27-word gregset starts at byte 112.
    let regs = [
        (CPU_R15, 0),
        (CPU_R14, 1),
        (CPU_R13, 2),
        (CPU_R12, 3),
        (CPU_RBP, 4),
        (CPU_RBX, 5),
        (CPU_R11, 6),
        (CPU_R10, 7),
        (CPU_R9, 8),
        (CPU_R8, 9),
        (CPU_RAX, 10),
        (CPU_RCX, 11),
        (CPU_RDX, 12),
        (CPU_RSI, 13),
        (CPU_RDI, 14),
        (CPU_RIP, 16),
        (CPU_CS, 17),
        (CPU_RFLAGS, 18),
        (CPU_RSP, 19),
        (CPU_SS, 20),
        (aurora_capture::CPU_FS_BASE, 21),
        (aurora_capture::CPU_GS_BASE, 22),
    ];
    for &(source, target) in &regs {
        put_u64(&mut desc, 112 + target * 8, cpu.words[source]);
    }
    Ok(desc)
}

fn aurora_note(cpu_index: u32, cpu: &CaptureCpu) -> Result<[u8; 288], &'static str> {
    let note = AuroraCaptureNote {
        magic: AURORA_NOTE_MAGIC,
        version: AURORA_NOTE_VERSION,
        size: core::mem::size_of::<AuroraCaptureNote>() as u32,
        checksum: 0,
        cpu_index,
        reserved: 0,
        words: cpu.words,
    };
    let mut desc = [0u8; 288];
    put_u64(&mut desc, 0, note.magic);
    put_u32(&mut desc, 8, note.version);
    put_u32(&mut desc, 12, note.size);
    put_u64(&mut desc, 16, 0);
    put_u32(&mut desc, 24, note.cpu_index);
    put_u32(&mut desc, 28, note.reserved);
    for (index, word) in note.words.iter().enumerate() {
        put_u64(&mut desc, 32 + index * 8, *word);
    }
    let sum = checksum(&desc);
    put_u64(&mut desc, 16, sum);
    Ok(desc)
}

fn elf_header(phnum: u16) -> [u8; EHDR_SIZE] {
    let mut header = [0u8; EHDR_SIZE];
    header[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    header[4] = 2; // ELFCLASS64
    header[5] = 1; // ELFDATA2LSB
    header[6] = 1; // EV_CURRENT
    put_u16(&mut header, 16, ET_CORE);
    put_u16(&mut header, 18, EM_X86_64);
    put_u32(&mut header, 20, 1);
    put_u64(&mut header, 32, EHDR_SIZE as u64);
    put_u16(&mut header, 52, EHDR_SIZE as u16);
    put_u16(&mut header, 54, PHDR_SIZE as u16);
    put_u16(&mut header, 56, phnum);
    header
}

fn note_phdr(offset: usize, length: usize) -> [u8; PHDR_SIZE] {
    let mut phdr = [0u8; PHDR_SIZE];
    put_u32(&mut phdr, 0, PT_NOTE);
    put_u32(&mut phdr, 4, PF_R);
    put_u64(&mut phdr, 8, offset as u64);
    put_u64(&mut phdr, 32, length as u64);
    put_u64(&mut phdr, 40, length as u64);
    put_u64(&mut phdr, 48, 4);
    phdr
}

fn load_phdr(region: &CaptureRegion) -> Result<[u8; PHDR_SIZE], &'static str> {
    if region.length == 0 {
        return Err("a zero-length memory region cannot be a PT_LOAD");
    }
    region
        .base
        .checked_add(region.length)
        .ok_or("a memory region physical range overflows")?;
    let mut phdr = [0u8; PHDR_SIZE];
    // `kind` is a Limine memory-map classification, not a page-permission bitmap. Do
    // not invent W/X permissions from it; the host reader gets the classification in
    // its own region table and this sparse core remains read-only.
    put_u32(&mut phdr, 0, PT_LOAD);
    put_u32(&mut phdr, 4, PF_R);
    put_u64(&mut phdr, 24, region.base);
    put_u64(&mut phdr, 32, 0);
    put_u64(&mut phdr, 40, region.length);
    put_u64(&mut phdr, 48, PAGE_ALIGN);
    Ok(phdr)
}

const PAGE_ALIGN: u64 = 4096;

/// Writes a sector-padded core into `buffer` and returns its exact byte length.
pub fn build(
    boot: &CaptureBootInfo,
    snapshots: &[CaptureCpu],
    regions: &[CaptureRegion],
    buffer: &mut [u8],
) -> Result<usize, &'static str> {
    if snapshots.len() != boot.online_cpus as usize {
        return Err("snapshot count does not match online CPU count");
    }
    if regions.len() != boot.regions_len as usize || regions.is_empty() {
        return Err("region table is empty or has the wrong count");
    }
    let phnum = regions
        .len()
        .checked_add(1)
        .ok_or("program-header count overflows")?;
    if phnum > u16::MAX as usize {
        return Err("region count exceeds ELF64 program-header capacity");
    }
    let output_bytes = (boot.capture_sectors as usize)
        .checked_mul(SECTOR)
        .ok_or("capture sector range overflows")?;
    if output_bytes == 0 || output_bytes > buffer.len() {
        return Err("capture sector reservation is zero or exceeds the static vmcore buffer");
    }

    let mut cursor = Cursor {
        bytes: buffer,
        pos: 0,
    };
    cursor.write(&[0u8; EHDR_SIZE])?;
    let note_offset = EHDR_SIZE + phnum * PHDR_SIZE;
    cursor.write(&[0u8; PHDR_SIZE])?; // PT_NOTE, patched after notes are sized
    for region in regions {
        cursor.write(&load_phdr(region)?)?;
    }
    let notes_start = cursor.pos;
    if notes_start != note_offset {
        return Err("internal vmcore program-header layout mismatch");
    }
    for (index, cpu) in snapshots.iter().enumerate() {
        let status = prstatus(cpu)?;
        cursor.note(b"CORE\0", NT_PRSTATUS, &status)?;
        let capture = aurora_note(index as u32, cpu)?;
        cursor.note(b"AURORA\0", NT_AURORA_CAPTURE, &capture)?;
    }
    let notes_end = cursor.pos;
    let output_bytes = align_up(output_bytes, SECTOR)?;
    if output_bytes > cursor.bytes.len() || notes_end > output_bytes {
        return Err("notes exceed the sector-padded capture output");
    }
    cursor.zeros(output_bytes - notes_end)?;

    let header = elf_header(phnum as u16);
    cursor.bytes[..EHDR_SIZE].copy_from_slice(&header);
    cursor.bytes[EHDR_SIZE..EHDR_SIZE + PHDR_SIZE]
        .copy_from_slice(&note_phdr(note_offset, notes_end - notes_start));
    Ok(output_bytes)
}
