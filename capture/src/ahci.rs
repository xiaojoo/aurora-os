//! One-shot AHCI DMA write. There is no retry, reset, interrupt, lock, or allocation path.

use aurora_capture::{
    CaptureBootInfo, CAPTURE_AHCI_CLIST_OFFSET, CAPTURE_AHCI_CTBL_OFFSET, CAPTURE_AHCI_DATA_OFFSET,
    CAPTURE_AHCI_MIN_DMA_BYTES, CAPTURE_AHCI_RXFIS_OFFSET,
};

const PAGE: u64 = 4096;
const SECTOR: usize = 512;
const PORT_BASE: usize = 0x100;
const PORT_STRIDE: usize = 0x80;
const GHC: usize = 0x04;
const GHC_AE: u32 = 1 << 31;
const P_CLB: usize = 0x00;
const P_CLBU: usize = 0x04;
const P_FB: usize = 0x08;
const P_FBU: usize = 0x0c;
const P_IS: usize = 0x10;
const P_CMD: usize = 0x18;
const P_TFD: usize = 0x20;
const P_SERR: usize = 0x30;
const P_SACT: usize = 0x34;
const P_CI: usize = 0x38;
const CMD_ST: u32 = 1 << 0;
const CMD_FRE: u32 = 1 << 4;
const ATA_ERR: u8 = 1 << 0;
const ATA_DRQ: u8 = 1 << 3;
const ATA_BUSY: u8 = 1 << 7;
const FIS_H2D: u8 = 0x27;
const FIS_D2H: u8 = 0x34;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const PORT_IS_FATAL: u32 = (1 << 23) | (1 << 22) | (1 << 24) | (1 << 26) | (1 << 30);
const MAX_CHUNK: usize = 255 * SECTOR;
const COMPLETION_SPINS: u32 = 100_000_000;

#[derive(Clone, Copy)]
pub struct Error {
    pub stage: &'static str,
    pub reason: &'static str,
    pub a: u64,
    pub b: u64,
}

impl Error {
    pub fn new(stage: &'static str, reason: &'static str) -> Self {
        Self {
            stage,
            reason,
            a: 0,
            b: 0,
        }
    }

    pub fn values(stage: &'static str, reason: &'static str, a: u64, b: u64) -> Self {
        Self {
            stage,
            reason,
            a,
            b,
        }
    }

    fn mismatch(stage: &'static str, a: u64, b: u64) -> Self {
        Self {
            stage,
            reason: "hardware/readback value mismatch",
            a,
            b,
        }
    }
}

pub struct Ahci {
    mmio: usize,
    port: usize,
    dma_phys: u64,
    dma_va: usize,
    dma_bytes: usize,
    rx_offset: usize,
}

impl Ahci {
    pub fn new(boot: &CaptureBootInfo, hhdm_offset: u64) -> Result<Self, Error> {
        if boot.ahci_port >= 32 {
            return Err(Error::new("ahci", "port number is outside 0..31"));
        }
        if boot.ahci_dma_phys == 0
            || boot.ahci_dma_phys & (PAGE - 1) != 0
            || boot.ahci_dma_phys >= 4 * 1024 * 1024 * 1024
        {
            return Err(Error::new(
                "ahci",
                "DMA base is not a page-aligned address below 4 GiB",
            ));
        }
        if (boot.ahci_dma_bytes as usize) < CAPTURE_AHCI_MIN_DMA_BYTES {
            return Err(Error::new(
                "ahci",
                "preinitialized DMA reservation is too small",
            ));
        }
        let dma_end = boot
            .ahci_dma_phys
            .checked_add(u64::from(boot.ahci_dma_bytes))
            .ok_or_else(|| Error::new("ahci", "DMA physical range overflows"))?;
        if dma_end > 4 * 1024 * 1024 * 1024 {
            return Err(Error::new(
                "ahci",
                "DMA range crosses the 32-bit ABAR boundary",
            ));
        }
        let mmio = hhdm_offset
            .checked_add(boot.ahci_mmio_phys)
            .ok_or_else(|| Error::new("ahci", "AHCI MMIO alias overflows"))?;
        let dma_va = hhdm_offset
            .checked_add(boot.ahci_dma_phys)
            .ok_or_else(|| Error::new("ahci", "AHCI DMA alias overflows"))?;
        let port = usize::try_from(boot.ahci_port)
            .map_err(|_| Error::new("ahci", "port conversion failed"))?;
        Ok(Self {
            mmio: usize::try_from(mmio)
                .map_err(|_| Error::new("ahci", "MMIO alias does not fit usize"))?,
            port,
            dma_phys: boot.ahci_dma_phys,
            dma_va: usize::try_from(dma_va)
                .map_err(|_| Error::new("ahci", "DMA alias does not fit usize"))?,
            dma_bytes: boot.ahci_dma_bytes as usize,
            rx_offset: CAPTURE_AHCI_RXFIS_OFFSET + port * 0x100,
        })
    }

    pub fn data_capacity(&self) -> usize {
        let bytes = self.dma_bytes - CAPTURE_AHCI_DATA_OFFSET;
        bytes.min(MAX_CHUNK) / SECTOR * SECTOR
    }

    fn reg(&self, offset: usize) -> usize {
        self.mmio + PORT_BASE + self.port * PORT_STRIDE + offset
    }

    fn global(&self, offset: usize) -> u32 {
        // SAFETY: paging maps the ABAR's first 4 KiB as UC. This validated offset is
        // inside that page and all accesses are volatile 32-bit ring-0 MMIO operations.
        unsafe { core::ptr::read_volatile((self.mmio + offset) as *const u32) }
    }

    fn r32(&self, offset: usize) -> u32 {
        // SAFETY: `reg` is a validated port register inside the UC-mapped ABAR page;
        // volatile 32-bit MMIO is exactly the required hardware access width.
        unsafe { core::ptr::read_volatile(self.reg(offset) as *const u32) }
    }

    fn w32(&self, offset: usize, value: u32) {
        // SAFETY: `reg` is a validated writable port register inside the UC-mapped ABAR
        // page; the access is a volatile 32-bit ring-0 MMIO store.
        unsafe { core::ptr::write_volatile(self.reg(offset) as *mut u32, value) };
    }

    fn dma_ptr(&self, offset: usize) -> *mut u8 {
        (self.dma_va + offset) as *mut u8
    }

    fn dma_read(&self, offset: usize, dst: &mut [u8]) -> Result<(), Error> {
        let end = offset
            .checked_add(dst.len())
            .ok_or_else(|| Error::new("ahci", "DMA read range overflows"))?;
        if end > self.dma_bytes {
            return Err(Error::new(
                "ahci",
                "DMA read exceeds the preinitialized reservation",
            ));
        }
        // SAFETY: paging maps the complete checked range through HHDM. `dst` is a live
        // exclusive slice; the leader is the only CPU touching this quiescent DMA area.
        unsafe {
            core::ptr::copy_nonoverlapping(self.dma_ptr(offset), dst.as_mut_ptr(), dst.len())
        };
        Ok(())
    }

    fn dma_write(&self, offset: usize, src: &[u8]) -> Result<(), Error> {
        let end = offset
            .checked_add(src.len())
            .ok_or_else(|| Error::new("ahci", "DMA write range overflows"))?;
        if end > self.dma_bytes {
            return Err(Error::new(
                "ahci",
                "DMA write exceeds the preinitialized reservation",
            ));
        }
        // SAFETY: the checked destination lies in the exclusive HHDM-mapped DMA
        // reservation; `src` is live and cannot overlap that reservation.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), self.dma_ptr(offset), src.len()) };
        Ok(())
    }

    fn check_quiescent(&self) -> Result<(), Error> {
        if self.global(GHC) & GHC_AE == 0 {
            return Err(Error::new("ahci", "GHC.AE is clear"));
        }
        let cmd = self.r32(P_CMD);
        if cmd & (CMD_FRE | CMD_ST) != (CMD_FRE | CMD_ST) {
            return Err(Error::mismatch(
                "ahci",
                u64::from(cmd),
                (CMD_FRE | CMD_ST) as u64,
            ));
        }
        #[cfg(feature = "kdump-busy-port")]
        let ci = {
            self.w32(P_CI, 1);
            self.r32(P_CI)
        };
        #[cfg(not(feature = "kdump-busy-port"))]
        let ci = self.r32(P_CI);
        let sact = self.r32(P_SACT);
        if ci != 0 || sact != 0 {
            return Err(Error {
                stage: "ahci",
                reason: "port is not quiescent (PxCI/PxSACT nonzero)",
                a: u64::from(ci),
                b: u64::from(sact),
            });
        }
        let tfd = self.r32(P_TFD);
        if (tfd as u8) & (ATA_BUSY | ATA_DRQ | ATA_ERR) != 0 || (tfd >> 8) as u8 != 0 {
            return Err(Error {
                stage: "ahci",
                reason: "port has pending/error ATA status",
                a: u64::from(tfd),
                b: 0,
            });
        }
        let pxis = self.r32(P_IS);
        if pxis & PORT_IS_FATAL != 0 {
            return Err(Error {
                stage: "ahci",
                reason: "port has a fatal HBA interrupt-status bit",
                a: u64::from(pxis),
                b: 0,
            });
        }
        let serr = self.r32(P_SERR);
        if serr != 0 {
            return Err(Error {
                stage: "ahci",
                reason: "port has a pending SATA error",
                a: u64::from(serr),
                b: 0,
            });
        }
        let clb = self.r32(P_CLB);
        let clbu = self.r32(P_CLBU);
        let fb = self.r32(P_FB);
        let fbu = self.r32(P_FBU);
        let want_clb = (self.dma_phys + CAPTURE_AHCI_CLIST_OFFSET as u64) as u32;
        let want_fb = (self.dma_phys + self.rx_offset as u64) as u32;
        if clbu != 0 || fbu != 0 || clb != want_clb || fb != want_fb {
            return Err(Error {
                stage: "ahci",
                reason: "PxCLB/PxFB do not match the reserved DMA layout",
                a: (u64::from(clbu) << 32) | u64::from(clb),
                b: (u64::from(fbu) << 32) | u64::from(fb),
            });
        }
        Ok(())
    }

    /// Writes one whole-sector chunk. Chunking is caller-visible, not a hidden retry.
    pub fn write_chunk(&self, lba: u64, src: &[u8]) -> Result<(), Error> {
        if src.is_empty() || !src.len().is_multiple_of(SECTOR) || src.len() > self.data_capacity() {
            return Err(Error::new(
                "ahci",
                "chunk is empty, partial-sector, or too large",
            ));
        }
        let sectors = (src.len() / SECTOR) as u64;
        lba.checked_add(sectors)
            .ok_or_else(|| Error::new("ahci", "LBA range overflows"))?;
        self.check_quiescent()?;
        self.dma_write(CAPTURE_AHCI_DATA_OFFSET, src)?;

        let mut fis = [0u8; 20];
        fis[0] = FIS_H2D;
        fis[1] = 0x80;
        fis[2] = ATA_WRITE_DMA_EXT;
        fis[4] = lba as u8;
        fis[5] = (lba >> 8) as u8;
        fis[6] = (lba >> 16) as u8;
        fis[7] = 0xe0 | ((lba >> 24) as u8 & 0x0f);
        fis[8] = (lba >> 24) as u8;
        fis[9] = (lba >> 32) as u8;
        fis[10] = (lba >> 40) as u8;
        fis[12] = sectors as u8;
        fis[13] = (sectors >> 8) as u8;

        let mut command_table = [0u8; 80];
        command_table[..20].copy_from_slice(&fis);
        let data_pa = self.dma_phys + CAPTURE_AHCI_DATA_OFFSET as u64;
        command_table[64..68].copy_from_slice(&(data_pa as u32).to_le_bytes());
        command_table[68..72].copy_from_slice(&((data_pa >> 32) as u32).to_le_bytes());
        command_table[76..80].copy_from_slice(&((src.len() - 1) as u32).to_le_bytes());

        let mut header = [0u8; 16];
        let dw0 = (1u32 << 16) | 5 | (1 << 6);
        let ctba = self.dma_phys + CAPTURE_AHCI_CTBL_OFFSET as u64;
        header[0..4].copy_from_slice(&dw0.to_le_bytes());
        header[8..12].copy_from_slice(&(ctba as u32).to_le_bytes());
        header[12..16].copy_from_slice(&((ctba >> 32) as u32).to_le_bytes());
        self.dma_write(CAPTURE_AHCI_CLIST_OFFSET, &header)?;
        self.dma_write(CAPTURE_AHCI_CTBL_OFFSET, &command_table)?;

        let mut header_check = [0u8; 16];
        let mut table_check = [0u8; 80];
        self.dma_read(CAPTURE_AHCI_CLIST_OFFSET, &mut header_check)?;
        self.dma_read(CAPTURE_AHCI_CTBL_OFFSET, &mut table_check)?;
        if header_check != header || table_check != command_table {
            return Err(Error::new("ahci", "command table/header readback differs"));
        }

        // Invalidate the previous D2H receipt before issuing this command.
        self.dma_write(self.rx_offset + 0x40, &[0u8; 16])?;
        let mut cleared = [0xffu8; 16];
        self.dma_read(self.rx_offset + 0x40, &mut cleared)?;
        if cleared != [0u8; 16] {
            return Err(Error::new("ahci", "previous D2H receipt did not clear"));
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.w32(P_CI, 1);

        let mut completed = false;
        let mut receipt = [0u8; 1];
        for _ in 0..COMPLETION_SPINS {
            let ci = self.r32(P_CI);
            let sact = self.r32(P_SACT);
            let tfd = self.r32(P_TFD);
            let status = tfd as u8;
            self.dma_read(self.rx_offset + 0x40, &mut receipt)?;
            if ci == 0 && sact == 0 && status & (ATA_BUSY | ATA_DRQ) == 0 && receipt[0] == FIS_D2H {
                completed = true;
                break;
            }
            if status & ATA_ERR != 0 {
                break;
            }
            core::hint::spin_loop();
        }
        let ci = self.r32(P_CI);
        let sact = self.r32(P_SACT);
        let tfd = self.r32(P_TFD);
        if !completed || ci != 0 || sact != 0 {
            return Err(Error {
                stage: "ahci",
                reason: "command did not complete cleanly",
                a: u64::from(ci),
                b: (u64::from(sact) << 32) | u64::from(tfd),
            });
        }
        let status = tfd as u8;
        let error = (tfd >> 8) as u8;
        if status & (ATA_ERR | ATA_BUSY | ATA_DRQ) != 0 || error != 0 {
            return Err(Error {
                stage: "ahci",
                reason: "ATA completion status/error is nonzero",
                a: u64::from(status),
                b: u64::from(error),
            });
        }
        let pxis = self.r32(P_IS);
        if pxis & PORT_IS_FATAL != 0 {
            return Err(Error {
                stage: "ahci",
                reason: "HBA reported an interface error",
                a: u64::from(pxis),
                b: 0,
            });
        }

        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.dma_read(CAPTURE_AHCI_CLIST_OFFSET, &mut header_check)?;
        self.dma_read(CAPTURE_AHCI_CTBL_OFFSET, &mut table_check)?;
        let mut d2h = [0u8; 16];
        self.dma_read(self.rx_offset + 0x40, &mut d2h)?;
        if table_check != command_table {
            return Err(Error::new("ahci", "command table changed during DMA"));
        }
        let prdbc = u32::from_le_bytes([
            header_check[4],
            header_check[5],
            header_check[6],
            header_check[7],
        ]);
        let prdbc_ok = if cfg!(feature = "kdump-bad-completion") {
            prdbc == src.len() as u32 + 1
        } else {
            prdbc == src.len() as u32
        };
        if !prdbc_ok {
            return Err(Error {
                stage: "ahci",
                reason: "PRDBC does not equal the requested byte count",
                a: u64::from(prdbc),
                b: src.len() as u64,
            });
        }
        if d2h[0] != FIS_D2H || d2h[2] != status || d2h[3] != error {
            return Err(Error {
                stage: "ahci",
                reason: "D2H FIS type/status/error does not match PxTFD",
                a: u64::from_le_bytes([d2h[0], d2h[1], d2h[2], d2h[3], 0, 0, 0, 0]),
                b: u64::from(tfd),
            });
        }
        // QEMU does not echo the requested LBA/sector count in this D2H receipt. Freshness is
        // pinned by the zero/readback gate above; status and exact PRDBC are the completion proof.
        Ok(())
    }
}
