//! §8.3 的硬件访问抽象：把设备物理区间映射进来，并只提供**带边界检查的 volatile 访问**。
//!
//! 为什么不暴露 `&mut [u8]`：设备寄存器不是内存，普通读写会被优化、重排或缓存，
//! 而越界写别人的 MMIO 是驱动最难归因的一类现场（§8.3 的对应设计）。

use crate::mm;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwError {
    /// 偏移或长度没对齐到访问宽度
    NotAligned,
    /// 访问落在区间外
    OutOfRange,
    /// 映射本身没成功
    Map(mm::MmError),
}

/// 一个已映射的设备区间。drop 即解映射（MMIO 不是 PMM 发的帧，所以不动页框账）。
pub struct MmioRegion {
    map: mm::MmioMapping,
    len: usize,
}

impl MmioRegion {
    /// 映射 `[pa, pa+len)`。`pa` 必须页对齐（要映射 MMIO  hole 里的东西请自己算整页）。
    pub fn map(pa: u64, len: usize) -> Result<Self, HwError> {
        if len == 0 || (pa % mm::PAGE as u64) != 0 {
            return Err(HwError::NotAligned);
        }
        let pages = (len as u64 + (mm::PAGE as u64 - 1)) / mm::PAGE as u64;
        let map = mm::map_mmio(pa, pages as usize).map_err(HwError::Map)?;
        Ok(Self { map, len })
    }

    pub fn base(&self) -> u64 {
        self.map.virt().0
    }

    /// 调用方可用的窗口长度（不是映射的整页数：越界判据要用它）
    pub fn len(&self) -> usize {
        self.len
    }

    fn check(&self, off: usize, w: usize) -> Result<(), HwError> {
        if off % w != 0 {
            return Err(HwError::NotAligned);
        }
        // 长度是**调用方给的**，所以这条加法必须在 checked 之后才用（同 §10.3 的指针校验）
        if off.checked_add(w).ok_or(HwError::OutOfRange)? > self.len {
            return Err(HwError::OutOfRange);
        }
        Ok(())
    }

    /// SAFETY: `check` 已保证 `off + w <= len`，而 `len` 来自建区时向上取整的整页映射。
    pub fn read8(&self, off: usize) -> Result<u8, HwError> {
        self.check(off, 1)?;
        Ok(unsafe { core::ptr::read_volatile((self.base() + off as u64) as *const u8) })
    }

    pub fn read16(&self, off: usize) -> Result<u16, HwError> {
        self.check(off, 2)?;
        Ok(unsafe { core::ptr::read_volatile((self.base() + off as u64) as *const u16) })
    }

    pub fn read32(&self, off: usize) -> Result<u32, HwError> {
        self.check(off, 4)?;
        Ok(unsafe { core::ptr::read_volatile((self.base() + off as u64) as *const u32) })
    }

    pub fn write16(&self, off: usize, v: u16) -> Result<(), HwError> {
        self.check(off, 2)?;
        // SAFETY: 同上。virtio 的队列通知**只允许 16 位写**（写宽了设备会当两次通知）
        unsafe { core::ptr::write_volatile((self.base() + off as u64) as *mut u16, v) };
        Ok(())
    }

    pub fn write8(&self, off: usize, v: u8) -> Result<(), HwError> {
        self.check(off, 1)?;
        // SAFETY: 同上。`device_status` 是一个字节，用 32 位写会连带改到隔壁的 `queue_select`
        unsafe { core::ptr::write_volatile((self.base() + off as u64) as *mut u8, v) };
        Ok(())
    }

    pub fn write32(&self, off: usize, v: u32) -> Result<(), HwError> {
        self.check(off, 4)?;
        // SAFETY: 同上；设备页是 `PageFlags::DEVICE`（PCD ⇒ UC-），不会被缓存
        unsafe { core::ptr::write_volatile((self.base() + off as u64) as *mut u32, v) };
        Ok(())
    }

    /// S9k（双缓冲）：把一段**已打包**的像素行一次性搬进窗口。帧缓冲是线性内存语义
    /// （不是逐寄存器设备），整行 memcpy 比逐像素 volatile 快一个量级，且一次 present
    /// 只调用它 height 次，把"整帧合成完再上屏"变成可能（单缓冲闪烁的根治）。
    /// SAFETY: `check` 保证 `off + src.len()*4 <= len`；目标是我们映射的帧缓冲窗口，
    /// 源是内核私有 back buffer，两者不重叠；调用方（Frame::present）单核串行。
    pub fn write_slice(&self, off: usize, src: &[u32]) -> Result<(), HwError> {
        let bytes = src.len().checked_mul(4).ok_or(HwError::OutOfRange)?;
        self.check(off, 4)?;
        if off.checked_add(bytes).ok_or(HwError::OutOfRange)? > self.len {
            return Err(HwError::OutOfRange);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), (self.base() + off as u64) as *mut u32, src.len());
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ 端口 I/O
//
// PCI 的 CAM 回退路径要 `in/out`；除此之外内核只用它访问 isa-debug-exit（见 exit.rs 的同一写法）。

pub fn outl(port: u16, v: u32) {
    // SAFETY: 端口写不影响内存，调用方负责端口是对的
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags))
    }
}

pub fn inl(port: u16) -> u32 {
    let v: u32;
    // SAFETY: 同上；端口读没有内存副作用，但**不能**被优化掉，所以标了 nomem 也留着 volatile 语义
    unsafe {
        core::arch::asm!("in eax, dx", in("dx") port, out("eax") v, options(nomem, nostack, preserves_flags))
    }
    v
}
