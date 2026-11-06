//! §8.2 / §8.5：驱动能触达内核的全部途径。
//!
//! 手册里那句"唯一的接口"要有牙齿，句柄就**不能是指针**：这里发出去的是
//! `槽号 + 世代号`，资源本体只活在这张表里。四条硬性质，每条都有用例打
//! （`KT_DRIVER_CTX`），不是写在注释里的承诺：
//!
//! 1. **撤销后旧句柄必须被拒**。槽位会被复用，所以"没拒"不是小事——那等于
//!    拿着上一份资源的钥匙去开这一份资源（世代号不等 ⇒ `StaleHandle`）。
//! 2. **句柄认主人**。表项记着 `ModuleId`，别的模块拿着正确的 `slot+gen` 也用不了。
//! 3. **窗口与对齐由表检查**，不靠驱动自觉（底层就是 §8.3 的 `hw::MmioRegion`）。
//! 4. **建/撤资源不许在中断上下文**（§7.1：那里面不许分配）。
//!
//! DMA 缓冲区**不暴露 `&[u8]` / `&mut [u8]`**：设备随时可能写那块内存，把它当成
//! 一段 Rust 可读写的切片就是语言层面的未定义行为。这里只给带偏移的 volatile
//! 访问器；总线地址（`bus_addr`）是拿去填描述符的整数，解不开引用。
//!
//! 没做的方法：`set_timer`、`log`。接口的方法表要跟着被兑现的能力
//! 一起长——先把没人调的签名摆在这里，就是把手册的目录当成实现（BACKLOG 记着）。
//! `request_irq` 已在 M5-g② 兑现（调用者是 AHCI），所以它出现在下面而不是这里。

use crate::apic;
use crate::hw::{self, HwError, MmioRegion};
use crate::irq;
use crate::mm::{self, Mapping, ModuleId, PageFlags, PAGE};
use crate::pci::Dev;
use core::cell::UnsafeCell;

/// MMIO 句柄槽数。首期只有 AHCI 一个驱动，留 8 格是给"同一份驱动多次映射不同 BAR"
/// 的余量，不是给未来的驱动池。
const MMIO_SLOTS: usize = 8;
/// DMA 句柄槽数（AHCI 首期只占 1 格：环形结构那一整块）
const DMA_SLOTS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverError {
    /// 配置空间里没有这块 BAR，或它不是内存型 BAR
    NoDevice,
    /// 设备侧超时（首期不产生，留给中断/命令等待那一步）
    Timeout,
    /// 一次设备访问失败，不带具体形状
    Io,
    /// 句柄表满了，或页框/VA 不够
    ResourceExhausted,
    /// 这个接口现在还不提供这件事
    Unsupported,
    /// 内部不变量破了
    Internal,
    /// 表里没有这一格（从没发过，或槽号超出表长）
    NoSuchHandle(u16),
    /// 槽号对但世代号不对：资源已撤销，或这一格已经换成了别人的
    StaleHandle { slot: u16, want: u32, have: u32 },
    /// 句柄是发给别的模块的
    NotOwner { slot: u16, owner: ModuleId },
    /// 越界 / 未对齐 / 映射失败，把底层的原始理由带上（压成一个字就没法归因）
    Access(HwError),
    /// 在不许做这件事的上下文里调用（中断里分配）
    WrongContext,
    /// 参数形状不对（长度不是整页、偏移溢出……），理由写成字符串免得靠猜
    Denied(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioHandle {
    slot: u16,
    gen: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaHandle {
    slot: u16,
    gen: u32,
}

/// 中断句柄就是认领表里那个（表在内核，见 `irq.rs` 开头那句"为什么这张表不在驱动里"），
/// 这里只给它一个驱动侧的名字，保持三颗资源的读法一致。
pub type IrqHandle = irq::Handle;

/// 一块已映射的设备窗口 + 它的授权证据
struct MmioEntry {
    gen: u32,
    owner: ModuleId,
    region: MmioRegion,
    /// `enable_command` 置完之后读回来的命令寄存器：授权是**看到的**，不是假设的
    authorized: u16,
}

/// 一段连续物理内存 + 它的 UC 映射。drop 即解映射并把页框还给 PMM（`Mapping` 负责）
struct DmaEntry {
    gen: u32,
    owner: ModuleId,
    map: Mapping,
    bus: u64,
    len: usize,
}

struct Table {
    mmio: [Option<MmioEntry>; MMIO_SLOTS],
    dma: [Option<DmaEntry>; DMA_SLOTS],
    /// 世代号全局递增：撤销后复用同一格也会拿到新的号
    next_gen: u32,
}

impl Table {
    const fn empty() -> Self {
        Self { mmio: [const { None }; MMIO_SLOTS], dma: [const { None }; DMA_SLOTS], next_gen: 1 }
    }

    fn fresh_gen(&mut self) -> u32 {
        let g = self.next_gen;
        self.next_gen = if g + 1 == 0 { 1 } else { g + 1 };
        g
    }

    fn free_mmio_slot(&self) -> Option<usize> {
        self.mmio.iter().position(|e| e.is_none())
    }

    fn free_dma_slot(&self) -> Option<usize> {
        self.dma.iter().position(|e| e.is_none())
    }
}

struct TableCell(UnsafeCell<Table>);
// SAFETY: 与 `pci::TABLE`、`ahci::RING` 同一条理由——这张表只在 BSP 的驱动初始化与
// ktest 序列里写；中断上下文在建表/撤表门口就被 `WrongContext` 挡住，所以没有并发写者。
unsafe impl Sync for TableCell {}
static TABLE: TableCell = TableCell(UnsafeCell::new(Table::empty()));

/// 驱动侧拿到的那个"上下文"。它是**令牌**而不是资源：只带身份（哪个模块、哪台设备）。
#[derive(Clone, Copy, Debug)]
pub struct DriverCtx {
    owner: ModuleId,
    dev: Dev,
}

fn check_m(e: &MmioEntry, slot: u16, gen: u32, owner: ModuleId) -> Result<(), DriverError> {
    if e.gen != gen {
        return Err(DriverError::StaleHandle { slot, want: gen, have: e.gen });
    }
    if e.owner != owner {
        return Err(DriverError::NotOwner { slot, owner: e.owner });
    }
    Ok(())
}

fn check_d(e: &DmaEntry, slot: u16, gen: u32, owner: ModuleId) -> Result<(), DriverError> {
    if e.gen != gen {
        return Err(DriverError::StaleHandle { slot, want: gen, have: e.gen });
    }
    if e.owner != owner {
        return Err(DriverError::NotOwner { slot, owner: e.owner });
    }
    Ok(())
}

impl DriverCtx {
    pub fn for_device(owner: ModuleId, dev: Dev) -> Self {
        Self { owner, dev }
    }

    pub fn owner(&self) -> ModuleId {
        self.owner
    }

    pub fn device(&self) -> Dev {
        self.dev
    }

    // ---------------------------------------------------------------- MMIO

    /// 映射一块内存型 BAR：自己量尺寸、自己开 `MSE|BME` 并把读回来的命令寄存器一起
    /// 存进表里。驱动侧从头到尾没有拿到物理地址，也没有拿到指针。
    pub fn map_mmio(&self, bar: u8) -> Result<MmioHandle, DriverError> {
        if apic::in_isr() {
            return Err(DriverError::WrongContext);
        }
        let bs = self.dev.size_mem_bar(u32::from(bar));
        if !bs.restored {
            return Err(DriverError::Denied("尺寸探测后 BAR 没能还原"));
        }
        if bs.size == 0 {
            return Err(DriverError::NoDevice);
        }
        let (raw, _is64) = self.dev.mem_bar(u32::from(bar)).ok_or(DriverError::NoDevice)?;
        // bit1 = Memory Space Enable，bit2 = Bus Master Enable。不开 MSE 寄存器读回来全 1，
        // 不开 BME 的 DMA 方向永远不会动——所以这两位是映射的前置条件，不是可选项。
        let cmd = self.dev.enable_command(0b110);
        if cmd & 0b110 != 0b110 {
            return Err(DriverError::Denied("命令寄存器没接受 MSE|BME"));
        }
        let region = MmioRegion::map(raw & !0xFFF, bs.size as usize).map_err(DriverError::Access)?;
        // SAFETY: 见 TableCell
        let t = unsafe { &mut *TABLE.0.get() };
        let slot = t.free_mmio_slot().ok_or(DriverError::ResourceExhausted)?;
        let gen = t.fresh_gen();
        t.mmio[slot] = Some(MmioEntry { gen, owner: self.owner, region, authorized: cmd as u16 });
        Ok(MmioHandle { slot: slot as u16, gen })
    }

    fn mmio_of<'a>(h: MmioHandle, owner: ModuleId) -> Result<&'a MmioEntry, DriverError> {
        let i = usize::from(h.slot);
        if i >= MMIO_SLOTS {
            return Err(DriverError::NoSuchHandle(h.slot));
        }
        // SAFETY: 见 TableCell。只读路径，世代号与主人两道都对上才给引用
        let e = unsafe { &*TABLE.0.get() }.mmio[i].as_ref().ok_or(DriverError::NoSuchHandle(h.slot))?;
        check_m(e, h.slot, h.gen, owner)?;
        Ok(e)
    }

    /// 句柄背后那块窗口有多大（用例据此确认"越界"那条判据用的偏移确实在窗口外）
    pub fn mmio_len(&self, h: MmioHandle) -> Result<usize, DriverError> {
        Ok(Self::mmio_of(h, self.owner)?.region.len())
    }

    /// 映射时 `MSE|BME` 读回来的命令寄存器值
    pub fn mmio_authorized(&self, h: MmioHandle) -> Result<u16, DriverError> {
        Ok(Self::mmio_of(h, self.owner)?.authorized)
    }

    pub fn read32(&self, h: MmioHandle, off: usize) -> Result<u32, DriverError> {
        Self::mmio_of(h, self.owner)?.region.read32(off).map_err(DriverError::Access)
    }

    pub fn write32(&self, h: MmioHandle, off: usize, v: u32) -> Result<(), DriverError> {
        Self::mmio_of(h, self.owner)?.region.write32(off, v).map_err(DriverError::Access)
    }

    pub fn read8(&self, h: MmioHandle, off: usize) -> Result<u8, DriverError> {
        Self::mmio_of(h, self.owner)?.region.read8(off).map_err(DriverError::Access)
    }

    pub fn read16(&self, h: MmioHandle, off: usize) -> Result<u16, DriverError> {
        Self::mmio_of(h, self.owner)?.region.read16(off).map_err(DriverError::Access)
    }

    pub fn write8(&self, h: MmioHandle, off: usize, v: u8) -> Result<(), DriverError> {
        Self::mmio_of(h, self.owner)?.region.write8(off, v).map_err(DriverError::Access)
    }

    pub fn write16(&self, h: MmioHandle, off: usize, v: u16) -> Result<(), DriverError> {
        Self::mmio_of(h, self.owner)?.region.write16(off, v).map_err(DriverError::Access)
    }

    /// 撤销：解映射并放手 VA 保留（都在 `MmioRegion`/`MmioMapping` 的 `Drop` 里）。
    /// 这一格从此空出来，可以发给下一次 `map_mmio`，而旧句柄因世代号变化必然被拒。
    pub fn release_mmio(&self, h: MmioHandle) -> Result<(), DriverError> {
        let i = usize::from(h.slot);
        if i >= MMIO_SLOTS {
            return Err(DriverError::NoSuchHandle(h.slot));
        }
        // 先检查再摘走：检查不过的时候表必须一点没动
        Self::mmio_of(h, self.owner)?;
        // SAFETY: 见 TableCell
        match unsafe { &mut *TABLE.0.get() }.mmio[i].take() {
            Some(_) => Ok(()),
            None => Err(DriverError::NoSuchHandle(h.slot)),
        }
    }

    // ----------------------------------------------------------------- DMA

    /// 申请一段**连续物理内存**并映射成 Uncacheable。`len` 必须是整页的非零倍数：
    /// 页框分配按 2 的幂走，而把"向上取整"藏在接口里会让调用方以为自己拿到了
    /// 请求的那个长度（对齐、边界、回收三处都会跟着错）。
    pub fn alloc_dma(&self, len: usize) -> Result<DmaHandle, DriverError> {
        if apic::in_isr() {
            return Err(DriverError::WrongContext);
        }
        if len == 0 || len % PAGE != 0 {
            return Err(DriverError::Denied("长度必须是整页的非零倍数"));
        }
        let order = (len / PAGE).ilog2();
        let order = u8::try_from(order).map_err(|_| DriverError::Denied("跨度过大"))?;
        let frames = mm::phys_alloc(order, self.owner).map_err(|_| DriverError::ResourceExhausted)?;
        let bus = frames.base().0;
        let n = frames.count();
        let va = match mm::alloc_va_range(n) {
            Some(v) => v,
            None => return Err(DriverError::ResourceExhausted),
        };
        let map = match mm::map(va, frames, PageFlags::DEVICE) {
            Ok(m) => m,
            // 映射失败时 `OwnedFrames` 已经被消费掉，它自己的 `Drop` 会把页框还回去；
            // 但那次 VA 保留没人放手，所以这里必须自己还，否则反复失败会吃光登记表
            // （`L4: VA 保留登记表已满` 那个形状在 M4-2 就出现过一次）。
            Err(e) => {
                mm::release_va(va.0);
                return Err(DriverError::Access(hw::HwError::Map(e)));
            }
        };
        // SAFETY: 见 TableCell
        let t = unsafe { &mut *TABLE.0.get() };
        let slot = t.free_dma_slot().ok_or(DriverError::ResourceExhausted)?;
        let gen = t.fresh_gen();
        t.dma[slot] = Some(DmaEntry { gen, owner: self.owner, map, bus, len });
        Ok(DmaHandle { slot: slot as u16, gen })
    }

    fn dma_of<'a>(h: DmaHandle, owner: ModuleId) -> Result<&'a DmaEntry, DriverError> {
        let i = usize::from(h.slot);
        if i >= DMA_SLOTS {
            return Err(DriverError::NoSuchHandle(h.slot));
        }
        // SAFETY: 见 TableCell
        let e = unsafe { &*TABLE.0.get() }.dma[i].as_ref().ok_or(DriverError::NoSuchHandle(h.slot))?;
        check_d(e, h.slot, h.gen, owner)?;
        Ok(e)
    }

    /// 给描述符用的总线地址。它是个整数：填进 `PxCLB`/PRDT 可以，解引用不行。
    pub fn bus_addr(&self, h: DmaHandle) -> Result<u64, DriverError> {
        Ok(Self::dma_of(h, self.owner)?.bus)
    }

    pub fn dma_len(&self, h: DmaHandle) -> Result<usize, DriverError> {
        Ok(Self::dma_of(h, self.owner)?.len)
    }

    /// 偏移窗口检查集中在这一个函数里（每个访问器各写一份就会有某一份漏写）
    fn at(e: &DmaEntry, off: usize, w: usize) -> Result<u64, DriverError> {
        let n = usize::try_from(w).map_err(|_| DriverError::Denied("长度溢出"))?;
        if off.checked_add(n).ok_or(DriverError::Denied("偏移溢出"))? > e.len {
            return Err(DriverError::Denied("偏移落在缓冲区外"));
        }
        Ok(e.map.virt().0 + off as u64)
    }

    pub fn dma_read8(&self, h: DmaHandle, off: usize) -> Result<u8, DriverError> {
        let e = Self::dma_of(h, self.owner)?;
        let at = Self::at(e, off, 1)?;
        // SAFETY: `at` 由 `at()` 保证在 `[virt, virt+len)` 内；这块是 PCD（UC）内存，
        // 必须 volatile 访问，否则会把设备写进来的新值读成缓存里的旧值
        Ok(unsafe { core::ptr::read_volatile(at as *const u8) })
    }

    pub fn dma_read32(&self, h: DmaHandle, off: usize) -> Result<u32, DriverError> {
        if off % 4 != 0 {
            return Err(DriverError::Access(HwError::NotAligned));
        }
        let e = Self::dma_of(h, self.owner)?;
        let at = Self::at(e, off, 4)?;
        Ok(unsafe { core::ptr::read_volatile(at as *const u32) })
    }

    pub fn dma_read16(&self, h: DmaHandle, off: usize) -> Result<u16, DriverError> {
        if off % 2 != 0 {
            return Err(DriverError::Access(HwError::NotAligned));
        }
        let e = Self::dma_of(h, self.owner)?;
        let at = Self::at(e, off, 2)?;
        // SAFETY: 同上，加上"偏移已验 2 字节对齐"；PCIe 配置/描述符环里一半的字段是 u16，
        //        没有这一条就只能拆成两次字节访问（那会把一次拆成两次之间被设备改写的窗口）。
        Ok(unsafe { core::ptr::read_volatile(at as *const u16) })
    }

    pub fn dma_write8(&self, h: DmaHandle, off: usize, v: u8) -> Result<(), DriverError> {
        let e = Self::dma_of(h, self.owner)?;
        let at = Self::at(e, off, 1)?;
        Ok(unsafe { core::ptr::write_volatile(at as *mut u8, v) })
    }

    pub fn dma_write16(&self, h: DmaHandle, off: usize, v: u16) -> Result<(), DriverError> {
        if off % 2 != 0 {
            return Err(DriverError::Access(HwError::NotAligned));
        }
        let e = Self::dma_of(h, self.owner)?;
        let at = Self::at(e, off, 2)?;
        // SAFETY: 同 `dma_read16`
        Ok(unsafe { core::ptr::write_volatile(at as *mut u16, v) })
    }

    pub fn dma_write32(&self, h: DmaHandle, off: usize, v: u32) -> Result<(), DriverError> {
        if off % 4 != 0 {
            return Err(DriverError::Access(HwError::NotAligned));
        }
        let e = Self::dma_of(h, self.owner)?;
        let at = Self::at(e, off, 4)?;
        Ok(unsafe { core::ptr::write_volatile(at as *mut u32, v) })
    }

    /// 填一段。设备缓冲区不交出切片，所以填内容只能走这里。
    /// 把一段任意字节写进设备缓冲区：与 `dma_copy_out` 对称，边界只检查一次。
    /// 没有它，调用方只能用 `dma_write8` 一字节一字节地填（那会把一次越界检查摊成 512 次，
    /// 而且中间的字节写失败时缓冲里留下的是"半张图"，看不出来）。
    pub fn dma_copy_in(&self, h: DmaHandle, off: usize, src: &[u8]) -> Result<(), DriverError> {
        let e = Self::dma_of(h, self.owner)?;
        Self::at(e, off, src.len())?;
        for (i, b) in src.iter().enumerate() {
            let at = e.map.virt().0 + off as u64 + i as u64;
            // SAFETY: 上面的 `at()` 已经保证 `[off, off+len)` 整段落在缓冲区里，
            //        所以这里的逐字节写不可能越出那块 PCD 区间
            unsafe { core::ptr::write_volatile(at as *mut u8, *b) };
        }
        Ok(())
    }

    pub fn dma_fill(&self, h: DmaHandle, off: usize, pat: u8, n: usize) -> Result<(), DriverError> {
        let e = Self::dma_of(h, self.owner)?;
        let at = Self::at(e, off, n)?;
        Ok(unsafe { core::ptr::write_bytes(at as *mut u8, pat, n) })
    }

    /// 读回一段到调用方给的普通切片：这一刻起内容归调用方，而设备随时可写的那块内存
    /// 本身不逃逸出这张表。
    pub fn dma_copy_out(&self, h: DmaHandle, off: usize, out: &mut [u8]) -> Result<(), DriverError> {
        let e = Self::dma_of(h, self.owner)?;
        let at = Self::at(e, off, out.len())?;
        for (i, o) in out.iter_mut().enumerate() {
            *o = unsafe { core::ptr::read_volatile((at + i as u64) as *const u8) };
        }
        Ok(())
    }

    /// 撤销：解映射并把页框还给 PMM（`Mapping` 的 `Drop` 干这两件事，台账跟着减）。
    pub fn release_dma(&self, h: DmaHandle) -> Result<(), DriverError> {
        let i = usize::from(h.slot);
        if i >= DMA_SLOTS {
            return Err(DriverError::NoSuchHandle(h.slot));
        }
        Self::dma_of(h, self.owner)?;
        // SAFETY: 见 TableCell
        match unsafe { &mut *TABLE.0.get() }.dma[i].take() {
            Some(_) => Ok(()),
            None => Err(DriverError::NoSuchHandle(h.slot)),
        }
    }

    /// 认领一颗外部中断：向量由核内分配，处理函数由驱动给。规矩与 `map_mmio`/`alloc_dma`
    /// 同一条——**中断上下文里不许建**（`WrongContext`）。
    /// 驱动拿到的是句柄，向量只是句柄上一个可以打印的数：分到了不等于那格归它，
    /// 归它是由表里的 `owner` 说的。
    pub fn request_irq(&self, handler: fn() -> bool) -> Result<IrqHandle, DriverError> {
        irq::request(self.owner, handler).map_err(DriverCtx::irq_err)
    }

    /// 这颗中断要往设备的 MSI 结构里写的三个 DWORD（低地址 / 高地址 / 数据）。
    /// 为什么由核内算而不是驱动自己拼：位数算错的失败形状是"一个中断都不来"，
    /// 而不是任何错误码——所以这件事不能有第二个实现散在驱动里。
    /// 写下去之后**必须读回来对账**（判据在 `KT_IRQ_AHCI` 第一格）。
    pub fn irq_message(&self, h: IrqHandle) -> Result<(u32, u32, u32), DriverError> {
        let m = irq::message(h, self.owner).map_err(DriverCtx::irq_err)?;
        Ok((m.addr_lo, m.addr_hi, m.data))
    }

    /// 这颗中断的两次计数：`(到过处理函数手里的发数, 它认领了的发数)`。
    /// 分成两本账是同一条规矩：只有一个数的话，"来了但它说不是我的"与"根本没来"读起来一样。
    pub fn irq_counts(&self, h: IrqHandle) -> Result<(usize, usize), DriverError> {
        irq::counts(h, self.owner).map_err(DriverCtx::irq_err)
    }

    /// L3-B：换目的地，并把核内**重算出来的那条消息**交回给驱动去编程。
    /// 返回值不是装饰：只有驱动把它写进设备，"表里说的"与"设备发的"才是同一颗 CPU。
    pub fn irq_set_affinity(&self, h: IrqHandle, lapic_id: u8) -> Result<irq::Msg, DriverError> {
        irq::set_affinity(h, self.owner, lapic_id).map_err(Self::irq_err)
    }

    /// 这颗中断现在的目的地（本地 APIC id）。判据拿它与"按 CPU 的投递分布"对账。
    pub fn irq_dest(&self, h: IrqHandle) -> Result<u8, DriverError> {
        irq::dest(h, self.owner).map_err(Self::irq_err)
    }

    /// 撤销认领。**不动设备**：MSI 的 enable 位是驱动自己开的，也就该由它自己关——
    /// 表里删掉一格而设备还在朝那个向量写，等于把一发中断扔进没人认领的账里。
    pub fn release_irq(&self, h: IrqHandle) -> Result<(), DriverError> {
        irq::release(self.owner, h).map_err(DriverCtx::irq_err)
    }

    /// 认领表的错误压回驱动侧那套拒绝形状：不改种类，只换外壳
    fn irq_err(e: irq::IrqError) -> DriverError {
        match e {
            irq::IrqError::Exhausted => DriverError::ResourceExhausted,
            irq::IrqError::WrongContext => DriverError::WrongContext,
            irq::IrqError::NoApic => DriverError::Denied("本地 APIC 还没初始化"),
            irq::IrqError::NoSuchHandle(s) => DriverError::NoSuchHandle(s),
            irq::IrqError::StaleHandle { slot, want, have } => DriverError::StaleHandle { slot, want, have },
            irq::IrqError::NotOwner { slot, owner } => DriverError::NotOwner { slot, owner },
            irq::IrqError::NoSuchCpu(_) => DriverError::Denied("目的地这个 APIC id 不在登记表里"),
            irq::IrqError::Offline(_) => DriverError::Denied("目的地那颗 CPU 还没上线"),
        }
    }
}

/// 表里当前占着几格 MMIO / DMA。用例用它证明"撤销真的把资源还回来了"，
/// 而不是只看返回值好不好看。
pub fn occupancy() -> (usize, usize) {
    // SAFETY: 见 TableCell，只读
    let t = unsafe { &*TABLE.0.get() };
    (t.mmio.iter().filter(|e| e.is_some()).count(), t.dma.iter().filter(|e| e.is_some()).count())
}

/// 只给用例用的后门：造一个"看起来像那么回事"的句柄（错的世代号、别人的槽号），
/// 判据才有得打。真实驱动代码不许调用，所以它们不在 `DriverCtx` 上。
pub const fn mmio_handle_at(slot: u16, gen: u32) -> MmioHandle {
    MmioHandle { slot, gen }
}

pub const fn dma_handle_at(slot: u16, gen: u32) -> DmaHandle {
    DmaHandle { slot, gen }
}

/// 句柄里的槽号（判据"撤销后复用同一格"要用它）
pub const fn mmio_slot(h: MmioHandle) -> u16 {
    h.slot
}

pub const fn mmio_gen(h: MmioHandle) -> u32 {
    h.gen
}

pub const fn dma_slot(h: DmaHandle) -> u16 {
    h.slot
}

/// 表里第 `slot` 格 MMIO 现在的世代号（空着就返回 `None`）。
/// 用例用它确认"撤销后复用同一格"真的发生了——不然 `StaleHandle` 可能只是因为
/// 那一格干脆空着，两种情形得分开。
pub fn mmio_gen_at(slot: u16) -> Option<u32> {
    // SAFETY: 见 TableCell，只读
    unsafe { &*TABLE.0.get() }.mmio[usize::from(slot)].as_ref().map(|e| e.gen)
}
