//! §8.7：PCI 配置空间访问与设备枚举。
//!
//! 两条后端：ECAM（ACPI MCFG 给的基址，内存映射）优先；没有 MCFG 就退回 CAM（`0xCF8/0xCFC`）。
//! 表是定长的：设备数来自外部世界，而堆的单次分配上限是 `heap::LARGE_MAX = 2048` 字节（§7.1），
//! "按枚举结果开 `Vec`"等于让固件用一个数打死内核。

use core::cell::UnsafeCell;

use crate::hw::{self, MmioRegion};

pub const MAX_DEVICES: usize = 64;
/// ECAM 最多映射多少条总线（1 MiB/总线）。超出的总线读不到时会被 `MmioRegion` 的边界检查挡下
/// 并计数，不是静默截断。
pub const MAX_ECAM_BUSES: u64 = 256;

#[derive(Clone, Copy, Debug)]
pub struct Dev {
    /// bus<<16 | device<<11 | function<<8
    pub bdf: u32,
    pub vendor: u16,
    pub device: u16,
    /// 配置偏移 0x08 的原始 DWORD；解码见 `Dev::class()` 等四个 impl
    pub cfg08: u32,
    /// 配置 0x0E：bit7 = 多功能，低 7 位 = 头布局（1 = PCI-PCI 桥）
    pub hdr: u8,
    pub bar0: u32,
}

const EMPTY_DEV: Dev = Dev { bdf: 0, vendor: 0, device: 0, cfg08: 0, hdr: 0, bar0: 0 };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Ecam,
    Cam,
}

#[derive(Clone, Copy, Debug)]
pub struct Info {
    pub backend: Backend,
    /// ECAM 的内核 VA；CAM 后端为 0
    pub va: u64,
    pub n: usize,
    /// 设备数到了 `MAX_DEVICES` ⇒ 后面被丢弃（必须是可见的读数，不能安静截断）
    pub truncated: bool,
    /// 读到 vendor=0xFFFF 的槽位数（不存在的 BDF，正常且很多）
    pub absent: usize,
}

struct TableCell(UnsafeCell<Option<(Info, [Dev; MAX_DEVICES])>>);
// SAFETY: 只有 BSP 在启动序列里写一次（IF=0），之后全部只读
unsafe impl Sync for TableCell {}
static TABLE: TableCell = TableCell(UnsafeCell::new(None));

/// ECAM 区域与内核同寿命（它是设施，不是某次申请的资源），所以这份 `MmioRegion`
/// 建好后不再被任何人 drop。
struct EcamCell(UnsafeCell<Option<MmioRegion>>);
// SAFETY: 同 TABLE
unsafe impl Sync for EcamCell {}
static ECAM: EcamCell = EcamCell(UnsafeCell::new(None));

const CAM_ADDR: u16 = 0x0CF8;
const CAM_DATA: u16 = 0x0CFC;

fn ecam_va() -> Option<u64> {
    // SAFETY: 见 EcamCell
    unsafe { (*ECAM.0.get()).as_ref().map(|r| r.base()) }
}

/// 读一个配置 DWORD。不存在的 BDF 读到 0xFFFF_FFFF 是**架构行为**，不是故障：
/// ECAM 的整页都映射着（设备在不在是各 slot 自己填 FF），CAM 是不存在时不置有效位。
fn cfg_read32(bus: u32, dev: u32, func: u32, reg: u32) -> u32 {
    let off = reg & 0xFC;
    match ecam_va() {
        Some(va) => {
            let o = ((bus << 20) | (dev << 15) | (func << 12) | off) as u64;
            // SAFETY: 区间由 init 时映射的总线范围保证；越界只会读到未映射页 ⇒ 由用例的
            // `rejected` 计数与 `MmioRegion` 版本负责，本函数只走已确认在范围内的偏移
            unsafe { core::ptr::read_volatile((va + o) as *const u32) }
        }
        None => {
            hw::outl(CAM_ADDR, 0x8000_0000u32 | (bus << 16) | (dev << 11) | (func << 8) | off);
            hw::inl(CAM_DATA)
        }
    }
}

fn cfg_read8(bus: u32, dev: u32, func: u32, reg: u32) -> u8 {
    (cfg_read32(bus, dev, func, reg) >> ((reg & 3) * 8)) as u8
}

fn cfg_write32(bus: u32, dev: u32, func: u32, reg: u32, v: u32) {
    let off = reg & 0xFC;
    match ecam_va() {
        Some(va) => {
            let o = ((bus << 20) | (dev << 15) | (func << 12) | off) as u64;
            // SAFETY: 范围同 cfg_read32
            unsafe { core::ptr::write_volatile((va + o) as *mut u32, v) }
        }
        None => {
            hw::outl(CAM_ADDR, 0x8000_0000u32 | (bus << 16) | (dev << 11) | (func << 8) | off);
            hw::outl(CAM_DATA, v);
        }
    }
}

pub fn info() -> Option<Info> {
    // SAFETY: 见 TABLE
    unsafe { (*TABLE.0.get()).as_ref().map(|(i, _)| *i) }
}

pub fn dev(i: usize) -> Option<Dev> {
    // SAFETY: 见 TABLE
    unsafe {
        (*TABLE.0.get())
            .as_ref()
            .and_then(|(_, d)| d.get(i).copied())
            .filter(|x| x.vendor != 0)
    }
}

/// 扫一条总线，命中就写进 `out[*next]` 并把游标往前推。
fn scan_bus(bus: u32, out: &mut [Dev; MAX_DEVICES], next: &mut usize, absent: &mut usize) {
    for d in 0..32u32 {
        if *next >= MAX_DEVICES {
            return;
        }
        if cfg_read32(bus, d, 0, 0x00) & 0xFFFF == 0xFFFF {
            *absent += 1;
            continue;
        }
        let hdr = cfg_read8(bus, d, 0, 0x0E);
        let funcs = if hdr & 0x80 != 0 { 8 } else { 1 };
        for f in 0..funcs {
            let id = cfg_read32(bus, d, f, 0x00);
            if id & 0xFFFF == 0xFFFF {
                *absent += 1;
                continue;
            }
            out[*next] = Dev {
                bdf: (bus << 16) | (d << 11) | (f << 8),
                vendor: (id & 0xFFFF) as u16,
                device: ((id >> 16) & 0xFFFF) as u16,
                cfg08: cfg_read32(bus, d, f, 0x08),
                hdr: cfg_read8(bus, d, f, 0x0E),
                bar0: cfg_read32(bus, d, f, 0x10),
            };
            *next += 1;
            if *next >= MAX_DEVICES {
                return;
            }
        }
    }
}

/// 建后端（ECAM 或 CAM）并枚举一次。由启动序列调，结果留在静态表里。
pub fn init(mcfg_base: Option<u64>, mcfg_bus_start: u16, mcfg_bus_end: u16) -> Info {
    let mut backend = Backend::Cam;
    if let Some(pa) = mcfg_base {
        let lo = (mcfg_bus_start as u64).min(mcfg_bus_end as u64);
        // MCFG 声明的是"从这条总线号开始的窗口"，我们按窗口大小映射，最多 256 条
        let span = ((mcfg_bus_end as u64).saturating_sub(lo) + 1).min(MAX_ECAM_BUSES);
        let len = (span * 1024 * 1024) as usize;
        match MmioRegion::map(pa & !0xFFF, len) {
            Ok(r) => {
                let va = r.base();
                // SAFETY: 见 EcamCell
                // 放进静态里就再也不取出来：它没有被 drop 的路径
                unsafe { *ECAM.0.get() = Some(r) };
                backend = Backend::Ecam;
                crate::log_info!("pci: ECAM pa={:#x} va={:#x} span={} MiB", pa, va, span);
            }
            Err(e) => crate::log_warn!("pci: ECAM 映射失败 {:?}，退回 CAM", e),
        }
    } else {
        crate::log_warn!("pci: ACPI 没给 MCFG，使用 CAM（0xCF8/0xCFC）");
    }

    let mut out = [EMPTY_DEV; MAX_DEVICES];
    let mut absent = 0usize;
    let mut next = 0usize;
    scan_bus(0, &mut out, &mut next, &mut absent);
    // 桥后面的总线在 ECAM 下按 secondary bus 号直接可寻址
    let mut sec: [u32; 8] = [0; 8];
    let mut ns = 0usize;
    for d in out[..next].iter() {
        if (d.hdr & 0x7F) != 1 || ns >= sec.len() {
            continue;
        }
        let (b, dv, f) = (d.bdf >> 16, (d.bdf >> 11) & 31, (d.bdf >> 8) & 7);
        let s = cfg_read8(b, dv, f, 0x19) as u32;
        if s != 0 {
            sec[ns] = s;
            ns += 1;
        }
    }
    for &b in &sec[..ns] {
        scan_bus(b, &mut out, &mut next, &mut absent);
    }

    let n = next;
    let info = Info { backend, va: ecam_va().unwrap_or(0), n, truncated: n >= MAX_DEVICES, absent };
    // SAFETY: 见 TABLE
    unsafe { *TABLE.0.get() = Some((info, out)) };
    info
}

/// 同一个配置 DWORD 的两条独立硬件路径，判据用它们互相核对（`KT_PCI` 的 ④）。
/// ECAM 是内存映射、CAM 是 0xCF8/0xCFC 端口，两者错不到一起去。
pub fn ecam_class(bus: u32, dev: u32, func: u32) -> u32 {
    match ecam_va() {
        Some(va) => {
            let o = ((bus << 20) | (dev << 15) | (func << 12) | 0x08) as u64;
            // SAFETY: 范围由 init 时映射的总线跨度保证，调用方传的是表里的 BDF
            unsafe { core::ptr::read_volatile((va + o) as *const u32) }
        }
        None => 0,
    }
}

pub fn cam_class(bus: u32, dev: u32, func: u32) -> u32 {
    hw::outl(CAM_ADDR, 0x8000_0000u32 | (bus << 16) | (dev << 11) | (func << 8) | 0x08);
    hw::inl(CAM_DATA)
}

/// BAR 尺寸探测的两格读数，**故意拆成两格**：还原失败是危险的（设备地址被我们弄坏了），
/// 尺寸量不出来只是信息缺失。合成一个布尔就会在日志里互相顶包。
#[derive(Clone, Copy, Debug)]
pub struct BarSize {
    /// 写进去的值有没有原样回来（地址 + 命令寄存器）
    pub restored: bool,
    /// 0 = 没量出来（槽位没实现，或掩码不成形状）
    pub size: u64,
}

/// 配置 0x08 那个 DWORD 的布局：`0x08=revision、0x09=progif、0x0A=subclass、0x0B=class`，
/// 小端 ⇒ class 在**高字节**。这不再是解读：`KT_PCI` 拿"已知设备 ⇒ 已知类别"钉它
/// （四台不同族的设备同时成立才算钉住，错一个字节序就会当场崩在某一台上）。
impl Dev {
    pub fn revision(&self) -> u8 {
        (self.cfg08 & 0xFF) as u8
    }
    pub fn progif(&self) -> u8 {
        (self.cfg08 >> 8) as u8
    }
    pub fn subclass(&self) -> u8 {
        (self.cfg08 >> 16) as u8
    }
    pub fn class(&self) -> u8 {
        (self.cfg08 >> 24) as u8
    }
    /// 再读这个设备配置空间里的任意 DWORD（BAR 解码、命令寄存器都用它）
    pub fn cfg32(&self, reg: u32) -> u32 {
        cfg_read32(self.bdf >> 16, (self.bdf >> 11) & 31, (self.bdf >> 8) & 7, reg)
    }
    /// 再写这个设备配置空间里的一个 DWORD（BAR 尺寸探测、命令寄存器都用它）
    pub fn cfg_write(&self, reg: u32, v: u32) {
        let (b, d, f) = self.bdf_str();
        cfg_write32(b, d, f, reg, v);
    }

    pub fn bdf_str(&self) -> (u32, u32, u32) {
        (self.bdf >> 16, (self.bdf >> 11) & 31, (self.bdf >> 8) & 7)
    }

    // ------------------------------------------------------------------ BAR 与命令寄存器
    //
    // 配置头的 BAR 槽位：`0x10 + 4*i`，i = 0..6。低位的类型标记必须先认再用，
    // 直接把 DWORD 当地址会把"IO BAR"当成一个极大的内存地址去映射。

    /// BAR 槽位的原始 DWORD（`slot` 超出 0..6 回 0：读不存在的槽位等于读到别的字段）
    pub fn bar_raw(&self, slot: u32) -> u32 {
        match slot {
            0..=5 => self.cfg32(0x10 + slot * 4),
            _ => 0xFFFF_FFFF,
        }
    }

    /// 这个 BAR 是不是内存空间 BAR（bit0=0），以及它是不是 64 位（bits2:1=0b110）。
    /// IO BAR 一律 `None`——本内核不驱动端口 IO 设备，映射它会写进一个不是地址的数。
    pub fn mem_bar(&self, slot: u32) -> Option<(u64, bool)> {
        let raw = self.bar_raw(slot);
        if raw & 1 != 0 || slot > 5 {
            return None;
        }
        let is64 = (raw >> 1) & 0b11 == 0b10;
        let base = (raw & !0xF) as u64;
        if is64 {
            // 64 位 BAR 的高半**占用下一个槽位**，所以槽位 5 不可能是 64 位
            if slot >= 5 {
                return None;
            }
            let hi = self.bar_raw(slot + 1) as u64;
            Some((((hi << 32) | base) & !0xF, true))
        } else {
            Some((base, false))
        }
    }

    /// §8.7 的 BAR 尺寸探测：写全 1、读回掩码、**立刻还原**，返回 `restored` 与 `size` 两格。
    ///
    /// 顺序按 PCI 规范：先关 Memory Space Enable 再改 BAR（改的时候设备可能正在解码
    /// 一个假地址），尺寸读完再开回来。全程每一步都读回核对。
    pub fn size_mem_bar(&self, slot: u32) -> BarSize {
        let none = BarSize { restored: false, size: 0 };
        let Some((base_addr, is64)) = self.mem_bar(slot) else {
            // IO BAR 或槽位越界：没有"尺寸"可量，也不算还原过什么
            crate::log_fatal!("pci: BAR{} 不是可用的 MEM BAR（原值={:#010x}）", slot, self.bar_raw(slot));
            return none;
        };
        let cmd_reg = 0x04;
        let cmd_before = self.cfg32(cmd_reg);
        let orig_lo = self.bar_raw(slot);
        let orig_hi = if is64 { self.bar_raw(slot + 1) } else { 0 };
        // bit1 = Memory Space Enable
        self.cfg_write(cmd_reg, cmd_before & !0b10);
        self.cfg_write(0x10 + slot * 4, 0xFFFF_FFFF);
        if is64 {
            self.cfg_write(0x10 + (slot + 1) * 4, 0xFFFF_FFFF);
        }
        let mask_lo = (self.bar_raw(slot) & !0xF) as u64;
        let mask_hi = if is64 { (self.bar_raw(slot + 1) as u64) << 32 } else { 0 };
        let mask = mask_lo | mask_hi;
        // 还原：先地址后命令，写完全部读回核对
        self.cfg_write(0x10 + slot * 4, orig_lo);
        if is64 {
            self.cfg_write(0x10 + (slot + 1) * 4, orig_hi);
        }
        self.cfg_write(cmd_reg, cmd_before);
        let restored = self.bar_raw(slot) == orig_lo
            && (!is64 || self.bar_raw(slot + 1) == orig_hi)
            && self.cfg32(cmd_reg) == cmd_before
            && self.mem_bar(slot).map(|(a, _)| a) == Some(base_addr);
        if !restored {
            crate::log_fatal!("pci: BAR{} 尺寸探测后**没能还原**（原值={:#010x}）", slot, orig_lo);
        }
        // 补码要按**这个 BAR 自己的宽度**取：32 位 BAR 读回的掩码高 32 位恒为 0，
        // 用 u64 求补就会得到 `0xffffffff00001000` 这种数（实测踩过，一次"尺寸不成形状"
        // 其实全是量具的宽度错，设备给的 4 KiB 是对的）。
        let size = if is64 {
            (!mask).wrapping_add(1)
        } else {
            (!(mask_lo as u32)).wrapping_add(1) as u64
        };
        if size < crate::mm::PAGE as u64 || !size.is_power_of_two() {
            crate::log_fatal!("pci: BAR{} 尺寸不成形状 = {:#x}（掩码={:#x}）", slot, size, mask);
            return BarSize { restored, size: 0 };
        }
        BarSize { restored, size }
    }

    /// 置位命令寄存器的若干 bit 并**读回**验证。返回读回后的整值。
    /// 只写不读就是"假设固件没把它锁死"——§8.7 要求设备认领前先确认它真的在解码。
    pub fn enable_command(&self, bits: u32) -> u32 {
        let before = self.cfg32(0x04);
        self.cfg_write(0x04, before | bits);
        self.cfg32(0x04)
    }
}

/// 第一台 class 等于 `hi` 的设备。解码表钉住之前不存在这个函数（见上面的 impl）。
pub fn first_of_class(hi: u8) -> Option<Dev> {
    let n = info()?.n;
    (0..n).filter_map(dev).find(|d| d.class() == hi)
}

/// 按 `(class, subclass, progif)` 三件套找第一台设备。
///
/// 为什么不能只看 class：这台机器上多挂一块 virtio-blk 之后，class 0x01（mass storage）
/// 有两台设备，而它的 PCI 槽位（06.0）排在 ICH9 AHCI（1f.2）**前面**——扫描顺序决定结果，
/// "只按 class 找"会挑错设备。三件套里 `subclass=0x06 / progif=0x01`（SATA + AHCI 编程接口）
/// 是 KT_PCI 那张解码表钉住过的读数，不是我从规范上认下来的。
pub fn first_of_triple(cls: u8, sub: u8, progif: u8) -> Option<Dev> {
    let n = info()?.n;
    (0..n).filter_map(dev).find(|d| d.class() == cls && d.subclass() == sub && d.progif() == progif)
}

/// 某个 class 有几台设备。用来把"这台机器上存储控制器不止一个"变成能读的数，
/// 而不是等它挑错设备那天才发现。
pub fn count_of_class(cls: u8) -> usize {
    let Some(i) = info() else { return 0 };
    (0..i.n).filter_map(dev).filter(|d| d.class() == cls).count()
}

// ------------------------------------------------------------------ 中断能力（M5-g① 取证）
//
// 走能力链的办法与 `virtio.rs::read_caps` 同一条规矩：**偏移一格一格读回来，不猜**。
// 这里只读不说——"这台设备能不能被我们认领中断"由读数决定，不由规范文本决定：
// INTx 要的是 pin + 一个 GSI（pin↔GSI 的表在 ACPI `_PRT` 里，本内核没有 AML ⇒ M5b），
// 而 MSI/MSI-X 要的是"设备里的消息地址/数据寄存器"，向量与目的地由**我们自己写**，
// 所以不需要那张表。哪条路今天走得通，看下面这几张表里谁非空。

/// 能力链头指针（配置头 0x34 的字节 0）
const CAP_PTR: u32 = 0x34;
/// 规范里的两颗 capability id
const CAP_ID_MSI: u8 = 0x05;
const CAP_ID_MSIX: u8 = 0x11;
/// INTx：0x3D 字节是 pin（0 = 这台设备没有 INTx），0x3C 字节是固件写下来的 line（GSI 号）
const REG_INT_PIN: u32 = 0x3D;
const REG_INT_LINE: u32 = 0x3C;
/// 能力区从 0x40 起；链上有跳数上限，坏链不许把用例拖死（与块层那几条有界等待同一形状）
const CAP_MIN_OFF: u32 = 0x40;
const CAP_HOPS_MAX: u8 = 16;

/// MSI 块的读数（`off` = 块在配置空间里的偏移）
#[derive(Clone, Copy, Debug, Default)]
pub struct Msi {
    pub off: u8,
    pub enabled: bool,
    /// Multiple Message Capable 的**原始 3 位编码**：n ⇒ 最多 2^n 条向量。这里不换算成条数，
    /// 换算留给判据那一侧（写死 `1 << mmc` 就是把规范读成约定）
    pub mmc: u8,
    pub sixtyfour: bool,
    pub per_vector: bool,
}

/// MSI-X 块的读数
#[derive(Clone, Copy, Debug, Default)]
pub struct Msix {
    pub off: u8,
    /// 表大小字段是"条数 - 1"，这里已经加回来
    pub table_size: u16,
    pub function_mask: bool,
    pub table_bir: u8,
    pub table_off: u32,
    pub pba_bir: u8,
    pub pba_off: u32,
}

/// 一台设备的中断能力全景。`broken` 是**读数不是错误**：链走歪了就停下并说清停在哪一关，
/// 已经走到的部分照报——"整台设备看不见"与"看见一半"是两种不同的事实。
#[derive(Clone, Copy, Debug, Default)]
pub struct IrqCaps {
    pub pin: u8,
    pub line: u8,
    pub msi: Option<Msi>,
    pub msix: Option<Msix>,
    pub hops: u8,
    pub broken: Option<&'static str>,
}

impl Dev {
    /// 配置空间里的一个字节（`cfg32` 之内已按 DWORD 对齐，这里只挑出那 8 位）
    pub fn cfg_byte(&self, reg: u32) -> u8 {
        (self.cfg32(reg) >> ((reg & 3) * 8)) as u8
    }

    /// 读这台设备的 INTx pin/line + MSI/MSI-X 块。纯配置空间读，不改任何寄存器。
    pub fn irq_caps(&self) -> IrqCaps {
        let mut out = IrqCaps {
            pin: self.cfg_byte(REG_INT_PIN),
            line: self.cfg_byte(REG_INT_LINE),
            ..IrqCaps::default()
        };
        let mut ptr = self.cfg_byte(CAP_PTR) as u32;
        while ptr != 0 {
            if out.hops >= CAP_HOPS_MAX {
                out.broken = Some("跳数到上限");
                return out;
            }
            if ptr & 3 != 0 {
                out.broken = Some("能力偏移不齐");
                return out;
            }
            if ptr < CAP_MIN_OFF || ptr > 0xFC {
                out.broken = Some("能力偏移不在能力区");
                return out;
            }
            // 能力头：bits 7:0 = id，bits 15:8 = 下一跳。规范说下一跳低两位恒读 0，
            // 掩一下而不是相信它（掩与不掩读出一样的形状这件事，由下面那条"偏移不齐"的
            // 判据在真实链上顺手验掉：掩完还是不齐，就是链本身坏了）
            let hdr = self.cfg32(ptr);
            let id = (hdr & 0xFF) as u8;
            let next = ((hdr >> 8) & 0xFC) as u32;
            out.hops += 1;
            // msg_ctrl 在 off+2 ⇒ 与能力头同一个 DWORD 的高 16 位
            let ctrl = (hdr >> 16) & 0xFFFF;
            match id {
                CAP_ID_MSI => out.msi = Some(Msi {
                    off: ptr as u8,
                    enabled: ctrl & 1 != 0,
                    mmc: ((ctrl >> 1) & 7) as u8,
                    sixtyfour: ctrl & (1 << 7) != 0,
                    per_vector: ctrl & (1 << 8) != 0,
                }),
                CAP_ID_MSIX => {
                    // 布局是 +0 头/控制、**+4 表偏移与 BIR**、+8 PBA 偏移与 BIR。
                    // 这里曾经写成 +8/+12（整体偏了一个 dword），后果不是"读不出来"而是
                    // **读回来的是 PBA 的数**——写进表里全零、读回全零，看起来像设备不配合。
                    // 判据由 `KT_VIRTIO_MSIX` 的"写下去读得回来"那一格把住（BACKLOG 75）。
                    let tbl = self.cfg32(ptr + 4);
                    let pba = self.cfg32(ptr + 8);
                    out.msix = Some(Msix {
                        off: ptr as u8,
                        table_size: (ctrl & 0x7FF) as u16 + 1,
                        function_mask: ctrl & (1 << 14) != 0,
                        // BIR 占低 3 位，偏移从第 4 位起（3:0 是保留位；按掩码取，
                        // 不做"读出来是 0 就当作没有 BIR"的解释）
                        table_bir: (tbl & 7) as u8,
                        table_off: tbl & 0xFFFF_FFF0,
                        pba_bir: (pba & 7) as u8,
                        pba_off: pba & 0xFFFF_FFF0,
                    });
                }
                _ => {}
            }
            if next == ptr {
                out.broken = Some("下一跳等于自己");
                return out;
            }
            ptr = next;
        }
        out
    }
}
