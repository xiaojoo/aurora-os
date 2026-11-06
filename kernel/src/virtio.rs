//! virtio-blk（PCI modern 传输）第一版：**只做现场取证**。
//!
//! 这一版的存在理由与 ADR-029 第一条一模一样：手册/规范上的偏移表必须由设备自己作证。
//! 我脑子里那张 virtio 表已经错过别的寄存器五次，而 virtio 的布局比 AHCI 更依赖
//! "能力链说它在哪个 BAR 的哪个偏移"——写死偏移的驱动在这台机器上可能连设备都不是。
//!
//! 形状规矩（五条）：
//! 1. 只有不含糊的仪器才当判据：`device_feature_select` 那一对的判据是
//!    "**换了选页，读数必须跟着变**"，不是"我读到了预期的位"。
//! 2. 每个偏移都要有设备给的回证（写下去读得回来、位跟着位走、隔壁的字节不许被我改动）。
//! 3. 能力链是**唯一合法的找寄存器办法**：`cfg_type/bar/offset/length` 全部读回来，
//!    并且每个结构必须落在量出来的 BAR 尺寸之内。
//! 4. 认不出设备就报可见失败，不猜一个偏移继续往下盖。
//! 5. 驱动故障只降级，不 panic。资源全部经 `DriverCtx`（§8.5 / ADR-030）。

use crate::driver::{DmaHandle, DriverCtx, DriverError, MmioHandle};
use crate::mm::ModuleId;
use crate::pci::{self, Dev};
use core::sync::atomic::Ordering;

pub const MOD_VIRTIO: ModuleId = ModuleId(19);

/// virtio 的厂商号（PCI SIG 分配给 Red Hat / OASIS virtio）
pub const VENDOR: u16 = 0x1AF4;

// PCI 配置空间里的能力链
const PCI_CAP_LIST_PTR: u32 = 0x34;
const PCI_CAP_ID_VNDR: u8 = 0x09;
const CAP_VNDR: usize = 0; // 能力头：厂商定义
const CAP_NEXT: usize = 1;
const CAP_LEN: usize = 2;
const CAP_CFG_TYPE: usize = 3;
const CAP_BAR: usize = 4;
const CAP_ID: usize = 5;
const CAP_OFFSET: usize = 8; // dword
const CAP_LENGTH: usize = 12; // dword
const CAP_NOTIFY_MULT: usize = 16; // notify 能力独有的 dword

// virtio vendor capability 的 cfg_type
pub const CAP_COMMON_CFG: u8 = 1;
pub const CAP_NOTIFY_CFG: u8 = 2;
pub const CAP_ISR_CFG: u8 = 3;
pub const CAP_DEVICE_CFG: u8 = 4;
pub const CAP_PCI_CFG: u8 = 5;

// `common_cfg` 内部偏移（先当假设，逐格由证人表判）。
// 注意 0x10 那一个 dword 里装着两个 u16，0x14 那一个 dword 里装着
// `device_status`(u8) + `config_generation`(u8) + `queue_select`(u16 低半)——
// 所以字节字段必须用字节宽度的访问器，用 32 位写会连带改动隔壁。
pub const CC_DFSELECT: usize = 0x00;
pub const CC_DF: usize = 0x04;
pub const CC_GFSELECT: usize = 0x08;
pub const CC_GF: usize = 0x0C;
pub const CC_MSIX_CFG: usize = 0x10;
pub const CC_NUM_QUEUES: usize = 0x12;
pub const CC_STATUS: usize = 0x14;
pub const CC_CFG_GEN: usize = 0x15;
pub const CC_QUEUE_SELECT: usize = 0x16;
pub const CC_QUEUE_SIZE: usize = 0x18;
pub const CC_QUEUE_MSIX: usize = 0x1A;
pub const CC_QUEUE_ENABLE: usize = 0x1C;
pub const CC_QUEUE_NOTIFY_OFF: usize = 0x1E;
pub const CC_QUEUE_DESC_LO: usize = 0x20;

// `device_status` 的位
pub const ACKNOWLEDGE: u8 = 1;
pub const DRIVER: u8 = 2;
pub const DRIVER_OK: u8 = 4;
pub const FEATURES_OK: u8 = 8;
pub const NEEDS_CONFIG: u8 = 32;
pub const FAILED: u8 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioError {
    /// 枚举表里没有 vendor 0x1AF4 的设备
    NoDevice,
    /// 有设备但能力链里找不到 `common_cfg`（那可能是 legacy-only 的呈现）
    NoCommonCap,
    /// 能力说了某个 BAR，但那个 BAR 不是内存型或量不出尺寸
    BadBar(u8),
    /// 能力声明的 `[offset, offset+length)` 落在量出来的 BAR 尺寸之外
    StructBeyondBar { cap: u8, off: u32, len: u32, size: u64 },
    /// 认领/映射设备时句柄表拒绝
    Ctx(DriverError),
    /// 能力链走了一圈没走完（自引用或超长的环）
    CapLoop,
    /// 这台 virtio 设备的能力链里没有 MSI-X（那 MSI-X 那一格就没东西可判）
    NoMsixCap,
    /// 表太小，装不下"0 给配置、1 给队列"这个惯例
    MsixTooSmall(u16),
    /// `device_status` 复位后读不回 0（那意味着我对这一格的理解是错的）
    StatusStuck(u8),
    /// 握手某一步被设备拒绝：`driver_feature` 读回不是我们写进去的，
    /// 或置了 `FEATURES_OK` 之后读回来没有它 / `FAILED` 起来了
    DeviceRefused(u32),
    /// 敲过门之后 `used.idx` 在有界等待之内没前进：设备没接这条请求
    UsedTimeout,
    /// 调用方给的缓冲不是整扇区（半扇区的读要设备配合做读-改-写，那是块层的事）
    BadLen(usize),
    /// `queue_size` 是 0 或大到放不下我预留的环
    BadQueue(u16),
    /// 收到/要解的那一包不是 IPv4/UDP/BOOTP。`guard` 点名是哪一格拒的（1 长度或以太类型号、
    /// 2 IPv4 头长或协议号、3 UDP 目的端口），否则红了只能说不知道是哪一格
    NotV4 { at: usize, guard: u8 },
}

/// 一条 virtio vendor capability 的读数
#[derive(Clone, Copy, Debug)]
pub struct Cap {
    pub cfg_type: u8,
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
    /// 只有 NOTIFY 那条有意义；其余为 0
    pub notify_mult: u32,
}

/// 一次取证的全部读数（判据与打印都用它，不留"只有日志知道"的事实）
#[derive(Clone, Copy, Debug)]
pub struct Reading {
    pub bdf: u32,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub progif: u8,
    pub rev: u8,
    pub n_caps: u8,
    pub caps: [Cap; 8],
    pub bar_size: u64,
    pub df0: u32,
    /// 同一选页连读两次：这一对必须相同，否则 0x04 不是"只读位图"而是别的东西
    pub df0_again: u32,
    pub df1: u32,
    pub df_bad_select: u32,
    pub num_queues: u16,
    pub msix_config: u16,
    pub cfg_gen_before: u8,
    pub cfg_gen_after: u8,
    pub status_after_set: u8,
    pub status_after_reset: u8,
    pub dword_10_before: u32,
    pub dword_10_after: u32,
    pub q0_size: u16,
    pub q1_size: u16,
    /// 选了"合法但没配出来"的索引（= `num_queues`）时的尺寸，必须读回 0
    pub q_beyond_size: u16,
    /// 写进 `queue_select` 再读回来的值：0、1、越界的 0xFFFF、以及 `num_queues`
    pub sel0_back: u16,
    pub sel1_back: u16,
    pub sel_ffff_back: u16,
    pub sel_beyond_back: u16,
    pub noff_q0: u16,
    pub noff_q1: u16,
    pub notify_mult: u32,
    pub isr_after_reset: u8,
    /// `virtio_blk_config.capacity`（512 字节扇区数）。宿主机那块 qcow2 的大小是已知的，
    /// 所以这一格是"设备自报容量"与"宿主机文件"两台仪器对账的那条线
    pub capacity: u64,
}

/// 配置空间里读一个字节（ECAM 只能整 dword 读，能力指针不保证 4 字节对齐）
fn cfg_byte(dev: &Dev, at: u32) -> u8 {
    let d = dev.cfg32(at & !3);
    ((d >> (8 * (at & 3))) & 0xFF) as u8
}

fn cfg_dword(dev: &Dev, at: u32) -> u32 {
    dev.cfg32(at & !3) >> (8 * (at & 3))
}

/// 走能力链，收齐 virtio 的 vendor capability。
/// `cap_next` 必须在 0x3C 之内（配置空间头部之后）且不与已访问过的地址重复，
/// 否则判 `CapLoop`——链表坏掉时安静地少收几条是最糟的结果。
fn read_caps(dev: &Dev) -> Result<(u8, [Cap; 8]), VirtioError> {
    let mut caps = [Cap { cfg_type: 0, bar: 0, offset: 0, length: 0, notify_mult: 0 }; 8];
    let mut n = 0usize;
    let mut ptr = cfg_byte(dev, PCI_CAP_LIST_PTR);
    let mut visited = 0u64;
    let mut guard = 0u8;
    while ptr != 0 {
        guard += 1;
        if guard > 48 {
            return Err(VirtioError::CapLoop);
        }
        if ptr < 0x40 || ptr > 0xFC {
            break;
        }
        let bit = 1u64 << (ptr >> 2);
        if visited & bit != 0 {
            return Err(VirtioError::CapLoop);
        }
        visited |= bit;
        let id = cfg_byte(dev, u32::from(ptr) + CAP_VNDR as u32);
        let next = cfg_byte(dev, u32::from(ptr) + CAP_NEXT as u32);
        if id == PCI_CAP_ID_VNDR {
            let cfg_type = cfg_byte(dev, u32::from(ptr) + CAP_CFG_TYPE as u32);
            let bar = cfg_byte(dev, u32::from(ptr) + CAP_BAR as u32);
            let offset = cfg_dword(dev, u32::from(ptr) + CAP_OFFSET as u32);
            let length = cfg_dword(dev, u32::from(ptr) + CAP_LENGTH as u32);
            let notify_mult = if cfg_type == CAP_NOTIFY_CFG {
                cfg_dword(dev, u32::from(ptr) + CAP_NOTIFY_MULT as u32)
            } else {
                0
            };
            if n < caps.len() {
                caps[n] = Cap { cfg_type, bar, offset, length, notify_mult };
                n += 1;
            }
        }
        ptr = next;
    }
    Ok((n as u8, caps))
}

fn find_cap(caps: &[Cap; 8], n: u8, cfg_type: u8) -> Option<Cap> {
    caps[..usize::from(n)].iter().copied().find(|c| c.cfg_type == cfg_type)
}

/// 认领设备并做完全部取证。**不建环、不发 I/O**——那些在 M5-f②。
pub fn probe() -> Result<Reading, VirtioError> {
    let info = pci::info().ok_or(VirtioError::NoDevice)?;
    let Some(dev) = (0..info.n).filter_map(pci::dev).find(|d| d.vendor == VENDOR) else {
        return Err(VirtioError::NoDevice);
    };
    let (n, caps) = read_caps(&dev)?;
    let common = find_cap(&caps, n, CAP_COMMON_CFG).ok_or(VirtioError::NoCommonCap)?;
    let ctx = DriverCtx::for_device(MOD_VIRTIO, dev);
    let bs = dev.size_mem_bar(u32::from(common.bar));
    if !bs.restored || bs.size == 0 {
        return Err(VirtioError::BadBar(common.bar));
    }
    // 能力声明的区间必须落在量出来的 BAR 里：这条不是审美，是"我读到的 offset/length
    // 是不是真属于这块窗口"的位置证据
    for c in caps[..usize::from(n)].iter() {
        let end = u64::from(c.offset) + u64::from(c.length);
        if c.length != 0 && end > bs.size {
            return Err(VirtioError::StructBeyondBar {
                cap: c.cfg_type,
                off: c.offset,
                len: c.length,
                size: bs.size,
            });
        }
    }
    let h: MmioHandle = ctx.map_mmio(common.bar).map_err(VirtioError::Ctx)?;
    let off = |c: &Cap, inner: usize| -> usize { c.offset as usize + inner };
    let cc = |inner: usize| -> usize { off(&common, inner) };

    // 证人 1：`device_feature_select`(0x00) / `device_feature`(0x04) 是一对
    ctx.write32(h, cc(CC_DFSELECT), 0).map_err(VirtioError::Ctx)?;
    let df0 = ctx.read32(h, cc(CC_DF)).map_err(VirtioError::Ctx)?;
    let df0_again = ctx.read32(h, cc(CC_DF)).map_err(VirtioError::Ctx)?;
    ctx.write32(h, cc(CC_DFSELECT), 1).map_err(VirtioError::Ctx)?;
    let df1 = ctx.read32(h, cc(CC_DF)).map_err(VirtioError::Ctx)?;
    // 越界的选页必须读回 0（Linux 的 `vp_modern_get_features` 依赖这一点；读回非 0
    // 说明 0x04 这一格不是"跟着选页走的只读位图"）
    ctx.write32(h, cc(CC_DFSELECT), 0xFFFF_FFFF).map_err(VirtioError::Ctx)?;
    let df_bad_select = ctx.read32(h, cc(CC_DF)).map_err(VirtioError::Ctx)?;
    ctx.write32(h, cc(CC_DFSELECT), 0).map_err(VirtioError::Ctx)?;

    // 证人 2：这一段的字段各有各的宽度，**读宽了不报错，只是把隔壁那半读成 0**。
    // 实测（本机 QEMU 11.1.0）：`read32(0x10)` 拿回 `0x0000_FFFF` —— 低半是 `msix_config`，
    // 高半本该是 `num_queues` 却是 0；同一台设备 `read16(0x12)` 读回的是真的队列数。
    // 机制在设备侧看得见：它按 `addr` 分支返回值，不看访问宽度。
    // 所以 `msix/num_queues/status/config_generation/queue_select` 全部按自身宽度访问，
    // 而"超宽读丢隔壁"这件事本身写成一条判据（换成合规宽度它就红）。
    let dword_10_before = ctx.read32(h, cc(CC_MSIX_CFG)).map_err(VirtioError::Ctx)?;
    let msix_config = ctx.read16(h, cc(CC_MSIX_CFG)).map_err(VirtioError::Ctx)?;
    let num_queues = ctx.read16(h, cc(CC_NUM_QUEUES)).map_err(VirtioError::Ctx)?;
    let cfg_gen_before = ctx.read8(h, cc(CC_CFG_GEN)).map_err(VirtioError::Ctx)?;
    // 复位一次再开始：状态机从"全 0"起才有确定的含义
    ctx.write8(h, cc(CC_STATUS), 0).map_err(VirtioError::Ctx)?;
    let status_after_reset = ctx.read8(h, cc(CC_STATUS)).map_err(VirtioError::Ctx)?;
    ctx.write8(h, cc(CC_STATUS), ACKNOWLEDGE | DRIVER).map_err(VirtioError::Ctx)?;
    let status_after_set = ctx.read8(h, cc(CC_STATUS)).map_err(VirtioError::Ctx)?;
    // 字节的写不许动到隔壁：0x10 那个 dword 与 0x15 那一字节都要保持原样
    let dword_10_after = ctx.read32(h, cc(CC_MSIX_CFG)).map_err(VirtioError::Ctx)?;
    let cfg_gen_after = ctx.read8(h, cc(CC_CFG_GEN)).map_err(VirtioError::Ctx)?;
    let isr_after_reset = find_cap(&caps, n, CAP_ISR_CFG)
        .and_then(|isr| ctx.read8(h, off(&isr, 0)).ok())
        .unwrap_or(0xFF);

    // 证人 3：`queue_select`(0x16) 真的是选择器，而且它的写有边界
    // - 写 0/1 读回来就是 0/1
    // - 写 `0xFFFF` 之后读回来**必须还是 1**：设备只接受合法索引，越界的写被忽略
    //   （把它当"接受了 0xFFFF"判会假绿，因为下一条 `queue_size` 读的还是队列 1 的数）
    // - 换一个选择器，只读的 `queue_notify_off`(0x1e) 要跟着走 ⇒ 偏移与"谁跟着谁"同时钉住
    ctx.write16(h, cc(CC_QUEUE_SELECT), 0).map_err(VirtioError::Ctx)?;
    let sel0_back = ctx.read16(h, cc(CC_QUEUE_SELECT)).map_err(VirtioError::Ctx)?;
    let q0_size = ctx.read16(h, cc(CC_QUEUE_SIZE)).map_err(VirtioError::Ctx)?;
    let noff_q0 = ctx.read16(h, cc(CC_QUEUE_NOTIFY_OFF)).map_err(VirtioError::Ctx)?;
    ctx.write16(h, cc(CC_QUEUE_SELECT), 1).map_err(VirtioError::Ctx)?;
    let sel1_back = ctx.read16(h, cc(CC_QUEUE_SELECT)).map_err(VirtioError::Ctx)?;
    let q1_size = ctx.read16(h, cc(CC_QUEUE_SIZE)).map_err(VirtioError::Ctx)?;
    let noff_q1 = ctx.read16(h, cc(CC_QUEUE_NOTIFY_OFF)).map_err(VirtioError::Ctx)?;
    ctx.write16(h, cc(CC_QUEUE_SELECT), 0xFFFF).map_err(VirtioError::Ctx)?;
    let sel_ffff_back = ctx.read16(h, cc(CC_QUEUE_SELECT)).map_err(VirtioError::Ctx)?;
    // 合法但没配出来的索引：尺寸必须读回 0（这才是"选择器+尺寸"这一对的负对照）
    ctx.write16(h, cc(CC_QUEUE_SELECT), num_queues).map_err(VirtioError::Ctx)?;
    let sel_beyond_back = ctx.read16(h, cc(CC_QUEUE_SELECT)).map_err(VirtioError::Ctx)?;
    let q_beyond_size = ctx.read16(h, cc(CC_QUEUE_SIZE)).map_err(VirtioError::Ctx)?;
    ctx.write16(h, cc(CC_QUEUE_SELECT), 0).map_err(VirtioError::Ctx)?;
    // 状态回到 0：取证不许把设备留在"半个握手"里给后面的用例
    ctx.write8(h, cc(CC_STATUS), 0).map_err(VirtioError::Ctx)?;

    let notify_mult = find_cap(&caps, n, CAP_NOTIFY_CFG).map(|c| c.notify_mult).unwrap_or(0);
    // 设备自己的配置结构：`virtio_blk_config` 的头 8 字节就是容量（512 字节扇区数）。
    // 这一格的价值不在"读到了个数"，而在它能与宿主机那块 qcow2 的大小对上 ⇒ 两台仪器
    let capacity = match find_cap(&caps, n, CAP_DEVICE_CFG) {
        Some(dc) => {
            let lo = ctx.read32(h, off_in(&dc, 0)).map_err(VirtioError::Ctx)? as u64;
            let hi = ctx.read32(h, off_in(&dc, 4)).map_err(VirtioError::Ctx)? as u64;
            lo | (hi << 32)
        }
        None => 0,
    };
    Ok(Reading {
        bdf: dev.bdf,
        vendor: dev.vendor,
        device: dev.device,
        class: dev.class(),
        subclass: dev.subclass(),
        progif: dev.progif(),
        rev: dev.revision(),
        n_caps: n,
        caps,
        bar_size: bs.size,
        df0,
        df0_again,
        df1,
        df_bad_select,
        num_queues,
        msix_config,
        cfg_gen_before,
        cfg_gen_after,
        status_after_set,
        status_after_reset,
        dword_10_before,
        dword_10_after,
        q0_size,
        q1_size,
        q_beyond_size,
        sel0_back,
        sel1_back,
        sel_ffff_back,
        sel_beyond_back,
        noff_q0,
        noff_q1,
        notify_mult,
        isr_after_reset,
        capacity,
    })
}

/// virtio 设备类型号（规范里的那个"device id"，不是 PCI 配置空间里的那一个）
pub const VIRTIO_ID_BLOCK: u16 = 2;
pub const VIRTIO_ID_NET: u16 = 1;

/// PCI 基类：0x01 块设备、0x02 网络设备。`claim` 用它挑设备，所以两台 virtio 同时挂上时
/// "谁是哪一台"由配置空间自己说，不由命令行顺序说。
pub const PCI_CLASS_STORAGE: u8 = 0x01;
pub const PCI_CLASS_NETWORK: u8 = 0x02;

/// 把 PCI 配置空间里的 device id 解成上面的设备类型。规范的两段编码是
/// transitional = `0x1000 + 类型`、modern-only = `0x1040 + 类型`。
/// **本机实测偏离**：QEMU 11.1.0 给 virtio-net-pci 的是 `0x1000`（解出类型 0），
/// 而块设备给的是 `0x1002`（解出 2，与规则一致）—— transitional 网卡沿用了 virtio 0.9.5
/// 的老编号表（net 排第一）。所以这一格**只打印不当判据**；网卡身份由
/// `num_queues >= 2` 加"RX/TX 各有一扇门"来证（`KT_NET_TX` 判据 2）。
pub fn dev_type(device: u16) -> u16 {
    if (0x1040..=0x107F).contains(&device) {
        device - 0x1040
    } else if device >= 0x1000 && device <= 0x103F {
        device - 0x1000
    } else {
        0xFFFF
    }
}

pub fn is_modern_id(device: u16) -> bool {
    (0x1040..=0x107F).contains(&device)
}

/// 能力结构内部偏移 → BAR 内偏移（所有寄存器访问都从这两步算出来，
/// 不留"我以为它从 BAR 开头开始"这种假设）
pub fn off_in(c: &Cap, inner: usize) -> usize {
    c.offset as usize + inner
}

// ==================================================== M5-f②：split queue 与第一条 I/O

/// 队列地址那几格的偏移。`probe` 只证过 `queue_desc_lo`(0x20) 之前的部分，
/// 新加的这三对**每一个都现场量一次**（见 `bind` 里的回读 witness）——规范说它们在，
/// 不等于这台设备会回读。
pub const CC_QUEUE_DESC_HI: usize = 0x24;
pub const CC_QUEUE_DRIVER_LO: usize = 0x28;
pub const CC_QUEUE_DRIVER_HI: usize = 0x2C;
pub const CC_QUEUE_DEVICE_LO: usize = 0x30;
pub const CC_QUEUE_DEVICE_HI: usize = 0x34;

/// 描述符标志（virtio 1.x split queue）
const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;
/// `virtio_blk` 的请求类型与状态
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const S_OK: u8 = 0;
const SECTOR_BYTES: usize = 512;

/// 一段连续 DMA 内存当整条队列的三段环 + 请求头 + 数据 + 状态。
/// 布局是手工定的（不靠"接着排"）：偏移要能写进判据里，也要能被宿主机那边按同一张表重算。
const DMA_PAGES: usize = 8;
const O_DESC: usize = 0x0000; // 256 × 16 B
const O_AVAIL: usize = 0x1000; // flags + idx + 256 × u16
const O_USED: usize = 0x2000; // flags + idx + 256 × {u32,u32}
const O_DATA: usize = 0x3000; // 一个扇区
const O_REQ: usize = 0x3400; // 16 B 请求头
const O_STATUS: usize = 0x3410; // 1 B 状态

/// 一条请求跑完之后能拿回来的读数。**判据只用读数，不用"我觉得成功了"**
#[derive(Clone, Copy, Debug)]
pub struct Xfer {
    pub sector: u64,
    pub avail_idx: u16,
    pub used_idx: u16,
    pub used_id: u32,
    pub used_len: u32,
    pub status: u8,
    pub hash: u64,
}

/// 已经绑定好的设备。句柄都在里面，所以"资源全部经 `DriverCtx`"这条（ADR-030）
/// 在这一格是可见的：没有裸指针，只有 `MmioHandle`/`DmaHandle`。
pub struct Bound {
    ctx: DriverCtx,
    mmio: MmioHandle,
    dma: DmaHandle,
    notify: usize,
    notify_mult: u32,
    qsize: u16,
    capacity: u64,
    bus: u64,
    /// 地址寄存器写下去能不能读回来。`None` = 设备不回读 ⇒ 只能拿"后续 I/O 成功"当行为证据
    addr_readback: Option<bool>,
    enable_readback: u16,
    /// common_cfg 在这段映射里的偏移。MSI-X 那一格要写 `queue_msix_vector`——那是 common_cfg
    /// 内部的偏移，留在这里由 `bind` 一次算好，不在第二处重算（重算就是抄表）。
    cc: usize,
}

struct DevCell(core::cell::UnsafeCell<Option<Bound>>);
// SAFETY: 只有一个 CPU（BSP）会在驱动路径上取用它，且所有写入都在 `bind`/`do_io` 内；
//         与 `ahci::RingCell` 同一套前提（本内核没有并发驱动路径，M5-e 之后也不引入）。
unsafe impl Sync for DevCell {}
static DEV: DevCell = DevCell(core::cell::UnsafeCell::new(None));

/// 上一次被我们消费的 used.idx（`u16` 回绕，比较一律用.wrapping_sub 而不是 `<`）
static USED_SEEN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn b<T>(f: impl FnOnce(&Bound) -> Result<T, VirtioError>) -> Result<T, VirtioError> {
    // SAFETY: 见 `DevCell` 的 Sync 论证；这里只借出不逃逸
    unsafe { (*DEV.0.get()).as_ref().map(f).ok_or(VirtioError::NoDevice)? }
}

/// 复位 → `ACKNOWLEDGE|DRIVER` → 不接受任何特性 → `FEATURES_OK`，每一步都拿"写下去读回来的值"
/// 当 witness。块设备与网卡共用这一段：分开写就是把同一张寄存器表抄两遍，而抄第二遍的人是我。
fn handshake(ctx: &DriverCtx, mmio: MmioHandle, cc: usize) -> Result<(), VirtioError> {
    ctx.write8(mmio, cc + CC_STATUS, 0).map_err(VirtioError::Ctx)?;
    let after_reset = ctx.read8(mmio, cc + CC_STATUS).map_err(VirtioError::Ctx)?;
    if after_reset != 0 {
        return Err(VirtioError::StatusStuck(after_reset));
    }
    ctx.write8(mmio, cc + CC_STATUS, ACKNOWLEDGE | DRIVER).map_err(VirtioError::Ctx)?;
    // 不接受任何 feature：`driver_feature` 写 0 也要**读回来确认是 0**，
    // 否则"我以为我没接受"和"设备把它改回去了"这两种情况在日志里长得一样
    ctx.write32(mmio, cc + CC_GFSELECT, 0).map_err(VirtioError::Ctx)?;
    ctx.write32(mmio, cc + CC_GF, 0).map_err(VirtioError::Ctx)?;
    let gf_back = ctx.read32(mmio, cc + CC_GF).map_err(VirtioError::Ctx)?;
    if gf_back != 0 {
        return Err(VirtioError::DeviceRefused(gf_back));
    }
    ctx.write8(mmio, cc + CC_STATUS, ACKNOWLEDGE | DRIVER | FEATURES_OK).map_err(VirtioError::Ctx)?;
    let now = ctx.read8(mmio, cc + CC_STATUS).map_err(VirtioError::Ctx)?;
    if now & FEATURES_OK == 0 || now & FAILED != 0 {
        return Err(VirtioError::DeviceRefused(u32::from(now)));
    }
    Ok(())
}

/// 选中第 `index` 个队列，读尺寸与门位，把三段环的地址交给设备，再使能。
/// 返回 `(qsize, queue_notify_off, queue_enable 读回, 地址回读)`；地址回读为 `None` 时
/// 只能改用行为证据，**不许把"没测到"写成"测到了"**。
#[allow(clippy::too_many_arguments)]
fn setup_vq(
    ctx: &DriverCtx,
    mmio: MmioHandle,
    cc: usize,
    dma: DmaHandle,
    bus: u64,
    index: u16,
    o_desc: usize,
    o_avail: usize,
    o_used: usize,
) -> Result<(u16, u16, u16, Option<bool>), VirtioError> {
    ctx.write16(mmio, cc + CC_QUEUE_SELECT, index).map_err(VirtioError::Ctx)?;
    let qsize = ctx.read16(mmio, cc + CC_QUEUE_SIZE).map_err(VirtioError::Ctx)?;
    if qsize == 0 || usize::from(qsize) > 256 {
        return Err(VirtioError::BadQueue(qsize));
    }
    let noff = ctx.read16(mmio, cc + CC_QUEUE_NOTIFY_OFF).map_err(VirtioError::Ctx)?;

    let put_addr = |lo_at: usize, hi_at: usize, at: u64| -> Result<(), VirtioError> {
        ctx.write32(mmio, cc + lo_at, at as u32).map_err(VirtioError::Ctx)?;
        ctx.write32(mmio, cc + hi_at, (at >> 32) as u32).map_err(VirtioError::Ctx)
    };
    put_addr(CC_QUEUE_DESC_LO, CC_QUEUE_DESC_HI, bus + o_desc as u64)?;
    put_addr(CC_QUEUE_DRIVER_LO, CC_QUEUE_DRIVER_HI, bus + o_avail as u64)?;
    put_addr(CC_QUEUE_DEVICE_LO, CC_QUEUE_DEVICE_HI, bus + o_used as u64)?;
    let want = [
        (bus + o_desc as u64) as u32,
        (bus + o_avail as u64) as u32,
        (bus + o_used as u64) as u32,
    ];
    let back = [
        ctx.read32(mmio, cc + CC_QUEUE_DESC_LO).map_err(VirtioError::Ctx)?,
        ctx.read32(mmio, cc + CC_QUEUE_DRIVER_LO).map_err(VirtioError::Ctx)?,
        ctx.read32(mmio, cc + CC_QUEUE_DEVICE_LO).map_err(VirtioError::Ctx)?,
    ];
    let addr_readback = Some(back == want);

    // 环的三个头都清零：`avail.idx`/`used.idx` 从 0 起，判据才有绝对参照
    ctx.dma_write16(dma, o_avail, 0).map_err(VirtioError::Ctx)?;
    ctx.dma_write16(dma, o_avail + 2, 0).map_err(VirtioError::Ctx)?;
    ctx.dma_write16(dma, o_used, 0).map_err(VirtioError::Ctx)?;
    ctx.dma_write16(dma, o_used + 2, 0).map_err(VirtioError::Ctx)?;

    ctx.write16(mmio, cc + CC_QUEUE_ENABLE, 1).map_err(VirtioError::Ctx)?;
    let enable_readback = ctx.read16(mmio, cc + CC_QUEUE_ENABLE).map_err(VirtioError::Ctx)?;
    Ok((qsize, noff, enable_readback, addr_readback))
}

/// 按 PCI class 认领一台 virtio 设备。必须按 class 找而不是"配置空间里第一台 vendor 0x1AF4"：
/// 命令行上多挂一张网卡之后，后者会变成随机的一件事（M8-a① 就是那"多挂的一张"）。
fn claim(class: u8) -> Result<(Dev, u8, [Cap; 8]), VirtioError> {
    let info = pci::info().ok_or(VirtioError::NoDevice)?;
    let Some(dev) = (0..info.n)
        .filter_map(pci::dev)
        .find(|d| d.vendor == VENDOR && d.class() == class)
    else {
        return Err(VirtioError::NoDevice);
    };
    let (n, caps) = read_caps(&dev)?;
    Ok((dev, n, caps))
}

/// 规范的算法：`notify 地址 = notify 区基址 + multiplier × queue_notify_off`。
/// multiplier 读到 0 是合法的（那表示 2 字节步长），不许拿"我猜的偏移"去替它。
fn notify_addr(noff: u16, cap_offset: u32, mult: u32) -> usize {
    cap_offset as usize + (u64::from(mult) * u64::from(noff)) as usize
}

/// 认领设备、握手、建环。**幂等**（`.ktests` 顺序由链接器决定，用例不能假设别人跑过）。
pub fn bind() -> Result<(), VirtioError> {
    if unsafe { (*DEV.0.get()).is_some() } {
        return Ok(());
    }
    let (dev, n, caps) = claim(PCI_CLASS_STORAGE)?;
    let common = find_cap(&caps, n, CAP_COMMON_CFG).ok_or(VirtioError::NoCommonCap)?;
    let notify_cap = find_cap(&caps, n, CAP_NOTIFY_CFG).ok_or(VirtioError::NoCommonCap)?;
    let ctx = DriverCtx::for_device(MOD_VIRTIO, dev);
    let mmio = ctx.map_mmio(common.bar).map_err(VirtioError::Ctx)?;
    let cc = common.offset as usize;
    let dma = ctx.alloc_dma(DMA_PAGES * crate::mm::PAGE).map_err(VirtioError::Ctx)?;
    let bus = ctx.bus_addr(dma).map_err(VirtioError::Ctx)?;

    handshake(&ctx, mmio, cc)?;
    let (qsize, noff, enable_readback, addr_readback) =
        setup_vq(&ctx, mmio, cc, dma, bus, 0, O_DESC, O_AVAIL, O_USED)?;
    let notify = notify_addr(noff, notify_cap.offset, notify_cap.notify_mult);

    // 容量：设备自报，宿主机那边另有 `qemu-img info` 一台仪器
    let dc = find_cap(&caps, n, CAP_DEVICE_CFG).ok_or(VirtioError::NoCommonCap)?;
    let lo = ctx.read32(mmio, off_in(&dc, 0)).map_err(VirtioError::Ctx)? as u64;
    let hi = ctx.read32(mmio, off_in(&dc, 4)).map_err(VirtioError::Ctx)? as u64;
    ctx.write8(mmio, cc + CC_STATUS, ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK)
        .map_err(VirtioError::Ctx)?;

    let bound = Bound {
        ctx,
        mmio,
        dma,
        notify,
        notify_mult: notify_cap.notify_mult,
        qsize,
        capacity: lo | (hi << 32),
        bus,
        addr_readback,
        enable_readback,
        cc,
    };
    unsafe { *DEV.0.get() = Some(bound) };
    Ok(())
}

/// 绑定后的读数（判据与打印都用它，别留"只有日志知道"的事实）
pub fn status() -> Option<(u16, u64, usize, u32, Option<bool>, u16)> {
    // SAFETY: 见 `DevCell`
    unsafe {
        (*DEV.0.get()).as_ref().map(|d| {
            (
                d.qsize,
                d.capacity,
                d.notify,
                d.notify_mult,
                d.addr_readback,
                d.enable_readback,
            )
        })
    }
}

/// 有界轮询一个 u16 读数直到它满足条件。TSC 计时，不依赖中断（这条路径可能在 IF=0 下跑）。
fn wait_u16<F: Fn(u16) -> bool>(read: impl Fn() -> Result<u16, DriverError>, want: F, ms: u64) -> Option<u16> {
    let t0 = crate::tsc::now();
    let budget = crate::clock::hz().map_or(ms * 4_000_000, |hz| hz * ms / 1000);
    loop {
        if let Ok(v) = read() {
            if want(v) {
                return Some(v);
            }
        }
        core::hint::spin_loop();
        if crate::tsc::now().wrapping_sub(t0) > budget {
            return None;
        }
    }
}

/// 描述符是 16 字节一条（`addr:10|len:4|flags:2|next:2`）。这张表在块设备与网卡两条路径上
/// 共用一个写法：同一个偏移抄两遍，第二遍抄错的就是"驱动把自己的环摆坏了"这种红。
fn put_desc(
    c: &DriverCtx,
    dma: DmaHandle,
    desc_base: usize,
    i: usize,
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
) -> Result<(), VirtioError> {
    let base = desc_base + i * 16;
    c.dma_write32(dma, base, addr as u32).map_err(VirtioError::Ctx)?;
    c.dma_write32(dma, base + 4, (addr >> 32) as u32).map_err(VirtioError::Ctx)?;
    c.dma_write32(dma, base + 8, len).map_err(VirtioError::Ctx)?;
    c.dma_write16(dma, base + 12, flags).map_err(VirtioError::Ctx)?;
    c.dma_write16(dma, base + 14, next).map_err(VirtioError::Ctx)?;
    Ok(())
}

/// 一条请求：描述符链 [头(可读) → 数据(读=可写/写=可读) → 状态(可写)]，通知，有界等回执。
/// `buf` 是调用方的那个扇区：读方向在成功后被填，写方向在发射前被填。
fn do_io(sector: u64, write: bool, buf: &mut [u8]) -> Result<Xfer, VirtioError> {
    if buf.len() != SECTOR_BYTES {
        return Err(VirtioError::BadLen(buf.len()));
    }
    b(|d| {
        let c = &d.ctx;
        let (mmio, dma, qsize) = (d.mmio, d.dma, d.qsize as usize);
        // 1. 请求头
        c.dma_write32(dma, O_REQ, if write { T_OUT } else { T_IN }).map_err(VirtioError::Ctx)?;
        c.dma_write32(dma, O_REQ + 4, 0).map_err(VirtioError::Ctx)?;
        c.dma_write32(dma, O_REQ + 8, sector as u32).map_err(VirtioError::Ctx)?;
        c.dma_write32(dma, O_REQ + 12, (sector >> 32) as u32).map_err(VirtioError::Ctx)?;
        // 2. 状态字节先填哨兵：设备没写与设备写了 0 要分得开（与 AHCI 那条同一原理）
        c.dma_fill(dma, O_STATUS, 0xEE, 1).map_err(VirtioError::Ctx)?;
        if write {
            c.dma_copy_in(dma, O_DATA, buf).map_err(VirtioError::Ctx)?;
        } else {
            // 读方向：数据缓冲填哨兵，"没搬"与"搬回一堆 0"分得开
            c.dma_fill(dma, O_DATA, 0xEE, SECTOR_BYTES).map_err(VirtioError::Ctx)?;
        }
        // 3. 三个描述符
        let flags_mid = DESC_F_NEXT | if write { 0 } else { DESC_F_WRITE };
        put_desc(c, dma, O_DESC, 0, d.bus + O_REQ as u64, 16, DESC_F_NEXT, 1)?;
        put_desc(c, dma, O_DESC, 1, d.bus + O_DATA as u64, SECTOR_BYTES as u32, flags_mid, 2)?;
        put_desc(c, dma, O_DESC, 2, d.bus + O_STATUS as u64, 1, DESC_F_WRITE, 0)?;
        // 4. 生产者环：把链头 0 挂进去，然后 `idx` +1
        let avail = c.dma_read16(dma, O_AVAIL + 2).map_err(VirtioError::Ctx)?;
        let slot = usize::from(avail % qsize as u16) * 2;
        c.dma_write16(dma, O_AVAIL + 4 + slot, 0).map_err(VirtioError::Ctx)?;
        c.dma_write16(dma, O_AVAIL + 2, avail.wrapping_add(1)).map_err(VirtioError::Ctx)?;
        // 5. 敲门。写的是**队列号**（u16），地址按 notify 能力的 multiplier 算出来的那一个
        c.write16(mmio, d.notify, 0).map_err(VirtioError::Ctx)?;
        // 6. 有界等 `used.idx` 前进（今天不认领中断，只能轮询）
        let seen = USED_SEEN.load(core::sync::atomic::Ordering::Relaxed) as u16;
        let got = wait_u16(
            || c.dma_read16(dma, O_USED + 2),
            |v| v != seen,
            2000,
        )
        .ok_or(VirtioError::UsedTimeout)?;
        let eslot = usize::from(seen % qsize as u16) * 8;
        let used_id = c.dma_read32(dma, O_USED + 4 + eslot).map_err(VirtioError::Ctx)?;
        let used_len = c.dma_read32(dma, O_USED + 4 + eslot + 4).map_err(VirtioError::Ctx)?;
        let status = c.dma_read8(dma, O_STATUS).map_err(VirtioError::Ctx)?;
        USED_SEEN.store(u32::from(got), core::sync::atomic::Ordering::Relaxed);
        c.dma_copy_out(dma, O_DATA, buf).map_err(VirtioError::Ctx)?;
        let hash = crate::ahci::fnv1a64(buf);
        Ok(Xfer { sector, avail_idx: avail, used_idx: got, used_id, used_len, status, hash })
    })
}

/// 读一个扇区（512 字节）。整扇区约束留在接口上（半个扇区要读-改-写，那是块层的事）。
pub fn read_block(sector: u64, out: &mut [u8]) -> Result<Xfer, VirtioError> {
    do_io(sector, false, out)
}

/// 写一个扇区。
pub fn write_block(sector: u64, src: &[u8]) -> Result<Xfer, VirtioError> {
    // `do_io` 要的是 `&mut`（同一份代码两条方向），这里立刻还回去，不改调用方的借用形状
    let mut buf = [0u8; SECTOR_BYTES];
    if src.len() != SECTOR_BYTES {
        return Err(VirtioError::BadLen(src.len()));
    }
    buf.copy_from_slice(src);
    do_io(sector, true, &mut buf)
}

// ==================================================== M8-a①：virtio-net 与第一帧

/// `virtio_net_config` 的字段偏移。规范那张表在这里只是**假设**：`mac_width_ok` 用
/// "逐字节读 vs dword(0)+word(4) 拼"证偏移与字节序，`pairs_width_ok` 用 dword 分解
/// 证 `max_virtqueue_pairs`/`mtu` 确实相邻。**字段值本身只打印不判** —— MTU 该是几，
/// 宿主机没有第二台仪器能对（与块设备那一格不同，那格有 `qemu-img info`）。
pub const NC_MAC: usize = 0x00;
pub const NC_STATUS: usize = 0x06;
pub const NC_MAX_PAIRS: usize = 0x08;
pub const NC_MTU: usize = 0x0A;
/// `VIRTIO_NET_F_MAC`：设备有没有把"配置空间里那个 MAC 算数"当成一项能力。只打印
pub const F_NET_MAC: u32 = 5;

/// TX 是队列 1（RX=0）。这是 virtio-net 的固定分工，写反了就是"把帧交给自己的接收环"
pub const NET_QUEUE_TX: u16 = 1;

/// 帧之前那个头。本机一个特性都没接受，所以按"没有 `num_buffers`"的 10 字节发；
/// 描述符里写的长度就是设备读走的长度 —— 这个数错了不会报错，只会让 pcap 里那帧的
/// 开头多出或少掉几个字节，而那恰是宿主机那台仪器看得见的事（实测结论记 BACKLOG 58）。
pub const NET_HDR_BYTES: usize = 10;
/// 预留比头大：写零覆盖到 16 字节，设备读多少由描述符长度决定，多出来的只属于我们
pub const NET_HDR_ROOM: usize = 16;

/// 我们自己那一帧的形状。宿主机按同一张表重算，`check-net-pattern` 逐字对账
pub const NET_TYPE: [u8; 2] = [0x88, 0xB5]; // IEEE 802 Local Experimental：不冒认任何协议
pub const NET_DST: [u8; 6] = [0xFF; 6]; // 广播：还没有邻居，也不需要邻居就能上线
pub const NET_HEAD_BYTES: usize = 6 + 6 + 2;
pub const NET_FRAME_BYTES: usize = 60; // ethernet 最小帧（64 减掉 FCS，硬件补 FCS）
pub const NET_PAYLOAD_BYTES: usize = NET_FRAME_BYTES - NET_HEAD_BYTES;
pub const NET_MUL: u32 = 11;
pub const NET_ADD: u32 = 0xA5;
pub const NET_XOR: u32 = 0x5C;

pub fn net_payload_byte(j: usize, seq: u32) -> u8 {
    ((j as u32).wrapping_mul(NET_MUL).wrapping_add(NET_ADD).wrapping_add(seq) as u8) ^ (NET_XOR as u8)
}

/// net 的 TX：环与缓冲在同一块连续 DMA 里；三段环与块设备共用同一张偏移表，帧的部分往后排
const O_NHDR: usize = 0x3000;
const O_NFRAME: usize = 0x3040;

/// net 的 RX 用**另一块**连续 DMA：两个队列的环地址不能混用，收的缓冲也不能盖到发的环上
const O_RHDR: usize = 0x3000;
const O_RDESC: usize = 0x0000;
const O_RAVAIL: usize = 0x1000;
const O_RUSED: usize = 0x2000;
const O_RDATA: usize = 0x3100;
pub const RX_MAX_BYTES: usize = 1514;
const _: () = assert!(RX_MAX_BYTES + O_RDATA <= DMA_PAGES * crate::mm::PAGE);

/// RX 是队列 0
pub const NET_QUEUE_RX: u16 = 0;

/// 绑定后的网卡读数。`mac_width_ok`/`addr_readback` 这类格是"设备到底配不配合"的事实，
/// 不是我以为的默认值。
#[derive(Clone, Copy, Debug)]
pub struct NetInfo {
    pub bdf: u32,
    pub device_id: u16,
    pub class: u8,
    pub qsize: u16,
    pub notify: usize,
    pub notify_mult: u32,
    pub noff_rx: u16,
    pub noff_tx: u16,
    pub rx_qsize: u16,
    pub rx_notify: usize,
    pub rx_enable_readback: u16,
    pub rx_addr_readback: Option<bool>,
    pub enable_readback: u16,
    pub addr_readback: Option<bool>,
    pub num_queues: u16,
    pub mac: [u8; 6],
    pub mac_width_ok: bool,
    pub pairs_width_ok: Option<bool>,
    pub mtu: u16,
    pub max_pairs: u16,
    pub link: u16,
    pub cfg_len: u32,
    pub cfg_raw: [u8; 16],
    pub df0: u32,
}

/// 一帧发完之后能拿回来的读数
#[derive(Clone, Copy, Debug)]
pub struct Frame {
    pub seq: u32,
    pub len: usize,
    pub hash: u64,
    pub avail_idx: u16,
    pub used_idx: u16,
    pub used_id: u32,
    pub used_len: u32,
    /// 回执之后再从 DMA 读回来的那 60 字节的哈希：TX 方向设备只许读不许写，
    /// 这两个数不同就是"我把环的地址与帧的地址摆重了"
    pub hash_after: u64,
}

pub struct Net {
    ctx: DriverCtx,
    mmio: MmioHandle,
    dma: DmaHandle,
    bus: u64,
    rx_dma: DmaHandle,
    rx_bus: u64,
    rx_notify: usize,
    rx_qsize: u16,
    rx_enable_readback: u16,
    rx_addr_readback: Option<bool>,
    qindex: u16,
    notify: usize,
    notify_mult: u32,
    noff_rx: u16,
    noff_tx: u16,
    qsize: u16,
    enable_readback: u16,
    addr_readback: Option<bool>,
    num_queues: u16,
    mac: [u8; 6],
    mac_width_ok: bool,
    pairs_width_ok: Option<bool>,
    mtu: u16,
    max_pairs: u16,
    link: u16,
    cfg_len: u32,
    cfg_raw: [u8; 16],
    df0: u32,
    bdf: u32,
    device_id: u16,
    class: u8,
}

struct NetCell(core::cell::UnsafeCell<Option<Net>>);
// SAFETY: 与 `DevCell` 同一套前提 —— 只有 BSP 在驱动路径上取用，写入都在 `bind_net`/
//         `send_frame` 内。两张表各管一台设备，不共用状态。
unsafe impl Sync for NetCell {}
static NET_DEV: NetCell = NetCell(core::cell::UnsafeCell::new(None));
static NET_USED_SEEN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn bn<T>(f: impl FnOnce(&Net) -> Result<T, VirtioError>) -> Result<T, VirtioError> {
    // SAFETY: 见 `NetCell` 的 Sync 论证；这里只借出不逃逸
    unsafe { (*NET_DEV.0.get()).as_ref().map(f).ok_or(VirtioError::NoDevice)? }
}

/// 认领网卡、握手、把 TX 队列建起来（RX 队列只读门位、不使能 —— 收方向是 M8-a②）。
/// 幂等，与 `bind()` 同理。
pub fn bind_net() -> Result<(), VirtioError> {
    if unsafe { (*NET_DEV.0.get()).is_some() } {
        return Ok(());
    }
    let (dev, n, caps) = claim(PCI_CLASS_NETWORK)?;
    let common = find_cap(&caps, n, CAP_COMMON_CFG).ok_or(VirtioError::NoCommonCap)?;
    let notify_cap = find_cap(&caps, n, CAP_NOTIFY_CFG).ok_or(VirtioError::NoCommonCap)?;
    let ctx = DriverCtx::for_device(MOD_VIRTIO, dev);
    let mmio = ctx.map_mmio(common.bar).map_err(VirtioError::Ctx)?;
    let cc = common.offset as usize;
    let dma = ctx.alloc_dma(DMA_PAGES * crate::mm::PAGE).map_err(VirtioError::Ctx)?;
    let bus = ctx.bus_addr(dma).map_err(VirtioError::Ctx)?;

    handshake(&ctx, mmio, cc)?;
    let num_queues = ctx.read16(mmio, cc + CC_NUM_QUEUES).map_err(VirtioError::Ctx)?;
    // 设备侧特性页 0：只拿来看它有没有把 MAC 当成一项能力，打印不当判据
    ctx.write32(mmio, cc + CC_DFSELECT, 0).map_err(VirtioError::Ctx)?;
    let df0 = ctx.read32(mmio, cc + CC_DF).map_err(VirtioError::Ctx)?;

    // ---- 配置空间：MAC 与它后面那几个字段
    let dc = find_cap(&caps, n, CAP_DEVICE_CFG).ok_or(VirtioError::NoCommonCap)?;
    let cfg_len = dc.length;
    // 原始 16 字节先读上来：下面每一个字段的读法都要能被这串字节重算出来。加这一格的直接
    // 原因是 `mtu`/`max_virtqueue_pairs` 现场读回 0xFFFF 而 `status` 读回的是对的 ——
    // "哪一格根本不存在"只有逐字节摆出来才说得清（实测记 BACKLOG 58）
    let mut cfg_raw = [0u8; 16];
    for (i, b) in cfg_raw.iter_mut().enumerate() {
        *b = ctx.read8(mmio, off_in(&dc, i)).map_err(VirtioError::Ctx)?;
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&cfg_raw[0..6]);
    // 宽度证人：`mac[6]` 跨了 dword 边界，所以"逐字节读"与"`dword(0)` + `word(4)`"必须同数。
    // 这一格钉的是偏移与字节序；值本身对不对由 pcap 那台仪器判
    let mac_d0 = ctx.read32(mmio, off_in(&dc, NC_MAC)).map_err(VirtioError::Ctx)?;
    let mac_w4 = ctx.read16(mmio, off_in(&dc, NC_MAC + 4)).map_err(VirtioError::Ctx)?;
    let by_width = [
        (mac_d0 & 0xFF) as u8,
        ((mac_d0 >> 8) & 0xFF) as u8,
        ((mac_d0 >> 16) & 0xFF) as u8,
        ((mac_d0 >> 24) & 0xFF) as u8,
        (mac_w4 & 0xFF) as u8,
        ((mac_w4 >> 8) & 0xFF) as u8,
    ];
    let mac_width_ok = by_width == mac;
    let max_pairs = ctx.read16(mmio, off_in(&dc, NC_MAX_PAIRS)).map_err(VirtioError::Ctx)?;
    let mtu = ctx.read16(mmio, off_in(&dc, NC_MTU)).map_err(VirtioError::Ctx)?;
    let pair_dword = ctx.read32(mmio, off_in(&dc, NC_MAX_PAIRS)).map_err(VirtioError::Ctx)?;
    // 一个特性都没接受 ⇒ 设备按 virtio 0.9.5 的形状只给 8 字节配置（`mac[6] + status`），
    // 第 8..12 字节读回来全是 0xFF。那不是"值等于 0xFFFF"，是**这一格不存在**，所以证人取
    // `None`；写成 `Some(true)` 就是拿 `0xFF == 0xFF` 冒充证明（这一格就是这么变假的）。
    let pairs_present = cfg_raw[8..12] != [0xFF; 4];
    let pairs_width_ok =
        pairs_present.then_some(pair_dword == u32::from(max_pairs) | (u32::from(mtu) << 16));
    let link = ctx.read16(mmio, off_in(&dc, NC_STATUS)).map_err(VirtioError::Ctx)?;

    // 两个队列各建一次：TX 用第一块连续区，RX 用第二块。门位各自从设备读回来
    let (qsize, noff_tx, enable_readback, addr_readback) =
        setup_vq(&ctx, mmio, cc, dma, bus, NET_QUEUE_TX, O_DESC, O_AVAIL, O_USED)?;
    let notify = notify_addr(noff_tx, notify_cap.offset, notify_cap.notify_mult);
    let rx_dma = ctx.alloc_dma(DMA_PAGES * crate::mm::PAGE).map_err(VirtioError::Ctx)?;
    let rx_bus = ctx.bus_addr(rx_dma).map_err(VirtioError::Ctx)?;
    let (rx_qsize, noff_rx, rx_enable_readback, rx_addr_readback) =
        setup_vq(&ctx, mmio, cc, rx_dma, rx_bus, NET_QUEUE_RX, O_RDESC, O_RAVAIL, O_RUSED)?;
    let rx_notify = notify_addr(noff_rx, notify_cap.offset, notify_cap.notify_mult);
    ctx.write8(mmio, cc + CC_STATUS, ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK)
        .map_err(VirtioError::Ctx)?;

    let net = Net {
        ctx,
        mmio,
        dma,
        bus,
        rx_dma,
        rx_bus,
        rx_notify,
        rx_qsize,
        rx_enable_readback,
        rx_addr_readback,
        qindex: NET_QUEUE_TX,
        notify,
        notify_mult: notify_cap.notify_mult,
        noff_rx,
        noff_tx,
        qsize,
        enable_readback,
        addr_readback,
        num_queues,
        mac,
        mac_width_ok,
        pairs_width_ok,
        mtu,
        max_pairs,
        link,
        cfg_len,
        cfg_raw,
        df0,
        bdf: dev.bdf,
        device_id: dev.device,
        class: dev.class(),
    };
    unsafe { *NET_DEV.0.get() = Some(net) };
    Ok(())
}

pub fn net_info() -> Option<NetInfo> {
    // SAFETY: 见 `NetCell`
    unsafe {
        (*NET_DEV.0.get()).as_ref().map(|d| NetInfo {
            bdf: d.bdf,
            device_id: d.device_id,
            class: d.class,
            qsize: d.qsize,
            notify: d.notify,
            notify_mult: d.notify_mult,
            noff_rx: d.noff_rx,
            noff_tx: d.noff_tx,
            rx_qsize: d.rx_qsize,
            rx_notify: d.rx_notify,
            rx_enable_readback: d.rx_enable_readback,
            rx_addr_readback: d.rx_addr_readback,
            enable_readback: d.enable_readback,
            addr_readback: d.addr_readback,
            num_queues: d.num_queues,
            mac: d.mac,
            mac_width_ok: d.mac_width_ok,
            pairs_width_ok: d.pairs_width_ok,
            mtu: d.mtu,
            max_pairs: d.max_pairs,
            link: d.link,
            cfg_len: d.cfg_len,
            cfg_raw: d.cfg_raw,
            df0: d.df0,
        })
    }
}

/// 凑一帧：目的(6) 源(6) 类型(2) 图案(46)。源地址用的是**从设备配置空间读回来的那个 MAC**，
/// 所以这一帧里没有一个是"我顺手写死的地址"。图案带 `seq` ⇒ 两帧逐字节不同。
pub fn build_frame(seq: u32, mac: &[u8; 6]) -> ([u8; NET_FRAME_BYTES], u64) {
    let mut f = [0u8; NET_FRAME_BYTES];
    f[0..6].copy_from_slice(&NET_DST);
    f[6..12].copy_from_slice(mac);
    f[12..NET_HEAD_BYTES].copy_from_slice(&NET_TYPE);
    for j in 0..NET_PAYLOAD_BYTES {
        f[NET_HEAD_BYTES + j] = net_payload_byte(j, seq);
    }
    let h = crate::ahci::fnv1a64(&f);
    (f, h)
}

/// 发一帧：头与帧体两段描述符（都在设备可读方向），敲门写的是队列号，有界等 `used.idx` 前进。
pub fn send_frame(seq: u32) -> Result<Frame, VirtioError> {
    let (frame, _) = bn(|d| Ok(build_frame(seq, &d.mac)))?;
    let mut f = send_raw(&frame)?;
    f.seq = seq; // `send_raw` 只管字节，序号是这一层加回去的（判据里"第几帧"要用它）
    Ok(f)
}

/// 把任意一段字节发出去（`seq` 只用于回执读数里的那一格，不参与内容）。
/// 有了这一格，用例才能发"对端看得懂的东西"（ARP 请求），而不是只发图案。
pub fn send_raw(frame: &[u8]) -> Result<Frame, VirtioError> {
    if frame.len() > NET_TX_MAX {
        return Err(VirtioError::BadLen(frame.len()));
    }
    let hash = crate::ahci::fnv1a64(frame);
    bn(|d| {
        let c = &d.ctx;
        let (mmio, dma, qsize) = (d.mmio, d.dma, d.qsize as usize);
        // 头：全零。`flags/gso_type/hdr_len/gso_size/csum_start/csum_offset` 全取"没有卸载"
        c.dma_fill(dma, O_NHDR, 0, NET_HDR_ROOM).map_err(VirtioError::Ctx)?;
        c.dma_copy_in(dma, O_NFRAME, frame).map_err(VirtioError::Ctx)?;
        put_desc(c, dma, O_DESC, 0, d.bus + O_NHDR as u64, NET_HDR_BYTES as u32, DESC_F_NEXT, 1)?;
        put_desc(c, dma, O_DESC, 1, d.bus + O_NFRAME as u64, frame.len() as u32, 0, 0)?;
        let avail = c.dma_read16(dma, O_AVAIL + 2).map_err(VirtioError::Ctx)?;
        let slot = usize::from(avail % qsize as u16) * 2;
        c.dma_write16(dma, O_AVAIL + 4 + slot, 0).map_err(VirtioError::Ctx)?;
        c.dma_write16(dma, O_AVAIL + 2, avail.wrapping_add(1)).map_err(VirtioError::Ctx)?;
        c.write16(mmio, d.notify, d.qindex).map_err(VirtioError::Ctx)?;
        let seen = NET_USED_SEEN.load(core::sync::atomic::Ordering::Relaxed) as u16;
        let got = wait_u16(|| c.dma_read16(dma, O_USED + 2), |v| v != seen, 2000)
            .ok_or(VirtioError::UsedTimeout)?;
        let eslot = usize::from(seen % qsize as u16) * 8;
        let used_id = c.dma_read32(dma, O_USED + 4 + eslot).map_err(VirtioError::Ctx)?;
        let used_len = c.dma_read32(dma, O_USED + 4 + eslot + 4).map_err(VirtioError::Ctx)?;
        NET_USED_SEEN.store(u32::from(got), core::sync::atomic::Ordering::Relaxed);
        // 回执之后把发出去的那段字节再读回来：TX 方向设备只许读，改了就是地址摆重了
        let mut back = [0u8; NET_TX_MAX];
        c.dma_copy_out(dma, O_NFRAME, &mut back[..frame.len()]).map_err(VirtioError::Ctx)?;
        Ok(Frame {
            seq: 0,
            len: frame.len(),
            hash,
            avail_idx: avail,
            used_idx: got,
            used_id,
            used_len,
            hash_after: crate::ahci::fnv1a64(&back[..frame.len()]),
        })
    })
}

/// 一次能发的最大帧长：一个标准 ethernet 帧（不带 FCS）的上限。
/// 帧体与三段环共用一块连续 DMA，所以这条还受"帧体之后剩下多少"限制——那条不变量写在下面
/// 的编译期断言里，不靠我每次手工量。
pub const NET_TX_MAX: usize = 1514;
const _: () = assert!(NET_TX_MAX + O_NFRAME <= DMA_PAGES * crate::mm::PAGE);

/// IPv4/UDP/BOOTP 的那几个号，与夹具里 `dhcpstart=` 那一个 IP：内核与 `tools/aurora.py`
/// 各写一份，由 `check-net-pattern` 逐字对账（对端答不答这两个数，两边说的必须是同一件事）
pub const NET_TYPE_IPV4: [u8; 2] = [0x08, 0x00];
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_XID: u32 = 0xA5A5_1234;
/// 夹具里 `dhcpstart=10.0.2.15` 那一个数：内核从线上读回来的 `yiaddr` 必须等于它
pub const DHCP_GUEST_IP: [u8; 4] = [10, 0, 2, 15];
/// magic cookie：`0x63825363` = 99,130,83,99（RFC 2131 定下来的那四个字节）。
/// 我第一版把它凭记忆写成 99,130,131,15 —— 对端照样答了（slirp 不校验入站的 cookie），
/// 所以这条只能靠**对端自己写下来的那四个字节**来纠正：真机上的服务器会直接丢掉这一份请求。
pub const DHCP_MAGIC: [u8; 4] = [99, 130, 83, 99];
pub const OPT_MSG_TYPE: u8 = 53;
pub const OPT_END: u8 = 255;
pub const OPT_PAD: u8 = 0;
pub const BOOTREQUEST: u8 = 1;
pub const BOOTREPLY: u8 = 2;
pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_ACK: u8 = 5;

/// BOOTP：固定段到 236，`magic` 在 236，options 从 240 起
const BOOTP_OFF: usize = 14 + 20 + 8;
const BOOTP_OPT: usize = 240;
const BOOTP_OPT_LEN: usize = 8;
const BOOTP_BYTES: usize = BOOTP_OPT + BOOTP_OPT_LEN;
pub const DHCP_FRAME_BYTES: usize = BOOTP_OFF + BOOTP_BYTES;
const _: () = assert!(DHCP_FRAME_BYTES <= NET_TX_MAX);

/// IPv4 首部校验和：16 位一步的反码和，进位回卷后取反
fn ip_cksum(b: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0usize;
    while i + 1 < b.len() {
        sum += u32::from(u16::from_be_bytes([b[i], b[i + 1]]));
        i += 2;
    }
    if i < b.len() {
        sum += u32::from(b[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// 凑一个 DHCP DISCOVER：以太网 + IPv4 + UDP + BOOTP。源 IP 是 `0.0.0.0`、目的
/// `255.255.255.255`（还没有地址可填），`chaddr` 用设备配置空间读回来的那个 MAC。
/// UDP 校验和按 IPv4 里的合法写法留 0；IPv4 首部校验和是真算的（`ip_cksum`）。
pub fn build_dhcp_discover(mac: &[u8; 6]) -> ([u8; DHCP_FRAME_BYTES], u64) {
    let mut f = [0u8; DHCP_FRAME_BYTES];
    f[0..6].copy_from_slice(&NET_DST);
    f[6..12].copy_from_slice(mac);
    f[12..14].copy_from_slice(&NET_TYPE_IPV4);
    let ip_len = 20 + 8 + BOOTP_BYTES;
    f[14] = 0x45;
    f[16] = (ip_len >> 8) as u8;
    f[17] = ip_len as u8;
    f[18] = 0x00;
    f[19] = 0x01;
    f[20] = 0x40; // Don't Fragment
    f[22] = 64;
    f[23] = 17;
    f[30..34].copy_from_slice(&[255, 255, 255, 255]);
    let ck = ip_cksum(&f[14..34]);
    f[24] = (ck >> 8) as u8;
    f[25] = ck as u8;
    f[34] = (DHCP_CLIENT_PORT >> 8) as u8;
    f[35] = DHCP_CLIENT_PORT as u8;
    f[36] = (DHCP_SERVER_PORT >> 8) as u8;
    f[37] = DHCP_SERVER_PORT as u8;
    let ul = 8 + BOOTP_BYTES;
    f[38] = (ul >> 8) as u8;
    f[39] = ul as u8;
    let b = BOOTP_OFF;
    f[b] = BOOTREQUEST;
    f[b + 1] = 1;
    f[b + 2] = 6;
    f[b + 4..b + 8].copy_from_slice(&DHCP_XID.to_be_bytes());
    f[b + 28..b + 34].copy_from_slice(mac);
    f[b + 236..b + 240].copy_from_slice(&DHCP_MAGIC);
    f[b + BOOTP_OPT] = OPT_MSG_TYPE;
    f[b + BOOTP_OPT + 1] = 1;
    f[b + BOOTP_OPT + 2] = DHCP_DISCOVER;
    f[b + BOOTP_OPT + 3] = 55;
    f[b + BOOTP_OPT + 4] = 2;
    f[b + BOOTP_OPT + 5] = 1;
    f[b + BOOTP_OPT + 6] = 3;
    f[b + BOOTP_OPT + 7] = OPT_END;
    let h = crate::ahci::fnv1a64(&f);
    (f, h)
}

/// 收到的那一包（BOOTREPLY）里能拿出来的事实。字段全从**收到的字节**里读，不是我以为的
#[derive(Clone, Copy, Debug)]
pub struct Reply {
    pub len: usize,
    pub hash: u64,
    pub ethertype: [u8; 2],
    pub op: u8,
    pub msg_type: u8,
    pub xid: u32,
    pub yiaddr: [u8; 4],
    pub used_idx: u16,
    pub used_len: u32,
    /// `used.id`：设备说它写的是我们挂的那一条链（今天只挂得下一条，所以合法值只有 0）
    pub used_id: u32,
}

/// 解一包：只解到"是不是 IPv4/UDP/BOOTP 与 `yiaddr` 是哪一个数"，不做任何协议决定。
/// 每一处切片都先验长度（§10.3 同一条：盘上/线上的数不能直接当界用）
pub fn parse_reply(buf: &[u8], used_idx: u16, used_len: u32, used_id: u32) -> Result<Reply, VirtioError> {
    if buf.len() < BOOTP_OFF || buf[12] != NET_TYPE_IPV4[0] || buf[13] != NET_TYPE_IPV4[1] {
        return Err(VirtioError::NotV4 { at: buf.len(), guard: 1 });
    }
    let ihl = usize::from(buf[14] & 0x0F) * 4;
    // 每一处都要先看长度：`ihl` 从线上来，它可以是 0..15 里的任何数，也可能大到越出这一包
    if ihl < 20 || buf[14 + 9] != 17 || buf.len() < 14 + ihl + 8 + BOOTP_OPT {
        return Err(VirtioError::NotV4 { at: buf.len(), guard: 2 });
    }
    // UDP 的头就在 IPv4 之后：源 67（服务器）→ 目的 68（客户机）。
    // 端口在 UDP 头的 **0..2 与 2..4**，6..8 是校验和（第一版按 +6 取目的端口，
    // 于是把校验和当成了端口，任何真回话都会被判成"不是给我这台机器的"）
    if buf[14 + ihl + 2] != (DHCP_CLIENT_PORT >> 8) as u8
        || buf[14 + ihl + 3] != DHCP_CLIENT_PORT as u8
    {
        return Err(VirtioError::NotV4 { at: buf.len(), guard: 3 });
    }
    let b = 14 + ihl + 8; // BOOTP 从以太网 14 + IP 头 + UDP 头之后开始
    // options 从固定段的 240 起，magic 在它前面（236..240），不要再跳 4 个字节
    let opts = b + BOOTP_OPT;
    let mut msg_type = 0u8;
    let mut i = opts;
    // 有界走查：`PAD` 是单字节，其余是 `code + len + len 个字节`。
    // 长度说出去就越过这一包末尾时**停下来**，不猜——猜下去就是把畸形输入当合法，
    // 而畸形输入正是 M8 那句验收（协议 fuzz）要喂的东西
    while i < buf.len() {
        let code = buf[i];
        if code == OPT_END {
            break;
        }
        if code == OPT_PAD {
            i += 1;
            continue;
        }
        if i + 1 >= buf.len() {
            break;
        }
        let ln = usize::from(buf[i + 1]);
        if ln == 0 || i + 2 + ln > buf.len() {
            break;
        }
        if code == OPT_MSG_TYPE {
            msg_type = buf[i + 2];
        }
        i += 2 + ln;
    }
    Ok(Reply {
        len: buf.len(),
        hash: crate::ahci::fnv1a64(buf),
        ethertype: [buf[12], buf[13]],
        op: buf[b],
        msg_type,
        xid: u32::from_be_bytes([buf[b + 4], buf[b + 5], buf[b + 6], buf[b + 7]]),
        yiaddr: [buf[b + 16], buf[b + 17], buf[b + 18], buf[b + 19]],
        used_idx,
        used_len,
        used_id,
    })
}

static RX_USED_SEEN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// 挂一个接收缓冲（头与数据两段都是**设备可写**方向），敲 RX 那扇门，有界等 `used.idx` 前进。
/// 返回 `(缓冲, 帧长, used.idx, used.len)`。帧长按 `used.len - 头长` 算，
/// 而 `used.len` 是设备写的数 ⇒ 下界与上界都要验（§10.3 那条：线上的数不能直接当界用）。
/// 缓冲在等回执之前先填哨兵 `0xEE`：那样"设备没写"与"写了一堆 0"才分得开。
pub fn receive(wait_ms: u64) -> Result<([u8; RX_MAX_BYTES], usize, u16, u32, u32), VirtioError> {
    bn(|d| {
        let c = &d.ctx;
        let (dma, qsize) = (d.rx_dma, d.rx_qsize as usize);
        c.dma_fill(dma, O_RDATA, 0xEE, RX_MAX_BYTES).map_err(VirtioError::Ctx)?;
        put_desc(c, dma, O_RDESC, 0, d.rx_bus + O_RHDR as u64, NET_HDR_BYTES as u32,
                 DESC_F_NEXT | DESC_F_WRITE, 1)?;
        put_desc(c, dma, O_RDESC, 1, d.rx_bus + O_RDATA as u64, RX_MAX_BYTES as u32,
                 DESC_F_WRITE, 0)?;
        let avail = c.dma_read16(dma, O_RAVAIL + 2).map_err(VirtioError::Ctx)?;
        let slot = usize::from(avail % qsize as u16) * 2;
        c.dma_write16(dma, O_RAVAIL + 4 + slot, 0).map_err(VirtioError::Ctx)?;
        c.dma_write16(dma, O_RAVAIL + 2, avail.wrapping_add(1)).map_err(VirtioError::Ctx)?;
        c.write16(d.mmio, d.rx_notify, NET_QUEUE_RX).map_err(VirtioError::Ctx)?;
        let seen = RX_USED_SEEN.load(core::sync::atomic::Ordering::Relaxed) as u16;
        let got = wait_u16(|| c.dma_read16(dma, O_RUSED + 2), |v| v != seen, wait_ms)
            .ok_or(VirtioError::UsedTimeout)?;
        let eslot = usize::from(seen % qsize as u16) * 8;
        let used_id = c.dma_read32(dma, O_RUSED + 4 + eslot).map_err(VirtioError::Ctx)?;
        let used_len = c.dma_read32(dma, O_RUSED + 4 + eslot + 4).map_err(VirtioError::Ctx)?;
        RX_USED_SEEN.store(u32::from(got), core::sync::atomic::Ordering::Relaxed);
        // 下界：设备写的长度连头都不够，说明它没按我们给的布局写；上界：不许越过我们给的缓冲
        if used_len <= NET_HDR_BYTES as u32 {
            return Err(VirtioError::BadLen(used_len as usize));
        }
        let n = (used_len as usize - NET_HDR_BYTES).min(RX_MAX_BYTES);
        let mut out = [0u8; RX_MAX_BYTES];
        c.dma_copy_out(dma, O_RDATA, &mut out[..n]).map_err(VirtioError::Ctx)?;
        Ok((out, n, got, used_len, used_id))
    })
}

// ---------------------------------------------------------------------------
// L3-B：virtio 的 MSI-X 表条目（变体 `virtio-msix-probe` 才跑；能力本身常驻）

/// MSI-X 每条目 16 字节：地址低半、地址高半、数据、向量控制（bit0 = mask）
pub const MSIX_ENTRY_BYTES: usize = 16;
pub const MSIX_CTRL_MASK: u32 = 1;
/// 表里给第一条队列用的条目号（virtio 的惯例：0 给配置变化，1 起给队列）
pub const MSIX_QUEUE0: usize = 1;
/// virtio 的"这条不分配向量"写法
pub const MSIX_NO_VECTOR: u16 = 0xFFFE;

/// MSI-X 编程一轮的全部读数。**每个字段都是设备自己给的**，不是我以为的偏移。
#[derive(Clone, Copy, Debug)]
pub struct MsixProbe {
    pub table_size: u16,
    pub bir: u8,
    pub table_off: u32,
    pub cap_off: u8,
    pub vector: u8,
    pub entry: usize,
    /// 全遮之后读到"已遮"的条目数（该等于 table_size）
    pub masked_all: u16,
    /// 写下去的三个 DWORD 与读回来的四个 DWORD（第四个是向量控制）
    pub want: [u32; 3],
    pub back: [u32; 4],
    /// 解除全遮后：function mask 是否真的关了、仍遮着的条目数（该等于 table_size - 1）
    pub fn_mask_off: bool,
    pub masked_rest: u16,
    /// `queue_msix_vector` 写下去读回来的是条目号本身
    pub qvector_back: u16,
    /// 撤销认领并重遮之后：该回到 table_size
    pub re_masked: u16,
    /// 一次真读盘期间：这一发到过处理函数手里几次、处理函数认领了几次、内容对不对
    pub calls: usize,
    pub claims: usize,
    pub content_ok: bool,
    pub flag_seen: bool,
    /// 读完之后为那一发旗子等了多久（自旋轮数）。0 = 立刻看到；上限是 200,000 轮。
    pub waited: u32,
}

static MSIX_FLAG: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// 顶半：只立旗与记一笔，**不**在里头发命令，也不在里头发结论——
/// 认领与否由 `used.idx` 的读数决定（AHCI 那格的递归教训在这里同一形状适用）。
fn virtio_msix_isr() -> bool {
    MSIX_FLAG.store(true, Ordering::Release);
    true
}

/// 数 vector_control 的 bit0 为 1 的条目。
fn count_masked(ctx: &DriverCtx, th: MmioHandle, table_off: usize, n: u16) -> Result<u16, VirtioError> {
    let mut c = 0u16;
    for i in 0..n as usize {
        let v = ctx
            .read32(th, table_off + i * MSIX_ENTRY_BYTES + 12)
            .map_err(VirtioError::Ctx)?;
        if v & MSIX_CTRL_MASK != 0 {
            c += 1;
        }
    }
    Ok(c)
}

/// 功能掩码位的读写。Message Control 在能力头 +2 的那个 word；用 dword 访问时**只动高半**：
/// 低半是 cap id 与 next 指针，那是只读的，写进去就是把能力链拆了。返回读回来的 mask 位。
fn set_fn_mask(dev: &pci::Dev, ctrl_off: u32, on: bool) -> bool {
    let dword = dev.cfg32(ctrl_off);
    let ctrl = (dword >> 16) & 0xFFFF;
    // 实验：解除功能掩码时同时置 **bit15 = MSI-X Enable**（QEMU 的 `msix_enabled()`
    // 读的是这一位与 function-mask 两个条件；只清 bit14 而 bit15 从来没置过，
    // 设备侧就会退到 INTx 那条线，而那根线的 RTE 今天没编程 ⇒ 一发都不到 guest）。
    let new = if on {
        ctrl | (1 << 14)
    } else {
        (ctrl & !(1 << 14)) | (1 << 15)
    };
    dev.cfg_write(ctrl_off, (dword & 0xFFFF) | (new << 16));
    (((dev.cfg32(ctrl_off) >> 16) & 0xFFFF) >> 14) & 1 != 0
}

/// MSI-X 编程一轮：全遮 → 认领 → 写条目 → 读回 → 解除全遮 → 交给设备 → 真读一次盘 → 撤销并重遮。
///
/// 两处顺序不许换：**先遮再改表**（改表途中设备正在发这一发，就会读到半新半旧的条目）；
/// **撤销之后重遮**（留一条 unmasked 而没人认领的条目 = 把中断扔进没人数的账里）。
pub fn msix_probe() -> Result<MsixProbe, VirtioError> {
    b(|bd| {
        let ctx = &bd.ctx;
        let dev = ctx.device();
        let caps = dev.irq_caps();
        let mx = caps.msix.ok_or(VirtioError::NoMsixCap)?;
        if mx.table_size < 2 {
            return Err(VirtioError::MsixTooSmall(mx.table_size));
        }
        let th = ctx.map_mmio(mx.table_bir).map_err(VirtioError::Ctx)?;
        let ctrl_off = u32::from(mx.off);
        let table_off = mx.table_off as usize;

        // ① 全遮：先确认"遮上"这件事设备认
        set_fn_mask(&dev, ctrl_off, true);
        for i in 0..mx.table_size as usize {
            ctx.write32(th, table_off + i * MSIX_ENTRY_BYTES + 12, MSIX_CTRL_MASK)
                .map_err(VirtioError::Ctx)?;
        }
        let masked_all = count_masked(ctx, th, table_off, mx.table_size)?;

        // ② 认领一颗向量，把核内算好的消息取回来，写进条目
        let h = ctx.request_irq(virtio_msix_isr).map_err(VirtioError::Ctx)?;
        let (alo, ahi, data) = ctx.irq_message(h).map_err(VirtioError::Ctx)?;
        let e = MSIX_QUEUE0;
        let base = table_off + e * MSIX_ENTRY_BYTES;
        ctx.write32(th, base, alo).map_err(VirtioError::Ctx)?;
        ctx.write32(th, base + 4, ahi).map_err(VirtioError::Ctx)?;
        ctx.write32(th, base + 8, data).map_err(VirtioError::Ctx)?;
        ctx.write32(th, base + 12, 0).map_err(VirtioError::Ctx)?;
        let back = [
            ctx.read32(th, base).map_err(VirtioError::Ctx)?,
            ctx.read32(th, base + 4).map_err(VirtioError::Ctx)?,
            ctx.read32(th, base + 8).map_err(VirtioError::Ctx)?,
            ctx.read32(th, base + 12).map_err(VirtioError::Ctx)?,
        ];

        // ③ 解除全遮。顺序假设的验证：QEMU 只在 `msix_table_write` 里对"从遮到不遮"那一次
        //    翻转做 `msix_unmask_vector`，而功能掩码开着时 `msix_is_masked()` 恒真 ⇒ 那次翻转被吞。
        //    所以这里解除功能掩码之后，**再翻一次目标条目的 ctrl**，让它作为一次真正的解除被看见。
        set_fn_mask(&dev, ctrl_off, false);
        ctx.write32(th, base + 12, MSIX_CTRL_MASK).map_err(VirtioError::Ctx)?;
        ctx.write32(th, base + 12, 0).map_err(VirtioError::Ctx)?;
        let dword = dev.cfg32(ctrl_off);
        let fn_mask_off = ((dword >> 30) & 1) == 0;
        let masked_rest = count_masked(ctx, th, table_off, mx.table_size)?;

        // ④ 把这条向量交给设备：队列 0 的完成通知走条目 e（写下去读回来）
        ctx.write16(bd.mmio, bd.cc + CC_QUEUE_MSIX, e as u16)
            .map_err(VirtioError::Ctx)?;
        let qvector_back = ctx
            .read16(bd.mmio, bd.cc + CC_QUEUE_MSIX)
            .map_err(VirtioError::Ctx)?;

        // ⑤ 一次真读盘：投递到过处理函数几次、它认领了几次。
        //    `with_interrupts` 与读完之后那一段有界等都不许省：AHCI 那一格实测过
        //    "IF=0 的窗口里中断只能攒着"，而旗子是在**别的 CPU 上被取走**也有可能（74b）。
        MSIX_FLAG.store(false, Ordering::Release);
        let (c0, k0) = ctx.irq_counts(h).map_err(VirtioError::Ctx)?;
        let mut buf = [0u8; 512];
        let r = crate::apic::with_interrupts(|| read_block(0, &mut buf));
        let mut waited = 0u32;
        while !MSIX_FLAG.load(Ordering::Acquire) && waited < 200_000 {
            core::hint::spin_loop();
            waited += 1;
        }
        let (c1, k1) = ctx.irq_counts(h).map_err(VirtioError::Ctx)?;

        // ⑥ 撤销认领 → 队列改回"不分配向量" → 这条重新遮上（谁开的关谁负责关）
        let _ = ctx.write16(bd.mmio, bd.cc + CC_QUEUE_MSIX, MSIX_NO_VECTOR);
        let _ = ctx.write32(th, base + 12, MSIX_CTRL_MASK);
        let re_masked = count_masked(ctx, th, table_off, mx.table_size)?;
        if ctx.release_irq(h).is_err() {
            return Err(VirtioError::Ctx(DriverError::NoSuchHandle(h.slot)));
        }
        Ok(MsixProbe {
            table_size: mx.table_size,
            bir: mx.table_bir,
            table_off: mx.table_off,
            cap_off: mx.off,
            vector: h.vector,
            entry: e,
            masked_all,
            want: [alo, ahi, data],
            back,
            fn_mask_off,
            masked_rest,
            qvector_back,
            re_masked,
            calls: c1 - c0,
            claims: k1 - k0,
            content_ok: r.is_ok(),
            flag_seen: MSIX_FLAG.load(Ordering::Acquire),
            waited,
        })
    })
}
