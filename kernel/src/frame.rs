//! S6a：帧缓冲窗口与最小像素写入。
//!
//! **为什么自己映射，而不用 Limine 直接给的那个 `address`**：那是 bootloader 在它自己
//! 页表里建的映射，而本内核在 `mm::take_over` 里换了 CR3 ⇒ 那个地址在我们的页表里不保证存在。
//! 所以这里取 memmap 里 `MemmapType::Framebuffer` 那段**物理区间**，走 `hw::MmioRegion`
//! （底下是 `mm::map_mmio`，`PageFlags::DEVICE` ⇒ PCD/UC-，不缓存、不可执行、不给用户态）。
//! Limine 给的地址只用来**实测对账**它和 `HHDM + pa` 到底是什么关系——
//! BACKLOG §229 二里"Limine 已给 framebuffer"这句话在本片之前没有代码兑现，本片要把它证真或证伪。
//!
//! **像素写入全部走 `MmioRegion` 的带检查访问器**（`write32`/`read32` 自己判偏移对齐与区间），
//! 所以本文件**零新增 unsafe 站点**，也就不进 unsafe 白名单——这是刻意选的：
//! 驱动侧一旦自己拿裸指针，越界就得靠人记；交给已经在 AHCI/virtio 那条路上被证过的闸。
//!
//! 串口仍是权威判据通道：本模块只往显存写字，**不**替代 `serial`，也不改它的任何字节。

use alloc::vec::Vec;

use crate::hw::{self, MmioRegion};
use crate::limine::{self, FbInfo};

/// 只支持 32bpp：24/16bpp 的打包要按掩码重排字节序，画错了不会报错、只会静默变色，
/// 那种"看起来出画面了"的结论本仓库不收（AGENTS 硬约束⑦）。
const SUPPORTED_BPP: u16 = 32;
/// `LIMINE_FRAMEBUFFER_RGB`
const MEMORY_MODEL_RGB: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// 启动信息里没有 framebuffer：请求没被满足，或 memmap 没有 Framebuffer 条目
    NotProvided,
    /// 模式不支持（非 32bpp 或非 RGB 内存模型）。值带出来，别让红因变成一句话
    UnsupportedMode { bpp: u16, memory_model: u8 },
    /// 几何自相矛盾：`height * pitch` 超出 memmap 那段区间
    BadGeometry { need: u64, have: u64, pitch: u64, height: u64 },
    /// 像素坐标落在屏幕外
    OutOfBounds { x: u64, y: u64, width: u64, height: u64 },
    /// 映射本身失败（VA 保留不够、落在大页里等）
    Map(hw::HwError),
}

/// 一个已映射、已核对过几何的帧缓冲。
pub struct Frame {
    region: MmioRegion,
    info: FbInfo,
    /// memmap 里那段物理区间，映射的就是它
    pa: u64,
    len: u64,
    /// Limine 给的 address **等于** `HHDM + pa` 吗（实测出来的，不是假设）
    limine_is_hhdm: bool,
    /// Limine 给的 address **等于** 我们刚映射出来的那个 VA 吗
    limine_is_ours: bool,
    /// Limine 给的 address 在**我们自己的页表**里映着吗。这一格是实测出来的
    /// （`mm::is_mapped` 走的是换过 CR3 之后的那棵树），不是从"那是它的映射"推出来的。
    limine_mapped_in_ours: bool,
}

impl Frame {
    /// 取启动信息、校验几何、映射窗口。任何一步不成立都**返回错误**，不"先画了再说"。
    pub fn init() -> Result<Self, FrameError> {
        let info = limine::framebuffer().ok_or(FrameError::NotProvided)?;
        let (pa, len) = limine::framebuffer_memmap().ok_or(FrameError::NotProvided)?;
        if info.bpp != SUPPORTED_BPP || info.memory_model != MEMORY_MODEL_RGB {
            return Err(FrameError::UnsupportedMode { bpp: info.bpp, memory_model: info.memory_model });
        }
        // 要映射的是"每一行 pitch 字节 × height 行"，不是 width*height*4：
        // pitch 比行宽大的时候，按后者算会少映射，于是最后一列的写入落在窗口外。
        let need = info.pitch.checked_mul(info.height).ok_or(FrameError::BadGeometry {
            need: u64::MAX,
            have: len,
            pitch: info.pitch,
            height: info.height,
        })?;
        if info.width == 0 || info.height == 0 || info.pitch < info.width * 4 || need > len {
            return Err(FrameError::BadGeometry { need, have: len, pitch: info.pitch, height: info.height });
        }
        let pages = ((need + (crate::mm::PAGE as u64 - 1)) / crate::mm::PAGE as u64) as usize;
        let region = MmioRegion::map(pa, (pages * crate::mm::PAGE) as usize).map_err(FrameError::Map)?;
        // 对账：Limine 的地址与 HHDM+pa、与我们自己映射的 VA 各差多少。
        // 只测量、不据此决定要不要映射——映射已经按物理区间做了。
        let hhdm = crate::limine::hhdm_offset();
        let ours = region.base();
        let limine_is_hhdm = hhdm != 0 && info.limine_address == hhdm + pa;
        let limine_is_ours = info.limine_address == ours;
        // **不 deref 那个地址去"试试看"**：§236 记过顺着叶子 deref 把内核打挂的现场
        // （run-943，cr2 落在 RAM 之外）。问页表要答案，不要问硬件。
        let limine_mapped_in_ours = crate::mm::is_mapped(info.limine_address);
        Ok(Self { region, info, pa, len, limine_is_hhdm, limine_is_ours, limine_mapped_in_ours })
    }

    pub fn geom(&self) -> (u64, u64, u64) {
        (self.info.width, self.info.height, self.info.pitch)
    }

    /// (物理基址, memmap 长度, Limine 给的原样地址, 我们的窗口基址)——日志与对账都要用。
    pub fn addrs(&self) -> (u64, u64, u64, u64) {
        (self.pa, self.len, self.info.limine_address, self.region.base())
    }

    /// Limine 地址与两种"应该等于"的关系读数。
    /// (== HHDM+pa, == 我们的窗口, 在我们自己的页表里映着)
    pub fn limine_relation(&self) -> (bool, bool, bool) {
        (self.limine_is_hhdm, self.limine_is_ours, self.limine_mapped_in_ours)
    }

    pub fn masks(&self) -> [(u8, u8); 3] {
        self.info.masks
    }

    /// 按启动信息报出的掩码打包 24 位 RGB。
    ///
    /// 为什么按掩码算而不是硬写 `0xFF0000` 当红：字段宽度不足 8 位时高位要丢掉，
    /// 而移位量是 bootloader/固件给的——不同机器上 BGRA 与 RGBX 都出现过。
    /// 硬编码的结果是"画出来了但颜色不对"，那种错不会让任何判据变红。
    fn pack(&self, rgb: u32) -> u32 {
        let mut v = 0u32;
        for (i, &channel) in [rgb >> 16, rgb >> 8, rgb].iter().enumerate() {
            let (size, shift) = (u32::from(self.info.masks[i].0), u32::from(self.info.masks[i].1));
            if size == 0 || shift >= 32 {
                continue;
            }
            let keep = size.min(8);
            // 先掩到 8 位，再右移到字段宽度。**这一掩不能省**：`channel` 是 `rgb >> k`，
            // 高位还留着别的通道。8/8/8 这块屏上"不掩"恰好也得对（每个字段写进去的都是
            // 原值的高位前缀，OR 起来仍是原值——四个采样点逐位相同），
            // 但换 5/6/5 的面板就会串色，而串色不会让任何判据变红。
            let dropped = (channel & 0xFF) >> (8 - keep);
            let left = size.saturating_sub(8);
            v |= (dropped << left) << shift;
        }
        v
    }

    /// 24 位 RGB → 这台机器的原生像素值。读回对账要拿它比，
    /// **不能拿 24 位值直接比 `get()`**：掩码不是 16/8/0 时两者天然不等，那种"红"是量具错。
    pub fn packed(&self, rgb: u32) -> u32 {
        self.pack(rgb)
    }

    /// 写一个像素。越界返回错误（**不夹到边界**：夹了就是把调用方的 bug 藏起来）。
    pub fn put(&self, x: u64, y: u64, rgb: u32) -> Result<(), FrameError> {
        if x >= self.info.width || y >= self.info.height {
            return Err(FrameError::OutOfBounds { x, y, width: self.info.width, height: self.info.height });
        }
        let off = (y * self.info.pitch + x * 4) as usize;
        self.region.write32(off, self.pack(rgb)).map_err(FrameError::Map)
    }

    /// 读回一个像素。**注意这只证明"我们写的字节还在我们映射的窗口里"**，
    /// 不证明设备把它显示出来了——后者由宿主机侧的 PPM 对账负责（第二台仪器）。
    pub fn get(&self, x: u64, y: u64) -> Result<u32, FrameError> {
        if x >= self.info.width || y >= self.info.height {
            return Err(FrameError::OutOfBounds { x, y, width: self.info.width, height: self.info.height });
        }
        let off = (y * self.info.pitch + x * 4) as usize;
        self.region.read32(off).map_err(FrameError::Map)
    }

    pub fn fill(&self, rgb: u32) -> Result<(), FrameError> {
        for y in 0..self.info.height {
            for x in 0..self.info.width {
                self.put(x, y, rgb)?;
            }
        }
        Ok(())
    }

    /// 画一张**宿主机可以独立复算**的图案：上半全黑，下半从左到右三个等宽色条
    /// （红 / 绿 / 蓝）。取样点由几何算出，不写死分辨率。
    ///
    /// 为什么是这种图案：它只需要五个采样点就能判"画面到底是不是我们画的那张"，
    /// 而且任何一处画错（错位、pitch 用错、字节序反了）都会至少打到其中一点。
    pub fn draw_test_pattern(&self) -> Result<(), FrameError> {
        let (w, h, _) = self.geom();
        self.fill(0x00_00_00)?;
        let band = h / 2;
        for y in band..h {
            for x in 0..w {
                let third = x * 3 / w;
                let rgb = match third {
                    0 => 0xFF_00_00,
                    1 => 0x00_FF_00,
                    _ => 0x00_00_FF,
                };
                self.put(x, y, rgb)?;
            }
        }
        Ok(())
    }

    /// 图案上应当出现的采样点：`(名字, x, y, 期望 RGB)`。
    /// 宿主机侧用同一份算法从 PPM 里取样对账——**两边各自算，不是互相抄**。
    pub fn samples(&self) -> Vec<(&'static str, u64, u64, u32)> {
        let (w, h, _) = self.geom();
        let mut v = Vec::new();
        v.push(("上左黑", w / 6, h / 4, 0x00_00_00));
        v.push(("下左红", w / 6, h - h / 4, 0xFF_00_00));
        v.push(("下中绿", w / 2, h - h / 4, 0x00_FF_00));
        v.push(("下右蓝", w - w / 6, h - h / 4, 0x00_00_FF));
        v
    }
}