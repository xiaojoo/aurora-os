//! 图形设备层（ADR-239）。
//!
//! ## 与 `display/frame.rs` 的分工
//!
//! | 文件 | 知道什么 |
//! |---|---|
//! | `frame.rs` | 像素怎么落到**一块已映射的显存**（几何、掩码、越界、双缓冲）|
//! | `fbcon.rs` | 字符怎么变成像素（字形、双宽格、浮窗）|
//! | **本文件** | **哪块显存、什么格式、能力有哪些** |
//!
//! 三者是**一层不许越过另一层**的关系：`Frame` 现在直接从 Limine 启动信息取帧缓冲，
//! 而本层要做的是「从**设备**取」，这样同一套 `Frame`/`fbcon` 能用在 Limine 之外。
//!
//! ## 今天做到哪
//!
//! **只做能力探测与格式推导**，不写任何寄存器、不做模式设置。
//! 与 USB 切片（ADR-208 先做 TRB 字节层）同一个思路：先让字节层可证，再接硬件。

/// 一个图形设备的**能力描述**（ADR-239）。
///
/// 它是 `Frame` 与真实设备之间的契约：`Frame` 只问「给我宽高/pitch/格式」，
/// 不关心是 Limine 的帧缓冲、VGA、还是 virtio-gpu。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModeInfo {
    pub width: u32,
    pub height: u32,
    /// 每行字节数（**可能大于 `width * bytes_per_pixel`**，行对齐）。
    pub pitch: u32,
    pub bpp: u16,
    /// 内存模型：1 = RGB（`Frame` 只支持这个）。
    pub memory_model: u8,
}

/// `ModeInfo` 的自洽性错误（ADR-239）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeError {
    /// 宽或高为 0。
    ZeroSize,
    /// `bpp` 为 0（会让 `bytes_per_pixel` 变成 0，后面除零）。
    ZeroBpp,
    /// `bpp` 不是 8 的整数倍（`bpp / 8` 会截断）。
    BppNotByteMultiple(u16),
    /// `pitch` 小于 `width * bytes_per_pixel` —— 行放不下。
    PitchTooSmall { pitch: u32, need: u32 },
    /// 内存模型不是 RGB。
    NotRgb(u8),
}

impl ModeInfo {
    /// 每像素字节数。**`bpp` 不是 8 的倍数时回 `None`**（不截断）。
    pub fn bytes_per_pixel(&self) -> Option<u32> {
        if self.bpp == 0 || self.bpp % 8 != 0 {
            return None;
        }
        Some(u32::from(self.bpp / 8))
    }

    /// 一行**真正**需要的字节数（`width * bytes_per_pixel`，不含行对齐）。
    pub fn row_bytes(&self) -> Option<u32> {
        self.width.checked_mul(self.bytes_per_pixel()?)
    }

    /// 整块显存需要多少字节（`pitch * height`）。
    pub fn fb_bytes(&self) -> Option<u64> {
        u64::from(self.pitch).checked_mul(u64::from(self.height))
    }

    /// **自洽性检查**（ADR-239）。
    ///
    /// 顺序有意义：先排除「除零」，再排除「行放不下」，最后排除「格式不支持」。
    /// 一个 `bpp=0` 的坏描述不该被报成「内存模型不对」。
    pub fn validate(&self) -> Result<(), ModeError> {
        if self.width == 0 || self.height == 0 {
            return Err(ModeError::ZeroSize);
        }
        if self.bpp == 0 {
            return Err(ModeError::ZeroBpp);
        }
        if self.bpp % 8 != 0 {
            return Err(ModeError::BppNotByteMultiple(self.bpp));
        }
        // **不用 `ok_or(ZeroBpp)` 兜底**（ADR-239 实测）：
        //
        // 第一版是 `self.row_bytes().ok_or(ModeError::ZeroBpp)?` —— 那是错的：
        // 它让「`bpp == 0`」与「`bpp` 非 8 倍数」在**删除前面的显式检查之后**
        // 仍然回同一个错误码，于是负样本咬不动（实测：去掉 `bpp == 0` 检查后判据全绿）。
        //
        // 现在走到这里时 `bpp` 已保证非 0 且是 8 的倍数，`row_bytes()` 只可能是 `Some`。
        // 用 `expect` 把它写成**不变量**而不是错误分支 —— 若它真回 `None`，那是本函数的 bug，
        // 该在开发期炸掉而不是伪装成 `ZeroBpp`。
        let row = self
            .row_bytes()
            .expect("bpp 已校验为非 0 且 8 的倍数，row_bytes 必然可算");
        if self.pitch < row {
            return Err(ModeError::PitchTooSmall { pitch: self.pitch, need: row });
        }
        if self.memory_model != 1 {
            return Err(ModeError::NotRgb(self.memory_model));
        }
        Ok(())
    }
}

/// 一个图形设备的**身份**（ADR-239）。
///
/// 用 PCI `(vendor, device)` 而不是型号字符串：前者是设备自己报的，后者要维护一张表。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuKind {
    /// QEMU 的 `std` VGA（`1234:1111`，Bochs 兼容）。
    Bochs,
    /// Cirrus CLGD 54xx（`1013:00b8`）。
    Cirrus,
    /// QXL（`1b36:0100`）。
    Qxl,
    /// virtio-gpu（`1af4:1050`）。
    VirtioGpu,
    /// 认得出是显示类（class 0x03）但型号不认识。
    UnknownDisplay,
}

impl GpuKind {
    /// **按 PCI ID 识别**（ADR-239）。
    ///
    /// 不认识的显示类设备回 `UnknownDisplay`，**不回 `None`** ——
    /// 「这是块显卡但我不认识」与「这不是显卡」是两件事，
    /// 前者要能被计数（判据要看见它），后者直接跳过。
    pub const fn from_ids(vendor: u16, device: u16, class: u8) -> Option<Self> {
        match (vendor, device) {
            (0x1234, 0x1111) => Some(Self::Bochs),
            (0x1013, 0x00B8) => Some(Self::Cirrus),
            (0x1B36, 0x0100) => Some(Self::Qxl),
            (0x1AF4, 0x1050) => Some(Self::VirtioGpu),
            _ => {
                if class == 0x03 {
                    Some(Self::UnknownDisplay)
                } else {
                    None
                }
            }
        }
    }

    /// 这个名字进日志与判据。
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bochs => "bochs",
            Self::Cirrus => "cirrus",
            Self::Qxl => "qxl",
            Self::VirtioGpu => "virtio-gpu",
            Self::UnknownDisplay => "unknown-display",
        }
    }
}

/// Bochs/QEMU-std VGA 的寄存器偏移（ADR-239）。
///
/// 只列**读**的那几个：今天不做模式设置，所以不碰写。
pub const BOCHS_REG_ID: usize = 0x500;
pub const BOCHS_REG_XRES: usize = 0x504;
pub const BOCHS_REG_YRES: usize = 0x508;
pub const BOCHS_REG_BPP: usize = 0x50C;

/// Bochs 的 `ID` 寄存器读回值（`0xB0C0` 是「Bochs VBE 扩展存在」）。
pub const BOCHS_ID_MAGIC: u32 = 0xB0C0;

/// **从 Bochs 的三个寄存器值构造 `ModeInfo`**（ADR-239 的核心纯函数）。
///
/// ## 为什么 `pitch` 要自己算
///
/// Bochs 的 `XRES` 只是像素宽，**没有 pitch 寄存器**。而 Bochs 的 pitch 固定是
/// `xres * bpp/8` 再按 4 字节对齐 —— 这是它的实现细节，不是协议字段。
///
/// 所以这里按「`xres * bytes_per_pixel` 再对齐到 4」算，并把结果交给 `validate` 复核。
pub fn bochs_mode(xres: u32, yres: u32, bpp: u16) -> ModeInfo {
    let bytes_pp = if bpp >= 8 { u32::from(bpp / 8) } else { 0 };
    let raw = xres.saturating_mul(bytes_pp);
    // 4 字节对齐（Bochs 的实现），向上取整
    let pitch = raw.saturating_add(3) & !3;
    ModeInfo { width: xres, height: yres, pitch, bpp, memory_model: 1 }
}
