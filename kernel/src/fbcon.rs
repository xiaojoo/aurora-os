//! S6b：文本→像素的机制，加一条**冻结契约**让画面有确定的静止时刻。
//!
//! **为什么需要冻结契约**：图案只要被第二次写入，"可以取 PPM 的那一刻"就不存在了——
//! 宿主机一边取，内核一边滚，对账会莫名其妙地红。所以本模块带一个一次性闸门 [`FROZEN`]：
//! `freeze_band()` 一旦调用，之后所有写入都是 no-op。内核在冻结之后**必须**在串口上打
//! `fbcon: 已冻结 …`，宿主机以这行为准再 dump。契约的两端都是可测的：
//! 串口少了这一行 ⇒ 夹具等不到就绪；画面还在变 ⇒ 同一张 PPM 两次采样不一致。
//!
//! **字形是一份资产，不是一个公式**（S6e / ADR-086）：S6b 时期 [`glyph`] 由码点的一个
//! 算术公式算出，结果是 95 个可打印 ASCII 只落在 **5 种** 8×8 图样上（每格约 2.3 bit）——
//! 画面"画得出"但**读不出**，连"某一行是不是某段文本"都没法从像素判。
//! 现在换成 95 个字符各一张 5×7 点阵（`kernel/assets/font8x8.art` 是稿，
//! 本文件的 [`FONT`] 由它生成），于是"可读"可以变成可复算的判据：
//! 图样两两不同、除空格外没有空白字形、以及宿主机按同一张表把真实画面**读回文本**。
//!
//! 本文件零 `unsafe`：所有像素写入都走 [`crate::frame::Frame::put`]，越界由它判。

use alloc::string::String;

use crate::frame::Frame;
use core::sync::atomic::{AtomicBool, Ordering};

/// 字符栅格：8×8 像素一格。选 8×8 是因为 `glyph()` 每行一个字节，没有跨字节的拼接分支。
pub const CELL_W: u64 = 8;
pub const CELL_H: u64 = 8;
/// 冻结带占底部几行（行号从 `rows - BAND_ROWS` 起）。
pub const BAND_ROWS: u64 = 2;
/// 冻结带上写的内容。**改了这里要同步改夹具里的期望**——两边各自独立算，不互相抄。
pub const BAND_TEXT: &str = "AURORA S6B FREEZE 0123456789";

/// 冻结闸门。一旦置位，`print` / `scroll` 全部变 no-op。
/// 用原子量而不是锁：本模块只在启动阶段单线程用，而"冻结之后不许再写"这件事
/// 不该依赖调用顺序正确才对得上。
static FROZEN: AtomicBool = AtomicBool::new(false);

/// 一块终端画面。`cols * rows` 由帧缓冲几何推出来，**不写死分辨率**。
pub struct Term {
    cols: u64,
    rows: u64,
}

/// 可读字形表：95 个可打印 ASCII（`0x20..=0x7E`），每格 8 行 × 5 列。
///
/// 列的位置：第 0 列落在 **bit6**、第 4 列落在 **bit2**，`bit7` 与 `bit1..0` 恒 0
/// ⇒ 字形右侧留一列白边，相邻字符不会粘在一起；第 7 行留给 `g/j/p/q/y` 的下伸部。
/// **表由 `kernel/assets/font8x8.art` 生成**（`build/_s6e_font.py`，两处逐字节对账由夹具做），
/// 不要手改这里：改了稿才对得上。
const FONT: [[u8; 8]; 95] = [
    // 0x20 空格
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 0x21 !
    [0x10, 0x10, 0x10, 0x10, 0x10, 0x00, 0x10, 0x00],
    // 0x22 双引号
    [0x28, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 0x23 #
    [0x28, 0x28, 0x7C, 0x28, 0x7C, 0x28, 0x28, 0x00],
    // 0x24 $
    [0x10, 0x3C, 0x50, 0x38, 0x14, 0x78, 0x10, 0x00],
    // 0x25 %
    [0x64, 0x68, 0x10, 0x20, 0x4C, 0x0C, 0x00, 0x00],
    // 0x26 &
    [0x30, 0x48, 0x50, 0x20, 0x54, 0x48, 0x34, 0x00],
    // 0x27 撇号
    [0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 0x28 (
    [0x08, 0x10, 0x20, 0x20, 0x20, 0x10, 0x08, 0x00],
    // 0x29 )
    [0x20, 0x10, 0x08, 0x08, 0x08, 0x10, 0x20, 0x00],
    // 0x2A *
    [0x00, 0x54, 0x38, 0x7C, 0x38, 0x54, 0x00, 0x00],
    // 0x2B +
    [0x00, 0x10, 0x10, 0x7C, 0x10, 0x10, 0x00, 0x00],
    // 0x2C ,
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10, 0x20],
    // 0x2D -
    [0x00, 0x00, 0x00, 0x7C, 0x00, 0x00, 0x00, 0x00],
    // 0x2E .
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00],
    // 0x2F /
    [0x04, 0x08, 0x08, 0x10, 0x20, 0x20, 0x40, 0x00],
    // 0x30 0
    [0x38, 0x44, 0x4C, 0x54, 0x64, 0x44, 0x38, 0x00],
    // 0x31 1
    [0x10, 0x30, 0x10, 0x10, 0x10, 0x10, 0x38, 0x00],
    // 0x32 2
    [0x38, 0x44, 0x04, 0x08, 0x10, 0x20, 0x7C, 0x00],
    // 0x33 3
    [0x78, 0x04, 0x04, 0x38, 0x04, 0x04, 0x78, 0x00],
    // 0x34 4
    [0x08, 0x18, 0x28, 0x48, 0x7C, 0x08, 0x08, 0x00],
    // 0x35 5
    [0x7C, 0x40, 0x78, 0x04, 0x04, 0x44, 0x38, 0x00],
    // 0x36 6
    [0x38, 0x40, 0x40, 0x78, 0x44, 0x44, 0x38, 0x00],
    // 0x37 7
    [0x7C, 0x04, 0x08, 0x10, 0x20, 0x20, 0x20, 0x00],
    // 0x38 8
    [0x38, 0x44, 0x44, 0x38, 0x44, 0x44, 0x38, 0x00],
    // 0x39 9
    [0x38, 0x44, 0x44, 0x3C, 0x04, 0x04, 0x38, 0x00],
    // 0x3A :
    [0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00],
    // 0x3B ;
    [0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0x10, 0x20],
    // 0x3C <
    [0x08, 0x10, 0x20, 0x40, 0x20, 0x10, 0x08, 0x00],
    // 0x3D =
    [0x00, 0x00, 0x7C, 0x00, 0x7C, 0x00, 0x00, 0x00],
    // 0x3E >
    [0x20, 0x10, 0x08, 0x04, 0x08, 0x10, 0x20, 0x00],
    // 0x3F ?
    [0x38, 0x44, 0x04, 0x08, 0x10, 0x00, 0x10, 0x00],
    // 0x40 @
    [0x38, 0x44, 0x5C, 0x54, 0x5C, 0x40, 0x38, 0x00],
    // 0x41 A
    [0x38, 0x44, 0x44, 0x7C, 0x44, 0x44, 0x44, 0x00],
    // 0x42 B
    [0x78, 0x44, 0x44, 0x78, 0x44, 0x44, 0x78, 0x00],
    // 0x43 C
    [0x38, 0x44, 0x40, 0x40, 0x40, 0x44, 0x38, 0x00],
    // 0x44 D
    [0x78, 0x44, 0x44, 0x44, 0x44, 0x44, 0x78, 0x00],
    // 0x45 E
    [0x7C, 0x40, 0x40, 0x78, 0x40, 0x40, 0x7C, 0x00],
    // 0x46 F
    [0x7C, 0x40, 0x40, 0x78, 0x40, 0x40, 0x40, 0x00],
    // 0x47 G
    [0x38, 0x44, 0x40, 0x5C, 0x44, 0x44, 0x38, 0x00],
    // 0x48 H
    [0x44, 0x44, 0x44, 0x7C, 0x44, 0x44, 0x44, 0x00],
    // 0x49 I
    [0x7C, 0x10, 0x10, 0x10, 0x10, 0x10, 0x7C, 0x00],
    // 0x4A J
    [0x1C, 0x08, 0x08, 0x08, 0x08, 0x48, 0x30, 0x00],
    // 0x4B K
    [0x44, 0x48, 0x50, 0x60, 0x50, 0x48, 0x44, 0x00],
    // 0x4C L
    [0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x7C, 0x00],
    // 0x4D M
    [0x44, 0x6C, 0x54, 0x44, 0x44, 0x44, 0x44, 0x00],
    // 0x4E N
    [0x44, 0x64, 0x54, 0x4C, 0x44, 0x44, 0x44, 0x00],
    // 0x4F O
    [0x38, 0x44, 0x44, 0x44, 0x44, 0x44, 0x38, 0x00],
    // 0x50 P
    [0x78, 0x44, 0x44, 0x78, 0x40, 0x40, 0x40, 0x00],
    // 0x51 Q
    [0x38, 0x44, 0x44, 0x44, 0x54, 0x48, 0x34, 0x00],
    // 0x52 R
    [0x78, 0x44, 0x44, 0x78, 0x50, 0x48, 0x44, 0x00],
    // 0x53 S
    [0x3C, 0x40, 0x40, 0x38, 0x04, 0x04, 0x78, 0x00],
    // 0x54 T
    [0x7C, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x00],
    // 0x55 U
    [0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x38, 0x00],
    // 0x56 V
    [0x44, 0x44, 0x44, 0x44, 0x44, 0x28, 0x10, 0x00],
    // 0x57 W
    [0x44, 0x44, 0x44, 0x54, 0x54, 0x6C, 0x44, 0x00],
    // 0x58 X
    [0x44, 0x44, 0x28, 0x10, 0x28, 0x44, 0x44, 0x00],
    // 0x59 Y
    [0x44, 0x44, 0x28, 0x10, 0x10, 0x10, 0x10, 0x00],
    // 0x5A Z
    [0x7C, 0x04, 0x08, 0x10, 0x20, 0x40, 0x7C, 0x00],
    // 0x5B [
    [0x1C, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1C, 0x00],
    // 0x5C 反斜杠
    [0x40, 0x20, 0x20, 0x10, 0x08, 0x08, 0x04, 0x00],
    // 0x5D ]
    [0x70, 0x10, 0x10, 0x10, 0x10, 0x10, 0x70, 0x00],
    // 0x5E 脱字符
    [0x10, 0x28, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 0x5F _
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7C],
    // 0x60 反引号
    [0x20, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 0x61 a
    [0x00, 0x00, 0x38, 0x04, 0x3C, 0x44, 0x3C, 0x00],
    // 0x62 b
    [0x40, 0x40, 0x78, 0x44, 0x44, 0x44, 0x78, 0x00],
    // 0x63 c
    [0x00, 0x00, 0x38, 0x40, 0x40, 0x40, 0x38, 0x00],
    // 0x64 d
    [0x04, 0x04, 0x38, 0x44, 0x44, 0x44, 0x38, 0x00],
    // 0x65 e
    [0x00, 0x00, 0x38, 0x44, 0x7C, 0x40, 0x38, 0x00],
    // 0x66 f
    [0x18, 0x20, 0x20, 0x78, 0x20, 0x20, 0x20, 0x00],
    // 0x67 g
    [0x00, 0x00, 0x38, 0x44, 0x44, 0x38, 0x04, 0x38],
    // 0x68 h
    [0x40, 0x40, 0x78, 0x44, 0x44, 0x44, 0x44, 0x00],
    // 0x69 i
    [0x10, 0x00, 0x30, 0x10, 0x10, 0x10, 0x38, 0x00],
    // 0x6A j
    [0x08, 0x00, 0x18, 0x08, 0x08, 0x08, 0x48, 0x30],
    // 0x6B k
    [0x40, 0x40, 0x48, 0x50, 0x60, 0x50, 0x48, 0x00],
    // 0x6C l
    [0x30, 0x10, 0x10, 0x10, 0x10, 0x10, 0x38, 0x00],
    // 0x6D m
    [0x00, 0x00, 0x68, 0x54, 0x54, 0x54, 0x54, 0x00],
    // 0x6E n
    [0x00, 0x00, 0x78, 0x44, 0x44, 0x44, 0x44, 0x00],
    // 0x6F o
    [0x00, 0x00, 0x38, 0x44, 0x44, 0x44, 0x38, 0x00],
    // 0x70 p
    [0x00, 0x00, 0x78, 0x44, 0x44, 0x78, 0x40, 0x40],
    // 0x71 q
    [0x00, 0x00, 0x38, 0x44, 0x44, 0x38, 0x04, 0x04],
    // 0x72 r
    [0x00, 0x00, 0x58, 0x60, 0x40, 0x40, 0x40, 0x00],
    // 0x73 s
    [0x00, 0x00, 0x3C, 0x40, 0x38, 0x04, 0x78, 0x00],
    // 0x74 t
    [0x20, 0x20, 0x78, 0x20, 0x20, 0x20, 0x18, 0x00],
    // 0x75 u
    [0x00, 0x00, 0x44, 0x44, 0x44, 0x44, 0x38, 0x00],
    // 0x76 v
    [0x00, 0x00, 0x44, 0x44, 0x44, 0x28, 0x10, 0x00],
    // 0x77 w
    [0x00, 0x00, 0x44, 0x44, 0x54, 0x54, 0x28, 0x00],
    // 0x78 x
    [0x00, 0x00, 0x44, 0x28, 0x10, 0x28, 0x44, 0x00],
    // 0x79 y
    [0x00, 0x00, 0x44, 0x44, 0x44, 0x38, 0x04, 0x38],
    // 0x7A z
    [0x00, 0x00, 0x7C, 0x08, 0x10, 0x20, 0x7C, 0x00],
    // 0x7B {
    [0x08, 0x10, 0x10, 0x20, 0x10, 0x10, 0x08, 0x00],
    // 0x7C 竖线
    [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x00],
    // 0x7D }
    [0x20, 0x10, 0x10, 0x08, 0x10, 0x10, 0x20, 0x00],
    // 0x7E 波浪号
    [0x00, 0x00, 0x34, 0x48, 0x00, 0x00, 0x00, 0x00],
];

/// 取一个字符的 8 行点阵（bit6..bit2 是 5 个像素，bit7 是最左那一列白边）。
///
/// 表外字符（控制字符、非 ASCII）画成 `?`：**不静默画空白**——空白会把"根本没渲染"
/// 伪装成一个空格，而空格在画面上是合法内容。
pub fn glyph(ch: char) -> [u8; 8] {
    let c = ch as u32;
    if !(0x20..=0x7E).contains(&c) {
        return FONT[(b'?' as usize) - 0x20];
    }
    FONT[(c as usize) - 0x20]
}

/// 前景色：与测试图案的三条带都不同，于是"画在带上的字"和"带本身"分得开。
const FG: u32 = 0xFF_FF_FF;
const BG: u32 = 0x00_00_00;

impl Term {
    /// 按帧缓冲的几何开一块终端。几何小到放不下一个字符时返回 `None`
    /// （不"缩着画"：那会让 `cols` 与夹具算的不一样，红因会变成对账而不是容量）。
    pub fn new(f: &Frame) -> Option<Term> {
        let (w, h, _) = f.geom();
        if w < CELL_W * 8 || h < CELL_H * (BAND_ROWS + 2) {
            return None;
        }
        Some(Self { cols: w / CELL_W, rows: h / CELL_H })
    }

    pub fn dims(&self) -> (u64, u64) {
        (self.cols, self.rows)
    }

    /// 正文区能放几行（冻结带不算）。实时重画用它来定窗口，不在调用方写死分辨率。
    pub fn body_rows(&self) -> usize {
        (self.rows - BAND_ROWS) as usize
    }

    pub fn frozen() -> bool {
        FROZEN.load(Ordering::Acquire)
    }

    /// 画一个字符。冻结之后是 no-op（返回 false 表示"没画"，调用方可以据此数账）。
    pub fn put_cell(&self, f: &Frame, col: u64, row: u64, ch: char) -> bool {
        if Self::frozen() || col >= self.cols || row >= self.rows {
            return false;
        }
        for (i, bits) in glyph(ch).iter().enumerate() {
            for j in 0..8usize {
                let on = bits & (1u8 << (7 - j)) != 0;
                // 单点写失败不能吞：几何是启动信息给的，越界说明上面哪一步算错了
                if f.put(col * CELL_W + j as u64, row * CELL_H + i as u64, if on { FG } else { BG }).is_err() {
                    return false;
                }
            }
        }
        true
    }

    /// 写一行文本（占一整行、末尾补空格）。返回实际写出的字符格数。
    pub fn print_line(&self, f: &Frame, row: u64, s: &str) -> usize {
        if Self::frozen() {
            return 0;
        }
        let mut n = 0;
        for (i, ch) in s.chars().enumerate().take(self.cols as usize) {
            if self.put_cell(f, i as u64, row, ch) {
                n = i + 1;
            }
        }
        // 行尾补空格：不补的话上一行的残留像素会变成"下一行也画对了"的假证人
        for i in n..self.cols as usize {
            self.put_cell(f, i as u64, row, ' ');
        }
        n
    }

    /// 在正文区（`0 .. rows-BAND_ROWS`）画满确定性内容。返回画了多少行。
    ///
    /// **这里没有滚动**：滚动属于"真镜像日志"那一步（本片还没做），
    /// 现在正文是一次性写完的，所以不需要往上挪。
    pub fn fill_body(&self, f: &Frame) -> u64 {
        let body = self.rows - BAND_ROWS;
        for r in 0..body {
            let mut line = String::new();
            for c in 0..self.cols {
                // 内容由 (行, 列) 唯一决定 ⇒ 宿主机可以原样复算，不需要看内核的脸色
                line.push(char::from(b'A' + (((r * self.cols + c) % 26) as u8)));
            }
            self.print_line(f, r, &line);
        }
        body
    }

    /// 正文区整体上移**一个字符行**（只搬正文区，冻结带不参与）。
    ///
    /// 逐像素搬：`get` 拿原生打包值、`put_raw` 写回去，中间不做任何色彩转换。
    /// 不"只搬最后几行"糊弄——那会让"滚动了"这件事只有日志证人、没有像素证人。
    pub fn scroll_up(&self, f: &Frame) -> bool {
        if Self::frozen() {
            return false;
        }
        let top = 0u64;
        let bottom = (self.rows - BAND_ROWS) * CELL_H;   // 正文区底边（不含冻结带）
        for y in top..bottom - CELL_H {
            for x in 0..self.cols * CELL_W {
                match f.get(x, y + CELL_H) {
                    Ok(v) => { if f.put_raw(x, y, v).is_err() { return false; } }
                    Err(_) => return false,
                }
            }
        }
        // 腾出来的最后一行刷成背景，否则旧内容会在底部留一层"看起来像上一行"的残影
        for y in bottom - CELL_H..bottom {
            for x in 0..self.cols * CELL_W {
                if f.put_raw(x, y, BG).is_err() { return false; }
            }
        }
        true
    }

    /// 滚动一行，再把文本画在正文区最后一行。返回画出的字符格数。
    pub fn print_scrolled(&self, f: &Frame, s: &str) -> usize {
        if Self::frozen() {
            return 0;
        }
        if !self.scroll_up(f) {
            return 0;
        }
        self.print_line(f, self.rows - BAND_ROWS - 1, s)
    }

    /// 落冻结契约：把 [`BAND_TEXT`] 写进底部带，然后**永久闸门**关上。
    /// 返回 (带首行行号, 实际写出的格数)。调用方必须在串口上打一行"已冻结"给宿主机看。
    pub fn freeze_band(&self, f: &Frame) -> (u64, usize) {
        let top = self.rows - BAND_ROWS;
        // 先把带刷成纯背景，免得正文残留混进来让"命中"变成巧合
        for r in top..self.rows {
            self.print_line(f, r, "");
        }
        let mut wrote = 0usize;
        for (i, ch) in BAND_TEXT.chars().enumerate() {
            if i as u64 >= self.cols {
                break;
            }
            // 带还没冻结，所以 print 照常走；闸门在最后一步才关
            if self.put_cell(f, i as u64, top, ch) {
                wrote += 1;
            }
        }
        FROZEN.store(true, Ordering::Release);
        (top, wrote)
    }

    /// 冻结带首行的像素左上角（宿主机按同一个数去 PPM 里取样）。
    pub fn band_origin(&self) -> (u64, u64) {
        (0, (self.rows - BAND_ROWS) * CELL_H)
    }
}

// ------------------------------------------------------------------ S6d 实时重画
//
/// **整窗重画**：把环里最后 `max_lines` 条完整行直接刷到正文区第 0.. 行，返回**有内容的行数**。
///
/// 与 [`drain_and_draw`] 的三点差别，每点都是"可重复调用"要求的：
/// 1. 不滚动，按行号直写 ⇒ 第 N 次调用与第 1 次调用画的是同一件事，宿主机可以任意时刻取样；
/// 2. **一个字都不打印**：每轮打一行会把 §245 那套按行序读的判据搅掉（而实时重画一轮都不打才成立）；
/// 3. 没画到的行也刷成空行：`print_line` 行尾补空格 ⇒ 上一帧更靠下的内容不会留下残影当假证人。
pub fn redraw_window(term: &Term, f: &Frame, max_lines: usize) -> usize {
    let n = crate::serial::mirror_len();
    let wrapped = crate::serial::mirror_wrapped();
    let mut total = 1usize;
    for i in 0..n {
        if crate::serial::mirror_byte(i) == 10 {
            total += 1;
        }
    }
    let skip = total.saturating_sub(max_lines);
    let mut line = [0u8; 200];
    let mut len = 0usize;
    let mut idx = 0usize;
    let mut row = 0usize;
    for i in 0..n {
        let c = crate::serial::mirror_byte(i);
        if c == 10 {
            let fragment = wrapped && idx == 0;
            if idx >= skip && !fragment && row < max_lines {
                let mut ascii = [0u8; 200];
                let n2 = drawable(&line[..len], &mut ascii);
                let s = core::str::from_utf8(&ascii[..n2]).unwrap_or("");
                if term.print_line(f, row as u64, s) > 0 || len == 0 {
                    row += 1;
                }
            }
            len = 0;
            idx += 1;
        } else if len < line.len() {
            line[len] = c;
            len += 1;
        }
    }
    // 窗口里没被内容占满的行一律刷空：残影像素会被下一帧读成"那行还在"
    while row < max_lines {
        term.print_line(f, row as u64, "");
        row += 1;
    }
    row.min(max_lines)
}

// ------------------------------------------------------------------ S6b-3 消费端
//
/// 把日志环里**最后 `max_lines` 行**逐行滚动画上去，返回 `(窗口行数, 真画上去的行数)`。
///
/// **环住在 `serial`，这里只读** ⇒ 边保持 `display -> diagnostics` 单向，不造新环（§244）。
/// **不许开 `Vec`**：堆上限 `LARGE_MAX = 2048`，一次 8 KiB 的 `with_capacity` 第一下就走
/// `handle_alloc_error` ⇒ 整机 39（ADR-018/026）。所以两遍扫描 + 栈上 200 字节行缓冲，
/// 装满就截断——宁可少画几个字符也要有界。
pub fn drain_and_draw(term: &Term, f: &Frame, max_lines: usize) -> (usize, usize) {
    let n = crate::serial::mirror_len();
    let wrapped = crate::serial::mirror_wrapped();
    // 第一遍：只数换行，不分配、不画图
    let mut total = 1usize;
    for i in 0..n {
        if crate::serial::mirror_byte(i) == 10 {
            total += 1;
        }
    }
    let skip = total.saturating_sub(max_lines);
    let mut line = [0u8; 200];
    let mut len = 0usize;
    let mut idx = 0usize;
    let mut drawn = 0usize;
    for i in 0..n {
        let c = crate::serial::mirror_byte(i);
        if c == 10 {
            // 绕回处那一段是上一行的残片，不是完整日志行：丢掉它，否则画面上是一条半截日志
            let fragment = wrapped && idx == 0;
            if idx >= skip && !fragment {
                let mut ascii = [0u8; 200];
                let n2 = drawable(&line[..len], &mut ascii);
                let s = core::str::from_utf8(&ascii[..n2]).unwrap_or("");
                // 空行也占一次滚动，否则"画了 N 行"里的空行会谎报成内容行
                if term.print_scrolled(f, s) > 0 || len == 0 {
                    drawn += 1;
                }
            }
            len = 0;
            idx += 1;
        } else if len < line.len() {
            line[len] = c;
            len += 1;
        }
    }
    (total, drawn)
}

/// 把环里的一行原始字节变成**可画的 ASCII**：ASCII 原样，其余**每个字符一个** `?`。
///
/// **为什么按字符而不是按字节**：按字节替换会让一个汉字占 3 格，于是这一行在屏幕上的
/// 列位置与日志里那段文本的字符位置不再对齐——§245 那条"末行 == 最后一条日志正文"
/// 就会从第一个汉字之后整体错位。本轮实测：按字节的版本让那条判据出现 48/1344 像素不等，
/// 症状看起来像"字体画错了"，其实是**列对齐**错了。
///
/// 非法 UTF-8（环在环绕处或 200 字节上限处截断过一个多字节字符）走逐字节分支：
/// 那时对齐本来就无法保证，能保证的是"不 panic、不乱画"。
fn drawable(raw: &[u8], out: &mut [u8; 200]) -> usize {
    match core::str::from_utf8(raw) {
        Ok(s) => {
            let mut n = 0usize;
            for ch in s.chars() {
                if n >= out.len() {
                    break;
                }
                out[n] = if (ch as u32) < 0x80 { ch as u8 } else { b'?' };
                n += 1;
            }
            n
        }
        Err(_) => {
            let n = raw.len().min(out.len());
            for i in 0..n {
                out[i] = if raw[i] < 0x80 { raw[i] } else { b'?' };
            }
            n
        }
    }
}
