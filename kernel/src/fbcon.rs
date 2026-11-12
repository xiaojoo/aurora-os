//! S6b：文本→像素的机制，加一条**冻结契约**让画面有确定的静止时刻。
//!
//! **为什么需要冻结契约**：图案只要被第二次写入，"可以取 PPM 的那一刻"就不存在了——
//! 宿主机一边取，内核一边滚，对账会莫名其妙地红。所以本模块带一个一次性闸门 [`FROZEN`]：
//! `freeze_band()` 一旦调用，之后所有写入都是 no-op。内核在冻结之后**必须**在串口上打
//! `fbcon: 已冻结 …`，宿主机以这行为准再 dump。契约的两端都是可测的：
//! 串口少了这一行 ⇒ 夹具等不到就绪；画面还在变 ⇒ 同一张 PPM 两次采样不一致。
//!
//! **字形是什么、以及它现在不是什么**：本片交付的是"文本→像素的**机制**"——
//! 栅格、寻址、滚动、冻结、以及宿主机能**独立复算**的字形函数 [`glyph`]。
//! 这不是给人读的字体：`glyph` 由码点确定性地算出来，两边同算即可逐位比。
//! 可读字形是下一步（要字体资产 + 逐字形验收），这里不假装已经做了。
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

/// 由码点确定性地算出 8 行字形（每行一个字节，bit7 是最左像素）。
///
/// 这条公式是**契约的一部分**：宿主机夹具照着同一句话独立实现一遍，
/// 于是"像素有没有落在该落的位置"被验了，而"字形好不好看"不在本片的判据里。
pub fn glyph(ch: char) -> [u8; 8] {
    let b = ch as u32;
    let mut g = [0u8; 8];
    for r in 0..8usize {
        let mut row = 0u8;
        for c in 0..8usize {
            if b.wrapping_mul(31).wrapping_add((r as u32) * 7).wrapping_add(c as u32) % 5 < 2 {
                row |= 1 << (7 - c);
            }
        }
        g[r] = row;
    }
    g
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
