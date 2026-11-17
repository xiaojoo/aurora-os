//! 最小 ELF64 装载器（A3 切片，ADR-131 草案）。
//!
//! **用户态装载**：内核的 `load_into` 只给内核自己用（init 编排）；一个用户程序要
//! "运行另一个 ELF"（A3 的外部命令执行），只能自己按段表把镜像铺进子进程的 AS。
//! 本模块做三件事：解析（e_entry + PT_LOAD 段表）、逐段 VMO+14 号映射、算栈顶。
//!
//! 边界与口径：
//! - 只接受 `ET_EXEC`（与内核装载器同一个拒绝集合的形状：ET_DYN 明确拒——重定位器还没有）；
//! - 段必须 4 KiB 页对齐且 `p_vaddr` 与 `p_offset` 同余（镜像窗口的既有约束，elf.rs 同律）；
//! - 逐段独立 VMO（段间有洞，不能一页连续铺）；栈在最大段末尾之后一页，由调用方建；
//! - 所有长度上限在 safe 层先拒（段数、单段页数、总页数），不给内核传未校验值。

use crate::{vmo_create, vmo_map, vmo_write, Handle, RTError};

/// 页大小（与内核 mm::PAGE 同值，两侧独立声明）。
pub const PAGE: u64 = 4096;
/// 允许的段数上限（hello/probe/fileprobe/shell/execprobe 都 ≤ 4）。
pub const MAX_SEGS: usize = 8;
/// 单段页数上限（8 MiB——用户窗口 1 MiB 的总量远小于此，仅作防呆）。
pub const MAX_SEG_PAGES: usize = 2048;

pub const EHDR_BYTES: usize = 64;
pub const PHDR_BYTES: usize = 56;
const PT_LOAD: u32 = 1;
const ET_EXEC: u16 = 2;

/// 一段已校验的 PT_LOAD。
///
/// **字段全用 u64（含 w/x 用 0/1）**：`bool` 字段的数组零值会被 LLVM 降成
/// `.rodata..Lanon` 常量模板 + memcpy，而用户程序链接基址在 +4 GiB（正数），
/// 模板取址的 `R_X86_64_32S` 装不下 ⇒ 链接期 out of range（2026-11-17 实测：
/// create_seg_vmos/write_chunk/map_segs 各引用一枚 anon 模板）。全整数 struct 的
/// 零值是 memset，不产生任何只读模板引用。
#[derive(Clone, Copy, Debug)]
pub struct Seg {
    /// 段内容在文件里的偏移。
    pub off: u64,
    /// 段虚拟地址（页对齐）。
    pub va: u64,
    /// 文件内容长度。
    pub filesz: u64,
    /// 内存长度（含 .bss 尾巴，memsz >= filesz）。
    pub memsz: u64,
    /// 可写（0/1；见上：bool 会引 rodata 模板）。
    pub w: u64,
    /// 可执行（0/1）。
    pub x: u64,
}

/// 解析结果：入口、段表、栈顶（最大段末尾对齐后加一页）。
#[derive(Clone, Copy, Debug)]
pub struct Image {
    pub entry: u64,
    pub segs: [Seg; MAX_SEGS],
    pub nseg: usize,
    pub stack_top: u64,
}

fn u16at(b: &[u8], o: usize) -> Option<u16> {
    let s = b.get(o..o.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}
fn u32at(b: &[u8], o: usize) -> Option<u32> {
    let s = b.get(o..o.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64at(b: &[u8], o: usize) -> Option<u64> {
    let s = b.get(o..o.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

/// 只解析、不映射。任何形状不成立都返回 `Err`（不 panic、不静默截断）。
///
/// `file_len` 是**整文件**的字节数（22 号 stat 的 size）：`b` 可以只是头部一块，
/// 段界校验必须按整文件判，否则 "段 offset 落在头块之后" 会被误拒（2026-11-17 实测）。
pub fn parse(b: &[u8], file_len: u64) -> Result<Image, RTError> {
    let magic = b.get(0..4).ok_or(RTError::INVALID)?;
    if b.len() < EHDR_BYTES || magic != b"\x7fELF" || b.get(4) != Some(&2) {
        return Err(RTError::INVALID);
    }
    if u16at(b, 16) != Some(ET_EXEC) {
        return Err(RTError::INVALID);
    }
    let entry = u64at(b, 24).ok_or(RTError::INVALID)?;
    let phoff = u64at(b, 32).ok_or(RTError::INVALID)? as usize;
    let phnum = u16at(b, 56).ok_or(RTError::INVALID)? as usize;
    if phnum > MAX_SEGS {
        return Err(RTError::TOOLONG);
    }
    // 全零段表：字段全整数 ⇒ 编译器用 memset（不产生 rodata 模板，见 Seg 的注释）。
    let zero = Seg {
        off: 0,
        va: 0,
        filesz: 0,
        memsz: 0,
        w: 0,
        x: 0,
    };
    let mut img = Image {
        entry,
        segs: [zero; MAX_SEGS],
        nseg: 0,
        stack_top: 0,
    };
    let mut max_end: u64 = 0;
    for i in 0..phnum {
        let o = phoff.checked_add(i * PHDR_BYTES).ok_or(RTError::INVALID)?;
        if u32at(b, o) != Some(PT_LOAD) {
            continue;
        }
        let flags = u32at(b, o + 4).ok_or(RTError::INVALID)?;
        let off = u64at(b, o + 8).ok_or(RTError::INVALID)?;
        let va = u64at(b, o + 16).ok_or(RTError::INVALID)?;
        let filesz = u64at(b, o + 32).ok_or(RTError::INVALID)?;
        let memsz = u64at(b, o + 40).ok_or(RTError::INVALID)?;
        // 形状：页对齐、文件界内、memsz>=filesz、页数上限。
        if va % PAGE != 0 || off % PAGE != va % PAGE || memsz < filesz {
            return Err(RTError::INVALID);
        }
        if off.checked_add(filesz).map_or(true, |e| e > file_len) {
            return Err(RTError::INVALID);
        }
        let pages = memsz.checked_add(PAGE - 1).ok_or(RTError::TOOLONG)?.checked_div(PAGE).ok_or(RTError::INVALID)? as usize;
        if pages == 0 || pages > MAX_SEG_PAGES {
            return Err(RTError::TOOLONG);
        }
        if img.nseg >= MAX_SEGS {
            return Err(RTError::TOOLONG);
        }
        img.segs[img.nseg] = Seg {
            off,
            va,
            filesz,
            memsz,
            w: (flags & 2 != 0) as u64,
            x: (flags & 1 != 0) as u64,
        };
        img.nseg += 1;
        max_end = max_end.max(va + memsz);
    }
    if img.nseg == 0 || !img.segs.iter().take(img.nseg).any(|s| s.x != 0) {
        return Err(RTError::INVALID); // 没有可执行段 = 装进去也跑不了
    }
    let aligned = max_end.checked_add(PAGE - 1).ok_or(RTError::TOOLONG)?.checked_div(PAGE).ok_or(RTError::INVALID)? * PAGE;
    img.stack_top = aligned + PAGE;
    Ok(img)
}

/// 为每段建 VMO（memsz 页数），返回句柄表与段数。**只建不填**——
/// 无 seek 的产品档按"顺序读块 + 段过滤"填（见 [`write_chunk`]），有全字节的调用方可直接写。
pub fn create_seg_vmos(img: &Image) -> Result<([Handle; MAX_SEGS], usize), RTError> {
    let mut sv = [0u64; MAX_SEGS];
    for i in 0..img.nseg {
        let s = *img.segs.get(i).ok_or(RTError::INVALID)?;
        let pages = s.memsz.checked_add(PAGE - 1).ok_or(RTError::TOOLONG)?.checked_div(PAGE).ok_or(RTError::INVALID)? as usize;
        *sv.get_mut(i).ok_or(RTError::INVALID)? = vmo_create(pages)?;
    }
    Ok((sv, img.nseg))
}

/// 把文件里 `base..base+b.len()` 这一段字节按**段过滤**写进对应的段 VMO。
/// 无 24 号 seek 的产品档用顺序读驱动它：每读一块就调一次，块跨段/跨洞都按交集切。
pub fn write_chunk(img: &Image, sv: &[Handle; MAX_SEGS], b: &[u8], base: u64) -> Result<(), RTError> {
    let lo = base;
    let hi = base + b.len() as u64;
    for i in 0..img.nseg {
        let s = match img.segs.get(i) {
            Some(v) => *v,
            None => return Err(RTError::INVALID),
        };
        let s_lo = s.off;
        let s_hi = s_lo + s.filesz;
        let a = lo.max(s_lo);
        let z = hi.min(s_hi);
        if a >= z {
            continue;
        }
        let src = b.get((a - lo) as usize..(z - lo) as usize).ok_or(RTError::INVALID)?;
        let vh = *sv.get(i).ok_or(RTError::INVALID)?;
        vmo_write(vh, a - s_lo, src)?;
    }
    Ok(())
}

/// 把段 VMO 逐段映射进 `proc` 的 AS（14 号，VA 对账：内核给了别的地址就明确拒）。
pub fn map_segs(proc: Handle, img: &Image, sv: &[Handle; MAX_SEGS]) -> Result<usize, RTError> {
    let mut done = 0usize;
    for i in 0..img.nseg {
        let s = match img.segs.get(i) {
            Some(v) => *v,
            None => return Err(RTError::INVALID),
        };
        let vh = *sv.get(i).ok_or(RTError::INVALID)?;
        let mapped = vmo_map(proc, vh, s.va, s.w != 0, s.x != 0)?;
        if mapped != s.va {
            return Err(RTError::INVALID);
        }
        done += 1;
    }
    Ok(done)
}
