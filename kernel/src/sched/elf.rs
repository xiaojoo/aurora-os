//! ELF64 程序头解析（手册 §10.7 的容器规则里"只收 / 只拒"那一半）。
//!
//! 这一步**只解析、不映射**。理由与 §12.4.1 的"尺子先要能分辨"同一条：
//! 容器解析器的正确性可以用一叠字节直接判定（含每一道拒绝的负样本），
//! 而一旦把它和"装页表 + 换到 ring3 + 跑起来"混在一次改动里，
//! 红了就分不清是解析错、映射错还是入口错——M4-1 那次五个缺陷互相掩护就是这个形状。
//!
//! 三条决定本文件形状的规则：
//!
//! 1. **每一处算术都用 checked 版本**。`p_offset`/`p_filesz`/`e_phoff` 这些字段
//!    全部来自不可信输入，`end - start` 的减法在容器损坏时就是溢出，
//!    而这里的溢出不是报错而是越界读别人的字节。
//! 2. **权限按 W^X 拒绝，不是按"能用就行"**。同时可写又可执行的段一律 `WxViolation`，
//!    哪怕 QEMU/真机都跑得起来：§6.4 承诺的是"用户代码页永远不可写"，
//!    收下这种段就等于把那条承诺改成"看容器作者的心情"。
//! 3. **地址必须落在用户半区**。一个自称 `0xffffffff80000000` 的段如果被接受，
//!    加载器就会替攻击者把内核页重新映射一遍——这是提权，不是"不稳定的程序"。
//!    判据用 `VirtAddr` 的规范地址规则加一条"低半区"上界，两者都写在这里而不是散在加载器里。

use crate::mm::PAGE;

/// 支持的最大 PT_LOAD 段数。**刻意用定长数组而不是 `Vec`**：
/// 段数来自不可信输入，先按它 `with_capacity` 分配就是让对方决定我们分配多少；
/// 而固定上限让"太多"变成一条明确的拒绝（`TooManySegments`），不是内存压力。
pub const MAX_LOAD_SEGMENTS: usize = 8;

const EI_NIDENT: usize = 16;
const HEADER_BYTES: usize = 64;
const PHDR_BYTES: usize = 56;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 0x3e;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// 低半区的上界：bit47 = 0 的那一半才是用户地址空间。
/// 内核的 HHDM/镜像全在高半区（`0xffff8000…` / `0xffffffff8000…`），
/// 一个要求把段装进高半区的容器必须被拒绝（见模块头第 3 条）。
pub const USER_VA_TOP: u64 = 0x0000_8000_0000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    /// 连固定头部都装不下
    TooShort,
    /// `\x7fELF` 不对
    BadMagic,
    /// `EI_CLASS != 2`：这不是 ELF64
    Not64Bit,
    /// `EI_DATA != 1`：大端/未知字节序
    NotLittleEndian,
    /// `EI_VERSION`/`e_version` 不是当前版本
    BadVersion,
    /// 不是 x86-64
    WrongMachine,
    /// 非固定加载地址（PIE）：本版本还没有重定位器，明确拒绝而不是"先当 ET_EXEC 用"
    RelocationUnsupported,
    /// `e_type` 既不是 ET_EXEC 也不是 ET_DYN：可重定位对象（`.o`）、核心转储等
    NotExecutableImage,
    /// 程序头每项大小小于 56（我们的读法会越出每项边界）
    BadPhEntSize,
    /// 程序头表落在文件之外，或长度算术溢出
    PhdrsOutOfBounds,
    /// 一个 PT_LOAD 都没有
    NoLoadSegment,
    /// 段数超过 `MAX_LOAD_SEGMENTS`
    TooManySegments,
    /// 段的文件区间超出文件末尾，或 `memsz < filesz`
    SegmentOutOfBounds,
    /// `p_vaddr` 与 `p_offset` 对不同页大小取模不相等：拷贝形状根本对不上
    MisalignedSegment,
    /// `p_align` 既不是 0 也不是 2 的幂
    BadAlignment,
    /// 段的 VA 落在内核半区或非规范地址
    NotUserRange,
    /// 两个 PT_LOAD 的 VA 区间重叠（一页同时属于两个段）
    OverlappingSegments,
    /// 段同时可写且可执行
    WxViolation,
    /// `e_entry` 不在任何 PT_LOAD 的 VA 区间内
    EntryNotLoaded,
    /// `e_entry` 所在的那个段没有执行权限
    EntryNotExecutable,
}

/// 一个已加载段的位置与权限。这里**不**保存指向文件的引用：
/// 加载器要在验完之后再按 `offset/filesz/memsz` 取字节，把 `&[u8]` 塞进结构里
/// 只会让人以为"已经拷好了"，而 bss 尾巴那段（`memsz > filesz`）根本没有文件字节。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// 文件内的起始偏移
    pub offset: u64,
    /// 要映射的虚拟地址（页对齐由 `MisalignedSegment` 保证与 offset 同余）
    pub vaddr: u64,
    /// 从文件里拷多少字节
    pub filesz: u64,
    /// 这段在内存里占多少（`memsz > filesz` 的尾巴必须清零）
    pub memsz: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl Segment {
    /// 段的 VA 末（不含）。溢出在这里不可能：`memsz` 的上界已由
    /// `NotUserRange`（vaddr 在高半区就被拒）与 `SegmentOutOfBounds` 夹住。
    pub fn va_end(&self) -> u64 {
        self.vaddr + self.memsz
    }

    pub fn contains_va(&self, va: u64) -> bool {
        va >= self.vaddr && va < self.va_end()
    }

    /// 需要的页数（向上取整，用 checked 版避免 `memsz` 巨大时溢出）。
    pub fn pages(&self) -> Option<u64> {
        let start_off = self.vaddr % PAGE as u64;
        (self.memsz + start_off + (PAGE as u64 - 1))
            .checked_div(PAGE as u64)
    }
}

/// 解析结果：入口 + 段表。
#[derive(Clone, Copy, Debug)]
pub struct Program {
    pub entry: u64,
    pub segs: [Segment; MAX_LOAD_SEGMENTS],
    /// 用到的段数（`segs[..n]` 才是有效的，其余是默认值）
    pub n: usize,
    /// 文件里程序头的数量（含非 PT_LOAD 的那些）——用例要能报出"读了几个、收了几个"
    pub phnum: usize,
}

impl Program {
    pub fn segments(&self) -> &[Segment] {
        &self.segs[..self.n]
    }
}

// 这三个读法刻意写成普通 fn + 显式取切片：`le64(bytes, 32)` 是整份解析里唯一
// 直接接触不可信偏移的地方，越界必须返回 `None`（由调用方翻成错误码），
// 而不是 panic（在 ring0 里就是停机）也不是"读过去算合法"。
fn le16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn le64(b: &[u8], at: usize) -> Option<u64> {
    let s = b.get(at..at + 8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// 解析 ELF64 的可加载段。字节可以来自任何地方（引导期由 Limine 的文件请求给出，
/// M4-2 的用例先用构建期嵌进镜像的夹具）——本函数不关心。
pub fn parse(bytes: &[u8]) -> Result<Program, ElfError> {
    if bytes.len() < HEADER_BYTES {
        return Err(ElfError::TooShort);
    }
    if bytes[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(ElfError::BadMagic);
    }
    if bytes[4] != 2 {
        return Err(ElfError::Not64Bit);
    }
    if bytes[5] != 1 {
        return Err(ElfError::NotLittleEndian);
    }
    if bytes[6] != 1 {
        return Err(ElfError::BadVersion);
    }
    let e_type = le16(bytes, 16).ok_or(ElfError::TooShort)?;
    let e_machine = le16(bytes, 18).ok_or(ElfError::TooShort)?;
    let e_version = le32(bytes, 20).ok_or(ElfError::TooShort)?;
    let e_entry = le64(bytes, 24).ok_or(ElfError::TooShort)?;
    let e_phoff = le64(bytes, 32).ok_or(ElfError::TooShort)?;
    let e_phentsize = le16(bytes, 54).ok_or(ElfError::TooShort)?;
    let e_phnum = le16(bytes, 56).ok_or(ElfError::TooShort)?;
    if e_version != 1 {
        return Err(ElfError::BadVersion);
    }
    if e_machine != EM_X86_64 {
        return Err(ElfError::WrongMachine);
    }
    // ET_DYN 的地址是"装载基址 + 相对偏移"，需要重定位表才能定下来。
    // 本版本没有重定位器，所以这里**明确拒绝**——而不是把 base 当 0 硬塞进去，
    // 那种做法的表现是"程序进去了但一跳转就故障"，比拒绝难查一个数量级。
    if e_type == ET_DYN {
        return Err(ElfError::RelocationUnsupported);
    }
    if e_type != ET_EXEC {
        // 共享库(ET_DYN)在上面已经单独拒绝过；走到这里的是 .o / core / e_type 乱值
        return Err(ElfError::NotExecutableImage);
    }
    if (e_phentsize as usize) < PHDR_BYTES {
        return Err(ElfError::BadPhEntSize);
    }

    // 程序头表的边界：先算 end，任何一步溢出都判失败。
    let phnum = e_phnum as usize;
    let table_end = (e_phoff as usize)
        .checked_add(phnum.checked_mul(e_phentsize as usize).ok_or(ElfError::PhdrsOutOfBounds)?)
        .ok_or(ElfError::PhdrsOutOfBounds)?;
    if e_phoff as usize > bytes.len() || table_end > bytes.len() {
        return Err(ElfError::PhdrsOutOfBounds);
    }

    let mut out = Program {
        entry: e_entry,
        segs: [Segment {
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            readable: false,
            writable: false,
            executable: false,
        }; MAX_LOAD_SEGMENTS],
        n: 0,
        phnum,
    };

    for i in 0..phnum {
        let at = (e_phoff as usize) + i * (e_phentsize as usize);
        // 只读前 PHDR_BYTES 个字节：`e_phentsize` 大于 56 时多出来的是给未来版本留的，
        // 按 ELF 的规则必须忽略（不是"未知就报错"）。
        let ph = bytes.get(at..at + PHDR_BYTES).ok_or(ElfError::PhdrsOutOfBounds)?;
        if le32(ph, 0).ok_or(ElfError::PhdrsOutOfBounds)? != PT_LOAD {
            continue;
        }
        let p_flags = le32(ph, 4).ok_or(ElfError::SegmentOutOfBounds)?;
        let p_offset = le64(ph, 8).ok_or(ElfError::SegmentOutOfBounds)?;
        let p_vaddr = le64(ph, 16).ok_or(ElfError::SegmentOutOfBounds)?;
        let p_filesz = le64(ph, 32).ok_or(ElfError::SegmentOutOfBounds)?;
        let p_memsz = le64(ph, 40).ok_or(ElfError::SegmentOutOfBounds)?;
        let p_align = le64(ph, 48).ok_or(ElfError::SegmentOutOfBounds)?;

        if p_flags & PF_W != 0 && p_flags & PF_X != 0 {
            return Err(ElfError::WxViolation);
        }
        if p_align != 0 && (p_align & (p_align - 1) != 0 || (p_align % PAGE as u64) != 0) {
            return Err(ElfError::BadAlignment);
        }
        if p_memsz < p_filesz {
            return Err(ElfError::SegmentOutOfBounds);
        }
        // 文件区间必须整段落在文件里（`checked_add` 而不是减法：见模块头第 1 条）
        let file_end = p_offset.checked_add(p_filesz).ok_or(ElfError::SegmentOutOfBounds)?;
        if file_end > bytes.len() as u64 {
            return Err(ElfError::SegmentOutOfBounds);
        }
        // 装载地址与文件偏移必须同余于页大小：否则"从 offset 拷 filesz 到 vaddr"
        // 这个动作根本没有对齐的页可以做。
        if (p_vaddr % PAGE as u64) != (p_offset % PAGE as u64) {
            return Err(ElfError::MisalignedSegment);
        }
        // 地址范围：规范 + 低半区。`va_end` 的溢出用 checked 版夹住。
        let va_end = p_vaddr.checked_add(p_memsz).ok_or(ElfError::NotUserRange)?;
        if p_vaddr >= USER_VA_TOP || va_end >= USER_VA_TOP {
            return Err(ElfError::NotUserRange);
        }
        let seg = Segment {
            offset: p_offset,
            vaddr: p_vaddr,
            filesz: p_filesz,
            memsz: p_memsz,
            readable: p_flags & PF_R != 0,
            writable: p_flags & PF_W != 0,
            executable: p_flags & PF_X != 0,
        };
        // 一页不能同时属于两个段：加载器按段逐个映射，重叠的那一段会**覆写**前一段的页，
        // 而前一段的拥有者并不知道（§6.3 的所有权在容器层的同一条规则）。
        for j in 0..out.n {
            let other = out.segs[j];
            if other.vaddr < seg.va_end() && seg.vaddr < other.va_end() {
                return Err(ElfError::OverlappingSegments);
            }
        }
        if out.n == MAX_LOAD_SEGMENTS {
            return Err(ElfError::TooManySegments);
        }
        out.segs[out.n] = seg;
        out.n += 1;
    }

    if out.n == 0 {
        return Err(ElfError::NoLoadSegment);
    }
    let entry_seg = out
        .segments()
        .iter()
        .find(|s| s.contains_va(e_entry))
        .ok_or(ElfError::EntryNotLoaded)?;
    if !entry_seg.executable {
        return Err(ElfError::EntryNotExecutable);
    }
    // 入口所在段必须可读（取指需要 R；`X` 已经在上一条查过，`R` 单独查是因为
    // 存在只执行不可读的段这种合法形状，而取指至少要求硬件真的能把那条指令读出来）。
    if !entry_seg.readable {
        return Err(ElfError::EntryNotExecutable);
    }
    Ok(out)
}

/// 用例与日志用：把错误码翻成一句人话（§9.7 的要求是"拒绝必须可解释"，
/// 一个数字不够，否则现场只能靠对照源码读）。
pub fn describe(e: ElfError) -> &'static str {
    match e {
        ElfError::TooShort => "文件比固定头部还短",
        ElfError::BadMagic => "不是 ELF（\\x7fELF 对不上）",
        ElfError::Not64Bit => "EI_CLASS 不是 2：这不是 ELF64",
        ElfError::NotLittleEndian => "EI_DATA 不是 1：字节序不是小端",
        ElfError::BadVersion => "版本不是当前 ELF 版本",
        ElfError::WrongMachine => "不是 x86-64 的可执行映像",
        ElfError::RelocationUnsupported => "ET_DYN：本版本没有重定位器",
        ElfError::NotExecutableImage => "e_type 不是可执行映像（.o / core / 乱值）",
        ElfError::BadPhEntSize => "程序头每项小于 56 字节",
        ElfError::PhdrsOutOfBounds => "程序头表落在文件之外",
        ElfError::NoLoadSegment => "一个 PT_LOAD 都没有",
        ElfError::TooManySegments => "PT_LOAD 段数超过上限",
        ElfError::SegmentOutOfBounds => "段越出文件末尾，或 memsz < filesz",
        ElfError::MisalignedSegment => "p_vaddr 与 p_offset 对页大小不同余",
        ElfError::BadAlignment => "p_align 不是 0 也不是页大小的倍数",
        ElfError::NotUserRange => "段的地址不在低半区（想装进内核地址）",
        ElfError::OverlappingSegments => "两个 PT_LOAD 的 VA 区间重叠",
        ElfError::WxViolation => "段同时可写且可执行：W^X 不允许",
        ElfError::EntryNotLoaded => "e_entry 不在任何 PT_LOAD 里",
        ElfError::EntryNotExecutable => "e_entry 所在段不可执行/不可读",
    }
}
