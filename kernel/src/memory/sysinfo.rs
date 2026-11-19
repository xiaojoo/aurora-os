//! ADR-157：内核身份与内存读数（46 号 `SYS_SYSINFO`）。
//!
//! **为什么需要一个新号**：`uname`/`arch`/`meminfo` 三条命令都要"这台机器是什么、
//! 有多少内存"这组事实，而内核侧今天**没有**任何版本/架构出口——
//! shell 里那句 `Aurora OS 6.1.0-aurora` 是**硬编码在 MSGS 里的字符串**，
//! 不是从内核读来的。把版本写死在用户态等于"用户态自己编造内核身份"。
//!
//! **为什么一次给全部而不是三个号**：三条命令读的是同一组事实，
//! 分三个号会让"版本 6.1.0 但架构读到空"这种半截状态变得可能。
//!
//! 记录定长 **64 字节**（小端）：
//!
//! | 偏移 | 宽 | 含义 |
//! |---|---|---|
//! | 0 | 4 | 魔数 `0x5349_4E46`（"SINF"）——调用方据此确认"这真是 sysinfo 记录" |
//! | 4 | 2 | ABI 主版本 |
//! | 6 | 2 | ABI 次版本 |
//! | 8 | 4 | 架构号（见 `ARCH_*`） |
//! | 12 | 4 | 保留（对齐） |
//! | 16 | 8 | 物理页总数 |
//! | 24 | 8 | 空闲页数 |
//! | 32 | 8 | 页大小（字节） |
//! | 40 | 8 | 已用页数（= 总 - 空闲，**内核算，不让用户态减**） |
//! | 48 | 16 | 版本串（定长，0 结尾；**内核自己写的**，不是用户态编的） |

/// 记录定长。
pub const SYSINFO_LEN: usize = 64;

/// 记录魔数。
pub const SYSINFO_MAGIC: u32 = 0x5349_4E46;

/// 架构号。今天只有 x86-64——**留成数字而不是字符串**：
/// 字符串在 32S 纪律下要占 `.rodata` 并被取址，数字让用户态自己映射。
pub const ARCH_X86_64: u32 = 1;

/// 内核版本串（**唯一来源**）。
///
/// 改这个串要同步改 `docs/` 与 `COORD.md` 的版本记录——它是 `uname` 的**唯一**
/// 输出，用户态不再持有自己的副本（ADR-157 决策 1）。
pub const VERSION: &[u8] = b"6.1.0-aurora";

/// 把记录填进 `out`（调用方保证 `out.len() >= SYSINFO_LEN`）。返回写入字节数。
///
/// **ABI 版本由调用方传**：本模块只依赖 `mm`（页统计），不引 `crate::user`——
/// 那会把 `memory` 拖进 `diagnostics` 的依赖里，实测让 SCC 环多三个模块。
///
/// **不返回 `Result`**：这五个数（版本、ABI、架构、页统计）在内核里恒有值，
/// 没有"读不到"的分支。真正的失败面（缓冲太小）由调用方在进来之前挡掉。
pub fn fill(out: &mut [u8], abi_major: u64, abi_minor: u64) -> usize {
    if out.len() < SYSINFO_LEN {
        return 0;
    }
    let total = crate::mm::total_frames() as u64;
    let free = crate::mm::free_frames() as u64;
    let page = crate::mm::PAGE as u64;
    let used = total.saturating_sub(free);
    // 逐段写，每段都先查长度（`out.len() >= SYSINFO_LEN` 已在上面保证，
    // 但用 `get_mut` 让"将来有人改小 SYSINFO_LEN"也不会 panic）
    let mut put = |off: usize, src: &[u8]| {
        if let Some(dst) = out.get_mut(off..off + src.len()) {
            dst.copy_from_slice(src);
        }
    };
    put(0, &SYSINFO_MAGIC.to_le_bytes());
    put(4, &(abi_major as u16).to_le_bytes());
    put(6, &(abi_minor as u16).to_le_bytes());
    put(8, &ARCH_X86_64.to_le_bytes());
    put(12, &0u32.to_le_bytes());
    put(16, &total.to_le_bytes());
    put(24, &free.to_le_bytes());
    put(32, &page.to_le_bytes());
    put(40, &used.to_le_bytes());
    // 版本串：最多 15 字节 + 0 结尾
    let mut vb = [0u8; 16];
    let mut k = 0usize;
    while k < 15 && k < VERSION.len() {
        if let Some(s) = vb.get_mut(k) {
            *s = VERSION.get(k).copied().unwrap_or(0);
        }
        k += 1;
    }
    put(48, &vb);
    SYSINFO_LEN
}
