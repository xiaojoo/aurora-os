//! 用户 capability 句柄表（P7）。设计见 `docs/design/user-abi-capability.md`，决定见 ADR-007。
//!
//! ## 句柄值
//!
//! ```text
//! bits [15:0]   slot   u16    槽号（只有 0..15 合法）
//! bits [63:16]  gen    u48    世代号（每槽独立，从 1 起、跳过 0）
//! ```
//!
//! 权限**不在**句柄里（用户可伪造整数，把权限放进去等于让用户自己授权）。世代宽度 48 位是
//! §9 G 的裁决：16+48 正好一个寄存器；承诺是可数的上界——同一槽连续复用 `2^48-2` 次内
//! 旧句柄必拒，**到上界后同 gen 会重新匹配**（编码的界，不是 bug；负样本 6 会把它打出来）。
//!
//! ## 锁
//!
//! 全局一把 rank 35。**盘 I/O 不在锁内**：AHCI 的同步读在关中断下拿不到完成中断，只能走
//! 轮询宽限窗；把盘读放进表锁会让每条命令多付一个宽限窗，还会把 `POLL_HITS` 记脏。
//! 读的提交是「取票（锁内）→ 读（锁外）→ 提交（锁内）」：任何一步失败都不提交游标。
//!
//! `owner` 是**两格**：全局任务下标 + `Task::id`。只认槽号会让新任务继承死者的句柄
//! （`spawn` 找 Free 槽而退出当场就标 Free，见设计 §2.2）。

use crate::filesystem::fat32::{FileCursor, FsError};
#[cfg(feature = "fs-open")]
use crate::filesystem::vfs_ro::{self, DirState, Entry as VfsEntry, ReadCursor, VfsError};
use crate::filesystem::vfs::{AhciDisk, Block, Partition, PartitionView};
use crate::sync::{IrqSpinLock, RANK_HANDLE};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// S9g（用户裁决 2026-11-15）：全局句柄表 16→64。16 格时每个活 shell 占 ~6-7 格，
/// 同时只能开 2 个，`+` 撞容量墙。槽号仍走 SLOT_BITS=16 位编码，64 远未越界。
/// 这是容量裁决（ADR-007 的 16 被用户放宽），si 描述表 MAX_STARTUP_HANDLES 仍 16（ABI 不动）。
/// 句柄表容量。
///
/// **`fs-open` 档要小 8 倍**（ADR-189 补记）：那个档的 `Entry` 内嵌 `VfsFile`
/// 的 `ReadCursor` + `VfsEntry`，单条 760 字节（其它档约 64 字节）。
///
/// 131072 x 760 B = **95 MiB**，在 512 MiB 机器上找不到连续块 ⇒
/// `handle::init 引导失败 OutOfMemory` ⇒ BOOT-INVALID（实测）。
///
/// 16384 x 760 B = 12 MiB，安全。**这不是「容量够用」，是「大 Entry 档的合理上限」**：
/// 真正的解法是把 `VfsFile` 的大字段挪进旁表（像 `cells` 那样），
/// 那要改十几处读写点，单独一轮做（ADR-189 未决 1）。
#[cfg(feature = "fs-open")]
pub const MAX_HANDLES: usize = 16384;
#[cfg(not(feature = "fs-open"))]
pub const MAX_HANDLES: usize = 131072;
/// 查「这个任务属于哪个进程」的函数指针（ADR-191）。
///
/// ## 为什么是函数指针而不是直接调 `sched`
///
/// `capability` 直接调 `sched::proc_id_of` 会形成**双向依赖**：`sched` 已经依赖
/// `capability`（`revoke_task`、`FdTable`），再加反向边就是新的强连通分量
/// `[capability, sched]`（`check-module-interfaces` 当场红，实测）。
///
/// 这是仓库里已有的解法（`sync::install_wait_ops` 同一模式）：**被依赖方提供注入点，
/// 依赖方在启动期装进去**。
static PROC_OF: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// 启动期安装一次（由 `sched` 调，与 `sync::install_wait_ops` 同一时点）。
pub fn install_proc_of(f: fn(usize) -> u16) {
    PROC_OF.store(f as usize as u64, core::sync::atomic::Ordering::Release);
}

/// 查任务所属进程；没装或越界时回 `NO_PROC`（**不 panic、不猜**）。
#[inline]
fn proc_of(gidx: usize) -> u16 {
    let v = PROC_OF.load(core::sync::atomic::Ordering::Acquire);
    if v == 0 {
        // **不引用 `crate::proc::NO_PROC`**（ADR-191）：那个符号属于 `sched` 模块，
        // 在非测试函数里引用它会造出 `capability -> sched` 的反向边 ⇒
        // 新强连通分量 `[capability, sched]`（门禁当场红，实测）。
        // 这里用同值字面量；值由 `sched` 侧的一致性断言守（见 `install_proc_of`）。
        return u16::MAX;
    }
    // SAFETY: 只可能是 `install_proc_of` 装进来的 `fn(usize) -> u16`，
    // 那个签名与这里的转换一一对应；指针在启动期装一次、之后只读。
    let f: fn(usize) -> u16 = unsafe { core::mem::transmute(v as usize) };
    f(gidx)
}

/// 一次 `revoke_task`/`reset_for_test` 里**栈上**收集 VMO 槽号的容量。
///
/// 为什么不能直接用 `MAX_HANDLES`（ADR-179 实测）：那两个函数原来写
/// `let mut vmos = [0u8; MAX_REVOKE_VMOS];` —— 当 `MAX_HANDLES` 是 131072 时，
/// 那是 **128 KiB 的栈数组**，直接把内核栈打穿 ⇒ `unexpected vector=8`（Double Fault）。
/// 一个任务最多同时持有这么多 VMO 句柄就已经不现实；超过的部分由调用方
/// 分批评，**不能靠加大栈数组解决**。
pub const MAX_REVOKE_VMOS: usize = 64;
/// 世代只用低 48 位；0 保留（空/从未分配过）。
pub const GEN_MAX: u64 = (1u64 << 48) - 1;
const SLOT_BITS: u64 = 16;
const SLOT_MASK: u64 = (1u64 << SLOT_BITS) - 1;

pub const RIGHT_READ: u32 = 1;
pub const RIGHT_WRITE: u32 = 2;
pub const RIGHT_MAP: u32 = 4;
pub const RIGHT_DUP: u32 = 8;
pub const RIGHT_TRANSFER: u32 = 16;
/// **Q7 裁的唯一新权限位**（P5c-1，ADR-075 决策 4）：只有带 `CREATE` 的 Job 句柄能造进程。
/// 它今天还没有产品调用方（11 号在 P5c-3），先把常量与校验接缝落地并各配一格负样本，
/// 免得 c-3 同时动"新号 + 新权限位 + 新序列"三件事。
pub const RIGHT_CREATE: u32 = 32;

/// 用户拿到的那个整数。构造永远成功（它是用户可伪造的值）；校验在查表时做。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Handle(pub u64);

impl Handle {
    pub const fn pack(slot: u16, gen: u64) -> Handle {
        Handle(slot as u64 | ((gen & GEN_MAX) << SLOT_BITS))
    }

    /// 形状检查：值 0 / gen 0 / slot ≥ `MAX_HANDLES` 都不合法（对用户是 `-1`，不是 `-5`）。
    pub fn unpack(self) -> Option<(u16, u64)> {
        let slot = (self.0 & SLOT_MASK) as u16;
        let gen = self.0 >> SLOT_BITS;
        if gen == 0 || slot as usize >= MAX_HANDLES {
            return None;
        }
        Some((slot, gen))
    }

    pub const fn slot(self) -> u16 {
        (self.0 & SLOT_MASK) as u16
    }

    pub const fn gen(self) -> u64 {
        self.0 >> SLOT_BITS
    }
}

impl core::fmt::Debug for Handle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.unpack() {
            Some((s, g)) => write!(f, "Handle(slot={} gen={:#x})", s, g),
            None => write!(f, "Handle(invalid {:#x})", self.0),
        }
    }
}

/// 核内拒绝形状。ABI 上 `NoSuch`/`Stale` 合成 `-5`，其余 `-4`；
/// 计数器**必须分开**（否则"撤销真的摘走了表项"没有证据）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HErr {
    /// 句柄值形状不对（0 / gen 0 / slot 越界）——对用户是 `-1`
    Invalid,
    NoSuch,
    Stale,
    NotOwner,
    Denied,
    Exhausted,
    /// 块设备失败。ABI 表里还没有 EIO 码，先按 `-2` 带出去并**记日志点名成因**（BACKLOG 待批）。
    Io(FsError),
    /// FS-03：VFS 层的成因（路径、坏卷、seek 越 EOF、目录当文件）。不许在这一层抹平。
    #[cfg(feature = "fs-open")]
    Vfs(VfsError),
}

impl HErr {
    pub fn tag(self) -> &'static str {
        match self {
            HErr::Invalid => "句柄形状非法",
            HErr::NoSuch => "槽不存在",
            HErr::Stale => "世代不符",
            HErr::NotOwner => "不是主人",
            HErr::Denied => "权限/撤销",
            HErr::Exhausted => "表满",
            HErr::Io(_) => "块设备失败",
            #[cfg(feature = "fs-open")]
            HErr::Vfs(_) => "VFS 错误",
        }
    }
}

#[derive(Clone, Copy)]
pub struct FileObj {
    pub port: u8,
    /// 分区区间；`None` = 整盘（既有语义）。**它是身份的一部分**（S2b，ADR-077 补记）：
    /// 同一个口、同一个文件名，两个不同区间是**两个对象**，读出来的字节可以不同。
    /// 为什么必须进身份而不是只活在打开那一刻：`read` 是**按表项重建块设备**的
    /// （见下面 `read`），表项里不带区间就只能重建出整盘 ⇒ 偏移在第一次读之后就丢了。
    pub part: Option<Partition>,
    pub cursor: FileCursor,
    /// 共享游标格子（ADR-108 补记二）：`None` = 游标还在本表项里（**未 dup 过的老形状**）；
    /// `Some(i)` = 游标住在 `Table.cells[i]`，dup 出来的句柄推进同一份读取位置。
    pub share: Option<u8>,
}

/// 表里存的**对象引用**，全 Copy（ADR-074 决策 1）。
/// 文件对象是值（port + 游标）；VMO 只存槽号，**本体在 `vmo.rs` 的表里、由 VMM(20) 保护**。
/// 这样 `close`/`revoke` 就不必在 HANDLE(35) 锁内丢一个持帧对象（那会是 35→20 的反向嵌套）：
/// 锁内取走引用、放锁之后才 `vmo::vmo_unref`。
#[derive(Clone, Copy)]
pub enum ObjRef {
    /// 控制台，附带**会话号**（S6p：每个会话一个镜像环与一份输入队列）
    Console(u8),
        File(FileObj),
    /// FS-03：通过 `vfs_ro` 打开的文件。游标自带 `Bpb`，所以表里仍是 Copy 值，
    /// 下一次盘 I/O 在表锁外重建 `AhciDisk`/`PartitionView` 即可。
    #[cfg(feature = "fs-open")]
    VfsFile {
        port: u8,
        part: Option<Partition>,
        cursor: ReadCursor,
        stat: VfsEntry,
        share: Option<u8>,
        /// **卷指纹**（ADR-221）：读路径要用它走页缓存。
        ///
        /// 没有它就只能走不缓存的 `read_disk` —— 而缓存版要 `(vol, lba)` 才能命中。
        vol: u64,
    },
    /// 目录句柄不内嵌 `DirCursor`（那会把每槽撑到 1.5 KiB）；`DirState` 是可复制的紧凑游标。
    #[cfg(feature = "fs-open")]
    VfsDir { port: u8, part: Option<Partition>, stat: VfsEntry, state: DirState },
    Vmo { slot: u8 },
    // ---- P5c-1（ADR-075 决策 4）：四种新 kind。本体各自住在 proc.rs / mm 的 AS 表 / sched 的任务表，
    // 表里只存**带世代号的引用**：`gen`（Thread 用 `id`）对不上就当"这个对象不是当初那个"。
    // 为什么必须有世代号：槽号是**复用的**，只比槽号会让新 Job/Proc/AS 继承旧句柄
    // ——那正是 ADR-073 给 `Task::id` 记过的同一条坑。
    // **这些 kind 的 close 不销毁本体**：撤掉的是一份名字，销毁仍走各自的显式路径
    // （`job_destroy` / `proc_reap`+`proc_discard` / `AspaceHandle::drop` / `terminate_task`）。
    // 这条与 ADR-075 影响 3 的"锁外要调三个模块"不同，已在该 ADR 的补记里记偏差。
    Job { slot: u16, gen: u32 },
    Proc { slot: u16, gen: u32 },
    ASpace { slot: u16, gen: u32 },
    Thread { gidx: usize, id: u32 },
    /// socket（ADR-181 决策 5）。本体住在 `network::socket` 的槽表，
    /// 这里只存带世代号的引用——与 `Proc`/`Job`/`ASpace` 同律：
    /// close 撤的是**名字**，销毁本体走 `socket::destroy`。
    Socket { slot: u16, gen: u32 },
}

#[derive(Clone, Copy)]
pub(crate) struct Entry {
    /// 该槽**最近发过**的世代；0 = 从未分配。释放时保留，下一次 grant 在它上面 +1。
    gen: u64,
    used: bool,
    owner_gidx: u16,
    owner_id: u32,
    /// 句柄所属的**进程**（ADR-191）。`NO_PROC` = 无进程上下文（boot 任务）。
    ///
    /// ## 为什么要这一格
    ///
    /// 原来只有 `owner_gidx`/`owner_id`，那是**任务**身份。于是同一进程的两个线程
    /// 不能共享 fd——线程 B 用线程 A 装的 fd 会拿到 `-4 NotOwner`（Linux 里 fd 属于
    /// `files_struct`，线程共享）。
    ///
    /// `check` 现在多一条路：**同进程也放行**。旧行为（同任务）保持。
    owner_proc: u16,
    rights: u32,
    obj: Option<ObjRef>,
}

const EMPTY: Entry = Entry {
    gen: 0,
    used: false,
    owner_gidx: 0,
    owner_id: 0,
    owner_proc: u16::MAX, // = `NO_PROC`，断言在 `sched::install_proc_of`（ADR-191）
    rights: 0,
    obj: None,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    pub grants: u32,
    pub closes: u32,
    pub stale: u32,
    pub not_owner: u32,
    pub denied: u32,
    pub exhausted: u32,
    pub invalid: u32,
    pub no_such: u32,
    pub revoked: u32,
    /// 成功转移的次数（P5c-3a，ADR-075 决策 4）。D3 的证人是 `stale` 的增量，
    /// 这一格是"转移真的发生了"的正向计数，两个数不能互相替代。
    pub transfers: u32,
    pub reads: u32,
    pub bytes: u64,
    pub live_peak: u32,
}

/// 一个共享游标格（ADR-108 补记二）。只在 `dup` 之后才出现：
/// 一条格子至少被两条句柄引用，所以格子上限是 `MAX_HANDLES / 2`。
#[derive(Clone, Copy)]
enum CellCur {
    Fat(FileCursor),
    #[cfg(feature = "fs-open")]
    Vfs(ReadCursor),
}

#[derive(Clone, Copy)]
struct Cell {
    used: bool,
    gen: u32,
    refs: u16,
    cur: Option<CellCur>,
}

const EMPTY_CELL: Cell = Cell {
    used: false,
    gen: 0,
    refs: 0,
    cur: None,
};

/// 句柄槽数组：**运行时分配**，不再是 `.bss` 里的定长数组（ADR-179）。
///
/// ## 为什么必须这样
///
/// ADR-178 把 `MAX_HANDLES` 提到 131072 时实测撞墙：`Table` 作为 `static` 会占 8 MiB `.bss`，
/// 把内核镜像布局推到让 `map_device` 的 IOAPIC 映射坏掉（`irt` 从 24 读成 1），
/// 整机 HANG。**那不是 IOAPIC 的问题，是定长静态数组的问题。**
///
/// 形状照抄 ADR-063 的 `bootstrap_frame_info()`（`mm.rs:3165`）：
/// `phys_alloc` 分连续帧 → `forget` 永不归还 → 存 HHDM 虚地址 → 按下标访问。
///
/// ## 为什么用 `Index`/`IndexMut` 而不是改 34 处调用点
///
/// 表里有 34 处 `t.slots[i]` / `t.slots.iter()`。让 `SlotArray` 实现 `Index`/`IndexMut`
/// 并提供 `iter()`，**调用点一行都不用改**——改动面从 34 处收缩到 1 个类型定义，
/// 这也让「改架构」与「改语义」彻底分开：本次只改「表放在哪」，语义一个字节都没动。
pub(crate) struct SlotArray {
    /// 槽数组的 HHDM 虚地址。0 = 还没 bootstrap（访问即 panic，见 `as_slice`）。
    base: AtomicU64,
    /// 容量。bootstrap 之后恒等于 `MAX_HANDLES`；0 = 还没 bootstrap。
    len: AtomicUsize,
}

impl SlotArray {
    const fn new() -> SlotArray {
        SlotArray { base: AtomicU64::new(0), len: AtomicUsize::new(0) }
    }

    /// 分连续帧并交给这张表（照 `bootstrap_frame_info` 的五步）。
    ///
    /// **调用方必须持 HANDLE 锁且还没让任何任务跑**（`main` 的启动期）。
    /// 返回 `Err` 表示分配失败 ⇒ 上层走 `boot-invalid`（判定 37），
    /// **绝不允许**「失败就用空表继续跑」（ADR-179 决策 4）。
    pub fn allocate() -> Result<SlotArray, crate::mm::MmError> {
        let bytes = MAX_HANDLES * core::mem::size_of::<Entry>();
        let pages = bytes.div_ceil(crate::mm::PAGE);
        if pages == 0 {
            // 容量为 0 的退化情形：给一个未 bootstrap 的数组，访问即 panic。
            // 不该发生（MAX_HANDLES 是编译期非零常量），但类型上必须有个返回值。
            return Ok(SlotArray::new());
        }
        // 2 的幂：phys_alloc 只收 order。向上取整到 2^order。
        let order = (usize::BITS - 1 - pages.leading_zeros()) as u8;
        //
        // **实测教训（ADR-179）**：直接 `phys_alloc(order)` 会分到**物理 2 MiB**，
        // 那是 bootloader 实际占用的低端区（`init_allocator` 只按 memmap 的 `usable`
        // 放开，而 bootloader 区在 memmap 里是 usable 但**内容不是零**）。
        // 后果：表的 `used` 字段读到垃圾 ⇒ `live()` 数出 184470 个句柄（容量只有 4096）。
        //
        // 修法：**自己清零**（下面已经做了）+ **按 order 逐级降级重试**，
        // 让分配器跳过拿不到大块的位置。清零是关键那一步——不清零就等于
        // 相信「刚分到的物理页是干净的」，而 bootloader 区恰恰不是。
        // **从 max_phys 的一半之上分配**（ADR-179 实测的修法）。
        //
        // 为什么不能直接 `phys_alloc`：它从 `1<<order` 页开始向上找，而**低端物理内存里
        // 住着 bootloader 的东西**（Limine 模块、AP 停车点、mp_info）。那块在 memmap 里
        // 是 `usable`、内容却不是零，要到 `reclaim_bootloader_regions()`（`stop_aps` 之后）
        // 才真正可用。`stage_memory()` 里调 `handle::init()` 时它还没被回收。
        //
        // 实测：分到物理 2 MiB ⇒ 清零后 `live()` 仍数出 184470 个句柄（容量 4096）
        // ⇒ 表被 bootloader 区的内容覆盖。
        //
        // 取 `max_phys / 2` 作起点：那是高半区，bootloader 从不往那里放东西，
        // 且按 2^order 对齐后仍有足够空间（512 MiB 机器 ⇒ 起点 256 MiB）。
        // **起点是镜像末尾，不是 max_phys/2**（ADR-179 补记四）：
        //
        // `max_phys/2` 在 512 MiB 机器上是 256 MiB，而 `fs-open` 档的镜像
        // `phys_base` 已经到 353 MiB —— **镜像本身跨过了那条线**，于是向上找
        // 连续块时撞上镜像 ⇒ `handle::init 引导失败 OutOfMemory`（实测）。
        //
        // 镜像末尾一定在镜像之后，也一定在 bootloader 区之上（那个区在镜像之前）。
        let min_phys = crate::mm::image_phys_end()
            .unwrap_or_else(|| crate::mm::max_phys() / 2);
        // **分配走 mm 侧的入口**（ADR-180 的环修正，与 `FdTable` 同一修法）：
        // `capability -> memory` 的新边让强连通分量涨大，`check-module-interfaces` 会红。
        // **传实际页数，不传 order**（ADR-179 补记四）：order 会把 5632 页
        // 取整到 16384 页（64 MiB），在 512 MiB 机器上找不到连续块。
        let _ = order;
        let va = crate::mm::alloc_handle_slots(pages, min_phys)?;
        // 清零：`EMPTY` 是全 0 语义（used=false, gen=0, obj=None），
        // 但**不能假设刚分到的物理页是干净的**（bootloader 可能留了内容）。
        // SAFETY: va 指向刚分配的 2^order 个连续帧（>= MAX_HANDLES 个 Entry），
        // 此刻单核 IF=0 的启动期、无并发；这块内存归 MOD_BOOT 永不归还。
        unsafe {
            let p = va as *mut Entry;
            for i in 0..MAX_HANDLES {
                core::ptr::write(p.add(i), EMPTY);
            }
        }
        // 清零**必须验证**：bootloader 区的内存不是零，若清零没生效，
        // `live()` 会数出垃圾（实测 184470）。这一步只在启动期跑一次，
        // 代价是 4096 次字节读，远小于「带着脏表跑一整个 boot」的代价。
        let mut dirty = 0usize;
        // SAFETY: 同上面的清零循环（va 指向刚分配的连续帧）。
        unsafe {
            let p = va as *const Entry;
            for i in 0..MAX_HANDLES {
                if core::ptr::read(p.add(i)).used {
                    dirty += 1;
                }
            }
        }
        crate::log_info!(
            "handle: slots 引导 base={:#x} len={} pages={} 清零后used={}",
            va, MAX_HANDLES, pages, dirty);
        Ok(SlotArray {
            base: AtomicU64::new(va),
            len: AtomicUsize::new(MAX_HANDLES),
        })
    }

    /// 取切片。**bootstrap 之前调用会 panic** —— 那是刻意的：
    /// 启动顺序错了就该立刻炸，而不是在空表上继续跑出随机行为。
    #[inline]
    fn as_slice(&self) -> &[Entry] {
        let base = self.base.load(Ordering::Acquire);
        let len = self.len.load(Ordering::Acquire);
        assert!(base != 0 && len == MAX_HANDLES, "handle slot array not bootstrapped");
        // SAFETY: base/len 由 `bootstrap` 一次性写入且此后不变（Release/Acquire 配对）；
        // 内存是 MOD_BOOT 的连续帧、永不归还，生命周期覆盖整个内核；
        // 调用方都持 HANDLE 锁（RANK_HANDLE），切片只在锁内用。
        unsafe { core::slice::from_raw_parts(base as *const Entry, len) }
    }

    #[inline]
    fn as_mut_slice(&mut self) -> &mut [Entry] {
        let base = self.base.load(Ordering::Acquire);
        let len = self.len.load(Ordering::Acquire);
        assert!(base != 0 && len == MAX_HANDLES, "handle slot array not bootstrapped");
        // SAFETY: 同上；`&mut` 的独占性由调用方持 HANDLE 锁保证。
        unsafe { core::slice::from_raw_parts_mut(base as *mut Entry, len) }
    }

    /// 遍历（`Table::live` 与 `find` 用）。
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, Entry> {
        self.as_slice().iter()
    }

    /// 可变迭代（ADR-179 补记三）：`fs-open` 档的 `reset_for_test` 要用。
    ///
    /// **这个方法是 `fs-open` 档编译失败暴露出来的**：ADR-179 只加了 `iter`，
    /// 而 `handles` 档从不编译走 `iter_mut` 的那两处，所以缺了半年没人发现。
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, Entry> {
        self.as_mut_slice().iter_mut()
    }
}

impl core::ops::Index<usize> for SlotArray {
    type Output = Entry;
    #[inline]
    fn index(&self, i: usize) -> &Entry {
        &self.as_slice()[i]
    }
}

impl core::ops::IndexMut<usize> for SlotArray {
    #[inline]
    fn index_mut(&mut self, i: usize) -> &mut Entry {
        &mut self.as_mut_slice()[i]
    }
}

impl core::ops::Index<u16> for SlotArray {
    type Output = Entry;
    #[inline]
    fn index(&self, i: u16) -> &Entry {
        &self.as_slice()[usize::from(i)]
    }
}

impl core::ops::IndexMut<u16> for SlotArray {
    #[inline]
    fn index_mut(&mut self, i: u16) -> &mut Entry {
        &mut self.as_mut_slice()[usize::from(i)]
    }
}

struct Table {
    slots: SlotArray,
    cells: [Cell; MAX_SHARE],
    c: Counters,
}

impl Table {
    const fn empty() -> Table {
        Table { slots: SlotArray::new(), cells: [EMPTY_CELL; MAX_SHARE], c: Counters {
            grants: 0, closes: 0, stale: 0, not_owner: 0, denied: 0, exhausted: 0, transfers: 0,
            invalid: 0, no_such: 0, revoked: 0, reads: 0, bytes: 0, live_peak: 0,
        } }
    }

    fn live(&self) -> u32 {
        let base = self.slots.base.load(Ordering::Acquire);
        let len = self.slots.len.load(Ordering::Acquire);
        let n = self.slots.iter().filter(|e| e.used).count() as u32;
        // 诊断：base/len/计数一起打，一次定位「计数超容量」是表错了还是内存脏了。
        // 只在异常时打，正常路径不加串口行（§486 的教训：日志会把自己刷超时）。
        if n as usize > len {
            crate::log_fatal!(
                "handle::live 计数 {} 超过容量 {}（base={:#x} len={}）—— 表或内存有误",
                n, len, base, len);
        }
        n
    }
}

const MAX_SHARE: usize = MAX_HANDLES / 2;

/// 占一格共享游标（锁内）。引用数从 1 起；世代 0 留给"从未分配"。
fn cell_alloc(t: &mut Table, cur: CellCur) -> Option<u8> {
    for i in 0..MAX_SHARE {
        if !t.cells[i].used {
            let mut gen = t.cells[i].gen.wrapping_add(1);
            if gen == 0 {
                gen = 1;
            }
            t.cells[i] = Cell {
                used: true,
                gen,
                refs: 1,
                cur: Some(cur),
            };
            return Some(i as u8);
        }
    }
    t.c.exhausted += 1;
    None
}

fn cell_retain(t: &mut Table, i: u8) {
    if let Some(c) = t.cells.get_mut(i as usize) {
        if c.used {
            c.refs = c.refs.saturating_add(1);
        }
    }
}

/// 关一条名字：引用减一；最后一条关上才丢格子（世代保留，票上的旧世代因此失效）。
fn cell_release(t: &mut Table, i: u8) {
    if let Some(c) = t.cells.get_mut(i as usize) {
        if c.used {
            c.refs = c.refs.saturating_sub(1);
            if c.refs == 0 {
                c.used = false;
                c.cur = None;
            }
        }
    }
}

// ---------------------------------------------------------------- ADR-180：per-process fd 表

/// fd 表容量（起步）。Linux 的 `NR_OPEN_DEFAULT = BITS_PER_LONG = 64`
///（`include/linux/fdtable.h`），我们取同一个数。
pub const FD_TABLE_INIT: usize = 64;

/// fd 表的**最大**容量。Linux 的 `RLIMIT_NOFILE` 软限默认 1024
///（`include/uapi/linux/limits.h` `NR_OPEN`），我们不做得比它大。
pub const FD_TABLE_MAX: usize = 1024;

/// 一个进程的 fd 表（ADR-180）。**每进程一份，首次 open 时分配**。
///
/// ## 为什么不是内嵌定长数组
///
/// `[u32; 64]` 内嵌进 `ProcEntry` 是 256 B × 32768 进程 = **8 MiB `.bss`**，
/// 那正是 ADR-179 撞过的坑（推高镜像布局 ⇒ IOAPIC `irt` 读成 1 ⇒ HANG）。
///
/// Linux 的 `files_struct` 由 kmem_cache 按需分配、fd 数组按需增长；本类型等价。
///
/// ## 形状
///
/// `entries[i]` = fd `i` 对应的**句柄值**（`u64`，与 `Handle` 同宽），0 = 该 fd 空闲。
/// 句柄值本身不可能是 0（`Handle::unpack` 把 0 判为非法），所以 0 可以安全地当哨兵。
pub struct FdTable {
    /// 表本体的 HHDM 虚地址。0 = 还没分配。
    base: AtomicU64,
    /// 当前容量（`FD_TABLE_INIT` 或翻倍后的值）。0 = 还没分配。
    cap: AtomicUsize,
    /// 已用个数（判据与 `close` 的快速路径用）。
    used: AtomicUsize,
}

impl FdTable {
    pub const fn new() -> FdTable {
        FdTable { base: AtomicU64::new(0), cap: AtomicUsize::new(0), used: AtomicUsize::new(0) }
    }

    /// 首次使用前分配表本体。**调用方持 HANDLE 锁**（与 `TABLE` 同一把）。
    ///
    /// 返回 `Err` 表示物理内存不足 ⇒ 上层回 `-6`（表/名额耗尽），
    /// **不是** `-1`（参数形状不对）。
    fn ensure(&self) -> Result<(), HErr> {
        if self.base.load(Ordering::Acquire) != 0 {
            return Ok(());
        }
        let bytes = FD_TABLE_INIT * core::mem::size_of::<u64>();
        let pages = bytes.div_ceil(crate::mm::PAGE);
        let order = (usize::BITS - 1 - pages.leading_zeros()) as u8;
        // 与句柄表同一修法：从 max_phys/2 之上分配，避开 bootloader 占用的低端区。
        // **起点是镜像末尾，不是 max_phys/2**（ADR-179 补记四）：
        //
        // `max_phys/2` 在 512 MiB 机器上是 256 MiB，而 `fs-open` 档的镜像
        // `phys_base` 已经到 353 MiB —— **镜像本身跨过了那条线**，于是向上找
        // 连续块时撞上镜像 ⇒ `handle::init 引导失败 OutOfMemory`（实测）。
        //
        // 镜像末尾一定在镜像之后，也一定在 bootloader 区之上（那个区在镜像之前）。
        let min_phys = crate::mm::image_phys_end()
            .unwrap_or_else(|| crate::mm::max_phys() / 2);
        // **分配在 mm 侧完成**（ADR-180 的环修正）：
        //
        // `capability -> memory` 会让依赖图出现新环（`check-module-interfaces` 抓到：
        // `memory.dependencies` 多了 `capability`、`capability.allowed_callers` 多了 `memory`，
        // 强连通分量从 10 个模块涨到 12 个）。
        //
        // 所以 `mm` 自己提供一个「分配并返回 HHDM 地址」的入口，`capability` 只调它、
        // 不碰 `phys_alloc_above`。这样 capability 仍然依赖 memory（既有边），
        // 但不新增**反向**边。
        // **显式映射**（与 `proc_create` 里同一条纪律）：不写 `From<MmError> for HErr`，
        // 那会让内存层与句柄层的错误语义被抹平。
        let va = crate::mm::alloc_fd_table_pages(order, min_phys)
            .map_err(|_| HErr::Exhausted)?;
        // SAFETY: va 指向刚分配的连续帧（>= FD_TABLE_INIT 个 u32），
        // 调用方持 HANDLE 锁 ⇒ 独占；归 MOD_BOOT 永不归还。
        unsafe {
            let p = va as *mut u64;
            for i in 0..FD_TABLE_INIT {
                core::ptr::write(p.add(i), 0);
            }
        }
        self.base.store(va, Ordering::Release);
        self.cap.store(FD_TABLE_INIT, Ordering::Release);
        Ok(())
    }

    /// 表切片。未分配时返回空。**调用方持 HANDLE 锁**。
    fn as_slice(&self) -> &[u64] {
        let base = self.base.load(Ordering::Acquire);
        let cap = self.cap.load(Ordering::Acquire);
        if base == 0 || cap == 0 {
            return &[];
        }
        // SAFETY: base/cap 由 `ensure` 一次性写入（Release/Acquire 配对）；
        // 内存是 MOD_BOOT 的连续帧、永不归还；调用方持 HANDLE 锁。
        unsafe { core::slice::from_raw_parts(base as *const u64, cap) }
    }

    fn as_mut_slice(&mut self) -> &mut [u64] {
        let base = self.base.load(Ordering::Acquire);
        let cap = self.cap.load(Ordering::Acquire);
        if base == 0 || cap == 0 {
            return &mut [];
        }
        // SAFETY: 同上；`&mut` 的独占性由调用方持 HANDLE 锁 + `&mut self` 共同保证。
        unsafe { core::slice::from_raw_parts_mut(base as *mut u64, cap) }
    }

    /// 装一个句柄进最小空闲 fd，返回 fd。**满了自动翻倍**（到 `FD_TABLE_MAX` 为止）。
    ///
    /// ## 扩容的发布协议（ADR-180 未决 3）
    ///
    /// 拷贝必须**在持 HANDLE 锁时**完成，且新表**先装好再换指针**：
    ///
    ///     1. 分配新表（锁外，走 PMM）
    ///     2. 拷旧内容 + 清尾巴
    ///     3. 一次性 store 新 base（Release）
    ///     4. 旧表**不立即归还**（可能有读者正拿着旧视图）
    ///
    /// 第 4 步是刻意的：`lookup` 走 `as_slice` 拿的是当时那个 base，
    /// 换指针之后它手里的旧切片仍然有效（内容还在）。若立刻归还旧页，
    /// 那个读者就读到已回收的内存。旧表由 `proc` 侧在进程销毁时一并还（见 `fd_tables`）。
    pub fn install(&mut self, h: Handle) -> Result<u32, HErr> {
        self.ensure()?;
        // 先找空位；满了就扩容再找。
        for _ in 0..4 {
            let cap = self.cap.load(Ordering::Acquire);
            let slice = self.as_mut_slice();
            for i in 0..cap {
                if slice[i] == 0 {
                    slice[i] = h.0;
                    self.used.fetch_add(1, Ordering::Relaxed);
                    return Ok(i as u32);
                }
            }
            // 满了：翻倍。到顶就返回耗尽。
            if cap >= FD_TABLE_MAX {
                return Err(HErr::Exhausted);
            }
            self.grow()?;
        }
        Err(HErr::Exhausted)
    }

    /// 把表翻倍（64 → 128 → … → `FD_TABLE_MAX`）。**调用方持 HANDLE 锁**。
    ///
    /// 返回新容量。旧表**不归还**（见 `install` 的第 4 步）。
    fn grow(&mut self) -> Result<usize, HErr> {
        let old_base = self.base.load(Ordering::Acquire);
        let old_cap = self.cap.load(Ordering::Acquire);
        if old_cap >= FD_TABLE_MAX {
            return Err(HErr::Exhausted);
        }
        let new_cap = (old_cap * 2).min(FD_TABLE_MAX);
        let bytes = new_cap * core::mem::size_of::<u64>();
        let pages = bytes.div_ceil(crate::mm::PAGE);
        let order = (usize::BITS - 1 - pages.leading_zeros()) as u8;
        // **起点是镜像末尾，不是 max_phys/2**（ADR-179 补记四）：
        //
        // `max_phys/2` 在 512 MiB 机器上是 256 MiB，而 `fs-open` 档的镜像
        // `phys_base` 已经到 353 MiB —— **镜像本身跨过了那条线**，于是向上找
        // 连续块时撞上镜像 ⇒ `handle::init 引导失败 OutOfMemory`（实测）。
        //
        // 镜像末尾一定在镜像之后，也一定在 bootloader 区之上（那个区在镜像之前）。
        let min_phys = crate::mm::image_phys_end()
            .unwrap_or_else(|| crate::mm::max_phys() / 2);
        let new_va = crate::mm::alloc_fd_table_pages(order, min_phys)
            .map_err(|_| HErr::Exhausted)?;
        // SAFETY: new_va 指向刚分配的连续帧（>= new_cap 个 u64）；
        // 调用方持 HANDLE 锁 ⇒ 独占；归 MOD_BOOT 永不归还（由 proc 侧记账）。
        unsafe {
            let dst = new_va as *mut u64;
            let src = old_base as *const u64;
            // 拷旧内容（old_cap 项），清尾巴（new_cap - old_cap 项）
            for i in 0..old_cap {
                core::ptr::write(dst.add(i), core::ptr::read(src.add(i)));
            }
            for i in old_cap..new_cap {
                core::ptr::write(dst.add(i), 0);
            }
        }
        // 一次性换指针（Release）：读者要么看到旧表、要么看到新表，不会看到半张。
        self.base.store(new_va, Ordering::Release);
        self.cap.store(new_cap, Ordering::Release);
        Ok(new_cap)
    }

    /// 这张表本体的 HHDM 地址（0 = 未分配）。
    ///
    /// **扩容后必须把它写回 `ProcEntry`**：`grow()` 换了新表，
    /// 主人若只知道旧 base，重建视图就会按新容量去读旧表（越界读脏）。
    pub fn base(&self) -> u64 {
        self.base.load(Ordering::Acquire)
    }

    /// 当前容量（0 = 未分配）。
    pub fn cap(&self) -> usize {
        self.cap.load(Ordering::Acquire)
    }

    /// fd → 句柄。fd 越界或该位为空 ⇒ `None`。
    pub fn lookup(&self, fd: u32) -> Option<Handle> {
        let slice = self.as_slice();
        let v = *slice.get(fd as usize)?;
        if v == 0 { None } else { Some(Handle(v)) }
    }

    /// 释放一个 fd，返回它原来装的句柄（`None` = 本来就空）。
    pub fn release(&mut self, fd: u32) -> Option<Handle> {
        let slice = self.as_mut_slice();
        let slot = slice.get_mut(fd as usize)?;
        let v = *slot;
        if v == 0 {
            return None;
        }
        *slot = 0;
        self.used.fetch_sub(1, Ordering::Relaxed);
        Some(Handle(v))
    }

    /// 当前已用个数。
    /// 已用个数。**现算，不存第二份真相**（ADR-180 实测教训）：
    /// `from_ptr` 重建的视图里 `used` 字段是 0（那个字段随临时值丢了），
    /// 存第二份就会与 entries 不一致。扫一遍 64 项代价可忽略。
    pub fn used(&self) -> usize {
        self.as_slice().iter().filter(|v| **v != 0).count()
    }

    /// 把 0/1/2 预置成给定的三个句柄（ADR-180 决策 2）。
    ///
    /// **必须在进程创建时调**：POSIX 程序不传 fd 就写 1，不预置等于任何 libc
    /// 程序的第一行输出就失败。
    pub fn preset_std(&mut self, stdin: Handle, stdout: Handle, stderr: Handle) -> Result<(), HErr> {
        self.ensure()?;
        let slice = self.as_mut_slice();
        slice[0] = stdin.0;
        slice[1] = stdout.0;
        slice[2] = stderr.0;
        self.used.store(3, Ordering::Relaxed);
        Ok(())
    }

    /// 分配一张 fd 表并返回它的 **HHDM 虚地址**（ADR-180）。
    ///
    /// ## 为什么返回裸地址而不是 `FdTable` 值
    ///
    /// `ProcEntry` 里存的是地址（`fd_table: AtomicU64`），不是值——值放进定长表
    /// 就是 ADR-179 撞过的 `.bss` 膨胀。所以这里给「分配 + 返回地址」，
    /// 由调用方（`proc_create`）把它装进 `ProcEntry`。
    ///
    /// ## 为什么在锁外调
    ///
    /// 内部走 `phys_alloc_above`（PMM，rank 30）。调用方若已持 VMM(20)，
    /// PMM 失败时回头取 VMM 记账 ⇒ 反向嵌套 ⇒ L4。`proc_create` 因此在
    /// `with_vmm_lock` **之外**调它。
    pub fn allocate() -> Result<u64, HErr> {
        let t = FdTable::new();
        t.ensure()?;
        let base = t.base.load(Ordering::Acquire);
        if base == 0 {
            return Err(HErr::Exhausted);
        }
        // 只返回 base。**容量是编译期常量**（`FD_TABLE_INIT`），不需要存在内存里；
        // 表本体只放 entries。`FdTable::from_ptr` 用常量重建视图。
        // **清零必须在这里再做一次**（ADR-180 实测）：
        //
        // `ensure()` 里清过，但那是在临时 `t` 上做的。调用方拿到 `base` 后用
        // `from_ptr` 重建视图，读的是同一块内存——若这块内存被分配器复用给过
        // 别人（`phys_alloc_above` 不保证返回零页），读出来就是脏的。
        // 实测症状：`procfd: 独立=false`（第二个进程的 `used()` 不是 0）。
        //
        // SAFETY: base 指向刚分配的连续帧（>= FD_TABLE_INIT 个 u64），
        // 调用方在锁外单线程路径；归 MOD_BOOT 永不归还。
        unsafe {
            let q = base as *mut u64;
            for i in 0..FD_TABLE_INIT {
                core::ptr::write(q.add(i), 0);
            }
        }
        Ok(base)
    }

    /// 从一个 `proc_create` 装进 `ProcEntry` 的地址重建视图（ADR-180）。
    ///
    /// ## 为什么需要它（实测教训）
    ///
    /// 第一版让 `proc_fd_table` 直接返回 `*mut FdTable`，然后 `&mut *p` 重建。
    /// 但 `ProcEntry` 里只存了 `base`（entries 的地址），**没存 `cap`/`used`** ⇒
    /// 重建出来的 `FdTable` 里 cap=0 ⇒ `as_mut_slice` 返回空 ⇒ `preset_std` 失败。
    /// 实测 `procfd: 取到=true 不同址=true 可用=false`。
    ///
    /// 修法：容量是编译期常量（`FD_TABLE_INIT`），`from_ptr` 直接用它；
    /// `used` 改成**每次现算**（扫一遍 entries），不存第二份真相。
    /// `cap` 是**这张表实际的容量**（`FD_TABLE_INIT` 或扩容后的值）。
    ///
    /// **为什么必须传进来**：`ProcEntry` 只存了 `base`（entries 的地址），
    /// 扩容之后容量不再是编译期常量 `FD_TABLE_INIT`。第一版让它恒等于
    /// `FD_TABLE_INIT`，扩容后重建的视图只看得见前 64 格 —— 后 960 格写了也读不到。
    pub fn from_ptr(base: u64, cap: usize) -> FdTable {
        FdTable {
            base: AtomicU64::new(base),
            cap: AtomicUsize::new(if base == 0 { 0 } else { cap }),
            used: AtomicUsize::new(0),
        }
    }
}

static TABLE: IrqSpinLock<Table> = IrqSpinLock::new(RANK_HANDLE, Table::empty());

/// 引导句柄槽数组（ADR-179）。**必须在 `mm::init_allocator()` 之后、任何任务跑起来之前**。
///
/// ## 为什么先分配、后取锁（这条写错了会当场 L4）
///
/// `RANK_HANDLE = 35`，`RANK_PMM = 30`。`lock-order.md` 对 35 的规矩是
/// 「表锁内只许调台账、不许调 mm」——因为 35 是**外层的下游**，从 35 里再取 30 是反向嵌套。
///
/// 第一版写成「持 TABLE 锁调 `slots.bootstrap()`」，实测当场：
///
///     [fatal] L4 sync: 锁序违规，外层 rank=35 本次 rank=30
///
/// **正确顺序**：先在锁外把连续帧分好（那时只取 PMM 30，没人持 35），
/// 再取 HANDLE 锁把基址装进去。装基址只写两个原子量，不碰 mm。
///
/// ## 失败语义
///
/// 分配失败往上传：`main` 收到 `Err` 走 `boot-invalid`（判定 37）。
/// **绝不允许**「失败就用空表继续跑」（ADR-179 决策 4）。
pub fn init() -> Result<(), crate::mm::MmError> {
    // 第一步：锁外分配。此时只取 PMM(30)，符合锁序。
    let slots = SlotArray::allocate()?;
    // 第二步：取 HANDLE 锁，只装基址与长度（两个原子写，不碰 mm）。
    let mut g = TABLE.lock();
    let t = g.get();
    t.slots = slots;
    Ok(())
}


/// 查表 + 所有校验。计数在这里加，所以每个拒绝都有读数。
fn check(t: &mut Table, h: Handle, owner: (usize, u32), need: u32) -> Result<usize, HErr> {
    let Some((slot, gen)) = h.unpack() else {
        t.c.invalid += 1;
        return Err(HErr::Invalid);
    };
    let e = &mut t.slots[slot as usize];
    if !e.used {
        t.c.no_such += 1;
        return Err(HErr::NoSuch);
    }
    if e.gen != gen {
        t.c.stale += 1;
        return Err(HErr::Stale);
    }
    // **同任务或同进程都算主人**（ADR-191）。
    //
    // 同任务：原来的语义，保持不变（boot 任务、单线程进程都走这条）。
    // 同进程：**新的一条**。Linux 里 fd 属于 `files_struct`，同一进程的线程共享；
    // 我们原来只比任务身份，于是线程 B 拿线程 A 的 fd 会 `-4 NotOwner`。
    //
    // 判据的顺序有讲究：先比任务（快、无依赖），不等再查进程。
    // `proc_id_of` 是只读快照、不取锁，所以能在 `TABLE` 锁内调。
    let same_task = e.owner_gidx as usize == owner.0 && e.owner_id == owner.1;
    let same_proc = !same_task
        // **不引用 `crate::proc::NO_PROC`**（ADR-191）：那是 `sched` 模块的符号，
        // 在非测试函数里引用会造出 `capability -> sched` 反向边。用同值字面量，
        // 由 `sched::install_proc_of` 里的 `assert!(NO_PROC == u16::MAX)` 守一致。
        && e.owner_proc != u16::MAX
        && proc_of(owner.0) == e.owner_proc;
    if !same_task && !same_proc {
        t.c.not_owner += 1;
        return Err(HErr::NotOwner);
    }
    if e.rights & need != need {
        t.c.denied += 1;
        return Err(HErr::Denied);
    }
    Ok(slot as usize)
}

/// 占一格并提交（**锁内**）。调用方已经在锁外给对象加好了它该有的那份引用。
fn insert(t: &mut Table, owner: (usize, u32), rights: u32, obj: ObjRef) -> Result<Handle, HErr> {
    let Some(slot) = t.slots.iter().position(|e| !e.used) else {
        t.c.exhausted += 1;
        return Err(HErr::Exhausted);
    };
    let next = next_gen(t.slots[slot].gen);
    t.slots[slot] = Entry {
        gen: next,
        used: true,
        owner_gidx: owner.0 as u16,
        owner_id: owner.1,
        owner_proc: proc_of(owner.0),
        rights,
        obj: Some(obj),
    };
    t.c.grants += 1;
    let live = t.live();
    if live > t.c.live_peak {
        t.c.live_peak = live;
    }
    Ok(Handle::pack(slot as u16, next))
}

pub fn grant_console(owner: (usize, u32), rights: u32, sid: u8) -> Result<Handle, HErr> {
    let mut g = TABLE.lock();
    insert(g.get(), owner, rights, ObjRef::Console(sid))
}

/// 给一次打开好的文件发句柄（**整盘**）。`cursor` 由调用方先 `mount`/`open_cursor` 得到——
/// 表里存的是**值**（C1：`port + Bpb + FileStat + 游标`），不存 `Volume` 的借用。
pub fn grant_file(owner: (usize, u32), port: u8, cursor: FileCursor, rights: u32) -> Result<Handle, HErr> {
    grant_file_at(owner, port, None, cursor, rights)
}

/// 给一个**分区里**打开好的文件发句柄（S2b）。`part` 进身份：`read` 会按它重建分区视图，
/// 所以同一口同一文件名的两个区间是两个对象。`None` 那一路（上面的 `grant_file`）语义逐字不变。
pub fn grant_file_at(
    owner: (usize, u32),
    port: u8,
    part: Option<Partition>,
    cursor: FileCursor,
    rights: u32,
) -> Result<Handle, HErr> {
    let mut g = TABLE.lock();
    insert(g.get(), owner, rights, ObjRef::File(FileObj { port, part, cursor, share: None }))
}

/// FS-03：打开好的 VFS 文件句柄。`stat` 是打开那一刻的目录项读数，不是实时元数据。
#[cfg(feature = "fs-open")]
pub fn grant_vfs_file(
    owner: (usize, u32),
    port: u8,
    part: Option<Partition>,
    cursor: ReadCursor,
    stat: VfsEntry,
    rights: u32,
    vol: u64,
) -> Result<Handle, HErr> {
    let mut g = TABLE.lock();
    insert(g.get(), owner, rights, ObjRef::VfsFile { port, part, cursor, stat, share: None, vol })
}

#[cfg(feature = "fs-open")]
pub fn grant_vfs_dir(
    owner: (usize, u32),
    port: u8,
    part: Option<Partition>,
    stat: VfsEntry,
    state: DirState,
    rights: u32,
) -> Result<Handle, HErr> {
    let mut g = TABLE.lock();
    insert(g.get(), owner, rights, ObjRef::VfsDir { port, part, stat, state })
}

#[cfg(feature = "fs-open")]
pub(crate) fn disk_for(port: u8, part: Option<Partition>) -> (AhciDisk, Option<Partition>) {
    (AhciDisk { port }, part)
}

#[cfg(feature = "fs-open")]
fn read_on_disk<T>(
    disk: &AhciDisk,
    part: Option<Partition>,
    f: impl FnOnce(&dyn Block) -> Result<T, HErr>,
) -> Result<T, HErr> {
    match part {
        None => f(disk),
        Some(p) => f(&PartitionView { inner: disk, part: p }),
    }
}

/// seek 用和读一样的两段式：锁内取票、锁外走 FAT、锁内按世代提交。
/// 中途盘失败或世代变了都不提交游标（ADR-108 §7）。
#[cfg(feature = "fs-open")]
pub fn seek(h: Handle, owner: (usize, u32), newpos: u32) -> Result<u32, HErr> {
    let (slot, gen, port, part, mut cursor, cell) = {
        let mut g = TABLE.lock();
        let t = g.get();
        let slot = check(t, h, owner, RIGHT_READ)?;
        let e_gen = t.slots[slot].gen;
        match t.slots[slot].obj {
            Some(ObjRef::VfsFile { port, part, cursor, share, .. }) => {
                let (cur, cell) = match share {
                    None => (cursor, None),
                    Some(i) => match t.cells[i as usize] {
                        Cell {
                            used: true,
                            gen,
                            cur: Some(CellCur::Vfs(c)),
                            ..
                        } => (c, Some((i, gen))),
                        _ => {
                            t.c.no_such += 1;
                            return Err(HErr::NoSuch);
                        }
                    },
                };
                (slot, e_gen, port, part, cur, cell)
            }
            Some(_) => {
                t.c.denied += 1;
                return Err(HErr::Denied);
            }
            None => {
                t.c.no_such += 1;
                return Err(HErr::NoSuch);
            }
        }
    };
    let disk = AhciDisk { port };
    let n = read_on_disk(&disk, part, |b| {
        vfs_ro::seek_disk(b, &mut cursor, newpos).map_err(vfs_to_herr)
    })?;
    let mut g = TABLE.lock();
    let t = g.get();
    if let Some((i, cg)) = cell {
        let c = &mut t.cells[i as usize];
        if !c.used || c.gen != cg {
            t.c.stale += 1;
            return Err(HErr::Stale);
        }
        let ok = match c.cur.as_mut() {
            Some(CellCur::Vfs(x)) => {
                *x = cursor;
                true
            }
            _ => false,
        };
        return if ok {
            Ok(n)
        } else {
            t.c.no_such += 1;
            Err(HErr::NoSuch)
        };
    }
    let e = &mut t.slots[slot];
    if !e.used || e.gen != gen {
        t.c.stale += 1;
        return Err(HErr::Stale);
    }
    match e.obj.as_mut() {
        Some(ObjRef::VfsFile { cursor: old, .. }) => {
            *old = cursor;
            Ok(n)
        }
        _ => {
            t.c.no_such += 1;
            Err(HErr::NoSuch)
        }
    }
}

#[cfg(feature = "fs-open")]
pub fn stat(h: Handle, owner: (usize, u32)) -> Result<VfsEntry, HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
    let slot = check(t, h, owner, 0)?;
    match t.slots[slot].obj {
        Some(ObjRef::VfsFile { stat, .. }) | Some(ObjRef::VfsDir { stat, .. }) => Ok(stat),
        Some(_) => {
            t.c.denied += 1;
            Err(HErr::Denied)
        }
        None => {
            t.c.no_such += 1;
            Err(HErr::NoSuch)
        }
    }
}

#[cfg(feature = "fs-open")]
pub struct DirTicket {
    slot: u16,
    gen: u64,
    port: u8,
    part: Option<Partition>,
    state: DirState,
}

#[cfg(feature = "fs-open")]
impl DirTicket {
    pub fn port(&self) -> u8 {
        self.port
    }

    pub fn partition(&self) -> Option<Partition> {
        self.part
    }
}

#[cfg(feature = "fs-open")]
pub fn begin_dir_read(h: Handle, owner: (usize, u32)) -> Result<DirTicket, HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
    let slot = check(t, h, owner, RIGHT_READ)?;
    let e = &t.slots[slot];
    match e.obj {
        Some(ObjRef::VfsDir { port, part, state, .. }) => {
            Ok(DirTicket { slot: slot as u16, gen: e.gen, port, part, state })
        }
        // 目录读专门把文件对象与别的对象类型分开：readdir 落在文件上不是"越权"，
        // 是类型形状错（用户会拿它重试），必须回 ENOTDIR。
        Some(ObjRef::File { .. }) | Some(ObjRef::VfsFile { .. }) => Err(HErr::Vfs(VfsError::NotDir)),
        Some(_) => {
            t.c.denied += 1;
            Err(HErr::Denied)
        }
        None => {
            t.c.no_such += 1;
            Err(HErr::NoSuch)
        }
    }
}

#[cfg(feature = "fs-open")]
pub fn next_dir_entry(ticket: &mut DirTicket) -> Result<Option<VfsEntry>, HErr> {
    let disk = AhciDisk { port: ticket.port };
    read_on_disk(&disk, ticket.part, |b| ticket.state.advance(b).map_err(vfs_to_herr))
}

#[cfg(feature = "fs-open")]
pub fn commit_dir_read(ticket: DirTicket) -> Result<(), HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
    let e = &mut t.slots[ticket.slot as usize];
    if !e.used || e.gen != ticket.gen {
        t.c.stale += 1;
        return Err(HErr::Stale);
    }
    match e.obj.as_mut() {
        Some(ObjRef::VfsDir { state, .. }) => {
            *state = ticket.state;
            Ok(())
        }
        _ => {
            t.c.no_such += 1;
            Err(HErr::NoSuch)
        }
    }
}

/// 给一个 VMO 发句柄（ADR-074 决策 1）。**引用在锁外加**（VMO 表那边取 VMM），
/// 占槽失败就在锁外退回那份引用 ⇒ HANDLE(35) 锁内一次 mm 调用都没有。
/// 调用方自己那份引用不受影响：要转移所有权就在拿到句柄之后自己 `vmo_unref`。
pub fn grant_vmo(owner: (usize, u32), id: crate::vmo::VmoId, rights: u32) -> Result<Handle, HErr> {
    crate::vmo::vmo_ref(id).map_err(|_| HErr::NoSuch)?;
    let r = {
        let mut g = TABLE.lock();
        insert(g.get(), owner, rights, ObjRef::Vmo { slot: id.slot() })
    };
    if r.is_err() {
        crate::vmo::vmo_unref(id);
    }
    r
}

/// 锁外判完活性之后，把这次拒绝记进台账。
/// **必须重新取一次 35**：活性判据要取 VMM(20)（proc/mm 的表在它下面），
/// 所以它只能在放掉句柄锁之后跑；计数还归台账，所以这里做第二次很短的取锁。
fn note(err: HErr) -> HErr {
    let mut g = TABLE.lock();
    let t = g.get();
    match err {
        HErr::Invalid => t.c.invalid += 1,
        HErr::NoSuch => t.c.no_such += 1,
        HErr::Stale => t.c.stale += 1,
        HErr::NotOwner => t.c.not_owner += 1,
        HErr::Denied => t.c.denied += 1,
        HErr::Exhausted => t.c.exhausted += 1,
        HErr::Io(_) => t.c.denied += 1,
        #[cfg(feature = "fs-open")]
        HErr::Vfs(_) => {}
    }
    err
}

/// 给一个 Job 发句柄（P5c-1）。**不加引用、不销毁**：见 `ObjRef` 那段。
///
/// `gen` 由**调用方**读好传进来（`proc::job_gen`），本模块不引用 `proc`/`sched`。
/// 为什么不在这里判活性：`sched → capability` 这条边本来就有（任务退出要 `revoke_task`），
/// 再来一条反向边就是一个二元强连通分量 ⇒ `sched` 从单例被拖进**冻结的核心环**，
/// 棘轮要一次性登记 `sched` 的十来条环内边（实测就是这么报红的，站点数 4/13/4/1）。
/// 槽位活性与世代判据因此归 `sched` 侧的消费方（c-3 的 11/15/16 在用之前自己核），
/// 用例把这条分工写成可判的读数，不留成散文。
pub fn grant_job(owner: (usize, u32), job: u16, gen: u32, rights: u32) -> Result<Handle, HErr> {
    let mut g = TABLE.lock();
    insert(g.get(), owner, rights, ObjRef::Job { slot: job, gen })
}

/// 进程版的 `grant_job`，同样由调用方传 `gen`。
pub fn grant_proc(owner: (usize, u32), proc_id: u16, gen: u32, rights: u32) -> Result<Handle, HErr> {
    let mut g = TABLE.lock();
    insert(g.get(), owner, rights, ObjRef::Proc { slot: proc_id, gen })
}

/// **按 `(owner, pid)` 反查一张带 `need` 权限的 Proc 句柄**（ADR-134 的 29 号接缝）。
///
/// **为什么是 capability 而不是"按 pid 直接操作"**：这里只在**调用者自己名下**的
/// 句柄里找——`owner` 两格必须与表项一致（`check` 用的同一组判据）。别人名下的
/// 同名进程句柄不算数：`pid` 只是寻址，授权仍由"你手里得有一张带 `RIGHT_WRITE`
/// 的句柄"决定。没有 ⇒ `NoSuch`（在用户侧是 `-5`），与 18 号对失效句柄的口径一致。
///
/// 世代不匹配（进程已被 reap 又复用槽）的句柄不算：`gen` 由调用方从
/// `proc::proc_gen(pid)` 取当前值传进来，旧的 gen 对不上就跳过（ABA）。
pub fn find_proc(owner: (usize, u32), pid: u16, gen: u32, need: u32) -> Result<Handle, HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
    for (i, e) in t.slots.iter().enumerate() {
        if !e.used
            || e.owner_gidx as usize != owner.0
            || e.owner_id != owner.1
            || e.rights & need != need
        {
            continue;
        }
        if let Some(ObjRef::Proc { slot, gen: obj_gen }) = e.obj {
            // 世代必须对上：进程槽号会复用，旧句柄的 gen 是上一任的（ABA）。
            if slot == pid && obj_gen == gen {
                return Ok(Handle::pack(i as u16, e.gen));
            }
        }
    }
    t.c.no_such += 1;
    Err(HErr::NoSuch)
}

/// 给一个地址空间发句柄。形状同 `grant_job`，活性判据换成 `mm::aspace_live`。
pub fn grant_aspace(owner: (usize, u32), slot: u16, rights: u32) -> Result<Handle, HErr> {
    let Some(gen) = crate::mm::aspace_gen(slot) else { return Err(note(HErr::NoSuch)) };
    let mut g = TABLE.lock();
    insert(g.get(), owner, rights, ObjRef::ASpace { slot, gen })
}

/// 给一条线程发句柄。`id` 由**调用方**读好传进来（`sched::id_of`），本模块不引用 `sched`。
///
/// **为什么不在这儿判活性**：`sched → capability` 这条边本来就有（任务退出要 `revoke_task`），
/// 反过来再来一条就是一个二元强连通分量 ⇒ `sched` 从单例被拖进冻结的核心环，
/// 棘轮要一次性登记 `sched` 的十来条环内边（实测报红就是这件事）。
/// 线程槽位的活性判据留在 `sched` 自己的入口（那里本来就要判 `state`），
/// 所以句柄层少这一判**不损失安全性**；用例 C4 把这条分工变成可判的读数。
/// 授一个 socket 句柄（ADR-181 决策 5）。
///
/// `gen` 是 `network::socket::create` 返回的世代号：槽号会复用，
/// 只比槽号会让新 socket 继承旧句柄（与 `Proc`/`Job` 同一条坑）。
pub fn grant_socket(owner: (usize, u32), slot: u16, gen: u32, rights: u32) -> Result<Handle, HErr> {
    if !crate::network::socket::live(slot, gen) {
        return Err(note(HErr::NoSuch));
    }
    let mut g = TABLE.lock();
    insert(g.get(), owner, rights, ObjRef::Socket { slot, gen })
}

pub fn grant_thread(owner: (usize, u32), gidx: usize, id: u32, rights: u32) -> Result<Handle, HErr> {
    if id == 0 {
        return Err(note(HErr::NoSuch));
    }
    let mut g = TABLE.lock();
    insert(g.get(), owner, rights, ObjRef::Thread { gidx, id })
}

/// 这个名字指向的对象还活着吗（**句柄锁外**判，取 VMM/任务表快照）。
fn obj_live(o: &ObjRef) -> bool {
    match *o {
        // Job/Proc/Thread 不在句柄层判：引用 proc/sched 会把 sched 拖进冻结的核心环
        // （`sched -> capability` 已有 `revoke_task` 那一条）。判据在 sched 侧的消费方，
        // 用例 C1b/C2b/C4 各配一格读数，把"谁判"变成可判的事实而不是注释。
        ObjRef::Job { .. } | ObjRef::Proc { .. } => true,
        ObjRef::ASpace { slot, gen } => crate::mm::aspace_live(slot, gen),
        // Thread 不在句柄层判：见 `grant_thread` 的"为什么不在这儿判活性"
        ObjRef::Thread { .. } => true,
        // File/Vmo 有自己的活性判据（游标有效性在盘路径、VMO 引用计数在 vmo 表）
        _ => true,
    }
}

/// 句柄 → `(对象引用, 权限)`，供"用之前先看本体在不在"的调用点用（c-3 的 11/15/16）。
/// 三段：锁内校验并复制引用 → 放锁后判活性 → 直接返回。中途失败只在 `note` 里补计数。
pub fn resolve(h: Handle, owner: (usize, u32), need: u32) -> Result<(ObjRef, u32), HErr> {
    let pair = {
        let mut g = TABLE.lock();
        let t = g.get();
        let slot = check(t, h, owner, need)?;
        match t.slots[slot].obj {
            Some(o) => Some((o, t.slots[slot].rights)),
            None => {
                t.c.no_such += 1;
                None
            }
        }
    };
    let Some((obj, rights)) = pair else { return Err(HErr::NoSuch) };
    if !obj_live(&obj) {
        return Err(note(HErr::NoSuch));
    }
    Ok((obj, rights))
}

/// 这个句柄是否**带着** `need` 里的全部权限位（`RIGHT_CREATE` 的判据接缝，c-3 用）。
/// 拒绝已经由 `check` 记在台账里（`denied`），这里只把它变成布尔。
pub fn has(h: Handle, owner: (usize, u32), need: u32) -> bool {
    match resolve(h, owner, need) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// 句柄 → 地址空间**槽号**（ADR-075 决策 6：14 号的 `rdx`）。形状照 `vmo_of`：
/// 锁内查表取引用，槽号是 Copy ⇒ 不需要锁外那一步。
/// 世代与 `used` 的活性核对留给 `mm::aspace_map_slot`（`capability -> memory` 已登记，
/// 但那两把锁的取放次序归 mm 自己，句柄层不在 35 之内取 VMM）。
pub fn aspace_of(h: Handle, owner: (usize, u32), need: u32) -> Result<u16, HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
    let slot = check(t, h, owner, need)?;
    match t.slots[slot].obj {
        Some(ObjRef::ASpace { slot, .. }) => Ok(slot),
        _ => {
            t.c.denied += 1;
            Err(HErr::Denied)
        }
    }
}

/// 转移一个句柄的**所有权**（P5c-3a，ADR-075 决策 4）：改 `owner` 两格 + bump 世代。
///
/// - 要 `RIGHT_TRANSFER`（16 号位，ADR-073 已占）。
/// - **发送方的旧句柄当场 `Stale`**：世代号在 `check` 里比不过 ⇒ 这条不需要新计数器，
///   `counters().stale` 的增量就是证人（D3）。
/// - 返回的是**新句柄值**——`process_start` 回填 `StartupInfo.handles[].handle` 用的正是它。
///   这也解释了为什么回填必须在转移之后：句柄值含世代号，转移之前谁也填不出来。
/// - 表仍是全局 16 格（决策 4）：这里没有"移进新进程的表"，只有名字换了主人。
pub fn transfer(h: Handle, from: (usize, u32), to: (usize, u32)) -> Result<Handle, HErr> {
    if from == to {
        return Err(note(HErr::Invalid));
    }
    let mut g = TABLE.lock();
    let t = g.get();
    let slot = check(t, h, from, RIGHT_TRANSFER)?;
    let e = &mut t.slots[slot];
    let next = next_gen(e.gen);
    e.gen = next;
    e.owner_gidx = to.0 as u16;
    e.owner_id = to.1;
    e.owner_proc = proc_of(to.0);
    t.c.transfers += 1;
    Ok(Handle::pack(slot as u16, next))
}

/// 回滚一次转移（`process_start` 第③步失败时调，ADR-075 决策 3 的那条"②③任一步失败必须回滚②"）。
/// 用**新句柄值**定位槽位、核对现在的主人就是 `to`，然后把 owner 改回 `from` 并**再 bump 一次世代**
/// ⇒ 中间态那个新句柄当场失效。
///
/// **返回回滚之后的可用名字**（P5c-3 的 refinement，实测逼出来的）：bump 之后**发送方原来那个
/// 句柄也一起失效**，如果这里只返回 `()`，那一格就变成"谁都 close 不掉的孤儿"——
/// 现场是漏一份 VMO 引用与一帧、并把后面 14 格用例的收尾闸全打红。
/// 交回新名字之后调用方 `close` 它即可回到基线，不需要动用 `revoke_task` 那种大范围撤销。
pub fn transfer_rollback(new_h: Handle, to: (usize, u32), from: (usize, u32)) -> Result<Handle, HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
    let Some((slot, gen)) = new_h.unpack() else {
        t.c.invalid += 1;
        return Err(HErr::Invalid);
    };
    let e = &mut t.slots[slot as usize];
    if !e.used || e.gen != gen || e.owner_gidx as usize != to.0 || e.owner_id != to.1 {
        // 回滚点已经不在这个状态上（槽被关掉/被别人接走）：不硬来，报 NoSuch 让调用方整段退场
        t.c.no_such += 1;
        return Err(HErr::NoSuch);
    }
    let next = next_gen(gen);
    e.gen = next;
    e.owner_gidx = from.0 as u16;
    e.owner_id = from.1;
    e.owner_proc = proc_of(from.0);
    t.c.transfers += 1;
    Ok(Handle::pack(slot, next))
}

/// 每槽独立；1..=GEN_MAX，跳过 0；到顶**回绕到 1**（设计 §9 G：承诺是计数上界，
/// 不是"永远"）。旧句柄在 `GEN_MAX-1` 次后续复用内必然对不上。
fn next_gen(prev: u64) -> u64 {
    if prev == 0 || prev >= GEN_MAX {
        1
    } else {
        prev + 1
    }
}

/// 关句柄。**两段式**（ADR-074 决策 1）：锁内校验 + 取走引用 + 清槽，
/// **放掉 HANDLE(35) 之后**才 `vmo_unref`（它要取 VMM(20)，在锁内调就是 35→20 的反向嵌套）。
/// 所以"句柄已失效"与"帧已归还"是两个时刻：判据要读 unref 之后的台账。
pub fn close(h: Handle, owner: (usize, u32)) -> Result<(), HErr> {
    let obj = {
        let mut g = TABLE.lock();
        let t = g.get();
        let slot = check(t, h, owner, 0)?;
        let obj = t.slots[slot].obj.take();
        // 共享格子（ADR-108 补记二）：关掉一条名字只减引用，最后一条关上才丢格子。
        match obj {
            Some(ObjRef::File(f)) => {
                if let Some(i) = f.share {
                    cell_release(t, i);
                }
            }
            #[cfg(feature = "fs-open")]
            Some(ObjRef::VfsFile { share, .. }) => {
                if let Some(i) = share {
                    cell_release(t, i);
                }
            }
            _ => {}
        }
        t.slots[slot].used = false;
        t.slots[slot].rights = 0;
        // gen 保留：这一格下一回 grant 在它上面 +1（旧句柄因此变成 Stale）。
        t.c.closes += 1;
        obj
    };
    if let Some(ObjRef::Vmo { slot }) = obj {
        crate::vmo::vmo_unref(crate::vmo::VmoId::from_slot(slot));
    }
    Ok(())
}

/// `dup` = 新占一格、同对象、权限收窄。第一版**没有** `DUP` 就没有 `dup`；
/// `new ⊄ old` 一律拒（扩权是这一格存在的理由）。
///
/// 对象语义按 kind 分三种（ADR-108 补记二改了第一种）：
/// * 文件 / VFS 文件：dup 之后**共享读取位置**——游标搬进 `Table.cells`，两条句柄推进同一份。
///   搬格子与 `insert` 在**同一把** HANDLE 锁内完成，不取别的锁，锁序不变。
/// * VMO：共享**同一份帧**（靠 `vmo_ref`，ADR-074 的 C3）。那份引用必须在锁外加，
///   所以仍走"取票（锁内）→ 加引用（锁外）→ 提交（锁内）"三段；提交失败在锁外退回引用。
/// * 其余 kind：引用本来就是"槽号 + 世代"，复制值即共享本体。
pub fn dup(h: Handle, owner: (usize, u32), new_rights: u32) -> Result<Handle, HErr> {
    {
        let mut g = TABLE.lock();
        let t = g.get();
        let slot = check(t, h, owner, RIGHT_DUP)?;
        let old = t.slots[slot];
        if new_rights & !old.rights != 0 {
            t.c.denied += 1;
            return Err(HErr::Denied);
        }
        let shared = match old.obj {
            Some(ObjRef::File(f)) => {
                let i = match f.share {
                    Some(i) => {
                        cell_retain(t, i);
                        i
                    }
                    None => match cell_alloc(t, CellCur::Fat(f.cursor)) {
                        // 格子出生时只有一条引用；新名字再加一条（一共 2 条）。
                        Some(i) => {
                            cell_retain(t, i);
                            i
                        }
                        None => return Err(HErr::Exhausted),
                    },
                };
                Some(ObjRef::File(FileObj { share: Some(i), ..f }))
            }
            #[cfg(feature = "fs-open")]
            Some(ObjRef::VfsFile { port, part, cursor, stat, share, vol }) => {
                let i = match share {
                    Some(i) => {
                        cell_retain(t, i);
                        i
                    }
                    None => match cell_alloc(t, CellCur::Vfs(cursor)) {
                        Some(i) => {
                            cell_retain(t, i);
                            i
                        }
                        None => return Err(HErr::Exhausted),
                    },
                };
                Some(ObjRef::VfsFile { port, part, cursor, stat, share: Some(i), vol })
            }
            Some(_) => None,
            None => {
                t.c.no_such += 1;
                return Err(HErr::NoSuch);
            }
        };
        if let Some(obj) = shared {
            // 原句柄也改指向共享格子（第一次 dup 时它是 None；之后的 dup 是同一个 i）。
            t.slots[slot].obj = Some(obj);
            return insert(t, owner, new_rights, obj);
        }
    }
    let obj = {
        let mut g = TABLE.lock();
        let t = g.get();
        let slot = check(t, h, owner, RIGHT_DUP)?;
        match t.slots[slot].obj {
            Some(o) => o,
            None => {
                t.c.no_such += 1;
                return Err(HErr::NoSuch);
            }
        }
    };
    // **VMO 与 Socket 都要加对象级引用**（ADR-192）：它们的本体住在旁表里，
    // 句柄只是名字。`dup` 之后两条名字共享一个本体，`close` 减到 0 才销毁。
    //
    // 加引用必须在**锁外**（`sock_ref` 要取 `RANK_NET(36)`，在 HANDLE(35) 里取就是
    // 正向嵌套但会让持锁时间变长；更重要的是提交失败要能退回）。
    if let ObjRef::Vmo { slot } = obj {
        if crate::vmo::vmo_ref(crate::vmo::VmoId::from_slot(slot)).is_err() {
            return Err(HErr::NoSuch);
        }
    }
    if let ObjRef::Socket { slot, gen } = obj {
        if !crate::network::socket::sock_ref(slot, gen) {
            return Err(HErr::NoSuch);
        }
    }
    let r = {
        let mut g = TABLE.lock();
        insert(g.get(), owner, new_rights, obj)
    };
    if r.is_err() {
        if let ObjRef::Vmo { slot } = obj {
            crate::vmo::vmo_unref(crate::vmo::VmoId::from_slot(slot));
        }
        if let ObjRef::Socket { slot, gen } = obj {
            let _ = crate::network::socket::sock_unref(slot, gen);
        }
    }
    r
}

/// 查出句柄背后的 VMO 引用（ADR-074 的 syscall 13/14 用）。**锁内只读表**：
/// 校验形状/世代/主人/权限之后把 Copy 的槽号带出去，对象本体的操作一律在放锁之后做。
pub fn vmo_of(h: Handle, owner: (usize, u32), need: u32) -> Result<crate::vmo::VmoId, HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
    let slot = check(t, h, owner, need)?;
    match t.slots[slot].obj {
        Some(ObjRef::Vmo { slot }) => Ok(crate::vmo::VmoId::from_slot(slot)),
        // 类型不符：不是"槽不存在"，计数分开
        _ => {
            t.c.denied += 1;
            Err(HErr::Denied)
        }
    }
}

/// 读票：锁内取走游标的副本，锁外读盘，锁内提交。中途任何失败都只是丢掉这张票——
/// 表项里的游标一格不动（"失败不提交"与 `FileCursor::read` 的语义同一条）。
#[derive(Clone, Copy)]
enum ReadTicketKind {
    Fat(FileCursor),
    #[cfg(feature = "fs-open")]
    Vfs(ReadCursor, u64),
}

pub struct ReadTicket {
    slot: u16,
    gen: u64,
    port: u8,
    part: Option<Partition>,
    /// 共享游标格 `(下标, 世代)`；`None` = 游标在本表项（未 dup 的老形状）。
    cell: Option<(u8, u32)>,
    kind: ReadTicketKind,
}

impl ReadTicket {
    pub fn port(&self) -> u8 {
        self.port
    }

    /// 这张票属于哪个分区（`None` = 整盘）。`read` 据此决定重建整盘还是分区视图。
    pub fn partition(&self) -> Option<Partition> {
        self.part
    }

    pub fn position(&self) -> u32 {
        match self.kind {
            ReadTicketKind::Fat(c) => c.position(),
            #[cfg(feature = "fs-open")]
            ReadTicketKind::Vfs(c, _) => c.position(),
        }
    }

    pub fn size(&self) -> u32 {
        match self.kind {
            ReadTicketKind::Fat(c) => c.stat().size,
            #[cfg(feature = "fs-open")]
            ReadTicketKind::Vfs(c, _) => c.size(),
        }
    }

    pub fn read_chunk(&mut self, disk: &dyn Block, dst: &mut [u8]) -> Result<usize, HErr> {
        match self.kind {
            ReadTicketKind::Fat(ref mut c) => c.read(disk, dst).map_err(HErr::Io),
            #[cfg(feature = "fs-open")]
            ReadTicketKind::Vfs(ref mut c, vol) => {
                // **保持不缓存版**（ADR-238 实测）：
                //
                // 锁序前提已满足（ADR-222 把 `XFER` 改成 `GROW(4)`），
                // 但**实测启用缓存让失败率从 4/20 涨到 7/20**：
                //
                //   `handles,fs-open` 无缓存：4/20
                //   `handles,fs-open` 有缓存：**7/20**
                //
                // 缓存改变了读路径的时序，加剧了那条既有竞态（ADR-228~237：
                // 探针自己的页在被回收后仍被读）。
                //
                // **缓存不能以稳定性为代价** —— 等那条竞态修好再启用。
                let n = vfs_ro::read_disk(disk, c, dst).map_err(vfs_to_herr)?;
                Ok(n)
            }
        }
    }
}

pub fn begin_read(h: Handle, owner: (usize, u32)) -> Result<ReadTicket, HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
    let slot = check(t, h, owner, RIGHT_READ)?;
    let e_gen = t.slots[slot].gen;
    let made = match t.slots[slot].obj {
        Some(ObjRef::File(f)) => {
            let (cur, cell) = match f.share {
                None => (f.cursor, None),
                Some(i) => match t.cells[i as usize] {
                    Cell {
                        used: true,
                        gen,
                        cur: Some(CellCur::Fat(c)),
                        ..
                    } => (c, Some((i, gen))),
                    _ => Err(HErr::NoSuch)?,
                },
            };
            Ok(ReadTicket {
                slot: slot as u16,
                gen: e_gen,
                port: f.port,
                part: f.part,
                cell,
                kind: ReadTicketKind::Fat(cur),
            })
        }
        #[cfg(feature = "fs-open")]
        Some(ObjRef::VfsFile { port, part, cursor, share, vol, .. }) => {
            let (cur, cell) = match share {
                None => (cursor, None),
                Some(i) => match t.cells[i as usize] {
                    Cell {
                        used: true,
                        gen,
                        cur: Some(CellCur::Vfs(c)),
                        ..
                    } => (c, Some((i, gen))),
                    _ => Err(HErr::NoSuch)?,
                },
            };
            Ok(ReadTicket {
                slot: slot as u16,
                gen: e_gen,
                port,
                part,
                cell,
                kind: ReadTicketKind::Vfs(cur, vol),
            })
        }
        // 目录句柄有对象、有 READ 权，但"读一个目录的字节"这件事在 VFS 层就不成立：
        // ADR-108 决策 3 要的是 `-11 EISDIR`，不是类型不符的 `-4`。（ring3 探针实测抓到过 -4。）
        #[cfg(feature = "fs-open")]
        Some(ObjRef::VfsDir { .. }) => Err(HErr::Vfs(crate::filesystem::vfs_ro::VfsError::IsDir)),
        // 不是文件对象就没有"文件读"这回事（VMO 与 P5c-1 的四种 kind 同理）：
        // 这是类型/权限不符，不是"槽不存在"，两个计数器分开
        Some(_) => {
            t.c.denied += 1;
            Err(HErr::Denied)
        }
        None => {
            t.c.no_such += 1;
            Err(HErr::NoSuch)
        }
    };
    made
}

/// 提交。表项必须仍是同一槽、同一世代——否则这次读的成果作废（返回 Stale）。
pub fn finish(ticket: ReadTicket, bytes: usize) -> Result<(), HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
    let committed = if let Some((i, cg)) = ticket.cell {
        // 共享格子：只认格子的世代。句柄可以在读盘期间被别的名字关掉——那不影响提交，
        // 只要这个文件对象还有别的名字（POSIX 的 open-file-description 语义）。
        let c = &mut t.cells[i as usize];
        if !c.used || c.gen != cg {
            t.c.stale += 1;
            return Err(HErr::Stale);
        }
        match (c.cur.as_mut(), ticket.kind) {
            (Some(CellCur::Fat(x)), ReadTicketKind::Fat(k)) => {
                *x = k;
                true
            }
            #[cfg(feature = "fs-open")]
            (Some(CellCur::Vfs(x)), ReadTicketKind::Vfs(k, _)) => {
                *x = k;
                true
            }
            _ => false,
        }
    } else {
        let e = &mut t.slots[ticket.slot as usize];
        if !e.used || e.gen != ticket.gen {
            t.c.stale += 1;
            return Err(HErr::Stale);
        }
        match (e.obj.as_mut(), ticket.kind) {
            (Some(ObjRef::File(f)), ReadTicketKind::Fat(c)) => {
                f.cursor = c;
                true
            }
            #[cfg(feature = "fs-open")]
            (Some(ObjRef::VfsFile { cursor: old, .. }), ReadTicketKind::Vfs(c, _)) => {
                *old = c;
                true
            }
            _ => false,
        }
    };
    if !committed {
        t.c.no_such += 1;
        return Err(HErr::NoSuch);
    }
    t.c.reads += 1;
    t.c.bytes += bytes as u64;
    Ok(())
}

#[cfg(feature = "fs-open")]
fn vfs_to_herr(e: VfsError) -> HErr {
    match e {
        // 既有块设备失败仍走 Io，保持 10 号的老负样本语义不变；其余 VFS 成因不降级成"盘坏"。
        VfsError::Fs(FsError::Io(be)) => HErr::Io(FsError::Io(be)),
        _ => HErr::Vfs(e),
    }
}

/// 丢弃一张票：表项不动。显式函数而不是 `Drop`，是为了让"没有提交"在调用点看得见。
pub fn abort(_ticket: ReadTicket) {}

/// 写方向的取票（ADR-111）：与 `begin_read` 对称，但**只认 `VfsFile`**，且要 `RIGHT_WRITE`。
///
/// 票里装的是游标的**副本**：`write_at` 在副本上推进 `position`，成功之后由 `finish` 原样写回表
/// （`finish` 只做 `*old = c`，不会再加一遍 `bytes`——那正是这里能直接复用它提交的原因）。
#[cfg(feature = "fs-rw")]
pub fn begin_write(h: Handle, owner: (usize, u32)) -> Result<ReadTicket, HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
    let slot = check(t, h, owner, RIGHT_WRITE)?;
    let e_gen = t.slots[slot].gen;
    match t.slots[slot].obj {
        Some(ObjRef::VfsFile { port, part, cursor, share, vol, .. }) => {
            let (cur, cell) = match share {
                None => (cursor, None),
                Some(i) => match t.cells[i as usize] {
                    Cell {
                        used: true,
                        gen,
                        cur: Some(CellCur::Vfs(c)),
                        ..
                    } => (c, Some((i, gen))),
                    _ => return Err(HErr::Denied),
                },
            };
            Ok(ReadTicket {
                slot: slot as u16,
                gen: e_gen,
                port,
                part,
                cell,
                kind: ReadTicketKind::Vfs(cur, vol),
            })
        }
        // 目录句柄、以及任何非文件对象：写不成立。与读的 `-11 EISDIR` 相对，这里回类型不符。
        _ => Err(HErr::Denied),
    }
}

/// 把一段字节写进票里的游标（覆盖已有区间，越 EOF 由 `write_at` 整次拒）。
#[cfg(feature = "fs-rw")]
pub fn write_chunk(ticket: &mut ReadTicket, disk: &dyn Block, src: &[u8]) -> Result<usize, HErr> {
    match ticket.kind {
        ReadTicketKind::Vfs(ref mut c, _) => vfs_ro::write_at(disk, c, src).map_err(vfs_to_herr),
        _ => Err(HErr::Denied),
    }
}

/// 生产路径：按表项里的口**与分区区间**重建块设备。一次读全部分配的 `dst`（事务性）。
/// 区间是身份的一部分（S2b）：这里若只重建 `AhciDisk{port}`，偏移在第一次读之后就丢了，
/// 而句柄看起来还是"那个分区里的文件"——那种错法读出来的字节合法、内容却是别人的。
pub fn read(h: Handle, owner: (usize, u32), dst: &mut [u8]) -> Result<usize, HErr> {
    let mut ticket = begin_read(h, owner)?;
    let disk = AhciDisk { port: ticket.port() };
    let n = match ticket.partition() {
        None => ticket.read_chunk(&disk, dst)?,
        Some(part) => ticket.read_chunk(&PartitionView { inner: &disk, part }, dst)?,
    };
    finish(ticket, n)?;
    Ok(n)
}

/// 取证路径：注入块设备（内存夹具）。与 `read` 共用取票/提交，只有盘不同。
/// **分区区间照样生效**：否则同一张票经两条路读出来的字节会不同，而两条路都自称"读这个句柄"。
#[cfg(feature = "fat32-probe")]
pub fn read_with(h: Handle, owner: (usize, u32), disk: &dyn Block, dst: &mut [u8]) -> Result<usize, HErr> {
    let mut ticket = begin_read(h, owner)?;
    let n = match ticket.partition() {
        None => ticket.read_chunk(disk, dst)?,
        Some(part) => ticket.read_chunk(&PartitionView { inner: disk, part }, dst)?,
    };
    finish(ticket, n)?;
    Ok(n)
}

/// ADR-098 诊断：句柄表当前占了几格（容量以 `MAX_HANDLES` 为唯一事实）。
/// 只读、只取一次表锁；用来把 16 号里的 `-6` 分成"表满"与"表不满"两种——
/// 这两类的下一步完全不同（前者去查谁没还，后者去查 `transfer` 的权限/世代）。
pub fn used() -> usize {
    TABLE.lock().get().live() as usize
}

/// 任务退出撤销（`reap` 调用）：主人的两格都对上的表项全部清掉。
/// **两段式**（ADR-074 决策 1）：锁内清槽并把 VMO 槽号抄出来，**放锁之后**逐个 `vmo_unref`。
/// 文件对象仍然不持帧（设计 §7）；VMO 持帧，所以归还这一步必须发生在 HANDLE 锁之外。
/// 调用点 `sched.rs:343` 也不在 RUNQ 锁内 ⇒ 这条路上没有"拿队列锁等跨 CPU 回执"的形状。
pub fn revoke_task(gidx: usize, id: u32) -> usize {
    let mut vmos = [0u8; MAX_REVOKE_VMOS];
    let mut nv = 0usize;
    let n = {
        let mut g = TABLE.lock();
        let t = g.get();
        let mut n = 0u32;
        for i in 0..MAX_HANDLES {
            if t.slots[i].used && t.slots[i].owner_gidx as usize == gidx && t.slots[i].owner_id == id
            {
                match t.slots[i].obj.take() {
                    Some(ObjRef::Vmo { slot }) => {
                        // 有界：超出的不收集（VMO 引用会在下面按 slot 释放，
                        // 但栈数组只容 MAX_REVOKE_VMOS 个——**不能越界写**）。
                        if nv < vmos.len() {
                            vmos[nv] = slot;
                            nv += 1;
                        }
                    }
                    Some(ObjRef::File(f)) => {
                        if let Some(c) = f.share {
                            cell_release(t, c);
                        }
                    }
                    #[cfg(feature = "fs-open")]
                    Some(ObjRef::VfsFile { share, .. }) => {
                        if let Some(c) = share {
                            cell_release(t, c);
                        }
                    }
                    _ => {}
                }
                t.slots[i].used = false;
                t.slots[i].obj = None;
                t.slots[i].rights = 0;
                n += 1;
            }
        }
        t.c.revoked += n;
        n
    };
    for slot in vmos.iter().take(nv) {
        crate::vmo::vmo_unref(crate::vmo::VmoId::from_slot(*slot));
    }
    n as usize
}

pub fn live() -> usize {
    let mut g = TABLE.lock();
    g.get().live() as usize
}

pub fn counters() -> Counters {
    let mut g = TABLE.lock();
    g.get().c
}

#[cfg(feature = "fat32-probe")]
pub fn preset_gen(slot: usize, gen: u64) {
    let obj = {
        let mut g = TABLE.lock();
        let t = g.get();
        if slot < MAX_HANDLES {
            t.slots[slot].gen = gen & GEN_MAX;
            t.slots[slot].used = false;
            t.slots[slot].obj.take()
        } else {
            None
        }
    };
    if let Some(ObjRef::Vmo { slot }) = obj {
        crate::vmo::vmo_unref(crate::vmo::VmoId::from_slot(slot));
    }
}

/// 只清槽，不清计数器：分段用例之间要清表，但"这一轮发生过几次拒绝"必须能累计到最后的日志。
#[cfg(any(feature = "fat32-probe", feature = "fs-open"))]
pub fn reset_for_test() {
    let mut vmos = [0u8; MAX_REVOKE_VMOS];
    let mut nv = 0usize;
    {
        let mut g = TABLE.lock();
        let t = g.get();
        for e in t.slots.iter_mut() {
            if let Some(ObjRef::Vmo { slot }) = e.obj.take() {
                if nv < vmos.len() {
                    vmos[nv] = slot;
                    nv += 1;
                }
            }
        }
        // ADR-179：`slots` 现在是运行时分配的 `SlotArray`，不是定长数组，
        // 不能再整体赋值。逐项写回 `EMPTY`（语义完全一致）。
        for e in t.slots.iter_mut() {
            *e = EMPTY;
        }
    }
    // 清表也要把 VMO 的引用还掉，否则用例之间会漏帧（锁外还，同 close/revoke）
    for slot in vmos.iter().take(nv) {
        crate::vmo::vmo_unref(crate::vmo::VmoId::from_slot(*slot));
    }
}

#[cfg(any(feature = "fat32-probe", feature = "fs-open"))]
pub fn reset_counters_for_test() {
    let mut g = TABLE.lock();
    g.get().c = Counters::default();
}

#[cfg(feature = "fat32-probe")]
mod tests {
    use super::*;
    use crate::filesystem::fat32::Volume;
    use crate::filesystem::vfs::MemDisk;

    const IMAGE: &[u8] = include_bytes!("../../fixtures/fat32-mem.img");
    const OWNER: (usize, u32) = (5, 77);

    fn fixture() -> Option<FileCursor> {
        let disk = MemDisk { img: IMAGE };
        let vol = match Volume::mount(&disk) {
            Ok(v) => v,
            Err(e) => {
                crate::log_fatal!("handle: 夹具挂载失败 {:?}", e);
                return None;
            }
        };
        match vol.open_cursor("LONG~1.TXT") {
            Ok(c) => Some(c),
            Err(e) => {
                crate::log_fatal!("handle: 夹具打开失败 {:?}", e);
                None
            }
        }
    }

    fn pattern(bytes: &[u8], start: usize) -> bool {
        bytes.iter().enumerate().all(|(i, b)| {
            let n = start + i;
            *b == ((n / 512) * 29 + (n % 512) * 3 + 0x11) as u8
        })
    }

    pub fn t_handle_table() -> bool {
        reset_for_test();
        reset_counters_for_test();
        // 句柄基线（§463）：`reset_for_test()` 之后、本用例授出任何句柄之前。
        //
        // ⑨ 段的 `revoke_ok` 判「撤销之后表回到基线」，不判「全系统归零」——句柄是
        // **多主人**资源，`.ktests` 的顺序由链接器决定，`== 0` 就成了判据依赖用例顺序。
        // 基线必须记在这里而不是 ⑨ 段之前：记在 ⑨ 段之前会把 ①–⑧ 段的泄漏算进基线，
        // 判据就看不见它了。
        let h0 = live();
        let Some(cur) = fixture() else { return false };

        // ① 打包形状：48 位世代填满高位；0 / gen 0 / slot 越界 全非法
        //
        // **不能直接用 `MAX_HANDLES`**（ADR-189 补记）：`MAX_HANDLES` 在非 `fs-open`
        // 档是 131072，`as u16` 截成 0，`0 - 1` 编译期就溢出（实测 `fat32-exec` 档红）。
        // 句柄的 slot 字段是 16 位，所以「能装下的最大值」是 `u16::MAX`。
        let slot_max = if MAX_HANDLES > u16::MAX as usize {
            u16::MAX
        } else {
            (MAX_HANDLES - 1) as u16
        };
        let h = Handle::pack(3, 5);
        let pack_ok = h.0 == 3 | (5u64 << 16) && h.unpack() == Some((3, 5))
            && Handle::pack(slot_max, GEN_MAX).unpack() == Some((slot_max, GEN_MAX))
            && Handle::pack(0, 0).unpack().is_none()
            && Handle(0).unpack().is_none();

        // ② 撤销后复用同槽：旧句柄 Stale，新句柄 gen 变了
        let a = match grant_file(OWNER, 3, cur, RIGHT_READ | RIGHT_DUP) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let close_ok = close(a, OWNER).is_ok();
        let b = match grant_file(OWNER, 3, cur, RIGHT_READ | RIGHT_DUP) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let stale_ok = a.slot() == b.slot() && a.gen() != b.gen()
            && begin_read(a, OWNER).is_err()
            && counters().stale >= 1;

        // ③ owner 两格：错一格都拒，且计到 NotOwner（不是侥幸 Stale）
        let owner_ok = begin_read(b, (5, 78)).is_err()
            && begin_read(b, (6, 77)).is_err()
            && counters().not_owner >= 2;

        // ④ 越权：dup(h,0) 之后读 ⇒ Denied；dup 扩权 / 无 DUP 权 ⇒ Denied
        let zero = match dup(b, OWNER, 0) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let denied_ok = begin_read(zero, OWNER).is_err()
            && dup(b, OWNER, RIGHT_READ | RIGHT_WRITE).is_err()
            && counters().denied >= 2;
        let nocap = match grant_file(OWNER, 3, cur, RIGHT_READ) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let nocap_ok = dup(nocap, OWNER, RIGHT_READ).is_err();
        close(zero, OWNER).ok();
        close(nocap, OWNER).ok();
        close(b, OWNER).ok();

        // ⑤ 表满：全槽填满后下一次 grant 必须 Exhausted；既有句柄仍可读。
        reset_for_test();
        let first_handle = match grant_file(OWNER, 3, cur, RIGHT_READ) {
            Ok(v) => v,
            Err(_) => return false,
        };
        {
            let mut g = TABLE.lock();
            let t = g.get();
            let first_slot = first_handle.slot() as usize;
            let entry = t.slots[first_slot];
            for (slot, e) in t.slots.iter_mut().enumerate() {
                if slot != first_slot {
                    *e = entry;
                }
            }
        }
        let full_ok = live() == MAX_HANDLES
            && matches!(grant_file(OWNER, 3, cur, RIGHT_READ), Err(HErr::Exhausted))
            && counters().exhausted == 1;
        let mut one = [0u8; 16];
        let existing_ok = read_with(first_handle, OWNER, &MemDisk { img: IMAGE }, &mut one).is_ok()
            && pattern(&one, 0);
        reset_for_test();

        // ⑥ 世代上界：预置到 GEN_MAX-1 ⇒ 下次 GEN_MAX，再一次回绕到 1（不是 0）。
        //    到界后"上一周期的 gen=1"会重新匹配——这是界的定义，必须打出来。
        preset_gen(0, GEN_MAX - 1);
        let g1 = match grant_file(OWNER, 3, cur, RIGHT_READ) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let gen1_ok = g1.gen() == GEN_MAX;
        close(g1, OWNER).ok();
        let g2 = match grant_file(OWNER, 3, cur, RIGHT_READ) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let wrap_ok = g2.gen() == 1 && g2.slot() == g1.slot();
        let stale_boundary = begin_read(g1, OWNER).is_err();
        // "上一周期"的句柄 = 同槽 gen=1；回绕后它与 g2 逐位相同 ⇒ 会被接受。
        let forge = Handle::pack(g2.slot(), 1);
        let restart_ok = begin_read(forge, OWNER).is_ok();
        close(g2, OWNER).ok();
        reset_for_test();

        // ⑦ 非法形状：0 / slot 越界 / gen 0 ⇒ Invalid（对用户是 -1，不是 -5）
        let slot_shape_ok = if MAX_HANDLES <= u16::MAX as usize {
            matches!(begin_read(Handle::pack(MAX_HANDLES as u16, 1), OWNER), Err(HErr::Invalid))
        } else {
            Handle::pack(u16::MAX, 1).unpack() == Some((u16::MAX, 1))
        };
        let shape_ok = matches!(begin_read(Handle(0), OWNER), Err(HErr::Invalid))
            && slot_shape_ok
            && matches!(begin_read(Handle::pack(5, 0), OWNER), Err(HErr::Invalid));

        // ⑧ EOF：2000 字节读完再读回 0；长度大于文件时返回剩余
        let h = match grant_file(OWNER, 3, cur, RIGHT_READ) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let mut buf = [0u8; 4096];
        let first = read_with(h, OWNER, &MemDisk { img: IMAGE }, &mut buf);
        let first_ok = matches!(first, Ok(2000)) && pattern(&buf[..2000], 0);
        let eof_ok = read_with(h, OWNER, &MemDisk { img: IMAGE }, &mut buf) == Ok(0)
            && counters().reads >= 2
            && counters().bytes >= 2000;
        close(h, OWNER).ok();

        // ⑨ 退出撤销：owner 的表项全部清掉
        let h1 = grant_file(OWNER, 3, cur, RIGHT_READ).ok();
        let h2 = grant_file(OWNER, 3, cur, RIGHT_READ).ok();
        let revoked = revoke_task(OWNER.0, OWNER.1);
        // **比基线，不比 0**（§463）：⑨ 段只该清掉 OWNER 名下那两格。少清或多清都会
        // 让 `live()` 偏离基线 ⇒ 判据仍然咬得到（不是放宽）。
        let revoke_ok = h1.is_some() && h2.is_some() && revoked == 2
            && live() == h0
            && h1.is_some_and(|v| matches!(begin_read(v, OWNER), Err(HErr::NoSuch)));
        // ⑩ 双 close：第二次是 NoSuch（表项已空），不是 Stale
        let h = match grant_file(OWNER, 3, cur, RIGHT_READ) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let twice_ok = close(h, OWNER).is_ok() && close(h, OWNER) == Err(HErr::NoSuch);
        // 先取账再清表：清表会把这一轮的计数器一起抹掉，日志就变成一排 0（量具在骗人）。
        let c = counters();
        reset_for_test();

        let checks = [pack_ok, close_ok, stale_ok, owner_ok, denied_ok, nocap_ok,
            full_ok, existing_ok, gen1_ok, wrap_ok, stale_boundary, restart_ok,
            shape_ok, first_ok, eof_ok, revoke_ok, twice_ok];
        crate::log_info!(
            "handle: checks={:?} grants={} closes={} reads={} bytes={} stale={} not_owner={} \
             denied={} exhausted={} invalid={} no_such={} revoked={} live_peak={}",
            checks, c.grants, c.closes, c.reads, c.bytes, c.stale, c.not_owner,
            c.denied, c.exhausted, c.invalid, c.no_such, c.revoked, c.live_peak
        );
        checks.iter().all(|v| *v)
    }

    crate::ktest!(KT_HANDLE_TABLE, t_handle_table);

    #[cfg(feature = "fat32-exec")]
    pub fn t_handle_syscalls() -> bool {
        use crate::arch::x86_64::trap::TrapFrame;
        use crate::filesystem::fat32::Volume;
        use crate::user::{SYS_FILE_READ, SYS_HANDLE_CLOSE, SYS_HANDLE_DUP};

        if crate::ahci::init().is_err() {
            return false;
        }
        // 用例必须自足：`.ktests` 的顺序由链接器决定（加一个特性就会变）。启动任务不初始化
        // 时 `current_identity()` 是 None——正常顺序里前面的用例替我们做了，那是运气不是设计。
        crate::sched::init_boot_task();
        let port = crate::FAT_PORT_A;
        let disk = AhciDisk { port };
        let vol = match Volume::mount(&disk) {
            Ok(v) => v,
            Err(e) => {
                crate::log_fatal!("handle-sys: 挂载失败 {:?}", e);
                return false;
            }
        };
        let cur = match vol.open_cursor("HELLO.ELF") {
            Ok(c) => c,
            Err(e) => {
                crate::log_fatal!("handle-sys: 打开失败 {:?}", e);
                return false;
            }
        };
        let size = cur.stat().size as usize;
        let Some(ident) = crate::sched::current_identity() else {
            crate::log_fatal!("handle-sys: 拿不到当前任务身份");
            return false;
        };
        reset_for_test();
        reset_counters_for_test();
        let h = match grant_file(ident, port, cur, RIGHT_READ | RIGHT_DUP) {
            Ok(v) => v,
            Err(e) => {
                crate::log_fatal!("handle-sys: 授予失败 {}", e.tag());
                return false;
            }
        };

        // 用户页：真实映射（user+writable），file_read 的写方向必须过页面校验
        let Some(va) = crate::mm::alloc_user_va_range(1) else { return false };
        let frames = match crate::mm::phys_alloc(0, crate::mm::MOD_TEST) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let flags = match crate::mm::PageFlags::new(true, false, true) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let map = match crate::mm::map(va, frames, flags) {
            Ok(m) => m,
            Err(e) => {
                crate::log_fatal!("handle-sys: 用户页映射失败 {:?}", e);
                return false;
            }
        };
        let mut frame = TrapFrame {
            cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
            rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
            error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
        };

        // ① 头 8 字节：返回值 == 8，且用户页里真的是 ELF 魔数
        frame.rax = SYS_FILE_READ;
        frame.rdi = h.0;
        frame.rsi = va.0;
        frame.rdx = 8;
        crate::user::syscall_dispatch(&mut frame);
        let mut got = [0u8; 8];
        let back = crate::user::copy_from_user(va.0, &mut got) == Ok(8);
        let head_ok = frame.rax == 8 && back && &got[..4] == b"\x7fELF";

        // ② 一直读到 EOF：4 KiB 一块，累计字节 == 目录项说的大小
        let mut total = 8usize;
        let mut calls = 0usize;
        let mut eof = false;
        loop {
            frame.rax = SYS_FILE_READ;
            frame.rdi = h.0;
            frame.rsi = va.0;
            frame.rdx = 4096;
            crate::user::syscall_dispatch(&mut frame);
            let n = frame.rax as i64;
            if n == 0 {
                eof = true;
                break;
            }
            if n < 0 {
                crate::log_fatal!("handle-sys: 流式读失败 rc={}", n);
                break;
            }
            total += n as usize;
            calls += 1;
            if calls > 64 {
                break;
            }
        }
        let stream_ok = eof && total == size;

        // ③ 长度形状：0 ⇒ -1；COPY_MAX+1 ⇒ -3（都不碰盘）
        frame.rax = SYS_FILE_READ;
        frame.rdi = h.0;
        frame.rsi = va.0;
        frame.rdx = 0;
        crate::user::syscall_dispatch(&mut frame);
        let len0_ok = frame.rax == crate::user::E_INVALID;
        frame.rax = SYS_FILE_READ;
        frame.rdx = (crate::user::COPY_MAX + 1) as u64;
        crate::user::syscall_dispatch(&mut frame);
        let lenbig_ok = frame.rax == crate::user::E_TOO_LONG;

        // ④ 坏指针 ⇒ -2，且**游标未提交**：紧接着用合法指针重读，必须还是文件开头
        let cur2 = match vol.open_cursor("HELLO.ELF") {
            Ok(c) => c,
            Err(_) => return false,
        };
        let h2 = match grant_file(ident, port, cur2, RIGHT_READ | RIGHT_DUP) {
            Ok(v) => v,
            Err(_) => return false,
        };
        frame.rax = SYS_FILE_READ;
        frame.rdi = h2.0;
        frame.rsi = 0; // 坏指针
        frame.rdx = 8;
        crate::user::syscall_dispatch(&mut frame);
        let badptr_ok = frame.rax == crate::user::E_FAULT;
        frame.rax = SYS_FILE_READ;
        frame.rsi = va.0;
        frame.rdx = 8;
        crate::user::syscall_dispatch(&mut frame);
        let mut again = [0u8; 8];
        let rollback_ok = frame.rax == 8
            && crate::user::copy_from_user(va.0, &mut again) == Ok(8)
            && again == got;

        // ⑤ 越权：dup 到 0 权之后读 ⇒ -4
        let h3 = match dup(h2, ident, 0) {
            Ok(v) => v,
            Err(_) => return false,
        };
        frame.rax = SYS_FILE_READ;
        frame.rdi = h3.0;
        frame.rsi = va.0;
        frame.rdx = 8;
        crate::user::syscall_dispatch(&mut frame);
        let denied_ok = frame.rax == crate::user::E_DENIED;

        // ⑥ dup 走系统调用：新句柄同对象、不同槽；close 之后再读旧句柄 ⇒ -5
        frame.rax = SYS_HANDLE_DUP;
        frame.rdi = h2.0;
        frame.rsi = RIGHT_READ as u64;
        crate::user::syscall_dispatch(&mut frame);
        let dup_h = Handle(frame.rax);
        let dup_ok = dup_h != h2 && dup_h.unpack().is_some();
        frame.rax = SYS_HANDLE_CLOSE;
        frame.rdi = h2.0;
        crate::user::syscall_dispatch(&mut frame);
        let close_ok = frame.rax == 0;
        frame.rax = SYS_FILE_READ;
        frame.rdi = h2.0;
        frame.rsi = va.0;
        frame.rdx = 8;
        crate::user::syscall_dispatch(&mut frame);
        let stale_ok = frame.rax == crate::user::E_BAD_HANDLE;

        // ⑦ ABI 位读回真实状态
        let abi_ok = crate::user::abi_word() & crate::user::F_HANDLES != 0;

        let c = counters();
        reset_for_test();
        drop(map);
        let checks = [head_ok, stream_ok, len0_ok, lenbig_ok, badptr_ok, rollback_ok,
            denied_ok, dup_ok, close_ok, stale_ok, abi_ok];
        crate::log_info!(
            "handle-sys: checks={:?} size={} bytes={} calls={} grants={} denied={} stale={} \
             no_such={} invalid={} reads={} 日志字节账={}",
            checks, size, total, calls, c.grants, c.denied, c.stale, c.no_such, c.invalid, c.reads, c.bytes
        );
        checks.iter().all(|v| *v)
    }

    #[cfg(feature = "fat32-exec")]
    crate::ktest!(KT_HANDLE_SYSCALLS, t_handle_syscalls);
    /// 设计 §8 第 5 条：任务退出 → reap 的**端到端**撤销。
    /// 前面 `t_handle_table` 只直调了 `revoke_task`；这一格证明 `sched::reap` 真的会走到它，
    /// 且只清死者（启动任务手里的句柄必须活着）。
    #[cfg(feature = "fat32-exec")]
    pub fn t_handle_reap() -> bool {
        let Some(s) = crate::acpi::summary() else { return false };
        let Some(m) = s.madt else { return false };
        if crate::apic::get_or_init(&m).is_err() {
            return false;
        }
        crate::sched::init_boot_task();
        crate::sched::start_workers();
        reset_for_test();
        reset_counters_for_test();
        let Some(keep_owner) = crate::sched::current_identity() else {
            crate::log_fatal!("handle-reap: 拿不到启动任务身份");
            return false;
        };
        let Some(cur) = fixture() else { return false };
        // 启动任务自己的句柄：reap 只清"死者"的表项，这一格必须活着
        let keep = match grant_file(keep_owner, 3, cur, RIGHT_READ) {
            Ok(h) => h,
            Err(_) => return false,
        };
        // 带 `SYS_EXIT` 的容器（与 `t_task_exit` 第二轮同形状）
        let l = match crate::user::load(crate::HELLO_ELF) {
            Ok(l) => l,
            Err(e) => {
                crate::log_fatal!("handle-reap: 装载失败 —— {}", crate::user::describe_load(e));
                return false;
            }
        };
        crate::user::write_at(l.data_va + crate::user::ABI_SLOT_FLAG, crate::user::FLAG_EXIT);
        let t = match crate::sched::spawn_user(l.entry, l.stack_top, 0, l.owned) {
            Ok(t) => t,
            Err(_) => return false,
        };
        let Some(dead_owner) = crate::sched::identity_of(t) else {
            return false;
        };
        let (h1, h2) = (
            grant_file(dead_owner, 3, cur, RIGHT_READ),
            grant_file(dead_owner, 3, cur, RIGHT_READ),
        );
        let (Ok(h1), Ok(h2)) = (h1, h2) else {
            return false;
        };
        // 开时钟让它自己退出；`drain_reap` 要靠 tick 把 reap 叫起来，所以时钟到 drain 之后再停。
        // 用例自足（T0.1 顺序暴露）：释放可能在本窗口之前就已完成，窗口里自然看不到增量。
        let released0 = crate::sched::reap_released();
        // §198：收尾必须**按原样放回**。旧写法无条件 start→stop，于是本用例把表停给了后面所有用例
        // （实测：96 个用例边界只有 2 次翻转，open→masked 恰好发生在本用例，之后一路 masked 到
        // t_sleep_until；而 t_sleep_until 靠探测自愈，偶尔失效就是第二终端的前置条件）。
        // 本用例**需要**表走（drain_reap 靠 tick），所以照样开；只是收尾时还原来时的样子。
        let tick_in = crate::apic::ticks();
        let probe = crate::apic::wait_ticks(tick_in, 2, crate::clock::window_cycles(2));
        let timer_was_running = probe.ticks >= 2;
        crate::apic::timer_start().ok();
        crate::apic::with_interrupts(|| {
            let t0 = crate::tsc::now();
            while crate::user::served() < crate::P7_CALLS
                && crate::tsc::now().wrapping_sub(t0) < 200_000_000
            {
                crate::tsc::spin(20_000);
            }
            if !crate::sched::wait_for_boot_task(300_000_000) {
                crate::log_fatal!("handle-reap: 窗口收不了场");
            }
        });
        let drained = crate::drain_reap() || crate::sched::reap_released() > released0;
        if !timer_was_running {
            crate::apic::timer_stop().ok();
        }
        let state = crate::sched::state_of(t);
        let c = counters();
        let live_after = live();
        let dead_gone = begin_read(h1, dead_owner).is_err() && begin_read(h2, dead_owner).is_err();
        let keep_ok = begin_read(keep, keep_owner).is_ok();
        let mut buf = [0u8; 4];
        let keep_read = read_with(keep, keep_owner, &MemDisk { img: IMAGE }, &mut buf) == Ok(4)
            && pattern(&buf, 0);
        let ok = drained
            && state == crate::sched::TaskState::Free
            && c.revoked >= 2
            && live_after == 1
            && dead_gone
            && keep_ok
            && keep_read;
        crate::log_info!(
            "handle-reap: drained={} state={:?} live={} revoked={} 死者句柄都没了={} 启动任务句柄还在={} keep读={} ⇒ {}",
            drained,
            state,
            live_after,
            c.revoked,
            dead_gone,
            keep_ok,
            keep_read,
            ok
        );
        close(keep, keep_owner).ok();
        reset_for_test();
        ok
    }

    #[cfg(feature = "fat32-exec")]
    /// dup 共享读取位置（ADR-108 补记二）：一条游标两个名字。
    #[cfg(feature = "fat32-exec")]
    pub fn t_handle_dup_shared() -> bool {
        use crate::filesystem::fat32::Volume;
        if crate::ahci::init().is_err() {
            return false;
        }
        crate::sched::init_boot_task();
        let port = crate::FAT_PORT_A;
        let disk = AhciDisk { port };
        let vol = match Volume::mount(&disk) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let cur = match vol.open_cursor("HELLO.ELF") {
            Ok(c) => c,
            Err(_) => return false,
        };
        let Some(ident) = crate::sched::current_identity() else {
            return false;
        };
        reset_for_test();
        let h1 = match grant_file(ident, port, cur, RIGHT_READ | RIGHT_DUP) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let img = crate::ktests::common::HELLO_ELF;
        let mut a = [0u8; 16];
        let first = read(h1, ident, &mut a) == Ok(16) && a == img[..16];
        let h2 = match dup(h1, ident, RIGHT_READ) {
            Ok(v) => v,
            Err(_) => return false,
        };
        // 关键顺序：dup 之后**先让原名字推进**，再读第二个名字。
        // 窗口 16 字节且落在 ELF 的非零区：复制语义下第二个名字从 dup 那一刻读（16..32），
        // 共享语义读到 32..48（e_phoff 一带）——两者字节不同，这一格才不是空转。
        let mut b = [0u8; 16];
        let advanced = read(h1, ident, &mut b) == Ok(16) && b == img[16..32];
        let mut c = [0u8; 16];
        let shared = read(h2, ident, &mut c) == Ok(16) && c == img[32..48];
        let closed1 = close(h1, ident).is_ok();
        let mut d = [0u8; 16];
        let survive = read(h2, ident, &mut d) == Ok(16) && d == img[48..64];
        let stale = matches!(close(h1, ident), Err(HErr::NoSuch));
        let closed2 = close(h2, ident).is_ok();
        crate::log_info!(
            "handle-dup: 首读={} 原名字推进={} 第二名字共享={} 关一条仍续读={} 旧名坏={} 端点={}",
            first, advanced, shared, survive, stale, closed1 && closed2
        );
        first && advanced && shared && survive && stale && closed1 && closed2
    }
    #[cfg(feature = "fat32-exec")]
    crate::ktest!(KT_HANDLE_DUP_SHARED, t_handle_dup_shared);
    #[cfg(feature = "fat32-exec")]
    crate::ktest!(KT_HANDLE_REAP, t_handle_reap);

}
