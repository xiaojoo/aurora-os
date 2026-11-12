//! Limine 启动协议的请求/响应结构。
//!
//! 逐字依据本地副本 `.tools/limine-protocol/include/limine.h` 与 `PROTOCOL.md` 手写，
//! **不引入 `limine` crate**：启动信息解析这条路径上因此没有第三方依赖。
//!
//! 本模块含少量 unsafe（响应指针转引用），已在 `docs/security/unsafe-whitelist.toml`
//! 登记；workspace 按 §2.5 拆分后，这部分落到 `aurora-arch`，本文件其余部分可无 unsafe。

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

const MAGIC: [u64; 2] = [0xc7b1dd30df4c8b88, 0x0a82e883a194f07b];

/// 向内核对 bootloader 声明的最高 base revision。
/// 协议：支持则把 tag 第 3 分量**清零**；未清零即视为不支持，尽早失败而不是带着错布局继续。
const REQUESTED_REVISION: u64 = 5;

/// `LIMINE_BASE_REVISION(N) = {0xf9562b2d5c95a6c8, 0x6a7b384944536bdc, N}`
/// rev>=3 时 bootloader 必须把第 2 分量改写为**实际使用**的 revision。
#[repr(C)]
pub struct BaseRevision([AtomicU64; 3]);

impl BaseRevision {
    const fn new(n: u64) -> Self {
        Self([
            AtomicU64::new(0xf9562b2d5c95a6c8),
            AtomicU64::new(0x6a7b384944536bdc),
            AtomicU64::new(n),
        ])
    }
    /// 协议宏 `LIMINE_BASE_REVISION_SUPPORTED`：第 3 分量为 0 才算支持。
    pub fn is_supported(&self) -> bool {
        self.0[2].load(Ordering::Relaxed) == 0
    }
    /// 协议宏 `LIMINE_LOADED_BASE_REVISION`：第 2 分量被改写即为实际 revision。
    /// 返回 `None` 表示 bootloader 没改写（不支持 rev>=3，或行为不合规）。
    pub fn negotiated(&self) -> Option<u64> {
        let v = self.0[1].load(Ordering::Relaxed);
        if v != 0x6a7b384944536bdc { Some(v) } else { None }
    }
}

#[repr(C)]
pub struct HhdmResponse {
    pub revision: u64,
    /// 物理地址 -> 高位直接映射虚地址的偏移。**协议明令不得硬编码。**
    pub offset: u64,
}

#[repr(C)]
pub struct MemmapEntry {
    pub base: u64,
    pub length: u64,
    pub kind: u64,
}

#[repr(C)]
pub struct MemmapResponse {
    pub revision: u64,
    pub entry_count: u64,
    pub entries: AtomicPtr<*const MemmapEntry>,
}

#[repr(C)]
pub struct RsdpResponse {
    pub revision: u64,
    pub address: AtomicPtr<u8>,
}

#[repr(C)]
pub struct BootloaderInfoResponse {
    pub revision: u64,
    pub name: AtomicPtr<u8>,
    pub version: AtomicPtr<u8>,
}

// ------------------------------------------------------------------ S6a：framebuffer
//
// 逐字取自本仓库固定的 `.tools/limine-protocol/include/limine.h`：
//   LIMINE_FRAMEBUFFER_REQUEST_ID = { COMMON_MAGIC, 0x9d5827dcd881dd75, 0xa3148604f6fab11b }
//   struct limine_framebuffer { address(void*), width, height, pitch, bpp, memory_model,
//                               红绿蓝各 (size, shift), unused[7], edid_size, edid,
//                               mode_count, modes }          // 末两个是 rev1 的尾字段
//   struct limine_framebuffer_response { revision, framebuffer_count, framebuffers }
// `framebuffers` 是 `struct limine_framebuffer **`，与 MemmapResponse.entries 同形，
// 所以照那张表已经验证过的写法切片。
#[cfg(feature = "framebuffer")]
#[repr(C)]
pub struct Framebuffer {
    /// bootloader 在它自己页表里建的映射地址。**不当可用指针用**，理由见 framebuffer()。
    pub address: AtomicPtr<u8>,
    pub width: u64,
    pub height: u64,
    /// 一行占多少**字节**（不是像素）。pitch 与 width*bpp/8 不等时必须按 pitch 走。
    pub pitch: u64,
    pub bpp: u16,
    /// 1 = RGB（`LIMINE_FRAMEBUFFER_RGB`）；其它值本片不支持
    pub memory_model: u8,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
    pub unused: [u8; 7],
    pub edid_size: u64,
    pub edid: AtomicPtr<u8>,
    pub mode_count: u64,
    pub modes: AtomicPtr<*const u8>,
}

#[cfg(feature = "framebuffer")]
#[repr(C)]
pub struct FramebufferResponse {
    pub revision: u64,
    pub framebuffer_count: u64,
    pub framebuffers: AtomicPtr<*const Framebuffer>,
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemmapType {
    Usable,
    Reserved,
    AcpiReclaimable,
    AcpiNvs,
    BadMemory,
    BootloaderReclaimable,
    ExecutableAndModules,
    Framebuffer,
    /// rev>=4 才有；rev<4 的 bootloader 不会产出该值
    ReservedMapped,
    Unknown,
}

impl MemmapType {
    pub fn from_raw(v: u64) -> Self {
        match v {
            0 => Self::Usable,
            1 => Self::Reserved,
            2 => Self::AcpiReclaimable,
            3 => Self::AcpiNvs,
            4 => Self::BadMemory,
            5 => Self::BootloaderReclaimable,
            6 => Self::ExecutableAndModules,
            7 => Self::Framebuffer,
            8 => Self::ReservedMapped,
            _ => Self::Unknown,
        }
    }
}

/// 把 bootloader 回写的响应指针转成引用。
///
/// SAFETY: 指针由 bootloader 在移交控制权之前写入，指向内核镜像所在 higher-half 内的
/// `#[repr(C)]` 结构；本函数**只**在该结构已由对应请求项声明后才被调用，
/// 且响应一旦提供即在内核生命周期内稳定（协议未规定失效条件）。
/// 空指针返回 `None`，不做任何解引用。
#[inline]
unsafe fn response<T>(p: &AtomicPtr<T>) -> Option<&T> {
    // SAFETY: 由本函数的调用约定保证（见函数文档）
    unsafe { p.load(Ordering::Relaxed).cast_const().as_ref() }
}

macro_rules! declare_request {
    ($name:ident, $ty:ty, $id0:expr, $id1:expr) => {
        #[repr(C)]
        struct $name {
            id: [u64; 4],
            revision: u64,
            response: AtomicPtr<$ty>,
        }
        impl $name {
            const fn new() -> Self {
                Self {
                    id: [MAGIC[0], MAGIC[1], $id0, $id1],
                    revision: 0,
                    response: AtomicPtr::new(core::ptr::null_mut()),
                }
            }
            fn get(&self) -> Option<&$ty> {
                // SAFETY: 见 response() —— 仅在本请求已被 bootloader 填充时才有非空指针
                unsafe { response(&self.response) }
            }
        }
    };
}

#[used]
#[link_section = ".requests_start_marker"]
static START_MARKER: [u64; 4] =
    [0xf6b8f4b39de7d1ae, 0xfab91a6940fcb9cf, 0x785c6ed015d3e316, 0x181e920a7852b9d9];

#[used]
#[link_section = ".requests"]
pub static BASE_REVISION: BaseRevision = BaseRevision::new(REQUESTED_REVISION);

// 以下 4 个 ID 逐条取自 include/limine.h
declare_request!(BootloaderInfoRequest, BootloaderInfoResponse, 0xf55038d8e2a1202f, 0x279426fcf5f59740);
declare_request!(HhdmRequest, HhdmResponse, 0x48dcf1cb8ad2b852, 0x63984e959a98244b);
declare_request!(MemmapRequest, MemmapResponse, 0x67cf3d9d378a806f, 0xe304acdfc50c3c62);
declare_request!(RsdpRequest, RsdpResponse, 0xc5e77b6b397e7b43, 0x27637845accdcf3c);

#[used]
#[link_section = ".requests"]
static BOOTLOADER_INFO: BootloaderInfoRequest = BootloaderInfoRequest::new();
#[used]
#[link_section = ".requests"]
static HHDM: HhdmRequest = HhdmRequest::new();
#[used]
#[link_section = ".requests"]
static MEMMAP: MemmapRequest = MemmapRequest::new();
#[used]
#[link_section = ".requests"]
static RSDP: RsdpRequest = RsdpRequest::new();
// S6a：在此之前只登记了 4+1 个请求，`LIMINE_FRAMEBUFFER_REQUEST_ID` **从来没被声明过**
// ——BACKLOG §229 二里那句"Limine 已给 framebuffer"是未兑现的预期，到本片才成为代码。
#[cfg(feature = "framebuffer")]
declare_request!(FramebufferRequest, FramebufferResponse, 0x9d5827dcd881dd75, 0xa3148604f6fab11b);

#[cfg(feature = "framebuffer")]
#[used]
#[link_section = ".requests"]
static FRAMEBUFFER: FramebufferRequest = FramebufferRequest::new();


// ------------------------------------------------------------------ MP 特性
//
// 逐字取自本仓库固定的 `.tools/limine-protocol/include/limine.h`（v11.4.1）：
//   ID      = { COMMON_MAGIC, 0x95a67b819a1b857e, 0xa0b61b723b6a73e0 }
//   request = { id[4], revision, response, flags }      // flags bit0 = 启用 x2APIC
//   respon  = { revision, flags(u32), bsp_lapic_id(u32), cpu_count(u64), cpus }
//   info    = { processor_id(u32), lapic_id(u32), reserved(u64), goto_address, extra_argument }
// 与 `declare_request!` 不同形（多一个 flags 字段），所以单独写。
//
// 协议原文里三条对本项目有直接影响，都记在这儿以免将来又变成口头结论：
// 1. 「请求存在 ⇒ bootloader 会 bootstrap 二级处理器」，请求不存在就不做 —— 所以
//    ADR-014 的"16 位 trampoline 归属"这条**只能靠加了这个请求来验**：我们没自备
//    任何 16 位代码，AP 能被停住就说明 trampoline 是 bootloader 内部提供的。
// 2. 「goto_address 在首次把控制权交给 BSP 时保证为 NULL」—— 这是"释放 AP"能做成
//    一次原子发布的前提，必须实测，不能当成公理。
// 3. 「若固件已启用 x2APIC 而 bit0 为 0，bootloader 会尝试关掉；关不掉就**拒绝启动**」
//    —— 所以 flags 不能随便填，本切片填 0 并把响应里的实际模式打出来。

/// 一个 CPU 条目的协议布局。`goto_address` 用 AtomicU64 存放函数指针：
/// 释放 AP 的定义就是一次 release 语义的原子写，非原子的写在这里是**协议违规**。
#[repr(C)]
pub struct MpInfo {
    pub processor_id: u32,
    pub lapic_id: u32,
    pub reserved: u64,
    pub goto_address: core::sync::atomic::AtomicU64,
    pub extra_argument: u64,
}

#[repr(C)]
pub struct MpResponse {
    pub revision: u64,
    pub flags: u32,
    pub bsp_lapic_id: u32,
    pub cpu_count: u64,
    pub cpus: *mut *mut MpInfo,
}

#[repr(C)]
struct MpRequest {
    id: [u64; 4],
    revision: u64,
    response: AtomicPtr<MpResponse>,
    flags: u64,
}

impl MpRequest {
    const fn new() -> Self {
        Self {
            id: [MAGIC[0], MAGIC[1], 0x95a67b819a1b857e, 0xa0b61b723b6a73e0],
            revision: 0,
            response: AtomicPtr::new(core::ptr::null_mut()),
            flags: 0,
        }
    }
    fn get(&self) -> Option<&MpResponse> {
        // SAFETY: 见 response() —— 仅在本请求已被 bootloader 填充时才有非空指针
        unsafe { response(&self.response) }
    }
}

#[used]
#[link_section = ".requests"]
static MP: MpRequest = MpRequest::new();

/// 本内核一次能登记多少个 CPU（多于这个数会计成 overflow，让用例失败而不是静默截断）
pub const MAX_CPUS_SEEN: usize = 16;

/// 拷贝出来的 CPU 清单。必须在**换页表之前**拷：响应结构住在 bootloader 可回收内存里，
/// 切换后那些帧可能被我们分配走（memmap 是同一道理，见 mm.rs 顶部）。
#[derive(Clone, Copy)]
pub struct Mp {
    pub cpu_count: usize,
    pub bsp_lapic_id: u32,
    /// 响应 flags bit0：bootloader 是否已把 APIC 切到 x2APIC
    pub x2apic_enabled: bool,
    /// 协议保证"首次交给 BSP 时全部为 NULL"；这里记下实测结果
    pub all_goto_null: bool,
    pub lapic_ids: [u32; MAX_CPUS_SEEN],
    pub processor_ids: [u32; MAX_CPUS_SEEN],
    /// 每个 CPU 的 `limine_mp_info` **地址**（HHDM 下的虚地址，协议给的是指针数组）。
    ///
    /// 为什么不存 `*mut MpInfo` 而存整数：这份快照要放进 static，而释放 AP 要**写**它的
    /// `goto_address`——那一页属于 bootloader 可回收内存，主人是谁、还能不能用，
    /// 由 ADR-019 那条"不回收"决定，不是由 Rust 的类型系统决定。存成整数就没有
    /// "看起来像个合法引用"的错觉，用到时才由 `release_mp_cpu` 的 SAFETY 注释交代依据。
    pub cpu_ptrs: [u64; MAX_CPUS_SEEN],
    pub ptr_count: usize,
    pub n: usize,
    pub overflow: usize,
}

/// 释放一个 AP：按协议原文的顺序，先写好它要观察的数据（含 `extra_argument`），
/// 再用**release 语义的原子写**发布入口地址。
///
/// # Safety
/// `p` 必须来自 MP 响应的 `cpus` 数组（`Mp::cpu_ptrs`），并且：
/// * 该内存仍未被回收（ADR-019：bootloader-reclaimable 默认不回收）；
/// * 调用之后**不能**再改 `extra_argument`—— parked CPU 观察到入口之后就没人再同步了。
///
/// 非原子的发布写在协议上是违规的（原文："an atomic write to this field causes the
/// parked CPU to jump … using release semantics or stronger"），所以这里没有
/// `write_volatile` 那条看起来更短的路。
pub unsafe fn release_mp_cpu(p: *mut MpInfo, extra_argument: u64, entry: u64) {
    // SAFETY: 见函数文档。extra_argument 是普通 u64 字段，用 volatile 写保证它
    // 一定落在发布之前（编译器不能把它和下面的原子写对调）。
    unsafe { core::ptr::write_volatile(&raw mut (*p).extra_argument, extra_argument) };
    // goto_address 是 AtomicU64：借一个 & 出来做 store，语义就是协议要的那次发布
    // SAFETY: 见函数文档
    unsafe { &*(&raw const (*p).goto_address as *const core::sync::atomic::AtomicU64) }
        .store(entry, Ordering::Release);
}

fn read_mp(resp: &MpResponse) -> Option<Mp> {
    let count = resp.cpu_count as usize;
    if count == 0 || resp.cpus.is_null() {
        return None;
    }
    let mut m = Mp {
        cpu_count: count,
        bsp_lapic_id: resp.bsp_lapic_id,
        x2apic_enabled: resp.flags & 0x1 != 0,
        all_goto_null: true,
        lapic_ids: [0; MAX_CPUS_SEEN],
        processor_ids: [0; MAX_CPUS_SEEN],
        cpu_ptrs: [0; MAX_CPUS_SEEN],
        ptr_count: 0,
        n: 0,
        overflow: 0,
    };
    for i in 0..count {
        // SAFETY: cpus 是协议给的数组，长度由 cpu_count 给出；每个指针由 bootloader 填充
        let info = unsafe { resp.cpus.add(i).read() };
        if info.is_null() {
            m.all_goto_null = false;
            continue;
        }
        // SAFETY: 上一步已排除空指针，指向的结构由 bootloader 拥有且此刻仍在它的映射里
        let info = unsafe { &*info };
        if info.goto_address.load(Ordering::Acquire) != 0 {
            m.all_goto_null = false;
        }
        if m.n < MAX_CPUS_SEEN {
            m.lapic_ids[m.n] = info.lapic_id;
            m.processor_ids[m.n] = info.processor_id;
            // 地址一起拷出来：释放 AP 要写的就是这一块。它住在可回收内存，
            // 所以 ADR-019 的"不回收"是这条数组能用下去的前提，不是可选优化。
            m.cpu_ptrs[m.n] = info as *const MpInfo as u64;
            m.ptr_count += 1;
            m.n += 1;
        } else {
            m.overflow += 1;
        }
    }
    Some(m)
}

#[used]
#[link_section = ".requests_end_marker"]
static END_MARKER: [u64; 2] = [0xadc0e0531bb10d03, 0x9572709f31764c62];

/// 本次垂直切片需要的启动信息集合。缺必需项返回 `None`，由调用方尽早失败。
pub struct BootInfo<'a> {
    pub hhdm_offset: u64,
    pub mmap_entries: &'a [*const MemmapEntry],
    pub rsdp: Option<u64>,
    pub bootloader_name: Option<&'a str>,
    /// 多处理器响应。**可选**：bootloader 不支持这个请求时是 None，
    /// M3b 起 AP 必须先判它，不能假设一定有。
    pub mp: Option<Mp>,
}

/// 读取内存映射条目数组。
///
/// SAFETY: `entries` 与 `entry_count` 均来自 bootloader 的 memmap 响应，
/// 二者一致性由协议保证；本函数不额外推算长度。
unsafe fn memmap_slice(resp: &MemmapResponse) -> &[*const MemmapEntry] {
    let base = resp.entries.load(Ordering::Relaxed).cast_const();
    // SAFETY: 见函数文档
    unsafe { core::slice::from_raw_parts(base, resp.entry_count as usize) }
}

pub fn collect() -> Option<BootInfo<'static>> {
    let hhdm = HHDM.get()?;
    let memmap = MEMMAP.get()?;
    // 必需项判据：偏移为 0 或条目数为 0 都说明布局不被理解，不能继续
    if hhdm.offset == 0 || memmap.entry_count == 0 || memmap.entry_count > 4096 {
        return None;
    }
    let rsdp = RSDP.get().and_then(|r| {
        let a = r.address.load(Ordering::Relaxed).cast_const();
        (!a.is_null()).then_some(a as u64)
    });
    let mp = MP.get().and_then(read_mp);
    let bootloader_name = BOOTLOADER_INFO.get().and_then(|b| {
        let p = b.name.load(Ordering::Relaxed).cast_const();
        if p.is_null() {
            return None;
        }
        // bootloader 给的名称是不可信输入：限长 32 字节，且只接受 ASCII 可打印字符，
        // 避免畸形启动信息把任意字节直接打进串口日志。
        let mut n = 0usize;
        while n < 32 {
            // SAFETY: 上面已判非空；长度由协议保证为 NUL 结尾的 static 字符串
            let byte = unsafe { p.add(n).read_volatile() };
            if byte == 0 || !(0x20..0x7f).contains(&byte) {
                break;
            }
            n += 1;
        }
        // SAFETY: 循环内已逐字节确认为 ASCII 可打印，故 UTF-8 必然成立
        if n == 0 {
            None
        } else {
            core::str::from_utf8(unsafe { core::slice::from_raw_parts(p, n) }).ok()
        }
    });
    // SAFETY: 见 memmap_slice
    let mmap_entries = unsafe { memmap_slice(memmap) };
    Some(BootInfo { hhdm_offset: hhdm.offset, mmap_entries, rsdp, bootloader_name, mp })
}

/// 一份**只有数值**的 framebuffer 摘要（刻意不带指针）。
#[cfg(feature = "framebuffer")]
#[derive(Debug, Clone, Copy)]
pub struct FbInfo {
    pub count: u64,
    /// bootloader 给的原样地址：只用来与 memmap 的物理区间**对账**，不解引用。
    pub limine_address: u64,
    pub width: u64,
    pub height: u64,
    pub pitch: u64,
    pub bpp: u16,
    pub memory_model: u8,
    /// 红、绿、蓝各自的 (size, shift)
    pub masks: [(u8, u8); 3],
}

/// 读第 0 个 framebuffer 的几何；一个都没有（或指针为空）返回 None。
///
/// **为什么不把 `address` 交出去当指针**：那是 bootloader 在它自己页表里的映射，
/// 而本内核在 `mm::take_over` 里换掉了 CR3 ⇒ 那个地址在我们的页表里不保证存在。
/// 可写窗口由 `frame` 模块拿 memmap 里 `MemmapType::Framebuffer` 那段**物理区间**
/// 经 `mm::map_mmio`（UC、不缓存）自己开；两个地址到底什么关系，由调用方**实测对账**，
/// 不当公理（这一片就是要把"Limine 给了就能直接用"这句话证真或证伪）。
#[cfg(feature = "framebuffer")]
pub fn framebuffer() -> Option<FbInfo> {
    let r = FRAMEBUFFER.get()?;
    // 上界 64：count 来自启动信息，是不可信输入；下面只取第 0 条，
    // 但先把荒谬值挡掉，免得将来有人改成遍历时无界。
    if r.framebuffer_count == 0 || r.framebuffer_count > 64 {
        return None;
    }
    let base = r.framebuffers.load(Ordering::Relaxed).cast_const();
    if base.is_null() {
        return None;
    }
    // SAFETY: 上面已判数组指针非空且条目数在界内；数组由 bootloader 在移交控制权前写好
    let fb: *const Framebuffer = unsafe { *base };
    if fb.is_null() {
        return None;
    }
    // SAFETY: 上一条已判非空；它指向协议规定的 repr(C) 结构，响应一经提供在内核生命周期内稳定
    let f = unsafe { &*fb };
    Some(FbInfo {
        count: r.framebuffer_count,
        limine_address: f.address.load(Ordering::Relaxed) as u64,
        width: f.width,
        height: f.height,
        pitch: f.pitch,
        bpp: f.bpp,
        memory_model: f.memory_model,
        masks: [
            (f.red_mask_size, f.red_mask_shift),
            (f.green_mask_size, f.green_mask_shift),
            (f.blue_mask_size, f.blue_mask_shift),
        ],
    })
}

#[cfg(feature = "framebuffer")]
/// HHDM 偏移；请求没被满足时返回 0（调用方据此判"对账不成立"而不是拿 0 去加）。
pub fn hhdm_offset() -> u64 {
    HHDM.get().map_or(0, |h| h.offset)
}

/// memmap 里 `Framebuffer` 类型的那段物理区间（取第一条）。
#[cfg(feature = "framebuffer")]
pub fn framebuffer_memmap() -> Option<(u64, u64)> {
    let m = MEMMAP.get()?;
    if m.entry_count == 0 || m.entry_count > 4096 {
        return None;
    }
    // SAFETY: 与 collect() 同一前置（条目数已判在界内），指向协议规定的条目指针数组
    let entries = unsafe { memmap_slice(m) };
    for e in entries {
        // SAFETY: 条目指针由 bootloader 提供；collect() 已经在按同样方式读这张表
        let Some(e) = (unsafe { e.as_ref() }) else { continue };
        if MemmapType::from_raw(e.kind) == MemmapType::Framebuffer {
            return Some((e.base, e.length));
        }
    }
    None
}
