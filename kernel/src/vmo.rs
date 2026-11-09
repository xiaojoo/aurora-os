//! W3 P4（ADR-074）：VMO —— 持帧的内存对象，用户可见内存对象的第一刀。
//!
//! 形状与 `mm::LazyRegion` 同律：表在 **VMM(20)** 内、载荷全是 **Copy 的帧号数值**，
//! 不存 `OwnedFrames`/`Mapping`（后者非 Copy 不能 const 初始化，而且它们的 `Drop` 会在
//! 已持 VMM 的编排里重入 VMM ⇒ 当场 L4）。归还走"锁内取走清单、锁外逐帧 `frame_put`"。
//!
//! 与句柄表的分工（ADR-074 决策 1，使用者裁决"释放移到锁外"）：
//! 句柄表里只存 `ObjRef::Vmo { slot }` 这个 Copy 引用，**对象本体在这里**；
//! `handle::close`/`revoke_task` 在锁内取走引用、**放掉 HANDLE(35) 之后**才调 `vmo_unref`。
//! 所以这条路径上不存在 35→20 的反向嵌套，也不在句柄锁内做可能阻塞的事。
//!
//! 引用计数：创建者那一份是 1，`vmo_ref` 加一（grant/dup 用），`vmo_unref` 减一，到 0 才还帧。
//! 映射（`mm::AspaceMapping`）另持 `frame_get` 参考，所以"VMO 的句柄全关了但映射还在"时帧不会消失。
//!
//! 今天**没有 syscall**（P4b 才接 12/13/14），调用者只有内核与 ktest。

use crate::mm::{self, AspaceHandle, AspaceMapping, MmError, ModuleId, PageFlags, PhysAddr, VirtAddr, PAGE};

/// VMO 的帧记在这个模块号下：台账要能分开回答"内存对象占了多少帧"。
pub const MOD_VMO: ModuleId = ModuleId(19);
/// 定长容量。与 `MAX_LAZY_REGIONS`/`MAX_ADDR_SPACES` 同一口径：接缝够用，欠 workload 依据
/// （ADR-074 未决 1：P5 真起进程之后按"一个进程几个 VMO、每个几页"重量）。
pub const MAX_VMOS: usize = 8;
pub const MAX_VMO_PAGES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmoError {
    TableFull,
    /// 长度为 0、越界、或 offset+len 溢出。
    BadLength,
    NoSuch,
    Mm(MmError),
}

/// 对象引用（Copy）。句柄表存的就是它的槽号；有效性在每次用的时候查表判。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmoId {
    slot: u8,
}

impl VmoId {
    pub fn slot(self) -> u8 {
        self.slot
    }
    /// 从句柄表里存的槽号还原。槽号越界也照造（它是用户可伪造的值），查表时会拒。
    pub fn from_slot(slot: u8) -> VmoId {
        VmoId { slot }
    }
}

#[derive(Clone, Copy)]
struct VmoEntry {
    used: bool,
    pages: u16,
    refs: u16,
    /// 帧号（物理基址 / PAGE）。0 = 空（帧 0 永不可分配）。
    frames: [u64; MAX_VMO_PAGES],
}

const VMO_EMPTY: VmoEntry = VmoEntry { used: false, pages: 0, refs: 0, frames: [0; MAX_VMO_PAGES] };

#[derive(Clone, Copy)]
struct VmoTable {
    items: [VmoEntry; MAX_VMOS],
    /// 三本计数与表同锁（VMM）：不用原子量，所以本模块不引 sync —— 环内边的棘轮只许减不许增。
    created: usize,
    released: usize,
    bytes_written: u64,
}

struct VmoCell(core::cell::UnsafeCell<VmoTable>);
// SAFETY: 表的读写全在 VMM(20) 内（create/ref/unref/write/read/frames/count），互斥由锁提供；
// 载荷全为 Copy 数值，没有别名逃逸出表。帧本身的访问经 HHDM，而那些帧在 refs>0 期间不会被归还
// （归还只在 unref 到 0 时发生，且先在锁内清表项 ⇒ 别的上下文此后查不到它）。
unsafe impl Sync for VmoCell {}

static T: VmoCell = VmoCell(core::cell::UnsafeCell::new(VmoTable {
    items: [VMO_EMPTY; MAX_VMOS],
    created: 0,
    released: 0,
    bytes_written: 0,
}));

/// 持 VMM 时的表引用。
fn tbl() -> &'static mut VmoTable {
    // SAFETY: 调用方持 VMM（本模块所有表操作都在 with_vmm_lock 闭包里）
    unsafe { &mut *T.0.get() }
}

/// 创建读数 / 归还读数 / 写入字节数（判据与台账对账用）。
pub fn counters() -> (usize, usize, u64) {
    mm::with_vmm_lock(|| {
        let t = tbl();
        (t.created, t.released, t.bytes_written)
    })
}

/// 在用对象数（收尾判据的证人）。
pub fn vmo_count() -> usize {
    mm::with_vmm_lock(|| tbl().items.iter().filter(|e| e.used).count())
}

/// 一个对象此刻的引用数（判据用；不存在返回 None）。
pub fn vmo_refs(id: VmoId) -> Option<u16> {
    mm::with_vmm_lock(|| {
        let e = tbl().items.get(usize::from(id.slot))?;
        if e.used { Some(e.refs) } else { None }
    })
}

/// 创建：当场分配并**清零** `pages` 页（即时帧后端，ADR-074 决策 2 的使用者裁决）。
/// 中途失败把已拿的帧还回去，不留半截对象。
pub fn vmo_create(pages: usize) -> Result<VmoId, VmoError> {
    if pages == 0 || pages > MAX_VMO_PAGES || !mm::is_ready() {
        return Err(VmoError::BadLength);
    }
    let mut frames = [0u64; MAX_VMO_PAGES];
    let mut got = 0usize;
    let hhdm = mm::hhdm();
    while got < pages {
        match mm::phys_alloc(0, MOD_VMO) {
            Ok(f) => {
                let pa = f.base().0;
                // 主人改记在表里（与 aspace_new 记 pt_frames 同一手法），归还走 unref
                core::mem::forget(f);
                // SAFETY: pa 刚由分配器独占交出，HHDM 覆盖全部物理内存（ADR-064），长度正好一页
                unsafe { core::ptr::write_bytes((pa + hhdm) as *mut u8, 0, PAGE) };
                frames[got] = pa / PAGE as u64;
                got += 1;
            }
            Err(_) => {
                for f in frames.iter().take(got) {
                    put_or_die(*f);
                }
                return Err(VmoError::Mm(MmError::OutOfMemory));
            }
        }
    }
    let id = mm::with_vmm_lock(|| {
        let t = tbl();
        let Some(slot) = t.items.iter().position(|e| !e.used) else {
            return Err(VmoError::TableFull);
        };
        t.items[slot] = VmoEntry { used: true, pages: pages as u16, refs: 1, frames };
        Ok(VmoId { slot: slot as u8 })
    });
    match id {
        Ok(_) => {
            mm::with_vmm_lock(|| tbl().created += 1);
            id
        }
        Err(e) => {
            for f in frames.iter().take(got) {
                put_or_die(*f);
            }
            Err(e)
        }
    }
}

/// 加一个引用（grant/dup 用）。对象不存在则失败，不静默。
pub fn vmo_ref(id: VmoId) -> Result<(), VmoError> {
    mm::with_vmm_lock(|| {
        let t = tbl();
        let e = t.items.get_mut(usize::from(id.slot)).ok_or(VmoError::NoSuch)?;
        if !e.used {
            return Err(VmoError::NoSuch);
        }
        e.refs = e.refs.checked_add(1).ok_or(VmoError::TableFull)?;
        Ok(())
    })
}

/// 减一个引用；到 0 才还帧。**调用方必须已经放掉 HANDLE 锁**（ADR-074 决策 1）。
/// 归还顺序与 `aspace_release` 同律：锁内取走清单并清表项，锁外逐帧 `frame_put`。
pub fn vmo_unref(id: VmoId) {
    let mut out = [0u64; MAX_VMO_PAGES];
    let n = mm::with_vmm_lock(|| {
        let t = tbl();
        let Some(e) = t.items.get_mut(usize::from(id.slot)) else { return 0 };
        if !e.used {
            return 0;
        }
        e.refs = e.refs.saturating_sub(1);
        if e.refs != 0 {
            return 0;
        }
        let n = usize::from(e.pages);
        out[..n].copy_from_slice(&e.frames[..n]);
        *e = VMO_EMPTY;
        n
    });
    for f in out.iter().take(n) {
        put_or_die(*f);
    }
    if n != 0 {
        mm::with_vmm_lock(|| tbl().released += 1);
    }
}

/// 归还失败 = 完整性违例（同一块页可能已经有两个主人），按 §9.2 升 L4，不吞错。
/// 走 mm 的同一个升级入口：本模块不自己引 diagnostics（环内边的棘轮只许减不许增）。
fn put_or_die(frame: u64) {
    if let Err(e) = mm::frame_put(frame) {
        mm::free_violation(e, PhysAddr(frame * PAGE as u64), MOD_VMO);
    }
}

/// 写：`offset + src.len()` 必须整段落在对象里，越界明确失败、不静默截断。
/// 整段在 VMM 内做（帧清单与帧内容要在同一个临界区里看，否则并发的 unref 能把帧还掉）。
pub fn vmo_write(id: VmoId, offset: usize, src: &[u8]) -> Result<usize, VmoError> {
    if src.is_empty() {
        return Err(VmoError::BadLength);
    }
    let n = mm::with_vmm_lock(|| {
        let t = tbl();
        let e = t.items.get(usize::from(id.slot)).ok_or(VmoError::NoSuch)?;
        if !e.used {
            return Err(VmoError::NoSuch);
        }
        let end = offset.checked_add(src.len()).ok_or(VmoError::BadLength)?;
        if end > usize::from(e.pages) * PAGE {
            return Err(VmoError::BadLength);
        }
        let hhdm = mm::hhdm();
        let mut done = 0usize;
        while done < src.len() {
            let pos = offset + done;
            let pi = pos / PAGE;
            let po = pos % PAGE;
            let k = (PAGE - po).min(src.len() - done);
            let pa = e.frames[pi] * PAGE as u64 + po as u64;
            // SAFETY: pa 属于本对象（refs>0 ⇒ 不会被归还），HHDM 覆盖全部物理内存，
            // k <= PAGE - po 所以不越出这一页；src[done..done+k] 在界内。
            // 用 copy 而不是 copy_nonoverlapping：调用方给的缓冲可能**就映射在这个对象里**
            // （aspace_map 之后用户态拿自己的 VA 当源），重叠时 memmove 语义才是有定义的。
            unsafe { core::ptr::copy(src.as_ptr().add(done), (pa + hhdm) as *mut u8, k) };
            done += k;
        }
        Ok(src.len())
    })?;
    mm::with_vmm_lock(|| tbl().bytes_written += n as u64);
    Ok(n)
}

/// 读回（判据与内核侧取证用；用户态读自己映射的 VA，不走这里）。越界规则与写相同。
pub fn vmo_read(id: VmoId, offset: usize, dst: &mut [u8]) -> Result<usize, VmoError> {
    if dst.is_empty() {
        return Err(VmoError::BadLength);
    }
    mm::with_vmm_lock(|| {
        let t = tbl();
        let e = t.items.get(usize::from(id.slot)).ok_or(VmoError::NoSuch)?;
        if !e.used {
            return Err(VmoError::NoSuch);
        }
        let end = offset.checked_add(dst.len()).ok_or(VmoError::BadLength)?;
        if end > usize::from(e.pages) * PAGE {
            return Err(VmoError::BadLength);
        }
        let hhdm = mm::hhdm();
        let mut done = 0usize;
        while done < dst.len() {
            let pos = offset + done;
            let pi = pos / PAGE;
            let po = pos % PAGE;
            let k = (PAGE - po).min(dst.len() - done);
            let pa = e.frames[pi] * PAGE as u64 + po as u64;
            // SAFETY: 同 vmo_write；dst[done..done+k] 在界内，重叠时 memmove 语义有定义
            unsafe { core::ptr::copy((pa + hhdm) as *const u8, dst.as_mut_ptr().add(done), k) };
            done += k;
        }
        Ok(dst.len())
    })
}

/// 把整个对象铺进一个 AS 的用户半区（`mm::aspace_map` 的薄壳：mm 不认识 VMO，帧号由这里给）。
/// 前置：调用方持着一个引用（句柄），所以清单拷出来之后帧不会被别人还掉。
pub fn vmo_map(
    id: VmoId,
    space: &AspaceHandle,
    va: VirtAddr,
    flags: PageFlags,
) -> Result<AspaceMapping, VmoError> {
    let mut frames = [0u64; MAX_VMO_PAGES];
    let n = mm::with_vmm_lock(|| {
        let t = tbl();
        let e = t.items.get(usize::from(id.slot)).ok_or(VmoError::NoSuch)?;
        if !e.used {
            return Err(VmoError::NoSuch);
        }
        let n = usize::from(e.pages);
        frames[..n].copy_from_slice(&e.frames[..n]);
        Ok(n)
    })?;
    mm::aspace_map(space, &frames[..n], va, flags, MOD_VMO).map_err(VmoError::Mm)
}
