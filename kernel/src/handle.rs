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
use crate::filesystem::vfs::{AhciDisk, Block};
use crate::sync::{IrqSpinLock, RANK_HANDLE};

pub const MAX_HANDLES: usize = 16;
/// 世代只用低 48 位；0 保留（空/从未分配过）。
pub const GEN_MAX: u64 = (1u64 << 48) - 1;
const SLOT_BITS: u64 = 16;
const SLOT_MASK: u64 = (1u64 << SLOT_BITS) - 1;

pub const RIGHT_READ: u32 = 1;
pub const RIGHT_WRITE: u32 = 2;
pub const RIGHT_MAP: u32 = 4;
pub const RIGHT_DUP: u32 = 8;
pub const RIGHT_TRANSFER: u32 = 16;

/// 用户拿到的那个整数。构造永远成功（它是用户可伪造的值）；校验在查表时做。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Handle(pub u64);

impl Handle {
    pub const fn pack(slot: u16, gen: u64) -> Handle {
        Handle(slot as u64 | ((gen & GEN_MAX) << SLOT_BITS))
    }

    /// 形状检查：值 0 / gen 0 / slot ≥ 16 都不合法（对用户是 `-1`，不是 `-5`）。
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
        }
    }
}

#[derive(Clone, Copy)]
pub struct FileObj {
    pub port: u8,
    pub cursor: FileCursor,
}

#[derive(Clone, Copy)]
struct Entry {
    /// 该槽**最近发过**的世代；0 = 从未分配。释放时保留，下一次 grant 在它上面 +1。
    gen: u64,
    used: bool,
    owner_gidx: u16,
    owner_id: u32,
    rights: u32,
    obj: Option<FileObj>,
}

const EMPTY: Entry = Entry {
    gen: 0,
    used: false,
    owner_gidx: 0,
    owner_id: 0,
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
    pub reads: u32,
    pub bytes: u64,
    pub live_peak: u32,
}

struct Table {
    slots: [Entry; MAX_HANDLES],
    c: Counters,
}

impl Table {
    const fn empty() -> Table {
        Table { slots: [EMPTY; MAX_HANDLES], c: Counters {
            grants: 0, closes: 0, stale: 0, not_owner: 0, denied: 0, exhausted: 0,
            invalid: 0, no_such: 0, revoked: 0, reads: 0, bytes: 0, live_peak: 0,
        } }
    }

    fn live(&self) -> u32 {
        self.slots.iter().filter(|e| e.used).count() as u32
    }
}

static TABLE: IrqSpinLock<Table> = IrqSpinLock::new(RANK_HANDLE, Table::empty());

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
    if e.owner_gidx as usize != owner.0 || e.owner_id != owner.1 {
        t.c.not_owner += 1;
        return Err(HErr::NotOwner);
    }
    if e.rights & need != need {
        t.c.denied += 1;
        return Err(HErr::Denied);
    }
    Ok(slot as usize)
}

/// 给一次打开好的文件发句柄。`cursor` 由调用方先 `mount`/`open_cursor` 得到——
/// 表里存的是**值**（C1：`port + Bpb + FileStat + 游标`），不存 `Volume` 的借用。
pub fn grant_file(owner: (usize, u32), port: u8, cursor: FileCursor, rights: u32) -> Result<Handle, HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
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
        rights,
            obj: Some(FileObj { port, cursor }),
    };
    t.c.grants += 1;
    let live = t.live();
    if live > t.c.live_peak {
        t.c.live_peak = live;
    }
    Ok(Handle::pack(slot as u16, next))
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

pub fn close(h: Handle, owner: (usize, u32)) -> Result<(), HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
    let slot = check(t, h, owner, 0)?;
    let e = &mut t.slots[slot];
    e.used = false;
    e.obj = None;
    e.rights = 0;
    // gen 保留：这一格下一回 grant 在它上面 +1（旧句柄因此变成 Stale）。
    t.c.closes += 1;
    Ok(())
}

/// `dup` = 新占一格、同对象、权限收窄。第一版**没有** `DUP` 就没有 `dup`；
/// `new ⊄ old` 一律拒（扩权是这一格存在的理由）。
pub fn dup(h: Handle, owner: (usize, u32), new_rights: u32) -> Result<Handle, HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
    let slot = check(t, h, owner, RIGHT_DUP)?;
    let old = t.slots[slot];
    if new_rights & !old.rights != 0 {
        t.c.denied += 1;
        return Err(HErr::Denied);
    }
    let Some(nslot) = t.slots.iter().position(|e| !e.used) else {
        t.c.exhausted += 1;
        return Err(HErr::Exhausted);
    };
    let next = next_gen(t.slots[nslot].gen);
    t.slots[nslot] = Entry {
        gen: next,
        used: true,
        owner_gidx: owner.0 as u16,
        owner_id: owner.1,
        rights: new_rights,
            // 对象本体与游标随表项复制：第一版没有对象表，两个句柄**不共享读取位置**。
        // 共享偏移要一张带引用计数的对象表，那是接缓冲区对象时一起做的事（设计 §3.3）。
        obj: old.obj,
    };
    t.c.grants += 1;
    let live = t.live();
    if live > t.c.live_peak {
        t.c.live_peak = live;
    }
    Ok(Handle::pack(nslot as u16, next))
}

/// 读票：锁内取走游标的副本，锁外读盘，锁内提交。中途任何失败都只是丢掉这张票——
/// 表项里的游标一格不动（"失败不提交"与 `FileCursor::read` 的语义同一条）。
pub struct ReadTicket {
    slot: u16,
    gen: u64,
    port: u8,
    cursor: FileCursor,
}

impl ReadTicket {
    pub fn port(&self) -> u8 {
        self.port
    }

    pub fn position(&self) -> u32 {
        self.cursor.position()
    }

    pub fn size(&self) -> u32 {
        self.cursor.stat().size
    }

    pub fn read_chunk(&mut self, disk: &dyn Block, dst: &mut [u8]) -> Result<usize, HErr> {
        self.cursor.read(disk, dst).map_err(HErr::Io)
    }
}

pub fn begin_read(h: Handle, owner: (usize, u32)) -> Result<ReadTicket, HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
    let slot = check(t, h, owner, RIGHT_READ)?;
    let e = &t.slots[slot];
    let Some(obj) = e.obj else {
        t.c.no_such += 1;
        return Err(HErr::NoSuch);
    };
    Ok(ReadTicket { slot: slot as u16, gen: e.gen, port: obj.port, cursor: obj.cursor })
}

/// 提交。表项必须仍是同一槽、同一世代——否则这次读的成果作废（返回 Stale）。
pub fn finish(ticket: ReadTicket, bytes: usize) -> Result<(), HErr> {
    let mut g = TABLE.lock();
    let t = g.get();
    let e = &mut t.slots[ticket.slot as usize];
    if !e.used || e.gen != ticket.gen {
        t.c.stale += 1;
        return Err(HErr::Stale);
    }
    if let Some(obj) = e.obj.as_mut() {
        obj.cursor = ticket.cursor;
    }
    t.c.reads += 1;
    t.c.bytes += bytes as u64;
    Ok(())
}

/// 丢弃一张票：表项不动。显式函数而不是 `Drop`，是为了让"没有提交"在调用点看得见。
pub fn abort(_ticket: ReadTicket) {}

/// 生产路径：按表项里的口重建 `AhciDisk`。一次读全部分配的 `dst`（事务性）。
pub fn read(h: Handle, owner: (usize, u32), dst: &mut [u8]) -> Result<usize, HErr> {
    let mut ticket = begin_read(h, owner)?;
    let disk = AhciDisk { port: ticket.port() };
    let n = ticket.read_chunk(&disk, dst)?;
    finish(ticket, n)?;
    Ok(n)
}

/// 取证路径：注入块设备（内存夹具）。与 `read` 共用取票/提交，只有盘不同。
#[cfg(feature = "fat32-probe")]
pub fn read_with(h: Handle, owner: (usize, u32), disk: &dyn Block, dst: &mut [u8]) -> Result<usize, HErr> {
    let mut ticket = begin_read(h, owner)?;
    let n = ticket.read_chunk(disk, dst)?;
    finish(ticket, n)?;
    Ok(n)
}

/// 任务退出撤销（`reap` 调用）：主人的两格都对上的表项全部清掉。
/// 不取 mm、不释放页框——只读文件对象**不持有页框**（设计 §7）。
pub fn revoke_task(gidx: usize, id: u32) -> usize {
    let mut g = TABLE.lock();
    let t = g.get();
    let mut n = 0u32;
    for e in t.slots.iter_mut() {
        if e.used && e.owner_gidx as usize == gidx && e.owner_id == id {
            e.used = false;
            e.obj = None;
            e.rights = 0;
                    n += 1;
        }
    }
    t.c.revoked += n;
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
    let mut g = TABLE.lock();
    let t = g.get();
    if slot < MAX_HANDLES {
        t.slots[slot].gen = gen & GEN_MAX;
        t.slots[slot].used = false;
        t.slots[slot].obj = None;
    }
}

/// 只清槽，不清计数器：分段用例之间要清表，但"这一轮发生过几次拒绝"必须能累计到最后的日志。
#[cfg(feature = "fat32-probe")]
pub fn reset_for_test() {
    let mut g = TABLE.lock();
    g.get().slots = [EMPTY; MAX_HANDLES];
}

#[cfg(feature = "fat32-probe")]
pub fn reset_counters_for_test() {
    let mut g = TABLE.lock();
    g.get().c = Counters::default();
}

#[cfg(feature = "fat32-probe")]
mod tests {
    use super::*;
    use crate::filesystem::fat32::Volume;
    use crate::filesystem::vfs::MemDisk;

    const IMAGE: &[u8] = include_bytes!("../fixtures/fat32-mem.img");
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
        let Some(cur) = fixture() else { return false };

        // ① 打包形状：48 位世代填满高位；0 / gen 0 / slot 16 全非法
        let h = Handle::pack(3, 5);
        let pack_ok = h.0 == 3 | (5u64 << 16) && h.unpack() == Some((3, 5))
            && Handle::pack(15, GEN_MAX).unpack() == Some((15, GEN_MAX))
            && Handle::pack(16, 1).unpack().is_none()
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

        // ⑤ 表满：16 格填满，第 17 次 Exhausted；既有句柄仍可读
        reset_for_test();
        let mut handles = [Handle(0); MAX_HANDLES];
        let mut filled = 0usize;
        for i in 0..MAX_HANDLES {
            match grant_file(OWNER, 3, cur, RIGHT_READ) {
                Ok(v) => {
                    handles[i] = v;
                    filled += 1;
                }
                Err(_) => break,
            }
        }
        let full_ok = filled == MAX_HANDLES
            && matches!(grant_file(OWNER, 3, cur, RIGHT_READ), Err(HErr::Exhausted))
            && counters().exhausted == 1;
        let mut one = [0u8; 16];
        let existing_ok = read_with(handles[0], OWNER, &MemDisk { img: IMAGE }, &mut one).is_ok()
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
        let shape_ok = matches!(begin_read(Handle(0), OWNER), Err(HErr::Invalid))
            && matches!(begin_read(Handle::pack(16, 1), OWNER), Err(HErr::Invalid))
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
        let revoke_ok = h1.is_some() && h2.is_some() && revoked == 2
            && live() == 0
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
        let t = match crate::sched::spawn_user(l.entry, l.stack_top, l.owned) {
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
        crate::apic::timer_stop().ok();
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
    crate::ktest!(KT_HANDLE_REAP, t_handle_reap);

}
