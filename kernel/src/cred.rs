//! C1（ADR-150）：凭据对象与身份模型。
//!
//! **为什么要一张表而不是一个全局 `uid`**：验收句要的是"不同用户访问同一资源
//! 产生可验证的授权差异"。差异只能来自**两个不同的凭据对象**——把身份塞进
//! 任务结构里就变成"每个任务一个数"，那是身份标签不是凭据。
//!
//! 形状纪律（与 ADR-142 的 ARP 表同族）：
//! 1. **无堆**：固定 `CRED_MAX` 项，线性查找（本机进程数远小于 16）。
//! 2. **不猜默认值**：查不到就是 `None`，不返回"root"。
//! 3. **判据读数**：`lookups/hits/misses/denies` 四计数由判定格核增量。
//! 4. **不可变身份**：`CredId` 一旦分配，`uid/gid` 不再改（`passwd` 改密码是
//!    另一个字段，见未决 1）。

/// 凭据表容量。16 与本仓库其它固定表（`MAX_OWNED`=16、ARP 8）同一量级。
pub const CRED_MAX: usize = 16;

/// 凭据 id：表内槽位 + 代次。**代次防 ABA**——槽位复用后旧 id 必须失效。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CredId {
    pub slot: u8,
    pub gen: u32,
}

/// 一个凭据对象。
///
/// `uid`/`gid` 是**数值身份**（C1 验收句要的 `id` 输出）；
/// `caps` 是能力位（与 `handle::RIGHT_*` 同一套位语义，但**独立一份**：
/// 句柄权限描述"对这个对象能做什么"，凭据描述"这个主体能要什么"）。
#[derive(Clone, Copy)]
pub struct Cred {
    pub id: CredId,
    pub used: bool,
    pub uid: u32,
    pub gid: u32,
    /// 能力位（`CAP_*`）
    pub caps: u32,
    /// 登录名（定长，0 结尾）。**不是字符串对象**：定长数组在 `no_std` 下
    /// 不需要分配器，也不会让"名字"变成一个可被 free 的堆对象。
    pub name: [u8; NAME_MAX],
    /// 名字的有效长度（不含结尾 0）
    pub name_len: u8,
}

/// 登录名上限。8 字节够 `root`/`guest`/`audit`，且让一个 `Cred` 保持在
/// 32 字节以内（16 项 = 512 字节静态，与仓库其它表同量级）。
pub const NAME_MAX: usize = 8;

/// 能力位。**六位**，与句柄权限同一套编码但语义是"主体能要什么"。
/// 取值刻意与 `RIGHT_*` 错开高位，避免把两套表混读。
pub const CAP_NONE: u32 = 0;
/// 能读任意文件/设备（`cat`、`ls`）
pub const CAP_READ: u32 = 1 << 8;
/// 能写（`cp`、`rm`、`mkdir`）
pub const CAP_WRITE: u32 = 1 << 9;
/// 能管进程（`kill`）
pub const CAP_KILL: u32 = 1 << 10;
/// 能读内核日志（`dmesg`）
pub const CAP_LOG: u32 = 1 << 11;
/// 能枚举设备（`lspci`/`lsdev`/`devctl`）
pub const CAP_DEV: u32 = 1 << 12;
/// 能管凭据（`passwd`、授受凭据）
pub const CAP_ADMIN: u32 = 1 << 13;

/// `root` 的全部能力
pub const CAP_ALL: u32 = CAP_READ | CAP_WRITE | CAP_KILL | CAP_LOG | CAP_DEV | CAP_ADMIN;

/// 判据读数（与 `ArpStats` 同族：四计数）。
#[derive(Clone, Copy, Default)]
pub struct CredStats {
    /// `cred_lookup` 的调用次数
    pub lookups: u32,
    /// 查到且代次匹配
    pub hits: u32,
    /// 查不到 / 代次不匹配 / 槽位空
    pub misses: u32,
    /// `cred_allows` 判否的次数（授权差异的**直接读数**）
    pub denies: u32,
}

struct Table {
    creds: [Cred; CRED_MAX],
    n: usize,
    next_gen: u32,
    stats: CredStats,
}

const EMPTY_CRED: Cred = Cred {
    id: CredId { slot: 0, gen: 0 },
    used: false,
    uid: 0,
    gid: 0,
    caps: CAP_NONE,
    name: [0u8; NAME_MAX],
    name_len: 0,
};

struct Cell(core::cell::UnsafeCell<Table>);

// SAFETY: 表的全部访问都在 `cred_*` 四个入口里，调用点全在内核串行上下文
// （syscall 处理与启动路径，本仓库今天没有并发写者）；`Table` 内部只有定长
// 数组与计数，没有指针，地址范围固定在这一个静态对象里，对齐由编译器保证，
// 生命周期 'static。不变量（`n` 与 `creds[..n].used` 一致）由
// `cred_create`/`cred_lookup`/`cred_allows` 共同维持。
unsafe impl Sync for Cell {}

static TABLE: Cell = Cell(core::cell::UnsafeCell::new(Table {
    creds: [EMPTY_CRED; CRED_MAX],
    n: 0,
    next_gen: 1,
    stats: CredStats {
        lookups: 0,
        hits: 0,
        misses: 0,
        denies: 0,
    },
}));

/// 建一个凭据。`name` 超长就截断（**不报错**：名字是显示件，不是身份）。
/// 返回 `None` 表示表满（`CRED_MAX` 个都用完了）。
pub fn cred_create(uid: u32, gid: u32, caps: u32, name: &[u8]) -> Option<CredId> {
    // SAFETY: 见 `Cell` 的 Sync 论证。
    let t = unsafe { &mut *TABLE.0.get() };
    let mut slot = CRED_MAX;
    let mut i = 0usize;
    while i < CRED_MAX {
        if !t.creds[i].used {
            slot = i;
            break;
        }
        i += 1;
    }
    if slot == CRED_MAX {
        return None;
    }
    let gen = t.next_gen;
    t.next_gen = t.next_gen.wrapping_add(1);
    if t.next_gen == 0 {
        t.next_gen = 1; // 代次 0 保留给"空槽"
    }
    let id = CredId {
        slot: slot as u8,
        gen,
    };
    let mut nm = [0u8; NAME_MAX];
    let mut k = 0usize;
    while k < NAME_MAX && k < name.len() {
        nm[k] = name[k];
        k += 1;
    }
    t.creds[slot] = Cred {
        id,
        used: true,
        uid,
        gid,
        caps,
        name: nm,
        name_len: k as u8,
    };
    if slot + 1 > t.n {
        t.n = slot + 1;
    }
    Some(id)
}

/// 按 id 查凭据。代次不匹配 = miss（**槽位复用后旧 id 必须失效**）。
pub fn cred_lookup(id: CredId) -> Option<Cred> {
    // SAFETY: 见 `Cell` 的 Sync 论证。
    let t = unsafe { &mut *TABLE.0.get() };
    t.stats.lookups = t.stats.lookups.wrapping_add(1);
    let slot = id.slot as usize;
    if slot >= CRED_MAX {
        t.stats.misses = t.stats.misses.wrapping_add(1);
        return None;
    }
    let c = &t.creds[slot];
    if !c.used || c.id.gen != id.gen {
        t.stats.misses = t.stats.misses.wrapping_add(1);
        return None;
    }
    t.stats.hits = t.stats.hits.wrapping_add(1);
    Some(*c)
}

/// 授权判定：这个凭据有没有 `cap` 这一位。
///
/// **这是验收句"可验证的授权差异"的唯一判据入口**——所有命令的权限检查都走
/// 这里，`denies` 计数就是差异的读数。
pub fn cred_allows(id: CredId, cap: u32) -> bool {
    match cred_lookup(id) {
        Some(c) => {
            if c.caps & cap == cap {
                true
            } else {
                // SAFETY: 见 `Cell` 的 Sync 论证。
                let t = unsafe { &mut *TABLE.0.get() };
                t.stats.denies = t.stats.denies.wrapping_add(1);
                false
            }
        }
        None => false,
    }
}

/// 表里当前有多少项（`id` 命令的分页上界）。
pub fn cred_len() -> u32 {
    // SAFETY: 见 `Cell` 的 Sync 论证。
    let t = unsafe { &*TABLE.0.get() };
    t.n as u32
}

/// 按游标读一项。**每条定长 28 字节**：
/// `slot1 | gen4 | uid4 | gid4 | caps4 | name_len1 | name8 | 保留2`（小端）。
///
/// 1+4+4+4+4+1+8 = 26，垫到 **28**（4 字节对齐；写 `24` 会越过记录边界——
/// 第一版就是这么写的，实测在 `out[at+18+k]` 越界 panic）。
///
/// 返回写入的条数；`cursor` 越过表长时返 0（分页的终点，与 37 号同约定）。
pub fn cred_read_from(cursor: u32, out: &mut [u8]) -> usize {
    // SAFETY: 见 `Cell` 的 Sync 论证。
    let t = unsafe { &*TABLE.0.get() };
    const REC: usize = 28;
    let mut n = 0usize;
    let mut i = cursor as usize;
    while i < t.n && (n + 1) * REC <= out.len() {
        let c = &t.creds[i];
        if c.used {
            let at = n * REC;
            out[at] = c.id.slot;
            out[at + 1..at + 5].copy_from_slice(&c.id.gen.to_le_bytes());
            out[at + 5..at + 9].copy_from_slice(&c.uid.to_le_bytes());
            out[at + 9..at + 13].copy_from_slice(&c.gid.to_le_bytes());
            out[at + 13..at + 17].copy_from_slice(&c.caps.to_le_bytes());
            out[at + 17] = c.name_len;
            let mut k = 0usize;
            while k < NAME_MAX {
                out[at + 18 + k] = c.name[k];
                k += 1;
            }
            // at+26..at+28 保留（对齐垫片，不写）
            n += 1;
        }
        i += 1;
    }
    n
}

/// 判据读数。
pub fn cred_stats() -> CredStats {
    // SAFETY: 见 `Cell` 的 Sync 论证。
    let t = unsafe { &*TABLE.0.get() };
    t.stats
}

/// 一条记录的字长（`id` 分页与宿主机对账用同一个常量）。
pub const CRED_RECORD_LEN: usize = 28;
