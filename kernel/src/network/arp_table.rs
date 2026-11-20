//! ARP 缓存表（RFC 826 的 merge 规则）。
//!
//! **无堆、固定 8 项、线性查找**。这张表是 `network` 域里唯一的并发共享状态
//! （`UnsafeCell` + `AtomicU32` 哨兵），所以它单独一个文件——
//! `check-unsafe` 的 U4 分类看的就是它。
// ---------------------------------------------------------------- B2 第四刀（ADR-142）：ARP 缓存
/// ARP 缓存（RFC 826 的"merge" 规则）：每次单播前先查表，miss 才广播。
/// **无堆、固定 8 项、线性查找**（不引堆、不引哈希）。`hits`/`misses` 是判据读数。
pub const ARP_TABLE_MAX: usize = 8;
pub struct ArpStats {
    pub hits: u32,
    pub misses: u32,
    pub learns: u32,
    pub evicts: u32,
}
static ARP_TABLE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0); // 0=未初始化 1=已初始化
struct ArpTable {
    // 线性数组，`ips[i]==0` 表示空槽（IP 0.0.0.0 不会是合法邻居）
    ips: [[u8; 4]; ARP_TABLE_MAX],
    macs: [[u8; 6]; ARP_TABLE_MAX],
    n: usize,
    hits: u32,
    misses: u32,
    learns: u32,
    evicts: u32,
}
struct ArpCell(core::cell::UnsafeCell<ArpTable>);
unsafe impl Sync for ArpCell {}
static ARP: ArpCell = ArpCell(core::cell::UnsafeCell::new(ArpTable {
    ips: [[0; 4]; ARP_TABLE_MAX],
    macs: [[0; 6]; ARP_TABLE_MAX],
    n: 0, hits: 0, misses: 0, learns: 0, evicts: 0,
}));

/// 查缓存。hit ⇒ MAC，miss ⇒ None（调用方广播）。
pub fn arp_lookup(ip: &[u8; 4]) -> Option<[u8; 6]> {
    // SAFETY: 见 `bn` 同款-- 单核初期内核、调用点都在内核串行上下文，无并发写。
    let t = unsafe { &mut *ARP.0.get() };
    let mut i = 0usize;
    while i < t.n {
        if t.ips[i] == *ip {
            t.hits += 1;
            return Some(t.macs[i]);
        }
        i += 1;
    }
    t.misses += 1;
    None
}

/// 学一条（ARP reply 的 sender）。已有则覆盖（RFC 826 merge），满则挤第一条（FIFO，最简而且测得出）。
pub fn arp_learn(ip: &[u8; 4], mac: &[u8; 6]) {
    // SAFETY: 同 `arp_lookup`。
    let t = unsafe { &mut *ARP.0.get() };
    t.learns += 1;
    let mut i = 0usize;
    while i < t.n {
        if t.ips[i] == *ip {
            t.macs[i] = *mac;
            return;
        }
        i += 1;
    }
    if t.n < ARP_TABLE_MAX {
        t.ips[t.n] = *ip;
        t.macs[t.n] = *mac;
        t.n += 1;
        return;
    }
    t.evicts += 1;
    // 满表：挤第 0 条，其余前移（FIFO）。
    let mut k = 0usize;
    while k + 1 < ARP_TABLE_MAX {
        t.ips[k] = t.ips[k + 1];
        t.macs[k] = t.macs[k + 1];
        k += 1;
    }
    t.ips[ARP_TABLE_MAX - 1] = *ip;
    t.macs[ARP_TABLE_MAX - 1] = *mac;
}

/// 缓存读数（判据用）。
pub fn arp_stats() -> ArpStats {
    // SAFETY: 同 `arp_lookup`。
    let t = unsafe { &*ARP.0.get() };
    ArpStats { hits: t.hits, misses: t.misses, learns: t.learns, evicts: t.evicts }
}

/// `arp_stats` 的同族入口：按游标把**表项**读出来（ADR-145：`ip neigh` 的读数通道）。
/// 每条**定长 10 字节**：IP4 + MAC6，紧排写到 `out`。
/// 返回写入的条数；`cursor` 超过表长时返 0（分页的终点）。
pub fn arp_read_from(cursor: u32, out: &mut [u8]) -> usize {
    // SAFETY: 同 `arp_lookup`。
    let t = unsafe { &*ARP.0.get() };
    let mut n = 0usize;
    let mut i = cursor as usize;
    while i < t.n && (n + 1) * 10 <= out.len() {
        let at = n * 10;
        out[at..at + 4].copy_from_slice(&t.ips[i]);
        out[at + 4..at + 10].copy_from_slice(&t.macs[i]);
        n += 1;
        i += 1;
    }
    n
}

/// 表里当前有多少项（`ip neigh` 分页的上界）。
pub fn arp_len() -> u32 {
    // SAFETY: 同 `arp_lookup`。
    let t = unsafe { &*ARP.0.get() };
    t.n as u32
}


