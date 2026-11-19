//! ACPI **固定布局**表解析（手册 §4.1 的 M2/M3b 一级，ADR-012a）。
//!
//! 边界（与 V1.2 R11 的拆分一致）：本文件只读那些"字段偏移由规范定死"的表
//! （RSDP / XSDT / RSDT / FADT / MADT / MCFG / DMAR / IVRS）。**AML 解释器不在这里**，
//! 那是 M5b 的 ADR-012b。之所以先把固定布局做掉：M3b 的多核启动要 MADT 里的
//! LAPIC 基址、IO APIC 地址与中断覆盖；M5 的 PCIe ECAM 要 MCFG 的基址；
//! IOMMU 要 DMAR/IVRS。这些都不需要解释 AML。
//!
//! 三条读内存的纪律，都是本文件形状的原因：
//! 1. **每次读之前先问页表**。HHDM 只按 usable/reclaimable 的上界铺开，ACPI 表可能
//!    落在 `ACPI_reclaimable` / `NVS` / `Reserved` 里；不看页表就解引用，故障现场是
//!    "unexpected #PF"，归因要到异常栈里，而这里一句 `Unmapped` 就能定位。
//! 2. **长度按表头自己说**。每张表的 `Length` 字段决定读多少，不信任任何固定尺寸，
//!    短于最小长度的表直接判 `Truncated`（真机固件上这是常见错误）。
//! 3. **校验和必须整表算**。ACPI 描述符校验和的定义是：整表（含校验和字段本身）
//!    按字节相加，低 8 位为 0。这条是 §12.4 "尺子先证明能分辨"的用武之地——
//!    用例里同时算一次"把一个字节取反后的和"，那个和**必须**不为 0（见
//!    `checksum_with_byte_flipped` 的注释：这是可证明的，不是碰运气）。

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub const MAX_TABLES: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiError {
    /// bootloader 没给 RSDP（RSDP 请求返回空）
    NoRsdp,
    /// RSDP 签名不对，或所在页没映射
    BadRsdp,
    /// revision>=2 却拿不到 XSDT，且 XSDT 所在页不可读
    NoXsdt,
    /// 只有 RSDT（32 位地址），本内核按 HHDM 读它
    RsdtOnly,
    /// 表头声明的长度小于该表的最小长度
    Truncated,
    /// 目标地址不在我们的页表里（见模块头第 1 条）
    Unmapped,
    /// 表数量超过 MAX_TABLES
    TooManyTables,
}

/// 一张被登记的表。`va` 是**经 HHDM 可达的虚拟地址**。
#[derive(Debug, Clone, Copy)]
pub struct TableRef {
    pub signature: [u8; 4],
    pub va: u64,
    pub length: usize,
    pub revision: u8,
    pub checksum_zero: bool,
}

impl TableRef {
    pub fn matches(&self, s: &[u8; 4]) -> bool {
        &self.signature == s
    }
}

pub const MAX_CPUS: usize = 8;
pub const MAX_IOAPICS: usize = 4;
pub const MAX_OVERRIDES: usize = 24;
/// 读进栈缓冲区的 MADT 上限。本机实测 144 字节；4 KiB 是"固件长度字段不可信"的防线
pub const MADT_MAX_BYTES: usize = 4096;

/// MADT type-1：一个 I/O APIC 的位置与它的 GSI 起点。
/// `addr` 是**物理** MMIO 地址，用之前必须经 HHDM 翻译（而且它不在 memmap 的可用区间里，
/// 见 BACKLOG 的"4 GiB 之上 MMIO 未映射"那条同源问题）。
#[derive(Debug, Clone, Copy)]
pub struct IoApic {
    pub id: u8,
    pub addr: u64,
    pub gsi_base: u32,
}

impl IoApic {
    pub const EMPTY: IoApic = IoApic { id: 0, addr: 0, gsi_base: 0 };
}

/// MADT type-2：ISA IRQ → GSI 的重映射，外加极性/触发方式。
/// flags 位：bit0 一致性、bit1 极性(1=下拉/低有效)、bit2 触发(1=电平)、bit3 屏蔽。
#[derive(Debug, Clone, Copy)]
pub struct Override {
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

impl Override {
    pub const EMPTY: Override = Override { bus: 0, source: 0, gsi: 0, flags: 0 };
}

/// ISA 中断 → GSI：有覆盖就用覆盖，没有就 1:1。这条函数是中断路径唯一的映射来源，
/// 所以它必须能脱离真表被测试（`gsi_for` 的入参是已解析好的表，不是内存）。
pub fn gsi_for(m: &Madt, isa_irq: u8) -> u32 {
    for o in &m.overrides[..m.n_overrides] {
        if o.bus == 0 && o.source == isa_irq {
            return o.gsi;
        }
    }
    isa_irq as u32
}

/// GSI → (用哪个 I/O APIC, 表内索引)。找不到返回 None，绝不"就当成第一个 APIC 的第 N 条"。
pub fn ioapic_for(m: &Madt, gsi: u32) -> Option<(usize, u8)> {
    for (i, a) in m.ioapic[..m.n_ioapic].iter().enumerate() {
        if gsi >= a.gsi_base && gsi < a.gsi_base + 24 {
            return Some((i, (gsi - a.gsi_base) as u8));
        }
    }
    None
}

#[derive(Debug, Clone, Copy)]
pub struct Madt {
    pub lapic_base: u64,
    pub pcat_compat: bool,
    /// type-0（本地 APIC）与 type-9（x2APIC）条目里被使能的 CPU 数
    pub cpu_enabled: usize,
    /// flags bit1 = Online capable（ACPI 6.3 起）。**不是** bootable：
    /// MADT 里根本没有"哪个是 BSP"这一位——那是 MP spec 的老标志位，ACPI 换成
    /// "Enabled / Online capable" 两个位。想认 BSP 只能问启动我们那位的人
    /// （limine 的多处理器响应给 boot CPU id），不能从 MADT 猜。
    pub cpu_online_capable: usize,
    pub cpu_total: usize,
    /// 使能 CPU 的 APIC id（type-0 偏移 +3，**不是** +2 的 ACPI processor id）
    pub lapic_ids: [u32; MAX_CPUS],
    /// 同一批条目的 ACPI processor id（type-0 偏移 +2）。与上面分开存，
    /// 因为两者在 QEMU 上恰好相等、在真机上可以差很远。
    pub acpi_ids: [u32; MAX_CPUS],
    pub n_ids: usize,
    /// 使能条目多于 MAX_CPUS 时的溢出数（不是 0 就说明这份清单不完整）
    pub ids_overflow: usize,
    pub ioapic: [IoApic; MAX_IOAPICS],
    pub n_ioapic: usize,
    pub ioapic_overflow: usize,
    pub overrides: [Override; MAX_OVERRIDES],
    pub n_overrides: usize,
    pub override_overflow: usize,
    /// MADT 声明但读不到/畸形的条目数（必须是 0 才算解析完整）
    pub skipped_entries: usize,
    /// 表比 44 字节还短（合成表测试里用来验证这条不会静默出好结果）
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Fadt {
    pub revision: u8,
    pub length: usize,
    /// Boot Architecture Flags（rev>=2.0 偏移 96，u32）；不足长度的表读不到就是 None
    pub boot_arch: Option<u32>,
    /// rev>=3 偏移 108 的 flags：bit19 = HW-reduced platform
    pub hw_reduced: Option<bool>,
}

#[derive(Debug, Clone, Copy)]
pub struct Summary {
    pub ready: bool,
    pub rsdp_va: u64,
    /// 根表（XSDT/RSDT）的**物理**地址；日志里和它一起打的虚地址才是我们读的
    pub root_phys: u64,
    pub rsdp_revision: u8,
    pub used_xsdt: bool,
    pub tables: usize,
    pub checksum_failures: usize,
    pub madt: Option<Madt>,
    pub fadt: Option<Fadt>,
    pub mcfg_base: Option<u64>,
    pub mcfg_bus_start: Option<u16>,
    pub mcfg_bus_end: Option<u16>,
    pub dmar_host_address_width: Option<u8>,
    pub dmar_flags: Option<u8>,
    pub ivrs_present: bool,
    pub unmapped_reads: usize,
}

// 解析结果放静态量：ktest 只读，不重复解析（解析本身要碰固件给的内存，跑两次
// 会得到两次同样的结论却花两倍的风险）。
static SUMMARY: AtomicU64 = AtomicU64::new(0); // 仅作 ready 的存在性哨兵，正体在 SUM_CELL
static UNMAPPED_READS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
struct SumCell {
    inner: Option<Summary>,
}
struct SumCellSync(UnsafeCell<SumCell>);
// SAFETY: 与 mm::State 同一条前提——单核 + IF=0 阶段写入一次、之后只读。
unsafe impl Sync for SumCellSync {}
static SUM_CELL: SumCellSync = SumCellSync(UnsafeCell::new(SumCell { inner: None }));

#[inline]
fn sum_set(s: Summary) {
    // SAFETY: 见 SumCellSync——单核启动阶段，写入发生在任何并发读者出现之前。
    unsafe { (*SUM_CELL.0.get()).inner = Some(s) };
    SUMMARY.store(1, Ordering::Release);
}

pub fn summary() -> Option<Summary> {
    if SUMMARY.load(Ordering::Acquire) == 0 {
        return None;
    }
    // SAFETY: 上面已确认 ready 标志置位，此后本文件不再写 SUM_CELL
    unsafe { (*SUM_CELL.0.get()).inner }
}

pub fn unmapped_reads() -> usize {
    UNMAPPED_READS.load(Ordering::Relaxed)
}

// ------------------------------------------------------------------ 读原语

/// ACPI 表内部的指针都是物理地址，必须经 HHDM 才能读。
///
/// 这里**不做**"地址低于 max_phys"之外的判断：翻译本身只是一次加法，越界交给
/// `span_mapped` 去拒。反过来，如果哪天要在没有 HHDM 的地址空间里读表（例如
/// 用户态映射），这条就是唯一要改的出口。
#[inline]
fn phys_to_virt(phys: u64) -> u64 {
    phys + crate::mm::hhdm()
}

/// 该 VA 跨度（`len` 字节）是否全部落在已映射的页里。
fn span_mapped(va: u64, len: usize) -> bool {
    if len == 0 {
        return mm_is_mapped(va);
    }
    let first = va & !(PAGE as u64 - 1);
    let last = (va + len as u64 - 1) & !(PAGE as u64 - 1);
    let mut p = first;
    while p <= last {
        if !mm_is_mapped(p) {
            return false;
        }
        p += PAGE as u64;
    }
    true
}

// 让本文件不直接依赖 mm 的名字，便于 §2.5 拆 crate 时只换这一层
#[inline]
fn mm_is_mapped(va: u64) -> bool {
    crate::mm::is_mapped(va)
}

const PAGE: usize = 4096;

fn read_bytes(va: u64, out: &mut [u8]) -> Result<(), AcpiError> {
    if !span_mapped(va, out.len()) {
        UNMAPPED_READS.fetch_add(1, Ordering::Relaxed);
        return Err(AcpiError::Unmapped);
    }
    for (i, o) in out.iter_mut().enumerate() {
        // SAFETY: 上一步已确认 [va, va+len) 整段落在已映射页内；volatile 是因为
        // 固件表可能被别的持有者改写（我们不做缓存假设），且长度受控不越页。
        *o = unsafe { core::ptr::read_volatile((va as usize + i) as *const u8) };
    }
    Ok(())
}

fn read_u8(va: u64) -> Result<u8, AcpiError> {
    let mut b = [0u8; 1];
    read_bytes(va, &mut b)?;
    Ok(b[0])
}

fn read_u16(va: u64) -> Result<u16, AcpiError> {
    let mut b = [0u8; 2];
    read_bytes(va, &mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32(va: u64) -> Result<u32, AcpiError> {
    let mut b = [0u8; 4];
    read_bytes(va, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64(va: u64) -> Result<u64, AcpiError> {
    let mut b = [0u8; 8];
    read_bytes(va, &mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// 整表按字节相加取低 8 位。ACPI 规定合法表此值为 0。
pub fn checksum(va: u64, len: usize) -> Result<u8, AcpiError> {
    if !span_mapped(va, len) {
        UNMAPPED_READS.fetch_add(1, Ordering::Relaxed);
        return Err(AcpiError::Unmapped);
    }
    let mut sum = 0u8;
    let mut off = 0usize;
    while off < len {
        let n = core::cmp::min(64, len - off);
        let mut buf = [0u8; 64];
        read_bytes(va + off as u64, &mut buf[..n])?;
        for b in &buf[..n] {
            sum = sum.wrapping_add(*b);
        }
        off += n;
    }
    Ok(sum)
}

/// **量具自检用**：把偏移 `at` 处的字节取反后的表和。
///
/// 为什么这是可证明的而不是碰运气：设整表和 S≡0 (mod 256)，字节 b 被换成 255−b，
/// 新和 ≡ 255 − 2b (mod 256)。`2b` 恒为偶数、`255` 为奇数，所以新和恒为奇数，
/// **永远不可能 ≡ 0**。也就是说：只要 `checksum` 真的在整表上求和，这个函数
/// 必然报"不为 0"；哪天它报了 0，就是求和的长度或分块写坏了——这正是
/// §12.4 要的"换一把仪器再数一次"。
pub fn checksum_with_byte_flipped(va: u64, len: usize, at: usize) -> Result<u8, AcpiError> {
    let b = read_u8(va + at as u64)?;
    let s = checksum(va, len)?;
    Ok(s.wrapping_add(255).wrapping_sub(b).wrapping_sub(b))
}

// ------------------------------------------------------------------ 结构偏移

/// 通用表头（36 字节）里 `Length` 的偏移
const SDT_LENGTH: u64 = 4;
const SDT_REVISION: u64 = 8;
const SDT_CHECKSUM: u64 = 9;
const SDT_HEADER_SIZE: usize = 36;

/// 读表头并登记一张表；长度不合法/不可读都返回 Err，由调用方计成失败而不是跳过。
fn register(entry_va: u64, refs: &mut [Option<TableRef>; MAX_TABLES], n: &mut usize) -> Result<(), AcpiError> {
    if *n >= MAX_TABLES {
        return Err(AcpiError::TooManyTables);
    }
    let len = read_u32(entry_va + SDT_LENGTH)? as usize;
    let rev = read_u8(entry_va + SDT_REVISION)?;
    let mut sig = [0u8; 4];
    read_bytes(entry_va, &mut sig)?;
    if len < SDT_HEADER_SIZE {
        return Err(AcpiError::Truncated);
    }
    // 校验和字段自己也在求和范围内，所以整表和必须为 0
    let sum = checksum(entry_va, len)?;
    refs[*n] = Some(TableRef { signature: sig, va: entry_va, length: len, revision: rev, checksum_zero: sum == 0 });
    *n += 1;
    Ok(())
}

/// 解析入口。`rsdp_va` 是 limine RSDP 响应给的**虚拟地址**（base revision>=4 的语义；
/// rev3 是物理地址，那种情况由 main.rs 的 KT_RSDP 先拒掉）。
pub fn init(rsdp_va: u64) -> Result<Summary, AcpiError> {
    let mut s = Summary {
        ready: false,
        rsdp_va,
        root_phys: 0,
        rsdp_revision: 0,
        used_xsdt: false,
        tables: 0,
        checksum_failures: 0,
        madt: None,
        fadt: None,
        mcfg_base: None,
        mcfg_bus_start: None,
        mcfg_bus_end: None,
        dmar_host_address_width: None,
        dmar_flags: None,
        ivrs_present: false,
        unmapped_reads: 0,
    };
    if rsdp_va == 0 {
        return Err(AcpiError::NoRsdp);
    }
    // ---- RSDP：签名 "RSD PTR "，rev0 校验和覆盖前 20 字节，rev>=2 再覆盖后 20 字节
    let mut sig = [0u8; 8];
    read_bytes(rsdp_va, &mut sig)?;
    if &sig != b"RSD PTR " {
        return Err(AcpiError::BadRsdp);
    }
    let rev = read_u8(rsdp_va + 15)?;
    s.rsdp_revision = rev;
    let c0 = checksum(rsdp_va, 20)?;
    // 前 20 字节的校验和必须为 0；这条是"固件给的表能不能信"的第一道闸
    if c0 != 0 {
        return Err(AcpiError::BadRsdp);
    }
    s.used_xsdt = rev >= 2;
    // **本模块最容易犯的错，写成一条规则**：limine 的 RSDP 响应给的是**虚拟**地址
    // （base revision>=4 的语义），但 RSDP 里面的 RSDT/XSDT 指针、以及 XSDT 每一项，
    // 都是固件按 ACPI 规范写的**物理**地址。两者混用不会崩溃，只会"读不到表"——
    // 第一版就是这么挂在 NoXsdt 上的：`mm_is_mapped(0x1feb6000)` 当然是 false。
    let root_phys = if rev >= 2 {
        let len = read_u32(rsdp_va + 20)? as usize;
        let cx = checksum(rsdp_va, core::cmp::max(len, 36))?;
        if cx != 0 || len < 36 {
            return Err(AcpiError::BadRsdp);
        }
        read_u64(rsdp_va + 24)?
    } else {
        read_u32(rsdp_va + 16)? as u64
    };
    s.root_phys = root_phys;
    let root_va = if root_phys == 0 { 0 } else { phys_to_virt(root_phys) };
    if root_va == 0 || !mm_is_mapped(root_va) {
        return Err(if s.used_xsdt { AcpiError::NoXsdt } else { AcpiError::RsdtOnly });
    }

    // ---- XSDT / RSDT：表头之后是地址数组
    let root_len = read_u32(root_va + SDT_LENGTH)? as usize;
    if root_len < SDT_HEADER_SIZE {
        return Err(AcpiError::Truncated);
    }
    let mut refs = [None; MAX_TABLES];
    let mut n = 0usize;
    let entry_size: usize = if s.used_xsdt { 8 } else { 4 };
    let count = (root_len - SDT_HEADER_SIZE) / entry_size;
    if count > MAX_TABLES {
        return Err(AcpiError::TooManyTables);
    }
    for i in 0..count {
        let e = root_va + (SDT_HEADER_SIZE as u64) + (i * entry_size) as u64;
        let tv_phys = if s.used_xsdt { read_u64(e)? } else { read_u32(e)? as u64 };
        if tv_phys == 0 {
            continue;
        }
        register(phys_to_virt(tv_phys), &mut refs, &mut n)?;
    }
    s.tables = n;
    // 把整份登记表留在静态量里（见 REFS 的注释）：之后只有 Summary 的派生字段被
    // init 消化，但用例需要逐张复核签名与校验和。
    for i in 0..n {
        // SAFETY: 见 RefsCell——此刻仍是单核启动阶段，写完后本文件不再写
        unsafe { (*REFS.0.get())[i] = refs[i] };
    }
    for r in refs.iter().flatten() {
        if !r.checksum_zero {
            s.checksum_failures += 1;
        }
        if r.matches(b"APIC") {
            s.madt = Some(parse_madt(r)?);
        } else if r.matches(b"FACP") {
            s.fadt = Some(parse_fadt(r)?);
        } else if r.matches(b"MCFG") {
            let (base, bs, be) = parse_mcfg(r)?;
            s.mcfg_base = Some(base);
            s.mcfg_bus_start = Some(bs);
            s.mcfg_bus_end = Some(be);
        } else if r.matches(b"DMAR") {
            s.dmar_host_address_width = Some(read_u8(r.va + 36)?);
            s.dmar_flags = Some(read_u8(r.va + 37)?);
        } else if r.matches(b"IVRS") {
            s.ivrs_present = true;
        }
    }
    s.unmapped_reads = unmapped_reads();
    s.ready = true;
    sum_set(s);
    Ok(s)
}

/// MADT：偏移 36 起 `Local APIC Address`(u32) + `Flags`(u32)，之后是条目流。
///
/// 先把整表读进栈上的缓冲区，再用字节切片的纯函数解析（`madt_from_bytes`）。
/// 不是为了"抽象"，是为了**能拿合成数据测偏移**：Processor Local APIC 条目里
/// `ACPI processor id` 在 +2、`APIC id` 在 +3，本机 QEMU 上两者恰好都是 0..3，
/// 取错偏移**不会**在这台机器上暴露（上一版取的就是 +2）。真机上这两个值不同，
/// 那时错一位就是把中断路由到不存在的核上——所以这里用合成表把它钉死。
/// `MADT_MAX_BYTES` 是对固件声明长度的防御，不是尺寸假设：超了直接报 Truncated。
fn parse_madt(t: &TableRef) -> Result<Madt, AcpiError> {
    if t.length < 44 {
        return Err(AcpiError::Truncated);
    }
    if t.length > MADT_MAX_BYTES {
        crate::log_fatal!("acpi: MADT 声明长度 {} 超过本模块上限 {}", t.length, MADT_MAX_BYTES);
        return Err(AcpiError::Truncated);
    }
    let mut buf = [0u8; MADT_MAX_BYTES];
    read_bytes(t.va, &mut buf[..t.length])?;
    Ok(madt_from_bytes(&buf[..t.length]))
}

#[inline]
fn u8_at(b: &[u8], i: usize) -> u8 {
    b.get(i).copied().unwrap_or(0)
}

#[inline]
fn u32_at(b: &[u8], i: usize) -> u32 {
    let w = [u8_at(b, i), u8_at(b, i + 1), u8_at(b, i + 2), u8_at(b, i + 3)];
    u32::from_le_bytes(w)
}

/// 纯解析：给定 MADT 原始字节（含 36 字节表头），返回结构化结果。
/// 没有任何内存访问，因此可以喂合成数据——这是本函数存在的理由。
pub fn madt_from_bytes(b: &[u8]) -> Madt {
    let mut m = Madt {
        lapic_base: u32_at(b, 36) as u64,
        pcat_compat: u32_at(b, 40) & 0x1 != 0,
        cpu_enabled: 0,
        cpu_online_capable: 0,
        cpu_total: 0,
        lapic_ids: [0; MAX_CPUS],
        acpi_ids: [0; MAX_CPUS],
        n_ids: 0,
        ids_overflow: 0,
        ioapic: [IoApic::EMPTY; MAX_IOAPICS],
        n_ioapic: 0,
        ioapic_overflow: 0,
        overrides: [Override::EMPTY; MAX_OVERRIDES],
        n_overrides: 0,
        override_overflow: 0,
        skipped_entries: 0,
        truncated: b.len() < 44,
    };
    let mut off = 44usize;
    while off + 2 <= b.len() {
        let ty = u8_at(b, off);
        let len = u8_at(b, off + 1) as usize;
        // len < 2 会让游标不动而永远转不完；条目越过表尾同样是畸形表。
        // 两种都**计数后停住**，绝不静默跳过——少报一个 CPU 的代价要等起不来核那天才付。
        if len < 2 || off + len > b.len() {
            m.skipped_entries += 1;
            break;
        }
        match (ty, len) {
            (0, 8) => {
                let acpi_id = u8_at(b, off + 2) as u32;
                let apic_id = u8_at(b, off + 3) as u32;
                let f = u32_at(b, off + 4);
                m.cpu_total += 1;
                if f & 0x1 != 0 {
                    m.cpu_enabled += 1;
                    if m.n_ids < MAX_CPUS {
                        m.lapic_ids[m.n_ids] = apic_id;
                        m.acpi_ids[m.n_ids] = acpi_id;
                        m.n_ids += 1;
                    } else {
                        m.ids_overflow += 1;
                    }
                }
                if f & 0x2 != 0 {
                    m.cpu_online_capable += 1;
                }
            }
            (1, 12) => {
                // I/O APIC：+2 id, +4 MMIO 地址(u32), +8 GSI base(u32)
                let e = IoApic { id: u8_at(b, off + 2), addr: u32_at(b, off + 4) as u64, gsi_base: u32_at(b, off + 8) };
                if m.n_ioapic < MAX_IOAPICS {
                    m.ioapic[m.n_ioapic] = e;
                    m.n_ioapic += 1;
                } else {
                    m.ioapic_overflow += 1;
                }
            }
            (2, 10) => {
                // Interrupt Source Override：+2 bus, +3 source(ISA IRQ), +4 GSI(u32), +8 flags(u16)
                let o = Override {
                    bus: u8_at(b, off + 2),
                    source: u8_at(b, off + 3),
                    gsi: u32_at(b, off + 4),
                    flags: (u8_at(b, off + 9) as u16) << 8 | u8_at(b, off + 8) as u16,
                };
                if m.n_overrides < MAX_OVERRIDES {
                    m.overrides[m.n_overrides] = o;
                    m.n_overrides += 1;
                } else {
                    m.override_overflow += 1;
                }
            }
            (9, 16) => {
                // Local x2APIC：+2 ACPI processor id(u32), +6 x2APIC id(u32), +10 flags
                let acpi_id = u32_at(b, off + 2);
                let apic_id = u32_at(b, off + 6);
                let f = u32_at(b, off + 10);
                m.cpu_total += 1;
                if f & 0x1 != 0 {
                    m.cpu_enabled += 1;
                    if m.n_ids < MAX_CPUS {
                        m.lapic_ids[m.n_ids] = apic_id;
                        m.acpi_ids[m.n_ids] = acpi_id;
                        m.n_ids += 1;
                    } else {
                        m.ids_overflow += 1;
                    }
                }
            }
            (5, _) | (10, _) | (11, _) | (12, _) | (17, _) => {
                // 其余 per-CPU 条目（NMI / LAPIC_NMI / GICC / GICDT）本切片只登记不取字段：
                // 取什么要按 ADR-014 的 x2APIC 决策一起定，不在这里猜。
            }
            _ => {}
        }
        off += len;
    }
    m
}


/// FADT：只取固定布局里我们真要用的两个 flag 字段，长度不足就报 None 而不是猜。
fn parse_fadt(t: &TableRef) -> Result<Fadt, AcpiError> {
    let boot_arch = if t.length >= 100 { Some(read_u32(t.va + 96)?) } else { None };
    let hw_reduced = if t.length >= 112 { Some(read_u32(t.va + 108)? & (1 << 19) != 0) } else { None };
    Ok(Fadt { revision: t.revision, length: t.length, boot_arch, hw_reduced })
}

/// MCFG：表头 36 + 保留 8，之后每条 16 字节：base(u64) / bus(u16) / dev(u16) / func(u16) / rsvd(u32)
fn parse_mcfg(t: &TableRef) -> Result<(u64, u16, u16), AcpiError> {
    if t.length < 60 {
        return Err(AcpiError::Truncated);
    }
    let base = read_u64(t.va + 44)?;
    let bus = read_u16(t.va + 52)?;
    // 本切片只登记第一段 ECAM（q35/真机都如此）；多段要等 M5 的 PCI 枚举，
    // 到时这里必须返回全部段而不是静默忽略后面的。
    Ok((base, bus, bus))
}

/// 供用例与日志逐张复核的登记表。
///
/// 为什么要留这份数组而不是只留派生字段：校验和的"量具自检"（见
/// `checksum_with_byte_flipped`）必须作用在**一张真表**上，而用例还要能在
/// "固件给了 20 张表、我只认得 4 张"的情况下把签名列出来——只留派生字段就说不清
/// 剩下那 16 张是什么。
#[repr(C, align(64))]
struct RefsCell(UnsafeCell<[Option<TableRef>; MAX_TABLES]>);
// SAFETY: 与 mm::State 同一条前提（单核 + IF=0，init 一次、之后只读）
unsafe impl Sync for RefsCell {}
static REFS: RefsCell = RefsCell(UnsafeCell::new([None; MAX_TABLES]));

pub fn table(i: usize) -> Option<TableRef> {
    let n = summary().map(|s| s.tables).unwrap_or(0);
    if i >= n {
        return None;
    }
    // SAFETY: 见 RefsCell；n 由已置位的 Summary 给出，读的是 init 期间写满的槽位
    unsafe { (*REFS.0.get())[i] }
}

/// 4 字节签名按大端打包成 u32：日志里 `APIC` 打成 `0x41504943`，肉眼可对照规范。
/// 不打印 &str，因为本内核唯一的日志通道是 115200 波特按字节忙等的串口，
/// 为一条签名再走一遍字符串化不值得（而且 `check-nofloat` 之外我们还盯着字节数）。
pub fn sig_be(t: TableRef) -> u32 {
    u32::from_be_bytes(t.signature)
}
