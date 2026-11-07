//! ACPI 固定布局表、MADT 与 RSDP 用例（T0.1 纯搬移）。

use crate::arch::x86_64::{apic};
use crate::{acpi, limine, mm};
use crate::{RSDP_VA, mp_snapshot};
use crate::ktest;
use core::sync::atomic::{Ordering};

/// RSDP 的地址语义随 base revision 变化（rev3 物理、rev4+ 虚拟）。
/// 我们请求 rev5，因此必须是**可直接读的虚拟地址**；签名读不对就是启动信息不可信。
fn t_rsdp_signature_at_virtual_addr() -> bool {
    let Some(negotiated) = limine::BASE_REVISION.negotiated() else {
        return false;
    };
    let raw = RSDP_VA.load(Ordering::Relaxed);
    if raw == 0 {
        crate::log_warn!("rsdp: bootloader did not provide it");
        return false;
    }
    let hhdm = mm::hhdm();
    if raw < hhdm {
        crate::log_fatal!("rsdp={:#x} 低于 HHDM({:#x})：这是 rev3 的物理地址语义，与协商到的 rev{} 不符", raw, hhdm, negotiated);
        return false;
    }
    if !mm::is_mapped(raw) {
        crate::log_fatal!("rsdp={:#x} 在我们的页表里没有映射", raw);
        return false;
    }
    const SIG: &[u8; 8] = b"RSD PTR ";
    for i in 0..8 {
        // SAFETY: 上面已确认地址已映射；RSDP 至少 20 字节，只读前 8 字节签名
        let got = unsafe { core::ptr::read_volatile((raw as *const u8).add(i)) };
        if got != SIG[i] {
            crate::log_fatal!("rsdp signature mismatch at byte {}: got {:#02x} want {:#02x}", i, got, SIG[i]);
            return false;
        }
    }
    true
}
ktest!(KT_RSDP, t_rsdp_signature_at_virtual_addr);

/// 每张表都要过校验和；同时**自证这把尺子能分辨**：把某个字节取反后的和必须不为 0。
/// 后者不是走过场——`checksum` 若把长度算错（比如只算了表头 36 字节），
/// "所有表都通过"会一起变成假话，而这条断言必然先炸。
fn t_acpi_tables_and_checksums() -> bool {
    let Some(s) = acpi::summary() else {
        crate::log_fatal!("acpi: no summary, init 没成功");
        return false;
    };
    if s.tables == 0 {
        crate::log_fatal!("acpi: 登记到 0 张表——根表读到的条目全是空的");
        return false;
    }
    let mut probe_len = 0usize;
    let mut probe_va = 0u64;
    let mut i = 0usize;
    while let Some(t) = acpi::table(i) {
        crate::log_info!(
            "acpi: table{} sig={:#010x} va={:#x} len={} rev={} checksum_zero={}",
            i, acpi::sig_be(t), t.va, t.length, t.revision, t.checksum_zero
        );
        if t.length >= 40 && probe_va == 0 {
            probe_va = t.va;
            probe_len = t.length;
        }
        i += 1;
    }
    // 尺子自检：合法表的整表和必须为 0，翻转一字节后必须不为 0（数学上恒成立，见 acpi.rs）
    let (real, flipped) = if probe_len >= 40 {
        (acpi::checksum(probe_va, probe_len).ok(), acpi::checksum_with_byte_flipped(probe_va, probe_len, 36).ok())
    } else {
        (None, None)
    };
    crate::log_info!(
        "acpi ruler: tables={} failures={} unmapped_reads={} probe_sum={:?} flipped_sum={:?}",
        s.tables, s.checksum_failures, s.unmapped_reads, real, flipped
    );
    s.checksum_failures == 0
        && s.unmapped_reads == 0
        && real == Some(0)
        && flipped.is_some_and(|f| f != 0)
}
ktest!(KT_ACPI_CHECKSUMS, t_acpi_tables_and_checksums);

/// MADT 是 M3b 起 AP 的硬前置：LAPIC 基址、IO APIC 数、中断覆盖、BSP id 都得是真值。
fn t_acpi_madt_shape() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else {
        crate::log_fatal!("acpi: MADT 缺席，M3b 无从起核");
        return false;
    };
    // LAPIC 基址必须是页对齐的 MMIO 地址（规范给的是 0xFEE00000 一类）
    let lapic_ok = m.lapic_base != 0 && m.lapic_base & 0xfff == 0 && (m.lapic_base >> 20) != 0;
    // 清单完整性：列出的 id 数必须等于使能数（没有溢出），且每个 id 都 < 255
    // （保留/无效值）。这条是 M3b 起核的直接输入，缺一个 CPU 起不来时必须现在就叫。
    let ids_ok = m.ids_overflow == 0 && m.n_ids == m.cpu_enabled && m.lapic_ids[..m.n_ids].iter().all(|&id| id < 255);
    crate::log_info!(
        "acpi madt: lapic_ok={} ids_ok={} pcat_compat={} cpu_total={} cpu_enabled={} online_capable={} ioapics={} overrides={} skipped={}",
        lapic_ok, ids_ok, m.pcat_compat, m.cpu_total, m.cpu_enabled, m.cpu_online_capable, m.n_ioapic, m.n_overrides, m.skipped_entries
    );
    lapic_ok && ids_ok && m.cpu_enabled >= 1 && m.cpu_total >= m.cpu_enabled && m.n_ioapic >= 1 && m.skipped_entries == 0
}
ktest!(KT_ACPI_MADT, t_acpi_madt_shape);

/// FADT / MCFG / IOMMU 表的形状。MCFG 是 M5 PCIe ECAM 的入口，缺它就要在 M2 说出来，
/// 不能等到 M5 才发现"没有 ECAM 地址"。
fn t_acpi_fadt_and_mcfg() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let fadt_ok = s.fadt.map_or(false, |f| f.revision >= 2 && f.length >= 36 && f.boot_arch.is_some());
    let mcfg_ok = s.mcfg_base.map_or(false, |b| b & (1024 * 1024 - 1) == 0 && b != 0)
        && s.mcfg_bus_start.map_or(false, |b| s.mcfg_bus_end.map_or(false, |e| b <= e));
    let iommu_ok = s.dmar_host_address_width.map_or(true, |w| (39..=57).contains(&w));
    crate::log_info!("acpi shapes: fadt_ok={} mcfg_ok={} dmar_haw={:?} ivrs={} iommu_ok={}", fadt_ok, mcfg_ok, s.dmar_host_address_width, s.ivrs_present, iommu_ok);
    fadt_ok && mcfg_ok && iommu_ok
}
ktest!(KT_ACPI_SHAPES, t_acpi_fadt_and_mcfg);

/// ADR-014 的第一条待核实项**用实测关闭**：limine 的 MP 响应与 MADT 是两台独立仪器，
/// 它们对"这台机器有几个 CPU、LAPIC id 是多少"必须给出相容的答案。
/// 顺带验协议那句"首次交给 BSP 时 goto_address 保证为 NULL"——释放 AP 是一次原子发布，
/// 前提就是那个字段初始为空；不成立就不能盲目释放。
fn t_mp_agrees_with_madt() -> bool {
    let Some(m) = mp_snapshot() else {
        crate::log_fatal!("mp: no response, ADR-014 的这条没法在本机构闭上");
        return false;
    };
    let Some(s) = acpi::summary() else { return false };
    let Some(md) = s.madt else { return false };
    let n = core::cmp::min(m.n, md.n_ids);
    // 每个 limine 报的 lapic_id 都要在 MADT 的使能清单里出现
    let mut subset = m.overflow == 0 && m.n == m.cpu_count;
    for i in 0..m.n {
        if !md.lapic_ids[..md.n_ids].contains(&m.lapic_ids[i]) {
            subset = false;
        }
    }
    let bsp_listed = md.lapic_ids[..md.n_ids].contains(&m.bsp_lapic_id);
    crate::log_info!(
        "mp vs madt: mp_cpus={} madt_enabled={} overlap={} bsp_in_madt={} all_goto_null={} x2apic={} processor_id[0]={}",
        m.cpu_count, md.cpu_enabled, n, bsp_listed, m.all_goto_null, m.x2apic_enabled, m.processor_ids[0]
    );
    // cpu_count 与 MADT 使能数相等：本机 QEMU 上两者都是 4。真机上如果固件
    // 禁用了某个核，这条会红——那时改的是**判定依据**（子集关系），不是把断言删掉。
    m.all_goto_null && subset && bsp_listed && m.cpu_count == md.cpu_enabled
}
ktest!(KT_MP_VS_MADT, t_mp_agrees_with_madt);

/// **合成 MADT**：偏移纪律的唯一可靠尺子。
///
/// 为什么必须用合成表：本机 QEMU 的 type-0 条目里 `ACPI processor id`(+2) 与
/// `APIC id`(+3) 恰好都是 0..3，取错偏移**在这台机器上读不出任何差别**——
/// 上一版就取的 +2，跨仪器对账照样全绿。真机上两者可以完全不同，那时才炸就太晚了。
/// 这里造一张两个核、两组 id 故意不同的表，再验 GSI 映射与畸形表的行为。
fn t_madt_offsets_synthetic() -> bool {
    // 36 字节表头 + lapic_base(4) + flags(4) = 44 起是条目
    let mut b = [0u8; 44 + 8 * 3 + 12 + 10]; // 表头 + 三条 CPU 条目 + 一个 I/O APIC + 一条覆盖
    let total = b.len() as u32;
    b[..4].copy_from_slice(b"APIC");
    b[4..8].copy_from_slice(&total.to_le_bytes());
    b[36..40].copy_from_slice(&0xFEE0_0000u32.to_le_bytes());
    b[40..44].copy_from_slice(&1u32.to_le_bytes()); // PCAT_COMPAT
    // 核 A：ACPI id=5, APIC id=1, enabled
    b[44] = 0; b[45] = 8; b[46] = 5; b[47] = 1; b[48..52].copy_from_slice(&1u32.to_le_bytes());
    // 核 B：ACPI id=6, APIC id=2, enabled；再加一条**被禁用**的核 C（ACPI 7 / APIC 3）
    b[52] = 0; b[53] = 8; b[54] = 6; b[55] = 2; b[56..60].copy_from_slice(&1u32.to_le_bytes());
    b[60] = 0; b[61] = 8; b[62] = 7; b[63] = 3; b[64..68].copy_from_slice(&0u32.to_le_bytes());
    // I/O APIC 0：GSI base 0，地址 0xFEC00000
    b[68] = 1; b[69] = 12; b[70] = 0; b[71] = 0;
    b[72..76].copy_from_slice(&0xFEC0_0000u32.to_le_bytes());
    b[76..80].copy_from_slice(&0u32.to_le_bytes());
    // Override：ISA IRQ0 -> GSI 2，极性/触发位都置上（q35 上IRQ0 就是这样被改写的）
    b[80] = 2; b[81] = 10; b[82] = 0; b[83] = 0;
    b[84..88].copy_from_slice(&2u32.to_le_bytes());
    b[88..90].copy_from_slice(&0xdu16.to_le_bytes());

    let m = acpi::madt_from_bytes(&b);
    // 关键三条：id 取自 +3 而不是 +2；被禁用的核不进清单；ISA0 经覆盖落到 GSI2
    let ids_ok = m.n_ids == 2 && m.lapic_ids[0] == 1 && m.lapic_ids[1] == 2
        && m.acpi_ids[0] == 5 && m.acpi_ids[1] == 6;
    let counts_ok = m.cpu_total == 3 && m.cpu_enabled == 2 && m.ids_overflow == 0 && m.skipped_entries == 0;
    let gsi0 = acpi::gsi_for(&m, 0) == 2;
    let gsi5 = acpi::gsi_for(&m, 5) == 5; // 没有覆盖的 ISA 走 1:1
    let route = acpi::ioapic_for(&m, 2) == Some((0, 2));
    let no_route = acpi::ioapic_for(&m, 40).is_none(); // 不许"就近塞给第一个 APIC"
    // 畸形表：长度不足 44 必须被标 truncated，且不能报出漂亮的 CPU 数
    let bad = acpi::madt_from_bytes(&b[..30]);
    crate::log_info!(
        "synthetic madt: ids_ok={} counts_ok={} gsi0={} gsi5={} route={:?} out_of_range_none={} bad_truncated={} bad_cpus={}",
        ids_ok, counts_ok, gsi0, gsi5, acpi::ioapic_for(&m, 2), no_route, bad.truncated, bad.cpu_total
    );
    ids_ok && counts_ok && gsi0 && gsi5 && route && no_route && bad.truncated && bad.cpu_total == 0
}
ktest!(KT_MADT_SYNTH, t_madt_offsets_synthetic);

/// 交接状态是不是协议说的那样：逐条**读回来**，不引用文档当结论。
fn t_apic_handoff_state() -> bool {
    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    // 两个用例都要用，而表的枚举顺序不由源码顺序决定，所以 init 必须可重复调用：
    // get_or_init 已建好就复用同一份状态，不会多占一个设备页 VA。
    let st = match apic::get_or_init(&m) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("apic::init failed: {:?}", e);
            return false;
        }
    };
    crate::log_info!(
        "apic handoff: id={} version={:#x} max_lvt={} svr={:#x} was_enabled={} ioapic_id={} gsi_base={} irt={} timer gsi={} rte={} vec={}",
        st.id, st.version, st.max_lvt, st.svr, st.svr_was_enabled, st.ioapic_id, st.gsi_base, st.irt_entries, st.timer_gsi, st.timer_rte, st.timer_vector
    );
    // LAPIC id 必须与 MP 响应给的 BSP id 一致，且出现在 MADT 的使能清单里：
    // 这是第三台仪器（硬件寄存器本身）对上前两台。
    let Some(mp) = mp_snapshot() else { return false };
    let id_matches = st.id == mp.bsp_lapic_id && m.lapic_ids[..m.n_ids].contains(&st.id);
    let svr_ok = st.svr & 0x100 != 0 && (st.svr & 0xff) == 0xff;
    let shape_ok = st.irt_entries >= 16 && st.max_lvt >= 4 && st.version != 0;
    id_matches && svr_ok && shape_ok
}
ktest!(KT_APIC_HANDOFF, t_apic_handoff_state);

