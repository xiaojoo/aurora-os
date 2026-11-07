//! PCI/AHCI/IRQ/串口与 DriverCtx 用例（T0.1 纯搬移）。

use crate::arch::x86_64::{apic, cpu, smp, trap};
use crate::{acpi, ahci, boot_guard, driver, hw, irq, mm, pci, resource};
use crate::ktest;

/// M5-a：PCI 配置空间。判据的原则同 §10.3：**能互相独立的两台仪器优先**。
/// 这里配置读同时走 ECAM 与 CAM 两条硬件路径，两边必须数到同一个数。
fn t_pci_config() -> bool {
    let Some(i) = pci::info() else {
        crate::log_fatal!("pci: 没跑过 init（表是空的）");
        return false;
    };
    // ① 根复合体必须是 bus0 dev0 func0 且属于"桥"类；这条不依赖任何我对 Q35 的记忆
    let root = pci::dev(0);
    let root_bdf0 = root.is_some_and(|d| d.bdf == 0);
    // ② 定长表不许静默截断
    let no_truncate = !i.truncated && i.n >= 1;
    // ③ 不存在的槽位不许被记成设备（vendor 既不能是 0 也不能是 0xFFFF）
    let all_real = (0..i.n).filter_map(pci::dev).all(|d| d.vendor != 0 && d.vendor != 0xFFFF);
    // ④ **两条硬件路径读同一个 DWORD**：ECAM 是内存映射，CAM 是 0xCF8/0xCFC 端口，
    //    它们错不到一起去。先按 vendor/device 找一台设备，再比它的 class DWORD。
    let target = (0..i.n).filter_map(pci::dev).find(|d| d.bar0 != 0).or(root);
    let (via_ecam, via_cam, t_bdf) = match target {
        Some(d) => {
            let (b, dv, f) = (d.bdf >> 16, (d.bdf >> 11) & 31, (d.bdf >> 8) & 7);
            let e = pci::ecam_class(b, dv, f);
            let c = pci::cam_class(b, dv, f);
            (e, c, d.bdf)
        }
        None => (0, 0, 0),
    };
    let agree = target.is_some() && via_ecam == via_cam && via_ecam & 0xFFFF_FFFF != 0xFFFF_FFFF;
    crate::log_info!(
        "pci: 判据 root_bdf0={} 不截断={} 槽位真实={} 目标={:04x}:{:02x}.{} ECAM@08={:#010x} CAM@08={:#010x} 两路一致={}",
        root_bdf0,
        no_truncate,
        all_real,
        t_bdf >> 16,
        (t_bdf >> 11) & 31,
        (t_bdf >> 8) & 7,
        via_ecam,
        via_cam,
        agree
    );
    // ⑤ **MMIO 映射不占页框账**（§8.3 与 §6.3 的边界）：设备区间不是 PMM 发出去的帧，
    //    所以一次 map/drop 前后 `free_frames()` 与保留条数都必须回到原值。
    let lapic = acpi::summary().and_then(|s| s.madt).map(|m| m.lapic_base).unwrap_or(0);
    let frames_before = mm::free_frames();
    let res_before = mm::reservation_count();
    let mut mmio_ok = false;
    let mut cross_ok = false;
    let mut bounds_ok = false;
    if lapic != 0 {
        match hw::MmioRegion::map(lapic & !0xFFF, mm::PAGE) {
            Ok(r) => {
                // 与 apic 模块的读数交叉核对：同一个寄存器、两条访问路径
                let raw = r.read32(0x20).unwrap_or(0xFFFF_FFFF);
                // 0x20 是 LAPIC 的 ID 寄存器，xAPIC 下 ID 在 bits 31:24
                cross_ok = (raw >> 24) as u8 == apic::self_id() as u8;
                // 三格都要判，缺一就不知道检查是不是"永远拒绝"那种假安全：
                // 范围内必须成功、越界必须拒、未对齐必须拒。
                bounds_ok = r.read32(0x20).is_ok()
                    && matches!(r.read32(4096), Err(hw::HwError::OutOfRange))
                    && matches!(r.read32(1), Err(hw::HwError::NotAligned))
                    && matches!(r.write32(4096, 0), Err(hw::HwError::OutOfRange));
                drop(r);
                mmio_ok = mm::free_frames() == frames_before && mm::reservation_count() == res_before;
            }
            Err(e) => crate::log_fatal!("pci: LAPIC 二次映射失败 {:?}", e),
        }
    }
    crate::log_info!(
        "pci: MMIO lapic={:#x} 与 apic 读数一致={} 边界检查生效={} 页框与保留不变={} frames={}→{}",
        lapic,
        cross_ok,
        bounds_ok,
        mmio_ok,
        frames_before,
        mm::free_frames()
    );
    // ㉑ 的收尾：**已知设备 ⇒ 已知类别**。这不是"我读出来什么就承认什么"——
    // 期望值来自 PCI 规范给这几台设备的类别，读回来必须一致；四台不同族的设备
    // 同时成立才叫钉住解码表，字节序差一位就会崩在其中某一台上。
    const PIN: [(&str, u16, u16, u8, u8); 6] = [
        ("Q35 宿主", 0x8086, 0x29C0, 0x06, 0x00),
        ("Q35 宿主桥的另一半(SIC)", 0x8086, 0x29C1, 0x08, 0x00),
        ("virtio-vga/STD VGA", 0x1234, 0x1111, 0x03, 0x00),
        ("e1000 网卡", 0x8086, 0x10D3, 0x02, 0x00),
        ("ICH9 AHCI", 0x8086, 0x2922, 0x01, 0x06),
        ("ICH9 SMBus", 0x8086, 0x2930, 0x0C, 0x05),
    ];
    let mut pinned = 0usize;
    let mut wrong = 0usize;
    let mut hit_names = 0usize;
    for (name, vend, dev_id, want_class, want_sub) in PIN.iter() {
        match (0..i.n).filter_map(pci::dev).find(|d| d.vendor == *vend && d.device == *dev_id) {
            Some(d) => {
                hit_names += 1;
                if d.class() == *want_class && d.subclass() == *want_sub {
                    pinned += 1;
                } else {
                    wrong += 1;
                    crate::log_fatal!(
                        "pci: 解码表对不上 {} cfg08={:#010x} 解出 class={:#x}/sub={:#x} 期望 {:#x}/{:#x}",
                        name, d.cfg08, d.class(), d.subclass(), want_class, want_sub
                    );
                }
            }
            None => crate::log_info!("pci: 跳过 {}（这台机器上没有）", name),
        }
    }
    crate::log_info!(
        "pci: class 解码表 命中{}台 / 钉住{}台 / 对不上{}台（少于 4 台就不算钉住）",
        hit_names, pinned, wrong
    );
    let decode_pinned = wrong == 0 && pinned >= 4 && first_class_lookup_ok(&pinned);
    // M5-b①：BAR 尺寸探测与命令寄存器。**这一步会临时改设备的 BAR**，所以判据的重点
    // 不是"读到了数"，而是"改完能复原，且复原出来的尺寸真的管得住访问边界"。
    let mut restore_ok = false;
    let mut sizing_ok = false;
    let mut sized_bounds_ok = false;
    let mut cmd_ok = false;
    let mut abar_size = 0u64;
    if let Some(hba) = pci::first_of_triple(0x01, 0x06, 0x01) {
        let (b, dv, f) = hba.bdf_str();
        let cmd_before = hba.cfg32(0x04);
        crate::log_info!(
            "pci: 存储控制器 {:04x}:{:02x}.{} progif={:#04x} cmd={:#06x} bar=[{:#010x},{:#010x},{:#010x},{:#010x},{:#010x},{:#010x}]",
            b,
            dv,
            f,
            hba.progif(),
            cmd_before,
            hba.cfg32(0x10),
            hba.cfg32(0x14),
            hba.cfg32(0x18),
            hba.cfg32(0x1c),
            hba.cfg32(0x20),
            hba.cfg32(0x24)
        );
        // progif 必须是 0x01（AHCI）才轮到 M5-b 往下走：0x00 是旧式 ATA、0x02 是兼容模式，
        // 按它们写代码等于拿错整张寄存器表。class/subclass 已由上面的解码表钉住，这里读回来再判一次。
        let is_ahci = hba.class() == 0x01 && hba.subclass() == 0x06 && hba.progif() == 0x01;
        let bar5_before = hba.mem_bar(5);
        let sized = hba.size_mem_bar(5);
        abar_size = sized.size;
        restore_ok = sized.restored;
        sizing_ok = is_ahci && sized.size != 0 && bar5_before.is_some();
        // 尺寸不是读来好看的：按它建区间，最后一格必须读得到、越过一格必须被拒
        if let (Some((pa, _64)), true) = (bar5_before, sizing_ok) {
            match hw::MmioRegion::map(pa & !0xFFF, abar_size as usize) {
                Ok(r) => {
                    sized_bounds_ok = r.read32(0).is_ok()
                        && r.read32((abar_size - 4) as usize).is_ok()
                        && matches!(r.read32(abar_size as usize), Err(hw::HwError::OutOfRange));
                    drop(r);
                }
                Err(e) => crate::log_fatal!("pci: ABAR {:#x} 映射失败 {:?}", pa, e),
            }
        }
        // MSE(bit1)+BME(bit2) 置位后必须**读回**成立。DMA 要的是 BME：只开 MSE 的现场是
        // "寄存器读得好好的、传输永远不完成"。
        let after = hba.enable_command(0b110);
        cmd_ok = after & 0b110 == 0b110;
        crate::log_info!(
            "pci: ABAR 取证 bar5={:?} 尺寸={:#x} 还原={} AHCI判据成立={} 尺寸管住边界={} cmd {:#06x}→{:#06x} MSE|BME={}",
            bar5_before.map(|(a, _)| a),
            abar_size,
            restore_ok,
            sizing_ok,
            sized_bounds_ok,
            cmd_before,
            after,
            cmd_ok
        );
    }
    let ok = root_bdf0
        && no_truncate
        && all_real
        && agree
        && mmio_ok
        && cross_ok
        && bounds_ok
        && decode_pinned
        && restore_ok
        && sizing_ok
        && sized_bounds_ok
        && cmd_ok;
    if !ok {
        crate::log_fatal!("pci: 判定不成立（上面两行是全部读数）");
    }
    ok
}
ktest!(KT_PCI, t_pci_config);

/// 解码表钉住之后，"按类别找回 AHCI"才算有依据。这一格现在同时读两条路：
/// 三件套（`first_of_triple`）与单按 class（`first_of_class`）——后者**只用来暴露风险**，
/// 不作依据（挂上 virtio-blk 之后它的结果是"扫描顺序里的第一台存储设备"，不是 AHCI）。
fn first_class_lookup_ok(pinned: &usize) -> bool {
    if *pinned < 4 {
        return false;
    }
    // 三件套必须找回 ICH9 AHCI，**不管 class 0x01 有几台**。多挂一块 virtio-blk 之后这条
    // 从"能找回"变成"能在两台里挑对"，判据变强而不是变松（`first_of_class` 那一台是谁
    // 由扫描顺序决定，所以它不能再当依据）
    let (tv, td, ok) = match pci::first_of_triple(0x01, 0x06, 0x01) {
        Some(d) => (d.vendor, d.device, d.vendor == 0x8086 && d.device == 0x2922),
        None => (0, 0, false),
    };
    crate::log_info!(
        "pci: class 0x01 共 {} 台；三件套 01/06/01 找回 vend={:#06x} dev={:#06x}；单按 class 找回 vend={:#06x}",
        pci::count_of_class(0x01),
        tv,
        td,
        pci::first_of_class(0x01).map(|d| d.vendor).unwrap_or(0)
    );
    ok
}

/// M5-g①：中断认领**之前**的现场取证。这一格不改任何路径、不写"已交付"，
/// 它只回答一个问题：这台 QEMU + OVMF 上，我们从哪条路认领得到中断。
///
/// 三个读数决定 M5-g② 的形状：
/// ① 固件有没有往配置空间写 Interrupt Line。写了 ⇒ INTx 只要编程那条 RTE 就能试；
///    没写 ⇒ pin↔GSI 的表只能从 ACPI `_PRT` 拿，而 `_PRT` 要 AML ⇒ **那是 M5b，不在今天**。
/// ② `ich9-ahci` 有没有 MSI 块。有 ⇒ 向量与目的地由我们自己写进设备，**不需要那张表**。
/// ③ virtio（vendor `0x1AF4`）是 MSI-X 还是 INTx，表在哪块 BAR 的什么偏移。
///
/// 四条结构自洽判据是给我自己的读数立的门禁（偏移/掩码/链读错位时它们必须红），
/// 不是对硬件的要求——硬件给什么数都照打，打不出来才算失败。
#[cfg(feature = "irq-probe")]
fn t_irq_probe() -> bool {
    let Some(info) = pci::info() else {
        crate::log_fatal!("irq: 枚举表是空的，取证没法做");
        return false;
    };
    // 逐台设备的读数先攒着，判据只看"我这台仪器自不自洽"
    let mut n_pin = 0usize;
    let mut n_line_none = 0usize;
    let mut n_msi = 0usize;
    let mut n_msix = 0usize;
    let mut n_broken = 0usize;
    let mut n_virtio_msix = 0usize;
    let mut size_ok = true;
    let mut align_ok = true;
    let mut distinct_ok = true;
    let mut hops_ok = true;
    let mut shown = 0usize;

    for i in 0..info.n {
        let Some(d) = pci::dev(i) else { continue };
        let c = d.irq_caps();
        let (bus, dev, func) = d.bdf_str();
        shown += 1;
        if c.pin != 0 {
            n_pin += 1;
            if c.line == 0 {
                n_line_none += 1;
            }
        }
        if c.msi.is_some() {
            n_msi += 1;
        }
        if c.msix.is_some() {
            n_msix += 1;
            if d.vendor == 0x1AF4 {
                n_virtio_msix += 1;
            }
        }
        if c.broken.is_some() {
            n_broken += 1;
        }
        // 判据 A/B/C/D：都是"我读错位就会红"的形状
        if let Some(x) = c.msix {
            // A 表大小字段是"条数 - 1"，加回来之后不可能是 0
            if x.table_size == 0 {
                size_ok = false;
            }
            // B 表/PBA 的偏移按规范以 16 字节为粒度（低 4 位是保留位 + BIR）
            if x.table_off & 0xF != 0 || x.pba_off & 0xF != 0 {
                align_ok = false;
            }
        }
        // C 同一台设备上 MSI 与 MSI-X 不可能共用一个偏移（id 匹配错了才会）
        if let (Some(m), Some(x)) = (c.msi, c.msix) {
            if m.off == x.off {
                distinct_ok = false;
            }
        }
        // D 链上跳的次数不会比数到的块数少
        let blocks = usize::from(c.msi.is_some()) + usize::from(c.msix.is_some());
        if blocks > usize::from(c.hops) {
            hops_ok = false;
        }
        crate::log_info!(
            "irq: 取证 {:02x}:{:02x}.{} vid={:#06x} class={:02x}/{:02x}/{:02x} pin={} line={:#04x} hops={} 断={} msi={} msix={}",
            bus, dev, func, d.vendor, d.class(), d.subclass(), d.progif(),
            c.pin, c.line, c.hops, c.broken.unwrap_or("无"),
            match c.msi { Some(m) => alloc::format!("@{:#04x} en={} mmc={} 64={} pvm={}", m.off as u32, u8::from(m.enabled), m.mmc, u8::from(m.sixtyfour), u8::from(m.per_vector)), None => alloc::string::String::from("无") },
            match c.msix { Some(x) => alloc::format!("@{:#04x} 表={} fm={} BIR={}/偏移={:#x}", x.off as u32, x.table_size, u8::from(x.function_mask), x.table_bir, x.table_off), None => alloc::string::String::from("无") },
        );
    }

    // 第二遍：每台 `pin != 0` 且 `line != 0` 的设备，把它那条 RTE 的原样读数解出来。
    // 为什么必须读而不是引用规范：触发模式（电平/边沿）与极性决定"先服务还是先 EOI"，
    // 而这两格本内核**从来没写过**（`init` 只写了向量与屏蔽位），所以"固件留下来的是什么"
    // 只有从 IOAPIC 读回来才知道。规范说 PCI INTx 是电平，那是设备引脚的性质，
    // 不等于这张表里那一位被编程成了什么——两者不一致时以读数为准，并把不一致打出来。
    let io = apic::state();
    let mut shared_vec = false;
    for i in 0..info.n {
        let Some(d) = pci::dev(i) else { continue };
        let c = d.irq_caps();
        if c.pin == 0 || c.line == 0 {
            continue;
        }
        let (bus, dev, func) = d.bdf_str();
        match &io {
            Some(st) if u32::from(c.line) < st.gsi_base => crate::log_info!(
                "irq: RTE {:02x}:{:02x}.{} gsi={:#04x} 低于本 APIC 的 GSI 基 {} ⇒ 这条线不归它管（多 APIC 平台，M5-g② 之前必须先解决）",
                bus, dev, func, c.line, st.gsi_base
            ),
            Some(st) if u32::from(c.line) - st.gsi_base >= st.irt_entries => crate::log_info!(
                "irq: RTE {:02x}:{:02x}.{} gsi={:#04x} 超出本 APIC 的 {} 条表项",
                bus, dev, func, c.line, st.irt_entries
            ),
            Some(st) => {
                let rte = (c.line as u32 - st.gsi_base) as u8;
                match apic::rte_raw(rte) {
                    Some((lo, hi)) => {
                        let vec = (lo & 0xFF) as usize;
                        if vec == st.timer_vector {
                            shared_vec = true;
                        }
                        crate::log_info!(
                            "irq: RTE {:02x}:{:02x}.{} gsi={:#04x} 编号={} lo={:#010x} 向量={:#04x} 屏蔽={} 触发={} 极性={} 投递={} hi={:#010x} 目的地={:#04x}",
                            bus, dev, func, c.line, rte, lo, vec,
                            (lo >> 16) & 1, (lo >> 15) & 1, (lo >> 13) & 1, (lo >> 8) & 7, hi, hi >> 24
                        );
                    }
                    None => crate::log_info!("irq: RTE {:02x}:{:02x}.{} gsi={:#04x} 读不回来", bus, dev, func, c.line),
                }
            }
            None => crate::log_fatal!("irq: APIC 状态还没建起来，RTE 这一遍没法做"),
        }
    }

    // AHCI 那台（M5-g② 的第一颗候选）单独点名，读数决定走 MSI 还是 INTx
    let hba = pci::first_of_triple(0x01, 0x06, 0x01);
    let hba_found = hba.is_some();
    let hba_caps = hba.map(|d| d.irq_caps());
    // 定时器那条 RTE 的原样读数：触发模式/极性**今天没人写过它们**，所以"固件留的是什么"
    // 只能读回来。后面 EOI 与重发的规矩要建在这个数上，不是建在"规范说电平"上。
    let timer_rte = apic::state().and_then(|st| apic::rte_raw(st.timer_rte).map(|v| (v, st.timer_rte, st.timer_gsi, st.timer_vector)));

    let ok = size_ok && align_ok && distinct_ok && hops_ok && hba_found;
    crate::log_info!(
        "irq: 取证判据 台数={} 有pin={} 有pin而line为0={} MSI={} MSI-X={} 链断={} virtio有MSIX={} 仪器自洽={}/{}/{}/{} AHCI={} AHCI的msi={} AHCI的msix={} AHCI的pin={} 有设备线与定时器共用同一向量={}",
        shown, n_pin, n_line_none, n_msi, n_msix, n_broken, n_virtio_msix,
        size_ok, align_ok, distinct_ok, hops_ok,
        hba_found,
        hba_caps.map_or(false, |c| c.msi.is_some()),
        hba_caps.map_or(false, |c| c.msix.is_some()),
        hba_caps.map_or(0, |c| c.pin),
        shared_vec,
    );
    match timer_rte {
        Some(((lo, hi), rte, gsi, want_vec)) => crate::log_info!(
            "irq: 取证 RTE gsi={} 编号={} 表项={} gsi基={:#x} lo={:#010x} hi={:#010x} 解码向量={:#04x} 与内核写的一致={} 屏蔽={} 触发={} 极性={} 投递模式={} 目的地={:#04x}",
            gsi, rte, io.as_ref().map_or(0, |s| s.irt_entries), io.as_ref().map_or(0, |s| s.gsi_base),
            lo, hi, lo & 0xFF, (lo as usize & 0xFF) == want_vec,
            (lo >> 16) & 1, (lo >> 15) & 1, (lo >> 13) & 1, (lo >> 8) & 7, hi >> 24
        ),
        None => crate::log_fatal!("irq: 定时器 RTE 读不回来（IOAPIC 没映射上或编号越界）⇒ 认领那一步的界检查没有依据"),
    }
    crate::log_info!(
        "irq: 已用向量 定时器={:#x} 每核定时器={:#x} shootdown={:#x} 杂凑={:#x} 外部向量区间={:#x}..{:#x}；认领表=还没做（这一格只取证）",
        trap::VEC_IRQ_BASE, trap::VEC_CPU_TIMER, trap::VEC_SHOOTDOWN, trap::VEC_SPURIOUS,
        trap::VEC_IRQ_BASE, trap::VEC_IRQ_LAST
    );
    if !ok {
        crate::log_fatal!("irq: 取证判据不成立（上面每台设备一行读数）");
    }
    ok
}
#[cfg(feature = "irq-probe")]
ktest!(KT_IRQ_PROBE, t_irq_probe);

/// M5-b②：认领 AHCI 主机控制器并枚举端口（到"认得出哪一口挂着盘"为止）。
///
/// 判据的形状是"**位写得进去、也经得起复位清；基址读回来就是我们写的那两个数**"：
/// 1 `GHC.AE` 读回成立，`GHC.HR` 在有界窗口内自己清零。
/// 2 端口 0 的 `PxCMD` 收得住 `FRE`，`HR` 之后又回到复位值 0——这一条同时验住 GHC 的
///   偏移、HR 的位、端口块基址 `0x100`、`PxCMD` 的偏移、`FRE` 的位（五件事一次过）。
/// 3 `PI` 位图与 `CAP.NP+1` 必须数到同一个端口数：两个独立字段互证。
/// 4 `VS` 主版本号 ≥ 1：端口块基址 `0x100` 只对 AHCI 1.0 及以后成立。
/// 5 每一口的 `PxCLB`/`PxFB` 读回来等于写进去的数（对齐保留位是只读 0，所以这一条
///   同时验住偏移、基址和那张表的对齐）。
/// 6 `FRE→FR`、`ST→CR` 每口都跟上：任一位写错就等不到，不可能假绿。
/// 7 认得出在位的 SATA 磁盘：`det=0b0011` 且 `PxSIG=0x00000101`，而设备写来的那条 FIS
///   的类型字节必须是 D2H（`0x34`）。
/// 8 页框账对得上：`free_frames` 少掉的数必须等于"环形结构 4 帧 + 新建页表页"，
///   而资源台账里 `MOD_AHCI` 的存活帧数必须报同一个 4（§6.7 那本账在真设备上也要平）。
fn t_ahci_claim() -> bool {
    let Some(dev) = pci::first_of_triple(0x01, 0x06, 0x01) else {
        crate::log_fatal!("ahci: 枚举表里没有 SATA-AHCI 那台（PCI 那条用例先红了）");
        return false;
    };
    let bar_before = dev.mem_bar(5);
    // 先幂等地确保认领已完成，再量"这一次调用本身"动了什么：`.ktests` 段的顺序不跟着
    // 源码顺序走（实测），所以"谁做第一次认领"不能写死在判据里
    let _ = ahci::init();
    let frames_before = mm::free_frames();
    let pt_before = mm::counters().page_table_pages;
    let live_before = resource::live_of(ahci::MOD_AHCI);
    let i = match ahci::init() {
        Ok(i) => i,
        Err(e) => {
            crate::log_fatal!("ahci: 认领失败 {:?}", e);
            return false;
        }
    };
    let e = match ahci::enumerate() {
        Ok(e) => e,
        Err(err) => {
            crate::log_fatal!("ahci: 端口枚举失败 {:?}", err);
            return false;
        }
    };
    let frames_used = frames_before.saturating_sub(mm::free_frames());
    let pt_delta = mm::counters().page_table_pages.saturating_sub(pt_before);
    let live_now = resource::live_of(ahci::MOD_AHCI);
    let ghc_now = ahci::global(ahci::REG_GHC).unwrap_or(0xFFFF_FFFF);
    let pi_now = ahci::global(ahci::REG_PI).unwrap_or(0xFFFF_FFFF);
    let ae_ok = ghc_now & ahci::REG_GHC_AE != 0 && ghc_now & ahci::REG_GHC_HR == 0;
    // 只咬"写进去的那一位被复位清掉了"：`HR` 之后 `PxCMD` 实测读回 0x6（SUD|POD 亮），
    // 那是 QEMU 给挂着设备的端口置的位，不是我写的——要求整寄存器归 0 是我多要了一格
    let scope_ok = i.cmd_fre_written & ahci::CMD_FRE != 0 && i.cmd_after_hr & ahci::CMD_FRE == 0;
    let ports_agree =
        i.ports == i.cap_ports && u8::try_from(pi_now.count_ones()) == Ok(i.ports) && pi_now == i.pi;
    let version_ok = (i.vs >> 16) >= 1;
    let space_ok = ahci::PORTS_BASE as u64 + ahci::PORT_STRIDE as u64 * u64::from(i.ports) <= i.size;
    let started_all = if boot_guard::optional_devices_allowed() {
        e.n == usize::from(i.ports)
    } else {
        // 安全模式：只该起到第一块有盘的口为止
        e.n == 1 && e.n_disks >= 1
    };
    let handshakes = e.ports[..e.n].iter().all(|p| p.fr && p.cr);
    let tables_ok = e.ports[..e.n].iter().all(|p| {
        p.clb == i.ring_pa as u32
            && p.fb == (i.ring_pa + ahci::OFF_RXFIS + ahci::RX_BYTES * u64::from(p.num)) as u32
    });
    let disk = e.disk.map(|n| e.ports[usize::from(n)].num);
    let cfg_intact = dev.mem_bar(5) == bar_before && dev.cfg32(0x04) & 0b110 == 0b110;
    // 第二次认领不许再分配：`live_before` 已经是一份环形结构的量
    let accounted =
        frames_used == pt_delta && live_before == ahci::RING_PAGES && live_now == ahci::RING_PAGES;
    crate::log_info!(
        "ahci: 认领 {:04x}:{:02x}.{} abar={:#x} 尺寸={:#x} cap={:#010x} vs={:#010x} 槽={} 端口={}(PI)/{}(CAP) ghc {:#010x}→{:#010x}→{:#010x}→{:#010x} cap2={:#010x} 复位后sig={:#010x} clb={:#010x} SAM={} S64A={}",
        i.bdf >> 16,
        (i.bdf >> 11) & 31,
        (i.bdf >> 8) & 7,
        i.abar,
        i.size,
        i.cap,
        i.vs,
        i.slots,
        i.pi.count_ones(),
        i.cap_ports,
        i.ghc_before,
        i.ghc_ae,
        i.ghc_hr,
        i.ghc_after,
        i.cap2,
        i.sig_after_hr,
        i.clb_after_hr,
        i.sam,
        i.s64a
    );
    for p in e.ports[..e.n].iter() {
        crate::log_info!(
            "ahci: 口{} cmd={:#010x} clb={:#010x} fb={:#010x} is={:#010x} tfd={:#06x} sig={:#010x} ssts={:#010x} d2h={:#04x}",
            p.num,
            p.cmd,
            p.clb,
            p.fb,
            p.is,
            p.tfd,
            p.sig,
            p.ssts,
            p.d2h_type
        );
    }
    crate::log_info!(
        "ahci: 判据 AE且HR清={} 复位作用域={} 端口数互证={} 版本>=1={} 区域够={} 口起齐={} FR|CR={} 表读回={} 磁盘口={:?} 无全1={} 配置没坏={} 本次页框用掉={} 页表新增={} 台账存活={}+={} 本次没多分配={}",
        ae_ok,
        scope_ok,
        ports_agree,
        version_ok,
        space_ok,
        started_all,
        handshakes,
        tables_ok,
        disk,
        i.reads_ff == 0,
        cfg_intact,
        frames_used,
        pt_delta,
        live_before,
        live_now,
        accounted
    );
    let ok = ae_ok
        && scope_ok
        && ports_agree
        && version_ok
        && space_ok
        && started_all
        && handshakes
        && tables_ok
        && disk.is_some()
        && i.reads_ff == 0
        && cfg_intact
        && accounted;
    if !ok {
        crate::log_fatal!("ahci: 判定不成立（上面几行是全部读数）");
    }
    ok
}
ktest!(KT_AHCI, t_ahci_claim);

/// M5-b③：第一条真 DMA 读。判据的落点是**内容**，不是寄存器。
///
/// 1 LBA 0：扇区末尾两字节必须是 MBR 签名 `0x55AA`。
/// 2 LBA 1：前 8 字节必须是 `EFI PART`（GPT 头）。这两条都是人眼能核的见证。
/// 3 两次读的哈希**必须不同**：LBA 那几格要是没起作用，两次就是同一个块，而
///   "同一个块读两次都一样"看着比现在还绿。
/// 4 设备自报的 PRDBC 等于请求字节数，而且数据缓冲里一个哨兵 `0xEE` 都不剩
///   （"没搬"与"搬回一堆 0"必须分得开，见 `ahci::fill` 那段注释）。
/// 5 两台仪器一致：端口侧 `PxTFD` 与接收区那条 D2H 的状态必须相等；签名也一样。
/// 6 哈希本身由 `tools/aurora.py` 与宿主机上的镜像对账——那是**另一个进程里的仪器**，
///   所以这条判据不受"驱动自己说自己对"污染。
fn t_ahci_disk() -> bool {
    if ahci::info().is_none() {
        let _ = ahci::init();
    }
    let e = match ahci::enumerate() {
        Ok(e) => e,
        Err(err) => {
            crate::log_fatal!("ahci: 读块之前枚举端口失败 {:?}", err);
            return false;
        }
    };
    let Some(disk) = e.disk else {
        crate::log_fatal!("ahci: 没有端口报在位的 SATA 磁盘（上面每口的读数就是证据）");
        return false;
    };
    let r0 = match ahci::read_lba(disk, 0, 1) {
        Ok(r) => r,
        Err(err) => {
            crate::log_fatal!("ahci: 读 LBA0 失败 {:?}", err);
            return false;
        }
    };
    let tail0 = ahci::mbr_tail().unwrap_or([0; 2]);
    // 保护 MBR 的分区表项：引导标志（0x1BE）必须是 0，类型（0x1C2）必须是 `0xEE`（GPT 的要求）。
    // 偏移按 GPT 的固定布局给（表项从 0x1BE 起、类型是表项内第 4 字节）。宿主机上量回来的
    // 整个扇区里 `0xEE` **只出现在 0x1C2 这一格** —— 也就是前面"哨兵剩 1"的那一格。
    // 位置敏感的见证要用绝对偏移，而且**必须在下一次读覆盖缓冲之前取**（第一版取晚了，
    // 量到的是 LBA1 的 GPT 头，读出来 0x00 就报假失败）。
    let pmbr_ok = ahci::data_at(0x1BE) == Ok(0x00) && ahci::data_at(0x1C2) == Ok(0xEE);
    let r1 = match ahci::read_lba(disk, 1, 1) {
        Ok(r) => r,
        Err(err) => {
            crate::log_fatal!("ahci: 读 LBA1 失败 {:?}", err);
            return false;
        }
    };
    let head1 = ahci::data_head(16).unwrap_or([0; 16]);
    // M5-c：**跨 255 扇区边界**的一次读（257 × 512 = 131584 字节）。
    // 这条是"扇区数高字节"唯一的现场判据：单扇区的读对计数放错位置不敏感
    // （`count=0` 时 QEMU 用 PRD 的字节数封顶，两边都读成 1 个扇区），而这次
    // PRD 与 count 必须互相对上，否则 `ahci_populate_sglist` 直接 `-1` 把命令丢掉 ⇒ 当场红。
    let big = match ahci::read_lba(disk, 0, 257) {
        Ok(r) => r,
        Err(err) => {
            crate::log_fatal!("ahci: 读 257 个扇区失败 {:?}", err);
            return false;
        }
    };
    // 缓冲现在装着 LBA 0..257：**开头那一扇区必须还是同一条 MBR**（证明长传输的起点没错），
    // 而整段哈希必须与单扇区那次不同（证明它真的搬了 257 个扇区而不是 1 个）
    let big_prefix_ok = ahci::data_at(0x1C2) == Ok(0xEE) && ahci::data_at(0x1FF) == Ok(0xAA);
    let big_wider = big.hash != r0.hash;
    // **同长度对读**：长读的最后一个扇区，必须等于单独读那一个扇区的结果。
    // 这条不需要阈值，也不需要"内容该是什么"的先验：负样本把扇区数高字节放错时，
    // QEMU 只搬第一个扇区就报完成，长读的尾巴还是哨兵 ⇒ 这里当场不相等（内核里就红）。
    let mut big_tail = [0u8; 512];
    let mut one_sector = [0u8; 512];
    let mut r_last = None;
    if ahci::copy_out(big.want as u64 - 512, &mut big_tail).is_ok() {
        if let Ok(r) = ahci::read_lba(disk, 256, 1) {
            if ahci::copy_out(0, &mut one_sector).is_ok() {
                r_last = Some(r);
            }
        }
    }
    let tail_same = r_last.is_some() && big_tail == one_sector && big_tail != [0xEEu8; 512];
    if let Some(r) = &r_last {
        crate::log_info!(
            "ahci: 读 lba=256 计数=1 端口={} 请求={}字节 状态={:#04x} 尾扇区一致={} 哈希={:#018x}",
            r.port,
            r.want,
            r.status,
            tail_same,
            r.hash
        );
    } else {
        crate::log_fatal!("ahci: 长读收尾对读没做成（tail_same=false 的成因是这条读不到）");
    }
    crate::log_info!(
        "ahci: 读 lba=0 计数=257 端口={} 请求={}字节 状态={:#04x} 前缀同一段={} 比单扇区长={} 哈希={:#018x}",
        big.port,
        big.want,
        big.status,
        big_prefix_ok,
        big_wider,
        big.hash
    );
    // 负样本：只改**报出去的标签**，不改读的东西。注入下内核自判的每一格都还成立，
    // 必须让宿主机那台仪器来叫（`tools/aurora.py` 的 `check_disk_content`）
    let printed1 = if cfg!(feature = "fault-ahci-lba") { 0 } else { 1 };
    crate::log_info!(
        "ahci: 读 lba=0 计数=1 端口={} 表头DW1={:#010x} 请求={}字节 状态={:#04x} 签名={:#010x}/{:#010x} 哨兵剩={} 哈希={:#018x} 尾两字节={:#04x}{:#04x}",
        r0.port,
        r0.dw1,
        r0.want,
        r0.status,
        r0.sig_port,
        r0.sig_d2h,
        r0.untouched,
        r0.hash,
        tail0[0],
        tail0[1]
    );
    crate::log_info!(
        "ahci: 读 lba={} 计数=1 端口={} 表头DW1={:#010x} 请求={}字节 状态={:#04x} 签名={:#010x}/{:#010x} 哨兵剩={} 哈希={:#018x} 头8字节={}{}{}{}{}{}{}{}",
        printed1,
        r1.port,
        r1.dw1,
        r1.want,
        r1.status,
        r1.sig_port,
        r1.sig_d2h,
        r1.untouched,
        r1.hash,
        head1[0] as char,
        head1[1] as char,
        head1[2] as char,
        head1[3] as char,
        head1[4] as char,
        head1[5] as char,
        head1[6] as char,
        head1[7] as char
    );
    let mbr_ok = tail0 == [0x55, 0xAA];
    let gpt_ok = &head1[0..8] == b"EFI PART";
    let distinct = r0.hash != r1.hash;
    // "搬到位"判在内容上，不判在设备自报的字节数上：本机 QEMU 把已搬字节数报在表头
    // DW1 的低 16 位，而规范的 PRDBC 在 bits 31:16（两者都对不上"判据"这个词）。
    let content_ok = mbr_ok && gpt_ok && distinct && pmbr_ok;
    let instruments = r0.status == r1.status
        && r0.sig_port == ahci::SIG_SATA_DISK
        && r0.sig_d2h == r0.sig_port
        && r0.d2h_type == ahci::FIS_TYPE_D2H;
    let ok = content_ok && instruments && big_prefix_ok && big_wider && tail_same;
    if !ok {
        crate::log_fatal!(
            "ahci: 内容判据不成立 MBR={} 保护类型0xEE={} GPT={} 两次不同={} 两台仪器={} 长读前缀={} 长读更宽={} 尾扇区一致={}",
            mbr_ok,
            pmbr_ok,
            gpt_ok,
            distinct,
            instruments,
            big_prefix_ok,
            big_wider,
            tail_same
        );
    }
    ok
}
ktest!(KT_AHCI_DISK, t_ahci_disk);

#[cfg(feature = "ahci-scratch")]
/// M5-c②：把 LBA 的**高位三格**从"只有出处"变成"有判据"。
///
/// 需要第二块盘（`tools/aurora.py` 造 130 GiB 的 qcow2 挂在口 2，并在 `LBA = 2^28` 那一格写
/// 512 字节的 `0xA5`）。为什么只有这条路：这条 64 MiB 的引导盘最大 LBA 是 `0x1FFFF` ⇒
/// 字节 8/9/10 恒为 0，写错也没人看得见（我第一版就把字节 8 按 `>>32` 写过）。
/// 判据是**配方对账**，不是驱动自证：
/// 1 高 LBA 那一格必须 512 个字节全是 `0xA5`（不等于它的个数 = 0）；
/// 2 同一块盘的 LBA 0 必须全是 0 —— 控制组：证明这两次读读的是**不同**的地方；
/// 3 引导盘（LBA 1 写着 `EFI PART` 的那一口）不许被当成第二块盘；
/// 4 两次的哈希必须不同。
/// 负样本 `fault-ahci-highlba` 把字节 8 改回 `>>32` ⇒ 设备读到 LBA 0 的全零扇区 ⇒ 必须红。
fn t_ahci_high_lba() -> bool {
    let e = match ahci::enumerate() {
        Ok(e) => e,
        Err(err) => {
            crate::log_fatal!("high: 枚举失败 {:?}", err);
            return false;
        }
    };
    if e.n_disks < 2 {
        crate::log_fatal!("high: 带 ahci-scratch 的构建只认到 {} 块在位的盘，第二块没挂上", e.n_disks);
        return false;
    }
    // 引导盘的身份证是内容，不是口号：它的 LBA 1 写着 `EFI PART`
    let mut boot = None;
    let mut scratch = None;
    for i in 0..e.n_disks {
        let p = e.disks[i];
        if let Err(err) = ahci::read_lba(p, 1, 1) {
            crate::log_fatal!("high: 口{} 读 LBA1 失败 {:?}", p, err);
            return false;
        }
        let is_gpt = ahci::data_head(8).map(|h| &h[0..8] == b"EFI PART").unwrap_or(false);
        if is_gpt {
            if boot.is_none() {
                boot = Some(p);
            }
        } else if scratch.is_none() {
            scratch = Some(p);
        }
    }
    let Some(sc) = scratch else {
        crate::log_fatal!("high: 没找到第二块盘（引导盘口={:?}）", boot);
        return false;
    };
    let hi = match ahci::read_lba(sc, 1 << 28, 1) {
        Ok(r) => r,
        Err(err) => {
            crate::log_fatal!("high: 读 LBA 2^28 失败 {:?}", err);
            return false;
        }
    };
    let hi_bad = ahci::data_diff_count(0xA5, 512).unwrap_or(usize::MAX);
    let lo = match ahci::read_lba(sc, 0, 1) {
        Ok(r) => r,
        Err(err) => {
            crate::log_fatal!("high: 读第二块盘的 LBA 0 失败 {:?}", err);
            return false;
        }
    };
    let lo_bad = ahci::data_diff_count(0x00, 512).unwrap_or(usize::MAX);
    crate::log_info!(
        "ahci: 高LBA 第二块盘口={} 引导盘口={:?} LBA2^28 里非A5的字节={} 哈希={:#018x}",
        sc,
        boot,
        hi_bad,
        hi.hash
    );
    crate::log_info!(
        "ahci: 高LBA 控制组 LBA0 里非零的字节={} 哈希={:#018x} 两次不同={}",
        lo_bad,
        lo.hash,
        hi.hash != lo.hash
    );
    let ok = hi_bad == 0 && lo_bad == 0 && hi.hash != lo.hash && boot.is_some() && boot != Some(sc);
    if !ok {
        crate::log_fatal!("high: 高位判据不成立（上面两行是全部读数）");
    }
    ok
}
#[cfg(feature = "ahci-scratch")]
ktest!(KT_AHCI_HIGH_LBA, t_ahci_high_lba);

#[cfg(feature = "ahci-scratch")]
/// M5-c③：写方向。判据全部落在**内容**上，不看"命令有没有完成"。
///
/// 只允许写第二块盘（scratch）：引导盘是这套测试自己的产物，写坏一次就得重造镜像才能复现，
/// 那种"顺手把被测对象改了"的做法在这里不接受。目标偏移选 LBA 4096 起 8 个扇区——
/// 离高 LBA 图案那一格（`2^28`）和读用例碰过的区间都远，互不污染。
///
/// 四格判据（缺一格就有一种错法能混过去）：
/// 1 **写之前的哈希 ≠ 写之后的哈希**：什么都不写、或写被静默丢掉，这一格先拦住；
/// 2 回读内容与 `pattern_byte(LBA, 序号)` **逐字节相同**：图案与 LBA 绑定，所以
///   "写到别的偏移去了"和"只写了第一个扇区"都过不了；
/// 3 紧接着在**另一个 LBA** 再写一段，然后回读第一段：图案必须仍然逐字节相同。
///   这一条才有咬合——"扇区数没生效、只搬了 1 个扇区"其实已经被第 2 条抓住了
///   （其余 7 个扇区还是旧内容，逐字节比对当场就不等），而我第一版在这里写的是
///   "第 1 与第 8 个扇区的首字节必须不同"，那是条**恒不成立也不报错的错判据**：
///   图案按 256 字节取模，两个扇区的首字节天然相同（实测两条都读出 `0x3c`）。
///   换成不覆盖判据：第二次的写如果落到了第一段上（地址没生效），第 2 条就会红；
/// 4 读回的哈希由 `tools/aurora.py` 与宿主机对账（QEMU 退出后用 `qemu-io` 读那个偏移）——
///   内核这一侧的 2、3 两条都在同一个进程里算，只有这一条是另一台仪器。
fn t_ahci_write() -> bool {
    let e = match ahci::enumerate() {
        Ok(e) => e,
        Err(err) => {
            crate::log_fatal!("write: 枚举失败 {:?}", err);
            return false;
        }
    };
    let mut boot = None;
    let mut scratch = None;
    for i in 0..e.n_disks {
        let p = e.disks[i];
        if let Err(err) = ahci::read_lba(p, 1, 1) {
            crate::log_warn!("write: 口{} 读 LBA1 失败 {:?}，这块不参与分类", p, err);
            continue;
        }
        let is_gpt = ahci::data_head(8).map(|h| &h[0..8] == b"EFI PART").unwrap_or(false);
        crate::log_info!("write: 候选口={} GPT={}", p, is_gpt);
        if is_gpt && boot.is_none() {
            boot = Some(p);
        } else if !is_gpt && scratch.is_none() {
            scratch = Some(p);
        }
    }
    let Some(sc) = scratch else {
        crate::log_fatal!(
            "write: 没找到可写的那块盘（引导盘口={:?} 起口数={} 枚举到的盘数={}）",
            boot,
            e.n,
            e.n_disks
        );
        return false;
    };
    const TARGET_LBA: u64 = 4096;
    const SECS: u16 = 8;
    let before = match ahci::read_lba(sc, TARGET_LBA, SECS) {
        Ok(r) => r.hash,
        Err(err) => {
            crate::log_fatal!("write: 写之前读 LBA{} 失败 {:?}", TARGET_LBA, err);
            return false;
        }
    };
    match ahci::write_lba(sc, TARGET_LBA, SECS) {
        Ok(r) => crate::log_info!(
            "write: 写完 口={} 状态={:#04x} 表头DW1={:#010x} 缓冲哈希={:#018x}",
            r.port,
            r.status,
            r.dw1,
            r.hash
        ),
        Err(err) => {
            crate::log_fatal!("write: 写 LBA{} 失败 {:?}", TARGET_LBA, err);
            return false;
        }
    }
    let back = match ahci::read_lba(sc, TARGET_LBA, SECS) {
        Ok(r) => r,
        Err(err) => {
            crate::log_fatal!("write: 回读 LBA{} 失败 {:?}", TARGET_LBA, err);
            return false;
        }
    };
    // 逐字节比对：图案由同一个式子供两头用（这里 + 宿主机的 `qemu-io` 那边）
    let mut mismatches = 0usize;
    for i in 0..(u64::from(SECS) * ahci::SECTOR) {
        let want = ahci::pattern_byte(TARGET_LBA, i);
        match ahci::data_at(i as usize) {
            Ok(got) => {
                if got != want {
                    mismatches += 1;
                }
            }
            Err(_) => mismatches += 1,
        }
    }
    let changed = back.hash != before;
    let exact = mismatches == 0;
    // 判据 3：在**下一段** LBA 上再写一次，然后回读第一段——还是原来的图案才算"地址真的生效"。
    // 第一版这里比的是"第 1 扇区与第 8 扇区的首字节不同"，那是条错的恒等式（图案周期 256 字节）
    let mut clobbered = 0usize;
    if ahci::write_lba(sc, TARGET_LBA + u64::from(SECS), SECS).is_ok() {
        if let Ok(r2) = ahci::read_lba(sc, TARGET_LBA, SECS) {
            for i in 0..(u64::from(SECS) * ahci::SECTOR) {
                if ahci::data_at(i as usize) != Ok(ahci::pattern_byte(TARGET_LBA, i)) {
                    clobbered += 1;
                }
            }
            let _ = r2;
        }
    }
    let no_clobber = clobbered == 0;
    crate::log_info!(
        "ahci: 写 lba={} 计数={} 端口={} 前哈希={:#018x} 后哈希={:#018x} 图案不一致={} 第二段没盖住第一段={} 被盖字节={}",
        TARGET_LBA,
        SECS,
        sc,
        before,
        back.hash,
        mismatches,
        no_clobber,
        clobbered
    );
    let ok = changed && exact && no_clobber && boot.is_some() && boot != Some(sc);
    if !ok {
        crate::log_fatal!(
            "write: 判据不成立 改了={} 逐字节={} 第二段没盖住第一段={}",
            changed,
            exact,
            no_clobber
        );
    }
    ok
}
#[cfg(feature = "ahci-scratch")]
ktest!(KT_AHCI_WRITE, t_ahci_write);

#[cfg(feature = "ahci-scratch")]
/// M5-d：§8.2 的"驱动故障可重置或隔离"，按手册那张状态机走。
///
/// 四格各挡一种错法（顺序就是函数体的顺序）：
/// 1 **干净错误不许触发 reset**：注入非法命令码，设备以 `ERR` 正常完成。
///   这一格同时给注入本身立判据（必须是 `BadCompletion` 且计数 +1），
///   否则"没抖控制器"会因为"根本没出错"而假绿。
/// 2 **卡住类错误必须走 `Resetting` 并恢复**：清掉 `ST` ⇒ 命令没人接走 ⇒ `PxCI`
///   恒为 1 ⇒ 超时；恢复里把端口重新起起来 ⇒ 下一条命令必须读回原来的内容。
/// 3 **修不好就必须隔离**：让 `start_port` 对这个口必然失败，重试到预算 ⇒
///   `Quarantined`，之后的命令**没下发就返回**——判据是 `resets` 不再增长，
///   不是"返回了 Err"（真又试一次也返回 Err，两种情形必须分得开）。
/// 4 **隔离的粒度是端口，不是驱动**：受害口的重置计数恰好停在预算上、引导口恒为 0，
///   且引导盘照常读出 `EFI PART`。
///   这一格才是"一个错误导致不了系统崩溃"的那条硬要求在本机的形状。
fn t_ahci_recovery() -> bool {
    let e = match ahci::enumerate() {
        Ok(e) => e,
        Err(err) => {
            crate::log_fatal!("recover: 枚举失败 {:?}", err);
            return false;
        }
    };
    let mut boot = None;
    let mut victim = None;
    for i in 0..e.n_disks {
        let p = e.disks[i];
        if ahci::read_lba(p, 1, 1).is_err() {
            continue;
        }
        let is_gpt = ahci::data_head(8).map(|h| &h[0..8] == b"EFI PART").unwrap_or(false);
        if is_gpt && boot.is_none() {
            boot = Some(p);
        } else if !is_gpt && victim.is_none() {
            victim = Some(p);
        }
    }
    let (Some(bt), Some(vi)) = (boot, victim) else {
        crate::log_fatal!("recover: 需要两块盘（引导盘口={:?} 受害口={:?}）", boot, victim);
        return false;
    };
    let Ok(baseline) = ahci::read_lba(vi, 4096, 8).map(|r| r.hash) else {
        crate::log_fatal!("recover: 受害口的基线读失败");
        return false;
    };
    let st0 = ahci::stats();
    // "整段都是自己的"：内容对得上基线，**且设备自报的字节数等于请求的字节数**。
    // 后半条不是装饰：恢复路径上端口里可能还挂着上一条没答完的命令，它完成后
    // 会把 DMA 和回执留在接收区里，只看哈希就会把"读到旧命令的回执"读成"恢复了"
    // （实测出现过：请求 8 个扇区、`PRDBC` 只有 512 字节，哈希因此不同）。
    let got_whole = |r: &Result<ahci::Xfer, ahci::AhciError>| match r {
        Ok(x) => x.hash == baseline && x.dw1 == x.want,
        Err(_) => false,
    };

    // 1 干净错误：非法命令码。设备以 READY|ERR 完成、命令位照样落下，所以这才是
    // "检测到了但不该抖控制器"那一格的形状（越界读在这台设备上根本不算错，见 BACKLOG ㉞）
    ahci::set_op_override(0xFF);
    let bad_op = ahci::read_lba(vi, 4096, 1);
    ahci::set_op_override(0);
    let s1 = ahci::stats();
    let clean_is_err = matches!(bad_op, Err(ahci::AhciError::BadCompletion { .. }));
    let clean_no_reset =
        clean_is_err && s1.resets == st0.resets && s1.clean_errors == st0.clean_errors + 1;
    let clean_read = ahci::read_lba(vi, 4096, 8);
    let clean_usable = got_whole(&clean_read);

    // 2 卡住 → `Resetting` → 恢复：关掉引擎，发出去的命令没人接
    let _ = ahci::wedge_port(vi);
    let stuck = ahci::read_lba(vi, 4096, 1);
    let s2 = ahci::stats();
    let stuck_is_timeout = matches!(stuck, Err(ahci::AhciError::CmdTimeout));
    let tried_reset =
        stuck_is_timeout && s2.resets == s1.resets + 1 && ahci::state(vi) == ahci::State::Running;
    let heal_read = ahci::read_lba(vi, 4096, 8);
    let healed = tried_reset && got_whole(&heal_read);
    // 恢复结束时端口里挂着几条命令。**只打印，不进判据**：实测把 `start_port` 里的
    // 排空整段关掉，这一格照样读到 0（旧命令在拉起 `ST` 那一刻同步答完了），
    // 也就是说它分辨不了"排空有没有发生"。真在量这件事的是上面 `healed` 的整段回执。
    let drained = ahci::pending_cmds(vi) == Ok(0);

    // 3 修不好 → 隔离：让恢复本身必然失败，重试到预算
    ahci::inject_dead_port(vi);
    let mut quarantined = false;
    let mut resets_at = 0u32;
    let mut tries = 0u32;
    for _ in 0..(ahci::RETRY_BUDGET + 2) {
        tries += 1;
        let _ = ahci::wedge_port(vi);
        let _ = ahci::read_lba(vi, 4096, 1);
        if ahci::state(vi) == ahci::State::Quarantined {
            quarantined = true;
            resets_at = ahci::stats().resets;
            break;
        }
    }
    // 隔离之后再发一条：必须"没下发就返回"，于是 `resets` 一格都不该再动
    let post = ahci::read_lba(vi, 4096, 1);
    let s3 = ahci::stats();
    let fails_fast = quarantined
        && matches!(post, Err(ahci::AhciError::Quarantined))
        && s3.resets == resets_at
        && s3.quarantines == st0.quarantines + 1
        // 预算是按口累计的：停在 RETRY_BUDGET 说明这一口自己试够了次数
        && ahci::resets_of(vi) == ahci::RETRY_BUDGET;

    // `.ktests` 的顺序由链接器决定，隔离态不能留给后面的用例（真机上它是终态）
    ahci::revive_port();
    let rel = ahci::release_quarantine(vi);
    let released = rel.is_ok();
    let after = ahci::read_lba(vi, 4096, 8);
    let usable_after_release = released && got_whole(&after);

    // 4 粒度：另一个端口必须照常，而且一次重置都没被牵连
    let boot_head = ahci::read_lba(bt, 1, 1).and_then(|_| ahci::data_head(8));
    let boot_ok =
        boot_head.map(|h| &h[0..8] == b"EFI PART").unwrap_or(false) && ahci::resets_of(bt) == 0;
    crate::log_info!(
        "recover: 干净错误={}(状态={:#04x}) 没抖控制器={} 之后照常读={} 卡住={} 走了重置={} 重置后恢复={} 恢复后排空={}",
        clean_is_err,
        match bad_op {
            Err(ahci::AhciError::BadCompletion { status, .. }) => status,
            _ => 0
        },
        clean_no_reset,
        clean_usable,
        stuck_is_timeout,
        tried_reset,
        healed,
        drained
    );
    crate::log_info!(
        "recover: 已隔离={}(第{}次命令) 隔离后快速失败且不再碰设备={} 撤销隔离后能用={} 引导盘照常={} 计数 全局resets={} 受害口resets={} 引导口resets={} 隔离数={} 干净错误={} 预算={} 被吞重发合计={} 引导口被吞={}",
        quarantined,
        tries,
        fails_fast,
        usable_after_release,
        boot_ok,
        s3.resets,
        ahci::resets_of(vi),
        ahci::resets_of(bt),
        s3.quarantines,
        s3.clean_errors,
        ahci::RETRY_BUDGET,
        ahci::issue_resets_total(),
        ahci::issue_resets_of(bt)
    );
    let rel_cmd = rel.as_ref().map(|p| p.cmd).unwrap_or(0xFFFF_FFFF);
    let (after_status, after_hash) = match after {
        Ok(r) => (r.status, r.hash),
        Err(ref e) => {
            crate::log_warn!("recover: 撤销隔离后的回读失败 {:?}", e);
            (0, 0)
        }
    };
    crate::log_info!(
        "recover: 撤销隔离 起口={} 端口CMD={:#010x} 回读状态={:#04x} 回读哈希={:#018x} 基线={:#018x}",
        released,
        rel_cmd,
        after_status,
        after_hash,
        baseline
    );
    let ok = clean_no_reset
        && clean_usable
        && tried_reset
        && healed
        && fails_fast
        && usable_after_release
        && boot_ok;
    if !ok {
        crate::log_fatal!("recover: 状态机判据不成立（上面两行是全部读数）");
    }
    ok
}
#[cfg(feature = "ahci-scratch")]
ktest!(KT_AHCI_RECOVERY, t_ahci_recovery);

/// 只给 `KT_IRQ_AHCI` 第六格用的一颗空处理函数：它永远说"不是我的"。
/// 要一颗**不接线到任何设备**的认领，是为了让"撤销→复用同一格→旧句柄必须被拒"
/// 这条路在不动 AHCI 那颗中断的前提下走完。
fn t_irq_noop_handler() -> bool {
    false
}

/// M5-g②：真的认领上一颗中断。判据六格，每格只挡一类错法（顺序就是函数体的顺序）：
/// ① **消息逐字对账**：核内算出的 `(addr_lo, addr_hi, data)` 与设备 MSI 结构里此刻的读数
///    三个全等、`ctrl` 的 enable 位读回 1。这一格与 `init` 里那次回读不是同一时刻：
///    中间隔了整段启动，别人（或恢复路径）动过它就得在这里露出来。
/// ② 链路上两道闸门真的开着：`GHC.IE` 与引导口 `PxIE` 各自读回含那一位。
/// ③ 开着中断窗口读一格：**中断到过**（三处同时 +1：本模块的 `irq_hits`+`race_hits`、
///    认领表的 `hits`、`apic` 那台按向量数的 `irq[vec-32]`），而内容仍是夹具的 GPT 头
///    （换了等待方式不许换数据），且"完全没等到中断"那本账 `poll_hits` 为 0。
/// ④ 负样本：关掉设备的 MSI enable 再读一格。命令**仍然成功**（退路必须出得来），
///    而 `irq_hits`/`race_hits` 都不涨、`poll_hits` 涨 ⇒ "其实还在轮询"读得出来。
/// ⑤ 恢复 enable 再读：中断又到过，且这一路没把端口推进隔离（§8.2 的账本读回来对）。
/// ⑥ 撤销一颗自己的认领后：旧句柄先被拒（`NoSuchHandle`），同一格被复用之后旧句柄必须变成
///    `StaleHandle` —— 这正是 ADR-030 那条"复用同一格"的规矩在中断上的续集；
///    而 `release` 不许动 `GHC.IE`：那颗闸门是控制器全局的。
///
/// ③ 里 `irq_hits` 与 `race_hits` 分成两本账：寄存器落定与消息落地之间只隔几十微秒，
/// 合成一本就把"赛跑输赢"读成"中断配没配上"，那是偶发红的形状。所以这一格要求的是
/// **中断到过**（两者之和 == 1），不是"我赢了赛跑"。
fn t_irq_ahci() -> bool {
    use crate::driver::DriverError;
    if ahci::init().is_err() {
        crate::log_fatal!("irq-ahci: AHCI 没认领上，中断判据没法做");
        return false;
    }
    // 接入中断的前置是 APIC 状态，而它不在启动路径上建（`main.rs` 早期那次 `ahci::init()`
    // 比它早）⇒ 这一格自己把前置要齐，而不是假定别人已经做过
    let Some(summary) = acpi::summary() else {
        crate::log_fatal!("irq-ahci: 没有 ACPI 摘要，拿不到 MADT ⇒ 接入中断的前置没法要齐");
        return false;
    };
    let Some(m) = summary.madt else {
        crate::log_fatal!("irq-ahci: MADT 不在摘要里");
        return false;
    };
    if let Err(e) = ahci::arm_irq(&m) {
        crate::log_fatal!("irq-ahci: 接入中断失败 {:?} ⇒ 后面的判据在量它没有的东西", e);
        return false;
    }
    let (Some(vec), Some(h)) = (ahci::irq_vector(), ahci::irq_handle()) else {
        crate::log_fatal!("irq-ahci: 这颗控制器没认领到中断 ⇒ 这一格在量它没有的东西");
        return false;
    };
    let num = match ahci::boot_port() {
        Ok(n) => n,
        Err(e) => {
            crate::log_fatal!("irq-ahci: 找不到引导盘 {:?}", e);
            return false;
        }
    };
    let Some(dev) = pci::first_of_triple(0x01, 0x06, 0x01) else {
        crate::log_fatal!("irq-ahci: 枚举表里没有 AHCI");
        return false;
    };
    let ctx = driver::DriverCtx::for_device(ahci::MOD_AHCI, dev);
    // `apic::counts()` 那 16 格是按 ISA 线号索引的（向量 - 0x20），不是按向量
    let vslot = usize::from(vec) - trap::VEC_IRQ_BASE;

    // ① 消息逐字对账
    let (msg_lo, msg_hi, msg_data) = match ctx.irq_message(h) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("irq-ahci: 消息算不出来 {:?}", e);
            return false;
        }
    };
    let (b_lo, b_hi, b_data, b_ctrl) = match ahci::msi_witness() {
        Some(v) => v,
        None => {
            crate::log_fatal!("irq-ahci: 设备里那三格读不回来 ⇒ 认领与设备没对上");
            return false;
        }
    };
    let msg_back = b_lo == msg_lo && b_hi == msg_hi && b_data == msg_data && b_ctrl & 1 != 0;

    // ② 两道闸门
    let (ghc, ie, _is) = match ahci::irq_gates() {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("irq-ahci: 闸门读数拿不到 {:?}", e);
            return false;
        }
    };
    let gates = (ghc & ahci::REG_GHC_IE != 0) && (ie & 1 != 0);

    // ③④⑤ 三个动作共用的读数器：一次"开窗口读 LBA 1"，回来报三本账的增量与内容
    let step = |who: &'static str| -> (usize, usize, usize, usize, usize, bool) {
        ahci::irq_counters_reset();
        let (calls0, hits0) = ctx.irq_counts(h).unwrap_or((0, 0));
        let c0 = apic::counts();
        let (disp0, uncl0) = irq::stats();
        // 旗子得有人来取：本地中断窗口要 IF=1，而 tick 是把被挂住的上下文往前推的那只手
        let timer = apic::timer_start().is_ok();
        let mut buf = [0u8; 512];
        let r = apic::with_interrupts(|| ahci::read_bytes(num, 1, &mut buf));
        let _ = apic::timer_stop();
        let c1 = apic::counts();
        let (calls1, hits1) = ctx.irq_counts(h).unwrap_or((0, 0));
        let (disp1, uncl1) = irq::stats();
        let content = &buf[0..8] == b"EFI PART";
        crate::log_info!(
            "irq-ahci: {} 中断={} 赛跑={} 轮询={} 顶半={} 认领表hits={}→{} calls={}→{} 按向量irq[{}]={}→{} 派发={} 没人认领={} 定时器开={} 判定={:?}",
            who, ahci::irq_hits(), ahci::race_stats().0, ahci::poll_hits(), ahci::isr_entry(),
            hits0, hits1, calls0, calls1, vslot,
            c1.irq[vslot].saturating_sub(c0.irq[vslot]),
            c0.irq[vslot], disp1 - disp0, uncl1 - uncl0, timer,
            r.as_ref().err()
        );
        (
            ahci::irq_hits() + ahci::race_stats().0,
            ahci::poll_hits(),
            hits1 - hits0,
            ahci::isr_entry(),
            c1.irq[vslot] - c0.irq[vslot],
            r.is_ok() && content,
        )
    };

    // ③ 开着中断读
    let (arrived3, polled3, tbl3, entry3, byvec3, good3) = step("③开中断");
    let third = arrived3 >= 1 && polled3 == 0 && tbl3 >= 1 && entry3 >= 1 && byvec3 >= 1 && good3;

    // ④ 负样本：关掉设备的 enable
    if ahci::set_msi_enabled(false).is_err() {
        crate::log_fatal!("irq-ahci: 关不上设备的 MSI enable");
        return false;
    }
    let (arrived4, polled4, _, _, _, good4) = step("④关掉enable");
    let fourth = arrived4 == 0 && polled4 == 1 && good4;
    // 恢复
    let restored = ahci::set_msi_enabled(true).is_ok();

    // ⑤ 恢复之后再读
    let (arrived5, polled5, _, _, _, good5) = step("⑤恢复enable");
    let resets5 = ahci::resets_of(num);
    let fifth = arrived5 >= 1 && polled5 == 0 && good5 && restored && resets5 == 0;

    // ⑥ 撤销 → 旧句柄被拒 → 同一格复用 → 旧句柄变成 StaleHandle；release 不许动 GHC.IE
    let extra = match ctx.request_irq(t_irq_noop_handler) {
        Ok(x) => x,
        Err(e) => {
            crate::log_fatal!("irq-ahci: 再要一颗认领失败 {:?}", e);
            return false;
        }
    };
    let released = ctx.release_irq(extra).is_ok();
    let after_release = ctx.irq_counts(extra);
    let ghc_after_release = ahci::irq_gates().map(|(g, _, _)| g).unwrap_or(0);
    // 复用同一格：表里第一格空出来，下一次要的就是它 ⇒ 槽号相同而世代号不同
    let again = ctx.request_irq(t_irq_noop_handler);
    let reused_same_slot = matches!(&again, Ok(x) if x.slot == extra.slot && x.gen != extra.gen);
    let stale_rejected = matches!(ctx.irq_counts(extra), Err(DriverError::StaleHandle { slot, .. }) if slot == extra.slot);
    let never_delivered = irq::stats().1 == 0;
    let _ = again.map(|x| ctx.release_irq(x));
    let sixth = released
        && matches!(after_release, Err(DriverError::NoSuchHandle(s)) if s == extra.slot)
        && reused_same_slot
        && stale_rejected
        && ghc_after_release == ghc
        && never_delivered;

    // ⑦ 分账与总账同数。这条不是装饰：只有"谁在服务"那本分账能对上总账，
    //    第 ⑥ 格与亲和性那一跑里的分账读数才许拿去当证据（BACKLOG 73f）。
    let isr_split = ahci::isr_entry_by_cpu();
    let (race_split, race_max_split) = ahci::race_by_cpu();
    let split_ok = isr_split.iter().sum::<usize>() == ahci::isr_entry()
        && race_split.iter().sum::<usize>() == ahci::race_stats().0;
    crate::log_info!(
        "irq-ahci: 判据 消息逐字={} GHC.IE={} PxIE={} 开中断到过={} 关enable纯轮询={} 恢复后又={} 撤销与复用={} 分账同数={} 向量={:#x} 赛跑最大间隔={} 端口={} 隔离计数={} 顶半按CPU={:?}",
        msg_back,
        ghc & ahci::REG_GHC_IE != 0,
        ie & 1 != 0,
        third,
        fourth,
        fifth,
        sixth,
        split_ok,
        vec,
        ahci::race_stats().1,
        num,
        resets5,
        isr_split
    );
    let ok = msg_back && gates && third && fourth && fifth && sixth && split_ok;
    if !ok {
        crate::log_fatal!("irq-ahci: 中断认领判据不成立（上面每个动作一行读数）");
    }
    ok
}
ktest!(KT_IRQ_AHCI, t_irq_ahci);

/// L3-B 亲和性：把 AHCI 那颗 MSI 的目的地移到一颗上线的 AP，做一次真读，看投递落到哪颗 CPU；
/// 再移回 BSP 做第二次。判据三件事，各管一种错法：
/// ① 消息里那条目的地位段与表里说的同一颗 CPU；② 设备**回读**逐字一致（写了不等于收下了）；
/// ③ 新投递只落在目的地上、BSP 那格一格都不许涨。
/// 宿主机另外拿 `-d int` 里 `SP` 的高位数一遍 BSP／非 BSP（矩阵第 32 行）——那是独立仪器。
#[cfg(feature = "irq-affinity-probe")]
fn t_irq_affinity() -> bool {
    let Some(h) = ahci::irq_handle() else {
        crate::log_fatal!("irq-aff: 这颗控制器没认领到中断 ⇒ 移动目的地没有对象");
        return false;
    };
    let Ok(num) = ahci::boot_port() else {
        crate::log_fatal!("irq-aff: 找不到引导盘 ⇒ 没有能触发中断的动作");
        return false;
    };
    let Some(bsp_id) = apic::state().map(|st| st.id as u8) else {
        crate::log_fatal!("irq-aff: 本地 APIC 没初始化 ⇒ 连目的地都算不出来");
        return false;
    };
    // 找一颗**上线**的 AP：目的地写成没上机的核，失败形状是"一个中断都不来"，
    // 那种故障没有别的尺子会报（§13.1 那条时钟前提之外的第二条跨 CPU 前提）
    let ap = (1..cpu::MAX_CPUS)
        .filter(|&s| cpu::is_registered(s) && cpu::is_online(s))
        .find_map(|s| cpu::lapic_id_of(s).map(|id| (s, id as u8)));
    let Some((ap_slot, ap_id)) = ap else {
        crate::log_fatal!("irq-aff: 没有第二颗上线的 CPU ⇒ 这一格在量它没有的东西");
        return false;
    };
    let moves0 = irq::moves();

    // ---- 一次"开中断窗口读 LBA 1"，回来报按 CPU 的分布 ----
    // 每个动作回来交两本分账：投递落到哪颗核（`by_cpu`），顶半在哪颗核跑过（`isr_entry_by_cpu`）。
    // 后者是 73f 那一格新加的出口——只有前者可用时，"谁在服务"只能从投递分布反推。
    let step = |who: &'static str| -> ([usize; cpu::MAX_CPUS], [usize; cpu::MAX_CPUS]) {
        ahci::irq_counters_reset();
        let timer = apic::timer_start().is_ok();
        let mut buf = [0u8; 512];
        let r = apic::with_interrupts(|| ahci::read_bytes(num, 1, &mut buf));
        let _ = apic::timer_stop();
        let now = irq::by_cpu();
        let (race, race_max) = ahci::race_stats();
        let served = ahci::isr_entry_by_cpu();
        crate::log_info!(
            "irq-aff: {} 读盘={} 内容={} 定时={} 中断落定={} 赛跑落定={} 轮询落定={} 顶半={} 赛跑最大间隔={} 按CPU={:?} 顶半按CPU={:?}",
            who,
            r.is_ok(),
            &buf[0..8] == b"EFI PART",
            timer,
            ahci::irq_hits(),
            race,
            ahci::poll_hits(),
            ahci::isr_entry(),
            race_max,
            now,
            served
        );
        (now, served)
    };

    // ① 移到 AP
    let (same_a, slot_a, msg_a) = match ahci::set_affinity(ap_id) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("irq-aff: 移到 AP 失败 {:?}", e);
            return false;
        }
    };
    let dest_a = ahci::affinity_dest() == Some(ap_id);
    // 用例自足（T0.1 顺序暴露）：改完目的地后先做一次**不计数**的读，把移动前已经在途的
    // MSI（落在旧目的地）吸收掉；基线在排空之后取，才真的是"这一步开始时的投递分布"。
    let _ = step("排空到AP前");
    let before = irq::by_cpu();
    let (mid, mid_served) = step("移到AP后");
    // ② 移回 BSP
    // 回移的基线取在**搬到 AP 那一步之后、改目的地之前**：这中间不许再产生 AP 投递，
    // 否则宿主机那台仪器会看到"收尾的非 BSP 比移动窗口里多"，那正是它在防的半程错。
    let back_base = irq::by_cpu();
    let (same_b, slot_b, msg_b) = match ahci::set_affinity(bsp_id) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("irq-aff: 移回 BSP 失败 {:?} ⇒ 目的地留在 AP 上，后面的判据没法读", e);
            return false;
        }
    };
    let (after, after_served) = step("移回BSP后");

    let want_a = msg_a.addr_lo == 0xFEE0_0000 | (u32::from(ap_id) << 12);
    let want_b = msg_b.addr_lo == 0xFEE0_0000 | (u32::from(bsp_id) << 12);
    let prog_ok = same_a && same_b && want_a && want_b && slot_a == ap_slot && slot_b == 0 && dest_a;
    // 新投递只许落在目的地；BSP 那一格在移动期间一格都不许涨
    let landed = mid[ap_slot] > before[ap_slot];
    let not_bsp = mid[0] == before[0];
    // 移回之后 BSP 继续涨、而非 BSP 一格都不再涨——这条排除"表里改了而设备没改"那种半程错
    let non_after: usize = after[1..].iter().sum();
    let non_back: usize = back_base[1..].iter().sum();
    let back_ok = after[0] > back_base[0] && non_after == non_back;
    let moves_ok = irq::moves() == moves0 + 2;
    // 73f：服务那一侧也要按 CPU 看得见。`step` 每步开头把账归零，所以读数就是"这一步里谁服务过"：
    // 目的地在 AP 那一步，顶半只能出现在 AP 那格；搬回 BSP 那一步反过来。
    // 第一版我写成"比移动前涨没涨"，那是拿归零后的数比归零前的数——`served0` 因此被删掉。
    let served_landed = mid_served[ap_slot] >= 1 && mid_served[0] == 0;
    let served_back = after_served[0] >= 1 && after_served[ap_slot] == 0;
    let served_split = after_served.iter().sum::<usize>() == ahci::isr_entry();
    let bsp_now = after[0] + after[1..].iter().sum::<usize>() > before[0] + before[1..].iter().sum::<usize>();
    crate::log_info!(
        "irq-aff: 判据 BSP id={:#04x} AP id={:#04x} 槽={} 移动期间落到AP={} AP前={} AP后={} BSP前={} BSP后={}          回读逐字={} 消息目的地对={} 表里说的={} 回到BSP={} 移动次数={}→{} 总投递动了={}              服务顶半搬到AP={} 服务顶半搬回={} 顶半分账同数={}",
        bsp_id,
        ap_id,
        ap_slot,
        landed,
        before[ap_slot],
        mid[ap_slot],
        before[0],
        mid[0],
        prog_ok,
        want_a && want_b,
        dest_a,
        back_ok,
        moves0,
        irq::moves(),
        bsp_now,
        served_landed,
        served_back,
        served_split
    );
    let _ = h;
    prog_ok && landed && not_bsp && back_ok && moves_ok && served_landed && served_back && served_split
}
#[cfg(feature = "irq-affinity-probe")]
ktest!(KT_IRQ_AFFINITY, t_irq_affinity);

/// L3-A：整行原子性。让每个在线 CPU 同时打一批行，内核这一侧只数**账**：
/// 每 CPU 自己数的行数、行锁四本账的增量、用完归还、没进停机放行。
/// 行的**形状**由另一台仪器判（矩阵第 31 行，`tools/aurora.py:check_line_atomicity`）——
/// 一台数账一台数形状，两边都过才算，任何一边单独绿都不算。
#[cfg(feature = "serial-atomic-probe")]
fn t_serial_atomic() -> bool {
    let o = match smp::print_round() {
        Ok(o) => o,
        Err(e) => {
            crate::log_fatal!("atomic: 一轮并发打印没跑起来 {:?}", e);
            return false;
        }
    };
    let total = o.bsp_total + o.ap_total;
    let lines_ok = o.ack_timeouts == 0
        && o.bsp_total == o.lines_per_cpu
        && o.ap_total == o.lines_per_cpu * (o.participants - 1);
    // 每一行恰好取一次锁：少了说明有行绕过了锁，多了说明同一行取了两次
    let holds_ok = o.holds == total;
    // `contended` 不进球：三跑里它分别是 1、2、6——它是"撞上了没有"的现场读数，不是
    // 能稳定判定的东西。非空转的举证放在核外那台仪器（变异 E：撤掉行锁后 96 行只剩
    // 65 个整行、10 行出现两种 tag、3 行张冠李戴），而不是押在这个计数上。
    let clean_ok = o.nested == 0 && o.timeouts == 0;
    let released_ok = o.owner_after == 0 && !o.halting;
    crate::log_info!(
        "atomic: 判据 参与核={} 每核行={} BSP行={} AP行={} 总行={} 取锁={} 竞争={} 重入={} 超时={} \
         回执超时={} 结束后持有者={} 停机放行={} 行数齐={} 每行一次锁={} 账干净={}",
        o.participants,
        o.lines_per_cpu,
        o.bsp_total,
        o.ap_total,
        total,
        o.holds,
        o.contended,
        o.nested,
        o.timeouts,
        o.ack_timeouts,
        o.owner_after,
        o.halting,
        lines_ok,
        holds_ok,
        clean_ok
    );
    lines_ok && holds_ok && clean_ok && released_ok
}
#[cfg(feature = "serial-atomic-probe")]
ktest!(KT_SERIAL_ATOMIC, t_serial_atomic);

/// M5-e①：§8.2/§8.5 的能力句柄表。六格各挡一种"句柄系统会怎么坏"，
/// 每格都要能单独变红（顺序就是函数体的顺序）：
/// 1 映射成功且授权是看得见的证据；同一格寄存器经 ctx 与经驱动两条路读到同一个数
/// 2 窗口外的偏移与不对齐的偏移必须被拒（不靠驱动自觉）
/// 3 **撤销后同一格被复用**，旧句柄必须开不了新资源（`StaleHandle`），新句柄照常
/// 4 句柄认主人：槽号与世代号全对，换一个 `ModuleId` 也必须被拒
/// 5 DMA：页框进台账、边界按窗口判、内容写得进也读得回
/// 6 撤销 DMA：页框回到原位、表里的占用格子数回到原位
fn t_driver_ctx() -> bool {
    // 用例必须自足：`.ktests` 的顺序由链接器决定，不能假设 `ahci` 已经认领过设备
    if ahci::init().is_err() {
        crate::log_fatal!("ctx: AHCI 认领失败，没有设备可发句柄");
        return false;
    }
    let Some(dev) = pci::first_of_triple(0x01, 0x06, 0x01) else {
        crate::log_fatal!("ctx: 枚举表里没有 SATA-AHCI 设备");
        return false;
    };
    let ctx = driver::DriverCtx::for_device(mm::MOD_TEST, dev);
    // 第二个令牌：设备一样、主人不一样。只用它的"读"去碰别人的句柄，不经它分配任何东西
    let other = driver::DriverCtx::for_device(mm::MOD_BOOT, dev);
    let (occ_m0, occ_d0) = driver::occupancy();
    let live0 = resource::live_of(mm::MOD_TEST);
    // 第三本账：VA 保留登记数。M4-2 撞过一次"映射解了但 VA 没放手"，表现是
    // 反复跑之后 `L4: VA 保留登记表已满` —— 一个进程生命周期的问题被报成内核故障。
    let res0 = mm::reservation_count();

    let Ok(h) = ctx.map_mmio(5) else {
        crate::log_fatal!("ctx: 映射 BAR5 失败");
        return false;
    };
    // 授权值要**当场存下来**：日志打印时那两格句柄都已经撤销了，再读一次只会拿到失败值
    let auth_val = ctx.mmio_authorized(h).unwrap_or(0);
    let authorized = auth_val & 0b110 == 0b110;
    let cap_ctx = ctx.read32(h, ahci::REG_CAP);
    // 两台仪器：经 ctx 读到的 `CAP` 必须等于驱动自己那张表里记着的同一个数
    let two_instruments = cap_ctx.ok() == ahci::info().map(|i| i.cap);
    let len = ctx.mmio_len(h).unwrap_or(0);
    let oob = matches!(ctx.read32(h, len), Err(driver::DriverError::Access(hw::HwError::OutOfRange)));
    let unaligned =
        matches!(ctx.read32(h, 1), Err(driver::DriverError::Access(hw::HwError::NotAligned)));

    // 3 撤销 → 复用同一格 → 旧句柄必须失效。两种坏法分开挡：表里空着时是"没有这一格"，
    // 被别人（或下一次分配）复用之后是"世代号不对"——只测后者就看不出撤销到底有没有真的摘走表项
    let slot = driver::mmio_slot(h);
    let released = ctx.release_mmio(h).is_ok();
    let refused_empty =
        matches!(ctx.read32(h, 0), Err(driver::DriverError::NoSuchHandle(s)) if s == slot);
    let Ok(h2) = ctx.map_mmio(5) else {
        crate::log_fatal!("ctx: 第二次映射失败，复用那一格没测成");
        return false;
    };
    let reused_same_slot = driver::mmio_slot(h2) == slot;
    let gen_moved = driver::mmio_gen(h2) != driver::mmio_gen(h);
    let table_agrees = driver::mmio_gen_at(slot) == Some(driver::mmio_gen(h2));
    let new_handle_works = ctx.read32(h2, ahci::REG_CAP).is_ok();
    let old_handle_refused =
        matches!(ctx.read32(h, ahci::REG_CAP), Err(driver::DriverError::StaleHandle { .. }));
    // 4 别人拿着完全正确的句柄也必须被拒（这一条只有表里的 owner 挡得住）
    let not_owner = matches!(
        other.read32(h2, ahci::REG_CAP),
        Err(driver::DriverError::NotOwner { slot: s, .. }) if s == slot
    );
    // 5 表里没有的槽号：越界一个、以及表内但空着的一格
    let no_such_far = matches!(
        ctx.read32(driver::mmio_handle_at(999, 1), 0),
        Err(driver::DriverError::NoSuchHandle(999))
    );
    let no_such_empty = matches!(
        ctx.read32(driver::mmio_handle_at(7, 1), 0),
        Err(driver::DriverError::NoSuchHandle(7))
    );
    let released2 = ctx.release_mmio(h2).is_ok();

    // 6/7 DMA：两本账（页框台账 + 表的占用数）与一条内容往返
    let dma_len = 2 * mm::PAGE;
    let d = match ctx.alloc_dma(dma_len) {
        Ok(d) => d,
        Err(e) => {
            crate::log_fatal!("ctx: 分配 DMA 失败 {:?}", e);
            return false;
        }
    };
    let live_dma = resource::live_of(mm::MOD_TEST);
    let frames_charged = live_dma == live0 + 2;
    let bus = ctx.bus_addr(d).unwrap_or(0);
    let bus_sane = bus != 0 && bus % mm::PAGE as u64 == 0;
    let (occ_m1, occ_d1) = driver::occupancy();
    let occupied = occ_d1 == occ_d0 + 1 && occ_m1 == occ_m0;
    let edge_write = ctx.dma_write8(d, dma_len - 1, 0x5A).is_ok();
    let edge_read = ctx.dma_read8(d, dma_len - 1) == Ok(0x5A);
    let head = ctx.dma_write32(d, 0, 0xDEAD_BEEF).and_then(|_| ctx.dma_read32(d, 0));
    let head_ok = head == Ok(0xDEAD_BEEF);
    let dma_oob =
        matches!(ctx.dma_read8(d, dma_len), Err(driver::DriverError::Denied(_)));
    let dma_unaligned =
        matches!(ctx.dma_read32(d, 1), Err(driver::DriverError::Access(hw::HwError::NotAligned)));
    let fill_ok = ctx
        .dma_fill(d, 0, 0xA7, dma_len)
        .and_then(|_| ctx.dma_read8(d, dma_len / 2))
        .map(|v| v == 0xA7)
        .unwrap_or(false);
    let mut out = [0u8; 8];
    ctx.dma_copy_out(d, dma_len - 8, &mut out).ok();
    let copy_out_ok = out == [0xA7; 8];
    ctx.release_dma(d).ok();
    let live_back = resource::live_of(mm::MOD_TEST) == live0;
    let occ_back = driver::occupancy() == (occ_m0, occ_d0);
    let res_back = mm::reservation_count() == res0;

    crate::log_info!(
        "ctx: 授权={}({:#06x}) 两条路同一个数={:#010x}={} 窗口={} 越界拒={} 未对齐拒={}",
        authorized,
        auth_val,
        cap_ctx.unwrap_or(0xFFFF_FFFF),
        two_instruments,
        len,
        oob,
        unaligned
    );
    crate::log_info!(
        "ctx: 复用同格={} 撤销返回={} 空表拒={} 世代号前/后={}/{} 表里读到={} 新句柄能用={} 旧句柄被拒={} 别人被拒={} 空槽拒={}/{}",
        reused_same_slot,
        released && released2,
        refused_empty,
        driver::mmio_gen(h),
        driver::mmio_gen(h2),
        table_agrees,
        new_handle_works,
        old_handle_refused,
        not_owner,
        no_such_far,
        no_such_empty
    );
    crate::log_info!(
        "ctx: DMA 总线地址={:#018x} 正常={} 页框进台账={}/{} 占用={} 边界内读写={} 首字节={} 越界拒={} 未对齐拒={} 填与读回={} 拷出={} 撤销后页框/占用/VA保留回到原位={}/{}/{}",
        bus,
        bus_sane,
        live0,
        live_dma,
        frames_charged && occupied,
        edge_write && edge_read,
        head_ok,
        dma_oob,
        dma_unaligned,
        fill_ok,
        copy_out_ok,
        live_back,
        occ_back,
        res_back
    );
    crate::log_info!(
        "ctx: 三本账基线 页框={} VA保留={} 表占用 MMIO/DMA={}/{} 探针后 VA保留={}",
        live0,
        res0,
        occ_m0,
        occ_d0,
        mm::reservation_count()
    );
    let ok = authorized
        && two_instruments
        && len > 0
        && oob
        && unaligned
        && released
        && refused_empty
        && released2
        && reused_same_slot
        && gen_moved
        && table_agrees
        && new_handle_works
        && old_handle_refused
        && not_owner
        && no_such_far
        && no_such_empty
        && bus_sane
        && frames_charged
        && occupied
        && edge_write
        && edge_read
        && head_ok
        && dma_oob
        && dma_unaligned
        && fill_ok
        && copy_out_ok
        && live_back
        && occ_back
        && res_back;
    if !ok {
        crate::log_fatal!("ctx: 句柄表判据不成立（上面三行是全部读数）");
    }
    ok
}
ktest!(KT_DRIVER_CTX, t_driver_ctx);

