//! 启动信息、页表接管探针与 IDT 入口的用例（T0.1 纯搬移）。

use crate::arch::x86_64::{trap};
use crate::{limine, mm};
use crate::{PROBE_ADDR};
use crate::ktest;
use core::sync::atomic::{Ordering};

fn t_revision_tag_rewritten() -> bool {
    // rev>=3 的 bootloader 必须把 tag 第 2 分量改写为实际 revision
    limine::BASE_REVISION.negotiated().is_some_and(|v| (3..=5).contains(&v))
}
ktest!(KT_REV, t_revision_tag_rewritten);

fn t_memmap_usable_ge_32mib() -> bool {
    // 读 mm 里**拷出来的**表，不读 bootloader 原始结构：那些帧现在是可分配的
    let mut i = 0usize;
    let mut usable = 0u64;
    while let Some(r) = mm::region(i) {
        if r.kind == limine::MemmapType::Usable {
            usable = usable.saturating_add(r.length);
        }
        i += 1;
    }
    crate::log_info!("memmap usable = {} MiB over {} entries", usable / (1024 * 1024), i);
    usable >= 32 * 1024 * 1024
}
ktest!(KT_MEMMAP, t_memmap_usable_ge_32mib);

fn t_hhdm_is_canonical_and_below_kernel() -> bool {
    let o = mm::hhdm();
    o != 0 && o < 0xffff_ffff_8000_0000 && (o >> 47) == 0x1_ffff
}
ktest!(KT_HHDM, t_hhdm_is_canonical_and_below_kernel);

/// 受控 #PF：异常被取到、CR2 与故障地址一致、且 iretq 后确实回到恢复点
fn t_pf_probe_recovers() -> bool {
    let addr = PROBE_ADDR.load(Ordering::Relaxed);
    if addr == 0 {
        return false;
    }
    match trap::probe_page_fault(addr) {
        Some(1) => trap::PF_TAKEN.load(Ordering::Relaxed) > 0,
        Some(other) => {
            crate::log_fatal!("pf probe resumed with unexpected rax={}", other);
            false
        }
        None => {
            crate::log_fatal!("pf probe did NOT fault: {:#x} is apparently mapped", addr);
            false
        }
    }
}
ktest!(KT_PF, t_pf_probe_recovers);

fn t_all_32_vectors_distinct() -> bool {
    trap::handler_count_distinct() == 32
}
ktest!(KT_IDT, t_all_32_vectors_distinct);

/// 负样本（§12.3 R19）：只在 `--features negative-probe` 构建里存在，且必然失败。
/// 它的作用是证明判定链会把失败真的报成失败（退出码 35），而不是“绿而无效”。
#[cfg(feature = "negative-probe")]
fn t_negative_probe_must_fail() -> bool {
    crate::log_warn!("negative-probe: 这条用例按设计返回 false");
    false
}
#[cfg(feature = "negative-probe")]
ktest!(KT_NEG, t_negative_probe_must_fail);
