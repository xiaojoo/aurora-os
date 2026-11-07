//! 物理页、映射与缺页探针用例（T0.1 纯搬移）。

use crate::arch::x86_64::{trap};
use crate::{mm};
use crate::ktest;

/// 分配-释放是否真的回到基线（不比对基线就等于没测）
fn t_alloc_free_returns_frames() -> bool {
    let base = mm::free_frames();
    let f = match mm::phys_alloc(0, mm::MOD_TEST) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("phys_alloc failed: {:?}", e);
            return false;
        }
    };
    let after_alloc = mm::free_frames();
    let addr = f.base().0;
    drop(f);
    let after_free = mm::free_frames();
    crate::log_info!("alloc/free: base={} alloc={} free={} frame={:#x}", base, after_alloc, after_free, addr);
    // 释放后该帧被毒化成 0xa5，读回来才说明“释放”真的发生了
    let poisoned = {
        // SAFETY: addr 来自分配器且在 max_phys 内，HHDM 覆盖全部物理内存
        let p = mm::hhdm() + addr;
        let v = unsafe { core::ptr::read_volatile(p as *const u8) };
        v == 0xa5
    };
    base > after_alloc && after_free == base && poisoned
}
ktest!(KT_ALLOC_FREE, t_alloc_free_returns_frames);

/// 映射 -> 写入 -> 读回 -> 解映射，且所有权随 Mapping 归还（§6.3 R13）
fn t_map_write_unmap() -> bool {
    const MAGIC: u64 = 0x5176_0dae_1234_beef;
    let va = match mm::alloc_va_range(1) {
        Some(v) => v,
        None => {
            crate::log_fatal!("no unmapped range for map test");
            return false;
        }
    };
    let base_free = mm::free_frames();
    let frames = match mm::phys_alloc(0, mm::MOD_TEST) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("map test alloc failed: {:?}", e);
            return false;
        }
    };
    let m = match mm::map(va, frames, mm::PageFlags::RW) {
        Ok(m) => m,
        Err(e) => {
            crate::log_fatal!("map failed: {:?}", e);
            return false;
        }
    };
    // SAFETY: m.virt() 刚建立的映射，页框来自分配器
    unsafe { core::ptr::write_volatile(m.virt().0 as *mut u64, MAGIC) };
    // SAFETY: 同上
    let got = unsafe { core::ptr::read_volatile(m.virt().0 as *mut u64) };
    let mapped_before = mm::is_mapped(m.virt().0);
    let after_alloc = mm::free_frames();
    let virt = m.virt();
    drop(m); // Mapping::drop -> unmap，然后 OwnedFrames::drop -> 释放
    // 端到端不变量：**数据页**必须归还；解映射后映射必须消失。
    // 注意 map() 建叶子表时会按 create=true 要一整页当页表页，那一页是长期占用，
    // 不该在 unmap 时回来（实测 base=128991 -> after_alloc=128989，正是数据页 + 页表页各一）。
    // 因此这里比的是 after_alloc + 1，而不是 base_free——第一版断言写成后者是错的。
    let ok = got == MAGIC && mapped_before && !mm::is_mapped(virt.0) && mm::free_frames() == after_alloc + 1;
    if !ok {
        crate::log_fatal!(
            "map/unmap wrong: got={:#x} mapped_before={} mapped_after={} free base={} after_alloc={} final={}",
            got,
            mapped_before,
            mm::is_mapped(virt.0),
            base_free,
            after_alloc,
            mm::free_frames()
        );
    }
    ok
}
ktest!(KT_MAP_UNMAP, t_map_write_unmap);

/// guard page：只映射第二页，第一页必须仍未映射且访问它要能取到异常。
/// 这是 M1 时我在 §5.2 注释里承认“还没有 guard page”的那一项。
fn t_guard_page_blocks_access() -> bool {
    let va = match mm::alloc_va_range(2) {
        Some(v) => v,
        None => {
            crate::log_fatal!("no unmapped range for guard test");
            return false;
        }
    };
    let frames = match mm::phys_alloc(1, mm::MOD_STACK) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("guard test alloc failed: {:?}", e);
            return false;
        }
    };
    // 只映射高地址那一页，低地址那页留作 guard
    let stack_va = mm::VirtAddr(va.0 + 4096);
    let m = match mm::map(stack_va, frames, mm::PageFlags::RW) {
        Ok(m) => m,
        Err(e) => {
            crate::log_fatal!("guard map failed: {:?}", e);
            return false;
        }
    };
    let guard = stack_va.0 - 4096;
    let stack_faults = trap::probe_page_fault(stack_va.0).is_some();
    let guard_faults = trap::probe_page_fault(guard).is_some();
    drop(m);
    crate::log_info!("guard: mapped_page_faulted={} guard_page_faulted={}", stack_faults, guard_faults);
    // 映射页不该故障，guard 页必须故障
    !stack_faults && guard_faults
}
ktest!(KT_GUARD_PAGE, t_guard_page_blocks_access);

/// W^X 在构造层面不可表达。**这只测 API**，硬件强制要等 M4 的执行路径探针，
/// 不把前者说成后者。
fn t_wx_construction_rejected() -> bool {
    mm::PageFlags::new(true, true, false) == Err(mm::MmError::WxViolation)
        && mm::PageFlags::new(true, false, false).is_ok()
}
ktest!(KT_WX_API, t_wx_construction_rejected);

/// 2 MiB 大页覆盖的 VA 里铺 4 KiB 叶子必须被**拒绝**（`HugeConflict`）。
///
/// 加这条的用例而不是只改 `walk_leaf`：修之前它会直接钻进大页表项，把那块**数据帧**
/// 当成下一级页表——`set_leaf` 检查的是叶子位，看不见大页父项的冲突，于是“映射成功”，
/// 而翻译仍然是那个大页。HHDM 尾部按 2 MiB 对齐铺大页，未对齐的物理上界正好被这样盖住，
/// 所以这不是假想路径。断言里有三条是"没留下痕迹"：不新增页表页、不计入 map_calls、
/// 物理页随 Drop 归还。
fn t_map_refused_inside_huge_page() -> bool {
    let va = mm::VirtAddr(mm::hhdm() + mm::PAGE as u64);
    if !mm::is_mapped(va.0) {
        crate::log_fatal!("huge probe va {:#x} is not mapped; 用例前提不成立", va.0);
        return false;
    }
    let before = mm::counters();
    let free_before = mm::free_frames();
    let frames = match mm::phys_alloc(0, mm::MOD_TEST) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("huge probe alloc failed: {:?}", e);
            return false;
        }
    };
    let err = mm::map(va, frames, mm::PageFlags::RW).err();
    let after = mm::counters();
    let back = mm::free_frames() == free_before;
    let no_table = after.page_table_pages == before.page_table_pages;
    let no_call = after.map_calls == before.map_calls;
    let still_mapped = mm::is_mapped(va.0);
    crate::log_info!(
        "huge conflict: err={:?} frames_back={} no_new_table={} no_map_call={} hhdm_alias_still_mapped={}",
        err, back, no_table, no_call, still_mapped
    );
    err == Some(mm::MmError::HugeConflict) && back && no_table && no_call && still_mapped
}
ktest!(KT_HUGE_CONFLICT, t_map_refused_inside_huge_page);

/// 重复释放必须升 L4（退出码 39）。只在注入构建里存在，与 negative-probe 同构。
#[cfg(feature = "fault-double-free")]
fn t_double_free_must_escalate() -> bool {
    crate::log_warn!("fault-double-free: 这条用例按设计触发一次重复释放");
    mm::force_double_free_for_test()
}
#[cfg(feature = "fault-double-free")]
ktest!(KT_DOUBLE_FREE, t_double_free_must_escalate);

