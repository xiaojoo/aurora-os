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

/// P1b（ADR-063）：FrameInfo 接管分配/释放后，多规格连续帧的分配-释放必须回基线，
/// 且台账 Σlive==Σalloc−Σfree 不变量不破坏。这是"位图→refcnt 独占行为等价"的见证：
/// 单帧那条（KT_ALLOC_FREE）只测 order 0，这里覆盖 order 0..=3（1/2/4/8 帧连续）。
/// 反空转：alloc 必须真的减少 free（base>after），否则"释放回基线"可能是常量真。
fn t_frame_info_alloc_free_equivalence() -> bool {
    let base = mm::free_frames();
    let live0 = crate::resource::live_of(mm::MOD_TEST);
    let mut ok = true;
    let mut detail = [0u64; 4];
    for order in 0u8..4 {
        let n = 1usize << order;
        let f = match mm::phys_alloc(order, mm::MOD_TEST) {
            Ok(f) => f,
            Err(e) => {
                crate::log_fatal!("frame_info 等价: order {} 分配失败 {:?}", order, e);
                ok = false;
                break;
            }
        };
        let after_alloc = mm::free_frames();
        drop(f);
        let after_free = mm::free_frames();
        detail[order as usize] = after_free as u64;
        if !(after_alloc == base - n && after_free == base) {
            crate::log_fatal!("frame_info 等价: order {} alloc={} free={} base={} 不回基线", order, after_alloc, after_free, base);
            ok = false;
        }
    }
    let t = crate::resource::totals();
    let live_back = crate::resource::live_of(mm::MOD_TEST) == live0;
    let ledger_ok = t.sum_live == t.sum_alloc - t.sum_free && !t.violation;
    crate::log_info!(
        "frame_info 等价(P1b): base={} 各order释放回={} live回基线={} 台账live={} alloc={} free={} 不变量={}",
        base, detail[0], live_back, t.sum_live, t.sum_alloc, t.sum_free, ledger_ok);
    ok && live_back && ledger_ok && base > 0
}
ktest!(KT_FRAME_INFO_EQUIV, t_frame_info_alloc_free_equivalence);

/// P1c（ADR-063）：共享帧 N 次 get、N 次 put 才归还，多一次 put 判 DoubleFree。
/// 这是"refcnt 驱动归还时机"的直接见证（P1b 等价用例只证 free_frames 记账，不证这个）：
/// ① 分配独占帧（refcnt 1）；② frame_get N 次（refcnt 1+N）；③ 丢独占主人——refcnt>1 不归还；
/// ④ 逐个丢共享凭证，前 N-1 个不归还、**最后一个才归还**（free_frames 此刻才 +1）；
/// ⑤ 再 put 一次 ⇒ DoubleFree。反空转：get 之后、最后一个 put 之前 free_frames 必须不动。
fn t_frame_refcount_get_put() -> bool {
    const N: usize = 3;
    let base = mm::free_frames();
    let live0 = crate::resource::live_of(mm::MOD_TEST);
    let f = match mm::phys_alloc(0, mm::MOD_TEST) {
        Ok(f) => f,
        Err(e) => { crate::log_fatal!("refcount: 分配失败 {:?}", e); return false; }
    };
    let frame = f.base().0 / mm::PAGE as u64;
    let after_alloc = mm::free_frames();
    let mut shares: [Option<mm::SharedFrame>; N] = core::array::from_fn(|_| None);
    for s in shares.iter_mut() {
        *s = Some(mm::frame_get(frame));
    }
    drop(f); // 独占主人放手：refcnt 1+N -> N，仍 >0，不归还
    let after_owner_drop = mm::free_frames();
    let mut mid_ok = true;
    for i in 0..N {
        drop(shares[i].take());
        let now = mm::free_frames();
        let expect = if i == N - 1 { base } else { after_alloc };
        if now != expect {
            crate::log_fatal!("refcount: 第 {} 个 put 后 free={} 期望 {}", i, now, expect);
            mid_ok = false;
        }
    }
    let extra = mm::frame_put(frame); // 已归还，再 put 必须 DoubleFree
    let live_back = crate::resource::live_of(mm::MOD_TEST) == live0;
    crate::log_info!(
        "refcount(P1c): N={} base={} alloc后={} 主人放手后={} 最后put回基线={} 多put={:?} live回基线={}",
        N, base, after_alloc, after_owner_drop, mm::free_frames() == base, extra, live_back);
    after_alloc == base - 1 && after_owner_drop == after_alloc && mid_ok
        && mm::free_frames() == base && extra == Err(mm::MmError::DoubleFree) && live_back
}
ktest!(KT_FRAME_REFCOUNT, t_frame_refcount_get_put);

/// P2（ADR-064）：KBuf 大块分配验收。9 档（64KiB–16MiB，2 的幂）逐档：
/// new→清零见证（写前首末字节 0）→写满 u64 图案→读回逐字同→drop→free_frames 与台账 live 回基线。
/// 反空转：alloc 后 free_frames 必须减少。new(0) 必须拒绝。写满/读回用 u64 字（8× 于逐字节，
/// 各档都是 8 的倍数无尾字节），图案覆盖每一字节，等价"写满读回逐字节同"。
fn t_kbuf_large_alloc() -> bool {
    if mm::KBuf::new(0, mm::MOD_TEST).is_ok() {
        crate::log_fatal!("kbuf: new(0) 居然成功");
        return false;
    }
    const PAT: u64 = 0x0123_4567_89ab_cdef;
    let pb = PAT.to_le_bytes();
    let sizes = [64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024,
        2 * 1024 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024, 16 * 1024 * 1024];
    let mut base_ok = true;
    let mut zero_ok = true;
    let mut content_ok = true;
    for &sz in sizes.iter() {
        let base = mm::free_frames();
        let live0 = crate::resource::live_of(mm::MOD_TEST);
        let mut buf = match mm::KBuf::new(sz, mm::MOD_TEST) {
            Ok(b) => b,
            Err(e) => { crate::log_fatal!("kbuf: {}KiB 分配失败 {:?}", sz / 1024, e); base_ok = false; break; }
        };
        let after_alloc = mm::free_frames();
        if buf.as_slice()[0] != 0 || buf.as_slice()[sz - 1] != 0 {
            zero_ok = false;
        }
        for c in buf.as_mut_slice().chunks_exact_mut(8) {
            c.copy_from_slice(&pb);
        }
        for c in buf.as_slice().chunks_exact(8) {
            if c != pb { content_ok = false; break; }
        }
        drop(buf);
        let after_free = mm::free_frames();
        let live_back = crate::resource::live_of(mm::MOD_TEST) == live0;
        if !(after_alloc < base && after_free == base && live_back) {
            crate::log_fatal!("kbuf: {}KiB 不回基线 base={} alloc={} free={} live回={}",
                sz / 1024, base, after_alloc, after_free, live_back);
            base_ok = false;
        }
    }
    crate::log_info!("kbuf(P2): 9档64KiB-16MiB 回基线={} 清零={} 写满读回={}", base_ok, zero_ok, content_ok);
    base_ok && zero_ok && content_ok
}
ktest!(KT_KBUF_LARGE, t_kbuf_large_alloc);

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

/// 共享帧多 put 必须升 L4（退出码 39）。只在 fault-put-double-free 注入构建里存在（P1c）。
#[cfg(feature = "fault-put-double-free")]
fn t_put_double_free_must_escalate() -> bool {
    crate::log_warn!("fault-put-double-free: 这条用例按设计对已归还的共享帧再 put 一次");
    mm::force_put_double_free_for_test()
}
#[cfg(feature = "fault-put-double-free")]
ktest!(KT_PUT_DOUBLE_FREE, t_put_double_free_must_escalate);

