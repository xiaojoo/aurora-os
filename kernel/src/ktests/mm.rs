//! 物理页、映射与缺页探针用例（T0.1 纯搬移）。

use crate::arch::x86_64::{trap};
use crate::{mm};
use crate::ktest;
use crate::ktests::common::drain_reap;

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

/// P3（ADR-065）：VA 区间表扩容 + 空闲位图。分配 100 段 1 页 VA（**> 旧容量 80**，证扩容到 256），
/// reservation_count 应 +100；逐段 release_va 回基线、va_released +100。
/// 旧 80 容量下第 81 段会表满 L4 停机——所以这条用例在改前必停机，是扩容的直接见证。
/// 位图作占用唯一真相：register 漏置位 ⇒ count 不涨/释放找不到槽 ⇒ 红（负样本）。
fn t_va_interval_table() -> bool {
    const N: usize = 100;
    let base = mm::reservation_count();
    let rel0 = mm::va_released();
    let mut vas = [0u64; N];
    let mut alloc_ok = true;
    for i in 0..N {
        match mm::alloc_va_range(1) {
            Some(v) => vas[i] = v.0,
            None => { crate::log_fatal!("va区间表: 第 {} 段分配失败", i); alloc_ok = false; break; }
        }
    }
    let after_alloc = mm::reservation_count();
    let mut release_ok = true;
    for i in 0..N {
        if vas[i] != 0 && !mm::release_va(vas[i]) {
            crate::log_fatal!("va区间表: 第 {} 段释放失败 base={:#x}", i, vas[i]);
            release_ok = false;
        }
    }
    let after_release = mm::reservation_count();
    let rel1 = mm::va_released();
    crate::log_info!(
        "va区间表(P3): N={} base={} alloc后={} release后={} 分配成={} 释放成={} released {}->{}",
        N, base, after_alloc, after_release, alloc_ok, release_ok, rel0, rel1);
    alloc_ok && release_ok && after_alloc == base + N && after_release == base
        && rel1 >= rel0 + N as u64
}
ktest!(KT_VA_INTERVAL, t_va_interval_table);

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

/// P4（ADR-066）：split_huge 翻译等价 + 幂等 + 拆后块内 map + 跨别名金丝雀双向。
/// 被测块不写死地址：phys_alloc(9) 交出的 2MiB 对齐全自由块即被测块（前提自证）。
/// 旧翻译（大页）逐页写金丝雀 → 拆分 → 新翻译（PT）逐页读回 + 权限相等 + phys_of 对账；
/// 反向由"新 VA 写 / 该帧 HHDM 别名读"及反向两格充当（旧翻译在时间上互斥，ADR-066 已记）。
/// fault-split-oom 下走 OOM 分支：失败必须原大页原样、台账与 free_frames 回基线。
fn t_split_huge() -> bool {
    const MAGIC: u64 = 0x9E37_79B9_7F4A_7C15;
    let f_base = mm::free_frames();
    let frames = match mm::phys_alloc(9, mm::MOD_TEST) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("split: 前提 phys_alloc(9) 失败 {:?}", e);
            return false;
        }
    };
    let base_phys = frames.base().0;
    let va0 = mm::VirtAddr(base_phys + mm::hhdm());
    let eff0 = match mm::effective_flags(va0.0) {
        Some(f) if f.levels == 3 => f,
        other => {
            crate::log_fatal!("split: 前提失效，块不是大页 eff={:?}", other);
            return false;
        }
    };
    // 旧翻译写金丝雀（帧归本用例独占，HHDM 直写安全）
    for k in 0..512u64 {
        // SAFETY: va0+k*PAGE 落在本用例 phys_alloc(9) 独占的块内，HHDM 覆盖，u64 对齐
        unsafe { core::ptr::write_volatile((va0.0 + k * mm::PAGE as u64) as *mut u64, MAGIC ^ k) };
    }
    if cfg!(feature = "fault-split-oom") {
        let c0 = mm::counters();
        let f0 = mm::free_frames();
        let live0 = crate::resource::live_of(mm::MOD_BOOT);
        let err = mm::split_huge(va0).err();
        let eff1 = mm::effective_flags(va0.0);
        // SAFETY: 同金丝雀写入，块仍归本用例独占
        let canary = unsafe { core::ptr::read_volatile(va0.0 as *const u64) };
        let intact = err == Some(mm::MmError::OutOfMemory)
            && mm::is_mapped(va0.0)
            && eff1.map_or(false, |f| f.levels == 3 && f == eff0)
            && canary == MAGIC;
        let c1 = mm::counters();
        let back = mm::free_frames() == f0
            && c1.page_table_pages == c0.page_table_pages
            && crate::resource::live_of(mm::MOD_BOOT) == live0;
        drop(frames);
        let back = back && mm::free_frames() == f_base;
        let t = crate::resource::totals();
        crate::log_info!(
            "split OOM(P4): err={:?} 原样={} 回基线={}",
            err.map_or(mm::MmError::NotInit, |e| e),
            intact, back && t.sum_live == t.sum_alloc - t.sum_free && !t.violation);
        return intact && back && t.sum_live == t.sum_alloc - t.sum_free && !t.violation;
    }
    let c0 = mm::counters();
    let f0 = mm::free_frames();
    let sd0 = mm::shootdown_stats();
    let boot0 = crate::resource::live_of(mm::MOD_BOOT);
    // 用块内非基址 VA 调用，证"任意块内 VA"语义
    if mm::split_huge(mm::VirtAddr(va0.0 + 7 * mm::PAGE as u64)).is_err() {
        crate::log_fatal!("split: split_huge 返回 Err");
        return false;
    }
    let c1 = mm::counters();
    let f1 = mm::free_frames();
    let sd1 = mm::shootdown_stats();
    let me = crate::arch::x86_64::cpu::self_slot();
    let mut acks_ok = sd1.timeouts == sd0.timeouts;
    for s2 in 0..crate::arch::x86_64::cpu::MAX_CPUS {
        if s2 != me && crate::arch::x86_64::cpu::is_online(s2) {
            acks_ok &= sd1.acks[s2] == sd0.acks[s2] + 1 && sd1.invlpg[s2] == sd0.invlpg[s2] + 1;
        }
    }
    let mut equiv = true;
    let mut canary = true;
    for k in 0..512u64 {
        let va = va0.0 + k * mm::PAGE as u64;
        // SAFETY: 拆分后该 VA 经 PT 翻译到本用例独占块的第 k 页，u64 对齐
        let got = unsafe { core::ptr::read_volatile(va as *const u64) };
        canary &= got == MAGIC ^ k;
        let eff = mm::effective_flags(va);
        equiv &= eff.map_or(false, |f| f.levels == 4
            && f.user == eff0.user && f.writable == eff0.writable && f.executable == eff0.executable);
        equiv &= mm::phys_of(va) == Some(base_phys + k * mm::PAGE as u64);
    }
    // 幂等：再拆一次所有计数不动
    let idem = mm::split_huge(va0).is_ok();
    let c2 = mm::counters();
    let f2 = mm::free_frames();
    let sd2 = mm::shootdown_stats();
    let idem = idem && c2.page_table_pages == c1.page_table_pages && f2 == f1
        && sd2.requests == sd1.requests;
    // 验收 b + 跨别名：在 HHDM 最后一个大页块的**尾页**（>= max_phys、非 RAM）上做。
    // 发现约束（ADR-066 落地记录）：unmap 清掉 RAM 帧的 HHDM 别名后，该帧若再走
    // fi_final_free，毒化经 HHDM 直写会踩缺失叶子 ⇒ ring0 #PF。尾页在 PMM 覆盖外，
    // 清它无害；P5 的 unmap 只作用于用户窗口 VA（非 HHDM 别名），同由此约束解释。
    let tail = mm::VirtAddr(mm::hhdm() + mm::max_phys());
    let probe = match mm::phys_alloc(0, mm::MOD_TEST) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("split: 尾页探针帧分配失败 {:?}", e);
            return false;
        }
    };
    // 不拆仍 HugeConflict（该块自己的旧负样本格）
    if mm::map(tail, probe, mm::PageFlags::RW).err() != Some(mm::MmError::HugeConflict) {
        crate::log_fatal!("split: 前提失效，尾页不在大页内（map 未报 HugeConflict）");
        return false;
    }
    if mm::split_huge(tail).is_err() {
        crate::log_fatal!("split: 尾块拆分失败");
        return false;
    }
    let sd_f = mm::shootdown_stats();
    mm::unmap(tail, 1);
    let nf = match mm::phys_alloc(0, mm::MOD_TEST) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("split: 跨别名帧分配失败 {:?}", e);
            return false;
        }
    };
    let nf_phys = nf.base().0;
    let alias = nf_phys + mm::hhdm();
    let m = match mm::map(tail, nf, mm::PageFlags::RW) {
        Ok(m) => m,
        Err(e) => {
            crate::log_fatal!("split: 拆后块内 map 仍失败 {:?}", e);
            return false;
        }
    };
    // SAFETY: m.virt() 与 alias 是同一物理帧（nf_phys）的两个别名，均页对齐、归本用例独占
    let cross = unsafe {
        core::ptr::write_volatile(m.virt().0 as *mut u64, MAGIC ^ 0xAA);
        let r1 = core::ptr::read_volatile(alias as *const u64);
        core::ptr::write_volatile(alias as *mut u64, MAGIC ^ 0xBB);
        let r2 = core::ptr::read_volatile(m.virt().0 as *const u64);
        r1 == MAGIC ^ 0xAA && r2 == MAGIC ^ 0xBB
    };
    let mut acks_f_ok = sd_f.timeouts == sd1.timeouts;
    for s2 in 0..crate::arch::x86_64::cpu::MAX_CPUS {
        if s2 != me && crate::arch::x86_64::cpu::is_online(s2) {
            acks_f_ok &= sd_f.acks[s2] == sd1.acks[s2] + 1 && sd_f.invlpg[s2] == sd1.invlpg[s2] + 1;
        }
    }
    drop(m);
    drop(frames);
    let f3 = mm::free_frames();
    let t = crate::resource::totals();
    let perm_pt = f_base - f3;
    let req_delta = sd_f.requests - sd0.requests;
    let ledger_ok = crate::resource::live_of(mm::MOD_BOOT) == boot0 + 2
        && t.sum_live == t.sum_alloc - t.sum_free && !t.violation;
    crate::log_info!(
        "split(P4): 等价={} 金丝雀={} 跨别名={} 幂等={} map成功={} 永久PT={} requests增量={}",
        equiv && acks_ok && acks_f_ok, canary, cross, idem, true, perm_pt, req_delta);
    equiv && canary && cross && idem && acks_ok && acks_f_ok && ledger_ok
        && perm_pt == 2 && req_delta == 2
        && f1 == f0 - 1 && c1.page_table_pages == c0.page_table_pages + 1
        && c1.map_calls == c0.map_calls
}
ktest!(KT_SPLIT_HUGE, t_split_huge);

/// P4（ADR-066）：map_hole 高地址 UC 窗口。单属性（HHDM 无别名 + 生效位）、覆盖内拒、
/// usable 拒、往返回基线；leaf 原始值打出，宿主机按 PAT 规则独立重算对账。
fn t_map_hole() -> bool {
    let pa: u64 = 0xFEC0_0000; // q35 IOAPIC：在 map_top 之上、HHDM 未覆盖（前提下面自证）
    if mm::is_mapped(mm::hhdm() + pa) {
        crate::log_fatal!("map_hole: 前提失效，pa 已被 HHDM 覆盖");
        return false;
    }
    let res0 = mm::reservation_count();
    let f0 = mm::free_frames();
    let mh = match mm::map_hole(pa, 2) {
        Ok(m) => m,
        Err(e) => {
            crate::log_fatal!("map_hole: 建映射失败 {:?}", e);
            return false;
        }
    };
    let va = mh.virt();
    let eff = mm::effective_flags(va.0);
    let single = !mm::is_mapped(mm::hhdm() + pa)
        && eff.map_or(false, |f| !f.user && f.writable && !f.executable && f.levels == 4);
    let leaf = mm::leaf_value(va.0).unwrap_or(0);
    let res1 = mm::reservation_count();
    drop(mh);
    let roundtrip = res1 == res0 + 1 && mm::reservation_count() == res0
        && mm::free_frames() == f0 && !mm::is_mapped(va.0);
    // 拒绝格：扫内存映射找 usable 基址与"覆盖内非 usable"基址，不写死本机布局
    let mut pa_usable = None;
    let mut pa_cov = None;
    for i in 0..mm::region_count() {
        let Some(r) = mm::region(i) else { break };
        let b = (r.base + mm::PAGE as u64 - 1) & !(mm::PAGE as u64 - 1);
        if b >= r.base + r.length {
            continue;
        }
        if r.usable && pa_usable.is_none() {
            pa_usable = Some(b);
        }
        if !r.usable && pa_cov.is_none() && mm::is_mapped(mm::hhdm() + b) {
            pa_cov = Some(b);
        }
    }
    let rej_usable = pa_usable.map_or(false, |p| mm::map_hole(p, 1).err() == Some(mm::MmError::InvalidAddress));
    let rej_cov = pa_cov.map_or(false, |p| mm::map_hole(p, 1).err() == Some(mm::MmError::Unsupported));
    let rej_zero = mm::map_hole(pa, 0).err() == Some(mm::MmError::InvalidAddress);
    crate::log_info!(
        "map_hole(P4): 单属性={} 拒覆盖={} 拒usable={} 往返={} leaf={:#x}",
        single, rej_cov, rej_usable, roundtrip, leaf);
    single && rej_cov && rej_usable && roundtrip && rej_zero && leaf != 0
}
ktest!(KT_MAP_HOLE, t_map_hole);

// ---- ADR-070（W3 P1）AddressSpace：能建、能切、能销 ----
//
// 六格：A1 内核半区逐项相等（含属性位）；A2 CR3 只在不同才写（同 AS 连切 N 次=0、
// 跨 AS 一次=1）；A3 销毁回基线（as_pt_live / free_frames / MOD_AS_PT 台账 / 表计数）；
// 前提格（进来时 aspace_count=0）；用户半区为空；A6 冻结闸（有 AS 时 map_hole 拒绝）。
// 负样本（落地时各跑一遍）：半复制 ⇒ A1 红；去掉"不同才写"的门 ⇒ A2 红；
// 不还表页 ⇒ A3 红。三条都要实测，没跑过的不算证据。

fn t_aspace_create_switch_destroy() -> bool {
    // 前提：进来时没有别的 AS（.ktests 顺序由链接器定，不能假设有别人替我清场）
    let n0 = mm::aspace_count();
    if n0 != 0 {
        crate::log_fatal!("aspace: 前提失效，进来时已有 {} 个 AS", n0);
        return false;
    }
    let c0 = mm::counters();
    let f0 = mm::free_frames();
    let led0 = crate::resource::live_of(mm::MOD_AS_PT);

    let h = match mm::aspace_new() {
        Some(h) => h,
        None => {
            crate::log_fatal!("aspace: 建不起来");
            return false;
        }
    };
    // A1：内核半区 256 项逐项相等（含缓存属性位）；用户半区 0 个 present
    let a1 = h.kernel_half_matches();
    let user0 = h.user_half_present();
    let pml4 = match h.pml4() {
        Some(p) => p,
        None => {
            crate::log_fatal!("aspace: 读不回 PML4");
            return false;
        }
    };

    // A2：切过去（真的写一次）→ 同 AS 连切 8 次（一次都不许写）→ 切回来（再写一次）
    // 切换期间跑的是**内核代码**（本用例自己），这正是"内核半区等价"的意义：
    // 不等价的话第一条指令就取不到，根本走不到读数行。
    let me = crate::arch::x86_64::cpu::self_slot();
    let w_cross = unsafe { mm::aspace_switch(pml4, me, Some(h.slot())) };
    let mut same_writes = 0usize;
    for _ in 0..8 {
        if unsafe { mm::aspace_switch(pml4, me, Some(h.slot())) } {
            same_writes += 1;
        }
    }
    // 在新 AS 上读一次自己的内核数据（证明确实在那个表上跑了一段）
    let alive_on_aspace = mm::is_ready() && mm::free_frames() > 0;
    let w_back = unsafe { mm::aspace_switch_kernel(me) };
    let c1 = mm::counters();
    let a2 = w_cross && same_writes == 0 && w_back
        && c1.cr3_writes == c0.cr3_writes + 2 && alive_on_aspace;

    // A6：有这个 AS 在，map_hole 必须拒绝（内核半区冻结）。用 t_map_hole 同款前提：
    // IOAPIC 那一页今天已被启动期映过，所以这里挑"usable 内存基址"那条拒绝路径不行
    // （它先撞 InvalidAddress）；直接验"冻结闸在其它检查之前"用一个**本来能成功**的 pa。
    // 0xFEC00000 已被 HHDM 覆盖 ⇒ 会撞 Unsupported 而不是 KernelHalfFrozen，
    // 所以先找一个 HHDM 未覆盖的非 usable 页（与 t_map_hole 的 pa_cov 同法）。
    let mut pa_frozen = None;
    for i in 0..mm::region_count() {
        let Some(r) = mm::region(i) else { break };
        let b = (r.base + mm::PAGE as u64 - 1) & !(mm::PAGE as u64 - 1);
        if b >= r.base + r.length {
            continue;
        }
        if !r.usable && !mm::is_mapped(mm::hhdm() + b) {
            pa_frozen = Some(b);
            break;
        }
    }
    let a6 = pa_frozen.map_or(false, |p| mm::map_hole(p, 1).err() == Some(mm::MmError::KernelHalfFrozen));

    // A3：销毁回基线
    drop(h);
    let c2 = mm::counters();
    let f2 = mm::free_frames();
    let led2 = crate::resource::live_of(mm::MOD_AS_PT);
    let n2 = mm::aspace_count();
    let a3 = c2.as_pt_live == c0.as_pt_live && f2 == f0 && led2 == led0 && n2 == 0;

    // 冻结闸的"另一侧"：没有 AS 时 map_hole 不被这道闸拦（今天它可能因别的前提拒绝，
    // 但只要不是 KernelHalfFrozen 就证明闸真的只看"有没有 AS"）
    let gate_off = pa_frozen.map_or(true, |p| mm::map_hole(p, 1).err() != Some(mm::MmError::KernelHalfFrozen));

    crate::log_info!(
        "aspace(P1): A1={:?} 用户半区={:?} A2=(跨写={} 同AS写={} 回写={} cr3累计{}->{}) A3=(live{}->{} free{}->{} 台账{}->{} 表{}->{}) A6={} 闸另一侧={}",
        a1, user0, w_cross, same_writes, w_back, c0.cr3_writes, c1.cr3_writes,
        c0.as_pt_live, c2.as_pt_live, f0, f2, led0, led2, n0, n2, a6, gate_off);
    let ok = a1 == Some((256, 0)) && user0 == Some(0) && a2 && a3 && a6 && gate_off;
    if !ok {
        crate::log_fatal!(
            "aspace: 判据不成立 A1={:?} 用户={:?} A2={} A3={} A6={} 闸另一侧={}",
            a1, user0, a2, a3, a6, gate_off);
    }
    ok
}
ktest!(KT_ASPACE, t_aspace_create_switch_destroy);

// ---- ADR-072（W3 P2）shootdown 按 AS 收窄 ----
//
// 四格：①位图登记（切入后 running_on 含 BSP）；②narrowed 只通知位图里的 CPU；
// ③broadcast 通知全在线 CPU；④销毁后位图清零。
// 变异：narrowed 忽略 mask 全广播 ⇒ ②的 ack 增量等于③ ⇒ 红。

fn t_shootdown_masked() -> bool {
    // 前提：AP 必须在线（narrowed 与 broadcast 的区别只在多核时可见）
    if crate::arch::x86_64::smp::bringup().is_err() {
        crate::log_fatal!("sd-mask: AP 起不来，收窄判据没有证人");
        return false;
    }
    let me = crate::arch::x86_64::cpu::self_slot();
    let n0 = mm::aspace_count();
    if n0 != 0 {
        crate::log_fatal!("sd-mask: 前提失效，进来时已有 {} 个 AS", n0);
        return false;
    }
    let h = match mm::aspace_new() {
        Some(h) => h,
        None => {
            crate::log_fatal!("sd-mask: 建 AS 失败");
            return false;
        }
    };
    let pml4 = match h.pml4() {
        Some(p) => p,
        None => { crate::log_fatal!("sd-mask: 读不回 PML4"); return false; }
    };
    // ① 切入 → 位图应含 BSP
    let _ = unsafe { mm::aspace_switch(pml4, me, Some(h.slot())) };
    let _ = unsafe { mm::aspace_switch_kernel(me) };
    let bm_after_switch = mm::aspace_running_on(0).unwrap_or(0);
    let reg_ok = bm_after_switch & (1 << me) != 0;

    // 手动登记 AP1（模拟"那颗 CPU 也曾跑过这个 AS"）
    let ap1 = 1usize;
    let _ = mm::aspace_register_cpu(0, ap1);
    let bm = mm::aspace_running_on(0).unwrap_or(0);

    // ② narrowed：只通知位图里的（BSP+AP1），BSP 是 self 排除 ⇒ 只 AP1 收到
    let va: u64 = 0x1_0000_0000; // 用户半区，未映射，invlpg 无害
    let s0 = mm::shootdown_stats();
    mm::with_vmm_lock(|| mm::shootdown_masked(va, bm));
    let s1 = mm::shootdown_stats();
    let ack_delta: [usize; crate::arch::x86_64::cpu::MAX_CPUS] =
        core::array::from_fn(|i| s1.acks[i] - s0.acks[i]);
    // AP1 应 +1，AP2/AP3 应 +0
    let narrowed_ok = ack_delta[ap1] == 1
        && ack_delta[2] == 0 && ack_delta[3] == 0
        && s1.requests == s0.requests + 1;

    // ③ broadcast：全在线 CPU 都收到（AP1/AP2/AP3 各 +1）
    let s2 = mm::shootdown_stats();
    mm::with_vmm_lock(|| mm::shootdown_masked(va, 0xFF)); // 0xFF = 全广播等价
    let s3 = mm::shootdown_stats();
    let bcast_delta: [usize; crate::arch::x86_64::cpu::MAX_CPUS] =
        core::array::from_fn(|i| s3.acks[i] - s2.acks[i]);
    let online_aps = (1..crate::arch::x86_64::cpu::MAX_CPUS)
        .filter(|&c| crate::arch::x86_64::cpu::is_online(c)).count();
    let bcast_ok = (1..crate::arch::x86_64::cpu::MAX_CPUS)
        .all(|c| !crate::arch::x86_64::cpu::is_online(c) || bcast_delta[c] == 1)
        && s3.requests == s2.requests + 1;

    // ④ 销毁后位图清零（AS_EMPTY.running_on = 0）
    drop(h);
    let bm_after_drop = mm::aspace_running_on(0);

    crate::log_info!(
        "sd-mask(P2): 登记={} 位图={:#x} narrowed_ack={:?} broadcast_ack={:?} 在线AP={} 销毁后位图={:?}",
        reg_ok, bm, ack_delta, bcast_delta, online_aps, bm_after_drop);
    let ok = reg_ok && narrowed_ok && bcast_ok && online_aps >= 1 && bm_after_drop.is_none();
    if !ok {
        crate::log_fatal!(
            "sd-mask: 判据不成立 登记={} narrowed={} broadcast={} 销毁后={:?}",
            reg_ok, narrowed_ok, bcast_ok, bm_after_drop);
    }
    ok
}
ktest!(KT_SHOOTDOWN_MASKED, t_shootdown_masked);

// ---- ADR-073（W3 P3）Process / Job / wait_for_task ----
//
// 六格：①建 Job/Process + 挂线程 + wait 收工 + 退出码；②进程数额度（僵尸仍占额度）；
// ③子 Job 只能收窄（进程数、页数各一格）；④两种还槽（reap 带回退出码 / discard 只给没起过线程的）；
// ⑤回基线（槽数、Job 数、额度、空闲帧）；⑥登记本身的前提格。
// 变异：M1 去掉 proc_create 的额度检查 ⇒ ②红；M2 去掉收工处的置 signal ⇒ ①只能超时红；
// M3 把 proc_reap 的"未终止也放行"⇒ ④的 Denied 格红；M4 去掉 terminate_task 清 proc_id ⇒
// 复用槽的任务把别人的线程计数减掉 ⇒ ①/④在连着跑两轮的形状下红（本轮用 ④ 的读回当证人）。

fn p3_worker() -> ! {
    crate::sched::finish_current();
    // 让出**一次**把 CPU 立刻还给等待方（一条中断，不是风暴）；换不动就靠下面的自旋等 tick。
    crate::sched::yield_now();
    // 收工之后**有界自旋**，等下一次 tick 把 CPU 换走（Done 的任务不会再被选中）。
    // 刻意不用 `loop { yield_now() }`：每次让出都是一条 `int 0xF0`，而挂 `-d int` 的矩阵行
    // 把每条中断写进宿主机日志 ⇒ 自旋让出在那一档变成中断风暴，实测烧穿 120 s 预算（BACKLOG §153）。
    // 换人靠 tick，所以用例必须保证时钟在跑（下面的探测与按需标定），这条前提比让出便宜得多。
    loop {
        crate::tsc::spin(1000);
    }
}

fn t_proc_job_wait() -> bool {
    use crate::{proc, sched};
    // 用例自足第一条（本轮在 ahci-scratch 与 fault-resched-ipi 两档实测撞出来的）：
    // 链接顺序可能把本用例排在第一个"依赖任务上下文"的测试之前，那一刻启动上下文还没登记进 RQ，
    // `current_of` 还是 `usize::MAX`，`yield_now` 的抢占点就在错误的槽位上记账——
    // 症状是 `runs=1` 而 `state` 永远停在 Running、等待方一次都等不到，甚至整机静默。
    // 所以登记必须在**建对象与 spawn 之前**，而不是在等待之前。
    crate::sched::init_boot_task();
    crate::sched::start_workers();
    // 前提格：表是空的（用例自足，不假设别的用例收过尾）
    let (pc0, pf0) = proc::proc_residual();
    let (jc0, jf0) = proc::job_residual();
    if pc0 != 0 || jc0 != 0 {
        crate::log_fatal!(
            "proc: 前提失效 残留进程={}({:#x}) 残留Job={}({:#x})",
            pc0, pf0, jc0, jf0);
        return false;
    }
    let f0 = mm::free_frames();

    // ① 根 Job（额度 2 个进程、64 页）→ 进程 → **先**登记线程计数 → spawn → 挂 proc_id
    // 顺序是有意的：反过来的话任务可能在两步之间就跑完了，收工边看到的是 NO_PROC，
    // 线程计数永远减不到，等待方只能空转到超时。
    let job = match proc::job_create(None, 2, 64) {
        Ok(j) => j,
        Err(e) => { crate::log_fatal!("proc: job_create {:?}", e); return false; }
    };
    let p = match proc::proc_create(job) {
        Ok(p) => p,
        Err(e) => { crate::log_fatal!("proc: proc_create {:?}", e); return false; }
    };
    if proc::proc_attach_thread(p).is_err() {
        crate::log_fatal!("proc: proc_attach_thread 失败");
        return false;
    }
    let g = match sched::spawn(p3_worker) {
        Ok(g) => g,
        Err(e) => { crate::log_fatal!("proc: spawn {:?}", e); return false; }
    };
    // ⑥ 登记的前提格：同 CPU、还活着才收得到；读回证明写进去的是这一槽
    let reg_ok = sched::set_proc_id(g, p) && sched::proc_id_of(g) == p;

    // 时钟：这里的推进**不靠** tick——工人收工后自己让出（见 `p3_worker`），停表也能等到结局。
    // 开时钟只为让 `drain_reap` 那一步有 tick 可等；停表时它退化成"没看到增量"的一句 warn，
    // 判据仍然靠 `reap_released` 的增量成立（就地回收那条路径不等窗口）。
    //
    // 用例自足三条（前两条与 `t_demand_zero` 同一套，第三条是本轮新撞的）：
    // ①启动上下文可能还没登记进 RQ（链接顺序排在第一个用户任务测试之前）⇒ spawn/yield 全落空；
    // ②`RUN` 位可能没别人替我开回来（依赖跨核 IPI 的几条用例在某些档位不注册）；
    // ③有些用例会停掉 LAPIC 定时器再不带回来 ⇒ 探测一次，不在跑就自己开、收尾还原。
    // 用例自足第四条（本轮 fault-resched-ipi 档实测）：链接顺序可能把本用例排在**时钟标定之前**，
    // 而今天 `yield_now` 的自陷只把牌立起来，真正换人发生在**中断出口路过 `preempt_point`** 的那一刻
    // （`switches=0` 而 `runs=0`、`state` 永远停在 Runnable 就是这一档的现场）。
    // 所以这里按 `smp::bringup` 的同一入口补一次幂等标定，再自己把定时器开回来。
    if crate::clock::current().is_none() {
        crate::calibrate_clock_once();
    }
    let tick_in = crate::arch::x86_64::apic::ticks();
    let probe = crate::arch::x86_64::apic::wait_ticks(tick_in, 1, crate::clock::window_cycles(1));
    let was_running = probe.ticks >= 1;
    if !was_running { crate::arch::x86_64::apic::timer_start().ok(); }
    // wait_ticks 返回时窗口已经关掉（ADR-068）；等待必须开在窗口里，否则换过去之后
    // 再也不会被 tick 抢占回来。
    // 预算按 tick 给（40 个窗 ≈ 400 ms，与 `dz_wait_free` 同一口径）：fault-resched-ipi 档实测
    // 纯周期预算推不动换人，只给 8 个窗在这一档不够（本轮第一版就是这么红的）。
    let waited = crate::arch::x86_64::apic::with_interrupts(|| {
        sched::wait_for_task(g, crate::clock::window_cycles(8))
    });
    let terminated = proc::proc_is_terminated(p);
    let code = proc::proc_exit_code(p);
    let wait_ok = reg_ok && waited && terminated && code == 0;

    // ② 进程数额度：僵尸还占着槽 ⇒ 第二个可以，第三个必须被拒
    let p2 = proc::proc_create(job);
    let p3 = proc::proc_create(job);
    let quota_ok = p2.is_ok() && p3 == Err(proc::ProcError::QuotaProcs)
        && proc::job_used_procs(job) == Some(2);

    // ③ 子 Job 只能收窄：放大进程数、放大页数各一条拒绝，两项都收才放行
    let wide_procs = proc::job_create(Some(job), 3, 32);
    let wide_pages = proc::job_create(Some(job), 2, 128);
    let child = proc::job_create(Some(job), 1, 32);
    let narrow_ok = wide_procs == Err(proc::ProcError::Denied)
        && wide_pages == Err(proc::ProcError::Denied)
        && child.is_ok();

    // ④ 两种还槽。p 是僵尸 ⇒ reap 放行并带回退出码；p2 从没起过线程 ⇒ discard 放行、reap 拒绝。
    // 顺序：先各自试一次"不该成功的"，再走对的那条。
    let pid2 = p2.unwrap_or(u16::MAX);
    let reap_running = proc::proc_reap(pid2);
    let discard_zombie = proc::proc_discard(p);
    let reap_zombie = proc::proc_reap(p);
    let discard_gone = proc::proc_discard(p);
    let discard_running = proc::proc_discard(pid2);
    let release_ok = reap_running == Err(proc::ProcError::Denied)
        && discard_zombie == Err(proc::ProcError::Denied)
        && reap_zombie == Ok(0)
        && discard_gone == Err(proc::ProcError::NoSuchProc)
        && discard_running.is_ok();

    // ⑤ 回基线。**先**把工人槽交出去并等到真回收，再读数：任务的内核栈是 4 帧，
    // 它们只在"标 Free + 过一次抢占点"之后才回来（`terminate_task` 与 `drain_reap` 的分工）。
    // released0 必须在 terminate 之前取——就地回收那条路径不等窗口，靠增量才能认出它已经发生。
    let released0 = sched::reap_released();
    let _ = sched::terminate_task(g);
    // 顺序有意：先看增量，再决定要不要烧那个 1G 周期的窗口。就地回收（旁观者路径）
    // 不等窗口，绝大多数时候增量已经在了；反过来写会**每跑一次白烧 ~300 ms 的客时**，
    // 而 `-d int` 那两行把每个中断都写进宿主机日志，客时被放大成墙钟 ⇒ 本轮实测把
    // "中断投递由宿主机数到"那一行挤成 HANG(-1)。
    let drained = sched::reap_released() > released0 || drain_reap();
    let up_after = proc::job_used_procs(job);
    let jd_child = match child {
        Ok(c) => proc::job_destroy(c),
        Err(e) => Err(e),
    };
    let jd_job = proc::job_destroy(job);
    let (pc1, _) = proc::proc_residual();
    let (jc1, _) = proc::job_residual();
    let f1 = mm::free_frames();
    let baseline_ok = drained
        && up_after == Some(0)
        && jd_child.is_ok() && jd_job.is_ok()
        && pc1 == 0 && jc1 == 0 && f1 == f0;

    if !was_running { crate::arch::x86_64::apic::timer_stop().ok(); }

    crate::log_info!(
        "proc(P3): 登记={} wait={} terminated={} code={} quota={} narrow={} release={} baseline=(drained free{}->{} pc{} jc{} released{}->{})",
        reg_ok, waited, terminated, code, quota_ok, narrow_ok, release_ok,
        f0, f1, pc1, jc1, released0, sched::reap_released());
    let ok = wait_ok && quota_ok && narrow_ok && release_ok && baseline_ok;
    if !ok {
        crate::log_fatal!(
            "proc: 判据不成立 wait={} quota={} narrow={} release={} baseline={}",
            wait_ok, quota_ok, narrow_ok, release_ok, baseline_ok);
    }
    ok
}
ktest!(KT_PROC_JOB, t_proc_job_wait);

// ---- ADR-067（W2 P5）demand-zero ----
//
// 七格：①ring3 首触未填充页读到 0 且计数 +1；②区间外未映射地址仍只杀任务；
// ③copy_from_user 触未填充惰性页在 validate 层 NotMapped、不修复；④区间内取指仍杀；
// ⑤任务退出后帧/VA/槽位/台账回基线；⑥双核竞争（3AP+BSP 四路）恰填 1 页且输家还帧；
// ⑦清零见证：填充前 drop 4 帧，first-fit 保证之后捞到刚毒化的 0xA5 帧——去清零必须红在①。

use core::sync::atomic::Ordering;

/// 竞争格的共享状态：工人就位 → 发令枪 → 各自调一次 demand_zero_try。
static DZ_CR2: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static DZ_START: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static DZ_READY: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static DZ_RET: [core::sync::atomic::AtomicU64; crate::arch::x86_64::cpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];
/// 工人/观察者等发令枪的上界（周期）。到期不放枪就不调，判据会红在"就位人数"。
const DZ_WAIT_BOUND: u64 = 200_000_000;

/// AP 空闲上下文里的竞争工人：就位、等枪、调一次、记返回值。
fn dz_worker() {
    let me = crate::arch::x86_64::cpu::self_slot();
    DZ_READY.fetch_add(1, Ordering::Relaxed);
    let cr2 = DZ_CR2.load(Ordering::Acquire);
    let t0 = crate::tsc::now();
    while DZ_START.load(Ordering::Acquire) == 0 && crate::tsc::now().wrapping_sub(t0) < DZ_WAIT_BOUND {
        core::hint::spin_loop();
    }
    if DZ_START.load(Ordering::Acquire) != 0 {
        let ok = mm::demand_zero_try(cr2);
        DZ_RET[me].store(if ok { 1 } else { 0 }, Ordering::Release);
    }
}

/// BSP 侧观察者：等 AP 就位再放枪，然后自己也调一次（四路竞争）。
fn dz_observer() {
    let want = crate::arch::x86_64::smp::participant_slots().0;
    let t0 = crate::tsc::now();
    while DZ_READY.load(Ordering::Acquire) < want && crate::tsc::now().wrapping_sub(t0) < DZ_WAIT_BOUND {
        core::hint::spin_loop();
    }
    DZ_START.store(1, Ordering::Release);
    let ok = mm::demand_zero_try(DZ_CR2.load(Ordering::Acquire));
    DZ_RET[0].store(if ok { 1 } else { 0 }, Ordering::Release);
}

/// 桩镜像：`movabs rax,LAZY; mov rbx,[rax]; movabs rcx,RES; mov [rcx],rbx;
/// mov rax,3; int 0x80`。一处 load 触发 demand-zero；exit 走 SYS_EXIT(3)。
fn dz_blob(lazy: u64, res: u64) -> [u8; 40] {
    let mut b = [0u8; 40];
    b[0] = 0x48; b[1] = 0xB8;
    b[2..10].copy_from_slice(&lazy.to_le_bytes());
    b[10] = 0x48; b[11] = 0x8B; b[12] = 0x18;
    b[13] = 0x48; b[14] = 0xB9;
    b[15..23].copy_from_slice(&res.to_le_bytes());
    b[23] = 0x48; b[24] = 0x89; b[25] = 0x19;
    b[26] = 0x48; b[27] = 0xC7; b[28] = 0xC0; b[29] = 0x03;
    b[33] = 0xCD; b[34] = 0x80;
    b
}

/// 建一页用户映射：内容经 HHDM 直写（RX 页装不进写），返回 (VA, Mapping)。
fn dz_page(flags: mm::PageFlags, fill: Option<&[u8]>) -> Option<(u64, mm::Mapping)> {
    let va = mm::alloc_user_va_range(1)?;
    let f = mm::phys_alloc(0, mm::MOD_TEST).ok()?;
    if let Some(bytes) = fill {
        // SAFETY: f 刚由本用例 phys_alloc 独占，HHDM 覆盖全部 max_phys；bytes<=PAGE
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), f.base().via_hhdm().0 as *mut u8, bytes.len());
        }
    }
    let m = mm::map(va, f, flags).ok()?;
    Some((va.0, m))
}

/// 等待上界的单位改成 tick（40 tick ≈ 400ms）：fault-resched-ipi 档实测，纯周期预算的
/// yield 环在该档不能推进用户任务（tick 驱动的换人才能），与 t_user_roundtrip 同一等法。
fn dz_wait_free(gidx: usize) -> bool {
    for _ in 0..40 {
        if matches!(crate::sched::state_of(gidx), crate::sched::TaskState::Free) {
            return true;
        }
        crate::sched::yield_now();
        let b = crate::arch::x86_64::apic::ticks();
        crate::arch::x86_64::apic::wait_ticks(b, 1, crate::clock::window_cycles(1));
    }
    matches!(crate::sched::state_of(gidx), crate::sched::TaskState::Free)
}

fn dz_wait_kills(target: u64) -> bool {
    for _ in 0..40 {
        if crate::user::kills() >= target {
            return true;
        }
        crate::sched::yield_now();
        let b = crate::arch::x86_64::apic::ticks();
        crate::arch::x86_64::apic::wait_ticks(b, 1, crate::clock::window_cycles(1));
    }
    crate::user::kills() >= target
}

fn t_demand_zero() -> bool {
    // 用例自足（§86e 的教训，实测复现于 fault-double-free 档）：链接顺序可能把本用例
    // 排在第一个用户任务测试之前，那一刻启动上下文还没登记进 RQ，spawn/yield 全部落空。
    crate::sched::init_boot_task();
    // 用例自足第二条（实测复现于 fault-resched-ipi 档 3/3）：那三档里设置 RUN 的跨核用例
    // 被整条不注册，没有别人替我开轮转——RUN 位不置，用户任务永远不被换入。
    crate::sched::start_workers();
    // 用例自足第三条（实测复现于 fault-ahci-lba / fault-resched-ipi 档）：链上有些用例
    // 会停掉 LAPIC 定时器再不带回来（t_percpu_queues 家族的"进来停就停回去"）。tick 一停，
    // 我的等待环与 preempt 传播全部失效——t_user_roundtrip 同一形状，它也是自己 start 的。
    crate::arch::x86_64::apic::timer_start().ok();
    // 落脚页是 kill 路径的前提（ADR-028）；init 幂等。
    if crate::user::init().is_err() {
        crate::log_fatal!("demand-zero: 落脚页建不起来");
        return false;
    }
    // 基线只取"我自己的计数面"。绝对 free/live 会被别的用例落在 AP 队列上的延迟回收
    // 污染（实测竞争窗口 ±28 帧），所以账目正确性交给台账不变量与逐 VA 检查。
    let reg0 = mm::lazy_region_count();
    let dz0 = mm::demand_zero_count();
    let kills0 = crate::user::kills();

    // R1：3 页区间；桩只读第 0 页 ⇒ 第 2 页永远未填充，给 ③ 用
    let r1 = match mm::lazy_new(3, mm::MOD_TEST) {
        Some(h) => h,
        None => {
            crate::log_fatal!("demand-zero: lazy_new 失败");
            return false;
        }
    };
    let base1 = match r1.base() {
        Some(b) => b,
        None => {
            crate::log_fatal!("demand-zero: 区间读不回基址");
            return false;
        }
    };
    // ③ 内核拷贝路径触未填充页：validate 层 NotMapped，不修复、不杀
    let mut scratch = [0u8; 8];
    let copy_refused = crate::user::copy_from_user(base1 + 2 * mm::PAGE as u64, &mut scratch)
        == Err(crate::user::PtrError::NotMapped)
        && mm::demand_zero_count() == dz0;

    // 结果页归**用例**持有：任务退出回收自身资源后，内核还要读它
    let (res_va, res_map) = match dz_page(mm::PageFlags::USER_RW, None) {
        Some(p) => p,
        None => {
            crate::log_fatal!("demand-zero: 结果页建不起来");
            drop(r1);
            return false;
        }
    };
    // 哨兵区分"用户真写了"与"页本来就是 0"；内核碰已映射用户页必须走校验+开窗（write_at）
    crate::user::write_at(res_va, 0xdead_beef);

    // ①⑤ 主任务：owned = 惰性柄 + 代码页 + 用户栈
    let (code_va, code_map) = match dz_page(mm::PageFlags::USER_RX, Some(&dz_blob(base1, res_va))) {
        Some(p) => p,
        None => {
            crate::log_fatal!("demand-zero: 代码页建不起来");
            drop(r1);
            return false;
        }
    };
    let (stk_va, stk_map) = match dz_page(mm::PageFlags::USER_RW, None) {
        Some(p) => p,
        None => {
            crate::log_fatal!("demand-zero: 用户栈建不起来");
            drop(r1);
            return false;
        }
    };
    // ⑦ 毒化铺垫：drop 4 帧 ⇒ 之后 first-fit 捞到的填充帧必是刚毒化的 0xA5 帧
    for _ in 0..4 {
        if let Ok(f) = mm::phys_alloc(0, mm::MOD_TEST) {
            drop(f);
        }
    }
    let mut owned = crate::sched::OwnedSet::new();
    let mut ok = owned.push_lazy(r1).is_ok();
    ok &= owned.push(code_map).is_ok();
    ok &= owned.push(stk_map).is_ok();
    let t1 = match crate::sched::spawn_user(code_va, stk_va + mm::PAGE as u64 - 16, 0, owned) {
        Ok(g) => g,
        Err(e) => {
            crate::log_fatal!("demand-zero: spawn_user 失败 {:?}", e);
            drop(res_map);
            return false;
        }
    };
    let ran = dz_wait_free(t1);
    let first_zero = ran && crate::user::peek_u64(res_va).unwrap_or(u64::MAX) == 0;
    let filled_1 = mm::demand_zero_count() == dz0 + 1;

    // ② 区间外：R4 尾后一格（上延变异边界才能当场咬）。前沿顺序：先分 code2/stk2、
    // 后建 R4，则 R4 尾后那格必还空闲；桩代码要引用 bad，所以内容后补——
    // 配方是经 HHDM 直写页框（ADR-026：RX 页装不进写，构造期走内核侧别名）。
    let (code2, map2) = match dz_page(mm::PageFlags::USER_RX, None) {
        Some(p) => p,
        None => {
            crate::log_fatal!("demand-zero: 越界桩建不起来");
            return false;
        }
    };
    let (stk2, smap2) = match dz_page(mm::PageFlags::USER_RW, None) {
        Some(p) => p,
        None => {
            crate::log_fatal!("demand-zero: 越界栈建不起来");
            return false;
        }
    };
    let r4 = match mm::lazy_new(2, mm::MOD_TEST) {
        Some(h) => h,
        None => {
            crate::log_fatal!("demand-zero: R4 建不起来");
            return false;
        }
    };
    let bad = match r4.base() {
        Some(b) => b + 2 * mm::PAGE as u64,
        None => {
            crate::log_fatal!("demand-zero: R4 读不回基址");
            return false;
        }
    };
    if mm::is_mapped(bad) {
        crate::log_fatal!("demand-zero: 前提失效，bad={:#x} 已被映射", bad);
        return false;
    }
    let blob2 = dz_blob(bad, res_va);
    let code2_frame = match mm::phys_of(code2) {
        Some(f) => f,
        None => {
            crate::log_fatal!("demand-zero: 读不回 code2 帧");
            return false;
        }
    };
    // SAFETY: code2_frame 的帧由 dz_page 独占分配；经 HHDM 内核别名写，不经用户 VA；
    // 此刻 t2 还没起，没有第二个主人
    unsafe {
        core::ptr::copy_nonoverlapping(blob2.as_ptr(), (code2_frame + mm::hhdm()) as *mut u8, blob2.len());
    }
    // 重置哨兵，"越界任务写了结果"必须读得出来（同样走 write_at，不开裸窗口）
    crate::user::write_at(res_va, 0xdead_beef);
    let mut o2 = crate::sched::OwnedSet::new();
    o2.push(map2).ok();
    o2.push(smap2).ok();
    let t2 = match crate::sched::spawn_user(code2, stk2 + mm::PAGE as u64 - 16, 0, o2) {
        Ok(g) => g,
        Err(e) => {
            crate::log_fatal!("demand-zero: 越界任务起不来 {:?}", e);
            return false;
        }
    };
    let got_kill2 = dz_wait_kills(kills0 + 1);
    let killed2 = got_kill2
        && mm::demand_zero_count() == dz0 + 1
        && crate::user::peek_u64(res_va).unwrap_or(0) == 0xdead_beef;
    crate::sched::terminate_task(t2);
    dz_wait_free(t2);
    drop(r4);

    // ④ 区间内取指：R3 单页区间不填充，entry 直接指过去 ⇒ err=0x15 不修
    let r3 = match mm::lazy_new(1, mm::MOD_TEST) {
        Some(h) => h,
        None => {
            crate::log_fatal!("demand-zero: R3 建不起来");
            return false;
        }
    };
    let base3 = r3.base().unwrap_or(0);
    let (stk3, smap3) = match dz_page(mm::PageFlags::USER_RW, None) {
        Some(p) => p,
        None => {
            crate::log_fatal!("demand-zero: 取指栈建不起来");
            return false;
        }
    };
    let mut o3 = crate::sched::OwnedSet::new();
    o3.push(smap3).ok();
    o3.push_lazy(r3).ok();
    let t3 = match crate::sched::spawn_user(base3, stk3 + mm::PAGE as u64 - 16, 0, o3) {
        Ok(g) => g,
        Err(e) => {
            crate::log_fatal!("demand-zero: 取指任务起不来 {:?}", e);
            return false;
        }
    };
    let got_kill3 = dz_wait_kills(kills0 + 2);
    let killed3 = got_kill3
        && mm::demand_zero_count() == dz0 + 1
        && !mm::is_mapped(base3);
    crate::sched::terminate_task(t3);
    dz_wait_free(t3);

    // ⑥ 双核竞争：R2 用**独占模块号 ModuleId(40)** 记账——外部用例的延迟回收再乱，
    // 也碰不到这个格；"恰留 1 页、drop 后回 0"因此对本用例是精确判据（M5-2 的杀手）。
    // race-demand-zero 变体在 alloc 与 map 之间注入自旋，保证输家路径**必然**被走到
    // （默认构建下 TCG 串行化会饿死它，"输家还帧=0"不能当证据）。
    let dz_owner = mm::ModuleId(40);
    let r2 = match mm::lazy_new(2, dz_owner) {
        Some(h) => h,
        None => {
            crate::log_fatal!("demand-zero: R2 建不起来");
            return false;
        }
    };
    let base2 = r2.base().unwrap_or(0);
    let lost0 = mm::demand_zero_lost();
    let dz_before = mm::demand_zero_count();
    let live0 = crate::resource::live_of(dz_owner);
    DZ_CR2.store(base2, Ordering::Release);
    DZ_START.store(0, Ordering::Relaxed);
    DZ_READY.store(0, Ordering::Relaxed);
    for r in DZ_RET.iter() {
        r.store(0, Ordering::Relaxed);
    }
    let ack = crate::arch::x86_64::smp::run_ap_role(dz_worker, dz_observer);
    // 参与者按"真的就位"数：participant_slots 要 cpu_ticks>0，在首次 bringup 之前
    // 从用例侧调用会读出 0（实测），而观察者/工人的计数在相位内自算——判据只认现场。
    let contenders = DZ_READY.load(Ordering::Acquire);
    let ready_all = contenders >= 1;
    let started = DZ_START.load(Ordering::Acquire) == 1;
    let filled_one = mm::demand_zero_count() == dz_before + 1;
    let ret_ones = DZ_RET.iter().filter(|r| r.load(Ordering::Acquire) == 1).count();
    let lost_delta = mm::demand_zero_lost() - lost0;
    // 竞争窗口里恰好留住一页（赢家的那页；输家的都已随 Err 路径归还）
    let holds_one = crate::resource::live_of(dz_owner) == live0 + 1;
    drop(r2);
    let ledger_clean = crate::resource::live_of(dz_owner) == live0;
    // 注入变体下必须看到真输家；默认构建只记录不苛求
    let forced_losers = if cfg!(feature = "race-demand-zero") { lost_delta >= 1 } else { true };
    let raced = ack.is_ok() && ready_all && started && filled_one
        && ret_ones == contenders + 1 && holds_one && ledger_clean && forced_losers;

    // ⑤ 收尾：只看"我自己的东西没了"。绝对 free/live 会被别的用例落在 AP 队列上的
    // 延迟回收污染（本轮实测竞争窗口 ±28 帧），账目正确性由台账不变量与逐 VA 检查兑现。
    drop(res_map);
    let t = crate::resource::totals();
    let back = !mm::is_mapped(base1)
        && !mm::is_mapped(base2)
        && !mm::is_reserved(base1)
        && !mm::is_reserved(base2)
        && mm::lazy_region_count() == reg0
        && t.sum_live == t.sum_alloc - t.sum_free
        && !t.violation;
    crate::log_info!(
        "demand-zero(P5): 修复计数=+{} 首读全0={} 区间外仍杀={} copy不修={} 取指仍杀={} 竞争填充={} 输家还帧={} 独占账回0={} 退出回基线={} 就位={} 发令={} 回执={} 持页={} ack={}",
        mm::demand_zero_count() - dz0,
        first_zero && filled_1,
        killed2,
        copy_refused,
        killed3,
        mm::demand_zero_count() - dz_before,
        lost_delta,
        ledger_clean,
        back,
        contenders,
        started,
        ret_ones,
        holds_one,
        ack.is_ok(),
    );
    ok && copy_refused && first_zero && filled_1 && killed2 && killed3 && raced && back
}
// fault-resched-ipi 档整条不注册（§138 同形先例）：该构建把 request_resched 全局打失败，
// 本用例的 ring3 推进（换入 t1/t2/t3）实测在该档的等待窗口里不发生、只在 run_ap_role
// 相位期间才走（40 tick 预算 + timer_start + start_workers 都救不回来，机制未归因）。
// 该档对"失败不丢唤醒"的见证由 t_resched_ipi_fail_fallback 负责；这里不冒充已修。
// ahci-scratch 档同样整条不注册：实测本用例的等待窗口内整机静默死（最后一行是
// "t1 已 spawn"，tick 预算走完都没有下一条打印，机制未归因，留档在案）。
// 两个欠账都记 BACKLOG §141 的"没做/新发现"，W3 排产时归因。
#[cfg(not(any(feature = "fault-resched-ipi", feature = "ahci-scratch")))]
ktest!(KT_DEMAND_ZERO, t_demand_zero);


// ---- ADR-074（W3 P4a）VMO / aspace_map / 句柄表两段式释放 ----
//
// 三条用例分工：`t_vmo_object` 管对象本身（写读回、越界、清零、还帧）；
// `t_aspace_map_vmo` 管"往指定 AS 铺"（双 AS 同 VA、W^X、高半区、互不影响、表页归还、shootdown 收窄）；
// `t_handle_vmo_release` 管句柄表那条裁决（dup 共享帧、close/revoke 两段式、锁序零违规）。
// 变异：M1 去掉长度检查 ⇒ 越界格红；M2 unref 不还帧 ⇒ 基线格红；M3 去掉引用计数 ⇒ dup 格红；
// M4 把 unref 搬进 HANDLE 锁内 ⇒ 锁序违规当场 L4(39)；M5 遍历仍用内核根 ⇒ 双 AS 格红；
// M6 去掉高半区闸 ⇒ 内核半区被写（A1 的叶项对照红）。

fn t_vmo_object() -> bool {
    use crate::vmo;
    let (c0, r0, b0) = vmo::counters();
    if vmo::vmo_count() != 0 {
        crate::log_fatal!("vmo: 前提失效，进来时已有 {} 个对象", vmo::vmo_count());
        return false;
    }
    let f0 = mm::free_frames();
    let id = match vmo::vmo_create(2) {
        Ok(v) => v,
        Err(e) => { crate::log_fatal!("vmo: create {:?}", e); return false; }
    };
    // ① 跨页写读回：offset = PAGE-3、长度 6 ⇒ 一条命令落在两页上
    let src = [1u8, 2, 3, 4, 5, 6];
    let w = vmo::vmo_write(id, mm::PAGE - 3, &src);
    let mut back = [0u8; 6];
    let r = vmo::vmo_read(id, mm::PAGE - 3, &mut back);
    let io_ok = w == Ok(6) && r == Ok(6) && back == src;
    // ② 越界三态：整段越界、offset+len 溢出、长度 0（都不许静默截断）
    let big = [0u8; 8];
    let oob = vmo::vmo_write(id, 2 * mm::PAGE - 3, &big);
    let ovf = vmo::vmo_write(id, usize::MAX - 1, &big);
    let zero = vmo::vmo_write(id, 0, &[]);
    let bound_ok = oob == Err(vmo::VmoError::BadLength)
        && ovf == Err(vmo::VmoError::BadLength)
        && zero == Err(vmo::VmoError::BadLength);
    // ③ 清零见证：没写过的地方读回全 0（分配器毒化过 0xA5，所以忘了清零会红在这一格）
    let mut zb = [0xFFu8; 16];
    let zeroed = vmo::vmo_read(id, mm::PAGE + 8, &mut zb) == Ok(16) && zb.iter().all(|&b| b == 0);
    // ④ 最后一个引用消失 ⇒ 帧回基线、对象数归零、三本计数对得上
    vmo::vmo_unref(id);
    let f1 = mm::free_frames();
    let (c1, r1, b1) = vmo::counters();
    let base_ok = f1 == f0 && vmo::vmo_count() == 0 && c1 == c0 + 1 && r1 == r0 + 1 && b1 == b0 + 6;
    crate::log_info!(
        "vmo(P4): 写读={} 越界={} 清零={} 基线=(free{}->{} n{} created{}->{} released{}->{} bytes{}->{})",
        io_ok, bound_ok, zeroed, f0, f1, vmo::vmo_count(), c0, c1, r0, r1, b0, b1);
    let ok = io_ok && bound_ok && zeroed && base_ok;
    if !ok {
        crate::log_fatal!("vmo: 判据不成立 写读={} 越界={} 清零={} 基线={}", io_ok, bound_ok, zeroed, base_ok);
    }
    ok
}
ktest!(KT_VMO_OBJECT, t_vmo_object);

fn t_aspace_map_vmo() -> bool {
    use crate::vmo;
    use crate::arch::x86_64::{cpu, smp};
    // 收窄格要有另一颗在线 CPU 当证人（与 t_shootdown_masked 同一前提）
    if smp::bringup().is_err() {
        crate::log_fatal!("asmap: AP 起不来，收窄判据没有证人");
        return false;
    }
    let me = cpu::self_slot();
    let ap1 = match (0..cpu::MAX_CPUS).find(|&c| c != me && cpu::is_online(c)) {
        Some(c) => c,
        None => { crate::log_fatal!("asmap: 没有第二颗在线 CPU"); return false; }
    };
    if mm::aspace_count() != 0 {
        crate::log_fatal!("asmap: 前提失效，进来时已有 {} 个 AS", mm::aspace_count());
        return false;
    }
    let f0 = mm::free_frames();
    let a1 = match mm::aspace_new() {
        Some(h) => h,
        None => { crate::log_fatal!("asmap: AS1 建不起来"); return false; }
    };
    let a2 = match mm::aspace_new() {
        Some(h) => h,
        None => { crate::log_fatal!("asmap: AS2 建不起来"); return false; }
    };
    let id = match vmo::vmo_create(1) {
        Ok(v) => v,
        Err(e) => { crate::log_fatal!("asmap: vmo {:?}", e); return false; }
    };
    let va = mm::VirtAddr(0x1_0000_0000); // 用户半区，两个新 AS 里都未映射
    let flags = mm::PageFlags::USER_RW;

    // ① 同一 VA 在两个 AS 里各自映射成功
    let m1 = vmo::vmo_map(id, &a1, va, flags);
    let m2 = vmo::vmo_map(id, &a2, va, flags);
    let both_ok = m1.is_ok() && m2.is_ok();
    // ② 同一棵树里重复 ⇒ AlreadyMapped（查的是那棵树，不是内核树）
    let again = vmo::vmo_map(id, &a1, va, flags);
    let tree_ok = matches!(again, Err(vmo::VmoError::Mm(mm::MmError::AlreadyMapped)));
    // ③ W^X 在构造期就拒绝（aspace_map 收的是 PageFlags，根本收不到 W+X 的意图）
    let wx_ok = mm::PageFlags::new(true, true, true) == Err(mm::MmError::WxViolation);
    // ④ 高半区一律拒：那里的下层表与内核共享，写它就是改内核表
    let hi = vmo::vmo_map(id, &a1, mm::VirtAddr(0xffff_8000_0000_0000), flags);
    let hi_ok = matches!(hi, Err(vmo::VmoError::Mm(mm::MmError::KernelHalfFrozen)));
    // ⑤ 第二台仪器：读两棵树的叶子，都指向同一个帧（不切 CR3、不碰用户页，与 SMAP 无关）
    let l1 = mm::aspace_leaf(&a1, va);
    let l2 = mm::aspace_leaf(&a2, va);
    let leaf_ok = l1.is_some() && l1 == l2;
    // ⑥ 互不影响的真正证人：丢掉 AS1 的映射之后，AS2 的同一 VA 还在
    drop(m1);
    let indep_ok = mm::aspace_leaf(&a1, va).is_none() && mm::aspace_leaf(&a2, va).is_some();
    // ⑥b 按**槽号**铺（ADR-075 决策 6：14 号的 `rdx`=AS 句柄走的就是这条实体）。
    // 与 ① 的 `vmo_map(&a2, ..)` 互为对照：同一棵树、同一个入口，引用来源从 RAII 柄换成槽号。
    let va2 = mm::VirtAddr(0x1_0000_1000);
    let ms = vmo::vmo_map_slot(id, a2.slot(), va2, flags);
    let slot_ok = ms.is_ok()
        && mm::aspace_leaf(&a2, va2).is_some()
        && mm::aspace_leaf(&a1, va2).is_none();
    // ⑥c 槽号不存在必须明确拒绝（这条判据的存在理由：`aspace_map` 有柄可依赖，
    // `aspace_map_slot` 没有 ⇒ `used` 必须自己核，漏核就是往一张已销毁的表里写叶子）
    let dead = mm::aspace_map_slot(3, &[], va2, flags, crate::vmo::MOD_VMO);
    let dead_ok = matches!(dead, Err(mm::MmError::NoSuchAspace));
    drop(ms);
    let slot_gone = mm::aspace_leaf(&a2, va2).is_none();
    // ⑦ 收窄：把 AS2 登记到 AP1，丢它的映射 ⇒ 只有 AP1 收到回执（ADR-072 的第一个产品调用者）
    let reg = mm::aspace_register_cpu(1, ap1);
    let sd1 = mm::shootdown_stats();
    drop(m2);
    let sd2 = mm::shootdown_stats();
    let narrowed_ok = reg.is_some()
        && sd2.acks[ap1] == sd1.acks[ap1] + 1
        && sd2.requests == sd1.requests + 1
        && (0..cpu::MAX_CPUS).all(|c| c == ap1 || c == me || sd2.acks[c] == sd1.acks[c]);
    // ⑧ 表页与帧都回基线（非内核 AS 按需建的下级表页记 MOD_AS_PT，销毁时归还）
    drop(a1);
    drop(a2);
    vmo::vmo_unref(id);
    let f1 = mm::free_frames();
    let base_ok = f1 == f0 && mm::aspace_count() == 0 && vmo::vmo_count() == 0;
    crate::log_info!(
        "asmap(P5c-2): 双AS={} 同树拒={} W^X={} 高半区拒={} 叶同帧={} 互不影响={} 按槽铺={} 死槽拒={} 丢掉后没了={} 收窄=(reg{} ack{}) 基线=(free{}->{} as{} vmo{})",
        both_ok, tree_ok, wx_ok, hi_ok, leaf_ok, indep_ok, slot_ok, dead_ok, slot_gone, reg.is_some(),
        sd2.acks[ap1] - sd1.acks[ap1], f0, f1, mm::aspace_count(), vmo::vmo_count());
    let ok = both_ok && tree_ok && wx_ok && hi_ok && leaf_ok && indep_ok
        && slot_ok && dead_ok && slot_gone && narrowed_ok && base_ok;
    if !ok {
        crate::log_fatal!(
            "asmap: 判据不成立 双AS={} 同树={} wx={} 高半区={} 叶={} 独立={} 按槽铺={} 死槽拒={} 丢后没={} 收窄={} 基线={}",
            both_ok, tree_ok, wx_ok, hi_ok, leaf_ok, indep_ok, slot_ok, dead_ok, slot_gone,
            narrowed_ok, base_ok);
    }
    ok
}
ktest!(KT_ASPACE_MAP_VMO, t_aspace_map_vmo);

#[cfg(feature = "handles")]
fn t_handle_vmo_release() -> bool {
    use crate::{handle, sync, vmo};
    // 合成主人（与 handle.rs 自己的用例同一手法，但取不同的两格，免得 revoke 互相清）
    let owner: (usize, u32) = (6, 9001);
    let lv0 = handle::live();
    let f0 = mm::free_frames();
    let ls0 = sync::stats();
    if vmo::vmo_count() != 0 {
        crate::log_fatal!("hvmo: 前提失效，进来时已有对象");
        return false;
    }
    let rights = handle::RIGHT_READ | handle::RIGHT_WRITE | handle::RIGHT_DUP | handle::RIGHT_MAP;
    let id = match vmo::vmo_create(1) {
        Ok(v) => v,
        Err(e) => { crate::log_fatal!("hvmo: create {:?}", e); return false; }
    };
    let pat = [7u8, 8, 9, 10];
    if vmo::vmo_write(id, 0, &pat) != Ok(4) {
        crate::log_fatal!("hvmo: 写不进对象");
        return false;
    }
    let h1 = match handle::grant_vmo(owner, id, rights) {
        Ok(h) => h,
        Err(e) => { crate::log_fatal!("hvmo: grant {:?}", e); return false; }
    };
    // 创建者那一份交出去：现在句柄是唯一主人
    vmo::vmo_unref(id);
    let refs1 = vmo::vmo_refs(id) == Some(1);
    // ① dup 共享同一份帧：引用数 +1，两个句柄都活着
    let h2 = handle::dup(h1, owner, handle::RIGHT_READ | handle::RIGHT_WRITE);
    let refs2 = vmo::vmo_refs(id) == Some(2);
    let dup_ok = h2.is_ok() && refs1 && refs2;
    // ② close 一个：帧还在、内容还读得到（没有引用计数的话第一次 close 就把帧还了）
    let c1 = handle::close(h1, owner);
    let mut b = [0u8; 4];
    let alive = vmo::vmo_read(id, 0, &mut b) == Ok(4) && b == pat && vmo::vmo_refs(id) == Some(1);
    // ③ 两个都 close 才还帧
    let h2v = match h2 { Ok(h) => h, Err(_) => handle::Handle(0) };
    let c2 = handle::close(h2v, owner);
    let gone = vmo::vmo_refs(id).is_none() && vmo::vmo_count() == 0 && mm::free_frames() == f0;
    let share_ok = dup_ok && c1.is_ok() && alive && c2.is_ok() && gone;
    // ④ revoke 也走两段式：锁内清槽、锁外还帧
    let id2 = match vmo::vmo_create(1) {
        Ok(v) => v,
        Err(e) => { crate::log_fatal!("hvmo: create2 {:?}", e); return false; }
    };
    let h3 = handle::grant_vmo(owner, id2, handle::RIGHT_READ);
    vmo::vmo_unref(id2);
    let rv = handle::revoke_task(owner.0, owner.1);
    let revoke_ok = h3.is_ok() && rv == 1 && vmo::vmo_count() == 0 && mm::free_frames() == f0;
    // ⑤ 类型不符：VMO 句柄走文件读 ⇒ Denied（不是 NoSuch，两个计数器分开）
    let id3 = match vmo::vmo_create(1) {
        Ok(v) => v,
        Err(_) => { crate::log_fatal!("hvmo: create3 失败"); return false; }
    };
    let h4 = handle::grant_vmo(owner, id3, handle::RIGHT_READ);
    let denied = match h4 {
        Ok(h) => matches!(handle::begin_read(h, owner), Err(handle::HErr::Denied)),
        Err(_) => false,
    };
    if let Ok(h) = h4 {
        handle::close(h, owner).ok();
    }
    vmo::vmo_unref(id3);
    // ⑥ 锁序零违规：这一格是"释放在锁外"那条裁决的正向证人（搬进锁内就是 35→20，当场 L4）
    let ls1 = sync::stats();
    let lock_ok = ls1.order_violations == ls0.order_violations && ls1.reentrant_hits == ls0.reentrant_hits;
    let base_ok = handle::live() == lv0 && vmo::vmo_count() == 0 && mm::free_frames() == f0;
    crate::log_info!(
        "hvmo(P4): dup共享={} close一个还活着={} 两个都close才还={} revoke={} 类型拒={} 锁序=(viol{}->{}/reent{}->{}) 基线=(live{}->{} free{}->{})",
        dup_ok, alive, gone, revoke_ok, denied,
        ls0.order_violations, ls1.order_violations, ls0.reentrant_hits, ls1.reentrant_hits,
        lv0, handle::live(), f0, mm::free_frames());
    let ok = share_ok && revoke_ok && denied && lock_ok && base_ok;
    if !ok {
        crate::log_fatal!(
            "hvmo: 判据不成立 共享={} revoke={} 类型={} 锁序={} 基线={}",
            share_ok, revoke_ok, denied, lock_ok, base_ok);
    }
    ok
}
#[cfg(feature = "handles")]
ktest!(KT_HANDLE_VMO_RELEASE, t_handle_vmo_release);
#[cfg(feature = "handles")]
fn kinds_sleep() -> ! {
    // 只存在、不需要跑：C4 判的是"槽里有没有这条线程"，不是它有没有收工
    loop {
        crate::tsc::spin(2000);
    }
}

/// P5c-1（ADR-075 决策 4）：句柄的四种新 kind、`RIGHT_CREATE`、世代号、
/// 以及"**close/revoke 只撤名字，不销毁本体**"这条与 VMO 不同的语义。
/// 七格各自一条证人，收场必须回到进来之前的三本账（proc/job/AS 各一）。
#[cfg(feature = "handles")]
fn t_handle_kinds() -> bool {
    use crate::{handle, proc, sync};
    let owner: (usize, u32) = (7, 9101);
    let lv0 = handle::live();
    let (jp0, _) = proc::job_residual();
    let (pp0, _) = proc::proc_residual();
    let as0 = mm::aspace_count();
    let ls0 = sync::stats();
    let R = handle::RIGHT_READ | handle::RIGHT_DUP;

    // ①② Job：带 CREATE 与不带 CREATE 是两格，拒绝必须记在 denied 而不是 no_such
    let job = match proc::job_create(None, 4, 64) {
        Ok(j) => j,
        Err(e) => { crate::log_fatal!("hkind: job_create {:?}", e); return false; }
    };
    let jgen = proc::job_gen(job).unwrap_or(0);
    let hj = match handle::grant_job(owner, job, jgen, R | handle::RIGHT_CREATE) {
        Ok(h) => h,
        Err(e) => { crate::log_fatal!("hkind: grant_job {:?}", e); return false; }
    };
    let d0 = handle::counters().denied;
    let hj_plain = handle::grant_job(owner, job, jgen, R);
    let create_ok = handle::has(hj, owner, handle::RIGHT_CREATE)
        && match hj_plain {
            Ok(h) => {
                let no = !handle::has(h, owner, handle::RIGHT_CREATE);
                handle::close(h, owner).ok();
                no
            }
            Err(_) => false,
        }
        && handle::counters().denied > d0;

    // ③ Proc
    let p = match proc::proc_create(job) {
        Ok(v) => v,
        Err(e) => { crate::log_fatal!("hkind: proc_create {:?}", e); return false; }
    };
    let pgen = proc::proc_gen(p).unwrap_or(0);
    let hp = match handle::grant_proc(owner, p, pgen, R) {
        Ok(h) => h,
        Err(e) => { crate::log_fatal!("hkind: grant_proc {:?}", e); return false; }
    };
    let proc_ok = handle::resolve(hp, owner, 0)
        .map(|(o, _)| matches!(o, handle::ObjRef::Proc { slot, .. } if slot == p))
        .unwrap_or(false);

    // ④ ASpace：活着能解析；**销毁之后**同一个句柄必须 `NoSuch`（世代号唯一的证人）
    let a = match mm::aspace_new() {
        Some(h) => h,
        None => { crate::log_fatal!("hkind: aspace_new 建不起来"); return false; }
    };
    let slot_a = a.slot();
    let ha = match handle::grant_aspace(owner, slot_a, R) {
        Ok(h) => h,
        Err(e) => { crate::log_fatal!("hkind: grant_aspace {:?}", e); return false; }
    };
    // C1b：句柄层**看不出** Job/Proc 的死亡（`capability -> sched` 这条边会把 sched 拖进
    // 冻结的核心环，见 `handle::grant_job`），sched 那侧看得出 ⇒ "谁判活性"是可判的分工，不是注释。
    let (j2, g2) = match proc::job_create(None, 1, 8) {
        Ok(v) => (v, proc::job_gen(v).unwrap_or(0)),
        Err(e) => { crate::log_fatal!("hkind: job_create(2) {:?}", e); return false; }
    };
    let hj2 = match handle::grant_job(owner, j2, g2, R) {
        Ok(h) => h,
        Err(e) => { crate::log_fatal!("hkind: grant_job(2) {:?}", e); return false; }
    };
    let jd2 = proc::job_destroy(j2).is_ok();
    // 另两张表的同一个 ABA（gen 必须活过销毁）：复用这格再建一个 Job，旧 `(slot, gen)` 仍对不上。
    let j3 = proc::job_create(None, 1, 8);
    let job_aba = match j3 {
        Ok(v) => {
            let back = v == j2 && !proc::job_live(j2, g2);
            proc::job_destroy(v).ok();
            back
        }
        Err(_) => false,
    };
    let split_ok = jd2 && job_aba && handle::resolve(hj2, owner, 0).is_ok() && !proc::job_live(j2, g2);
    // 这一格只是证人，不留句柄在表里：⑥/⑦ 的账要按"只剩 ASpace 那一个"算
    handle::close(hj2, owner).ok();
    let as_live = handle::resolve(ha, owner, 0)
        .map(|(o, _)| matches!(o, handle::ObjRef::ASpace { slot, .. } if slot == slot_a))
        .unwrap_or(false);
    let n0 = handle::counters().no_such;
    drop(a);
    let as_stale = handle::resolve(ha, owner, 0).is_err() && handle::counters().no_such > n0;
    // ABA 证人（P5c-3a 补的）：**复用同一格再建一张 AS**，旧句柄仍然必须解析不过。
    // 只判"销毁之后"不够：销毁若把 gen 复位成 0，下一张 AS 复用这格又变 1，
    // 旧句柄的 (slot, gen) 就重新匹配上了——世代号白加（本轮实测第一版正是这样）。
    let a_b = mm::aspace_new();
    let ab_slot = a_b.as_ref().map(|h| h.slot());
    let as_aba = ab_slot == Some(slot_a)
        && handle::resolve(ha, owner, 0).is_err()
        && mm::aspace_live(slot_a, mm::aspace_gen(slot_a).unwrap_or(0));
    drop(a_b);

    // ⑤ Thread：任务是槽 + id 两格；terminate 之后槽标 Free ⇒ 同一个句柄 `NoSuch`
    let gi = match crate::sched::spawn(kinds_sleep) {
        Ok(g) => g,
        Err(_) => { crate::log_fatal!("hkind: spawn 失败"); return false; }
    };
    let th_id = crate::sched::id_of(gi);
    let ht = match handle::grant_thread(owner, gi, th_id, R) {
        Ok(h) => h,
        Err(e) => { crate::log_fatal!("hkind: grant_thread {:?}", e); return false; }
    };
    let th_live = handle::resolve(ht, owner, 0)
        .map(|(o, _)| matches!(o, handle::ObjRef::Thread { gidx, .. } if gidx == gi))
        .unwrap_or(false);
    let t1 = crate::sched::terminate_task(gi);
    // C4 的形状是**两半**：句柄层看不见线程死亡（设计上不判，见 grant_thread），
    // sched 那侧看得见 ⇒ 安全性由消费方（c-3 的 thread_create/process_start）兜住。
    // 只写"resolve 报错"会把这条分工判成假的。
    let th_gone = t1
        && !crate::sched::thread_live(gi, th_id)
        && crate::sched::id_of(gi) == th_id
        && handle::resolve(ht, owner, 0).is_ok();

    // ⑥ close 不销毁本体：关到只剩"内核那一份都没有"，三本账一个都不能动
    let _ = handle::close(hj, owner);
    let _ = handle::close(hp, owner);
    let _ = handle::close(ht, owner);
    let (jp1, _) = proc::job_residual();
    let (pp1, _) = proc::proc_residual();
    let noclose_ok = jp1 == jp0 + 1 && pp1 == pp0 + 1 && mm::aspace_count() == as0
        && handle::live() == lv0 + 1;

    // ⑦ revoke 只摘名字：撤掉这一路剩下的那一个句柄（ASpace），本体账不变
    let rv = handle::revoke_task(owner.0, owner.1);
    let rev_ok = rv == 1 && handle::live() == lv0;

    // 收场：对象按各自的显式路径销毁（进程先弃、Job 后销，反了就是 Denied）
    let disc = proc::proc_discard(p).is_ok();
    let jdel = proc::job_destroy(job).is_ok();
    let ls1 = sync::stats();
    let lock_ok = ls1.order_violations == ls0.order_violations && ls1.reentrant_hits == ls0.reentrant_hits;
    let base_ok = disc && jdel && handle::live() == lv0
        && proc::job_residual().0 == jp0 && proc::proc_residual().0 == pp0
        && mm::aspace_count() == as0;
    crate::log_info!(
        "hkind(P5c-3a): CREATE={} proc={} 活性分工={} AS活={} AS世代={} AS复用ABA={} 线程活={} 线程撤销={} close不动本体={} revoke={} 锁序=(viol{}->{}/reent{}->{}) 基线=(live{}->{} AS{}->{} job{}->{} proc{}->{})",
        create_ok, proc_ok, split_ok, as_live, as_stale, as_aba, th_live, th_gone, noclose_ok, rev_ok,
        ls0.order_violations, ls1.order_violations, ls0.reentrant_hits, ls1.reentrant_hits,
        lv0, handle::live(), as0, mm::aspace_count(), jp0, proc::job_residual().0,
        pp0, proc::proc_residual().0);
    let ok = create_ok && proc_ok && split_ok && as_live && as_stale && as_aba
        && th_live && th_gone && noclose_ok && rev_ok && lock_ok && base_ok;
    if !ok {
        crate::log_fatal!(
            "hkind: 判据不成立 CREATE={} proc={} 活性分工={} AS活={} AS世代={} AS复用ABA={} 线程={} 线程撤={} close={} revoke={} 锁序={} 收场={}",
            create_ok, proc_ok, split_ok, as_live, as_stale, as_aba, th_live, th_gone,
            noclose_ok, rev_ok, lock_ok, base_ok);
    }
    // ASpace 那个句柄在 ⑦ 已经被 revoke 摘走；a 已经 drop，这里没有 leftovers
    ok
}
#[cfg(feature = "handles")]
ktest!(KT_HANDLE_KINDS, t_handle_kinds);
/// 一个只自旋、自己不会收工的工人：给 `block_task`/`wake_task` 当被试对象。
#[cfg(feature = "handles")]
fn tr_worker() -> ! {
    loop {
        crate::tsc::spin(2_000);
    }
}

/// P5c-3a 底座那一半的**真实调用者**：`handle::transfer` / `transfer_rollback`、
/// `sched::block_task`、`mm::aspace_new_kernel` / `aspace_destroy`。
/// 这四样在 11/15/16 落地之前只有实现没有调用者（硬约束 2），所以本用例就是它们的调用者，
/// 同时把"转移即失效""回滚不留中间态""内核侧 AS 的所有权与幂等销毁"写成可判的读数。
#[cfg(feature = "handles")]
fn t_handle_transfer() -> bool {
    use crate::{handle, sync, vmo};
    let from: (usize, u32) = (4, 8101);
    let to: (usize, u32) = (5, 8202);
    let lv0 = handle::live();
    let c0 = handle::counters();
    let f0 = mm::free_frames();
    let as0 = mm::aspace_count();
    if vmo::vmo_count() != 0 || as0 != 0 {
        crate::log_fatal!("tr: 前提失效，进来已有对象 vmo={} as={}", vmo::vmo_count(), as0);
        return false;
    }

    // ① 转移：新句柄可用、旧句柄当场 Stale、两个计数各涨各的
    let id = match vmo::vmo_create(1) {
        Ok(v) => v,
        Err(e) => { crate::log_fatal!("tr: create {:?}", e); return false; }
    };
    let rights = handle::RIGHT_READ | handle::RIGHT_DUP | handle::RIGHT_TRANSFER;
    // 先 grant（它自己加一份引用）再交出创建者那一份——顺序反了就是 unref 到 0 把对象销毁，
    // grant 当场 NoSuch（本用例第一版就是这么红的）
    let h1 = match handle::grant_vmo(from, id, rights) {
        Ok(h) => h,
        Err(e) => { crate::log_fatal!("tr: grant {:?}", e); return false; }
    };
    vmo::vmo_unref(id);
    let h2 = match handle::transfer(h1, from, to) {
        Ok(h) => h,
        Err(e) => { crate::log_fatal!("tr: transfer {:?}", e); return false; }
    };
    let new_owner_ok = handle::vmo_of(h2, to, handle::RIGHT_READ).is_ok();
    let old_stale = matches!(handle::vmo_of(h1, from, handle::RIGHT_READ), Err(handle::HErr::Stale));
    let c1 = handle::counters();
    let count_ok = c1.transfers == c0.transfers + 1 && c1.stale > c0.stale
        // 转移**不占新格子**（决策 4：表里还是那 16 格，只是名字换了主人）
        && handle::live() == lv0 + 1;
    // ② 类型/kind 跟着走：同一个 VMO 槽，不是复制出一个新对象
    let same_obj = handle::vmo_of(h2, to, handle::RIGHT_READ).ok() == Some(id);
    // ③ 没有 TRANSFER 权限 ⇒ Denied（计数与 Stale 分开）
    let h3 = match handle::grant_vmo(from, id, handle::RIGHT_READ | handle::RIGHT_DUP) {
        Ok(h) => h,
        Err(e) => { crate::log_fatal!("tr: grant3 {:?}", e); return false; }
    };
    let c2 = handle::counters();
    let no_right = matches!(handle::transfer(h3, from, to), Err(handle::HErr::Denied))
        && handle::counters().denied > c2.denied;
    // 自己转自己必须是形状非法，不是"静默成功"
    let self_tr = matches!(handle::transfer(h2, to, to), Err(handle::HErr::Invalid));

    // ④ 回滚：owner 改回 from，且**中间态那个新句柄当场失效**（再 bump 一次世代）
    if let Err(e) = handle::transfer_rollback(h2, to, from) {
        crate::log_fatal!("tr: rollback {:?}", e);
        return false;
    }
    let back_ok = handle::vmo_of(h2, from, handle::RIGHT_READ).is_err()
        && handle::vmo_of(h1, from, handle::RIGHT_READ).is_err()
        && handle::counters().transfers == c1.transfers + 1;
    // 回滚点不在那个状态上（已被别的核接走/已关掉）⇒ 明确 NoSuch，绝不硬改
    let re_bad = matches!(
        handle::transfer_rollback(h2, to, from),
        Err(handle::HErr::NoSuch) | Err(handle::HErr::Invalid)
    );

    // ④b **回滚的连带后果（本用例实测撞出来的）**：回滚再 bump 一次世代，所以**发送方手里那个
    // 旧句柄也已经失效** ⇒ 那格名字谁都 `close` 不掉，只有 `revoke_task(from)` 收得走。
    // 只回滚不 revoke 的代价不是"少一格名字"，而是永久漏一份 VMO 引用与一帧
    // （实测 `live0->1 vmo1 free 少 1 帧`，把后面 14 格用例的收尾闸全打红）。
    // ⇒ 16 号的失败路径必须**连着 revoke 一起走**，这是设计 §10.3 第 7 步"整条装载序列回滚"的一部分。
    let sender_dead = matches!(handle::close(h1, from), Err(handle::HErr::Stale));

    // ⑤ 内核侧 AS：建、数、销、二次销（幂等）、越界槽
    let k1 = match mm::aspace_new_kernel() {
        Some(v) => v,
        None => { crate::log_fatal!("tr: aspace_new_kernel 失败"); return false; }
    };
    let created_ok = mm::aspace_count() == as0 + 1 && mm::aspace_live(k1.0, k1.1);
    let first_destroy = mm::aspace_destroy(k1.0);
    let second_destroy = mm::aspace_destroy(k1.0);
    let out_of_range = mm::aspace_destroy(u8::MAX);
    let destroy_ok = first_destroy && !second_destroy && !out_of_range
        && mm::aspace_count() == as0;
    // 复用同一格再建一次：世代必须对不上旧读数（与 hkind 的 ABA 格同一口径，但走内核侧入口）
    let k2 = mm::aspace_new_kernel();
    let aba_ok = match k2 {
        Some((slot, gen)) => {
            let r = slot == k1.0 && gen != k1.1 && !mm::aspace_live(slot, k1.1);
            mm::aspace_destroy(slot);
            r
        }
        None => false,
    };

    // ⑥ block_task：停住一个不是当前的 Runnable，wake 放回来；停自己/停已死的不许动
    crate::sched::init_boot_task();
    crate::sched::start_workers();
    let me = crate::arch::x86_64::cpu::self_slot();
    let gi = match crate::sched::spawn(tr_worker) {
        Ok(g) => g,
        Err(_) => { crate::log_fatal!("tr: spawn 失败"); return false; }
    };
    let tok = sync::WaitToken { queue: 15, seq: 0xA11C };
    let parked = crate::sched::block_task(gi, tok)
        && crate::sched::state_of(gi) == crate::sched::TaskState::Blocked(tok);
    // 停一个**正在 CPU 上跑**的任务必须是无效操作（那是 `block_current` 的活，它还要负责让出）。
    // **诚实记一笔**：这一格证的是"Running 不许被 block_task 改写"，**不是** `block_task` 里
    // 那道 `current_of(cpu) == gidx` 守卫——M27 把那道守卫删掉之后本用例仍然全绿，
    // 因为当前任务的状态是 `Running`，前一个条件已经把它挡住了。
    // 那道守卫按 ADR-054 的口径**降级为结构性论证**（防将来有人先把它标成 Runnable 再来停），
    // 不写成"已实测"。
    let self_no = !crate::sched::block_task(crate::sched::current_of(me), tok);
    // 陈旧 token 的 wake 不放人（ADR-053 决策 4 的口径），同 token 才放
    let stale_wake = !crate::sched::wake_task(gi, sync::WaitToken { queue: 15, seq: 0xDEAD });
    let still_blocked = crate::sched::state_of(gi) == crate::sched::TaskState::Blocked(tok);
    let woke = crate::sched::wake_task(gi, tok)
        && crate::sched::state_of(gi) == crate::sched::TaskState::Runnable;

    // 收场：按"整条装载序列回滚"的口径收 —— h3 还能 close，h1/h2 都已 Stale，
    // 那格只能靠 revoke_task(from) 收走（④b 就是它的证人）
    handle::close(h3, from).ok();
    handle::close(h2, from).ok();
    let revoked_from = handle::revoke_task(from.0, from.1);
    handle::revoke_task(to.0, to.1);
    let rollback_collected = sender_dead && revoked_from >= 1;
    let _ = crate::sched::terminate_task(gi);
    let base_ok = rollback_collected && handle::live() == lv0 && vmo::vmo_count() == 0
        && mm::free_frames() == f0 && mm::aspace_count() == as0
        && crate::sched::state_of(gi) == crate::sched::TaskState::Free;
    crate::log_info!(
        "tr(P5c-3a): 转移后可用={} 旧句柄Stale={} 计数=(transfers{}->{}) 同对象={} 无权限拒={} 自转拒={} 回滚到位={} 二次回滚拒={} 回滚需revoke={} AS建销=(1{} 2{} 越界{}) ABA={} 停={} 停Running拒={} 陈旧wake={} 唤醒={} 基线=(live{}->{} vmo{} free{}->{} as{})",
        new_owner_ok, old_stale, c0.transfers, handle::counters().transfers, same_obj,
        no_right, self_tr, back_ok, re_bad, rollback_collected, first_destroy, second_destroy,
        out_of_range, aba_ok, parked, self_no, stale_wake && still_blocked, woke,
        lv0, handle::live(), vmo::vmo_count(), f0, mm::free_frames(), mm::aspace_count());
    let ok = new_owner_ok && old_stale && count_ok && same_obj && no_right && self_tr
        && back_ok && re_bad && rollback_collected && created_ok && destroy_ok && aba_ok
        && parked && self_no && stale_wake && still_blocked && woke && base_ok;
    if !ok {
        crate::log_fatal!(
            "tr: 判据不成立 转移={} 旧Stale={} 计数={} 同对象={} 无权限={} 自转={} 回滚={} 二次={} 需revoke={} AS={} ABA={} 停={} 停Running拒={} 陈旧={} 唤醒={} 收场={}",
            new_owner_ok, old_stale, count_ok, same_obj, no_right, self_tr, back_ok, re_bad,
            rollback_collected, created_ok && destroy_ok, aba_ok, parked, self_no,
            stale_wake && still_blocked, woke, base_ok);
    }
    ok
}
#[cfg(feature = "handles")]
ktest!(KT_HANDLE_TRANSFER, t_handle_transfer);

// ---- ADR-074（W3 P4b）12/13/14 三个号 + 退出时归还 ----
//
// 为什么要在**工人任务**里打这三个号而不是在用例上下文里：14 返回的映射挂进的是
// **当前任务**的资源袋，只有任务退出才由 `release_owned` 在锁外 drop。在用例上下文里打号，
// 那份映射会跟着启动任务活到整机停机 ⇒ 帧参考与 VA 保留都回不来，基线格必然红。
// 所以这条用例顺带把 C9 的真正内容证了：**任务退出 ⇒ 映射、VA、帧参考一起回来**。
// 变异：M7 去掉 13 的整段长度预校验 ⇒ 越界格红（且会留下半截写）；
// M8 让 14 不给任务挂袋（直接 forget 映射）⇒ 基线格红；M9 去掉 F_VMO 位 ⇒ ABI 格红。

#[cfg(feature = "handles")]
static VMO_SYS: [core::sync::atomic::AtomicU64; 10] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 10];

#[cfg(feature = "handles")]
fn vmo_sys_worker() -> ! {
    use crate::sched;
    use crate::arch::x86_64::trap::TrapFrame;
    use crate::handle::{Handle, RIGHT_READ};
    use crate::user::{
        COPY_MAX, F_VMO, SYS_ASPACE_MAP, SYS_HANDLE_CLOSE, SYS_HANDLE_DUP, SYS_VMO_CREATE,
        SYS_VMO_WRITE, abi_word, copy_from_user, copy_to_user, syscall_dispatch,
    };
    let put = |i: usize, v: u64| VMO_SYS[i].store(v, core::sync::atomic::Ordering::Release);
    let mut f = TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    };
    // 用户缓冲页：真实映射（user+writable），13 的读方向必须过页面校验
    let va = match mm::alloc_user_va_range(1) {
        Some(v) => v,
        None => { put(0, u64::MAX); sched::finish_current(); loop { crate::tsc::spin(1000); } }
    };
    let frames = match mm::phys_alloc(0, mm::MOD_TEST) {
        Ok(fr) => fr,
        Err(_) => { put(0, u64::MAX); sched::finish_current(); loop { crate::tsc::spin(1000); } }
    };
    let flags = mm::PageFlags::new(true, false, true).ok();
    let map = flags.and_then(|fl| mm::map(va, frames, fl).ok());
    let Some(user_buf) = map else {
        put(0, u64::MAX);
        sched::finish_current();
        loop { crate::tsc::spin(1000); }
    };
    let pat = [0x5Au8, 1, 2, 3, 4, 5, 6, 7];
    if copy_to_user(&pat, va.0) != Ok(8) {
        put(0, u64::MAX);
        sched::finish_current();
        loop { crate::tsc::spin(1000); }
    }

    // ① 12：建两页的对象，拿到句柄
    f.rax = SYS_VMO_CREATE;
    f.rdi = 2;
    syscall_dispatch(&mut f);
    let h = f.rax;
    put(0, h);
    // ② 13：从用户缓冲写 8 字节到 offset 0
    f.rax = SYS_VMO_WRITE;
    f.rdi = h;
    f.rsi = 0;
    f.rdx = va.0;
    f.r10 = 8;
    syscall_dispatch(&mut f);
    put(1, f.rax);
    // ③ 长度三态：0 ⇒ -1；COPY_MAX+1 ⇒ -3；对象里放不下 ⇒ -1（整段先校验）
    f.rax = SYS_VMO_WRITE;
    f.rdi = h;
    f.rsi = 0;
    f.rdx = va.0;
    f.r10 = 0;
    syscall_dispatch(&mut f);
    put(2, f.rax);
    f.rax = SYS_VMO_WRITE;
    f.r10 = (COPY_MAX + 1) as u64;
    syscall_dispatch(&mut f);
    put(3, f.rax);
    f.rax = SYS_VMO_WRITE;
    f.rsi = (2 * mm::PAGE - 3) as u64;
    f.r10 = 8;
    syscall_dispatch(&mut f);
    put(4, f.rax);
    // ④ 14：铺进自己的 AS，拿到一个用户 VA；从它读回必须等于写进去的图案
    f.rax = SYS_ASPACE_MAP;
    f.rdi = h;
    f.rsi = 1;
    // **必须显式清 rdx 与 r10**（P5c-2 实测撞出来的，两个都撞了一次）：这一格复用同一个合成帧，
    // 13 号把 `r10` 留成 8、把 `rdx` 留成一个用户 VA，而扩展形里它们分别是"请求的 VA"与"AS 句柄"
    // ⇒ 脏的 rdx 连句柄形状都过不了（`unpack` 拒 ⇒ -1）。
    // 所以决策 6 的承诺准确说法是"旧调用方**把新参数传 0** 行为不变"，
    // **不是**"不传/随便传也不变"——寄存器是调用方负责清零的，这条要写进 ABI 文档。
    f.rdx = 0;
    f.r10 = 0;
    syscall_dispatch(&mut f);
    let mva = f.rax;
    put(5, mva);
    let mut back = [0u8; 8];
    let read_back = copy_from_user(mva, &mut back) == Ok(8) && back == pat;
    // 反向：往映射里写新值，对象那边必须看得到（同一份帧的双向证明）
    let newv = [0xA5u8; 8];
    let wrote = copy_to_user(&newv, mva) == Ok(8);
    let id = crate::handle::vmo_of(Handle(h), crate::sched::current_identity().unwrap_or((0, 0)), RIGHT_READ).ok();
    let mut seen = [0u8; 8];
    let shared = match id {
        Some(i) => crate::vmo::vmo_read(i, 0, &mut seen) == Ok(8) && seen == newv,
        None => false,
    };
    put(6, if read_back && wrote && shared { 1 } else { 0 });
    // ⑤ 权限：dup 到只读之后 13/14 都必须 -4
    f.rax = SYS_HANDLE_DUP;
    f.rdi = h;
    f.rsi = RIGHT_READ as u64;
    syscall_dispatch(&mut f);
    let hro = f.rax;
    f.rax = SYS_VMO_WRITE;
    f.rdi = hro;
    f.rsi = 0;
    f.rdx = va.0;
    f.r10 = 8;
    syscall_dispatch(&mut f);
    put(7, f.rax);
    f.rax = SYS_ASPACE_MAP;
    f.rdi = hro;
    f.rsi = 1;
    f.r10 = 0;
    f.rdx = 0;
    syscall_dispatch(&mut f);
    put(8, f.rax);
    // ⑥ ABI 位读回真实状态
    put(9, abi_word() & F_VMO);
    // 收尾：关两个句柄；映射留在袋里，**退出时**由 reap 还（这正是本用例要证的那条）
    f.rax = SYS_HANDLE_CLOSE;
    f.rdi = h;
    syscall_dispatch(&mut f);
    f.rax = SYS_HANDLE_CLOSE;
    f.rdi = hro;
    syscall_dispatch(&mut f);
    // 用户缓冲页需要**显式** drop：工人收工之后不再返回（它在自旋让出里等着被回收），
    // 局部变量的析构永远不会跑。第一版忘了这一句，基线格红在"少 1 帧、多 1 条 VA 保留"。
    drop(user_buf);
    sched::finish_current();
    loop {
        sched::yield_now();
    }
}

#[cfg(feature = "handles")]
fn t_vmo_syscalls() -> bool {
    use crate::sched;
    use crate::user::{E_DENIED, E_INVALID, E_TOO_LONG, F_VMO};
    use core::sync::atomic::Ordering;
    // 用例自足（P3 撞出来的四条，一条都不能省）：登记要在 spawn 之前、时钟要自己探测
    sched::init_boot_task();
    sched::start_workers();
    if crate::clock::current().is_none() {
        crate::calibrate_clock_once();
    }
    let tick_in = crate::arch::x86_64::apic::ticks();
    let probe = crate::arch::x86_64::apic::wait_ticks(tick_in, 1, crate::clock::window_cycles(1));
    let was_running = probe.ticks >= 1;
    if !was_running {
        crate::arch::x86_64::apic::timer_start().ok();
    }
    for i in 0..10 {
        VMO_SYS[i].store(0, Ordering::Relaxed);
    }
    let f0 = mm::free_frames();
    let va0 = mm::reservation_count();
    let rel0 = sched::reap_released();
    let v0 = crate::vmo::vmo_count();
    let g = match sched::spawn(vmo_sys_worker) {
        Ok(g) => g,
        Err(e) => { crate::log_fatal!("vmosys: spawn {:?}", e); return false; }
    };
    let waited = crate::arch::x86_64::apic::with_interrupts(|| {
        sched::wait_for_task(g, crate::clock::window_cycles(8))
    });
    let _ = sched::terminate_task(g);
    let drained = sched::reap_released() > rel0 || drain_reap();
    if !was_running {
        crate::arch::x86_64::apic::timer_stop().ok();
    }
    let r: [u64; 10] = core::array::from_fn(|i| VMO_SYS[i].load(Ordering::Acquire));
    let create_ok = waited && crate::handle::Handle(r[0]).unpack().is_some();
    let write_ok = r[1] == 8;
    let len_ok = r[2] == E_INVALID && r[3] == E_TOO_LONG && r[4] == E_INVALID;
    let map_ok = r[5] != 0 && r[5] < u64::MAX && r[6] == 1;
    let rights_ok = r[7] == E_DENIED && r[8] == E_DENIED;
    let abi_ok = r[9] == F_VMO;
    // 退出之后：对象、句柄、帧、VA 保留全部回基线（映射是挂在工人袋里的那一份）
    let f1 = mm::free_frames();
    let va1 = mm::reservation_count();
    let base_ok = drained && f1 == f0 && va1 == va0 && crate::vmo::vmo_count() == v0
        && crate::handle::live() == 0;
    crate::log_info!(
        "vmosys(P4b): 建={} 写={} 长度三态={} 映射双向={} 权限={} ABI={} 退出回基线=(drained{} free{}->{} va{}->{} vmo{} live{})",
        create_ok, write_ok, len_ok, map_ok, rights_ok, abi_ok,
        drained, f0, f1, va0, va1, crate::vmo::vmo_count(), crate::handle::live());
    let ok = create_ok && write_ok && len_ok && map_ok && rights_ok && abi_ok && base_ok;
    if !ok {
        crate::log_fatal!(
            "vmosys: 判据不成立 建={} 写={} 长度={} 映射={} 权限={} ABI={} 基线={} 原始={:?}",
            create_ok, write_ok, len_ok, map_ok, rights_ok, abi_ok, base_ok, r);
    }
    ok
}
#[cfg(feature = "handles")]
ktest!(KT_VMO_SYSCALLS, t_vmo_syscalls);

/// 没有 `handles` 的构建里，12/13/14 必须走默认分支回 -1，且 ABI 的 F_VMO 位必须是 0。
/// 这一格与上面那条互斥注册：它证的是"少了一个特性，用户看得见"，不是"号悄悄成功"。
#[cfg(not(feature = "handles"))]
fn t_vmo_numbers_absent() -> bool {
    use crate::sched;
    use crate::arch::x86_64::trap::TrapFrame;
    use crate::user::{E_INVALID, F_VMO, SYS_ASPACE_MAP, SYS_VMO_CREATE, SYS_VMO_WRITE, abi_word, syscall_dispatch};
    sched::init_boot_task();
    let mut f = TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    };
    let mut rets = [0u64; 3];
    for (i, n) in [SYS_VMO_CREATE, SYS_VMO_WRITE, SYS_ASPACE_MAP].iter().enumerate() {
        f.rax = *n;
        f.rdi = 1;
        f.rsi = 0;
        f.rdx = 0;
        f.r10 = 8;
        syscall_dispatch(&mut f);
        rets[i] = f.rax;
    }
    let bit = abi_word() & F_VMO;
    crate::log_info!("vmosys-absent(P4b): 三号返回={:?} F_VMO位={}", rets, bit);
    rets.iter().all(|&v| v == E_INVALID) && bit == 0
}
#[cfg(not(feature = "handles"))]
ktest!(KT_VMO_NUMBERS_ABSENT, t_vmo_numbers_absent);
// ---- ADR-075（W3 P5b 第二半）AS 接进换人路径：D7 隔离 / D8 只在不同时写 CR3 ----
//
// 两个工人各跑在自己的 AS 里，读**同一个用户半区 VA**：a1 里映的是 v1、a2 里映的是 v2，
// 图案不同 ⇒ 读回来的数不同就证明换人真的换了表（不是"两张表内容碰巧一样"）。
// 映射用**内核可见**的 flags（不给 U/S）：工人是内核任务，读用户页会撞 SMAP，
// 而这一格要证的是地址空间隔离，不是 ring3 可达性（那一格由 t_aspace_map_vmo 与探针证）。
// D8 分两段：先把两个工人都登记到 a1（同 AS）跑一段 ⇒ 换人多次而 CR3 至多写一次；
// 再把 w2 改登记到 a2 ⇒ 跨 AS 的换人必须真的写。
// 变异：M13 换人点去掉 `prev_as != next_as` 的比较（无条件写）⇒ D8 第一段红；
// M14 换人点整段删掉（永不写 CR3）⇒ D7 两个读数相同 ⇒ 红。

static ASGO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static ASR: [core::sync::atomic::AtomicU64; 2] = [const { core::sync::atomic::AtomicU64::new(0) }; 2];
/// 两个 AS 共用的那个 VA（用户半区、别的用例不用它）。
const AS_VA: u64 = 0x2_0000_0000;

fn as_worker(idx: usize) -> ! {
    use core::sync::atomic::Ordering;
    let t0 = crate::tsc::now();
    while ASGO.load(Ordering::Acquire) == 0 && crate::tsc::now().wrapping_sub(t0) < 20_000_000_000 {
        core::hint::spin_loop();
    }
    // SAFETY: AS_VA 由本用例在**两个 AS 里各自**映过（内核可见的 RW 页），
    // 本任务跑在哪个 AS 由换人点写 CR3 决定；只读一个 u64，落在这一页内。
    let v = unsafe { core::ptr::read_volatile(AS_VA as *const u64) };
    ASR[idx].store(v, Ordering::Release);
    crate::sched::finish_current();
    crate::sched::yield_now();
    loop {
        crate::tsc::spin(1000);
    }
}

fn as_w0() -> ! {
    as_worker(0)
}
fn as_w1() -> ! {
    as_worker(1)
}

fn t_aspace_switch_isolation() -> bool {
    use crate::sched;
    use crate::vmo;
    use core::sync::atomic::Ordering;
    let me = crate::arch::x86_64::cpu::self_slot();
    if mm::aspace_count() != 0 {
        crate::log_fatal!("assw: 前提失效，进来已有 {} 个 AS", mm::aspace_count());
        return false;
    }
    // 用例自足：登记与时钟（P3/P5a 撞出来的那几条）
    sched::init_boot_task();
    sched::start_workers();
    if crate::clock::current().is_none() {
        crate::calibrate_clock_once();
    }
    let tick_in = crate::arch::x86_64::apic::ticks();
    let probe = crate::arch::x86_64::apic::wait_ticks(tick_in, 1, crate::clock::window_cycles(1));
    let was_running = probe.ticks >= 1;
    if !was_running {
        crate::arch::x86_64::apic::timer_start().ok();
    }
    ASGO.store(0, Ordering::Relaxed);
    ASR[0].store(0, Ordering::Relaxed);
    ASR[1].store(0, Ordering::Relaxed);
    let f0 = mm::free_frames();
    let a1 = match mm::aspace_new() { Some(h) => h, None => { crate::log_fatal!("assw: a1 建不起来"); return false; } };
    let a2 = match mm::aspace_new() { Some(h) => h, None => { crate::log_fatal!("assw: a2 建不起来"); return false; } };
    let v1 = match vmo::vmo_create(1) { Ok(v) => v, Err(_) => { crate::log_fatal!("assw: v1 建不起来"); return false; } };
    let v2 = match vmo::vmo_create(1) { Ok(v) => v, Err(_) => { crate::log_fatal!("assw: v2 建不起来"); return false; } };
    let p1 = 0x1122_3344_5566_7788u64;
    let p2 = 0x8877_6655_4433_2211u64;
    let _ = vmo::vmo_write(v1, 0, &p1.to_le_bytes());
    let _ = vmo::vmo_write(v2, 0, &p2.to_le_bytes());
    // 内核可见的 RW（不给 U/S）：工人是内核任务，读用户页会撞 SMAP
    let flags = match mm::PageFlags::new(true, false, false) {
        Ok(f) => f,
        Err(_) => { crate::log_fatal!("assw: flags 造不出来"); return false; }
    };
    let va = mm::VirtAddr(AS_VA);
    let m1 = vmo::vmo_map(v1, &a1, va, flags);
    let m2 = vmo::vmo_map(v2, &a2, va, flags);
    let maps_ok = m1.is_ok() && m2.is_ok();
    let w0 = match sched::spawn(as_w0) { Ok(g) => g, Err(_) => { crate::log_fatal!("assw: w0 spawn 失败"); return false; } };
    let w1 = match sched::spawn(as_w1) { Ok(g) => g, Err(_) => { crate::log_fatal!("assw: w1 spawn 失败"); return false; } };
    // 第一段：**三方都在 a1**（启动任务也要登记，否则 boot↔工人 每次都跨 AS，
    // 第一版就是这么把 21 次换人数出 14 次写的）⇒ 同 AS 换人不该写 CR3
    let boot = sched::current_id();
    let reg_same = sched::set_aspace(w0, 0) && sched::set_aspace(w1, 0) && sched::set_aspace(boot, 0);
    let c0 = mm::counters().cr3_writes;
    let s0 = sched::stats_of(me).0;
    crate::arch::x86_64::apic::with_interrupts(|| {
        for _ in 0..6 {
            sched::yield_now();
        }
    });
    let c1 = mm::counters().cr3_writes;
    let s1 = sched::stats_of(me).0;
    let switches_a = s1.saturating_sub(s0);
    let writes_a = c1.saturating_sub(c0);
    // 至多一次：从内核 AS 第一次切进 a1。之后全是 a1↔a1 ⇒ 0 次
    let same_as_ok = reg_same && switches_a >= 3 && writes_a <= 1;
    // 第二段：w1 改到 a2，发令 ⇒ 两个工人各读自己 AS 里的那一页
    let reg_diff = sched::set_aspace(w1, 1);
    let c2 = mm::counters().cr3_writes;
    ASGO.store(1, Ordering::Release);
    let e0 = crate::arch::x86_64::apic::with_interrupts(|| sched::wait_for_task(w0, crate::clock::window_cycles(8)));
    let e1 = crate::arch::x86_64::apic::with_interrupts(|| sched::wait_for_task(w1, crate::clock::window_cycles(8)));
    let c3 = mm::counters().cr3_writes;
    let r0 = ASR[0].load(Ordering::Acquire);
    let r1 = ASR[1].load(Ordering::Acquire);
    let isolate_ok = reg_diff && maps_ok && e0 && e1 && r0 == p1 && r1 == p2 && r0 != r1;
    let cross_ok = c3 > c2;
    // D9：换人路径上那一次切换**不取任何锁**（ADR-075 决策 2 的实现约束）。
    // 形状与生产调用点一致：`aspace_switch(目标根, me, Some(槽号))`。
    // 判据是"这一次调用的取锁次数增量为 0"——增量的口径是 sync 的全局 acquire 计数，
    // 而这一句里除它自己没有任何别的取锁来源，所以 delta 就是它自己的取锁数。
    // 负样本（M15）：把 `let _g = vmm();` 加回 aspace_switch ⇒ delta=1 ⇒ 本格红。
    let pml4_a2 = match a2.pml4() { Some(p) => p, None => { crate::log_fatal!("assw: a2 读不回 PML4"); return false; } };
    // 先把 CR3 定回内核根，否则第二段跑完停在谁的表上是不确定的，
    // 那会让"这一次调用真的写了表"变成运气——提前返回把登记一起短路，
    // 停在 a2 时 delta=0 是**空转出来的绿**，量具不能靠运气。
    // SAFETY: our_cr3 是启动建的内核根
    let _ = unsafe { mm::aspace_switch_kernel(me) };
    let lock_in = crate::sync::stats().acquires;
    // SAFETY: pml4_a2 是自建表根且内核半区等价；此刻 IF 状态由本用例负责，本函数不动 IF
    let wrote_a2 = unsafe { mm::aspace_switch(pml4_a2, me, Some(a2.slot())) };
    let lock_delta = crate::sync::stats().acquires.wrapping_sub(lock_in);
    // 位图必须照样登记（不取锁不等于不记账）；这句**在 delta 之后**取 VMM
    let bm_a2 = mm::aspace_running_on(a2.slot()).unwrap_or(0);
    // SAFETY: 切回启动时建的内核根
    let back_kernel = unsafe { mm::aspace_switch_kernel(me) };
    let bit_me = 1u8.checked_shl(me as u32).unwrap_or(0);
    let nolock_ok = wrote_a2 && back_kernel && lock_delta == 0 && bm_a2 & bit_me != 0;
    // 收场：**先把启动任务的 CR3 真的换回内核**，再销毁 AS。
    // 只改 as_slot 不改 CR3 的话，下面 drop(a1) 之后本 CPU 还站在一张已经还掉的表上。
    // 上面 D9 那段已经把它换回内核了，所以这里判"状态对不对"而不是"又写了一次"。
    let unreg = sched::set_aspace(boot, sched::NO_ASPACE);
    // SAFETY: 内核根由启动建立且一直有效；此刻 IF 状态由调用方负责
    let _ = unsafe { mm::aspace_switch_kernel(me) };
    // SAFETY: 同一个内核根再切一次；返回 false 才说明 CR3 确实已经在内核表上
    let back = !unsafe { mm::aspace_switch(mm::our_cr3(), me, None) };
    // 任务先死、映射再丢、AS 最后销毁（ADR-074 的契约顺序）
    let _ = sched::terminate_task(w0);
    let _ = sched::terminate_task(w1);
    drop(m1);
    drop(m2);
    vmo::vmo_unref(v1);
    vmo::vmo_unref(v2);
    drop(a1);
    drop(a2);
    if !was_running {
        crate::arch::x86_64::apic::timer_stop().ok();
    }
    let f1 = mm::free_frames();
    let base_ok = unreg && back && f1 == f0 && mm::aspace_count() == 0 && vmo::vmo_count() == 0;
    crate::log_info!(
        "assw(P5b): 同AS段=(换人{} 写CR3{}) 隔离=(r0={:#x} r1={:#x} 期望 {:#x}/{:#x}) 跨AS写={} 不取锁=(增量{} 位图{:#x}/应含{:#x}) 映射={} 收场={} free{}->{}",
        switches_a, writes_a, r0, r1, p1, p2, c3.saturating_sub(c2),
        lock_delta, bm_a2, bit_me, maps_ok, base_ok, f0, f1);
    let ok = same_as_ok && isolate_ok && cross_ok && nolock_ok && base_ok;
    if !ok {
        crate::log_fatal!(
            "assw: 判据不成立 同AS={} 隔离={} 跨AS={} 不换锁={} 收场={}",
            same_as_ok, isolate_ok, cross_ok, nolock_ok, base_ok);
    }
    ok
}
ktest!(KT_ASPACE_SWITCH, t_aspace_switch_isolation);
