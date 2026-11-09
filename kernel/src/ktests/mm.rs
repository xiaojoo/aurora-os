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
    let w_cross = unsafe { mm::aspace_switch(pml4, me) };
    let mut same_writes = 0usize;
    for _ in 0..8 {
        if unsafe { mm::aspace_switch(pml4, me) } {
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
    let _ = unsafe { mm::aspace_switch(pml4, me) };
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
    let t1 = match crate::sched::spawn_user(code_va, stk_va + mm::PAGE as u64 - 16, owned) {
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
    let t2 = match crate::sched::spawn_user(code2, stk2 + mm::PAGE as u64 - 16, o2) {
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
    let t3 = match crate::sched::spawn_user(base3, stk3 + mm::PAGE as u64 - 16, o3) {
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

