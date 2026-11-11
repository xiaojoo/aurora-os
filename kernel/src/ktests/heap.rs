//! 内核堆分配器与锁重入用例（T0.1 纯搬移）。

use crate::{heap, mm};
use crate::ktest;
use alloc::vec::Vec;

/// 全局分配器是否真的挂上了：直接用 `Vec`，走的就是 `AuroraGlobal`。
/// 这比单测 `try_alloc` 更实在——它证明 `alloc` 钩子被 std/alloc  machinery 调用且没走到
/// handle_alloc_error（那会变成 panic → 39，这里要求的是它正常返回）。
fn t_global_allocator_backs_vec() -> bool {
    let before = heap::stats();
    let mut v: Vec<u64> = Vec::new();
    for i in 0..64u64 {
        v.push(i * i);
    }
    let mid = heap::stats();
    let sum_ok = v.len() == 64 && v[8] == 64 && v[63] == 3969;
    let grew = mid.alloc_calls > before.alloc_calls;
    drop(v);
    let after = heap::stats();
    crate::log_info!(
        "heap vec: alloc {} -> {} -> {}, live {} -> {} -> {}",
        before.alloc_calls, mid.alloc_calls, after.alloc_calls, before.live_bytes, mid.live_bytes, after.live_bytes
    );
    // 释放后存活字节必须回到基线，否则就是分配器把内存吞了
    sum_ok && grew && after.live_bytes == before.live_bytes && after.live_count == before.live_count
}
ktest!(KT_VEC_ALLOC, t_global_allocator_backs_vec);

/// 释放后再分配同一大小类，应当复用槽位（不继续吃 bump 指针）
fn t_heap_reuses_freed_slot() -> bool {
    let l = match core::alloc::Layout::from_size_align(100, 8) {
        Ok(l) => l,
        Err(_) => return false,
    };
    let a = heap::try_alloc(l);
    let bump_after_first = heap::stats().window_used;
    let Some(p) = a else {
        crate::log_fatal!("heap try_alloc(100) failed");
        return false;
    };
    // SAFETY: p 是刚分配的 128 字节槽位
    unsafe { core::ptr::write_bytes(p, 0x5a, 100) };
    // SAFETY: 同一槽位归还
    unsafe {
        if !heap::dealloc_small(p, 100) {
            return false;
        }
    }
    let b = heap::try_alloc(l);
    let reused = b == Some(p);
    let bump_after = heap::stats().window_used;
    crate::log_info!("heap reuse: reused={} window_used {} -> {}", reused, bump_after_first, bump_after);
    reused && bump_after == bump_after_first
}
ktest!(KT_HEAP_REUSE, t_heap_reuses_freed_slot);

/// 超过大小类上限的请求必须**显式失败**并计入 OOM 计数（ADR-018），
/// 而不是悄悄走进一条没做完的大对象路径。
fn t_heap_rejects_oversize() -> bool {
    let l = match core::alloc::Layout::from_size_align(heap::LARGE_MAX + 1, 8) {
        Ok(l) => l,
        Err(_) => return false,
    };
    let before = heap::stats().oom_count;
    let got = heap::try_alloc(l);
    let after = heap::stats().oom_count;
    crate::log_info!("heap oversize: got={:?} oom {} -> {}", got.is_none(), before, after);
    got.is_none() && after == before + 1
}
ktest!(KT_HEAP_OVERSIZE, t_heap_rejects_oversize);

/// 交出去的每一个槽位，首尾两字节所在页都必须**真的映射过**。
///
/// 这条是 M2-b 第一版故障的复现用例：当时补映射的判据拿分配光标当映射前沿，
/// 光标恰好压在页边界上时 `need < aligned` 不成立，于是把从未映射的页发了出去，
/// 现场是写在窗口内 1.06 MiB 处的 #PF(err=0x2)。用例刻意越过预映射的 16 个 chunk，
/// 让补映射这条真路被走到——不走过它的分配器测不出这个 bug。
fn t_heap_slots_are_mapped() -> bool {
    let oom_before = heap::stats().oom_count;
    let mut held: Vec<(*mut u8, usize)> = Vec::new();
    for cls in [heap::LARGE_MAX, 1024usize, 16usize] {
        let l = match core::alloc::Layout::from_size_align(cls, 8) {
            Ok(l) => l,
            Err(_) => return false,
        };
        for i in 0..40 {
            let Some(p) = heap::try_alloc(l) else {
                crate::log_fatal!("heap slots: cls={} alloc #{} failed", cls, i);
                return false;
            };
            let tail = (p as usize) + cls - 1;
            let head_page = (p as u64) & !(mm::PAGE as u64 - 1);
            let tail_page = (tail as u64) & !(mm::PAGE as u64 - 1);
            // 先问页表再写：顺序反过来时故障会先进异常处理器，
            // 现象从“一条 FAIL(35) 的用例”变成“整个构建 39”，归因难度差一个量级。
            if !mm::is_mapped(head_page) || !mm::is_mapped(tail_page) {
                crate::log_fatal!("heap slot {:#x}..{:#x} lands on unmapped page", p as usize, tail);
                return false;
            }
            // SAFETY: p 是刚交出的 cls 字节槽位，上一步已确认首尾页都在
            unsafe {
                core::ptr::write_volatile(p, 0x4c);
                core::ptr::write_volatile(p.add(cls - 1), 0x7a);
            }
            // SAFETY: 同上，且写入紧接在读回之前，中间没有释放
            let head_ok = unsafe { core::ptr::read_volatile(p) } == 0x4c;
            let tail_ok = unsafe { core::ptr::read_volatile(p.add(cls - 1)) } == 0x7a;
            if !(head_ok && tail_ok) {
                crate::log_fatal!("heap slot {:#x} read-back wrong", p as usize);
                return false;
            }
            held.push((p, cls));
        }
    }
    let st = heap::stats();
    crate::log_info!("heap slots: {} held, window used={} mapped={}", held.len(), st.window_used, st.window_mapped);
    let frontier = heap::frontier_covered();
    // 归还，别把这些槽位留在存活计数里污染后面用例的读数
    for (p, cls) in held {
        // SAFETY: 每个指针都来自上面那次 try_alloc，大小一致
        unsafe {
            if !heap::dealloc_small(p, cls) {
                return false;
            }
        }
    }
    frontier && st.window_mapped >= st.window_used && st.oom_count == oom_before
}
ktest!(KT_HEAP_SLOTS_MAPPED, t_heap_slots_are_mapped);

/// 故障注入（§7.1 R16）：同一上下文重复获取堆锁，必须被 `held_by` 认出并升 L4。
/// 走到注入函数内部之后就不会返回（重入被抓就是 39）；真的返回了说明检测器是假的。
#[cfg(feature = "fault-lock-reentrant")]
fn t_lock_reentry_must_escalate() -> bool {
    crate::log_warn!("fault-lock-reentrant: 按设计重复获取堆锁");
    heap::force_reentrant_lock_for_test();
    false
}
#[cfg(feature = "fault-lock-reentrant")]
ktest!(KT_LOCK_REENTRY, t_lock_reentry_must_escalate);

/// 故障注入（ADR-081 决策 4）：同一上下文重复获取 GROW(4)，必须被认出并升 L4。
#[cfg(feature = "fault-grow-reentrant")]
fn t_grow_reentry_must_escalate() -> bool {
    crate::log_warn!("fault-grow-reentrant: 按设计重复获取 GROW(4)");
    heap::force_reentrant_grow_for_test();
    false
}
#[cfg(feature = "fault-grow-reentrant")]
ktest!(KT_GROW_REENTRY, t_grow_reentry_must_escalate);

