//! 资源台账平衡用例（T0.1 纯搬移）。

use crate::{heap, mm, resource};
use crate::ktest;

/// 资源台账（§6.7“按模块汇总存活分配”）的三条不变量 + 一台交叉仪器：
/// 1. `Σ live == Σ alloc − Σ free`（台账自洽）
/// 2. 测试模块结束时必须清零——用例自己不许漏内存
/// 3. 堆的台账帧数 == 堆自己报的映射页数（两个独立计数指同一批页框，缺一不可对不上）
/// 4. 没有模块号落在表外（`unknown_module_hits`），否则报告会长得好看但漏计
fn t_resource_ledger_balanced() -> bool {
    let tt = resource::totals();
    let balanced = tt.sum_live == tt.sum_alloc.saturating_sub(tt.sum_free);
    let test_live = resource::live_of(mm::MOD_TEST);
    let heap_live = resource::live_of(heap::MOD_HEAP_CORE);
    let heap_mapped = heap::stats().window_mapped / mm::PAGE;
    let mut i = 0usize;
    while let Some(e) = resource::entry(i) {
        crate::log_info!("ledger: module {} live={} frames alloc={} calls={}", e.module, e.live_frames, e.alloc_frames, e.alloc_calls);
        i += 1;
    }
    crate::log_info!(
        "ledger totals: live={} alloc={} free={} unknown_hits={} violation={} heap_live={} vs mapped={}",
        tt.sum_live, tt.sum_alloc, tt.sum_free, tt.unknown_module_hits, tt.violation, heap_live, heap_mapped
    );
    balanced && test_live == 0 && heap_live == heap_mapped && tt.unknown_module_hits == 0 && !tt.violation
}
ktest!(KT_LEDGER, t_resource_ledger_balanced);

