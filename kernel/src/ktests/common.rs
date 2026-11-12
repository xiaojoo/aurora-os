//! 跨用例共用的夹具与等待辅助（T0.1 从 main.rs 纯搬移）。

use crate::arch::x86_64::{apic};
use crate::{sched, tsc};

// ---------------------------------------------------------------- M4-2：ELF 容器
//
/// 第一个用户程序的 ELF 产物。由 `python tools/aurora.py build` 从 `user/hello`
/// 构建后写到这里（ADR-016：一条命令做完全套），所以它是**真工具链的产物**：
/// `rustc`/`lld` 会产出多段、带 `.debug_*` 但不进 PT_LOAD、`filesz == memsz` 这类
/// 我手编不出来的形状。手编的字节只能证明"我读的位置和我写的位置一致"，
/// 证明不了"我假设的那个形状真的存在"。
pub(crate) static HELLO_ELF: &[u8] = include_bytes!("../../fixtures/hello.elf");
/// 第二个用户产物（W3 P5a，ADR-075）：真在 ring3 打 12/13/14 的探针。
/// 与 hello 一样由 `tools/aurora.py build` 现构建、只在字节变了时覆写；**不进签名链**。
#[cfg(feature = "handles")]
pub(crate) static PROBE_ELF: &[u8] = include_bytes!("../../fixtures/probe.elf");
/// 第三个用户产物（S5c）：串口 shell。与前两个同一条构建纪律，**不进签名链**。
/// 只在 `handles` 档嵌入：控制台句柄要经 `grant_console` 授予，默认档没有这条路。
#[cfg(feature = "handles")]
pub(crate) static SHELL_ELF: &[u8] = include_bytes!("../../fixtures/shell.elf");

/// M4-2 第二段：把**真 ELF** 装进用户窗口并跑起来。
///
/// 与 `t_user_roundtrip` 的分工是刻意的：那条继续用内核自己编的 66 字节镜像，
/// 它管"入口/ABI/kill/SMAP"这套机制；这条管"容器 → 页表 → ring3"这段路，
/// 判据因此全在**装完之后的生效位与程序自己写回的数**上。
/// 两条一起才完整：blob 那条不经过加载器，容器这条不经过手写机器码。
/// 夹具这一版会打的系统调用总数：1 次 ping + 29 次归因用的 ping + add + unknown。
/// 改了 `user/hello` 的调用次数就要改这里——**用例等的是"打完"而不是"开始打了"**。
pub(crate) const P7_CALLS: u64 = 32;

/// 让本 CPU 过一次抢占点，把"标了 Free 但还牵着映射"的槽位放手。
///
/// 为什么需要它而不是在测试里直接释放：正在 CPU 上跑的那个任务的映射**不能**由它自己解映射
/// （rsp 就在里面）。回收只发生在"本 CPU 上跑的已经不是它"的那一刻，
/// 而那一刻的唯一来源是中断出口路过 `preempt_point` ⇒ 想回收就得开一次窗口让 tick 进来。
/// "它的资源已经交回去了"的判据（P6c）。**回收时刻确定之后**，释放可能发生在观测窗口之前，
/// 所以只要求"释放数在窗口内涨"会假红（实测 `released=1→1` 而槽早已 Free）。
/// 三个等价证据按代价从低到高排：增量已在 → 槽已归化成 Free → 才烧 `drain_reap` 那个窗口。
/// 槽已 Free 是充分证据：`reap` 是**先释放资源、再标 Free** 的，所以 Free 蕴含释放已发生。
pub(crate) fn drained_or_free(rel0: u64, g: usize) -> bool {
    crate::sched::reap_released() > rel0
        || crate::sched::state_of(g) == crate::sched::TaskState::Free
        || drain_reap()
}

pub(crate) fn drain_reap() -> bool {
    // **等的是"回收发生了"，不是"过了多少毫秒"**。第一版这里写的是固定时长 30M 周期
    // (≈9 ms)，而 tick 的周期是 10 ms —— 于是一轮 tick 都可能进不来，
    // 判据读到的就是"还没回收"（`released` 不动、`reservations` 还 +5），
    // 而那**不是被测代码的错，是用例的等待条件不成立**。
    // 改成轮询 `reap_released()` 真的涨之后，上限仍留了一次实测的坑：本机 `bench` 连着
    // 第二次启动（宿主正忙）时，120M 周期(≈36 ms，只够 3 轮 tick)到过窗 ⇒ `KT_USER_POINTER`
    // 报假红。上限抬到 1G 周期(≈300 ms)，并且**失败时把窗口里到底进来了几轮 tick 一起打**——
    // 下一次再红，就能分清"tick 没进来"（环境）与"tick 进来了但没回收"（被测代码）。
    let before = sched::reap_released();
    let ticks_before = sched::ticks_of(0);
    let mut hit = false;
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        while tsc::now().wrapping_sub(t0) < 1_000_000_000 {
            if sched::reap_released() > before {
                hit = true;
                break;
            }
            tsc::spin(20_000);
        }
    });
    if !hit {
        // `warn` 而不是 `fatal`：这个函数有三个调用点，其中两个把返回值当判据（红会从
        // 用例本身出来），第三个明确"可能本来就没有待收的"（旁观者路径已就地回收）。
        // 在这里打 fatal 会让每一跑都固定有一条不失败的 fatal，看惯之后就没人看 fatal 了。
        crate::log_warn!(
            "reap: 窗口内没看到回收 released={}→{} 窗口内 tick {}→{}（调用方自己决定这算不算失败）",
            before,
            sched::reap_released(),
            ticks_before,
            sched::ticks_of(0)
        );
    }
    hit
}

