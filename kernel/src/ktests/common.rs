//! 跨用例共用的夹具与等待辅助（T0.1 从 main.rs 纯搬移）。

use crate::arch::x86_64::{apic};
use crate::arch::x86_64::trap::TrapFrame;
use crate::{sched, tsc, user};

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
/// 第四个用户产物（FS-03 切片 D，ADR-108 决策 8）：第一个在 ring3 打 22/24/25/26 的调用方。
/// 只在 `fs-open` 档嵌入——没有那一族号，这个容器除了 `-1` 什么都测不到。
#[cfg(feature = "fs-open")]
pub(crate) static FILEPROBE_ELF: &[u8] = include_bytes!("../../fixtures/fileprobe.elf");

/// A2 切片（ADR-130）：外部命令探针。只在 `a2-exec` 构建里被 include（init 编排的
/// `cfg` 门），构建入口 `tools/aurora.py` 的 `do_build_execprobe`。
pub(crate) static EXECPROBE_ELF: &[u8] = include_bytes!("../../fixtures/execprobe.elf");

/// D4（ADR-154）：**应用 SDK 的第一个样板**——真在 ring3 打 38/40 号（凭据与授权）
/// 的调用方，也是"怎么写一个 Aurora 应用"的活文档。
/// 只在 `handles` 档嵌入：38/40 号要凭据表，没有那条路它只能读到 `Err`。
#[cfg(feature = "handles")]
pub(crate) static SDKDEMO_ELF: &[u8] = include_bytes!("../../fixtures/sdkdemo.elf");

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
///
/// **2026-11-23 更正（ADR-243）**：这里的第二条曾经写的是「槽已 Free 是充分证据」，
/// 理由是「`reap` 先释放资源、再标 Free」。**那条前提只对 `reap` 成立，对 `terminate_task` 不成立**：
/// `terminate_task` 在拿队列锁时就把槽标成 `Free`，而 `release_owned` 要等到**放锁之后**
/// （持 RUNQ 去 drop `Mapping` 会反向嵌套，见 ADR-047 决策 2）。所以存在一个窗口：
/// **槽是 Free、而袋里还牵着映射**。`mod.rs` 的 `owned_of` 注释早就记过这句话——
/// 「槽位是 Free 不等于资源回去了」——只是这里没跟着改。
///
/// 后果不是「等得久一点」，而是**漏掉释放**：本函数一返回 true，调用方就不再进 `drain_reap`
/// 那个窗口，而没有 tick 就没有抢占点，回收脏位就永远不被消费 ⇒ 袋里的映射
/// （内核栈 4 页 + 一条 VA 保留）**再也没人放手**。实测 `t_q2_workload_slots`
/// 14 次跑 14 次红：`回滚不成立 f97212->97208(差 -4) va17->18(差 1)`。
///
/// 修法：`Free` 只在**袋也空了**时才算证据。袋子还在就说明释放还没发生，
/// 必须烧那个窗口让抢占点真的跑一次。
/// **没有放宽**：袋子空是释放已发生的直接证据（`release_owned` 把袋搬空之后才 drop），
/// 比原来的 `Free` 更强。
pub(crate) fn drained_or_free(rel0: u64, g: usize) -> bool {
    crate::sched::reap_released() > rel0
        || (crate::sched::state_of(g) == crate::sched::TaskState::Free
            && crate::sched::owned_of(g) == 0)
        || drain_reap_for(g)
}

/// **等这一个任务**的袋子真的空了（ADR-243）。
///
/// 为什么不能用 `drain_reap`：那个等的是**全局** `reap_released` 涨——
/// 别的 CPU 上任何一个任务被回收都会让它涨，于是「窗口里涨了」可以与本任务的释放
/// **完全无关**。实测 `t_q2_workload_slots` 在加了袋子检查之后仍有 1/5 红：
/// `回滚不成立 f97427->97423(差 -4) va21->22(差 1)`，而同一跑 `drained=true` ——
/// 判据以为收完了，实际本任务那 4 页内核栈还挂在袋里。
///
/// ## 判据是 `owned_of(g) == 0`（**已知不完美**）
///
/// 它由 `release_owned` 在搬出袋子时变 0（`core::mem::take(&mut ...owned.n)`），
/// 所以它是**本任务自己的**计数 —— 别的 CPU 的回收动不了它，不会像全局
/// `reap_released` 那样被噪声顶成真。
///
/// **但它不等于 `drop(bag)` 已跑完**（真正的解映射/还帧在那之后）。我试过改用
/// `kstack_lo == 0`（那一格确实是 `drop(bag)` 之后才清的），实测**更差**
/// （8 跑 5 红），已回退 —— 原因未查清，记在这里免得下一个人重走。
///
/// ## 2026-11-25 更正（BACKLOG §575）
///
/// `0x100002000` 的“第 2 页仍映射”不是长期泄漏：3 页保留拆成 2+1 两条 Mapping，
/// 第一条 drop 时第三条仍在，`release_va_locked` 正确推迟；第二条 drop 后保留与
/// 三帧全部归还。`t_va_reservation_split_drop` 已直查，`forget(m1)` 负样本精确红；
/// handles 40/40 PASS、完整矩阵 82/82。
pub(crate) fn drain_reap_for(g: usize) -> bool {
    let done = || crate::sched::owned_of(g) == 0;
    if done() {
        return true;
    }
    let ticks_before = sched::ticks_of(0);
    let timer_was_running = apic::timer_running();
    if !timer_was_running {
        if crate::clock::current().is_none() {
            crate::calibrate_clock_once();
        }
        apic::timer_start().ok();
    }
    let mut hit = false;
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        while tsc::now().wrapping_sub(t0) < 1_000_000_000 {
            if done() {
                hit = true;
                break;
            }
            tsc::spin(20_000);
        }
    });
    if !timer_was_running {
        apic::timer_stop().ok();
    }
    if !hit {
        crate::log_warn!(
            "reap: 窗口内这个任务的资源没交回 g={} state={:?} owned={} 窗口内 tick {}→{}",
            g,
            crate::sched::state_of(g),
            crate::sched::owned_of(g),
            ticks_before,
            sched::ticks_of(0)
        );
    }
    hit
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

// ---------------------------------------------------------------- 用户页与 syscall 夹具
// 从 `fs_open.rs` 提出来（23 号写方向要同一套）：三份各自维护，"用户页怎么造"就会漂成三份。
pub(crate) fn put_user(va: u64, off: usize, bytes: &[u8]) -> bool {
    matches!(user::copy_to_user(bytes, va + off as u64), Ok(n) if n == bytes.len())
}
pub(crate) fn get_user(va: u64, off: usize, dst: &mut [u8]) -> bool {
    matches!(user::copy_from_user(va + off as u64, dst), Ok(n) if n == dst.len())
}
pub(crate) fn frame0() -> TrapFrame {
    TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    }
}
pub(crate) fn call(fr: &mut TrapFrame, nr: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    fr.rax = nr;
    fr.rdi = a1;
    fr.rsi = a2;
    fr.rdx = a3;
    user::syscall_dispatch(fr);
    fr.rax
}
