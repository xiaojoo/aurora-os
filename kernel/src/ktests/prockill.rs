//! ADR-134：`kill` 的内核侧判据——18 号的句柄语义。
//!
//! `kill` 命令在用户态（shell），但**能不能杀**这件事全在内核。本用例只测约定面：
//! 1. **11 号建的 Proc 句柄带 `RIGHT_WRITE`** ⇒ 18 号能直接杀（句柄是 capability，
//!    授权由 11 号那一刀给出，不是 `kill` 自己另找的旁路）；
//! 2. 杀完进程 `terminated=true`（27/28 号看得到），线程被真收掉；
//! 3. 负样本：拿 **Job 句柄**打 18 号 ⇒ `-4`（类型不符不静默当成"杀不了"）；
//! 4. 负样本：进程被 reap 之后句柄失效 ⇒ `-5`（不是 -4）；
//! 5. 用例自清：进程/Job 清零、句柄关掉。
//!
//! **为什么这里不测"按 pid 杀"**：句柄是 capability，能看到 pid 不等于能杀
//! （ADR-134 决策 1）。按 pid 反查句柄是用户态的账（shell 记 `(pid, 句柄)`），
//! 内核不提供那个号——本用例证明的正是"必须经手柄"这条。

use crate::arch::x86_64::trap::TrapFrame;
use crate::handle::{self, Handle};
use crate::ktest;
use crate::user::{self, syscall_dispatch};
use crate::{proc, sched};

/// 本用例专用的等待队列号（与 `p7b` 的 4 号错开，避免两个用例抢同一张队列）。
const PKILL_QID: u8 = 6;

fn frame0() -> TrapFrame {
    TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    }
}

/// 被杀的工人：登记到进程名下，然后**阻塞在等待队列上**等死。
///
/// **为什么必须起真的线程**：18 号杀的是**线程**（`kill_process_threads` 扫 72 格
/// 按 proc_id 认）。没有线程的进程被杀时，`proc_thread_exited` 没人调用 ⇒ 进程**不会**
/// 变成僵尸（实测：本片第一版判据 `已终止=false`）——那种结局只能走 `proc_discard`
/// 回滚，不是"杀"的形状。起一条线程，杀完才验得到"真收掉 1 条 + 进程已终止"。
///
/// **为什么阻塞而不是自旋**（第一版自旋 ⇒ 整档 HANG，实测）：自旋的工人 IF=0 占着
/// CPU 不让出，被杀之前 BSP 等它就再也回不来（BACKLOG 记过的 wedge 形状：截断的
/// worker 按"活跃必让出"归类）。阻塞在等待队列上的工人让出 CPU、能被 18 号收掉，
/// deadline 取 20 个 tick 兜底——被杀后那两份注册是孤儿，让轮自己到期把槽放开
/// （与 `p7b_blocked_worker` 同一条纪律，见 sched.rs 的注释）。
fn kill_worker() -> ! {
    if let Some(q) = crate::sync::wait_queue(PKILL_QID) {
        let tick = crate::clock::current().map_or_else(
            crate::clock::max_tick_period_cycles,
            |c| c.tick_period_cycles,
        );
        let _ = q.wait_while_until(
            PKILL_QID,
            || false, // 条件永不成立 ⇒ 一直等到被杀
            crate::tsc::now().wrapping_add(tick * 20),
        );
    }
    sched::finish_current();
    loop {
        crate::tsc::spin(3_000);
    }
}

/// 一个 Job + 它名下的一个进程（**不起线程**：本用例只测句柄语义）。
fn make_job_proc(owner: (usize, u32)) -> Option<(Handle, Handle, u16, u16)> {
    let job = proc::job_create(None, 2, 64).ok()?;
    let jgen = proc::job_gen(job).unwrap_or(0);
    let hj = handle::grant_job(
        owner,
        job,
        jgen,
        handle::RIGHT_READ | handle::RIGHT_CREATE | handle::RIGHT_TRANSFER,
    )
    .ok()?;
    let mut f = frame0();
    f.rax = user::SYS_PROCESS_CREATE;
    f.rdi = hj.0;
    syscall_dispatch(&mut f);
    let hp = Handle(f.rax);
    match handle::resolve(hp, owner, 0) {
        Ok((handle::ObjRef::Proc { slot, .. }, _)) => Some((hj, hp, slot, job)),
        _ => None,
    }
}

fn t_proc_kill() -> bool {
    use crate::user::E_DENIED;
    crate::log_info!("prockill: 起（18 号的句柄语义判据）");
    // 与 `t_proc_info` 同一条纪律：`.ktests` 次序由链接器决定，排在前面时任务 0
    // 还没登记 ⇒ 先探、缺了才建；排在后面时再调会重写 tasks[0] 的 owned 袋，
    // 把别的用例的现场清掉（那次的症状记在 procinfo.rs 的注释里）。
    if sched::current_identity().is_none() {
        sched::init_boot_task();
    }
    let Some(owner) = sched::current_identity() else {
        crate::log_fatal!("prockill: 没有当前任务身份");
        return false;
    };

    let Some((hj, hp, pid, job_slot)) = make_job_proc(owner) else {
        crate::log_fatal!("prockill: 造 Job/Proc 失败");
        return false;
    };

    // ---- ① 11 号给的句柄带 `RIGHT_WRITE`**（`has` 是句柄层的权限查询）。
    //     这一格是"kill 能干活"的前提：18 号要 WRITE，没有它就一路 -5。
    let writable_ok = handle::has(hp, owner, handle::RIGHT_WRITE);

    // ---- ①' **收窄权限后就不能杀**（capability 语义的核心负样本）。
    //     `handle_dup` 把同一个进程复制成一份只有 READ 的句柄 ⇒ 拿它打 18 号必须被拒。
    //     这一格证明"18 号按句柄权限判"，而不是"拿到 pid 就能杀"。
    //     负样本（变异）：把 18 号的 `RIGHT_WRITE` 要求去掉 ⇒ 这一格红。
    let narrowed = handle::dup(hp, owner, handle::RIGHT_READ).ok();
    let narrow_denied = match narrowed {
        Some(hn) => {
            let mut fn1 = frame0();
            fn1.rax = user::SYS_PROCESS_KILL;
            fn1.rdi = hn.0;
            syscall_dispatch(&mut fn1);
            let denied = fn1.rax == crate::user::E_DENIED;
            let _ = handle::close(hn, owner);
            denied
        }
        None => false,
    };

    // ---- ② 负样本：拿 **Job 句柄**打 18 号 ⇒ -4（类型不符）。
    let mut f2 = frame0();
    f2.rax = user::SYS_PROCESS_KILL;
    f2.rdi = hj.0;
    syscall_dispatch(&mut f2);
    let type_ok = f2.rax == E_DENIED;

    // ---- ③ 给进程起一条真线程（否则杀完不是僵尸，见 `kill_worker` 的注释）。
    let attached = proc::proc_attach_thread(pid).is_ok();
    let mut gid = usize::MAX;
    let mut spawned = false;
    match sched::spawn(kill_worker) {
        Ok(g) => {
            spawned = sched::set_proc_id(g, pid);
            gid = g;
            // **不要求它"跑过一次"也不要求它"已阻塞"**：18 号扫的是
            // `state != Free && proc_id == pid`（`kill_process_threads`），线程**在槽里、
            // 归属已登记**就够了。两版更严的判据都红过：等"变 Blocked"在 a2-exec 档
            // 不成立（实测 run-1744/run-1749：那个档的调度环境与 handles 档不同，
            // 工人未必在 200 轮 `yield_now` 里被换上去）；等 `runs > 0` 同样不成立
            // （它可能还没被调度过就被 18 号收了）。
            // 这一格只验**归属登记**这件事：线程槽的 proc_id 就是我们建的那个进程。
        }
        Err(_) => {}
    }
    let owned_ok = gid != usize::MAX
        && sched::state_of(gid) != sched::TaskState::Free
        && sched::proc_id_of(gid) == pid;
    let threads_ok = attached && spawned && owned_ok;

    // ---- ④ 18 号杀它 ⇒ 真收掉 1 条线程、进程变僵尸。
    let mut f3 = frame0();
    f3.rax = user::SYS_PROCESS_KILL;
    f3.rdi = hp.0;
    syscall_dispatch(&mut f3);
    let killed_rc = f3.rax;
    // 收掉的线程数：这条进程名下**恰好一条**线程 ⇒ 必须是 1。
    // （用 `== 1` 而不是 `>= 1`：多收一条就意味着 proc_id 认错了人。）
    let killed_ok = killed_rc == 1;
    // 杀完必须是"已终止"（27/28 号看得到 `terminated`）。
    let terminated_ok = proc::proc_is_terminated(pid);

    // ---- ④ 负样本：句柄失效（进程已被 reap）⇒ -5，不是 -4。
    //     先 reap 再打 18 号：18 号的判据是 `proc_live(pid, gen)` 不成立 ⇒ E_BAD_HANDLE。
    let reaped = proc::proc_reap(pid).is_ok();
    let mut f4 = frame0();
    f4.rax = user::SYS_PROCESS_KILL;
    f4.rdi = hp.0;
    syscall_dispatch(&mut f4);
    let stale_ok = reaped && f4.rax == crate::user::E_BAD_HANDLE;

    // ---- 清理：Job 销掉、两个句柄关掉。收尾不变量会点名"还有进程记录没交出去"
    //     与"还有句柄没关"，所以清理失败也要红。
    let mut cleaned = true;
    cleaned &= proc::job_destroy(job_slot).is_ok();
    for h in [hj, hp] {
        cleaned &= handle::close(h, owner).is_ok();
    }

    let ok = writable_ok && narrow_denied && type_ok && threads_ok && killed_ok && terminated_ok
        && stale_ok && cleaned;
    crate::log_info!(
        "prockill: 判据={} 句柄带WRITE={} 收窄拒={} 类型拒={} 有线程={} 杀掉={} 已终止={} 句柄失效={} 清理={}",
        ok, writable_ok, narrow_denied, type_ok, threads_ok, killed_ok, terminated_ok, stale_ok, cleaned
    );
    ok
}
ktest!(KT_PROC_KILL, t_proc_kill);
