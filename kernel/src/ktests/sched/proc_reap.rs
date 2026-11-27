//! ADR-270：83 号 `proc_reap` 的内核侧判据。**未编译未运行**。形状沿用 `prockill.rs`。
//!
//! 九格（每格都有"能让它变红"的负样本，见各格注释；变异开关见 `kernel/Cargo.toml`）：
//! ① 进程**还在跑**时 reap ⇒ `E_DENIED`，且进程**仍存在、仍占额度**（"不是杀"）；
//! ② 杀成僵尸后 reap ⇒ 返回**退出码**，且与 `proc_exit_code` 在 reap 前读到的值一致；
//! ③ **槽与额度回来了**：reap 前 Job 的 `job_used_procs` 比基线多 1，reap 后回基线；Job 满额时再 `process_create` 先失败、reap 后成功；
//! ④ **页数回基线**（含 fd 表，ADR-180）：reap 前先 `proc_fd_table` 触发懒分配，`free_frames` 在 reap 后必须回到分配之前；
//!    变异 `fault-reap-leak-fdtable`（复现 ADR-180 漏改的旧缺陷）⇒ 本格红；
//! ⑤ 成功后**调用方的句柄已关**：再 reap ⇒ `E_BAD_HANDLE`（不是 -4）；
//! ⑥ **`dup` 出的副本靠世代失效**：reap 后拿副本再 reap/kill ⇒ `E_BAD_HANDLE`，且**复用同一槽的新进程不会被副本误伤**（ABA）；
//! ⑦ 权限：收窄成只有 `READ` 的副本 ⇒ `E_DENIED`，且进程**未被收**；
//! ⑧ 类型：拿 **Job 句柄**打 83 ⇒ `E_DENIED`；
//! ⑨ 防空转证人：`proc_reap_calls()` 增量 == 成功次数（不是"全走了失败分支也绿"）。
//! 用例自清：Job/句柄全收；收尾不变量会点名残留进程记录。

use crate::arch::x86_64::trap::TrapFrame;
use crate::handle::{self, Handle};
use crate::ktest;
use crate::user::{self, syscall_dispatch};
use crate::{mm, proc, sched};

/// 本用例专用等待队列号（与 prockill 的 6 错开）。
const PREAP_QID: u8 = 7;

fn frame0() -> TrapFrame {
    TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    }
}

/// 工人：阻塞等死（理由同 `prockill::kill_worker`：自旋会 wedge，必须让出 CPU 才能被 18 号收掉）。
fn reap_worker() -> ! {
    if let Some(q) = crate::sync::wait_queue(PREAP_QID) {
        let tick = crate::clock::current().map_or_else(
            crate::clock::max_tick_period_cycles,
            |c| c.tick_period_cycles,
        );
        let _ = q.wait_while_until(PREAP_QID, || false, crate::tsc::now().wrapping_add(tick * 20));
    }
    sched::finish_current();
    sched::yield_now();
    loop {
        crate::tsc::spin(3_000);
    }
}

fn call(nr: u64, a1: u64) -> u64 {
    let mut f = frame0();
    f.rax = nr;
    f.rdi = a1;
    syscall_dispatch(&mut f);
    f.rax
}

/// 一个 Job（额度 `max_procs`）。
fn make_job(owner: (usize, u32), max_procs: u32) -> Option<(Handle, u16)> {
    let job = proc::job_create(None, max_procs, 64).ok()?;
    let jgen = proc::job_gen(job).unwrap_or(0);
    let hj = handle::grant_job(owner, job, jgen, handle::RIGHT_READ | handle::RIGHT_CREATE | handle::RIGHT_TRANSFER).ok()?;
    Some((hj, job))
}

/// 在 Job 名下建一个进程并起一条真线程（否则杀完不是僵尸，见 prockill）。
fn make_proc_with_thread(owner: (usize, u32), hj: Handle) -> Option<(Handle, u16)> {
    let hp = Handle(call(user::SYS_PROCESS_CREATE, hj.0));
    let pid = match handle::resolve(hp, owner, 0) {
        Ok((handle::ObjRef::Proc { slot, .. }, _)) => slot,
        _ => return None,
    };
    if proc::proc_attach_thread(pid).is_err() {
        return None;
    }
    let g = sched::spawn(reap_worker).ok()?;
    if !sched::set_proc_id(g, pid) {
        return None;
    }
    Some((hp, pid))
}

fn t_proc_reap_syscall() -> bool {
    crate::log_info!("preap: 起（83 号 proc_reap 的判据）");
    if sched::current_identity().is_none() {
        sched::init_boot_task();
    }
    let Some(owner) = sched::current_identity() else {
        crate::log_fatal!("preap: 没有当前任务身份");
        return false;
    };
    let calls0 = user::proc_reap_calls();
    let Some((hj, job)) = make_job(owner, 2) else {
        crate::log_fatal!("preap: 造 Job 失败");
        return false;
    };
    // 用 **Job 的已用额度**做基线（`job_used_procs`）而不是全局进程计数：别的任务同时建/收进程不会干扰本用例。
    let procs_base = proc::job_used_procs(job).unwrap_or(u32::MAX);
    let Some((hp, pid)) = make_proc_with_thread(owner, hj) else {
        crate::log_fatal!("preap: 造进程/线程失败");
        let _ = proc::job_destroy(job);
        let _ = handle::close(hj, owner);
        return false;
    };
    let pgen = proc::proc_gen(pid).unwrap_or(0);

    // ---- ⑥ 先留一份 dup 副本（带 WRITE，会在 reap 后因世代失效）与一份只读副本（⑦ 用）
    let copy = handle::dup(hp, owner, handle::RIGHT_READ | handle::RIGHT_WRITE).ok();
    let ro = handle::dup(hp, owner, handle::RIGHT_READ).ok();

    // ---- ① 还在跑 ⇒ E_DENIED，且进程仍在、仍占额度（"不是杀"）
    let live_rc = call(user::SYS_PROC_REAP, hp.0);
    let still_there = proc::proc_live(pid, pgen) && !proc::proc_is_terminated(pid) && proc::job_used_procs(job) == Some(procs_base + 1);
    let c1 = live_rc == user::E_DENIED && still_there;

    // ---- ⑦ 只读副本 ⇒ E_DENIED（句柄层拒；进程未被收）
    let c7 = match ro {
        Some(h) => call(user::SYS_PROC_REAP, h.0) == user::E_DENIED && proc::proc_live(pid, pgen),
        None => false,
    };

    // ---- ⑧ 类型：Job 句柄 ⇒ E_DENIED
    let c8 = call(user::SYS_PROC_REAP, hj.0) == user::E_DENIED;

    // ---- ④ 触发 fd 表懒分配（与 sys_fd_install 同一条 `proc_fd_table`），记页数；之后杀、收
    let frames_before_fd = mm::free_frames();
    let fd_alloc = proc::proc_fd_table(pid, pgen).is_some();
    let frames_after_fd = mm::free_frames();
    let fd_cost_visible = fd_alloc && frames_after_fd < frames_before_fd; // 防空转证人：fd 表真的占了页

    // 杀成僵尸
    let killed = call(user::SYS_PROCESS_KILL, hp.0) == 1;
    let terminated = proc::proc_is_terminated(pid);
    let code_before = proc::proc_exit_code(pid);
    let jobfull_before = {
        // Job 额度 2，已占 1；再建一个占满，第三个必须失败
        let h2 = Handle(call(user::SYS_PROCESS_CREATE, hj.0));
        let third = call(user::SYS_PROCESS_CREATE, hj.0);
        let full = third == user::E_EXHAUSTED;
        // 归还第二个（没线程 ⇒ discard 路径）
        if let Ok((handle::ObjRef::Proc { slot, .. }, _)) = handle::resolve(h2, owner, 0) {
            let _ = proc::proc_discard(slot);
        }
        let _ = handle::close(h2, owner);
        full
    };

    // ---- ② 杀成僵尸后 reap ⇒ 退出码
    let fdrel0 = proc::proc_reap_fd_releases();
    let rc = call(user::SYS_PROC_REAP, hp.0);
    let c2 = killed && terminated && rc == u64::from(code_before);

    // ---- ③ 额度回来了：进程计数回基线；Job 满额时 reap 后能再建
    let c3a = proc::job_used_procs(job) == Some(procs_base);
    let again = Handle(call(user::SYS_PROCESS_CREATE, hj.0));
    let again_proc = match handle::resolve(again, owner, 0) {
        Ok((handle::ObjRef::Proc { slot, gen }, _)) => Some((slot, gen)),
        _ => None,
    };
    let c3b = again_proc.map(|(slot, gen)| {
        proc::proc_live(slot, gen) && !proc::proc_is_terminated(slot)
    }).unwrap_or(false);
    if let Some((slot, _)) = again_proc {
        let _ = proc::proc_discard(slot);
    }
    let _ = handle::close(again, owner);
    let c3 = jobfull_before && c3a && c3b;

    // ---- ④ 页数回基线（**本用例最关键的一格**）：fd 表也必须还。
    //     注意基线取在 fd 表分配**之前**；reap 之后 `free_frames` 必须 >= 基线（不要求恰好相等：
    //     别的任务可能同时归还页，但**绝不能更少**——更少就是漏）。
    let frames_after_reap = mm::free_frames();
    let fdrel1 = proc::proc_reap_fd_releases();
    let c4 = fd_cost_visible && fdrel1 == fdrel0 + 1 && frames_after_reap >= frames_before_fd;

    // ---- ⑤ 成功后句柄已被内核关闭 ⇒ 再 reap = E_BAD_HANDLE（不是 -4）
    let c5 = call(user::SYS_PROC_REAP, hp.0) == user::E_BAD_HANDLE;

    // ---- ⑥ 副本靠世代失效：reap/kill 都得 E_BAD_HANDLE；新进程复用同一槽时副本不得误伤它
    let wrong_gen_rejected = proc::proc_reap_gen(pid, pgen.wrapping_add(1)) == Err(proc::ProcError::NoSuchProc);
    let c6a = match copy {
        Some(h) => call(user::SYS_PROC_REAP, h.0) == user::E_BAD_HANDLE && call(user::SYS_PROCESS_KILL, h.0) == user::E_BAD_HANDLE,
        None => false,
    };
    let c6b = {
        // 立刻再建一个进程（槽极可能被复用），旧副本去打它 ⇒ 仍必须 E_BAD_HANDLE，新进程毫发无伤
        let hn = Handle(call(user::SYS_PROCESS_CREATE, hj.0));
        let ok = match (copy, handle::resolve(hn, owner, 0)) {
            (Some(h), Ok((handle::ObjRef::Proc { slot, .. }, _))) => {
                let rc = call(user::SYS_PROC_REAP, h.0);
                let rk = call(user::SYS_PROCESS_KILL, h.0);
                let intact = proc::proc_live(slot, proc::proc_gen(slot).unwrap_or(u32::MAX)) && !proc::proc_is_terminated(slot);
                rc == user::E_BAD_HANDLE && rk == user::E_BAD_HANDLE && intact
            }
            _ => false,
        };
        if let Ok((handle::ObjRef::Proc { slot, .. }, _)) = handle::resolve(hn, owner, 0) {
            let _ = proc::proc_discard(slot);
        }
        let _ = handle::close(hn, owner);
        ok
    };
    let c6 = wrong_gen_rejected && c6a && c6b;

    // ---- ⑨ 防空转证人：成功次数增量 == 1（只有 ② 那一次成功）
    let c9 = user::proc_reap_calls() - calls0 == 1;

    // ---- 清理
    let mut cleaned = true;
    for h in [copy, ro].into_iter().flatten() {
        let _ = handle::close(h, owner);
    }
    cleaned &= proc::job_destroy(job).is_ok();
    let _ = handle::close(hj, owner);

    let ok = c1 && c2 && c3 && c4 && c5 && c6 && c7 && c8 && c9 && cleaned;
    crate::log_info!(
        "preap: 判据={} 还在跑拒={} 退出码={} 额度回={} 页回基线={} 句柄已关={} 副本世代失效={} 只读拒={} Job拒={} 证人={} 清理={} (fd表占页={} fd归还{}→{} 基线={} 回收后={})",
        ok, c1, c2, c3, c4, c5, c6, c7, c8, c9, cleaned, fd_cost_visible, fdrel0, fdrel1, frames_before_fd, frames_after_reap
    );
    ok
}
ktest!(KT_PROC_REAP, t_proc_reap_syscall);
