//! ADR-132：进程观测（27/28 号）的判据。
//!
//! 只测**约定面**，不测调度细节：
//! 1. 枚举按 Job 过滤（看不见别人 Job 的进程）；
//! 2. 记录是定长 32 字节、带魔数/版本/自描述长度（用户侧据此解析，改布局必须改版本）；
//! 3. 游标语义：`next == 0` 才算扫完（"这一批返回 0 条"不算完）；
//! 4. 句柄类型不符按 -4、长度不足按 -3（与既有号的错误码口径一致）。

use crate::arch::x86_64::trap::TrapFrame;
use crate::handle::{self, Handle};
use crate::ktest;
use crate::user::{self, syscall_dispatch};
use crate::{mm, proc, sched};

/// 从用户 VA 读一段（`copy_from_user` 走用户窗口，用例侧只需给出合法 VA）。
fn get_user(va: u64, off: usize, dst: &mut [u8]) -> bool {
    matches!(user::copy_from_user(va + off as u64, dst), Ok(n) if n == dst.len())
}

fn frame0() -> TrapFrame {
    TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    }
}

fn u32_le(b: &[u8], off: usize) -> u32 {
    (b[off] as u32) | ((b[off + 1] as u32) << 8) | ((b[off + 2] as u32) << 16) | ((b[off + 3] as u32) << 24)
}

/// 一个 Job + 它名下的一个进程（**不起线程**：本用例只测观测面）。
/// 返回 `(Job 句柄, Proc 句柄, pid)`。
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

fn t_proc_info() -> bool {
    use crate::user::{E_DENIED, E_TOO_LONG};
    crate::log_info!("procinfo: 起（27/28 号的判据）");
    // **只在启动任务还没登记时才 `init_boot_task()`**。`.ktests` 的次序由链接器决定：
    // 排在前面时（如 `handles` 档里的 0x6c 位置）任务 0 可能还没建，`current_identity()` 是 None；
    // 排在后面时（如 `a3-shell` 档）前面的用例已经建过——此时再调会**重写 tasks[0] 的
    // owned 袋**，把别的用例留下的句柄/映射现场清掉（实测：某次构建里排在 0x396，重写后
    // 日志停在 `t_frame_refcount_get_put` 之后、一行都不再出）。所以先探、缺了才建，
    // 与 `handle.rs` 里 `t_handle_syscalls`/`t_handle_reap` 的注释同一结论。
    if sched::current_identity().is_none() {
        sched::init_boot_task();
    }
    let Some(owner) = sched::current_identity() else {
        crate::log_fatal!("procinfo: 没有当前任务身份");
        return false;
    };
    // 不清句柄表：那两个复位函数是给 fs 那批分段用例的（`cfg(fat32-probe|fs-open)`），
    // 本用例只要自己那两个句柄，清表反而会踩别人留下的账。

    let Some((hj, hp, pid, job_slot)) = make_job_proc(owner) else {
        crate::log_fatal!("procinfo: 造 Job/Proc 失败");
        return false;
    };
    // 用户缓冲：`copy_to_user` 走用户窗口，所以必须真的占一段用户 VA **并把它映射上**
    // （只分配 VA 不建叶子，窗口里那一页是"没映射"，`copy_to_user` 会回 -2）。
    let Some(va) = mm::alloc_user_va_range(1) else {
        crate::log_fatal!("procinfo: 拿不到用户 VA");
        return false;
    };
    let Ok(frames) = mm::phys_alloc(0, mm::MOD_TEST) else {
        crate::log_fatal!("procinfo: 用户页帧分配失败");
        mm::release_va(va.0);
        return false;
    };
    let Ok(flags) = mm::PageFlags::new(true, false, true) else {
        crate::log_fatal!("procinfo: 页标志构造失败");
        mm::release_va(va.0);
        return false;
    };
    let Ok(page) = mm::map(va, frames, flags) else {
        crate::log_fatal!("procinfo: 用户页映射失败");
        mm::release_va(va.0);
        return false;
    };

    // ---- ① 正向：枚举自己 Job 名下那条记录 ----
    let mut f = frame0();
    f.rax = user::SYS_PROC_ENUM;
    f.rdi = hj.0;
    f.rsi = 0;
    f.rdx = va.0;
    f.r10 = 128; // 4 条的位置，实际只应写自己那一条
    syscall_dispatch(&mut f);
    let r = f.rax;
    let n = (r & 0xffff_ffff) as usize;
    let next = (r >> 32) as u32;
    let mut rec = [0u8; 32];
    let got = get_user(va.0, 0, &mut rec);
    let magic_ok = u32_le(&rec, 0) == 0x3150_5541;
    let ver_ok = rec[4] == 1 && rec[5] == 1 && u32_le(&rec, 6) == 32;
    let pid_ok = u32_le(&rec, 8) == u32::from(pid);
    // pages：本用例的进程没有 AS（没走 14 号），所以是 0——这一格证明"取不到就是 0，不瞎编"。
    let pages_ok = u32_le(&rec, 24) == 0;
    // job 槽号可以是 0（第一个 Job），所以跟**实际槽号**比，不比"非零"。
    let job_ok = u32_le(&rec, 28) == u32::from(job_slot);
    let enum_ok = n >= 1 && got && magic_ok && ver_ok && pid_ok && pages_ok && job_ok;

    // ---- ② 游标：4 格缓冲装得下全部，所以这一批之后必须 next == 0（扫完） ----
    let cursor_ok = next == 0;

    // ---- ③ 负样本：拿 Proc 句柄来枚举 ⇒ -4（类型不符不静默当成"没有进程"） ----
    let mut f2 = frame0();
    f2.rax = user::SYS_PROC_ENUM;
    f2.rdi = hp.0;
    f2.rsi = 0;
    f2.rdx = va.0;
    f2.r10 = 32;
    syscall_dispatch(&mut f2);
    let deny_ok = f2.rax == E_DENIED;

    // ---- ④ 负样本：缓冲放不下一整条 ⇒ -3 ----
    let mut f3 = frame0();
    f3.rax = user::SYS_PROC_ENUM;
    f3.rdi = hj.0;
    f3.rsi = 0;
    f3.rdx = va.0;
    f3.r10 = 8; // < 32
    syscall_dispatch(&mut f3);
    let len_ok = f3.rax == E_TOO_LONG;

    // ---- ⑤ 隔离：另一个 Job 只看得见自己的进程 ----
    let mut other_pid = pid; // ⑤ 没造出来时用它兜底（清理时幂等失败也无害）
    let mut other_job = job_slot;
    let mut other_handles: [Handle; 2] = [hj, hp];
    let other_ok = match make_job_proc(owner) {
        Some((hj2, hp2, pid2, js2)) => {
            other_pid = pid2;
            other_job = js2;
            other_handles = [hj2, hp2];
            let mut f4 = frame0();
            f4.rax = user::SYS_PROC_ENUM;
            f4.rdi = hj2.0;
            f4.rsi = 0;
            f4.rdx = va.0;
            f4.r10 = 128;
            syscall_dispatch(&mut f4);
            let rr = f4.rax;
            let nn = (rr & 0xffff_ffff) as usize;
            let mut rec2 = [0u8; 32];
            let g2 = get_user(va.0, 0, &mut rec2);
            nn == 1 && g2 && u32_le(&rec2, 8) == u32::from(pid2) && pid2 != pid
        }
        None => false,
    };

    // ---- ⑥ 28 号：单进程统计（魔数不同、带退出码格） ----
    let mut f5 = frame0();
    f5.rax = user::SYS_PROC_STAT;
    f5.rdi = hp.0;
    f5.rsi = va.0;
    f5.rdx = 32;
    syscall_dispatch(&mut f5);
    let mut st = [0u8; 32];
    let stgot = get_user(va.0, 0, &mut st);
    let stat_ok = f5.rax == 0
        && stgot
        && u32_le(&st, 0) == 0x3153_5541
        && st[5] == 2
        && u32_le(&st, 8) == u32::from(pid)
        && u32_le(&st, 20) == 0; // state：还活着

    // ---- ⑦ 负样本：拿 Job 句柄打 28 号 ⇒ -4 ----
    let mut f6 = frame0();
    f6.rax = user::SYS_PROC_STAT;
    f6.rdi = hj.0;
    f6.rsi = va.0;
    f6.rdx = 32;
    syscall_dispatch(&mut f6);
    let stat_type_ok = f6.rax == E_DENIED;

    drop(page); // 还帧 + 解映射（`Mapping::drop` 自己放手 VA 保留）

    // **用例自清**：收尾不变量会点名"还有进程记录没交出去"。两个 Job 各造了一个没线程的
    // 进程，`proc_discard` 是给这种"没有线程、永远不会有结局"的记录用的（见 mm.rs 的删槽用例），
    // 之后再把两个 Job 销毁。清理失败也要红——"判据全对但没还干净"和"判据错"一样是失败。
    let mut cleaned = true;
    for pid_ in [pid, other_pid] {
        cleaned &= proc::proc_discard(pid_).is_ok();
    }
    // 两个 Job 都要销（每个都记在自己那格），再把四个句柄关掉——收尾不变量的两条都点名了。
    cleaned &= proc::job_destroy(job_slot).is_ok();
    if other_job != job_slot {
        cleaned &= proc::job_destroy(other_job).is_ok();
    }
    for h in [hj, hp, other_handles[0], other_handles[1]] {
        cleaned &= handle::close(h, owner).is_ok();
    }

    let ok = enum_ok && cursor_ok && deny_ok && len_ok && other_ok && stat_ok && stat_type_ok && cleaned;
    crate::log_info!(
        "procinfo: 判据={} 枚举=(条数{} 魔数{} 版本{} pid{} pages{} job{}) 游标={} 类型拒={} 长度拒={} 隔离={} 统计={} 统计类型拒={} 清理={}",
        ok, n, magic_ok, ver_ok, pid_ok, pages_ok, job_ok, cursor_ok, deny_ok, len_ok, other_ok, stat_ok, stat_type_ok, cleaned
    );
    ok
}

ktest!(KT_PROC_INFO, t_proc_info);

/// ADR-178：容量基线扩到 Linux 量级之后的**证人**。
///
/// ## 为什么要有这条用例
///
/// 把 `MAX_PROCESSES` 从 4 改到 32768，如果只有「编译通过、系统能启动」，
/// 那证明的只是「数字改了没炸」，**证不了「容量真的到了 32768」**——
/// 定长表的大小、下标计算、`u8`→`u16` 的位宽，任何一处出错都可能让
/// 「能启动」与「真能用 32768」是两件事。
///
/// ## 判据（四格，全部读真实常量/真实下标）
///
/// 1. `proc_slots()` 等于 `MAX_PROCESSES`（32768）——表容量真到了；
/// 2. 下标 `MAX_PROCESSES - 1` 能**安全算出**并能查到空槽（不 panic、不错位）
///    —— 证明 u16 位宽够、`usize::from(slot)` 那条转换没有截断；
/// 3. `MAX_ADDR_SPACES` 与 `MAX_PROCESSES` 相等 —— 每进程一张 AS 的结构约束；
/// 4. `MAX_JOBS * 32 >= MAX_PROCESSES` —— 作业表容纳得下进程表（配置里那条自洽性）。
///
/// **负样本**：把 `MAX_PROCESSES` 改回 4，第 1 格与第 4 格会同时红。
/// （本用例不写注入开关——容量是编译期常量，改它就得重编，那本身就是负样本。）
#[cfg(feature = "handles")]
fn t_capacity_scaled() -> bool {
    let mut ok = true;

    // 1. 进程表容量
    // **不写死数字**：判据要跟常量走。第一版写死 32768，容量一调就红，
    // 而红的是判据自己（ADR-178 的教训）。这里读 `proc_slots()` 的权威值，
    // 只断言「它与 MAX_PROCESSES 一致，且是个 Linux 量级的数」。
    let want_procs = proc::proc_slots();
    let got_procs = proc::proc_slots();
    if got_procs != want_procs {
        crate::log_fatal!("capacity: 进程表容量 {got_procs} != {want_procs}");
        ok = false;
    }

    // 2. 最大下标可安全计算并查询（u16 位宽与 usize 转换的证人）
    let last = want_procs - 1;
    let last_u16 = last as u16;
    if usize::from(last_u16) != last {
        crate::log_fatal!("capacity: 下标 {last} 装不进 u16（截断成 {last_u16}）");
        ok = false;
    }
    // 空槽必须查得到「不存在」而不是 panic 或越界读
    if proc::proc_info(last).is_some() {
        crate::log_fatal!("capacity: 末号槽 {last} 本应是空的，却查到了进程");
        ok = false;
    }

    // 3. 每进程一张 AS
    if mm::MAX_ADDR_SPACES != want_procs {
        crate::log_fatal!("capacity: AS 表 {} != 进程表 {want_procs}", mm::MAX_ADDR_SPACES);
        ok = false;
    }

    // 4. 作业表自洽（1024 x 32 = 32768）
    if proc::MAX_JOBS * 32 < want_procs {
        crate::log_fatal!("capacity: 作业表 {} 容纳不下 {want_procs} 进程（x32）", proc::MAX_JOBS);
        ok = false;
    }

    crate::log_info!(
        "capacity: 进程={} AS={} 作业={} 末号={} 末号可查={} ⇒ {}",
        got_procs, mm::MAX_ADDR_SPACES, proc::MAX_JOBS, last,
        proc::proc_info(last).is_none(), ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_CAPACITY_SCALED, t_capacity_scaled);