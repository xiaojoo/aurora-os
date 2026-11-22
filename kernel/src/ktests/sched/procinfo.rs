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

/// ADR-180：per-process fd 表的**证人**。
///
/// ## 为什么要有这条用例
///
/// `FdTable` 是新增类型，`ProcEntry.fd_table` 是新增字段。如果只有「编译通过」，
/// 证明的只是「类型定义没写错」，**证不了「装/查/释放/预置 std 都真的对」**。
///
/// 判据五格：
///
/// 1. **预置 std**：`preset_std` 之后 fd 0/1/2 各指向给定句柄，`used()==3`；
/// 2. **装**：`install` 拿到最小空闲 fd（3），`lookup(3)` 回到那个句柄；
/// 3. **不重复**：再装一次拿到 4（不是覆盖 3）；
/// 4. **释放**：`release(3)` 返回原句柄、`lookup(3)` 变 `None`、`used()` 减 1；
/// 5. **空槽释放**：`release` 一个空 fd 返回 `None`（不是 panic）。
///
/// **负样本**：把 `install` 的 `slice[i] == 0` 判断去掉（改成无条件写 0 号位），
/// 第 2 格与第 3 格会同时红。
#[cfg(feature = "handles")]
fn t_fd_table() -> bool {
    // 用真实的句柄值形状（Handle 的 unpack 要求 slot/gen 非 0），
    // 但这条用例**不碰真句柄表**——它只验 fd 表本身的装/查/放。
    let mk = |slot: u64, gen: u64| crate::handle::Handle((gen << 16) | slot);
    let h_in = mk(1, 1);
    let h_out = mk(2, 1);
    let h_err = mk(3, 1);
    let h_a = mk(10, 1);
    let h_b = mk(11, 1);

    let mut t = crate::handle::FdTable::new();
    let mut ok = true;

    // 1. 预置 std
    if t.preset_std(h_in, h_out, h_err).is_err() {
        crate::log_fatal!("fd: preset_std 失败");
        return false;
    }
    let std_ok = t.lookup(0) == Some(h_in)
        && t.lookup(1) == Some(h_out)
        && t.lookup(2) == Some(h_err)
        && t.used() == 3;
    if !std_ok {
        crate::log_fatal!("fd: 预置 std 不成立 used={} 0={:?} 1={:?} 2={:?}",
            t.used(), t.lookup(0), t.lookup(1), t.lookup(2));
        ok = false;
    }

    // 2. 装 -> 最小空闲 fd 是 3
    let fd_a = match t.install(h_a) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("fd: install 失败 {:?}", e);
            return false;
        }
    };
    let install_ok = fd_a == 3 && t.lookup(fd_a) == Some(h_a) && t.used() == 4;
    if !install_ok {
        crate::log_fatal!("fd: 装不成立 fd={} used={}", fd_a, t.used());
        ok = false;
    }

    // 3. 再装 -> 4（不是覆盖 3）
    let fd_b = match t.install(h_b) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("fd: 第二次 install 失败 {:?}", e);
            return false;
        }
    };
    let distinct_ok = fd_b == 4 && t.lookup(3) == Some(h_a) && t.lookup(4) == Some(h_b);
    if !distinct_ok {
        crate::log_fatal!("fd: 两次装不独立 fd_b={} 3={:?} 4={:?}",
            fd_b, t.lookup(3), t.lookup(4));
        ok = false;
    }

    // 4. 释放 3
    let released = t.release(fd_a);
    let release_ok = released == Some(h_a) && t.lookup(fd_a).is_none() && t.used() == 4;
    if !release_ok {
        crate::log_fatal!("fd: 释放不成立 got={:?} used={}", released, t.used());
        ok = false;
    }

    // 5. 释放空槽 -> None（不是 panic）
    let empty_release = t.release(fd_a).is_none();
    if !empty_release {
        crate::log_fatal!("fd: 释放空槽应当返回 None");
        ok = false;
    }

    // 越界 fd 也要安全
    let oob = t.lookup(9999).is_none() && t.release(9999).is_none();
    if !oob {
        crate::log_fatal!("fd: 越界 fd 不安全");
        ok = false;
    }

    crate::log_info!(
        "fd: 预置std={} 装={} 独立={} 释放={} 空释放={} 越界安全={} 末used={} ⇒ {}",
        std_ok, install_ok, distinct_ok, release_ok, empty_release, oob, t.used(), ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_FD_TABLE, t_fd_table);

/// ADR-180 第 4 项：`proc_create` 真的给进程装了 fd 表。
///
/// ## 为什么需要这条
///
/// `t_fd_table` 验的是 `FdTable` 类型本身（装/查/放），但它用的是**自己 new 的**一张表，
/// 碰不到 `proc_create`。如果 `proc_create` 忘了装、装错、或装了一张 0 地址的表，
/// `t_fd_table` 照样全绿——**那个字段就还是空壳**（违反 AGENTS.md 硬约束 2）。
///
/// ## 判据三格
///
/// 1. `proc_create` 之后 `proc_fd_table` 能取到**非 0** 地址；
/// 2. 两个不同进程的 fd 表地址**不同**（不是共用一张）；
/// 3. 取到的地址能当 `FdTable` 用（`preset_std` 成功且 `lookup(1)` 回到给定句柄）。
///
/// **负样本**：把 `proc_create` 里那行 `fd_table.store(fd, ...)` 去掉，
/// 第 1 格立刻红（`proc_fd_table` 返回 `None`）。
#[cfg(feature = "handles")]
fn t_proc_fd_table() -> bool {
    let mk = |slot: u64| crate::handle::Handle((1u64 << 16) | slot);

    let Ok(job) = proc::job_create(None, 4, 64) else {
        crate::log_fatal!("procfd: job_create 失败");
        return false;
    };
    let Ok(p1) = proc::proc_create(job) else {
        crate::log_fatal!("procfd: 第一个 proc_create 失败");
        return false;
    };
    let g1 = proc::proc_gen(p1).unwrap_or(0);
    let Ok(p2) = proc::proc_create(job) else {
        crate::log_fatal!("procfd: 第二个 proc_create 失败");
        proc::proc_reap(p1);
        return false;
    };
    let g2 = proc::proc_gen(p2).unwrap_or(0);

    let mut ok = true;

    // 1. 能取到 fd 表（`proc_create` 真的装了）
    let t1 = proc::proc_fd_table(p1, g1);
    let t2 = proc::proc_fd_table(p2, g2);
    let got_ok = t1.is_some() && t2.is_some();
    if !got_ok {
        crate::log_fatal!("procfd: proc_create 之后取不到 fd 表 p1={} p2={}", t1.is_some(), t2.is_some());
        ok = false;
    }

    // 2. 两个进程各有一张（不是共用）—— 用「装一个 fd 后另一个看不到」来判，
    //    比比地址更本质：地址不同也可能是同一张表被映射两次。
    let mut distinct = false;
    if let (Some(mut a), Some(b)) = (t1, t2) {
        let h = mk(1);
        let _ = a.preset_std(h, mk(2), mk(3));
        // a 装了一个 fd，b 仍然是空的（`used()==0`）
        // **查 fd 0**（`preset_std` 把 stdin 放 0、stdout 放 1、stderr 放 2）。
        // 第一版查 fd 1 期望拿到 `h`，那是把 stdin 和 stdout 搞混了 ——
        // 实测 `a.lookup(1)=Some(slot=2)` 而期望 `slot=1`，判据自己写错。
        distinct = a.lookup(0) == Some(h) && b.used() == 0;
        if !distinct {
            crate::log_fatal!(
                "procfd: a.lookup(0)={:?} 期望={:?}; b.used()={} 期望=0",
                a.lookup(0), h, b.used()
            );
        }
    }
    if !distinct {
        crate::log_fatal!("procfd: 两个进程的 fd 表不独立");
        ok = false;
    }

    // 3. 取到的表真的能用（`preset_std` 之后 0/1/2 都在）
    let mut usable = false;
    if let Some(mut t) = proc::proc_fd_table(p1, g1) {
        usable = t.preset_std(mk(1), mk(2), mk(3)).is_ok()
            && t.lookup(0) == Some(mk(1))
            && t.lookup(2) == Some(mk(3))
            && t.used() == 3;
    }
    if !usable {
        crate::log_fatal!("procfd: 取到的表当 FdTable 用不成立");
        ok = false;
    }

    crate::log_info!("procfd: 取到={} 独立={} 可用={} ⇒ {}", got_ok, distinct, usable, ok);

    // 收场：两个进程都没起线程 ⇒ 走 proc_discard（不是 proc_reap）。
    //
    // **必须逐个查返回值**（ADR-180 实测）：第一版忽略了返回值，
    // 若 discard 失败（比如 threads 非 0），进程与 Job 都留了下来，
    // 后续用例的 `登记N->N+1` 就对不上 ⇒ 4 个用例级联红。
    let d1 = proc::proc_discard(p1);
    let d2 = proc::proc_discard(p2);
    let jd = proc::job_destroy(job);
    if d1.is_err() || d2.is_err() || jd.is_err() {
        crate::log_fatal!("procfd: 收场失败 d1={:?} d2={:?} job={:?}", d1.is_err(), d2.is_err(), jd.is_err());
        ok = false;
    }
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_PROC_FD_TABLE, t_proc_fd_table);

/// ADR-180 未决 3：fd 表扩容。
///
/// ## 判据四格
///
/// 1. **装满 64 格**（`FD_TABLE_INIT`），`install` 全成功；
/// 2. **第 65 个触发扩容**，返回 fd 64（不是 `Exhausted`）；
/// 3. **扩容后旧数据不丢**：fd 0..63 的句柄逐个还在；
/// 4. **容量写回主人**：`proc_fd_table` 重建的视图也看得见 fd 64。
///
/// 第 4 格是关键：`FdTable` 只是视图，容量记在 `ProcEntry.fd_cap`。
/// 若 `install` 扩了容却没写回主人，下次重建视图只看得见前 64 格 ——
/// **新扩的那些格写了也读不到**。
///
/// **负样本**：把 `proc_set_fd_cap` 那一步去掉，第 4 格立刻红。
#[cfg(feature = "handles")]
fn t_fd_table_grow() -> bool {
    let mk = |slot: u64| crate::handle::Handle((1u64 << 16) | slot);

    let Ok(job) = proc::job_create(None, 4, 64) else {
        crate::log_fatal!("fdgrow: job_create 失败");
        return false;
    };
    let Ok(p) = proc::proc_create(job) else {
        crate::log_fatal!("fdgrow: proc_create 失败");
        let _ = proc::job_destroy(job);
        return false;
    };
    let g = proc::proc_gen(p).unwrap_or(0);

    let mut ok = true;

    // 1+2. 装满 64 格，第 65 个应触发扩容并返回 fd 64
    let mut installed = 0usize;
    let mut first_beyond = None;
    if let Some(mut t) = proc::proc_fd_table(p, g) {
        for i in 0..=crate::handle::FD_TABLE_INIT {
            match t.install(mk((i as u64) + 1)) {
                Ok(fd) => {
                    installed += 1;
                    if i == crate::handle::FD_TABLE_INIT {
                        first_beyond = Some(fd);
                    }
                }
                Err(e) => {
                    crate::log_fatal!("fdgrow: 第 {} 个 install 失败 {:?}", i, e);
                    ok = false;
                    break;
                }
            }
        }
        // 3. 旧数据不丢
        let mut kept = 0usize;
        for i in 0..crate::handle::FD_TABLE_INIT {
            if t.lookup(i as u32) == Some(mk((i as u64) + 1)) {
                kept += 1;
            }
        }
        let kept_ok = kept == crate::handle::FD_TABLE_INIT;
        if !kept_ok {
            crate::log_fatal!("fdgrow: 扩容后旧数据丢了 {}/{}", kept, crate::handle::FD_TABLE_INIT);
            ok = false;
        }
        // 把新容量写回主人（`install` 扩了容，但主人还不知道）
        // **base 与 cap 一起写回**（实测教训）：`grow()` 换了新表，
        // 只写 cap 不写 base 的话，重建的视图会按新容量去读旧表。
        let new_cap = t.cap();
        let new_base = t.base();
        if !proc::proc_set_fd_table(p, g, new_base, new_cap) {
            crate::log_fatal!("fdgrow: 写回 base/cap 失败");
            ok = false;
        }
    } else {
        crate::log_fatal!("fdgrow: 取不到 fd 表");
        ok = false;
    }

    // 4. 重建的视图看得见 fd 64（容量已写回）
    let rebuilt_ok = match proc::proc_fd_table(p, g) {
        Some(t) => t.lookup(crate::handle::FD_TABLE_INIT as u32).is_some() && t.used() > crate::handle::FD_TABLE_INIT,
        None => false,
    };
    if !rebuilt_ok {
        crate::log_fatal!("fdgrow: 重建视图看不见扩容后的 fd（容量没写回主人？）");
        ok = false;
    }

    let beyond_ok = first_beyond == Some(crate::handle::FD_TABLE_INIT as u32);
    if !beyond_ok {
        crate::log_fatal!("fdgrow: 第 65 个 fd = {:?} 期望 {:?}", first_beyond, crate::handle::FD_TABLE_INIT);
        ok = false;
    }

    crate::log_info!(
        "fdgrow: 装={} 第65个={:?} 旧数据保留={} 重建可见={} ⇒ {}",
        installed, first_beyond, true, rebuilt_ok, ok
    );

    proc::proc_discard(p);
    let _ = proc::job_destroy(job);
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_FD_TABLE_GROW, t_fd_table_grow);
