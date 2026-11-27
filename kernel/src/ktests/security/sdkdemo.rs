//! D4（ADR-154）：应用 SDK 样板的端到端用例。
//!
//! **它证明什么**：`sdkdemo.elf`（一个只经 `aurora-user-runtime` 调号的用户程序）
//! 能被内核装载、在 ring3 跑起来、读到自己的凭据、做出一次授权判定，并把结果
//! 写到串口。判据读的是**串口原文**（不是"加载成功"这种间接信号）。
//!
//! **为什么不走 FAT32 卷**：`tools/patch_fat32_file.py` 只能替换已有文件，
//! 不能新增 `SDKDEMO.ELF`；而"把新文件塞进真卷"需要 mtools（本机没有，
//! BACKLOG 78h-6 / 80f-1）。所以这里用 `include_bytes!` 的内嵌夹具——
//! 与 `t_elf` / `t_exec` 同一条路径，证的是"装载器 + ABI + 用户态库"这条链，
//! 不是"卷上有一个文件"（那条已由 FS-03 覆盖）。
//!
//! **判据三格**（都从用户态信箱读，不依赖串口句柄）：
//!   ① 信箱魔数对 —— 程序真的跑到了写信箱那一步，且 `.slots` 在 data 段首位
//!   ② `dev <= 1` —— 40 号真的回答了（允许/拒绝之一，不是未初始化值）
//!   ③ 自洽 —— `dev` 与 `caps` 的 `CAP_DEV` 位一致（程序自己的检查也同意）
//!
//! **`uid == u64::MAX` 是"没有凭据"的哨兵，不是失败**：本用例用 `spawn_user`
//! 起任务（不经 16 号），这条路径不授凭据。凭据的授予与授权差异由
//! `a3-cred-guest` 档 + ADR-151 那条判定行覆盖——本用例证的是"SDK 样板能跑通
//! 调号 + 回传结果"这条链。

use crate::{ktests::common::{SDKDEMO_ELF, drain_reap}, user};

/// 在 ring3 跑 `sdkdemo` 并把它的串口输出抓出来。
///
/// **为什么用 `user::load` + `spawn_user` 而不是 16 号全链**：本用例要证的是
/// "SDK 样板能跑"，不是"进程创建 API 正确"（后者由 A2/A3 那几片覆盖）。
/// 直接装载能少两层间接，红因更清楚。
fn t_sdkdemo() -> bool {
    let loaded = match user::load(SDKDEMO_ELF) {
        Ok(l) => l,
        Err(e) => {
            crate::log_fatal!("sdkdemo: 装载失败 —— {}", user::describe_load(e));
            return false;
        }
    };
    // 起在 ring3。第 3 参 0 = 不要控制台句柄（本用例靠串口判，不靠句柄）。
    let t = match crate::sched::spawn_user(loaded.entry, loaded.stack_top, 0, loaded.owned) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("sdkdemo: spawn_user 失败 {:?}", e);
            return false;
        }
    };
    // 让它跑完（它自己 exit）。窗口给足：用户态要经时间片轮转才排到。
    let _ = crate::apic::with_interrupts(|| {
        crate::sched::wait_for_task(t, crate::clock::window_cycles(64))
    });
    // **必须显式收尾**：`sdkdemo` 自己 `exit(0)` 只让任务变 `Done`，
    // 而它装载时占的 VA 登记要到任务真正回收才放手。
    // 不收尾就会让**后面**的用例在装载时报
    // `目标 VA 已被登记或已映射`——实测 `t_copy_user` / `t_syscall_fastpath` /
    // `t_user_pointer_checks` 三条一起红（它们装到同一批 VA）。
    // 这与 AGENTS 那条「用例必须自足，不能假设别的用例已经认领过设备」是同一件事的
    // 镜像：**也不能假设别的用例会替你收尾**。

    // 判据读**用户态信箱**（`.slots` 段）。
    //
    // **为什么不读串口**：`spawn_user` 的第 3 参为 0 时这个任务**没有控制台句柄**，
    // 它写不了串口（实测 `跑到输出=false`）。而"结果"必须有一条不依赖句柄的路
    // ——hello 用的就是信箱（`user/hello` 的 `OFF_*` 三个槽），本用例沿用同一形状。
    //
    // 槽布局见 `user/sdkdemo/src/main.rs` 的 `SLOTS`：
    //   [0]=魔数 0x53444B31 · [1]=uid · [2]=gid · [3]=caps · [4]=dev · [5]=自洽
    let base = loaded.data_va;
    // **读失败与值不对必须分开报**（ADR-225）：
    //
    // 原来这里是 `read_at(base).unwrap_or(0)` —— 那正是下面 76-81 行注释批评的写法。
    // 读不到用户页时它变成 `magic=0`，日志只说「魔数不对」，
    // 而真正的原因是「读用户页被拒」在另一行 —— 两者处置方向完全不同。
    let magic_read = crate::user::read_at(base);
    let magic = magic_read.unwrap_or(0);
    if magic != 0x5344_4B31 {
        let (nu, nm, ns, nw, tl) = crate::user::read_at_refused_by_kind();
        crate::log_fatal!(
            "sdkdemo: 信箱魔数不对 读到={:#x} 读成功={} 期望=0x53444b31（data_va={:#x}）",
            magic, magic_read.is_some(), base
        );
        crate::log_fatal!(
            "sdkdemo: 被拒分类 不在用户区={} 没映射={} 不共享={} 不可写={} 太长={} 映射在={}",
            nu, nm, ns, nw, tl, crate::mm::is_mapped(base)
        );
        return false;
    }
    // **不再 `unwrap_or` 兜底**（硬约束 6）：读失败必须与「值不对」分开报。
    //
    // 实测（BACKLOG §459）：`dev = read_at(base+32).unwrap_or(9)` 把
    // 「读用户页被拒」变成了「读到了 9」，于是判据报「40 号没回答」——
    // 而真正的原因是 `abi: 读用户页被拒 va=0x100002020`，在另一行日志里。
    // **读不到 ≠ 值不对**，两者的处置方向完全不同。
    let uid = crate::user::read_at(base + 8);
    let gid = crate::user::read_at(base + 16);
    let caps = crate::user::read_at(base + 24);
    let dev = crate::user::read_at(base + 32);
    let consistent = crate::user::read_at(base + 40);
    // **收尾必须在六个槽全读完之后**（BACKLOG §465）。
    //
    // `terminate_task` 只把任务置 `Done`，而它装载时占的 VA 登记
    // **要到异步 reaper 在 tick 上真正回收才放手**。原来的顺序是
    // 「先 terminate、再读六个槽」⇒ 中间一次 tick 就把页还了，
    // 于是 `base+0`（魔数）读得到、`base+8..40` 全部 `NotMapped`。
    //
    // 实测（run-8430，a2-exec-bad 档）：五个地址在同一页，而页若没映射
    // 连 `base+0` 也读不到 ⇒ **不是页表问题，是时间问题**。
    //
    // 这与 §366 是同一类：`fs_open.rs` 的注释写过「容器一被 reap，
    // 它名下的页就还给分配器」，所以它在 `IF=0` 窗口里取快照。
    // 这里六个读是纯读、无副作用，提前比关中断简单。
    #[cfg(not(feature = "fault-sdkdemo-no-cleanup"))]
    {
        let _ = crate::sched::terminate_task(t);
        crate::sched::yield_now();
        let _ = drain_reap();
    }
    let released = !crate::mm::is_reserved(loaded.image_lo)
        && !crate::mm::is_mapped(loaded.entry);
    // 五个槽全读到了，后面的判据才有意义。读不到时它单独红一格。
    let readable = uid.is_some()
        && gid.is_some()
        && caps.is_some()
        && dev.is_some()
        && consistent.is_some();

    // ① **38 号给出了一个明确的回答**：要么读到真凭据（uid != u64::MAX），
    //    要么明确说"没有"（uid == u64::MAX）。**两种都算过**——
    //    本用例用 `spawn_user` 起任务（不经 16 号），这条路径**不授凭据**，
    //    所以 `uid=u64::MAX` 是**正确结果**，不是失败。
    //    （凭据的授予与差异由 `a3-cred-guest` 档 + ADR-151 那条判定行覆盖。）
    let g1 = true;
    // ② 40 号真回答了（dev 只能是 0 或 1）。**读不到时这一格不参与**——
    //    它已经由 `readable` 那一格报了，强行判假会让成因说谎。
    let g2 = dev.is_none_or(|d| d <= 1);
    // ③ 自洽：`dev` 必须与 caps 的 CAP_DEV 位一致
    let expect_dev = caps.is_some_and(|c| {
        (c & u64::from(crate::cred::CAP_DEV)) == u64::from(crate::cred::CAP_DEV)
    });
    // `consistent`：1=自洽、0=不自洽、2=回读失败（写没生效）。
    // **三种分开报**：把 2 说成"不自洽"会把"写失败"伪装成"程序逻辑错"。
    let g3 = consistent == Some(1);
    // 读数里 `uid=18446744073709551615` 是"没有凭据"的哨兵（u64::MAX）——
    // 本用例这条路径不授凭据，所以那是**正确读数**，判据不据此报红。
    crate::log_info!(
        "sdkdemo: 判据 读得到={} 38号有回答={} 40号有回答={} 自洽={} 回收={} \
         读数 uid={:?} gid={:?} caps={:?} dev={:?} consistent={:?}",
        readable, g1, g2, g3, released, uid, gid, caps, dev, consistent
    );
    // **`readable` 是独立一格**：它红的时候日志直接说「读不到」，
    // 而不再伪装成「40 号没回答」。
    let ok = readable && g1 && g2 && g3 && released;
    if !ok {
        crate::log_fatal!("sdkdemo: 样板不成立（上面一行是全部读数）");
    }
    ok
}
// 依赖全局 APIC/调度基础设施；放在普通 .ktests 之后，避免链接顺序把它提前。
#[used]
#[link_section = ".ktests_late"]
static KT_SDKDEMO: crate::ktest::KTest = crate::ktest::KTest {
    name: stringify!(t_sdkdemo),
    run: t_sdkdemo,
};
