//! 持久状态区与启动循环保护用例（T0.1 纯搬移）。

use crate::{ahci, boot_guard, state_store, user};
use crate::ktest;

/// M6-a①：§9.4/§9.7/ADR-011-临时 的共同地基 —— 一块跨重启保留的记录区。
///
/// 判据分两层，故意的：**格式判据不碰盘**（纯函数，跑一百次都一样），
/// **现场判据必须碰盘**（不碰盘就证明不了"下一次启动还看得见"）。
/// 1 `encode`→`decode` 往返：六个字段 + kind + seq 都要原样回来
/// 2 全 0 缓冲 ⇒ 判为"读不到"（这就是全新镜像那 4 KiB 的形状）
/// 3 payload 中间翻一个字节 ⇒ 判为"读不到"，**不许**读出一个看似合法的中间值
/// 4 `size` 被改成超出缓冲 ⇒ 必须挡住（它会让校验和指着缓冲外面）
/// 5 `version` 不认识 ⇒ 单独一种错误，不猜字段含义
/// 6 抹掉整块区域后 `read()` 必须是 `NoValidSlot`（最坏情况的入口）
/// 7 写→读要一致，且第二次写的 `seq` 严格 +1、槽位轮转
/// 8 **把最新那个槽弄坏，`read()` 必须退回上一槽的旧记录**——轮转只毁一个槽的全部意义
/// 9 全坏之后重新写：从 `seq=1` 起（坏记录不会把状态机永久卡住）
/// 10 跨种类（M6-b①）：区里只有一种记录时另一种必须读不到；写进第三种记录 `KIND_PROBE` 之后
///    `seq` 仍按**整块区**单调；`read(种类)` 取的是该种类自己的最新，不是"区里最新那条"
/// 11 弄坏"全局最新那一条"⇒ 只许毁它自己那一格：同种类的退回旧记录，隔壁种类一条不少
fn t_state_store() -> bool {
    use state_store as ss;
    let s1 = ss::BootState {
        failed_boots: 2,
        good_slot: 1,
        bad_slot: 3,
        last_vector: 14,
        last_cpu: 1,
        last_rip: 0xffff_8000_1234_5678,
    };
    // 1 往返
    let buf = ss::encode(ss::KIND_BOOT, 7, &s1);
    let back = ss::decode(0, &buf);
    let round_trip = matches!(back, Ok((kind, seq, ref st)) if kind == ss::KIND_BOOT && seq == 7 && *st == s1);
    // 2 全 0
    let zeroed = [0u8; ss::SLOT_BYTES];
    let blank_rejected = matches!(ss::decode(1, &zeroed), Err(ss::StoreError::Torn { slot: 1, .. }));
    // 3 撕裂：翻 payload 里的一个字节 ⇒ 校验和必须挡；翻校验和本身也一样
    let mut torn = buf;
    torn[30] ^= 0xFF;
    let torn_rejected = matches!(ss::decode(0, &torn), Err(ss::StoreError::Torn { .. }));
    let mut cut_sum = buf;
    cut_sum[52] ^= 0x80;
    let sum_rejected = matches!(ss::decode(0, &cut_sum), Err(ss::StoreError::Torn { .. }));
    // 3b 校验和**只覆盖头部 + payload**：翻填充区（第 256 字节）记录照旧可解。
    // 这一条不是说"那样也行"，是把保护范围写成能判的事实 —— 半条记录落在保护范围外
    // 的那种撕裂，本来就得靠"长度字段 + 校验和"这两个一起挡（上面两条已挡）。
    let mut padded = buf;
    padded[256] ^= 0xFF;
    let outside_range_ok = matches!(ss::decode(0, &padded), Ok((_, 7, _)));
    // 4 size 越界（把首字段改成 4000，仍保留原校验和位置 ⇒ 必须先在界检查上被挡）
    let mut huge = buf;
    huge[0..4].copy_from_slice(&4000u32.to_le_bytes());
    let size_rejected = matches!(ss::decode(0, &huge), Err(ss::StoreError::Torn { .. }));
    // 5 版本
    let mut future = buf;
    future[8..12].copy_from_slice(&7u32.to_le_bytes());
    let version_rejected = matches!(ss::decode(0, &future), Err(ss::StoreError::Version(7)));

    // 以下必须碰盘。先确保设备已认领（`.ktests` 顺序由链接器决定，不能假设别人跑过）
    if ahci::init().is_err() {
        crate::log_fatal!("state: AHCI 没认领上，现场判据没法做");
        return false;
    }
    let port = match ahci::boot_port() {
        Ok(p) => p,
        Err(e) => {
            crate::log_fatal!("state: 找不到引导盘 {:?}", e);
            return false;
        }
    };
    // **先存下启动时那条记录**：用例要在盘上折腾，最后必须原样放回。
    // 不放回会怎样是实测到的：本用例写的 `failed_boots=2` 留在盘上，下一次启动读到 2、
    // 再下一次还是 2 —— 跨重启的计数被用例冻住，而每一跑都"全绿"。
    let saved = ss::read(ss::KIND_BOOT).ok();
    let wiped = ss::wipe().is_ok();
    let empty_is_worst_case = matches!(ss::read(ss::KIND_BOOT), Err(ss::StoreError::NoValidSlot));

    let w1 = ss::write(ss::KIND_BOOT, &s1);
    let s2 = ss::BootState { failed_boots: 5, ..s1 };
    let w2 = ss::write(ss::KIND_BOOT, &s2);
    let (slot1, seq1) = match w1 {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("state: 第一次写失败 {:?}", e);
            return false;
        }
    };
    let (slot2, seq2) = match w2 {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("state: 第二次写失败 {:?}", e);
            return false;
        }
    };
    let read2 = ss::read(ss::KIND_BOOT);
    let persisted = matches!(read2, Ok((_, seq, ref st)) if seq == seq2 && st.failed_boots == 5 && st.good_slot == 1);
    let rotated = slot2 != slot1 && seq2 == seq1 + 1;
    // 8 把最新的槽弄坏 ⇒ 必须退回上一槽（seq1 那条，failed_boots=2）
    let mut broken = [0u8; ss::SLOT_BYTES];
    broken[3] = 0xE5;
    let corrupted = ahci::write_bytes(port, ss::slot_lba(slot2), &broken).is_ok();
    let fell_back = matches!(ss::read(ss::KIND_BOOT), Ok((slot, seq, ref st)) if slot == slot1 && seq == seq1 && st.failed_boots == s1.failed_boots);
    // 9 两个槽全坏 ⇒ NoValidSlot，然后重新写得起来（seq 从 1 重新开始）
    let _ = ahci::write_bytes(port, ss::slot_lba(slot1), &broken);
    let all_broken = matches!(ss::read(ss::KIND_BOOT), Err(ss::StoreError::NoValidSlot));
    let w3 = ss::write(ss::KIND_BOOT, &s1);
    let recovered = matches!(w3, Ok((_, 1)));
    let readable_after_recover = matches!(ss::read(ss::KIND_BOOT), Ok((_, _, ref st)) if st.failed_boots == s1.failed_boots);
    // 10 两种记录共用一块区 ⇒ `seq` 必须按**整块区**单调，"最新"必须按种类各取各的。
    //    这是 §9.7 崩溃记录（第二种 `kind`）的硬前置：各数各的 `seq` 时"谁新"没有定义。
    let (slot3, seq3) = match w3 { Ok(v) => v, Err(_) => (0, 0) };
    let crash_absent = matches!(ss::read(ss::KIND_PROBE), Err(ss::StoreError::NoValidSlot))
        && matches!(ss::read(ss::KIND_BOOT), Ok((_, seq, _)) if seq == seq3);
    let s_probe = ss::BootState { last_vector: 13, last_cpu: 2, ..s1 };
    let w4 = ss::write(ss::KIND_PROBE, &s_probe);
    let w5 = ss::write(ss::KIND_BOOT, &s2);
    let (slot4, seq4) = match w4 { Ok(v) => v, Err(_) => (0, 0) };
    let (slot5, seq5) = match w5 { Ok(v) => v, Err(_) => (0, 0) };
    let cross_seq_monotonic = seq4 == seq3 + 1 && seq5 == seq4 + 1;
    let per_kind_latest = matches!(ss::read(ss::KIND_BOOT), Ok((s, seq, ref st)) if s == slot5 && seq == seq5 && st.failed_boots == 5)
        && matches!(ss::read(ss::KIND_PROBE), Ok((s, seq, ref st)) if s == slot4 && seq == seq4 && st.last_vector == 13);
    // 11 弄坏"全局最新那一条"（它恰好是 boot 记录）⇒ boot 退回自己那条旧的，崩溃记录一条不少。
    //    这一格把"轮转只毁一个槽"从同种类的说法升级成跨种类的说法：撕裂不许把隔壁种类也带走。
    let _ = ahci::write_bytes(port, ss::slot_lba(slot5), &broken);
    let one_slot_only = matches!(ss::read(ss::KIND_BOOT), Ok((s, seq, ref st)) if s == slot3 && seq == seq3 && st.failed_boots == s1.failed_boots)
        && matches!(ss::read(ss::KIND_PROBE), Ok((s, seq, _)) if s == slot4 && seq == seq4);
    // 收尾：把盘放回启动时那条记录，然后按**放回之后的现场**打印对账用的那一行。
    // 顺序很重要：宿主机那台仪器读的是跑完之后的镜像，所以它必须看到这一行说的槽。
    ss::wipe().ok();
    let rest = match saved {
        Some((_, _, st)) => ss::write(ss::KIND_BOOT, &st),
        None => Ok((0u8, 0u64)),
    };
    let (final_slot, final_seq, final_failed) = match &rest {
        Ok((slot, seq)) => (*slot, *seq, saved.map(|(_, _, st)| st.failed_boots).unwrap_or(0)),
        Err(_) => (0, 0, 0),
    };
    let put_back = rest.is_ok()
        && matches!(ss::read(ss::KIND_BOOT), Ok((_, _, ref st)) if saved.map(|(_, _, s)| s.failed_boots == st.failed_boots).unwrap_or(true));

    crate::log_info!(
        "state: 格式判据 往返={} 全0拒={} 撕裂拒={}/{}（payload/校验和） 界外照解={} size拒={} 版本拒={}",
        round_trip,
        blank_rejected,
        torn_rejected,
        sum_rejected,
        outside_range_ok,
        size_rejected,
        version_rejected
    );
    crate::log_info!(
        "state: 现场判据 抹掉={} 空区按最坏={} 写后读回={} 轮转(槽{}→{} seq{}→{})={} 弄坏最新仍读旧的={} 全坏={} 重新写起={}/{}",
        wiped,
        empty_is_worst_case,
        persisted,
        slot1,
        slot2,
        seq1,
        seq2,
        rotated,
        corrupted && fell_back,
        all_broken,
        recovered,
        readable_after_recover
    );
    crate::log_info!(
        "state: 跨种类判据 只有一种时另一种读不到={} seq全局单调({}→{}→{})={} 各取各的最新={} 撕裂只毁一个种类={}",
        crash_absent,
        seq3,
        seq4,
        seq5,
        cross_seq_monotonic,
        per_kind_latest,
        one_slot_only
    );
    // 宿主机那台仪器要用的一行：**放回之后**留在盘上的那条记录是哪一槽、seq、failed 多少
    crate::log_info!(
        "state: 落盘 区LBA={} 槽={} 槽字节={} seq={} failed={} 种类={} 放回={}",
        ss::STATE_START_LBA,
        final_slot,
        ss::SLOT_BYTES,
        final_seq,
        final_failed,
        ss::KIND_BOOT,
        put_back
    );
    let ok = round_trip
        && blank_rejected
        && torn_rejected
        && sum_rejected
        && outside_range_ok
        && size_rejected
        && version_rejected
        && wiped
        && empty_is_worst_case
        && persisted
        && rotated
        && corrupted
        && fell_back
        && all_broken
        && recovered
        && readable_after_recover
        && crash_absent
        && cross_seq_monotonic
        && per_kind_latest
        && one_slot_only
        && put_back;
    if !ok {
        crate::log_fatal!("state: 状态区判据不成立（上面四行是全部读数）");
    }
    ok
}
ktest!(KT_STATE_STORE, t_state_store);

/// M6-a②：§9.4 的决策与"安全模式真的有后果"。四格：
/// 1 纯函数：阈值之下是正常、达到阈值是安全模式（`u32::MAX` 也要给安全模式，不许回绕）
/// 2 启动时那条决定自洽：模式 == `mode_for(读到的数)`；而"读不到"那次必须落在安全模式
/// 3 模式对外可见：`sys_abi_info()` 的 `F_SAFE_MODE` 位与内核内部状态一致（不一致就是装饰位）
/// 4 后果：安全模式下 AHCI 只起到第一块有盘的口；还原成正常模式后口数必须回到全数
fn t_boot_guard() -> bool {
    use boot_guard as bg;
    let pure = bg::mode_for(0) == bg::BootMode::Normal
        && bg::mode_for(bg::MAX_FAILED_BOOTS - 1) == bg::BootMode::Normal
        && bg::mode_for(bg::MAX_FAILED_BOOTS) == bg::BootMode::Safe
        && bg::mode_for(u32::MAX) == bg::BootMode::Safe;
    let decided_ok = bg::decided()
        && bg::mode() == bg::mode_for(bg::failed_seen())
        && (!bg::read_failed() || bg::mode() == bg::BootMode::Safe);
    let abi_agrees = (user::abi_word() & user::F_SAFE_MODE != 0) == (bg::mode() == bg::BootMode::Safe);

    let ports_all = ahci::info().map(|i| usize::from(i.ports)).unwrap_or(0);
    // 基线要在**已知的模式**下量：启动时的模式可能是安全模式（那正是第 3、4 格的现场），
    // 拿它当"正常模式的口数"会把两条判据混成一个数
    let pre = bg::mode();
    let _ = bg::force_for_test(bg::BootMode::Normal);
    let normal = ahci::enumerate();
    let _ = bg::force_for_test(bg::BootMode::Safe);
    let safe = ahci::enumerate();
    let _ = bg::force_for_test(pre);
    let after_restore = ahci::enumerate();
    let (n_normal, d_normal) = normal.as_ref().map(|e| (e.n, e.n_disks)).unwrap_or((0, 0));
    let (n_safe, d_safe) = safe.as_ref().map(|e| (e.n, e.n_disks)).unwrap_or((0, 0));
    let consequence = normal.is_ok()
        && safe.is_ok()
        && n_normal == ports_all
        && d_normal >= 1
        && n_safe == 1
        && d_safe >= 1;
    // 还原格比的是"回到进入时那个模式之后，口数是否等于**那个模式**的应有值"。
    // 上一版拿正常模式的基线去比安全模式下的还原现场 ⇒ 一次偶发的"状态区读不到"
    // 会把这台机器永久锁在安全模式里：那遍启动因此永远不健康、计数永远清不掉（BACKLOG ㊿）。
    let expect_after = if pre == bg::BootMode::Normal { n_normal } else { n_safe };
    let restored = bg::mode() == pre && after_restore.map(|e| e.n) == Ok(expect_after);

    crate::log_info!(
        "guard: 模式={:?} 读到的计数={} 读不到={} ABI位={} | 正常模式口={}/{} 盘={} 安全模式口={} 盘={} 还原={}/{} 期望口={}",
        bg::mode(),
        bg::failed_seen(),
        bg::read_failed(),
        user::abi_word() & user::F_SAFE_MODE != 0,
        n_normal,
        ports_all,
        d_normal,
        n_safe,
        d_safe,
        restored,
        after_restore.map(|e| e.n).unwrap_or(0),
        expect_after
    );
    let ok = pure && decided_ok && abi_agrees && consequence && restored;
    if !ok {
        crate::log_fatal!(
            "guard: 判据不成立 纯函数={} 决定自洽={} 可见={} 后果={} 还原={}",
            pure,
            decided_ok,
            abi_agrees,
            consequence,
            restored
        );
    }
    ok
}
ktest!(KT_BOOT_GUARD, t_boot_guard);

