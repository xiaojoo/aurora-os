//! NVMe 驱动的判据（ADR-169）。
//!
//! 三格，按「最便宜的先证」排序：
//!
//! 1. **识别**：PCI 三件套能认到设备，且 CAP/VS/CSTS 的读数形状自洽。
//!    这一格不碰队列——它只证「我们读到了这台设备」。
//! 2. **容量对账**：Identify Namespace 读回的 `NSZE × LBA` 必须等于
//!    宿主机造那块 qcow2 时的 virtual-size。**这是第二台仪器**：
//!    内核算一遍、`qemu-img info` 算一遍，两边各自算。
//! 3. **读回图案**：`_make_vblk` 用 `qemu-io` 写了 `0x7E` 的图案，
//!    读第 0 扇区必须看到它。
//!
//! 三格各自能独立红：识别红 ⇒ 后面两格都没意义；容量红 ⇒ 尺寸账错了；
//! 图案红 ⇒ 数据通路错了。**不合并成"NVMe 能不能用"一个布尔**
//! ——那是本仓库反复拒绝的形状（成因不能压成一个数）。

use crate::driver::nvme;
use crate::ktest;

/// 判据：设备识别与寄存器读数自洽。
///
/// 为什么先验 `CSTS.RDY == 0`：未使能时它必须是 0。若不是，说明这块寄存器
/// 不是我们想的那块——这时候往下走，每条命令都会超时，而日志只会说"超时"，
/// 成因被藏起来。
fn t_nvme_identify() -> bool {
    let r = match nvme::init() {
        Ok(r) => r,
        Err(e) => {
            crate::log_fatal!("nvme: init 失败 {:?} —— {}", e, nvme::NvmeError::describe(e));
            return false;
        }
    };
    // CAP.MQES+1 至少要能装下我们的队列深度（`init` 里已经拦过，这里再证一次读数）
    let mqes_ok = r.max_qdepth >= nvme::QDEPTH;
    // VS 不为 0：NVMe 规范要求它报一个版本号，全 0 说明这块不是 NVMe
    let vs_ok = r.vs != 0;
    // **起始状态允许两种**（实测教训）：QEMU 的 `-device nvme` 在 EDK2 阶段
    // 就可能已经使能过控制器，所以进内核时 RDY 已经是 1 是**合法**的。
    // 原来这里要求「起始 RDY 必须为 0」，那是**环境假设**，不是设备性质。
    //
    // 现在证状态机合法：起始 CFS=0（不能一进来就致命），终态 RDY=1 且 CFS=0。
    // 这比原来**更强**——它同时覆盖两种起始，且额外验了 CFS。
    let csts_ok = (r.csts_before & nvme::CSTS_CFS) == 0
        && (r.csts_after & nvme::CSTS_RDY) != 0
        && (r.csts_after & nvme::CSTS_CFS) == 0;
    let already = (r.csts_before & nvme::CSTS_RDY) != 0;
    // LBA 大小必须是 512 的整数倍且非零（块层的 `SECTOR_BYTES` 契约）
    let lba_ok = r.lbads >= 9 && r.lbads <= 12;
    crate::log_info!(
        "nvme: 识别 bdf={} vendor={:#x} device={:#x} cap_lo={:#x} cap_hi={:#x} vs={:#x} \
         csts={:#x}->{:#x} already={} mqes={} nn={} nsze={} lbads={}",
        r.bdf, r.vendor, r.device, r.cap_lo, r.cap_hi, r.vs,
        r.csts_before, r.csts_after, already, r.max_qdepth,
        r.namespaces, r.nsze, r.lbads
    );
    let ok = mqes_ok && vs_ok && csts_ok && lba_ok;
    if !ok {
        crate::log_fatal!(
            "nvme: 判据不成立 mqes={} vs={} csts={} lba={}",
            mqes_ok, vs_ok, csts_ok, lba_ok
        );
    }
    ok
}

/// 判据：容量账。
///
/// 内核侧算 `NSZE × (1 << lbads)`，宿主机侧用 `qemu-img info` 读同一个 qcow2
/// 的 virtual-size。**两边各自算**——这是本仓库"第二台仪器"的规矩：
/// 谁抄谁，"两边都错"时判据是绿的。
///
/// 内核这一侧只把读数打出来（`nvme: 容量 扇区=… 字节=…`），
/// 对账在 `tools/aurora.py` 里做（它能跑 `qemu-img`）。
fn t_nvme_capacity() -> bool {
    let (Some(nsze), Some(lba)) = (nvme::nsze(), nvme::lba_bytes()) else {
        crate::log_fatal!("nvme: 容量判据 设备没初始化");
        return false;
    };
    let bytes = nsze.saturating_mul(lba as u64);
    // 扇区数（按块层的 512）也要报：宿主机按它跟 virtual-size 对账
    let sectors = bytes / 512;
    crate::log_info!("nvme: 容量 扇区={} 字节={} lba={}", sectors, bytes, lba);
    // 内核侧的自洽判据：容量必须非零、且能整除 512
    let ok = nsze != 0 && bytes % 512 == 0 && sectors != 0;
    if !ok {
        crate::log_fatal!("nvme: 判据不成立 nsze={} bytes={} sectors={}", nsze, bytes, sectors);
    }
    ok
}

/// 判据：读第 0 扇区，看到 `qemu-io` 写下的图案。
///
/// `_make_vblk` 把整块盘写成同一个字节（NVMe 用 `0x7E`）。读回来逐字节比：
/// **不是"读到非零就算过"**——那样缓冲区里的残留也能让它绿。
fn t_nvme_read_pattern() -> bool {
    let mut buf = [0u8; 512];
    if let Err(e) = nvme::read_lba(0, &mut buf) {
        crate::log_fatal!("nvme: 读扇区 0 失败 {:?}", e);
        return false;
    }
    // **判据是「这是一块结构合法的 FAT32 卷」，不是「全 0x7E」。**
    //
    // ADR-172 起 NVMe 盘上是 `make_fat32_rw.py` 造的真卷，所以第 0 扇区
    // 是引导扇区。这比原来的图案判据**更强**：原来只证「能读回我写的字节」，
    // 现在证「读回的是一块能被解析的卷」。
    //
    // 三条独立特征：
    //   ① 偏移 510 的 0x55AA 引导签名
    //   ② 偏移 82 的 `FAT32   ` 字样（8 字节，尾部补空格）
    //   ③ 偏移 0 的跳转指令（0xEB .. 0x90 或 0xE9 ..）
    let sig_ok = buf[510] == 0x55 && buf[511] == 0xAA;
    let fstype_ok = &buf[82..90] == b"FAT32   ";
    let jump_ok = (buf[0] == 0xEB && buf[2] == 0x90) || buf[0] == 0xE9;
    // 首 8 字节的哈希：宿主机用同一份算法独立重算（`check-nvme-pattern` 对账）
    let head = crate::network::eth::frame_hash(&buf[..8]);
    crate::log_info!(
        "nvme: 读回 扇区0 首8={:#x} 引导签名={} FAT32字样={} 跳转={}",
        head, sig_ok, fstype_ok, jump_ok
    );
    let ok = sig_ok && fstype_ok && jump_ok;
    if !ok {
        crate::log_fatal!(
            "nvme: 判据不成立 扇区0 不是合法 FAT32 引导扇区（签名={} 字样={} 跳转={}）",
            sig_ok, fstype_ok, jump_ok
        );
    }
    ok
}

/// 三格合起来跑：**顺序固定**（识别 → 容量 → 图案），因为后两格依赖第一格。
/// 但每一格自己的读数与 `fatal` 都独立打出来——红在哪一格一眼可见。
#[cfg(feature = "nvme")]
fn t_nvme_all() -> bool {
    let a = t_nvme_identify();
    let b = if a { t_nvme_capacity() } else { false };
    let c = if a { t_nvme_read_pattern() } else { false };
    crate::log_info!("nvme: 三格 识别={} 容量={} 图案={} ⇒ {}", a, b, c, a && b && c);
    a && b && c
}

#[cfg(feature = "nvme")]
// `ktest!` 的第一个参数是**任意的 static 名**（宏体里是 `#[used] static $name`），
// 不是预定义常量——照既有写法 `ktest!(KT_PCI, t_pci_config);`。
ktest!(KT_NVME, t_nvme_all);

#[cfg(feature = "nvme")]
fn nvme_async_wait(disk: &crate::filesystem::vfs::NvmeDisk) -> Option<crate::filesystem::vfs::IoCompletion> {
    use crate::filesystem::vfs::AsyncBlock;
    let mut one = [crate::filesystem::vfs::IoCompletion { local_id: 0, sectors_done: 0, error: None }; 1];
    for _ in 0..4 {
        if disk.reap(&mut one) > 0 {
            return Some(one[0]);
        }
        crate::tsc::spin(10_000);
    }
    None
}

#[cfg(feature = "nvme")]
fn nvme_block_wait(
    disk: &crate::filesystem::vfs::NvmeDisk,
    target: crate::filesystem::block_io::TargetId,
) -> Option<crate::filesystem::block_io::LeaseClaim> {
    use crate::filesystem::block_io;
    for _ in 0..200 {
        if let Some(claim) = block_io::async_take_completion(target) {
            return Some(claim);
        }
        let _ = block_io::async_poll(disk);
        crate::tsc::spin(10_000);
    }
    None
}

#[cfg(feature = "nvme")]
fn nvme_fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// ADR-259 第4片：NVMe 单槽只发不等、显式 reap、租约互斥与 poisoned 迟到完成。
/// 所有阶段自足清理；负样本只让对应判据变红，不在 Reserved 探针里真去覆盖在途 DMA。
#[cfg(feature = "nvme")]
fn t_nvme_async() -> bool {
    use crate::arch::x86_64::smp;
    use crate::filesystem::block_io::{self, TargetId};
    use crate::filesystem::vfs::{
        AsyncBlock, Block, BlockError, CancelResult, IoCompletion, IoRequest, NvmeDisk,
    };

    if nvme::init().is_err() {
        crate::log_fatal!("nvme-async: NVMe 认领失败");
        return false;
    }
    let disk = NvmeDisk;
    let Some(before) = nvme::async_stats() else {
        crate::log_fatal!("nvme-async: 异步台账不可读");
        return false;
    };
    if before.occupied != 0 || before.poisoned {
        crate::log_fatal!("nvme-async: 用例不是自足的，起始 occupied={} poisoned={}", before.occupied, before.poisoned);
        return false;
    }
    let mut expected = [0u8; 512];
    if disk.read_sectors(0, &mut expected).is_err() {
        crate::log_fatal!("nvme-async: 同步基线读失败");
        return false;
    }
    let adapter = disk.adapter_id();
    let adapter_ok = adapter.0 == 0x6100_0000
        && disk.adapter_id() == adapter
        && adapter != crate::filesystem::vfs::AdapterId(0x4100_0000)
        && adapter != crate::filesystem::vfs::AdapterId(0x5600_0000);

    // 外层 rank 高于 GROW 时，lock_checked 必须在 CAS 前拒绝，不能留下锁序违规。
    let (rank_rejected, rank_clean) = {
        let stats_before = crate::sync::stats();
        let _outer = smp::CONTENTION_LOCK.lock();
        let rejected = matches!(disk.alloc_lease(1), Err(BlockError::NotSettled));
        let stats_after = crate::sync::stats();
        (
            rejected,
            stats_after.order_violations == stats_before.order_violations
                && stats_after.reentrant_hits == stats_before.reentrant_hits,
        )
    };

    // Reserved 也拥有 DMA 数据页；同步读不得穿插。变异档在这里真发一条同步读，
    // 但此刻没有异步命令在飞，不会覆盖在途 DMA。
    let Ok(reserved) = disk.alloc_lease(1) else {
        crate::log_fatal!("nvme-async: 预占失败");
        return false;
    };
    let mut sync_tmp = [0u8; 512];
    let sync_busy_reserved = matches!(disk.read_sectors(0, &mut sync_tmp), Err(BlockError::NotSettled));
    let cancel_reserved = disk.cancel(u64::from(reserved.0)) == CancelResult::Cancelled;
    let cancelled_count = nvme::async_stats().is_some_and(|s| s.cancelled == before.cancelled + 1);
    let release_after_cancel = disk.release_lease(reserved).is_err();
    if !(rank_rejected && rank_clean && sync_busy_reserved && cancel_reserved && cancelled_count && release_after_cancel) {
        crate::log_fatal!(
            "nvme-async: 前置互斥失败 rank={}/{} reserved={} cancel={}/{} release拒={}",
            rank_rejected, rank_clean, sync_busy_reserved, cancel_reserved, cancelled_count, release_after_cancel
        );
        return false;
    }

    // 直接适配器：submit 返回时 wait_calls 必须一格不动。
    let Ok(read_lease) = disk.alloc_lease(1) else {
        crate::log_fatal!("nvme-async: 读租约分配失败");
        return false;
    };
    let read_id = match disk.submit(IoRequest { lba: 0, sectors: 1, token: 401, write: false }, read_lease) {
        Ok(id) => id,
        Err(e) => {
            crate::log_fatal!("nvme-async: 读提交失败 {:?}", e);
            let _ = disk.release_lease(read_lease);
            return false;
        }
    };
    let immediate = nvme::async_stats().is_some_and(|s| s.wait_calls == before.wait_calls);
    let second_lease = disk.alloc_lease(1).ok();
    let second_lease_ok = second_lease.is_some();
    let second_release = second_lease.as_ref().is_some_and(|lease| disk.release_lease(*lease).is_ok());
    let sync_busy_inflight = {
        #[cfg(not(feature = "fault-nvme-sync-interleave"))]
        {
            matches!(disk.read_sectors(0, &mut sync_tmp), Err(BlockError::NotSettled))
        }
        #[cfg(feature = "fault-nvme-sync-interleave")]
        {
            // Reserved 格已经证红；这里不真去穿插一条在途 DMA。
            true
        }
    };
    let cancel_inflight = disk.cancel(read_id) == CancelResult::InFlight;
    let release_inflight = disk.release_lease(read_lease).is_err();
    let read_done = nvme_async_wait(&disk);
    let mut got = [0u8; 512];
    let read_ok = read_done.as_ref().is_some_and(|c| {
        c.local_id == read_id && c.sectors_done == 1 && c.error.is_none()
            && disk.copy_out(read_lease, &mut got) == Ok(())
    }) && got == expected;
    let cancel_completed = read_done.as_ref().is_some_and(|c| disk.cancel(c.local_id) == CancelResult::Completed);
    let released_read = disk.release_lease(read_lease).is_ok();
    let stale_release = disk.release_lease(read_lease).is_err();
    if !(immediate && second_lease_ok && second_release && sync_busy_inflight && cancel_inflight && release_inflight
        && read_ok && cancel_completed && released_read && stale_release)
    {
        crate::log_fatal!(
            "nvme-async: 读阶段失败 immediate={} second={}/{} sync={} cancel={} release拒={} read={} completed取消={} release={}/{}",
            immediate, second_lease_ok, second_release, sync_busy_inflight, cancel_inflight, release_inflight,
            read_ok, cancel_completed, released_read, stale_release
        );
        return false;
    }

    // 经 VFS AsyncBlock 路由到 block_io，证 AdapterId/LeaseClaim 认主与释放闭环。
    let target = TargetId(adapter.0);
    let routed = block_io::async_submit(&disk, target, 0, 1, false, 402, None);
    let mut routed_claim = routed.as_ref().ok().and_then(|_| nvme_block_wait(&disk, target));
    let mut routed_data = [0u8; 512];
    let routed_ok = routed.is_ok() && routed_claim.as_ref().is_some_and(|c| {
        c.token == 402 && c.sectors == 1 && c.sectors_done == 1 && c.error.is_none()
            && block_io::async_copy_out(&disk, c, &mut routed_data) == Ok(())
    }) && routed_data == expected;
    let routed_release = routed_claim.as_mut().is_some_and(|c| block_io::async_release(&disk, c).is_ok());
    if !(routed_ok && routed_release) {
        crate::log_fatal!("nvme-async: block_io 路由失败 routed={}/{} release={}", routed.is_ok(), routed_ok, routed_release);
        return false;
    }

    // 空输出不消费；短 copy_out 只取前缀，租约仍须显式释放。
    let Ok(small_lease) = disk.alloc_lease(1) else {
        crate::log_fatal!("nvme-async: 小缓冲租约分配失败");
        return false;
    };
    let small_id = match disk.submit(IoRequest { lba: 0, sectors: 1, token: 403, write: false }, small_lease) {
        Ok(id) => id,
        Err(e) => {
            crate::log_fatal!("nvme-async: 小缓冲提交失败 {:?}", e);
            let _ = disk.release_lease(small_lease);
            return false;
        }
    };
    let Some(empty_before) = nvme::async_stats() else {
        crate::log_fatal!("nvme-async: 空回收前台账不可读");
        return false;
    };
    let mut empty: [IoCompletion; 0] = [];
    let empty_reap = disk.reap(&mut empty) == 0;
    let Some(empty_after) = nvme::async_stats() else {
        crate::log_fatal!("nvme-async: 空回收后台账不可读");
        return false;
    };
    let empty_untouched = empty_after.completed == empty_before.completed
        && empty_after.wait_calls == empty_before.wait_calls;
    let small_done = nvme_async_wait(&disk);
    let mut small_data = [0u8; 16];
    let small_ok = small_id > read_id && small_done.as_ref().is_some_and(|c| {
        c.local_id == small_id && c.sectors_done == 1 && c.error.is_none()
            && disk.copy_out(small_lease, &mut small_data) == Ok(())
    }) && small_data == expected[..16];
    let small_release = disk.release_lease(small_lease).is_ok();
    if !(empty_reap && empty_untouched && small_ok && small_release) {
        crate::log_fatal!("nvme-async: 小缓冲失败 empty={}/{} small={} release={}", empty_reap, empty_untouched, small_ok, small_release);
        return false;
    }

    // 真写 + 真回读。写盘末尾空闲 LBA，避免碰 FAT32 夹具；宿主机随后按锚点独立读盘。
    let Some(nsze) = nvme::nsze() else {
        crate::log_fatal!("nvme-async: 容量不可读");
        return false;
    };
    if nsze <= 16 {
        crate::log_fatal!("nvme-async: 容量不足，无法选择安全写 LBA");
        return false;
    }
    let write_lba = nsze - 16;
    let src = [0xA5u8; 512];
    let write_hash = nvme_fnv1a64(&src);
    let Ok(write_lease) = disk.alloc_lease(1) else {
        crate::log_fatal!("nvme-async: 写租约分配失败");
        return false;
    };
    if disk.copy_in(write_lease, &src).is_err() {
        crate::log_fatal!("nvme-async: copy_in 失败");
        let _ = disk.release_lease(write_lease);
        return false;
    }
    let write_id = match disk.submit(IoRequest { lba: write_lba, sectors: 1, token: 404, write: true }, write_lease) {
        Ok(id) => id,
        Err(e) => {
            crate::log_fatal!("nvme-async: 写提交失败 {:?}", e);
            let _ = disk.release_lease(write_lease);
            return false;
        }
    };
    let write_immediate = nvme::async_stats().is_some_and(|s| s.wait_calls == before.wait_calls);
    let write_done = nvme_async_wait(&disk);
    let write_ok = write_done.as_ref().is_some_and(|c| {
        c.local_id == write_id && c.sectors_done == 1 && c.error.is_none()
    });
    let write_release = disk.release_lease(write_lease).is_ok();
    let Ok(back_lease) = disk.alloc_lease(1) else {
        crate::log_fatal!(
            "nvme-async: 回读租约分配失败 write_done={} write_release={} stats={:?}",
            write_done.is_some(), write_release, nvme::async_stats()
        );
        return false;
    };
    let back_id = match disk.submit(IoRequest { lba: write_lba, sectors: 1, token: 405, write: false }, back_lease) {
        Ok(id) => id,
        Err(e) => {
            crate::log_fatal!("nvme-async: 回读提交失败 {:?}", e);
            let _ = disk.release_lease(back_lease);
            return false;
        }
    };
    let back_done = nvme_async_wait(&disk);
    let mut back = [0u8; 512];
    let write_read_ok = back_id > write_id && back_done.as_ref().is_some_and(|c| {
        c.local_id == back_id && c.sectors_done == 1 && c.error.is_none()
            && disk.copy_out(back_lease, &mut back) == Ok(())
    }) && back == src;
    let back_release = disk.release_lease(back_lease).is_ok();
    crate::log_info!("nvme-async-write: 写 lba={} 计数=1 哈希={:#018x}", write_lba, write_hash);
    if !(write_immediate && write_ok && write_release && write_read_ok && back_release) {
        crate::log_fatal!("nvme-async: 写/回读失败 immediate={} write={}/{} read={}/{}", write_immediate, write_ok, write_release, write_read_ok, back_release);
        return false;
    }

    // 设备完成错误必须原样交给 lease，不能伪装成丢失或 poison。
    let Ok(error_lease) = disk.alloc_lease(1) else {
        crate::log_fatal!("nvme-async: 错误回执租约分配失败");
        return false;
    };
    let error_id = match disk.submit(IoRequest { lba: nsze, sectors: 1, token: 406, write: false }, error_lease) {
        Ok(id) => id,
        Err(e) => {
            crate::log_fatal!("nvme-async: 错误回执提交失败 {:?}", e);
            let _ = disk.release_lease(error_lease);
            return false;
        }
    };
    let error_done = nvme_async_wait(&disk);
    let completion_error_ok = error_done.as_ref().is_some_and(|c| {
        c.local_id == error_id && c.sectors_done == 0 && c.error == Some(BlockError::DeviceError)
    });
    let error_release = disk.release_lease(error_lease).is_ok();
    let error_clean = nvme::async_stats().is_some_and(|s| !s.poisoned && s.occupied == 0);
    if !(completion_error_ok && error_release && error_clean) {
        crate::log_fatal!("nvme-async: 完成错误未原样带回 error={} release={} clean={}", completion_error_ok, error_release, error_clean);
        return false;
    }

    // 模拟超时隔离后，仍允许 reap 真实迟到 CQE；完成后才能释放并解除 poison。
    let Ok(late_lease) = disk.alloc_lease(1) else {
        crate::log_fatal!("nvme-async: 迟到完成租约分配失败");
        return false;
    };
    let late_id = match disk.submit(IoRequest { lba: 0, sectors: 1, token: 407, write: false }, late_lease) {
        Ok(id) => id,
        Err(e) => {
            crate::log_fatal!("nvme-async: 迟到完成提交失败 {:?}", e);
            let _ = disk.release_lease(late_lease);
            return false;
        }
    };
    let poisoned = nvme::async_quarantine_for_test().is_ok();
    let poisoned_health = disk.ensure_readable() == Err(BlockError::Quarantined);
    let late_done = nvme_async_wait(&disk);
    let mut late_data = [0u8; 512];
    let late_ok = late_done.as_ref().is_some_and(|c| {
        c.local_id == late_id && c.sectors_done == 1 && c.error.is_none()
            && disk.copy_out(late_lease, &mut late_data) == Ok(())
    }) && late_data == expected;
    let late_release = disk.release_lease(late_lease).is_ok();
    let recovered = nvme::async_recover_for_test().is_ok();

    // 同步等待超时也必须关闭新 I/O；注入不真发命令，随后可在 Free 槽上恢复。
    nvme::async_force_sync_timeout_for_test();
    let sync_timeout = matches!(disk.read_sectors(0, &mut sync_tmp), Err(BlockError::NotSettled));
    let sync_quarantined = nvme::async_stats().is_some_and(|s| s.poisoned);
    let sync_recovered = sync_quarantined && nvme::async_recover_for_test().is_ok();
    let Some(after) = nvme::async_stats() else {
        crate::log_fatal!("nvme-async: 收尾台账不可读");
        return false;
    };
    let submitted = after.submitted.saturating_sub(before.submitted);
    let completed = after.completed.saturating_sub(before.completed);
    let wait_delta = after.wait_calls.saturating_sub(before.wait_calls);
    let stats_ok = submitted == 7 && completed == 7 && wait_delta == 0
        && after.bad_used == before.bad_used && after.occupied == 0 && !after.poisoned;
    let ok = adapter_ok && poisoned && poisoned_health && late_ok && late_release && recovered
        && sync_timeout && sync_quarantined && sync_recovered && stats_ok;
    crate::log_info!(
        "nvme-async: adapter={:#x} rank={}/{} 立即={} 预约互斥={} 在途互斥={} 第二租约={}/{} 取消={}/{}/{} 释放拒={}/{} 读={} 块层={} 空缓冲={} 小缓冲={} 写回读={} 完成错误={} poisoned={} 迟到={} 恢复={} 同步超时隔离={}/{}/{} 计数={}/{}/{} wait={} ⇒ {}",
        adapter.0, rank_rejected, rank_clean, immediate, sync_busy_reserved, sync_busy_inflight,
        second_lease_ok, second_release, cancel_reserved, cancel_inflight, cancel_completed, release_after_cancel,
        release_inflight, read_ok, routed_ok, empty_reap && empty_untouched, small_ok,
        write_read_ok, completion_error_ok, poisoned, late_ok, recovered,
        sync_timeout, sync_quarantined, sync_recovered,
        submitted, completed, after.bad_used.saturating_sub(before.bad_used), wait_delta, ok
    );
    if !ok {
        crate::log_fatal!("nvme-async: 单槽异步判据不成立（上面一行是全部读数）");
    }
    ok
}

#[cfg(feature = "nvme")]
ktest!(KT_NVME_ASYNC, t_nvme_async);

#[cfg(feature = "nvme")]
fn t_nvme_checked_async_wrap() -> bool {
    use crate::filesystem::block_io;
    use crate::filesystem::vfs::NvmeDisk;
    if nvme::init().is_err() {
        return false;
    }
    let disk = NvmeDisk;
    let before = nvme::async_stats().unwrap_or_default();
    let mut expected = [0u8; 512];
    if let Err(error) = nvme::read_lba(0, &mut expected) {
        crate::log_fatal!("nvme-wrap: 基线读失败 {:?}", error);
        return false;
    }
    let mut got = [0u8; 512];
    let read = block_io::read_checked(&disk, 0, &mut got, &block_io::Budget::UNBOUNDED);
    let after = nvme::async_stats().unwrap_or_default();
    let ok = read == Ok(()) && got == expected
        && after.submitted == before.submitted + 1 && after.completed == before.completed + 1
        && after.occupied == 0 && !after.poisoned;
    crate::log_info!("nvme-wrap: read={:?} 内容={} 异步={}->{} 完成={}->{} 占槽={} ⇒ {}",
        read, got == expected, before.submitted, after.submitted, before.completed, after.completed, after.occupied, ok);
    if !ok {
        crate::log_fatal!("nvme-wrap: read_checked 未走 NVMe 异步核心");
    }
    ok
}
#[cfg(feature = "nvme")]
ktest!(KT_NVME_CHECKED_ASYNC_WRAP, t_nvme_checked_async_wrap);

#[cfg(feature = "nvme")]
fn t_nvme_multi() -> bool {
    use crate::filesystem::vfs::{AsyncBlock, BlockError, IoCompletion, IoLease, IoRequest, NvmeDisk};
    if nvme::init().is_err() {
        return false;
    }
    let disk = NvmeDisk;
    let before = nvme::async_stats().unwrap_or_default();
    crate::log_info!("nvme-multi: 起始 {:?}", before);
    let mut leases = [IoLease(0); nvme::DATA_SLOTS];
    let mut ids = [0u64; nvme::DATA_SLOTS];
    let mut hashes = [0u64; nvme::DATA_SLOTS];
    let mut sector = [0u8; 512];
    for i in 0..nvme::DATA_SLOTS {
        if let Err(error) = nvme::read_lba(i as u64, &mut sector) {
            crate::log_fatal!("nvme-multi: 基线读 {} 失败 {:?}", i, error);
            return false;
        }
        hashes[i] = nvme_fnv1a64(&sector);
    }
    for i in 0..nvme::DATA_SLOTS {
        let Ok(lease) = disk.alloc_lease(1) else {
            crate::log_fatal!("nvme-multi: 租约 {} 分配失败", i);
            return false;
        };
        leases[i] = lease;
        let Ok(id) = disk.submit(IoRequest { lba: i as u64, sectors: 1, token: 500 + i as u64, write: false }, lease) else {
            crate::log_fatal!("nvme-multi: 提交 {} 失败", i);
            let _ = disk.release_lease(lease);
            return false;
        };
        ids[i] = id;
    }
    let ninth = matches!(disk.alloc_lease(1), Err(BlockError::NotSettled));
    let mut done = [IoCompletion { local_id: 0, sectors_done: 0, error: None }; nvme::DATA_SLOTS];
    let mut count = disk.reap(&mut done);
    let one_call = count == nvme::DATA_SLOTS;
    while count < nvme::DATA_SLOTS {
        let mut one = [IoCompletion { local_id: 0, sectors_done: 0, error: None }; 1];
        let n = disk.reap(&mut one);
        if n == 0 {
            break;
        }
        done[count] = one[0];
        count += 1;
    }
    let mut unique = true;
    let mut data_ok = true;
    for i in 0..nvme::DATA_SLOTS {
        let matches: usize = done.iter().filter(|completion| completion.local_id == ids[i]).count();
        unique &= matches == 1;
        let Some(completion) = done.iter().find(|completion| completion.local_id == ids[i]) else {
            data_ok = false;
            continue;
        };
        data_ok &= completion.sectors_done == 1 && completion.error.is_none();
        let mut got = [0u8; 512];
        data_ok &= disk.copy_out(leases[i], &mut got) == Ok(()) && nvme_fnv1a64(&got) == hashes[i];
    }
    let mut released = true;
    for lease in leases {
        released &= disk.release_lease(lease).is_ok();
    }
    let after = nvme::async_stats().unwrap_or_default();
    let ok = ninth && one_call && count == nvme::DATA_SLOTS && unique && data_ok && released
        && after.submitted == before.submitted + nvme::DATA_SLOTS as u32
        && after.completed == before.completed + nvme::DATA_SLOTS as u32
        && after.occupied == 0 && !after.poisoned;
    crate::log_info!(
        "nvme-multi: 深度={} 第九拒={} 单次回收={}/{} 唯一={} 数据={} 释放={} 计数={}->{}/{}->{} 占槽={} ⇒ {}",
        nvme::DATA_SLOTS, ninth, one_call, count, unique, data_ok, released,
        before.submitted, after.submitted, before.completed, after.completed, after.occupied, ok
    );
    if !ok {
        crate::log_fatal!("nvme-multi: 多 outstanding 判据不成立");
    }
    ok
}
#[cfg(feature = "nvme")]
ktest!(KT_NVME_MULTI, t_nvme_multi);

#[cfg(feature = "nvme")]
fn t_nvme_drain_recover() -> bool {
    use crate::filesystem::vfs::{AsyncBlock, IoLease, IoRequest, NvmeDisk};
    if nvme::init().is_err() {
        return false;
    }
    let disk = NvmeDisk;
    let mut leases = [IoLease(0); 2];
    for i in 0..2 {
        let Ok(lease) = disk.alloc_lease(1) else { return false };
        leases[i] = lease;
        let Ok(_id) = disk.submit(IoRequest { lba: i as u64, sectors: 1, token: 600 + i as u64, write: false }, lease) else {
            let _ = disk.release_lease(lease);
            return false;
        };
    }
    crate::tsc::spin(10_000_000);
    let drain = nvme::async_drain();
    crate::log_info!("nvme-drain: 第一次 {:?} 状态={:?}", drain, nvme::async_stats());
    let drain_ok = drain.as_ref().is_ok_and(|report| report.disabled && report.queues_deleted && report.completed == 2 && report.outstanding == 0);
    let mut released = true;
    for lease in leases {
        released &= disk.release_lease(lease).is_ok();
    }
    let recover_result = nvme::async_recover();
    crate::log_info!("nvme-drain: 恢复结果={:?}", recover_result);
    let recovered = drain_ok && released && recover_result.is_ok();
    let post = if recovered {
        let lease = match disk.alloc_lease(1) { Ok(lease) => lease, Err(_) => return false };
        let submitted = disk.submit(IoRequest { lba: 0, sectors: 1, token: 602, write: false }, lease);
        let done = nvme_async_wait(&disk);
        let ok = submitted.is_ok() && done.as_ref().is_some_and(|completion| completion.error.is_none());
        let _ = disk.release_lease(lease);
        ok
    } else {
        false
    };

    crate::log_info!("nvme-drain: 恢复后读={} 状态={:?}", post, nvme::async_stats());
    let fatal_lease = match disk.alloc_lease(1) { Ok(lease) => lease, Err(_) => return false };
    let fatal_submit = disk.submit(IoRequest { lba: 0, sectors: 1, token: 603, write: false }, fatal_lease);
    crate::tsc::spin(10_000_000);
    nvme::async_inject_fatal_for_test();
    let fatal_drain = nvme::async_drain();
    let fatal_drain_ok = fatal_submit.is_ok()
        && fatal_drain.as_ref().is_ok_and(|report| report.disabled && report.queues_deleted && report.completed == 1 && report.outstanding == 0);
    let _ = nvme::async_reap(&mut [crate::nvme::NvmeIoCompletion { local_id: 0, sectors_done: 0, error: None }; 1]);
    let fatal_released = disk.release_lease(fatal_lease).is_ok();
    let fatal_recover_refused = matches!(nvme::async_recover(), Err(nvme::NvmeError::ControllerFatal { .. }));
    nvme::async_clear_fatal_for_test();
    let fatal_recover_result = nvme::async_recover();
    crate::log_info!("nvme-drain: 致命恢复结果={:?}", fatal_recover_result);
    let fatal_recovered = fatal_recover_refused && fatal_recover_result.is_ok();
    crate::log_info!("nvme-drain: 致命排空={} 释放={} 拒恢复={} 恢复={} 状态={:?}", fatal_drain_ok, fatal_released, fatal_recover_refused, fatal_recovered, nvme::async_stats());

    let busy_lease = match disk.alloc_lease(1) { Ok(lease) => lease, Err(_) => return false };
    let recover_busy_refused = matches!(nvme::async_recover(), Err(nvme::NvmeError::AsyncBusy));
    let busy_released = disk.release_lease(busy_lease).is_ok();
    let after = nvme::async_stats().unwrap_or_default();
    let ok = drain_ok && released && recovered && post
        && fatal_drain_ok && fatal_released && fatal_recover_refused && fatal_recovered
        && recover_busy_refused && busy_released && after.occupied == 0 && !after.poisoned;
    crate::log_info!(
        "nvme-drain: 禁用={:?} 释放={} 恢复={} 恢复后读={} 致命排空={} 致命拒恢复={} 致命恢复={} 在途拒恢复={}/{} 收尾={}/{} ⇒ {}",
        drain, released, recovered, post, fatal_drain_ok, fatal_recover_refused, fatal_recovered,
        recover_busy_refused, busy_released, after.occupied, after.poisoned, ok
    );
    if !ok {
        crate::log_fatal!("nvme-drain: 禁用/致命态排空与恢复判据不成立");
    }
    ok
}
#[cfg(feature = "nvme")]
ktest!(KT_NVME_DRAIN_RECOVER, t_nvme_drain_recover);
