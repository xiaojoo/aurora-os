use crate::filesystem::block_notify::{self, NotifyEndpoint, NotifyError};
use crate::ktest;
use crate::filesystem::vfs::BlockError;

fn endpoint(vmo: u8, generation: u64) -> NotifyEndpoint {
    NotifyEndpoint {
        proc: 7,
        proc_gen: 3,
        vmo,
        vmo_gen: 11,
        ring_va: 0x2_6000_0000,
        capacity: block_notify::NOTIFY_SLOTS as u16,
        generation,
    }
}

struct NotifyFakeDisk {
    state: core::sync::atomic::AtomicU8,
    sectors: u32,
    sectors_done: u32,
    error: Option<BlockError>,
}

impl crate::filesystem::vfs::AsyncBlock for NotifyFakeDisk {
    fn adapter_id(&self) -> crate::filesystem::vfs::AdapterId {
        crate::filesystem::vfs::AdapterId(0x6200_0000)
    }

    fn alloc_lease(&self, sectors: u32) -> Result<crate::filesystem::vfs::IoLease, BlockError> {
        if sectors == 0 || sectors != self.sectors {
            return Err(BlockError::Refused);
        }
        self.state.compare_exchange(0, 1, core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire)
            .map(|_| crate::filesystem::vfs::IoLease(1)).map_err(|_| BlockError::NotSettled)
    }

    fn copy_in(&self, _: crate::filesystem::vfs::IoLease, _: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::Refused)
    }

    fn copy_out(&self, _: crate::filesystem::vfs::IoLease, dst: &mut [u8]) -> Result<(), BlockError> {
        if self.state.load(core::sync::atomic::Ordering::Acquire) != 3
            || dst.len() > self.sectors as usize * 512
        {
            return Err(BlockError::Refused);
        }
        dst.fill(0x5A);
        Ok(())
    }

    fn submit(
        &self,
        request: crate::filesystem::vfs::IoRequest,
        _: crate::filesystem::vfs::IoLease,
    ) -> Result<u64, BlockError> {
        if request.sectors != self.sectors {
            return Err(BlockError::Refused);
        }
        self.state.compare_exchange(1, 2, core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire)
            .map(|_| 1).map_err(|_| BlockError::NotSettled)
    }

    fn reap(&self, out: &mut [crate::filesystem::vfs::IoCompletion]) -> usize {
        if out.is_empty() || self.state.compare_exchange(2, 3, core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire).is_err() {
            return 0;
        }
        out[0] = crate::filesystem::vfs::IoCompletion {
            local_id: 1,
            sectors_done: self.sectors_done,
            error: self.error,
        };
        1
    }

    fn cancel(&self, _: u64) -> crate::filesystem::vfs::CancelResult {
        crate::filesystem::vfs::CancelResult::NotFound
    }

    fn release_lease(&self, _: crate::filesystem::vfs::IoLease) -> Result<(), BlockError> {
        self.state.store(0, core::sync::atomic::Ordering::Release);
        Ok(())
    }
}

fn t_block_notify_wire() -> bool {
    use crate::filesystem::block_io::{self, TargetId};
    use crate::filesystem::vfs::AsyncBlock;
    block_notify::reset_for_test();
    block_io::queue_clear();
    let disk = NotifyFakeDisk {
        state: core::sync::atomic::AtomicU8::new(0),
        sectors: 1,
        sectors_done: 1,
        error: None,
    };
    let Ok(endpoint) = block_notify::install(endpoint(5, 0)) else { return false };
    let target = TargetId(disk.adapter_id().0);
    let submitted = block_io::async_submit(&disk, target, 0, 1, false, 777, None);
    let polled = block_io::async_poll(&disk);
    let notice = block_notify::next_to_write(endpoint).ok().flatten();
    let notice_ok = notice.as_ref().is_some_and(|record| {
        record.token == 777 && record.target == target.0 && record.result == 0 && record.sectors_done == 1
    });
    let mut claim = submitted.as_ref().ok().and_then(|_| block_io::async_take_completion(target));
    let mut data = [0u8; 512];
    let data_ok = claim.as_ref().is_some_and(|claim| block_io::async_copy_out(&disk, claim, &mut data) == Ok(()))
        && data == [0x5A; 512];
    let released = claim.as_mut().is_some_and(|claim| block_io::async_release(&disk, claim).is_ok());
    let acked = notice.as_ref().is_some_and(|record| {
        block_notify::mark_published(endpoint, record.seq).is_ok()
            && block_notify::confirm_acked(endpoint, record.seq).is_ok()
    });
    let clean = block_notify::stats().retained == 0 && disk.state.load(core::sync::atomic::Ordering::Acquire) == 0;
    let ok = submitted.is_ok() && polled == 1 && notice_ok && data_ok && released && acked && clean;
    crate::log_info!(
        "block-notify-wire: 提交={} poll={} 通知={} 数据={} 释放={} 确认={} 收尾={} ⇒ {}",
        submitted.is_ok(), polled, notice_ok, data_ok, released, acked, clean, ok
    );
    if !ok {
        crate::log_fatal!("block-notify-wire: block_io 到通知账本的接线判据不成立");
    }
    ok
}

ktest!(KT_BLOCK_NOTIFY_WIRE, t_block_notify_wire);

fn t_block_notify_partial() -> bool {
    use crate::filesystem::block_io::{self, TargetId};
    use crate::filesystem::vfs::AsyncBlock;
    block_notify::reset_for_test();
    block_io::queue_clear();
    let disk = NotifyFakeDisk {
        state: core::sync::atomic::AtomicU8::new(0),
        sectors: 2,
        sectors_done: 2,
        error: Some(BlockError::DeviceError),
    };
    let Ok(endpoint) = block_notify::install(endpoint(8, 0)) else { return false };
    let target = TargetId(disk.adapter_id().0);
    let submitted = block_io::async_submit(&disk, target, 0, 2, false, 778, None);
    let polled = block_io::async_poll(&disk);
    let notice = block_notify::next_to_write(endpoint).ok().flatten();
    let notice_ok = notice.as_ref().is_some_and(|record| {
        record.token == 778 && record.result == 4 && record.sectors_done == 2
    });
    let mut claim = submitted.as_ref().ok().and_then(|_| block_io::async_take_completion(target));
    let completion_ok = claim.as_ref().is_some_and(|claim| {
        claim.sectors_done == 2 && claim.error == Some(BlockError::DeviceError)
    });
    let released = claim.as_mut().is_some_and(|claim| block_io::async_release(&disk, claim).is_ok());
    let acked = notice.as_ref().is_some_and(|record| {
        block_notify::mark_published(endpoint, record.seq).is_ok()
            && block_notify::confirm_acked(endpoint, record.seq).is_ok()
    });
    let clean = block_notify::stats().retained == 0
        && disk.state.load(core::sync::atomic::Ordering::Acquire) == 0;
    let ok = submitted.is_ok() && polled == 1 && notice_ok && completion_ok && released && acked && clean;
    crate::log_info!(
        "block-notify-partial: 提交={} poll={} 通知={} 完成={} 释放={} 确认={} 收尾={} ⇒ {}",
        submitted.is_ok(), polled, notice_ok, completion_ok, released, acked, clean, ok
    );
    if !ok {
        crate::log_fatal!("block-notify-partial: 错误完成的部分扇区数被丢失");
    }
    ok
}

ktest!(KT_BLOCK_NOTIFY_PARTIAL, t_block_notify_partial);

fn t_block_notify_page() -> bool {
    use crate::notify_broker;
    use crate::vmo;
    use core::sync::atomic::Ordering;
    block_notify::reset_for_test();
    let Ok(page) = vmo::vmo_create(1) else { return false };
    let init = notify_broker::init_ring(page, 0).is_ok();
    let Ok(first) = block_notify::install(endpoint(6, 0)) else { return false };
    let published = block_notify::publish(0x9876, 0x55, 9, None, [0x33; 16]);
    let record = block_notify::next_to_write(first).ok().flatten();
    let mirrored = record.as_ref().is_some_and(|record| notify_broker::mirror_record(page, first, *record).is_ok());
    let producer = vmo::vmo_atomic_load(page, block_notify::OFF_PRODUCER, Ordering::Acquire);
    let mut bytes = [0u8; block_notify::NOTIFY_RECORD_BYTES];
    let read = vmo::vmo_read(page, block_notify::NOTIFY_HEADER_BYTES, &mut bytes);
    let content_ok = read == Ok(bytes.len()) && record.is_some_and(|record| bytes == record.to_bytes());
    let ack_store = vmo::vmo_atomic_store(page, block_notify::OFF_CONSUMED, 1, Ordering::Release);
    let acked = block_notify::confirm_acked(first, 1).is_ok();

    let reinit = notify_broker::init_ring(page, 1).is_ok();
    let Ok(second) = block_notify::install(endpoint(7, 0)) else { return false };
    let published2 = block_notify::publish(0x9877, 0x55, 0, Some(BlockError::DeviceError), [0; 16]);
    let record2 = block_notify::next_to_write(second).ok().flatten();
    let mirrored2 = record2.as_ref().is_some_and(|record| {
        record.seq == 2 && notify_broker::mirror_record(page, second, *record).is_ok()
    });
    let producer2 = vmo::vmo_atomic_load(page, block_notify::OFF_PRODUCER, Ordering::Acquire);
    let mut header = [0u8; block_notify::NOTIFY_HEADER_BYTES];
    let header_read = vmo::vmo_read(page, 0, &mut header);
    let header_ok = header_read == Ok(header.len())
        && header[0..4] == block_notify::NOTIFY_MAGIC.to_le_bytes()
        && header[8..12] == (block_notify::NOTIFY_SLOTS as u32).to_le_bytes();
    let clean = block_notify::confirm_acked(second, 2).is_ok() && block_notify::stats().retained == 0;
    vmo::vmo_unref(page);
    block_notify::reset_for_test();
    let ok = init && published == Ok(1) && mirrored && producer == Ok(1) && content_ok
        && ack_store == Ok(()) && acked && reinit && published2 == Ok(2) && mirrored2
        && producer2 == Ok(2) && header_ok && clean;
    crate::log_info!(
        "block-notify-page: 头={} 发布={:?}/{:?} 镜像={}/{} producer={:?}/{:?} 内容={} 确认={} 替换={} 收尾={} ⇒ {}",
        init, published, published2, mirrored, mirrored2, producer, producer2, content_ok, acked, header_ok, clean, ok
    );
    if !ok {
        crate::log_fatal!("block-notify-page: 共享页镜像判据不成立");
    }
    ok
}

ktest!(KT_BLOCK_NOTIFY_PAGE, t_block_notify_page);

fn t_block_notify_ring3() -> bool {
    use crate::notify_broker;
    block_notify::reset_for_test();
    crate::filesystem::block_io::queue_clear();
    let handles0 = crate::handle::used();
    let procs0 = crate::proc::proc_residual();
    let vmos0 = crate::vmo::vmo_count();
    let exits0 = crate::user::exits();
    let kills0 = crate::user::kills();

    let Ok(first) = notify_broker::spawn(0) else {
        crate::log_fatal!("block-notify-ring3: 首个 broker 创建失败");
        return false;
    };
    let seq1 = block_notify::publish(0xface, 0x77, 1, None, [0x11; 16]);
    let pump1 = first.pump();
    let code1 = first.wait();

    let seq2 = block_notify::publish(0xbeef, 0x77, 0, Some(BlockError::NotSettled), [0x22; 16]);
    let Ok(panic_broker) = notify_broker::spawn(1) else {
        crate::log_fatal!("block-notify-ring3: panic broker 创建失败");
        return false;
    };
    let pump_panic = panic_broker.pump();
    let panic_code = panic_broker.wait();
    let retained_after_panic = block_notify::stats().retained;

    let Ok(replacement) = notify_broker::spawn(0) else {
        crate::log_fatal!("block-notify-ring3: 替换 broker 创建失败");
        return false;
    };
    let pump_replacement = replacement.pump();
    let replacement_code = replacement.wait();
    let stats = block_notify::stats();
    let handles1 = crate::handle::used();
    let procs1 = crate::proc::proc_residual();
    let vmos1 = crate::vmo::vmo_count();
    let exits1 = crate::user::exits();
    let kills1 = crate::user::kills();
    let session_clean = crate::user::session_va_count(notify_broker::BROKER_SID) == 0;
    let ok = seq1 == Ok(1) && pump1 == Ok(1) && code1 == Ok(0)
        && seq2 == Ok(2) && pump_panic == Ok(1) && panic_code == Ok(3)
        && retained_after_panic == 1 && pump_replacement == Ok(1) && replacement_code == Ok(0)
        && stats.acked_seq == 2 && stats.retained == 0
        && handles1 == handles0 && procs1 == procs0 && vmos1 == vmos0
        && exits1 == exits0 + 3 && kills1 == kills0 && session_clean;
    crate::log_info!(
        "block-notify-ring3: seq={:?}/{:?} pump={:?}/{:?}/{:?} 退出={:?}/{:?}/{:?} panic保留={} 重投后={}/{} 资源=(h{}->{} p{}->{} v{}->{}) exits{}->{} kills{}->{} session={} ⇒ {}",
        seq1, seq2, pump1, pump_panic, pump_replacement, code1, panic_code, replacement_code,
        retained_after_panic, stats.acked_seq, stats.retained,
        handles0, handles1, procs0.0, procs1.0, vmos0, vmos1,
        exits0, exits1, kills0, kills1, session_clean, ok
    );
    if !ok {
        crate::log_fatal!("block-notify-ring3: ring3 broker/死亡/替换/panic 判据不成立");
    }
    block_notify::reset_for_test();
    ok
}

ktest!(KT_BLOCK_NOTIFY_RING3, t_block_notify_ring3);

fn t_block_notify_core() -> bool {
    block_notify::reset_for_test();
    let first = match block_notify::install(endpoint(1, 0)) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            crate::log_fatal!("block-notify: 安装失败 {:?}", error);
            return false;
        }
    };
    let s1 = block_notify::publish(101, 0x41, 1, None, [0; 16]);
    let s2 = block_notify::publish(102, 0x41, 0, Some(BlockError::NotSettled), [0; 16]);
    let record1 = block_notify::next_to_write(first).ok().flatten();
    let publish1 = record1.as_ref().is_some_and(|record| {
        record.seq == 1 && record.token == 101 && record.target == 0x41 && record.result == 0 && record.sectors_done == 1
    });
    let mark1 = record1.as_ref().is_some_and(|record| block_notify::mark_published(first, record.seq).is_ok());
    let ack1 = block_notify::confirm_acked(first, 1).is_ok();
    let duplicate_ack = block_notify::confirm_acked(first, 1).is_ok();
    let bad_ack = block_notify::confirm_acked(first, 2) == Err(NotifyError::BadAck);

    let second = match block_notify::install(endpoint(2, 0)) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            crate::log_fatal!("block-notify: 替换失败 {:?}", error);
            return false;
        }
    };
    let record2 = block_notify::next_to_write(second).ok().flatten();
    let replay = record2.as_ref().is_some_and(|record| {
        record.seq == 2 && record.token == 102 && record.result == 3 && record.sectors_done == 0
            && block_notify::mark_published(second, 2).is_ok()
    });
    let mut forged = second;
    forged.generation += 1;
    let stale = block_notify::next_to_write(forged) == Err(NotifyError::StaleEndpoint);
    let ack2 = block_notify::confirm_acked(second, 2).is_ok();
    let replaced = block_notify::stats().replacements == 1;
    let empty = block_notify::next_to_write(second) == Ok(None);

    block_notify::reset_for_test();
    let fill_endpoint = match block_notify::install(endpoint(3, 0)) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            crate::log_fatal!("block-notify: 满队列端点失败 {:?}", error);
            return false;
        }
    };
    let mut fill_ok = true;
    for token in 0..block_notify::NOTIFY_SLOTS as u64 {
        fill_ok &= block_notify::publish(token, 1, 1, None, [0; 16]).is_ok();
    }
    let full_refused = block_notify::publish(99, 1, 1, None, [0; 16]) == Err(NotifyError::Full);
    let retained = block_notify::stats().retained == block_notify::NOTIFY_SLOTS;
    let first_intact = block_notify::next_to_write(fill_endpoint).ok().flatten().is_some_and(|r| r.seq == 1);
    let mut drain_ok = true;
    for seq in 1..=block_notify::NOTIFY_SLOTS as u64 {
        drain_ok &= block_notify::mark_published(fill_endpoint, seq).is_ok();
    }
    drain_ok &= block_notify::confirm_acked(fill_endpoint, block_notify::NOTIFY_SLOTS as u64).is_ok();

    block_notify::reset_for_test();
    let stats_before = crate::sync::stats();
    let _outer = crate::arch::x86_64::smp::CONTENTION_LOCK.lock();
    let rank_rejected = block_notify::install(endpoint(4, 0)) == Err(NotifyError::Locked);
    let stats_after = crate::sync::stats();
    let rank_clean = stats_after.order_violations == stats_before.order_violations
        && stats_after.reentrant_hits == stats_before.reentrant_hits;
    drop(_outer);
    block_notify::reset_for_test();

    let encoded = block_notify::NotifyRecord {
        seq: u64::MAX,
        token: 0x1122_3344_5566_7788,
        target: 0x8877_6655_4433_2211,
        result: -3,
        sectors_done: 0x1234_5678,
        diagnostic: [0xA5; 16],
    }
    .to_bytes();
    let layout_ok = encoded[0..8] == u64::MAX.to_le_bytes()
        && encoded[8..16] == 0x1122_3344_5566_7788u64.to_le_bytes()
        && encoded[24..28] == (-3i32).to_le_bytes()
        && encoded[32..48] == [0xA5; 16]
        && encoded[48..64] == [0; 16];
    let ok = s1 == Ok(1)
        && s2 == Ok(2)
        && publish1
        && mark1
        && ack1
        && duplicate_ack
        && bad_ack
        && replay
        && stale
        && ack2
        && replaced
        && empty
        && fill_ok
        && full_refused
        && retained
        && first_intact
        && drain_ok
        && rank_rejected
        && rank_clean
        && layout_ok;
    crate::log_info!(
        "block-notify: seq={:?}/{:?} 发布={} 确认={}/{} 替换重投={} 世代拒={} 已确认不重投={} 满队列拒={}/{} 首记录在={} 排空={} 锁秩={}/{} 布局={} ⇒ {}",
        s1, s2, publish1, ack1, duplicate_ack, replay, stale, empty,
        full_refused, retained, first_intact, drain_ok, rank_rejected, rank_clean, layout_ok, ok
    );
    if !ok {
        crate::log_fatal!("block-notify: 通知账本判据不成立");
    }
    ok
}

ktest!(KT_BLOCK_NOTIFY_CORE, t_block_notify_core);
