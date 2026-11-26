#![no_std]
#![no_main]

use aurora_user_runtime as rt;
use core::sync::atomic::{AtomicU64, Ordering};

const CONFIG_MAGIC: u32 = 0x424e_4f54;
const CONFIG_VERSION: u32 = 1;
const CONFIG_BYTES: usize = 48;
const RING_MAGIC: u32 = 0x4e4f_5446;
const RING_VERSION: u32 = 1;
const RING_HEADER: usize = 32;
const RING_RECORD: usize = 64;
const RING_SLOTS: usize = 32;
const OFF_PRODUCER: usize = 16;
const OFF_CONSUMED: usize = 24;

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    // SAFETY: 调用方只传已核长的 header/args/record 与常量偏移，read_unaligned 不要求对齐。
    unsafe { core::ptr::read_unaligned(bytes.as_ptr().add(offset) as *const u32) }
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    // SAFETY: 同 u32_at；8 字节读取落在已核长的定长缓冲内。
    unsafe { core::ptr::read_unaligned(bytes.as_ptr().add(offset) as *const u64) }
}

#[inline(never)]
fn panic_exit() -> ! {
    rt::exit(3);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    panic_exit();
}

unsafe fn run(si_va: u64) -> u32 {
    // SAFETY: si_va 是 process_start 校验并映射的 StartupInfo 页。
    let Some(args) = (unsafe { rt::args_at(si_va) }) else { return 2 };
    if args.len() < CONFIG_BYTES || u32_at(args, 0) != CONFIG_MAGIC || u32_at(args, 4) != CONFIG_VERSION {
        return 2;
    }
    let ring_va = u64_at(args, 8);
    let capacity = u32_at(args, 16) as usize;
    let record_bytes = u32_at(args, 20) as usize;
    let mode = u32_at(args, 24);
    if ring_va == 0 || ring_va % 4096 != 0 || capacity != RING_SLOTS || record_bytes != RING_RECORD || mode > 1 {
        return 2;
    }
    // SAFETY: 同一 StartupInfo 页，角色表由内核回填且读取期间不解映射。
    let Some(self_thread) = (unsafe { rt::find_role(si_va, rt::ROLE_SELF_THREAD) }) else { return 2 };
    let base = ring_va as *const u8;
    let mut header = [0u8; RING_HEADER];
    // SAFETY: ring_va 是内核映射的一页 user+RW，头部 32 字节在页内。
    unsafe { core::ptr::copy_nonoverlapping(base, header.as_mut_ptr(), RING_HEADER) };
    if u32_at(&header, 0) != RING_MAGIC
        || u32_at(&header, 4) != RING_VERSION
        || u32_at(&header, 8) as usize != capacity
        || u32_at(&header, 12) as usize != record_bytes
    {
        return 2;
    }
    // SAFETY: 两个字段按 8 对齐且同页；生产/消费各只访问自己的原子量。
    let producer = unsafe { &*((ring_va + OFF_PRODUCER as u64) as *const AtomicU64) };
    let consumed = unsafe { &*((ring_va + OFF_CONSUMED as u64) as *mut AtomicU64) };
    for _ in 0..60_000 {
        let published = producer.load(Ordering::Acquire);
        let acked = consumed.load(Ordering::Relaxed);
        if published > acked {
            let index = (acked % capacity as u64) as usize;
            let offset = RING_HEADER + index * record_bytes;
            let mut record = [0u8; RING_RECORD];
            // SAFETY: index<capacity=32，offset+64 落在同一页 2080 字节环内。
            unsafe { core::ptr::copy_nonoverlapping(base.add(offset), record.as_mut_ptr(), RING_RECORD) };
            if u64_at(&record, 0) != acked + 1 {
                return 2;
            }
            if mode == 1 {
                let target: u64;
                // SAFETY: lea 只算本程序函数地址；RIP 相对调用避免高基址的 R_X86_64_32S。
                unsafe {
                    core::arch::asm!("lea {0}, [rip + {sym}]", out(reg) target, sym = sym panic_exit,
                        options(nomem, nostack, preserves_flags));
                    core::arch::asm!("call {0}", in(reg) target, options(nostack, noreturn));
                }
            }
            consumed.store(acked + 1, Ordering::Release);
            return 0;
        }
        let _ = rt::sleep_ms(self_thread, 1);
    }
    4
}

#[no_mangle]
pub extern "C" fn _start(si_va: u64) -> ! {
    // SAFETY: si_va 由 process_start 校验并映射；ring_va 来自同页 args，由内核映射一页 user+RW。
    let code = unsafe { run(si_va) };
    rt::exit(u64::from(code));
}
