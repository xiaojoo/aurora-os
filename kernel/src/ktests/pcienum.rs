//! ADR-136：31 号 `SYS_PCI_ENUM` 的判据——用户态读 PCI 设备清单。
//!
//! 只测**约定面**（不测 PCI 扫描本身，`ktests/driver.rs` 已有大量判据）：
//! 1. 正向：缓冲够大 ⇒ 返回 `n = info.n`（全量拿到）、`next = 0`（游标走完）；
//! 2. **与内核表逐字段一致**：每条记录的 bdf/vendor/device/cfg08/hdr/bar0
//!    与 `pci::dev(i)` 同槽读数相同（第二台仪器 = 内核自己的只读快照接口，
//!    与 31 号走的是不同路径：一个走 syscall+用户拷贝，一个直读表）；
//! 3. 魔数/版本/记录长自洽（`APC1`/1/32）；
//! 4. **游标语义**：容量只够 1 条 ⇒ 返回 `n=1` 且 `next = 1`（>0）；
//!    从 `next` 续读能拿到剩余的（游标可续，不是每次都从头）；
//! 5. 负样本：`len < 32` ⇒ `-3`、`len > COPY_MAX` ⇒ `-3`、
//!    目标页只读 ⇒ `-2`、无身份时不能直接打（这条由 27 号同族判据覆盖，
//!    本用例在身份已建后调用，不单列）。
//!
//! **为什么与内核表对账不违反"别拿被测物自己对账"**：31 号走的是
//! syscall→记录打包→copy_to_user→用户缓冲→`copy_from_user` 读回这条**长路径**，
//! 每一环都可能错位/丢字段；`pci::dev(i)` 是**直读表**的另一条路径。
//! 两条路径共享的只有源数据本身（启动时扫好的 TABLE），这与 logread 的
//! "recent_tail 自己对账自己"不同——那一条连源读法都是同一份函数。

use crate::arch::x86_64::trap::TrapFrame;
use crate::ktest;
use crate::user::{self, syscall_dispatch};
use crate::{mm, pci, sched};

fn frame0() -> TrapFrame {
    TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    }
}

fn get_user(va: u64, dst: &mut [u8]) -> bool {
    matches!(user::copy_from_user(va, dst), Ok(n) if n == dst.len())
}

const REC: usize = 32;

fn t_pci_enum() -> bool {
    use crate::user::E_TOO_LONG;
    crate::log_info!("pcienum: 起（31 号的判据）");
    if sched::current_identity().is_none() {
        sched::init_boot_task();
    }
    let info = match pci::info() {
        Some(x) => x,
        None => {
            crate::log_fatal!("pcienum: PCI 表未初始化");
            return false;
        }
    };
    if info.n == 0 {
        crate::log_fatal!("pcienum: 本档下 PCI 表为空，判据无意义");
        return false;
    }

    // 用户缓冲：4 页（128 台 × 32 字节 = 4 KiB，正好是 COPY_MAX 的量级）。
    let Some(va) = mm::alloc_user_va_range(1) else {
        crate::log_fatal!("pcienum: 拿不到用户 VA");
        return false;
    };
    let Ok(frames) = mm::phys_alloc(0, mm::MOD_TEST) else {
        crate::log_fatal!("pcienum: 页帧分配失败");
        mm::release_va(va.0);
        return false;
    };
    let Ok(flags) = mm::PageFlags::new(true, false, true) else {
        crate::log_fatal!("pcienum: 页标志构造失败");
        mm::release_va(va.0);
        return false;
    };
    let Ok(page) = mm::map(va, frames, flags) else {
        crate::log_fatal!("pcienum: 用户页映射失败");
        mm::release_va(va.0);
        return false;
    };

    // ---- ① 正向：一次拿全量。
    let want = (info.n * REC).min(user::COPY_MAX);
    let mut f = frame0();
    f.rax = user::SYS_PCI_ENUM;
    f.rdi = va.0;
    f.rsi = 0; // 游标从头
    f.r10 = want as u64;
    syscall_dispatch(&mut f);
    let r = f.rax;
    let next = (r >> 32) as u32;
    let n = (r & 0xffff_ffff) as usize;
    let full_ok = r > 0 && n == info.n && next == 0;

    // ---- ② 与内核表逐字段一致 + ③ 魔数/版本/记录长自洽。
    let mut buf = [0u8; 4096];
    let got = n > 0 && get_user(va.0, &mut buf[..n * REC]);
    let mut fields_ok = got;
    let mut magic_ok = got;
    if got {
        for i in 0..n {
            let off = i * REC;
            let Some(rec) = buf.get(off..off + REC) else { fields_ok = false; magic_ok = false; break };
            let Some(d) = pci::dev(i) else { fields_ok = false; break };
            // 记录里 bdf@8、vendor|device@12、cfg08@16、hdr@20、bar0@24
            let rbdf = u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]);
            let rvd = u32::from_le_bytes([rec[12], rec[13], rec[14], rec[15]]);
            let rc08 = u32::from_le_bytes([rec[16], rec[17], rec[18], rec[19]]);
            let rhdr = u32::from_le_bytes([rec[20], rec[21], rec[22], rec[23]]);
            let rbar = u32::from_le_bytes([rec[24], rec[25], rec[26], rec[27]]);
            if rbdf != d.bdf
                || rvd != (u32::from(d.vendor) | (u32::from(d.device) << 16))
                || rc08 != d.cfg08
                || rhdr != u32::from(d.hdr)
                || rbar != d.bar0
            {
                fields_ok = false;
                break;
            }
            let m = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
            let ver = rec[4];
            // 长度字段在 6..10，但它与 8..12 的 bdf **共用 8..10 两字节**——
            // 这是 27 号 `proc_enum_record` 的既有形状（user.rs:1515/1516 同位），
            // 用户侧从来只把它当 16 位读。判据也按同一口径核低 16 位 = 32。
            let rl = u16::from_le_bytes([rec[6], rec[7]]);
            if m != 0x3150_4341 || ver != 1 || rl != REC as u16 {
                magic_ok = false;
                break;
            }
        }
    }

    // ---- ④ 游标语义：容量只够 1 条 ⇒ n=1 且 next=1；从 next 续读拿到其余。
    let mut cursor_ok = false;
    if info.n >= 2 {
        let mut f2 = frame0();
        f2.rax = user::SYS_PCI_ENUM;
        f2.rdi = va.0;
        f2.rsi = 0;
        f2.r10 = REC as u64; // 只装 1 条
        syscall_dispatch(&mut f2);
        let r2 = f2.rax;
        let n2 = (r2 & 0xffff_ffff) as usize;
        let next2 = (r2 >> 32) as u32;
        if n2 == 1 && next2 == 1 {
            // 从 next=1 续读，应拿到 info.n - 1 条且 next 归 0。
            let want3 = ((info.n - 1) * REC).min(user::COPY_MAX);
            let mut f3 = frame0();
            f3.rax = user::SYS_PCI_ENUM;
            f3.rdi = va.0;
            f3.rsi = next2 as u64;
            f3.r10 = want3 as u64;
            syscall_dispatch(&mut f3);
            let r3 = f3.rax;
            let n3 = (r3 & 0xffff_ffff) as usize;
            let next3 = (r3 >> 32) as u32;
            cursor_ok = n3 == info.n - 1 && next3 == 0;
        }
    } else {
        // 只有一台设备时游标格退化为"单条容量 ⇒ next=0"
        let mut f2 = frame0();
        f2.rax = user::SYS_PCI_ENUM;
        f2.rdi = va.0;
        f2.rsi = 0;
        f2.r10 = REC as u64;
        syscall_dispatch(&mut f2);
        let r2 = f2.rax;
        cursor_ok = (r2 & 0xffff_ffff) as usize == 1 && (r2 >> 32) == 0;
    }

    // ---- ⑤ 负样本：len < 32 ⇒ -3
    let mut f4 = frame0();
    f4.rax = user::SYS_PCI_ENUM;
    f4.rdi = va.0;
    f4.rsi = 0;
    f4.r10 = (REC - 1) as u64;
    syscall_dispatch(&mut f4);
    let short_ok = f4.rax == E_TOO_LONG;

    // ---- ⑥ 负样本：len > COPY_MAX ⇒ -3
    let mut f5 = frame0();
    f5.rax = user::SYS_PCI_ENUM;
    f5.rdi = va.0;
    f5.rsi = 0;
    f5.r10 = (user::COPY_MAX + 1) as u64;
    syscall_dispatch(&mut f5);
    let long_ok = f5.rax == E_TOO_LONG;

    // ---- ⑦ 负样本：目标页只读 ⇒ -2。
    //     用 USER_R 映射一页（`validate_range(.., writable=true)` 必然拒）。
    let ro_ok = match (mm::alloc_user_va_range(1), mm::phys_alloc(0, mm::MOD_TEST)) {
        (Some(va2), Ok(fr)) => match mm::map(va2, fr, mm::PageFlags::USER_R) {
            Ok(ro) => {
                let mut f6 = frame0();
                f6.rax = user::SYS_PCI_ENUM;
                f6.rdi = va2.0;
                f6.rsi = 0;
                f6.r10 = REC as u64;
                syscall_dispatch(&mut f6);
                let ok = f6.rax == crate::user::E_FAULT;
                drop(ro);
                mm::release_va(va2.0);
                ok
            }
            Err(_) => {
                mm::release_va(va2.0);
                false
            }
        },
        (Some(va2), Err(_)) => {
            mm::release_va(va2.0);
            false
        }
        (None, _) => false,
    };

    drop(page);
    mm::release_va(va.0);

    let ok = full_ok && fields_ok && magic_ok && cursor_ok && short_ok && long_ok && ro_ok;
    crate::log_info!(
        "pcienum: 判据={} 全量={} 字段一致={} 魔数自洽={} 游标续读={} 短长拒={} 超长拒={} 只读拒={}",
        ok, full_ok, fields_ok, magic_ok, cursor_ok, short_ok, long_ok, ro_ok
    );
    ok
}

ktest!(KT_PCI_ENUM, t_pci_enum);
