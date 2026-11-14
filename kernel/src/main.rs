//! Aurora OS 内核 · 第一条垂直切片（手册 §14 的 M1）
//!
//! 链路：Limine 进入 -> 串口自检 -> 校验启动信息 -> 自建 GDT/IDT/TSS ->
//! 受控 #PF 并异常返回 -> 跑 `.ktests` 表 -> 用 isa-debug-exit 的退出码交付判定。
//!
//! 这一条切片同时验掉文档里六个“写了但没测过”的假设：
//! base revision 协商、HHDM 偏移不可硬编码、RSDP 的地址语义（rev4+ 虚拟 / rev3 物理）、
//! 异常栈与 CR2 取值时机、`.ktests` 段注册、以及退出码判定契约本身。

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

#[global_allocator]
static GLOBAL: heap::AuroraGlobal = heap::AuroraGlobal;

mod acpi;
mod arch;
mod ahci;
mod boot_guard;
mod clock;
mod crash;
mod driver;
mod elf;
mod filesystem;
mod heap;
mod hooks;
#[cfg(feature = "handles")]
mod handle;
mod hw;
#[cfg(feature = "framebuffer")]
mod frame;
#[cfg(feature = "framebuffer")]
mod fbcon;
#[cfg(feature = "ps2-kbd")]
mod kbd;
#[cfg(feature = "ps2-mouse")]
mod mouse;
mod irq;
mod exit;
mod ktest;
mod ktests;

// T0.1：跨文件引用保持 `crate::HELLO_ELF` / `crate::P7_CALLS` / `crate::drain_reap` 可用。
pub(crate) use ktests::common::{HELLO_ELF, P7_CALLS, drain_reap};
#[cfg(feature = "fat32-probe")]
pub(crate) use ktests::fs::{FAT_PORT_A, FAT_PORT_B};
mod limine;
mod mm;
mod proc;
mod sched;
mod serial;
mod sign;
mod sync;
mod resource;
mod user;
mod pci;
mod state_store;
mod watchdog;
mod tsc;
mod virtio;
mod vmo;

use crate::arch::x86_64::{apic, cpu, cpuid, smp, trap};
use core::cell::UnsafeCell;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

/// 供 #PF 探针使用的地址，运行期算出来并**验证过确实未映射**
pub(crate) static PROBE_ADDR: AtomicU64 = AtomicU64::new(0);

/// 多处理器响应的快照。换页表之后响应结构就在 bootloader 可回收内存里，
/// 那些帧随时可能被我们自己分配走，所以**必须在切换前拷出来**（与 memmap 同一条理由）。
#[derive(Clone, Copy)]
struct MpSlot(Option<limine::Mp>);
struct MpCell(UnsafeCell<MpSlot>);
// SAFETY: 单核启动阶段写入一次，之后只读（与 mm::State 同一条前提）
unsafe impl Sync for MpCell {}
static MP_SNAP: MpCell = MpCell(UnsafeCell::new(MpSlot(None)));

#[inline]
fn mp_store(m: limine::Mp) {
    // SAFETY: 见 MpCell
    unsafe { (*MP_SNAP.0.get()) = MpSlot(Some(m)) };
}

pub fn mp_snapshot() -> Option<limine::Mp> {
    // SAFETY: 写入发生在 kmain 早期、任何用例之前，此后本文件不再写
    unsafe { (*MP_SNAP.0.get()).0 }
}

/// 切换页表前落下来的 RSDP 虚地址（0 表示 bootloader 没给）。
/// 不能等切换后再读启动信息：它位于可回收内存，帧被分配走之后就是别人的数据。
pub(crate) static RSDP_VA: AtomicU64 = AtomicU64::new(0);

#[panic_handler]
fn on_panic(info: &PanicInfo) -> ! {
    // panic=abort（ADR-005）：这里是终点，不是可恢复错误。
    // 只打印位置：PanicInfo::message() 返回 PanicMessage，在 no_std 下没有可移植的
    // payload 读法，凭空包一层 Display 只会打出骗人的内容。
    let loc = info.location().map_or("<unknown location>", |l| l.file());
    crate::log_fatal!("kernel panic at {}", loc);
    exit::finish(exit::Code::ExceptionFatal)
}

/// 异常里判定为致命的出口：打印现场后给独立退出码（ExceptionFatal=39）。
pub fn exit_fatal_from_exception(frame: &trap::TrapFrame) -> ! {
    // 无锁现场记录的第一格：**在任何串口写、任何块设备写之前**。抓到的那次挂死 RIP
    // 落在 `dump_site` 里而串口上没有 `[fatal]`——那一行有没有出去从此不再是唯一证据。
    crash::mark_fatal(
        crash::STAGE_FATAL_ENTER,
        0,
        Some(crash::Site {
            vector: frame.vector as u32,
            error_code: frame.error_code as u32,
            cr2: frame.cr2,
            rip: frame.rip,
            rsp: frame.rsp,
            rbp: frame.rbp,
        }),
    );
    // P3 的第二条路径：**在打现场之前**取时间。dump_frame 要吐几百字节，而串口是按字节
    // 忙等的，把它算进"终止路径延迟"就等于让日志长度冒充处置成本。
    // 也就是说这里量的是"判定到可以停机"，崩溃现场打印的成本另有一条字节数可以换算。
    // 槽位在这里读一次是允许的：这条路径马上就要停机，不在任何被测区间之内。
    let cpu = cpu::self_slot();
    let cost = tsc::now().wrapping_sub(trap::entry_tsc_of(cpu));
    trap::p3_record_fatal(cpu, cost);
    trap::dump_frame(frame);
    crash::dump_site(
        crash::Site {
            vector: frame.vector as u32,
            error_code: frame.error_code as u32,
            cr2: frame.cr2,
            rip: frame.rip,
            rsp: frame.rsp,
            rbp: frame.rbp,
        },
        cpu,
    )
    .ok();
    exit::finish(exit::Code::ExceptionFatal)
}

/// 内核入口。Limine 在完成长模式、分页、higher-half 映射后直接跳到这里，
/// 交接状态由协议规定（IF=0、IDT 未定义、FS/GS base=0、栈 ≥64KiB）。
#[no_mangle]
pub extern "C" fn kmain() -> ! {
    // ---- Stage0：串口。先自证能收发，否则后面每条“成功”日志都是假证据
    serial::init();
    if !serial::is_ready() {
        // 这里已经不可能输出原因了，只能靠独立退出码把“串口是哑的”和其它失败分开
        exit::finish(exit::Code::BootInvalid);
    }
    crate::log_info!("boot-ok: aurora stage0 serial up (com1 0x3f8)");
    tsc::stage("serial");

    // ---- Stage1：校验启动信息
    if !limine::BASE_REVISION.is_supported() {
        exit::boot_invalid("bootloader rejected requested base revision 5");
    }
    match limine::BASE_REVISION.negotiated() {
        Some(v) => crate::log_info!("limine: negotiated base revision = {}", v),
        None => crate::log_warn!("limine: base revision tag not rewritten (impl is pre-rev3 behaviour)"),
    }

    let Some(info) = limine::collect() else {
        exit::boot_invalid("missing HHDM or memory map response");
    };
    crate::log_info!("hhdm offset = {:#x}", info.hhdm_offset);
    crate::log_info!("memmap entries = {}", info.mmap_entries.len());
    match info.bootloader_name {
        Some(n) => crate::log_info!("bootloader = {}", n),
        None => crate::log_warn!("bootloader did not provide its name/version"),
    }

    let feats = cpuid::detect();
    if let Some(missing) = feats.missing_required() {
        // 必需项缺失就拒绝启动（§5.1），并给独立退出码，不与“测试失败”混在一起
        crate::log_fatal!("required CPU feature missing: {}", missing);
        exit::finish(exit::Code::BootInvalid);
    }
    crate::log_info!("cpu: nx={} smep={} smap={} pcid={} x2apic={} xsave={} rdrand={} tsc_inv={}", feats.nx, feats.smep, feats.smap, feats.pcid, feats.x2apic, feats.xsave, feats.rdrand, feats.tsc_inv);
    crate::log_info!("tsc: rdtscp_available={}", tsc::rdtscp_available());
    tsc::stage("bootinfo+cpu");

    // ---- Stage2：自己的 GDT/TSS/IDT。协议保证交接时 IDT 状态未定义、FS/GS base = 0，
    // 所以这一步不做，任何异常都是三重故障。
    trap::init_cpu_tables(cpu::BSP_SLOT);
    crate::log_info!("cpu tables: gdt/idt/tss loaded for bsp slot 0, 256 gates installed");
    tsc::stage("idt");

    // ---- Stage2：页表接管（M2）。这一步**不返回**：它换栈后尾跳进 after_switch。
    // 因此凡是在切换之后还要用的启动信息，都必须先落到静态量里——`info` 住在旧栈上，
    // 切换后它就是悬垂引用；而 memmap 原始结构位于可回收内存，一旦该帧被分配走也会被复用。
    RSDP_VA.store(info.rsdp.unwrap_or(0), Ordering::Relaxed);
    // MP 必须在 take_over 之前读并拷出来：见 MpSlot 的注释
    if let Some(m) = info.mp {
        crate::log_info!(
            "limine: mp present cpus={} bsp_lapic={} x2apic={} all_goto_null={} ids={:?}",
            m.cpu_count, m.bsp_lapic_id, m.x2apic_enabled, m.all_goto_null, &m.lapic_ids[..m.n]
        );
        mp_store(m);
    } else {
        crate::log_warn!("limine: MP request not supported (no response) -- M3b cannot start APs from this boot");
    }
    if let Err(e) = mm::take_over(&info, after_switch, 0) {
        // boot_invalid 是 -> !，原因必须先打出来
        crate::log_fatal!("mm::take_over failed: {:?}", e);
        exit::boot_invalid("mm take_over failed");
    }
    unreachable!()
}

/// 页表切换完成后运行在自己的栈上。`_` 是续体参数，留着以便将来传启动句柄。
extern "C" fn after_switch(_: usize) -> ! {
    // ADR-040：先把调度器实现装进 arch 的回调表，早于 AP 释放与任何定时器窗口。
    sched::install_arch_hooks();
    // P4b：等待队列的回调表（ADR-053 的反转），与 arch hooks 同一时机装好
    sched::install_wait_ops();
    // Task C（V1.0 §14）：启动编排按阶段函数组织；顺序与日志契约不变。
    stage_memory();
    stage_cpu_protections();
    stage_probe_addr();
    stage_acpi_and_pci();
    // S6c：键盘在 ACPI/MADT 之后开（要查 IRQ1 的 GSI），在 ktests 之前（用例可能要用它）
    #[cfg(feature = "ps2-kbd")]
    stage_keyboard();
    #[cfg(feature = "ps2-mouse")]
    stage_mouse();
    stage_fault_injections();
    stage_storage_guard_crash();
    stage_signature_check();
    // S6a：帧缓冲开在 ktests **之前**——图案一旦画上就再没人动显存，
    // 宿主机要在 QEMU 退出之前拿到 screendump，这个位置等于给对账留整个 ktests 阶段的余量。
    #[cfg(feature = "framebuffer")]
    stage_framebuffer();
    run_ktests_and_finish()
}

/// S6b-2：把 ktests 的结果**真画到屏幕上**，并当场演示一次滚动，然后落冻结契约。
///
/// **为什么放在判定之前、而且这一档要配 `resident-init` 一起跑**：冻结标记一旦打完，
/// 剩下的串口输出只有 `verdict:` 与 `qemu-exit=`（几十字节，几毫秒），宿主机根本来不及
/// 轮询到标记再发 QMP `screendump`。所以取证跑用 `framebuffer,handles,resident-init`：
/// 判定之后系统停在那儿等 init（§237 判据①已经证过那一格），宿主机就有了不限时的窗口。
/// **不用 socket 输入通道**——那条路是 §237 记着的已知坏格子。
///
/// 滚动是**真搬像素**（`scroll_up`：正文区逐像素上移一个字符行），不是只改行号。
/// 判据形状由 `fbcon::Term::fill_body` 的定义决定：正文第 r 行第 c 格是 `'A' + ((r*cols+c) % 26)`；
/// 滚一行之后，屏幕上的第 r 行应当等于**滚动前的第 r+1 行**。宿主机照这条公式独立复算。
#[cfg(feature = "framebuffer")]
fn stage_fbcon_tail(total: usize, failed: usize, table_invalid: bool) {
    // S6g：`fbcon-live` 是**终端**，不是要取样的测试图案：
    // 这条路上不画 A..Z 填充图案、也不落冻结闸门，否则画面会在 init 等待窗口结束后
    // 被一张测试图案盖掉、并且从此再也不刷新（终端就没法用了）。
    #[cfg(feature = "fbcon-live")]
    {
        crate::log_info!("fbcon-live: 终端模式 ⇒ 跳过测试图案与冻结闸门（画面交给实时重画）");
    }
    #[cfg(not(feature = "fbcon-live"))]
    fbcon_test_pattern(total, failed, table_invalid);
}

/// 取样式的一帧：填充图案 + 演示一次滚动 + 镜像最后几行 + 落冻结闸门（§242/§245 的判据靶子）。
#[cfg(all(feature = "framebuffer", not(feature = "fbcon-live")))]
fn fbcon_test_pattern(total: usize, failed: usize, table_invalid: bool) {
    let Ok(f) = crate::frame::Frame::init() else {
        crate::log_warn!("fbcon: tail 阶段拿不到帧缓冲");
        return;
    };
    let Some(term) = crate::fbcon::Term::new(&f) else {
        crate::log_warn!("fbcon: 几何放不下终端栅格（至少要到 {}x{}）",
                         crate::fbcon::CELL_W * 8, crate::fbcon::CELL_H * (crate::fbcon::BAND_ROWS + 2));
        return;
    };
    let (cols, rows) = term.dims();
    let body = term.fill_body(&f);

    let line = crate::fbcon::BAND_TEXT;
    let drew = term.print_scrolled(&f, &line);
    crate::log_info!("fbcon: 滚动一次 末行画出格数={}", drew);
    // S6b-3：把这一跑攒下的日志正文**最后几行**滚动画上去。单独一档 `fbcon-mirror` 是有意的：
    // 它会继续滚动，会顶掉 §242"滚动恰好一次"那条已提交的像素判据 ⇒ 两个判据必须各自可复现。
    #[cfg(feature = "fbcon-mirror")]
    {
        const MIRROR_LINES: usize = 8;
        let (total, drawn) = crate::fbcon::drain_and_draw(&term, &f, MIRROR_LINES);
        crate::log_info!(
            "fbcon: 镜像 旁挂字节={} 现存字节={} 窗口行数={} 画上={} 预算={} 绕过={}",
            crate::serial::mirror_total(), crate::serial::mirror_len(),
            total, drawn, MIRROR_LINES, crate::serial::mirror_wrapped()
        );
    }
    let (band_row, wrote) = term.freeze_band(&f);
    let (bx, by) = term.band_origin();
    crate::log_info!(
        "fbcon: 栅格 {}x{} 正文行={} 冻结带首行像素=({},{}) 带宽字符={} 文本=\"{}\" 用例 总={} 败={} 表无效={}",
        cols, rows, body, bx, by, wrote, line, total, failed, table_invalid
    );
    let before = f.get(bx, by).unwrap_or(u32::MAX);
    term.print_line(&f, band_row, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
    let after = f.get(bx, by).unwrap_or(u32::MAX);
    crate::log_info!("fbcon: 冻结后再写无效={}（带首像素 {:#010x} vs {:#010x}）", before == after, before, after);
    crate::log_info!("fbcon: 已冻结 带首像素=({},{}) 字宽={} 字高={}", bx, by, crate::fbcon::CELL_W, crate::fbcon::CELL_H);
}

/// S6c：开 PS/2 键盘。失败**必须在串口上看见具体成因**——"键盘不响"和"根本没去开"
/// 是两种完全不同的现场，合成一句 warn 就把下一次排查的时间花掉了。
#[cfg(feature = "ps2-kbd")]
fn stage_keyboard() {
    let Some(m) = acpi::summary().and_then(|s| s.madt) else {
        crate::log_warn!("kbd: 没有 MADT，IRQ1 无从路由");
        return;
    };
    match kbd::enable(&m) {
        Ok(i) => crate::log_info!(
            "kbd: 已开 IRQ={} 环容量={} 命令字节=0x{:02X} 口开={} 中断允许={} 设备ACK=0x{:02X} 预排={} 字节",
            1,
            kbd::ring_cap(),
            i.cmd_byte,
            i.kbd_enabled,
            i.irq_enabled,
            i.dev_ack,
            i.preflush
        ),
        Err(e) => crate::log_warn!("kbd: 开启失败 —— {:?}", e),
    }
}

/// S6o：开鼠标（i8042 第二口 + IRQ12），并把指针放在屏幕中心。
#[cfg(feature = "ps2-mouse")]
fn stage_mouse() {
    let Some(m) = acpi::summary().and_then(|s| s.madt) else {
        crate::log_warn!("mouse: 没有 MADT，IRQ12 无从路由");
        return;
    };
    let Some(fb) = crate::limine::framebuffer() else {
        crate::log_warn!("mouse: 没有帧缓冲信息，指针位置无从限定");
        return;
    };
    match crate::mouse::enable(&m, fb.width as u32, fb.height as u32) {
        Ok(i) => crate::log_info!(
            "mouse: 已开 IRQ={} 命令字节=0x{:02X}->0x{:02X} 设备ACK=0x{:02X} 屏幕={}x{}",
            crate::mouse::MOUSE_IRQ,
            i.cmd_before,
            i.cmd_after,
            i.dev_ack,
            fb.width,
            fb.height
        ),
        Err(e) => crate::log_warn!("mouse: 开启失败 —— {:?}", e),
    }
}

/// S6a：把帧缓冲开起来、报出几何与两处地址、画一张宿主机能独立复算的图案。
///
/// **串口仍然是权威判据通道**：这一段只**新增**日志行，一个既有字节的顺序都不改
/// （判定表那些行读的仍是串口）。画面本身在这段里不当判据用——它由宿主机侧的
/// QMP screendump 独立取证（BACKLOG §240），两边各自算同一张图案，不互相抄。
#[cfg(feature = "framebuffer")]
fn stage_framebuffer() {
    use crate::frame::Frame;
    let f = match Frame::init() {
        Ok(f) => f,
        Err(e) => {
            // 不吞错、也不"没有画面就当没事"：这一档没成立就要在串口上看见具体成因。
            crate::log_warn!("frame: 帧缓冲不可用 —— {:?}", e);
            return;
        }
    };
    let (w, h, pitch) = f.geom();
    let (pa, len, lva, ours) = f.addrs();
    let (is_hhdm, is_ours, is_mapped_here) = f.limine_relation();
    crate::log_info!(
        "frame: 几何 宽={} 高={} pitch={} bpp=32 掩码(尺寸,移位)=红{:?} 绿{:?} 蓝{:?}",
        w, h, pitch, f.masks()[0], f.masks()[1], f.masks()[2]
    );
    // 这一行是本片真正要的那个数：Limine 给的地址与 HHDM+pa、与我们自己映射的 VA 各是什么关系。
    // 不写死结论——先把它打出来，让"Limine 已给 framebuffer 能直接用"这句话被实测处置。
    crate::log_info!(
        "frame: 地址 memmap基址={:#x} 长度={:#x} limine={:#x} 我们的窗口={:#x} limine==HHDM+pa={} limine==我们的窗口={} 在我们页表里映着={}",
        pa, len, lva, ours, is_hhdm, is_ours, is_mapped_here
    );
    // `fbcon-live` 是**终端**：不画测试图案。它会在开场被终端清屏覆盖，
    // 但在那之前（ktests 与 init 启动的几秒里）用户看到的就是下面那三条红绿蓝色带
    // —— 用户两次截图都在问这件事（§250/§251）。取样式变体（framebuffer / fbcon-mirror）照旧画。
    #[cfg(feature = "fbcon-live")]
    {
        crate::log_info!("frame: 终端模式 ⇒ 不画测试图案（几何与地址仍然照报）");
        return;
    }
    #[cfg(not(feature = "fbcon-live"))]
    if let Err(e) = f.draw_test_pattern() {
        crate::log_warn!("frame: 画图案失败 —— {:?}", e);
        return;
    }
    // 写后读回：只证明"我们写的字节还在我们映射的窗口里"，**不**证明设备显示出来了。
    // 比的是 packed 后的原生像素值——拿 24 位期望值直接比 read32 会把量具错读成产品错。
    let mut bad = 0usize;
    let pts = f.samples();
    for (name, x, y, want) in &pts {
        let exp = f.packed(*want);
        let got = f.get(*x, *y).unwrap_or(u32::MAX);
        if got != exp {
            bad += 1;
            crate::log_warn!("frame: 采样 {} ({},{}) 读回={:#010x} 期望={:#010x}", name, x, y, got, exp);
        }
    }
    crate::log_info!(
        "frame: 图案已画 采样点数={} 读回不符点数={} —— 这一行只证窗口自洽，画面真伪由宿主机 screendump 对账",
        pts.len(),
        bad
    );


}

/// Stage2a/2b：页表接管后的内存统计与内核堆。
fn stage_memory() {
    mm::mark_switched();
    if let Err(e) = mm::init_allocator() {
        crate::log_fatal!("mm::init_allocator 引导失败 {:?}（FrameInfo 元数组分不出）", e);
        exit::boot_invalid("mm init_allocator failed");
    }
    if !mm::is_ready() {
        crate::log_fatal!("mm not ready after takeover");
        exit::finish(exit::Code::BootInvalid);
    }
    // P1b：FrameInfo 已接管分配/释放（位图退化为引导期临时量）。引导期那次的逐帧对账
    // 已在 P1a 证红；接管后的正确性由 ktest 等价判据与 fault-double-free 链盯，不再拿
    // 已经停更的位图做影子对账（那会在第一次 alloc 后必然不符）。
    crate::log_info!("mm: frames total={} free={} max_phys={:#x}", mm::total_frames(), mm::free_frames(), mm::max_phys());
    let (fi_frames, fi_bytes) = mm::frame_info_size();
    crate::log_info!("mm: frame_info 帧条目={} 字节={} 接管=true（P1b，refcnt 驱动分配）", fi_frames, fi_bytes);
    crate::log_info!("mm: usable memory = {} MiB over {} regions", mm::usable_bytes() / (1024 * 1024), mm::region_count());
    crate::log_info!("mm: bootloader regions held back = {} MiB (AP park area; reclaim is explicit, M3b)", mm::boot_reclaimable_bytes() / (1024 * 1024));
    tsc::stage("mm-takeover");

    // 无锁现场记录表的物理地址，必须在**尽可能早**的地方说出来：宿主机只有拿到它，
    // 才能在挂死那一跑用 `pmemsave` 把表读回。译不出来就明说"取证只剩寄存器"，
    // 不许静默——静默的下一次挂会让人以为探针在位。
    match crash::record_phys() {
        Some(p) => crate::log_info!(
            "fatalrec: 物理={:#x} cpu数={} 每cpu字段={} 字节={}",
            p,
            cpu::MAX_CPUS,
            crash::FATAL_FIELDS,
            cpu::MAX_CPUS * crash::FATAL_FIELDS * 8
        ),
        None => crate::log_warn!("fatalrec: 物理=译不出（页表未就绪？）挂死取证只剩寄存器"),
    }

    // ---- Stage2b：内核堆（M2-b）。堆未就绪时 GlobalAlloc 会返回空指针，
    // 所以在任何可能分配的路径之前先把它建起来。
    match heap::init() {
        Ok(chunks) => crate::log_info!("heap: window ready, pre-mapped {} chunks ({} KiB)", chunks, chunks * 4),
        Err(e) => {
            crate::log_fatal!("heap::init failed: {:?}", e);
            exit::finish(exit::Code::BootInvalid);
        }
    }
    tsc::stage("heap");
}

/// Stage2c：SMEP/SMAP 必需项与 BSP 的 #DF guard 栈。
fn stage_cpu_protections() {
    // ---- Stage2c：把 BSP 的 #DF 栈从 .bss 那一页换成**带 guard page** 的栈（§6.4）。
    // 顺序要求：MM 就绪之后（要走分配器和页表）、任何 AP 释放之前（IST1 是 per-CPU 的）。
    // 换的只是 TSS 里的一个字段，IDT/GDT 不用重装——硬件每次取 IST 都读 TSS。
    // ---- Stage2c：SMEP/SMAP（§5.1 R17 的 M4 必需项）。开完必须读回来，
    // 因为"设了位"与"这位真的生效"是两件事；cpuid 说支持而 CR4 读不回两位，就是启动失败。
    let (smep_on, smap_on, cr4) = cpu::enable_user_protections();
    // 注入点放在这里而不是别处：这条判据要能动，就必须有人**真的**看到"位没开成"。
    // 见 `tools/aurora.py test` 的 BOOT-INVALID 那一行。
    #[cfg(feature = "fault-no-smap")]
    cpu::clear_smap_for_test();
    let feat = cpuid::detect();
    let (act_smep, act_smap) = cpu::user_protections_active();
    crate::log_info!(
        "cr4: smep={} smap={} cr4={:#x} 复核=({},{}) cpuid=({},{})",
        smep_on, smap_on, cr4, act_smep, act_smap, feat.smep, feat.smap
    );
    // §5.1（R17）把 SMEP/SMAP 列为**必需项**，必需项就得回答"没开成功怎么办"。
    // 答案是 BOOT-INVALID(37)：这两条保护的是"内核不许执行用户页 / 不许随手读用户页"，
    // 带着半开的边界继续跑，M4 之后所有隔离承诺都是空的——这不是可以降级的运行时故障，
    // 是机器不满足前提（§9.2 把"前提不满足"与"故障"分成两级，就是因为处置方式不同：
    // 故障要分级止损，前提不满足要**不启动**）。判据用两位：CPUID 说支持 **且** CR4 读回为 1。
    if !(feat.smep && feat.smap && act_smep && act_smap) {
        crate::log_fatal!(
            "SMEP/SMAP 必需项未满足：cpuid=({},{}) cr4=({},{}) —— 不启动",
            feat.smep, feat.smap, act_smep, act_smap
        );
        exit::finish(exit::Code::BootInvalid);
    }

    match trap::install_exception_stack(cpu::BSP_SLOT) {
        Ok(si) => crate::log_info!(
            "exstack bsp: guard={:#x} stack=[{:#x}..{:#x}) ist1={:#x} guard_mapped={}",
            si.guard_va, si.stack_lo, si.stack_hi, si.top, mm::is_mapped(si.guard_va)
        ),
        Err(e) => crate::log_fatal!("exstack bsp: 装不上（继续用 .bss 那一页，没有 guard page）: {:?}", e),
    }
}

/// Stage3：用真实页表挑一个确定未映射的探针地址。
fn stage_probe_addr() {
    // ---- Stage3：探针地址现在按**真实页表**判定，不再靠算术推算
    match pick_probe_addr() {
        Some(a) => {
            PROBE_ADDR.store(a, Ordering::Relaxed);
            crate::log_info!("probe address (page-table-verified unmapped) = {:#x}", a);
        }
        None => crate::log_fatal!("no validatable probe address; #PF probe will fail"),
    }
    // 把登记表条数打出来：堆窗口和探针地址必须各占一条，少一条就说明有人在绕过登记发放 VA
    crate::log_info!("mm: VA reservations in force = {}", mm::reservation_count());
    tsc::stage("probe");
}

/// Stage3b/M5-a：ACPI 固定表与 PCI 枚举的只读快照。
fn stage_acpi_and_pci() {
    // ---- Stage3b：ACPI 固定布局表（M2-c / ADR-012a）。放在堆建好之后：解析要用的
    // 缓冲区都是栈上的，但日志格式化会走全局分配器，顺序反了就是"堆未就绪 -> 空指针"。
    match acpi::init(RSDP_VA.load(Ordering::Relaxed)) {
        Ok(s) => crate::log_info!(
            "acpi: root={} tables={} checksum_fail={} unmapped_reads={} rsdp_rev={} rsdp_va={:#x} root_phys={:#x}",
            if s.used_xsdt { "XSDT" } else { "RSDT" },
            s.tables, s.checksum_failures, s.unmapped_reads, s.rsdp_revision, s.rsdp_va, s.root_phys
        ),
        Err(e) => crate::log_fatal!("acpi::init failed: {:?}", e),
    }
    if let Some(s) = acpi::summary() {
        if let Some(m) = s.madt {
            crate::log_info!(
                "acpi: madt lapic_base={:#x} pcat_compat={} cpu={} (enabled {}) ioapic={} overrides={} lapic_ids={:?} acpi_ids={:?}",
                m.lapic_base, m.pcat_compat, m.cpu_total, m.cpu_enabled, m.n_ioapic, m.n_overrides,
                &m.lapic_ids[..m.n_ids], &m.acpi_ids[..m.n_ids]
            );
        }
        if let Some(f) = s.fadt {
            crate::log_info!("acpi: fadt rev={} len={} boot_arch={:?} hw_reduced={:?}", f.revision, f.length, f.boot_arch, f.hw_reduced);
        }
        crate::log_info!(
            "acpi: mcfg={:?} bus={}..{} dmar_haw={:?} dmar_flags={:?} ivrs={}",
            s.mcfg_base, s.mcfg_bus_start.unwrap_or(0), s.mcfg_bus_end.unwrap_or(0), s.dmar_host_address_width, s.dmar_flags, s.ivrs_present
        );
    }

    // ---- M5-a：PCI 配置空间与设备枚举（§8.7）。放在 ACPI 之后：ECAM 的基址来自 MCFG。
    // 只读配置空间、只映射一段 MMIO，不认领任何中断，所以它对启动判定与性能基线的影响
    // 只体现在多出来的那几行日志上。
    let (mcfg_base, mcfg_bs, mcfg_be) = acpi::summary()
        .map(|s| (s.mcfg_base, s.mcfg_bus_start.unwrap_or(0), s.mcfg_bus_end.unwrap_or(0)))
        .unwrap_or((None, 0, 0));
    match pci::init(mcfg_base, mcfg_bs, mcfg_be) {
        pi => crate::log_info!(
            "pci: backend={} n={} absent={} va={:#x} truncated={}",
            match pi.backend {
                pci::Backend::Ecam => "ECAM",
                pci::Backend::Cam => "CAM",
            },
            pi.n,
            pi.absent,
            pi.va,
            pi.truncated
        ),
    }
    if let Some(pi) = pci::info() {
        for k in 0..pi.n.min(8) {
            if let Some(d) = pci::dev(k) {
                crate::log_info!(
                    "pci: {:04x}:{:02x}.{} vend={:#06x} dev={:#06x} cfg08={:#010x} hdr={:#02x} bar0={:#010x}",
                    d.bdf >> 16,
                    (d.bdf >> 11) & 31,
                    (d.bdf >> 8) & 7,
                    d.vendor,
                    d.device,
                    d.cfg08,
                    d.hdr,
                    d.bar0
                );
            }
        }
    }
}

/// 构建级故障注入（heap OOM / 资源泄漏）；正常构建为空。
fn stage_fault_injections() {
    // ---- 故障注入（ADR-018）：向全局分配器要一个超过大小类上限的分配。
    // `GlobalAlloc::alloc` 返回 null 之后，稳定版唯一的去向是 handle_alloc_error
    // → panic → panic=abort → 我们的 handler → 39。这条只能靠注入证明，
    // 正常构建里永远不会有人真的把堆要空，所以它不能只在文档里写"应该会停机"。
    #[cfg(feature = "fault-heap-oom")]
    {
        crate::log_warn!(
            "fault-heap-oom: 按设计向全局分配器要 {} 字节（LARGE_MAX={}）",
            heap::LARGE_MAX + 1,
            heap::LARGE_MAX
        );
        let mut big: Vec<u8> = Vec::with_capacity(heap::LARGE_MAX + 1);
        big.push(1);
        // 走到这里说明失败没有升级成 L4：那 ADR-018 的出口就是假的，报 FAIL 而不是继续跑绿。
        crate::log_fatal!("fault-heap-oom: 分配失败却没有停机，ADR-018 的 L4 出口不成立");
        exit::finish(exit::Code::Failed);
    }

    // ---- 故障注入（§12.3 R19 的"每道门禁都要有负样本"）：故意泄漏一帧给测试模块，
    // 台账必须把它报出来。如果 t_resource_ledger_balanced 照样绿，说明泄漏检测是假的。
    #[cfg(feature = "fault-resource-leak")]
    {
        // 这里不能用 unwrap/expect（§2.5 的 lint 门禁），所以把"注入没做成"写成分支
        if let Ok(leak) = mm::phys_alloc(0, mm::MOD_TEST) {
            core::mem::forget(leak);
            crate::log_warn!("fault-resource-leak: 已按设计泄漏 1 帧，台账必须抓到");
        } else {
            crate::log_fatal!("fault-resource-leak: 分配失败，注入没有发生（这条构建就没意义了）");
            exit::finish(exit::Code::BootInvalid);
        }
    }
}

/// 存储认领、启动循环保护与上一次崩溃的读回。
fn stage_storage_guard_crash() {
    // ---- §9.4 的启动循环保护：必须先有存储，才谈得上"跨重启的那个计数"。
    // 认领提到启动路径里不是顺手多调一次（`ahci::init` 本来就幂等）：`decide()` 要在
    // 任何可能崩的路径**之前**把 `n+1` 写回盘，而驱动与用例都在后面。
    // 存储没起来 ⇒ 状态区读不到 ⇒ 按最坏情况进安全模式（这正是"读不到"该有的处置）。
    match ahci::init() {
        Ok(i) => crate::log_info!("boot: 存储已认领 abar={:#x} 端口={}", i.abar, i.ports),
        Err(e) => {
            crate::log_warn!("boot: 存储没认领上 {:?}，状态区读不到 ⇒ 按最坏情况处理", e)
        }
    }
    boot_guard::decide();
    // §9.7 的另一半：上一条崩溃在存储就绪之后才读得回来，所以它一定在串口现场之后。
    crash::report_previous();
}

/// 签名包的缓冲（`sign::PKG_BYTES` = 57,856 字节）比分配器上限（2048）大两个数量级，
/// 理由与 `ktests/sign.rs` 的 `PkgScratch`、`ktests/elf.rs` 的 `ElfScratch` 同一条：
/// 按外部输入大小去分配，第一次就走 `handle_alloc_error` ⇒ 整机 39（ADR-018/026）。
/// **产品路径自己一份**，不复用用例那份——那份是 `sig-check` 门控的，正常构建里根本不存在。
struct BootPkgCell(UnsafeCell<[u8; sign::PKG_BYTES]>);
// SAFETY: 指针来源 = 本 static 自己的 UnsafeCell，不是外部传进来的地址；
//         地址范围 = 这一个数组，可变借用只在 `stage_signature_check` 一次调用内活着、不外泄；
//         对齐 = [u8; N] 对齐 1，任何切片访问都合法；生命周期 = 整个内核（static，永不释放）；
//         并发规则 = **单一访问者**：全内核只有 `stage_signature_check` 引用它，而启动编排只调一次；
//         上下文约束 = BOOT，且调用点在 AP 释放之前（`smp::bringup` 在 ktests/mm.rs 里，晚于本阶段）；
//         不变量由"启动编排的顺序 + 只此一处引用"保证，两者都能用 grep 与 after_switch 的顺序核。
unsafe impl Sync for BootPkgCell {}
static BOOT_PKG_BUF: BootPkgCell = BootPkgCell(UnsafeCell::new([0u8; sign::PKG_BYTES]));

/// Stage3c（W4 S3，ADR-080）：验签**进启动决策**，但口径是**只检测、不拒启**。
///
/// 为什么现在只检测：拒启（"验不过 ⇒ BOOT-INVALID(37)"）要等装载侧身份 + A/B 槽位 +
/// ADR-011 正式方案 + 生产钥匙的保管/轮换/吊销（手册 M9 行自己写着这条依赖）。
/// 在那些都没有之前启用拒启，等于每次启动都拒。所以这一阶段**无论验签成败都继续启动**，
/// 把结果与拒因写进日志与读数；`拒启=false` 是显式打出来的，不是靠"没看到拒启"推断。
/// 读失败也只记录：那是设备/存储的问题，不是"这份包不可信"的证据，两者不许混成一个结论。
fn stage_signature_check() {
    const CHUNK: usize = 4096;
    let port = match ahci::boot_port() {
        Ok(p) => p,
        Err(e) => {
            crate::log_warn!("sign-boot: 找不到引导口 {:?} ⇒ 验签没跑 拒启=false（ADR-080）", e);
            return;
        }
    };
    // SAFETY: 见 BootPkgCell —— 单一访问者、启动编排只调一次、借用不出本次调用
    let buf = unsafe { &mut *BOOT_PKG_BUF.0.get() };
    let mut off = 0usize;
    let mut reads = 0usize;
    while off < sign::PKG_BYTES {
        let n = CHUNK.min(sign::PKG_BYTES - off);
        let lba = sign::PKG_START_LBA + (off / sign::SECTOR_BYTES) as u64;
        if let Err(e) = ahci::read_bytes(port, lba, &mut buf[off..off + n]) {
            crate::log_warn!(
                "sign-boot: 读包失败 lba={} 长={} 第{}次 {:?} ⇒ 验签没跑完 拒启=false（ADR-080）",
                lba, n, reads, e
            );
            return;
        }
        off += n;
        reads += 1;
    }
    match sign::check_package(buf, &sign::PK_ANCHOR) {
        Ok(n) => crate::log_info!(
            "sign-boot: 验签通过 载荷字节={} 读盘次数={} 包字节={} 起始LBA={} 拒启=false",
            n, reads, sign::PKG_BYTES, sign::PKG_START_LBA
        ),
        Err(e) => crate::log_warn!(
            "sign-boot: 验签被拒 理由={} 附带={} 读盘次数={} 包字节={} 起始LBA={} 拒启=false（ADR-080：只检测不拒启）",
            sign::reason(e), sign::reason_arg(e), reads, sign::PKG_BYTES, sign::PKG_START_LBA
        ),
    }
}

/// Stage4：跑 .ktests、报 P1–P5/P4 读数并交付退出码。
/// 用例收尾的账（ADR-050 / ADR-061 / W1 收尾 B2）。
/// 两类残留**分开点名**，因为成因与处置不同：
/// * `stray`：还 `Runnable`/`Running` 而**不在常驻名单**里的任务——原来只数用户任务，
///   今天把"没人收的内核工人"一起数进来，豁免从 blanket 收到 `sched::is_resident`
///   那份**显式名单**（名单在启动路径里写定：每 CPU 的启动/空闲上下文、BSP 的兜底 idle、
///   AP 的工人循环）。新工人忘了登记会当场红，而不是被"它是内核任务"悄悄放过。
/// * `blocked`：还 `Blocked` 的任务 ⇒ 等待槽/轮项漏了（ADR-061）。
/// 范围从"本 CPU"扩到**所有在线 CPU**（ADR-050 未决 2 / ADR-061 未决 2）。
/// 只读快照、不取队列锁：拿着 BSP 的锁去等 AP 的 RUNQ 正是 ADR-047 决策 2 禁止的形状。
pub(crate) struct Sweep {
    pub stray: usize,
    pub first_stray: usize,
    pub stray_cpu: usize,
    pub blocked: usize,
    pub first_blocked: usize,
    pub blocked_cpu: usize,
    /// 名单里被豁免掉的任务数。**防空转格**：这一格要是 0，"豁免是显式的"就是修辞。
    pub residents: usize,
    /// 扫了几颗在线 CPU（含 BSP）
    pub cpus: usize,
    /// W3 P3（ADR-073）：还占着的进程槽数（含僵尸）。同一条收尾律——用例造的记录用例自己收。
    pub procs: usize,
    pub first_proc: u16,
    /// 还存活的 Job 数。
    pub jobs: usize,
    pub first_job: u16,
    /// W3 P4b（ADR-074 的 C9）：还没归还的 VMO 与没关的句柄。同一条收尾律。
    pub vmos: usize,
    pub first_vmo: u8,
    pub handles: usize,
}

/// 句柄表只在 `handles` 特性里编译；别的构建这一格恒 0（读回真实状态，不读"我打算开"）。
fn handles_live() -> usize {
    #[cfg(feature = "handles")]
    {
        crate::handle::live()
    }
    #[cfg(not(feature = "handles"))]
    {
        0
    }
}

pub(crate) fn finish_sweep() -> Sweep {
    let mut s = Sweep {
        stray: 0,
        first_stray: usize::MAX,
        stray_cpu: usize::MAX,
        blocked: 0,
        first_blocked: usize::MAX,
        blocked_cpu: usize::MAX,
        residents: 0,
        cpus: 0,
        procs: 0,
        first_proc: u16::MAX,
        jobs: 0,
        first_job: u16::MAX,
        vmos: 0,
        first_vmo: u8::MAX,
        handles: 0,
    };
    for c in 0..cpu::MAX_CPUS {
        if cpu::is_online(c) {
            s.cpus += 1;
        }
    }
    for i in 0..sched::MAX_TASKS_TOTAL {
        let c = sched::cpu_of(i);
        if !cpu::is_online(c) {
            continue;
        }
        match sched::state_of(i) {
            sched::TaskState::Blocked(_) => {
                s.blocked += 1;
                if s.first_blocked == usize::MAX {
                    s.first_blocked = i;
                    s.blocked_cpu = c;
                }
            }
            sched::TaskState::Runnable | sched::TaskState::Running => {
                if sched::is_resident(i) {
                    s.residents += 1;
                } else {
                    s.stray += 1;
                    if s.first_stray == usize::MAX {
                        s.first_stray = i;
                        s.stray_cpu = c;
                    }
                }
            }
            _ => {}
        }
    }
    // W3 P3（ADR-073）：进程与 Job 上同一条收尾律。两张表是全局的（不属于某个 CPU），
    // 所以不进上面的 CPU 循环；读数不取锁，理由写在 proc::proc_residual 的头注释里。
    let (pr, pf) = proc::proc_residual();
    s.procs = pr;
    s.first_proc = pf;
    let (jr, jf) = proc::job_residual();
    s.jobs = jr;
    s.first_job = jf;
    // VMO 与句柄（ADR-074 的 C9）：VMO 表在 VMM 内读，句柄表它自己那把锁内读，
    // 两把锁不嵌套（依次获取），所以这个扫描仍然不持任何锁进入下一段。
    let (vr, vf) = vmo::vmo_residual();
    s.vmos = vr;
    s.first_vmo = vf;
    s.handles = handles_live();
    s
}

fn run_ktests_and_finish() -> ! {
    // ---- Stage4：跑用例并交付判定
    // P3b-2：先给 BSP 登记兜底 idle，再跑用例。有了它，"没有别人可换"不再是
    // "返回 prev 让 Done 任务永远占着 CPU"，而是切到 idle ⇒ reap 收得到那个槽（ADR-051）。
    let idle_ok = sched::init_idle();
    crate::log_info!("sched idle: 登记={} 下标={}", idle_ok, sched::idle_of(cpu::BSP_SLOT));
    // P3a-2 的收尾不变量：**用例跑完时，任何在线 CPU 都不许留下"没登记的"可运行任务，
    // 也不许留下阻塞任务**。豁免只给启动路径显式登记的常驻工人（`finish_sweep` 的注释）。
    // 为什么这条值得当判据：残留的 ring3 自旋任务会让任何"关窗口让出"或"停掉唯一
    // tick 源"的动作变成整机静默（§111/§114a 两次挂死同一地址 RIP=0x100102040），
    // 而残留的 Blocked 内核工人占着等待槽与轮项（ADR-061）。
    // 它不是调度器的缺陷，是用例没把自己造的东西收干净——所以判据放在用例边界上，
    // 由这里点名是哪一条用例留下的、在哪个 CPU、首个槽号，而不是让每个用例各自扫一遍。
    let s = ktest::run_all(|name| {
        let sw = finish_sweep();
        if sw.blocked != 0 {
            crate::log_fatal!(
                "用例收尾不变量破坏：test={} 之后 cpu{} 仍有 {} 个阻塞任务（首个 #{}）⇒ 等待槽/轮项漏了",
                name, sw.blocked_cpu, sw.blocked, sw.first_blocked);
        }
        if sw.stray != 0 {
            crate::log_fatal!(
                "用例收尾不变量破坏：test={} 之后 cpu{} 仍有 {} 个未登记的可运行任务（首个 #{}，用户或内核工人在 `Task::resident` 名单之外）",
                name, sw.stray_cpu, sw.stray, sw.first_stray);
        }
        if sw.procs != 0 {
            crate::log_fatal!(
                "用例收尾不变量破坏：test={} 之后仍有 {} 个进程记录没交出去（首个 #{}）⇒ 僵尸走 proc_reap、没起线程的走 proc_discard",
                name, sw.procs, sw.first_proc);
        }
        if sw.jobs != 0 {
            crate::log_fatal!(
                "用例收尾不变量破坏：test={} 之后仍有 {} 个 Job 没销毁（首个 #{}，名下额度必须已清零）",
                name, sw.jobs, sw.first_job);
        }
        if sw.vmos != 0 {
            crate::log_fatal!(
                "用例收尾不变量破坏：test={} 之后仍有 {} 个 VMO 没归还（首个 #{}）⇒ 最后一个引用要 vmo_unref",
                name, sw.vmos, sw.first_vmo);
        }
        if sw.handles != 0 {
            crate::log_fatal!(
                "用例收尾不变量破坏：test={} 之后仍有 {} 个句柄没关（close 或 revoke_task）",
                name, sw.handles);
        }
        sw.stray == 0 && sw.blocked == 0 && sw.procs == 0 && sw.jobs == 0
            && sw.vmos == 0 && sw.handles == 0
    });
    crate::log_info!("ktests: total={} passed={} failed={} table_invalid={}", s.total, s.passed, s.failed, s.table_invalid);
    // §9.6 的账本：开机到现在看过几次心跳、报过几次、处置过几次。处置次数今天必须是 0，
    // 它变成非 0 的那一天就是"把核摘线"真的实现了的那一天（在那之前它只是个计数器）。
    let (wd_samples, wd_windows, wd_events, wd_mask, wd_actions) = watchdog::stats();
    crate::log_info!(
        "watchdog: 采样={} 报警窗口={} 核次={} 末位图={:#x} 处置={}",
        wd_samples,
        wd_windows,
        wd_events,
        wd_mask,
        wd_actions
    );
    // 健康条件：本轮用例一条没红且表不是空的 ⇒ 把连续失败计数清回 0
    if s.failed == 0 && !s.table_invalid {
        boot_guard::mark_healthy();
    }
    // 用例跑完才让 AP 停机（放在用例之间会让同一条用例在两种链接顺序下给出两种结论）。
    // 停机之后再把 per-CPU 的数打出来，免得 hlt 之前的读数被后面的 tick 追改。
    smp::stop_aps();
    // ADR-019 的那次**显式**回收：前提条件此刻才成立——所有 AP 都已经从 bootloader 给的
    // 启动栈上走开并停机（stop_aps 里逐个等到"已关定时器 + 已关 IF"的信号，并把它们摘下线）。
    // 回收必须在 stop_aps 之后、也必须在最后一次用到 mp.cpu_ptrs 之后：
    // 那些 mp_info 结构本身就住在可回收内存里。
    let reclaimed = mm::reclaim_bootloader_regions();
    crate::log_info!(
        "smp final: released={} online={} stuck_online={} cpu_ticks={:?} bsp_ticks={}",
        smp::released_count(), cpu::online_count(), smp::stuck_online_count(), apic::cpu_ticks_all(), sched::ticks_of(cpu::BSP_SLOT)
    );
    crate::log_info!(
        "mm: bootloader regions reclaimed = {} frames ({} MiB) ; free frames now {}",
        reclaimed, reclaimed * mm::PAGE / (1024 * 1024), mm::free_frames()
    );
    let ls = sync::stats();
    crate::log_info!(
        "sync: acquires={} order_violations={} reentrant_hits={} wait_events={} wait_spins={} wait_max={} wait_timeouts={}",
        ls.acquires, ls.order_violations, ls.reentrant_hits, ls.wait_events, ls.wait_spins_total,
        ls.wait_max_cycles, ls.wait_timeouts
    );
    crate::log_info!("percpu: registered={} unmatched_self_lookups={}", cpu::registered(), cpu::unmatched_self_lookups());
    // P5 的见证读数：idle 与 AP 工人真的进了 hlt（内核自报，宿主机解析这一行；
    // 不是独立见证——`-d int` 不记录 hlt，仓库里没有数它的仪器，见 ADR-057）
    crate::log_info!(
        "idle hlt: bsp={} ap={:?}（自报数；判据在 t_percpu_queues）",
        sched::idle_hlt_count(cpu::BSP_SLOT),
        [smp::ap_worker_hlt(1), smp::ap_worker_hlt(2), smp::ap_worker_hlt(3)]);
    let c = mm::counters();
    crate::log_info!(
        "mm counters: map_calls={} mapped_pages={} unmapped_pages={} page_table_pages={} early_pool={} as_pt_live={} cr3_writes={}",
        c.map_calls, c.mapped_pages, c.unmapped_pages, c.page_table_pages, c.early_pool_used,
        c.as_pt_live, c.cr3_writes
    );
    tsc::stage("ktests");

    // ---- P3 / P4 交付（§12.4.1）。P3 的两条路径分开报；一条都没取到就是量具坏了，
    // 必须让它进判定条件而不是留一行空数字——量具不出数不等于出数为 0。
    let pr = trap::p3_resume_stats();
    let pf = trap::p3_fatal_stats();
    let p5 = trap::p5_irq_stats();
    let c = apic::counts();
    let rust_irq_total: usize = c.irq.iter().sum::<usize>() + c.unexpected + c.spurious + c.resched;
    let (n1, mean1, min1, max1) = sched::p1_stats();
    crate::log_info!("p1 switch: samples={} mean={} min={} max={} cycles", n1, mean1, min1, max1);
    // P1 也按 CPU 分行（M3b-2b）。注意这里**不能**写"之前 min 涨了是因为混样"：
    // 分行之后 BSP 自己那一行还是 2603（AP 的行 3090~3572），而 AP 不参与调度的 M3b-1
    // 是同一条尺子的 462~987。涨的原因尚未归因（最可能是宿主侧争用），已挂任务 #11。
    // 这一行的用途是让"哪个核的样本进了哪个数"变成可见的，而不是给出因果。
    for (cpu, n, mean, min, max) in sched::p1_with_samples() {
        crate::log_info!("p1 percpu cpu{}: samples={} mean={} min={} max={} cycles", cpu, n, mean, min, max);
    }
    // P2（§12.4 的"驱动接口往返开销"）在这里采：ktests 已经跑完，设备与页框都在
    // 稳态里，探针自己认领、自己撤销
    p2_probe();
    crate::log_info!(
        "p5 irq: samples={} mean={} min={} max={} last_vec={:#x} cycles | rust total={} irq0={} irq1..15={} 按CPU={:?} unexpected={} spurious={} eoi={} | PF_TAKEN={}",
        p5.faults, p5.mean_cycles, p5.min_cycles, p5.max_cycles, trap::p5_last_vec(),
        rust_irq_total, c.irq[0], c.irq[1..].iter().sum::<usize>(), irq::by_cpu(), c.unexpected, c.spurious, c.eois,
        trap::PF_TAKEN.load(Ordering::Relaxed)
    );
    crate::log_info!(
        "p3 resume: faults={} mean={} min={} max={} cycles",
        pr.faults, pr.mean_cycles, pr.min_cycles, pr.max_cycles
    );
    // 边界移动之后的读数说明（ADR-021 同段记录）：P3/P5 的下界从"异常桩第一条指令"
    // 移到"进 Rust 垫片"，上界从"寄存器恢复之后"移到"垫片末尾"，并且整张表按 CPU 分行。
    // 所以这三行与 M3a/M3b-1 存档里的数字**不可直接比**；能比的只有同一构建内部的比值
    // （那正是 §12.4.1 规则 3 的判别方式，bench 就是这么判的）。
    for ps in trap::p_stats_all().iter() {
        if ps.cpu >= crate::arch::x86_64::cpu::registered() && ps.cpu != crate::arch::x86_64::cpu::BSP_SLOT {
            continue;
        }
        if ps.cpu != crate::arch::x86_64::cpu::BSP_SLOT && ps.irq.faults == 0 && ps.resume.faults == 0 {
            continue; // 没登记或没样本的槽位不占一行
        }
        crate::log_info!(
            "p percpu cpu{}: p3(faults={} min={}) p5(faults={} mean={} min={} max={} last_vec={:#x}) fatal(faults={} min={}) p7(faults={} mean={} min={})",
            ps.cpu, ps.resume.faults, ps.resume.min_cycles, ps.irq.faults, ps.irq.mean_cycles,
            ps.irq.min_cycles, ps.irq.max_cycles, ps.last_vec, ps.fatal.faults, ps.fatal.min_cycles,
            ps.syscall.faults, ps.syscall.mean_cycles, ps.syscall.min_cycles
        );
    }
    crate::log_info!(
        "p totals across cpus: p5_samples={} p3_faults={} (对照：apic 侧计数与 PF_TAKEN)",
        trap::p5_samples_total(), trap::p3_faults_total()
    );
    crate::log_info!(
        "p3 fatal: faults={} mean={} min={} max={} cycles (fatal path = detect + stop prep, excludes crash dump emission)",
        pf.faults, pf.mean_cycles, pf.min_cycles, pf.max_cycles
    );
    // µs 列只有在标定成功之后才出现；没标定就只报 cycles，**不回退成"假设 1 GHz"**
    let us = clock::micros(tsc::elapsed());
    match us {
        Some(v) => crate::log_info!(
            "p4: stages={} total={} cycles = ~{} us (estimated: TSC not invariant, so long spans drift) serial_bytes={}",
            tsc::total_stages(), tsc::elapsed(), v, serial::bytes_out()
        ),
        None => crate::log_info!(
            "p4: stages={} total={} cycles (no calibration -> cycles only) serial_bytes={}",
            tsc::total_stages(), tsc::elapsed(), serial::bytes_out()
        ),
    }

    // 量具自检：样本数>0 且 min<=mean<=max。这一条不是装饰——asm 里 min/max 的分支方向
    // 写反时，mean 看着完全正常而 min 停在 u64::MAX、max 停在 0，只有这条链能抓住它。
    // 它不进 ktest 表而进判定，因为表的枚举顺序不由源码顺序决定，用例之间不能假设
    // "前面已经有人触发过故障"。
    let ruler_ok = pr.faults > 0 && pr.min_cycles <= pr.mean_cycles && pr.mean_cycles <= pr.max_cycles;
    crate::log_info!("p3 ruler: samples_ok={} min<=mean<=max={}", pr.faults > 0, pr.min_cycles <= pr.mean_cycles && pr.mean_cycles <= pr.max_cycles);

    // S4a（W5 第一片，BACKLOG §229）：产品路径**真起 ring3**。放在判定之前、ktests 之后，
    // 这样用例读数不受影响，而 hello 的输出能进同一份串口。
    // S5d：接住 init 的任务号——判定之后要不要等它，由 `park_until_init_exits` 说。
    let init_task = stage_init_user(0);
    // S6p：第二个会话（多标签）。**只在新特性下起**：既有变体的任务与句柄账一格不动。
    #[cfg(feature = "multisession")]
    {
        let second = stage_init_user(1);
        // S6q 补记三：窗口条目上的 `×` 要能终止这个会话 ⇒ 任务号留一份给 `LiveTerm` 用。
        SECOND_TASK.store(second.unwrap_or(0), Ordering::Relaxed);
        crate::log_info!("multisession: 第二个会话 任务={:?}", second);
    }
    // S6c：init 的交互窗口结束后报键盘的六本账——**放在这里**是因为窗口之内才是按键时间，
    // 放到 verdict 之后就只数得到空闲期的包。
    #[cfg(feature = "ps2-kbd")]
    {
        let (bytes, irqs, pushed, dropped, breaks, ext, swallowed, unmapped, queued) = kbd::stats();
        crate::log_info!(
            "kbd: 字节={} 派发={} 入环={} 丢弃={} break={} 扩展={} 吞掉={} 不映射={} 排队={}",
            bytes,
            irqs,
            pushed,
            dropped,
            breaks,
            ext,
            swallowed,
            unmapped,
            queued
        );
    }
    // S6b-2：把这一跑的用例结果画到屏幕上（画面取证要像素证人，不是串口证人）
    #[cfg(feature = "framebuffer")]
    stage_fbcon_tail(s.total as usize, s.failed as usize, s.table_invalid);

    // 判定必须同时满足：表可用且非空、无失败、异常确实被取到过、且 P3 的量具真的收到过样本
    let clean = !s.table_invalid
        && s.total > 0
        && s.failed == 0
        && trap::PF_TAKEN.load(Ordering::Relaxed) > 0
        && ruler_ok;
    if clean {
        crate::log_info!("verdict: PASS");
        park_until_init_exits(init_task);
        exit::finish(exit::Code::Success);
    }
    crate::log_warn!("verdict: FAIL");
    park_until_init_exits(init_task);
    exit::finish(exit::Code::Failed)
}

/// S5d（W5，BACKLOG §237）：`resident-init` 档在判定**打完之后不退出**，一直等到 init 自己收工
/// 才走 `debug-exit`。判定行的位置一字不动 ⇒ 日志契约不变，改的只有"什么时候停机"。
///
/// **为什么是"有界轮询"而不是一个新的无限等待**：`wait_for_task` 每一次自己登记槽、
/// 每条出口都 `task_wait_take` 取回（sched.rs 里那三条返回路径都是这个形状），
/// 所以循环调用不残留注册；而无限等待要动 sched 的等待语义——硬约束①不许顺手改的东西。
/// 顺带一条：轮询对"跨 CPU 的收工唤醒只置标志、不发 IPI"这种情形天然免疫，
/// init 落在哪颗 CPU 上都能推进。
///
/// 非常驻档这个函数体整体不存在（`#[cfg]` 不是 `cfg!`）⇒ 默认档与 `handles` 档产物逐字节不变，
/// 判定表里 `do_run(["handles"])` 那一行更不会受影响。
fn park_until_init_exits(init: Option<usize>) {
    #[cfg(feature = "resident-init")]
    {
        let Some(gidx) = init else { return };
        crate::log_info!("resident-init: 判定已出，等 init（任务={}）收工；没人喂命令就不会退出", gidx);
        // S6g：判定之后的常驻期画面**继续刷新**（terminal 的意义就在这里）。
        // 这里单独开一次映射：stage_init_user 里那一个已经随函数返回 drop 掉了。
        #[cfg(feature = "fbcon-live")]
        let mut live = LiveTerm::open();
        loop {
            // S6u：**一拍 1 窗口（约 16 ms）**，内容签名每 8 拍才算一次。
            // 拆之前这里是"每轮 8 窗口（约 140 ms）"，而指针只在 repaint 里画 ⇒
            // 画面上的指针最高约 7 fps——用户量到的"鼠标卡顿"就是这个数，与 QEMU/GTK 无关
            // （A/B：`-display none` 与 `-display gtk` 的每帧毫秒同一量级，140.1 / 198.3）。
            let woke = apic::with_interrupts(|| sched::wait_for_task(gidx, crate::clock::window_cycles(1)));
            if woke {
                crate::log_info!("resident-init: init 已收工 ⇒ 系统停机");
                return;
            }
            #[cfg(feature = "fbcon-live")]
            if let Some(t) = live.as_mut() {
                // 拍数从墙上读，而不是自己数循环：提前返回的那些拍没有画面动作。
                if crate::main_frames() % 8 == 7 {
                    t.repaint();      // 结尾自带一次 tick()
                } else {
                    t.tick();
                }
            }
            // 点击与统计统一在 `LiveTerm::repaint` 里处理（两个等待循环都会路过它）。
        }
    }
    #[cfg(not(feature = "resident-init"))]
    {
        let _ = init;
    }
}


/// S4a（W5 第一片）：产品启动路径装载并跑起第一个用户程序。
///
/// **为什么这一片单独存在**：在此之前用户态执行**只在 ktest 里**，产品路径一个用户程序都不跑
/// （`main.rs` 里搜不到 `spawn_user`）⇒ 没有 init、也就不可能有 shell（BACKLOG §229）。
/// 本片只做"装载 + 跑起来 + 看到它自己的输出"；**句柄授予留 S4b**（权限只从句柄来）、
/// **`MAX_TASKS` 余量重算留 S4c**。
///
/// 装载产物用与 ktest 同源的嵌入式夹具（`ktests::common::HELLO_ELF`），
/// 从卷上取 ELF 那条路已在 L3-C 交付，这里不重做。
#[cfg(not(feature = "handles"))]
fn stage_init_user(_sid: u8) -> Option<usize> {
    let loaded = match crate::user::load(crate::ktests::common::HELLO_ELF) {
        Ok(l) => l,
        Err(e) => {
            crate::log_warn!("init-user: 装载失败 —— {} ⇒ 产品路径没起用户程序", crate::user::describe_load(e));
            return None;
        }
    };
    let t = match sched::spawn_user(loaded.entry, loaded.stack_top, 0, loaded.owned) {
        Ok(t) => t,
        Err(e) => {
            crate::log_warn!("init-user: spawn_user 失败 {:?} ⇒ 产品路径没起用户程序", e);
            return None;
        }
    };
    // 用户态要靠时间片轮转才跑得到；表若停着就先开（与用例同一律）。
    apic::timer_start().ok();
    let done = apic::with_interrupts(|| sched::wait_for_task(t, crate::clock::window_cycles(32)));
    // **判据是信箱不是串口**：hello 不打印，它往自己的数据段写 magic/ping/add（user/hello 的 OFF_*）。
    // 所以"产品路径真跑过 ring3"的证据是**这几个槽被用户态写过**，而不是串口出现字符串。
    // bounded_wait_done=false 是预期的：hello 写完就停在自旋里，不会自己收工。
    let magic = crate::user::read_at(loaded.data_va);
    let ping = crate::user::read_at(loaded.data_va + 8);
    let add = crate::user::read_at(loaded.data_va + 16);
    crate::log_info!(
        "init-user: 产品路径起 ring3 任务={} entry={:#x} 栈顶={:#x} 段={} 页={} 等待收工={} 信箱 magic={:?} ping={:?} add={:?}",
        t, loaded.entry, loaded.stack_top, loaded.segs, loaded.pages, done, magic, ping, add
    );
    // S5d：默认档没有控制台句柄可授，谈不上常驻 ⇒ 交回 None。
    None
}

/// 起一个 shell 会话：`sid` 决定它拿到的控制台句柄属于哪个会话（0 号兼作 init）。
#[cfg(feature = "handles")]
fn stage_init_user(sid: u8) -> Option<usize> {
    use crate::arch::x86_64::trap::TrapFrame;
    use crate::handle::{self, Handle, RIGHT_CREATE, RIGHT_DUP, RIGHT_MAP, RIGHT_READ, RIGHT_TRANSFER, RIGHT_WRITE};
    use crate::user::{
        SYS_ASPACE_MAP, SYS_PROCESS_CREATE, SYS_PROCESS_START, SYS_THREAD_CREATE, syscall_dispatch,
        ABI_MAJOR, ABI_MINOR, SI_MAGIC, SI_OFF_HANDLES, SI_DESC_BYTES, SI_DESC_ROLE, SI_DESC_HANDLE,
        ROLE_JOB, ROLE_LOG, E_DENIED,
    };
    use crate::{proc, vmo};

    let Some(owner) = sched::current_identity() else {
        crate::log_warn!("init-user: 启动上下文没有身份 ⇒ 产品路径没起用户程序");
        return None;
    };
    let mut f = TrapFrame {
        cr2: 0, r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0, vector: 0,
        error_code: 0, rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    };
    // 根 Job 由内核持有，只在这里出示。两个句柄：一个**没有 CREATE**（判据用），一个有。
    let job = match proc::job_create(None, 2, 64) { Ok(v) => v, Err(e) => {
        crate::log_warn!("init-user: job_create 失败 {:?}", e); return None;
    } };
    let jgen = proc::job_gen(job).unwrap_or(0);
    let hj_plain = match handle::grant_job(owner, job, jgen, RIGHT_READ | RIGHT_DUP) {
        Ok(h) => h, Err(_) => { crate::log_warn!("init-user: grant_job(plain) 失败"); return None; }
    };
    let hj = match handle::grant_job(owner, job, jgen, RIGHT_READ | RIGHT_DUP | RIGHT_CREATE | RIGHT_TRANSFER) {
        Ok(h) => h, Err(_) => { crate::log_warn!("init-user: grant_job(create) 失败"); return None; }
    };
    // **判据①：无 CREATE 权限的 Job 句柄必须拒 E_DENIED**（权限只从句柄来）。
    f.rax = SYS_PROCESS_CREATE; f.rdi = hj_plain.0; f.rsi = 0; f.rdx = 0; f.r10 = 0;
    syscall_dispatch(&mut f);
    let denied = f.rax == E_DENIED;
    // S6p：这条"无 CREATE"句柄只服务上面那一次拒绝，**用完当场还槽**。
    // 不还的话每个会话都白占一格，而句柄表是全局 16 格（ADR-007）——
    // 第二个会话在 15 号上就是被这 16 格卡死的（`ret=-6`，而槽、袋、si 都还有空）。
    let _ = handle::close(hj_plain, owner);
    f.rax = SYS_PROCESS_CREATE; f.rdi = hj.0;
    syscall_dispatch(&mut f);
    let hp = Handle(f.rax);
    let (pid, pgen) = match handle::resolve(hp, owner, 0) {
        Ok((handle::ObjRef::Proc { slot, gen }, _)) => (slot, gen),
        _ => { crate::log_warn!("init-user: Proc 句柄解不开 ret={:#x}", f.rax); return None; }
    };
    let Some((aslot, _)) = proc::proc_aspace(pid, pgen) else {
        crate::log_warn!("init-user: 进程没有 AS"); return None;
    };
    // S4b-1 的装载器：真 ELF 进**子 AS**，映射经 aspace_map_slot（那棵树）。
    // S5c：装的是 shell 而不是 hello——控制台句柄已经在下面按 ROLE_LOG 授予，
    // 这一档的 init 从此是**交互式**的。默认档（无 handles）仍装 hello、判据仍是信箱，
    // 因为那条路没有控制台句柄可授，shell 进去只会 exit(1)。
    // ADR-098：这一段是"这个会话从全局 VA 表里占的东西"（逐段 + 栈）。
    // end 放在 match **之前**执行 ⇒ 任何一条 `return None` 都不会把作用域留在打开状态。
    let loaded = {
        crate::user::begin_session_load(sid);
        let r = crate::user::load_into(aslot, crate::ktests::common::SHELL_ELF);
        crate::user::end_session_load();
        match r {
            Ok(l) => l,
            Err(e) => { crate::log_warn!("init-user: load_into 失败 {}", crate::user::describe_load(e)); return None; }
        }
    };
    // 装载器把映射柄**交回调用方**而不是自动入袋（用例要能自己丢弃并核账）。不归创建者，
    // 这一袋就在本函数返回时落地 ⇒ 子进程的代码/栈被解映射。归了创建者，16 号的
    // `adopt_asmaps` 才搬得动：它只搬"创建者袋里目标 AS = 子 AS"的那些项。
    let owned_n = match loaded.owned.into_current() {
        Ok(n) => n,
        Err(e) => { crate::log_warn!("init-user: 映射归创建者失败 {:?}", e); return None; }
    };
    let Some(madt) = acpi::summary().and_then(|s| s.madt) else {
        crate::log_warn!("init-user: 没有 MADT，控制台未授予"); return None;
    };
    if let Err(e) = serial::enable_rx(&madt) {
        crate::log_warn!("init-user: 控制台接收初始化失败 {:?}", e); return None;
    }
    let console = match handle::grant_console(owner, RIGHT_READ | RIGHT_WRITE | RIGHT_DUP | RIGHT_TRANSFER, sid) {
        Ok(h) => h, Err(e) => { crate::log_warn!("init-user: 控制台授予失败 {:?}", e); return None; }
    };
    // S6p：控制台反例句柄是**启动路径仪器的**，只发给 init 会话：它只被写进 si 交给
    // 子进程（今天的 shell 不读那一格），而每发一份都占全局 16 格句柄表的一格。
    let foreign = if cfg!(feature = "console-probe") && sid == 0 {
        match handle::grant_console(owner, RIGHT_READ | RIGHT_WRITE, sid) {
            Ok(h) => h.0, Err(e) => { crate::log_warn!("init-user: 控制台反例句柄失败 {:?}", e); return None; }
        }
    } else { 0 };
    let si = match vmo::vmo_create(1) { Ok(v) => v, Err(_) => { crate::log_warn!("init-user: si vmo 失败"); return None; } };
    let mut hdr = [0u8; SI_OFF_HANDLES];
    hdr[0..4].copy_from_slice(&SI_MAGIC.to_le_bytes());
    hdr[4..6].copy_from_slice(&(ABI_MAJOR as u16).to_le_bytes());
    hdr[6..8].copy_from_slice(&(ABI_MINOR as u16).to_le_bytes());
    hdr[8..12].copy_from_slice(&2u32.to_le_bytes());
    if cfg!(feature = "console-probe") {
        hdr[12..16].copy_from_slice(&512u32.to_le_bytes());
        hdr[16..20].copy_from_slice(&8u32.to_le_bytes());
    }
    if vmo::vmo_write(si, 0, &hdr) != Ok(hdr.len()) { crate::log_warn!("init-user: si 头写失败"); return None; }
    let mut d = [0u8; SI_DESC_BYTES];
    d[SI_DESC_ROLE..SI_DESC_ROLE + 4].copy_from_slice(&ROLE_JOB.to_le_bytes());
    d[SI_DESC_HANDLE..SI_DESC_HANDLE + 8].copy_from_slice(&hj.0.to_le_bytes());
    if vmo::vmo_write(si, SI_OFF_HANDLES, &d) != Ok(SI_DESC_BYTES) { crate::log_warn!("init-user: si 描述写失败"); return None; }
    d[SI_DESC_ROLE..SI_DESC_ROLE + 4].copy_from_slice(&ROLE_LOG.to_le_bytes());
    d[SI_DESC_HANDLE..SI_DESC_HANDLE + 8].copy_from_slice(&console.0.to_le_bytes());
    if vmo::vmo_write(si, SI_OFF_HANDLES + SI_DESC_BYTES, &d) != Ok(SI_DESC_BYTES) {
        crate::log_warn!("init-user: 控制台描述写失败"); return None;
    }
    if cfg!(feature = "console-probe") && vmo::vmo_write(si, 512, &foreign.to_le_bytes()) != Ok(8) {
        crate::log_warn!("init-user: 控制台探针参数写失败"); return None;
    }
    let hi = match handle::grant_vmo(owner, si, RIGHT_READ | RIGHT_WRITE | RIGHT_MAP) {
        Ok(h) => h, Err(_) => { crate::log_warn!("init-user: grant_vmo(si) 失败"); return None; }
    };
    vmo::vmo_unref(si);
    // si 页也要经 14 号铺进子 AS（rdx = Proc 句柄别名）。
    // S6p：**每个会话要一个自己的 si VA**——`reserve_va_at` 的登记表不是按 AS 分的
    // （单地址空间，ADR-070），第一个会话占住 0x2_5000_0000 之后，第二个会话拿同一个
    // 地址会被当场拒成 -6（实测：`si_va=0xfffffffffffffffa`，而三个生效位一个没读错）。
    let si_want = 0x2_5000_0000 + (sid as u64) * mm::PAGE as u64;
    // ADR-098：si 那一页也是从全局表里占的（固定地址分支），同样要记上。
    crate::user::begin_session_load(sid);
    f.rax = SYS_ASPACE_MAP; f.rdi = hi.0; f.rsi = 0; f.rdx = hp.0; f.r10 = si_want;
    syscall_dispatch(&mut f);
    crate::user::end_session_load();
    let si_va = f.rax;
    // 生效位是**那棵树**里的真值（不是"我请求了什么"）：代码要 user+X+!W、栈要 user+W、
    // si 页要 user+!W。S4b-1 只在用例里核过这三格，产品路径这里补上。
    // **必须在放行之前读**：子进程一旦被杀、AS 被收，这三格就只会读回"没映射"。
    let bits = |va: u64| match mm::aspace_effective_flags(aslot, va) {
        Some(f) => (f.user as u8) | ((f.writable as u8) << 1) | ((f.executable as u8) << 2),
        None => 0xffu8,
    };
    crate::log_info!(
        "init-user(S5c): 生效位 代码={:#x} 栈={:#x} si={:#x}（bit0=user bit1=W bit2=X，0xff=没映射）",
        bits(loaded.entry), bits(loaded.stack_top & !0xfff), bits(si_va)
    );
    // S6p：第二个会话起步时的三道资源墙里，**这道读数管两道**：`si_va` 是不是真地址
    // （-6 = 地址被拒）与创建者袋还剩几格（`MAX_OWNED = 8`）。句柄表那一道见 15 号前的槽读数。
    crate::log_info!(
        "session-va: 会话={} 记={} 条（ADR-098：关会话时按这张表逐条 release_va）",
        sid,
        crate::user::session_va_count(sid)
    );
    crate::log_info!(
        "init-user(S4b-2): 会话={} si_va={:#x} 创建者袋={}",
        sid, si_va, sched::owned_of(owner.0)
    );
    // 15：建一条**停住**的线程。
    // S6p：第二个会话在 15 号上失败过一次（ret=-6），而 -6 在 15 号里对应四种不同原因
    // （`proc_attach_thread` / `spawn_user` 没空槽 / `set_aspace` / `block_task`）。
    // 槽占用是唯一能从外面读出来的那一格：先报它，再让失败行自己说话。
    let mut occ = 0u32;
    for i in 0..sched::MAX_TASKS {
        if !matches!(sched::state_of(i), sched::TaskState::Free) {
            occ |= 1 << i;
        }
    }
    crate::log_info!("init-user(S4b-2): 会话={} BSP 槽占用={:#011b}", sid, occ);
    f.rax = SYS_THREAD_CREATE; f.rdi = hp.0; f.rsi = loaded.entry; f.rdx = loaded.stack_top; f.r10 = 0;
    syscall_dispatch(&mut f);
    let ht = Handle(f.rax);
    let (gidx, _tid) = match handle::resolve(ht, owner, 0) {
        Ok((handle::ObjRef::Thread { gidx, id }, _)) => (gidx, id),
        _ => { crate::log_warn!("init-user: Thread 句柄解不开 ret={:#x}", f.rax); return None; }
    };
    let stopped = matches!(sched::state_of(gidx), sched::TaskState::Blocked(_));
    // 16：回填 StartupInfo 并放行。
    f.rax = SYS_PROCESS_START; f.rdi = hp.0; f.rsi = ht.0; f.rdx = hi.0; f.r10 = si_va;
    syscall_dispatch(&mut f);
    let started = f.rax;
    // 诊断（S5c）：子进程在入口就 #PF（rip=entry cr2=0 err=4），而三格生效位都对。
    // 只打**原值**：叶子表项（地址位+标志位）与首帧地址，不 deref 任何东西。
    // 上一版顺着叶子走 HHDM 读代码头，实测把内核打挂（cr2=HHDM+0x85000000，而 RAM 只有 512 MiB）
    // ⇒ 先问"表项里到底写了什么"，再决定要不要读它背后的帧。
    let leaf = |va: u64| mm::aspace_leaf_slot(aslot, mm::VirtAddr(va));
    crate::log_info!(
        "init-user(S5c): 叶子 代码={:#x?} 栈={:#x?} si={:#x?} 帧址={:#x?}",
        leaf(loaded.entry), leaf(loaded.stack_top & !0xfff), leaf(si_va), sched::task_frame(gidx)
    );
    apic::timer_start().ok();
    let windows = if cfg!(feature = "console-probe") { 1000 } else { 32 };
    #[cfg(not(feature = "fbcon-live"))]
    let done = apic::with_interrupts(|| sched::wait_for_task(gidx, crate::clock::window_cycles(windows)));
    // S6d：要实时上屏就得**边等边画**，所以这一档把那发长等待拆成有界轮询（总上界不变）。
    #[cfg(feature = "fbcon-live")]
    let done = live_wait_and_redraw(gidx, windows);
    let runs = sched::runs_of(gidx);
    // S5c：`等待收工=false` 在这一档是**预期**——shell 是常驻 init，只有收到 `exit` 才收工。
    // "它真的在跑"这一格由串口上的横幅与提示符作证（宿主机侧读），不靠这个布尔。
    crate::log_info!(
        "init-user(S4b-2): 会话={} 程序=shell 无CREATE拒={} Proc句柄={} 子AS={} 任务AS={} entry={:#x} 栈顶={:#x} 段={} 页={} 归创建者={} 子袋={} 线程停住={} start_ret={} 跑过次数={} 等待收工={} si_va={:#x}",
        sid,
        denied, hp.0, aslot, sched::aspace_of(gidx), loaded.entry, loaded.stack_top,
        loaded.segs, loaded.pages, owned_n, sched::owned_of(gidx), stopped, started, runs, done, si_va
    );

    // S6p：**创建者手里这两格在放行之后就是死重**——Proc/Thread 句柄只服务 15/16 号，
    // 之后内核按任务号（`gidx`）等它收工；而 16 号每开一个会话要向子进程补授三格 SELF_*，
    // 全局句柄表只有 16 格（ADR-007）⇒ 不还这两格，第二个会话的 16 号当场 `-6`（实测）。
    // `close` 对 Proc/Thread 只清表项（不像 Vmo 会 `vmo_unref`），所以不牵动对象寿命。
    // **si 的 VMO 句柄 `hi` 不关**：`vmo_unref` 在最后一个引用上会把帧还回去，
    // 而 si 页正映在子进程 AS 里——关它会把子进程的角色表页变成别人的帧（未证，故不动）。
    let _ = handle::close(hp, owner);
    let _ = handle::close(ht, owner);

    // S5d：交回 init 的任务号，让 main 在**判定打完之后**等它收工（BACKLOG §237）。
    Some(gidx)
}

/// 第二个会话的任务号（S6q 补记三）：窗口条目上的 `×` 关会话 1 时要用它终止任务。
/// 0 = 没起（`multisession` 关掉时恒 0）。
// **不挂 cfg**：`×` 的关闭分支在"没有多会话"的档里也要编得过（它只是不会真终止谁）——
// S6q 补记三刚踩过：不带 multisession 的那档直接 E0425。
static SECOND_TASK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// S6g：`fbcon-live` 档的**活终端**——映射只做一次，之后每轮调一次 [`LiveTerm::repaint`]。
///
/// 它不落冻结闸门（`freeze_band` 在这条路上根本不会被调用）：冻结契约是为"取一张确定的
/// 静止画面"服务的，而终端要一直刷新。两个变体因此各自有各自的确定性。
#[cfg(feature = "fbcon-live")]
struct LiveTerm {
    frame: crate::frame::Frame,
    term: crate::fbcon::Term,
    /// S6q：**上一次整窗重画的判据**。整屏一次是上百万次 UC 设备写（实测一轮里能占到
    /// 上百毫秒），而指针与光标每秒要动好几次；只要这一格没变就**不重画正文**。
    /// (会话号, 该会话环里累计字节, 该会话环里的换行数, 标签数, 活动标签)
    /// —— 换行数是"整窗 vs 只画输入行"的分水岭；最后一格是版面（S6t：标签条 ⇄ 浮窗）。
    sig: (u8, usize, u64, u64, u64, bool),
    /// 光标（下划线）**现在**画在哪一格；`None` = 现在是灭的一相。
    caret: Option<(u64, u64)>,
    /// 下一相光标该在哪一格（整窗重画时由 `redraw_window` 交回来）。
    caret_at: Option<(u64, u64)>,
    /// 指针当前位置（已画在屏上）与它盖住的 7×11 背景。
    /// **为什么不靠整窗重画擦指针**：那就是"指针跟着整屏一起闪"的来源；
    /// 保存/恢复 77 个像素是 154 次设备写，比一次重画便宜四个数量级。
    ptr: Option<(i32, i32)>,
    ptr_bg: [[u32; 7]; 11],
    /// 四本账：整窗重画 / 指针重画 / 光标翻转 / 只重画输入行各做了多少次
    /// （进日志，宿主机可复算"没内容变化时一个字都不写"）。
    paints: (u32, u32, u32, u32),
    /// 窗口三态（S6q 补记二）：点 `-`/`□` 改它，正文与标签栏的画法由 `fbcon::Chrome` 决定。
    chrome: crate::fbcon::Chrome,
    /// 上一次画的时候是哪个态（换态必须整窗重画）。
    last_chrome: crate::fbcon::Chrome,
    /// 每个窗口自己的"最小化"（列表条目上的 `-`，S6q 补记三）：窗口列表里一项一个。
    mins: [bool; crate::serial::SESSIONS],
    /// 已经关掉的窗口（`×`）。今天的实现只允许从最高的那个往下关。
    closed: [bool; crate::serial::SESSIONS],
    /// S6r：浮窗矩形 / z 序（末尾 = 最上面）/ 最大化前的矩形。
    #[cfg(feature = "wm")]
    wins: [crate::fbcon::WinRect; crate::serial::SESSIONS],
    #[cfg(feature = "wm")]
    saved: [crate::fbcon::WinRect; crate::serial::SESSIONS],
    #[cfg(feature = "wm")]
    z: [usize; crate::serial::SESSIONS],
    /// 每扇窗自己的内容签名 `(累计字节, 换行数)`：**只重画变了的那些矩形**。
    #[cfg(feature = "wm")]
    sigw: [(usize, usize); crate::serial::SESSIONS],
    /// 聚焦窗口 + z 序的签名（变了就要重排遮挡）。
    #[cfg(feature = "wm")]
    zsig: (u8, [usize; crate::serial::SESSIONS]),
    /// S6t：**版面开关**。false = 标签条 + 单正文（默认，与用户给的截图同构），
    /// true = 浮窗。默认不再是浮窗——`wm` 档一开就把标签条整条关掉，是用户截图里
    /// "参考图最显眼的那一条没了"的直接原因。
    #[cfg(feature = "wm")]
    float: bool,
    /// 桌面签名（哪些窗口开着 + 版面）：变了要**重铺桌面**，否则关掉的窗、
    /// 切走的版面会把旧像素留在屏幕上（它们已经不在任何矩形的负责范围里了）。
    #[cfg(feature = "wm")]
    desk: (u64, bool),
}

#[cfg(feature = "fbcon-live")]
impl LiveTerm {
    fn open() -> Option<Self> {
        let frame = match crate::frame::Frame::init() {
            Ok(f) => f,
            Err(e) => {
                crate::log_warn!("fbcon-live: 拿不到帧缓冲（{:?}）⇒ 画面不会有内容", e);
                return None;
            }
        };
        let Some(term) = crate::fbcon::Term::new(&frame) else {
            crate::log_warn!("fbcon-live: 几何放不下终端栅格 ⇒ 画面不会有内容");
            return None;
        };
        // 这里**不打印**：`open()` 在等待期与常驻期各调用一次，每次打一行只会在画面上多两行噪声。
        // 几何由 `live_wait_and_redraw` 打一次（那一次还带"每轮窗口"）。
        // 终端模式开屏先清屏：启动阶段（S6a）画的测试图案会留在下面 2/3 屏上（用户截图里的红绿蓝）。
        term.clear(&frame);
        Some(Self {
            frame, term,
            sig: (u8::MAX, usize::MAX, u64::MAX, 0, 0, false),
            caret: None,
            caret_at: None,
            ptr: None,
            ptr_bg: [[0; 7]; 11],
            paints: (0, 0, 0, 0),
            chrome: crate::fbcon::Chrome::Normal,
            last_chrome: crate::fbcon::Chrome::Normal,
            mins: [false; crate::serial::SESSIONS],
            closed: [false; crate::serial::SESSIONS],
            #[cfg(feature = "wm")]
            wins: [
                // S6t：旧几何 (1,1,56,14) 与 (20,8,56,14) 让下面那扇的标题栏和正文被盖掉
                // 四分之三，截图里看就是"一条空的灰条"。新几何**两扇标题都看得见**，
                // 但仍保留一段交叠——s6r 那条"遮挡由 z 序补"的判据要靠它才有证人。
                crate::fbcon::WinRect { x: 1, y: 1, cols: 70, rows: 11 },
                crate::fbcon::WinRect { x: 6, y: 7, cols: 70, rows: 11 },
            ],
            #[cfg(feature = "wm")]
            saved: [crate::fbcon::WinRect { x: 0, y: 0, cols: 0, rows: 0 }; crate::serial::SESSIONS],
            #[cfg(feature = "wm")]
            z: [0, 1],
            #[cfg(feature = "wm")]
            sigw: [(usize::MAX, usize::MAX); crate::serial::SESSIONS],
            #[cfg(feature = "wm")]
            zsig: (u8::MAX, [0; crate::serial::SESSIONS]),
            #[cfg(feature = "wm")]
            float: false,
            #[cfg(feature = "wm")]
            desk: (u64::MAX, false),
        })
    }

    /// **内容重画**：只在正文真的变了的时候写像素。结尾一定走一次 `tick()`——
    /// 整窗重画会把指针与光标擦掉，不立刻补就会缺半拍。
    /// 当前版面四元组：会话号 / 标签数 / 活动标签 / 三态。
    /// `repaint`（算内容签名）与 `tick`（判点击命中哪一格）**必须共用这一份**：
    /// 两处各算一遍，命中就会按另一套标签数走。
    fn layout(&self) -> (usize, u64, u64, crate::fbcon::Chrome) {
        #[cfg(feature = "handles")]
        let sid = crate::user::active_session() as usize;
        #[cfg(not(feature = "handles"))]
        let sid = 0usize;
        // S6q 补记三：窗口列表里"没关掉的有几项"决定标签条上画几项。
        #[cfg(feature = "handles")]
        let tabs = (0..crate::serial::SESSIONS).filter(|i| !self.closed[*i]).count() as u64;
        #[cfg(not(feature = "handles"))]
        let tabs = 1u64;
        let active = sid as u64;
        #[cfg(feature = "handles")]
        let chrome = if self.mins.get(sid).copied().unwrap_or(false) {
            crate::fbcon::Chrome::Minimized
        } else {
            self.chrome
        };
        #[cfg(not(feature = "handles"))]
        let chrome = self.chrome;
        (sid, tabs, active, chrome)
    }

    fn repaint(&mut self) {
        let rows = self.term.body_rows();
        let (sid, tabs, active, chrome) = self.layout();
        let chrome_changed = self.chrome != self.last_chrome || chrome != self.last_chrome;
        // S6q：**只有内容真的变了才画**。两档判据：
        //   · 换行数变了 / 换会话 / 换标签 ⇒ 整窗重画（正文真的动了）；
        //   · 只有尾部半行在长（换行数没变）⇒ **只重画输入行**（一个键不再拖整屏）；
        //   · 什么都没变 ⇒ 一个字都不写。指针与光标不在这两条判据里。
        let total = crate::serial::mirror_total_sid(sid);
        let nl = crate::serial::mirror_newlines_sid(sid);
        // S6t：**版面也进签名**。标签条 ⇄ 浮窗切换时环里的字节一个字没变，不这么写
        // 就要等下一次内容变化才换版面（实测过的那种"点了没反应"）。
        #[cfg(feature = "wm")]
        let lay = self.float;
        #[cfg(not(feature = "wm"))]
        let lay = false;
        let sig = (sid as u8, total, nl as u64, tabs, active, lay);
        // S6t：**浮窗里"只改 z 序/桌面"的点击不会动内容签名**，只看 `sig` 的话置顶永远
        // 不生效（实测：点 win0 标题后 base 与 raised 只差 120 个像素=光标与指针，
        // 而点关闭之后差 38610——因为关闭顺带改了内容）。所以把浮窗的脏判定也接进这一格。
        #[cfg(feature = "wm")]
        let need = sig != self.sig || chrome_changed || (self.float && self.wm_pending());
        #[cfg(not(feature = "wm"))]
        let need = sig != self.sig || chrome_changed;
        if need {
            // 先把指针的像素还回去（它盖住的那 77 个像素是上一帧的背景）；
            // 整窗重画也会覆盖它，但**输入行那一路只动一行**——行外的指针必须自己擦。
            self.ptr_erase();
            let incremental = !chrome_changed
                && self.sig.0 == sid as u8
                && self.sig.2 == nl as u64
                && self.sig.1 != usize::MAX
                && self.sig.5 == lay;
            #[cfg(feature = "wm")]
            let (cc, cr) = if self.float {
                self.wm_frame()
            } else {
                // 从浮窗切回来：窗口矩形之外的桌面没人负责，先把旧像素铺掉再画标签条版面。
                if self.sig.5 {
                    self.term.clear(&self.frame);
                    self.desk = (u64::MAX, false);
                }
                self.tabbed_frame(incremental, sid, tabs, active, chrome, rows)
            };
            #[cfg(not(feature = "wm"))]
            let (cc, cr) = self.tabbed_frame(incremental, sid, tabs, active, chrome, rows);
            self.sig = sig;
            self.last_chrome = chrome;
            // 画过的像素一律作废：光标靠下一相重画，指针靠下面 `ptr_track` 重画。
            self.caret = None;
            self.caret_at = if cr != 0 { Some((cc, cr)) } else { None };
            if incremental {
                self.paints.3 += 1;
            } else {
                self.paints.0 += 1;
            }
        }
        self.tick();
    }

    /// **一次节拍**（S6u）：指针、光标眨眼、点击拾取。这三样都不需要读内容签名——
    /// `mirror_newlines_sid` 每次要扫完整段环（最多 8 KiB），拿它当指针的节拍就是
    /// 用约 140 ms 的代价换约 16 ms 的观感。用户说的"鼠标移动卡顿"就是这个数。
    fn tick(&mut self) {
        let n = FRAMES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        // 眨眼：每 32 拍翻一次 ⇒ 约 0.5 s 亮／0.5 s 灭，与拆出来之前同速（原来是每 4 个
        // 约 140 ms 的轮次）。
        let on = (n / 32) % 2 == 0;
        // 光标：只翻那一格的三行半格宽（24 个像素），不再为一次眨眼重写整屏。
        match (on, self.caret, self.caret_at) {
            (true, None, Some((c, r))) => {
                self.term.caret(&self.frame, c, r);
                self.caret = Some((c, r));
                self.paints.2 += 1;
            }
            (false, Some((c, r)), _) => {
                self.term.caret_erase(&self.frame, c, r);
                self.caret = None;
                self.paints.2 += 1;
            }
            _ => {}
        }
        // 指针：位置变了才擦旧画新（保存/恢复 77 个背景像素）。
        #[cfg(feature = "ps2-mouse")]
        {
            self.ptr_track();
            // 点击的**打印在任务上下文**：`repaint` 只从两个等待循环里调，ISR 走不到这里。
            // 放在这里而不是只放常驻循环：**等待期也会点**（实测：只在 park 里取，
            // 等待期那几下点击就永远读不到）。
            if let Some((cx, cy)) = crate::mouse::take_click() {
                // S6t：**版面决定点击归谁**。默认是标签条版面 ⇒ 走 `hit_test` 与那套窗口动作；
                // 浮窗版面才走 `wm_click`（旧代码在 wm 档无条件走 wm_click，把标签条的动作全废了）。
                #[cfg(feature = "wm")]
                let float = self.float;
                #[cfg(not(feature = "wm"))]
                let float = false;
                // 注意 cfg 加在**调用语句**上：`float` 在两个档都存在（非 wm 档恒 false），
                // 但 `wm_click` 这个方法只在 wm 档有——不加就是 b721070 那个 cfg 洞的形状。
                #[cfg(feature = "wm")]
                let on_win = float && self.wm_click(cx, cy);
                #[cfg(not(feature = "wm"))]
                let on_win = false;
                let (_, tabs, _, chrome) = self.layout();
                let hit = if on_win {
                    crate::fbcon::Hit::Body
                } else {
                    crate::fbcon::hit_test(
                        self.term.dims().0, tabs, cx as u64, cy as u64, chrome)
                };
                crate::log_info!("mouse: 点击 x={} y={} 命中={}", cx, cy, hit.name());
                // S6q 补记二：三个窗口按钮**有动作了**——但各自的口径要写清楚：
                //   · `-` 最小化：正文整块收起（只留标签栏），再点一次恢复；
                //   · `□` 最大化：收起标签栏、正文从第 0 行开始（多一行），再点一次恢复；
                //   · `×` 关闭窗口：关掉那个会话，最后一个也关掉才停机（S6q 补记三裁决）。
                // 三态互斥且都可逆，所以"点错了"能点回来——不可逆的只有关闭。
                // S6t：这一套动作在**没被窗口收下**的点击上生效（浮窗里点窗口自带另一套动作）。
                if !on_win {
                    match hit {
                        crate::fbcon::Hit::Min => {
                            // 最小化时点标签就能恢复：标签栏一直画着，用户不会被困住。
                            self.chrome = if self.chrome == crate::fbcon::Chrome::Minimized {
                                crate::fbcon::Chrome::Normal
                            } else {
                                crate::fbcon::Chrome::Minimized
                            };
                            crate::log_info!("窗口: 最小化={}", self.chrome == crate::fbcon::Chrome::Minimized);
                        }
                        crate::fbcon::Hit::Max => {
                            self.chrome = if self.chrome == crate::fbcon::Chrome::Maximized {
                                crate::fbcon::Chrome::Normal
                            } else {
                                crate::fbcon::Chrome::Maximized
                            };
                            crate::log_info!("窗口: 最大化={}", self.chrome == crate::fbcon::Chrome::Maximized);
                        }
                        crate::fbcon::Hit::Close => {
                            crate::log_info!("窗口: 关闭 ⇒ 系统停机");
                            crate::exit::finish(crate::exit::Code::Success);
                        }
                        // S6q 补记三：**每个窗口条目**自己的 `-` 与 `×`。
                        crate::fbcon::Hit::TabMin(i) => {
                            let i = (i as usize).min(crate::serial::SESSIONS - 1);
                            self.mins[i] = !self.mins[i];
                            crate::log_info!("窗口: 会话 {} 最小化={}", i, self.mins[i]);
                        }
                        crate::fbcon::Hit::TabClose(i) => {
                            let i = i as usize;
                            if i == 0 {
                                // 0 号是 init：关它等于整机收工（与全局 `×` 同一口径）
                                crate::log_info!("窗口: 关闭会话 0（init）⇒ 系统停机");
                                crate::exit::finish(crate::exit::Code::Success);
                            } else if i < crate::serial::SESSIONS && !self.closed[i] {
                                // 关掉这个会话的任务，窗口从列表里消失；最后一个也关掉才停机。
                                // **记账**：内核按任务号终止，返回 false 说明槽已经不在了 ⇒ 如实打出来。
                                let g = SECOND_TASK.load(Ordering::Relaxed);
                                let killed = g != 0 && crate::sched::terminate_task(g);
                                self.closed[i] = true;
                                crate::log_info!("窗口: 关闭会话 {} 终止任务={} 任务={}", i, killed, g);
                                if crate::user::active_session() as usize == i {
                                    crate::user::set_active_session(0);
                                }
                                if self.closed.iter().filter(|c| **c).count() == crate::serial::SESSIONS {
                                    crate::log_info!("窗口: 全部关闭 ⇒ 系统停机");
                                    crate::exit::finish(crate::exit::Code::Success);
                                }
                            }
                        }
                        // S6t：标签条上的 `∨` **有动作了**——切换版面（标签条 ⇄ 浮窗）。
                        // 非 `wm` 档没有浮窗可切，只如实报读数，不假装切了。
                        crate::fbcon::Hit::Layout => {
                            #[cfg(feature = "wm")]
                            {
                                self.float = !self.float;
                                // 版面切换时把浮窗侧的两份签名作废：它们只在自己的版面里更新，
                                // 不作废的话切回去的那一帧 `wm_frame` 会判"没变"而一像素不写。
                                self.zsig = (u8::MAX, [0; crate::serial::SESSIONS]);
                                self.sigw = [(usize::MAX, usize::MAX); crate::serial::SESSIONS];
                                crate::log_info!("版面: 浮窗={}", self.float);
                            }
                            #[cfg(not(feature = "wm"))]
                            crate::log_info!("版面: 本档没有浮窗，切换无效");
                        }
                        _ => {}
                    }
                    // S6p：点在标签上就**切会话**；关闭符只记读数（0 号是 init，不能关）
                    #[cfg(feature = "handles")]
                    match hit {
                        crate::fbcon::Hit::Tab(i) => {
                            // 最小化时点标签 = 恢复正文（否则正文收着、用户只剩一个看不清的条）。
                            if self.chrome == crate::fbcon::Chrome::Minimized {
                                self.chrome = crate::fbcon::Chrome::Normal;
                                crate::log_info!("窗口: 最小化=false（点标签恢复）");
                            }
                            crate::user::set_active_session(i);
                            crate::log_info!("multisession: 切到会话 {}", i);
                        }
                        _ => {}
                    }
                }
            }
            // S6q：**不再每 8 帧打一行统计**。那一行日志本身就会让正文整窗重画一次
            // （每秒一次、约 94 万次 UC 写）⇒ 用户看到的"鼠标一直在闪"有一半是它造成的。
            // 读数改在收工那一刻报一次（`鼠标收工` 行），判据仍可复算。
            if n % 256 == 0 {
                // S6q：三本账——正文整画 / 指针重画 / 光标翻转各做了多少次。
                // 判据用它们证明"指针不再跟着整屏重画"（全画数应远小于帧数）。
                crate::log_info!(
                    "fbcon-live: 帧={} 整画={} 指针={} 光标={} 行画={}",
                    n, self.paints.0, self.paints.1, self.paints.2, self.paints.3
                );
            }
        }
    }

    /// **标签条版面**的重画（S6t 起的默认版面，与参考截图同构）：
    /// 换行数变了 ⇒ 整窗重画；只有尾部半行在长 ⇒ 只重画输入行。
    /// 浮窗版面（`self.float`）不走这里，它有自己的矩形重画。
    fn tabbed_frame(
        &self,
        incremental: bool,
        sid: usize,
        tabs: u64,
        active: u64,
        chrome: crate::fbcon::Chrome,
        rows: usize,
    ) -> (u64, u64) {
        if incremental {
            crate::fbcon::redraw_input(&self.term, &self.frame, rows.min(LIVE_ROWS), sid, chrome)
        } else {
            let (_, cc, cr) = crate::fbcon::redraw_window(
                &self.term, &self.frame, rows.min(LIVE_ROWS), sid, tabs, active, chrome);
            (cc, cr)
        }
    }

    /// **只重画一扇窗的矩形**（S6r）：标题栏一行 + 正文整块（每行补空格 ⇒ 矩形内是自足的）。
    /// 返回聚焦窗口的光标 `(列, 行)`（屏幕绝对行），非聚焦窗口返回 `(0,0)`。
    #[cfg(feature = "wm")]
    fn paint_win(&mut self, i: usize) -> (u64, u64) {
        use crate::fbcon::Term;
        let w = self.wins[i];
        let focused = crate::user::active_session() as usize == i;
        if let Some(t) = Term::at(&self.frame, w.x, w.y, w.cols, 1) {
            let title = if i == 0 { "Aurora shell" } else { "shell 1" };
            t.paint_title(&self.frame, title, focused);
        }
        let mut caret = (0u64, 0u64);
        if let Some(b) = w.body() {
            if let Some(t) = Term::at(&self.frame, b.x, b.y, b.cols, b.rows) {
                if self.mins[i] {
                    for r in 0..b.rows {
                        t.print_line(&self.frame, r, "");
                    }
                } else {
                    let (_, cc, cr) = crate::fbcon::redraw_window(
                        &t, &self.frame, b.rows as usize, i, 0, 0, crate::fbcon::Chrome::Floating);
                    if focused && cr != 0 {
                        caret = (cc, b.y + cr);
                    }
                }
            }
        }
        self.sigw[i] = (crate::serial::mirror_total_sid(i), crate::serial::mirror_newlines_sid(i));
        self.paints.0 += 1;
        caret
    }

    /// **浮窗点击**（S6r）：从最上面一扇往下找，第一个命中的窗口收下这次点击。
    /// 点标题栏/正文 = 置顶 + 聚焦；`-`/`□`/`×` 作用于**那扇窗**。
    /// 返回 `false` = 没落在任何窗上 ⇒ 调用方按**标签条版面**处理这一击（S6t：
    /// 浮窗模式下标签条仍然画着，`∨` 必须还能点，否则浮窗就是一扇单向门）。
    #[cfg(feature = "wm")]
    fn wm_click(&mut self, cx: i32, cy: i32) -> bool {
        use crate::fbcon::{win_hit, WinHit};
        for k in (0..crate::serial::SESSIONS).rev() {
            let i = self.z[k];
            if self.closed[i] {
                continue;
            }
            let hit = win_hit(self.wins[i], cx as u64, cy as u64);
            if hit == WinHit::None {
                continue;
            }
            // 置顶：把这扇窗挪到 z 数组末尾（z 序变了 ⇒ 下一帧整栈重排）
            for j in k..crate::serial::SESSIONS - 1 {
                self.z[j] = self.z[j + 1];
            }
            self.z[crate::serial::SESSIONS - 1] = i;
            if crate::user::active_session() as usize != i {
                crate::user::set_active_session(i as u8);
                crate::log_info!("wm: 聚焦窗口 {}", i);
            }
            match hit {
                WinHit::Min => {
                    if self.mins[i] {
                        self.wins[i] = self.saved[i];
                        self.mins[i] = false;
                    } else {
                        self.saved[i] = self.wins[i];
                        self.mins[i] = true;
                    }
                    crate::log_info!("wm: 窗口 {} 最小化={}", i, self.mins[i]);
                }
                WinHit::Max => {
                    let (cols, rows) = self.term.dims();
                    if self.wins[i].cols == cols && self.wins[i].y == 0 {
                        self.wins[i] = self.saved[i];
                        crate::log_info!("wm: 窗口 {} 还原", i);
                    } else {
                        self.saved[i] = self.wins[i];
                        self.wins[i] = crate::fbcon::WinRect { x: 0, y: 0, cols, rows };
                        crate::log_info!("wm: 窗口 {} 最大化", i);
                    }
                }
                WinHit::Close => {
                    if i == 0 {
                        crate::log_info!("wm: 关闭会话 0（init）⇒ 系统停机");
                        crate::exit::finish(crate::exit::Code::Success);
                    } else {
                        let g = SECOND_TASK.load(Ordering::Relaxed);
                        let killed = g != 0 && crate::sched::terminate_task(g);
                        self.closed[i] = true;
                        crate::log_info!("wm: 关闭窗口 {} 终止任务={}", i, killed);
                        crate::user::set_active_session(0);
                    }
                }
                _ => {}
            }
            return true;
        }
        false
    }

    /// **重画一扇窗 + 补它上面被它破坏的那些**（S6r 的核心口径）：
    /// 只重画矩形是省钱的，但压在这块矩形上的高 z 窗会被写花 ⇒ 按 z 序把它们**再画一遍**
    /// （画的是整矩形，不是交集——交集的簿记不值那点像素，两扇窗的重画仍然是全屏的零头）。
    #[cfg(feature = "wm")]
    fn repaint_stack(&mut self, from: usize) -> (u64, u64) {
        let mut caret = (0u64, 0u64);
        let rect = self.wins[from];
        let mut above = false;
        for k in 0..crate::serial::SESSIONS {
            let i = self.z[k];
            if self.closed[i] {
                continue;
            }
            if i == from {
                above = true;
                caret = self.paint_win(i);
            } else if above && crate::fbcon::WinRect::intersects(&self.wins[i], &rect) {
                let c = self.paint_win(i);
                if c != (0, 0) {
                    caret = c;
                }
            }
        }
        caret
    }

    /// 一帧的 WM 重画：内容变了才画那一扇（+ 补遮挡）；聚焦/z 变了就整栈重排（两扇，很便宜）。
    #[cfg(feature = "wm")]
    /// 浮窗版面**要不要画**：z 序、桌面（开着哪些窗 / 在不在浮窗）、任一扇窗的内容，
    /// 三者之一变了才画。`repaint` 与 `wm_frame` 共用这一份判定——两边各算一遍的话，
    /// "只改 z 序的置顶"就会在一边算成脏、在另一边算成干净。
    #[cfg(feature = "wm")]
    fn wm_pending(&self) -> bool {
        if (crate::user::active_session() as u8, self.z) != self.zsig {
            return true;
        }
        for i in 0..crate::serial::SESSIONS {
            if self.closed[i] {
                continue;
            }
            if (crate::serial::mirror_total_sid(i), crate::serial::mirror_newlines_sid(i))
                != self.sigw[i]
            {
                return true;
            }
        }
        self.wm_desk() != self.desk
    }

    /// 桌面签名：开着哪些窗（位图）+ 当前是不是浮窗版面。
    #[cfg(feature = "wm")]
    fn wm_desk(&self) -> (u64, bool) {
        let mask: u64 = (0..crate::serial::SESSIONS)
            .filter(|i| !self.closed[*i])
            .map(|i| 1u64 << i)
            .sum();
        (mask, true)
    }

    /// 浮窗版面的一帧：桌面（变了就重铺）→ 标签条 → 按 z 序从下往上画每扇窗的矩形。
    /// cfg 加在**定义**上（不是只加在调用点）——那是 b721070 的教训，这一片又踩了一次：
    /// 插两个新方法时把原来这行 `#[cfg]` 顶掉了，`fbcon-live` 无 `wm` 的档当场编不过，
    /// 而 `check` 17 道全是静态门禁，看不见这种跨特性断裂。
    #[cfg(feature = "wm")]
    fn wm_frame(&mut self) -> (u64, u64) {
        let active = crate::user::active_session() as u8;
        let desk = self.wm_desk();
        let desk_changed = desk != self.desk;
        if !self.wm_pending() {
            return (0, 0);
        }
        self.zsig = (active, self.z);
        self.desk = desk;
        // 桌面变了（关窗 / 切进来）⇒ 先重铺：关掉的窗与切走的版面已经不在任何矩形的负责
        // 范围里，不铺就把旧像素留在屏上。
        if desk_changed {
            self.term.clear(&self.frame);
        }
        // S6t：**浮窗模式下标签条仍然画着**。旧版把标签条整条收掉，于是浮窗是一扇单向门
        // ——`∨` 没了，切不回去（实测：第二次点同一格串口只有 `浮窗=true`、没有 `false`）。
        // 窗口从第 1 格行开始，与标签条那一行不重叠。
        let open = (0..crate::serial::SESSIONS)
            .filter(|i| !self.closed[*i])
            .count() as u64;
        self.term.tab_bar(&self.frame, open, active as u64);
        // 整栈从最下面一扇开始画；每扇只画自己的矩形 ⇒ 这就是"每扇窗只重画矩形"。
        let mut caret = (0u64, 0u64);
        for k in 0..crate::serial::SESSIONS {
            let i = self.z[k];
            if self.closed[i] {
                continue;
            }
            let c = self.paint_win(i);
            if c != (0, 0) {
                caret = c;
            }
        }
        caret
    }

    /// 指针跟随：位置变了才擦旧画新。**保存的背景是"画之前"的像素**（`get` 读回的原生值，
    /// 用 `put_raw` 原样写回），所以擦除不会做第二次 24→32 位打包（§S6b 的同一教训）。
    #[cfg(feature = "ps2-mouse")]
    fn ptr_track(&mut self) {
        let (px, py) = crate::mouse::pos();
        if self.ptr == Some((px, py)) {
            return;
        }
        self.ptr_erase();
        for r in 0..11usize {
            for c in 0..7usize {
                let (x, y) = (px + c as i32, py + r as i32);
                if x < 0 || y < 0 {
                    continue;
                }
                if let Ok(v) = self.frame.get(x as u64, y as u64) {
                    self.ptr_bg[r][c] = v;
                }
            }
        }
        self.term.draw_pointer(&self.frame, px, py);
        self.ptr = Some((px, py));
        self.paints.1 += 1;
    }

    fn ptr_erase(&mut self) {
        let Some((px, py)) = self.ptr.take() else { return };
        for r in 0..11usize {
            for c in 0..7usize {
                let (x, y) = (px + c as i32, py + r as i32);
                if x < 0 || y < 0 {
                    continue;
                }
                let _ = self.frame.put_raw(x as u64, y as u64, self.ptr_bg[r][c]);
            }
        }
    }
}

/// 实时重画的窗口行预算（一行 = 160 格 × 16 行设备写，画满 48 行会把一轮拉长）。
#[cfg(feature = "fbcon-live")]
const LIVE_ROWS: usize = 24;

/// 已经画过多少帧。光标闪烁按帧数除（常驻期一轮 8 窗口），鼠标跟手则靠轮询变勤。
#[cfg(feature = "fbcon-live")]
/// S6u：**节拍计数**（一拍 = 一次 `tick()`，常驻循环里约 16 ms）。
/// 拆之前它是"内容轮次"（约 140 ms 一轮），指针/光标/点击都跟着它 ⇒ 画面上的指针只有约 7 fps。
/// `fbcon-live: 帧=` 那行日志的**格式一字未动**，变的只是这个计数的单位——读数按
/// "帧≈16 ms"来读，别再拿它乘 140 ms。
static FRAMES: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// 当前拍数（常驻循环用它决定"这一拍要不要算内容签名"）。
/// cfg 跟着 `FRAMES` 走：那个静态量只在 `fbcon-live` 档存在。
#[cfg(feature = "fbcon-live")]
pub fn main_frames() -> usize {
    FRAMES.load(core::sync::atomic::Ordering::Relaxed)
}

/// S6d：`fbcon-live` 档的"等 init 收工 + 每轮重画一次屏"。
///
/// **为什么不新开等待语义**：用的还是同一个 `wait_for_task`，只是把一发 1000 窗口的上界拆成
/// 62 发 16 窗口 ⇒ 总上界不变、调度语义不变（`park_until_init_exits` 早就在用同一个形状）。
/// **映射只做一次**：`Frame::init()` 每次都真映射一遍 MMIO 窗口，轮询里反复映射既贵又要碰 VMM 锁。
/// 拿不到帧缓冲或几何时**退回一次性等待**并在串口上说清楚 ⇒ 特性退化是可见的，不是静默的。
#[cfg(all(feature = "fbcon-live", feature = "handles"))]
fn live_wait_and_redraw(gidx: usize, total_windows: u64) -> bool {
    const STEP: u64 = 16;
    let one_shot = |g: usize| apic::with_interrupts(|| sched::wait_for_task(g, crate::clock::window_cycles(total_windows)));
    let Some(mut live) = LiveTerm::open() else {
        crate::log_warn!("fbcon-live: 退回一次性等待（画面不会有键入内容）");
        return one_shot(gidx);
    };
    crate::log_info!(
        "fbcon-live: 活终端 正文行={} 窗口行={} 格={}x{}；实时重画已开 每轮窗口={}",
        live.term.body_rows(), live.term.body_rows().min(LIVE_ROWS),
        crate::fbcon::CELL_W, crate::fbcon::CELL_H, STEP
    );
    let mut left = total_windows;
    let mut rounds = 0usize;
    loop {
        let step = if left > STEP { STEP } else { left };
        if step == 0 {
            break;
        }
        left -= step;
        rounds += 1;
        if apic::with_interrupts(|| sched::wait_for_task(gidx, crate::clock::window_cycles(step))) {
            crate::log_info!("fbcon-live: 轮询={} 收工=init 自己退出", rounds);
            return true;
        }
        live.repaint();
    }
    crate::log_info!("fbcon-live: 轮询={} 收工=没有（等待上界到）", rounds);
    false
}

/// 用页表本身找一个确定未映射的页：先问 `mm::is_mapped`，不再靠区间算术推断。
/// 取到即登记，堆窗口之后不可能再拿到同一页。
fn pick_probe_addr() -> Option<u64> {
    mm::alloc_va_page().map(|v| v.0)
}

// ------------------------------------------------------------------ 用例

// ---------------------------------------------------------------- M2 内存用例

// ---------------------------------------------------------------- ACPI 用例

// ---------------------------------------------------------------- M3a：中断

/// **幂等**的标定：已经标定过就直接回读数。
///
/// 为什么要有这个函数而不是让用例自己标定：AP 的本地定时器初值要用 `tsc_hz` 反推，
/// 而 `.ktests` 的枚举顺序由链接顺序决定、不由源码顺序决定。把"谁先跑"当成前提
/// 就等于写一个偶发的"AP 起不来"。所以 `smp::bringup` 自己补一次标定，
/// 用例也走同一个入口——两个调用点，一份实现。
pub fn calibrate_clock_once() -> Option<clock::Calibration> {
    if let Some(c) = clock::current() {
        return Some(c);
    }
    let s = acpi::summary()?;
    let m = s.madt?;
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("clock: APIC 起不来，标定无从谈起");
        return None;
    }
    if apic::timer_start().is_err() {
        crate::log_fatal!("clock: cannot start timer");
        return None;
    }
    // 窗口里**一行日志都不打**：串口按字节忙等，一次输出就是几十毫秒，
    // 期间必然跳过好几个 tick，而"观察到的相邻间隔"会把漏掉的 tick 算成更长的周期
    // （第一次标定报 4.78 GHz 就是这么来的）。
    let base_ticks = apic::reset_tick_stats();
    // 窗口按 cycles 给上界，样本目标 20 次；上界 `window_cycles(MIN_SAMPLES)` 是
    // "任何可信 TSC 都至少能数到 MIN_SAMPLES 次"的那个长度（推导见 clock::window_cycles）。
    // 原先这里写的是 `r < 4000` 轮：KVM 对照档实测同一颗 QEMU 只换 accel，
    // 4000 轮在 tcg 档值 2.08 亿 cycles（数到 6 个 tick）、在 kvm 档只值 1.01 亿（数到 4 个），
    // 样本数正好压在门槛上——第一次调用 3 个就报 NoSamples，第二次同样代码却有 4 个。
    let w = apic::wait_ticks(base_ticks, 20, clock::window_cycles(clock::MIN_SAMPLES));
    apic::timer_stop().ok();
    let inv = cpuid::detect().tsc_inv;
    let ints = apic::tick_delta_sum();
    let cal = match clock::from_pit_window(w.cycles, w.ticks, apic::tick_delta_max_cycles(), ints, inv) {
        Ok(c) => c,
        Err(e) => {
            crate::log_fatal!("clock: calibration refused: {:?}", e);
            return None;
        }
    };
    crate::log_info!(
        "clock: {} ticks in {} cycles -> tsc_hz={} Hz, tick ~ {:?} us, max_gap={} (PIT divisor {} Hz/{} Hz, invariant={}) 窗口={} cycles 轮数={}",
        cal.samples, w.cycles, cal.tsc_hz, clock::micros(cal.tick_period_cycles),
        apic::tick_delta_max_cycles(), clock::PIT_HZ, clock::PIT_DIVISOR, inv,
        clock::window_cycles(clock::MIN_SAMPLES), w.rounds
    );
    // 两把尺子并排印出来：窗口均值（含两端切掉的半段，必然偏高）与 ISR 自己量的相邻间隔均值。
    // 那条硬不等式在 `clock::from_pit_window` 里判——红起来是标定当场拒，不是一个打印出来的数。
    crate::log_info!(
        "clock 两把尺子: 窗口 total={} ÷ ticks={} ⇒ 窗口均值={}；ISR 相邻间隔 n={} 和={} ⇒ 均值={}（估计器用后者）；容许区间={}..{}（上界=和+2×每 tick 最长 {} cycles）",
        w.cycles, cal.samples, w.cycles / cal.samples as u64,
        cal.interval_n, ints.0, cal.interval_mean,
        ints.0, ints.0 + 2 * clock::max_tick_period_cycles(), clock::max_tick_period_cycles(),
    );
    Some(cal)
}


// ---------------------------------------------------------------- M3b：多核

// ---------------------------------------------------------------- M4：用户态

/// P2 的采样次数与单条测量的窗口（写成模块级常量，`p2_one` 是被测闭包的通用包装，
/// 闭包参数不能是 `impl Trait` ⇒ 只能做成泛型函数而不是嵌套闭包）
const P2_SAMPLES: u64 = 64;

fn p2_one<F: Fn()>(inner: F) -> (u64, u64, u64) {
    let (mut sum, mut mn, mut mx) = (0u64, u64::MAX, 0u64);
    for _ in 0..P2_SAMPLES {
        let a = tsc::now();
        inner();
        let d = tsc::now().wrapping_sub(a);
        sum += d;
        mn = mn.min(d);
        mx = mx.max(d);
    }
    (sum / P2_SAMPLES, mn, mx)
}

/// §12.4 的 P2：`DriverCtx` 一次 MMIO 读 / 一次 MMIO 写 / 一次 DMA 映射+撤销的往返开销。
/// 手册给它的理由是"§8.5 那条'同一份驱动代码迁到用户态'到底要付多少"——没有这一行，
/// §2.4 那张表里"微内核的 IPC 代价"那一列就永远是修辞。
///
/// 三条线之外还有一条 `p2 ruler`：同一次测量做 1 遍与做 4 遍，`min` 必须按比例走。
/// 不按比例说明这把尺子量的不是这件事（§12.4.1 规则 3：先证明量具能分辨，再谈数字）。
fn p2_probe() {
    let Some(dev) = pci::first_of_triple(0x01, 0x06, 0x01) else {
        crate::log_warn!("p2: 枚举表里没有 SATA-AHCI 设备，这条基线出不了数");
        return;
    };
    // 自己认领一份 ctx（owner 用 MOD_TEST：这条探针不是驱动的一部分，不该记到驱动台账上）。
    // 用完必须撤销，否则 `mm counters` 与句柄表占用会把"探针跑过"当成常态状态留给后面的读数。
    let ctx = driver::DriverCtx::for_device(mm::MOD_TEST, dev);
    let Ok(h) = ctx.map_mmio(5) else {
        crate::log_warn!("p2: 映射 BAR5 失败，这条基线出不了数");
        return;
    };
    // 写方向选 `GHC`：先读回当前值再原样写回去，这一格是幂等的（AE 已经置着，
    // 绝不能测 `HR`——那位一写就是整个控制器复位，会把 AHCI 的端口全打回复位态）
    let ghc = ctx.read32(h, ahci::REG_GHC).unwrap_or(0);
    let (rd_mean, rd_min, rd_max) = p2_one(|| {
        core::hint::black_box(ctx.read32(h, ahci::REG_CAP).unwrap_or(0));
    });
    let (wr_mean, wr_min, wr_max) = p2_one(|| {
        core::hint::black_box(ctx.write32(h, ahci::REG_GHC, ghc).is_err());
    });
    let (dma_mean, dma_min, dma_max) = p2_one(|| {
        if let Ok(d) = ctx.alloc_dma(mm::PAGE) {
            core::hint::black_box(ctx.bus_addr(d).unwrap_or(0));
            ctx.release_dma(d).ok();
        }
    });
    // 尺子自证：一次读 vs 连着四次读。四次里省掉的是两次 `tsc::now()`，
    // 所以要求不是严格的 4 倍，而是"至少两倍"——连两倍都不到就说明这两次测量
    // 测的是同一个别的东西（比如被外层循环摊平了）
    let (_, four_min, _) = p2_one(|| {
        for _ in 0..4 {
            core::hint::black_box(ctx.read32(h, ahci::REG_CAP).unwrap_or(0));
        }
    });
    let ruler_ok = four_min > rd_min.saturating_mul(2);
    ctx.release_mmio(h).ok();
    crate::log_info!(
        "p2 mmio-rd: samples={} mean={} min={} max={} cycles",
        P2_SAMPLES,
        rd_mean,
        rd_min,
        rd_max
    );
    crate::log_info!("p2 mmio-wr: samples={} mean={} min={} max={} cycles", P2_SAMPLES, wr_mean, wr_min, wr_max);
    crate::log_info!("p2 dma: samples={} mean={} min={} max={} cycles", P2_SAMPLES, dma_mean, dma_min, dma_max);
    crate::log_info!(
        "p2 ruler: 1次min={} 4次min={} 比值x100={} 能分辨={}",
        rd_min,
        four_min,
        four_min.saturating_mul(100) / rd_min.max(1),
        ruler_ok
    );
    if !ruler_ok {
        crate::log_fatal!("p2: 这把尺子分辨不出 1 次与 4 次，上面的数字不能当基线用");
    }
}









