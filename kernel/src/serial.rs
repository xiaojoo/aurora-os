//! 16550 串口收发：启动日志与控制台输入（手册 §4.5）。
//!
//! 端口 I/O 属 unsafe；`aurora-kernel` 已整体登记在 `docs/security/unsafe-whitelist.toml`
//! （垂直切片阶段的临时状态，§2.5 拆 crate 后由 aurora-arch/aurora-hw 承接）。

use core::fmt;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

const COM1: u16 = 0x3f8;
const R_DATA: u16 = 0;
const R_IER: u16 = 1;
const R_FCR: u16 = 2;
const R_LCR: u16 = 3;
const R_MCR: u16 = 4;
const R_LSR: u16 = 5;
const LSR_DATA: u8 = 0x01;
const LSR_THRE: u8 = 0x20;

#[inline]
pub fn out8(port: u16, v: u8) {
    // SAFETY: `out` 只做端口写，不访问内存、不影响 Rust 可观测状态；端口号由本模块常量给出。
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) }
}

#[inline]
pub fn in8(port: u16) -> u8 {
    let v: u8;
    // SAFETY: `in` 同上。
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)) };
    v
}

/// 串口自检是否通过。**这是本文件存在的核心理由**：如果日志通道其实是哑的，
/// 后面每一条“成功”日志都是假证据，所以必须先证明它能收能发。
static READY: AtomicBool = AtomicBool::new(false);
static TICK: AtomicU64 = AtomicU64::new(0);
/// 实际发出的字节数。
///
/// **这条在 QEMU 上不等于时间**，本机实测：一次启动 total=486,387,919 cycles 约 145 ms
/// （按标定的 3.35 GHz），而同期发了 7,325 字节——真 115200 波特要 637 ms，比整个启动还长。
/// 所以 QEMU 的串口后端不按波特率节流，LSR.THRE 几乎立刻可读。字节数因此是
/// **真机成本的代理量**（真机上 1 字节约 87 us），不是本机的实测耗时；
/// 原来这里写着日志自己就是启动时间的大头，那句在 QEMU 上不成立，已按实测改正。
static BYTES_OUT: AtomicU64 = AtomicU64::new(0);

pub fn bytes_out() -> u64 {
    BYTES_OUT.load(Ordering::Relaxed)
}

/// §9.7"最近日志"的落点：环形缓冲是格式化输出的**旁路拷贝**，不是第二条日志通道。
/// 4096 字节按本机平均行长 ≈130 B 算约 30 行，一次崩溃只取最近 `LOG_TEXT_MAX` 字节。
/// 之所以旁路在 `READY` 检查**之前**：环要量的不是"串口响不响"，而是"内核临终前说了什么"——
/// 真机上串口坏掉那一档恰恰是唯一还需要这份记录的场合（§9.7 的持久化 crash dump）。
pub const RING_LEN: usize = 4096;
static RING: [AtomicU8; RING_LEN] = [const { AtomicU8::new(0) }; RING_LEN];
/// 逻辑写字节数（不取模）：它决定"最近 N 字节"从哪儿开始回看。
static RING_POS: AtomicU64 = AtomicU64::new(0);

/// 一段"最近的整行日志"。
#[derive(Clone, Copy, Debug, Default)]
pub struct Tail {
    pub lines: u32,
    pub bytes: u32,
}

#[inline]
fn ring_push(b: u8) {
    let i = RING_POS.fetch_add(1, Ordering::Relaxed) as usize % RING_LEN;
    RING[i].store(b, Ordering::Relaxed);
}

/// 从环里取"最近的一段，且必须是整行"。规则两条都不许含糊：
/// ① 开头那个被截断的半行**丢掉**，不从半行中间开始；② 结尾若不是换行，把那一行也**丢掉**。
/// 所以返回值只可能是 0 行或若干完整行；装不下的老行自然落选，绝不截半行（半行会伪装成
/// 一条没打完的日志）。`out` 按时间顺序填，宿主机拿去与串口原文逐行比。
pub fn recent_tail(out: &mut [u8]) -> Tail {
    let total = RING_POS.load(Ordering::Relaxed) as usize;
    let want = total.min(RING_LEN).min(out.len());
    if want == 0 {
        return Tail::default();
    }
    let base = total - want;
    for (i, o) in out.iter_mut().enumerate().take(want) {
        *o = RING[(base + i) % RING_LEN].load(Ordering::Relaxed);
    }
    // ① 跳到第一个换行之后：换行前面的那半行不属于这一段
    let mut start = 0;
    while start < want && out[start] != b'\n' {
        start += 1;
    }
    start += 1;
    // ② 从后往前找到最后一个换行：它之后就是半行，不要
    let mut end = want;
    while end > start && out[end - 1] != b'\n' {
        end -= 1;
    }
    if end <= start {
        return Tail::default();
    }
    let lines = out[start..end].iter().filter(|b| **b == b'\n').count() as u32;
    if start != 0 {
        out.copy_within(start..end, 0);
    }
    Tail { lines, bytes: (end - start) as u32 }
}

/// 环里累计过多少字节（用例用它确认"我打的那几行真的进了环"）。
pub fn ring_total() -> u64 {
    RING_POS.load(Ordering::Relaxed)
}

/// 只给用例：把环清零，好让"我打了 N 行"这件事与前面整个启动的日志分开。
pub fn ring_reset_for_test() {
    RING_POS.store(0, Ordering::Relaxed);
    for slot in RING.iter() {
        slot.store(0, Ordering::Relaxed);
    }
}

pub fn init() {
    out8(COM1 + R_IER, 0x00);
    out8(COM1 + R_LCR, 0x80); // DLAB=1
    out8(COM1 + R_DATA, 0x01); // 115200 baud -> divisor 1 (low)
    out8(COM1 + R_IER, 0x00); // divisor high
    out8(COM1 + R_LCR, 0x03); // 8n1
    out8(COM1 + R_FCR, 0xc7); // FIFO on, 64B trigger, reset FIFO
    out8(COM1 + R_MCR, 0x0b); // DTR | RTS | OUT2

    // 回环自测：置 LOOP，写 0x5a 再读回。读不到就认定串口不可用，
    // 后续所有 line() 都成 no-op —— 判定契约因此不会把“没输出”误读成“输出正常”。
    out8(COM1 + R_MCR, 0x1e); // LOOP | OUT2
    out8(COM1 + R_DATA, 0x5a);
    let mut ok = false;
    for _ in 0..1000 {
        if in8(COM1 + R_LSR) & LSR_DATA != 0 && in8(COM1 + R_DATA) == 0x5a {
            ok = true;
            break;
        }
        core::hint::spin_loop();
    }
    out8(COM1 + R_MCR, 0x0b);
    READY.store(ok, Ordering::Release);
}

// BSP ISR 单生产者、一个任务消费者；留一格区分满与空。
const RX_CAP: usize = 256;
const RX_ISR_BUDGET: usize = 8;
static RX_BUDGET_HITS: AtomicUsize = AtomicUsize::new(0);
static RX_BUF: [AtomicU8; RX_CAP] = [const { AtomicU8::new(0) }; RX_CAP];
static RX_HEAD: AtomicUsize = AtomicUsize::new(0); // ISR 写
static RX_TAIL: AtomicUsize = AtomicUsize::new(0); // 读者写
static RX_DROPPED: AtomicUsize = AtomicUsize::new(0);
static RX_BYTES: AtomicUsize = AtomicUsize::new(0);
static RX_IRQS: AtomicUsize = AtomicUsize::new(0);
static RX_ON: AtomicBool = AtomicBool::new(false);
const SERIAL_IRQ: u8 = 4;

#[derive(Debug)]
pub enum RxError {
    NotReady,
    WrongContext,
    Apic(crate::arch::x86_64::apic::ApicError),
    Irq(crate::irq::IrqError),
}

fn rx_isr() -> bool {
    if !RX_ON.load(Ordering::Relaxed) {
        return false;
    }
    // 临时撤下 UART IRQ，预算用尽后重新使能仍能生成下一条边沿。
    out8(COM1 + R_IER, 0);
    RX_IRQS.fetch_add(1, Ordering::Relaxed);
    let mut taken = 0;
    for _ in 0..RX_ISR_BUDGET {
        if in8(COM1 + R_LSR) & LSR_DATA == 0 {
            break;
        }
        let b = in8(COM1 + R_DATA);
        let h = RX_HEAD.load(Ordering::Relaxed);
        let t = RX_TAIL.load(Ordering::Acquire);
        if (h + 1) % RX_CAP == t {
            RX_DROPPED.fetch_add(1, Ordering::Relaxed);
        } else {
            RX_BUF[h].store(b, Ordering::Relaxed);
            RX_HEAD.store((h + 1) % RX_CAP, Ordering::Release);
            RX_BYTES.fetch_add(1, Ordering::Relaxed);
        }
        taken += 1;
    }
    if taken == RX_ISR_BUDGET && in8(COM1 + R_LSR) & LSR_DATA != 0 {
        RX_BUDGET_HITS.fetch_add(1, Ordering::Relaxed);
    }
    out8(COM1 + R_IER, 1);
    taken != 0
}

pub fn rx_budget_hits() -> usize {
    RX_BUDGET_HITS.load(Ordering::Relaxed)
}

pub fn enable_rx(m: &crate::acpi::Madt) -> Result<(), RxError> {
    use crate::arch::x86_64::{apic, cpu};
    if apic::in_isr() || cpu::self_slot() != 0 {
        return Err(RxError::WrongContext);
    }
    if RX_ON.load(Ordering::Acquire) {
        return Ok(());
    }
    if !is_ready() {
        return Err(RxError::NotReady);
    }
    apic::get_or_init(m).map_err(RxError::Apic)?;
    let h = crate::irq::request(crate::mm::MOD_BOOT, rx_isr).map_err(RxError::Irq)?;
    if let Err(e) = apic::ioapic_route(m, SERIAL_IRQ, h.vector) {
        crate::irq::release(crate::mm::MOD_BOOT, h).map_err(RxError::Irq)?;
        return Err(RxError::Apic(e));
    }
    RX_ON.store(true, Ordering::Release);
    out8(COM1 + R_IER, 1);
    Ok(())
}

/// 只供一个任务消费者调用；空队列立即返回 None。
pub fn read_byte() -> Option<u8> {
    let t = RX_TAIL.load(Ordering::Relaxed);
    if t == RX_HEAD.load(Ordering::Acquire) {
        return None;
    }
    let b = RX_BUF[t].load(Ordering::Relaxed);
    RX_TAIL.store((t + 1) % RX_CAP, Ordering::Release);
    Some(b)
}

/// 入环字节 / 软件溢出丢弃 / ISR 次数 / 当前排队字节；不含 UART 硬件错误。
pub fn rx_stats() -> (usize, usize, usize, usize) {
    let h = RX_HEAD.load(Ordering::Acquire);
    let t = RX_TAIL.load(Ordering::Relaxed);
    (
        RX_BYTES.load(Ordering::Relaxed),
        RX_DROPPED.load(Ordering::Relaxed),
        RX_IRQS.load(Ordering::Relaxed),
        (h + RX_CAP - t) % RX_CAP,
    )
}

pub fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}

fn putb(b: u8) -> bool {
    // 环先收：它记的是"内核说了什么"，串口那一头还有"发出去了没有"这一关（下面那个有界等待
    // 超时时会真的丢字节）。两边只在串口丢字节时分叉，而那时判据红的就是真故障。
    ring_push(b);
    if !is_ready() {
        return false;
    }
    // 有界等待：真硬件卡住时不能无限自旋（会撞 §9.6 看门狗，且没有任何输出）
    for _ in 0..1_000_000 {
        if in8(COM1 + R_LSR) & LSR_THRE != 0 {
            out8(COM1 + R_DATA, b);
            BYTES_OUT.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

pub fn write_bytes(bytes: &[u8]) -> usize {
    let guard = acquire_line();
    if !guard.held {
        return 0;
    }
    let mut done = 0;
    for &b in bytes {
        if !putb(b) {
            break;
        }
        done += 1;
    }
    // S6d：控制台的字节流也进同一个环 ⇒ 画面镜像的是"控制台上真看到的东西"，不只是内核日志。
    // 只旁挂**真写出去的那一截**（`done`），串口因背压少写的字节不该在画面上假装存在。
    #[cfg(feature = "framebuffer")]
    mirror_bytes(&bytes[..done]);
    done
}

fn putstr(s: &[u8]) {
    for b in s {
        putb(*b);
    }
}

struct Sink;

impl Write for Sink {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        putstr(s.as_bytes());
        #[cfg(feature = "framebuffer")]
        crate::serial::mirror_note(s);
        Ok(())
    }
}

// ------------------------------------------------------------------ S6b-3 日志镜像的字节环
//
// **为什么环住在 `serial`（diagnostics）而不是 `fbcon`（display）**：`fbcon` 自己要用
// `log_info!` 打日志 ⇒ `display -> diagnostics` 这条边本来就在。若让 serial 反过来调
// `fbcon::note_bytes`，就凭空造出一个真环——第三次尝试就是这么被 `check-module-interfaces`
// 的 `known_scc` 基线拦下的（BACKLOG §244）。环放在这里，边保持单向；画图由 `main` 的
// tail 阶段驱动（integration 两边都允许依赖）。
//
// 用 `AtomicU8` 数组而不是 `UnsafeCell`：原子数组自带内部可变性 ⇒ **零新增 unsafe 站点**，
// 也就不动白名单。
const MIRROR_BYTES: usize = 8192;
static MIRROR: [AtomicU8; MIRROR_BYTES] = [const { AtomicU8::new(0) }; MIRROR_BYTES];
/// 单调写入计数（不回绕）。写入位置 = `MIRROR_POS % MIRROR_BYTES` ⇒ **循环覆写**：
/// 判据要的是最后几行，而"填满即弃"留下的恰好是最老的字节（§244 实测 `丢弃=29666`，方向相反）。
static MIRROR_POS: AtomicUsize = AtomicUsize::new(0);

/// 旁挂一段日志正文。由 `Sink::write_str` 调用，**只存字节、绝不画图**：
/// 画一行是上万次设备写，而调用点持有串口行锁——在锁里做设备写等于把锁的暴露面撑大。
pub fn mirror_note(s: &str) {
    mirror_bytes(s.as_bytes());
}

/// 旁挂一段**字节流**。控制台的写出走这里而不是 `mirror_note`：20 号交来的是一段字节，
/// 硬转成 `&str` 会把非 UTF-8 的写变成"悄悄少几个字节"，那种丢法没有读数。
pub fn mirror_bytes(b: &[u8]) {
    for &x in b {
        mirror_note_byte(x);
    }
}

/// 打一个行尾。换行是 `line()` 用 `putb` 直接写串口的、**不经过 `Sink`**，所以必须单独通知：
/// 不通知的话环里一个换行都没有，整场启动被当成"一行"，一行也画不出（§244 实测）。
pub fn mirror_note_break() {
    mirror_note_byte(10);
}

fn mirror_note_byte(b: u8) {
    let i = MIRROR_POS.fetch_add(1, Ordering::Relaxed);
    MIRROR[i % MIRROR_BYTES].store(b, Ordering::Relaxed);
}

/// 环里现存多少字节（不超过容量）。
pub fn mirror_len() -> usize {
    MIRROR_POS.load(Ordering::Relaxed).min(MIRROR_BYTES)
}

/// 开机以来旁挂过的总字节数。和 `mirror_len` 一起报才看得出"环绕过没有"。
pub fn mirror_total() -> usize {
    MIRROR_POS.load(Ordering::Relaxed)
}

/// 读现存窗口第 `i` 个字节。**绕回之后窗口逻辑起点不是 0**，偏移在这里算：
/// 让调用方去猜的表现是画出一条半截日志，而它看起来完全像"镜像对了"。
pub fn mirror_byte(i: usize) -> u8 {
    let total = MIRROR_POS.load(Ordering::Relaxed);
    let start = total - total.min(MIRROR_BYTES);
    MIRROR[(start + i) % MIRROR_BYTES].load(Ordering::Relaxed)
}

/// 窗口开头那一截是不是上一行的**残片**（只有环绕过才是）。消费方必须丢掉它。
pub fn mirror_wrapped() -> bool {
    MIRROR_POS.load(Ordering::Relaxed) > MIRROR_BYTES
}

/// 行锁：一次一行。持有者 = CPU 槽号 + 1，`0` = 空闲。
///
/// 为什么不用"关中断打一行"这个更简单的形状：真机 115200 波特下一行 ≈130 字节 ≈11 ms
/// 的中断关闭窗口，那是不能接受的代价。本机 QEMU 的串口后端不节流，所以这个选择在
/// 这台机上量不出差别——写下来是因为它是纪律，不是因为这里有读数。
static OWNER: AtomicUsize = AtomicUsize::new(0);
/// 四本账，一本一个成因：拿到锁 / 发现别人占着而等待 / 同 CPU 重入 / 等待到期。
static HOLDS: AtomicUsize = AtomicUsize::new(0);
static CONTENDED: AtomicUsize = AtomicUsize::new(0);
static NESTED: AtomicUsize = AtomicUsize::new(0);
static TIMEOUTS: AtomicUsize = AtomicUsize::new(0);
/// L4 出口那条路：停机前说的话一行都不能丢，所以不再排队。
static HALTING: AtomicBool = AtomicBool::new(false);

const LINE_WAIT_MAX: u32 = 2_000_000;

struct LineGuard {
    held: bool,
}

fn acquire_line() -> LineGuard {
    if HALTING.load(Ordering::Relaxed) {
        return LineGuard { held: false };
    }
    let me = crate::arch::x86_64::cpu::self_slot() + 1;
    if OWNER.compare_exchange(0, me, Ordering::Acquire, Ordering::Relaxed).is_ok() {
        HOLDS.fetch_add(1, Ordering::Relaxed);
        return LineGuard { held: true };
    }
    if OWNER.load(Ordering::Relaxed) == me {
        // 同一个 CPU 重入——今天只有"在中断里打印"能走到这里，而那条禁令由 §6.5 的探测器守着。
        // 这里**不**阻塞：阻塞就是拿自己的锁等自己，会当场死锁。
        NESTED.fetch_add(1, Ordering::Relaxed);
        LineGuard { held: false }
    } else {
        CONTENDED.fetch_add(1, Ordering::Relaxed);
        for _ in 0..LINE_WAIT_MAX {
            if OWNER.compare_exchange(0, me, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                HOLDS.fetch_add(1, Ordering::Relaxed);
                return LineGuard { held: true };
            }
            core::hint::spin_loop();
        }
        // 等不到也照样打：通道的可用性排在行的整齐前面，而超时的成因由 `timeouts` 报出来
        TIMEOUTS.fetch_add(1, Ordering::Relaxed);
        LineGuard { held: false }
    }
}

impl Drop for LineGuard {
    fn drop(&mut self) {
        if self.held {
            OWNER.store(0, Ordering::Release);
        }
    }
}

/// 行锁的四本账。`owner` 与 `halting` 是现场，不是计数——"用完归还"这类断言要读它们。
#[derive(Clone, Copy, Debug, Default)]
pub struct LineStats {
    pub holds: usize,
    pub contended: usize,
    pub nested: usize,
    pub timeouts: usize,
    pub owner: usize,
    pub halting: bool,
}

pub fn line_stats() -> LineStats {
    LineStats {
        holds: HOLDS.load(Ordering::Relaxed),
        contended: CONTENDED.load(Ordering::Relaxed),
        nested: NESTED.load(Ordering::Relaxed),
        timeouts: TIMEOUTS.load(Ordering::Relaxed),
        owner: OWNER.load(Ordering::Relaxed),
        halting: HALTING.load(Ordering::Relaxed),
    }
}

/// 只给用例：四本账与两个现场归零，好让"这一段里涨了几次"有起点。
pub fn line_stats_reset() {
    for a in [&HOLDS, &CONTENDED, &NESTED, &TIMEOUTS, &OWNER] {
        a.store(0, Ordering::Relaxed);
    }
}

/// 停机路径用：此后打印不再排队。放在 `exit::finish(ExceptionFatal)` 的第一批动作里，
/// 因为崩溃现场那几行正是最需要整行、也最没有别人来抢的一段话。
pub fn unlock_for_halt() {
    OWNER.store(0, Ordering::Release);
    HALTING.store(true, Ordering::Release);
}

/// 一行日志：`[级别] 序号 正文`。序号在行锁**里面**取——不然两个 CPU 的序号会与其出现
/// 顺序错开，宿主机就少了"整条日志的序号列严格递增"这一把尺子。
pub fn line(level: &str, args: fmt::Arguments<'_>) {
    let _g = acquire_line();
    let seq = TICK.fetch_add(1, Ordering::Relaxed);
    putstr(b"[");
    putstr(level.as_bytes());
    putstr(b"] ");
    hex32(seq as u32);
    putstr(b" ");
    // fmt 不会失败（无分配、Sink 恒返回 Ok），仍不用 expect（§2.5 lint: expect_used=deny）
    let _ = Sink.write_fmt(args);
    putb(b'\n');
    // 行尾必须单独通知镜像环：换行是这一行直接写串口的、不经过 `Sink`。
    // 漏了它的表现不是报错，而是环里一个换行都没有、整场启动被当成"一行"，一行也画不出
    // （§244 实测 `总行数=1 画上=0 丢弃=29666`）。
    #[cfg(feature = "framebuffer")]
    crate::serial::mirror_note_break();
}

macro_rules! hex_impl {
    ($name:ident, $t:ty, $n:expr) => {
        pub fn $name(v: $t) {
            const D: &[u8; 16] = b"0123456789abcdef";
            putstr(b"0x");
            for i in (0..$n).rev() {
                putb(D[((v >> (i * 4)) & 0xf) as usize]);
            }
        }
    };
}
hex_impl!(hex32, u32, 8);

// 宏由 #[macro_export] 暴露到 crate 根
/// info 级日志一行。
#[macro_export]
macro_rules! log_info {
    ($($a:tt)*) => { $crate::serial::line("info", format_args!($($a)*)) };
}
// 宏由 #[macro_export] 暴露到 crate 根
/// warn 级日志一行。
#[macro_export]
macro_rules! log_warn {
    ($($a:tt)*) => { $crate::serial::line("warn", format_args!($($a)*)) };
}
// 宏由 #[macro_export] 暴露到 crate 根
/// fatal 级日志一行。
#[macro_export]
macro_rules! log_fatal {
    ($($a:tt)*) => { $crate::serial::line("fatal", format_args!($($a)*)) };
}
