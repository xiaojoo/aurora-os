//! S6c：PS/2 键盘（i8042 控制器 + IRQ1）。
//!
//! **三条刻意的形状，每条都对应一条这个仓库踩过的坑**：
//!
//! 1. **字符环住在 `kbd`，`user`（capability）来读**——不是反过来。`diagnostics` 里已经有
//!    `serial`，`kbd` 与它同家，于是 `capability -> diagnostics`、`diagnostics -> irq/arch`
//!    这些边全部早就存在 ⇒ **零新边、零新环**（§245 的教训：先问这条边会不会成环）。
//! 2. **端口读写复用 `serial::out8/in8`**，本文件不写 `asm!` ⇒ **零新增 unsafe 站点**，
//!    不动 unsafe 白名单与普查。
//! 3. **ISR 只搬字节进环，绝不解码成"动作"、绝不打印、绝不取锁**——和串口 RX 同一条纪律；
//!    解码是纯函数 [`step`]，所以它能被用例直接测（也是这条判据的负样本靶子）。
//!
//! **本片只解 make 码，且不处理 shift/caps**：画面/串口上出的是小写字母与符号。
//! 组合键、扩展集（方向键等 E0 序列）、其他布局**没做**，计数器会如实报 `扩展未映射`，
//! 不假装支持（AGENTS 硬约束⑦：不得夸大结论）。

use crate::arch::x86_64::apic;
use crate::serial::{in8, out8};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

const KBD_DATA: u16 = 0x60;
const KBD_CMD: u16 = 0x64;
/// 状态位：bit0 = 输出缓冲区有数据可读，bit1 = 输入缓冲区可写
const STS_OBF: u8 = 0x01;
const STS_IBF: u8 = 0x02;
/// ISA 键盘 IRQ。IRQ1 由键盘独占（串口是 IRQ4，S5a 已经打通过一次同一形状）。
const KBD_IRQ: u8 = 1;
/// 控制器级命令（写 0x64）：0x20 把命令字节原样放回 0x60，读得到也验得了。
/// **这里故意不发 0xAD/0xAE**：那两位是"关/开第一个 PS/2 口"，0xAD 会把键盘关掉，
/// 而且本机实测发完 0xAD 等不到任何回包 ⇒ PortTimeout（run-982）。接口状态不问控制器
/// 的意图，只读它自己的命令字节；读到没开就报错，不写、不猜、不"试试看"。
const CMD_RD_CMD_BYTE: u8 = 0x20;
/// 命令字节的位（与 Linux i8042.h 同一命名）：bit0 键盘中断允许、bit1 鼠标中断允许、
/// bit2/3 忽略键盘/鼠标、bit4 键盘口禁用、bit5 鼠标口禁用、bit6/7 集 2→集 1 转换。
/// 本机实测读回 0x67 = `ATT1|AUXDIS|IGNKEY|KBDINT` ⇒ 键盘口是开的、中断是允许的。
const CTR_KBDDIS: u8 = 0x10;
const CTR_KBDINT: u8 = 0x01;
/// 设备级命令（写 0x60）：0xF4 让键盘开始扫描；设备 ACK = 0xFA
const KBD_ENABLE_SCANNING: u8 = 0xF4;
const ACK: u8 = 0xFA;

const RING_CAP: usize = 64;
/// 键入**字符**环（不是扫描码环）：解码在 ISR 里做完，因为它是纯算术、不分支到内存。
static RING: [AtomicU8; RING_CAP] = [const { AtomicU8::new(0) }; RING_CAP];
static HEAD: AtomicUsize = AtomicUsize::new(0);
static TAIL: AtomicUsize = AtomicUsize::new(0);
static ON: AtomicBool = AtomicBool::new(false);
/// 上一条是不是 `0xE0` 前缀。只在 ISR 里读写，且 ISR 不嵌套同一 IRQ ⇒ 单所有者。
static EXT: AtomicBool = AtomicBool::new(false);
/// Ctrl 是否按着（S6q）。左 Ctrl 的 make/break 是 `0x1D`/`0x9D`，
/// 右 Ctrl 是 `E0 1D`/`E0 9D`——两种都在 `sc` 那一层看得到，所以只看这两个字节。
/// **只在 ISR 里读写**（同 `EXT`，ISR 不嵌套同一个 IRQ ⇒ 单所有者）。
static CTRL: AtomicBool = AtomicBool::new(false);

// 八格读数，一格一个成因——"收到了但没解出来"和"根本没收到"必须分得开
static BYTES: AtomicUsize = AtomicUsize::new(0);
static IRQS: AtomicUsize = AtomicUsize::new(0);
static PUSHED: AtomicUsize = AtomicUsize::new(0);
static DROPPED: AtomicUsize = AtomicUsize::new(0);
static BREAKS: AtomicUsize = AtomicUsize::new(0);
static EXT_SEQ: AtomicUsize = AtomicUsize::new(0);
/// 扩展序列里被吃掉的后缀字节（`0xF0` 与真码各算一个）。有这一格，账才能闭合。
static SWALLOWED: AtomicUsize = AtomicUsize::new(0);
static UNMAPPED: AtomicUsize = AtomicUsize::new(0);

/// 开启成功时交出的**原值**：接口到底开没开、中断到底允许没允许，由日志里这两字节的
/// 位自己说；`dev_ack` 是设备对 0xF4 的实际回包。
#[derive(Debug)]
pub struct EnableInfo {
    pub cmd_byte: u8,
    pub kbd_enabled: bool,
    pub irq_enabled: bool,
    pub dev_ack: u8,
    /// 发第一条命令之前从输出缓冲区里排掉的字节数。控制器可能早就存了一个上电包，
    /// 不排干净的话第一个读到的"命令字节"其实是那个包——读数会假。
    pub preflush: usize,
}

#[derive(Debug)]
pub enum KbdError {
    /// 上下文不对：ISR 里或不是 BSP。路由 IOAPIC 只能在 BSP 的任务上下文做（同串口那条）
    WrongContext,
    /// APIC 还没起来
    NotReady,
    /// 端口等待超时（控制器不理会我们的命令，或那一问根本没有回包）
    PortTimeout,
    /// 命令字节的 bit4 说键盘口被禁 ⇒ 本片没有写命令字节的手段，直接报错并交出原值
    PortDisabled(u8),
    /// 命令字节的 bit3 说键盘中断没允许 ⇒ 同上，不假装路由好了就能收包
    IrqDisabled(u8),
    /// 设备回了字节但不是 ACK —— 把实际字节报出来，别只说"失败"
    NotAck(u8),
    /// IRQ 认领不了（槽位满 / 向量耗尽）
    Irq(crate::irq::IrqError),
    /// APIC 起不来，或 MADT 里查不到 IRQ1 的 GSI、那条 RTE 不被接受
    Apic(crate::arch::x86_64::apic::ApicError),
}

/// scan code set 1 的 make 码 → 字符。`0` = 本片不映射（含 Ctrl/Shift/Alt/F1-12/小键盘）。
/// 表由脚本按布局生成，不手打——手打 128 个数错一个，表现是"某个键悄悄不出现"。
const CHAR_MAP: [u8; 128] = [
    0x00, 0x1B, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x2D, 0x3D, 0x7F, 0x09,
    0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6F, 0x70, 0x5B, 0x5D, 0x0D, 0x00, 0x61, 0x73,
    0x64, 0x66, 0x67, 0x68, 0x6A, 0x6B, 0x6C, 0x3B, 0x27, 0x60, 0x00, 0x5C, 0x7A, 0x78, 0x63, 0x76,
    0x62, 0x6E, 0x6D, 0x2C, 0x2E, 0x2F, 0x00, 0x2A, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// 一个扫描码字节的归类。ISR 的账目**只由它决定**——如果 ISR 自己再看一遍 bit7，
    /// 那"解码器把 break 当 make"这类错就永远不会在环那一侧露出来（本机实测：变异 N1
    /// 注入后 `入环` 仍是 19，因为 ISR 的重复过滤把错误遮住了）。所以这里做成单一证人。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// `0xE0` 前缀本身：只置状态，不出字符
    ExtPrefix,
    /// 扩展序列的后缀（`0xF0` 那一拍与载荷字节）：吃掉，不出字符
    ExtTail,
    /// break 码（松开）：计数，不出字符
    Break,
    /// 解出了一个字符
    Char(u8),
    /// 表里没有的 make 码：计数，**不猜**
    Unmapped,
}

/// 纯解码：给定"上一条是不是 `0xE0` 前缀"与本字节，返回新的前缀状态与本字节的归类。
///
/// **它被单独拎出来是为了可测**：`t_ps2_kbd_decode` 直接喂序列，不需要真键盘。
/// 三条规则各自都是一条判据，也各自都是负样本的靶子：
/// - `0xE0` 只置前缀、**不出字符**；前缀之后的字节（含 `0xF0` 这一拍）只吞不判，
///   否则松开右 Shift 的 `E0 F0 12` 会把 `12` 当普通 make 码解成 'e'；
/// - make 码 `& 0x80 != 0` 是 **break 码**，必须**不出字符**
///   （把它当 make 的后果是"按一下出两个字符"，而它在串口上看起来完全像"键盘能用"）；
/// - 表里没有的码计数后返回 None，**不猜**。
pub fn step(prev_ext: bool, sc: u8) -> (bool, Code) {
    if sc == 0xE0 {
        return (true, Code::ExtPrefix);
    }
    if prev_ext {
        // 扩展序列（方向键、Home 等）：本片不解码，但要数得出来。
        // `0xF0` 是扩展 break 的前缀，后面还有一拍真码，所以这一拍**保持扩展态**；
        // 其余字节吃掉并复位。少了这个区分，`E0 F0 12` 的最后一拍会被当普通 make 解出字符。
        return (sc == 0xF0, Code::ExtTail);
    }
    if sc & 0x80 != 0 {
        return (false, Code::Break);
    }
    let c = CHAR_MAP[sc as usize];
    if c == 0 {
        return (false, Code::Unmapped);
    }
    (false, Code::Char(c))
}

/// Ctrl + 字母 ⇒ 控制码（`c & 0x1F`；Ctrl+C = `0x03`）。
///
/// **只对字母生效**：Ctrl+数字/符号在不同终端里不一致，本片不猜（与 `CHAR_MAP`
/// "表里没有就不映射"同一条纪律）。Shift 仍然没做（`CHAR_MAP` 只有小写这一套）。
pub fn apply_ctrl(ctrl: bool, c: u8) -> u8 {
    if ctrl && c.is_ascii_lowercase() {
        c & 0x1F
    } else {
        c
    }
}

/// 往 `port` 发一个字节，再取回对方放在 0x60 的那个字节（命令字节或 ACK）。
/// 输入缓冲区**非空**不可写（bit1=1 表示还在忙），所以这里判的是 `== 0`，
/// 不能复用串口那条 `wait_for`——它等的是"某位置位"，方向正好相反。
fn xfer(port: u16, v: u8, spins: usize) -> Result<u8, KbdError> {
    for _ in 0..spins {
        if in8(KBD_CMD) & STS_IBF == 0 {
            out8(port, v);
            for _ in 0..spins {
                if in8(KBD_CMD) & STS_OBF != 0 {
                    return Ok(in8(KBD_DATA));
                }
            }
            return Err(KbdError::PortTimeout);
        }
    }
    Err(KbdError::PortTimeout)
}

/// ISR：只搬字节。返回 `false` 表示"不是我这条线的数据"（与串口同一约定）。
pub fn kbd_isr() -> bool {
    if !ON.load(Ordering::Relaxed) {
        return false;
    }
    IRQS.fetch_add(1, Ordering::Relaxed);
    let st = in8(KBD_CMD);
    if st & STS_OBF == 0 {
        return false;
    }
    // **0x60 是两个设备共用的**：状态位 bit5（0x20）说这个字节来自鼠标口。
    // 键盘 ISR 只吃 bit5=0 的字节，否则它会把鼠标包当成扫描码吃掉（S6o 实测：
    // 指针第一下能到 (760,400)、之后就丢包 —— 因为字节被键盘抢走了）。
    if st & 0x20 != 0 {
        return false;
    }
    let sc = in8(KBD_DATA);
    BYTES.fetch_add(1, Ordering::Relaxed);
    // Ctrl 的按下/松开（S6q）：这两个字节本身仍按 Unmapped/Break 记账，
    // 账目一格不动，只是多记一个"修饰键现在按着没"。
    match sc {
        0x1D => CTRL.store(true, Ordering::Relaxed),
        0x9D => CTRL.store(false, Ordering::Relaxed),
        _ => {}
    }
    let prev = EXT.load(Ordering::Relaxed);
    let (now_ext, code) = step(prev, sc);
    EXT.store(now_ext, Ordering::Relaxed);
    // **分账**：一个字节只落进一格，于是 `字节 = 入环 + 丢弃 + break + 扩展 + 吞掉 + 不映射`
    // 是一条宿主机能独立复算的闭合判据；缺任何一格，等式就先在那一格上咬人。
    // 这一格只问 `code`，**不再自己判 bit7**——否则解码器错了也量不出来。
    match code {
        Code::ExtPrefix => {
            EXT_SEQ.fetch_add(1, Ordering::Relaxed);
        }
        Code::ExtTail => {
            SWALLOWED.fetch_add(1, Ordering::Relaxed);
        }
        Code::Break => {
            BREAKS.fetch_add(1, Ordering::Relaxed);
        }
        Code::Unmapped => {
            // 表里没有的 make 码（Ctrl、F1-F12、小键盘那些）计数后什么都不做，**不猜**
            UNMAPPED.fetch_add(1, Ordering::Relaxed);
        }
        Code::Char(c) => {
            // S6q：Ctrl 按着就把字母压成控制码（Ctrl+C = 0x03）。账目不变：
            // 这个字节仍然只落进"入环"这一格，只是入环的**值**是控制码。
            let c = apply_ctrl(CTRL.load(Ordering::Relaxed), c);
            let h = HEAD.load(Ordering::Relaxed);
            if (h + 1) % RING_CAP == TAIL.load(Ordering::Relaxed) {
                DROPPED.fetch_add(1, Ordering::Relaxed);   // 环满：丢新键并计数，不覆盖、不等待
            } else {
                RING[h].store(c, Ordering::Relaxed);
                HEAD.store((h + 1) % RING_CAP, Ordering::Release);
                PUSHED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    true
}

/// 开键盘：认领 IRQ1 → 路由 IOAPIC → 读命令字节核对 → 让键盘开始扫描。
/// 任一步失败都返回**具体**错误（含实际读到的字节），不降级成"键盘不能用就算了"。
pub fn enable(m: &crate::acpi::Madt) -> Result<EnableInfo, KbdError> {
    use crate::arch::x86_64::cpu;
    if apic::in_isr() || cpu::self_slot() != 0 {
        return Err(KbdError::WrongContext);
    }
    // 幂等：第二次进来不重发命令也不重复认领，交出的读数与首跑同一口径
    if ON.load(Ordering::Acquire) {
        let cmd_byte = xfer(KBD_CMD, CMD_RD_CMD_BYTE, 20000)?;
        return Ok(EnableInfo {
            cmd_byte,
            kbd_enabled: cmd_byte & CTR_KBDDIS == 0,
            irq_enabled: cmd_byte & CTR_KBDINT != 0,
            dev_ack: 0,
            preflush: 0,
        });
    }
    apic::get_or_init(m).map_err(KbdError::Apic)?;
    let h = crate::irq::request(crate::mm::MOD_BOOT, kbd_isr).map_err(KbdError::Irq)?;
    // 撤销顺序：路由失败要先把刚认领的槽还回去，不然就是一次静默的泄漏
    // （串口那条用"连续拒绝 16 次仍能认领"来暴露这类泄漏，这里同一形状）
    if let Err(e) = apic::ioapic_route(m, KBD_IRQ, h.vector) {
        crate::irq::release(crate::mm::MOD_BOOT, h).map_err(KbdError::Irq)?;
        return Err(KbdError::Apic(e));
    }
    // 先置开关再命令：0xF4 之后键盘可能立刻吐包，晚置会把第一个键丢掉
    ON.store(true, Ordering::Release);
    let r = (|| -> Result<EnableInfo, KbdError> {
        let mut preflush = 0usize;
        while preflush < 16 && in8(KBD_CMD) & STS_OBF != 0 {
            let _ = in8(KBD_DATA);
            preflush += 1;
        }
        let cmd_byte = xfer(KBD_CMD, CMD_RD_CMD_BYTE, 20000)?;
        if cmd_byte & CTR_KBDDIS != 0 {
            return Err(KbdError::PortDisabled(cmd_byte));
        }
        if cmd_byte & CTR_KBDINT == 0 {
            return Err(KbdError::IrqDisabled(cmd_byte));
        }
        let dev_ack = xfer(KBD_DATA, KBD_ENABLE_SCANNING, 20000)?;
        if dev_ack != ACK {
            return Err(KbdError::NotAck(dev_ack));
        }
        Ok(EnableInfo {
            cmd_byte,
            kbd_enabled: true,
            irq_enabled: true,
            dev_ack,
            preflush,
        })
    })();
    match r {
        Ok(info) => Ok(info),
        Err(e) => {
            ON.store(false, Ordering::Release);
            crate::irq::release(crate::mm::MOD_BOOT, h).map_err(KbdError::Irq)?;
            Err(e)
        }
    }
}

pub fn enabled() -> bool {
    ON.load(Ordering::Acquire)
}

/// 取一个键入字符。`user::sys_console_io` 的读路径先取串口环、再取这里（零新 syscall，
/// 裁决见 ADR-083 决策 5）。
pub fn read_char() -> Option<u8> {
    let t = TAIL.load(Ordering::Relaxed);
    if t == HEAD.load(Ordering::Acquire) {
        return None;
    }
    let b = RING[t].load(Ordering::Relaxed);
    TAIL.store((t + 1) % RING_CAP, Ordering::Release);
    Some(b)
}

/// `(收到字节, ISR 次数, 入环字符, 环满丢弃, break 码, E0 前缀, 表内未映射, 环内排队)`
pub fn stats() -> (usize, usize, usize, usize, usize, usize, usize, usize, usize) {
    let h = HEAD.load(Ordering::Acquire);
    let t = TAIL.load(Ordering::Relaxed);
    (
        BYTES.load(Ordering::Relaxed),
        IRQS.load(Ordering::Relaxed),
        PUSHED.load(Ordering::Relaxed),
        DROPPED.load(Ordering::Relaxed),
        BREAKS.load(Ordering::Relaxed),
        EXT_SEQ.load(Ordering::Relaxed),
        SWALLOWED.load(Ordering::Relaxed),
        UNMAPPED.load(Ordering::Relaxed),
        (h + RING_CAP - t) % RING_CAP,
    )
}

/// 环容量。用例与日志都要用它来判"排队数有没有越界"，别在断言里再写一遍 64。
pub fn ring_cap() -> usize {
    RING_CAP
}
