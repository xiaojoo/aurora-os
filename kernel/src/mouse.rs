//! S6o：PS/2 鼠标（i8042 第二口 + IRQ12）——屏幕指针与点击命中。
//!
//! 与键盘（`kbd.rs`）同一套形状，差别只有三处，每处都是实测决定的：
//! 1. **命令字节必须写**：本机读回 0x67（`ATT1|AUXDIS|IGNKEY|KBDINT`）⇒ 鼠标口**是关的**
//!    （bit5=AUXDIS）、鼠标中断也没允许（bit1）⇒ 必须把它改成 `0x47`（清 AUXDIS、置 AUXINT）。
//!    键盘那条不用写，是因为它的口本来就开着（§246）；
//! 2. 设备命令要先发 `0xD4`（"下一字节写给 aux 口"）再发 `0xF6`/`0xF4`；
//! 3. 数据是**3 字节包**，首字节 bit3 恒 1（同步位）。同步失败就丢这个字节，
//!    不要把它当包首——错位之后会一直错位，表现为"指针自己乱跑"。
//!
//! **ISR 只做三件事**：攒包、更新原子量（位置/按钮/脏标记）、记一次点击。不打印、不取锁。
//! 打印是**任务上下文**的事（park 循环每轮取一次），因为串口行锁不能在 ISR 里拿。

use crate::arch::x86_64::apic;
use crate::serial::{in8, out8};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, AtomicUsize, Ordering};

const KBD_DATA: u16 = 0x60;
const KBD_CMD: u16 = 0x64;
const STS_OBF: u8 = 0x01;
const STS_IBF: u8 = 0x02;
/// 鼠标的 IRQ 是 12（键盘是 1）
pub const MOUSE_IRQ: u8 = 12;

const CMD_RD_CMD_BYTE: u8 = 0x20;
const CMD_WR_CMD_BYTE: u8 = 0x60;
const CMD_WRITE_AUX: u8 = 0xD4;
const CTR_AUXDIS: u8 = 0x20;
const CTR_AUXINT: u8 = 0x02;
const MOUSE_SET_DEFAULTS: u8 = 0xF6;
const MOUSE_ENABLE_REPORTING: u8 = 0xF4;
const ACK: u8 = 0xFA;

#[derive(Debug)]
pub enum MouseError {
    WrongContext,
    PortTimeout,
    WriteDenied(u8),
    PortDisabled(u8),
    IrqDisabled(u8),
    NotAck(u8),
    Irq(crate::irq::IrqError),
    Apic(crate::arch::x86_64::apic::ApicError),
}

/// 开启成功时交出的**原值**（与键盘同一口径：读数自己说话，不让代码的意图说话）。
#[derive(Debug)]
pub struct EnableInfo {
    pub cmd_before: u8,
    pub cmd_after: u8,
    pub dev_ack: u8,
}

static ON: AtomicBool = AtomicBool::new(false);
/// 指针位置（屏幕像素）。初始在屏幕中心，由 `set_bounds` 在开启时定。
static X: AtomicI32 = AtomicI32::new(0);
static Y: AtomicI32 = AtomicI32::new(0);
static W: AtomicU32 = AtomicU32::new(0);
static H: AtomicU32 = AtomicU32::new(0);
/// 当前按键位（bit0 左、bit1 右、bit2 中），与 PS/2 包首字节同序。
static BTNS: AtomicU8 = AtomicU8::new(0);
/// 位置变过就置位；画面侧取走并清零。
static MOVED: AtomicBool = AtomicBool::new(false);

// 3 字节包的攒包状态。只在 ISR 里读写（同一 IRQ 不嵌套）⇒ 单所有者。
static PKT: [AtomicU8; 3] = [const { AtomicU8::new(0) }; 3];
static PKT_IDX: AtomicUsize = AtomicUsize::new(0);
static BAD_SYNC: AtomicUsize = AtomicUsize::new(0);
static PACKETS: AtomicUsize = AtomicUsize::new(0);

/// 一次按下事件的记录（由 ISR 写、任务上下文取走打印）。
static CLICK_X: AtomicI32 = AtomicI32::new(0);
static CLICK_Y: AtomicI32 = AtomicI32::new(0);
static CLICK_PENDING: AtomicBool = AtomicBool::new(false);
static CLICKS: AtomicUsize = AtomicUsize::new(0);

/// 给**aux 设备**发一条命令：`0xD4`（下一字节写给鼠标）→ 设备命令 → 等设备的 ACK。
///
/// 控制器对 `0xD4` 自己回不回 `0xFA` 是实现相关的（本机 QEMU 实测**不回**，写成"等 ACK"
/// 会 20 ms 后 PortTimeout）。所以发完 0xD4 只把可能存在的杂字节排掉，判据放在**设备**的回包上。
fn aux_cmd(v: u8, spins: usize) -> Result<u8, MouseError> {
    for _ in 0..spins {
        if in8(KBD_CMD) & STS_IBF == 0 {
            out8(KBD_CMD, CMD_WRITE_AUX);
            break;
        }
    }
    // 排掉 0xD4 自己的回包（如果有）
    let mut drained = 0;
    while drained < 2 && in8(KBD_CMD) & STS_OBF != 0 {
        let _ = in8(KBD_DATA);
        drained += 1;
    }
    xfer(KBD_DATA, v, spins).map_err(|_| MouseError::WriteDenied(v))
}

fn xfer(port: u16, v: u8, spins: usize) -> Result<u8, MouseError> {
    for _ in 0..spins {
        if in8(KBD_CMD) & STS_IBF == 0 {
            out8(port, v);
            for _ in 0..spins {
                if in8(KBD_CMD) & STS_OBF != 0 {
                    return Ok(in8(KBD_DATA));
                }
            }
            return Err(MouseError::PortTimeout);
        }
    }
    Err(MouseError::PortTimeout)
}

/// 只取一段 3 字节包的解码（纯函数，可测）：返回 `(dx, dy, buttons, 是否合法包)`。
///
/// `dy` 已经**反号**：PS/2 的 y 越大越向上，屏幕坐标是向下为正。
pub fn decode(p0: u8, p1: u8, p2: u8) -> Option<(i32, i32, u8)> {
    if p0 & 0x08 == 0 {
        return None; // 同步位不对：不是包首
    }
    let dx = if p0 & 0x10 != 0 {
        -((256 - p1 as i32) & 0xFF)
    } else {
        p1 as i32
    };
    let dy_raw = if p0 & 0x20 != 0 {
        -((256 - p2 as i32) & 0xFF)
    } else {
        p2 as i32
    };
    Some((dx, -dy_raw, p0 & 0x07))
}

fn clamp(v: i32, hi: u32) -> i32 {
    if v < 0 {
        0
    } else if v as u32 >= hi {
        (hi as i32) - 1
    } else {
        v
    }
}

/// IRQ12：只攒包与更新原子量。
pub fn isr() -> bool {
    if !ON.load(Ordering::Relaxed) {
        return false;
    }
    let st = in8(KBD_CMD);
    if st & STS_OBF == 0 {
        return false;
    }
    // 共用 0x60：状态位 bit5=1 才是鼠标口的字节（键盘 ISR 也按同一口径分流）。
    if st & 0x20 == 0 {
        return false;
    }
    let b = in8(KBD_DATA);
    let idx = PKT_IDX.load(Ordering::Relaxed);
    PKT[idx].store(b, Ordering::Relaxed);
    let next = (idx + 1) % 3;
    PKT_IDX.store(next, Ordering::Relaxed);
    if next != 0 {
        return true;
    }
    PACKETS.fetch_add(1, Ordering::Relaxed);
    let p0 = PKT[0].load(Ordering::Relaxed);
    let p1 = PKT[1].load(Ordering::Relaxed);
    let p2 = PKT[2].load(Ordering::Relaxed);
    let Some((dx, dy, btns)) = decode(p0, p1, p2) else {
        BAD_SYNC.fetch_add(1, Ordering::Relaxed);
        return true;
    };
    let w = W.load(Ordering::Relaxed);
    let h = H.load(Ordering::Relaxed);
    if w == 0 || h == 0 {
        return true;
    }
    let nx = clamp(X.load(Ordering::Relaxed) + dx, w);
    let ny = clamp(Y.load(Ordering::Relaxed) + dy, h);
    X.store(nx, Ordering::Relaxed);
    Y.store(ny, Ordering::Relaxed);
    MOVED.store(true, Ordering::Relaxed);
    let prev = BTNS.swap(btns, Ordering::Relaxed);
    // 按下沿（bit0 左键）才记一次点击：按住不放不会刷屏
    if btns & 0x01 != 0 && prev & 0x01 == 0 {
        CLICK_X.store(nx, Ordering::Relaxed);
        CLICK_Y.store(ny, Ordering::Relaxed);
        CLICK_PENDING.store(true, Ordering::Relaxed);
        CLICKS.fetch_add(1, Ordering::Relaxed);
    }
    true
}

/// 当前按键字节（bit0 = 左键按下）。**拖动要用"按住"这一格**：
/// 点击事件只在按下沿发一次，拖动的中间帧只能靠轮询这个状态。
pub fn buttons() -> u8 {
    BTNS.load(Ordering::Relaxed)
}

/// 指针位置与"有没有动过"（画面侧每帧读）。
pub fn pos() -> (i32, i32) {
    (X.load(Ordering::Relaxed), Y.load(Ordering::Relaxed))
}

/// 取走"动过"标记。
pub fn take_moved() -> bool {
    MOVED.swap(false, Ordering::Relaxed)
}

/// 取走一次点击（任务上下文用；返回 (x, y)）。
pub fn take_click() -> Option<(i32, i32)> {
    if !CLICK_PENDING.swap(false, Ordering::Relaxed) {
        return None;
    }
    Some((CLICK_X.load(Ordering::Relaxed), CLICK_Y.load(Ordering::Relaxed)))
}

pub fn stats() -> (usize, usize, usize, usize) {
    (
        PACKETS.load(Ordering::Relaxed),
        BAD_SYNC.load(Ordering::Relaxed),
        CLICKS.load(Ordering::Relaxed),
        PKT_IDX.load(Ordering::Relaxed),
    )
}

/// 开鼠标：认领 IRQ12 → 路由 IOAPIC → 改命令字节（开 aux 口与 aux 中断）→ 让鼠标开始上报。
pub fn enable(m: &crate::acpi::Madt, w: u32, h: u32) -> Result<EnableInfo, MouseError> {
    use crate::arch::x86_64::cpu;
    if apic::in_isr() || cpu::self_slot() != 0 {
        return Err(MouseError::WrongContext);
    }
    apic::get_or_init(m).map_err(MouseError::Apic)?;
    let slot = crate::irq::request(crate::mm::MOD_BOOT, isr).map_err(MouseError::Irq)?;
    if let Err(e) = apic::ioapic_route(m, MOUSE_IRQ, slot.vector) {
        crate::irq::release(crate::mm::MOD_BOOT, slot).map_err(MouseError::Irq)?;
        return Err(MouseError::Apic(e));
    }
    W.store(w, Ordering::Relaxed);
    H.store(h, Ordering::Relaxed);
    X.store((w / 2) as i32, Ordering::Relaxed);
    Y.store((h / 2) as i32, Ordering::Relaxed);
    ON.store(true, Ordering::Release);

    let r = (|| -> Result<EnableInfo, MouseError> {
        // 排空输出缓冲区（里面可能有键盘/鼠标的旧包）
        let mut flushed = 0;
        while flushed < 16 && in8(KBD_CMD) & STS_OBF != 0 {
            let _ = in8(KBD_DATA);
            flushed += 1;
        }
        let cmd_before = xfer(KBD_CMD, CMD_RD_CMD_BYTE, 20000)
            .map_err(|_| MouseError::WriteDenied(0x20))?;
        if cmd_before & CTR_AUXDIS != 0 || cmd_before & CTR_AUXINT == 0 {
            let want = (cmd_before & !CTR_AUXDIS) | CTR_AUXINT;
            // **0x60 这一条不等 ACK**：控制器对"写命令字节"回不回 0xFA 是实现相关的
            // （本机 QEMU 实测不回 ⇒ 原来的写法 20 ms 后 PortTimeout）。写完**用 0x20 读回来核对**
            // 才是可信的证据 —— 与键盘那条"读命令字节"同一口径。
            for _ in 0..20000 {
                if in8(KBD_CMD) & STS_IBF == 0 {
                    break;
                }
            }
            out8(KBD_CMD, CMD_WR_CMD_BYTE);
            out8(KBD_DATA, want);
            let mut drained = 0;
            while drained < 8 && in8(KBD_CMD) & STS_OBF != 0 {
                let _ = in8(KBD_DATA);
                drained += 1;
            }
        }
        let cmd_after = xfer(KBD_CMD, CMD_RD_CMD_BYTE, 20000)
            .map_err(|_| MouseError::WriteDenied(0x21))?;
        if cmd_after & CTR_AUXDIS != 0 {
            return Err(MouseError::PortDisabled(cmd_after));
        }
        if cmd_after & CTR_AUXINT == 0 {
            return Err(MouseError::IrqDisabled(cmd_after));
        }
        // 0xF6：恢复默认；0xF4：开始上报。**设备**的 ACK 才是判据；
        // 控制器对 0xD4 本身回不回 ACK 是实现相关的（本机 QEMU 实测不回 ⇒ 不等它）。
        let a1 = aux_cmd(MOUSE_SET_DEFAULTS, 20000)?;
        let a2 = aux_cmd(MOUSE_ENABLE_REPORTING, 20000)?;
        if a1 != ACK {
            return Err(MouseError::NotAck(a1));
        }
        if a2 != ACK {
            return Err(MouseError::NotAck(a2));
        }
        Ok(EnableInfo {
            cmd_before,
            cmd_after,
            dev_ack: a2,
        })
    })();
    match r {
        Ok(info) => Ok(info),
        Err(e) => {
            ON.store(false, Ordering::Release);
            crate::irq::release(crate::mm::MOD_BOOT, slot).map_err(MouseError::Irq)?;
            Err(e)
        }
    }
}
