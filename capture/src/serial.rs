//! Crash-only COM serial output and QEMU debugexit. No main-kernel services are used.

use core::sync::atomic::{AtomicU16, Ordering};

const DEFAULT_PORT: u16 = 0x3f8;
const DEBUGEXIT_PORT: u16 = 0xf4;
const FATAL_CODE: u8 = 0x13;
const LSR: u16 = 5;
const LSR_THRE: u8 = 1 << 5;
const SPIN_LIMIT: u32 = 100_000;

static PORT: AtomicU16 = AtomicU16::new(DEFAULT_PORT);

/// Selects the already-configured debug serial port supplied by the main kernel.
pub fn select(port: u16) {
    if port != 0 {
        PORT.store(port, Ordering::Relaxed);
    }
}

/// Initializes a standard 16550-compatible UART at 115200 8N1 without interrupts.
pub fn init(port: u16) {
    select(port);
    let base = PORT.load(Ordering::Relaxed);
    outb(base + 1, 0);
    outb(base + 3, 0x80);
    outb(base, 1);
    outb(base + 1, 0);
    outb(base + 3, 0x03);
    outb(base + 2, 0xc7);
    outb(base + 4, 0x0b);
}

pub fn line(stage: &str, message: &str) {
    out_str("[capture] ");
    out_str(stage);
    out_str(": ");
    out_str(message);
    out_str("\n");
}

pub fn value(label: &str, value: u64) {
    out_str(label);
    out_str("=0x");
    out_hex(value);
    out_str("\n");
}

pub fn fatal(reason: &str) -> ! {
    line("fatal", reason);
    outb(DEBUGEXIT_PORT, FATAL_CODE);
    halt();
}

fn out_str(text: &str) {
    for &byte in text.as_bytes() {
        outb(PORT.load(Ordering::Relaxed), byte);
    }
}

fn out_hex(mut value: u64) {
    let mut digits = [0u8; 16];
    let mut count = 0;
    loop {
        let digit = (value & 0xf) as u8;
        digits[count] = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
        count += 1;
        value >>= 4;
        if value == 0 || count == digits.len() {
            break;
        }
    }
    while count != 0 {
        count -= 1;
        outb(PORT.load(Ordering::Relaxed), digits[count]);
    }
}

fn outb(port: u16, value: u8) {
    // The UART has no useful recovery action if it is absent. Bound the THRE wait so a
    // broken serial device cannot turn a fatal capture into an unbounded hang.
    let mut spins = 0;
    while spins < SPIN_LIMIT {
        if inb(port + LSR) & LSR_THRE != 0 {
            break;
        }
        spins += 1;
        core::hint::spin_loop();
    }
    // SAFETY: `port` is the validated/debug 16550 I/O port and all accesses are ring-0
    // port I/O. No memory is dereferenced and the caller keeps interrupts disabled.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nostack, nomem))
    };
}

fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: `port` is a 16550 register selected by this crash-only kernel; the operation
    // is ring-0 I/O and does not access memory.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nostack, nomem))
    };
    value
}

pub fn exit(code: u8) -> ! {
    outb(DEBUGEXIT_PORT, code);
    halt()
}

pub fn halt() -> ! {
    loop {
        // SAFETY: the terminal crash state is entered with interrupts disabled; hlt does
        // not access memory and an NMI may still enter the main kernel's parked stub.
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}
