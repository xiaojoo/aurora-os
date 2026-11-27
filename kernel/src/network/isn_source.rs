//! ISN / 临时端口的**内核侧来源**（S4 步骤 4 的接线层）。纯算法在 `crates/host-tcp/src/isn.rs`；本文件只负责：
//! 取 secret、取时钟、**未播种时降级并计数**。放在 `network/`，依赖 `security::rand`（S1）与 `sign::digest`。
//!
//! ## ISN 必须在**知道四元组的时刻**算（本批的关键更正）
//! 初稿有一个 `isn_for_listen`：在 `socket::create` 时给每个监听槽一个随机初值。**沙箱抓到它不满足 RFC 6528**：
//! `tcp_accept` 之后槽用 `iss+0x1000` 重开（socket.rs:919），所以哪怕初值随机，连续连接的 ISN 差恒为 4096，
//! 攻击者建 1 个合法连接就能预测该槽之后全部连接。已删除。正确接线点：被动端 = LISTEN 收 SYN 时（四元组此刻才知），
//! 主动端 = `tcp_start_connect`（local/peer 此刻已设）。`create`/`accept` 里的 iss 仅是占位。
//!
//! ## 为什么要有"降级"而不是直接 unwrap
//! `rand::fill` 在熵源 <2 路时返回 `Err(NotSeeded)`（S1 契约）。QEMU 默认配置下 rdrand/rdseed 可用，但 `-cpu` 选项或老 CPU 可能没有。
//! 启动不能因此失败，测试也要能跑 ⇒ 未播种时回退到**旧公式**并让 `ISN_WEAK` 计数 +1，`tcp_info`/日志暴露它。
//! **降级发生过 = 本次启动的 ISN 可预测**，这条必须可观测，不许静默。
//!
//! ## 并发
//! `SECRET` 在启动期单线程写一次（`init_secret`），之后只读；用 `AtomicU64` 对存两半，**不需要锁**。
//! 未初始化时 `ready=false`，调用方走降级。
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

static SECRET_LO: AtomicU64 = AtomicU64::new(0);
static SECRET_HI: AtomicU64 = AtomicU64::new(0);
static READY: AtomicBool = AtomicBool::new(false);
/// 降级次数（判据与诊断读它）。**非 0 ⇒ 曾给出可预测 ISN**。
pub static ISN_WEAK: AtomicU32 = AtomicU32::new(0);
pub static ISN_STRONG: AtomicU32 = AtomicU32::new(0);
/// 临时端口 per-boot 计数器（RFC 6056 算法 3 的 counter）。
static PORT_COUNTER: AtomicU32 = AtomicU32::new(0);

/// 启动期调用一次（在 `security::rand::init_from_hw` 之后）。熵不足返回 false，调用方打日志但不阻断启动。
pub fn init_secret() -> bool {
    let mut b = [0u8; 16];
    if crate::security::rand::fill(&mut b).is_err() { return false; }
    SECRET_LO.store(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]), Ordering::Relaxed);
    SECRET_HI.store(u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]), Ordering::Relaxed);
    READY.store(true, Ordering::Release);
    true
}

pub fn is_ready() -> bool { READY.load(Ordering::Acquire) }

fn secret() -> Option<[u8; 16]> {
    if !is_ready() { return None; }
    let (lo, hi) = (SECRET_LO.load(Ordering::Relaxed).to_le_bytes(), SECRET_HI.load(Ordering::Relaxed).to_le_bytes());
    let mut s = [0u8; 16]; s[..8].copy_from_slice(&lo); s[8..].copy_from_slice(&hi); Some(s)
}

/// PRF：SHA-256(secret ‖ 输入) 的前 4 字节。用仓库里已有、已被宿主机 hashlib 第二仪器对账的 `crate::security::sign::digest`（签名 `fn digest(msg:&[u8]) -> [u8; DIGEST_BYTES]`，security/sign.rs:86）。
/// **性能**：每个 ISN/端口一次 SHA-256（约几百 ns~µs 量级，**未实测**）；连接建立路径可接受，不得放进逐包路径。
fn prf32(parts: &[&[u8]]) -> Option<u32> {
    let s = secret()?;
    let mut buf = [0u8; 16 + 32];
    buf[..16].copy_from_slice(&s);
    let mut n = 16;
    for p in parts { let k = p.len().min(buf.len() - n); buf[n..n + k].copy_from_slice(&p[..k]); n += k; }
    let d = crate::security::sign::digest(&buf[..n]);
    Some(u32::from_le_bytes([d[0], d[1], d[2], d[3]]))
}

/// 旧公式（`socket.rs:267`）。仅降级用。
#[inline]
pub fn legacy_isn(slot: u16, gen: u32) -> u32 { 0x1000_0000u32.wrapping_add((slot as u32) << 8).wrapping_add(gen) }

/// 单调微秒：`crate::time::clock::uptime_micros() -> Option<u64>`（time/clock.rs，**已核实存在**；初稿写的 `crate::time::now_us()` 不存在）。
pub fn now_us() -> Option<u64> { crate::time::clock::uptime_micros() }
/// 时钟未校准（`None`）。
pub static ISN_NOCLOCK: AtomicU32 = AtomicU32::new(0);

/// RFC 6528 ISN：`M + F(四元组, secret)`，M = `now_us/4`。
///
/// **降级矩阵**（任何一格都计数，不静默）：
/// | secret 就绪 | 时钟就绪 | 结果 |
/// |---|---|---|
/// | 是 | 是 | RFC 6528（`ISN_STRONG`+1） |
/// | 否 | — | 旧公式（`ISN_WEAK`+1）——**ISN 可预测** |
/// | 是 | 否 | **旧公式**（`ISN_NOCLOCK`+1，同时 `ISN_WEAK`+1）——**不取 M=0**：沙箱证明 M=0 时同四元组两次连接 ISN **完全相同**，
/// |  |  | 旧连接迟到段会被新连接接受；旧公式至少含 slot/gen 区分不同槽 |
pub fn isn_for(lip: [u8; 4], lport: u16, rip: [u8; 4], rport: u16, slot: u16, gen: u32) -> u32 {
    let now = now_us();
    if now.is_none() { ISN_NOCLOCK.fetch_add(1, Ordering::Relaxed); }
    // 先探 secret 是否就绪：未就绪直接降级（prf 闭包里不能返回 Option）。
    let (Some(now), true) = (now, is_ready()) else {
        ISN_WEAK.fetch_add(1, Ordering::Relaxed);
        return legacy_isn(slot, gen);
    };
    // 算法单一来源：与宿主机 `cargo test -p host-tcp` 跑的是同一个 `host_tcp::isn::isn`（第二仪器对账依赖这一点）。
    let c = host_tcp::isn::Conn { lip, lport, rip, rport };
    let prf = |c: &host_tcp::isn::Conn| -> u32 {
        prf32(&[&c.lip, &c.lport.to_be_bytes(), &c.rip, &c.rport.to_be_bytes()]).unwrap_or(0)
    };
    ISN_STRONG.fetch_add(1, Ordering::Relaxed);
    host_tcp::isn::isn(&c, now, &prf)
}

/// 临时端口（RFC 6056 算法 3）。`in_use` 查 socket 表（调用方在持 `RANK_NET` 时传入闭包，**本函数不取任何锁**）。
/// 未播种时降级为旧公式 `49152 + slot` 并计数（UDP 路径原行为）。
pub fn ephemeral(lip: [u8; 4], rip: [u8; 4], rport: u16, slot: u16, in_use: &dyn Fn(u16) -> bool) -> u16 {
    let c = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let prf = |l: [u8; 4], r: [u8; 4], p: u16| prf32(&[&l, &r, &p.to_be_bytes(), b"port"]).unwrap_or(0);
    if is_ready() {
        // 上限 = MAX_SOCKETS(256)+1：占用端口数 ≤ socket 数，所以必能找到（沙箱 3000 次实测最坏 255 次探测）
        if let Some(p) = host_tcp::isn::ephemeral_port(lip, rip, rport, c, 257, &prf, in_use) { return p; }
    }
    ISN_WEAK.fetch_add(1, Ordering::Relaxed);
    49152u16.wrapping_add(slot)
}
