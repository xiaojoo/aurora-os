//! 内核 CSPRNG 的熵收集与 ChaCha20 输出。
//!
//! 熵不足时 `fill()` 返回 `NotSeeded`；至少两路独立熵源成功才置 `seeded`。
//! 取锁期间不分配、不打日志，也不获取其他锁。

use crate::sync::IrqSpinLock;

pub(crate) const MIN_SOURCES: u8 = 2;
/// 每输出这么多个 64 字节块后，用自身输出换一把新密钥（快速密钥擦除，防回溯）。
const RATCHET_BLOCKS: u32 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RandError {
    /// 熵源不足，尚未播种。
    NotSeeded,
}

struct Pool {
    key: [u32; 8],
    ctr: u64,
    seeded: bool,
    blocks_since_ratchet: u32,
    /// 已混入的熵源路数的位图：bit0=rdseed bit1=rdrand bit2=tsc。
    source_mask: u8,
}

static POOL: IrqSpinLock<Pool> = IrqSpinLock::new(crate::sync::RANK_RAND,
    Pool { key: [0; 8], ctr: 0, seeded: false, blocks_since_ratchet: 0, source_mask: 0 },
);

#[inline(always)]
fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// ChaCha20 块函数（RFC 8439 §2.3）。64 位计数器放在 words 12..13，nonce 恒 0。
pub(crate) fn block(key: &[u32; 8], ctr: u64) -> [u32; 16] {
    let mut s: [u32; 16] = [
        0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574,
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
        ctr as u32, (ctr >> 32) as u32, 0, 0,
    ];
    let init = s;
    for _ in 0..10 {
        qr(&mut s, 0, 4, 8, 12); qr(&mut s, 1, 5, 9, 13); qr(&mut s, 2, 6, 10, 14); qr(&mut s, 3, 7, 11, 15);
        qr(&mut s, 0, 5, 10, 15); qr(&mut s, 1, 6, 11, 12); qr(&mut s, 2, 7, 8, 13); qr(&mut s, 3, 4, 9, 14);
    }
    for i in 0..16 { s[i] = s[i].wrapping_add(init[i]); }
    s
}

/// 混入一路熵：`new_key = SHA256(old_key || src_id || data)`。
/// `src_id`：0=rdseed 1=rdrand 2=tsc。同一路重复混入只算一路。
fn add_entropy(src_id: u8, data: &[u8]) {
    let mut guard = POOL.lock();
    let p = guard.get();
    let mut buf = [0u8; 32 + 1 + 64];
    for (i, w) in p.key.iter().enumerate() { buf[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes()); }
    buf[32] = src_id;
    let n = data.len().min(64);
    buf[33..33 + n].copy_from_slice(&data[..n]);
    let digest = crate::sign::digest(&buf[..33 + n]);   // sign.rs 的零依赖 SHA-256（`pub fn digest(msg:&[u8])->[u8;32]`）
    for i in 0..8 {
        p.key[i] = u32::from_le_bytes([digest[i * 4], digest[i * 4 + 1], digest[i * 4 + 2], digest[i * 4 + 3]]);
    }
    p.source_mask |= 1 << (src_id & 7);
    if p.source_mask.count_ones() as u8 >= MIN_SOURCES { p.seeded = true; }
}

pub(crate) fn is_seeded() -> bool { POOL.lock().get().seeded }
pub(crate) fn sources() -> u8 { POOL.lock().get().source_mask.count_ones() as u8 }

pub(crate) fn fill(out: &mut [u8]) -> Result<(), RandError> {
    let mut guard = POOL.lock();
    let p = guard.get();
    if !p.seeded { return Err(RandError::NotSeeded); }
    for chunk in out.chunks_mut(64) {
        let blk = block(&p.key, p.ctr);
        p.ctr = p.ctr.wrapping_add(1);
        for (i, c) in chunk.iter_mut().enumerate() { *c = (blk[i / 4] >> ((i % 4) * 8)) as u8; }
        p.blocks_since_ratchet += 1;
        if p.blocks_since_ratchet >= RATCHET_BLOCKS {
            let nb = block(&p.key, p.ctr);
            p.ctr = p.ctr.wrapping_add(1);
            for i in 0..8 { p.key[i] = nb[i]; }
            p.blocks_since_ratchet = 0;
        }
    }
    Ok(())
}

/// 便捷：取 8 字节作 u64（ISN/端口/canary 种子用）；熵不足向上传 Err。
pub(crate) fn next_u64() -> Result<u64, RandError> {
    let mut b = [0u8; 8];
    fill(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

pub(crate) fn init() -> u8 {
    if cfg!(feature = "fault-rand-no-entropy") {
        return 0;
    }
    let feats = crate::arch::x86_64::cpuid::detect();
    let rdseed = core::arch::x86_64::__cpuid_count(7, 0).ebx & (1 << 18) != 0;
    init_from_hw(feats.rdrand, rdseed)
}

fn init_from_hw(rdrand: bool, rdseed: bool) -> u8 {
    let mut ok = 0u8;
    if rdseed {
        let mut words = [0u64; 4];
        if hw_rdseed(&mut words) {
            let mut bytes = [0u8; 32];
            for (i, word) in words.iter().enumerate() {
                bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
            }
            add_entropy(0, &bytes);
            ok += 1;
        }
    }
    if rdrand {
        let mut words = [0u64; 4];
        if hw_rdrand(&mut words) {
            let mut bytes = [0u8; 32];
            for (i, word) in words.iter().enumerate() {
                bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
            }
            add_entropy(1, &bytes);
            ok += 1;
        }
    }
    // TSC 抖动：连续读 64 次，取相邻差的低位拼接；差值恒定（如被模拟成固定步长）则不算一路。
    let mut j = [0u8; 64];
    let mut last = crate::tsc::now();
    let mut distinct = 0u32;
    let mut prev_d = 0u64;
    for k in 0..64 {
        crate::tsc::spin(37 + (k as usize % 5));
        let t = crate::tsc::now();
        let d = t.wrapping_sub(last);
        if k > 0 && d != prev_d { distinct += 1; }
        prev_d = d; last = t;
        j[k] = (d ^ (d >> 7)) as u8;
    }
    if distinct >= 8 { add_entropy(2, &j); ok += 1; }
    crate::log_info!("rand: 熵源 {} 路成功 seeded={}", ok, is_seeded());
    ok
}

fn hw_rdrand(out: &mut [u64; 4]) -> bool {
    for word in out.iter_mut() {
        let mut value = 0u64;
        let mut ok = false;
        for _ in 0..10 {
            // SAFETY: 调用前已由 CPUID 确认 rdrand 位；指令只写寄存器。登记 U1。
            if unsafe { core::arch::x86_64::_rdrand64_step(&mut value) } == 1 {
                ok = true;
                break;
            }
        }
        if !ok { return false; }
        *word = value;
    }
    true
}
fn hw_rdseed(out: &mut [u64; 4]) -> bool {
    for word in out.iter_mut() {
        let mut value = 0u64;
        let mut ok = false;
        for _ in 0..10 {
            // SAFETY: 调用前已由 CPUID.7.0:EBX[18] 确认 rdseed；指令只写寄存器。登记 U1。
            if unsafe { core::arch::x86_64::_rdseed64_step(&mut value) } == 1 {
                ok = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !ok { return false; }
        *word = value;
    }
    true
}

#[cfg(feature = "fault-rand-reentrant")]
pub(crate) fn reenter_for_test() {
    let _guard = POOL.lock();
    let _ = is_seeded();
}
