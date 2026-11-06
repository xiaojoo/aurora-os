//! SHA-256（FIPS 180-4）：**零依赖、零 `unsafe`**，M9"驱动与更新包签名"那一列的地基。
//!
//! 这张表不是抄来的：`K` 是前 64 个素数立方根的小数前 32 位、`IV` 是前 8 个素数平方根的
//! 小数前 32 位。`check-sha-primitives` 每轮按这条**定义**用整数/十进制定点重算一遍再与这里
//! 逐字对账；摘要本身另有一台仪器（宿主机的 `hashlib`，矩阵第 25 行）。两道独立：
//! 表错了 ⇒ 门禁红；轮函数错了 ⇒ 对账红；两边一起错才可能瞒过去，而那正是可以审的。

/// 初始哈希值（前 8 个素数平方根的小数前 32 位）
pub const IV: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

/// 轮常数（前 64 个素数立方根的小数前 32 位）
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// 摘要长度（字节）
pub const DIGEST_BYTES: usize = 32;
const BLOCK: usize = 64;

/// 压缩一个块。`blk` 的长度由调用方保证是 64（补位那两处都是），这里不重复检查也不复制
fn compress(h: &mut [u32; 8], blk: &[u8]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        let j = i * 4;
        w[i] = u32::from_be_bytes([blk[j], blk[j + 1], blk[j + 2], blk[j + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// 一次算完的摘要。补位规则唯一容易被长度边界绊倒：`rem == 55` 与 `rem == 56` 走的是
/// 不同的块数（8 字节的比特长度放不下就得再开一块），所以 55/56/63/64/111/112/119/120
/// 这些长度都必须现场量一遍，不能只测"abc"。
pub fn digest(msg: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut h = IV;
    let mut i = 0usize;
    while i + BLOCK <= msg.len() {
        compress(&mut h, &msg[i..i + BLOCK]);
        i += BLOCK;
    }
    let bits = (msg.len() as u64).wrapping_mul(8);
    let rem = msg.len() - i;
    let mut blk = [0u8; BLOCK];
    blk[..rem].copy_from_slice(&msg[i..]);
    blk[rem] = 0x80;
    if rem >= BLOCK - 8 {
        compress(&mut h, &blk);
        blk = [0u8; BLOCK];
    }
    blk[BLOCK - 8..].copy_from_slice(&bits.to_be_bytes());
    compress(&mut h, &blk);
    let mut out = [0u8; DIGEST_BYTES];
    for (j, w) in h.iter().enumerate() {
        out[j * 4..j * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

/// 摘要的 8 个字（大端序展开，日志与对账都按这个形状）
pub fn words(d: &[u8; DIGEST_BYTES]) -> [u32; 8] {
    let mut w = [0u32; 8];
    for (j, x) in w.iter_mut().enumerate() {
        *x = u32::from_be_bytes([d[j * 4], d[j * 4 + 1], d[j * 4 + 2], d[j * 4 + 3]]);
    }
    w
}


// ==================================================== M9-a②：一次性签名（Lamport）与签名包

/// 内核内置的那把锚：整张公钥的摘要。由 `tools/esp_image.py::pkg_anchor()` 算出来后写在这里，
/// `check-sig-anchor` 每轮重算对账（不一致 = 镜像里的包与内核认的钥匙不是同一把）。
/// **这不是生产钥匙**：种子是定下来的测试值，真流程要离线保管私钥并支持轮换（BACKLOG 61）。
pub const PK_ANCHOR: [u8; DIGEST_BYTES] = [
    0x7a, 0x08, 0x5e, 0x9c, 0xf4, 0x82, 0x1e, 0x13,
    0x9e, 0x7c, 0xc4, 0x19, 0x1b, 0x0d, 0xbf, 0xc9,
    0x44, 0x4f, 0x68, 0x20, 0x0a, 0x1f, 0x4a, 0x74,
    0x7a, 0xe4, 0x4f, 0x83, 0x01, 0x35, 0xb4, 0x6d
];

/// 密钥不是随机数生成器给的，而是**由一个种子按定义导出**：
/// `priv[i] = SHA-256(seed || "aurora-lamport" || u32(i))`，`pk[i] = SHA-256(priv[i])`。
/// 这样宿主机与内核各自都能重算出同一张钥匙 —— 验签的判据才不需要"把私钥交给内核"。
/// 锚点只内置**整张公钥的摘要**（32 字节），公钥随包交付；先核摘要再逐比特，
/// 否则攻击者可以直接换一张自己的公钥。
pub const KEY_LABEL: &[u8] = b"aurora-lamport";
/// 256 个摘要比特 ⇒ 256 对公钥元素；签名交出的就是被选中的那一列的原像
pub const PK_ITEMS: usize = 512;
pub const PK_BYTES: usize = PK_ITEMS * DIGEST_BYTES;
pub const SIG_ITEMS: usize = 256;

/// 签名包在盘上的形状：头 + 公钥 + 签名 + 载荷（`tools/esp_image.py` 那边是同一张表，
/// `check-sig-anchor` 逐字对账——两边各写一份而不对账，就会有一天"内核读的偏移"与
/// "生成器写的偏移"分家，而那表现为一枚永远验不过的签名）
pub const PKG_MAGIC: [u8; 4] = *b"PKGA";
pub const PKG_VERSION: u32 = 1;
pub const PKG_HDR_BYTES: usize = 512;
pub const PK_OFF: usize = PKG_HDR_BYTES;
pub const SIG_OFF: usize = PK_OFF + PK_BYTES;
pub const PAY_OFF: usize = SIG_OFF + SIG_BYTES;
pub const PKG_PAYLOAD_BYTES: usize = 32_768;
pub const PKG_BYTES: usize = PAY_OFF + PKG_PAYLOAD_BYTES;
/// 包在盘上的位置与长度（`tools/esp_image.py` 的 `PKG_START_LBA`/`PKG_SECTORS` 同数）。
/// 这一段与状态区一样，是 GPT 未分配空隙里的**约定**，还不是一条带 GUID 的分区条目
pub const PKG_START_LBA: u64 = 67_664;
pub const SECTOR_BYTES: usize = 512;
pub const PKG_SECTORS: usize = PKG_BYTES / SECTOR_BYTES;
pub const SIG_BYTES: usize = SIG_ITEMS * DIGEST_BYTES;

/// 导出私钥：`seed` 与序号一起进哈希。序号按大端，避免"两个不同序号撞出同一个数"
pub fn derive_priv(seed: &[u8; 32], i: usize) -> [u8; DIGEST_BYTES] {
    let mut buf = [0u8; 64 + KEY_LABEL.len()];
    let n = KEY_LABEL.len();
    buf[..32].copy_from_slice(seed);
    buf[32..32 + n].copy_from_slice(KEY_LABEL);
    buf[32 + n..36 + n].copy_from_slice(&(i as u32).to_be_bytes());
    digest(&buf[..36 + n])
}

/// 整张公钥（`PK_ITEMS` 个摘要）由私钥导出。宿主机那份是同一式子的另一实现
pub fn derive_pk(seed: &[u8; 32], out: &mut [u8; PK_BYTES]) {
    for i in 0..PK_ITEMS {
        let h = digest(&derive_priv(seed, i));
        out[i * DIGEST_BYTES..(i + 1) * DIGEST_BYTES].copy_from_slice(&h);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigError {
    /// 公钥整张的摘要与内置锚点不符 ⇒ 后面每一个比特都不用看了
    AnchorMismatch,
    /// 第 `n` 个比特的原像哈希不上（`0..256`）
    BitMismatch(usize),
    /// 交付的字节数不对（公钥或签名的长度）
    BadLen(usize),
    /// 载荷自己的摘要与签名承诺的那个摘要不同
    PayloadMismatch,
}

/// 一个比特取的是公钥里哪一个元素：`digest_bit=0` 取偶数那一个，`1` 取奇数那一个
fn key_slot(bit_index: usize, bit: u8) -> usize {
    bit_index * 2 + usize::from(bit & 1)
}

/// 逐字节把摘要展开成 256 个比特（大端：字节 0 的最高位是第 0 个比特）
pub fn bits(d: &[u8; DIGEST_BYTES]) -> [u8; SIG_ITEMS] {
    let mut b = [0u8; SIG_ITEMS];
    for (i, x) in d.iter().enumerate() {
        for j in 0..8 {
            b[i * 8 + j] = (x >> (7 - j)) & 1;
        }
    }
    b
}

/// 验一份签名包：`anchor` 是内核内置的那 32 字节，`pk`/`sig` 随包交付，`msg` 是载荷字节。
/// 顺序是"先贵后便宜"还是"先能判的"？——按**能定性的顺序**：锚点先过（不过就没什么好看的），
/// 再逐比特（这是签名本体），最后才把载荷的摘要与签名承诺的对上。
/// 每一步都返回**不同的错误**，因为"红了"要能说清是哪一类篡改
pub fn verify(anchor: &[u8; DIGEST_BYTES], pk: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), SigError> {
    if pk.len() != PK_BYTES || sig.len() != SIG_BYTES {
        return Err(SigError::BadLen(if pk.len() != PK_BYTES { pk.len() } else { sig.len() }));
    }
    if digest(pk) != *anchor {
        return Err(SigError::AnchorMismatch);
    }
    let d = digest(msg);
    let bits_of = bits(&d);
    for i in 0..SIG_ITEMS {
        let given = &sig[i * DIGEST_BYTES..(i + 1) * DIGEST_BYTES];
        let slot = key_slot(i, bits_of[i]);
        let want = &pk[slot * DIGEST_BYTES..(slot + 1) * DIGEST_BYTES];
        if digest(given) != *want {
            return Err(SigError::BitMismatch(i));
        }
    }
    Ok(())
}

/// 包头之外的拒绝形状（`SigError` 只管签名本体）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PkgError {
    /// 魔数或版本不对：这一格先过，否则下面每一个长度字段都没有意义
    BadHeader,
    /// 头里承诺的长度与内核给的缓冲/表的形状不符（`n` = 那个数）
    BadLen(usize),
    /// 载荷长度越界：说好的字节数放不下这一包
    PayloadTooLong(usize),
    /// 签名本体的拒绝
    Sig(SigError),
}

/// 一个头的字段读法。每一个从盘上/包里来的数都用**它自己的宽度**读，并且先验上界再用
/// （§10.3 同一条：线上的数不能直接当界用）
fn le32(b: &[u8], at: usize) -> Option<u32> {
    if at + 4 > b.len() {
        return None;
    }
    Some(u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]))
}

/// 验一整包：先看形状，再看钥匙，最后看签名。`anchor` 是内核内置那 32 字节。
pub fn check_package(pkg: &[u8], anchor: &[u8; DIGEST_BYTES]) -> Result<usize, PkgError> {
    if pkg.len() != PKG_BYTES || le32(pkg, 0).is_none() {
        return Err(PkgError::BadLen(pkg.len()));
    }
    if pkg[0..4] != PKG_MAGIC || le32(pkg, 4) != Some(PKG_VERSION) {
        return Err(PkgError::BadHeader);
    }
    let pk_len = le32(pkg, 8).ok_or(PkgError::BadHeader)? as usize;
    let sig_len = le32(pkg, 12).ok_or(PkgError::BadHeader)? as usize;
    let pay_len = le32(pkg, 16).ok_or(PkgError::BadHeader)? as usize;
    if pk_len != PK_BYTES || sig_len != SIG_BYTES {
        return Err(PkgError::BadLen(pk_len.max(sig_len)));
    }
    if pay_len > PKG_PAYLOAD_BYTES || PAY_OFF + pay_len > pkg.len() {
        return Err(PkgError::PayloadTooLong(pay_len));
    }
    verify(
        anchor,
        &pkg[PK_OFF..PK_OFF + PK_BYTES],
        &pkg[SIG_OFF..SIG_OFF + SIG_BYTES],
        &pkg[PAY_OFF..PAY_OFF + pay_len],
    )
    .map_err(PkgError::Sig)?;
    Ok(pay_len)
}

/// 一次篡改：包内第 `at` 个字节异或 `mask`。表在两边各写一份（宿主机自己算同一批理由），
/// `check-sig-anchor` 逐条对账 —— 一边的表变了，另一边就会给出不同的答案
#[derive(Clone, Copy, Debug)]
pub struct Tamper {
    pub at: usize,
    pub mask: u8,
    /// 这格存在的目的写在日志里，方便红了以后一眼知道在测什么
    pub why: &'static str,
}

pub const TAMPERS: [Tamper; 9] = [
    Tamper { at: PK_OFF, mask: 0x01, why: "public key first byte" },
    Tamper { at: PK_OFF + PK_BYTES - 1, mask: 0x80, why: "public key last byte" },
    Tamper { at: SIG_OFF, mask: 0x01, why: "signature first byte" },
    Tamper { at: SIG_OFF + SIG_BYTES / 2, mask: 0x10, why: "signature middle byte" },
    Tamper { at: SIG_OFF + SIG_BYTES - 1, mask: 0x01, why: "signature last byte" },
    Tamper { at: PAY_OFF, mask: 0x01, why: "payload first byte" },
    // 载荷长度的**高字节**：翻低位只会得到一个更小的合法数（那样走的是签名不符那条路，
    // 而不是界检查），这一格要的是 `PayloadTooLong` 确实被走到
    Tamper { at: 19, mask: 0xFF, why: "payload length high byte" },
    Tamper { at: 8, mask: 0xFF, why: "public key length field" },
    Tamper { at: 0, mask: 0xFF, why: "magic" },
];

/// 拒绝理由的稳定文本：日志与宿主机比的是这个名字，不是 `Debug` 的排版。
/// 名字两边各写一份 ⇒ `check-sig-anchor` 把这张表也逐条对账
pub fn reason(e: PkgError) -> &'static str {
    match e {
        PkgError::BadHeader => "BadHeader",
        PkgError::BadLen(_) => "BadLen",
        PkgError::PayloadTooLong(_) => "PayloadTooLong",
        PkgError::Sig(SigError::AnchorMismatch) => "AnchorMismatch",
        PkgError::Sig(SigError::BitMismatch(_)) => "BitMismatch",
        PkgError::Sig(SigError::BadLen(_)) => "SigBadLen",
        PkgError::Sig(SigError::PayloadMismatch) => "PayloadMismatch",
    }
}

/// 拒绝理由附带的数字（`BitMismatch` 的下标、`*TooLong/BadLen` 的那个数）；没有就 0xFFFF_FFFF
pub fn reason_arg(e: PkgError) -> u32 {
    match e {
        PkgError::BadLen(n) | PkgError::PayloadTooLong(n) => n as u32,
        PkgError::Sig(SigError::BitMismatch(i)) => i as u32,
        PkgError::Sig(SigError::BadLen(n)) => n as u32,
        _ => 0xFFFF_FFFF,
    }
}
