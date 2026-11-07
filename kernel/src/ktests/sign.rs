//! SHA-256 与签名包用例（T0.1 纯搬移）。

use crate::{ahci, sign};
use crate::ktests::common::{HELLO_ELF};
use crate::ktest;
use core::cell::UnsafeCell;

/// M9-a①：SHA-256 的现场。判据五格（**对不对**由宿主机的 `hashlib` 判，见矩阵第 25 行；
/// 这一格只判内核自己知道的那些形状）：
/// 1 十三个长度向量两两摘要不同 —— 长度取 0/3/55/56/57/63/64/65/111/112/119/120/128，
///    把补位的四个边界（55|56、63|64、111|112、119|120）都各踩一次
/// 2 空串的八个字都不为 0，也不是全 F（护栏：写错初始值最容易塌成这两种）
/// 3 雪崩：把 payload 里一个 bit 翻掉，摘要至少 8/32 个字节不同
/// 4 同一输入两次算出的摘要相同（幂等，防"状态忘了复位"这种错法）
/// 5 `words()` 与字节数组的端序自洽：第一个字的高两字节就是摘要的前两个字节
#[cfg(feature = "sig-check")]
fn t_sha256() -> bool {
    fn payload_byte(i: usize) -> u8 {
        ((i * 7 + 0x5A) & 0xFF) as u8
    }
    const LENGTHS: [usize; 13] = [0, 3, 55, 56, 57, 63, 64, 65, 111, 112, 119, 120, 128];
    let mut digests: [[u8; sign::DIGEST_BYTES]; 13] = [[0; sign::DIGEST_BYTES]; 13];
    let mut same_as_prev = false;
    for (n, len) in LENGTHS.iter().enumerate() {
        let mut msg = [0u8; 128];
        for i in 0..*len {
            msg[i] = payload_byte(i);
        }
        digests[n] = sign::digest(&msg[..*len]);
        if n > 0 && digests[n] == digests[n - 1] {
            same_as_prev = true;
        }
        let w = sign::words(&digests[n]);
        crate::log_info!(
            "sha: 向量 长度={} 摘要={:#010x} {:#010x} {:#010x} {:#010x} {:#010x} {:#010x} {:#010x} {:#010x}",
            len, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]
        );
    }
    let distinct = !same_as_prev;
    let empty = sign::digest(&[]);
    let ew = sign::words(&empty);
    let shape_ok = ew.iter().all(|x| *x != 0 && *x != 0xFFFF_FFFF);
    // 雪崩：与"长度 64 的那个向量"只差一个 bit
    let mut flip = [0u8; 64];
    for i in 0..64 {
        flip[i] = payload_byte(i);
    }
    flip[10] ^= 0x01;
    let mut orig = [0u8; 64];
    for i in 0..64 {
        orig[i] = payload_byte(i);
    }
    let avalanche = sign::digest(&flip)
        .iter()
        .zip(sign::digest(&orig).iter())
        .filter(|(a, b)| a != b)
        .count();
    let again = sign::digest(&orig) == sign::digest(&orig);
    let endian_ok = (ew[0] >> 16) as u16 == u16::from_be_bytes([empty[0], empty[1]]);
    crate::log_info!(
        "sha: 判据 长度向量互不相同={} 空串形状={} 雪崩字节={}/32 幂等={} 端序自洽={}",
        distinct,
        shape_ok,
        avalanche,
        again,
        endian_ok
    );
    let ok = distinct && shape_ok && avalanche >= 8 && again && endian_ok;
    if !ok {
        crate::log_fatal!("sha: SHA-256 判据不成立（上面十四行是全部读数）");
    }
    ok
}
#[cfg(feature = "sig-check")]
ktest!(KT_SHA256, t_sha256);

/// 签名包的缓冲（57,856 字节 = 56.5 KiB）比分配器上限大两个数量级，理由与 `ELF_SCRATCH`
/// 同一条：按外部输入大小 `to_vec()` 第一次分配就走 `handle_alloc_error`，整机构成 39。
#[cfg(feature = "sig-check")]
struct PkgScratch(UnsafeCell<[u8; sign::PKG_BYTES]>);
#[cfg(feature = "sig-check")]
// SAFETY: 只在 `sig-check` 变体的这一条用例里用，调用点在关中断窗口内，
//         可变借用只在这一次调用内活着（不外泄 `&'static mut`），不同时存在两份
unsafe impl Sync for PkgScratch {}
#[cfg(feature = "sig-check")]
static PKG_BUF: PkgScratch = PkgScratch(UnsafeCell::new([0u8; sign::PKG_BYTES]));

/// M9-a②：盘上那份签名包的读取与验证。判据六格：
/// 1 从固定 LBA 分块读满一整包（`sign::PKG_BYTES` 个字节一次不少，读失败就直接红）
/// 2 头自洽：魔数、版本、三个长度字段各按自身宽度读，并且**先验上界再用**（§10.3 那条）
/// 3 真包验签通过（`check_package` 回 `Ok`）
/// 4 包里的载荷与内核手上那份夹具是同一段字节：长度同数、两条摘要同数
///    （一个来自盘上 15 次分块读，一个来自镜像里 `include_bytes!` 的那份）
/// 5 八种篡改**每一种都必须被拒**，并把拒绝理由与附带的数字打出来 —— 宿主机用自己的实现
///    对同一批输入算同一份答案，两边逐条相同（这就是"协议 fuzz"的第一个形状：畸形输入
///    必须被定性拒绝，不许崩、不许静默接受）
/// 6 走完这一大包之后，引导盘的 LBA 1 仍读得到 `EFI PART`：读盘 15 次不许把别的读者弄坏
#[cfg(feature = "sig-check")]
fn t_sig_package() -> bool {
    const CHUNK: usize = 4096;
    let port = match ahci::boot_port() {
        Ok(p) => p,
        Err(e) => {
            crate::log_fatal!("pkg: 找不到引导口 {:?}", e);
            return false;
        }
    };
    // SAFETY: 见 `PkgScratch` —— 单一持有者、关中断窗口内的用例上下文、借用不出本次调用
    let buf = unsafe { &mut *PKG_BUF.0.get() };
    let mut off = 0usize;
    let mut reads = 0usize;
    while off < sign::PKG_BYTES {
        let n = CHUNK.min(sign::PKG_BYTES - off);
        let lba = sign::PKG_START_LBA + (off / sign::SECTOR_BYTES) as u64;
        if let Err(e) = ahci::read_bytes(port, lba, &mut buf[off..off + n]) {
            crate::log_fatal!("pkg: 第 {} 次分块读失败 lba={} 长={} {:?}", reads, lba, n, e);
            return false;
        }
        off += n;
        reads += 1;
    }
    let load_ok = off == sign::PKG_BYTES;
    let accepted = sign::check_package(buf, &sign::PK_ANCHOR);
    let (hdr_ok, verify_ok, pay_len) = match accepted {
        Ok(n) => (true, true, n),
        Err(e) => {
            let h = !matches!(e, sign::PkgError::BadLen(_) | sign::PkgError::PayloadTooLong(_));
            crate::log_fatal!("pkg: 真包被拒 理由={} 附带={}", sign::reason(e), sign::reason_arg(e));
            (h, false, 0)
        }
    };
    // 载荷 vs 内核手上那份夹具：两条来源必须给同一个数
    let payload_same = pay_len == HELLO_ELF.len()
        && sign::digest(&buf[sign::PAY_OFF..sign::PAY_OFF + pay_len])
            == sign::digest(HELLO_ELF);
    crate::log_info!(
        "pkg: 取证 读满={} 次 字节={} 头自洽={} 验签={} 载荷长={}/{} 载荷同={} 锚点={:#010x}",
        reads,
        off,
        hdr_ok,
        verify_ok,
        pay_len,
        HELLO_ELF.len(),
        payload_same,
        u32::from_be_bytes([
            sign::PK_ANCHOR[0],
            sign::PK_ANCHOR[1],
            sign::PK_ANCHOR[2],
            sign::PK_ANCHOR[3]
        ])
    );
    // 八种篡改：改一个字节 → 必须被拒 → 打回理由 → 还原。还原是必须的，
    // 否则下一格测的就不是"那一种篡改"而是前一种的残留（用例自己污染现场，与 ㊻ 同形）
    let mut rejected = 0usize;
    for (i, t) in sign::TAMPERS.iter().enumerate() {
        buf[t.at] ^= t.mask;
        let r = match sign::check_package(buf, &sign::PK_ANCHOR) {
            Err(e) => {
                rejected += 1;
                (sign::reason(e), sign::reason_arg(e))
            }
            Ok(_) => ("ACCEPTED", 0u32),
        };
        buf[t.at] ^= t.mask;
        crate::log_info!(
            "pkg: 篡改 {} 位置={} 掩码={:#04x} 目的={} 理由={} 附带={}",
            i,
            t.at,
            t.mask,
            t.why,
            r.0,
            r.1
        );
    }
    let tamper_ok = rejected == sign::TAMPERS.len();
    // 大包读完之后引导盘那条路仍然完好
    let mut head = [0u8; 512];
    let ahci_still_ok = ahci::read_bytes(port, 1, &mut head).is_ok() && &head[0..8] == b"EFI PART";
    crate::log_info!(
        "pkg: 判据 读满={} 头自洽={} 验签={} 载荷同={} 篡改全拒={}/{} AHCI照常={}",
        load_ok,
        hdr_ok,
        verify_ok,
        payload_same,
        rejected,
        sign::TAMPERS.len(),
        ahci_still_ok
    );
    let ok = load_ok && hdr_ok && verify_ok && payload_same && tamper_ok && ahci_still_ok;
    if !ok {
        crate::log_fatal!("pkg: 签名包判据不成立（上面十行是全部读数）");
    }
    ok
}
#[cfg(feature = "sig-check")]
ktest!(KT_SIG_PACKAGE, t_sig_package);

