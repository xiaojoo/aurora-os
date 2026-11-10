//! ESP 分区里**真读一个已存在的文件**（W4 S2b，ADR-078 补记七 / ADR-077 补记）。只在 `esp-probe` 档注册。
//!
//! 与前两刀的分工：S1 只解析分区表、S2a 只判型与读整卷，这一刀把两者接起来——
//! `gpt::find_esp` 给的 `first_lba/last_lba` 喂给 `PartitionView`，再喂给**语义逐字未动**的
//! `Volume::mount`。偏移只活在块层那一个包装里，所以 FAT 那三族解析一个字都不用改。
//!
//! 读的目标是 `LIMINE.CON`（`limine.conf` 的 8.3 短名，`name_matches` 拼的是 `NAME.EXT`）。
//! **不是**立项书里写的 `/boot/aurora.bin`：`open()` 只扫根、不走子目录，LFN 也没实现，
//! 而根级常驻的 8.3 可开文件只有这一个（`startup.nsh` 只在诊断变体里）。不往 ESP 加新文件。
//!
//! 六件容易写错、且错了"计数还好看"的事各有一格：
//! 1 真读出来的字节要与宿主机从 `build/aurora.img` 独立取出的那份同数（矩阵行对账，不在本用例里判）
//! 2 句柄**带偏移**：经 `handle::read` 读出来的必须与直接读相同
//! 3 偏移**是身份**：同一口同一份游标、`part=None` 的另一个句柄读出来必须**不同**
//!   （若偏移没进身份，`read` 重建整盘 ⇒ 两个句柄读出一样的错字节，而句柄看着都合法）
//! 4 越界与形状错**两个码分开**：越出分区是 `BeyondPartition`，长度不整扇区仍是 `Refused`
//! 5 `base=0` 必须拒（读到的是保护性 MBR，不是 BPB）
//! 6 偏移敏感性在**ELF 内合成盘**上证：改 base 一格 ⇒ 内容变。为什么不去改真盘：
//!   S1 实测 EDK2 会用备份 GPT 把主表修回，口 0 又是引导盘 ⇒ 改盘注入到不了内核；
//!   口 1 的 GPT 夹具盘**没有文件系统** ⇒ 也读不出文件。所以这一格只能合成。

use crate::filesystem::fat32;
use crate::filesystem::gpt;
use crate::filesystem::vfs::{AhciDisk, Block, BlockError, MemDisk, Partition, PartitionView, SECTOR_BYTES};
use crate::{ahci, handle, ktest};

/// `limine.conf` 的 8.3 短名。点号不是空格：`name_matches` 把名字与扩展名拼成 `NAME.EXT`。
const WANT: &str = "LIMINE.CON";
/// 本用例自己的所有者（与 handle.rs 内部用例的 OWNER 不同，免得互相踩表项）。
const OWNER: (usize, u32) = (9, 4211);
/// 配置文件读进这个栈缓冲。超了不是静默截断，而是点名红（`size` 会打出来）。
const BUF: usize = 2048;
/// 合成盘的前缀扇区数（非零就够：要证的是"偏移真的被加上了"）。
const PREFIX: usize = 4;
/// S2a 那份合成整卷（23 扇区）。与 `ktests/fat16.rs` 同一份字节，指纹由门禁在编译前核。
static FAT16_MEM: &[u8] = include_bytes!("../../fixtures/fat16-mem.img");
const SYN_SECTORS: usize = 23;
const SYN_FILE: &str = "TEST.BIN";
const SYN_SIZE: usize = 1000;

fn t_esp_file() -> bool {
    let port = match ahci::boot_port() {
        Ok(p) => p,
        Err(e) => {
            crate::log_fatal!("esp: 找不到引导盘 {:?}", e);
            return false;
        }
    };
    let disk = AhciDisk { port };

    // ① 真读：GPT → 分区视图 → mount（FAT16）→ open → 游标读全
    let esp = match gpt::find_esp(&disk) {
        Ok(Some(e)) => e,
        Ok(None) => {
            crate::log_fatal!("esp: 引导盘上没有 ESP 条目 ⇒ 这一刀没有被测物");
            return false;
        }
        Err(e) => {
            crate::log_fatal!("esp: 分区表读不下来 {:?}", e);
            return false;
        }
    };
    let part = Partition { base: esp.first_lba, last: esp.last_lba };
    let view = PartitionView { inner: &disk, part };
    let vol = match fat32::Volume::mount(&view) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("esp: 按分区偏移挂载失败 {:?}（base={} last={}）", e, part.base, part.last);
            return false;
        }
    };
    let st = match vol.open(WANT) {
        Ok(s) => s,
        Err(e) => {
            crate::log_fatal!("esp: 根里开不出 {} {:?}", WANT, e);
            return false;
        }
    };
    let mut got = [0u8; BUF];
    let mut cur = match vol.open_cursor(WANT) {
        Ok(c) => c,
        Err(e) => {
            crate::log_fatal!("esp: 开游标失败 {:?}", e);
            return false;
        }
    };
    let n = match cur.read(&view, &mut got) {
        Ok(n) => n,
        Err(e) => {
            crate::log_fatal!("esp: 读 {} 失败 {:?}", WANT, e);
            return false;
        }
    };
    let fits = st.size as usize <= BUF;
    let read_ok = fits && n == st.size as usize;
    let fnv = ahci::fnv1a64(&got[..n]);
    let is16 = vol.bpb.fat_type == fat32::FatType::Fat16;

    // ②③ 句柄身份：带偏移的读法必须与直接读同数；不带偏移的必须**不同**
    let mut hbuf = [0u8; BUF];
    let mut nbuf = [0u8; BUF];
    let cur2 = match vol.open_cursor(WANT) {
        Ok(c) => c,
        Err(e) => {
            crate::log_fatal!("esp: 第二份游标开不出来 {:?}", e);
            return false;
        }
    };
    let cur3 = match vol.open_cursor(WANT) {
        Ok(c) => c,
        Err(e) => {
            crate::log_fatal!("esp: 第三份游标开不出来 {:?}", e);
            return false;
        }
    };
    let h_at = handle::grant_file_at(OWNER, port, Some(part), cur2, handle::RIGHT_READ);
    let h_whole = handle::grant_file(OWNER, port, cur3, handle::RIGHT_READ);
    let at_read = h_at.ok().and_then(|h| handle::read(h, OWNER, &mut hbuf).ok());
    let whole_read = h_whole.ok().and_then(|h| handle::read(h, OWNER, &mut nbuf).ok());
    let handle_same = at_read == Some(n) && ahci::fnv1a64(&hbuf[..n.min(BUF)]) == fnv;
    // 不带偏移那一路：要么读失败，要么读出来的字节与正确那份不同。两者都算"身份起作用"，
    // 但**必须把是哪一种打出来**——合成一个 bool 就看不出它是拒了还是读错了。
    let whole_differs = match whole_read {
        None => true,
        Some(m) => m != n || ahci::fnv1a64(&nbuf[..m.min(BUF)]) != fnv,
    };
    if let Ok(h) = h_at {
        handle::close(h, OWNER).ok();
    }
    if let Ok(h) = h_whole {
        handle::close(h, OWNER).ok();
    }

    // ④ 越界与形状错是两个码
    let mut one = [0u8; SECTOR_BYTES];
    let beyond = view.read_sectors(part.sectors(), &mut one) == Err(BlockError::BeyondPartition);
    let shape = view.read_sectors(0, &mut one[..SECTOR_BYTES - 1]) == Err(BlockError::Refused);
    let empty_part = PartitionView { inner: &disk, part: Partition { base: 9, last: 3 } };
    let empty_rejected = empty_part.read_sectors(0, &mut one) == Err(BlockError::BeyondPartition);

    // ⑤ base=0 ⇒ 读到保护性 MBR，挂载必须拒
    let zero_base = PartitionView { inner: &disk, part: Partition { base: 0, last: part.last } };
    let zero_rejected = fat32::Volume::mount(&zero_base).is_err();

    // ⑥ 偏移敏感性（合成盘，不碰真盘）：前缀 + 整卷，base=PREFIX 必须与整卷读逐字节相同
    let mut prefixed = [0u8; (PREFIX + SYN_SECTORS) * SECTOR_BYTES];
    prefixed[PREFIX * SECTOR_BYTES..].copy_from_slice(FAT16_MEM);
    let syn_whole = MemDisk { img: FAT16_MEM };
    let syn_part = MemDisk { img: &prefixed };
    let mut base_buf = [0u8; SYN_SIZE];
    let mut off_buf = [0u8; SYN_SIZE];
    let mut wrong_buf = [0u8; SYN_SIZE];
    let whole_fnv = read_syn(&syn_whole, &mut base_buf);
    let view_ok = PartitionView {
        inner: &syn_part,
        part: Partition { base: PREFIX as u64, last: (PREFIX + SYN_SECTORS - 1) as u64 },
    };
    let off_fnv = read_syn(&view_ok, &mut off_buf);
    let view_wrong = PartitionView {
        inner: &syn_part,
        part: Partition { base: (PREFIX + 1) as u64, last: (PREFIX + SYN_SECTORS) as u64 },
    };
    let wrong_fnv = read_syn(&view_wrong, &mut wrong_buf);
    let offset_honored = whole_fnv.is_some() && whole_fnv == off_fnv && base_buf == off_buf;
    let offset_sensitive = wrong_fnv != whole_fnv;

    crate::log_info!(
        "esp: 口={} ESP[first={} last={} 扇区={}] 类型FAT16={} 文件={} 大小={} 读到={} 装得下={} FNV={:#018x} 扫过项={} 长名项={}",
        port, part.base, part.last, part.sectors(), is16, WANT, st.size, n, fits, fnv,
        st.entries_seen, st.lfn_entries
    );
    crate::log_info!(
        "esp: 判据 真读={} 句柄带偏移同数={} 不带偏移不同={}（那一路读到={:?}） 越界拒={} 形状错另码={} 空区间拒={} base0拒={} 合成偏移照读={} 偏移改一格内容变={}",
        read_ok, handle_same, whole_differs, whole_read, beyond, shape, empty_rejected,
        zero_rejected, offset_honored, offset_sensitive
    );
    let ok = read_ok && handle_same && whole_differs && beyond && shape && empty_rejected
        && zero_rejected && offset_honored && offset_sensitive && is16;
    if !ok {
        crate::log_fatal!("esp: 分区偏移读文件的判据不成立（上面两行是全部读数）");
    }
    ok
}

/// 在任意一块 Block 上挂 FAT16、开 `TEST.BIN`、读满 1000 字节，返回内容 FNV。
/// 挂不开/开不出/读不满都返回 `None`——**与"读到了但内容不同"分开**，
/// 否则"偏移错一格导致挂载失败"会被当成"内容变了"而假绿。
fn read_syn(disk: &dyn Block, out: &mut [u8; SYN_SIZE]) -> Option<u64> {
    let vol = fat32::Volume::mount(disk).ok()?;
    let mut cur = vol.open_cursor(SYN_FILE).ok()?;
    let n = cur.read(disk, out).ok()?;
    if n != SYN_SIZE {
        return None;
    }
    Some(ahci::fnv1a64(out))
}

ktest!(KT_ESP_FILE, t_esp_file);
