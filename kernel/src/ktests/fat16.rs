//! FAT16 只读判型与读路径的取证用例（ADR-078 / W4 S2a）。只在 `fat16-probe` 档注册。
//!
//! 载体是**合成整卷**（23 个扇区，栈上，零 unsafe）：本机没有 mtools，而 FAT16 的真卷在引导盘的
//! ESP 里、要等 S2b 的分区偏移才读得到。合成卷只做便宜的分支覆盖（ADR-038 决策 3 同族手法），
//! 几何与内容的**第二台独立仪器**是下一刀（宿主机侧读表 + 矩阵行），本轮不宣称已对账。
//!
//! 三件最容易被写错、且错了"计数还好看"的事各有一格：
//! 1 **判型只看结构**：本卷簇数落在 FAT12 档，仍必须按 FAT16 读；另有一格纯 BPB 的反例——
//!   结构是 FAT16 而簇数落在 FAT32 档，也必须按 FAT16 收下（不许用阈值分流）。
//! 2 **FAT16 没有簇号高半**：目录项偏移 20 那两字节是 EA 索引。把它写成非零，读路径必须**忽略**它。
//! 3 **EOC 是 0xFFF8 不是 0x0FFF_FFF8**：正向那一格就是它的证人（用错常数会 ChainEndsLate）。

use crate::filesystem::fat32::{self, FatType, FsError};
use crate::filesystem::vfs::{MemDisk, SECTOR_BYTES};
use crate::ktest;

const SPC: usize = 1;
const RESERVED: usize = 1;
const FAT_COUNT: usize = 2;
const SPF16: usize = 1;
const ROOT_ENTRIES: usize = 64;
const ROOT_SECTORS: usize = ROOT_ENTRIES * 32 / SECTOR_BYTES;   // 4
const DATA_START: usize = RESERVED + FAT_COUNT * SPF16 + ROOT_SECTORS;   // 7
const DATA_CLUSTERS: usize = 16;
const TOTAL_SECTORS: usize = DATA_START + DATA_CLUSTERS * SPC;   // 23
const VOL_BYTES: usize = TOTAL_SECTORS * SECTOR_BYTES;
const FILE_SIZE: usize = 1000;

fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// 文件内容**显式依赖扇区序号**：只写成 `i*m mod 256` 的话，因为 512 ≡ 0 (mod 256)，
/// 每个扇区会逐字节相同 ⇒ 读错扇区也对得上（本仓在 FAT32 合成卷上踩过这个坑）。
fn content_at(i: usize) -> u8 {
    (((i / SECTOR_BYTES) * 7 + (i % SECTOR_BYTES) * 13) & 0xFF) as u8
}

fn entry(off: usize, name: &[u8; 11], attr: u8, cluster: u16, size: u32) -> impl Fn(&mut [u8]) + '_ {
    move |b: &mut [u8]| {
        b[off..off + 11].copy_from_slice(name);
        b[off + 11] = attr;
        put16(b, off + 26, cluster);
        put32(b, off + 28, size);
    }
}

/// 造一卷 FAT16：LBA0 引导扇区、LBA1/2 两份 FAT、LBA3..6 固定根目录区、LBA7.. 数据区。
/// 文件 TEST.BIN 占簇 2→3，FAT[3] = 0xFFFF（FAT16 的 EOC）。
fn build(b: &mut [u8]) {
    b.fill(0);
    b[0..3].copy_from_slice(&[0xEB, 0xFE, 0x90]);
    b[3..11].copy_from_slice(b"AURORA16");
    put16(b, 11, SECTOR_BYTES as u16);
    b[13] = SPC as u8;
    put16(b, 14, RESERVED as u16);
    b[16] = FAT_COUNT as u8;
    put16(b, 17, ROOT_ENTRIES as u16);
    put16(b, 19, 0);                       // total16 = 0 ⇒ 用 total32
    b[21] = 0xF8;
    put16(b, 22, SPF16 as u16);
    put32(b, 32, TOTAL_SECTORS as u32);
    put32(b, 36, 0);                       // 36..40 在 FAT16 里不是 spf32，是扩展引导记录
    b[38] = 0x29;                          // FAT16 的 BS_BootSig 在 38（**故意写它**：
                                           // 它让 36..40 那四字节非零，第一版那条 `spf32==0`
                                           // 的结构闸就是这么被当场抓到的）
    b[54..62].copy_from_slice(b"FAT16   ");
    b[510] = 0x55;
    b[511] = 0xAA;
    for k in 0..FAT_COUNT {
        let f = (RESERVED + k * SPF16) * SECTOR_BYTES;
        put16(b, f, 0xFFF8);
        put16(b, f + 2, 0xFFFF);
        put16(b, f + 4, 3);                // 簇 2 → 簇 3
        put16(b, f + 6, 0xFFFF);           // 簇 3 = EOC
    }
    let root = (RESERVED + FAT_COUNT * SPF16) * SECTOR_BYTES;
    entry(root, b"AURORA16   ", 0x08, 0, 0)(b);          // 卷标：必须被跳过
    entry(root + 32, b"TEST    BIN", 0x20, 2, FILE_SIZE as u32)(b);
    for i in 0..FILE_SIZE {
        b[DATA_START * SECTOR_BYTES + i] = content_at(i);
    }
}

/// 纯 BPB 的阈值反例：结构是 FAT16（固定根区 + spf16 + spf32=0），而簇数落在 FAT32 档。
/// 用阈值分流就会把它当 FAT32 拒掉/误读，本格要求**按结构收下为 Fat16**。
fn threshold_counterexample(img: &mut [u8]) -> bool {
    // 复用调用方那块整卷缓冲：`build` 要写 FAT/根区/数据区，喂它一个 512 字节的扇区缓冲会越界
    // （本轮第一版就是这么 panic 的，EXCEPTION(39) 而不是判据红）。
    build(img);
    let mut b = [0u8; SECTOR_BYTES];
    b.copy_from_slice(&img[..SECTOR_BYTES]);
    put32(&mut b, 32, 0x0002_0000);        // 131072 扇区 ⇒ 簇数远超 65525
    match fat32::parse_boot_sector(&b) {
        Ok(bpb) => {
            let band = fat32::band_type(bpb.clusters);
            let ok = bpb.fat_type == FatType::Fat16 && band == FatType::Fat32;
            crate::log_info!(
                "fat16: 阈值反例 结构判型={:?} 阈值判型={:?} 簇数={} 收下为FAT16={}",
                bpb.fat_type, band, bpb.clusters, ok
            );
            ok
        }
        Err(e) => {
            crate::log_fatal!("fat16: 阈值反例竟然被拒 拒因={:?}（用阈值分流就会长这样）", e);
            false
        }
    }
}

fn t_fat16() -> bool {
    let mut img = [0u8; VOL_BYTES];
    build(&mut img);
    let disk = MemDisk { img: &img };
    let vol = match fat32::Volume::mount(&disk) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("fat16: 合成整卷挂载被拒 拒因={:?}", e);
            return false;
        }
    };
    let v = &vol.bpb;
    let geom_ok = v.fat_type == FatType::Fat16 && v.root_entries == ROOT_ENTRIES as u16
        && v.root_dir_sectors == ROOT_SECTORS as u64 && v.data_start == DATA_START as u64
        && v.sectors_per_fat == SPF16 as u32 && v.fat_entry_bytes == 2
        && v.eoc_marker == 0xFFF8 && v.cluster_mask == 0xFFFF && v.fs_name_ok
        && !vol.backup_same;
    crate::log_info!(
        "fat16: 几何 判型={:?} 簇数={} 数据起点={} 根目录区扇区={} 根项数={} 每份扇区={} 项宽={} EOC={:#x} 掩码={:#x} 名字串={} 无备份引导={} 阈值判型={:?}",
        v.fat_type, v.clusters, v.data_start, v.root_dir_sectors, v.root_entries, v.sectors_per_fat,
        v.fat_entry_bytes, v.eoc_marker, v.cluster_mask, v.fs_name_ok, !vol.backup_same,
        fat32::band_type(v.clusters)
    );
    let st = match vol.open("TEST.BIN") {
        Ok(s) => s,
        Err(e) => {
            crate::log_fatal!("fat16: 固定根目录区里找不到 TEST.BIN 拒因={:?}（把根当簇链走就会长这样）", e);
            return false;
        }
    };
    // 走链喂出来的字节必须与造卷时写下去的逐字节相同（不是只比哈希：比字节抓得到读错扇区）。
    let mut got = [0u8; 1024];
    let mut fed = 0usize;
    let w = match vol.walk(&st, |seg| {
        got[fed..fed + seg.len()].copy_from_slice(seg);
        fed += seg.len();
    }) {
        Ok(w) => w,
        Err(e) => {
            crate::log_fatal!("fat16: 走链被拒 拒因={:?}（EOC 用成 FAT32 的数就会 ChainEndsLate）", e);
            return false;
        }
    };
    let mut content_ok = fed == FILE_SIZE && w.bytes == FILE_SIZE;
    for i in 0..FILE_SIZE {
        if got[i] != content_at(i) {
            content_ok = false;
            break;
        }
    }
    // 游标续读必须与走链同数（两条路共用一份几何，分家就会在这里露）。
    let mut cur = match vol.open_cursor("TEST.BIN") {
        Ok(c) => c,
        Err(e) => {
            crate::log_fatal!("fat16: 开游标被拒 拒因={:?}", e);
            return false;
        }
    };
    let mut cgot = [0u8; 1024];
    let mut cdone = 0usize;
    let mut cursor_ok = true;
    while cdone < FILE_SIZE {
        match cur.read(&disk, &mut cgot[cdone..FILE_SIZE]) {
            Ok(0) => { cursor_ok = false; break; }
            Ok(n) => cdone += n,
            Err(e) => {
                crate::log_fatal!("fat16: 游标续读被拒 拒因={:?}", e);
                cursor_ok = false;
                break;
            }
        }
    }
    cursor_ok = cursor_ok && cdone == FILE_SIZE && cgot[..FILE_SIZE] == got[..FILE_SIZE];
    crate::log_info!(
        "fat16: 读 目录大小={} 首簇={} 扫过项={} 走字节={} 走簇={} 尾字节={} 末簇后继={:#x} 内容逐字节同={} 游标一致={}",
        st.size, st.first_cluster, st.entries_seen, w.bytes, w.clusters, w.tail_bytes, w.after_last,
        content_ok, cursor_ok
    );

    // 三格点名负样本：每格重造 pristine 再改一处，要求红在**点名**的成因上。
    let mut hi_ignored = false;
    build(&mut img);
    let root = (RESERVED + FAT_COUNT * SPF16) * SECTOR_BYTES;
    put16(&mut img, root + 32 + 20, 0x1234);   // FAT16 没有高半，这两字节是 EA 索引
    if let Ok(v2) = fat32::Volume::mount(&MemDisk { img: &img }) {
        if let Ok(s2) = v2.open("TEST.BIN") {
            hi_ignored = s2.first_cluster == 2;
            crate::log_info!("fat16: 负样本[高半非零必须忽略] 首簇={} 忽略={}", s2.first_cluster, hi_ignored);
        } else {
            crate::log_info!("fat16: 负样本[高半非零必须忽略] open 被拒 ⇒ 没忽略（读了高半）");
        }
    }
    let mut bad_eoc_named = false;
    build(&mut img);
    for k in 0..FAT_COUNT {
        put16(&mut img, (RESERVED + k * SPF16) * SECTOR_BYTES + 6, 0xFFF7);   // 坏簇标记，不是 EOC
    }
    if let Ok(v3) = fat32::Volume::mount(&MemDisk { img: &img }) {
        if let Ok(s3) = v3.open("TEST.BIN") {
            let r = v3.walk(&s3, |_| {});
            bad_eoc_named = matches!(r, Err(FsError::ChainEndsLate { .. }));
            crate::log_info!("fat16: 负样本[0xFFF7不是EOC] 结果={:?} 点名={}", r.err(), bad_eoc_named);
        }
    }
    let mut root_gone_named = false;
    build(&mut img);
    let r0 = (RESERVED + FAT_COUNT * SPF16) * SECTOR_BYTES;
    img[r0..r0 + ROOT_SECTORS * SECTOR_BYTES].fill(0);
    if let Ok(v4) = fat32::Volume::mount(&MemDisk { img: &img }) {
        let r = v4.open("TEST.BIN");
        root_gone_named = matches!(r, Err(FsError::NoEntry));
        crate::log_info!("fat16: 负样本[根目录区清空] 结果={:?} 点名={}", r.err(), root_gone_named);
    }
    let counter = threshold_counterexample(&mut img);
    let ok = geom_ok && content_ok && cursor_ok && st.entries_seen == 2
        && hi_ignored && bad_eoc_named && root_gone_named && counter;
    crate::log_info!(
        "fat16: 判据 几何={} 内容={} 游标={} 卷标被跳过={} 高半忽略={} 坏簇不当EOC={} 根区清空点名={} 阈值反例={}",
        geom_ok, content_ok, cursor_ok, st.entries_seen == 2, hi_ignored, bad_eoc_named, root_gone_named, counter
    );
    if !ok {
        crate::log_fatal!("fat16: 判据不成立（上面每格都有读数）");
    }
    ok
}

#[cfg(feature = "fat16-probe")]
ktest!(KT_FAT16, t_fat16);