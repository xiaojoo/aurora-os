//! FAT16 只读判型与读路径的取证用例（ADR-078 / W4 S2a）。只在 `fat16-probe` 档注册。
//!
//! 载体是**宿主机现算的合成整卷**：`tools/make_fat16_mem.py` 写出 `kernel/fixtures/fat16-mem.img`
//! （23 扇区，不在仓库里，指纹登记在 `tools/aurora.py`），内核 `include_bytes!` **同一份字节**。
//! 这样两台仪器读的是同一块卷，而不是各自实现同一个配方——后者错会一起错（ADR-038 决策 2/3）。
//! 宿主机那台独立读表在 `tools/validate_esp.py` 的 `fat16_facts`，由矩阵行逐格对账。
//!
//! 三件最容易写错、且错了"计数还好看"的事各有一格：
//! 1 **判型只看结构**：本卷簇数 16 落在 FAT12 档，仍必须按 FAT16 读；另有一格纯 BPB 反例——
//!   结构是 FAT16 而簇数落在 FAT32 档，也必须按 FAT16 收下（不许用阈值分流）。
//! 2 **FAT16 没有簇号高半**：目录项偏移 20 那两字节是 EA 索引。写成非零，读路径必须**忽略**它。
//! 3 **EOC 是 0xFFF8 不是 0x0FFF_FFF8**：正向那一格就是它的证人（用错常数会 ChainEndsLate）。

use crate::filesystem::fat32::{self, FatType, FsError};
use crate::filesystem::vfs::{MemDisk, SECTOR_BYTES};
use crate::{ahci, ktest};

/// 与 `tools/make_fat16_mem.py` 的产物同一份字节；指纹由 `ensure_fat16_mem` 在**编译之前**核。
static FAT16_MEM: &[u8] = include_bytes!("../../fixtures/fat16-mem.img");

// 这几个数与配方脚本里的同名常数由门禁逐字对账（两处各写一份而不核对正是手册 V8 点名的形状）。
const RESERVED: usize = 1;
const FAT_COUNT: usize = 2;
const SPF16: usize = 1;
const ROOT_ENTRIES: usize = 64;
const ROOT_SECTORS: usize = ROOT_ENTRIES * 32 / SECTOR_BYTES;   // 4
const DATA_START: usize = RESERVED + FAT_COUNT * SPF16 + ROOT_SECTORS;   // 7
const DATA_CLUSTERS: usize = 16;
const TOTAL_SECTORS: usize = DATA_START + DATA_CLUSTERS;         // 23（每簇 1 扇区）
const VOL_BYTES: usize = TOTAL_SECTORS * SECTOR_BYTES;
const FILE_SIZE: usize = 1000;

fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// 回到 pristine。负样本每格都先调它再改一处，免得上一格的残留把下一格证错对象。
fn pristine(b: &mut [u8]) {
    b.copy_from_slice(FAT16_MEM);
}

/// 纯 BPB 的阈值反例：结构是 FAT16（固定根区 + spf16），而簇数落在 FAT32 档。
/// 用阈值分流就会把它当 FAT32 拒掉/误读，本格要求**按结构收下为 Fat16**。
fn threshold_counterexample(img: &mut [u8]) -> bool {
    // 复用调用方那块整卷缓冲：造卷要写 FAT/根区/数据区，喂它一个 512 字节的扇区缓冲会越界
    // （本轮第一版就是这么 panic 的，EXCEPTION(39) 而不是判据红）。
    pristine(img);
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
    pristine(&mut img);
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
        && !vol.backup_same && v.clusters == DATA_CLUSTERS as u64;
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
    crate::log_info!(
        "fat16: 目录 大小={} 首簇={} 扫过项={} 长名={}",
        st.size, st.first_cluster, st.entries_seen, st.lfn_entries
    );
    // 走链喂出来的字节与**夹具里那段字节**逐字节比（不只比哈希：比字节抓得到读错扇区），
    // 同时算一个 FNV 交给宿主机那台独立实现去对（它自己走一遍链算同一个数）。
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
    let want = &FAT16_MEM[DATA_START * SECTOR_BYTES..DATA_START * SECTOR_BYTES + FILE_SIZE];
    let content_ok = fed == FILE_SIZE && w.bytes == FILE_SIZE && got[..FILE_SIZE] == *want;
    let fnv = ahci::fnv1a64(&got[..fed]);
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
        "fat16: 走链 字节={} 簇={} 尾字节={} 末簇后继={:#x} 内容FNV={:#018x} 内容逐字节同={} 游标一致={}",
        w.bytes, w.clusters, w.tail_bytes, w.after_last, fnv, content_ok, cursor_ok
    );

    // 三格点名负样本：每格重造 pristine 再改一处，要求红在**点名**的成因上。
    let mut hi_ignored = false;
    pristine(&mut img);
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
    pristine(&mut img);
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
    pristine(&mut img);
    let r0 = (RESERVED + FAT_COUNT * SPF16) * SECTOR_BYTES;
    img[r0..r0 + ROOT_SECTORS * SECTOR_BYTES].fill(0);
    if let Ok(v4) = fat32::Volume::mount(&MemDisk { img: &img }) {
        let r = v4.open("TEST.BIN");
        root_gone_named = matches!(r, Err(FsError::NoEntry));
        crate::log_info!("fat16: 负样本[根目录区清空] 结果={:?} 点名={}", r.err(), root_gone_named);
    }
    let counter = threshold_counterexample(&mut img);
    let ok = geom_ok && content_ok && cursor_ok && st.entries_seen == 2 && st.size == FILE_SIZE as u32
        && st.first_cluster == 2 && hi_ignored && bad_eoc_named && root_gone_named && counter;
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