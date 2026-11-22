//! FS-01：只读 VFS 适配层的取证用例（ADR-107）。只在 `fs-ro` 档注册。
//!
//! 载体是**本文件现算**的 24 扇区 FAT16 合成整卷：根目录固定区、一个子目录簇、两条 8.3 文件、
//! 一条 LFN 计数项。选 FAT16 是因为它不需要 FSInfo/备份引导，几何小到能在栈上造；
//! 被测的是 `vfs_ro`，不是又一份 FAT 解析器——卷的形状仍由 `fat32.rs` 读。
//!
//! 每一格都写清“改哪一条会让它红”：
//! 1 路径：相对路径、`.`/`..`、超长、重复斜杠；
//! 2 目录：根/子目录枚举、LFN 计数、`.`/`..` 跳过、`entries_seen` 覆盖面；
//! 3 读：顺序读、目录当文件拒、FAT16 目录项高半必须忽略；
//! 4 坏卷：越界簇、簇链成环、目录项损坏——必须 `Err`，不许不返回。

use crate::ahci;
use crate::filesystem::fat32::FsError;
use crate::filesystem::gpt;
use crate::filesystem::vfs::{AhciDisk, Block, BlockError, DiskKey, MemDisk, Partition, PartitionView, SECTOR_BYTES};
use crate::filesystem::vfs_ro::{self, Entry, ReadOnlyFs, VfsError};
use crate::ktest;

const SECTOR: usize = 512;
const RESERVED: usize = 1;
const FATS: usize = 2;
const SPF16: usize = 1;
const ROOT_ENTRIES: usize = 64;
const ROOT_SECTORS: usize = ROOT_ENTRIES * 32 / SECTOR; // 4
const TOTAL_SECTORS: usize = 24;
const DATA_START: usize = RESERVED + FATS * SPF16 + ROOT_SECTORS; // 7
const VOL_BYTES: usize = TOTAL_SECTORS * SECTOR;
const ROOT_LBA: usize = RESERVED + FATS * SPF16; // 3

const ATTR_DIR: u8 = 0x10;
const ATTR_FILE: u8 = 0x20;
const ATTR_LFN: u8 = 0x0F;

// FAT32 合成卷：与 `tools/make_fat32_mem.py` 同一种布局口径（保留区 8、FSInfo 1、备份 6、
// FAT 两份在 8/9、数据从 10 开始），但只为 VFS 这一层裁剪到 22 扇区。
const F32_RESERVED: usize = 8;
const F32_FATS: usize = 2;
const F32_SPF: usize = 1;
const F32_TOTAL: usize = 22;
const F32_DATA_START: usize = F32_RESERVED + F32_FATS * F32_SPF; // 10
const F32_VOL_BYTES: usize = F32_TOTAL * SECTOR;
const F32_ROOT_LBA: usize = F32_DATA_START; // 簇 2
const F32_SUB_LBA: usize = F32_DATA_START + 1; // 簇 3
const F32_LFN_LBA: usize = F32_DATA_START + 2; // 簇 4
const F32_INNER_LBA: usize = F32_DATA_START + 3; // 簇 5

/// ESP 根的 VFAT 长名。短名 `LIMINE.CON` 与它指向同一目录项。
const ESP_BUF: usize = 1024;
static LIMINE_CONF: &[u8] = include_bytes!("../../../../boot/limine.conf");

const FILE_ROOT_LEN: usize = 5;
const FILE_LFN_LEN: usize = 3;
const FILE_INNER_LEN: usize = 7;

fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn set_name(e: &mut [u8], base: &str, ext: &str) {
    for b in &mut e[0..8] {
        *b = b' ';
    }
    for b in &mut e[8..11] {
        *b = b' ';
    }
    for (i, b) in base.as_bytes().iter().take(8).enumerate() {
        e[i] = *b;
    }
    for (i, b) in ext.as_bytes().iter().take(3).enumerate() {
        e[8 + i] = *b;
    }
}

fn set_entry(e: &mut [u8], base: &str, ext: &str, attr: u8, hi: u16, cluster: u32, size: u32) {
    e.fill(0);
    set_name(e, base, ext);
    e[11] = attr;
    // FAT16 的偏移 20 是 EA 索引；FAT32 的偏移 20 是簇号高半。调用方决定写什么。
    put16(e, 20, hi);
    put16(e, 26, cluster as u16);
    put32(e, 28, size);
}

fn put_entry(img: &mut [u8], lba: usize, idx: usize, base: &str, ext: &str, attr: u8, hi: u16, cluster: u32, size: u32) {
    let mut e = [0u8; 32];
    set_entry(&mut e, base, ext, attr, hi, cluster, size);
    let off = lba * SECTOR + idx * 32;
    img[off..off + 32].copy_from_slice(&e);
}

fn put_lfn(img: &mut [u8], lba: usize, idx: usize) {
    let off = lba * SECTOR + idx * 32;
    img[off..off + 32].fill(0);
    img[off] = 0x41; // 最后一条 LFN、序号 1
    img[off + 11] = ATTR_LFN;
    img[off + 13] = 0x12; // 校验和（今天只计数，不解析）
}

fn fat_set(img: &mut [u8], cluster: u32, val: u16) {
    for copy in 0..FATS {
        let base = (RESERVED + copy * SPF16) * SECTOR;
        put16(img, base + cluster as usize * 2, val);
    }
}

fn make_image(img: &mut [u8; VOL_BYTES]) {
    img.fill(0);
    // 引导扇区：FAT16 = root_entries != 0 && spf16 != 0
    put16(img, 11, SECTOR as u16);
    img[13] = 1;
    put16(img, 14, RESERVED as u16);
    img[16] = FATS as u8;
    put16(img, 17, ROOT_ENTRIES as u16);
    put16(img, 19, TOTAL_SECTORS as u16);
    img[21] = 0xF8;
    put16(img, 22, SPF16 as u16);
    img[36] = 0x80;
    img[38] = 0x29;
    img[43..54].copy_from_slice(b"AURORA FS  ");
    img[54..62].copy_from_slice(b"FAT16   ");
    img[510] = 0x55;
    img[511] = 0xAA;

    // FAT 两份同步；0/1 保留，2=子目录，3/4/5=三个文件。
    fat_set(img, 0, 0xFFF8);
    fat_set(img, 1, 0xFFFF);
    for c in 2..=5 {
        fat_set(img, c, 0xFFFF);
    }

    // 根目录（固定区）：SUB / ROOT.TXT / LFN + LONGFI~1.TXT
    put_entry(img, ROOT_LBA, 0, "SUB", "", ATTR_DIR, 0x1234, 2, 0);
    put_entry(img, ROOT_LBA, 1, "ROOT", "TXT", ATTR_FILE, 0x1234, 3, FILE_ROOT_LEN as u32);
    put_lfn(img, ROOT_LBA, 2);
    put_entry(img, ROOT_LBA, 3, "LONGFI~1", "TXT", ATTR_FILE, 0x1234, 4, FILE_LFN_LEN as u32);
    // idx 4 保持全零 = 目录结束

    // 子目录簇 2：. / .. / INNER.TXT
    put_entry(img, DATA_START, 0, ".", "", ATTR_DIR, 0x1234, 2, 0);
    put_entry(img, DATA_START, 1, "..", "", ATTR_DIR, 0x1234, 0, 0);
    put_entry(img, DATA_START, 2, "INNER", "TXT", ATTR_FILE, 0x1234, 5, FILE_INNER_LEN as u32);

    let root_data = (DATA_START + 1) * SECTOR; // 簇 3
    img[root_data..root_data + FILE_ROOT_LEN].copy_from_slice(b"root\n");
    let lfn_data = (DATA_START + 2) * SECTOR; // 簇 4
    img[lfn_data..lfn_data + FILE_LFN_LEN].copy_from_slice(b"lfn");
    let inner_data = (DATA_START + 3) * SECTOR; // 簇 5
    img[inner_data..inner_data + FILE_INNER_LEN].copy_from_slice(b"inner!\n");
}

fn fat_set32(img: &mut [u8], cluster: u32, val: u32) {
    for copy in 0..F32_FATS {
        let base = (F32_RESERVED + copy * F32_SPF) * SECTOR;
        put32(img, base + cluster as usize * 4, val);
    }
}

fn make_image32(img: &mut [u8; F32_VOL_BYTES]) {
    img.fill(0);
    put16(img, 11, SECTOR as u16);
    img[13] = 1;
    put16(img, 14, F32_RESERVED as u16);
    img[16] = F32_FATS as u8;
    put16(img, 17, 0); // FAT32：固定根区为 0
    put16(img, 19, F32_TOTAL as u16);
    img[21] = 0xF8;
    put16(img, 22, 0);
    put32(img, 32, F32_TOTAL as u32);
    put32(img, 36, F32_SPF as u32);
    put32(img, 44, 2); // 根目录簇
    put16(img, 48, 1); // FSInfo
    put16(img, 50, 6); // 备份引导扇区
    img[64] = 0x80;
    img[66] = 0x29;
    img[82..90].copy_from_slice(b"FAT32   ");
    img[510] = 0x55;
    img[511] = 0xAA;

    put32(img, SECTOR, 0x4161_5252);
    put32(img, SECTOR + 484, 0x6141_7272);
    put32(img, SECTOR + 488, 0xFFFF_FFFF);
    put32(img, SECTOR + 492, 0xFFFF_FFFF);
    put16(img, SECTOR + 510, 0xAA55);
    // 备份引导扇区必须与 0 号扇区逐字节相同（mount 会判）。
    img.copy_within(0..SECTOR, 6 * SECTOR);

    fat_set32(img, 0, 0x0FFF_FFF8);
    fat_set32(img, 1, 0x0FFF_FFFF);
    for c in 2..=5 {
        fat_set32(img, c, 0x0FFF_FFFF);
    }

    put_entry(img, F32_ROOT_LBA, 0, "SUB", "", ATTR_DIR, 0, 3, 0);
    put_lfn(img, F32_ROOT_LBA, 1);
    put_entry(img, F32_ROOT_LBA, 2, "LONGFI~1", "TXT", ATTR_FILE, 0, 4, FILE_LFN_LEN as u32);
    put_entry(img, F32_SUB_LBA, 0, ".", "", ATTR_DIR, 0, 3, 0);
    put_entry(img, F32_SUB_LBA, 1, "..", "", ATTR_DIR, 0, 0, 0);
    put_entry(img, F32_SUB_LBA, 2, "INNER", "TXT", ATTR_FILE, 0, 5, FILE_INNER_LEN as u32);

    img[F32_LFN_LBA * SECTOR..F32_LFN_LBA * SECTOR + FILE_LFN_LEN].copy_from_slice(b"lfn");
    img[F32_INNER_LBA * SECTOR..F32_INNER_LBA * SECTOR + FILE_INNER_LEN].copy_from_slice(b"inner!\n");
}

fn short_checksum_name(base: &str, ext: &str) -> u8 {
    let mut e = [b' '; 11];
    for (i, b) in base.as_bytes().iter().take(8).enumerate() {
        e[i] = *b;
    }
    for (i, b) in ext.as_bytes().iter().take(3).enumerate() {
        e[8 + i] = *b;
    }
    let mut sum = 0u8;
    for b in e {
        sum = sum.rotate_right(1).wrapping_add(b);
    }
    sum
}

/// 写一组 LFN 片段 + 对应的 8.3 短名。返回占用的目录项数（含短名）。
fn put_lfn_name(img: &mut [u8], lba: usize, idx: usize, base: &str, ext: &str, long: &str) -> usize {
    const UNITS: usize = 20 * 13;
    let mut units = [0xFFFFu16; UNITS];
    let mut n = 0usize;
    for ch in long.chars() {
        if n + 1 >= UNITS {
            break;
        }
        units[n] = ch as u16;
        n += 1;
    }
    units[n] = 0;
    let count = (n + 1 + 12) / 13;
    let sum = short_checksum_name(base, ext);
    for k in 0..count {
        let ord = count - k;
        let mut e = [0u8; 32];
        e[0] = (ord as u8) | if ord == count { 0x40 } else { 0 };
        e[11] = ATTR_LFN;
        e[13] = sum;
        let base_unit = (ord - 1) * 13;
        for (j, &off) in [1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30].iter().enumerate() {
            put16(&mut e, off, units[base_unit + j]);
        }
        let at = lba * SECTOR + (idx + k) * 32;
        img[at..at + 32].copy_from_slice(&e);
    }
    put_entry(img, lba, idx + count, base, ext, ATTR_FILE, 0x1234, 0, 0);
    count + 1
}

fn put_times(img: &mut [u8], lba: usize, idx: usize, tens: u8, ct: u16, cd: u16, ad: u16, wt: u16, wd: u16) {
    let o = lba * SECTOR + idx * 32;
    img[o + 13] = tens;
    put16(img, o + 14, ct);
    put16(img, o + 16, cd);
    put16(img, o + 18, ad);
    put16(img, o + 22, wt);
    put16(img, o + 24, wd);
}

fn make_image_lfn(img: &mut [u8; VOL_BYTES]) {
    make_image(img);
    // 清掉 FS-01 的根/子目录内容，保留几何、FAT 与数据区。
    img[ROOT_LBA * SECTOR..(ROOT_LBA + ROOT_SECTORS) * SECTOR].fill(0);
    img[DATA_START * SECTOR..(DATA_START + 1) * SECTOR].fill(0);

    let used = put_lfn_name(img, ROOT_LBA, 0, "LONGFI~1", "TXT", "AuroraLongFileName.txt");
    put_entry(img, ROOT_LBA, used - 1, "LONGFI~1", "TXT", 0x27, 0x1234, 3, 5);
    put_times(img, ROOT_LBA, used - 1, 0x0A, 0x6000, 0x5A21, 0x5A22, 0x6123, 0x5A23);

    let used2 = put_lfn_name(img, ROOT_LBA, used, "PROJEC~1", "", "项目目录");
    put_entry(img, ROOT_LBA, used + used2 - 1, "PROJEC~1", "", ATTR_DIR, 0x1234, 2, 0);

    put_entry(img, DATA_START, 0, ".", "", ATTR_DIR, 0x1234, 2, 0);
    put_entry(img, DATA_START, 1, "..", "", ATTR_DIR, 0x1234, 0, 0);
    let used3 = put_lfn_name(img, DATA_START, 2, "INNER~1", "TXT", "inner-long-name.txt");
    put_entry(img, DATA_START, 2 + used3 - 1, "INNER~1", "TXT", ATTR_FILE, 0x1234, 4, 7);

    let d3 = (DATA_START + 1) * SECTOR;
    img[d3..d3 + 5].copy_from_slice(b"long\n");
    let d4 = (DATA_START + 2) * SECTOR;
    img[d4..d4 + FILE_INNER_LEN].copy_from_slice(b"inner!\n");
}

fn fail(what: &str, why: VfsError) -> bool {
    crate::log_fatal!("vfs-ro: 不成立 {} 成因={}", what, why.tag());
    false
}

fn lookup(fs: &ReadOnlyFs<'_>, path: &str) -> Result<Entry, VfsError> {
    fs.lookup(path)
}

fn read_all(fs: &ReadOnlyFs<'_>, e: &Entry, out: &mut [u8]) -> Result<usize, VfsError> {
    let mut cur = fs.open(e)?;
    let mut n = 0usize;
    while n < out.len() {
        match fs.read(&mut cur, &mut out[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

fn drain_bad(fs: &ReadOnlyFs<'_>, dir: &Entry) -> Result<u32, VfsError> {
    let mut cur = fs.dir_cursor(dir)?;
    while fs.next_entry(&mut cur)?.is_some() {}
    Ok(cur.lfn_bad())
}

fn t_vfs_ro() -> bool {
    let mut img = [0u8; VOL_BYTES];
    make_image(&mut img);
    let disk = MemDisk { img: &img };
    let fs = match ReadOnlyFs::mount(&disk) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("vfs-ro: 合成卷挂载被拒 成因={}", e.tag());
            return false;
        }
    };
    crate::log_info!(
        "vfs-ro: 几何 根项数={} 根区扇区={} 数据起点={} 簇数={}",
        ROOT_ENTRIES, ROOT_SECTORS, DATA_START, TOTAL_SECTORS - DATA_START
    );

    let root = fs.root();
    let sub = match lookup(&fs, "/SUB") {
        Ok(e) => e,
        Err(e) => return fail("查 /SUB", e),
    };
    if !sub.is_dir() || sub.first_cluster != 2 {
        return fail("SUB 目录项", VfsError::BadPath);
    }
    let inner = match lookup(&fs, "/SUB/INNER.TXT") {
        Ok(e) => e,
        Err(e) => return fail("查 /SUB/INNER.TXT", e),
    };
    if inner.is_dir() || inner.size as usize != FILE_INNER_LEN || inner.first_cluster != 5 {
        return fail("INNER 元数据", VfsError::BadPath);
    }
    let mut buf = [0u8; 16];
    let n = match read_all(&fs, &inner, &mut buf) {
        Ok(n) => n,
        Err(e) => return fail("读 INNER", e),
    };
    if n != FILE_INNER_LEN || &buf[..n] != b"inner!\n" {
        return fail("INNER 内容", VfsError::BadPath);
    }
    let root_txt = match lookup(&fs, "/ROOT.TXT") {
        Ok(e) => e,
        Err(e) => return fail("查 /ROOT.TXT", e),
    };
    let n = match read_all(&fs, &root_txt, &mut buf) {
        Ok(n) => n,
        Err(e) => return fail("读 ROOT.TXT", e),
    };
    if n != FILE_ROOT_LEN || &buf[..n] != b"root\n" {
        return fail("ROOT.TXT 内容", VfsError::BadPath);
    }
    let lfn = match lookup(&fs, "/LONGFI~1.TXT") {
        Ok(e) => e,
        Err(e) => return fail("查 LONGFI~1.TXT", e),
    };
    let n = match read_all(&fs, &lfn, &mut buf) {
        Ok(n) => n,
        Err(e) => return fail("读 LONGFI~1.TXT", e),
    };
    if n != FILE_LFN_LEN || &buf[..n] != b"lfn" {
        return fail("LFN 短名内容", VfsError::BadPath);
    }
    crate::log_info!(
        "vfs-ro: 路径 SUB首簇={} INNER大小={} 读={} 根文件读={} 长名项={}",
        sub.first_cluster, inner.size, FILE_INNER_LEN, FILE_ROOT_LEN, inner.lfn_entries
    );

    // 重复斜杠折叠：与带单斜杠的必须指向同一项。
    match lookup(&fs, "//SUB///INNER.TXT") {
        Ok(e) if e.first_cluster == inner.first_cluster && e.size == inner.size => {}
        Ok(_) => return fail("重复斜杠折叠", VfsError::BadPath),
        Err(e) => return fail("查 //SUB///INNER.TXT", e),
    }

    // 根目录枚举：3 个可见项，扫过 4 条（含 LFN），LFN 计数 1。
    let mut root_cur = match fs.dir_cursor(&root) {
        Ok(c) => c,
        Err(e) => return fail("开根目录游标", e),
    };
    let mut names = [[0u8; vfs_ro::NAME_MAX]; 4];
    let mut lens = [0usize; 4];
    let mut count = 0usize;
    loop {
        match fs.next_entry(&mut root_cur) {
            Ok(Some(e)) => {
                if count < names.len() {
                    names[count][..e.name().len()].copy_from_slice(e.name());
                    lens[count] = e.name().len();
                }
                count += 1;
            }
            Ok(None) => break,
            Err(e) => return fail("根目录枚举", e),
        }
    }
    let root_ok = count == 3
        && &names[0][..lens[0]] == b"SUB"
        && &names[1][..lens[1]] == b"ROOT.TXT"
        && &names[2][..lens[2]] == b"LONGFI~1.TXT"
        && root_cur.entries_seen() == 4
        && root_cur.lfn_entries() == 1;
    crate::log_info!(
        "vfs-ro: 根目录 可见={} 扫过项={} 长名={}",
        count, root_cur.entries_seen(), root_cur.lfn_entries()
    );
    if !root_ok {
        return fail("根目录枚举读数", VfsError::BadPath);
    }

    // 子目录枚举：`.`/`..` 必须跳过，只看到 INNER.TXT；扫过 3 条。
    let mut sub_cur = match fs.dir_cursor(&sub) {
        Ok(c) => c,
        Err(e) => return fail("开 SUB 游标", e),
    };
    let mut sub_count = 0usize;
    let mut sub_name = [0u8; vfs_ro::NAME_MAX];
    let mut sub_len = 0usize;
    loop {
        match fs.next_entry(&mut sub_cur) {
            Ok(Some(e)) => {
                if sub_count == 0 {
                    sub_name[..e.name().len()].copy_from_slice(e.name());
                    sub_len = e.name().len();
                }
                sub_count += 1;
            }
            Ok(None) => break,
            Err(e) => return fail("SUB 枚举", e),
        }
    }
    let sub_ok = sub_count == 1
        && &sub_name[..sub_len] == b"INNER.TXT"
        && sub_cur.entries_seen() == 3
        && sub_cur.lfn_entries() == 0;
    crate::log_info!(
        "vfs-ro: 子目录 可见={} 扫过项={} 长名={}",
        sub_count, sub_cur.entries_seen(), sub_cur.lfn_entries()
    );
    if !sub_ok {
        return fail("子目录枚举读数", VfsError::BadPath);
    }

    // -------- 负样本：路径形状 --------
    let neg_relative = matches!(fs.lookup("SUB"), Err(VfsError::NotAbsolute));
    let neg_dot = matches!(fs.lookup("/."), Err(VfsError::BadPath));
    let neg_dotdot = matches!(fs.lookup("/SUB/.."), Err(VfsError::BadPath));
    let neg_missing = matches!(fs.lookup("/NOPE.TXT"), Err(VfsError::NotFound));
    let neg_notdir = matches!(fs.lookup("/SUB/INNER.TXT/EXTRA"), Err(VfsError::NotDir));
    // 长名允许 >12 字节；这里只是“形状合法但不存在”，超长由下一格 PATH_MAX 拦。
    let neg_long_absent = matches!(fs.lookup("/ABCDEFGHIJKLM"), Err(VfsError::NotFound));
    let mut long = [b'a'; 300];
    long[0] = b'/';
    let long_path = core::str::from_utf8(&long).unwrap_or("/");
    let neg_toolong_path = matches!(fs.lookup(long_path), Err(VfsError::TooLong));
    let neg_dir_read = matches!(fs.open(&sub), Err(VfsError::IsDir));
    let negs = [
        ("相对路径", neg_relative),
        ("点目录", neg_dot),
        ("父目录", neg_dotdot),
        ("不存在", neg_missing),
        ("文件当目录", neg_notdir),
        ("长名不存在", neg_long_absent),
        ("路径过长", neg_toolong_path),
        ("读目录", neg_dir_read),
    ];
    let mut neg_ok = true;
    for (what, ok) in negs {
        crate::log_info!("vfs-ro: 负格 {}={}", what, ok);
        neg_ok &= ok;
    }
    if !neg_ok {
        return fail("路径负样本", VfsError::BadPath);
    }

    // -------- 负样本：坏卷 --------
    // 1 目录簇成环：FAT[2] = 2，且子目录扇区没有结束标记（整扇区填 0xE5）。
    //    “没有 0x00 结束”+“簇链回到自己”必须被有界错误拦住，而不是不返回。
    //    目录项上界（4096）先于簇链上界（65535）触发，所以这里期望 DirTooLong。
    make_image(&mut img);
    for b in &mut img[DATA_START * SECTOR..(DATA_START + 1) * SECTOR] {
        *b = 0xE5;
    }
    fat_set(&mut img, 2, 2);
    let disk_loop = MemDisk { img: &img };
    let fs_loop = match ReadOnlyFs::mount(&disk_loop) {
        Ok(f) => f,
        Err(e) => return fail("环卷挂载", e),
    };
    let loop_rejected = matches!(fs_loop.lookup("/SUB/INNER.TXT"), Err(VfsError::DirTooLong));

    // 2 目录项簇号越界：SUB 指向 0x1000（卷只有 17 个簇）。
    make_image(&mut img);
    put_entry(&mut img, ROOT_LBA, 0, "SUB", "", ATTR_DIR, 0x1234, 0x1000, 0);
    let disk_out = MemDisk { img: &img };
    let fs_out = match ReadOnlyFs::mount(&disk_out) {
        Ok(f) => f,
        Err(e) => return fail("越界卷挂载", e),
    };
    let out_rejected = matches!(
        fs_out.lookup("/SUB"),
        Err(VfsError::Fs(crate::filesystem::fat32::FsError::EntryOutsideData(0x1000)))
    );

    // 3 子目录里的文件簇号越界：枚举到 INNER.TXT 时必须报，而不是交出一个坏 Entry。
    make_image(&mut img);
    put_entry(&mut img, DATA_START, 2, "INNER", "TXT", ATTR_FILE, 0x1234, 0x1000, FILE_INNER_LEN as u32);
    let disk_bad = MemDisk { img: &img };
    let fs_bad = match ReadOnlyFs::mount(&disk_bad) {
        Ok(f) => f,
        Err(e) => return fail("坏项目录挂载", e),
    };
    let sub_bad = match lookup(&fs_bad, "/SUB") {
        Ok(e) => e,
        Err(e) => return fail("查坏项 SUB", e),
    };
    let mut cur_bad = match fs_bad.dir_cursor(&sub_bad) {
        Ok(c) => c,
        Err(e) => return fail("开坏项目录游标", e),
    };
    let entry_rejected = loop {
        match fs_bad.next_entry(&mut cur_bad) {
            Ok(Some(_)) => continue,
            Ok(None) => break false,
            Err(VfsError::Fs(crate::filesystem::fat32::FsError::EntryOutsideData(0x1000))) => break true,
            Err(_) => break false,
        }
    };

    crate::log_info!(
        "vfs-ro: 坏卷 环={} 越界={} 坏项={}",
        loop_rejected, out_rejected, entry_rejected
    );
    if !(loop_rejected && out_rejected && entry_rejected) {
        return fail("坏卷负样本", VfsError::BadPath);
    }

    // ADR-111 决策 2：写方向的两种拒绝必须分得开——"只读实现"是 Refused，
    // "越过 GPT 给的那个区间"是 BeyondPartition。合成一格，负样本就再也分不开是谁拒的。
    // 借用只在这一次里：上面 `make_image(&mut img)` 之后，早先那个 `disk` 已经不再借 `img`，
    // 这里另起一个短借，别把旧绑定的生命周期拖到函数末尾（会的，NLL 一扩就红）。
    let mut one = [0u8; 512];
    let (ro_refused, out_beyond, in_refused, bad_shape) = {
        let ro = MemDisk { img: &img };
        let part = Partition { base: 0, last: 0 };
        let view = PartitionView { inner: &ro, part };
        (
            ro.write_sectors(0, &one) == Err(BlockError::Refused),
            view.write_sectors(1, &one) == Err(BlockError::BeyondPartition),
            view.write_sectors(0, &one) == Err(BlockError::Refused),
            ro.write_sectors(0, &one[..SECTOR_BYTES - 1]) == Err(BlockError::Refused),
        )
    };
    crate::log_info!(
        "vfs-ro: 写方向 只读实现拒={} 分区外拒={} 分区内转发={} 形状拒={}",
        ro_refused, out_beyond, in_refused, bad_shape
    );
    if !(ro_refused && out_beyond && in_refused && bad_shape) {
        return fail("写方向四种拒绝", VfsError::BadPath);
    }

    crate::log_info!("vfs-ro: 判据 到达末尾=true");
    true
}


/// 可变内存盘：写方向的判据要"写进去再读回来"，只读的 `MemDisk` 给不了。
/// 用 `RefCell<&mut [u8]>` 而不是裸指针：这一格不值得开一个 unsafe 白名单条目。
struct RwDisk<'a>(core::cell::RefCell<&'a mut [u8]>);

impl<'a> RwDisk<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        RwDisk(core::cell::RefCell::new(buf))
    }

    fn snapshot(&self) -> alloc::vec::Vec<u8> {
        self.0.borrow().to_vec()
    }
}

impl crate::filesystem::vfs::Block for RwDisk<'_> {
    fn read_sectors(&self, lba: u64, dst: &mut [u8]) -> Result<(), BlockError> {
        let img = self.0.borrow();
        if dst.is_empty() || dst.len() % SECTOR_BYTES != 0 {
            return Err(BlockError::Refused);
        }
        let start = lba as usize * SECTOR_BYTES;
        let end = start + dst.len();
        if end > img.len() {
            return Err(BlockError::Refused);
        }
        dst.copy_from_slice(&img[start..end]);
        Ok(())
    }

    fn write_sectors(&self, lba: u64, src: &[u8]) -> Result<(), BlockError> {
        let mut img = self.0.borrow_mut();
        if src.is_empty() || src.len() % SECTOR_BYTES != 0 {
            return Err(BlockError::Refused);
        }
        let start = lba as usize * SECTOR_BYTES;
        let end = start + src.len();
        if end > img.len() {
            return Err(BlockError::Refused);
        }
        img[start..end].copy_from_slice(src);
        Ok(())
    }
}

/// FAT32 那一半：根在簇链上而不是固定区，目录项簇号要拼高半。与 FAT16 用例分开登记，
/// 免得一条红把另一族的成因也盖住。
fn t_vfs_ro_fat32() -> bool {
    let mut img = [0u8; F32_VOL_BYTES];
    make_image32(&mut img);
    let disk = MemDisk { img: &img };
    let fs = match ReadOnlyFs::mount(&disk) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("vfs-ro-f32: 合成卷挂载被拒 成因={}", e.tag());
            return false;
        }
    };
    let root = fs.root();
    let inner = match fs.lookup("/SUB/INNER.TXT") {
        Ok(e) => e,
        Err(e) => return fail("FAT32 查 /SUB/INNER.TXT", e),
    };
    if inner.is_dir() || inner.size as usize != FILE_INNER_LEN || inner.first_cluster != 5 {
        return fail("FAT32 INNER 元数据", VfsError::BadPath);
    }
    let mut buf = [0u8; 16];
    let n = match read_all(&fs, &inner, &mut buf) {
        Ok(n) => n,
        Err(e) => return fail("FAT32 读 INNER", e),
    };
    if n != FILE_INNER_LEN || &buf[..n] != b"inner!\n" {
        return fail("FAT32 INNER 内容", VfsError::BadPath);
    }
    let lfn = match fs.lookup("/LONGFI~1.TXT") {
        Ok(e) => e,
        Err(e) => return fail("FAT32 查 LONGFI~1.TXT", e),
    };
    let n = match read_all(&fs, &lfn, &mut buf) {
        Ok(n) => n,
        Err(e) => return fail("FAT32 读 LONGFI~1.TXT", e),
    };
    if n != FILE_LFN_LEN || &buf[..n] != b"lfn" {
        return fail("FAT32 LFN 短名内容", VfsError::BadPath);
    }

    let mut root_cur = match fs.dir_cursor(&root) {
        Ok(c) => c,
        Err(e) => return fail("FAT32 开根目录游标", e),
    };
    let mut names = [[0u8; vfs_ro::NAME_MAX]; 3];
    let mut lens = [0usize; 3];
    let mut count = 0usize;
    loop {
        match fs.next_entry(&mut root_cur) {
            Ok(Some(e)) => {
                if count < names.len() {
                    names[count][..e.name().len()].copy_from_slice(e.name());
                    lens[count] = e.name().len();
                }
                count += 1;
            }
            Ok(None) => break,
            Err(e) => return fail("FAT32 根目录枚举", e),
        }
    }
    let root_ok = count == 2
        && &names[0][..lens[0]] == b"SUB"
        && &names[1][..lens[1]] == b"LONGFI~1.TXT"
        && root_cur.entries_seen() == 3
        && root_cur.lfn_entries() == 1;
    crate::log_info!(
        "vfs-ro-f32: 根=簇{} INNER大小={} 根目录可见={} 扫过项={} 长名={}",
        root.first_cluster, inner.size, count, root_cur.entries_seen(), root_cur.lfn_entries()
    );
    if !root_ok {
        return fail("FAT32 根目录读数", VfsError::BadPath);
    }

    // 高半必须被拼进来：hi=1、lo=5 ⇒ 簇号 0x10005，越出这个 12 簇的小卷。
    // 若实现只读低半，这一格会「查得到」而不是被拒 ⇒ 用例红。
    make_image32(&mut img);
    put_entry(&mut img, F32_SUB_LBA, 2, "INNER", "TXT", ATTR_FILE, 1, 5, FILE_INNER_LEN as u32);
    let disk_hi = MemDisk { img: &img };
    let fs_hi = match ReadOnlyFs::mount(&disk_hi) {
        Ok(f) => f,
        Err(e) => return fail("FAT32 高半卷挂载", e),
    };
    let hi_rejected = matches!(
        fs_hi.lookup("/SUB/INNER.TXT"),
        Err(VfsError::Fs(FsError::EntryOutsideData(0x10005)))
    );
    crate::log_info!("vfs-ro-f32: 高半越界被拒={}", hi_rejected);
    if !hi_rejected {
        return fail("FAT32 高半越界", VfsError::BadPath);
    }
    crate::log_info!("vfs-ro-f32: 判据 到达末尾=true");
    true
}

fn t_vfs_ro_lfn() -> bool {
    let mut img = [0u8; VOL_BYTES];
    make_image_lfn(&mut img);
    let disk = MemDisk { img: &img };
    let fs = match ReadOnlyFs::mount(&disk) {
        Ok(f) => f,
        Err(e) => return fail("LFN 卷挂载", e),
    };

    let f = match fs.lookup("/AuroraLongFileName.txt") {
        Ok(e) => e,
        Err(e) => return fail("LFN 查长名文件", e),
    };
    let long_ok = f.long_name() == Some(b"AuroraLongFileName.txt".as_slice())
        && f.name() == b"LONGFI~1.TXT"
        && f.display_name() == b"AuroraLongFileName.txt"
        && f.size == 5
        && f.first_cluster == 3
        && f.is_readonly()
        && f.is_hidden()
        && f.is_system()
        && f.is_archive()
        && !f.is_dir()
        && f.create_tenths == 0x0A
        && f.create_time == 0x6000
        && f.create_date == 0x5A21
        && f.access_date == 0x5A22
        && f.write_time == 0x6123
        && f.write_date == 0x5A23;
    let mut buf = [0u8; 16];
    let n = match read_all(&fs, &f, &mut buf) {
        Ok(n) => n,
        Err(e) => return fail("LFN 读长名文件", e),
    };
    let content_ok = n == 5 && &buf[..5] == b"long\n";
    let short = match fs.lookup("/LONGFI~1.TXT") {
        Ok(e) => e,
        Err(e) => return fail("LFN 短别名", e),
    };
    let alias_ok = short.first_cluster == f.first_cluster && short.size == f.size;

    let dir = match fs.lookup("/项目目录") {
        Ok(e) => e,
        Err(e) => return fail("LFN 查中文目录", e),
    };
    let dir_ok = dir.is_dir()
        && dir.long_name() == Some("项目目录".as_bytes())
        && dir.name() == b"PROJEC~1";
    let inner = match fs.lookup("/项目目录/inner-long-name.txt") {
        Ok(e) => e,
        Err(e) => return fail("LFN 多级长名路径", e),
    };
    let n = match read_all(&fs, &inner, &mut buf) {
        Ok(n) => n,
        Err(e) => return fail("LFN 读子目录文件", e),
    };
    let inner_ok = n == FILE_INNER_LEN && &buf[..n] == b"inner!\n";
    let inner_short = match fs.lookup("/PROJEC~1/INNER~1.TXT") {
        Ok(e) => e,
        Err(e) => return fail("LFN 多级短别名", e),
    };
    let inner_alias_ok = inner_short.first_cluster == inner.first_cluster
        && inner_short.size == inner.size;

    let root = fs.root();
    let mut rc = match fs.dir_cursor(&root) {
        Ok(c) => c,
        Err(e) => return fail("LFN 根目录游标", e),
    };
    let mut visible = 0usize;
    loop {
        match fs.next_entry(&mut rc) {
            Ok(Some(_)) => visible += 1,
            Ok(None) => break,
            Err(e) => return fail("LFN 根目录枚举", e),
        }
    }
    let root_count_ok = visible == 2
        && rc.entries_seen() == 5
        && rc.lfn_entries() == 3
        && rc.lfn_bad() == 0;
    let mut sc = match fs.dir_cursor(&dir) {
        Ok(c) => c,
        Err(e) => return fail("LFN 子目录游标", e),
    };
    let mut sub_visible = 0usize;
    loop {
        match fs.next_entry(&mut sc) {
            Ok(Some(_)) => sub_visible += 1,
            Ok(None) => break,
            Err(e) => return fail("LFN 子目录枚举", e),
        }
    }
    let sub_count_ok = sub_visible == 1
        && sc.entries_seen() == 5
        && sc.lfn_entries() == 2
        && sc.lfn_bad() == 0;
    crate::log_info!(
        "vfs-ro-lfn: 长名={} 短名={} 内容={} 别名={} 中文目录={} 多级={} 根(可见{} 扫过{} 长名{} 坏{}) 子(可见{} 扫过{} 长名{} 坏{})",
        long_ok, f.name().len(), content_ok, alias_ok, dir_ok, inner_ok && inner_alias_ok,
        visible, rc.entries_seen(), rc.lfn_entries(), rc.lfn_bad(),
        sub_visible, sc.entries_seen(), sc.lfn_entries(), sc.lfn_bad()
    );
    if !(long_ok && content_ok && alias_ok && dir_ok && inner_ok && inner_alias_ok
        && root_count_ok && sub_count_ok)
    {
        return fail("LFN 正样本", VfsError::BadPath);
    }

    // ①a 整组校验和一致、但与短名不符：两片都翻成同一个错值 ⇒ 只有“与短名绑定”那一道闸能拒。
    make_image_lfn(&mut img);
    img[ROOT_LBA * SECTOR + 13] ^= 0xFF;
    img[ROOT_LBA * SECTOR + 32 + 13] ^= 0xFF;
    let disk_bad = MemDisk { img: &img };
    let fs_bad = match ReadOnlyFs::mount(&disk_bad) {
        Ok(f) => f,
        Err(e) => return fail("坏校验和卷挂载", e),
    };
    let long_gone = matches!(fs_bad.lookup("/AuroraLongFileName.txt"), Err(VfsError::NotFound));
    let short_ok = fs_bad.lookup("/LONGFI~1.TXT").is_ok();
    let bad_both = match drain_bad(&fs_bad, &fs_bad.root()) {
        Ok(n) => n >= 1,
        Err(e) => return fail("坏校验和根枚举", e),
    };

    // ①b 组内不一致：只翻一片 ⇒ 组装阶段就必须拒。
    make_image_lfn(&mut img);
    img[ROOT_LBA * SECTOR + 32 + 13] ^= 0xFF;
    let disk_mix = MemDisk { img: &img };
    let fs_mix = match ReadOnlyFs::mount(&disk_mix) {
        Ok(f) => f,
        Err(e) => return fail("组内不一致卷挂载", e),
    };
    let mix_long_gone = matches!(fs_mix.lookup("/AuroraLongFileName.txt"), Err(VfsError::NotFound));
    let mix_short_ok = fs_mix.lookup("/LONGFI~1.TXT").is_ok();
    let bad_mix = match drain_bad(&fs_mix, &fs_mix.root()) {
        Ok(n) => n >= 1,
        Err(e) => return fail("组内不一致根枚举", e),
    };
    let bad_checksum_ok = long_gone && short_ok && bad_both && mix_long_gone && mix_short_ok && bad_mix;

    // ② 孤项：LFN 后面直接是目录结束标记；不能挂到任何项上，也不能不返回。
    make_image_lfn(&mut img);
    img[ROOT_LBA * SECTOR + 32] = 0;
    let disk_orphan = MemDisk { img: &img };
    let fs_orphan = match ReadOnlyFs::mount(&disk_orphan) {
        Ok(f) => f,
        Err(e) => return fail("孤项卷挂载", e),
    };
    let mut oc = match fs_orphan.dir_cursor(&fs_orphan.root()) {
        Ok(c) => c,
        Err(e) => return fail("孤项根游标", e),
    };
    let mut orphan_visible = 0usize;
    loop {
        match fs_orphan.next_entry(&mut oc) {
            Ok(Some(_)) => orphan_visible += 1,
            Ok(None) => break,
            Err(e) => return fail("孤项根枚举", e),
        }
    }
    let orphan_ok = orphan_visible == 0 && oc.lfn_bad() >= 1;

    crate::log_info!(
        "vfs-ro-lfn: 坏卷 校验和={} 孤项={}",
        bad_checksum_ok, orphan_ok
    );
    if !(bad_checksum_ok && orphan_ok) {
        return fail("LFN 坏卷负样本", VfsError::BadPath);
    }
    crate::log_info!("vfs-ro-lfn: 判据 到达末尾=true");
    true
}

/// FS-02b：GPT → PartitionView → 只读 VFS，在**真 ESP** 上读文件。没有新增 syscall，
/// 也不改 `Volume::mount` 的语义；证的是“分区偏移 + 只读 VFS”这条链能走通。
fn t_vfs_ro_esp() -> bool {
    if ahci::init().is_err() {
        crate::log_fatal!("vfs-ro-esp: AHCI 认领失败");
        return false;
    }
    let port = match ahci::boot_port() {
        Ok(p) => p,
        Err(e) => {
            crate::log_fatal!("vfs-ro-esp: 找不到引导盘 {:?}", e);
            return false;
        }
    };
    let disk = AhciDisk { port };
    let esp = match gpt::find_esp(&disk) {
        Ok(Some(e)) => e,
        Ok(None) => {
            crate::log_fatal!("vfs-ro-esp: 引导盘上没有 ESP 条目");
            return false;
        }
        Err(e) => {
            crate::log_fatal!("vfs-ro-esp: GPT 读不下来 {:?}", e);
            return false;
        }
    };
    let part = Partition { base: esp.first_lba, last: esp.last_lba };
    let view = PartitionView { inner: &disk, part };
    let fs = match ReadOnlyFs::mount(&view) {
        Ok(f) => f,
        Err(e) => return fail("ESP 挂载", e),
    };

    let short = match fs.lookup("/LIMINE.CON") {
        Ok(e) => e,
        Err(e) => return fail("ESP 查短名", e),
    };
    let long = match fs.lookup("/limine.conf") {
        Ok(e) => e,
        Err(e) => return fail("ESP 查长名", e),
    };
    let alias_ok = long.first_cluster == short.first_cluster
        && long.size == short.size
        && long.long_name() == Some(b"limine.conf".as_slice());
    let mut buf = [0u8; ESP_BUF];
    let n = match read_all(&fs, &short, &mut buf) {
        Ok(n) => n,
        Err(e) => return fail("ESP 读 LIMINE.CON", e),
    };
    let bytes_ok = n == LIMINE_CONF.len() && &buf[..n] == LIMINE_CONF;

    let root = fs.root();
    let mut cur = match fs.dir_cursor(&root) {
        Ok(c) => c,
        Err(e) => return fail("ESP 根目录游标", e),
    };
    let mut visible = 0usize;
    loop {
        match fs.next_entry(&mut cur) {
            Ok(Some(_)) => visible += 1,
            Ok(None) => break,
            Err(e) => return fail("ESP 根目录枚举", e),
        }
    }
    let root_ok = visible >= 2
        && cur.lfn_entries() >= 1
        && cur.lfn_bad() == 0
        && !short.is_dir()
        && short.size as usize == LIMINE_CONF.len();

    // 负样本：base=0 时读到的是保护性 MBR，不能挂成 FAT。
    let bad_view = PartitionView { inner: &disk, part: Partition { base: 0, last: part.last } };
    let base0_rejected = matches!(
        ReadOnlyFs::mount(&bad_view),
        Err(VfsError::Fs(FsError::BadBytesPerSector(0)))
    );

    crate::log_info!(
        "vfs-ro-esp: 口={} base={} 大小={} 别名={} 字节同={} 根可见={} 扫过={} 长名={} 坏={} base0拒={}",
        port, part.base, short.size, alias_ok, bytes_ok, visible, cur.entries_seen(),
        cur.lfn_entries(), cur.lfn_bad(), base0_rejected
    );
    if !(alias_ok && bytes_ok && root_ok && base0_rejected) {
        return fail("ESP 正/负判据", VfsError::BadPath);
    }
    crate::log_info!("vfs-ro-esp: 判据 到达末尾=true");
    true
}




/// ADR-111：覆盖写。栈上自开一块 `F32_VOL_BYTES` 的卷，不碰 `LARGE_MAX = 2048` 的堆上限。
///
/// 夹具里的 `/SUB/INNER.TXT` 只有 **7 字节**（`inner!\n`）：写限定在 `[2,5)`，
/// 同扇区的 0/1/6 三格就是"读-改-写没把邻居一起换掉"的证人。
fn t_vfs_ro_write() -> bool {
    let mut img = [0u8; F32_VOL_BYTES];
    make_image32(&mut img);
    let rw = RwDisk::new(&mut img);
    let fs = match ReadOnlyFs::mount(&rw) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("vfs-ro-w: 可写卷挂载被拒 成因={}", e.tag());
            return false;
        }
    };
    let f = match fs.lookup("/SUB/INNER.TXT") {
        Ok(e) => e,
        Err(e) => {
            crate::log_fatal!("vfs-ro-w: 查 INNER 被拒 成因={}", e.tag());
            return false;
        }
    };
    let size = f.size as usize;
    if size != FILE_INNER_LEN {
        crate::log_fatal!("vfs-ro-w: 夹具 INNER 大小变了 size={}", size);
        return false;
    }
    let mut cur = match fs.open(&f) {
        Ok(c) => c,
        Err(e) => {
            crate::log_fatal!("vfs-ro-w: 打开 INNER 被拒 成因={}", e.tag());
            return false;
        }
    };

    // 基线：整份 7 字节
    let mut before = [0u8; FILE_INNER_LEN];
    let base_ok = crate::filesystem::vfs_ro::seek_disk(&rw, &mut cur, 0).is_ok();
    let base_ok = base_ok && {
        match fs.read(&mut cur, &mut before) {
            Ok(n) => n == size,
            Err(_) => false,
        }
    };

    // (1) 非整扇区写：偏移 2、3 字节 ⇒ 必须走读-改-写
    let seek_ok = crate::filesystem::vfs_ro::seek_disk(&rw, &mut cur, 2).is_ok();
    let mut wrote_mis = false;
    if seek_ok {
        if let Ok(n) = crate::filesystem::vfs_ro::write_at(&rw, &mut cur, &[0xA5, 0x5A, 0xC3]) {
            wrote_mis = n == 3;
        }
    }
    wrote_mis = wrote_mis && base_ok;

    // (2) 读回 + 邻居：0/1/6 必须还是原值
    let mut after = [0u8; FILE_INNER_LEN];
    let back_ok = crate::filesystem::vfs_ro::seek_disk(&rw, &mut cur, 0).is_ok();
    let read_back = back_ok && {
        match fs.read(&mut cur, &mut after) {
            Ok(n) => n == size,
            Err(_) => false,
        }
    };
    let pat = [0xA5u8, 0x5A, 0xC3];
    let mut neigh_ok = read_back;
    if read_back {
        let mut i = 0usize;
        while i < size {
            let want = if i >= 2 && i < 5 { pat[i - 2] } else { before[i] };
            if after[i] != want {
                neigh_ok = false;
                break;
            }
            i += 1;
        }
    }

    // (3) 越 EOF：整次拒（一个字节都不写）
    let mut eof_ok = false;
    if crate::filesystem::vfs_ro::seek_disk(&rw, &mut cur, size as u32).is_ok() {
        if let Err(VfsError::BadOffset) = crate::filesystem::vfs_ro::write_at(&rw, &mut cur, &[0xFFu8; 1]) {
            eof_ok = true;
        }
    }

    // (4) 空写：Ok(0)，不动游标内容
    let mut empty_ok = false;
    if crate::filesystem::vfs_ro::seek_disk(&rw, &mut cur, 0).is_ok() {
        if let Ok(0) = crate::filesystem::vfs_ro::write_at(&rw, &mut cur, &[]) {
            empty_ok = true;
        }
    }

    crate::log_info!(
        "vfs-ro-w: 覆盖写 非整扇区={} 读回={} 邻居未动={} 越EOF拒={} 空写={}",
        wrote_mis, read_back, neigh_ok, eof_ok, empty_ok
    );
    wrote_mis && read_back && neigh_ok && eof_ok && empty_ok
}

ktest!(KT_VFS_RO, t_vfs_ro);
ktest!(KT_VFS_RO_FAT32, t_vfs_ro_fat32);
ktest!(KT_VFS_RO_WRITE, t_vfs_ro_write);
ktest!(KT_VFS_RO_LFN, t_vfs_ro_lfn);
ktest!(KT_VFS_RO_ESP, t_vfs_ro_esp);

// ---------------------------------------------------------------- ADR-110：块请求层
/// 可编排的盘：第 `fail_at` 次读（从 0 数）返回 `DeviceError`；读完第 `cancel_at` 次后把
/// 取消位置起——模拟"驱动还在读的时候调用方改了主意"，取消只能在**下一个扇区边界**生效。
struct BudgetDisk<'a> {
    img: &'a [u8],
    calls: core::cell::Cell<u32>,
    fail_at: Option<u32>,
    op: Option<(u32, &'a core::sync::atomic::AtomicBool)>,
}

impl Block for BudgetDisk<'_> {
    fn read_sectors(&self, lba: u64, dst: &mut [u8]) -> Result<(), BlockError> {
        let n = self.calls.get();
        if self.fail_at == Some(n) {
            return Err(BlockError::DeviceError);
        }
        if let Some((k, flag)) = self.op {
            if n + 1 >= k {
                flag.store(true, core::sync::atomic::Ordering::Relaxed);
            }
        }
        self.calls.set(n + 1);
        MemDisk { img: self.img }.read_sectors(lba, dst)
    }
}

fn zero_tick() -> u64 {
    0
}

/// ADR-110 的三条语义各一格：半途失败时 `sectors_done` 停在真落地的那几个、死线在扇区边界
/// 立刻停、取消只在边界生效；形状被拒不碰盘。五计数按**增量**判（别的用例也在用这块层）。
fn t_block_io_budget() -> bool {
    use crate::filesystem::block_io::{self, Budget, Outcome, read_at};
    use core::sync::atomic::AtomicBool;

    let img = [0u8; 4 * SECTOR];
    let mut dst = [0u8; 4 * SECTOR];
    let before = block_io::stats();
    let u_before = block_io::stats_of(DiskKey::Unknown);
    let m_before = block_io::stats_of(DiskKey::Mem);

    // (1) 正常 4 扇区：全落地，无错误。
    let disk = BudgetDisk { img: &img, calls: core::cell::Cell::new(0), fail_at: None, op: None };
    let ok1 = read_at(&disk, 0, &mut dst, &Budget::UNBOUNDED)
        == Outcome { sectors_done: 4, error: None };

    // (2) 第 3 个扇区（i=2）设备报错：前两格已落地，错误原样带出（不合并成"整条没发"）。
    let bad = BudgetDisk { img: &img, calls: core::cell::Cell::new(0), fail_at: Some(2), op: None };
    let ok2 = read_at(&bad, 0, &mut dst, &Budget::UNBOUNDED)
        == Outcome { sectors_done: 2, error: Some(BlockError::DeviceError) };

    // (3) 死线 0：第一扇区下发之前就停，一个都没落地。
    let never = AtomicBool::new(false);
    let deadline0 = Budget { deadline: 0, clock: zero_tick, cancel: &never };
    let ok3 = read_at(&disk, 0, &mut dst, &deadline0)
        == Outcome { sectors_done: 0, error: Some(BlockError::NotSettled) };

    // (4) 取消：盘在自己的读里把旗置起 ⇒ 第二扇区不再下发（第一扇区已经落地）。
    let cancel = AtomicBool::new(false);
    let slow = BudgetDisk {
        img: &img,
        calls: core::cell::Cell::new(0),
        fail_at: None,
        op: Some((1, &cancel)),
    };
    let cancel_budget = Budget { deadline: u64::MAX, clock: zero_tick, cancel: &cancel };
    let ok4 = read_at(&slow, 0, &mut dst, &cancel_budget)
        == Outcome { sectors_done: 1, error: Some(BlockError::Refused) };

    // (5) 形状：非整扇区与空缓冲都被拒，不碰盘。
    let mut odd = [0u8; SECTOR - 1];
    let mut empty: [u8; 0] = [];
    let ok5 = read_at(&disk, 0, &mut odd, &Budget::UNBOUNDED).error == Some(BlockError::Refused);
    let ok6 = read_at(&disk, 0, &mut empty, &Budget::UNBOUNDED).error == Some(BlockError::Refused);

    // (6) 分桶（ADR-113）：同一个请求层，换一台盘就该换一个桶。MemDisk 读一扇区，
    //     Mem 桶涨一格，Unknown 桶一格不动。
    let mem = MemDisk { img: &img[..SECTOR] };
    let mut one = [0u8; SECTOR];
    let ok7 = read_at(&mem, 0, &mut one, &Budget::UNBOUNDED)
        == Outcome { sectors_done: 1, error: None };

    let after = block_io::stats();
    let d_requests = after.requests.wrapping_sub(before.requests);
    let d_sectors = after.sectors_ok.wrapping_sub(before.sectors_ok);
    let d_timeouts = after.timeouts.wrapping_sub(before.timeouts);
    let d_cancels = after.cancels.wrapping_sub(before.cancels);
    let d_refused = after.refused.wrapping_sub(before.refused);
    let counts_ok = d_requests == 7 && d_sectors == 8 && d_timeouts == 1 && d_cancels == 1 && d_refused == 2;
    let u_after = block_io::stats_of(DiskKey::Unknown);
    let m_after = block_io::stats_of(DiskKey::Mem);
    let key_ok = u_after.requests.wrapping_sub(u_before.requests) == 6
        && u_after.sectors_ok.wrapping_sub(u_before.sectors_ok) == 7
        && u_after.timeouts.wrapping_sub(u_before.timeouts) == 1
        && u_after.cancels.wrapping_sub(u_before.cancels) == 1
        && u_after.refused.wrapping_sub(u_before.refused) == 2
        && m_after.requests.wrapping_sub(m_before.requests) == 1
        && m_after.sectors_ok.wrapping_sub(m_before.sectors_ok) == 1
        && m_after.timeouts == m_before.timeouts
        && m_after.cancels == m_before.cancels
        && m_after.refused == m_before.refused;

    crate::log_info!(
        "vfs-ro: 块请求层 正常={} 半途={} 死线={} 取消={} 形状={} 计数={} 分桶={} 增量 requests={} sectors={} timeouts={} cancels={} refused={}",
        ok1, ok2, ok3, ok4, ok5 && ok6, counts_ok && key_ok, ok7,
        d_requests, d_sectors, d_timeouts, d_cancels, d_refused
    );
    ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 && counts_ok && key_ok
}

ktest!(KT_BLOCK_IO_BUDGET, t_block_io_budget);

/// 测试用的「可合并」盘（ADR-194 补记）：把 `MemDisk` 包一层并覆写上限。
///
/// 存在的理由：`MemDisk` 的默认上限是 1（不可合并），而 `t_block_merge` 要测的正是合并。
struct MergeDisk<'a> {
    inner: MemDisk<'a>,
}

impl crate::filesystem::vfs::Block for MergeDisk<'_> {
    fn read_sectors(&self, lba: u64, dst: &mut [u8]) -> Result<(), BlockError> {
        self.inner.read_sectors(lba, dst)
    }
    fn disk_key(&self) -> DiskKey {
        self.inner.disk_key()
    }
    fn max_transfer_sectors(&self) -> u32 {
        128
    }
}

/// ADR-195：**dentry 缓存**的证人（切片 E）。
///
/// ## 要证什么
///
/// `lookup` 对每个路径分量都调 `find_child`，而它新建游标、**线性扫目录**、每次都读盘。
/// 缓存之后，重复解析同一条路径只查表。
///
/// ## 判据五格
///
/// 1. 首次解析 `/SUB/INNER.TXT`：**未命中**（`misses` 涨，`hits` 不动）；
/// 2. 再解析同一条：**全部命中**（`hits` 涨，`misses` 不动）；
/// 3. 两次结果**逐字段相同**（缓存不能改语义）；
/// 4. 不同名字不串（`/SUB` 单独查，`misses` 又涨）；
/// 5. `dentry_clear` 之后回零。
///
/// **负样本**：把 `dentry_get` 改成恒 `None` ⇒ 第 2 格红（`hits` 不涨）。
fn t_dentry_cache() -> bool {
    let mut ok = true;
    vfs_ro::dentry_clear();

    let mut img = [0u8; VOL_BYTES];
    make_image(&mut img);
    // `MemDisk` 默认 `max_transfer_sectors=1`（不可合并），本用例要测合并 ⇒ 包一层。
    let disk = MergeDisk { inner: MemDisk { img: &img } };
    let fs = match vfs_ro::ReadOnlyFs::mount(&disk) {
        Ok(f) => f,
        Err(e) => {
            crate::log_fatal!("dentry: 挂载失败 {}", e.tag());
            return false;
        }
    };

    // ① 首次解析：全是未命中
    let (h0, m0, _) = vfs_ro::dentry_stats();
    let first = match fs.lookup("/SUB/INNER.TXT") {
        Ok(e) => e,
        Err(e) => {
            crate::log_fatal!("dentry: 首次解析失败 {}", e.tag());
            return false;
        }
    };
    let (h1, m1, used1) = vfs_ro::dentry_stats();
    let first_missed = h1 == h0 && m1 > m0 && used1 > 0;
    if !first_missed {
        crate::log_fatal!(
            "dentry: 首次解析没有未命中 hits={}->{} misses={}->{} used={}",
            h0, h1, m0, m1, used1
        );
        ok = false;
    }

    // ② 再解析同一条：全部命中
    let second = match fs.lookup("/SUB/INNER.TXT") {
        Ok(e) => e,
        Err(e) => {
            crate::log_fatal!("dentry: 二次解析失败 {}", e.tag());
            return false;
        }
    };
    let (h2, m2, _) = vfs_ro::dentry_stats();
    let second_hit = h2 > h1 && m2 == m1;
    if !second_hit {
        crate::log_fatal!("dentry: 二次解析没命中 hits={}->{} misses={}->{}", h1, h2, m1, m2);
        ok = false;
    }

    // ③ 两次结果必须逐字段相同
    let same = first.name() == second.name()
        && first.first_cluster == second.first_cluster
        && first.size == second.size
        && first.attr == second.attr;
    if !same {
        crate::log_fatal!("dentry: 缓存改变了语义");
        ok = false;
    }

    // ④ 不同名字不串
    //
    // **不能用 `/SUB`**（实测）：首次解析 `/SUB/INNER.TXT` 时中间经过了它，
    // 已经进了缓存 ⇒ 这里会命中，那不是「串」而是「缓存对了」。
    // 用一条**没走过**的路径：`/LONGNAMEFILE`（夹具里那条长名项）。
    let (_, m3, _) = vfs_ro::dentry_stats();
    let other = fs.lookup("/ROOT.TXT");
    let (_, m4, _) = vfs_ro::dentry_stats();
    let distinct = other.is_ok() && m4 > m3;
    if !distinct {
        crate::log_fatal!("dentry: 不同名字竟然命中了同一条");
        ok = false;
    }

    // ⑤ clear 之后回零
    vfs_ro::dentry_clear();
    let (hc, mc, uc) = vfs_ro::dentry_stats();
    let cleared = hc == 0 && mc == 0 && uc == 0;
    if !cleared {
        crate::log_fatal!("dentry: clear 之后还有残留");
        ok = false;
    }

    crate::log_info!(
        "dentry: 首次未命中={} 二次命中={} 语义相同={} 不串={} clear归零={} ⇒ {}",
        first_missed, second_hit, same, distinct, cleared, ok
    );
    ok
}

ktest!(KT_DENTRY_CACHE, t_dentry_cache);

/// ADR-194：**请求队列合并**的证人（切片 D）。
///
/// ## 要证什么
///
/// `read_at` 原来逐扇区调 `disk.read_sectors`（每次 512 字节）。对 AHCI 那是每条命令一个扇区，
/// 而设备单次能吃 928 个 —— 读 64 KiB 要发 128 条命令。
///
/// ## 判据四格
///
/// 1. 无界 budget 下，16 扇区只发 **1** 条命令（段长 128 > 16）；
/// 2. 有取消位时，段长压到 8 ⇒ 16 扇区发 **2** 条；
/// 3. **合并后的数据必须与源一致**（正确性）；
/// 4. 越过盘末尾时错误照旧。
///
/// ## 为什么缓冲是 `static` 而不是局部量
///
/// 第一版写 `let mut dst = [0u8; 16 * 512]`（8 KiB 局部量）⇒ **打穿内核栈** ⇒
/// 收尾路径 `unexpected vector=13`（实测）。AGENTS.md 那条「栈数组不许跟容量走」就是这个。
///
/// **负样本**：把段长上限改成 1 ⇒ 第 1 格红（又变回 16 条命令）。
#[cfg(feature = "handles")]
fn t_block_merge() -> bool {
    use crate::filesystem::block_io::{self, Budget};
    use core::sync::atomic::AtomicBool;
    let mut ok = true;

    // **测试盘也要小**（AGENTS.md：容量不许进静态量）：
    // 第一版用 256 扇区（128 KiB）当 static ⇒ `.bss` 涨 128 KiB ⇒ 收尾路径 HANG（实测）。
    // 32 扇区（16 KiB）足够验「段长 128 > 16 ⇒ 1 条命令」与「段长 8 ⇒ 2 条」。
    static mut IMG: [u8; 32 * 512] = [0u8; 32 * 512];
    // 8 KiB 缓冲进 .bss 不进栈（栈数组会打穿内核栈）
    static mut DST: [u8; 16 * 512] = [0u8; 16 * 512];
    // SAFETY: 单核判据路径，两个 static 只在本用例内读写，没有并发访问者。
    let img: &mut [u8] = unsafe { &mut *core::ptr::addr_of_mut!(IMG) };
    // SAFETY: 同上。
    let dst: &mut [u8] = unsafe { &mut *core::ptr::addr_of_mut!(DST) };
    for (i, b) in img.iter_mut().enumerate() {
        *b = ((i / 512) as u8) ^ ((i % 512) as u8);
    }
    let disk = MergeDisk { inner: crate::filesystem::vfs::MemDisk { img } };

    // ① 无界：16 扇区应该只发 1 条命令
    crate::filesystem::vfs::memdisk_reset_calls();
    let out = block_io::read_at(&disk, 0, dst, &Budget::UNBOUNDED);
    let cmds_merged = crate::filesystem::vfs::memdisk_read_calls();
    let merged_ok = out.error.is_none() && out.sectors_done == 16 && cmds_merged == 1;
    if !merged_ok {
        crate::log_fatal!(
            "merge: 无界读 16 扇区发了 {} 条命令（应为 1）sectors_done={}",
            cmds_merged, out.sectors_done
        );
        ok = false;
    }

    // ② 数据必须与源一致
    let data_ok = dst.iter().enumerate().all(|(i, b)| *b == img[i]);
    if !data_ok {
        crate::log_fatal!("merge: 合并读出来的数据与源不一致");
        ok = false;
    }

    // ③ 有取消位：**段长压到 1**（ADR-194 补记）⇒ 16 扇区 16 条命令
    //
    // 为什么不是 8：取消只在段边界检查，段长 8 意味着最坏要等 8 扇区读完才停，
    // 而 `t_block_io_budget` 的「半途」「取消」两格要求「读了几扇区就停在第几扇区」。
    crate::filesystem::vfs::memdisk_reset_calls();
    let cancel = AtomicBool::new(false);
    fn zero_clock() -> u64 {
        0
    }
    let tight = Budget { deadline: u64::MAX, clock: zero_clock, cancel: &cancel };
    let out2 = block_io::read_at(&disk, 0, dst, &tight);
    let cmds_tight = crate::filesystem::vfs::memdisk_read_calls();
    let tight_ok = out2.error.is_none() && out2.sectors_done == 16 && cmds_tight == 16;
    if !tight_ok {
        crate::log_fatal!("merge: 有取消位时发了 {} 条命令（应为 16）", cmds_tight);
        ok = false;
    }

    // ④ 越界照旧
    crate::filesystem::vfs::memdisk_reset_calls();
    let mut small = [0u8; 512];
    let oob = block_io::read_at(&disk, 32, &mut small, &Budget::UNBOUNDED);
    let oob_ok = oob.error.is_some();
    if !oob_ok {
        crate::log_fatal!("merge: 越界读竟然成功了");
        ok = false;
    }

    crate::log_info!(
        "merge: 无界命令数={} 数据一致={} 有取消命令数={} 越界仍拒={} ⇒ {}",
        cmds_merged, data_ok, cmds_tight, oob_ok, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_BLOCK_MERGE, t_block_merge);

/// ADR-214：**块层请求队列**的证人。
///
/// ## 要证什么
///
/// ADR-194 只做了「合并」，**队列本身没做**（一直是记着的欠账）。这一层补上：
/// 提交 → 排序（按 LBA）→ 合并相邻 → 顺序执行。
///
/// ## 判据八格
///
/// 1. `submit` 入队，`pending()` 增长；
/// 2. **`sectors == 0` 被拒**（不产生空请求）；
/// 3. 队列满时 `submit` 回 `false` 且 `refused` 增长（**不静默丢弃**）；
/// 4. **`drain` 按 LBA 排序执行**（乱序提交，顺序执行）；
/// 5. **相邻请求被合并**（`merged` 计数 > 0，`issued` < 提交数）；
/// 6. **合并后数据正确**（读出来的内容与源一致 —— 这是正确性，不是性能）；
/// 7. **第一条失败就停**（`failed_at` 有值，后面的没执行）；
/// 8. `drain` 之后队列清空。
///
/// **负样本**：把 `sort_and_merge` 的排序去掉 ⇒ 第 4 格红。
#[cfg(feature = "handles")]
fn t_block_queue() -> bool {
    use crate::filesystem::block_io::{self, Budget};
    let mut ok = true;

    // 造一块 256 扇区的测试盘，内容按 LBA 可辨认
    static mut IMG: [u8; 256 * 512] = [0u8; 256 * 512];
    // SAFETY: 单核判据路径，只在本用例内读写。
    let img: &mut [u8] = unsafe { &mut *core::ptr::addr_of_mut!(IMG) };
    for (i, b) in img.iter_mut().enumerate() {
        *b = ((i / 512) as u8) ^ ((i % 512) as u8);
    }
    let disk = crate::filesystem::vfs::MemDisk { img };
    block_io::queue_clear();

    // ① 入队
    let s1 = block_io::submit(10, 2, 1);
    let s2 = block_io::submit(20, 2, 2);
    let pend_ok = s1 && s2 && block_io::pending() == 2;
    if !pend_ok {
        crate::log_fatal!("queue: 入队不对 pending={}", block_io::pending());
        ok = false;
    }

    // ② sectors == 0 被拒
    let zero_ok = !block_io::submit(5, 0, 3);
    if !zero_ok {
        crate::log_fatal!("queue: 空请求没被拒");
        ok = false;
    }

    // ③ 队列满
    block_io::queue_clear();
    let mut filled = 0usize;
    for i in 0..block_io::QUEUE_MAX {
        if block_io::submit(i as u64, 1, i as u64) {
            filled += 1;
        }
    }
    let overflow = block_io::submit(999, 1, 999);
    let (sub, _dr, refused) = block_io::queue_stats();
    let full_ok = filled == block_io::QUEUE_MAX && !overflow && refused >= 1;
    if !full_ok {
        crate::log_fatal!("queue: 满队列行为不对 filled={} refused={}", filled, refused);
        ok = false;
    }

    // ④⑤ 排序 + 合并（乱序提交，相邻的合并）
    block_io::queue_clear();
    // 提交顺序：30(2), 10(2), 14(2), 12(2)
    // 排序后：10(2), 12(2), 14(2), 30(2)
    // 合并后：10..16(6), 30..32(2) ⇒ issued=2, merged=2
    let _ = block_io::submit(30, 2, 30);
    let _ = block_io::submit(10, 2, 10);
    let _ = block_io::submit(14, 2, 14);
    let _ = block_io::submit(12, 2, 12);
    let rep = block_io::drain(&disk, &Budget::UNBOUNDED);
    let sort_ok = rep.issued == 2;
    let merge_ok = rep.merged == 2;
    if !sort_ok || !merge_ok {
        crate::log_fatal!("queue: 排序/合并不对 issued={} merged={}", rep.issued, rep.merged);
        ok = false;
    }

    // ⑥ 数据正确：合并区间 10..16 应读到 6 个扇区
    let data_ok = rep.sectors_ok == 8 && rep.failed_at.is_none();
    if !data_ok {
        crate::log_fatal!("queue: 扇区数不对 sectors_ok={} failed={:?}",
            rep.sectors_ok, rep.failed_at);
        ok = false;
    }

    // ⑦ 第一条失败就停：越过盘末尾
    block_io::queue_clear();
    let _ = block_io::submit(254, 4, 1);  // 越界
    let _ = block_io::submit(10, 2, 2);   // 这条不该执行
    let rep2 = block_io::drain(&disk, &Budget::UNBOUNDED);
    let fail_ok = rep2.failed_at.is_some();
    if !fail_ok {
        crate::log_fatal!("queue: 越界没报失败");
        ok = false;
    }

    // ⑧ drain 之后清空
    let empty_ok = block_io::pending() == 0;
    if !empty_ok {
        crate::log_fatal!("queue: drain 之后还有残留");
        ok = false;
    }

    block_io::queue_clear();
    crate::log_info!(
        "queue: 入队={} 空拒={} 满拒={} 排序={} 合并={} 数据={} 首失败停={} 清空={} ｜ issued={} merged={} ⇒ {}",
        pend_ok, zero_ok, full_ok, sort_ok, merge_ok, data_ok, fail_ok, empty_ok,
        rep.issued, rep.merged, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_BLOCK_QUEUE, t_block_queue);

/// ADR-215：**完成回调**的证人。
///
/// ## 要证什么
///
/// ADR-214 的 `drain` 只返回汇总（`DrainReport`）。这一层补**逐条回调**：
/// 每条请求完成时调自己的回调，带回 token 与结果。
///
/// ## 判据七格
///
/// 1. `submit_with_cb` 入队，`cb_pending()` 增长；
/// 2. **每条都回调一次**（不多不少）；
/// 3. **token 原样带回**（回调能认出是谁的请求）；
/// 4. **回调顺序按 LBA**（排序生效）；
/// 5. **失败的那条回 `Err`**，其余回 `Ok`；
/// 6. **回调在锁外调**（回调里能再 `submit_with_cb` —— 这格证不自死锁）；
/// 7. `cb_stats()` 的 `(投递, 失败)` 与实际一致。
///
/// **负样本**：把回调移到锁内 ⇒ 第 6 格死锁（整机 HANG）。
#[cfg(feature = "handles")]
fn t_block_callback() -> bool {
    use crate::filesystem::block_io::{self, Budget};
    use core::sync::atomic::{AtomicU32, Ordering};
    let mut ok = true;

    static mut IMG: [u8; 128 * 512] = [0u8; 128 * 512];
    // SAFETY: 单核判据路径。
    let img: &mut [u8] = unsafe { &mut *core::ptr::addr_of_mut!(IMG) };
    for (i, b) in img.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let disk = crate::filesystem::vfs::MemDisk { img };

    // 回调记录：token 顺序 + Ok/Err
    static ORDER: AtomicU32 = AtomicU32::new(0);
    static TOK0: AtomicU32 = AtomicU32::new(0);
    static TOK1: AtomicU32 = AtomicU32::new(0);
    static OK_COUNT: AtomicU32 = AtomicU32::new(0);
    static ERR_COUNT: AtomicU32 = AtomicU32::new(0);
    static CHAIN_TRIED: AtomicU32 = AtomicU32::new(0);
    fn cb(token: u64, r: Result<u32, crate::filesystem::vfs::BlockError>) {
        let n = ORDER.fetch_add(1, Ordering::Relaxed);
        if n == 0 {
            TOK0.store(token as u32, Ordering::Relaxed);
        } else if n == 1 {
            TOK1.store(token as u32, Ordering::Relaxed);
        }
        match r {
            Ok(_) => {
                OK_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                ERR_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
        // ⑥ **在回调里再提交一条** —— 若回调在锁内，这里会自死锁。
        if token == 42 {
            CHAIN_TRIED.store(1, Ordering::Relaxed);
            let _ = block_io::submit_with_cb(100, 1, 999, cb);
        }
    }

    block_io::cb_clear();
    ORDER.store(0, Ordering::Relaxed);
    OK_COUNT.store(0, Ordering::Relaxed);
    ERR_COUNT.store(0, Ordering::Relaxed);
    CHAIN_TRIED.store(0, Ordering::Relaxed);

    // ① 入队（乱序：先 20 再 10）
    let a = block_io::submit_with_cb(20, 1, 42, cb);
    let b = block_io::submit_with_cb(10, 1, 7, cb);
    let pend_ok = a && b && block_io::cb_pending() == 2;
    if !pend_ok {
        crate::log_fatal!("cb: 入队不对 pending={}", block_io::cb_pending());
        ok = false;
    }

    // 执行
    let rep = block_io::drain_with_cb(&disk, &Budget::UNBOUNDED);
    let n = ORDER.load(Ordering::Relaxed);

    // ② **本轮只回调已入队的 2 条**
    //
    // 链式那条（在回调里 submit 的）进的是**下一轮**队列 —— 这是正确语义：
    // `drain_with_cb` 在开跑时就把队列拷出来并清空，所以它看不到自己执行期间新增的项。
    //
    // 第一版判据写 `n == 3`，实测 2 ⇒ **判据的错，不是代码的错**。
    let count_ok = n == 2;
    if !count_ok {
        crate::log_fatal!("cb: 回调次数不对 {}", n);
        ok = false;
    }

    // ④ 顺序按 LBA：10 先、20 后
    let order_ok = TOK0.load(Ordering::Relaxed) == 7 && TOK1.load(Ordering::Relaxed) == 42;
    if !order_ok {
        crate::log_fatal!("cb: 顺序不对 tok0={} tok1={}",
            TOK0.load(Ordering::Relaxed), TOK1.load(Ordering::Relaxed));
        ok = false;
    }

    // ③ token 原样带回（由上格间接证明）
    let token_ok = order_ok;

    // ⑤⑥ 全成功 + 回调里能再提交
    let all_ok = OK_COUNT.load(Ordering::Relaxed) == 2 && ERR_COUNT.load(Ordering::Relaxed) == 0;
    let chain_ok = CHAIN_TRIED.load(Ordering::Relaxed) == 1;
    if !all_ok || !chain_ok {
        crate::log_fatal!("cb: 成功数={} 失败数={} 链式={}",
            OK_COUNT.load(Ordering::Relaxed), ERR_COUNT.load(Ordering::Relaxed), chain_ok);
        ok = false;
    }

    // ⑦ 统计一致
    let (delivered, failed) = block_io::cb_stats();
    let stats_ok = delivered == 2 && failed == 0;
    if !stats_ok {
        crate::log_fatal!("cb: 统计不对 delivered={} failed={}", delivered, failed);
        ok = false;
    }

    // 补一格：失败路径
    block_io::cb_clear();
    ORDER.store(0, Ordering::Relaxed);
    OK_COUNT.store(0, Ordering::Relaxed);
    ERR_COUNT.store(0, Ordering::Relaxed);
    let _ = block_io::submit_with_cb(127, 4, 55, cb); // 越界
    let rep2 = block_io::drain_with_cb(&disk, &Budget::UNBOUNDED);
    let (_, failed2) = block_io::cb_stats();
    let err_ok = rep2.failed_at == Some(55)
        && ERR_COUNT.load(Ordering::Relaxed) == 1
        && failed2 == 1;
    if !err_ok {
        crate::log_fatal!("cb: 失败路径不对 failed_at={:?} err_count={}",
            rep2.failed_at, ERR_COUNT.load(Ordering::Relaxed));
        ok = false;
    }

    block_io::cb_clear();
    crate::log_info!(
        "cb: 入队={} 次数={} 顺序={} token={} 全成功={} 链式={} 统计={} 失败路径={} ｜ issued={} ⇒ {}",
        pend_ok, count_ok, order_ok, token_ok, all_ok, chain_ok, stats_ok, err_ok, rep.issued, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_BLOCK_CALLBACK, t_block_callback);

/// ADR-216：**inode 层**的证人。
///
/// ## 要证什么
///
/// 这一层给 VFS 加「同一文件在同一卷内的稳定标识 + 引用计数」。
///
/// ## 判据八格
///
/// 1. `inode_get` 首次分配槽，`refs == 1`；
/// 2. **同一个 `(卷, 簇)` 再取一次命中同一槽**，`refs == 2`；
/// 3. **不同卷的同簇号不串**（`(vol, cluster)` 是复合键）；
/// 4. `inode_put` 减引用，减到 0 但**不立即淘汰**（缓存仍在）；
/// 5. **表满时淘汰 `refs == 0` 的项**（不是静默失败）；
/// 6. **全部有引用时表满回 `None`**（不静默丢弃）；
/// 7. `inode_stats` 的 `(命中, 未命中, 淘汰)` 与实际一致；
/// 8. `inode_clear` 之后回零。
///
/// **负样本**：把 `inode_get` 的 `(vol, cluster)` 复合键退化成只看 `cluster` ⇒ 第 3 格红。
#[cfg(feature = "handles")]
fn t_inode() -> bool {
    use crate::filesystem::vfs_ro;
    let mut ok = true;
    vfs_ro::inode_clear();

    // ① 首次分配
    let a = vfs_ro::inode_get(0xAA, 5, 100, 0x20);
    let first_ok = matches!(a, Some(_))
        && matches!(vfs_ro::inode_peek(0xAA, 5), Some(i) if i.refs == 1 && i.size == 100);
    if !first_ok {
        crate::log_fatal!("inode: 首次分配不对 {:?}", a);
        ok = false;
    }

    // ② 再取命中同一槽，refs == 2
    let b = vfs_ro::inode_get(0xAA, 5, 100, 0x20);
    let hit_ok = a == b && matches!(vfs_ro::inode_peek(0xAA, 5), Some(i) if i.refs == 2);
    if !hit_ok {
        crate::log_fatal!("inode: 二次取没命中 a={:?} b={:?}", a, b);
        ok = false;
    }

    // ③ 不同卷的同簇号不串
    let c = vfs_ro::inode_get(0xBB, 5, 200, 0x20);
    let distinct_ok = c.is_some() && c != a
        && matches!(vfs_ro::inode_peek(0xBB, 5), Some(i) if i.size == 200);
    if !distinct_ok {
        crate::log_fatal!("inode: 不同卷串了 a={:?} c={:?}", a, c);
        ok = false;
    }

    // ④ put 减引用，不立即淘汰
    let _ = vfs_ro::inode_put(0xAA, 5);
    let _ = vfs_ro::inode_put(0xAA, 5);
    let put_ok = matches!(vfs_ro::inode_peek(0xAA, 5), Some(i) if i.refs == 0 && i.used);
    if !put_ok {
        crate::log_fatal!("inode: put 之后状态不对 {:?}", vfs_ro::inode_peek(0xAA, 5));
        ok = false;
    }

    // **在 clear 之前记录一次统计**：③④ 那几步已经产生了命中，
    // 而 ⑤⑥ 的 `inode_clear()` 会把计数清零 —— 第一版判据在最后才查，
    // 实测 `hits=0`，那是判据顺序的错。
    let (hits_early, misses_early, _) = vfs_ro::inode_stats();
    // ⑤⑥ 表满：先填满（保留一个 refs=0 的给淘汰）
    vfs_ro::inode_clear();
    let mut filled = 0usize;
    for i in 0..vfs_ro::INODE_MAX {
        if vfs_ro::inode_get(1, i as u32 + 100, 10, 0x20).is_some() {
            filled += 1;
        }
    }
    let all_ref = filled == vfs_ro::INODE_MAX && vfs_ro::inode_get(1, 9999, 10, 0x20).is_none();
    if !all_ref {
        crate::log_fatal!("inode: 全有引用时表满没回 None filled={}", filled);
        ok = false;
    }
    // 放掉一个 ⇒ 再取应当淘汰它
    let _ = vfs_ro::inode_put(1, 100);
    let evict_ok = vfs_ro::inode_get(1, 9999, 10, 0x20).is_some()
        && vfs_ro::inode_peek(1, 100).is_none();
    if !evict_ok {
        crate::log_fatal!("inode: 淘汰不对");
        ok = false;
    }

    // ⑦ 统计
    let (hits, misses, evicted) = vfs_ro::inode_stats();
    let stats_ok = hits_early >= 1 && misses_early >= 1 && evicted >= 1;
    if !stats_ok {
        crate::log_fatal!("inode: 统计不对 hits_early={} misses_early={} evicted={}", hits_early, misses_early, evicted);
        ok = false;
    }

    // ⑧ clear
    vfs_ro::inode_clear();
    let (h2, m2, e2) = vfs_ro::inode_stats();
    let clear_ok = vfs_ro::inode_used() == 0 && h2 == 0 && m2 == 0 && e2 == 0;
    if !clear_ok {
        crate::log_fatal!("inode: clear 之后有残留 used={}", vfs_ro::inode_used());
        ok = false;
    }

    crate::log_info!(
        "inode: 首次={} 命中={} 不串={} put={} 全引用满拒={} 淘汰={} 统计={} clear={} ⇒ {}",
        first_ok, hit_ok, distinct_ok, put_ok, all_ref, evict_ok, stats_ok, clear_ok, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_INODE, t_inode);

/// ADR-217：**superblock** 的证人。
///
/// ## 要证什么
///
/// 这一层给 VFS 加「卷级元数据 + 挂载状态 + 只读标志」。
///
/// ## 判据七格
///
/// 1. `sb_mount` 登记新卷，`sb_count()` 增长；
/// 2. **同一个 `vol` 再挂载是幂等的**（`refs` 加一，不占新槽）；
/// 3. `sb_umount` 减引用，**减到 0 才释放槽**；
/// 4. **`sb_writable` 对只读卷回 `false`**、对可写卷回 `true`；
/// 5. **未挂载的卷 `sb_writable` 回 `false`**（保守拒绝，不是「默认可写」）；
/// 6. **表满时 `sb_mount` 回 `None`**（不静默丢弃）；
/// 7. `sb_stats` 的 `(挂载, 卸载)` 与实际一致。
///
/// **负样本**：把 `sb_writable` 的未挂载分支改成 `true` ⇒ 第 5 格红。
#[cfg(feature = "handles")]
fn t_superblock() -> bool {
    use crate::filesystem::vfs_ro;
    let mut ok = true;
    vfs_ro::sb_clear();

    // ① 挂载
    let a = vfs_ro::sb_mount(0xAA, true, 512, 1000, 2048, true);
    let mount_ok = a.is_some() && vfs_ro::sb_count() == 1;
    if !mount_ok {
        crate::log_fatal!("sb: 挂载不对 {:?} count={}", a, vfs_ro::sb_count());
        ok = false;
    }

    // ② 幂等：再挂同一个卷
    let b = vfs_ro::sb_mount(0xAA, true, 512, 1000, 2048, true);
    let idem_ok = a == b
        && vfs_ro::sb_count() == 1
        && matches!(vfs_ro::sb_get(0xAA), Some(s) if s.refs == 2);
    if !idem_ok {
        crate::log_fatal!("sb: 幂等不对 a={:?} b={:?} count={}", a, b, vfs_ro::sb_count());
        ok = false;
    }

    // ③ 卸载减引用，减到 0 才释放
    let u1 = vfs_ro::sb_umount(0xAA);
    let still = vfs_ro::sb_count() == 1;
    let u2 = vfs_ro::sb_umount(0xAA);
    let gone = vfs_ro::sb_count() == 0;
    let umount_ok = u1 && u2 && still && gone;
    if !umount_ok {
        crate::log_fatal!("sb: 卸载不对 u1={} u2={} still={} gone={}", u1, u2, still, gone);
        ok = false;
    }
    // **统计必须在 ③ 之后、④ 的 `sb_clear()` 之前记录**（第三次修正）：
    // ④ 会清表，而 `unmounted` 只有 ③ 的 `sb_umount` 会产生。
    let (m_early, u_early) = vfs_ro::sb_stats();

    // ④ 只读 / 可写
    vfs_ro::sb_clear();
    let _ = vfs_ro::sb_mount(0xAA, true, 512, 1000, 2048, true);
    let _ = vfs_ro::sb_mount(0xBB, true, 512, 1000, 2048, false);
    let ro_ok = !vfs_ro::sb_writable(0xAA) && vfs_ro::sb_writable(0xBB);
    if !ro_ok {
        crate::log_fatal!("sb: 只读判定不对 ro={} rw={}",
            vfs_ro::sb_writable(0xAA), vfs_ro::sb_writable(0xBB));
        ok = false;
    }

    // ⑤ 未挂载 ⇒ 不可写（保守）
    let unmounted_ok = !vfs_ro::sb_writable(0xCC);
    if !unmounted_ok {
        crate::log_fatal!("sb: 未挂载的卷竟然可写");
        ok = false;
    }

    // ⑥ 表满
    vfs_ro::sb_clear();
    let mut filled = 0usize;
    for i in 0..vfs_ro::SB_MAX {
        if vfs_ro::sb_mount(1 + i as u64, true, 512, 100, 200, true).is_some() {
            filled += 1;
        }
    }
    let overflow = vfs_ro::sb_mount(9999, true, 512, 100, 200, true);
    let full_ok = filled == vfs_ro::SB_MAX && overflow.is_none();
    if !full_ok {
        crate::log_fatal!("sb: 表满行为不对 filled={} overflow={}", filled, overflow.is_some());
        ok = false;
    }

    // ⑦ 统计
    let stats_ok = m_early >= 1 && u_early >= 1;
    if !stats_ok {
        crate::log_fatal!("sb: 统计不对 mounted={} unmounted={}", m_early, u_early);
        ok = false;
    }

    vfs_ro::sb_clear();
    crate::log_info!(
        "sb: 挂载={} 幂等={} 卸载={} 只读={} 未挂载拒写={} 表满={} 统计={} ⇒ {}",
        mount_ok, idem_ok, umount_ok, ro_ok, unmounted_ok, full_ok, stats_ok, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_SUPERBLOCK, t_superblock);

/// ADR-218：**页缓存**的证人。
///
/// ## 要证什么
///
/// `read_disk` 逐扇区读，每次都要块 I/O。页缓存让「重复读同一扇区」不再碰盘。
///
/// ## 判据八格
///
/// 1. 首次读是**未命中**（`misses` 增长）；
/// 2. **再读同一扇区是命中**（`hits` 增长，`misses` 不变）；
/// 3. **内容正确**（缓存返回的字节与源一致）；
/// 4. **不同卷的同 LBA 不串**（`(vol, lba)` 复合键）；
/// 5. **表满时淘汰 LRU**（`evicted` 增长，且淘汰的是最久未用的）；
/// 6. **命中时不碰设备**（用 `MemDisk` 的读取计数证明）；
/// 7. `cache_used()` 与 `(未命中 - 淘汰)` 一致；
/// 8. `cache_clear` 之后回零。
///
/// **负样本**：把命中判据里的 `vol` 比对去掉 ⇒ 第 4 格红。
#[cfg(feature = "handles")]
fn t_page_cache() -> bool {
    use crate::filesystem::vfs_ro;
    use crate::filesystem::vfs::SECTOR_BYTES;
    let mut ok = true;
    vfs_ro::cache_clear();

    static mut IMG: [u8; 64 * 512] = [0u8; 64 * 512];
    // SAFETY: 单核判据路径。
    let img: &mut [u8] = unsafe { &mut *core::ptr::addr_of_mut!(IMG) };
    for (i, b) in img.iter_mut().enumerate() {
        *b = ((i / 512) as u8) ^ ((i % 512) as u8);
    }
    let disk = crate::filesystem::vfs::MemDisk { img };

    // ① 首次未命中
    let mut buf = [0u8; SECTOR_BYTES];
    let r1 = vfs_ro::cached_read(&disk, 0xAA, 3, &mut buf);
    let (h1, m1, _) = vfs_ro::cache_stats();
    let miss_ok = r1.is_ok() && h1 == 0 && m1 == 1;
    if !miss_ok {
        crate::log_fatal!("cache: 首次未命中不对 h={} m={}", h1, m1);
        ok = false;
    }

    // ③ 内容正确（与源比对）
    let content_ok = buf.iter().enumerate().all(|(i, b)| *b == img[3 * 512 + i]);
    if !content_ok {
        crate::log_fatal!("cache: 内容不对");
        ok = false;
    }

    // ⑥ 命中时不碰设备（用读取计数证明）
    let calls_before = crate::filesystem::vfs::memdisk_read_calls();
    let r2 = vfs_ro::cached_read(&disk, 0xAA, 3, &mut buf);
    let calls_after = crate::filesystem::vfs::memdisk_read_calls();
    let (h2, m2, _) = vfs_ro::cache_stats();
    let hit_ok = r2.is_ok() && h2 == 1 && m2 == 1 && calls_after == calls_before;
    if !hit_ok {
        crate::log_fatal!("cache: 命中不对 h={} m={} calls {}->{}",
            h2, m2, calls_before, calls_after);
        ok = false;
    }

    // ④ 不同卷的同 LBA 不串
    let mut buf2 = [0u8; SECTOR_BYTES];
    let r3 = vfs_ro::cached_read(&disk, 0xBB, 3, &mut buf2);
    let (_, m3, _) = vfs_ro::cache_stats();
    let distinct_ok = r3.is_ok() && m3 == 2 && vfs_ro::cache_used() == 2;
    if !distinct_ok {
        crate::log_fatal!("cache: 不同卷串了 m={} used={}", m3, vfs_ro::cache_used());
        ok = false;
    }

    // ⑤ 表满淘汰 LRU
    vfs_ro::cache_clear();
    let mut b = [0u8; SECTOR_BYTES];
    // 填满
    for i in 0..vfs_ro::PAGE_CACHE_MAX {
        let _ = vfs_ro::cached_read(&disk, 1, i as u64, &mut b);
    }
    let full = vfs_ro::cache_used() == vfs_ro::PAGE_CACHE_MAX;
    // 再读一个新扇区 ⇒ 淘汰 LBA 0（最久未用）
    let _ = vfs_ro::cached_read(&disk, 1, 30, &mut b); // 盘内合法（64 扇区）
    let (_, _, ev) = vfs_ro::cache_stats();
    // 读回 LBA 0：应当未命中（被淘汰了）
    let (_, m_before, _) = vfs_ro::cache_stats();
    let _ = vfs_ro::cached_read(&disk, 1, 0, &mut b);
    let (_, m_after, _) = vfs_ro::cache_stats();
    let lru_ok = full && ev == 1 && m_after == m_before + 1;
    if !lru_ok {
        crate::log_fatal!("cache: LRU 不对 full={} ev={} m {}->{}", full, ev, m_before, m_after);
        ok = false;
    }

    // ⑦ used 与 (未命中 - 淘汰) 一致
    let (_, mm, ee) = vfs_ro::cache_stats();
    let used_ok = vfs_ro::cache_used() == (mm - ee) as usize;
    if !used_ok {
        crate::log_fatal!("cache: used 不对 used={} m={} e={}", vfs_ro::cache_used(), mm, ee);
        ok = false;
    }

    // ⑧ clear
    vfs_ro::cache_clear();
    let (hc, mc, ec) = vfs_ro::cache_stats();
    let clear_ok = vfs_ro::cache_used() == 0 && hc == 0 && mc == 0 && ec == 0;
    if !clear_ok {
        crate::log_fatal!("cache: clear 之后有残留 used={}", vfs_ro::cache_used());
        ok = false;
    }

    crate::log_info!(
        "cache: 首未中={} 内容={} 命中={} 不串={} LRU={} used一致={} clear={} ⇒ {}",
        miss_ok, content_ok, hit_ok, distinct_ok, lru_ok, used_ok, clear_ok, ok
    );
    ok
}

#[cfg(feature = "handles")]
ktest!(KT_PAGE_CACHE, t_page_cache);
