//! GPT 只读解析的取证用例（ADR-078，W4 S1）。只在 `gpt-probe` 档注册。
//!
//! 三部分，各证一件不同的事：
//! 1. **真盘**：引导盘上那张 GPT 真读得出来，ESP 真找得到，状态区与签名包那两个裸 LBA 区
//!    真被报成"未分派"而不是被当分区收进名单。几何读数打出来给宿主机第二台仪器对账
//!    （对账行与六条改盘负样本是下一刀，本轮**没有**宿主机对账，不写成已对账）。
//! 2. **CRC32 已知答案向量**：两个常数是外部的（空串 = 0、`"123456789"` = `0xCBF43926`），
//!    不是自己算给自己看。合成盘的数组 CRC 也由 CPython `binascii.crc32` 先算出常数嵌进来，
//!    所以"内核 crc32 与宿主机错得一样"这件事会被这一格抓住。
//! 3. **合成盘（4 个扇区 = 2 KiB，栈上）**：每道闸各喂一次它该拒的输入，**红必须点名**。
//!    这是 ADR-038 决策 3 那条"合成卷只做便宜的分支覆盖"的同族手法：真盘上没法把 CRC 改坏
//!    （只读），而改盘注入要等下一刀，先用合成盘证明这些闸不是装饰。

use crate::filesystem::gpt::{self, GptError};
use crate::filesystem::vfs::{AhciDisk, MemDisk, SECTOR_BYTES};
use crate::{ahci, ktest, sign, state_store};

/// 合成盘那 512 字节条目数组的 CRC，由宿主机 CPython `binascii.crc32` 独立算出：
/// 第 0 格 = ESP type GUID + unique GUID 全 `0x5A` + first/last = 2，其余三格全零。
/// **不是内核自己算的**——否则两台仪器退化成一台（ADR-038 决策 2）。
const HOST_ARRAY_CRC: u32 = 0xE09B_7D45;

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// 写一个 92 字节的 GPT 头并把头 CRC 封好（计算时自身字段为 0）。
fn seal_header(img: &mut [u8], off: usize, my: u64, alt: u64, array_crc: u32) {
    img[off..off + 8].copy_from_slice(b"EFI PART");
    put32(img, off + 8, gpt::GPT_REVISION);
    put32(img, off + 12, gpt::MIN_HEADER_BYTES);
    put32(img, off + 16, 0);
    put64(img, off + 24, my);
    put64(img, off + 32, alt);
    put64(img, off + 40, 2);
    put64(img, off + 48, 2);
    img[off + 56..off + 72].fill(0x42);
    put64(img, off + 72, 2);
    put32(img, off + 80, 4);
    put32(img, off + 84, gpt::MIN_ENTRY_BYTES);
    put32(img, off + 88, array_crc);
    let crc = gpt::crc32(&img[off..off + 92]);
    put32(img, off + 16, crc);
}

/// 改了头字段之后重新封 CRC。**只有想证后面那道闸时才用它**：
/// 不重封的话头 CRC 会先 fire，负样本就证错了对象（"变异必须从点名的成因失败"）。
fn reseal(img: &mut [u8], off: usize) {
    put32(img, off + 16, 0);
    let crc = gpt::crc32(&img[off..off + 92]);
    put32(img, off + 16, crc);
}

/// 4 个扇区：LBA0 保护性 MBR、LBA1 主头、LBA2 条目数组（4×128 = 512，正好一个扇区）、
/// LBA3 备份头。只有第 0 格非空 ⇒ `used=1` 而 `entries_seen=4`，两个数分开才证得出
/// "空条目被跳过"而不是"扫到第一条就停了"。
fn build_tiny(img: &mut [u8]) {
    img.fill(0);
    img[446 + 4] = 0xEE;
    img[510] = 0x55;
    img[511] = 0xAA;
    let a = 2 * SECTOR_BYTES;
    img[a..a + 16].copy_from_slice(&gpt::ESP_TYPE_GUID);
    img[a + 16..a + 32].fill(0x5A);
    put64(img, a + 32, 2);
    put64(img, a + 40, 2);
    let array_crc = gpt::crc32(&img[a..a + SECTOR_BYTES]);
    seal_header(img, SECTOR_BYTES, 1, 3, array_crc);
    seal_header(img, 3 * SECTOR_BYTES, 3, 1, array_crc);
}

/// 真盘那一半：读数 + 结构判据。几何的**对不对**由宿主机判（下一刀），这里只判
/// 内核自己知道的那些形状，并把每个数打进串口供对账。
fn real_disk() -> bool {
    // 用例必须自足：`.ktests` 的顺序由链接器决定，不能假设别的用例已认领过 AHCI。
    if ahci::init().is_err() {
        crate::log_fatal!("gpt: AHCI 认领失败，没有块设备可读");
        return false;
    }
    let port = match ahci::boot_port() {
        Ok(p) => p,
        Err(e) => {
            crate::log_fatal!("gpt: 找不到引导盘（LBA1 写着 EFI PART 的那块） err={:?}", e);
            return false;
        }
    };
    let disk = AhciDisk { port };
    let mut calls = 0u32;
    let mut covers_state = false;
    let mut covers_pkg = false;
    let table = match gpt::scan(&disk, &mut |e| {
        calls += 1;
        if e.first_lba <= state_store::STATE_START_LBA && state_store::STATE_START_LBA <= e.last_lba {
            covers_state = true;
        }
        if e.first_lba <= sign::PKG_START_LBA && sign::PKG_START_LBA <= e.last_lba {
            covers_pkg = true;
        }
    }) {
        Ok(t) => t,
        Err(err) => {
            crate::log_fatal!("gpt: 真盘扫描被拒 口{} 拒因={:?}", port, err);
            return false;
        }
    };
    let h = &table.header;
    crate::log_info!(
        "gpt: 头 口{} revision={:#010x} header_size={} my_lba={} alternate_lba={} first_usable={} last_usable={} entry_lba={} entry_count={} entry_size={} header_crc={:#010x} array_crc={:#010x}",
        port, h.revision, h.header_size, h.my_lba, h.alternate_lba, h.first_usable, h.last_usable,
        h.entry_lba, h.entry_count, h.entry_size, h.header_crc, h.array_crc
    );
    crate::log_info!(
        "gpt: 表 扫过={} 非空={} 回调={} 数组字节={} 自算CRC={:#010x} 备份my_lba={} 备份alternate_lba={} disk_guid={:02x?}",
        table.entries_seen, table.used, calls, table.array_bytes, table.array_crc,
        table.backup.my_lba, table.backup.alternate_lba, h.disk_guid
    );
    let esp = match gpt::find_esp(&disk) {
        Ok(e) => e,
        Err(err) => {
            crate::log_fatal!("gpt: 找 ESP 被拒 口{} 拒因={:?}", port, err);
            return false;
        }
    };
    let (esp_first, esp_last, esp_ok) = match esp {
        Some(e) => {
            crate::log_info!(
                "gpt: ESP 序号={} first={} last={} attrs={:#x} type={:02x?} unique={:02x?}",
                e.index, e.first_lba, e.last_lba, e.attrs, e.type_guid, e.unique_guid
            );
            (e.first_lba, e.last_lba,
             e.first_lba >= h.first_usable && e.last_lba <= h.last_usable && e.first_lba <= e.last_lba)
        }
        None => {
            crate::log_fatal!("gpt: 真盘上找不到 ESP（type GUID 端序写错就会长这样）");
            return false;
        }
    };
    // 状态区与签名包是 GPT 未分派空隙里的裸 LBA 约定，**不是分区项**（ADR-078 决策 8）。
    let in_usable = |lba: u64| lba >= h.first_usable && lba <= h.last_usable;
    let gap_ok = !covers_state && !covers_pkg
        && in_usable(state_store::STATE_START_LBA) && in_usable(sign::PKG_START_LBA);
    crate::log_info!(
        "gpt: 未分派 状态区LBA={} 签名包LBA={} 被条目覆盖=({},{}) 都在可用区间={} 空隙成立={}",
        state_store::STATE_START_LBA, sign::PKG_START_LBA, covers_state, covers_pkg,
        in_usable(state_store::STATE_START_LBA) && in_usable(sign::PKG_START_LBA), gap_ok
    );
    let ok = calls == table.used && table.used >= 1 && table.entries_seen == h.entry_count
        && table.array_bytes <= gpt::MAX_ARRAY_BYTES && esp_ok && gap_ok;
    crate::log_info!(
        "gpt: 判据 回调与非空同数={} 有条目={} 扫过等于头说的={} 数组在预算内={} ESP在可用区间内={} 空隙成立={}",
        calls == table.used, table.used >= 1, table.entries_seen == h.entry_count,
        table.array_bytes <= gpt::MAX_ARRAY_BYTES, esp_ok, gap_ok
    );
    if !ok {
        crate::log_fatal!("gpt: 真盘判据不成立（上面四行是全部读数） esp=({},{})", esp_first, esp_last);
    }
    ok
}

/// CRC32 的外部已知答案 + 合成盘的正向格与逐闸负样本。
fn synthetic() -> bool {
    let v_empty = gpt::crc32(&[]);
    let v_std = gpt::crc32(b"123456789");
    let vectors_ok = v_empty == 0 && v_std == 0xCBF4_3926;
    crate::log_info!(
        "gpt: CRC向量 空串={:#010x}(期望0) 123456789={:#010x}(期望0xcbf43926) 成立={}",
        v_empty, v_std, vectors_ok
    );

    let mut base = [0u8; 4 * SECTOR_BYTES];
    build_tiny(&mut base);
    let mut calls = 0u32;
    let mut got: Option<gpt::Entry> = None;
    let table = match gpt::scan(&MemDisk { img: &base }, &mut |e| {
        calls += 1;
        got = Some(*e);
    }) {
        Ok(t) => t,
        Err(err) => {
            crate::log_fatal!("gpt: 合成盘正向格被拒 拒因={:?}（夹具与解析器对不上）", err);
            return false;
        }
    };
    let entry_ok = match got {
        Some(e) => e.type_guid == gpt::ESP_TYPE_GUID && e.first_lba == 2 && e.last_lba == 2 && e.index == 0,
        None => false,
    };
    // 数组 CRC 与宿主机常数同数：这一格证的是"两台实现算出同一个数"，不是"自己自洽"。
    let host_crc_ok = table.array_crc == HOST_ARRAY_CRC;
    let positive_ok = calls == 1 && table.used == 1 && table.entries_seen == 4 && entry_ok && host_crc_ok;
    crate::log_info!(
        "gpt: 合成盘 正向={} 回调={} 非空={} 扫过={} 条目对={} 数组CRC={:#010x} 宿主机常数={:#010x} 同数={}",
        positive_ok, calls, table.used, table.entries_seen, entry_ok, table.array_crc, HOST_ARRAY_CRC, host_crc_ok
    );

    let find_ok = matches!(gpt::find_esp(&MemDisk { img: &base }), Ok(Some(_)));
    let bogus = [0xFFu8; 16];
    let find_none = matches!(gpt::find_by_type(&MemDisk { img: &base }, &bogus), Ok(None));
    crate::log_info!("gpt: 查找 按ESP_GUID找到={} 按没见过的GUID回Ok(None)={}", find_ok, find_none);

    // 每格改一处、期望一个**点名**的拒因。改头字段的那些必须 reseal，否则头 CRC 先 fire
    // 就证错了对象；故意证 CRC 闸的那两格不 reseal。
    type Mut = fn(&mut [u8]);
    type Want = fn(&GptError) -> bool;
    // 必须是 const 而不是 let：闭包一旦捕获局部变量就不能退化成 fn 指针，这张表装不进去。
    const H1: usize = SECTOR_BYTES;
    const H3: usize = 3 * SECTOR_BYTES;
    let cells: [(&str, Mut, Want); 16] = [
        ("MBR类型不是0xEE", |b| b[446 + 4] = 0x0C, |e| matches!(e, GptError::NoProtectiveMbr)),
        ("MBR签名不在位", |b| b[510] = 0, |e| matches!(e, GptError::NoProtectiveMbr)),
        ("头签名错", |b| b[H1] = b'X', |e| matches!(e, GptError::BadSignature)),
        ("revision错", |b| put32(b, H1 + 8, 2), |e| matches!(e, GptError::BadRevision(2))),
        ("header_size太小", |b| put32(b, H1 + 12, 91), |e| matches!(e, GptError::HeaderTooSmall(91))),
        ("header_size太大", |b| put32(b, H1 + 12, 513), |e| matches!(e, GptError::HeaderTooBig(513))),
        ("头CRC不符", |b| b[H1 + 40] ^= 0x01, |e| matches!(e, GptError::HeaderCrc { .. })),
        ("entry_count超上界", |b| { put32(b, H1 + 80, 129); reseal(b, H1); }, |e| matches!(e, GptError::TooManyEntries(129))),
        ("entry_size太小", |b| { put32(b, H1 + 84, 127); reseal(b, H1); }, |e| matches!(e, GptError::EntryTooSmall(127))),
        ("entry_size太大", |b| { put32(b, H1 + 84, 513); reseal(b, H1); }, |e| matches!(e, GptError::EntryTooBig(513))),
        ("数组CRC不符", |b| b[2 * SECTOR_BYTES] ^= 0x01, |e| matches!(e, GptError::ArrayCrc { .. })),
        ("备份签名错", |b| b[H3] = b'X', |e| matches!(e, GptError::BackupSignature)),
        ("备份CRC不符", |b| b[H3 + 40] ^= 0x01, |e| matches!(e, GptError::BackupCrc { .. })),
        ("备份交叉核不符", |b| { put64(b, H3 + 24, 9); reseal(b, H3); }, |e| matches!(e, GptError::BackupMismatch { field: "my_lba", .. })),
        ("备份指到盘外", |b| { put64(b, H1 + 32, 99); reseal(b, H1); }, |e| matches!(e, GptError::Io(_))),
        ("扇区不足512", |_| {}, |e| matches!(e, GptError::ShortSector(100))),
    ];
    let mut named = 0usize;
    for (name, mutate, want) in cells.iter() {
        let mut work = base;
        mutate(&mut work);
        // 最后一格证的是 parse_header 的输入边界，不走整盘扫描。
        let err = if *name == "扇区不足512" {
            match gpt::parse_header(&work[..100]) {
                Err(e) => e,
                Ok(_) => {
                    crate::log_fatal!("gpt: 负样本[{}] 没咬到——100 字节竟然解出了头", name);
                    continue;
                }
            }
        } else {
            match gpt::scan(&MemDisk { img: &work }, &mut |_| {}) {
                Ok(_) => {
                    crate::log_fatal!("gpt: 负样本[{}] 没咬到——竟然解析成功了", name);
                    continue;
                }
                Err(e) => e,
            }
        };
        let hit = want(&err);
        if hit {
            named += 1;
        }
        crate::log_info!("gpt: 负样本[{}] 点名={} 拒因={:?}", name, hit, err);
    }
    let negatives_ok = named == cells.len();
    let ok = vectors_ok && positive_ok && find_ok && find_none && negatives_ok;
    crate::log_info!(
        "gpt: 合成判据 向量={} 正向={} 查找={} 找不到回None={} 点名负样本={}/{}",
        vectors_ok, positive_ok, find_ok, find_none, named, cells.len()
    );
    if !ok {
        crate::log_fatal!("gpt: 合成盘判据不成立（上面每格都有读数）");
    }
    ok
}

/// GPT 夹具盘挂哪个口。**与 `tools/aurora.py` 的 `GPT_FIX_PORT` 由门禁逐字对账**。
/// 为什么负样本落在夹具盘而不是引导盘（实测）：OVMF/EDK2 启动时会用备份 GPT 把主表修回原值
/// （数组首字节 0x29 改下去、跑完读回 0x28），四条注入根本到不了内核；另两条固件治不好 ⇒ NOBOOT。
/// 这块盘固件永远不碰，所以改它才证得到内核那道闸。
const GPT_FIX_PORT: u8 = 1;

/// 夹具盘上第二条分区的 type GUID（`0FC63DAF-8483-4772-8E79-3D69D8477DE4`，混合端序）。
/// 它存在的唯一理由是**反空转**：只放一条 ESP 的话，"按 GUID 找对了"与"返回了第一条"长得一样。
const DATA_TYPE_GUID: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
];

/// 夹具盘那一半：六条改盘负样本的载体。读数打给宿主机独立对账；
/// 判据只判结构性质（两条都在可用区间内、互不重叠、按两个 GUID 各找到各自那一条），
/// **不写死 first/last 的具体值**——那两个数由宿主机从盘上重算，写死就退化成一台仪器。
fn fixture_disk() -> bool {
    if ahci::init().is_err() {
        crate::log_fatal!("gptfix: AHCI 认领失败，没有块设备可读");
        return false;
    }
    let disk = AhciDisk { port: GPT_FIX_PORT };
    let mut calls = 0u32;
    let mut esp: Option<gpt::Entry> = None;
    let mut data: Option<gpt::Entry> = None;
    let table = match gpt::scan(&disk, &mut |e| {
        calls += 1;
        if e.type_guid == gpt::ESP_TYPE_GUID && esp.is_none() {
            esp = Some(*e);
        }
        if e.type_guid == DATA_TYPE_GUID && data.is_none() {
            data = Some(*e);
        }
    }) {
        Ok(t) => t,
        Err(err) => {
            // 注入就是要让它走到这里：**拒因必须点名**，宿主机证人按这个名字核。
            crate::log_fatal!("gptfix: 扫描被拒 口{} 拒因={:?}", GPT_FIX_PORT, err);
            return false;
        }
    };
    let h = &table.header;
    crate::log_info!(
        "gptfix: 头 口{} revision={:#010x} header_size={} my_lba={} alternate_lba={} first_usable={} last_usable={} entry_lba={} entry_count={} entry_size={} header_crc={:#010x} array_crc={:#010x}",
        GPT_FIX_PORT, h.revision, h.header_size, h.my_lba, h.alternate_lba, h.first_usable, h.last_usable,
        h.entry_lba, h.entry_count, h.entry_size, h.header_crc, h.array_crc
    );
    crate::log_info!(
        "gptfix: 表 扫过={} 非空={} 回调={} 数组字节={} 自算CRC={:#010x} 备份my_lba={} 备份alternate_lba={} disk_guid={:02x?}",
        table.entries_seen, table.used, calls, table.array_bytes, table.array_crc,
        table.backup.my_lba, table.backup.alternate_lba, h.disk_guid
    );
    let (e, d) = match (esp, data) {
        (Some(e), Some(d)) => (e, d),
        _ => {
            crate::log_fatal!(
                "gptfix: 两个 GUID 没各找到一条 ESP={} DATA={}（夹具只放一条就证不出查找不是返回第一条）",
                esp.is_some(), data.is_some()
            );
            return false;
        }
    };
    crate::log_info!(
        "gptfix: ESP 序号={} first={} last={} attrs={:#x} type={:02x?} unique={:02x?}",
        e.index, e.first_lba, e.last_lba, e.attrs, e.type_guid, e.unique_guid
    );
    crate::log_info!(
        "gptfix: 另一条 序号={} first={} last={} attrs={:#x} type={:02x?} unique={:02x?}",
        d.index, d.first_lba, d.last_lba, d.attrs, d.type_guid, d.unique_guid
    );
    let in_range = |x: gpt::Entry| x.first_lba >= h.first_usable && x.last_lba <= h.last_usable && x.first_lba <= x.last_lba;
    let disjoint = e.last_lba < d.first_lba || d.last_lba < e.first_lba;
    let find_esp_ok = matches!(gpt::find_esp(&disk), Ok(Some(x)) if x.index == e.index && x.first_lba == e.first_lba);
    let find_data_ok = matches!(gpt::find_by_type(&disk, &DATA_TYPE_GUID), Ok(Some(x)) if x.index == d.index);
    let ok = calls == table.used && table.used == 2 && table.entries_seen == h.entry_count
        && in_range(e) && in_range(d) && disjoint && e.index != d.index && find_esp_ok && find_data_ok;
    crate::log_info!(
        "gptfix: 判据 回调与非空同数={} 两条={} 扫过等于头说的={} 都在可用区间={} 互不重叠={} 序号不同={} 按ESP_GUID找对={} 按DATA_GUID找对={}",
        calls == table.used, table.used == 2, table.entries_seen == h.entry_count,
        in_range(e) && in_range(d), disjoint, e.index != d.index, find_esp_ok, find_data_ok
    );
    if !ok {
        crate::log_fatal!("gptfix: 判据不成立（上面四行是全部读数）");
    }
    ok
}

/// ADR-078 / W4 S1：GPT 只读解析。**三部分都必须成立**——真盘证"读得出来"，
/// 合成盘证"每道闸真会咬"，夹具盘是六条改盘负样本的载体（固件不碰它）。
/// 宿主机对账由 `validate_esp.py --report` 做（矩阵行 `GPT分区表与宿主机对账`）。
#[cfg(feature = "gpt-probe")]
fn t_gpt() -> bool {
    let real = real_disk();
    let synth = synthetic();
    let fix = fixture_disk();
    real && synth && fix
}
#[cfg(feature = "gpt-probe")]
ktest!(KT_GPT, t_gpt);