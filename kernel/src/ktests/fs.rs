//! FAT32 只读解析、内存卷与从盘装载用例（T0.1 纯搬移）。

use crate::arch::x86_64::{apic};
#[cfg(feature = "fat32-exec")]
use crate::handle;
use crate::{acpi, ahci, elf, filesystem, heap, mm, sched, sign, tsc, user};
use crate::ktests::common::{HELLO_ELF, P7_CALLS};
use crate::ktest;
use core::cell::UnsafeCell;

#[cfg(feature = "fat32-probe")]
/// 打开一条文件并走完整条链，把三本账收齐：目录项说的、链给的、内容算出来的。
/// 失败原样带出去——"设备没接走"与"这卷不是 FAT32"必须分开落在日志上，不许在这一层抹平。
fn fat32_file(
    vol: &filesystem::fat32::Volume<'_>,
    name: &str,
) -> Result<
    (
        filesystem::vfs::FileStat,
        filesystem::fat32::Walk,
        u64,
        [u8; 4],
    ),
    filesystem::fat32::FsError,
> {
    let st = vol.open(name)?;
    let mut h = ahci::FNV_OFFSET;
    let mut head = [0u8; 4];
    let mut fed = 0usize;
    let w = vol.walk(&st, |chunk| {
        for (i, b) in chunk.iter().enumerate() {
            h = ahci::fnv1a_step(h, *b);
            if fed + i < head.len() {
                head[fed + i] = *b;
            }
        }
        fed += chunk.len();
    })?;
    Ok((st, w, h, head))
}

#[cfg(feature = "fat32-probe")]
/// 三块盘挂在哪个口：0 是引导 ESP（也是"保护性 MBR 必须被拒"那一格的证人），
/// 3 与 4 是两块 FAT32 卷。②（`t_fat32_mem`）不用它们，③（`t_fat32_exec`）要再读一次卷A，
/// 所以这三个数从 `t_fat32` 的函数体里提到模块层——两处各写一份的话，
/// 改了接线那一处不会让另一处红，而串口只会说"挂载失败"。
/// 与 `tools/aurora.py` 的 `FAT_PORTS` 由门禁 `check-fat32-ports` 对账。
#[cfg(feature = "fat32-probe")]
const FAT_PORT_MBR: u8 = 0;
#[cfg(feature = "fat32-probe")]
pub(crate) const FAT_PORT_A: u8 = 3;
#[cfg(feature = "fat32-probe")]
pub(crate) const FAT_PORT_B: u8 = 4;

#[cfg(feature = "fat32-probe")]
/// 内存夹具卷（11,264 字节，配方 `tools/make_fat32_mem.py`，布局表在那个文件头）。
/// 它进 `.rodata` 而不进镜像：这一格的用途是让"贵到没法在真卷上跑"的分支有个便宜的落点。
static FAT32_MEM: &[u8] = include_bytes!("../../fixtures/fat32-mem.img");

#[cfg(feature = "fat32-probe")]
/// 把 0 号扇区拷一份、按 `f` 改一格、交给**与真卷同一个** `parse_boot_sector`。
/// 拷一份是因为这些是纯函数用例：改的是字节，不是盘。
fn fat32_mutate(f: fn(&mut [u8])) -> Result<filesystem::fat32::Bpb, filesystem::fat32::FsError> {
    let mut b = [0u8; 512];
    b.copy_from_slice(&FAT32_MEM[..512]);
    f(&mut b);
    filesystem::fat32::parse_boot_sector(&b)
}

#[cfg(feature = "fat32-probe")]
/// L3-C①：FAT32 只读解析的第一个真调用点。三本账各挡一种坏法——
/// 几何挡"偏移表是我编的"，目录挡"扫到第一条就像"，内容挡"簇号只取了低半"。
///
/// 两块卷的角色不能互相代替：卷A（32 MiB）是**阈值判型的反例**（64,496 簇按微软那条经验
/// 阈值算 FAT16，按结构算 FAT32，我们按结构收），卷B（64 MiB）里 FILLER.BIN 把后面三个文件
/// 推到 65,536 簇之上，于是目录项的簇号必须两半拼。每一格的期望数都来自夹具配方
/// （BACKLOG 78 的 mtools 那一节），没有一格是从解析器自己读回来的数抄的。
fn t_fat32() -> bool {
    use filesystem::fat32::{band_type, FsError, FatType, Volume, EOC_MARKER};
    use filesystem::vfs::{AhciDisk, FileStat};

    // 用例必须自足：`.ktests` 的顺序由链接器决定，不能假设别的用例已经认领过 AHCI
    if ahci::init().is_err() {
        crate::log_fatal!("fat32: AHCI 认领失败，没有块设备可读");
        return false;
    }
    // 卷挂在哪两个口由 `tools/aurora.py` 的 `FAT_PORTS` 定，两处由门禁 `check-fat32-ports` 对账
    let disk_a = AhciDisk { port: FAT_PORT_A };
    let disk_b = AhciDisk { port: FAT_PORT_B };

    // ⑥ 先判"必须被拒"的那一个。保护性 MBR 的 0x55AA **也在位上**，所以第一道崩下来的
    //    不是签名闸而是每扇区字节数闸（那 512 字节的 11..12 是全零）——这一格是量出来的。
    let mbr = Volume::mount(&AhciDisk { port: FAT_PORT_MBR });
    let mbr_rejected = matches!(mbr.as_ref().err(), Some(FsError::BadBytesPerSector(0)));
    crate::log_info!(
        "fat32: 引导盘 口{} 拒因={:?} 落在第一道闸={}",
        FAT_PORT_MBR,
        mbr.as_ref().err(),
        mbr_rejected
    );

    let va = match Volume::mount(&disk_a) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("fat32: 卷A（口{}）挂载失败 {:?}——盘没挂上就是红，不静默跳过", FAT_PORT_A, e);
            return false;
        }
    };
    let vb = match Volume::mount(&disk_b) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("fat32: 卷B（口{}）挂载失败 {:?}", FAT_PORT_B, e);
            return false;
        }
    };

    // ① 判型：结构收下、阈值拒绝的那一对。夹具哪天换成一簇数落在 FAT32 档的卷，
    //    这一格当场红，而不是悄悄变成一条空转的断言。
    let a_band = band_type(va.bpb.clusters);
    let b_band = band_type(vb.bpb.clusters);
    let a_counter = va.bpb.fat_type == FatType::Fat32 && a_band == FatType::Fat16;
    let b_struct = vb.bpb.fat_type == FatType::Fat32 && b_band == FatType::Fat32;
    let geo = va.bpb.data_start == 1040
        && va.bpb.clusters == 64_496
        && va.bpb.root_cluster == 2
        && vb.bpb.data_start == 2050
        && vb.bpb.clusters == 129_022;
    // 两卷同一组字段、各打一行：宿主机那台仪器按同一张表逐字段对账，字段集不对称时
    // 它对不到一半（把 卷B 写成"只有簇数与数据起点"就是这种半瞎状态）。
    // `自由簇` 内核自己不判——它是设备自报的数，判它的只有宿主机按偏移 488 重读那一遍。
    for (tag, vol, band) in [("A", &va, a_band), ("B", &vb, b_band)] {
        crate::log_info!(
            "fat32: 几何 卷{} 簇数={} 数据起点={} 每簇字节={} FAT份={} 每份扇区={} 根簇={} \
             FSInfo扇区={} 备份扇区={} 阈值判型={:?} 结构判型={:?} 名字串={} 备份逐字节同={} \
             自由簇={}(设备自报，内核不判)",
            tag,
            vol.bpb.clusters,
            vol.bpb.data_start,
            vol.bpb.cluster_bytes,
            vol.bpb.fat_count,
            vol.bpb.sectors_per_fat,
            vol.bpb.root_cluster,
            vol.bpb.fsinfo_sector,
            vol.bpb.backup_boot_sector,
            band,
            vol.bpb.fat_type,
            vol.bpb.fs_name_ok,
            vol.backup_same,
            vol.witness.free_clusters
        );
    }

    struct Want {
        name: &'static str,
        size: u32,
        cluster: u32,
        seen: u32,
        hi: u16,
        lo: u16,
    }
    let want_a = [
        Want { name: "HELLO.ELF", size: 32_672, cluster: 3, seen: 1, hi: 0, lo: 3 },
        Want { name: "NOTES", size: 1_000, cluster: 65, seen: 2, hi: 0, lo: 65 },
        Want { name: "SMALL.BIN", size: 100, cluster: 67, seen: 3, hi: 0, lo: 67 },
    ];
    let want_b = [
        Want { name: "HELLO.ELF", size: 32_672, cluster: 67_587, seen: 2, hi: 1, lo: 2_051 },
        Want { name: "NOTES", size: 1_000, cluster: 67_649, seen: 3, hi: 1, lo: 2_113 },
        Want { name: "SMALL.BIN", size: 100, cluster: 67_651, seen: 4, hi: 1, lo: 2_115 },
    ];

    let mut dir_ok = true;
    let mut walk_ok = true;
    let mut magic_ok = true;
    let mut lfn_zero = true;
    let mut hello_hash = [0u64; 2];
    for (vi, (vol, want)) in [(0usize, (&va, &want_a[..])), (1, (&vb, &want_b[..]))] {
        for w in want {
            let (st, wa, h, head) = match fat32_file(vol, w.name) {
                Ok(got) => got,
                Err(e) => {
                    crate::log_fatal!("fat32: 卷{} {} 读不成 {:?}", vi + 1, w.name, e);
                    dir_ok = false;
                    walk_ok = false;
                    continue;
                }
            };
            let clusters = (w.size as usize + vol.bpb.cluster_bytes - 1) / vol.bpb.cluster_bytes;
            let tail = w.size as usize - (clusters - 1) * vol.bpb.cluster_bytes;
            let d = st.size == w.size
                && st.first_cluster == w.cluster
                && st.entries_seen == w.seen
                && (st.first_cluster >> 16) as u16 == w.hi
                && (st.first_cluster as u16) == w.lo;
            let k = wa.bytes == w.size as usize
                && wa.clusters as usize == clusters
                && wa.tail_bytes == tail
                && wa.after_last >= EOC_MARKER;
            // HELLO.ELF 就是 `kernel/fixtures/hello.elf` 那份（宿主机独立知道它的头四字节），
            // 所以这一格是有已知常量的对照，不是"自己与自己一致"。
            let m = w.name != "HELLO.ELF" || head == [0x7f, b'E', b'L', b'F'];
            dir_ok &= d;
            walk_ok &= k;
            magic_ok &= m;
            lfn_zero &= st.lfn_entries == 0;
            if w.name == "HELLO.ELF" {
                hello_hash[vi] = h;
            }
            crate::log_info!(
                "fat32: 卷{} {:<9} 大小={} 簇={} 高半={} 低半={} 扫过项={} LFN={} \
                 走字节={} 走簇={} 尾字节={} 末簇后继={:#010x} 头四字节={:02x?} 哈希={:#018x} \
                 该到簇数={} 该到尾格={} 目录对={} 链对={} 头对={}",
                vi + 1,
                w.name,
                st.size,
                st.first_cluster,
                (st.first_cluster >> 16) as u16,
                (st.first_cluster as u16),
                st.entries_seen,
                st.lfn_entries,
                wa.bytes,
                wa.clusters,
                wa.tail_bytes,
                wa.after_last,
                head,
                h,
                clusters,
                tail,
                d,
                k,
                m
            );
        }
    }
    // ② 同一份文件从两个完全不同的簇号区间（3 与 67,587）读出来必须同一个哈希。
    //    这一格与 ⑦ 是一对：⑦ 证明"只取低半会指到别处"，② 证明"两半拼对了地方"。
    let cross_ok = hello_hash[0] != 0 && hello_hash[0] == hello_hash[1];

    // ④ 大小写不敏感是真的比过三个写法，不是抄了一遍期望名
    let notes = va.open("NOTES");
    let case_ok = match (va.open("notes"), va.open("NoTeS")) {
        (Ok(l), Ok(m)) => notes.ok().is_some_and(|u| u == l && l == m),
        _ => false,
    };
    // ⑤ 扫到目录末尾还没有 ⇒ NoEntry（证明 open 的退出条件不是"第一条不像就返回"）
    let absent_ok = matches!(va.open("NOFILE.TXT"), Err(FsError::NoEntry));

    // ⑦ 只取低半的对照：簇号拿 2,051 就落在 FILLER.BIN 的中间，链比元数据说的 31,320 字节长得多。
    //    期望 `ChainEndsLate`——它也是这个变体唯一的真调用点：没有这一格，那条分支没人走过。
    let lo_outcome = vb
        .open("HELLO.ELF")
        .map(|st| FileStat { first_cluster: (st.first_cluster as u16) as u32, ..st })
        .and_then(|wrong| vb.walk(&wrong, |_| {}));
    let lo_ok = matches!(lo_outcome, Err(FsError::ChainEndsLate { .. }));
    crate::log_info!(
        "fat32: 对照 卷A哈希={:#018x} 卷B哈希={:#018x} 同数={} 低半单独走的拒因={:?} | \
         大小写三写法同数={} 没有的那项被拒={}",
        hello_hash[0],
        hello_hash[1],
        cross_ok,
        lo_outcome.as_ref().err(),
        case_ok,
        absent_ok
    );

    let ok = mbr_rejected
        && a_counter
        && b_struct
        && geo
        && dir_ok
        && walk_ok
        && magic_ok
        && lfn_zero
        && cross_ok
        && case_ok
        && absent_ok
        && lo_ok;
    crate::log_info!(
        "fat32: 判据 引导盘被拒={} 卷A阈值反例={} 卷B结构={} 几何={} 目录={} 链={} ELF头={} \
         无长名={} 两卷同哈希={} 大小写={} 缺项被拒={} 低半单独被拒={} ⇒ {}",
        mbr_rejected,
        a_counter,
        b_struct,
        geo,
        dir_ok,
        walk_ok,
        magic_ok,
        lfn_zero,
        cross_ok,
        case_ok,
        absent_ok,
        lo_ok,
        ok
    );
    if !ok {
        crate::log_fatal!("fat32: 判据不成立（上面两行是卷自己读回来的数）");
    }
    ok
}
#[cfg(feature = "fat32-probe")]
ktest!(KT_FAT32, t_fat32);

#[cfg(feature = "fat32-probe")]
/// L3-C②：内存夹具那一本账。真卷上一次走链要发几百条块命令，所以三种"真卷上造不出来
/// 或造出来太贵"的形状放在这里：**环链撞界**、**已删除/目录/卷标条目被跳过**、
/// **LPN 计数那一格真的走过**（真卷上 `lfn_entries` 恒为 0，那条分支没人验证过）。
/// 负表 11 行走的是 `parse_boot_sector` 这个纯函数：每条必须命中**它点名的那一格**拒绝码，
/// 因为"只要求解析失败"的判据会让任何一条先生效的检查替其余的门背书（M4-2 那条老规矩）。
fn t_fat32_mem() -> bool {
    use filesystem::fat32::{band_type, FsError, FatType, Volume, Bpb, MAX_CLUSTERS_WALKED};
    use filesystem::vfs::{Block, BlockError, MemDisk};

    let disk = MemDisk { img: FAT32_MEM };
    let vol = match Volume::mount(&disk) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("fat32-mem: 挂载失败 {:?}", e);
            return false;
        }
    };
    // ① 几何：12 簇按阈值算 FAT12，按结构算 FAT32 —— 与卷A 同一类反例，但这里是我们自己造的，
    //    所以"阈值不是判型依据"这句话有两个独立来源（一个来自 mtools，一个来自合成卷）。
    let m_geo = vol.bpb.data_start == 10
        && vol.bpb.clusters == 12
        && vol.bpb.root_cluster == 2
        && vol.bpb.cluster_bytes == 512;
    let m_band = vol.bpb.fat_type == FatType::Fat32 && band_type(vol.bpb.clusters) == FatType::Fat12;
    crate::log_info!(
        "fat32-mem: 几何 簇数={} 数据起点={} 每簇字节={} FAT份={} 每份扇区={} 根簇={} 阈值判型={:?} \
         结构判型={:?} 名字串={} 备份逐字节同={} 自由簇={}(自报不判)",
        vol.bpb.clusters,
        vol.bpb.data_start,
        vol.bpb.cluster_bytes,
        vol.bpb.fat_count,
        vol.bpb.sectors_per_fat,
        vol.bpb.root_cluster,
        band_type(vol.bpb.clusters),
        vol.bpb.fat_type,
        vol.bpb.fs_name_ok,
        vol.backup_same,
        vol.witness.free_clusters
    );

    // ② 目录里那 12 条各挡一种坏法
    //    `?LD.TXT` 不是笔误：配方把首字节写成 0x05（"曾删除但还能留下"那一族），于是名字第一位
    //    的那个 `O` 在盘上**已经不存在了**，`name_matches` 只能按规范把它读成 '?'。
    //    上一轮这里查的是 `?OLD.TXT`，红在 NoEntry——那读的是配方的意图，不是盘上的字节。
    let long = vol.open("LONG~1.TXT");
    let old = vol.open("?LD.TXT");
    let noshort = vol.open("NOSHORT");
    let m_long = match long {
        Ok(st) => st.size == 2000 && st.first_cluster == 3 && st.entries_seen == 4 && st.lfn_entries == 2,
        Err(_) => false,
    };
    let m_old = match old {
        Ok(st) => st.size == 10 && st.first_cluster == 7 && st.entries_seen == 6 && st.lfn_entries == 2,
        Err(_) => false,
    };
    let m_noshort = match noshort {
        Ok(st) => st.size == 10 && st.first_cluster == 7 && st.entries_seen == 8,
        Err(_) => false,
    };
    // 卷标、子目录、已删除条目：三种"不能当成文件命中"。跳过它们的代码若删掉，
    // 前两格会从 NoEntry 变成 Ok。
    let m_skip = matches!(vol.open("MYVOLUME"), Err(FsError::NoEntry))
        && matches!(vol.open("MYDIR"), Err(FsError::NoEntry));
    crate::log_info!(
        "fat32-mem: 目录 LONG~1.TXT={:?} ?LD.TXT={:?} NOSHORT={:?} 卷标/子目录被跳过={} 界={}",
        long,
        old,
        noshort,
        m_skip,
        MAX_CLUSTERS_WALKED
    );

    // ③ 内容：2,000 字节、4 簇、尾格 464。前四字节是夹具配方里的已知常量（不是解析器自报的数）。
    let mut h = ahci::FNV_OFFSET;
    let mut head = [0u8; 4];
    let m_walk = match &long {
        Ok(st) => {
            let mut off = 0usize;
            match vol.walk(st, |chunk| {
                for (i, b) in chunk.iter().enumerate() {
                    h = ahci::fnv1a_step(h, *b);
                    // 只抓文件最前四字节。旧写法每段都覆写 head，等于抓"最后一段的前四字节的
                    // 残留"——旧夹具内容按偏移 4 周期重复，那个错法恰好绿；逐扇区不同内容后当场红。
                    if off + i < head.len() {
                        head[off + i] = *b;
                    }
                }
                off += chunk.len();
            }) {
                Ok(w) => {
                    w.bytes == 2000
                        && w.clusters == 4
                        && w.tail_bytes == 464
                        && w.after_last >= filesystem::fat32::EOC_MARKER
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    };
    let m_head = head == [0x11, 0x14, 0x17, 0x1a];

    // ④ 环链必须有界：8→9→10→**9** 永远走不完，而 size 写的是 0xFFFF_FFFF（左边的量永远不减到 0），
    //    所以唯一能停下来的东西就是 `MAX_CLUSTERS_WALKED`。这一格删掉，"有界"就只是注释。
    //    名字写的是盘上那一条（`CYCLIC.BIN`）：上一轮这里写成 `open("CYCLIC")`，于是这一格
    //    红在"条目读不出来"——而被判的那件事是"读出来之后走链有界"，两者差一整条路径。
    let m_cyclic = match vol.open("CYCLIC.BIN") {
        Ok(_) => true,
        Err(e) => {
            crate::log_fatal!("fat32-mem: CYCLIC 条目读不出来 {:?}", e);
            false
        }
    };
    let cyclic_err = vol
        .open("CYCLIC.BIN")
        .and_then(|st| vol.walk(&st, |_| {}));
    let m_bound = matches!(cyclic_err, Err(FsError::ChainTooLong));

    // ⑤ 链比元数据短：size=4096 而首簇直接就是链尾 ⇒ `ChainEndsEarly`，报出来的字节数是 512。
    //    簇号与那个 EOC 读数现在跟着错误一起出来：上一轮 `FAT32_CLUSTER_MASK` 少写一个 nibble 时，
    //    真卷报的是 `ChainEndsLate { bytes: 31320, size: 31320 }`——两个数相等，看起来像自相矛盾，
    //    而当时日志里没有末簇与它的 FAT 读数，只能靠宿主机重算扇区哈希才定位到掩码。
    let early = vol.open("SHORTCHN.BIN").and_then(|st| vol.walk(&st, |_| {}));
    let m_early = matches!(early, Err(FsError::ChainEndsEarly { bytes: 512, size: 4096, .. }));
    crate::log_info!("fat32-mem: 链不自洽的两格 短链={:?} 环链={:?}", early, cyclic_err);

    // ⑥ 目录项的簇号落在坏簇区 ⇒ 拒，而不是拿它去算一个地址
    let m_badclu = matches!(vol.open("BADCLU.BIN"), Err(FsError::EntryOutsideData(_)));

    // ⑦ 内存适配器自己的界：越过镜像末尾是参数错（没有对端会回话），与真盘上"设备报越界"分开数
    let mut junk = [0u8; 512];
    let m_bounds = disk.read_sectors(22, &mut junk) == Err(BlockError::Refused)
        && disk.read_sectors(0, &mut junk[..511]) == Err(BlockError::Refused)
        && disk.read_sectors(21, &mut junk).is_ok();

    // ⑧ 负表：11 行各命中一格拒绝码，外加一行"没改动的必须解析成功"当对照组
    let neg: [(&str, fn(&mut [u8]), fn(&FsError) -> bool); 11] = [
        ("签名挪走", |b| b[510] = 0x00, |e| matches!(e, FsError::NoSignature)),
        ("每扇区 0", |b| { b[11] = 0; b[12] = 0 }, |e| matches!(e, FsError::BadBytesPerSector(0))),
        ("每扇区 1024", |b| { b[11] = 0; b[12] = 4 }, |e| matches!(e, FsError::UnsupportedSectorSize(1024))),
        ("每扇区 3", |b| { b[11] = 3; b[12] = 0 }, |e| matches!(e, FsError::BadBytesPerSector(3))),
        ("每簇 3", |b| b[13] = 3, |e| matches!(e, FsError::BadSectorsPerCluster(3))),
        ("介质 0", |b| b[21] = 0, |e| matches!(e, FsError::BadMedia(0))),
        // 固定根目录区在位 ⇒ 结构上说它不是 FAT32；22 个扇区算出来 12 簇 ⇒ 阈值说 FAT12
        ("固定根区", |b| { b[17] = 224; b[18] = 0 }, |e| matches!(e, FsError::UnsupportedFat(FatType::Fat12))),
        // 软盘形状：**W4 S2a 重新瞄准过这一格**。原来它是"纯 FAT16 结构"并期望 UnsupportedFat(Fat16)；
        // FAT16 现在被收下了，那个期望不再成立。改成**两族结构闸都不收**：
        // 固定根区清零（FAT32 闸要求 spf16==0，这里 spf16=9 ⇒ 不收）、spf16 在位而 root_entries=0
        // （FAT16 闸要求 root_entries!=0 ⇒ 也不收）⇒ 落到"阈值只用来给拒因起名字"那一支。
        // total32=32,640、spf=9 ⇒ 簇数 32,621 落 FAT16 档 ⇒ 仍点名 Fat16，期望值与负表 11 行计数都不变。
        // 它现在证的是"结构不匹配就不收，阈值只负责起名字"；而"FAT16 结构必须收下、即使簇数落在
        // FAT32 档"那条更强的反例由 t_fat16 负责（不在这里放宽）。
        // total32 按**小端**写：上一轮这里写成 `0, 0x80, 0x7f, 0` ⇒ 读出来是 0x007F8000（835 万），
        // 阈值判型当场翻成 FAT32、于是这一行解析成功——字节序写反的负样本不会红，它会**绿着不测东西**。
        ("软盘形状", |b| {
            b[14] = 1; b[15] = 0;
            b[17] = 0; b[18] = 0;
            b[19] = 0; b[20] = 0;
            b[22] = 9; b[23] = 0;
            b[36] = 0; b[37] = 0; b[38] = 0; b[39] = 0;
            b[32] = 0x80; b[33] = 0x7f; b[34] = 0; b[35] = 0;   // total32 = 0x00007F80 = 32,640
        }, |e| matches!(e, FsError::UnsupportedFat(FatType::Fat16))),
        ("零份 FAT", |b| { b[16] = 0; b[17] = 224 }, |e| matches!(e, FsError::MalformedBpb)),
        ("几何越出镜像", |b| { b[36] = 0xFF; b[37] = 0xFF }, |e| matches!(e, FsError::GeometryBeyondVolume { .. })),
        // FAT32 结构分支里的 `fat_count == 0`：上一行那一格走的是**非 32 分支**的那道闸，
        // 两道闸在源码里差十几行，只测一道等于另一道没人验过。
        // （这里原本写的是"扩展字段不在位 ⇒ NoSignature"，那是错的期望：`BS_BootSig` 与
        //  510 那两字节的签名是两格，清 66 号字节只会让 `fs_name_ok` 变 false，解析照旧成功。
        //  那一格的期望由下面的 `m_boot_sig` 单独判，不该混在"必须被拒"这张表里。）
        ("FAT32 里零份 FAT", |b| b[16] = 0, |e| matches!(e, FsError::MalformedBpb)),
    ];
    let mut m_neg = true;
    let mut neg_detail = [0u8; 12];
    for (i, (tag, poke, want)) in neg.iter().enumerate() {
        match fat32_mutate(*poke) {
            Err(e) if want(&e) => neg_detail[i] = 1,
            other => {
                neg_detail[i] = 0;
                m_neg = false;
                crate::log_fatal!("fat32-mem: 负表【{}】没有命中那一格，实际={:?}", tag, other.as_ref().err());
            }
        }
    }
    // 对照组：一格没改的 0 号扇区必须解析成功——否则上面 11 行是"全都失败"混出来的绿
    let m_control = fat32_mutate(|_| {}).map(|b: Bpb| b.clusters == 12).unwrap_or(false);
    // 最后一行单独判：`BS_BootSig` 不在位时 82 那格是保留区，不许当文件系统名收
    let m_boot_sig = fat32_mutate(|b| b[66] = 0x00).map(|b| !b.fs_name_ok).unwrap_or(false);
    let m_pos = fat32_mutate(|_| {}).map(|b| b.fs_name_ok).unwrap_or(false);

    let ok = m_geo
        && m_band
        && m_long
        && m_old
        && m_noshort
        && m_skip
        && m_walk
        && m_head
        && m_cyclic
        && m_bound
        && m_early
        && m_badclu
        && m_bounds
        && m_neg
        && m_control
        && m_boot_sig
        && m_pos;
    crate::log_info!(
        "fat32-mem: 判据 几何={} 阈值反例={} 长名计数={} 问号名={} 无扩展名={} 卷标子目录跳过={} \
         内容={} 头四字节={} 环链撞界={} 短链={} 坏簇号={} 适配器界={} 负表11行={} 对照组={} \
         boot_sig不在位则名字不算={} ⇒ {}",
        m_geo,
        m_band,
        m_long,
        m_old,
        m_noshort,
        m_skip,
        m_walk,
        m_head,
        m_bound,
        m_early,
        m_badclu,
        m_bounds,
        m_neg,
        m_control,
        m_boot_sig,
        ok
    );
    if !ok {
        crate::log_fatal!("fat32-mem: 判据不成立（上面三行是卷自己读回来的数）");
    }
    ok
}
#[cfg(feature = "fat32-probe")]
ktest!(KT_FAT32_MEM, t_fat32_mem);

#[cfg(feature = "fat32-exec")]
/// 从盘上读出来的镜像最多接多少字节。**这不是"文件应该多大"**——文件多大由目录项说，
/// 这一格说的是"缓冲准备接多少"。§10.3 那条老规矩：先验上界再用（`sign::PKG_BYTES`
/// 那一族的第三个使用点，见 BACKLOG 61a：按外部输入的大小开缓冲在这台机上第一次分配就走
/// `handle_alloc_error`，整机构成 39，而分配器上限只有 2048 字节）。
const ELF_DISK_MAX: usize = 64 * 1024;

#[cfg(feature = "fat32-exec")]
struct ElfDiskScratch(UnsafeCell<[u8; ELF_DISK_MAX]>);
#[cfg(feature = "fat32-exec")]
// SAFETY: 只在 `fat32-exec` 变体的这一条用例里用；可变借用不越过那一次 `walk` 调用，
//         不外泄 `&'static mut`，同一时刻不存在两份借用（与 `PkgScratch` 同一条理由）。
unsafe impl Sync for ElfDiskScratch {}
#[cfg(feature = "fat32-exec")]
static ELF_DISK: ElfDiskScratch = ElfDiskScratch(UnsafeCell::new([0u8; ELF_DISK_MAX]));

#[cfg(feature = "fat32-exec")]
/// L3-C③：把用户镜像的来源从 `include_bytes!` 换成**卷A 上的 `HELLO.ELF`**，然后真的跑起来。
///
/// 七个现场、八条 bool（`②` 那一步同时判走链的账与整份字节）。顺序就是函数体的顺序：
/// ① 上界先验再用：`size` 来自盘上的目录项，不来自我对夹具的记忆
/// ② 走链的账（字节数/簇数/尾格/末簇后继）**加上**缓冲里那 31,320 个字节与 `include_bytes!`
///    那份逐字节相同——不是同哈希：`0xa4cd9301241b0161` 那一格由 `t_fat32` 判，
///    这里判的是"要交给加载器的那段字节本身"
/// ③ 两条来源的**段表**逐项相同（入口、每条段的 offset/vaddr/filesz/memsz 与三个权限位）
/// ④ 装得上、跑得通：五个槽的数与内嵌那条路径同一组期望（`elfload:` 那两行是同一跑的第二台仪器）
/// ⑤ 元数据把大小说大 4096 字节 ⇒ 走链必须先 `ChainEndsEarly`，**装载这一步根本不该发生**
/// ⑥ 把长度截到最后一条 PT_LOAD 的文件末尾减 1 ⇒ 加载器必须按 `SegmentOutOfBounds` 拒
/// ⑦ 收尾把 VA 还回去：结束时的保留数与开始时相同（不给后面任何一次 `user::load` 留 `VaTaken`）
///
/// ⑤ 与 ⑥ 是这一格特有的：**"容器对不对"以前只能信内嵌那份字节**，因为输入是我编的；
/// 现在输入来自一块真盘上的元数据，"目录项撒谎时不许往下装"才第一次成为可判的事。
fn t_fat32_exec() -> bool {
    use filesystem::fat32::{FsError, Volume, EOC_MARKER};
    use filesystem::vfs::{AhciDisk, FileStat};

    let Some(s) = acpi::summary() else { return false };
    let Some(m) = s.madt else { return false };
    if ahci::init().is_err() {
        crate::log_fatal!("elfdisk: AHCI 认领失败，没有卷可读");
        return false;
    }
    if apic::get_or_init(&m).is_err() {
        crate::log_fatal!("elfdisk: APIC 起不来，跑不了时间片");
        return false;
    }
    let before = mm::reservation_count();
    let vol = match Volume::mount(&AhciDisk { port: FAT_PORT_A }) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("elfdisk: 卷A（口{}）挂载失败 {:?}", FAT_PORT_A, e);
            return false;
        }
    };
    let st = match vol.open("HELLO.ELF") {
        Ok(s) => s,
        Err(e) => {
            crate::log_fatal!("elfdisk: 打开 HELLO.ELF 失败 {:?}", e);
            return false;
        }
    };

    // ① 上界先验再用：`st.size` 是**盘上元数据给的数**，它必须先在界内才允许变成拷贝长度
    let size = st.size as usize;
    if size > ELF_DISK_MAX {
        crate::log_fatal!("elfdisk: 目录项说大小={} 超过缓冲上限={} ⇒ 拒，不看内容", size, ELF_DISK_MAX);
        return false;
    }
    let bound_ok = size == HELLO_ELF.len();
    crate::log_info!(
        "elfdisk: 目录 大小={} 首簇={} 扫过项={} 缓冲上限={} 与内嵌夹具同长={}",
        size,
        st.first_cluster,
        st.entries_seen,
        ELF_DISK_MAX,
        bound_ok
    );

    // ② 走链喂进**静态**缓冲。为什么不是一次读满整个文件：`heap::LARGE_MAX = 2048`
    //    决定了"按外部输入的大小分配"在这台机上第一次分配就走 `handle_alloc_error`（BACKLOG 61a
    //    那条老账，这里是它的第四个使用点）；而每段最多一个簇 ⇒ 一次拷贝最多 512 字节。
    let dst = ELF_DISK.0.get();
    let mut fed = 0usize;
    // 第一次"喂出来的已经比目录项说的还多"的现场（已喂了多少、这一段又要喂多少）。
    // 这个量必须存在：注入 `fault-fat32-tail` 就是让它多喂一个字节，而那正是
    // "写区间靠一个来自盘上元数据的计数"会越界的地方。
    let mut over: Option<(usize, usize)> = None;
    let walked = vol.walk(&st, |chunk| {
        if fed + chunk.len() > size {
            // **不再写**。写下去的下一步是越界，而那表现是 panic 不是判据红——
            // 量具自己把"用例红"升级成"内核挂"是本仓库最不能留的一类错（§9.2 态度的延伸）。
            if over.is_none() {
                over = Some((fed, chunk.len()));
            }
            return;
        }
        // SAFETY: 见 `ElfDiskScratch`。写区间的界由这一格自己判（上面那个 `fed + len > size`
        // 就是那道闸），而 `size` 已在 ① 验过 `<= ELF_DISK_MAX`。
        // 这里**不再**依赖"`walk` 承诺不超过 size"那句话：它正是 `fault-fat32-tail` 推翻的东西。
        unsafe {
            let buf = &mut *dst;
            buf[fed..fed + chunk.len()].copy_from_slice(chunk);
        }
        fed += chunk.len();
    });
    let (w, disk) = match walked {
        Ok(w) => {
            // 显式取数组首地址再切片：`&(*dst)[..size]` 会对裸指针的解引用做隐式 autoref，
            // 那条会静默加上一层别名要求（本工具链直接判错）。写明白反而更容易看出借用从哪来。
            let head = unsafe { (*dst).as_ptr() };
            (w, unsafe { core::slice::from_raw_parts(head, size) })
        }
        Err(e) => {
            crate::log_fatal!("elfdisk: 走链失败 {:?}", e);
            return false;
        }
    };
    if let Some((at, n)) = over {
        crate::log_fatal!(
            "elfdisk: 尾格溢出 已喂={} 这段还要喂={} 目录项说={} 走链自报字节={} ⇒ 不往下装",
            at,
            n,
            size,
            w.bytes
        );
        return false;
    }
    let walk_ok = w.bytes == size
        // 簇数由大小推出来，不写死 62：容器一改（P7 加了句柄实验段，31,320 → 33,856），
        // 写死的数会把"夹具换了"读成"走链坏了"。
        && w.clusters as usize == (size + vol.bpb.cluster_bytes - 1) / vol.bpb.cluster_bytes
        && w.tail_bytes == size - (w.clusters as usize - 1) * vol.bpb.cluster_bytes
        && w.after_last >= EOC_MARKER
        && fed == size;
    let bytes_same = disk == &HELLO_ELF[..];

    // ②b 句柄路径（P7 设计 §6.4）：同一份字节经 16 格表 + 每槽 u48 世代读回来，必须与走链
    //     那份逐个相同。表里存的是值（port + Bpb + FileStat + 游标），不借 `Volume` 的生命周期。
    //     这条把「取文件路径改走表的核内入口」变成有真实调用者的一件事；它仍是 ktest，不是产品路径。
    sched::init_boot_task();
    let ident = match crate::sched::current_identity() {
        Some(v) => v,
        None => {
            crate::log_fatal!("elfdisk: 句柄路径拿不到当前任务身份");
            return false;
        }
    };
    let hcur = match vol.open_cursor("HELLO.ELF") {
        Ok(c) => c,
        Err(e) => {
            crate::log_fatal!("elfdisk: 句柄路径打开失败 {:?}", e);
            return false;
        }
    };
    let h = match crate::handle::grant_file(
        ident,
        FAT_PORT_A,
        hcur,
        crate::handle::RIGHT_READ | crate::handle::RIGHT_DUP,
    ) {
        Ok(h) => h,
        Err(e) => {
            crate::log_fatal!("elfdisk: 授予句柄失败 {}", e.tag());
            return false;
        }
    };
    let mut hoff = 0usize;
    let mut hsame = true;
    let mut hchunk = [0u8; crate::filesystem::vfs::SECTOR_BYTES];
    while hoff < size {
        let ask = core::cmp::min(hchunk.len(), size - hoff);
        match crate::handle::read(h, ident, &mut hchunk[..ask]) {
            Ok(0) => break,
            Ok(n) => {
                hsame &= disk[hoff..hoff + n] == hchunk[..n];
                hoff += n;
                if n < ask {
                    break;
                }
            }
            Err(e) => {
                crate::log_fatal!("elfdisk: 句柄路径读失败 {}", e.tag());
                return false;
            }
        }
    }
    let heof = crate::handle::read(h, ident, &mut hchunk) == Ok(0);
    let hclose = crate::handle::close(h, ident).is_ok();
    let handle_ok = hoff == size && hsame && heof && hclose;
    crate::log_info!(
        "elfdisk: 句柄 slot={} gen={:#x} 字节={} 同走链={} EOF={} 关闭={}",
        h.slot(),
        h.gen(),
        hoff,
        hsame,
        heof,
        hclose
    );

    // ③ 段表两处对比（这份容器是 `ET_EXEC`，地址搬不动，所以两处必须逐格相同）
    let prog_d = elf::parse(disk);
    let prog_e = elf::parse(HELLO_ELF);
    let mut segs_same = false;
    match (&prog_d, &prog_e) {
        (Ok(a), Ok(b)) => {
            segs_same = a.entry == b.entry
                && a.n == b.n
                && a.phnum == b.phnum
                && a.segments().iter().zip(b.segments()).all(|(x, y)| {
                    x.offset == y.offset
                        && x.vaddr == y.vaddr
                        && x.filesz == y.filesz
                        && x.memsz == y.memsz
                        && x.readable == y.readable
                        && x.writable == y.writable
                        && x.executable == y.executable
                });
            for (i, s) in a.segments().iter().enumerate() {
                crate::log_info!(
                    "elfdisk: 段{} off={} va={:#x} filesz={} memsz={} r={} w={} x={}",
                    i,
                    s.offset,
                    s.vaddr,
                    s.filesz,
                    s.memsz,
                    s.readable,
                    s.writable,
                    s.executable
                );
            }
        }
        (Err(e), _) => crate::log_fatal!("elfdisk: 盘上那份解析失败 {:?}", e),
        _ => crate::log_fatal!("elfdisk: 内嵌那份解析失败（对照物本身没了）"),
    }

    // ④ 装进用户窗口并跑起来。这一段与 `t_elf_load_run` 同形状，差别只有一处：
    //    `bytes` 来自一次走链而不是 `.rodata`——所以判据必须与那条**同一组数**，
    //    否则"换了来源就换了行为"这件事没人能发现（串口上 `elfload:` 那两行就是第二台仪器）。
    let loaded = match user::load(disk) {
        Ok(l) => l,
        Err(e) => {
            crate::log_fatal!("elfdisk: 加载失败 —— {}", user::describe_load(e));
            return false;
        }
    };
    let code_eff = mm::effective_flags(loaded.entry);
    let data_eff = mm::effective_flags(loaded.data_va);
    let eff_ok = code_eff.is_some_and(|f| f.user && f.executable && !f.writable)
        && data_eff.is_some_and(|f| f.user && f.writable && !f.executable);
    let same_image = loaded.segs == prog_d.as_ref().map(|p| p.n).unwrap_or(0)
        && loaded.pages > 0;

    sched::init_boot_task();
    sched::start_workers();
    user::clear_counters();
    let t = match sched::spawn_user(loaded.entry, loaded.stack_top, 0, loaded.owned) {
        Ok(t) => t,
        Err(e) => {
            crate::log_fatal!("elfdisk: spawn_user 失败 {:?}", e);
            return false;
        }
    };
    // P7 ⑤：装载器给**这个容器**授予 READ|DUP 句柄，指向它自己那份镜像。
    // 身份按 spawn 返回的 gidx 查两格（gidx + Task::id）——不是启动上下文自己的身份；
    // 把句柄写进容器的 `.slots`，与 `flag` 一起在它被换上来之前写好（定时器还没开）。
    let ring3_h = match crate::sched::identity_of(t) {
        Some(ident) => {
            let hc = match vol.open_cursor("HELLO.ELF") {
                Ok(c) => c,
                Err(e) => {
                    crate::log_fatal!("elfdisk: 授予前打开失败 {:?}", e);
                    return false;
                }
            };
            // 负样本：owner 的 Task::id 改错一格。容器读自己的句柄必须 `-4`。
            let owner = {
                #[cfg(feature = "fault-handle-owner")]
                { (ident.0, ident.1 ^ 1) }
                #[cfg(not(feature = "fault-handle-owner"))]
                { ident }
            };
            let h = match crate::handle::grant_file(
                owner,
                FAT_PORT_A,
                hc,
                crate::handle::RIGHT_READ | crate::handle::RIGHT_DUP,
            ) {
                Ok(h) => h,
                Err(e) => {
                    crate::log_fatal!("elfdisk: 授予容器失败 {}", e.tag());
                    return false;
                }
            };
            user::write_at(loaded.data_va + user::ABI_SLOT_HANDLE, h.0);
            user::write_at(loaded.data_va + user::ABI_SLOT_FLAG, user::FLAG_HANDLE);
            crate::log_info!("elfdisk: 授予容器 句柄={:#x} 主人=({},{})", h.0, owner.0, owner.1);
            h
        }
        None => {
            crate::log_fatal!("elfdisk: 容器身份查不到（gidx={}）", t);
            return false;
        }
    };
    // §199：收尾按原样放回（与 t_handle_reap 同一律）。本用例需要表走，所以照样开；
    // 旧写法无条件 stop，把表停给了后面所有用例（第二终端的前置条件，BACKLOG §198/§199）。
    let tick_in = apic::ticks();
    let timer_was_running =
        apic::wait_ticks(tick_in, 2, crate::clock::window_cycles(2)).ticks >= 2;
    apic::timer_start().ok();
    let mut rounds = 0u64;
    apic::with_interrupts(|| {
        let t0 = tsc::now();
        // 句柄实验的最后一步写 `h_done`；等它，而不是只等基础序列的调用数——
        // 否则"程序还在跑句柄段、内核已经去读槽"这种赛跑会被读成判据红。
        while (user::served() < P7_CALLS
            || user::read_at(loaded.data_va + user::ABI_SLOT_H_DONE).unwrap_or(0) == 0)
            && tsc::now().wrapping_sub(t0) < 200_000_000
        {
            rounds += 1;
            tsc::spin(20_000);
        }
        tsc::spin(2_000_000);
        if !sched::wait_for_boot_task(300_000_000) {
            crate::log_fatal!("elfdisk: 窗口收不了场（启动上下文没回到 CPU）");
        }
    });
    if !timer_was_running {
        apic::timer_stop().ok();
    }
    let magic = user::read_at(loaded.data_va);
    let ping = user::read_at(loaded.data_va + 8);
    let add = user::read_at(loaded.data_va + 16);
    let unk = user::read_at(loaded.data_va + 24);
    let rod = user::read_at(loaded.data_va + 32);
    let loops = user::read_at(loaded.data_va + 40);
    // ring3 那两格：由**用户侧**写，内核只读。close 的成功不单占一格——`live()==0` 就是见证。
    let h_magic = user::read_at(loaded.data_va + user::ABI_SLOT_H_MAGIC);
    let h_done = user::read_at(loaded.data_va + user::ABI_SLOT_H_DONE);
    let table_clean = crate::handle::live() == 0;
    let ring3_ok = h_magic == Some(0x464c_457f)
        && h_done == Some(0x4844_4f4e_45)
        && table_clean;
    crate::log_info!(
        "elfdisk: ring3 句柄 魔数={:?} done={:?} 句柄值={:#x} 表清空={} ⇒ {}",
        h_magic,
        h_done,
        ring3_h.0,
        table_clean,
        ring3_ok
    );
    let served = user::served();
    let guard_ok = !mm::is_mapped(loaded.stack_top - mm::PAGE as u64 - 8);
    crate::log_info!(
        "elfdisk: 跑后 entry={:#x} data={:#x} stack_top={:#x} segs={} pages={} magic={:?} ping={:?} \
         add={:?} unk={:?} rodata={:?} loops={:?} served={} rounds={} guard_unmapped={} code={:?} data={:?}",
        loaded.entry,
        loaded.data_va,
        loaded.stack_top,
        loaded.segs,
        loaded.pages,
        magic,
        ping,
        add,
        unk,
        rod,
        loops,
        served,
        rounds,
        guard_ok,
        code_eff,
        data_eff
    );
    let run_ok = magic == Some(0xa5a5_5a5a_1234_5678)
        && loops == Some(28)
        && add == Some(0x2a + 0x12)
        && unk == Some(user::E_INVALID)
        && rod == Some(0xa7)
        && ping.is_some_and(|v| v >= 1)
        && served >= P7_CALLS
        && eff_ok
        && guard_ok
        && same_image
        && ring3_ok;

    // ⑤ 目录项把大小说大 4096：链在喂完之前就到 EOC ⇒ 必须红在走链那一步，装载无从发生。
    //    这一格是"来源换成盘"之后新增的那一类：内嵌夹具的 size 是我编的，改不动它。
    let big = FileStat { size: (size + 4096) as u32, ..st };
    let oversized = vol.walk(&big, |_| {});
    let early_ok = matches!(oversized, Err(FsError::ChainEndsEarly { .. }));

    // ⑥ 截到最后一条 PT_LOAD 的文件末尾减 1 ⇒ 加载器必须拒。界取"段表自己说的最远字节"
    //    而不是随便少几个：这份容器的尾部还有 `.symtab/.strtab`（`filesz` 不覆盖它们），
    //    截 5 个字节谁都发现不了——那一格会绿着不测任何东西（`fault-fat32-tail` 同族的形状）。
    let last_end = prog_d
        .as_ref()
        .map(|p| p.segments().iter().map(|s| s.offset + s.filesz).max().unwrap_or(0))
        .unwrap_or(0);
    let last_end_ok = last_end > 0 && (last_end as usize) <= size;
    let truncated = if last_end_ok {
        user::load(&disk[..last_end as usize - 1])
    } else {
        // 段表自己给的界不可信 ⇒ 这一格没跑成。这里造的是一条**别的**拒绝码，
        // 于是下面那句 `matches!` 必然红——而不是"跳过这一格"混成绿（§12.4.1 规则 3 的形状）。
        crate::log_fatal!("elfdisk: 段表给的文件末尾不可信 last_end={} size={}，⑥ 没跑成", last_end, size);
        Err(user::LoadError::SegmentNotPageAligned { va: 0 })
    };
    let short_ok =
        matches!(truncated, Err(user::LoadError::Elf(elf::ElfError::SegmentOutOfBounds)));

    // ⑦ 收尾：把本用例名下的资源还回去，然后与开始前的保留数对账。
    //    `terminate_task` 之后还要 `reap_released()`——`elfload` 那一条的串口读数
    //    （`收尾回收 released=`）证明这两步都真发生了才有 6 条这个数。
    let terminated = sched::terminate_task(t);
    let released = sched::reap_released();
    let after = mm::reservation_count();
    let clean_up = terminated && after == before;
    crate::log_info!(
        "elfdisk: 负格 元数据说大={:?} 截短={:?} | 收尾 终止={} 回收={} 保留{}→{}",
        oversized.as_ref().err(),
        truncated.as_ref().err(),
        terminated,
        released,
        before,
        after
    );

    let ok = bound_ok && walk_ok && bytes_same && handle_ok && segs_same && run_ok && early_ok && short_ok && clean_up;
    crate::log_info!(
        "elfdisk: 判据 同长={} 走链={} 字节同={} 段表同={} 跑通={} 元数据说大被拒={} 截短被拒={} 收尾干净={} 句柄路径={} ring3句柄={} ⇒ {}",
        bound_ok,
        walk_ok,
        bytes_same,
        segs_same,
        run_ok,
        early_ok,
        short_ok,
        clean_up,
        handle_ok,
        ring3_ok,
        ok
    );
    if !ok {
        crate::log_fatal!("elfdisk: 判据不成立（上面三行是这一跑的读数）");
    }
    ok
}
#[cfg(feature = "fat32-exec")]
ktest!(KT_FAT32_EXEC, t_fat32_exec);

