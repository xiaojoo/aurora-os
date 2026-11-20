//! NVMe 上挂真卷并读文件（ADR-172）。
//!
//! ## 这一条证什么
//!
//! `t_nvme_all` 三格证的是**设备级**通路（识别 / 容量 / 读扇区图案）。
//! 这一条证**文件系统级**：`NvmeDisk` 作为 `Block` 交给 `Volume::mount`，
//! 挂载成功、读到目录项、读出文件内容。
//!
//! **两者是不同层的证据**：设备能读扇区 ≠ 那块盘上有能被解析的卷；
//! 卷能挂 ≠ 文件内容对。三层各自能独立红。
//!
//! ## 盘上有什么（`tools/make_fat32_rw.py` 造的）
//!
//!     /DATA.BIN   1024 字节，2 簇
//!     /LOG.TXT      64 字节，1 簇
//!
//! 这一条读 `/DATA.BIN` 的前 8 字节——它的内容由脚本按固定式子生成，
//! **宿主机侧（`check_nvme_fat`）用同一份式子独立重算**，两边各自算。
//!
//! ## 为什么用 `Volume::mount` 而不是 `vfs_ro::mount`
//!
//! `Volume` 是 FAT32 解析器的直接入口，它接受任意 `&dyn Block`——
//! 而 `vfs_ro::mount` 那条路是「按口号找 AHCI 盘」，绑死了设备类型。
//! 这一条要证的正是「**换一种 Block 也能挂**」。

use crate::ktest;

#[cfg(feature = "nvme")]
fn t_nvme_fat() -> bool {
    use crate::filesystem::fat32::Volume;
    use crate::filesystem::vfs::NvmeDisk;

    // **用例自足**（AGENTS.md）：`.ktests` 顺序由链接器决定，本用例可能排在
    // `t_nvme_all` **之前**。不补这一下，`NvmeDisk` 用时 `STATE` 还是 `None`
    // ⇒ 挂载报 `Io(NoDevice)`（实测就是这样红的）。`init` 是幂等的。
    if crate::nvme::reading().is_none() {
        if let Err(e) = crate::nvme::init() {
            crate::log_fatal!("nvme-fat: 判据不成立 设备初始化失败 {:?}", e);
            return false;
        }
    }
    let disk = NvmeDisk;
    let vol = match Volume::mount(&disk) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("nvme-fat: 挂载失败 {:?}（盘上没有可解析的 FAT32 卷？）", e);
            return false;
        }
    };
    // 几何读数：宿主机侧按同一份配方独立算（簇数 2048、每簇 512、数据起点 32+2*17）
    let geo_ok = vol.bpb.clusters == 2_048
        && vol.bpb.cluster_bytes == 512
        && vol.bpb.root_cluster == 2;
    crate::log_info!(
        "nvme-fat: 几何 簇数={} 数据起点={} 每簇字节={} FAT份={} 每份扇区={} 根簇={}",
        vol.bpb.clusters,
        vol.bpb.data_start,
        vol.bpb.cluster_bytes,
        vol.bpb.fat_count,
        vol.bpb.sectors_per_fat,
        vol.bpb.root_cluster
    );
    if !geo_ok {
        crate::log_fatal!("nvme-fat: 判据不成立 几何不符");
        return false;
    }

    // 读 /DATA.BIN 的前 8 字节。宿主机侧按同一式子重算这 8 个字节。
    //
    // **用 `open` + `walk`**：`Volume` 没有 `read_file`——`walk` 逐扇区回调，
    // 调用方自己累加（它带 `Walk` 返回值是为了让调用方核字节数/簇数）。
    let st = match vol.open("DATA.BIN") {
        Ok(s) => s,
        Err(e) => {
            crate::log_fatal!("nvme-fat: 判据不成立 open DATA.BIN 失败 {:?}", e);
            return false;
        }
    };
    let mut head = [0u8; 8];
    let mut filled = 0usize;
    let walked = vol.walk(&st, |chunk| {
        for &b in chunk {
        if filled < head.len() {
            head[filled] = b;
            filled += 1;
        }
        }
    });
    match walked {
        Ok(w) => {
            crate::log_info!(
                "nvme-fat: 读回 DATA.BIN 大小={} 走过字节={} 簇数={} 尾格={}",
                st.size, w.bytes, w.clusters, w.tail_bytes
            );
            // 这一行的形状是宿主机 `check_nvme_fat` 的锚点，改它要同步改那一侧。
            crate::log_info!("nvme-fat: 判据 首8={:02x?}", head);
            // 自洽：走过字节数必须等于 stat 的大小（链没走短也没走长）
            if w.bytes as u32 != st.size {
                crate::log_fatal!("nvme-fat: 判据不成立 走过 {} != stat {}", w.bytes, st.size);
                return false;
            }
            true
        }
        Err(e) => {
            crate::log_fatal!("nvme-fat: 判据不成立 walk DATA.BIN 失败 {:?}", e);
            false
        }
    }
}

#[cfg(not(feature = "nvme"))]
fn t_nvme_fat() -> bool {
    crate::log_fatal!("nvme-fat: 判据不成立 本档没开 nvme 特性");
    false
}

#[cfg(feature = "nvme")]
ktest!(KT_NVME_FAT, t_nvme_fat);
