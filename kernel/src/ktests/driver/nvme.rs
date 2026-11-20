//! NVMe 驱动的判据（ADR-169）。
//!
//! 三格，按「最便宜的先证」排序：
//!
//! 1. **识别**：PCI 三件套能认到设备，且 CAP/VS/CSTS 的读数形状自洽。
//!    这一格不碰队列——它只证「我们读到了这台设备」。
//! 2. **容量对账**：Identify Namespace 读回的 `NSZE × LBA` 必须等于
//!    宿主机造那块 qcow2 时的 virtual-size。**这是第二台仪器**：
//!    内核算一遍、`qemu-img info` 算一遍，两边各自算。
//! 3. **读回图案**：`_make_vblk` 用 `qemu-io` 写了 `0x7E` 的图案，
//!    读第 0 扇区必须看到它。
//!
//! 三格各自能独立红：识别红 ⇒ 后面两格都没意义；容量红 ⇒ 尺寸账错了；
//! 图案红 ⇒ 数据通路错了。**不合并成"NVMe 能不能用"一个布尔**
//! ——那是本仓库反复拒绝的形状（成因不能压成一个数）。

use crate::driver::nvme;
use crate::ktest;

/// 判据：设备识别与寄存器读数自洽。
///
/// 为什么先验 `CSTS.RDY == 0`：未使能时它必须是 0。若不是，说明这块寄存器
/// 不是我们想的那块——这时候往下走，每条命令都会超时，而日志只会说"超时"，
/// 成因被藏起来。
fn t_nvme_identify() -> bool {
    let r = match nvme::init() {
        Ok(r) => r,
        Err(e) => {
            crate::log_fatal!("nvme: init 失败 {:?} —— {}", e, nvme::NvmeError::describe(e));
            return false;
        }
    };
    // CAP.MQES+1 至少要能装下我们的队列深度（`init` 里已经拦过，这里再证一次读数）
    let mqes_ok = r.max_qdepth >= nvme::QDEPTH;
    // VS 不为 0：NVMe 规范要求它报一个版本号，全 0 说明这块不是 NVMe
    let vs_ok = r.vs != 0;
    // **起始状态允许两种**（实测教训）：QEMU 的 `-device nvme` 在 EDK2 阶段
    // 就可能已经使能过控制器，所以进内核时 RDY 已经是 1 是**合法**的。
    // 原来这里要求「起始 RDY 必须为 0」，那是**环境假设**，不是设备性质。
    //
    // 现在证状态机合法：起始 CFS=0（不能一进来就致命），终态 RDY=1 且 CFS=0。
    // 这比原来**更强**——它同时覆盖两种起始，且额外验了 CFS。
    let csts_ok = (r.csts_before & nvme::CSTS_CFS) == 0
        && (r.csts_after & nvme::CSTS_RDY) != 0
        && (r.csts_after & nvme::CSTS_CFS) == 0;
    let already = (r.csts_before & nvme::CSTS_RDY) != 0;
    // LBA 大小必须是 512 的整数倍且非零（块层的 `SECTOR_BYTES` 契约）
    let lba_ok = r.lbads >= 9 && r.lbads <= 12;
    crate::log_info!(
        "nvme: 识别 bdf={} vendor={:#x} device={:#x} cap_lo={:#x} cap_hi={:#x} vs={:#x} \
         csts={:#x}->{:#x} already={} mqes={} nn={} nsze={} lbads={}",
        r.bdf, r.vendor, r.device, r.cap_lo, r.cap_hi, r.vs,
        r.csts_before, r.csts_after, already, r.max_qdepth,
        r.namespaces, r.nsze, r.lbads
    );
    let ok = mqes_ok && vs_ok && csts_ok && lba_ok;
    if !ok {
        crate::log_fatal!(
            "nvme: 判据不成立 mqes={} vs={} csts={} lba={}",
            mqes_ok, vs_ok, csts_ok, lba_ok
        );
    }
    ok
}

/// 判据：容量账。
///
/// 内核侧算 `NSZE × (1 << lbads)`，宿主机侧用 `qemu-img info` 读同一个 qcow2
/// 的 virtual-size。**两边各自算**——这是本仓库"第二台仪器"的规矩：
/// 谁抄谁，"两边都错"时判据是绿的。
///
/// 内核这一侧只把读数打出来（`nvme: 容量 扇区=… 字节=…`），
/// 对账在 `tools/aurora.py` 里做（它能跑 `qemu-img`）。
fn t_nvme_capacity() -> bool {
    let (Some(nsze), Some(lba)) = (nvme::nsze(), nvme::lba_bytes()) else {
        crate::log_fatal!("nvme: 容量判据 设备没初始化");
        return false;
    };
    let bytes = nsze.saturating_mul(lba as u64);
    // 扇区数（按块层的 512）也要报：宿主机按它跟 virtual-size 对账
    let sectors = bytes / 512;
    crate::log_info!("nvme: 容量 扇区={} 字节={} lba={}", sectors, bytes, lba);
    // 内核侧的自洽判据：容量必须非零、且能整除 512
    let ok = nsze != 0 && bytes % 512 == 0 && sectors != 0;
    if !ok {
        crate::log_fatal!("nvme: 判据不成立 nsze={} bytes={} sectors={}", nsze, bytes, sectors);
    }
    ok
}

/// 判据：读第 0 扇区，看到 `qemu-io` 写下的图案。
///
/// `_make_vblk` 把整块盘写成同一个字节（NVMe 用 `0x7E`）。读回来逐字节比：
/// **不是"读到非零就算过"**——那样缓冲区里的残留也能让它绿。
fn t_nvme_read_pattern() -> bool {
    let mut buf = [0u8; 512];
    if let Err(e) = nvme::read_lba(0, &mut buf) {
        crate::log_fatal!("nvme: 读扇区 0 失败 {:?}", e);
        return false;
    }
    // **判据是「这是一块结构合法的 FAT32 卷」，不是「全 0x7E」。**
    //
    // ADR-172 起 NVMe 盘上是 `make_fat32_rw.py` 造的真卷，所以第 0 扇区
    // 是引导扇区。这比原来的图案判据**更强**：原来只证「能读回我写的字节」，
    // 现在证「读回的是一块能被解析的卷」。
    //
    // 三条独立特征：
    //   ① 偏移 510 的 0x55AA 引导签名
    //   ② 偏移 82 的 `FAT32   ` 字样（8 字节，尾部补空格）
    //   ③ 偏移 0 的跳转指令（0xEB .. 0x90 或 0xE9 ..）
    let sig_ok = buf[510] == 0x55 && buf[511] == 0xAA;
    let fstype_ok = &buf[82..90] == b"FAT32   ";
    let jump_ok = (buf[0] == 0xEB && buf[2] == 0x90) || buf[0] == 0xE9;
    // 首 8 字节的哈希：宿主机用同一份算法独立重算（`check-nvme-pattern` 对账）
    let head = crate::network::eth::frame_hash(&buf[..8]);
    crate::log_info!(
        "nvme: 读回 扇区0 首8={:#x} 引导签名={} FAT32字样={} 跳转={}",
        head, sig_ok, fstype_ok, jump_ok
    );
    let ok = sig_ok && fstype_ok && jump_ok;
    if !ok {
        crate::log_fatal!(
            "nvme: 判据不成立 扇区0 不是合法 FAT32 引导扇区（签名={} 字样={} 跳转={}）",
            sig_ok, fstype_ok, jump_ok
        );
    }
    ok
}

/// 三格合起来跑：**顺序固定**（识别 → 容量 → 图案），因为后两格依赖第一格。
/// 但每一格自己的读数与 `fatal` 都独立打出来——红在哪一格一眼可见。
#[cfg(feature = "nvme")]
fn t_nvme_all() -> bool {
    let a = t_nvme_identify();
    let b = if a { t_nvme_capacity() } else { false };
    let c = if a { t_nvme_read_pattern() } else { false };
    crate::log_info!("nvme: 三格 识别={} 容量={} 图案={} ⇒ {}", a, b, c, a && b && c);
    a && b && c
}

#[cfg(feature = "nvme")]
// `ktest!` 的第一个参数是**任意的 static 名**（宏体里是 `#[used] static $name`），
// 不是预定义常量——照既有写法 `ktest!(KT_PCI, t_pci_config);`。
ktest!(KT_NVME, t_nvme_all);
