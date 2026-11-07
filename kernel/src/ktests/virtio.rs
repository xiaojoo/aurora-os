//! virtio-blk 与 MSI-X 用例（T0.1 纯搬移）。

use crate::{ahci, virtio};
use crate::ktest;

/// KT_VIRTIO_MSIX：virtio 的 MSI-X 表条目一格。读数全来自设备回读，不来自我以为的偏移。
#[cfg(feature = "virtio-msix-probe")]
fn t_virtio_msix() -> bool {
    if let Err(e) = virtio::bind() {
        crate::log_fatal!("virtio-msix: 设备没绑上 {:?}", e);
        return false;
    }
    let p = match virtio::msix_probe() {
        Ok(p) => p,
        Err(e) => {
            crate::log_fatal!("virtio-msix: 编程一轮没跑起来 {:?}", e);
            return false;
        }
    };
    // ① 能力形状：条数与 BIR 对上 M5-g① 那次取证。**表偏移不当常数判**——
    //    它是设备的数，而"它到底落在哪一段"由第 ③⑦ 格的"写下去读得回来"判：
    //    上一轮我把 PBA 的偏移(0x800)当成表偏移记进了台账，就是因为这里没有写读对账。
    let caps_ok = p.table_size == 5 && p.bir == 1;
    let mask_all_ok = p.masked_all == p.table_size;
    let words_ok = p.back[0] == p.want[0] && p.back[1] == p.want[1] && p.back[2] == p.want[2]
        && p.back[3] == 0;
    let unmask_ok = p.fn_mask_off && p.masked_rest == p.table_size - 1;
    let handed_ok = p.qvector_back == p.entry as u16;
    // 到过的每一发都必须被认领——不等就是归属判断在骗人
    let claim_ok = p.claims == p.calls;
    let wake_ok = p.flag_seen == (p.calls > 0);
    let remask_ok = p.re_masked == p.table_size;
    crate::log_info!(
        "virtio-msix: 判据 表条数={} BIR={} 表偏移={:#x} 能力头={:#x} 向量={:#x} 条目={} \
         全遮读回={}/{} 写=({:#010x},{:#010x},{:#010x}) 读回=({:#010x},{:#010x},{:#010x},{:#010x}) \
         功能遮={} 解除后仍遮={}/{} 交队列读回={:#x} 到过={} 认领={} 旗子={} 撤销后重遮={}/{} \
         读盘={} 等了={} 轮 ⇒ 能力对={} 全遮={} 逐字={} 解除={} 交队列={} 认领一致={} 叫醒一致={} 重遮={}",
        p.table_size,
        p.bir,
        p.table_off,
        p.cap_off,
        p.vector,
        p.entry,
        p.masked_all,
        p.table_size,
        p.want[0],
        p.want[1],
        p.want[2],
        p.back[0],
        p.back[1],
        p.back[2],
        p.back[3],
        p.fn_mask_off,
        p.masked_rest,
        p.table_size,
        p.qvector_back,
        p.calls,
        p.claims,
        p.flag_seen,
        p.re_masked,
        p.table_size,
        p.content_ok,
        p.waited,
        caps_ok,
        mask_all_ok,
        words_ok,
        unmask_ok,
        handed_ok,
        claim_ok,
        wake_ok,
        remask_ok
    );
    let ok = caps_ok && mask_all_ok && words_ok && unmask_ok && handed_ok && claim_ok && wake_ok
        && remask_ok && p.content_ok;
    if !ok {
        crate::log_fatal!("virtio-msix: 判据不成立（上面一行是设备自己读回来的数）");
    }
    ok
}
#[cfg(feature = "virtio-msix-probe")]
ktest!(KT_VIRTIO_MSIX, t_virtio_msix);

#[cfg(feature = "virtio-blk")]
/// M5-f①：virtio-blk 的现场取证（不建环、不发 I/O）。十格判据，每格都是"偏移的证人"，
/// 形状与 ADR-029 的端口寄存器表同一套：
/// 1 vendor 必须是 `0x1AF4`，能力链里 COMMON/NOTIFY/ISR/DEVICE 四条都要在（找不到 COMMON
///   就是 legacy 呈现，整个 modern 布局的前提不成立）
/// 2 `device_feature_select`(0x00) 与 `device_feature`(0x04) 是一对：换选页读数必须跟着变、
///   同页连读两次必须相同（只读）、选页越界必须读回 0
/// 3 `df1` 的 bit0（= `VIRTIO_F_VERSION_1`，位 32）必须置起来：modern 设备不提供它就说明
///   我对"这台设备是 modern"的理解是错的
/// 4 `device_status` 是 0x14 那**一个字节**：写 `ACK|DRIVER` 读回要等于它，0x10 那个 dword
///   与 0x15 的 `config_generation` 都不能被这次字节写改动
/// 5 写 0 复位之后 `device_status` 必须读回 0
/// 6 **字段各有宽度**：`read32(0x10)` 的高半在这台设备上读回 0，而 `read16(0x12)` 的
///   `num_queues` 非 0 ⇒ "读宽了会把隔壁那半丢成 0"是设备的实际行为，钉成判据
/// 7 `queue_select`(0x16) 真的是选择器：写 0/1 读回 0/1、写越界的 `0xFFFF` 被忽略（读回还是 1）、
///   写 `num_queues` 读回 `num_queues`，而只读的 `queue_notify_off`(0x1e) 跟着选择器 +1
/// 8 `queue_size` 必须是 2 的幂且非 0，选了"合法但没配出来"的索引必须读回 0
/// 9 ISR 那条能力指向的字节在复位后必须读回 0（读不到就说明 ISR 的偏移/宽度不对）
/// 10 `num_queues` 与容量必须非 0；容量的绝对对账在宿主机那侧做（`qemu-img` 知道这块文件多大）
fn t_virtio_probe() -> bool {
    let r = match virtio::probe() {
        Ok(r) => r,
        Err(e) => {
            crate::log_fatal!("virtio: 取证失败 {:?}", e);
            return false;
        }
    };
    let has = |t: u8| -> bool {
        r.caps[..usize::from(r.n_caps)].iter().any(|c| c.cfg_type == t)
    };
    for i in 0..usize::from(r.n_caps) {
        let c = r.caps[i];
        crate::log_info!(
            "virtio: 能力 cfg_type={} bar={} offset={:#06x} length={:#06x} notify_mult={}",
            c.cfg_type,
            c.bar,
            c.offset,
            c.length,
            c.notify_mult
        );
    }
    let found = r.vendor == virtio::VENDOR && r.n_caps >= 4;
    let four_caps =
        has(virtio::CAP_COMMON_CFG) && has(virtio::CAP_NOTIFY_CFG) && has(virtio::CAP_ISR_CFG) && has(virtio::CAP_DEVICE_CFG);
    let select_pair = r.df0 != r.df1 && r.df0 == r.df0_again && r.df_bad_select == 0;
    let version1 = r.df1 & 1 != 0;
    let status_byte = r.status_after_set == virtio::ACKNOWLEDGE | virtio::DRIVER
        && (r.dword_10_before as u16) == r.msix_config
        && r.dword_10_before == r.dword_10_after
        && r.cfg_gen_after == r.cfg_gen_before;
    let reset_ok = r.status_after_reset == 0;
    // 越宽读的那一格必须**丢掉**隔壁：`read32(0x10)` 的高半读回 0，而 `read16(0x12)` 非 0。
    // 这一条把"字段各有宽度"钉成判据，而不是写在注释里的规矩
    let width_witness = r.num_queues != 0 && (r.dword_10_before >> 16) as u16 == 0;
    // 选择器：写进去要读得回来；越界的 `0xFFFF` 必须被忽略（读回还是 1）；
    // 换选择器时只读的 `queue_notify_off` 要跟着 +1 ⇒ 0x16/0x18/0x1e 三格的关系一起钉住
    let selector = r.sel0_back == 0
        && r.sel1_back == 1
        && r.sel_ffff_back == 1
        && r.sel_beyond_back == r.num_queues
        && r.noff_q1 == r.noff_q0 + 1;
    let queue_size_ok = r.q0_size != 0 && r.q0_size.is_power_of_two() && r.q_beyond_size == 0;
    let isr_ok = r.isr_after_reset == 0;
    let shape_ok = r.num_queues != 0 && r.capacity != 0;
    crate::log_info!(
        "virtio: 设备 bdf={:#010x} vend={:#06x} dev={:#06x} 三件套={:#02x}/{:#02x}/{:#02x} rev={:#02x} BAR尺寸={} modern_id={}",
        r.bdf,
        r.vendor,
        r.device,
        r.class,
        r.subclass,
        r.progif,
        r.rev,
        r.bar_size,
        virtio::is_modern_id(r.device)
    );
    crate::log_info!(
        "virtio: 特征页0={:#010x} 页1={:#010x} 越界选页读回={:#010x} 队列数={} msix={:#06x} 配置代={}→{}",
        r.df0,
        r.df1,
        r.df_bad_select,
        r.num_queues,
        r.msix_config,
        r.cfg_gen_before,
        r.cfg_gen_after
    );
    crate::log_info!(
        "virtio: 状态写后读回={:#04x} 复位后={:#04x} 超宽读0x10={:#010x} 按宽度读 msix={:#06x} 队列数={}",
        r.status_after_set,
        r.status_after_reset,
        r.dword_10_before,
        r.msix_config,
        r.num_queues
    );
    crate::log_info!(
        "virtio: 选择器读回={}/{}/{}(越界写0xFFFF) 队列数索引读回={} 尺寸 q0={} q1={} 越界={} notify_off {}→{} ISR={:#04x} 容量扇区={} mult={}",
        r.sel0_back,
        r.sel1_back,
        r.sel_ffff_back,
        r.sel_beyond_back,
        r.q0_size,
        r.q1_size,
        r.q_beyond_size,
        r.noff_q0,
        r.noff_q1,
        r.isr_after_reset,
        r.capacity,
        r.notify_mult
    );
    let ok = found
        && four_caps
        && select_pair
        && version1
        && status_byte
        && reset_ok
        && width_witness
        && selector
        && queue_size_ok
        && isr_ok
        && shape_ok;
    crate::log_info!(
        "virtio: 取证判据 设备与能力链={}/{} 选页对={} VERSION_1={} 状态字节={} 复位={} 宽度={} 选择器={} 队列尺寸={} ISR={} 形状={}",
        found,
        four_caps,
        select_pair,
        version1,
        status_byte,
        reset_ok,
        width_witness,
        selector,
        queue_size_ok,
        isr_ok,
        shape_ok
    );
    if !ok {
        crate::log_fatal!("virtio: 取证判据不成立（上面五行是全部读数）");
    }
    ok
}
#[cfg(feature = "virtio-blk")]
ktest!(KT_VIRTIO_PROBE, t_virtio_probe);

/// M5-f②：virtqueue 建起来之后第一条真 I/O。判据八格：
/// 1 `bind()` 的握手全过，且 `queue_enable` 写 1 读回 1
/// 2 队列地址那三格**设备到底回不回读**——回读一致就当判据，不回读就只能打出来当事实、
///    改用"后续 I/O 成功"当行为证据（这一格不许把"没测到"写成"测到了"）
/// 3 读扇区 0：整扇区 512 字节都等于宿主机写进夹具的那个图案字节
///    （图案值两边各写一份 ⇒ `check-virtio-pattern` 那道门禁逐字对账）
/// 4 读回来的不是哨兵：证明"设备真的搬了数据"，不是缓冲里留着自己的 `0xEE`
/// 5 位置敏感：读扇区 1 的哈希必须与扇区 0 不同（防"读到的是上一次留在缓冲里的"）
/// 6 回执三格：`used.id` 是我们挂的链头 0、`used.len == 513`（数据 512 + 状态 1）、状态字节 = `S_OK`
/// 7 写方向：把与 LBA 绑定的图案写进扇区 8，再读回来逐字节一致（哈希相同）
/// 8 两台控制器互不牵连：这一路做完之后再走一遍 AHCI 的引导盘读，仍要成功
#[cfg(feature = "virtio-blk")]
fn t_virtio_io() -> bool {
    const EXPECT_PATTERN: u8 = 0x5C; // 必须与 tools/aurora.py 的 VBLK_PATTERN 同数（check-virtio-pattern 对账）
    if let Err(e) = virtio::bind() {
        crate::log_fatal!("vq: 绑定/握手失败 {:?}", e);
        return false;
    }
    let (qsize, capacity, notify, mult, addr_back, enable_back) = match virtio::status() {
        Some(v) => v,
        None => {
            crate::log_fatal!("vq: 绑定之后拿不到读数");
            return false;
        }
    };
    let mut zero = [0u8; 512];
    let r0 = match virtio::read_block(0, &mut zero) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("vq: 读扇区 0 失败 {:?}", e);
            return false;
        }
    };
    let pattern_ok = zero.iter().all(|b| *b == EXPECT_PATTERN);
    let not_sentinel = r0.hash != ahci::fnv1a64(&[0xEEu8; 512]);
    let mut one = [0u8; 512];
    let r1 = match virtio::read_block(1, &mut one) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("vq: 读扇区 1 失败 {:?}", e);
            return false;
        }
    };
    let position_dependent = r1.hash != r0.hash;
    let receipt_ok = r0.used_id == 0 && r0.used_len == 513 && r0.status == 0;
    // 写方向：图案与 LBA 绑定，所以"没写"、"写到别处"、"只写了一半"三种错法都过不了回读
    let mut src = [0u8; 512];
    for i in 0..512usize {
        src[i] = ahci::pattern_byte(8, i as u64);
    }
    let want_hash = ahci::fnv1a64(&src);
    if let Err(e) = virtio::write_block(8, &src) {
        crate::log_fatal!("vq: 写扇区 8 失败 {:?}", e);
        return false;
    }
    let mut back = [0u8; 512];
    let rw = match virtio::read_block(8, &mut back) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("vq: 写完回读失败 {:?}", e);
            return false;
        }
    };
    let write_ok = rw.hash == want_hash && ahci::data_head(8).map(|h| &h[0..8] == b"EFI PART").unwrap_or(false) == false;
    // 两台控制器互不牵连：走完 virtio 之后再读一次引导盘的分区头
    let ahci_still_ok = ahci::read_lba(ahci::boot_port().unwrap_or(0), 1, 1).is_ok()
        && ahci::data_head(8).map(|h| &h[0..8] == b"EFI PART").unwrap_or(false);
    crate::log_info!(
        "vq: 判据 enable读回={} 地址回读={:?} 队列深={} 容量={} notify={:#x}×{} | 扇区0图案={} 非哨兵={} 位置敏感={} 回执={}/{}/{} 写完回读={} AHCI照常={}",
        enable_back == 1,
        addr_back,
        qsize,
        capacity,
        notify,
        mult,
        pattern_ok,
        not_sentinel,
        position_dependent,
        r0.used_id,
        r0.used_len,
        r0.status,
        write_ok,
        ahci_still_ok
    );
    crate::log_info!(
        "vq: 取证 扇区0哈希={:#018x} 扇区1哈希={:#018x} 扇区8写后哈希={:#018x} 期望写值哈希={:#018x} used前后进过=({},{})",
        r0.hash,
        r1.hash,
        rw.hash,
        want_hash,
        r0.avail_idx,
        r0.used_idx
    );
    let ok = enable_back == 1 && pattern_ok && not_sentinel && position_dependent && receipt_ok
        && write_ok && ahci_still_ok && capacity > 0;
    if !ok {
        crate::log_fatal!("vq: virtqueue 判据不成立（上面两行是全部读数）");
    }
    ok
}
#[cfg(feature = "virtio-blk")]
ktest!(KT_VIRTIO_IO, t_virtio_io);

