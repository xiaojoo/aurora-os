//! virtio-net 收发与 pcap 对账用例（T0.1 纯搬移）。

use crate::{ahci, virtio};
use crate::ktest;

/// M8-a①：第一帧从 virtio-net 出去。判据八格（帧的**内容**由宿主机的 pcap 判，见矩阵第 23 行；
/// 这一格只判内核自己知道的事）：
/// 1 TX 队列（编号 1）使能写 1 读回 1，且队列深由设备给的非 0 数
/// 2 这台设备是"有收发两扇门"的网卡：`num_queues >= 2` 且 RX 与 TX 的 `queue_notify_off` 不同。
///    （不用 PCI device id 当身份：本机 QEMU 给 transitional 网卡的是 `0x1000`，按规范的
///    `0x1000+类型` 解出来是 0 而不是 1 —— 那一格改成只打印，实测记 BACKLOG 58）
/// 3 配置空间里的 MAC 是个"能用的地址"：不全 0、不全 FF、首字节的组播位为 0
/// 4 两个宽度证人：MAC 逐字节 == `dword(0)+word(4)` 拼出来的；`max_pairs`/`mtu` 是一个 dword 的两半。
///    第二格是 `Option`：本机不接受任何特性时设备只给 8 字节配置（legacy 形状），
///    第 8..12 字节读回全 0xFF —— 那是"这一格不存在"，取 `None` 打印，不许用 `0xFF==0xFF` 充当 `true`
/// 5 第一帧有回执：`used.idx` 比它自己那次发布的 `avail.idx` 大 1，`used.id` 是链头 0，长度是整帧 60
/// 6 第二帧的回执紧接在第一帧之后（再 +1）且**内容不同**（图案里带了序号）—— 只发得出一次不算队列能用
///    （5、6 都按增量判：绝对 `used.idx` 会把"别的用例先敲过这扇门"读成故障，见代码里那条注释）
/// 7 回执之后从 DMA 再读那 60 字节哈希不变：TX 方向设备只许读，改了就是环与帧的地址摆重了
/// 8 走完网卡之后 AHCI 那条读仍成功：两台控制器互不牵连（与块设备那条同一格）
#[cfg(feature = "virtio-net")]
fn t_net_tx() -> bool {
    if let Err(e) = virtio::bind_net() {
        crate::log_fatal!("net: 绑定/握手失败 {:?}", e);
        return false;
    }
    let i = match virtio::net_info() {
        Some(v) => v,
        None => {
            crate::log_fatal!("net: 绑定之后拿不到读数");
            return false;
        }
    };
    let q_ok = i.enable_readback == 1 && i.qsize > 0;
    let nic_shape = i.num_queues >= 2 && i.noff_rx != i.noff_tx;
    let mac_shape = i.mac != [0u8; 6]
        && i.mac != [0xFF; 6]
        && i.mac[0] & 0x01 == 0;
    let width_ok = i.mac_width_ok && i.pairs_width_ok != Some(false);
    let f1 = match virtio::send_frame(1) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("net: 第一帧失败 {:?}", e);
            return false;
        }
    };
    let f2 = match virtio::send_frame(2) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("net: 第二帧失败 {:?}", e);
            return false;
        }
    };
    // 两格都按**增量**判：`used.idx` 的绝对值取决于别的用例有没有先敲过这扇门
    // （`.ktests` 的顺序由链接器决定，判据不许依赖用例先后——这条本轮又撞了一次：
    //   `KT_NET_RX` 先发了一次 DISCOVER，写成"必须等于 1/2"的绝对判据就当场红了）
    let tx1_ok = f1.used_id == 0
        && f1.len == virtio::NET_FRAME_BYTES
        && f1.used_idx == f1.avail_idx.wrapping_add(1);
    let tx2_ok = f2.used_idx == f1.used_idx.wrapping_add(1) && f2.hash != f1.hash;
    let untouched_ok = f1.hash_after == f1.hash && f2.hash_after == f2.hash;
    let ahci_still_ok = ahci::read_lba(ahci::boot_port().unwrap_or(0), 1, 1).is_ok();
    crate::log_info!(
        "net: 判据 enable读回={} 队列深={} 网卡形状={} MAC形状={} 宽度证人={}/{:?} 帧1={}/{}/{} 帧2={} 字节没动={} AHCI照常={}",
        i.enable_readback,
        i.qsize,
        nic_shape,
        mac_shape,
        i.mac_width_ok,
        i.pairs_width_ok,
        f1.used_idx,
        f1.used_id,
        f1.len,
        f2.used_idx,
        untouched_ok,
        ahci_still_ok
    );
    crate::log_info!(
        "net: 取证 bdf={:#010x} 设备id={:#06x} 解出类型={}(网卡={}) class={:#04x} 队列数={} 门={:#x}×{} 门位rx/tx={}/{} 地址回读={:?} 配置长={} mtu={} 队列对={} 链路={:#06x} 特性页0={:#010x} 有MAC位={}",
        i.bdf,
        i.device_id,
        virtio::dev_type(i.device_id),
        virtio::VIRTIO_ID_NET,
        i.class,
        i.num_queues,
        i.notify,
        i.notify_mult,
        i.noff_rx,
        i.noff_tx,
        i.addr_readback,
        i.cfg_len,
        i.mtu,
        i.max_pairs,
        i.link,
        i.df0,
        i.df0 & (1 << virtio::F_NET_MAC) != 0
    );
    crate::log_info!(
        "net: 配置原始 {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x}",
        i.cfg_raw[0], i.cfg_raw[1], i.cfg_raw[2], i.cfg_raw[3],
        i.cfg_raw[4], i.cfg_raw[5], i.cfg_raw[6], i.cfg_raw[7],
        i.cfg_raw[8], i.cfg_raw[9], i.cfg_raw[10], i.cfg_raw[11],
        i.cfg_raw[12], i.cfg_raw[13], i.cfg_raw[14], i.cfg_raw[15]
    );
    for f in [f1, f2] {
        crate::log_info!(
            "net: 帧 序号={} 长={} 哈希={:#018x} 源MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} 回执长={} 发后哈希={:#018x} avail/used=({},{})",
            f.seq,
            f.len,
            f.hash,
            i.mac[0],
            i.mac[1],
            i.mac[2],
            i.mac[3],
            i.mac[4],
            i.mac[5],
            f.used_len,
            f.hash_after,
            f.avail_idx,
            f.used_idx
        );
    }
    let ok = q_ok && nic_shape && mac_shape && width_ok && tx1_ok && tx2_ok && untouched_ok && ahci_still_ok;
    if !ok {
        crate::log_fatal!("net: 第一帧判据不成立（上面几行是全部读数）");
    }
    ok
}
#[cfg(feature = "virtio-net")]
ktest!(KT_NET_TX, t_net_tx);

/// M8-a②：第一次真协议往返（对端 = QEMU 的用户网络里那个 DHCP 服务器）。判据七格：
/// 1 RX 队列也建起来了：`queue_enable` 写 1 读回 1、队列深非 0、且 RX 与 TX 的门位不是同一个
/// 2 DISCOVER 发出去有回执（TX 那条路仍然通）
/// 3 收到一包：RX 的 `used.idx` 在有界等待之内前进（等不到就是 `UsedTimeout`，当场红）
/// 4 那一包解得开：ethertype 0x0800、IPv4 协议号 17、BOOTP `op=2`、选项 53 是 OFFER 或 ACK
/// 5 `xid` 等于我们发出去的那一个 —— 回话必须是答**这一次**请求的，不是答上一次启动留下的
/// 6 `yiaddr` 等于夹具里 `dhcpstart=` 那一个数（内核从线上读出来的地址，与宿主机自己配的对照）
/// 7 `used.id` 等于我们挂的那条链（今天只挂一条 ⇒ 只许是 0）：写错缓冲就是下一个包覆盖我
///    帧字节本身由第二台仪器判：矩阵第 24 行拿 pcap 里那条 inbound 包重算同一个哈希
#[cfg(feature = "virtio-net")]
fn t_net_rx() -> bool {
    if let Err(e) = virtio::bind_net() {
        crate::log_fatal!("rx: 绑定/握手失败 {:?}", e);
        return false;
    }
    let i = match virtio::net_info() {
        Some(v) => v,
        None => {
            crate::log_fatal!("rx: 绑定之后拿不到读数");
            return false;
        }
    };
    let q_ok = i.rx_enable_readback == 1 && i.rx_qsize > 0 && i.noff_rx != i.noff_tx;
    let (frame, want_hash) = virtio::build_dhcp_discover(&i.mac);
    match virtio::send_raw(&frame) {
        Ok(f) => crate::log_info!(
            "rx: 发 DISCOVER 长={} 哈希={:#018x} 自算={:#018x} 回执idx={} id={}",
            f.len,
            f.hash,
            want_hash,
            f.used_idx,
            f.used_id
        ),
        Err(e) => {
            crate::log_fatal!("rx: DISCOVER 发不出去 {:?}", e);
            return false;
        }
    }
    let (buf, n, used_idx, used_len, used_id) = match virtio::receive(3000) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("rx: 有界等待之内没等到回话 {:?}", e);
            return false;
        }
    };
    let r = match virtio::parse_reply(&buf[..n], used_idx, used_len, used_id) {
        Ok(v) => v,
        Err(e) => {
            crate::log_fatal!("rx: 收到的那包解不开（长 {}）{:?} 前十六字节={:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x}",
                n, e, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
                buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
            return false;
        }
    };
    let parsed_ok = r.op == virtio::BOOTREPLY
        && (r.msg_type == virtio::DHCP_OFFER || r.msg_type == virtio::DHCP_ACK)
        && r.ethertype == virtio::NET_TYPE_IPV4;
    let xid_ok = r.xid == virtio::DHCP_XID;
    let ip_ok = r.yiaddr == virtio::DHCP_GUEST_IP;
    // 设备写回来的必须是**我们挂上去的那一条链**：今天只挂一条，所以合法 id 只有 0。
    // 这一格是"内存安全"那一侧的：写错缓冲就是别人（下一个包）覆盖我
    let id_ok = r.used_id == 0;
    crate::log_info!(
        "rx: 收到 长={} 哈希={:#018x} 类型={:#06x} op={} 消息={} xid={:#010x} yiaddr={}.{}.{}.{} used.idx={} 设备写={} used.id={}",
        r.len,
        r.hash,
        u16::from(r.ethertype[0]) << 8 | u16::from(r.ethertype[1]),
        r.op,
        r.msg_type,
        r.xid,
        r.yiaddr[0],
        r.yiaddr[1],
        r.yiaddr[2],
        r.yiaddr[3],
        r.used_idx,
        r.used_len,
        r.used_id
    );
    crate::log_info!(
        "rx: 判据 RX队列={} 解得开={} xid对={} 地址对={} 缓冲对={} RX门={:#x} 门位rx/tx={}/{} RX地址回读={:?}",
        q_ok,
        parsed_ok,
        xid_ok,
        ip_ok,
        id_ok,
        i.rx_notify,
        i.noff_rx,
        i.noff_tx,
        i.rx_addr_readback
    );
    // 第 2、3 格（发出去、收到包）是提前退出：任何一条失败就已经 `return false`
    let ok = q_ok && parsed_ok && xid_ok && ip_ok && id_ok;
    if !ok {
        crate::log_fatal!("rx: 第一条协议往返判据不成立（上面三行是全部读数）");
    }
    ok
}
#[cfg(feature = "virtio-net")]
ktest!(KT_NET_RX, t_net_rx);

