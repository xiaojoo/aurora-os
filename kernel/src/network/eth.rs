//! 以太网帧布局（ADR-171：从 `proto.rs` 拆出）。
//!
//! 这一层只有常量与一个纯函数，**不依赖任何兄弟模块**——所以它是拆分后的根。
//! 网络协议层实现（ADR-166 决策 1 的第一刀）。
//!
//! **全部是纯函数**：吃 `&[u8]` 与几个读数，吐解析结果或 `NetError`。不碰设备、
//! 不取锁、不分配。收发由 `driver` 域的网卡驱动负责（依赖方向 `network → driver`）。
//!
//! 这一版**整块搬**而不是一次拆成 7 个文件：这些函数互相引用
//! （`build_dns_query` 用 MAC 布局、`parse_reply` 用 `ip_cksum`、
//! `arp_learn_from_frame` 用 `NET_TYPE_ARP`），一次拆 7 个要同时改几十处 `use`，
//! 出错面比收益大。**先证明「搬出去能编、判据不变」，再按文件细分**——两步分开，
//! 各自可验证。下一步的机械工作见 ADR-166 的表。


// ---- 帧布局常量（ADR-166：从 `driver/virtio.rs` 下沉到这一层）----
//
// 这 8 个是**协议概念**（帧怎么排、载荷怎么算），不属驱动层。下沉之后
// 依赖方向才是 `driver → network` 单向；之前 `network` 反过来 `use driver`
// 拿这两个常量，与 `driver` 的重导出凑成双向边 ⇒ `network` 进了环 A。
// **环消失是分类变对的结果，不是目的。**
pub const NET_TYPE: [u8; 2] = [0x88, 0xB5]; // IEEE 802 Local Experimental：不冒认任何协议
pub const NET_DST: [u8; 6] = [0xFF; 6]; // 广播：还没有邻居，也不需要邻居就能上线
pub const NET_HEAD_BYTES: usize = 6 + 6 + 2;
pub const NET_FRAME_BYTES: usize = 60; // ethernet 最小帧（64 减掉 FCS，硬件补 FCS）
pub const NET_PAYLOAD_BYTES: usize = NET_FRAME_BYTES - NET_HEAD_BYTES;
pub const NET_MUL: u32 = 11;
pub const NET_ADD: u32 = 0xA5;
pub const NET_XOR: u32 = 0x5C;

/// 一次能发的最大帧长（驱动侧也 `pub use` 它，供既有调用点保持路径不变）。
pub const NET_TX_MAX: usize = 1514;


/// 一次能发的最大帧长：一个标准 ethernet 帧（不带 FCS）的上限。
/// 帧体与三段环共用一块连续 DMA，所以这条还受"帧体之后剩下多少"限制——那条不变量写在下面
/// 的编译期断言里，不靠我每次手工量。


/// 帧内容的 FNV-1a 64 位哈希。
///
/// **为什么本域自带一份**：原先用 `crate::network::eth::frame_hash`，于是 `network`
/// 反向依赖 `driver`，与 `driver` 的重导出凑成双向边 ⇒ `network` 进了环 A
/// （ADR-168 记的取舍）。拆文件时把那两个调用点改成这里，**依赖变单向**。
///
/// 它是纯函数（`&[u8] -> u64`），放哪一层都不改变语义；放在 `eth` 是因为
/// 唯一的使用者是帧对账。
pub fn frame_hash(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &x in b {
        h ^= u64::from(x);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}
