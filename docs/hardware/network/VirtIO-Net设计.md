# VirtIO-Net 设计

状态：**已实施**（收发与协议已通；中断未做）

- 代码：`kernel/src/driver/virtio.rs`（网络部分）
- 特性门控：`virtio-net`（默认构建不编；QEMU 命令行按特性加设备）
- 相关 ADR：`ADR-032`（第一帧由宿主机抓包判）、`ADR-139`–`ADR-147`、
  `ADR-112`（virtio 设备表化）、`ADR-158`（DNS 名字参数化）
- 上位：[网卡驱动设计](网卡驱动设计.md)

---

## 1. 队列布局（实测常量）

```rust
pub const NET_QUEUE_RX: u16 = 0;     // 接收
pub const NET_QUEUE_TX: u16 = 1;     // 发送
pub const NET_HDR_BYTES: usize = 10; // virtio_net_hdr（无 mergeable，无 GSO）
pub const NET_HDR_ROOM: usize = 16;  // 描述符里给头的空间
pub const RX_MAX_BYTES: usize = 1514;// 以太网 MTU 1500 + 14
pub const NET_TX_MAX: usize = 1514;
```

**`NET_HDR_ROOM=16` 与 `NET_HDR_BYTES=10` 不是冗余**：设备写 `used.len` 时
按它自己的头长算，而驱动给的描述符空间要留余量。判据里两个都用到。

---

## 2. 接收路径（`receive`）

### 2.1 形状

```text
1. dma_fill(rx_dma, O_RDATA, 0xEE, RX_MAX_BYTES)   ← 先填哨兵
2. put_desc 两个描述符：头（可写）+ 数据（可写）
3. 取 avail.idx，写进 ring，avail.idx += 1
4. notify（RX 队列）
5. wait_u16 等 used.idx 前进（有界，wait_ms）
6. 读 used.id（描述符头）与 used.len
7. 验上下界：used.len <= NET_HDR_BYTES ⇒ BadLen
              n = (used.len - NET_HDR_BYTES).min(RX_MAX_BYTES)
8. dma_copy_out 到调用方栈上数组
```

### 2.2 三个刻意的决定（源码注释原文 + 本文的补充）

1. **先填哨兵 `0xEE`**：那样"设备没写"与"写了一堆 0"才分得开。
   **这是判据的一部分**，不是调试残留。
2. **`used.len` 的上下界都要验**：源码注释引 §10.3「线上的数不能直接当界用」。
   下界（连头都不够）说明设备没按我们给的布局写；上界（超缓冲）是防越界读。
3. **`RX_USED_SEEN` 是模块静态量**：跨调用记住"上次看到哪"。这是
   **单设备单消费者的假设**——多队列时这个设计必须改。

---

## 3. 发送路径（`send_frame` / `send_raw`）

```text
build_frame(seq, mac)  → 60 字节最小帧（NET_FRAME_BYTES）
  头部 14 字节：dst(6) + src(6) + type(2, = 0x88B5)
  载荷 46 字节：字节 j 由 net_payload_byte(j, seq) 算出
                （NET_MUL=11 / NET_ADD=0xA5 / NET_XOR=0x5C 的算术）
send_raw(frame)        → 填描述符、notify TX、有界等 used.idx
```

**为什么载荷是算术而不是随机**（源码注释）：宿主机要能**独立重算**同一串字节
（`aurora.py` 的 `build_net_frame` 是第二台实现）。随机字节无法对账。

**`NET_TYPE = [0x88, 0xB5]`**（IEEE 802 Local Experimental）：**不冒认任何协议**。
这条很重要——用一个真实 ethertype 会让"我们发的包"和"真协议包"混在一起，
而宿主机抓包时就分不开。

---

## 4. 判据（已有，逐条说清"证了什么"）

### 4.1 第一帧（判定表第 32 行）

| 内核侧 | 宿主机侧 |
|---|---|
| 打印 `net: 帧 seq=… 长度=… 哈希=…` | 打开 pcap，找 `0x88B5` 的包 |
| 自报发了几帧 | 数 pcap 里有几个 |
| — | 用 `build_net_frame(seq, kmac)` **独立重算**期望字节，逐字节比 |

**判据的关键**：两边**各自算**，不互相抄。若谁抄谁，"两边都错"时判据是绿的。

**实测的坑**（`aurora.py:3888` 注释）：「抓包文件每次重开：上一跑的包会被读成
这一跑发出去的（实测那类'旧证据冒充新事实'在 scratch 夹具上已经栽过一次）」。
所以 `PCAP.unlink()` 在每次 run 之前。

### 4.2 协议往返（判定表第 33 行）

内核发 ARP → 等回包 → 解析 → 打印。宿主机用 pcap 里**同一个包**再解一遍，
且**地址必须是宿主机定的那一个**（QEMU 的 `10.0.2.2` 网关）。

### 4.3 协议层的六条内核用例

`KT_NET_TX` / `KT_NET_RX` / `KT_NET_ARP` / `KT_NET_PING` / `KT_NET_UDP` / `KT_NET_ROUTE`。

---

## 5. 未实施的：RX 中断

### 5.1 今天的事实

**virtio-net 没有认领中断。** 全仓 `request_irq` 的产品调用者只有 `ahci.rs:686`。
收方向靠 `receive(wait_ms)` 的**轮询 + 有界等待**。

### 5.2 改成中断要先定三件事（**这不是"加个 request_irq"**）

1. **契约变更**：`receive(wait_ms)` 的同步语义会变。今天调用方知道"最多等
   `wait_ms` 毫秒"；改中断后要么变成"睡到有包"（无界），要么保留有界等待但
   多一条唤醒路径。
2. **锁序**：中断处理里要唤醒等待者 ⇒ 会碰 `RANK_WAITQ(5)`。
   `lock-order.md` 已标它是"中断里取"。**新的等待者要在同一张表里登记。**
3. **两本账**：中断计数要能分开"来了"与"认领了"（`irq::counts` 已有这个形状）。

**所以这一条要写 ADR**，不能顺手加。

---

## 6. 容量与限制

| 项 | 值 | 影响 |
|---|---|---|
| 队列数 | 2（RX/TX） | 无多队列 |
| `DMA_PAGES` | 固定 | 环与缓冲共用一个 `alloc_dma` ⇒ 占 1 格 |
| `RX_MAX_BYTES` | 1514 | 无 jumbo frame |
| `ARP_TABLE_MAX` | 8 | 表满时新学习被拒（计数可见） |
| `RX_USED_SEEN` | 单设备静态 | **多设备会串** |

**最后一行是真实脆性**：`Net` 是 `static NetCell`（单台设备）。
挂第二块 virtio-net 会覆盖第一台的 `NET_DEV`。
`virtio-blk` 已经有 `MAX_VBLK=4` 的**表化**（ADR-112），而 net 还没表化。

---

## 7. 未实施清单

1. RX 中断（需 ADR，§5）。
2. net 的设备表化（照 `MAX_VBLK` 的形状）；今天单设备。
3. DHCP 掩码/网关进配置槽（见 [网卡驱动设计](网卡驱动设计.md) §3.1）。
4. 多队列（`NC_MAX_PAIRS` 已读，但只用了 1 对）。
5. 协议栈拆到 `network` 逻辑模块（需 ADR，见 [网卡驱动设计](网卡驱动设计.md) §5）。
