# ADR-139：B2 第一刀——ARP 往返（`t_net_arp`）

状态：采纳（2026-11-18，证据来源 / 总设计阶段 B2 / 零新号零零门禁改动）
关联：ADR-032（virtio-net 与 DHCP 往返）、`virtio.rs`（帧构造/解析的形状母本）、
总设计《Aurora-OS-完整操作系统架构与Shell命令体系建设总设计-V1.0》§阶段 B2
（验收句 `ip link`、`ip addr`、网络 `ping`、UDP/TCP 客户端——本片交付
"以太网 + ARP 那两行"的地基：**ARP 是把 IP 地址变成 MAC 的第一步，没有它
任何单播 IP 包都发不出去**）

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计；发现冲突先记差异，
> 不要为了让文档一致去改已经验证的结论。每条结论标「实测」或「推断」。

## 背景

B2 验收句的第一块地基是 **ARP**：IPv4 单播包要先知道对端的 MAC（RFC 826），
没有 ARP 连 ICMP ping 都发不出去。基线盘点：`virtio.rs` 已有完整的
**以太网帧构造**（`build_dhcp_discover`：广播 eth 头 + IPv4/UDP/BOOTP）、
**RX 通道**（`receive()` 有界等待 + `parse_reply` 逐字段先验长度）、
**真协议往返判据**（`t_net_rx`：对端 = QEMU slirp 的 DHCP 服务器）——
**唯独没有 ARP**。

⇒ 第一刀：加 `build_arp_request` + `parse_arp_reply` + ktest `t_net_arp`，
形状全部照抄 DHCP 那两条（同族纪律）。

## 决策

### 决策 1：问 slirp 的网关（10.0.2.2），不是广播一件"谁有我"

ARP request 的形状是广播"谁是 **网关** 10.0.2.2？告诉 **我们** 10.0.2.15"
——网关 IP 是 QEMU 用户网络（slirp）的固定值，**reply 的 sender_ip 必须等于它**
（这一格的第二台仪器 = slirp 自己答的，不是我们回环）。`sender_mac` 填我们自己的
MAC（对端靠它把 reply 寄回来）。

### 决策 2：帧长垫满 60（`NET_FRAME_BYTES`）

以太网最小帧 64 减 FCS；ARP 主体只有 42 字节，垫零到 60——**不依赖设备的补零形状**
（与 `NET_FRAME_BYTES` 注释同一条）。

### 决策 3：判据五格，内容对账靠对端自证

①request 发出去（TX 回执）②RX 有界等待内收到 ③解得开
（ethertype=0x0806、opcode=2）④**内容对**（sender_ip=网关 10.0.2.2、
sender_mac 是个能用的地址：非 0 非 FF 且组播位 0）⑤target_ip=我们（10.0.2.15）
+ used_id=0（缓冲对）。
**实测**：`sender_mac=52:55:0a:00:02:02`（slirp 网关真 MAC）、
`sender_ip=10.0.2.2`、五格全绿 PASS(33) 5.9s。

## 落地时撞到的两件事（实测）

1. **`used_len` 不能直接当界**（§10.3 纪律的现场版）：初版
   `fnv1a64(&buf[..used_len])` 用设备写的字节数切我们的缓冲 ⇒ panic
   （`virtio.rs:1248`）。修：夹到 `(used_len).min(buf.len())`。
   教训：**RX 的每一个长度字段都来自对端，取界前先夹**——
   `parse_reply` 的逐字段先验长度是同一句话在 DHCP 那侧的形状。
2. **变异证红**：把 ④ 的期望从 `NET_GATEWAY_IP` 改成 `DHCP_GUEST_IP`
   （自己）⇒ `网关ip=false` ⇒ FAIL(35)；还原 ⇒ 绿。

## 影响

正面：IP→MAC 的解析器有了；**ICMP/UDP/TCP 的地基**（任何单播发送都先查 ARP 表）；
`NET_GATEWAY_IP` 与 `DHCP_GUEST_IP` 同源对账（check-net-pattern 族）。

负面：**ARP 表（缓存）还没做**（第一版只问不记，每次都广播）；`ip link`/`ip addr`
命令还没接（网卡信息在 `net_info()` 里，差 shell 命令）；ICMP/UDP/TCP 全部待建。

## 验收与负样本

- `t_net_arp` 五格，virtio-net 档全绿 PASS(33) 5.9s（实测）。
- **变异证红**：④ 期望错 ⇒ 红，还原 ⇒ 绿（实测）。
- `check` 18/18；整链 69/69 rc=0。

## 迁移与回滚

零新号、零门禁数变化、零既有判据改动。回滚 = 删 `build_arp_request`/
`parse_arp_reply`/`t_net_arp` 三块，互不牵连。

## 未决

1. **ARP 表（缓存 + 老化）**：每次单播都广播不可持续；表项的 TTL/清理形状
   要与 `sched` 的定时器语义对（单独片）。
2. **`ip link`/`ip addr` 命令**：`net_info()` 的读数（MAC/IP/链路状态）已在，
   差 shell 命令与十进制/十六进制打印（`put_u64` 只有十进制）。
3. **ICMP ping**：ARP 之后的最短路径——echo request/reply 直接走
   `build_arp_request` 同族的帧构造。
