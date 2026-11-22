# ADR-182：IPv6 接入（地址抽象、NDP、SLAAC、AAAA）

状态：**部分采纳**（2026-11-22：IpAddr / IPv6 头 / EUI-64 / NDP / UDP over IPv6 / DNS AAAA 已落地；SLAAC 与分片见未决）

关联：ADR-181（socket 族，`domain` 已收 `AF_INET6`）、ADR-165（网络两族语义不合并）

> 写作纪律：每条结论标「实测」或「推断」。

## 背景

### 现状（实测）

| 项 | 现状 |
|---|---|
| 地址表示 | **到处是 `[u8; 4]`**（`ipv4.rs` / `arp*.rs` / `dhcp.rs` / `dns.rs` / `udp.rs`）|
| 以太网类型 | 只有 `NET_TYPE_IPV4 = [0x08, 0x00]` |
| DNS | 只有 `DNS_QTYPE_A = 1`，解析只认 `rdlen == 4` |
| socket `domain` | **已收 `AF_INET6`，回 `-38`**（ADR-181 决策 2）|
| 地址配置 | 只有 DHCPv4 |

### 为什么不能「直接把 `[u8;4]` 换成 `[u8;16]`」

那会让 IPv4 路径也变成 16 字节，每个 `copy_from_slice` 都要改，而 IPv4 是**今天唯一能跑的**。

## 决策

### 决策 1：新增 `IpAddr` 枚举，**IPv4 路径一行不改**

```rust
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}
```

**只在新代码（IPv6 收发、NDP、AAAA）里用 `IpAddr`**，既有 IPv4 函数签名保持 `[u8; 4]`。

理由：IPv4 的 8 个文件、几十处调用**都实测在跑**；改签名是纯风险，没有收益。
迁移是渐进的：哪天某个函数真的两个族都要服务，那时再改它一个。

### 决策 2：IPv6 头与地址格式按 RFC 8200 / 4291 逐字节实现

| 项 | 值 |
|---|---|
| 以太网类型 | `0x86DD` |
| 版本 | 头前 4 位 = `6` |
| 固定头长 | **40 字节**（与 IPv4 的 20 不同，没有选项字段）|
| 地址长 | 16 字节 |
| 下一头部 | 与 IPv4 的 `protocol` 同位置语义（`17` = UDP）|

**IPv6 没有头校验和**（与 IPv4 的关键差异）：校验交给上层（UDP/TCP 强制带伪首部）。
少算这一点会让「发出去的包对端不认」——与 UDP 伪首部是同一类错误。

### 决策 3：先做「链路本地 + 静态配置」，SLAAC 放第二轮

IPv6 上线的最小闭环：

| 步 | 内容 | 本轮 |
|---|---|---|
| 1 | 链路本地地址 `fe80::/10`（由 MAC 按 EUI-64 推出）| **做** |
| 2 | 邻居发现（NDP）替代 ARP：`NS`/`NA`（ICMPv6 类型 135/136）| **做** |
| 3 | 静态全局地址（手工配）| **做** |
| 4 | SLAAC（`RA` 里取前缀 + 自己拼接口 ID）| 第二轮 |
| 5 | DHCPv6 | 不做（SLAAC 够用）|

**为什么先做 NDP 不做 SLAAC**：没有 NDP 就发不出包（不知道对端 MAC），
而 SLAAC 只是「地址从哪来」——链路本地地址已经够验证收发闭环。

### 决策 4：DNS 加 `AAAA`（类型 28），与 `A` 并列不替代

```rust
pub const DNS_QTYPE_A: u16 = 1;
pub const DNS_QTYPE_AAAA: u16 = 28;
```

**解析器要能同时处理两种记录**：一个名字可能只有 A、只有 AAAA、或两者都有。
`DnsReply` 加一个 `aaaa: Option<[u8; 16]>` 字段，**不改 `a` 字段的类型**。

### 决策 5：socket 层只加 `AF_INET6` 的分支，不改 UDP 的既有形状

`udp::build_frame` 是 IPv4 专用的（`NET_TYPE_IPV4` 硬编码）。
新增 `udp6::build_frame`（IPv6 + UDP 伪首部），**两个函数并存**。

`socket::create` 的 `AF_INET6` 分支从「回 -38」改成「真建 socket」。

## 本轮范围

| 项 | 本轮 |
|---|---|
| `IpAddr` 枚举 | **做** |
| IPv6 头解析/构造 | **做** |
| 链路本地地址（EUI-64）| **做** |
| NDP（NS/NA）| **做** |
| UDP over IPv6 | **做** |
| `socket(AF_INET6, SOCK_DGRAM)` | **做** |
| DNS AAAA | **做** |
| SLAAC | 第二轮 |
| TCP over IPv6 | 不做（TCP 本身还没做）|

## 未决

1. **SLAAC**（RA 处理 + 前缀拼接）。
2. **IPv6 分片**（扩展头链）——本轮只处理无扩展头的简单包。
3. **双栈策略**（`AF_INET6` socket 是否也收 IPv4 映射地址 `::ffff:a.b.c.d`）。
4. **真实 IPv6 环境验证**——QEMU slirp 的 IPv6 支持有限，可能需要换网络后端。