# ADR-171：`network` 协议拆成 7 个文件，`network` 出环

状态：已采纳（2026-11-20）
关联：ADR-166（拆出 network 模块）、ADR-168（协议搬迁与「network 进环」的取舍）、
ADR-044（SCC 棘轮）

> 本文了结 ADR-168 的未决 1 与未决 2。

---

## 一、做了什么

`network/proto.rs`（862 行）拆成 7 个文件，`proto.rs` 保留为**重导出层**（17 行）。

| 文件 | 行数 | 内容 |
|---|---|---|
| `eth.rs` | 55 | 帧布局常量 + `frame_hash` |
| `arp.rs` | 87 | ARP 构造/解析 + `ArpReply` |
| `ipv4.rs` | 85 | 子网/下一跳/`ip_cksum`/`arp_learn_from_frame` |
| `icmp.rs` | 109 | ICMP 常量/校验和/构造/解析 |
| `dns.rs` | 298 | DNS 常量 + 构造/解析 |
| `dhcp.rs` | 185 | DHCP/BOOTP 常量 + 构造/解析 |
| `arp_table.rs` | 114 | ARP 缓存表（`UnsafeCell` 那套） |

---

## 二、`network` 出环——但用的不是 ADR-168 设想的办法

### ADR-168 当时怎么说的

> 硬拆 `pub use` 只有一条路：所有调用方改成 `crate::network::proto::X`，
> 要同时改 `main.rs`、`ktests/net/net.rs`、`ktests/storage/fs.rs` 几十处，
> 而收益只是"少一条环内边"。**代价大于收益。**

### 实际怎么做的

**只消了环的另一半。**

| 边 | 原来 | 现在 |
|---|---|---|
| `network → driver` | `proto.rs` 用 `crate::ahci::fnv1a64`（8 处） | 换成 `eth::frame_hash`（本域自带，纯函数） |
| `driver → network` | `virtio.rs` 的 `pub use` | **保留不动** |

**环需要两条边，消掉任意一条就出环。** 而 `network → driver` 那条**本来就不该存在**：
`fnv1a64` 是纯函数（`&[u8] -> u64`），放哪一层都不改变语义，
它落在 `ahci` 只是历史巧合。

### 实测

    源码 SCC: [arch boot diagnostics driver irq memory pci resource sync time]
    基线 SCC: [... driver irq memory **network** pci ...]   ← 旧基线

**`network` 从环里消失了。** 棘轮从 38 条 / 431 站点降到 **36 条 / 429 站点**。

**这一条最该记的**：ADR-168 把问题描述成「要么改几十处调用点、要么接受进环」，
而**第三个选项是"看那条边是否本来就该存在"**。它不是——所以代价是 9 处
机械替换，不是几十处调用点重写。

---

## 三、拆文件时顺带改对的两处分类

### `ip_cksum` 从 `dhcp.rs` 移到 `ipv4.rs`

它是 **IPv4 头校验和**（RFC 791），`dhcp`/`dns`/`icmp` 三个协议都要构造 IP 头、
都要用它。按行号切时它落在 `dhcp` 里，**分类不对**。

移到 `ipv4.rs` 之后：`ipv4` 不依赖任何人（纯算术），三个协议各自 `use` 它。

### `arp_learn_from_frame` 放 `ipv4.rs` 而不是 `arp.rs`

它解的是以太网帧里的 IPv4/ARP，需要 `ipv4` 与 `arp` 两边的常量。
放 `ipv4` 更顺（它先判以太类型再分派）。

---

## 四、依赖图（拆分后，全部单向无环）

    eth       ← 无依赖（帧布局 + 纯函数）
    arp       → eth, dhcp, NetError
    ipv4      → arp, arp_table, dhcp, eth, NetError
    icmp      → arp, dhcp, eth, ipv4, NetError
    dns       → arp, dhcp, eth, ipv4, NetError
    dhcp      → eth, ipv4, NetError
    arp_table → 无依赖（只存表）

`network` 对外依赖：**空**（`dependencies = []`）。

**注意 `icmp → arp`**：它用 `NET_GATEWAY_IP`。那不是环——`arp` 不反过来依赖 `icmp`。

---

## 五、`proto.rs` 为什么保留

**路径不变、实现分开。**

判定表第 32/33 行的帧对账按 `net: 帧 seq=…` 这类**中文锚点**匹配。
改调用点（`driver/virtio.rs` 的 `pub use`、`main.rs`、`ktests/net/`）时
容易连带改日志文本 ⇒ 判据**静默读成零条**。

`proto.rs` 现在是 8 行 `pub use`，既有路径全部可用。
**它是那道缓冲，不是遗留。**

---

## 六、读数

| 项 | 值 |
|---|---|
| `check` | **18/18** |
| 特性档 | **74/74** |
| SCC | **10 个模块**（`network` 出环） |
| 棘轮 | 36 条 / 429 站点（原 38 / 431） |
| unsafe 普查 | **530 处**（`network/proto` → `network/arp_table`，总数不变） |
| `proto.rs` | 862 行 → **17 行** |

---

## 七、负样本

| 判据 | 负样本 | 红在哪 |
|---|---|---|
| 拆分后判据不变 | 把 `eth::NET_FRAME_BYTES` 从 60 改成 64 | `check-net-pattern` 红（与宿主机重算不符） |
| `frame_hash` 与原 `fnv1a64` 等价 | 改 FNV 偏移基 | `arp: 哈希=… 自算=…` 两值不等 ⇒ 用例红 |
| `network` 不依赖 driver | 在任一文件加 `use crate::driver::…` | `check-module-interfaces` 报 `network.dependencies 源码多 ['driver']` |
| U4 归属 | 把 ARP 表搬回 `arp.rs` 而不改登记 | `check-unsafe` 报「白名单虚报」+「越权 unsafe」 |
| 判定表锚点 | 把 `net: 帧 seq=` 改成别的 | 第 32/33 行读成零条 ⇒ 不符合 |

---

## 八、未决

1. **`proto.rs` 的重导出是永久的吗**：若将来所有调用点都改成新路径，它可以删。
   但**没有期限**——删它的收益只是少一个 17 行的文件，风险是改调用点时碰日志文本。
2. **`dns.rs` 仍有 298 行**：它是最大的一个。再拆（`dns_name.rs` 放编解码）
   是可选的美化，**没有判据压力**。
3. **`network` 域仍没有自己的 ktests**：判据都在 `ktests/net/` 里按用例组织，
   没有按域分。这与其他域（`storage`/`memory` 有独立目录）不一致，
   但**搬迁会改 `.ktests` 链接顺序**，而顺序敏感的用例存在（§442 记过）。
4. **`arp_table.rs` 的 U4 仍是 6 处**：那是 `UnsafeCell` + `AtomicU32` 哨兵。
   要降到 0 需要换成 `IrqSpinLock`，而那是另一个决定（会改锁序，`AGENTS.md` 要求先问）。
