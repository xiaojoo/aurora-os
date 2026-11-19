# ADR-168：`network` 协议层搬迁落地；`network` 进环 A 的取舍

状态：已采纳（2026-11-20）
关联：ADR-166（拆出 network 模块）、ADR-044（SCC 棘轮）、ADR-167（ADR-165/166 落地）
取代：ADR-166 未决 1（「协议搬迁未做」）与未决 4（「借用关系未设计」）

---

## 一、做了什么

把 `driver/virtio.rs:1148–1979` 的**协议块**（约 1050 行）搬到
`kernel/src/network/proto.rs`，并把帧布局常量一起下沉。

### 切口（实测，不是估的）

搬迁前先量了协议块对驱动侧的依赖：**只有 7 个符号**
（`NET_FRAME_BYTES` 3 次、`NET_DST` 2、`O_NFRAME` 1、`DMA_PAGES` 1、
`fnv1a64` 8、`NET_TX_MAX` 6、`DHCP_FRAME_BYTES` 4），
且对 `VirtioError` **只用了 `NotV4` 一个变体**（12 处）+ 4 个返回类型。

所以错误翻译是机械的：`VirtioError::NotV4 { at, guard }` → `NetError::NotV4 { at, guard }`。

### 整块搬 vs 一次拆 7 个文件

ADR-166 的表要求拆成 `eth`/`arp`/`ipv4`/`icmp`/`udp`/`dns`/`dhcp` 七个文件。
**这一轮先整块搬**，理由：

这些函数**互相引用**（`build_dns_query` 用 MAC 布局、`parse_reply` 用 `ip_cksum`、
`arp_learn_from_frame` 用 `NET_TYPE_ARP`），一次拆 7 个要同时改几十处 `use`，
出错面比收益大。**先证明「搬出去能编、判据不变」，再按文件细分**——
两步分开，各自可验证。

### 帧布局常量下沉（8 个）

`NET_TYPE` / `NET_DST` / `NET_HEAD_BYTES` / `NET_FRAME_BYTES` /
`NET_PAYLOAD_BYTES` / `NET_MUL` / `NET_ADD` / `NET_XOR` 从 `virtio.rs` 搬进 `proto.rs`。

**理由不是"为了消环"，是分类更对**：这 8 个是**协议概念**（帧怎么排、载荷怎么算），
不属驱动层。驱动只需要知道"环有多大"，不需要知道"帧怎么排"。

---

## 二、`network` 进了环 A —— 这是有意的取舍

### 实测

    源码 SCC: [arch boot diagnostics driver irq memory **network** pci resource sync time]
    基线 SCC: [arch boot diagnostics driver irq memory          pci resource sync time]

    环内新边 driver->network（站点 2）
    环内新边 network->driver（站点 8）
    driver->memory 已降到 16（登记 17）

### 两条边的来源

- `network → driver`（8 站点）：`proto.rs` 用驱动侧的 `fnv1a64`（8 处）等；
- `driver → network`（2 站点）：`virtio.rs` 的 `pub use crate::network::proto::{...}`
  ——**这是真代码，不是注释**。

### 为什么不硬拆

`pub use` 是我为"**调用点一字不改**"故意加的。判定表第 32/33 行的帧对账按
`net: 帧 seq=…` 这类**中文锚点**匹配，改调用点容易连带改日志文本
⇒ 判据**静默读成零条**（不是报错，是读不到）。这是本仓库踩过的坑。

硬拆只有一条路：所有调用方改成 `crate::network::proto::X`，
要同时改 `main.rs`、`ktests/net/net.rs`、`ktests/storage/fs.rs` 几十处，
而收益只是"少一条环内边"。**代价大于收益。**

### ADR-044 的要求是"显式登记"，不是"不许变大"

所以按实测重写基线：`known_scc` 加 `network`、棘轮加两条新边、
`driver->memory` 从 17 收紧到 16（"减一处也红，请把登记一起收紧"）。

**这一条留给下一轮**：协议按文件拆成 7 个时，调用点本来就要动，
那时一并把 `pub use` 去掉，`network` 就出环了。

---

## 三、搬迁的验证（三条独立证据）

### 1. unsafe 普查**逐类完全相同**

| 项 | 搬迁前 | 搬迁后 |
|---|---|---|
| `driver/virtio` U4 | 14 | **8** |
| `network/proto` U4 | — | **6** |
| 合计 | 14 | **14** |

**总数守恒**，且**六类合计仍是 523（U1 85 / U2 119 / U3 13 / U4 142 / U5 128 / U6 36）**
——这是"纯移动"最强的证据：那 6 处是 `ARP` 表那套 `UnsafeCell` 跟着代码走的。

### 2. 判据读数一字未变

`virtio-net` 档跑出 `PASS(33)`，且：

    arp: 发 REQUEST 长=60 哈希=0xe181794f14a49a60 自算=0xe181794f14a49a60
    arp: 判据 发出=true 解得开=true 网关ip=true mac形状=true 问的是我们=true 缓冲对=true
    udp: 判据 ARP往返=true 发出=true 收到ICMP=true 内嵌对账=true 缓冲对=true
    net: 判据 enable读回=1 队列深=256 网卡形状=true … 帧1=7/0/60

与搬迁前**逐字相同**。

### 3. 73 个特性档全通

---

## 四、门禁在这一轮抓到的四件事（都对）

1. **`mod network` 未登记** → 报「被 0 个逻辑模块覆盖」；
2. **`network` 依赖填错** → 我按"将来"填，门禁比源码实测；
3. **`check-net-pattern` 找不到常量** → 它只扫 `virtio.rs`，而常量已下沉。
   修法：**两个文件都扫**（不是放宽判据——常量真被删掉仍然红）；
4. **`network/proto` 的 6 处 U4 未登记** → 报「越权 unsafe」。

还有一次**我自己的错**：改 `known_scc` 时用 `re.findall(r"\[([^\]]+)\]")`
去解析门禁报的 `[['arch', ...]]`（**两层**方括号），把 `['arch` 当成了模块名。
门禁立刻报 `baseline.known_scc 含未知模块 "['arch"`。最后改用正则整段替换。

---

## 五、读数

| 项 | 值 |
|---|---|
| `check` | **18/18** |
| 特性档 | **73/73** |
| `virtio-net` 档 | **PASS(33)** |
| unsafe 普查 | **523 处**（逐类与搬迁前相同） |
| SCC | 11 个模块（新增 `network`） |
| 棘轮 | 38 条边 / 431 站点（搬迁前 36 条 / 422） |

---

## 六、未决

1. **协议按文件拆成 7 个**（ADR-166 的表）**未做**：本轮整块搬，
   拆文件是下一轮的机械工作。
2. **`network` 仍在环 A**：`driver → network` 那条边来自 `pub use`，
   下一轮拆文件时一并去掉（那时调用点本来就要动）。
3. **`net-pattern` 现在扫两个文件**：若将来拆成 7 个，要改成扫整个 `network/`。
4. **`MAX_TASKS`/槽位扩容后的 `.bss` 增量仍未实测**（ADR-165 未决 5 未变）。
