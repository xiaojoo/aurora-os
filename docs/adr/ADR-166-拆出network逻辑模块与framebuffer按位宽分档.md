# ADR-166：拆出 `network` 逻辑模块；framebuffer 按位宽分档而不引入 `PixelFormat` 枚举

状态：已采纳（2026-11-20，使用者裁决）
关联：ADR-043（依赖图按逻辑模块聚合）、ADR-044（SCC 棘轮）、ADR-083（framebuffer 首刀）、
ADR-161（按域分层）、ADR-162（USB 推翻之后网络栈会更大）

> 两件事合在一份 ADR：它们都是"**分类与形状**"的决定，不是容量或编号，
> 而且都会改 `module-interfaces.toml` 或 `display/frame.rs` 的对外形状。

## 一、拆出 `network` 逻辑模块

### 背景（实测）

`docs/architecture/module-interfaces.toml` 里**没有 `network`**（18 个逻辑模块，
我核过：`boot arch memory sched sync display driver pci irq storage diagnostics
input security time capability resource testing integration`）。

所以今天 virtio-net 的**协议栈住在 `driver/virtio.rs` 里**（该文件 96 KiB），
被归在 `driver` 域。这是历史形状：先做 blk 再扩 net，没有重新分类。

代价三条：

1. **一个文件两套职责**：`virtio.rs` 同时是"virtio 硬件驱动"和"以太网/ARP/IPv4/ICMP/UDP/DNS/路由"；
2. **物理网卡进来后必然重复**：e1000e/igb/rtl8139 都要引用同一份协议代码，
   而它们不属于 `driver/virtio.rs`；
3. **ADR-162（USB）之后还会加 TCP/Socket**，几百行塞进 96 KiB 的文件不可维护。

### 决策

**新开 `network` 逻辑模块**（第 19 个），物理落点 `kernel/src/network/`：

| 成员 | 从哪来 | 职责 |
|---|---|---|
| `network/eth.rs` | `virtio.rs` 的 `build_frame`/`parse_*` | 以太网帧 |
| `network/arp.rs` | `virtio.rs` 的 ARP 一族 + `ARP_TABLE` | ARP 与表 |
| `network/ipv4.rs` | `virtio.rs` 的 `is_local_subnet`/`next_hop` | IPv4 与路由 |
| `network/icmp.rs` | `virtio.rs` 的 echo | ICMP |
| `network/udp.rs` | `virtio.rs` 的 UDP | UDP |
| `network/dns.rs` | `virtio.rs` 的 DNS 一族 | DNS |
| `network/dhcp.rs` | `virtio.rs` 的 DHCP 一族 | DHCP |

**`driver/virtio.rs` 只留硬件侧**：能力链、握手、队列、描述符环、MAC/链路状态读取。

**必须同步改的**：

1. `module-interfaces.toml`：新增 `[modules."network"]` 段（`source_modules`、`dependencies`、
   `allowed_callers`、`public_api`、`unsafe_scope`）；
2. **`known_scc` 与 `ring_edge_sites` 会变**——这是 ADR-044 明确要求"新增/消除环都要
   同步 baseline"的情形。**必须先实测再写基线，不许猜**（ADR-161 那次就是这么做的）；
3. `driver` 的 `source_modules` 要移除协议成员，`network` 的依赖里要含 `driver`
   （网络栈通过驱动的收发原语工作）。

### 为什么不是"再等等"

若等 TCP/Socket 一起拆，那次改动会同时动"分类"与"新功能"，两者的判据混在一起，
出问题时分不清是分类错了还是功能错了。**先纯移动（分类），再加功能。**

### 负样本

| 判据 | 负样本 |
|---|---|
| 协议成员全部在 `network` 域、`driver` 域不再含它们 | 留一个 ARP 函数在 `virtio.rs` ⇒ `check-module-interfaces` 红 |
| SCC 基线按实测更新 | 沿用旧 `known_scc` ⇒ `check` 红（这道门禁本来就会咬） |
| 搬完之后 73 档全编译、`ktests` 读数不变 | 搬迁时漏改 `use` ⇒ 编译失败 |

---

## 二、framebuffer 按位宽分档，**不**引入 `PixelFormat` 枚举

### 背景（实测）

`display/frame.rs` 的 `pack()` **按 Limine 给的掩码**算：

```rust
for (i, &channel) in [rgb >> 16, rgb >> 8, rgb].iter().enumerate() {
    let (size, shift) = (self.info.masks[i].0, self.info.masks[i].1);  // ← 来自 bootloader
    let keep = size.min(8);
    let dropped = (channel & 0xFF) >> (8 - keep);   // 这一掩不能省（见源码注释）
    v |= (dropped << size.saturating_sub(8)) << shift;
}
```

三个数（每通道位宽、移位）是**设备在启动时报的**。所以任何面板
（RGBX / BGRA / 5-6-5）都能画对。

**真正的缺口不是"格式不够多"，而是 `frame.rs:76` 硬拒绝非 32bpp**：

```rust
if info.bpp != SUPPORTED_BPP || info.memory_model != MEMORY_MODEL_RGB {
    return Err(FrameError::UnsupportedMode { bpp, memory_model });
}
```

### 决策

**按位宽分档，仍然用掩码打包。不引入 `PixelFormat` 枚举。**

分三档：

| 位宽 | 写法 | 说明 |
|---|---|---|
| 32bpp（今天） | `region.write32`，一像素一次 | 已实施 |
| 24bpp | 按掩码拆成 3 个字节写 | 注意 `pitch` 可能不是 `width * 3` |
| 16bpp（5/6/5 等） | `write16`，掩码打包已能处理窄字段 | `dropped` 那一掩是关键 |

`UnsupportedMode` **保留**给真正不支持的形状（索引色等），且**必须打印实际值**
（今天已经在打印 `bpp` 与 `memory_model`）。

### 为什么不做 `PixelFormat` 枚举

原草案提议：

```rust
enum PixelFormat { Rgb888, Bgr888, Xrgb8888, Xbgr8888 }
```

**问题**：这个枚举是我们**预先写死**的四种可能，运行时得先判断"这块屏是四种里的
哪一种"，**判断本身就是猜**。方向反了：

- 现在：**设备报什么我们就按什么算**（设备说了算）；
- 枚举：**我们列出可能的答案让设备去匹配**（我们猜）。

判错的表现是"画面出来了但**颜色不对**"，而**这种错不会让任何判据变红**——
图案的几何、位置、读回值全对，只有颜色通道错位。

这与本仓库反复的纪律同向：`bus/pci.rs` 的 BAR 尺寸靠写全 1 读掩码（不猜）、
`ADR-029` 的寄存器偏移要由设备作证（不按手册写死）、
`input/kbd.rs` 的 `CHAR_MAP` 是表而不是 `match`（表能由脚本生成并核对）。

### 负样本

| 判据 | 负样本 | 第二台仪器 |
|---|---|---|
| 32bpp 图案四采样点 | 色条顺序改错 ⇒ 红在"下左红" | QMP `screendump`（**今天不在链里**，见 ADR-167） |
| 24bpp 像素值 | 把通道移位写错一位 ⇒ 颜色错 ⇒ 红 | 同上 |
| 16bpp 5/6/5 | 去掉 `dropped` 那一掩 ⇒ 串色 ⇒ 红 | 同上 |
| `UnsupportedMode` 打印实际值 | 只报"不支持"不报 bpp ⇒ 红 | 无（日志检查） |

**注意：这三档的判据全部依赖 `screendump` 进链**。它今天不在链里，
所以**分档支持的实现顺序必须排在 ADR-167 之后**，否则做完了也判不出来。

---

## 影响

**正面**：

- `network` 从 `driver` 里独立出来，物理网卡与 TCP 各有落点；
- framebuffer 的支持面从"只有 32bpp"扩到三种位宽，且**不牺牲"设备说了算"**。

**负面 / 代价**：

- 拆 `network` 会让 `known_scc` 变（可能新增环，也可能消除环），
  要按实测重写基线并写清变化；
- 协议代码搬文件时，`virtio.rs` 里那些**取证日志的中文锚点**（`net: 帧 seq=…`）
  不能动，否则判定表第 32/33 行会静默读成零条；
- 三种位宽各有自己的 `pitch` 陷阱（24bpp 的 `pitch != width*3` 是最常见的）。

## 未决

1. **`network` 拆出来之后 `known_scc` 会怎么变**：**未实测**。
   按 ADR-044，必须先把代码搬完、跑 `check` 拿到真实 SCC，再写基线。
2. **24bpp 的 `pitch` 是否真的会出现 `!= width*3`**：QEMU 上不会，真机可能。
   **未验证**——这要在 `bringup.md` 加一条待测项。
3. **16bpp 的 `dropped` 那一掩在真 5/6/5 面板上是否够**：只在 8/8/8 上验证过
   "不掩也恰好对"，5/6/5 **没有真实面板可测**。
4. **`network` 与 `driver` 的依赖方向**：协议通过驱动的收发原语工作，
   所以 `network → driver` 单向。但今天 `virtio.rs` 里的 `receive()` 返回
   `&[u8]` 到一个静态缓冲——**搬出去之后这个借用关系怎么表达，未设计**。
