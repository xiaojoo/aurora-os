# ADR-208：xHCI 字节层（TRB 与环游标）

状态：**已采纳**（2026-11-22：`t_xhci_trb` 七格全 true）

关联：ADR-196（驱动注册表）、ADR-197（TCP 字节层，同一分层思路）

> 切片 H 的第一层。**控制器初始化、端口枚举、设备类驱动都没做**。

## 为什么只做字节层

USB 与前面几片都不同：它有真正的**硬件状态机**（xHCI 控制器），判据要证的东西
大多必须有真实设备（或 QEMU 的 xHCI 模拟）才有意义。

所以先做**能被纯函数判据完整证伪**的部分：

| 做 | 不做 |
|---|---|
| TRB 的构造 / 解析 | 控制器的实际初始化 |
| 环的游标（生产者/消费者索引）| 端口枚举 |
| 寄存器偏移常量 | 设备类驱动（HID/大容量存储）|

与 TCP 分层（ADR-197 先做段格式）同一个思路：**先让字节层可证，再接硬件**。

## 交付

```rust
pub const TRB_BYTES: usize = 16;
pub const TRB_RING_SIZE: usize = 4096 / 16 = 256;   // 一页，推导值

pub enum TrbType { Normal, SetupStage, DataStage, StatusStage, Link,
                   EnableSlot, AddressDevice, ConfigureEndpoint,
                   TransferEvent, CommandCompletionEvent }
pub fn parse_trb(&[u8;16]) -> Option<Trb>
pub fn build_trb(&mut [u8;16], ty, parameter, status, cycle) -> bool
pub struct RingCursor { enqueue, dequeue, producer_cycle, consumer_cycle }
```

## 决策 1：环容量是推导值，不是接缝尺

`TRB_RING_SIZE = 256` 来自 `TRB_BYTES × N == PAGE` 且 N 是 2 的幂 ——
一页对齐的环是 xHCI 的要求（TR Dequeue Pointer 低 4 位必须为 0）。

## 决策 2：**最后一格固定是 Link TRB**

这一条在实测里绕了三圈才弄对，值得记全过程：

1. 第一版绕回阈值写 `SIZE`，游标停在 255 就判满 ⇒ `enqueue=255 pc=true flips=0`；
2. 改成 `SIZE-1` 后能绕回，但 `free()` 还按 `SIZE-1` 算 ⇒ 满环判据矛盾；
3. 改成 `free = SIZE-2 - used` 后，第 255 次推进才绕回，而判据循环了 254 次。

**最终语义**：

- 环共 `SIZE` 格，最后一格固定是 Link，**永不可写**；
- 可装 `SIZE-2` 条 TRB（还要留一格区分满/空）；
- `advance_enqueue` **先判绕回、再判满**：停在 Link 前一格且满时，下一次写入合法地绕回，
  而不是返回 `None`。若先判满，游标永远卡在 `SIZE-2`，cycle 永不翻转。

## 决策 3：不把 DMA 内存当切片

TRB 环住在 DMA 内存里，设备随时会写。按 `driver/mod.rs` 的纪律，
这里只构造/解析**自己的字节缓冲**，真正放进 DMA 环时走 `DmaHandle` 的 volatile 访问器。

## 判据七格（`t_xhci_trb`）

```
xhci: 往返=true cycle=true 未知拒=true 字段=true 恒等式=true 绕回翻转=true 满拒=true ⇒ true
```

## 负样本（变异证红）

去掉绕回时的 `producer_cycle` 翻转：

```
xhci: 绕回 cycle 没翻转 enqueue=0 pc=true flips=0
xhci: ... 绕回翻转=false ⇒ false
```

## 读数

| 项 | 结果 |
|---|---|
| `check` | **21/21** |
| `handles` 档 | `t_xhci_trb` 七格全绿；唯一失败是既有 `t_map_hole` |

## 未决

1. **控制器初始化**（CAP/OP 寄存器读写、运行/停止、TR Dequeue Pointer 编程）
2. **端口枚举**（Enable Slot → Address Device → Configure Endpoint）
3. **Link TRB 真的写进环** —— 今天只是「游标跳过」，没有构造 Link TRB 本身
4. **事件环**（Transfer Event / Command Completion 的消费）
5. **设备类驱动**（HID / 大容量存储）
6. **QEMU xHCI 的端到端验证** —— 今天没有任何真实设备参与