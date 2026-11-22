# ADR-209：xHCI 能力解码与初始化序列

状态：**已采纳**（2026-11-22：`t_xhci_init` 七格全 true）

关联：ADR-208（xHCI 字节层）

> 切片 H 第二层。**真正的控制器寄存器读写还没做** —— 本层只把「读 CAP → 算出该写哪些 OP」做成纯函数。

## 为什么还是纯函数

当前 QEMU 配置只有 6 台 PCI 设备，**没有 xHCI**（class 0x0c/0x03）。
真机初始化无法在这里验证，所以继续走 ADR-208 的路线：

**输入寄存器快照 → 输出配置动作序列**，判据可以喂任意快照（包括损坏的）。

## 交付

```rust
pub struct CapSnapshot { cap_length, hcsparams1, hccparams1, doorbell_offset }
pub enum InitError { NoSlots, BadCapLength, BadDoorbell, No64Bit, NoPorts, BadAlignment }
pub enum OpWrite { UsbCmd{...}, Crcr{...}, Dcbaap{...}, Config{...} }
pub fn plan_init(&cap, cmd_ring_bus, dcbaa_bus) -> Result<[OpWrite;5], InitError>
```

## 能力字段（xHCI spec §5.3）

| 字段 | 位置 | 说明 |
|---|---|---|
| MaxSlotsEn | HCSPARAMS1 bit 7:0 | 0 = 控制器不支持任何槽，**必须拒绝** |
| MaxIntrs | HCSPARAMS1 bit 18:8 | 中断器数 |
| MaxPorts | HCSPARAMS1 bit 31:24 | 下游端口数 |
| AC64 | HCCPARAMS1 bit 0 | 1 = 支持 64 位寻址 |
| CSZ | HCCPARAMS1 bit 3 | 1 = 控制端点用 64 字节 TRB |
| Max Scratchpad | HCCPARAMS1 bit 12:7 | Scratchpad Buffer 张数 |
| CAPLength | CAP+0x00 低字节 | 运行寄存器偏移，**最小 0x20 且 4 的倍数** |
| Doorbell Offset | CAP+0x0C | **必须在 CAP 区域外**且 4 对齐 |

## 决策 1：先形状校验，再能力校验，最后产出写序列

顺序有意义：一个形状非法的寄存器（比如 CAPLength=0x10）不该先报「没有端口」——
**根因优先级要让判据能定位**。

## 决策 2：错误码按成因分开

第一版把 DMA 未对齐复用了 `BadCapLength(0)`，那会让调用方分不清该改驱动还是改分配器。
补了 `BadAlignment(u64)` 带出那个地址。

**「能力寄存器形状」和「软件给的缓冲没对齐」是完全不同的成因，不能混成一个码。**

## 决策 3：5 步序列的顺序是硬约束

```
1) USBCMD HCRST=1    复位（硬件自清）
2) DCBAAP  表指针
3) CRCR    命令环指针（cycle=1）
4) CONFIG  MaxSlotsEn
5) USBCMD  RS=1 + IE=1   运行 + 中断使能
```

**复位必须第一步、运行必须最后一步**。负样本把复位去掉 ⇒ 顺序格当场红。

## 判据七格（`t_xhci_init`）

```
xhci-init: 解码=true op=true db=true 序列=true 顺序=true 拒绝=true 对齐=true ⇒ true
```

## 负样本（变异证红）

去掉第一步的复位：

```
xhci-init: 序列不对 plan=true order=false
xhci-init: ... 顺序=false ⇒ false
```

## 读数

| 项 | 结果 |
|---|---|
| `check` | **21/21** |
| `handles` 档 | `t_xhci_init` 七格全绿；唯一失败是既有 `t_map_hole` |

## 未决

1. **真的读写 CAP/OP 寄存器** —— 需要 `DriverCtx::map_mmio/read32/write32`，且要有 xHCI 设备
2. **QEMU 配置加 xHCI 设备** —— 否则真机路径永远测不到
3. **等 CNR=0**（Controller Not Ready）的轮询 —— 判据里只是序列，没做等待
4. **Scratchpad Buffer 分配** —— 解码了张数但没分配
5. **端口枚举**（Enable Slot → Address Device → Configure Endpoint）