# ADR-211：xHCI 真实初始化（第一次写寄存器）

状态：**已采纳**（2026-11-22：`t_xhci_run` 八格全 true，`PASS(33)`）

关联：ADR-208（TRB）、ADR-209（序列推导）、ADR-210（真读 CAP）

> 切片 H 第四层。**前三层只读不写，这一层第一次真的改硬件状态。**

## 交付

```rust
pub const USBCMD_RUN/HCRST/INTE
pub const USBSTS_HCH/CNR
pub const SPIN_LIMIT: u32 = 2_000_000;
pub fn run_device(dev) -> Result<RunReading, RunError>
```

执行 ADR-209 算出的 5 步序列，且**真的等状态位**：

1. 分配两块 DMA（命令环一页 + DCBAA 一页），都清零
2. 写 `USBCMD.HCRST=1`，等 `HCRST` 自清 **且** `CNR=0`
3. 写 DCBAAP / CRCR（低 6 位标志，cycle=1）/ CONFIG
4. 写 `USBCMD.RS=1 + INTE=1`，等 `HCH=0`

## 决策 1：命令环与 DCBAA 分开两次 `alloc_dma`

两者都必须 64 字节对齐（CRCR 低 6 位是标志）。一页对齐天然满足，
而放一起会让「谁对齐了」变含糊。

## 决策 2：两块 DMA 都清零

**脏数据会让硬件把旧 TRB 当成有效项** —— 这与 NVMe 那条教训同源（那里是 phase 位）。

## 决策 3：DMA 句柄故意 `forget`

控制器在跑，环必须一直有效。这与 NVMe 同一条：**设备活着，缓冲就得活着**。

## 实测撞出的错：`ModuleId` 越界

第一版 `MOD_XHCI = ModuleId(88)`，而 `resource::MAX_MODULES = 64`。

后果不是「驱动失败」，而是**每次 `alloc_dma` 都算一次 `unknown_module_hits`**，
于是 `t_resource_ledger_balanced` 的 `unknown_hits == 0` 那一条红 ——
而红的地方**离成因很远**（看起来像台账坏了）。

改成 `41`（已用 0-3、10-21、40）后 `unknown_hits=0`。

**教训**：新增 `ModuleId` 时必须先查 `MAX_MODULES` 与已用集合，越界不会当场报错。

## 判据八格（`t_xhci_run`）

```
xhci-run: 初始化=true cnr清=true hch清=true rs=true ring对齐=true dcbaa对齐=true
          分开=true 一致=true ｜ ring=0x8d000 dcbaa=0x8e000
          sts_after_reset=0x1 sts_after_run=0x0 cmd=0x5 ⇒ true
```

`sts_after_run=0x0`（HCH 清）+ `cmd=0x5`（RS|INTE）是控制器**真的进了运行态**的证据。

## 负样本（变异证红）

把 `USBCMD_RUN` 去掉（只写 INTE）：

```
xhci-run: run_device 失败 RunTimeout
```

控制器不进入运行态 ⇒ HCH 保持 1 ⇒ 等满 2e6 次自旋后超时。

**这条负样本证明「等 HCH=0」那个循环真的在工作**，不是摆设。

## 读数

| 项 | 结果 |
|---|---|
| `check` | **21/21** |
| `handles,xhci` 档 | **`PASS(33)`**，`t_xhci_run` 八格全绿 |
| `ledger totals` | `unknown_hits=0 violation=false` |

## 一个刻意的保守

**没有投递任何命令**：TRB 环写好了、CRCR 指过去了，但没发 Enable Slot。
端口枚举是下一层。今天只证「控制器真的进了运行态」。

## 未决

1. **端口枚举**（Enable Slot → Address Device → Configure Endpoint）
2. **命令环的消费者**（投递 TRB + 等 Command Completion Event）
3. **事件环**（Interrupter 0 的 ERST + 中断）
4. **Scratchpad Buffer 分配**（`max_scratchpad` 读了但没分配）
5. **DMA 泄漏** —— `forget` 是故意的，但**没有卸载路径**；控制器若需重置，这两块永远回不来