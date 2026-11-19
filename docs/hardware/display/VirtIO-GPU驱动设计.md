# VirtIO GPU 驱动设计

状态：**未实施**（全仓零行 virtio-gpu 代码；QEMU 设备已核实存在）

- 相关 ADR：`ADR-030`（驱动唯一接口）、`ADR-112`（virtio 设备表化）
- 实测前提：QEMU **11.1.0** 支持 `virtio-gpu-pci` / `virtio-gpu-device` /
  `virtio-vga` / `virtio-vga-gl` / `virtio-gpu-gl-pci`
- 上位：[硬件驱动体系总设计](../Aurora-OS-硬件驱动体系总设计-V1.0.md)
- 同层：[Framebuffer设计](Framebuffer设计.md)、[显示设备管理设计](显示设备管理设计.md)

---

## 1. 先分清三条设备路径（**这是本文最重要的一节**）

| 路径 | QEMU 参数 | 有没有 framebuffer | 驱动工作量 |
|---|---|---|---|
| **D-0 现在** | `-display none`（隐式默认 VGA） | 有（Limine 拿到 memmap 的 Framebuffer 段） | 零（已实施） |
| **D-1 显式 VGA** | `-device VGA,vgamem_mb=16` | 有 | 零（只是把隐式变显式） |
| **D-2 virtio-vga** | `-device virtio-vga` | **有**（兼容模式：PCI BAR 仍给 framebuffer） | 小（识别设备 + 走既有 frame 路径） |
| **D-3 virtio-gpu-pci** | `-device virtio-gpu-pci` | **没有** | 大（必须走资源创建 + scanout） |

**原草案那句判断是对的，本文保留并落成判据**：

> 不能把标准 VGA 帧缓冲输出成功，当成 VirtIO GPU 驱动完成。

**落成判据的方式**：`devctl status` 必须能分辨 D-1/D-2/D-3 三种设备形态，
判定表**各有一行**。否则"GPU 驱动做完了"这句话没有证据。

**今天的接线是 D-0**（实测 `tools/aurora.py:3830` 的 `-display none`，
且命令行**无 `-vga`**）。所以任何 GPU 工作的第一步是改接线。

---

## 2. D-2：virtio-vga 兼容模式（小，先做这个）

### 2.1 为什么先做它

`virtio-vga` 是"virtio-gpu 设备 + 兼容的 VGA framebuffer"。它的价值在于：

- **设备已经是 virtio 了**（PCI ID 0x1AF4:0x1050）；
- **framebuffer 仍由 BAR 给**，所以 `frame.rs` 的既有路径能继续用；
- 于是可以在**不改显示栈**的前提下，先把"virtio 设备的识别与握手"做对。

这是一次**低风险的过渡**：万一 virtio 握手有问题，画面仍然出得来
（framebuffer 不依赖 virtio 命令）。

### 2.2 要做的

1. PCI 识别：vendor `0x1AF4`，device `0x1050`（virtio-vga）。
   `virtio.rs` 的 `is_modern_id` / `dev_type` 已有这套解码，
   但要确认 `dev_type(0x1050)` 给出的是 GPU（通常 `0x10` 起）。
2. 走既有 `virtio` 的握手（`handshake`）——`CC_STATUS` 的 0→ACK→DRIVER→
   FEATURES_OK→DRIVER_OK 五步已经是既有代码。
3. **只读设备配置空间**（`NC_*` 那套偏移的 GPU 版本），**不发任何 GPU 命令**。
4. 判据：设备被认领、握手成功、framebuffer 仍可用、既有显示判据全绿。

**这一片不改任何显示代码。** 它证明的是"virtio GPU 设备能被我们接住"。

---

## 3. D-3：virtio-gpu-pci（大，真 GPU 路径）

### 3.1 协议要点（按 virtio 1.x GPU 规范）

```text
两个 virtqueue：
  controlq   —— 命令/响应（资源创建、scanout 绑定、传输）
  cursorq    —— 光标（10 字节命令）
   （事件队列 eventq 用于设备→驱动通知，第一阶段可不用）

命令形状（每个都是 { hdr, payload }）：
  hdr = { type: u32, flags: u32, fence_id: u64, ctx_id: u32, padding: u32 }
  响应 hdr 的 type 带 RESP 位（0x0100）

关键命令：
  GET_DISPLAY_INFO          → 每个 scanout 的 { rect, enabled, flags }
  RESOURCE_CREATE_2D        → 建资源（id, format, width, height）
  RESOURCE_ATTACH_BACKING   → 把一组 page 挂到资源上（GPU 地址 + 长度）
  SET_SCANOUT               → scanout_id ← (resource_id, rect)
  RESOURCE_FLUSH            → 把某块区域刷到显示
  TRANSFER_TO_HOST_2D       → 从 guest 内存搬到资源
  RESOURCE_DETACH_BACKING / RESOURCE_UNREF  → 销毁
```

**fence_id 是整套机制的同步点**：命令带上 fence，设备完成时回一个
`RESP_OK` 且 `fence_id` 相同（或用 event）。第一阶段建议**只用同步等待 fence**，
不启用 async/event——少一条中断路径。

### 3.2 五片（每片独立可验收）

```text
G-1  识别 + 握手 + 读 GET_DISPLAY_INFO
     判据：读回 scanout 的 rect/enabled 与 QEMU 声明的分辨率一致
           （宿主机可用 QMP `info qtree` 或 `query-display-options` 对账）

G-2  建资源 + attach backing（还不 scanout）
     判据：RESOURCE_CREATE_2D 返回 OK；attach 后设备不报错
     负样本：format 用未支持的值 ⇒ 必须拿到具名错误，不是"没反应"

G-3  SET_SCANOUT + TRANSFER + FLUSH，画出第一个像素
     判据：**宿主机 screendump** 看到我们写的那块颜色
     ← 这是唯一真正的"画面判据"，也是 AHE-04 必须先做好的原因

G-4  双缓冲与帧同步（两个资源轮换 + fence 等待）
     判据：连续 8 帧无撕裂（宿主机连拍 8 张 PPM 比对）

G-5  错误与资源回收
     判据：RESOURCE_UNREF 后资源 id 可复用；detach 后再 flush 必须报错
```

**顺序不能换**：G-3 依赖 G-1/G-2，而 G-3 的判据依赖宿主机截图能力。
若 AHE-04（screendump 进链）没做，**G-3 做完也判不出来**。

### 3.3 与 `frame.rs` 的关系（关键设计选择）

D-3 下**没有 framebuffer**，所以有两条路：

| 方案 | 做法 | 代价 |
|---|---|---|
| **A. 把 GPU 资源当 framebuffer** | 分配一块 guest 内存当"逻辑帧缓冲"，`Frame` 仍往它写；每次 `present` 时 TRANSFER + FLUSH | `frame.rs` 几乎不用改（只是把 `MmioRegion` 换成普通映射）；代价是每次上屏多两次命令 |
| B. 让 `fbcon` 直接产生 GPU 命令 | 重写绘制路径 | 4968 行要动，且会打破"像素写入只经 Frame"的边界 |

**本文选 A**。理由：它保住 `fbcon.rs` 零 `unsafe` 与"像素只经 `Frame::put`"
这条边界，而这些边界是 ADR-083/086 用判据钉住的。

**A 的代价要说清**：`Frame::present()` 从"搬脏行到 MMIO"变成
"搬脏行到 guest 内存 + 一次 TRANSFER_TO_HOST_2D + 一次 RESOURCE_FLUSH"。
在 QEMU 上这条路径比 MMIO 直写**慢**（多两次命令往返），
但它是**正确的 GPU 语义**——而且换上真 GPU 时这条路径不变。

---

## 4. 判据与负样本

| 判据 | 宿主机第二台仪器 | 负样本 |
|---|---|---|
| G-1 读数一致 | `info qtree` / 启动日志的 scanout rect | scanout rect 读错 ⇒ 红 |
| G-2 资源创建 | 无（命令返回自证 + 计数） | format 非法 ⇒ 必须有具名错误 |
| G-3 第一个像素 | **QMP screendump** | 颜色写错 ⇒ 采样点红 |
| G-4 无撕裂 | 连拍 8 张 PPM 逐张比对 | 双缓冲关掉 ⇒ 撕裂 ⇒ 红 |
| G-5 资源回收 | 无（id 复用可见） | detach 后 flush 不报错 ⇒ 红 |

**G-3/G-4 没有第二台仪器就判不出来**。这不是"以后补"，是**前置**：
AHE-04 必须排在 AHE-06 之前（见总设计 §4.2）。

---

## 5. 容量与约束（会直接卡住）

| 约束 | 实测值 | 影响 |
|---|---|---|
| `MMIO_SLOTS` | **8** | GPU 占 1 格；若与 AHCI + 2×blk + net 同挂，**已满** |
| `DMA_SLOTS` | **8** | GPU 至少要 controlq + cursorq + 资源 backing ⇒ 2..3 格 |
| 中断向量 | 16（剩 ~9） | 若用 MSI-X 要 1 颗；同步等待 fence 则 0 颗 |
| 堆单次上限 | 2048 | 资源 backing 必须 `alloc_dma`，不能进堆 |
| `.text` | 已扩到 128 KiB（ADR-155） | GPU 驱动代码会再撞墙 |

**`MMIO_SLOTS`/`DMA_SLOTS` = 8 是第一个硬前置**（AHE-01）。
GPU + NVMe + 物理网卡同时上，8 格必然不够。

---

## 6. 与 `virtio.rs` 的关系

`driver/virtio.rs` 已经有：能力链解析（`read_caps` / `find_cap` / `off_in`）、
握手（`handshake`）、描述符环操作（`put_desc` / `wait_u16`）、MSI-X 探测。

**GPU 应当复用这些，而不是新写一份。** 具体：

- `claim(PCI_CLASS_...)` 要扩一个"按 vendor+device 找 GPU"的入口
  （今天的 `claim` 按 class 找，GPU 的 class 是 `0x03`/`0x00`，与显示控制器同 class，
  只按 class 会挑错设备——这正是 `bus/pci.rs` 的 `first_of_triple` 存在的理由）。
- 命令队列的提交/回收可以照 `blk` 的环形结构，但 GPU 多一个 `fence_id` 维度。

**不要新开 `gpu.rs` 然后复制一遍环操作** —— 那会变成两份会漂的算术。

---

## 7. 未实施清单

1. **QEMU 接线**：D-1 显式 `-device VGA`、D-2 `-device virtio-vga`、D-3 `-device virtio-gpu-pci`
   （三者都已核实存在）。
2. `virtio` 的 GPU 识别入口（vendor 0x1AF4 + device 0x1050/0x1051…）。
3. D-2 的最小实现（识别 + 握手 + 读配置，**不发 GPU 命令**）。
4. G-1..G-5（§3.2）。
5. **前置 AHE-01（容量）与 AHE-04（screendump 进链）**。

---

## 8. 未验证

- virtio-gpu 的 `GET_DISPLAY_INFO` 在 QEMU 11.1.0 上的实际返回（scanout 数、
  rect 值）：**未跑**。
- 资源 format 的支持集合（`VIRTIO_GPU_FORMAT_*`）在 QEMU 上接受哪些：**未查**。
- `virtio-vga` 的 framebuffer BAR 与 `virtio-gpu-pci` 的 BAR 布局差异：**未读**。
- 双缓冲轮换时 `RESOURCE_FLUSH` 的同步语义（是否需要等上一帧）：**未验证**。

**上述任一条在实施前都要先量**，不许按本文件当事实。
