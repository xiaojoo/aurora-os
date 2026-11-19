# Framebuffer 设计

状态：**已实施**（`kernel/src/display/frame.rs`，295 行；`framebuffer` 特性档）

- 相关 ADR：`ADR-083`（显示第一刀：按物理区间自映射 + 宿主机 PPM 判据）、
  `ADR-086`（字形改为点阵资产）、`ADR-087`（中文与双宽格）、
  `ADR-088`（fbcon-live 走终端模式）、`ADR-089`（行规程最小形态）
- 上位：[硬件驱动体系总设计](../Aurora-OS-硬件驱动体系总设计-V1.0.md)

---

## 1. 已实施（实测，不要重做）

### 1.1 为什么自己映射，而不用 Limine 给的地址

源码注释原话：那是 bootloader 在**它自己页表**里建的映射，而本内核在
`mm::take_over` 里换了 CR3 ⇒ 那个地址在我们的页表里不保证存在。

所以 `Frame::init()` 走这条：

```text
limine::framebuffer()            取 FbInfo（几何 + 掩码 + Limine 的 address）
limine::framebuffer_memmap()     取 memmap 里 MemmapType::Framebuffer 那段物理区间
校验 bpp == 32 && memory_model == 1(RGB)
校验 width/height>0、pitch >= width*4、pitch*height <= len
MmioRegion::map(pa, pages*PAGE)  走 mm::map_mmio，PageFlags::DEVICE（PCD/UC-）
```

### 1.2 三格对账（都是实测出来的，不是假设）

```rust
limine_is_hhdm          Limine 的 address == HHDM + pa ?
limine_is_ours          Limine 的 address == 我们映射的 VA ?
limine_mapped_in_ours   Limine 的 address 在**我们自己页表**里映着吗（mm::is_mapped）
```

**为什么不 deref 那个地址"试试看"**：源码注释记了现场
「§236 记过顺着叶子 deref 把内核打挂的现场（run-943，cr2 落在 RAM 之外）。
问页表要答案，不要问硬件。」

### 1.3 像素打包：按掩码，不按枚举

`pack(rgb)` 用**启动信息给的掩码**：

```rust
for (i, &channel) in [rgb>>16, rgb>>8, rgb].iter().enumerate() {
    let (size, shift) = (masks[i].0, masks[i].1);
    let keep = size.min(8);
    let dropped = (channel & 0xFF) >> (8 - keep);      // ← 这一掩不能省
    v |= (dropped << (size.saturating_sub(8))) << shift;
}
```

**为什么按掩码而不是写死 `0xFF0000`**（源码注释）："字段宽度不足 8 位时高位要丢掉，
而移位量是 bootloader/固件给的——不同机器上 BGRA 与 RGBX 都出现过。
硬编码的结果是'画出来了但颜色不对'，那种错不会让任何判据变红。"

**`dropped` 那一掩也不能省**：8/8/8 上"不掩"恰好也对（每个字段写进去的都是
原值的高位前缀），但换 5/6/5 面板就会串色，而串色同样不会让任何判据变红。

### 1.4 双缓冲（行级脏标记）

```text
BACK: static [u32; 1280*800]     离屏缓冲（紧凑排，不含 pitch）
ROW_DIRTY: static [bool; 800]    行级脏标记
present(): 只搬脏行
```

**为什么行级而不是整帧**（源码注释）：QEMU 软件 MMIO 下整帧搬 4 MB 是点击卡顿的
主因；指针/输入行只脏十几行，开销降一个量级。

**为什么 BACK 是 `static mut` 而不是堆**：4 MB 级 BSS，且**堆上限 2048 字节**
（`memory/heap.rs` 的 `LARGE_MAX`）——进堆直接 OOM。

### 1.5 绘图原语

| 原语 | 用途 | 注意 |
|---|---|---|
| `put(x,y,rgb)` | 写 24 位色（内部打包） | 越界返回 `OutOfBounds`，**不夹到边界** |
| `put_raw(x,y,packed)` | 写已打包值 | **滚动必须用它**（见下） |
| `put_mix(x,y,rgb,a15)` | 按覆盖率混色 | 指针抗锯齿边缘 |
| `get(x,y)` | 读回 | **只证"字节还在我们映射的窗口里"** |
| `fill(rgb)` | 全屏填充 | — |
| `draw_test_pattern()` | 可独立复算的图案 | 见 §2 |
| `samples()` | 图案上的采样点 | 宿主机用**同一份算法**独立复算 |

**`put_raw` 为什么必须存在**（源码注释）：`put` 收 24 位色再打包，
而滚动拿到的是 `get` 读回来的原生值，再打包一次就是二次转换——
在 8/8/8 上看不出来，换上窄字段面板就会把自家滚动画糊掉，而且不报错。

---

## 2. 判据

### 2.1 内核侧（只证窗口自洽）

`draw_test_pattern()` 画：上半全黑、下半从左到右红/绿/蓝三等分。
`samples()` 给四个采样点（几何算出，不写死分辨率）：上左黑、下左红、下中绿、下右蓝。

内核写后读回、逐点比对 ⇒ 打印 `frame: 图案已画 采样点数=N 读回不符点数=0`。

**这一行只证"窗口自洽"**（源码注释原话），不证画面真伪。

### 2.2 宿主机侧（第二台仪器）—— **今天不在链里**

**实测缺口**：`tools/aurora.py` 里 `screendump` **零命中**。
screendump 脚本全在 `.scratch/`（`s57-drag-check.py`、`s6q_flicker.py` 等），
而 `.scratch/` 被 `.gitignore` 挡着、**零个文件被跟踪**。

**所以**：显示域**今天没有任何进判定表的宿主机对账**。
这是 [总设计 §3.7](../Aurora-OS-硬件驱动体系总设计-V1.0.md) 指出的最大缺口。

### 2.3 补法（AHE-04）

| 新增 | 形状 |
|---|---|
| `tools/aurora.py` 内 `qmp_screendump(port, path)` | 复用已有 `qmp_snapshot`（`:2993`）的 socket 形状 |
| `check_frame_ppm(ppm, log)` | 按 `frame.rs::samples()` 的**同一份算法**独立复算四个点 |
| 判定表新增行 | `("帧缓冲图案与宿主机PPM对账", ..., "PASS", 33)` |
| 负样本 | 改 `draw_test_pattern` 的色条顺序 ⇒ 必须红在"下左红"那一点 |

**两条必须注意的坑**（`.scratch/s6h_docs.py` 记过）：

1. **`screendump` 返回 ≠ 文件已落盘**：不等会读到**上一版** PPM
   （那一次解码出满屏 `?`）。
2. **冻结契约**：`fbcon::freeze_band()` 一旦调用，之后所有写入是 no-op；
   内核必须在串口打 `fbcon: 已冻结 …`，宿主机以这行为准再 dump。
   契约两端都可测：串口少了这行 ⇒ 夹具等不到；画面还在变 ⇒ 两次采样不一致。

---

## 3. 已知限制（写清，不是待办）

| 限制 | 值 | 影响 |
|---|---|---|
| 只接受 32bpp + RGB | `SUPPORTED_BPP=32`、`MEMORY_MODEL_RGB=1` | 非此形状**直接拒**（`UnsupportedMode`，带实际值） |
| BACK 容量 | `1280*800` | 超过 ⇒ `enable_double_buffer()` 返回 false，**退回直写**（不硬画） |
| `ROW_DIRTY` | 800 行 | 与 BACK 同界 |
| 单显示器 | 只有第 0 个 framebuffer | `limine.rs` 读 `framebuffers[0]` |
| 无分辨率切换 | — | 模式在启动期定死 |
| 无热插拔 | — | **UEFI GOP 没有热插拔语义**；写进里程碑会让"通过"永不达成 |

---

## 4. 要不要支持 24bpp / 16bpp（本设计的选择）

**原草案给了一个 `PixelFormat { Rgb888, Bgr888, Xrgb8888, Xbgr8888 }` 枚举。
本文明确反对**，理由见 [总设计 §3.3](../Aurora-OS-硬件驱动体系总设计-V1.0.md)：
枚举把"设备说了算"改回"我们猜"，方向正好相反。

**真正的缺口**是 `frame.rs:76` 直接拒掉非 32bpp：

```rust
if info.bpp != SUPPORTED_BPP || info.memory_model != MEMORY_MODEL_RGB {
    return Err(FrameError::UnsupportedMode { bpp, memory_model });
}
```

**改法**（分级支持，保留掩码打包）：

1. 32bpp（今天）：`region.write32`，一次一像素。
2. 24bpp：按掩码拆字节写（3 字节/像素，注意 pitch 可能不是 `width*3`）。
3. 16bpp（5/6/5 等）：`write16`，掩码打包已经能处理字段宽度。

每种宽度**一条用例 + 一条变异**（把字段宽度写错一位 ⇒ 串色 ⇒ 红）。
`UnsupportedMode` 保留给真正不支持的形状（索引色等），且**必须打印实际值**
（今天已在打印）。

---

## 5. 与 `fbcon` 的分工（一层不许越过另一层）

```text
frame：像素怎么落到显存（几何、掩码、越界、双缓冲）
fbcon：字符怎么变成像素（字形资产、双宽格、浮窗、标签条）
       —— 每一次像素写入都经 Frame::put，自己零 unsafe
```

`fbcon.rs` 4968 行，零 `unsafe`（源码注释：「本文件零 `unsafe`：所有像素写入都走
`crate::frame::Frame::put`，越界由它判」）。这个边界**不要打破**。

---

## 6. 未实施清单

1. `qmp_screendump` 进 `tools/aurora.py` + `check_frame_ppm` + 判定表一行 + 负样本。
2. 24bpp / 16bpp 的分级支持（§4），各一条用例与变异。
3. `Frame` 的几何读数进 `devctl status`（今天只能从串口日志看）。
4. **不做**：分辨率切换、多显示器、热插拔（§3）。
