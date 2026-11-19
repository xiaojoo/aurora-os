# QEMU 硬件测试规范

状态：**部分实施**（18 门禁 + 74 行判定表 + 73 特性档已通；显示/输入的第二台仪器不在链里）

- 上位：[硬件驱动体系总设计](../Aurora-OS-硬件驱动体系总设计-V1.0.md)
- 相关：[真机测试规范](真机测试规范.md)、[硬件兼容性矩阵](硬件兼容性矩阵.md)

---

## 1. 唯一入口与铁律

```powershell
$env:PYTHONIOENCODING='utf-8'; $env:PYTHONUTF8='1'
python tools/aurora.py build     # 构建（含夹具 ELF 产物）
python tools/aurora.py image     # 造引导镜像
python tools/aurora.py run       # 单跑一档（--features / --host-fault / --timeout）
python tools/aurora.py test      # 判定表（74 行）
python tools/aurora.py bench     # 四把尺子（P1/P2/P3/P4）
python tools/aurora.py check     # 18 道静态门禁
python tools/aurora.py ktests    # 只跑内核用例
python tools/aurora.py release   # 发布检查
```

### 1.1 铁律一：必须带 UTF-8 环境

本机控制台是 **GBK**。不带 `PYTHONIOENCODING=utf-8 PYTHONUTF8=1` 时中文日志读成乱码，
而判定表里**大量判据按中文锚点匹配** ⇒ 会静默读成"零条记录" ⇒ 判据变成空转。

**这条不是"建议"，是本机的既有事实。**

### 1.2 铁律二：只记取证跑那一轮的数

跨轮比 `serial_bytes`（P4 那把尺子）**只能用 bench 那四跑**。
`do_test` 的正向跑之前不 unlink 镜像，它的读数取决于 `ensure_image` 有没有重造
（变体名或 ELF sha 不符才重造）——实测同一份代码不同来路差过 274 字节。

### 1.3 铁律三：`.ktests` 的顺序由链接器决定

用例必须**自足**，不能假设别的用例已经认领过设备。搬迁模块会改串口行序，
"逐行 diff 一致"这种判据要先归一行序。

---

## 2. 判定表（74 行）

### 2.1 形状

```python
rows = [
    ("行名", 实际值, 退出码变量, "期望判定", 期望退出码),
    ...
]
logs = { "行名": 那一跑的串口日志变量, ... }
```

### 2.2 判定值契约

| 判定 | 退出码 | 含义 |
|---|---|---|
| PASS | 33 | 正常完成 |
| FAIL | 35 | 用例/判据不成立 |
| BOOT-INVALID | 37 | 前提不满足 ⇒ **不启动** |
| EXCEPTION | 39 | 运行中停机（L4） |
| HANG | -1 | 挂死（**也是一种期望结果**） |
| CONTENT-MISMATCH | 33 或 35 | 内核绿但宿主机对账不上 |
| SEQ-BROKEN | 同上 | 多跑序列不对 |

**最后两个是本仓库的关键设计**：它们把"被测物坏了"与"量具对不上"分开。
只有 33/35 两级时，一次对账失败会看起来像内核崩了。

### 2.3 `check-matrix-wiring` 抓的四类撞车

这道门禁**专门抓"某一行静默变成另一行的副本"**：

1. 行名重复；
2. `logs` 表里没有该行的日志（红的时候打不出成因）；
3. 两行共用同一份串口日志变量；
4. 两行共用同一个退出码变量；
5. （第三种形状）判定值那个名字被**别的语句**重新赋过。

第 5 条是实测买来的：「`ov = EVF_OV_RE.search(evlog)` 撞上了
`ov, orc, olog = do_run(["fault-heap-oom"])` ⇒ 那一行的实际值变成一个 Match 对象，
看起来像被测物坏了，其实是量具在互相覆盖」。

---

## 3. 四类测试在本仓库的落法（不是另起一套）

| 类别 | 对应物 | 今天的覆盖 |
|---|---|---|
| 单元测试 | `ktest!` 的纯函数用例（`t_ps2_kbd_decode`、`t_madt_offsets_synthetic`、`t_pci_config`…） | **151 条**注册 |
| 硬件集成 | 判定行 + `--features` 挂设备 | 存储/网络/中断/内存覆盖较好 |
| 端到端 | ring3 探针（`KT_PROBE_RING3`、`KT_FS_OPEN_RING3`、`KT_SDKDEMO`） | 文件/进程/凭据覆盖 |
| 故障注入 | `fault-*` 特性 | **25 个**（锁/堆/中断/TLB/AHCI/GPT/FAT/句柄） |
| **第二台仪器** | pcap / `qemu-img` / `-d int` / `pmemsave` / `validate_esp.py` | **缺显示与输入** |

**结论**：不需要新框架。**需要补的是显示/输入的第二台仪器**（§5）。

---

## 4. 第二台仪器清单（已进链的）

| 设备 | 仪器 | 在哪 |
|---|---|---|
| 磁盘 | `qemu-img info --output=json` 的 virtual-size | `aurora.py:668` |
| 磁盘内容 | `qemu-io` 写图案 + 内核读回对账 | `aurora.py:690` |
| 磁盘（写方向） | 跑完后宿主机从镜像读回校验 | `check_scratch_write` / `check_fs_rw_image` |
| 网卡 | QEMU `filter-dump` 写 pcap + 宿主机独立重算帧 | `aurora.py:3890` |
| 中断投递 | QEMU `-d int` 日志（`SP` 的高位分 BSP/非 BSP） | `aurora.py` 的 `check_irq_trace` |
| 中断边沿 | `-d int` 的 raise 与投递一对一 | `check_edge_absorption` |
| 崩溃现场 | QMP `pmemsave` 读回物理内存 | `aurora.py:3088` |
| GPT/FAT16 | `validate_esp.py` 独立重算 | `tools/validate_esp.py` |
| ECDSA/SHA | CPython `hashlib` 逐字核对 | `check_sha256` |
| 签名包 | 宿主机自己的实现读+验+篡改 | `check_sig_package` |

**共同规矩**：两边**各自算**，不互相抄。谁抄谁，"两边都错"时判据是绿的。

---

## 5. 缺的第二台仪器（本文档要补的）

### 5.1 显示：QMP `screendump`

**实测缺口**：`tools/aurora.py` 里 `screendump` **零命中**。
脚本全在 `.scratch/`（`s57-drag-check.py`、`s6q_flicker.py`、`_s6g_look.py`、`_s6h_docs.py`），
而 `.scratch/` 被 `.gitignore` 挡着、**零个文件被跟踪**。

**补法**：

```text
1. aurora.py 加 qmp_screendump(port, path)
   —— 复用已有 qmp_snapshot（:2993）与 qmp_pmemsave（:3088）的 socket 形状
2. 加 check_frame_ppm(ppm, log)
   —— 按 frame.rs::samples() 的**同一份算法**独立复算四个采样点
3. 判定表加一行
4. 负样本：改 draw_test_pattern 的色条顺序 ⇒ 红在"下左红"
```

**两个必须知道的坑**（`.scratch/s6h_docs.py:57` 记过）：

1. **`screendump` 返回 ≠ 文件已落盘**。不等会读到**上一版** PPM
   （那次解码出满屏 `?`）。建议等 1.0–1.5 s。
2. **冻结契约**：`fbcon::freeze_band()` 之后所有写入是 no-op；
   内核必须在串口打 `fbcon: 已冻结 …`，宿主机以这行为准再 dump。

### 5.2 输入：QMP `input-send-event`

**实测缺口**：`tools/aurora.py` 里 `input-send-event` / `send-key` **零命中**。

**注意**：`serial-rx-probe` 走的是**串口**喂字节（`chardev:serialrx`），
**不是 QMP 键盘注入**。这两件事不要混。

**补法**（与显示同形状）：加 `qmp_input_event(port, kind, code, down)`，
判据是"注入的按键到达 InputEvent"。**这一条同时解锁 PS/2 与未来的 USB HID**。

---

## 6. 门禁（18 道）

| 门禁 | 管什么 | 本轮读数 |
|---|---|---|
| `check-lints-wired` | 全 workspace 成员的 `[lints] workspace = true` | ok |
| `check-unsafe` | 登记表 ↔ 源码普查**逐格**对账 | ok（523 处：U1 85/U2 119/U3 13/U4 142/U5 128/U6 36） |
| `check-crates` | `docs/architecture/crates.toml` ↔ `cargo metadata` | ok |
| `check-module-interfaces` | 18 个逻辑模块 ↔ 源码双向对账（含 SCC 与棘轮） | ok |
| `check-vector-table` | 具名中断向量登记 | ok |
| `check-interface-change` | 改登记表必须有 ADR 改动 | ok |
| `check-driver-ctx` | 驱动不许裸访问（`driver/ahci.rs`、`driver/virtio.rs`） | ok |
| `check-state-window` | 持久状态区记录格式 | ok |
| `check-virtio-pattern` | 夹具图案字节 ↔ 内核期望值 | ok |
| `check-fat32-ports` | 口号 ↔ `FS_OPEN_PORTS`；楔子仪器符号 | ok |
| `check-net-pattern` | 帧形状常量 ↔ 宿主机重算那份 | ok |
| `check-sha-primitives` | SHA-256 的 IV/K 按**定义**重算 | ok |
| `check-sig-anchor` | 签名锚点字节 | ok |
| `check-pkg-manifest` | 包清单（`docs/pkg/manifest.json`） | ok |
| `check-sbom` | SBOM（`docs/release/sbom.json`） | ok |
| `check-matrix-wiring` | 判定表的行与证据一一对应 | ok |
| `check-verdict` | 退出码契约（`diag/exit.rs` ↔ `aurora.py`） | ok |
| `check-nofloat` | 内核镜像里无浮点/向量指令 | ok（反汇编 108706 行，命中 0） |

**每条门禁都配了负样本**（`AGENTS.md`：每条新规则都要一个能让它变红的变异）。

---

## 7. QEMU 拓扑（今天的事实）

| 项 | 值 | 来源 |
|---|---|---|
| 机器 | `-M q35` | `aurora.py:3823` |
| CPU | `-cpu max`（**必需**：默认 `qemu64` 的 smep/smap/x2apic 全 false） | 同上 |
| 核数 / 内存 | `-smp 4` / `-m 512M` | `aurora.py:57-58` |
| 固件 | 两块 pflash（code 只读 + vars 每次重拷） | `aurora.py:3824-3825` |
| 显示 | **`-display none`，无 `-vga`** | `aurora.py:3830` |
| 串口 | `-serial file:build/serial.log` | `aurora.py:3827` |
| 退出 | `isa-debug-exit,iobase=0xf4,iosize=0x04` | `aurora.py:3829` |
| QEMU 版本 | **11.1.0** | 实测 `--version` |

**可用设备（已核实存在）**：`virtio-gpu-pci`、`virtio-vga`、`nvme`、`qemu-xhci`、
`usb-kbd`、`usb-mouse`、`intel-iommu`、`e1000`、`e1000e`、`igb`、`rtl8139`、
`pcie-root-port`、`ich9-intel-hda`。

---

## 8. 新增一档的检查清单

新驱动/新设备要进链，必须**同时**改这些，缺一样就是"看起来绿、实际没测"：

- [ ] `kernel/Cargo.toml` 加特性（名字进 `-C metadata`，会改 crate disambiguator）
- [ ] `tools/aurora.py` 的 `*_FEATURES` 集合 + QEMU 命令行加设备
- [ ] 判定表加行（**行名唯一、各拿自己那一跑的日志与退出码**）
- [ ] 负样本（能红一次，还原后绿）
- [ ] `DRIVER_MODULES`（若新驱动有裸访问风险）
- [ ] `docs/architecture/module-interfaces.toml` 的 `source_modules`
- [ ] 若是新产品包：`docs/architecture/crates.toml` + `docs/release/sbom.json`
- [ ] 若新增 `unsafe`：`unsafe-whitelist.toml`（七项登记）
- [ ] 若新增锁：`lock-order.md`
- [ ] 若改接口：ADR（`check-interface-change` 会拦）

**"不加特性、只改代码"这条路不存在**：不带特性的用例不注册，
判据也不会假装"过了"。
