# ADR-172：NVMe 上挂真 FAT32 卷——`NvmeDisk` 接进 `Block` 路径

状态：已采纳（2026-11-20）
关联：ADR-169（NVMe 驱动三格）、ADR-111（可写 FAT32 夹具）、ADR-110（块层）

> 了结 ADR-169 未决 4「`NvmeDisk` 还没接进 `Block` 的默认路径」。

---

## 一、做了三层里的第三层

| 层 | 用例 | 证什么 | 之前 |
|---|---|---|---|
| 设备 | `t_nvme_all` 三格 | 认到设备、容量对、能读扇区 | ✅ ADR-169 |
| 文件系统 | `t_nvme_fat` | 那块盘上有能挂的卷、文件内容对 | **本文** |

**两层各自能独立红**：设备通了但盘上没卷 ⇒ 文件系统层红；
卷能挂但内容错 ⇒ 宿主机对账红。**不合并成一个布尔。**

---

## 二、盘从「纯图案」换成「真 FAT32 卷」

### 之前

`nvme.img` 是 `qemu-io` 写的全 `0x7E`。它只能证「数据通路通」——
而这已经由设备层三格证过了。

### 现在

1. `tools/make_fat32_rw.py` 生成 1 MiB 的 FAT32 卷（脚本自带读回复算，不成立就退出非零）；
2. `qemu-img resize` 扩到 64 MiB（保留前 1 MiB，后面补零）；
3. QEMU 接线从 `format=qcow2` 改成 `format=raw`（与 AHCI 那几块 FAT 卷一致）。

盘上有：

    /DATA.BIN   1024 字节，2 簇
    /LOG.TXT      64 字节，1 簇

### 图案格判据跟着改（**变强了**）

原来：读扇区 0 全是 `0x7E`。
现在：读扇区 0 是**结构合法的 FAT32 引导扇区**——三条独立特征：

- 偏移 510 的 `0x55AA` 引导签名
- 偏移 82 的 `FAT32   ` 字样（8 字节，尾部补空格）
- 偏移 0 的跳转指令（`0xEB .. 0x90` 或 `0xE9 ..`）

**这比原来更强**：原来只证「能读回我写的字节」，现在证「读回的是一块能被解析的卷」。

---

## 三、为什么用 `Volume::mount` 而不是 `vfs_ro::mount`

`vfs_ro::mount` 那条路是「按口号找 AHCI 盘」，**绑死了设备类型**。
而 `Volume::mount(&dyn Block)` 接受任意 `Block`——这一条要证的正是
「**换一种 `Block` 也能挂**」。

---

## 四、实测读数

    nvme-fat: 几何 簇数=2048 数据起点=66 每簇字节=512 FAT份=2 每份扇区=17 根簇=2
    nvme-fat: 读回 DATA.BIN 大小=1024 走过字节=1024 簇数=2 尾格=512
    nvme-fat: 判据 首8=[0a, 31, 54, 7b, 9e, c5, e8, 0f]
    t_nvme_fat -> ok

    nvme: 读回 扇区0 首8=0x829a1a871be45174 引导签名=true FAT32字样=true 跳转=true
    nvme: 三格 识别=true 容量=true 图案=true

`1024 字节 / 2 簇 / 尾格 512` 与 `make_fat32_rw.py` 的配方**完全一致**。

---

## 五、宿主机侧对账：照抄式子，不 import

`check_nvme_fat` 按 `make_fat32_rw.py` 的 `body(seed, n)` **逐字重算**：

    ((i * 37 + seed * 11) & 0xFF) ^ (seed & 0xFF)
    DATA.BIN 用 body(1, 512) 写两簇

**为什么照抄而不是 import**：那个脚本顶层就跑整份生成逻辑，import 会执行它。

**代价是两边要同步**——而不同步时判据会红，那正是我们要的。

**这一条踩过一次**：第一版我猜 `(i*37 + 0x0A) & 0xFF`（漏了 `^ seed` 与 `seed*11`），
算出来 `0a 2f 54 79 9e c3 e8 0d`，与内核的 `0a 31 54 7b 9e c5 e8 0f` 对不上。
**对账立刻发现**——这就是"两边各自算"的价值：抄错一项就红，而不是两边一起错。

---

## 六、`t_nvme_fat` 必须自己 `init`（用例自足）

第一次跑就红了：

    nvme-fat: 挂载失败 Io(NoDevice)     ← 0x1fd
    nvme: 识别 …                        ← 0x312（**在它之后**）

`.ktests` 的顺序由链接器决定，`t_nvme_fat` 排在 `t_nvme_all` **之前**，
于是 `NvmeDisk` 用时 `STATE` 还是 `None`。

**这是 AGENTS.md「用例必须自足」的又一实例**（§442 是同一类）。
修法：`t_nvme_fat` 自己先调 `nvme::init()`（幂等）。

---

## 七、读数

| 项 | 值 |
|---|---|
| `check` | **18/18** |
| 特性档 | **74/74** |
| `nvme` 档 | **PASS(33)**（设备层三格 + 文件系统层） |
| 判定表 | 77 行（+1：`NVMe 卷上读出文件与宿主机对账`） |

---

## 八、负样本

| 判据 | 负样本 | 红在哪 |
|---|---|---|
| 挂载 | 把盘换成纯图案（`make_nvme_pattern`） | `Volume::mount` 失败 ⇒ `Io(NoDevice)` |
| 文件内容 | 把 `body` 的 seed 从 1 改成 2 | 宿主机按 seed=1 算 ⇒ 首 8 字节不符 ⇒ `CONTENT-MISMATCH` |
| 几何 | 改 `CLUSTERS` 常量 | `簇数 != 2048` ⇒ 对账红 |
| 引导扇区 | 把 `0x55AA` 签名抹掉 | 图案格 `引导签名=false` ⇒ 红 |
| 用例自足 | 删掉 `t_nvme_fat` 里的 `init()` | 若它排在 `t_nvme_all` 之前 ⇒ `Io(NoDevice)` |
| 链走短 | 把 `DATA.BIN` 的 FAT 链改短 | `walk` 返回 `ChainEndsEarly` ⇒ 红 |

---

## 九、未决

1. **`/LOG.TXT` 没读**：它是 1 簇 64 字节，用来证「只覆盖前 64 字节」。
   本条只读 `/DATA.BIN`（2 簇，跨簇）。**读 LOG 能多证一条「单簇小文件」**，
   留给下一轮。
2. **只读挂载，没验写**：`Volume` 是 FAT32 解析器，写方向在 `fs_rw.rs` 那条路
   （AHCI 口 4）。NVMe 的写方向**未验**。
3. **`nvme.img` 每次重造**：`make_nvme_fat` 每跑跑一次 `make_fat32_rw.py` +
   `qemu-img resize`。那要 ~0.2 秒，可接受；但**夹具不进仓库**，
   所以「同一份夹具」这件事靠脚本可复现性担保（与 `make_fat32_rw.py` 的定位一致）。
4. **`format=raw` 的容量对账**：`qemu-img resize` 到 64 MiB，文件大小 = 容量。
   若哪天改成 `qcow2`，容量对账要改成读 `virtual-size`。
