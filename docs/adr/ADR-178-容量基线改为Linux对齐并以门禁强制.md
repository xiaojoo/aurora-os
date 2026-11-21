# ADR-178：容量基线改为 Linux 对齐，并以门禁强制

状态：**已采纳**（2026-11-22，使用者裁决「里面的配置要按 Linux 配置参数来，如果 Linux 有待优化的可以
在基础上优化但要有依据，不要以开发机的配置做硬件参考」）

关联：ADR-065（VA 保留表容量与 sched 解耦）、ADR-070（地址空间）、ADR-075（每 AS 页表）、
ADR-007（句柄表 16→用户放宽）、ADR-106（号段与错误码扩展）、ADR-176（E_NOSYS）

> 写作纪律：本文每个「Linux 值」都带源码出处；每个「取舍」都标 `is_tradeoff` 并写理由。
> 没有出处的数字不许进 `capacity-baseline.toml`。

## 背景：为什么要改

### 1. 实测现状（2026-11-22）

源码里所有容量常量都是「按开发机够用」定的，注释里自己写着：

    MAX_ADDR_SPACES: 「今天无 workload 依据，按接缝够用定尺」
    MAX_PROCESSES = 4、MAX_ADDR_SPACES = 8、MAX_HANDLES = 64

那在 4 核 2 GiB 的 QEMU 里够用。**装到真机上立刻撞墙**：4 个进程、64 个句柄，
连 shell 跑几条命令都不够。使用者明确要求停止以开发机为参考。

### 2. 一个结构性障碍（实测）

`MAX_PROCESSES` 提不上去不是「没改数字」，是**装不下**：

    pub const NO_ASPACE: u8 = 0xFF;   // 哨兵
    pub as_slot: u8,                  // 上限 255
    aspace: u8,                       // 上限 255

每个进程要一张 AS，AS 槽号是 `u8` ⇒ **理论上限 254**。所以「扩到 1024/32768」在
位宽不改时结构上不可能。ADR-178 因此把位宽作为**第一等交付**，不是附录。

## 决策

### 决策 1：建立 `docs/architecture/capacity-baseline.toml` 作为唯一来源

与 `crates.toml` / `module-interfaces.toml` / `vectors.toml` 同一套纪律：
**机器可读 + 门禁双向对账**。

文件结构（三层）：

    [[linux]]   Linux 的原始常量，只作依据，Aurora 不改
    [[const]]   Aurora 自己的容量，每项必须带 linux_source +（若取舍）reason
    [slot_width] / [memory_cost]  位宽前提与内存自检

**硬规则（门禁强制）：**

1. 每个 `[[const]]` 必须有 `linux_source`；没有直接对应项的写「Linux 无等价物」。
2. 标了 `is_tradeoff = true` 的必须有 `reason`。
3. 源码里每个 `MAX_*` 容量必须在文件里登记。
4. `MAX_ADDR_SPACES` 必须装得进槽号位宽。

### 决策 2：Linux 依据（全部取自 Linux 主线源码）

| Linux 常量 | 值 | 出处 |
|---|---|---|
| `PID_MAX_DEFAULT` | 32768（0x8000） | `include/linux/threads.h` |
| `PID_MAX_LIMIT` | 4194304 | `include/linux/threads.h` |
| `MAX_THREADS` | 2^30-1（`FUTEX_TID_MASK`） | `kernel/fork.c` |
| `MIN_THREADS` | 20 | `kernel/fork.c` |
| `NR_OPEN` | 1024 | `include/uapi/linux/limits.h` |
| `sysctl_nr_open` | 1048576 | `fs/file.c` |
| `NR_OPEN_DEFAULT` | 64（`BITS_PER_LONG`） | `include/linux/fdtable.h` |

**`threads-max` 不是常量而是公式**（`kernel/fork.c` `set_max_threads()`）：

    threads = (nr_pages * PAGE_SIZE) / (THREAD_SIZE * 8)
    threads = clamp(threads, MIN_THREADS=20, MAX_THREADS=2^30-1)

**含义：线程结构只许占物理内存的 1/8。** 那个 `* 8` 就是这条纪律。
我们照此实现（`capacity-baseline.toml` 的 `[thread_limit]`）。

### 决策 3：Aurora 的目标值

| 常量 | 旧值 | 新值 | 依据 | 取舍？ |
|---|---|---|---|---|
| `MAX_PROCESSES` | 4 | **32768** | 对齐 `PID_MAX_DEFAULT` | 否 |
| `MAX_ADDR_SPACES` | 8 | **32768** | 每进程一张 AS，必须相等 | 否 |
| `MAX_HANDLES` | 64 | **131072** | `sysctl_nr_open` 的保守子集 | **是**（见下） |
| `MAX_JOBS` | 4 | **1024** | Linux 无 Job；1024×32=32768 自洽 | **是** |
| `MAX_TASKS` | 12 | **256** | Linux 动态；256/CPU 是定长取舍 | **是** |
| `MAX_TASKS_SUPPORTED` | 12 | **256** | 容量契约，须 ≥ `MAX_TASKS` | 否 |
| `MAX_VA_RESERVATIONS` | 256 | **65536** | Linux 用 maple tree 动态 | **是** |
| `MAX_LAZY_REGIONS` | 8 | **4096** | 同上 | **是** |
| `MAX_LAZY_PAGES` | 16 | **4096** | 同上 | **是** |
| 槽号位宽 | u8 | **u16** | Linux `pid_t` = s32 | 否 |

**取舍的如实说明（不藏）：**

- `MAX_HANDLES` 全局表 vs Linux 每进程 `files_struct`。131072 = 32768 进程 × 4 个基础句柄。
  **结构差异不因改数字而消失**，per-process fd 表是 ADR-179 的事。
- `MAX_TASKS` 是定长表。Linux 用动态分配，我们按 CPU 静态分配 per-CPU 数组。
  256 是「在 target_min_cpus=2 下给 512 任务槽」的取舍。
- 惰性区间与 VA 保留表同理：Linux 用 maple tree，我们用定长表。

### 决策 4：内存代价必须写进配置并自检

    ProcEntry    ~20 B  × 32768 = 0.6 MiB
    AspaceEntry ~152 B  × 32768 = 4.75 MiB
    静态表合计 ~5.4 MiB（target_min_ram_mib=1024 时占 0.54%）

**运行时（按需，不是静态）**：每进程 PML4 4 KiB + 内核栈 32 KiB = 36 KiB；
32768 进程全开需 **~1.15 GiB**，超过 `target_min_ram_mib=1024`。

**这是已知边界，不是 bug**：真实负载不会 32768 进程同时跑满；静态表启动即占，
运行时按需才涨。该数字写进 `[memory_cost]`，改容量时必须重算。

### 决策 5：门禁 `check-capacity-baseline`（第 20 道）

`python tools/aurora.py check` 新增一道，判据四条（见决策 1）。

**判据范围如实记录（这是本 ADR 里最容易做错的一处）**：

只扫 `MAX_` 前缀。第一版只扫 `pub const MAX_*`，于是 `AS_PT_SLOTS`（每张 AS 的页表页
上界，货真价实的容量）**漏网**——门禁报「登记了但源码里没有」，查半天才发现它压根不在
扫描范围。**那种漏网比不扫更坏**：门禁看起来在工作，实际有一类容量永远不受检。

但把范围放宽成「名字含 MAX/SLOTS/PAGES/...」也错了（同一轮实测）：它一口气卷进 **38 个
协议常量**——`COPY_MAX=4096` 是协议上限不是表长、`NAME_MAX=12`/`PATH_MAX=256` 是格式宽度、
`NET_TX_MAX=1514` 是 MTU、`IDT_ENTRIES=256` 是 x86 硬件规定（不由我们选）。
要求它们「举证 Linux 依据」是错的要求。

**最终判据：`MAX_` 前缀 = 我们选的容量。** 非 MAX_ 的容量例外必须显式登记，
走「登记了但源码里找不到」分支时用宽松正则再确认一次。

### 负样本（变异证红，都跑过）

| 负样本 | 期望 | 实测 |
|---|---|---|
| 把某容量改成与基线一致 | 该条消失，条数 −1 | **10 → 9，消失** ✅ |
| 新增一个未登记容量 | 精确点名 | `MAX_UNREGISTERED_TEST = 123` 被点名 ✅ |

## 影响

1. **`check` 从 19 道变 20 道。** 当前 **10 条红**——这不是回归，是门禁刚立、
   内核还没跟上。九条「值不符」+ 一条「位宽装不下」，正是要做的活。
2. **位宽扩容是其他一切的先决条件。** `u8 → u16` 涉及 9 个文件 59 处，
   且 `sched/mod.rs` 有 `assert!(MAX_TASKS <= MAX_TASKS_SUPPORTED)` 会保护顺序。
3. **`AGENTS.md` 的「已知脆性」段要更新**（旧措辞把 8/16/64 写成事实）。
4. 不改任何 ABI：`MAX_STARTUP_HANDLES=16` 是 ABI 承诺，本次**不动**（已在配置里标明「ABI 冻结」）。

## 未决

1. **位宽扩容的实施顺序**（先改位宽还是先改值）——本 ADR 只裁决「位宽必须是 u16 才装得下」，
   实施切片顺序由下一轮定。
2. **per-process fd 表**（`MAX_HANDLES` 的取舍何时消掉）——ADR-179 范围。
3. `AS_PT_SLOTS=16` / `MAX_AS_MAP_PAGES=16` 在 AS 容量扩到 32768 后是否还够——
   **已知欠账，本轮未动**。
4. `MAX_CPUS=8` 是否要按 Linux `CONFIG_NR_CPUS=64` 提——涉及 per-CPU 数组全量重算，
   本轮只登记依据，**未改值**。