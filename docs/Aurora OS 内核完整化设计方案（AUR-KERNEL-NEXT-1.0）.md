# Aurora OS 内核完整化设计方案（AUR-KERNEL-NEXT-1.0）

基于 aurora-os-main（2026-11-07 版）· 对照手册 V1.2 §14 与 BACKLOG §1–§86

> 读法说明：我在沙箱里读了源码和文档，**没有构建、没有跑 QEMU**（沙箱无 QEMU 也无网络）。「现状」来自源码行为和你在 BACKLOG 里记录的实测，我没有复测；属于我推断的地方会写「推断」。工作量数字是量级估计，不是承诺。

## 0 一页结论

**位置**：M0–M3 完成（仅 QEMU）。M4 用户态闭环已通，但只在 ktest 里跑——产品启动路径不装载任何用户程序。capability 句柄表落了第一刀（`handles` 特性，16 格，只有 File 一种对象）。存储、网络只有驱动雏形。`kernel/src` 约 2.6 万行 Rust，其中 `main.rs` 单文件 7,617 行（含 74 个用例）；BACKLOG 记录的门禁是 41 行判定矩阵、`check` 14/14、`fat32-exec` 档 61/61 用例。

**离「完整内核」的五道结构性墙**（按依赖顺序，前一道不拆，后一道做不了）：

1. **没有阻塞**：无 `yield`、无等待队列、无 `sleep`、无定时器轮、任务不迁移。驱动、IPC、socket 全都需要「等」。
2. **内存只够内核自用**：堆单次 ≤ 2048 字节，VA 保留表 24 条，页帧没有元数据（无引用计数）⇒ 做不了大缓冲、共享内存、COW、页缓存。
3. **没有进程**：全系统一个 CR3，用户页只是低半区的一段窗口。
4. **对象与调用太少**：对象只有 File，系统调用号 10 个（`match` 分发），句柄表是全局 16 格而不是每进程。
5. **存储/网络上层缺失**：无请求队列、页缓存、可写文件系统、协议栈，全轮询。

**建议路线**：W0 结构债 → W1 调度阻塞 → W2 内存 → W3 进程与地址空间 → W4 对象与 IPC → W5 存储 → W6 中断化驱动 → W7 网络 → W8 安全与可靠 → W9 真机与电源，合并为六个阶段 S1–S6，出口门是 K-Complete 1.0（§2）。**下一步直接做 S1**，任务卡见 §6。

**最大的一个决定**是进程模型（§3 D1）：我建议 capability-native、内核不提供 `fork`。全部待你拍板的决定集中在 §9。

## 1 现状盘点

| 子系统 | 已有 | 阻塞完整化的缺口 | 依据 |
| --- | --- | --- | --- |
| 启动/CPU/中断 | Limine、GDT/IDT/TSS/IST、LAPIC/IOAPIC、AHCI 的一颗 MSI | x2APIC、PCID（QEMU 测不到）、中断重映射 | BACKLOG M3a、M5-g |
| 内存 | PMM/VMM、8 档 slab 堆、VA 保留、shootdown、45 MiB 回收 | `split_huge`、大块分配、页帧元数据、缺页处理、MMIO 高地址窗口、位图按 4 GiB 静态 | `heap.rs` LARGE\_MAX；BACKLOG M2 |
| 调度 | 每 CPU 队列、时钟抢占、AP 跑调度 | 无 yield/block/sleep/wait、无迁移、无优先级、Done 槽不回收、每 CPU 8 个任务、AP 工人常驻自旋 | `sched.rs`；BACKLOG M3b/M4 |
| 用户态 | int 0x80 + SYSCALL、ELF 加载、`copy_*_user`、SMEP/SMAP、`SYS_EXIT` 回收 | 无进程、单 CR3、10 个调用号、产品路径不载用户程序、无 init | `user.rs`；user-abi 设计 §1 |
| Capability | `handle.rs` 862 行：16 格、owner 两格、READ+DUP、号 8/9/10 | 仅 File、全局表而非每进程、特性开关后才有、`dup` 不共享游标 | BACKLOG 86 |
| 存储 | AHCI 读写、virtio-blk、DMA、状态区 | 全轮询同步、一次一扇区；无请求队列/页缓存/GPT 分区；无 NVMe | BACKLOG M5 |
| 文件系统 | FAT32 只读 + 153 行薄 VFS | 无写、无挂载表、无 fd、无 tmpfs/initramfs/devfs | `vfs.rs`、`fat32.rs` |
| 驱动框架 | `DriverCtx` 句柄表（8+8 写死） | virtio MSI-X/共享 INTx 未走；`set_timer`/`log` 未兑现；无隔离名单/重启；IOMMU 表内容空 | M5-e/g |
| 网络 | virtio-net 收发 + 一次 DHCP 往返 | 无 ARP/IP/UDP/TCP/socket；全轮询；无 fuzz | M8-a |
| 可靠/安全 | boot\_guard、crash V2 + 栈符号化、日志环、watchdog 检测、SHA-256 + Lamport 验签、SBOM | 验签未接启动决策；无 A/B；无处置；无 fuzz；无 KASLR/KPTI 决策 | M6/M9 |
| 时间/电源 | PIT/LAPIC/TSC 标定 | 无 RTC/HPET 墙钟；无关机/重启；无 AML | M3a、M5b |
| 工程 | 矩阵 41 行、`check` 14 道 | `main.rs` 7.6k 行测试与实现同文件；矩阵单次 95 s 以上；无主机侧可 fuzz 的 crate | BACKLOG M2-c |

## 2 K-Complete 1.0 验收定义

「完整内核」= 下面十条全部成立。每条都要有**独立见证**（沿用你的方法：内核自判不算证据，要有宿主机对账或第二份实现，并且至少一条变异能把它变红）。

| # | 能力 | 通过条件 | 独立见证 |
| --- | --- | --- | --- |
| 1 | 进程隔离 | 两进程同一 VA 内容互不可见；杀 A 不影响 B；回收后台账回基线 | 串口标签宿主机对账；变异：共用 PML4 用户半区 ⇒ 红 |
| 2 | 阻塞与定时 | 4 核生产者/消费者无丢唤醒；sleep 误差有界；idle 真 `hlt` | wake/block 序号对账；`-d int` 数 hlt 与 IPI |
| 3 | 内存 | 64 KiB–16 MiB 分配释放回基线；按需清零；COW；共享内存对象 | 台账 + 引用计数自洽；变异：漏 `put` ⇒ 红 |
| 4 | 对象与 IPC | Process/Thread/Vmo/Channel/Event/Timer/Interrupt/File/Socket；句柄可经 Channel 转移并收窄 | 沿用 ADR-007 的 12 条负样本 |
| 5 | ABI 1.0 | 表驱动分发；每号有参数描述与权限要求；随机参数 fuzz 一小时无 panic | 宿主机种子驱动的用户态 fuzz |
| 6 | 文件系统 | FAT32 读写 + tmpfs + initramfs + devfs；挂载表；fd 即句柄 | 宿主机独立 FAT32 解析器写后复验 |
| 7 | 块与存储 | 请求队列 + IRQ 完成；AHCI/virtio-blk/NVMe；GPT；页缓存 | qemu-io 读回哈希（沿用 M5-b/c） |
| 8 | 网络 | ARP/IPv4/ICMP/UDP/TCP + socket + DHCP 四次握手 | hostfwd TCP 回显 + pcap 逐帧对账（沿用 M8-a） |
| 9 | 可靠与安全 | 验签进启动决策；A/B；驱动隔离与重启；解析器 fuzz | 宿主机第二实现重算；变异证红 |
| 10 | 时间/电源/真机 | 墙钟；关机/重启；至少一台真机按串口日志通过 | 真机串口日志宿主机判定 |

**非目标**（K-Complete 之后再说）：显示/GUI、POSIX 兼容层、IPv6、NUMA、自有日志/CoW 文件系统、USB 存储、WiFi/蓝牙、虚拟化。

## 3 关键架构决策（拟 ADR-039…047，先写 ADR 再编码）

| ADR | 议题 | 建议 | 主要代价 |
| --- | --- | --- | --- |
| 039 | 进程与地址空间模型 | 每进程一份 PML4，内核半区顶层项共享；capability-native 创建（见 D1） | 现有用例的单 CR3 假设要全部改写 |
| 040 | 阻塞、等待、定时 | `WaitQueue` + 每 CPU 定时器轮 + resched IPI；睡眠锁建在其上 | 新增锁 rank 与 IPI 向量，要改 lock-order.md |
| 041 | 内存分层 | 页帧元数据 + 引用计数；大块走 `phys_alloc(order)` + HHDM 直接寻址（不占 VA 保留表）；堆保持 ≤ 2048 | 帧元数组要按内存映射动态分配 |
| 042 | 对象与句柄泛化 | 沿用 `slot:u16 + gen:u48`，表改每进程、动态大小；补 MAP/TRANSFER/WAIT/SIGNAL 权限 | 需给每进程加上限，避免耗尽 |
| 043 | 系统调用与 ABI 1.0 | 表驱动、编号即下标、`aurora-abi` crate 生成两侧常量；1.0 起只加不改 | 冻结后的错误码/调用号改不回去 |
| 044 | 块层与页缓存 | 异步 `submit` + IRQ 完成；完成路径「只叫醒不放行」 | 写回线程与 `fsync` 语义要先定 |
| 045 | VFS 对象模型与 FS 范围 | `Superblock/Inode/Dentry/File` 四个 trait 对象；FAT32 读写 + tmpfs + initramfs + devfs | 自有 FS 推迟 |
| 046 | 网络栈边界 | 独立 `aurora-net` crate（`no_std`，宿主机可测可 fuzz）；TCP 来源见 D2 | 外部依赖会改变供应链姿态 |
| 047 | 驱动隔离路径 | 先内核内故障域（隔离名单 + 重置/重启），再用户态驱动 | 用户态驱动依赖 W4 的 Interrupt/Mmio/Dma 对象与 IOMMU |

**D1 进程模型三选项**

| 方案 | 做法 | 好处 | 代价 |
| --- | --- | --- | --- |
| A capability-native（建议） | 内核只提供 `process_create / aspace_map / thread_create / process_start`，`spawn` 由用户态库实现，不要 `fork` | 与 ADR-007 一致；每进程句柄表天然成立；攻击面小 | 现成 libc/软件移植要写兼容层（放 K-Complete 之后） |
| B POSIX `fork + exec` | 内核做写时复制的 `fork` | 移植现成软件最省事 | COW、信号、进程组、会话一并要做，内核面大；与 capability 模型要折中 |
| C 混合 | 内核提供 A，再在用户态实现 `fork` 仿真 | 兼顾 | 仿真层复杂，边角语义易错 |

## 4 阶段与依赖

| 阶段 | 内容 | 出口门 | 量级（推断） |
| --- | --- | --- | --- |
| S1 地基 | W0 + W1 | 4 核阻塞/唤醒/定时压力通过；`main.rs` 拆分后矩阵输出逐行不变 | +0.4 万行（含搬移） |
| S2 内存与进程 | W2 + W3 | 两进程隔离 + 回收回基线 + 按 AS 的 shootdown | +0.9 万行 |
| S3 对象与 ABI | W4 + init + `libaurora` | 两进程 Channel 转移句柄；syscall fuzz 通过 | +0.7 万行 |
| S4 存储 | W5 + W6 前半（IRQ 化、MSI-X） | 读写 FAT32 + tmpfs；NVMe；页缓存 | +1.2 万行 |
| S5 网络与隔离 | W7 + W6 后半 + W8 前半 | TCP 回显；驱动故障重启；解析器 fuzz | +1.5 万行 |
| S6 收口 | W8 后半 + W9 | K-Complete 十条全绿 + 一台真机 | +0.8 万行 |

合计 +5～6 万行，是我的量级估计。S4 的块层不依赖 IPC，可与 S3 后半并行，其余严格串行。

## 5 工作流详设

### W0 结构债与门禁（S1，先做）

**目标**：否则后面每个任务都在 7.6k 行的 `main.rs` 里改，AI 代理误伤概率高。

1. **纯搬移**：74 个 `t_*` 用例按被测模块搬到 `kernel/src/ktests/{mm,sched,user,driver,fs,net}.rs`。判据：默认构建与各特性构建的串口输出（用例名与顺序）与搬移前逐行一致，矩阵 41 行不变。注意 BACKLOG §86e 的教训：链接顺序会改变 `.ktests` 的执行顺序并暴露隐式依赖，搬完必须全跑，用例必须自足。
2. **抽 `aurora-abi` crate**（`no_std`，只放调用号、错误码、特性位、`Rights`、`Handle` 打包）。内核里 `2` 是裸字面量而用户侧有 `SYS_ADD`（user-abi 设计 §1），这是现成的双写。
3. **抽主机可测的纯逻辑 crate**：`aurora-elf`、`aurora-fat32`（解析层）、`aurora-sign`、`aurora-handle-core`（世代/owner/权限判定，不含锁）。目的不是拆得好看（你定的「先造空壳只会得到没人实现的 trait」仍然成立），而是让它们能在宿主机 `cargo test` 与 `cargo fuzz`——W8 的 fuzz 依赖这一步。每个都登记 `crates.toml`。
4. **矩阵分快慢两层**（BACKLOG M2-c 已预告）：快层（合入必过，目标 30 s 内）与全量（夜间）。
5. **P4 容忍度按多核重设**（M3b 遗留，离散度 2.86–5.15%）。

验收：搬移前后输出 diff 为空；`check-crates` 双向比对通过；故意在 `aurora-abi` 里改一个号 ⇒ 内核与用户侧同时编译失败（证明不再双写）。

### W1 调度阻塞（S1）

**设计要点**

```rust
enum TaskState { Free, Runnable, Running, Blocked(WaitToken), Done }
pub fn yield_now();                       // 走 schedule()，覆盖 loads_closed>0 那条路径
pub struct WaitQueue { /* 侵入式链表，起步定长，不进堆 */ }
impl WaitQueue {
    pub fn wait_until(&self, cond: impl Fn() -> bool, deadline: Option<Tsc>) -> WaitResult;
    pub fn wake_one(&self);
    pub fn wake_all(&self);
}
pub fn sleep_until(deadline: Tsc);        // 每 CPU 定时器轮
```

- **防丢唤醒**：「检查条件 → 入队 → 切走」在队列锁内完成，`wake` 在同一把锁内改状态。跨 CPU 唤醒 = 向目标 CPU 队列投递 + resched IPI（新向量，登记进 ADR-020 的向量表）。
- **锁**：等待队列锁的 rank 低于运行队列锁（持等待队列锁时要唤醒，即取运行队列锁）。写进 `lock-order.md`，并造一条重入负样本（沿用 rank 35 的做法）。
- **idle**：每 CPU idle 任务真 `hlt`，取代 AP 常驻自旋工人；P1/P4 的绝对值从此才可解读（BACKLOG M3b 已写明）。
- **迁移**：先做「唤醒时选核」，再做「空闲核拉取」；协议用 BACKLOG 已写好的前提——迁移窗口内两边关中断并持有队列所有权，不能只改 `on_cpu`。
- **优先级**：起步两类（实时 FIFO + 普通时间片），不做 CFS。
- **内核线程生命周期**：补 `wait()` 雏形（结束记录表），解掉「Done 槽不回收」；`MAX_TASKS` 先放宽到 64 并留接口，Task 对象走 slab 要等 W2。
- **睡眠锁**：`Mutex`、`Semaphore`、`Event`；规则「持自旋锁或关中断窗口内不得睡」，调试构建加断言（如同堆的 ISR 断言）。

验收：

- 4 核 N 生产者 N 消费者 100 万条消息：`wake` 次数与 `block` 次数对得上（差值 ≤ 在途数），丢唤醒数为 0。
- 变异 A：把「入队」和「查条件」拆到锁外 ⇒ 丢唤醒计数大于 0 或 HANG；变异 B：去掉 resched IPI ⇒ 跨核唤醒延迟超界。
- sleep 精度：落在 \[d, d+2 tick\]，用已标定的 `tsc_hz` 并与宿主机墙钟交叉（BACKLOG 75 的 KVM 对照档）。
- idle：`-d int` 数到 `hlt` 退出，宿主 CPU 占用下降（观察量，不当判据）。

### W2 内存管理完整化（S2）

**目标**：拆第 2 道墙。

1. **页帧元数据**：`FrameInfo { refcnt: AtomicU32, flags, owner }` 数组，按内存映射动态分配，顺手替换「位图按 4 GiB 静态 128 KiB」。引用计数是 COW、共享、页缓存的共同前提。
2. **大块分配**：`phys_alloc(order)`（已有）经 **HHDM 直接寻址**交出连续大缓冲，不占 VA 保留表——这正是 ADR-018 与 BACKLOG M2-b 留的口子。API 形状 `KBuf`（RAII，带台账模块号）。堆仍 ≤ 2048，规则写进 §6.5.1：凡按外部输入大小开缓冲的路径，必须用 `KBuf` 或流式。
3. **VA 保留表**：24 条定长 → 区间表（定长 256 + 空闲位图），保持「表满即拒绝并 L4 日志」的语义。
4. **`split_huge`**（M2 未完项）与 MMIO 高地址窗口 `map_hole(va, size, UC)`，供 ECAM 多段、MSI-X 表、NVMe BAR。
5. **缺页处理**：用户半区缺页 → 查所属 AS 的 VMA 表 → 按需清零页 / 栈增长 / COW / 非法则只杀该进程（现在是一律杀）。
6. **配额与 OOM**：台账按进程聚合（W3 后）；内核堆 OOM 仍 L4（ADR-018），用户分配耗尽走「杀占用最大的用户进程」。
7. 后做：KASLR、用户 ASLR、页面下线（A.5 的 #MC 空白）。

验收：

- 64 KiB–16 MiB 各规格分配、写满、释放，台账与 `frames_free` 回基线。
- 引用计数：共享帧 N 次 `get`、N 次 `put` 才归还；多一次 `put` 判 DoubleFree 升 L4（沿用 M2 用例形态）。变异：COW 路径漏 `put` ⇒ 台账不回基线。
- `split_huge` 前后翻译等价（BACKLOG 已列）。
- 按需页首次读为 0：用户程序读回自判，内核另有 `demand_zero` 计数交叉。

### W3 进程与地址空间（S2，整份方案最大的一刀）

```rust
pub struct AddressSpace { pml4: PhysFrame, vmas: VmaTable, cpus: CpuMask, asid: Option<Pcid>, id: AsId }
pub struct Process { pid: Pid, aspace: AsId, threads: [TaskId; N], handles: HandleTable,
                     exit: Option<ExitStatus>, parent: Option<Pid> }
```

- **页表**：每进程一份 PML4；**内核半区顶层项在创建时从内核 PML4 拷贝，之后不再改动**（内核映射只在已预填的顶层项之下增删，避免跨进程同步）。换入任务时 AS 不同才写 CR3。
- **shootdown**：目标集合从「全部在线核」收窄到 `AddressSpace::cpus`（ADR-023 欠账、BACKLOG M3b 的 per-AS cpumask）；内核映射变更仍广播。PCID 只能在真机验证（QEMU `-cpu max` 下 pcid=false，见 BACKLOG 环境表）：代码两条路径都留，QEMU 只测无 PCID 那条，验收里必须写明。
- **创建**：见 D1（A 方案）。内核只留一个内置装载器给 init，其余装载在用户态 `libaurora::spawn`。
- **退出回收**：`Task::owned` 定长 8 条（ADR-027）升级为进程级所有权（整棵 VMA 拆除）；`Mapping::drop` 语义保留；沿用「释放延迟到本 CPU 上跑的已经不是它」；多线程加「最后一个线程退出才拆 AS」。
- **取代** `user::load` 的固定 VA 窗口：每进程独立用户 VA（ADR-028 的镜像区/动态区划分保留）。
- **接进产品启动路径**：init 先从签名包（M9-a②）载入，W5 后改从 initramfs——这让「验签接启动」第一次有落点。
- 与 `handle.rs` 的关系：W4 把全局 16 格表改为 `Process::handles`；owner 两格检查变成「属于本进程」，世代与权限规则不变。

验收：

- 隔离：A、B 在同一 VA 各写不同魔数，互读各自的值；A 访问 B 的页 ⇒ 只杀 A。
- 同一 AS 的两个线程在两个核上并发 map/unmap（BACKLOG M3b 点名缺的那条）：`requests` 与各核 `acks/invlpg` 自洽。
- 退出：帧、VA 保留、句柄全回基线（`KT_TASK_EXIT` 三轮形态扩到进程）。
- 变异：新进程 PML4 用户半区共用同一份 ⇒ 隔离用例红；shootdown 目标漏掉一个运行该 AS 的核 ⇒ 红（注意 ADR-023：QEMU TCG 观测不到陈旧 TLB，这条只验协议，真机补）。

### W4 对象模型与 IPC（S3）

**目标**：拆第 4 道墙。

```rust
enum ObjKind { Process, Thread, Vmo, Channel, Event, Timer, Interrupt, File, Dir, Socket }
struct HandleEntry { gen: u64 /*低 48 位*/, kind: ObjKind, obj: ObjRef, rights: Rights } // 每进程一张，动态大小
struct SyscallEntry { nr: u16, name: &'static str, args: [ArgKind; 6], need: Rights, hot: bool,
                      f: fn(&mut Frame) -> isize }
static SYSCALLS: [SyscallEntry; N] = /* 编号 = 下标，缺口用 NOSYS 占位 */;
```

- 保留 `handle.rs` 的 owner 两格、世代、`Rights`，补 `MAP`/`TRANSFER`/`WAIT`/`SIGNAL`；句柄值仍是 `slot:u16 + gen:u48`，**表容量改动态**（ADR-007 §9 A 当时定的「16 格无配额」在这里改为每进程上限，防耗尽）。
- **Channel**：有界消息队列，句柄随消息转移（`TRANSFER` 位，转移后发送方旧句柄 `Stale`），是 IPC 的第一原语。**Event/Port**：`wait_many(handles[], deadline)`，建在 W1 的 `WaitQueue` 上。**Vmo**：可共享内存对象，依赖 W2 的引用计数。**Interrupt/Mmio/Dma** 对象：为用户态驱动预留（手册 §8.5，W6/ADR-047 用）。
- **表驱动分发**同时回答 BACKLOG 里那条「分发器别写成巨大 match」的规则：热调用前置，冷样本数不再随分支数线性涨。`aurora-abi` 生成用户侧常量，两侧不再手抄。
- **ABI 1.0 冻结规则（ADR-043）**：0.x 允许破坏；1.0 起只加不改；`sys_abi_info()` 特性位是唯一探测手段（沿用）；错误码「有返回分支才加」（你已冻结的原则）。BACKLOG 86d-4 悬着的 `-7=EIO` 在这里一并裁决。

验收：

- 两进程 Channel 往返 + 句柄转移：转移后发送方旧句柄 `Stale`；接收方权限不可能高于发送方。
- ADR-007 的 12 条负样本迁到新表后仍然各自红得出来（第 5、12 条补造）。
- syscall fuzz：用户程序用宿主机给的种子对每个号打随机参数几万次，内核只许回错误码或只杀该进程，不许 panic、不许 L4。变异：删掉某个号的指针校验 ⇒ fuzz 红；删掉权限位比较 ⇒ 红。

### W5 存储与文件系统（S4）

- **块层（ADR-044）**：`BlockDev::submit(bio) -> Ticket`，异步，完成走 IRQ，回调只叫醒不放行（M5-g② 的教训）。请求队列 + 相邻扇区合并 + 多描述符链，顺带解掉 virtio「一次一扇区单链」与 AHCI 255 扇区上限。完成路径唤醒 `WaitQueue`（依赖 W1）。
- **分区**：GPT 解析 → 分区设备。现在状态区与签名包是在 GPT 空隙里按常量布局的，要统一登记，避免互相覆盖。
- **NVMe**：新驱动（admin + I/O 队列对，MSI-X 完成），QEMU `-device nvme`，宿主机 qemu-io 读回哈希对账（沿用 M5-b/c）。
- **页缓存**：按 (file, index) 的 `FrameInfo` 页；写回线程（内核线程，依赖 W1）；`fsync` 语义先定。
- **VFS（ADR-045）**：`Superblock/Inode/Dentry/File` 四个 trait 对象、挂载表、路径解析；fd 就是 `File` 对象的句柄。现有 153 行 `vfs.rs` 与 `walk` 旧路替换为句柄路径（BACKLOG 85d-4）。
- **文件系统范围**：FAT32 写路径（长文件名、创建/删除/重命名、双 FAT、FSInfo）、tmpfs、initramfs（cpio newc，init 的来源）、devfs（null/zero/console）。**自有文件系统不进 K-Complete**。
- **宿主机见证**：把 `tools/` 里的独立 FAT32 解析器扩成「写后复验」（你已有 `patch_fat32_file.py` 的写后复验形态），对账目录项、两份 FAT 一致、簇链、FSInfo。

验收：读写往返哈希（含跨簇、跨 255 扇区、长文件名）；掉电一致性只承诺 FAT32 级，不写成日志文件系统。变异：写完不更新第二份 FAT ⇒ 宿主机复验红；脏页不写回 ⇒ 重启后读到旧值红。

### W6 中断化驱动与设备（S4 前半 + S5 后半）

- 完成路径全部改 IRQ：AHCI 已有一颗 MSI；补 virtio MSI-X（BACKLOG 75h 已修表偏移）与共享电平 INTx（先归属判定后 EOI）；补上「ISR 内 `request_irq` 被拒」那格判据。
- **线程化中断**：顶半只读/清源/立旗，底半在内核线程（W1 之后可睡）。这补上手册 A.5「线程化中断选型」的空白。
- `DriverCtx` 补 `set_timer`/`log`；句柄表 8+8 写死 → 动态。
- **IOMMU（VT-d）**：DMAR 表内容 + 中断重映射表，QEMU `-device intel-iommu,intremap=on` 配方升为矩阵第六变体（BACKLOG M2-c 已预告）；AMD IVRS 要另一套配方，放真机阶段。
- **控制台输入**：COM1 RX 中断 → 行缓冲 → `console` 设备对象（init 和调试 shell 要用）。
- **时间**：RTC 读墙钟；HPET 作 TSC 的第二参照（BACKLOG M3a 已挂）。
- **驱动隔离分两步（ADR-047）**：先内核内故障域（隔离名单 + 重置/重启，复用 M5-d 状态机，驱动崩溃只升 L2/L3）；再用户态驱动（Interrupt/Mmio/Dma 对象 + IOMMU 域，hybrid 内核的入口）。K-Complete 只要求第一步加一个用户态驱动样例（串口或 virtio-net）。

验收：投递由宿主机数（沿用 M5-g③ 的 `-d int` 对账）；MSI-X 逐字读回；共享 INTx 下两台设备互不误认领；驱动故障注入 ⇒ 仅该驱动被重启，其余 ktests 继续绿。

### W7 网络（S5）

- 协议栈放独立 crate `aurora-net`（`no_std`、无内核依赖、宿主机可 `cargo test`/fuzz）：Ethernet、ARP、IPv4（分片重组做最小版）、ICMP、UDP、DHCP 四次握手、TCP（状态机、重传定时器、滑动窗口、Reno 拥塞控制起步）。
- 内核侧只做：mbuf 池（大缓冲走 W2 的 `KBuf`，正是 BACKLOG 点名「网络 mbuf 拿不到内存」那条）、virtio-net 多缓冲 RX + IRQ、`Socket` 对象（句柄）、定时器接 W1。
- TCP 的来源见 §9 D2。
- 见证：QEMU `hostfwd`，宿主机程序与客户机互通 TCP 回显；`filter-dump` pcap 逐帧重算校验和（沿用 M8-a）；协议解析器在宿主机 fuzz——手册 M8 那句「协议 fuzz 无高危缺陷」今天一条 fuzz 都没跑，这一步才让它有对象。

验收：DHCP 完整四次；ARP 缓存；ICMP echo；UDP 回显；TCP 三次握手 + 1 MiB 传输哈希一致 + 经宿主机侧代理注入丢包/乱序仍一致。变异：TCP 校验和不检查 ⇒ fuzz/注入红。

### W8 安全、可靠与可观测（S5 前半 + S6）

- **验签进启动决策**（ADR-011 正式 / ADR-033）：验不过 ⇒ `BOOT-INVALID(37)` 不启动；init 镜像从签名包取。生产钥匙的离线保管/轮换/吊销流程今天一条都没有（现有锚点来自测试种子，只证明机制对）。**推断**：`sign.rs` 是 Lamport 一次性签名，每把钥匙只能签一次，发布流程要设计成「一发布一钥」或换成可复用方案，这需要 ADR。
- **A/B 槽位**（§9.5）：卡在「装载侧身份」，W3/W5 之后才有落点。
- **处置那一半**：watchdog 摘线、软锁死处置（M6-c① 明写「处置没有」）、可恢复 #MC 页面下线。
- **fuzz 总汇**：syscall（W4）、ELF 装载器、FAT32 解析、签名包头、网络解析器，全部宿主机侧可跑（依赖 W0 的纯逻辑 crate）。
- **缓解措施**：KASLR、用户 ASLR、栈保护/CFI 评估、**KPTI 决策**（有了每进程 PML4 才可行，且真机上才有意义，走 ADR）。
- **可观测**：内核内 kallsyms（今天符号化只在宿主机，BACKLOG M6-e）、每 CPU 追踪环、`crashdecode` 宿主工具（A.5 空白）。
- **能力审计日志**：句柄授予/撤销/拒绝入环（M8「审计」那一格）。

验收：同前；每条 fuzz 都要有「删校验 → fuzz 能抓出」的变异证明。

### W9 时间、电源与真机（S6）

- **电源**：先做关机/重启——FADT 复位寄存器、0xCF9、键盘控制器三级回退；S5 关机需要 `_S5_` 对象，AML 之前可用扫描 DSDT 的办法（**推断**：不少业余内核这么做，是否采用要你评估）；`sys_abi_info()` 必须显示「无睡眠」特性位（手册 M5b 的验收句）。
- **AML（ADR-012b）**：见 D3。
- **真机 bring-up 清单**（手册 §13 与 BACKLOG 里所有「M7 重测」项）：x2APIC（固件已开而请求未置位，bootloader 可能直接拒绝引导）、PCID、ICR 目的缩写、INTx 路由、MCFG 多段、UC 读成本、串口真实吞吐、HHDM 在 4 GiB 之上。QEMU 与真机之间的中间站：`-machine q35` 对 `pc`、KVM 加速（BACKLOG 75 已有对照档）、VirtualBox/Hyper-V 等 hypervisor，最后一台真机 + USB 转串口线。
- USB HID（xHCI）按手册放 M7，**不进 K-Complete 必需项**（当前阶段无 UI）；真机没有 PS/2 时靠串口控制台。

验收：真机串口日志由宿主机解析判 PASS；关机/重启由宿主机观察 QEMU 退出码与重启次数。

## 6 首个冲刺：S1 的任务卡

每张卡先写 ADR（如需）再编码；卡内「不得动」是给 AI 代理划的边界。

| 卡 | 内容 | 完成判据 | 不得动 |
| --- | --- | --- | --- |
| T0.1 | 拆 `main.rs` 用例（纯搬移） | 串口输出逐行不变；矩阵 41/41 | 任何被测实现 |
| T0.2 | 抽 `aurora-abi` | 内核/用户两侧无裸字面量；`check-crates` 过 | 调用号取值 |
| T0.3 | 矩阵分快慢层 + P4 多核阈值 | 快层 <30 s；阈值写进 `docs/testing/` | 判据本身 |
| T1.1 | `yield_now` + `loads_closed>0` 用例 | 关闭 M3b 遗留那一格 | 抢占路径 |
| T1.2 | `WaitQueue` + 丢唤醒判据 + 两条变异 | 见 W1 验收；先写 ADR-040 与 lock-order | `sync.rs` 既有 rank |
| T1.3 | `sleep_until` + 每 CPU 定时器轮 | sleep 落在 \[d, d+2 tick\] | PIT/LAPIC 标定 |
| T1.4 | idle `hlt` + resched IPI（新向量） | `-d int` 见 hlt；ADR-020 向量表更新 | 现有向量号 |
| T1.5 | `Mutex`/`Event` + 「持自旋锁不得睡」断言 | 负样本：持锁睡 ⇒ L4 | 堆锁与 ISR 断言 |
| T1.6 | 内核线程 `wait()` 雏形 + `MAX_TASKS` 放宽 | Done 槽可回收；`KT_PREEMPT` 事后读数改写有说明 | 用户回收路径 |
| T1.7 | 任务迁移（唤醒选核 + 空闲拉取） | 两核并发用例；迁移窗口内队列所有权可证 | `QueueCell` 的 SAFETY 前提需同步改 |

### 提示词骨架（给 AI 代理）

```text
任务：<卡号 + 一句话>
先读：<ADR/BACKLOG 条目/源文件，限定范围>
可改：<文件白名单>   不得动：<见任务卡>
判据：<串口原文里必须出现/不得出现的行 + 宿主机对账项>
必须附：① 变异前后的串口原文 ② `tools/aurora.py check` 与 `test` 的结果 ③ BACKLOG 新条目（标「实测」或「推断」）
禁止：自行宣布通过（以宿主机判定为准）；顺手改判据；放宽 unsafe 白名单而不登记
```

每张卡的收尾清单沿用你现有的做法：ADR、用例、独立见证、至少一条变异证红、BACKLOG 条目、unsafe 普查更新、`lock-order.md` 更新、新特性变体进矩阵并通过 `check-matrix-wiring`。

## 7 与现有文档的衔接

- 本方案是手册 V1.2 §14 里程碑的**延长线**，不替代它：M4 未完项（`UserSlice`、缓冲区两次调用的原子性）、M5 未完项（NVMe、IOMMU、动态句柄表）、M6 未完项（A/B、隔离名单、fuzz）、M8/M9 未完项都已被分进上面的 W 条目；落地后同步回写 §14。
- 我没有 AUR-KERNEL-API-1.0（Tasks A–E，模块归属/接口契约/crate 拆分）的原文——zip 里不含它。W0 第 3 条的 crate 拆分如果与它的模块边界冲突，以你那份为准；把它发给我我再对齐。

## 8 风险与诚实边界

- **量级**：完整内核对单人 AI 辅助开发是年量级的工作。K-Complete 1.0 已经刻意收窄（§2 非目标），再往里加东西会把目标变成移动靶。
- **证据全在 QEMU**：TLB、PCID、x2APIC、真实中断与时钟行为都没被覆盖。M7 之前不要对外说「可用于真机」。
- **顺序风险**：W3 会让几乎所有现有用例改写（单 CR3 假设遍布 ktests、handle owner、shootdown 的全在线核）。所以必须在 W4/W5 之前做，越晚越贵。
- **大文件的反噬**：AI 代理改 7.6k 行的文件容易误伤，W0 就是为此。
- **方法论的软肋**：每个「独立见证」本身也是代码，可能和内核一样写错。你已经在做的「变异证红 + 两份实现」不要因为进度压力省掉。
- **许可证与供应链**：当前外部 crate 为 0。引入 smoltcp、uACPI 一类依赖会改变这个姿态，且要先过 ADR-009a 的白名单（现有白名单含 MIT/Apache-2.0/BSD-2/BSD-3/ISC/Zlib/MPL-2.0）。这些项目具体用什么许可证、是否适配 `no_std`，我没有核实，需要你到项目页面确认。

## 9 需要你拍板的决定

| # | 决定 | 我的建议 | 理由与代价 |
| --- | --- | --- | --- |
| D1 | 进程模型 | A：capability-native，不做 `fork` | 与 ADR-007 一致；代价是移植现成软件要等用户态兼容层 |
| D2 | TCP 来源 | UDP/ICMP/ARP/DHCP 自研（已有基础）；TCP 先评估 smoltcp 当 `aurora-net` 后端，评估不过再自研 | TCP 是最大的单点工作量和 bug 来源；代价是外部依赖进 TCB，许可证与 `no_std` 适配要先核实 |
| D3 | AML | K-Complete 只做关机/重启 + 「无睡眠」特性位；AML 放其后，届时倾向复用成熟 C 库经 FFI（符合你 C+Rust 混合的决定） | AML 解释器体量大；候选库的许可证与适配我未核实 |
| D4 | 文件系统范围 | FAT32 + tmpfs + initramfs + devfs；自有 FS 在 K-Complete 之后立项 | 自有 FS 要日志/CoW 与崩溃一致性，工作量独立成项 |
| D5 | KPTI | W3 完成后评估，真机验证再定，不抢在 K-Complete 前强上 | QEMU 上测不出收益，成本却要进每次系统调用 |
| D6 | 驱动隔离深度 | K-Complete = 内核内故障域 + 1 个用户态驱动样例；完整 hybrid 在其后 | 用户态驱动依赖 W4 对象与 IOMMU，二者都晚到 |

**我建议你先回复 D1。** 它决定 W3/W4 的接口形状；D2–D6 可以晚到各自阶段开工前再定。

## 10 D1 已裁决：A（capability-native）与启动协议草案

**裁决**：进程模型取方案 A。内核只提供创建进程的原语，`spawn` 在用户态库里组合，内核不做 `fork`。本节细化 ADR-039，并**修正 §3/D1 讨论里我写的一处**：`process_create` 不能是「无需权限」——那等于给每个进程一份环境权限（ambient authority），与 capability 模型矛盾，也挡不住 spawn 炸弹。

### 10.1 修正：新增 `Job` 对象

- `ObjKind` 增加 `Job`：进程配额的容器（最大进程数、最大线程数、最大内存页数），带 `CREATE` 权限位。
- `process_create(job_handle) -> (proc_handle, aspace_handle)`：必须出示带 `CREATE` 的 `Job` 句柄；创建出的进程计入该 Job 的额度，超额回拒绝码。
- 内核启动时建根 `Job`，只交给 init；init 再按需切出子 `Job`（额度只能收窄，不能放大，同 `dup` 缩权的规则）。

### 10.2 启动协议：为什么不能约定「句柄 0/1/2」

句柄值是 `slot:u16 + gen:u48`，世代每槽独立递增，所以新进程里某个句柄的数值不可预测，不能像 POSIX 那样硬编码 fd 号。改成**内核在启动时交一页只读的 `StartupInfo`**，进程通过角色（role）查句柄。

```rust
#[repr(C)] struct StartupInfo {
    magic: u32, abi_major: u16, abi_minor: u16,
    nhandles: u32, args_off: u32, args_len: u32,       // args 是调用方给的字节串，内核不解释
    handles: [HandleDesc; MAX_STARTUP_HANDLES],        // 例如 16
}
#[repr(C)] struct HandleDesc { role: u32, kind: u32, handle: u64 }
```

角色编号由 `aurora-abi` 一处分配，初版约定：`SELF_PROC`、`SELF_ASPACE`、`SELF_THREAD`、`PARENT_CHAN`（与父进程的 Channel）、`LOG`（控制台/日志对象）、`NS_ROOT`（根目录句柄，没有就是无文件系统访问）、`JOB`（可选）。**没传的角色就是不存在**，进程没有任何办法凭空取得。没有环境变量，没有当前目录。

新线程第一条指令时 `rdi` = `StartupInfo` 的用户 VA。

### 10.3 `libaurora::spawn` 的调用序列

1. `process_create(job)` → `proc`、`aspace`。
2. **用户态**解析 ELF（装载器主体搬出内核）。对每个 `PT_LOAD`：`vmo_create(len)` → `vmo_write` 填文件字节与 bss 清零 → `aspace_map(proc, vmo, va, rights)`，权限按段取 `R`/`RW`/`RX`，**不允许 W+X**（沿用 §6.4 的 W^X 构造期拒绝）。
3. 建栈：`vmo_create` + `aspace_map`，栈底下留一页不映射作 guard。
4. 建 `StartupInfo` 页：`vmo_write` 写 `magic/args`，`handles` 先留空，映射为只读。
5. `thread_create(proc, entry, sp, arg = startup_va)` → `thread`。
6. `process_start(proc, thread, startup_vmo, transfers[{role, handle}])`：**原子地**把 `transfers` 里的句柄移进新进程的句柄表，并由**内核回填** `StartupInfo.handles`（句柄数值只有转移之后才知道，父进程自己填不了）。转移之后发送方的旧句柄立即 `Stale`。
7. 任一步失败：`process_kill` + 关闭已建句柄，台账回基线（这条是单独的负样本，见 10.5）。

### 10.4 init 与内置装载器

内核保留一个最小的内置装载器，只装载 init；init 拿到 `SELF_*`、根 `Job`、`NS_ROOT`（来自 initramfs，W5 之前先用签名包里的单文件）、`LOG`。init 之后的所有进程都由用户态 `spawn` 起，所以内核里 `elf.rs` 的容器解析可以在 W3 末尾缩成「只服务 init」。

### 10.5 验收与负样本

- **只拿到传给它的句柄**：子进程对自己表里每个槽试 `dup`/`close`，只有 `StartupInfo` 里列出的那几个成功，其余回 `NoSuchHandle`。
- **无 Job 不能造进程**：不带 `CREATE` 的 `Job`、或额度已满 ⇒ 拒绝；变异：去掉额度检查 ⇒ spawn 炸弹用例红（进程数涨过额度）。
- **回填正确**：子进程读 `StartupInfo.handles` 里的 `NS_ROOT` 并 `file_read` 成功；变异：`process_start` 不回填 ⇒ 子进程读到空句柄，红。
- **转移即失效**：`process_start` 后父进程用旧句柄 ⇒ `Stale`；变异：转移后不失效 ⇒ 红。
- **中途失败回滚**：在第 3 步注入失败 ⇒ `process_kill` 后帧、VA 保留、句柄、Job 额度全部回基线。
- **W^X**：装载器试图映射 `RWX` ⇒ `aspace_map` 拒绝。

### 10.6 仍开的点

1. `StartupInfo` 的最大句柄数与 `MAX_STARTUP_HANDLES` 的取值要结合 W4 的每进程句柄表上限一起定。
2. 系统调用号由 `aurora-abi` 一处分配（现有 8/9/10 保留）；八个新调用加 `Job` 相关调用的具体编号，等 ADR-043 的表一起排。
3. 时间读取（类似 vDSO）、`process_wait` 的退出码语义、线程独立退出是否需要 `thread_wait`，留到 W3 做的时候由用例逼出来再定，不预先摆。
4. 现有 `user.rs` 里「每个用户任务占 `Task` 槽 + `Task::owned` 定长 8 条」的结构要随 W3 改成进程级所有权，这一步要新开一张 ADR-027 的补记。

## 11 勘误（T0.1 动手前读源码发现的）

- **§5 W0 第 1 条与 §6 T0.1 的判据「串口输出逐行不变」不成立，改为「用例名称集合相等 + 判定矩阵不变」。** 原因：用例经 `.ktests` 段注册，执行顺序由链接顺序决定，而不是源码顺序（BACKLOG §86e 已经因此踩过一次隐式依赖）；把用例搬到别的文件，顺序可能变。顺序变不是 bug，但必须被报告；若顺序变了且有用例红，按「用例必须自足」处理，不得靠调整顺序掩盖。
- **W0 第 1 条漏写了一个依赖面**：宿主机门禁直接读 `main.rs` 的文本（`check-fat32-ports`、`check_virtio_pattern`、`check_net_pattern`），unsafe 普查按文件路径记模块（`[modules."main"]`）。搬移必须同步改这几处，并各证一次「改坏就变红」。
- 另有 5 个外部引用（`crate::mp_snapshot`、`crate::calibrate_clock_once`、`crate::exit_fatal_from_exception`、`crate::HELLO_ELF`、`crate::drain_reap`）要保持路径可用。
