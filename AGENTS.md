# AGENTS.md — Aurora OS 内核仓库的代理工作约定

你在维护 Aurora OS：从零开发的 x86-64 内核，Rust `no_std` 为主，垂直切片阶段只有
`aurora-kernel` 一个内核包（`kernel/src`）与一个用户程序产物包 `aurora-user-hello`（`user/hello`）。
Limine 引导，主要在 QEMU（q35 / ich9-ahci / OVMF）中验证。

## 权威资料与优先级

`docs/Aurora OS 开发手册（企业级）V1.2.md`；`docs/adr/`（**目前 153 份，编号 007–176**（1–6、8–13、15、119–129 从未建号）；
完整化方案 §3 拟用的 039–047 已全部撞车，新决定从 **046** 起编——实际已编到 **176**）；
`BACKLOG.md`（逐轮实测与欠账的唯一来源）；`docs/architecture/crates.toml`、`module-interfaces.toml`、`module-dependencies.md` 与 `lock-order.md`；
`docs/security/unsafe-whitelist.toml`。

**已采纳 ADR 与有测试证据的事实 > V1.2 强制规范 > 架构规范的目标设计 > 建议。**
冲突时先记录差异，不要自行改动已验证的结论；要改架构，先起草 ADR。

**2026-11-21 更正**：这两条都已不成立——`docs/adr/ADR-007-*.md` 与
`docs/Aurora_OS_内核详细架构设计与模块接口规范_V1.0.md` 都已被跟踪（`git ls-files` 实测），
capability 的产品路径也已接通（`handles` 档 init 授 Job+Console，22 号授 VfsFile/VfsDir）。
保留这段是为了让下一个人知道它曾经错过一次：**文档里的未跟踪/未接，会过期。**

## 统一入口

`python tools/aurora.py <子命令>`，子命令只有这八个：
`build` / `image` / `run` / `test` / `bench` / `check` / `ktests` / `release`。
不要凭印象编命令或参数；不确定就跑 `--help`。

- `check`：**20 道静态门禁**（lints-wired、unsafe、crates、module-interfaces、vector-table、interface-change、driver-ctx、state-window、virtio-pattern、
  fat32-ports、net-pattern、sha-primitives、sig-anchor、pkg-manifest、sbom、matrix-wiring、verdict、**syscall-abi-arms**、
  **capacity-baseline**、nofloat）。
  `check-syscall-abi-arms` 是 2026-11-21 加的，**三条判据**：①用户态 `syscall_abi(SYS_X)` 的每个名字，内核分派表里必须有同名臂；
  ②53/54 不许挂原始以太网帧的 handler（两族语义不合并）；③（ADR-176）内核**声明**的每个 `pub const SYS_X` 也必须有臂，
  豁免仅 `SYS_RESERVED_FIRST/LAST`（哨兵）与 `SYS_NOT_A_NUMBER`（99，专供「未知号回 -1」的负样本）。
  判据 3 只对账「有没有臂」，不证臂里干的对不对 —— `=> E_NOSYS` 的空壳照样绿，那是设计意图。
- `test`：**判定表 82 行**，每行各拿自己那一跑的串口日志与退出码。
  判定值契约：PASS=33、FAIL=35、BOOT-INVALID=37、EXCEPTION=39、HANG=-1，
  另有量具级的 CONTENT-MISMATCH / SEQ-BROKEN。
- `bench`：四把尺子（P1 切换 / P2 MMIO 与 DMA / P3 故障恢复 / P4 串口量对照），
  原始输出自动入库 `docs/testing/baselines/<UTC>-p3p4.txt`（已有 67 份）。
- `run --features X --host-fault Y`：宿主机侧注入（改盘不改构建），见 BACKLOG §80。

本机控制台是 GBK：跑任何 Python 入口都要带 `PYTHONIOENCODING=utf-8 PYTHONUTF8=1`，
否则中文日志读成乱码、按中文锚点的判据会静默读成"零条记录"。

## 硬约束

1. 不重写 `mm` / `sched` / `trap`；不改已实测的中断、TLB、任务回收、驱动资源语义。
2. 不为了引入 C 而引入 C；不创建没有真实调用者的空 trait、空服务、空模块。
3. 驱动只能通过 `DriverCtx` 访问 MMIO/DMA；不新增裸指针访问（`check-driver-ctx` 是文本网关，
   扫 `ahci.rs` / `virtio.rs`，禁用 `read_volatile`/`write_volatile`/`ptr::`/`from_raw_parts`）。
4. 新增锁必须同步改 `lock-order.md`、代码里的 rank、测试与负样本。
5. 新增 `unsafe` 必须登记白名单，写明指针来源、地址范围、对齐、生命周期、并发规则、
   上下文约束、由谁保证不变量。
6. 故障路径不分配内存、不等待可能已损坏的锁；关键路径禁止吞错
   （不得用 `unwrap_or_default` 掩盖失败）。堆上限 `LARGE_MAX = 2048` 字节，
   "按段开缓冲"的写法会被当场打死（ADR-018 / ADR-026）。
7. **"检测到"不等于"已恢复"；"验签通过"不等于"安全启动"**；不得在文档或发布说明里夸大结论。

## 工作协议

- 先读相关文件与 ADR，再给不超过 15 行的计划。遇到以下情形**停下来问**：
  要改 ADR 已定的语义、要改锁序、要新增 syscall 号、要拆 crate、要改变日志契约。
- 小步前进：每次改动都能独立通过门禁。每一步之后跑构建、`ktests`、`check`、`test`，贴前后读数。
- **每条新规则或新判据，都配一个能让它变红的负样本（变异证红）。**
  涉及硬件、存储、网络、签名的结论，要有宿主机侧的第二台仪器对账。
- 一个会话只做一个任务，不顺手做别的。
- 结束时汇报：改了什么、读数前后对比、哪些没做、新发现的风险；更新 `BACKLOG.md` 与相关文档；
  没验证过的一律写"未验证"。

## 这个仓库特有的取证纪律（踩过的坑，别重踩）

- **只记取证跑那一轮的数。** 跑长链期间冻结树；不要为了文档 cosmetics 重跑整链（BACKLOG 77e）。
  引数时写清来路；拆不开的差值**显式写"不归因"**，不要编一个解释。
- **量具自己也会错，而且错了看起来像被测物坏了。** 新闸/新证人必须各自被证一次会咬：
  造一个错看它红，还原看它绿。只跑整链不够——单独跑那一遍抓出过整链看不出的量具错（§80d-3）。
- **跨轮比 `serial_bytes` 只能用 bench 那四跑。** `do_test` 的正向跑之前不 unlink 镜像，
  它的读数取决于 `ensure_image` 有没有重造（变体名或 ELF sha 不符才重造），
  同一份代码不同来路差过 274 字节（79g-4）。
- **`.ktests` 的顺序由链接器决定。** 用例必须自足，不能假设别的用例已经认领过设备；
  搬迁模块会改串口行序，"逐行 diff 一致"这种判据要先归一行序。
- **负样本注入分两种，别混。** 内核侧 `cfg!` 注入是 cargo 特性；宿主机侧改盘注入**不许**做成特性
  ——特性名进 `-C metadata` 会改 crate disambiguator ⇒ 符号哈希与链接布局变（§80a 实测）。
- **行尾**：`tools/aurora.py` 与 `tools/make_fat32_mem.py` 必须保持 **CRLF**。
  整文件转成 LF 会让 `git diff` 显示几千行增删，那不是改动量，是量具在骗人（79f）。
- **夹具**：`kernel/fixtures/fat32-mem.img` 被 `.gitignore` 挡着，由 `tools/make_fat32_mem.py` 现算，
  不要 force-add。两块 FAT32 真卷的配方是仓库里的 `.img.zz`，本机**没有 mtools**。单文件替换已有
  `tools/patch_fat32_file.py`（P7 用它把 hello.elf 换进两卷，写后复验）；整卷 mformat 仍卡着（78h-6 / 80f-1）。
- 提交按 **explicit 文件名** stage，不要 `git add -A`；未跟踪的架构规范 V1.0 不是本轮产物，别顺手带上。

## 当前进度快照（2026-11-21，HEAD 见 `git log -1`）

**这一节只写实测过的。** 上一版停在 2026-11-07 的 HEAD 385c05a；
把它当历史读，不要当现状。

已交付（每条都有判定行或 ktest 撑着）：ring3 闭环与真 ELF 装载（M4）、SYSCALL/SYSRET
快路径与 GS 窗口（M4-4）、PCI/AHCI/virtio-blk/virtio-net/NVMe（M5/M8）、中断认领与亲和性
（M5-g、L3-A/B）、持久状态区与启动循环保护（M6）、核内 SHA-256 与签名包两份实现（M9-a）、
FAT32 只读解析 + 从卷上取 `HELLO.ELF` 真跑（L3-C①②③④）、FAT32 写方向（`fs-rw`）、
GPT/FAT16/ESP 分区层、用户态装载器与 shell 外部命令、capability 句柄（产品路径已接通）、
验签接启动路径（只检测不拒启）、帧缓冲文本出口、显示/输入的 QMP 第二台仪器、
块请求层（死线/取消/半途读数）。

仍然开着的四个里程碑缺口（2026-11-21 复核）：
1. **capability 的产品语义**——产品路径已接通（`handles` 档 init 授 Job+Console，
   22 号授 VfsFile/VfsDir），`dup` 已共享游标，块设备失败已统一 `-7=EIO`。仍开：
   表是**全局 16 格**而不是每进程、`handle` 缺「按句柄值查活性」的 API（加它动契约）、
   `t_handle_table` ⑨ 段只证了 `revoke_task` 的清表而没证「只清 OWNER 的」。
2. **验签不拒启**——`stage_signature_check()` 在启动路径上真调，`拒启=false` 是打出来的；
   拒启要等 W5 身份/槽位 + ADR-011 正式方案 + W12 生产钥匙（ADR-080 未决 1）。
3. **真机（M7）零条已测**——`docs/hardware/bringup.md` 的 **51 条**（H-01…H-51，H-32…H-51 已于
   2026-11-21 并入）全是「待测/未验证」。**没有机型就没有 M7 的通过**，这条卡在硬件不在代码。
4. **块设备抽象**——`block_io` 有死线/取消/半途读数，但**没有请求队列/完成通知**；
   virtio-blk 的 `Block` 实现已做（78h-3 收口）。

**长链抖动仍未归因**（§468 三次同一 ELF 得 74/73/71；§469 已证伪「串口吞吐」假设，
现最可疑的是宿主机 VM exit 开销漂移，**未验证**）。判定表恒红 2 条：`崩溃记录跨重启读回`
（§446 已裁决未实施）与 `A3 shell…`（§441 记过；2026-11-21 起其中 ping 那格已修）。

已知脆性：堆上限 2048 字节、**每进程页表已做但容量只有 `MAX_ADDR_SPACES = 8` / `AS_PT_SLOTS = 16`**
（2026-11-21 更正：旧措辞「单地址空间（per-AS 页表未做）」已过期——`aspace_new_kernel` /
`aspace_root` / `cr3_writes` 都在，换人路径按 AS 真写 CR3，判据 `ktests/memory/mm.rs:613`）、
`MAX_CPUS = 8`、驱动句柄表 8+8 写死、`MAX_OWNED = 16`、资源台账按模块聚合而非逐句柄。

**2026-11-22 更正（ADR-178）**：上面这一整段容量数字（`MAX_ADDR_SPACES = 8`、`MAX_CPUS = 8`、
`MAX_OWNED = 16`、驱动句柄 8+8 …）都是**按开发机拍的**，源码注释里自己写着「今天无 workload
依据，按接缝够用定尺」。**不要再把它们当硬件参考。**

容量基线的唯一来源现在是 `docs/architecture/capacity-baseline.toml`：每个值都带 Linux 主线源码
出处，取舍的标 `is_tradeoff` 并写理由。门禁 `check-capacity-baseline`（第 20 道）双向对账——
源码里每个 `MAX_*` 必须登记，登记的值必须与源码相等。

**2026-11-22 更新（ADR-179 落地后）：全部达成，该门禁已绿。**

| 常量 | 值 | 验证 |
|---|---|---|
| `MAX_PROCESSES` / `MAX_ADDR_SPACES` | 32768 / 32768 | `capacity: ... ⇒ true` |
| `MAX_JOBS` | 1024 | 同上 |
| `MAX_HANDLES` | **131072** | `handle: slots ... len=131072` + `irt=24` |
| `MAX_TASKS` / `MAX_TASKS_SUPPORTED` | **256** / 256 | 100/100 |
| `MAX_VA_RESERVATIONS` | **65536** | `map_hole 往返=true` |

**ADR-179 把句柄槽数组从 `.bss` 改成了运行时分配**（`phys_alloc_above` + HHDM），
所以 131072 不再撑爆镜像布局。

**一条新纪律（两次实测撞出来的）**：**栈数组不许跟容量走。**
`[0u8; MAX_HANDLES]` 在 131072 时是 128 KiB、`[0usize; MAX_TASKS_TOTAL]` 在 256×8 时是 16 KiB，
两者都把内核栈打穿（`unexpected vector=8`）。改成小常量 + 边界判断 + 分批判。

<!-- aoci:begin -->
## AOCI 仓库认知

AOCI 为本仓库维护一个稳定、可版本化、可增量更新的仓库级认知层，供模型跨任务复用对系统的理解。

`aoci.txt` 是面向模型的结构化认知索引。它以每个受管理文件、数据库表或其他受管理对象一条独立 Entry 的方式，用符号标签与 F/R/A/S 语义表达对象的核心职责、重要关系、对外契约，以及理解或修改系统时必须知道的非显然约束和设计决策。

Header、目录段和全部 Entry 共同组成完整仓库索引，可以覆盖前端、后端、配置、数据库结构及其他受管理内容。受管理内容发生变化时，通常只需维护受影响的认知条目，不需要重新生成整个索引。

AOCI 提供系统架构、对象职责、重要关系、对外契约和关键约束的高密度视图。

### 工作原理

AOCI 采用“模型生成、模型读取”的认知闭环。

Header、Entry 和 Curation 语义的创作只按当前机器签发的 Plan 与实时 Guide 执行；由 Host 模型基于当前绑定证据独立完成。

Entry 的语义必须来自模型对真实证据的理解。不得仅依据路径、文件名、扩展名、AST、符号列表、依赖扫描、正则、固定模板或规则引擎推导、预填、拼接或改写索引语义。

对 Fresh Bootstrap，只按当前机器签发的 Plan 和实时 Guide 执行。当它们要求创作时，Host 模型创作 Root、Meta、Tag 和 F/R/A/S，提供 authoring-run 声明，并把它绑定到 Plan、Evidence 与完整 Candidate。不得要求 AOCI 填写 `origin=host_model`、制造 Receipt 或把程序生成的 Framework 当作语义。本文件不自行重建 Onboarding 流程。内部批次不是用户决策；只有遇到既有批准边界或真实的安全、漂移、CAS、Recovery 条件才停止。

### 最小使用入口

- `aoci_rules`：取得当前AOCI版本的会话运行合同。
- `aoci_overview`：建立或恢复本仓库的完整认知。
- `aoci_maintain`：受管理对象达到最终稳定状态后检查认知是否需要维护。
- `aoci_update_entry`：提交与当前证据和源码摘要绑定的完整语义更新批次。
- `aoci_report`：仅当当前布局和工具状态支持时，在证据不足、无法可靠生成语义时登记待办，不猜写。

其他MCP工具、CLI命令、参数和专项流程，以当前工具说明、Guide和 `--help` 返回内容为准，不在本文件中重复完整手册。

本区块只规定仓库接入、认知使用和收尾原则。`aoci_rules` 承载当前会话合同，Guide实时输出承载当前Plan的执行顺序与停点，工具Schema、Spec和Validator承载机器结构与判据；Prompt、Description、README和静态文档不能覆盖这些机器事实。

### 建立、生成和恢复认知

1. 每个新的 Agent Run 开始时，应先判断：

   - 本仓库是否已经存在可用的完整AOCI索引；
   - 当前上下文中是否已有与本仓库根、当前索引版本和当前AOCI服务相匹配，并且模型仍可可靠使用的完整仓库认知。

2. 仓库已经存在可用的完整索引，但当前Run没有可靠完整认知时，先调用 `aoci_rules`，再调用 `aoci_overview`。

   完整认知仍可靠时直接复用。局部不确定本身不要求机械重读系统全貌。可靠认知建立后，默认以它作为仓库级系统上下文，只读取当前任务直接需要的源码、测试、配置与契约，只有某个缺失的具体事实可能改变回答或验证结论时才扩大证据范围；AOCI不能替代修改对象与验证行为所需的直接源码证据。

   本Run从已知Host上下文压缩恢复时（包括宿主注入的压缩摘要），必须把此前模型认知视为不可靠。压缩handoff不得保留或摘要正式Whole-Index，也不得保留或摘要任何Overview Header、Entry、Chunk、Challenge或Attestation正文；只能保留安全续接所需的receipt身份、未完成write或Recovery状态，以及立即重载指令。复制进handoff的Whole-Index语义或receipt不能证明恢复后模型的当前认知可靠。若当前上下文已无法可靠保留运行合同，先调用 `aoci_rules`。继续业务任务前，使用 `refresh_reasons=["context_compaction"]` 和新的 `refresh_event_id` 调用普通完整Whole-Index `aoci_overview`（不设置 `check_only` 或设为false）；不得使用 `check_only` 或认知probe。原样跟随每个 `next_cursor` 直到 `completed=true`，确认交付，并且只基于新交付正文提交一次Attestation。完成这次新的完整传输后，即使Attestation为partial或fail也消费该generation，并按既有合同继续source-bound任务，不再自动调用第二次Overview。若该请求返回 `delivery_mode=capacity_stop`，说明Whole-Index装不进本Host的上下文：不得重试或调小 `chunk_tokens`；该停止消费本generation，任务按source-bound继续，且不作无保留的完整系统认知声明。

   AOCI可以针对 `context_compaction`、项目 `cognition_refresh_threshold` 下的机器 `semantic_threshold` 或主要 `phase_transition` 提供checkpoint与认知状态事实。只需要这些紧凑事实时使用 `check_only=true`；这些事实只向Agent提供建议，不替模型决定是否需要系统全貌。

   Agent显式调用普通 `aoci_overview`（未设置 `check_only` 或为false）时，只要能形成一致的CognitionSet，AOCI必须完整交付请求scope。不得因为已有receipt、阈值未达到或没有待处理刷新原因而抑制正文；唯一例外是待处理压缩刷新的上述容量停止。正式认知Dirty或Stale时仍交付正文，但必须标记不可靠。存在未决恢复或无法形成一致snapshot时失败关闭，不返回混合正文。

   普通Overview返回 `continuation_required=true` 时，必须原样提交 `next_cursor` 并自动继续到 `completed=true`。不得询问用户、开始业务任务或给出阶段性系统结论。每块单独一次工具调用；不得在一个脚本里连取多块或合并其输出。缺块、重复、乱序、cursor失败、Index变化或`chunk_tokens`变化时停止本次认知链。Attestation完成前不得用Memory、源码、Spec、`aoci.txt`、历史会话、scope、search或Entry读取修补或补充Whole-Index认知。Challenge ordinal是正式Entry序列中的1-based位置；Header内容、注释、空行、Section/Overview/Chunk Marker、Receipt与Metadata均不计数，Chunk Receipt ordinal使用同一序列。Attestation必须原样回绑本次Challenge发布的当前`index_sha256`、`entry_sequence_sha256`与`entry_count`；旧Index、旧Entry序列、旧数量或旧Attestation均无效。完整链结束后只正式提交一次既有模型认知Attestation；同一响应只允许一次不改变语义答案的JSON Schema或字段格式修正。未达通过（全对的序号不足80%，或对象身份错超过一题）即记为不确定回执，不得语义重试或旁路补答。首次认知失败时还不得执行Root/Meta、Migration、全局布局或其他未重新绑定的系统级决策。上下文压缩刷新若传输完整、认知身份不变、治理对齐且没有Recovery或第三方冲突，即使Attestation为partial或fail也消耗该refresh generation，并继续原任务，不再自动重读Overview。`system_mastery_percent`只自评系统框架——架构、职责、强关系、稳定外部契约以及高熵安全和维护约束——不表示完整实现或运行实况知识；机器索引覆盖率必须分开。默认只向用户输出由本次真实覆盖率、Challenge、块数、Token和掌握度生成的规定成功或失败一句话。Host截断某一块时，用同一cursor重取一次并核对 `chunk_sha256`，服务端返回完全相同的字节。仍被截断才停止，提示用户把 `overview_delivery.chunk_tokens` 设置为更小的合法值后重新开始，不得自动修改。

   加法认知等级必须与严格证明字段分开解释。`delivery_verified`表示已加载Index且Host交付已确认，但完整认知验证仍未完成；应表达为“已加载且交付已验证”，不得描述为“没有认知”或“没有理解系统”。`cognition_verified`要求Attestation通过（Challenge至少80%的ordinal完全正确且对象身份至多失手一处），`cognition_governed`还要求治理对齐。通用完整读取失败句只用于真实交付故障。

   当Overview响应包含可选`cognition-state/v2`投影时，必须分别解释各维度。其Level止于`model_cognition_usable`；`strict_attestation_verified`、`governance_aligned`与`current_system_cognition_reliable`都是独立状态，绝不参与该Level。ordinal、对象身份、Tag或核心F不匹配可以导致严格Attestation失败，而模型认知仍然可用；不得仅凭这种不匹配就宣称模型没有理解系统。只有`current_system_cognition_reliable=true`允许无保留地声称当前完整系统认知可靠。投影缺失时继续使用上述Legacy解释。

   普通的只读审计、分析、检查、不修改代码或不提交、不push，不自动等于严格零写入，也不改变上述认知有效性判断。Codex Memory和历史Skill只能辅助恢复经验、用户偏好与调查方向，不能替代与当前仓库根、索引摘要、AOCI服务身份和认知范围匹配的当前认知收据；项目AGENTS和当前AOCI身份在AOCI状态上优先于历史Memory。

   只有用户明确禁止Ledger、元数据、`.aoci`运行资产及任何文件写入时，才按严格零写入处理。若必要的认知建立与该边界冲突，必须报告冲突并请求用户裁决或建议使用隔离副本，不得静默以Memory替代当前仓库认知。

3. 仓库没有可用的完整索引，或当前只有最小骨架、Header不完整、Entries未完成、必要Curation尚未裁决时，如果需要建立正式完整AOCI索引，先取得 `aoci_rules`，然后进入当前AOCI Guide。由Guide依据仓库真实状态决定下一阶段并完成必要安全步骤。

   `aoci_maintain` 不替代索引建立流程。

   不在本文件中自行重建或硬编码完整索引生成状态机。

4. 在长程任务中，模型负责保留当前认知收据并正确使用刷新门禁：

   - Host报告上下文压缩或模型已知系统全貌丢失时，执行上述强制 `context_compaction` 重载规则；AOCI不能自行推断Host事件；
   - 进入真正的主要阶段时声明 `phase_transition`，不得把函数、测试运行或小步骤当作阶段；
   - 在有用的稳定检查点通过 `check_only=true` 取得机器语义计数；
   - 除已知压缩的强制重载外，由Agent判断当前任务是否需要再次显式获取指定scope或完整Overview；
   - 在维护和对齐完成前，保留AOCI报告的Dirty或Stale可靠性状态。

### 任务收尾与认知维护

5. 纯只读问答、分析、版本核验，或没有产生受AOCI管理对象变化的任务，不需要调用维护工具。当前AOCI版本是任意`aoci_overview` check_only或`aoci_maintain`响应里的`cognition_receipt.mcp_service_version`；二进制路径是项目`.mcp.json`里的`command`，CLI不必在PATH上。

6. 发生受AOCI管理对象变化时，待其达到本次任务的最终稳定状态后，只调用一次 `aoci_maintain`。不要在每次中间修改后逐文件维护。

7. 若维护结果返回真实语义候选，Host 模型必须基于每个候选绑定的对象和必要证据，独立创作完整标签与F/R/A/S更新。通过 `aoci_update_entry` 一次提交当前机器签发批次的完整候选集合，同时原样保留每项路径与对应domain批次身份；`source_sha256` 与 `candidate_id` 可以省略，由服务端按签发的批次取得。`max_entries`只限制单次请求和原子事务，不限制logical plan、Whole-Index或Managed Scope。`remaining`非零时，在当前批次成功Apply后重新调用Maintain并从新preimage继续；绝不能为满足transport上限缩减Index覆盖或自行截取返回批次。

   没有足够证据且当前布局支持 `aoci_report` 时，使用它而不猜测、套用模板或为消除待办而生成缺乏证据的认知。

8. 必须遵守工具返回的结构化状态和安全边界：

   - `repair_required`：只修复明确命中的候选，再重新提交当前机器签发的完整批次；
   - `stopped`：结束当前写入尝试并检查 `failed_step`、错误、正式写入证据与Recovery。auto模式下，已证明零写入则记录closure并重新Plan；完整Intent和可证明postimage则Resume；策略要求Rollback且preimage可证明则精确恢复后重新Plan。只有证据不足、第三方正式字节冲突、需要审批或外部动作，或命中其他真实安全边界时，才停止整个用户任务；
   - 冲突、审批、人工裁决、权限和安全信号不得忽略；
   - 已经对齐后不得重复维护或重复写入；`refresh_ready_for_overview` 是checkpoint事实，由Agent决定是否为下一阶段请求普通完整Overview。

   维护完成后如果又修改了任何受管理对象，之前的维护结果失效，应在新的最终稳定状态重新完成收尾。

9. 用户只限制业务文件范围，但没有明确禁止仓库托管资产时，AOCI托管资产可以在收尾阶段为保持认知一致而更新，并应在审计和提交中与业务文件区分。

   用户明确禁止修改 `aoci.txt`、`.aoci`、元数据或任何额外文件时，以用户限制为准，不得写入，并如实报告剩余不一致。

10. **本仓库的裁决（2026-11-22，使用者）：符合条件就必须自动更新，不再问。**

    上面第 9 条把「更新」写成**可以**（"可以…更新"），把「不写」留成默认。
    "可以"在实践中等于"不做"——所以这里把它改成必须。

    **先澄清一个我差点写错的读数**：`scope show` 报 `index 4 / observe 486 / exclude 28`，
    而索引里只有 **1 条 Entry**。看着像欠了 3 条账，**其实不是**：
    那 4 个 index 角色是 `kernel/src/memory/mm.rs` **加上索引自身**（`aoci.txt` /
    `aoci.code.txt` / `aoci.meta.txt`），`governance: 已对齐` 说的就是这个。
    **1 条 Entry ↔ 1 个业务 index 文件，没有欠账。**
    其余 486 个文件是 `observe`（记指纹、不写 Entry），那是 `aurora-observe-rest`
    这条人工规则的**试点范围决定**，不是漏更新。

    **本仓库从今天起改为强制。判据是机器可查的，不是靠自觉：**

    - **何时算「符合条件」**：本次任务改了 `managed_scope` 里的对象，且这些改动已达
      本次任务的**最终稳定状态**（不再有后续编辑）。中间状态**不**触发。
    - **触发后必须做的**：在收尾前调用一次 `aoci_maintain`；有真实语义候选时
      按第 7 条一次提交完整批次；`remaining` 非零则继续，直到 `terminal_proof`。
    - **什么情况下才允许不更新**：只有三种——① 使用者当次明确说"不要动索引"；
      ② `aoci_report` 因证据不足登记了待办（此时**必须**在收尾汇报里写出这条待办）；
      ③ AOCI MCP 工具在本会话**不可用**（此时**必须**在收尾汇报里写明"索引未更新"及原因）。
    - **静默跳过不允许。** 没更新就写"未更新"，不许不吭声。

    **为什么这一条要写进本文件而不是留在会话里**：索引与源码的一致性
    只有在**每次**改动后都维持才成立；漏一次就开始漂，而漂了的索引比没有索引更坏
    ——它会让后来的人以为"这里没东西"。

### 专项流程

初始化、完整索引生成、Header生成、Entries生成、数据库结构索引、Curation、人工评审和故障恢复，只按当前AOCI Guide或工具在对应阶段返回的指令、命令和安全停点执行。

不预加载、不猜测，也不自行重建这些专项流程。平台调用方式、请求格式、批次上限、审批规则、索引格式细节和恢复步骤由对应Guide、工具说明、模型Prompt和CLI帮助按需提供。
<!-- aoci:end -->
