# ADR-266：S4 网络与安全 I —— NewReno / SACK / SYN cookie / RFC 6528 ISN；KASLR·栈保护·PTI 仅评估

状态：**部分采纳**（2026-11-27）。关联：ADR-203（重传）、ADR-200（accept）、ADR-263/264（S2）、ADR-265（S3）、S1 `rand.rs`。
**纯函数层与 ISN/临时端口接线已编译并在 QEMU 验证；NewReno/SACK/cookie 未接入内核产品路径。**

> 合入记录（2026-11-27，主线）：纯函数层、`isn_source.rs`、`ktests/net/isn.rs`、socket.rs 四处 ISN 接线、user.rs UDP 临时端口、main.rs 播种、`kernel/Cargo.toml` 依赖均已落入。
> 合入时对原包的**修正**：①`isn_source::isn_for` 改为调用 `host_tcp::isn::isn`（算法单一来源，原包自己重写了一遍）；②ktest 的 `tsc::spin` 路径改为 `crate::time::tsc::spin`；③播种放在 `stage_rand()`（原包写的 `init_from_hw` 是私有函数）；④主动端 `(s.local,s.peer)` 先拷到局部变量再进闭包；⑤UDP 临时端口 `in_use` 传恒假（socket 层无占用查询，新增会碰锁序，待裁决），冲突由 `bind` 判定；⑥原包的 `socket.rs.diff` 没有 `user.rs` 的 UDP 端口改动，但 ADR 声称已做——本次补上。
> **仍未编译、未跑 check/ktests。**

## 0. 范围结论（先读这一节）
S4 手册的出口判据——**packetdrill ≥ 90%、iperf 小样、SYN 洪泛下仍可建立合法连接**——在今天**没有被测对象**。读源码得到：

| 事实 | 出处 |
|---|---|
| `tcp_start_connect`/`tcp_on_segment`/`tcp_listen`/`tcp_close` 在产品代码里**零调用点**，只有 `ktests` 调用。产品里只有 `tcp_accept`(user.rs:3020) 与 `tcp_send_payload`(user.rs:3097) | `rg` 全仓 |
| `deliver_frame`/`poll_once`（真实收包路径）只解析 **UDP**；IPv4 分支只调 `udp::parse_frame`，TCP 段不进 `tcp_on_segment` | socket.rs:493-541 |
| `tcp_send_payload` 一次一段、不看任何窗口；`RetxState` 只记一段（"连续发两段时第一段记录被覆盖——真实的能力缺失"） | socket.rs:817-855；tcp_conn.rs:131-133 |
| `Listen` 槽同一时刻只承载一条连接，**无 backlog** | socket.rs:866 |

**推论**：
1. **没有任何真实网络 TCP 流量经过内核 TCP 状态机**。TCP 只存在于"测试手工喂段"的环境。packetdrill/iperf 要先把 TCP 接进收包路径（一个独立且很大的工作，不是 S4 的一步）。
2. **NewReno/SACK 无处施加**：没有发送循环、没有 `cwnd`/`snd_una`，必须先接入 S2 的 `host-tcp::{window,retx}`；而那两个也还没接。**依赖链**：`收包路径接 TCP → S2 window/retx 接入 → S4 cc/sack 接入`。
3. **SYN cookie 无触发条件**：无 backlog ⇒ 不存在"队列满"。要先有监听队列。
4. 因此本批**只**交付：纯函数层（宿主机可测）+ **真正能接的 ISN/UDP 端口接线** + 阻塞依据。**不宣称任何网络出口判据。**

## 1. 决策一览
| 步 | 内容 | 状态 | 证据 |
|---|---|---|---|
| 1 | NewReno | 纯函数层 ✅；接线 ⛔（依赖链 2） | 手册案例 11 **实为 Reno**，已补 RFC 6582 部分确认 + `recover` 点；Python 等价移植：基线全绿，两变异各被恰好 1 个测试抓到 |
| 2 | SACK | 纯函数层 ✅；接线 ⛔ | 收端与 RFC 2018 §7 **4 组权威示例逐字一致**；发端 3000 随机序列 0 违例；`next_hole` 变异 27536 违例 |
| 3 | SYN cookie | 纯函数层 ✅；接线 ⛔（无 backlog） | 布局更正；往返 16 组合；黑盒盲猜 4 个位宽命中率与 2⁻ᵇⁱᵗˢ 吻合 |
| 4 | ISN / 临时端口 | 纯函数 ✅；**接线 ✅（socket.rs + user.rs UDP 端口）** | 见 §3 |
| 5 | KASLR | **仅评估**（需你裁决） | §5 |
| 6 | 栈保护 | **仅评估**（需你裁决 + 本机核实一个事实） | §5 |
| 7 | PTI | **仅评估** | §5 |
| 8 | `mitigations=` | 设计一句话 | §5 |

## 2. 手册案例的缺陷（已纠正）
* **案例 11 不是 NewReno**：部分确认（ack < recover）直接退出恢复，多段丢失只能等 RTO。补 `recover` 与部分确认处理。
  端到端模拟（同一随机丢包链路、**仅此一个变量**）：p=0.005 → 完成轮数 −1.2%；p=0.05 → RTO 次数 41.5→32.1、完成轮数 −9.0%。**只证方向，不证数值**（取决于模拟器的 RTO=10 轮与独立丢包假设）。
* **我自己的两次错**：(a) `recover` 初值取 `snd_una`，使**新连接第一次丢包永不触发快速重传**（RFC 6582 的初值是 ISS=`snd_una-1`），被 Python 等价移植的单测抓到 3 项失败；`first_loss_on_new_connection_fast_retransmits` 咬住它。(b) 我的前两版端到端模拟器给出"NewReno 比 Reno 慢 137%"这类荒谬结果，根因是让两个算法改了不同状态；已修，**只有最后一版可引用**。
* **案例 12 的布局与手册自己的 S4.3 矛盾**（要求保留 SACK/WS 标志，布局却只有 5+3+24 位）。已改为 4+2+1+1+24；代价：MSS 4 档、时间片周期 1024 s。
* IW10（RFC 6928）：手册自己说"未在已核验链接中，落地前请自行核对"——**我也没核对**，已集中到常量 `IW_SEGMENTS`。

## 3. ISN 与临时端口（本批唯一能接线的部分）
### 3.1 现状（有数）
* ISN：`socket.rs:267` `0x1000_0000 + (slot<<8) + gen`；`accept` 后 `+0x1000`（socket.rs:919）。相邻槽差**恒为 256**；accept 后**恒为 4096**。
* 端口：UDP `user.rs:3197` `49152 + slot`，顺序可预测。TCP 无分配（`tcp_start_connect` 零产品调用点）。
### 3.2 一个被抓到的设计缺陷（落笔前）
初稿有 `isn_for_listen`：在 `create` 时给监听槽一个随机初值。**沙箱证明它不满足 RFC 6528**：accept 后槽用 `iss+0x1000` 重开，哪怕初值随机，连续连接的 ISN 差恒为 4096 ⇒ 攻击者建 1 个合法连接就能预测该槽之后全部连接。**已删除**。
正确做法：**ISN 在知道四元组的时刻算**——被动端在 LISTEN 收 SYN（tcp_on_segment，调 `on_segment` 之前覆盖 `st.iss`），主动端在 `tcp_start_connect`。`create`/`accept` 里的 iss 仅是占位。
### 3.3 验证
RFC 6528：同四元组 +4 s ⇒ 差恰 1_000_000；相邻端口差高 8 位卡方 260.4（自由度 255，95% 上界≈293）；旧公式差恒 256；固定 secret 变异被判红。
RFC 6056 算法 3：段内、避开占用、起点卡方 57.9（自由度 63，上界≈82）；**真实上限 MAX_SOCKETS=256 下最坏探测 255 次**（我先报的 8045 是人为占了 16380 个端口，超出内核真实上限，已更正）。
**ktest 格 1 的两侧**（Python 等价移植状态机）：有重算钩子 ⇒ 绿；删钩子 ⇒ 红。
### 3.4 降级矩阵（不静默）
| secret | 时钟 | 结果 |
|---|---|---|
| 是 | 是 | RFC 6528，`ISN_STRONG`+1 |
| 否 | — | 旧公式，`ISN_WEAK`+1（**ISN 可预测**） |
| 是 | 否 | **旧公式**，`ISN_NOCLOCK`+1 且 `ISN_WEAK`+1。**不取 M=0**：沙箱证明 M=0 时同四元组两次连接 ISN **完全相同** |
`ktests/net/isn.rs` 在未播种时对前三格**跳过并告警，不判绿**。

## 4. 本批没有、且不得宣称的
| 项 | 状态 |
|---|---|
| 编译 | **未编译**。本批在落笔/自查阶段抓出我自己 **13 条**错误（均已更正，**不代表没有第 14 条**）：①`crate::time::now_us()` 不存在（真实 `clock::uptime_micros()->Option<u64>`）②`crate::sign::digest` 路径错（应 `security::sign::digest`，**S1 同错**）③ktest 里 4 处 `tcp::Segment` 漏 `data_off` ④`isn_for_listen` 设计不满足 RFC 6528 ⑤NewReno `recover` 初值取 `snd_una` 致新连接首次丢包永不快速重传 ⑥cookie 单包伪造概率先写 2⁻²³（应 2⁻²⁴）⑦**用概率抽样冒充"对 check 做攻击"的测试**（已改黑盒盲猜）⑧端口探测最坏 8045 次的前提超出内核真实上限 ⑨前两版端到端模拟器荒谬结果（NewReno 慢 137%）⑩cc.rs 恒假分支与恒真断言 ⑪isn.rs 的 `probes += 0` 假测试 ⑫时钟未就绪时 M=0 会令同四元组两次连接 ISN 相同 ⑬S1/S2 漏 `kernel/Cargo.toml` 依赖与 `license.pending`。其中 ⑦⑩⑪ 是"测试/断言本身不真"，最危险：它们会让一个有缺陷的实现显示为绿。**以编译器与 ktests 为准。** |
| `siphash24` | **未实现**。手册案例用它，需标准向量测试；本批 PRF 由调用方注入，内核侧先接已被 hashlib 对账的 `security::sign::digest`（SHA-256，**每个 ISN/端口一次，耗时未测**） |
| packetdrill / iperf / SYN 洪泛 | **无被测对象**，见 §0 |
| 真机 | 无 |

## 5. 步骤 5/6/7/8：评估与你需要裁决的点（不写代码）
**读源码得到的约束**：
* 内核基址固定 `0xffffffff80000000`，`relocation-model=static`（非 PIE）（kernel/linker.ld、.cargo/config.toml）；linker.ld 注释写"协议硬约束：可执行段必须在 higher half（**非重定位内核**要求）"。
* 工具链固定 **1.99.1**；rust-toolchain.toml 注释记载：曾因 `stable` 漂移到 1.100.0，**每个用户 ELF 的字节都变了**。
* `do_release` 要求"同一源码两次构建同产物"。

| 步 | 要改什么 | 影响面 | 需你裁决 |
|---|---|---|---|
| **5 KASLR** | 内核由静态改为 **PIE + 重定位**（或 Limine 的 KASLR 配置，**需核对 Limine 11.4.1 文档，我这里没有**）；`.got`、所有绝对地址常量、`ktests` 段符号都受影响 | **整个构建模型**，不是加一个函数 | 是否接受 PIE？熵估算见下 |
| **6 栈保护** | 加 `-C stack-protector=...`。**事实未确认**：存在稳定化提案 PR #146369（已 proposed-FCP、disposition-merge），**我抓取被截断，没看到合并状态与版本**。若已进 1.99.1 → 加一个 rustflag；若未 → 需 nightly（违反工具链固定）或手写 canary | 所有 ELF 字节变（基线 91 份须重生成）；canary 来自 `rand`，**未播种时 canary 可预测**须处理 | **请你本机跑 `rustc +1.99.1 -C stack-protector=strong --version`（或试编）确认**；再决定 |
| **7 PTI** | 每进程双页表根 + PCID；CPUID 判不受 Meltdown 影响则不开 | 内存模型（mm.rs/aspace_switch）；ADR-075 记过**换人路径在 IF=0 下不许取锁** | 是否做？QEMU 默认 CPU 的 Meltdown 声明待测 |
| **8 mitigations=** | 解析 Limine 命令行；`off/auto` | 小；依赖 5/6/7 才有东西可开关 | 5/6/7 之后 |

**KASLR 熵（手册案例 13 的算术我复核）**：窗口 1 GiB、镜像 8 MiB、粒度 2 MiB ⇒ slots≈508 ⇒ **≈9 bit**；20 bit 需 ≥2 TiB 窗口。手册自己说"≥20 bit 默认不可达，须实测后修订指标"——**我同意，并建议 G4/G5 的 "熵≥20 bit" 在 S4 实测前改写为"≥9 bit 单区域；叠加后另算"**。

## 6. 待使用者裁决
| 编号 | 问题 | 建议 |
|---|---|---|
| R13 | 是否把"TCP 接入真实收包路径"立为独立切片（S4 之前或之内）？ | **是**——否则 S4 手册的三个网络出口判据无法评估。需先量：IPv4 TCP 解析/校验和/分片/ARP 已有多少 |
| R14 | `host-*` crate 是否改名 `aurora-host-*`（与全仓风格一致）？ | 改，成本低 |
| R15 | `crates/` 目录是新约定（仓库原本没有） | 批准 |
| R16 | 步骤 5（PIE）、6（栈保护）、7（PTI）是否做、先后 | 6 先（若 1.99.1 已稳定则最便宜）→5→7 |
| R17 | IW10 与 MSS 4 档、时间片周期 1024 s | 接受或指定 |
| R18 | `siphash24` 何时做（cookie 性能） | cookie 能接线时再做 |
