# ADR-142：B2 第四刀——ARP 缓存（`arp_lookup` / `arp_learn` / `arp_stats`）

状态：采纳（2026-11-18，证据来源 / 总设计阶段 B2 / **零新号**）
关联：ADR-139（ARP 往返）、ADR-140（ICMP ping 闭环）、`virtio.rs::arp_*`、
总设计《Aurora-OS-完整操作系统架构与Shell命令体系建设总设计-V1.0》§阶段 B2

> **补记说明**：本 ADR 的代码与判据在 ADR-141 之后、ADR-143 之前落地（BACKLOG §417
> 是当时的现场记录），但当时的 ADR 文件漏写；合并（`56426fd`）后按 BACKLOG §417
> 与代码现状补写，**不新增任何已实测之外的主张**。

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计；发现冲突先记差异，
> 不要为了让文档一致去改已经验证的结论。每条结论标「实测」或「推断」。

## 背景

ADR-139/140 让 ARP 与 ICMP 都通了，但每个单播包前都**广播一次 ARP**——
在 ping 的用例里是可接受的一次性开销，在"连续发包"的形状里就不可持续。
RFC 826 的做法是**维护一张表**（收到 reply 就 merge 进表，发送前先查）。

## 决策

### 决策 1：无堆、固定 8 项、线性查找

`no_std` 内核没有动态分配可用（`LARGE_MAX = 2048`，按段开缓冲会被当场打死）。
所以表是**两个固定数组 + 一个长度**：

```rust
struct ArpTable {
    ips:  [[u8; 4]; ARP_TABLE_MAX],   // ARP_TABLE_MAX = 8
    macs: [[u8; 6]; ARP_TABLE_MAX],
    n: usize,
    hits: u32, misses: u32, learns: u32, evicts: u32,
}
```

`ips[i] == [0;4]` 表示空槽（`0.0.0.0` 不会是合法邻居）。**线性查找**：
8 项的上界就是 8 次比较，比引入哈希便宜也更可读。

### 决策 2：RFC 826 的 merge 规则 + 满表 FIFO 挤出

- `arp_learn(ip, mac)`：表里已有这个 ip ⇒ **覆盖**（RFC 826 的 merge）；
- 没有且**没满** ⇒ 追加到 `n`；
- 没有且**满了** ⇒ `evicts += 1`，**整体前移一格、新的放末尾**（FIFO 挤出第 0 条）。

FIFO 而不是 LRU：8 项规模下 LRU 要多一个"最近使用"字段与更新路径，
收益（少挤一条）远小于它自己的出错面。

### 决策 3：三条读数进判据，而不是"看起来有缓存"

`arp_stats() -> ArpStats { hits, misses, learns, evicts }` 是**判据读数**：
`t_net_ping` 的三格 `learned`（learns +1）/ `miss_accounted`（misses 按
broadcast 增量核）/ `hit_ok`（hit 按 lookup 增量核）**全接进 `ok`**——
只判"缓存里有东西"是"看起来像"的判据，判增量才是结构性判据。

### 决策 4：`stats_before` 必须在 `lookup` 之前取

**实测踩到的坑**：`arp_lookup` 自己会记 miss/hit。先 lookup 后取基线，
增量的分子分母就错位——读数 `misses=1/1` 会被误读成"广播了但没核上"，
判据红而代码是对的。**基线采样点本身是判据的一部分**。

## 落地时撞到的事（实测）

1. 上面那条基线顺序（判据红一度指向"代码坏了"）。
2. `net.rs` 的格式串引号写错（`"..." 参数 ...`）⇒ **295 个编译错误的雪崩**；
   另有一次**直接调 `cargo.exe` 丢了 PATH**（`rustc -vV` not found），
   295 个错误全是它级联。**构建一律走 `aurora.py build`**。

## 验收与负样本

- **实测**：`misses=0/1 learns=0/1 hits=0/0`（`stats_before` 在 lookup 之前取），
  `t_net_ping` 六格 + 缓存三格全绿 PASS(33) 6.1s；virtio-net 档 87/87。
- **变异证红**：`arp_learn` 提前 `return`（不学）⇒ FAIL(35)；还原 ⇒ 绿。
- `check` 18/18。

## 影响

正面：单播不再每帧广播；`arp_stats` 的四计数是后续 `ip neigh` 与
"缓存有效性"判据的接缝。

负面：**没有老化（TTL）**——表项永久有效，邻居换 MAC 只能靠 RFC 826 的
merge 覆盖；**用户态路径没有用它**（shell 的 ping 每次仍自己广播 ARP，
ADR-143 未决 1）；**表项没有出口**（`ip neigh` 还没做，ADR-144 未决 1）。

## 迁移与回滚

零新号、零既有判据改动（只加三格）。回滚 = 删 `arp_lookup`/`arp_learn`/
`arp_stats` 与 `t_net_ping` 里那三格 + `stats_before`。

## 未决

1. **老化**：需要与 `sched` 的定时器语义对齐（表项带时间戳 + 周期清理），
   单独片。
2. **`ip neigh` 出口**：把 8 项表读给用户态（扩 35 号或新开一个号）。
3. **用户态共享**：shell 的 ping 应该走内核缓存而不是自己广播。
