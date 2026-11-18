# ADR-149：B1 验收句——`lsdev` 与 `devctl status`（零新号、零新 trait）

状态：采纳（2026-11-19，证据来源 / 总设计阶段 B1 / **零新号**）
关联：ADR-136（31 号 `SYS_PCI_ENUM` 与 `lspci`）、
总设计《Aurora-OS-完整操作系统架构与Shell命令体系建设总设计-V1.0》§阶段 B1
（验收句：`lspci`、`lsdev`、`devctl status` 读取真实设备对象）

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计；发现冲突先记差异，
> 不要为了让文档一致去改已经验证的结论。每条结论标「实测」或「推断」。

## 背景

B1 验收句要三条命令：`lspci`（已达成，ADR-136）、`lsdev`、`devctl status`。
后两条的"自然"做法是先建 Device/Driver trait 与设备树——但 AGENTS 硬约束第 2 条
明确禁止"创建没有真实调用者的空 trait"。

**今天唯一真实的设备枚举出口就是 31 号 `pci_enum`**，它的 32 字节记录里
已经有 class code（`cfg08 >> 8` 的 24 位 class）。所以本片**不建 trait**，
直接从已有读数派生两个只读视图。

## 决策

### 决策 1：`lsdev` = class 直方图

按 class code 的**高字节**（base class）分组：

```
class 0x0 count=3
class 0x1 count=1
class 0x6 count=1
class 0x5 count=1
```

**实测**（本机 q35）：6 台设备 = 3 台 unclassified(0x00) + 1 台 mass-storage(0x01)
+ 1 台 bridge(0x06) + 1 台 memory-controller(0x05)。**这与 `lspci` 的六行一致**。

### 决策 2：`devctl status` = 同一份数据的另一种口径

打同样的分类行，末行 `devctl status count=<总数>`。
`count` 是**真数出来的**（每次迭代 +1），不是分类行相加——两处独立计数
互为对账（分类行漏一类，总数仍对；总数错，分类行加起来也对不上）。

### 决策 3：不做 class 名字映射（32S 纪律的硬约束）

"把 class 号映射成 `net`/`blk`/`display` 字符串"这个需求，试了三种写法：

| 写法 | 结果 |
|---|---|
| `match k { 1 => msg(A), 2 => msg(B), ... }` | `.Lswitch.table` ⇒ **R_X86_64_32S** |
| `if k == 1 { A } else if k == 2 { B } ...` | LLVM 仍重组成跳转表 ⇒ **32S** |
| 拆成独立 `#[inline(never)]` 函数 | 函数自己又被降成跳转表 ⇒ **32S** |

**结论**：只要"按数值选一个字符串"，LLVM 就会生成跳转表；4 GiB+ 基址下必炸。
所以**本片不做名字映射**——class 名字由用户看数字（`0x01` = storage 是
PCI 规范常识，不需要内核翻译）。这是**有意的取舍**，不是遗漏。

## 落地时撞到的三个坑（全部实测）

1. **分页终止条件在两个号里语义不同**：
   - 31 号 `pci_enum`：**`next == 0`** 表示到尾（最后一批仍有条目）
   - 37 号 `arp_enum`：**`n == 0`** 表示到尾（`next` 一直等于 `cursor`）

   我批量把三处 `n == 0` 改成 `next == 0`，`cmd_ip_neigh` 立刻**死循环**
   （a3-shell 从 15s 拖到 31s 后超时，`ip route`/`lsdev` 全没跑）。
   **教训**：同族形状不等于同族语义，改终止条件要看那个号自己的约定。

2. **终止判据的位置**：把 `if next == 0 { break; }` 放在**打印之前**，
   第一批就 break——`lsdev` 一行都不打。必须放在**处理完这一批之后**。
   `lspci` 原本就是对的（我抄的时候挪错了位置）。

3. **判定格的段边界**：`_lsdev_rows` 最初扫 18 行找 `class 0x..`，
   结果变异（`lsdev` 不输出）时把 `devctl status` 的输出当成 `lsdev` 的，
   判定**假绿**。修法：扫到下一个命令回显就停（`echo` 正则列出 argv 里所有命令名）。

## 验收与负样本

**实测**（a3-shell，PASS(33) 15.1s）：

```
lsdev
class 0x0 count=3
class 0x1 count=1
class 0x6 count=1
class 0x5 count=1
devctl status
class 0x0 count=3
class 0x1 count=1
class 0x5 count=1
class 0x6 count=1
devctl status count=6
```

**变异证红**：`cmd_lsdev` 开头加 `if c.h != 0 { return true; }`（不打任何东西）
⇒ `_lsdev_rows=False`；还原 ⇒ True（实测两次，第二次还修掉了判定格的段边界漏洞）。

`check` 18/18。整链 68 符合 + 5 条不符——**全部单跑复验通过**：
`virtio-net` PASS、`fat32-probe` PASS、默认档 PASS（82/82、模式 Normal）。
不归因（`t_fat32` 卷抖动连带）。

## 影响

正面：B1 验收句的三条命令**全部达成**；零新号、零新 trait；
两个视图互为对账（分类行 vs 总数）。

负面：**没有真正的 Device 对象**——`devctl` 只能看"有哪些设备"，
不能 `devctl bind/unbind/reset`（那需要 ADR 级别的设备模型设计）；
class 名字不翻译；只覆盖 PCI（virtio-blk/net 之外的设备类型没进这个视图）。

## 迁移与回滚

零新号、零 ABI 变化。回滚 = 删两个命令 + `_lsdev_rows` 格 + MSGS 的 11 段常量。

## 未决

1. **Device/Driver trait 与设备树**：B1 的"统一 Device/Driver API"、
   "驱动匹配和生命周期"仍未做——那是真正的大件，需要单独 ADR 定形。
2. **class 名字表**：如果一定要，得用**运行期构造**（栈上拼字符串）而不是
   const 表，否则 32S。
3. **`devctl` 的写操作**：bind/unbind/reset 需要设备模型先落地。
