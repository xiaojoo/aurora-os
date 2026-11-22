# ADR-189：`fd_io` 的 VfsFile 分派，以及 `fs-open` 档的容量修正

状态：**已采纳**（2026-11-22：VfsFile 分派落地；`fs-open` 档从 BOOT-INVALID 恢复到能跑）

关联：ADR-188（fd 读写，未决 1 就是本 ADR 要解决的）、ADR-179（句柄表运行时分配）

> 写作纪律：每条结论标「实测」或「推断」。

## 背景

ADR-188 的 `fd_io` 只接了 Console，VfsFile 回 `-95`。本轮接上。

**接的过程中撞出一个更严重的问题**：`fs-open` 档已经 BOOT-INVALID 了。

## 交付

### 1. 抽出 `file_read_h` / `file_write_h`

`sys_file_read` / `sys_file_write` 的核心逻辑抽成独立函数，供 10/23 号与 76/77 号共用。

**为什么必须抽**：`TrapFrame` 不是 `Copy`，没法「换个 rdi 再调一遍」（与 ADR-188 抽
`console_io_sid` 同一条理由）。

**锁序**：`begin_read`/`begin_write` 取 `RANK_HANDLE(35)`，返回票之后全程锁外做磁盘 IO。
`fd_io` 自己只持 `RANK_NET(36)` 到「解出对象」为止，解完就放锁，然后才调这里。
反过来（先 35 再 36）就是反向嵌套 ⇒ L4。

### 2. `SlotArray::iter_mut`（补一个存在半年的缺口）

`fs-open` 档编译失败，报 `SlotArray` 没有 `iter_mut`。

**这是 ADR-179 留下的**：它只加了 `iter`，而 `handles` 档从不编译走 `iter_mut` 的那两处
（`reset_for_test`），所以缺了没人发现。

### 3. `MAX_HANDLES` 按档区分（本 ADR 最重要的发现）

**根因**：`fs-open` 档的 `Entry` 内嵌 `VfsFile` 的 `ReadCursor` + `VfsEntry`，
单条 **760 字节**（其它档约 64 字节）。

```
131072 x 760 B = 95 MiB
```

在 512 MiB 机器上找不到连续块 ⇒ `handle::init 引导失败 OutOfMemory` ⇒ BOOT-INVALID。

**历史证据**：`fs-open` 档历史 PASS 过 762 次、BOOT-INVALID 0 次 ——
说明这是 ADR-179 把 `MAX_HANDLES` 从 4096 提到 131072 之后才出现的回归。

**修法**：那个档取 16384（`16384 x 760 B = 12 MiB`）。

**这不是「容量够用」，是「大 Entry 档的合理上限」。** 真正的解法是把 `VfsFile` 的大字段
挪进旁表（像 `cells` 那样），那要改十几处读写点 —— 见未决 1。

## 三个实测撞出来的坑

**① 2 的幂取整浪费 3 倍内存**：

`handle::init` 里 `order = bits - 1 - pages.leading_zeros()` 把 5632 页取整到
`2^14 = 16384` 页（64 MiB）。诊断读数：

```
phys_alloc_above: 找不到 order=14 连续块（min_phys=0x17ceab78 limit_pages=130780 free=102233）
```

加 `phys_alloc_contig(pages, owner, min_phys)` 按**实际页数**找连续块，不取整。

**② `min_phys = max_phys/2` 在大镜像下失效**：

`fs-open` 档镜像 `phys_base` 已经到 353 MiB，而 `max_phys/2` 是 256 MiB ——
**镜像本身跨过了那条线**。加 `image_phys_end()`（读链接器符号 `__bss_end`），
起点改成镜像末尾。

**③ 链接器符号名是 `__bss_end` 不是 `__kernel_end`**：第一版写错，链接失败。

## 读数

| 档 | 结果 |
|---|---|
| `handles` | **PASS(33)**，108/108，连跑 3 次全绿 |
| `handles,fs-open` | **从 BOOT-INVALID 恢复到能跑**，117 条用例 |

`fs-open` 档的 `handle: slots 引导 base=... len=16384 pages=3040 清零后used=0`。

那个档的失败是 `t_sdkdemo`（历史 8%）与 `t_fs_open_ring3`（**历史 17.7%**，210/1187，
最早 11-16）—— 都是既有偶发。

## 未决

1. **`VfsFile` 的大字段挪进旁表**：`Entry` 不该被最大的变体撑大。
   那要改十几处读写点，且 `ReadTicket` 的锁序要重新审。
2. **Socket 分派**（复用 53/54，但 socket 的 `send` 要 `connect` 过）。
3. **`readv`/`writev`**。
4. **`t_fs_open_ring3` 的 17.7% 失败率** —— 那个档的既有偶发，本轮没碰。