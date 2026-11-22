# ADR-207：`reserved_end` 的位图批扫（修 `t_sdkdemo` 抖动）

状态：**已采纳**（2026-11-22：`t_sdkdemo` 从 4/10 红降到 10/10 绿）

关联：ADR-179 补记二（`release_va_locked` 的同一教训）、ADR-206

## 现象

`t_sdkdemo` 4/10 红，日志：

```
abi: 读用户页被拒 va=0x100002000 —— 页表链没走完（没映射）
sdkdemo: 信箱魔数不对 读到=0x0 期望=0x53444b31（data_va=0x100002000）
```

而同一份日志里反复出现：

```
va: 保留 0x100002000(+12288B) 第 2 页仍已映射，不放手
```

## 根因

`reserved_end` 写的是：

```rust
for i in 0..MAX_VA_RESERVATIONS {
    if st.va_used[i / 64] >> (i % 64) & 1 == 1 { ... }
}
```

**`MAX_VA_RESERVATIONS` 从 256 提到 65536 之后，最坏迭代数涨了 256 倍**，而本函数
在某些路径上持 VMM 锁 —— 持锁时间变长，临界区被打断，保留记录没被正确处理。

**这个教训 ADR-179 补记二早就记过，而且 `release_va_locked` 已经改成位图批扫了 —— 但这里漏了。**

## 修法

与 `release_va_locked` 同一套：按 word 批扫，跳过全 0 的 word。

```rust
for w in 0..VA_BITMAP_WORDS {
    let word = st.va_used[w];
    if word == 0 { continue; }        // 64 个槽全空
    for b in 0..64usize {
        if word >> b & 1 == 0 { continue; }
        let i = w * 64 + b;
        ...
    }
}
```

实际在用的保留数是个位数到几十 ⇒ 迭代数从 65536 降到 ~1。

## 一个自我纠正

排查过程中我一度以为「`t_sdkdemo` 在 `terminate_task` 之后才读槽」，还写了一段修改 ——
**那是误判**：读取本来就在 terminate 之前（第 82-86 行 < 第 100 行）。
那段修改因文本不匹配没有写入，所以没有留下后果。记在这里是因为它说明：

> **先读代码再下结论。判据里的「图象」和源码的「行序」要逐字核对，不能凭印象。**

## 第二个坑：`t_ifaddr` 的 HANG 是假线索

「HANG 前最后一条是 `t_ifaddr`（15 次）」看着像它的错，但对齐用例顺序后发现：
它自己 `→ ok`，只是恰好排在那一轮最后一条。

**`.ktests` 顺序由链接器决定，同一个用例在不同跑里位置可以差 65 位**（第 23 位 vs 第 88 位）。
拿「HANG 前最后一条」当根因，本身就是错的取证方法。

## 读数

| 项 | 改前 | 改后 |
|---|---|---|
| `t_sdkdemo` | 4/10 红 | **10/10 绿** |
| 10 轮 PASS | **5/10** | **8/10** |
| 10 轮 FAIL | 5/10 | 2/10（`t_map_hole`、`t_q2_workload_slots`）|
| 10 轮 HANG | 0/10 | **0/10** |
| `check` | 21/21 | **21/21** |

## 未决

1. **`reserved_end` 与 `release_va_locked` 是同一份教训的第二处** —— 还有没有第三处？
   `grep "0..MAX_VA_RESERVATIONS"` 应当成为一次审计，但这次没做
2. **`t_map_hole` / `t_q2_workload_slots` 仍是 1/10 的偶发
3. **8/10 的 PASS 率** —— 距 100% 仍有两段路