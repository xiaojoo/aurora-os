# ADR-019: bootloader-reclaimable 内存的回收时机

状态：已采纳（2026-11-04，M2-c 实测）
关联：手册 §6.2 §6.7、ADR-014（MP）、ADR-018（堆的失败出口）、里程碑 M3b

## 背景

M2-a 起，物理分配器把 memmap 里 `Usable` **和** `BootloaderReclaimable` 两类区间一起当成可自由分配。
依据是 Limine 协议里"reclaimable"这个词的日常含义（可以收回用）。
M2-c 加上 MP（多处理器）请求之后，这个假设炸了：判定链报出一种以前没见过的退出形态——

```
判定=QEMU-EXIT-0 qemu_rc=0   # 不是 33/35/37/39 中的任何一个
```

串口停在跑用例的中途（`t_map_write_unmap -> ok` 之后就没有下文），没有 panic、没有异常行、
没有 debugexit。这个形态只能是一种东西：**三重故障**，QEMU 在 `-no-reboot` 下以客户机 panic 退出 0。

## 根因（协议原文 + 实测）

`.tools/limine-protocol/PROTOCOL.md` 的 memmap 一节，对
`LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE` 的定义是：

> "…containing RAM used to store bootloader or firmware information that should be available to the
> executable (**or, in some cases, hardware, such as for MP trampolines**). The executable should make
> **absolutely sure** that no data contained in these regions is still needed before deciding to
> reclaim these memory regions for itself."

加了 MP 请求之后，bootloader 会真的把 3 个 AP 引导起来**停在**这些区域里
（"The presence of this request will prompt the bootloader to bootstrap the secondary processors"）。
我们的用例一分配/写入那些帧，正在自旋等待 `goto_address` 的 AP 就踩到自己被改写的停车代码/栈
→ 三重故障。

换句话说：协议给的词是 "reclaimable"，给的**条件**是"绝对确认没人还在用"。
M2-a 只照了词、没照条件；而且当时没有 AP，条件恰好成立，所以错误一直没暴露——
**这是一个只在加了新功能后才显形的潜在错误**，这正是 §12.4 要把判定分级做细的理由
（`rc=0` 若被读成"没失败"，这条就会被漏掉）。

## 决策

1. **默认不回收**：物理分配器只放开 `Usable`。`BootloaderReclaimable` 的帧保持"已用"状态。
2. 回收改成**显式、一次性、可计数**的动作：`mm::reclaim_bootloader_regions() -> usize`
   （`#[must_use]`，带幂等哨兵，第二次调用返回 0）。调用前提写进函数文档：
   "所有 AP 都已经离开 bootloader 给的启动栈"。M3b 之前不允许有人调用它。
3. **把代价变成数字**：`mm: bootloader regions held back = 45 MiB` 进启动日志。
   实测（`-smp 4 -m 512M`）：free 帧 128,988 → 117,769，即 512 MiB 里扣着 **45 MiB（≈9%）**。

## 为什么不选别的

| 选项 | 不选的理由 |
| --- | --- |
| 干脆不发 MP 请求（回到 M2-a 行为） | ADR-014 的核实项就是要拿 MP 响应做交叉验证（CPU 数、LAPIC id、`goto_address` 初值），发不出去就关不掉那些待核实项；而且 M3b 早晚要发 |
| 只回收"确认没用"的部分 | 协议**没有**给出哪些帧是 AP 停车点的边界，memmap 只按类型给整段。想细分需要读 bootloader 自己的布局，那是不可依赖的内部实现 |
| 回收后再把 AP 释放掉 | 顺序反了：释放 AP 需要我们自己的每 CPU 栈与 GDT/IDT 就绪（M3a/M3b），而那时才能安全回收 |

## 后果

- 45 MiB 现在在 QEMU 上是"扣着的钱"。**这是有意的保守**，不是完成品：M3b 实现 AP 释放之后
  应立刻调用 `reclaim_bootloader_regions()` 把这笔钱收回来，并把回收帧数记进内存账。
- **M3b-2a 已经执行了这次回收**，前提条件也是那时才第一次具备（"AP 彻底停机"变得可确认，
  依据见 ADR-023：`stop_aps` 逐个等到每个 AP 报告"已关本地定时器 + 已关 IF"，再把它摘出
  在线名单 `cpu::mark_offline`，之后才回收）：
  ```
  smp final: released=3 online=1 stuck_online=0 cpu_ticks=[0, 47, 48, 48, 0, 0, 0, 0]
  mm: bootloader regions reclaimed = 11764 frames (45 MiB) ; free frames now 129258
  ```
  11,764 帧 = 45 MiB，与本 ADR 当初记下的"扣着的钱"逐 MiB 对上（不是同一个帧数：那次是
  free 帧的差值，这次是回收动作自己返回的计数，两者之间还夹着正常分配）。
  两条调用前提也写进了 `after_switch` 的注释：必须在 `stop_aps` 之后，
  也必须在最后一次用到 `mp.cpu_ptrs` 之后——那些 `mp_info` 结构本身就住在可回收内存里。
- 判定链新增了一类真实退出形态（客户机 panic → `rc=0`）。脚本原本把它归成
  "QEMU-EXIT-0（不是任何一个约定码）→ 判失败"，这次证明这条分级是必要的：
  如果 `rc=0` 被读成成功，这个三重故障会一路绿到真机上才炸。
- 台账（§6.7）不受影响：这些帧从没经过分配器，所以不计入任何模块的 `live`。
