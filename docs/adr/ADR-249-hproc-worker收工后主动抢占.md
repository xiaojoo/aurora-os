# ADR-249：hproc worker 收工后必须主动抢占

状态：已采纳（2026-11-24）。关联：ADR-206（hproc 提前返回缺陷）、BACKLOG §571。

## 现象与最小化

`handles` 档偶发在串口最后一条 `t_syscall_abi_arms -> ok` 后 HANG，下一格 `t_handle_proc_owner`
没有完成行。20 秒超时、精确匹配“最后一条为该用例且无退出码”的循环在 `run-12705` 第 15 轮复现。

把 QEMU 改成单核后，同一停机点第 1 轮即复现（`run-12752`），排除跨核死锁。QMP 红跑
`run-12760` 显示：

- CPU 在 `tsc::spin+48`，`RDI=1000`、`IF=0`、`HLT=0`；
- 定时器/等待/换入计数两次采样全冻结；
- 当前栈含 `hproc_worker`、`finish_current`、`aurora_trap_entry` 的返回地址。

因此 CPU 已进入下一格 worker，且走过 `finish_current`，卡在函数末尾的 `loop { spin(1000) }`。
`HPROC_GO` 初始等待使用 `spin(20_000)`，与现场 `RDI=1000` 不符，排除“收工标志没发布”。

## 决定

`hproc_worker` 在 `finish_current()` 后调用一次 `sched::yield_now()`，再保留原有有界自旋收尾。
worker 可能以 `IF=0` 被换入；`finish_current` 只标 Done，不会自行打开抢占窗口。主动让出一次
即可建立抢占点，无需逐轮 `int 0xF0`，避免中断风暴。

只改测试工人，不改调度器、任务状态、锁序或产品 syscall 语义。

## 验收

- 修前：单核首轮复现；四核反馈环 `run-12705` 精确红。
- 修后：单核 40 轮 0 次该 HANG（单核 AP 用例按预期 FAIL）；四核 40 轮 0 次该 HANG，
  36 PASS、4 FAIL，4 条均为既有 `t_sdkdemo` 的 `0x100002000` 信箱失败。
- 最终门禁：默认 ktests **91/91**、handles ktests **153/153**、`check` **21/21**。
- 完整矩阵原始读数 **67/82 符合、15 不符**；其中 5 条 FAT32/P7、7 条 A3 是 §570
  已登记的同一组基线偏差。另 3 条用矩阵同一 ELF 单跑清除：`run-12931` `sig-check`
  （`b82c0aa7e11f`）、`run-12932` `fat32-probe`（`6500e718fc7c`）、`run-12933`
  `fs-open`（`be27e9160dc0`），均为 PASS；清除后仍只剩 12 条既有基线偏差。
- `t_syscall_abi_arms` 后 HANG 在整链与 40 轮四核复跑中均未再出现。
- 负样本就是删掉该 `yield_now()` 回到修前状态；同一反馈环会重新在 `hproc_worker` 的
  `spin(1000)` 停机，证明这一行是承重改动。
- 真机未验证。

## 边界

本 ADR 只关闭 `hproc_worker` 这一处。仓库里其他 `finish_current(); loop { spin }` 工人尚未
逐条做同型审计，不把本轮结论外推成“所有 worker 都已安全”。
