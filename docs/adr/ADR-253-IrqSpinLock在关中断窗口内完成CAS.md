# ADR-253：IrqSpinLock 的 CAS 必须在关中断窗口内完成

状态：**已采纳**（2026-11-25）。关联：ADR-081（等锁开窗与锁序）、ADR-248（AHCI 入口闸）、BACKLOG §580。

## 背景

`run-14229` 与 `run-14595` 都在 `t_proc_info` 触发 rank20 等锁看门狗，日志显示
`locked=1` 但 `held_by=0xffffffffffffffff`。两次同 ELF 单跑都能清除，因此不能只归因于
宿主机停顿。

`IrqSpinLock::lock()` 的 `may_open` 路径原来在每轮开头 `sti`，随后 CAS；CAS 成功后
才执行 `cli` 并发布 `held_by`。在 CAS 与 `cli` 之间，另一个 CPU 可能看到锁已占用但
持有者令牌尚未发布；若此窗口被中断或宿主停顿拉长，看门狗就会报出 UNHELD。

## 决定

1. 正常路径先用 IF=0 执行 CAS；只有 CAS 失败后才开中断窗口自旋。
2. 每次开窗自旋后先 `cli`，再读 `held_by`、检查看门狗或进入下一轮 CAS。
3. `held_by` 与 `INNERMOST` 只在 CAS 成功且 IF=0 后发布。
4. 新增 `open_window_cas_successes` 计数；正常构建必须恒为 0。
5. 负样本特性 `fault-lock-open-before-cas` 恢复旧顺序，现有跨核竞争用例必须红。

## 验收

| 场景 | 读数 |
|---|---|
| 修复前红测 | `run-15030`：`open_window_cas=16000`，`t_cross_cpu_lock_contention` FAIL |
| 修复后正常档 | `run-15031`：`open_window_cas=0`，默认 **92/92** PASS |
| 恢复旧顺序 | `run-15032`：`open_window_cas=16000`，同一用例精确 FAIL |
| `handles,fs-open` | `run-15033`：**160/160**，`open_window_cas=0` |
| `fs-rw` | `run-15037`：**164/164**；修复随链接顺序暴露的 `t_sdkdemo` 未自足收尾 |
| IRQ 宿主机对账 | 沉降在途 IRQ 后三行 `5=5` / `5=5` / `10=10`；跳过沉降的负样本回到 `5≠4` |
| `check` / 完整矩阵 | **22/22 / 82/82 符合** |

## 边界

- 不改锁等级、锁序、看门狗阈值或 `may_open` 的三个准入条件。
- 该修复消除元数据发布窗口，不宣称所有 rank20 超时都已归因；真机未验证。
- `OpenSpinLock` 仍只有 AHCI 入口契约与设备有界等待，不在本 ADR 偷换成通用锁。
