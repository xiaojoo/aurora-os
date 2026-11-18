# ADR-137：B3 时间出口——32 号 `SYS_CLOCK_UPTIME` 与 shell `uptime`

状态：采纳（2026-11-18，证据来源 / 总设计阶段 B3 / 使用者裁决：**新增号不再逐个询问**）
**两侧都已交付并进判定行**（内核 `t_clock_uptime` 四格 + 变异证红；shell `uptime`
进 a3 判定行 `_uptime_row` + 变异证红）。
关联：手册 §12（时间）、ADR-036（时钟）、`clock.rs`（PIT 标定纪律）、ADR-135/136
（30/31 号，同族的"底座+用户态出口"切片）、总设计《Aurora-OS-完整操作系统架构与
Shell命令体系建设总设计-V1.0》§阶段 B3（验收句 `date`/`uptime`/`sleep`/`service status`/
`reboot`/`poweroff`——本片交付 `uptime` 那一半）

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计；发现冲突先记差异，
> 不要为了让文档一致去改已经验证的结论。每条结论标「实测」或「推断」。

## 背景

总设计阶段 B3 的验收句是"`date`、`uptime`、`sleep`、`service status`、
`reboot`/`poweroff` 有实际效果"。基线盘点：`clock.rs` 已有 **PIT 反推的 TSC 频率
标定**（`from_pit_window`/`hz`/`micros`，没标定回 `None`、绝不编默认值的纪律写在
函数头）与既有判据（`t_clock_calibrated_by_pit` 的 9..11 ms 区间 + 跨仪器等式）；
缺的是 ①**启动锚点**（内核没记"启动那一刻的 TSC"）②**用户态读出口**。

⇒ 使用者裁决：新增 32 号 `SYS_CLOCK_UPTIME`；**且从本轮起新增调用号不再逐个询问**
（"下次都直接新增，不要询问了"）。

## 决策

### 决策 1：锚点记在 stage0 自证之后

`clock::record_boot(tsc::now())` 放在 `kmain` 的 `boot-ok` 日志之后：再早就可能在
串口失败退出的路径上白记一次，再晚就把 bootloader 那段算漏了。
**只允许一次**：重复调用忽略并计数（`reanchors()`），判据有一格专查它为 0——
重锚会把 uptime 拉回 0，那是骗人的形状。

### 决策 2：32 号无参数、无缓冲、无 capability

`uptime() -> micros(u64)`。锚点没记 / 频率没标定 ⇒ `-1`，**绝不回退成默认频率**
（与 `clock::micros` 同一条纪律）。返回 64 位微秒（约 58 万年不回绕），无翻页问题。

### 决策 3：判据的区间口径（本片修掉的数学错误）

内核 `t_clock_uptime` 四格：①单调不减（两次 syscall 相等也算过——间隔可能小于
1 µs）②**与 ticks 对账** ③**与 TSC 上界对账** ④无重锚。

**② 的初版是错的**：下界写成 `micros(tick_period × 2)`（20 ms 整），但
`wait_ticks(t, 2, ..)` 等的是"计数 ≥ 2"，它可能在 tick 边界**中途**开始 ⇒
实际等待在 [1, 2] 个周期之间。a3-shell 档实测增量 19023 µs < 20000 ⇒ 红
（§399 的 prockill 同族：跨档才暴露的判据错误，不是内核错）。
**修订**：下界 = 1 个完整周期（跨 2 个边界至少跨过 1 个），上界 = `w.cycles`
（wait_ticks 自带）**+ 1 个周期余量**——`t1` 在返回**之后**才读，中间的指令可能
再跨一个边界（实测差 44 µs）。

**③**：同一段真实时间里，"走 syscall 的那条路"（trap+分派+锚点换算）不可能比
"TSC 直接量"更快 ⇒ `uptime(现在) − uptime(那时) ≤ micros(tsc 差)`。

**变异证红**：把 32 号改成恒定返回 42 ⇒ ②红（`a=b=42`）⇒ FAIL(35)；还原绿。

### 决策 4：shell 判据不依赖数值

`_uptime_row`：回显后首行必须是**纯十进制正数**。打 `-1`（内核没锚点/没标定）
或非数字 ⇒ 红。不依赖具体数值（机器快慢、跑多久都成立）。
**变异证红**：把输出改成恒 `-1` ⇒ `False`。

## 落地时撞到的两件事（实测）

### 1. dispatch 的 32S（≥5 字节命令名的 memcmp 取址）

加 `uptime`（6 字节）后链接报 `R_X86_64_32S out of range`——**三处**，全是
dispatch 里 `streq(p.cmd, &CMD_xxx)` 对 `.rodata` 数组的取址（`lspci`/`dmesg`
5 字节 + `uptime` 6 字节）。机理：`streq` 的 `a == b` 对**短数组（≤4 字节）**
折叠成 immediate 比较（不取址，dispatch 的老分支全走这条）；**≥5 字节折叠不动**，
LLVM 降级成 `memcmp` 并对 `.rodata` 数组 **32 位绝对取址** ⇒ 镜像基址在 4 GiB
之上必炸（与 MSGS/`put_u64` 那族同根）。`lspci`/`dmesg` 加入时侥幸没炸——
**分支数改变折叠决策**，加到 12 个分支时三个数组全走了 memcmp。

试过 `black_box` 挡 memcmp：**不行**——循环展开后仍对固定数组取址。
**正解**：新形状 `cmd_is(cmd, name)`（长度 + 逐字节比较，比较数以 immediate 出现
在指令流里，`.rodata` 里不落数组），三个 ≥5 字节命令的分支全部换用它。
**纪律**：dispatch 里加 ≥5 字节命令名一律用 `cmd_is`，`streq` 只留给 ≤4 字节的。

### 2. `.text` 窗口第三次涨

`cmd_is` 的真循环让 dispatch 再涨 ~1.5 KiB ⇒ `.text` 结束 0x100005614 > `.rodata`
起点 ⇒ 窗口 20 KiB → **24 KiB**（`.rodata@0x100006000`、`.data@0x100008000`）。
ADR-133 记过 16→20 的同一件事，这是第三次。

## 备选方案

1. **32 号返回 `(secs, nanos)`**：两格寄存器够，但内核现在**没有墙钟**
   （RTC 未读），nanos 是编的。不选——uptime 只有微秒一种真实单位。
2. **32 号带游标支持"自某时刻起的间隔"**：消费方还没有；等 `sleep`/`timeout`
   命令出现再说。不选。
3. **不加号，uptime 从串口日志的时间戳算**：那是宿主机侧的量具，不是内核的
   读数，违背"读取真实数据"。不选。

## 影响

正面：B3 验收句的 `uptime` 那半达成；`clock::record_boot/uptime_micros` 是
后续 `sleep`/`date`（墙钟）的底座。

负面：`date`/`sleep`/`service`/`reboot`/`poweroff` 未做（RTC/电源/init 各是
独立片）；`uptime` 只有微秒单位，人性化显示（s/m/h）属显示层后续片。

## 验收与负样本

- 内核侧：`t_clock_uptime` 四格，handles 与 a3-shell 两档全绿（108/108）；
  变异证红（恒 42 ⇒ 红还原绿）。
- shell 侧：`uptime` 进 a3 判定行（`_uptime_row`），变异证红（恒 -1 ⇒ 红）。
- `check` 17/17（unsafe runtime U5 40→41、census 471→472；module-interfaces
  登记 `clock::record_boot`/`clock::uptime_micros`）。

## 迁移与回滚

32 号是**新增号**：回滚 = 删常量/分派/实现 + `t_clock_uptime` + `record_boot` 调用
+ runtime 封装 + shell `cmd_uptime`。`_uptime_row` 撤下不影响其它格。

## 未决

1. **`date`**：要读 RTC（CMOS 端口），与时区/墙钟语义是独立片（BACKLOG 已记
   "RTC 游标实测不可用"的旧账）。
2. **`sleep <ms>`**：用户态已有 `rt::sleep_ms`（19 号薄壳，ADR-133 加的），
   差的是 shell 命令与参数解析——最薄的一片，可作 B3 下一刀。
3. **`reboot`/`poweroff`**：ACPI 电源状态 + 8042 键盘控制器复位/ACPI S5，
   触及"停机语义"（`exit.rs`），要单独 ADR。
