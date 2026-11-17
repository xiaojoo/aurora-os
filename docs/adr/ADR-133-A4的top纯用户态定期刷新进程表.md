# ADR-133：A4 的 `top`——纯用户态定期刷新进程表（27 号的第二个调用方）

状态：采纳（2026-11-17，证据来源 / A4 阶段后续片 / ADR-132 §未做 1）
关联：手册 §10.4（capability 句柄）、ADR-130（argv 区与标准句柄）、ADR-132（27/28 号进程观测）、
总设计《Aurora-OS-完整操作系统架构与Shell命令体系建设总设计-V1.0》§阶段 A4
（验收句"ps、top、kill、free 有真实数据"）、BACKLOG §346

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计；发现冲突先记差异，
> 不要为了让文档一致去改已经验证的结论。每条结论标「实测」或「推断」。

## 背景

A4（ADR-132）交付了 27 号枚举与 28 号统计，shell 有 `ps`/`free`。总设计 A4 验收句里
`top` 还缺着。ADR-132 §未做 1 留了两个待拍板点：**排序口径**与"定期刷新怎么定时"。

本轮开工前的实测事实：

1. **定时原语已存在，零内核改动**：19 号 `SYS_OBJECT_WAIT`（user.rs:1160）带
   `timeout_ms`（≤ `WAIT_MAX_MS` 60 000），超时路径走 `sched::wait_for_proc` 的
   `TASK_WAITERS` 槽 + `task_wake_tick`（sched.rs:1748）的**定时器唤醒**——等待期间
   任务真阻塞（`TaskState::Blocked`），不让 CPU 空转。超时返回 `None`（exit code 0），
   "时限到了"是业务事实不是契约违例（ADR-071 决策 1 的口径）。
2. **可睡的句柄已就位**：16 号 `process_start` 第③步自动 grant 三个 SELF_* 句柄进
   子进程的 SI 描述表（user.rs:989-993），`ROLE_SELF_THREAD`（角色 2）的 Thread 对象
   **永不终止**——拿它打 19 号，唯一出路就是超时。`signals = 0` 是合法位图（无信号位）。
3. **shell 的栈只有一页**：内核装载器给每个 ring3 任务一页栈（user.rs:2909-2916，
   "动态区第一段的第二页，第一页当 guard"）。A4 收口时的 shell 已经贴近上限——
   本轮第一版 `top`（8 行 × 40 字节的行数组 + 128 字节枚举缓冲上栈）当场实测：
   `#PF rip=0x10000397e cr2=0x100100fb8 err=0x6 cpu_cpl=3`（run-1584，栈顶
   0x100101ff0，cr2 在栈顶页下一页 0x100100000，穿出量 ≈0x48 字节）。
4. **排序口径没有现成答案**：单 Job 内进程 ≤4 条（`t_proc_info`/`q2` 判据约束的形状），
   `ps` 按 pid 升序流水打出。`top` 要"按资源视角看谁吃得多"。

## 决策

1. **`top` 是纯用户态命令，内核零改动**。不新增调用号，不新增内核结构；数据面
   全部走 27 号枚举（与 `ps`/`free` 同源），定时面全部走 19 号带时限等待。

2. **runtime 加一个 `sleep_ms(h, ms)` 薄壳**（`user/runtime/src/lib.rs`）：
   `object_wait(h, 0, ms)` 的"等一个永不置位的信号图"。语义 = "至少间隔 ms 毫秒
   后才继续"（超时与提前醒来都算睡到了，调用方不需要区分——`top` 的帧间隔不要求
   精确）。`Ok(_)` = 睡到了；`Err(-4)` = 句柄不能等（resolve 到非 Proc，19 号今天
   只认 Proc 对象）。**推断**：Thread/ASpace 句柄打 19 号会回 `-4`，`top` 的降级
   路径（不睡连打）靠它触发。

3. **排序口径定案：pages 降序，并列按 pid 升序**（ADR-132 §未做 1 的拍板）。
   理由：`pages` 是 28 号的"名下 AS 当前映射页"（ADR-132 决策 3 的口径），
   `free` 的聚合读数同源——`top` 与 `free` 天然可交叉对账；并列取 pid 升序使
   同页数时行序**确定**，宿主机判定器才写得出来。

4. **帧数由参数给**：`top`（无参）= 默认 3 帧；`top N`（N ≥ 2 且 ≤ 5）= N 帧。
   帧间隔固定 1000 ms（总时长 = (N-1) × 1 s）；`top 0`/`top 1`/负数/超限/非数字
   一律打 `top: usage`，不静默降级——"至少两帧"是刷新语义的最低要求，1 帧那不叫
   刷新，那叫 `ps`。

5. **每帧输出形状**：`frame N` 前缀行 + `PID GEN THR ST PAGES` 表头（与 `ps`
   逐字节同一条消息）+ 排好序的表行。五列单空格分隔、无对齐（无堆、无格式化库，
   沿用 ADR-132 的纪律）。

6. **睡眠失败的降级是显式的**：`sleep_ms` 报错时剩余各帧**不睡连打**一次打完，
   不假装刷新、不空转重试——显示层如实降级（实测未触发过；这条是写进代码的
   保底路径）。

7. **shell 栈预算纪律（本轮实测出的新约束）**：shell 单页栈，`cmd_top` 的行数组
   收缩到 4 行（160 字节）上栈；**static 不行**——static 的地址在 4 GiB+ 链接基址
   下同样会被取成 32 位绝对重定位（`R_X86_32S out of range`，本轮实测，与
   `user/shell/src/main.rs` MSGS 注释记的是同一族事故）。`user/shell/link.ld` 的
   `.text` 窗口 16 KiB → 20 KiB（`.rodata` 起点 0x100004000 → 0x100005000）。

## 备选方案

1. **内核加 `SYS_SLEEP`**：为了一个用户态命令加调用号，还要动分派器、加判据、
   走新增号的审批。19 号带时限等待已经是同一件事的通用形状——不选。
2. **`top` 用 TSC 忙等定时**：等待期间任务一直占着 CPU（ Runnable/Running），
   单核时钟下会挤压其它任务；与"等待就该阻塞"的调度器设计（ADR-051/053）相反。
   不选。
3. **static 快照缓冲**：绕开一页栈的约束——但取址本身就是这仓库的第三族 32S
   事故（MSGS 注释、`ctrl_c` 注释记过两回），本轮实测第三回。不选。
4. **8 行快照 + 链接脚本再放大 .text/.data**：8 行版本触发 `R_X86_32S` 的是
   数组初始化的常量图样（.rodata 模板 memcpy），与 static 是同族事故；再放大
   镜像是把量具风险（更大的 ELF = 更多的串口字节）当修法。不选——4 行已覆盖
   单 Job 判据约束的最大形状（q2 至多 4 条），余量按形状给，不按"万一"给。
5. **排序按 threads 降序**：`free` 聚合里 threads 也在，但"谁吃资源"的资源视角
   主语是页（`pages` 口径在 ADR-132 决策 3 已写明是映射页），threads 是活跃度不是
   占用。不选。

## 影响

正面：
- 总设计 A4 验收句的 `top` 到位（`ps`/`free` ADR-132 已交付，`kill` 见未决）；
- 27 号有了第二个真实调用方——`ps`/`free`/`top` 三条命令互相构成对方的对账证人；
- `sleep_ms` 是 runtime 的通用原语，`top` 之外任何需要"定时等待"的用户程序都能用，
  不新增内核面。

负面 / 代价：
- shell ELF 从 35 056 → 35 200 字节，`.text` 窗口 16→20 KiB，`shell.elf` 夹具
  与镜像里两份 shell（卷夹具 hello.elf 同理）都要重算——夹具级变更，随本片提交。
- shell 的栈预算从此是**显式纪律**：任何给 shell 加局部大缓冲的改动都可能重演
  run-1584 的 `#PF`。这条写进 registry.rs 的注释，不写进门禁（量具抓不到"将来
  谁又加了 300 字节"）。
- `top 5` 的整跑时长多 ~4 s；a3-shell 判定行的预算里（12.1 s 单跑实测，
  `t_fs_open_ring3` 的窗口已放宽到 1.6×10^9，见 ADR-132 补记）未见挤兑。

## 验收与负样本

判据行：判定表 `A3 shell执行argv命令并ps/free读数`（`--features a3-shell,fat32-probe`），
argv 脚本扩成 `run /HELLO.ELF; ps; free; top 2`（kernel/src/main.rs 的 `A3_CMD`），
宿主机 `tools/aurora.py` 的 a3-shell 判据从六格扩到九格：

- `top 2` 在串口里出现（argv 确实带进来了）；
- `frame 0` + 表头、`frame 1` + 表头两块都在（"定期刷新"的最低语义）；
- **排序对账**（新增 `_top_pages_nondecreasing`）：把串口里每个 frame 块的表行
  抽出来，逐帧核 pages 列非升、同 pages 时 pid 升序；解析不出每帧至少一行 = 判不成立。

串口原文（run-1587，判定 PASS 33，单跑 12.1 s）：

```
top 2
frame 0
PID GEN THR ST PAGES
0 8 1 live 9
1 6 1 live 7
frame 1
PID GEN THR ST PAGES
0 8 1 live 9
1 6 1 live 7
```

与同跑的 `ps`（`0 8 1 live 9 / 1 6 1 live 7`）和 `free`（`procs=2 threads=2 pages=16`）
三方一致：top 两帧的读数与 ps 逐值相同，pages 聚合 9+7=16 与 free 相同。

**变异证红**（已做）：把 `top_cmp` 的 `a.pages > b.pages` 翻成 `<`（升序），重跑
a3-shell——串口变成 `1 6 1 live 7` 在前（pages 7 < 9），`_top_pages_nondecreasing`
对 run-1586 的日志返回 `False` ⇒ `ash_ok` 判 False ⇒ 判定行 CONTENT-MISMATCH。
还原后 run-1587 判定器返回 `True`。排序判据不是空转。

门禁与整链：`check` 17/17（unsafe 白名单 U5 90→91、census 467→468，registry.rs:470
的 `handle_of_role(si_va, ROLE_SELF_THREAD)` 登记，与本片同轮）；整链见 BACKLOG 本条
的读数记录。

## 迁移与回滚

- 旧 `ps`/`free` 判据六格全部保留，`top` 三格是**追加**不是替换——回滚 = 撤掉
  `A3_CMD` 里的 `; top 2` 与宿主机三格、registry 的 top 一节、runtime 的 sleep_ms，
  互相独立可分步撤。
- `shell.elf` 夹具与 link.ld 窗口属于"不能只回滚一半"的成对变更：回滚 top 但留下
  20 KiB 窗口无害；留下 top 但回滚窗口 = 链接期 `overlaps` 挡住（本轮实测过 16 KiB
  挡住第一版）。

## 未决

1. **`kill`**（A4 验收句的最后一条）：18 号内核面已就绪（`process_kill` runtime
   封装都在），缺的是 shell 侧取 Proc 句柄的角色号——`ROLE_SELF_PROC` 只指向 shell
   自己，杀别人需要"按 pid 找 Proc 句柄"的语义（句柄是 capability，不是裸 pid），
   那是 ADR-132 §未做 2 的设计题，不是本片的手工活。
2. **`top` 的刷新频率/帧数上限是写死的**（1 s、≤5 帧）。参数化毫秒间隔要走 argv
   解析的两个数字，属于显示层便利，不构成判据——留到有真实诉求再动。
3. **`pages` 快照间的一致性没有跨帧断言**：宿主机只核每帧内部的排序，不核
   "frame 0 与 frame 1 读数必须相同"——那是内核判据（`t_proc_info` 的隔离格）的
   职责，显示层不做重复断言。若未来把 `top` 当"变化检测器"用，需要另立判据。
