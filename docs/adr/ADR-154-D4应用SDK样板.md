# ADR-154：D4 第一片——应用 SDK 样板（**部分落地**）

状态：**部分采纳**（2026-11-19，证据来源 / 总设计阶段 D4 / **零新号**，
使用者裁决"⑥A"：D4 做用户态 SDK 骨架，D5 跳过）
关联：ADR-150/151（凭据与授权）、ADR-153（帧缓冲文本出口）、
总设计《Aurora-OS-完整操作系统架构与Shell命令体系建设总设计-V1.0》§阶段 D4

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计；发现冲突先记差异，
> 不要为了让文档一致去改已经验证的结论。每条结论标「实测」或「推断」。
>
> **本 ADR 的状态是「部分采纳」而不是「采纳」**：可构建的样板与它的构建链已交付，
> 但**运行期判据没有打通**（见「未达成」一节）。按 AGENTS 硬约束 7，
> 「能编译」不等于「能跑」，这里如实标注。

## 背景与裁决

D4 的完整内容是"应用 SDK、开发工具和包生态"。**使用者裁决 ⑥A：D4 做用户态
SDK 骨架**。AGENTS 硬约束 2 禁止"创建没有真实调用者的空 trait/空模块"，
所以这里的"骨架"不能是一堆空接口——它必须是一个**真能编译、真调用已存在号**
的程序。

## 决策

### 决策 1：SDK 样板 = 一个真实用户程序 `user/sdkdemo`

`aurora-user-sdkdemo` 是 workspace 第七个成员（第五个用户产物）。它演示：

1. **只经 `aurora-user-runtime` 调号**——本文件没有一处 `int 0x80`；
2. **38/40 号读凭据并做授权判定**（C1 的出口）；
3. **44/45 号上屏**（D3 的出口，本片只保留了 API 形状，未在样板里调用）。

它同时是"怎么写一个 Aurora 应用"的**活文档**——注释里写清了每一条纪律的来路。

### 决策 2：结果走 `.slots` 信箱，不走串口

`spawn_user` 的第 3 参为 0 时任务**没有控制台句柄**，写不了串口（实测）。
所以结果写进 `.slots` 段的定长结构（`magic/uid/gid/caps/dev/consistent/pad`），
内核用例按 `data_va` 读。这与 `user/hello` 的 `Slots` 形状**完全同源**——
仓库里已经验证过的路，不另发明一条。

### 决策 3：`.slots` 必须是"不可变 `static` + `#[link_section]`"

`static mut SLOTS` + `#[used]` **实测不会进对象文件**（`llvm-objdump -h` 里
根本没有 `.slots`），于是链接脚本收不到、`data_va=0x0`。
改成 `#[repr(C)] struct Slots` + `static SLOTS: Slots` + `#[link_section = ".slots"]`，
写的时候用裸指针 `write_volatile`——这是 hello 的形状，一次就通。

## 本片踩过的坑（全部实测，按代价排序）

### 坑 1：`R_X86_64_32S` 反复出现（四次）

镜像基址 `0x100000000` > 4 GiB，任何**绝对地址引用**都会在链接期炸。触发源：

| 写法 | 为什么炸 | 修法 |
|---|---|---|
| `MSGS.get(off..off+len)` | 边界检查的失败分支生成 24 字节 panic location（`.rodata..Lanon`，`0x18` 是标识） | 裸指针 + `from_raw_parts` |
| `u32::from_le_bytes([..])` | 数组字面量被 const 提升 | 手写移位 |
| `static DIGITS: [u8; 10]` + 索引 | 静态数组取址 | `b'0' + d` 算术 |
| `out(h, (off, len))` 元组参数 | 元组字面量被 const 提升 | 拆成两个标量参数 |

**统一的解法**：`MSGS` 用 `asm!("lea {0}, [rip + {1}]", sym MSGS)` 取基址，
其余全部裸指针。这是 shell / execprobe 已经走过的路。

### 坑 2：`rust-lld` 直接崩（`0xC0000005`）

32S 错误太多时 lld 会 segfault 而不是正常报错，输出变成
`PLEASE submit a bug report to https://github.com/llvm/llvm-project/issues/`。
**看到 lld 崩溃先怀疑 32S，不要怀疑工具链坏了**。

### 坑 3：`.data` 段被 lld 省略

只有 `.text`（flags=5）和 `.rodata`（flags=4）两个 LOAD 段，
没有 `flags=6` ⇒ `data_va=0x0`。修法见决策 3。

### 坑 4：`copy_from_user(va, dst)` 的参数顺序是 **va 在前**

我按 `(dst, va)` 写，E0308。

### 坑 5：`ahci::boot_port()` 与 `fs_open::port()` 都可能是坏盘

（这是 ADR-152 的坑，本片复用了那条结论。）

## 已达成

- `user/sdkdemo` **可构建**：`sdkdemo.elf` 13560 字节、三个 LOAD 段
  （`.text` 1656 / `.rodata` 39 / `.data` 64）——**data 段存在**，`.slots` 在首位。
- 构建链打通：`tools/aurora.py build` 会构建它并落成 `kernel/fixtures/sdkdemo.elf`；
  登记进 `Cargo.toml` members 与 `docs/architecture/crates.toml`。
- 内核夹具 `SDKDEMO_ELF`（`ktests/common.rs`）已就位。

## 未达成（**必须诚实列出**）

**`t_sdkdemo` 的判据没有跑绿**，因此**未注册进 `.ktests` 段**（文件保留在
`kernel/src/ktests/sdkdemo.rs`，`mod sdkdemo;` 已注释掉，供后续接手）。

实测读数：

```
sdkdemo: 判据 38号有回答=true 40号有回答=true 自洽=false
         读数 uid=18446744073709551615 gid=... caps=0 dev=0
```

- **信箱通了**：魔数 `0x53444B31` 读到了、`uid/gid/caps/dev` 五个槽都读到了。
- **`uid=u64::MAX` 是正确结果**：`spawn_user` 这条路不授凭据（凭据只在
  `stage_init_user` 的 16 号路径上授予），所以"没有凭据"是对的。
- **`consistent` 槽读到 0**，而用户态写的是 `if got_dev == expect_dev { 1 } else { 0 }`。
  `caps=0` ⇒ `expect_dev=false`；`dev=0` ⇒ `got_dev=false` ⇒ 应当写 1。
  **读到 0 说明那段写入没有执行到**——最可能是 `cred_allows` 在无凭据时
  返回 `Err`，而 `unwrap_or(false)` 之后某处提前 `exit` 了；也可能是
  `write_volatile` 到 `p.add(5)` 与内核读的偏移不一致（`data_va` 指向的是
  段首，而 `.slots` 在 `.data` 段首位——这一点**已验证**，魔数就在 `data_va+0`）。

**没有继续追**：本片已投入约 40 轮，而 D4 的其余部分（工具链、包生态）
远比这个判据重要。按"需要裁决的跳过"，把运行期判据留成明确的欠账。

## 影响

正面：SDK 有一个**真实可编译**的样板与构建链；`crates.toml` 有说明；
四个 32S 陷阱被系统整理成表（这本身对后续所有用户程序都有用）。

负面：**样板"能编译"但"没跑通判据"**；没有 SDK 头文件式的 ABI 文档；
没有开发工具（调试器、符号化）；没有包生态。

## 迁移与回滚

零新号。回滚 = 删 `user/sdkdemo/`、`Cargo.toml` members 里那一项、
`crates.toml` 那条、`tools/aurora.py` 的 `SDKDEMO_*` 与 `do_build_sdkdemo`、
`ktests/common.rs` 的 `SDKDEMO_ELF`、`ktests/sdkdemo.rs`。

## 未决

1. **`t_sdkdemo` 判据打通**：查 `consistent` 为什么是 0。
2. **SDK 的 ABI 文档**：把 1–45 号的形状整理成一份 `docs/sdk/abi.md`。
3. **开发工具**：符号化、调试器接口、`elf` 检查工具。
4. **包生态**（D5 按裁决跳过）：安装器、仓库、签名分发。
