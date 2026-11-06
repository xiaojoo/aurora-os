# ADR-016: host 开发平台与统一命令入口

状态：已采纳（2026-11-04，本机实测）
关联：手册 §3.1 §3.2 §3.5、A.5「host 开发平台声明」

## 背景

手册 §3.5 假设 Linux host（sh 脚本、`just`、`$OVMF`、mtools/xorriso），但 A.5 把
"host 平台声明"列为 M0 阻塞项，因为开发机是 Windows 11 x64，且用户要求
**环境依赖全部装在项目根目录内，不写系统**。

## 实测结论（不是推断，都在本机跑过）

| 事实 | 依据 |
| --- | --- |
| rustup 可用 `RUSTUP_HOME`/`CARGO_HOME` 完全落在 `.tools/` 下，`--no-modify-path` 不碰全局 PATH | 实装 rustc/cargo 1.99.1 成功 |
| **MSVC 宿主可以直接交叉链 `x86_64-unknown-none` 成静态 ELF**，链接器是随 rustc 自带的 `rust-lld`，无需外部 LLVM/GCC | 实测产物 `ELF 64-bit LSB executable, x86-64`，`type=ET_EXEC`，入口 `0xffffffff80000950`，3 个 PT_LOAD 段权限 5/4/6 |
| Git Bash 里 PATH 必须是 `/h/...` 形式，而 Windows 程序读的 `RUSTUP_HOME/CARGO_HOME` 必须是 `H:/...` 形式；混用会**静默**找不到 cargo | 踩到后修正 `.tools/env.sh` |
| `__cpuid` / `__cpuid_count` 在本工具链版本是**安全函数**，包 `unsafe` 会触发 `unused_unsafe` | 构建警告实测 |
| `[workspace.lints]` 需要每个成员显式 `[lints] workspace = true` 才生效；漏写则 lint 门禁空转 | `unsafe_op_in_unsafe_fn` 的 deny 在接入后立刻报错，反证生效 |

## 选项

1. WSL2 + apt（本机有 Ubuntu 发行版，可停可起）：与 §3.5 原样一致，但依赖落在
   WSL 文件系统里，不满足"装在项目根目录"。
2. **纯 Windows 便携链进 `.tools/`（采纳）**：满足要求，代价是要自己造 ESP 镜像工具。
3. 系统安装：最快，但违反要求。

## 决策

采纳 2。因此对手册做三处偏离，均以本 ADR 为准：

* **统一入口从 `justfile` 改为 `tools/aurora.py`**（Python 3.12，Windows/Linux 同构，
  后续 CI 直接复用同一脚本，不需要 sh）。`just` 本身也要从 GitHub 下载，属于额外风险。
* **`.cargo/config.toml` 不设 `[build] target`**（§12 V1.2 R15 的落地）：目标由 aurora.py
  显式传 `--target`，因此 `cargo test` 不会被拖到 bare-metal 目标上执行。
* **镜像生成自研**（`tools/esp_image.py`）：本机没有 mtools/mkfs.vfat/xorriso，
  且 GitHub release 资产主机 `objects.githubusercontent.com` 连接被重置，拿不到任何
  现成 Windows 工具。

## 后果

* A.5 里"host 平台声明"一项关闭。
* §3.5 的 sh 片段需要在手册下一版改写为本 ADR 的形式，否则文档与实现不一致。
* `tools/esp_image.py` 是本项目自己写的代码，属于 TCB 之外的开发工具，但它的正确性
  由 `read_back()` 独立读回 + sha256 摘要比对来兜底，不靠"算完就认为写对了"。

## 回退

若 QEMU 在 Windows 上出现不可用的硬伤（如 OVMF 缺文件、isa-debug-exit 不生效），
改走 WSL2 路线，`.tools/env.sh` 与 `tools/aurora.py` 的接口不变，只换命令实现。
