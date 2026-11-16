# user 产物 ELF 跨树字节稳定性——修复方案（草案，待 qoder 拍板）

状态：**草案/提议，未采纳，未动任何量具代码**（2026-11-16，workbuddy）。
关联：COORD.md 台账"elfdisk 字节同 2 行红"条目、`tools/aurora.py` `do_build_user` 的 mtime 注释、
AGENTS.md"量具自己也会错"纪律、§80d-3（单独跑抓出整链看不出的量具错）。

## 1. 根因链（实测，每步有证据）

1. `t_fat32_exec` 的 `bytes_same` 格 = 内核 `include_bytes!("../../fixtures/hello.elf")`（fs.rs:13、
   `ktests/common.rs`）⇔ 卷夹具里打包的 HELLO.ELF 字节。
2. 卷夹具（真卷配方 / `make_fat32_mem.py` 现算卷）打包的是**现算时刻**的 fixtures/hello.elf；
   内核嵌入的是**编译时刻**的 fixtures/hello.elf。两时刻之间 hello.elf 只要变一次，这格就**确定性红**。
3. worktree 首建触发变异：`cargo build` 的产物 ELF 含 **debug 路径信息（编译目录 comp_dir 等）**，
   `H:/aurora-os-wb` ≠ `H:/aurora-os` ⇒ 产物字节不同 ⇒ `do_build_user` 覆写夹具（"夹具已更新"）
   ⇒ 与卷里固化/现算的旧字节永久错位。
4. 实测佐证：worktree 内核 sha `5900712` ≠ 主树 HEAD `5900808`；单跑 `run --features fat32-exec`
   **复现 FAIL(35)**（非环境形状）；`跑通=true`——ELF 真装载跑通，红的只是字节级对账格。

## 2. 实验证据（aurora-user-hello，同 RUSTFLAGS 仅改 debuginfo/路径）

| 构建参数 | worktree (`H:/aurora-os-wb`) | 主树 (`H:/aurora-os`) | 一致？ |
|---|---|---|---|
| 现行 flags（无处理） | `d4104f53755e82fc…` | （主树夹具 `e5d84753af57…`，另一份字节） | ✗ |
| `+ --remap-path-prefix=<树路径>=/src` | `4441022a1d66ba16…` | `a579ddfe1f186ad…` | ✗（comp_dir 等残留） |
| **`+ -C debuginfo=0 --remap-path-prefix=<树路径>=/src`** | `8e3972a8a788b2d6e8c9` | **`8e3972a8a788b2d6e8c9`** | **✓ 完全一致** |

结论：**路径差唯一的载体就是 debuginfo**。去掉 debuginfo（remap 可作双保险）后，用户产物 ELF
与构建树无关——worktree / 主树 / 未来任何 worktree 的夹具对账永远同字节。

## 3. 提议的改动（均属 qoder 域，workbuddy 未动）

`tools/aurora.py` 中四个用户产物各自的 RUSTFLAGS 常量（`USER_RUSTFLAGS` 与
`do_build_shell/fileprobe/probe` 的平行副本，126 行起）各追加 `-C debuginfo=0`；
可选再加 `--remap-path-prefix`（双保险，成本为零）。

**为什么是 debuginfo=0 而不是只 remap**：实测 remap 不够（comp_dir 等残留，见上表第二行）。

## 4. 影响面（合并前必须逐条过）

1. **四份用户产物 ELF 字节全变** ⇒ `include_bytes!` 的内核（hello/probe/fileprobe 三处嵌入）
   一次性全量重编（fingerprint 变）⇒ **所有 elf sha 变** ⇒ 判定矩阵需在合并态整链重验一次（本就该跑）。
2. **签名包载荷 = hello.elf 字节** ⇒ PKG 变。判据是内核自算 SHA + 包内 Lamport 签名自洽，
   配方现算则自洽；**需 qoder 确认 esp_image 配方是现算而非固化字节**。
3. **用户 ELF 失去 debuginfo**：内核对 ring3 现场的符号/行号本来就不存在（用户态无符号表），
   崩溃现场靠内核侧记录；P3/P4 的尺子不碰用户 ELF。**需 qoder 确认没有判据读用户 ELF 的 debug 段**
   （`llvm-objdump` 反汇编门禁只对内核镜像）。
4. **worktree 侧立刻收益**：`fat32-exec` 档单跑转绿 ⇒ 判定表 61 行恢复 60 符合（仅剩 q2 环境形状），
   具备合并态重验条件。

## 5. 验证步骤（qoder 执行时）

1. 主树改四处 RUSTFLAGS → `build`（全量重编，看四份"夹具已更新"）→ 单跑
   `run --features fat32-exec` 与 `run --features fs-open` 应 PASS/33 且"字节同=true"。
2. 任意 worktree/新克隆重跑同一命令，产物 sha 应与主树逐字节相同（本方案的核心判据）。
3. `check` 17/17 → 判定表整链（运行队列）→ 与 2a67c68 的 59 符合对账（期望 61 行 ≥59 符合，
   剩余不符只允许 q2 环境形状家族）。
4. 记 BACKLOG（口径变更段）：夹具对账从"路径敏感"变"路径无关"的口径说明。

## 6. 备选方案（若 qoder 否掉 debuginfo=0）

- **只 remap 全部路径来源**：需补 comp_dir（rustc 无直接开关，实践中 `--remap-path-prefix` 对
  comp_dir 也生效——但实测上表第二行仍不一致，说明还有未映射的路径源；继续排查成本高且脆）。
- **卷夹具构建后刷新**：每次 build 后用 `patch_fat32_file.py` 把最新 hello.elf 换进两卷并强制内核
  重编一轮——把"时序交错"变成"强制串行"，但每跑多一轮编译，且仍在治标。
- **维持现状**：worktree 永远带 2 行已知红——违背"合并态重验全绿才 push"（COORD.md §5），
  不可接受。
