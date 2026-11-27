# ADR-260：initramfs cpio newc 只读挂载对象

状态：**已采纳**（2026-11-27；依据完整化路线 D4 的既有 initramfs/cpio newc 范围）。
关联：ADR-107（薄 VFS）、ADR-258（操作表接缝）、BACKLOG §590。

## 背景

initramfs 一直未交付，但当前 `ReadOnlyFs/ReadCursor` 与 FAT 的 `Bpb/Volume` 深度绑定。
直接把它塞进现有挂载路径会同时扩成通用文件系统框架，掩盖本片要验证的 cpio 解析边界。
完整化路线已经规定 initramfs 使用 cpio newc、只读，并作为将来 init 的来源。

## 决定

1. 新增独立 `Initramfs<'a>` 只读挂载对象，借用启动镜像字节；不分配、不加锁、不增加 unsafe。
   本片不接 FAT `ReadOnlyFs`、init、NS_ROOT、syscall 或产品句柄表。
2. `mount` 完整扫描并校验 newc：110 字节头、13 个八位十六进制字段、名字含单个结尾 NUL、
   名字与数据分别按 4 字节对齐、文件边界、`TRAILER!!!` 后只允许零填充。070702/CRC、设备节点、
   硬链接语义与符号链接跟随不在本片范围；遇到不支持的类型明确拒绝。
3. `lookup` 只收绝对路径，拒空组件、`.`、`..`；归档内名字可有或没有前导 `/`。根目录是合成目录。
   `open` 只打开普通文件，目录回 `IsDir`，符号链接回 `Unsupported`；`read` 到 EOF 回 0，
   `seek` 允许等于 EOF、拒绝越过 EOF。
4. 确定性夹具由 `tools/make_initramfs.py` 生成，内核与宿主分别解析。宿主第二实现独立核对
   条目数、三份文件 FNV-1a、EOF/seek/错误格与夹具 sha256；矩阵新增一行。
5. `fault-initramfs-no-align` 跳过名字后的 4 字节对齐，必须红；损坏 magic、截断、内嵌 NUL、
   非零尾填充各有独立负样本。真机未验证；AOCI MCP 不可用，索引未更新。

## 验收

- `run-18772`：initramfs-probe **96/96 PASS**；6 条目、三份哈希、EOF、seek、错误格全真。
- `run-18774`：跳过对齐红 `mount 失败 BadMagic`，目标用例 FAIL。
- 宿主解析器对真实日志零偏差；把 `init_sha` 离线改为全零必须红。
- `check` **21/21**；相关 cfg 构建通过；矩阵新增 initramfs 行后总行数 94，最终独立进程整链
  **94/94 符合**（`build/initramfs-matrix.out.log`）。真机未验证；AOCI MCP 不可用，索引未更新。

## S1 补记（2026-11-27）

实现原样搬入 `crates/host-initramfs`，内核侧保留五个显式类型别名；搬移前后 231 行有效实现
逐字一致。宿主单测 **11/11**，专用四字节对齐变异证红；内核 `fault-initramfs-no-align` 目标用例
证红。最终 S1 合并态 `check` **21/21**、矩阵 **106/106 符合**。Miri 与真机未验证。
