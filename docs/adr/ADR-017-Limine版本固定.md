# ADR-017: Limine 固定在 v11.4.1-binary，而不是最新 12.9.6

状态：已采纳为**临时固定**，需在 M2 前复审
关联：手册 §2.4 ADR-003、§4.1、§4.3、§13.1、A.5、B.3 的 V2

## 背景

本机 `git ls-remote`/`git clone` 到 github.com 可用，但 release 资产所在的
`objects.githubusercontent.com` **连接被重置**（实测 curl 失败；HEAD github.com 返回 000）。
Limine 官方预编译产物只通过 release 资产分发（`limine-binary.zip`）。

## 可用的替代路径

Limine 仓库另有把预编译产物直接提交进版本库的 `-binary` 标签。实测：

* `-binary` 标签最新到 **v11.4.1-binary**（12.x 没有对应标签）。
* 该标签内含 `BOOTX64.EFI` **以及 Windows 宿主工具 `limine.exe`**，因此不需要 Linux 侧
  的 `limine` ELF 工具，也不需要 clang/make 自建。

## 决策

固定 `v11.4.1-binary`，理由记入 `tools/versions.toml`。同时把内核侧改为
**请求 base revision 5 并在启动日志里打印实际协商值**：协议 rev≥3 要求 bootloader
把 base revision tag 的第 2 分量改写为实际使用的版本，所以"11.4.1 到底实现了哪一版
交接保证"这件事**由内核自己报**，不靠我猜。

这条设计顺带把 V1.2 的 R20（SMP 待核实清单）里的"revision 协商"一项从"未核实"
变成"运行期可见"。

## 已知风险与待办

1. **11.4.1 早于 12.9.6**：rev5 新增的交接保证（IOMMU 显式关闭、LAPIC 初始化到已知状态、
   RFLAGS=0x2、无 TSS/LDT/IDTR）是否在 11.4.1 全部落实，未核实；启动日志会给出协商值，
   但协商值≠每一条都实现了。M2 前要用 12.9.6 复跑同一组用例。
2. **取得 12.9.6 的途径**：换网络出口取 release 资产，或取得 clang+make 后从源码自建
   （ADR-009a 需先判定其 BSD-2-Clause 许可证允许）。
3. `limine.exe` 在 11.4.1 只有 `bios-install`/`enroll-config` 命令，**没有 UEFI install**
   ——UEFI 侧就是"把 BOOTX64.EFI 放到 ESP 的 `EFI/BOOT/` 下"，本项目由自研镜像工具完成。
   `enroll-config`（把配置嵌进 EFI，走 SMBIOS 传递）是备用路径，用于将来 LFN 或
   FAT 查找出问题时绕开文件系统依赖。
4. 配置文件名 `limine.conf` 的扩展名 4 字符，**塞不进 8.3**（FAT 扩展名字段 3 字节）。
   自研镜像同时写 LFN 条目与短名 `LIMINE CON`；Limine 的 FAT 驱动是否支持 LFN **未核实**，
   所以真机或 QEMU 上若出现"找不到配置"，先按第 3 条走 `enroll-config`。

## 回退

若 11.4.1 的 rev5 交接保证不足以支撑 §8.4 IOMMU 或 SMP 假设：改用自写 UEFI loader
（需自己实现 PE/COFF 加载与内存映射），或在 M2 前换成 12.9.6 并同步更新
`tools/versions.toml` 与 `boot/limine.conf`。
