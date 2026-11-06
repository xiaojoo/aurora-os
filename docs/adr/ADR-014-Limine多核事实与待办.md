# ADR-014: Limine 多核（MP）请求的事实与剩余待办

状态：**已核实**（2026-11-04，M2-c 实测；原文来自固定的 11.4.1 `include/limine.h`）
关联：手册 V1.2 §13.1 R20、ADR-017、**ADR-019**（本请求的直接后果）、里程碑 M3b

## 实测结果（不再是"读原文得到的结论"）

M2-c 真的把 `LIMINE_MP_REQUEST` 加进了 `.requests` 段，`flags = 0`（不请求 x2APIC）。本机
`-smp 4 -m 512M` 的启动日志：

```
limine: mp present cpus=4 bsp_lapic=0 x2apic=false all_goto_null=true ids=[0, 1, 2, 3]
mp vs madt: mp_cpus=4 madt_enabled=4 overlap=4 bsp_in_madt=true all_goto_null=true x2apic=false processor_id[0]=0
```

| 待核实项 | 现在的依据 |
| --- | --- |
| 11.4.1 的结构体布局是否与 trunk 一致 | **按本机固定的 `limine.h` 逐字段写完并跑通**：`{revision, flags(u32), bsp_lapic_id(u32), cpu_count(u64), cpus}`，`mp_info = {processor_id, lapic_id, reserved, goto_address, extra_argument}`。偏移错了不会"少几个 CPU"，而是读到垃圾并让 `subset` 断言红 |
| `cpu_count` 是否含 BSP | 含：报 4，`-smp 4` 相符 |
| `goto_address` 首次为 NULL | 实测 `all_goto_null=true`（4 条全空）。这条不是装饰——**释放 AP 就是一次原子发布，前提就是这字段初始为空** |
| LAPIC id 与 MADT 的关系 | 两台独立仪器互相印证：MP 的 `lapic_ids=[0,1,2,3]` 全部落在 MADT 的使能清单里，`bsp_lapic_id=0` 也在其中，`processor_id[0]=0` 与 MADT 的 ACPI UID 对应 |
| 是否请求 x2APIC | 本切片填 0，响应 bit0=false（未启用）。**后果已记录**：协议说固件已开而请求未置位时 bootloader 会尝试关掉，关不掉就拒绝引导——真机上这条必须重测（见下方剩余待办） |
| trampoline 归谁 | **bootloader 自备**：内核镜像里没有任何 16 位代码，AP 仍能被停住 |

## 本请求的直接代价（必须一起看）

发出 MP 请求 = bootloader 真的引导并**停在** bootloader-reclaimable 内存里等我们。
M2-a 那种"reclaimable 一起当空闲"的做法因此立刻变成三重故障（`qemu_rc=0`）。
处理见 **ADR-019**：默认不回收，改成显式 `reclaim_bootloader_regions()`，实测扣着 45 MiB。

## 仍需在 M3b 前确认的事

1. AP 的**内核栈**由谁给：协议说 AP 进入时栈跟随 Stack Size 请求（即 bootloader 给的栈，
   位于 reclaimable 区），与 §5.2 的"每 CPU 独立栈 + guard page"必须在同一张表里定；
   一旦切到自己的栈，`reclaim_bootloader_regions()` 才有调用条件。
2. x2APIC 的真机策略：请求位要不要置 1；置 1 之后 AP 入口的 APIC 访问要改 MSR 而不是 MMIO，
   这条会影响 MADT 的 `lapic_base` 是否还用得上。
3. "AP 起不来算不算过"仍然是本项目自己的决策（协议只给核数与入口，不给失败语义）。
4. 多核之后本文件用到的所有静态量（`mm::State`、`Heap`、`resource::Ledger`、P3 表）
   都是单核假设，M3a 之前必须逐个加锁或搬进 per-CPU 结构。

