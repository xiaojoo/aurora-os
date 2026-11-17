/* A2 切片：ring3 外部命令探针的链接脚本（ADR-108 决策 8）。
 * 三条硬约束与前三个产物同源，都来自内核侧解析器 kernel/src/elf.rs：
 *   1) ET_EXEC（还没有重定位器，ET_DYN 明确拒绝）；
 *   2) 段地址落在加载器的固定镜像窗口 [mm::USER_VA_BASE, mm::USER_MMAP_BASE) 里；
 *   3) 每段 p_vaddr 与 p_offset 对 4 KiB 同余，且不允许 W+X 同段。
 *
 * **基址与三个既有产物全部错开**：hello 与 shell 在 0x100000000、probe 在 0x100080000，
 * A3 后 execprobe 带 code-model=large（约 750 KiB），基址取**窗口起点** 0x100000000：
 * 与 hello 同址不冲突（同一时刻只装一个进程，14 号映射在各自子 AS）；窗口 1 MiB 装得下。
 * 所以 0x1000e0000 这一段既不与任何镜像重叠，也不吃掉动态分配区的起点。
 *
 * .slots 放在 data 段最前面、第一个 8 字节是哨兵魔数：内核用例按它确认槽基址，
 * 不靠"我记得链接脚本怎么排的"（与 probe 同一条纪律）。
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS {
  text   PT_LOAD FLAGS(5);   /* R+X */
  rodata PT_LOAD FLAGS(4);   /* R   */
  data   PT_LOAD FLAGS(6);   /* R+W */
}

SECTIONS {
  . = 0x100000000;

  /* 段间用 ALIGN(4K) 自动推进，**不写死段地址**：A3 后 execprobe 带上了 runtime 的
   * elf 装载器，.text 超过 4 KiB，写死 0x1000e1000 会让 .rodata 与 .text 重叠
   * （2026-11-17 实测：rust-lld 报 "text virtual address range overlaps with .rodata"）。
   * 镜像窗口的硬约束仍是 p_vaddr 与 p_offset 4K 同余、W+X 不同段——ALIGN 满足前者。 */
  .text ALIGN(4K) : {
    *(.text.unlikely .text.unlikely.*)
    *(.text .text.*)
  } :text

  .rodata ALIGN(4K) : {
    *(.rodata .rodata.*)
    *(.rdata)
  } :rodata

  .slots ALIGN(4K) : {
    KEEP(*(.slots .slots.*))
  } :data

  .data ALIGN(4K) : {
    *(.data .data.*)
  } :data

  /* **.bss 必须显式收进来**：它是 ALLOC 但不占文件，若留成 orphan section 就
   * 不进任何 PT_LOAD ⇒ 运行时该地址未映射 ⇒ 用户缓冲被内核判 E_FAULT
   * （2026-11-17 实测：execprobe 的 CHUNK(.bss) 在 file_read 上吃到 -2）。 */
  .bss ALIGN(4K) : {
    *(.bss .bss.*)
    *(COMMON)
  } :data

  /DISCARD/ : {
    *(.comment)
    *(.eh_frame .eh_frame.*)
    *(.note .note.*)
    *(.gcc_except_table)
  }
}
