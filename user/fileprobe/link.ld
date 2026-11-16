/* FS-03 切片 D：ring3 文件探针的链接脚本（ADR-108 决策 8）。
 * 三条硬约束与前三个产物同源，都来自内核侧解析器 kernel/src/elf.rs：
 *   1) ET_EXEC（还没有重定位器，ET_DYN 明确拒绝）；
 *   2) 段地址落在加载器的固定镜像窗口 [mm::USER_VA_BASE, mm::USER_MMAP_BASE) 里；
 *   3) 每段 p_vaddr 与 p_offset 对 4 KiB 同余，且不允许 W+X 同段。
 *
 * **基址与三个既有产物全部错开**：hello 与 shell 在 0x100000000、probe 在 0x100080000，
 * 这里从 0x1000c0000 起。窗口只有 1 MiB（到 0x100100000），probe 用到 0x100083000，
 * 所以 0x1000c0000 这一段既不与任何镜像重叠，也不吃掉动态分配区的起点。
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
  . = 0x1000c0000;

  .text ALIGN(4K) : {
    *(.text.unlikely .text.unlikely.*)
    *(.text .text.*)
  } :text

  . = 0x1000c1000;
  .rodata ALIGN(4K) : {
    *(.rodata .rodata.*)
    *(.rdata)
  } :rodata

  . = 0x1000c2000;
  .slots ALIGN(4K) : {
    KEEP(*(.slots .slots.*))
  } :data

  .data ALIGN(4K) : {
    *(.data .data.*)
  } :data

  /DISCARD/ : {
    *(.comment)
    *(.eh_frame .eh_frame.*)
    *(.note .note.*)
    *(.gcc_except_table)
  }
}
