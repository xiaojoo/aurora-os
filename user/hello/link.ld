/* 第一个用户程序的链接脚本（手册 §10.7）。
 *
 * 三条约束都来自内核侧的解析器（kernel/src/elf.rs），不是风格偏好：
 *   1) `e_type = ET_EXEC`：M4-2 还没有重定位器，ET_DYN 会被明确拒绝；
 *   2) 段地址必须落在**低半区**（< 2^47），自称内核地址的容器一律 NotUserRange；
 *      并且必须落在内核加载器的窗口里（`mm::USER_VA_BASE = 4 GiB` 起，本脚本正好从那里起链）——
 *      窗口之外、低半区之内的地址会被 `SegmentOutsideWindow` 拒绝；
 *   3) 每个段的 `p_vaddr` 与 `p_offset` 必须对 4 KiB 同余（MisalignedSegment），
 *      所以每一段都单独 ALIGN(4K) 起步，且不允许 W+X 同段（WxViolation）。
 *
 * .slots 放在 data 段的最前面，并且第一个 8 字节是哨兵魔数：内核用例靠魔数
 * 确认"它以为的槽位地址"就是真的槽位地址，而不是靠"我记得链接脚本是这么排的"。
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

  .text ALIGN(4K) : {
    *(.text.unlikely .text.unlikely.*)
    *(.text .text.*)
  } :text

  . = 0x100001000;
  .rodata ALIGN(4K) : {
    *(.rodata .rodata.*)
    *(.rdata)
  } :rodata

  . = 0x100002000;
  .slots ALIGN(4K) : {
    KEEP(*(.slots .slots.*))
  } :data

  .data ALIGN(4K) : {
    *(.data .data.*)
  } :data

  .bss ALIGN(4K) : {
    PROVIDE(__bss_start = .);
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
