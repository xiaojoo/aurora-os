/* 第二个用户程序的链接脚本（W3 P5a，ADR-075）。约束与 user/hello/link.ld 同源，
 * 都来自内核侧解析器 kernel/src/elf.rs，不是风格偏好：
 *   1) e_type = ET_EXEC（还没有重定位器，ET_DYN 明确拒绝）；
 *   2) 段地址落在低半区且落在加载器窗口 [USER_VA_BASE, USER_MMAP_BASE) 里；
 *   3) 每段 p_vaddr 与 p_offset 对 4 KiB 同余，且不允许 W+X 同段。
 *
 * **基址与 hello 错开**：hello 从 0x100000000 起，这里从 0x100080000 起。
 * 窗口是 [0x100000000, 0x100100000)（mm.rs 的 USER_VA_BASE / USER_MMAP_BASE），
 * 所以两份容器可以同时在世而不撞保留表——"两个产物共存"这件事本身是 P5a 的判据之一。
 *
 * .slots 放在 data 段最前面、第一个 8 字节是哨兵魔数：内核用例靠魔数确认槽基址，
 * 不靠"我记得链接脚本怎么排的"（与 hello 同一条纪律）。
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
  . = 0x100080000;

  .text ALIGN(4K) : {
    *(.text.unlikely .text.unlikely.*)
    *(.text .text.*)
  } :text

  . = 0x100081000;
  .rodata ALIGN(4K) : {
    *(.rodata .rodata.*)
    *(.rdata)
  } :rodata

  . = 0x100082000;
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
