/* Aurora OS 内核链接脚本（手册 §3.3）
 *
 * 三条来自 Limine 协议的硬约束，不是本项目自选：
 *   1) 可执行段必须在 higher half，且 >= 0xffffffff80000000（协议 Machine State / 非重定位内核要求）
 *   2) .requests 段必须被 start/end marker 包住；base revision >= 2 时 marker 是**强制**的，
 *      不再是可选提示
 *   3) 段权限按 W^X 分派：text = R+X，rodata+requests+ktests = R，data/bss = R+W
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(kmain)

PHDRS {
  text   PT_LOAD FLAGS(5);   /* R+X */
  rodata PT_LOAD FLAGS(4);   /* R   */
  data   PT_LOAD FLAGS(6);   /* R+W */
}

SECTIONS {
  . = 0xffffffff80000000;

  .text ALIGN(4K) : {
    PROVIDE(__text_start = .);
    *(.text.boot .text.boot.*)
    *(.text.unlikely .text.unlikely.*)
    *(.text .text.*)
    PROVIDE(__text_end = .);
  } :text

  . = ALIGN(4K);
  .rodata ALIGN(4K) : {
    PROVIDE(__rodata_start = .);
    *(.rodata .rodata.*)
    *(.data.rel.ro .data.rel.ro.*)

    /* Limine 请求区：marker 必须紧邻包住 .requests，顺序不可交换 */
    KEEP(*(.requests_start_marker))
    KEEP(*(.requests))
    KEEP(*(.requests_end_marker))

    /* 内核测试表（§12.2 的段注册方案）：运行器遍历两个符号之间的条目 */
    . = ALIGN(8);
    PROVIDE(__ktests_start = .);
    KEEP(*(.ktests .ktests.*))
    PROVIDE(__ktests_end = .);
    PROVIDE(__rodata_end = .);
  } :rodata

  . = ALIGN(4K);
  .data ALIGN(4K) : {
    PROVIDE(__data_start = .);
    *(.data .data.*)
    *(.got .got.*)
    PROVIDE(__data_end = .);
  } :data

  . = ALIGN(4K);
  .bss ALIGN(4K) : {
    PROVIDE(__bss_start = .);
    *(.bss .bss.*)
    *(COMMON)
    PROVIDE(__bss_end = .);
  } :data

  /* 调试栈回溯走 force-frame-pointers（§3.2），不依赖 .eh_frame 运行时展开表 */
  /DISCARD/ : {
    *(.eh_frame .eh_frame.*)
    *(.comment)
    *(.note .note.*)
    *(.debug_line .debug_line.* .debug_line_end)
    *(.debug_frame)
  }
}

ASSERT(__ktests_end >= __ktests_start, "ktest 段符号顺序错误")
