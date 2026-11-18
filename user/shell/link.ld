/* S5c：串口 shell 的链接脚本。约束与 user/hello/link.ld 逐条相同（都来自 kernel/src/elf.rs）：
 *   1) ET_EXEC（没有重定位器，ET_DYN 会被拒）；
 *   2) 段地址落在低半区且在内核加载器窗口里（mm::USER_VA_BASE = 4 GiB 起）；
 *   3) 每段 p_vaddr 与 p_offset 对 4 KiB 同余，且不允许 W+X 同段。
 * 与 hello 的差别：①**没有 .slots 哨兵段**——shell 的结果走控制台，不走内存信箱，
 * 所以不需要"内核按固定偏移读回"那套契约；②**.text 留 20 KiB**（hello 只留 4 KiB）——
 * shell 的代码比 hello 大：第一版按 4 KiB 排直接撞 `section .text virtual address range
 * overlaps with .rodata`（S5c 实测）；ADR-133 的 `top`（排序 + 帧打印 + sleep）再涨
 * ~2.5 KiB，提到 20 KiB。ADR-136/137 的 lspci/uptime 再涨 ~2 KiB，
 * 20 KiB 又不够（本轮实测：dispatch 的 32S 重定位 out of range），提到 24 KiB。
 * ADR-143 的 ping（点分十进制解析 + 两次收发循环）再涨 ~2 KiB，24 KiB 又不够
 * （本轮实测：.text 结束 0x100006xxx > .rodata 起点），提到 32 KiB。
 * 段仍各自 ALIGN(4K)，窗口约束不变。
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

  . = 0x10000C000;
  .rodata ALIGN(4K) : {
    *(.rodata .rodata.*)
    *(.rdata)
  } :rodata

  . = 0x10000D000;
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