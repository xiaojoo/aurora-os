/* D4（ADR-154）：应用 SDK 样板的链接脚本。
 * 三条硬约束与其它产物同源，都来自内核侧解析器 kernel/src/elf.rs：
 *   1) ET_EXEC（还没有重定位器，ET_DYN 明确拒绝）；
 *   2) 段地址落在加载器的固定镜像窗口里；
 *   3) 每段 p_vaddr 与 p_offset 对 4 KiB 同余，且不允许 W+X 同段。
 *
 * 段间用 ALIGN(4K) 自动推进、**不写死段地址**：写死会让 .rodata 与 .text 重叠
 * （ADR-108 决策 8 踩过）。.bss 必须显式收进来——留成 orphan section 就不进
 * 任何 PT_LOAD，运行时未映射（execprobe 踩过，吃到 -2）。
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

  .rodata ALIGN(4K) : {
    *(.rodata .rodata.*)
    *(.rdata)
  } :rodata

  /* `.slots` 必须显式收进来并**放在 .data 的最前面**：内核用例按 `data_va`
   * 找它（`user::load` 报的 data 段首地址）。留成 orphan 或被 .data 挤到后面
   * 都会让 `data_va` 指不到魔数（实测 sdkdemo 首版 `data_va=0x0`）。 */
  .data ALIGN(4K) : {
    KEEP(*(.slots .slots.*))
    *(.data .data.*)
  } :data

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
