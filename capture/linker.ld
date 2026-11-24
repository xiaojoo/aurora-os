OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(capture_entry)

PHDRS {
  text   PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data   PT_LOAD FLAGS(6);
}

SECTIONS {
  . = 0xffffffffc0000000;

  .text ALIGN(4K) : {
    PROVIDE(__capture_text_start = .);
    *(.text.boot .text.boot.*)
    *(.text .text.*)
    PROVIDE(__capture_text_end = .);
  } :text

  . = ALIGN(4K);
  .rodata ALIGN(4K) : {
    *(.rodata .rodata.*)
    *(.data.rel.ro .data.rel.ro.*)
  } :rodata

  . = ALIGN(4K);
  .data ALIGN(4K) : {
    *(.data .data.*)
    *(.got .got.*)
  } :data

  . = ALIGN(4K);
  .bss ALIGN(4K) : {
    PROVIDE(__capture_bss_start = .);
    *(.bss .bss.*)
    *(COMMON)
    PROVIDE(__capture_bss_end = .);
  } :data

  .capture_stack (NOLOAD) : {
    . = 0xffffffffc0800000 - 0x40000 - 16;
    capture_stack_top = 0xffffffffc0800000 - 0x40000 - 16;
  } :data

  /DISCARD/ : {
    *(.eh_frame .eh_frame.*)
    *(.comment)
    *(.note .note.*)
  }
}

ASSERT(__capture_text_end <= 0xffffffffc0010000, "capture text exceeds its executable window")
ASSERT(__capture_bss_end <= 0xffffffffc07b0000, "capture image overlaps its stack or AHCI DMA area")
ASSERT(capture_stack_top == 0xffffffffc0800000 - 0x40000 - 16, "capture stack top moved")
