/* Hypothetical conservative 128KiB OCRAM window: must validate FlexRAM before hardware execution. */
MEMORY { OCRAM (rwx) : ORIGIN = 0x20200000, LENGTH = 128K }
__StackTop = ORIGIN(OCRAM) + LENGTH(OCRAM) - 16;
ENTRY(Reset_Handler)
SECTIONS {
 .vectors : ALIGN(256) { KEEP(*(.vectors)) } > OCRAM
 .text : ALIGN(4) { *(.text .text.*) *(.rodata .rodata.*) } > OCRAM
 .data : ALIGN(4) { *(.data .data.*) } > OCRAM
 .usb_dma (NOLOAD) : ALIGN(64) {
  __usb_dma_begin = .;
  KEEP(*(.usb_dma .usb_dma.*))
  . = ALIGN(64);
  __usb_dma_end = .;
 } > OCRAM
 .bss (NOLOAD) : ALIGN(4) { *(.bss .bss.* COMMON) } > OCRAM
 __image_end = .;
}
ASSERT(__image_end < __StackTop - 4096,"RAM image intrudes into stack reserve")
ASSERT((__usb_dma_begin % 64)==0,"Unaligned DMA staging area")
