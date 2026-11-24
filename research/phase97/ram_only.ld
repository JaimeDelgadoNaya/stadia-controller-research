/* THIS IS AN ILLUSTRATIVE ADDRESS WINDOW, NOT A STADIA DEPLOYMENT MAP.
 * No image derived from this linker script should be loaded on real hardware
 * without independent, exact device-memory and ROM-state verification.
 */
ENTRY(Reset_Handler)
MEMORY { ram (rwx) : ORIGIN = 0x20000000, LENGTH = 64K }
__stack_top = ORIGIN(ram) + LENGTH(ram);
SECTIONS {
  .isr_vector : { KEEP(*(.isr_vector)) } > ram
  .text : { *(.text*) *(.rodata*) } > ram
  .bss (NOLOAD) : { *(.bss*) *(COMMON) } > ram
  /DISCARD/ : { *(.comment*) *(.note*) *(.ARM.attributes*) }
}
ASSERT(SIZEOF(.isr_vector) == 8, "Unexpected vector count")
