/* RAM-only diagnostic for ARMv7E-M; NO ROM, flash, USB, OTP or GPIO IO. */
.syntax unified
.cpu cortex-m7
.thumb
.section .vectors,"a",%progbits
.balign 256
.global __vector_table
__vector_table:
.word __StackTop
.word Reset_Handler + 1
.rept 14
.word Default_Handler + 1
.endr
.section .text.Default_Handler,"ax",%progbits
.thumb_func
.global Default_Handler
Default_Handler:
 b Default_Handler
