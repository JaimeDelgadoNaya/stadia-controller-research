/* Offline teaching image. Address/window is illustrative, not validated on Stadia. */
.syntax unified
.cpu cortex-m7
.thumb

.section .isr_vector, "a", %progbits
.global __vectors
__vectors:
    .word __stack_top
    .word Reset_Handler /* ARM Thumb symbol already carries its low bit! */

.section .text.Reset_Handler, "ax", %progbits
.global Reset_Handler
.type Reset_Handler, %function
.thumb_func
Reset_Handler:
    movs r0, #0x5a
    ldr r1, =proof_marker
    str r0, [r1]
loop:
    b loop
.size Reset_Handler, . - Reset_Handler

.section .bss.proof_marker, "aw", %nobits
.balign 4
.global proof_marker
proof_marker:
    .space 4
