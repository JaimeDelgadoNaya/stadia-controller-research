; Análisis estático: restricted_ivt_flashloader.bin
; GetProperty: r0 = property tag, se resta 1 antes del TBB.
; Tabla 0x20009a90: entrada 0x11 -> 0x20009af0
; Función 0x2000a87c: lectura de OCOTP_CFG5; extracción del bit 1.

20009a78: f8b5         push       {r3, r4, r5, r6, r7, lr}
20009a7a: 1e46         mov        r6, r3
20009a7c: 2a4b         ldr        r3, [pc, #0xa8]
20009a7e: 1546         mov        r5, r2
20009a80: 0138         subs       r0, #1
20009a82: da68         ldr        r2, [r3, #0xc]
20009a84: 0f46         mov        r7, r1
20009a86: 1169         ldr        r1, [r2, #0x10]
20009a88: 1828         cmp        r0, #0x18
20009a8a: 47d8         bhi        #0x20009b1c
20009a8c: dfe800f0     tbb        [pc, r0]

20009af0: 00f0c4fe     bl         #0x2000a87c
20009af4: 0030         adds       r0, #0
20009af6: 0d49         ldr        r1, [pc, #0x34]
20009af8: 18bf         it         ne
20009afa: 0120         movne      r0, #1
20009afc: f3e7         b          #0x20009ae6

2000a87c: 034b         ldr        r3, [pc, #0xc]
2000a87e: 1b68         ldr        r3, [r3]
2000a880: 034b         ldr        r3, [pc, #0xc]
2000a882: 1868         ldr        r0, [r3]
2000a884: c0f34000     ubfx       r0, r0, #1, #1
2000a888: 7047         bx         lr

; Literal 0x2000a88c = 0x401f4000
; Literal 0x2000a890 = 0x401f4460
; No se ha ejecutado este cargador en el mando.