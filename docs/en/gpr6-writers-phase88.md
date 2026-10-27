# Phase 88 — provenance of the GPR6 update request bit

**27 October 2026.** Follows [phase 87](../es/bootloader-update-trigger-phase87.md). Entirely offline; no controller, USB commands, memory, flash or OTP writes.

The signed bootloader A's startup code reads and clears SRC_GPR6 **`0x400F8038`** and enters its bootloader update coordinator when the old low-byte value has **bit 3 / `0x08`** set. The producer of that bit has not been established.

We compared (a) the exact SHA-256-pinned original signed Bruce public update (`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`), and (b) 903 *selected* previously published original bootloader-A Thumb instructions, **not** a newly retrieved private bootloader binary.

The [phase88 tool](../../tools/audit_gpr6_provenance_phase88.py) found **six** raw signed Bruce `0x400F8000` SRC block-base literals at file offsets `0x1F160`, `0x1F188`, `0x204CC`, `0x38ABC`, `0xFD454`, `0xFD4AC`. It found **zero exact `0x400F8038` literals**, which is **not** proof that the address cannot be formed indirectly.

**New original signed instruction finding** at Bruce `0x60078A1C` through `0x60078A28` (byte pin `237a012b264b0cbf052206229a63`):

```asm
0x60078A1C  LDRB  R3, [R4, #8]
0x60078A1E  CMP   R3, #1
0x60078A20  LDR   R3, [PC, #0x98]  ; signed literal at 0x60078ABC = 0x400F8000
0x60078A22  ITE   EQ
0x60078A24  MOVEQ R2, #5
0x60078A26  MOVNE R2, #6
0x60078A28  STR   R2, [R3, #0x38]  ; writes 5 or 6 to 0x400F8038 if reached
```

Both **5 and 6 have update bit 3 clear**, so this is a confirmed *non-update* GPR6 writer in the signed original. Neither runtime execution nor a host USB trigger is established.

Within the selected bootloader disassembly, only the pinned GPR6 clear at `0x6080286A` (writes zero) and app-validation status writer `0x60801F14` (writes `0x10/0x20`) are demonstrated. Those also keep bit 3 clear. **This is not a complete writer census:** a computed pointer, indirect branch, another firmware image or an unexamined code region could still set the bit.

**Decision:** GO for bounded offline computed/indirect writer provenance if new signed-code evidence is available; NO-GO for claiming USB→GPR6 bit3, live updates, firmware unlock or attempting to set/update registers on the sole device. HAB CLOSED remains unbypassed. [Sanitized evidence](../../evidence/gpr6-provenance-phase88.json) · [unit tests](../../tests/test_gpr6_provenance_phase88.py) · [PR #97](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/97).
