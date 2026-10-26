# Bruce signed class table cross-reference audit — phase #36

**2026-10-26 · entirely offline.** Original signed OEM Bruce **update** image, 1,050,984 bytes, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. This is not a physical dump of the installed device.

[Phase #35](bruce-class-control-setup-provenance.md) verified that `0x600D0E58` conditionally forwards an interface-directed USB SETUP `bRequest` argument into a class-object callback. A signed function pointer `0x600D0E59` is stored as **data** at `0x60104BAC`. Crucially, no live EP0 registration was established.

This phase checked whether code statically references the neighboring flash range `0x60104B80..0x60104BDF` via PC-relative Thumb literal loads or local MOVW/MOVT address construction. **One** PC-relative literal load was found; **zero** local MOVW/MOVT pairs constructing an address in this range were detected.

## Verified new original-code finding

```asm
0x6005679A  LDR    R5,[PC,#0x5C]     ; literal at 0x600567F8 = 0x60104BDC
0x600567A2  ADD.W  R2,R5,R3,LSL #3   ; eight-byte entry stride
0x600567A6  LDR    R2,[R2,#4]        ; load function pointer at entry+4
0x600567AA  LDRB.W R3,[R5,R3,LSL #3]
0x600567B6  BLX    R2                ; conditional indirect call
```

The **literal, five signed instructions and eight-byte indexing** are verified by hash-pinned regression checks. The `0x60104BDC` reference is to a **different indexed table base**, not to `0x60104BA4` or the original class SETUP forwarder `0x600D0E58`. Its presence must **not** be counted as proof of the desired EP0 class-handler installation.

The adjacent data words near `0x60104B88..0x60104BB7` have a recurring four-word appearance, including numeric entries `2`, `4`, `10`, but type boundaries and runtime usage are **unproven**. In particular, calling `0x60104BA4` an established table **start** would be overprecise; its word is confirmed to be `0x60055321`, while `0x60104BAC` holds `0x600D0E59`. Phase #35 had also resolved a distinct initializer literal at `0x60104BC4`.

## Scope and next gate

The XIP Thumb scan is linear, not whole-program CFG or dynamic object reconstruction. It can miss calculated addresses, ADR, RAM relocation, indirect init and object pointer aliasing, and may decode literal pools as executable code. **No** live EP0 callback pointer, receiver of USB class requests `0x81/0x83/0x84`, controlled code execution, HAB CLOSED bypass, safe rollback or direct Xbox/Switch 2 firmware has been demonstrated.

Next investigate runtime-object **initialization provenance** for the class SETUP dispatcher and the function pointer loaded from object `[R0,#4]`; treat it as a separate problem from an eight-byte table for another subsystem. No hardware operations.

```sh
python -m unittest tests.test_bruce_class_table_xrefs -v
python -m tools.audit_bruce_class_table_xrefs local/bruce_pvt_a_prod_signed.bin
```

The CI workflow uses an ephemeral, SHA-verified public OEM copy, deletes it afterward and neither sends USB packets nor changes the controller.
