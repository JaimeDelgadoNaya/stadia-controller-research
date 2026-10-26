# Phase 56 — R0 origin, relocated ITCM allocation-like wrapper and +0x80 read candidates

**26 October 2026.** Read-only analysis of original signed Bruce OEM update, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Not a live installed firmware or RAM readback.

## Verified producer of constructor R0

Eight original signed Thumb instructions between `0x60079D74` and `0x60079D84` establish:

```asm
0x60079D74 MOVS R0,#0xA4
0x60079D76 BL 0x6013D378
0x60079D7A MOV R3,R5
0x60079D7C LDR R2,[PC,#0x54] ; owner literal = 0x2000A2A8
0x60079D7E MOV R4,R0
0x60079D80 LDR R1,[PC,#0x54]
0x60079D82 STR R6,[SP]
0x60079D84 BL 0x6007EB8C
```

Thus the R0 base passed to the signed holder constructor comes from the **return of `0x6013D378`, called with 164 decimal**. No numeric live R0 value has been recovered. Phase 55 separately pinned the storage of R2 (owner) into `[R4+0x80]` where R4 comes from constructor R0.

## Follow the real signed ITCM trampoline

`0x6013D378` is a `LDR.W PC,[PC,#-0x0]` veneer. Its adjacent aligned literal **`0x0000B533`** resolves to Thumb runtime **`0xB532`**. This is in ITCM *relocated from the signed boot image*, not a pointer outside the known application: bytes at source file offset **`0xBD4E = 0x81C + 0xB532`** must be decoded at **runtime ITCM PC 0xB532**.

The signed chain is:

```text
0x60079D76 BL 0x6013D378  (R0=0xA4)
     → Thumb veneer 0x0000B533
     → ITCM 0xB532: wrapper
     → BL 0x8832
     → B.W 0x7F58: memory management routine
     → dynamic R0 return (physical value UNMEASURED)
     → 0x6007EB8C holds owner via R2/R8 at [R4+0x80]
```

Fifteen signed ITCM wrapper/forwarder instructions were pinned: zero input becomes one; nonzero R0 from helper exits; zero invokes fallback/retry. The inner `0x7F58` routine manipulates aligned sizes and memory management structures, supporting an **allocation-like interpretation**. No runtime allocation or complete allocator semantics has been demonstrated.

## Enumerating possible +0x80 readers

A bounded linear XIP scan yielded **32 candidate reads**: **29 LDR and 3 LDRB**. Relevant possible local readers include `0x6007E9A4 LDR.W R0,[R4,#0x80]`, `0x6007E810 LDR.W R0,[R4,#0x80]` and `0x6007E7EA LDR.W R0,[R0,#0x80]`.

They are **not known to read the same R0-based object**. Offset coincidence and geographic code proximity are not object-identity or CFG proofs; the linear decode may also encounter non-code data.

The object appears to be obtained dynamically, explaining why a static absolute base has not been recovered. However, **class10 activation and the writer of `owner+4/+8/+12` are still unresolved**. Host-controlled callbacks, unsigned firmware execution, HAB CLOSED bypass and native Xbox/Switch2 support remain **not demonstrated**.

**Next step (phase 57):** track the *incoming object base* of local consumer `0x6007E9A4` and nearby signed routines to verify whether they read the very same dynamically produced object. If provenance remains unresolved, strictly read-only passive USB enumeration may provide indirect evidence, not a RAM capture.

## Reproduce

```bash
python -m unittest tests.test_bruce_parent_r0_phase56 -v
python -m tools.audit_bruce_parent_r0_phase56 local/bruce_pvt_a_prod_signed.bin --out local/phase56-r0.json
```

**673 offline tests** on Python 3.11 and 3.12 passed. [Original OEM audit CI](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40351166570) · [Structured evidence](../../evidence/bruce-parent-r0-phase56.json).

No USB request, RAM dump, flash write or eFuse changes.
