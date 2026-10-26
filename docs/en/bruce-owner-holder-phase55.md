# Phase 55 — Signed producer-first analysis: owner pointer stored in a different parent object

**26 October 2026 — SHA-256-pinned original signed Bruce OEM update**, `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Offline code-only audit.

## New finding: owner-pointer delegation to a separate holder

The OEM code loads `owner=0x2000A2A8` into **R2**, calls `0x6007EB8C`, copies R2 into **callee-saved R8**, and stores R8 through a **different** object base taken from **R0**:

```asm
0x60079D7C LDR R2,[PC,#0x54]      ; literal at 0x60079DD4 = owner
0x60079D84 BL 0x6007EB8C

0x6007EB96 MOV R4,R0              ; parent object base UNKNOWN
0x6007EB9E MOV R8,R2              ; owner address
...
0x6007EBAC BL 0x601017FC         ; R4/R8 are callee-saved
...
0x6007EBB4 STR.W R8,[R4,#0x80]   ; [parent + 0x80] = owner (conditional)
```

**19 original signed instruction anchors verified on the exact OEM update**, including PC-relative owner literal. R0 is not automatically owner: this **is not** a store to `owner+4/+8/+12` and does not reveal the parent object's absolute address or show that the instructions executed on physical hardware.

The producer-first hypothesis is that an unidentified parent may hold owner through its `+0x80` field. Its consumers and relationship to the active USB configuration are **not established**.

## Signed initialized class group (separate evidence chain)

Two original signed getters at `0x600610FC` and `0x60061104` load the same literal pointer **`0x200030E8`**.

The signed image also contains two contiguous 12-byte records initialized by startup:

| Boot RAM address | Signed Thumb callback | Descriptor pointer | Descriptor class selector byte +4 |
|---|---|---|---|
| `0x200030E8` | `0x60061249` | `0x200030A0` | **2** |
| `0x200030F4` | `0x600613FD` | `0x20003100` | **10** |

These entries confirm code/data provenance, **not runtime class10 selection**. The pointer value in `[owner+4]=[0x2000A2AC]`, the method in `[owner+8]=[0x2000A2B0]` and class count at `owner+12` remain **unmeasured**. No link between the getters and the active owner configuration is proved.

## Next target

Phase 56: identify the origin of **R0 at call site 0x60079D84** (parent object), then find consumers of **parent+0x80** and see whether they produce owner configuration fields. Distinguish code may-paths from physical execution, and use only passive/read-only USB enumeration if actual runtime evidence is needed.

This phase has not proved host-controlled callbacks, arbitrary code execution, a HAB CLOSED bypass, nor native Xbox/Switch 2 interoperability.

## Reproduce

```bash
python -m unittest tests.test_bruce_owner_holder_phase55 -v
python -m tools.audit_bruce_owner_holder_phase55 local/bruce_pvt_a_prod_signed.bin --out local/phase55-owner-holder.json
```

[Original signed audit CI](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40347175043) · [Structured evidence](../../evidence/bruce-owner-holder-phase55.json).

No physical USB requests, installed flash/RAM readback, flash write or eFuse changes.
