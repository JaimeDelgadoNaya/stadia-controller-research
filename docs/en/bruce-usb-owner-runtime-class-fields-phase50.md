# Phase 50 — Signed USB owner object, mode-2 branch and class record provenance

**26 October 2026 · PR #52 · Original signed Bruce OEM UPDATE, exact SHA-256; not a device RAM or installed flash dump.**

## What was verified

A signed conditional transition uses RAM owner object **\`0x2000A2A8\`**. Original \`0x60071416: LDR R0,[PC,#0x20]\` loads a word from \`0x60071438\` equal to \`0x2000A2A8\`, then \`0x6007141C: B.W 0x60060FE8\` enters the mode-transition handler.

If the argument saved in R4 equals 1, signed \`0x60071428–2E\` selects mode **R1=2**; other branches select 1 or 3. In the handler, \`0x60061020: CMP R5,#2\` and \`0x6006102A: BNE\` guard \`0x6006102E: BL 0x60060F84\`, the USB config constructor previously traced in phase 49. **None of these conditional instructions proves that a real controller chose mode 2 or executed this constructor.**

The constructed USB configuration begins at **\`owner+4\`**. In this specific static path, the corresponding addresses are:

| Owner field | RAM field address | Runtime config interpretation |
|---|---|---|
| \`owner+4\` | \`0x2000A2AC\` | \`config+0\`: runtime class-record array pointer |
| \`owner+8\` | \`0x2000A2B0\` | \`config+4\`: dynamic method pointer |
| \`owner+12\` | \`0x2000A2B4\` | \`config+8\`: record-count byte |
| \`owner+0x10\` | \`0x2000A2B8\` | initialization mode byte |
| \`owner+0x98\` | \`0x2000A340\` | USB-engine pointer output |

The addresses follow from signed register/offset semantics. **The actual memory values have not been measured.**

## Signed XIP owner pointer census

In the first \`0xFF000\` bytes of authenticated signed application space the offline tool counted **16 aligned 32-bit words** equal to owner base \`0x2000A2A8\`:

\`\`\`text
0x60041E98  0x6005AC14  0x6005ACC8  0x6005ACD4
0x6005ACEC  0x6005BC1C  0x600610F8  0x60064940
0x60065450  0x60071438  0x60074B00  0x60074E68
0x600755B8  0x600761CC  0x60079DD4  0x6007F714
\`\`\`

There are **no directly aligned 32-bit literal words** in that region equal to the derived field addresses \`0x2000A2AC\`, \`0x2000A2B0\` and \`0x2000A2B4\`. This **does not** imply there are no writers: code typically loads the owner base and accesses fields by \`STR [register,#offset]\`. The xref auditor emits candidate nearby linear Thumb decoding for inspection; bytes from literal pools may be *mis-disassembled* and should not be treated as reachable instructions without CFG/dataflow proof.

Owner base \`0x2000A2A8\` lies outside the signed startup-initialized data copy window **\`0x20002740–0x20003FD8\`**, so reading data directly from that file cannot reconstruct owner field contents. There may be other signed startup or runtime initialization paths.

## What this achieves and what it does not

We have a grounded **owner address and conditional mode-to-constructor path**, beyond phase49's unknown-R0 owner argument. But a signed class10 record at \`0x200030F4\` and a conditional class10 event distributor do not establish that **\`[0x2000A2AC]\` points to an active class-record array containing class selector 10**.

The actual class record list, count, dynamic method, physical EP0 event delivery and class10 secondary callback remain **unmeasured/unverified**. No host-supplied executable address, unsigned code execution, HAB CLOSED bypass, native Xbox or Switch 2 support has been proven. Nothing was sent to the physical controller, flashed or written to eFuses.

## Recommended phase 51

Trace **actual base-register-relative stores** to \`owner+4/+8/+12\` and their signed data provenance, then validate whether the runtime list can include class10. If static attribution is exhausted, plan passive and reversible USB observations first; USB descriptors may offer indirect evidence but not prove internal RAM contents. A known recovery route would be essential before more invasive experiments.

## Reproduce

\`\`\`bash
python -m unittest tests.test_bruce_usb_owner_survey_phase50 tests.test_bruce_usb_owner_pointer_phase50 tests.test_bruce_owner_xrefs_phase50 -v
python -m tools.audit_bruce_usb_owner_survey_phase50 bruce_pvt_a_prod_signed.bin
python -m tools.audit_bruce_usb_owner_pointer_phase50 bruce_pvt_a_prod_signed.bin
python -m tools.audit_bruce_owner_xrefs_phase50 bruce_pvt_a_prod_signed.bin
\`\`\`

Required original SHA-256: \`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3\`.

[Spanish report](../es/bruce-propietario-configuracion-usb-fase50.md) · [PR #52](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/52).
