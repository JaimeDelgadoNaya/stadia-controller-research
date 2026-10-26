# Phase 49 — Signed USB configuration construction and active class-list provenance

**26 October 2026 · PR #51 · Exact SHA-256-pinned signed Bruce OEM update only; no physical-device observations.**

## Main result: signed writer of the shared configuration pointer

The original signed function **\`0x600550E4\`** retains its incoming R1 as R4 at \`0x600550EA\`. It loads a PC-relative literal at **\`0x600551A8\`**, equal to **\`0x20004080\`**, into R5 and executes:

\`\`\`asm
0x6005512E  STR R4,[R5,#4]   ; [0x20004084] = caller-supplied config pointer
\`\`\`

This is the requested static *writer provenance*. The function has pointer, shared-state and initialization guards. The signed update **does not prove this store executed on a physical controller** or the actual value of the pointer in RAM.

The signed direct caller is \`0x60060F90: BL 0x600550E4\`, inside function **\`0x60060F84\`**. Given a caller object \`owner\`, it passes:

| Constructor argument | Signed source | Configuration interpretation |
|---|---|---|
| R1 | \`owner+4\`, instruction \`0x60060F8A\` | Config structure address |
| R0 | byte \`owner+0x10\`, \`0x60060F8E\` | Initialization mode |
| R2 | \`owner+0x98\`, \`0x60060F86\` | Engine-object output pointer |

A signed direct caller of this owner constructor occurs at **\`0x6006102E\`**. The exact live owner address and owner field contents are **not established**.

### Where the class records and dynamic method come from

The previously verified common class distributor \`0x6005505C\` interprets \`[0x20004084]\` as a configuration with a record-list pointer at \`config+0\`, a dynamic control method pointer at \`config+4\` (read by \`0x600D0BFA\`) and a record-count byte at \`config+8\`. Given this constructor's argument relationship, these fields correspond to **\`owner+4\`, \`owner+8\` and \`owner+12\`**.

The *physical runtime bytes* of those fields have not been measured, and none of the signed code shown here establishes that an active record describes class selector **10**. Although an original signed startup image includes a structurally valid class10 record at \`0x200030F4\`, its existence does not imply that it is present in the **active** configuration record list.

## OEM engine initialization and fixed signed functions

The shared constructor loads these signed original literals:

| Original literal | Verified value |
|---|---|
| \`0x600551A8\` | \`0x20004080\` — shared USB singleton |
| \`0x600551AC\` | \`0x200040A0\` — auxiliary pointer written to singleton +8 |
| \`0x600551B0\` | \`0x600D0BC9\` — signed engine-side callback |
| \`0x600551B4\` | \`0x60104B74\` — signed per-class ROM method table |

It then invokes **\`0x60055138: BL 0x60055350\`**, the USB engine initializer. Original constants at \`0x600553F8\` and \`0x600553FC\` are **\`0x200063C0\`** (RAM engine object) and **\`0x60104BC4\`** (OEM method/vtable pointer); the first original word at \`0x60104BC4\` is **\`0x6005556D\`**.

Within the signed conditional initialization sequence:

- \`0x600553A0\` stores the signed \`0x600D0BC9\` callback into an engine-object field.
- \`0x600553C0\` stores signed \`0x60104BC4\` as the engine object's vtable pointer.
- \`0x600553C2\` writes the engine-object pointer into the output field supplied by the constructor; in this caller's setup that output is **\`0x20004080\`**.
- \`0x600553CA: BLX R3\` invokes the fixed OEM method loaded from the engine vtable.

**None of these instructions demonstrates a host-provided arbitrary executable pointer.** All are signed original-image relationships. They do not establish that the engine initialized successfully on the real controller.

The shared USB global \`0x20004080\` is **outside the startup initialized data copy region**. The signed update does not provide the current RAM object contents.

## Decision boundary and Phase 50

We have traced the configuration pointer **two calls backward** and identified the OEM engine implementation that consumes it. The decisive missing data has moved to the original \`owner\` object and the writes to its \`+4\`, \`+8\` and \`+12\` fields.

**Recommended Phase 50:** recover the owner's constructor/data provenance and identify active config class-record contents. If runtime behavior cannot be inferred from signed code alone, prioritize passive, reversible USB observation (no firmware writes).

Still unverified: class10 inclusion in a connected controller's active USB configuration, physical EP0-to-class10 execution, live secondary callback installation, arbitrary host callback registration, unsigned execution, HAB CLOSED bypass, native Xbox/Switch 2 compatibility. No USB device, flash or eFuses were touched.

## Reproducible audits

\`\`\`bash
python -m unittest tests.test_bruce_runtime_usb_config_phase49 tests.test_bruce_usb_config_writer_phase49 -v
python -m tools.audit_bruce_runtime_usb_config_phase49 local/bruce_pvt_a_prod_signed.bin
python -m tools.audit_bruce_usb_config_writer_phase49 local/bruce_pvt_a_prod_signed.bin
\`\`\`

SHA-256 of the required OEM update: \`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3\`.

[Spanish technical report](../es/bruce-configuracion-usb-activa-fase49.md) · [PR #51](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/51).
