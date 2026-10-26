# Phase 51 — Signed USB owner pointer loads, local class-field writers, and one-hop callers

**26 October 2026 · PR #53 · Original SHA-pinned Bruce OEM signed UPDATE only.** No physical USB device accessed, no flash writes, and no live RAM readback.

## Main findings

The signed application contains **16 aligned 32-bit literal words** equal to the USB owner base **\`0x2000A2A8\`**. The new tool validates literal PC arithmetic, identifying **11 candidate Thumb LDR instructions** that actually address these words via \`((PC+4)&~3)+immediate\`. This is stronger than counting bytes, but linear-decoding near literal pools still does not prove reachability in a control-flow graph (CFG).

A conservative local register-alias analysis (moves, constant additions/subtractions, register redefinitions; stop at branches/calls) finds **no attributable direct local store** to:

- \`owner+4 = 0x2000A2AC\`: runtime class-list pointer
- \`owner+8 = 0x2000A2B0\`: runtime control method
- \`owner+12 = 0x2000A2B4\`: runtime class-record count byte

**This does not establish that these fields are never written.** The analysis is intra-basic-block, not an exhaustive interprocedural or whole-firmware alias analysis. The physical RAM field values were not measured, so **active class10 membership remains unverified**.

## Eleven exact PC-derived literal load candidates

The code candidates are at:

\`\`\`text
0x60041E90  0x6005ABF2  0x6005ACC0  0x6005ACCC
0x6005ACDA  0x600610EA  0x60065446  0x60071416
0x60074AF8  0x60074E56  0x60079D7C
\`\`\`

The previously verified mode switch at \`0x60071416\` loads the owner pointer from \`0x60071438\`. Other candidates include wrappers that pass the owner through R0 to a helper or through R2 as an argument. **All candidates need CFG evidence** before treating their decoded neighborhoods as reachable code.

## One-hop signed callee inspection

| Signed function | Verified original behavior | Implication |
|---|---|---|
| \`0x600D4E64\` | Reads mode \`[R0+0x90]\`, engine pointer \`[R0+0x98]\` | Not a direct local writer of class config fields |
| \`0x600D5512\` | Reads \`[R0+0x90]\` and status byte \`[R0+0x104]\` | Mode/status check |
| \`0x600D546A\` | Reads \`[R0+0x9C]\` | Auxiliary field access |
| \`0x60060FE8\` | R0 moved to R4; mode-2 may invoke \`0x60060F84\` | Conditional USB configuration setup, not active class-list readback |
| \`0x60079D7C\` → \`0x6007EB8C\` | First loads owner base into **R2**; second routine stores words through **R0** and \`R0+4\` | **Do not** mistakenly attribute stores in another argument to owner+4 |

This last distinction eliminates a particularly tempting but ungrounded conclusion: a nearby store to offset +4 is not necessarily a store to **owner+4** if the owner base is only supplied in R2.

The surveyed one-hop callees also include signed veneers and status helpers; a narrow linear function window is not an exhaustive CFG.

## Implications for custom firmware goal

This phase provides **negative discrimination and more trustworthy original OEM dataflow**: 11 anchored literal loads and several rejected false-positive writers. It **does not** demonstrate activation of class10 on the original controller, arbitrary host-controlled callback registration, execution of unsigned firmware, any path around **HAB CLOSED**, or native Xbox / Switch 2 support. It would be misleading to interpret the phase number or growing test suite as a percent-completion towards custom firmware.

## Phase 52 recommendation

Prioritize an **interprocedural CFG and alias/value propagation** beginning at the signed mode-2 owner path \`0x60071416 → 0x60060FE8 → 0x60060F84\`, tracing who initializes \`owner+4/+8/+12\`. If full static provenance is impractical, compare safe passive/reversible USB descriptor observations with the signed static class routing (while acknowledging that descriptor observations do not read internal RAM). No firmware or eFuse writes without proven recovery.

## Reproduce

\`\`\`bash
python -m unittest tests.test_bruce_owner_alias_writers_phase51 tests.test_bruce_owner_transitive_phase51 tests.test_bruce_owner_mode_guards_phase51 -v
python -m tools.audit_bruce_owner_alias_writers_phase51 bruce_pvt_a_prod_signed.bin --out phase51-aliases.json
python -m tools.audit_bruce_owner_transitive_phase51 bruce_pvt_a_prod_signed.bin --out phase51-callees.json
python -m tools.audit_bruce_owner_mode_guards_phase51 bruce_pvt_a_prod_signed.bin --out phase51-mode-guards.json
\`\`\`

Pinned original signed Bruce SHA-256: \`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3\`.

[Spanish report](../es/bruce-escritores-clases-owner-fase51.md) · [PR #53](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/53).
