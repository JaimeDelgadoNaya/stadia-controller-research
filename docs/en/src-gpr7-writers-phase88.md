# Phase 88 — SRC_GPR7 writer provenance and NXP register-map correction

**27 October 2026. Offline only.** Builds on [phase87](bootloader-update-trigger-phase87.md).

## Correction: GPR7, not GPR6

The [NXP RT1060 Reference Manual Rev. 3, SRC chapter, §§21.6.10–11](https://www.pjrc.com/teensy/IMXRT1060RM_rev3.pdf) places **SRC_GPR6 at `0x400F8034`** and **SRC_GPR7 at `0x400F8038`**. Both are ROM-used registers (application code is advised not to use them); the GPR7 documented reset value is 0. Phase87 had the *right MMIO address and bit 3 test* but incorrectly called it GPR6. The earlier PR, reports, evidence, code, tests and README have been corrected.

**ROM-reserved does not mean the ROM is proved to set this specific update flag.** Neither warm-reset persistence on the owner device nor a host-controlled bit writer is measured.

## Bounded original owner bootloader A evidence

The [previously published selected Thumb disassembly](../../evidence/bootloader-analysis.json) covers **28 functions and 903 instructions**, not the full binary. The private original bootloader A file was unavailable for an independent rehash in this session.

The [phase88 auditor](../../tools/audit_src_gpr7_writers_phase88.py) validates the existing selected pins and attributes precisely two direct `STR R2,[R3,#0x38]` operations to the SRC base literal `0x400F8000` in that corpus:

- `0x6080286A`: clears **SRC_GPR7** to **0** after saving its previous value.
- `0x60801F14`: writes **0x10 or 0x20** as application-validation failure status. Neither value asserts the **0x08** update trigger.

The original signed update handler later reads saved bit 3 and conditionally dispatches wrapper `0x60801ED0`, using fixed OEM parameters. **The writer of bit3 has not been identified**. Two selected direct writers are not a whole-firmware census. Indirect, calculated, unexamined and BootROM writers remain unexcluded.

## Bounded hash-pinned public image census

The optional mode checks exact SHA-256 for the archived Bruce signed app and signed RAM flashloader, then counts raw little-endian words for `SRC_BASE` `0x400F8000`, `SRC_GPR6` `0x400F8034` and `SRC_GPR7` `0x400F8038` in each image's pre-CSF span. Raw word occurrences are **not proven function references or executed writes**, and zero does not rule out computed addresses, ROM code or other firmware.

[Tests](../../tests/test_src_gpr7_writers_phase88.py) cover source pins, disambiguation, mutation rejection, count/region limits and false attribution; [CI](../../.github/workflows/nxp-rom-advisories-phase81.yml) uses temporary SHA-pinned public OEM samples. No controller, USB requests, memory or eFuse writes.

```sh
python -m unittest tests/test_src_gpr7_writers_phase88.py -v
python -m tools.audit_src_gpr7_writers_phase88
python -m tools.audit_src_gpr7_writers_phase88 --public-image local/bruce_pvt_a_prod_signed.bin --sample bruce_prod
```

## Second-pass discovery: signed Bruce does write SRC_GPR7

The bounded original-image scan found **12 SRC base literal-load shapes in signed Bruce** and **15 in the signed RAM loader**. One contiguous **original signed Bruce Thumb** sequence at XIP `0x60078A1C–0x60078A28` / file `0x38A1C` uses literal `0x400F8000` at `0x38ABC`:

```asm
0x60078A1C  LDRB  R3, [R4, #8]
0x60078A1E  CMP   R3, #1
0x60078A20  LDR   R3, [PC, #0x98]
0x60078A22  ITE   EQ
0x60078A24  MOVEQ R2, #5
0x60078A26  MOVNE R2, #6
0x60078A28  STR   R2, [R3, #0x38]  ; SRC_GPR7 = 5 or 6
```

**Static code finding:** the original app stores **5 or 6** depending on an internal state byte at `[R4+8]`. Neither asserts update bit `0x08`. The original byte sequence `237a012b264b0cbf052206229a63` and signed literal are SHA-256 gated and checked by the [original-code auditor](../../tools/audit_bruce_gpr7_status_phase88.py). This proves neither actual hardware execution nor a USB- or reset-reachable bit3 writer. The ownership of R4 and its call graph remain unresolved.

The raw constant inventory also found six SRC base words and one distinct GPR6 word in Bruce, ten SRC base words in RAM loader and **zero direct GPR7 literal words in both**; a direct GPR7 word is not required for base-plus-offset access. [Evidence](../../evidence/src-gpr7-writers-phase88.json) · [Original-image CI](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40579561235).

**Provisional decision:** offline GO to identify **actual SRC_GPR7 bit3 writer/provenance** only. NO-GO for setting bits, USB mutation or IVT/flash tests without independent reachability and recovery evidence. HAB ROM version and unsigned code execution remain unproven.

[Sanitized evidence](../../evidence/src-gpr7-writers-phase88.json) · [PR #97](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/97).
