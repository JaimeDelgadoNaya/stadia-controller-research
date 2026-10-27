# Phase 89 — offline Thumb-2 MOVW/MOVT SRC_GPR7 address synthesis survey

**27 October 2026.** Follows [phase 88](src-gpr7-writers-phase88.md). No controller, USB traffic, MMIO, flash, or OTP writes.

The [SHA-gated analyzer](../../tools/audit_src_gpr7_movw_movt_phase89.py) verifies original full-file hashes and signed IVT/CSF, then surveys halfword-aligned Thumb-2 MOVW encodings for lower half 0x8000, 0x8034 (SRC_GPR6) or 0x8038 (SRC_GPR7) paired with MOVT upper half 0x400F. Nearby STR word encodings are screened for a possible effective address **0x400F8038**. Pair spacing and store windows are limited to 96 bytes.

**This is an encoding census, not a call graph or actual live register tracing.** It misses indirect address arithmetic, alternate forms, relocated RAM code and ROM writers. Even paired machine-code patterns can be data.

[Original-image GitHub Actions](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40583595092):

| Pattern | Signed Bruce original | Signed RAM loader |
|---|---:|---:|
| MOVW SRC-related low halves | **1** | **0** |
| MOVT high half 0x400F | **0** | **0** |
| Same-register MOVW/MOVT pairs | **0** | **0** |
| Possible GPR7 store shapes from such pairs | **0** | **0** |

**118 cumulative synthetic NXP phase81–89 tests passed**, along with Python 3.11/3.12 and five parallel regression tracks.

## NXP documentary caution

The [RT1060 Rev.3 reference manual, §21.6.11](https://www.pjrc.com/teensy/IMXRT1060RM_rev3.pdf) lists SRC_GPR7 at **0x400F8038**, with documented reset value zero and reserved ROM use. However, [an NXP employee clarified](https://community.nxp.com/t5/i-MX-RT-Crossover-MCUs/SRC-GPRx-Register-Usage/m-p/1037773) that **the current ROM does not necessarily use all SRC_GPR registers**, reserving them for cross-silicon and ROM-revision compatibility. No evidence here identifies a ROM writer of bit3 or confirms retention across the device's actual warm-reset path.

**Decision:** bounded NO-GO for this specific MOVW/MOVT construction pattern in the two original signed images. The source of **SRC_GPR7 bit3 (0x08)** remains unknown; the existing Bruce status writer stores **5 or 6**, neither setting bit3. A NXP ROM role, reset persistence, USB-host control and any custom-code execution or HAB bypass remain unproven.

Next step: verify RT1060 SRC_GPR7 ROM ownership and reset semantics using primary documentation only, with no hardware risk.

[Tests](../../tests/test_src_gpr7_movw_movt_phase89.py) · [Sanitized evidence](../../evidence/src-gpr7-synthesis-phase89.json) · [Bruce track #99](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/99).
