# NXP research phase 85 — signed HAB failsafe caller candidates and decision

**27 October 2026.** Bounded offline continuation of [phase84](nxp-hab-rvt-literals-phase84.md).

The SHA-pinned original signed Bruce application contains a confirmed **outgoing** Thumb instruction fragment at `0x60040726` that dispatches via the ROM HAB **`failsafe`** pointer (`RVT+0x28`), not `get_version` (`+0x30`). The previously extracted private bootloader A separately uses `entry`, `authenticate_image_no_dcd`, and `exit` during additional-image validation (see [boot chain](../es/arranque.md)), but the owner's private binary was **not available for a fresh scan in this session**.

The [new SHA-pinned auditor](../../tools/audit_hab_failsafe_callers_phase85.py) searches the signed pre-CSF Bruce span for raw little-endian pointer words matching `0x60040726/27` and *syntactically* decoded direct Thumb branches to the stub. It cannot prove instruction boundaries, execution, indirect pointer calls, computed branches, physical ROM state or vulnerability.

**[CI on original hash-verified OEM images](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40568935912):** zero raw direct pointer candidates, zero decoded direct branch candidates, and no established runtime callers. **52 synthetic regression tests passed** across NXP phases 81–85. Nothing ran on the controller; no firmware/OTP writes.

**Decision: provisional NO-GO** for treating the `failsafe` stub as a path to custom firmware or ROM-version disclosure. The result is not proof that no indirect caller or alternate HAB entry exists. Keep the HAB research lane secondary until independently verified hardware version, a reachable additional-image authentication weakness, or a recoverable execution avenue becomes available.

The historical HAB authentication advisory and SDP information disclosure CVE-2022-45163 are separate questions. Neither a potentially affected family nor memory disclosure establishes signed-code execution. No ROM version, custom firmware, signature bypass or console compatibility is demonstrated.

[Tools](../../tools/audit_hab_failsafe_callers_phase85.py) · [tests](../../tests/test_hab_failsafe_callers_phase85.py) · [sanitized evidence](../../evidence/nxp-hab-failsafe-callers-phase85.json).
