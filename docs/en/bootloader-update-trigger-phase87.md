# Phase 87 — Bootloader A update trigger provenance (GPR7 bit 3)

**27 October 2026. Correction:** NXP defines `0x400F8038` as SRC_GPR7, not GPR6 (`0x400F8034`). The initial version misnamed the register. **Address and bit-3 behavior are unchanged.**

 Offline continuation of [phase86](bootloader-update-transaction-phase86.md) based on **previously archived selected original Thumb instructions** for bootloader A build 169429, SHA-256 recorded from the owner's earlier extraction `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`. The complete owner-private file is **not available for rehashing in this phase**.

## New evidence

The signed OEM handler reads **GPR7 at `0x400F8038`** into R4, writes zero to that register, restricts the snapshot to its low eight bits and conditionally dispatches the update wrapper **only if bit 3 (`0x08`) is set**:

```asm
0x60802860  LDR  R3, [PC, #0xA4] ; base literal 0x400F8000
0x60802862  MOVS R2, #0
0x60802866  LDR  R4, [R3, #0x38]
0x6080286A  STR  R2, [R3, #0x38]
0x6080286C  UXTB R4, R4
0x608028B0  LSLS R3, R4, #0x1C
0x608028B2  BPL  0x608028CE    ; skip when original bit 3 = 0
0x608028C6  BL   0x60801ED0    ; when bit 3 = 1
```

Before the call, fixed original OEM literals and pointer arithmetic prepare:

| Register | Original source |
|---|---|
| `r0 = 0x200095A8` | `0x200090D8 + 0x4D0`, internal storage object |
| `r1 = 0x6080285D` | Original signed Thumb callback; delegates to power/input guard |
| `r2 = 0x200090D8` | Original OEM callback context |

The wrapper `0x60801ED0` calls the constructor `0x60801CC8`, which resolves storage descriptor **`0x12`** and installs the callback/context, then calls update coordinator `0x60801DD4`. **These are not demonstrated host-provided USB parameters.**

A separate original selected writer at `0x60801F14` stores only **`0x10` or `0x20`** to the same GPR7 register for app validation failure. Neither sets bit 3. **This is not a whole-image writer census.** We do not know which component writes bit 3, whether the value survives reboot, or whether any USB command can set it.

## Verified offline results

[Sanitized evidence](../../evidence/bootloader-update-trigger-phase87.json) · [Dedicated CI](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40575899921) · [General Python 3.11/3.12 CI](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40575899852).

The original-disassembly gate confirms **31 pinned instructions**, and the 256 synthetic low-byte GPR7 values contain exactly **128 states with bit 3 set**. **76 specific phase81–87 regression tests passed**, along with the general Python test suites. **No caller or writer of the actual hardware bit has been established.**

## Evidence and decision

The [auditor](../../tools/audit_bootloader_update_trigger_phase87.py) pins **31 selected original Thumb instructions** and reuses phase86 transaction validation. [Synthetic tests](../../tests/test_bootloader_update_trigger_phase87.py) cover all 256 low-byte flag states, exact internal arguments and fail-closed mutations. The source is a published *selected disassembly*, not an independently rehashed original binary or observed physical execution.

**GO (offline only):** find the true writer and provenance of GPR7 bit 3 using independent signed original image evidence. **NO-GO:** USB-trigger, IVT write, hardware reset fault-injection, flash or eFuse tests on the only controller. No HAB bypass, installed custom firmware or ROM patch-version evidence.

[Sanitized results](../../evidence/bootloader-update-trigger-phase87.json) · [PR #96](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/96).
