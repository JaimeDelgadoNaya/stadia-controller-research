# Phase 53 — Necessary signed USB mode-2 entry guards

**26 October 2026.** Read-only analysis of the original signed Bruce OEM update, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. No USB requests, device access or flash/eFuse modifications.

## Main result: requesting mode 2 is not sufficient

Phase 52 traced a **conditional** write `[0x20004084] = 0x2000A2AC`. Phase 53 pins the earlier necessary guards to original signed instructions:

```asm
0x60060FEC  LDR.W R3,[R0,#0x90] ; prior mode at owner+0x90
0x60060FF0  MOV R4,R0
0x60060FF2  MOV R5,R1
0x60060FF4  CMP R3,R1
0x60060FF6  BEQ 0x6006107C    ; previous == requested: exit
0x60060FF8  CMP R3,#0
0x60060FFA  BEQ 0x6006107C    ; previous == 0: exit
...
0x60061020  CMP R5,#2
0x6006102A  BNE 0x60061080
0x6006102E  BL 0x60060F84     ; only on mode-2 path
```

The **necessary, not sufficient** conjunction is `requested==2 && previous!=0 && previous!=requested`. Prior mode is loaded from `owner+0x90 = 0x2000A338`.

| Hypothetical prior mode | Request | Pass THESE early guards? |
|---|---|---|
| 0 | 2 | No |
| 1 | 2 | Yes, not evidence of the final constructor |
| 2 | 2 | No |
| 3 | 2 | Yes, not evidence of the final constructor |

Further OEM calls, hardware state and returns are unknown. A passing row is not proof of reachability on a physical controller.

## Original signed mode-field writes

`0x6006101C` initializes R7 to **1** and `0x60061022` conditionally writes it to `[R4+0x90]` *before* the constructor call. Later, `0x60061070` conditionally stores requested mode R5 to the same field. Thus a transient stored **1** must not be mistaken for the ultimate active mode.

Separately, `0x600550F6–0x600550FA` rejects a **zero** method at `[owner+8] = [0x2000A2B0]`. A nonzero method is only a necessary condition, not proof of a valid callable address or an installed runtime class.

## Boundaries and next question

We have established more precise signed-code guards, **not** values of physical RAM, active class10 selection, host-controlled callback pointers, unsigned execution or a HAB CLOSED bypass. Writer provenance for `owner+4/+8/+12` remains open; passive USB descriptor observation is an alternate next source of **indirect** evidence and is not a RAM snapshot.

## Reproduce

```bash
python -m unittest tests.test_bruce_mode2_preconditions_phase53 -v
python -m tools.audit_bruce_mode2_preconditions_phase53 local/bruce_pvt_a_prod_signed.bin --out local/phase53-guards.json
```

The script verifies exact OEM hash/size and the original signed instruction pins before producing a report. Synthetic mode scenarios are not hardware measurements.

[Structured evidence](../../evidence/bruce-mode2-preconditions-phase53.json).
