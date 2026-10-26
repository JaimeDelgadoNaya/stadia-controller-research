# Phase 57 — Signed dynamic-object to USB owner +0x80 consumer bridge

**26 October 2026.** Offline original Bruce OEM SHA-256-pinned signed update (`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`). Signed-code **conditional paths**, not actual live RAM or physical execution evidence.

## Core new finding: identical writer and getter SRAM address

Phase 56 proved the 164-byte allocation-like R0 producer, and phase 55 showed the constructor stores `owner=0x2000A2A8` at object `+0x80`.

Now original signed instructions connect the produced object to a global holder:

```text
0x60079D76 BL 0x6013D378 (R0 size 164)
  -> R4 <- R0
0x60079D84 BL 0x6007EB8C (constructor; stores owner at [R4+0x80])
0x60079D9A BL 0x6007E784 (tail memory operation on object+0x0C)
  -> conditional branch at 0x60079DA2
0x60079DBA MOV R1,R4
0x60079DBC LDR R0,[PC,#0x24] (literal at 0x60079DE4)
0x60079DBE BL 0x60079C6C
  -> 0x60079C78 STR R1,[SP]
  -> 0x60079CD2 LDR R3,[SP]
  -> 0x60079CD8 STR R3,[R6] (R6 is incoming global R0)

    SAME SIGNED GLOBAL ADDRESS: 0x2001EE30

0x60079C50 LDR R1,[PC,#0x14] (literal at 0x60079C68)
0x60079C52 LDR R3,[R1],#4
0x60079C5A STR R3,[R0],#4 (copy first global word to output buffer)
0x60074D94 BL 0x60079C50 (SP buffer)
0x60074DA4 LDR R0,[SP]
0x60074DAA BL 0x6007E794 (+0x80 reader)
```

**The original OEM literals at both sites are exactly `0x2001EE30`.** Thus a conditional signed producer → common global address → getter → reader call is demonstrable. The *runtime value* of the global and temporal ordering are **unmeasured**. Other writers or overwrites remain possible; physical reachability not shown.

## Guarded reads inside 0x6007E794

The function copies its input R0 into R4 at `0x6007E79A`. Under branches indicated by `CMP R3,#2; BEQ` and `CMP R5,#2; BEQ`, signed code reads `[R0+0x80]` at `0x6007E7EA` or `[R4+0x80]` at `0x6007E810`. They are **the same incoming argument on these local control-flow edges**, not yet a live-device observation. These routes then call `0x600D54B8`, which is a focused next audit target.

Nearby `0x6007E784` is **not** one of the +0x80 readers: it sets up `R0+0x0C`, R2=27 and tail-branches to `0x6010177A`. Code adjacency alone would falsely conflate the functions.

## Second reader via actual ITCM veneer

The XIP reader `0x6007E8AC` is reached by a signed ITCM `0xB7C8` veneer with literal `0x6007E8AD` at original file offset `0xBFE8`. Original ITCM PC `0xAA22` has `BL 0xB7C8` immediately after `0xAA20 MOV R0,R4`. Its `0x6007E9A4` read also uses an R4 derived from that function's input. **No same-instance bridge to the global `0x2001EE30` is established for this separate ITCM path.**

## Limits and next experiment

No actual runtime `[0x2001EE30]` value or ordering, no active USB class10, no writers for `owner+4/+8/+12`, no host-controlled code pointers, unsigned execution or HAB CLOSED bypass.

**Phase 58:** inspect `0x600D54B8` with the now grounded +0x80 read as input, seeking a signed USB configuration/registration path. Passive read-only USB enumeration can add indirect runtime evidence if static findings remain insufficient.

## Verification

```bash
python -m unittest tests.test_bruce_parent_consumer_phase57 -v
python -m tools.audit_bruce_parent_consumer_phase57 local/bruce_pvt_a_prod_signed.bin --out local/phase57-parent-consumers.json
```

[Verified original OEM CI](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40361129985) · [Structured evidence](../../evidence/bruce-parent-consumer-phase57.json). No physical USB requests, installed RAM dumps, flash writes or eFuse changes.
