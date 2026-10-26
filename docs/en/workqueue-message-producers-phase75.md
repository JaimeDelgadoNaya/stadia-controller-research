# Phase 75 — Signed Work Queue producer, enqueue primitive and indirect worker callback

**26 October 2026.** Original signed Bruce OEM SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`, studied entirely offline.

## Finding: conditional producer for the same Work Queue object

Original signed code links two conditional caller sites `0x6006228C` and `0x6006B2B0` to `0x600926A0`. That API loads the exact original Work Queue object **`0x2002014C`**, checks `[WorkQueue+0x58]` and branches to producer **`0x600EE18A`** if its handle-like guard passes.

The signed producer:
- Stores **1 at [work-item+8]**, and stores the incoming item pointer to `[SP+8]`.
- Sets **zero at [SP+4]** as a message-type byte.
- Reads **`[WorkQueue+0xB0]`** into R0, passes **`SP+4`** in R1 and **`0xFFFFFFFF`** timeout in R2.
- Calls signed veneer **`0x6013D0E8`**, with raw Thumb word **`0x00006A75`**, reaching original ITCM **`0x6A74`**.

In its bounded original code, ITCM `0x6A74` checks count `+0x38` against capacity `+0x3C` and can call `0xB37C`; **`0xB394 ADDS R6,#1; 0xB396 STR R6,[R4,#0x38]`** describe a conditional count increment. A separate `0x6C88` routine contains a similar increment at `0x6CEC`, but no same-object identity is inferred from equal offsets alone.

### Original receiver/dispatch side

Phase 74 linked the Work Queue worker `0x600EE142` to receiver ITCM **`0x6D2C`**. Subsequent original worker instructions, **not executed by this phase**, read the message type at `[SP+4]`, read the pointer from `[SP+8]`, and under a zero-type branch load a method and argument from the work object using `0x600EE16E LDRD R3,R0,[R4]`, then **`0x600EE172 BLX R3`**.

This forms a **conditional static send → queue → dispatch design**, not proof that any item was actually enqueued/dequeued or that an actual callback ran.

### Upstream caller census

The original signed XIP BL scan finds:

| BL site | Work Queue API |
|---|---|
| `0x6006228C` | `0x600926A0` |
| `0x6006B2B0` | `0x600926A0` |
| `0x60060E62`, `0x60062458`, `0x600624D4`, `0x60077386` | `0x600926B8`, a separate Work Queue API |

The first site passes a pointer based on R4+0x10 following LDREXB/STREXB; the second passes R4+0x11C under signed state guards. **No USB host event to either callsite has been established.** Code/data ambiguity, indirect calls and alias paths are not ruled out by the bounded scan.

## What is proven, and what is not

Signed function instructions, queue object literal, selected send kernel veneer, guarded enqueue/count-update code, conditional message layout and original worker BLX have been pinned. **Live queue population, USB origin, callback invocation, host pointer control, physical class10 activation, custom code and HAB CLOSED bypass remain unproven.** The virtual empty queue from phase74 has not been artificially populated.

**Phase76 proposal:** trace the upstream callers and their object identities back toward known USB EP0/interrupt handlers, and reject a claimed host path unless the dataflow can actually be established.

## Reproduce

```bash
python -m tools.audit_queue_producers_phase75 local/bruce.bin --out local/phase75.json
STADIA_BRUCE_IMAGE=local/bruce.bin python -m unittest tests.test_queue_producers_phase75 -v
```

[PR #77](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/77) · [Original SHA-pinned evidence](../../evidence/usb-workqueue-producers-phase75.json) · [OEM CI](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40405156106). No USB device commands, live RAM, flash/eFuse writes or hardware exploitation.
