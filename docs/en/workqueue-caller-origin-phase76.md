# Phase 76 — Original signed Work Queue caller provenance and B callback initialization

**26 October 2026.** Entirely offline audit of the exact Bruce OEM SHA-256-pinned signed firmware `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.

## Signed producer A: atomic flag gate

Original `0x60062288 ADD.W R0,R4,#0x10` prepares the first work item and `0x6006228C BL 0x600926A0` conditionally calls the signed Work Queue API. The preceding `LDREXB/STREXB` loop operates on `[R5]`; successful exclusive store and a previously zero flag are necessary for the observed branch. This does **not** identify the R4 owner object, producer of the original flag, physical USB activity, or runtime execution.

## Signed producer B: state-dependent dispatch

The function at `0x6006B290` calls `0x600D8F64`; a status byte `[R4+0x182]` must be zero, and the helper result must be exactly **2** for the `0x6006B2AC ADD.W R0,R4,#0x11C` / `0x6006B2B0 BL 0x600926A0` branch. `0x600D8F64` delegates to `0x600D8E6C` with `R1=9`. No USB host origin is inferred.

## New signed OEM attribution of B callback pointer

An aligned original signed literal at **`0x6006B4B4`** holds Thumb **`0x6006B291`**, targeting signed function **`0x6006B290`**. Crucially, the signed initializer contains:

```asm
0x6006B416  LDR   R3,[PC,#0x9C]      ; load 0x6006B291
0x6006B41C  STR.W R4,[R4,#0x120]     ; signed context R4
0x6006B420  STR.W R3,[R4,#0x11C]     ; signed callback address
0x6006B2AC  ADD.W R0,R4,#0x11C       ; producer argument
0x6006B2B0  BL    0x600926A0        ; conditional queue posting
```

**The signed image itself supplies and installs the B callback pointer** on the shown initialization path. This does not establish its actual installed RAM value, exclude unknown other writes, or demonstrate that USB can select a method pointer. A generic worker `BLX` is not evidence of user-controlled unsigned execution.

## Shared helper with phase 66, not proven end-to-end host path

The phase 66 original owner/mode writer, `0x60060F2C`, is followed by `0x60060F34 BL 0x6009267C`. The B initializer also executes an original-code `0x6006B400 BL 0x6009267C` instruction **if its path is reached**. The shared helper narrows candidate integrations, but **the two callers have not been proven to use the same object or execute in an order linking a physical USB request to callback registration**.

The signed audit finds **no direct BL to B function entry** in the bounded XIP survey; it does find the exact Thumb literal and PC-relative signed loader. Indirect calls and state paths are not excluded. Other known class10/EP0 function anchors are inspected separately; no actual USB-to-queue event is proven.

## Next

Phase77: trace R4 object owners and flag/status writers with explicit stop criteria. Avoid treating runtime function pointers as host-controlled without proving the assignment and trigger.

**Unproven:** physical USB event → Work Queue posting, real message delivery, callback execution, host-selected code, HAB CLOSED bypass, custom firmware and native Xbox acceptance. No hardware accesses or flash/eFuse writes occurred.

```bash
python -m tools.audit_workqueue_caller_provenance_phase76 local/bruce.bin --out local/phase76.json
STADIA_BRUCE_IMAGE=local/bruce.bin python -m unittest tests.test_workqueue_caller_provenance_phase76 -v
```

[PR #78](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/78) · [Original SHA-pinned evidence](../../evidence/usb-workqueue-caller-provenance-phase76.json).
