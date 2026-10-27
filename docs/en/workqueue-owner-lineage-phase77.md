# Phase 77 — Signed Work Queue owner-relative object and publication guard provenance

**27 October 2026.** Offline audit of original signed Bruce OEM image, pinned SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Follow-up to [phase 76](workqueue-caller-origin-phase76.md).

## Signed activation directly calls object B constructor

The phase66 USB-mode activation path includes original **`0x600747D8 BL 0x6006B3E8`**, immediately preceded by **`0x600747D6 MOV R0,R5`**. In the same original path, **`0x600747BE ADD.W R5,R5,#0x3F00`** followed by **`0x600747C4 ADDS R5,#4`** forms the constructor argument as original R5 + `0x3F04`. An earlier signed call, **`0x600747B2 BL 0x60060F28`**, is the USB owner prior-mode writer investigated in phase66. The intervening `0x600747D2 BL 0x6006B2E8` has not been executed or assumed harmless.

**Under the specific phase66 modeled input** `GLOBAL=0x200064C0`, the modeled `owner=0x2000A2A8` is `GLOBAL+0x3DE8`. Therefore B constructor receives **`0x2000A3C4 = owner+0x11C`** *if the modeled flow reaches it*. This is signed original pointer arithmetic with a prior synthetic global input; it is **not a measured live device pointer or proof of host USB event reachability**.

## B original constructor and distinct byte gates

Original B constructor entry **`0x6006B3E8`**:
- Checks `[input+0x180]` and takes an early-return path if nonzero.
- Loads original signed Thumb callback literal **`0x6006B291`** and stores it into `[R4+0x11C]` at `0x6006B420`.
- Stores context R4 into `[R4+0x120]` at `0x6006B41C`.
- Stores value **1** into `[R4+0x180]` at `0x6006B442` after the signed `MOVS R3,#1`.

Original callback B `0x6006B290` instead reads **`[R4+0x182]`** and writes **zero** to that byte at `0x6006B2C2`. A bounded shape scan in XIP `0x6006A000..0x6006D000` found these two exact-offset `+0x182` accesses; cross-register aliases and other image regions remain out of scope. **These are distinct byte fields.**

The full XIP direct-BL shape census found the activation call to B's constructor. It does not prove that this code is executed on the physical controller or that callback fields are host writable.

## A original arguments and extra gate

A function candidate at `0x60062126` saves **R5=R0** and **R4=R2**. The producer at `0x6006228C` passes **R4+0x10**. Before doing so, it requires `UXTB R0; CMP R0,#0x0E` to pass the signed result-value guard, then the original `LDREXB/STREXB` path requires the prior byte at `[R5]` to be zero.

This establishes **bounded local input-register lineage**. It does not identify the upstream owner of those input arguments, an EP0 transaction, physical USB origin or runtime execution of the branch. No direct XIP BL shape to the candidate A entry was recovered within the census.

## Decision and follow-up

The signed owner-relative B constructor link is substantially stronger than the previously known shared helper. **It is still not a host-controlled code execution path**: no physical USB packet → Work Queue message → callback was observed, nor arbitrary callback rewriting, unsigned firmware execution, HAB CLOSED bypass or reliable recovery.

If focused searches fail to connect upstream producer inputs with a verified USB-origin event, deprioritize this Work Queue as an exploit hypothesis and prefer passive USB observations and a reversible external bridge.

## Reproduce

```bash
python -m tools.audit_workqueue_owners_phase77 local/bruce.bin --out local/phase77-owner.json
STADIA_BRUCE_IMAGE=local/bruce.bin python -m unittest tests.test_workqueue_owners_phase77 -v
```

[PR #79](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/79) · [SHA-pinned evidence](../../evidence/usb-workqueue-owner-origin-phase77.json) · [OEM CI](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40478927390).

No physical USB commands, flash/eFuse writes or installed RAM readback.
