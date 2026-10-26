# Phase 59 — Signed function/context pair consumers and real ITCM handler

**26 October 2026.** Offline study of exact SHA-256-pinned original signed Bruce OEM firmware `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.

## Findings

Phase 58 established conditional writes of a two-word pair at **`0x2000FBF4`** (Thumb-shaped function pointer `0x600CE233` or `0xA9C5`) and **`0x2000FBF8`** (null or a dynamic object context). Phase 59 investigates its **readers and invocations**, and resolves the ITCM handler target.

**No signed code path reading *this specific global pair* and invoking its function pointer has been proved within the audited scan.** This bounded negative finding is **not** proof such a route is absent.

### 1. Aligned signed-literal survey

The original update contains **8 aligned words exactly equal to the global base `0x2000F878`**, with **10 candidate PC-relative LDR instructions** that load this base. The audit found no aligned literal word equal to the **absolute field addresses** `0x2000FBF4` or `0x2000FBF8`. Computed aliases and indirect accesses are not excluded.

### 2. Corrected Thumb scan with positive controls

The initial linear XIP/ITCM disassembly missed the known original stores `0x60063878` and `0x6006387E`, so it was not accepted as absence evidence. A second pass starts Capstone at **every 2-byte Thumb-aligned position** and requires these two original writer sites as fail-closed controls.

This halfword scan detected **11 instruction-shaped accesses** using exact immediate offset `+0x37C` or `+0x380`. Only **one** is a load-shaped instruction: `0x600BD138 LDRB.W R3,[R3,#0x380]`.

The signed PC-relative literal at `0x600BD148`, accessed by `0x600BD136 LDR R3,[PC,#0x10]`, is **`0x20025CE0`**, *not* the target global base **`0x2000F878`**. The nearby store `0x600BD12C` uses that same unrelated literal. Therefore this **one direct load cannot be attributed to the target pair via its fixed base**. Runtime indirection and other offset-calculation patterns remain untested.

### 3. Resolve ITCM trampoline to the signed real handler

The `0xA9C5` Thumb pointer enters `0xA9C4 B.W 0xB980`, where `0xB980` is a four-byte **LDR.W PC** veneer, *not the handler body*. The signed literal at ITCM `0xB984` (original image offset **`0xC1A0`**) is **`0x6007E6A1`**, yielding the genuine signed XIP entry **`0x6007E6A0`**.

Thirteen original instruction pins establish that the XIP routine:
- Checks an object flag at `+0x6C` and state bits at `+0x70`.
- Uses `LDREX/STREX` on object word `+0x74`.
- Makes conditional direct signed calls including `0x60101B76` and `0x6013D138`.

These are **object state/worker code semantics**, not proof that the global pair is invoked, or that the worker is USB-triggered.

## Research decision

The apparent callback/context structure remains an interesting **signed internal registration pattern**, but there is still **no host-controllable execution path**. Phase 60 should narrowly test computed aliases of global base `0x2000F878`, possible indirect calls and the event provenance of `0x6007E6A0`, then stop prioritizing this branch if a USB bridge cannot be established. Passive read-only USB enumeration is an alternative for indirect live evidence, never an installed RAM dump.

Live class10, `owner+4/+8/+12`, unsigned execution, HAB CLOSED bypass and native Xbox/Switch 2 support remain **unproven**.

## Reproduce

```bash
python -m unittest tests.test_bruce_pair_consumers_phase59 -v
python -m tools.audit_bruce_pair_consumers_phase59 local/bruce_pvt_a_prod_signed.bin --out local/phase59-consumers.json
```

[Phase 59 PR](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/61) · [Original OEM CI](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40368779599) · [Structured evidence](../../evidence/bruce-pair-consumers-phase59.json).

No physical USB commands, RAM readback, flash writes or eFuse modifications.
