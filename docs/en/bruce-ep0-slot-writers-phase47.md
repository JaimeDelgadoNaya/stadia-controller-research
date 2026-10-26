# Phase 47 — Signed EP0 callback slot writer provenance and conditional adapter selection

**26 October 2026 · PR #49 · Read-only analysis of the exact SHA-pinned original Bruce OEM signed update.**

## Verified result

We now know **how signed code chooses a callback/function and context pair when registering an endpoint**. We do **not** know the values actually written to EP0 OUT and EP0 IN on a physical controller; the signed update file is not installed flash or live RAM readback.

The signed endpoint registrar at **`0x600D10B8`** reads the endpoint-address byte from `[R1+2]`, and uses:

```text
index = 2 * (endpoint_address & 15) + ((endpoint_address >> 7) & 1)
callback_word = usb_object + 0x0C + 12 * index
context_word  = usb_object + 0x10 + 12 * index
```

It reads the signed function from `[R2]` and the context from `[R2+4]`, storing them at **`0x600D10DE`** and **`0x600D10DA`**, respectively. Thus EP0 OUT (`0x00`) selects slot 0 and EP0 IN (`0x80`) selects slot 1.

**Caller A — `0x60054728`:** A signed call exists at `0x600CFD92` inside a class-configuration path. A preserves the caller's object pointer `R0→R6`, extracts endpoint address and flag bytes from a four-byte descriptor-like record, puts address at `SP+6`, signed function pointer at `SP+0x0C` and object context R6 at `SP+0x10`, then calls `0x600D10B8` at **`0x60054782`**.

The signed choice is:
- `flags & 0x30 == 0x10`: adapter `0x600CFC53` (internal event **2**).
- Otherwise, `(flags & 3)==1` **and** endpoint-direction bit7 set: adapter `0x600CFC35` (internal event **1**, the conditional bRequest decoding route of phase 46).
- Otherwise: adapter `0x600CFC71` (internal event **3**).

**Caller B:** conditional code at `0x60054850` registers adapter **`0x600CFC1B`** (internal event **4**) with object context R4 only when `(flags & 3)==3` and the endpoint-direction bit7 is set. Other cases skip **that local** registrar call. This is not proof that the endpoint cannot be registered through a different path.

## What the EP0-specific checks mean

At endpoint address **`0x00`** (EP0 OUT), caller A's guard cannot select the **event-1** callback. At **`0x80`** (EP0 IN), the event-1 callback is **possible only when the record's other flags satisfy the original predicates**; endpoint **`0x81`** (EP1 IN) can also select the same callback.

**Therefore, finding event-1 in signed code does not establish that any real EP0 callback is event-1, nor prove physical USB1 EP0-to-class10 reachability.** The source/contents of the actual endpoint descriptors, runtime USB object and class vtable remain unresolved.

## Callback lifecycle: signed clearing routine

The signed firmware has a complementary slot-clearing function **`0x600D10F6`**. It computes the same endpoint index, zeroes R2 at `0x600D1120`, then writes **two zeros** via `0x600D1122: STRD R2,R2,[R3,#0x0C]` to callback and context; at `0x600D1126` it also clears a byte of entry state. The code is structurally able to address EP0 indexes 0 and 1; there is no runtime evidence which slots are cleared on an actual controller.

These signed routines are an internal registration/clearing mechanism. They do **not** prove an arbitrary host-controlled callback store.

## Evidence boundary and next step

The auditor pins original signed instructions, source literals and direct class-configuration BL call, and provides a **synthetic** EP0 OUT/IN and EP1 IN predicate matrix. It never opens a USB device or writes firmware.

Still missing: actual endpoint records and active configuration, object base and class vtable contents, physical SETUP reception/forwarding, unsigned execution, HAB CLOSED bypass, recovery and native console compatibility.

**Recommended next phase:** trace provenance of the signed configuration record pointer `[R5+8]` into caller A; distinguish true configured endpoints from synthetic addresses. If not statically provable, consider passive, safe and reversible observation rather than unsupported flash changes.

Reproduce:

```bash
python -m unittest tests.test_bruce_ep0_slot_provenance_phase47 -v
python -m tools.audit_bruce_ep0_slot_provenance_phase47 local/bruce_pvt_a_prod_signed.bin
```

Source SHA-256: `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.

[Full Spanish analysis](../es/bruce-escritores-slots-ep0-fase47.md) · [PR #49](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/49).
