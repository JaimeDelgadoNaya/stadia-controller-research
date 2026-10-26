# Phase 46 — Original signed USB1 endpoint callbacks and class SETUP event routing

**26 October 2026 · PR #48 · Read-only, exact SHA-256-pinned OEM Bruce signed update, not installed-device readback.**

## Signed original chain and the precise missing link

The signed image's Cortex-M vector slot for **USB_OTG1, IRQ 113**, at file offset `0x204`, contains Thumb pointer **`0x600610D1`**. Its handler selects among mode-dependent paths. A candidate path through startup-relocated ITCM processes SETUP status and at **`0x1258`** calls the ITCM veneer **`0xBA68`**, which points to signed XIP receiver **`0x600D0FB6`**. Live SCB->VTOR, IRQ mode and physical execution were **not measured**.

The signed receiver looks up an endpoint callback from a 12-byte table using `2*(event.endpoint_address&0x0F) + ((event.endpoint_address>>7)&1)`, rejecting endpoint numbers above 7. **EP0 OUT index 0** and **EP0 IN index 1** use function/context offsets `+0x0C`/`+0x10` relative to the USB object, plus 12 bytes for each additional slot. The callback is loaded at `0x600D104A` and invoked via **`0x600D104E: BLX R5`**.

A separate signed registrar at **`0x600D10B8`** computes the same endpoint index from an endpoint descriptor-like byte and stores a callback at `0x600D10DE` and context at `0x600D10DA`. Signed direct calls at `0x60054782` and `0x60054850` select from four OEM adapter literals:

| Literal source | OEM Thumb adapter | Internal event code placed in R1 |
|---|---|---|
| `0x600547A0` | `0x600CFC71` | 3 |
| `0x600547A4` | `0x600CFC35` | **1** |
| `0x600547A8` | `0x600CFC53` | 2 |
| `0x60054870` | `0x600CFC1B` | 4 |

Each adapter conditionally tail-calls an OEM class event method through the object pointer. A signed literal **does not prove** that EP0 ever registers it. The **actual EP0 OUT/IN callback words, class object and active USB configuration remain unknown**.

## Critical correction: internal event 1, not event 4, decodes bRequest

The forwarder `0x600D0E58` does **not** directly interpret R1 as an external `bRequest`. It first subtracts 1 and uses `0x600D0E68: TBB [PC,R1]` on an *internal event code*. Original bytes at `0x600D0E6C` are exactly **[27, 2, 7, 18]**:

| Internal event | Target in signed code |
|---|---|
| **1** | **`0x600D0EA2`**, SETUP-shaped request processing |
| 2 | `0x600D0E70` |
| 3 | `0x600D0E7A` |
| 4 | `0x600D0E90` |

An initial hypothesis incorrectly chose event 4. Pinned original-image CI caught the error, and the auditor/tests now verify **event 1**.

**If** EP0's registered callback is `0x600CFC35` and its runtime context/vtable resolves to the class forwarder, the adapter sets R1=1. The class forwarder routes that event to `0x600D0EA2` (read SETUP-like buffer pointer from R2), checks recipient/interface and at **`0x600D0EB8`** loads R1 from `[request+1]`. Only here does R1 become the candidate USB `bRequest`; phase 45 then described the further conditional route into class10 and the signed 13-case handler `0x80..0x8C`.

These are authenticated **static signed instruction/data relationships**, **not** a proven real physical USB1 EP0-to-class10 request path. The endpoint event record is not automatically a raw SETUP packet. A runtime slot capture or stronger instruction-traced registration proof is still needed.

## Stop conditions and phase 47

Missing evidence: who writes EP0 callback slots **0 and 1**, which callback they actually hold, the class event object/vtable, active USB configuration and physical SETUP data origin. No host-controlled arbitrary function pointer, HAB CLOSED bypass, unsigned firmware execution, reliable recovery or Xbox/Switch 2 direct support has been shown. Nothing was sent to or written on the physical controller.

**Next step:** reconstruct the exact writer and predicates for the two EP0 slots, and map the reception event record to the class SETUP buffer without conflating internal event types and USB request bytes.

Reproduce:

```bash
python -m unittest tests.test_bruce_usb1_ep0_bridge_phase46 tests.test_bruce_ep0_slot_handoff_phase46 tests.test_bruce_event_to_brequest_phase46 -v
python -m tools.audit_bruce_usb1_ep0_bridge_phase46 local/bruce_pvt_a_prod_signed.bin
python -m tools.audit_bruce_ep0_slot_handoff_phase46 local/bruce_pvt_a_prod_signed.bin
python -m tools.audit_bruce_event_to_brequest_phase46 local/bruce_pvt_a_prod_signed.bin
```

[Spanish detailed evidence](../es/bruce-usb1-ep0-clase10-fase46.md) · [PR #48](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/48).
