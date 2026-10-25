# Bruce EP0 SETUP: original signed interrupt-to-endpoint callback chain

**Phase PR #33 · 25 October 2026 · offline-only investigation.** The auditor requires the exact original Google-signed Bruce update image (1,050,984 bytes, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`). The image is an **archived update**, not a measured full readback of installed flash. No device or firmware was modified.

## Proven static chain (conditional)

| Stage | Signed original code observation |
|---|---|
| USB OTG1 IRQ 113 | Image vector slot `0x204` contains Thumb `0x600610D1` |
| IRQ wrapper | `0x600610D0` checks a runtime mode; mode `2` branches to `0x6013D1F8` |
| XIP/ITCM veneer | `0x6013D1F8` loads PC from signed literal `0x00001111` |
| Relocated ITCM USB IRQ handler | `0x00001110` inspects controller status/interrupt registers `+0x144` and `+0x148` |
| SETUP status | `0x000011C6` reads `ENDPTSETUPSTAT` (`+0x1AC`); subsequent code copies SETUP metadata using the tripwire sequence |
| Event forwarding | `0x00001258 BL 0x0000BA68`; ITCM veneer targets Thumb `0x600D0FB7` |
| Endpoint event dispatcher | XIP `0x600D0FB6` checks endpoint events and invokes **`0x600D104E BLX R5`** using a callback pointer loaded from a runtime table |

The dispatcher builds an endpoint/direction index `2*(endpoint & 0x0f) + ((endpoint>>7)&1)`, bounds the endpoint number at seven, uses a **12-byte callback-entry stride**, and conditionally invokes the registered function/context pair. The relevant Thumb instruction semantics are pinned by assertions against the exact signed image.

**Critical limit:** the concrete EP0 callback address stored in RAM has **not** been recovered, nor have its class request handling and side effects. A callback registration is not proof of host-controlled arbitrary execution.

## Class requests versus matching bytes

Archived OEM host JavaScript sends normal-mode class requests `bRequest 0x81` (version), `0x83` (battery trigger) and `0x84` (battery read). Eight literal immediate comparisons in earlier Bruce research are **not direct loads** of `SETUP.bRequest` at buffer byte offset `+1`. A broader linear XIP scan found **49** local `+0/+1` byte-load pairs, with **zero nearby direct comparisons** to the host request constants. This incomplete linear scan can encounter literal data, misses indirect/table dispatch and copied ITCM logic, and does **not** rule out a real EP0 receiver.

## Unresolved gates

Physical `SCB→VTOR`, actual runtime mode `2`, dynamically initialized endpoint slot 0/1 pointers, the exact `bRequest` receiver and any memory effect are not proven. No unsigned execution, HAB CLOSED bypass, reliable firmware recovery, direct Xbox compatibility or Switch 2 support has been demonstrated.

Next bounded offline task: trace **who populates endpoint callback slots 0 and 1**, then follow the registered function to its actual EP0 SETUP parser and supported read-only commands.

```sh
python -m unittest tests.test_bruce_ep0_setup_provenance tests.test_bruce_usb_irq_vector -v
python -m tools.audit_bruce_ep0_setup_provenance local/bruce_pvt_a_prod_signed.bin --compact
python -m tools.audit_bruce_usb_irq_vector local/bruce_pvt_a_prod_signed.bin --out local/ep0-irq.json
```

CI downloads and SHA-verifies the public original in an ephemeral runner; it never sends USB, writes RAM/flash, or publishes the OEM binary.
