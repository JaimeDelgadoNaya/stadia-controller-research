# Bruce USB endpoint callback registration — bounded EP0 attribution

**PR #34 · 26 October 2026.** Purely offline audit of the **exact signed OEM Bruce update image**, 1,050,984 bytes, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. This update archive is **not** a full live flash readback.

[Previous phase](bruce-ep0-callback-chain.md) traced a conditional signed-code chain from OTG1 IRQ through relocated ITCM `ENDPTSETUPSTAT` intake, its XIP endpoint dispatcher `0x600D0FB6`, and indirect callback call at `0x600D104E`. **This phase identifies the exact endpoint callback registration routine, two direct callers, and four possible class-event forwarding callbacks. It does not resolve the actual live EP0 callback.**

## Verified callback registration routine

At XIP `0x600D10B8`:

| PC | Verified effect |
|---|---|
| `0x600D10C0` | `LDRB R4,[R1,#2]`: endpoint address in config descriptor |
| `0x600D10C2` / `0x600D10C6` | Endpoint number masking and upper limit 7 |
| `0x600D10CA..0x600D10D0` | Builds `2*(address&0xf)+((address>>7)&1)` index |
| `0x600D10D6` | `MLA` computes `device+12*index` |
| `0x600D10DA` | Writes callback context at slot `+0x10` |
| `0x600D10DE` | Writes callback function at slot `+0x0c` |
| `0x600D10E0` | Clears slot state |
| `0x600D10E8` | Delegates configuration operation 2 to `0x600D0EDE` |

**Relative to the device object**, EP0 OUT index 0 would have a function pointer at `+0x0c`, context at `+0x10`; EP0 IN index 1 function at `+0x18`, context at `+0x1c`. The actual object location, active mode and live pointer values are **unmeasured**. De-registration at `0x600D1122` zeroes a selected slot's pair.

## Direct caller origins and literal callback values

Two XIP direct BL callsites have been confirmed against the signed file:

- `0x60054782 → 0x600D10B8`, inside the endpoint descriptor loop at `0x60054728`.
- `0x60054850 → 0x600D10B8`, inside another descriptor loop at `0x600547AC`.

Upstream direct XIP calls include `0x600CFD92 → 0x60054728` and `0x600D03AC → 0x600547AC` (with a tail branch `0x600CFDA0 → 0x60054728`). These **configure descriptor-described endpoints**, not a proven path specifically configuring USB control endpoint zero.

Original Thumb literal constants used at those registration sites:

| Literal position | Thumb pointer | Signed forwarder |
|---|---|---|
| `0x600547A0` | `0x600CFC71` | `0x600CFC70` |
| `0x600547A4` | `0x600CFC35` | `0x600CFC34` |
| `0x600547A8` | `0x600CFC53` | `0x600CFC52` |
| `0x60054870` | `0x600CFC1B` | `0x600CFC1A` |

The four functions forward internal events **1–4** via a further indirect class-object function pointer loaded from memory (`BX R3`), rather than a host-selected arbitrary function address. Class handler pointer identity remains unknown. Their event values are **not** USB `bRequest 0x81/0x83/0x84` from the OEM updater.

Auxiliary census: seven **heuristic** XIP regions show 12-byte-stride-plus-store shapes (only the known registrar is semantically validated). Startup-copied initialized data holds 258 broadly Thumb-pointer-shaped words, of which 56 target a USB-adjacent XIP address range. These are **not** all verified USB callbacks and do not establish live slot contents. A bounded aligned-word scan found zero matching Thumb pointer words for the registrar and its two descriptor loops; this cannot exclude computed, relocated, unaligned or indirect references.

## Gates still open

- **Proven from signed static code:** callback registration, endpoint index arithmetic, two descriptor-based callers, four candidate class-event forwarders and some upstream configuration calls.
- **Unproven:** active VTOR and mode, which function is installed specifically in EP0 OUT/IN, actual class callback instance, specific host `bRequest` parsing/effects and device-visible read/write behavior.
- **Not accomplished:** custom code execution, bypass of HAB CLOSED, independently tested safe rollback, or native Xbox/Switch 2 compatibility.

**Next bounded step:** investigate how the **EP0 control request class object** is initialized and which registered class callback consumes SETUP byte `+1`. Do not infer EP0 from ordinary endpoint descriptor registration, or test unknown/write-capable requests on the only controller.

## Reproduce offline

```sh
python -m unittest tests.test_bruce_ep0_registration -v
python -m tools.audit_bruce_ep0_registration local/bruce_pvt_a_prod_signed.bin --out local/ep0-registration.json
```

GitHub Actions SHA-verifies a temporary public archive and deletes it after audit. No USB packets are emitted, no private binaries are committed, and nothing is flashed.
