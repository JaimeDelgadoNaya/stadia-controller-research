# Phase 17 — Vendor USB endpoint callback registration

**Sample:** Stadia bootloader A, build 169429, 131072 bytes, SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
Analyzed **offline** using the owner's private image. No USB communication or
device writes occurred; the binary is not published.

The vendor configuration declares **bulk IN `0x87`** and **bulk OUT `0x07`**
(512-byte maximum packet size). The endpoint initialization routine
`0x60809EB8` performs two registration iterations. At `0x60809F12`, it
loads one callback per iteration from the function-pointer table
`0x60814F24`, then passes the selected callback/context and endpoint
descriptor to registration helper `0x60806660` from `0x60809F1A`.

| Address | Grounded observation |
|---|---|
| `0x60814F24` | Thumb callback `0x60809E31` (function `0x60809E30`) |
| `0x60814F28` | Thumb callback `0x6080A06B` (function `0x6080A06A`) |
| `0x60809F12` | Indexed callback-table load |
| `0x60809F16` | Callback/context saved to registration arguments |
| `0x60809F1A` | Endpoint initialization helper call |
| `0x60809F7E` | Second iteration |
| `0x6080A044` | Class-event 9 initializes, event 1 tears down endpoints |

The helper `0x60806660` uses the endpoint address from `[R1+2]`,
rejects endpoint numbers above 7, and derives a per-direction slot:

```text
index = 2*(bEndpointAddress & 15) + (bEndpointAddress >> 7)
slot = device + 12*index
function_pointer_field = slot + 12
context_pointer_field = slot + 16
```

For standard addresses with reserved bits clear, bulk OUT `0x07` has
**index 14** (function field offset `0xB4`) and bulk IN `0x87` has
**index 15** (function field offset `0xC0`). They are distinct entries.
The two callback functions are **forwarding trampolines**, not yet
identified as packet parsers.

**Critical limitation:** endpoint configurations are read from a runtime
**RAM descriptor structure near `0x200000D8`**. We have **not** resolved
which callback is associated with OUT `0x07` from the iteration order.
The final indirect target, externally controlled host command parser,
flash-writer reachability, and HAB CLOSED bypass remain unproven.

## Reproduce without hardware

```sh
python tools/audit_vendor_endpoints.py local/bootloader-a.bin --out local/phase17.json
python -m unittest discover -s tests -v
```

The CLI verifies the exact full-image SHA-256, seven machine-code-region
fingerprints, callback table and opcode anchors. The CI tests use synthetic
images; no proprietary firmware is committed.

**Next:** reconstruct the RAM endpoint-descriptor initialization, then
follow the **verified** OUT callback into its actual completion handler
and data provenance. No custom firmware execution has been demonstrated.
