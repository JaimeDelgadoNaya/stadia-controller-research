# Phase 15 — Internal USB event table and transfer bound

**Verified sample:** bootloader A build 169429, 131,072 bytes, SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`. The owner's binary was examined **offline** and is not committed.

## Eleven internal events, not host opcodes

Function `0x60809C58` subtracts one from its event identifier, accepts indices 0–10, and executes `TBB [PC,R1]` at `0x60809C64`, using the 11-byte table at `0x60809C68`. Its Thumb pointer `0x60809C59` is present at `0x60816284`.

| Internal event | Branch target |
|---:|---|
| 1 | `0x60809C74` |
| 2 | `0x60809CCC` |
| 3 | `0x60809CF2` |
| 4 | `0x60809D74` |
| 5 | `0x60809D74` |
| 6 | `0x60809CFA` |
| 7 | `0x60809D22` |
| 8 | `0x60809D74` |
| 9 | `0x60809D48` |
| 10 | `0x60809D54` |
| 11 | `0x60809D68` |

Events 4, 5 and 8 jump straight to a default return code 1, as do identifiers outside 1–11. This is a switch over **internal controller events**, **not** proof of eleven externally sendable USB commands.

## Transfer-size guard

At `0x60809B28`, `CMP.W R2, #0x200` prevents continuation for a size above **512 bytes**, returning code 3. Subsequent paths involve an indirect method call and `0x60805694`. This is a limit for this **specific helper**, not every transfer or host command. The origin of R2 has not been proven to be externally controlled.

## Separate vendor callback

The event routine `0x60809E64` (pointer at `0x60816290`) instead gates on events **above 127** and conditionally invokes a RAM callback pointer at `0x20009168`, initialized to a no-op handler. It is distinct from the 11-event dispatch routine. Replacement callback registration, an externally reachable request parser, and any path into flash operations remain **unproven**.

## Offline reproduction

```sh
python tools/audit_usb_event_dispatch.py local/bootloader-a.bin --out local/phase15.json
python -m unittest discover -s tests -v
```

The SHA-locked analyzer verifies seven machine-code slices plus essential control-flow anchors and emits JSON. CI tests are synthetic and require no copyrighted firmware. No USB activity, flash writes, resets, fuse changes or code execution on the controller occurred.

**Next:** trace bulk OUT endpoint `0x07` to actual receive buffers, request parsing, argument provenance and signature checks. Internal event dispatch and USB-to-flash reachability are different claims. HAB CLOSED remains a measured barrier; no custom firmware execution has been demonstrated.