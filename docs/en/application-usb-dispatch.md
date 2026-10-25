# Application USB callback dispatch and ITCM relocation

[Español](../es/despacho-usb-aplicacion.md)

The private SHA-matched Bruce update sample now supplies a conditional static
receive-callback path to the [tag-5 two-channel HID control receiver](application-message-role.md).
This is not a measured host command, firmware writer or custom-execution path.

## Correct runtime addresses

Startup copies `0xBDF8` bytes from image address `0x6004081C` to ITCM address zero.
The routine stored at image address `0x600429BC` (file offset `0x29BC`) therefore
executes at **`0x000021A0`**. Its relative call targets must be decoded with that
runtime PC. For example, the receive-rearm call at runtime `0x21F8` targets ITCM
veneer `0xB610`, which loads the XIP destination `0x600D5400`.

A separate startup data copy maps image `0x6013E058` into RAM `0x200031F0`,
containing Thumb callback `0x21A1`. Getter `0x6006262C` returns that RAM
configuration address. These facts connect the relocated routine to an initialized
callback record; they do not measure live registration or execution.

## Conditional dispatch path

The routine's TBB table maps **internal event 2** to runtime `0x21D6`. This is an
internal completion/event identifier, not a USB host opcode. With global byte
`0x2000A33C` nonzero, it obtains buffer and length from the event-data words at
offsets 0 and 4. Length `0xFFFFFFFF` is a sentinel that skips invocation.

The invocation at `0x21F4` uses function/context fields at
`0x200064C0+0x3950/+0x3954`, which exactly alias `0x20009E00+0x10/+0x14`.
Wrapper `0x60058BDC` directly installs thunk `0x600D3687` and parser
`0x60058B65` in those fields. The thunk rearranges arguments and jumps to the
tag-5 parser at `0x60058B64`.

**Registration correction:** helper `0x600D543C` copies a different callback/context
pair to object **+8**, not +0x10. The tag-5 pair is installed by the wrapper's
separate direct stores. Keeping these pairs distinct is necessary to reconstruct
the actual receive path.

After the conditional callback, the dispatcher rearms via `0x600D5400` with
endpoint argument **3** and length **64**, then helper `0x600D0E38`. These arguments
alone do not establish endpoint direction, report descriptor semantics, or the
physical event source. No USB output report or malformed packet was sent.

## Reproduce

```sh
python tools/audit_app_usb_dispatch.py local/bruce_pvt_a_prod_signed.bin
python -m unittest tests.test_app_usb_dispatch -v
```

The tool first verifies the exact full-file SHA and previous tag-5 audit, then
checks startup literals, region fingerprints, relocated instruction semantics and
pointer aliases. [Sanitized evidence](../../evidence/application-usb-dispatch.json)
contains addresses and conclusions, not the proprietary image. Synthetic tests
check relocation bounds, initialized-data mapping, rejection of incorrect XIP
call targets and rejection of other samples. The real-image CLI also passed.

No generic vendor-request receiver, flash-update reachability, signature bypass,
installable patch or Switch 2 compatibility follows from this bounded result.
