# Phase 16 — CDC versus vendor callback provenance

**Sample:** privately owned 128-KiB Stadia bootloader A, build 169429,
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
All findings are offline; the binary must not be committed or redistributed.

## The 512-byte helper belongs to a CDC-labelled object

The Thumb entry `0x60809B29`, the `0x200`-byte size-guard helper from
phase 15, is the first entry of a function table at `0x60814E18`.
The constructor loads that table at `0x6080BB14` from literal
`0x6080BBA8` and stores it at object offset `+0x578` in
`0x6080BB1C`. The nearby diagnostic string is `usb_device_cdc.cc`;
a separate source label `usb_device_vendor.cc` occurs later.
This does **not** establish that CDC is an active USB interface: the
observed configuration descriptor contains vendor-specific and HID interfaces.

## Separate callbacks, both initially inert

**CDC-labelled object**: the constructor sets `r5=0` at
`0x6080BACE` and stores it at offset `+0x584` at `0x6080BB06`.
The object base is `RAM base +0x578` so its optional callback at
`[object+0x0C]` is initialized to NULL. `0x60809C44` checks that slot,
performs `BLX R3` only if non-null, and otherwise returns zero.
The event path at `0x60809CE0` passes the CDC object and
`0x60809CE4` calls that conditional wrapper.

**Vendor event path**: `0x60816290` points to `0x60809E64`,
which handles events above 127 using callback address `0x20009168`
and context `0x2000916C`. Initially the callback points to a
zero-return stub `0x60809E3D` installed at `0x6080BB46`.
Searching only for the **exact encoding** of
`STR.W R3,[R4,#0x5F0]` yields one occurrence at that initializer,
but other write forms and runtime registration remain possible.

## Limits and reproducibility

The signed firmware's bulk OUT endpoint `0x07` is present, but
there is **no demonstrated** path from external USB bytes through a
parser to the flash writer. The table of CDC methods and USB
class-event callbacks must not be confused with host commands.

```sh
python tools/audit_usb_callback_provenance.py local/bootloader-a.bin --out local/phase16.json
python -m unittest discover -s tests -v
```

The SHA-locked script reads one private local file and emits sanitized JSON.
Synthetic tests require no copyrighted firmware. No USB I/O, flash writes
or processor eFuse changes occur.

**Next:** trace the vendor bulk OUT `0x07` receive completion to an
actual message parser, including parameter provenance and signature
checks, before alleging a reachable firmware update path. HAB CLOSED
remains a measured security boundary, with no custom execution demonstrated.