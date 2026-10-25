# Phase 14 — USB interfaces and vendor callback (verified bootloader)

Offline analysis of the owner's **128 KiB bootloader A**, build **169429**,
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
The copyrighted binary is **not** committed, distributed or accessed over USB.

At `0x6080BF78`, the device descriptor gives Google VID `18D1`, PID
`946B`, device class `EF/02/01` and USB 2.0. The **80-byte** configuration
at `0x6081527C` describes two interfaces:

- **Interface 0, vendor class FF**: bulk IN `0x87` (512-byte max packet)
  and bulk OUT `0x07` (512-byte max packet).
- **Interface 1, HID class 03**: interrupt IN `0x83` and OUT `0x03`,
  each 64-byte max packet; HID report descriptor length **156 bytes**.

A configuration pointer literal is at `0x6080AF54`; the setter around
`0x6080AF48` passes its address and 80-byte length.

The vendor class-event function pointer at `0x60816290` targets the
Thumb routine `0x60809E64`. It filters events (`r1 > 0x7F`) and
conditionally invokes a callback stored at
`[0x20008B78 + 0x5F0]` with context from
`[0x20008B78 + 0x5F4]`. The constructor at `0x6080BB46`
initializes the pointer to the inert, zero-return default
`0x60809E3D`. Later registration, actual bulk message parsing
and reachability of flash-writing routines are **not yet established**.

Use the SHA-locked, standard-library-only offline parser:

```sh
python tools/audit_usb_callbacks.py local/bootloader-a.bin --out local/phase14.json
python -m unittest discover -s tests -v
```

The parser produces JSON and performs no USB, flash, reset, fuse or firmware
operations. The CI suite uses synthetic descriptors and memory images, not
proprietary firmware. Avoid publishing binary firmware or device identifiers.

**Next:** identify any registration of callback field `0x20009168`,
trace bulk OUT endpoint `0x07` reception to actual command handling,
then investigate data provenance and authentication. Nothing so far
demonstrates external USB-to-flash reachability, HAB bypass or custom execution.
