# Phase 18 — RAM initialization proves vendor bulk OUT callback mapping

**Sample:** Stadia bootloader A build **169429**, 131072 bytes, SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
Offline examination of the owner's private image, **not published**. The
derivation concerns normal startup, not a direct measurement of live device RAM.

At `0x60801600`, the normal startup code copies **400 bytes** in 32-bit
words from flash **`0x608161E0`** to RAM `0x20000000..0x20000190`
(end-exclusive). The bounds/source literals are at
`0x60801694`, `0x60801698`, and `0x6080169C`.
There is an alternate early startup branch at `0x608015C4`
that can skip this initialization.

The source data at `0x608162B8` comprises two 4-byte records:
`87 02 00 02 07 02 00 02`. Their normal RAM copies are
`0x200000D8` and `0x200000DC`. The address/attribute/packet-size
fields match the standard USB bulk endpoint descriptors at
`0x60815296` (IN) and `0x6081529D` (OUT).

The endpoint-registration loop at `0x60809EB8` starts with `R4`
loaded from literal `0x60809F90` (`0x200000DC`), reads the
first compact descriptor at `[R4-4]`, and chooses callback-table
entry `R6=0`. It then advances `R4` by four and sets `R6=1`
for the second registration. The function `0x60806660`
installs the callbacks in direction-indexed USB slots.

| Iteration | Flash source | RAM descriptor | Endpoint | Callback |
|---|---|---|---|---|
| 0 | `0x608162B8` | `0x200000D8` | Bulk IN `0x87` | `0x60809E30` |
| 1 | `0x608162BC` | `0x200000DC` | **Bulk OUT `0x07`** | **`0x6080A06A`** |

This **resolves the phase-17 direction-to-callback uncertainty**, with
independent agreement among normal-startup code, RAM initializer data,
USB configuration descriptors, registration instructions and callback table.

Bulk OUT callback `0x6080A06A` forwards via `0x6080A062`;
the latter loads a function from `[R0+0x18]`, context from
`[R0+0x1C]`, and branches indirectly at `0x6080A068`.
**The final dynamic callback is unresolved.** There is no proven
host packet parser, external USB-to-flash path, HAB bypass, or custom
firmware execution.

`tools/audit_endpoint_ram_init.py` is a SHA-locked local-file-only
auditor, with six independent instruction-region fingerprints and
synthetic tests (no proprietary image committed):

```sh
python tools/audit_endpoint_ram_init.py local/bootloader-a.bin --out local/phase18.json
python -m unittest discover -s tests -v
```

**Next (phase 19):** find the initialization of the `+0x18/+0x1C`
handler/context fields and trace actual data provenance and validation,
without making a hardware modification or asserting an exploit.