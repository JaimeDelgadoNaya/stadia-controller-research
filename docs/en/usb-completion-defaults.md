# Phase 19 — Initially inert vendor USB completion handlers

Verified private sample: Stadia bootloader A, build 169429, **131072 bytes**,
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
This is **offline static analysis**. No controller access, USB I/O,
flash writes or proprietary firmware publication.

Phase 18 associated vendor **bulk OUT `0x07`** with registered adapter
`0x6080A06A` and **bulk IN `0x87`** with `0x60809E30`.
The generic USB controller saves callback/context at
`0x60806674–0x60806686` and invokes them on completion at
`0x60806554–0x60806558`.

The OUT adapter forwards its context through
`0x6080A062`: function pointer from `[R0+0x18]`, context from
`[R0+0x1C]`, then `BX R3`. That context is the vendor object at
`0x20008B78 + 0x5E8 = 0x20009160`.

The constructor `0x6080BAC0` sets these **initial** values:

| Endpoint | Function field (RAM) | Context field | Literal | Handler |
|---|---|---|---|---|
| Bulk IN `0x87` | `0x20009170` | `0x20009174` | `0x6080BBB4` | `0x6080AFFA` |
| Bulk OUT `0x07` | `0x20009178` | `0x2000917C` | `0x6080BBB8` | **`0x6080AFFC`** |

Both contexts start at zero; the literal values are odd Thumb pointers
`0x6080AFFB` and `0x6080AFFD`. **Both default handlers contain only
`70 47` (ARM Thumb `BX LR`)** and immediately return.

Relevant static anchors include constructor stores
`0x6080BB50`/`0x6080BB5A`, zeroing at
`0x6080BB6C`/`0x6080BB70`, vendor object construction
`0x6080BB7C`, and the adapter `0x6080A062`.
An exact four-byte opcode search for the constructor OUT store
finds one occurrence at `0x6080BB5A` **but cannot exclude**
alternative store encodings or runtime callback replacement.

**Conclusion limited to normal initial state:** the OUT completion path's
initial registered target is inert. This does **not** rule out later
callback registration, other USB update paths, externally controlled
command parsers elsewhere, or authentication checks. USB-to-flash
reachability, HAB CLOSED bypass and custom execution remain unproven.

## Reproduce safely

`tools/audit_vendor_completion.py` verifies the whole-image SHA-256,
eight independent code-region fingerprints, machine instructions, USB
endpoint table and constructor literals. CI uses **synthetic images**.

```sh
python tools/audit_vendor_completion.py local/bootloader-a.bin --out local/phase19.json
python -m unittest discover -s tests -v
```

**Next (phase 20):** inspect possible setter/registration paths for
function fields `0x20009170` and `0x20009178`, then trace the
actual USB-byte provenance to any reachable parser. No hardware tests
are needed to reproduce this phase.
