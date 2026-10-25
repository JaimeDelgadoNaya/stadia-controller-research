# Phase 29 — Provenance and limits of the `+0x2C` bucket index

**Sample:** private Stadia bootloader A build 169429, 131072 bytes,
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
Research is **offline**; no USB commands, flash writes, eFuse changes or
proprietary firmware publication.

## Five indexed-object stores in the selected firmware window

A narrow scan of the **Thumb16 `STR Rt,[Rn,#0x2C]`** encoding
within `0x60811400..0x60812200` (exclusive end) identifies five
sites, also grounded in the original disassembly:

| Store site | Source and interpretation |
|---|---|
| `0x608115A0` | Initial R6 argument, unsigned-clamped to **15** |
| `0x60811F90` | Copy the index from another object's `+0x2C` |
| `0x60811FB2` | Copy from the same reference field on an alternative branch |
| `0x60812056` | Restore index from own object `+0x50` |
| `0x608120D6` | Store the unsigned maximum of incoming argument and `+0x50` on this path |

The first two *runtime* copy sources reference an object pointer stored
at `0x2000A7EC`. Its live pointee/value is not measured. The list
above is **not an exhaustive whole-image writer inventory**, excluding
other offset forms, aliases, register-offset stores, DMA and other
firmware components.

## Exact initialization bound

At `0x60811590..0x608115A2`:

```asm
LDR    R6,[SP,#0x20]
CMP    R6,#15
IT     HS
MOVHS  R6,#15
STR    R6,[R4,#0x2C]
STRD   R6,R5,[R4,#0x50]
```

The condition `HS` means **unsigned >=**. Consequently, the local
constructor stores `min(input,15)` in `object+0x2C` and the same
initialized R6 in `object+0x50`. That proves a **constructor-local
0..15 bound**, not a global invariant across subsequent state changes.

## Later assignments and conditional guards

The route towards `0x60811F90` checks an index relationship with a
`CMP/BHS` pair at `0x60811F5A/5C`; the alternative
`0x60811FB2` path copies a reference-object index. In
`0x60812050/56`, the object `+0x50` value is loaded and
stored to `+0x2C`.

On the update path, `0x6081208E` copies incoming R1 to R5.
`0x608120A6/A8/AA/AC` loads `object+0x50`, compares unsigned
and conditionally sets R5 to it, resulting in a **local unsigned max**
that is stored at `0x608120D6`, if the intervening control path is
taken. This region alone does **not** bound both operands to 15.
Upstream restrictions and other state invariants are still unknown.

## What this does *not* show

The phase-28 indexed heads use `0x2000A7F8+20×index`. We still do
not know the allocated bucket count or prove that *every* runtime
index remains in 0..15. Additional callgraph and field-provenance
work is necessary before assessing memory safety.

**No out-of-bounds access, memory corruption, externally controlled
index, callback replacement, host USB-to-flash path, HAB CLOSED bypass
or custom firmware execution has been demonstrated.**

## Reproduction

```sh
python tools/audit_bucket_index_writers.py local/bootloader-a.bin --out local/phase29.json
python -m unittest discover -s tests -v
```

The analyzer checks the whole-image SHA-256, four region fingerprints,
machine-code anchors and a bounded raw Thumb16 store census. CI tests
use **synthetic images only**, without the proprietary bootloader.

**Phase 30:** trace assignment and provenance of `object+0x50`,
the reference object through `0x2000A7EC`, and the incoming update
argument before asserting any unsafe index path.
