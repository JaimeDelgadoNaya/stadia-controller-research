# Phase 28 — Provenance of nodes and bucket indexes

**Private image:** Stadia bootloader A build 169429, 131072 bytes,
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
All analysis is **offline** with no controller I/O, flash programming,
eFuse changes or proprietary binary publication.

## Two embedded-node insertion paths

The examined calls to the front insertion routine `0x608109B8`
pass nodes that are **embedded at offset +4 within larger objects**.

| | Route A | Route B |
|---|---|---|
| Insertion call | `0x60811A32` | `0x60811E0C` |
| Main object | `R6` from two pointer dereferences | `R4 = [[incoming R0+0xC]+0xC]` |
| Node | `R6+4` held in `R8` | `R4+4` held in `R5` |
| Index field | `[R6+0x2C]` | `[R4+0x2C]` |
| Bucket `MLA` | `0x60811A2E` | `0x60811E08` |

Both calculate `head = 0x2000A7F8 + 20 * index` using a Thumb
multiply-accumulate instruction. This is address arithmetic, **not an
index validity check**. Object addresses and runtime index values have
not been observed.

Route A resolves `R2=[R10]`, then `R2=[R2+0xC]`,
then `R6=[R2+0xC]`. At `0x608119FE`, `R8=R6+4`.
The code loads the index at `0x60811A14`, prepares the embedded
node `R1=R8`, computes the bucket head and calls insertion.

Route B resolves `R3=[incoming R0+0xC]`,
`R4=[R3+0xC]`; it computes `R5=R4+4` at
`0x60811DEC`, loads the index at `0x60811DF6`,
and calls insertion with `R1=R5`.

## Guard and comparison scope

Route A compares reloaded values at `0x60811A3C`;
route B compares reloaded values at `0x60811E18`.
**Both comparisons are located after the corresponding insertion
call**, and cannot alone serve as validation before that call.

A specific pre-insertion bucket-index bounds check is **not identified
in the selected local instruction windows**. This is **not** proof that
earlier callers, object constructors or state invariants impose no
valid range. Route A already accesses indexed table state earlier
in its enclosing routine. The array's element count and actual index
bounds are unknown.

**No out-of-bounds access, memory corruption, host-controllable index
or exploitable vulnerability has been demonstrated.** Neither host USB
reachability nor callback modification or HAB bypass is established.

## Reproduction

The read-only `tools/audit_bucket_node_provenance.py` requires the exact
whole-image SHA-256, four regional fingerprints, instruction anchors,
two bucket-base literal words and decoded direct BL targets. The
verification scope is narrow; CI tests use only synthetic data.

```sh
python tools/audit_bucket_node_provenance.py local/bootloader-a.bin --out local/phase28.json
python -m unittest discover -s tests -v
```

**Next (phase 29):** inspect provenance and any domain constraints on
the objects' `+0x2C` index, including their construction and upstream
callers, before drawing conclusions about address safety.
