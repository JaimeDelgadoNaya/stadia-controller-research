# Phase 27 — List insertion routines and bounded pointer-field store census

**Image:** private 128-KiB Stadia bootloader A, build 169429, SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
Entirely offline; no device access, flash write, eFuse operation or proprietary binary publication.

## Two complementary list insertion routines

Phase 25 identified list removal at `0x608109FE`. Phase 27 verifies:

| Routine | Recognizable operation | Verified static edges |
|---|---|---|
| `0x608109B8` | Insert node at the front of a doubly-linked list | **9 direct `BL` calls** |
| `0x608109D0` | Compare keys and traverse to insert in ordering | **4 direct `BL` calls**, **1 direct `B.W` tail branch** |

All **14** selected direct edges were independently decoded from the
SHA-matched original Thumb instructions. These counts describe the verified
inventory, **not** a proof of exhaustive callgraph completeness.

At `0x608109B8`, R0 is the list head and R1 the node. The routine
updates the new node's `+4/+8` links, the neighbors' reciprocal
links, stores `node+0x10=head`, and increments `head+0` count.
At `0x608109D0`, comparisons against node keys determine insertion
position before applying link updates and incrementing the count.

## Two indexed bucket insertion callsites

The caller instructions at `0x60811A32` and `0x60811E0C` each compute
an R0 destination using `MLA` with base literal **`0x2000A7F8`**
and a **0x14-byte stride**:

`head = 0x2000A7F8 + 20 * index`

These bucket heads differ in starting address from the conditional
phase-26 self-referential initial heads `0x20009114` and
`0x20009128`. Runtime index values and range checks are **not**
proven here, and other insertion callsites cannot be assumed to share
one head domain.

## Narrow re-assignment search for two RAM fields

A halfword-aligned positive-immediate Thumb-2 `STR.W Rt,[Rn,#imm12]`
scan of `0x60801000..0x60814F00` gives:

| Field | Raw encoding site |
|---|---|
| `global+0x560 = 0x200090D8` | Only `0x6080BAEC` |
| `global+0x568 = 0x200090E0` | Only `0x6080BAF2` |

These are the original constructor writes, initializing both fields to
`global+0x134 = 0x20008CAC`.

**No later reassignment has been demonstrated, nor ruled out.**
Stores via computed pointers, alternate offsets, `STRD/STM`,
additional modules, or runtime code paths are not exhaustively
examined. No host USB reachability or security bypass is inferred.

## Reproduce safely

```sh
python tools/audit_list_insertion_paths.py local/bootloader-a.bin --out local/phase27.json
python -m unittest discover -s tests -v
```

The tool checks whole-image SHA-256, five regional fingerprints, list
instruction anchors, the 14 direct transfer edges, and indexed head
base literals. CI uses synthetic images only; no proprietary bootloader
is committed.

**Phase 28:** scope the provenance of the inserted nodes and the
validations around bucket indexes. USB-to-flash and HAB CLOSED bypass
remain unproven.
