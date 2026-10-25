# Phase 20 — Bounded census of possible USB callback writers

**Verified image:** Stadia bootloader A build 169429, 131,072 bytes,
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
All analysis is **offline**, with no controller I/O and no proprietary
binary checked into Git.

Phase 19 documented four normal-startup fields relative to RAM aggregate
`0x20008B78`: bulk IN handler at `+0x5F8` (`0x20009170`),
IN context at `+0x5FC`, bulk OUT handler at `+0x600`
(`0x20009178`), OUT context at `+0x604`.
Both handlers initially point to `BX LR` return-only stubs.

## Verified pattern-search result

The new `tools/audit_callback_writers.py` scans the **halfword-aligned
bytes**, not an established whole-program control-flow graph, within
`0x60801000..0x60814F00` (end-exclusive). It searches for the
Thumb-2 `STR.W Rt,[Rn,#imm12]` positive-immediate encoding, regardless
of source/base register:

| Positive immediate | Raw candidate addresses |
|---|---|
| `0x5F8` | Only `0x6080BB50` (constructor) |
| `0x5FC` | Only `0x6080BB6C` (constructor) |
| `0x600` | Only `0x6080BB5A` (constructor) |
| `0x604` | Only `0x6080BB70` (constructor) |

An aligned full-image search also finds **zero 32-bit absolute pointers**
to the four RAM callback/context addresses.

A second limited search in `0x60809E24..0x6080A076` for
Thumb16 word `STR` and Thumb-2 positive-immediate `STR.W`
using vendor-object offsets `+0x10,+0x14,+0x18,+0x1C`
finds **no candidates of those forms**.

**Interpretation:** no further setter has been identified using these
specific encodings/intervals. This **does not rule out** stores via
register-offset/alias pointer, `STRD/STM`, different base registers,
additional code paths, DMA or callbacks registered by other firmware
components. Linear halfword pattern matching can also match data.
The results are **not** complete disassembly, reachability proof, or
evidence that firmware updates are impossible.

## Reproduce without hardware

```sh
python tools/audit_callback_writers.py local/bootloader-a.bin --out local/phase20.json
python -m unittest discover -s tests -v
```

The CLI checks the exact known whole-image SHA-256 and constructor
machine-code anchors. CI uses synthetic images and deliberately injected
alternative STR encodings for regression tests. No USB transfers, flash
writes or device resets are performed.

**Next:** phase 21 should trace aliases and possible setter functions
using pointer/data-flow provenance. There is still no proven host USB
command parser leading to the flash writer, no HAB CLOSED bypass, and
no custom firmware execution.
