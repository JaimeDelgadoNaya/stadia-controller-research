# Phase 26 — Initial pointers and self-referential list heads

**Image:** privately held 128-KiB Stadia bootloader A, build 169429,
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
Research remains offline and does not access or modify the device.

## Two initialized pointer fields

The global constructor at `0x6080BAC0` maintains base `0x20008B78`
in R4. At `0x6080BAE2` it calculates `R3=R4+0x134` and stores
that same pointer at two fields:

| Instruction | RAM field | Initial value |
|---|---|---|
| `0x6080BAEC` | `global+0x560 = 0x200090D8` | `0x20008CAC` |
| `0x6080BAF2` | `global+0x568 = 0x200090E0` | `0x20008CAC` |
| `0x6080BAE8` | `global+0x570 = 0x200090E8` | **One zero byte** |

**Correction to provisional Phase-24/25 notes:** `global+0x570` was
listed as a possible third pointer source. The constructor actually
uses **STRB.W** to initialize this as a byte. There is no evidence
it holds a third independent 32-bit object pointer.

The initial value supplied to the transfer-like routine `0x60809048`
from the first two fields is therefore `0x20008CAC` **if unchanged
since construction**. Its derived `input+0x6C/+0xA4/+0xF8` and
read offsets `+0x154/+0x158/+0x15C` initially fall between
`0x20008D18` and `0x20008E08`, below the callback fields
`0x20009170/74/78/7C`. This does not rule out later pointer
replacement or effects inside callees.

## Two sentinel/list head initializers

In the nonzero-flag path, `0x60810B38` calls `0x6081099C`
twice with `R0=global+0x59C` and `R0=global+0x5B0`
(`0x20009114` and `0x20009128`). Direct BL sites are
`0x60810B9C` and `0x60810BA4`.

That function initializes each head H with:

| Field | Initial contents |
|---|---|
| `[H+0]` | 0 |
| `[H+4]` | `H+8` |
| `[H+8]` | `0xFFFFFFFF` sentinel, **not** a pointer |
| `[H+12]` | `H+8` |
| `[H+16]` | `H+8` |

The constructor route at `0x60810C06` sets `R1=1` before
calling `0x60810B38` from `0x60810C1A`, so the list-head
initialization is supported for that conditional startup path.
Later link mutations are possible and live RAM was not measured.

## Scope and reproducibility

The offline `tools/audit_pointer_initializers.py` verifies whole-image
SHA-256, five code-region SHA fingerprints, opcode anchors, BL edges,
and a bounded positive-immediate `STR.W` census for `+0x560/+0x568`.
No whole-program pointer alias or USB reachability proof is claimed.

```sh
python tools/audit_pointer_initializers.py local/bootloader-a.bin --out local/phase26.json
python -m unittest discover -s tests -v
```

CI contains synthetic tests only. No firmware binary, USB traffic, flash
write, eFuse operation, HAB CLOSED bypass or custom execution is involved.

**Next:** investigate later reassignments and dynamic node allocation
before asserting a host-controlled route.
