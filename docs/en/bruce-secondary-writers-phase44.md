# Phase 44 — Original signed second callback setter and 13-way dispatch

**2026-10-26 · PR #46 · Offline, exact SHA-pinned Bruce OEM signed update image only.**

## Confirmed second callback setter

The original signed image contains a second function that writes to the **exact same class-10 secondary RAM slots** initialized to a no-op sentinel in phase 43:

- `0x600771EE` loads the PC-relative signed literal **`0x200064C0`** from `0x600772E4`.
- `0x600771F0` loads signed Thumb function pointer **`0x600DB029`** from `0x600772E8`.
- `0x600771F2` builds offset `0x3A38`; `0x600771F6` writes **`0x600DB029` → `0x20009EF8`**.
- `0x600771F8` builds offset `0x3A3C`; `0x600771FC` writes **R4 → `0x20009EFC`**.
- Function `0x600DB028` starts with a signed `B.W 0x60077360`, not a host-supplied code pointer.

A signed direct caller at `0x60051240` invokes getter `0x60077138` (via `BL` at `0x60051248`), then the setter `0x60077140` (via `BL` at `0x6005124C`). The getter returns a signed literal **`0x20003670`** from `0x6007713C`. The setter preserves its R0 input into R4 at `0x60077144`.

The context object's address `0x20003670` lies inside the known startup data copy `0x20002740..0x20003FD8`. Its signed source file offset is `0xFE4D8`. The first original word is **`0x600D5637`**, followed by eleven zero words in the inspected *initial copy*. No runtime object contents have been measured.

The setter has branches and early-exit conditions before the store. **Its execution on a real controller is not demonstrated.** The exhaustive halfword-aligned direct-branch scan found caller `0x6005124C` but not a direct BL to `0x60051240`; indirect calls or tables remain possible.

## Original signed 13-case dispatch

The OEM function `0x60077360` transforms R1 with `SUBS R1,#0x80`, checks `CMP R1,#0xC` and dispatches via `TBB [PC,R1]`.

| R1 code | Signed handler target | R1 code | Signed handler target |
|---|---|---|---|
| `0x80` | `0x60077382` | `0x87` | `0x600773E0` |
| `0x81` | `0x60077392` | `0x88` | `0x60077406` |
| `0x82` | `0x6007739C` | `0x89` | `0x60077420` |
| `0x83` | `0x600773A4` | `0x8A` | `0x60077434` |
| `0x84` | `0x600773AE` | `0x8B` | `0x60077494` |
| `0x85` | `0x600773BA` | `0x8C` | `0x6007749A` |
| `0x86` | `0x600773C2` | — | — |

These are **code-path possibilities if the handler runs**, not proven physical USB EP0 requests. No arbitrary function-pointer install, host-controlled callback or unsigned-code execution has been demonstrated.

## Search coverage and remaining gates

The signed Thumb halfword-offset census found 2625 MOVW instructions from 2648 prefiltered candidates. Exactly **five** MOVW instruction sites used the matching offsets: two in the original class-10 reads, one in the no-op initializer and **two in this additional writer**. This is not an exhaustive memory-store proof: constants can also come from MOVT, ADD.W, memory, DMA and cross-function pointer aliases; decoding unreferenced bytes can produce false instructions.

**Next phase:** verify the early runtime/indirect caller of `0x60051240`, trace active USB EP0 parameter propagation into R1, and determine what each of the 13 signed cases can actually do. No direct console interoperability, HAB CLOSED bypass, custom firmware execution or recovery has been shown. No physical device has been connected or altered.

Reproduce:

```bash
python -m unittest tests.test_bruce_secondary_late_writers_phase44 tests.test_bruce_secondary_override_phase44 -v
python -m tools.audit_bruce_secondary_late_writers_phase44 local/bruce_pvt_a_prod_signed.bin
python -m tools.audit_bruce_secondary_override_phase44 local/bruce_pvt_a_prod_signed.bin
```

[Spanish full signed-instruction analysis](../es/bruce-callback-secundario-escritores-fase44.md) · [PR #46](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/46). The pinned OEM update image is **not** a full installed-flash readback.
