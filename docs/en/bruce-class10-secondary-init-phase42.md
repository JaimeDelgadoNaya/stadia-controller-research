# Phase 42 — Signed class-10 secondary callback initializer and alias boundaries

**2026-10-26 · PR #44 · Exact SHA-pinned signed OEM Bruce update archive, offline only.**

## New verified conditional setter

The class-10 OEM handler at `0x600613FC` reads a secondary function pointer at `0x20009EF8` and context at `0x20009EFC`, comparing the pointer to the signed sentinel **`0x600D4F05`**. The corresponding function at `0x600D4F04` is `MOV.W R0,#0; BX LR`, returning zero.

The original signed initializer at `0x60073BF0` contains the following independently verified instructions:

| PC | Signed instruction | Meaning |
|---|---|---|
| `0x60073BF4` | `MOV R4,R0` | Preserve caller-supplied base |
| `0x60073C0C` | `MOVS R5,#0` | Set zero |
| `0x60073CE6` | `LDR R1,[PC,#0x13C]` | Load signed `0x600D4F05` from `0x60073E24` |
| `0x60073CEA` | `MOVW R3,#0x3A38` | Callback offset |
| `0x60073CF2` | `ADDS R2,R4,R3` | Pointer arithmetic |
| `0x60073CF4` | `STR R1,[R4,R3]` | `base+0x3A38 = sentinel` |
| `0x60073CFC` | `STR R5,[R2,#4]` | `base+0x3A3C = 0` |

**Condition:** only if the caller supplies `R0=0x200064C0`, the writes target exactly `0x20009EF8` and `0x20009EFC`. The bounded signed-XIP direct-BL census found **no direct callers** of `0x60073BF0`, and no aligned literal equal to its Thumb function pointer `0x60073BF1`. **Actual invocation, runtime R0, and live RAM values remain unverified.** This conditional setter does **not** demonstrate a host-controlled callback or execution of unsigned code.

If this constructor is executed with that base and the values remain unchanged, the existing comparison against the sentinel would skip the secondary call. Later setters and live EP0 routing are still unknown.

## Nine offset-shaped candidate stores from phase 41

All nine original site instructions were checked with an alignment-aware, bounded Thumb window audit. **Five** derive the base from indirect object pointers held in `[R7+field]`, **three** retain an unknown base after local control-flow boundaries, and one constructor store has a concrete non-aliasing direct call.

That last case is `0x60058846: STRB R5,[R4,#0xFC]`, where the original direct caller at `0x60058926` passes `R0=0x20015E74` (loaded at `0x60058914` from literal `0x60058A44`). The callee copies R0 into R4, so this **particular direct-call path** writes to `0x20015F70`, not the class-10 fields. Indirect callers are not ruled out.

The full nine-site table, disassembly caveats and reproducibility commands are in the [Spanish report](../es/bruce-inicializador-callback-fase42.md). The original image is a **signed update archive, not a full byte-identical installed-flash readback**.

## Next decision gate

Recover the actual call path into `0x60073BF0` and establish its first argument. Next, trace any subsequent writers and the source of their values; only a proven host-to-writer chain can justify an execution hypothesis. The device has not been accessed or modified. No HAB CLOSED bypass, custom firmware execution, recovery guarantee, or native Xbox/Switch 2 support exists.

Reproduce:

```bash
python -m unittest tests.test_bruce_secondary_alias_phase42 tests.test_bruce_class10_secondary_init_phase42 -v
python -m tools.audit_bruce_secondary_alias_phase42 local/bruce_pvt_a_prod_signed.bin
python -m tools.audit_bruce_class10_secondary_init_phase42 local/bruce_pvt_a_prod_signed.bin
```

[Original image GitHub Actions verification](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40301594977).
