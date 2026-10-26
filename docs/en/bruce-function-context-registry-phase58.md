# Phase 58 — Signed +0x80 consumer leads to a global function/context pair

**26 October 2026.** Offline static inspection of original SHA-256-pinned Bruce signed OEM update (`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`). No live hardware RAM, USB requests, flash or eFuse writes.

## Key result: original owner-derived R0 is not directly passed to the backend

Phase 57 established a conditional producer/global/reader chain reaching `0x6007E794` and reading `[object+0x80]`. Both original signed branches then call `0x600D54B8` (`0x6007E7FA`, `0x6007E81E`).

Six original signed instruction pins establish that `0x600D54B8` stages incoming **R1/R2** on the stack, reloads them into **R0/R1**, and tail-branches to `0x6006386C`. The incoming **R0**, even though previously loaded from `object+0x80`, is **not passed as the backend's R0**.

Ten additional pinned original instructions in `0x6006386C` show a global pair store, whose base literal at `0x60063888` is exactly `0x2000F878`:

| Destination SRAM address | Branch at 0x6007E7FA | Branch at 0x6007E81E |
|---|---|---|
| `0x2000FBF4 = base+0x37C` | `0x600CE233` | `0x0000A9C5` |
| `0x2000FBF8 = base+0x380` | `0` | Incoming object pointer R4 |

The literal values are original signed data from `0x6007E824` and `0x6007E828`, not live RAM. Both are odd Thumb function-pointer shaped values. Original target-code entry pins resolve to:

- `0x600CE232` in signed XIP: **`BX LR`**, immediate no-op return.
- `0x0000A9C4` in startup-relocated ITCM: **`B.W 0xB980`**, a tail branch to additional ITCM functionality.

This is **consistent with installing a callback/context pair and choosing between a no-op and an object-dependent worker**, but **not proof** that those words are ever read, invoked, USB-bound, host-controlled or active at runtime.

## What this settles and what it does not

The helper is an **argument adapter** followed by a **global two-word store**, not a demonstrated live class registration. The second route still passes the object itself as context R4, which may be related to owner indirectly, but no direct host-controlled callback is established.

Two direct signed `BL` shapes to the adapter were found in the bounded original scan. That is not an exhaustive reachable call graph.

**Next phase 59:** identify all possible **readers and indirect invocation paths** of `0x2000FBF4/0x2000FBF8` and audit the ITCM worker at `0xB980`, checking if any path has an actual original USB host request provenance. If that bridge cannot be proved, this branch should not be considered a firmware-execution avenue.

Live USB config `owner+4/+8/+12`, active class10, custom firmware execution and HAB CLOSED bypass remain unproven.

## Reproduce

```bash
python -m unittest tests.test_bruce_field80_helper_phase58 -v
python -m tools.audit_bruce_field80_helper_phase58 local/bruce_pvt_a_prod_signed.bin --out local/phase58-helper.json
```

[Original OEM GitHub Actions verification](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40364601068) · [Structured evidence](../../evidence/bruce-field80-helper-phase58.json).
