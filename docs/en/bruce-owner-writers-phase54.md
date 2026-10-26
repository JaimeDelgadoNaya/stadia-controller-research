# Phase 54 — Bounded interprocedural USB owner writer search with positive controls

**26 October 2026 · original SHA-256-pinned signed Bruce OEM update**. Offline analysis only, no device USB, flash or eFuse writes.

## Result: two signed positive controls, no attributed target-field writers

The auditor extends the 11 verified PC-relative loads of `owner=0x2000A2A8` with known-register alias propagation, bounded Thumb direct branches, calls and literal veneers. It recovered **zero attributable possible stores** to the sought fields within its scope:

| Live RAM field address | Interpretation | Bounded signed-code candidates |
|---|---|---|
| `0x2000A2AC` | `owner+4`: runtime class array pointer | 0 |
| `0x2000A2B0` | `owner+8`: configuration method pointer | 0 |
| `0x2000A2B4` | `owner+12`: class count | 0 |

**This is not proof of writer absence.** The search starts only from 11 original owner literal loads, has an interprocedural depth of 2, a window limit of `0x200` bytes and 10,000 states per seed. The `0x60071416` seed **exhausted its budget** at state 10,001. Unknown indirect calls, predicated code, incomplete CFG and runtime producer paths remain untracked.

## Validated signed-code positive controls

A fail-closed verification requires the tool to rediscover two original stores to the **known different** field `owner+0x90=0x2000A338`:

- `0x60061022 STR.W R7,[R4,#0x90]`: resolves R7=1 from `0x6006101C`.
- `0x60061070 STR.W R5,[R4,#0x90]`: resolves the effective **destination**, not the current R5 value; it stays **UNKNOWN**.

Both have the context `0x60071416 → 0x6007141C → 0x60060FE8`. These are **signed possible code paths**, **not physical execution or real RAM snapshots**. Original binary verification passes in GitHub Actions.

## Scope and next avenue

Register values are derived only from pinned XIP literals and conservative arithmetic. The tool invalidates caller-saved registers after unmodelled calls and restored registers after POP/LDM; it stops at indirect returns and unmodelled IT/table jumps. Unknown conditions explore both sides and therefore cannot establish feasibility.

The open question remains the producer of `owner+4/+8/+12`: follow constructors or indirect producer argument flows *backwards*, or use strictly passive read-only USB descriptor observation as **indirect** evidence of a selected configuration. Descriptors cannot prove the RAM layout.

No runtime class10 selection, host-controllable code pointer, unsigned code execution or HAB CLOSED bypass has been established.

## Reproduction

```bash
python -m unittest tests.test_bruce_owner_writers_phase54 -v
python -m tools.audit_bruce_owner_writers_phase54 local/bruce_pvt_a_prod_signed.bin --out local/phase54-writers.json
```

Required original OEM SHA-256: `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.

[Structured evidence](../../evidence/bruce-owner-writers-phase54.json) · [Verified original CI run](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40344287059).
