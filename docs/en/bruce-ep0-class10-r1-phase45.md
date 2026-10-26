# Phase 45 — Conditional signed bRequest path into Bruce class-10 dispatch

**26 October 2026 · PR #47 · Offline inspection of the SHA-256 pinned signed OEM Bruce update image.**

## Verified signed path, with explicit runtime prerequisites

The original class registry entry at `0x60104BA4` has selector **10** and class-event method pointer **`0x600D0E59`**. The signed initialized RAM data contains the class-10 configuration record at **`0x200030F4`**, whose callback word is **`0x600613FD`**.

The original class forwarder at `0x600D0E58` checks `bmRequestType & 0x1F == 1` (interface recipient), then compares `SETUP[4]` with the class-object byte at offset `+0x0D`. It executes `0x600D0EB8: LDRB R1,[R1,#1]` to place the candidate `bRequest` byte in R1 and tail-dispatches with `0x600D0EBE: BX R3`, whose destination comes from the selected class record.

**If** the signed class-10 function at `0x600613FC` is the selected target, it requires `R1 > 0x7F`. **If** the secondary callback RAM word has been set to the independently verified signed OEM value **`0x600DB029`** (rather than boot default sentinel `0x600D4F05`), `0x60061416: BLX R3` conditionally invokes that callback, with R1 unchanged. The OEM callback branches to `0x60077360`, where R1 is reduced by `0x80`, checked against `0x0C`, then used as the original `TBB` case index.

**This is a static, instruction-validated conditional argument path, not a verified physical USB1 EP0-to-class-10 execution path.** We have not shown that an actual device selects this class or activates the second handler.

## Signed code handling of interesting cases

All 13 original branch-table entries, `0x80..0x8C`, are decoded independently from real Thumb destinations (not the inline jump-table data).

| Candidate R1 | Locally verified original behavior, assuming this code runs |
|---|---|
| `0x81` | Derive `context+0x190`, store in response-like `R2+4`, use response tag 8 |
| `0x83` | Derive `context+0x12C`, clear `[R2+8]`, branch to signed common routine |
| `0x84` | Derive `context+0x1D8`, store in `[R2+4]`, use response tag 2 |
| `0x8B` | Call original signed function `0x60077744` |
| `0x8C` | Call signed functions `0x60077720` and `0x60077730`, store results at `context+0x198` and `context+4`, reuse response block from case `0x81` |

The local `0x81/0x83/0x84` code does **not** show an incoming arbitrary callback pointer being written directly to the global callback slot. This limited observation neither excludes indirect paths nor constitutes proof of security.

## Synthetic guard matrix

- Recipient `0x20` or `0x22`: fails the interface recipient check; `0x21` and `0xA1` satisfy *only that check*.
- An interface mismatch fails before the class callback.
- Candidate request `0x7F`: rejected by first signed callback; `0x80..0x8C`: has signed case targets if all other guards pass; `0x8D` or `0xFF`: passes the first guard but fails the 13-case range.
- With the boot-default signed sentinel, there is no delegation to the second handler.

All matrix examples are **synthetic**; there are no USB packets, device writes, firmware replacement or HAB CLOSED bypass attempts.

## What remains

Prove the actual USB1 IRQ/EP0 SETUP ingestion to class forwarder `0x600D0E58`, class-10 selection, the conditions under which the signed setter activates, and the effects of deeper signed callees. Only then would investigating an actual host-controlled action be warranted.

Reproduce:

```bash
python -m unittest tests.test_bruce_ep0_class10_bridge_phase45 tests.test_bruce_class10_case_effects_phase45 -v
python -m tools.audit_bruce_ep0_class10_bridge_phase45 local/bruce_pvt_a_prod_signed.bin
python -m tools.audit_bruce_class10_case_effects_phase45 local/bruce_pvt_a_prod_signed.bin
```

[Detailed Spanish audit](../es/bruce-ep0-clase10-r1-fase45.md) · [PR #47](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/47).
