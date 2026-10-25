# FillMemory — 32-bit end-address wrap versus actual memory effects

**25 October 2026, offline-only review.** This analysis uses the exact original
signed Stadia RAM loader (100,672 bytes, SHA-256
`c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`)
and does not connect to hardware, send HID packets or modify memory.

## Confirmed code path

1. FillMemory handler `0x20003380` dispatches to `0x20003C86`.
2. The operation-0 whitelist in `0x200039A8` first checks the address
   against a minimum, then a *32-bit computed end address* against the
   maximum. There is no explicit non-wrap comparison in this block.
3. The dynamic protection function `0x20003B30` checks additional ranges
   derived from runtime RAM state; their actual values have not been measured.
4. The region-map function `0x200039F4` also uses a 32-bit computed end
   address and its comparisons can accept an end less than the start.
5. The RAM and peripheral FillMemory backends `0x20003D06` and
   `0x20003942` forward to `0x20002698`. This function performs
   **repeated memory writes** over the requested byte count, rather than
   a single write based on the wrapped end address.

The synthetic, original-instruction-anchored model
`tools/audit_fillmemory_wrap_model.py` finds arithmetic scenarios
that pass **both initial range tests** for the execution-table fields.
That is a **partial precheck finding**, not proof of a permitted
memory write. The dynamic protected-region check is unresolved, and
the implied very large fill would leave the loader's declared RAM
region `0x20000000..0x2001FFFF` far before completion.

## What this does not establish

- No verified acceptance by the dynamic protected-region check.
- No demonstrated write to restricted command-table memory.
- No return from a large fill with intact execution state.
- No custom code execution, HAB CLOSED bypass, or safe recovery.

Therefore this is **not a working exploit or a firmware-install route**.

## Reproduce without touching the controller

```sh
python -m unittest tests.test_fillmemory_wrap_model -v
python -m tools.audit_fillmemory_overflow local/restricted_ivt_flashloader.bin --print-disassembly
python -m tools.audit_fillmemory_wrap_model local/restricted_ivt_flashloader.bin --out local/fillmemory-wrap.json
```

[Original-image CI validation](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40234757038)

Next justified step: identify actual dynamic protection range initialization,
then emulate bounded effects of the FillMemory backend. Do not try this
against the only physical controller without independently validated recovery.
