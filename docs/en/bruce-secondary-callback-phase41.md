# Phase 41 — Signed Bruce class-10 secondary callback-slot audit

**2026-10-26 · PR #43 · Offline analysis of the exact signed OEM update archive only.**

## Verified results

Phase 40 established that signed function `0x600613FC` reads a secondary callback word at **`0x20009EF8`** and a context word at **`0x20009EFC`** for request codes greater than `0x7F`, with a guarded `BLX R3`. The live EP0 request path and installer of the secondary word are still unknown.

`tools/audit_bruce_secondary_registry.py` requires the exact signed Bruce image SHA-256 (`466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`). It performs a bounded linear Thumb sweep over XIP and startup-relocated ITCM, and an additional decode at the independently pinned class-10 callback entry. Its register-constant propagation is **not** an interprocedural control-flow proof.

| Observation | Result |
|---|---:|
| Linearly decoded instructions, including focused-window overlap | 180,127 |
| Statically resolved candidate accesses to target words | **1 read, 0 writes** |
| Known original read | `0x6006140A: LDR R3,[R0,R3]` → `0x20009EF8` |
| Aligned literal words equal to `0x20009EF8 / 0x20009EFC` | **0 / 0** |
| Aligned literal words equal to global base `0x200064C0` | 58 |
| Aligned literal words equal to nearby object base `0x20009E00` | 3 |
| Recognized PC-relative literal loads of those bases | 4 |
| Offset-shaped stores (`+0xF8/+0xFC/+0x3A38/+0x3A3C`) | 24 |

The known boot-time initialized-data copy is `0x20002740..0x20003FD8`. The two secondary slots lie **outside that particular copy**; their actual runtime initialization and values remain unknown.

Of the 24 offset-shaped stores, **12** use SP as base, **3** resolve to the unrelated address `0x20026160`, and **9** have unresolved non-stack base registers. These nine instruction PCs are `0x60058846`, `0x600A4FF2`, `0x600A54F4`, `0x600D574E`, `0x600DDB84`, `0x600EBD86`, `0x600F1C60`, `0x600F4E44`, `0x600FF9EC`.

An offset `+0xF8` is **not evidence** that the base equals `0x20009E00`. Linear code sweeps may decode inline data or miss valid call paths, while indirect stores, later initialization, DMA and dynamically computed aliases are outside the model.

## Next decision gate

1. Establish real function boundaries and callers for the nine unresolved sites; reject data-as-code false positives.
2. Trace the base register provenance across calls before linking any site to the class-10 object.
3. If a concrete writer emerges, trace its **stored value** and host-input reachability. A signed OEM callback setter does not alone establish custom execution.
4. Separate active EP0 registration, signed-boot acceptance and reliable hardware recovery before considering physical tests.

**Current outcome:** no direct statically resolved writer was found by this bounded model. This neither proves the slot immutable nor demonstrates host control, a HAB CLOSED bypass, installable custom firmware or native Xbox/Switch 2 support.

Reproduce locally with:

```bash
python -m unittest tests.test_bruce_secondary_registry -v
python -m tools.audit_bruce_secondary_registry local/bruce_pvt_a_prod_signed.bin --out local/phase41.json
```

[SHA-pinned original-image CI result](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40298495926). CI deletes downloaded OEM binaries and reports after execution. No physical controller USB operations or flash writes occur. The signed update archive is **not** verified as a full readback of the installed firmware.
