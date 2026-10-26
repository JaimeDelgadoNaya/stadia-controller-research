# Phase 43 — Signed early startup to class-10 secondary callback initialization

**26 October 2026 · PR #45 · Exact OEM signed Bruce update archive, offline only.**

## Verified static chain

The previous chunk-linear XIP scan missed a valid `BL` because embedded literals can disrupt disassembly alignment. Scanning potential Thumb branch opcodes at every halfword position, then independently validating the original instructions, established:

1. Early signed code `0x6004C742` calls the constructor-array walker at **`0x600CDB74`**.
2. The walker uses signed table bounds `0x6013D4F0` to `0x6013D5A4` (**45 entries**), and loads/calls pointers via `0x600CDBA2 LDR.W` and `0x600CDBA6 BLX R3`.
3. Table entry **21 (zero-based)** at `0x6013D544` holds Thumb pointer `0x600748ED`.
4. That wrapper, at `0x600748EC`, loads original literal **`0x200064C0`** from `0x60074904` and calls `0x60073BF0` at `0x600748F2`.
5. The verified signed initializer stores a no-op sentinel **`0x600D4F05`** at `base+0x3A38 = 0x20009EF8` and zero at `base+0x3A3C = 0x20009EFC`. The signed class-10 handler later tests the sentinel before a potential indirect callback.

This is a fully linked **static chain in the signed update image**, not an actual device execution trace. The physical flash identity, real startup path, runtime RAM contents, later writers and live USB EP0 request route remain unverified. The sentinel does not confer custom execution, HAB CLOSED bypass, recovery or Xbox/Switch 2 compatibility.

The identified constructor table excludes adjacent words at `0x6013D4EC` and `0x6013D5A4`; the earlier shape-only scanner grouped them with 45 actual table entries. The original XIP Thumb-caller census in phase 42 was incomplete, not proof of no caller.

## Reproduction

```bash
python -m unittest tests.test_bruce_init_inbound_phase43 tests.test_bruce_init_table_phase43 -v
python -m tools.audit_bruce_init_inbound_phase43 local/bruce_pvt_a_prod_signed.bin
python -m tools.audit_bruce_init_table_phase43 local/bruce_pvt_a_prod_signed.bin
```

[Detailed Spanish evidence and instruction addresses](../es/bruce-arranque-inicializador-fase43.md) · [PR #45](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/45). Neither script accesses a USB controller or changes firmware.
