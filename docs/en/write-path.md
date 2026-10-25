# Phase 12 — Reproducible IVT writer call-path audit

**Scope:** bootloader A build 169429, SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`. This is an **offline** analysis of *selected* instruction ranges in `evidence/bootloader-analysis.json`; it is not a whole-firmware audit.

`tools/trace_write_path.py` verifies direct calls, selected instruction anchors and virtual-table entries against the public disassembly record. No proprietary binary or controller connection is needed.

For the **constructed IVT descriptor `0x12`** from phase 11, the supported path is:

```text
0x6080285C --BL at 0x608028C6--> 0x60801ED0
0x60801ED0 --BL at 0x60801EE4--> 0x60801DD4
0x60801DD4 --BL at 0x60801E62--> 0x60801D9C
0x60801D9C --BL at 0x60801DC0--> 0x60801D40
0x60801D40 --BLX R4 at 0x60801D98--> 0x6080B0F0 (conditional: 0x60815300, slot 2)
0x6080B0F0 --BX IP at 0x6080B132--> 0x60808E38 (conditional: 0x60815320, slot 6)
```

The last two targets require a **specific reconstructed storage object**, not generic indirect-call resolution. The writer checks its range through `0x6080AA7C`. The reviewed IVT caller uses a **fixed zero offset** and **4096-byte length**. No externally controlled path to the synthetic wrapped-offset case from phase 11 has been established.

## Reproduce

```sh
python tools/trace_write_path.py > phase12-report.json
python -m unittest discover -s tests -v
```

The report lists targets outside the selected disassembly and indirect calls not generically resolved. **External input reachability, flash impact, signature bypass and custom-firmware execution remain unproven.** The SHA recorded in public evidence documents provenance; the original raw image is needed for independent hash verification.

## Next boundary

Trace a verified USB command dispatcher and actual argument provenance before assessing reachability to storage methods. Separately reconstruct boot-selection and rollback states before proposing a hardware experiment. Do not flash unverified firmware.
