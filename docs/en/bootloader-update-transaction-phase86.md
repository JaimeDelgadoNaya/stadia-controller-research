# Phase 86 — Bootloader A update transaction: trust boundaries and recovery

**27 October 2026.** Fully offline audit of **selected previously published original Thumb instructions** for bootloader A build **169429** (owner-extracted SHA-256 provenance: `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`). The owner-private raw binary was unavailable in this session: exact published opcode bytes/callsite edges are verified, **not an independent whole-binary rehash**.

**Key finding:** the signed OEM update coordinator may attempt to **install a 4096-byte candidate IVT before final HAB authentication** of that candidate. This is a *write-before-final-check* interval, **not** an authorization for unsigned code. The same selected path authenticates the candidate after attempting installation and conditionally attempts restoration on failure; application boot has a separate authenticated handoff.

Pinned original stages:

1. Current bootloader authentication (`0x60801E00/02`, `r1=1`).
2. Candidate structural-only validation (`0x60801E26/28`, `r1=0` derived from the successful prior return).
3. Existing IVT 0x1000-byte backup and power/input callback (`0x60801E36–5C`).
4. Candidate IVT read and attempted fixed-length installation (`0x60801E62 → 0x60801D9C → 0x60801D40`); read error `0x0A` returns without installation.
5. Post-install candidate HAB authentication (`0x60801E80–8C`, `r1=1`).
6. Conditional attempt to restore the prior IVT (`0x60801E9A–A6`) after relevant write/auth errors; rollback can fail.

The original 0x12 storage descriptor conditionally maps the shared IVT to flash `0x60001000`. The [phase86 auditor](../../tools/audit_bootloader_update_transaction_phase86.py) validates **31 original instruction pins** and the existing [write-path checker](../../tools/trace_write_path.py), then models all **256 synthetic gate-result combinations**. [Regression tests](../../tests/test_bootloader_update_transaction_phase86.py) ensure failures do not masquerade as accepted authenticated updates.

**Important consequence:** there is no demonstrated power-loss atomicity or reliable rollback after an interrupted IVT write, and the observed B bootloader slot is erased. A call to a restore routine cannot guarantee restoration after a sudden power loss. There is no proven externally triggerable route, unsigned execution, HID/USB-to-flash bypass, modified-image boot, physical recovery or HAB version measurement.

**Provisional NO-GO** for experimenting with flash writes or malicious image inputs on the only physical controller. **GO** for further passive/static analysis of update input provenance and storage backend restrictions only when backed by original signed code and a safe recovery criterion.

```sh
python -m unittest tests/test_bootloader_update_transaction_phase86.py -v
python -m tools.audit_bootloader_update_transaction_phase86
```

[Sanitized evidence](../../evidence/bootloader-update-transaction-phase86.json) · [Original instruction corpus](../../evidence/bootloader-analysis.json) · [PR #95](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/95).

No device, flash, RAM, ROM API or OTP operation was performed.
