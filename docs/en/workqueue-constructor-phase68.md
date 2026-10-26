# Phase 68 — Original work-queue constructor and auxiliary fields

**26 October 2026.** Offline exact Bruce OEM SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`, continuing [phase 67](pending-workqueue-call-phase67.md).

## Result

Original constructor **`0x600926D0`** is identified and executed to establish the fields of object **`0x2002014C`** consumed by phase67's pending call. Auxiliary pointer/size values now come from original OEM stores rather than auditor-selected fixtures.

The constructor clears the handle and supplies auxiliary structure **`0x20020278`**, size word **`0x200`**, buffer pointer **`0x2002034C`**. These fields pass the original creation-path guards; actual creation still uses an explicit opaque-return model. Physical constructor execution and a running task are not established.

## Signed initializer-table linkage

File offset **`0xFD59C`** holds Thumb pointer **`0x600926D1`**, zero-based index **43** of the **45 entries** in signed range `0x6013D4F0..0x6013D5A4`. Phase43's original walker **`0x600CDB74`** semantics/bounds are reused and verified.

This establishes membership in the table consumed by the signed walker. It does not establish completion of the preceding startup/iterations on physical hardware.

## Verified original stores

| Field | Address | Constructed virtual value | Store PC |
|---|---|---|---|
| Object handle `+0x58` | `0x200201A4` | **0** | `0x600926F4` STRD |
| Auxiliary pointer `+0x5C` | `0x200201A8` | **`0x20020278`** | `0x6009271E` |
| Auxiliary `+0xCC` | `0x20020344` | **`0x2002034C`** | `0x6009270C` |
| Auxiliary `+0xD0` | `0x20020348` | **`0x200`** | `0x60092716` |

Shifting the original size word by two gives `0x800`, precisely the accepted phase67 threshold. Structure/buffer names describe use in that path, not demonstrated scheduler operation.

Two cases execute: ordinary virtual input and handle/auxiliary fields poisoned with `A5A5A5A5/5A5A5A5A`. Both produce the same original fields. The poisoned case is an overwrite control, not a physically reachable-state claim.

## Original code and remaining models

Constructor `0x600926D0` and helpers **`0x601017FC`**, **`0x600C9DE4`** execute original code. Deeper helper **`0x6013D3D0`** is a no-op returning unchanged R0; its kernel initialization effects are not reproduced. Execution stops on entry to final wrapper `0x60101C48`, after field construction/frame restoration, without executing final registration. This remains conditional execution under explicit models, not complete startup or proof that physical helpers always return.

Phase67's internal preserve-fields option consumes this constructed RAM without replacing auxiliary state. Original pending-call/creation guards accept the original zero handle and pointer/size. **`0x600CA1F8` remains an opaque-return stub**; original wrapper stores that handle and the mode function returns normally.

A subsequent staged transition/original-driver run with virtual MMIO word 8 binds class10 instance **`0x200040E0`**. Prior registration/synchronization/transition-helper models and stage joins remain. Remaining classes, final mode publication and callbacks do not execute.

```powershell
python -m tools.audit_workqueue_constructor_phase68 local/bruce.bin --out local/phase68.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_workqueue_constructor_phase68 -v
```

Requires `requirements-emulation.txt` and the separately obtained exact [OEM image](https://github.com/StadiaMemories/firmware). SHA, walker bounds, entry43, semantic anchors and field results are enforced. Negative tests mutate the table pointer, auxiliary store and size. All **746 local tests** pass with original-image fixtures enabled; CI reproduces complete evidence. Phase67 default evidence is unchanged. No firmware or RAM snapshot is published.

## Remaining frontier

The synthetic auxiliary state has been replaced by identified/executed OEM producers. Handle provenance is bounded to the modeled return from **`0x600CA1F8`**; its actual body/scheduler effects, helper **`0x6013D3D0`** and real startup continuity remain next.

No installed fields were measured, real tasks created, device commands sent or firmware/eFuses changed. Physical class10 activation, custom device code and HAB bypass remain unproven.

[Evidence](../../evidence/usb-workqueue-constructor-phase68.json) · [Auditor](../../tools/audit_workqueue_constructor_phase68.py)
