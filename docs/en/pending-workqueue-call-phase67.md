# Phase 67 — Pending-call resolution and normal-return conditions

**26 October 2026.** Offline exact Bruce OEM SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`, following [phase 66](usb-driver-prior-mode-phase66.md).

## Result

Previously omitted call **`0x6009267C` now executes original instructions** to normal return or an observed error branch. It accesses SRAM object **`0x2002014C`** and OEM label **“Work Queue Task”** at `0x6012F592`. The label and creation-shaped code suggest task registration/creation; a real scheduler, allocation and running task are not executed or established.

`0x60060F28` writes mode 1 before calling this helper with argument 1. The helper returns zero immediately if object `+0x58`, address **`0x200201A4`**, is nonzero. It does not validate that field as a real/running task.

With a zero field, original wrapper `0x6010177A` calls `0x600CC178`. Missing auxiliary pointer at `+0x5C`, address **`0x200201A8`**, returns **9**. Otherwise it reads auxiliary word `+0xD0`, computes **`(word << 2) mod 2^32`** and returns **3** if the result is below `0x800`. The tested `word=0x200` calls `0x600CA1F8` and stores its return in the handle field. This last call is modeled by an opaque nonzero return, not real task creation; wrapper synchronization hooks are no-ops.

## Four original-code cases

| Virtual handle field | Auxiliary pointer | Word `+0xD0` | Helper status | Mode-function outcome |
|---|---|---|---:|---|
| Nonzero | Not needed | — | **0** | Original return to `0x600747B6` |
| Zero | Missing | — | **9** | Error branch `0x60060F3E`, before logging |
| Zero | Present | `0x1FF` → `0x7FC` | **3** | Same error branch |
| Zero | Present | `0x200` → `0x800` | **0**, modeled creation | Normal return; opaque value stored |

**The mode field is 1 in all four cases** because its store precedes the call. A mode-1 store alone therefore does not prove completed activation. The fast case executes neither creation nor wrapper synchronization. All fields are synthetic vectors, not installed-state observations.

## Join after complete original return

Starting at caller fragment `0x60074772`, with phase66's synthetic register inputs and four registration-helper models, original code derives the owner, executes the mode function, pending call and returns to `0x600747B6`.

Only after a normal original return, a second stage enters transition `0x60060FE8`, requests mode 2 and uses phase66's original driver with virtual MMIO word 8. The OEM record binds instance **`0x200040E0`**. The previously pending call is no longer skipped before this join.

This remains a staged composition: the full caller path from `0x600747B6` to a later mode request is not executed. Constructor dependencies, no-op transition helper `0x60060C70` and plain-memory MMIO models remain. Execution stops after the first class at transient mode 1, before final mode publication or callbacks.

```powershell
python -m tools.audit_pending_workqueue_phase67 local/bruce.bin --out local/phase67.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_pending_workqueue_phase67 -v
```

Requires `requirements-emulation.txt` and the separately obtained exact [OEM sample](https://github.com/StadiaMemories/firmware). SHA, semantic anchors, literals, label and outcomes are checked. Negative tests mutate the handle guard, size comparison and label. All **742 local tests** pass with original-image fixtures enabled; CI reproduces complete evidence. No firmware or RAM snapshot is published.

## Remaining work

The pending call's return conditions are resolved within the explicit models, including a failure after mode 1 was already stored. Next: trace the actual initializer of **`0x200201A8`** and handle field, then execute/bound `0x600CA1F8` and synchronization effects. Physical field values remain unknown.

No physical class10 activation, USB-to-callback execution, custom code or HAB bypass is demonstrated. No device commands, firmware/eFuse changes or physical register writes occurred.

[Evidence](../../evidence/usb-pending-workqueue-phase67.json) · [Auditor](../../tools/audit_pending_workqueue_phase67.py)
