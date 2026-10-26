# Phase 72 — Original software restore up to exception return

**26 October 2026.** Offline exact Bruce OEM SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`, following [phase 71](critical-normalization-svc-phase71.md).

## Result

The original SVC wrapper/handler **`0x6004CB40` executes**, retaining the **same virtual machine** from phase71's accepted pre-SVC stop. Original code loads the model's selected task, restores R4–R11/LR, sets **PSP=`0x20020B28`** and clears **BASEPRI to zero**.

Execution stops **before `0x6004CB5A BX LR`**. SVC, real exception entry, hardware unstacking and task entry do not execute. Manual entry into handler code is not NVIC exception delivery.

## Preserved state and explicit entry

Phase71's accepted `0xF0` readback model reaches the pre-SVC boundary with nesting zero, BASEPRI `0x50` and MSP `0x2002B828`. Its internal optional return preserves CPU/memory; only prior stopping hooks are removed. Default phase71 CLI/evidence remains unchanged.

The new stage reads SVC vector **`0x6004063D`** through the existing virtual VTOR, then manually enters its wrapper, which selects Thumb handler `0x6004CB41` via literal `0x60040744`. Actual exception-entry/automatic MSP stacking is omitted.

The handler's original literal `0x20027410` supplies task state **`0x20020278`** and frame **`0x20020B04`**. This task was selected by the earlier empty-scheduler model, not observed on a physical controller.

| Original operation | Virtual observation |
|---|---|
| R4–R11/LR LDM.W at `0x6004CB46` | Matches prepared frame words |
| PSP write at `0x6004CB4A` | **`0x20020B28`**, after nine words |
| Restored LR | **`0xFFFFFFFD`** |
| BASEPRI write at `0x6004CB56` | **0**, previously `0x50` |
| MSP during software fragment | Unchanged `0x2002B828` |
| Final reached instruction | `0x6004CB5A BX LR`, **not executed** |

Restored R4–R11 words come from the prepared virtual buffer/fill pattern, not physical registers or a real user context.

## Hardware frame still pending

At the stop, virtual CPU R0 is **0**, used for mask clearing. The task's intended argument/PC remain in the frame:

| Pending word | Value |
|---|---|
| R0 at `[PSP]` | **`0x2002014C`**, Work Queue object |
| PC at `[PSP+0x18]` | **`0x60101760`** |
| Status at `[PSP+0x1C]` | `0x01000000` |

They are not loaded as running task CPU state. The exception-return mechanism would need to consume this frame; neither that mechanism nor BX LR executes. Mask clearing/PSP preparation therefore does not establish work execution.

```powershell
python -m tools.audit_svc_restore_phase72 local/bruce.bin --out local/phase72.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_svc_restore_phase72 -v
```

Requires `requirements-emulation.txt` and the separately obtained exact [OEM image](https://github.com/StadiaMemories/firmware). SHA, vector, current-task literal, instruction semantics and exact BX LR encoding `0x4770` are enforced. Negative tests alter vector, multiple-load and return instruction. All **762 local tests** pass with original-image fixtures enabled; CI reproduces complete evidence and previous phase71 output.

Software restoration is now executed rather than only statically identified. **Exception return and `0x60101760` execution remain next**, alongside existing priority/system/timer/constructor/synchronization models and incomplete high-level scheduler startup. No device commands, firmware/eFuse changes, physical class10 activation, custom device execution or HAB bypass are demonstrated.

[Evidence](../../evidence/usb-svc-restore-phase72.json) · [Auditor](../../tools/audit_svc_restore_phase72.py)
