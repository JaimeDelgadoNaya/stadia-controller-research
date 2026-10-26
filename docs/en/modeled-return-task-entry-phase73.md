# Phase 73 — Explicit return model and original task entry

**26 October 2026.** Offline exact Bruce OEM SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`, following [phase 72](svc-software-restore-phase72.md).

## Result

After an **explicit exception-return register model**, original task entry **`0x60101760`** and worker **`0x600EE142`** execute up to their first queue call at **`0x600EE152`**, stopping before that call.

SVC/BX LR/NVIC exception return is **not executed**. Emulator APIs load the pending frame's registers; original OEM code executes afterwards. This is not a task running on the physical controller.

## Explicit frame bridge

The phase71–72 virtual machine is retained at the pre-BX-LR stop, with BASEPRI zero and PSP=`0x20020B28`. Only the observed `0xFFFFFFFD`, eight-word basic thread/PSP frame is supported. Extended/floating frames, unmodeled alignment padding, different size and exception-state profiles are rejected.

R0–R3, R12, LR, PC/status are read from the OEM-prepared frame and assigned through emulator APIs. The bridge models 32-byte consumption and virtual thread-stack selection:

| Modeled state | Value |
|---|---|
| Input PSP | `0x20020B28` |
| Selected task PSP | **`0x20020B48`** |
| Loaded R0 | **`0x2002014C`**, Work Queue object |
| Loaded PC | **`0x60101760`** |
| Retained MSP | `0x2002B828` |

This is a bounded execution hypothesis, not complete architectural exception emulation or physical validation. Phase72's BX LR does not execute.

## Original code after the bridge

The original task wrapper reads Work Queue vtable **`0x60115C34`**, then method `+8` **`0x600EE143`**. Original BLX at `0x6010176A` enters worker `0x600EE142`, which prepares its stack and reaches:

| Pre-call argument | Observation |
|---|---|
| R0 | **`0x200201AC`**, queue control from Work Queue `+0xB0` |
| R1 | Virtual-stack output buffer |
| R2 | **`0xFFFFFFFF`**, original wait value |
| BL target at `0x600EE152` | **`0x6013D268`** |

The BL does not execute. Queue receive success, blocking/scheduling, dequeued work and callback invocation remain unobserved. Later callback branches are not run.

```powershell
python -m tools.audit_task_entry_phase73 local/bruce.bin --out local/phase73.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_task_entry_phase73 -v
```

Requires `requirements-emulation.txt` and the separately obtained exact [OEM sample](https://github.com/StadiaMemories/firmware). SHA, entry/indirect dispatch/queue-call anchors and frame rejection are checked. Negative tests mutate BLX, queue-control load and first BL. All **767 local tests** pass with original-image fixtures enabled; CI reproduces complete evidence.

Next: resolve **`0x6013D268`**, receive conditions and original work-item producers. No physical USB-to-work-item/callback path is established. Prior constructor/synchronization/system/priority/timer models and incomplete scheduler startup remain. No device commands, firmware/eFuse changes, physical class10 activation, custom on-controller code or HAB bypass are demonstrated.

[Evidence](../../evidence/usb-task-entry-phase73.json) · [Auditor](../../tools/audit_task_entry_phase73.py)
