# Phase 69 — Original task preparation and handle provenance

**26 October 2026.** Offline exact Bruce OEM SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`, following [phase 68](workqueue-constructor-phase68.md).

## Result

**`0x600CA1F8` executes original code** using the constructor-provided resources. Its return is no longer replaced with an opaque handle: original stores produce **`0x20020278`**, the preallocated state structure from phase68.

Original state preparation **`0x600CA0FC`**, local initialization **`0x601007B6`** and frame preparation **`0x600CC554`** also execute. **Task entry and real scheduler registration do not execute.** Registration routine `0x600C9FD8` remains a no-op stub.

## Original return path

The creator receives nonzero preallocated state/buffer arguments from the original wrapper. `0x600CA242` stores the buffer in state `+0x30`. State preparation builds the frame and **`0x600CA1A0 STR R4,[R7]`** writes the state pointer through its output argument. After modeled registration, **`0x600CA264 LDR R0,[SP,#0x14]`** loads that original output; wrapper code stores it into Work Queue `+0x58`, address `0x200201A4`.

This establishes **`0x20020278`** as the handle in this modeled preallocated path. It does not establish all creation variants or a valid physical task.

| Prepared virtual field | Original-code value |
|---|---|
| Handle/state structure | **`0x20020278`** |
| Buffer at state `+0x30` | `0x2002034C` |
| Original size | `0x200` words |
| Saved frame pointer | **`0x20020B04`** |
| State word `+0x2C` | 1 |
| Prepared PC at frame `+0x3C` | **`0x60101760`** |
| Prepared R0 at frame `+0x24` | **`0x2002014C`**, Work Queue object |
| Frame status word `+0x40` | `0x01000000` |
| Frame return word `+0x20` | `0xFFFFFFFD` |

Original instructions compute buffer + byte size − 4, align to 8 and reserve `0x44` bytes. The resulting address and frame words are checked. **Preparing the PC is not executing it:** no task entry or context switch occurs. Byte fill, including the original `0xA5` pattern, is bounded virtual-memory modeling; no full buffer/RAM snapshot is published.

## Remaining models and continuation

The mode function returns with this original-code-generated handle. The staged transition/original-driver experiment again binds class10 instance **`0x200040E0`** with virtual MMIO word 8. Existing stage joins, registration/synchronization helpers and stop before final mode publication remain.

**`0x600C9FD8` is not executed**: the stub preserves R0 and performs no scheduling or registration. Phase68's `0x6013D3D0` constructor model also remains. Real helper success, concurrency, work processing and peripheral effects are not established.

```powershell
python -m tools.audit_task_handle_phase69 local/bruce.bin --out local/phase69.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_task_handle_phase69 -v
```

Requires `requirements-emulation.txt` and the separately obtained exact [OEM sample](https://github.com/StadiaMemories/firmware). SHA, handle/return/frame semantic anchors and full results are verified. Negative tests mutate the handle store, frame-PC store and return load. All **750 local tests** pass with original-image fixtures enabled; CI reproduces complete evidence. Existing phase67 default output is preserved.

Next: resolve **`0x600C9FD8` registration and kernel dependencies**, then the prepared entry and work processing. No physical task or class10 activation, device commands, firmware/eFuse changes, custom device execution or HAB bypass is demonstrated.

[Evidence](../../evidence/usb-task-handle-phase69.json) · [Auditor](../../tools/audit_task_handle_phase69.py)
