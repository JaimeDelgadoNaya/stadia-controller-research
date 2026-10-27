# Phase 78 — Shared Work Queue initializer and the bounded USB inference

**27 October 2026.** Original exact SHA-256-pinned signed Bruce OEM firmware `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`, **offline only**.

## Finding

The earlier signed USB-mode path and signed B-object initializer both call **`0x6009267C` with R0=1**, as shown by the original instructions:

- USB mode path: `0x60060F28 MOVS R3,#1`, `0x60060F32 MOV R0,R3`, `0x60060F34 BL 0x6009267C`.
- B constructor: `0x6006B3FE MOVS R0,#1`, `0x6006B400 BL 0x6009267C`.

The common routine loads the original **Work Queue singleton** at `0x2002014C` (signed literal PC `0x60092698`), reads its task handle at `+0x58`, and conditionally prepares the original **`Work Queue Task`** label from signed literal PC `0x6009269C` (value `0x6012F592`). When no handle exists, it calls `0x6010177A`. When one exists, it returns zero without starting creation.

This is supported by **16 exact original signed instruction pins** and independent phase 66/77 anchors. Common use of this *global initialization service* **does not establish that the USB host caused an event**, that both caller paths execute sequentially, or that the host controls a callback pointer.

## Bounded original execution

The exact original helper bytes were executed in Unicorn with only virtual SRAM handle fixtures:

| Virtual handle at `WorkQueue+0x58` | Observed original code path |
|---|---|
| Zero | Original code reached `0x6010177A`; execution **stopped before task creation** with R0 queue object, R1 label pointer, R2 = 1 |
| `0x20025000` (test fixture) | Original code skipped task creation and returned R0 = 0 |

Neither virtual guard path changed the handle. Original signed code executed; task creation, scheduler, callbacks and USB did not. No live RAM/device hardware was accessed.

## Go/no-go

**Do not prioritize the shared-helper coincidence as a host-controlled execution route.** It is consistent with independent callers requesting the same Work Queue singleton. This is **not proof that all possible USB-to-queue routes are absent**: indirect paths, runtime conditions and host-origin tracing remain outside the audit.

The next meaningful validation is **passive USB descriptor/normal-traffic evidence**, correlated to the existing original signed class/interface model, or a separate external Stadia→Xbox bridge. Confirm any alleged host-control chain with actual observations before treating it as an execution primitive. HAB CLOSED, custom firmware and native Xbox compatibility remain unresolved.

## Reproduce

```bash
python -m tools.audit_workqueue_shared_init_phase78 local/bruce.bin --out local/phase78.json
STADIA_BRUCE_IMAGE=local/bruce.bin python -m unittest tests.test_workqueue_shared_init_phase78 -v
```

[Original signed evidence](../../evidence/usb-workqueue-shared-init-phase78.json) · [OEM GitHub Actions](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40486798083) · [PR #80](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/80).

No physical USB command, installed RAM readback, flash/eFuse write or HAB CLOSED bypass.
