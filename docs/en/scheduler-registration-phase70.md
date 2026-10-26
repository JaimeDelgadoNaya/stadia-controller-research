# Phase 70 — Original registration/list insertion and critical-section state

**26 October 2026.** Offline exact Bruce OEM SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`, continuing [phase 69](original-task-handle-phase69.md).

## Result

**`0x600C9FD8` executes original code rather than a stub.** Its list/critical-section helpers execute through original veneers and relocated signed ITCM bytes. State structure **`0x20020278`** is linked into the virtual priority-1 ready list, updating counters and bitmap.

Scheduler startup, context switching and prepared task entry `0x60101760` do not execute. **List insertion is not a running task.** Initial scheduler globals are an empty virtual model, not an installed running controller's state.

| XIP veneer | Original Thumb target | Observed use |
|---|---|---|
| `0x6013D360` | `0x7D65` | Critical-section entry |
| `0x6013D000` | `0x7DAD` | Critical-section exit |
| `0x6013D060` | `0xB2E9` | List initialization |
| `0x6013D188` | `0xB2FF` | Node insertion |

ITCM bytes are copied from file offset `0x81C` and executed at runtime addresses, not decoded with their flash-storage PCs. All four helpers execute original instructions, including CPU mask operations. System page `0xE000E000` is plain virtual memory without real NVIC effects, asynchronous interrupts or hardware timing.

## Observed original stores

| Virtual field | Address | Result |
|---|---|---|
| Task count | `0x200276A0` | 1 |
| Global current-task pointer | `0x20027410` | `0x20020278` |
| Ready priority bitmap | `0x200276B4` | `0x2` |
| Priority-1 list | `0x20027430` | Count 1 |
| Task node | `0x2002027C` | Both head links point to node |
| Node container | `0x2002028C` | `0x20027430` |

The original code initializes lists/inserts the node, then the upper path publishes the original handle. Virtual scheduler-state word `0x20027700` is zero; a running system and all priority/preemption branches are not tested.

## OEM sentinel and separate zero-depth vector

Signed initialized data contains **`0xAAAAAAAA` at `0x20003D68`**, consumed as the critical nesting counter. Two independent executions show:

| Counter input | Source | Final counter | Virtual final BASEPRI |
|---|---|---|---|
| `0xAAAAAAAA` | Original initialized bytes | `0xAAAAAAAA` | **`0x50`** |
| 0 | Explicit synthetic test vector | 0 | **0** |

Entry increments the counter and sets the mask; exit decrements and clears BASEPRI only when zero. This is not presented as a defect or installed state. Complete startup normalization has not been followed. Returning from registration alone therefore does not guarantee a cleared CPU mask.

Only RAM from the **zero-depth vector** is joined to the later transition/original-driver/class10 stage, which binds instance `0x200040E0` with virtual MMIO 8. The sentinel case remains separate; no real normalization is assumed. The later stage uses a new virtual CPU/register context, not a physical continuation. Prior constructor/synchronization/fill/transition models and stop before final mode publication remain.

```powershell
python -m tools.audit_scheduler_registration_phase70 local/bruce.bin --out local/phase70.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_scheduler_registration_phase70 -v
```

Requires `requirements-emulation.txt` and the separately obtained exact [OEM sample](https://github.com/StadiaMemories/firmware). SHA, registration anchors, veneer targets and source sentinel are enforced. List links, counts, bitmap and mask outcomes are checked. Negative tests mutate insertion call, ITCM target and sentinel. All **754 local tests** pass with original-image fixtures enabled; CI reproduces complete evidence. Previous phase69 default output is preserved.

Next: trace normalization of **`0x20003D68`**, scheduler startup/context switch and work flow from `0x60101760`. No physical tasks, USB events, class10 activation, device commands, firmware/eFuse changes, custom device execution or HAB bypass are demonstrated.

[Evidence](../../evidence/usb-scheduler-registration-phase70.json) · [Auditor](../../tools/audit_scheduler_registration_phase70.py)
