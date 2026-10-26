# Phase 71 — Critical-counter normalization and the pre-SVC boundary

**26 October 2026.** Offline exact Bruce OEM SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`, continuing [phase 70](scheduler-registration-phase70.md).

## Result

Port-start routine **`0x600CC5AC`** normalizes critical nesting word **`0x20003D68`** using original **`0x600CC624 STR R5,[R4]`**, after a priority-bit readback check. With explicit virtual readback mask **`0xF0`**, original execution clears the word and reaches **`0x600CC536 SVC #0`**, stopping **before executing SVC**. No task entry or context switch occurs.

The experiment carries phase70's constructed RAM and original sentinel `0xAAAAAAAA`, explicitly initializes virtual BASEPRI to the prior observed `0x50`, and starts directly at the port entry. Full high-level scheduler startup is not executed. Virtual VTOR is explicitly set to OEM base `0x60040000`; this is not a physical VTOR observation.

## Readback models

Original code writes `0xFF` to byte **`0xE000E400`** and reads it back. The model returns `stored & mask` on reads of that byte. Masks are synthetic hypotheses, not measured implemented priority bits or complete NVIC emulation.

| Readback mask | Original outcome | Final nesting | Virtual BASEPRI |
|---|---|---|---|
| `0xFF` | Assertion call before normalization | `0xAAAAAAAA` | `0x50` |
| **`0xF0`** | Stop before SVC | **0** | **`0x50`** |
| `0xE0` | Assertion call before normalization | `0xAAAAAAAA` | `0x50` |

Assertion implementation is not executed: the hook stops at entry `0x601016A2`. The profiles are not claimed to be physically reachable. This original path accepts the tested `0xF0` model.

## Original setup before SVC

Accepted execution includes original helpers `0x600CC578`, `0x600CC540`, `0x600CC518`. Timer setup reads the OEM-initialized snapshot word at **`0x20003020`**, computes `clock/1000 - 1` and writes virtual registers. This is not current physical-clock measurement.

`0x600CC518` reads virtual VTOR and the OEM initial stack word, establishing **MSP=`0x2002B828`**, then executes original CONTROL/mask/barrier instructions. Actual timer, interrupt and exception effects are absent. At the stop, nesting is zero but **BASEPRI remains `0x50`**: normalization has not yet completed control transfer or cleared that mask.

## Subsequent handler, statically identified

The OEM SVC vector is **`0x6004063D`**. Its wrapper uses literal `0x60040744` to select Thumb handler **`0x6004CB41`**. Original handler code restores saved registers/PSP and contains **`0x6004CB56 MSR BASEPRI,R0`** after setting R0=0, before **`0x6004CB5A BX LR`**.

Those instructions are checked statically here; **the handler is not executed**. Real exception entry/return and first-task restoration remain the next boundary.

```powershell
python -m tools.audit_port_start_phase71 local/bruce.bin --out local/phase71.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_port_start_phase71 -v
```

Requires `requirements-emulation.txt` and the separately obtained exact [OEM sample](https://github.com/StadiaMemories/firmware). SHA, anchors/literals, counter, timer arithmetic and SVC boundary are enforced. Negative tests mutate counter store, SVC and handler mask clear. All **758 local tests** pass with original-image fixtures enabled; CI reproduces complete evidence.

Earlier constructor/synchronization models, stage joins and the absence of a physical running scheduler remain. No device commands, firmware/eFuse changes, physical class10 activation, custom device execution or HAB bypass are demonstrated.

[Evidence](../../evidence/usb-port-start-phase71.json) · [Auditor](../../tools/audit_port_start_phase71.py)
