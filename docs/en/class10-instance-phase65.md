# Phase 65 — Class10 instance gates and the original owner path

**26 October 2026.** Bounded offline execution of exact Bruce OEM SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`, continuing [phase 64](original-class-records-phase64.md).

## Result

The original owner path binds the first OEM record to class10 instance **`0x200040E0`**, **conditional on an injected successful low-level USB driver return**. Unlike phase64's selector fragment, `[singleton+4]=owner+4` is now written by original instruction `0x6005512E`, not imposed by the experiment.

Driver `0x6005556C` is stubbed; hardware initialization, installed SRAM and callback `0x600613FD` execution remain unobserved.

## Original class10 gates

Initializer `0x60055320` checks the first word of class state `0x200040E0`. If already nonzero, it returns **2** before checking the engine. Otherwise original helper `0x60055024` requires a nonzero engine pointer in singleton `0x20004080` and a matching mode byte at singleton `+0x0E`. Missing engine/mode mismatch returns **4**. A match copies the engine pointer into class state and returns zero.

| Synthetic engine | Engine mode | Class already busy | Original return for requested mode 2 | New record instance |
|---|---:|---|---:|---|
| Absent | 2 | No | 4 | None |
| Present | 3 | No | 4 | None |
| Present | 2 | No | **0** | **`0x200040E0`** |
| Present | 2 | Yes | 2 | None written |
| Absent | 2 | Yes | 2 | None written |

These are test vectors, not physical states. The final case demonstrates check ordering without establishing physical reachability of that combination.

## Owner-to-instance execution

The experiment reuses phase64's constructed RAM with the original four class records. It first clears virtual core/class/engine state, including phase64's injected singleton handoff, then starts at `0x60060F84`, R0=`0x2000A2A8`. Original code derives R1=`owner+4`, R2=`owner+0x98`, and mode 2 from `owner+0x10`, then executes `0x600550E4`, engine constructor `0x60055350`, selector comparison and the actual class10 initializer/helper.

With injected driver status zero, original stores establish:

| Field | Address | Observed virtual value |
|---|---|---|
| Singleton engine | `0x20004080` | `0x200063C0` |
| Singleton configuration | `0x20004084` | `0x2000A2AC` = `owner+4` |
| Class10 engine | `0x200040E0` | `0x200063C0` |
| Class10 original record | `0x200040E4` | `0x2000A274` |
| First record instance | `0x2000A278` | **`0x200040E0`** |
| Class10 `+0x0C/+0x0E` bytes | `0x200040EC/0x200040EE` | `0 / 255` |

Success stops at `0x60055196`, immediately after the first class method returns. Remaining classes and final owner registration/return are not executed; observed zero is **not complete USB startup success**.

With injected driver status **5**, original code enters the error path and stops at `0x600553D0`, before cleanup and before class10 initialization. Any pointer observed there is transient; final cleanup state is not established.

## Earlier transition remains outside the experiment

The intermediate phase64 snapshot has **`owner+0x90 = 0`**. Phase53's mode-2 transition requires a prior mode that is nonzero and different from 2. Starting directly at `0x60060F84` **bypasses that transition's guards at `0x60060FE8`**. The snapshot predates complete initialization; later writers and real installed mode are not excluded or observed.

## Explicit models and reproduction

The snapshot inherits phase64's subobject/mutex/copy models. Low-level driver `0x6005556C` returns injected 0/5 without hardware effects. Helper `0x6013D3E0` writes zero to its virtual-stack status byte; `0x600D15E8` is a no-op. Their original implementations and concurrency are not executed. Owner/core/engine/selector/class10 instructions execute original code. No application callback, remaining class initialization, failure cleanup, prior transition or final owner registration executes.

```powershell
python -m tools.audit_class10_instance_phase65 local/bruce.bin --out local/phase65.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_class10_instance_phase65 -v
```

Requires `requirements-emulation.txt` and the separately obtained exact [OEM sample](https://github.com/StadiaMemories/firmware). Image SHA, semantic anchors, pointers and all seven scenario outcomes are enforced. Negative tests alter a gate, instance store and driver pointer. All **733 local tests** pass with original-image fixtures enabled; CI reproduces complete evidence. Phase64's internal optional RAM return supports reuse without publishing a snapshot; its previous CLI output is unchanged.

## Next boundary

The injected singleton handoff has been removed from the owner path. **Actual low-level driver success remains an explicit assumption**, alongside the unresolved earlier mode transition. Follow `0x6005556C` and prior-mode writers next, then physical-event delivery to the identified OEM callback.

No physical class10 activation, host-chosen pointers, custom execution, HAB bypass or native console compatibility is demonstrated. No device commands, firmware/eFuse writes or mode changes occurred.

[Evidence](../../evidence/usb-class10-instance-phase65.json) · [Auditor](../../tools/audit_class10_instance_phase65.py)
