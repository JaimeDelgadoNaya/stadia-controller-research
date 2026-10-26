# Phase 66 — Original USB driver, MMIO gate and prior-mode writer

**26 October 2026.** Offline Bruce OEM SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`, continuing [phase 65](class10-instance-phase65.md).

## Result and changed model

The **original driver `0x6005556C` and initializer `0x60055400` execute without stubs**. Their external dependency is now an explicit plain-memory MMIO model at `0x402E0000`, seeded with synthetic values; real peripheral behavior is not reproduced.

A caller of `0x60060F28` is also identified. The original routine writes **1 to `owner+0x90`** before a pending external call. A staged experiment uses that store, runs the original mode-transition guards, driver and class10 initialization: virtual MMIO word 8 permits binding; word 7 produces an original driver error before class10. This is not physical register observation or complete startup.

## Original driver gate

`0x6005556C` returns **6** for modes other than 2 before MMIO access. In mode 2 it reads **`0x402E0124`**, masks `0x1F`, and returns **1** if the result is at most 7. Values 8–31 enter the original initializer; under the plain-memory model it publishes driver object `0x20011DFC` and returns zero. No official register name or hardware interpretation is assigned here.

| Synthetic mode | Virtual word | Low five bits | Original return | `0x60055400` executed |
|---:|---|---:|---:|---|
| 2 | `0x00` | 0 | 1 | No |
| 2 | `0x07` | 7 | 1 | No |
| 2 | `0x08` | 8 | **0** | Yes |
| 2 | `0x1F` | 31 | **0** | Yes |
| 2 | `0x108` | 8 | **0** | Yes |
| 2 | `0x100` | 0 | 1 | No |
| 3 | `0x08` | 8 | 6 | No |

Successful cases establish driver object `0x20011DFC`, context `0x200063C0`, queue structures and original writes to MMIO offsets including `+0x140`, `+0x148`, `+0x154`, `+0x158`, `+0x1A8`. Every MMIO read address and write is recorded. All accesses are virtual.

## Prior-mode 1 writer

Activation routine `0x60074658` saves R0 in R5. The fragment at `0x60074772` derives R7=`R5+0x3DC0+0x28`; with global base `0x200064C0`, this is owner `0x2000A2A8`. `0x600747B0` passes R7 as R0; `0x600747B2` calls `0x60060F28`. Original MOVS/STR at `0x60060F28/0x60060F2C` write **1** to field `0x2000A338`.

The experiment starts with synthetic R5/global and R6/stack inputs consistent with pinned instructions. The complete activation caller's actual argument is not traced here. Four registration helpers are no-op zero-return stubs. Owner derivation, BL and mode store execute original code.

Execution **stops before `0x60060F34 BL 0x6009267C`**. That pending call, its outcome and side effects are omitted. The experiment does not establish completed activation or persistent mode 1.

## Staged transition/driver/class10 execution

The next stage explicitly joins the post-store virtual RAM to original transition `0x60060FE8`, requesting mode 2. The pending `0x6009267C` call is not executed between stages. Transition helper `0x60060C70` remains a no-op stub. Original guards, transient-mode store, owner, engine, driver, selector and class10 initializer execute.

| Input state | Virtual MMIO word | Observation |
|---|---:|---|
| Phase64 intermediate snapshot, prior mode 0 | 8 | Early transition return before class10 |
| After original mode-1 store | 8 | Original driver publishes `0x20011DFC`; first record receives **`0x200040E0`** |
| After original mode-1 store | 7 | Original driver returns **1** before class10 initialization |

Success stops after the first class. Requested mode is 2, but the field at that stop remains **transient 1**: remaining classes and final mode publication do not execute. Error stops before cleanup, without proving its final state.

## Remaining boundaries

MMIO is ordinary virtual memory, without real register side effects, clocks, resets, DMA or timing. Phase64 constructor and phase65 guard-helper models remain. The writer/transition join omits `0x6009267C`; full activation-caller state is unresolved. No remaining classes, final mode publication, OEM callbacks or error cleanup execute. Physical register values, class10 activation and packet-to-callback reachability remain unmeasured.

```powershell
python -m tools.audit_usb_driver_phase66 local/bruce.bin --out local/phase66.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_usb_driver_phase66 -v
```

Requires `requirements-emulation.txt` and the separately obtained exact [OEM sample](https://github.com/StadiaMemories/firmware). SHA, semantic anchors, MMIO literals and mode-store semantics are enforced. Negative tests mutate the gate branch, MMIO base and mode STR. All **738 local tests** pass with original-image fixtures enabled; CI reproduces complete evidence. Phase65's new optional execution controls preserve its previous default output.

Next: resolve pending call **`0x6009267C`**, activation-caller conditions and transition-helper effects. Original execution against a virtual register bank does not prove a real controller accepts that sequence.

No physical USB commands, register access, firmware/eFuse changes, custom on-controller execution or HAB bypass occurred.

[Evidence](../../evidence/usb-driver-mode-phase66.json) · [Auditor](../../tools/audit_usb_driver_phase66.py)
