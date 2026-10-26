# Phase 62 — Exact live descriptor match in the Bruce OEM application

**26 October 2026.** Offline comparison with the 1,050,984-byte OEM image pinned to SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.

## Full descriptor match

The complete **80-byte configuration descriptor** measured through the parent hub in phase 61 occurs exactly once in the inspected authenticated OEM application content: file offset **`0xDE45A`**, XIP address **`0x6011E45A`**. This matches every measured descriptor byte, rather than only the endpoint layout. It does **not** hash-match the complete installed application.

The 32-byte WinUSB function view has no exact match in that content. A separate vendor-only OEM descriptor is **40 bytes**, including an interface association. It must not be confused with Windows' partial 32-byte view. This comparison does not establish which Windows layer produces that view.

## Signed descriptor selector

The original routine at **`0x600619BC`** writes a descriptor pointer and length into `[R1]` and `[R1+4]`:

| Descriptor XIP address | Bytes | Distinct interfaces | USB classes | Exact live hub match |
|---|---:|---:|---|---|
| `0x6011E45A` | 80 | 2 | `FF`, `03` | Yes |
| `0x6011E4AA` | 40 | 1 | `FF` | No |
| `0x6011E4D2` | 204 | 4 | `FF`, `03`, `01` | No |
| `0x6011E59E` | 287 | 5 | `FF`, `03`, `01` | No |

The last two contain audio-class interfaces and streaming alternate settings. All four have **bConfigurationValue = 1**; they are alternative firmware profiles, not four host-selectable SET_CONFIGURATION values. No audio behavior or profile switch was tested.

Let H be the return from `0x600DFFE8`, which receives the return of `0x6005BDAC` plus `0x448`, and argument `7`. Its meaning/effects remain unresolved. Let A/B be bytes at `0x2000A804/0x2000A805`, derived from original literal `0x200064C0` plus `0x4344/0x4345`.

| Original-code condition | Selected length |
|---|---:|
| H nonzero | 40 |
| H zero, A zero | 80; B not read |
| H zero, A nonzero, B zero | 204 |
| H zero, A nonzero, B nonzero | 287 |

**No live H/A/B values were read.** Only conditionally, if this unchanged routine produced the measured configuration, the 80-byte output is consistent with H=0 and A=0. Flag meaning, writers, host control and installed-path execution remain unverified.

## Bounded original-code execution

Unicorn executes `0x600619BC..0x60061A2C` with a 200-instruction limit, synthetic RAM/stack/output and all eight H/A/B combinations in `{0,1}`. Singleton lookup, the H helper and logging are explicitly stubbed; their original implementations and effects are not executed. This is not a SoC emulator. Each case returns zero and the expected descriptor pointer/length. Evidence includes every intercepted helper call.

The auditor enforces image SHA/size, semantic instruction anchors, PC-relative pointer literals and descriptor structure/counts. A negative test replaces the initial PUSH with NOP and confirms semantic/hash rejection. All **720 local tests** pass with the optional original-image fixture enabled. Dedicated CI reproduces the complete JSON against the pinned original image.

```powershell
python -m tools.audit_usb_descriptor_match_phase62 local/bruce.bin --emulate --out local/phase62.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_usb_descriptor_match_phase62 -v
```

Install `requirements-emulation.txt`, create `local/`, and obtain the exact sample separately from [StadiaMemories' archive](https://github.com/StadiaMemories/firmware). No OEM binary is committed or published as an artifact. Live descriptor evidence comes from [phase 61](usb-enumeration-phase61.md); this phase performs no device I/O.

## Research boundary

This establishes a unique complete descriptor match and a conditional OEM provider path. It does not establish internal selector 10 activation, callback invocation, custom execution, HAB bypass or native console compatibility. Next: trace callers of `0x600619BC` and writers of A/B, then connect this descriptor provider to the configuration/class-record owner. Descriptor equality alone does not reveal internal RAM pointers.

[Reproducible evidence](../../evidence/usb-descriptor-oem-match-phase62.json) · [Auditor](../../tools/audit_usb_descriptor_match_phase62.py)
