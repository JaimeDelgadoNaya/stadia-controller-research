# Phase #40 — original signed Bruce class-10 callback found in boot-copied RAM image

**26 October 2026, offline-only.** Sample: Google OEM signed Bruce update image, 1,050,984 bytes; SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Not an installed-flash readback or live RAM measurement. No USB commands, firmware writes or callbacks executed.

## The formerly missing word at class10 configuration record +0

The prior [phase #39](bruce-class10-r1-origin.md) identified a conditional 12-byte class configuration record passed in R1 to `0x60055320`. The original *authenticated boot-initialized data* holds **two consecutive records**:

| Boot RAM base | Original source offset | +0 signed Thumb callback | +4 initial class object | +8 descriptor pointer | Byte descriptor+4 |
|---|---|---|---|---|---|
| `0x200030E8` | `0xFDF50` | `0x60061249` | 0 | `0x200030A0` | 2 |
| **`0x200030F4`** | **`0xFDF5C`** | **`0x600613FD`** | **0** | **`0x20003100`** | **10** |

Both records are within the region the OEM startup copies from signed XIP source `0xFD5A8` to RAM `0x20002740`. The class-10 callback entry's **first word is therefore already supplied by signed OEM image data**: Thumb address **`0x600613FD`** (code address `0x600613FC`). This resolves the previously missing static writer/value *for this particular record*; it does not establish live class activation.

Two signed flash literal words at file offsets `0x21100` and `0x21108` contain `0x200030E8`, near two `LDR R0,[PC,#0]; BX LR` getter snippets. Another pointer at `0x213F8` contains `0x200030F4`. Static references do not prove that these functions were called on the physical controller.

In the bounded census, 73 initialized-RAM triple shapes were found, but only **one** matched descriptor byte +4 equal to 10. Another 522 candidate shapes occurred in the scanned high-XIP data window, **none** with byte+4 equal to 10. These are scan/model-specific counts, not exhaustive whole-program uniqueness.

## New signed callback behavior

Actual Thumb code beginning at **`0x600613FC`** first performs:

```asm
CMP R1, #0x7F
BLS 0x60061422       ; returns zero for 0x00..0x7F
LDR R0, [PC,#0x24]   ; RAM registry base
MOVW R3,#0x3A38
LDR R4, [PC,#0x20]   ; guard sentinel
LDR R3,[R0,R3]      ; secondary registered callback
CMP R3,R4
BEQ 0x60061422
MOVW R4,#0x3A3C
LDR R0,[R0,R4]      ; secondary registered callback context
BLX R3              ; indirect invocation, NOT emulated or observed on hardware
```

Thus requests `0x81`, `0x83`, and `0x84` **pass the first high-byte threshold**. The signed class-10 callback then delegates to a **second RAM-registered function** only if its guard passes. The original signed literal words at `0x60061428` and `0x6006142C` are **`0x200064C0`** (RAM base) and **`0x600D4F05`** (guard sentinel). Thus the second function pointer is read at **`0x20009EF8`** (`base + 0x3A38`) and its context at **`0x20009EFC`** (`base + 0x3A3C`). These are verified static-address calculations, **not live SRAM readings**. A bounded Unicorn audit checks the original guards with synthetic RAM and stops before `BLX R3`.

The second function's **runtime value, registration source, security properties and reachability are unverified**. `bRequest` is data, not a host-supplied branch address.

The tool `tools/audit_bruce_class10_record_producer.py` verifies original SHA/length, the actual contiguous signed records, both descriptor class bytes, signed literal references and machine-code guard instructions. The original OEM binary is never committed. Regression tests use synthetic fixtures.

**Next evidence gate:** identify the writer/registrar for the **secondary callback in RAM** and its context, not the now-resolved first word of the boot record. Until this is known, no arbitrary firmware execution, HAB CLOSED bypass, safe recovery or direct Xbox/Switch 2 use is demonstrated.

```sh
python -m unittest tests.test_bruce_class10_record_producer -v
python -m tools.audit_bruce_class10_record_producer local/bruce_pvt_a_prod_signed.bin --out local/class10-provenance.json
```

CI fetches a transient hash-pinned public OEM copy and deletes it after the audit. [PR #40](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/40).
