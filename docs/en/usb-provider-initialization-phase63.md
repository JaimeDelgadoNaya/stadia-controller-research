# Phase 63 — Descriptor provider, configuration owner and initial flag writers

**26 October 2026.** Offline SHA-pinned Bruce OEM analysis, continuing [phase 62](usb-descriptor-oem-match-phase62.md). Required image SHA-256: `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.

## Result

The 80-byte descriptor provider is linked to the **configuration owner identified in phases 49–55**. Original code also supplies two initial flag stores. This establishes a signed static path, checked by bounded execution of original fragments with synthetic RAM. It is **not installed-RAM observation or captured physical USB dispatch**.

At `0x600748EE`, a literal at `0x60074904` loads `0x200064C0`; this is passed to initializer `0x60073BF0` at `0x600748F2`, then saved in R4 at `0x60073BF4`. The initializer's copy loop runs from `base+0x3DB4` to `base+0x3DE4` with a 12-byte stride: four triplets obtained through indirect object methods. The actual producer methods and triplet contents are not executed or identified here.

| Field | SRAM address | Original-flow value |
|---|---|---|
| Configuration owner | `0x2000A2A8` | Previously identified owner base |
| `owner+4` | `0x2000A2AC` | Record array `0x2000A274` |
| `owner+8` | `0x2000A2B0` | Thumb method `0x60060D55` |
| `owner+12` | `0x2000A2B4` | Count byte **4** |
| Descriptor provider object | `0x2000A2A4` | Method table `0x60105B88` |
| `owner+0x8C` = `base+0x3E74` | `0x2000A334` | Provider pointer `0x2000A2A4` |
| Provider's first method word | XIP `0x60105B88` | Thumb selector **`0x600619BD`** |

The provider pointer is computed by original shift/multiply/mask/MLA instructions using literal `0x2AAAAAAB`; emulation checks the computed result rather than substituting it. Principal store PCs are `0x60073E4E`, `0x60073EAC`, `0x60073EB2`, `0x60073EB6` and `0x60073EF0`. These are concrete producers in this initializer, not proof of final physical RAM or absence of later writers.

**Four internal records do not imply four USB interfaces.** Phase 61 still measures two advertised interfaces. No internal selectors are assigned to the four records yet.

## Indirect invocation

The method at `0x60060D54` dispatches **internal event 12** through its original TBH table to `0x60060DB2`. Given a non-null output argument, it reads `[base+0x3E74]`, the provider's table and its first method, then executes **`0x60060DC4 BLX R3`**. With the metadata built by the original fragment, this reaches the original selector at `0x600619BC`.

Bounded virtual dispatch traverses that BLX and executes the selector. Synthetic H=0 plus the virtual initialized flags produce descriptor pointer `0x6011E45A`, length 80 and zero return status. **Internal event 12 is not USB bRequest 12.** Physical request-to-event translation and on-controller invocation remain unmeasured.

## Initial flag stores

`0x6007408C..0x6007409E` derives `R3=base+0x433C`. Original `STRB R5,[R3,#8]` at `0x6007409A` targets A=`0x2000A804`; `STRB R5,[R3,#9]` at `0x6007409C` targets B=`0x2000A805`. R5 is set to zero by `0x60073EA4 MOVS R5,#0` in the metadata fragment.

The writer test is a **separate fragment** carrying that synthetic R5 zero. Intervening code is not executed. The test starts A/B at `A5/5A` and observes both original stores produce zero. It does not establish physical values or exclude later/aliased/wide/block writes.

## Explicit emulation boundaries

1. Metadata fragment `0x60073E44..0x60073EF4`, starting from synthetic four-record-loop exit state. The 48 bytes of class records are zero-filled fixtures, **not OEM class records**.
2. Flag-writer fragment `0x6007408C..0x600740A0`, separately executed.
3. Original dispatch from `0x60060D54` with synthetic internal event 12, through the indirect selector call and return.

Initialization clear/copy helpers are no-op stubs returning unchanged R0; their memory effects are not reproduced. Singleton lookup, H and logging are also stubbed. Instruction bounds, expected execution ranges, output checks and relevant original-store observations constrain the run.

```powershell
python -m tools.audit_usb_provider_phase63 local/bruce.bin --out local/phase63.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_usb_provider_phase63 -v
```

Requires `requirements-emulation.txt` and the separately obtained exact OEM sample. The auditor enforces image SHA, semantic anchors, literals and the event-table entry. Negative tests alter the method pointer, flag store and event-12 table entry and confirm rejection. All **724 local tests** pass with original-image fixtures enabled. Dedicated CI reproduces this phase's evidence against the pinned image. No OEM binary is published.

## Remaining boundary

Configuration/provider producers are now identified in this initializer. The four record-producing objects, their selectors and later owner changes remain unresolved. **Active internal class 10 is not demonstrated.** The physical descriptor match does not prove every constructed RAM field matches installed state.

No device commands, firmware changes, on-controller custom execution, HAB bypass or native console interoperability occurred. Next: resolve the four producers invoked at `0x60073DFC`; never interpret this experiment's synthetic zero records as OEM evidence.

[Evidence](../../evidence/usb-provider-phase63.json) · [Auditor](../../tools/audit_usb_provider_phase63.py)
