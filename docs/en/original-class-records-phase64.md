# Phase 64 — Four original producers and internal class 10 inclusion

**26 October 2026.** Offline analysis of exact Bruce OEM SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`, following [phase 63](usb-provider-initialization-phase63.md).

## Changed conclusion

**The OEM initializer constructs the internal selector array [10, 1, 2, 4] under the modeled execution conditions.** All four producer objects/methods are identified and executed as original instructions. The records now come from the signed initialized-data image, replacing phase 63's synthetic zero triplets.

The first record contains original class10 callback **`0x600613FD`**. Bounded original selector execution reaches Thumb method **`0x60055321`**, with R1=`0x2000A274`, R2=`0x2000A278`, and stops before executing the class initializer. **On-controller class10 activation remains unmeasured.**

## Original producer paths

The initializer at `0x60073BF0` receives global base `0x200064C0`, matching phase 63's pinned caller. It constructs the objects' tables and four-pointer list. The original loop invokes each producer at `0x60073DFC`, loads its returned triplet, and copies it at `0x60073E00 STM.W`.

| Object SRAM | Original producer | Returned record SRAM | Signed record file offset | Internal selector |
|---|---|---|---|---:|
| `0x20009EF0` | `0x600613F4` | `0x200030F4` | `0xFDF5C` | **10** |
| `0x20009E00` | `0x6006262C` | `0x200031F0` | `0xFE058` | 1 |
| `0x20009E84` | `0x60061104` | `0x200030E8` | `0xFDF50` | 2 |
| `0x20009F20` | `0x60061E08` | `0x2000312C` | `0xFDF94` | 4 |

The four method-table addresses are `0x60105A5C`, `0x60105F30`, `0x60105A40`, `0x60105F1C`. Each method is an original literal load returning its record pointer, followed by BX LR. The auditor does not replace their return values.

## Signed records copied into the owner array

The 6,296-byte initialized-data source at file offset `0xFD5A8` is loaded into virtual SRAM `0x20002740..0x20003FD8`, using the previously documented startup mapping. Its SHA-256 is `85b39fa62734059a14d13a7067330fd1e1cf1570b2ad8b61eb272df00a273806`. This is image data loaded into emulation, not live SRAM or complete startup execution.

| Array destination | Original callback | Instance before class init | Internal descriptor | Selector |
|---|---|---|---|---:|
| `0x2000A274` | **`0x600613FD`** | 0 | `0x20003100` | **10** |
| `0x2000A280` | `0x000021A1` | 0 | `0x200031C4` | 1 |
| `0x2000A28C` | `0x60061249` | 0 | `0x200030A0` | 2 |
| `0x2000A298` | `0x600624F9` | 0 | `0x20003138` | 4 |

Each copied triplet is checked byte-for-byte against its signed source. Callback `0x21A1` is an ITCM execution address, not XIP. No callback executes. Original metadata stores also establish owner `0x2000A2A8` with array `0x2000A274`, method `0x60060D55`, count byte 4. Internal records and advertised USB interfaces are different structures; four records do not contradict phase 61's two interfaces.

## Original class comparison

A second bounded stage executes `0x60055170..0x60055194`, using the constructed array, original descriptors and original ROM registry `0x60104B74`:

| Original record selector | Selected Thumb method |
|---:|---|
| **10** | **`0x60055321`** |
| 1 | `0x600552F1` |
| 2 | `0x60054C7D` |
| 4 | `0x60054875` |

The singleton handoff `[singleton+4]=owner+4` and fragment register inputs are **explicitly injected**. Full USB engine setup, preceding success checks and all class initializers remain unexecuted. The hook stops before the BLX at `0x60055194`.

## Modeling limits

Execution starts at the main initializer's entry `0x60073BF0`, with synthetic R0/base and stack, and stops before `0x60073EF4`. Original producer calls, record loads/stores and metadata stores execute; loop-interior state is no longer manually imposed.

Helper `0x6013CF90` is modeled as bounded virtual-SRAM byte fill. `0x600723B4`, `0x600D9B6C`, `0x6013D3A0` are no-op stubs returning unchanged R0. Their subobject/mutex initialization and metadata-copy effects are not reproduced. Calls/arguments are recorded. This is a conditional original-flow result, not complete SoC emulation or physical observation.

```powershell
python -m tools.audit_usb_class_records_phase64 local/bruce.bin --out local/phase64.json
$env:STADIA_BRUCE_IMAGE = (Resolve-Path local/bruce.bin).Path
python -m unittest tests.test_usb_class_records_phase64 -v
```

Requires `requirements-emulation.txt` and the separately obtained exact [OEM sample](https://github.com/StadiaMemories/firmware). The auditor enforces image SHA, phase63 anchors/literals, original registry, producer semantics/literals, source triplets and selectors. Negative tests alter a producer literal, callback and selector and confirm rejection. All **729 local tests** pass with original-image fixtures enabled. Dedicated CI reproduces complete evidence without publishing firmware.

## Next boundary

Class10 **is included in this constructor-built configuration**, with an OEM-supplied callback rather than a host-chosen pointer. This resolves the previous gap between a present signed class10 record and the constructed array. It does not establish physical activation, USB-to-callback reachability, custom execution or HAB bypass.

Next: follow the constructed owner to the actual engine call and success conditions, especially class10 instance initialization. Then connect physical events to invocation. No device commands, firmware/eFuse writes or mode changes occurred.

[Evidence](../../evidence/usb-class-records-phase64.json) · [Auditor](../../tools/audit_usb_class_records_phase64.py)
