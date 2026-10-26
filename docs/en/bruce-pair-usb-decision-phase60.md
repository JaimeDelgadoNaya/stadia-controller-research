# Phase 60 — Decision on possible USB-controlled callback pair

**26 October 2026.** Offline audit of exact SHA-256-pinned, original signed Bruce OEM update `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`.

## Research question and constraints

Phase 58 established original signed conditional **function/context** writes at `0x2000FBF4` (base `0x2000F878+0x37C`) and `0x2000FBF8` (base +`0x380`). The pair may contain a no-op signed Thumb pointer `0x600CE233` with null context, or the ITCM pointer `0xA9C5` with a dynamic object context. Phase 59 resolved the actual XIP work routine to `0x6007E6A0`.

Phase 60 asked whether any code could be proved to **read/invoke this specific pair**, especially through a USB event.

## A. Bounded computed-alias investigation

Ten original signed PC-relative literal load candidates reference the exact global base `0x2000F878`. The phase 60 tool follows register identity and arithmetic **only within straight-line windows**, stopping at branches, calls and clobbers.

Verified original signed results: **10 starting loads**, **two expected original writes** (`0x60063878` to `0x2000FBF4`, `0x6006387E` to `0x2000FBF8`) and **zero substantiated reads** of those fields in these windows. The tool fails closed unless all ten base load candidates and the two known writer controls are recovered.

This is **not a whole-program absence proof**: cross-function aliases, merged CFG branches, pointer tables, indirect loads, and physical runtime state are not covered.

## B. Original signed callback/handler references

An aligned-word scan finds **37 exact Thumb-shaped pointers**:

| Pointer | Count | Interpretation |
|---|---:|---|
| `0x600CE233` | 35 | Signed no-op XIP entry `BX LR` |
| `0x0000A9C5` | 1 | Signed ITCM veneer towards object-associated worker |
| `0x6007E6A1` | 1 | Signed XIP target literal of `0xB980` veneer |

A signed XIP/relocated ITCM scan found **no instruction-shaped direct `BL` to the four studied targets**. This is **not proof against** indirect `BLX/BX`, tables or other event handlers; code/data ambiguity and unreachable decoded instruction shapes remain.

## Go/no-go decision

**DEPRIORITIZE this global pair as a host-controlled code execution route**, unless fresh evidence ties a particular real host USB event to a consumer of the pair.

There is no established invoker of `0x2000FBF4/FBF8`, no proven host-triggered path, no installed RAM values, no class10 runtime activation, and no custom firmware execution or HAB CLOSED bypass. **Deprioritize does not mean impossible**.

### Practical next experiment

Capture actual **read-only USB enumeration/descriptors** from a physical Stadia controller using Windows USBView/USB Device Tree Viewer. For existing enumeration traffic, observe USBPcap/Wireshark without sending vendor-specific commands, changing boot mode, writing firmware or eFuses. Remove serial numbers or other unique IDs before sharing. This can verify exposed interfaces/endpoints, **not** callback pointer or SRAM state.

An external Stadia→Xbox bridge should be evaluated in parallel as a potentially more achievable route, while acknowledging Xbox authentication requirements.

## Reproduce

```bash
python -m unittest tests.test_bruce_pair_event_phase60 -v
python -m tools.audit_bruce_pair_event_phase60 local/bruce_pvt_a_prod_signed.bin --out local/phase60-pair-event.json
```

[PR #62](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/62) · [Evidence](../../evidence/bruce-pair-event-phase60.json) · [Original signed OEM verification](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40371183749).

No USB commands, installed RAM reads, flash writes or eFuse actions.
