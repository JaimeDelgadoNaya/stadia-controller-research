# Signed Bruce USB SETUP / class request provenance (#35)

**2026-10-26. Offline only.** Sample: signed OEM Bruce **update image**, exactly 1,050,984 bytes, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Not a physical flash dump or measured active runtime VTOR.

## Results verified against actual signed ARM Thumb bytes

- **SETUP-like input field triad** in the routine at `0x600D08E8`: `0x600D08EE` copies argument R1 to R4; `0x600D090E` reads R4+1; `0x600D091A/1C` reads and masks R4+0 (recipient); `0x600D0922` reads R4+2 (wValue); `0x600D0958` reads R4+4 (wIndex). The host EP0 callback/physical buffer provenance is **not yet fully connected**.
- **Bounded standard interface request branch** at `0x600D0D3C...` reads byte +0, masks recipient `0x1f`, checks interface recipient `1`, reads +4 (wIndex) and +1 (bRequest). At `0x600D0D52..58` it subtracts 1, checks against 10 and uses a TBB. This branch supports the limited case IDs **1–11**, not direct `0x81/0x83/0x84` in that particular branch.
- **Conditional class request forwarding branch** at `0x600D0EA2..0x600D0EBE`: obtains SETUP-like buffer pointer from `[R2]`; checks request recipient interface and matches `[buffer+4]` against object field `[R0+0x0D]`; puts `[buffer+1]` (bRequest) into **R1**; dereferences a function pointer via `[R0+4]` and `BX R3`. The host **does not directly supply the branch address** in this code. The installed class handler and whether OEM `0x81/0x83/0x84` reach it remain unknown.
- By contrast, `0x600CFCDA` is an endpoint **descriptor-table** byte +1 load with mask `0x30`, not proven bRequest. One-byte offset alone is not a valid provenance argument.

## Exact class table / initializer boundary

Signed flash contains neighboring **data** words (not decoded as instructions):

| Flash XIP address | Word | Candidate role |
|---|---|---|
| `0x60104BA4` | `0x60055321` | Function `0x60055320` |
| `0x60104BA8` | `0x600D0ECB` | Function `0x600D0ECA` |
| `0x60104BAC` | `0x600D0E59` | Class request dispatcher `0x600D0E58` |
| `0x60104BC4` | `0x6005556D` | **Different** table |

Function `0x60055320` receives a callback pointer in R1 and stores it into a global object's field +4 at `0x6005533A`, after using the `0x60055024` helper. **This does not prove the host controls the pointer or that it is the same object used by the class request branch.**

At `0x600553BA`, **function `0x60055350` loads a literal at `0x600553FC`, which is `0x60104BC4`, NOT `0x60104BA4`**. The value is saved in object +4 at `0x600553C0` and its first method is called through `BLX`. Keep these two table sources separate. The other literal at `0x600553F8` equals RAM address `0x200063C0`. A bounded full-image 32-bit literal scan found **one** direct word reference to `0x60104BC4` (offset `0x153FC`), **zero** to `0x60104BA4`. Computed, relocated, indirect or synthesized references remain possible.

## Reproduction and next blocker

```sh
python -m unittest tests.test_bruce_control_setup tests.test_bruce_setup_verified tests.test_bruce_class_vtable -v
python -m tools.audit_bruce_control_setup original_signed_bruce.bin --out /tmp/control-census.json
python -m tools.audit_bruce_setup_verified original_signed_bruce.bin --out /tmp/setup-verified.json
python -m tools.audit_bruce_class_vtable original_signed_bruce.bin --out /tmp/vtable-verified.json
```

The existing isolated GitHub Actions job verifies original SHA-256, runs the auditors using **transient** OEM files and deletes them afterward. No hardware IO, firmware writing, eFuse operations or source binary distribution.

**Next blocker:** locate which code **instantiates/registers the table containing `0x600D0E59`**, then resolve the function passed into the class object (and finally the `0x81/0x83/0x84` semantics). The static path is not proof of arbitrary code execution, HAB CLOSED bypass, rollback safety or native Xbox/Switch 2 firmware.
