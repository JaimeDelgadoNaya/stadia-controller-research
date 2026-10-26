# Phase #39 — class 10 callback R1 argument provenance in signed Bruce

**2026-10-26 · offline read-only.** Exact original signed Bruce **update archive**, size 1,050,984 bytes; SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. Not a live controller flash dump or verified running SRAM.

Phase #38 established that class ID **10**, not 4, has first method `0x60055320` and SETUP event method `0x600D0E58`. This phase traces the **R1 input of the first method** through the class configuration loop using **32 machine instruction semantic anchors** checked against the original signed image.

## Verified conditional signed code path

| Original PC | Machine behavior |
|---|---|
| `0x600550EA` | Preserve configuration function's incoming R1 as R4 |
| `0x6005512E` | Store R4 at `[R5+4]`, conditional initialization |
| `0x60055178` | Load R3 = `[R5+4]` |
| `0x6005517A` | Load R1 = `[R3]` (12-byte record array base) |
| `0x60055174` | Multiply interface index by 12 |
| `0x60055180` | Add byte offset to R1: `R1 = [original_R1]+12*interface_index` |
| `0x60055184/86` | Load interface descriptor at record `+8`, then class ID at descriptor `+4` |
| `0x60055182/88` | Compare class ID against ROM class registry selector `+12` |
| `0x6005518C–94` | Select method `+0` and invoke via `BLX R3`, passing `R1=record`, `R2=record+4` |
| `0x60055324` | Class 10 constructor saves the record pointer in R6 |
| `0x6005533A` | Stores record pointer into class global object's field `+4` on its successful path |
| `0x600D0EB6–BE` | Class SETUP forwarder later dereferences the stored record pointer's first word as a callback and branches indirectly |

Thus **the class10 constructor is passed an application configuration-record pointer**, not an arbitrary address directly derived from USB `bRequest`. Potential layout: record `+0` might be the callback function pointer (its **writer and real value remain unknown**); record `+4` is the class object output; record `+8` is an interface descriptor pointer.

The exact signed literal addresses `0x20004080` (configuration state) and `0x200040E0` (class10 global object) occur in OEM XIP data. They do **not** establish their live contents.

## Search results and limits

An aligned 32-bit literal census returned **zero** references to Thumb `0x600550E5` (configuration dispatcher); **one** to `0x60055321` (class10 initializer) and **one** to `0x600D0E59` (class10 setup forwarder), in the original static registry. RAM literal `0x200040E0` occurs **once**, and `0x20004080` occurs **five** times. A bounded linear XIP search for direct `BL` callers found zero for several targeted functions. **No conclusion of non-reachability follows**: class-table and calculated indirect calls are explicitly used in the original code.

The last missing source is **who populates record `+0`** and who supplies the configuration object (incoming R1 of `0x600550E4`). Next bounded investigation: find builders/writers of 12-byte interface callback records, then establish whether the callback address is preselected by signed application code.

**Not proven:** actual physical class10/EP0 activation, requests `0x81/0x83/0x84` reachability, USB-host-controlled callback pointer, user firmware execution, secure-boot HAB bypass, safe rollback or native Xbox/Switch 2 interoperability. No device IO or writes were attempted.

```sh
python -m unittest tests.test_bruce_class10_r1_origin -v
python -m tools.audit_bruce_class10_r1_origin local/bruce_pvt_a_prod_signed.bin --out local/class10-r1.json
```

CI pins original signed SHA, downloads only to temporary storage, runs offline and deletes its inputs and output JSON.

[PR #39](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/39).
