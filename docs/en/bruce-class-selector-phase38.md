# Phase #38 — actual signed Bruce class registry selection: class 10, not class 4

**26 October 2026. Offline only.** The exact original Google signed Bruce **update image** is checked by SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`, length 1,050,984 bytes. Not a readback of installed controller flash.

## Correction to phase #37

The previous phase interpreted the first word of each 16-byte record as a selector. **That was wrong.** Two original Thumb instructions at `0x60055142` and `0x600551CC` load PC-relative literals at `0x600551B4` and `0x60055220`. Both literal values are **`0x60104B74`**. Original code at `0x60055178..0x6005519A` scans entries of length **16 bytes**, comparing the selector at **record +0x0C** and loading a method pointer from record +0 for indirect invocation; it increments by 16 until offset 0x50. Another selector-related loop at `0x600551FC..0x6005521A` loads method at +4 from the same table. A related routine computes `index << 4` at `0x600552D0`.

### Five signed ROM records (method+0/+4/+8, selector+12)

| Record base | Method +0 | Method +4 | Method +8 | Selector +12 |
|---|---|---|---|---:|
| `0x60104B74` | `0x600552F1` | `0x600D0DFD` | `0x600D0C6B` | 1 |
| `0x60104B84` | `0x60054C7D` | `0x60054D09` | `0x60054A55` | 2 |
| `0x60104B94` | `0x60054875` | `0x600D0591` | `0x600D0333` | 4 |
| `0x60104BA4` | `0x60055321` | `0x600D0ECB` | **`0x600D0E59`** | **10** |
| `0x60104BB4` | 0 | 0 | 0 | 0 |

**The existing signed class SETUP `bRequest` forwarder at `0x600D0E58` belongs to selector 10, NOT selector 4.** Both original machine-code table accesses and the actual signed words are pinned by semantic tests. Phase #37's report and evidence have been corrected.

## Actual machine-code selector emulation

Unicorn 2.1.4 executes only the genuine signed `0x60055178..0x60055192` snippet with synthetic RAM objects, configuration descriptors and IDs, stopping **before the `BLX R3` method call**:

| Synthetic selector | ROM entry chosen | Result |
|---|---|---|
| 4 | class 4 | Match, first method `0x60054875` in R3 |
| 10 | class 10 | Match, first method `0x60055321` in R3 |
| 10 | class 4 | Mismatch, no method called |
| 4 | class 10 | Mismatch, no method called |

13 original instructions execute in each matching case; **no class method executes**. This establishes the static table/index/conditional selection mechanism, not that the physical controller enables class 10.

Phase #37 independently showed the original signed class-request forwarding suffix can pass synthetic `bRequest 0x81, 0x83, 0x84` to a synthetic callback. The two emulations do **not** form a complete, host-reachable execution chain; there is no verified real EP0 instance, live callback, hardware access or arbitrarily chosen branch target.

## Static data and remaining questions

The boot-copied initialized RAM data (source `0xFD5A8`, destination `0x20002740`, length 6,296 bytes) does not directly contain aligned words for the class-10 methods or class table base. That does not imply non-use: the **base is directly present in signed XIP code literal pools**, which prior scans targeting mistakenly inferred `0x60104BA4` did not cover.

**Unresolved:** whether the tested physical Stadia controller installs selector 10, which pointer argument is passed to its first method `0x60055320` and what its first word contains, whether OEM `0x81/0x83/0x84` actually reaches that class callback, firmware custom execution, HAB CLOSED bypass, recovery and direct Xbox/Switch 2 interoperability.

**Next bounded task:** trace the original class-10 initialization's R1 data argument and the function word `[R1]`, not speculative writes to the real controller.

## Offline reproduction

```sh
python -m pip install -r requirements-emulation.txt
python -m unittest tests.test_bruce_class_selector tests.test_bruce_class_selector_verified tests.test_emulate_bruce_class_selector tests.test_bruce_class_object_origins -v
python -m tools.audit_bruce_class_selector_verified local/bruce_pvt_a_prod_signed.bin
python -m tools.emulate_bruce_class_selector local/bruce_pvt_a_prod_signed.bin
```

GitHub Actions pins the original public SHA-256, runs the analyzers in ephemeral storage, deletes all OEM inputs and sends no physical USB commands or firmware writes.

[PR #38](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/38).
