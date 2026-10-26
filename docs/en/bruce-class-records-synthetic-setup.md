# Phase #37 — signed Bruce class record layout and bounded USB SETUP execution

**26 October 2026. Original signed OEM Bruce UPDATE image only, not installed-flash readback.** Size 1,050,984 bytes, SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`. No physical controller operations.

## Signed class table — phase #38 correction (2026-10-26)

**Erratum:** The earlier interpretation placing the selector at the first word was **wrong**. Signed Bruce Thumb at `0x60055142` and `0x600551CC` loads the **table base `0x60104B74`**, and both selector loops use **16-byte strides**, reading the selector from **offset +12**. The correct five entries are:

| Actual record start | Method +0 | Method +4 | Method +8 | Selector +12 |
|---|---|---|---|---|
| `0x60104B74` | `0x600552F1` | `0x600D0DFD` | `0x600D0C6B` | 1 |
| `0x60104B84` | `0x60054C7D` | `0x60054D09` | `0x60054A55` | 2 |
| `0x60104B94` | `0x60054875` | `0x600D0591` | `0x600D0333` | 4 |
| `0x60104BA4` | `0x60055321` | `0x600D0ECB` | **`0x600D0E59`** | **10** |
| `0x60104BB4` | 0 | 0 | 0 | 0 |

**The `0x600D0E58` class-SETUP forwarding routine belongs to class selector 10, not 4.** Previous claims about class 4 are superseded. The original signed-code Unicorn experiment in this phase started *after* event selection and used a synthetic callback object, so that specific experiment remains valid regardless of the record interpretation.

Phase #38 separately emulates the original selector, with synthetic descriptors: class 4 selects `0x60054875`, and class 10 selects `0x60055321`, stopping before either method executes. See [corrected phase #38 report](bruce-class-selector-phase38.md). Physical EP0 selection remains unmeasured.

## Original machine-code emulation

The **actual** signed ARM Thumb branch at `0x600D0EA2..0x600D0EBE` was executed using Unicorn 2.1.4, with *synthetic* class objects, RAM pointers and eight-byte SETUP input. The emulation **started after the event-selection dispatch**; it does not simulate real USB EP0, hardware state, or the callback registration code.

The emulator stops **before** `BX R3`, so **no callback function is executed**:

| Synthetic type + request + interface | Outcome | Stop PC | R1 before callback |
|---|---|---|---|
| `A1 / 81 / 1` | Forwarding conditions met | `0x600D0EBE` | `0x81` |
| `21 / 83 / 1` | Forwarding conditions met | `0x600D0EBE` | `0x83` |
| `A1 / 84 / 1` | Forwarding conditions met | `0x600D0EBE` | `0x84` |
| `A0 / 81 / 1` | Rejected (recipient mismatch) | `0x600D0E76` | — |
| `A1 / 84 / 2` | Rejected (interface mismatch) | `0x600D0EC6` | — |

On the three valid synthetic calls, `R3` contained the **artificial, nonexecuted callback pointer** `0x20003001`; `R1` held the original request code. The real branch therefore **passes** the request byte to the class callback if the prerequisite event and class-object conditions are artificially provided. It does not itself filter these particular `bRequest` values.

**Not demonstrated:** real-host reachability, installed EP0 class object, physical callback target or permissions, arbitrary execution, HAB CLOSED bypass, safe firmware recovery or direct Xbox/Switch 2 behavior.

## Reproduce entirely offline

```sh
python -m pip install -r requirements-emulation.txt
python -m unittest tests.test_bruce_class_object_origins tests.test_bruce_class_request_fragment -v
python -m tools.audit_bruce_class_object_origins local/bruce_pvt_a_prod_signed.bin --out /tmp/class-origins.json
python -m tools.emulate_bruce_class_request_fragment local/bruce_pvt_a_prod_signed.bin --out /tmp/virtual-setup.json
```

CI downloads the SHA-locked public OEM update only to ephemeral disk, runs the read-only analyzers, removes the temporary data and does not connect to hardware or execute any generated user code.

**Next gate:** trace how class selector 10 is instantiated for the actual device and which **actual runtime class callback** it would install for EP0. Until a host-reachable and recoverable code-execution path is independently demonstrated, do not try physical writes.

[PR #37](https://github.com/JaimeDelgadoNaya/stadia-controller-research/pull/37).
