# FillMemory — initializer boot ordering and first declared RAM boundary

**25 October 2026 · Read-only original-loader audit.** This phase uses the
original signed 100,672-byte `restricted_ivt_flashloader.bin`, SHA-256
`c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`.
No USB/HID commands, real RAM writes, flash changes, or eFuse operations.

## Was the signed protection initializer called before FillMemory dispatch?

The initializer `0x20009904` is registered as Thumb pointer
`0x20009905` at `0x20016078`, in the second slot of provider
table `0x20016074`. The table pointer is copied into initial RAM
global `0x20208200`. A pinned-image search finds just one aligned
literal occurrence of each pointer; a non-exhaustive Thumb disassembly
scan detects no **direct** call to the initializer.

Because the call can be made **indirectly** from the provider table,
the absence of a direct call does **not** prove it never runs. More
importantly, it does **not establish initialization before command
dispatch** on a physical gamepad. This temporal relationship remains
unverified. The current audit confirms registration, not dynamic reachability.

## Which writes would the enormous wrapped-length backend attempt?

The actual signed fill routine at `0x20002698` checks length and
address alignment. For the two word-aligned control fields, the
`CMP R2,#4` and **signed** `BLT` at `0x200026C2..0x200026C4`
take the byte-write remainder branch when the supplied uint32 count
has its high bit set. The function executes a `STRB` loop at
`0x200026FC..0x2000270A`. The fast `STM` path is **not** used for
these enormous initial counts.

The hash-verified offline model computes the first address beyond the
loader's **declared** `0x20000000..0x2001FFFF` RAM map entry,
**without** actually writing billions of bytes:

| Hypothetical start | Requested bytes | Bytes within declared region | First outside |
|---|---:|---:|---|
| `0x200159E0` (Execute flag) | 3,758,016,036 | 42,528 | `0x20020000` |
| `0x200159EC` (Call flag) | 3,758,016,024 | 42,516 | `0x20020000` |

**First outside a declared map entry does not imply a physical bus
fault.** The model does not represent bus aliases, RAM controllers,
interrupts, runtime initialization, or safe recovery. It writes at
most 64 bytes to a disposable process-local preview buffer and none
to controller memory.

## Decision

The conditional 32-bit range-wrap observation is reproducible, but
**no effective restricted-memory write, safe return, custom code
execution, HAB bypass or recoverable firmware modification is shown**.
Do not send enormous FillMemory commands to the only physical controller.

Offline reproduction:

```sh
python -m unittest tests.test_fillmemory_first_boundary -v
python -m tools.audit_fillmemory_init_flow local/restricted_ivt_flashloader.bin --preview
python -m tools.audit_fillmemory_first_boundary local/restricted_ivt_flashloader.bin
```

[Original signed-loader CI run](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40237237957).


## Original-code Unicorn emulation of the first virtual write fault

The signed image's **actual** low-level routine at `0x20002698` was
executed under **Unicorn 2.1.4 (ARM Thumb/M-class)** with just
`0x20000000..0x2001FFFF` mapped as **virtual** RAM, plus a return
sentinel at `0x00001000`. The code image was loaded from the pinned
original (SHA-256 checked) and called with **synthetic arguments**.

This is a **backend-only** simulation. It deliberately does not emulate
the USB command, initialization order, original guard functions, hardware
bus map, flash, or HAB.

| Hypothetical start | Byte stores within virtual RAM | First attempted virtual unmapped write | PC | Returned? |
|---|---:|---|---|---|
| `0x200159E0` | 42,528 | `0x20020000` (one byte) | `0x20002700` | No |
| `0x200159EC` | 42,516 | `0x20020000` (one byte) | `0x20002700` | No |

Both cases stopped with Unicorn's **`UC_ERR_WRITE_UNMAPPED`** while
`R2 = 3757973508` bytes remained. Machine-code emulation confirms
the signed `BLT` enters the repeated `STRB` byte loop and does not
return before leaving this virtual region.

**This is not a physical BusFault measurement or proof of code
execution, command reachability, persistence, or recovery.** Additional
SoC memory mapping or aliases could change actual hardware behavior.

[Original-image offline CI emulation](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40237699575).

```sh
python -m pip install -r requirements-emulation.txt
python -m tools.emulate_fillmemory_first_fault local/restricted_ivt_flashloader.bin
```
