# IVT update flow and isolated ARM validation — phase 10

[Español](../es/actualizacion.md)

This phase analyzes the same extracted bootloader build 169429. It performs no
device access or persistent update. Addresses and labels below apply only to
the recorded image hash. Storage-method names are inferred from their call
arguments and surrounding messages; concrete backend implementations remain
to be traced.

## The update callback is a power/input guard

The caller at `0x608028B4` loads function pointer `0x6080285D`, and passes it to
`0x60801ED0` from `0x608028C6`, with context argument `0x200090D8`. The constructor
at `0x60801CC8` stores that callback and its argument in the temporary update
context. The indirect call at `0x60801E58` therefore resolves to the Thumb thunk
at `0x6080285C`, which branches to `0x608022FC`.

`0x608022FC` first calls `0x608021B4`. The latter references
`lightweight_power_manager.cc`, “Issues reading voltage” and “Voltage is”, reads
a 16-bit value and compares it with `0x0D4C` (3404). The units and conversion have
not been independently traced. A nonzero result stops the update. If it returns
zero, the callback reads a hardware-input bit and returns the inverted bit as a
boolean. The exact physical input has not been identified.

This callback is a guard, not a callback that copies the whole candidate image.
Its address is supplied as a constant in the traced caller; this is not evidence
of an externally controlled function pointer.

## Current and candidate slots are selected explicitly

`0x60801DD4` calls `0x60807E64`, which consults the shared IVT entry at
`0x60001004`. In the subsequent branch, current partition ID `0x03` selects
candidate base `0x60820000` and descriptor ID `0x13`; current ID `0x13` selects
candidate base `0x60800000` and descriptor ID `0x03`. These are bootloader
partition identifiers, not an assertion about application-slot IDs.

The current bootloader is authenticated first. The opposite candidate then
receives the structural-only check documented in phase 9. A blank candidate B
does not supply a valid vector table, so the measured blank slot should not be
treated as an immediately usable fallback. No candidate was installed or changed.

## IVT buffers, fixed transfer counts and restoration

The update context selects storage descriptor ID `0x12`. Messages identify this
operation as IVT installation. The observed argument flow is:

| Step | Evidence | Value or action |
|---|---|---|
| Preserve existing IVT | `0x60801E36..0x60801E42` | Read-method call with buffer `0x200029C8`, offset 0, length `0x1000` |
| Select candidate descriptor | `0x60801E4A..0x60801E50` | Opposite bootloader descriptor from the partition table |
| Run guard | `0x60801E54..0x60801E5C` | Resolved power/input callback must return zero |
| Read candidate IVT | `0x60801D9C..0x60801DAE` | Read-method call with buffer `0x200019C8`, offset 0, length `0x1000` |
| Install candidate IVT | `0x60801D40..0x60801D98` | Preparation/query methods, then write-method call with offset 0 and length `0x1000` |
| Authenticate after operation | `0x60801E80..0x60801E8C` | Candidate validator called with authentication flag 1 |
| Attempt restoration on relevant failure | `0x60801E9A..0x60801EA2` | Calls the same IVT writer with preserved buffer `0x200029C8` |

The candidate-IVT read failure returns `0x0A` before the IVT write; the caller
has a separate early-return path for that result. Other installation failures
and post-operation authentication failures lead toward the restoration path.
This is evidence of restoration logic, **not** a guarantee of recovery from
power loss or failure in the storage backend. The backend's physical erase
granularity and complete behavior remain unverified.

The reviewed read/write calls use a fixed **4096-byte length argument**.
The boot-data length inspected by the arithmetic range helper has not been
found to replace that argument in this path. Consequently, the observed
arithmetic behavior alone does not establish an oversized IVT copy.

## The arithmetic result is now instruction-level reproducible

The public evidence contains the original helper's 36 instruction bytes at
`0x60801FE6`, SHA-256
`29d8988e80bc7a4292ead2e4c029ae437ce0f7220eb66962f10a2c0c3a3eb3ce`.
`tools/emulate_range_check.py` checks that fingerprint and executes only those
bytes in a bounded Unicorn ARM/Thumb M-class emulator with isolated memory.

All eight cases agree with the Python model. The real instructions accept the
wrapped-range witness and also accept a zero-sized range starting inside the
interval. They reject the tested normal out-of-bounds cases. Results and
instruction counts are in [range-emulation.json](../../evidence/range-emulation.json).

```sh
python -m pip install -r requirements-emulation.txt
python tools/emulate_range_check.py
python -m unittest discover -s tests -v
```

This demonstrates the isolated helper's arithmetic, not whole-program
reachability, a device exploit, an arbitrary write or a signature bypass.

## Next boundary to resolve

Resolve the storage virtual methods and the concrete mapping of descriptor
`0x12`, then trace whether malformed boot-data can affect any operation other
than preliminary validation. The signed authentication path and the fixed IVT
transfer counts are existing constraints any proposed execution path must explain.
