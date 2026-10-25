# Storage mapping and bounded wrapper emulation — phase 11

[Español](../es/almacenamiento.md) · [Full handoff](handoff.md)

Scope: static analysis of the same build/hash, plus isolated emulation. There
was no controller access, physical write or new firmware execution in this phase.

## Descriptor 0x12 is the shared IVT block

The global constructor at `0x6080BAC0` receives the aggregate object rooted at
`0x20008B78`. The setup fragment around `0x6080BD50..0x6080BDCA` constructs the
descriptor with ID `0x12`, storage object at root+`0xA78` (`0x200095F0`), first
block 1 and block count 1. `0x6080BD8E` loads its plain-storage vtable address
`0x60815300`; `0x6080BD94` stores that pointer into the object.

The device pointer is root+`0x3BC` (`0x20008F34`). Its constructor is called with
root+`0x2C`; stores at relative offsets `0x394` and `0x398` set block size and
device block count to `0x1000` each. Its base offset and base block index are zero.
The device address mapper at `0x60808A50` adds `0x60000000` to a flash offset.

The translation at `0x6080AA66` therefore gives:

```text
flash_offset = (partition_first_block - device_first_block) * block_size
               + device_base_offset + partition_offset
             = (1 - 0) * 4096 + 0 + partition_offset
mapped_address = 0x60000000 + flash_offset
```

For partition offset zero, descriptor `0x12` maps to **`0x60001000`**, size
**4096 bytes**. This agrees with the shared IVT addresses seen in authentication.

## Resolved virtual methods

| Plain storage vtable `0x60815300` offset | Target | Role inferred from code |
|---|---|---|
| `0x00` | `0x6080AB4C` | Erase wrapper, delegating block count |
| `0x04` | `0x6080AB10` | Read wrapper |
| `0x08` | `0x6080B0F0` | Write wrapper |
| `0x0C` | `0x6080B036` | Blank/content check |
| `0x10` | `0x6080AFE4` | Alignment/geometry byte getter |
| `0x14` | `0x6080AA3C` | Partition block-count getter |

The physical device vtable is `0x60815320`. The read target is `0x60808ACC`,
erase target `0x60808C00`, write target `0x60808E38`, and address mapper
`0x60808A50`. The erase routine loops over blocks using the device block size.
Its controller-level details and power-loss behavior were not exhaustively audited.

## Second arithmetic observation and its scope

The shared bounds helper `0x6080AA7C` computes `offset + length` in 32 bits and
compares it with `partition_block_count * device_block_size`. The write wrapper
calls it before translating the offset and delegating to the physical device.

`tools/emulate_storage.py` executes the recorded wrapper, bounds helper,
translator and block-count getter in an isolated ARM emulator. It constructs
the IVT object using the statically traced geometry. **The physical writer is
intercepted and mocked to return success; it is never executed.** A bounds-error
case stops at the diagnostic branch rather than emulating logging or claiming
a particular completed error return.

| Synthetic invocation | Observed delegation |
|---|---|
| Actual IVT call: offset 0, length `0x1000` | Flash offset `0x1000`, same source and length |
| Offset `0x1000`, length 1 | Bounds-error branch, no backend call |
| Offset 0, length `0x1001` | Bounds-error branch, no backend call |
| Offset `0xFFFFFFF0`, length `0x10` | Flash offset `0xFF0`, length `0x10`, delegated to mocked backend |

The last case demonstrates out-of-partition **delegation in a constructed
context**, not a real flash write. The reviewed IVT update caller supplies fixed
offset zero and length `0x1000`, not this synthetic offset. External control of
such parameters, final device acceptance, memory corruption and any signature
bypass have not been established. Flash writes and authenticated execution are
separate questions; crossing a partition boundary alone does not solve HAB.

```sh
python -m pip install -r requirements-emulation.txt
python tools/emulate_storage.py
python -m unittest discover -s tests -v
```

The four recorded cases are in [storage-emulation.json](../../evidence/storage-emulation.json).
