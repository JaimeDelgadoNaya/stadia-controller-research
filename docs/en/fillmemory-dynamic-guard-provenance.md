# Signed Stadia FillMemory runtime-guard initialization

**25 October 2026 — original-image offline investigation only.** The signed
100,672-byte RAM loader was verified by SHA-256
`c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`.
No controller connection, memory request, RAM/flash write or HAB change occurred.

## Exact signed-image chain

The FillMemory guard at `0x20003B30` loads the global RAM object at
`0x202081F4`. The object's `+0x0C` field points to a provider table
at `0x20016074`; the table's `+0x10` field references RAM
`0x20212CD0`. The guard reads four words at context offsets
`+0x70/+0x74/+0x78/+0x7C`.

The **initializer function `0x20009904`** is referenced through Thumb
entry `0x20009905` at `0x20016078`. Its four literal loads and
stores have been verified against the original binary:

| Context offset | Store instruction | Initialized value |
|---|---|---|
| `+0x70` | `0x2000992C` | `0x20002000` |
| `+0x74` | `0x20009934` | `0x20016D08` |
| `+0x78` | `0x2000993A` | `0x20208000` |
| `+0x7C` | `0x20009946` | `0x20216FFF` |

**The static function is proven; its execution on the physical controller
and possible later setters have not been verified.** The context is
outside the loader's `0x830`-byte fixed startup RAM copy.

## Modeled implication, not a working exploit

With those four initializer values, the symbolic model of the guard
rejects an ordinary 4-byte write to the Execute/Call table fields.
Certain 32-bit end-address-wrap cases that pass the earlier two static
range comparisons are **not rejected by this modeled guard**.

This does **not** demonstrate memory write success, arbitrary execution,
a HAB bypass or recovery. Such cases imply roughly 3.5 GiB of attempted
write operations, far exceeding the declared RAM region
`0x20000000..0x2001FFFF`. The actual fill backend loops over the
entire requested length, and a safe return has not been shown. The
runtime RAM guard fields have not been measured.

A linear store-offset inventory also finds three unrelated store
candidates; their aliases and reachability have not been established.

## Offline reproducibility

```sh
python -m unittest tests.test_fillmemory_dynamic_guard tests.test_fillmemory_init_limits -v
python -m tools.audit_fillmemory_dynamic_guard local/restricted_ivt_flashloader.bin --summary
python -m tools.audit_fillmemory_init_limits local/restricted_ivt_flashloader.bin
```

[Original-image CI check](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40236085352).

**Next defensible work:** independently trace whether the initializer is
called before FillMemory dispatch, and test bounded backend effects in a
no-hardware emulator. Do not issue an experimental huge fill to the only controller.
