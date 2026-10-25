# Phase 23 — Bounded interprocedural pointer handoffs

**Sample:** private 128 KiB Stadia bootloader A, build 169429,
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
Everything remains **offline**; no firmware binary is published or device
accessed.

## Four verifiable global-object calls

Each Thumb16 `LDR R0,[PC,#imm]` reads a literal containing the global
RAM pointer `0x20008B78`. The following direct `BL` target is decoded
from the actual bytes:

| Global load | BL site | Target |
|---|---|---|
| `0x6080C0B2` | `0x6080C0B4` | `0x6080BAC0` (constructor) |
| `0x60802502` | `0x60802504` | `0x6080B218` |
| `0x60808136` | `0x60808138` | `0x6080B218` |
| `0x6080FB4A` | `0x6080FB4C` | `0x6080B17C` |

These are **code-level pointer handoffs**, not verified host USB opcodes.

## Derived subobjects in `0x6080B17C`

That function saves the global pointer in `R4` and prepares four
immediate-derived `R0` arguments in a straight-line series, assuming
preceding calls return normally and preserve the ABI's callee-saved R4.

| BL site | R0 argument | Target |
|---|---|---|
| `0x6080B186` | global `+0x568` | `0x6080A990` |
| `0x6080B18E` | global `+0x560` | `0x608022A0` |
| `0x6080B196` | global `+0x630` | `0x6080990C` |
| `0x6080B19E` | global `+0x578` | `0x60809D98` |

Separately, `0x6080B218` adds `+0x630` to `R0` and
branches directly to `0x60809ABC`. There, an additional
`+0x14` is applied before the first call at `0x60809AC2`
to `0x60809688`: hence the derived argument **global `+0x644`**
on that static path.

These subobject arguments differ from the vendor completion fields
`global+0x5F8` (IN) and `global+0x600` (OUT), but this **does
not prove** that callee bodies lack aliases or later setters.

## Scope and reproducibility

`tools/audit_interprocedural_aliases.py` validates the whole-image
SHA-256, exact instruction anchors, literal sources, decoded direct
`BL` and `B.W` targets. Sixteen synthetic regression tests avoid
publishing copyrighted firmware.

```sh
python tools/audit_interprocedural_aliases.py local/bootloader-a.bin --out local/phase23.json
python -m unittest discover -s tests -v
```

The tool proves selected **conditional static pointer-flow edges** only;
it does not follow unknown callee effects, resolve runtime branches,
show host-USB reachability, prove a flash-write route or bypass
HAB CLOSED. No controller modification or custom firmware execution
occurred.

**Next (phase 24):** bounded store/provenance inspections of the four
callees, followed by assessment of actual callback registration
and authentication.
