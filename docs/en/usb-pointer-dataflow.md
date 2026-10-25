# Phase 22 — Bounded Thumb pointer-provenance prefixes

**Verified private sample:** 128-KiB Stadia bootloader A, build 169429,
SHA-256 `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
All work is offline; original image is **not** in GitHub.

Phase 21 found **29 candidate PC-relative loads** of the global RAM pointer
`0x20008B78`. Phase 22 adds `tools/audit_alias_dataflow.py`,
which uses Capstone Thumb disassembly to **conservatively** follow each
candidate's register aliases within a single straight-line prefix,
bounded to **96 bytes** and stopped at the first call, branch or return.
It models register copies, simple immediate pointer arithmetic,
memory loads and stores and invalidates overwritten aliases. Calls are
recorded as boundaries, not followed as if externally reachable.

## Grounded examples

| Address | Static behavior |
|---|---|
| `0x6080978E` / `0x60809790` | Load global to R2, then byte-store to `global+0x6C4` |
| `0x60809838` / `0x60809842` | Load global to R4, then byte-store to `global+0x6C4` |
| `0x60809E6A` | Followed by reads at `global+0x5F0/+0x5F4` (vendor event callback) |
| `0x60809EB8` | Followed by read at `global+0x6C4` (endpoint state) |

**Both identified writes target `0x2000923C` (state), not**
`0x20009170` / `0x20009178` (completion callbacks).

## Strict scope limits

The **29 entries are disassembly candidates, not runtime-observed
instructions**. This is not a whole-program CFG, path-sensitive
analysis, stack alias tracker, indirect-call resolver or memory SSA.
Aliases escaping through callees, branches, computed addresses, DMA,
other modules and unmodelled transfers remain unknown. No negative
result in one prefix can prove that a callback setter is absent.

The report distinguishes reads, writes, aliases passed in known
argument registers and boundaries where analysis stops. It does **not**
establish a host USB packet parser, access to the flash writer,
HAB CLOSED bypass or custom firmware execution.

```sh
python -m pip install -r requirements.txt
python tools/audit_alias_dataflow.py local/bootloader-a.bin --out local/phase22.json
python -m unittest discover -s tests -v
```

Tests use synthetic instruction sequences and never include the private
bootloader. All operations are read-only.

**Next (phase 23):** selectively follow pointer aliases across known
call boundaries with a scoped interprocedural graph, classify stores
and validation order, and maintain no-bricking as a hard requirement.