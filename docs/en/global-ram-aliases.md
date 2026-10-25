# Phase 21 — Global RAM alias sources and verified constructor chain

**Sample:** private 128 KiB Stadia bootloader A, build 169429, SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.
All research is **offline** and the original image is **not** committed.

## Global pointer sources

The signed image contains **21 aligned 32-bit words** with value
`0x20008B78` (global RAM object). A bounded scan of candidate
**Thumb16/Thumb32 PC-relative LDR encodings** in
`0x60801000..0x60814F00` (exclusive end) finds **29 candidate loads**
pointing at these words. They are candidate instruction encodings, **not**
proven reachable instructions or a complete callgraph.

## One actual static alias relation

- `0x6080C0B2`: `LDR R0,[PC,#8]` references `0x6080C0BC`,
  a verified literal holding `0x20008B78`.
- `0x6080C0B4`: decoded `BL` target `0x6080BAC0`, constructor.
- `0x6080BAC4`: `MOV R4,R0` retains the global-object pointer.
- Anchored `STR.W` instructions at `0x6080BB50/5A/6C/70`
  initialize the IN/OUT completion handlers and contexts relative to `R4`.

The target RAM fields are `0x20009170` (IN), `0x20009178`
(OUT), and context fields `0x20009174/0x2000917C`.

This is a **verified conditional static alias-to-initializer chain**,
not a dynamic setter, live RAM measurement, host command or runtime
reachability demonstration.

Two other source sites illustrate **reads** of the same object:
`0x60809E6A` is followed by loads at `+0x5F0/+0x5F4` for the
vendor *event* callback; `0x60809EB8` reads `+0x6C4` as
an endpoint setup state byte. Those are not callback replacement evidence.

## Limitations and reproduction

This tool does **not** exhaustively model register propagation, computed
aliases, indirect calls, function-pointer tables, branch feasibility, DMA,
or other firmware images. It cannot establish that any setter is absent.
The 29 source sites are an inventory for targeted data-flow tracing.

```sh
python tools/audit_global_alias_sources.py local/bootloader-a.bin --out local/phase21.json
python -m unittest discover -s tests -v
```

The CLI checks the complete SHA-256, known literal inventory, instruction
bytes and decoded direct constructor BL. CI uses **synthetic images**.
No device contact, flash write, fuse operation or custom firmware execution
is performed.

**Next (phase 22):** function-scoped data-flow inspection from each of
the 29 candidates, tracking register copies, pointer arithmetic and
stores, and separately checking possible host input paths. USB-to-flash
reachability and HAB CLOSED bypass remain **unproven**.
