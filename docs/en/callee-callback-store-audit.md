# Phase 24 — Callee stores and pointer provenance

> **Phase-26 provenance update:** the constructor points `global+0x560` and `+0x568` at `global+0x134`, whereas `global+0x570` is initially a **one-byte field**. Later values remain subject to potential runtime writes. [Details](initial-pointer-and-list-heads.md).

**Local sample:** Stadia bootloader A, build 169429, 131,072 bytes.
SHA-256: \`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0\`.
The binary remains private. The original was reviewed offline with LLVM Thumb disassembly and SHA-256 fingerprints for each inspected range.

## Main result

The four phase-23 callees and the initialization chain reached from \`0x60809D98\` were inspected. The bounded ranges contain **23 direct-store observations with calculable global-object-relative addresses, covering 19 unique instruction sites** (function `0x6081099C` is analyzed with two different incoming object offsets). **None overlaps the four USB callback fields**:

- IN handler: \`global+0x5F8\` = \`0x20009170\`
- IN context: \`global+0x5FC\` = \`0x20009174\`
- OUT handler: \`global+0x600\` = \`0x20009178\`
- OUT context: \`global+0x604\` = \`0x2000917C\`

This is a scoped finding, not proof that no other path can change those fields.

## Observed stores

| Function / block | Offsets from \`0x20008B78\` | Interpretation |
|---|---|---|
| \`0x6080A990\` | \`+0x574\` (two sites) | Field in the passed subobject |
| \`0x6080990C\` | \`+0x6C0\` | Controller state; not \`+0x6C4\` and not a callback |
| \`0x60809D98\` | \`+0x588\` | Subobject state field |
| \`0x60810210\` | \`+0x5DC\` | Auxiliary object member/result |
| \`0x60810BB8\` | \`+0x58C, +0x5C8, +0x5CC, +0x5D2, +0x5D8\` | Auxiliary-object initialization |
| \`0x60810B38\` | \`+0x590, +0x594, +0x598, +0x5C4, +0x5D0, +0x5D1\` | Subobject initialization |
| \`0x6081099C\` | \`+0x59C, +0x5A0, +0x5A4, +0x5A8, +0x5AC\` | Linked-node initialization |
| \`0x6081099C\` (second object) | \`+0x5B0, +0x5B4, +0x5B8, +0x5BC, +0x5C0\` | Second linked-node initialization |

The callback fields start at \`+0x5F8\`; stores in the auxiliary initialization chain end at \`+0x5D8\`. The \`+0x6C0\` store is outside that area.

## Verified pointer-flow chain

The path from \`0x60809D98\` is:

1. It derives \`global+0x58C\` and calls \`0x60810210\`.
2. \`0x60810210\` reads and, on its initialization branch, writes \`global+0x5DC\`; it passes \`global+0x58C\` to \`0x60810BB8\`.
3. \`0x60810BB8\` retains the alias and calls \`0x60810B38\`.
4. \`0x60810B38\` initializes fields through \`+0x5D8\), then passes \`global+0x59C\` to \`0x60811DC8\` and \`global+0x59C/+0x5B0\` to \`0x6081099C\`.
5. \`0x6081099C\` initializes the two nodes at the offsets listed above.

At \`0x60811DC8\`, code reads the value at \`global+0x5A8\`, dereferences that value, then calls \`0x608109FE\` with a derived pointer. **The final target of this pointer is dynamic and remains unresolved.**

## Important limitations

- \`0x6080A990\` reads values from \`global+0x568\` and \`global+0x570\` and passes them to \`0x60809048\`; \`0x608021B4\` reads \`global+0x560\` and also passes that value to \`0x60809048\`. The pointees are not statically known.
- \`0x6080C150\`, called by \`0x6080990C\`, replaces its incoming argument with a literal pointer (\`0x20009DC0\)); it does not use the supplied alias to write the USB callbacks.
- \`0x60802174\` reads global-object fields and contains an unconditional self-loop at \`0x608021A6\); a path reaching it does not return.
- \`0x60809048\` and \`0x608109FE\` remain separate analysis targets. Register provenance does not prove that their dynamic pointers cannot reference other areas.

**Conclusion:** no direct write to the IN/OUT callback fields was found in the inspected ranges. A later setter, host USB-to-flash route, or HAB CLOSED bypass has not been demonstrated.

## Reproduction

\`\`\`sh
python -m pip install -r requirements.txt
python tools/audit_callee_store_provenance.py local/bootloader-a.bin --out local/phase24.json
python -m unittest discover -s tests -v
\`\`\`

The auditor checks the complete image hash and per-range fingerprints before disassembly. CI tests use synthetic instruction sequences; they do not include or require the proprietary image. Sanitized \`evidence/usb-phase24.json\` contains addresses and fingerprints, not the image.
