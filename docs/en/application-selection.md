# Application A/B selection — phase 12

[Español](../es/seleccion-aplicacion.md) · [Handoff](handoff.md)

This phase models 0x60801EF0..0x60801F4A from recorded disassembly of bootloader build 169429, image SHA-256 59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0. The 90-byte routine SHA-256 is 3d167008abac66682b155fc2ee091c34811cdd70517fda34b3b0853df5787afe.

The script checks instruction bytes, selected disassembly and literals before building its control-flow scenarios. **No CPU emulation or device access.**

| Selector in r0 | Application validated by 0x6080200C | On successful validation | On failure |
|---|---|---|---|
| 2 | 0x60040000 (A) | Prepare VTOR, MSP/PSP and branch to reset handler | Write 0x10 to 0x400F8038 and return |
| 3 | 0x60840000 (B) | Same for B | Write 0x20 to 0x400F8038 and return |
| Other | None | — | Return without dispatch |

Only a zero result in the validator's low byte follows the success path. 0x400F8038 is the GPR7 status register, **not firmware flash**. This does not demonstrate automatic fallback, reboot or recovery. The callers providing selector values 2 and 3 remain untraced.

## Reproduction

    python tools/audit_application_selection.py
    python -m unittest discover -s tests -v

Six **synthetic** control-flow outcomes supported by fingerprinted evidence, not device tests, ARM emulation or a signature bypass.

**Next:** trace callers of 0x60801EF0 and GPR7 readers/writers using a matching local bootloader image.
