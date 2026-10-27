# NXP research phase 84 — bounded HAB RVT literal survey

**27 October 2026. Offline only; no controller attached.** Follows [NXP phase83](hab-rom-version-phase83.md); the phase number is independent from the parallel HID workstream.

The [SHA-256-pinned auditor](../../tools/audit_hab_rvt_literals_phase84.py) inspects only the **pre-CSF** portion of the original Google-signed images. It searches halfword-aligned 32-bit little-endian constant words for the exact documented RT1060 HAB RVT base and pointer slots `0x00200300`, `0x00200304`, `0x00200308`, `0x00200324`, `0x0020032c`, and `0x00200330` (`get_version`). It reports file offsets and alignments, but every hit has **`instruction_reference_confirmed=false`**.

For each hit, a second bounded pass also looks for **syntactically compatible 16/32-bit Thumb literal-LDR encodings** targeting the word. Instruction boundaries and actual execution are **not validated**. This remains a **raw literal-word census, not a call graph**. It can miss computed `MOVW/MOVT` addresses, pointer arithmetic, indirect calls and byte-unaligned values. A hit does not establish executable code or an active caller; **zero hits never establishes that `get_version` cannot be invoked**.

Previously identified direct HAB authentication API use in the privately extracted bootloader A is documented in [phase9](../es/arranque.md). The private sample is never uploaded to CI. The dedicated [GitHub Actions workflow](../../.github/workflows/nxp-rom-advisories-phase81.yml) audits two public archived signed images after enforcing their whole-file SHA-256, runs [synthetic tests](../../tests/test_hab_rvt_literals_phase84.py), and deletes source binaries.

```sh
python -m unittest tests/test_hab_rvt_literals_phase84.py -v
python -m tools.audit_hab_rvt_literals_phase84 local/bruce_pvt_a_prod_signed.bin --sample bruce_prod
python -m tools.audit_hab_rvt_literals_phase84 local/restricted_ivt_flashloader.bin --sample restricted_ram_loader
```

## Verified result on exact signed OEM files

[Sanitized pinned evidence](../../evidence/nxp-hab-rvt-failsafe-phase84.json) · [Successful original-image GitHub Actions](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40567286976).

| Signed sample | Literal word `0x00200300` occurrences | Direct `get_version` slot word `0x00200330` |
|---|---:|---:|
| Bruce original update | **2**, offsets `0x810` / `0xcd224` | **0** |
| Original signed RAM loader | **0** | **0** |

A signed original Thumb16 sequence at image file offset `0x726` has been verified byte-for-byte as `3a48816a0847`, decoding to:

```asm
0x60040726  LDR R0, [PC, #0xE8]    ; dereference signed literal 0x810 -> 0x00200300
0x60040728  LDR R1, [R0, #0x28]    ; ROM RVT pointer slot 0x00200328
0x6004072A  BX R1                   ; conditional-on-entry indirect tail branch
```

[NXP's own HAB RVT structure](https://github.com/nxp-mcuxpresso/sbl/blob/master/component/secure/semifunc/hab_rvt.c) labels `+0x28` **`failsafe`**, `+0x2c` `authenticate_image_no_dcd` and `+0x30` `get_version`. This original OEM sequence **targets failsafe, not get_version**. Neither code reachability nor ROM pointer contents have been observed on hardware. The second literal at `0xcd224` has no syntactic Thumb literal-load candidate in the selected window.

The dedicated action and all **45 synthetic phase81–84 tests** pass. The private owner-extracted bootloader A is not included in public CI or this census.

**Evidence boundary:** physical ROM HAB patch version, live RVT contents, execution of `get_version`, CSF parser vulnerabilities, signed-code bypass and rollback all remain unverified. No USB, flash or OTP operations are performed.

References: [NXP AN12263](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/160465/2/AN12263.pdf) · [NXP additional-image HAB advisory](https://community.nxp.com/t5/i-MX-Security/Authentication-Vulnerability-when-extending-the-Root-of-Trust/ta-p/1511348).
