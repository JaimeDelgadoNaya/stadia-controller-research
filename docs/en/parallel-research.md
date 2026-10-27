# Parallel research workstreams — Stadia controller

**Five independent GitHub tasks and parallel CI jobs are now defined; these are NOT five autonomous AI agents running in the background.** This chat still coordinates, reviews and initiates work.

| Track | Issue | Goal |
|---|---|---|
| **A. Bruce** | [#99](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/99) | Signed SRC_GPR7 bit-3 writer provenance; verify code, address, values and reachability |
| **B. Bootloader A** | [#100](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/100) | Signed update/authentication and IVT rollback safety, external-input origins |
| **C. NXP ROM/HAB** | [#101](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/101) | Exact ROM HAB-version provenance and advisory applicability |
| **D. USB / HID / BLE** | [#102](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/102) | Privacy-safe passive URB/IRP correlation and verified USB-to-code attribution |
| **E. Independent QA** | [#103](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/103) | Source pins, hash gates, regression tests, GO/NO-GO and unsupported-claim rejection |

**Critical register correction:** RT1060 `0x400F8038` is **SRC_GPR7**, while SRC_GPR6 is `0x400F8034`. Earlier GPR6-labelled phase88 PR **#97 is superseded and must not be merged**; PRs **#96/#98** carry the documented correction. Original signed Bruce writes **5 or 6** to SRC_GPR7 through a computed address; neither sets update bit 3 (`0x08`). The producer of that bit and any USB-host trigger remain unknown.

All results must label **physical measurement**, **whole-file SHA-pinned original**, **selected published disassembly**, **synthetic test**, or **hypothesis**. The [parallel CI workflow](../../.github/workflows/research-workstreams.yml) runs isolated synthetic test jobs for each track. Existing main CI covers Python 3.11/3.12, and the pinned OEM workflow audits archived public signed binaries after SHA verification. CI tasks are automation for tests, **not autonomous LLM research agents**.

**Safety gates:** no controller writes, ROM exploitation, flash/IVT modifications, eFuse changes, power-cut fault injections, owner-private bootloader publishing, or ungrounded host execution claims. HAB CLOSED remains unbypassed. Even a genuine USB→GPR7 update request would not authorize unsigned custom firmware.

This integration reconciles historical USB research PRs **#81/#82** with NXP/bootloader PRs **#90–#96/#98**, while preserving the physically measured HID changes already in `main`. Do not merge the superseded #97.
