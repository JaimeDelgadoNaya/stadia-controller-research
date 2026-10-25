# Stadia Controller Research

[English](README.md) · [Español](README.es.md)

Reverse-engineering notes, measured evidence and offline tools for investigating
the original Google Stadia Controller electronics. The long-term question is
whether custom firmware can run on the original hardware.

**Current result: secure boot is CLOSED on the tested controller. No custom
firmware execution or signature bypass has been demonstrated.**

## Measured progress

| Item | Observed result |
|---|---|
| Application | Bruce build **337784** (`0x52778`) |
| Bootloader A | Build **169429** (`0x295D5`), extracted and CMS signatures verified |
| Bootloader B slot | 128 KiB entirely `0xFF`; no installed second bootloader |
| MCU identifier | `0x006C0000`, labelled **106XA0** by stadiatool |
| Flash identification | `0x17C8`, GigaDevice 16 MB |
| ROM HAB status | **CLOSED**, `0x12343412` |
| Signed RAM loader property `0x11` | Value **1**; statically traced to `OCOTP_CFG5` bit 1 |
| Final device state | Normal USB mode; original version response unchanged |

Measurements come from **one controller**, on 2026-10-25. They do not establish
that every controller has the same configuration. The firmware build was read
from the device; the full installed application was not dumped and hash-matched.

## Research notes

- **[Complete handoff: state, reproduction and where to resume](docs/en/handoff.md)**
- [Device measurements and extraction method](docs/en/measurements.md)
- [Boot chain, update validation and open questions](docs/en/boot-chain.md)
- [IVT update flow and ARM emulation — phase 10](docs/en/update-flow.md)
- [Storage mapping and wrapper emulation — phase 11](docs/en/storage.md)
- [Roadmap and evidence levels](docs/en/roadmap.md)
- [Evidence manifest](evidence/manifest.json)
- [Credits, provenance and publication scope](NOTICE.md)

The new static analysis traces application validation before the final branch to
the application's reset handler. It also distinguishes structural pre-validation
from the authentication-enabled calls around a bootloader update operation.
An arithmetic range-check observation is recorded with an offline witness;
reachability with useful impact and any authentication bypass remain unproven.

Phase 10 resolves the indirect callback to a power/input guard and traces the
fixed 4096-byte IVT transfer arguments and restoration path. Executing the
recorded range helper in isolated ARM emulation confirms the arithmetic witness
across eight cases; it does not establish a device-level exploit.


- **[Phase 12: IVT write-path audit](docs/en/write-path.md)**

**Phase 12** audits a selected call path to the physical flash writer with a
constructed IVT context. It verifies instruction anchors, virtual tables and
fixed 4096-byte arguments. **USB reachability**, out-of-bounds physical writes,
and custom-firmware execution are **not established**.

- **[Phase 13 — USB surface and dispatcher limits](docs/en/usb-surface.md)**

Phase 13 quantifies coverage of the published bootloader disassembly and adds a **read-only** static USB triage tool for a locally SHA-verified image. No exploitable USB dispatcher or custom-firmware execution has been demonstrated.

- **[Phase 14 — Bootloader vendor USB interface and callback](docs/en/usb-callbacks.md)**

A SHA-256-matched private bootloader image establishes **two USB interfaces** (vendor bulk + HID) and conditional vendor event dispatch to a RAM callback pointer. No externally reachable flash-write path or custom-firmware execution has been demonstrated.

- **[Phase 15 — Internal USB event dispatch and transfer guard](docs/en/usb-events.md)**

The SHA-matched bootloader contains an 11-case internal event table (not host USB commands) and a 512-byte upper-bound guard in one transfer helper. No external flash-write reachability or signature bypass is established.

- **[Phase 16 — CDC versus vendor callback provenance](docs/en/usb-reception.md)**

The 512-byte guarded helper belongs to a **CDC-labelled method table**, separate from the vendor event callback. Both initial callback states and selected internal call paths are verified. A bulk OUT `0x07` host-to-flash path and custom firmware execution are still **unproven**.

- **[Phase 17 — Vendor endpoint callback registration](docs/en/vendor-endpoints.md)**

On the SHA-verified bootloader A, two endpoint registrations reach `0x60806660`. Bulk OUT `0x07` and IN `0x87` map to distinct internal slots, but the specific OUT callback assignment and actual message parser are unproven. HAB CLOSED has not been bypassed.

- **[Phase 18 — RAM initialization resolves bulk OUT callback](docs/en/usb-ram-initialization.md)**

Normal startup copies compact endpoint records from flash into RAM, proving the initial **bulk OUT `0x07` callback is `0x6080A06A`** and bulk IN `0x87` is `0x60809E30`. The final dynamic handler, external flash-write reachability and HAB bypass remain unresolved.

- **[Phase 19 — Initially inert vendor USB completion handlers](docs/en/usb-completion-defaults.md)**

The initial vendor bulk IN `0x87` and OUT `0x07` completion callbacks both point to single-instruction `BX LR` stubs. Later registration and other USB update paths are **not excluded**; HAB CLOSED has not been bypassed.

- **[Phase 20 — Bounded USB callback-writer census](docs/en/callback-writer-census.md)**

The bounded Thumb-2 encoding search finds only constructor stores for the vendor IN/OUT callback fields within the selected range. **No later setter is proved or ruled out**, and there is no externally reachable flash-write or HAB-bypass demonstration.

- **[Phase 21 — Global RAM literal sources and constructor alias](docs/en/global-ram-aliases.md)**

The image has **21 aligned global-pointer literals** and **29 candidate PC-relative loads**. One direct alias chain reaches the known constructor initialization stores; this is **not** a later callback setter or proof of USB-to-flash reachability.

- **[Phase 22 — Bounded USB pointer dataflow](docs/en/usb-pointer-dataflow.md)**

Conservative tracking of 29 RAM-alias source candidates, with writes to state field `+0x6C4` distinguished from the IN/OUT completion callback fields. Call and branch boundaries remain unresolved.

- **[Phase 23 — Bounded interprocedural pointer handoffs](docs/en/interprocedural-aliases.md)**

Four verified Thumb direct calls pass the global RAM object to internal routines. One initializer derives four subobject pointers. No externally reachable callback setter, USB-to-flash write path, or HAB bypass is demonstrated.

- **[Phase 24 — Callee stores and pointer provenance](docs/en/callee-callback-store-audit.md)**

Four callees and their auxiliary-object initialization chain were reviewed. The bounded audit records 23 store observations across 19 unique instruction sites, with no overlap with the four known callback fields. Values loaded from `global+0x568/+0x570/+0x560` and passed to `0x60809048`, plus the pointer derived from `global+0x5A8` passed to `0x608109FE`, remain unresolved.

## Offline reproduction

Python 3.11 or newer:

```sh
python -m venv .venv
# Activate the environment using the command for your operating system.
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python tools/model_ranges.py
```

Optional instruction-level reproduction from the public evidence, without a
firmware binary or connected controller:

```sh
python -m pip install -r requirements-emulation.txt
python tools/emulate_range_check.py
```

With your own matching bootloader dump:

```sh
python tools/analyze_bootloader.py local/bootloader-a.bin
python tools/verify_hab.py local/bootloader-a.bin --base 0x60800000 --csf-offset 0x18000 --alias 0x60001000:0:0x1000
```

The alias explicitly represents the shared IVT block using the image's first
4096 bytes. CMS verification validates content digests and RSA signatures with
embedded certificates; it does **not** independently validate the fused SRK
trust anchor or establish a complete recovery image.

`tools/StadiaRead.cs` and `tools/Read-Stadia.ps1` provide a Windows version reader
using an already-installed WinUSB interface. The Python analysis tools above
perform no device I/O, downloads or firmware execution.

## Contributing

Include the image build/hash, exact addresses, reproduction steps and whether a
claim is measured, statically inferred or hypothetical. Keep device identifiers,
credentials, full device dumps and proprietary firmware binaries out of patches.
See the bilingual roadmap for bounded research tasks. This repository is a
research log, not an installable firmware release.
