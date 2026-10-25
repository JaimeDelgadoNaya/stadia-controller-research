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
