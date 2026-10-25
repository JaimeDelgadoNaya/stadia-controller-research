# Complete research handoff

[Español](../es/traspaso.md)

Status on 2026-10-25. This document is sufficient to resume without the chat.
There is no installable custom firmware or demonstrated custom-code execution.

## Original objective

Determine whether the Stadia Controller can run custom firmware on its original
electronics, eventually improving platform compatibility. Direct Xbox-console
support would additionally require solving that console's authentication; no
new controller protocol or Xbox-console support has been implemented.

## Established state

| Item | Result | Evidence level |
|---|---|---|
| Installed application | Bruce 337784 (`0x52778`) | Device USB read |
| Bootloader A | 169429 (`0x295D5`), extracted | Device read and verified CMS signatures |
| Bootloader B slot | 128 KiB entirely `0xFF` | Device read and spot re-reads |
| MCU | ID `0x006C0000`, upstream label 106XA0 | Device read |
| Flash | ID `0x17C8`, GigaDevice 16 MB | Device read |
| HAB | CLOSED; ROM `0x12343412`, property 0x11 = 1 | Two device-query paths |
| Final device state after physical tests | Normal USB, unchanged version response | Post-reset device read |
| Image-range helper | Accepts a wrapped range and one zero-size case | Original instructions in isolated emulation |
| Storage bounds | Can delegate outside a partition with a synthetic offset | Emulation with a mocked physical writer |
| Custom execution / signature bypass | Not demonstrated | Open |

Measurements concern one controller. The full installed application was not
extracted; reading its build does not hash-verify its complete contents.

## Hardware work already performed

The existing WinUSB driver was used to read the version, and HID for diagnostics.
The owner pressed the buttons to transition from `18D1:9400` through `18D1:946B`
to ROM `1FC9:0135`. ROM ERROR_STATUS was queried before loading any code. The
original Google signed loader was subsequently loaded only into RAM. HAB and
MCU identifiers were queried, then flash was read through a temporary read-only
FlexSPI LUT.

There were volatile RAM/SRAM and FlexSPI-register writes, but no firmware
programming, flash erase or fuse programming commands. Two 128 KiB regions were
extracted: A contains the bootloader and B is erased. Loader RESET succeeded;
normal mode and the identical eight-byte version response were confirmed.
Phases 9, 10 and 11 involved no hardware access.

## Reading order

1. [Measurements](measurements.md): protocols, responses, extraction and limits.
2. [Phase 9](boot-chain.md): application validation, HAB and structural-only flag.
3. [Phase 10](update-flow.md): callback, IVT buffers and restoration.
4. [Phase 11](storage.md): descriptor 0x12, storage methods and mocked delegation.
5. [Manifest](../../evidence/manifest.json): artifact hashes and scope.

## Minimal address map

All addresses refer to A build 169429, SHA-256
`59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0`.

| Address | Research description |
|---|---|
| `0x60801DD4` | IVT update/selection flow |
| `0x60801EF0` | Validated application handoff |
| `0x60801F5C` | HAB entry/authenticate_image_no_dcd/exit wrapper |
| `0x60801FE6` | Image-range helper, 32-bit arithmetic |
| `0x6080200C` | Application validator |
| `0x608020A8` | Structural/authenticated bootloader validator |
| `0x608022FC` | Power/input guard callback |
| `0x6080285C` | Thumb thunk to that guard |
| `0x6080AA66` | Partition-offset to flash-offset translation |
| `0x6080AA7C` | Offset-plus-length bounds helper |
| `0x6080B0F0` | Plain partition write wrapper |
| `0x60815300` | Plain partition vtable |
| `0x60815320` | Physical-device vtable |
| `0x60001000` | Shared IVT, descriptor 0x12, 4096 bytes |

Labels are inferred descriptions, not recovered source symbols.
`evidence/bootloader-analysis.json` records selected instruction bytes, direct
calls, literals and tables. Decoding uses Thumb M-class mode.

## Reproduce from a clean clone

```sh
python -m venv .venv
# Activate .venv with your operating system's command.
python -m pip install -r requirements-emulation.txt
python -m unittest discover -s tests -v
python tools/model_ranges.py
python tools/emulate_range_check.py
python tools/emulate_storage.py
```

Tests and emulators use public evidence without a controller or full firmware
binary. The complete suite contains 14 tests. The range emulator executes eight
cases. The storage emulator executes four invocations with a constructed object;
it intercepts the physical writer and returns mock success. It does not establish
that real flash would accept the delegated request.

With your own matching dump:

```sh
python tools/analyze_bootloader.py local/bootloader-a.bin
python tools/verify_hab.py local/bootloader-a.bin --base 0x60800000 --csf-offset 0x18000 --alias 0x60001000:0:0x1000
```

The alias represents the shared IVT with the image's first 4096 bytes. Verification
checks content digests and signatures with embedded certificates, not the fused
SRK trust anchor independently. These regions are not a complete 16 MB recovery
backup.

## Claims that remain unproven

- CLOSED is measured: loading RAM data is not proof it can execute.
- The Google signed loader ran; custom code did not.
- “dev” is not an unlock: the compared Bruce images share their content before
  the final signing area.
- Empty B refers to bootloader B, not the unmeasured application B region.
- IVT restoration exists, but recovery from power loss has not been demonstrated.
- Arithmetic witnesses work in emulation, but an external input controlling
  those parameters in the reviewed path has not been demonstrated.
- The IVT caller uses offset zero and fixed length 4096. Out-of-partition writes
  alone do not establish HAB bypass or code execution.

## Next useful work

1. Trace callers of `0x6080B0F0` through their interfaces to determine whether
   USB or another controllable input can supply the relevant parameters.
2. Separate reachability from effect: examine later checks, alignment, permitted
   destinations and authentication before assigning device-level impact.
3. Reconstruct application A/B selection and boot-attempt metadata.
4. Propose a physical experiment only for a concrete, recoverable hypothesis.
   Modified firmware flashing is unnecessary to reproduce the published work.

## Material retained locally

Public artifacts omit full proprietary firmware and personal device identifiers.
The original workspace retains `outputs/bootloader-a.bin`,
`outputs/bootloader-b.bin`, the phase-8 report and ZIP, and extraction scripts in
`work/`. The ZIP is a local archive, not a public release. The owner may supply
these files to a subsequent environment for full-image analysis. No extraction
process was left running.

## Phase 12 — Automated IVT write-path audit

Added the [write-path audit](write-path.md), with `tools/trace_write_path.py`
and tests detecting changes in callsites, fixed arguments and virtual tables.
It relies only on `evidence/bootloader-analysis.json` and verifies a
**conditional** call path from `0x6080285C` to physical writer `0x60808E38`
under the phase-11 constructed IVT context, with fixed offset zero and
length `0x1000`. **No USB reachability, HAB bypass or custom-firmware
execution is demonstrated.** Reproduce with:

```sh
python tools/trace_write_path.py
python -m unittest discover -s tests -v
```

## Phase 13 — USB input surface boundary

[Phase 13](usb-surface.md) adds `tools/audit_usb_surface.py`: it audits the selected public instruction coverage (28 regions, 2340 of 131072 instruction bytes, 67 direct calls, 41 targets outside selected ranges, 16 indirect transfers), and offers **offline-only** descriptor/pointer/vector/heuristic callgraph triage of an owner's SHA-256-verified local bootloader image. Candidate descriptors do not demonstrate usable USB commands or external reachability. No custom firmware execution is established.

Run `python tools/audit_usb_surface.py` and `python -m unittest discover -s tests -v`. With a matching private image, run `python tools/audit_usb_surface.py --bootloader local/bootloader-a.bin`. Never commit proprietary firmware.

## Phase 14 — Verified USB descriptors and vendor callback

A private 128 KiB bootloader A image matches the recorded SHA-256. [Phase 14](usb-callbacks.md) decodes USB `18D1:946B`: vendor interface with bulk IN `0x87` and OUT `0x07` (512-byte packets), plus HID with interrupt IN `0x83` and OUT `0x03` (64-byte packets). Vendor callback at `0x60809E64` dispatches conditionally through a RAM function pointer initialized to an inert default handler. A USB-to-flash-write path **remains unproven**. The offline `tools/audit_usb_callbacks.py` requires a locally stored SHA-matched binary; nothing proprietary is published.

## Phase 15 — Internal USB event dispatcher

[Phase 15](usb-events.md) decodes the SHA-locked 11-case Thumb TBB event table at `0x60809C68`. Internal event IDs 4, 5 and 8 directly return through the default handler. A distinct transfer helper at `0x60809B28` guards its size argument against `0x200` (512) bytes. **These are not eleven verified externally sendable commands.** There is still no proved bulk OUT `0x07` to flash-writer path and no HAB CLOSED bypass. Offline `tools/audit_usb_event_dispatch.py` and synthetic tests are committed; the private bootloader image remains excluded.

## Phase 16 — CDC/vendor callback provenance

[Phase 16](usb-reception.md) confirms that the 512-byte limited `0x60809B28` belongs to the CDC-labelled method table at `0x60814E18`, installed at object offset `+0x578`. That object's optional `+0x0C` callback starts as NULL; the internal event path reaches a conditional wrapper at `0x60809C44`. Independently, the vendor event handler `0x60809E64` starts with inert Thumb callback `0x60809E3D`. A bulk OUT `0x07` receive parser and any route to flash writes are still **not established**. Reproduce offline with `tools/audit_usb_callback_provenance.py`; no private firmware has been committed.

## Phase 17 — Vendor USB endpoint registration

[Phase 17](vendor-endpoints.md) verifies two endpoint registrations through `0x60806660` and a two-entry callback table at `0x60814F24`. Endpoint address and direction determine separate internal indices: bulk OUT `0x07` → 14 and IN `0x87` → 15. **Callback assignment by direction is not yet determined** because the endpoint registration reads a runtime RAM descriptor. The true receive parser, flash-writer reachability and HAB bypass remain unproven. `tools/audit_vendor_endpoints.py` operates offline on the matching private binary with SHA-256/region checks; sanitized evidence is public.

## Phase 18 — RAM initializer resolves bulk OUT callback

[Phase 18](usb-ram-initialization.md) verifies a **400-byte** normal-startup flash-to-RAM copy, from `0x608161E0` into RAM `0x20000000`. It contains compact endpoint records `87 02 00 02` at RAM `0x200000D8` and `07 02 00 02` at `0x200000DC`. Verified loop and callback table associate **IN `0x87` with `0x60809E30`** and **OUT `0x07` with `0x6080A06A`**. The latter forwards into `0x6080A062`, which loads a dynamically registered callback from `+0x18`, still unresolved. SHA-locked offline auditor: `tools/audit_endpoint_ram_init.py`; sanitized evidence: `evidence/usb-phase18.json`. No custom execution or HAB bypass is demonstrated.

## Phase 19 — Initially inert USB completion callbacks

[Phase 19](usb-completion-defaults.md) follows `0x60806554` → `0x6080A06A` → `0x6080A062`. The vendor object at RAM `0x20009160` has an initial OUT `0x07` handler at `0x20009178` pointing to Thumb `0x6080AFFD` (function `0x6080AFFC`) and initial IN `0x87` handler at `0x20009170` pointing to `0x6080AFFB` (function `0x6080AFFA`). Both are **single-instruction BX LR return-only stubs**; handler contexts are initially zero. No later registration is ruled out, and external USB-to-flash reachability or HAB bypass is not established. SHA-locked offline tool: `tools/audit_vendor_completion.py`; sanitized `evidence/usb-phase19.json`; synthetic tests.
