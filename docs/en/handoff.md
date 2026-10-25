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

## Phase 20 — Bounded USB callback writer candidate scan

[Phase 20](callback-writer-census.md) adds a **bounded raw encoding** census of Thumb-2 `STR.W Rt,[Rn,#imm12]` patterns in `0x60801000..0x60814F00`. The four offsets `+0x5F8/+0x5FC/+0x600/+0x604` each match only the corresponding constructor store at `0x6080BB50/+0xBB6C/+0xBB5A/+0xBB70`. No aligned absolute pointer literal to the four RAM field addresses was found. An additional small vendor-code range scan for Thumb16/Thumb2 object-relative stores at `+0x10/+0x14/+0x18/+0x1C` returned no candidates. **These negative searches do not prove lack of later callback registration or reachable USB parsers**: pointer aliases, alternative encodings and code outside the range are not exhaustively analyzed. Tool `tools/audit_callback_writers.py`; synthetic tests `tests/test_callback_writers.py`; sanitized evidence `evidence/usb-phase20.json`. No hardware access or HAB bypass.

## Phase 21 — RAM global alias sources

[Phase 21](global-ram-aliases.md) identifies **21 aligned** `0x20008B78` global-pointer words and **29 Thumb PC-relative load candidates** to those literals. The verified static path `0x6080C0B2` LDR global → `0x6080C0B4` BL to `0x6080BAC0` → `0x6080BAC4` MOV R4,R0 links a known alias to four initial constructor stores. Other checked sources at `0x60809E6A` and `0x60809EB8` perform reads. This does not prove runtime reachability, a later callback setter, USB packet parser, flash write or HAB bypass. Offline tool: `tools/audit_global_alias_sources.py`; synthetic tests and sanitized `evidence/usb-phase21.json`.

## Phase 22 — Bounded pointer-alias prefixes

[Phase 22](usb-pointer-dataflow.md) adds `tools/audit_alias_dataflow.py`: conservative Thumb decoding of at most 96 bytes after each of 29 RAM-global pointer candidate loads, stopping at call, branch and return boundaries. Stores at `0x60809790` and `0x60809842` target state field `global+0x6C4`, not IN/OUT completion callback fields `+0x5F8/+0x600`. No claim of exhaustive aliases, externally reachable USB parser, flash write path or secure boot bypass is made. Tests are synthetic; the matching bootloader remains private.

## Phase 23 — Bounded interprocedural alias handoffs

[Phase 23](interprocedural-aliases.md) verifies direct global-pointer handoffs at `0x6080C0B4` (constructor), `0x60802504/0x60808138` (service `0x6080B218`) and `0x6080FB4C` (initializer `0x6080B17C`). The latter derives four R0 subobject pointers `global+0x568/+0x560/+0x630/+0x578` for direct callees. The service `0x6080B218` adds `+0x630` and branches to `0x60809ABC`, which prepares `global+0x644` for another call. The SHA-locked offline `tools/audit_interprocedural_aliases.py` checks concrete machine-code edges; synthetic tests and sanitized `evidence/usb-phase23.json` are committed. No later callback setter, USB reachability or HAB bypass has been demonstrated.

## Phase 24 — Callee store and pointer provenance

[Phase 24](callee-callback-store-audit.md) reviews the four phase-23 callees and the auxiliary initialization chain from `0x60809D98`. It records 23 store observations across 19 unique instruction sites (the same `0x6081099C` initializer is analyzed with two incoming offsets); none overlaps `global+0x5F8/+0x5FC/+0x600/+0x604`. The chain `global+0x58C → 0x60810210 → 0x60810BB8 → 0x60810B38` initializes fields through `+0x5D8`. `0x60811DC8` loads a pointer from `global+0x5A8` and passes a derived pointer to `0x608109FE`; this dynamic target and the `0x60809048` paths (values loaded from `global+0x568/+0x570/+0x560`) remain unresolved. Offline tool `tools/audit_callee_store_provenance.py`, synthetic tests and sanitized `evidence/usb-phase24.json`.

## Phase 25 — Opaque pointer sinks

[Phase 25](dynamic-pointer-sinks.md) examines `0x60809048`, a transfer-like routine reading opaque incoming-object offsets `+0x154/+0x158/+0x15C` and delegating to other callees, plus `0x608109FE`, a linked-list node unlink operation writing through unknown node/previous/next/owner pointers. Caller `0x60811DC8` derives node arguments `link+0x18` and sometimes `link+4` after dynamic pointer loads. No concrete callback-field address or host-to-flash route is established. SHA-locked offline tool `tools/audit_dynamic_pointer_sinks.py`, synthetic tests and sanitized `evidence/usb-phase25.json` are in main; no binary or device I/O.

## Phase 26 — Constructor pointer provenance and list heads

[Phase 26](initial-pointer-and-list-heads.md) statically verifies that `0x6080BAE2` computes `global+0x134 = 0x20008CAC` and stores this same address into `global+0x560` and `global+0x568` (`0x6080BAEC`/`0x6080BAF2`). **Correction:** `global+0x570` is initialized by a **one-byte STRB zero**, not proved to be a third pointer. Two conditional calls to `0x6081099C` initialize self-referential list heads at `global+0x59C/+0x5B0`; `0xFFFFFFFF` is a sentinel marker, not a pointer. These are **initial states**, not measured live RAM or a no-mutation proof. Reproducer: `tools/audit_pointer_initializers.py`, sanitized `evidence/usb-phase26.json`.

## Phase 27 — List insertion and indexed bucket callsites

[Phase 27](list-insertions-and-aliases.md) verifies `0x608109B8` as direct linked-list insertion (9 decoded BL sites) and `0x608109D0` as key-ordered insertion (4 decoded BL sites plus one B.W tail). Two `0x608109B8` callers derive list heads with `MLA`: `0x2000A7F8 + 0x14×index`, distinct from the initialized heads at `0x20009114/0x20009128`. A deliberately bounded positive-immediate Thumb-2 `STR.W` search for global `+0x560/+0x568` only finds constructor sites; **other alias writes and later reassignment are not ruled out**. Offline tool `tools/audit_list_insertion_paths.py`, synthetic tests and sanitized `evidence/usb-phase27.json`. No host USB-to-flash route or HAB CLOSED bypass is demonstrated.

## Phase 28 — Indexed-node and index-source provenance

[Phase 28](indexed-node-provenance.md) statically establishes two direct `0x608109B8` insertion arguments: `0x60811A32` takes node `R6+4` and index `[R6+0x2C]`; `0x60811E0C` takes node `R4+4` and index `[R4+0x2C]`. Both compute `0x2000A7F8 + 20×index` via MLA. Index-related comparisons at `0x60811A3C` and `0x60811E18` appear **after** their insertion calls. No specific bounds check was identified in the narrow immediately preceding windows; upstream caller or state validation, runtime index values, host input, and out-of-bounds effects are **not resolved**. SHA-locked offline auditor `tools/audit_bucket_node_provenance.py`, synthetic regression tests, and sanitized `evidence/usb-phase28.json` are published.

## Phase 29 — Writer provenance for object+0x2C

[Phase 29](bucket-index-writers.md) verifies five Thumb16 `STR` sites within `0x60811400..0x60812200`: `0x608115A0` constructor unsigned clamp to 15 (`CMP/IT HS/MOVHS`), `0x60811F90/0x60811FB2` copy another runtime object's `+0x2C` field through pointer slot `0x2000A7EC`, `0x60812056` restores own `+0x50`, and `0x608120D6` locally stores unsigned max(incoming argument, own `+0x50`). The constructor also initializes `+0x50` with the clamped index using `STRD` at `0x608115A2`. **The 0..15 constructor bound is NOT proven as a runtime invariant.** Offline SHA-locked auditor `tools/audit_bucket_index_writers.py`, synthetic tests and sanitized `evidence/usb-phase29.json`. No out-of-bounds index, external host access or HAB bypass has been shown.

## New post-phase-29 priority — host update or stop

**[Finite decision gate](update-execution-decision-gate.md).** Stop unlimited pointer-analyses. Trace archived WebUSB host update packets into real receivers and HAB/storage checks; application firmware and signed ROM/RAM loaders may provide routes absent from bootloader A. The private supplied `bruce_pvt_a_prod_signed(1).bin` (1,050,984 bytes; SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`) is a signed candidate update image, **not verified installed flash**. Initial offline observation: SP `0x2002B828`, Thumb reset `0x60040501`; candidate request parser at `0x60058B68` checks a **buffer byte** of value 5 and calls `0x60058AA8`. Neither USB bRequest nor update reachability is proven. After at most **two offline packages**, if no externally controllable, authorizable and recoverable custom-execution route is proven, end internal firmware modification and pursue an external Xbox bridge; PC XInput support does not prove console support. Read-only tool `tools/audit_signed_app_surface.py`; sanitized `evidence/application-surface-gate.json`.

## Package A complete — actual host WebHID updater path

[Archived host protocol analysis](archived-updater-host-protocol.md). The original `hazrpg/stadia-flasher` `controller/app_combined.js` (Git blob SHA-1 `3c877738c12e7d5750714cd0770935ad39bd9990`, 149,810 bytes) uses **WebUSB** for normal version/battery status (`0x81/0x83/0x84`) but **WebHID** for NXP ROM `1FC9:0135` and signed RAM flashloader `15A2:0073` firmware installation. ROM SDP `WRITE_FILE 0x0404` loads the signed RAM loader and `JUMP_ADDRESS 0x0B0B` transfers to it. The flashloader handles `ConfigureMemory 0x11`, erase `0x02` (up to 16 KiB), write `0x04` (up to 512-byte HID payload fragments), and reset `0x0B`. Browser-side metadata checks are **not cryptographic signature validation**. The archived host updater sends no firmware bulk OUT to bootloader A endpoint `0x07`. Source-pin auditor `tools/audit_archived_updater.py` and `evidence/archived-updater-host-protocol.json`. **One bounded offline package B remains** for signed-boot and recovery assessment, then mandatory stop/go.
