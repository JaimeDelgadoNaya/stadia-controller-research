# Phase 91 — November 2026 community findings: SDP, Gotham, and local binary intake

**22 November 2026.** Offline research continuation of phase 90. No USB/BLE/network requests to any controller, no exploit invocation, no fuse operations, no flash programming, and no third-party executable run.

## Source and confidence ledger

| Claim | Evidence | Current status |
| --- | --- | --- |
| `tchebb` disclosed an NXP SDP overrun and reports having a custom Zephyr port | [Author's 14 November Reddit thread](https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/) and [announced Codeberg repository](https://codeberg.org/tchebb/nxp-sdp-overrun) | **Author report**, not reproduced or independently audited here. Codeberg source was unavailable to this review; no exploit code was fetched. |
| Persistent unlock through `FIELD_RETURN` | Proposed in Reddit; not a reviewed final implementation | **Not demonstrated** on the owner's hardware; no eFuse action is authorized. |
| A patched bootloader offers a corrected CDC ACM USB descriptor | Private community description and uploaded candidate | **Unverified operational claim**. Static source-file strings alone do not validate a USB descriptor, authenticity, compatibility or safe installation. |
| A local replacement for Gotham Wi-Fi services is already functional | [jkfran/stadiacast](https://github.com/jkfran/stadiacast), head observed at `9605bf461a157608b8a8756ba21fb68f7afd5ffb`, README and protocol documentation | **Upstream author-reported end-to-end result** on Gotham `ota.282115`; not independently tested on the owner's device. |
| KVS restrictions, FVC setting wrappers, Clearcut and DNS fallback | Fran / tchebb / Lacipe Discord conversation provided by the owner, **17 November 2026** | **Community reverse-engineering claims**, pending reproducible static firmware provenance. |

These are **different** tracks: a BootROM/SDP disclosure does not prove that an arbitrary patched bootloader is safe; Wi-Fi protocol interoperability does not require a bootloader unlock; a working community patch does not prove universal compatibility.

## New uploaded candidate: passive facts

The privately supplied `bootloader-usb-acm.bin` is **94,248 bytes**, SHA-256 `ea37f7cd38ab7ae392fa80911aeed4b07ac7e557b8bb66375e099e8ebd148957`. At file offset zero it contains a candidate NXP IVT header (`d1 00 20 41`), with entry `0x60801000`, self `0x60001000`, boot-data `0x60001020`, and null DCD/CSF pointers. It contains textual markers `usb_device_cdc_acm.c` and `usb_device_vendor.cc`. **New static observation:** an 85-byte USB configuration descriptor chain is structurally parseable at file offset `0x1527c`, describing three interfaces (vendor 0, CDC communication 1, CDC data 2), five endpoints, an ACM function and union `1→2`; **no IAD appears in that chain**. This does not establish that the descriptor is used at runtime or accepted by a host. **No signature, descriptor, executable path, board fit, recovery procedure or flashing suitability was proven.** An IVT version field is not the silicon's BootROM HAB version. This image is **not equivalent** to the owner's previously archived 131,072-byte bootloader A hash-pinned in `evidence/manifest.json`.

The privately supplied `bluetooth.bin` is **2,048 bytes** and begins with `#BONDING`. Treat it as potentially containing **bonding keys and device identifiers**. The analysis deliberately does not reproduce its contents or publish a hash. It is **not** evidence of a Bluetooth firmware image. Neither supplied binary is committed.

Run the optional read-only inspector against local private files with:

```sh
python -m tools.audit_community_artifacts_phase91 --bootloader /private/bootloader-usb-acm.bin --bonding /private/bluetooth.bin
python -m unittest tests.test_community_artifacts_phase91 -v
```

The inspector emits only sanitized metadata, refuses unknown IVTs and unknown bonding prefixes and never imports firmware code. Its tests use synthetic bytes exclusively.

## Gotham and KVS: decision table from 17 November Discord

| Item | Reported behavior | Next evidence requirement |
| --- | --- | --- |
| `YetiDiscoUrl` | Registry ID 22; override-settable, no default. Redirects `RegisterController`, `DiscoverDisplay`, `ResolveDiscovery` only. | Pin exact signed Gotham build and identify the settings registry entry, getter and consumers. |
| `YetiGmsgUrl` | Read by code but no registry entry; generic official writers reject it. | Prove original name-to-ID lookup and every relevant KVS writer/reader. A proposed custom shim is a **hypothesis**, not a demonstrated route. |
| `YetiEnvironment` | Registry ID 21 selects a fixed set of Google environment hosts for GMsg. | Trace name-to-ID, allowed values and the GMsg hostname constructor. |
| FVC | `FirmwareVersionCheck` uses `cloudcast-pa.googleapis.com` rather than `YetiDiscoUrl`. Override uses a nested Setting submessage, not a bare string. | Byte-pinned protobuf schema and controlled synthetic decoder tests only. |
| Clearcut | Analytics uploader uses `play.googleapis.com/log/batch`; reportedly a secondary uploader survives `AnalyticsOptIn=false`. | Ground in exact signed function graph and validate refusal/response behavior with fake traffic. |
| DNS fallback | Reported DHCP-resolver failure can switch queries to hardcoded `8.8.8.8`. | Independent firmware function trace and synthetic DNS fault matrix. Do not use real secrets or live network interception. |
| `AppImageFdrVer` | Discord warning that sending registry ID 44 can trigger a reset during post-update verification. | Treat as **dangerous input** and exclude it from every generated test packet. No physical FVC injection. |
| Vendor USB `set KVS` | Open question: does the handler enforce the registry or write arbitrary names? | Identify the exact **signed** dispatcher, parsed string, registry lookup and final storage call. Require proven call/control-flow edges before any capability claim. |

The critical functional dependency for Stadiacast is the **GMsg channel** that carries the WebRTC SDP answer. Changing a discovery URL alone cannot be assumed to redirect GMsg. A firmware replacement could choose different network behavior, but no firmware change is part of this phase.

## Practical priorities and boundaries

1. **SDP provenance, first:** obtain an immutable source revision and its hashes for `nxp-sdp-overrun`, then document target chip, BootROM assumptions, patched/unpatched conditions, execution persistence and recovery claims as distinct statements. Do not apply Toradex's 2026 U-Boot SDP vulnerability automatically: that is a separate software-stage issue.
2. **USB vendor-to-KVS, second:** start with the community's outstanding question about the signed `set KVS` command. A call-chain proof needs actual instructions/branching, not strings or an endpoint name; link to existing workstreams [#100](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/100) and [#102](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/102).
3. **Gotham interoperability, third:** compare fixed discovery/GMsg hostnames and optional settings against Stadiacast's already working protocol notes; use fake clients and synthetic credentials only. See [#107](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/107).
4. **Risk gate:** no firmware upload, CDC patch installation, flash erase/write, SDP payload execution, `FIELD_RETURN`, forced SDP via shorted flash pins, or destructive recovery on the only controller. An independent, reproducible recovery plan and spare hardware are prerequisites to even considering such experiments.

**Conclusion:** the community's November disclosure makes a new boot chain possible *in the author's reported experiments*, but custom execution on the owner's production unit, persistence, validated descriptors and recoverability are **not established in this repository**. Respect the upstream author's request to let their Zephyr/Switch effort mature instead of publishing an unreviewed substitute.
