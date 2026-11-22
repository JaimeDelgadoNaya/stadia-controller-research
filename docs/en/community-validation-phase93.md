# Phase 93 — Cross-phase evidence and test audit

> **Update 22 Nov 2026 (Phase 95):** the actual Gotham images and KVS tables have now been verified. An 8-byte parser offset error was corrected: Bruce has 67 keys, Gotham has 115 per image. Verified Gotham IDs are `YetiEnvironment=21`, `YetiDiscoUrl=22` and `AppImageFdrVer=44`. Section 5 records the earlier historical state before Gotham was available through CI.


**22 November 2026.** This phase cross-checks phases 91–92 against repository artifacts, GitHub Actions logs and newly identified public sources. No controller is connected and no firmware is executed.

## 1. Own-repository test results

| Group | Result | Run |
|---|---:|---|
| Phase 91 private-artifact intake | 10/10 per version | Python 3.11 and 3.12 |
| Phase 92 USB descriptors and OEM differential | 17/17 per version | Python 3.11 and 3.12 |
| Full offline suite | 1,063 passed; 35 skipped | Python 3.11 and 3.12 |
| OEM sample and bounded-emulation lane | 89 passed; 0 skipped | GitHub Actions |
| Five regression lanes | All successful | Bruce, bootloader, NXP HAB, USB HID and independent QA |

The 35 skips in the general offline suite are conditional tests requiring optional samples/fixtures, not failures. A separate original-sample/emulation lane completed 89 tests. Action run URLs are pinned in `evidence/community-validation-phase93.json`.

**Documentation correction:** PR #110 initially said eight Phase 91 tests. The actual test file contains ten; the PR and report should say ten.

## 2. Existing firmware evidence audit

The private `bootloader-usb-acm.bin` has the same size and SHA-256 in phase91 and phase92. That proves consistency between the recorded reports, **not a fresh read of the original bytes**: the binary is not in the repository and was not remounted in this session.

The candidate is unauthenticated; its CSF pointer is null; compatibility, execution and recovery have not been proven. `bluetooth.bin` remains classified as a private `#BONDING` store; its contents and hash are not published.

The USB comparison remains properly scoped: physically measured OEM mode (`18D1:9400`, Vendor + HID, two IADs) versus a statically inspected community candidate (`18D1:946B`, Vendor + CDC ACM + CDC Data, no IAD). Shared endpoints `0x07/0x87` do not prove a shared handler.

## 3. Important correction on Tomás's firmware status

In his public 14 November post, Tomás says his Zephyr port and custom firmware work fairly well but are not ready to release. He also explicitly says he **had not started the Nintendo Switch controller emulation firmware yet**. His `FIELD_RETURN` shellcode was described as planned work. Source: [author's thread](https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/).

He also requested that others not vibe-code duplicate Zephyr or Switch firmware. We respect that request: this research will not produce a competing Zephyr port or a clone of his Switch firmware. The Codeberg exploit source remains unavailable for independent audit in this environment.

## 4. Stadiacast external validation

Upstream `jkfran/stadiacast` is at **v1.3.0**. Its last successful CI examined reported:

- Python 3.11: 520 passed, 45 skipped.
- Python 3.12: 520 passed, 45 skipped.
- Lowest direct dependencies: 506 passed, 59 skipped.

The latest visible 22 November CI run is marked `action_required` and started no jobs; it must not be described as a failing test run. The normal suite uses `tests/fake_controller.py` and loopback tests, so it does not require a physical controller. The receiver does not modify controller firmware. This validates the interoperability project against its own tests, not installation on the owner's device.

A separate ESP32-S3 external adapter project was also found. It emulates several USB controller identities, including Switch Pro, but it is not firmware running on the Stadia controller and does not meet the direct/no-adapter goal. It is recorded only as an external fallback.

## 5. Next major step: original Gotham image

Two public `ota.282115` Wi-Fi firmware images were located in `StadiaMemories/firmware`:

- [PVT-A](https://github.com/StadiaMemories/firmware/blob/main/ota.282115.stable-channel.gotham-pvt-a.214f6fe20f7b993046c77a9245c5805b056882dc.bin), 4,163,944 bytes; Git blob `e87bbd94e3843746af39c5920725e0bcf2b42c54`.
- [PVT-B](https://github.com/StadiaMemories/firmware/blob/main/ota.282115.stable-channel.gotham-pvt-b.b252d0d5a16538621abfb09609746cabc0f33292.bin), 4,163,944 bytes; Git blob `128c65d9a5b5f44d1d2a217e5c6502370958dd86`.

The repository is pinned at commit `c86e2a397a747ce51c0988cd967142e5324ef0f9`. Their existence and metadata are verified, but the binary bytes could not be brought into the analysis environment. Current repository evidence concerns bootloader A and a Bruce update sample, **not the Gotham Wi-Fi firmware**.

Once one image is available locally, the next static audit should trace the USB Vendor dispatcher, `set KVS`, name→ID registry, storage call and consumers of `YetiDiscoUrl`, `YetiEnvironment` and `YetiGmsgUrl`. No live vendor traffic should be sent, and `AppImageFdrVer` (ID 44) must not be written.

## Conclusion

Automated tests for the research repository are green. Discord claims remain hypotheses until checked against Gotham. The best next step is not flashing: it is obtaining the exact Gotham image and resolving the KVS path in signed firmware.

## 6. Direct OEM-to-CDC bootloader comparison

The two private files `bootloader-a.bin` and `bootloader-usb-acm.bin` were compared byte-for-byte.

| Field | OEM original | CDC candidate |
|---|---:|---:|
| Size | 131,072 bytes | 94,248 bytes |
| SHA-256 | `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0` | `ea37f7cd38ab7ae392fa80911aeed4b07ac7e557b8bb66375e099e8ebd148957` |
| VID:PID | `18D1:946B` | `18D1:946B` |
| Interfaces | Vendor + HID | Vendor + CDC ACM + CDC Data |
| Configuration length | 80 bytes | 85 bytes |
| IAD descriptors | 2 | 0 |
| CDC Union | No | Master 1, slave 2 |

Across the 94,248-byte common prefix, **72 bytes differ** in 12 ranges. All differences are confined to three regions:

1. **IVT:** the original CSF pointer `0x60818000` is cleared (three bytes of the four-byte field change).
2. **Code:** at `0xAF4E`, the Thumb instruction changes from `MOVS r3,#0x50` to `MOVS r3,#0x55`. The pointer literal `0x6081527C` is unchanged. The immediate changes from 80 to 85, matching the new USB configuration length.
3. **USB descriptors:** 68 bytes change to replace the HID interface with CDC ACM + CDC Data and add a CDC Union.

The original authentication area begins at file offset `0x18000` with CSF header `D4 00 60 42`. The candidate ends at `0x17028`, before that area, and its CSF pointer is zero. It therefore **does not retain the original CSF chain**. The original signature was not cryptographically verified here, and candidate HAB acceptance was not tested.

**Interpretation:** the CDC candidate is a very close derivative of bootloader A, mainly modified to expose CDC ACM instead of HID. It is not a new controller firmware or evidence of permanent unlock. Binary similarity does not make it safe to flash.

Reproducer: `tools/audit_community_bootloader_patch_phase93.py`. CI uses synthetic fixtures; the hashes and findings above come from a local comparison of private binaries, which are not published.

## 7. Separate artifact: `thebb_ivt_flashloader.bin`

A separate library file was inspected:

- 98,148 bytes; SHA-256 `700e2cbbb884dc74a2b5d71da420350d6dca67e55f456a24f2d3ba7a69dde258`.
- IVT at offset `0x400`; entry `0x20002000`; Boot Data at `0x20000420`; null CSF pointer.
- Boot Data declares `0x18000` bytes, 156 more than the supplied file.
- USB device `15A2:0073`, one HID interface, interrupt endpoints `0x81`/`0x02`, 64 bytes.
- The binary contains the ASCII marker `CDC`, but its parsed USB configuration has **no CDC ACM interface or CDC Union**.

This is a separate RAM-flashloader-like artifact with a Freescale/NXP-style USB HID identity. Its provenance and relationship to tchebb's exploit are unverified. Do not confuse it with `bootloader-usb-acm.bin`.

## 8. Bruce KVS table: Phase 95 verified correction

New reverse-engineering notes revealed that the first parser started eight bytes too late: the actual table begins at file offset `0xC3C58`, records are 32 bytes, **ID is at +0** and **name pointer is at +8**. The old parser paired each name with the following record's ID.

The exact SHA-256-pinned signed Bruce image has **67 keys**, with IDs 0–66.

| Actual Bruce ID | Key |
|---:|---|
| 20 | `AnalyticsOptIn` |
| 21 | `LastKnownSntp` |
| 22 | `IsDfDevice` |
| 23 | `UpdateGauge` |
| 24 | `OtaFromBuild` |
| 39 | `AppImageFdrVer` |
| 40 | `BootImageFdrVer` |
| 41 | `HidOverGatt` |
| 43 | `LogToUart` |
| 44 | `CrashReboot` |

**These are Bruce IDs, not Gotham IDs.** Stock Wi-Fi Gotham has 115 keys with a different mapping. Bruce contains no ASCII `YetiEnvironment`, `YetiDiscoUrl` or `YetiGmsgUrl` literals.

Verified exact-image CI: [Bruce KVS](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/45062718753). Corrected evidence: `evidence/bruce-kvs-registry-phase93.json` and `evidence/community-file-intake-phase95.json`. No real KVS write was performed.

## 9. Updated technical decision

- **Verified:** the CDC candidate is a byte-level derivative of bootloader A; its code/descriptor changes are bounded; it removes the original CSF pointer and authentication tail.
- **Verified:** `thebb_ivt_flashloader.bin` is a separate HID-descriptor artifact, not a CDC ACM device.
- **Verified:** the Bruce KVS map does not match the IDs reported for Gotham.
- **Pending:** inspect original Gotham `ota.282115` to resolve the 115-key registry, USB `set KVS` handler and GMsg consumer.
- **NO-GO:** flashing the CDC candidate, invoking SDP, changing fuses, real KVS writes or invasive recovery.


## 10. Stadiacast upstream source check

Reviewed public repository `jkfran/stadiacast`, commit `9605bf461a157608b8a8756ba21fb68f7afd5ffb`, release **v1.3.0**, published 18 November 2026. Its README states end-to-end operation with stock Wi-Fi firmware `ota.282115` and **no controller firmware modification**.

Its `docs/protocol.md`, `config.py` and `receiver.py` corroborate the split:

| Service | Host |
|---|---|
| FVC / Discovery RPC | `cloudcast-pa.googleapis.com` |
| GMsg / signaling-message delivery | `cloudcast-gmsg-prod.googleapis.com` |
| Clearcut | `play.googleapis.com` |
| SNTP | `time.google.com` |

The project also forwards `connectivitycheck.gstatic.com` and `clients3.google.com` to Google. GMsg delivers the WebRTC answer bundle to the controller. The Discord network description is consistent with this public source.

**Limit:** Stadiacast verifies stock-firmware network interoperability. It does not prove that USB `set KVS` accepts arbitrary keys, nor that Tomás's custom firmware is published or works on Switch 2.

Sources: [README](https://github.com/jkfran/stadiacast/blob/9605bf461a157608b8a8756ba21fb68f7afd5ffb/README.md), [protocol](https://github.com/jkfran/stadiacast/blob/9605bf461a157608b8a8756ba21fb68f7afd5ffb/docs/protocol.md), [config](https://github.com/jkfran/stadiacast/blob/9605bf461a157608b8a8756ba21fb68f7afd5ffb/src/stadiacast/config.py).

## 11. FIELD_RETURN fuse risk: NO-GO

The i.MX RT1060 reference manual describes `FIELD_RETURN` at `0x400[31]`: 0 is functional/secure mode; 1 opens the device for field-return testing. It is intended for parts returned from shipped products and fuse burning is CSF-protected. NXP community guidance for RT1061 confirms `SEC_CONFIG_CLOSED` means only authenticated images execute.

We have not found sufficient primary evidence to confirm the exact FIELD_RETURN map and consequences on the controller's RT1061. An NXP i.MX7D case where Field Return left the part unable to boot is a different SoC and is **not generalized** to RT1061; it is a caution against assuming Field Return is a harmless unlock.

**Decision:** do not read or program fuses in this research. Do not invoke any FIELD_RETURN command. No hardware was touched.

Sources: [i.MX RT1060 Reference Manual, fuse table](https://www.pjrc.com/teensy/IMXRT1060RM_rev3.pdf), [NXP RT1061 fuse discussion](https://community.nxp.com/t5/i-MX-RT-Crossover-MCUs/1061-fuse-configuration/td-p/1705836), [NXP i.MX7D FIELD_RETURN warning](https://community.nxp.com/t5/i-MX-Processors/iMX7D-not-booting-after-FIELD-RETURN-fuse-blown/m-p/1206202/highlight/true).
