# Phase 93 — Cross-phase evidence and test audit

**22 November 2026.** This phase cross-checks phases 91–92 against repository artifacts, GitHub Actions logs and newly identified public sources. No controller is connected and no firmware is executed.

## 1. Own-repository test results

| Group | Result | Run |
|---|---:|---|
| Phase 91 private-artifact intake | 10/10 per version | Python 3.11 and 3.12 |
| Phase 92 USB descriptors and OEM differential | 17/17 per version | Python 3.11 and 3.12 |
| Full offline suite | 1,012 passed; 34 skipped | Python 3.11 and 3.12 |
| OEM sample and bounded-emulation lane | 89 passed; 0 skipped | GitHub Actions |
| Five regression lanes | All successful | Bruce, bootloader, NXP HAB, USB HID and independent QA |

The 34 skips in the general offline suite are conditional tests requiring optional samples/fixtures, not failures. A separate original-sample/emulation lane completed 89 tests. Action run URLs are pinned in `evidence/community-validation-phase93.json`.

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