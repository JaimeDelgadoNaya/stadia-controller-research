# Phase 31 — Final internal-execution gate: authentication and recovery

**The second and final offline work package is complete. Decision: STOP internal custom firmware modification; GO for a reversible external bridge.**

This follows the previously agreed finite research budget. It is **not** a proof that no Stadia device could ever be modified. It means a host-originating channel, **authorizable custom-code execution** and **reliable recovery** were not jointly demonstrated.

## Authentication facts

Two privately held user-provided images were checked offline. The existing
`tools/verify_hab.py` cryptographically verifies RSA/CMS signatures against
certificates embedded in the image and SHA-256 digests of declared signed
regions. Both images verified **two CMS signatures each**. A one-byte code
mutation in each *temporary copy* caused content-digest validation to fail.

| Sample | SHA-256 | IVT, CSF | Signed regions |
|---|---|---|---|
| Extracted bootloader A (128 KiB) | `59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0` | IVT offset 0, CSF offset `0x18000` | 0x60001000 length 0x1000 via explicit offset-0 alias, plus 0x60800000 length 0x18000 |
| Supplied Bruce signed update image (1,050,984 B) | `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3` | IVT `0xFF000`, CSF `0xFF030` | 0x60040000 length `0xFF030` |

**Limits:** mathematical signature/digest verification is **not** verification
against the fused SRK hash on the actual device. The signed Bruce update file
is **not** a byte-confirmed full installed-application dump.

The [physical measurements](../es/mediciones.md) of this particular device
established HAB **CLOSED**: ROM ERROR_STATUS `0x12343412`, HAB Success
`0xF0F0F0F0`, restricted RAM flashloader `GetProperty 0x11=1` backed
by code reading OCOTP_CFG5 bit 1.

The [bootloader A authentication path](../es/arranque.md) validates an
application via `0x6080200C`, uses HAB ROM RVT
`0x00200304` (entry), `0x0020032C`
(authenticate_image_no_dcd), `0x00200308` (exit) in
`0x60801F5C`, and jumps at `0x60801F46` only after success.
`0x608020A8` has a **structure-only** update pre-check but later
authentication is mandatory along the verified successful path. Structure
alone does not authorize unsigned custom firmware.

Official technical background:
[NXP RT1060 bootable image format](https://mcuxpresso.nxp.com/mcuxsdk/latest/middleware/mcu_bootloader/docs/iMXRT1060_Manufacturing_User_Guide/topics/imx_rt_bootable_image.html)
and [NXP RT1060 Reference Manual](https://www.pjrc.com/teensy/IMXRT1060RM_rev2.pdf).

## Recoverability decision

The [archived browser updater](archived-updater-host-protocol.md) documents
host → ROM SDP → **Google-signed RAM flashloader** →
flash erase/write/reset → boot/HAB validation. That proves a supported
vendor programming workflow, **not** unsigned custom execution.

- ROM SDP was entered previously, and the original signed RAM loader ran.
- Bootloader B was confirmed entirely erased on the sampled unit.
- There is no complete 16-MB installed-flash backup.
- Interrupted-write recovery and custom-image rollback were not tested.
- Neither custom-signed image trusted by the device nor a HAB CLOSED bypass
  was demonstrated.

**Final gate:** host-to-flash exists, but custom execution and robust
recovery are unproven. **STOP firmware modification**, preserving the only
working controller.

## External bridge next

Prototype using an **ESP32-S3 BLE central + native USB**, drawing on
[danzig666/stadia-dongle-esp](https://github.com/danzig666/stadia-dongle-esp).
Its documented output is a wired **Xbox 360 gamepad for a PC**. That is
**not** proof of Xbox One / Series X|S console support; actual console
deployment needs a verified compatible/authorized interface or adapter.

First validate BLE connection, button mapping, sticks, triggers, rumble,
reconnection and latency on a PC, without changing controller firmware.
Only then select and confirm a console-compatible output method.

```sh
python tools/audit_final_auth_recovery.py local/bootloader-a.bin local/bruce_pvt_a_prod_signed.bin --out local/phase31-final.json
python -m unittest discover -s tests -v
```

This audit reads files only. CI runs synthetic tests, not private firmware.
Reopen the internal track **only if new independent, verifiable evidence
changes the authorization and recovery gates**.
