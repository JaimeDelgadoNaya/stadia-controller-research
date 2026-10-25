# Post-phase-29 decision gate: actual host updater, application and external bridge

The priorities have changed: **first verify a host-originating update path,
then inspect the signed Bruce application where justified, then stop firmware
modification research if no viable and recoverable entry appears**. Do not
keep accumulating unrelated ARM pointer analyses.

## Facts to keep separate

- Normal USB `18D1:9400`: earlier real WinUSB class-IN request
  `0xA1/0x81` returned application/bootloader build numbers.
  A version query is **not** a firmware-writing command.
- Bootloader `18D1:946B`: the vendor bulk OUT `0x07`/IN `0x87`
  callbacks are structurally known, but no authenticated host command
  has been traced from OUT to flash.
- ROM `1FC9:0135` and signed RAM flashloader `15A2:0073` were
  previously observed on one controller. The preserved official WebUSB
  updater uses **signed loaders and signed Bruce images**.
- The private signed Bruce update image (1,050,984 bytes,
  SHA-256 `466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3`)
  is **not** a byte-verified dump of the currently installed flash.
- HAB **CLOSED** remains the measured secure-boot state.

### Initial signed-app audit

A read-only binary check indicates `SP=0x2002B828`, Thumb reset
`0x60040501`, with an **inferred** application XIP base
`0x60040000`. App bytes include logs for updates and USB, and the
source component `usb_device_vendor.cc`.

There is a **candidate message parser at `0x60058B68`**: after a
non-null check it compares the **first byte of an input buffer to 5**
(`0x60058B74`), advances the pointer on this branch and calls
`0x60058AA8` from `0x60058B7A`; an alternative path logs an unknown
USB host request. **This byte is not identified as USB `bRequest` 0x05,
nor as an update command**. Host reachability and any storage/authentication
path remain unknown. Reproduce with `tools/audit_signed_app_surface.py`.

## Two bounded work packages, then a mandatory stop/go decision

**A. Host updater entry (one offline package):**
- Extract the archived WebUSB updater state machine, device VID/PIDs,
  `bRequest`, endpoints, directions, lengths, error handling and mode
  transitions **without executing any transfers**.
- Match host messages to normal USB, bootloader, ROM SDP or the signed
  RAM flashloader; then verify the receiving firmware handler and
  length, authentication and storage conditions.
- Deliver a **host → mode → packet → receiver → validation → storage**
  graph with each edge marked verified/inferred/unproven.

**B. Application and viable execution alternatives (one more offline
package, only if A yields a concrete path):**
- Follow the candidate app message handler and real update receiver.
- Distinguish installing Google-signed images from executing custom
  code. Validate image format and realistic recovery preconditions.
- Never treat the blank backup bootloader B slot as a functioning
  rollback mechanism.

**STOP:** after these two packages, if a host-controlled receiving
edge, authorizable custom execution and reliable recovery cannot be
shown, **end the internal firmware modification track**. Do not launch
another unfocused 20 phases or run a persistent test on the controller.

## External bridge fallback

Keep the original controller firmware untouched; receive Stadia BLE HID
or wired USB, normalize axes/buttons, and output through a genuinely
supported/authorized Xbox interface.

An existing ESP32-S3 open-source Stadia BLE → wired Xbox 360/XInput
**PC** dongle exists:
https://github.com/danzig666/stadia-dongle-esp

**Xbox-console compatibility is not established** by a PC XInput
implementation. Xbox One / Xbox Series X|S may require approved
authentication hardware or compatible licensed adapters. Verify actual
console support before choosing hardware.

Public updater references:
- https://github.com/GaryOderNichts/StadiaController
- https://github.com/hazrpg/stadia-flasher
- https://github.com/merlinschumacher/Stadia-Controller-Bluetooth-Firmware-Bin

All investigation is offline with no USB operations, flash writes,
or proprietary image publication.
