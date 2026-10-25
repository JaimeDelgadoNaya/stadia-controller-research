# Work package A — Actual archived Stadia updater host protocol

**Completed as offline source inspection only.** Never execute the archived
JavaScript, connect the controller, issue HID requests, or program flash.

Primary [archived Closure-minified script](https://github.com/hazrpg/stadia-flasher/blob/main/controller/app_combined.js):
149,810 bytes, **Git blob SHA-1 `3c877738c12e7d5750714cd0770935ad39bd9990`**.
Independent command-ID comparison:
[stadiatool/sdp.py](https://github.com/GaryOderNichts/StadiaController/blob/main/stadiatool/sdp.py)
and [stadiatool/flashloader.py](https://github.com/GaryOderNichts/StadiaController/blob/main/stadiatool/flashloader.py).

## Main result

The archived browser updater does **not** send firmware bytes to bootloader A
vendor Bulk OUT 0x07. This source contains **zero WebUSB bulk transfer calls**.
It uses **WebHID** for ROM SDP and the signed RAM flashloader. WebUSB is
used for normal-mode status:

| Mode | VID:PID | Purpose |
|---|---|---|
| OEM normal | `18D1:9400` | WebUSB class version/battery requests |
| Bootloader | `18D1:946B` | Enumerated mode, not this script's flash-data recipient |
| ROM SDP | `1FC9:0135` | WebHID, load original signed RAM loader |
| RAM flashloader | `15A2:0073` | WebHID, configure/erase/write/reset flash |

## Host → receiver sequence and validations

| Stage | Minified JS functions | Host requests | Receiving component / condition |
|---|---|---|---|
| Normal status | `Aj/Bj/Dj/Cj/Ej` | WebUSB class interface IN **0x81**, OUT **0x83**, IN **0x84** | Normal application; version and battery; not flash writes |
| Load flashloader | `wm/bj/cj` | WebHID SDP **WRITE_FILE 0x0404** to RAM `0x20000000`, report 2 data, **JUMP_ADDRESS 0x0b0b** to `0x20000400` | NXP ROM SDP; original **signed** RAM loader previously accepted on HAB CLOSED |
| Configure | `hj/ij/sj/pj` | Flashloader commands **0x11 ConfigureMemory**, **0x03 ReadMemory**, **0x05 FillMemory** | Signed RAM flashloader; status/error handling |
| Select signed image | `lm/Ri/Qi` | Choose Bruce/Gotham dev/dvt/pvt, check metadata header/footer/size/reset vector partition | Host structural checks, **not** signature authentication |
| Install | `fj/kj/lj/mj/nj` | **0x02 erase** in ≤16-KiB segments, **0x04 write** with ≤512-byte HID report-2 payloads, then **0x0b reset** | Signed RAM flashloader; check command statuses |
| Verify | `xm/Dj` | Reconnect normal WebUSB and query **0x81** | Expected build number, not whole-flash integrity or power-loss recovery |

ROM SDP's command structures use big-endian fields; the later
flashloader's command parameters are little-endian. The host may
process a 4096-byte IVT for bootable images and selects a flash partition
based on the reset handler. The firmware installation path runs through
ROM and signed RAM loader rather than the previously investigated
bootloader vendor callback.

The browser's serial prefix checks, DVT/PVT selection, battery ≥10%
restriction (when measured), flash-type detection, metadata checks and
command responses are not proof of an authorization policy accepting
third-party unsigned firmware. HAB CLOSED remains measured; neither
arbitrary execution nor safe rollback was shown. Bootloader B was empty
on the tested controller. The tentative signed Bruce app message
`0x60058B68` / payload byte 5 is **not** tied to these update packets.

## Reproduce safely

Save the original archived JavaScript to `local/app_combined.js`;
**do not run it inside a browser**.

```sh
python tools/audit_archived_updater.py local/app_combined.js --out local/host-updater.json
python -m unittest discover -s tests -v
```

The auditor verifies exact byte count and Git blob SHA-1, named
function anchors, and USB transfer-site census, without executing JS
or opening USB. CI uses synthetic text only.

**Package A result:** real host-originating firmware installation commands
are demonstrated **in archival source** through ROM SDP and a signed
RAM flashloader; custom unsigned code execution and reliable recovery
are **not** demonstrated. One bounded **package B** remains:
signature/boot acceptance and recovery assessment, then mandatory STOP/GO
per the [decision gate](update-execution-decision-gate.md).
