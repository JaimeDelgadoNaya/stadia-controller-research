# Phase 79 — Passive USB host-metadata audit against OEM descriptors

**27 October 2026.** A bounded continuation of [phase 78](original-shared-workqueue-init-phase78.md). The new offline-only tool processes existing host USB URB metadata. It does **not** open a device, issue requests, parse payload bytes or write firmware.

## What was established

`tools/audit_passive_usb_phase79.py` consumes Tshark metadata CSV and verifies the **full 80-byte phase61 measured configuration descriptor** using SHA-256 `01b299fc757c731df8c2de21a953ed8b0fc0c854f6043c178b8cc7588c26e5db`. Phase62 found that same descriptor exactly once in the examined signed OEM image, but the installed application hash remains unmeasured.

The active declared endpoint map is vendor interface 0 bulk OUT `0x07` / bulk IN `0x87` (512-byte maximum each), and HID interface 1 interrupt OUT `0x03` / interrupt IN `0x83` (64 bytes each). EP0 control submits are grouped by standard/class/vendor request kind, direction and bRequest. Unknown endpoints are reported separately.

URB submission `S`, completion `C` and error `E` events are counted separately: submission and completion may refer to the same transfer. Length sums are **capture-reported metadata**, not verified device-consumed bytes. The operator must select a bus/address pair. A correct VID/PID `18D1:9400` must be present *in those selected records* before the report can label identity as observed; if absent, identity is explicitly unverified. Mismatches fail closed.

**Testing:** ten local synthetic tests passed. They cover signed-descriptor identity, endpoint mapping, mixed-device exclusion, wrong/partial VID/PID, malformed USB records, EP0 setup fields and private payload-column rejection. **No new physical USB trace was available or analyzed** in this phase.

## Reproduce

First make a **passive normal-operation capture** using Wireshark/USBPcap on Windows or usbmon on Linux. Keep `.pcapng` local. Do not inject any packets. With Tshark and a UTF-8-capable shell (PowerShell 7+ or POSIX shell):

```sh
tshark -r local/stadia-normal.pcapng -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e usb.bus_id -e usb.device_address -e usb.endpoint_address -e usb.urb_type -e usb.data_len -e usb.bmRequestType -e usb.setup.bRequest -e usb.idVendor -e usb.idProduct > local/stadia-metadata.csv
python -m tools.audit_passive_usb_phase79 local/stadia-metadata.csv --bus 1 --address 4 --out local/phase79.json
python -m unittest tests.test_passive_usb_phase79 -v
```

The bus/address arguments are **placeholders**, not a recorded real controller identity. Select the actual assigned address after enumeration; it may change after reconnect. Do not restrict the capture export to VID/PID-only rows, as most operational URBs lack these fields.

The input allowlist deliberately excludes raw data, serial numbers and timestamps; the output is aggregate-only. Raw captures/CSV should not be published without independent privacy review. See [Wireshark USB field reference](https://www.wireshark.org/docs/dfref/u/usb.html) and [USB capture description](https://wiki.wireshark.org/USB).

## Decision boundary

A repeatable physical transfer on a declared endpoint would justify targeted static receiver tracing. It would **not** by itself establish a firmware callback, RAM pointer control, custom execution, HAB CLOSED bypass or native Xbox interoperability. The shared Work Queue helper found in phase 78 is not a host-origin execution proof.

[Tool](../../tools/audit_passive_usb_phase79.py) · [Synthetic tests](../../tests/test_passive_usb_phase79.py) · [Prior phase](original-shared-workqueue-init-phase78.md)
