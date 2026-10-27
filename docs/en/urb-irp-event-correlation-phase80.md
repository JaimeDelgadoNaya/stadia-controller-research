# Phase 80 — Passive USB URB/IRP event correlation

**27 October 2026.** Offline follow-up to [phase 79](passive-usb-metadata-audit-phase79.md). No controller is required. Phase 61 descriptor SHA-256 gating and older metadata CSVs stay compatible.

## Methodology improvement

Host `S` (submit) and `C` (complete), or `S` and `E` (error), can be events of the **same USB operation**. Wireshark exposes `usb.urb_id`, and some Windows USBPcap exports expose `usb.irp_id`. The auditor now uses those IDs **only in memory** to distinguish:

- Same-ID and same-endpoint `S→C` / `S→E` pairs.
- Orphan `C/E` events and unfinished `S` events at the capture boundary.
- Sequential reuse of an ID after its previous operation completes.
- Duplicate submits while an ID is pending: mark ambiguous, never count as a valid pair.
- Endpoint mismatches and missing endpoint/ID metadata: no invented pairing.

Raw URB/IRP IDs **never appear in output or errors**. The parser supports unsigned 64-bit IDs in decimal or `0x` hex notation. Conflicting values between exported ID columns are rejected. At most 200,000 active IDs may be held in memory.

## Deferred physical capture procedure

When a controller becomes available, capture only normal operation with usbmon or USBPcap. Keep `.pcapng` local, then export metadata:

```sh
tshark -r local/stadia-normal.pcapng -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e usb.bus_id -e usb.device_address -e usb.endpoint_address -e usb.urb_type -e usb.data_len -e usb.bmRequestType -e usb.setup.bRequest -e usb.idVendor -e usb.idProduct -e usb.urb_id -e usb.irp_id > local/stadia-metadata.csv
python -m tools.audit_passive_usb_phase79 local/stadia-metadata.csv --bus <actual_bus> --address <actual_address> --out local/phase80.json
python -m unittest tests/test_passive_usb_phase80.py -v
```

Check whether installed Tshark supports each ID field, omitting unsupported `-e` fields. If neither field is exported, old behavior remains and `urb_pairing.status` becomes `not_exported`. Identifiers are capture-local and can be reused. A paired URB is **not evidence that firmware processed bytes or that any OEM callback ran**.

Do not commit packet captures, raw metadata exports or host identifiers. No device requests, payload inspection, RAM access or firmware modification occur.

## Evidence boundary

**Validated only by synthetic regression tests and code review:** pairing/disambiguation logic. **Still absent:** physical traffic, signed OEM endpoint-to-receiver linkage, host→Work Queue callback provenance, arbitrary code execution, custom firmware or HAB CLOSED bypass.

**GO**: analyze user-owned passive capture aggregates, then pursue independent OEM receiver evidence. **NO-GO**: infer device-side execution from host-side correlation counts.

References: [Wireshark USB](https://wiki.wireshark.org/USB) · [Wireshark USB fields](https://www.wireshark.org/docs/dfref/u/usb.html) · [Linux usbmon](https://docs.kernel.org/usb/usbmon.html).

[Implementation](../../tools/audit_passive_usb_phase79.py) · [Synthetic tests](../../tests/test_passive_usb_phase80.py)
