# Phase 85 — User-confirmed physical USB controls

27 October 2026. The owner operated the USB-connected controller. Each window requested a single action, and the owner explicitly confirmed that action after the read. Aggregated HID reports contain no paths, serials, per-report timestamps or ordering.

| Confirmed control | Observed USB field |
|---|---|
| A / B / X / Y | Button usages **1 / 2 / 4 / 5** |
| D-pad up / right / down / left | Hat **0 / 2 / 4 / 6**, released **8** |
| Left trigger | Analog page 2 usage **0xC5**, 0–255; digital button **20** |
| Right trigger | Analog page 2 usage **0xC4**, 0–255; digital button **19** |

Each face button and cardinal direction had an active and a released state with other controls unchanged. Both trigger trials reached 0 and 255 and intermediate values. The 346 left and 345 right reports are report counts, not counts of presses.

The previously unlabeled USB usages 20 and 19 are the left and right trigger digital indicators in this session, in addition to their analog values. Sampled values fit a candidate boundary of 64: left clear 0–63 and set 64–255; right clear 0–63 and set 65–255. **Right value 64 was not sampled**; aggregated reports have no order, so an exact universal threshold or absence of hysteresis is not established.

A/B/X/Y and both analog trigger positions match labels in the pinned BLE bridge source. That source translates the analog trigger values; phase 84 found the two candidate digital bits do not change its Xbox output or 13 inspected flags in hypothetical input. This identifies their USB role but does not prove the BLE layout or real bridge behavior.

No diagonals, sticks, LB/RB, vibration or console output were tested; no HID output, mode change or firmware/eFuse write was performed. [Aggregated captures](../../evidence/usb-labeled-controls-phase85.json) and [derived map](../../evidence/usb-control-map-phase85.json) can be reproduced offline using `python -m tools.analyze_labeled_controls_phase85 evidence/usb-labeled-controls-phase85.json evidence/stadia-hid-report-contract.json evidence/usb-ble-layout-comparison-phase83.json --out local/control-map85.json` and `python -m unittest tests.test_labeled_controls_phase85 -v`. CI checks analysis of recorded evidence, not the physical measurement.
