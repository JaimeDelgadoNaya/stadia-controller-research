# Phase 79 — Bounded physical HID input observation

27 October 2026. Following phase 78's stopping criterion, the connected controller was observed through Windows HID, rather than extending the shared Work Queue initializer hypothesis.

One matching Game Pad collection (VID 18D1, PID 9400, usage page 1, usage 5) was opened using hidapi 0.14.0.post4. **Windows delivered zero input reports during 10.015 seconds.** No button actions were requested or labeled. This does not establish device failure, absence of USB traffic, or incompatibility; inactivity, publication behavior, device mode and other causes remain unresolved. The earlier descriptor contract (ID 3, 11 bytes) is not dynamically confirmed by an empty observation.

The tool invokes no output writes, feature operations or mode commands. HID reads use the Windows stack; this is not a passive bus packet capture. Vendor bulk endpoints are not observed. No drivers were installed or firmware/eFuses written. Paths, serials and instance identifiers are omitted. No USB-to-Work-Queue or callback link is established.

On Windows, install `hidapi==0.14.0.post4`, then run `python -m tools.capture_hid_input_phase79 --seconds 10 --out local/hid-observation.json`. Duration is capped at 30 seconds. Distinct report bytes and frequencies are aggregated without per-report timing or ordering. Offline tests validate aggregation and the recorded evidence; CI cannot reproduce physical observations.

[Evidence](../../evidence/usb-live-hid-input-phase79.json). Next discriminating experiment: repeat with deliberate user-labeled button actions, then use a bus capture if input remains absent. USBPcapCMD/tshark were not found in PATH or their usual Program Files directories; other installations are not excluded.
