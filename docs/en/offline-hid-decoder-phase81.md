# Phase 81 — Offline HID decoder for bridge input

27 October 2026. The user requested offline work. Two initial requested five-second windows (neutral and A) received no reports and action performance was not confirmed; they are not used to assign controls. No further live reads followed the offline instruction.

The decoder converts phase 80's recorded input into structured state, requiring the exact recorded descriptor SHA-256 and ID 3 / 11 bytes. The fifteen button bits follow usages **18,17,20,19,13,12,11,15,14,8,7,5,4,2,1**, rather than consecutive numbering. This matters for translating input correctly. Tests cross-check all 1,399 distinct recorded reports against generic descriptor extraction and exercise all fifteen bits individually.

Replay covers 1,758 reports. Active button usages and report counts are 20:252, 19:222, 15:1, 14:15, 8:20, 7:8, 2:9, 1:43. These count reports containing a set bit, not press events or durations. Simultaneous buttons are possible. Physical A/B assignments remain unverified.

Hat raw value 8 maps to a null direction in all recorded reports. Codes 8–15 remain preserved as raw values and outside the eight directions; no cardinal orientation is invented. X/Y/Z/Rz retain raw bytes with declared range 1–255, and page 2 usages 0xC5/0xC4 retain 0–255. Nonzero constant padding and generic axes outside logical range are flagged; neither occurs in the recording. Consumer usages remain inactive.

Run `python -m tools.decode_hid_input_phase81 evidence/usb-live-hid-input-phase80.json evidence/stadia-hid-report-contract.json --out local/replay81.json` and `python -m unittest tests.test_hid_decoder_phase81 -v`. The `decode_report(raw, descriptor)` function and replay require no device or hidapi. Tests cover descriptor cross-checks, one-hot buttons, analog boundaries, null states, padding and invalid descriptor/report/count rejection.

[Reproducible evidence](../../evidence/usb-hid-decoder-replay-phase81.json). This prepares input for an external bridge; no output emulation, console authentication, XInput, Xbox/Switch compatibility, Work Queue link or custom firmware execution is implemented. Labeled physical assignments and bridge-target validation remain pending.
