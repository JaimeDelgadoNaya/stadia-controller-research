# Phase 82 — Differential HID decoder tests

27 October 2026. Entirely offline work; no device opening or physical actions requested.

The phase 81 direct decoder matches descriptor-driven extraction for **39,424 synthetic reports**: all 32,768 subsets of 15 button bits, 2,560 individual payload-byte sweeps, and 4,096 reproducible mixed payloads using seed 82. Every returned state field and diagnostic is compared. All button subsets are covered; the complete 80-bit payload space is not exhausted.

The auditor also verifies rejection of all 255 wrong report IDs, 64 wrong lengths within 0–64 bytes, and 1,504 single-bit descriptor mutations. Descriptor mutation checks exercise the hash guard, not alternate device contracts. Negative controls deliberately swap button usages or drop the padding diagnostic; both are detected. A SHA-256 identifies the exact generated vector stream. The reference shares the earlier generic descriptor parser/extractor and does not independently validate those helpers or the entire HID standard.

A validation defect was fixed: replay accepted Boolean or floating-point report totals when Python numeric equality matched the integer sum. `report_count` now requires an actual nonnegative integer, rejecting Boolean, floating-point, negative, string and null values. Valid published capture results remain unchanged.

Run `python -m tools.audit_hid_differential_phase82 evidence/stadia-hid-report-contract.json --out local/differential82.json` and `python -m unittest tests.test_hid_differential_phase82 -v`.

[Evidence](../../evidence/usb-hid-differential-phase82.json). This validates input processing for a possible bridge, not physical control assignments, latency/polling, console output/authentication, Xbox/Switch compatibility, Work Queue reachability or custom firmware execution.
