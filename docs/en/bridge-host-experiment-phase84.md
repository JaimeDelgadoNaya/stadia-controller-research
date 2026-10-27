# Phase 84 — Original BLE bridge host tests

27 October 2026. The pinned upstream `bridge.c` was compiled for the host with Zig/Clang 0.13.0 and stubbed FreeRTOS queues. A small host wrapper calls the original parser and translation functions. The GPL source remains in its separate checkout; the commit, pinned source hashes and compiled headers are verified against Git objects.

Individual bits of synthetic payload bytes 1, 2 and 9 were tested. Phase 80's 1,399 distinct USB payloads were also replayed **as hypothetical BLE-shaped inputs**, each paired with five individual bit flips: 6,995 comparisons (8,790 weighted by recorded report frequencies). All five flips preserved the 20-byte output and the 13 selected parsed flags for the tested payloads.

Byte 1 bits 2 and 3 correspond by USB position to usages 20 and 19; byte 9 bits 0–2 correspond to USB Consumer usages. For these hypothetical inputs none changed the inspected flags or Xbox output. Byte 1 bits 0 and 1 changed the upstream `capture` and `assistant` flags respectively without changing ordinary Xbox output. The upstream receiver passes those flags to a configurable-action subsystem, which this test did not execute. The parser also retains raw bytes: invariance refers only to the 13 inspected flags and output, not the complete state object.

USB replay does **not** establish the real BLE layout or physical meaning, and therefore does not demonstrate real lost controls. Queue scheduling, timing, transport, reconnection and configurable actions were not executed. A separately captured BLE trace with labeled actions is needed before attributing a bridge defect.

Reproduce with `python -m pip install ziglang==0.13.0`, verify the separately prepared source using `python tools/prepare_external_bridge.py local/stadia-dongle-esp --verify-only`, then run `python -m tools.audit_bridge_host_phase84 local/stadia-dongle-esp evidence/usb-live-hid-input-phase80.json --library local/bridge84.dll --out local/bridge84.json`. Set `STADIA_BRIDGE_CHECKOUT` and `STADIA_BRIDGE_LIBRARY` to absolute paths to enable the unittest host reproduction. CI reproduces it on Linux; the local original experiment ran on Windows. [Evidence](../../evidence/usb-bridge-host-tests-phase84.json).

No ESP32 firmware build, physical device access, BLE pairing, console compatibility test or firmware/eFuse write occurred.
