# Phase 32 — Reversible continuation

2026-10-25. The owner's priority is use on compatible consoles. Phase 31's
internal-flashing stop remains in effect. See the
[console compatibility matrix](console-compatibility.md) and the
[full Spanish continuation](../es/puente-externo.md).

`tools/prepare_external_bridge.py` fetches a separate GPL-3.0 upstream checkout
of [stadia-dongle-esp](https://github.com/danzig666/stadia-dongle-esp/tree/d8392de8f838e12cf16c985b9beb8080c7acd970)
at commit `d8392de8f838e12cf16c985b9beb8080c7acd970`. It checks HEAD and
nine SHA-256 source hashes, refuses nonempty destinations and writes provenance.
It never builds, flashes, installs drivers or communicates with the controller.

```sh
python tools/prepare_external_bridge.py local/stadia-dongle-esp
python tools/prepare_external_bridge.py local/stadia-dongle-esp --verify-only
python -m unittest discover -s tests -v
```

Python 3.10+ and Git are required. The separately fetched project retains its
own license. Selected source hashes establish source identity, not a complete
audit or a reproducible binary. The upstream uses ESP32-S3 native USB, NimBLE
and TinyUSB, requires ESP-IDF 6.x and at least 4 MB flash, and targets PC Xbox
360 input. No ESP32-S3 availability, build, pairing, rumble, latency or console
operation has been verified locally. USB firmware version does not prove BLE
pairability. The live web installer does not preserve this source pin.

Before hardware validation record the board, SDK and binary hashes, then test
enumeration, BLE pairing, every input, rumble, neutral state on disconnect and
reconnection. Validate each exact console/adapter/firmware combination separately.
No audio or microphone support follows from button translation.
