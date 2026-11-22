# Phase 92 — Offline CDC ACM descriptor audit of a community bootloader candidate

**22 November 2026.** Locally provided `bootloader-usb-acm.bin`: **94,248 bytes**, SHA-256 `ea37f7cd38ab7ae392fa80911aeed4b07ac7e557b8bb66375e099e8ebd148957`. Neither uploaded firmware nor private bonding data are published. **Static bytes only**, no flashed device/USB experiment; this is not the owner's signed original bootloader A.

## Byte-grounded facts

- Device descriptor at file **`0xBF78`**: 18 bytes, USB 2.0, class/subclass/protocol **`EF/02/01`**, VID:PID **`18D1:946B`**, EP0 size 64, string index `iSerialNumber=4`, and **three advertised configurations**.
- Configuration at **`0x1527C`**: `wTotalLength=85`, three interfaces and **12 descriptors summing to 85 bytes**. No malformed descriptor lengths, endpoint-count mismatches or unknown CDC Union references were found.
- Interface 0: Vendor, bulk IN `0x87` and OUT `0x07`, 512 max packets.
- Interface 1: CDC Communication/ACM `02/02`, interrupt IN `0x82` (8).
- Interface 2: CDC Data `0A`, bulk IN `0x81` and OUT `0x01`, 512 max packets.
- CDC Union subtype `06` **master 1, slave 2** is present. **Zero IAD descriptors** in this configuration.
- Device class `EF/02/01` usually advertises IAD-based composite behavior, whereas this configuration has none. See [Microsoft IAD documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-interface-association-descriptor) and [CDC collection enumeration](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/support-for-interface-collections).

**Caveat:** Windows can also group CDC interfaces using the Union Functional Descriptor; missing IAD is a plausible interoperability issue, **not a confirmed enumeration error**. The device descriptor advertises three configurations but the raw file scan found only one decodable `09 02` configuration. Runtime construction or other sources remain possible. No assertion is made that three configurations are missing at runtime.

## Offline reproduction

```sh
python -m tools.audit_usb_descriptors_phase92 /private/bootloader-usb-acm.bin --device-offset 0xbf78 --configuration-offset 0x1527c
python -m unittest tests.test_usb_descriptors_phase92 -v
```

**12 synthetic tests passed locally** for headers, lengths, endpoint counts, Union associations, missing/present IAD, truncation and invalid data. CI checks Python 3.11/3.12. Sanitized findings are in `evidence/usb-cdc-phase92.json`.

## Research decisions

- Correlate any future **authorized, safe, passive USB host capture** with active configuration, the three declared configuration values, and OS driver selection. **No new capture occurred.**
- Before claiming a fixed descriptor or bootability, compare against the same revision of the **original signed firmware** and record a real enumerated descriptor. Current uploaded candidate's null CSF pointer does not validate HAB CLOSED boot.
- The [NXP SDP claim by tchebb](https://www.reddit.com/r/Stadia/comments/1xwcedq/has_anyone_bypassed_the_bootloader_signage/) is author-reported; external exploit source is **not available for independent audit here**. No ROM version, permanent FIELD_RETURN success, device-execution or safe recovery is established by this work.
- The Gotham `set KVS` vendor handler and `YetiGmsgUrl` registry question is **separate** and still requires exact signed Gotham firmware static evidence. See [#111](https://github.com/JaimeDelgadoNaya/stadia-controller-research/issues/111).

**GO** only for static analysis and synthetic checks. **NO-GO** for flashing, SDP execution, fuse operations, intrusive recovery, or exposing the confidential bonding file.
## Differential comparison with the **physically measured** OEM phase61 USB descriptors

Internal primary source: [`evidence/usb-enumeration-phase61.json`](../../evidence/usb-enumeration-phase61.json), physical host hub measurement **26 October 2026**; [phase62](usb-descriptor-oem-match-phase62.md) separately matched its 80-byte configuration to the signed OEM application. This is a **descriptor-only** comparison of different execution contexts.

| Field | Live original OEM application | Private community bootloader candidate |
|---|---|---|
| VID:PID | `18D1:9400` | `18D1:946B` |
| bcdUSB / advertised config count | `0x0201` / 1 | `0x0200` / 3 |
| Config length | 80 bytes | 85 bytes |
| Interfaces | Vendor `FF` + HID `03` | Vendor `FF` + ACM `02/02` + CDC Data `0A` |
| IAD count | **2** | **0** |
| Shared endpoints | `0x87`, `0x07` | `0x87`, `0x07` |
| Serial string index (not its value) | 3 | 4 |

The candidate is **not the measured normal USB mode**. Two common Vendor endpoints do not establish a shared handler, working host protocol, boot success or flashing safety. The original firmware's two IADs and candidate's zero IADs sharpen the Windows CDC enumeration hypothesis, but do **not** prove a Windows problem.

Five additional differential tests now compare the archived phase61 measured bytes with the synthetic community-descriptor fixture: **17 total tests**, no device contact.
