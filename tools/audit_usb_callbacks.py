"""Phase 14: SHA-locked, offline bootloader USB descriptor and callback analysis.

Never opens USB, modifies a device, uploads a binary, or runs firmware.
Descriptions are limited to observed data and selected machine-code anchors.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

BASE = 0x60800000
SIZE = 0x20000
EXPECTED_SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
DEVICE_OFFSET = 0xBF78
CONFIG_OFFSET = 0x1527C
EVENT_TABLE_OFFSET = 0x16290
SECOND_EVENT_TABLE_OFFSET = 0x16284
CALLBACK_ROUTINE = 0x60809E64
DEFAULT_HANDLER = 0x60809E3D
OBJECT_BASE = 0x20008B78

TRANSFER = {0: "control", 1: "isochronous", 2: "bulk", 3: "interrupt"}


def u16(data, pos):
    return struct.unpack_from("<H", data, pos)[0]


def u32(data, pos):
    return struct.unpack_from("<I", data, pos)[0]


def parse_device_descriptor(data):
    """Parse a standard USB descriptor supplied as 18 bytes."""
    if len(data) != 18 or data[0:2] != b"\x12\x01":
        raise ValueError("Not an 18-byte USB device descriptor")
    return {
        "bcd_usb": f"0x{u16(data, 2):04x}",
        "device_class": f"0x{data[4]:02x}",
        "device_subclass": f"0x{data[5]:02x}",
        "device_protocol": f"0x{data[6]:02x}",
        "max_packet_size_ep0": data[7],
        "vid": f"0x{u16(data, 8):04x}",
        "pid": f"0x{u16(data, 10):04x}",
        "bcd_device": f"0x{u16(data, 12):04x}",
        "num_configurations": data[17],
    }


def parse_configuration(blob):
    """Parse standard USB descriptors, refuse truncation and duplicate endpoints."""
    if len(blob) < 9 or blob[0:2] != b"\x09\x02":
        raise ValueError("Invalid configuration descriptor")
    total = u16(blob, 2)
    if not 9 <= total <= len(blob):
        raise ValueError("Truncated or invalid configuration")
    if total != len(blob):
        raise ValueError("Unexpected bytes after configuration")
    config = {"total_length": total, "num_interfaces": blob[4],
              "configuration_value": blob[5], "interfaces": [],
              "interface_associations": [], "unknown_descriptors": []}
    pos, current = 0, None
    while pos < total:
        if pos + 2 > total:
            raise ValueError("Truncated descriptor header")
        n, typ = blob[pos], blob[pos+1]
        if n < 2 or pos + n > total:
            raise ValueError(f"Invalid USB descriptor length at {pos}")
        d = blob[pos:pos+n]
        if typ == 2 and pos == 0:
            if n != 9:
                raise ValueError("Invalid configuration header size")
        elif typ == 11 and n == 8:
            config["interface_associations"].append({
                "first_interface": d[2], "count": d[3],
                "function_class": f"0x{d[4]:02x}",
            })
        elif typ == 4 and n >= 9:
            current = {"number": d[2], "alternate_setting": d[3],
                       "declared_endpoints": d[4], "class": f"0x{d[5]:02x}",
                       "subclass": f"0x{d[6]:02x}", "protocol": f"0x{d[7]:02x}",
                       "endpoints": []}
            config["interfaces"].append(current)
        elif typ == 5 and n >= 7:
            if current is None:
                raise ValueError("Endpoint before interface")
            ep = d[2]
            if any(v["address"] == f"0x{ep:02x}" for v in current["endpoints"]):
                raise ValueError("Duplicate endpoint on same interface")
            current["endpoints"].append({
                "address": f"0x{ep:02x}",
                "direction": "IN" if (ep & 0x80) else "OUT",
                "transfer": TRANSFER[d[3] & 3],
                "max_packet_bytes": u16(d, 4) & 0x7FF,
                "interval": d[6],
            })
        elif typ == 0x21 and n >= 9 and current is not None:
            current["hid_report_descriptor_bytes"] = u16(d, 7)
        else:
            config["unknown_descriptors"].append({"offset": pos, "type": f"0x{typ:02x}"})
        pos += n
    if len({i["number"] for i in config["interfaces"]}) != config["num_interfaces"]:
        raise ValueError("Configuration interface count mismatch")
    for i in config["interfaces"]:
        if len(i["endpoints"]) != i["declared_endpoints"]:
            raise ValueError("Interface endpoint count mismatch")
    return config


def _locations(image, pointer):
    return [f"0x{BASE + offset:08x}" for offset in range(0, len(image)-3, 4)
            if u32(image, offset) == pointer]


def audit(image, expected_sha256=EXPECTED_SHA256):
    """Use an override only in synthetic tests. Real CLI enforces known SHA."""
    if len(image) != SIZE:
        raise ValueError("Bootloader must be exactly 131072 bytes")
    sha = hashlib.sha256(image).hexdigest()
    if sha != expected_sha256:
        raise ValueError("Unexpected bootloader SHA-256; refusing build-specific decoding")
    device = parse_device_descriptor(image[DEVICE_OFFSET:DEVICE_OFFSET+18])
    if (device["vid"], device["pid"]) != ("0x18d1", "0x946b"):
        raise ValueError("Unexpected bootloader USB VID/PID")
    total = u16(image, CONFIG_OFFSET+2)
    config = parse_configuration(image[CONFIG_OFFSET:CONFIG_OFFSET+total])
    if total != 80:
        raise ValueError("Unexpected configuration length for build 169429")

    # Thumb odd pointers from the signed image's static event table.
    first = u32(image, EVENT_TABLE_OFFSET)
    second = u32(image, SECOND_EVENT_TABLE_OFFSET)
    if first != CALLBACK_ROUTINE | 1:
        raise ValueError("Vendor event callback pointer changed")
    if second != 0x60809C59:
        raise ValueError("Secondary event callback pointer changed")
    if u32(image, 0x9E8C) != OBJECT_BASE or u32(image, 0x9E90) != DEFAULT_HANDLER:
        raise ValueError("Vendor callback literal data changed")
    if u32(image, 0xBBB0) != DEFAULT_HANDLER:
        raise ValueError("Constructor callback default changed")
    if u32(image, 0xAF54) != BASE + CONFIG_OFFSET:
        raise ValueError("Configuration descriptor pointer changed")

    # These instruction slices are direct matches for the audited build,
    # not a general-purpose decoder or proof of dynamic control flow.
    anchors = {
        0x9E64: bytes.fromhex("7f 29"),  # cmp r1, #0x7f
        0x9E6E: bytes.fromhex("d0 f8 f0 35"),  # ldr.w r3, [r0,#0x5f0]
        0x9E76: bytes.fromhex("d0 f8 f4 05"),  # ldr.w r0, [r0,#0x5f4]
        0x9E7A: bytes.fromhex("98 47"),  # blx r3
        0xBB46: bytes.fromhex("c4 f8 f0 35"),  # str.w r3, [r4,#0x5f0]
        0xBB68: bytes.fromhex("c4 f8 f4 55"),  # str.w r5, [r4,#0x5f4]
    }
    for at, raw in anchors.items():
        if image[at:at+len(raw)] != raw:
            raise ValueError(f"Changed instruction anchor at {BASE+at:#x}")

    return {
        "phase": 14, "firmware_image": "bootloader A build 169429",
        "sha256_verified": True, "sha256": sha, "bytes": len(image),
        "hardware_access": False, "flash_operations": False,
        "usb_device_descriptor": {"address": f"0x{BASE+DEVICE_OFFSET:08x}", **device},
        "usb_configuration": {"address": f"0x{BASE+CONFIG_OFFSET:08x}", **config},
        "configuration_pointer_words": _locations(image, BASE+CONFIG_OFFSET),
        "usb_class_event_tables": {
            "vendor_event_table_entry": f"0x{BASE+EVENT_TABLE_OFFSET:08x}",
            "vendor_event_callback": f"0x{CALLBACK_ROUTINE:08x}",
            "other_event_table_entry": f"0x{BASE+SECOND_EVENT_TABLE_OFFSET:08x}",
            "other_event_callback": "0x60809c58",
        },
        "vendor_event_path": {
            "callback_entry": f"0x{CALLBACK_ROUTINE:08x}",
            "event_filter": "unsigned event value > 0x7f",
            "object_base_literal": f"0x{OBJECT_BASE:08x}",
            "callback_pointer_at_ram": f"0x{OBJECT_BASE+0x5f0:08x}",
            "callback_context_at_ram": f"0x{OBJECT_BASE+0x5f4:08x}",
            "initial_default_handler_thumb": f"0x{DEFAULT_HANDLER:08x}",
            "default_handler_is_zero_return_stub": True,
            "dynamic_dispatch": "conditional BLX through registered callback pointer",
            "subsequent_handler_registration": "NOT RECONSTRUCTED",
        },
        "usb_to_flash_writer": "NOT DEMONSTRATED",
        "custom_firmware_execution": "NOT DEMONSTRATED",
        "scope": "USB descriptor structures and anchored callback instructions only",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bootloader", type=Path,
                        help="Private locally owned bootloader-a.bin (never uploaded)")
    parser.add_argument("--out", type=Path, help="Write sanitized JSON report to this file")
    args = parser.parse_args()
    result = audit(args.bootloader.read_bytes())
    encoded = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
