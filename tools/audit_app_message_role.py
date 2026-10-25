"""Bounded offline classification of the private Bruce tag-5 receiver.

No USB/device APIs and no firmware contents in the report. This classifies a
signed update sample, not a verified installed application or reachable endpoint.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

try:
    from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE
except ModuleNotFoundError:
    from audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE

BASE = 0x60040000
REGION = (0x18A7C, 0x18ED8)
REGION_SHA256 = "a83def5a442b49781d9cfc31593f43809657de8173e01457cc077debe74f40e0"
# Semantic anchors, not redistributed firmware bytes. Full-file and region hashes
# are mandatory before decoding. Windows exclude interspersed literal pools.
WINDOWS = [(0x18A7C, 0x18AA4), (0x18AA8, 0x18B54),
           (0x18B64, 0x18B82), (0x18BDC, 0x18BFE),
           (0x18E84, 0x18EBC), (0x96D2A, 0x96D7C)]
ANCHORS = {
    0x60058B64: ("subs", "r1, #1"),
    0x60058B66: ("cmp", "r1, #0xfe"),
    0x60058B6E: ("bhi", "#0x60058b7e"),
    0x60058B70: ("cbz", "r0, #0x60058b7e"),
    0x60058B72: ("ldrb", "r3, [r0]"),
    0x60058B74: ("cmp", "r3, #5"),
    0x60058B76: ("bne", "#0x60058b82"),
    0x60058B78: ("adds", "r0, #1"),
    0x60058B7A: ("bl", "#0x60058aa8"),
    0x60058AA8: ("cmp", "r1, #3"),
    0x60058AB0: ("bhi", "#0x60058b06"),
    0x60058B06: ("ldrb", "r3, [r0, #3]"),
    0x60058B0A: ("ldrb", "r2, [r0, #2]"),
    0x60058B0C: ("ldrb", "r4, [r0, #1]"),
    0x60058B0E: ("ldrb", "r1, [r0]"),
    0x60058B10: ("orr.w", "r2, r2, r3, lsl #8"),
    0x60058B16: ("orr.w", "r1, r1, r4, lsl #8"),
    0x60058B1E: ("strh", "r1, [r3]"),
    0x60058B20: ("strh", "r2, [r3, #2]"),
    0x60058B30: ("movs", "r1, #6"),
    0x60058B34: ("bl", "#0x6013d2a0"),
    0x60058BEA: ("bl", "#0x600d543c"),
    0x60058BF4: ("str", "r3, [r4, #0x10]"),
    0x60058BF8: ("str", "r3, [r4, #0x14]"),
    0x60058A7E: ("ldrh", "r3, [r0]"),
    0x60058A82: ("ldrh", "r2, [r0, #2]"),
    0x60058A9A: ("bl", "#0x600d6d2a"),
    0x600D6D6E: ("bl", "#0x600658b4"),
}
LITERALS = {
    0x18B54: 0x6011B5A0,  # component
    0x18B58: 0x6011B5D9,  # invalid data length
    0x18B5C: 0x2001A430,  # two-channel state/timer object
    0x18C0C: 0x60058B65,  # corrected Thumb entry
    0x18EBC: 0x2001A430,
    0x18EC4: 0x6011B5CA,  # timer name
    0x18EC8: 0x60058A7D,  # timer consumer callback
}


def validate_semantics(decoded):
    for address, expected in ANCHORS.items():
        if decoded.get(address) != expected:
            raise ValueError(f"Changed instruction semantics at 0x{address:08x}")


def inspect(image):
    if len(image) != IMAGE_SIZE or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("Requires exact private signed Bruce update sample")
    if hashlib.sha256(image[slice(*REGION)]).hexdigest() != REGION_SHA256:
        raise ValueError("Changed message-role region")
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    decoded = {}
    for start, end in WINDOWS:
        decoded.update({i.address: (i.mnemonic, i.op_str)
                        for i in decoder.disasm(image[start:end], BASE + start)})
    validate_semantics(decoded)
    for offset, expected in LITERALS.items():
        if struct.unpack_from("<I", image, offset)[0] != expected:
            raise ValueError("Changed role pointer literal")
    for address, text in [(0x6011B5A0, b"hid_input_target.cc\0"),
                          (0x6011B5D9, b"Invalid data length: \0"),
                          (0x6011B5CA, b"HidRumbleTimer\0")]:
        start = address - BASE
        if image[start:start + len(text)] != text:
            raise ValueError("Changed role label")
    return {
        "analysis_date": "2026-10-25", "offline_only": True,
        "sample_kind": "signed Bruce update image; installed identity unverified",
        "sha256": IMAGE_SHA256, "bytes": IMAGE_SIZE,
        "region_sha256": REGION_SHA256,
        "classification": "two-channel HID control; rumble strongly inferred from timer label and consumer",
        "corrected_entry": "0x60058b64", "previous_incomplete_entry": "0x60058b68",
        "entry_length_guard": "unsigned (length - 1) <= 254, hence original length 1..255",
        "tag": 5, "payload_pointer": "input + 1", "payload_length": "original length - 1",
        "handler": "0x60058aa8", "handler_length_guard": "payload length > 3",
        "decoded_values": "two little-endian uint16 values from first four payload bytes",
        "state_writes": ["0x2001a430 uint16", "0x2001a432 uint16"],
        "event_argument": 6, "event_helper": "0x6013d2a0",
        "callback_registration": {
            "wrapper": "0x60058bdc", "helper": "0x600d543c",
            "thumb_callback_literal": "0x60058b65 at 0x60058c0c",
            "installed_field": "object 0x20009e00 + 0x14",
            "executing_host_to_callback_chain": "not established",
        },
        "consumer": {
            "timer_label": "HidRumbleTimer", "initializer": "0x60058e84",
            "thumb_callback_literal": "0x60058a7d at 0x60058ec8",
            "reads": "two uint16 values from incoming object offsets 0 and 2",
            "direct_calls": ["0x60058a9a -> 0x600d6d2a", "0x600d6d6e -> 0x600658b4"],
        },
        "component": "hid_input_target.cc",
        "limits": [
            "No USB endpoint, report descriptor or live host reachability established",
            "No malformed input or rumble command sent to device",
            "This bounded path does not establish firmware update or custom execution",
            "Does not prove absence of other receivers or vulnerabilities",
            "No signature bypass, installable patch, recovery or Switch 2 compatibility demonstrated",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    report = json.dumps(inspect(args.image.read_bytes()), indent=2) + "\n"
    if args.out:
        args.out.write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
