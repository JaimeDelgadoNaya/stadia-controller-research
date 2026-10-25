"""Phase 16: independently anchor two distinct USB callback paths in bootloader A.

Offline only: this program reads a local 128-KiB file, never connects to USB,
programs flash or eFuses, nor runs controller code. It does not infer that a
compiled routine is actively exposed on a production USB interface.

The private original image must not be committed. SHA override is TEST-ONLY.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

BASE = 0x60800000
SIZE = 131072
EXPECTED_SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
RAM_OBJECT_BASE = 0x20008B78
CDC_OFFSET = 0x578
CDC_VTABLE_LITERAL = 0xBBA8
CDC_VTABLE_OFFSET = 0x14E18
CDC_EVENT_TABLE = 0x16284
VENDOR_EVENT_TABLE = 0x16290
VENDOR_CALLBACK_DEFAULT = 0x60809E3D

# Unique anchored instructions in the examined paths. Keeping semantics
# explicit prevents treating the results as a general whole-program audit.
ANCHORS = {
    0xBB06: "c4f88455",      # STR.W r5, [r4,#0x584] (r5 was set to zero)
    0xBB14: "244b",          # LDR r3,[pc,#0x90] => literal at +0xBBA8
    0xBB1C: "c4f87835",      # STR.W r3,[r4,#0x578] (CDC method-table pointer)
    0x9B28: "b2f5007f",      # CMP.W r2,#0x200 (512-byte guard in CDC method)
    0x9C44: "10b5c368",      # PUSH {r4,lr}; LDR r3,[r0,#0xC] (callback)
    0x9C4A: "13b1114620469847", # CBZ r3; MOV r1,r2; MOV r0,r4; BLX r3
    0x9CE0: "00f5af60",      # ADD.W r0,r0,#0x578
    0x9CE4: "fff7aeff",      # BL 0x60809C44 (event-mediated callback)
    0xBB40: "1b4b",          # LDR r3,[pc] from 0xBBB0
    0xBB46: "c4f8f035",      # STR.W r3,[r4,#0x5F0] vendor default handler
    0xBB68: "c4f8f455",      # STR.W r5,[r4,#0x5F4] vendor context default
    0x9E6E: "d0f8f035",      # LDR.W r3,[r0,#0x5F0]
    0x9E76: "d0f8f405",      # LDR.W r0,[r0,#0x5F4]
    0x9E7A: "9847",          # BLX r3
}


def word(blob, offset):
    return struct.unpack_from("<I", blob, offset)[0]


def hexaddr(n):
    return f"0x{n:08x}"


def find_ascii(data, phrase):
    """Require the diagnostic string, but do not claim it uniquely labels code."""
    offset = data.find(phrase)
    if offset < 0:
        raise ValueError(f"Expected diagnostic string missing: {phrase!r}")
    return hexaddr(BASE + offset)


def audit(image, expected_sha256=EXPECTED_SHA256):
    """Audit strictly the recorded build; override digest in synthetic tests."""
    if len(image) != SIZE:
        raise ValueError("Expected exactly 131072 bytes of bootloader A")
    digest = hashlib.sha256(image).hexdigest()
    if digest != expected_sha256:
        raise ValueError("SHA-256 mismatch: rejecting unknown firmware build")

    for offset, encoding in ANCHORS.items():
        raw = bytes.fromhex(encoding)
        if image[offset:offset+len(raw)] != raw:
            raise ValueError(f"Instruction anchor changed at {hexaddr(BASE+offset)}")

    expected_pointers = {
        CDC_VTABLE_LITERAL: BASE + CDC_VTABLE_OFFSET,
        CDC_VTABLE_OFFSET: BASE + 0x9B29,  # Thumb-method entry
        CDC_EVENT_TABLE: BASE + 0x9C59,   # Internal class event switch
        VENDOR_EVENT_TABLE: BASE + 0x9E65,
        0xBBB0: VENDOR_CALLBACK_DEFAULT,
        0x9E8C: RAM_OBJECT_BASE,
        0x9E90: VENDOR_CALLBACK_DEFAULT,
    }
    for off, expected in expected_pointers.items():
        if word(image, off) != expected:
            raise ValueError(f"Pointer-table change at {hexaddr(BASE+off)}")

    strings = {
        "cdc_source_name": find_ascii(image, b"usb_device_cdc.cc"),
        "vendor_source_name": find_ascii(image, b"usb_device_vendor.cc"),
        "vendor_endpoint_diagnostic": find_ascii(image, b"Vendor usb device unloaded."),
    }

    # Does not identify all possible direct/indirect stores or all registration
    # paths. It counts only this EXACT form of a direct-offset STR encoding.
    direct_store_encoding = bytes.fromhex(ANCHORS[0xBB46])
    matches = [hexaddr(BASE+pos) for pos in range(len(image)-3)
               if image[pos:pos+4] == direct_store_encoding]

    return {
        "phase": 16, "image_sha256_verified": True, "image_sha256": digest,
        "image_bytes": len(image), "hardware_access": False,
        "usb_transfers_sent": False, "flash_or_efuse_writes": False,
        "source_name_strings": strings,
        "cdc_object_path": {
            "constructed_object_base": hexaddr(RAM_OBJECT_BASE+CDC_OFFSET),
            "method_table": hexaddr(BASE+CDC_VTABLE_OFFSET),
            "method_table_literal": hexaddr(BASE+CDC_VTABLE_LITERAL),
            "first_method_thumb": hexaddr(BASE+0x9B29),
            "512_byte_guard_at": hexaddr(BASE+0x9B28),
            "object_callback_slot": hexaddr(RAM_OBJECT_BASE+CDC_OFFSET+0xC),
            "initial_callback_slot_write": hexaddr(BASE+0xBB06),
            "internal_event_switch": hexaddr(BASE+0x9C58),
            "event_case_entry": hexaddr(BASE+0x9CCC),
            "event_callsite": hexaddr(BASE+0x9CE4),
            "conditional_callback_wrapper": hexaddr(BASE+0x9C44),
            "called_on_real_external_packet": "NOT ESTABLISHED",
            "active_USB_interface": "NOT ESTABLISHED",
        },
        "vendor_object_path": {
            "class_event_table": hexaddr(BASE+VENDOR_EVENT_TABLE),
            "event_handler": hexaddr(BASE+0x9E64),
            "callback_pointer_ram": hexaddr(RAM_OBJECT_BASE+0x5F0),
            "callback_context_ram": hexaddr(RAM_OBJECT_BASE+0x5F4),
            "default_handler_thumb": hexaddr(VENDOR_CALLBACK_DEFAULT),
            "initial_pointer_store_at": hexaddr(BASE+0xBB46),
            "observed_exact_direct_store_opcode_occurrences": matches,
            "scope_of_store_search": "Exact 4-byte STR encoding only, NOT a proof of no later dynamic writes",
            "subsequent_handler_registration": "NOT PROVEN",
        },
        "distinguishing_finding": (
            "The 512-byte guard is in a CDC-labelled object's method table, "
            "not a proved vendor bulk OUT receive handler."
        ),
        "vendor_bulk_out_0x07_to_parser": "NOT RECONSTRUCTED",
        "vendor_bulk_out_to_flash_writer": "NOT DEMONSTRATED",
        "hab_closed_bypass": "NOT DEMONSTRATED",
        "alternative_firmware_executed": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--out", type=Path, help="Optional private local JSON output")
    args = parser.parse_args()
    report = json.dumps(audit(args.image.read_bytes()), indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
