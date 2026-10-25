"""Phase 20 — bounded offline census of possible USB callback field writers.

This is a byte-pattern discovery aid, NOT a complete ARM control/data-flow
analysis. Results describe candidate Thumb encodings in selected flash ranges,
not proven reachable instructions or proof that runtime callback mutation is
impossible. No USB, hardware, flash or eFuse access is performed.

The CLI accepts ONLY a local bootloader A with the known SHA-256. Synthetic
test functions may override the digest but never contact a controller.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

BASE = 0x60800000
SIZE = 0x20000
SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
RAM_GLOBAL = 0x20008B78
CALLBACK_FIELDS = {
    "bulk_in_handler": (RAM_GLOBAL + 0x5F8, 0x5F8),
    "bulk_in_context": (RAM_GLOBAL + 0x5FC, 0x5FC),
    "bulk_out_handler": (RAM_GLOBAL + 0x600, 0x600),
    "bulk_out_context": (RAM_GLOBAL + 0x604, 0x604),
}
# Selected instruction-bearing interval; a linear scan can also interpret
# Thumb data/literal pools as opcodes. No assumed whole-image CFG.
START, END = 0x1000, 0x14F00
VENDOR_START, VENDOR_END = 0x9E24, 0xA076
CONSTRUCTOR_STORES = {
    "bulk_in_handler": 0xBB50,
    "bulk_in_context": 0xBB6C,
    "bulk_out_handler": 0xBB5A,
    "bulk_out_context": 0xBB70,
}
INITIALIZERS = {
    0xBB50: "c4f8f835",  # STR.W R3,[R4,#0x5F8]
    0xBB6C: "c4f8fc55",  # STR.W R5,[R4,#0x5FC]
    0xBB5A: "c4f80036",  # STR.W R3,[R4,#0x600]
    0xBB70: "c4f80456",  # STR.W R5,[R4,#0x604]
    0xA062: "8369",      # LDR R3,[R0,#0x18] callback under inspection
    0xA066: "c069",      # LDR R0,[R0,#0x1C] callback context
    0xAFFA: "7047",      # IN no-op
    0xAFFC: "7047",      # OUT no-op
}


def fmt(value):
    return f"0x{value:08x}"


def scan_thumb2_positive_str(image, immediate, start=START, end=END):
    """Identify raw halfword-aligned STR.W Rt,[Rn,#imm12] candidates.

    Encoding: first halfword F8C0 | Rn, second (Rt << 12) | imm12.
    Explicitly excludes register-offset, STRD, store-multiple, negative
    offsets, 16-bit stores, and any aliasing through an object pointer.
    """
    if not isinstance(immediate, int) or not 0 <= immediate <= 0xFFF:
        raise ValueError("STR.W immediate must be an unsigned 12-bit value")
    if not 0 <= start < end <= len(image) or (start | end) & 1:
        raise ValueError("Scan range must be aligned and inside image")
    result = []
    for offset in range(start, end - 3, 2):
        first, second = struct.unpack_from("<HH", image, offset)
        if first & 0xFFF0 == 0xF8C0 and second & 0xFFF == immediate:
            result.append({
                "address": fmt(BASE + offset),
                "base_register": f"r{first & 0xF}",
                "source_register": f"r{second >> 12}",
                "encoding": image[offset:offset+4].hex(),
                "status": "raw encoding candidate; requires CFG and pointer provenance",
            })
    return result


def scan_thumb16_str_word(image, immediate, start=VENDOR_START, end=VENDOR_END):
    """Raw Thumb 16-bit STR word (imm5*4), with no inferred base pointer."""
    if not isinstance(immediate, int) or not 0 <= immediate <= 124 or immediate % 4:
        raise ValueError("Thumb16 STR offset must be a multiple of four <=124")
    if not 0 <= start < end <= len(image) or (start | end) & 1:
        raise ValueError("Scan range must be aligned and inside image")
    rows = []
    for offset in range(start, end - 1, 2):
        hw = struct.unpack_from("<H", image, offset)[0]
        if hw & 0xF800 == 0x6000 and ((hw >> 6) & 0x1F)*4 == immediate:
            rows.append({
                "address": fmt(BASE + offset),
                "base_register": f"r{(hw >> 3) & 7}",
                "source_register": f"r{hw & 7}",
                "encoding": image[offset:offset+2].hex(),
                "status": "raw Thumb16 encoding candidate; NOT pointer-verified",
            })
    return rows


def aligned_literal_references(image, address):
    """Count only aligned 32-bit little-endian absolute occurrences."""
    pattern = struct.pack("<I", address)
    return [fmt(BASE + offset) for offset in range(0, len(image)-3, 4)
            if image[offset:offset+4] == pattern]


def audit(image, expected_sha256=SHA256):
    if len(image) != SIZE:
        raise ValueError("Expected 131072 bytes of bootloader A")
    digest = hashlib.sha256(image).hexdigest()
    if digest != expected_sha256:
        raise ValueError("Unexpected SHA-256; refusing build-specific audit")
    for offset, encoding in INITIALIZERS.items():
        expected = bytes.fromhex(encoding)
        if image[offset:offset+len(expected)] != expected:
            raise ValueError(f"Changed machine-code anchor at {fmt(BASE+offset)}")
    fields = {}
    for name, (address, relative_offset) in CALLBACK_FIELDS.items():
        candidates = scan_thumb2_positive_str(image, relative_offset)
        expected_site = fmt(BASE + CONSTRUCTOR_STORES[name])
        if not any(v["address"] == expected_site and v["base_register"] == "r4"
                   for v in candidates):
            raise ValueError(f"Constructor STR.W missing from {name} candidate list")
        fields[name] = {
            "ram_address": fmt(address),
            "offset_from_aggregate": hex(relative_offset),
            "initializer": expected_site,
            "positive_immediate_strw_candidates": candidates,
            "other_than_initializer": [v for v in candidates if v["address"] != expected_site],
            "aligned_absolute_pointer_literals": aligned_literal_references(image, address),
        }
    vendor_object_offsets = {}
    for off in (0x10, 0x14, 0x18, 0x1C):
        vendor_object_offsets[f"0x{off:02x}"] = {
            "thumb16_word_store_candidates": scan_thumb16_str_word(image, off),
            "thumb2_positive_strw_candidates": scan_thumb2_positive_str(
                image, off, VENDOR_START, VENDOR_END),
        }
    return {
        "phase": 20, "build": 169429,
        "sha256_verified": True, "sha256": digest, "image_bytes": len(image),
        "device_access": False, "usb_transactions": False,
        "flash_or_fuse_operations": False,
        "bounds": {
            "thumb2_raw_candidate_scan": [fmt(BASE+START),fmt(BASE+END)],
            "vendor_callback_raw_scan": [fmt(BASE+VENDOR_START),fmt(BASE+VENDOR_END)],
            "alignment": "halfword",
            "not_a_control_flow_graph": True,
        },
        "fields": fields, "vendor_object_local_store_candidates": vendor_object_offsets,
        "initial_bulk_out_callback": "0x6080affc (BX LR) at normal construction",
        "later_replacement": "NOT PROVEN AND NOT EXCLUDED",
        "other_store_forms_or_pointer_aliases": "NOT ANALYZED EXHAUSTIVELY",
        "host_bulk_out_to_message_parser": "NOT ESTABLISHED",
        "host_to_flash_write": "NOT DEMONSTRATED",
        "hab_closed_bypass": "NOT DEMONSTRATED",
        "custom_firmware_execution": "NOT DEMONSTRATED",
        "scope": "Constrained encoding census, not proof of lack of dynamic setter",
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("bootloader", type=Path, help="Private local matching bootloader A")
    p.add_argument("--out", type=Path, help="Write sanitized JSON privately")
    args = p.parse_args()
    output = json.dumps(audit(args.bootloader.read_bytes()), indent=2) + "\n"
    if args.out:
        args.out.write_text(output, encoding="utf-8")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
