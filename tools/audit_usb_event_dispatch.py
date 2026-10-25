"""SHA-locked offline audit of Stadia bootloader USB class events.

Works only with a locally supplied 128-KiB image of the verified build.
No device access, USB transfers, firmware execution or flash writes.
The eleven dispatch cases are INTERNAL events, not host command opcodes.
"""
import argparse
import hashlib
import json
from pathlib import Path

BASE = 0x60800000
IMAGE_BYTES = 0x20000
IMAGE_SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
DISPATCH = 0x9C58
TABLE = 0x9C68
DEFAULT = 0x9D74
TRANSFER_GUARD = 0x9B28
CLASS_EVENT_TABLE = 0x16284
VENDOR_EVENT_TABLE = 0x16290
VENDOR_HANDLER = 0x9E64

# Selected portions from the privately rehashed bootloader. Small hashes
# protect each selected finding against accidental firmware-version drift.
SPANS = {
    (0x9B28, 0x9B42): "a1f742ae2271780fe804997239e208e3088ecf1952ee7078c938b5af9fe7741b",
    (0x9B4A, 0x9B7E): "6e88fc80c676384ad6a857ff51613590a643dd7537c88b7d31b83b0549149fcd",
    (0x9C58, 0x9C68): "e3a6152ce86f02b40103c968f7c971732017a27f6378fe00bc75ab93dc51a835",
    (0x9C68, 0x9C73): "3f14c32c34150e75019c0c77ede8118a4fe61835e84d5e63cb7490522e818478",
    (0x9C94, 0x9CC8): "40e698f63e1b6637c8951d001fbc2e4cd73ab97ae10a795cc4ae82fa26370451",
    (0x9CFA, 0x9D68): "940d1c829d7f0f6ca86d105bc8395128ddb175dcaff3271cff51464b1f130c5b",
    (0x9E64, 0x9E8A): "9b4bba994901ec08b9e4f72483b88370f0ad394466de23260734d75be37247ed",
}

# Explicit Thumb instruction anchors, distinct from fingerprints.
GUARD_BYTES = bytes.fromhex("b2f5007f")       # cmp.w r2,#0x200
DISPATCH_BYTES = bytes.fromhex("013970b504460a29")  # subtract 1, cmp #10
TBB_BYTES = bytes.fromhex("dfe801f0")         # tbb [pc,r1]
DEFAULT_BYTES = bytes.fromhex("0120")         # movs r0,#1
VENDOR_BYTES = bytes.fromhex("7f2910b50dd9") # cmp r1,#127; push; bls
DEFAULT_VENDOR_POINTER = 0x60809E3D
VALID_EVENT_CASES = {
    0x9C74, 0x9CCC, 0x9CF2, 0x9D74, 0x9CFA,
    0x9D22, 0x9D48, 0x9D54, 0x9D68
}


def address(offset):
    return f"0x{BASE + offset:08x}"


def audit(data: bytes, expected_sha256=IMAGE_SHA256):
    """Only synthetic tests should override the expected SHA-256."""
    if len(data) != IMAGE_BYTES:
        raise ValueError("Expected exact 131072-byte bootloader A")
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise ValueError("SHA-256 mismatch: refusing version-specific interpretation")
    for (start, end), expected in SPANS.items():
        if hashlib.sha256(data[start:end]).hexdigest() != expected:
            raise ValueError(f"Instruction evidence mismatch at {address(start)}")
    for offset, expected, label in (
        (TRANSFER_GUARD, GUARD_BYTES, "Transfer limit"),
        (DISPATCH, DISPATCH_BYTES, "Event dispatcher"),
        (DISPATCH + 12, TBB_BYTES, "TBB instruction"),
        (DEFAULT, DEFAULT_BYTES, "Default event result"),
        (VENDOR_HANDLER, VENDOR_BYTES, "Vendor callback threshold"),
    ):
        if data[offset:offset+len(expected)] != expected:
            raise ValueError(f"{label} anchor mismatch")
    read_pointer = lambda off: int.from_bytes(data[off:off+4], "little")
    if (read_pointer(CLASS_EVENT_TABLE), read_pointer(VENDOR_EVENT_TABLE)) != (
        BASE + DISPATCH + 1, BASE + VENDOR_HANDLER + 1
    ):
        raise ValueError("USB class-event callback pointers mismatch")
    if read_pointer(0xBBB0) != DEFAULT_VENDOR_POINTER:
        raise ValueError("Expected initial default vendor callback changed")
    event_jumps = [TABLE + 2 * delta for delta in data[TABLE:TABLE+11]]
    if any(dst not in VALID_EVENT_CASES or dst & 1 for dst in event_jumps):
        raise ValueError("Unexpected event-table destination")
    cases = [
        {"event_id": i, "entry": address(dst),
         "uses_default_error_branch": dst == DEFAULT}
        for i, dst in enumerate(event_jumps, start=1)
    ]
    return {
        "phase": 15,
        "image_sha256_verified": True,
        "image_sha256": digest,
        "firmware_bytes": len(data),
        "hardware_access": False,
        "usb_commands_sent": False,
        "flash_write_or_fuse_operations": False,
        "event_dispatch": {
            "class_callback_table": address(CLASS_EVENT_TABLE),
            "handler": address(DISPATCH),
            "jump_table": address(TABLE),
            "accepted_internal_events": "1..11",
            "otherwise": "default return 1",
            "cases": cases,
            "direct_call_to_flash_writer_found": False,
            "not_host_command_opcodes": True,
        },
        "transfer_guard": {
            "instruction": address(TRANSFER_GUARD),
            "maximum_bytes_at_this_helper": 512,
            "out_of_range": "return code 3",
            "firmware_externally_controlled_size": "NOT ESTABLISHED",
        },
        "vendor_callback": {
            "table": address(VENDOR_EVENT_TABLE),
            "handler": address(VENDOR_HANDLER),
            "threshold": "event > 127",
            "initial_handler_thumb": "0x60809e3d",
            "handler_pointer_ram": "0x20009168",
            "later_registration": "NOT RECONSTRUCTED",
        },
        "instruction_spans_checked": len(SPANS),
        "usb_host_command_parser": "NOT IDENTIFIED",
        "external_input_to_flash_writer": "NOT DEMONSTRATED",
        "hab_bypass": "NOT DEMONSTRATED",
        "custom_firmware_execution": "NOT DEMONSTRATED",
        "scope": "Selected event/transfer routines; no complete USB input taint analysis",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Private local bootloader image")
    parser.add_argument("--out", type=Path, help="Optional local sanitized JSON report")
    args = parser.parse_args()
    report = json.dumps(audit(args.image.read_bytes()), indent=2) + "\n"
    if args.out:
        args.out.write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
