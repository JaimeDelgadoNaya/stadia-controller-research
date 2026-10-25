"""Phase 17: offline verification of Stadia bootloader vendor endpoint registration.

A local 131072-byte bootloader A is required. The CLI enforces the measured
SHA-256 and selected instruction-region fingerprints. No controller I/O,
flashing, triggering of callbacks, firmware execution or fuse manipulation.

IMPORTANT: endpoint 0x07/0x87 descriptors exist, but the initial endpoint
configuration is copied/read from RAM. The callback-to-direction association
is therefore NOT proven by the two-entry callback table alone.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

BASE = 0x60800000
SIZE = 131072
SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"

# Selected fixed machine-code regions from build 169429. The SHA-256 of
# each region is independently checked after the whole-image hash.
FINGERPRINTS = {
    (0x9EB8, 0x9F82): "8dc3a38ecb51da54476b3f26cab243d38507ab483e927c1f174c0b06a996da88",
    (0x9FA4, 0xA030): "fbbf8d58bcdbaefbfd35c43f2b2bc0274b7b31bc693406983b03fe9a7152cb65",
    (0xA044, 0xA062): "180cae6d0a770056f528988cbf0ff4dae597370fa57bcf59bc5f056dfbdd1d1f",
    (0xA062, 0xA076): "396508bac8cf113add9f1ab58d953d550d911eac71dbcc18245c42e6f7b4792a",
    (0x9E30, 0x9E3C): "d6ae856663eaf48fc45ab8a301de43515f636f3d6c8be73d07f81cf6f92cf409",
    (0x6660, 0x669E): "87413bb85d5c84feeac058e7fc941cd03cbce8cb8fa9ed442edbb4578ba249e9",
    (0x669E, 0x66DC): "aea7b46f92a2e393fb034e8a819cb471d667ceb1acad4ee341451e811846160b",
}
# Machine-code anchors for a few individual control/data transfers.
ANCHORS = {
    0x9F12: "59f82630",    # LDR.W r3,[r9,r6,LSL #2]
    0x9F16: "cde90337",    # STRD r3,r7,[sp,#12]
    0x9F1A: "fcf7a1fb",    # BL 0x60806660
    0x9F70: "0434",        # ADDS r4,#4 (next descriptor)
    0x9F7E: "0126b4e7",    # MOVS r6,#1; branch back to second registration
    0x9FC0: "fcf76dfb",    # BL 0x6080669e (endpoint deinitialization)
    0xA052: "fff731ff",    # BL 0x60809eb8 (configuration)
    0xA05C: "fff7a2ff",    # BL 0x60809fa4 (teardown)
    0x6668: "8c78",        # LDRB r4,[r1,#2] USB endpoint address
    0x666A: "04f00f05",    # AND r5,r4,#0xf
    0x666E: "072d",        # CMP r5,#7 endpoint number guard
    0x6672: "e309",        # LSRS r3,r4,#7
    0x6678: "43ea4503",    # ORR.W r3,r3,r5,LSL #1
    0x667C: "0c25",        # MOVS r5,#12
    0x667E: "05fb0303",    # MLA r3,r5,r3,r0
    0x6682: "1a61",        # STR r2,[r3,#0x10] callback context
    0x6686: "dc60",        # STR r4,[r3,#0xc] callback pointer
    0x9E36: "9847",        # BLX r3 in first callback trampoline
    0xA068: "1847",       # BX r3 in second callback trampoline
}
TABLE = 0x14F24
TABLE_LITERAL = 0x9F9C
RAM_DESCRIPTOR_LITERAL = 0x9F90
VENDOR_BULK_IN = 0x87
VENDOR_BULK_OUT = 0x07
ENDPOINT_INIT = 0x60806660
ENDPOINT_DEINIT = 0x6080669E
CALLBACKS = (0x60809E31, 0x6080A06B)


def word(data, pos):
    return struct.unpack_from("<I", data, pos)[0]


def hexaddr(n):
    return f"0x{n:08x}"


def endpoint_index(address):
    """Bootloader's direction/number mapping, valid for endpoint number 0..7.

    Reconstructed from 0x60806668-0x60806686. This is a pure offline model,
    not a call into firmware or a test of device behavior.
    """
    if not isinstance(address, int) or isinstance(address, bool) or not 0 <= address <= 255:
        raise ValueError("USB endpoint address must be one unsigned byte")
    number = address & 0x0F
    if number > 7:
        raise ValueError("Bootloader rejects endpoints numbered above 7")
    return 2 * number + ((address >> 7) & 1)


def endpoint_slots(address):
    index = endpoint_index(address)
    # 0x6080667C..86: entry = device + 12*index; pointers at +12/+16.
    return {"endpoint": f"0x{address:02x}", "index": index,
            "handler_offset_from_device": hex(12*index + 12),
            "context_offset_from_device": hex(12*index + 16)}


def audit(data, expected_sha256=SHA256, fingerprints=FINGERPRINTS):
    """Allow alternate fingerprints/digest ONLY for independent synthetic tests."""
    if len(data) != SIZE:
        raise ValueError("Expected 131072 bytes of bootloader A")
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise ValueError("Wrong SHA-256: image is not the recorded bootloader build")
    for (start, end), expected in fingerprints.items():
        if not 0 <= start < end <= SIZE or hashlib.sha256(data[start:end]).hexdigest() != expected:
            raise ValueError(f"Machine code region mismatch at {hexaddr(BASE+start)}")
    for start, string in ANCHORS.items():
        encoded = bytes.fromhex(string)
        if data[start:start+len(encoded)] != encoded:
            raise ValueError(f"Instruction anchor mismatch at {hexaddr(BASE+start)}")

    if word(data, TABLE_LITERAL) != BASE + TABLE:
        raise ValueError("Unexpected endpoint callback table literal")
    if word(data, RAM_DESCRIPTOR_LITERAL) != 0x200000DC:
        raise ValueError("Unexpected RAM endpoint descriptor source")
    table = [word(data, TABLE+4*i) for i in range(2)]
    if tuple(table) != CALLBACKS:
        raise ValueError("Unexpected endpoint callback pair")
    descriptor = data[0x1527C:0x1527C+80]
    if descriptor[:9] != bytes.fromhex("0902500002010080fa"):
        raise ValueError("Unexpected USB configuration descriptor")
    vendor_endpoints = [data[0x15296:0x1529D], data[0x1529D:0x152A4]]
    if vendor_endpoints != [
        bytes.fromhex("07058702000200"), bytes.fromhex("07050702000200")
    ]:
        raise ValueError("Unexpected vendor bulk endpoint descriptors")

    slots = [endpoint_slots(x) for x in (VENDOR_BULK_IN, VENDOR_BULK_OUT)]
    return {
        "phase": 17, "bootloader_build": 169429,
        "sha256_verified": True, "sha256": digest, "firmware_bytes": len(data),
        "hardware_access": False, "usb_transactions": False,
        "flash_or_efuse_writes": False,
        "configuration": {
            "device": "18D1:946B", "vendor_interface": 0,
            "bulk_in": "0x87", "bulk_out": "0x07",
            "max_packet_size": 512,
            "source": "USB descriptors at 0x6081527c, 0x60815296 and 0x6081529d",
        },
        "endpoint_registration": {
            "function": hexaddr(BASE+0x9EB8),
            "callback_table": hexaddr(BASE+TABLE),
            "callback_table_literal": hexaddr(BASE+TABLE_LITERAL),
            "callbacks_thumb": [hexaddr(v) for v in CALLBACKS],
            "callback_selection": hexaddr(BASE+0x9F12),
            "entry_arguments_stored": hexaddr(BASE+0x9F16),
            "endpoint_init_called_at": hexaddr(BASE+0x9F1A),
            "endpoint_init_target": hexaddr(ENDPOINT_INIT),
            "loop_second_iteration": hexaddr(BASE+0x9F7E),
            "endpoint_config_source": "RAM descriptor structure around 0x200000d8",
            "endpoint_direction_to_callback_assignment":
                "UNRESOLVED: cannot assign IN/OUT callback from the table alone",
        },
        "endpoint_registration_helper": {
            "function": hexaddr(ENDPOINT_INIT),
            "endpoint_address_source": "byte [r1 + 2]",
            "reject_endpoint_number_above": 7,
            "index_formula": "2*(bEndpointAddress & 0x0f) + ((bEndpointAddress >> 7) & 1)",
            "entry_stride_bytes": 12,
            "endpoint_slots": slots,
            "writes": "callback at device+12*index+12, context at device+12*index+16",
            "trampolines": {
                "first": "0x60809e30: loads function/context from completion record, BLX",
                "second": "0x6080a06a -> 0x6080a062: indirect forwarding via record fields",
            },
        },
        "class_configuration_handler": {
            "function": "0x6080a044",
            "event_9": "calls 0x60809eb8 (endpoint setup)",
            "event_1": "calls 0x60809fa4 (endpoint teardown)",
        },
        "host_bulk_out_to_command_parser": "NOT TRACED",
        "host_bulk_out_to_flash_writer": "NOT DEMONSTRATED",
        "signature_bypass": "NOT DEMONSTRATED",
        "custom_firmware_execution": "NOT DEMONSTRATED",
        "scope": "Verified endpoint setup, callback array and slot arithmetic only; dynamic RAM endpoint assignment unverified",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bootloader", type=Path, help="Private local SHA-matched file")
    parser.add_argument("--out", type=Path, help="Optional private local JSON output")
    args = parser.parse_args()
    report = json.dumps(audit(args.bootloader.read_bytes()), indent=2) + "\n"
    if args.out:
        args.out.write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
