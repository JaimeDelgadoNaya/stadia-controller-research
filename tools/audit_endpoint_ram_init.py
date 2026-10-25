"""Phase 18: verify vendor USB endpoint-to-callback pairing from RAM initialization.

OFFLINE ONLY. Requires a SHA-256-matched local bootloader A, 131072 bytes.
Reads a private file; does not contact USB, execute firmware, flash, or touch fuses.
All conclusions concern the NORMAL startup path reconstructed statically.
Synthetic tests may override the digest/fingerprints but the CLI cannot.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

BASE = 0x60800000
IMAGE_BYTES = 131072
IMAGE_SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
COPY_SOURCE_LITERAL, COPY_START_LITERAL, COPY_END_LITERAL = 0x1694, 0x1698, 0x169C
FLASH_INITIALIZER = 0x161E0
RAM_INITIALIZER, RAM_END = 0x20000000, 0x20000190
RAM_ENDPOINT_0, RAM_ENDPOINT_1 = 0x200000D8, 0x200000DC
ENDPOINT_RAM_LITERAL, CALLBACK_TABLE_LITERAL, CALLBACK_TABLE = 0x9F90, 0x9F9C, 0x14F24
VENDOR_EP_DESCRIPTOR_0, VENDOR_EP_DESCRIPTOR_1 = 0x15296, 0x1529D
EXPECTED_ENDPOINTS = (0x87, 0x07)
EXPECTED_CALLBACKS = (0x60809E31, 0x6080A06B)

# Verified selected machine-code region SHA-256 digests for bootloader build 169429.
FINGERPRINTS = {
    (0x1600, 0x1614): "d9b748d4151d3fc1889c0046f8d7c554485e0ddbffd66262bb8728699a4a8e32",
    (0x1694, 0x16A0): "f8184c0baaa979b7bedb7cdee978b7bed99fdad267f6f00f2466f7f29dc0733d",
    (0x9EDC, 0x9F1E): "5fc5ae41a63dedc9a1a24149970ab2bb03b90a32cbf86d3dba8045380114bd16",
    (0x9F70, 0x9F82): "e0fb00c05bae86168c16e5c2fa7737549f0307a71a828e097dd7121b40b06642",
    (0x6660, 0x6692): "7f517d9ce72bcc01e762f27194d96b3d0915ad5568fdf312a52cd6da6db0210a",
    (0xA062, 0xA076): "396508bac8cf113add9f1ab58d953d550d911eac71dbcc18245c42e6f7b4792a",
}
ANCHORS = {
    0x1600: "2449",      # LDR r1, [pc] => copy source
    0x1602: "254a",      # LDR r2, [pc] => copy destination
    0x1604: "254b",      # LDR r3, [pc] => copy end
    0x1606: "9a42",      # CMP r2,r3
    0x1608: "bebf",      # ITTT LT
    0x160A: "51f8040b",  # LDRLT r0,[r1],#4
    0x160E: "42f8040b",  # STRLT r0,[r2],#4
    0x1612: "f8e7",      # BLT 0x60801606
    0x9EDC: "0026",      # MOVS r6,#0 (first callback index)
    0x9EDE: "2c4c",      # LDR r4, [pc] (RAM endpoint+4)
    0x9EEC: "34f8023c",  # LDRH r3,[r4,#-2] packet size
    0x9EFC: "14f8043c",  # LDRB r3,[r4,#-4] endpoint
    0x9F08: "14f8033c",  # LDRB r3,[r4,#-3] attributes
    0x9F12: "59f82630",  # LDR.W r3,[r9,r6,LSL#2] callback
    0x9F16: "cde90337",  # STRD r3,r7,[sp,#12] registration arguments
    0x9F1A: "fcf7a1fb",  # BL 0x60806660 registration
    0x9F70: "0434",      # ADDS r4,#4 next record
    0x9F7E: "0126",      # MOVS r6,#1 second callback index
    0x9F80: "b4e7",      # B 0x60809EEC
    0x6668: "8c78",      # LDRB r4,[r1,#2] endpoint address
    0x666A: "04f00f05",  # AND r5,r4,#15
    0x6672: "e309",      # LSRS r3,r4,#7 direction
    0x6678: "43ea4503",  # ORR r3,r3,r5,LSL#1
    0x6682: "1a61",      # STR r2,[r3,#16] context
    0x6686: "dc60",      # STR r4,[r3,#12] callback
    0xA062: "8369",     # LDR r3,[r0,#24] final function
    0xA066: "c069",     # LDR r0,[r0,#28] context
    0xA068: "1847",     # BX r3
    0xA06A: "1046",     # MOV r0,r2 (OUT trampoline)
}


def word(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def fmt(address):
    return f"0x{address:08x}"


def parse_compact(data):
    if len(data) != 4:
        raise ValueError("Expected 4-byte compact endpoint record")
    address, attributes, packet = struct.unpack("<BBH", data)
    if attributes != 2 or packet != 512 or address not in EXPECTED_ENDPOINTS:
        raise ValueError("Unexpected compact endpoint contents")
    return {"endpoint": f"0x{address:02x}", "attributes": f"0x{attributes:02x}",
            "max_packet_bytes": packet}


def endpoint_register_index(address):
    if not isinstance(address, int) or isinstance(address, bool) or not 0 <= address <= 255:
        raise ValueError("Expected unsigned USB endpoint address byte")
    n = address & 15
    if n > 7:
        raise ValueError("Bootloader rejects endpoint numbers >7")
    return 2*n + ((address >> 7) & 1)


def audit(image, expected_sha256=IMAGE_SHA256, fingerprints=FINGERPRINTS):
    """SHA-locked normal-startup static derivation; digest override for tests only."""
    if len(image) != IMAGE_BYTES:
        raise ValueError("Expected 131072-byte bootloader A")
    digest = hashlib.sha256(image).hexdigest()
    if digest != expected_sha256:
        raise ValueError("Unexpected bootloader SHA-256")
    for (start, end), expected in fingerprints.items():
        if (not 0 <= start < end <= IMAGE_BYTES or
                hashlib.sha256(image[start:end]).hexdigest() != expected):
            raise ValueError(f"Machine-code fingerprint mismatch at {fmt(BASE+start)}")
    for offset, encoded in ANCHORS.items():
        raw = bytes.fromhex(encoded)
        if image[offset:offset+len(raw)] != raw:
            raise ValueError(f"Machine-code anchor changed at {fmt(BASE+offset)}")

    if tuple(word(image, x) for x in (COPY_SOURCE_LITERAL, COPY_START_LITERAL,
                                      COPY_END_LITERAL)) != (
                                      BASE+FLASH_INITIALIZER, RAM_INITIALIZER, RAM_END):
        raise ValueError("Unexpected startup flash-to-RAM copy literals")
    if (RAM_END-RAM_INITIALIZER) % 4:
        raise ValueError("Startup copy is not word aligned")
    if word(image, ENDPOINT_RAM_LITERAL) != RAM_ENDPOINT_0+4:
        raise ValueError("Unexpected RAM compact descriptor pointer")
    if word(image, CALLBACK_TABLE_LITERAL) != BASE+CALLBACK_TABLE:
        raise ValueError("Unexpected callback table pointer")
    callbacks = struct.unpack_from("<II", image, CALLBACK_TABLE)
    if callbacks != EXPECTED_CALLBACKS:
        raise ValueError("Unexpected callback pointers")

    # Startup copy: LMA flash 0x608161e0 -> VMA RAM 0x20000000..0x20000190.
    initialized_ram = image[FLASH_INITIALIZER:FLASH_INITIALIZER+RAM_END-RAM_INITIALIZER]
    records = []
    for i, (expected_ep, cb, config_offset) in enumerate(zip(
            EXPECTED_ENDPOINTS, callbacks,
            (VENDOR_EP_DESCRIPTOR_0, VENDOR_EP_DESCRIPTOR_1))):
        addr = RAM_ENDPOINT_0+i*4
        off = addr-RAM_INITIALIZER
        rec = parse_compact(initialized_ram[off:off+4])
        actual_ep = int(rec["endpoint"], 16)
        if actual_ep != expected_ep:
            raise ValueError("Unexpected endpoint ordering in RAM initializer")
        if image[config_offset:config_offset+7] != bytes((7, 5, actual_ep, 2, 0, 2, 0)):
            raise ValueError("Compact initializer disagrees with USB configuration descriptor")
        records.append({
            "iteration": i, "flash_source": fmt(BASE+FLASH_INITIALIZER+off),
            "initialized_ram": fmt(addr), **rec,
            "usb_config_endpoint_descriptor": fmt(BASE+config_offset),
            "registered_callback_thumb": fmt(cb),
            "registered_callback_function": fmt(cb & ~1),
            "usb_internal_endpoint_slot": endpoint_register_index(actual_ep),
        })

    return {
        "phase": 18, "bootloader_build": 169429,
        "sha256_verified": True, "image_sha256": digest,
        "firmware_bytes": len(image),
        "device_access": False, "usb_transactions": False,
        "flash_or_fuse_operations": False,
        "startup_initializer": {
            "normal_startup_copy_routine": "0x60801600",
            "source_flash": fmt(BASE+FLASH_INITIALIZER),
            "destination_ram_start": fmt(RAM_INITIALIZER),
            "destination_ram_end_exclusive": fmt(RAM_END),
            "bytes_copied": len(initialized_ram),
            "execution_on_live_device": "NOT MEASURED; conditional startup path",
        },
        "vendor_endpoint_registration": {
            "routine": "0x60809eb8",
            "endpoint_descriptor_pointer_literal": fmt(BASE+ENDPOINT_RAM_LITERAL),
            "callback_pointer_table": fmt(BASE+CALLBACK_TABLE),
            "endpoint_setup_helper": "0x60806660",
            "direction_to_callback_resolved": True,
            "records": records,
        },
        "bulk_out_0x07_completion_callback": "0x6080a06a",
        "bulk_out_0x07_next_indirect": {
            "intermediate": "0x6080a062",
            "handler_loaded_from": "[r0 + 0x18]",
            "context_loaded_from": "[r0 + 0x1c]",
            "indirect_branch": "0x6080a068",
            "final_callback_target": "NOT RESOLVED",
        },
        "host_packet_parser": "NOT IDENTIFIED",
        "host_to_flash_writer": "NOT DEMONSTRATED",
        "hab_bypass": "NOT DEMONSTRATED",
        "custom_firmware_execution": "NOT DEMONSTRATED",
        "scope": "Normal startup RAM copy/endpoint registration only; final dynamic handler unresolved",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Locally owned SHA-matched bootloader-a.bin")
    parser.add_argument("--out", type=Path, help="Private local JSON report")
    args = parser.parse_args()
    result = json.dumps(audit(args.image.read_bytes()), indent=2) + "\n"
    if args.out:
        args.out.write_text(result, encoding="utf-8")
    else:
        print(result, end="")


if __name__ == "__main__":
    main()
