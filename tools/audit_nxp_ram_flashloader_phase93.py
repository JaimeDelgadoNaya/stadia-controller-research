"""Offline structural audit of a local NXP-style RAM flashloader candidate.

This only parses file bytes. It does not invoke SDP, execute code, or access hardware.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_community_bootloader_patch_phase93 import (
    parse_device_descriptor, parse_configuration
)

MAX_IMAGE = 2 * 1024 * 1024
IVT_OFFSET = 0x400
LOAD_BASE = 0x20000000
DEVICE_OFFSET = 0x17EC1
CONFIG_OFFSET = 0x17E98


def audit(data):
    if not isinstance(data, bytes) or len(data) > MAX_IMAGE:
        raise ValueError("Invalid or oversized image")
    if len(data) < IVT_OFFSET + 32:
        raise ValueError("Image too short for IVT")
    ivt = data[IVT_OFFSET:IVT_OFFSET+32]
    if ivt[:4] != bytes.fromhex("d1002041"):
        raise ValueError("Expected NXP IVT at offset 0x400")
    words = struct.unpack_from("<8I", ivt)
    entry, dcd, boot_data, self_ptr, csf = words[1], words[3], words[4], words[5], words[6]
    boot_offset = boot_data - LOAD_BASE
    if boot_offset < 0 or boot_offset + 12 > len(data):
        raise ValueError("Boot Data pointer is outside the local image")
    boot_start, boot_size, plugin = struct.unpack_from("<3I", data, boot_offset)
    entry_offset = entry - LOAD_BASE
    if entry_offset < 0 or entry_offset + 8 > len(data):
        raise ValueError("Entry pointer is outside the local image")
    initial_sp, reset_handler = struct.unpack_from("<2I", data, entry_offset)
    device = parse_device_descriptor(data, DEVICE_OFFSET)
    config = parse_configuration(data, CONFIG_OFFSET)
    markers = {
        name: token in data for name,token in {
            "UART":b"UART","I2C":b"I2C","SPI":b"SPI","CAN":b"CAN",
            "HID":b"HID","CDC":b"CDC","DFU":b"DFU","MSD":b"MSD"
        }.items()
    }
    return {
        "kind":"offline_ram_flashloader_candidate_not_authenticated",
        "size_bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),
        "ivt_offset":hex(IVT_OFFSET),
        "ivt":{"entry":hex(entry),"dcd":hex(dcd),"boot_data":hex(boot_data),
               "self":hex(self_ptr),"csf":hex(csf)},
        "boot_data":{"offset":hex(boot_offset),"load_address":hex(boot_start),
                     "declared_length":hex(boot_size),"plugin":plugin,
                     "file_shortfall_bytes":max(0,boot_size-len(data)),
                     "declared_length_matches_file":boot_size==len(data)},
        "entry_vector_candidate":{"offset":hex(entry_offset),
                                  "initial_stack_pointer":hex(initial_sp),
                                  "reset_handler":hex(reset_handler),
                                  "reset_handler_thumb_bit_set":bool(reset_handler&1),
                                  "reset_handler_in_declared_load_range":
                                      boot_start <= (reset_handler & ~1) < boot_start+boot_size},
        "usb_device":device,"usb_configuration":config,
        "transport_name_markers":markers,
        "limits":{"source_provenance_verified":False,"hab_signature_verified":False,
                  "sdpoverrun_applicability_verified":False,"exploit_executed":False,
                  "firmware_executed":False,"hardware_accessed":False}
    }


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    args=p.parse_args(argv)
    if not args.image.is_file() or args.image.stat().st_size>MAX_IMAGE:
        p.error("Missing or oversized image")
    print(json.dumps(audit(args.image.read_bytes()),indent=2,sort_keys=True))


if __name__=="__main__":
    main()
