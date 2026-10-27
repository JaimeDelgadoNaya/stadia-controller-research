"""Phase 88: exact signed Bruce sequence writing SRC_GPR7 status 5 or 6.

Static offline byte pins with whole-file SHA-256 and IVT/CSF structure checks.
The original instruction sequence is NOT proof of USB-controlled reachability,
ROM persistence, or an update trigger. Never touch a physical controller.
"""
import argparse
import json
import struct
from pathlib import Path

from tools.audit_nxp_rom_advisories_phase81 import audit as pin_public_image
from tools.audit_src_gpr7_writers_phase88 import SRC_BASE, SRC_GPR7, UPDATE_BIT

SOURCE_OFFSET=0x38A1C
LITERAL_OFFSET=0x38ABC
BRUCE_XIP_BASE=0x60040000
# LDRB r3,[r4,#8]; CMP r3,#1; LDR r3,lit; ITE EQ;
# MOVEQ r2,#5; MOVNE r2,#6; STR r2,[r3,#0x38]
ORIGINAL_THUMB=bytes.fromhex("237a012b264b0cbf052206229a63")
STATUS_IF_EQ=5
STATUS_IF_NE=6


def inspect_original_fragment(image):
    if not isinstance(image,bytes) or len(image)<LITERAL_OFFSET+4:
        raise ValueError("Original Bruce fragment truncated")
    signed=image[SOURCE_OFFSET:SOURCE_OFFSET+len(ORIGINAL_THUMB)]
    if signed!=ORIGINAL_THUMB:
        raise ValueError("Signed Bruce SRC_GPR7 status Thumb fragment mismatch")
    literal=struct.unpack_from("<I",image,LITERAL_OFFSET)[0]
    if literal!=SRC_BASE:
        raise ValueError("Signed Bruce SRC base literal mismatch")
    words=struct.unpack("<"+"H"*(len(signed)//2),signed)
    if words!=(0x7a23,0x2b01,0x4b26,0xbf0c,0x2205,0x2206,0x639a):
        raise ValueError("Original Thumb16 words differ from expected")
    # LDR R3, PC+0x98 starts at signed offset 0x38a20
    ldr_at=SOURCE_OFFSET+4
    computed=((ldr_at+4)&~3)+0x98
    if computed!=LITERAL_OFFSET:
        raise ValueError("PC-relative literal does not target pinned original")
    return {
        "site_start":f"0x{BRUCE_XIP_BASE+SOURCE_OFFSET:08x}",
        "original_fragment_file_offset":hex(SOURCE_OFFSET),
        "fragment_thumb16_hex":ORIGINAL_THUMB.hex(),
        "literal_file_offset":hex(LITERAL_OFFSET),
        "source_base":f"0x{literal:08x}",
        "computed_destination":f"0x{literal+0x38:08x}",
        "register_name":"SRC_GPR7",
        "condition":"signed LDRB R3,[R4,#8]; CMP R3,#1; ITE EQ",
        "value_when_equal":STATUS_IF_EQ,
        "value_when_not_equal":STATUS_IF_NE,
        "either_value_sets_bootloader_update_bit3":bool((STATUS_IF_EQ|STATUS_IF_NE)&UPDATE_BIT),
        "host_usb_controls_condition":"NOT_ESTABLISHED",
        "hardware_execution_or_warm_reset_delivery":"NOT_OBSERVED",
    }


def audit(image):
    pinned=pin_public_image(image,"bruce_prod")
    frag=inspect_original_fragment(image)
    return {"phase":88,"sample":"bruce_prod",
            "signed_image_sha256":pinned["sample_sha256"],
            "finding":frag,
            "interpretation":"Original signed app has a concrete conditional GPR7 STATUS writer, not a demonstrated setter of update bit3.",
            "owner_installed_image_hash_matched":False,
            "usb_host_control_of_status_or_trigger":False,
            "physical_execution":False,
            "hab_bypass":False,
            "no_device_io":True}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image",type=Path)
    ap.add_argument("--out",type=Path)
    a=ap.parse_args()
    result=audit(a.image.read_bytes())
    payload=json.dumps(result,indent=2,ensure_ascii=False)+"\n"
    if a.out:
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(payload,encoding="utf-8")
    else:
        print(payload,end="")


if __name__=="__main__":
    main()
