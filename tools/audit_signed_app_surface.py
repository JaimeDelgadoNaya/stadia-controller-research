"""Offline surface audit for the user-supplied signed Stadia Bruce application.

**No device/USB APIs**. Requires the exact privately held
bruce_pvt_a_prod_signed(1).bin sample; no executable, firmware or
certificate contents are ever printed or committed to Git.

Findings are conditional code/string references; the file is an *update
image*, NOT a verified full dump of the controller's installed flash.
A first-byte == 5 gate is an internal packet parser check, NOT evidence
of USB bRequest 0x05 or a host-reachable firmware-update opcode.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

IMAGE_SIZE = 1050984
IMAGE_SHA256 = "466ddd2dbcd8d1a66e2826f25849a6e5e45d9bb7e696e3fe0d500af56a5507a3"
ASSUMED_XIP_BASE = 0x60040000
REGION_BEGIN, REGION_END = 0x18B68, 0x18BE0
REGION_SHA256 = "2509b2d695fd6b55bcfcd4a9b63e32766976e5858e41b1a7fc8583d153c54a1e"
PARSER_ENTRY = 0x18B68
PARSER_GUARD = 0x18B74
PARSER_CALL = 0x18B7A
EXPECTED_PARSE_TARGET = 0x18AA8
STRING_LABELS = {
    "unknown_host_request": b"Unknown host USB request:",
    "applied_update_status": b"An update has just been applied. Marking verified",
    "vendor_component": b"usb_device_vendor.cc",
    "build_string": b"337784",
}
EXPECTED_REFERENCE_OFFSETS = {
    "unknown_host_request": [0x18BD8],
    "applied_update_status": [0x1B3FC],
    "vendor_component": [0x21504, 0x215B4],
    "build_string": [0x18380, 0x1D96C],
}
# Minimal instruction anchors confirm branch/conditional behavior without
# distributing the application binary.
ANCHORS = {
    0x18B68: "10b5",  # PUSH {r4, lr}
    0x18B70: "28b1",  # CBZ r0
    0x18B72: "0378",  # LDRB r3,[r0]
    0x18B74: "052b",  # CMP r3,#5 -- *payload byte*, NOT USB bRequest
    0x18B76: "04d1",  # BNE alternative message
    0x18B78: "0130",  # ADDS r0,#1
    0x18B7A: "fff795ff",  # BL 0x60058aa8, wrapper after recognized tag
    0x18B86: "1449",  # LDR r1,[pc,#0x50], error message literal
}


def fmt(number):
    return f"0x{number:08x}"


def decode_thumb_bl_target(image, offset, base=ASSUMED_XIP_BASE):
    if not isinstance(offset,int) or offset<0 or offset+4>len(image) or offset&1:
        raise ValueError("Invalid Thumb BL location")
    first,second=struct.unpack_from("<HH",image,offset)
    if first&0xF800 != 0xF000 or second&0xD000 != 0xD000:
        raise ValueError("Not an unconditional Thumb BL")
    s,j1,j2=(first>>10)&1,(second>>13)&1,(second>>11)&1
    i1,i2=1^(j1^s),1^(j2^s)
    encoded=(s<<24)|(i1<<23)|(i2<<22)|((first&0x3ff)<<12)|((second&0x7ff)<<1)
    signed=encoded-(1<<25) if s else encoded
    return (base+offset+4+signed)&0xFFFFFFFF


def reference_offsets(image, absolute_value):
    needle=struct.pack("<I",absolute_value)
    return [i for i in range(0,len(image)-3,4)
            if image[i:i+4]==needle]


def inspect(image,expected_sha256=IMAGE_SHA256,expected_region=REGION_SHA256,
            expected_refs=EXPECTED_REFERENCE_OFFSETS):
    if len(image)!=IMAGE_SIZE:
        raise ValueError("Signed Bruce sample must have 1050984 bytes")
    actual_hash=hashlib.sha256(image).hexdigest()
    if actual_hash!=expected_sha256:
        raise ValueError("Unexpected signed Bruce SHA-256")
    if hashlib.sha256(image[REGION_BEGIN:REGION_END]).hexdigest()!=expected_region:
        raise ValueError("Unexpected application parser code fingerprint")
    sp,reset=struct.unpack_from("<II",image,0)
    if sp!=0x2002B828 or reset!=0x60040501:
        raise ValueError("Application vector evidence changed")
    target=decode_thumb_bl_target(image,PARSER_CALL)
    if target!=ASSUMED_XIP_BASE+EXPECTED_PARSE_TARGET:
        raise ValueError("Parser wrapper call destination changed")
    for offset,raw in ANCHORS.items():
        blob=bytes.fromhex(raw)
        if image[offset:offset+len(blob)]!=blob:
            raise ValueError(f"Parser instruction anchor mismatch at {fmt(ASSUMED_XIP_BASE+offset)}")

    refs={}
    for label,needle in STRING_LABELS.items():
        at=image.find(needle)
        if at<0:
            raise ValueError(f"Expected application label absent: {label}")
        matches=reference_offsets(image,ASSUMED_XIP_BASE+at)
        if expected_refs is not None and matches!=expected_refs[label]:
            raise ValueError(f"Changed xrefs to application label: {label}")
        refs[label]={
            "first_file_offset":fmt(at),
            "computed_address":fmt(ASSUMED_XIP_BASE+at),
            "word_reference_file_offsets":[fmt(x) for x in matches],
            "reference_count":len(matches),
            "claim":"literal references only; executing caller and USB reachability NOT established"
        }
    # String literal used by the logging code at 0x18B86.
    err_ptr=struct.unpack_from("<I",image,0x18BD8)[0]
    if err_ptr!=int(refs["unknown_host_request"]["computed_address"],16):
        raise ValueError("Unknown-request string pointer not at expected literal site")

    return {
        "phase":"updater_decision_gate","module":"signed_application_surface",
        "sample_kind":"owner-provided signed Bruce update image",
        "same_as_full_installed_flash":"NOT VERIFIED",
        "bytes":len(image),"sha256":actual_hash,"sha256_verified":True,
        "physical_access":False,"usb_io":False,"flash_or_fuse_writes":False,
        "model":{
            "base_assumption":fmt(ASSUMED_XIP_BASE),
            "initial_stack_pointer":fmt(sp),
            "thumb_reset_vector":fmt(reset),
            "reset_vector_status":"within signed image's assumed XIP range; does not prove installed image identity",
        },
        "parser_candidate":{
            "entry":fmt(ASSUMED_XIP_BASE+PARSER_ENTRY),
            "non_null_buffer_check":fmt(ASSUMED_XIP_BASE+0x18B70),
            "payload_first_byte_guard":fmt(ASSUMED_XIP_BASE+PARSER_GUARD),
            "guard_value":5,
            "guard_classification":"first byte of pointed-to input buffer; NOT USB bRequest",
            "recognized_branch_prepares_buffer_plus_one":fmt(ASSUMED_XIP_BASE+0x18B78),
            "next_direct_call":fmt(target),
            "unrecognized_branch_uses_string_literal":fmt(ASSUMED_XIP_BASE+0x18BD8),
            "reachable_from_real_host_usb_request":"NOT DEMONSTRATED",
            "update_write_or_HAB_authentication_path":"NOT DEMONSTRATED",
        },
        "read_only_literal_xrefs":refs,
        "limits":{
            "USB_version_query_documented_externally":"0xA1/0x81 on normal-mode WinUSB; previously measured, not sent by this tool",
            "historical_WebUSB_update_path":"documented in external archived updater, but its host requests NOT matched to this candidate",
            "application_authentication_status":"signed update image filename only; no local signature validation by this tool",
            "safe_custom_execution":"NOT DEMONSTRATED",
            "HAB_closed_bypass":"NOT DEMONSTRATED",
        },
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image",type=Path,help="Private signed Bruce sample")
    parser.add_argument("--out",type=Path,help="Local JSON report")
    args=parser.parse_args()
    report=json.dumps(inspect(args.image.read_bytes()),indent=2,ensure_ascii=False)+"\n"
    if args.out:
        args.out.write_text(report,encoding="utf-8")
    else:
        print(report,end="")


if __name__=="__main__":
    main()
