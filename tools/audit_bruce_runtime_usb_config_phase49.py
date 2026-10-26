"""Phase49 original signed Bruce configuration construction evidence collection.

No device I/O. The file is the exact SHA-pinned *signed OEM update*, not
installed-flash readback or observed RAM. Inspects bounded Thumb functions
that can populate the shared USB singleton and its configuration object.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE,ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import DATA_DESTINATION,DATA_END,DATA_SOURCE_OFFSET
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_ep0_class_object_phase48 import raw_word
from tools.audit_bruce_init_inbound_phase43 import find_inbound_branches,all_byte_word_references

BASE=ASSUMED_XIP_BASE
USB_CORE=0x20004080
CLASS10_GLOBAL=0x200040E0
SLICES={
    "usb_shared_constructor_body":(0x600550E0,0x60055170),
    "class_runtime_configuration_selector":(0x600551A0,0x60055234),
    "class_runtime_constructor":(0x60055234,0x600552D0),
    "usb_class_adapter_configuration":(0x600CFE00,0x600CFEC0),
    "host_usb_control_routing":(0x600D0B54,0x600D0C54),
    "usb_singleton_utility":(0x60054E98,0x6005505C),
}
CENSUS={
    "shared_usb_constructor_candidate":0x600550E0,
    "class_runtime_configuration_selector":0x60055100,
    "class_runtime_constructor":0x60055234,
    "usb_shared_global_lookup":0x60054F7C,
    "usb_dynamic_config_method":0x600D0BC8,
}
EXPECTED={
    0x60054FAC:USB_CORE,
    0x60054FE8:USB_CORE,
    0x60055020:USB_CORE,
    0x6005534C:CLASS10_GLOBAL,
}


def source_for_ram(addr):
    if DATA_DESTINATION<=addr<DATA_END:
        return {"kind":"signed_initialized_copy",
                "file_offset":hex(DATA_SOURCE_OFFSET+addr-DATA_DESTINATION)}
    return {"kind":"NOT IN signed initialized data copy; runtime population required",
            "file_offset":None}


def inspect(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Phase49 exact Bruce original signed SHA-256 update required")
    literal_rows=[]
    for addr,expected in EXPECTED.items():
        got=raw_word(image,addr)
        if got!=expected:
            raise ValueError("Original global literal drift "+hex(addr))
        literal_rows.append({"source":hex(addr),"ram_target":hex(got),
                             "copy_origin":source_for_ram(got)})
    output={"phase":49,
        "pinned_sha256_verified":True,
        "source":"exact signed OEM update not actual installed flash",
        "verified_literal_rows":literal_rows,
        "shared_USB_global_plus4":hex(USB_CORE+4),
        "runtime_config_method_from":"[ [0x20004080 + 4] + 4 ]",
        "class_record_array_from":"[ [0x20004080 + 4] + 0 ]",
        "runtime_class_count_from":"byte [ [0x20004080 + 4] + 8 ]",
        "signed_code_windows":{
            k:[hex(x["pc"])+" "+x["m"]+" "+x["op"] for x in decode(image,start,end)]
            for k,(start,end) in SLICES.items()},
        "candidate_direct_branch_callers":{
            k:find_inbound_branches(image,only_target=target)["direct_branch_candidates"][:20]
            for k,target in CENSUS.items()},
        "literal_references_to_core":all_byte_word_references(image,USB_CORE,limit=60),
        "literal_references_to_core_config":all_byte_word_references(image,USB_CORE+4,limit=40),
        "physical_EP0_active_config":"UNMEASURED",
        "host_controlled_callback_writes":"NOT DEMONSTRATED",
        "usb_packets_or_flash_writes":False,
    }
    return output


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    x=inspect(args.image.read_bytes())
    if args.out:args.out.write_text(json.dumps(x,indent=2)+"\n")
    print("PHASE49 VERIFIED CONFIG LITERALS",json.dumps(x["verified_literal_rows"]))
    for k,v in x["signed_code_windows"].items():
        print("PHASE49 SIGNED CODE WINDOW",k,json.dumps(v))
    for k,v in x["candidate_direct_branch_callers"].items():
        print("PHASE49 DIRECT INBOUND",k,json.dumps(v))
    print("PHASE49 CORE REFERENCES",json.dumps(x["literal_references_to_core"]))
    print("PHASE49 CONFIG PTR REFERENCES",json.dumps(x["literal_references_to_core_config"]))
    print("PHASE49 DEVICE/CLASS ACTIVATION: NOT VERIFIED; NO HARDWARE WRITES")


if __name__=="__main__":
    main()
