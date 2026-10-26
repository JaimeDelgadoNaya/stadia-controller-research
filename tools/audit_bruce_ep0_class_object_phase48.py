"""Phase 48: map signed class-object lookup and EP0 dynamic method provenance.

Read-only, SHA-256-pinned signed OEM Bruce UPDATE; not installed flash or RAM.
Target of the double dereference at 0x600D0BFA remains conditional until
the object construction and runtime selection can be verified.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE,ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_ep0_pair_phase47 import pin_pair
from tools.audit_bruce_class_selector_verified import verified_rom_table
from tools.audit_bruce_init_inbound_phase43 import find_inbound_branches,all_byte_word_references

BASE=ASSUMED_XIP_BASE
LOOKUP=0x60054F7C
BRIDGE=0x600D0BC8
INDIRECT=0x600D0BFA
WINDOWS={
    "class_object_lookup":(0x60054F7C,0x60055018),
    "class_object_utility":(0x60054FC0,0x600550C4),
    "control_to_class_call":(0x600D0BA0,0x600D0C20),
    "class_candidate_constructor":(0x600552D0,0x600553A8),
    "class_configurator":(0x600CFD20,0x600CFE18),
}
BRIDGE_PINS={
    0x600D0BC8:("push","{r0, r1, r4, r5, r6, lr}"),
    0x600D0BCA:("mov","r5, r1"),
    0x600D0BCC:("add","r1, sp, #4"),
    0x600D0BCE:("mov","r4, r0"),
    0x600D0BD0:("mov","r6, r2"),
    0x600D0BD2:("bl","#0x60054f7c"),
    0x600D0BD6:("cbnz","r0, #0x600d0bfc"),
    0x600D0BDC:("ldr","r1, [sp, #4]"),
    0x600D0BDE:("mov","r0, r4"),
    0x600D0BE0:("bl","#0x60054f30"),
    0x600D0BEE:("ldr","r3, [sp, #4]"),
    0x600D0BF0:("mov","r2, r6"),
    0x600D0BF2:("mov","r1, r5"),
    0x600D0BF4:("mov","r0, r4"),
    0x600D0BF6:("ldr","r3, [r3, #4]"),
    0x600D0BF8:("ldr","r3, [r3, #4]"),
    0x600D0BFA:("blx","r3"),
}


def pins_match(actual,pins=BRIDGE_PINS):
    for pc,expected in pins.items():
        if actual.get(pc)!=expected:
            raise ValueError("Signed EP0 dynamic class method bridge drift "+hex(pc)+": "+str(actual.get(pc)))
    return len(pins)


def raw_word(image,pc):
    if pc%4 or not BASE<=pc<BASE+len(image)-3:
        raise ValueError("not a signed aligned XIP word")
    return struct.unpack_from("<I",image,pc-BASE)[0]


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("requires exact SHA-256 pinned Bruce signed OEM update")
    pair=pin_pair(image)
    signed=verified_rom_table(image)
    if pair["signed_callback_pointer"]!="0x60054d75" or signed[3]["selector_at_plus_0xc"]!=10:
        raise ValueError("Previous independently signed anchors drifted")
    bridge=decode(image,0x600D0BC8,0x600D0BFC)
    pin_count=pins_match({x["pc"]:(x["m"],x["op"]) for x in bridge})
    original_global_addr_literal=0x60054FAC
    raw_global_base=raw_word(image,original_global_addr_literal)
    additional_literals=[
        {"load":"0x60054f8a","literal":"0x60054fac","value":hex(raw_global_base)},
        {"load":"0x60054fbc","literal":"0x60054fe8","value":hex(raw_word(image,0x60054FE8))},
        {"load":"0x60054ffa","literal":"0x60055020","value":hex(raw_word(image,0x60055020))},
    ]
    windows={name:[hex(x["pc"])+" "+x["m"]+" "+x["op"]
                   for x in decode(image,lo,hi)]
             for name,(lo,hi) in WINDOWS.items()}
    inbound={}
    for name,pc in {"lookup":LOOKUP,"bridge":BRIDGE,
                    "constructor":0x60055320,
                    "class_setup":0x600D0E58}.items():
        inbound[name]=find_inbound_branches(image,only_target=pc)["direct_branch_candidates"][:12]
    return {
        "phase":48,
        "signed_OEM_update_sha_verified":True,
        "signed_instruction_pins":pin_count,
        "signed_lookup_literals":additional_literals,
        "matching_USB_object_global_RAM_address":hex(raw_global_base),
        "lookup_proven_semantics":{
            "input_usb_object":"R5 = caller R0 at 0x60054f7e",
            "compare_to_stored_usb_pointer":"0x60054f90 LDR R2,[R3]; 0x60054f92 CMP R5,R2",
            "on_match_output":"0x60054f96 STR R3,[R4], where R4 is output-pointer address",
            "class_method_pointer_source":"on match [SP+4] = signed RAM global base, then method is *(*([base+4]+4)) at 0x600d0bf6/f8",
            "runtime_global_RAM_values":"NOT MEASURED",
        },
        "class_records":[{
            "selector":r["selector_at_plus_0xc"],
            "method_0":r["method_0"],"method_4":r["method_4"],"method_8":r["method_8"],
            "source_signed_flash":r["record_base"],
        } for r in signed],
        "double_indirect_class_method":{
            "class_lookup_call":"0x600d0bd2 BL 0x60054f7c; class object via [SP+4]",
            "first_deref":"0x600d0bf6 LDR R3,[R3,#4]",
            "second_deref":"0x600d0bf8 LDR R3,[R3,#4]",
            "call":"0x600d0bfa BLX R3",
            "pass_through_args":"R0 USB object, R1 event-type, R2 original event data",
            "actual_selected_method":"UNVERIFIED; must derive class object, not equate pointer-table neighbors",
        },
        "windows":windows,"direct_inbound_candidate_bl":inbound,
        "class10_selected_on_hardware":"UNVERIFIED",
        "EP0_live":"UNMEASURED",
        "host_controlled_function_pointer":"NOT DEMONSTRATED",
        "hardware_usb_or_flash_access":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    data=audit(args.image.read_bytes())
    if args.out:args.out.write_text(json.dumps(data,indent=2)+"\n")
    print("PHASE48 BRIDGE",json.dumps(data["double_indirect_class_method"]))
    print("PHASE48 GLOBAL LOOKUP LITERALS",json.dumps(data["signed_lookup_literals"]))
    for name,lines in data["windows"].items():
        print("PHASE48 WINDOW",name,json.dumps(lines))
    for name,lines in data["direct_inbound_candidate_bl"].items():
        print("PHASE48 INBOUND",name,json.dumps(lines))
    print("PHASE48 RUNTIME CLASS METHOD: UNVERIFIED; NO USB/FLASH")

if __name__=="__main__":
    main()
