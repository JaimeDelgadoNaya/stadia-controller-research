"""Phase 46: signed USB1 IRQ -> EP0 callback-registration bridge, offline.

Prints bounded, original SHA-pinned Thumb windows at the missing link between
SETUP receiver dynamic callback slots and registered class forwarders.
No claims of runtime VTOR, configured endpoints or host reachability.
No USB device access.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SIZE,IMAGE_SHA256,ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_usb_irq_vector import (
    IRQS, CORE_EXCEPTIONS, EP0_RECEIVER_ANCHORS,
    check_setup_dispatch_anchors
)
from tools.audit_bruce_class_selector_verified import verified_rom_table
from tools.audit_bruce_ep0_registration import (
    REGISTRAR_ANCHORS, CALLBACK_THUMB_POINTER_ANCHORS,
    validate_registration_anchors,
)
from tools.audit_bruce_init_inbound_phase43 import (
    find_inbound_branches, all_byte_word_references
)

BASE=ASSUMED_XIP_BASE
WINDOWS={
    "endpoint_registration_caller_A":(0x60054728,0x600547A0),
    "endpoint_registration_caller_B":(0x600547EC,0x60054858),
    "class_event_wrapper_A":(0x600CFC1A,0x600CFC8E),
    "class_event_wrapper_B":(0x600CFD28,0x600CFDCE),
    "usb_xip_setup_dispatcher":(0x600D0FB6,0x600D1056),
    "endpoint_registry_setter":(0x600D10B8,0x600D10EA),
    "signed_class_callback_forwarder":(0x600D0E58,0x600D0EC0),
}
CENSUS={
    "class_event_wrapper_A":0x600CFC1A,
    "class_event_wrapper_B":0x600CFC8E,
    "ep0_setup_receiver":0x600D0FB6,
    "endpoint_registry_setter":0x600D10B8,
    "class10_forwarder":0x600D0E58,
}
VECTOR_USB_OTG1_OFFSET=(CORE_EXCEPTIONS+IRQS["USB_OTG1"])*4


def read_u32(image,off):
    if off<0 or off+4>len(image):
        raise ValueError("outside original image")
    return struct.unpack_from("<I",image,off)[0]


def verify_read_only_pins(image):
    reg=decode(image,0x600D10B8,0x600D1134)
    reg+=decode(image,0x60054728,0x60054858)
    instructions={i["pc"]:(i["m"],i["op"]) for i in reg}
    literals={pc:read_u32(image,pc-BASE) for pc in CALLBACK_THUMB_POINTER_ANCHORS}
    validate_registration_anchors(instructions,literals)
    receiver=decode(image,0x600D0FB6,0x600D1056)
    check_setup_dispatch_anchors({i["pc"]:(i["m"],i["op"]) for i in receiver})
    cls=verified_rom_table(image)
    if cls[3]["method_8"]!="0x600d0e59":
        raise ValueError("signed class10 event target moved")
    return len(REGISTRAR_ANCHORS)+len(EP0_RECEIVER_ANCHORS),literals


def scan(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("exact SHA-pinned original Bruce OEM image required")
    pins,literals=verify_read_only_pins(image)
    v=read_u32(image,VECTOR_USB_OTG1_OFFSET)
    windows={
        name:[hex(x["pc"])+" "+x["m"]+" "+x["op"]
              for x in decode(image,lo,hi)]
        for name,(lo,hi) in WINDOWS.items()
    }
    inbound={}
    refs={}
    for name,addr in CENSUS.items():
        q=find_inbound_branches(image,only_target=addr)
        inbound[name]=q["direct_branch_candidates"]
        refs[name]=all_byte_word_references(image,addr|1,limit=24)
    return {
        "phase":46,
        "sha256_verified":True,
        "signed_usb_otg1_vector_entry":hex(v),
        "usb_otg1_vector_source_file_offset":hex(VECTOR_USB_OTG1_OFFSET),
        "pins_verified":pins,
        "callback_literals":{hex(k):hex(v) for k,v in literals.items()},
        "bounded_signed_windows":windows,
        "inbound_immediate_branch_candidates":inbound,
        "all_offset_thumb_pointer_refs":refs,
        "usb1_vtor_live":"UNVERIFIED",
        "ep0_callback_slot_ram_contents":"UNMEASURED",
        "class10_packet_path":"NOT PROVEN",
        "physical_operations":False
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    opt=p.parse_args()
    result=scan(opt.image.read_bytes())
    if opt.out:opt.out.write_text(json.dumps(result,indent=2)+"\n")
    print("PHASE46 PINNED USB VECTOR",result["signed_usb_otg1_vector_entry"])
    print("PHASE46 VERIFIED SEMANTIC PINS",result["pins_verified"])
    print("PHASE46 CALLBACK POINTER LITERALS",json.dumps(result["callback_literals"]))
    for name,items in result["bounded_signed_windows"].items():
        print("PHASE46 WINDOW",name,json.dumps(items))
    for name,items in result["inbound_immediate_branch_candidates"].items():
        print("PHASE46 INBOUND",name,json.dumps(items))
    for name,items in result["all_offset_thumb_pointer_refs"].items():
        print("PHASE46 PTRREF",name,json.dumps(items))
    print("PHASE46 EP0 TO CLASS10 HARDWARE: UNVERIFIED; OFFLINE ONLY")

if __name__=="__main__":
    main()
