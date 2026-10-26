"""Phase 46: pin original USB endpoint event handoff and four class adapters.

The signed USB1 code dispatches into an endpoint slot chosen from an event
structure, but that does not tell us which function is in EP0 during runtime.
Keep separate: event structure from the IRQ, endpoint callback, event wrapper,
class event forwarder, and the class10 bRequest-byte dispatch. Original-image
SHA-256 pinning is mandatory; this module performs no physical USB or writes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_usb_irq_vector import IRQS, CORE_EXCEPTIONS
from tools.audit_bruce_ep0_registration import CALLBACK_THUMB_POINTER_ANCHORS
from tools.audit_bruce_init_inbound_phase43 import find_inbound_branches
from tools.audit_bruce_ep0_class10_bridge_phase45 import original_pins

BASE=ASSUMED_XIP_BASE
USB1_VECTOR_OFFSET=(CORE_EXCEPTIONS+IRQS["USB_OTG1"])*4
WRAPPERS={
    "type4":(0x600CFC1A,0x600CFC28,0x600CFC2A,4),
    "type1":(0x600CFC34,0x600CFC46,0x600CFC48,1),
    "type2":(0x600CFC52,0x600CFC64,0x600CFC66,2),
    "type3":(0x600CFC70,0x600CFC82,0x600CFC84,3),
}
PINS={
    0x600D0FCA:("ldrb","r2, [r1, #8]"),
    0x600D1010:("and","r3, r2, #0xf"),
    0x600D1014:("cmp","r3, #7"),
    0x600D1018:("lsls","r3, r3, #1"),
    0x600D101A:("orr.w","r3, r3, r2, lsr #7"),
    0x600D101E:("movs","r2, #0xc"),
    0x600D1020:("mla","r2, r2, r3, r0"),
    0x600D1024:("ldr","r0, [r2, #0xc]"),
    0x600D1026:("cbz","r0, #0x600d105a"),
    0x600D1028:("ldr","r0, [r1]"),
    0x600D102C:("ldr","r0, [r1, #4]"),
    0x600D102E:("ldrb","r1, [r1, #9]"),
    0x600D1040:("movs","r2, #0xc"),
    0x600D1042:("add","r1, sp, #4"),
    0x600D1046:("mla","r3, r2, r3, r4"),
    0x600D104A:("ldrd","r5, r2, [r3, #0xc]"),
    0x600D104E:("blx","r5"),
    0x600D10C0:("ldrb","r4, [r1, #2]"),
    0x600D10C2:("and","r5, r4, #0xf"),
    0x600D10CA:("lsrs","r3, r4, #7"),
    0x600D10CC:("ldr","r4, [r2]"),
    0x600D10CE:("ldr","r2, [r2, #4]"),
    0x600D10D0:("orr.w","r3, r3, r5, lsl #1"),
    0x600D10D4:("movs","r5, #0xc"),
    0x600D10D6:("mla","r3, r5, r3, r0"),
    0x600D10DA:("str","r2, [r3, #0x10]"),
    0x600D10DE:("str","r4, [r3, #0xc]"),
    0x600D10E0:("strb","r2, [r3, #0x14]"),
}
WRAPPER_PINS={}
for name,(entry,event_pc,branch_pc,event) in WRAPPERS.items():
    WRAPPER_PINS[entry+2]=("cbz","r2, #"+hex({"type4":0x600CFC2C,"type1":0x600CFC4A,"type2":0x600CFC68,"type3":0x600CFC86}[name]))
    WRAPPER_PINS[event_pc]=("movs","r1, #"+str(event))
    WRAPPER_PINS[branch_pc]=("bx","r3")


def endpoint_index(address):
    if not 0<=address<=255:
        raise ValueError("endpoint address must be 0..255")
    ep=address&15
    if ep>7:
        raise ValueError("signed receiver rejects endpoint > 7")
    return 2*ep+((address>>7)&1)


def verify_anchor_subset(actual, pins):
    for pc,pair in pins.items():
        if actual.get(pc)!=pair:
            raise ValueError("Signed endpoint event handoff drift at "+hex(pc)+
                             ": "+repr(actual.get(pc)))
    return len(pins)


def relocated_itcm_window(image,start,end):
    if not 0<=start<end<=ITCM_LENGTH:
        raise ValueError("out-of-range copied ITCM window")
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    raw=image[ITCM_SOURCE_OFFSET+start:ITCM_SOURCE_OFFSET+end]
    return [{"pc":x.address,"m":x.mnemonic,"op":x.op_str}
            for x in md.disasm(raw,start)]


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("exact original signed Bruce SHA-256 image required")
    rows=[]
    for start,end in ((0x600D0FB6,0x600D1056),
                      (0x600D10B8,0x600D10EA),
                      (0x600CFC1A,0x600CFC8E)):
        rows.extend(decode(image,start,end))
    actual={r["pc"]:(r["m"],r["op"]) for r in rows}
    n=verify_anchor_subset(actual,{**PINS,**WRAPPER_PINS})
    original_pins(image)
    vector=struct.unpack_from("<I",image,USB1_VECTOR_OFFSET)[0]
    if vector!=0x600610D1:
        raise ValueError("Original USB_OTG1 vector drift")
    literal_callbacks={
        hex(pc):hex(struct.unpack_from("<I",image,pc-BASE)[0])
        for pc in CALLBACK_THUMB_POINTER_ANCHORS
    }
    expected={hex(pc):hex(val) for pc,val in CALLBACK_THUMB_POINTER_ANCHORS.items()}
    if literal_callbacks!=expected:
        raise ValueError("Original signed endpoint adapter literal drift")
    itcm=relocated_itcm_window(image,0x1238,0x1268)
    adapters={}
    for name,(entry,event_pc,branch_pc,event) in WRAPPERS.items():
        adapters[name]={
            "signed_thumb_pointer":hex(entry|1),
            "entry":hex(entry),
            "r1_internal_event_tag":event,
            "event_tag_pc":hex(event_pc),
            "indirect_class_event_tail_call":hex(branch_pc),
            "target_from":"load pointer at [context+4], dereference [pointer], then BX R3",
            "class10_method_target_confirmed_in_this_endpoint_slot":False,
        }
    result={
        "phase":46,"original_image_sha256_verified":True,
        "usb1_vector":{"file_offset":hex(USB1_VECTOR_OFFSET),
                       "thumb":hex(vector),
                       "VTOR_live_measured":False},
        "semantic_pins":n,
        "irq_to_setup_candidate":{
            "signed_relocated_ITCM_setup_call_site":"0x1258",
            "signed_relocated_ITCM_setup_veneer":"0xba68",
            "xip_receiver":"0x600d0fb6",
            "local_ITCM_before_handoff":[hex(i["pc"])+" "+i["m"]+" "+i["op"]
                                        for i in itcm],
            "IRQ_taken_in_physical_hardware":"UNVERIFIED",
        },
        "receiver_event_structure":{
            "endpoint_address_field":"callback argument event+8 at 0x600d0fca",
            "endpoint_selection":"2*(event.endpoint_address & 0x0f)+((event.endpoint_address>>7)&1)",
            "EP0_OUT":endpoint_index(0x00),
            "EP0_IN":endpoint_index(0x80),
            "per_slot_bytes":12,
            "function_word_offset":12,
            "context_word_offset":16,
            "indirect_callback_pc":"0x600d104e",
            "event_arg_is_original_SETUP_packet":"UNVERIFIED; event structure != assumed raw SETUP",
            "runtime_slot_contents":"UNMEASURED",
        },
        "signed_slot_registration":{
            "function":"0x600d10b8",
            "endpoint_from":"[R1+2] (descriptor-like endpoint byte)",
            "callback_from":"[R2]",
            "context_from":"[R2+4]",
            "function_store":"0x600d10de STR R4,[R3+0x0c]",
            "context_store":"0x600d10da STR R2,[R3+0x10]",
            "confirmed_signed_literal_candidates":literal_callbacks,
            "EP0_registration_with_class_forwarder":"NOT PROVEN",
        },
        "signed_event_adapters":adapters,
        "host_setup_byte_and_internal_event_code_are_distinct":True,
        "class10_forwarder_connection":"CONDITIONAL via dynamic endpoint callback and class object",
        "actual_physical_EP0_class10_path":"UNVERIFIED",
        "arbitrary_code_execution":"NOT DEMONSTRATED",
        "no_hardware_or_flash":True,
    }
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    opt=p.parse_args()
    x=audit(opt.image.read_bytes())
    if opt.out:opt.out.write_text(json.dumps(x,indent=2)+"\n")
    print("PHASE46 PINNED EVENT HANDOFF",json.dumps({
        "pins":x["semantic_pins"],"vector":x["usb1_vector"],
        "receiver":x["receiver_event_structure"],
        "registrar":x["signed_slot_registration"]}))
    print("PHASE46 FOUR CLASS EVENT ADAPTERS",json.dumps(x["signed_event_adapters"]))
    print("PHASE46 ITCM SETUP HANDOFF CONTEXT",json.dumps(x["irq_to_setup_candidate"]["local_ITCM_before_handoff"]))
    print("PHASE46 PHYSICAL EP0 CLASS10 PATH: UNVERIFIED")

if __name__=="__main__":
    main()
