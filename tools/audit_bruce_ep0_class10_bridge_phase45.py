"""Phase 45: prove conditional bRequest-register continuity to the OEM class10 table.

All code/data anchors are read from the SHA-256 pinned original signed
Bruce *update image*. The path is conditional on runtime class selection,
the class object, the secondary callback setter, and USB EP0 reachability.
No USB IO, firmware patch, unsigned code or physical RAM access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_class_selector_verified import verified_rom_table
from tools.audit_bruce_class10_record_producer import (
    confirmed_boot_records, original_class10_handler_guard,
)
from tools.audit_bruce_secondary_override_phase44 import (
    audit_handler_table, inspect_second_writer, verify_signed_second_setter_caller,
)
from tools.audit_bruce_init_inbound_phase43 import find_inbound_branches, all_byte_word_references

CONTROL_ENTRY=0x600D0E58
SIGNED_CLASS10=0x600613FC
SIGNED_SECONDARY=0x600DB028
DISPATCH=0x60077360
COPY_RECORD=0x200030F4
SENTINEL=0x600D4F05
ACTIVE=0x600DB029
PINS={
    0x600D0EA2:("ldr","r1, [r2]"),
    0x600D0EA4:("ldrb","r3, [r1]"),
    0x600D0EA6:("and","r3, r3, #0x1f"),
    0x600D0EAA:("cmp","r3, #1"),
    0x600D0EAE:("ldrb","r5, [r0, #0xd]"),
    0x600D0EB0:("ldrb","r4, [r1, #4]"),
    0x600D0EB2:("cmp","r5, r4"),
    0x600D0EB6:("ldr","r3, [r0, #4]"),
    0x600D0EB8:("ldrb","r1, [r1, #1]"),
    0x600D0EBA:("ldr","r3, [r3]"),
    0x600D0EBE:("bx","r3"),
    0x600613FC:("cmp","r1, #0x7f"),
    0x60061400:("bls","#0x60061422"),
    0x6006140A:("ldr","r3, [r0, r3]"),
    0x6006140C:("cmp","r3, r4"),
    0x6006140E:("beq","#0x60061422"),
    0x60061414:("ldr","r0, [r0, r4]"),
    0x60061416:("blx","r3"),
    0x600DB028:("b.w","#0x60077360"),
    0x60077360:("subs","r1, #0x80"),
    0x6007736A:("cmp","r1, #0xc"),
    0x6007736C:("bhi.w","#0x600774ae"),
    0x60077370:("tbb","[pc, r1]"),
}


def original_pins(image):
    spans=(
        (0x600D0EA0,0x600D0EC0),
        (0x600613FC,0x60061420),
        (0x600DB028,0x600DB02C),
        (0x60077360,0x60077374),
    )
    rows={}
    for start,end in spans:
        for item in decode(image,start,end):
            rows[item["pc"]]=(item["m"],item["op"])
    for pc,expected in PINS.items():
        if rows.get(pc)!=expected:
            raise ValueError("Original signed class10 request bridge drift at "+hex(pc)+
                             " actual "+repr(rows.get(pc)))
    return len(PINS)


def route_symbolic(bm_request_type, b_request, *, matching_interface=True,
                   registered_class10=True, active_secondary=True):
    """Model only proved, guarded Thumb operations, NOT a live USB path.

    A simulated SETUP structure passes a direct two-register R1 value;
    'registered_class10' and 'active_secondary' are explicit prerequisites.
    It does not execute the signed callback.
    """
    if not 0 <= bm_request_type <= 0xFF or not 0 <= b_request <= 0xFF:
        raise ValueError("USB request bytes must be 0..255")
    steps=[]
    if bm_request_type & 0x1f != 1:
        return {"stage":"recipient_guard_reject", "dispatch":None, "steps":steps}
    steps.append("recipient: interface")
    if not matching_interface:
        return {"stage":"interface_guard_reject", "dispatch":None, "steps":steps}
    steps.append("interface comparison: matches")
    if not registered_class10:
        return {"stage":"class10_not_registered", "dispatch":None, "steps":steps}
    steps.append("conditionally R1 := SETUP byte[1], then BX selected class function")
    if b_request <= 0x7f:
        return {"stage":"class10_r1_guard_reject", "dispatch":None, "steps":steps}
    steps.append("class10 R1 > 0x7f")
    if not active_secondary:
        return {"stage":"signed_default_sentinel_guard", "dispatch":None, "steps":steps}
    steps.append("secondary OEM signed callback; R1 unchanged before B.W")
    index=b_request-0x80
    if index > 0xc:
        return {"stage":"handler_range_guard_reject","dispatch":None,"steps":steps}
    return {"stage":"table_dispatch","dispatch":index,"steps":steps}


def prove_r1_continuity():
    """Pin architecture of register use to the instructions validated above."""
    return [
        {"pc":"0x600d0ea2","effect":"R1 = [R2], candidate SETUP buffer"},
        {"pc":"0x600d0eb8","effect":"R1 = unsigned byte([R1+1]); request byte"},
        {"pc":"0x600d0ebe","effect":"BX R3; no R1 rewrite; conditional class10 selection"},
        {"pc":"0x600613fc","effect":"CMP R1,#0x7F; rejects <=0x7F"},
        {"pc":"0x60061416","effect":"BLX R3; R1 unchanged on qualified path"},
        {"pc":"0x600db028","effect":"B.W 0x60077360; R1 unchanged"},
        {"pc":"0x60077360","effect":"R1 -= 0x80, dispatch index"},
        {"pc":"0x6007736a","effect":"reject unsigned index > 12"},
        {"pc":"0x60077370","effect":"TBB [PC,R1] to signed OEM case"},
    ]


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("exact SHA-256 pinned OEM original Bruce required")
    n=original_pins(image)
    records=confirmed_boot_records(image)
    if records[1]["destination_boot_RAM"]!=hex(COPY_RECORD):
        raise ValueError("original signed class10 record moved")
    if records[1]["callback_thumb_word"]!=hex(SIGNED_CLASS10|1):
        raise ValueError("class10 signed callback pointer changed")
    table=verified_rom_table(image)
    if table[3]["selector_at_plus_0xc"]!=10 or table[3]["method_8"]!=hex(CONTROL_ENTRY|1):
        raise ValueError("original class10 forwarder registry changed")
    guard=original_class10_handler_guard(image)
    if guard["sentinel_word_from_pc_literal"]!=hex(SENTINEL):
        raise ValueError("secondary signed guard changed")
    writer=inspect_second_writer(image)
    if writer["callback_value_literal"]["value"]!=hex(ACTIVE) or not writer["base_equals_class10_global"]:
        raise ValueError("secondary signed callback setter changed")
    caller=verify_signed_second_setter_caller(image)
    if caller["getter_returns_RAM_object"]!="0x20003670":
        raise ValueError("fixed OEM secondary context changed")
    dispatch=audit_handler_table(image)
    samples=[]
    for request in (0x7f,0x80,0x81,0x82,0x83,0x84,0x8c,0x8d,0xff):
        result=route_symbolic(0xA1,request)
        case=next((x for x in dispatch["dispatches"]
                   if x["table_index"]==result["dispatch"]),None)
        samples.append({
            "candidate_brequest":hex(request),
            "symbolic_stage":result["stage"],
            "original_signed_case_pc":case["branch_target"] if case else None,
            "simulates_physical_USB":False,
        })
    return {
        "phase":45,"original_signed_image_sha_verified":True,
        "source":"signed OEM Bruce update, NOT readback of real installed flash",
        "signed_r1_semantic_anchors":n,
        "registration":{
            "class10_table_selector":10,
            "class10_event_forwarder_thumb":table[3]["method_8"],
            "boot_copied_class10_callback_thumb":records[1]["callback_thumb_word"],
            "boot_copied_record_RAM":hex(COPY_RECORD),
            "class10_selection_runtime":"UNVERIFIED",
        },
        "conditional_r1_chain":prove_r1_continuity(),
        "host_buffer_field":"[R1+1] (class forwarder), forwarded as R1",
        "recipient_bits_guard":"bmRequestType & 0x1F == 1",
        "wIndex_match_guard":"SETUP byte +4 == class object byte +0x0D",
        "signed_secondary_values":{
            "boot_default_sentinel":hex(SENTINEL),
            "later_signed_callback":hex(ACTIVE),
            "later_callback_context":caller["R4_context_written_by_setter"],
            "real_hardware_active_callback":"UNMEASURED",
        },
        "signed_dispatch_table":dispatch["dispatches"],
        "sample_symbolic_matrix":samples,
        "usb_setup_class_endpoint_proven":False,
        "live_EP0_to_forwarder_reachability":"UNVERIFIED",
        "class10_selected_on_original_controller":"UNVERIFIED",
        "signed_second_callback_installed_on_real_controller":"UNVERIFIED",
        "host_controlled_arbitrary_callback_write":"NOT DEMONSTRATED",
        "custom_code_execution_or_HAB_bypass":"NOT DEMONSTRATED",
        "remaining":["Connect USB1 EP0 IRQ packet ingestion to class10 forwarder",
                     "Prove class10 selected for active interface at runtime",
                     "Prove second setter's early branch predicates",
                     "Inspect signed case payload/side effects without treating TBB data as code"],
        "hardware_used":False,"flash_written":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    opt=p.parse_args()
    x=audit(opt.image.read_bytes())
    if opt.out:opt.out.write_text(json.dumps(x,indent=2)+"\n")
    print("PHASE45 SIGNED BRIDGE",json.dumps({
        "pins":x["signed_r1_semantic_anchors"],
        "event":x["registration"]["class10_event_forwarder_thumb"],
        "callback":x["registration"]["boot_copied_class10_callback_thumb"],
        "second":x["signed_secondary_values"],
        "recipient":x["recipient_bits_guard"],
        "interface":x["wIndex_match_guard"]}))
    print("PHASE45 SIGNED ROUTE TABLE",json.dumps(x["sample_symbolic_matrix"]))
    print("PHASE45 USB EP0 ACTIVITY: UNVERIFIED; NO DEVICE I/O")

if __name__=="__main__":
    main()
