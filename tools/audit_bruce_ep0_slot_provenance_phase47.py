"""Phase 47: trace original signed endpoint-slot writer arguments and guards.

Proof scope: exact SHA-256 pinned signed Bruce UPDATE IMAGE, not a live dump.
Describe which descriptor fields select the four signed class-event adapters
and propagate the caller's object pointer to each 12-byte callback slot.

The descriptor caller is *not* known to register endpoint zero at runtime.
No host-controlled function-pointer write, native Xbox compatibility, HAB
bypass or on-device execution is inferred. No device USB/flash activity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE, ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_ep0_slot_handoff_phase46 import endpoint_index, PINS as REG_PINS
from tools.audit_bruce_ep0_registration import CALLBACK_THUMB_POINTER_ANCHORS
from tools.audit_bruce_init_inbound_phase43 import find_inbound_branches

BASE=ASSUMED_XIP_BASE
REGISTRAR=0x600D10B8
DESCRIPTOR_LOOP_A=0x60054728
DESCRIPTOR_LOOP_B=0x600547AC
CLASS_CONFIGURATION_CALL=0x600CFD92

# Anchors are verified *in original real code* before their meaning is used.
ANCHORS_A={
    0x6005472C:("mov","r6, r0"),
    0x60054736:("ldr","r7, [pc, #0x68]"),
    0x60054738:("ldr.w","r8, [pc, #0x68]"),
    0x6005473C:("ldr.w","sb, [pc, #0x68]"),
    0x6005474E:("ldr","r2, [r5, #8]"),
    0x60054758:("ldrb.w","r2, [r2, r4, lsl #2]"),
    0x6005475C:("strb.w","r2, [sp, #6]"),
    0x60054766:("ldrb","r3, [r3, #1]"),
    0x60054768:("and","r1, r3, #0x30"),
    0x60054770:("cmp","r1, #0x10"),
    0x60054772:("bne","#0x60054788"),
    0x60054774:("str.w","sb, [sp, #0xc]"),
    0x60054778:("add","r2, sp, #0xc"),
    0x6005477A:("add","r1, sp, #4"),
    0x6005477C:("ldr","r0, [r6]"),
    0x60054780:("str","r6, [sp, #0x10]"),
    0x60054782:("bl","#0x600d10b8"),
    0x60054788:("and","r3, r3, #3"),
    0x6005478C:("cmp","r3, #1"),
    0x6005478E:("bne","#0x6005479a"),
    0x60054790:("lsrs","r3, r2, #7"),
    0x60054792:("beq","#0x6005479a"),
    0x60054794:("str.w","r8, [sp, #0xc]"),
    0x6005479A:("str","r7, [sp, #0xc]"),
}
ANCHORS_B={
    0x6005480E:("ldr.w","r8, [pc, #0x60]"),
    0x6005481C:("ldr","r2, [r6, #8]"),
    0x60054826:("ldrb.w","r2, [r2, r5, lsl #2]"),
    0x6005482A:("strb.w","r2, [sp, #6]"),
    0x60054834:("ldrb","r3, [r3, #1]"),
    0x6005483A:("and","r3, r3, #3"),
    0x6005483E:("cmp","r3, #3"),
    0x60054840:("bne","#0x60054854"),
    0x60054842:("lsrs","r3, r2, #7"),
    0x60054844:("beq","#0x60054854"),
    0x60054846:("add","r2, sp, #0xc"),
    0x60054848:("add","r1, sp, #4"),
    0x6005484A:("ldr","r0, [r4]"),
    0x6005484C:("strd","r8, r4, [sp, #0xc]"),
    0x60054850:("bl","#0x600d10b8"),
}
ANCHORS_CONFIG={
    0x600CFD90:("mov","r0, r4"),
    0x600CFD92:("bl","#0x60054728"),
    0x600CFD96:("ldr","r1, [r4, #0x10]"),
}
REGISTRAR_PINS={
    0x600D10C0:REG_PINS[0x600D10C0],
    0x600D10C2:REG_PINS[0x600D10C2],
    0x600D10CA:REG_PINS[0x600D10CA],
    0x600D10CC:REG_PINS[0x600D10CC],
    0x600D10CE:REG_PINS[0x600D10CE],
    0x600D10D0:REG_PINS[0x600D10D0],
    0x600D10D4:REG_PINS[0x600D10D4],
    0x600D10D6:REG_PINS[0x600D10D6],
    0x600D10DA:REG_PINS[0x600D10DA],
    0x600D10DE:REG_PINS[0x600D10DE],
}
CLEAR_PINS={
    0x600D10F6:("push","{r0, r1, r4, r5, r6, lr}"),
    0x600D10F8:("mov","r6, r0"),
    0x600D110C:("and","r5, r4, #0xf"),
    0x600D1110:("cmp","r5, #7"),
    0x600D1114:("lsrs","r3, r4, #7"),
    0x600D1116:("movs","r2, #0xc"),
    0x600D1118:("orr.w","r3, r3, r5, lsl #1"),
    0x600D111C:("mla","r3, r2, r3, r6"),
    0x600D1120:("movs","r2, #0"),
    0x600D1122:("strd","r2, r2, [r3, #0xc]"),
    0x600D1126:("strb","r2, [r3, #0x14]"),
}
PINS={**ANCHORS_A,**ANCHORS_B,**ANCHORS_CONFIG,**REGISTRAR_PINS,**CLEAR_PINS}
LITERALS={
    "a_default_type3":(0x600547A0,0x600CFC71),
    "a_type1":(0x600547A4,0x600CFC35),
    "a_high_flag_type2":(0x600547A8,0x600CFC53),
    "b_type4":(0x60054870,0x600CFC1B),
}


def validate_pins(actual,pins=PINS):
    for pc,exp in pins.items():
        if actual.get(pc)!=exp:
            raise ValueError("Phase47 signed endpoint selector semantic drift "+hex(pc)+
                             ": "+repr(actual.get(pc)))
    return len(pins)


def select_a(endpoint_address,flags):
    """Signed caller A local branch decisions; caller entry itself is conditional."""
    endpoint_index(endpoint_address)
    if not 0<=flags<=255:
        raise ValueError("record flags must be 0..255")
    if flags&0x30==0x10:
        return "type2"
    if flags&0x03==1 and (endpoint_address&0x80):
        return "type1"
    return "type3"


def select_b(endpoint_address,flags):
    """Signed caller B special branch to registered type4; otherwise skip call."""
    endpoint_index(endpoint_address)
    if not 0<=flags<=255:
        raise ValueError("record flags must be 0..255")
    return "type4" if flags&0x03==3 and endpoint_address&0x80 else None


def symbolic_registration(endpoint_address,flags,*,caller="A"):
    """Not a hardware USB packet; parameters stand for OEM record fields."""
    index=endpoint_index(endpoint_address)
    kind=select_a(endpoint_address,flags) if caller=="A" else (
        select_b(endpoint_address,flags) if caller=="B" else None)
    if caller not in ("A","B"):
        raise ValueError("caller must be A or B")
    if kind is None:
        return {"endpoint_address":hex(endpoint_address),
                "flags":hex(flags),"caller":caller,
                "slot_index":index,"signed_adapter":None,
                "registrar_called_on_these_local_predicates":False}
    pointers={"type1":0x600CFC35,"type2":0x600CFC53,
              "type3":0x600CFC71,"type4":0x600CFC1B}
    return {"endpoint_address":hex(endpoint_address),"flags":hex(flags),
            "caller":caller,"slot_index":index,
            "slot_function_field_offset":hex(0x0c+12*index),
            "slot_context_field_offset":hex(0x10+12*index),
            "signed_adapter":hex(pointers[kind]),
            "internal_event_tag":{"type1":1,"type2":2,"type3":3,"type4":4}[kind],
            "registrar_called_on_these_local_predicates":True,
            "runtime_descriptor_present":"NOT VERIFIED"}


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("exact signed OEM Bruce SHA-256 update required")
    decoded={}
    for lo,hi in ((0x60054728,0x600547A0),
                  (0x6005480E,0x60054858),
                  (0x600CFD80,0x600CFDA2),
                  (0x600D10B8,0x600D10E2),
                  (0x600D10F6,0x600D112A)):
        decoded.update({x["pc"]:(x["m"],x["op"]) for x in decode(image,lo,hi)})
    pin_count=validate_pins(decoded)
    actual_literals={}
    for name,(addr,expected) in LITERALS.items():
        found=struct.unpack_from("<I",image,addr-BASE)[0]
        if found!=expected or CALLBACK_THUMB_POINTER_ANCHORS.get(addr)!=expected:
            raise ValueError("Original signed adapter literal mismatch at "+hex(addr))
        actual_literals[name]={"literal_address":hex(addr),"thumb_pointer":hex(found)}
    inbound=find_inbound_branches(image,only_target=DESCRIPTOR_LOOP_A)
    clear_callers=find_inbound_branches(image,only_target=0x600D10F6)
    if not any(x["pc"]==hex(CLASS_CONFIGURATION_CALL)
               for x in inbound["direct_branch_candidates"]):
        raise ValueError("Original signed class configuration BL not found")
    test_cases=[
        (0x00,0x00),(0x80,0x00),
        (0x00,0x01),(0x80,0x01),
        (0x80,0x11),(0x80,0x03),(0x00,0x03),
        (0x81,0x01),(0x01,0x01)
    ]
    rows=[symbolic_registration(addr,flags,caller=caller)
          for addr,flags in test_cases for caller in ("A","B")]
    return {
        "phase":47,"signed_original_image_hash_verified":True,
        "source":"OEM signed firmware UPDATE, NOT installed flash readback",
        "signed_semantic_pins":pin_count,
        "descriptor_caller_A":{
            "entry":hex(DESCRIPTOR_LOOP_A),
            "class_configuration_call":hex(CLASS_CONFIGURATION_CALL),
            "caller_context":"R6=R0 at 0x6005472c; R6 passed in stack pair [SP+0x10] at 0x60054780",
            "endpoint_address":"record byte [R5+8][R4*4] saved SP+6",
            "flag_byte":"next byte of 4-byte record saved SP+7",
            "type1_predicates":"flag & 0x30 != 0x10; (flag & 3)==1; endpoint_address bit7 set",
            "type2_predicates":"flag & 0x30 == 0x10",
            "fallback_type3":"all other locally accepted records",
        },
        "descriptor_caller_B":{
            "entry":hex(DESCRIPTOR_LOOP_B),
            "callback_store_site":"0x6005484c STRD R8,R4,[SP+0x0c]",
            "registrar_site":"0x60054850",
            "type4_predicates":"(flag&3)==3 and endpoint_address bit7 set",
            "else":"no call to 0x600d10b8 through this particular branch",
        },
        "slot_writer":{
            "function":"0x600d10b8",
            "input_endpoint_record":"[R1+2]",
            "input_pair":"[R2] callback; [R2+4] context",
            "signed_store_callback":"0x600d10de",
            "signed_store_context":"0x600d10da",
            "EP0_OUT_slot":0,
            "EP0_IN_slot":1,
            "EP0_OUT_function_offset":"0xc",
            "EP0_IN_function_offset":"0x18",
        },
        "original_signed_adapter_literals":actual_literals,
        "signed_slot_clearer":{
            "entry":"0x600d10f6",
            "endpoint_address_source":"function input R1 low byte stored on stack, later loaded into R4",
            "index_formula":"2*(address&15)+((address>>7)&1)",
            "zero_pair_instruction":"0x600d1122 STRD R2,R2,[R3,#0x0c], R2=0",
            "cleared_words":"callback at slot+0x0c and context at slot+0x10",
            "extra_slot_status_zero":"0x600d1126 STRB R2,[R3,#0x14]",
            "can_address_ep0_out_in_by_index":True,
            "physical_device_invocation":"NOT MEASURED",
            "direct_callsite_candidates":clear_callers["direct_branch_candidates"][:16],
        },
        "synthetic_branch_matrix":rows,
        "direct_inbound_descriptor_loop_A":inbound["direct_branch_candidates"][:16],
        "focused_ep0_registration_candidate":[
            hex(q["pc"])+" "+q["m"]+" "+q["op"]
            for q in decode(image,0x60054E98,0x60054F70)
        ],
        "nearby_cleanup_call_context":[
            hex(q["pc"])+" "+q["m"]+" "+q["op"]
            for q in decode(image,0x60061510,0x60061552)
        ],
        "signed_deregistrar_candidate_window":[
            hex(q["pc"])+" "+q["m"]+" "+q["op"]
            for q in decode(image,0x600D10EA,0x600D1134)
        ],
        "observed_limits":{
            "EP0_OUT_not_select_type1_under_A_predicates":True,
            "EP0_IN_may_select_type1_only_if_flag_predicates_met":True,
            "whether_real_signed_configuration_contains_EP0_record":"UNVERIFIED",
            "actual_runtime_slot_writers_exhaustive":"NO; alias/caller paths unresolved",
            "real_EP0_IN_OUT_callback_contents":"UNMEASURED",
            "class10_object_vtable_at_runtime":"UNVERIFIED",
            "any_external_host_writable_callback_pointer":"NOT DEMONSTRATED",
            "custom_execution":"NOT DEMONSTRATED",
        },
        "hardware_access":False,"flash_or_efuse_writes":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    o=p.parse_args()
    result=audit(o.image.read_bytes())
    if o.out:o.out.write_text(json.dumps(result,indent=2)+"\n")
    print("PHASE47 VERIFIED DESCRIPTOR REGISTRATION",json.dumps({
        "pins":result["signed_semantic_pins"],
        "caller_A":result["descriptor_caller_A"],
        "caller_B":result["descriptor_caller_B"],
        "slot_writer":result["slot_writer"],
    }))
    print("PHASE47 ORIGINAL SIGNED ENDPOINT ADAPTERS",json.dumps(result["original_signed_adapter_literals"]))
    print("PHASE47 CONDITIONAL SLOT MATRIX",json.dumps(result["synthetic_branch_matrix"]))
    print("PHASE47 SIGNED SLOT CLEARER",json.dumps(result["signed_slot_clearer"]))
    print("PHASE47 FOCUSED EP0 REGISTRAR",json.dumps(result["focused_ep0_registration_candidate"]))
    print("PHASE47 OTHER CLEANUP CONTEXT",json.dumps(result["nearby_cleanup_call_context"]))
    print("PHASE47 SLOT CLEARING CONTEXT",json.dumps(result["signed_deregistrar_candidate_window"]))
    print("PHASE47 LIVE EP0 CALLBACK: UNMEASURED; NO DEVICE IO")

if __name__=="__main__":
    main()
