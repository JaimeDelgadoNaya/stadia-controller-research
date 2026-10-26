"""Phase 49: prove signed shared USB config pointer writers and callback provenance.

This is *original-image static dataflow only*. The OEM signed update is
SHA-pinned. In particular, config pointer [0x20004084] is a caller supplied
RAM struct pointer, not a reconstructed ROM class table. The live class
count and signed class10 presence are NOT asserted by this audit.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_ep0_class_object_phase48 import raw_word
from tools.audit_app_usb_dispatch import DATA_DESTINATION, DATA_END
from tools.audit_bruce_init_inbound_phase43 import find_inbound_branches

SHARED_USB=0x20004080
CONFIG_PTR_SLOT=SHARED_USB+4
ENGINE_PTR_SLOT=SHARED_USB
ENGINE_OBJECT=0x200063C0
ENGINE_VTABLE=0x60104BC4
ROM_CLASS_METHODS=0x60104B74

ORIGINAL_LITERALS={
    0x600551A8:SHARED_USB,
    0x600551AC:0x200040A0,
    0x600551B0:0x600D0BC9,
    0x600551B4:ROM_CLASS_METHODS,
    0x600553F8:ENGINE_OBJECT,
    0x600553FC:ENGINE_VTABLE,
    0x60104BC4:0x6005556D,
}
PINS={
    0x600550E4:("push.w","{r0, r1, r2, r4, r5, r6, r7, r8, sb, sl, fp, lr}"),
    0x600550E8:("mov","r6, r0"),
    0x600550EA:("mov","r4, r1"),
    0x600550EC:("mov","sl, r2"),
    0x60055104:("ldr","r3, [pc, #0xa0]"),
    0x6005510C:("mov","r5, r3"),
    0x60055124:("ldr","r7, [pc, #0x84]"),
    0x60055128:("str","r7, [r3, #8]"),
    0x6005512E:("str","r4, [r5, #4]"),
    0x60055130:("sub.w","r2, r7, #0x20"),
    0x60055134:("ldr","r1, [pc, #0x78]"),
    0x60055136:("mov","r0, r6"),
    0x60055138:("bl","#0x60055350"),
    0x60055350:("push.w","{r0, r1, r4, r5, r6, r7, r8, lr}"),
    0x60055356:("mov","r8, r1"),
    0x60055358:("mov","r7, r2"),
    0x60055366:("ldr","r3, [pc, #0x90]"),
    0x6005536C:("ldr","r6, [r3]"),
    0x6005539A:("add.w","r2, r3, #0xc0"),
    0x600553A0:("str.w","r8, [r4, #8]"),
    0x600553AA:("strd","r6, r6, [r3, #0xc]"),
    0x600553BA:("ldr","r3, [pc, #0x40]"),
    0x600553C0:("str","r3, [r4, #4]"),
    0x600553C2:("str","r4, [r7]"),
    0x600553C6:("ldr","r3, [r4, #4]"),
    0x600553C8:("ldr","r3, [r3]"),
    0x600553CA:("blx","r3"),
    0x60060F84:("push","{r3, r4, r5, lr}"),
    0x60060F86:("add.w","r2, r0, #0x98"),
    0x60060F8A:("adds","r1, r0, #4"),
    0x60060F8C:("mov","r4, r0"),
    0x60060F8E:("ldrb","r0, [r0, #0x10]"),
    0x60060F90:("bl","#0x600550e4"),
    0x6006102C:("mov","r0, r4"),
    0x6006102E:("bl","#0x60060f84"),
}

SPANS=((0x600550E4,0x6005513C),
       (0x60055350,0x60055372),
       (0x60055390,0x600553CE),
       (0x60060F84,0x60060F94),
       (0x6006102C,0x60061032))


def check_original_pins(actual, expected=PINS):
    for pc,pair in expected.items():
        if actual.get(pc)!=pair:
            raise ValueError("Phase49 signed OEM config writer drift "+hex(pc)+": "+repr(actual.get(pc)))
    return len(expected)


def abstract_config_owner(owner_address):
    if owner_address<0x20000000 or owner_address>0x20FFFF00:
        raise ValueError("synthetic RAM owner pointer required")
    return {"owner":hex(owner_address),
            "config_start":hex(owner_address+4),
            "class_record_array_pointer_field":hex(owner_address+4),
            "dynamic_config_method_field":hex(owner_address+8),
            "class_record_count_byte":hex(owner_address+12),
            "engine_output_pointer_field":hex(owner_address+0x98),
            "mode_byte_field":hex(owner_address+0x10),
            "live_contents":"NOT MEASURED",
            "method_points_to_host_supplied_code":"NOT PROVEN"}


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("original exact SHA-256 pinned Bruce OEM image required")
    rows={}
    for start,end in SPANS:
        rows.update({q["pc"]:(q["m"],q["op"]) for q in decode(image,start,end)})
    pin_count=check_original_pins(rows)
    literals=[]
    for address,expected in ORIGINAL_LITERALS.items():
        found=raw_word(image,address)
        if found!=expected:
            raise ValueError("Original signed constructor literal drift "+hex(address))
        literals.append({"PC":hex(address),"value":hex(found)})
    if DATA_DESTINATION<=SHARED_USB<DATA_END:
        raise ValueError("shared singleton is not supposed to be signed boot initialized data")
    callers=find_inbound_branches(image,only_target=0x600550E4)["direct_branch_candidates"]
    direct=any(x["pc"]=="0x60060f90" for x in callers)
    if not direct:
        raise ValueError("exact signed constructor direct BL to 0x600550E4 missing")
    return {
        "phase":49,"original_signed_sha_verified":True,
        "original_static_semantic_pins":pin_count,
        "signed_literals":literals,
        "usb_common_config_writer":{
            "entry":"0x600550e4",
            "singleton_global":hex(SHARED_USB),
            "shared_config_pointer_RAM_field":hex(CONFIG_PTR_SLOT),
            "pointer_source":"original caller's R1; preserved in R4 at 0x600550ea",
            "signed_pointer_store":"0x6005512e STR R4,[R5,#4]",
            "signed_object_registry_pointer_RAM":"0x20004088 receives literal 0x200040a0 via 0x60055128",
            "signed_engine_initializer_call":"0x60055138 BL 0x60055350",
            "invocation_runtime":"UNVERIFIED",
        },
        "signed_owner_to_config_args":{
            "owner_entry":"0x60060f84",
            "original_R0":"owner context pointer not reconstructed to a fixed RAM address",
            "input_config_arg":"owner+4 -> R1 at 0x60060f8a",
            "mode_byte":"owner+0x10 -> R0 at 0x60060f8e",
            "engine_output":"owner+0x98 -> R2 at 0x60060f86",
            "BL_shared_constructor":"0x60060f90 BL 0x600550e4",
            "significant_guard":"constructor verifies inputs and singleton state; no unconditional guarantee",
            "example_synthetic_fields":abstract_config_owner(0x20008000),
        },
        "signed_engine_initializer":{
            "entry":"0x60055350",
            "original_signed_engine_global_literal":"0x600553f8 -> 0x200063c0",
            "initialized_engine_pointer_stored_to":"0x600553c2 STR R4,[R7], R7 points to 0x20004080 if caller passed literal 0x200040a0 - 0x20",
            "engine_vtable_literal":"0x600553fc -> 0x60104bc4",
            "engine_first_signed_method":"0x60104bc4 -> 0x6005556d",
            "engine_vtable_stored_to":"0x600553c0 STR R3,[R4,#4]",
            "engine_bRequest_delegate_stored_to":"0x600553a0 STR.W R8,[R4,#8], R8 originated 0x600d0bc9",
            "signed_engine_initialisation_call":"0x600553ca BLX R3",
            "runtime_success":"UNVERIFIED",
        },
        "origin_of_live_class_record_array":{
            "pointer_read_by_class_fanout":"[config+0], equal to owner+4 word if config=owner+4",
            "method_read_at":"[config+4], equal to owner+8 word if config=owner+4",
            "count_read_at":"[config+8], equal to owner+0xc byte if config=owner+4",
            "actual_bytes":"UNMEASURED",
            "class10_present":"NOT PROVEN",
            "signed_boot_class10_record_exists":"YES but DOES NOT imply listed in active config",
        },
        "direct_original_callers":callers[:8],
        "physical_host_EP0_class10_reachable":"UNVERIFIED",
        "unsigned_execution_and_HAB_closed_bypass":"NOT DEMONSTRATED",
        "usb_device_used":False,"flash_efuse_modified":False
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    result=audit(args.image.read_bytes())
    if args.out:args.out.write_text(json.dumps(result,indent=2)+"\n")
    print("PHASE49 VERIFIED WRITER",json.dumps(result["usb_common_config_writer"]))
    print("PHASE49 SIGNED OWNER INPUT",json.dumps(result["signed_owner_to_config_args"]))
    print("PHASE49 SIGNED ENGINE INITIALISER",json.dumps(result["signed_engine_initializer"]))
    print("PHASE49 CLASS RECORD GATE",json.dumps(result["origin_of_live_class_record_array"]))
    print("PHASE49 ACTUAL USB CONFIG UNMEASURED; NO PHYSICAL DEVICE")


if __name__=="__main__":
    main()
