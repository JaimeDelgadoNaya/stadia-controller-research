"""Phase 48: signed class selector -> singleton pointer provenance and limitations.

Verifies the original class-selection loop and the class10 initializer in the
exact signed OEM update. Distinguishes a *runtime 12-byte class record* selected
by the method-0 loop from the signed XIP 16-byte method table that contains
the method-0/-4/-8 implementations. No live RAM or physical USB assumptions.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SIZE,IMAGE_SHA256,ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_class_selector_verified import verified_rom_table
from tools.audit_bruce_class10_record_producer import confirmed_boot_records
from tools.audit_bruce_ep0_class_object_phase48 import raw_word,BRIDGE_PINS,pins_match

BASE=ASSUMED_XIP_BASE
EP0_LOOKUP_GLOBAL=0x20004080
CLASS10_GLOBAL=0x200040E0
CLASS1_GLOBAL=0x200040C0
CLASS2_GLOBAL=0x20004040
CLASS4_GLOBAL=0x20004020
CLASS2_GLOBAL_LIT=0x60054CF4
CLASS4_GLOBAL_LIT=0x600548C0
STATIC_TABLE_CLASS10=0x60104BA4
SIGNED_CLASS10_CALLBACK=0x600613FD
BOOT_CLASS10_RAM_RECORD=0x200030F4
CLASS10_INIT=0x60055320
CLASS1_INIT=0x600552F0
CLASS1_GLOBAL_LIT=0x6005531C

PINS={
    0x60055072:("bl","#0x60054f7c"),
    0x60055086:("ldr","r3, [sp, #4]"),
    0x6005508A:("ldr","r3, [r3, #4]"),
    0x6005508C:("ldrb","r2, [r3, #8]"),
    0x60055092:("ldr","r3, [r3]"),
    0x60055094:("mla","r0, r8, r0, r3"),
    0x60055098:("ldr","r3, [r0, #8]"),
    0x6005509A:("ldrb","r3, [r3, #4]"),
    0x600550A8:("cmp","r3, #0xa"),
    0x600550BA:("ldr","r3, [r3, #8]"),
    0x600550BC:("blx","r3"),
    0x60055178:("ldr","r3, [r5, #4]"),
    0x6005517A:("ldr","r1, [r3]"),
    0x6005517C:("add.w","r3, fp, r7"),
    0x60055180:("add","r1, r8"),
    0x60055182:("ldrb","r3, [r3, #0xc]"),
    0x60055184:("ldr","r2, [r1, #8]"),
    0x60055186:("ldrb","r2, [r2, #4]"),
    0x60055188:("cmp","r2, r3"),
    0x6005518A:("bne","#0x60055196"),
    0x6005518C:("ldr.w","r3, [r7, fp]"),
    0x60055190:("adds","r2, r1, #4"),
    0x60055192:("mov","r0, r6"),
    0x60055194:("blx","r3"),
    0x60055196:("adds","r7, #0x10"),
    0x60055198:("cmp","r7, #0x50"),
    0x600552F0:("push","{r4, r5, r6, lr}"),
    0x600552F2:("ldr","r4, [pc, #0x28]"),
    0x600552F4:("mov","r6, r1"),
    0x600552FA:("cbnz","r3, #0x60055314"),
    0x6005530A:("str","r6, [r4, #4]"),
    0x60055310:("str","r4, [r5]"),
    0x60055320:("push","{r4, r5, r6, lr}"),
    0x60055322:("ldr","r4, [pc, #0x28]"),
    0x60055324:("mov","r6, r1"),
    0x60055326:("mov","r5, r2"),
    0x6005532E:("bl","#0x60055024"),
    0x6005533A:("str","r6, [r4, #4]"),
    0x60055340:("str","r4, [r5]"),
}
SLICES=((0x60055178,0x6005519C),(0x600552F0,0x6005534C),
        (0x60055070,0x600550C0))
GLOBAL_LIT=0x6005534C


def assert_original_pins(actual):
    for pc,semantics in PINS.items():
        if actual.get(pc)!=semantics:
            raise ValueError("signed phase48 class selector provenance drift "+hex(pc))
    return len(PINS)


def signed_12byte_record_impact(record_addr=BOOT_CLASS10_RAM_RECORD,
                                 instance_before=0,global_base=EP0_LOOKUP_GLOBAL):
    """Pure symbolic model; NEVER a claim about actual executed instructions."""
    return {
        "selected_record_pointer":hex(record_addr),
        "class_record_callback_initial":hex(SIGNED_CLASS10_CALLBACK),
        "runtime_record_second_word_before_class_init":hex(instance_before),
        "if_class10_initializer_receives_R1_record_address":"class10_singleton[+4] = record_addr",
        "if_R2_was_record_plus4":"record[+4] = singleton_addr",
        "then_double_deref_value":"singleton[+4] -> record[+4] -> singleton_addr",
        "can_treat_that_as_signed_Thumb_method":False,
        "conclusion":"insufficient execution/order/object-provenance to resolve indirect method",
    }


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("exact original SHA-256 pinned Bruce required")
    rows={}
    for a,b in SLICES:
        for x in decode(image,a,b):
            rows[x["pc"]]=(x["m"],x["op"])
    pins=assert_original_pins(rows)
    rom=verified_rom_table(image)
    boot=confirmed_boot_records(image)
    if boot[1]["destination_boot_RAM"]!=hex(BOOT_CLASS10_RAM_RECORD) or boot[1]["callback_thumb_word"]!=hex(SIGNED_CLASS10_CALLBACK):
        raise ValueError("original signed boot class10 record changed")
    if rom[3]["record_base"]!=hex(STATIC_TABLE_CLASS10) or rom[3]["method_0"]!="0x60055321" or rom[0]["method_0"]!="0x600552f1":
        raise ValueError("class10 ROM method0 changed")
    glob=raw_word(image,GLOBAL_LIT)
    first=raw_word(image,CLASS1_GLOBAL_LIT)
    lookup=raw_word(image,0x60054FAC)
    cl2=raw_word(image,CLASS2_GLOBAL_LIT)
    cl4=raw_word(image,CLASS4_GLOBAL_LIT)
    if (glob,first,lookup,cl2,cl4)!=(CLASS10_GLOBAL,CLASS1_GLOBAL,EP0_LOOKUP_GLOBAL,CLASS2_GLOBAL,CLASS4_GLOBAL):
        raise ValueError("original signed class global pointers differ from pinned values: "+str((hex(glob),hex(first),hex(lookup),hex(cl2),hex(cl4))))
    return {
        "phase":48,"signed_original_OEM_SHA_verified":True,
        "semantic_pins":pins,
        "shared_usb_configuration_routing":{
            "entry":"0x6005505c",
            "singleton_lookup":"0x60055072 BL 0x60054f7c",
            "shared_config_object":"0x60055086 loads singleton from SP+4; 0x6005508a loads config pointer from singleton+4",
            "config_structure_header":"0x6005508c reads byte at config+8 (count); 0x60055092 reads pointer at config+0 (array)",
            "dynamic_control_method":"0x600d0bf6 loads config object from singleton+4; 0x600d0bf8 loads method pointer from config+4",
            "signed_class_table_selection":"0x60055098 LDR [record+8] -> 0x6005509a LDRB class id +4; compare class 10 in 0x600550a8",
            "table_method8_dispatch":"0x600550ba LDR R3,[ROM record+8]; 0x600550bc BLX R3",
            "live_configuration_methods":"UNMEASURED",
        },
        "class_selector":{
            "candidate_record_source":"0x60055178 LDR R3,[R5,#4]; 0x6005517a LDR R1,[R3]",
            "candidate_record_add_stride12":"0x60055180 ADD R1,R8",
            "class_selector_comparison":"0x60055182 [fp+r7+0x0c] vs 0x60055186 [selected record[+8]+4]",
            "ROM_16byte_selected_method0":"0x6005518c LDR.W R3,[fp+r7] -> 0x60055194 BLX R3",
            "arguments":"R0=R6 USB context, R1=12-byte runtime record pointer, R2=record+4",
            "class10_signed_method0":"0x60055321",
        },
        "distinct_signed_class_singletons":{
            "class_selector_1_method0":"0x600552f1",
            "class_selector_1_initializer_global_literal":"0x6005531c",
            "class_selector_1_singleton":hex(first),
            "class_selector_10_method0":"0x60055321",
            "class_selector_10_initializer_global_literal":hex(GLOBAL_LIT),
            "class_selector_10_singleton":hex(glob),
            "EP0_lookup_literal":"0x60054fac",
            "EP0_lookup_singleton":hex(lookup),
            "EP0_lookup_matches_class_selector_1_singleton":lookup==first,
            "EP0_lookup_matches_class_selector_10_singleton":lookup==glob,
            "EP0_lookup_matches_either_class1_or_class10":lookup in (first,glob),
            "class_selector_2_method0":rom[1]["method_0"],
            "class_selector_2_singleton":hex(cl2),
            "class_selector_4_method0":rom[2]["method_0"],
            "class_selector_4_singleton":hex(cl4),
            "EP0_lookup_distinct_from_all_four_classes":lookup not in (first,glob,cl2,cl4),
            "runtime_selected_class":"UNVERIFIED",
        },
        "class10_initializer":{
            "entry":"0x60055320",
            "singleton_load":"0x60055322 LDR R4,[PC,#0x28]",
            "singleton_literal_at":hex(GLOBAL_LIT),
            "singleton_address":hex(glob),
            "R6_original_R1":"0x60055324 MOV R6,R1",
            "R5_original_R2":"0x60055326 MOV R5,R2",
            "singleton_plus4_store":"0x6005533a STR R6,[R4,#4]",
            "original_record_output_store":"0x60055340 STR R4,[R5]",
        },
        "signed_ROM_class10_methods":{
            "method0_init":rom[3]["method_0"],
            "method4":rom[3]["method_4"],
            "method8_event":rom[3]["method_8"],
            "ROM_table_address":rom[3]["record_base"],
            "not_equivalent_to_live_12byte_record":True,
        },
        "signed_boot_class10_record":boot[1],
        "synthetic_alias_caveat":signed_12byte_record_impact(),
        "live_global_plus4":"UNMEASURED",
        "live_class10_selection":"UNVERIFIED",
        "indirect_method_from_0x600d0bfa":"NOT RESOLVED",
        "EP0_setup_host_control":"UNVERIFIED",
        "HAB_closed_bypass_or_unsigned_execution":"NOT DEMONSTRATED",
        "device_IO":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    arg=p.parse_args()
    result=audit(arg.image.read_bytes())
    if arg.out:arg.out.write_text(json.dumps(result,indent=2)+"\n")
    print("PHASE48 SIGNED CLASS SELECTOR",json.dumps(result["class_selector"]))
    print("PHASE48 SHARED USB CONFIG ROUTING",json.dumps(result["shared_usb_configuration_routing"]))
    print("PHASE48 SIGNED SINGLETON INIT",json.dumps(result["class10_initializer"]))
    print("PHASE48 TWO CLASS SINGLETONS",json.dumps(result["distinct_signed_class_singletons"]))
    print("PHASE48 SIGNED METHOD RECORD VS RUNTIME RECORD",json.dumps(result["signed_ROM_class10_methods"]))
    print("PHASE48 STATIC ALIAS LIMITS",json.dumps(result["synthetic_alias_caveat"]))
    print("PHASE48 LIVE VTABLE: UNVERIFIED; NO HARDWARE ACCESS")

if __name__=="__main__":
    main()
