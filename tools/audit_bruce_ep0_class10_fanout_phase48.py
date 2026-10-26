"""Phase48: signed EP0 event-1 -> common class-aware fanout -> class10 candidate.

This corrects the misleading shortcut that equates 0x600D0BFA's dynamic
config-object method with the signed class10 ROM method. Instead the original
EP0 callback itself conditionally calls 0x6005505C with internal event R1=1.
That function validates per-configuration runtime 12-byte records and
dispatches through signed 16-byte class ROM table method +8. Class10 can be
selected only if the *runtime* class record list includes selector 10.
All proofs are code/data from exact signed OEM Bruce update, not physical USB.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_class_selector_verified import verified_rom_table,ROM_TABLE_BASE
from tools.audit_bruce_ep0_class_object_phase48 import raw_word
from tools.audit_bruce_class_singleton_phase48 import audit as audit_singletons

CLASS_FANOUT=0x6005505C
SIGNED_ROM_LOAD=0x60055082
SIGNED_ROM_WORD_AT=0x600550E0
EP0_SIGNED_HANDLER=0x60054D74
EVENT1_EP0_SITES=[(0x60054E08,0x60054E1A),(0x60054E5A,0x60054E6A)]
PINS={
    0x60054E08:("movs","r1, #1"),
    0x60054E1A:("bl","#0x6005505c"),
    0x60054E5A:("movs","r1, #1"),
    0x60054E6A:("bl","#0x6005505c"),
    0x6005505C:("push.w","{r0, r1, r2, r4, r5, r6, r7, r8, sb, lr}"),
    0x60055060:("mov","r7, r1"),
    0x60055062:("mov","r6, r2"),
    0x60055072:("bl","#0x60054f7c"),
    0x60055082:("ldr.w","sb, [pc, #0x5c]"),
    0x6005508A:("ldr","r3, [r3, #4]"),
    0x6005508C:("ldrb","r2, [r3, #8]"),
    0x60055092:("ldr","r3, [r3]"),
    0x60055094:("mla","r0, r8, r0, r3"),
    0x60055098:("ldr","r3, [r0, #8]"),
    0x6005509A:("ldrb","r3, [r3, #4]"),
    0x600550A8:("cmp","r3, #0xa"),
    0x600550B0:("add.w","r3, sb, r3, lsl #4"),
    0x600550B4:("mov","r2, r6"),
    0x600550B6:("mov","r1, r7"),
    0x600550B8:("ldr","r0, [r0, #4]"),
    0x600550BA:("ldr","r3, [r3, #8]"),
    0x600550BC:("blx","r3"),
    0x600550D8:("movs","r3, #3"),
    0x600550DA:("b","#0x600550b0"),
}


def verify_pins(seen):
    for pc,expected in PINS.items():
        if seen.get(pc)!=expected:
            raise ValueError("Signed EP0 event1 class fanout drift at "+hex(pc))
    return len(PINS)


def conditional_class10(event,selectors,*,runtime_config_known=False):
    """Pure logic gate, NEVER executes firmware or USB request."""
    if event!=1:
        return {"stage":"not_event1","class10_method8":None}
    if not runtime_config_known:
        return {"stage":"runtime_class_config_unmeasured","class10_method8":None}
    if 10 not in selectors:
        return {"stage":"class10_not_in_configuration","class10_method8":None}
    return {"stage":"conditionally_class10_event_method8","class10_method8":"0x600d0e59"}


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("requires exact original SHA-256 signed Bruce update")
    initial=audit_singletons(image)
    seen={}
    for a,b in ((0x60054E08,0x60054E1C),(0x60054E5A,0x60054E6C),
                (0x6005505C,0x600550BE),(0x600550D8,0x600550DC)):
        seen.update({x["pc"]:(x["m"],x["op"]) for x in decode(image,a,b)})
    n=verify_pins(seen)
    signed_rom_ptr=raw_word(image,SIGNED_ROM_WORD_AT)
    if signed_rom_ptr!=ROM_TABLE_BASE:
        raise ValueError("Signed class fanout ROM method table literal mismatch "+hex(signed_rom_ptr))
    records=verified_rom_table(image)
    if records[3]["selector_at_plus_0xc"]!=10 or records[3]["method_8"]!="0x600d0e59":
        raise ValueError("Original class10 method8 changed")
    if not initial["distinct_signed_class_singletons"]["EP0_lookup_distinct_from_all_four_classes"]:
        raise ValueError("EP0 core/global no longer distinct from class objects")
    return {
        "phase":48,"signed_original_OEM_SHA_verified":True,
        "signed_semantic_pins":n,
        "EP0_original_handler":"0x60054d74",
        "EP0_internal_event1_routers":[{"set_R1":hex(a),"call":hex(b)}
                                       for a,b in EVENT1_EP0_SITES],
        "common_class_fanout":{
            "entry":"0x6005505c",
            "lookup_shared_USB_global":"0x60055072 BL 0x60054f7c returns 0x20004080 if USB pointer matches",
            "signed_ROM_method_table_literal":hex(SIGNED_ROM_WORD_AT),
            "signed_ROM_method_table_address":hex(signed_rom_ptr),
            "runtime_config_from_shared_global":"0x6005508a load [USB_core_global+4]",
            "config_record_count_byte":"0x6005508c LDRB [config+8]",
            "runtime_record_table_pointer":"0x60055092 LDR [config+0]",
            "runtime_record_stride_bytes":12,
            "runtime_record_class_selector":"[record+8]+4 byte (0x60055098..9a)",
            "explicit_compare_class10":"0x600550a8 CMP R3,#0x0a",
            "class10_ROM_record_index":3,
            "class10_method8_thumb":records[3]["method_8"],
            "per_class_method8_call":"0x600550ba LDR [ROM_record+8] -> 0x600550bc BLX R3",
            "event_arg_forwarded_unchanged":"0x60055060 R7=R1 -> 0x600550b6 MOV R1,R7",
            "payload_arg_forwarded":"0x60055062 R6=R2 -> 0x600550b4 MOV R2,R6",
        },
        "conditional_examples":[
            {"scenario":"live config unknown","result":conditional_class10(1,[],runtime_config_known=False)},
            {"scenario":"class10 missing","result":conditional_class10(1,[1,2,4],runtime_config_known=True)},
            {"scenario":"class10 record present (hypothetical)","result":conditional_class10(1,[1,2,4,10],runtime_config_known=True)},
        ],
        "real_EP0_to_class10":{"status":"CONDITIONAL IN SIGNED CODE; LIVE CLASS CONFIG UNVERIFIED",
                               "USB_setup_to_event1_real_delivery":"UNMEASURED",
                               "class10_signed_secondary_handler_active":"UNMEASURED"},
        "host_controlled_arbitrary_memory":"NOT DEMONSTRATED",
        "unsigned_code_or_HAB_bypass":"NOT DEMONSTRATED",
        "physical_USB_or_flash_access":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    data=audit(a.image.read_bytes())
    if a.out:a.out.write_text(json.dumps(data,indent=2)+"\n")
    print("PHASE48 EP0 EVENT1 CLASS FANOUT",json.dumps(data["common_class_fanout"]))
    print("PHASE48 EP0 EVENT1 CALLS",json.dumps(data["EP0_internal_event1_routers"]))
    print("PHASE48 SYNTHETIC CLASS10 ROUTE",json.dumps(data["conditional_examples"]))
    print("PHASE48 ACTUAL EP0 CLASS10 USB ROUTE: UNVERIFIED; NO HARDWARE I/O")
if __name__=="__main__":
    main()
