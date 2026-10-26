"""Trace the R1 argument supplied to Bruce OEM class 10 initializer.

Strict signed-image SHA, static Thumb semantics, direct XIP calls only. The
pointer is an application-created configuration-entry address, *not* a raw
USB SETUP bRequest-derived jump address. Final callback contents and actual
EP0 reachability remain unproven. No physical device interface.
"""
import argparse
import hashlib
import json
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256
from tools.audit_bruce_ep0_registration import decode, callers_of_known
from tools.audit_bruce_class_selector_verified import verified_rom_table

# Pinned instructions read directly from the exact original signed image.
R1_PROVENANCE_PINS = {
    0x600550E8: ("mov", "r6, r0"),
    0x600550EA: ("mov", "r4, r1"),
    0x600550EC: ("mov", "sl, r2"),
    0x600550F2: ("cmp", "r1, #0"),
    0x600550F6: ("ldr", "r3, [r1, #4]"),
    0x6005510C: ("mov", "r5, r3"),
    0x6005512E: ("str", "r4, [r5, #4]"),
    0x60055142: ("ldr.w", "fp, [pc, #0x70]"),
    0x60055170: ("movs", "r3, #0xc"),
    0x60055174: ("mul", "r8, r3, r8"),
    0x60055178: ("ldr", "r3, [r5, #4]"),
    0x6005517A: ("ldr", "r1, [r3]"),
    0x6005517C: ("add.w", "r3, fp, r7"),
    0x60055180: ("add", "r1, r8"),
    0x60055182: ("ldrb", "r3, [r3, #0xc]"),
    0x60055184: ("ldr", "r2, [r1, #8]"),
    0x60055186: ("ldrb", "r2, [r2, #4]"),
    0x60055188: ("cmp", "r2, r3"),
    0x6005518A: ("bne", "#0x60055196"),
    0x6005518C: ("ldr.w", "r3, [r7, fp]"),
    0x60055190: ("adds", "r2, r1, #4"),
    0x60055192: ("mov", "r0, r6"),
    0x60055194: ("blx", "r3"),
    0x60055320: ("push", "{r4, r5, r6, lr}"),
    0x60055324: ("mov", "r6, r1"),
    0x60055326: ("mov", "r5, r2"),
    0x6005533A: ("str", "r6, [r4, #4]"),
    0x60055340: ("str", "r4, [r5]"),
    0x600D0EB6: ("ldr", "r3, [r0, #4]"),
    0x600D0EB8: ("ldrb", "r1, [r1, #1]"),
    0x600D0EBA: ("ldr", "r3, [r3]"),
    0x600D0EBE: ("bx", "r3"),
}

def check_r1_pins(rows):
    for pc, expected in R1_PROVENANCE_PINS.items():
        if rows.get(pc) != expected:
            raise ValueError("Signed R1 origin semantic drift at %s; actual=%r" % (hex(pc), rows.get(pc)))
    return True

def origin_equation(index, base):
    if index < 0 or index >= 256:
        raise ValueError("invalid synthetic class-interface index")
    return base + index * 12

def literal_pointer_census(image):
    """Aligned 32-bit pointer shapes; presence is NOT caller reachability."""
    import struct
    wanted={
        "config_class_selector_callback":0x600550E5,
        "class10_init_method":0x60055321,
        "class10_event_forwarder":0x600D0E59,
        "class10_global_ram_address":0x200040E0,
        "class_configuration_ram_address":0x20004080,
    }
    results={}
    for name,ptr in wanted.items():
        packed=struct.pack("<I",ptr)
        hits=[off for off in range(0,0xFF030-3,4)
              if image[off:off+4]==packed]
        results[name]={"pointer":hex(ptr),
                       "aligned_source_offsets":[hex(o) for o in hits[:45]],
                       "count":len(hits),
                       "function_was_executed":False}
    return results


def audit(image, *, direct_call_samples=16):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Exactly pinned original signed Bruce image required")
    rows={}
    for a,b in [(0x600550E8,0x6005510E),
                (0x60055128,0x6005514A),
                (0x60055170,0x60055196),
                (0x60055320,0x60055342),
                (0x600D0EB6,0x600D0EC0)]:
        rows.update({ins["pc"]:(ins["m"],ins["op"]) for ins in decode(image,a,b)})
    check_r1_pins(rows)
    rom=verified_rom_table(image)
    assert rom[3]["selector_at_plus_0xc"]==10
    assert rom[3]["method_0"]=="0x60055321"

    # Direct XIP callers are candidates, not full CFG proof; a callback through
    # BLX is not a direct BL and must be recovered from the class selection.
    direct=callers_of_known(image,{
        "configure_class_dispatch":0x600550E4,
        "class10_init_method":0x60055320,
        "class_global_object_helper":0x60055024,
        "class_configure_global_object":0x60055350,
    },max_examples=direct_call_samples)
    return {
        "original_signed_sha256":IMAGE_SHA256,
        "original_image_pinned":True,
        "semantic_pins_verified":len(R1_PROVENANCE_PINS),
        "class_id":10,
        "class10_registration_entry":"0x60104ba4",
        "class10_method0_thumb":"0x60055321",
        "class10_registration_method":"0x60055320",
        "dataflow_chain":[
            {"pc":"0x600550ea","evidence":"R4 = initial function argument R1"},
            {"pc":"0x6005512e","evidence":"global state [R5+4] = R4 (initial argument R1), conditional startup branch"},
            {"pc":"0x60055178","evidence":"R3 = [R5+4]"},
            {"pc":"0x6005517a","evidence":"R1 = [R3], base of caller-owned interface callback/descriptor records"},
            {"pc":"0x60055174","evidence":"R8 = 12*interface index"},
            {"pc":"0x60055180","evidence":"R1 += R8; points to a 12-byte record"},
            {"pc":"0x60055184","evidence":"R2 = [R1+8] descriptor pointer"},
            {"pc":"0x60055186","evidence":"R2 = byte([R2+4]), class ID from descriptor"},
            {"pc":"0x60055182","evidence":"R3 = selector at registry record+12"},
            {"pc":"0x60055188","evidence":"class ID compared to registry selector before indirect call"},
            {"pc":"0x60055190","evidence":"R2 = R1+4, output pointer for initialized class object"},
            {"pc":"0x60055194","evidence":"BLX first method from registry: class10=>0x60055320"},
            {"pc":"0x60055324","evidence":"R6 = received R1"},
            {"pc":"0x6005533a","evidence":"global class object +4 = R6, preserved record pointer"},
            {"pc":"0x600d0eb6","evidence":"later class event loads record pointer from class object+4"},
            {"pc":"0x600d0eba","evidence":"later event dereferences [record], potentially callback word"},
            {"pc":"0x600d0ebe","evidence":"conditional BX to function loaded from record"},
        ],
        "indirect_bridge_is_conditional":True,
        "configuration_record_first_word_contents":"UNRESOLVED; must track caller of 0x600550e4, or record producer",
        "record_layout_hypothesis":{"size_bytes":12,
            "offset_0":"callback function pointer? (unverified producer)",
            "offset_4":"class global object pointer written by initializer",
            "offset_8":"interface descriptor pointer (verified reads)",
        },
        "aligned_function_pointer_census":literal_pointer_census(image),
        "known_global_RAM_base_from_selector_literal":"0x20004080",
        "known_class10_global_RAM_from_initializer_literal":"0x200040e0",
        "direct_caller_census":{
            name:[{"callsite":x["callsite"],"preceding":x["before"]}
                  if "before" in x else x for x in examples]
            for name,examples in direct.items()},
        "host_can_set_callback_pointer":"NOT DEMONSTRATED",
        "real_controller_activated_class10":"NOT MEASURED",
        "physical_usb_requests_81_83_84_reachability":"NOT MEASURED",
        "signed_boot_bypass_or_custom_execution":"NOT DEMONSTRATED",
        "firmware_written":False,
        "physical_USB_used":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    result=audit(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print("R1 signed semantic anchors",result["semantic_pins_verified"])
    print("CLASS 10 RECORD POINTER FORMULA",result["record_layout_hypothesis"])
    print("ALIGNED XIP POINTER WORDS",json.dumps(result["aligned_function_pointer_census"]))
    print("DIRECT XIP CALLER SITES",json.dumps({
      k:[entry["callsite"] for entry in v]
      for k,v in result["direct_caller_census"].items()}))
    print("USER-CHOSEN CALLBACK POINTER:",result["host_can_set_callback_pointer"])
    print("REAL USB AND FLASH OPERATIONS: NONE")

if __name__=="__main__":
    main()
