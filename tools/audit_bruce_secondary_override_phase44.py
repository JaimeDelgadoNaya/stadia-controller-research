"""Phase 44: independently pin the second signed class10 callback/context writer.

Resolve its original XIP literal base and callback value and show the nearby
object provenance. This is read-only static OEM image analysis, not evidence of
host control or the ability to install unsigned firmware.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_init_inbound_phase43 import (
    find_inbound_branches, all_byte_word_references,
)

BASE=ASSUMED_XIP_BASE
PC_BASE=0x600771EE
PC_FUNCTION=0x600771F0
PC_WRITE_FUNCTION=0x600771F6
PC_WRITE_CONTEXT=0x600771FC
PC_NEXT=0x600771FE
GLOBAL=0x200064C0
OFFSET_FUNCTION=0x3A38
OFFSET_CONTEXT=0x3A3C

PINS={
    0x600771EE:("ldr","r3, [pc, #0xf4]"),
    0x600771F0:("ldr","r1, [pc, #0xf4]"),
    0x600771F2:("movw","r2, #0x3a38"),
    0x600771F6:("str","r1, [r3, r2]"),
    0x600771F8:("movw","r2, #0x3a3c"),
    0x600771FC:("str","r4, [r3, r2]"),
    0x600771FE:("bl","#0x600776f8"),
}


def check_pins(insns):
    for addr,exp in PINS.items():
        if insns.get(addr)!=exp:
            raise ValueError("Original signed second-callback writer instruction drift "+hex(addr))
    return True


def literal_pc(instruction_pc, disp):
    return ((instruction_pc+4)&~3)+disp


def read_u32(image,addr):
    if addr<BASE or addr+4>BASE+len(image):
        raise ValueError("outside signed update file")
    return struct.unpack_from("<I",image,addr-BASE)[0]


def inspect_second_writer(image):
    rows=decode(image,0x600771D8,0x6007720A)
    check_pins({x["pc"]:(x["m"],x["op"]) for x in rows})
    base_literal_addr=literal_pc(PC_BASE,0xF4)
    fn_literal_addr=literal_pc(PC_FUNCTION,0xF4)
    if (base_literal_addr,fn_literal_addr)!=(0x600772E4,0x600772E8):
        raise ValueError("Original literal addressing unexpectedly changed")
    base=read_u32(image,base_literal_addr)
    function=read_u32(image,fn_literal_addr)
    known_base=base==GLOBAL
    return {
        "setter_sites":{
            "callback_store":hex(PC_WRITE_FUNCTION),
            "context_store":hex(PC_WRITE_CONTEXT)
        },
        "signed_semantic_pins":len(PINS),
        "global_base_literal": {"load_at":hex(PC_BASE),"literal_at":hex(base_literal_addr),"value":hex(base)},
        "callback_value_literal": {"load_at":hex(PC_FUNCTION),"literal_at":hex(fn_literal_addr),"value":hex(function),
            "looks_signed_XIP_thumb":bool(function&1) and BASE <= (function&~1) < BASE+0xFF000},
        "base_equals_class10_global":known_base,
        "callback_slot_if_executed":hex(base+OFFSET_FUNCTION),
        "context_slot_if_executed":hex(base+OFFSET_CONTEXT),
        "context_stored_from_register":"r4",
        "register_r4_provenance":"NOT YET TRACED",
        "runtime_reachable":"NOT VERIFIED",
        "USB_host_controls_callback":"NOT VERIFIED",
    }


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("exact original Bruce OEM SHA-256 required")
    writer=inspect_second_writer(image)
    callback=writer["callback_value_literal"]["value"]
    func=int(callback,16)&~1
    # Context larger than one basic block intentionally printed as candidate
    # linear decode only; do not infer path reachability or entry arguments.
    near=decode(image,0x600770E0,0x6007720A)
    literal_window=[
        {"PC":hex(pc),"word":hex(read_u32(image,pc))}
        for pc in range(0x600772D0,0x60077310,4)
    ]
    return {
        "phase":44,"signed_oem_exact_sha_verified":True,
        "second_writer":writer,
        "later_writer_local_decode":[
            hex(x["pc"])+" "+x["m"]+" "+x["op"] for x in near
        ],
        "original_literal_pool_neighborhood":literal_window,
        "original_callback_target_preview":[
            hex(x["pc"])+" "+x["m"]+" "+x["op"]
            for x in decode(image,func,min(func+0x60,BASE+0xFF000))
        ] if writer["callback_value_literal"]["looks_signed_XIP_thumb"] else [],
        "callback_function_ref_count":all_byte_word_references(image,int(callback,16)),
        "second_writer_outgoing_callee":hex(0x600776F8),
        "direct_inbound_to_after_writer_callee":find_inbound_branches(image,only_target=0x600776F8),
        "installed_device_RAM_unmeasured":True,
        "host_controlled_callback_not_demonstrated":True,
        "physical_controller_touched":False,"flash_written":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    arg=p.parse_args()
    x=audit(arg.image.read_bytes())
    if arg.out:arg.out.write_text(json.dumps(x,indent=2)+"\n")
    print("PHASE44 SECONDARY WRITER LITERALS",json.dumps(x["second_writer"]))
    print("PHASE44 SECONDARY WRITER PRIOR CODE",json.dumps(x["later_writer_local_decode"]))
    print("PHASE44 SECONDARY WRITER CALLBACK TARGET",json.dumps(x["original_callback_target_preview"]))
    print("PHASE44 SECONDARY WRITER LITERAL POOL",json.dumps(x["original_literal_pool_neighborhood"]))

if __name__=="__main__":
    main()
