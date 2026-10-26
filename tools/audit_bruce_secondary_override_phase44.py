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
from tools.audit_app_usb_dispatch import DATA_SOURCE_OFFSET, DATA_DESTINATION, DATA_END
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



CALLER_PINS={
    0x60051240:("push.w","{r4, r5, r6, r7, r8, lr}"),
    0x60051248:("bl","#0x60077138"),
    0x6005124C:("bl","#0x60077140"),
}
GETTER_PINS={
    0x60077138:("ldr","r0, [pc, #0]"),
    0x6007713A:("bx","lr"),
}

def verify_signed_second_setter_caller(image):
    code=decode(image,0x60051240,0x60051258)
    getter=decode(image,0x60077138,0x6007713C)
    pairs={row["pc"]:(row["m"],row["op"]) for row in code+getter}
    for pc,required in {**CALLER_PINS,**GETTER_PINS}.items():
        if pairs.get(pc)!=required:
            raise ValueError("Original signed second setter call/getter drift at "+hex(pc))
    returned_object=read_u32(image,0x6007713C)
    if not 0x20000000 <= returned_object < 0x21000000:
        raise ValueError("Original object getter no longer returns RAM pointer")
    return {
        "signed_caller_pc":"0x60051240",
        "getter_called_at":"0x60051248",
        "getter_code":"0x60077138 LDR R0,[PC,#0]; 0x6007713A BX LR",
        "getter_signed_literal_at":"0x6007713c",
        "getter_returns_RAM_object":hex(returned_object),
        "setter_called_at":"0x6005124c",
        "setter_function":"0x60077140",
        "R0_argument_to_setter":hex(returned_object),
        "R4_context_written_by_setter":hex(returned_object),
        "signed_instruction_pins":len(CALLER_PINS)+len(GETTER_PINS),
        "actual_call_executed_on_device":"NOT MEASURED",
        "host_controls_object_pointer":"NOT DEMONSTRATED",
    }


HANDLER_BRANCH_PINS={
    0x60077360:("subs","r1, #0x80"),
    0x6007736A:("cmp","r1, #0xc"),
    0x6007736C:("bhi.w","#0x600774ae"),
    0x60077370:("tbb","[pc, r1]"),
}
TBB_PC=0x60077370
TBB_BASE=TBB_PC+4

def audit_handler_table(image):
    # TBB PC-relative byte table; Thumb target = PC+4 + 2*byte.
    code=decode(image,0x60077360,0x60077374)
    ins={q["pc"]:(q["m"],q["op"]) for q in code}
    for pc,expected in HANDLER_BRANCH_PINS.items():
        if ins.get(pc)!=expected:
            raise ValueError("Original signed callback dispatch guard drift at "+hex(pc))
    raw=image[TBB_BASE-BASE:TBB_BASE-BASE+13]
    if len(raw)!=13:
        raise ValueError("truncated OEM handler dispatch table")
    routes=[]
    for n,offset in enumerate(raw):
        dest=TBB_BASE+2*offset
        preview=decode(image,dest,dest+0x12)
        routes.append({
            "r1_candidate_code":hex(0x80+n),
            "table_index":n,
            "raw_signed_tbb_byte":offset,
            "branch_target":hex(dest),
            "target_in_signed_XIP":BASE<=dest<BASE+0xFF000,
            "linear_preview":[hex(i["pc"])+" "+i["m"]+" "+i["op"] for i in preview[:5]],
            "EP0_request_route_proven":False,
        })
    return {
        "signed_pins_verified":len(HANDLER_BRANCH_PINS),
        "signed_callback_thumb":"0x600db029",
        "signed_callback_branch":"0x600db028 B.W 0x60077360",
        "handler_entry":"0x60077360",
        "required_r1_range_if_called":"0x80 through 0x8c inclusive",
        "out_of_range_target":"0x600774ae",
        "table_file_offset":hex(TBB_BASE-BASE),
        "dispatches":routes,
        "external_request_origin_unverified":True,
    }

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("exact original Bruce OEM SHA-256 required")
    writer=inspect_second_writer(image)
    caller=verify_signed_second_setter_caller(image)
    handler=audit_handler_table(image)
    object_ram=int(caller["getter_returns_RAM_object"],16)
    if not DATA_DESTINATION <= object_ram < DATA_END:
        raise ValueError("Original second callback context object outside signed data copy")
    object_file_off=DATA_SOURCE_OFFSET + object_ram - DATA_DESTINATION
    object_words=[{"ram_address":hex(object_ram+4*i),
                   "file_offset":hex(object_file_off+4*i),
                   "initial_signed_copy_word":hex(struct.unpack_from("<I",image,object_file_off+4*i)[0])}
                  for i in range(12)]
    callback=writer["callback_value_literal"]["value"]
    func=int(callback,16)&~1
    # Context larger than one basic block intentionally printed as candidate
    # linear decode only; do not infer path reachability or entry arguments.
    full=decode(image,0x60077140,0x6007720A)
    trusted_fn={q["pc"]:(q["m"],q["op"]) for q in full}
    origin_pins={
        0x60077140:("ldr","r3, [pc, #0x180]"),
        0x60077142:("push","{r0, r1, r2, r4, r5, lr}"),
        0x60077144:("mov","r4, r0"),
        0x6007715A:("bne.w","#0x6007727c"),
        0x60077168:("bne","#0x6007720a"),
        0x600771AE:("add.w","r0, r4, #0xc"),
        0x600771F6:("str","r1, [r3, r2]"),
        0x600771FC:("str","r4, [r3, r2]"),
    }
    for pc,expected in origin_pins.items():
        if trusted_fn.get(pc)!=expected:
            raise ValueError("Original signed callback context origin anchor drift "+hex(pc))
    if trusted_fn.get(PC_WRITE_FUNCTION)!=("str","r1, [r3, r2]"):
        raise ValueError("Original signed setter lost sync in entry-anchored function")
    target_instruction_in_decoder=(0x600771F6 in trusted_fn and 0x600771FC in trusted_fn)
    # Do not cross a code/data island when attributing instruction provenance.
    if not target_instruction_in_decoder:
        raise ValueError("Original signed entry-anchored function lost setter alignment")
    near=decode(image,0x600771D8,0x6007720A)
    focus=[
        {
            "window_start":hex(lo),
            "window_end_exclusive":hex(hi),
            "linear_decode_only":True,
            "instructions":[hex(q["pc"])+" "+q["m"]+" "+q["op"]
                            for q in decode(image,lo,hi)]
        }
        for lo,hi in (
            (0x60077000,0x6007706C),
            (0x6007706C,0x600770D8),
            (0x600770D8,0x60077144),
            (0x60077144,0x600771B0),
            (0x600771B0,0x60077210),
            (0x60077360,0x600773E0),
        )
    ]
    literal_window=[
        {"PC":hex(pc),"word":hex(read_u32(image,pc))}
        for pc in range(0x600772D0,0x60077310,4)
    ]
    return {
        "phase":44,"signed_oem_exact_sha_verified":True,
        "second_writer":writer,
        "second_writer_signed_getter_caller":caller,
        "installed_OEM_callback_handler":handler,
        "signed_boot_data_copy_object":{
            "destination_ram":hex(object_ram),
            "source_file_offset":hex(object_file_off),
            "initial_12_word_snapshot":object_words,
            "not_a_runtime_readback":True,
        },
        "caller_inbound_branch_candidates":find_inbound_branches(image,only_target=0x60051240),
        "caller_ptr_literal_refs":all_byte_word_references(image,0x60051241),
        "candidate_signed_object_initializer_entry":"0x60077140",
        "candidate_r4_origin_at":"0x60077144 MOV R4,R0",
        "context_r4_source":"function input R0 at 0x60077140, preserved in R4",
        "context_origin_semantic_pins":len(origin_pins),
        "candidate_entry_has_early_branch_gates":["0x6007715a","0x60077168"],
        "direct_call_candidates_to_object_initializer":find_inbound_branches(image,only_target=0x60077140),
        "original_thumb_function_pointer_refs":all_byte_word_references(image,0x60077141),
        "entry_anchored_function_decode":[hex(q["pc"])+" "+q["m"]+" "+q["op"] for q in full],
        "potential_context_r4_origin_windows":focus,
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
    print("PHASE44 SIGNED SECOND SETTER CALL CHAIN",json.dumps(x["second_writer_signed_getter_caller"]))
    print("PHASE44 SIGNED OBJECT BOOT COPY",json.dumps(x["signed_boot_data_copy_object"]))
    print("PHASE44 INSTALLED OEM HANDLER DISPATCH",json.dumps(x["installed_OEM_callback_handler"]))
    print("PHASE44 SECOND SETTER WRAPPER INBOUND",json.dumps(x["caller_inbound_branch_candidates"]))
    print("PHASE44 SECONDARY WRITER PRIOR CODE",json.dumps(x["later_writer_local_decode"]))
    print("PHASE44 SECONDARY WRITER ENTRY ANCHORED",json.dumps(x["entry_anchored_function_decode"]))
    print("PHASE44 SECONDARY WRITER INBOUND",json.dumps(x["direct_call_candidates_to_object_initializer"]))
    print("PHASE44 SECONDARY WRITER POINTER REFS",json.dumps(x["original_thumb_function_pointer_refs"]))
    for window in x["potential_context_r4_origin_windows"]:
        print("PHASE44 SECONDARY WRITER R4 ORIGIN",json.dumps(window))
    print("PHASE44 SECONDARY WRITER CALLBACK TARGET",json.dumps(x["original_callback_target_preview"]))
    print("PHASE44 SECONDARY WRITER LITERAL POOL",json.dumps(x["original_literal_pool_neighborhood"]))

if __name__=="__main__":
    main()
