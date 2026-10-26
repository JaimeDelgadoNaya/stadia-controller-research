"""Phase 58: bounded signed Bruce field+0x80 consumer and callee inspection.

No hardware IO. Inspect original SHA-pinned signed application code paths,
their argument setup, and the apparent helper 0x600D54B8. Distinguish
directly verifiable instruction flow from runtime pointer values.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import (
    IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE, decode_thumb_bl_target,
)
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_parent_consumer_phase57 import verify_global_chain, READ_PINS
from tools.audit_bruce_parent_r0_phase56 import itcm_rows
from tools.audit_app_usb_dispatch import ITCM_LENGTH

BASE=ASSUMED_XIP_BASE
HELPER=0x600D54B8
CALLS=(0x6007E7FA,0x6007E81E)
HELPER_PINS={
    0x600D54B8:("sub","sp, #8"),
    0x600D54BA:("mov","r3, sp"),
    0x600D54BC:("stm.w","r3, {r1, r2}"),
    0x600D54C0:("ldm.w","r3, {r0, r1}"),
    0x600D54C4:("add","sp, #8"),
    0x600D54C6:("b.w","#0x6006386c"),
}
BACKEND=0x6006386C
BACKEND_PINS={
    0x6006386C:("sub","sp, #8"),
    0x6006386E:("add","r3, sp, #8"),
    0x60063870:("stmdb","r3, {r0, r1}"),
    0x60063874:("ldr","r3, [pc, #0x10]"),
    0x60063876:("ldr","r2, [sp]"),
    0x60063878:("str.w","r2, [r3, #0x37c]"),
    0x6006387C:("ldr","r2, [sp, #4]"),
    0x6006387E:("str.w","r2, [r3, #0x380]"),
    0x60063882:("add","sp, #8"),
    0x60063884:("bx","lr"),
}


def signed_word(image,address):
    off=address-BASE
    if address%4 or off<0 or off+4>len(image):
        raise ValueError("phase58 unaligned/outside signed XIP literal")
    return struct.unpack_from("<I",image,off)[0]


def classify_signed_thumb_code_pointer(value):
    """Classification, NOT proof that stored function pointer is invoked."""
    if not value&1:
        return "NOT_THUMB_CODE_POINTER"
    pc=value&~1
    if BASE<=pc<BASE+0xFF000:
        return "SIGNED_XIP_CODE_CANDIDATE"
    if 0<=pc<ITCM_LENGTH:
        return "SIGNED_STARTUP_RELOCATED_ITCM_CODE_CANDIDATE"
    return "OUTSIDE_SIGNED_IMAGE_OR_RELOCATED_ITCM"


def signed_function_preview(image,raw_ptr):
    kind=classify_signed_thumb_code_pointer(raw_ptr)
    pc=raw_ptr&~1
    if kind=="SIGNED_XIP_CODE_CANDIDATE":
        code=decode(image,pc,pc+0x50)
        return {"kind":kind,"runtime_pc":hex(pc),
                "source_file_offset":hex(pc-BASE),
                "code":[{"pc":hex(r["pc"]),"m":r["m"],"op":r["op"]}
                        for r in code[:22]]}
    if kind=="SIGNED_STARTUP_RELOCATED_ITCM_CODE_CANDIDATE":
        code=itcm_rows(image,pc,0x50)
        return {"kind":kind,"runtime_pc":hex(pc),
                "source_file_offset":hex(0x81C+pc),
                "code":code[:22]}
    return {"kind":kind,"runtime_pc":hex(pc),"code":[]}


def verify_signed_callback_entries(image,first,second):
    """Validate actual original Thumb entry instructions; no live invocation."""
    if first!=0x600CE233 or second!=0x0000A9C5:
        raise ValueError("phase58 original signed callback-like pointer literal drift")
    x=decode(image,0x600CE232,0x600CE234)
    y=itcm_rows(image,0xA9C4,4)
    if (len(x),len(y))!=(1,1) or (x[0]["m"],x[0]["op"])!=("bx","lr") or (
        y[0]["m"],y[0]["op"])!=("b.w","#0xb980"):
        raise ValueError("phase58 signed callback entry instructions drift")
    return {
        "entry_one":"0x600ce232 BX LR (no-op return)",
        "entry_two":"0xa9c4 B.W 0xb980 (ITCM function tail branch)",
        "second_target_preview":itcm_rows(image,0xB980,0x90)[:36],
        "callback_registered_or_executed":"UNVERIFIED",
        "USB_source":"UNVERIFIED",
    }


def backend_pair_provenance(image):
    rows=decode(image,BACKEND,0x60063886)
    result={r["pc"]:(r["m"],r["op"]) for r in rows}
    for pc,ins in BACKEND_PINS.items():
        if result.get(pc)!=ins:
            raise ValueError(f"phase58 original backend pin drift {pc:#x}: {result.get(pc)!r}")
    literal_at=((0x60063874+4)&~3)+0x10
    base=signed_word(image,literal_at)
    if not 0x20000000<=base<0x20040000:
        raise ValueError("phase58 backend global base not within expected SRAM")
    first=signed_word(image,((0x6007E7E8+4)&~3)+0x38)
    second=signed_word(image,((0x6007E80E+4)&~3)+0x18)
    entries=verify_signed_callback_entries(image,first,second)
    return {
        "original_pins":len(BACKEND_PINS),
        "global_base_literal_address":hex(literal_at),
        "global_base":hex(base),
        "first_word_destination":hex(base+0x37C),
        "second_word_destination":hex(base+0x380),
        "backend_input_R0":"original helper R1 (literal from caller)",
        "backend_input_R1":"original helper R2 (0 or object R4 in two branches)",
        "branch_one_literal_word":hex(first),
        "branch_one_function_preview":signed_function_preview(image,first),
        "branch_one_second_word":"0 (0x6007E7F0/0x6007E7F2)",
        "branch_two_literal_word":hex(second),
        "verified_signed_entries":entries,
        "branch_two_function_preview":signed_function_preview(image,second),
        "branch_two_second_word":"caller R4 object pointer (0x6007E814 STRD R3,R4)",
        "runtime_values_or_invocation":"UNMEASURED",
        "semantic_classification":"SIGNED_PAIR_GLOBAL_STORE; USB_CALLBACK_NOT_PROVEN",
    }


WINDOWS={
    "caller_branch_one":(0x6007E7D6,0x6007E800),
    "caller_branch_two":(0x6007E80E,0x6007E824),
    "helper_entry":(0x600D54B8,0x600D5540),
    "backend":(0x6006386C,0x60063910),
    "nearby_backends":(0x6006384C,0x6006389A),
    "neighbor_helper":(0x600D54F2,0x600D5550),
    "other_related":(0x600D543C,0x600D54C0),
}


def signed_windows(image,windows=WINDOWS):
    return {name:[{"pc":hex(r["pc"]),"m":r["m"],"op":r["op"]}
                  for r in decode(image,start,end)]
            for name,(start,end) in windows.items()}


def pinpoint(image,pc):
    rows=decode(image,pc,pc+4)
    if len(rows)!=1:
        raise ValueError(f"phase58 cannot decode exact call at {pc:#x}")
    return rows[0]


def call_sites(image,target=HELPER):
    """Candidate static Thumb BL sites; no claim all are executable code."""
    out=[]
    for off in range(0xC800,0xFF000,2):
        try: computed=decode_thumb_bl_target(image,off)
        except ValueError: continue
        if computed==target:
            out.append(hex(BASE+off))
    return out


def literal_refs(image,target=HELPER):
    out=[]
    for off in range(0,len(image)-3,4):
        ptr=struct.unpack_from("<I",image,off)[0]
        if (ptr&~1)==target:
            out.append({"offset":hex(off),"raw":hex(ptr)})
    return out


def modeled_helper_forward(r0,r1,r2):
    """The original R0 is overwritten by original R1 before tail branch."""
    return {"backend_r0":r1,"backend_r1":r2,"backend_r2":r2,
            "incoming_r0_forwarded_directly":False}


def verify_helper_pins(image):
    rows=decode(image,HELPER,0x600D54CA)
    decoded={r["pc"]:(r["m"],r["op"]) for r in rows}
    for pc,expect in HELPER_PINS.items():
        if decoded.get(pc)!=expect:
            raise ValueError(f"phase58 signed helper anchor drift {pc:#x}: {decoded.get(pc)!r}")
    return len(HELPER_PINS)


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("phase58 requires original signed Bruce SHA-256")
    global_bridge=verify_global_chain(image)
    pins=verify_helper_pins(image)
    pair=backend_pair_provenance(image)
    reads=[]
    for pc in (0x6007E7EA,0x6007E810):
        original=pinpoint(image,pc)
        if (original["m"],original["op"])!=READ_PINS[pc]:
            raise ValueError(f"phase58 original reader pin drift {pc:#x}")
        reads.append({"pc":hex(pc),"m":original["m"],"op":original["op"]})
    for pc in CALLS:
        item=pinpoint(image,pc)
        if (item["m"],item["op"])!=("bl","#0x600d54b8"):
            raise ValueError(f"phase58 original direct helper call drift {pc:#x}")
    sites=call_sites(image)
    if not {hex(x) for x in CALLS}.issubset(set(sites)):
        raise ValueError("phase58 original direct-call xref positive control failed")
    return {
        "phase":58,"signed_sha_verified":True,"sha256":IMAGE_SHA256,
        "signed_global_bridge":global_bridge["same_global_RAM_address"],
        "readers":reads,
        "helper":hex(HELPER),
        "helper_signed_pins":pins,
        "backend_signed_pair":pair,
        "helper_register_transfer":{
            "from_entry_r0":"DISCARDED as direct register argument",
            "new_r0":"old R1", "new_r1":"old R2",
            "tail_target":"0x6006386c",
            "note":"Original R0 could indirectly be related to other inputs; no live device read",
        },
        "signed_callers":[hex(x) for x in CALLS],
        "candidate_all_direct_call_sites":sites,
        "aligned_pointer_literals":literal_refs(image),
        "signed_windows":signed_windows(image),
        "physical_ram_values":"UNMEASURED",
        "active_class10":"UNVERIFIED",
        "host_controllable_callbacks":"NOT DEMONSTRATED",
        "unsigned_execution":"NOT DEMONSTRATED",
        "HAB_closed_bypass":"NOT DEMONSTRATED",
        "hardware_access":False,"flash_or_efuse_write":False,
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image",type=Path)
    parser.add_argument("--out",type=Path)
    args=parser.parse_args()
    result=audit(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(result,indent=2)+"\n")
    print("PHASE58 VERIFIED ARGUMENT ADAPTER",json.dumps(result["helper_register_transfer"]))
    print("PHASE58 BACKEND SIGNED GLOBAL PAIR",json.dumps(result["backend_signed_pair"]))
    print("PHASE58 ORIGINAL HELPER CALLERS",json.dumps({
       "direct_sites":result["candidate_all_direct_call_sites"],
       "literals":result["aligned_pointer_literals"],
       "confirmed":result["signed_callers"],
    }))
    for name,rows in result["signed_windows"].items():
        print("PHASE58 ORIGINAL WINDOW",name,json.dumps(rows))
    print("PHASE58 NO LIVE CONFIG OR ARBITRARY EXECUTION PROOF")


if __name__=="__main__":
    main()
