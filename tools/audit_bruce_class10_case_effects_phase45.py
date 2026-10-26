"""Phase 45: audit local effects of each of Bruce's 13 OEM class10 cases.

Reads ONLY the exact signed OEM update bytes. Thumb TBB branches are resolved
from the pinned signed table; each case is decoded from its own true target
so inline jump-table bytes are not interpreted as instructions. Local effects
are observations, not fully proven CFG, EP0 reachability or safe host commands.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_secondary_override_phase44 import audit_handler_table

FOCUS_PINS={
    0x60077368:("mov","r5, r2"),
    0x60077392:("add.w","r4, r0, #0x190"),
    0x60077396:("str","r4, [r5, #4]"),
    0x60077398:("movs","r3, #8"),
    0x6007739A:("b","#0x600773b6"),
    0x600773A4:("movs","r3, #0"),
    0x600773A6:("add.w","r0, r0, #0x12c"),
    0x600773AA:("str","r3, [r2, #8]"),
    0x600773AC:("b","#0x60077386"),
    0x600773AE:("add.w","r4, r0, #0x1d8"),
    0x600773B2:("movs","r3, #2"),
    0x600773B4:("str","r4, [r2, #4]"),
    0x600773B6:("str","r3, [r5, #8]"),
}
SUMMARY={
    "0x81":{"signed_local_operation":"derive context_object +0x190 into response-like R2+4, output tag 8 at +8",
            "is_incoming_arbitrary_callback_address_store":False},
    "0x83":{"signed_local_operation":"derive context_object +0x12c; clear [R2+8] then branch to signed common function",
            "is_incoming_arbitrary_callback_address_store":False},
    "0x84":{"signed_local_operation":"derive context_object +0x1d8 into [R2+4], write tag 2 at +8",
            "is_incoming_arbitrary_callback_address_store":False},
}


def pin_case_instructions(image):
    allrows={}
    # Independent case starts; TBB data bytes are not executable instructions.
    for start,end in (
        (0x60077360,0x60077370),
        (0x60077392,0x6007739C),
        (0x600773A4,0x600773AE),
        (0x600773AE,0x600773BA),
    ):
        allrows.update({x["pc"]:(x["m"],x["op"]) for x in decode(image,start,end)})
    for pc,pair in FOCUS_PINS.items():
        if allrows.get(pc)!=pair:
            raise ValueError("Signed class10 focus case instruction drift "+hex(pc)+
                             " actual "+repr(allrows.get(pc)))
    return len(FOCUS_PINS)


def inspect_cases(image):
    dispatch=audit_handler_table(image)
    branches=dispatch["dispatches"]
    if len(branches)!=13:
        raise ValueError("Original signed 13-way case table changed")
    pin_count=pin_case_instructions(image)
    ordered=sorted({int(x["branch_target"],16) for x in branches})
    case_records=[]
    for row in branches:
        pc=int(row["branch_target"],16)
        next_pc=min((addr for addr in ordered if addr>pc),default=0x600774AE)
        if next_pc>0x600774AE:
            raise ValueError("unexpected case branch target beyond range")
        instructions=decode(image,pc,next_pc)
        transfers=[{"pc":hex(x["pc"]),"ins":x["m"]+" "+x["op"]}
                   for x in instructions
                   if x["m"].startswith(("str","stm","bl","b.","bx"))
                   or x["m"] in ("b","b.w","blx","tbb","tbh")]
        rec={
            "r1_signed_case":row["r1_candidate_code"],
            "signed_branch_target":row["branch_target"],
            "linear_region_end_exclusive":hex(next_pc),
            "signed_code_preview":[hex(x["pc"])+" "+x["m"]+" "+x["op"]
                                   for x in instructions[:22]],
            "candidate_stores_calls_branches":transfers[:26],
            "control_flow_graph_complete":False,
            "USB_reachable":False,
        }
        if rec["r1_signed_case"] in SUMMARY:
            rec["local_verified_semantics"]=SUMMARY[rec["r1_signed_case"]]
        case_records.append(rec)
    return {
        "signed_original_semantic_pins":pin_count,
        "signed_cases":case_records,
        "case_count":len(case_records),
        "focus_case_meanings_are_local_only":True,
        "all_case_side_effects_proven":False,
        "host_supply_of_callback_pointer_proven":False,
    }


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("requires SHA-256 pinned original OEM Bruce update")
    report=inspect_cases(image)
    return {"phase":45,"signed_original_image_sha_verified":True,
            "cases":report,"device_connected":False,"usb_transfers":False,
            "flash_written":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    opt=p.parse_args()
    result=audit(opt.image.read_bytes())
    if opt.out:opt.out.write_text(json.dumps(result,indent=2)+"\n")
    print("PHASE45 CASES",json.dumps([
        {"r1":x["r1_signed_case"],"pc":x["signed_branch_target"],
         "transfers":x["candidate_stores_calls_branches"],
         "local_summary":x.get("local_verified_semantics")}
        for x in result["cases"]["signed_cases"]
    ]))
    print("PHASE45 CASES HOST CONTROL: NOT VERIFIED")

if __name__=="__main__":
    main()
