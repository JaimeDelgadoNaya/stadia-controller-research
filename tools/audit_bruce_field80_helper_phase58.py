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

BASE=ASSUMED_XIP_BASE
HELPER=0x600D54B8
CALLS=(0x6007E7FA,0x6007E81E)
WINDOWS={
    "caller_branch_one":(0x6007E7D6,0x6007E800),
    "caller_branch_two":(0x6007E80E,0x6007E824),
    "helper_entry":(0x600D54B8,0x600D5540),
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


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("phase58 requires original signed Bruce SHA-256")
    global_bridge=verify_global_chain(image)
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
