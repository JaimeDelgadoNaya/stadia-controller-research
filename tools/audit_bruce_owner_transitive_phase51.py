"""Phase51 follow confirmed literal-load -> direct-branch wrappers one hop.

The caller word 0x2000A2A8 is part of the pinned signed OEM UPDATE.
The presence of a branch to a routine that receives the pointer is a
static argument-flow candidate, not proof that it stores owner fields or
executes at runtime. Windows are inspected, not assumed CFG.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_owner_alias_writers_phase51 import audit as audit_xrefs

FOLLOW={
 "early_owner_thunk_to_0x6004c374":0x6004C374,
 "owner_thunk_to_0x600d4e64":0x600D4E64,
 "owner_thunk_to_0x600d5512":0x600D5512,
 "owner_thunk_to_0x60060fd0":0x60060FD0,
 "owner_thunk_to_0x600d546a":0x600D546A,
 "owner_thunk_to_0x600d5482":0x600D5482,
 "owner_thunk_to_0x600d5578":0x600D5578,
 "owner_thunk_to_0x6007eb8c":0x6007EB8C,
 "owner_callback_mode_branch":0x60071404,
 "owner_config_init_function":0x60060F84,
 "owner_mode2_transition":0x60060FE8,
}
SPAN=0xAC

def inspect(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("exact original signed Bruce OEM SHA-256 required")
    prev=audit_xrefs(image)
    windows={}
    for name,start in FOLLOW.items():
        windows[name]=[
            hex(x["pc"])+" "+x["m"]+" "+x["op"]
            for x in decode(image,start,start+SPAN)
        ]
    return {
        "phase":51,
        "signed_sha_verified":True,
        "prior_signed_owner_PC_loads":prev["literal_PC_derived_load_candidates"],
        "prior_local_field_writes":prev["targeted_field_store_candidates"],
        "one_hop_candidate_target_windows":windows,
        "limitations":{
           "runtime_owner_field_values":"UNMEASURED",
           "r0_owner_argument_across_indirect_calls":"NOT FULLY TRACKED",
           "class10_in_active_config":"UNVERIFIED",
           "actual_usb_command_execution":"NONE PERFORMED",
        }
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    data=inspect(args.image.read_bytes())
    if args.out:args.out.write_text(json.dumps(data,indent=2)+"\n")
    print("PHASE51 TRANSITIVE SUMMARY",json.dumps({
        "signed_owner_PC_loads":data["prior_signed_owner_PC_loads"],
        "verified_local_owner_field_writes":data["prior_local_field_writes"],
        "window_count":len(data["one_hop_candidate_target_windows"])}))
    for name,rows in data["one_hop_candidate_target_windows"].items():
        print("PHASE51 CALLEE",name,json.dumps(rows))
    print("PHASE51 NO RUNTIME USB OR FLASH ACCESSED")

if __name__=="__main__": main()
