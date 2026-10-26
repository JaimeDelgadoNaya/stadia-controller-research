"""Phase50 exact signed OEM owner literal usages (candidate disassembly only).

Shows nearby code for each 0x2000A2A8 aligned word; independently verifies
required OEM SHA-256. Does not infer runtime writes or treat arbitrary linear
Thumb disassembly as reachable control flow. No device access.
"""
from __future__ import annotations
import argparse,hashlib,json,struct
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SIZE,IMAGE_SHA256,ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_usb_owner_pointer_phase50 import OWNER,nearby_exact_literals

BASE=ASSUMED_XIP_BASE
OWNERSHIP_WINDOWS={
    "boot_owner_candidate":(0x60041E70,0x60041EA0),
    "owner_mode_update_candidate":(0x6005AC20,0x6005ACF4),
    "owner_secondary_candidate":(0x6005BBD8,0x6005BC28),
    "owner_boot_mode_candidate":(0x600648E0,0x60064948),
    "owner_config_candidate":(0x60065408,0x60065458),
    "owner_context_candidate_one":(0x60074AC0,0x60074B08),
    "owner_context_candidate_two":(0x60074E30,0x60074E70),
    "owner_context_candidate_three":(0x60075578,0x600755C0),
    "owner_context_candidate_four":(0x60076188,0x600761D4),
    "owner_context_candidate_five":(0x60079D90,0x60079DE0),
    "owner_context_candidate_six":(0x6007F6D8,0x6007F71C),
}

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("exact original signed OEM update SHA-256 required")
    hits=nearby_exact_literals(image,targets=(OWNER,OWNER+4,OWNER+8,OWNER+12))
    assert hits[hex(OWNER)]["aligned_signed_literal_matches"]==16
    assert all(hits[hex(OWNER+n)]["aligned_signed_literal_matches"]==0 for n in (4,8,12))
    windows={name:[hex(x["pc"])+" "+x["m"]+" "+x["op"] for x in decode(image,lo,hi)]
             for name,(lo,hi) in OWNERSHIP_WINDOWS.items()}
    return {
        "phase":50,
        "OEM_original_sha_verified":True,
        "exact_RAM_base":hex(OWNER),
        "literal_census":{k:v["flash_address_words"] for k,v in hits.items()},
        "candidate_code_windows":windows,
        "runtime_object_fields":"UNMEASURED",
        "owner_plus4_plus8_plus12_writers_verified":"NOT EXHAUSTIVELY ATTRIBUTED",
        "active_class10_selected":"UNVERIFIED",
        "physical_device_access":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    x=audit(a.image.read_bytes())
    if a.out:a.out.write_text(json.dumps(x,indent=2)+"\n")
    print("PHASE50 OWNER LITERAL REFERENCES",json.dumps(x["literal_census"]))
    for name,items in x["candidate_code_windows"].items():
        print("PHASE50 XREF WINDOW",name,json.dumps(items))
    print("PHASE50 ACTIVE CLASS10 CONFIG NOT VERIFIED; STATIC ONLY")
if __name__=="__main__": main()
