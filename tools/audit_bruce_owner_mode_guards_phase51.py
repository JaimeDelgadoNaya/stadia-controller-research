"""Phase51 verify signed one-hop USB owner *status paths*, not class record stores.

Original signed Bruce update only. Several wrappers receiving owner in R0
read mode/engine fields (+0x90/+0x98/+0x104), which does NOT attribute writes
to class config +4/+8/+12. A separate call provides owner as R2 and
must not be conflated with the callee's R0 stores.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_owner_transitive_phase51 import inspect as inspect_followup

PINS={
    0x600D4E64:("push","{r4, lr}"),
    0x600D4E66:("ldr.w","r3, [r0, #0x90]"),
    0x600D4E70:("ldr.w","r0, [r0, #0x98]"),
    0x600D4E74:("bl","#0x600d1066"),
    0x600D5512:("ldr.w","r3, [r0, #0x90]"),
    0x600D551A:("ldrb.w","r3, [r0, #0x104]"),
    0x600D546E:("ldr.w","r0, [r0, #0x9c]"),
    0x60060FEC:("ldr.w","r3, [r0, #0x90]"),
    0x60060FF0:("mov","r4, r0"),
    0x6006100E:("ldr.w","r0, [r4, #0x98]"),
    0x60061020:("cmp","r5, #2"),
    0x6006102E:("bl","#0x60060f84"),
    0x60079D7C:("ldr","r2, [pc, #0x54]"),
    0x60079D84:("bl","#0x6007eb8c"),
    0x6007EB96:("mov","r4, r0"),
    0x6007EB98:("str","r3, [r0]"),
    0x6007EBA6:("strd","r5, r5, [r0, #4]"),
}
SPANS=[
    (0x600D4E64,0x600D4E78),
    (0x600D5512,0x600D5524),
    (0x600D546A,0x600D5478),
    (0x60060FE8,0x60061032),
    (0x60079D7C,0x60079D88),
    (0x6007EB8C,0x6007EBB0),
]

def pin_original(actual):
    for pc,pair in PINS.items():
        if actual.get(pc)!=pair:
            raise ValueError("phase51 original signed mode/owner callee drift "+hex(pc)+": "+repr(actual.get(pc)))
    return len(PINS)

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("exact signed Bruce SHA-256 required")
    row={}
    for a,b in SPANS:
        row.update({x["pc"]:(x["m"],x["op"]) for x in decode(image,a,b)})
    n=pin_original(row)
    follow=inspect_followup(image)
    return {
        "phase":51,"OEM_signed_SHA_verified":True,
        "pinned_instructions":n,
        "proven_local_modes":[
          {"function":"0x600d4e64","uses_owner_R0":"read +0x90, engine pointer +0x98; no local field writer at +4/+8/+12"},
          {"function":"0x600d5512","uses_owner_R0":"read +0x90,+0x104 mode/status; no local config field store"},
          {"function":"0x600d546a","uses_owner_R0":"read +0x9c; no local class field store"},
          {"function":"0x60060fe8","uses_owner_R0":"mode transition; R0->R4; constructor call gated by mode 2"},
          {"function":"0x6007eb8c","different_argument_roles":"original xref 0x60079d7c loads owner into R2, whereas 0x6007eb8c stores through R0; cannot attribute those R0 stores to owner"},
        ],
        "verified_local_owner_class_store_candidates":follow["prior_local_field_writes"],
        "cannot_conclude":{
            "owner+4/+8/+12_never_written":True,
            "live_class10_selected":"UNVERIFIED",
            "physical_owner_RAM":"UNMEASURED",
            "host_writable_callback":"NOT DEMONSTRATED",
        },
        "no_device_access":True,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    out=audit(a.image.read_bytes())
    if a.out:a.out.write_text(json.dumps(out,indent=2)+"\n")
    print("PHASE51 SIGNED MODE OWNER CODE",json.dumps(out["proven_local_modes"]))
    print("PHASE51 FIELD WRITERS NOT ATTRIBUTED",json.dumps(out["cannot_conclude"]))
if __name__=="__main__":main()
