"""Phase50 read-only original-signed Bruce USB owner, configuration and class list provenance survey.

The source is the pinned OEM UPDATE, not installed-flash or live RAM readback.
Bounded Thumb windows are candidates; linear disassembly is not CFG proof.
No USB traffic, flash writes, arbitrary code, or device interaction.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_init_inbound_phase43 import find_inbound_branches
from tools.audit_bruce_usb_config_writer_phase49 import audit as audit_writer
from tools.audit_bruce_ep0_class_object_phase48 import raw_word

SLICES={
 "owner_lifecycle_first":(0x60060B40,0x60060C80),
 "owner_lifecycle_second":(0x60060C80,0x60060DA0),
 "owner_lifecycle_third":(0x60060DA0,0x60060EC0),
 "owner_lifecycle_fourth":(0x60060EC0,0x60060F84),
 "owner_constructor":(0x60060F84,0x60060FC4),
 "owner_mode_transition":(0x60060FE8,0x600610A8),
 "owner_mode_next":(0x600610A8,0x600611A0),
 "owner_post_mode":(0x600611A0,0x60061280),
 "descriptor_owner_init_candidate":(0x60060460,0x600605B0),
 "owner_direct_caller_mode_a":(0x60064900,0x60064958),
 "owner_direct_caller_mode_b":(0x60071400,0x60071440),
 "owner_direct_caller_mode_c":(0x600D4E40,0x600D4EA0),
 "owner_usb_init_earlier":(0x60060A00,0x60060B40),
 "owner_usb_init_later":(0x60060B64,0x60060C18),
}
CALL_TARGETS={
 "owner_constructor":0x60060F84,
 "owner_mode_transition":0x60060FE8,
 "owner_mode_helper":0x60060C70,
 "owner_descriptors":0x60060DB0,
 "owner_instance_seed":0x60060C00,
}
KNOWN={
0x60060FE8:("push.w","{r4, r5, r6, r7, r8, lr}"),
0x60060FF0:("mov","r4, r0"),
0x60061020:("cmp","r5, #2"),
0x6006102C:("mov","r0, r4"),
0x6006102E:("bl","#0x60060f84"),
0x60060F86:("add.w","r2, r0, #0x98"),
0x60060F8A:("adds","r1, r0, #4"),
0x60060F8E:("ldrb","r0, [r0, #0x10]"),
0x60060F90:("bl","#0x600550e4"),
}

def validate_pins(rows, anchors=KNOWN):
    for pc,pair in anchors.items():
        if rows.get(pc)!=pair:
            raise ValueError("Phase50 signed USB owner anchor drift "+hex(pc)+": "+repr(rows.get(pc)))
    return len(anchors)

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Exact SHA-256 pinned original OEM Bruce update required")
    writer=audit_writer(image)
    windows={}
    actual={}
    for name,(start,end) in SLICES.items():
        out=decode(image,start,end)
        windows[name]=[hex(x["pc"])+" "+x["m"]+" "+x["op"] for x in out]
        actual.update({x["pc"]:(x["m"],x["op"]) for x in out})
    count=validate_pins(actual)
    callers={name:find_inbound_branches(image,only_target=addr)["direct_branch_candidates"][:18] for name,addr in CALL_TARGETS.items()}
    return {
        "phase":50,"original_OEM_update_SHA256_verified":True,
        "signed_owner_pins":count,
        "source":"original signed Bruce OEM update; no physical RAM/flash readback",
        "writer_chain_phase49":writer["signed_owner_to_config_args"],
        "owner_code_windows":windows,
        "owner_mode_b_signed_literals":[{"PC":hex(p),"raw_word":hex(raw_word(image,p))} for p in range(0x60071430,0x60071440,4)],
        "owner_mode_a_signed_literals":[{"PC":hex(p),"raw_word":hex(raw_word(image,p))} for p in range(0x60064950,0x60064968,4)],
        "direct_branch_callers_candidates":callers,
        "static_boundaries":{
            "owner_address":"R0 at 0x60060FE8, R4 after 0x60060FF0",
            "mode2_specific_constructor":"0x60061020 CMP R5,#2; 0x6006102e BL 0x60060f84, conditional",
            "input_config":"owner+4, passed by 0x60060f8a",
            "input_config_method":"owner+8 word, if config=owner+4",
            "input_config_count":"owner+12 low byte, if config=owner+4",
            "physical_values":"NOT MEASURED",
            "class10_selected":"UNVERIFIED",
        },
        "device_access":False,"flash_efuse_writes":False
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    z=audit(a.image.read_bytes())
    if a.out:a.out.write_text(json.dumps(z,indent=2)+"\n")
    print("PHASE50 OWNER MODE",json.dumps(z["static_boundaries"]))
    print("PHASE50 OWNER MODE B LITERALS",json.dumps(z["owner_mode_b_signed_literals"]))
    print("PHASE50 OWNER MODE A LITERALS",json.dumps(z["owner_mode_a_signed_literals"]))
    for name,rows in z["owner_code_windows"].items():
        print("PHASE50 WINDOW",name,json.dumps(rows))
    for name,rows in z["direct_branch_callers_candidates"].items():
        print("PHASE50 INBOUND",name,json.dumps(rows))
    print("PHASE50 ACTIVE USB CLASS COUNT/CLASS10 UNMEASURED")
if __name__=="__main__":
    main()
