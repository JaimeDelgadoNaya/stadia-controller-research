"""Phase 77: signed original Work Queue owner / gate writer provenance.

Trace only original signed code windows, precise producer call arguments,
byte-guard read/write shapes, original B callback owner initializer and
direct BL candidates. A literal address or nearby USB routine is not an
observed host event. No physical USB/flash interaction.
"""
from __future__ import annotations
import argparse,hashlib,json,re,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS
from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_queue_producers_phase75 import BASE, xip_target_BL_shapes
from tools.audit_workqueue_caller_provenance_phase76 import (
    original_callsite_assertions,verify_B_callback_registration,
    cross_check_phase66_shared_helper, CALL_A,CALL_B,B_ENTRY
)

# These are carefully bounded original file regions, not CFG/function proofs.
WINDOWS={
    "A_candidate_prior_block":(0x60062040,0x600620C0),
    "A_candidate_middle_block":(0x600620C0,0x60062140),
    "A_candidate_late_block":(0x60062140,0x600621C0),
    "A_candidate_last_block":(0x600621C0,0x60062220),
    "A_candidate_atomic_setup":(0x60062220,0x60062270),
    "A_atomic_and_enqueue":(0x6006226A,0x60062298),
    "B_owner_initializer_predecessor":(0x6006B380,0x6006B400),
    "B_owner_initializer_and_callbacks":(0x6006B400,0x6006B450),
    "B_callback_storage_adjacent":(0x6006B450,0x6006B4B0),
    "B_guard_state_source":(0x600D8E6C,0x600D8EF0),
    "B_caller_and_guard_clear":(0x6006B290,0x6006B2D8),
}
TARGETS={
    "B_initializer_candidate_6006b3f8":0x6006B3F8,
    "B_initializer_candidate_6006b3e0":0x6006B3E0,
    "B_initializer_candidate_6006b400":0x6006B400,
    "A_candidate_entry_60062040":0x60062040,
    "A_candidate_entry_60062140":0x60062140,
    "A_candidate_entry_600621c0":0x600621C0,
    "B_work_callback":B_ENTRY,
    "shared_init_helper":0x6009267C,
}
# A direct target name tagged 'candidate' is not a function-start assertion.
def code_rows(image,start,end):
    if not BASE<=start<end<=BASE+len(image):
        raise ValueError("Phase77 source window outside signed OEM")
    return [{"pc":hex(x["pc"]),"m":x["m"],"op":x["op"]}
            for x in decode(image,start,end)]

def bounded_signed_windows(image):
    return {name:code_rows(image,lo,hi) for name,(lo,hi) in WINDOWS.items()}

def near_field_access_candidates(image,lower=0x6006A000,upper=0x6006D000):
    """Thumb-shaped accesses to #0x182 and #0x181; not runtime R4 identity."""
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    hits=[]
    for pc in range(lower,upper-2,2):
        off=pc-BASE
        i=next(cs.disasm(image[off:off+4],pc,count=1),None)
        if not i or i.mnemonic.split(".")[0] not in ("ldrb","strb","ldr","str"):
            continue
        if not re.search(r"#0x18[12]\]",i.op_str):
            continue
        left=max(lower,pc-0x14)
        # Bounded code-shaped context only. Might include embedded literals.
        context=code_rows(image,left,min(upper,pc+0x1A))
        hits.append({"pc":hex(pc),"m":i.mnemonic,"op":i.op_str,
                     "context":context,
                     "base_register_identity":"UNPROVEN",
                     "execution":"NOT_OBSERVED"})
    return hits

def direct_upstream_edges(image):
    # Single full XIP opcode-shape scan; individual edges are not verified CFG.
    hits=xip_target_BL_shapes(image,set(TARGETS.values()))
    return {label:[x for x in hits if int(x["target"],16)==dst]
            for label,dst in TARGETS.items()}

def verify_field_anchors(image):
    expected={
        0x60062288:("add.w","r0, r4, #0x10"),
        0x6006228C:("bl","#0x600926a0"),
        0x6006B29C:("ldrb.w","r3, [r4, #0x182]"),
        0x6006B2AC:("add.w","r0, r4, #0x11c"),
        0x6006B2B0:("bl","#0x600926a0"),
        0x6006B2C2:("strb.w","r0, [r4, #0x182]"),
        0x6006B416:("ldr","r3, [pc, #0x9c]"),
        0x6006B41C:("str.w","r4, [r4, #0x120]"),
        0x6006B420:("str.w","r3, [r4, #0x11c]"),
    }
    mapping={}
    for low,high in ((0x60062288,0x60062290),
                     (0x6006B290,0x6006B2D0),
                     (0x6006B416,0x6006B424)):
        mapping.update({int(r["pc"],16):(r["m"],r["op"])
                        for r in code_rows(image,low,high)})
    for pc,pin in expected.items():
        if mapping.get(pc)!=pin:
            raise ValueError(f"Phase77 signed original source anchor drift {pc:#x}: {mapping.get(pc)}")
    return len(expected)

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Phase77 exact original Bruce OEM SHA-256 required")
    original_callsite_assertions(image)
    B=verify_B_callback_registration(image)
    shared=cross_check_phase66_shared_helper(image)
    n=verify_field_anchors(image)
    windows=bounded_signed_windows(image)
    accesses=near_field_access_candidates(image)
    edges=direct_upstream_edges(image)
    return {
        "phase":77,"signed_original_SHA256":IMAGE_SHA256,
        "original_SHA_verified":True,"signed_pin_count":n,
        "B_signed_function_initializer":B,
        "B_shared_helper":shared,
        "signed_bounded_owner_windows":windows,
        "signed_byte_status_shape_candidates":accesses,
        "upstream_direct_BL_shapes":edges,
        "decision":{
            "A_R4_owner":"UNRESOLVED",
            "A_R5_atomic_flag_origin":"UNRESOLVED",
            "B_R4_owner":"UNRESOLVED",
            "B_status_writer_0x182":"NOT_PROVEN",
            "physical_USB_origin":"NOT_PROVEN",
            "class10_or_EP0_event_link":"NOT_PROVEN",
            "original_B_callback_selected_by_host":"NOT_PROVEN",
            "callback_execution":"NOT_OBSERVED",
            "unsigned_code_execution":"NOT_DEMONSTRATED",
            "HAB_CLOSED_bypass":"NOT_DEMONSTRATED",
            "hardware_commands_or_flash_writes":False,
        }
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    result=audit(args.image.read_bytes())
    if args.out:args.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    for key,v in result["signed_bounded_owner_windows"].items():
        print("PHASE77 WINDOW",key,json.dumps(v,separators=(",",":")))
    print("PHASE77 FIELD_SHAPES",json.dumps(result["signed_byte_status_shape_candidates"]))
    print("PHASE77 DIRECT_BL",json.dumps(result["upstream_direct_BL_shapes"]))
    print("PHASE77 EVIDENCE",json.dumps(result,separators=(",",":")))
    print("PHASE77 PHYSICAL USB ORIGIN UNPROVEN")

if __name__=="__main__":main()
