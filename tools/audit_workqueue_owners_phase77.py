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
    "A_candidate_entry_prologue":(0x60062126,0x60062140),
    "A_candidate_late_block":(0x60062140,0x600621C0),
    "A_candidate_last_block":(0x600621C0,0x60062220),
    "A_atomic_setup_after_table":(0x60062250,0x60062270),
    "A_atomic_and_enqueue":(0x6006226A,0x60062298),
    "mode_activation_upstream":(0x60074772,0x600747B0),
    "mode_activation_direct_B_initializer":(0x600747B0,0x60074818),
    "B_owner_initializer_predecessor":(0x6006B380,0x6006B400),
    "B_owner_initializer_and_callbacks":(0x6006B400,0x6006B450),
    "B_callback_storage_adjacent":(0x6006B450,0x6006B4B0),
    "B_guard_state_source":(0x600D8E6C,0x600D8EF0),
    "B_caller_and_guard_clear":(0x6006B290,0x6006B2D8),
}
TARGETS={
    "B_initializer_candidate_6006b3e8":0x6006B3E8,
    "B_initializer_candidate_6006b3f8":0x6006B3F8,
    "B_initializer_candidate_6006b3e0":0x6006B3E0,
    "B_initializer_candidate_6006b400":0x6006B400,
    "A_candidate_entry_60062040":0x60062040,
    "A_candidate_entry_60062126":0x60062126,
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
        0x60062126:("push","{r4, r5, r6, lr}"),
        0x60062128:("mov","r5, r0"),
        0x6006212C:("mov","r4, r2"),
        0x60062264:("uxtb","r0, r0"),
        0x60062266:("cmp","r0, #0xe"),
        0x60062268:("bne","#0x6006229e"),
        0x60062288:("add.w","r0, r4, #0x10"),
        0x6006228C:("bl","#0x600926a0"),
        0x6006B29C:("ldrb.w","r3, [r4, #0x182]"),
        0x6006B2AC:("add.w","r0, r4, #0x11c"),
        0x6006B2B0:("bl","#0x600926a0"),
        0x6006B2C2:("strb.w","r0, [r4, #0x182]"),
        0x6006B416:("ldr","r3, [pc, #0x9c]"),
        0x6006B41C:("str.w","r4, [r4, #0x120]"),
        0x6006B420:("str.w","r3, [r4, #0x11c]"),
    0x6006B43E:("movs","r3, #1"),
    }
    mapping={}
    for low,high in ((0x60062126,0x60062130),(0x60062264,0x60062290),
                     (0x6006B290,0x6006B2D0),
                     (0x6006B416,0x6006B452)):
        mapping.update({int(r["pc"],16):(r["m"],r["op"])
                        for r in code_rows(image,low,high)})
    for pc,pin in expected.items():
        if mapping.get(pc)!=pin:
            raise ValueError(f"Phase77 signed original source anchor drift {pc:#x}: {mapping.get(pc)}")
    return len(expected)

B_INIT_ANCHORS={
    0x6006B3E8:("push","{r4, r5, lr}"),
    0x6006B3EA:("ldrb.w","r3, [r0, #0x180]"),
    0x6006B3F0:("mov","r4, r0"),
    0x6006B3F2:("cbz","r3, #0x6006b3fe"),
    0x6006B3F8:("mov","r0, r5"),
    0x6006B400:("bl","#0x6009267c"),
    0x6006B416:("ldr","r3, [pc, #0x9c]"),
    0x6006B41C:("str.w","r4, [r4, #0x120]"),
    0x6006B420:("str.w","r3, [r4, #0x11c]"),
    0x6006B442:("strb.w","r3, [r4, #0x180]"),
    0x6006B44A:("mov","r0, r4"),
}
B_GATE_RESET_ANCHORS={
    0x6006B29C:("ldrb.w","r3, [r4, #0x182]"),
    0x6006B2BC:("movs","r0, #0"),
    0x6006B2C2:("strb.w","r0, [r4, #0x182]"),
}

def verify_B_owner_state(image):
    found={}
    for lo,hi in (
        (0x6006B3E8,0x6006B404),
        (0x6006B416,0x6006B452),
        (0x6006B290,0x6006B2CA),
    ):
        found.update({int(r["pc"],16):(r["m"],r["op"])
                      for r in code_rows(image,lo,hi)})
    pins={**B_INIT_ANCHORS,**B_GATE_RESET_ANCHORS}
    for pc,expected in pins.items():
        if found.get(pc)!=expected:
            raise ValueError(f"Phase77 signed original B owner/gate drift {pc:#x}: {found.get(pc)}")
    return {
        "original_signed_instruction_pins":len(pins),
        "initializer_entry":"0x6006b3e8",
        "entry_R4_source":"R4=R0 at 0x6006b3f0",
        "pre_init_guard":"[R0+0x180] != 0 skips the main initializer",
        "ready_flag_store":"0x6006b43e MOVS R3,#1; 0x6006b442 STRB R3,[R4+0x180]",
        "signed_callback_method_store":"0x6006b420 STR.W signed_0x6006B291,[R4+0x11C]",
        "signed_callback_context_store":"0x6006b41c STR.W R4,[R4+0x120]",
        "runtime_callback_gate_read":"0x6006b29c LDRB R3,[R4+0x182]",
        "runtime_gate_clear":"0x6006b2c2 STRB 0,[R4+0x182]",
        "identity_of_initializer_R0_in_live_device":"UNKNOWN",
        "other_writers_outside_local_scanned_region":"NOT_EXCLUDED",
        "host_USB_control":"NOT_DEMONSTRATED",
    }

def signed_pointer_refs(image,targets):
    wanted={addr|1:key for key,addr in targets.items()}
    out={key:[] for key in targets}
    for off in range(0,len(image)-3,4):
        value=struct.unpack_from("<I",image,off)[0]
        if value in wanted:
            out[wanted[value]].append({"file_offset":hex(off),
                  "thumb_value":hex(value),"role":"STATIC_WORD_NOT_RUNTIME_INVOCATION"})
    return out

B_DIRECT_ACTIVATION_CALL_PINS={
    0x600747B0:("mov","r0, r7"),
    0x600747B2:("bl","#0x60060f28"),
    0x600747D8:("bl","#0x6006b3e8"),
}

def verify_B_direct_activation_caller(image):
    found={int(row["pc"],16):(row["m"],row["op"])
           for row in code_rows(image,0x600747B0,0x60074800)}
    for pc,expected in B_DIRECT_ACTIVATION_CALL_PINS.items():
        if found.get(pc)!=expected:
            raise ValueError(f"Phase77 signed activation->B initializer drift {pc:#x}: {found.get(pc)}")
    return {
        "original_signed_pins":len(B_DIRECT_ACTIVATION_CALL_PINS),
        "phase66_mode_activation":"0x600747b2 BL 0x60060f28",
        "direct_B_initializer":"0x600747d8 BL 0x6006b3e8",
        "B_initializer_entry":"0x6006b3e8",
        "callsite_R0_argument":"PENDING_LINEAGE_AUDIT",
        "runtime_executed":"UNVERIFIED",
        "host_USB_event_origin":"NOT_PROVEN",
    }

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Phase77 exact original Bruce OEM SHA-256 required")
    original_callsite_assertions(image)
    B=verify_B_callback_registration(image)
    shared=cross_check_phase66_shared_helper(image)
    n=verify_field_anchors(image)
    B_owner=verify_B_owner_state(image)
    activation=verify_B_direct_activation_caller(image)
    windows=bounded_signed_windows(image)
    accesses=near_field_access_candidates(image)
    edges=direct_upstream_edges(image)
    ptrs=signed_pointer_refs(image,TARGETS)
    return {
        "phase":77,"signed_original_SHA256":IMAGE_SHA256,
        "original_SHA_verified":True,"signed_pin_count":n,
        "B_object_initializer_and_local_gate":B_owner,
        "B_direct_activation_caller":activation,
        "candidate_function_pointer_literals":ptrs,
        "B_signed_function_initializer":B,
        "B_shared_helper":shared,
        "signed_bounded_owner_windows":windows,
        "signed_byte_status_shape_candidates":accesses,
        "upstream_direct_BL_shapes":edges,
        "decision":{
            "A_R4_owner":"LOCAL_PROVENANCE_R4_FROM_R2_AT_0x6006212C; caller of function unknown",
            "A_R5_atomic_flag_origin":"LOCAL_PROVENANCE_R5_FROM_R0_AT_0x60062128; upstream object unknown",
            "B_R4_owner":"UNRESOLVED",
            "A_additional_gate":"0x60062266 CMP R0,#0x0E; 0x60062268 BNE skip producer",
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
    print("PHASE77 B_OWNER",json.dumps(result["B_object_initializer_and_local_gate"]))
    print("PHASE77 B_ACTIVATION",json.dumps(result["B_direct_activation_caller"]))
    print("PHASE77 POINTERS",json.dumps(result["candidate_function_pointer_literals"]))
    print("PHASE77 EVIDENCE",json.dumps(result,separators=(",",":")))
    print("PHASE77 PHYSICAL USB ORIGIN UNPROVEN")

if __name__=="__main__":main()
