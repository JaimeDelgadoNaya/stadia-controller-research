"""Phase 75: inspect original signed Work Queue enqueue-producer provenance.

Offline, SHA-256-pinned OEM only. A pointer value in signed firmware is
not proof of a runtime queue or of a USB host-triggered producer.
This phase first surveys original signed enqueue-adjacent veneers,
ITCM helper calls and direct Work Queue pointer references, then uses
bounded instruction windows to distinguish plausible producers from
proven writes/queue insertions.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS

from tools.audit_signed_app_surface import (
    IMAGE_SHA256,IMAGE_SIZE,ASSUMED_XIP_BASE,decode_thumb_bl_target
)
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET,ITCM_LENGTH
from tools.audit_bruce_ep0_registration import decode
from tools.audit_pending_workqueue_phase67 import QUEUE
from tools.audit_queue_receive_phase74 import VENEER as QUEUE_RECEIVER

BASE=ASSUMED_XIP_BASE
XIP_END=min(0xFF000,IMAGE_SIZE)
CONTROL_FIELD=QUEUE+0xB0
INITIAL_VENEERS=(0x6013D238,0x6013D268,0x6013D2D0,0x6013D2E0)
ITCM_KNOWN_CALL_TARGETS=(0x768C,0x7734,0x7674,0x6D2C,0x7490,0x713C)
WORKQUEUE_VALUE_WORDS=(QUEUE,CONTROL_FIELD)
XIP_VENEER_START=0x6013D210
XIP_VENEER_END=0x6013D310

def signed_word(image,off):
    if off<0 or off%4 or off+4>len(image):
        raise ValueError("Phase75 invalid aligned source word")
    return struct.unpack_from("<I",image,off)[0]

def one(image,pc,itcm=False):
    offset=ITCM_SOURCE_OFFSET+pc if itcm else pc-BASE
    if offset<0 or offset+4>len(image):
        return None
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    return next(decoder.disasm(image[offset:offset+4],pc,count=1),None)

def signed_windows(image):
    areas={
        "xip_queue_veneer_neighbor":(XIP_VENEER_START,XIP_VENEER_END,False),
        "itcm_dequeue_helper":(0x7640,0x76E0,True),
        "itcm_queue_lock":(0x7700,0x77A0,True),
        "itcm_queue_wait":(0x6D2C,0x6E64,True),
        "xip_original_queue_constructor":(0x600926D0,0x60092730,False),
        "xip_queue_getter_one":(0x6009269E,0x600926B4,False),
        "xip_queue_getter_two":(0x600926B8,0x600926CC,False),
        "xip_queue_post_worker":(0x600EE180,0x600EE1F4,False),
        "xip_queue_other_worker":(0x600925B8,0x6009262E,False),
        "xip_other_wrapper":(0x60101820,0x60101852,False),
        "itcm_count_inc_context":(0x6C80,0x6D2C,True),
        "itcm_possible_send_start":(0x6A6C,0x6B48,True),
        "xip_queue_start":(0x60092490,0x600924C4,False),
        "xip_queue_kernel_wrapper":(0x60101810,0x6010183C,False),
        "xip_queue_extra_caller":(0x600C9EBC,0x600C9EE4,False),
        "xip_usb_neighbor_call":(0x6006EA4C,0x6006EA84,False),
        "itcm_adjacent_sender_candidate":(0x6E5C,0x7060,True),
    }
    windows={}
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    for name,(start,end,itcm) in areas.items():
        offset=(ITCM_SOURCE_OFFSET+start if itcm else start-BASE)
        rows=cs.disasm(image[offset:offset+(end-start)],start)
        windows[name]=[{"pc":hex(i.address),"m":i.mnemonic,"op":i.op_str}
                       for i in rows]
    return windows

def inspect_veneers(image):
    results=[]
    for pc in range(XIP_VENEER_START,XIP_VENEER_END-7,2):
        ins=one(image,pc)
        if ins and ins.mnemonic=="ldr.w" and ins.op_str=="pc, [pc, #-0x0]":
            off=pc-BASE+4
            if (pc+4)%4:
                # An arbitrary Thumb-shaped hit is NOT necessarily a
                # valid PC-relative literal; keep provenance explicit.
                continue
            w=signed_word(image,off)
            dst=w&~1
            destination=("ITCM" if w&1 and 0<=dst<ITCM_LENGTH else
                         "XIP" if w&1 and BASE<=dst<BASE+XIP_END
                         else "UNKNOWN_OR_NOT_THUMB")
            results.append({"pc":hex(pc),"literal_at":hex(pc+4),
                            "raw_destination":hex(w),
                            "dest_pc":hex(dst),"domain":destination,
                            "signed_literal_not_execution":True})
    if not any(v["pc"]==hex(QUEUE_RECEIVER)
               and v["dest_pc"]=="0x6d2c" for v in results):
        raise ValueError("Phase75 missing known signed receive veneer control")
    return results

def queue_literals(image):
    found=[]
    for off in range(0,len(image)-3,4):
        w=signed_word(image,off)
        if w in WORKQUEUE_VALUE_WORDS:
            is_itcm=ITCM_SOURCE_OFFSET<=off<ITCM_SOURCE_OFFSET+ITCM_LENGTH
            found.append({"offset":hex(off),"value":hex(w),
                          "pc":hex(off-ITCM_SOURCE_OFFSET if is_itcm else BASE+off),
                          "domain":"ITCM_COPY" if is_itcm else "XIP_OR_DATA"})
    return found

def direct_bl_target(image,offset,itcm):
    try:
        if itcm:
            return decode_thumb_bl_target(image,ITCM_SOURCE_OFFSET+offset,
                                          base=-ITCM_SOURCE_OFFSET)
        return decode_thumb_bl_target(image,offset)
    except ValueError:
        return None

def signed_itcm_BL_targets(image,targets=ITCM_KNOWN_CALL_TARGETS):
    """Candidates only, may include data interpreted as Thumb BL."""
    result=[]
    wanted=set(targets)
    for off in range(0,ITCM_LENGTH-3,2):
        target=direct_bl_target(image,off,True)
        if target in wanted:
            result.append({"pc":hex(off),"target":hex(target),
                           "domain":"ITCM","path_executed":"UNVERIFIED"})
    return result

def xip_target_BL_shapes(image,targets):
    """Only exact direct BL opcode shapes; not indirect BLX/branch calls."""
    wanted=set(targets)
    result=[]
    for off in range(0xC800,XIP_END-3,2):
        val=direct_bl_target(image,off,False)
        if val in wanted:
            result.append({"pc":hex(BASE+off),"target":hex(val),
                           "domain":"XIP","path_executed":"UNVERIFIED"})
    return result

def pc_literal_load_candidates(image,literals,prior=0x100):
    """Thumb-aligned PC LDR candidates, not path-sensitive attribution."""
    cand=[]
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    for item in literals:
        pc=int(item["pc"],16)
        itcm=item["domain"]=="ITCM_COPY"
        minimum=0 if itcm else BASE
        for location in range(max(minimum,pc-prior)&~1,pc,2):
            src=ITCM_SOURCE_OFFSET+location if itcm else location-BASE
            ins=next(cs.disasm(image[src:src+4],location,count=1),None)
            if ins is None or ins.mnemonic not in ("ldr","ldr.w"):
                continue
            # Parsing exactly (Rdest,[PC,#imm]); exclude SP/negative and
            # data patterns. This recovers original literal load *shapes*.
            import re
            m=re.fullmatch(r"(r(?:1[0-2]|[0-9])), \[pc, #(0x[0-9a-f]+|\d+)\]",ins.op_str)
            if m and ((location+4)&~3)+int(m.group(2),0)==pc:
                cand.append({"pc":hex(location),"instruction":ins.mnemonic+" "+ins.op_str,
                             "loaded_register":m.group(1),
                             "loaded_word":item["value"],
                             "literal_pc":item["pc"],
                             "domain":"ITCM" if itcm else "XIP",
                             "reachable":"UNVERIFIED"})
    return cand

def inspect_itcm_count_sites(image):
    """Code-shaped +0x38 accesses around queue primitives; base unproven."""
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    result=[]
    for pc in range(0x6300,0x7100,2):
        start=ITCM_SOURCE_OFFSET+pc
        ins=next(cs.disasm(image[start:start+4],pc,count=1),None)
        if ins is None:
            continue
        if ins.mnemonic.startswith(("ldr","str")) and "[r" in ins.op_str and "#0x38]" in ins.op_str:
            frompc=max(0x6300,pc-0x24)
            to=min(0x7100,pc+0x28)
            block=cs.disasm(image[ITCM_SOURCE_OFFSET+frompc:ITCM_SOURCE_OFFSET+to],frompc)
            result.append({
                "pc":hex(pc),"m":ins.mnemonic,"op":ins.op_str,
                "likely_count_field_but_base_UNPROVEN":True,
                "context":[{"pc":hex(i.address),"m":i.mnemonic,"op":i.op_str} for i in block],
            })
    return result

def focus_receiver_like_veneers(veneers,callers):
    subset=("0x6013d268","0x6013d270")
    return {
        "candidate_veneer_records":[v for v in veneers if v["pc"] in subset],
        "direct_BL_shapes":[x for x in callers if x["target"] in subset],
        "not_event_reachability":"ALL CALLS ARE INSTRUCTION SHAPES, NOT RUNTIME PATHS",
    }


PRODUCER_PINS={
    0x600926A0:("mov","r1, r0"),
    0x600926A2:("ldr","r0, [pc, #0x10]"),
    0x600926A4:("ldr","r2, [r0, #0x58]"),
    0x600926A6:("cbz","r2, #0x600926ac"),
    0x600926A8:("b.w","#0x600ee18a"),
    0x600EE18A:("push","{r0, r1, r2, r3, r4, lr}"),
    0x600EE18C:("cbnz","r1, #0x600ee196"),
    0x600EE196:("movs","r4, #0"),
    0x600EE198:("movs","r3, #1"),
    0x600EE1A2:("strb","r3, [r1, #8]"),
    0x600EE1AA:("str","r1, [sp, #8]"),
    0x600EE1AC:("ldr.w","r0, [r0, #0xb0]"),
    0x600EE1B0:("add","r1, sp, #4"),
    0x600EE1B2:("strb.w","r4, [sp, #4]"),
    0x600EE1B6:("bl","#0x6013d0e8"),
}
SENDLIKE_VENEERS=(0x6013D0E8,0x6013CFD8)
QUEUE_WRITER_COUNT_PINS={
    0x6CDC:("ldr","r2, [r4, #0x38]"),
    0x6CDE:("ldr","r3, [r4, #0x3c]"),
    0x6CE0:("cmp","r3, r2"),
    0x6CE2:("bls","#0x6d1e"),
    0x6CE8:("adds","r2, #1"),
    0x6CEC:("str","r2, [r4, #0x38]"),
}

def verify_producer_chain(image):
    pins={}
    for start,end in ((0x600926A0,0x600926B2),(0x600EE18A,0x600EE1BE)):
        for row in decode(image,start,end):
            pins[row["pc"]]=(row["m"],row["op"])
    for pc,expected in PRODUCER_PINS.items():
        if pins.get(pc)!=expected:
            raise ValueError(f"Phase75 producer original signed instruction drift {pc:#x}: {pins.get(pc)}")
    if signed_word(image,0x600926B4-BASE)!=QUEUE:
        raise ValueError("Phase75 producer Work Queue object literal drift")
    sender=one(image,0x6013D0E8)
    target=None
    if sender and sender.mnemonic=="ldr.w" and sender.op_str=="pc, [pc, #-0x0]":
        target_word=signed_word(image,0x6013D0EC-BASE)
        target=target_word&~1
        if not target_word&1 or not 0<=target<ITCM_LENGTH:
            raise ValueError("Phase75 sender original ITCM pointer drift")
    else:
        raise ValueError("Phase75 sender original veneer instruction drift")
    return {
        "signed_anchors":len(PRODUCER_PINS)+2,
        "producer_API_entry":"0x600926a0",
        "producer_object_literal":"0x2002014c",
        "producer_state_guard":"0x600926a4 [WorkQueue+0x58] checked before tail branch",
        "worker_entry":"0x600ee18a",
        "worker_input_message":"R1 incoming, stored to [SP+8]; flag at message+8 set to 1",
        "worker_queue_control":"R0 = [WorkQueue+0xb0]",
        "worker_send_buffer":"R1 = SP+4; local byte [SP+4] set zero",
        "worker_timeout":"R2 = -1 at 0x600ee19e",
        "worker_kernel_veneer":"0x6013d0e8",
        "kernel_veneer_raw_thumb":hex(target_word),
        "kernel_original_ITCM_entry":hex(target),
        "object_state_on_physical_hardware":"UNMEASURED",
        "actual_enqueue_or_success":"UNVERIFIED",
    }

def confirm_count_writer(image):
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    rows={}
    start,end=0x6CD8,0x6CF0
    for i in cs.disasm(image[ITCM_SOURCE_OFFSET+start:ITCM_SOURCE_OFFSET+end],start):
        rows[i.address]=(i.mnemonic,i.op_str)
    for pc,expected in QUEUE_WRITER_COUNT_PINS.items():
        if rows.get(pc)!=expected:
            raise ValueError(f"Phase75 signed original count writer drift {pc:#x}")
    return {
        "count_writer_pc":"0x6cec",
        "guarded_capacity_field":"0x3c",
        "item_count_field":"0x38",
        "guard_and_increment_proven_in_signed_code":True,
        "specific_WorkQueue_instance":"NOT_ESTABLISHED_BY_FIELD_OFFSET_ALONE",
    }


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Phase75 original exact SHA-pinned Bruce OEM required")
    windows=signed_windows(image)
    producer=verify_producer_chain(image)
    count=confirm_count_writer(image)
    veneers=inspect_veneers(image)
    literal=queue_literals(image)
    loads=pc_literal_load_candidates(image,literal)
    veneer_pcs={int(v["pc"],16) for v in veneers}
    itcm=xip_target_BL_shapes(image,veneer_pcs)
    known=signed_itcm_BL_targets(image)
    count_sites=inspect_itcm_count_sites(image)
    focused=focus_receiver_like_veneers(veneers,itcm)
    return {
        "phase":75,"original_SHA256_verified":True,"original_SHA256":IMAGE_SHA256,
        "work_queue_RAM_object":hex(QUEUE),
        "work_queue_virtual_control_pointer":hex(CONTROL_FIELD),
        "signed_adjacent_veneers":veneers,
        "verified_WorkQueue_producer_chain":producer,
        "verified_ITCM_count_increment_helper":count,
        "queue_address_words":literal,
        "signed_queue_literal_load_candidates":loads,
        "signed_ITCM_primitive_BL_shapes":known,
        "signed_XIP_BL_shapes_to_neighbor_veneers":itcm,
        "bounded_original_windows":windows,
        "signed_ITCM_count_field_instruction_candidates":count_sites,
        "receiver_neighbor_callers":focused,
        "inference_boundary":{
            "producer_identity":"RESEARCH_IN_PROGRESS",
            "actual_message_in_queue":"NOT_OBSERVED",
            "USB_event_to_enqueue":"UNPROVEN",
            "host_controlled_callback":"UNPROVEN",
            "custom_firmware_execution":"NOT_DEMONSTRATED",
            "HAB_closed_bypass":"NOT_DEMONSTRATED",
            "hardware_traffic":False,
            "flash_or_eFuse_write":False,
        },
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    output=audit(a.image.read_bytes())
    if a.out:a.out.write_text(json.dumps(output,indent=2)+"\n",encoding="utf-8")
    print("PHASE75 VERIFIED WORKQUEUE PRODUCER",json.dumps(output["verified_WorkQueue_producer_chain"]))
    print("PHASE75 VERIFIED COUNT WRITE",json.dumps(output["verified_ITCM_count_increment_helper"]))
    print("PHASE75 SIGNED QUEUE POINTER WORDS",json.dumps(output["queue_address_words"]))
    print("PHASE75 SIGNED QUEUE POINTER LOADS",json.dumps(output["signed_queue_literal_load_candidates"]))
    print("PHASE75 SIGNED QUEUE VENEERS",json.dumps(output["signed_adjacent_veneers"]))
    print("PHASE75 SIGNED ITCM PRIMITIVE CALLS",json.dumps(output["signed_ITCM_primitive_BL_shapes"]))
    print("PHASE75 SIGNED XIP VENEER CALL COUNT",len(output["signed_XIP_BL_shapes_to_neighbor_veneers"]))
    print("PHASE75 SIGNED XIP FOCUSED RECEIVE CALLERS",json.dumps(output["receiver_neighbor_callers"]["direct_BL_shapes"]))
    print("PHASE75 COUNT FIELD CANDIDATES",json.dumps(output["signed_ITCM_count_field_instruction_candidates"]))
    print("PHASE75 RECEIVER NEIGHBOR CALLERS",json.dumps(output["receiver_neighbor_callers"]))
    for label,rows in output["bounded_original_windows"].items():
        print("PHASE75 SIGNED WINDOW",label,json.dumps(rows))
    print("PHASE75 NO PHYSICAL QUEUE OR USB SOURCE PROVEN")

if __name__=="__main__":
    main()
