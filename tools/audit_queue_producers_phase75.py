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
        "xip_queue_object_methods":(0x60092698,0x600926D0,False),
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

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Phase75 original exact SHA-pinned Bruce OEM required")
    windows=signed_windows(image)
    veneers=inspect_veneers(image)
    literal=queue_literals(image)
    loads=pc_literal_load_candidates(image,literal)
    veneer_pcs={int(v["pc"],16) for v in veneers}
    itcm=xip_target_BL_shapes(image,veneer_pcs)
    known=signed_itcm_BL_targets(image)
    return {
        "phase":75,"original_SHA256_verified":True,"original_SHA256":IMAGE_SHA256,
        "work_queue_RAM_object":hex(QUEUE),
        "work_queue_virtual_control_pointer":hex(CONTROL_FIELD),
        "signed_adjacent_veneers":veneers,
        "queue_address_words":literal,
        "signed_queue_literal_load_candidates":loads,
        "signed_ITCM_primitive_BL_shapes":known,
        "signed_XIP_BL_shapes_to_neighbor_veneers":itcm,
        "bounded_original_windows":windows,
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
    print("PHASE75 SIGNED QUEUE POINTER WORDS",json.dumps(output["queue_address_words"]))
    print("PHASE75 SIGNED QUEUE POINTER LOADS",json.dumps(output["signed_queue_literal_load_candidates"]))
    print("PHASE75 SIGNED QUEUE VENEERS",json.dumps(output["signed_adjacent_veneers"]))
    print("PHASE75 SIGNED ITCM PRIMITIVE CALLS",json.dumps(output["signed_ITCM_primitive_BL_shapes"]))
    print("PHASE75 SIGNED XIP VENEER CALLS",json.dumps(output["signed_XIP_BL_shapes_to_neighbor_veneers"]))
    for label,rows in output["bounded_original_windows"].items():
        print("PHASE75 SIGNED WINDOW",label,json.dumps(rows))
    print("PHASE75 NO PHYSICAL QUEUE OR USB SOURCE PROVEN")

if __name__=="__main__":
    main()
