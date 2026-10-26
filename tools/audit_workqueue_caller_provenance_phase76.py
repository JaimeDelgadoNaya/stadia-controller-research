"""Phase 76: bounded OEM signed provenance for the two Work Queue producers.

This audit identifies original callsite argument formation, source gates and
direct Thumb BL-shaped upstream references. It deliberately does NOT treat a
call graph xref as a verified runtime path, or 'USB-looking' names and nearby
addresses as USB-event provenance.

Exact signed Bruce OEM SHA-256 only. No device access or memory writes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE,ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_queue_producers_phase75 import (
    xip_target_BL_shapes, verify_producer_chain, verify_signed_pipeline,
    BASE, XIP_END
)

CALL_A=0x6006228C
CALL_B=0x6006B2B0
API=0x600926A0
B_ENTRY=0x6006B290
CALL_A_ANCHORS={
    0x6006226A:("mov.w","r2, #1"),
    0x60062272:("ldrexb","r3, [r5]"),
    0x60062276:("strexb","r1, r2, [r5]"),
    0x6006227A:("cmp","r1, #0"),
    0x6006227C:("bne","#0x60062272"),
    0x6006227E:("tst.w","r3, #0xff"),
    0x60062282:("dmb","ish"),
    0x60062286:("bne","#0x60062290"),
    0x60062288:("add.w","r0, r4, #0x10"),
    CALL_A:("bl","#0x600926a0"),
}
CALL_B_ANCHORS={
    B_ENTRY:("push","{r4, lr}"),
    0x6006B292:("mov","r4, r0"),
    0x6006B294:("bl","#0x600d8f64"),
    0x6006B298:("dmb","ish"),
    0x6006B29C:("ldrb.w","r3, [r4, #0x182]"),
    0x6006B2A0:("dmb","ish"),
    0x6006B2A4:("cbnz","r3, #0x6006b2b6"),
    0x6006B2A6:("cbz","r0, #0x6006b2b6"),
    0x6006B2A8:("cmp","r0, #2"),
    0x6006B2AA:("bne","#0x6006b2cc"),
    0x6006B2AC:("add.w","r0, r4, #0x11c"),
    CALL_B:("bl","#0x600926a0"),
    0x6006B2B6:("mov","r0, r4"),
    0x6006B2B8:("bl","#0x600d8ed4"),
}
# Phase 75 supplies the exact original API and downstream send/dispatch checks.
USB_ANCHOR_TARGETS={
    "class10_callback":0x600613FC,
    "class10_secondary":0x600DB028,
    "EP0_class_forwarder":0x600D0E58,
    "class10_initializer":0x60055320,
    "USB_mode_owner":0x60060F84,
    "USB_low_level_driver":0x6005556C,
}
# Do not equate an indirect or cross-function link to direct user triggering.
MAX_CONTEXT_ROWS=80


def rows(image,start,end):
    if not (BASE <= start < end <= BASE+len(image)):
        raise ValueError("Phase76 signed XIP code window outside image")
    return [{"pc":hex(r["pc"]),"mnemonic":r["m"],"operands":r["op"]}
            for r in decode(image,start,end)]


def original_callsite_assertions(image):
    a=rows(image,0x6006226A,0x60062292)
    b=rows(image,B_ENTRY,0x6006B2C0)
    mapping={
        int(r["pc"],16):(r["mnemonic"],r["operands"])
        for r in a+b
    }
    for pc,pin in {**CALL_A_ANCHORS,**CALL_B_ANCHORS}.items():
        if mapping.get(pc)!=pin:
            raise ValueError(
                f"Phase76 signed callsite pin drift {pc:#x}: {mapping.get(pc)!r}"
            )
    return {"site_A_count":len(CALL_A_ANCHORS),
            "site_B_count":len(CALL_B_ANCHORS),
            "total_pins":len(CALL_A_ANCHORS)+len(CALL_B_ANCHORS)}


def signed_producer_argument_paths(image):
    original_callsite_assertions(image)
    return [
        {
            "caller":hex(CALL_A),
            "argument_origin":"R0 = R4+0x10 at 0x60062288",
            "signed_sequence":"LDREXB/STREXB over [R5], then TST previous byte, branch skip on nonzero; direct BL",
            "necessary_local_conditions":[
                "STREXB must report success (retry loop otherwise)",
                "prior [R5] byte tested as zero, otherwise skip producer",
                "valid R4 object assumed by signed code",
            ],
            "object_identity":"UNRESOLVED",
            "host_USB_provenance":"UNPROVEN",
            "execution":"UNVERIFIED",
        },
        {
            "caller":hex(CALL_B),
            "function_entry":hex(B_ENTRY),
            "argument_origin":"R0 = R4+0x11C at 0x6006b2ac",
            "signed_sequence":"BL 0x600d8f64; test [R4+0x182]; CBZ result; CMP result with 2; direct BL",
            "necessary_local_conditions":[
                "[R4+0x182] status must be zero",
                "0x600D8F64 result nonzero and equal to 2",
                "valid R4 object assumed by signed code",
            ],
            "object_identity":"UNRESOLVED",
            "host_USB_provenance":"UNPROVEN",
            "execution":"UNVERIFIED",
        },
    ]


def branch_aware_footprints(image):
    # Deliberately use known block anchor rather than guess that this is
    # the start of caller A's containing function.
    regions={
        "A_previous_signed_fragment":(0x600621F0,0x60062220),
        "A_atomic_tail":(0x60062264,0x60062298),
        "B_exact_function":(B_ENTRY,0x6006B2D8),
        "B_status_callee":(0x600D8F64,0x600D8FCE),
        "B_fallback_callee":(0x600D8ED4,0x600D8F20),
        "B_common_status_helper":(0x600D8E6C,0x600D8ED0),
        "B_status_helper_variant":(0x600D8F24,0x600D8F64),
        "B_callback_pointer_registration":(0x6006B3F8,0x6006B450),
        "B_callback_pointer_reference_neighbor":(0x6006B470,0x6006B4D4),
        "B_status_owner_neighbor":(0x6006B320,0x6006B38A),
        "queue_producer_API":(API,0x600926B2),
        "known_class10_callback":(0x600613FC,0x60061422),
    }
    return {name:rows(image,start,end)[:MAX_CONTEXT_ROWS]
            for name,(start,end) in regions.items()}


def direct_xrefs(image,targets):
    """Instruction-shaped BL edges only; no reachability/CFG assertion."""
    union=xip_target_BL_shapes(image,set(targets.values()))
    return {name:[r for r in union if int(r["target"],16)==address]
            for name,address in targets.items()}


def upstream_census(image):
    targets={
        "producer_call_A_direct_site_function_START_UNKNOWN":CALL_A,
        "producer_call_B_function":B_ENTRY,
        "queue_producer_API":API,
        "B_status_callee":0x600D8F64,
        "B_fallback_callee":0x600D8ED4,
    }
    targets.update(USB_ANCHOR_TARGETS)
    graph=direct_xrefs(image,targets)
    # Bound static intersections explicitly: xref presence does not imply
    # the earlier functions can be reached from USB EP0.
    usb_names=set(USB_ANCHOR_TARGETS)
    # Do not claim an intersection of callers of different functions
    # establishes common execution; just retain summary candidates.
    return {
        "direct_BL_shapes":graph,
        "potential_USB_anchor_intersection":"NOT_ESTABLISHED_BY_DIRECT_XREF_COUNTS",
        "USB_event_to_call_A":"NOT_VERIFIED",
        "USB_event_to_call_B":"NOT_VERIFIED",
        "cross_function_alias_or_indirect_call":"NOT_COVERED",
    }


def aligned_original_code_pointer_refs(image,targets):
    """Exact aligned Thumb-pointer words; static only, never callback proof."""
    inv={addr|1:name for name,addr in targets.items()}
    matches={name:[] for name in targets}
    for off in range(0,len(image)-3,4):
        value=struct.unpack_from("<I",image,off)[0]
        if value in inv:
            matches[inv[value]].append({
                "file_offset":hex(off),
                "pc_if_XIP":hex(BASE+off),
                "value":hex(value),
                "role":"ORIGINAL_SIGNED_LITERAL_NOT_RUNTIME_REACHABILITY",
            })
    return matches


def find_pc_relative_load_to_signed_literal(image,literal_pc,limit=0x480):
    """Bounded Thumb-shaped LDR PC xrefs, neither CFG nor proof of registration."""
    if not(BASE<=literal_pc<=BASE+len(image)-4 and (literal_pc&3)==0):
        raise ValueError("phase76 pointer-literal location invalid")
    from re import fullmatch
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    found=[]
    for pc in range(max(BASE,literal_pc-limit)&~1,literal_pc,2):
        off=pc-BASE
        i=next(cs.disasm(image[off:off+4],pc,count=1),None)
        if i is None or i.mnemonic not in ("ldr","ldr.w"):
            continue
        m=fullmatch(r"(r(?:1[0-2]|[0-9])), \[pc, #(0x[0-9a-f]+|\d+)\]",i.op_str)
        if m and ((pc+4)&~3)+int(m.group(2),0)==literal_pc:
            found.append({
                "pc":hex(pc),
                "instruction":i.mnemonic+" "+i.op_str,
                "value":hex(struct.unpack_from("<I",image,literal_pc-BASE)[0]),
                "literal_pc":hex(literal_pc),
                "execution":"UNVERIFIED",
            })
    return found


def upstream_source_analysis(image):
    targets={
        "B_worker_callback":B_ENTRY,
        "B_status_read":0x600D8F64,
        "B_status_common":0x600D8E6C,
        "B_status_variant":0x600D8F24,
        "B_status_fallback":0x600D8ED4,
    }
    literals=aligned_original_code_pointer_refs(image,targets)
    installs=[find_pc_relative_load_to_signed_literal(image,int(row["pc_if_XIP"],16))
              for row in literals["B_worker_callback"]]
    flattened=[candidate for group in installs for candidate in group]
    if not any(item["pc"]=="0x6006b416" and item["value"]=="0x6006b291"
               for item in flattened):
        raise ValueError("Phase76 signed callback B pointer source loader drift")
    return {
        "aligned_thumb_pointer_words":literals,
        "B_callback_literal_PC_load_candidates":flattened,
        "direct_bl_shapes":direct_xrefs(image,targets),
        "statically_pinned_status_helper_edges":{
            "B_primary":"0x6006b294 BL 0x600d8f64",
            "B_primary_internal":"0x600d8f70 BL 0x600d8e6c; R1=9",
            "B_fallback":"0x6006b2b8 BL 0x600d8ed4",
            "B_fallback_internal":"0x600d8ee2 BL 0x600d8e6c; R1=9",
        },
        "owner_object_of_R4":"UNDETERMINED",
        "USB_EP0_or_class10_provenance":"NOT_DEMONSTRATED",
    }


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Phase76 requires original signed Bruce OEM exact SHA-256")
    # Retain previous exact controls: must fail rather than silently accept
    # a changed signed sample or a variant producer.
    verify_producer_chain(image)
    verify_signed_pipeline(image)
    pins=original_callsite_assertions(image)
    paths=signed_producer_argument_paths(image)
    contexts=branch_aware_footprints(image)
    xrefs=upstream_census(image)
    nested=upstream_source_analysis(image)
    return {
        "phase":76,
        "original_SHA256":IMAGE_SHA256,
        "original_signed_image_verified":True,
        "signed_original_pin_counts":pins,
        "signed_producer_callsites":paths,
        "bounded_signed_contexts":contexts,
        "direct_code_shaped_upstream_references":xrefs,
        "B_nested_status_source_xrefs":nested,
        "limits":{
            "runtime_call_A_executed":False,
            "runtime_call_B_executed":False,
            "physical_USB_event_origin":"UNPROVEN",
            "object_R4_source":"UNRESOLVED",
            "host_controllable_work_item":"UNPROVEN",
            "queue_enqueue_or_dequeue":"NOT_EXECUTED",
            "callback_BLX":"NOT_EXECUTED",
            "HAB_CLOSED_bypass":"NOT_DEMONSTRATED",
            "custom_firmware_execution":"NOT_DEMONSTRATED",
            "physical_commands_or_flash_eFuse_writes":False,
        },
    }


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image",type=Path)
    ap.add_argument("--out",type=Path)
    a=ap.parse_args()
    r=audit(a.image.read_bytes())
    if a.out:a.out.write_text(json.dumps(r,indent=2)+"\n",encoding="utf-8")
    print("PHASE76 ARGUMENT_PATHS",json.dumps(r["signed_producer_callsites"]))
    print("PHASE76 XREFS",json.dumps(r["direct_code_shaped_upstream_references"]))
    print("PHASE76 NESTED_STATUS_SOURCE",json.dumps(r["B_nested_status_source_xrefs"]))
    for label,context in r["bounded_signed_contexts"].items():
        print("PHASE76 WINDOW",label,json.dumps(context))
    print("PHASE76 COMPLETE EVIDENCE",json.dumps(r,separators=(",",":")))
    print("PHASE76 USB HOST CONTROL REMAINS UNPROVEN")

if __name__=="__main__":
    main()
