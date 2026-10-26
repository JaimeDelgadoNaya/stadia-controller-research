"""Phase56 signed Bruce R0 caller provenance / parent+0x80 reader census.

Entirely offline; sha-pinned original OEM update required. A local linear
decode does not imply a reachable CFG, and generic [reg,#0x80] readers
are NOT linked to the object passed as R0 at 0x60079D84.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE, ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_owner_holder_phase55 import validate_original, OWNER

BASE = ASSUMED_XIP_BASE
SIGNED_XIP_END = BASE + 0xFF000
CALLSITE = 0x60079D84
TARGET = 0x6007EB8C
READER = re.compile(r"^(r(?:1[0-2]|[0-9])|sb|sl|fp|ip), \[(r(?:1[0-2]|[0-9])|sb|sl|fp|ip), #(0x[0-9a-f]+|\d+)\]$")
PROLOGUE_WINDOWS = (
    (0x60079D40, CALLSITE + 4),
    (0x60079D64, CALLSITE + 4),
    (0x60079D6C, CALLSITE + 4),
    (0x60079D74, CALLSITE + 4),
)

R0_ORIGIN_PINS = {
    0x60079D74: ("movs", "r0, #0xa4"),
    0x60079D76: ("bl", "#0x6013d378"),
    0x60079D7A: ("mov", "r3, r5"),
    0x60079D7C: ("ldr", "r2, [pc, #0x54]"),
    0x60079D7E: ("mov", "r4, r0"),
    0x60079D80: ("ldr", "r1, [pc, #0x54]"),
    0x60079D82: ("str", "r6, [sp]"),
    0x60079D84: ("bl", "#0x6007eb8c"),
}


def prove_r0_producer(image):
    """Pin each signed instruction, then track R0 returned by direct BL.

    This proves the static argument dependency. It does NOT establish
    the allocation semantics or absolute value of the BL return.
    """
    rows=decode(image, 0x60079D74, 0x60079D88)
    m={row["pc"]:(row["m"],row["op"]) for row in rows}
    for pc,expected in R0_ORIGIN_PINS.items():
        if m.get(pc)!=expected:
            raise ValueError(f"phase56 OEM R0 source drift {pc:#x}: {m.get(pc)!r}")
    # Explicitly reject unrecognized instructions inserted between the
    # call's return PC and the second BL.
    if set(m)!=set(R0_ORIGIN_PINS):
        raise ValueError("phase56 unexpected caller instructions in R0 dataflow")
    return {
        "producer_call_pc":"0x60079d76",
        "producer_target":"0x6013d378",
        "producer_input_r0_immediate":0xA4,
        "return_r0_preserved_until":"0x60079d84",
        "return_r0_value":"UNKNOWN",
        "owner_argument_r2":"0x2000a2a8 (phase55 literal)",
        "base_saved_r4":"0x60079d7e MOV R4,R0",
        "pinned_original_instructions":len(R0_ORIGIN_PINS),
        "classification":"SIGNED_STATIC_RETURN_PROVENANCE; ALLOCATION_SEMANTICS_NOT_YET_PROVEN",
    }


def resolve_producer_veneer(image):
    """Resolve LDR.W PC literal as data, including startup-relocated ITCM.

    The original startup copies signed bytes from ITCM_SOURCE_OFFSET to
    runtime ITCM address zero. Decode those source bytes with the runtime
    PC, never as flash-XIP code or as a physical device RAM observation.
    """
    entry=0x6013D378
    first=decode(image,entry,entry+4)
    if len(first)!=1 or (first[0]["m"],first[0]["op"])!=("ldr.w","pc, [pc, #-0x0]"):
        raise ValueError("phase56 signed producer veneer opcode drift")
    at=(entry+4)&~3
    off=at-BASE
    ptr=struct.unpack_from("<I",image,off)[0]
    target=ptr&~1
    out={"veneer_entry":hex(entry),"literal_at":hex(at),
         "raw_target_word":hex(ptr),
         "thumb_bit_set":bool(ptr&1),
         "resolved_target":hex(target),
         "target_in_signed_XIP":BASE<=target<SIGNED_XIP_END,
         "target_in_startup_relocated_ITCM":0<=target<ITCM_LENGTH,
         "semantic_role":"UNVERIFIED"}
    if ptr&1 and BASE<=target<SIGNED_XIP_END:
        out["target_source_offset"]=hex(target-BASE)
        out["target_classification"]="signed_XIP"
        out["target_code_window"]=select_original_window(image,target,
                                min(target+0x60,SIGNED_XIP_END))
    elif ptr&1 and 0<=target<ITCM_LENGTH:
        # The signed update startup copies image[ITCM_SOURCE_OFFSET:
        # ITCM_SOURCE_OFFSET+ITCM_LENGTH] to ITCM runtime address zero.
        # Unlike XIP, disassembly must use the *runtime* Thumb PC.
        from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS
        md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
        source=ITCM_SOURCE_OFFSET+target
        limit=min(source+0x100,ITCM_SOURCE_OFFSET+ITCM_LENGTH)
        out["target_source_offset"]=hex(source)
        out["target_classification"]="startup_relocated_ITCM_candidate"
        out["target_code_window"]=[
            {"pc":hex(i.address),"m":i.mnemonic,"op":i.op_str,"ins":i.mnemonic+" "+i.op_str}
            for i in md.disasm(image[source:limit],target)
        ]
    else:
        out["target_classification"]="unknown_or_unmapped"
        out["target_code_window"]=[]
    return out


def reader_focus_windows(image):
    """Show known candidate local neighborhoods; base identity is unknown."""
    anchors=(
        (0x6007E980,0x6007E9B0),
        (0x6007E7DC,0x6007E81C),
        (0x6005B988,0x6005B9C0),
    )
    return [
        {"start":hex(lo),"end":hex(hi),
         "rows":select_original_window(image,lo,hi),
         "known_parent_identity":False}
        for lo,hi in anchors
    ]



ITCM_WRAPPER_PINS={
    0xB532:("push","{r4, lr}"),
    0xB534:("cmp","r0, #0"),
    0xB536:("ite","ne"),
    0xB538:("movne","r4, r0"),
    0xB53A:("moveq","r4, #1"),
    0xB53C:("mov","r0, r4"),
    0xB53E:("bl","#0x8832"),
    0xB542:("cbnz","r0, #0xb552"),
    0xB544:("bl","#0xbbb8"),
    0xB548:("cbnz","r0, #0xb54e"),
    0xB54A:("bl","#0xbb90"),
    0xB54E:("blx","r0"),
    0xB550:("b","#0xb53c"),
    0xB552:("pop","{r4, pc}"),
}


def itcm_rows(image, runtime_start, size):
    """Decode original signed startup-copied bytes at ITCM runtime PC."""
    from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS
    if not 0<=runtime_start<ITCM_LENGTH or runtime_start+size>ITCM_LENGTH:
        raise ValueError("ITCM range outside signed startup copy")
    off=ITCM_SOURCE_OFFSET+runtime_start
    d=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    return [
        {"pc":hex(i.address),"m":i.mnemonic,"op":i.op_str,"ins":i.mnemonic+" "+i.op_str}
        for i in d.disasm(image[off:off+size],runtime_start)
    ]


def verify_itcm_wrapper(image):
    rows=itcm_rows(image,0xB532,0x22)
    ins={int(q["pc"],16):(q["m"],q["op"]) for q in rows}
    for addr,expected in ITCM_WRAPPER_PINS.items():
        if ins.get(addr)!=expected:
            raise ValueError(f"phase56 signed ITCM wrapper drift {addr:#x} {ins.get(addr)!r}")
    return {
        "pins":len(ITCM_WRAPPER_PINS),
        "runtime_entry":"0xb532",
        "source_file_offset":hex(ITCM_SOURCE_OFFSET+0xB532),
        "size_argument_from_caller":164,
        "zero_size_normalized_to":1,
        "forward_to_ITCM":"0x8832 (BL)",
        "successful_nonzero_return":"0xb542 CBNZ R0,#0xB552 followed by POP",
        "fallback_on_zero":"0xb544/0xb54a/0xb54e unknown handler and retry loop",
        "classification":"SIGNED_ALLOCATION_LIKE_WRAPPER; INNER_ROUTINE_SEMANTICS_NOT_INFERRED",
        "inner_target_preview":itcm_rows(image,0x8832,0x70),
    }


def select_original_window(image, low, high):
    """Unverified bounded linear disassembly, not function boundary proof."""
    return [dict(pc=hex(x["pc"]), ins=x["m"]+" "+x["op"],
                 m=x["m"], op=x["op"])
            for x in decode(image, low, high)]


def near_call_r0_writes(rows):
    """Report candidates, including instructions that *invalidate* R0.

    Do not infer the actual R0 across branches, indirect calls, or an
    unseen function boundary. The analysis is an evidence inventory.
    """
    out=[]
    for row in rows:
        pc=int(row["pc"],16)
        if pc >= CALLSITE:
            break
        m=row["m"]
        op=row["op"]
        if m in ("bl","blx"):
            out.append({"pc":row["pc"],"instruction":row["ins"],
                        "r0":"UNTRUSTED_CALL_RETURN"})
        elif re.match(r"^(?:ldr|mov|add|sub|adr|eor|and|orr|mul|rsb|uxt|ldm)",m) and (
            re.match(r"^r0(?:,|\b)",op) or (m.startswith("ldm") and "r0" in op)
        ):
            out.append({"pc":row["pc"],"instruction":row["ins"],
                        "r0":"LOCAL_CANDIDATE_DEFINITION_UNVERIFIED"})
    return out


def offset_reader(m,op,offset=0x80):
    if m not in ("ldr","ldr.w","ldrb","ldrb.w","ldrh","ldrh.w","ldrsb","ldrsh"):
        return None
    match=READER.fullmatch(op)
    if not match or int(match.group(3),0)!=offset:
        return None
    return {"output":match.group(1), "base":match.group(2),
            "width":m.split(".")[0]}


def census(image):
    start=(ITCM_SOURCE_OFFSET+ITCM_LENGTH+1)&~1
    results=[]
    counts={}
    for off in range(start,0xFF000,0x2000):
        lo=BASE+off
        hi=BASE+min(off+0x2000,0xFF000)
        decoded=decode(image,lo,hi)
        for i,row in enumerate(decoded):
            read=offset_reader(row["m"],row["op"])
            if read is None:
                continue
            k=read["width"]
            counts[k]=counts.get(k,0)+1
            results.append({
                "pc":hex(row["pc"]),
                "instruction":row["m"]+" "+row["op"],
                "base_register":read["base"],
                "output_register":read["output"],
                "width":read["width"],
                "area":("caller_neighborhood" if abs(row["pc"]-CALLSITE)<=0x280
                        else "holder_constructor_neighborhood" if abs(row["pc"]-TARGET)<=0x280
                        else "other_XIP"),
                "proven_parent_identity": False,
                "classification":"LINEAR_XIP_INSTRUCTION_CANDIDATE_ONLY",
                "preceding":[hex(t["pc"])+" "+t["m"]+" "+t["op"]
                              for t in decoded[max(0,i-3):i]],
            })
    return {
        "total":len(results),
        "by_opcode":counts,
        "near_caller":[x for x in results if x["area"]=="caller_neighborhood"],
        "near_holder_constructor":[x for x in results if x["area"]=="holder_constructor_neighborhood"],
        "other_examples":[x for x in results if x["area"]=="other_XIP"][:24],
        "all_read_sites":[x["pc"] for x in results],
        "method_warning":"Linear Thumb decode can interpret inline literals as code; all results are candidates."
    }


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("phase56 exact original signed OEM SHA-256 required")
    previous=validate_original(image)
    windows={}
    for lo,hi in PROLOGUE_WINDOWS:
        rows=select_original_window(image,lo,hi)
        windows[hex(lo)]={
            "rows":rows,
            "caller_instruction_present":any(row["pc"]==hex(CALLSITE) and
                       row["ins"]=="bl #0x6007eb8c" for row in rows),
            "r0_definition_candidates":near_call_r0_writes(rows)
        }
    if not windows[hex(0x60079D64)]["caller_instruction_present"]:
        raise ValueError("phase56 0x60079d64 original caller Thumb alignment drift")
    reads=census(image)
    origin=prove_r0_producer(image)
    wrapper=verify_itcm_wrapper(image)
    return {
        "phase":56, "original_signed_OEM_SHA_verified":True,
        "sha256":IMAGE_SHA256,
        "prior_phase55_pins_verified":previous["pins_verified"],
        "caller_R0_exploration":windows,
        "pinned_R0_producer":origin,
        "producer_veneer":resolve_producer_veneer(image),
        "producer_ITCM_wrapper":wrapper,
        "reader_focus_windows":reader_focus_windows(image),
        "parent_plus80_reader_census":reads,
        "proven_parent_R0": "RETURN_VALUE_OF_0x6013D378; NUMERIC_VALUE_UNKNOWN",
        "known_owner_R2":hex(OWNER),
        "links_between_R0_and_readers": "UNPROVEN",
        "owner_cfg_fields_plus4_plus8_plus12": "UNMEASURED",
        "active_class10": "UNVERIFIED",
        "unsigned_execution":"NOT DEMONSTRATED",
        "HAB_CLOSED_bypass":"NOT DEMONSTRATED",
        "physical_USB_requests":False, "flash_efuse_writes":False
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    res=audit(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(res,indent=2)+"\n",encoding="utf-8")
    print("PHASE56 R0 PRODUCER",json.dumps(res["pinned_R0_producer"]))
    print("PHASE56 R0 VENEER",json.dumps(res["producer_veneer"]))
    print("PHASE56 ITCM WRAPPER",json.dumps(res["producer_ITCM_wrapper"]))
    for item in res["reader_focus_windows"]:
        print("PHASE56 READER FOCUS",json.dumps(item))
    for lo,w in res["caller_R0_exploration"].items():
        print("PHASE56 R0 WINDOW",lo,json.dumps(w))
    cs=res["parent_plus80_reader_census"]
    print("PHASE56 FIELD80 READER CENSUS",json.dumps({k:v for k,v in cs.items() if k not in ("all_read_sites","other_examples")}))
    print("PHASE56 FIELD80 READER EXAMPLES",json.dumps(cs["other_examples"]))
    print("PHASE56 R0 IS RETURN FROM 0x6013D378; NUMERIC VALUE AND READER LINKS UNKNOWN")


if __name__=="__main__":
    main()
