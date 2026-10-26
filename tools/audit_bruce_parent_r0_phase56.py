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
    (0x60079D72, CALLSITE + 4),
)


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
    return {
        "phase":56, "original_signed_OEM_SHA_verified":True,
        "sha256":IMAGE_SHA256,
        "prior_phase55_pins_verified":previous["pins_verified"],
        "caller_R0_exploration":windows,
        "parent_plus80_reader_census":reads,
        "proven_parent_R0": "UNRESOLVED",
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
    for lo,w in res["caller_R0_exploration"].items():
        print("PHASE56 R0 WINDOW",lo,json.dumps(w))
    cs=res["parent_plus80_reader_census"]
    print("PHASE56 FIELD80 READER CENSUS",json.dumps({k:v for k,v in cs.items() if k not in ("all_read_sites","other_examples")}))
    print("PHASE56 FIELD80 READER EXAMPLES",json.dumps(cs["other_examples"]))
    print("PHASE56 R0 UNKNOWN; NO RUNTIME OR OWNER CFG WRITER CLAIM")


if __name__=="__main__":
    main()
