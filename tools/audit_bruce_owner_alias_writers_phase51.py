"""Phase 51: bounded *signed* owner-base literal xref and field-store analysis.

Original pinned Bruce OEM signed UPDATE only, not a live RAM/flash dump.

Candidate XIP xrefs are validated by PC-relative address arithmetic. A decoded
LDR referring to the actual signed 0x2000A2A8 literal is stronger evidence than
a raw word occurrence, but instructions around literal pools can be incorrectly
linear-decoded. A store relative to owner is emitted only for a *local* straight
line instruction sequence without ambiguous branching, register reassignment
or calls; the result is labelled candidate, not device-runtime proof.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_usb_owner_pointer_phase50 import OWNER,nearby_exact_literals

BASE=ASSUMED_XIP_BASE
TARGET_FIELDS={OWNER+n:label for n,label in (
    (0,"owner_base"),(4,"class_record_pointer"),
    (8,"config_method"),(12,"class_record_count"),
    (16,"mode_byte"),(0x90,"owner_mode"),
    (0x94,"owner_state"),(0x98,"engine_pointer"))}
# Literal pools can contain non-code bytes. Restrict search to a bounded
# backwards window; record every candidate, not only apparent writer.
LDR_PC=re.compile(r"^([a-z][a-z0-9]*), \[pc(?:, #(0x[0-9a-f]+|\d+))?\]$")
MEMOP=re.compile(r"^([a-z][a-z0-9]*), \[([a-z][a-z0-9]*)(?:, #(0x[0-9a-f]+|\d+))?\]!?$")
BL=re.compile(r"^#0x([0-9a-f]+)$")
CONTROL_PREFIXES=("b","cb","tb","pop","bx","it")


def xip_literal_sites(image):
    """Do not manufacture references from a fabricated binary."""
    needle=struct.pack("<I",OWNER)
    return [BASE+off for off in range(0,0xFF000-3,4)
            if image[off:off+4]==needle]


def pc_aligned_value(pc,imm=0):
    return ((pc+4)&~3)+imm


def xref_loads(lines,literal_address):
    """Search only for literal loads whose *computed address* matches."""
    result=[]
    for i,x in enumerate(lines):
        if x["m"] not in ("ldr","ldr.w"):continue
        hit=LDR_PC.match(x["op"])
        if not hit:continue
        reg,imm=hit.groups()
        disp=int(imm,0) if imm is not None else 0
        if pc_aligned_value(x["pc"],disp)==literal_address:
            result.append((i,reg,x))
    return result


def local_field_actions(lines,load_index,base_register):
    """Conservative local straight-line register tracking, never CFG-complete."""
    aliases={base_register:0}
    touched=[]
    for x in lines[load_index+1:]:
        m,op=x["m"],x["op"]
        if m.startswith(CONTROL_PREFIXES) or m in ("bl","blx","svc","udf"):
            break
        mm=MEMOP.match(op)
        if m.startswith(("str","ldr")) and mm:
            src,base,imm=mm.groups()
            if base in aliases and m.startswith("str"):
                offset=aliases[base]+(int(imm,0) if imm else 0)
                touched.append({"pc":hex(x["pc"]),"mnemonic":m,"op":op,
                                "owner_offset":hex(offset),
                                "field":TARGET_FIELDS.get(OWNER+offset,"other"),
                                "classification":"LOCAL_ALIAS_CANDIDATE_NOT_RUNTIME"})
            # Loading into an alias destroys its original pointer value.
            if m.startswith("ldr"):aliases.pop(src,None)
            continue
        op2=[p.strip() for p in op.split(",")]
        if m in ("mov","mov.w") and len(op2)==2 and not op2[1].startswith("#"):
            dst,src=op2
            if src in aliases: aliases[dst]=aliases[src]
            else: aliases.pop(dst,None)
            continue
        if m in ("add","add.w","adds","sub","sub.w","subs") and len(op2)==3:
            dst,src,imm=op2
            if src in aliases and imm.startswith("#"):
                change=int(imm[1:],0)
                aliases[dst]=aliases[src]+change*(-1 if m.startswith("sub") else 1)
            else:
                aliases.pop(dst,None)
            continue
        # Unmodeled updates: fail closed, do not manufacture alias proof.
        if op2 and op2[0] in aliases:
            aliases.pop(op2[0],None)
    return touched


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("exact pinned signed OEM Bruce SHA-256 required")
    sites=xip_literal_sites(image)
    if len(sites)!=16:
        raise ValueError("signed OEM owner base literal census drift")
    code_refs=[]
    for addr in sites:
        start=max(BASE,addr-112)
        # A fixed-start Thumb decoder may start mid-instruction; report both
        # alignments, keep highest-confidence exact PC-derived candidate.
        for parity in (0,2):
            begin=start+parity
            instrs=decode(image,begin,addr)
            for idx,reg,ldr in xref_loads(instrs,addr):
                code_refs.append({
                    "literal_address":hex(addr),
                    "candidate_pc":hex(ldr["pc"]),
                    "destination_register":reg,
                    "decoded_from":hex(begin),
                    "local_stores":local_field_actions(instrs,idx,reg),
                    "certainty":"EXACT_LITERAL_DATA_REFERENCE; CFG/REACHABILITY_UNVERIFIED",
                    "immediate_codelines":[hex(z["pc"])+" "+z["m"]+" "+z["op"]
                         for z in instrs[idx:idx+14]]
                })
    dedup={}
    for q in code_refs:
        key=(q["literal_address"],q["candidate_pc"],q["destination_register"])
        old=dedup.get(key)
        if old is None or len(q["local_stores"])>len(old["local_stores"]):
            dedup[key]=q
    refs=sorted(dedup.values(),key=lambda x:int(x["candidate_pc"],16))
    return {
        "phase":51,"signed_original_sha_verified":True,
        "owner_base":hex(OWNER),"signed_aligned_literal_count":len(sites),
        "literal_PC_derived_load_candidates":len(refs),
        "references":refs,
        "targeted_field_store_candidates":[
            {"literal_address":q["literal_address"],"pc":q["candidate_pc"],
             **st}
            for q in refs for st in q["local_stores"]
            if st["field"] in ("class_record_pointer","config_method","class_record_count")
        ],
        "evidence_boundary":{
            "active_owner_RAM_values":"NOT MEASURED",
            "full_CFG_interprocedural_alias_analysis":False,
            "runtime_class10_selected":"UNVERIFIED",
            "no_host_command_or_firmware_flash":True,
        }
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image",type=Path)
    parser.add_argument("--out",type=Path)
    a=parser.parse_args()
    result=audit(a.image.read_bytes())
    if a.out:a.out.write_text(json.dumps(result,indent=2)+"\n")
    print("PHASE51 OWNER XREF SUMMARY",json.dumps({
        "aligned_signed_literals":result["signed_aligned_literal_count"],
        "PC_derived_candidates":result["literal_PC_derived_load_candidates"],
        "target_field_store_candidates":result["targeted_field_store_candidates"]}))
    for item in result["references"]:
        print("PHASE51 XREF",json.dumps(item))
    print("PHASE51 CLASS10 ACTIVE CONFIG: UNVERIFIED; NO DEVICE I/O")
if __name__=="__main__": main()
