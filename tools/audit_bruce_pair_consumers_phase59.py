"""Phase59: signed RAM callback/context pair use-sites and ITCM worker.

Offline, SHA-pinned original Bruce OEM binary. Scans for exact aligned
literal references to the known RAM pair, recovers compatible *candidate*
Thumb PC-relative literal loads (not a CFG proof), inspects bounded
register/use neighborhoods, and disassembles the signed startup-relocated
ITCM worker entered via the 0xA9C5 pointer. Never invokes any callback.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_field80_helper_phase58 import backend_pair_provenance

BASE=ASSUMED_XIP_BASE
IMAGE_XIP_LIMIT=0xFF000
PAIR_BASE=0x2000F878
PAIR_FIRST=0x2000FBF4
PAIR_SECOND=0x2000FBF8
CALLBACK_ITCM=0xB980
POINTERS=(PAIR_BASE,PAIR_FIRST,PAIR_SECOND)
PINNED_ITCM_WRAPPER={
    0xA9C4:("b.w","#0xb980"),
}
LITERAL_OP=re.compile(r"^(r(?:1[0-2]|[0-9])|ip), \[pc, #(?:(0x[0-9a-f]+)|(\d+))\]$")

def unsigned_word(image,offset):
    if offset<0 or offset%4 or offset+4>len(image):
        raise ValueError("phase59 aligned signed-image literal required")
    return struct.unpack_from("<I",image,offset)[0]


def scan_aligned_literals(image, targets=POINTERS):
    """Exact pointer equality in signed bytes, no execution proof."""
    hits=[]
    lookup=set(targets)
    for off in range(0,len(image)-3,4):
        value=unsigned_word(image,off)
        if value in lookup:
            in_itcm=ITCM_SOURCE_OFFSET<=off<ITCM_SOURCE_OFFSET+ITCM_LENGTH
            hits.append({
                "image_offset":hex(off),
                "value":hex(value),
                "code_region":"ITCM_COPY" if in_itcm else "XIP_OR_DATA",
                "literal_runtime_pc":hex(off-ITCM_SOURCE_OFFSET) if in_itcm
                                     else hex(BASE+off),
                "classification":"SIGNED_ALIGNED_WORD_NOT_EXECUTION_PROOF",
            })
    return hits


def pc_ldr_candidate(image,pc,source_offset,relocated):
    """Decode exactly one Thumb opcode; do not infer CFG reachability."""
    dec=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    rows=list(dec.disasm(image[source_offset:source_offset+4],pc,count=1))
    if len(rows)!=1:
        return None
    r=rows[0]
    if r.mnemonic not in ("ldr","ldr.w"):
        return None
    m=LITERAL_OP.fullmatch(r.op_str)
    if not m:
        return None
    imm=int(m.group(2) or m.group(3),0)
    target=((pc+4)&~3)+imm
    return {
        "pc":hex(pc),"instruction":r.mnemonic+" "+r.op_str,
        "loaded_register":m.group(1),
        "literal_pc":hex(target),
        "source_file_offset":hex(source_offset),
        "execution_domain":"ITCM" if relocated else "XIP",
        "runtime_proven":"UNVERIFIED",
    }


def recover_signed_literal_loads(image,hits,back_bytes=0x100):
    """Search bounded prior PCs; false positives may include inline data."""
    found=[]
    seen=set()
    for hit in hits:
        addr=int(hit["literal_runtime_pc"],16)
        is_itcm=hit["code_region"]=="ITCM_COPY"
        region_start=0 if is_itcm else BASE
        # source and runtime relationship is exactly known for startup ITCM
        for pc in range(max(region_start,addr-back_bytes)&~1,addr,2):
            source=ITCM_SOURCE_OFFSET+pc if is_itcm else pc-BASE
            if source<0 or source+4>len(image):
                continue
            r=pc_ldr_candidate(image,pc,source,is_itcm)
            if r and int(r["literal_pc"],16)==addr:
                key=(r["pc"],hit["value"])
                if key not in seen:
                    seen.add(key)
                    found.append({**r,"loaded_value":hit["value"]})
    return sorted(found,key=lambda q:(q["execution_domain"],int(q["pc"],16)))


def follow_load_neighborhood(image,load,span=0x90):
    """Bounded forward linear decoded view, NOT path-sensitive alias proof."""
    pc=int(load["pc"],16)
    is_itcm=load["execution_domain"]=="ITCM"
    off=ITCM_SOURCE_OFFSET+pc if is_itcm else pc-BASE
    bound=min(span,ITCM_LENGTH-pc if is_itcm else IMAGE_XIP_LIMIT-(pc-BASE))
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    rows=[]
    for r in md.disasm(image[off:off+bound],pc):
        if len(rows)>=42:
            break
        rows.append({"pc":hex(r.address),"m":r.mnemonic,"op":r.op_str})
        if r.mnemonic in ("bx","pop") and ("lr" in r.op_str or "pc" in r.op_str):
            break
    return {
        "seed_pc":load["pc"],
        "loaded_value":load["loaded_value"],
        "loaded_register":load["loaded_register"],
        "rows":rows,
        "reachable":"UNPROVEN",
        "same_pair_read":"UNPROVEN",
    }


def itcm_code(image,at,size=0x130):
    if at<0 or at+size>ITCM_LENGTH:
        raise ValueError("phase59 original ITCM worker outside startup copy")
    off=ITCM_SOURCE_OFFSET+at
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    return [{"pc":hex(i.address),"m":i.mnemonic,"op":i.op_str}
            for i in md.disasm(image[off:off+size],at)]


PAIR_MEM_REGEXP=re.compile(
    r"\[(r(?:1[0-2]|[0-9])|ip|sb|sl|fp), #(0x[0-9a-f]+|\d+)\]"
)
PAIR_IMMEDIATES={0x37C,0x380}


def scan_field_offset_ops(image,span=0x1000):
    """Find XIP and relocated ITCM instructions using pair-field offsets.

    This is a *linear* decoder scan. It does not prove the base register
    contains the global pointer or that a matching instruction is executable.
    """
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    rows=[]
    domains=[
        ("XIP",0xC800,IMAGE_XIP_LIMIT,BASE,0),
        ("ITCM",0,ITCM_LENGTH,0,ITCM_SOURCE_OFFSET),
    ]
    for name,start,end,pcbase,sourcebase in domains:
        for begin in range(start,end,span):
            stop=min(begin+span,end)
            data=image[sourcebase+begin:sourcebase+stop]
            for inst in decoder.disasm(data,pcbase+begin):
                hit=PAIR_MEM_REGEXP.search(inst.op_str)
                if not hit or int(hit.group(2),0) not in PAIR_IMMEDIATES:
                    continue
                rows.append({
                    "pc":hex(inst.address),
                    "source_file_offset":hex(sourcebase+begin+(inst.address-(pcbase+begin))),
                    "m":inst.mnemonic,"op":inst.op_str,"base_reg":hit.group(1),
                    "field_offset":hex(int(hit.group(2),0)),
                    "domain":name,
                    "classification":"LINEAR_OFFSET_MATCH; OBJECT_BASE_UNKNOWN",
                })
    return rows


def halfword_field_scan(image):
    """Exhaustive *instruction-shaped* halfword scan of signed code ranges.

    Unlike stream decode, restart Capstone on each possible Thumb-aligned
    opcode. This catches the known writer even when linear disassembly
    loses synchronization near literal tables, but includes speculative
    non-code hits. Every hit must still be assigned a known object base.
    """
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    matches=[]
    for domain,origin,end,base,source in (
        ("XIP",0xC800,IMAGE_XIP_LIMIT,BASE,0),
        ("ITCM",0,ITCM_LENGTH,0,ITCM_SOURCE_OFFSET),
    ):
        for off in range(origin,end-3,2):
            raw=image[source+off:source+off+4]
            if len(raw)!=4:
                continue
            item=next(md.disasm(raw,base+off,count=1),None)
            if item is None:
                continue
            op=item.op_str
            if "#0x37c" not in op and "#0x380" not in op:
                continue
            m=PAIR_MEM_REGEXP.search(op)
            if m is None or int(m.group(2),0) not in PAIR_IMMEDIATES:
                continue
            matches.append({
                "pc":hex(item.address),"m":item.mnemonic,"op":op,
                "region":domain,"base_reg":m.group(1),
                "offset":hex(int(m.group(2),0)),
                "source_file_offset":hex(source+off),
                "classification":"THUMB_SHAPED_MAY_BE_DATA; NO_BASE_PROVEN",
            })
    sites={x["pc"] for x in matches}
    if not {"0x60063878","0x6006387e"}.issubset(sites):
        raise ValueError("phase59 halfword scan missed two known signed writer controls")
    return matches


def resolve_itcm_trampoline(image,entry=CALLBACK_ITCM):
    """Stop at Thumb LDR.W PC and read the following signed word as data.

    A veneer is 4 bytes of instruction + a 4-byte literal; decoding both
    as executable instructions produces spurious code and false conclusions.
    """
    ins=itcm_code(image,entry,4)
    if len(ins)!=1 or (ins[0]["m"],ins[0]["op"])!=(
            "ldr.w","pc, [pc, #-0x0]"):
        raise ValueError("phase59 signed ITCM B980 veneer instruction drift")
    src=ITCM_SOURCE_OFFSET+entry+4
    raw=unsigned_word(image,src)
    target=raw&~1
    if raw&1 and BASE<=target<BASE+IMAGE_XIP_LIMIT:
        classification="SIGNED_XIP_POINTER"
        code=[{"pc":hex(r["pc"]),"m":r["m"],"op":r["op"]}
              for r in decode(image,target,target+0x90)[:38]]
    elif raw&1 and target<ITCM_LENGTH:
        classification="STARTUP_RELOCATED_ITCM_POINTER"
        code=itcm_code(image,target,0x90)[:38]
    else:
        classification="OUT_OF_KNOWN_CODE_RANGE_OR_NON_THUMB"
        code=[]
    return {
        "veneer_PC":hex(entry),
        "original_file_instruction_offset":hex(ITCM_SOURCE_OFFSET+entry),
        "original_file_literal_offset":hex(src),
        "raw_target_word":hex(raw),
        "target_thumb_PC":hex(target),
        "target_classification":classification,
        "target_code_preview":code,
        "physical_execution":"UNVERIFIED",
    }


FOLLOWUP_WINDOWS={
    "lone_0x380_load_context":(0x600BD100,0x600BD158),
    "other_0x380_store_context":(0x6005BCDC,0x6005BD0E),
    "alternate_pair_store_context":(0x60076856,0x600768A0),
    "ITCM_callback_XIP_worker":(0x6007E6A0,0x6007E790),
}


def focused_signed_windows(image):
    result={}
    for name,(lo,hi) in FOLLOWUP_WINDOWS.items():
        result[name]=[
            {"pc":hex(i["pc"]),"m":i["m"],"op":i["op"]}
            for i in decode(image,lo,hi)
        ]
    return result


def classify_direct_reader_evidence(matches):
    """Do not confuse offset match with verified global-base provenance."""
    loads=[r for r in matches if r["m"].startswith("ldr")]
    # This list is intentionally *not* upgraded by a guessed Rn identity.
    return {
        "raw_thumb_shape_matches":len(matches),
        "direct_load_shapes":[{"pc":r["pc"],"instruction":r["m"]+" "+r["op"],
                               "base_proven_global":False} for r in loads],
        "literal_0x2000fbf4_or_fbf8_detected":"UNVERIFIED_BY_THIS_VALUE_ONLY",
        "pair_function_invocation":"NOT DEMONSTRATED",
        "negative_scope":"only one-instruction immediate offsets 0x37c/0x380",
        "other_alias_or_indirect_offsets":"NOT EXCLUDED",
    }


LONE_READER_PINS={
    0x600BD128:("ldr","r2, [pc, #0x1c]"),
    0x600BD12C:("strb.w","r3, [r2, #0x380]"),
    0x600BD136:("ldr","r3, [pc, #0x10]"),
    0x600BD138:("ldrb.w","r3, [r3, #0x380]"),
}


def lone_reader_literal_identity(image):
    """Prove or disprove same *literal* global base for the only load shape.

    This does not exclude other computed pointer aliases. Inline literal
    0x600BD148 must be treated as DATA, not the following Thumb code.
    """
    rows=decode(image,0x600BD128,0x600BD13C)
    mapping={r["pc"]:(r["m"],r["op"]) for r in rows}
    for pc,expect in LONE_READER_PINS.items():
        if mapping.get(pc)!=expect:
            raise ValueError(f"phase59 signed lone-load pin drift {pc:#x}")
    p1=((0x600BD128+4)&~3)+0x1C
    p2=((0x600BD136+4)&~3)+0x10
    if p1!=p2 or p1!=0x600BD148:
        raise ValueError("phase59 PC-relative base arithmetic drift")
    actual=unsigned_word(image,p1-BASE)
    return {
        "signed_pins":len(LONE_READER_PINS),
        "shared_literal_address":hex(p1),
        "shared_source_global_base":hex(actual),
        "target_pair_global_base":hex(PAIR_BASE),
        "same_literal_base_as_target":actual==PAIR_BASE,
        "load_PC":"0x600bd138",
        "store_PC":"0x600bd12c",
        "known_static_alias_result":"SAME_LITERAL" if actual==PAIR_BASE
                                    else "DIFFERENT_LITERAL",
        "indirect_or_runtime_aliases":"NOT EXCLUDED",
    }


def original_check(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("phase59 exact signed Bruce OEM SHA-256 required")
    parent=backend_pair_provenance(image)
    if (int(parent["first_word_destination"],16),
        int(parent["second_word_destination"],16))!=(PAIR_FIRST,PAIR_SECOND):
        raise ValueError("phase59 signed pair destinations changed")
    pin=decode(image,0x60063874,0x60063880)
    if not any(r["pc"]==0x60063878 and r["op"]=="r2, [r3, #0x37c]" for r in pin):
        raise ValueError("phase59 writer original positive control missing")
    worker=itcm_code(image,0xA9C4,4)
    if [(r["m"],r["op"]) for r in worker]!=[("b.w","#0xb980")]:
        raise ValueError("phase59 signed ITCM worker target drift")
    return parent


def audit(image):
    parent=original_check(image)
    hits=scan_aligned_literals(image)
    loads=recover_signed_literal_loads(image,hits)
    neighborhoods=[follow_load_neighborhood(image,l) for l in loads]
    worker_veneer=resolve_itcm_trampoline(image)
    paired_offsets=scan_field_offset_ops(image)
    halfwords=halfword_field_scan(image)
    focus=focused_signed_windows(image)
    lone=lone_reader_literal_identity(image)
    evidence=classify_direct_reader_evidence(halfwords)
    return {
        "phase":59,"SHA256_signed_original_verified":True,
        "original_SHA256":IMAGE_SHA256,
        "known_signed_pair":{
            "base":parent["global_base"],
            "function_field":parent["first_word_destination"],
            "context_field":parent["second_word_destination"],
            "code_paths":"phase58 signed code writes, runtime not measured",
        },
        "exact_aligned_RAM_literal_hits":hits,
        "PC_relative_literal_load_candidates":loads,
        "bounded_candidate_neighborhoods":neighborhoods,
        "relocated_ITCM_veneer":worker_veneer,
        "matching_pair_field_access_candidates":paired_offsets,
        "complete_halfword_offset_candidates":halfwords,
        "direct_reader_evidence":evidence,
        "focused_signed_windows":focus,
        "lone_load_base_identity":lone,
        "open_questions":{
            "pair_read_and_indirect_invocation":"UNPROVEN_FROM_LITERAL_SCAN",
            "USB_host_trigger":"UNPROVEN",
            "runtime_RAM_pair_values":"UNMEASURED",
            "class10_active":"UNVERIFIED",
            "unsigned_firmware":"NOT DEMONSTRATED",
            "HAB_CLOSED_bypass":"NOT DEMONSTRATED",
        },
        "safety":{"USB_requests":False,"live_RAM_read":False,
                  "flash_writes":False,"efuse_writes":False}
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image",type=Path)
    parser.add_argument("--out",type=Path)
    args=parser.parse_args()
    output=audit(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(output,indent=2)+"\n",encoding="utf-8")
    print("PHASE59 PAIR LITERALS",json.dumps(output["exact_aligned_RAM_literal_hits"]))
    print("PHASE59 LOAD CANDIDATES",json.dumps(output["PC_relative_literal_load_candidates"]))
    for row in output["bounded_candidate_neighborhoods"]:
        print("PHASE59 LOAD WINDOW",json.dumps(row))
    print("PHASE59 ITCM B980 VENEER",json.dumps(output["relocated_ITCM_veneer"]))
    print("PHASE59 PAIR-FIELD OFFSET CANDIDATES",json.dumps(output["matching_pair_field_access_candidates"]))
    print("PHASE59 HALFWORD FIELD SCAN",json.dumps(output["complete_halfword_offset_candidates"]))
    print("PHASE59 DIRECT READER EVIDENCE",json.dumps(output["direct_reader_evidence"]))
    print("PHASE59 LONE READ BASE",json.dumps(output["lone_load_base_identity"]))
    for name,rows in output["focused_signed_windows"].items():
        print("PHASE59 FOCUSED WINDOW",name,json.dumps(rows))
    print("PHASE59 NO USB HOST TRIGGER OR CUSTOM CODE EXECUTION PROOF")


if __name__=="__main__":
    main()
