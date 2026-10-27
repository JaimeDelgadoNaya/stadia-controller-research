"""Bounded, SHA-pinned Thumb LDR(SRC_BASE) -> STR [base, #0x38] triage.

This is *syntactic*, without confirmed function boundaries, paths, RAM state,
runtime register values or hardware access. The candidate list is not a
demonstrated writer of SRC_GPR7 or its bit3 update flag.
"""
import argparse
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.arm import ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

from tools.audit_src_gpr7_writers_phase88 import (
    SRC_BASE, SRC_GPR7, audit_public_original, raw_src_constant_census, SAMPLES
)

MAPPED_BASES={"bruce_prod":0x60040000,"restricted_ram_loader":0x20000000}
MAX_INSTRUCTIONS=18
MAX_WINDOW=96


def triage_src_loads(image,boundary,*,mapped_base=0):
    """Conservative straight-line syntactic pattern matching from raw words."""
    hits=raw_src_constant_census(image,boundary)
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    md.detail=True
    candidates=[]
    matches=[]
    for lit in hits:
        if lit["word"] != f"0x{SRC_BASE:08x}":
            continue
        for c in lit["syntactic_thumb_pc_ldr_candidates"]:
            pos=int(c["potential_instruction_file_offset"],16)
            if pos >= boundary or pos+2 > boundary:
                continue
            decoded=list(md.disasm(image[pos:min(pos+MAX_WINDOW,boundary)],
                                   mapped_base+pos,count=MAX_INSTRUCTIONS))
            if not decoded:
                continue
            first=decoded[0]
            if (not first.mnemonic.startswith("ldr") or len(first.operands)<2 or
                    first.operands[0].type!=ARM_OP_REG or
                    first.operands[1].type!=ARM_OP_MEM or
                    first.operands[1].mem.base!=ARM_REG_PC):
                continue
            relative_target=((pos+4)&~3)+first.operands[1].mem.disp
            if relative_target!=int(lit["file_offset"],16):
                continue
            reg=first.operands[0].reg
            record={"literal_file_offset":lit["file_offset"],
                    "syntactic_ldr_file_offset":hex(pos),
                    "initial_ldr_decodes":True,
                    "control_flow_reachability":"UNKNOWN"}
            candidates.append(record)
            cursor=pos+first.size
            for ins in decoded[1:]:
                if ins.address != mapped_base+cursor:
                    break
                if ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL) or ins.group(CS_GRP_RET):
                    break
                if (ins.mnemonic.startswith("str") and len(ins.operands)>=2 and
                    ins.operands[1].type==ARM_OP_MEM and
                    ins.operands[1].mem.base==reg and
                    ins.operands[1].mem.disp==SRC_GPR7-SRC_BASE):
                    matches.append({
                        "literal_file_offset":lit["file_offset"],
                        "possible_ldr_file_offset":hex(pos),
                        "possible_store_file_offset":hex(ins.address-mapped_base),
                        "store_mnemonic":ins.mnemonic,
                        "base_address":f"0x{SRC_BASE:08x}",
                        "destination_if_straightline":f"0x{SRC_GPR7:08x}",
                        "physical_execution_or_bit3_write_proven":False,
                        "instruction_boundary_or_path_verified":False,
                    })
                if reg in ins.regs_access()[1]:
                    break
                cursor+=ins.size
    return {"candidate_literal_ldr_encodings":len(candidates),
            "candidate_load_sites":candidates,
            "syntactic_stores_to_src_gpr7":matches,
            "syntactic_store_count":len(matches),
            "confirmed_reachable_bit3_writers":0,
            "full_original_control_flow_or_rom_writers_included":False,
            "interpretation":"Short local decoding is not a verified instruction boundary, register lifetime across branches, USB trigger or firmware execution."}


def audit(image,sample):
    pinned=audit_public_original(image,sample)
    t=triage_src_loads(image,SAMPLES[sample]["csf"],mapped_base=MAPPED_BASES[sample])
    return {"phase":88,"sample":sample,
            "public_original_sha256":pinned["sha256_verified_whole_original"],
            "counts_by_name":pinned["counts_by_name"],**t,
            "source":"public archived OEM signed image, SHA-256 checked, no device contact"}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image",type=Path)
    ap.add_argument("--sample",required=True,choices=MAPPED_BASES)
    ap.add_argument("--out",type=Path)
    a=ap.parse_args()
    result=audit(a.image.read_bytes(),a.sample)
    data=json.dumps(result,indent=2,ensure_ascii=False)+"\n"
    if a.out:
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(data,encoding="utf-8")
    else:
        print(data,end="")


if __name__=="__main__":
    main()
