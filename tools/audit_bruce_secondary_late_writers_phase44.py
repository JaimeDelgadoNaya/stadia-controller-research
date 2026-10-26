"""Phase 44: hash-pinned read-only signed Bruce callback post-initializer setter census.

A MOVW-offset scan at every Thumb halfword removes the chunk-alignment blind
spot of phase 41 and detects computed addresses (base + 0x3a38/0x3a3c) which
do not embed a whole-word absolute reference. Results are only candidates:
no real control-flow graph, RAM values, alias proof, physical USB or flash I/O.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_OP_REG

from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH
from tools.audit_bruce_class10_secondary_init_phase42 import (
    INIT, GLOBAL_BASE_CANDIDATE, OFF_CALLBACK, OFF_CONTEXT,
)

BASE = ASSUMED_XIP_BASE
# 0xFF000 excludes the signed image authentication metadata at the end.
XIP_END_FILE = 0xFF000
XIP_START_FILE = (ITCM_SOURCE_OFFSET + ITCM_LENGTH + 1) & ~1
OFFSETS = frozenset((OFF_CALLBACK, OFF_CONTEXT))
PINNED_WRITER = 0x60073CEA
MAX_CONTEXT_LINES = 28


def md_thumb():
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    md.detail = True
    return md


def movw_encoding_candidate(hw):
    """Thumb T3 MOVW begins 11110 i 10 0100 (Thumb halfword mask)."""
    return (hw & 0xFBF0) == 0xF240


def decode_movw(md, image, file_off, pc):
    if file_off + 4 > len(image):
        return None
    h = struct.unpack_from("<H", image, file_off)[0]
    if not movw_encoding_candidate(h):
        return None
    ins = tuple(md.disasm(image[file_off:file_off + 4], pc, count=1))
    if len(ins) != 1 or ins[0].size != 4 or ins[0].mnemonic != "movw":
        return None
    ops = ins[0].operands
    if len(ops) != 2 or ops[0].type != ARM_OP_REG or ops[1].type != ARM_OP_IMM:
        return None
    return {"pc": pc, "reg": ins[0].reg_name(ops[0].reg),
            "constant": ops[1].imm, "instruction": ins[0].mnemonic+" "+ins[0].op_str}


def context(image, pc, kind, before=32, after=72):
    # Only independently decoded linear window, not trusted as CFG.
    if kind == "itcm":
        off = ITCM_SOURCE_OFFSET + pc
        startpc = max(0, pc-before)
        endpc = min(ITCM_LENGTH, pc+after)
        data = image[ITCM_SOURCE_OFFSET+startpc:ITCM_SOURCE_OFFSET+endpc]
    else:
        startpc = max(BASE+XIP_START_FILE,pc-before)
        endpc = min(BASE+XIP_END_FILE,pc+after)
        data = image[startpc-BASE:endpc-BASE]
    md=md_thumb()
    rows = list(md.disasm(data,startpc))
    return [hex(i.address)+" "+i.mnemonic+" "+i.op_str for i in rows[:MAX_CONTEXT_LINES]]


def find_offset_builders(image):
    md=md_thumb()
    regions=[
        ("xip",XIP_START_FILE,XIP_END_FILE,lambda off: BASE+off),
        ("itcm",ITCM_SOURCE_OFFSET,ITCM_SOURCE_OFFSET+ITCM_LENGTH,
            lambda off: off-ITCM_SOURCE_OFFSET),
    ]
    candidates=[]
    total_filtered=0
    total_movw=0
    counts_by_offset={}
    for region,start,end,to_pc in regions:
        for pos in range(start,end-3,2):
            h=struct.unpack_from("<H",image,pos)[0]
            if not movw_encoding_candidate(h):
                continue
            total_filtered+=1
            decoded=decode_movw(md,image,pos,to_pc(pos))
            if decoded is None:
                continue
            total_movw+=1
            if decoded["constant"] not in OFFSETS:
                continue
            offset=decoded["constant"]
            counts_by_offset[hex(offset)]=counts_by_offset.get(hex(offset),0)+1
            candidates.append({
                "pc":hex(decoded["pc"]), "file_offset":hex(pos),
                "space":region,"offset":hex(offset),"register":decoded["reg"],
                "instruction":decoded["instruction"],
                "local_linear_context":context(image,decoded["pc"],region),
                "base_pointer_and_store_proven":False,
                "runtime_reachable":False,
                "host_control_proven":False,
            })
    return {
        "movw_first_halfwords_screened":total_filtered,
        "decoded_movw_at_halfword_boundaries":total_movw,
        "target_counts":counts_by_offset,
        "target_sites":candidates,
        "scan_coverage":{
            "xip":[hex(BASE+XIP_START_FILE),hex(BASE+XIP_END_FILE)],
            "itcm_runtime":[hex(0),hex(ITCM_LENGTH)]
        },
        "blind_spots":[
            "MOVT, ADD.W, LDR literals and computed register aliases can build the same address without MOVW",
            "Disassembly at every halfword includes possible non-code bytes",
            "Local context is not a verified control-flow path",
            "Stores can occur with a pointer passed from another function, DMA or interrupt",
        ],
    }


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("exact SHA-256 pinned OEM Bruce update required")
    res=find_offset_builders(image)
    if not any(x["pc"]==hex(PINNED_WRITER) and x["offset"]==hex(OFF_CALLBACK)
               for x in res["target_sites"]):
        raise ValueError("Original signed global callback initializer MOVW not found")
    return {
        "phase":44,
        "signed_oem_original_sha256_verified":True,
        "image_is_installed_flash_readback":False,
        "global_base":hex(GLOBAL_BASE_CANDIDATE),
        "secondary_callback_slot":hex(GLOBAL_BASE_CANDIDATE+OFF_CALLBACK),
        "secondary_context_slot":hex(GLOBAL_BASE_CANDIDATE+OFF_CONTEXT),
        "previously_confirmed_startup_initializer":{
            "function":hex(INIT),"offset_builder":hex(PINNED_WRITER),
            "setter":"0x60073cf4", "context_zero_setter":"0x60073cfc",
        },
        "offset_builder_census":res,
        "post_initializer_setter_proven":False,
        "host_controlled_setter_proven":False,
        "console_compatible_custom_firmware_proven":False,
        "physical_controller_touched":False,
        "flash_or_efuses_written":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    report=audit(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(report,indent=2)+"\n")
    census=report["offset_builder_census"]
    print("PHASE44 MOVW OFFSET COUNTS",json.dumps({
        "total_candidate_encodings":census["movw_first_halfwords_screened"],
        "total_movw":census["decoded_movw_at_halfword_boundaries"],
        "target_counts":census["target_counts"],
    }))
    for site in census["target_sites"]:
        print("PHASE44 OFFSET BUILDER",json.dumps(site))
    print("PHASE44 HOST CONTROL: UNVERIFIED")

if __name__=="__main__":
    main()
