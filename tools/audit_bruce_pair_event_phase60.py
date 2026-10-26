"""Phase 60: bounded pair-global computed aliases and event-source xrefs.

Verify original signed Bruce OEM SHA-256. Follow PC-relative global-base
loads *only within straight-line instruction runs* until branch/call, and
report calculated accesses to exact pair addresses. Independently census
direct code references and literal words for the signed handler/veneers.
None of these checks observes installed RAM, USB traffic or live invocation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS

from tools.audit_signed_app_surface import (
    IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE, decode_thumb_bl_target,
)
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH
from tools.audit_bruce_pair_consumers_phase59 import (
    PAIR_BASE, PAIR_FIRST, PAIR_SECOND, REAL_HANDLER_XIP,
    original_check, scan_aligned_literals, recover_signed_literal_loads,
    resolve_itcm_trampoline, pin_real_handler,
)

BASE=ASSUMED_XIP_BASE
XIP_LIMIT=0xFF000
VENEEER_XIP=0x600CE232
ITCM_WRAPPER=0xA9C4
ITCM_TRAMPOLINE=0xB980
THUMB_TARGETS=(REAL_HANDLER_XIP, VENEEER_XIP, ITCM_WRAPPER, ITCM_TRAMPOLINE)
PAIR_FIELDS={PAIR_FIRST,PAIR_SECOND}
REG=r"(?:r(?:1[0-2]|[0-9])|ip|sp|lr)"
MEM_RE=re.compile(r"\[("+REG+r"), #(?P<imm>0x[0-9a-f]+|\d+)\]")
MOVE_RE=re.compile(r"^("+REG+r"), ("+REG+r")$")
ARITH_RE=re.compile(r"^("+REG+r"), ("+REG+r"), #(0x[0-9a-f]+|\d+)$")
KILL_FIRST={"ldr","ldrb","ldrh","ldrsb","ldrsh","mov","movs","movw",
           "movt","add","addw","adds","sub","subw","subs",
           "orr","and","eor","bic","lsl","lsr","asr","uxtb","uxth","mul"}
STORE_NAMES={"str","strb","strh","strd","stm","stmdb","str.w","strb.w"}


def dec_one(image,pc,itcm=False):
    src=ITCM_SOURCE_OFFSET+pc if itcm else pc-BASE
    if src<0 or src+4>len(image):
        return None
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    return next(cs.disasm(image[src:src+4],pc,count=1),None)


def run_local_alias(image,loader,span=0x120):
    """No branch merge, no call-preservation assumption, no dynamic alias.

    The seed is the original PC-relative LDR of the exact global base;
    a Thumb-shaped decoder hit may still be embedded data. Keep
    potential code entry separate from verified runtime execution.
    """
    reg=loader["loaded_register"]
    pc=int(loader["pc"],16)
    itcm=loader["execution_domain"]=="ITCM"
    alias={reg:PAIR_BASE}
    accesses=[]
    insns=[]
    for _ in range(span//2):
        row=dec_one(image,pc,itcm)
        if row is None:
            break
        nm,op=row.mnemonic,row.op_str
        stem=nm.split(".")[0]
        insns.append({"pc":hex(pc),"m":nm,"op":op})
        if len(insns)>90:
            break
        if len(insns)>1 and (
            stem in ("b","bl","blx","bx","cbz","cbnz","tbb","tbh","pop")
            or (stem.startswith("b") and stem not in ("bic",))
            or stem.startswith("it")
        ):
            break
        mem=MEM_RE.search(op)
        if mem and stem.startswith(("ldr","str")):
            base=mem.group(1)
            disp=int(mem.group("imm"),0)
            if base in alias:
                absolute=alias[base]+disp
                if absolute in PAIR_FIELDS:
                    accesses.append({
                        "pc":hex(pc),
                        "instruction":nm+" "+op,
                        "absolute_address":hex(absolute),
                        "read":stem.startswith("ldr"),
                        "classification":"LOCAL_STRAIGHT_LINE_STATIC_ALIAS",
                    })
        # Treat destination writes to tracked registers conservatively.
        dest=op.split(",",1)[0].strip()
        if stem in ("mov","movs"):
            mm=MOVE_RE.fullmatch(op)
            if mm and mm.group(2) in alias:
                alias[mm.group(1)]=alias[mm.group(2)]
            elif dest in alias:
                del alias[dest]
        elif stem in ("add","addw","sub","subw"):
            mm=ARITH_RE.fullmatch(op)
            if mm and mm.group(2) in alias:
                step=int(mm.group(3),0)
                alias[mm.group(1)]=alias[mm.group(2)]+(
                  step if stem.startswith("add") else -step
                )
            elif dest in alias:
                del alias[dest]
        elif stem in KILL_FIRST and dest in alias and not (
            len(insns)==1 and stem=="ldr"
        ):
            del alias[dest]
        pc+=row.size
    return {
        "entry_PC":loader["pc"],
        "source_literal_value":loader["loaded_value"],
        "signed_code_candidate":True,
        "runtime_reachability":"UNVERIFIED",
        "bounded_alias_pair_accesses":accesses,
        "sample_decoded_rows":insns[:30],
        "scope":"single local linear path; any branch/call stops analysis",
    }


def scan_target_pointer_literals(image):
    target_ptrs={pc|1 for pc in THUMB_TARGETS}
    items=[]
    for off in range(0,len(image)-3,4):
        val=struct.unpack_from("<I",image,off)[0]
        if val in target_ptrs:
            items.append({"file_offset":hex(off),
                          "word":hex(val),
                          "signed_original_literal_only":True})
    return items


def scan_direct_bl_shapes(image):
    """Full signed code-range scan of 32-bit Thumb BL *shapes*.

    Not a CFG and not exhaustive for indirect BX/BLX or table callbacks.
    """
    hits=[]
    wanted=set(THUMB_TARGETS)
    for domain,lo,hi,base,source in (
        ("XIP",0xC800,XIP_LIMIT,BASE,0),
        ("ITCM",0,ITCM_LENGTH,0,ITCM_SOURCE_OFFSET),
    ):
        for off in range(lo,hi-3,2):
            src=source+off
            try:
                target=decode_thumb_bl_target(
                    image,src,base=(base-source)
                )
            except ValueError:
                continue
            if target in wanted:
                hits.append({"domain":domain,"pc":hex(base+off),
                             "target":hex(target),
                             "code_reachability":"UNVERIFIED"})
    return hits


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("phase60 exact original signed Bruce OEM SHA-256 required")
    original_check(image)
    veneer=resolve_itcm_trampoline(image)
    handler=pin_real_handler(image,veneer)
    loaders=recover_signed_literal_loads(image,scan_aligned_literals(image))
    base_loaders=[r for r in loaders if int(r["loaded_value"],16)==PAIR_BASE]
    local=[run_local_alias(image,seed) for seed in base_loaders]
    if len(base_loaders)!=10:
        raise ValueError("phase60 signed base-reference loader count drift")
    proven_writes={
        (item["pc"],item["absolute_address"])
        for row in local for item in row["bounded_alias_pair_accesses"]
        if not item["read"]
    }
    required_writes={
        ("0x60063878",hex(PAIR_FIRST)),
        ("0x6006387e",hex(PAIR_SECOND)),
    }
    if not required_writes.issubset(proven_writes):
        raise ValueError("phase60 signed pair writer positive controls missing")
    pointers=scan_target_pointer_literals(image)
    direct=scan_direct_bl_shapes(image)
    ptr_counts={}
    for item in pointers:
        v=item["word"]
        ptr_counts[v]=ptr_counts.get(v,0)+1
    if ptr_counts.get(hex(REAL_HANDLER_XIP|1),0)!=1 or (
        ptr_counts.get(hex(ITCM_WRAPPER|1),0)!=1
    ):
        raise ValueError("phase60 signed callback-target literals drift")
    return {
        "phase":60,
        "original_signed_SHA256_verified":True,
        "original_signed_SHA256":IMAGE_SHA256,
        "pair":{"base":hex(PAIR_BASE),"function":hex(PAIR_FIRST),
                "context":hex(PAIR_SECOND)},
        "signed_handler":handler,
        "signed_handler_veneer":veneer["raw_target_word"],
        "base_loader_count":len(base_loaders),
        "local_alias_seed_analyses":local,
        "local_alias_read_count":sum(
            len([x for x in r["bounded_alias_pair_accesses"] if x["read"]])
            for r in local
        ),
        "signed_pair_writer_positive_controls":sorted([{"pc":pc,"address":dest}
                         for pc,dest in proven_writes if (pc,dest) in required_writes],
                         key=lambda r:r["pc"]),
        "handler_pointer_literals":pointers,
        "handler_literal_value_counts":ptr_counts,
        "direct_BL_shape_hits":direct,
        "decision":{
            "pair_is_actionable_host_execution_candidate":False,
            "basis":"no proven pair reader/invocation, no signed direct BL to studied entries, no USB host provenance in bounded audit",
            "status":"DEPRIORITIZE_THIS_HYPOTHESIS; NOT A PROOF OF IMPOSSIBILITY",
            "follow_up":"Prefer passive hardware USB descriptor capture or investigate other control paths without flash/eFuse writes",
        },
        "limits":{
            "calculated_aliases_across_calls":"NOT COVERED",
            "branch_path_merges":"NOT COVERED",
            "indirect_callback_loads":"NOT PROVEN",
            "runtime_pair_read":"NOT OBSERVED",
            "USB_origin":"NOT DEMONSTRATED",
            "host_controlled_pointers":"NOT DEMONSTRATED",
            "HAB_CLOSED_bypass":"NOT DEMONSTRATED",
            "custom_firmware_execution":"NOT DEMONSTRATED",
        },
        "safety":{"physical_USB_commands":False,
                  "hardware_RAM_capture":False,"flash_writes":False,
                  "eFuse_writes":False},
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    results=audit(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(results,indent=2)+"\n",encoding="utf-8")
    print("PHASE60 SIGNED BASE LOADER ALIASES",json.dumps(results["local_alias_seed_analyses"]))
    print("PHASE60 SIGNED FUNCTION LITERALS",json.dumps(results["handler_pointer_literals"]))
    print("PHASE60 DIRECT BL SHAPES",json.dumps(results["direct_BL_shape_hits"]))
    print("PHASE60 VALUE COUNTS",json.dumps(results["handler_literal_value_counts"]))
    print("PHASE60 DECISION",json.dumps(results["decision"]))
    print("PHASE60 RUNTIME USB LINK UNPROVEN; NO HARDWARE WRITES")


if __name__=="__main__":
    main()
