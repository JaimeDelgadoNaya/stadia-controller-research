"""Read-only original Bruce EP0 slot registration reconnaissance.

Investigates initialization of the 12-byte endpoint callback entries used
by the verified SETUP event dispatcher at XIP 0x600D0FB6. Only scans a
SHA-pinned public signed update image; never opens any USB device.
Linear disassembly produces *candidate* BL xrefs, not a CFG proof.
"""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH

BASE=ASSUMED_XIP_BASE
REGION_START=0x600D0B00
REGION_END=0x600D1200
FOCUSED_START=0x600D0D40
FOCUSED_END=0x600D0FC0
DISPATCHER=0x600D0FB6
ENDPOINT_STRIDE=12
EP0_OUT_INDEX=0
EP0_IN_INDEX=1


def decode(image, start, end):
    """Thumb instructions in XIP-addressed bytes; no reachability claim."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    if not BASE <= start < end <= BASE+0xFF000:
        raise ValueError("disassembly outside signed XIP application")
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    return [{"pc":i.address,"m":i.mnemonic,"op":i.op_str}
            for i in md.disasm(image[start-BASE:end-BASE],start)]


def direct_call_target(row):
    if row["m"] not in ("bl","b.w"):
        return None
    op=row["op"]
    if not op.startswith("#"):
        return None
    try:
        return int(op[1:],0)
    except ValueError:
        return None


def candidate_calls(image, *, max_per_target=8):
    # The XIP region follows startup's relocated ITCM code. Avoid that
    # source image and its misleading stored PC-relative branch targets.
    initial=(ITCM_SOURCE_OFFSET+ITCM_LENGTH+1)&~1
    hits=Counter()
    exemplars={}
    boundary=0xFF000
    for off in range(initial,boundary,0x2000):
        rows=decode(image,BASE+off,BASE+min(off+0x2000,boundary))
        for k,row in enumerate(rows):
            if row["m"]!="bl":
                continue
            target=direct_call_target(row)
            if target is None or not REGION_START<=target<REGION_END:
                continue
            key=hex(target)
            hits[key]+=1
            if len(exemplars.setdefault(key,[]))<max_per_target:
                exemplars[key].append({
                    "callsite":hex(row["pc"]),
                    "preceding":[{"pc":hex(q["pc"]),"ins":q["m"]+" "+q["op"]}
                                 for q in rows[max(0,k-7):k]],
                    "method":"linear Thumb decode, unverified as executable call path",
                })
    return {"counts":dict(sorted(hits.items(),key=lambda item:int(item[0],16))),
            "examples":exemplars,
            "limitations":"Linear XIP-only decode may miss true calls and decode tables as instructions; indirect BLX not found."}


def audit(image, *, include_focused=False):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Exact signed Bruce update sample required (SHA256 and size)")
    calls=candidate_calls(image)
    focused=decode(image,FOCUSED_START,FOCUSED_END)
    stores=[x for x in focused if x["m"].startswith(("str","stm"))]
    return {
        "oem_signed_image_sha256_verified":True,
        "original_sha256":IMAGE_SHA256,
        "dispatcher":hex(DISPATCHER),
        "entry_byte_stride":ENDPOINT_STRIDE,
        "endpoint_slot_formula":"2*(endpoint & 0x0f) + ((endpoint>>7)&1)",
        "ep0_out_slot_index":EP0_OUT_INDEX,
        "ep0_in_slot_index":EP0_IN_INDEX,
        "ep0_out_callback_offset_from_object":hex(0x0c),
        "ep0_in_callback_offset_from_object":hex(0x0c+ENDPOINT_STRIDE),
        "candidate_function_calls_to_usb_core":calls,
        "usb_core_window":
            [{"pc":hex(i["pc"]),"m":i["m"],"op":i["op"]} for i in focused]
            if include_focused else [],
        "candidate_stores_count_in_window":len(stores),
        "ep0_runtime_callback_pointer":"NOT IDENTIFIED",
        "ep0_setup_class_brequest_receiver":"NOT IDENTIFIED",
        "host_to_custom_execution":"NOT DEMONSTRATED",
        "physical_device_access":False,
        "firmware_writes":False,
    }


def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument("image",type=Path)
    a.add_argument("--out",type=Path)
    a.add_argument("--show-focused",action="store_true")
    p=a.parse_args()
    result=audit(p.image.read_bytes(),include_focused=p.show_focused)
    if p.out:
        p.out.write_text(json.dumps(result,indent=2)+"\n")
    print("BL TARGET CENSUS",json.dumps(result["candidate_function_calls_to_usb_core"]))
    if p.show_focused:
        for ins in result["usb_core_window"]:
            print("FOCUSED",ins["pc"],ins["m"],ins["op"])


if __name__=="__main__":
    main()
