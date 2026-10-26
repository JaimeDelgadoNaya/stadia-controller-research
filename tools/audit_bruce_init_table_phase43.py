"""Phase43: classify the original signed function-pointer word before .data.

The Thumb function pointer for the verified secondary-global initializer
wrapper is stored at original file offset 0xFD544. Inspect its neighbors and
test whether they form a plausible static initializer table. This module does
not assert that the table is used, that startup invokes it, or that any device
runs this exact update image. All operations are read-only.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import (
    ITCM_LENGTH, DATA_SOURCE_OFFSET, DATA_DESTINATION, DATA_END
)
from tools.audit_bruce_init_inbound_phase43 import CALLER, all_byte_word_references, find_inbound_branches
from tools.audit_bruce_ep0_registration import decode

BASE=ASSUMED_XIP_BASE
POINTER_FILE_OFFSET=0xFD544
POINTER_VALUE=CALLER|1
MAX_NEIGHBORS=100


def le32(blob,off):
    if off < 0 or off + 4 > len(blob):
        raise ValueError("source byte offset invalid")
    return struct.unpack_from("<I",blob,off)[0]


def executable_thumb_value(value):
    even=value & ~1
    return bool(value & 1) and (
        BASE <= even < BASE + 0xFF000 or 0 <= even < ITCM_LENGTH
    )


def neighbor_candidate_range(image,center=POINTER_FILE_OFFSET,max_entries=MAX_NEIGHBORS):
    if center % 4:
        raise ValueError("candidate center not word-aligned")
    if not executable_thumb_value(le32(image,center)):
        raise ValueError("center must contain Thumb function candidate")
    lo=hi=center
    for _ in range(max_entries):
        p=lo-4
        if p < 0 or not executable_thumb_value(le32(image,p)):
            break
        lo=p
    for _ in range(max_entries):
        p=hi+4
        if p+4 > len(image) or not executable_thumb_value(le32(image,p)):
            break
        hi=p
    return lo,hi+4



WALKER = 0x600CDB74
WALKER_PINS = {
    0x600CDB74: ("push", "{r4, r5, r6, lr}"),
    0x600CDB76: ("ldr", "r6, [pc, #0x34]"),
    0x600CDB78: ("ldr", "r4, [pc, #0x34]"),
    0x600CDB7A: ("subs", "r4, r4, r6"),
    0x600CDB7C: ("asrs", "r4, r4, #2"),
    0x600CDB84: ("ldr", "r6, [pc, #0x2c]"),
    0x600CDB86: ("ldr", "r4, [pc, #0x30]"),
    0x600CDB8C: ("subs", "r4, r4, r6"),
    0x600CDB8E: ("asrs", "r4, r4, #2"),
    0x600CDB92: ("cmp", "r5, r4"),
    0x600CDB94: ("bne", "#0x600cdba2"),
    0x600CDBA2: ("ldr.w", "r3, [r6, r5, lsl #2]"),
    0x600CDBA6: ("blx", "r3"),
    0x600CDBA8: ("adds", "r5, #1"),
    0x600CDBAA: ("b", "#0x600cdb92"),
}


def verify_walker_pins(decoded):
    for pc,expected in WALKER_PINS.items():
        if decoded.get(pc)!=expected:
            raise ValueError("Original signed startup walker drift at "+hex(pc))
    return True


def verify_constructor_walker(image):
    # Validate signed bytes, table bounds and dynamic call index.
    rows=decode(image,WALKER,0x600CDBAC)
    verify_walker_pins({row["pc"]:(row["m"],row["op"]) for row in rows})
    lo_pre=le32(image,0x8DBAC)
    hi_pre=le32(image,0x8DBB0)
    start=le32(image,0x8DBB4)
    end=le32(image,0x8DBB8)
    if (lo_pre,hi_pre,start,end)!=(0x6013D4F0,0x6013D4F0,
                                    0x6013D4F0,0x6013D5A4):
        raise ValueError("Signed constructor bounds drift")
    if (end-start)%4 or not start<=BASE+POINTER_FILE_OFFSET<end:
        raise ValueError("Wrapper pointer not in constructor range")
    idx=(BASE+POINTER_FILE_OFFSET-start)//4
    if idx!=21 or le32(image,start-BASE+4*idx)!=POINTER_VALUE:
        raise ValueError("Wrapper table index drift")
    count=(end-start)//4
    if count!=45:
        raise ValueError("Signed constructor count drift")
    return {
        "walker_function":hex(WALKER),
        "semantic_instruction_anchors":len(WALKER_PINS),
        "preinit_range":[hex(lo_pre),hex(hi_pre)],
        "init_array_range":[hex(start),hex(end)],
        "init_array_entry_count":count,
        "wrapper_index_zero_based":idx,
        "wrapper_pointer":hex(POINTER_VALUE),
        "load_at":"0x600cdba2",
        "indirect_blx_at":"0x600cdba6",
        "invoked_if_walker_runs_and_iteration_completes":True,
        "runtime_walker_executed":"NOT VERIFIED",
    }


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("requires exact pinned original signed Bruce OEM update")
    if le32(image,POINTER_FILE_OFFSET)!=POINTER_VALUE:
        raise ValueError("phase43 signed initializer function-pointer word drift")
    lo,hi=neighbor_candidate_range(image)
    items=[{
        "file_offset":hex(p),"flash_address":hex(BASE+p),
        "word":hex(le32(image,p)),
        "classification":("candidate_Thumb_address" if executable_thumb_value(le32(image,p))
                         else "other"),
        "is_verified_wrapper":p == POINTER_FILE_OFFSET,
    } for p in range(max(0,lo-0x30),min(len(image)-3,hi+0x30),4)]
    bounds={
        "candidate_first_file_offset":hex(lo),
        "candidate_end_exclusive_file_offset":hex(hi),
        "candidate_entries":(hi-lo)//4,
        "candidate_first_flash_address":hex(BASE+lo),
        "candidate_end_flash_address":hex(BASE+hi),
        "contains_verified_wrapper":lo<=POINTER_FILE_OFFSET<hi,
        "identified_as_real_startup_init_array":False,
    }
    walker=verify_constructor_walker(image)
    walker_calls=find_inbound_branches(image,only_target=WALKER)
    refs={
        label:all_byte_word_references(image,addr,limit=20)
        for label,addr in {
           "candidate_table_start":BASE+lo,
           "candidate_table_start_plus4":BASE+lo+4,
           "candidate_table_start_plus8":BASE+lo+8,
           "candidate_table_start_minus4":BASE+lo-4,
           "candidate_table_end":BASE+hi,
           "function_pointer_slot":BASE+POINTER_FILE_OFFSET,
           "data_copy_flash_start":BASE+DATA_SOURCE_OFFSET,
           "verified_wrapper_thumb":POINTER_VALUE,
        }.items()
    }
    return {
        "phase":43,"sample_exact_sha256_verified":True,
        "entry":{"file_offset":hex(POINTER_FILE_OFFSET),
                 "flash_address":hex(BASE+POINTER_FILE_OFFSET),
                 "signed_function_pointer":hex(POINTER_VALUE)},
        "table_shape":bounds,
        "verified_constructor_walker":walker,
        "inbound_walker_branch_candidates":walker_calls,
        "walker_thumb_reference_census":all_byte_word_references(image,WALKER|1),
        "neighbor_words":items,
        "boundary_reference_census":refs,
        "candidate_start_reference_code":[
            hex(x["pc"])+" "+x["m"]+" "+x["op"]
            for x in __import__("tools.audit_bruce_ep0_registration",fromlist=["decode"]).decode(
                image,0x600CDB60,0x600CDBAC
            )
        ],
        "candidate_start_reference_words":[
            {"file_offset":hex(i),"word":hex(le32(image,i))}
            for i in range(0x8DB80,0x8DBC0,4)
        ],
        "possible_table_iterator_near_0x60061608":[
            hex(x["pc"])+" "+x["m"]+" "+x["op"]
            for x in __import__("tools.audit_bruce_ep0_registration",fromlist=["decode"]).decode(
                image,0x60061590,0x60061638
            )
        ],
        "known_startup_data_copy":{
            "file_offset":hex(DATA_SOURCE_OFFSET),
            "RAM_start":hex(DATA_DESTINATION),
            "RAM_end":hex(DATA_END),
            "table_candidate_before_copy":hi<=DATA_SOURCE_OFFSET,
        },
        "startup_iteration_path":"NOT VERIFIED",
        "actual_boot_invocation":"NOT VERIFIED",
        "host_control":"NOT VERIFIED",
        "custom_firmware_execution":False,
        "physical_usb":False,"flash_writes":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    report=audit(a.image.read_bytes())
    if a.out:a.out.write_text(json.dumps(report,indent=2)+"\n")
    print("PHASE43 POINTER TABLE SHAPE",json.dumps(report["table_shape"]))
    print("PHASE43 POINTER TABLE WORDS",json.dumps(report["neighbor_words"]))
    print("PHASE43 POINTER TABLE REFS",json.dumps(report["boundary_reference_census"]))
    print("PHASE43 VERIFIED CONSTRUCTOR WALKER",json.dumps(report["verified_constructor_walker"]))
    print("PHASE43 WALKER INBOUND",json.dumps(report["inbound_walker_branch_candidates"]))
    print("PHASE43 WALKER STATIC PTR",json.dumps(report["walker_thumb_reference_census"]))
    print("PHASE43 POSSIBLE TABLE ITERATOR",json.dumps(report["possible_table_iterator_near_0x60061608"]))
    print("PHASE43 INIT ARRAY START CONTEXT",json.dumps(report["candidate_start_reference_code"]))
    print("PHASE43 INIT ARRAY START WORDS",json.dumps(report["candidate_start_reference_words"]))

if __name__=="__main__":
    main()
