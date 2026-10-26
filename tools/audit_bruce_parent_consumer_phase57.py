"""Phase 57: OEM signed constructor -> post-init call -> +0x80 reader provenance.

Do not equate same register spelling across functions. This auditor first
verifies the signed caller: an allocation-like return is saved as R4,
passed to constructor, and passed as R0 to post-initialization. It then
examines signed, bounded reader neighborhoods, recording whether their
base register can be shown to derive from the post-init R0.

No hardware USB or flash writes; no installed RAM sample.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_parent_r0_phase56 import prove_r0_producer, offset_reader

CALLER_START=0x60079D74
CTOR_CALL=0x60079D84
POST_INIT_CALL=0x60079D9A
POST_INIT_ENTRY=0x6007E784
CANDIDATE_READERS=(0x6007E7EA,0x6007E810,0x6007E9A4)

# Known signed source site + call from prior phase 56. These pins ensure
# the producer's R4 really survives until passed to the next routine.
CALLER_PINS={
    0x60079D74:("movs","r0, #0xa4"),
    0x60079D76:("bl","#0x6013d378"),
    0x60079D7E:("mov","r4, r0"),
    0x60079D84:("bl","#0x6007eb8c"),
    0x60079D90:("bl","#0x6013d3c8"),
    0x60079D96:("mov","r0, r4"),
    0x60079D98:("str","r3, [r4, #0x68]"),
    0x60079D9A:("bl","#0x6007e784"),
}
READ_PINS={
    0x6007E7EA:("ldr.w","r0, [r0, #0x80]"),
    0x6007E810:("ldr.w","r0, [r4, #0x80]"),
    0x6007E9A4:("ldr.w","r0, [r4, #0x80]"),
}
WINDOWS={
    "constructor_caller":(0x60079D74,0x60079DA8),
    "post_init_entry":(0x6007E784,0x6007E7CC),
    "post_init_reader_early":(0x6007E7C8,0x6007E838),
    "reader_later":(0x6007E8A0,0x6007E9BA),
}


def bounded_decode(image, start, end):
    return [
        {"pc":hex(r["pc"]),"m":r["m"],"op":r["op"]}
        for r in decode(image,start,end)
    ]


def verify_pins(image, pinset, windows):
    observed={}
    for begin,end in windows:
        observed.update({
            row["pc"]:(row["m"],row["op"])
            for row in decode(image,begin,end)
        })
    for pc,pair in pinset.items():
        if observed.get(pc)!=pair:
            raise ValueError(f"phase57 original signed instruction drift {pc:#x}: {observed.get(pc)!r}")
    return len(pinset)


def same_register_without_redefinition(rows, from_pc, to_pc, name):
    """Conservative single-block local check; never cross calls or branches.

    Returns False if a control-flow barrier, unknown instruction, or write
    to the tracked register appears. This is NOT a CFG reachability proof.
    """
    saw_from=False
    for row in rows:
        pc=int(row["pc"],16)
        if pc==from_pc:
            saw_from=True
            continue
        if not saw_from:
            continue
        if pc==to_pc:
            return True
        m=row["m"].split(".")[0]
        op=row["op"]
        if m in ("b","bl","blx","bx","pop","ldm","cbz","cbnz","tbb","tbh"):
            return False
        if m.startswith("it") or (m.startswith("b") and m!="bic"):
            return False
        if op.split(",",1)[0]==name and m not in ("cmp","tst","str","strb","strh","strd","push"):
            return False
    return False


def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("phase57 original SHA-256-pinned signed OEM required")
    original=prove_r0_producer(image)
    ncaller=verify_pins(image,CALLER_PINS,[(0x60079D74,0x60079DA8)])
    nread=verify_pins(image,READ_PINS,[
        (0x6007E7E8,0x6007E7EE),
        (0x6007E80E,0x6007E814),
        (0x6007E9A2,0x6007E9A8),
    ])
    views={name:bounded_decode(image,*bounds) for name,bounds in WINDOWS.items()}
    # R4 is callee-saved by AAPCS, but without proving that each signed
    # callee conforms and returns we only claim a conditional argument route.
    # 0x60079d7e -> 0x60079d96 both save and forward caller's R4.
    chain={
        "allocation_like_return_to_r4":"0x60079d7e MOV R4,R0",
        "constructor":"0x60079d84 BL 0x6007eb8c",
        "after_constructor_call":"0x60079d90 BL 0x6013d3c8",
        "post_constructor_r0":"0x60079d96 MOV R0,R4",
        "post_constructor_entry":"0x60079d9a BL 0x6007e784",
        "argument_identity":"CONDITIONAL: caller R4 is callee-saved across intervening signed BLs",
        "live_execution":"UNMEASURED",
    }
    readers=[]
    for pc in CANDIDATE_READERS:
        match=READ_PINS[pc]
        check=offset_reader(*match)
        if check is None:
            raise ValueError("phase57 reader semantic drift "+hex(pc))
        readers.append({
            "pc":hex(pc),
            "instruction":match[0]+" "+match[1],
            "base_register":check["base"],
            "post_init_object_identity":"PENDING_INCOMING_REGISTER_PROVENANCE",
            "claim":"SIGNED_READ_INSTRUCTION; NOT_YET_PROVEN_SAME_OBJECT",
        })
    return {
        "phase":57,
        "sha256":IMAGE_SHA256,
        "original_signed_image_verified":True,
        "caller_pin_count":ncaller,
        "reader_pin_count":nread,
        "phase56_producer":original,
        "post_constructor_pass":chain,
        "read_candidates":readers,
        "instruction_windows":views,
        "owner_config_fields":"UNMEASURED",
        "active_class10":"UNVERIFIED",
        "host_code_execution":"NOT DEMONSTRATED",
        "HAB_CLOSED_bypass":"NOT DEMONSTRATED",
        "device_IO":False,"flash_or_efuse_writes":False,
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image",type=Path)
    parser.add_argument("--out",type=Path)
    args=parser.parse_args()
    result=audit(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print("PHASE57 CONSTRUCTOR-POSTINIT PASS",json.dumps(result["post_constructor_pass"]))
    for name,rows in result["instruction_windows"].items():
        print("PHASE57 ORIGINAL WINDOW",name,json.dumps(rows))
    print("PHASE57 READER CANDIDATES",json.dumps(result["read_candidates"]))
    print("PHASE57 PINS",result["caller_pin_count"],result["reader_pin_count"])
    print("PHASE57 NO LIVE USB CONFIG OR EXECUTION PROOF")


if __name__=="__main__":
    main()
