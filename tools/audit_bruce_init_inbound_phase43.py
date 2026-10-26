"""Phase 43: offset-complete Thumb inbound-reference audit for signed Bruce init.

Read-only, hash-pinned OEM update image. The earlier XIP BL sweep began each
large chunk at only one instruction boundary, so interleaved literal pools may
hide valid branch instructions. This tool checks each halfword for valid Thumb
branch encodings, decodes candidate instructions at their actual PCs and
reports matches separately from *reachability*. Also checks unaligned static
function pointers, and startup-relocated ITCM branch encodings. Nothing here
invokes the controller, writes firmware or proves boot-time execution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB
from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET, ITCM_LENGTH
from tools.audit_bruce_class10_secondary_init_phase42 import INIT, GLOBAL_BASE_CANDIDATE

BASE = ASSUMED_XIP_BASE
SIGNED_END = BASE + 0xFF000
XIP_CODE_START = (ITCM_SOURCE_OFFSET + ITCM_LENGTH + 1) & ~1
THUMB_TARGET = INIT | 1
NEAR_DISTANCE = 0x20


def decoder():
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    md.detail = True
    return md


def candidate_thumb32_branch(h1, h2):
    """Fast SUPerset: Thumb-2 B.W/BL/BLX share 11110 leading halfword.

    Prefilter must avoid missing valid BL/B.W; Capstone validates candidates.
    """
    return (h1 & 0xF800) == 0xF000 and (h2 & 0x8000) == 0x8000


def parse_direct_target(ins):
    """For the one immediate operand branch, ignore register-indirect BLX."""
    if ins.mnemonic not in ("bl", "blx", "b.w", "b"):
        return None
    if not ins.op_str.startswith("#"):
        return None
    try:
        return int(ins.op_str[1:], 0) & ~1
    except ValueError:
        return None


def decode_if_direct(md, data, off, pc):
    h1, h2 = struct.unpack_from("<HH", data, off)
    if not candidate_thumb32_branch(h1, h2):
        return None
    dec = tuple(md.disasm(data[off:off + 4], pc, count=1))
    if not dec or dec[0].address != pc or dec[0].size != 4:
        return None
    ins = dec[0]
    target = parse_direct_target(ins)
    if target is None:
        return None
    return {"pc": hex(pc), "opcode": ins.mnemonic + " " + ins.op_str,
            "target": hex(target), "target_int": target}


def linear_bounded_context(md, data, file_off, pc, *, preceding_bytes=24):
    """Only candidate previous instructions; pool/branch alignment unverified."""
    start = max(0, file_off - preceding_bytes)
    start &= ~1
    context = []
    for ins in md.disasm(data[start:file_off], pc-(file_off-start)):
        if len(context) >= 22:
            break
        context.append(hex(ins.address) + " " + ins.mnemonic + " " + ins.op_str)
    return context[-10:]


def find_inbound_branches(image, *, only_target=INIT):
    md = decoder()
    hits = []
    near = []
    accepted_counts = {"XIP": 0, "ITCM": 0}
    ranges = (
        ("XIP", XIP_CODE_START, 0xFF000, lambda off: BASE + off),
        ("ITCM", ITCM_SOURCE_OFFSET, ITCM_SOURCE_OFFSET + ITCM_LENGTH,
         lambda off: off - ITCM_SOURCE_OFFSET),
    )
    for kind, start, stop, pc_from_off in ranges:
        for off in range(start, stop - 3, 2):
            pc = pc_from_off(off)
            row = decode_if_direct(md, image, off, pc)
            if row is None:
                continue
            accepted_counts[kind] += 1
            target = row.pop("target_int")
            if target == only_target:
                row.update({"region":kind,
                            "file_offset":hex(off),
                            "preceding_linear_candidate": linear_bounded_context(
                                 md, image, off, pc),
                            "real_callsite_or_reachability_verified":False})
                hits.append(row)
            elif kind == "XIP" and abs(target - only_target) <= NEAR_DISTANCE:
                if len(near) < 30:
                    near.append({"region":kind,"pc":row["pc"],
                                 "opcode":row["opcode"],"target":row["target"]})
    return {"target":hex(only_target), "direct_branch_candidates":hits,
            "near_target_examples":near,
            "decoded_branch_candidates_by_region":accepted_counts,
            "scanned_halfword_range":{
                "XIP":[hex(BASE+XIP_CODE_START),hex(BASE+0xFF000)],
                "ITCM_relocated":[hex(0),hex(ITCM_LENGTH)],
            },
            "cannot_rule_out_indirect_branch_or_external_rom":True}


def all_byte_word_references(image, value, limit=28):
    needle = struct.pack("<I", value)
    hits = []
    cursor = 0
    while True:
        p = image.find(needle, cursor)
        if p < 0:
            break
        hits.append(p)
        cursor = p+1
    return {"value":hex(value),
            "count":len(hits),
            "aligned4_count":sum(p%4 == 0 for p in hits),
            "aligned2_count":sum(p%2 == 0 for p in hits),
            "file_offsets": [hex(p) for p in hits[:limit]],
            "examples_truncated":len(hits)>limit,
            "interpretation":"word matches only, not executable pointer use"}


def audit(image: bytes):
    if len(image) != IMAGE_SIZE or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("Exact original signed Bruce image and SHA256 required")
    calls = find_inbound_branches(image)
    refs = {name:all_byte_word_references(image,value) for name,value in {
        "initializer_thumb":THUMB_TARGET,
        "initializer_even":INIT,
        "candidate_global_base":GLOBAL_BASE_CANDIDATE,
        "guard_sentinel":0x600D4F05,
    }.items()}
    return {
        "phase":43,"image_exact_sha256_verified":True,
        "sample_kind":"signed OEM update, not physical readback",
        "target_initializer":hex(INIT),
        "inbound_scan":calls,
        "raw_static_references":refs,
        "initializer_r0_proven":False,
        "base_equals_0x200064c0_proven":False,
        "runtime_reachable":False,
        "usb_host_can_rewrite_callback":"NOT DEMONSTRATED",
        "custom_firmware_execution":"NOT DEMONSTRATED",
        "limitations":[
            "Overlap-resistant per-halfword branch scan includes non-code bytes; hits remain candidates.",
            "Only direct immediate B.W/BL/BLX; register indirect BLX, table dispatch and computed PC not resolved.",
            "Raw pointer matches are not code and may appear in arbitrary data.",
            "ITCM is decoded at its startup-relocated runtime PC, not its XIP stored address.",
            "No physical controller IO or firmware writes."
        ],
        "controller_connected":False,"flash_written":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    out=audit(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(out,indent=2)+"\n")
    print("PHASE43 INIT INBOUND BRANCHES",json.dumps(out["inbound_scan"]))
    print("PHASE43 INIT RAW REFERENCES",json.dumps(out["raw_static_references"]))
    print("PHASE43 EXECUTION STATUS: UNVERIFIED")

if __name__=="__main__":
    main()
