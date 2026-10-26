"""Phase42: confirm signed OEM writes to the class10 secondary callback fields.

This verifies original instructions and the exact signed sentinel literal.
The destination is base(argument r0) + offsets; proving the caller supplies
0x200064c0 requires an independently grounded call edge. No device I/O.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode, callers_of_known

BASE = ASSUMED_XIP_BASE
INIT = 0x60073BF0
SIGNED_NOOP_THUMB = 0x600D4F05
GLOBAL_BASE_CANDIDATE = 0x200064C0
OFF_CALLBACK = 0x3A38
OFF_CONTEXT = 0x3A3C

# Exact machine instructions from the signed XIP image, not synthetic code.
PINS = {
    0x60073BF0: ("push.w", "{r4, r5, r6, r7, r8, sb, sl, fp, lr}"),
    0x60073BF4: ("mov", "r4, r0"),
    0x60073C0C: ("movs", "r5, #0"),
    0x60073CE6: ("ldr", "r1, [pc, #0x13c]"),
    0x60073CEA: ("movw", "r3, #0x3a38"),
    0x60073CF2: ("adds", "r2, r4, r3"),
    0x60073CF4: ("str", "r1, [r4, r3]"),
    0x60073CFC: ("str", "r5, [r2, #4]"),
    0x600D4F04: ("mov.w", "r0, #0"),
    0x600D4F08: ("bx", "lr"),
}

def pc_literal_at(instruction_pc, pc_offset):
    return ((instruction_pc + 4) & ~3) + pc_offset

def check_pins(rows):
    for pc, expected in PINS.items():
        if rows.get(pc) != expected:
            raise ValueError("Original signed initializer drift at " + hex(pc) +
                             ": " + repr(rows.get(pc)))
    return True

def audit(image):
    if len(image) != IMAGE_SIZE or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("Requires the exact SHA-pinned original OEM signed Bruce update")
    entries = decode(image, INIT, 0x60073D00) + decode(image, 0x600D4F04, 0x600D4F0A)
    decoded = {row["pc"]:(row["m"],row["op"]) for row in entries}
    check_pins(decoded)
    literal = pc_literal_at(0x60073CE6, 0x13C)
    if literal != 0x60073E24:
        raise ValueError("Wrong literal PC value")
    word = struct.unpack_from("<I", image, literal - BASE)[0]
    if word != SIGNED_NOOP_THUMB:
        raise ValueError("Original signed inactive callback literal changed")
    # Bound the search to the authenticated image, and do not classify it as
    # a real caller just because the code bytes decode linearly.
    candidates = callers_of_known(image, {
        "class10_secondary_global_initializer": INIT
    }, max_examples=30)
    raw_thumb = struct.pack("<I", INIT | 1)
    aligned_hits = [off for off in range(0, 0xFF030-3, 4)
                    if image[off:off+4] == raw_thumb]
    report = {
        "phase":42, "signed_oem_sha256_verified": True,
        "initializer":"0x60073bf0", "pins":len(PINS),
        "argument_base_register":"r0 copied into r4 at 0x60073bf4",
        "conditional_callback_write":{
            "pc":"0x60073cf4", "address":"[input_r0 + 0x3a38]",
            "source_pc":"0x60073ce6", "literal_at":hex(literal),
            "value":hex(word), "no_op_original_function":"0x600d4f04 returns 0",
        },
        "conditional_context_write":{
            "pc":"0x60073cfc","address":"[input_r0 + 0x3a3c]",
            "stored_value":"0 from original r5 initialization",
        },
        "if_base_equals":hex(GLOBAL_BASE_CANDIDATE),
        "then_callback_slot":hex(GLOBAL_BASE_CANDIDATE+OFF_CALLBACK),
        "then_context_slot":hex(GLOBAL_BASE_CANDIDATE+OFF_CONTEXT),
        "original_signed_function_ptr_literal_refs":{
            "count":len(aligned_hits),
            "file_offsets_limited":[hex(x) for x in aligned_hits[:30]]
        },
        "direct_bl_caller_candidates":candidates,
        "caller_passes_expected_global_base":"NOT VERIFIED",
        "physical_ep0_or_host_control":"NOT VERIFIED",
        "callback_can_be_replaced_from_USB":"NOT DEMONSTRATED",
        "custom_code_execution":"NOT DEMONSTRATED",
        "operations":{"device_connected":False,"physical_ram_writes":False,"flash_writes":False}
    }
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    r=audit(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(r,indent=2)+"\n")
    print("PHASE42 SIGNED CALLBACK INITIALIZER",json.dumps(r))

if __name__=="__main__":
    main()
