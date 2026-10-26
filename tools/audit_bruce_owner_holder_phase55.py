"""Phase 55: original-signed producer-first provenance of Bruce USB owner.

A caller passes literal owner=0x2000A2A8 as R2 to a signed object
constructor, which saves it in a distinct object's +0x80 field.
This is NOT a write to owner+4/+8/+12. Also pins two original signed
getters of the boot-initialized class2/class10 record group. The
relationship between these paths is still UNRESOLVED.

Input is the exact signed OEM UPDATE (not physical RAM/flash readback).
No USB I/O, flash writes, efuses, or execution of unsigned firmware.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE, ASSUMED_XIP_BASE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_bruce_usb_owner_pointer_phase50 import OWNER
from tools.audit_bruce_class10_record_producer import confirmed_boot_records

BASE = ASSUMED_XIP_BASE
GROUP = 0x200030E8
HOLDER_FIELD_OFFSET = 0x80
CFG_METHOD = OWNER + 8
WINDOWS = (
    (0x60079D60, 0x60079D88),
    (0x6007EB8C, 0x6007EBC0),
    (0x600610FC, 0x6006110A),
    (0x600550F4, 0x60055100),
)

# All mnemonic/operand pairs must match original Capstone/Thumb decoding.
PINS = {
    0x60079D7C: ("ldr", "r2, [pc, #0x54]"),
    0x60079D7E: ("mov", "r4, r0"),
    0x60079D80: ("ldr", "r1, [pc, #0x54]"),
    0x60079D82: ("str", "r6, [sp]"),
    0x60079D84: ("bl", "#0x6007eb8c"),
    0x6007EB90: ("mov", "r7, r3"),
    0x6007EB96: ("mov", "r4, r0"),
    0x6007EB9E: ("mov", "r8, r2"),
    0x6007EBA6: ("strd", "r5, r5, [r0, #4]"),
    0x6007EBAA: ("adds", "r0, #0x10"),
    0x6007EBAC: ("bl", "#0x601017fc"),
    0x6007EBB4: ("str.w", "r8, [r4, #0x80]"),
    0x600610FC: ("ldr", "r0, [pc, #0]"),
    0x600610FE: ("bx", "lr"),
    0x60061104: ("ldr", "r0, [pc, #0]"),
    0x60061106: ("bx", "lr"),
    0x600550F6: ("ldr", "r3, [r1, #4]"),
    0x600550F8: ("cmp", "r3, #0"),
    0x600550FA: ("beq", "#0x600551a2"),
}


def read_word(image: bytes, address: int) -> int:
    off = address - BASE
    if address % 4 or off < 0 or off + 4 > len(image):
        raise ValueError("unsigned/unmapped or unaligned original literal")
    return struct.unpack_from("<I", image, off)[0]


def pc_literal_address(pc: int, imm: int) -> int:
    return ((pc + 4) & ~3) + imm


def propagate_holder(caller_r2: int | None, saved_r8: int | None = None):
    """Relevant abstract register flow, no simulated runtime execution.

    R2 is copied to R8 before an external BL. R8 is callee-saved on
    ARM AAPCS. R4 is an unknown but distinct *base*, not OWNER simply
    because some input argument also points to OWNER.
    """
    if caller_r2 is None:
        return {"holder_field_offset": HOLDER_FIELD_OFFSET,
                "value": "UNKNOWN", "absolute_address": "UNKNOWN"}
    saved_r8 = caller_r2 if saved_r8 is None else saved_r8
    return {"holder_field_offset": HOLDER_FIELD_OFFSET,
            "value": hex(saved_r8), "absolute_address": "UNKNOWN",
            "reason": "R0 parent base cannot be inferred from owner in R2"}


def validate_original(image: bytes) -> dict:
    code = {}
    for lo, hi in WINDOWS:
        for row in decode(image, lo, hi):
            code[row["pc"]] = (row["m"], row["op"])
    for pc, anchor in PINS.items():
        if code.get(pc) != anchor:
            raise ValueError(f"phase55 original signed anchor drift {pc:#x}: {code.get(pc)!r}")

    owner_ptr = read_word(image, pc_literal_address(0x60079D7C, 0x54))
    if owner_ptr != OWNER:
        raise ValueError("phase55 owner R2 argument literal drift")
    group_getters = []
    for pc in (0x600610FC, 0x60061104):
        ptr = read_word(image, pc_literal_address(pc, 0))
        if ptr != GROUP:
            raise ValueError("phase55 class record group getter literal drift")
        group_getters.append({"pc": hex(pc), "literal_address": hex(pc_literal_address(pc, 0)),
                              "returned_pointer": hex(ptr)})
    records = confirmed_boot_records(image)
    if len(records) != 2 or [r["byte_at_descriptor_plus_4"] for r in records] != [2, 10]:
        raise ValueError("phase55 signed class group records drift")
    if [r["destination_boot_RAM"] for r in records] != ["0x200030e8", "0x200030f4"]:
        raise ValueError("phase55 boot class record addresses drift")

    context = []
    for row in decode(image, 0x60079D60, 0x60079D88):
        context.append(hex(row["pc"]) + " " + row["m"] + " " + row["op"])
    return {"pins_verified": len(PINS), "owner_literal": hex(owner_ptr),
            "record_group_getters": group_getters, "group_records": records,
            "caller_window": context}


def audit(image: bytes) -> dict:
    if len(image) != IMAGE_SIZE or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("phase55 original exact signed Bruce OEM SHA-256 required")
    signed = validate_original(image)
    holder = propagate_holder(OWNER)
    return {
        "phase": 55,
        "original_signed_OEM_sha_verified": True,
        "sha256": IMAGE_SHA256,
        "owner": hex(OWNER),
        "new_owner_pointer_holder_edge": {
            "caller": "0x60079d7c LDR R2,[PC,#0x54] => owner",
            "call": "0x60079d84 BL 0x6007eb8c",
            "callee_save": "0x6007eb9e MOV R8,R2",
            "callee_base": "0x6007eb96 MOV R4,R0",
            "intervening_call": "0x6007ebac BL 0x601017fc; R8/R4 callee-saved",
            "store": "0x6007ebb4 STR.W R8,[R4,#0x80]",
            "abstract_store": holder,
            "classification": "CONDITIONAL_SIGNED_CODE_POINTER_TRANSFER_TO_PARENT_FIELD",
            "not_a_writer_to_owner_plus4_plus8_plus12": True,
            "parent_base": "UNKNOWN",
            "run_on_hardware": "UNVERIFIED",
        },
        "class_group_source": {
            "signed_getters": signed["record_group_getters"],
            "boot_initialized_records": signed["group_records"],
            "class_selectors_in_signed_records": [2, 10],
            "class10_in_live_owner_config": "UNVERIFIED",
            "link_from_owner_plus4_to_group": "UNPROVEN",
        },
        "original_pins": signed["pins_verified"],
        "caller_context": signed["caller_window"],
        "configuration_consumer": {
            "method_address": hex(CFG_METHOD),
            "method_guard": "0x600550f6 LDR R3,[R1,#4] -> 0x600550fa BEQ if zero",
            "method_value": "UNMEASURED",
            "proven_producer_of_method_or_class_list": "NONE IN THIS ANALYSIS",
        },
        "limits": {
            "parent_object_base": "UNKNOWN",
            "runtime_RAM": "UNMEASURED",
            "runtime_class10": "UNVERIFIED",
            "method_and_class_list_writers": "UNRESOLVED",
            "firmware_own_execution": "NOT DEMONSTRATED",
            "HAB_CLOSED_bypass": "NOT DEMONSTRATED",
            "USB_packets_sent": False,
            "flash_or_efuse_writes": False,
        },
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    out = audit(args.image.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print("PHASE55 ORIGINAL OEM PINS", out["original_pins"])
    print("PHASE55 OWNER POINTER HOLDER", json.dumps(out["new_owner_pointer_holder_edge"]))
    print("PHASE55 SIGNED CLASS RECORDS", json.dumps(out["class_group_source"]))
    print("PHASE55 CALLER CONTEXT", json.dumps(out["caller_context"]))
    print("PHASE55 METHOD/ARRAY UNRESOLVED; NO LIVE RAM OR OWN FIRMWARE")


if __name__ == "__main__":
    main()
