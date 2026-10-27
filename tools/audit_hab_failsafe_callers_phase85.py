"""NXP research phase 85: bounded *candidate* callers of signed HAB failsafe.

Only SHA-pinned original OEM application bytes are processed. No ROM or USB I/O.
A raw pointer and a disassembled branch at a halfword offset can both be DATA.
No instruction-boundary, function-entry, control-flow, or runtime proof.
"""
import argparse
import json
import struct
from pathlib import Path

from tools.audit_hab_rvt_failsafe_phase84 import (
    BRUCE_XIP_BASE, INSTRUCTION_OFFSET, audit as audit_original_veneer,
)

FAILSAFE_ENTRY = BRUCE_XIP_BASE + INSTRUCTION_OFFSET
MAX_CANDIDATES = 4096


def candidate_branch_prefix(hw):
    """Coarse Thumb branch families, intentionally not an exhaustive ISA decoder."""
    if (hw & 0xf800) in (0xe000, 0xe800, 0xf000, 0xf800):
        return True
    if (hw & 0xf000) == 0xd000:
        return True
    return (hw & 0xf500) == 0xb100  # CBZ/CBNZ encodings


def enumerate_candidate_references(image, *, base=BRUCE_XIP_BASE,
                                    target=FAILSAFE_ENTRY, stop=None):
    """Find pointer words and potential direct PC-branch decodings to target."""
    if not isinstance(image, bytes):
        raise ValueError("Image must be bytes")
    if stop is None:
        stop = len(image)
    if not 0 <= stop <= len(image):
        raise ValueError("Invalid search span")
    if target < base or target >= base + stop or target & 1:
        raise ValueError("Target is outside declared aligned file mapping")

    pointers = []
    branches = []
    # Pointer census includes both halfword and word-aligned candidates.
    for at in range(0, stop - 3, 2):
        word = struct.unpack_from("<I", image, at)[0]
        if word not in (target, target | 1):
            continue
        pointers.append({
            "file_offset": hex(at),
            "word": f"0x{word:08x}",
            "word_alignment": "4_byte" if at % 4 == 0 else "2_byte_only",
            "thumb_entry_bit": bool(word & 1),
            "actual_reference_established": False,
        })
        if len(pointers) > MAX_CANDIDATES:
            raise ValueError("Excessive pointer candidates")

    # Capstone is a decoder only. Starting independently at every matching
    # halfword can decode data and the middle of another real instruction.
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_JUMP, CS_GRP_CALL
    from capstone.arm import ARM_OP_IMM
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    for at in range(0, stop - 1, 2):
        hw = struct.unpack_from("<H", image, at)[0]
        if not candidate_branch_prefix(hw):
            continue
        insns = list(md.disasm(image[at:min(at+4,stop)], base+at, count=1))
        if not insns:
            continue
        ins = insns[0]
        if not (ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL)):
            continue
        dests = [int(operand.imm) for operand in ins.operands
                 if operand.type == ARM_OP_IMM]
        if not dests or all((d & ~1) != target for d in dests):
            continue
        branches.append({
            "file_offset": hex(at),
            "mapped_address": f"0x{base + at:08x}",
            "raw_instruction_bytes": ins.bytes.hex(),
            "mnemonic": ins.mnemonic,
            "destination": f"0x{target:08x}",
            "real_instruction_boundary_established": False,
            "caller_function_identified": False,
            "reachable_in_hardware": False,
        })
        if len(branches) > MAX_CANDIDATES:
            raise ValueError("Excessive branch candidates")
    return pointers, branches


def audit(image):
    original = audit_original_veneer(image)  # also pins exact SHA-256/IVT/CSF
    # The original image's CSF starts at 0xff030; do not treat signature
    # metadata as code/callers.
    from tools.audit_nxp_rom_advisories_phase81 import SAMPLES
    end = SAMPLES["bruce_prod"]["csf"]
    pointers, branches = enumerate_candidate_references(image, stop=end)
    return {
        "nxp_phase": 85,
        "sample": "bruce_prod",
        "original_sha256": original["original_sha256"],
        "mapped_base": f"0x{BRUCE_XIP_BASE:08x}",
        "scanned_pre_csf_bytes": end,
        "failsafe_veneer_entry": f"0x{FAILSAFE_ENTRY:08x}",
        "pinned_slot_offset": "0x28",
        "raw_pointer_candidates": pointers,
        "decoded_direct_branch_candidates": branches,
        "candidate_pointer_count": len(pointers),
        "candidate_direct_branch_count": len(branches),
        "confirmed_runtime_callers": 0,
        "confirmed_usb_or_update_trigger": False,
        "rom_version_measured": False,
        "go_no_go": "NO_GO_FOR_THIS_STATIC_ROUTE_ABSENT_A_VERIFIED_HOST_TRIGGER",
        "interpretation_limits": [
            "Candidates may occur in data or decode mid-instruction; no full control-flow reachability proof.",
            "Scanning a specific XIP range cannot prove an indirect caller is absent.",
            "No signed OEM evidence that this failsafe veneer reads get_version or permits custom code.",
            "Private bootloader A is not included in this signed Bruce application census.",
            "No device attached, ROM calls, firmware writes, or OCOTP modifications.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = audit(args.image.read_bytes())
    payload = json.dumps(result, indent=2, ensure_ascii=False)+"\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")


if __name__ == "__main__":
    main()
