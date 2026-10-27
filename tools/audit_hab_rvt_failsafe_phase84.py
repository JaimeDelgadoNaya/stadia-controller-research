"""Phase84: pinned original Bruce HAB failsafe veneer (no device execution).

The original signed sequence loads the documented HAB ROM RVT base from an
in-image literal and tail-branches through the RVT +0x28 (failsafe) slot.
Neither the actual pointer contents in ROM nor hardware reachability is known.
"""
import argparse
import json
import struct
from pathlib import Path

from tools.audit_nxp_rom_advisories_phase81 import audit as audit_phase81
from tools.audit_hab_rom_version_phase83 import RVT_BASE

INSTRUCTION_OFFSET = 0x726
LITERAL_OFFSET = 0x810
# Thumb16 encodings, decoded and compared with original SHA-pinned image.
EXPECTED_THUMB = bytes.fromhex("3a48816a0847")
FAILSAFE_SLOT_OFFSET = 0x28
BRUCE_XIP_BASE = 0x60040000


def decode_pinned_fragment(image):
    """Validate exact Thumb16 bytes and derived PC-relative literal address."""
    if not isinstance(image, bytes) or len(image) < LITERAL_OFFSET + 4:
        raise ValueError("Truncated original signed fragment")
    code = image[INSTRUCTION_OFFSET:INSTRUCTION_OFFSET + 6]
    if code != EXPECTED_THUMB:
        raise ValueError("Pinned original Thumb HAB sequence mismatch")
    first, second, third = struct.unpack("<HHH", code)
    if first & 0xf800 != 0x4800 or (first >> 8) & 7 != 0:
        raise ValueError("Expected LDR R0, [PC, #imm] encoding")
    target = ((INSTRUCTION_OFFSET + 4) & ~3) + 4 * (first & 0xff)
    if target != LITERAL_OFFSET:
        raise ValueError("LDR PC-relative effective address mismatch")
    if second & 0xf800 != 0x6800:
        raise ValueError("Expected register-relative word LDR")
    rt, rn, imm5 = second & 7, (second >> 3) & 7, (second >> 6) & 31
    if (rt, rn, imm5 * 4) != (1, 0, FAILSAFE_SLOT_OFFSET):
        raise ValueError("Expected LDR R1, [R0, #0x28]")
    if third != 0x4708:
        raise ValueError("Expected BX R1")
    base = struct.unpack_from("<I", image, LITERAL_OFFSET)[0]
    if base != RVT_BASE:
        raise ValueError("Signed literal is not documented HAB RVT base")
    return {
        "thumb_sequence_file_offset": hex(INSTRUCTION_OFFSET),
        "thumb_sequence_xip_address": hex(BRUCE_XIP_BASE + INSTRUCTION_OFFSET),
        "signed_literal_file_offset": hex(LITERAL_OFFSET),
        "signed_literal_value": f"0x{base:08x}",
        "computed_literal_file_offset": hex(target),
        "rvt_indirect_pointer_slot": f"0x{base + FAILSAFE_SLOT_OFFSET:08x}",
        "rvt_member_by_nxp_layout": "failsafe",
        "traced_static_operations": [
            "LDR R0 from literal at 0x60040810",
            "LDR R1 from 32-bit ROM RVT slot [R0+0x28]",
            "BX R1 (indirect tail branch if the OEM stub is entered)",
        ],
        "get_version_called_by_this_sequence": False,
        "reachable_from_physical_event": "NOT_ESTABLISHED",
        "actual_rom_slot_content": "NOT_READ",
    }


def audit(image):
    original = audit_phase81(image, "bruce_prod")
    result = decode_pinned_fragment(image)
    return {
        "phase": 84, "sample": "bruce_prod",
        "original_sha256": original["sample_sha256"],
        "finding": result,
        "source_for_rvt_layout": "https://github.com/nxp-mcuxpresso/sbl/blob/master/component/secure/semifunc/hab_rvt.c",
        "limits": [
            "These are exact original signed instruction bytes but execution/reachability is not observed.",
            "The 0x28 ROM slot is failsafe, NOT get_version (0x30).",
            "Installed app may differ from the archived signed update file.",
            "Does not measure HAB patch version, bypass signatures, or access device RAM/flash/fuses.",
        ],
        "device_access": False,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", type=Path)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    result = audit(args.image.read_bytes())
    output = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output, encoding="utf-8")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
