"""Phase 84: SHA-pinned offline census of HAB ROM RVT pointer-slot literals.

This is a literal-word survey, NOT a call graph or a ROM-version read.
Only data in the declared authenticated/pre-CSF span is considered.
Words need not be instructions or referenced by instructions.
"""
import argparse
from collections import Counter
import json
import struct
from pathlib import Path

from tools.audit_nxp_rom_advisories_phase81 import SAMPLES, audit as audit_phase81
from tools.audit_hab_rom_version_phase83 import RVT_BASE

# Exact, previously documented RT1060 ROM HAB pointer slots.
SLOTS = {
    RVT_BASE: "rvt_base",
    RVT_BASE + 0x04: "entry_slot",
    RVT_BASE + 0x08: "exit_slot",
    RVT_BASE + 0x24: "report_status_slot",
    RVT_BASE + 0x2C: "authenticate_image_no_dcd_slot",
    RVT_BASE + 0x30: "get_version_slot",
}
MAX_HITS = 4096



def thumb_pc_relative_ldr_candidates(image, literal_offset, *, lookback=1100):
    """Find *syntactic* Thumb LDR-literal encodings targeting a known word.

    16-bit T1 (0x4800) and 32-bit T2 (0xF8DF/0xF85F) are recognized
    without disassembling or validating instruction boundaries. Therefore
    findings remain untrusted code-candidate encodings, not true xrefs.
    """
    if not isinstance(image, bytes) or not 0 <= literal_offset < len(image):
        raise ValueError("Invalid literal offset")
    found = []
    start = max(0, literal_offset - lookback)
    start += start & 1
    for at in range(start, literal_offset, 2):
        if at + 2 > len(image):
            break
        hw = struct.unpack_from("<H", image, at)[0]
        pc = (at + 4) & ~3
        target, encoding = None, None
        if (hw & 0xf800) == 0x4800:
            target = pc + (hw & 0xff) * 4
            encoding = "thumb16_ldr_literal_t1"
        if at + 4 <= len(image) and (hw & 0xff7f) == 0xf85f:
            second = struct.unpack_from("<H", image, at + 2)[0]
            imm = second & 0x0fff
            target = pc + imm if hw & 0x80 else pc - imm
            encoding = "thumb32_ldr_literal_t2"
        if target == literal_offset:
            found.append({
                "potential_instruction_file_offset": hex(at),
                "encoding_shape": encoding,
                "instruction_boundary_verified": False,
                "executed_or_reachable": False,
            })
    return found


def census_pre_csf_words(image, end):
    """Find exact little-endian RVT slot words at halfword-aligned offsets.

    Deliberately no inference of Thumb reachability, MOVW/MOVT synthesis,
    byte-unaligned values, indirect pointers or actual executed paths.
    """
    if not isinstance(image, bytes) or not 0 <= end <= len(image):
        raise ValueError("Invalid image data or census boundary")
    hits = []
    for at in range(0, end - 3, 2):
        address = struct.unpack_from("<I", image, at)[0]
        if address not in SLOTS:
            continue
        hits.append({
            "file_offset": f"0x{at:x}",
            "word": f"0x{address:08x}",
            "slot_name": SLOTS[address],
            "word_alignment": "4_byte" if at % 4 == 0 else "2_byte_only",
            "instruction_reference_confirmed": False,
            "syntactic_thumb_load_candidates": thumb_pc_relative_ldr_candidates(image, at),
        })
        if len(hits) > MAX_HITS:
            raise ValueError("Too many RVT literal candidates")
    return hits


def audit(image, sample):
    original = audit_phase81(image, sample)
    spec = SAMPLES[sample]
    # We intentionally stop before the CSF commands. The signed application
    # can include data pools; the result does not assert code execution.
    end = spec["csf"]
    hits = census_pre_csf_words(image, end)
    tally = Counter(hit["slot_name"] for hit in hits)
    exact_version = [hit for hit in hits if hit["slot_name"] == "get_version_slot"]
    base = [hit for hit in hits if hit["slot_name"] == "rvt_base"]
    return {
        "phase": 84,
        "sample": sample,
        "original_sha256": original["sample_sha256"],
        "census_pre_csf_bytes": end,
        "halfword_alignment_stride_bytes": 2,
        "recognized_slot_words": len(hits),
        "literal_hits": hits,
        "counts_by_slot": {
            SLOTS[slot]: tally[SLOTS[slot]] for slot in sorted(SLOTS)
        },
        "direct_get_version_slot_word_count": len(exact_version),
        "rvt_base_word_count": len(base),
        "get_version_invocation_established": False,
        "actual_rom_version_established": False,
        "interpretation": (
            "Literal candidates are unverified raw data. "
            "A zero count does not rule out a calculated or indirect RVT access."
        ),
        "out_of_scope": [
            "Thumb instruction boundary/reachability and actual uses of literal pools",
            "MOVW/MOVT, address arithmetic and dynamic pointer tables",
            "Installed application identity or the physical BootROM version",
            "HAB bypass, arbitrary execution and firmware recovery",
        ],
        "hardware_access": False,
        "flash_or_efuse_writes": False,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", type=Path)
    ap.add_argument("--sample", required=True, choices=sorted(SAMPLES))
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    result = audit(args.image.read_bytes(), args.sample)
    report = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
