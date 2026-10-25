"""Offline 32-bit FillMemory interval analysis based on the original Stadia loader.

This module neither assembles/transmits memory commands nor runs a write backend.
The pure arithmetic model separates a *precheck candidate* from a write effect.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from tools import audit_fillmemory_verified as original

MASK = 0xFFFFFFFF
MEMORY_MAP_AT = 0x16C94
MEMORY_MAP_COUNT = 6
RAM_REGION_START = 0x20000000
RAM_REGION_END = 0x2001FFFF
CONTROL_FIELDS = (original.EXEC_ENABLE, original.CALL_ENABLE)
MODEL_NOTE = (
    "A wrapped end can satisfy the static interval prechecks. "
    "A real call still traverses the dynamic protected-region gate and a "
    "large fill loop; memory side effects and recovery are unproved."
)


def end32(start, count):
    if not (0 <= start <= MASK and 1 <= count <= MASK):
        raise ValueError("nonzero uint32 length and uint32 address required")
    return (start + count - 1) & MASK


def policy_op_zero_precheck(start, count, ranges=original.FILL_EXPECTED):
    """Models only the comparisons in 0x200039C4..0x200039E6."""
    finish = end32(start, count)
    return any(start >= low and finish <= high for low, high in ranges)


def parse_memory_regions(data, offset=MEMORY_MAP_AT, count=MEMORY_MAP_COUNT):
    if offset < 0 or offset + count * 16 > len(data):
        raise ValueError("region descriptors outside image")
    return tuple(struct.unpack_from("<4I", data, offset + i * 16)
                 for i in range(count))


def memory_map_precheck(start, count, regions):
    """Models only start/end comparisons in 0x20003A18..0x20003A30."""
    finish = end32(start, count)
    return [dict(start=low, end=high, attr=attributes, methods=interface)
            for low, high, attributes, interface in regions
            if low <= high and low <= start <= high and finish <= high]


def wrap_length_for_end(start, chosen_end):
    if not (0 <= start <= MASK and 0 <= chosen_end <= MASK):
        raise ValueError("start/end must be uint32")
    length = (chosen_end - start + 1) & MASK
    if not length:
        raise ValueError("zero-length witness excluded")
    if start + length - 1 <= MASK:
        raise ValueError("requested witness does not wrap")
    return length


def byte_count_within_region(start, region_end):
    if not (0 <= start <= region_end <= MASK):
        raise ValueError("invalid region")
    return region_end - start + 1


def _assert_ins(data, address, mnemonic, operands=None):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    offset = address - original.BASE
    ins = next(iter(decoder.disasm(data[offset:offset + 4], address, count=1)), None)
    if not ins or ins.mnemonic.lower() != mnemonic.lower() or (
        operands is not None and ins.op_str.lower().replace(" ", "") != operands.lower().replace(" ", "")
    ):
        raise ValueError("32-bit control-flow anchor mismatch at " + hex(address))
    return {"at": hex(address), "instruction": ins.mnemonic + " " + ins.op_str}


def inspect_original(data):
    if len(data) != original.SIZE or hashlib.sha256(data).hexdigest() != original.SHA256:
        raise ValueError("exact original signed image required")
    verified = original.verify_original(data)
    anchors = [
        (0x200039BC, "subs", "r2, #1"),
        (0x200039C2, "add", "r2, r1"),
        (0x200039C6, "cmp", "r1, r4"),
        (0x200039CC, "cmp", "r2, r4"),
        (0x200039CE, "bls", "#0x200039e4"),
        (0x20003A22, "subs", "r0, #1"),
        (0x20003A24, "add", "r1, r0"),
        (0x20003A2A, "cmp", "r4, r1"),
        (0x20003B32, "subs", "r1, #1"),
        (0x20003B36, "add", "r1, r0"),
        (0x200026D6, "stm", "r0!, {r1, r4, r5, r6}"),
        (0x200026D8, "subs", "r2, #0x10"),
        (0x200026F4, "str", "r1, [r0]"),
        (0x200026F8, "subs", "r2, #4"),
    ]
    checks = [_assert_ins(data, a, m, o) for a, m, o in anchors]
    map_entries = parse_memory_regions(data)
    expected_ram = (RAM_REGION_START, RAM_REGION_END, 0x11, 0x20015EA8)
    if expected_ram not in map_entries:
        raise ValueError("original ITCM RAM region absent")
    scenarios = []
    for field in CONTROL_FIELDS:
        # Static witness: an end address at the small FillMemory table limit;
        # no HID packet or write to hardware is created.
        count = wrap_length_for_end(field, 0x2003)
        pre = policy_op_zero_precheck(field, count)
        candidates = memory_map_precheck(field, count, map_entries)
        until_outside_ram = byte_count_within_region(field, RAM_REGION_END)
        if not pre or not any(row["start"] == RAM_REGION_START for row in candidates):
            raise ValueError("witness fails modeled checks; inspect instruction semantics")
        if count <= until_outside_ram:
            raise ValueError("witness unexpectedly fits mapped RAM segment")
        scenarios.append({
            "field": hex(field),
            "ordinary_four_byte_policy_allows": policy_op_zero_precheck(field, 4),
            "wrapped_end_address": hex(end32(field, count)),
            "wrapped_candidate_passes_policy_precheck": pre,
            "wrapped_candidate_matches_initial_memory_map": bool(candidates),
            "required_length_exceeds_mapped_ram": True,
            "bytes_until_leaving_declared_ram_region": until_outside_ram,
            "protected_region_gate_0x20003b30": "DYNAMIC, NOT VERIFIED FOR WITNESS",
            "backend_write_effect": "NOT DEMONSTRATED, no device execution",
            "command_execution_or_recovery": "NOT DEMONSTRATED",
        })
    return {
        "source_sha256": original.SHA256,
        "image_sha256_checked": verified["sha256_matches_original"],
        "verified_instruction_anchors": checks,
        "model_intervals": {
            "FillMemory": [list(x) for x in original.FILL_EXPECTED],
            "RAM_region": list(expected_ram),
        },
        "control_fields_offline_scenarios": scenarios,
        "bounded_conclusion": MODEL_NOTE,
        "note": "The model does not execute the protected-region guard, the backend, or any transport; real RAM state and aliasing are unknown.",
        "device_access": False,
        "memory_writes": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("loader", type=Path)
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    report = inspect_original(args.loader.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
