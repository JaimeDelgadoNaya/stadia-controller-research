"""Verify the REAL signed Stadia flashloader FillMemory policy, read-only.

The original 100672-byte image is obtained separately. This module never
downloads it, connects to a device, or sends memory commands.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools import audit_loader_execution_gate as gate

BASE = 0x20000000
SHA256 = gate.SHA256
SIZE = gate.SIZE
FILL_RANGE_TABLE = 0x166EC     # startup copy at RAM 0x20208214
WRITE_RANGE_TABLE = 0x16744    # startup copy at RAM 0x2020826C
FILL_HANDLER = 0x20003380
FILL_METHOD = 0x20003C86
POLICY = 0x200039A8
EXEC_ENABLE = 0x200159E0
CALL_ENABLE = 0x200159EC

FILL_EXPECTED = (
    (0x00002000, 0x00002003),
    (0x400F8030, 0x400F803B),
    (0x402A8014, 0x402A8017),
    (0x402A8080, 0x402A8083),
    (0x402A80A0, 0x402A80BF),
)
WRITE_EXPECTED = tuple(gate.WRITE_RANGES)


def range_pairs(data, offset, count):
    return tuple(struct.unpack_from("<2I", data, offset + i * 8)
                 for i in range(count))


def ordinary_nonwrapping_allowed(ranges, address, length):
    """Positive, nonwrapping operation ONLY; reject unmodeled arithmetic."""
    if not (0 <= address <= 0xFFFFFFFF and 1 <= length <= 0xFFFFFFFF):
        raise ValueError("invalid uint32 address or positive length")
    if address + length - 1 > 0xFFFFFFFF:
        raise ValueError("wrapped end address is outside this model")
    end = address + length - 1
    return any(address >= low and end <= high for low, high in ranges)


def _check_instruction(data, address, predicate, label):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    md.detail = True
    pos = address - BASE
    ins = next(iter(md.disasm(data[pos:pos + 4], address, count=1)), None)
    if not ins or not predicate(ins):
        raise ValueError("instruction check failed: " + label)
    return {"address": hex(address), "mnemonic": ins.mnemonic, "operands": ins.op_str}


def verify_original(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("exact signed loader size/SHA-256 required")
    word = lambda off: struct.unpack_from("<I", data, off)[0]
    pointer_facts = {
        "handler_literal_RAM": (0x339C, 0x202081F4),
        "startup_copied_memory_interface": (0x166CC, 0x20015E8C),
        "memory_interface_fill_method_thumb": (0x15E98, 0x20003C87),
        "Fill_policy_table_RAM": (0x39F0, 0x20208214),
        "Write_policy_table_RAM": (0x39EC, 0x2020826C),
    }
    for name, (off, expected) in pointer_facts.items():
        if word(off) != expected:
            raise ValueError("pointer/literal mismatch: " + name)
    for tag, expected in ((4, True), (5, True), (9, False), (10, False)):
        if gate.command_entry(data, tag)["dispatches"] != expected:
            raise ValueError("command dispatch flags mismatch")
    fill = range_pairs(data, FILL_RANGE_TABLE, 5)
    write = range_pairs(data, WRITE_RANGE_TABLE, 4)
    if fill != FILL_EXPECTED or write != WRITE_EXPECTED:
        raise ValueError("verified access-range table differs")
    checks = [
        _check_instruction(data, 0x2000338E,
                           lambda i: i.mnemonic.lower() == "blx" and i.op_str.lower() == "r3",
                           "FillMemory dispatcher indirect call"),
        _check_instruction(data, 0x20003C94,
                           lambda i: i.mnemonic.lower().startswith("mov") and i.op_str.lower().replace(" ", "") == "r0,#0",
                           "Fill policy operation 0"),
        _check_instruction(data, 0x20003C96,
                           lambda i: i.mnemonic.lower() == "bl" and "0x200039a8" in i.op_str.lower(),
                           "Fill calls address policy"),
        _check_instruction(data, 0x20003CA0,
                           lambda i: i.mnemonic.lower() == "bl" and "0x20003b30" in i.op_str.lower(),
                           "Fill calls memory-region check"),
        _check_instruction(data, 0x20003CAC,
                           lambda i: i.mnemonic.lower() == "bl" and "0x200039f4" in i.op_str.lower(),
                           "Fill calls memory-map lookup"),
        _check_instruction(data, 0x20003CBE,
                           lambda i: i.mnemonic.lower() == "blx" and i.op_str.lower() == "r3",
                           "Fill calls indirect region backend"),
    ]
    h = lambda value: hex(value)
    def table_format(items):
        return [{"start": h(start), "end_inclusive": h(end)} for start, end in items]
    return {
        "image_size": len(data),
        "sha256_matches_original": True,
        "signed_loader_sha256": SHA256,
        "original_bytes_verified": True,
        "source_note": "Original expected SHA-256; external archive must be independently checked",
        "fill_handler": h(FILL_HANDLER),
        "fill_method": h(FILL_METHOD),
        "range_policy_shared": h(POLICY),
        "policy_operation": {"FillMemory": 0, "WriteMemory": 2},
        "fill_ranges": table_format(fill),
        "write_ranges": table_format(write),
        "instruction_anchors": checks,
        "normal_positive_nonwrapping_fill_to_execution_flags": {
            h(EXEC_ENABLE): ordinary_nonwrapping_allowed(fill, EXEC_ENABLE, 4),
            h(CALL_ENABLE): ordinary_nonwrapping_allowed(fill, CALL_ENABLE, 4),
        },
        "unresolved": [
            "Potential uint32 wrap in isolated end-address arithmetic; downstream conditions and effects not audited exhaustively",
            "Dynamic RAM state and indirect callback substitution not measured",
            "No demonstrated unsigned code execution, HAB bypass, or reliable recovery",
        ],
        "hardware_access": False,
        "firmware_writes": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("loader", type=Path, help="Exact original signed image, local file only")
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    result = json.dumps(verify_original(args.loader.read_bytes()), indent=2) + "\n"
    if args.out:
        args.out.write_text(result, encoding="utf-8")
    else:
        print(result, end="")


if __name__ == "__main__":
    main()
