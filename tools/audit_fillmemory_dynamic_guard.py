"""Offline provenance audit of the Stadia signed loader's FillMemory dynamic guard.

This tool never connects to a gamepad and cannot send a memory command. It
verifies the original image by SHA-256 before interpreting static instructions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools import audit_fillmemory_verified as original
from tools import audit_fillmemory_wrap_model as previous

BASE = original.BASE
GUARD = 0x20003B30
PROVIDER_TABLE = 0x20016074
PROVIDER_PTR_IMAGE_OFFSET = 0x166D8
PROVIDER_CONTEXT_IMAGE_OFFSET = 0x16084
PROVIDER_CONTEXT = 0x20212CD0
DYNAMIC_OFFSETS = (0x70, 0x74, 0x78, 0x7C)
DYNAMIC_ADDRESSES = tuple(PROVIDER_CONTEXT + o for o in DYNAMIC_OFFSETS)
STARTUP_COPY_SOURCE = 0x164D8
STARTUP_COPY_DEST = 0x20208000
STARTUP_COPY_LENGTH = 0x830
SCAN_END = 0x15800


def read_u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def code_window(data: bytes, offset: int, length: int):
    """Linear disassembly for context only; not a CFG or proof of execution."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    ins = list(md.disasm(data[offset:offset + length], BASE + offset))
    if sum(i.size for i in ins) != length:
        raise ValueError("partial instruction decoding in context window")
    return [{"address": hex(i.address), "mnemonic": i.mnemonic,
             "operands": i.op_str} for i in ins]


def guard_symbolic_model(start: int, count: int, runtime_limits: tuple[int, int, int, int],
                         map_first_low: int = 0, map_second_low: int = 0x20000000):
    """Model precisely the branches shown in the guard at 0x20003B30..0x20003B76.

    The 4 runtime fields must be passed explicitly; we MUST NOT invent
    their values for a real device. 'True' means the guard returns nonzero,
    i.e. FillMemory rejects, not accepts. Other guards still apply.
    """
    if len(runtime_limits) != 4 or any(not (0 <= x <= 0xFFFFFFFF) for x in runtime_limits):
        raise ValueError("Four explicit uint32 runtime limits are required")
    A, B, C, D = runtime_limits
    finish = previous.end32(start, count)
    # The first range is tested unless low equals BOTH of its dynamic bounds.
    if not (map_first_low == A == B):
        if start <= B and finish >= A:
            return True
    # Second range: equality of both endpoints suppresses rejection.
    if map_second_low == C == D:
        return False
    if start > D:
        return False
    return finish >= C


def guard_raw_branch_model(start, count, limits, map_first_low=0, map_second_low=0x20000000):
    """Return a compact explanation, without claiming limits are measured."""
    bad = guard_symbolic_model(start, count, limits, map_first_low, map_second_low)
    return {"guard_returns_nonzero": bad, "guard_rejects": bad,
            "calculated_end": hex(previous.end32(start, count)),
            "note": "Runtime boundary values are synthetic inputs, NOT measurements"}


def scan_store_candidates(data, limit=120):
    """Instruction-pattern inventory, *not* provenance or verified reachability."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    hits = []
    # Chunk decoding may begin in data, miss instructions and produce spurious
    # store sites: never treat a hit as a confirmed write to dynamic context.
    for off in range(0x2000, SCAN_END, 0x1000):
        for ins in md.disasm(data[off:min(off + 0x1000, SCAN_END)], BASE + off):
            if ins.mnemonic.lower().startswith(("str", "stm")):
                operand = ins.op_str.lower().replace(" ", "")
                if any("#0x%x]" % d in operand or "#%d]" % d in operand
                       for d in DYNAMIC_OFFSETS):
                    hits.append({"at": hex(ins.address), "instruction": ins.mnemonic+" "+ins.op_str})
    return {"candidate_count": len(hits), "candidates": hits[:limit],
            "limitation": "Linear chunk disassembly. Cannot establish alias to 0x20212cd0 or reachability."}


def analyze_original(data: bytes):
    if len(data) != original.SIZE or hashlib.sha256(data).hexdigest() != original.SHA256:
        raise ValueError("Original Stadia signed RAM loader hash/size mismatch")
    # Strictly verified static indirection chain:
    assertfacts = (
        (PROVIDER_PTR_IMAGE_OFFSET, PROVIDER_TABLE),
        (PROVIDER_CONTEXT_IMAGE_OFFSET, PROVIDER_CONTEXT),
        (0x166D0, 0x202087BC),
        (0x3B78, 0x202081F4),
    )
    for pos, expected in assertfacts:
        if read_u32(data,pos) != expected:
            raise ValueError("Unexpected pinned pointer at " + hex(pos))
    # Interface struct was copied 0x200164d8 -> 0x20208000, 0x830 bytes.
    context_is_copied = STARTUP_COPY_DEST <= PROVIDER_CONTEXT < STARTUP_COPY_DEST + STARTUP_COPY_LENGTH
    if context_is_copied:
        raise ValueError("Provider RAM context unexpectedly overlaps startup copy")
    guard = code_window(data, 0x3B30, 0x48)
    anchors = {
        "context_from_provider_table": ("0x20003b3a", "ldr", "[r3, #0x10]"),
        "range_a": ("0x20003b3e", "ldr", "[r3, #0x70]"),
        "range_b": ("0x20003b44", "ldr", "[r3, #0x74]"),
        "range_c": ("0x20003b58", "ldr", "[r3, #0x78]"),
        "range_d": ("0x20003b5c", "ldr", "[r3, #0x7c]"),
        "wrapped_end_add": ("0x20003b36", "add", "r1, r0"),
    }
    for label, (pc, opcode, operand_fragment) in anchors.items():
        ins=next((item for item in guard if item["address"] == pc), None)
        if not ins or ins["mnemonic"].lower() != opcode or operand_fragment not in ins["operands"]:
            raise ValueError("Guard code anchor changed: " + label)
    # Read one literal pointer only; NO claim that provider RAM holds any value.
    result = {
        "source_sha256_verified": True,
        "guard_entry": hex(GUARD),
        "provenance": {
            "global_ram": hex(0x202081F4),
            "global_context_slot": hex(0x20208200),
            "provider_table": hex(PROVIDER_TABLE),
            "provider_context_pointer_at": hex(0x20016084),
            "provider_context_ram": hex(PROVIDER_CONTEXT),
            "guard_fields": [hex(x) for x in DYNAMIC_ADDRESSES],
            "initial_context_bytes_known": False,
            "context_in_fixed_startup_copy": context_is_copied,
            "context_source": "outside 0x20208000..0x20208830 initialized snapshot; writes during startup/runtime require independent proof",
        },
        "guard_disassembly": guard,
        "provider_function_context": code_window(data,0x98F0,0x180),
        "write_site_inventory": scan_store_candidates(data),
        "runtime_values": {"field_0x70":None,"field_0x74":None,"field_0x78":None,"field_0x7c":None},
        "conclusion": "Four guard bounds are RAM dynamic; exact original defaults/reachability NOT established by immutable image alone.",
        "no_usb": True,
        "no_writes": True
    }
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("loader",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--summary",action="store_true")
    args=p.parse_args()
    out=analyze_original(args.loader.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(out,indent=2)+"\n",encoding="utf-8")
    if args.summary:
        print("Guard fields:",out["provenance"]["guard_fields"])
        print("Provider code context:")
        for ins in out["provider_function_context"]:
            print(ins["address"],ins["mnemonic"],ins["operands"])
        print("Store candidates:", out["write_site_inventory"]["candidate_count"])
        for hit in out["write_site_inventory"]["candidates"][:40]:
            print(hit["at"],hit["instruction"])
        print(out["conclusion"])
    elif not args.out:
        print(json.dumps(out,indent=2))


if __name__ == "__main__":
    main()
