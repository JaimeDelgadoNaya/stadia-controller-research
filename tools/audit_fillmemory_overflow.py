"""Bounded static inspection of FillMemory arithmetic and memory backend.

Read-only. Uses the exact SHA-pinned original Stadia loader file.
Disassembly is evidence for analysis, not a control-flow or exploit proof.
"""
import argparse
import hashlib
import json
from pathlib import Path
from tools import audit_fillmemory_verified as original

WINDOWS = {
    "policy_selector_and_range_loop": (0x39A8, 0x39F4),
    "additional_memory_map_checks": (0x39F4, 0x3A9C),
    "target_region_bounds": (0x3B30, 0x3B78),
    "fill_region_and_backend": (0x3C86, 0x3CC4),
}


def inspect(data):
    if len(data) != original.SIZE or hashlib.sha256(data).hexdigest() != original.SHA256:
        raise ValueError("Require exact signed original sample")
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    rows = {}
    for name, (start, end) in WINDOWS.items():
        pos = start
        values = []
        for ins in md.disasm(data[start:end], original.BASE + start):
            if ins.address != original.BASE + pos:
                raise ValueError("disassembly gap in " + name)
            values.append({"address": hex(ins.address), "mnemonic": ins.mnemonic,
                           "operands": ins.op_str})
            pos += ins.size
        if pos != end:
            raise ValueError("incomplete disassembly " + name)
        rows[name] = values
    return {
        "original_sha256_checked": True,
        "windows": rows,
        "status": "STATIC ONLY: no command invoked, no branch reachability or memory effect established",
        "device_access": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("loader", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--print-disassembly", action="store_true", help="Print bounded code only")
    args = p.parse_args()
    result = inspect(args.loader.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if args.print_disassembly:
        for label, items in result["windows"].items():
            print("## " + label)
            for item in items:
                print("%s: %-8s %s" % (item["address"], item["mnemonic"], item["operands"]))
    elif not args.out:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
