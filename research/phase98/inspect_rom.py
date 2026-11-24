#!/usr/bin/env python3
"""Read-only Thumb disassembly of public RT1060 BootROM snippets.

Requires the exact 128-KiB ROM reference SHA256 from nxp-sdp-overrun README,
Clang and llvm-objdump. It cannot inspect any actual Stadia unit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile

ROM_BASE = 0x00200000
ROM_SIZE = 131072
ROM_SHA = "a5d9af17f0e21866774df91c1e634e955e72b1442aedd84c8aac8eefc8e58f8e"
REGIONS = {
    "enable_mpu": {"address": 0x0020CAB8, "length": 320},
    "sdp_hid_callback": {"address": 0x0020EA7E, "length": 192},
    "hab_get_config": {"address": 0x002147F8, "length": 64},
}

def inspect_rom(data: bytes, disassemble: bool = True) -> dict:
    if len(data) != ROM_SIZE:
        raise ValueError(f"raw internal ROM must contain exactly {ROM_SIZE} bytes")
    sha = hashlib.sha256(data).hexdigest()
    if sha != ROM_SHA:
        raise ValueError(f"reference ROM SHA-256 mismatch: {sha}")
    result = {
        "reference_sha256": sha,
        "rom_base": f"0x{ROM_BASE:08x}",
        "provenance": "Zenofex public RT1060 reference, NOT verified Stadia internal ROM",
        "execution_proven": False,
        "hab_bypass_proven": False,
        "regions": {},
    }
    for name, ref in REGIONS.items():
        start = ref["address"] - ROM_BASE
        buf = data[start:start + ref["length"]]
        if len(buf) != ref["length"]:
            raise ValueError("region outside source")
        entry = {
            "function_label_author_supplied": name,
            "origin": f"0x{ref['address']:08x}",
            "size": len(buf),
            "sha256": hashlib.sha256(buf).hexdigest(),
            "first_32_bytes_hex": buf[:32].hex(),
            "assume_thumb_entry": True,
            "instructions": None,
        }
        if disassemble:
            with tempfile.TemporaryDirectory(prefix="rom-thumb-") as d:
                p = pathlib.Path(d)
                snippet = p / "snippet.bin"
                snippet.write_bytes(buf)
                asm = p / "snippet.S"
                asm.write_text(
                    ".syntax unified\n.cpu cortex-m7\n.thumb\n"
                    ".section .text.ref,\"ax\",%progbits\n.global ref_function\n"
                    ".thumb_func\nref_function:\n"
                    f'.incbin "{snippet}"\n',
                    encoding="utf-8",
                )
                obj = p / "snippet.o"
                subprocess.run(
                    ["clang", "--target=arm-none-eabi", "-mcpu=cortex-m7", "-mthumb",
                     "-c", str(asm), "-o", str(obj)],
                    check=True, capture_output=True, text=True,
                )
                out = subprocess.run(
                    ["llvm-objdump", "-d", "--triple=thumbv7em-none-eabi", str(obj)],
                    check=True, capture_output=True, text=True,
                ).stdout
                entry["instructions"] = "\n".join(
                    line for line in out.splitlines() if "\t" in line and ":" in line
                )
        result["regions"][name] = entry
    return result

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("rom", type=pathlib.Path)
    ap.add_argument("--out", type=pathlib.Path)
    args = ap.parse_args()
    result = inspect_rom(args.rom.read_bytes())
    output = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.write_text(output, encoding="utf-8")
    print(output)

if __name__ == "__main__":
    main()
