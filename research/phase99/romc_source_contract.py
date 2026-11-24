"""SHA-locked offline provenance checks for the user's nxp-sdp-overrun main.py.

This file only parses text, never imports exploit modules, connects USB,
assembles or executes shellcode. No private/OEM binaries committed.
"""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path

SHA256 = "e41e659f25388578ef9b2c1a1800adecf9e290d5ec0b57fbabb8705c3f765404"
BASE = 0x40180000
ROMC = {
    "data": BASE + 0xD4 + 0x1C,   # 0x401800f0
    "address": BASE + 0xD4 + 0x2C, # 0x40180100
    "enable": BASE + 0xD4 + 0x28, # 0x401800fc
    "control": BASE + 0xD4 + 0x20, # 0x401800f4
}

def find_string(t: ast.Module, name: str) -> str:
    for s in t.body:
        if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
            if s.targets[0].id == name and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str):
                return s.value.value
    raise ValueError("Missing source string: " + name)

def audit(path: Path) -> dict:
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != SHA256:
        raise ValueError("Unrecognized SHA-256 of uploaded exploit source")
    t = ast.parse(data, filename=str(path))
    normal = find_string(t, "SHELLCODE_ROMC")
    permanent = find_string(t, "SHELLCODE_FIELD_RETURN")
    instructions = [
        "ldr r1, =usb_dev", "ldr r0, =sdp_dev", "str r1, [r0]",
        "ldr r0, =romc", "adds r0, #0xd4", "ldr r1, =hab_config_patch",
        "str r1, [r0, #0x1c]", "ldr r1, =hab_get_config",
        "str r1, [r0, #0x2c]", "movs r1, #0x1",
        "str r1, [r0, #0x28]", "str r1, [r0, #0x20]", "bx lr",
    ]
    cursor = 0
    for instr in instructions:
        found = normal.find(instr, cursor)
        if found < 0:
            raise ValueError("Patch sequence differs or is reordered: " + instr)
        cursor = found + len(instr)
    text = data.decode("utf-8")
    if "ks.asm(\"movs r0, #0xf0; bx lr\")" not in text:
        raise ValueError("Return-value patch has changed")
    if "SHELLCODE_FIELD_RETURN if args.permanent else SHELLCODE_ROMC" not in text:
        raise ValueError("Default route has changed")
    if "ocotp" in normal.lower() or "field_return" in normal.lower():
        raise ValueError("Default branch unexpectedly mentions irreversible path")
    if "ocotp" not in permanent.lower() or "field_return" not in permanent.lower():
        raise ValueError("Permanent branch could not be identified")
    return {
        "sha256": sha,
        "status": "ORIGINAL_SOURCE_STATIC_SEQUENCE_VERIFIED",
        "romc_registers_from_source": {k: hex(v) for k, v in ROMC.items()},
        "patch_instruction_bytes_expected": "f0207047",
        "hab_return_value_intended": "0xf0",
        "usb_pointer_restoration_precedes_romc_register_writes": True,
        "default_path_avoids_ocotp": True,
        "permanent_path_uses_ocotp": True,
        "hid_write_length_verifies_real_execution": False,
        "actual_stadia_bootrom_equivalence": False,
        "actual_stadia_custom_firmware_executed": False,
    }

def gate(rom_match: bool, patch_observed: bool, loader_accepted: bool,
         marker_observed: bool, same_boot: bool) -> str:
    if not rom_match: return "BLOCKED_ROM_IDENTITY_UNKNOWN"
    if not same_boot: return "NEW_BOOT_REQUIRES_NEW_VERIFICATION"
    if not patch_observed: return "PATCH_EFFECT_NOT_OBSERVED"
    if not loader_accepted: return "UNSIGNED_LOAD_NOT_OBSERVED"
    if not marker_observed: return "CODE_EXECUTION_NOT_OBSERVED"
    return "ALL_GATES_HYPOTHETICALLY_ASSUMED_NOT_PROVEN"

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("original_main_py", type=Path)
    args = p.parse_args()
    print(json.dumps(audit(args.original_main_py), indent=2))
