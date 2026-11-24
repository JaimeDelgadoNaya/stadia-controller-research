#!/usr/bin/env python3
"""Phase 104: inspect the HAB ROM Vector Table in a SHA-pinned PUBLIC RT1060 ROM.

The HAB header version byte, slot address and actual get_version() return are
distinct values. No Stadia internal ROM has been measured. Never attempts to
connect to hardware, invoke ROM functions on a device, or modify fuses/flash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from tools.audit_hab_rom_version_phase83 import (
    parse_rvt_snapshot, RVT_BASE, ROM_LOWER, ROM_UPPER_EXCLUSIVE,
)

EXPECTED_SHA = "a5d9af17f0e21866774df91c1e634e955e72b1442aedd84c8aac8eefc8e58f8e"
ROM_START = 0x00200000
ROM_BYTES = 131072
RVT_OFFSET = RVT_BASE - ROM_START
RVT_WINDOW = 128


def public_rom_audit(data: bytes, decoder=None) -> dict:
    if len(data) != ROM_BYTES:
        raise ValueError("Expected complete public 128 KiB RT1060 BootROM")
    actual = hashlib.sha256(data).hexdigest()
    if actual != EXPECTED_SHA:
        raise ValueError("Public RT1060 BootROM SHA-256 mismatch")
    snapshot = data[RVT_OFFSET:RVT_OFFSET+RVT_WINDOW]
    rvt = parse_rvt_snapshot(snapshot)
    version_field = rvt["get_version_slot"]
    if isinstance(version_field, dict):
        pointer = int(version_field["pointer"],16)
        in_rom = (pointer & 1) != 0 and ROM_LOWER <= (pointer & ~1) < ROM_UPPER_EXCLUSIVE
    else:
        pointer = None
        in_rom = False
    result = {
        "phase": 104,
        "public_reference": "Zenofex/SoC-BootROMs/nxp/imxrt1060.bootrom.bin",
        "reference_sha256": actual,
        "rvt": rvt,
        "rvt_get_version_pointer_is_in_public_rom": in_rom,
        "get_version_first_bytes_hex": None,
        "get_version_first_instructions": [],
        "get_version_return_on_public_rom": None,
        "get_version_invoked": False,
        "owner_stadia_rom_observed": False,
        "owner_stadia_hab_patch_version": "UNKNOWN",
        "hab_closed_owner_status_is_rom_version": False,
        "signed_oem_ivt_csf_headers_are_rom_version": False,
        "device_access_performed": False,
        "flash_or_otp_modified": False,
        "custom_firmware_executed_on_stadia": False,
    }
    if in_rom:
        index = (pointer & ~1)-ROM_START
        first = data[index:index+64]
        result["get_version_first_bytes_hex"] = first[:32].hex()
        if decoder is not None:
            instructions = list(decoder.disasm(first, pointer & ~1))
            result["get_version_first_instructions"] = [
                f"{ins.address:#010x}: {ins.mnemonic} {ins.op_str}" for ins in instructions[:24]
            ]
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("public_rom", type=Path)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    result = public_rom_audit(args.public_rom.read_bytes(), Cs(CS_ARCH_ARM,CS_MODE_THUMB))
    serialized = json.dumps(result, indent=2, ensure_ascii=False)+"\n"
    if args.out:
        args.out.write_text(serialized,encoding="utf-8")
    print(serialized)


if __name__ == "__main__":
    main()
