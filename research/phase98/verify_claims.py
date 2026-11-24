#!/usr/bin/env python3
"""Nine static Thumb opcode signatures in SHA-verified PUBLIC RT1060 BootROM.

Does not emulate whole BootROM, execute payloads or infer Stadia chip ROM identity.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from research.phase98.inspect_rom import ROM_BASE, ROM_SIZE, ROM_SHA

MPU = 0x0020CAB8
HID = 0x0020EA7E

SIGNATURES = {
  "mpu_disable_ctrl": (MPU + 0x30, bytes.fromhex("3160")),
  "mpu_set_ctrl_7": (MPU + 0xA8, bytes.fromhex("3760")),
  "mpu_jump_skips_ctrl_enable": (MPU + 0xA6, bytes.fromhex("04e0")),
  "mpu_loopback_before_skip": (MPU + 0xA4, bytes.fromhex("d6d3")),
  "hid_report_length_cmp_2048": (HID + 0x4C, bytes.fromhex("b0f5006f")),
  "hid_report_too_long_branch": (HID + 0x50, bytes.fromhex("06d8")),
  "hid_report_buf_low16": (HID + 0x52, bytes.fromhex("47f23f21")),
  "hid_report_buf_high16": (HID + 0x56, bytes.fromhex("c2f22001")),
  "hid_report_write_buf_pointer": (HID + 0x5C, bytes.fromhex("1160")),
}

def branch_target(opcode: int, pc: int) -> int:
    if opcode & 0xF800 == 0xE000:
        imm = opcode & 0x7FF
        if imm & 0x400: imm -= 0x800
        return pc + 4 + (imm << 1)
    if opcode & 0xF000 == 0xD000 and ((opcode >> 8) & 0xF) < 0xE:
        imm = opcode & 0xFF
        if imm & 0x80: imm -= 0x100
        return pc + 4 + (imm << 1)
    raise ValueError("not a supported Thumb16 conditional/unconditional branch")

def verify_static(data: bytes) -> dict:
    if len(data) != ROM_SIZE:
        raise ValueError("wrong raw ROM size")
    if hashlib.sha256(data).hexdigest() != ROM_SHA:
        raise ValueError("wrong public reference SHA-256")
    matches = {}
    for name, (addr, expected) in SIGNATURES.items():
        off = addr - ROM_BASE
        matches[name] = data[off:off+len(expected)] == expected
    result = {
      "rom_sha256_verified": True,
      "all_nine_signatures_present": all(matches.values()),
      "signatures": matches,
      "mpu_normal_loop_exit_branch": hex(branch_target(
          struct.unpack_from("<H", data, MPU+0xA6-ROM_BASE)[0], MPU+0xA6)),
      "mpu_enable_store_address": hex(MPU+0xA8),
      "mpu_early_exit_branch_target": hex(branch_target(
          struct.unpack_from("<H", data, MPU+0x58-ROM_BASE)[0], MPU+0x58)),
      "hid_length_limit": 2048,
      "report_ptr_address_from_thumb_immediates": "0x2020723f",
      "author_labeled_global_start": "0x2020723c",
      "author_labeled_next_global": "0x20207a3c",
      "overflow_bytes_in_author_memory_layout": 0x2020723f+2048-0x20207a3c,
      "static_only": True,
      "complete_control_flow_validated": False,
      "stadia_internal_bootrom_verified": False,
      "real_code_execution_proven": False,
      "hab_bypass_on_stadia_proven": False,
    }
    if not result["all_nine_signatures_present"]:
        raise ValueError("ROM signatures do not match expected opcodes")
    if result["mpu_normal_loop_exit_branch"] != hex(MPU+0xB2):
        raise ValueError("MPU branch target unexpected")
    if result["mpu_early_exit_branch_target"] != hex(MPU+0xA8):
        raise ValueError("MPU abnormal exit target unexpected")
    if result["overflow_bytes_in_author_memory_layout"] != 3:
        raise ValueError("HID layout not 3-byte overlap")
    return result

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("rom", type=Path)
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    result = json.dumps(verify_static(args.rom.read_bytes()), indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(result, encoding="utf-8")
    print(result)

if __name__ == "__main__":
    main()
