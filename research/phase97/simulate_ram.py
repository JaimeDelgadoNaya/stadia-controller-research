#!/usr/bin/env python3
"""OFFLINE Thumb-subset interpreter for a 20-byte Cortex-M7 RAM demo.

This is a tiny synthetic interpreter, not an i.MX RT1061, BootROM, SDP or HAB
emulator. It forbids any write other than a single private SRAM marker.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

RAM_BASE = 0x20000000
RAM_SIZE = 65536
MARKER_ADDR = RAM_BASE + 0x14
MARKER_VALUE = 0x5a


def simulate(image: bytes) -> dict:
    if len(image) != 20:
        raise ValueError("Expected exactly the 20-byte teaching image")
    ram = bytearray(RAM_SIZE)
    ram[:len(image)] = image
    sp, reset = struct.unpack_from("<II", ram)
    if sp != RAM_BASE + RAM_SIZE:
        raise ValueError("Unexpected illustrative stack value")
    if reset != RAM_BASE + 9 or not reset & 1:
        raise ValueError("Missing or invalid Thumb reset vector")

    pc = reset & ~1
    regs = [0] * 16
    steps = []
    writes = []
    for i in range(8):
        addr = pc - RAM_BASE
        if addr < 8 or addr + 2 > len(image):
            raise ValueError("Opcode fetch outside image")
        op = struct.unpack_from("<H", ram, addr)[0]
        trace = {"pc": hex(pc), "opcode": hex(op)}
        if op & 0xf800 == 0x2000:  # Thumb MOVS #imm8
            rd = (op >> 8) & 7
            regs[rd] = op & 255
            pc += 2
        elif op & 0xf800 == 0x4800:  # Thumb PC-relative literal LDR
            rt = (op >> 8) & 7
            literal = ((pc + 4) & ~3) + ((op & 255) << 2)
            offset = literal - RAM_BASE
            if not 0 <= offset <= len(image) - 4:
                raise ValueError("Literal points outside binary")
            regs[rt] = struct.unpack_from("<I", ram, offset)[0]
            pc += 2
        elif op & 0xf800 == 0x6000:  # Thumb word STR
            rt, rn = op & 7, (op >> 3) & 7
            write_addr = regs[rn] + (((op >> 6) & 31) << 2)
            if write_addr != MARKER_ADDR:
                raise ValueError("Forbidden write outside private RAM marker")
            val = regs[rt]
            struct.pack_into("<I", ram, write_addr - RAM_BASE, val)
            writes.append({"address": hex(write_addr), "value": val})
            pc += 2
        elif op & 0xf800 == 0xe000:  # Thumb unconditional B
            imm11 = op & 0x7ff
            offset = (imm11 if imm11 < 1024 else imm11 - 2048) * 2
            branch = pc + 4 + offset
            if branch != pc:
                raise ValueError("Demo must stop in a local self-loop")
            steps.append(trace)
            if writes != [{"address": hex(MARKER_ADDR), "value": MARKER_VALUE}]:
                raise ValueError("Expected single proof marker write")
            if struct.unpack_from("<I", ram, MARKER_ADDR - RAM_BASE)[0] != MARKER_VALUE:
                raise ValueError("Marker readback failed")
            return {
                "status": "SYNTHETIC_RAM_CODE_EXECUTED",
                "size_bytes": len(image),
                "sha256": hashlib.sha256(image).hexdigest(),
                "steps": steps,
                "writes": writes,
                "hardware_execution_proven": False,
                "hab_bypass_proven": False,
                "flash_modified": False,
                "otp_modified": False,
                "real_usb_or_device_access": False,
            }
        else:
            raise ValueError(f"Unsupported Thumb instruction {op:#06x}")
        steps.append(trace)
    raise ValueError("Demo failed to reach its stop condition")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    output = json.dumps(simulate(args.binary.read_bytes()), indent=2) + "\n"
    if args.out:
        args.out.write_text(output)
    print(output)
