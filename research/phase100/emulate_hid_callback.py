#!/usr/bin/env python3
"""Offline execution of a *bounded handler excerpt* in SHA-verified RT1060 BootROM.

The ROM image is the public nxp/imxrt1060.bootrom.bin. We start INSIDE the
SDP HID callback, at its report-length check, with fully synthetic registers,
stack and OCRAM. We stop BEFORE returning to unknown ROM state. This does
NOT emulate the controller, USB stack, HAB, exploitation, or custom firmware.
The program never opens a USB device, calls NXP SDP or accesses OTP/flash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

ROM_BASE = 0x00200000
ROM_SIZE = 0x20000
EXPECTED_SHA256 = "a5d9af17f0e21866774df91c1e634e955e72b1442aedd84c8aac8eefc8e58f8e"
FUNCTION = 0x0020EA7E
BEGIN = FUNCTION + 0x46
END_ACCEPT = FUNCTION + 0x5E  # next opcode is POP, never executed
END_REJECT = FUNCTION + 0x62  # next opcode is POP, never executed
REPORT_STATE = 0x20210000
MAX_REPORT_BYTES = 0x800
EXPECTED_REPORT_PTR = 0x2020723F
ANCHORS = {
    FUNCTION + 0x46: bytes.fromhex("002c"),  # cmp r4,#0
    FUNCTION + 0x4A: bytes.fromhex("5068"),  # ldr r0,[r2,#4]
    FUNCTION + 0x4C: bytes.fromhex("b0f5006f"),  # cmp.w r0,#0x800
    FUNCTION + 0x50: bytes.fromhex("06d8"),  # bhi rejected
    FUNCTION + 0x52: bytes.fromhex("47f23f21"),  # movw r1,#0x723f
    FUNCTION + 0x56: bytes.fromhex("c2f22001"),  # movt r1,#0x2020
    FUNCTION + 0x5A: bytes.fromhex("0020"),  # movs r0,#0
    FUNCTION + 0x5C: bytes.fromhex("1160"),  # str r1,[r2]
    FUNCTION + 0x60: bytes.fromhex("0520"),  # movs r0,#5
}


def validate_rom(data: bytes) -> dict:
    if len(data) != ROM_SIZE:
        raise ValueError("Expected exactly 128 KiB of PUBLIC RT1060 internal ROM")
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError("Wrong RT1060 reference ROM SHA-256")
    mismatches = [hex(a) for a, seq in ANCHORS.items()
                  if data[a - ROM_BASE:a - ROM_BASE + len(seq)] != seq]
    if mismatches:
        raise ValueError("Static opcode anchors differ: " + ", ".join(mismatches))
    return {"public_reference_sha256": digest, "opcode_anchors_verified": len(ANCHORS)}


def emulate_report_registration(data: bytes, report_length: int) -> dict:
    """Run only the selected ARM Thumb code path with synthetic memory/registers."""
    if not 0 <= report_length <= 0xFFFF:
        raise ValueError("Synthetic report length must be uint16")
    identity = validate_rom(data)

    # Imported here, not needed for SHA/identity-only validation.
    from unicorn import (
        Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_PROT_READ, UC_PROT_WRITE,
        UC_PROT_EXEC, UC_HOOK_CODE, UC_HOOK_MEM_WRITE,
    )
    from unicorn.arm_const import (
        UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R4,
        UC_ARM_REG_SP,
    )

    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.mem_map(ROM_BASE, ROM_SIZE, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(ROM_BASE, data)
    uc.mem_map(0x20000000, 0x20000, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(0x20200000, 0x40000, UC_PROT_READ | UC_PROT_WRITE)
    uc.reg_write(UC_ARM_REG_R0, 0)
    uc.reg_write(UC_ARM_REG_R1, 0)
    uc.reg_write(UC_ARM_REG_R2, REPORT_STATE)
    uc.reg_write(UC_ARM_REG_R4, 1)  # synthetic nonzero precondition, earlier callback not run
    uc.reg_write(UC_ARM_REG_SP, 0x2001FF00)
    uc.mem_write(REPORT_STATE, struct.pack("<II", 0, report_length))

    steps = []
    writes = []
    terminus = [None]

    def trace_code(engine, address, size, user_data):
        steps.append(hex(address))
        if address in (END_ACCEPT, END_REJECT):
            terminus[0] = address
            engine.emu_stop()
        elif not BEGIN <= address <= END_REJECT:
            raise ValueError("Control flow escaped bounded callback excerpt")

    def trace_write(engine, access, address, size, value, user_data):
        # Allow ONLY the expected 4-byte write to the synthetic struct's reportBuffer.
        if (address, size) != (REPORT_STATE, 4):
            raise ValueError("Unexpected emulated RAM write")
        writes.append({"address": hex(address), "value": hex(value & 0xFFFFFFFF)})

    uc.hook_add(UC_HOOK_CODE, trace_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, trace_write)
    uc.emu_start(BEGIN | 1, 0, count=16)
    if terminus[0] not in (END_ACCEPT, END_REJECT):
        raise ValueError("No safe termination in bounded callback path")

    actual_pointer = struct.unpack("<I", uc.mem_read(REPORT_STATE, 4))[0]
    actual_status = uc.reg_read(UC_ARM_REG_R0)

    accepted = report_length <= MAX_REPORT_BYTES
    if accepted:
        if terminus[0] != END_ACCEPT or actual_pointer != EXPECTED_REPORT_PTR:
            raise ValueError("Accepted path did not register expected ROM buffer")
        if actual_status != 0 or len(writes) != 1:
            raise ValueError("Unexpected accepted-path status or writes")
    else:
        if terminus[0] != END_REJECT or actual_pointer != 0:
            raise ValueError("Rejected path modified synthetic report pointer")
        if actual_status != 5 or writes:
            raise ValueError("Rejected path returned unexpected status or writes")

    return {
        **identity,
        "report_length": report_length,
        "accepted_by_bounded_thumb_excerpt": accepted,
        "registered_report_buffer": hex(actual_pointer),
        "status_in_r0": actual_status,
        "executed_addresses": steps,
        "memory_writes": writes,
        "scope": "CPU emulation of selected public RT1060 callback instructions only",
        "real_usb_transfer_performed": False,
        "stadia_rt1061_rom_measured": False,
        "bootrom_overflow_exploited": False,
        "custom_firmware_executed_on_stadia": False,
        "permanent_unlock_or_fuse_action": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public_rom", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    data = args.public_rom.read_bytes()
    result = {
        "method": "sha256_pinned_public_bootrom_bounded_unicorn",
        "runs": [emulate_report_registration(data, n)
                 for n in (0, 1, 2047, 2048, 2049, 4096)],
    }
    output = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.write_text(output, encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
