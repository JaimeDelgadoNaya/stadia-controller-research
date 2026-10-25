"""Execute the recorded range helper in isolated ARM emulation, never on hardware."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_PROT_READ, UC_PROT_EXEC, UC_HOOK_CODE
from unicorn import __version__ as UNICORN_VERSION
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

if __package__:
    from .model_ranges import observed_range_check, nonwrapping_range_check
else:
    from model_ranges import observed_range_check, nonwrapping_range_check

IMAGE_SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
HELPER_SHA256 = "29d8988e80bc7a4292ead2e4c029ae437ce0f7220eb66962f10a2c0c3a3eb3ce"
ENTRY = 0x60801FE6
RETURN = 0x1000
CASES = [
    ("whole_interval", 0x60000000, 0x01000000),
    ("last_byte", 0x60FFFFFF, 1),
    ("past_last_byte", 0x60FFFFFF, 2),
    ("below_interval", 0x5FFFFFFF, 1),
    ("above_interval", 0x61000000, 1),
    ("zero_size_at_lower_bound", 0x60000000, 0),
    ("zero_size_inside_interval", 0x60000010, 0),
    ("wrapped_range", 0x60000010, 0xFFFFFFF8),
]


def helper_bytes(evidence):
    if evidence["sha256"] != IMAGE_SHA256:
        raise ValueError("Evidence does not identify the recorded bootloader")
    region = next(r for r in evidence["functions"] if r["start"] == hex(ENTRY))
    instructions = region["instructions"]
    at, chunks = ENTRY, []
    for ins in instructions:
        if int(ins["address"], 16) != at:
            raise ValueError("Noncontiguous instruction evidence")
        raw = bytes.fromhex(ins["bytes"])
        chunks.append(raw)
        at += len(raw)
    if at != 0x6080200A:
        raise ValueError("Unexpected helper extent")
    code = b"".join(chunks)
    if hashlib.sha256(code).hexdigest() != HELPER_SHA256:
        raise ValueError("Helper bytes do not match the recorded function")
    return code


def execute(code, lower, upper, start, size):
    if any(not 0 <= v <= 0xFFFFFFFF for v in (lower, upper, start, size)):
        raise ValueError("Arguments must be unsigned 32-bit values")
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    cpu.mem_map(0x60801000, 0x2000)
    cpu.mem_write(ENTRY, code)
    cpu.mem_protect(0x60801000, 0x2000, UC_PROT_READ | UC_PROT_EXEC)
    cpu.mem_map(0x20000000, 0x2000)
    cpu.mem_map(RETURN, 0x1000)
    cpu.mem_write(0x20000000, struct.pack("<II", lower, upper))
    for register, value in [(UC_ARM_REG_R0, 0x20000000), (UC_ARM_REG_R1, start),
                            (UC_ARM_REG_R2, size), (UC_ARM_REG_SP, 0x20001000),
                            (UC_ARM_REG_LR, RETURN | 1)]:
        cpu.reg_write(register, value)
    count = [0]
    cpu.hook_add(UC_HOOK_CODE, lambda *_: count.__setitem__(0, count[0] + 1))
    cpu.emu_start(ENTRY | 1, RETURN, count=200)
    if cpu.reg_read(UC_ARM_REG_PC) != RETURN:
        raise ValueError("Function did not return within the instruction budget")
    result = cpu.reg_read(UC_ARM_REG_R0)
    if result not in (0, 1):
        raise ValueError("Unexpected function result")
    return bool(result), count[0]


def run(evidence):
    code = helper_bytes(evidence)
    results = []
    for name, start, size in CASES:
        args = (0x60000000, 0x60FFFFFF, start, size)
        actual, instructions = execute(code, *args)
        model = observed_range_check(*args)
        if actual != model:
            raise ValueError(f"Emulator/model disagreement: {name}")
        results.append({"case": name, "start": hex(start), "size": hex(size),
                        "computed_end_uint32": hex((start + size - 1) & 0xFFFFFFFF),
                        "arm_accepts": actual, "model_accepts": model,
                        "nonwrapping_accepts": nonwrapping_range_check(*args),
                        "instructions_executed": instructions})
    return {"image_sha256": IMAGE_SHA256, "helper_address": hex(ENTRY),
            "emulator": "Unicorn", "emulator_version": UNICORN_VERSION,
            "helper_bytes": len(code), "helper_sha256": hashlib.sha256(code).hexdigest(),
            "hardware_access": False, "results": results,
            "scope": "Isolated arithmetic function only; no whole-program reachability or signature bypass demonstrated"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path,
                        default=Path(__file__).resolve().parents[1] / "evidence/bootloader-analysis.json")
    args = parser.parse_args()
    print(json.dumps(run(json.loads(args.evidence.read_text())), indent=2))
