"""Analyze the known bootloader offline; never access or execute a device."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

EXPECTED = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
BASE = 0x60800000
REGIONS = [(0x1C64, 0x1CC0), (0x1CC8, 0x1D38), (0x1D40, 0x1D9C),
           (0x1D9C, 0x1DD0), (0x1DD4, 0x1EAE), (0x1ED0, 0x1EEE),
           (0x1EF0, 0x1F4A), (0x1F5C, 0x1F9E), (0x1FAC, 0x1FE6),
           (0x1FE6, 0x200A), (0x200C, 0x2096), (0x20A8, 0x2170),
           (0x21B4, 0x228A), (0x22FC, 0x231A), (0x285C, 0x2908),
           (0x7E64, 0x7E92), (0x8A50, 0x8A98),
           (0xAA3C, 0xAA40), (0xAA66, 0xAA7A), (0xAA7C, 0xAAFE),
           (0xAB10, 0xAB4C), (0xAB4C, 0xAB8E), (0xB0F0, 0xB134),
           (0xBA2E, 0xBA96), (0xBAC0, 0xBADE), (0xBCB6, 0xBCC4),
           (0xBD50, 0xBDCA), (0xBE40, 0xBE44)]


def analyze(data):
    if hashlib.sha256(data).hexdigest() != EXPECTED:
        raise ValueError("Unknown image: address interpretations require the recorded build/hash")
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    md.detail = True
    records = []
    for start, end in REGIONS:
        instructions = []
        for ins in md.disasm(data[start:end], BASE + start):
            record = {"address": hex(ins.address), "bytes": ins.bytes.hex(),
                      "mnemonic": ins.mnemonic, "operands": ins.op_str}
            if ins.mnemonic in ("bl", "b.w") and ins.operands and ins.operands[0].type == ARM_OP_IMM:
                record["direct_target"] = hex(ins.operands[0].imm)
            if ins.mnemonic.startswith("ldr") and len(ins.operands) > 1:
                source = ins.operands[1]
                if source.type == ARM_OP_MEM and source.mem.base == ARM_REG_PC:
                    location = ((ins.address + 4) & ~3) + source.mem.disp
                    offset = location - BASE
                    if 0 <= offset <= len(data) - 4:
                        record["literal_address"] = hex(location)
                        record["literal_uint32"] = hex(struct.unpack_from("<I", data, offset)[0])
            instructions.append(record)
        if sum(len(bytes.fromhex(i["bytes"])) for i in instructions) != end - start:
            raise ValueError(f"Incomplete decoding in {start:#x}..{end:#x}")
        records.append({"start": hex(BASE + start), "end_exclusive": hex(BASE + end), "instructions": instructions})
    return {"sha256": EXPECTED, "bytes": len(data),
            "build": struct.unpack_from("<I", data, 0x1414)[0],
            "functions": records,
            "storage_vtables": [{"address": hex(BASE + offset),
                                  "entries": [hex(v) for v in struct.unpack_from(
                                      "<" + "I" * (8 if offset == 0x15320 else 6), data, offset)]}
                                 for offset in (0x15300, 0x15320)],
            "scope": "Selected instruction ranges; not a whole-program audit"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.image.read_bytes()), indent=2))
