"""Isolated storage-wrapper emulation with a constructed IVT object and mocked backend."""
import hashlib
import json
import struct
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

FINGERPRINTS = {
    0x6080AA3C: "d19fad8501266b846fb3ccebe743c2dbfc819ce1d06e3660d17a537a9eb0439f",
    0x6080AA66: "a668cf423c26fe35c10e03df9862c1e0507abdba9d61882b30b1da40ab39d9a6",
    0x6080AA7C: "625932530dac7b1b547c63f19cbe385b441ffb2dfa204568fd5d82067cedaafa",
    0x6080B0F0: "d7ac66037af0d9248a2fcdeb436ffdb14141eda6f9e5ff43453d01363c38c212",
}
OBJECT, DEVICE, SOURCE, RETURN = 0x200095F0, 0x20008F34, 0x200019C8, 0x1000
CASES = [("actual_ivt_arguments", 0, 0x1000),
         ("past_partition", 0x1000, 1),
         ("oversized", 0, 0x1001),
         ("synthetic_wrapped_offset", 0xFFFFFFF0, 0x10)]


def execute(evidence, offset, length):
    if any(not 0 <= v <= 0xFFFFFFFF for v in (offset, length)):
        raise ValueError("Expected unsigned 32-bit arguments")
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    cpu.mem_map(0x6080A000, 0x2000)
    cpu.mem_map(0x60808000, 0x1000)
    cpu.mem_map(0x60815000, 0x1000)
    cpu.mem_map(0x20000000, 0x10000)
    cpu.mem_map(RETURN, 0x1000)
    for region in evidence["functions"]:
        address = int(region["start"], 16)
        if address in FINGERPRINTS:
            raw = b"".join(bytes.fromhex(i["bytes"]) for i in region["instructions"])
            if hashlib.sha256(raw).hexdigest() != FINGERPRINTS[address]:
                raise ValueError("Recorded storage instructions changed")
            cpu.mem_write(address, raw)
    present = {int(r["start"], 16) for r in evidence["functions"]}
    if not FINGERPRINTS.keys() <= present:
        raise ValueError("Required instruction evidence is missing")
    tables = {int(t["address"], 16): [int(v, 16) for v in t["entries"]]
              for t in evidence["storage_vtables"]}
    if tables[0x60815300] != [0x6080AB4D, 0x6080AB11, 0x6080B0F1, 0x6080B037, 0x6080AFE5, 0x6080AA3D]:
        raise ValueError("Unexpected plain storage vtable")
    if tables[0x60815320][6:8] != [0x60808E39, 0x60808A51]:
        raise ValueError("Unexpected physical writer/address mapper")
    cpu.mem_write(0x60815300, struct.pack("<6I", *tables[0x60815300]))
    # Only the backend write slot is needed. It is intercepted before execution.
    cpu.mem_write(0x60815320, struct.pack("<8I", *tables[0x60815320]))
    cpu.mem_write(OBJECT, struct.pack("<5I", 0x60815300, DEVICE, 1, 1, 0))
    cpu.mem_write(DEVICE, struct.pack("<6I", 0x60815320, 0x1000, 0x1000, 1, 0, 0))
    for register, value in [(UC_ARM_REG_R0, OBJECT), (UC_ARM_REG_R1, offset),
                            (UC_ARM_REG_R2, SOURCE), (UC_ARM_REG_R3, length),
                            (UC_ARM_REG_SP, 0x2000F000), (UC_ARM_REG_LR, RETURN | 1)]:
        cpu.reg_write(register, value)
    result = {"offset": hex(offset), "length": hex(length), "backend_calls": []}

    def hook(uc, address, size, user_data):
        if address == 0x6080AA98:
            result["stopped_at_bounds_error_path"] = True
            uc.emu_stop()
        elif address == 0x60808E38:
            result["backend_calls"].append({"device": hex(uc.reg_read(UC_ARM_REG_R0)),
                                             "flash_offset": hex(uc.reg_read(UC_ARM_REG_R1)),
                                             "source": hex(uc.reg_read(UC_ARM_REG_R2)),
                                             "length": hex(uc.reg_read(UC_ARM_REG_R3))})
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    cpu.hook_add(UC_HOOK_CODE, hook)
    cpu.emu_start(0x6080B0F1, RETURN, count=500)
    if not result.get("stopped_at_bounds_error_path") and cpu.reg_read(UC_ARM_REG_PC) != RETURN:
        raise ValueError("Wrapper did not return within budget")
    result["physical_backend_executed"] = False
    return result


def run(evidence):
    results = []
    for name, offset, length in CASES:
        case = execute(evidence, offset, length)
        case["case"] = name
        results.append(case)
    return {"hardware_access": False, "object_context": "constructed from statically traced IVT geometry",
            "backend": "intercepted mock returning success; no physical flash routines executed",
            "results": results,
            "scope": "Synthetic wrapper arguments; external control and device-level impact are not established"}


if __name__ == "__main__":
    path = Path(__file__).resolve().parents[1] / "evidence/bootloader-analysis.json"
    print(json.dumps(run(json.loads(path.read_text())), indent=2))
