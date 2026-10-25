"""Offline, fingerprinted audit of Stadia bootloader app dispatch.

This script reads published disassembly only. No USB, flash or CPU emulation.
"""
import argparse
import hashlib
import json
from pathlib import Path

IMAGE_SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
REGION_START = 0x60801EF0
REGION_END = 0x60801F4A
REGION_SHA256 = "3d167008abac66682b155fc2ee091c34811cdd70517fda34b3b0853df5787afe"

# Expected instruction meanings pin the model to the evidence, not to labels.
REQUIRED = {
    0x60801EF0: ("cmp", "r0, #2"),
    0x60801EF4: ("beq", "#0x60801f18"),
    0x60801EF6: ("cmp", "r0, #3"),
    0x60801EF8: ("bne", "#0x60801f16"),
    0x60801EFA: ("ldr", "r4, [pc, #0x50]"),
    0x60801EFC: ("movs", "r5, #0"),
    0x60801F00: ("bl", "#0x6080200c"),
    0x60801F04: ("tst.w", "r0, #0xff"),
    0x60801F08: ("beq", "#0x60801f1e"),
    0x60801F0A: ("cmp", "r5, #0"),
    0x60801F0C: ("ldr", "r3, [pc, #0x40]"),
    0x60801F0E: ("ite", "eq"),
    0x60801F10: ("moveq", "r2, #0x20"),
    0x60801F12: ("movne", "r2, #0x10"),
    0x60801F14: ("str", "r2, [r3, #0x38]"),
    0x60801F16: ("pop", "{r3, r4, r5, pc}"),
    0x60801F18: ("ldr", "r4, [pc, #0x38]"),
    0x60801F1A: ("movs", "r5, #1"),
    0x60801F1C: ("b", "#0x60801efe"),
    0x60801F1E: ("ldrd", "r3, r2, [r4]"),
    0x60801F22: ("ldr", "r1, [pc, #0x34]"),
    0x60801F24: ("cpsid", "i"),
    0x60801F2E: ("str", "r4, [r1]"),
    0x60801F30: ("msr", "msp, r3"),
    0x60801F34: ("msr", "psp, r3"),
    0x60801F46: ("mov", "pc, r2"),
}


def verified_instructions(evidence):
    """Reject mismatched build, altered ARM bytes and inconsistent disassembly."""
    if evidence.get("sha256") != IMAGE_SHA256:
        raise ValueError("Evidence is not from the recorded bootloader")
    matches = [r for r in evidence.get("functions", [])
               if r.get("start") == hex(REGION_START)]
    if len(matches) != 1 or matches[0].get("end_exclusive") != hex(REGION_END):
        raise ValueError("Missing or different application-selection region")
    by_address, raw, position = {}, bytearray(), REGION_START
    for ins in matches[0]["instructions"]:
        address = int(ins["address"], 16)
        if address != position or address in by_address:
            raise ValueError("Noncontiguous or duplicated instruction evidence")
        chunk = bytes.fromhex(ins["bytes"])
        if len(chunk) not in (2, 4):
            raise ValueError("Invalid Thumb instruction length")
        raw.extend(chunk)
        position += len(chunk)
        by_address[address] = ins
    if position != REGION_END or hashlib.sha256(raw).hexdigest() != REGION_SHA256:
        raise ValueError("Application selector instruction fingerprint mismatch")
    for address, expected in REQUIRED.items():
        ins = by_address.get(address)
        if ins is None or (ins.get("mnemonic"), ins.get("operands")) != expected:
            raise ValueError(f"Unexpected dispatch instruction at {address:#x}")
    return by_address


def audit(evidence):
    instructions = verified_instructions(evidence)

    def literal(address):
        return int(instructions[address]["literal_uint32"], 16)

    app_a = literal(0x60801F18)
    app_b = literal(0x60801EFA)
    gpr6 = literal(0x60801F0C) + 0x38
    vtor = literal(0x60801F22)
    if (app_a, app_b, gpr6, vtor) != (0x60040000, 0x60840000, 0x400F8038, 0xE000ED08):
        raise ValueError("Unexpected literals in documented application dispatch")
    if int(instructions[0x60801F00]["direct_target"], 16) != 0x6080200C:
        raise ValueError("Unexpected application validator target")

    cases = []
    for selected_id in (2, 3, 0, 4):
        outcomes = (False, True) if selected_id in (2, 3) else (None,)
        for valid in outcomes:
            if selected_id not in (2, 3):
                row = {"selected_id": selected_id, "validation_success": None,
                       "action": "return_without_dispatch"}
            elif valid:
                row = {"selected_id": selected_id, "validation_success": True,
                       "action": "prepare_vector_table_and_branch",
                       "application_base": hex(app_a if selected_id == 2 else app_b),
                       "vtor": hex(vtor)}
            else:
                row = {"selected_id": selected_id, "validation_success": False,
                       "action": "write_boot_status_and_return",
                       "application_base": hex(app_a if selected_id == 2 else app_b),
                       "status_register": hex(gpr6),
                       "status_value": hex(0x10 if selected_id == 2 else 0x20)}
            cases.append(row)
    return {"image_sha256": IMAGE_SHA256, "region": hex(REGION_START),
            "region_sha256": REGION_SHA256, "validator": hex(0x6080200C),
            "scenarios": cases, "hardware_access": False,
            "evidence_level": "fingerprinted disassembly and symbolic control-flow model",
            "limitations": ["The caller supplying selector IDs is not audited here",
                            "Validation outcome is synthetic; the validator is not emulated",
                            "Success-path branch is not executed, and no fallback/retry is demonstrated",
                            "No bypass, custom firmware, or device-level recovery demonstrated"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=Path(__file__).resolve().parents[1]
                        / "evidence/bootloader-analysis.json")
    args = parser.parse_args()
    print(json.dumps(audit(json.loads(args.evidence.read_text(encoding="utf-8"))), indent=2))


if __name__ == "__main__":
    main()
