"""Offline USB-surface triage for Stadia bootloader build 169429.

Runs on public instruction evidence or a *local* 128 KiB binary, never a USB
device. Descriptor matches and callgraph candidates are NOT proof of a
reachable USB command dispatcher, firmware write, or authentication bypass.
"""

import argparse
import hashlib
import json
import struct
from collections import deque
from pathlib import Path

BASE = 0x60800000
IMAGE_SIZE = 0x20000
KNOWN_SHA256 = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
BOOT_VECTOR_OFFSET = 0x1000
KNOWN_VENDORS = {0x18D1: "Google", 0x1FC9: "NXP", 0x15A2: "NXP"}
KNOWN_PRODUCTS = {0x9400: "Stadia OEM", 0x946B: "Stadia bootloader",
                  0x0135: "NXP SDP", 0x0073: "NXP RAM flashloader"}


def _hex(value):
    return f"0x{value:08x}"


def audit_public_evidence(evidence):
    """Describe known coverage, without inventing a USB-to-writer path."""
    if (evidence.get("sha256") != KNOWN_SHA256 or
            evidence.get("build") != 169429 or
            evidence.get("bytes") != IMAGE_SIZE):
        raise ValueError("Unexpected evidence provenance or bootloader build")

    ranges = []
    instructions = []
    for f in evidence["functions"]:
        start, end = int(f["start"], 16), int(f["end_exclusive"], 16)
        if not BASE <= start < end <= BASE + IMAGE_SIZE:
            raise ValueError("Disassembly range outside bootloader")
        position = start
        for ins in f["instructions"]:
            if int(ins["address"], 16) != position:
                raise ValueError("Noncontiguous instruction evidence")
            raw = bytes.fromhex(ins["bytes"])
            if not raw:
                raise ValueError("Empty instruction")
            position += len(raw)
            instructions.append(ins)
        if position != end:
            raise ValueError("Disassembly byte coverage mismatch")
        ranges.append((start, end))
    ordered = sorted(ranges)
    if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
        raise ValueError("Overlapping disassembly ranges")

    def included(addr):
        return any(lo <= addr < hi for lo, hi in ranges)

    direct = [i for i in instructions if i["mnemonic"] == "bl" and "direct_target" in i]
    outside = [i for i in direct if not included(int(i["direct_target"], 16))]
    indirect = [i for i in instructions
                if i["mnemonic"] in ("blx", "bx") and i["operands"] != "lr"]
    inspected = sum(hi - lo for lo, hi in ranges)
    return {
        "image_build": 169429,
        "reported_image_sha256": KNOWN_SHA256,
        "firmware_binary_examined": False,
        "selected_regions": len(ranges),
        "selected_instruction_bytes": inspected,
        "image_bytes": IMAGE_SIZE,
        "coverage_percent": round(inspected * 100 / IMAGE_SIZE, 3),
        "direct_calls": len(direct),
        "direct_calls_outside_selection": len(outside),
        "indirect_transfer_sites": len(indirect),
        "known_internal_writer": _hex(0x6080B0F0),
        "known_physical_writer": _hex(0x60808E38),
        "usb_dispatcher": "NOT IDENTIFIED FROM SELECTED INSTRUCTIONS",
        "usb_to_writer_reachability": "NOT DEMONSTRATED",
        "hardware_access": False,
    }


def _device_descriptors(image):
    """Find strictly-shaped USB descriptors; candidates may be unused data."""
    found = []
    for off in range(IMAGE_SIZE - 17):
        if image[off:off+2] != b"\x12\x01":
            continue
        bcd_usb = struct.unpack_from("<H", image, off + 2)[0]
        vendor, product = struct.unpack_from("<HH", image, off + 8)
        if (vendor not in KNOWN_VENDORS or
                not 0x0100 <= bcd_usb <= 0x0340 or
                image[off + 7] not in (8, 16, 32, 64) or
                not 1 <= image[off + 17] <= 8):
            continue
        found.append({
            "address": _hex(BASE + off),
            "vid": f"0x{vendor:04x}",
            "pid": f"0x{product:04x}",
            "vendor_label": KNOWN_VENDORS[vendor],
            "product_label": KNOWN_PRODUCTS.get(product, "unknown"),
            "evidence": "possible USB device descriptor: presence != active USB mode",
        })
    return found


def _pointer_refs(image, targets):
    """Exact aligned 32-bit pointers; presence alone does not prove use."""
    pointers = []
    for off in range(0, len(image) - 3, 4):
        value = struct.unpack_from("<I", image, off)[0]
        if value in targets:
            pointers.append({"pointer_at": _hex(BASE + off), "points_to": _hex(value)})
    return pointers


def _vector_entries(image, count=96):
    """Collect *candidate* Cortex-M vector entries at IVT + 0x1000."""
    sp, reset = struct.unpack_from("<II", image, BOOT_VECTOR_OFFSET)
    if not 0x20000000 <= sp < 0x20400000 or not (reset & 1):
        return {"valid_initial_sp_and_reset": False, "initial_sp": _hex(sp),
                "reset_vector": _hex(reset), "candidates": []}
    entries = []
    for slot in range(min(count, (len(image) - BOOT_VECTOR_OFFSET) // 4)):
        ptr = struct.unpack_from("<I", image, BOOT_VECTOR_OFFSET + 4*slot)[0]
        if (ptr & 1) and BASE <= (ptr & ~1) < BASE + len(image):
            entries.append({"vector_slot": slot, "handler": _hex(ptr & ~1)})
    return {"valid_initial_sp_and_reset": True, "initial_sp": _hex(sp),
            "reset_vector": _hex(reset), "candidates": entries}


def _code_walk(image, entry_points, descriptor_addrs, instruction_limit=25000):
    """Conservative *potential* Thumb control-flow graph, not dynamic tracing."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    decoder.detail = True
    work = deque(entry_points)
    seen = set()
    calls = []
    descriptor_literals = []
    indirect = []
    while work and len(seen) < instruction_limit:
        addr = work.popleft() & ~1
        while BASE <= addr < BASE + len(image) - 1 and addr not in seen and len(seen) < instruction_limit:
            offset = addr - BASE
            inst = next(decoder.disasm(image[offset:offset+4], addr, count=1), None)
            if inst is None:
                break
            seen.add(addr)
            next_addr = addr + inst.size
            if (inst.mnemonic.startswith("ldr") and len(inst.operands) > 1 and
                    inst.operands[1].type == ARM_OP_MEM and
                    inst.operands[1].mem.base == ARM_REG_PC):
                source = inst.operands[1]
                lit = ((addr + 4) & ~3) + source.mem.disp
                i = lit - BASE
                if 0 <= i <= len(image) - 4:
                    val = struct.unpack_from("<I", image, i)[0]
                    if val in descriptor_addrs:
                        descriptor_literals.append({
                            "instruction": _hex(addr),
                            "literal_address": _hex(lit),
                            "descriptor": _hex(val),
                            "note": "potential code reference; not proven USB dispatch",
                        })
            if inst.mnemonic in ("bl", "b", "b.w") or (
                    inst.mnemonic.startswith("b") and inst.mnemonic in {
                        "beq", "bne", "bhs", "blo", "bhi", "bls", "bgt",
                        "blt", "bge", "ble", "bcc", "bcs", "bmi", "bpl",
                        "bvs", "bvc", "b.eq", "b.ne", "b.hs", "b.lo",
                        "b.hi", "b.ls", "b.gt", "b.lt", "b.ge", "b.le",
                    }):
                if inst.operands and inst.operands[-1].type == ARM_OP_IMM:
                    dest = inst.operands[-1].imm & ~1
                    if BASE <= dest < BASE + len(image):
                        work.append(dest)
                        if inst.mnemonic == "bl":
                            calls.append({"at": _hex(addr), "to": _hex(dest)})
                if inst.mnemonic in ("b", "b.w"):
                    break
            if inst.mnemonic in ("cbz", "cbnz") and inst.operands[-1].type == ARM_OP_IMM:
                dest = inst.operands[-1].imm & ~1
                if BASE <= dest < BASE + len(image):
                    work.append(dest)
            if inst.mnemonic in ("bx", "tbb", "tbh", "blx"):
                indirect.append({"instruction": _hex(addr), "opcode": inst.mnemonic,
                                 "operands": inst.op_str})
                if inst.mnemonic != "blx":
                    break
            if (inst.mnemonic.startswith("pop") and "pc" in inst.op_str) or (
                    inst.mnemonic.startswith("ldr") and inst.operands and
                    inst.operands[0].reg and inst.reg_name(inst.operands[0].reg) == "pc"):
                break
            addr = next_addr
    return {
        "instructions_reached_by_heuristic_walk": len(seen),
        "hit_instruction_limit": len(seen) >= instruction_limit,
        "potential_direct_calls": len(calls),
        "potential_direct_calls_to_known_writer": [
            c for c in calls if c["to"] in {_hex(0x6080B0F0), _hex(0x60808E38)}
        ],
        "descriptor_literal_references": descriptor_literals[:100],
        "indirect_transfers_observed": indirect[:100],
        "note": "Static control flow from vector candidates; may omit jump tables and include false positives",
    }


def audit_local_image(image, expected_sha256=KNOWN_SHA256, walk=True):
    """Validate the build-specific blob *before* assigning addresses to data."""
    if len(image) != IMAGE_SIZE:
        raise ValueError("Expected 131072 bytes for bootloader A")
    digest = hashlib.sha256(image).hexdigest()
    if digest != expected_sha256:
        raise ValueError(f"Unexpected SHA-256 {digest}; refusing build-specific interpretations")
    descriptors = _device_descriptors(image)
    targets = {int(d["address"], 16) for d in descriptors}
    vectors = _vector_entries(image)
    result = {"sha256_verified": True, "sha256": digest, "bytes": len(image),
              "hardware_access": False, "usb_descriptor_candidates": descriptors,
              "aligned_pointers_to_descriptor_candidates": _pointer_refs(image, targets),
              "vectors": vectors,
              "custom_firmware_execution": "NOT TESTED"}
    if walk and vectors["valid_initial_sp_and_reset"]:
        points = [int(v["handler"], 16) for v in vectors["candidates"]]
        result["control_flow_candidates"] = _code_walk(image, points, targets)
    else:
        result["control_flow_candidates"] = {"status": "SKIPPED"}
    result["usb_to_writer_reachability"] = "NOT DEMONSTRATED"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootloader", type=Path,
                        help="Local verified bootloader-a.bin; no device access")
    parser.add_argument("--no-walk", action="store_true",
                        help="Only inspect vector/USB descriptor structures")
    parser.add_argument("--evidence", type=Path,
                        default=Path(__file__).resolve().parents[1] /
                        "evidence/bootloader-analysis.json")
    args = parser.parse_args()
    report = {"phase": 13, "public_evidence": audit_public_evidence(
        json.loads(args.evidence.read_text(encoding="utf-8")))}
    if args.bootloader:
        report["local_binary"] = audit_local_image(
            args.bootloader.read_bytes(), walk=not args.no_walk)
    else:
        report["local_binary"] = {
            "status": "NOT PROVIDED: dispatcher cannot be reconstructed from selected ranges"}
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
