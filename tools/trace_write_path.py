"""Audit a *selected* signed-bootloader write path from public disassembly evidence.

Offline only. Does not parse a USB device, dump firmware or perform flash writes.
The source corpus covers selected regions of a single firmware build, not the
whole program. No path from USB or a custom-firmware bypass is established.
"""

import argparse
import json
from pathlib import Path

EXPECTED_IMAGE = "59ebfd2c156075e498ecf318984cb297750c9c5b7cb321b0ea97edee315f2ca0"
EXPECTED_BUILD = 169429
SIZE = 131072
ROOT = 0x6080285C

# (site address, opcode, target or operands). Addresses are build-specific.
DIRECT_PATH = (
    (0x608028C6, 0x60801ED0),  # update-entry -> coordinator
    (0x60801EE4, 0x60801DD4),  # coordinator -> update transaction
    (0x60801E62, 0x60801D9C),  # update -> candidate IVT read/write
    (0x60801DC0, 0x60801D40),  # IVT read/write -> writer wrapper
)

# Anchor opcode *and* operands to avoid interpreting an unverified JSON as a
# current firmware version. The image digest in JSON is provenance, not an
# independent check of the (unpublished) raw image.
ANCHORS = {
    0x60801D8E: ("movs", "r1, #0"),
    0x60801D90: ("ldr", "r3, [r0]"),
    0x60801D92: ("ldr", "r4, [r3, #8]"),
    0x60801D94: ("mov.w", "r3, #0x1000"),
    0x60801D98: ("blx", "r4"),
    0x60801DA2: ("movs", "r2, #0"),
    0x60801DA8: ("mov.w", "r3, #0x1000"),
    0x60801DAE: ("blx", "r5"),
    0x60801E38: ("ldr", "r1, [pc, #0x88]"),
    0x60801E3E: ("mov.w", "r3, #0x1000"),
    0x60801E42: ("blx", "r7"),
    0x6080B10C: ("bl", "#0x6080aa7c"),
    0x6080B11C: ("bl", "#0x6080aa66"),
    0x6080B126: ("ldr", "r4, [r3, #0x18]"),
    0x6080B12C: ("mov", "ip, r4"),
    0x6080B132: ("bx", "ip"),
    0x6080BD8E: ("ldr", "r2, [pc, #0x22c]"),
    0x6080BD94: ("str.w", "r2, [r4, #0xa78]"),
}

PLAIN_VTABLE = (0x60815300, 2, 0x6080B0F0)
PHYSICAL_VTABLE = (0x60815320, 6, 0x60808E38)


def number(value):
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        return int(value, 16)
    raise ValueError(f"Invalid address: {value!r}")


def scan(evidence):
    """Return supported relations and explicit unresolved boundaries.

    Raises ValueError when expected instruction or table evidence is absent.
    No speculative indirect-call targets are inferred.
    """
    if (evidence.get("sha256") != EXPECTED_IMAGE or
            evidence.get("build") != EXPECTED_BUILD or evidence.get("bytes") != SIZE):
        raise ValueError("Unsupported firmware build, size or provenance")

    regions = []
    instructions = {}
    for region in evidence["functions"]:
        start, end = number(region["start"]), number(region["end_exclusive"])
        if not start < end:
            raise ValueError("Invalid disassembly region")
        position = start
        for inst in region["instructions"]:
            address = number(inst["address"])
            try:
                encoded = bytes.fromhex(inst["bytes"])
            except (ValueError, KeyError) as exc:
                raise ValueError("Invalid instruction bytes") from exc
            if not encoded or address != position or address in instructions:
                raise ValueError("Non-contiguous or duplicate instruction evidence")
            position += len(encoded)
            instructions[address] = inst
        if position != end:
            raise ValueError("Disassembly region length mismatch")
        regions.append((start, end))

    ordered = sorted(regions)
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        raise ValueError("Overlapping disassembly regions")

    for at, (mnemonic, operands) in ANCHORS.items():
        inst = instructions.get(at)
        if not inst or (inst["mnemonic"], inst["operands"]) != (mnemonic, operands):
            raise ValueError(f"Anchor mismatch at {at:#x}")

    for site, target in DIRECT_PATH:
        inst = instructions.get(site)
        if not inst or inst["mnemonic"] != "bl" or number(inst.get("direct_target", "0x0")) != target:
            raise ValueError(f"Direct-call mismatch at {site:#x}")

    tables = {number(t["address"]): [number(e) for e in t["entries"]]
              for t in evidence["storage_vtables"]}
    for addr, slot, target in (PLAIN_VTABLE, PHYSICAL_VTABLE):
        try:
            actual = tables[addr][slot]
        except (KeyError, IndexError) as exc:
            raise ValueError(f"Missing storage table at {addr:#x}") from exc
        if actual & ~1 != target or actual & 1 != 1:
            raise ValueError(f"Unexpected virtual target at {addr:#x}[{slot}]")

    # Check both the constructor's literal and the wrapper-to-writer boundary.
    if number(instructions[0x6080BD8E].get("literal_uint32", "0")) != PLAIN_VTABLE[0]:
        raise ValueError("Plain vtable address does not match constructor")
    if number(instructions[0x60801E38].get("literal_uint32", "0")) != 0x200029C8:
        raise ValueError("IVT backup buffer address changed")

    # These are observed *callsite* relations. Interior addresses are left as
    # addressed evidence; outside targets are not silently assumed reachable.
    full_direct = []
    unknown = []
    indirect = []
    for at in sorted(instructions):
        inst = instructions[at]
        if inst["mnemonic"] == "bl" and "direct_target" in inst:
            dest = number(inst["direct_target"])
            covered = any(start <= dest < end for start, end in regions)
            edge = {"callsite": hex(at), "target": hex(dest), "target_in_selected_ranges": covered}
            full_direct.append(edge)
            if not covered:
                unknown.append(edge)
        elif inst["mnemonic"] in ("blx", "bx") and inst["operands"] != "lr":
            indirect.append({"callsite": hex(at), "opcode": inst["mnemonic"],
                             "operands": inst["operands"], "automatically_resolved": False})

    # The two vtable resolutions below rely on the annotated constructor and
    # fixed IVT object context documented in docs/es/almacenamiento.md. They
    # are *conditional*, not arbitrary input-to-USB reachability results.
    chain = [{"from": hex(ROOT), "site": hex(site), "to": hex(target),
              "type": "direct bl"} for site, target in DIRECT_PATH]
    chain += [
        {"from": hex(0x60801D40), "site": hex(0x60801D98),
         "to": hex(PLAIN_VTABLE[2]), "type": "conditional vtable slot 2",
         "context": "constructed descriptor 0x12; 0x60815300"},
        {"from": hex(0x6080B0F0), "site": hex(0x6080B132),
         "to": hex(PHYSICAL_VTABLE[2]), "type": "conditional vtable slot 6",
         "context": "constructed physical storage object; 0x60815320"},
    ]
    return {
        "image_sha256": EXPECTED_IMAGE,
        "build": EXPECTED_BUILD,
        "hardware_access": False,
        "selected_regions": len(regions),
        "selected_instruction_bytes": sum(e-s for s, e in regions),
        "image_bytes": SIZE,
        "path": chain,
        "fixed_ivt_arguments": {"offset": "0x0", "length": "0x1000", "read_buffer": "0x200019c8",
                                "backup_buffer": "0x200029c8"},
        "direct_call_count": len(full_direct),
        "out_of_scope_direct_call_count": len(unknown),
        "out_of_scope_direct_calls": unknown,
        "indirect_sites_not_resolved_generically": indirect,
        "external_input_to_path": "NOT ESTABLISHED",
        "custom_firmware_execution": "NOT DEMONSTRATED",
        "provenance": "Selected public instruction records, not an independently rehashed full bootloader",
        "scope": "Conditional local call path only; no USB dispatch audit and no HAB bypass",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", nargs="?", type=Path,
                        default=Path(__file__).resolve().parents[1] / "evidence/bootloader-analysis.json")
    args = parser.parse_args()
    print(json.dumps(scan(json.loads(args.evidence.read_text(encoding="utf-8"))), indent=2))


if __name__ == "__main__":
    main()
