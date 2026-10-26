"""Phase 54: bounded signed Bruce owner-field store search (offline only).

Starts at exact PC-relative owner-address loads recovered in phase 51.
Follows Thumb direct branches, bounded calls and literal veneers with
conservative known-register propagation. Unknown branches take both
sides; call returns invalidate caller-saved registers. Reports POSSIBLE
code-path stores, never real USB reachability or actual live RAM values.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
from collections import deque
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE, ASSUMED_XIP_BASE
from tools.audit_bruce_usb_owner_pointer_phase50 import OWNER

BASE = ASSUMED_XIP_BASE
END = BASE + 0xFF000
FIELDS = {OWNER + 4: "class_array_pointer",
          OWNER + 8: "config_method_pointer",
          OWNER + 12: "class_count"}
SEEDS = (0x60041E90, 0x6005ABF2, 0x6005ACC0, 0x6005ACCC,
         0x6005ACDA, 0x600610EA, 0x60065446, 0x60071416,
         0x60074AF8, 0x60074E56, 0x60079D7C)
REGISTER = re.compile(r"^(?:r(?:1[0-2]|[0-9])|sb|sl|fp|sp|lr)$")
MEM = re.compile(r"^\[([a-z][a-z0-9]*)(?:, #(-?(?:0x[0-9a-f]+|\d+)))?\]!?$")


def immediate(s):
    if not s.startswith("#"):
        return None
    try:
        return int(s[1:], 0)
    except ValueError:
        return None


def xip_literal(image, pc, operand):
    match = MEM.fullmatch(operand)
    if not match or match.group(1) != "pc":
        return None
    offset = int(match.group(2) or "0", 0)
    address = ((pc + 4) & ~3) + offset
    if address % 4 == 0 and BASE <= address <= BASE + len(image) - 4:
        return struct.unpack_from("<I", image, address - BASE)[0]
    return None


def known_stores(m, op, registers):
    """No proof for unsupported indexed, post-indexed or unknown-base stores."""
    typ = m.split(".")[0]
    if typ not in ("str", "strh", "strb", "strd") or "[" not in op:
        return []
    pos = op.index("[")
    prefixes = [s.strip() for s in op[:pos].rstrip(", ").split(",")]
    need = 2 if typ == "strd" else 1
    if len(prefixes) != need:
        return []
    match = MEM.fullmatch(op[pos:])
    if match is None or match.group(1) not in registers:
        return []
    base = registers[match.group(1)]
    offset = int(match.group(2) or "0", 0)
    return [((base + offset + 4 * idx) & 0xFFFFFFFF, src)
            for idx, src in enumerate(prefixes)]


def trace(image, seeds=SEEDS, *, max_states=10000, max_depth=2, max_span=0x200):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    cache = {}

    def instruction(pc):
        if not BASE <= pc < END or pc % 2:
            return None
        if pc not in cache:
            sample = image[pc - BASE:pc - BASE + 8]
            rows = list(decoder.disasm(sample, pc, count=1))
            cache[pc] = (rows[0].mnemonic, rows[0].op_str, rows[0].size) if rows else None
        return cache[pc]

    events = {}
    roots = []
    for root in seeds:
        first = instruction(root)
        if first is None or first[0] not in ("ldr", "ldr.w") or ", " not in first[1]:
            raise ValueError("phase54 original xref opcode drift " + hex(root))
        reg, operand = first[1].split(", ", 1)
        if xip_literal(image, root, operand) != OWNER:
            raise ValueError("phase54 original owner literal drift " + hex(root))
        queue = deque([(root, {}, root, 0, ())])
        seen = set()
        states = 0
        stops = {}

        def stop(reason):
            stops[reason] = stops.get(reason, 0) + 1

        while queue:
            pc, registers, start, depth, chain = queue.popleft()
            key = (pc, tuple(sorted(registers.items())), start, depth)
            if key in seen:
                continue
            seen.add(key)
            states += 1
            if states > max_states:
                stop("budget_exceeded")
                break
            if pc < start or pc - start > max_span:
                stop("outside_window")
                continue
            row = instruction(pc)
            if row is None:
                stop("unmapped")
                continue
            mnemonic, op, length = row
            following = pc + length

            def follow(dest, regs=registers, window=start, lvl=depth, context=chain):
                if BASE <= dest < END and dest % 2 == 0:
                    queue.append((dest, dict(regs), window, lvl, context))
                else:
                    stop("outside_XIP")

            if mnemonic in ("ldr", "ldr.w") and op.startswith("pc, [pc"):
                v = xip_literal(image, pc, op.split(", ", 1)[1])
                if v is not None and v & 1 and BASE <= (v & ~1) < END and depth < max_depth:
                    follow(v & ~1, registers, v & ~1, depth + 1,
                           chain + ((hex(pc), hex(v & ~1), "veneer"),))
                else:
                    stop("unresolved_veneer")
                continue
            if (mnemonic.startswith("pop") and "pc" in op) or mnemonic == "bx" or mnemonic in ("udf", "svc", "bkpt"):
                stop("return_or_indirect")
                continue
            if mnemonic.startswith(("it", "tbb", "tbh")):
                stop("unmodelled_predication_or_table")
                continue
            target = immediate(op)
            if mnemonic in ("b", "b.w") and target is not None:
                if start <= target <= start + max_span:
                    follow(target)
                elif depth < max_depth:
                    follow(target, registers, target, depth + 1,
                           chain + ((hex(pc), hex(target), "tail"),))
                else:
                    stop("depth_limited")
                continue
            if mnemonic.startswith("b") and mnemonic not in ("bl", "blx", "bic", "bfi", "bfc") and target is not None:
                if start <= target <= start + max_span:
                    follow(target)
                else:
                    stop("branch_beyond_window")
                follow(following)
                continue
            if mnemonic in ("cbz", "cbnz"):
                a = op.split(", ")
                if len(a) == 2:
                    dest = immediate(a[1])
                    if dest is not None and start <= dest <= start + max_span:
                        follow(dest)
                follow(following)
                continue
            if mnemonic in ("bl", "blx"):
                if mnemonic == "bl" and target is not None and depth < max_depth and any(
                    OWNER - 4 <= v <= OWNER + 16 for v in registers.values()
                ):
                    follow(target, registers, target, depth + 1,
                           chain + ((hex(pc), hex(target), "BL"),))
                for name in ("r0", "r1", "r2", "r3", "r12", "lr"):
                    registers.pop(name, None)
                follow(following)
                continue

            for address, source in known_stores(mnemonic, op, registers):
                if address in FIELDS:
                    event = {
                        "seed": hex(root), "site": hex(pc), "instruction": mnemonic + " " + op,
                        "field": FIELDS[address], "address": hex(address),
                        "source_register": source,
                        "source_value": hex(registers[source]) if source in registers else "UNKNOWN",
                        "direct_call_context": [{"site": a, "target": b, "kind": k} for a, b, k in chain],
                        "classification": "SIGNED_MAY_PATH; NOT_HARDWARE_RUNTIME_PROOF",
                    }
                    events[(root, pc, address, chain)] = event

            args = [s.strip() for s in op.split(",")]
            plain = mnemonic.split(".")[0]
            if plain.startswith("ldr") and ", " in op:
                dst, address = op.split(", ", 1)
                v = xip_literal(image, pc, address)
                if v is None:
                    registers.pop(dst, None)
                else:
                    registers[dst] = v
            elif plain.startswith("str"):
                if op.endswith("!") and "[" in op:
                    registers.pop(op.split("[", 1)[1].split(",", 1)[0].split("]", 1)[0], None)
            elif plain in ("mov", "movs") and len(args) == 2 and REGISTER.fullmatch(args[0]):
                v = registers.get(args[1]) if REGISTER.fullmatch(args[1]) else immediate(args[1])
                if v is None:
                    registers.pop(args[0], None)
                else:
                    registers[args[0]] = v
            elif plain in ("add", "adds", "sub", "subs") and len(args) in (2, 3) and REGISTER.fullmatch(args[0]):
                src = args[1] if len(args) == 3 else args[0]
                amount = immediate(args[2] if len(args) == 3 else args[1])
                if src in registers and amount is not None:
                    registers[args[0]] = (registers[src] + (amount if plain.startswith("add") else -amount)) & 0xFFFFFFFF
                else:
                    registers.pop(args[0], None)
            elif plain not in ("cmp", "tst", "nop", "push", "dmb", "dsb", "isb") and args and REGISTER.fullmatch(args[0]):
                registers.pop(args[0], None)
            follow(following)

        roots.append({"pc": hex(root), "loaded_register": reg, "states": states,
                      "stop_reasons": stops})
    return {
        "source_load_count": len(seeds),
        "source_summary": roots,
        "potential_store_sites": sorted(events.values(), key=lambda e: (e["seed"], e["site"])),
        "limits": {
            "max_states_per_seed": max_states, "max_call_depth": max_depth,
            "max_bytes_per_function": max_span, "indirect_calls": "UNRESOLVED",
            "branches": "MAY-PATH; cannot establish feasibility",
        },
    }


def audit(image):
    if len(image) != IMAGE_SIZE or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("phase54 exact SHA-256-pinned original signed Bruce OEM required")
    out = trace(image)
    return {
        "phase": 54, "original_signed_SHA_verified": True,
        "signed_SHA256": IMAGE_SHA256, **out,
        "live_RAM_fields": "UNMEASURED", "active_class10": "UNVERIFIED",
        "host_controlled_callback": "NOT DEMONSTRATED",
        "unsigned_firmware_execution": "NOT DEMONSTRATED",
        "HAB_CLOSED_bypass": "NOT DEMONSTRATED",
        "physical_USB_access": False, "flash_or_efuse_writes": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("--out", type=Path)
    a = p.parse_args()
    r = audit(a.image.read_bytes())
    if a.out:
        a.out.write_text(json.dumps(r, indent=2) + "\n")
    print("PHASE54 OWNER WRITER SURVEY", json.dumps({
        "source_count": r["source_load_count"],
        "store_candidates": len(r["potential_store_sites"]),
        "roots": r["source_summary"],
    }))
    for row in r["potential_store_sites"]:
        print("PHASE54 POSSIBLE OWNER STORE", json.dumps(row))
    print("PHASE54 NO LIVE RAM; CLASS10 ACTIVE AND UNSIGNED EXECUTION UNVERIFIED")


if __name__ == "__main__":
    main()
