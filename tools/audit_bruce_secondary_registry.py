"""Phase 41: bounded, read-only census of Bruce's secondary class-10 callback slot.

This is a *candidate* constant-propagation audit over linearly decoded OEM
Thumb bytes (XIP and startup-relocated ITCM). Not a control-flow proof: computed
aliases, runtime pointer stores, DMA and interrupt paths may evade this census.
Never performs USB I/O or writes to physical memory/flash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from collections import Counter, deque
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_MCLASS, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE, ASSUMED_XIP_BASE
from tools.audit_app_usb_dispatch import (
    DATA_DESTINATION, DATA_END, ITCM_LENGTH, ITCM_SOURCE_OFFSET
)
from tools.audit_bruce_class10_record_producer import original_class10_handler_guard

BASE = ASSUMED_XIP_BASE
SIGNED_END = BASE + 0xFF000
XIP_FIRST = (ITCM_SOURCE_OFFSET + ITCM_LENGTH + 1) & ~1
TARGETS = {0x20009EF8: "secondary_callback", 0x20009EFC: "secondary_context"}
RELATED = {
    0x200064C0: "secondary_global_base",
    0x20009E00: "neighbor_object_base",
    **TARGETS,
}
CONTEXT_OFFSETS = {0x3A38, 0x3A3C, 0xF8, 0xFC}
RESULT_LIMIT = 28


def decoder():
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    md.detail = True
    return md


def original_word(image: bytes, address: int, *, relocated: bool = False):
    if relocated:
        offset = ITCM_SOURCE_OFFSET + address
        valid = 0 <= address <= ITCM_LENGTH - 4
    else:
        offset = address - BASE
        valid = BASE <= address <= SIGNED_END - 4
    if not valid or offset < 0 or offset + 4 > len(image):
        return None
    return struct.unpack_from("<I", image, offset)[0]


def effective_address(op, state):
    mem = op.mem
    # A PC-relative literal is handled separately. A dynamic index requires
    # a tracked constant, not an assumed zero.
    if mem.base not in state:
        return None
    value = state[mem.base] + mem.disp
    if mem.index:
        if mem.index not in state:
            return None
        value += state[mem.index] * (mem.scale or 1)
    return value & 0xFFFFFFFF


def synthetic_walk(image: bytes, start: int, end: int, *, kind="xip"):
    """Return bounded store/read candidates. Used on synthetic tests too.

    State is invalidated at control-flow boundaries and whenever Capstone
    identifies register writes. This is deliberately conservative, not a CFG.
    """
    if kind not in ("xip", "itcm"):
        raise ValueError("invalid code address space")
    origin = BASE if kind == "xip" else -ITCM_SOURCE_OFFSET
    blob = image[start:end]
    md = decoder()
    state = {}
    discoveries = []
    pointer_uses = []
    offset_candidates = []
    instructions = 0
    trail = deque(maxlen=10)
    for ins in md.disasm(blob, origin + start):
        instructions += 1
        ops = ins.operands
        m = ins.mnemonic.lower().split(".")[0]
        branch = ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP) or m in ("bx", "pop", "it", "cbz", "cbnz")
        candidate = None

        if m.startswith(("ldr", "str")) and len(ops) >= 2:
            for op in ops[1:]:
                if op.type != ARM_OP_MEM:
                    continue
                if op.mem.base == ARM_REG_PC and m == "ldr" and ops[0].type == ARM_OP_REG:
                    at = ((ins.address + 4) & ~3) + op.mem.disp
                    word = original_word(image, at, relocated=kind == "itcm")
                    if word is not None:
                        candidate = (ops[0].reg, word)
                        if word in RELATED:
                            pointer_uses.append({
                                "pc": hex(ins.address), "literal_at": hex(at),
                                "value": hex(word), "role": RELATED[word],
                                "region": kind, "linear_decode_only": True
                            })
                else:
                    address = effective_address(op, state)
                    if m.startswith("str") and op.mem.disp in CONTEXT_OFFSETS:
                        offset_candidates.append({
                            "pc": hex(ins.address), "instruction": ins.mnemonic + " " + ins.op_str,
                            "base_register": ins.reg_name(op.mem.base),
                            "displacement": hex(op.mem.disp), "region": kind,
                            "base_constant_proven": address is not None,
                            "resolved_address": hex(address) if address is not None else None,
                            "base_constant": hex(state[op.mem.base]) if op.mem.base in state else None,
                            "preceding_linear_instructions": list(trail)[-7:],
                        })
                    if address is not None:
                        size = (8 if m in ("strd", "ldrd") else
                                1 if m.endswith("b") else 2 if m.endswith("h") else 4)
                        for target, role in TARGETS.items():
                            if address < target + 4 and address + size > target:
                                discoveries.append({
                                    "pc": hex(ins.address), "instruction": ins.mnemonic + " " + ins.op_str,
                                    "direction": "write" if m.startswith("str") else "read",
                                    "address": hex(address), "slot": role, "region": kind,
                                    "basis": "tracked PC literal/immediate within a linear basic-block candidate",
                                    "reachable_or_runtime_executed": False,
                                })
        elif m in ("movw", "mov", "movs") and len(ops) >= 2 and ops[0].type == ARM_OP_REG:
            if ops[1].type == ARM_OP_IMM:
                candidate = (ops[0].reg, ops[1].imm & 0xFFFFFFFF)
            elif ops[1].type == ARM_OP_REG and ops[1].reg in state:
                candidate = (ops[0].reg, state[ops[1].reg])
        elif m == "movt" and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            # MOVT preserves the prior low half, which must be known.
            reg = ops[0].reg
            if reg in state:
                candidate = (reg, (state[reg] & 0xFFFF) | ((ops[1].imm & 0xFFFF) << 16))
        elif m in ("add", "sub") and len(ops) >= 3 and ops[0].type == ARM_OP_REG:
            if ops[1].type == ARM_OP_REG and ops[1].reg in state:
                if ops[2].type == ARM_OP_IMM:
                    amount = ops[2].imm if m == "add" else -ops[2].imm
                    candidate = (ops[0].reg, (state[ops[1].reg] + amount) & 0xFFFFFFFF)
                elif m == "add" and ops[2].type == ARM_OP_REG and ops[2].reg in state:
                    candidate = (ops[0].reg, (state[ops[1].reg] + state[ops[2].reg]) & 0xFFFFFFFF)

        # An instruction may overwrite the tracked base or input index. Apply
        # its writes *after* evaluating its memory operand, never before.
        try:
            _, written = ins.regs_access()
            for reg in written:
                state.pop(reg, None)
        except Exception:
            # Unsupported register-access detail means no reuse of stale state.
            state.clear()
        if branch:
            state.clear()
        elif candidate:
            state[candidate[0]] = candidate[1]
        trail.append(hex(ins.address) + " " + ins.mnemonic + " " + ins.op_str)
    return {
        "instructions_linear": instructions,
        "candidate_accesses": discoveries,
        "related_pc_literals": pointer_uses,
        "near_offset_stores": offset_candidates,
    }


def triage_offset_stores(rows):
    """Priority classification, without claiming control-flow reachability."""
    stack = [x for x in rows if x["base_register"] == "sp"]
    other = [x for x in rows if x["base_register"] != "sp"
             and x["resolved_address"] is not None
             and int(x["resolved_address"], 16) not in TARGETS]
    unresolved = [x for x in rows if x["base_register"] != "sp"
                  and x["resolved_address"] is None]
    exact = [x for x in rows if x["resolved_address"] is not None
             and int(x["resolved_address"], 16) in TARGETS]
    return {
        "stack_based_store_shapes": len(stack),
        "statically_resolved_other_address": len(other),
        "unresolved_nonstack_store_shapes": len(unresolved),
        "statically_resolved_target_store_shapes": len(exact),
        "unresolved_nonstack_pc": [x["pc"] for x in unresolved[:RESULT_LIMIT]],
        "only_static_prioritization": True,
    }


def audit(image: bytes):
    if len(image) != IMAGE_SIZE or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("Requires exact SHA-256 pinned OEM signed Bruce update image")
    guard = original_class10_handler_guard(image)
    if guard["registered_callback_word_address"] != hex(next(iter(TARGETS))):
        raise ValueError("secondary slot moved from signed guard")

    aligned_refs = {}
    for addr, role in RELATED.items():
        needle = struct.pack("<I", addr)
        offsets = [i for i in range(0, 0xFF030 - 3, 4) if image[i:i + 4] == needle]
        aligned_refs[role] = {
            "pointer": hex(addr), "count": len(offsets),
            "offsets_limited": [hex(i) for i in offsets[:RESULT_LIMIT]],
            "proves_live_reference": False,
        }
    totals = Counter()
    accesses, pc_refs, near_stores = [], [], []
    # Runtime ITCM uses a different PC (file offset 0x81c -> runtime 0x0).
    windows = [(ITCM_SOURCE_OFFSET, ITCM_SOURCE_OFFSET + ITCM_LENGTH, "itcm"),
               # Function entry is independently pinned on the original bytes.
               # A raw XIP sweep across embedded literal pools can lose Thumb
               # instruction alignment; therefore also decode this known entry.
               (0x213FC, 0x21426, "xip")]
    windows += [(start, min(start + 0x4000, 0xFF000), "xip")
                for start in range(XIP_FIRST, 0xFF000, 0x4000)]
    for start, end, mode in windows:
        part = synthetic_walk(image, start, end, kind=mode)
        totals["instructions_linear"] += part["instructions_linear"]
        for key, source, dest in (
            ("candidate_accesses", part["candidate_accesses"], accesses),
            ("related_pc_literals", part["related_pc_literals"], pc_refs),
            ("near_offset_stores", part["near_offset_stores"], near_stores)
        ):
            totals[key] += len(source)
            dest.extend(source[:RESULT_LIMIT])
    direct_writes = [x for x in accesses if x["direction"] == "write"]
    return {
        "phase": 41, "signed_image_exact_sha_verified": True,
        "sample": "OEM signed update image; not installed flash readback",
        "secondary_slot": {k: hex(a) for a, k in TARGETS.items()},
        "secondary_guard_verified_at": guard["callback_pointer_read_at"],
        "startup_initialized_data_span": [hex(DATA_DESTINATION), hex(DATA_END)],
        "secondary_slots_outside_known_initialized_copy": all(
            not DATA_DESTINATION <= x < DATA_END for x in TARGETS),
        "aligned_literal_census": aligned_refs,
        "linear_windows": len(windows),
        "counts": dict(totals),
        "offset_store_triage": triage_offset_stores(near_stores),
        "candidate_accesses_limited": accesses[:RESULT_LIMIT],
        "candidate_writes_limited": direct_writes[:RESULT_LIMIT],
        "related_pc_literals_limited": pc_refs[:RESULT_LIMIT],
        "stores_with_interesting_displacements_limited": near_stores[:RESULT_LIMIT],
        "candidate_lists_are_truncated": {
            "accesses": len(accesses) > RESULT_LIMIT,
            "pc_literals": len(pc_refs) > RESULT_LIMIT,
            "store_offsets": len(near_stores) > RESULT_LIMIT,
        },
        "result_limits": [
            "Linear disassembly includes possible literal data and misses computed aliases.",
            "Chunk boundaries and indirect RAM/USB/DMA writes are not tracked.",
            "A candidate store is not a reachable host-controlled setter.",
            "No dynamic memory state or physical EP0/USB behaviour measured.",
            "No custom execution, signed-boot bypass or recovery established.",
        ],
        "physical_controller_touched": False,
        "firmware_written": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("bruce", type=Path)
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    report = audit(args.bruce.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(report, indent=2) + "\n")
    print("SECONDARY CLASS10 REGISTRY AUDIT", json.dumps({
        "slots": report["secondary_slot"], "counts": report["counts"],
        "triage": report["offset_store_triage"],
        "static_direct_writes": report["candidate_writes_limited"],
        "literal_refs": report["aligned_literal_census"],
        "decoded_pc_literals": report["related_pc_literals_limited"],
        "candidate_accesses": report["candidate_accesses_limited"],
        "near_offset_stores": report["stores_with_interesting_displacements_limited"],
        "truncated": report["candidate_lists_are_truncated"],
        "host_control": "UNVERIFIED", "firmware_execution": "NOT DEMONSTRATED",
    }))


if __name__ == "__main__":
    main()
