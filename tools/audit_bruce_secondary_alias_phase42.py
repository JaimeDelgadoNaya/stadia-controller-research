"""Phase 42: inspect nine unresolved secondary callback writer *shapes*.

Original-image-only offline analysis. The per-site windows are intentionally
bounded and do not constitute a control-flow graph. No device communication.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
from tools.audit_signed_app_surface import IMAGE_SIZE, IMAGE_SHA256, ASSUMED_XIP_BASE
from tools.audit_bruce_secondary_registry import TARGETS, triage_offset_stores

BASE = ASSUMED_XIP_BASE
WINDOW_BEFORE = 192
WINDOW_AFTER = 72
SITES = (
    0x60058846, 0x600A4FF2, 0x600A54F4,
    0x600D574E, 0x600DDB84, 0x600EBD86,
    0x600F1C60, 0x600F4E44, 0x600FF9EC,
)
BASE_REGISTERS = {
    0x60058846: "r4", 0x600A4FF2: "r3", 0x600A54F4: "r3",
    0x600D574E: "r4", 0x600DDB84: "r1", 0x600EBD86: "r4",
    0x600F1C60: "r3", 0x600F4E44: "r3", 0x600FF9EC: "r3",
}
OFFSETS = {0x60058846: 0xFC, 0x600A4FF2: 0xF8, 0x600A54F4: 0xF8,
           0x600D574E: 0xFC, 0x600DDB84: 0xFC, 0x600EBD86: 0xF8,
           0x600F1C60: 0xF8, 0x600F4E44: 0xF8, 0x600FF9EC: 0xFC}


def decode_raw(image, start, end):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    md.detail = True
    return list(md.disasm(image[start-BASE:end-BASE], start))


def is_barrier(ins):
    m = ins.mnemonic.lower()
    return m in ("bl", "blx", "bx", "pop", "cbz", "cbnz", "it",
                 "itt", "ittt", "itttt") or m.startswith(("b.", "beq", "bne", "blt", "ble", "bgt", "bge", "bhi", "bls", "bcc", "bcs", "bpl", "bmi")) or m == "b" or m == "b.w"


def basic_window(rows, target):
    ix = next((i for i, x in enumerate(rows) if x.address == target), None)
    if ix is None:
        raise ValueError("candidate PC not on local Thumb decoding boundary")
    prev = rows[:ix]
    # The current basic-block candidate starts immediately after the last
    # branch-like barrier. This can omit predecessor blocks by design.
    cut = max((i for i, ins in enumerate(prev) if is_barrier(ins)), default=-1)
    return prev[cut+1:], rows[ix]


def last_writer(rows, reg_name):
    for row in reversed(rows):
        try:
            writes = {row.reg_name(r) for r in row.regs_access()[1]}
        except Exception:
            continue
        if reg_name in writes:
            return {"pc": hex(row.address), "instruction": row.mnemonic + " " + row.op_str}
    return None


def origin_class(last):
    if not last:
        return "unknown_entry_or_predecessor"
    instr = last["instruction"].lower()
    if instr.startswith("ldr") and ("[sp" in instr or "[r7" in instr or "[r4" in instr):
        return "loaded_through_other_pointer; no resolved absolute base"
    if instr.startswith("ldr"):
        return "loaded_from_memory; resolve pointer source"
    if instr.startswith("mov"):
        return "copied_register; continue predecessor dataflow"
    if instr.startswith("add"):
        return "computed_register; continue predecessor dataflow"
    return "other_register_definition"


def inspect_site(image, pc):
    if pc not in SITES:
        raise ValueError("unlisted site")
    # Decode instruction at its exact PC independently of preceding bytes.
    ins = decode_raw(image, pc, pc + 4)
    if not ins or ins[0].address != pc or not ins[0].mnemonic.startswith("str"):
        raise ValueError("Pinned candidate no longer decodes as a Thumb store: " + hex(pc))
    cur = ins[0]
    target_base = BASE_REGISTERS[pc]
    expected_disp = OFFSETS[pc]
    if f"[{target_base}, #0x{expected_disp:x}]" not in cur.op_str and f"[{target_base}, #{expected_disp}]" not in cur.op_str:
        raise ValueError("Candidate displacement/base changed: " + hex(pc) + " " + cur.op_str)
    lo = max(BASE + 0xBDF8, pc - WINDOW_BEFORE)
    hi = min(BASE + 0xFF000, pc + WINDOW_AFTER)
    # Try two halfword-aligned starts; require a matching site instruction.
    candidates = []
    for shift in (0, 2):
        start = lo + shift
        rows = decode_raw(image, start, hi)
        try:
            block, actual = basic_window(rows, pc)
        except ValueError:
            continue
        if actual.mnemonic == cur.mnemonic and actual.op_str == cur.op_str:
            candidates.append((start, rows, block))
    if not candidates:
        raise ValueError("No consistent bounded site disassembly: " + hex(pc))
    start, rows, block = candidates[0]
    before = [x for x in rows if x.address < pc][-26:]
    following = [x for x in rows if pc < x.address < pc + WINDOW_AFTER][:12]
    origin = last_writer(block, target_base)
    return {
        "site": hex(pc),
        "candidate_instruction": cur.mnemonic + " " + cur.op_str,
        "base_register": target_base, "offset": hex(expected_disp),
        "necessary_base_for_secondary_slot": hex(next(iter(TARGETS)) - expected_disp),
        "other_slot_needs_base": hex(max(TARGETS) - expected_disp),
        "local_basic_block_before_target": len(block),
        "base_last_writer_current_basic_block": origin,
        "source_class": origin_class(origin),
        "context_before": [hex(i.address) + " " + i.mnemonic + " " + i.op_str for i in before],
        "context_after": [hex(i.address) + " " + i.mnemonic + " " + i.op_str for i in following],
        "control_flow_validated": False,
        "runtime_object_link_proven": False,
        "host_control_proven": False,
    }


def audit(image):
    if len(image) != IMAGE_SIZE or hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise ValueError("Exact SHA-256 original signed Bruce update image required")
    rows = [inspect_site(image, pc) for pc in SITES]
    if {int(r["site"], 16) for r in rows} != set(SITES):
        raise ValueError("Candidate list incomplete")
    return {
        "phase": 42, "sample": "exact original signed OEM Bruce update, not installed readback",
        "sha256_verified": True, "candidate_count": len(rows), "candidates": rows,
        "site_inspection_limit": "bounded Thumb linear decode, not a control-flow graph",
        "live_EP0_selection": "UNVERIFIED", "second_callback_writer": "UNVERIFIED",
        "host_control": "UNVERIFIED", "custom_execution": "NOT DEMONSTRATED",
        "hardware_connected": False, "flash_written": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("--out", type=Path)
    a = p.parse_args()
    report = audit(a.image.read_bytes())
    if a.out:
        a.out.write_text(json.dumps(report, indent=2) + "\n")
    print("BRUCE PHASE42 NINE SITE TRIAGE", json.dumps([
        {k: r[k] for k in ("site", "candidate_instruction", "base_register",
                          "offset", "local_basic_block_before_target",
                          "base_last_writer_current_basic_block", "source_class")}
        for r in report["candidates"]
    ]))
    for row in report["candidates"]:
        print("PHASE42 SITE CONTEXT", json.dumps({
            "site": row["site"], "before": row["context_before"],
            "after": row["context_after"],
        }))


if __name__ == "__main__":
    main()
