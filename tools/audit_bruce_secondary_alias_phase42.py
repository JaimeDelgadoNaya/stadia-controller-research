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
from tools.audit_bruce_ep0_registration import callers_of_known

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
    # Thumb code may include inline literals. A wide window seeded at one
    # offset can lose alignment; retry bounded even-PC seeds and disclose how
    # far the recovered linear context extends. Never infer CFG reachability.
    candidates = []
    for start in range(lo, pc + 1, 2):
        rows = decode_raw(image, start, hi)
        try:
            block, actual = basic_window(rows, pc)
        except ValueError:
            continue
        if actual.mnemonic == cur.mnemonic and actual.op_str == cur.op_str:
            before = [x for x in rows if x.address < pc][-26:]
            candidates.append((start, rows, block, before))
    if not candidates:
        raise ValueError("Original store matches alone, but no local instruction boundary: " + hex(pc))
    # Prefer greatest supported local context. Ties prefer closest starting
    # offset. This only ranks linear disassembly, not physical reachability.
    start, rows, block, before = max(candidates, key=lambda x: (len(x[3]), x[0]))
    following = [x for x in rows if pc < x.address < pc + WINDOW_AFTER][:12]
    origin = last_writer(block, target_base)
    return {
        "site": hex(pc),
        "candidate_instruction": cur.mnemonic + " " + cur.op_str,
        "base_register": target_base, "offset": hex(expected_disp),
        "necessary_base_for_secondary_slot": hex(next(iter(TARGETS)) - expected_disp),
        "other_slot_needs_base": hex(max(TARGETS) - expected_disp),
        "local_basic_block_before_target": len(block),
        "selected_linear_decode_start": hex(start),
        "base_last_writer_current_basic_block": origin,
        "source_class": origin_class(origin),
        "context_before": [hex(i.address) + " " + i.mnemonic + " " + i.op_str for i in before],
        "context_after": [hex(i.address) + " " + i.mnemonic + " " + i.op_str for i in following],
        "control_flow_validated": False,
        "runtime_object_link_proven": False,
        "host_control_proven": False,
    }



def secondary_context_xrefs(image):
    """Bounded references to the actual global object and sentinel.

    Literal words and linear BL candidates are not a resolved call graph.
    """
    import struct
    values = {
        "secondary_object_0x20009e00": 0x20009E00,
        "global_0x200064c0": 0x200064C0,
        "guard_sentinel_0x600d4f05": 0x600D4F05,
        "class10_handler_0x600613fd": 0x600613FD,
    }
    ref_counts = {}
    for name, value in values.items():
        raw = struct.pack("<I", value)
        offsets = [i for i in range(0, 0xFF030 - 3, 4)
                   if image[i:i+4] == raw]
        ref_counts[name] = {"count": len(offsets),
                            "first_offsets": [hex(x) for x in offsets[:24]]}
    return {
        "signed_pointer_literals": ref_counts,
        "direct_call_candidates": callers_of_known(image, {
            "large_struct_constructor": 0x600587FC,
            "candidate_struct_method_d572a": 0x600D572A,
            "class10_signed_callback": 0x600613FC,
            "guard_sentinel_function": 0x600D4F04,
        }, max_examples=10),
        "handler_sentinel_disassembly": [
            hex(i.address) + " " + i.mnemonic + " " + i.op_str
            for i in decode_raw(image, 0x600D4F04, 0x600D4F44)
        ],
        "sentinel_second_literal_neighborhood": [
            hex(i.address) + " " + i.mnemonic + " " + i.op_str
            for i in decode_raw(image, 0x60073D70, 0x60073E48)
        ],
        "constructor_direct_call_neighborhood": [
            hex(i.address) + " " + i.mnemonic + " " + i.op_str
            for i in decode_raw(image, 0x600588E0, 0x60058950)
        ],
        "neighbor_object_caller_window": [
            hex(i.address) + " " + i.mnemonic + " " + i.op_str
            for i in decode_raw(image, 0x60058BC0, 0x60058C30)
        ],
        "runtime_execution_proven": False,
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
        "secondary_context_xrefs": secondary_context_xrefs(image),
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
    refs = report["secondary_context_xrefs"]
    print("PHASE42 SECOND LEVEL LITERALS", json.dumps(refs["signed_pointer_literals"]))
    print("PHASE42 POTENTIAL CALLERS", json.dumps({
        name: [{"callsite": v["callsite"], "before": v["before"][-6:]}
               for v in rows]
        for name, rows in refs["direct_call_candidates"].items()
    }))
    print("PHASE42 SENTINEL CODE", json.dumps(refs["handler_sentinel_disassembly"]))
    print("PHASE42 OBJECT NEIGHBOR CODE", json.dumps(refs["neighbor_object_caller_window"]))
    print("PHASE42 OTHER SENTINEL SITE", json.dumps(refs["sentinel_second_literal_neighborhood"]))
    print("PHASE42 CONSTRUCTOR CALLER CODE", json.dumps(refs["constructor_direct_call_neighborhood"]))


if __name__ == "__main__":
    main()
