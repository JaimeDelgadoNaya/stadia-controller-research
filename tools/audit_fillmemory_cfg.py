"""Bounded, read-only over-approximation of the signed loader FillMemory call graph.

Never connects to hardware. Does not demonstrate a vulnerability or that a call
is taken at runtime. Requires the exact private image and its SHA-256.
"""
import argparse
import hashlib
import json
from collections import deque
from pathlib import Path

try:
    from . import audit_fillmemory_route as previous
except ImportError:
    import audit_fillmemory_route as previous

BASE = previous.BASE
CUTOFF = BASE + previous.CODE_CUTOFF
FILL = 0x20003380
FILL_END = 0x200033A0
KNOWN_WRITE_POLICY = previous.TRACKED_WRITEMEMORY_POLICY
KNOWN_WRITE_BACKEND = previous.TRACKED_WRITEMEMORY_BACKEND
CONDS = {"beq", "bne", "bcs", "bcc", "bhs", "blo", "bmi", "bpl",
         "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt", "ble"}


def classify(mnemonic, target=None, operands=""):
    """Conservative Thumb control-flow classification; no invented edge."""
    m = mnemonic.lower().split(".")[0]
    if m in {"bl", "blx"}:
        return "call" if target is not None else "indirect_call"
    if m in {"b"}:
        return "jump" if target is not None else "indirect_jump"
    if m in CONDS or m in {"cbz", "cbnz"}:
        return "conditional" if target is not None else "indirect_jump"
    if m in {"bx", "tbb", "tbh"}:
        return "return" if m == "bx" and operands.strip().lower() == "lr" else "indirect_jump"
    if m in {"pop", "ldm", "ldmia"} and "pc" in operands.lower():
        return "return"
    if m in {"ldr", "mov", "add"} and operands.lower().replace(" ", "").startswith("pc,"):
        return "indirect_jump"
    if m.startswith("it"):
        return "it_context_unmodeled"
    if m in {"udf", "bkpt"}:
        return "trap"
    return "linear"


def _decode_one(image, addr, decoder, immediate_type):
    pos = addr - BASE
    if pos < 0 or pos + 2 > min(len(image), previous.CODE_CUTOFF):
        return None
    code = image[pos:min(pos + 4, len(image), previous.CODE_CUTOFF)]
    inst = next(iter(decoder.disasm(code, addr, count=1)), None)
    if inst is None or inst.address != addr or addr + inst.size > CUTOFF:
        return None
    target = None
    for op in inst.operands:
        if op.type == immediate_type:
            target = op.imm & 0xFFFFFFFF
    return inst, target


def trace(image, expected_sha=previous.SHA256, *, function_span=384,
          max_depth=3, max_functions=40, max_instructions=4000):
    """Follow direct branches/calls under strict bounds; never infer state.

    Per-function limits are NOT function boundaries. Conditional branches are
    followed both ways. Indirect branches, IT state, and unvisited paths remain
    explicit uncertainties. A discovered call is not proof of execution or
    authorization, and absence is not evidence of a missing validation.
    """
    if function_span < 32 or function_span > 4096 or function_span % 2:
        raise ValueError("invalid function_span")
    if not 0 <= max_depth <= 8 or not 1 <= max_functions <= 256:
        raise ValueError("invalid traversal budget")
    if not 1 <= max_instructions <= 50000:
        raise ValueError("invalid instruction budget")
    if len(image) != previous.SIZE or hashlib.sha256(image).hexdigest() != expected_sha:
        raise ValueError("exact signed-loader size/hash required")
    # Check the actual dispatch table before considering any code path.
    for tag, handler, enabled in ((5, previous.FILL_HANDLER, True),
                                  (4, 0x200030D9, True),
                                  (9, 0x200033A1, False),
                                  (10, 0x2000340D, False)):
        item = previous.command_entry(image, tag)
        if item["handler"] != hex(handler) or item["dispatches"] != enabled:
            raise ValueError("original command table differs")
    decoder, imm_type = previous._capstone()
    functions = deque([(FILL, 0)])
    visited_funcs = set()
    all_calls = set()
    unknown = set()
    counts = {"instructions": 0, "functions": 0, "conditional_branches": 0}
    while functions and counts["functions"] < max_functions and counts["instructions"] < max_instructions:
        start, depth = functions.popleft()
        if (start, depth) in visited_funcs:
            continue
        visited_funcs.add((start, depth))
        counts["functions"] += 1
        limit = min(start + function_span, CUTOFF)
        if start == FILL:
            limit = min(limit, FILL_END)
        work = [start]
        visited_pc = set()
        while work and counts["instructions"] < max_instructions:
            pc = work.pop()
            if pc in visited_pc:
                continue
            if not start <= pc < limit:
                unknown.add("branch_or_fallthrough_outside_bounded_window")
                continue
            visited_pc.add(pc)
            result = _decode_one(image, pc, decoder, imm_type)
            if result is None:
                unknown.add("undecodable_instruction")
                continue
            ins, target = result
            counts["instructions"] += 1
            kind = classify(ins.mnemonic, target, ins.op_str)
            nextpc = pc + ins.size
            if kind == "call":
                all_calls.add((pc, target, depth))
                if BASE <= target < CUTOFF:
                    if depth < max_depth:
                        functions.append((target & ~1, depth + 1))
                    else:
                        unknown.add("max_call_depth")
                else:
                    unknown.add("call_outside_loader")
                work.append(nextpc)
            elif kind == "jump":
                work.append(target & ~1)
            elif kind == "conditional":
                counts["conditional_branches"] += 1
                work.append(nextpc)
                work.append(target & ~1)
            elif kind == "linear":
                work.append(nextpc)
            elif kind == "it_context_unmodeled":
                unknown.add("IT_condition_state_not_modeled")
                work.append(nextpc)
            elif kind in {"indirect_call", "indirect_jump"}:
                unknown.add(kind)
                if kind == "indirect_call":
                    work.append(nextpc)
            elif kind == "trap":
                unknown.add("trap_encountered")
    if functions:
        unknown.add("function_or_instruction_budget_reached")
    direct_targets = {target for _, target, _ in all_calls}
    return {
        "source_sha256": hashlib.sha256(image).hexdigest(),
        "root": hex(FILL),
        "method": "Over-approximate direct-call/branch discovery; offline, not execution or full symbolic analysis",
        "budgets": {"max_call_depth": max_depth, "max_functions": max_functions,
                    "max_instructions": max_instructions, "function_span_bytes": function_span},
        "counts": counts,
        "observed_direct_calls": [{"at": hex(pc), "to": hex(target), "depth": depth}
                                  for pc, target, depth in sorted(all_calls)],
        "known_WriteMemory_policy_direct_call_observed": KNOWN_WRITE_POLICY in direct_targets,
        "known_WriteMemory_backend_direct_call_observed": KNOWN_WRITE_BACKEND in direct_targets,
        "unresolved_or_unmodeled": sorted(unknown),
        "conclusion": {
            "FillMemory_same_policy": "NOT PROVEN: calls may be conditional or indirect",
            "absence_of_policy": "NOT PROVEN: bounded control flow only",
            "control_memory_write": "NOT DEMONSTRATED",
            "custom_code_execution": "NOT DEMONSTRATED",
            "recovery": "NOT VERIFIED"
        },
        "device_access": False,
        "firmware_modification": False
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("loader", type=Path, help="Private original restricted_ivt_flashloader.bin")
    parser.add_argument("--out", type=Path, help="Write report locally, never upload original firmware")
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--function-span", type=int, default=384)
    args = parser.parse_args()
    report = trace(args.loader.read_bytes(), function_span=args.function_span,
                   max_depth=args.max_depth)
    result = json.dumps(report, indent=2) + "\n"
    if args.out:
        args.out.write_text(result, encoding="utf-8")
    else:
        print(result, end="")


if __name__ == "__main__":
    main()
