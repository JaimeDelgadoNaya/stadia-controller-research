"""Phase 22: bounded, intrablock Thumb pointer-provenance triage.

No hardware contact. Requires owner's local SHA-matched bootloader A and the
Capstone version pinned in requirements.txt. Each of the 29 Phase-21 raw LDR
candidates is decoded only to its next branch/call/return or 96 bytes.
Tracking is CONSERVATIVE: no interprocedural or path-sensitive analysis.
Neither a candidate nor an observed store is proof of USB reachability.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

try:
    from .audit_global_alias_sources import (
        BASE, SIZE, SHA256, GLOBAL, literal_words, literal_load_candidates
    )
except ImportError:
    from audit_global_alias_sources import (
        BASE, SIZE, SHA256, GLOBAL, literal_words, literal_load_candidates
    )

CALLBACK_FIELDS = {
    0x5F8: "bulk_IN_handler",
    0x5FC: "bulk_IN_context",
    0x600: "bulk_OUT_handler",
    0x604: "bulk_OUT_context",
}
SCOPE_LIMIT = 96
KNOWN_CANDIDATE_COUNT = 29

def fmt(value):
    return f"0x{value:08x}"


def _decoder():
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    md.detail = True
    return md


def _stop_reason(ins):
    op = ins.mnemonic.lower().split(".")[0]
    if op in {"bl", "blx"}:
        return "call_boundary"
    if op in {"bx", "b", "cbz", "cbnz", "tbb", "tbh", "svc", "bkpt"} or (
            op.startswith("b") and op in {
                "beq", "bne", "bhs", "blo", "bhi", "bls", "bgt",
                "blt", "bge", "ble", "bcc", "bcs", "bmi", "bpl",
                "bvs", "bvc", "bal", "b.n", "b.w"}):
        return "branch_or_return_boundary"
    if op.startswith("pop") and "pc" in ins.op_str:
        return "branch_or_return_boundary"
    return None


def trace_prefix(image, site, initial_register, byte_limit=SCOPE_LIMIT):
    """Conservatively follow offsets from GLOBAL in one decoded instruction prefix.

    This requires the *caller* to verify the initial instruction loads GLOBAL.
    Sources of unmodelled register writes are invalidated using regs_access().
    All records are potential code paths only, not asserted runtime behavior.
    """
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

    if not 0 <= site < len(image) or site % 2 or not 4 <= byte_limit <= 256:
        raise ValueError("Invalid source site or scan limit")
    md = _decoder()
    instructions = list(md.disasm(
        image[site:min(len(image), site+byte_limit)], BASE+site))
    if not instructions or instructions[0].address != BASE+site:
        raise ValueError("Cannot decode source instruction")
    aliases = {initial_register: 0}
    reads, writes, escapes, calls = [], [], [], []
    stopped = "byte_or_instruction_limit"
    visited = 0
    # First instruction's literal-global origin is supplied and checked by audit().
    for index, ins in enumerate(instructions):
        if index == 0:
            visited += 1
            continue
        visited += 1
        op = ins.mnemonic.lower().split(".")[0]
        operands = ins.operands
        reason = _stop_reason(ins)
        if reason:
            if reason == "call_boundary":
                transferred = {md.reg_name(k): fmt(GLOBAL+v) for k,v in aliases.items()
                               if md.reg_name(k) in {"r0", "r1", "r2", "r3"}}
                calls.append({"at": fmt(ins.address), "kind": op,
                              "known_argument_aliases": transferred,
                              "callee_followed": False})
            stopped = reason
            break

        if op in {"ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "str", "strb", "strh"} and len(operands) >= 2:
            is_load = op.startswith("ldr")
            mem = operands[1]
            if mem.type == ARM_OP_MEM:
                base = mem.mem.base
                disp = mem.mem.disp
                if base in aliases:
                    absolute_offset = aliases[base] + disp
                    row = {"at": fmt(ins.address), "mnemonic": ins.mnemonic,
                           "offset_from_global": fmt(absolute_offset),
                           "ram": fmt(GLOBAL+absolute_offset),
                           "field": CALLBACK_FIELDS.get(absolute_offset, "other_field"),
                           "pointer_base_register": md.reg_name(base),
                           "code_reachable_from_host": "NOT ESTABLISHED"}
                    (reads if is_load else writes).append(row)
                if not is_load and operands[0].type == ARM_OP_REG and operands[0].reg in aliases:
                    escapes.append({"at": fmt(ins.address),
                                    "kind": "alias stored via other pointer",
                                    "destination_base_known_global": base in aliases})
                if is_load and operands[0].type == ARM_OP_REG:
                    dst = operands[0].reg
                    if base == ARM_REG_PC:
                        # Track another global literal in the same *basic block*.
                        loc = ((ins.address+4)&~3) + disp - BASE
                        if 0 <= loc <= len(image)-4 and struct.unpack_from("<I", image, loc)[0] == GLOBAL:
                            aliases[dst] = 0
                        else:
                            aliases.pop(dst, None)
                    else:
                        aliases.pop(dst, None)
                continue

        if op in {"strd", "ldrd", "stm", "stmia", "stmdb", "ldm", "ldmia", "ldmdb",
                  "push", "pop"}:
            if op in {"push", "strd", "stm", "stmia", "stmdb"} and aliases:
                escapes.append({"at": fmt(ins.address),
                                "kind": "store-multiple/stack not modeled"})
            # Push/stack bookkeeping is not a full memory SSA; do not propagate
            # aliases through stack or multi-register transfers.
            if op not in {"push"}:
                stopped = "unmodelled_memory_transfer"
                break
            continue

        if op in {"mov", "movs"} and len(operands) >= 2 and operands[0].type == ARM_OP_REG:
            dst = operands[0].reg
            if operands[1].type == ARM_OP_REG and operands[1].reg in aliases:
                aliases[dst] = aliases[operands[1].reg]
            else:
                aliases.pop(dst, None)
            continue

        if op in {"add", "adds", "addw", "sub", "subs", "subw"} and operands and operands[0].type == ARM_OP_REG:
            dst = operands[0].reg
            if len(operands) == 3 and operands[1].type == ARM_OP_REG and operands[2].type == ARM_OP_IMM:
                origin, imm = operands[1].reg, operands[2].imm
            elif len(operands) == 2 and operands[1].type == ARM_OP_IMM:
                origin, imm = dst, operands[1].imm
            else:
                origin, imm = None, None
            if origin in aliases and imm is not None:
                aliases[dst] = aliases[origin] + (-imm if op.startswith("sub") else imm)
            else:
                aliases.pop(dst, None)
            continue

        # Unknown transformations must not silently preserve a tracked pointer.
        try:
            _, written = ins.regs_access()
        except (ValueError, AttributeError):
            stopped = "unmodelled_register_effect"
            break
        for reg in written:
            aliases.pop(reg, None)

    return {"source_site": fmt(BASE+site), "decoded_instructions": visited,
            "stopped_at": stopped, "reads": reads, "writes": writes,
            "potential_pointer_escapes": escapes, "call_boundaries": calls,
            "scope": "single linear prefix, no alternate branch or callee followed"}


def audit(image, expected_sha256=SHA256, enforce_29=True):
    if len(image) != SIZE:
        raise ValueError("Expected 131072-byte Stadia bootloader A")
    digest = hashlib.sha256(image).hexdigest()
    if digest != expected_sha256:
        raise ValueError("Unrecognized bootloader SHA-256")
    sources = literal_load_candidates(image, literal_words(image))
    if enforce_29 and len(sources) != KNOWN_CANDIDATE_COUNT:
        raise ValueError("Phase-21 candidate count changed")
    entries = []
    for source in sources:
        site = int(source["at"], 16)-BASE
        md = _decoder()
        first = next(md.disasm(image[site:site+4], BASE+site, count=1), None)
        if first is None or not first.mnemonic.lower().startswith("ldr") or not first.operands:
            raise ValueError("Candidate no longer decodes as LDR")
        dest = first.operands[0].reg
        entry = trace_prefix(image, site, dest)
        entry["source_literal"] = source["literal"]
        entry["source_kind"] = source["kind"]
        entries.append(entry)
    reads = [dict(site=e["source_site"], **r) for e in entries for r in e["reads"]]
    writes = [dict(site=e["source_site"], **r) for e in entries for r in e["writes"]]
    callback_writes = [r for r in writes if r["field"] in CALLBACK_FIELDS.values()]
    return {
        "phase":22, "build":169429, "sha256_verified":True, "sha256":digest,
        "hardware_access":False, "usb_transactions":False,
        "flash_operations":False, "candidate_sources":len(entries),
        "bounded_prefixes":entries,
        "direct_reads_in_prefixes":reads, "direct_writes_in_prefixes":writes,
        "callback_field_writes_in_examined_prefixes":callback_writes,
        "access_counts":{"reads":len(reads),"writes":len(writes),
                         "callback_field_writes":len(callback_writes)},
        "critical_limitation": (
            "Candidate Thumb decodings and single basic-block prefixes, not full CFG. "
            "Branches, calls, aliases passed to callees, stack aliases, indirect "
            "stores and firmware outside the image remain unresolved."),
        "later_callback_registration":"NOT PROVEN OR EXCLUDED",
        "host_bulk_out_to_parser":"NOT DEMONSTRATED",
        "host_to_flash_write":"NOT DEMONSTRATED",
        "hab_closed_bypass":"NOT DEMONSTRATED",
        "custom_firmware_execution":"NOT DEMONSTRATED",
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bootloader",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    output=json.dumps(audit(args.bootloader.read_bytes()),indent=2)+"\n"
    if args.out:
        args.out.write_text(output,encoding="utf-8")
    else:
        print(output,end="")


if __name__=="__main__":
    main()
