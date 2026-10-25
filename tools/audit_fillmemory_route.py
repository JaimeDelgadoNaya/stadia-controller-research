"""Offline investigation of FillMemory in Stadia's signed RAM flashloader.

This tool never connects to USB/HID, sends commands, writes flash, modifies
firmware or tests execution. It requires the *exact* original 100672-byte
restricted_ivt_flashloader.bin, SHA-256 c39ea... and uses Capstone to inspect
the bounded FillMemory handler and nearby direct call targets.

Crucial: the policy and fragment bounds proven for WriteMemory in PR #24
CANNOT be applied to FillMemory without a separate path trace. A lack of a
policy call in bounded previews does not establish its absence globally.
NXP's general bootloader reference says FillMemory follows WriteMemory rules;
the specific Google restricted-loader implementation must be verified.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

try:
    from .audit_loader_execution_gate import (
        BASE, SIZE, SHA256, TABLE, command_entry,
    )
except ImportError:
    from audit_loader_execution_gate import (
        BASE, SIZE, SHA256, TABLE, command_entry,
    )

TAG_FILL = 5
TAG_WRITE = 4
FILL_HANDLER = 0x20003381  # Thumb pointer from original table; opcode at 0x20003380
FILL_CODE_RANGE = (0x3380, 0x33A0)  # stop before next command handler
MAX_PREVIEW_BYTES = 128
TRACKED_WRITEMEMORY_POLICY = 0x200039A8
TRACKED_WRITEMEMORY_BACKEND = 0x20003B7C
CODE_CUTOFF = 0x17000  # begins HAB CSF in the original loader


def _capstone():
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    from capstone.arm import ARM_OP_IMM
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    md.detail = True
    return md, ARM_OP_IMM


def decode_window(image, begin, end):
    """Linear decoder of an explicitly bounded range; not a control-flow graph."""
    if not (0 <= begin < end <= min(len(image), CODE_CUTOFF)
            and begin % 2 == end % 2 == 0):
        raise ValueError("Invalid aligned code window")
    md, arm_imm = _capstone()
    items = []
    offset = begin
    for ins in md.disasm(image[begin:end], BASE + begin):
        if ins.address != BASE + offset:
            raise ValueError("Disassembly gap")
        offset += ins.size
        if offset > end:
            raise ValueError("Decoded instruction exceeded window")
        direct = None
        if ins.mnemonic.lower() in ("bl", "b.w", "b", "blx"):
            if ins.operands and ins.operands[-1].type == arm_imm:
                direct = ins.operands[-1].imm & 0xFFFFFFFF
        items.append({
            "at": f"0x{ins.address:08x}",
            "mnemonic": ins.mnemonic,
            "operands": ins.op_str,
            "direct_target": f"0x{direct:08x}" if direct is not None else None,
            "indirect_or_data_effects":"NOT INFERRED from isolated instruction"
        })
    if offset != end:
        raise ValueError("Incomplete bounded disassembly")
    return items


def summarize(image, expected_sha=SHA256, preview_bytes=MAX_PREVIEW_BYTES):
    if len(image) != SIZE:
        raise ValueError("Original signed RAM flashloader size mismatch")
    digest = hashlib.sha256(image).hexdigest()
    if digest != expected_sha:
        raise ValueError("Original signed RAM flashloader SHA-256 mismatch")
    if not (16 <= preview_bytes <= 256 and preview_bytes % 2 == 0):
        raise ValueError("Preview window must be 16..256 aligned bytes")
    fill = command_entry(image, TAG_FILL)
    write = command_entry(image, TAG_WRITE)
    execute = command_entry(image, 9)
    call = command_entry(image, 10)
    if (fill["handler"] != hex(FILL_HANDLER) or not fill["dispatches"]
            or not write["dispatches"] or execute["dispatches"] or call["dispatches"]):
        raise ValueError("Original loader command-table gate differs from pinned PR #24")
    handler = decode_window(image, *FILL_CODE_RANGE)
    targets = sorted({
        int(x["direct_target"], 16) for x in handler
        if x["mnemonic"].lower() in ("bl", "blx") and x["direct_target"]
        and BASE <= int(x["direct_target"],16) < BASE + CODE_CUTOFF
    })
    previews = []
    for target in targets:
        start = (target & ~1) - BASE
        if start + preview_bytes > CODE_CUTOFF:
            continue
        try:
            decoded = decode_window(image,start,start + preview_bytes)
        except ValueError:
            decoded = []
        previews.append({
            "target":f"0x{target:08x}",
            "decoded_preview":decoded,
            "preview_limit_bytes":preview_bytes,
            "callgraph_complete":False,
            "branch_conditions_analyzed":False,
        })
    immediate = [x["direct_target"] for x in handler
                 if x["direct_target"] and x["mnemonic"].lower() in ("bl","blx")]
    secondary = [
        x["direct_target"] for p in previews for x in p["decoded_preview"]
        if x["direct_target"] and x["mnemonic"].lower() in ("bl","blx")
    ]
    seen = set(immediate + secondary)
    observed_checks = {
        "known_WriteMemory_range_policy":f"0x{TRACKED_WRITEMEMORY_POLICY:08x}" in seen,
        "known_WriteMemory_backend":f"0x{TRACKED_WRITEMEMORY_BACKEND:08x}" in seen,
    }
    return {
        "review":"PR #24 FillMemory separate route",
        "image_bytes":len(image),"image_sha256":digest,
        "original_image_digest_checked":True,
        "device_access":False,"hid_requests":False,"flash_or_fuse_writes":False,
        "table":{
            "FillMemory":fill,"WriteMemory":write,"Execute":execute,"Call":call,
        },
        "protocol":{
            "tag":"0x05",
            "parameters":["startAddress uint32","byteCount uint32","patternWord uint32"],
            "payload_report_stage":False,
            "pattern_width_bits":32,
            "expected_alignment":"NXP general reference: word alignment/length multiple of 4; device-specific implementation not proven",
            "distinct_from_WriteMemory_fragment_gate":True,
            "source":"https://mcuxpresso.nxp.com/mcuxsdk/25.09.00/html/middleware/mcu_bootloader/docs/MCU_Bootloader_Reference_Manual/topics/mcu_bootloader_command_api.html",
        },
        "fill_handler":{
            "address":"0x20003380",
            "selected_instructions":handler,
            "direct_call_targets":[f"0x{x:08x}" for x in targets],
            "single_window_limit":"0x20003380..0x2000339f, not complete function reachability proof",
        },
        "first_level_callee_previews":previews,
        "tracked_WriteMemory_policy_hits_in_bounded_previews":observed_checks,
        "conclusions":{
            "host_can_issue_FillMemory_command":"SUPPORTED BY TABLE AND PUBLIC HOST IMPLEMENTATION; NO PACKET SENT",
            "FillMemory_uses_same_write_policy":"NOT ESTABLISHED from a bounded preview",
            "FillMemory_can_modify_execution_gate":"NOT DEMONSTRATED",
            "unsigned_custom_code_execution":"NOT DEMONSTRATED",
            "HAB_CLOSED_bypass":"NOT DEMONSTRATED",
            "recovery_after_bad_write":"NOT VERIFIED",
            "next_required_evidence":"trace FillMemory's own checked address/length and backend with full CFG or verified callee semantics before any device tests",
        },
        "limitations":"Linear Thumb decode + one level of bounded callee previews. Literal data and branch fall-through can be misinterpreted. Does not prove the absence of deeper indirect calls or bounds checks.",
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("loader",type=Path,help="Private exact 100672-byte restricted_ivt_flashloader.bin")
    parser.add_argument("--out",type=Path,help="Local-only evidence output")
    args=parser.parse_args()
    result=json.dumps(summarize(args.loader.read_bytes()),indent=2)+"\n"
    if args.out:
        args.out.write_text(result,encoding="utf-8")
    else:
        print(result,end="")


if __name__=="__main__":
    main()
