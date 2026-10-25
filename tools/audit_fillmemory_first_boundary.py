"""No-hardware FillMemory first-boundary-effect model (arithmetic only).

The model does NOT execute unsigned firmware, emulate the entire MCU or
transmit any command. It validates the original signed loader's relevant
instructions, then computes the first departure from a declared memory-map
region without allocating a 3.5 GiB buffer or generating HID packets.
"""
import argparse
import hashlib
import json
from pathlib import Path
from tools import audit_fillmemory_verified as verified
from tools import audit_fillmemory_wrap_model as wrapped

MASK = 0xFFFFFFFF
SIGNED_LIMIT = 0x80000000
REGION_LOW = wrapped.RAM_REGION_START
REGION_HIGH = wrapped.RAM_REGION_END
CONTROL_FIELDS = wrapped.CONTROL_FIELDS
MAX_PREVIEW_BYTES = 64


def signed32(x):
    if not 0 <= x <= MASK:
        raise ValueError("unsigned 32-bit only")
    return x if x < SIGNED_LIMIT else x - (1 << 32)


def chosen_loop_route(start, count):
    """Approximate branch route at 0x20002698..0x200026FC.

    On word-aligned starts with count high bit set, signed BLT at 0x26c4
    enters the single-byte remainder loop, not the 16-byte STM loop.
    """
    if not (0 <= start <= MASK and 0 <= count <= MASK):
        raise ValueError("start/count must be uint32")
    if count == 0:
        return "zero_length_fast_return"
    if start & 3:
        return "unaligned_prefix_needs_independent_emulation"
    if signed32(count) < 4:
        return "byte_tail_signed_blt"
    return "bulk_or_short_tail_bounded_model"


def first_declared_boundary(start, count, lo=REGION_LOW, hi=REGION_HIGH):
    """No actual writes: compute first symbolic store outside [lo,hi].

    'outside' means outside this single declared region, *not necessarily*
    an unmapped bus address on the actual SoC.
    """
    if not (0 <= lo <= hi <= MASK):
        raise ValueError("invalid declared region")
    if not (0 <= start <= MASK and 0 <= count <= MASK):
        raise ValueError("start/count not uint32")
    route=chosen_loop_route(start,count)
    if count == 0:
        return {"route":route, "writes_before_region_exit":0,
                "first_outside_this_region":None,"actual_bus_fault":"UNKNOWN"}
    if not lo <= start <= hi:
        return {"route":route,"writes_before_region_exit":0,
                "first_outside_this_region":hex(start),"actual_bus_fault":"UNKNOWN"}
    available=hi-start+1
    if count <= available:
        return {"route":route,"writes_before_region_exit":count,
                "first_outside_this_region":None,"actual_bus_fault":"UNKNOWN"}
    return {
        "route":route,
        "writes_before_region_exit":available,
        "first_outside_this_region":hex((hi+1)&MASK),
        "requested_length_exceeds_declared_region":True,
        "actual_bus_fault":"UNKNOWN — no bus decoder/MMU/hardware emulated",
        "continuation_and_recovery":"UNVERIFIED",
    }


def small_mock_preview(start, count, preview=MAX_PREVIEW_BYTES):
    """Independent disposable page preview; no command transport or real RAM.

    The pattern is abstracted to one repeated byte, as the only property
    modeled here is *which symbolic addresses* the first stores affect.
    """
    if not 0 <= preview <= MAX_PREVIEW_BYTES:
        raise ValueError("preview is bounded to 64 bytes")
    if not (0 <= start <= MASK and 0 <= count <= MASK):
        raise ValueError("start/count uint32")
    n=min(count,preview)
    sandbox=bytearray(preview)
    for i in range(n):
        sandbox[i]=0xA5
    return {"simulated_bytes":n,"first":hex(start),"last":hex((start+n-1)&MASK)
            if n else None,"disposable_buffer_bytes":len(sandbox),
            "actual_memory_touched":False}


def anchor(data, pc, mnemonic, op_part):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
    at=pc-verified.BASE
    ins=next(iter(md.disasm(data[at:at+4],pc,count=1)),None)
    if not ins or ins.mnemonic != mnemonic or op_part not in ins.op_str:
        raise ValueError("Signed Thumb branch anchor differs at "+hex(pc))
    return {"at":hex(pc),"mnemonic":ins.mnemonic,"operands":ins.op_str}


def original_report(data):
    if len(data)!=verified.SIZE or hashlib.sha256(data).hexdigest()!=verified.SHA256:
        raise ValueError("pinned original signed flashloader required")
    # The signed-vs-unsigned distinction is specific to these BLT branches.
    code=[
        anchor(data,0x20002698,"cmp","r2, #0"),
        anchor(data,0x200026AA,"cmp","r3, #0"),
        anchor(data,0x200026C2,"cmp","r2, #4"),
        anchor(data,0x200026C4,"blt","#0x200026fc"),
        anchor(data,0x200026D6,"stm","r0!"),
        anchor(data,0x200026FC,"cmp","r2, #0"),
        anchor(data,0x20002700,"strb","[r0]"),
        anchor(data,0x20002708,"subs","r2, #1"),
        anchor(data,0x2000270A,"bne","#0x200026fc"),
    ]
    cases=[]
    for field in CONTROL_FIELDS:
        length=wrapped.wrap_length_for_end(field,0x2003)
        route=chosen_loop_route(field,length)
        if route!="byte_tail_signed_blt":
            raise ValueError("expected signed-byte loop route changed")
        info=first_declared_boundary(field,length)
        cases.append({
            "start":hex(field),
            "length_bytes":length,
            "signed_length":signed32(length),
            "idealized_first_region_exit":info,
            "first_64_bytes_sandbox_preview":small_mock_preview(field,length),
            "whole_fill_processed":False,
            "cpu_can_return":"NOT ESTABLISHED",
        })
    return {
        "signed_image_sha256":verified.SHA256,
        "hash_checked":True,
        "instruction_anchors":code,
        "model_scope":"arithmetic plus signed Thumb branch route, disposable page preview; NOT a full CPU/bus emulator",
        "cases":cases,
        "device_access":False,"flash_writes":False,"host_commands":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("loader",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    result=original_report(args.loader.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"hash_checked":result["hash_checked"],
        "model_scope":result["model_scope"],
        "cases":[{k:v for k,v in x.items() if k!="first_64_bytes_sandbox_preview"}
                 for x in result["cases"]]},indent=2))


if __name__=="__main__":
    main()
