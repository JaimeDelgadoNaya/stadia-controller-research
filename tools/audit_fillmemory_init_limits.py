"""SHA-locked original Stadia loader: FillMemory dynamic guard initializer.

Read-only, no USB or firmware writes. Proves which constants are stored by a
specific initializer, NOT that it necessarily ran before a host command.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools import audit_fillmemory_verified as original
from tools import audit_fillmemory_wrap_model as wrap
from tools import audit_fillmemory_dynamic_guard as guard

ENTRY = 0x20009904
ENTRY_THUMB = ENTRY | 1
TABLE_OFFSET = 0x16078
# Literal + store pairs in the original signed loader, in code order.
PAIRS = (
    (0x20009926, 0x99A0, 0x2000992C, 0x70, 0x20002000),
    (0x2000992E, 0x99A4, 0x20009934, 0x74, 0x20016D08),
    (0x20009936, 0x99A8, 0x2000993A, 0x78, 0x20208000),
    (0x2000993C, 0x99AC, 0x20009946, 0x7C, 0x20216FFF),
)
INIT_LIMITS = tuple(row[-1] for row in PAIRS)


def _one_instruction(data, pc):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    pos = pc - original.BASE
    ins = next(iter(md.disasm(data[pos:pos+4], pc, count=1)), None)
    if not ins or ins.address != pc:
        raise ValueError("cannot disassemble anchor " + hex(pc))
    return ins


def model_initial_state():
    """Hypothesis: 0x20009904 ran normally and nobody altered its four fields."""
    cases=[]
    for field in wrap.CONTROL_FIELDS:
        ordinary_bad=guard.guard_symbolic_model(field,4,INIT_LIMITS)
        count=wrap.wrap_length_for_end(field,0x2003)
        wrapped_bad=guard.guard_symbolic_model(field,count,INIT_LIMITS)
        returnable_ram_bytes=wrap.byte_count_within_region(field,wrap.RAM_REGION_END)
        cases.append({
            "field":hex(field),
            "normal_four_bytes_rejected_by_guard":ordinary_bad,
            "wrapped_prechecks_can_pass":wrap.policy_op_zero_precheck(field,count),
            "wrapped_length_rejected_by_guard_if_initialized":wrapped_bad,
            "wrapped_length_exceeds_loader_ram":count>returnable_ram_bytes,
            "can_finish_and_return_control":"UNKNOWN — no hardware execution or full emulator",
            "execution_bypass":"NOT DEMONSTRATED",
        })
    return cases


def analyze(data:bytes):
    if len(data)!=original.SIZE or hashlib.sha256(data).hexdigest()!=original.SHA256:
        raise ValueError("must use exact original signed flashloader")
    u32=lambda off:struct.unpack_from("<I",data,off)[0]
    if u32(TABLE_OFFSET)!=ENTRY_THUMB:
        raise ValueError("initializer function pointer does not match pinned original")
    if u32(0x9998)!=0x202081F4:
        raise ValueError("initializer global pointer source changed")
    # Guard -> interface+0xC -> table+0x10 -> context, already checked by PR #29.
    records=[]
    for load_pc,lit_off,store_pc,field_off,expected in PAIRS:
        value=u32(lit_off)
        if value!=expected:
            raise ValueError("initializer literal differs " + hex(lit_off))
        load=_one_instruction(data,load_pc)
        store=_one_instruction(data,store_pc)
        if (load.mnemonic!="ldr" or not load.op_str.startswith("r0, [pc,")
                or store.mnemonic!="str"
                or store.op_str.replace(" ","")!=f"r0,[r3,#0x{field_off:x}]"):
            raise ValueError("literal-load to field-store anchor changed at "+hex(store_pc))
        records.append({"load_at":hex(load_pc),"literal_at":hex(original.BASE+lit_off),
                        "store_at":hex(store_pc),"context_field":hex(guard.PROVIDER_CONTEXT+field_off),
                        "stored_value":hex(value)})
    cases=model_initial_state()
    if not all(c["normal_four_bytes_rejected_by_guard"]
               and not c["wrapped_length_rejected_by_guard_if_initialized"]
               and c["wrapped_length_exceeds_loader_ram"] for c in cases):
        raise ValueError("unexpected branch model result, inspect graph")
    return {
        "original_sha256_verified":True,
        "initializer_function":hex(ENTRY),
        "initializer_reference_in_signed_table":hex(original.BASE+TABLE_OFFSET),
        "context_ram":hex(guard.PROVIDER_CONTEXT),
        "signed_literal_and_store_pairs":records,
        "limits_if_initializer_executed":[hex(x) for x in INIT_LIMITS],
        "state_measured_on_real_device":False,
        "initialization_reachability_verified":False,
        "possible_later_setters_excluded":False,
        "conditional_guard_cases":cases,
        "exploitation_conclusion":"Wrapped arithmetic may bypass static and initialized guard comparisons, but massive write effects and safe return NOT PROVEN.",
        "usb_or_hardware_access":False,"writes":False
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("loader",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    report=analyze(args.loader.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({key:report[key] for key in (
        "original_sha256_verified","initializer_function","limits_if_initializer_executed",
        "conditional_guard_cases","state_measured_on_real_device","exploitation_conclusion")},
        indent=2))


if __name__=="__main__":
    main()
