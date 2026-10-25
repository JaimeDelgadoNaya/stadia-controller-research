"""Bounded Unicorn execution of the SHA-verified ORIGINAL FillMemory byte loop.

Runs ONLY the low-level RAM fill routine 0x20002698 in a fake ARM memory map.
No transports, no controller or actual memory writes; no command dispatcher.
A virtual write outside the declared 128-KiB map is treated as an emulator
boundary observation, NOT proof of a real device bus fault.
"""
import argparse
import hashlib
import json
from pathlib import Path
from tools import audit_fillmemory_verified as verified
from tools import audit_fillmemory_wrap_model as wrapped

RAM_BASE = wrapped.RAM_REGION_START
RAM_SIZE = wrapped.RAM_REGION_END - wrapped.RAM_REGION_START + 1
SUBROUTINE = 0x20002698
RETURN = 0x1000
MAX_INSTRUCTIONS = 450000


def execute_low_level(blob, start, length, pattern=0xA5A5A5A5,
                      *, budget=MAX_INSTRUCTIONS):
    if len(blob)!=verified.SIZE or hashlib.sha256(blob).hexdigest()!=verified.SHA256:
        raise ValueError("SHA-256 pinned original signed loader required")
    if not (0 <= start <= 0xffffffff and 1 <= length <= 0xffffffff):
        raise ValueError("Require positive uint32 arguments")
    from unicorn import (
        Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS,
        UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_WRITE, UC_HOOK_CODE,
    )
    from unicorn.arm_const import (
        UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
        UC_ARM_REG_R7, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
    )
    cpu=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS)
    cpu.mem_map(RAM_BASE,RAM_SIZE)
    cpu.mem_write(RAM_BASE,blob)
    cpu.mem_map(RETURN,0x1000)
    # r0=dest, r1=pattern, r2=byte count, r3=optimized-fill selector.
    for reg,value in (
        (UC_ARM_REG_R0,start),(UC_ARM_REG_R1,pattern),
        (UC_ARM_REG_R2,length),(UC_ARM_REG_R3,1),
        (UC_ARM_REG_SP,0x2001F800),(UC_ARM_REG_LR,RETURN|1),
    ):
        cpu.reg_write(reg,value)
    state={
        "start":hex(start),"length":length,
        "mapped_ram":f"0x{RAM_BASE:08x}..0x{RAM_BASE+RAM_SIZE-1:08x}",
        "first_store_addresses":[],"virtual_invalid_write":None,
        "virtual_store_events":0,"byte_tail_store_events":0,"entered_signed_byte_tail":False,
        "virtual_return_observed":False,"budget_exhausted":False,
        "real_bus_fault":"NOT TESTED",
        "writes_on_physical_controller":False,
        "backend_only_no_command_dispatch":True,
    }
    def trace_write(uc,access,address,size,value,user_data):
        state["virtual_store_events"] += 1
        # Exclude routine prologue PUSH/store side-effects on synthetic stack.
        if uc.reg_read(UC_ARM_REG_PC)==0x20002700:
            state["byte_tail_store_events"] += 1
            if len(state["first_store_addresses"])<8:
                state["first_store_addresses"].append(hex(address))
    def invalid(uc,access,address,size,value,user_data):
        state["virtual_invalid_write"]={"address":hex(address),"size":size,
                "pc":hex(uc.reg_read(UC_ARM_REG_PC)),
                "remaining_count":uc.reg_read(UC_ARM_REG_R2)}
        return False
    def trace_code(uc,address,size,user_data):
        if address==0x200026FC:
            state["entered_signed_byte_tail"]=True
        if address==RETURN:
            state["virtual_return_observed"]=True
            uc.emu_stop()
    cpu.hook_add(UC_HOOK_MEM_WRITE,trace_write)
    cpu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED,invalid)
    cpu.hook_add(UC_HOOK_CODE,trace_code)
    try:
        cpu.emu_start(SUBROUTINE|1,RETURN,count=budget)
    except UcError as e:
        state["emulator_exception"]=str(e)
    state["pc_at_stop"]=hex(cpu.reg_read(UC_ARM_REG_PC))
    state["remaining_r2_at_stop"]=cpu.reg_read(UC_ARM_REG_R2)
    if state["virtual_invalid_write"] is None and not state["virtual_return_observed"]:
        state["budget_exhausted"]=True
    return state


def audit(blob):
    if len(blob)!=verified.SIZE or hashlib.sha256(blob).hexdigest()!=verified.SHA256:
        raise ValueError("SHA-256 pinned original signed loader required")
    scenarios=[]
    for start in wrapped.CONTROL_FIELDS:
        count=wrapped.wrap_length_for_end(start,0x2003)
        x=execute_low_level(blob,start,count)
        expected=wrapped.byte_count_within_region(start,wrapped.RAM_REGION_END)
        if not x["entered_signed_byte_tail"]:
            raise ValueError("signed byte-tail was not reached in original code")
        if x["virtual_invalid_write"] is None:
            raise ValueError("expected a bounded-map virtual write exception")
        if int(x["virtual_invalid_write"]["address"],16)!=RAM_BASE+RAM_SIZE:
            raise ValueError("different boundary from arithmetic model")
        if x["byte_tail_store_events"] not in (expected, expected+1):
            raise ValueError("Virtual byte-loop store count differs from bounded model "
                             f"actual={x['byte_tail_store_events']} expected={expected} "
                             f"all_writes={x['virtual_store_events']}")
        if x["virtual_return_observed"]:
            raise ValueError("unexpected return before virtual-region exit")
        scenarios.append(x)
    return {
        "source_sha256":verified.SHA256,
        "original_image_verified":True,
        "engine":"Unicorn ARM Thumb/M-class, exact signed original low-level fill code",
        "memory_map":"Only 0x20000000..0x2001ffff declared region + sentinel, not a full SoC model",
        "scenarios":scenarios,
        "device_access":False,
        "firmware_modification":False,
        "interpretation":"A virtual write hits first unmapped page; actual bus result and recoverability are UNKNOWN."
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("loader",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    result=audit(args.loader.read_bytes())
    if args.out:
        args.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(result,indent=2))


if __name__=="__main__":
    main()
