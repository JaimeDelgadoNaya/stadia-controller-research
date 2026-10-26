"""Emulate the *original signed* Bruce 16-byte class-selector comparison.

Uses synthetic RAM descriptors; begins at 0x60055178 and stops before the
BLX at 0x60055194. Does not run class methods, EP0, bootloader, or hardware.
"""
import argparse,hashlib,json,struct
from pathlib import Path
from tools.audit_signed_app_surface import IMAGE_SIZE,IMAGE_SHA256
from tools.audit_bruce_class_selector_verified import verified_rom_table,ROM_TABLE_BASE

FLASH_BASE=0x60040000
ENTRY_PC=0x60055178
MATCH_PC=0x60055194
NO_MATCH_PC=0x60055196
RAM_BASE=0x20000000
RAM_SIZE=0x10000
DEVICE=0x20003000
REGISTRY_CONTEXT=0x20001000
CONFIG_OBJECT=0x20001100
INTERFACE_RECORD=0x20001200
DESCRIPTOR=0x20001300

def synthetic_case(original,record_index,advertised_id):
    from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_MODE_MCLASS,UC_HOOK_CODE
    from unicorn.arm_const import (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,
        UC_ARM_REG_R3,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
        UC_ARM_REG_R8,UC_ARM_REG_R11,UC_ARM_REG_SP)
    if not 0<=record_index<5:raise ValueError("record_index outside signed table")
    if not 0<=advertised_id<=255:raise ValueError("advertised class byte invalid")
    uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS)
    uc.mem_map(FLASH_BASE,0x200000)
    uc.mem_write(FLASH_BASE,original)
    uc.mem_map(RAM_BASE,RAM_SIZE)
    uc.mem_write(REGISTRY_CONTEXT+4,struct.pack("<I",CONFIG_OBJECT))
    uc.mem_write(CONFIG_OBJECT,struct.pack("<I",INTERFACE_RECORD))
    uc.mem_write(INTERFACE_RECORD+8,struct.pack("<I",DESCRIPTOR))
    uc.mem_write(DESCRIPTOR+4,bytes([advertised_id]))
    uc.reg_write(UC_ARM_REG_R5,REGISTRY_CONTEXT)
    uc.reg_write(UC_ARM_REG_R6,DEVICE)
    uc.reg_write(UC_ARM_REG_R7,record_index*16)
    uc.reg_write(UC_ARM_REG_R8,0)
    uc.reg_write(UC_ARM_REG_R11,ROM_TABLE_BASE)
    uc.reg_write(UC_ARM_REG_SP,RAM_BASE+0xf000)
    outcome={}
    steps=[]
    def stop(emu,pc,size,ctx):
        steps.append(hex(pc))
        if pc in (MATCH_PC,NO_MATCH_PC):
            outcome.update({
              "stop_pc":hex(pc),
              "matched_before_indirect_call":pc==MATCH_PC,
              "method_thumb_in_R3":hex(emu.reg_read(UC_ARM_REG_R3)),
              "class_input_r0":hex(emu.reg_read(UC_ARM_REG_R0)),
              "arg_r1":hex(emu.reg_read(UC_ARM_REG_R1)),
              "arg_r2":hex(emu.reg_read(UC_ARM_REG_R2)),
            })
            emu.emu_stop()
    uc.hook_add(UC_HOOK_CODE,stop)
    uc.emu_start(ENTRY_PC|1,0x6005519C,count=32)
    if not outcome:raise RuntimeError("Signed selector left bounded window unexpectedly")
    return {"record_index":record_index,"advertised_selector":advertised_id,
            "original_signed_table_selector":[1,2,4,10,0][record_index],
            "result":outcome,"instructions_before_stop":len(steps),
            "method_executed":False,"RAM_synthetic":True}

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Exact original signed Bruce image required")
    table=verified_rom_table(image)
    results=[
        synthetic_case(image,2,4),
        synthetic_case(image,3,10),
        synthetic_case(image,2,10),
        synthetic_case(image,3,4),
    ]
    if results[0]["result"]["method_thumb_in_R3"]!="0x60054875":
        raise AssertionError("signed class4 method unexpected")
    if results[1]["result"]["method_thumb_in_R3"]!="0x60055321":
        raise AssertionError("signed class10 method unexpected")
    for r in results[:2]:
        if not r["result"]["matched_before_indirect_call"]:
            raise AssertionError("expected synthetic class selector match")
    for r in results[2:]:
        if r["result"]["matched_before_indirect_call"]:
            raise AssertionError("expected mismatched descriptor class selector")
    return {"sha256_verified":True,"table_record_count":len(table),
            "original_start":"0x60055178",
            "last_executed_before_call":"0x60055192",
            "never_execute_indirect_BLX":"0x60055194",
            "virtual_cases":results,
            "USB_physical_used":False,"flash_written":False,
            "real_EP0_class_id":"UNMEASURED",
            "actual_class10_callback_source":"UNMEASURED",
            "host_0x81_0x83_0x84_reachability":"UNMEASURED"}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    result=audit(a.image.read_bytes())
    if a.out:a.out.write_text(json.dumps(result,indent=2)+"\n")
    print("SELECTOR EMULATION",json.dumps(result["virtual_cases"]))
    print("NO CLASS METHOD EXECUTED OR PHYSICAL USB TRAFFIC")
if __name__=="__main__":main()
