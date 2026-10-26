"""Bounded Unicorn experiment with original signed Bruce class-10 callback.

Loads exact OEM signed machine code, using a synthetic secondary RAM callback
registry. NEVER executes BLX callback, sends USB, or modifies a controller.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE
from tools.audit_bruce_class10_record_producer import (
    original_class10_handler_guard, confirmed_boot_records
)

ROM_BASE=0x60040000
EXEC_PC=0x600613FC
RETURN_ZERO_PC=0x60061422
BEFORE_INDIRECT_BLX=0x60061416
RAM_BASE=0x20000000
GLOBAL_CALLBACK_BASE=0x200064C0
GLOBAL_CALLBACK_ADDR=0x20009EF8
GLOBAL_CONTEXT_ADDR=0x20009EFC
SENTINEL_SIGNED_THUMB=0x600D4F05
OTHER_SIGNED_CALLBACK=0x60061249
SYNTHETIC_CONTEXT=0x20003100

def case(original,request_code,registered_ptr,context=SYNTHETIC_CONTEXT):
    from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_MODE_MCLASS,UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R3,UC_ARM_REG_SP
    if request_code<0 or request_code>255:
        raise ValueError("request_code must be an 8-bit value")
    if registered_ptr not in (SENTINEL_SIGNED_THUMB,OTHER_SIGNED_CALLBACK):
        raise ValueError("secondary target must be a pinned signed OEM pointer")
    uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS)
    uc.mem_map(ROM_BASE,0x200000)
    uc.mem_write(ROM_BASE,original)
    uc.mem_map(RAM_BASE,0x10000)
    uc.mem_write(GLOBAL_CALLBACK_ADDR,struct.pack("<I",registered_ptr))
    uc.mem_write(GLOBAL_CONTEXT_ADDR,struct.pack("<I",context))
    uc.reg_write(UC_ARM_REG_R0,0x20003000)
    uc.reg_write(UC_ARM_REG_R1,request_code)
    uc.reg_write(UC_ARM_REG_SP,RAM_BASE+0xF000)
    stops=[]
    def stop(emu,pc,size,ctx):
        if pc in (RETURN_ZERO_PC,BEFORE_INDIRECT_BLX):
            stops.append({"pc":hex(pc),"result":(
                "would_delegate_but_BLX_not_executed" if pc==BEFORE_INDIRECT_BLX
                else "zero_return_guard"),
                "r0":hex(emu.reg_read(UC_ARM_REG_R0)),
                "r1":hex(emu.reg_read(UC_ARM_REG_R1)),
                "r3":hex(emu.reg_read(UC_ARM_REG_R3))})
            emu.emu_stop()
    uc.hook_add(UC_HOOK_CODE,stop)
    uc.emu_start(EXEC_PC|1,0x60061426,count=40)
    if len(stops)!=1:
        raise RuntimeError("original signed handler exited bounded inspection unexpectedly")
    return {"request":hex(request_code),
            "secondary_registry_word":hex(registered_ptr),
            "stop":stops[0],"callback_executed":False,
            "all_memory_synthetic":True}

def inspect(original):
    if len(original)!=IMAGE_SIZE or hashlib.sha256(original).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Exact signed OEM Bruce SHA256 and length required")
    cb=confirmed_boot_records(original)
    guard=original_class10_handler_guard(original)
    if cb[1]["callback_function_address"]!="0x600613fc":
        raise AssertionError("signed class10 original callback address mismatch")
    if guard["global_base_from_pc_literal"]!=hex(GLOBAL_CALLBACK_BASE):
        raise AssertionError("signed original class10 RAM base mismatch")
    if guard["sentinel_word_from_pc_literal"]!=hex(SENTINEL_SIGNED_THUMB):
        raise AssertionError("signed original sentinel mismatch")
    expected=[
        (0x7F,OTHER_SIGNED_CALLBACK,"zero_return_guard"),
        (0x81,SENTINEL_SIGNED_THUMB,"zero_return_guard"),
        (0x83,OTHER_SIGNED_CALLBACK,"would_delegate_but_BLX_not_executed"),
        (0x84,OTHER_SIGNED_CALLBACK,"would_delegate_but_BLX_not_executed"),
    ]
    results=[]
    for req,registered,result in expected:
        item=case(original,req,registered)
        if item["stop"]["result"]!=result:
            raise AssertionError("original signed callback guard mismatch "+hex(req))
        if result=="would_delegate_but_BLX_not_executed":
            if item["stop"]["r3"]!=hex(registered) or item["stop"]["r0"]!=hex(SYNTHETIC_CONTEXT):
                raise AssertionError("synthetic callback/context registers unexpected")
        results.append(item)
    return {"original_sha256_verified":True,
            "source_callback_thumb":"0x600613fd",
            "guarded_RAM_function_slot":hex(GLOBAL_CALLBACK_ADDR),
            "guarded_RAM_context_slot":hex(GLOBAL_CONTEXT_ADDR),
            "original_sentinel_thumb":hex(SENTINEL_SIGNED_THUMB),
            "cases":results,"real_USB_reachability":"UNVERIFIED",
            "real_callback_registered":"UNVERIFIED",
            "executed_any_indirect_callback":False,
            "device_USB_used":False,"flash_written":False,"own_firmware_execution":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    report=inspect(a.image.read_bytes())
    if a.out:
        a.out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print("SIGNED CLASS10 GUARD EMULATION",json.dumps(report["cases"]))
    print("SECONDARY REGISTRY ADDRESS",report["guarded_RAM_function_slot"])
    print("NO INDIRECT CALLBACK EXECUTED; NO PHYSICAL USB IO")

if __name__=="__main__":
    main()
