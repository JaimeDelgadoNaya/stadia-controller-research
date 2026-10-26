"""Execute ONLY signed Bruce's existing SETUP forwarding suffix in virtual RAM.

This is deliberately not the USB transport, full callback dispatcher, EP0
registration or any physical device. An original signed code fragment runs
under Unicorn, starting at 0x600D0EA2 with *synthetic* registers and class
object pointers. We stop BEFORE BX dispatch to any callback. The emulator
does not emulate HAB, USB hardware, physical SRAM or flash persistence.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256, IMAGE_SIZE

FIRMWARE_BASE=0x60040000
EXEC_START=0x600D0EA2
EXEC_DISPATCH=0x600D0EBE
REJECT_BRANCH=0x600D0E76
MISMATCH_BRANCH=0x600D0EC6
RAM_BASE=0x20000000
OBJ=0x20002000
MSG=0x20002100
REQUEST=0x20002200
TABLE=0x20002300
DUMMY_CALLBACK=0x20003001
INTERFACE=1

def synthetic_packet(request_code,bm_request_type=0xA1,w_index=INTERFACE):
    if not all(0<=v<=255 for v in (request_code,bm_request_type,w_index)):
        raise ValueError("synthetic USB fields must fit one byte")
    return bytes([bm_request_type,request_code,0,0,w_index,0,0,0])

def prepare_synthetic_state(uc,request_code,request_type,w_index):
    """All pointer values are explicit *virtual* values on discarded memory."""
    from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP
    uc.mem_map(RAM_BASE,0x10000)
    uc.mem_write(OBJ+4,struct.pack("<I",TABLE))
    uc.mem_write(OBJ+0xD,bytes([INTERFACE]))
    uc.mem_write(MSG,struct.pack("<I",REQUEST))
    uc.mem_write(REQUEST,synthetic_packet(request_code,request_type,w_index))
    uc.mem_write(TABLE,struct.pack("<I",DUMMY_CALLBACK))
    uc.reg_write(UC_ARM_REG_R0,OBJ)
    uc.reg_write(UC_ARM_REG_R1,0)
    uc.reg_write(UC_ARM_REG_R2,MSG)
    uc.reg_write(UC_ARM_REG_SP,RAM_BASE+0xF000)

def run_case(image,request_code,request_type=0xA1,w_index=INTERFACE):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R3
    uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS)
    uc.mem_map(FIRMWARE_BASE,0x200000)
    uc.mem_write(FIRMWARE_BASE,image)
    prepare_synthetic_state(uc,request_code,request_type,w_index)
    stops={}
    visited=[]
    def on_code(emu,pc,size,ctx):
        visited.append(hex(pc))
        if pc in (EXEC_DISPATCH,REJECT_BRANCH,MISMATCH_BRANCH):
            stops.update({"pc":hex(pc),
                "r0":hex(emu.reg_read(UC_ARM_REG_R0)),
                "r1":hex(emu.reg_read(UC_ARM_REG_R1)),
                "r3":hex(emu.reg_read(UC_ARM_REG_R3)),
                "classification":"forwarded_before_bx" if pc==EXEC_DISPATCH
                                 else "rejected_before_callback"})
            emu.emu_stop()
    uc.hook_add(UC_HOOK_CODE,on_code)
    uc.emu_start(EXEC_START|1,0x600D0EE0,count=75)
    if not stops:
        raise RuntimeError("Original fragment left bounded region without known stop")
    if stops["classification"]=="forwarded_before_bx":
        if stops["r1"]!=hex(request_code) or stops["r3"]!=hex(DUMMY_CALLBACK):
            raise AssertionError("Original signed instructions did not forward synthetic request as expected")
    return {
        "packet":synthetic_packet(request_code,request_type,w_index).hex(),
        "request_code":hex(request_code),
        "bmRequestType":hex(request_type),
        "wIndex_low":w_index,
        "stop":stops,
        "instruction_count":len(visited),
        "executed_callback":False,
        "callback_pointer_is_synthetic_dummy":True,
    }

def emulate(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Requires exact original signed Bruce SHA-256 and size")
    cases=[
        run_case(image,0x81,0xA1,1),
        run_case(image,0x83,0x21,1),
        run_case(image,0x84,0xA1,1),
        run_case(image,0x81,0xA0,1), # recipient device, not interface
        run_case(image,0x84,0xA1,2), # mismatched interface
    ]
    for x in cases[:3]:
        if x["stop"]["classification"]!="forwarded_before_bx":
            raise AssertionError("Expected conditional forwarding for synthetic matching interface")
    for x in cases[3:]:
        if x["stop"]["classification"]!="rejected_before_callback":
            raise AssertionError("Expected guarded rejection for synthetic mismatched recipient/index")
    return {
      "source":"SHA-pinned original Google signed Bruce update (not readback)",
      "sha256":IMAGE_SHA256,
      "start":"0x600d0ea2",
      "last_executable_instruction":"BEFORE 0x600d0ebe BX R3",
      "behavior":"Actual signed Thumb code executed only for synthetic arguments; no USB firmware source, callback instance or EP0 registration proven",
      "results":cases,
      "USB_transfer_sent":False,
      "original_flash_changed":False,
      "callback_code_executed":False,
      "own_code_executed_on_physical_device":False,
      "HAB_bypassed":False
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("bruce",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args()
    x=emulate(a.bruce.read_bytes())
    if a.out:
        a.out.write_text(json.dumps(x,indent=2)+"\n",encoding="utf-8")
    for case in x["results"]:
        print("SIMULATED",case["request_code"],case["bmRequestType"],case["wIndex_low"],
              case["stop"]["classification"],case["stop"]["pc"],
              case["stop"]["r1"],case["stop"]["r3"],
              "instr",case["instruction_count"])
    print("NO PHYSICAL USB, CALLBACK INVOCATION, FIRMWARE WRITES OR HAB TEST")

if __name__=="__main__":
    main()
