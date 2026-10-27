"""Phase 78: original signed Work Queue singleton helper, not a USB event.

Two independent signed callers (USB mode function / B initializer) pass
the same scalar 1 to the common 0x6009267C helper. Check what the
helper actually does and execute only its queue-handle guard in virtual
SRAM. Stop before any task creation/scheduler. No physical device I/O.
"""
from __future__ import annotations
import argparse,hashlib,json,struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SHA256,IMAGE_SIZE
from tools.audit_bruce_ep0_registration import decode
from tools.audit_pending_workqueue_phase67 import QUEUE,LABEL
from tools.audit_usb_driver_phase66 import machine
from tools.audit_workqueue_owners_phase77 import (
    verify_B_direct_activation_caller, verify_B_owner_state,
    verify_field_anchors, cross_check_phase66_shared_helper
)
from tools.audit_usb_provider_phase63 import BASE

HELPER=0x6009267C
CREATE=0x6010177A
MODE_CALL=0x60060F34
B_CALL=0x6006B400
HANDLE=QUEUE+0x58
SENTINEL=0x10000000
PINS={
    0x60060F28:("movs","r3, #1"),
    0x60060F32:("mov","r0, r3"),
    MODE_CALL:("bl","#0x6009267c"),
    0x6006B3FE:("movs","r0, #1"),
    B_CALL:("bl","#0x6009267c"),
    HELPER:("mov","r2, r0"),
    0x6009267E:("ldr","r0, [pc, #0x18]"),
    0x60092680:("push","{r3, lr}"),
    0x60092682:("ldr","r1, [r0, #0x58]"),
    0x60092684:("cbnz","r1, #0x60092692"),
    0x60092686:("ldr","r1, [pc, #0x14]"),
    0x60092688:("bl","#0x6010177a"),
    0x6009268C:("tst.w","r0, #0xff"),
    0x60092690:("bne","#0x60092696"),
    0x60092692:("mov.w","r0, #0"),
    0x60092696:("pop","{r3, pc}"),
}

def signed_verification(image):
    pieces=((0x60060F28,0x60060F38),
            (0x6006B3FE,0x6006B404),
            (HELPER,0x60092698))
    found={}
    for start,end in pieces:
        found.update({int(row["pc"],16):(row["m"],row["op"])
                      for row in decode(image,start,end)})
    for pc,expected in PINS.items():
        if found.get(pc)!=expected:
            raise ValueError(f"Phase78 signed OEM original instruction drift {pc:#x}: {found.get(pc)}")
    first=struct.unpack_from("<I",image,0x60092698-BASE)[0]
    second=struct.unpack_from("<I",image,0x6009269C-BASE)[0]
    if (first,second)!=(QUEUE,LABEL) or image[LABEL-BASE:LABEL-BASE+16]!=b"Work Queue Task\0":
        raise ValueError("Phase78 original Work Queue pointer/label literal drift")
    return {
        "pinned_original_instructions":len(PINS),
        "mode_caller":{"pc":hex(MODE_CALL),"original_argument_setup":"0x60060f28 R3=1; 0x60060f32 R0=R3",
                       "R0_when_calling_helper":1},
        "B_initializer":{"pc":hex(B_CALL),"original_argument_setup":"0x6006b3fe MOVS R0,#1",
                         "R0_when_calling_helper":1},
        "helper":hex(HELPER),
        "helper_action":"check [WorkQueue+0x58]; call original task creation helper only if no handle",
        "queue_object_literal_PC":"0x60092698","queue_object":hex(first),
        "worker_label_literal_PC":"0x6009269c","worker_label_pointer":hex(second),
        "worker_label":"Work Queue Task",
        "creation_callee":hex(CREATE),
    }

def original_guard_case(image,*,existing_handle):
    """Execute exact original helper; only bounded virtual, no task creation."""
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import (
        UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,
        UC_ARM_REG_LR,UC_ARM_REG_PC
    )
    u=machine(image)
    handle_value=0x20025000 if existing_handle else 0
    u.mem_write(HANDLE,struct.pack("<I",handle_value))
    u.reg_write(UC_ARM_REG_R0,1)
    u.reg_write(UC_ARM_REG_LR,SENTINEL|1)
    pcs=[]
    def hook(uc,pc,size,data):
        pcs.append(pc)
        if pc in (CREATE,SENTINEL):
            uc.emu_stop()
        elif not HELPER<=pc<0x60092698:
            raise ValueError(f"Phase78 unexpected original helper code {pc:#x}")
    h=u.hook_add(UC_HOOK_CODE,hook)
    try:
        u.emu_start(HELPER|1,0x10000002,count=40)
    finally:
        u.hook_del(h)
    destination=pcs[-1] if pcs else None
    expected=SENTINEL if existing_handle else CREATE
    if destination!=expected:
        raise ValueError(f"Phase78 original helper destination differs {destination!r}")
    if u.reg_read(UC_ARM_REG_R2)!=1:
        raise ValueError("Phase78 caller scalar R2 differs")
    if not existing_handle and (u.reg_read(UC_ARM_REG_R0),u.reg_read(UC_ARM_REG_R1))!=(QUEUE,LABEL):
        raise ValueError("Phase78 helper did not pass original Work Queue/label")
    if existing_handle and u.reg_read(UC_ARM_REG_R0)!=0:
        raise ValueError("Phase78 existing-handle fast path return differs")
    if struct.unpack("<I",bytes(u.mem_read(HANDLE,4)))[0]!=handle_value:
        raise ValueError("Phase78 unexpected mutation of queue handle")
    return {
        "seeded_existing_handle":existing_handle,
        "virtual_handle_before":hex(handle_value),
        "instruction_pcs":[hex(x) for x in pcs],
        "stop_before_creation":destination==CREATE,
        "original_helper_returned_without_creation":destination==SENTINEL,
        "r0_after":hex(u.reg_read(UC_ARM_REG_R0)),
        "r1_after":hex(u.reg_read(UC_ARM_REG_R1)),
        "r2_after":hex(u.reg_read(UC_ARM_REG_R2)),
        "handle_after":hex(handle_value),
        "creation_executed":False,
        "scheduler_or_USB_executed":False,
    }

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError("Phase78 exact signed Bruce OEM SHA-256 required")
    # Positive controls from previous signed linkages.
    prior=verify_B_direct_activation_caller(image)
    verify_B_owner_state(image)
    verify_field_anchors(image)
    shared=cross_check_phase66_shared_helper(image)
    signed=signed_verification(image)
    absent=original_guard_case(image,existing_handle=False)
    present=original_guard_case(image,existing_handle=True)
    return {
        "phase":78,"original_image_sha256":IMAGE_SHA256,
        "exact_signed_OEM_verified":True,
        "signed_initialization":signed,
        "virtual_guard_cases":[absent,present],
        "prior_phase77_activation_join":prior,
        "prior_phase76_shared_helper":shared,
        "interpretation":{
            "helper_shared_because_global_WorkQueue":"CONSISTENT_WITH_SIGNED_CODE_AND_VIRTUAL_GUARD",
            "USB_mode_call_must_imply_USB_host_event":False,
            "B_initializer_call_must_imply_USB_host_event":False,
            "proof_of_USB_physical_event_to_work_item":"NOT_ESTABLISHED",
            "host_controlled_code_pointer":"NOT_DEMONSTRATED",
            "A_producer_source":"UNRESOLVED",
            "B_callback_original_OEM":"0x6006b291",
            "signed_callback_call_executed":False,
            "unsigned_execution_or_HAB_bypass":"NOT_DEMONSTRATED",
        },
        "limits":{
            "USB_device_commands":False,"live_RAM_readback":False,
            "flash_or_eFuse_writes":False,
            "queue_creation_or_message_delivery":False,
            "runtime_mapped_USB_event":False,
            "alternative_indirect_callers_or_aliases":"NOT_EXCLUDED",
        },
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--out",type=Path)
    args=p.parse_args()
    r=audit(args.image.read_bytes())
    if args.out:args.out.write_text(json.dumps(r,indent=2)+"\n",encoding="utf-8")
    print("PHASE78 VERIFIED SHARED QUEUE INITIALIZER",json.dumps(r["signed_initialization"]))
    print("PHASE78 VIRTUAL GUARDS",json.dumps(r["virtual_guard_cases"]))
    print("PHASE78 EVIDENCE",json.dumps(r,separators=(",",":")))
    print("PHASE78 NO HOST TRIGGER, CALLBACK OR FIRMWARE EXECUTION DEMONSTRATED")

if __name__=="__main__":main()
