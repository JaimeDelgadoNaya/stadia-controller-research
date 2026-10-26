"""Phase74 bounded execution of original queue receiver's argument guards.

Inherits the exact virtual machine prepared by phase73. Executes original
BL at 0x600EE152, OEM XIP veneer and ITCM receiver prologue, but stops
before the first kernel helper at 0x6D58. No dequeue or callback executes.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from tools.audit_signed_app_surface import IMAGE_SIZE,IMAGE_SHA256
from tools.audit_task_entry_phase73 import WAIT
from tools.audit_app_usb_dispatch import ITCM_SOURCE_OFFSET,ITCM_LENGTH
from tools.audit_queue_receive_phase74 import (
    prepare_phase73_state,receiver_code,queue_snapshot,code_window,itcm_code,
    VENEER,word
)

PINS={
    0x6D2C:('push.w','{r4, r5, r6, r7, r8, sb, lr}'),
    0x6D30:('sub','sp, #0x14'),
    0x6D32:('mov','r7, r1'),
    0x6D34:('mov','r4, r0'),
    0x6D36:('str','r2, [sp, #4]'),
    0x6D38:('cbnz','r0, #0x6d46'),
    0x6D46:('cbnz','r7, #0x6d58'),
    0x6D58:('bl','#0x7734'),
    0x6D7A:('ldr','r5, [r4, #0x38]'),
    0x6D7C:('cbz','r5, #0x6db4'),
    0x6DB4:('ldr','r5, [sp, #4]'),
    0x6DB6:('cbnz','r5, #0x6dc0'),
}

def verify_original(image):
    row=code_window(image,VENEER,VENEER+4)
    if len(row)!=1 or (row[0]['m'],row[0]['op'])!=(
        'ldr.w','pc, [pc, #-0x0]'):
        raise ValueError('Phase74 signed original XIP veneer drift')
    if word(image,VENEER+4)!=0x6D2D:
        raise ValueError('Phase74 signed original queue target word drift')
    found={int(row['pc'],16):(row['m'],row['op'])
           for row in itcm_code(image,0x6D2C,0xB0)}
    for pc,expected in PINS.items():
        if found.get(pc)!=expected:
            raise ValueError(f'Phase74 signed original receiver instruction drift {pc:#x}')
    return len(PINS)+1

def execute_guards(uc,image):
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import (
        UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R4,
        UC_ARM_REG_R7,UC_ARM_REG_SP
    )
    # The phase73 retained machine executes from XIP only. Mapping signed
    # startup-copied ITCM here is a modeling action, not a physical read.
    uc.mem_map(0,0x10000)
    uc.mem_write(0,image[ITCM_SOURCE_OFFSET:ITCM_SOURCE_OFFSET+ITCM_LENGTH])
    read=lambda a:struct.unpack('<I',bytes(uc.mem_read(a,4)))[0]
    orig=dict(r0=uc.reg_read(UC_ARM_REG_R0),r1=uc.reg_read(UC_ARM_REG_R1),
              r2=uc.reg_read(UC_ARM_REG_R2))
    if not orig['r0'] or not orig['r1'] or orig['r2']!=0xFFFFFFFF:
        raise ValueError('Phase74 modeled input not observed phase73 argument state')
    output_before=read(orig['r1'])
    pcs=[]
    def hook(machine,pc,size,user):
        pcs.append(pc)
        if pc==0x6D58:
            machine.emu_stop()
        elif pc not in (WAIT,VENEER) and not 0x6D2C<=pc<0x6D58:
            raise ValueError(f'Phase74 unexpected original receiver instruction {pc:#x}')
    ident=uc.hook_add(UC_HOOK_CODE,hook)
    try:
        try:
            uc.emu_start(WAIT|1,0x10000002,count=50)
        except Exception as exc:
            from unicorn.arm_const import UC_ARM_REG_PC
            raise ValueError(
                f'Phase74 virtual receive failed at PC={uc.reg_read(UC_ARM_REG_PC):#x}; '
                f'last signed instructions={list(map(hex,pcs[-12:]))}; '
                f'error={exc}'
            ) from exc
    finally:
        uc.hook_del(ident)
    if not pcs or pcs[-1]!=0x6D58 or VENEER not in pcs or 0x6D2C not in pcs:
        raise ValueError('Phase74 original receive prologue did not reach guard boundary')
    if (uc.reg_read(UC_ARM_REG_R4)!=orig['r0']
        or uc.reg_read(UC_ARM_REG_R7)!=orig['r1']
        or read(uc.reg_read(UC_ARM_REG_SP)+4)!=orig['r2']):
        raise ValueError('Phase74 prologue lost queue/output/timeout provenance')
    output_after=read(orig['r1'])
    if output_before!=output_after:
        raise ValueError('Phase74 original guard path unexpectedly modified output')
    return {
        'original_instruction_addresses':[hex(pc) for pc in pcs[:-1]],
        'stop_before_helper':hex(pcs[-1]),
        'input_queue_control':hex(orig['r0']),
        'input_output_buffer':hex(orig['r1']),
        'input_wait':hex(orig['r2']),
        'saved_queue_control_R4':hex(uc.reg_read(UC_ARM_REG_R4)),
        'saved_output_buffer_R7':hex(uc.reg_read(UC_ARM_REG_R7)),
        'stacked_timeout':hex(read(uc.reg_read(UC_ARM_REG_SP)+4)),
        'output_before':hex(output_before),
        'output_after':hex(output_after),
        'original_guard_path_executed':True,
        'first_sync_helper_executed':False,
        'queue_dequeue_executed':False,
        'work_item_callback_executed':False,
    }

def audit(image):
    if len(image)!=IMAGE_SIZE or hashlib.sha256(image).hexdigest()!=IMAGE_SHA256:
        raise ValueError('Phase74 original exact SHA-pinned OEM required')
    pins=verify_original(image)
    target=receiver_code(image)
    if target['target_pc']!='0x6d2c' or target['target_kind']!='relocated_ITCM':
        raise ValueError('Phase74 signed veneer resolution drift')
    uc,entry=prepare_phase73_state(image)
    queue=queue_snapshot(uc)
    executed=execute_guards(uc,image)
    return dict(
        phase=74,
        original_oem_SHA256=IMAGE_SHA256,
        signed_receiver_pins=pins,
        original_receiver_ITCM='0x6d2c',
        inherited_phase73_queue_state=queue,
        original_receive_guard_execution=executed,
        safety_and_limits=[
            'Retained original-task virtual state still depends on modeled scheduler, SVC frame and virtual MMIO.',
            'Only the original BL, signed XIP veneer and ITCM argument-check prologue execute in emulator.',
            'Stopped before original 0x7734 kernel primitive. No kernel critical sections, semaphore waits or task switching run.',
            'No work item is dequeued and no callback is executed; no artificial message is injected.',
            'No physical USB or installed RAM evidence; no custom firmware execution or HAB CLOSED bypass.',
        ]
    )

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('image',type=Path)
    p.add_argument('--out',type=Path)
    args=p.parse_args()
    result=audit(args.image.read_bytes())
    text=json.dumps(result,indent=2)+'\n'
    if args.out:args.out.write_text(text,encoding='utf-8')
    print('PHASE74 ORIGINAL RECEIVE GUARDS',json.dumps(result['original_receive_guard_execution']))
    print('PHASE74 STOP BEFORE 0x7734: NO MESSAGE, CALLBACK OR DEVICE I/O')

if __name__=='__main__':
    main()
